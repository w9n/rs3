set dotenv-load := false

# Show available recipes.
default:
    just --list

# Format Rust and TOML sources.
fmt:
    cargo fmt --all
    taplo fmt

# Check Rust and TOML formatting without writing changes.
fmt-check:
    cargo fmt --all --check
    taplo fmt --check

# Run formatting, lint, workspace tests, and docs checks.
check:
    cargo fmt --all --check
    taplo fmt --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace
    just docs-check
    just helm-lint

# Run the S3 feature lint and tests.
check-s3:
    cargo clippy -p rs3-storage -p rs3-server -p xtask --features rs3-server/s3,xtask/s3 --all-targets -- -D warnings
    cargo test -p rs3-storage -p rs3-server -p xtask --features rs3-server/s3,xtask/s3

# Run backend-parser fuzz targets briefly for scheduled hardening.
fuzz-smoke:
    #!/usr/bin/env bash
    set -euo pipefail
    seconds="${RS3_FUZZ_SMOKE_SECONDS:-60}"
    rss_limit_mb="${RS3_FUZZ_RSS_LIMIT_MB:-512}"
    tmpdir="$(mktemp -d)"
    trap 'rm -rf "${tmpdir}"' EXIT
    RUSTC_BOOTSTRAP=1 cargo fuzz build --sanitizer none
    pids=()
    for target in v2_commit v2_cbor index_delta keyring_envelope restore_bundle; do
      corpus="${tmpdir}/${target}"
      mkdir -p "${corpus}"
      if [[ -d "fuzz/corpus/${target}" ]]; then
        cp -R "fuzz/corpus/${target}/." "${corpus}/"
      fi
      RUSTC_BOOTSTRAP=1 cargo fuzz run --sanitizer none "${target}" "${corpus}" -- -max_total_time="${seconds}" -rss_limit_mb="${rss_limit_mb}" &
      pids+=("$!")
    done
    status=0
    for pid in "${pids[@]}"; do
      if ! wait "${pid}"; then
        status=1
      fi
    done
    exit "${status}"

# Run the full deterministic storage fault-injection sweep.
fault-injection-sweep:
    RS3_FAULT_INJECTION_FULL_SWEEP=1 cargo test -p rs3-repository --test fault_injection

# Run a local filesystem-backed gateway with fixture credentials.
serve-local:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p /tmp/rs3-backend
    RS3_PUBLIC_BUCKET=backup \
    RS3_BACKEND_ENDPOINT=file:///tmp/rs3-backend \
    RS3_BACKEND_BUCKET=repo \
    RS3_ANCHOR_MODE=memory \
    RS3_ALLOW_MEMORY_ANCHOR=true \
    RS3_ALLOW_REPOSITORY_INIT=true \
    RS3_REPOSITORY_ID=local-dev \
    RS3_REPOSITORY_SALT_HEX=2222222222222222222222222222222222222222222222222222222222222222 \
    RS3_KEYRING_WRAPPING_KEY_HEX=3333333333333333333333333333333333333333333333333333333333333333 \
    RS3_STATIC_ACCESS_KEY_ID=local \
    RS3_STATIC_SECRET_ACCESS_KEY=local-secret \
        cargo run -p rs3-server -- serve \
            --bind 127.0.0.1:9080 \
            --admin-bind 127.0.0.1:9082 \
            --admin-bearer-token local-admin-token-12345 \
            --admin-profile local

# Run the local console against `just serve-local`.
console-local:
    RS3_CONSOLE_BEARER_TOKEN=local-console-token-12345 \
    RS3_GATEWAY_ADMIN_URL=http://127.0.0.1:9082 \
    RS3_GATEWAY_ADMIN_BEARER_TOKEN=local-admin-token-12345 \
        cargo run -p rs3-console

# Cheap production-preview gate for local handoff.
preview-gate-local:
    just check
    just check-s3
    just deny
    just deny-s3

# Expensive v2 production-preview integration gate for release candidates.
preview-gate-release:
    just integration-kopia-gateway
    just integration-velero-kopia-dynamic-pvc-gateway-restart-smoke
    just integration-velero-kopia-postgres-smoke

# Expensive local v2 gate for scheduled CI or release-candidate hardening.
preview-gate-v2-nightly:
    just check-s3
    just fuzz-smoke
    just fault-injection-sweep
    just integration-s3-gateway --tooling-smoke
    just integration-kopia-gateway
    just integration-k8s-gateway-v2 --wait-secs 240
    just integration-velero-kopia-dynamic-pvc-gateway-restart-smoke
    just integration-velero-kopia-postgres-smoke

# Live retained-backend v2 gate. Credentials are read from the normal AWS/S3 env.
preview-gate-v2-live BACKEND_BUCKET ENDPOINT_URL REGION:
    #!/usr/bin/env bash
    set -euo pipefail
    timestamp="$(date -u +%Y%m%dT%H%M%SZ)-$$"
    base="${RS3_LIVE_BACKEND_PREFIX_BASE:-rs3-live/${timestamp}}"
    mkdir -p .local/integration
    printf '%s\n' "${base}" > ".local/integration/${timestamp}.txt"
    echo "v2 live gate using a fresh backend prefix; exact value is in the local artifact directory"
    just check-v2-provider-v2-live "{{BACKEND_BUCKET}}" "{{ENDPOINT_URL}}" "{{REGION}}" "${base}/a" > ".local/integration/${timestamp}.json"
    just integration-s3-gateway-v2-live --backend-bucket "{{BACKEND_BUCKET}}" --endpoint-url "{{ENDPOINT_URL}}" --region "{{REGION}}" --backend-prefix "${base}/b"
    just integration-kopia-gateway-v2-live --backend-bucket "{{BACKEND_BUCKET}}" --endpoint-url "{{ENDPOINT_URL}}" --region "{{REGION}}" --backend-prefix "${base}/c"
    just integration-k8s-gateway-v2 --wait-secs 240
    just integration-velero-kopia-dynamic-pvc-gateway-restart-v2-live --backend-bucket "{{BACKEND_BUCKET}}" --backend-endpoint-url "{{ENDPOINT_URL}}" --backend-region "{{REGION}}" --backend-prefix "${base}/d"
    just integration-velero-kopia-postgres-v2-live --backend-bucket "{{BACKEND_BUCKET}}" --backend-endpoint-url "{{ENDPOINT_URL}}" --backend-region "{{REGION}}" --backend-prefix "${base}/e"

# Check a live v2 backend for retained-version and object-lock behavior.
check-v2-provider-v2-live BACKEND_BUCKET ENDPOINT_URL REGION BACKEND_PREFIX:
    #!/usr/bin/env bash
    set -euo pipefail
    : "${RS3_GOVERNANCE_BYPASS_REVIEWED:?set RS3_GOVERNANCE_BYPASS_REVIEWED=true after reviewing that gateway credentials cannot bypass governance retention}"
    if [[ "${RS3_GOVERNANCE_BYPASS_REVIEWED}" != "true" ]]; then
      echo "RS3_GOVERNANCE_BYPASS_REVIEWED must be true after operator IAM review" >&2
      exit 2
    fi
    RS3_PUBLIC_BUCKET=client-bucket \
    RS3_BACKEND_ENDPOINT="{{ENDPOINT_URL}}" \
    RS3_BACKEND_BUCKET="{{BACKEND_BUCKET}}" \
    RS3_BACKEND_PREFIX="{{BACKEND_PREFIX}}" \
    AWS_DEFAULT_REGION="{{REGION}}" \
    RS3_REPOSITORY_RETENTION_MODE=governance \
    RS3_REPOSITORY_RETENTION_DAYS=1 \
    RS3_ANCHOR_MODE=memory \
    RS3_ALLOW_MEMORY_ANCHOR=true \
    RS3_REPOSITORY_ID=rs3-provider-conformance \
    RS3_REPOSITORY_SALT_HEX=2222222222222222222222222222222222222222222222222222222222222222 \
    RS3_KEYRING_WRAPPING_KEY_HEX=3333333333333333333333333333333333333333333333333333333333333333 \
      cargo run -p rs3-server --features s3 -- check-v2-provider \
        --probe-prefix "{{BACKEND_PREFIX}}/p" \
        --legal-hold \
        --governance-bypass-reviewed \
        --format json

# Rehearse v2 garbage collection against a live backend.
v2-gc-rehearsal-live BACKEND_BUCKET ENDPOINT_URL REGION BACKEND_PREFIX:
    cargo run -p xtask --bin xtask --features s3 -- v2 gc-rehearsal --backend s3 --s3-bucket "{{BACKEND_BUCKET}}" --s3-prefix "{{BACKEND_PREFIX}}" --s3-endpoint-url "{{ENDPOINT_URL}}" --s3-region "{{REGION}}" --retained-provider-conformance-passed --format json

# Run live S3 storage contract tests against configured credentials.
integration-s3:
    cargo test -p rs3-storage --features s3 --test s3_live -- --ignored --nocapture

# Run the local S3 integration harness.
integration-s3-local *ARGS:
    cargo run -p xtask --bin xtask -- integration s3-local {{ARGS}}

# Run the local S3 integration harness in containers.
integration-s3-container *ARGS:
    cargo run -p xtask --bin xtask --features containers -- integration s3-local --mode container {{ARGS}}

# Run the S3 gateway integration harness.
integration-s3-gateway *ARGS:
    cargo run -p xtask --bin xtask --features containers -- integration s3-gateway {{ARGS}}

# Run the v2 live S3 gateway integration harness.
integration-s3-gateway-v2-live *ARGS:
    cargo run -p xtask --bin xtask --features containers -- integration s3-gateway --mode provided --retention-mode governance --retention-days 1 --tooling-smoke {{ARGS}}

# Run the Kopia gateway integration harness.
integration-kopia-gateway *ARGS:
    cargo run -p xtask --bin xtask --features containers -- integration kopia-gateway {{ARGS}}

# Run the v2 live Kopia gateway integration harness.
integration-kopia-gateway-v2-live *ARGS:
    cargo run -p xtask --bin xtask --features containers -- integration kopia-gateway --mode provided --retention-mode governance --retention-days 1 {{ARGS}}

# Run the Kubernetes gateway integration harness.
integration-k8s-gateway *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration k8s-gateway {{ARGS}}

# Run the v2 Kubernetes gateway integration harness.
integration-k8s-gateway-v2 *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration k8s-gateway {{ARGS}}

# Run the Velero Kopia smoke test.
integration-velero-kopia-smoke *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-smoke {{ARGS}}

# Run the Velero Kopia local-PV smoke test.
integration-velero-kopia-local-pv-smoke *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-local-pv-smoke {{ARGS}}

# Run the Velero Kopia dynamic-PVC smoke test.
integration-velero-kopia-dynamic-pvc-smoke *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-dynamic-pvc-smoke {{ARGS}}

# Run the Velero Kopia dynamic-PVC gateway-restart smoke test.
integration-velero-kopia-dynamic-pvc-gateway-restart-smoke *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-dynamic-pvc-gateway-restart-smoke {{ARGS}}

# Run the v2 live dynamic-PVC gateway-restart smoke test.
integration-velero-kopia-dynamic-pvc-gateway-restart-v2-live *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-dynamic-pvc-gateway-restart-smoke --backend-mode provided --repository-retention-mode governance --repository-retention-days 1 {{ARGS}}

# Run the Velero Kopia restore-readonly dynamic-PVC smoke test.
integration-velero-kopia-dynamic-pvc-restore-readonly-smoke *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-dynamic-pvc-restore-readonly-smoke {{ARGS}}

# Run the Velero Kopia Postgres smoke test.
integration-velero-kopia-postgres-smoke *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-postgres-smoke {{ARGS}}

# Run the v2 live Velero Kopia Postgres smoke test.
integration-velero-kopia-postgres-v2-live *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-postgres-smoke --backend-mode provided --repository-retention-mode governance --repository-retention-days 1 {{ARGS}}

# Lint the Helm chart with required fixture values.
helm-lint:
    helm lint charts/rs3-gateway \
        --set credentials.create=true \
        --set-string credentials.accessKeyId=fixture-access-key \
        --set-string credentials.secretAccessKey=fixture-secret-key \
        --set admin.createToken=true \
        --set-string admin.bearerToken=fixture-admin-token-12345 \
        --set repositoryKeys.create=true \
        --set-string repositoryKeys.saltHex=1111111111111111111111111111111111111111111111111111111111111111 \
        --set-string repositoryKeys.wrappingKeyHex=2222222222222222222222222222222222222222222222222222222222222222

# Run the workspace test suite.
test:
    cargo test --workspace

# Run the performance harness.
perf *ARGS:
    cargo run -p xtask --bin xtask -- perf {{ARGS}}

# Run committed-write performance measurements.
perf-commit *ARGS:
    cargo run -p xtask --bin xtask -- perf --scenario write-committed {{ARGS}}

# Run parallel committed-write performance measurements.
perf-commit-parallel *ARGS:
    cargo run -p xtask --bin xtask -- perf --scenario write-committed-parallel {{ARGS}}

# Run performance measurements against an S3 backend.
perf-s3 *ARGS:
    cargo run -p xtask --bin xtask --features s3 -- perf --backend s3 {{ARGS}}

# Run performance measurements against a container S3 backend.
perf-s3-container *ARGS:
    cargo run -p xtask --bin xtask --features containers -- perf --backend s3-container {{ARGS}}

# Run performance measurements through a containerized gateway.
perf-s3-gateway *ARGS:
    cargo run -p xtask --bin xtask --features containers -- perf --backend s3-gateway-container {{ARGS}}

# Run the workspace suite with nextest.
nextest:
    cargo nextest run --workspace

# Run cargo-deny checks.
deny:
    cargo deny check

# Run cargo-deny checks with S3 feature metadata.
deny-s3:
    cargo metadata --features xtask/s3 --format-version 1 > target/deny-s3-metadata.json
    cargo deny check --metadata-path target/deny-s3-metadata.json

# Run cargo-audit.
audit:
    cargo audit

# Build Rust API documentation.
doc:
    cargo doc --workspace --no-deps

alias docs-build := docs-check

# Build the public documentation strictly.
docs-check:
    mkdocs build --strict

# Serve the public documentation locally.
docs-serve *ARGS:
    mkdocs serve {{ARGS}}
