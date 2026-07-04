set dotenv-load := false

default:
    just --list

fmt:
    cargo fmt --all
    taplo fmt

fmt-check:
    cargo fmt --all --check
    taplo fmt --check

check:
    cargo fmt --all --check
    taplo fmt --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace
    just docs-check

check-s3:
    cargo clippy -p rs3-storage -p rs3-server -p xtask --features rs3-server/s3,xtask/s3 --all-targets -- -D warnings
    cargo test -p rs3-storage -p rs3-server -p xtask --features rs3-server/s3,xtask/s3

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
    just integration-s3-gateway --repository-format v2-preview --tooling-smoke
    just integration-kopia-gateway --repository-format v2-preview
    just integration-k8s-gateway-v2 --wait-secs 240
    just integration-velero-kopia-dynamic-pvc-gateway-restart-smoke --repository-format v2-preview
    just integration-velero-kopia-postgres-smoke --repository-format v2-preview

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
    RS3_REPOSITORY_FORMAT=v2-preview \
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

v2-gc-rehearsal-live BACKEND_BUCKET ENDPOINT_URL REGION BACKEND_PREFIX:
    cargo run -p xtask --bin xtask --features s3 -- v2 gc-rehearsal --backend s3 --s3-bucket "{{BACKEND_BUCKET}}" --s3-prefix "{{BACKEND_PREFIX}}" --s3-endpoint-url "{{ENDPOINT_URL}}" --s3-region "{{REGION}}" --retained-provider-conformance-passed --format json

integration-s3:
    cargo test -p rs3-storage --features s3 --test s3_live -- --ignored --nocapture

integration-s3-local *ARGS:
    cargo run -p xtask --bin xtask -- integration s3-local {{ARGS}}

integration-s3-container *ARGS:
    cargo run -p xtask --bin xtask --features containers -- integration s3-local --mode container {{ARGS}}

integration-s3-gateway *ARGS:
    cargo run -p xtask --bin xtask --features containers -- integration s3-gateway {{ARGS}}

integration-s3-gateway-v2-live *ARGS:
    cargo run -p xtask --bin xtask --features containers -- integration s3-gateway --mode provided --repository-format v2-preview --retention-mode governance --retention-days 1 --tooling-smoke {{ARGS}}

integration-kopia-gateway *ARGS:
    cargo run -p xtask --bin xtask --features containers -- integration kopia-gateway {{ARGS}}

integration-kopia-gateway-v2-live *ARGS:
    cargo run -p xtask --bin xtask --features containers -- integration kopia-gateway --mode provided --repository-format v2-preview --retention-mode governance --retention-days 1 {{ARGS}}

integration-k8s-gateway *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration k8s-gateway {{ARGS}}

integration-k8s-gateway-v2 *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration k8s-gateway --repository-format v2-preview {{ARGS}}

integration-velero-kopia-smoke *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-smoke {{ARGS}}

integration-velero-kopia-local-pv-smoke *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-local-pv-smoke {{ARGS}}

integration-velero-kopia-dynamic-pvc-smoke *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-dynamic-pvc-smoke {{ARGS}}

integration-velero-kopia-dynamic-pvc-gateway-restart-smoke *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-dynamic-pvc-gateway-restart-smoke {{ARGS}}

integration-velero-kopia-dynamic-pvc-gateway-restart-v2-live *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-dynamic-pvc-gateway-restart-smoke --backend-mode provided --repository-format v2-preview --repository-retention-mode governance --repository-retention-days 1 {{ARGS}}

integration-velero-kopia-dynamic-pvc-restore-readonly-smoke *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-dynamic-pvc-restore-readonly-smoke {{ARGS}}

integration-velero-kopia-postgres-smoke *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-postgres-smoke {{ARGS}}

integration-velero-kopia-postgres-v2-live *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-postgres-smoke --backend-mode provided --repository-format v2-preview --repository-retention-mode governance --repository-retention-days 1 {{ARGS}}

helm-lint:
    helm lint charts/rs3-gateway \
        --set credentials.create=true \
        --set-string credentials.accessKeyId=fixture-access-key \
        --set-string credentials.secretAccessKey=fixture-secret-key \
        --set repositoryKeys.create=true \
        --set-string repositoryKeys.saltHex=1111111111111111111111111111111111111111111111111111111111111111 \
        --set-string repositoryKeys.wrappingKeyHex=2222222222222222222222222222222222222222222222222222222222222222

test:
    cargo test --workspace

perf *ARGS:
    cargo run -p xtask --bin xtask -- perf {{ARGS}}

perf-commit *ARGS:
    cargo run -p xtask --bin xtask -- perf --scenario write-committed {{ARGS}}

perf-commit-parallel *ARGS:
    cargo run -p xtask --bin xtask -- perf --scenario write-committed-parallel {{ARGS}}

perf-s3 *ARGS:
    cargo run -p xtask --bin xtask --features s3 -- perf --backend s3 {{ARGS}}

perf-s3-container *ARGS:
    cargo run -p xtask --bin xtask --features containers -- perf --backend s3-container {{ARGS}}

perf-s3-gateway *ARGS:
    cargo run -p xtask --bin xtask --features containers -- perf --backend s3-gateway-container {{ARGS}}

nextest:
    cargo nextest run --workspace

deny:
    cargo deny check

deny-s3:
    cargo metadata --features xtask/s3 --format-version 1 > target/deny-s3-metadata.json
    cargo deny check --metadata-path target/deny-s3-metadata.json

audit:
    cargo audit

doc:
    cargo doc --workspace --no-deps

docs-build:
    just docs-check

docs-check:
    mkdocs build --strict

docs-serve *ARGS:
    mkdocs serve {{ARGS}}
