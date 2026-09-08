set dotenv-load := false

# Show available recipes.
default:
    just --list

# Print the exact tracked source revision used to build release evidence.
_candidate-revision:
    #!/usr/bin/env bash
    set -euo pipefail
    revision="$(git rev-parse --verify HEAD)"
    if ! git diff --quiet --ignore-submodules -- || ! git diff --cached --quiet --ignore-submodules --; then
      revision="${revision}-dirty"
    fi
    printf '%s\n' "${revision}"

# Format Rust and TOML sources.
fmt:
    cargo fmt
    taplo fmt

# Check Rust and TOML formatting without writing changes.
fmt-check:
    cargo fmt --check
    taplo fmt --check

# Run formatting, lint, workspace tests, and docs checks.
check:
    cargo fmt --check
    taplo fmt --check
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo test --workspace --all-features
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
    for target in \
      v03_commit \
      canonical_cbor \
      repository_envelope \
      recovery_bundle \
      v03_index_run \
      v03_index_root \
      v03_format_root \
      v03_payload_pack \
      v03_standalone_single
    do
      corpus="${tmpdir}/${target}"
      mkdir -p "${corpus}"
      if [[ -d "fuzz/corpus/${target}" ]]; then
        cp -R "fuzz/corpus/${target}/." "${corpus}/"
      fi
      if [[ -d "test-vectors/v03/${target}" ]]; then
        cp -R "test-vectors/v03/${target}/." "${corpus}/"
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

# Verify 1,024 fixed-key churn cycles, metadata IO and protected-root GC.
test-churn-scale:
    cargo test -p rs3-repository --test fault_injection fixed_live_set_churn_scale -- --ignored --nocapture

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
    just deny
    just deny-s3

# Expensive v2 production-preview integration gate for release candidates.
preview-gate-release:
    just perf-standalone-gate
    just integration-kopia-gateway
    just integration-velero-kopia-dynamic-pvc-gateway-restart-smoke --pull-velero-images --pull-openebs-images --pull-postgres-image --pull-rustfs-image
    just integration-velero-kopia-postgres-smoke --pull-velero-images --pull-openebs-images --pull-postgres-image --pull-rustfs-image

# Expensive local v2 gate for scheduled CI or release-candidate hardening.
preview-gate-v2-nightly:
    #!/usr/bin/env bash
    set -euo pipefail
    qualification_status=0
    just check-s3 || qualification_status=1
    just fuzz-smoke || qualification_status=1
    just fault-injection-sweep || qualification_status=1
    just perf-standalone-gate || qualification_status=1
    just integration-s3-gateway --tooling-smoke || qualification_status=1
    just preview-gate-v2-retained-local || qualification_status=1
    just integration-kopia-gateway || qualification_status=1
    just integration-k8s-gateway --wait-secs 240 || qualification_status=1
    just integration-velero-kopia-dynamic-pvc-gateway-restart-smoke --pull-velero-images --pull-openebs-images --pull-postgres-image --pull-rustfs-image || qualification_status=1
    just integration-velero-kopia-postgres-smoke --pull-velero-images --pull-openebs-images --pull-postgres-image --pull-rustfs-image || qualification_status=1
    exit "${qualification_status}"

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
    just integration-k8s-gateway --wait-secs 240
    just integration-velero-kopia-dynamic-pvc-gateway-restart-v2-live --backend-bucket "{{BACKEND_BUCKET}}" --backend-endpoint-url "{{ENDPOINT_URL}}" --backend-region "{{REGION}}" --backend-prefix "${base}/d" --pull-velero-images --pull-openebs-images --pull-postgres-image
    just integration-velero-kopia-postgres-v2-live --backend-bucket "{{BACKEND_BUCKET}}" --backend-endpoint-url "{{ENDPOINT_URL}}" --backend-region "{{REGION}}" --backend-prefix "${base}/e" --pull-velero-images --pull-openebs-images --pull-postgres-image

# Check a live v2 backend for retained-version and object-lock behavior.
check-v2-provider-v2-live BACKEND_BUCKET ENDPOINT_URL REGION BACKEND_PREFIX:
    #!/usr/bin/env bash
    set -euo pipefail
    : "${RS3_GOVERNANCE_BYPASS_REVIEWED:?set RS3_GOVERNANCE_BYPASS_REVIEWED=true after reviewing that gateway credentials cannot bypass governance retention}"
    : "${RS3_PROVIDER_PRINCIPAL_FINGERPRINT:?set RS3_PROVIDER_PRINCIPAL_FINGERPRINT to the lowercase SHA-256 fingerprint of the reviewed credential principal}"
    if [[ "${RS3_GOVERNANCE_BYPASS_REVIEWED}" != "true" ]]; then
      echo "RS3_GOVERNANCE_BYPASS_REVIEWED must be true after operator IAM review" >&2
      exit 2
    fi
    build_revision="$(just --quiet _candidate-revision)"
    RS3_BUILD_GIT_SHA="${build_revision}" \
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
        --legal-hold \
        --governance-bypass-reviewed \
        --format json

# Rehearse v2 garbage collection against a live backend through the enforced
# Kubernetes writer fence. Set RS3_V2_REHEARSAL_LEASE_NAMESPACE (and optionally
# RS3_V2_REHEARSAL_LEASE_NAME) to name the dedicated rehearsal Lease.
v2-gc-rehearsal-live BACKEND_BUCKET ENDPOINT_URL REGION BACKEND_PREFIX:
    cargo run -p xtask --bin xtask --features k8s -- v2 gc-rehearsal --backend s3 --s3-bucket "{{BACKEND_BUCKET}}" --s3-prefix "{{BACKEND_PREFIX}}" --s3-endpoint-url "{{ENDPOINT_URL}}" --s3-region "{{REGION}}" --retained-provider-conformance-passed --format json

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
    cargo build -p rs3-server --bin rs3-server --features s3
    cargo run -p xtask --bin xtask --features containers -- integration s3-gateway {{ARGS}}

# Qualify retained-version storage and guarded gateway behavior against disposable local providers.
# Governance bypass IAM remains separately qualified; this fixture uses compliance Object Lock.
preview-gate-v2-retained-local:
    just integration-s3-container --qualification-profile retained-version --object-lock --retention-days 1 --gc-rehearsal
    just integration-k8s-gateway --retention-mode compliance --retention-days 30 --tooling-smoke

# Run the v2 live S3 gateway integration harness.
integration-s3-gateway-v2-live *ARGS:
    cargo build -p rs3-server --bin rs3-server --features s3
    cargo run -p xtask --bin xtask --features containers -- integration s3-gateway --mode provided --retention-mode governance --retention-days 1 --tooling-smoke {{ARGS}}

# Run the Kopia gateway integration harness.
integration-kopia-gateway *ARGS:
    cargo build -p rs3-server --bin rs3-server --features s3
    cargo run -p xtask --bin xtask --features containers -- integration kopia-gateway {{ARGS}}

# Run the v2 live Kopia gateway integration harness.
integration-kopia-gateway-v2-live *ARGS:
    cargo build -p rs3-server --bin rs3-server --features s3
    cargo run -p xtask --bin xtask --features containers -- integration kopia-gateway --mode provided --retention-mode governance --retention-days 1 {{ARGS}}

# Run the Kubernetes gateway integration harness.
integration-k8s-gateway *ARGS:
    RS3_BUILD_GIT_SHA="$(just --quiet _candidate-revision)" cargo run -p xtask --bin xtask --features k8s -- integration k8s-gateway {{ARGS}}

# Run the Velero Kopia smoke test.
integration-velero-kopia-smoke *ARGS:
    RS3_BUILD_GIT_SHA="$(just --quiet _candidate-revision)" cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-smoke {{ARGS}}

# Run the Velero Kopia local-PV smoke test.
integration-velero-kopia-local-pv-smoke *ARGS:
    RS3_BUILD_GIT_SHA="$(just --quiet _candidate-revision)" cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-local-pv-smoke {{ARGS}}

# Run the Velero Kopia dynamic-PVC smoke test.
integration-velero-kopia-dynamic-pvc-smoke *ARGS:
    RS3_BUILD_GIT_SHA="$(just --quiet _candidate-revision)" cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-dynamic-pvc-smoke {{ARGS}}

# Run the Velero Kopia dynamic-PVC gateway-restart smoke test.
integration-velero-kopia-dynamic-pvc-gateway-restart-smoke *ARGS:
    RS3_BUILD_GIT_SHA="$(just --quiet _candidate-revision)" cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-dynamic-pvc-gateway-restart-smoke {{ARGS}}

# Run the v2 live dynamic-PVC gateway-restart smoke test. Governance retention
# on a provided backend needs operator review inputs: RS3_GOVERNANCE_BYPASS_REVIEWED=true
# and RS3_PROVIDER_PRINCIPAL_FINGERPRINT (see check-v2-provider-v2-live). The chart
# requires retention above the renewal horizon plus maintenance interval (14 days).
integration-velero-kopia-dynamic-pvc-gateway-restart-v2-live *ARGS:
    RS3_BUILD_GIT_SHA="$(just --quiet _candidate-revision)" cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-dynamic-pvc-gateway-restart-smoke --backend-mode provided --repository-retention-mode governance --repository-retention-days 15 {{ARGS}}

# Run the Velero Kopia restore-readonly dynamic-PVC smoke test.
integration-velero-kopia-dynamic-pvc-restore-readonly-smoke *ARGS:
    RS3_BUILD_GIT_SHA="$(just --quiet _candidate-revision)" cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-dynamic-pvc-restore-readonly-smoke {{ARGS}}

# Run the Velero Kopia Postgres smoke test.
integration-velero-kopia-postgres-smoke *ARGS:
    RS3_BUILD_GIT_SHA="$(just --quiet _candidate-revision)" cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-postgres-smoke {{ARGS}}

# Run the v2 live Velero Kopia Postgres smoke test. Needs the same governance
# review inputs and retention floor as the gateway-restart v2-live recipe.
integration-velero-kopia-postgres-v2-live *ARGS:
    RS3_BUILD_GIT_SHA="$(just --quiet _candidate-revision)" cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-postgres-smoke --backend-mode provided --repository-retention-mode governance --repository-retention-days 15 {{ARGS}}

# Candidate-only lifecycle qualification: generated salt, restart, same-values
# Helm repeat against the live writer, and image-only requalification.
integration-k8s-gateway-lifecycle *ARGS:
    RS3_BUILD_GIT_SHA="$(just --quiet _candidate-revision)" cargo run -p xtask --bin xtask --features k8s -- integration k8s-gateway --generated-salt --lifecycle-checks --wait-secs 300 {{ARGS}}

# Lint both the local fixture and fail-closed production value profiles.
helm-lint:
    helm lint charts/rs3-gateway \
        --set admin.profile=local \
        --set credentials.create=true \
        --set-string credentials.accessKeyId=fixture-access-key \
        --set-string credentials.secretAccessKey=fixture-secret-key \
        --set admin.createToken=true \
        --set-string admin.bearerToken=fixture-admin-token-12345 \
        --set repositoryKeys.create=true \
        --set-string repositoryKeys.saltHex=1111111111111111111111111111111111111111111111111111111111111111 \
        --set-string repositoryKeys.wrappingKeyHex=2222222222222222222222222222222222222222222222222222222222222222
    helm lint charts/rs3-gateway \
        --set-string image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000 \
        --set-string backend.endpoint=https://s3.example.invalid \
        --set credentials.existingSecret=fixture-client-credentials \
        --set admin.existingTokenSecret=fixture-admin-token \
        --set repositoryKeys.existingSecret=fixture-repository-keys \
        --set repository.retention.mode=governance \
        --set repository.retention.days=30 \
        --set providerConformance.existingConfigMap=fixture-provider-conformance \
        --set-string providerConformance.principalFingerprint=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    python3 tests/helm_network_policy.py
    python3 tests/helm_runtime_limits.py
    python3 -B tests/helm_bootstrap.py

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

# Enforce the four mandatory small-write ceilings and retain every raw JSONL sample.
# Requires a clean committed revision; RS3_SCALE_GATE_RUNS defaults to three.
perf-small-workloads EVIDENCE_DIR:
    #!/usr/bin/env bash
    set -euo pipefail
    runs="${RS3_SCALE_GATE_RUNS:-3}"
    if ! [[ "${runs}" =~ ^[1-9][0-9]*$ ]]; then
      echo "RS3_SCALE_GATE_RUNS must be a positive integer" >&2
      exit 2
    fi
    build_revision="$(git rev-parse --verify HEAD)"
    verify_source() {
      local observed_revision observed_status
      observed_revision="$(git rev-parse --verify HEAD)"
      observed_status="$(git status --porcelain --untracked-files=all)"
      if [[ "${observed_revision}" != "${build_revision}" || -n "${observed_status}" ]]; then
        echo "small-workload qualification requires the same clean committed revision, including untracked inputs" >&2
        exit 2
      fi
    }
    verify_source
    evidence_dir="{{EVIDENCE_DIR}}"
    mkdir -p "${evidence_dir}"
    for artifact in build.log commands.txt binary.sha256; do
      if [[ -e "${evidence_dir}/${artifact}" ]]; then
        echo "refusing to overwrite existing build evidence: ${artifact}" >&2
        exit 2
      fi
    done
    build=(env "RS3_BUILD_GIT_SHA=${build_revision}" cargo build --release -p xtask --bin xtask)
    printf '%q ' "${build[@]}" > "${evidence_dir}/commands.txt"
    printf '\n' >> "${evidence_dir}/commands.txt"
    verify_source
    "${build[@]}" 2>&1 | tee "${evidence_dir}/build.log"
    verify_source
    sha256sum target/release/xtask > "${evidence_dir}/binary.sha256"
    failed=0
    for ((run = 1; run <= runs; run++)); do
      for lane in empty-64 batch-4k-64 batch-256k-64 sequential-512-64; do
        scenario=write-batch
        batch=64
        concurrency=64
        case "${lane}" in
          empty-64) size=0; ceiling=(--max-write-bytes-per-object 320) ;;
          batch-4k-64) size=4096; ceiling=(--max-write-amp 1.15) ;;
          batch-256k-64) size=262144; ceiling=(--max-write-amp 1.03) ;;
          sequential-512-64) size=512; scenario=write-committed; batch=1; concurrency=1; ceiling=(--max-write-amp 3.0) ;;
        esac
        report="${evidence_dir}/${lane}-run-$(printf '%03d' "${run}").jsonl"
        if [[ -e "${report}" ]]; then
          echo "refusing to overwrite existing raw performance evidence: ${report}" >&2
          exit 2
        fi
        command=(target/release/xtask perf
          --scenario "${scenario}" --backend memory --objects 64 --object-size "${size}"
          --logical-path-len 32 --commit-batch-items "${batch}"
          --commit-max-pending-items "${batch}" --commit-batch-delay-ms 60000
          --concurrency "${concurrency}" "${ceiling[@]}" --format jsonl)
        printf '%q ' "${command[@]}" >> "${evidence_dir}/commands.txt"
        printf '> %q\n' "${report}" >> "${evidence_dir}/commands.txt"
        verify_source
        echo "small-workload run ${run}/${runs}: ${lane}" >&2
        if ! "${command[@]}" | tee "${report}"; then
          failed=1
        fi
        if ! python3 - "${report}" "${build_revision}" "${scenario}" "${size}" "${batch}" <<'PYVERIFY'
    import json, sys
    path, revision, scenario, size, batch = sys.argv[1:]
    with open(path, encoding="utf-8") as source:
        records = [json.loads(line) for line in source if line.strip()]
    assert len(records) == 1, "one raw measurement is required per workload/run"
    record = records[0]
    assert revision != "unknown" and not revision.endswith("-dirty")
    assert record["source_revision"] == revision, "compiled revision differs from selected source"
    assert record["scenario"] == scenario and record["backend_name"] == "memory"
    assert record["objects"] == 64 and record["object_size"] == int(size)
    assert record["logical_path_len"] == 32
    assert record["commit"]["batch_items"] == int(batch)
    assert record["backend"]["puts"] == (1 if scenario == "write-batch" else 64), "workload publication shape changed"
    assert record["checkpoint"] is None, "small-write budgets exclude final checkpoint"
    assert record["requested_plaintext_write_bytes"] == 64 * int(size)
    PYVERIFY
        then
          failed=1
        fi
      done
    done
    verify_source
    sha256sum --check "${evidence_dir}/binary.sha256"
    exit "${failed}"

# Run the fixed release-profile object-count scale tiers. Set
# RS3_SCALE_GATE_RUNS to change the default three-run stability sample.
[private]
perf-scale-tier OBJECTS BATCH="0" MIN_COMPACTIONS="0" OBJECT_SIZE="512":
    #!/usr/bin/env bash
    set -euo pipefail
    runs="${RS3_SCALE_GATE_RUNS:-3}"
    if ! [[ "${runs}" =~ ^[1-9][0-9]*$ ]]; then
      echo "RS3_SCALE_GATE_RUNS must be a positive integer" >&2
      exit 2
    fi
    build_revision="$(git rev-parse --verify HEAD)"
    if ! git diff --quiet --ignore-submodules -- || ! git diff --cached --quiet --ignore-submodules --; then
      build_revision="${build_revision}-dirty"
    fi
    RS3_BUILD_GIT_SHA="${build_revision}" cargo build --release -p xtask --bin xtask
    batch_items=64
    concurrency=64
    max_write_amp=1.50
    checkpoint_after={{OBJECTS}}
    if (( checkpoint_after >= 100000 )); then
      batch_items=4096
      concurrency=4096
      max_write_amp=1.30
    fi
    if (( {{BATCH}} > 0 )); then
      batch_items={{BATCH}}
      concurrency={{BATCH}}
    fi
    report="$(mktemp)"
    trap 'rm -f "${report}"' EXIT
    for ((run = 1; run <= runs; run++)); do
      echo "scale gate run ${run}/${runs}: {{OBJECTS}} objects" >&2
      target/release/xtask perf \
        --scenario write-committed-parallel \
        --objects "{{OBJECTS}}" \
        --object-size "{{OBJECT_SIZE}}" \
        --commit-batch-items "${batch_items}" \
        --commit-max-pending-items "${batch_items}" \
        --concurrency "${concurrency}" \
        --verify-reload \
        --checkpoint-after-objects "${checkpoint_after}" \
        --max-elapsed-seconds 180 \
        --max-reload-elapsed-seconds 30 \
        --max-peak-rss-bytes 4294967296 \
        --max-write-amp "${max_write_amp}" \
        --max-cold-read-amp 1.04 \
        --max-cold-read-requests-per-read 1.0 \
        --max-active-index-runs 255 \
        --format jsonl | tee "${report}"
      python3 -c 'import json, sys; rows = [json.loads(line) for line in open(sys.argv[1])]; assert len(rows) == 1, "missing scale report"; count = rows[0]["observed_compactions"]; assert count >= int(sys.argv[2]), f"observed only {count} compactions"' "${report}" "{{MIN_COMPACTIONS}}"
    done

# Fast scale gate for pull requests and local development.
perf-scale-10k: (perf-scale-tier "10000")

# Exercise automatic compaction with one 16-object run per write wave.
perf-scale-10k-compaction: (perf-scale-tier "10000" "16" "1" "1024")

# Release-candidate scale gate.
perf-scale-100k: (perf-scale-tier "100000")

# Scheduled/manual high-capacity scale gate. This needs substantial memory.
perf-scale-1m: (perf-scale-tier "1000000")

# Enforce exact logical-path-length write-amplification evidence without
# conflating it with the automatic-compaction lifetime lane.
[private]
perf-scale-path-matrix-tier OBJECTS:
    #!/usr/bin/env bash
    set -euo pipefail
    runs="${RS3_SCALE_GATE_RUNS:-3}"
    if ! [[ "${runs}" =~ ^[1-9][0-9]*$ ]]; then
      echo "RS3_SCALE_GATE_RUNS must be a positive integer" >&2
      exit 2
    fi
    build_revision="$(git rev-parse --verify HEAD)"
    if ! git diff --quiet --ignore-submodules -- || ! git diff --cached --quiet --ignore-submodules --; then
      build_revision="${build_revision}-dirty"
    fi
    RS3_BUILD_GIT_SHA="${build_revision}" cargo build --release -p xtask --bin xtask
    for specification in "32:1.32" "256:1.80" "1024:3.40"; do
      path_len="${specification%%:*}"
      max_write_amp="${specification##*:}"
      for ((run = 1; run <= runs; run++)); do
        echo "path matrix run ${run}/${runs}: {{OBJECTS}} objects, ${path_len}-byte paths" >&2
        target/release/xtask perf \
          --scenario write-committed-parallel \
          --objects "{{OBJECTS}}" \
          --object-size 512 \
          --logical-path-len "${path_len}" \
          --commit-batch-items 64 \
          --commit-max-pending-items 64 \
          --concurrency 64 \
          --verify-reload \
          --checkpoint-after-objects "{{OBJECTS}}" \
          --max-elapsed-seconds 180 \
          --max-reload-elapsed-seconds 30 \
          --max-peak-rss-bytes 4294967296 \
          --max-write-amp "${max_write_amp}" \
          --max-cold-read-amp 1.04 \
          --max-cold-read-requests-per-read 1.0 \
          --max-active-index-runs 255 \
          --format jsonl
      done
    done

# Three-run 10k matrix for 32, 256, and 1,024-byte logical paths.
perf-scale-path-matrix: (perf-scale-path-matrix-tier "10000")

# Run the pinned fresh-process filesystem scale tier. ROOT must name retained
# local-disk evidence storage; each run keeps its backend and reports.
[private]
perf-scale-fs-tier OBJECTS ROOT:
    #!/usr/bin/env bash
    set -euo pipefail
    runs="${RS3_SCALE_GATE_RUNS:-3}"
    if ! [[ "${runs}" =~ ^[1-9][0-9]*$ ]]; then
      echo "RS3_SCALE_GATE_RUNS must be a positive integer" >&2
      exit 2
    fi
    mkdir -p "{{ROOT}}"
    build_revision="$(git rev-parse --verify HEAD)"
    if ! git diff --quiet --ignore-submodules -- || ! git diff --cached --quiet --ignore-submodules --; then
      build_revision="${build_revision}-dirty"
    fi
    RS3_BUILD_GIT_SHA="${build_revision}" cargo build --release -p xtask --bin xtask
    batch_items=64
    concurrency=64
    max_write_amp=1.50
    if (( {{OBJECTS}} >= 100000 )); then
      batch_items=4096
      concurrency=4096
      max_write_amp=1.30
    fi
    stamp="$(date -u +%Y%m%dT%H%M%SZ)-$$"
    for ((run = 1; run <= runs; run++)); do
      run_root="{{ROOT}}/${stamp}-objects-{{OBJECTS}}-run-${run}"
      backend_dir="${run_root}/backend"
      evidence_dir="${run_root}/evidence"
      echo "fresh-process filesystem scale run ${run}/${runs}: {{OBJECTS}} objects" >&2
      target/release/xtask perf \
        --scenario write-committed-parallel \
        --objects "{{OBJECTS}}" \
        --object-size 512 \
        --commit-batch-items "${batch_items}" \
        --commit-max-pending-items "${batch_items}" \
        --concurrency "${concurrency}" \
        --verify-reload \
        --fresh-process-reload \
        --checkpoint-after-objects "{{OBJECTS}}" \
        --backend filesystem \
        --backend-dir "${backend_dir}" \
        --evidence-dir "${evidence_dir}" \
        --max-elapsed-seconds 180 \
        --max-reload-elapsed-seconds 180 \
        --max-writer-peak-rss-bytes 4294967296 \
        --max-reader-peak-rss-bytes 4294967296 \
        --max-write-amp "${max_write_amp}" \
        --max-cold-read-amp 1.04 \
        --max-cold-read-requests-per-read 1.0 \
        --max-active-index-runs 255 \
        --format jsonl
      {
        uname -a
        rustc -Vv
        df -T "${backend_dir}"
      } > "${evidence_dir}/runner.txt"
    done

# Fresh-process filesystem qualification tiers. Pass a pinned local-disk root.
perf-scale-fs-10k ROOT: (perf-scale-fs-tier "10000" ROOT)
perf-scale-fs-100k ROOT: (perf-scale-fs-tier "100000" ROOT)
perf-scale-fs-1m ROOT: (perf-scale-fs-tier "1000000" ROOT)

# Complete fresh-process scale and amplification sample for a release candidate.
# Run on the documented pinned runner and retain ROOT as release evidence.
preview-gate-scale-candidate ROOT:
    just perf-scale-path-matrix
    just perf-scale-fs-10k "{{ROOT}}"
    just perf-scale-fs-100k "{{ROOT}}"
    just perf-scale-fs-1m "{{ROOT}}"

# Run one bounded three-sample real-client profile with revision-bound evidence.
# Invoke once for each profile listed in the release process.
perf-kopia-profile-candidate PROFILE:
    #!/usr/bin/env bash
    set -euo pipefail
    build_revision="$(git rev-parse --verify HEAD)"
    if ! git diff --quiet --ignore-submodules -- || ! git diff --cached --quiet --ignore-submodules --; then
      build_revision="${build_revision}-dirty"
    fi
    export RS3_BUILD_GIT_SHA="${build_revision}"
    cargo build -p xtask --bin xtask --features containers
    cargo build --release -p rs3-server --bin rs3-server --features s3
    cargo build -p xtask --bin rs3-integration-storage-proxy
    target/debug/xtask integration kopia-measured-matrix \
      --runs 3 \
      --profile-set single \
      --workload-profile "{{PROFILE}}" \
      --gateway-build-profile release \
      --enforce-regression-budgets

# Run performance measurements against an S3 backend.
perf-s3 *ARGS:
    cargo run -p xtask --bin xtask --features s3 -- perf --backend s3 {{ARGS}}

# Run performance measurements against a container S3 backend.
perf-s3-container *ARGS:
    cargo run -p xtask --bin xtask --features containers -- perf --backend s3-container {{ARGS}}

# Run performance measurements through a containerized gateway.
perf-s3-gateway *ARGS:
    cargo run -p xtask --bin xtask --features containers -- perf --backend s3-gateway-container {{ARGS}}

# Qualify concurrent known-length standalone writes through the release gateway,
# then reload and exactly read every object through a fresh repository instance.
perf-standalone-gate:
    #!/usr/bin/env bash
    set -euo pipefail
    build_revision="$(git rev-parse --verify HEAD)"
    if ! git diff --quiet --ignore-submodules -- || ! git diff --cached --quiet --ignore-submodules --; then
      build_revision="${build_revision}-dirty"
    fi
    RS3_BUILD_GIT_SHA="${build_revision}" cargo build --release -p xtask --bin xtask --features containers
    # Keep cold compilation outside the gateway's bounded readiness wait.
    RS3_BUILD_GIT_SHA="${build_revision}" cargo build --release -p rs3-server --features s3
    objects=8
    object_size=67108865
    baseline_throughput=""
    for concurrency in 1 2 4 8; do
      output="$(target/release/xtask perf \
        --backend s3-gateway-container \
        --gateway-build-profile release \
        --scenario write-standalone-parallel \
        --objects "${objects}" \
        --concurrency "${concurrency}" \
        --object-size "${object_size}" \
        --commit-batch-items 1 \
        --max-write-amp 1.02 \
        --max-verification-read-amp 1.02 \
        --max-total-write-io-amp 2.04 \
        --max-elapsed-seconds 240 \
        --max-peak-rss-bytes 1073741824 \
        --format jsonl)"
      printf '%s\n' "${output}"
      throughput="$(printf '%s\n' "${output}" | sed -n 's/.*"plaintext_mib_s":\([0-9.eE+-]*\).*/\1/p')"
      if [[ -z "${throughput}" ]]; then
        echo "standalone gate could not parse plaintext throughput" >&2
        exit 1
      fi
      if (( concurrency == 1 )); then
        baseline_throughput="${throughput}"
      elif (( concurrency == 8 )); then
        if ! awk -v baseline="${baseline_throughput}" -v current="${throughput}" \
          'BEGIN { exit !(current >= baseline * 2.0) }'; then
          echo "standalone concurrency-8 throughput ${throughput} MiB/s is below 2x concurrency-1 ${baseline_throughput} MiB/s" >&2
          exit 1
        fi
      fi
    done
    target/release/xtask perf \
      --backend s3-container \
      --gateway-build-profile release \
      --scenario write-standalone-parallel \
      --objects "${objects}" \
      --concurrency 8 \
      --object-size "${object_size}" \
      --commit-batch-items 1 \
      --verify-reload \
      --expected-multipart-parts-per-object 5 \
      --max-write-amp 1.02 \
      --max-verification-read-amp 1.02 \
      --max-total-write-io-amp 2.04 \
      --max-cold-read-amp 1.02 \
      --max-cold-read-requests-per-read 1 \
      --max-reload-elapsed-seconds 30 \
      --max-elapsed-seconds 240 \
      --max-peak-rss-bytes 1073741824 \
      --format jsonl

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
