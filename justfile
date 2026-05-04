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

# Cheap production-preview gate for local handoff.
preview-gate-local:
    just check
    just check-s3
    just deny
    just deny-s3

# Expensive production-preview integration gate for release candidates.
preview-gate-release:
    just integration-kopia-gateway
    just integration-velero-kopia-dynamic-pvc-gateway-restart-smoke
    just integration-velero-kopia-postgres-smoke

integration-s3:
    cargo test -p rs3-storage --features s3 --test s3_live -- --ignored --nocapture

integration-s3-local *ARGS:
    cargo run -p xtask --bin xtask -- integration s3-local {{ARGS}}

integration-s3-container *ARGS:
    cargo run -p xtask --bin xtask --features containers -- integration s3-local --mode container {{ARGS}}

integration-s3-gateway *ARGS:
    cargo run -p xtask --bin xtask --features containers -- integration s3-gateway {{ARGS}}

integration-kopia-gateway *ARGS:
    cargo run -p xtask --bin xtask --features containers -- integration kopia-gateway {{ARGS}}

integration-k8s-gateway *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration k8s-gateway {{ARGS}}

integration-velero-kopia-smoke *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-smoke {{ARGS}}

integration-velero-kopia-local-pv-smoke *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-local-pv-smoke {{ARGS}}

integration-velero-kopia-dynamic-pvc-smoke *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-dynamic-pvc-smoke {{ARGS}}

integration-velero-kopia-dynamic-pvc-gateway-restart-smoke *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-dynamic-pvc-gateway-restart-smoke {{ARGS}}

integration-velero-kopia-postgres-smoke *ARGS:
    cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-postgres-smoke {{ARGS}}

helm-lint:
    helm lint charts/rs3-gateway \
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
