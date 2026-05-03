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

check-s3:
    cargo clippy -p rs3-storage -p rs3-server -p xtask --features rs3-server/s3,xtask/s3 --all-targets -- -D warnings
    cargo test -p rs3-storage -p rs3-server -p xtask --features rs3-server/s3,xtask/s3

integration-s3:
    cargo test -p rs3-storage --features s3 --test s3_live -- --ignored --nocapture

integration-s3-local *ARGS:
    cargo run -p xtask -- integration s3-local {{ARGS}}

integration-s3-container *ARGS:
    cargo run -p xtask --features containers -- integration s3-local --mode container {{ARGS}}

test:
    cargo test --workspace

perf *ARGS:
    cargo run -p xtask -- perf {{ARGS}}

perf-s3 *ARGS:
    cargo run -p xtask --features s3 -- perf --backend s3 {{ARGS}}

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
