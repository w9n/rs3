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

test:
    cargo test --workspace

nextest:
    cargo nextest run --workspace

deny:
    cargo deny check

audit:
    cargo audit

doc:
    cargo doc --workspace --no-deps
