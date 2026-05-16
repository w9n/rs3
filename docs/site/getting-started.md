# Getting Started

This page gives the local development path. If you are evaluating whether `rs3`
is worth a controlled trial, start with [Evaluation](evaluation.md) first.
Production deployment guidance stays conservative until the repository format
and anchor integrations are stable.

## Prerequisites

Use the Nix shell:

```sh
nix develop
```

Inside the shell, the default verification command is:

```sh
just check
```

The equivalent manual path is:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
mkdocs build --strict
```

## Build The Docs

```sh
just docs-check
just docs-build
```

For local browsing:

```sh
just docs-serve
```

The site builds from `docs/site/` into `target/mkdocs-site/`.

## Run A Local Gateway Smoke

The gateway runtime is configured through environment variables. A local
development run can use the memory anchor only when it is explicitly allowed.

```sh
RS3_PUBLIC_BUCKET=backup \
RS3_BACKEND_ENDPOINT=file:///tmp/rs3-backend \
RS3_BACKEND_BUCKET=repo \
RS3_ANCHOR_MODE=memory \
RS3_ALLOW_MEMORY_ANCHOR=true \
RS3_REPOSITORY_ID=local-dev \
RS3_REPOSITORY_SALT_HEX=2222222222222222222222222222222222222222222222222222222222222222 \
RS3_KEYRING_WRAPPING_KEY_HEX=3333333333333333333333333333333333333333333333333333333333333333 \
RS3_STATIC_ACCESS_KEY_ID=local \
RS3_STATIC_SECRET_ACCESS_KEY=local-secret \
cargo run -p rs3-server -- serve --bind 127.0.0.1:9080
```

On first start with an empty backend prefix, the gateway writes an encrypted
keyring envelope under `keyrings/` and uses `v2-preview` by default. The memory
anchor is only for local development; it is not a production rollback boundary.

## Run S3 Contract Checks

Local S3-compatible checks are opt-in:

```sh
just integration-s3-local --mode container
just integration-s3-gateway
```

Live provider checks require an existing S3-compatible endpoint and credentials:

```sh
RS3_TEST_S3_BUCKET=<bucket> \
RS3_TEST_S3_ENDPOINT_URL=<endpoint> \
RS3_TEST_S3_REGION=<region> \
just integration-s3
```

## Run Kopia Measurement

The Kopia matrix compares the gateway to a straight RustFS proxy baseline:

```sh
cargo run -p xtask --bin xtask --features containers -- integration kopia-measured-matrix \
  --runs 3 \
  --profile-set larger-restores \
  --gateway-build-profile release
```

Artifacts are written under `.local/integration/` by default. They are local
evidence and should not be staged without review.
