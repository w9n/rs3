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

Local integration lanes also need the tooling for the lane being run:

| Lane | Additional tools |
| --- | --- |
| Disposable S3 and Kopia lanes | Docker-compatible container runtime, Kopia, `mc`, and `rclone` from the Nix shell. |
| Kubernetes and Velero lanes | Docker-compatible container runtime, `kind`, `kubectl`, Helm, Velero CLI, and the chart dependencies from the Nix shell. |
| Live S3-compatible provider lanes | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, provider region, endpoint URL, empty bucket or fresh prefix, and provider retention/Object Lock when testing the retained-version profile. |

Use [Testing](testing.md) for the full lane matrix and [Configuration](reference/configuration.md)
for runtime variables.

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
RS3_ALLOW_REPOSITORY_INIT=true \
RS3_REPOSITORY_ID=local-dev \
RS3_REPOSITORY_SALT_HEX=2222222222222222222222222222222222222222222222222222222222222222 \
RS3_KEYRING_WRAPPING_KEY_HEX=3333333333333333333333333333333333333333333333333333333333333333 \
RS3_STATIC_ACCESS_KEY_ID=local \
RS3_STATIC_SECRET_ACCESS_KEY=local-secret \
cargo run -p rs3-server -- serve --bind 127.0.0.1:9080
```

On first start with an empty backend prefix, `RS3_ALLOW_REPOSITORY_INIT=true`
lets the gateway write an encrypted keyring envelope under `keyrings/` and use
`v2-preview` by default. Leave that switch unset for existing repositories and
recover a missing anchor from a trusted bundle instead. The memory anchor is
only for local development; it is not a production rollback boundary.

With the gateway still running, use a second shell to write and list an object
through the S3 API:

```sh
printf 'hello rs3\n' >/tmp/rs3-smoke.txt

AWS_ACCESS_KEY_ID=local \
AWS_SECRET_ACCESS_KEY=local-secret \
AWS_DEFAULT_REGION=us-east-1 \
aws --endpoint-url http://127.0.0.1:9080 \
  s3 cp /tmp/rs3-smoke.txt s3://backup/smoke/hello.txt

AWS_ACCESS_KEY_ID=local \
AWS_SECRET_ACCESS_KEY=local-secret \
AWS_DEFAULT_REGION=us-east-1 \
aws --endpoint-url http://127.0.0.1:9080 \
  s3 ls s3://backup/smoke/
```

The same round trip with `mc` is:

```sh
mc alias set rs3-local http://127.0.0.1:9080 local local-secret
mc cp /tmp/rs3-smoke.txt rs3-local/backup/smoke/hello.txt
mc ls rs3-local/backup/smoke/
```

## Run S3 Contract Checks

Local S3-compatible checks are opt-in:

```sh
just integration-s3-local --mode container
just integration-s3-gateway
```

Live provider checks require an existing S3-compatible endpoint and credentials:

```sh
export AWS_ACCESS_KEY_ID=<access-key-id>
export AWS_SECRET_ACCESS_KEY=<secret-access-key>
export AWS_REGION=<region>
export RS3_GOVERNANCE_BYPASS_REVIEWED=true # after IAM or bucket-policy review
just preview-gate-v2-live <bucket> <endpoint> <region>
```

Use an empty bucket or a fresh backend prefix for live trials. When evaluating
the retained-version profile, enable provider versioning and Object Lock before
running the gate.

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
