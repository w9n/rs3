# rs3

`rs3` is an experimental Rust workspace for an S3-compatible backup gateway.

## Status

This repository is a clean-room scaffold. The current code defines workspace
boundaries, typed contracts, and initial implementation tests. It intentionally
does not contain a wire-compatible gateway implementation yet.

## Development

This project is Nix-first.

```sh
nix develop
just check
```

Equivalent Cargo commands inside the shell:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

For faster local feedback, use `just nextest` when standard Cargo test output is
not required. Use `cargo build --timings` when investigating compile-time
regressions.

Real S3 backend checks are opt-in so the normal edit/test loop stays small:

```sh
just check-s3
just integration-s3
just deny-s3
just perf-s3 --s3-bucket test-bucket --s3-endpoint-url http://localhost:9000 --s3-allow-http
```

`just integration-s3` runs the ignored live storage-contract test against an
existing S3-compatible endpoint. Set `RS3_TEST_S3_BUCKET` and standard AWS
credential environment variables before running it. Optional knobs:
`RS3_TEST_S3_ENDPOINT_URL`, `RS3_TEST_S3_REGION`, `RS3_TEST_S3_PREFIX`,
`RS3_TEST_S3_PROVIDER`, `RS3_TEST_S3_ALLOW_HTTP`, and
`RS3_TEST_S3_VIRTUAL_HOSTED_STYLE`.

The `rs3-server/s3` feature enables the server runtime to use the S3-compatible
storage adapter. Set `RS3_BACKEND_ENDPOINT=s3` for the default AWS endpoint, or
use an `http://` / `https://` endpoint URL for an S3-compatible service.

The Nix shell includes `sccache` for clean rebuild or CI-like cache experiments,
but it is not enabled by default. Set `RUSTC_WRAPPER=sccache` for runs where that
tradeoff is useful.

## Workspace Layout

- `crates/rs3-types`: shared strongly typed identifiers and policy types.
- `crates/rs3-crypto`: cryptographic primitives and key derivation boundaries.
- `crates/rs3-index`: append-friendly encrypted index and checkpoint model.
- `crates/rs3-storage`: object-store abstraction.
- `crates/rs3-k8s`: Kubernetes checkpoint-anchor abstraction.
- `crates/rs3-server`: command-line entry point for the future gateway.
- `xtask`: local automation used by `just`.

Additional design notes will be added as interfaces stabilize.
