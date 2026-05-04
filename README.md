# rs3

`rs3` is an experimental Rust workspace for a path-private, tamper-evident,
S3-compatible backup gateway for Kubernetes operators.

## Status

The project has a working local S3-compatible gateway path, repository
encryption boundaries, signed checkpoint plumbing, integration harnesses,
Kubernetes Lease anchoring, restore verification, production posture checks, and
Kopia-focused performance measurement. The current release target is a
production preview: suitable for controlled evaluation, not yet a stable
repository-format or security guarantee.

Current engineering priorities:

- path privacy for client-visible keys and Kubernetes object names
- rollback resistance through signed checkpoints and external anchors
- restore correctness for S3-oriented backup tools, with Kopia and
  Velero/Kopia as the preview clients
- measured performance against a straight proxy baseline
- operational evidence for retention, tracing, and metrics

See `docs/site/production-preview.md` for the preview contract and release
gates.

## Development

This project is Nix-first.

```sh
nix develop
just check
```

Equivalent Cargo commands inside the shell:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
mkdocs build --strict
```

The documentation site uses Material for MkDocs:

```sh
just docs-check
just docs-build
just docs-serve
```

The public docs source lives under `docs/site/`.

For faster local feedback, use `just nextest` when standard Cargo test output is
not required. Use `cargo build --timings` when investigating compile-time
regressions.

Real S3 backend checks are opt-in so the normal edit/test loop stays small:

```sh
just check-s3
just integration-s3
just integration-s3-local
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
use an `http://` / `https://` endpoint URL for an S3-compatible service. For the
production-preview shape, configure an encrypted keyring envelope with
`RS3_KEYRING_WRAPPING_KEY_HEX`, `RS3_REPOSITORY_ID`, and a stable public
`RS3_REPOSITORY_SALT_HEX`. `RS3_KEYRING_WRAPPING_KEY_ID` defaults to `wrap-v1`;
`RS3_KEYRING_ENVELOPE_OBJECT_ID` is only a bootstrap or recovery override.

`just integration-s3-local` is the orchestration entrypoint for local S3
integration checks. It currently expects a provided endpoint and delegates to
the live storage contract test; container and Kubernetes startup can be added
behind this command.

The Nix shell includes `sccache` for clean rebuild or CI-like cache experiments,
but it is not enabled by default. Set `RUSTC_WRAPPER=sccache` for runs where that
tradeoff is useful.

## Workspace Layout

- `crates/rs3-anchor`: checkpoint-anchor contract and test anchor.
- `crates/rs3-types`: shared strongly typed identifiers and policy types.
- `crates/rs3-crypto`: cryptographic primitives, envelopes, and key derivation
  boundaries.
- `crates/rs3-index`: append-friendly index and checkpoint model.
- `crates/rs3-storage`: object-store abstraction.
- `crates/rs3-k8s`: Kubernetes checkpoint-anchor abstraction.
- `crates/rs3-repository`: repository write, read, checkpoint, and maintenance
  behavior.
- `crates/rs3-server`: command-line gateway process and S3 compatibility layer.
- `xtask`: local automation used by `just`.

Start with `docs/site/index.md` for the curated project map.
