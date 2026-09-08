# rs3

`rs3` is an experimental Rust workspace for a path-private, tamper-evident,
S3-compatible backup gateway for Kubernetes operators.

For the operator path, start with [Deploy, Back Up, and Restore](docs/site/deploy-backup-restore.md): configure once, let Helm initialize the repository, then use the same gateway for backups and ordinary restores.

## Status

The project has a working local S3-compatible gateway path, repository
encryption boundaries, signed v03 commits and anchors, integration harnesses,
Kubernetes Lease anchoring, restore-bundle workflows, production posture checks,
and Kopia-focused performance measurement. The current release target is a
production preview: suitable for controlled evaluation, not yet a stable
repository-format or security guarantee. New preview repositories use the
`v3-preview` repository format; it is the only format accepted by the current
gateway.

Bounded nonempty writes publish a ciphertext-only `PAYLOAD_PACK` with an
`INDEX_RUN`. Large or unknown-length nonempty streams upload one opaque detached
payload, verify its complete stored ciphertext, then publish a short
`[INDEX_RUN]` commit containing the encrypted exact reference. Empty values are
index-only. Checkpoints, recovery, compaction and garbage collection preserve
exact payload references without copying ciphertext. Success requires accepted,
anchored publication; an uploaded payload alone is not visible repository state.

Current engineering priorities:

- path privacy for client-visible keys and Kubernetes object names
- rollback resistance through signed commits and external anchors
- restore correctness for S3-oriented backup tools, with Kopia and
  Velero/Kopia as the preview clients
- incident restore through an explicit `restore-readonly` gateway mode and
  trusted restore bundles
- measured performance against a straight proxy baseline
- operational evidence for retention, tracing, and metrics

See `docs/site/production-preview.md` for the preview contract and release
gates, and `docs/site/release-process.md` for the artifact and publication
checklist.

The separate `rs3-console` crate is experimental operator tooling outside the
production-preview gateway deployment contract. The gateway image and
`rs3-gateway` Helm chart do not include or deploy it; run it separately for
local or controlled inspection.

## Development

This project is Nix-first.

```sh
nix develop
just check
```

Equivalent Cargo commands inside the shell:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
mkdocs build --strict
```

The documentation site uses Material for MkDocs:

```sh
just docs-check
just docs-build
just docs-serve
```

The public docs source lives under `docs/site/`. Keep working notes and
uncurated design material out of the tracked documentation tree.

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
`RS3_KEYRING_WRAPPING_KEY_HEX` and `RS3_REPOSITORY_ID`; the public salt is
generated at initialization and recovered from the verified envelope, with
`RS3_REPOSITORY_SALT_HEX` only pinning a known value. The wrapping key must be
high-entropy key material;
derive human passphrases outside `rs3`. `RS3_KEYRING_WRAPPING_KEY_ID` defaults
to `wrap-v1`; `RS3_KEYRING_ENVELOPE_OBJECT_ID` is only a bootstrap or recovery
override.

`just integration-s3-local` is the orchestration entrypoint for local S3
integration checks. Use `--mode container` for a disposable local provider, or
`--mode provided` with the S3 environment above when qualifying an existing
endpoint.

The Nix shell includes `sccache` for clean rebuild or CI-like cache experiments,
but it is not enabled by default. Set `RUSTC_WRAPPER=sccache` for runs where that
tradeoff is useful.

## Workspace Layout

- `crates/rs3-console`: experimental, read-only single-gateway operations
  console. It is outside the gateway image, Helm chart, and production-preview
  deployment contract.
- `crates/rs3-types`: shared strongly typed identifiers and policy types.
- `crates/rs3-crypto`: cryptographic primitives, envelopes, and key derivation
  boundaries.
- `crates/rs3-index`: append-friendly index and repository state model.
- `crates/rs3-storage`: object-store abstraction.
- `crates/rs3-k8s`: Kubernetes anchor integration surface.
- `crates/rs3-repository`: repository write, read, anchor contracts, commit,
  and maintenance behavior.
- `crates/rs3-server`: command-line gateway process and S3 compatibility layer.
- `xtask`: local automation used by `just`.

Start with `docs/site/index.md` for the curated project map.

## License

`rs3` is licensed under the GNU Affero General Public License v3.0 only
(`AGPL-3.0-only`). See `LICENSE` for the full text.

The AGPL covers network use. If you run a modified `rs3` gateway and let others
interact with it over a network, section 13 requires you to offer those users
the corresponding source of your modified version.

Security reports go through GitHub private vulnerability reporting; see
`SECURITY.md`.
