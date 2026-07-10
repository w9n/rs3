# Agent Instructions

Repository-wide instructions. A deeper `AGENTS.md` overrides these.

## Product Contract

`rs3` is a path-private, tamper-evident, S3-compatible backup gateway for
Kubernetes operators. Path privacy, rollback resistance, and restore
correctness are product requirements.

## Checks

Use the Nix shell first; run `just check` before handoff when practical:

```sh
nix develop
just check
```

For docs-only changes, prefer `just docs-check`. Fallback when `just` is
unavailable:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
mkdocs build --strict
```

## Hard Rules

- Preserve path privacy: no plaintext paths, directory names, Kubernetes object
  names, namespaces, or snapshot names in object-store keys, unauthenticated
  metadata, logs, metrics labels, or errors.
- Keep cryptography in `rs3-crypto`; prefer typed IDs in `rs3-types`.
- Model repository changes as append-friendly deltas plus signed commits and
  external anchors; avoid designs that rewrite many objects during normal
  operation.
- Treat S3-compatible stores as eventually inconsistent unless documented
  otherwise.
- Kubernetes rollback anchors fail closed. If an anchor cannot be read or
  advanced, do not silently accept newer-looking repository state.
- Preserve Kopia/Velero compatibility: prefix listing, metadata-only `HEAD`,
  range `GET`, and read/list-after-write behavior.
- Avoid `unsafe`, `unwrap`, `expect`, `todo`, and `dbg` in production code.
  Tests may use `expect` when it improves failure clarity.
- Keep public APIs small, documented, and preview-scoped unless deliberately
  stabilized.

## Docs And Context

- `docs/site/` is the public documentation source; keep behavior, security,
  performance, operations, repository-format, and compatibility changes synced.
- For each feature, know what the object store can observe: path hierarchy,
  filename equality, object counts, file sizes, write cadence, tenant identity,
  and Kubernetes resource names. Document necessary leakage in
  `docs/site/security-model.md` and verify rollback behavior when the backend
  can list, delete, delay, or replay objects.
- Before architecture, security, repository-format, anchoring, retention,
  compatibility, or observability work, read:
  `README.md`, `docs/site/index.md`, `docs/site/architecture.md`,
  `docs/site/security-model.md`, `docs/site/reference/repository-format.md`.

## Workflow

- Before non-trivial work, update the active plan with requirements,
  constraints, and intended verification.
- When new user instructions arrive, compare them with the active plan and let
  the newest instruction steer if they conflict.
- Keep patches small and behavior-focused. Add tests with code changes unless
  the change is docs-only.
- Before committing, review `git status --short --ignored` and
  `git diff --cached --name-only`; do not stage ignored workspace-local context.

## Design Biases

- Favor explicit manifests and signed commits over implicit latest objects.
- Favor bounded batch reads over one-read-per-file listings.
- Favor provider-neutral semantics first; add S3-specific acceleration behind
  feature flags.
- Favor Kubernetes-native coordination for the first deployment target.
