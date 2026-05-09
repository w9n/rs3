# Agent Instructions

Repository-wide instructions. A deeper `AGENTS.md` overrides these.

## Mission

Build `rs3` as a path-private, tamper-evident, S3-compatible backup gateway for
Kubernetes operators. Path privacy, rollback resistance, and restore correctness
are product requirements.

## Local Checks

Use the Nix shell first:

```sh
nix develop
just check
```

Fallback when `just` is unavailable:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
mkdocs build --strict
```

## Engineering Rules

- Preserve path privacy. Do not place plaintext paths, directory names,
  Kubernetes object names, namespaces, or snapshot names in object-store keys,
  unauthenticated metadata, logs, metrics labels, or errors.
- Prefer typed identifiers in `rs3-types` over raw strings.
- Keep cryptography behind `rs3-crypto`; do not scatter ad hoc hashing, MAC,
  encryption, signing, or key-derivation logic across crates.
- Model repository changes as append-friendly deltas plus signed checkpoints.
  Avoid designs that rewrite many objects during normal operation.
- Treat S3-compatible stores as eventually inconsistent unless a storage
  implementation documents a stronger provider contract.
- Treat Kopia/Velero as the first compatibility workload. Preserve prefix
  listing, metadata-only `HEAD`, range `GET`, and read/list-after-write behavior.
- Kubernetes rollback anchors fail closed. If an anchor cannot be read or
  advanced, do not accept newer-looking repository state silently.
- Avoid `unsafe`. Avoid `unwrap`, `expect`, `todo`, and `dbg` in production
  code. Tests may use `expect` when it improves failure clarity.
- Keep public APIs small, documented, and preview-scoped unless deliberately
  stabilized.
















## Privacy Review

For each feature, know what the object store can observe: path hierarchy,
filename equality, object counts, file sizes, write cadence, tenant identity, or
Kubernetes resource names. Document necessary leakage in
`docs/site/security-model.md`, and verify rollback behavior when the backend can
list, delete, delay, or replay objects.

## Documentation Sync

- `docs/site/` is the public documentation source.
- Keep behavior, security, performance, operations, repository-format, and
  compatibility changes synchronized with docs in the same commit.
- Use `just docs-check` for docs-only changes and `just check` before handoff
  when practical.

## Agent Workflow

- Before non-trivial work, update the active plan with requirements,
  constraints, and intended verification.
- When new user instructions arrive, compare them with the active plan and
  prior requirements first. If they conflict, let the newest instruction steer
  and update the plan before editing.
- Before architecture/security/repository-format edits, read relevant current
  docs: `README.md`, `docs/site/index.md`, `docs/site/architecture.md`,
  `docs/site/security-model.md`, and
  `docs/site/reference/repository-format.md`.
- Keep patches small and behavior-focused. Add tests with code changes unless
  the change is docs-only.
- Before committing, review `git status --short --ignored` and
  `git diff --cached --name-only`; do not stage ignored workspace-local context.

## Design Biases

- Favor explicit manifests and signed checkpoints over implicit latest objects.
- Favor bounded batch reads over one-read-per-file listings.
- Favor provider-neutral semantics first; add S3-specific acceleration behind
  feature flags.
- Favor Kubernetes-native coordination for the first deployment target.
