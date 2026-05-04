# Agent Instructions

These instructions apply to the whole repository unless a deeper `AGENTS.md`
overrides them.

## Mission

Build `rs3` as a path-private, tamper-evident, S3-compatible backup gateway for
Kubernetes operators. Treat path privacy, rollback resistance, and restore
correctness as product requirements.

## Local Environment

Use the Nix shell first:

```sh
nix develop
```

Inside the shell, use:

```sh
just check
```

If `just` is unavailable, run:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
mkdocs build --strict
```

## Engineering Rules

- Preserve path privacy in new designs. Do not put plaintext paths, directory
  names, Kubernetes object names, namespaces, or snapshot names in object-store
  keys or unauthenticated metadata.
- Prefer typed identifiers in `rs3-types` over raw strings.
- Keep cryptographic operations behind `rs3-crypto`; do not spread ad hoc
  hashing, MAC, encryption, or key-derivation logic across crates.
- Model repository-state changes as append-friendly deltas plus checkpoints.
  Avoid designs that require rewriting many objects during normal operation.
- Treat Kopia as the first compatibility workload. Preserve efficient prefix
  listing, metadata-only HEAD, range GET, and immediate read/list-after-write
  semantics when changing gateway or storage contracts.
- Treat S3-compatible object stores as eventually inconsistent unless a
  provider-specific contract is documented by the storage implementation.
- Kubernetes rollback anchors must fail closed. If the anchor cannot be read or
  advanced, do not accept a newer-looking repository state silently.
- Avoid `unsafe`. The workspace forbids it.
- Avoid `unwrap`, `expect`, `todo`, and `dbg` in production code. Tests may use
  `expect` only when it makes failures clearer.
- Keep public APIs small and documented.
- Treat Git history as public by default. Keep commits focused on source,
  tests, and documentation intended for the repository.

## Privacy Review Checklist

Before merging a feature, answer these questions in the change description:

- What new information can the object store observe?
- Does the change reveal path hierarchy, filename equality, object counts, file
  sizes, write cadence, tenant identity, or Kubernetes resource names?
- Is the leakage necessary for usability or performance?
- Is the leakage documented in `docs/site/security-model.md`?
- Does the rollback story still work if an attacker can list, delete, delay, or
  replay backend objects?

## Documentation Sync

- Treat `docs/site/` as the current public documentation source.
- Keep behavior, security, performance, operations, repository-format, and
  compatibility changes synchronized with the relevant `docs/site/` page in the
  same commit. If there is no docs impact, say so in the change description.
- Keep old untracked `docs/*.md` design notes as local context until they are
  deliberately curated into `docs/site/`.
- Run `just docs-check` for docs-only changes and rely on `just check` before
  handoff when practical.

## Agent Workflow

- Read relevant docs before editing: `README.md`, `docs/site/index.md`,
  `docs/site/architecture.md`, `docs/site/security-model.md`,
  `docs/site/reference/repository-format.md`, and any crate-local docs.
- Keep patches small and behavior-focused.
- Add or update tests with code changes unless the change is docs-only.
- Run the narrowest relevant tests while iterating, then `just check` before
  final handoff when practical.
- Do not rewrite unrelated files or generated lockfiles without a concrete
  reason.
- Before committing, review `git status --short --ignored` and `git diff
  --cached --name-only`; do not stage ignored workspace-local context.

## Design Biases

- Favor explicit manifests and signed checkpoints over implicit latest-object
  conventions.
- Favor bounded batch reads over one-read-per-file directory listings.
- Favor provider-neutral object-store semantics first; add S3-specific
  acceleration behind feature flags.
- Favor Kubernetes-native coordination for the first deployment target.
- Favor Kopia-first S3 compatibility before broad S3 application compatibility.
