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

## Workspace Layout

- `crates/rs3-types`: shared strongly typed identifiers and policy types.
- `crates/rs3-crypto`: cryptographic primitives and key derivation boundaries.
- `crates/rs3-index`: append-friendly encrypted index and checkpoint model.
- `crates/rs3-storage`: object-store abstraction.
- `crates/rs3-k8s`: Kubernetes checkpoint-anchor abstraction.
- `crates/rs3-server`: command-line entry point for the future gateway.
- `xtask`: local automation used by `just`.

Additional design notes will be added as interfaces stabilize.
