# Repository Format Reference

The repository format is draft. This page records the current intended shape,
not a compatibility promise.

## Invariants

- Backend object names are opaque.
- Plaintext logical paths and Kubernetes names do not appear in backend keys,
  tags, unauthenticated metadata, checkpoints, metrics, or logs.
- Privacy-sensitive metadata is encrypted and authenticated.
- Checkpoints are signed and monotonic.
- Old data remains readable while any protected checkpoint can reference it.
- Provider retention is never shortened by `rs3`.

## Backend Object Classes

The design uses a small number of non-secret classes:

```text
format/
segments/
manifests/
index/
checkpoints/
evidence/
```

The class leaks broad object type. That is currently accepted because it helps
operations, lifecycle policy, and debugging. Hiding class prefixes would require
a future format version.

## Payload Segments

Payload segments are independently encrypted so ranged reads can fetch only the
overlapping backend segments. Segment associated data binds ciphertext to the
repository context and object identity.

The current default segment size is 512 plaintext bytes for Kopia-first restore
behavior. This is a tuning parameter, not a permanent format guarantee.

## Index State

Namespace index state maps blinded logical names and prefix tokens to encrypted
metadata needed for `HEAD`, `GET`, and `LIST`.

Index changes are append-friendly deltas covered by checkpoints. Compaction can
rewrite index state later, but it must preserve rollback and retention rules.

## Checkpoints

A checkpoint records an ordered repository state transition:

- sequence number
- parent checkpoint reference
- referenced index deltas or compacted segments
- active key descriptors
- repository-state digest
- creation time
- retention/evidence policy marker
- signature over the canonical payload

Checkpoints must not contain plaintext logical names.

## Evidence

Each newly published checkpoint writes a create-only evidence object under
`evidence/`. Evidence records contain the checkpoint sequence, checkpoint ID,
canonical checkpoint digest, and signed checkpoint object ID. They are retained
with the same policy and legal hold as the checkpoint object.

Evidence is not a latest-state authority. It gives operators retained storage
history to compare with the external anchor during rollback investigations.

## Keyrings

The repository uses purpose-specific keys for:

- namespace PRF
- content encryption
- metadata and index encryption
- Ed25519 checkpoint signing

New writes use primary keys. Reads and replay accept enabled historical keys
until retention and migration policy allow retirement.

Gateway-derived default keyrings use HKDF-SHA-256 to bind the master key to a
repository ID and a stable public repository salt. Both values must remain
unchanged for the life of the repository. Checkpoint-signing descriptors include
the Ed25519 public verification key so checkpoint payloads can be verified
without exposing signing material.

## Compatibility Promise

There is no stable-format promise yet. Before a stable format, the project still needs final
decisions for:

- canonical metadata encoding
- default segment-size policy
- index compaction thresholds
- padding policy
- keyring envelope encoding
