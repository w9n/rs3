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
keyrings/
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

Payload segments are independently encrypted with XChaCha20-Poly1305 so ranged
reads can fetch only the overlapping backend segments. Segment associated data
binds ciphertext to the backend object ID, segment size, plaintext length,
segment index, and final-segment marker.

The current default segment size is 512 plaintext bytes for Kopia and Velero
with Kopia-uploader restore behavior. This is a tuning parameter, not a
permanent format guarantee.

## Index State

Namespace index state maps blinded logical names and prefix tokens to encrypted
metadata needed for `HEAD`, `GET`, and `LIST`.

Metadata records are sealed with AES-256-GCM-SIV under the repository metadata
key. Associated data is object-type specific: manifest records bind to the
manifest ID, and index deltas bind to the index-delta object domain. Signed
checkpoints and object IDs decide which sealed metadata is reachable repository
state.

Index changes are append-friendly deltas covered by checkpoints. Compaction can
rewrite index state later, but it must preserve rollback and retention rules.

## Checkpoints

A checkpoint records an ordered repository state transition:

- sequence number
- parent checkpoint reference
- referenced index deltas or compacted segments
- active key descriptors
- active keyring envelope generation, object ID, and digest when configured
- repository-state digest
- signed publish time
- retention/evidence policy marker
- signature over the canonical payload

Checkpoints must not contain plaintext logical names.

## Evidence

Each newly published checkpoint writes a create-only evidence object under
`evidence/`. Evidence records contain the checkpoint sequence, checkpoint ID,
canonical checkpoint digest, and signed checkpoint object ID. They are retained
with the same policy and legal hold as the checkpoint object.

Evidence is not a latest-state authority. It gives operators retained storage
history to compare with the external anchor during open, restore, and rollback
investigations. The external anchor decides which checkpoint position is
accepted; evidence proves what storage retained for that position.

## Keyrings

The repository uses purpose-specific keys for:

- namespace PRF
- content encryption
- metadata and index encryption
- Ed25519 checkpoint signing

New writes use primary keys. Reads and replay accept enabled historical keys
until retention and migration policy allow retirement.

The preferred bootstrap shape is to use an operator-provided repository ID and
public salt, generate random purpose-specific data keys, and store them in an
encrypted keyring envelope under a counted `keyrings/` object. The wrapping-key
source, such as a KMS key or high-entropy wrapping key, stays outside the
repository. Signed checkpoints bind the active envelope by generation, object ID,
and digest so a backend cannot silently swap envelopes.

Wrapping-key rewrap preserves the same repository data keys. It is useful for
moving the wrapping-key source or retiring a clean wrapping key, but it is not
recovery from exposure of an old wrapping key plus the old envelope bytes.

Initial empty repositories are initialized by writing an encrypted keyring
envelope. Existing anchored repositories open through the envelope reference
inside the accepted signed checkpoint, not through S3 listing order or a mutable
latest pointer.

Checkpoint-signing descriptors include the Ed25519 public verification key so
checkpoint payloads can be verified without exposing signing material.

See [Cryptography](cryptography.md) for primitive choices, nonce rules, and
known preview limits.

## Compatibility Promise

There is no stable-format promise yet. The production-preview target is an
evaluation contract, not a durable repository-format guarantee. Before a stable
format v1, the project still needs final decisions for:

- canonical metadata encoding
- default segment-size policy
- index compaction thresholds
- padding policy
- KMS/HSM/Vault wrapping-key integration workflow
