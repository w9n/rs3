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
- Retained restore-critical references are bound to provider object versions
  when the backend supports version IDs.

## Backend Object Classes

The design uses a small number of non-secret classes:

```text
format/
keyrings/
commits/
segments/
manifests/
index/
checkpoints/
evidence/
```

The class leaks broad object type. That is currently accepted because it helps
operations, lifecycle policy, and debugging. Hiding class prefixes would require
a future format version.

## v2 Preview

`v2-preview` is the default format for new repositories. `v1-preview` remains
selectable for legacy preview experiments, but new deployments should use a
fresh `v2-preview` repository rather than carrying forward unused v1 state.

v2 commit objects use random, path-private keys:

```text
commits/v01/<20-digit-sequence>/<32-byte-random-id-base64url>
```

The sequence segment is for bounded listing only. The accepted head is the
external anchor's full commit key, body digest, provider version ID when
required, and signing key ID. A v2 reader verifies the fixed header, header
digest, canonical CBOR header, signed `self.commit_key`, Ed25519 signature,
section layout, and body digest before trusting a commit.

The retained-version/Object Lock provider profile does not require atomic
`If-None-Match: *` support. It requires provider version IDs, exact-version
`HEAD`/`GET`/range `GET`, visible retention or legal-hold state, and preserved
old versions after a newer latest version exists.

The current v2 runtime reuses the trusted namespace, sealed manifest, and
segmented encrypted payload model described below. The difference is the
durable commit boundary: pending sealed index deltas are embedded in signed v2
commit sections and replayed from the anchor-selected commit chain.

The gateway uses the same commit batching knobs for v2 as for v1. Concurrent
client PUTs can stage multiple encrypted payloads and publish one signed v2
delta commit that covers all pending index updates; if commit publication or
anchor advancement fails, the unaccepted in-memory namespace state is rolled
back while the failed logical payload sequences remain reserved.

v2 snapshot commits consolidate the live blinded namespace into an encrypted
`INDEX_SNAPSHOT` section. Readers walk the signed parent chain only until the
nearest snapshot, apply that full state, then replay newer delta commits. A
snapshot writer first flushes any pending client-write batch so the snapshot
chains from an accepted state. Operators can force this maintenance action with
`rs3 write-index-snapshot` on `v2-preview` repositories.

v2 quick maintenance verifies the anchor-selected commit chain and reports
path-redacted orphan counts. Conservative orphan GC can delete unanchored
commit candidates only after reachability, visible retention, legal-hold, age,
and same-sequence safety checks pass. Retained or legally held candidates are
reported and skipped; retained-profile candidates with missing protection
metadata are also skipped.

`rs3 export-restore-bundle` is format-aware: for `v2-preview` it verifies the
anchor-selected commit chain and exports the anchor state as the normal DR
weak-subjectivity bundle. If the external anchor is lost, `rs3 import-v2-anchor`
recreates it from a trusted bundle after verifying the named commit chain.
`rs3 check-v2-provider` runs the selected v2 provider-profile probes against the
configured backend; retained governance profiles require an explicit operator
review flag because gateway credentials must not be able to bypass retention.

## Payload Segments

Payload segments are independently encrypted with XChaCha20-Poly1305 so ranged
reads can fetch only the overlapping backend segments. Segment associated data
binds ciphertext to the backend object ID, segment size, plaintext length,
segment index, and final-segment marker.

Segment size is recorded per payload object. The current writer default keeps
small objects at 512 plaintext bytes per segment and uses larger segments for
medium and large objects. This is a tuning policy, not a permanent format
guarantee.

## Index State

Namespace index state maps blinded logical names and prefix tokens to encrypted
metadata needed for `HEAD`, `GET`, and `LIST`.

Metadata records are sealed with AES-256-GCM-SIV under the repository metadata
key. Associated data is object-type specific: manifest records bind to the
manifest ID, and index deltas bind to the index-delta object domain. Signed
checkpoints and object IDs decide which sealed metadata is reachable repository
state.

Namespace entries reference the encrypted payload object ID and, when available,
the provider version ID returned by the backend write. Retained/Object Lock
repository operation requires this version ID so restore can read the exact
retained payload version even if the backend later presents a different latest
version.

For retained-version providers, a same-key write may create another retained
version instead of failing as a duplicate. The format does not treat latest
object state as authoritative in that profile; checkpoint-bound object IDs,
provider version IDs, and digests decide reachable state.

Index changes are append-friendly deltas covered by checkpoints. Compaction can
rewrite index state later, but it must preserve rollback and retention rules.

## Checkpoints

A checkpoint records an ordered repository state transition:

- sequence number
- parent checkpoint reference and provider version ID when available
- referenced index deltas or compacted segments, including provider version IDs
  when available
- active key descriptors
- active keyring envelope generation, object ID, provider version ID, and digest
  when configured
- repository-state digest
- signed publish time
- retention/evidence policy marker
- signature over the canonical payload

Checkpoints must not contain plaintext logical names.

## Evidence

Each newly published checkpoint writes a create-only evidence object under
`evidence/`. Evidence records contain the checkpoint sequence, checkpoint ID,
canonical checkpoint digest, signed checkpoint object ID, and signed checkpoint
object version ID when available. They are retained with the same policy and
legal hold as the checkpoint object.

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
until retention policy and repository reachability allow retirement. Data-key
rotation adds a fresh primary key for one purpose and demotes the previous
primary to enabled historical use.

The preferred bootstrap shape is to use an operator-provided repository ID and
public salt, generate random purpose-specific data keys, and store them in an
encrypted keyring envelope under a counted `keyrings/` object. The wrapping-key
source, such as a KMS key or high-entropy wrapping key, stays outside the
repository. Signed checkpoints bind the active envelope by generation, object
ID, provider version ID when available, and digest so a backend cannot silently
swap envelopes. The envelope is checkpoint-bound, not checkpoint-embedded:
normal checkpoints do not rewrite key material, but a key update becomes
accepted repository state only after a signed checkpoint names the new envelope.

Wrapping-key rewrap preserves the same repository data keys. It is useful for
moving the wrapping-key source or retiring a clean wrapping key, but it is not
recovery from exposure of an old wrapping key plus the old envelope bytes.

Repository-local orphan cleanup is reachability and retention aware. It derives
candidates from an accepted checkpoint chain, skips objects with known retention
or legal hold, and treats provider retention or legal-hold delete failures as
blocked cleanup rather than as successful deletion.

Initial empty repositories are initialized by writing an encrypted keyring
envelope. Existing anchored repositories open through the envelope reference
inside the accepted signed checkpoint, not through S3 listing order or a mutable
latest pointer.

In retained/Object Lock mode, keyring envelopes, checkpoints, index objects, and
payload objects must all return provider version IDs at write time. Missing
version IDs are treated as provider capability failures, because retained
restore cannot depend on mutable latest-object reads.

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
