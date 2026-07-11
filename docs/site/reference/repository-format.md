# Repository Format Reference

The repository format is draft. This page is the design contract for
`commits/v02`. It is not a compatibility promise. The gateway now reads and
writes a transitional `v02` commit envelope, but the catalog-and-run design on
this page is not complete.

!!! warning "Implementation status"
    `commits/v01` has been removed and is unsupported. No production repository
    depends on it, so `rs3` will not add a migration path or a dual reader. The
    current `v02` envelope authenticates every stored section with a signed
    digest and rebuilds namespace state without reading payload ciphertext, but
    it still uses prototype `INDEX_DELTA` and `INDEX_SNAPSHOT` sections. Framed
    `INDEX_RUN`, signed `INDEX_ROOT`, compaction, automatic checkpointing, and
    the new recovery gates remain to be implemented. Until those gates pass,
    the runtime is evaluation-only.

## Invariants

- Backend object names are opaque and never derived from logical paths.
- Plaintext logical paths and Kubernetes names do not appear in backend keys,
  tags, unauthenticated metadata, signed headers, metrics, logs, or errors.
- Privacy-sensitive metadata is encrypted and authenticated.
- Every accepted repository transition is a signed, monotonic commit selected
  by an external anchor.
- S3 listing order and mutable latest-object state are never authoritative.
- Every retained restore-critical reference includes the exact provider object
  version when the backend supplies version IDs.
- Normal writes append a small delta. They do not rewrite the live namespace.
- Recovery and maintenance have fixed input, allocation, request, and byte
  bounds and fail closed before exceeding them.
- Every protected anchor root keeps its exact index, payload, keyring, and
  format-root dependencies reachable.
- Provider retention is never shortened by `rs3`.

## Format Generations

The existing prototype uses keys of this form:

```text
commits/v01/<20-digit-sequence>/<32-byte-random-id-base64url>
```

That generation is removed and unsupported. It is not an input to the `v02`
design, and initialization of a `v02` repository must fail if the chosen backend
prefix is not demonstrably fresh. Importing or converting a `v01` repository is
outside the product contract.

The transitional runtime and future catalog format use:

```text
commits/v02/<20-digit-sequence>/<32-byte-random-id-base64url>
objects/v02/<32-byte-random-id-base64url>
```

The sequence component bounds commit discovery and operational analysis. The
random component prevents paths, namespace equality, and content identity from
appearing in keys. `objects/v02/` contains independently sealed compacted index
runs and payload packs created by later cleaning. Its keys do not distinguish
object type, index level, tenant, path, or workload.

The other backend-visible classes remain generic:

```text
format/
keyrings/
```

These class names, object counts, ciphertext sizes, provider version IDs, and
write/compaction timing are accepted leakage. Plaintext catalog bounds, run
levels, logical object counts, paths, and payload identities remain encrypted.

Bounded writes publish `PAYLOAD_PACK` plus `INDEX_RUN`; signed `INDEX_ROOT`
checkpoints replace the parent-chain replay boundary with an exact catalog of
accepted run sections. Streaming writes still use the transitional
`INDEX_DELTA` shape and therefore make the current state ineligible for a
catalog checkpoint until framed streaming publication lands. All current v02
repositories remain evaluation data and may need recreation.

## Signed Commits

The accepted head is the external anchor's exact commit key, body digest,
provider version ID when required, signing key ID, and format-root reference.
A newest-looking key returned by `LIST` has no authority.

A `v02` commit has a bounded fixed prefix followed by a canonical signed header
and encrypted sections. The signed header covers:

- the format generation and required reader capabilities;
- the commit sequence and exact self key;
- the exact parent commit reference;
- the active format-root and keyring-envelope references;
- each section's type, ordinal, offset, encrypted length, and digest;
- the complete commit-object length and body digest; and
- the signing-key identifier and Ed25519 signature.

The complete header span is limited to 8 KiB and a reader accepts at most 65
sections so the transitional envelope remains bounded. The completed normal
writer emits at most one `PAYLOAD_PACK` and one `INDEX_RUN`; a catalog
checkpoint contains exactly one `INDEX_ROOT`. Multipart commits reserve
the fixed header span only when the body is genuinely streamed. Bounded commits
use one `PutObject` and the canonical encoded header length, without 8 KiB
padding.
Readers reject non-canonical encodings, unknown required capabilities,
out-of-order or overlapping sections, arithmetic overflow, duplicate ordinals,
lengths outside the object, and trailing data not covered by the signed layout.

Capability bit `0x01` requires signed per-section digests. Bit `0x02` identifies
framed index sections. The fixed header advertises `0x01` for transitional
delta/snapshot commits and `0x03` whenever a commit contains `PAYLOAD_PACK`,
`INDEX_RUN`, or `INDEX_ROOT`; the signed section shape must agree with those
bits. Readers support both shapes during the preview transition.

Normal commits contain one encrypted `INDEX_RUN` and at most one encrypted
`PAYLOAD_PACK`; an all-delete or all-empty batch needs no payload pack. A
catalog checkpoint commit contains an encrypted `INDEX_ROOT`. A checkpoint may
also cover a final bounded mutation batch, but the catalog must describe the
exact resulting state.

Signed per-section descriptors are required for descriptor-first recovery. A
reader can authenticate an index range without downloading unrelated payload
sections. Payload ciphertext is authenticated when the referenced object is
read. The whole-object digest remains an identity and maintenance check, not a
reason to read every payload during startup.

## Value-Separated Payload Packs

`PAYLOAD_PACK` is an immutable value container, not an index level. A normal
batch places its non-empty values into one pack and stores only compact pack
pointers in `INDEX_RUN`. Empty objects are index-only. Index checkpointing and
compaction never rewrite payload bytes.

Each pack has a random 256-bit identity, one content-key identifier, a bounded
encrypted directory, and records in randomized physical order. A small record
is ciphertext followed by one 16-byte AEAD tag. Its nonce is derived through a
keyed KDF from the pack identity, record ordinal, and authenticated plaintext
digest, so the format does not store a nonce per record. Records larger than 64
KiB use canonical 64 KiB independently authenticated segments for efficient
range reads; smaller records use one segment. Both writer and reader enforce
that rule so a writer bug cannot create pathological one-byte segments or make
a one-byte range request read an entire large record. The bounded in-memory
normal-commit codec accepts at most 1,024 records, a 64 KiB encrypted
directory, and 32 MiB per pack; larger values stay on the streaming payload
path. The normal low-latency coordinator uses 64 records, while the
release-binary bulk scale lane uses 1,024. These are writer policies inside the
same bounded format, not different trust models. A cold small-record read from
the bulk shape must first authenticate its roughly 62 KiB encrypted directory;
cold-read amplification is therefore qualified separately from bulk write and
recovery evidence.

The encrypted directory maps record ordinals to bounded ciphertext spans and
authenticated plaintext lengths. An index payload pointer is a container-table
ordinal plus record ordinal, rather than a repeated commit key, payload ID,
key ID, nonce, offset, and digest. The signed containing-object descriptor and
encrypted container table carry those shared facts once.

Record associated data binds the immutable repository identity, the exact
historical keyring-envelope reference signed by the containing commit, exact
containing object key, pack and section identities, record and segment
ordinals, plaintext length, and final-segment marker. The provider version does
not exist before upload; after publication the accepted signed reference binds
the exact returned version, object length, and commit-body digest. Moving a
record to a different repository, object, pack, section, or ordinal must fail
authentication. Keyring-envelope rotation remains readable because readers use
the containing commit's historical reference, not the current writer option.

Retention and legal hold apply to the physical containing object. Batches must
therefore use one protection cohort, or be partitioned by retention mode,
retain-until horizon, and legal-hold requirement. Reusing or repacking a value
must never weaken the strongest logical protection that reaches it.

Padding is not part of the first `v02` contract. Content-defined chunking,
gateway-level deduplication, and compression are also outside the baseline
format until their equality leakage, liveness, range-read, and amplification
costs have explicit security modes and qualification evidence. Kopia already
performs its own chunking and packing, so duplicating that work in the gateway
is not a baseline optimization. The researched extension boundary is recorded
in [Deduplication](deduplication.md).

## Framed Index Runs

`INDEX_RUN` is the append-friendly unit for namespace mutations. Runs are
immutable, sorted, encrypted, and divided into independently authenticated
bounded frames. A normal commit embeds one recent run. Compaction may write a
run as an exact-version `objects/v02/` object and later make it reachable from
an accepted catalog.

Each mutation carries a monotonic logical generation and is one of:

- an upsert containing the complete trusted metadata and exact payload
  reference; or
- a tombstone containing the blinded lookup key, encrypted logical path, and
  generation.

The highest generation wins. Two different records for the same key and
generation are corruption, not a tie to resolve by object order, timestamp, or
provider listing.

Runs contain two encrypted projections linked by mutation ordinal:

- a namespace projection sorted by the secret-derived lookup key for `HEAD`
  and `GET`; and
- a listing projection sorted by logical path for ordered prefix listing inside
  the trusted gateway.

The namespace projection stores the raw 32-byte blinded key, generation,
compact payload pointer, trusted `HEAD` metadata, and retention state. The
listing projection stores the encrypted logical path once together with
generation, size, and modification time. Frame-local container tables dedupe
exact commit or standalone-object keys, provider versions, lengths, and
digests. Canonical varints and fixed-width binary fields replace JSON, hex,
decimal byte arrays, durable prefix tokens, nested sealed manifests, and
repeated per-record identifiers. Projection record counts and mutation-ordinal
pairing are authenticated and validated.

Logical paths and projection bounds exist only in authenticated ciphertext.
`v02` does not persist prefix-token objects or path-shaped keys. A reader may
initially materialize a compact in-memory state, but the durable layout must
also permit a future bounded local cache and range-selected frames without a
format change.

The first generation uses canonical length-delimited records and no
compression. Each ciphertext frame and run has an explicit record and byte
limit; the target maximum encrypted run object is 8 MiB. Index-frame associated
data binds at least the immutable repository identity, exact historical
keyring-envelope reference, exact containing object key, section ordinal, run
identity, and frame ordinal. The provider version does not exist until after
upload, so the accepted signed catalog will bind that returned exact version
together with object length and ciphertext digest. Reordering, duplicating, or
transplanting frames must fail authentication.

## Small Signed Index Roots

An `INDEX_ROOT` is a small encrypted catalog, not a serialized copy of the live
namespace. It records:

- the repository sequence covered by the catalog;
- the expected logical-object count;
- active immutable run references and their non-secret identities;
- encrypted generation and projection bounds used by the reader;
- run level and compaction generation;
- each run's exact object key, provider version, length, digest, and section or
  frame layout;
- the active format-root and keyring-envelope references; and
- required reader capabilities and absolute resource ceilings.

Recent runs may be sections of exact accepted commit versions. Compacted runs
are independently sealed `objects/v02/` versions. The catalog authenticates
the complete active run set, so backend listing visibility and ordering are not
part of recovery.

`INDEX_ROOT` names index runs, not every payload pack. Effective highest-
generation namespace records are the authoritative payload-pack reachability
map. Size-tiered compaction merges several similarly sized immutable runs into a
bounded set of larger, sharded runs. This intentionally favors low write
amplification for append-heavy backup ingestion over the lowest possible point
read amplification. Compaction never rewrites payloads merely to consolidate
the namespace.

## Descriptor-First Recovery

Cold recovery starts only from the external anchor:

1. Read and verify bounded signed commit headers from the anchored head back to
   the newest accepted `INDEX_ROOT`.
2. Retain the root and tail index sections only, not payload sections or commit
   bodies.
3. Open the catalog and every named run by exact key and provider version.
4. Verify and apply each bounded run in generation order, retaining no
   cumulative run set beyond the accepted state.
5. Replay post-catalog commit runs oldest to newest, again retaining at most one
   bounded frame beyond the accepted state.
6. Verify catalog cardinality and structural invariants, then sample exact
   payload references as required by the recovery gate.
7. Re-read the external anchor before installing the recovered state. If it
   changed, discard the candidate and retry within a bounded policy.

Recovery does not read payload sections merely to rebuild the index. Missing
versions, missing frames, malformed records, digest failures, AEAD failures,
generation conflicts, catalog-count mismatches, resource-ceiling violations,
or anchor drift all fail closed.

The runtime keeps one accepted compact state plus a bounded pending-mutation
overlay. Unaccepted writes never mutate accepted state. Successful anchor
publication applies the overlay once; failed publication discards it. Startup
must not clone a second complete repository state.

## Automatic Catalog Checkpoints

The writer must keep every accepted head inside its recoverable envelope.
Checkpointing therefore runs automatically under the same live Kubernetes
writer fence used for anchor advancement.

Initial engineering watermarks are:

| State | Commit tail after catalog | Encrypted tail index bytes |
| --- | ---: | ---: |
| Checkpoint requested | 1,000 | 32 MiB |
| Operationally degraded | 2,000 | 48 MiB |
| New mutations paused | 3,000 | 64 MiB |
| Absolute verifier ceiling | 4,096 | 96 MiB |

The active-run reference budget starts at 256 for checkpointing, 512 for
degraded posture, 768 for write pause, and an absolute verifier ceiling of
1,024. Measurements may lower the operational watermarks before format freeze;
raising an absolute reader ceiling requires a format and hostile-input review.

If checkpointing repeatedly fails, already accepted reads remain available.
Writes may continue only until the pause watermark. At that point new mutations
receive a path-safe service-unavailable response, readiness and admin posture
report the write-blocked state, and the anchor is not advanced into an
unrecoverable tail. Failure never silently raises a limit or accepts a
newer-looking backend candidate.

## Checkpoint Publication

Compaction and catalog publication use this order:

1. Capture the accepted anchor and live writer fence.
2. Stream-merge selected runs with bounded buffers.
3. Upload replacement runs under random opaque keys.
4. Verify exact provider version, length, digest, retention, and legal-hold
   posture for every candidate run.
5. Write the signed catalog checkpoint commit.
6. Open the candidate through a fresh reader and compare the complete trusted
   namespace state and accepted run lineage.
7. Recheck the writer fence and unchanged anchor.
8. Advance the real anchor with one resource-version CAS that also checks the
   fence identity and token.
9. Install the accepted catalog and state.
10. Leave replaced and failed candidate objects for conservative orphan GC.

Uploading a run does not make it reachable. Only the fenced anchor CAS makes
the signed catalog an accepted root. Delayed list visibility, duplicate
versions, and abandoned uploads are therefore availability and cleanup
concerns, not state-selection mechanisms.

The current writer refuses a compact mutation before it would create a 1,025th
active run. This keeps exhaustion fail closed, but it is availability
backpressure, not compaction. Packed-run compaction and an automatic watermark
must land before sustained production writes can rely on this path.

## Reachability, Retention, and GC

The authoritative reachability graph starts from the current anchor and every
explicitly protected historical anchor. For each root it includes:

- the exact catalog and post-catalog commit versions;
- the exact active index-run versions;
- the exact payload-containing object versions selected by effective live index
  records;
- the active format root and keyring envelopes; and
- keys needed to authenticate or decrypt those objects.

A live payload reference protects its exact containing commit version. It does
not recursively protect every ancestor merely because the payload was first
written in an old commit. GC resolves active runs by generation before deriving
these exact payload roots. Conservative over-retention is permitted when a mark
cannot be proven complete; deletion on an incomplete or ambiguous mark is not.

GC must finish the whole mark phase before deleting, fail closed on missing or
malformed reachable data, treat unknown retention or legal-hold state as
protected, recheck the maintenance fence and anchor before every deletion, and
delete exact versions only. Prepared but unaccepted objects remain protected
until the configured orphan-age floor passes. Retention-renewal planning
includes catalogs, runs, payload commits, format roots, and keyring envelopes.

Payload-pack cleaning is a separate log-cleaning operation. A fully dead pack
may be deleted only after the complete exact-root mark, orphan-age floor,
protection checks, and maintenance-fence checks pass. A mixed pack is left in
place until its dead fraction justifies cleaning. Cleaning re-encrypts its live
records into a new random pack, publishes higher-generation physical
references, and retains the old exact version while any current or protected
historical root reaches it. Mutable reference counts are not authoritative.

If a candidate pack has live fraction `l`, cleaning must copy at least
`l / (1 - l)` bytes for every byte it can reclaim. The cleaner therefore uses
an explicit utilization threshold and never runs on every checkpoint. Index
checkpointing and compaction must not copy every live payload.

## Anchors and Writer Coordination

The Kubernetes Lease remains the sole production writer-coordination and
latest-state authority. Failover gateways in one apiserver coordination domain
may acquire a new monotonic fence epoch. Every anchor advance verifies the
current owner and fence token in the same Lease `resourceVersion` CAS.

Disconnected or partitioned writers that only share S3 are unsupported. S3
conditional object creation can prevent one key collision, but it cannot order
repository-wide state, fence a stale writer, or safely merge two encrypted
namespace histories. Object-store listing and timestamps cannot fill that gap.
A future disconnected multi-writer mode would require explicit branches,
authenticated merge semantics, deterministic conflict policy, and a different
repository contract. `v02` has no such mode.

Anchors fail closed. If an anchor cannot be read, renewed, advanced, or matched
to the verified graph, the gateway must not accept newer-looking repository
state. Disaster recovery requires a trusted bundle, an external minimum
sequence floor, and offline authorization before recreating a missing anchor.

## Keyrings and Initialization

The repository uses separate namespace-PRF, content-encryption,
metadata/index-encryption, and Ed25519 commit-signing keys. New writes use the
primary key for each purpose. Reads accept enabled historical keys while any
protected root requires them.

Initialization creates random purpose-specific keys, seals them in a keyring
envelope under an external high-entropy wrapping-key source, writes an encrypted
`v02` format root, and publishes a genesis catalog commit. The format root binds
the exact envelope generation, key, provider version, and digest. In retained
mode, every restore-critical initialization write must return a provider version
ID.

Initialization is permitted only on a verified fresh prefix. Detection of
unsupported `v01` objects, an existing anchor, an existing format root, or
ambiguous listing state fails closed. There is no automatic import, overwrite,
or migration behavior.

Wrapping-key rewrap preserves repository data keys and is not compromise
recovery. Historical keys may be retired only after reachability and retention
prove that no protected root requires them.

## Implementation and Qualification Gates

Before `commits/v02` can qualify as the repository format, implementation must
include:

- canonical encoding, crypto, corruption, and cross-object transplant vectors;
- descriptor and frame parsers with fixed hostile-input budgets and fuzzing;
- fresh-process 10k, 100k, and 1M committed-write recovery gates that verify
  exact cardinality plus first, middle, and last payload bytes;
- a 1M filesystem recovery target of at most 180 seconds and 4 GiB RSS on the
  documented 4-vCPU, 16-GiB runner;
- no payload reads during normal index recovery and at most 1.25x index byte
  read amplification;
- enforced small-object write gates for a 64-object batch: at most 1.50x for
  512 B values (target 1.40x), at most 1.15x for 4 KiB values, at most 1.03x
  for 256 KiB values, and at most 320 fixed backend bytes per empty object;
- a sequential 512 B committed-write gate of at most 3.0x plus a provisional
  lifetime gate of at most 3.5x after forced index compaction;
- amplification evidence at 32 B, 256 B, and 1,024 B logical path lengths that
  reports payload amplification separately from fixed metadata bytes per
  object;
- separate adversarial raw-S3 and real Kopia/Velero tiny-source-file gates, so
  a million 512 B S3 objects does not pretend to model a client that already
  packs and deduplicates its repository blobs;
- checkpoint crash, stale-fence, delayed-read, replay, deletion, and exact
  provider-version fault tests;
- GC tests proving exact payload reachability across overlapping runs,
  tombstones, protected roots, and failed compactions; and
- a retained-provider restart and writer-handoff qualification run.

Absolute time limits are enforced only on pinned runners. Correctness,
allocation, request, byte, and amplification ceilings apply everywhere.

## Compatibility Promise

There is no stable repository-format promise yet. `commits/v01` is removed and
unsupported without migration support. The gateway reads and writes a
transitional `commits/v02` envelope, while its catalog, framed-run, compaction,
and bounded-recovery contract remains incomplete. Wire details freeze only
after the implementation, cryptographic review, scale gates, retained-provider
evidence, and recovery runbooks all pass together.
