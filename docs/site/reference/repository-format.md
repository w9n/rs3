# Repository Format Reference

The repository format is draft. This page is the design contract for
`commits/v02`. It is not a compatibility promise. The gateway reads and writes
bounded payload packs, encrypted index runs, signed index-root checkpoints, and
canonical framed streamed payloads with guarded metadata-only compaction.
Protection cohorts, complete retained-provider GC qualification, and final
qualification are not complete.

!!! warning "Implementation status"
    `commits/v01` has been removed and is unsupported. No production repository
    depends on it, so `rs3` will not add a migration path or a dual reader. The
    current `v02` envelope authenticates every stored section with a signed
    digest. Bounded normal writes use ciphertext-only `PAYLOAD_PACK` sections,
    authenticated `INDEX_RUN` record descriptors, and signed `INDEX_ROOT`
    checkpoints; recovery rebuilds namespace state without reading payload
    ciphertext. Known-length, unknown-length, and zero-length streams use
    `[PAYLOAD, INDEX_RUN]`, and exact stream carriers survive checkpoints,
    metadata-only compaction, and GC marking. Guarded compaction and automatic
    active-run watermarks are implemented. Protection cohorts, complete
    retained-provider GC qualification, and final recovery qualification remain.
    Until those gates pass, the runtime is evaluation-only.

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

The current preview runtime and catalog format use:

```text
commits/v02/<20-digit-sequence>/<32-byte-random-id-base64url>
objects/v02/<32-byte-random-id-base64url>
```

The sequence component bounds commit discovery and operational analysis. The
random component prevents paths, namespace equality, and content identity from
appearing in keys. The current compactor stores index shards in sibling
`commits/v02/` delta carriers so the existing signed commit and exact-version
machinery authenticates them. `objects/v02/` remains reserved for possible
independently sealed objects such as payload packs created by later cleaning.
Foreground standalone payload uploads are not part of the current format.
Reserved keys do not distinguish object type, index level, tenant, path, or
workload.

The other backend-visible classes remain generic:

```text
format/
keyrings/
```

These class names, object counts, ciphertext sizes, provider version IDs, and
write/compaction timing are accepted leakage. Plaintext catalog bounds, run
levels, logical object counts, paths, and payload identities remain encrypted.

Bounded writes publish `[PAYLOAD_PACK, INDEX_RUN]`; all-delete or all-empty
bounded batches may publish `[INDEX_RUN]`. Streamed writes publish exactly
`[PAYLOAD, INDEX_RUN]`, including zero-length streams. Signed `INDEX_ROOT`
checkpoints replace the parent-chain replay boundary with an exact catalog of
accepted run sections. All current v02 repositories remain evaluation data and
may need recreation.

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
sections so the preview envelope remains bounded. The completed normal writer
emits `[INDEX_RUN]`, `[PAYLOAD_PACK, INDEX_RUN]`, or `[PAYLOAD, INDEX_RUN]`; a
catalog checkpoint contains exactly one `INDEX_ROOT`. Multipart commits reserve
the fixed header span only when the body is genuinely streamed. Bounded commits
use one `PutObject` and the canonical encoded header length, without 8 KiB
padding.
Readers reject non-canonical encodings, unknown required capabilities,
out-of-order or overlapping sections, arithmetic overflow, duplicate ordinals,
lengths outside the object, and trailing data not covered by the signed layout.

Capability bit `0x01` requires signed per-section digests. Bit `0x02` identifies
framed index sections. Bit `0x04` requires compacted-run root semantics,
including authenticated run level and compaction generation. This preview
capability accepts only tier 0 and tier 1; higher level values fail closed until
a future capability defines their semantics. The fixed header
advertises `0x01` for transitional delta/snapshot commits, `0x03` for framed
pack, stream, or index-run carriers, and `0x07` for `INDEX_ROOT` commits; the
signed section shape must agree with those bits. Readers support these shapes
during the preview transition and fail closed on unknown required capabilities.

Normal commits contain one encrypted `INDEX_RUN` and exactly the carrier
permitted by their canonical shape. An all-delete or all-empty bounded batch
needs no payload pack, while a zero-length streamed request deliberately keeps
its authenticated `PAYLOAD` carrier. A catalog checkpoint commit contains an
encrypted `INDEX_ROOT`. A checkpoint may
also cover a final bounded mutation batch, but the catalog must describe the
exact resulting state.

The current framed index plaintext is wire version 4. Mutation ordinals,
generations, content lengths, and bounded counts use canonical varints; readers
reject overlong encodings. Generation and content length appear in both the
namespace and listing projections because each projection must be independently
validated before the two records are paired.

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

Each pack has a random 256-bit identity, one content-key identifier, and records
in randomized physical order. The pack section contains ciphertext only; its
authenticated layout lives in the encrypted `INDEX_RUN`. A small record is
ciphertext followed by one 16-byte AEAD tag. Its nonce is derived through a
keyed KDF from the pack identity, record ordinal, and authenticated plaintext
digest, so the format does not store a nonce per record. Records larger than 64
KiB use canonical 64 KiB independently authenticated segments for efficient
range reads; smaller records use one segment. Both writer and reader enforce
that rule so a writer bug cannot create pathological one-byte segments or make
a one-byte range request read an entire large record. The bounded in-memory
normal-commit codec accepts at most 1,024 records and 32 MiB per pack; larger
values stay on the streaming payload path. The normal low-latency coordinator
uses 64 records, while the release-binary bulk scale lane uses 1,024. These are
writer policies inside the same bounded format, not different trust models.

The encrypted index container table carries the shared pack identity,
content-key ID, record count, and exact containing-object reference. For a pack
embedded beside the run, the historical keyring-envelope object and digest come
from that signed commit; an external container-table entry preserves them
explicitly. Each compact record pointer carries its record ordinal, physical
ciphertext offset, and plaintext digest, while the authenticated mutation
carries the plaintext length. The decoder validates the complete bounded
layout, including canonical segment lengths, non-overlap, pack limits, and
arithmetic overflow. Once recovery has authenticated the run, a cold read can
calculate the exact ciphertext span without another metadata fetch. For a 512
B record, one exact range `GET` fetches 528 B including the AEAD tag, or
1.03125x ciphertext-byte amplification.

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

## Streamed Payload Carriers

A known-length or chunked unknown-length upload that exceeds the bounded pack
path is one multipart-padded commit with exactly two required sections:

```text
0  PAYLOAD
1  INDEX_RUN
```

The writer encrypts authenticated payload segments as the request body arrives,
then finalizes and seals the covering run at EOF. It advances the anchor only
after the complete commit version, object length, retention posture, and signed
layout have been verified. A stalled or truncated request fails before
publication.

This is a repository-layer format capability. The current S3 listener supplies
the length from `Content-Length` or valid SigV4 streaming metadata and rejects
unsigned HTTP chunked `PutObject` without a length as `411 MissingContentLength`.
The EOF-finalized path remains directly tested but is not currently a public
unknown-length S3 operation.

The embedded run uses a self-stream pointer. Its shared facts are the signed
payload-section ordinal, opaque payload identity, and authenticated segmented
header. The containing signed commit supplies the exact section offset, length,
and digest. The run codec permits a zero-plaintext stream to keep this carrier:
the payload section still contains an authenticated header, its run remains
catalogued, and GC must retain the exact commit. This is distinct from an empty
bounded value, which is index-only.

Replay materializes a self-stream pointer into an exact commit reference.
Compaction performs the same normalization before discarding the source-run
boundary. An external stream carrier records:

- exact commit key and provider version;
- complete stored commit length and signed body digest;
- historical keyring-envelope object and digest;
- section-region start plus payload ordinal, offset, length, and digest; and
- opaque payload identity and authenticated segmented-payload header.

These facts are encrypted inside the run. The decoder rejects missing, unused,
duplicate, out-of-order, mismatched-length, or out-of-object carriers. A
compacted run has no self carrier: both embedded packs and streams become exact
external references. Checkpointing and compaction therefore write index
metadata only and never read, decrypt, or copy the streamed payload.

A partial read derives the minimal complete ciphertext-segment span from the
authenticated header and section facts, bounds it against the exact stored
commit length, and issues an exact-version range `GET` when the provider supplies
versions. A full read fetches the named payload section. Decrypted segments are
cached under a process-local opaque digest of repository/keyring context,
commit key/version/body/stored length, section ordinal/digest/start/offset/length,
payload identity/header, and content length. The actual payload identity remains
the AEAD associated-data identity. The synthetic cache identity is never written
to the backend and adds no backend-visible name, although the provider still
observes range offsets, lengths, timing, and cache misses.

Foreground standalone payload objects are deferred. Separating payload upload
from the signed run would require adoption semantics for partially published
objects, another retained-version and orphan-cleanup state, and equivalent
cross-object authentication without improving the primary Kopia path. Gateway
deduplication is deferred for the same reason plus its equality and
shared-liveness leakage; Kopia already chunks, packs, and deduplicates its own
repository blobs. Any future standalone or deduplicating mode needs an explicit
capability and its own security and GC qualification.

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
generation, size, and modification time. Wire version 4 frame-local container
tables separately dedupe exact pack and stream carriers, including commit keys,
provider versions, stored lengths, signed digests, historical keyring context,
and carrier-specific section facts. One run may carry either a self pack or a
self stream, never both. Canonical varints and fixed-width binary fields replace
JSON, hex,
decimal byte arrays, durable prefix tokens, nested sealed manifests, and
repeated per-record identifiers. Projection record counts and mutation-ordinal
pairing are authenticated and validated.

Logical paths and projection bounds exist only in authenticated ciphertext.
`v02` does not persist prefix-token objects or path-shaped keys. A reader may
initially materialize a compact in-memory state, but the durable layout must
also permit a future bounded local cache and range-selected frames without a
format change.

Wire version 4 uses canonical length-delimited records and no compression. Each
ciphertext frame and run has an explicit record and byte
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

Recent runs may be sections of exact accepted commit versions. Current
compacted runs are sealed sections in exact sibling `commits/v02/` delta-carrier
versions. The catalog authenticates the complete active run set, so backend
listing visibility and ordering are not part of recovery.

`INDEX_ROOT` names index runs, not every payload carrier. Effective highest-
generation namespace records are the authoritative pack and stream reachability
map. Foreground runs are level 0. The current run compactor selects at
most the oldest 128 level-0 runs, chooses the newest mutation for each blinded
key in that bounded window, and retains a winning tombstone just like a winning
upsert. Newer level-0 runs and every existing level-1 shard remain
exact-referenced and unchanged. Level is a storage tier, never a compaction
epoch; every foreground compaction emits level 1 instead of incrementing a
level counter. The decoder accepts only levels 0 and 1. Supporting another tier
requires an explicit future capability and hostile-input review. Different
mutations for the same key and generation are
corruption. Source-relative self-pack and self-stream pointers are normalized to
exact external historical commit, version, section, payload, and
keyring-envelope facts before source-run boundaries disappear. The result is
split into the fewest bounded
generation-range shards the canonical run codec accepts. Every equal-generation
group stays indivisible, even when that means rejecting an oversized generation
instead of partially publishing it. A level-1 tombstone continues to mask older
values in preserved level-1 shards. Reclaiming bottom-tier tombstones and
records they mask requires a separate future guarded or offline merge with
protected-root and GC proof. Foreground compaction is metadata-only and never
reads, decrypts, or rewrites payload ciphertext.

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

The runtime keeps one accepted compact state plus a hard-bounded
1,024-mutation overlay. Unaccepted writes never mutate accepted state. An
exclusive publication barrier freezes the overlay from commit snapshot through
the anchor CAS and local install. Successful anchor publication applies the
validated overlay once; failed publication discards it. Startup must not clone
a second complete repository state. One atomic RAII mutation lease owns this
overlay per service instance; delayed publishers retain the lease, and direct
mutation or maintenance APIs cannot bypass an active coordinator. Semantic
installation checks complete before CAS. If local lock installation alone
fails after CAS, the caller receives a recovery-required result and all further
mutations fail until restart from the accepted anchor.

## Automatic Catalog Watermarks

The writer must keep every accepted head inside its recoverable envelope.
Active-run compaction therefore runs automatically under the same live
Kubernetes writer fence used for anchor advancement. Commit-tail and encrypted
tail-byte posture remains part of the release design, but is not yet an
equivalent automatic runtime gate.

Initial engineering watermarks are:

| State | Commit tail after catalog | Encrypted tail index bytes |
| --- | ---: | ---: |
| Checkpoint requested | 1,000 | 32 MiB |
| Operationally degraded | 2,000 | 48 MiB |
| New mutations paused | 3,000 | 64 MiB |
| Absolute verifier ceiling | 4,096 | 96 MiB |

For active runs, a coordinator requests compaction at 256. If no maintenance
guard is configured, it degrades and retries at each additional 64-run boundary,
then pauses before staging another mutation at 896. The absolute verifier
ceiling is 1,024. The release scale recipes
require at most 255 active authenticated runs after the final checkpoint and
fresh recovery. Measurements may lower the operational watermarks before format
freeze; raising an absolute reader ceiling requires a format and hostile-input
review.

If the maintenance guard is not configured, already accepted reads remain
available and writes may continue only until the pause watermark. A fully
validated bounded plan that cannot reduce its source-run count may also defer
below that watermark and retry later. A configured guard rejection, corruption,
storage or anchor failure, and every other compaction error poisons the
coordinator immediately. At the pause watermark, a still-missing guard or a
still-nonreducing plan blocks new mutations with a
path-safe service-unavailable response. Readiness and admin posture report the
write-blocked state, and the anchor is not advanced into an unrecoverable tail.
Failure never silently raises a limit or accepts a newer-looking backend
candidate.

## Checkpoint Publication

Compaction and catalog publication use this order:

1. Capture the accepted anchor and live Kubernetes `WriterFence` with no
   pending mutations.
2. Select and verify at most the oldest 128 level-0 runs, then merge that
   bounded foreground window newest-wins while retaining tombstones and
   normalizing self-pack and self-stream references. Preserve newer level-0 and
   every existing level-1 reference unchanged.
3. Shard the result on generation boundaries and write each metadata-only run
   in an unanchored delta-carrier commit that is a direct child of the captured
   base.
4. Write an unanchored signed `INDEX_ROOT`, also a direct child of that base,
   that exact-references every new sibling carrier plus the preserved level-1
   inventory. New shards have level 1 and a compaction generation equal to the
   sibling commit sequence.
5. Read back the exact candidate root and every new sibling carrier, verify
   their signed headers, section descriptors, lineage, authenticated framing,
   and canonical decoded value, and require the opened root to equal the
   constructed catalog exactly. Preserved run references must be byte-for-byte
   unchanged.
6. Recheck the writer fence and unchanged base anchor.
7. Advance the real anchor to the root with one resource-version CAS that also
   checks the fence identity and token.
8. Install the accepted catalog and anchor while keeping the already-accepted
   logical namespace state in place. Metadata-only compaction changes no
   client-visible record or payload reference.
9. Leave replaced and failed candidate objects for conservative orphan GC.

Uploading a carrier does not make it accepted. Only the fenced anchor CAS makes
the signed catalog an accepted root. Recovery requires exact carrier versions
and validates the compacted sibling's parent, sequence, section position,
level, and compaction generation. Delayed list visibility, duplicate versions,
and abandoned uploads are therefore availability and cleanup concerns, not
state-selection mechanisms.

The coordinator requests compaction at 256 active runs. A missing maintenance
guard degrades and retries at subsequent 64-run boundaries below 896. A fully
validated bounded plan that cannot reduce run count may likewise defer and
retry below 896. Both fail closed at that pause watermark. A configured guard
rejection, corruption, storage or anchor failure, and every other compaction
error poisons immediately. The writer also refuses a compact mutation before it
would create a 1,025th active run. These are distinct defenses: operational
backpressure acts early, while the immutable format ceiling remains the final
fail-closed bound.

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
these exact payload roots. This includes streamed carriers normalized by
compaction and zero-length streamed carriers whose payload section need not be
read to answer the client. Conservative over-retention is permitted when a mark
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
Metadata-only compaction uses that live `WriterFence` as its maintenance guard
and rechecks it before adopting a candidate root.

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
- fresh post-recovery sentinel reads that use one exact backend range `GET` per
  record and at most 1.04x ciphertext-byte amplification for 512 B values (528
  B including the AEAD tag, or 1.03125x, is the format expectation);
- enforced small-object write gates for a 64-object batch: at most 1.50x for
  512 B values (target 1.40x), at most 1.15x for 4 KiB values, at most 1.03x
  for 256 KiB values, and at most 320 fixed backend bytes per empty object;
- a sequential 512 B committed-write gate of at most 3.0x plus a
  checkpoint-and-compaction-inclusive lifetime gate of at most 1.65x;
- amplification evidence at 32 B, 256 B, and 1,024 B logical path lengths that
  reports payload amplification separately from fixed metadata bytes per
  object;
- separate adversarial raw-S3 and real Kopia/Velero tiny-source-file gates, so
  a million 512 B S3 objects does not pretend to model a client that already
  packs and deduplicates its repository blobs;
- measured known-length and chunked streamed-write lanes that cover checkpoint
  reload, post-compaction cold ranges, and exact GC reachability without
  attributing historical pre-wire-4 results to the current format;
- checkpoint crash, stale-fence, delayed-read, replay, deletion, and exact
  provider-version fault tests;
- GC tests proving exact payload reachability across overlapping runs,
  tombstones, protected roots, and failed compactions; and
- a retained-provider restart and writer-handoff qualification run.

The local and CI recipes enforce generous elapsed-time regression ceilings on
every runner, including a separate recovery ceiling. Time results qualify a
release only on the pinned runner. Correctness, allocation, request, byte, and
amplification ceilings apply everywhere.

## Compatibility Promise

There is no stable repository-format promise yet. `commits/v01` is removed and
unsupported without migration support. The gateway reads and writes the preview
`commits/v02` envelope with index-run wire version 4. Version 4 is the first run
wire that includes exact self/external streamed carriers; the current reader
does not promise to open earlier preview run wires. Recreate evaluation
repositories when the preview wire changes. Catalog, exact descriptors,
framed streaming, and guarded metadata-only mixed-carrier compaction are
integrated, while protection cohorts, complete retained-provider GC, and final
bounded-recovery qualification remain incomplete. Wire details freeze only
after cryptographic review, scale gates, retained-provider evidence, and
recovery runbooks all pass together.
