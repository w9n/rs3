# Repository Format Reference

The repository format is draft. This page is the design contract for
`commits/v03`. It is not a compatibility promise. The gateway reads and writes
bounded payload packs, encrypted index runs, signed index-root checkpoints, and
ciphertext-only detached payloads with guarded metadata-only compaction.
New bounded writes are partitioned by effective protection cohort, and exact
full-GC planning plus guarded retention renewal are implemented. Live-provider
restart/fault qualification and final release qualification are not complete.

!!! warning "Implementation status"
    `commits/v01` and `commits/v02` have been removed and are unsupported. No production repository
    depends on them, so `rs3` will not add a migration path or a dual reader. The
    current `v03` envelope authenticates every stored section with a signed
    digest. Bounded normal writes use ciphertext-only `PAYLOAD_PACK` sections,
    authenticated `INDEX_RUN` record descriptors, and signed `INDEX_ROOT`
    checkpoints; recovery rebuilds namespace state without reading payload
    ciphertext. Nonempty large streams use a standalone `objects/v03` payload
    plus `[INDEX_RUN]`; empty streams are index-only. Exact carriers survive
    checkpoints, metadata-only compaction, and GC marking. Guarded compaction,
    automatic active-run watermarks, and new-write protection cohorts are
    implemented. Live retained-provider and final recovery qualification remain.
    Until those gates pass, the runtime is evaluation-only.

A v03 gateway refuses v02 commit/object prefixes, version-2 commit and format
roots, and JSON keyring artifacts. Bootstrap requires a fresh prefix. Old
Kubernetes anchor annotations fail closed instead of appearing to be a missing
anchor. Evaluation repositories must be recreated; no migration or dual reader
is provided. Current anchor records explicitly carry repository format
generation 3, distinct from format-root envelope rotation generations.

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

That generation is removed and unsupported. It is not an input to the `v03`
design, and initialization of a `v03` repository must fail if the chosen backend
prefix is not demonstrably fresh. Importing or converting a `v01` repository is
outside the product contract.

The current preview runtime and catalog format use:

```text
commits/v03/<20-digit-sequence>/<32-byte-random-id-base64url>
objects/v03/<32-byte-random-id-base64url>
```

The sequence component bounds commit discovery and operational analysis. The
random component prevents paths, namespace equality, and content identity from
appearing in keys. The current compactor stores index shards in sibling
`commits/v03/` delta carriers so the existing signed commit and exact-version
machinery authenticates them. `objects/v03/` stores independently sealed
streamed payloads with known or unknown lengths.
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

Bounded nonempty writes publish `[PAYLOAD_PACK, INDEX_RUN]`; all-delete or
all-empty batches publish `[INDEX_RUN]`. Large streams first seal one random
`objects/v03/` payload and then publish an `[INDEX_RUN]` commit with its encrypted
exact reference. Empty streams are index-only. Signed `[INDEX_ROOT]` checkpoints
replace the replay boundary with an exact catalog of accepted runs. Genesis is
an authenticated empty index root. Recreate evaluation repositories when the
preview wire changes.

## Signed Commits

The accepted head is the external anchor's exact commit key, body digest,
provider version ID when required, signing key ID, and format-root reference.
A newest-looking key returned by `LIST` has no authority.

A `v03` commit starts with the eight-byte magic `rs3:cmt\n`, followed by
32 fixed-field bytes and a canonical CBOR signed header. The complete fixed
prelude is 40 bytes:

| Object offset | Field | Required value |
| --- | --- | --- |
| 8..12 | Format version, u32 big-endian | 3 |
| 12..16 | Minimum reader, u32 big-endian | 3 |
| 16..20 | CBOR header length, u32 big-endian | Exact canonical length |
| 20..28 | Capability word, u64 big-endian | 0 |
| 28..40 | Reserved bytes | All zero |

The signed header records the commit sequence and self key, exact parent
reference, publish time, kind, algorithm identifiers, keyring-envelope
reference, ordered section descriptors and digests, body digest, signing-key
ID, and Ed25519 signature. The format-root reference belongs to the anchor and
index root. Exact stored lengths are checked against postconditions and signed
section coverage. Signature input is the complete prelude and canonical header
with the signature field zeroed. There is no separate header digest.

The complete header span is limited to 8 KiB and a reader accepts at most two
sections. Delta commits contain `[INDEX_RUN]` or `[PAYLOAD_PACK, INDEX_RUN]`;
root commits contain exactly `[INDEX_ROOT]`. Every section must carry the
must-understand flag, with no compression. Every commit uses a single PUT;
there is no upload-mode field or padded header. Retired section codes
`0x0001` through `0x0004`, nonzero reserved bytes or capabilities, noncanonical
encodings, overlapping sections, arithmetic overflow, and trailing bytes
outside the signed layout fail closed. Signed section digests, framed indices,
compacted runs and detached payloads are intrinsic to format 3; no capability
bits are assigned. Root catalogs accept levels zero and one.

The current framed index plaintext is wire version 7. Frame, section and mutation
ordinals, generations, content lengths, retention days, and bounded counts use
canonical unsigned varints; readers reject overlong encodings. Generation and
content length appear in both the namespace and listing projections because each
projection must be independently validated before the two records are paired.

Listing records start with a shared-prefix byte count, suffix byte count and
suffix bytes, followed by the mutation ordinal, kind and listing facts. The
prefix is the longest byte prefix shared with the preceding path in that frame.
The first record always has prefix zero and carries its full path. Identical
paths at distinct ordinals use the full predecessor length and an empty suffix.
Frames reset the prefix context and can be decoded independently. Prefixes may
split a UTF-8 code point, but the complete reconstructed path must be valid UTF-8
and satisfy the path-byte limit. Readers reject nonmaximal or out-of-bounds
prefixes and oversized reconstructed paths before allocating path storage.
Namespace projections retain their full 32-byte blinded keys.

Frame ciphertext lengths reflect compressed metadata, including aggregate path
lengths and shared-prefix structure. Front coding reduces stored and transferred
index bytes; recovery still holds complete logical paths in trusted memory.

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

Each pack has a random 256-bit carrier identity, a fresh 256-bit sealing attempt,
one content-key identifier, and records
in randomized physical order. The pack section contains ciphertext only; its
authenticated layout lives in the encrypted `INDEX_RUN`. A small record is
ciphertext followed by one 16-byte AEAD tag. Its nonce is derived through a
keyed HMAC from authenticated carrier, attempt, record and segment context,
using the same scheme as detached payloads. The format stores no nonce per record. Records larger than 64
KiB use canonical 64 KiB independently authenticated segments for efficient
range reads; smaller records use one segment. Both writer and reader enforce
that rule so a writer bug cannot create pathological one-byte segments or make
a one-byte range request read an entire large record. The bounded in-memory
normal-commit codec accepts at most 4,096 records and 32 MiB per pack; larger
values stay on the streaming payload path. The normal low-latency coordinator
uses 64 records, while the release-binary high-throughput scale lane can use
4,096. These are
writer policies inside the same bounded format, not different trust models.

The encrypted index container table carries the shared pack and attempt identities,
content-key ID, record count, and exact containing-object reference. For a pack
embedded beside the run, the historical keyring-envelope object and digest come
from that signed commit; an external container-table entry preserves them
explicitly. Each compact record pointer carries its record ordinal and physical
ciphertext offset, while the authenticated mutation carries the plaintext
length. The metadata frame stores each sorted unique namespace-key ID once,
and namespace mutations reference it by a bounded ordinal. The decoder
validates the complete bounded layout, including canonical segment lengths,
non-overlap, pack limits, and arithmetic overflow. Once recovery has
authenticated the run, a cold read can
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
The format retains the hold dimension for fail-closed parsing of historical
state, but the v03 gateway currently rejects new client legal holds.

Padding is not part of the first `v03` contract. Content-defined chunking,
gateway-level deduplication, and compression are also outside the baseline
format until their equality leakage, liveness, range-read, and amplification
costs have explicit security modes and qualification evidence. Kopia already
performs its own chunking and packing, so duplicating that work in the gateway
is not a baseline optimization. The researched extension boundary is recorded
in [Deduplication](deduplication.md).

## Detached Payload Carriers

Large streams upload encrypted segmented ciphertext under a fresh random
`objects/v03/` key before publication. Known-length and unknown-length bodies
use the same writer. Empty streams publish only metadata. The S3 listener still
requires a length from `Content-Length` or valid SigV4 streaming metadata;
unsigned HTTP chunked `PutObject` receives `411 MissingContentLength`.

The writer verifies the completed exact object version, length, post-completion
retention deadline, exact EOF, and full ciphertext digest. Readback requires the
bounded full-object provider interface with an expected-length ceiling checked
before consuming the body. Verification holds one chunk of at most 1 MiB plus
digest state, and refuses providers without that interface. There is no sampling
or buffered-read fallback. A short fenced
`[INDEX_RUN]` commit then publishes the encrypted reference. Payload storage
alone does not make a value visible. A stalled, truncated, oversized, or failed
body does not publish a value. A failed publication can leave an opaque orphan
for later guarded reclamation. Registered in-flight objects are protected from
same-process GC; maintenance across processes still requires external quiescence.

The encrypted carrier record binds the exact object key and version, stored
length, ciphertext digest, historical keyring envelope, carrier ID, content key,
segment size, total plaintext length and selected parts. Backend payload bytes
contain only concatenated ciphertext and 16-byte tags. There is no payload header.

The descriptor accepts at most 10,000 positive-length parts in strictly increasing
original part-number order. Each part records its number, fresh 32-byte attempt ID
and plaintext length. Every part ends on its own segment boundary, so completion
can assemble independently sealed parts without re-encryption. This is a format
capability; client multipart endpoints remain deferred. The current writer emits
one part. Ordinary metadata records retain their 16 KiB cap; only a standalone
container record can use up to 512 KiB, within the existing bounded index frame.

Readers validate lengths, bounds and ordering, then derive part offsets once.
Range translation accounts for a short final segment in each part. Compaction
and checkpoints preserve descriptors without copying payloads. Full reads
verify the first bounded segment group before returning a response body and
withhold the final group until exact EOF and the aggregate digest match. Cache
identities bind repository/keyring context and every carrier, attempt, part,
layout and content-length fact; decryption uses the real payload identity.

### Shared segment authentication

All payload carriers use XChaCha20-Poly1305 with a 24-byte nonce derived as:

```text
context = carrier_id[32] || attempt_id[32] || part_or_record_u32be || segment_u64be
nonce = HMAC-SHA256(content_secret,
    "rs3:payload-segment-nonce:v3" || 0x00 ||
    len_u64be(aad) || aad || len_u64be(context) || context)[0..24]
```

Canonical AAD starts with `rs3:payload-segment-aad:v3`, then length-framed
repository/historical-keyring context, containing object key and content-key ID.
It binds the optional section ordinal, fixed context above, segment plaintext
length, EOF byte and length-framed carrier layout. Integers use big-endian bytes.
A detached layout binds segment size. A pack layout additionally binds pack size,
record count, record offset and length, and segment offsets and lengths.

Writers generate a fresh attempt ID before sealing a replacement part or changed
pack. Repeating backend transmission of already sealed bytes preserves the same
attempt. Matching content is not an upload identity. Attempt and layout metadata
stay encrypted; object counts, ciphertext lengths and write timing remain the
accepted backend observations.

Gateway deduplication remains deferred because it adds equality and
shared-liveness leakage; Kopia already chunks, packs, and deduplicates its own
repository blobs. Any future deduplicating mode needs an explicit capability
and its own security and GC qualification.

## Framed Index Runs

`INDEX_RUN` is the append-friendly unit for namespace mutations. Runs are
immutable, sorted, encrypted, and divided into independently authenticated
bounded frames. A normal commit embeds one recent run. Compaction writes metadata-only sibling commits and makes their exact run
sections reachable from an accepted catalog.

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
generation, size, and modification time. Frame-local tables deduplicate exact
pack and detached carriers, including object keys, provider versions, stored
lengths, authenticated digests, and historical keyring context. A run may carry
one self-pack declaration. Canonical varints and fixed-width binary fields replace
JSON, hex,
decimal byte arrays, durable prefix tokens, nested sealed manifests, and
repeated per-record identifiers. Projection record counts and mutation-ordinal
pairing are authenticated and validated.

Logical paths and projection bounds exist only in authenticated ciphertext.
`v03` does not persist prefix-token objects or path-shaped keys. A reader may
initially materialize a compact in-memory state, but the durable layout must
also permit a future bounded local cache and range-selected frames without a
format change.

Wire version 7 uses canonical length-delimited records and no compression. Each
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
compacted runs are sealed sections in exact sibling `commits/v03/` delta-carrier
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
corruption. Source-relative self-pack pointers are normalized to
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

Format-envelope and keyring-envelope objects are control-plane inputs with
fixed encoded-size ceilings of 1 MiB and 16 MiB respectively. The provider's
declared response length is checked before allocation, and an exact terminal
EOF is required. Bootstrap and recovery inventories use provider-private pages
under fixed total page and raw-member ceilings; a partial or over-budget
inventory is never interpreted as empty.

Both encrypted envelopes use one version-3 canonical CBOR map. Integer keys
0 through 8 encode, in order: version, purpose, generation, repository ID,
public salt, wrapping-key ID, nonce, ciphertext, and authentication tag.
Purpose is 0 for keyrings and 1 for format roots. AEAD associated data is the
seven-field map containing keys 0 through 6. The nonce is 12 random bytes;
the detached AES-256-GCM-SIV tag is 16 bytes. Each purpose derives a separate
AEAD key from the wrapping key. SHA-256 covers the exact complete canonical
envelope bytes, including the public fields. Keyring objects end in `.cbor`.

Keyring plaintext is `[3, keys]`, with keys sorted by purpose and key ID. Each
key is `[id, purpose, status, created_at_ms, public_key_or_null, secret_bytes]`.
Purpose tags are namespace 0, content 1, metadata 2, and signing 3. Status tags
are primary 0, enabled 1, disabled 2, and retired 3. Signing public keys are raw
32-byte Ed25519 values. Secret serialization and decrypted plaintext use
zeroizing buffers. Limits are 4,096 keys, 255 bytes per key ID, and 4,096 bytes
per secret. Algorithm, validity-window, and external-KMS descriptor fields are
absent.

The encrypted format-root plaintext is a six-element canonical array:
`[format_version, repository_id, keyring_ref, signing_key_id, provider_profile, retention]`.
An envelope reference is `[generation, digest_bytes_32, object_id, version_or_null]`.
Provider profiles are development 0, atomic-create 1, and retained-version
Object Lock 2. Retention is null or `[mode, retain_days]`, with modes none 0,
governance 1, and compliance 2. Days are an unsigned 32-bit duration. The unused
snapshot-cadence fields have been removed. The outer commit and format-root
version are 3. Envelope generations still count key or format-root rotations.

Portable recovery bundles use the version-3 array
`[3, repository_id_or_null, salt_digest_or_null, anchor, floor, exported_at_ms, signature_or_null]`.
The anchor is `[3, sequence, commit_key, body_digest_bytes_32, version_or_null, signing_key_id, format_ref]`.
The first field is the repository format generation, independent of the format
envelope reference generation.
The format reference occurs once. The optional signature is exactly 64 bytes.
The signature payload is the canonical two-element array containing
`rs3:v3-recovery-bundle-offline-signature:v1` and the six-element unsigned
bundle, omitting the signature slot. Signing requires a repository ID. Thus
the signature binds the salt digest, recovery floor and export time as well
as every accepted-anchor field.

Bundle readers cap input at 16 KiB. Envelope and bundle text fields are capped
at 1,024 bytes, with the narrower key-ID limit above; envelope salts are 32 to
4,096 bytes. All these codecs reject indefinite lengths, nonminimal integers,
unexpected fields or order, and trailing bytes. JSON remains an operator
report format; retired JSON envelopes and recovery artifacts are not accepted.

The runtime keeps one accepted compact state plus a hard-bounded
4,096-mutation overlay. Unaccepted writes never mutate accepted state. Publication
freezes a prefix and permits bounded successor staging within the same total
pending-item limit. Accepting the prefix preserves the successor and its
allocation high-water mark. A failed prefix rejects dependent staged successors.
Startup does not clone a second complete repository state. One atomic RAII
mutation lease owns the overlay; timed and immediate owned publishers retain it.
Direct mutations and maintenance cannot bypass an active coordinator.

Semantic installation checks complete before CAS. A lost CAS reply is reconciled
against the exact child and parent anchors before a successor can publish. An
unresolved outcome or a post-CAS local installation failure requires local
recovery and prevents further mutations until restart from the trusted anchor.
These runtime changes do not alter the repository wire format.

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
   normalizing self-pack references. Preserve newer level-0 and
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

A live payload reference protects its exact pack commit or detached object version. It does
not recursively protect every ancestor merely because the payload was first
written in an old commit. GC resolves active runs by generation before deriving
these exact payload roots. Empty foreground values have no payload dependency. Conservative over-retention is permitted when a mark
cannot be proven complete; deletion on an incomplete or ambiguous mark is not.

GC must finish the whole mark phase before deleting, fail closed on missing or
malformed reachable data, treat unknown retention or legal-hold state as
protected, recheck the maintenance fence and anchor before every deletion, and
delete exact versions only. Prepared but unaccepted objects remain protected
until the configured orphan-age floor passes. Retention-renewal planning
includes catalogs, runs, payload commits, format roots, and keyring envelopes.
The guarded apply uses that single immutable plan, renews and verifies exact
live versions before any deletion, and aborts if authority-root references or
protection metadata are missing. Request-level retention is conservatively
propagated to every dependency required to restore the represented state.
Inventory is consumed through provider-private bounded pages under explicit
page and item ceilings. A provider without bounded paging, an oversized page,
or exhaustion of either ceiling aborts before mutation.

Protected historical anchors must bind the active exact format-root reference.
Supplying a root from another format generation fails before object-store
reads. The gateway does not expose historical-root registration, in-place
format/data-key rotation, or cross-format protected-root renewal. Existing held
graphs also fail full maintenance. New v03 legal holds are disabled until hold
propagation and guarded release cover every restore dependency.

Payload-pack cleaning is a separate space-reclamation operation, not part of
the exact-root deletion proof. A fully dead pack
may be deleted only after the complete exact-root mark, orphan-age floor,
protection checks, and maintenance-fence checks pass. A mixed pack is left in
place until its dead fraction justifies cleaning. Cleaning re-encrypts its live
records into a new random pack, publishes higher-generation physical
references, and retains the old exact version while any current or protected
historical root reaches it. Mutable reference counts are not authoritative.

Current writers never mix different effective `(retention mode, retain days,
legal hold)` cohorts in one new payload pack. Client legal-hold publication is
currently disabled, but the cohort dimension remains a defensive format
invariant for preexisting data. Packs written before that rule, or
otherwise conservatively over-protected, remain safe but may occupy space until
a future cleaner rewrites their live records.

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
repository contract. `v03` has no such mode.

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
`v03` format root, and publishes a genesis catalog commit. The format root binds
the exact envelope generation, key, provider version, and digest. In retained
mode, every restore-critical initialization write must return a provider version
ID.

Genesis preparation produces exact signed bytes before publication. Publication
reads back the complete stored object and reconciles an ambiguous anchor reply
against that exact candidate. A repeated prepared operation reads an already
accepted provider version and refuses a different or newer anchor. Its bounded
journal representation belongs in trusted bootstrap storage; it is not authority
to recreate a lost anchor after completed initialization. The prepared publisher
requires an explicit upload allowance to create a missing object; without one,
it can verify and anchor an existing exact candidate. Durable retry callers must
reserve that allowance before publication. Protected S3 PUTs disable SDK retries
so a lost reply returns to the publication caller before another version is
created. Kubernetes init persists keyring, format and genesis intent in its
declared bootstrap Secret before their writes, with three upload allowances per
artifact. Retries use the verified exact provider versions of their dependencies.
A matching unfinished journal can resume without an anchor; a completed or
missing journal with existing backend data requires explicit recovery.

Initialization is permitted only on a verified fresh prefix. Detection of
unsupported `v01` objects, an existing anchor, an existing format root, or
ambiguous listing state fails closed. There is no automatic import, overwrite,
or migration behavior. The freshness inventory is paged and capped at 4,096
pages and 2,000,000 raw provider members, including filtered version members.

Wrapping-key rewrap preserves repository data keys and is not compromise
recovery. Historical keys may be retired only after reachability and retention
prove that no protected root requires them.

## Implementation and Qualification Gates

Before `commits/v03` can qualify as the repository format, implementation must
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
  checkpoint-and-compaction-inclusive lifetime gate of at most 1.50x;
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
`commits/v03` envelope with index-run wire version 7. The current reader rejects
retired streamed-commit pointers and earlier preview layouts. Recreate evaluation
repositories when the preview wire changes. Catalog, exact descriptors,
framed streaming, and guarded metadata-only mixed-carrier compaction are
integrated, while retained-provider restart/fault GC qualification and final
bounded-recovery qualification remain incomplete. Wire details freeze only
after cryptographic review, scale gates, retained-provider evidence, and
recovery runbooks all pass together.
