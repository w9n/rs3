# Repository Format Reference

This reference describes the current `commits/v03` encoding and runtime bounds
for implementers and verifiers. The format remains preview-scoped. The gateway
reads and writes bounded payload packs, encrypted index runs, signed index-root checkpoints, and
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
- Every accepted repository transition has a signed sequence and exact parent
  selected by an external anchor.
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

The complete header span is limited to 8 KiB and a reader accepts at most three
sections. Delta commits contain `[INDEX_RUN]`, `[PAYLOAD_PACK, INDEX_RUN]`, or
one of those layouts with a trailing `[RECOVERY]`; root commits contain
`[INDEX_ROOT]` with an optional `[RECOVERY]`. Every section must carry the
must-understand flag, with no compression. Every commit uses a single PUT;
there is no upload-mode field or padded header. Retired section codes
`0x0001` through `0x0004`, nonzero reserved bytes or capabilities, noncanonical
encodings, overlapping sections, arithmetic overflow, and trailing bytes
outside the signed layout fail closed. Signed section digests, framed indices,
compacted runs and detached payloads are intrinsic to format 3; no capability
bits are assigned. Root catalogs accept levels zero and one.

`publish_time_ms` is signed wall-clock metadata. Each accepted child must have a
strictly later publication time than its exact parent. The writer chooses that
time from one sampled clock value with a bounded lead for millisecond
tie-breaking, and exact retries reuse the prepared value. Recovery expiry uses
the separately sampled current time and its declared uncertainty; a signed
publication timestamp alone never authorizes expiry. Sequence order is
independently validated.

The current framed index plaintext is wire version 10. Frame, section and mutation
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

## Authenticated Recovery History

When the recovery policy is enabled, accepted v03 commits carry an encrypted
`Recovery` section with wire code `0x0008`. The section is authenticated by the
containing signed section descriptor and sealed with the metadata key under the
same repository and exact-object context as other encrypted metadata. A root
commit may pair it with `INDEX_ROOT`; a child commit may pair it with `INDEX_RUN`
and an optional payload pack.

Each accepted successor registers the exact predecessor anchor in this section.
The registered point stores the predecessor publication time, the fixed
supersession deadline, and the policy identity that produced that deadline.
The accepted current anchor is implicit and is not duplicated as a historical
record. A point enters history only when its successor is accepted through the
external anchor. The server preset is a 30-day window with a one-day renewal
margin; these values and the clock uncertainty are bounded configuration. A
reduction changes the policy for new points; it cannot shorten an already
accepted point's deadline.

Expiry is an authenticated state transition. The writer derives a conservative
cutoff from a sampled current clock minus the configured uncertainty, then
publishes that cutoff in a later accepted recovery section under the normal
writer fence and anchor protocol. Parent chronology uses signed commit times;
expiry does not use provider timestamps or the commit timestamp as a substitute
for current time.

The encrypted registry uses a bounded tail and exact page references. The
encoded recovery section is capped at 8 MiB, the active tail at 4,096 points,
the registry at 1,024 pages, and each page at 4,096 points. Page references
carry authenticated sequence and deadline claims plus the exact commit,
provider-version, section, and page location needed to read that page. Recovery
loads one exact page at a time and never treats an old page's embedded registry
as new authority. If a page contains both expired and live points, its release
is delayed conservatively to the page's maximum deadline. When the tail holds
4,096 live points and 1,024 live pages remain, publication fails closed with a
recovery-history capacity error: no promise is shortened and no live point is
dropped, and every write path shares that refusal until the oldest page's
maximum deadline passes the expiry cutoff. The storage ceiling is therefore
about 4.2 million points, which at the thirty-day preset is roughly 1.62
accepted commits per second sustained for the whole window. These storage
bounds do not establish an effective history capacity: replay, graph,
inventory, and provider byte budgets can impose a lower limit, and v03 has no
qualified four-million-point capacity claim.

For the retained-version Object Lock profile, a successor is not acknowledged
until the exact restore dependency graph is covered through the required
supersession promise. Renewal reserves an additional margin that subsequent
writes may reuse. The writer renews and post-verifies exact
provider versions, rechecks the writer fence and unchanged parent, and only then
performs the anchor CAS. Missing version IDs, insufficient protection, an
ambiguous provider result, a budget exhaustion, or a fence change fails closed.
Non-retained profiles do not provide this provider-history guarantee and remain
subject to their selected provider conformance contract.

Each S3 endpoint exposes one unversioned namespace: the live namespace by
default, or the selected historical namespace in a readonly recovery gateway.
Historical `versionId` reads, version listings, delete-marker APIs, and client
registration of arbitrary historical roots are unsupported. Recovery points are
selected through the separate authenticated operator recovery interface and
opened in an isolated read-only namespace; selection never rewinds or advances
the live anchor.

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
can assemble independently sealed parts without re-encryption. Client multipart
writes use this layout; ordinary single-stream writes emit one part. Ordinary
metadata records retain their 16 KiB cap; only a standalone
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

## Metadata-Only Copies

A supported same-bucket `CopyObject` captures a current accepted namespace
entry under the writer fence and creates a fresh encrypted destination manifest
and `INDEX_RUN` upsert. The upsert preserves the source plaintext length, ETag,
flexible checksum, effective protection, and exact authenticated payload
reference. It creates no payload-pack record, detached payload, plaintext
payload read, re-encryption, or carrier rewrite. A later source overwrite or
logical delete therefore cannot alter the copied value.

The copied upsert is an ordinary staged mutation: it shares admission bounds,
compatible protection-cohort batching, signed publication, anchor advancement,
and rollback behavior with writes. Source `If-Match`, when supplied, compares
the trusted accepted ETag at capture rather than a provider latest object. The
format has no client-visible historical copy reference and no metadata-replace
variant.

For retained copies, the provider's exact source carrier and restore metadata
dependencies must cover the fresh copy timestamp before the new entry is
acknowledged. The check can use bounded metadata `HEAD` and retention-extension
operations, but never payload reads or a full-GC traversal. Missing exact
versions, deadlines, or protection facts fail closed; a copy never shortens the
source protection clock.

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
compact payload pointer, trusted `HEAD` metadata, retention state, mandatory
trusted `ObjectEtag` derived from plaintext MD5 values, and an optional flexible
checksum. The listing projection stores the encrypted logical path once
together with generation, size, and modification time. Frame-local
tables deduplicate exact pack and detached carriers, including object keys,
provider versions, stored lengths, authenticated digests, and historical
keyring context. A run may carry one self-pack declaration. Canonical varints
and fixed-width binary fields replace
JSON, hex,
decimal byte arrays, durable prefix tokens, nested sealed manifests, and
repeated per-record identifiers. Projection record counts and mutation-ordinal
pairing are authenticated and validated.

Logical paths and projection bounds exist only in authenticated ciphertext.
`v03` does not persist prefix-token objects or path-shaped keys. A reader may
initially materialize a compact in-memory state, but the durable layout must
also permit a future bounded local cache and range-selected frames without a
format change.

Wire version 10 uses canonical length-delimited records and no compression. Each
ciphertext frame and run has an explicit record and byte
limit; the maximum encrypted run object is 8 MiB. Index-frame associated
data binds at least the immutable repository identity, exact historical
keyring-envelope reference, exact containing object key, section ordinal, run
identity, and frame ordinal. The provider version does not exist until after
upload, so the accepted signed catalog will bind that returned exact version
together with object length and ciphertext digest. Reordering, duplicating, or
transplanting frames must fail authentication.

Wire version 9 added one optional checksum field to each namespace upsert. Wire
version 10 adds the mandatory `ObjectEtag` field. It is exactly 20 bytes:
big-endian u32 multipart count followed by the raw 16-byte MD5 digest. Count
zero identifies a single-object ETag; counts one through 10,000 identify a
multipart ETag. A one-byte length prefixes at most 48 bytes of canonical
`ObjectChecksum` encoding, `[algorithm_tag, composite_parts_or_zero, raw_digest]`;
a zero length
means that no client checksum was accepted. The supported algorithms are
CRC32, CRC32C, CRC64NVME, SHA1, and SHA256. Full-object checksums cover the
complete plaintext object stream. Composite checksums hash the ordered raw
part digests and carry the exact part count. This field is encrypted and
authenticated with the namespace metadata. It is never an object-store key,
provider metadata value, or repository authentication digest.

Default plaintext and framing bounds are distinct:

| Bound | Limit |
| --- | ---: |
| Encoded run plaintext | 7 MiB |
| Plaintext projection frame | 1 MiB minus 1 KiB |
| Ordinary record | 16 KiB |
| Standalone container record | 512 KiB |
| External containers | 4,096 |
| Mutations per run | 65,536 |
| Logical path | 1,024 bytes |
| Physical run envelope | 8 MiB |
| Frames per physical run | 4,096 |

## Multipart Completion Receipts

The repository publication API binds each accepted multipart completion to one
receipt inside its encrypted index run. Metadata record tag 4 follows all
container and namespace-key records and occurs at most once. It uses the
canonical CBOR array `[upload_id, commit_sequence, selection_digest,
attempts_digest, logical_key, content_len, etag, checksum]`. IDs and digests
are 32-byte strings. The `etag` field is a CBOR byte string containing the exact
20-byte `ObjectEtag` encoding. The final checksum field is either null or a CBOR
byte string containing the bounded canonical `ObjectChecksum` encoding
described above. Commit sequence is the enclosing accepted commit sequence,
independent of namespace mutation generations. The receipt binds the run's
single upsert key, plaintext length, ETag, and checksum exactly. The run may also
carry stale namespace tombstones for
the same key and generation; they do not change the receipt binding. Each
receipt is capped at 2,048 bytes, with a 1,024-byte key and an exact 20-byte
ETag encoding.

The client-selection digest uses SHA-256 over
`rs3:v3-multipart-client-selection:v2` followed by a zero byte, a big-endian
u64 part count, then each big-endian u32 part number, big-endian u16 unquoted
ETag length and exact ETag bytes. It then includes, for each selected part and
the optional final checksum, a big-endian u64 length plus its canonical checksum
bytes, or a zero length when absent, followed by one byte for the declared
construction kind (`0` none, `1` full-object, `2` composite).

The selected-attempt digest uses the domain
`rs3:v3-multipart-selected-attempts:v1` followed by a zero byte and big-endian
u64 count, then each big-endian u32 part number, 32-byte attempt ID,
big-endian u64 plaintext length and 32-byte expected ciphertext digest.

Root plaintext wire version 6 appends a big-endian u32 receipt count after the
run catalog, followed by big-endian u32 lengths and canonical receipt bytes,
sorted by upload ID. The latest 1,024 accepted completion results survive
checkpoint, compaction and replay. A root snapshot replaces receipt state
reconstructed from its named runs, so old runs cannot resurrect evicted results.
Post-root accepted deltas update that bounded set. Root receipts must precede
the root's commit sequence. Compacted runs carry no completion record.

Receipt eviction is count-based and has no payload-retention meaning. Lookup
requires the original upload ID, logical destination and exact selected-part
digest; it can return the original result after a later overwrite without
publishing again. An unknown or evicted ID never authorizes a new write.
Receipt preparation precedes the anchor CAS, and installation accompanies the
accepted namespace change. Unresolved anchor outcomes require recovery before
receipt lookup or another write. The client-facing multipart routes use these primitives; see
[Supported S3 operations](s3-operations.md) for current option and session limits.

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
map. Foreground runs are level 0. The compactor selects at most 128
active runs, regardless of level, as a contiguous generation window, capped at
131,072 source mutations and 16 MiB of stored index-run sections. Catalog facts
select the window with the most runs; ties prefer fewer mutations, fewer stored
bytes, then the oldest window. This avoids stalling behind full live older
shards when newer churn can reduce the catalog. Both maximum-size runs fit
these ceilings. The compactor validates every source and selects the newest
mutation for each blinded key.
The already accepted namespace proves an upsert obsolete when that blinded key
is absent or has a newer generation. Those upserts are omitted; winning
tombstones remain. A namespace generation behind a source or inconsistent
same-generation namespace-key identity fails closed. Different mutations for
the same blinded key and generation fail before pruning, even if obsolete.

Runs outside the window remain exact-referenced and unchanged. Output is level
1, never an incrementing compaction epoch. The decoder accepts only levels 0
and 1. Source-relative self-pack pointers become exact historical commit,
version, section, payload and keyring-envelope facts. All other winning mutation
metadata is preserved. The output uses the fewest generation-range shards
accepted by the canonical run codec, preserving each equal-generation group.
A fully obsolete window emits no replacement carrier; otherwise output must
contain fewer runs than the source window. The root preserves the accepted
coverage generation, logical object count and completion receipts.

Compaction is metadata-only: it never reads, decrypts or rewrites payload
ciphertext. It does not delete replaced runs or payloads. Protected historical
roots still name their original exact dependencies, and guarded GC marks those
roots independently. Winning tombstone reclamation remains future guarded
work; this merge changes neither the wire encoding nor history retention policy.

An index root is bounded to 8 MiB and 1,024 active runs, with aggregate
ceilings of 16,777,216 mutations and 8 GiB of stored run bytes. Per-run limits
remain 65,536 mutations, 4,096 frames and 8 MiB. These bounds apply before
accepting the catalog, independently of the number of live logical objects.

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
6. Verify catalog cardinality and structural invariants. Payload checks belong
   to subsequent reads and qualification tests, not index reconstruction.
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

Default replay budgets are independent of the active-run watermarks:

| Budget | Default |
| --- | ---: |
| Commits walked to a snapshot | 4,096 |
| Cumulative provider-reported commit-object bytes | 1 TiB |
| Retained encrypted index-section bytes | 64 MiB |
| One body-verification range read | 8 MiB |

These are `V2ReplayLimits` defaults. They are verifier ceilings, not automatic
checkpoint triggers. Descriptor-first startup avoids reading unrelated payload
bytes even though their containing object sizes count toward its object budget.

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
2. Select and verify at most 128 active runs across levels 0 and 1.
   Merge this contiguous window newest-wins, prune upserts proven obsolete by
   the accepted blinded-key namespace, retain winning tombstones and normalize
   self-pack references. Preserve every run outside the window unchanged.
3. Shard the result on generation boundaries and write each metadata-only run
   in an unanchored delta-carrier commit that is a direct child of the captured
   base.
4. Write an unanchored signed `INDEX_ROOT`, also a direct child of that base,
   that exact-references every new sibling carrier plus the preserved run
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

The writer also refuses a mutation that would create a 1,025th active run.
[Automatic watermarks](#automatic-catalog-watermarks) provide earlier
backpressure; the format ceiling remains the final bound.

## Reachability, Retention, and GC

The authoritative reachability graph starts from the current anchor, every
unexpired point in the accepted encrypted recovery registry, and any explicitly
supplied same-format protected root. For each root it includes:

- the exact catalog and post-catalog commit versions;
- the exact active index-run versions;
- the exact payload-containing object versions selected by effective live index
  records;
- the active format root and keyring envelopes; and
- keys needed to authenticate or decrypt those objects.

A live payload reference protects its exact pack commit or detached object version. It does
not recursively protect every ancestor merely because the payload was first
written in an old commit. A metadata-only copy adds another live encrypted
reference to that same exact carrier; source overwrite or deletion does not
break the copied reference, and exact-root GC retains it until no live or
protected root requires it. GC resolves active runs by generation before
deriving these exact payload roots. Empty foreground values have no payload
dependency. Conservative over-retention is permitted when a mark cannot be
proven complete; deletion on an incomplete or ambiguous mark is not.

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
reads. The gateway does not expose client registration of arbitrary historical
roots, in-place format/data-key rotation, or cross-format protected-root
renewal. Existing held graphs also fail full maintenance. New v03 legal holds
are disabled until hold propagation and guarded release cover every restore
dependency.

Payload-pack cleaning is not implemented. A fully dead pack can be reclaimed
by exact-root GC once age, protection and fence checks pass. A mixed pack keeps
its dead bytes while live or protected historical references reach it. Current
writers partition new packs by effective protection cohort, but there is no
promise of prompt space reclamation from partially dead packs. A future cleaner
must publish replacement references and preserve old exact versions for every
protected root; index compaction does not copy payloads.

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

A new initialization requires a verified fresh prefix. Unsupported `v01` or
`v02` objects, foreign existing state and ambiguous inventory fail closed. Only
a matching unfinished bootstrap journal can resume its prepared operation;
there is no automatic import, overwrite or migration. The freshness inventory
is paged and capped at 4,096 pages and 2,000,000 raw provider members, including filtered version members.

Wrapping-key rewrap preserves repository data keys and is not compromise
recovery. Historical keys may be retired only after reachability and retention
prove that no protected root requires them.

## Implementation and Qualification Gates

Frozen canonical fixtures and nine fuzz targets cover current codecs;
[Testing](../testing.md) maps the executable coverage and its limits. Full
qualification still requires strict publication chronology, retained-provider
restart/fault evidence, production-cardinality maintenance and matched recovery
and amplification results for the exact candidate. Historical v02 measurements
do not qualify v03. See [Production Preview](../production-preview.md) and
[Performance](../performance.md) for evidence and release gates.

## Compatibility Promise

There is no stable repository-format promise yet. `commits/v01` is removed and
unsupported, as is `commits/v02`, without migration support. The gateway reads
and writes the preview `commits/v03` envelope with index-run wire version 10 and
index-root wire version 6. The current reader rejects wire versions 8 and 9 and
other earlier preview layouts. Recreate evaluation repositories when the preview wire
changes. Catalog, exact descriptors,
framed streaming, and guarded metadata-only mixed-carrier compaction are
integrated, while retained-provider restart/fault GC qualification and final
bounded-recovery qualification remain incomplete. Wire details freeze only
after cryptographic review, scale gates, retained-provider evidence, and
recovery runbooks all pass together.
