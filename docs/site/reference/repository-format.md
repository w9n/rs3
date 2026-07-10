# Repository Format Reference

The repository format is draft. This page is the design contract for the next
repository generation, `commits/v02`. It is not a compatibility promise and it
does not describe a format that the gateway can read or write today.

!!! warning "Implementation status"
    The current prototype stores signed commits under `commits/v01/` and is
    deprecated. No production repository depends on it, so `rs3` will not add a
    migration path or a dual reader. The `commits/v02` reader, writer, index
    catalog, compactor, and recovery gates described here remain to be
    implemented. Until those gates pass, the current runtime is evaluation-only.

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

That generation is deprecated and may be removed. It is not an input to the
`v02` design, and initialization of a `v02` repository must fail if the chosen
backend prefix is not demonstrably fresh. Importing or converting a `v01`
repository is outside the product contract.

New repositories will use a distinct generation:

```text
commits/v02/<20-digit-sequence>/<32-byte-random-id-base64url>
objects/v02/<32-byte-random-id-base64url>
```

The sequence component bounds commit discovery and operational analysis. The
random component prevents paths, namespace equality, and content identity from
appearing in keys. `objects/v02/` contains independently sealed compacted index
runs. Its keys do not distinguish index levels, tenants, paths, or workloads.

The other backend-visible classes remain generic:

```text
format/
keyrings/
```

These class names, object counts, ciphertext sizes, provider version IDs, and
write/compaction timing are accepted leakage. Plaintext catalog bounds, run
levels, logical object counts, paths, and payload identities remain encrypted.

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

The header has a fixed maximum size. Readers reject non-canonical encodings,
unknown required capabilities, overlapping sections, arithmetic overflow,
duplicate ordinals, lengths outside the object, and trailing data not covered
by the signed layout.

Normal commits contain zero or more encrypted `PAYLOAD` sections and one
encrypted `INDEX_RUN` section. A catalog checkpoint commit contains an
encrypted `INDEX_ROOT` section. A checkpoint may also cover a final bounded
mutation batch, but the catalog must describe the exact resulting state.

Signed per-section descriptors are required for descriptor-first recovery. A
reader can authenticate an index range without downloading unrelated payload
sections. Payload ciphertext is authenticated when the referenced object is
read. The whole-object digest remains an identity and maintenance check, not a
reason to read every payload during startup.

## Payload Sections

Payload sections use a segmented authenticated envelope. The encrypted index
record stores the exact commit key and provider version, commit digest, section
ordinal, encrypted offset and length, plaintext length, payload identity, key
identifier, segment size, and nonce/header facts needed for bounded full and
range reads.

Segment associated data binds ciphertext to the format generation, repository
context, payload identity, section ordinal, segment index, plaintext length,
and final-segment marker. Moving a segment to another commit, section, payload,
or ordinal must fail authentication.

Segment size remains a writer policy recorded in each payload. Readers follow
the authenticated header rather than assuming the current default. Padding is
not part of the first `v02` contract; adding it requires a new capability and
new leakage and amplification evidence.

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

Runs contain two encrypted projections:

- a namespace projection sorted by the secret-derived lookup key for `HEAD`
  and `GET`; and
- a listing projection sorted by logical path for ordered prefix listing inside
  the trusted gateway.

Logical paths and projection bounds exist only in authenticated ciphertext.
`v02` does not persist prefix-token objects or path-shaped keys. A reader may
initially materialize a compact in-memory state, but the durable layout must
also permit a future bounded local cache and range-selected frames without a
format change.

The first generation uses canonical length-delimited records and no
compression. Each ciphertext frame and run has an explicit record and byte
limit; the target maximum encrypted run object is 8 MiB. Index-frame associated
data binds at least the format generation, exact containing object key and
version, section ordinal, run identity, and frame ordinal. Reordering,
duplicating, or transplanting frames must fail authentication.

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

Size-tiered compaction merges several similarly sized immutable runs into a
bounded set of larger, sharded runs. This intentionally favors low write
amplification for append-heavy backup ingestion over the lowest possible point
read amplification. Compaction never rewrites payloads merely to consolidate
the namespace.

## Descriptor-First Recovery

Cold recovery starts only from the external anchor:

1. Read and verify bounded signed commit headers from the anchored head back to
   the newest accepted `INDEX_ROOT`.
2. Retain compact descriptors, not commit bodies or cumulative encrypted index
   sections.
3. Open the catalog and every named run by exact key and provider version.
4. Verify and apply one bounded frame at a time, resolving records by generation
   into one accepted state.
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
6. Open the candidate through a fresh reader and verify state cardinality and
   selected payload reads.
7. Recheck the writer fence and unchanged anchor.
8. Advance the real anchor with one resource-version CAS that also checks the
   fence identity and token.
9. Install the accepted catalog and state.
10. Leave replaced and failed candidate objects for conservative orphan GC.

Uploading a run does not make it reachable. Only the fenced anchor CAS makes
the signed catalog an accepted root. Delayed list visibility, duplicate
versions, and abandoned uploads are therefore availability and cleanup
concerns, not state-selection mechanisms.

## Reachability, Retention, and GC

The authoritative reachability graph starts from the current anchor and every
explicitly protected historical anchor. For each root it includes:

- the exact catalog and post-catalog commit versions;
- the exact active index-run versions;
- the exact payload commit versions selected by effective live index records;
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

Payload repacking is a separate future operation. Index checkpointing and
compaction must not copy every live payload.

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
deprecated `v01` objects, an existing anchor, an existing format root, or
ambiguous listing state fails closed. There is no automatic import, overwrite,
or migration behavior.

Wrapping-key rewrap preserves repository data keys and is not compromise
recovery. Historical keys may be retired only after reachability and retention
prove that no protected root requires them.

## Implementation and Qualification Gates

Before `commits/v02` can replace the deprecated prototype, implementation must
include:

- canonical encoding, crypto, corruption, and cross-object transplant vectors;
- descriptor and frame parsers with fixed hostile-input budgets and fuzzing;
- fresh-process 10k, 100k, and 1M committed-write recovery gates that verify
  exact cardinality plus first, middle, and last payload bytes;
- a 1M filesystem recovery target of at most 180 seconds and 4 GiB RSS on the
  documented 4-vCPU, 16-GiB runner;
- no payload reads during normal index recovery and at most 1.25x index byte
  read amplification;
- checkpoint crash, stale-fence, delayed-read, replay, deletion, and exact
  provider-version fault tests;
- GC tests proving exact payload reachability across overlapping runs,
  tombstones, protected roots, and failed compactions; and
- a retained-provider restart and writer-handoff qualification run.

Absolute time limits are enforced only on pinned runners. Correctness,
allocation, request, byte, and amplification ceilings apply everywhere.

## Compatibility Promise

There is no stable repository-format promise yet. `commits/v01` is deprecated
without migration support. `commits/v02` is a fresh, currently unimplemented
format target. Its wire details freeze only after the implementation,
cryptographic review, scale gates, retained-provider evidence, and recovery
runbooks all pass together.
