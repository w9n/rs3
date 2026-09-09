# Architecture

`rs3` is organized around a narrow gateway, a repository service, and a
provider-neutral storage boundary.

The overview below shows the three important boundaries. S3 backup clients call
the gateway through the S3 API. Inside the trusted gateway process, the
compatibility layer, namespace mapping, payload encryption, encrypted index
state, signed commit publication, and path-redacted admin facts stay under
operator control. The gateway writes encrypted `format/`, `keyrings/`,
`commits/`, and opaque repository `objects/` to the backend and reads or advances a
separate Kubernetes Lease anchor. `rs3-console` only reads path-redacted admin
posture and status.

<figure class="rv-figure">
  <a class="rv-lightbox" href="../assets/architecture-overview.png" aria-label="Enlarge rs3 architecture overview diagram" aria-haspopup="dialog" data-rv-title="Architecture overview">
    <picture>
      <source srcset="../assets/architecture-overview.webp" type="image/webp">
      <img class="rv-diagram" src="../assets/architecture-overview.png" width="1605" height="980" loading="lazy" decoding="async" alt="v03 architecture: S3 clients use the trusted rs3 gateway, which stores encrypted packed or detached payloads in the object store and verifies or advances a separate Kubernetes Lease anchor. An optional read-only console accesses redacted admin status.">
    </picture>
  </a>
</figure>

The gateway is the trusted data-plane boundary. The object store keeps opaque
encrypted objects and can still observe operational signals such as object
counts, sizes, timing, and broad object classes. The external anchor is a
separate latest-state authority for the preview. The gateway must fail closed
when the anchor cannot be read, advanced, or reconciled with verified commit
state.

## Crate Boundaries

| Crate | Responsibility |
| --- | --- |
| `rs3-types` | Typed identifiers and shared policy types. |
| `rs3-crypto` | Key derivation, encryption, metadata sealing, payload envelopes, and commit signatures. |
| `rs3-storage` | Provider-neutral object-store trait, local stores, S3 adapter, retention contracts. |
| `rs3-index` | Durable index and repository state model. |
| `rs3-repository` | Namespace, payload, anchor contracts, commit, replay, maintenance, and commit coordination. |
| `rs3-k8s` | Kubernetes Lease anchor integration surface. |
| `rs3-server` | Gateway process, configuration, identity, S3 boundary, core admin reports, metrics, and shutdown. |
| `rs3-console` | Read-only single-gateway operations UI over the authenticated admin report. |
| `xtask` | Integration, performance, and compatibility automation. |

Cryptographic operations stay behind `rs3-crypto`; higher-level crates should
not add ad hoc hashing, MAC, encryption, or key derivation logic.
Repository streaming hashes, random carrier identities and payload nonce
construction use that boundary. Shared payload layout constants in
`rs3-types` keep index validation and payload writers aligned.

The repository API entrypoint is `rs3_repository::v2::V2Repository`.
Tools can store keyring envelopes through
`rs3_repository::store_keyring_envelope`, passing retention and legal-hold
policy explicitly. The keyring, cache and runtime options shared by repository
operations are private implementation resources.

The local filesystem backend runs asynchronous read, write and inventory I/O
on blocking workers. It publishes synced temporary files by rename or an
exclusive hard link, then syncs directory entries before acknowledging writes
and deletions. This requires a filesystem that supports hard links and directory
syncs; it does not provide versioning or Object Lock. Construction is synchronous.
A canceled filesystem read or listing must be reopened, because reusing its
cursor fails rather than silently skipping work completed by a detached worker.

## Repository State

!!! warning "Format implementation status"
    `commits/v01` has been removed and is unsupported. It has no production
    repositories and will not gain a migration path or dual reader. The runtime
    now publishes bounded normal batches as one compact `PAYLOAD_PACK` plus one
    framed `INDEX_RUN`, and bounded recovery replays those runs without reading
    payload bytes. Signed `INDEX_ROOT` checkpoints catalog exact embedded run
    sections; publication reads back and opens the exact signed root and every
    new compacted run before anchor adoption. They also drive exact maintenance
    reachability. Guarded metadata-only compaction and automatic active-run
    watermarks are implemented for packed and streamed payload carriers.
    Nonempty large streams publish an opaque standalone payload carrier plus a
    short `[INDEX_RUN]` commit containing its encrypted exact reference. Empty
    streams are index-only. Both participate in the same catalog, compaction,
    and GC graph. New bounded writes are partitioned by effective protection
    cohort, and guarded full GC renews exact restore dependencies before orphan
    deletion. Retained-provider restart/fault qualification and pinned-runner
    filesystem qualification remain release blockers. The current automatic-compaction 1M
    in-memory gate and three local separate-process filesystem runs pass.

Normal writes are append-friendly and value-separated:

1. Put every non-empty bounded value in the batch into one encrypted payload
   pack and stage one compact framed binary index run. Empty bounded values are
   index-only. Nonempty large streams use the detached carrier flow below.
2. Publish a signed `v03` commit under a random path-private key.
3. Advance the external commit anchor.
4. Acknowledge the client write only after the covering commit is accepted.

This avoids rewriting many backend objects during normal operation and gives
crash recovery a concrete boundary.

The payload pack is an immutable value log. It carries shared encryption and
container facts once, keeps small-record overhead to one AEAD tag, randomizes
record order, and retains segmented AEAD for large range-readable values. The
pack itself is ciphertext-only. Its encrypted `INDEX_RUN` stores authenticated
shared pack facts plus each record's ordinal, physical offset, and plaintext
length. Per-segment AEAD binds the complete record and segment layout, so a
second plaintext digest is not stored. The accepted record reference preserves
the exact historical keyring-envelope object and digest used by the containing
commit.
This lets a cold read issue one exact range `GET` instead of fetching a pack
directory first. Retention mode, expiry horizon, and legal-hold requirement
define protection cohorts because the backend protects the containing object.

For a nonempty large stream, the preview uploads one encrypted
segmented `objects/v03/` carrier outside the publication lock. It verifies the
completed exact version, length, post-completion retention horizon, EOF, and full ciphertext
digest before a short fenced commit publishes the encrypted reference. This
allows distinct large uploads to overlap while keeping repository ordering at
one atomic anchor transition per mutation. Cancellation before unambiguous
multipart completion aborts the upload. Ambiguous completion, create-only
races, or anchor failure can leave an invisible opaque orphan, which guarded
maintenance reports and later reclaims. Same-process GC excludes registered
in-flight carriers even with a zero minimum age.

The v03 preview does not publish new legal holds. It rejects client hold
requests until every catalog, chain, format, and keyring dependency can be held
and later released through one guarded lifecycle. The storage conformance layer
still tests provider legal-hold mechanics independently. This is an explicit
unsupported S3 capability, not an incomplete protection mode operators may
enable.

The gateway does not deduplicate payloads. Deduplication would add equality
leakage and shared-liveness policy; Kopia already performs chunking and
deduplication for the primary client workload.

`v03` replaces monolithic index snapshots with an encrypted LSM-style index.
Recent immutable foreground runs are level 0. Each compaction selects at most
256 active runs, including older level-1 shards, as one contiguous
generation window with at most 131,072 mutations and 16 MiB of stored run
sections. That read window favors more source runs, then lower mutation/byte
cost and older windows. Signed catalog sizes rank the complete window and one
cheaper contiguous subset before fetching either. The compactor reads the better
estimate first, fetching only signed headers and selected run sections. It tries
the other candidate only when actual sharding or nonreduction makes that useful,
reusing fetched sources. Across both plans the original bounds still apply. A
large older shard can remain unchanged when merging newer runs gives better byte
cost per catalog entry removed. Every fetched source is fully authenticated;
corruption fails the operation. After validating selected sources, it selects newest mutations
and discards upserts proven obsolete by the accepted blinded-key namespace.
Winning tombstones remain to mask older values. This prevents overwritten or
deleted versions from filling the catalog indefinitely, including when full
older shards precede later churn. Runs outside the selected window retain their exact
references. Combining more small runs amortizes root publication. The encoded
source budget does not bound total process memory: decoded records and per-run
structures also occupy memory. The output contains fewer bounded level-1 generation-range shards;
an entirely obsolete window needs no replacement run. Level is a storage tier,
never a compaction epoch. The format accepts only levels 0 and 1.

Equal-generation mutations remain indivisible. Source-relative payload pointers
become exact external historical object, section and keyring-envelope references
before source boundaries disappear. A small signed `INDEX_ROOT` catalog names
the complete active run set and preserves accepted completion receipts. One
fenced anchor CAS publishes the candidate after exact read-back. Compaction
never reads or rewrites payload ciphertext or deletes source objects. Protected
historical roots continue to reach their original exact versions through GC;
compaction does not change history retention policy. Tombstone reclamation
remains future guarded work.

Runs contain two specialized encrypted binary projections linked by mutation
ordinal. The blinded namespace projection answers `HEAD` and `GET`; the
path-sorted listing projection answers prefix listings. Frame-local container
tables share exact object references. Values never live in an index frame, so
LSM compaction is metadata-only and cold recovery does not read user data. Run
wire version 10 includes exact detached-payload references, encrypted client checksums and plaintext MD5 ETags,
an authenticated namespace-key table, and larger bounded small-object
packs. It uses canonical bounded varints for generation and content length in
both projections.

The runtime keeps one accepted compact state plus a hard-bounded 4,096-mutation
overlay. Publication freezes a prefix while the next bounded batch can stage
behind it. Both share the pending-item limit. Accepting a commit installs only
its frozen prefix; a failed publication rejects that prefix and its dependent
staged successor. Sequence allocations are not reused. Reads continue to resolve
against accepted state. Only one carrier publication and anchor transition run
at a time; maintenance drains both batches before entering its exclusion window.

The bounded compaction path follows the same memory invariant. It does not clone
the full accepted state before planning, verifies each source run with
short-lived scratch state instead of accumulating replay state across the
window, and interns shared exact container facts while selecting winners.
Catalog checkpoints and metadata-only compaction validate exact read-back bytes
without materializing another complete query state, then keep the accepted
namespace in place and change only the run inventory and anchor. The scale
harness enforces process peak RSS so these are measured constraints rather than
allocator lore.

Cold recovery is descriptor-first. It walks bounded signed headers from the
anchor to the newest catalog, then verifies and applies one encrypted index
frame at a time. Signed section descriptors let recovery authenticate index
ranges without downloading unrelated payload sections. The recovered state is
installed only after a final anchor recheck. The storage boundary also checks
the declared length of control-plane objects before allocation: format
envelopes are capped at 1 MiB and keyring envelopes at 16 MiB, then the exact
stream must terminate at the declared EOF. Provider implementations must opt
into this pre-allocation-bounded read path; the storage trait fails closed
rather than adapting through a whole-object buffered read. Bootstrap freshness
checks and anchor-import commit inventories consume provider-private pages
under a fixed 4,096-page/2,000,000-member budget. Emptiness probes stop after
the first raw member and permit at most 4,096 empty pages, while unanchored
keyring discovery admits at most two raw members. A provider that cannot page
within the requested bound, returns an oversized page, or exceeds the
applicable budget causes the control path to fail closed.

Format roots and keyrings share a canonical CBOR envelope implemented in
`rs3-crypto`, using bounded CBOR primitives from `rs3-types`. An authenticated
purpose and separate derived AEAD key distinguish the two uses. Portable
recovery artifacts use a bounded canonical CBOR schema in `rs3-repository`;
the CLI keeps JSON inspection reports separate from importable artifact bytes.

Automatic maintenance starts requesting packed-run compaction at 256 active
runs. With no configured guard it degrades and retries at each additional
64-run boundary, then pauses new mutations at 896. The immutable format ceiling
remains 1,024 active runs. Compaction requires the same live Kubernetes
`WriterFence` used for anchor advancement. A fully validated bounded plan that
cannot reduce run count may also defer below 896 and retry later. A configured
guard rejection, corruption, storage or anchor failure, and every other
compaction error poisons the coordinator immediately instead of allowing writes
to run past an uncertain maintenance failure. Already accepted reads remain
available.

Retained writers also track conservative recovery metadata, encoded pending
sections and exact-target capacity separately from cached retention coverage. Ordinary publications add
bounded costs; a cold cache or exhausted estimate requires an exact candidate
graph check before acceptance. Foreground admission leaves a small margin for
an expiry root. The [metadata admission contract](reference/repository-format.md#recovery-metadata-admission)
describes the shared limits and the separate replay and inventory constraints.
Maintenance caches signed commit headers and decodes required historical
sections one at a time, releasing their encoded bytes before following
dependencies. Current replay buffers are released after namespace and accepted
recovery-registry reconstruction. This check does not raise the qualified operating capacity.

The state-flow view below separates the normal write path from the restore read
path. Bounded nonempty writes pack encrypted values with an index run; large
uploads store detached ciphertext referenced by a short index-run commit.
Empty values are index-only. Publication verifies stored ciphertext, accepts
the signed commit through the external anchor, and only then acknowledges the
client write. A restore read
starts from trusted anchor state, verifies the signed catalog and runs, finds
the exact encrypted payload reference, range-reads the retained version when
required, verifies AEAD segments, and returns restored bytes.

<figure class="rv-figure">
  <a class="rv-lightbox" href="../assets/architecture-state-flow.png" aria-label="Enlarge rs3 write and restore state flow diagram" aria-haspopup="dialog" data-rv-title="Write and restore flow">
    <picture>
      <source srcset="../assets/architecture-state-flow.webp" type="image/webp">
      <img class="rv-diagram" src="../assets/architecture-state-flow.png" width="1605" height="980" loading="lazy" decoding="async" alt="Writes use packed values or detached payloads, verify stored ciphertext and advance the Lease before returning success. Restores start from a trusted anchor or retained point, verify the catalog and runs, resolve exact payload references and authenticate segments. Unresolved publication outcomes block mutations.">
    </picture>
  </a>
</figure>

## Path Privacy

The backend object store sees class-like prefixes and opaque object IDs. It must
not see plaintext paths, directory names, Kubernetes namespaces, resource names,
snapshot names, tenant names, or user metadata labels.

Logical lookup uses secret-derived namespace tokens inside the trusted gateway.
Directory listing is answered from repository index state, not by exposing
client paths as backend object keys.

In `v03`, encrypted runs carry a blinded lookup projection and a plaintext-path
listing projection inside authenticated ciphertext. Run keys, public metadata,
and signed headers expose neither paths nor plaintext projection bounds. The
v03 runtime does not persist the legacy durable prefix-token representation.

## Rollback Resistance

The object store can preserve encrypted bytes, but it cannot establish that it
served the latest valid commit. `rs3` therefore separates storage durability
from latest-state authority:

- Object store: encrypted keyring envelopes, format roots, signed commits, and
  independently sealed index runs.
- External anchor: monotonic latest commit sequence and digest.
- Gateway: verification, replay, and fail-closed behavior when the anchor
  cannot be trusted.

Provider retention and Object Lock are useful for preventing deletion of object
versions. They do not replace commit signatures or external anchors.

For `v03`, the external anchor stores the accepted commit key, body digest,
provider version ID when needed, signing key ID, and active format-root
reference. Recovery derives the exact catalog, run, and payload graph from that
root. Anchor import from a trusted bundle verifies the graph before recreating
a missing anchor.

Catalogs and effective index records are exact reachability roots. `INDEX_ROOT`
catalogs name index runs only; effective highest-generation records name exact
payload-pack or streamed-payload carriers. Maintenance marks the exact catalog
and run versions plus the exact payload-containing object versions selected by
live records. A payload reference does not keep its commit's entire ancestry
reachable. Empty foreground values have no payload dependency. GC completes a fail-closed mark before any deletion and rechecks both the
maintenance fence and anchor before deleting an exact version.

Payload-pack cleaning is separate from index compaction. It rewrites live
records from a sufficiently sparse pack into a new random pack, publishes new
higher-generation physical references, and retains the old version until no
current or protected historical root reaches it. It does not use mutable
reference counts as deletion authority.

## Writer Coordination

Read-write failover is supported only inside one Kubernetes apiserver and Lease
coordination domain. The writer owns a monotonic fence epoch on the anchor Lease,
and the same resource-version CAS checks that fence when advancing the anchor.
Checkpointing and compaction use the same authority. Compaction writes
metadata-only delta-carrier commits and the candidate signed root as direct
children of the same accepted base. The candidate runs are exact-referenced by
the root and are not individually anchored. The writer reads back and
authenticates every new run plus the exact signed root, then rechecks the fence
and base anchor before one CAS adopts the root. Recovery rejects a
compacted carrier whose parent, sequence, level, or compaction generation does
not match that sibling publication shape.

Inside one gateway process, a repository instance admits exactly one mutation
owner. A commit coordinator holds an RAII lease that is also retained by every
delayed publisher task; direct mutation and maintenance entry points fail while
that lease exists. This prevents a cancelled request or a second local API path
from publishing and clearing another batch's speculative overlay. All semantic
installation checks occur before anchor CAS. A lost CAS reply is settled by a
resource-version-guarded fencing update on the Lease. Once that update succeeds,
the earlier request cannot land afterward: a matching accepted child completes
normally, while an unchanged parent permits failure rollback. If the fencing
update fails or the outcome cannot be resolved,
or local installation fails after acceptance, callers receive a recovery-required
error and new mutations stop until restart from the trusted anchor.

The single owner does not serialize large request bodies. Distinct declared-
length standalone uploads run concurrently, then queue for the short stage,
commit, and anchor publication section. A stalled standalone request therefore
does not block an unrelated buffered mutation. Conflicting create-only writes
are resolved during fenced publication, with exactly one visible winner.

Disconnected writers that merely share S3 are unsupported. Conditional object
creation can prevent a collision at one key, but it cannot fence a stale writer,
order repository-wide state, or merge divergent encrypted namespace histories.
S3 listing and timestamps are not coordination primitives. A future
disconnected mode would need explicit branches, authenticated merge semantics,
and deterministic conflict policy in a different repository contract.

Payload segmentation is recorded in encrypted pack or detached-payload layouts.
Both carriers use the same attempt-bound segment nonce scheme. Detached layouts
retain original selected part numbers and fresh attempt IDs, allowing independent
parts to be assembled without re-encryption. Readers derive offsets from bounded
authenticated metadata, including each part's final short segment. Backend payload
objects contain only ciphertext and tags. All publication commits use one bounded
PUT; large payloads use backend multipart before their short index publication.

Partial streamed reads fetch only the authenticated ciphertext segments that
cover the requested plaintext range. The in-memory decrypted-segment cache uses
an opaque identity derived from repository and historical keyring context plus
the exact commit, version, body, section, payload-layout, and content-length
facts. The actual payload ID remains the AEAD identity. This prevents cache
entries from aliasing across exact carriers without creating a backend object
or exposing a new backend key.

## S3 Compatibility

The first gateway surface focuses on the operations backup clients need:

- `PUT Object`
- `GET Object`, including ranges
- `HEAD Object`
- `ListObjectsV2`
- unversioned `GetBucketVersioning` and current-only `ListObjectVersions`
- `DELETE Object`
- native conditional create behavior (`PutObject` with `If-None-Match: *`)
- retention and legal-hold plumbing where the backend supports it
- provider version IDs and exact-version reads for retained/Object Lock
  repositories

There are two preview-qualified storage safety profiles. The atomic-create
profile requires native `PutObject` with `If-None-Match: *`. The
retained-version profile requires Object Lock, provider version IDs for all
restore-critical writes, and exact-version reads after a newer latest version
exists. Non-atomic `HEAD` before `PUT` is not a security-equivalent fallback for
either profile.

The preview compatibility workloads are Kopia and Velero with the Kopia
uploader. Kopia drives the lower-level S3 behavior; Velero exercises the
Kubernetes backup and restore workflow through that path. Broader S3
compatibility should be added behind tests that verify restored bytes and
privacy invariants.

## Maintenance Supervisor

Full maintenance is supervised inside the mutation-capable gateway. It is not
a second controller, CronJob, or repository writer. The supervisor depends on
the provider-neutral commit-anchor and maintenance-guard traits; Kubernetes
supplies those contracts with the same fenced Lease used by normal writes.

Automatic mode evaluates bounded retention-deadline, authenticated recovery-expiry,
and reclaimable-orphan facts, adds bounded random jitter, and applies cooldown or
failure backoff only when doing so cannot cross the renewal safety boundary. Manual mode performs no
background inventory scans and accepts explicit operator runs. Restore-readonly
mode forces the supervisor off. A missing guard parks the state machine rather
than retrying or mutating without exclusion.

An operator dry run returns aggregates plus an opaque digest computed by the
repository over the canonical exact private plan. Apply enters the coordinator
maintenance window, drains pending commit work, verifies the guard and anchor,
builds one fresh exact plan, compares its digest, and mutates that same plan
instance. Object/version identities never cross the repository boundary. A
different exact delete or renewal target therefore invalidates approval even
when aggregate counts and bytes happen to match.

The break-glass offline command builds the same repository runtime but first
fences the real anchor Lease. It refuses a live renewing writer and renews its
own fence until the run and release complete. This path is for a stopped gateway
and is not an alternative scheduler.

## Admin Surface

Core code owns the path-redacted admin report model used by doctor checks,
runtime status, backend and anchor posture, retention settings, and
restore-trust summaries. That keeps the S3 data plane independent from
operator UX and broader management concerns.

In `rs3-server`, `src/admin.rs` contains only the shared report builders and
serializable summaries. A separate operator UI or platform integration should
consume those summaries through an explicit admin boundary instead
of sharing backup-client S3 credentials or browsing repository objects
directly. The report shape remains a preview fact contract. Full maintenance is
the first narrow workflow API: read routes accept the admin read or mutation
token, while dry-run, digest-gated apply, cancel, pause, and resume require a
distinct mutation token and emit path-redacted operation records. Recovery,
key-management, and arbitrary storage workflows are not exposed.

`rs3-console` is the narrow single-gateway UI for these reports. It serves a
browser interface and proxies `GET /api/posture`, `GET /api/status`, or `GET
/api/maintenance` to the gateway admin listener. The browser authenticates to
the console; the gateway read token remains server-side. The console has no
repository browser, database, scheduler, work queue, or mutation routes.

Admin and platform surfaces are not part of the S3 data plane and should not
expose client-visible object browsing, backend object IDs, configured bucket
names, repository IDs, prefixes, or secret material.

Mutating workflows other than the narrowly authorized maintenance API, such as
anchor import, recovery apply, key rewrap, data-key rotation, or arbitrary
compaction, stay explicit local operator actions until they have a dedicated
authorization and audit model.
