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
      <img class="rv-diagram" src="../assets/architecture-overview.png" width="1672" height="941" loading="lazy" decoding="async" alt="Architecture overview showing S3 backup clients, the trusted rs3 gateway process, an opaque object store, an external Kubernetes Lease anchor, and the read-only console path.">
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
    Known-length, unknown-length, and zero-length streaming writes publish the
    canonical `[PAYLOAD, INDEX_RUN]` shape and participate in the same catalog,
    compaction, and GC graph. Payload protection cohorts, complete
    retained-provider GC qualification, and pinned-runner filesystem
    qualification remain release blockers. The current automatic-compaction 1M
    in-memory gate and three local separate-process filesystem runs pass.

Normal writes are append-friendly and value-separated:

1. Put every non-empty bounded value in the batch into one encrypted payload
   pack and stage one compact framed binary index run. Empty bounded values are
   index-only. A genuinely streamed request instead writes one encrypted
   `PAYLOAD` followed by its `INDEX_RUN`, including for a zero-length stream.
2. Publish a signed `v02` commit under a random path-private key.
3. Advance the external commit anchor.
4. Acknowledge the client write only after the covering commit is accepted.

This avoids rewriting many backend objects during normal operation and gives
crash recovery a concrete boundary.

The payload pack is an immutable value log. It carries shared encryption and
container facts once, keeps small-record overhead to one AEAD tag, randomizes
record order, and retains segmented AEAD for large range-readable values. The
pack itself is ciphertext-only. Its encrypted `INDEX_RUN` stores authenticated
shared pack facts plus each record's ordinal, physical offset, plaintext
length, and digest. The accepted record reference also preserves the exact
historical keyring-envelope object and digest used by the containing commit.
This lets a cold read issue one exact range `GET` instead of fetching a pack
directory first. Retention mode, expiry horizon, and legal-hold requirement
define protection cohorts because the backend protects the containing object.

A streamed value is also immutable and value-separated, but its ciphertext is
the `PAYLOAD` section of the same commit as its foreground run. While that run
is embedded, a self-stream pointer carries the authenticated payload identity,
section ordinal, and segmented-payload header. Before compaction removes the
source-run boundary, the pointer is normalized to an exact external carrier:
commit key and provider version, stored object length and body digest,
historical keyring-envelope reference, section start, ordinal, offset, length,
and digest, plus the payload identity and header. Compaction and checkpoints
therefore move metadata references only. They do not read or rewrite streamed
payload ciphertext.

The preview does not upload foreground payloads as standalone `objects/v02/`
objects and does not deduplicate them in the gateway. Keeping payload and run in
one signed commit gives publication one atomic anchor transition and keeps
liveness explicit. Standalone carriers and deduplication would add orphan,
retention, equality-leakage, and shared-liveness policy that has not yet been
qualified; Kopia already performs chunking and deduplication for the primary
client workload.

`v02` replaces monolithic index snapshots with an encrypted LSM-style index.
Recent immutable foreground runs are level 0. Each compaction selects at most
the oldest 128 level-0 runs, merges that bounded window newest-wins, retains
tombstones, and emits fewer bounded level-1 generation-range shards. Newer
level-0 runs and existing level-1 shards remain exact-referenced and are not
rewritten. Level is a storage tier, never a compaction epoch. The preview
format accepts only level 0 and level 1, rejecting higher values until a future
capability explicitly defines another tier. Equal-generation mutations remain
indivisible so a root cannot
publish half of one logical generation. Pointers to packs or streams embedded
beside a source run are normalized to exact external historical commit,
section, and keyring-envelope references before source boundaries are
discarded. A retained
level-1 tombstone masks older records in earlier level-1 shards. Reclaiming
those bottom-tier tombstones and the records they mask remains future guarded
or offline maintenance. A small signed `INDEX_ROOT` catalog names the complete
active run set. It does not serialize every live path, and compaction never
reads or rewrites payload ciphertext.

Runs contain two specialized encrypted binary projections linked by mutation
ordinal. The blinded namespace projection answers `HEAD` and `GET`; the
path-sorted listing projection answers prefix listings. Frame-local container
tables share exact object references. Values never live in an index frame, so
LSM compaction is metadata-only and cold recovery does not read user data. Run
wire version 4 adds canonical self-stream and exact external-stream carriers to
the existing bounded pack pointers. It uses canonical bounded varints for
generation and content length in both projections.

The runtime keeps one accepted compact state plus a hard-bounded 1,024-mutation
overlay. An exclusive publication barrier freezes that overlay from pre-CAS
validation through accepted-state installation. Publication failure discards
the overlay instead of rolling back a second full state copy. This preserves
commit atomicity without doubling steady-state namespace memory.

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
installed only after a final anchor recheck.

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

The state-flow view below separates the normal write path from the restore read
path. A normal write blinds the namespace lookup, encrypts payload segments,
stages payload plus an index run, publishes a signed commit, advances the
external anchor, and only then acknowledges the client write. A restore read
starts from trusted anchor state, verifies the signed catalog and runs, finds
the exact encrypted payload reference, range-reads the retained version when
required, verifies AEAD segments, and returns restored bytes.

<figure class="rv-figure">
  <a class="rv-lightbox" href="../assets/architecture-state-flow.png" aria-label="Enlarge rs3 write and restore state flow diagram" aria-haspopup="dialog" data-rv-title="Write and restore flow">
    <picture>
      <source srcset="../assets/architecture-state-flow.webp" type="image/webp">
      <img class="rv-diagram" src="../assets/architecture-state-flow.png" width="1692" height="930" loading="lazy" decoding="async" alt="Write and restore flow showing committed writes through signed v2 commits and anchored restore reads through verified commit state.">
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

In `v02`, encrypted runs carry a blinded lookup projection and a plaintext-path
listing projection inside authenticated ciphertext. Run keys, public metadata,
and signed headers expose neither paths nor plaintext projection bounds. The
transitional runtime's durable prefix-token representation is not carried into
the completed format.

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

For `v02`, the external anchor stores the accepted commit key, body digest,
provider version ID when needed, signing key ID, and active format-root
reference. Recovery derives the exact catalog, run, and payload graph from that
root. Anchor import from a trusted bundle verifies the graph before recreating
a missing anchor.

Catalogs and effective index records are exact reachability roots. `INDEX_ROOT`
catalogs name index runs only; effective highest-generation records name exact
payload-pack or streamed-payload carriers. Maintenance marks the exact catalog
and run versions plus the exact payload-containing object versions selected by
live records. A payload reference does not keep its commit's entire ancestry
reachable. This rule also protects a zero-length streamed carrier even though a
client read can return an empty body without fetching payload bytes. GC
completes a fail-closed mark before any deletion and rechecks both the
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
installation checks occur before anchor CAS. If the anchor advances but local
lock installation fails, callers receive an explicit recovery-required error,
new mutations stop, and the process must restart from the accepted anchor.

Disconnected writers that merely share S3 are unsupported. Conditional object
creation can prevent a collision at one key, but it cannot fence a stale writer,
order repository-wide state, or merge divergent encrypted namespace histories.
S3 listing and timestamps are not coordination primitives. A future
disconnected mode would need explicit branches, authenticated merge semantics,
and deterministic conflict policy in a different repository contract.

Payload segmentation is recorded per pack record or streamed-payload header.
Small packed values use one AEAD record; medium and large values use
independently authenticated segments for bounded range reads. The authenticated
index descriptor carries the physical pack layout or exact streamed section
facts, so neither read path needs an unauthenticated directory lookup. Bounded
commits use one single-part upload with a compact header; only genuinely
streaming commits pay the fixed multipart header reservation.

Partial streamed reads fetch only the authenticated ciphertext segments that
cover the requested plaintext range. The in-memory decrypted-segment cache uses
an opaque identity derived from repository and historical keyring context plus
the exact commit, version, body, section, payload-header, and content-length
facts. The actual payload ID remains the AEAD identity. This prevents cache
entries from aliasing across exact carriers without creating a backend object
or exposing a new backend key.

## S3 Compatibility

The first gateway surface focuses on the operations backup clients need:

- `PUT Object`
- `GET Object`, including ranges
- `HEAD Object`
- `ListObjectsV2`
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

## Admin Surface

Core code owns the path-redacted admin report model used by doctor checks,
runtime status, backend and anchor posture, retention settings, and
restore-trust summaries. That keeps the S3 data plane independent from
operator UX and broader management concerns.

In `rs3-server`, `src/admin.rs` contains only the shared report builders and
serializable summaries. A separate operator UI or platform integration should
consume those summaries through an explicit admin boundary instead
of sharing backup-client S3 credentials or browsing repository objects
directly. The report shape is a preview fact contract, not a complete workflow
API. Mutating workflows require their own authorization, audit, and
stabilization decision.

`rs3-console` is the narrow single-gateway UI for these reports. It serves a
browser interface and proxies `GET /api/posture` or `GET /api/status` to the
gateway admin listener. The browser authenticates to the console; the gateway
admin token remains server-side. The console has no repository browser,
database, scheduler, work queue, or mutating recovery/key-management routes.

Admin and platform surfaces are not part of the S3 data plane and should not
expose client-visible object browsing, backend object IDs, configured bucket
names, repository IDs, prefixes, or secret material.

Mutating workflows such as anchor import, recovery apply, key rewrap, data-key
rotation, compaction, or garbage collection should stay explicit operator
actions until they have a dedicated authorization and audit model.
