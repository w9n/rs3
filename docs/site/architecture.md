# Architecture

`rs3` is organized around a narrow gateway, a repository service, and a
provider-neutral storage boundary.

The overview below shows the three important boundaries. S3 backup clients call
the gateway through the S3 API. Inside the trusted gateway process, the
compatibility layer, namespace mapping, payload encryption, encrypted index
state, signed v2 commit publication, and path-redacted admin facts stay under
operator control. The gateway writes encrypted `format/`, `keyrings/`, and
`commits/` objects to the backend and reads or advances a separate Kubernetes
Lease anchor. `rs3-console` only reads path-redacted admin status.

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
| `rs3-anchor` | External anchor contracts and in-memory test anchors. |
| `rs3-repository` | Namespace, payload, v2 commit, replay, maintenance, and commit coordination. |
| `rs3-k8s` | Kubernetes-facing anchor integration surface. |
| `rs3-server` | Gateway process, configuration, identity, S3 boundary, core admin reports, metrics, and shutdown. |
| `rs3-console` | Read-only single-gateway operations UI over the authenticated admin report. |
| `xtask` | Integration, performance, and compatibility automation. |

Cryptographic operations stay behind `rs3-crypto`; higher-level crates should
not add ad hoc hashing, MAC, encryption, or key derivation logic.

## Repository State

Normal writes are append-friendly:

1. Stage encrypted payload and index delta sections.
2. Publish a signed v2 commit under a random path-private key.
3. Advance the external commit anchor.
4. Acknowledge the client write only after the covering commit is accepted.

This avoids rewriting many backend objects during normal operation and gives
crash recovery a concrete boundary.

`v2-preview` stores payload and index-delta sections inside the signed commit
chain. Concurrent PUTs can batch into one signed delta commit. Periodic index
snapshot commits consolidate the live blinded namespace so cold-start replay
walks only from the accepted anchor back to the nearest snapshot.

The state-flow view below separates the normal write path from the restore read
path. A normal write blinds the namespace lookup, encrypts payload segments,
stages payload plus index-delta sections, publishes a signed v2 commit, advances
the external anchor, and only then acknowledges the client write. A restore read
starts from trusted anchor state, verifies the signed chain, loads the nearest
snapshot and newer deltas, finds the encrypted payload reference, range-reads
the exact retained version when required, verifies AEAD segments, and returns
restored bytes.

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

## Rollback Resistance

The object store can preserve encrypted bytes, but it cannot establish that it
served the latest valid commit. `rs3` therefore separates storage durability
from latest-state authority:

- Object store: encrypted keyring envelopes, format roots, and signed commits.
- External anchor: monotonic latest commit sequence and digest.
- Gateway: verification, replay, and fail-closed behavior when the anchor
  cannot be trusted.

Provider retention and Object Lock are useful for preventing deletion of object
versions. They do not replace commit signatures or external anchors.

For `v2-preview`, the external anchor stores the accepted commit key, body
digest, provider version ID when needed, signing key ID, and active format-root
reference. Anchor import from a trusted v2 bundle verifies the signed chain
before recreating a missing anchor.

Payload segment size is per object. The default writer keeps small objects at
512 B segments and raises medium and large objects to larger authenticated
segments to reduce AEAD overhead. Reads still follow the authenticated payload
header, so this is a writer policy, not a repository-format change.

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

There are two production-capable storage profiles. The atomic-create profile
requires native `PutObject` with `If-None-Match: *`. The retained-version
profile requires Object Lock, provider version IDs for all restore-critical
writes, and exact-version reads after a newer latest version exists. Non-atomic
`HEAD` before `PUT` is not a security-equivalent fallback for either profile.

The preview compatibility workloads are Kopia and Velero with the Kopia
uploader. Kopia drives the lower-level S3 behavior; Velero exercises the
Kubernetes backup and restore workflow through that path. Broader S3
compatibility should be added behind tests that verify restored bytes and
privacy invariants.

## Admin Surface

Core code owns the path-redacted admin report model used by doctor checks,
runtime status, backend and anchor posture, retention settings, and
restore-trust summaries. That keeps the S3 data plane independent from
operator UX, management integrations, and management authorization.

In `rs3-server`, `src/admin.rs` contains only the shared report builders and
serializable summaries. A separate operator UI or platform integration should
consume those summaries through an explicit admin boundary instead of
sharing backup-client S3 credentials or browsing repository objects directly.
The report shape is a preview fact contract, not a complete workflow API: fleet
inventory, multi-management workflows, policy workflows, rotation workflows, approvals,
auditing, and recovery orchestration require their own authorization, audit, and stabilization decision.

`rs3-console` is the narrow single-gateway UI for this report. It serves a
browser interface and proxies `GET /api/status` to the gateway admin listener's
`GET /admin/status`. The browser authenticates to the console; the gateway
admin token remains server-side. The console has no repository browser,
database, scheduler, work queue, or mutating recovery/key-management routes.

Admin and platform surfaces are not part of the S3 data plane and should not
expose client-visible object browsing, backend object IDs, configured bucket
names, repository IDs, prefixes, or secret material.

Mutating workflows such as anchor import, recovery apply, key rewrap, data-key
rotation, compaction, or garbage collection should stay explicit operator
actions until they have a dedicated authorization and audit model.
