# Architecture

`rs3` is organized around a narrow gateway, a repository service, and a
provider-neutral storage boundary.

```text
S3 client / backup tool
        |
        v
rs3 gateway
        |
        +-- S3 compatibility layer
        +-- path-private namespace mapping
        +-- payload segment encryption
        +-- encrypted index deltas
        +-- signed checkpoint publication
        |
        +-------------------+-------------------+
        |                                       |
        v                                       v
opaque object store                    external checkpoint anchor
```

## Crate Boundaries

| Crate | Responsibility |
| --- | --- |
| `rs3-types` | Typed identifiers and shared policy types. |
| `rs3-crypto` | Key derivation, encryption, metadata sealing, payload envelopes, checkpoint signatures. |
| `rs3-storage` | Provider-neutral object-store trait, local stores, S3 adapter, retention contracts. |
| `rs3-index` | Durable index and checkpoint data model. |
| `rs3-anchor` | Checkpoint anchor contract and in-memory test anchor. |
| `rs3-repository` | Namespace, payload, checkpoint, replay, maintenance, and commit coordination. |
| `rs3-k8s` | Kubernetes-facing anchor integration surface. |
| `rs3-server` | Gateway process, configuration, identity, S3 boundary, core admin reports, metrics, and shutdown. |
| `xtask` | Integration, performance, and compatibility automation. |

Cryptographic operations stay behind `rs3-crypto`; higher-level crates should
not add ad hoc hashing, MAC, encryption, or key derivation logic.

## Repository State

Normal writes are append-friendly:

1. Write encrypted payload segments.
2. Write encrypted or authenticated metadata/index state.
3. Publish a signed checkpoint that references the new state.
4. Advance the external checkpoint anchor.
5. Acknowledge the client write only after the covering checkpoint is accepted.

This avoids rewriting many backend objects during normal operation and gives
crash recovery a concrete boundary.

## Path Privacy

The backend object store sees class-like prefixes and opaque object IDs. It must
not see plaintext paths, directory names, Kubernetes namespaces, resource names,
snapshot names, tenant names, or user metadata labels.

Logical lookup uses secret-derived namespace tokens inside the trusted gateway.
Directory listing is answered from repository index state, not by exposing
client paths as backend object keys.

## Rollback Resistance

The object store can preserve encrypted bytes, but it cannot prove that it
served the latest valid checkpoint. `rs3` therefore separates storage durability
from latest-state authority:

- Object store: encrypted objects, checkpoint objects, and optional retained
  evidence.
- External anchor: monotonic latest checkpoint sequence and digest.
- Gateway: verification, replay, and fail-closed behavior when the anchor
  cannot be trusted.

Provider retention and Object Lock are useful for preventing deletion of object
versions. They do not replace checkpoint signatures or external anchors.

## S3 Compatibility

The first gateway surface focuses on the operations backup clients need:

- `PUT Object`
- `GET Object`, including ranges
- `HEAD Object`
- `ListObjectsV2`
- `DELETE Object`
- conditional create behavior
- retention and legal-hold plumbing where the backend supports it

The preview compatibility workloads are Kopia and Velero with the Kopia
uploader. Kopia drives the lower-level S3 behavior; Velero proves the
Kubernetes backup and restore workflow through that path. Broader S3
compatibility should be added behind tests that prove restored bytes and
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

Admin and platform surfaces are not part of the S3 data plane and should not
expose client-visible object browsing, backend object IDs, configured bucket
names, repository IDs, prefixes, or secret material.

Mutating workflows such as anchor import, recovery apply, key rewrap, data-key
rotation, compaction, or garbage collection should stay explicit operator
actions until they have a dedicated authorization and audit model.
