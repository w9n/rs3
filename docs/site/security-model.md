# Security Model

`rs3` optimizes for backup privacy and restore correctness when object storage
is untrusted or partially compromised.

## Goals

- Hide plaintext paths and Kubernetes names from backend-visible storage.
- Encrypt and authenticate payloads and privacy-sensitive metadata.
- Detect tampering with repository objects.
- Detect rollback through signed checkpoints and an external anchor.
- Preserve restore usability for operators using S3-oriented backup clients.

## Non-Goals

- Hiding total repository size, all traffic timing, or source network metadata.
- Protecting data after repository keys and trusted gateway hosts are
  compromised.
- Making S3 Object Lock behave like a repository-wide latest-state oracle.
- Supporting every S3 operation in the first compatibility profile.

## Adversaries

| Adversary | Capability |
| --- | --- |
| Backend reader | Lists objects, reads ciphertext, observes object names, sizes, timestamps, tags, and provider-visible metadata. |
| Backend writer | Deletes, delays, overwrites, reorders, or replays backend objects unless provider controls prevent it. |
| Compromised backup pod | Creates bad new backups while credentials are valid, but should not erase correctly retained old evidence. |
| Compromised Kubernetes control plane | Rewrites the anchor unless protected by RBAC, admission policy, audit logs, and storage-side evidence. |

If Kubernetes and the object-storage account are both fully compromised,
rollback resistance needs an offline or externally protected authority. Online
anchors alone cannot outvote compromise of every online authority.

## Forbidden Backend-Visible Data

Do not expose these outside encrypted and authenticated payloads:

- file paths
- directory names
- Kubernetes namespace names
- Kubernetes object names
- backup schedule names
- snapshot labels
- tenant or customer names

This applies to object keys, tags, unauthenticated metadata, logs, metrics
labels, traces, checkpoints, and error messages.

## Accepted Leakage

The default design accepts specific backend-visible leakage:

| Leakage | Why It Exists | Current Mitigation |
| --- | --- | --- |
| Backend object count | Object stores expose object inventory and request effects. | Batch checkpoints and compact index state where possible. |
| Encrypted object size | The provider stores ciphertext bytes. | Segment sizing and future padding policy. |
| Coarse write and restore timing | The provider sees requests arrive. | Avoid path labels in telemetry; future batching/jitter where useful. |
| Retention mode | Provider retention APIs expose mode and retain-until behavior. | Treat retention mode as policy metadata, not tenant identity. |
| Source network metadata | The provider sees the gateway's network identity. | Deploy through controlled egress where required. |
| Broad object class | Class prefixes support lifecycle and operations. | Keep class names generic and path-free; revisit in a new format if needed. |
| Prefix-token structure | Current prefix tokens reveal token count and shared-token relationships. | Document as an open privacy risk; redesign index compaction before stable-format claims. |

Optional mitigations include padding, pack-size normalization, checkpoint
batching, compaction jitter, and stricter telemetry redaction.

## Control Map

| Requirement | Mechanism | Current Evidence |
| --- | --- | --- |
| Backend keys do not reveal client paths | Opaque backend object IDs and path privacy property tests. | `crates/rs3-repository/tests/path_invariants.rs` |
| Payload bytes are not plaintext in storage | Authenticated encrypted payload segments. | Repository payload tests in `crates/rs3-repository/src/tests/payload.rs` |
| Metadata bytes are not plaintext in durable index state | AES-256-GCM-SIV sealed metadata records. | Crypto metadata tests and repository path-invariant tests. |
| Payload objects cannot be moved silently | Associated data binds ciphertext to backend object context. | Payload tamper and object-context tests. |
| Repository key reuse is compartmentalized | Purpose keys are generated into an encrypted keyring envelope or derived with HKDF-SHA-256 from the master key, repository ID, and public salt on the compatibility path. | Crypto keyring/envelope tests. |
| Envelope swaps are detectable | Signed checkpoints bind the active keyring envelope generation, object ID, and digest. | Repository key-envelope checkpoint test. |
| Old content remains readable after rotation | Enabled historical content keys are accepted for reads. | Repository key rotation tests. |
| Writes are not acknowledged before checkpoint acceptance | Commit coordinator waits for covering checkpoint. | Commit coordinator and checkpoint tests. |
| Storage rollback is not trusted as latest state | Ed25519 checkpoint verification, external anchor model, and retained checkpoint evidence. | Anchor, checkpoint replay, and orphan-report tests. |
| Retention is never shortened | Retention extension contract rejects shortening. | Storage and repository immutability tests. |

## Rollback Rule

A checkpoint is acceptable only when:

- its signature verifies
- its sequence is not lower than the locally trusted sequence
- its digest matches the external anchor when an anchor exists
- its digest matches storage-side evidence when hardened evidence is configured
- its parent reference is valid or it is a trusted compaction root

When the configured anchor cannot be checked, the default behavior is fail
closed. Break-glass restore modes must be explicit and auditable.

## Object Lock Rule

Object Lock protects object versions from deletion or overwrite before their
retention deadline. It does not prevent a backend from presenting an older valid
version as latest, and it does not make a latest pointer trustworthy by itself.

Use Object Lock for retained payload segments, checkpoint objects, and evidence
records. Do not use it as the only anti-rollback mechanism.

## Current Open Risks

- Durable format compatibility is not promised yet.
- Metadata sealing now uses a standard misuse-resistant AEAD, but the durable
  envelope format is still not stable.
- Prefix token shape currently prioritizes semantics and testability; it still
  leaks namespace structure through token count and shared-token relationships.
- Storage evidence depends on provider retention or Object Lock to resist
  deletion by a storage administrator.
- Key retirement must remain retention-aware to avoid losing access to locked
  historical data.

## Review Standard

A security review should not accept prose claims alone. For every new feature,
reviewers should ask:

- What new backend-visible data exists?
- Can the data reveal paths, tenant identity, object equality, object counts,
  file size, timing, or Kubernetes resource names?
- Which test proves the privacy boundary?
- Which runbook explains recovery when the object store or anchor service is
  hostile?
- Does the change preserve fail-closed anchor behavior?
