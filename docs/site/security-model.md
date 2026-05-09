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
| Deterministic metadata equality | Stable metadata sealing can produce identical sealed bytes for identical metadata under identical associated data. | Use object-type-specific associated data and signed reachability; revisit before stable-format. |
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
| Repository key reuse is compartmentalized | Random purpose keys are generated into an encrypted keyring envelope and bound to the repository ID, public salt, and wrapping-key identity. | Crypto keyring/envelope tests. |
| Envelope swaps are detectable | Signed checkpoints bind the active keyring envelope generation, object ID, and digest. | Repository key-envelope checkpoint test. |
| Old content remains readable after data-key rotation | Enabled historical content keys are accepted for reads. | Repository key rotation tests. |
| Writes are not acknowledged before checkpoint acceptance | Commit coordinator waits for covering checkpoint. | Commit coordinator and checkpoint tests. |
| Storage rollback is not trusted as latest state | Ed25519 checkpoint verification, Kubernetes Lease anchor, and retained checkpoint evidence. | Anchor, checkpoint replay, restore verification, and orphan-report tests. |
| Incident restore does not advance repository state | `restore-readonly` mode requires an accepted anchor and rejects supported mutations. | Gateway mode config, startup, and S3 adapter tests. |
| Retention is never shortened | Retention extension contract rejects shortening. | Storage and repository immutability tests. |
| Operator reporting does not become a path oracle | Core admin reports are path-redacted and do not include path browsing fields. | Admin status redaction tests. |

## Rollback Rule

A checkpoint is acceptable only when:

- its signature verifies
- its sequence is not lower than the locally trusted sequence
- its digest matches the external anchor when an anchor exists
- its digest matches storage-side evidence for the accepted checkpoint
- its parent reference is valid or it is a trusted compaction root

When the configured anchor cannot be checked, the default behavior is fail
closed. Break-glass restore modes must be explicit and auditable.

The Kubernetes Lease is the production-preview authority. Storage-side evidence
is a retained witness. Evidence that is missing, lower, higher, or conflicting
with the Lease is not a reason to trust storage; it is a reason to stop and
recover from an explicitly chosen checkpoint.

If the Lease is lost during disaster recovery, the recovery mode may scan
storage evidence and choose the highest observed valid checkpoint only with an
operator-supplied maximum signed checkpoint age. This bounds replay of old valid
checkpoints; it does not prove the backend showed every newer valid checkpoint.

## Object Lock Rule

Object Lock protects object versions from deletion or overwrite before their
retention deadline. It does not prevent a backend from presenting an older valid
version as latest, and it does not make a latest pointer trustworthy by itself.

Use Object Lock for retained payload segments, checkpoint objects, and evidence
records. Do not use it as the only anti-rollback mechanism.

## Operator Reporting Rule

The core admin report model is path-redacted. Any operator UI or management integration built on it is not a repository browser. It may show profile
findings, backend kind, anchor kind, checkpoint sequence, checkpoint ID,
checkpoint digest, retention posture, and path-safe fingerprints. It must not
show client-visible paths, Kubernetes object names, tenant names, configured
backend bucket names, backend prefixes, repository IDs, access keys, wrapping
keys, or raw backend object IDs.

Expose any admin listener only on localhost, a protected cluster-only address,
or behind an authenticated internal ingress. Mutating recovery and maintenance
actions need explicit authorization and audit controls before they belong in an
admin interface. Operator reports should stay fact-only until a
separate authorization and audit design exists.

Do not reuse backup-client S3 credentials as admin credentials. S3 client IAM
controls backup-tool operations on the data plane; admin/operator identity is a
separate admin boundary.

## Key Compromise Rule

Wrapping-key rewrap is not compromise recovery. The wrapping key must be raw
high-entropy key material or come from an external KMS/HSM/Vault/password-KDF
workflow before it reaches `rs3`. Rewrap keeps the same repository data keys and
creates a new envelope around them. If an attacker may have both an old wrapping
key and the old envelope bytes, data protected by that keyring must be treated
as exposed. Provider deletion or retention changes cannot revoke access to
envelope bytes that a malicious backend may already have copied.

Recovery from exposed repository data keys requires a new data-key epoch for
future writes and, where historical confidentiality must be restored,
re-encryption or expiry of old retained data. Retention may intentionally keep
old ciphertext available for compliance, which also means old compromised
ciphertext cannot be made confidential again by envelope rewrap alone.

## Current Open Risks

- Durable format compatibility is not promised yet.
- The cryptographic design has not had an external review.
- Metadata sealing uses a standard misuse-resistant AEAD, but deterministic
  sealing leaks equality for identical metadata under identical associated data.
- Prefix token shape currently prioritizes semantics and testability; it still
  leaks namespace structure through token count and shared-token relationships.
- Storage evidence depends on provider retention or Object Lock to resist
  deletion by a storage administrator.
- Key retirement remains retention-aware and must not remove material still
  required by locked historical checkpoints.

See [Cryptography](reference/cryptography.md) for the primitive-level reference
and review rules.

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
