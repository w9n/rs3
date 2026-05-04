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

The default design accepts that the backend can observe:

- number of backend objects
- encrypted object sizes
- coarse write and restore timing
- provider retention mode where configured
- source network metadata visible to the provider
- broad object classes when class prefixes are used

Optional mitigations include padding, pack-size normalization, checkpoint
batching, compaction jitter, and stricter telemetry redaction.

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
- Metadata sealing and checkpoint signatures still need final production
  primitive decisions.
- Prefix token shape currently prioritizes semantics and testability; it still
  leaks namespace structure through token count and shared-token relationships.
- Hardened storage evidence needs continued deployment integration.
- Key retirement must remain retention-aware to avoid losing access to locked
  historical data.
