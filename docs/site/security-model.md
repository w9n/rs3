# Security Model

`rs3` optimizes for backup privacy and restore correctness when object storage
is untrusted or partially compromised.

## Goals

- Hide plaintext paths and Kubernetes names from backend-visible storage.
- Encrypt and authenticate payloads and privacy-sensitive metadata.
- Detect tampering with repository objects.
- Detect rollback through signed commits and an external anchor.
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
| Compromised backup pod | Creates bad new backups while credentials are valid, but should not erase correctly retained old commit versions. |
| Compromised Kubernetes control plane | Rewrites the anchor unless protected by RBAC, admission policy, audit logs, and offline recovery bundles. |

If Kubernetes, the object-storage account, the wrapping-key source, and
preserved restore bundles are all controlled by the same compromised authority,
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
labels, traces, commit headers, and error messages.

## Accepted Leakage

The default design accepts specific backend-visible leakage:

| Leakage | Why It Exists | Current Mitigation |
| --- | --- | --- |
| Backend object count | Object stores expose object inventory and request effects. | Batch commits and compact index state where possible. |
| Encrypted object size | The provider stores ciphertext bytes. | Segment sizing and future padding policy. |
| Coarse write and restore timing | The provider sees requests arrive. | Avoid path labels in telemetry; future batching/jitter where useful. |
| Retention mode | Provider retention APIs expose mode and retain-until behavior. | Treat retention mode as policy metadata, not tenant identity. |
| Source network metadata | The provider sees the gateway's network identity. | Deploy through controlled egress where required. |
| Broad object class | Class prefixes support lifecycle and operations. | Keep class names generic and path-free; revisit in a new format if needed. |
| Deterministic metadata equality | Stable metadata sealing can produce identical sealed bytes for identical metadata under identical associated data. | Use object-type-specific associated data and signed reachability; revisit before stable-format. |
| Prefix-token structure | Current prefix tokens reveal token count and shared-token relationships. | Document as an open privacy risk; redesign index compaction before stable-format claims. |

Optional mitigations include padding, pack-size normalization, commit batching,
compaction jitter, and stricter telemetry redaction.

## Control Map

| Requirement | Mechanism | Current Evidence |
| --- | --- | --- |
| Backend keys do not reveal client paths | Opaque backend object IDs and path privacy property tests. | `crates/rs3-repository/tests/path_invariants.rs` |
| Payload bytes are not plaintext in storage | Authenticated encrypted payload segments. | Repository payload tests in `crates/rs3-repository/src/tests/payload.rs` |
| Metadata bytes are not plaintext in durable index state | AES-256-GCM-SIV sealed metadata records. | Crypto metadata tests and repository path-invariant tests. |
| Payload objects cannot be moved silently | Associated data binds ciphertext to backend object context. | Payload tamper and object-context tests. |
| Repository key reuse is compartmentalized | Random purpose keys are generated into an encrypted keyring envelope and bound to the repository ID, public salt, and wrapping-key identity. | Crypto keyring/envelope tests. |
| Envelope swaps are detectable | The v2 format root and signed commits bind the active keyring envelope generation, object ID, and digest. | v2 format-root and key-envelope tests. |
| Old content remains readable after data-key rotation | Enabled historical content keys are accepted for reads. | Repository key rotation tests. |
| Writes are not acknowledged before commit acceptance | Commit coordinator waits for a covering signed commit and anchor advance. | v2 coordinator and commit tests. |
| Storage rollback is not trusted as latest state | Ed25519 commit verification, Kubernetes Lease anchor, and retained exact-version commit reads. | v2 anchor, replay, recovery import, and orphan-report tests. |
| v2 writes are not acknowledged before signed commit acceptance | The v2 commit coordinator batches staged writes into a signed commit and advances the external v2 anchor before returning success. | v2 coordinator batching, rollback, and snapshot tests. |
| v2 replay cost is bounded by signed snapshots | v2 readers walk the signed parent chain to the nearest encrypted index snapshot, then replay newer deltas. | v2 snapshot replay tests and format vectors. |
| Create-only writes are not silently downgraded | Atomic-create providers must honor `PutObject` with `If-None-Match: *`; non-atomic `HEAD` before `PUT` is not treated as production create-only. | Storage contract tests and opt-in live S3 tests. |
| Retained restore reads do not trust mutable latest objects | Retained-version providers must return version IDs for restore-critical writes; anchors bind commit versions and restore reads exact versions. | Memory version-addressed storage tests, v2 retained commit tests, and opt-in live S3 Object Lock tests. |
| Incident restore does not advance repository state | `restore-readonly` mode requires an accepted anchor and rejects supported mutations. | Gateway mode config, startup, and S3 adapter tests. |
| Retention is never shortened | Retention extension contract rejects shortening. | Storage and repository immutability tests. |
| Operator reporting does not become a path oracle | Core admin reports are path-redacted and do not include path browsing fields. | Admin status redaction tests. |

## Rollback Rule

A commit is acceptable only when:

- its signature verifies
- its sequence is not lower than the locally trusted sequence
- its body digest matches the external anchor when an anchor exists
- its provider version matches the external anchor when the anchor carries one
- its parent reference is valid or it is a trusted snapshot root
- its format-root and keyring-envelope references match the configured
  repository context

When the configured anchor cannot be checked, the default behavior is fail
closed. Break-glass restore modes must be explicit and auditable.

The Kubernetes Lease is the production-preview authority. Retained commit
versions are useful history, not latest-state authority. A missing, older, or
newer-looking backend commit is not a reason to trust storage; it is a reason to
stop and recover from an explicitly trusted anchor bundle.

For `v2-preview`, the external anchor names the accepted commit key, body
digest, provider version ID when required, signing key ID, and format-root
reference. Normal disaster recovery requires a trusted exported bundle;
`import-v2-anchor` verifies the named signed chain to the nearest snapshot
before recreating a missing anchor. Missing anchor plus missing trusted bundle
is fail-closed for normal recovery.

## Object Lock Rule

Object Lock protects object versions from deletion or overwrite before their
retention deadline. It does not prevent a backend from presenting an older valid
version as latest, and it does not make a latest pointer trustworthy by itself.

Use Object Lock for retained commit objects, keyring envelopes, and format
roots. Do not use it as the only anti-rollback mechanism.

In retained/Object Lock mode, `rs3` requires the backend to return a provider
version ID for restore-critical writes. The v2 anchor binds the accepted commit
version and format-root version, and commit headers bind parent commit versions
and keyring envelope versions. Restore reads exact versions. If a retained
write does not return a version ID, startup or write flow must fail closed;
otherwise a malicious backend could append a newer object version and make
restore follow mutable latest state.

A retained-version provider may accept a second same-key write instead of
rejecting `If-None-Match: *`. That is acceptable only for retained/Object Lock
repository objects when the new write returns a distinct version ID and old
anchor-bound versions remain exactly readable. The object key is then not the
uniqueness authority; the signed commit, external anchor, object digest, and
provider version ID are.

In `v2-preview`, commit keys include a random component. For retained-version
providers that do not support atomic create, the writer performs a preflight
`HEAD` and binds the accepted object version into the anchor. A same-sequence
or orphaned retained commit is reported and skipped by automatic GC until
retention, legal-hold, and age checks allow safe cleanup.

Non-retained development backends may omit version IDs. In that mode `rs3` can
still authenticate object bytes and detect tampering of the bytes it reads, but
it cannot force the provider to return an older exact version after a newer
version has appeared.

## Restore Mode Rule

`read-write` is the normal Velero restore mode for a healthy repository. Velero
restore result artifacts are writes, so they must be accepted only through the
same committed repository path as other mutations.

`restore-readonly` is the incident and disaster-recovery mode. It rejects those
artifact writes rather than storing unanchored side-channel state. Velero
may therefore report `PartiallyFailed` even when the restored workload data is
correct. Treat that status as acceptable only when the denied writes are restore
bookkeeping artifacts, pod-volume restore completed, restored data verifies,
and backend write counters remain unchanged.

## Provider Qualification Rule

S3-compatible providers qualify through one of two profiles:

- **Atomic create:** `PutObject` with `If-None-Match: *` rejects an existing
  current object. This is the preferred profile when provider versioning or
  Object Lock is not part of the deployment.
- **Retained version:** Object Lock and versioning are enabled; retained writes
  return provider version IDs; exact-version reads return the anchor-bound
  object after a newer latest version exists; retention or legal hold blocks
  destructive cleanup before expiry.

`HEAD` before `PUT` is not a security-equivalent fallback. It can improve UX for
single-writer compatibility probes, but it is not atomic and does not protect
against a provider that races requests, serves stale state, or ignores conditional headers.

`rs3 check-v2-provider` runs the selected v2 profile probes against the
configured backend, including multipart upload behavior used by large
streaming writes. Governance-retention deployments require an explicit operator
review that gateway credentials cannot bypass retention.

## Operator Reporting Rule

The core admin report model is path-redacted. Any operator UI or management integration built on it is not a repository browser. It may show profile
findings, backend kind, anchor kind, commit sequence, commit key, commit digest,
retention posture, and path-safe fingerprints. It must not
show client-visible paths, Kubernetes object names, tenant names, configured
backend bucket names, backend prefixes, repository IDs, access keys, wrapping
keys, or raw backend object IDs.

Expose the admin listener only on localhost, a protected cluster-only address,
or behind an authenticated internal ingress. The listener is separate from the
S3 data plane and currently exposes path-redacted facts at `GET /admin/status`;
it must use an admin bearer token that is separate from backup-client S3
credentials and backend S3 credentials. Mutating recovery and maintenance
actions need explicit authorization and audit controls before they belong in an
admin interface. Operator reports should stay fact-only until a
separate authorization and audit design exists.

Do not reuse backup-client S3 credentials as admin credentials. S3 client IAM
controls backup-tool operations on the data plane; admin/operator identity is a
separate admin boundary.

The single-gateway console follows the same reporting rule. It may render the
gateway admin report in a browser, but it must keep the gateway admin bearer
token server-side, require a separate console bearer token for `GET
/api/status`, and stay read-only. It must not add object browsing, workflow
execution, recovery mutation, key rotation, or backend-object inspection.

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
- Retained backend history depends on provider retention or Object Lock to
  resist deletion by a storage administrator.
- Key retirement remains retention-aware and must not remove material still
  required by locked historical commits.

See [Cryptography](reference/cryptography.md) for the primitive-level reference
and review rules.

## Review Standard

A security review should not accept prose claims alone. For every new feature,
reviewers should ask:

- What new backend-visible data exists?
- Can the data reveal paths, tenant identity, object equality, object counts,
  file size, timing, or Kubernetes resource names?
- Which test verifies the privacy boundary?
- Which runbook explains recovery when the object store or anchor service is
  hostile?
- Does the change preserve fail-closed anchor behavior?
