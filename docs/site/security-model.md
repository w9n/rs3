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
- Coordinating or merging disconnected writers through S3 alone.

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

The replacement `v02` design accepts specific backend-visible leakage:

| Leakage | Why It Exists | Current Mitigation |
| --- | --- | --- |
| Backend object count | Object stores expose object inventory and request effects. | Batch commits and compact index state where possible. |
| Encrypted object size | The provider stores ciphertext bytes. | Segment sizing and future padding policy. |
| Coarse write and restore timing | The provider sees requests arrive. | Avoid path labels in telemetry; future batching/jitter where useful. |
| Retention mode | Provider retention APIs expose mode and retain-until behavior. | Treat retention mode as policy metadata, not tenant identity. |
| Source network metadata | The provider sees the gateway's network identity. | Deploy through controlled egress where required. |
| Broad object class | `format/`, `keyrings/`, `commits/v02/`, and `objects/v02/` support lifecycle and operations. | Keep class names generic and path-free; standalone run and cleaned-pack keys do not reveal object type, level, tenant, or workload. |
| Commit sequence and run inventory | Sequence-bounded commit keys and immutable run objects expose commit and compaction activity. | Batch commits, use random object IDs, keep catalog counts, levels, and bounds encrypted. |
| Compaction cadence | The provider sees standalone run writes and later cleanup. | Use bounded size tiers and optional compaction jitter; never include paths in scheduling telemetry. |
| Payload-pack shape and access | A commit exposes aggregate pack size, and range reads can reveal record-size and access patterns. | Batch by bounded protection cohort, randomize record order, keep directories encrypted, and consider optional padding only with measured budgets. |
| Deterministic metadata equality | Stable metadata sealing can produce identical sealed bytes for identical metadata under identical associated data. | Bind framed ciphertext to a unique run and frame context; complete equality analysis before format freeze. |

Optional mitigations include padding, pack-size normalization, commit batching,
compaction jitter, and stricter telemetry redaction.

The removed prototype used `format/`, `keyrings/`, and
`commits/v01/<sequence>/<random-id>`. The transitional runtime now uses
`commits/v02`, but still has prototype index sections and durable prefix-token
semantics. No production repository used `v01`, and no migration or dual reader
is planned.

!!! warning "Security implementation status"
    The gateway reads and writes a transitional `v02` commit envelope with
    signed per-section digests and payload-skipping index replay, but does not
    yet read or write `INDEX_ROOT` catalogs or `objects/v02` framed runs. The
    remaining controls below are requirements, not current evidence. Security
    claims remain blocked on implementation, hostile-input tests, scale
    recovery, and external cryptographic review.

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
| Transitional v2 replay does not read payload ciphertext | Signed per-section digests let readers walk to the nearest encrypted index snapshot while range-reading only authenticated index sections. Fixed commit, cumulative-object, and retained-index budgets still fail closed. | v2 bounded replay, payload-independent request-count, malformed-length, and range-tamper tests. |
| Create-only writes are not silently downgraded | Atomic-create providers must honor `PutObject` with `If-None-Match: *`; non-atomic `HEAD` before `PUT` is not treated as production create-only. | Storage contract tests and opt-in live S3 tests. |
| Retained restore reads do not trust mutable latest objects | Retained-version providers must return version IDs for restore-critical writes; anchors bind commit versions and restore reads exact versions. | Memory version-addressed storage tests, v2 retained commit tests, and opt-in live S3 Object Lock tests. |
| Single-writer read-write serving is guarded in Kubernetes deployments | `RS3_WRITER_GUARD=required` acquires a unique process identity and monotonic fencing token on the anchor Lease before serving. Every anchor advance verifies that live fence in the same resource-version CAS. | Lease skew, handoff, stale-writer, runtime startup guard, and configuration tests. |
| Incident restore does not advance repository state | `restore-readonly` mode requires an accepted anchor and rejects supported mutations. | Gateway mode config, startup, and S3 adapter tests. |
| Retention is never shortened | Retention extension contract rejects shortening. | Storage and repository immutability tests. |
| Operator reporting does not become a path oracle | Core admin reports are path-redacted and do not include path browsing fields. | Admin status redaction tests. |
| v02 index frames cannot be transplanted or reordered | Frame AEAD binds format generation, repository context, exact object key, section ordinal, run identity, authenticated directory digest, and complete frame descriptor. The signed catalog separately binds the provider-returned exact version, length, and ciphertext digest. | The bounded framed-run codec and corruption tests are implemented; commit publication, catalogs, and selected-projection replay remain release blockers. |
| v02 payload-pack records cannot be transplanted or downgraded | Record AEAD binds repository, exact object key, pack, section, record, segment, key, layout, and length context. The accepted signed reference binds the returned exact version, length, and digest. Protection-cohort checks prevent reuse under weaker retention or legal hold. | The bounded compact-pack codec, canonical segmentation, and corruption tests are implemented; commit publication, protection-cohort partitioning, and cleaning remain release blockers. |
| v02 recovery does not retain cumulative attacker-sized deltas | Descriptor-first recovery applies one bounded authenticated frame at a time from an exact signed catalog. | Required for v02; 100k and 1M fresh-recovery gates currently block release. |
| v02 checkpoint failure cannot anchor unrecoverable state | Fenced automatic checkpointing degrades, then pauses mutation before fixed tail-byte, commit, or run-count ceilings. | Required for v02; not implemented. |
| v02 GC retains every live payload without retaining whole ancestry | Effective run records mark exact payload commit versions; full mark completes before exact-version sweep. | Required for v02; not implemented. |

## Rollback Rule

A commit is acceptable only when:

- its signature verifies
- its sequence is not lower than the locally trusted sequence
- its body digest matches the external anchor when an anchor exists
- its provider version matches the external anchor when the anchor carries one
- its parent reference is valid or its accepted `INDEX_ROOT` catalog covers the
  declared sequence
- its format-root and keyring-envelope references match the configured
  repository context

When the configured anchor cannot be checked, the default behavior is fail
closed. Break-glass restore modes must be explicit and auditable.

The Kubernetes Lease is the production-preview authority. Retained commit
versions are useful history, not latest-state authority. A missing, older, or
newer-looking backend commit is not a reason to trust storage; it is a reason to
stop and recover from an explicitly trusted anchor bundle.

For read-write Kubernetes deployments, the writer guard records ownership on
the anchor Lease itself before serving and renews it while the process runs.
Each process identity is random-suffixed, every ownership transfer increments a
monotonic fence token, and every anchor advance atomically checks that identity
and token through the same Lease `resourceVersion` CAS. Takeover waits for an
unchanged renewal counter for a full locally measured monotonic lease duration;
wall-clock skew cannot make a competing Lease expire early. A process also
refuses anchor advances once its own monotonic renewal deadline passes. If
ownership changes or renewal is no longer trustworthy, the gateway shuts down.
An orderly shutdown releases ownership with another Lease CAS so unfenced
maintenance can run while no writer is active. Unfenced maintenance refuses to
advance a Lease with an active writer epoch. This guard is runtime coordination,
not a replacement for signed commits or the external anchor.

For `v02`, the external anchor names the accepted commit key, body digest,
provider version ID when required, signing key ID, and format-root reference.
The named commit authenticates the small index catalog, exact active run set,
and exact live payload references. Descriptor-first recovery verifies that
graph and rechecks the anchor before installing state. Missing anchor plus
missing trusted bundle is fail-closed for normal recovery.

S3 is not a writer lock. A conditional create can arbitrate one object key but
cannot fence a stale gateway or establish an order between divergent repository
roots. Read-write failover is supported only under one Kubernetes Lease
coordination domain. Disconnected S3-only writers are rejected; safely adding
them would require authenticated branches and merge semantics outside `v02`.

## Object Lock Rule

Object Lock protects object versions from deletion or overwrite before their
retention deadline. It does not prevent a backend from presenting an older valid
version as latest, and it does not make a latest pointer trustworthy by itself.

Use Object Lock for retained commit objects, standalone index runs, keyring
envelopes, and format roots. Do not use it as the only anti-rollback mechanism.

In retained/Object Lock mode, `rs3` requires the backend to return a provider
version ID for restore-critical writes. The anchor binds the accepted commit
version and format-root version, while catalog and commit descriptors bind exact
index-run, parent-commit, payload-commit, and keyring-envelope versions. Restore
reads exact versions. If a retained
write does not return a version ID, startup or write flow must fail closed;
otherwise a malicious backend could append a newer object version and make
restore follow mutable latest state.

For multipart writes, `rs3` verifies Object Lock on the completed provider
version before accepting the write. Providers that do not carry retention or
legal-hold headers from multipart creation must support applying and verifying
the protection on the returned version immediately after completion. Missing
version IDs or failed protection verification fail closed.

A retained-version provider may accept a second same-key write instead of
rejecting `If-None-Match: *`. That is acceptable only for retained/Object Lock
repository objects when the new write returns a distinct version ID and old
anchor-bound versions remain exactly readable. The object key is then not the
uniqueness authority; the signed commit, external anchor, object digest, and
provider version ID are.

In both the removed prototype and transitional `v02`, commit keys include a random
component. For retained-version
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
against a provider that races requests, serves stale state, or ignores
conditional headers.

`rs3 check-v2-provider` currently runs the selected prototype profile probes against the
configured backend, including multipart upload behavior used by large
streaming writes. Governance-retention deployments require an explicit operator
review that gateway credentials cannot bypass retention. It must be extended to
cover exact standalone run versions before it qualifies `v02`.

## Operator Reporting Rule

The core admin report model is path-redacted. Any operator UI or management
plane built on it is not a repository browser. It may show profile
findings, backend kind, anchor kind, commit sequence, commit key, commit digest,
retention posture, and path-safe fingerprints. It must not
show client-visible paths, Kubernetes object names, tenant names, configured
backend bucket names, backend prefixes, repository IDs, access keys, wrapping
keys, or raw backend object IDs.

The current S3, admin, metrics, and console listeners do not terminate TLS
themselves. Expose them only behind TLS termination or on cluster-local
networks protected by NetworkPolicy or equivalent controls. The admin listener
is separate from the S3 data plane and currently exposes path-redacted facts at
`GET /admin/posture` and `GET /admin/status`; it must use an admin bearer token
that is separate from backup-client S3 credentials and backend S3 credentials.
Mutating recovery and maintenance actions need explicit authorization and audit
controls before they belong in an admin interface. Operator reports should stay
fact-only until a separate authorization and audit design exists.

Do not reuse backup-client S3 credentials as admin credentials. S3 client IAM
controls backup-tool operations on the data plane; admin/operator identity is a
separate admin boundary.

The single-gateway console follows the same reporting rule. It may render the
gateway admin report in a browser, but it must keep the gateway admin bearer
token server-side, require a separate console bearer token for `GET
/api/posture` and `GET /api/status`, and stay read-only. It must not add object
browsing, workflow execution, recovery mutation, key rotation, or backend-object
inspection. The console-to-gateway admin hop carries the gateway admin bearer
token, so use `https://` for that hop unless it is restricted to a protected
cluster-local network.

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

- The transitional `v02` envelope is implemented, but its catalog-and-run
  security contract is not; the removed prototype was not a production format.
- Durable format compatibility is not promised yet.
- The cryptographic design has not had an external review.
- Metadata sealing uses a standard misuse-resistant AEAD, but deterministic
  sealing leaks equality for identical metadata under identical associated data.
- The transitional runtime's prefix tokens leak namespace structure through
  token count and shared-token relationships. The completed `v02` design removes
  durable prefix tokens, but that property still needs implementation and tests.
- Gateway-level deduplication is not part of the baseline format. A future mode
  must account for provider-visible equality through omitted writes and shared
  liveness, not merely hide a content digest inside encrypted metadata. See the
  [deduplication design note](reference/deduplication.md).
- Payload-pack protection cohorts and cleaning have not passed retained-version,
  legal-hold, protected-root, or crash testing.
- Catalog compaction, exact payload-root GC, and failure backpressure have not
  passed adversarial crash, replay, and stale-fence testing.
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
