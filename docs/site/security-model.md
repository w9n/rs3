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
| Broad object class | `format/`, `keyrings/`, `commits/v02/`, and `objects/v02/` support lifecycle and operations. | Keep class names generic and path-free; compacted sibling carriers and cleaned-pack keys do not reveal tenant, path, or workload. |
| Commit sequence and run inventory | Sequence-bounded commit keys and immutable run objects expose commit and compaction activity. | Batch commits, use random object IDs, keep catalog counts, levels, and bounds encrypted. |
| Compaction cadence | The provider sees sibling delta-carrier and root writes, plus later cleanup. | Compact at bounded active-run watermarks and consider optional jitter; never include paths in scheduling telemetry. |
| Payload-pack shape and access | A commit exposes aggregate pack size, and exact range reads reveal ciphertext span and access patterns. | Batch by bounded protection cohort, randomize record order, keep record descriptors inside encrypted authenticated index runs, and consider optional padding only with measured budgets. |
| Deterministic metadata equality | Stable metadata sealing can produce identical sealed bytes for identical metadata under identical associated data. | Bind framed ciphertext to a unique run and frame context; complete equality analysis before format freeze. |

Optional mitigations include padding, pack-size normalization, commit batching,
compaction jitter, and stricter telemetry redaction.

The removed prototype used `format/`, `keyrings/`, and
`commits/v01/<sequence>/<random-id>`. The runtime now uses `commits/v02` with
compact payload-pack, index-run, and index-root sections. No production
repository used `v01`, and no migration or dual reader is planned.

!!! warning "Security implementation status"
    The gateway reads and writes a transitional `v02` commit envelope with
    signed per-section digests. Bounded normal writes use encrypted payload
    packs and framed index runs; recovery replays index runs without reading
    payload bytes. The encrypted run carries each payload record's authenticated
    physical descriptor and the containing commit's historical keyring-envelope
    reference. A cold payload read therefore fetches and authenticates only the
    required canonical ciphertext segments, without a pack-directory request.
    Publication verifies the returned object length and immediate exact-version
    visibility before advancing the external anchor. The gateway reads and
    writes signed `INDEX_ROOT` catalogs of exact embedded run sections.
    Candidate checkpoints are reconstructed by a fresh reader before anchor
    adoption, and maintenance derives exact run and live-payload reachability
    from the same verified catalog. Guarded metadata-only packed-run compaction
    and automatic active-run watermarks are implemented. Production claims
    remain blocked on framed streaming, protection-cohort and GC qualification,
    the revised 1M scale rerun, live-provider reruns, and external cryptographic
    review.

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
| v2 replay does not read payload ciphertext | Signed per-section digests and an encrypted `INDEX_ROOT` let readers verify exact run sections and replay the post-root tail without reading payload sections. Fixed commit, catalog, object-byte, and retained-index budgets fail closed. | v2 bounded replay, root codec, root-plus-tail, payload-independent request-count, malformed-length, and range-tamper tests. |
| Create-only writes are not silently downgraded | Atomic-create providers must honor `PutObject` with `If-None-Match: *`; non-atomic `HEAD` before `PUT` is not treated as production create-only. | Storage contract tests and opt-in live S3 tests. |
| Retained restore reads do not trust mutable latest objects | Retained-version providers must return version IDs for restore-critical writes; anchors bind commit versions and restore reads exact versions. | Memory version-addressed storage tests, v2 retained commit tests, and opt-in live S3 Object Lock tests. |
| Single-writer read-write serving is guarded in Kubernetes deployments | `RS3_WRITER_GUARD=required` acquires a unique process identity and monotonic fencing token on the anchor Lease before serving. Every anchor advance verifies that live fence in the same resource-version CAS. | Lease skew, handoff, stale-writer, runtime startup guard, and configuration tests. |
| Incident restore does not advance repository state | `restore-readonly` mode requires an accepted anchor and rejects supported mutations. | Gateway mode config, startup, and S3 adapter tests. |
| Retention is never shortened | Retention extension contract rejects shortening. | Storage and repository immutability tests. |
| Operator reporting does not become a path oracle | Core admin reports are path-redacted and do not include path browsing fields. | Admin status redaction tests. |
| v02 index frames cannot be transplanted or reordered | Frame AEAD binds immutable repository identity, the historical keyring-envelope reference, exact object key, section ordinal, run identity, and complete frame descriptor. The signed catalog binds exact embedded commit version, length, body digest, layout, level, and compaction generation. Compacted carriers must be direct siblings of their root with the exact parent and sequence relation. | Framed-run and root codecs, guarded sibling publication, fresh-reader candidate verification, exact catalog recovery, bounded replay, and corruption tests. Retained-provider restart and fault qualification remain. |
| v02 payload-pack records cannot be transplanted or downgraded | Record AEAD binds immutable repository identity, historical keyring context, exact object key, pack, section, record, segment, layout, and length facts. Encrypted `INDEX_RUN` descriptors bind the pack identity, content-key ID, historical envelope object and digest, ordinal, offset, length, and plaintext digest. The accepted signed reference binds the returned exact version, length, and commit-body digest. | The bounded ciphertext-only pack codec, canonical segmentation, publication, direct cold range-read, replay, and corruption tests are implemented; protection-cohort partitioning and cleaning remain release blockers. |
| Cold packed reads do not fetch unrelated records or metadata | Recovery materializes authenticated direct record descriptors from encrypted runs. A fresh post-recovery read uses one exact backend range `GET`; a 512 B record fetches 528 B including its AEAD tag, for 1.03125x ciphertext-byte amplification. | Direct cold-read request-count and exact-range repository test; the scale harness enforces configurable request and byte-amplification ceilings during sentinel reads. |
| v02 recovery does not retain cumulative attacker-sized deltas | Descriptor-first recovery verifies exact bounded run sections sequentially from a signed catalog under count and byte ceilings. Compaction uses per-run scratch state and shared exact-container interning instead of a cumulative replay scratch. | Embedded and compacted recovery tests pass. A memory-remediated 270k bounded-compaction sample passed at 4,042,354,688 B peak RSS; the revised fresh-process filesystem 1M gate remains. |
| v02 checkpoint failure cannot anchor unrecoverable state | A coordinator requests metadata-only compaction at 256 active runs. A missing guard or a fully validated nonreducing bounded plan may defer below 896 and retry at later 64-run boundaries; both fail closed at 896. Configured-guard, corruption, storage, anchor, and other compaction errors poison immediately. The hard 1,024-run verifier ceiling remains. | Automatic success, missing-guard and nonreducing-plan retry and pause, configured-guard failure, hard-ceiling, and exact recovered-run-count tests. Three 270k release runs crossed the watermark and recovered 140 active runs; adversarial restart and retained-provider qualification remain. |
| v02 compaction cannot publish a partial or payload-rewriting merge | At most the oldest 128 foreground level-0 runs are merged newest-wins including tombstones; newer level-0 and existing level-1 shards remain exact-referenced; self-pack references become exact historical external references; equal-generation groups are indivisible; candidate carriers and root are siblings verified by a fresh reader before one fenced CAS. Level denotes tier, not epoch, and the preview decoder rejects levels above 1. | Pure planner, bounded-window selection, historical-envelope, no-payload-write, guard-loss, publication-lineage, fresh-recovery, invalid-tier, and automatic-watermark tests. Bottom-tier tombstone reclamation remains future guarded or offline work. |
| v02 GC retains every live payload without retaining whole ancestry | Effective run records mark exact payload commit versions; catalog-named run commits and protected roots are marked before exact-version sweep. | Implemented for embedded and compacted catalog runs; payload-pack cleaning remains blocked. |

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

Use Object Lock for retained commit objects, including compacted-run carriers,
plus keyring envelopes and format roots. Do not use it as the only anti-rollback
mechanism.

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
cover exact compacted sibling-carrier versions before it qualifies `v02`.

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

- The `v02` catalog, packed-run compaction, and automatic watermark paths remain
  preview-scoped. Durable format freeze, retained-provider qualification, and
  external cryptographic review are still outstanding.
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
- Packed-run catalog compaction and automatic pre-ceiling backpressure are
  implemented, but have not passed the revised 1M lane, retained-provider
  restart, or the full adversarial crash and delayed-visibility matrix. Exact
  payload-root GC and cleaning also remain incomplete. Level-1 tombstones are
  retained to mask older shards; safe bottom-tier tombstone reclamation remains
  future guarded or offline work. The hard 1,024-run stop is implemented and
  fails closed.
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
