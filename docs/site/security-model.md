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
| Streamed-payload shape and access | An embedded `[PAYLOAD, INDEX_RUN]` commit or a standalone `objects/v02/` payload followed by `[INDEX_RUN]` reveals that one streamed carrier was written, its ciphertext length, write cadence, publication delay, and later range-access spans. Concurrent standalone uploads also expose aggregate concurrency through timing and request volume. A zero-length stream still has an authenticated payload header and is distinguishable by size from larger streams. | Keep path and payload identity inside authenticated ciphertext, use opaque random commit and object keys, fetch only authenticated segments, and treat padding or traffic shaping as future measured modes. |
| Deterministic metadata equality | Stable metadata sealing can produce identical sealed bytes for identical metadata under identical associated data. | Bind framed ciphertext to a unique run and frame context; complete equality analysis before format freeze. |

Optional mitigations include padding, pack-size normalization, commit batching,
compaction jitter, and stricter telemetry redaction.

The removed prototype used `format/`, `keyrings/`, and
`commits/v01/<sequence>/<random-id>`. The runtime now uses `commits/v02` with
compact payload-pack, index-run, and index-root sections. No production
repository used `v01`, and no migration or dual reader is planned.

!!! warning "Security implementation status"
    The gateway reads and writes the preview `v02` commit envelope with
    signed per-section digests. Bounded normal writes use encrypted payload
    packs and framed index runs; recovery replays index runs without reading
    payload bytes. The encrypted run carries each payload record's authenticated
    physical descriptor and the containing commit's historical keyring-envelope
    reference. A cold payload read therefore fetches and authenticates only the
    required canonical ciphertext segments, without a pack-directory request.
    Publication verifies the returned object length and immediate exact-version
    visibility before advancing the external anchor. The gateway reads and
    writes signed `INDEX_ROOT` catalogs of exact embedded run sections.
    Publication reads back and opens the exact signed candidate root and every
    new compacted run before anchor adoption, and maintenance derives exact run
    and live-payload reachability from the same verified catalog. Known-length,
    unknown-length, and zero-length streaming writes use the canonical
    `[PAYLOAD, INDEX_RUN]` shape and enter the same catalog. Guarded metadata-only
    packed/streamed-run compaction and automatic active-run watermarks are
    implemented. New bounded writes are partitioned by effective protection
    cohort, and guarded full GC renews exact restore dependencies from one
    bounded plan before deleting exact orphans. Production claims remain blocked
    on retained-provider restart/fault qualification, pinned-runner filesystem
    qualification, live-provider reruns, and external cryptographic review.

## Control Map

| Requirement | Mechanism | Current Evidence |
| --- | --- | --- |
| Backend keys do not reveal client paths | Opaque backend object IDs and path privacy property tests. | `crates/rs3-repository/tests/path_invariants.rs` |
| Payload bytes are not plaintext in storage | Authenticated encrypted payload segments. | Repository payload tests in `crates/rs3-repository/src/tests/payload.rs` |
| Metadata bytes are not plaintext in durable index state | AES-256-GCM-SIV sealed metadata records. | Crypto metadata tests and repository path-invariant tests. |
| Payload objects cannot be moved silently | Associated data binds ciphertext to backend object context. | Payload tamper and object-context tests. |
| Repository key reuse is compartmentalized | Random purpose keys are generated into an encrypted keyring envelope and bound to the repository ID, public salt, and wrapping-key identity. | Crypto keyring/envelope tests. |
| Envelope swaps are detectable | The v2 format root and signed commits bind the active keyring envelope generation, object ID, and digest. | v2 format-root and key-envelope tests. |
| Unsupported format transitions fail closed | The runtime exposes no v02 format or data-key rotation operation. Destructive maintenance rejects a protected root from a different exact format generation before storage reads. | Repository key-rotation read tests and cross-format protected-root rejection tests. A future rotation capability requires a separately reviewed migration design. |
| Writes are not acknowledged before commit acceptance | Commit coordinator waits for a covering signed commit and anchor advance. | v2 coordinator and commit tests. |
| Storage rollback is not trusted as latest state | Ed25519 commit verification, Kubernetes Lease anchor, and retained exact-version commit reads. | v2 anchor, replay, recovery import, and orphan-report tests. |
| v2 writes are not acknowledged before signed commit acceptance | The v2 commit coordinator batches staged writes into a signed commit and advances the external v2 anchor before returning success. | v2 coordinator batching, rollback, and snapshot tests. |
| One process cannot publish another local batch's speculative overlay | Each repository instance grants one atomic RAII mutation lease. Delayed publisher tasks retain the coordinator lease; direct mutation and compaction APIs are rejected until it is released. A post-CAS local installation failure returns an explicit recovery-required error and blocks new mutations. | Duplicate-coordinator, cancelled delayed-publisher, direct-bypass, compaction-bypass, and accepted-but-recovery-required tests. |
| v2 replay does not read payload ciphertext | Signed per-section digests and an encrypted `INDEX_ROOT` let readers verify exact run sections and replay the post-root tail without reading payload sections. Fixed commit, catalog, object-byte, and retained-index budgets fail closed. | v2 bounded replay, root codec, root-plus-tail, payload-independent request-count, malformed-length, and range-tamper tests. |
| Create-only writes are not silently downgraded | Atomic-create providers must honor `PutObject` with `If-None-Match: *`; non-atomic `HEAD` before `PUT` is not treated as production create-only. | Storage contract tests and opt-in live S3 tests. |
| Retained restore reads do not trust mutable latest objects | Retained-version providers must return version IDs for restore-critical writes; anchors bind commit versions and restore reads exact versions. | Memory version-addressed storage tests, v2 retained commit tests, and opt-in live S3 Object Lock tests. |
| Single-writer read-write serving is guarded in Kubernetes deployments | `RS3_WRITER_GUARD=required` acquires a unique process identity and monotonic fencing token on the anchor Lease before serving. Every anchor advance verifies that live fence in the same resource-version CAS. | Lease skew, handoff, stale-writer, runtime startup guard, and configuration tests. |
| Incident restore does not advance repository state | `restore-readonly` mode requires an accepted anchor and rejects supported mutations. | Gateway mode config, startup, and S3 adapter tests. |
| Retention is never shortened | Retention extension contract rejects shortening. | Storage and repository immutability tests. |
| Operator reporting does not become a path oracle | Core admin reports are path-redacted and do not include path browsing fields. | Admin status redaction tests. |
| v02 index frames cannot be transplanted or reordered | Frame AEAD binds immutable repository identity, the historical keyring-envelope reference, exact object key, section ordinal, run identity, and complete frame descriptor. The signed catalog binds exact embedded commit version, length, body digest, layout, level, and compaction generation. Compacted carriers must be direct siblings of their root with the exact parent and sequence relation. | Framed-run and root codecs, guarded sibling publication, exact candidate read-back, exact catalog recovery, bounded replay, and corruption tests. Retained-provider restart and fault qualification remain. |
| v02 payload-pack records cannot be transplanted or downgraded | Record AEAD binds immutable repository identity, historical keyring context, exact object key, pack, section, record, segment, layout, length, and final-segment facts. Encrypted `INDEX_RUN` descriptors bind the pack identity, content-key ID, historical envelope object and digest, ordinal, offset, and length. The accepted signed reference binds the returned exact version, length, and commit-body digest. | The bounded ciphertext-only pack codec, canonical segmentation, production pack-identity freshness, segment reorder/transplant rejection, publication, direct cold range-read, replay, corruption tests, and new-write protection-cohort partitioning are implemented. Mixed-pack cleaning remains a capacity optimization and needs qualification before operators rely on prompt space reclamation. |
| v02 streamed payloads cannot be detached from their exact carrier | A self-stream run record binds the payload identity, signed section ordinal, and authenticated segmented header. Replay and compaction materialize an exact external carrier with commit key/version, stored length/body digest, historical keyring envelope, section start/ordinal/offset/length/digest, payload identity, and header. Section ranges beyond the exact stored object fail closed. | Canonical known/unknown/zero-length write, replay, checkpoint, exact-carrier tamper, compaction, GC, and range-read tests. Retained-provider fault qualification remains. |
| v02 standalone payloads cannot become visible partially or under weaker protection | A fresh random object is segmented-AEAD sealed outside the publication lock. After completion, the writer computes a required horizon, renews only the exact returned version, and requires the provider's result to meet at least that deadline, so upload duration cannot consume the requested interval. That version must match object identity, stored length, absolute retention deadline, exact EOF, and the writer's complete ciphertext digest before an encrypted carrier reference can enter a signed run and fenced anchor transition. Unanchored objects have no namespace authority. Client legal hold is rejected until dependency-wide hold and release exist. | Concurrent 1/2/4/8 overlap with serialized publication, stalled-upload isolation, pre-completion abort, ambiguous-completion orphan, digest mismatch, delayed-body post-completion retention, missing-version pre-mutation rejection, exact protection, create-only race, anchor failure/reclaim, zero-age in-flight GC, compaction, checkpoint, fresh reload, full-read, and range-read tests pass. Retained-provider restart and fault qualification remain. |
| Full streamed restores do not require object-sized trusted memory | One exact provider stream is length-bounded. The authenticated header is checked before the response, each bounded segment group is AEAD-verified before release, and exact EOF plus the signed aggregate digest are checked before the final plaintext group. Segment size is hard-limited to 64 MiB. | Repository tests cover bounded multi-chunk reads, one backend `GET`, header rejection, and final-group withholding on aggregate mismatch; the S3 adapter restores an object larger than its download-memory reservation. Retained-provider and fresh-process gateway performance qualification remain. |
| Decrypted streamed-payload cache entries cannot alias across authenticated carriers | The in-memory cache key hashes repository/keyring context and every exact commit, section, payload-header, and content-length fact. Decryption continues to use the real payload ID as AEAD associated data, not the synthetic cache key. | Cache-field binding, cache/AEAD identity separation, and section-bound tests. The derived key is process-local and creates no backend object or additional backend-visible identifier. |
| Cold packed reads do not fetch unrelated records or metadata | Recovery materializes authenticated direct record descriptors from encrypted runs. A fresh post-recovery read uses one exact backend range `GET`; a 512 B record fetches 528 B including its AEAD tag, for 1.03125x ciphertext-byte amplification. | Direct cold-read request-count and exact-range repository test; the scale harness enforces configurable request and byte-amplification ceilings during sentinel reads. |
| v02 recovery does not retain cumulative attacker-sized deltas | Descriptor-first recovery verifies exact bounded run sections sequentially from a signed catalog under count and byte ceilings. Runtime publication keeps one accepted state plus a hard-bounded 4,096-mutation overlay; compaction uses per-run scratch state and shared identifiers rather than a cumulative replay scratch or candidate namespace. The accepted state omits the legacy prefix-token projection, structurally shares ordered path keys and exact authenticated carrier facts, and interns namespace-key IDs inside authenticated frames. | Three wire-v6 1M runs with 4,096-record batches recovered 245 runs at 1,681,272,832-1,681,723,392 B process peak RSS including the in-memory backend and 1.268292436x writes. Three fresh-process ext4 wire-v6 runs passed at 955,678,720-956,338,176 B writer RSS, 1,010,085,888-1,010,372,608 B reader RSS, and 5.280-5.350 s recovery. The filesystem build was dirty, so the exact committed and pinned-runner qualification remains. |
| v02 checkpoint failure cannot anchor unrecoverable state | A coordinator requests metadata-only compaction at 256 active runs. A missing guard or a fully validated nonreducing bounded plan may defer below 896 and retry at later 64-run boundaries; both fail closed at 896. Configured-guard, corruption, storage, anchor, and other compaction errors poison immediately. The hard 1,024-run verifier ceiling remains. | Automatic success, missing-guard and nonreducing-plan retry and pause, configured-guard failure, hard-ceiling, and exact recovered-run-count tests. Three wire-v6 1M release runs stayed below the trigger at 245 active runs; the earlier 1,024-record lane crossed six compaction windows and recovered 233. Adversarial restart and retained-provider qualification remain. |
| v02 compaction cannot publish a partial or payload-rewriting merge | At most the oldest 128 foreground level-0 runs are merged newest-wins including tombstones; newer level-0 and existing level-1 shards remain exact-referenced; self-pack and self-stream references become exact historical external references; equal-generation groups are indivisible; candidate carriers and root are direct siblings read back and opened exactly before one fenced CAS. Level denotes tier, not epoch, and the preview decoder rejects levels above 1. | Pure planner, bounded-window selection, historical-envelope, mixed pack/stream no-payload-write, exact candidate read-back, guard-loss, publication-lineage, recovery, invalid-tier, and automatic-watermark tests. Bottom-tier tombstone reclamation remains future guarded or offline work. |
| v02 GC retains every live payload without retaining unrelated payload ancestry | Effective run records mark exact payload-pack and streamed-carrier versions; catalog-named runs, the replay chain, format root, and keyring envelope are marked before exact-version sweep. The strongest represented finite retention is propagated across required restore dependencies. One read-only store-boundary ledger meters every planning HEAD, bounded range GET, and LIST page before forwarding; the verified current chain and namespace state are reused instead of replayed twice. Bounded inventory and one immutable plan renew and post-verify exact versions before guarded deletion. Existing graphs that require legal hold and foreign-format protected roots fail closed. | Implemented for the current anchor graph and repository-level same-format protected-root inputs, including actual-operation budget parity, zero-budget non-forwarding, invalid page rejection, and ambiguous renewal failure. The gateway does not expose historical-root registration, legal holds, or format rotation. S3 list XML is capped before deserialization and returned member counts are checked against requested `MaxKeys`. Retained-provider restart/fault qualification remains unavailable. |

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

### Anchor Lease Annotation Visibility

The Kubernetes Lease anchor stores its state in Lease annotations under the
`rs3.rs/v2-*` prefix: the accepted sequence, commit object key, commit body
digest, provider version ID, signing key ID, and format-root reference. Any
subject with `get` or `list` on that Lease can read these annotations. That
reveals the current anchor position, the backend commit object keys and digests,
and, over time, repository write cadence. It does not reveal client paths,
directory names, Kubernetes namespace or object names, snapshot names, or key
material. The commit keys and digests are opaque backend identifiers, not client
paths, so path privacy holds; the exposure is repository activity metadata, not
protected content. Restrict Lease read access with RBAC to the gateway service
account and cluster operators who already administer the anchor trust domain.

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

For retained multipart writes, `rs3` verifies finite Object Lock retention on
the completed provider version before accepting the write. Providers that do
not carry retention from multipart creation must support applying and verifying
it on the returned exact version immediately after completion. Missing version
IDs or failed protection verification fail closed. Client legal-hold requests
are rejected until restore-dependency propagation and guarded release ship.

A retained-version provider may accept a second same-key write instead of
rejecting `If-None-Match: *`. That is acceptable only for retained/Object Lock
repository objects when the new write returns a distinct version ID and old
anchor-bound versions remain exactly readable. The object key is then not the
uniqueness authority; the signed commit, external anchor, object digest, and
provider version ID are.

In both the removed prototype and current preview `v02`, commit keys include a
random component. For retained-version
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
is separate from the S3 data plane. Path-redacted `GET` routes accept the read
or mutation bearer token. Full-maintenance `POST` routes accept only a distinct
mutation token; configuring no mutation token leaves the listener read-only.
Both tokens must remain separate from backup-client and backend S3 credentials.

Maintenance dry run returns aggregates and an opaque digest that binds the
repository's canonical exact private plan. Apply re-plans after entering the
guarded exclusion window, rejects a different digest, and consumes that same
plan instance. Exact backend object/version identities stay inside the
repository layer. Audit records expose only bounded operation identifiers,
aggregate counts and bytes, stable outcomes, and the opaque plan digest.
Recovery, key management, and general storage mutation remain outside the HTTP
admin surface.

Do not reuse backup-client S3 credentials as admin credentials. S3 client IAM
controls backup-tool operations on the data plane; admin/operator identity is a
separate admin boundary.

The single-gateway console follows the same reporting rule. It may render the
gateway admin report in a browser, but it must keep the gateway admin bearer
token server-side, require a separate console bearer token for `GET
/api/posture`, `GET /api/status`, and `GET /api/maintenance`, and stay
read-only. It must not add object
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

- The `v02` catalog, wire-version-6 pack/stream run model, compaction, and
  automatic watermark paths remain preview-scoped. Durable format freeze,
  retained-provider qualification, and external cryptographic review are still
  outstanding.
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
- Foreground known-length standalone payload uploads are implemented with
  random object identities, segmented AEAD, exact-version postconditions, a
  complete ciphertext verification read, fenced reference publication,
  process-local in-flight GC roots, and opaque-orphan reporting. Retained-
  provider restart/handoff and destructive cross-process maintenance still need
  release-candidate qualification.
- New writes isolate payload packs by effective retention cohort. The physical
  cohort type also preserves a legal-hold dimension for defensive parsing of
  historical state, but v02 client hold publication is disabled. Historical or
  otherwise over-protected mixed packs remain safe but may retain dead bytes
  until a future cleaner passes retained-version, protected-root, and crash
  qualification.
- Packed-run catalog compaction and automatic pre-ceiling backpressure pass the
  in-memory and local fresh-process filesystem 1M lanes, but not pinned-runner
  timing, retained-provider restart, or the full adversarial crash and
  delayed-visibility matrix. Exact
  mixed-pack cleaning remains incomplete. Level-1 tombstones are
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
