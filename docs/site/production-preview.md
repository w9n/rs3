# Production Preview

The first release target is a production preview for Kubernetes operators who
store backups on S3-compatible infrastructure they do not fully trust. The main
client is Velero with Kopia uploader; direct Kopia use remains in scope because
it is the compatibility substrate.

The preview defines the behavior to evaluate. It is not a stable
repository-format promise.

!!! danger "Repository release is currently blocked"
    `commits/v01` has been removed and is unsupported; it had no production
    repositories. The runtime now reads and writes a transitional
    `commits/v02` envelope with signed per-section digests and payload-skipping
    replay, but framed index runs, signed catalogs, compaction, and bounded
    catalog recovery remain unimplemented. Existing compatibility and provider
    results are useful gateway regression evidence, but they do not qualify the
    complete `v02` format or a production repository release. There will be no
    `v01` migration or dual-reader requirement.

## Preview Scope

`rs3` is a path-private, tamper-evident S3 gateway for backup repositories.

It should let an operator put Velero/Kopia backup data on an S3-compatible
store while reducing what that provider can learn or change:

- backend object keys do not reveal backup paths, namespaces, Kubernetes object
  names, snapshot names, or Kopia blob names
- payloads and privacy-sensitive metadata are encrypted and authenticated before
  they reach the backend
- backend-injected objects are ignored unless they are referenced by signed
  repository state
- backend rollback is rejected against the configured external anchor
- retained exact-version objects and trusted recovery bundles help investigate
  whether the backend or anchor service served stale or inconsistent state

`rs3` does not replace Velero, Kopia, database-native backup consistency, or
application-aware restore validation. It protects the object-store boundary and
the repository-state transition model.

## Claim Boundaries

| Evaluated preview behavior | Not a preview claim |
| --- | --- |
| Backend object keys and path-sensitive metadata are opaque to the storage backend. | The backend learns nothing; object counts, sizes, timing, and broad object classes remain visible. |
| Anchored signed commits detect backend rollback against the trusted anchor. | S3 Object Lock or retention alone establishes the latest repository state. |
| `restore-readonly` serves restore reads and rejects supported repository mutations. | Every backup client will report a successful status when its own restore bookkeeping writes are denied. |
| Velero/Kopia and Kopia compatibility are covered by local integration evidence. | Broad generic S3 application compatibility is promised. |
| The preview repository can be evaluated with documented recovery material. | The durable repository format is stable across future releases. |

## Supported Shape

| Area | Preview scope |
| --- | --- |
| Primary client | Velero with Kopia uploader |
| Compatibility client | Kopia |
| Deployment | Kubernetes |
| External anchor | Kubernetes Lease |
| Storage witness | Retained exact-version commit objects; the Kubernetes Lease remains the latest-state authority |
| Backend | S3-compatible retained-version backend; RustFS/local checks for disposable evidence, live checks opt-in |
| Keys | Encrypted keyring envelope |
| Gateway modes | `read-write` for backups and routine restores, `restore-readonly` for incident restore |
| Retention | Provider retention/Object Lock capability checked where configured |

## Trust Model

The preview assumes the S3-compatible backend can read, list, delay, delete,
overwrite, replay, or inject objects unless provider retention prevents it. It
also assumes the Kubernetes API used for the Lease anchor is a separate trust
domain from the storage backend.

That separation is operational, not automatic. If the same compromised control
domain can rewrite the Lease, read the wrapping-key source, alter backend
credentials, and replace preserved restore bundles, the online protection model
is exhausted. Preview deployments should keep those authorities separated
enough for incident recovery and audit.

The Kubernetes Lease is the preview authority for latest accepted repository
state. Retained commit objects are useful history, not the authority. On a
healthy open, the accepted anchor position, signed commit chain, format root,
and keyring envelope reference must agree. If they do not agree, the gateway
must fail closed or enter an explicit recovery workflow.

This means a malicious backend should not be able to make the gateway silently
restore an older valid commit while the in-cluster anchor still records a newer
one. The backend can still deny service by hiding required objects.

## Failure Rules

| Situation | Preview behavior |
| --- | --- |
| Empty backend prefix and no anchor | Startup may initialize one generated keyring envelope only when repository initialization is explicitly enabled using the supplied repository ID, salt, and wrapping-key source. An envelope object ID is optional override state, not normal Helm state. |
| Existing backend prefix and matching anchor | Open after signed commit-chain, format-root, and envelope validation. |
| Fresh initialization finds unsupported `commits/v01` objects or ambiguous existing state | Fail closed. `v02` initialization does not import, migrate, overwrite, or adopt the old generation. |
| Backend serves an older commit than the Lease anchor | Fail closed as rollback. |
| Backend hides the commit named by the Lease anchor | Fail closed as unavailable or tampered. |
| Backend adds unrelated objects | Ignore them unless signed and reachable from anchored state. |
| Backend overwrites format, keyring, commit, metadata, or payload bytes | Reject through native create-only write checks, signed/digested state, AEAD authentication, or retained-version exact reads. S3 providers qualify through either `atomic-create` or `retained-version`; `HEAD` before `PUT` is not a production fallback. |
| Backend contains commits newer than the Lease anchor | Do not silently advance. Treat as ambiguous until explicit recovery validates a trusted bundle or a separately approved anchor decision. |
| Lease missing but backend objects exist | Do not silently trust storage. Require a trusted generation-matched recovery bundle and verify the exact catalog, run, and payload graph before recreating the anchor. |
| Multiple gateways serve the same repository as `read-write` | Supported only as failover within one Kubernetes apiserver and anchor-Lease coordination domain. A gateway acquires a unique fenced writer epoch on the anchor Lease itself; every anchor advance verifies that epoch atomically, and the gateway shuts down if renewal is no longer trustworthy. Disconnected writers that only share S3 are unsupported. |
| Gateway started as `restore-readonly` without an accepted anchor | Fail closed. Run explicit anchor recovery first, then serve restore traffic. |
| Healthy Velero restore through the primary path | Run through the single `read-write` gateway so Velero restore-result artifacts are committed and the restore can report `Completed`. |
| Restore client attempts PUT, DELETE, or legal-hold mutation through `restore-readonly` | Reject the request instead of advancing repository state. |
| Velero restore reports `PartiallyFailed` only because restore-result artifact uploads were denied by `restore-readonly` | Accept only after verifying restored data, completed pod-volume restore, and zero backend writes during restore. Treat any other restore error as failure. |
| Lease and backend are both compromised | Online protection is exhausted; recovery needs offline or externally protected authority. |
| Wrapping key and old envelope are both exposed | Rewrap protects only future envelope handling; historical data under that keyring is treated as exposed. |

Kubernetes Lease fencing is not a cross-cluster consensus protocol. S3 object
synchronization, conditional writes, Object Lock, or a newest-looking commit do
not provide a safe writer lock under the malicious and eventually inconsistent
backend threat model. Run disconnected gateways as `restore-readonly` readers;
multiple such readers are supported when each can verify an accepted anchored
state. A future disconnected multi-writer mode would need authenticated
branches, deterministic conflict handling, and a separate repository protocol,
not an S3-sync switch.

## Incomplete Multipart Cleanup

Production-preview retained S3-compatible buckets MUST configure a lifecycle
rule that aborts incomplete multipart uploads. Client disconnects, pod crashes,
or provider-side abort failures can leave temporary multipart parts that are
not committed repository objects, so rs3 repository GC cannot discover or clean
them.

Example lifecycle shape, adapting the prefix syntax to the selected provider:

```json
{
  "Rules": [
    {
      "ID": "abort-incomplete-rs3-multipart-uploads",
      "Status": "Enabled",
      "Filter": {
        "Prefix": "<backend-prefix>/"
      },
      "AbortIncompleteMultipartUpload": {
        "DaysAfterInitiation": 1
      }
    }
  ]
}
```

## Bootstrap UX

The preview bootstrap path is declarative:

1. Choose a stable `repository.id`.
2. Generate and keep a stable 32-byte public `repositoryKeys.saltHex`.
3. Store the wrapping-key source outside the object store.
4. Deploy the gateway with Kubernetes Lease anchoring.

The salt is not secret, but it is required restore metadata. Put it in trusted
GitOps or a recovery bundle with the repository ID and anchor position. Do not
make the gateway generate an undeclared salt on first normal startup; that makes
disaster recovery dependent on a cluster Secret that may be gone.

Bootstrap assumes a fresh, randomized backend prefix. The gateway probes the
root and known v2 sub-prefixes before initializing, but provider `LIST`
semantics are still part of the storage trust boundary. Do not bootstrap over an
old or unknown prefix; recover or import the existing repository instead.

For production-like Helm deployments, values remain declarative. The chart
should consume an existing Secret or explicit values. It should not mutate Helm
values after first run.

Startup bootstrap behavior is:

- if the configured backend prefix is empty, initialize exactly one repository
  using the supplied repository ID, supplied salt, and wrapping-key source
- if the prefix already contains repository state, verify that the configured
  repository ID, salt, format-bound envelope, wrapping-key source, anchor, and
  commit chain match
- if the prefix is non-empty but cannot be verified, stop with a precise error
  instead of creating new state

## Disaster Recovery

A new cluster needs more than backend credentials:

- repository ID
- repository salt
- wrapping-key source for the envelope
- trusted v2 anchor position: sequence, commit key, commit object version ID
  when available, commit body digest, signing key ID, and format-root reference

The trusted anchor position can come from a recovery bundle or audited export.
Retained backend versions can help establish what existed in storage, but by
themselves they are not a latest-state authority because a malicious backend
can hide newer valid commits or replay older valid commits.

Recovery bundles are weak-subjectivity inputs. Import requires an
operator-supplied `--min-sequence` floor external to the bundle and refuses
older valid bundles below that floor. Production recovery also requires an
offline Ed25519 bundle signature verified by `RS3_RECOVERY_PUBLIC_KEY`.
Import scans stored v2 commits and refuses to strand higher commit sequences
unless the operator passes the explicit `--force-rollback` override after
rollback review.
Preserve fresh signed bundles outside the backend and compare the sequence and
commit digest with an external record before anchor import.

Any external anchor should store or sign the accepted commit position, not the
whole repository index. That position already commits to the signed commit
chain and therefore to the repository state reachable from it.

## Current Evidence

Release evidence below is maintainer-run evidence for the deprecated preview
implementation. Treat it as compatibility, storage-contract, and gateway
regression evidence only. It predates the generation switch and does not
exercise standalone framed index runs, signed `INDEX_ROOT` catalogs, automatic
checkpoint backpressure, or exact catalog-root GC. Exact backend prefixes and
workspace-local artifact paths are not part of the public evidence record
because they are operational identifiers. Preserve raw reports, checksums, and
run logs in release assets or private evidence bundles when independent review
needs them.

At a glance:

- consolidated v2 live preview gate passed against the retained-version profile
- live provider qualification covered exact-version reads, retained multipart
  completion, and retention behavior
- provider conformance can be preserved as JSON and surfaced through admin
  posture without rerunning live probes from status
- DR rehearsal verified bundle export, missing-Lease rejection without retention
  context, and anchor import into a new cluster
- 2026-05-18 live checks reran the retained-version gate after adding
  post-complete verification for retained multipart writes
- local performance and compatibility smokes remain release evidence, not a
  provider certification

| Evidence | Result |
| --- | --- |
| Live retained-backend v2 preview gate | Passed on 2026-05-18 with `just preview-gate-v2-live`. S3 gateway/tooling, Kopia, Kubernetes Lease, Velero dynamic-PVC gateway-restart, and Velero/Postgres lanes all passed against fresh opaque backend prefixes. |
| Live retained-backend v2 GC rehearsal | Passed on 2026-05-21 with `just v2-gc-rehearsal-live` against a fresh Object Lock prefix. The dry run found two orphan candidates, planned one exact-version delete, treated the retained orphan as protected, applied one unprotected exact-version delete, left the protected candidate blocked, and reloaded the anchor-selected chain. |
| Live retained-backend v2 DR anchor import/export | Passed on 2026-05-18 against fresh v2 Velero dynamic-PVC gateway-restart output. The source backup/restore lane passed, the source bundle verified 34 commits, a new kind cluster with a missing Lease rejected import when the retention context was omitted, import with governance retention recreated the Lease, and the recovered bundle verified the same anchor. |
| Live retained-backend v2 provider conformance | Passed on 2026-05-18 with `rs3 check-v2-provider` for the retained-version/Object Lock profile, including retained multipart completion, exact-version `HEAD`, `GET`, range `GET`, overwrite version survival, retention extension, delete blocking, legal hold, and the governance-bypass review marker. A focused live storage test also confirmed retained multipart exact-version range read and version-delete blocking. A provider-specific SDK probe found that retention metadata may not appear on `HEAD` when retention is supplied only on `CreateMultipartUpload`; rs3 therefore verifies the completed version and applies provider protection to that returned version when required. |
| Live retained-backend v2 Velero dynamic-PVC gateway-restart restore | Passed on 2026-05-18 with `just preview-gate-v2-live` against an Object Lock bucket with repository governance retention enabled; backup and restore completed, restored bytes matched, and v2 Lease assertions passed after backup, after gateway restart, and after restore. |
| Live retained-backend v2 Velero/Postgres restore | Passed on 2026-05-18 with `just preview-gate-v2-live` against an Object Lock bucket with repository governance retention enabled; Postgres rows were backed up and restored, and v2 Lease assertions passed after backup and after restore. |
| Live retained-backend v2 Kopia gateway backup/restore | Passed on 2026-05-18 as part of `just preview-gate-v2-live` against an Object Lock bucket with repository governance retention enabled; restored bytes matched. |
| Live retained-backend v2 gateway smoke | Passed on 2026-05-18 as part of `just preview-gate-v2-live` through the local gateway using `mc` and default `rclone lsf` for `PUT`, `HEAD`, `GET`, and prefix listing with governance retention. |
| v2 Kubernetes Lease gateway smoke | Passed on 2026-05-18 as part of `just preview-gate-v2-live`; Helm deployed the default v2-preview gateway with Kubernetes Lease anchoring, the S3 smoke passed, and the harness verified v2 Lease annotations. |
| Local v2 streamable payload and unknown-length PUT checks | Passed on 2026-05-18 with focused repository and gateway tests plus `just check`, `just check-s3`, and `just docs-check`. These checks cover streamable commit-embedded payloads, signed payload-section length validation, known-length multipart PUT, unknown-length multipart PUT, and retained multipart Object Lock compile coverage. |
| Local v2 Velero dynamic-PVC gateway-restart smoke | Passed on 2026-05-17 with `just integration-velero-kopia-dynamic-pvc-gateway-restart-smoke` on a fresh kind cluster. Backup completed, the gateway deployment was restarted, restore completed, restored pod data was verified, and the cluster was deleted. |
| Local v2 Velero/Postgres RustFS smoke | Passed on 2026-05-16 after v2 concurrent payload-section cache fills were coalesced. The gateway run completed backup and restore, wrote no backend `segments/` objects, read 29.0 MB versus 28.9 MB for the direct RustFS baseline, and used 57 backend requests versus 708 for direct RustFS. |
| Local v2 gateway perf baseline | Refreshed on 2026-05-16 with `just perf-s3-gateway --objects 16 --object-size 4096 --reads 16 --range-len 512 --commit-batch-items 8 --concurrency 8 --format jsonl`. Sequential writes emitted one backend commit PUT per client object, parallel writes batched to 2 PUTs for 16 objects, and repeated full/range reads of one object reused a verified payload-section cache after the first commit GET. |
| Local v2 S3 and Kopia gateway smokes | Passed on 2026-05-16 with `just integration-s3-gateway` and `just integration-kopia-gateway` after the v2 read-cache and measurement-surface repairs. |
| Live retained-version S3 qualification | Passed on 2026-05-16 with `xtask integration s3-local --qualification-profile retained-version --object-lock`; Object Lock retention and legal hold checks passed with versioned delete blocking. |

??? note "Background compatibility evidence"
    | Evidence | Result |
    | --- | --- |
    | Live retained-backend Kopia gateway backup/restore | Passed on 2026-05-13 against an Object Lock bucket with repository governance retention enabled. |
    | Live retained-backend Velero dynamic-PVC gateway-restart restore | Passed on 2026-05-13 against an Object Lock bucket with repository governance retention enabled. |
    | Velero dynamic-PVC gateway-restart in `read-write` | Passed on 2026-05-12 with restore status `Completed`. |
    | Velero strict `restore-readonly` incident-restore smoke | Passed on 2026-05-12 with workload verification, expected restore-artifact write denial, and zero backend writes during restore. |
    | Velero/Postgres compatibility smoke | Passed on 2026-05-12. |
    | Larger Kopia restore matrix | Passed on 2026-05-13 with adaptive payload segment sizing, `regression_budgets=pass`, and `workload_consistency=pass`. |

The release evidence is local harness evidence, not a provider certification. A
production-preview trial should still run the selected live S3-compatible
provider with an empty bucket and a deliberately preserved restore bundle. The
provider trial must explicitly choose `atomic-create` or `retained-version`.
The retained-version profile must include Object Lock, retained version IDs, and
exact-version reads after a newer latest object exists.
For governance-mode buckets, also review IAM or bucket policy so normal gateway
credentials cannot use governance-bypass permissions; the live retained-version
test does not replace that credential review.

## Release Candidate Note

The current preview implementation remains useful for controlled Velero/Kopia,
provider, and gateway evaluation. Do not initialize it for production data or
present it as the new repository format. A repository release candidate is
blocked until the complete `commits/v02` contract is implemented and passes the
format, recovery, checkpoint, retained-provider, GC, and scale gates.

Governance-bypass IAM review remains operator-owned, live provider gates must be
rerun after the new run-object path lands, and public security claims need
separate external review.

## Non-Goals

The preview does not promise:

- stable repository-format compatibility
- broad generic S3 application compatibility
- external anchor implementation beyond Kubernetes Lease
- replacement of Kopia, Velero, or database-native backup systems
- that Velero application backups are confidential or complete by themselves

## Release Gates

The commands below exercise the transitional preview implementation and remain
useful regression checks. They do not qualify the complete `v02` contract.

Run the cheap local regression gate first:

```sh
just preview-gate-local
```

Release candidates should also run the release integration gate:

```sh
just preview-gate-release
```

Scheduled hardening may run the local prototype nightly gate:

```sh
just preview-gate-v2-nightly
```

For gateway regression evidence, run restore traffic through the anchored gateway and
verify the restored bytes against the application workload.

For disaster-recovery evidence, export a trusted restore bundle with
`rs3-server export-restore-bundle` and verify anchor import with
`rs3-server import-v2-anchor` in a new cluster. For retained-version
repositories, first verify that the same bundle is rejected when the matching
retention context is omitted, then import with the configured retention mode
and verify the recovered bundle with `rs3 verify-bundle`.

## Configuration Checklist

For a controlled prototype deployment only:

- use `RS3_ANCHOR_MODE=kubernetes-lease`
- leave `RS3_WRITER_GUARD=required` enabled for read-write gateways
- place the S3, admin, and console listeners behind TLS termination, or keep
  them on cluster-local networks protected by NetworkPolicy or equivalent
  controls
- use `repositoryKeys.create=true` or `repositoryKeys.existingSecret` in Helm
- set `repository.allowInit=true` only for deliberate first initialization on a
  fresh backend prefix; turn it off for normal existing-repository serving
- keep Helm `updateStrategy.type=Recreate` for `read-write` gateways so rollouts
  do not overlap two writers
- set a stable `repository.id`
- set a stable, operator-provided `repositoryKeys.saltHex`
- configure gateway access credentials explicitly
- configure repository retention when retention evidence is part of the trial
- preserve `rs3 check-v2-provider --format json` output and configure
  `RS3_PROVIDER_CONFORMANCE_REPORT_FILE` when exposing admin posture
- set gateway hardening limits for maximum `PutObject` size, buffered upload
  threshold, backend multipart part size, in-flight upload body bytes, open
  connections, concurrent requests, and request rate; align ingress limits with
  them
- use `gateway.mode=restore-readonly` for incident restore deployments
- run `rs3-server doctor --profile production --probe` before exposing the
  gateway
- keep restore verification inputs outside the object-store trust boundary
- collect metrics and logs with path-safe labels only
- treat wrapping-key rewrap as hygiene, not as recovery from a leaked wrapping
  key plus copied envelope

Do not rely on backend state alone for production-preview evidence. Use the
configured anchor position and restore verification inputs from a trusted bundle
or separate authority.

## Readiness Bar

Preview evidence should show:

- default checks and S3-feature checks pass
- dependency policy checks pass or have documented exceptions
- Kopia can create, snapshot, and restore through the gateway
- Velero with Kopia uploader can restore a dynamic PVC after gateway restart in
  normal `read-write` mode with restore status `Completed`
- the Velero/Postgres compatibility smoke restores verified application data
- restore-readonly mode rejects supported writes and still serves restore reads
- restore verification succeeds for the anchored commit chain under test,
  including format-root and keyring-envelope binding
- a trusted restore bundle can be exported and imported into a missing anchor
- performance evidence compares gateway behavior to the straight RustFS proxy
  baseline
- accepted leakage is documented in the security model

## `v02` Release Blockers

The replacement repository generation must complete all of these together:

- implement canonical framed `INDEX_RUN` objects and small signed `INDEX_ROOT`
  catalogs under the new `commits/v02` generation;
- replace one payload section per object with immutable value-separated
  `PAYLOAD_PACK` sections, compact record pointers, and protection cohorts;
- replace cumulative delta retention with descriptor-first, one-frame-at-a-time
  recovery;
- keep one accepted repository state plus a bounded pending mutation overlay;
- add fenced automatic checkpointing with degraded and write-paused failure
  posture before absolute replay ceilings;
- make maintenance mark exact catalog, run, and effective payload versions
  without recursively retaining entire payload commit ancestry;
- pass fresh-process committed-write recovery at 10k, 100k, and 1M objects,
  including exact cardinality and first, middle, and last payload verification;
- enforce the small-object write-amplification ceilings in the performance
  reference, including separate raw-S3 and real Kopia/Velero tiny-file lanes;
- prove payload-pack reachability and cleaning across tombstones, protected
  historical roots, retention, legal hold, and interrupted repacks;
- qualify exact standalone-run versions, restart, checkpoint crash, stale
  fencing, delayed visibility, retention renewal, and writer handoff on a real
  retained provider;
- finalize canonical encoding, capability negotiation, key-provider, and
  compatibility policy; and
- complete external cryptographic and security review for public guarantees.
