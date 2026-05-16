# V2 Production Preview

The first release target is a production preview for Kubernetes operators who
store backups on S3-compatible infrastructure they do not fully trust. The main
client is Velero with Kopia uploader; direct Kopia use remains in scope because
it is the compatibility substrate.

The preview defines the behavior to evaluate. It is not a stable
repository-format promise.

## Preview Claim

`rs3` is a path-private, tamper-evident S3 gateway for backup repositories.

It should let an operator put Velero/Kopia backup data on a provider such as
retained-backend, RustFS, or another S3-compatible store while reducing what that
provider can learn or change:

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

| Safe preview claim | Not a preview claim |
| --- | --- |
| Backend object keys and path-sensitive metadata are opaque to the storage backend. | The backend learns nothing; object counts, sizes, timing, and broad object classes remain visible. |
| Anchored signed commits detect backend rollback against the trusted anchor. | S3 Object Lock or retention alone proves the latest repository state. |
| `restore-readonly` serves restore reads and rejects supported repository mutations. | Every backup client will report a clean success status when its own restore bookkeeping writes are denied. |
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
| Backend | RustFS/local S3-compatible first, live S3-compatible checks opt-in |
| Keys | Encrypted keyring envelope |
| Gateway modes | `read-write` for backups and routine restores, `restore-readonly` for incident restore |
| Retention | Provider retention/Object Lock capability checked where configured |
| External trust sources | external anchor/key-provider source, not a preview blocker |

## Trust Model

The preview assumes the S3-compatible backend can read, list, delay, delete,
overwrite, replay, or inject objects unless provider retention prevents it. It
also assumes the Kubernetes API used for the Lease anchor is a separate trust
domain from the storage backend.

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
| Empty backend prefix and no anchor | Startup may initialize one generated keyring envelope using the supplied repository ID, salt, and wrapping-key source. An envelope object ID is optional override state, not normal Helm state. |
| Existing backend prefix and matching anchor | Open after signed commit-chain, format-root, and envelope validation. |
| Backend serves an older commit than the Lease anchor | Fail closed as rollback. |
| Backend hides the commit named by the Lease anchor | Fail closed as unavailable or tampered. |
| Backend adds unrelated objects | Ignore them unless signed and reachable from anchored state. |
| Backend overwrites format, keyring, commit, metadata, or payload bytes | Reject through native create-only write checks, signed/digested state, AEAD authentication, or retained-version exact reads. S3 providers qualify through either `atomic-create` or `retained-version`; `HEAD` before `PUT` is not a production fallback. |
| Backend contains commits newer than the Lease anchor | Do not silently advance. Treat as ambiguous until explicit recovery validates a trusted bundle or a separately approved anchor decision. |
| Lease missing but backend objects exist | Do not silently trust storage. Require a trusted v2 recovery bundle and verify the named commit chain before recreating the anchor. |
| Multiple gateways serve the same repository as `read-write` | Unsupported. Run one writer per repository; use `restore-readonly` for scaled restore readers. |
| Gateway started as `restore-readonly` without an accepted anchor | Fail closed. Run explicit anchor recovery first, then serve restore traffic. |
| Healthy Velero restore through the primary path | Run through the single `read-write` gateway so Velero restore-result artifacts are committed and the restore can report `Completed`. |
| Restore client attempts PUT, DELETE, or legal-hold mutation through `restore-readonly` | Reject the request instead of advancing repository state. |
| Velero restore reports `PartiallyFailed` only because restore-result artifact uploads were denied by `restore-readonly` | Accept only after proving restored data, completed pod-volume restore, and zero backend writes during restore. Treat any other restore error as failure. |
| Lease and backend are both compromised | Online protection is exhausted; recovery needs offline or externally protected authority. |
| Wrapping key and old envelope are both exposed | Rewrap protects only future envelope handling; historical data under that keyring is treated as exposed. |

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

The trusted anchor position can come from a recovery bundle, audited export, or
trusted external anchor. Retained backend versions can help prove what
existed in storage, but by themselves they are not a latest-state authority
because a malicious backend can hide newer valid commits or replay older valid
commits.

An external anchor can distribute trust outside the cluster. It should store
or sign the accepted commit position, not the whole repository index. That
position already commits to the signed commit chain and therefore to the
repository state reachable from it.

## Current Evidence

Latest focused evidence:

| Evidence | Result |
| --- | --- |
| Live retained-backend clean v2 preview gate | Passed on 2026-05-16 with `just preview-gate-v2-live`. S3 gateway/tooling, Kopia, Kubernetes Lease, Velero dynamic-PVC gateway-restart, and Velero/Postgres lanes all passed under prefix base `isolated live prefix`; artifacts `.local/integration/` and `.local/integration/`. |
| Local v2 Velero/Postgres RustFS smoke | Passed on 2026-05-16 after v2 concurrent payload-section cache fills were coalesced; artifact `.local/integration/`. The gateway run completed backup and restore, wrote no backend `segments/` objects, read 29.0 MB versus 28.9 MB for direct RustFS baseline `.local/integration/`, and used 57 backend requests versus 708 for direct RustFS. |
| Local v2 gateway perf baseline | Refreshed on 2026-05-16 with `just perf-s3-gateway --objects 16 --object-size 4096 --reads 16 --range-len 512 --commit-batch-items 8 --concurrency 8 --format jsonl`. Sequential writes emitted one backend commit PUT per client object, parallel writes batched to 2 PUTs for 16 objects, and repeated full/range reads of one object reused a verified payload-section cache after the first commit GET. |
| Local v2 S3 and Kopia gateway smokes | Passed on 2026-05-16 with `just integration-s3-gateway --repository-format v2-preview` and `just integration-kopia-gateway --repository-format v2-preview` after the v2 read-cache and measurement-surface repairs. |
| Live retained-backend v2 provider conformance | Passed on 2026-05-16 with `rs3 check-v2-provider` for the retained-version/Object Lock profile, including exact-version `HEAD`, `GET`, range `GET`, overwrite version survival, retention extension, delete blocking, and the governance-bypass review marker; backend prefix `isolated live prefix`. |
| Live retained-backend v2 gateway smoke | Passed on 2026-05-16 with `just integration-s3-gateway-v2-live` through the local gateway using `mc` and default `rclone lsf` for `PUT`, `HEAD`, `GET`, and prefix listing with governance retention; the xtask backend key check found no client-visible names in repository object keys; backend prefix `isolated live prefix`. |
| Live retained-backend v2 Kopia gateway backup/restore | Passed on 2026-05-16 with `just integration-kopia-gateway-v2-live` against an Object Lock bucket with repository governance retention enabled; restored bytes matched, and a backend key check found no obvious Kopia/source/restore names in 45 repository objects; backend prefix `isolated live prefix`. |
| v2 Kubernetes Lease gateway smoke | Passed on 2026-05-16 with `just integration-k8s-gateway-v2`; Helm deployed `RS3_REPOSITORY_FORMAT=v2-preview` with Kubernetes Lease anchoring, the S3 smoke passed, and the harness verified v2 Lease annotations. |
| Live retained-backend v2 Velero dynamic-PVC gateway-restart restore | Passed on 2026-05-16 with `just integration-velero-kopia-dynamic-pvc-gateway-restart-v2-live` against an Object Lock bucket with repository governance retention enabled; backup and restore completed, restored bytes matched, v2 Lease assertions passed after backup, after gateway restart, and after restore, and a backend key check found no obvious Velero/Kopia/workload names in 66 repository objects; artifact `.local/integration/`; backend prefix `isolated live prefix`. |
| Live retained-backend v2 DR anchor import/export | Passed on 2026-05-16 against fresh v2 Velero dynamic-PVC gateway-restart output under backend prefix `isolated live prefix`; artifact `.local/integration/`. The source bundle verified 34 commits, a clean kind cluster with a missing Lease rejected import when the retention context was omitted, import with governance retention recreated the Lease, and the recovered bundle verified the same anchor. |
| Live retained-backend v2 Velero/Postgres restore | Passed on 2026-05-16 with `just integration-velero-kopia-postgres-v2-live` against an Object Lock bucket with repository governance retention enabled; Postgres rows were backed up and restored, v2 Lease assertions passed after backup and after restore, and a backend key check found no obvious Velero/Kopia/Postgres/workload names in 68 repository objects; artifact `.local/integration/`; backend prefix `isolated live prefix`. |
| Live retained-backend retained-version S3 qualification | Passed on 2026-05-16 with `xtask integration s3-local --qualification-profile retained-version --object-lock`; Object Lock retention and legal hold checks passed with versioned delete blocking under backend prefix `isolated live prefix`. |
| Live retained-backend Kopia gateway backup/restore | Passed on 2026-05-13 against an Object Lock bucket with repository governance retention enabled; backend prefix `isolated live prefix`. |
| Live retained-backend Velero dynamic-PVC gateway-restart restore | Passed on 2026-05-13 against an Object Lock bucket with repository governance retention enabled; artifact `.local/integration/`; backend prefix `isolated live prefix`. |
| Velero dynamic-PVC gateway-restart in `read-write` | Passed on 2026-05-12 with restore status `Completed`; artifact `.local/integration/`. |
| Velero strict `restore-readonly` incident-restore smoke | Passed on 2026-05-12 with workload verification, expected restore-artifact write denial, and zero backend writes during restore; artifact `.local/integration/`. |
| Velero/Postgres compatibility smoke | Passed on 2026-05-12; artifact `.local/integration/`. |
| Larger Kopia restore matrix | Passed on 2026-05-13 with adaptive payload segment sizing, `regression_budgets=pass`, and `workload_consistency=pass`; artifact `.local/integration/`. |

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

`v0.1.0-preview.2` is a production-preview candidate for evaluating `rs3` with
Velero/Kopia on Kubernetes and a retained S3-compatible backend. The primary
repository format for new evaluation repositories is `v2-preview`. The
candidate includes the adaptive payload segment default, the decrypted-segment
cache, retained-version restore checks, the live S3 provider qualification
lane, and the refreshed retained-backend backup/restore evidence above.

Use this candidate for controlled evaluation, not for a stable repository-format
commitment. The durable format remains preview-scoped, governance-bypass IAM
review remains operator-owned, and strong public security guarantees
still need external review.

## Non-Goals

The preview does not promise:

- stable repository-format compatibility
- broad generic S3 application compatibility
- external anchor implementation beyond Kubernetes Lease
- replacement of Kopia, Velero, or database-native backup systems
- that Velero application backups are confidential or complete by themselves

## Release Gates

Run the cheap local gate first:

```sh
just preview-gate-local
```

Release candidates should also run the release integration gate:

```sh
just preview-gate-release
```

Scheduled or release-candidate hardening should run the local v2 nightly gate:

```sh
just preview-gate-v2-nightly
```

For restore evidence, run restore traffic through the anchored v2 gateway and
verify the restored bytes against the application workload.

For disaster-recovery evidence, export a trusted restore bundle with
`rs3-server export-restore-bundle` and prove anchor import with
`rs3-server import-v2-anchor` in a clean cluster. For retained-version
repositories, first prove that the same bundle is rejected when the matching
retention context is omitted, then import with the configured retention mode
and verify the recovered bundle with `xtask v2 verify-bundle`.

## Configuration Checklist

For a production-preview deployment:

- use `RS3_ANCHOR_MODE=kubernetes-lease`
- use `repositoryKeys.create=true` or `repositoryKeys.existingSecret` in Helm
- set a stable `repository.id`
- set a stable, operator-provided `repositoryKeys.saltHex`
- configure gateway access credentials explicitly
- configure repository retention when retention evidence is part of the trial
- use `gateway.mode=restore-readonly` for incident restore deployments
- run `rs3-server doctor --profile production` before exposing the gateway
- keep restore verification inputs outside the object-store trust boundary
- collect metrics and logs with path-safe labels only
- treat wrapping-key rewrap as hygiene, not as recovery from a leaked wrapping
  key plus copied envelope

Do not rely on backend state alone for production-preview evidence. Use the
configured anchor position and restore verification inputs from a trusted bundle
or separate authority.

## Readiness Bar

A preview is ready when the release evidence shows:

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

## Stable Format Blockers

A stable repository format needs more than the preview:

- explicit repository-format compatibility policy
- broader provider matrix
- chaos coverage for stale backend state, anchor unavailability, backend
  injection, and retention failure
- a finalized external anchor and key-provider interface
- external security review for public guarantees
