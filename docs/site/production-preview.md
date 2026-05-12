# V1 Production Preview

The first release target is a production preview for Kubernetes operators who
store backups on S3-compatible infrastructure they do not fully trust. The main
client is Velero with Kopia uploader; direct Kopia use remains in scope because
it is the compatibility substrate.

The preview is a product contract, not a stable repository-format promise.

## Product Claim

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
- retained storage evidence helps investigate whether the backend or control
  plane lied

`rs3` does not replace Velero, Kopia, database-native backup consistency, or
application-aware restore validation. It protects the object-store boundary and
the repository-state transition model.

## Claim Boundaries

| Safe preview claim | Not a preview claim |
| --- | --- |
| Backend object keys and path-sensitive metadata are opaque to the storage backend. | The backend learns nothing; object counts, sizes, timing, and broad object classes remain visible. |
| Anchored signed checkpoints detect backend rollback against the trusted anchor. | S3 Object Lock or retention alone proves the latest repository state. |
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
| Storage witness | Create-only checkpoint evidence under `evidence/` |
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
state. Storage-side checkpoint evidence is a witness, not the authority. On a
healthy open, the accepted anchor position, signed checkpoint chain, keyring
envelope reference, and checkpoint evidence must agree. If they do not agree,
the gateway must fail closed or enter an explicit recovery workflow.

This means a malicious backend should not be able to make the gateway silently
restore an older valid checkpoint while the in-cluster anchor still records a
newer one. The backend can still deny service by hiding required objects.

## Failure Rules

| Situation | Preview behavior |
| --- | --- |
| Empty backend prefix and no anchor | Startup may initialize one generated keyring envelope using the supplied repository ID, salt, and wrapping-key source. An envelope object ID is optional override state, not normal Helm state. |
| Existing backend prefix and matching anchor | Open after signed checkpoint, envelope, and evidence validation. |
| Backend serves an older checkpoint than the Lease anchor | Fail closed as rollback. |
| Backend hides the checkpoint or evidence named by the Lease anchor | Fail closed as unavailable or tampered. |
| Backend adds unrelated objects | Ignore them unless signed and reachable from anchored state. |
| Backend overwrites checkpoint, evidence, index, metadata, or payload bytes | Reject through native create-only write checks, signatures, digests, or AEAD authentication. S3-compatible providers must honor `If-None-Match: *`; `HEAD` before `PUT` is not a production fallback. |
| Backend evidence appears newer than the Lease anchor | Treat as ambiguous; fail closed until explicit recovery resolves whether the anchor missed an advance or was rolled back. |
| Lease missing but backend evidence exists | Do not silently trust storage. Require a trusted bundle or explicit bounded recovery that validates the highest observed valid checkpoint and enforces a maximum signed checkpoint age. |
| Multiple gateways serve the same repository as `read-write` | Unsupported. Run one writer per repository; use `restore-readonly` for scaled restore readers. |
| Gateway started as `restore-readonly` without an accepted anchor | Fail closed. Run explicit anchor recovery first, then serve restore traffic. |
| Healthy Velero restore through the primary path | Run through the single `read-write` gateway so Velero restore-result artifacts are checkpointed and the restore can report `Completed`. |
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
  repository ID, salt, checkpoint-bound envelope, wrapping-key source, anchor,
  and evidence match
- if the prefix is non-empty but cannot be verified, stop with a precise error
  instead of creating new state

## Disaster Recovery

A new cluster needs more than backend credentials:

- repository ID
- repository salt
- wrapping-key source for the envelope
- trusted anchor position: sequence, checkpoint ID, checkpoint object version ID
  when available, and checkpoint digest, or an explicit bounded recovery
  decision from retained evidence

The trusted anchor position can come from a recovery bundle, audited export, or
trusted external anchor. Storage evidence can help prove what existed in the
backend, but by itself it is not a perfect latest-state authority because a
malicious backend can hide newer valid evidence or replay older valid evidence.

An external anchor can distribute trust outside the cluster. It should store
or sign the accepted checkpoint position, not the whole repository index. That
position already commits to the signed checkpoint chain and therefore to the
repository state reachable from it.

## Current Evidence

Latest focused local evidence:

| Evidence | Result |
| --- | --- |
| Velero dynamic-PVC gateway-restart in `read-write` | Passed on 2026-05-12 with restore status `Completed`; artifact `.local/integration/`. |
| Velero strict `restore-readonly` incident-restore smoke | Passed on 2026-05-12 with workload verification, expected restore-artifact write denial, and zero backend writes during restore; artifact `.local/integration/`. |
| Velero/Postgres compatibility smoke | Passed on 2026-05-12; artifact `.local/integration/`. |
| Larger Kopia restore matrix | Passed with `regression_budgets=pass` and `workload_consistency=pass`; artifact `.local/integration/`. |

The release evidence is local harness evidence, not a provider certification. A
production-preview trial should still run the selected live S3-compatible
provider with an empty bucket and a deliberately preserved restore bundle. The
provider trial must include native conditional create, retained version IDs, and
exact-version reads after a newer latest object exists when retention/Object
Lock is in scope.

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

For restore evidence, run `xtask restore verify` against a trusted checkpoint
position from the configured anchor.

For disaster-recovery evidence, export a trusted restore bundle with
`rs3-server export-restore-bundle` and prove anchor import with
`rs3-server import-anchor` in a clean cluster.

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
- restore verification succeeds for the checkpoint under test, including
  checkpoint evidence and keyring-envelope binding
- a trusted restore bundle can be exported and imported into a missing anchor
- performance evidence compares gateway behavior to the straight RustFS proxy
  baseline
- accepted leakage is documented in the security model

## Stable-Format Blockers

A stable repository-format v1 needs more than the preview:

- explicit repository-format compatibility policy
- broader provider matrix
- chaos coverage for stale backend state, anchor unavailability, backend
  injection, and retention failure
- a finalized external anchor and key-provider interface
- a committed repository migration policy
- external security review for public guarantees
