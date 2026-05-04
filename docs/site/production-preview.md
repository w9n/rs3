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
| Retention | Provider retention/Object Lock capability checked where configured |
| External trust sources | HSM/KMS/Vault anchor and unwrap authority, not a preview blocker |

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
| Empty backend prefix and no anchor | Startup may initialize the configured keyring envelope using the supplied repository ID, salt, envelope object ID, and unwrap authority. |
| Existing backend prefix and matching anchor | Open after signed checkpoint, envelope, and evidence validation. |
| Backend serves an older checkpoint than the Lease anchor | Fail closed as rollback. |
| Backend hides the checkpoint or evidence named by the Lease anchor | Fail closed as unavailable or tampered. |
| Backend adds unrelated objects | Ignore them unless signed and reachable from anchored state. |
| Backend overwrites checkpoint, evidence, index, metadata, or payload bytes | Reject through create-only write checks, signatures, digests, or AEAD authentication. |
| Backend evidence appears newer than the Lease anchor | Treat as ambiguous; fail closed until explicit recovery resolves whether the anchor missed an advance or was rolled back. |
| Lease missing but backend evidence exists | Do not silently trust storage. Require recovery input from a trusted bundle or future external anchor. |
| Lease and backend are both compromised | Online protection is exhausted; recovery needs offline or externally protected authority. |

## Bootstrap UX

The preview bootstrap path is declarative:

1. Choose a stable `repository.id`.
2. Generate and keep a stable 32-byte public `repositoryKeys.saltHex`.
3. Choose the initial keyring envelope object ID under `keyrings/`.
4. Store the unwrap authority outside the object store.
5. Deploy the gateway with Kubernetes Lease anchoring.

The salt is not secret, but it is required restore metadata. Put it in trusted
GitOps or a recovery bundle with the repository ID and anchor position. Do not
make the gateway generate an undeclared salt on first normal startup; that makes
disaster recovery dependent on a cluster Secret that may be gone.

For production-like Helm deployments, values remain declarative. The chart
should consume an existing Secret or explicit values. It should not mutate Helm
values after first run.

Startup bootstrap behavior is:

- if the configured backend prefix is empty, initialize exactly one repository
  using the supplied repository ID, supplied salt, and unwrap authority
- if the prefix already contains repository state, verify that the configured
  repository ID, salt, envelope, unwrap authority, anchor, and evidence match
- if the prefix is non-empty but cannot be verified, stop with a precise error
  instead of creating new state

## Disaster Recovery

A new cluster needs more than backend credentials:

- repository ID
- repository salt
- keyring-envelope object ID
- unwrap authority for the envelope
- trusted anchor position: sequence, checkpoint ID, and checkpoint digest

The trusted anchor position can come from a recovery bundle, audited export, or
trusted external anchor. Storage evidence can help prove what existed in the
backend, but by itself it is not enough because a malicious backend can hide or
replay evidence.

An external anchor can distribute trust outside the cluster. It should store
or sign the accepted checkpoint position, not the whole repository index. That
position already commits to the signed checkpoint chain and therefore to the
repository state reachable from it.

## Implementation Gaps Before Freeze

This document defines the preview contract. Before freezing the preview, close or
explicitly defer these gaps:

- normal startup validation compares the accepted Kubernetes Lease position with
  storage-side evidence and fails closed on mismatch
- startup validation completes storage-evidence comparison for existing prefixes
- disaster-recovery tooling exports or imports the trusted anchor position for a
  new cluster
- Helm production-preview guidance uses an operator-provided salt and encrypted
  keyring envelope without hidden first-run mutation

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

## Configuration Checklist

For a production-preview deployment:

- use `RS3_ANCHOR_MODE=kubernetes-lease`
- use `repositoryKeys.create=true` or `repositoryKeys.existingSecret` in Helm
- set a stable `repository.id`
- set a stable, operator-provided `repositoryKeys.saltHex`
- configure gateway access credentials explicitly
- configure repository retention when retention evidence is part of the trial
- run `rs3-server doctor --profile production` before exposing the gateway
- keep restore verification inputs outside the object-store trust boundary
- collect metrics and logs with path-safe labels only

Do not rely on backend state alone for production-preview evidence. Use the
configured anchor position and restore verification inputs from a trusted bundle
or separate authority.

## Readiness Bar

A preview is ready when the release evidence shows:

- default checks and S3-feature checks pass
- dependency policy checks pass or have documented exceptions
- Kopia can create, snapshot, and restore through the gateway
- Velero with Kopia uploader can restore a dynamic PVC after gateway restart
- the Velero/Postgres compatibility smoke restores verified application data
- restore verification succeeds for the checkpoint under test, including
  checkpoint evidence and keyring-envelope binding
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
