# Production Preview

The first release target is a production preview. It is meant for controlled
platform evaluation, not as a stable repository-format promise.

## Supported Shape

| Area | Preview scope |
| --- | --- |
| Primary clients | Kopia and Velero with Kopia uploader |
| Deployment | Kubernetes |
| Anchor | Kubernetes Lease |
| Backend | RustFS/local S3-compatible evidence, with live S3-compatible checks opt-in |
| Keys | Encrypted keyring envelope preferred |
| Retention | Provider retention/Object Lock capability checked where configured |

## Preview Promise

The preview should let an operator verify that:

- client-visible paths, backup names, namespaces, Kubernetes object names, and
  Kopia blob names do not appear in backend object names or unauthenticated
  metadata
- repository changes become visible only through accepted checkpoints
- stale checkpoint state is rejected against the configured external anchor
- injected backend objects are ignored unless referenced by authenticated
  repository state
- restore verification checks checkpoint chain, reachable objects,
  decryptability, keyring-envelope binding, and retention evidence
- unsafe production posture is rejected by `rs3-server doctor --profile production`

## Non-Goals

The preview does not promise:

- stable repository-format compatibility
- broad generic S3 application compatibility
- external anchoring
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
- use `repositoryKeys.source=keyring-envelope` in Helm
- configure gateway access credentials explicitly
- configure repository retention when retention evidence is part of the trial
- run `rs3-server doctor --profile production` before exposing the gateway
- keep restore verification inputs outside the object-store trust boundary
- collect metrics and logs with path-safe labels only

## Readiness Bar

A preview is ready when the release evidence shows:

- default checks and S3-feature checks pass
- dependency policy checks pass or have documented exceptions
- Kopia can create, snapshot, and restore through the gateway
- Velero with Kopia uploader can restore a dynamic PVC after gateway restart
- the Velero/Postgres compatibility smoke restores verified application data
- restore verification succeeds for the checkpoint under test
- performance evidence compares gateway behavior to the straight RustFS proxy
  baseline
- accepted leakage is documented in the security model

## Stable-Format Blockers

A stable repository-format v1 needs more than the preview:

- explicit repository-format compatibility policy
- broader provider matrix
- chaos coverage for stale backend state, anchor unavailability, backend
  injection, and retention failure
- external security review for public guarantees
