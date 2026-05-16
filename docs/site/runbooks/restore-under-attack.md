# Restore Under Attack

Do not repair repository state automatically during an incident. First preserve
evidence, then choose the trusted v2 anchor, then restore with the narrowest
credentials practical.

## Assume

- object storage can delay, delete, replay, or hide objects
- the Kubernetes anchor can be stale or maliciously advanced
- a backup pod may have written bad new state
- old retained versions may exist even when latest listings mislead
- in-cluster logs may be incomplete

## Required Inputs

Before serving restore traffic, identify or recover:

- repository ID
- public repository salt
- wrapping-key source for the keyring envelope
- accepted v2 anchor sequence, commit key, commit object version ID when
  available, commit body digest, signing key ID, and format-root reference
- format-bound keyring-envelope reference
- backend endpoint, bucket, and prefix
- object-store audit events where available

Backend credentials alone are not sufficient recovery material.

## 1. Stop New Writes

Stop or isolate the read-write gateway before investigating.

```sh
kubectl -n <gateway-namespace> scale deployment/<gateway-deployment> --replicas=0
```

If the deployment must remain online for restore traffic, switch it to
`restore-readonly` before exposing it to restore clients.

```sh
helm upgrade <release> charts/rs3-gateway \
  --namespace <gateway-namespace> \
  --reuse-values \
  --set-string gateway.mode=restore-readonly
```

Do not switch back to `read-write` until the trusted commit chain and anchor state
are understood.

## 2. Preserve Evidence

Capture the anchor, gateway logs, Velero resources, and storage evidence before
cleanup.

```sh
kubectl -n <anchor-namespace> get lease <anchor-name> -o yaml > anchor.yaml
kubectl -n <gateway-namespace> logs deployment/<gateway-deployment> --since=24h > gateway.log
kubectl -n velero get backups,restores,podvolumebackups,podvolumerestores -o yaml > velero.yaml
```

Preserve object-store audit logs outside the affected account when available.
Do not include plaintext paths or Kubernetes secrets in shared artifacts.

## 3. Prefer a Trusted Restore Bundle

From a healthy cluster or regular operations job, export a trusted bundle and
store it outside the object-store account.

```sh
cargo run -p rs3-server -- export-restore-bundle --format json > rs3-restore-bundle.json
```

The bundle contains public restore metadata, not wrapping-key material. Verify
the preserved bundle before anchor import:

```sh
cargo run -p xtask --features s3 -- v2 verify-bundle \
  --bundle-file rs3-restore-bundle.json \
  --repository-salt-hex <repository-salt-hex> \
  --wrapping-key-hex-file <wrapping-key-hex-file> \
  --backend s3 \
  --s3-bucket <bucket> \
  --s3-prefix <repository-prefix>
```

If a fresh cluster is missing the Kubernetes Lease, import the trusted v2 anchor
after configuring the same repository ID, salt, wrapping-key source, backend,
and retention settings.

```sh
cargo run -p rs3-server -- import-v2-anchor --bundle-file rs3-restore-bundle.json
```

If the incident workflow cannot pass the bundle file, import the same trusted
anchor with explicit fields:

```sh
cargo run -p rs3-server -- import-v2-anchor \
  --anchor-sequence <bundle-anchor-sequence> \
  --anchor-commit-key <bundle-anchor-commit-key> \
  --anchor-version-id <bundle-anchor-version-id> \
  --anchor-body-digest <bundle-anchor-body-digest> \
  --signing-key-id <bundle-signing-key-id> \
  --format-generation <bundle-format-generation> \
  --format-digest <bundle-format-digest> \
  --format-object-id <bundle-format-object-id> \
  --format-version-id <bundle-format-version-id> \
  --weak-subjectivity-floor-sequence <bundle-floor-sequence>
```

`verify-bundle` does not write storage or anchors. `import-v2-anchor` repeats
the named signed commit-chain, format-root, and keyring-envelope checks before
writing the missing anchor. Do not mix `--bundle-file` and explicit anchor
fields. Omit version IDs only for a trusted bundle that does not contain them;
retained/Object Lock repositories should contain them.

## 4. If No Bundle Exists, Stop

When the old Lease is gone and no trusted v2 bundle exists, do not promote
backend state by listing storage. A malicious backend can hide newer valid
commits. Escalate to an operator-held authority, offline audit trail, or future
HSM/KMS-backed anchor record before recreating the Lease.

## 5. Verify Before Restore

Verify the trusted v2 anchor before using it for restore. The
`xtask v2 verify-bundle` command and the import path check the signed commit
chain, format root, and keyring envelope. After the gateway starts from the
recovered anchor, run the restore client and verify restored application bytes
before declaring the incident restore successful.

## 6. Restore Read-Only

Patch Velero's backup storage location to read-only and serve restore traffic
through `restore-readonly`.

```sh
kubectl -n velero patch backupstoragelocations.velero.io/default \
  --type=merge \
  -p '{"spec":{"accessMode":"ReadOnly"}}'
```

```sh
helm upgrade <release> charts/rs3-gateway \
  --namespace <gateway-namespace> \
  --reuse-values \
  --set-string gateway.mode=restore-readonly
```

Run the restore into an isolated target where practical.

```sh
velero --namespace velero restore create <restore-name> \
  --from-backup <backup-name> \
  --wait
```

Velero may report `PartiallyFailed` if the only failure is denied upload of
restore result artifacts after data restore. Accept that status only when all of
the following are true:

- Velero logs show restore-result artifact upload attempts denied by
  `restore-readonly`
- pod-volume restore completed
- restored bytes or application checks verify
- gateway/backend counters show no writes during restore

Any other restore error is a failed restore.

## Decision Table

| Observation | Action |
| --- | --- |
| Signature fails | Reject commit chain. |
| Parent chain broken | Reject unless it is a trusted snapshot root. |
| Sequence lower than trusted anchor | Treat as rollback. |
| Digest differs from anchor | Fail closed and investigate. |
| Anchor unavailable | Do not accept newer-looking storage state silently. |
| Backend contains commits newer than anchor | Investigate anchor rollback or missed anchor advance. |
| Backend lacks the anchored commit | Treat as unavailable or tampered. |
| Anchor missing but backend objects exist | Require a trusted recovery bundle; do not trust storage alone. |

## Break Glass

Break-glass restore, if implemented, must require:

- explicit operator command
- selected commit key and sequence
- audit reason or ticket
- read-only backend credentials where possible
- no automatic anchor repair

Its job is data recovery, not making ambiguous state look healthy.
