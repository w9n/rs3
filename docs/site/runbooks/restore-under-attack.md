# Restore Under Attack

Do not repair repository state automatically during an incident. First preserve
evidence, then choose the trusted checkpoint, then restore with the narrowest
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
- accepted checkpoint sequence, checkpoint ID, and checkpoint digest
- checkpoint-bound keyring-envelope reference
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

Do not switch back to `read-write` until the trusted checkpoint and anchor state
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

The bundle contains public restore metadata, not wrapping-key material. If a
fresh cluster is missing the Kubernetes Lease, import the trusted checkpoint
position after configuring the same repository ID, salt, wrapping-key source, and
backend.

```sh
cargo run -p rs3-server -- import-anchor \
  --checkpoint-sequence <bundle-sequence> \
  --checkpoint-id <bundle-checkpoint-id> \
  --checkpoint-digest <bundle-checkpoint-digest>
```

`import-anchor` verifies the checkpoint chain, checkpoint evidence, keyring
envelope, and restore-critical objects before writing the missing anchor.

## 4. If No Bundle Exists, Use Bounded Recovery

When the old Lease is gone and no trusted bundle exists, storage evidence can
help but is not a perfect latest-state authority. A malicious backend can hide
newer valid evidence.

Use explicit bounded recovery:

```sh
cargo run -p rs3-server -- recover-anchor \
  --max-checkpoint-age-seconds <freshness-bound> \
  --apply-if-missing \
  --format text
```

Choose the freshness bound from the recovery objective. For example, `86400`
means the recovered signed checkpoint must be no older than 24 hours. Do not use
an unbounded scan as a substitute for a trusted anchor.

## 5. Verify Before Restore

Verify the chosen checkpoint against the backend before using it for restore.

```sh
cargo run -p xtask --bin xtask --features s3 -- restore verify \
  --repository-id <repository-id> \
  --repository-salt-hex <salt-hex> \
  --keyring-envelope-object-id <envelope-object-id> \
  --wrapping-key-id <wrapping-key-id> \
  --wrapping-key-hex-file <wrapping-key-file> \
  --checkpoint-sequence <checkpoint-sequence> \
  --checkpoint-id <checkpoint-id> \
  --checkpoint-digest <checkpoint-digest> \
  --backend s3 \
  --s3-bucket <bucket> \
  --require-provider-delete-protection \
  --format json
```

Reject the checkpoint if verification reports signature failure, broken parent
chain, missing checkpoint evidence, keyring-envelope mismatch, payload
decryptability failure, or missing required provider delete protection.

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
| Signature fails | Reject checkpoint. |
| Parent chain broken | Reject unless it is a trusted compaction root. |
| Sequence lower than trusted anchor | Treat as rollback. |
| Digest differs from anchor | Fail closed and investigate. |
| Anchor unavailable | Do not accept newer-looking storage state silently. |
| Evidence higher than anchor | Investigate anchor rollback or missed anchor advance. |
| Evidence lower than anchor | Investigate failed evidence write or backend replay. |
| Anchor missing but evidence exists | Require recovery bundle or bounded recovery; do not trust storage alone. |

## Break Glass

Break-glass restore, if implemented, must require:

- explicit operator command
- selected checkpoint ID and sequence
- audit reason or ticket
- read-only backend credentials where possible
- no automatic anchor repair

Its job is data recovery, not making ambiguous state look healthy.
