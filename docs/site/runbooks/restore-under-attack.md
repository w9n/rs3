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

## 3. Select a recovery point

### Use the authenticated live registry

When the current anchor and recovery registry are available, list the bounded
set of authenticated points before reaching for a bundle:

```sh
rs3 recovery-points --limit 100 --format json
rs3 recovery-points --limit 100 --cursor '<next_cursor>' --format json
```

Review `sequence`, `publish_time_ms`, `protected_until_ms`, and `current` in the
response. The cursor is tied to the live anchor; restart the listing if the
anchor advances or the cursor is rejected. Select the exact sequence in an
isolated read-only gateway:

```sh
rs3 serve \
  --gateway-mode restore-readonly \
  --recovery-point <sequence> \
  --bind 127.0.0.1:9081
```

The selected view rechecks the live anchor and protection deadline before
serving reads. It rejects writes, deletes, multipart mutation, and copy
operations, and does not change the live anchor. Point the restore client at
the isolated S3 endpoint and copy recovered data to an isolated destination;
copying data back to production is a separately reviewed normal write. This
preview implementation does not expose S3 `versionId` history or select an
arbitrary time. Retained-provider restart, fault, and outage qualification is
still pending; if the live authority is unavailable, use the trusted-bundle
path below.

### Fall back to a trusted restore bundle

From a healthy cluster or regular operations job, export a trusted bundle and
store it outside the object-store account.

```sh
cargo run -p rs3-server --features s3,k8s -- export-restore-bundle --output rs3-restore-bundle-unsigned.cbor --format json > rs3-restore-report.json
```

The CBOR artifact is written to `--output`, which must not already exist.
JSON stdout is an inspection report, not an importable bundle. Logs go to stderr.

Export a new bundle after each successful backup window or at least before
declaring a repository trial ready for incident restore. The bundle contains
public but integrity-sensitive restore metadata, not wrapping-key material.
Store it outside the object-store account and outside the cluster whose Lease it
may need to recreate. Export prints `offline_signature_payload_hex`; sign those
canonical bytes with an offline Ed25519 recovery key. Attach and verify the resulting signature before
production import:

```sh
cargo run -p rs3-server -- attach-bundle-signature \
  --bundle-file rs3-restore-bundle-unsigned.cbor \
  --signature-hex <128-hex-character-signature> \
  --public-key ed25519:<recovery-public-key-hex> \
  --output rs3-restore-bundle.cbor
```

This command runs offline and verifies the signature before writing the signed
CBOR artifact. The signature binds the repository, salt digest, complete anchor,
recovery floor, and export time. Keep the signer private key outside the gateway.


```sh
RS3_BACKEND_ENDPOINT=s3 \
RS3_BACKEND_BUCKET=<bucket> \
RS3_BACKEND_PREFIX=<repository-prefix> \
RS3_REPOSITORY_ID=<repository-id> \
RS3_REPOSITORY_SALT_HEX=<repository-salt-hex> \
RS3_RECOVERY_PUBLIC_KEY=ed25519:<recovery-public-key-hex> \
cargo run -p rs3-server --features s3,k8s -- verify-bundle \
  --bundle-file rs3-restore-bundle.cbor \
  --min-sequence <external-floor-sequence> \
  --wrapping-key-hex-file <wrapping-key-hex-file>
```

If a fresh cluster is missing the Kubernetes Lease, import the trusted v2 anchor
after configuring the same repository ID, salt, wrapping-key source, backend,
and retention settings.

```sh
cargo run -p rs3-server --features s3,k8s -- import-anchor \
  --bundle-file rs3-restore-bundle.cbor \
  --min-sequence <external-floor-sequence>
```

`verify-bundle` does not write storage or anchors. `import-anchor` repeats
the named signed commit-chain, format-root, and keyring-envelope checks before
writing the missing anchor. Anchor import reads repository, anchor, format-root,
and recovery-signature fields only from `--bundle-file`. Production import also
requires `RS3_RECOVERY_PUBLIC_KEY` and refuses a bundle whose anchor sequence is
below the operator-supplied `--min-sequence`.
It also lists stored v03 commits and refuses to import when it sees a higher
commit sequence than the bundle names. Use `--force-rollback` only after an
explicit rollback review accepts stranding those newer commits.

### Recover an older view with a separate Lease

To recover a known earlier state, import its bundle into a separate Kubernetes
Lease and serve that anchor from a second `restore-readonly` gateway. Keep the
production Lease unchanged. This provides the logical namespace selected by
that bundle; it does not expose historical S3 object versions or select arbitrary times.

Before starting:

- Preserve a trusted, signed bundle from before the unwanted writes, with the
  matching repository ID, salt, wrapping key and recovery public key.
- Verify that every referenced commit, index, payload, format root and keyring
  version is still readable and protected through the expected restore duration.
  The configured retention duration alone does not prove this.
- Pause destructive gateway and offline maintenance for this repository. A side
  Lease does not register a protected historical root with production GC. Keep
  writes isolated as described in step 1 and monitor protection deadlines while
  renewal is paused.
- Choose an unused recovery Lease name, preferably in an isolated namespace.
  Give the import identity permission to create that Lease without permission
  to change the production Lease. The serving identity needs read access to the
  recovery Lease and backend; use read-only backend credentials where practical.
- Review a historical `--min-sequence` floor appropriate to the selected bundle.
  Do not lower the production recovery floor. The offline signature covers the
  repository ID and anchor; the outer export timestamp is informational and
  does not prove which state predates the incident.

Use the existing repository, backend, retention, authentication and key-source
configuration from the verified recovery setup. The example runs in a subshell
so the recovery anchor and mode do not replace your normal shell settings.
Replace the namespace, bundle path and historical floor before running it:

```sh
(
  set -eu
  export RS3_ANCHOR_MODE=kubernetes-lease
  export RS3_ANCHOR_NAMESPACE='<recovery-namespace>'
  export RS3_ANCHOR_NAME=rs3-incident-restore
  export RS3_GATEWAY_MODE=restore-readonly
  unset RS3_MAINTENANCE_MODE
  export RS3_ALLOW_REPOSITORY_INIT=false

  cargo run -p rs3-server --features s3,k8s -- import-anchor \
    --bundle-file '<pre-incident-bundle.cbor>' \
    --min-sequence '<reviewed-historical-floor>' \
    --force-rollback

  cargo run -p rs3-server --features s3,k8s -- serve \
    --gateway-mode restore-readonly \
    --bind 127.0.0.1:9081
)
```

The import scan looks for newer commits in the backing repository independently
of the Lease name. `--force-rollback` is therefore required when those commits
exist, even for an unused recovery Lease. It only acknowledges that older view:
import still verifies the signature, external floor and graph, and refuses to
replace a different existing anchor. Stop on any such refusal; do not delete a
Lease to bypass it.

The second gateway listens on a separate loopback port. Also choose separate
admin and metrics listeners if those are configured. For a Kubernetes deployment,
use a separate release and Service with the same repository configuration,
`gateway.mode=restore-readonly`, and the recovery `anchor.namespace` and
`anchor.name`. Never start a read-write gateway against the side Lease.

Point the restore client's S3 endpoint at this isolated view and copy the needed
data to an isolated destination. Verify restored bytes or application state as
in steps 5 and 6. Recovery does not modify the production namespace; any later
copy back is a separately reviewed normal write. Keep the production anchor and
its floor unchanged throughout.

## 4. If No Bundle Exists, Stop

When the old Lease is gone and no trusted v2 bundle exists, do not promote
backend state by listing storage. A malicious backend can hide newer valid
commits. Escalate to an operator-held authority, offline audit trail, or
external anchor record before recreating the Lease.

## 5. Verify Before Restore

Verify the trusted v2 anchor before using it for restore. The
`rs3 verify-bundle` command and the import path check the signed commit
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
