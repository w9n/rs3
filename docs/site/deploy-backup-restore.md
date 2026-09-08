# Deploy, Back Up, and Restore

Use this guide to deploy one rs3 gateway on Kubernetes, connect Kopia, and
verify an ordinary restore. Configure the repository once. Helm then runs
journaled initialization before admitting backup clients. Backups and routine
restores use the same S3 endpoint.

This is a production-preview evaluation flow. It requires an existing supported
S3 backend and Kubernetes cluster; it does not provision either. See
[Production Preview](production-preview.md) for qualification limits.

## 1. Configure the repository once

Prepare these inputs before installing:

- A pinned gateway image digest, an HTTPS S3 endpoint, and a fresh repository
  prefix in a versioned bucket with Object Lock enabled.
- A backend principal with the required permissions and lifecycle policy from
  [Retention and Object Lock](runbooks/retention-and-object-lock.md).
- Four externally managed Secrets in the gateway namespace, using the keys
  below. Keep secret values out of Helm values and release history.
- Helm and `kubectl`. For the client example, use Kopia from `nix develop`.

| Secret in this example | Required keys | Purpose |
| --- | --- | --- |
| `rs3-backend` | `access-key-id`, `secret-access-key` | Provider credentials used by the gateway. |
| `rs3-client` | `access-key-id`, `secret-access-key` | Separate S3 credentials accepted from backup clients. |
| `rs3-admin` | `bearer-token` | Admin health and status authentication; at least 16 bytes. |
| `rs3-keys` | `salt-hex`, `wrapping-key-hex` | Stable public salt and high-entropy wrapping key, each 32 bytes encoded as 64 hex characters. Optional `wrapping-key-id` defaults to `wrap-v1`. |

Generate the salt and wrapping key once using your secret-management process.
Keep the key Secret, repository configuration, and trusted recovery material
outside the cluster being protected. Provider credentials alone cannot restore
an rs3 repository. Kopia also needs its own repository password.

Save the following as `values.backup.yaml`, replacing the image and backend
values. The example uses 30-day compliance retention with the existing recovery
and maintenance presets. Compliance protection cannot be shortened before its
deadline. For governance, follow the explicit principal-review requirements in
[Configuration](reference/configuration.md#provider-conformance-evidence).

```yaml
image:
  repository: <gateway-image-repository>
  digest: sha256:<64-hex-image-digest>
backend:
  endpoint: https://<s3-endpoint>
  bucket: <versioned-object-lock-bucket>
  prefix: <fresh-repository-prefix>
  region: us-east-1
backendCredentials:
  existingSecret: rs3-backend
credentials:
  existingSecret: rs3-client
admin:
  existingTokenSecret: rs3-admin
repositoryKeys:
  existingSecret: rs3-keys
repository:
  id: backups
  allowInit: false
  retention:
    mode: compliance
    days: 30
publicBucket: backup
anchor:
  name: backup-anchor
bootstrap:
  enabled: true
```

The chart defaults to one read-write gateway, a required Kubernetes writer
fence, automatic maintenance, and a 30-day recovery window. Leave those defaults
in place. The chart creates the Lease RBAC and a retained bootstrap journal
Secret in the release namespace. No recovery signing key or manually transferred
provider report is needed for this initialization path.

## 2. Deploy and wait for verified initialization

From the repository checkout, with the Secrets already available in namespace
`backup`, run:

```sh
helm upgrade --install backup charts/rs3-gateway \
  --namespace backup --create-namespace \
  -f values.backup.yaml --wait --timeout 35m
```

The initialization Job qualifies the provider, publishes the repository under
the writer Lease, and verifies a real payload restore from fresh caches. It
then logically removes the synthetic fixture. The gateway's init container
waits for the completed journal and matching evidence before serving traffic.
A successful Helm wait means the deployment passed its readiness checks.

If initialization stops, inspect the Job and its logs:

```sh
kubectl -n backup get jobs -l app.kubernetes.io/instance=backup
kubectl -n backup logs job/<init-job-name>
```

Correct the reported configuration or provider issue and repeat the same Helm
command. Keep the journal Secret and Lease. Do not reset the journal, change the
repository salt, or enable serving-time initialization to retry. A completed
journal with a missing anchor requires the recovery procedure below.

Keep `bootstrap.enabled=true` for ordinary upgrades. Existing journaled progress
is reused; implementation or policy changes may require fresh qualification.
[Bootstrap operations](operations.md#keys-and-bootstrap) explains retry limits
and protected probe objects that may remain after qualification.

## 3. Connect Kopia and make a backup

For a local evaluation, forward the cluster-internal gateway port in a separate
terminal. The HTTP connection below stays on the local port-forward; configure
TLS when exposing the gateway beyond this tunnel.

```sh
kubectl -n backup port-forward service/backup-rs3-gateway 9080:9080
```

In your client shell, load the credentials from `rs3-client` into
`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` using your normal secret source.
Set `KOPIA_PASSWORD` to a separate Kopia repository password and preserve it.
Use a dedicated local Kopia configuration:

```sh
export KOPIA_CONFIG_PATH="$PWD/kopia-rs3.config"

# Create only once, on the new Kopia prefix inside the public gateway bucket.
kopia repository create s3 \
  --bucket backup --endpoint 127.0.0.1:9080 --disable-tls \
  --region us-east-1 --prefix kopia/

mkdir -p source
printf 'restore verification\n' > source/proof.txt
kopia snapshot create "$PWD/source"
```

For an existing Kopia repository or a second client, use
`kopia repository connect s3` with the same S3 options and Kopia password instead
of `repository create`. For later backups, run `snapshot create` again. The
public bucket is `backup`; clients never use the encrypted provider bucket.

## 4. Restore and compare ordinary backup data

Keep the gateway in read-write mode. Restore the latest snapshot of this source
to a new directory, then compare it with the source:

```sh
kopia restore "$PWD/source" "$PWD/restored"
diff -r source restored
```

Success means Kopia exits successfully and `diff` reports no differences.
For real workloads, verify application-specific integrity as well. This uses
the same `repository create`, `snapshot create`, and `restore` path exercised
by the Kopia integration harness.

Velero likewise uses the normal gateway endpoint for routine restore. Keep its
backup storage location writable so it can publish restore-result artifacts.
The strict read-only incident procedure has a different status contract; do not
apply it to an ordinary restore merely because data is being read.

## Recover an earlier gateway state

Use this path when the current trusted Lease and authenticated recovery registry
remain available. First list accepted points using the running gateway's
existing configuration:

```sh
kubectl -n backup exec deployment/backup-rs3-gateway -- \
  /usr/local/bin/rs3-server recovery-points --limit 100 --format json
```

Choose a still-protected exact sequence after the desired backup completed.
A gateway point represents accepted S3 state, not necessarily a complete Kopia
snapshot. Create `values.restore.yaml` as a small overlay:

```yaml
bootstrap:
  enabled: false
  existingJournalSecret: <original-bootstrap-journal-secret>
gateway:
  mode: restore-readonly
maintenance:
  mode: ""
recovery:
  point: "<accepted-sequence>"
```

Get the journal name from the original initialization Job's
`RS3_INIT_JOURNAL_SECRET` environment entry. Keep the original journal; the
explicit reference preserves its projected provider evidence when bootstrap is
disabled. The base values already reference the existing key and credential
Secrets and `backup-anchor`, so this reader shares that exact live authority.
An externally supplied evidence ConfigMap retains precedence if configured.

Deploy a separate reader in the same namespace:

```sh
helm upgrade --install backup-restore charts/rs3-gateway \
  --namespace backup -f values.backup.yaml -f values.restore.yaml \
  --wait --timeout 10m
kubectl -n backup port-forward service/backup-restore-rs3-gateway 9082:9080
```

The quoted sequence is passed to `serve --recovery-point`. The reader checks the
live anchor and protection deadline and rejects mutation; it does not rewind
the writer's anchor. Use a separate client configuration for the recovery
endpoint and copy out to an isolated destination. Historical S3 copyout with
AWS CLI/rclone is qualified locally; see
[Restore Under Attack](runbooks/restore-under-attack.md#use-the-authenticated-live-registry)
for those boundaries and the Velero read-only caveat.

With AWS CLI installed and the same gateway client credentials loaded, copy
historical S3 objects out through the reader:

```sh
AWS_DEFAULT_REGION=us-east-1 aws --endpoint-url http://127.0.0.1:9082 \
  s3 cp s3://backup/kopia/ ./historical-kopia-objects/ --recursive
```

These are the Kopia repository objects exposed by the selected gateway state;
Kopia is still needed to decode application backups. This command writes only
to the local destination. Copying recovered data back to production is a
separate normal write.

## Recover after loss of the cluster or anchor

The historical reader above needs the live trusted anchor. When that authority
is lost, follow the [trusted-bundle recovery procedure](runbooks/restore-under-attack.md#fall-back-to-a-trusted-restore-bundle):
preserve an exported bundle off-cluster, sign it with the independent offline
recovery key, verify it against an external minimum sequence, and explicitly
import the verified anchor before serving read-only restores. Preserve the
wrapping key and Kopia password separately. Export and verify recovery material
after backup windows; a bundle is not a permanent retention pin.

Do not rerun initialization against populated storage to recover a missing
anchor. The bootstrap journal records progress and cannot replace lost trust.
