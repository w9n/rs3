# Configuration Reference

The gateway reads runtime configuration from environment variables. Command-line
flags may override selected listener and gateway-mode settings.

## Server

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `RS3_BIND` | no | `127.0.0.1:9080` | Gateway S3 listener socket address. |
| `RS3_GATEWAY_MODE` | no | `read-write` | `read-write` accepts checkpointed mutations. `restore-readonly` serves restore reads, rejects supported mutations, refuses bootstrap, and requires an accepted anchor. |
| `RS3_METRICS_BIND` | no | unset | Prometheus/OpenMetrics listener socket address. |
| `RS3_LOG_FORMAT` | no | `plain` | `plain` or `json`. |
| `RUST_LOG` | no | `info` | Standard tracing filter. |
| `RS3_RECOVERY_MAX_CHECKPOINT_AGE_SECONDS` | for `recover-anchor` | none | Maximum signed checkpoint age accepted by explicit anchor recovery. |

## Public S3 Surface

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `RS3_PUBLIC_BUCKET` | yes | none | Client-visible bucket served by this gateway. |
| `RS3_STATIC_ACCESS_KEY_ID` | for serving | none | Static access key accepted by the gateway. Must be paired with the secret. |
| `RS3_STATIC_SECRET_ACCESS_KEY` | for serving | none | Static secret key accepted by the gateway. Must be paired with the access key. |

## Backend Storage

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `RS3_BACKEND_ENDPOINT` | yes | none | Backend endpoint. Use `file://<path>` for the local filesystem backend, `memory` for tests, `s3` for default AWS S3, or `http://` / `https://` for S3-compatible stores when the S3 feature is enabled. |
| `RS3_BACKEND_BUCKET` | yes | none | Backend bucket or local bucket-equivalent repository root. |
| `RS3_BACKEND_PREFIX` | no | none | Optional backend prefix for repository-owned objects. |

## Anchor

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `RS3_ANCHOR_MODE` | yes | none | `memory` or `kubernetes-lease`. Kubernetes mode requires the k8s-enabled gateway path. |
| `RS3_ALLOW_MEMORY_ANCHOR` | only for memory | `false` | Must be `true` to permit the local memory anchor. |
| `RS3_ANCHOR_NAMESPACE` | for Kubernetes | none | Kubernetes namespace for the Lease anchor. |
| `RS3_ANCHOR_NAME` | for Kubernetes | none | Kubernetes Lease name. |
| `RS3_ANCHOR_FIELD_MANAGER` | no | `rs3-server` | Server-side apply field manager. |

Helm defaults to `anchor.mode=kubernetes-lease`. If `rbac.create=false`, set
`rbac.existing=true` to document that equivalent Lease permissions are provided
outside the chart. If `serviceAccount.create=false`, set `serviceAccount.name`.

## Repository Keys

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `RS3_REPOSITORY_ID` | yes | none | Stable repository context. Keep it with trusted restore metadata. |
| `RS3_REPOSITORY_SALT_HEX` | yes | none | Stable operator-provided 32-byte public salt, hex-encoded. Generate once per repository and keep with trusted public restore metadata. |
| `RS3_KEYRING_ENVELOPE_OBJECT_ID` | no | unset | Bootstrap or recovery override for a specific encrypted keyring envelope object. Existing anchored repositories use the envelope reference bound into the signed checkpoint. |
| `RS3_KEYRING_WRAPPING_KEY_ID` | no | `wrap-v1` | Operator-visible wrapping key identifier expected by the envelope. |
| `RS3_KEYRING_WRAPPING_KEY_HEX` | yes | none | Hex-encoded high-entropy wrapping key used to open or initialize the envelope. KMS/HSM/Vault integration should replace this for hardened deployments. |

For an anchored repository, startup reads the anchor, reads the accepted
checkpoint, and opens the checkpoint-bound envelope. It does not list S3 and
guess a latest envelope.

For a first empty repository, startup creates a random purpose-specific keyring
and stores the encrypted envelope under the default counted `keyrings/` object
name. If `RS3_KEYRING_ENVELOPE_OBJECT_ID` is set, that object is used as an
explicit bootstrap override. A missing anchor with committed repository objects
is a recovery error, not an invitation to pick a backend checkpoint.

Minimal first-run settings:

```sh
RS3_REPOSITORY_ID=<id>
RS3_REPOSITORY_SALT_HEX=<salt-hex>
RS3_KEYRING_WRAPPING_KEY_HEX=<wrapping-key-hex>
```

For production-like deployments, set `RS3_REPOSITORY_SALT_HEX` explicitly and
keep the same value with trusted restore metadata. The salt is public, but a new
cluster needs it to open the same repository context.

## Gateway Mode

`read-write` is the normal backup mode. It may initialize a first empty
repository, publish committed checkpoints, and advance the configured anchor.
Run only one read-write gateway for a repository.

`restore-readonly` is the incident and disaster-recovery restore mode. It opens
only from an existing accepted anchor, does not initialize a missing keyring
envelope, and rejects supported repository mutations such as PUT, DELETE, and
object legal-hold changes. Use it after explicit anchor recovery when a new
cluster starts without the old Kubernetes Lease. Pair it with Velero
`BackupStorageLocation` read-only mode, Kopia read-only repository settings
where practical, and backend credentials that cannot write.

## Repository Behavior

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `RS3_PAYLOAD_SEGMENT_SIZE_BYTES` | no | `512` | Plaintext bytes per independently encrypted payload segment. |
| `RS3_COMMIT_MAX_BATCH_ITEMS` | no | `64` | Maximum staged writes covered by one checkpoint batch. |
| `RS3_COMMIT_MAX_BATCH_DELAY_MS` | no | `10` | Maximum delay before publishing a partial commit batch. |
| `RS3_COMMIT_MAX_PENDING_ITEMS` | no | batch item limit | Maximum writes waiting for commit before backpressure. |
| `RS3_REPOSITORY_RETENTION_MODE` | no | unset | `governance` or `compliance` when repository retention is enabled. |
| `RS3_REPOSITORY_RETENTION_DAYS` | with retention mode | unset | Positive retention duration in days. |

## Validation

Use:

```sh
cargo run -p rs3-server -- doctor
cargo run -p rs3-server -- doctor --profile production
```

The local profile validates runtime configuration and redacts secrets in debug
output. The production profile also rejects memory anchors,
retention-unsupported local backends, missing gateway credentials, and missing
repository retention for mutation-capable serving.

## Helm Repository Keys

The chart always uses the encrypted keyring-envelope model. Provide the
repository key Secret with `repositoryKeys.create=true`, or reference one with
`repositoryKeys.existingSecret`.

| Secret key | Meaning |
| --- | --- |
| `salt-hex` | Stable public repository salt. |
| `envelope-object-id` | Optional bootstrap or recovery override for the encrypted keyring envelope. |
| `wrapping-key-id` | Optional operator-visible wrapping key identifier; defaults to `wrap-v1` when absent. |
| `wrapping-key-hex` | High-entropy wrapping key material for the preview. |

Helm should consume the configured repository ID, salt, and unwrap settings from
values or an existing Secret. The gateway writes the encrypted envelope object
on first empty-repository startup; chart state does not need to mutate after
that first run.
