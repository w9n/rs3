# Configuration Reference

The gateway reads runtime configuration from environment variables. Command-line
flags may override selected listener settings.

## Server

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `RS3_BIND` | no | `127.0.0.1:9080` | Gateway S3 listener socket address. |
| `RS3_METRICS_BIND` | no | unset | Prometheus/OpenMetrics listener socket address. |
| `RS3_LOG_FORMAT` | no | `plain` | `plain` or `json`. |
| `RUST_LOG` | no | `info` | Standard tracing filter. |

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
| `RS3_REPOSITORY_ID` | yes | none | Stable repository derivation context. Do not reuse with the same master key for another repository. |
| `RS3_REPOSITORY_SALT_HEX` | yes | none | Stable 32-byte public salt, hex-encoded. Generate once per repository and keep with trusted config. |
| `RS3_REPOSITORY_MASTER_KEY_HEX` | yes | none | Hex-encoded repository master key with at least 32 bytes of entropy. |

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
```

The command validates runtime configuration and redacts secrets in debug output.
