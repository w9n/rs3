# Configuration Reference

The gateway reads runtime configuration from environment variables. Command-line
flags may override selected listener and gateway-mode settings.

## Server

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `RS3_BIND` | no | `127.0.0.1:9080` | Gateway S3 listener socket address. |
| `RS3_GATEWAY_MODE` | no | `read-write` | `read-write` accepts committed mutations. `restore-readonly` serves restore reads, rejects supported mutations, refuses bootstrap, and requires an accepted anchor. |
| `RS3_METRICS_BIND` | no | unset | Prometheus/OpenMetrics listener socket address. |
| `RS3_ADMIN_BIND` | no | unset | Separate gateway admin listener for path-redacted facts. |
| `RS3_ADMIN_BEARER_TOKEN` | with admin listener | none | Bearer token for admin routes. Must be at least 16 bytes and separate from backup-client S3 credentials. |
| `RS3_ADMIN_PROFILE` | no | `production` | Admin status profile: `local` or `production`. |
| `RS3_RECOVERY_PUBLIC_KEY` | production recovery | none | `ed25519:<hex-public-key>` used to verify signed v2 restore bundles during `import-v2-anchor` and `xtask v2 verify-bundle`. |
| `RS3_LOG_FORMAT` | no | `plain` | `plain` or `json`. |
| `RUST_LOG` | no | `info` | Standard tracing filter. |

`export-restore-bundle`, `import-v2-anchor`, and `write-index-snapshot` use the
same repository, backend, anchor, and keyring settings as `serve`. The exported
bundle contains public but integrity-sensitive restore metadata; keep
wrapping-key material in the configured secret source. Prefer
`import-v2-anchor --bundle-file <json>` over manually transcribing anchor fields
from the exported bundle. Production recovery requires an external
`--min-sequence` floor and `RS3_RECOVERY_PUBLIC_KEY`. `export-restore-bundle`
prints `offline_signature_payload_hex`; sign those canonical bytes offline with
the matching Ed25519 recovery key and store the hex signature in
`offline_signature` before import. `import-v2-anchor` also refuses when stored
commit keys contain a sequence higher than the imported anchor; `--force-rollback`
is an explicit rollback override for that condition.
Machine-readable command output is written to stdout; tracing logs are written
to stderr for both `plain` and `json` log formats.

The core server library exposes path-redacted admin reports for operator
tooling. `GET /admin/posture` is the cheap report for frequent polling: it shows
runtime posture, selected provider profile, last persisted provider-conformance
evidence, and profile findings without verifying repository state. `GET
/admin/status` adds commit trust and maintenance verification and may touch the
backend. Both reports avoid configured bucket names, backend prefixes,
repository IDs, client object paths, and secret values. The reports are preview
fact contracts; workflow APIs need a separate authorization, audit, approval,
and orchestration model from the gateway data plane.

When `RS3_ADMIN_BIND` is set, `rs3-server serve` exposes `GET /admin/posture`
and `GET /admin/status` on that separate listener. `GET /healthz` is
unauthenticated; admin routes require `Authorization: Bearer <token>`. Bind the
admin listener only to localhost, cluster-internal addresses, or a protected
internal ingress.

## Console

`rs3-console` is a read-only single-gateway UI. It keeps the gateway admin
bearer token server-side and exposes `GET /api/posture` and `GET /api/status`
to the browser after console bearer authentication.

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `RS3_CONSOLE_BIND` | no | `127.0.0.1:9083` | Console listener socket address. |
| `RS3_CONSOLE_BEARER_TOKEN` | yes | none | Bearer token for console API routes. Must be at least 16 bytes. |
| `RS3_GATEWAY_ADMIN_URL` | yes | none | Gateway admin origin, for example `http://127.0.0.1:9082`. The preview client supports HTTP origins; run it over loopback or a protected cluster-local path. |
| `RS3_GATEWAY_ADMIN_BEARER_TOKEN` | yes | none | Bearer token used by the console to call the gateway admin listener. This token is never sent to the browser. |

Console routes:

| Route | Authentication | Purpose |
| --- | --- | --- |
| `GET /healthz` | none | Console health check. |
| `GET /`, `/ui/*` | none | Static browser UI. |
| `GET /api/posture` | console bearer token | Fetch and return the gateway's cheap path-redacted admin posture report. |
| `GET /api/status` | console bearer token | Fetch and return the gateway's path-redacted admin status report. |

The console is not a repository browser and has no mutating recovery, key
rotation, deployment, or storage-management API.

## Public S3 Surface

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `RS3_PUBLIC_BUCKET` | yes | none | Client-visible bucket served by this gateway. |
| `RS3_STATIC_ACCESS_KEY_ID` | for serving | none | Static access key accepted by the gateway. Must be paired with the secret. |
| `RS3_STATIC_SECRET_ACCESS_KEY` | for serving | none | Static secret key accepted by the gateway. Must be paired with the access key. |

## Data Plane Hardening

These limits are enforced inside the gateway process. Keep ingress or service
mesh limits aligned with them so rejected traffic is shed before it consumes
cluster resources.

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `RS3_MAX_PUT_OBJECT_BYTES` | no | `5368709120` | Maximum accepted single `PutObject` body. Requests with larger declared bodies fail before a repository commit is staged. |
| `RS3_BUFFERED_PUT_OBJECT_BYTES` | no | `67108864` | Largest `PutObject` body buffered in process memory as a single repository write. Bodies above this threshold use backend multipart upload when supported; unknown-length bodies switch to streaming after the threshold is crossed. |
| `RS3_BACKEND_MULTIPART_PART_BYTES` | no | `16777216` | Backend multipart part size for large `PutObject` writes. S3-compatible backends require at least `5242880` bytes. |
| `RS3_STREAM_READ_STALL_TIMEOUT_SECS` | no | `30` | Maximum idle time between chunks while the gateway streams a large `PutObject` request body into a backend multipart commit. Stalled streams fail as incomplete request bodies. |
| `RS3_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES` | no | `536870912` | Admission budget for request body bytes held by in-flight upload operations. Buffered uploads reserve their full collected body; streaming uploads reserve a bounded working set, not a hard RSS cap for every HTTP chunk. Excess uploads fail with S3 `SlowDown`. |
| `RS3_MAX_IN_FLIGHT_DOWNLOAD_BODY_BYTES` | no | `536870912` | Admission budget for response body bytes held by in-flight download operations. Full-object and ranged `GetObject` responses reserve their resolved response length until the response body is dropped. Excess downloads fail with S3 `SlowDown`. |
| `RS3_MAX_CONCURRENT_CONNECTIONS` | no | `1024` | Maximum simultaneously open S3 listener connections accepted by the process. Additional connections are dropped. |
| `RS3_MAX_CONCURRENT_REQUESTS` | no | `256` | Maximum concurrently executing S3 operations. Additional operations fail with S3 `SlowDown`. |
| `RS3_REQUEST_RATE_LIMIT_PER_SECOND` | no | `1024` | Per-process S3 operation admission rate. Bursts up to one second of capacity are allowed; excess operations fail with S3 `SlowDown`. |

## Backend Storage

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `RS3_BACKEND_ENDPOINT` | yes | none | Backend endpoint. Use `file://<path>` for the local filesystem backend, `memory` for tests, `s3` for default AWS S3, or `http://` / `https://` for S3-compatible stores when the S3 feature is enabled. |
| `RS3_BACKEND_BUCKET` | yes | none | Backend bucket or local bucket-equivalent repository root. |
| `RS3_BACKEND_PREFIX` | no | none | Optional backend prefix for repository-owned objects. |

## Provider Conformance Evidence

Run `rs3 check-v2-provider --format json` against the selected backend/profile
and preserve the JSON report outside the backend. Mount that report into the
gateway and configure the path below so admin reports can show last-known
provider evidence without running live probes from status.

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `RS3_PROVIDER_CONFORMANCE_REPORT_FILE` | no | unset | Local path to a JSON report emitted by `rs3 check-v2-provider --format json`. The path itself is not reported. |
| `RS3_PROVIDER_CONFORMANCE_MAX_AGE_SECONDS` | no | `604800` | Maximum report age before admin reports mark provider evidence `stale`. |

## Anchor

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `RS3_ANCHOR_MODE` | yes | none | `memory` or `kubernetes-lease`. Kubernetes mode requires the k8s-enabled gateway path. |
| `RS3_ALLOW_MEMORY_ANCHOR` | only for memory | `false` | Must be `true` to permit the local memory anchor. |
| `RS3_ANCHOR_NAMESPACE` | for Kubernetes | none | Kubernetes namespace for the Lease anchor. |
| `RS3_ANCHOR_NAME` | for Kubernetes | none | Kubernetes Lease name. |
| `RS3_ANCHOR_FIELD_MANAGER` | no | `rs3-server` | Server-side apply field manager. |
| `RS3_WRITER_GUARD` | no | `required` with Kubernetes anchors, otherwise `off` | `required` or `off`. In `read-write` mode with Kubernetes anchors, `required` acquires `<RS3_ANCHOR_NAME>-writer` before serving and renews it while running. |

Helm defaults to `anchor.mode=kubernetes-lease`. If `rbac.create=false`, set
`rbac.existing=true` to document that equivalent Lease permissions are provided
outside the chart. If `serviceAccount.create=false`, set `serviceAccount.name`.

## Repository Keys

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `RS3_ALLOW_REPOSITORY_INIT` | no | `false` | Allows first-run initialization when the configured anchor is missing. Set only for deliberate new-repository bootstrap on a fresh prefix; leave unset for existing repositories and use anchor import for recovery. |
| `RS3_REPOSITORY_ID` | yes | none | Stable repository context. Keep it with trusted restore metadata. |
| `RS3_REPOSITORY_SALT_HEX` | yes | none | Stable operator-provided 32-byte public salt, hex-encoded. Generate once per repository and keep with trusted public restore metadata. |
| `RS3_KEYRING_ENVELOPE_OBJECT_ID` | no | unset | Bootstrap or recovery override for a specific encrypted keyring envelope object. Existing anchored repositories use the envelope reference bound through the v2 format root. |
| `RS3_KEYRING_WRAPPING_KEY_ID` | no | `wrap-v1` | Operator-visible wrapping key identifier expected by the envelope. |
| `RS3_KEYRING_WRAPPING_KEY_HEX` | yes | none | Hex-encoded high-entropy wrapping key used to open or initialize the envelope. KMS/HSM/Vault integration should replace this for hardened deployments. |

For an anchored repository, startup reads the anchor, verifies the accepted
commit chain and format root, and opens the format-bound envelope. It does not
list S3 and guess a latest envelope.

The gateway no longer exposes a repository-format selector. Legacy
`RS3_REPOSITORY_FORMAT=v2-preview` is accepted for migration friendliness; any
other value is rejected.

For a first empty repository, startup creates a random purpose-specific keyring
only when `RS3_ALLOW_REPOSITORY_INIT=true`, then stores the encrypted envelope
under the default counted `keyrings/` object name. If
`RS3_KEYRING_ENVELOPE_OBJECT_ID` is set, that object is used as an explicit
bootstrap override. A missing anchor with committed repository objects is a
recovery error, not an invitation to pick backend state.

Before creating the v2 format root, startup performs a defensive repository
inventory and rejects foreign objects. Retained-version object-lock profiles
inventory object versions as well as current objects so data hidden behind
provider versioning still blocks bootstrap. This LIST is a preflight guard, not
the serialization boundary: S3-compatible listings can be stale, and the first
commit's anchor compare-and-advance is the final bootstrap safety check.

Minimal first-run settings:

```sh
RS3_REPOSITORY_ID=<id>
RS3_ALLOW_REPOSITORY_INIT=true
RS3_REPOSITORY_SALT_HEX=<salt-hex>
RS3_KEYRING_WRAPPING_KEY_HEX=<wrapping-key-hex>
```

For production-like deployments, set `RS3_REPOSITORY_SALT_HEX` explicitly and
keep the same value with trusted restore metadata. The salt is public, but a new
cluster needs it to open the same repository context.

## Gateway Mode

`read-write` is the normal backup and routine-restore mode. It may initialize a
first empty repository, publish signed commits, and advance the configured
anchor. Run only one read-write gateway for a repository. Velero restore result
artifacts are repository writes in this mode and should be committed like other
accepted mutations.

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
| `RS3_PAYLOAD_SEGMENT_SIZE_BYTES` | no | adaptive, `512` B floor | Plaintext bytes per independently encrypted payload segment. Leave unset to use adaptive per-object defaults: 512 B for small objects, 8 KiB for medium objects, and 64 KiB for large objects. Set it to force a fixed segment size. |
| `RS3_DECRYPTED_SEGMENT_CACHE_MAX_BYTES` | no | `268435456` | Maximum plaintext bytes retained in the process-local decrypted segment LRU cache. Set to `0` to disable the cache. |
| `RS3_COMMIT_MAX_BATCH_ITEMS` | no | `64` | Maximum staged writes covered by one commit batch. |
| `RS3_COMMIT_MAX_BATCH_DELAY_MS` | no | `25` | Maximum delay before publishing a partial commit batch. |
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
retention-unsupported local backends, plaintext S3-compatible backend
endpoints, missing gateway credentials, and missing repository retention for
mutation-capable serving.

## Helm Repository Keys

The chart always uses the encrypted keyring-envelope model. Provide the
repository key Secret with `repositoryKeys.create=true`, or reference one with
`repositoryKeys.existingSecret`.

For `gateway.mode=read-write`, the chart defaults to
`updateStrategy.type=Recreate` and rejects rolling-update strategy values. This
preserves the one-writer repository rule during upgrades. Use
`restore-readonly` for scaled restore readers. The chart also sets
`gateway.writerGuard=required` by default so a read-write gateway holds the
runtime writer Lease before accepting traffic.

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
