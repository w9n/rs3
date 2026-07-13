# Metrics Reference

`rs3` exposes path-redacted runtime metrics when `RS3_METRICS_BIND` is set.

```sh
RS3_METRICS_BIND=127.0.0.1:19090
```

The integration harness scrapes the endpoint before and after measured runs and
writes deltas into Kopia matrix artifacts.

## Privacy Rules

Metrics labels may include:

- operation class
- result class
- HTTP status
- range mode
- object class
- provider class

Metrics labels must not include:

- client-visible object keys
- Kubernetes namespaces or object names
- tenant names
- backend object IDs
- access keys or secret values
- commit digests or key material

Startup logs use `backend_kind` and `config_profile` instead of configured
bucket names, endpoints, prefixes, or repository IDs.

## Gateway Request Metrics

The gateway records S3 request counts, response bytes, request body bytes,
request duration, request-body collection duration, request admission
rejections by reason, and connection admission rejections.
Upload body budget rejections use the admission-rejection reason
`body_budget`.

These metrics are used to separate client request ingestion from repository
work and backend provider cost.

Native series commonly used in alerting and triage:

- `rs3_s3_requests_total`
- `rs3_s3_request_duration_seconds`
- `rs3_s3_request_admission_rejections_total`
- `rs3_s3_connection_admission_rejections_total`
- `rs3_s3_request_body_bytes_total`
- `rs3_s3_request_body_collect_duration_seconds`
- `rs3_s3_response_body_bytes_total`

Prometheus also exposes target health through the standard `up` series for
the metrics scrape. HTTP probes against `GET /healthz` usually use the
Blackbox Exporter `probe_success` series. Those two series are not emitted by
`rs3`, but the alert examples use them for gateway-down detection.

## Repository Metrics

Repository metrics cover:

- operation counts by repository operation
- plaintext bytes by operation
- backend bytes read and written by operation
- range mode, returned bytes, payload span cache behavior, and decrypted
  segment cache behavior
- list selectivity, candidate counts, and prefix misses
- commit queue, batch publish, batch size, waiter, and phase durations

The labels describe behavior without exposing logical names.

Native v2 commit-coordinator series commonly used in alerting and triage:

- `rs3_repository_v2_commit_enqueues_total`
- `rs3_repository_v2_commit_enqueue_pending_items_total`
- `rs3_repository_v2_commit_batch_publishes_total`
- `rs3_repository_v2_commit_batch_waiters_total`
- `rs3_repository_v2_commit_batch_waiters_per_publish`
- `rs3_repository_v2_commit_batch_publish_duration_seconds`
- `rs3_repository_v2_commit_batch_publish_failures_total`
- `rs3_repository_v2_commit_coordinator_poisoned`
- `rs3_repository_v2_commit_put_phase_duration_seconds`
- `rs3_repository_v2_multipart_abort_failures_total`

`rs3_repository_v2_commit_batch_publish_failures_total` uses `stage="publish"`
for failures while publishing the pending commit batch, including external
anchor-advance failures. It uses `stage="rollback"` when the coordinator also
fails to restore the unaccepted in-memory state after a publish failure.

Cache counters use `result` labels such as `hit`, `miss`, `insert`, `evict`,
and `skip_too_large`. Payload span cache byte counters describe ciphertext span
bytes. Decrypted segment cache byte counters describe plaintext segment bytes
retained or served from the process-local cache.

## Maintenance Metrics

The in-gateway supervisor exports path-private scheduling, pressure, and outcome
facts:

- `rs3_maintenance_seconds_to_nearest_renewal_deadline`
- `rs3_maintenance_last_success_timestamp_seconds`
- `rs3_maintenance_orphan_candidate_bytes`
- `rs3_maintenance_orphan_candidate_count`
- `rs3_maintenance_consecutive_failures`
- `rs3_maintenance_runs_total{outcome}`
- `rs3_maintenance_budget_exceeded_total`
- `rs3_maintenance_planning_failures_total`
- `rs3_maintenance_window_duration_seconds`
- `rs3_maintenance_paused`
- `rs3_maintenance_parked`

Pressure gauges count deletion-eligible candidates, not retained, held,
unknown-protection, same-sequence, timestamp-less, or too-young inventory. The
last-success series is absent until a run actually succeeds; absence is not a
synthetic success. The Helm stale-success alert therefore treats an absent
series as unhealthy after its `for` interval, and renders that alert only for
the automatic maintenance posture. Counters and the paused/parked gauges are
initialized when the supervisor starts so first events remain observable.

All labels are closed outcome classes or fixed metric dimensions. They do not
contain plan digests, operation identifiers, repository paths, object IDs, or
Kubernetes names.

## Admin-Derived Alert Metrics

The native metrics listener does not currently export accepted-chain age as a
Prometheus gauge. Operators that alert on restore freshness should scrape the
authenticated `GET /admin/status` report with a trusted in-cluster exporter and
emit the following path-redacted series:

- `rs3_admin_status_up`: `1` when `GET /admin/status` returns HTTP 200 and the
  exporter decodes the report; `0` otherwise.
- `rs3_admin_v2_last_anchored_commit_age_seconds`: the
  `maintenance.v2.last_anchored_commit_age_ms` report field divided by 1000.
- `rs3_admin_v2_anchor_present`: `1` when `maintenance.v2.anchor_present` is
  true; `0` otherwise.
- `rs3_admin_v2_retention_renewal_blocked_count`: the
  `maintenance.v2.retention_renewal_blocked_count` report field.

Derived admin metrics may use operational labels such as `job`, `instance`, and
bounded reason codes. They must not add configured bucket names, backend
prefixes, repository IDs, Kubernetes object names, logical paths, commit
digests, or secret material.

## Storage Provider Metrics

The S3 storage adapter records provider operation attempts, successes,
failures, bytes sent, bytes received, and elapsed duration for:

- `put`
- `get`
- `head`
- `list`
- `delete`
- retention extension
- legal hold updates

Provider-specific HTTP metrics may differ across backends. Treat the
provider-neutral `BlobStore` counters as the stable comparison boundary.

## Integration Artifacts

Kopia matrix summaries include:

- `backend_metrics`
- `client_metrics`
- `prometheus_metrics`
- `gateway_process`
- `gateway_vs_direct`
- `gateway_internal`
- `regression_budgets`

These fields are designed to explain performance regressions without requiring
path-bearing logs.

See [Performance](../performance.md) for the current measured matrix and the
ratio rules used for release evidence.
