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
- checkpoint digests or key material

Startup logs use `backend_kind` and `config_profile` instead of configured
bucket names, endpoints, prefixes, or repository IDs.

## Gateway Request Metrics

The gateway records S3 request counts, response bytes, request body bytes,
request duration, and request-body collection duration by operation and result.

These metrics are used to separate client request ingestion from repository
work and backend provider cost.

## Repository Metrics

Repository metrics cover:

- operation counts by repository operation
- plaintext bytes by operation
- backend bytes read and written by operation
- range mode, returned bytes, and payload span cache behavior
- list selectivity, candidate counts, and prefix misses
- commit queue, batch publish, batch size, waiter, and phase durations

The labels describe behavior without exposing logical names.

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
