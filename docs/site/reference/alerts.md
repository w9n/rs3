# Alerting Reference

This page gives starting Prometheus rules for production-preview operators.
Tune windows and severities to the backup cadence, restore objectives, and
maintenance schedule for the deployment.

Use two direct probes:

- Scrape the native metrics listener configured by `RS3_METRICS_BIND`.
- Probe unauthenticated `GET /healthz` on the S3 listener.

For restore-freshness alerts, also scrape authenticated `GET /admin/status`
with a trusted exporter and emit the derived admin metrics named in
[Metrics](metrics.md#admin-derived-alert-metrics).

## Example Rules

This example assumes backups should advance the accepted v2 chain at least
once per hour. `Rs3AcceptedCheckpointStale` therefore fires after the newest
accepted checkpoint is more than two hours old.

```yaml
groups:
  - name: rs3.preview
    rules:
      - alert: Rs3AcceptedCheckpointStale
        expr: rs3_admin_v2_last_anchored_commit_age_seconds > 7200
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: rs3 accepted checkpoint is stale
          description: >-
            The accepted v2 chain head is older than 2x the expected backup
            cadence. Check client backup jobs, commit publishing, and anchor
            availability before trusting newer unanchored backend objects.

      - alert: Rs3AdminStatusUnavailable
        expr: rs3_admin_status_up == 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: rs3 admin status is unavailable
          description: >-
            The admin-status exporter cannot verify restore and maintenance
            facts. Fix this before relying on freshness or anchor-present
            alerts.

      - alert: Rs3CommitPublishFailures
        expr: increase(rs3_repository_v2_commit_batch_publishes_total{result="error"}[15m]) > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: rs3 commit publish failures detected
          description: >-
            One or more coordinated v2 write batches failed before acceptance.
            Inspect path-redacted repository logs and backend health; clients
            may see write failures until publishing recovers.

      - alert: Rs3CommitCoordinatorPoisoned
        expr: rs3_repository_v2_commit_coordinator_poisoned == 1
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: rs3 commit coordinator is poisoned
          description: >-
            The coordinator failed to roll back an unaccepted batch and is
            refusing new writes. Keep the gateway fail-closed and perform
            operator recovery from the accepted anchor.

      - alert: Rs3PossibleAnchorAdvanceFailures
        expr: increase(rs3_repository_v2_commit_batch_publish_failures_total{stage="publish"}[15m]) > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: rs3 commit publish or anchor advance failed
          description: >-
            The native publish-failure counter includes external anchor advance
            failures. Check Kubernetes Lease access, stale-anchor errors,
            backend writes, and the accepted anchor before retrying recovery
            actions.

      - alert: Rs3GatewayMetricsScrapeDown
        expr: up{job="rs3-gateway-metrics"} == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: rs3 metrics scrape is down
          description: >-
            Prometheus cannot scrape the gateway metrics endpoint. The process
            may be down, wedged before metrics install, or unreachable from the
            monitoring plane.

      - alert: Rs3GatewayHealthProbeFailed
        expr: probe_success{job="rs3-gateway-healthz"} == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: rs3 health probe failed
          description: >-
            The unauthenticated S3 listener health probe is failing. Check pod
            readiness, listener binding, service routing, and recent restarts.
```

## Rationale

`Rs3AcceptedCheckpointStale` catches the most important operator symptom:
backup clients may still be producing objects, but the accepted anchor has not
advanced. Treat newer unanchored backend objects as untrusted until the accepted
chain advances or an operator verifies recovery material.

`Rs3CommitPublishFailures` and `Rs3CommitCoordinatorPoisoned` cover the write
path. Publish failures should recover when the backend or anchor does; a
poisoned coordinator means rollback failed too, so writes stay fail-closed until
an operator intervenes.

`Rs3PossibleAnchorAdvanceFailures` routes possible external-anchor failures
separately. The current native metric records them under `stage="publish"`, so
use repository logs, admin status, and Kubernetes events to distinguish anchor
CAS failures from backend commit-object failures.

`Rs3GatewayMetricsScrapeDown`, `Rs3GatewayHealthProbeFailed`, and
`Rs3AdminStatusUnavailable` protect the monitoring surface itself. Freshness
and publish alerts are not useful if the scraper, health probe, or admin-status
exporter is blind.
