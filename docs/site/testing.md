# Testing

Testing is part of the architecture because privacy and rollback behavior are
product requirements.

## Default Check

Inside `nix develop`:

```sh
just check
```

This runs formatting, clippy with warnings denied, and workspace tests.

## Important Lanes

| Lane | Command | Scope |
| --- | --- | --- |
| Default | `just check` | Format, clippy, workspace tests. |
| Preview local gate | `just preview-gate-local` | Default checks, S3-feature checks, and dependency policy checks. |
| Storage S3 | `just integration-s3-local --mode container` | Storage contract against a disposable S3-compatible provider. |
| Gateway S3 | `just integration-s3-gateway` | Gateway S3 operations through the repository path. |
| Kopia | `just integration-kopia-gateway` | Real Kopia create, snapshot, and restore through the gateway. |
| Kubernetes | `just integration-k8s-gateway` | Image build, kind cluster, Helm install, readiness, S3 smoke. |
| Velero/Kopia | `just integration-velero-kopia-smoke` | Velero node-agent/Kopia backup and restore smoke. |
| Preview release gate | `just preview-gate-release` | Kopia gateway, Velero dynamic PVC gateway-restart, and Velero Postgres smoke. |
| Performance | `just perf-s3-gateway -- --format jsonl` | Gateway scenario metrics and amplification. |

Expensive lanes emit artifacts under `.local/integration/` by default.

## Privacy Tests

Features that handle logical names should prove:

- plaintext paths do not appear in backend object IDs
- plaintext paths do not appear in unauthenticated repository metadata
- logs, traces, metrics labels, and errors remain redacted
- generated Kubernetes-like names do not leak into backend storage

## Rollback Tests

Rollback-sensitive changes should cover:

- latest checkpoint accepted
- stale checkpoint rejected after anchor advance
- anchor digest mismatch rejected
- missing configured anchor fails closed
- checkpoint write succeeded but anchor advance failed
- recovery accepts an already-written identical checkpoint object

## Retention Tests

Retention and Object Lock work should cover:

- retention extension never shortens existing retention
- legal hold blocks destructive cleanup
- provider cannot extend retention
- governance bypass is not present in normal gateway credentials
- garbage collection does not remove reachable or retained objects

## Performance Tests

Performance changes should update the measured matrix when they affect:

- payload segment size
- range `GET`
- namespace listing
- commit batching
- S3 request body handling
- backend storage adapters
- metrics collection overhead

Use release-profile gateway runs for performance claims. Debug builds are useful
for development but distort medium and larger payload timings.
