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
| Live v2 preview gate | `just preview-gate-v2-live <bucket> <endpoint> <region>` | Consolidated retained-backend gate. Generates fresh sub-prefixes and runs v2 Gateway S3, Kopia, Kubernetes Lease, Velero dynamic-PVC gateway-restart, and Velero/Postgres lanes. |
| Live v2 Gateway S3 | `just integration-s3-gateway-v2-live --backend-bucket <bucket> --endpoint-url <endpoint> --region <region> --backend-prefix <fresh-prefix>` | v2-preview gateway smoke against an existing retained S3-compatible backend, including `mc`, default `rclone lsf`, and backend key privacy checks. |
| Kopia | `just integration-kopia-gateway` | Real Kopia create, snapshot, and restore through the gateway. |
| Live v2 Kopia | `just integration-kopia-gateway-v2-live --backend-bucket <bucket> --endpoint-url <endpoint> --region <region> --backend-prefix <fresh-prefix>` | Real Kopia create, snapshot, and restore through a v2-preview gateway against an existing retained backend. |
| Kubernetes | `just integration-k8s-gateway` | Image build, kind cluster, Helm install, readiness, S3 smoke. |
| Kubernetes v2 Lease | `just integration-k8s-gateway-v2` | v2-preview Helm deployment using a Kubernetes Lease anchor, with an assertion that v2 anchor annotations are written. |
| Velero/Kopia | `just integration-velero-kopia-smoke` | Velero node-agent/Kopia backup and restore smoke. |
| Live v2 Velero dynamic PVC | `just integration-velero-kopia-dynamic-pvc-gateway-restart-v2-live --backend-bucket <bucket> --backend-endpoint-url <endpoint> --backend-region <region> --backend-prefix <fresh-prefix>` | Velero/Kopia dynamic-PVC backup and restore through a v2-preview gateway after a gateway restart, against an existing retained backend. |
| Live v2 Velero Postgres | `just integration-velero-kopia-postgres-v2-live --backend-bucket <bucket> --backend-endpoint-url <endpoint> --backend-region <region> --backend-prefix <fresh-prefix>` | Velero/Kopia Postgres backup and restore through a v2-preview gateway against an existing retained backend. |
| Preview release gate | `just preview-gate-release` | v2 Kopia gateway, Velero dynamic PVC gateway-restart in normal write mode, and Velero Postgres smoke. |
| Velero strict restore-readonly | `just integration-velero-kopia-dynamic-pvc-restore-readonly-smoke` | Incident-restore behavior: restored bytes verify, Velero artifact writes are denied, and backend writes stay at zero during restore. |
| Lightweight perf smoke | `just perf-s3-gateway --format jsonl` | Small gateway scenario metrics and amplification. |
| Gateway perf smoke | `just perf-s3-gateway --objects 32 --object-size 262144 --reads 64 --range-len 4096 --commit-batch-items 8 --concurrency 8 --format jsonl` | Release-profile local gateway run for current v2 request cost, throughput, and amplification. |
| Kopia measured matrix | `cargo run -p xtask --bin xtask --features containers -- integration kopia-measured-matrix --runs 3 --profile-set larger-restores --gateway-build-profile release --enforce-regression-budgets` | Release-grade Kopia restore comparison against the straight RustFS proxy baseline with current gateway defaults. |

Expensive lanes emit artifacts under `.local/integration/` by default.

## S3 Provider Qualification

Do not infer production support from S3 compatibility alone. A live provider
trial must choose and prove one storage safety profile:

- `atomic-create`: a second `PutObject` with `If-None-Match: *` for an existing
  current object must fail instead of creating a new version.
- `retained-version`: Object Lock/versioning must return provider version IDs
  for retained writes, block version deletion before expiry, and support
  exact-version reads after a newer latest version exists.

`HEAD` before `PUT` is not the production fallback for create-only writes. It is
non-atomic and only useful for a deliberately degraded compatibility mode, which
is not part of the production-preview contract.

Use `--qualification-profile retained-version --object-lock` for providers such
as retained-backend where retained version IDs are the safety primitive. The command
rejects `retained-version` without `--object-lock` because the profile is only
meaningful when the retention and exact-version checks run:

```sh
just integration-s3-local --qualification-profile retained-version --object-lock
```

For governance mode, also review IAM or bucket policy so normal gateway
credentials cannot bypass governance retention. The live retained-version test
does not grant or use bypass headers, so it is not a substitute for that
credential review.

After a provider passes qualification, run a real Kopia backup/restore through
the gateway against the same backend. Use a fresh backend prefix for each live
run, and enable repository retention when validating an Object Lock bucket:

```sh
RS3_REPOSITORY_RETENTION_MODE=governance \
RS3_REPOSITORY_RETENTION_DAYS=1 \
just integration-kopia-gateway --mode provided --backend-prefix <fresh-prefix>
```

For the Kubernetes path, run the Velero dynamic PVC gateway-restart lane against
the same provider. This creates a disposable kind cluster, runs a Velero/Kopia
backup, deletes the namespace, restarts the stateless gateway, restores the
namespace, and verifies the restored file bytes:

```sh
RS3_REPOSITORY_RETENTION_MODE=governance \
RS3_REPOSITORY_RETENTION_DAYS=1 \
just integration-velero-kopia-dynamic-pvc-gateway-restart-v2-live --backend-prefix <fresh-prefix>
```

## Privacy Tests

Features that handle logical names should prove:

- plaintext paths do not appear in backend object IDs
- plaintext paths do not appear in unauthenticated repository metadata
- logs, traces, metrics labels, and errors remain redacted
- generated Kubernetes-like names do not leak into backend storage

## Rollback Tests

Rollback-sensitive changes should cover:

- latest anchored commit accepted
- stale commit rejected after anchor advance
- anchor digest mismatch rejected
- missing configured anchor fails closed
- commit write succeeded but anchor advance failed
- recovery accepts an already-written identical commit object

## Retention Tests

Retention and Object Lock work should cover:

- native conditional create rejects duplicate create-only writes for the
  `atomic-create` profile
- retention extension never shortens existing retention
- retained writes fail when the provider does not return version IDs
- retry after an anchor failure remains safe when a retained-version provider
  appends a same-key version instead of rejecting duplicate create-only writes
- exact-version reads return the anchor-bound object after a newer latest
  version exists
- legal hold blocks destructive cleanup
- provider cannot extend retention
- governance bypass is not present in normal gateway credentials
- garbage collection does not remove reachable or retained objects

The ignored live S3 Object Lock tests exercise provider version IDs against a
real retained bucket. They are the lane for S3-compatible providers where local
RustFS/container tests cannot prove retained version-addressed reads.

## Performance Tests

Performance changes should update the measured matrix when they affect:

- payload segment size
- range `GET`
- namespace listing
- commit batching
- S3 request body handling
- backend storage adapters
- metrics collection overhead
- adaptive payload segment sizing
- decrypted segment cache behavior

Use release-profile gateway runs for performance claims. Debug builds are useful
for development but distort medium and larger payload timings.
