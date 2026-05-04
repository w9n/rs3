# Performance

Performance work in `rs3` is evidence-driven. Claims should be tied to measured
artifacts and compared to a straight proxy baseline.

## Baseline Rule

The direct baseline is Kopia talking to RustFS through
`rs3-integration-storage-proxy`. The proxy is an integration-only binary under
`xtask`; it forwards requests unchanged while recording request counts, response
counts, body bytes, transport bytes, status, method, and connection counts.

Gateway performance should be compared to that direct path, not to an
unmeasured expectation.

## Measured Matrix

Run the larger restore matrix with the release gateway profile:

```sh
cargo run -p xtask --bin xtask --features containers -- integration kopia-measured-matrix \
  --runs 3 \
  --profile-set larger-restores \
  --gateway-build-profile release \
  --payload-segment-size 512
```

The current larger profiles are:

| Profile | Shape |
| --- | --- |
| `medium-restore` | One large file restore profile. |
| `kubernetes-objects` | Many Kubernetes-shaped manifests plus an etcd-like fragment. |
| `postgres-pgdata` | Relation files, WAL-shaped files, and a dump-shaped object. |

Artifacts are written under `.local/integration/` and should stay out of Git
unless deliberately reviewed and promoted.

## Primary Ratios

Track these before optimizing:

- gateway backend request count divided by direct backend request count
- gateway backend read bytes divided by direct backend read bytes
- gateway backend write bytes divided by direct backend write bytes
- gateway backend read bytes per returned client `GET` byte
- gateway backend write bytes per client `PUT` request byte
- restore phase elapsed ratio
- gateway CPU time and high-water RSS
- variability across repeated runs

Wall-clock time is useful, but it is more environment-sensitive than request
and byte ratios. Treat elapsed time as a regression signal, not a universal
provider claim.

## Current Interpretation

Recent release-profile artifacts show larger restore read and write byte ratios
near the direct baseline, with request counts at or below the direct path in the
measured local setup. Tiny-file restore profiles are more sensitive to payload
segment size because Kopia can issue many small ranged reads whose response
bodies are only a few dozen or hundred bytes each.

For tiny ranged restores, smaller segments reduce read-byte amplification while
larger segments reduce backend request count. The current Kopia-first candidate
is 512 bytes because it keeps byte amplification low in the edge case while
larger restore profiles stay close to baseline.

## Regression Budgets

The matrix writes a `regression_budgets` block. To turn supported budgets into
a command failure:

```sh
cargo run -p xtask --bin xtask --features containers -- integration kopia-measured-matrix \
  --runs 1 \
  --workload-profile small-smoke \
  --gateway-build-profile release \
  --payload-segment-size 512 \
  --enforce-regression-budgets
```

Budgets focus on request and byte amplification. Elapsed-time budgets remain
reported but should be enforced carefully because local container and host load
can dominate.

## Next Measurements

- Refresh the larger restore matrix after docs and cleanup changes.
- Keep run order alternating between direct and gateway lanes.
- Keep measuring variability with at least three runs for release claims.
- Add provider matrix runs only after local release artifacts are consistent.
