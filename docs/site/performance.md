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

## Current Release Matrix

Run date: 2026-05-04. Gateway profile: release. Workload set:
`larger-restores`. Each row is the average of three direct/gateway run pairs.
The direct baseline is the straight RustFS measurement proxy.

Artifact:
`.local/integration/`.

| Profile | Shape | Elapsed Ratio | Backend Requests | Backend Reads | Backend Writes | Gateway CPU | Gateway HWM RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `medium-restore` | one 64 MiB object | 1.11x | 0.89x | 1.03x | 1.03x | 1.07 s | 107.65 MiB |
| `kubernetes-objects` | 1,536 manifests plus a 32 MiB fragment | 0.27x | 0.99x | 1.05x | 1.03x | 1.58 s | 93.39 MiB |
| `postgres-pgdata` | 96 relation files, 4 WAL segments, and an 8 MiB dump | 1.31x | 1.00x | 1.03x | 1.03x | 2.77 s | 214.63 MiB |

Interpretation:

- Larger restore read and write bytes stay close to the straight proxy
  baseline, about 1.03x to 1.05x in these runs.
- Backend request counts are at or below the straight proxy baseline.
- The Kubernetes-shaped profile is faster in this local harness despite similar
  backend bytes. Treat that as a local RustFS/proxy observation, not a cloud
  provider claim.
- The Postgres-shaped profile has modest byte overhead but slower elapsed time.
  The next performance target is gateway-side request/body handling and commit
  wait around snapshot creation.

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

## Segment-Size Finding

The `many-small-files` profile is the current edge case because Kopia issued
hundreds of small ranged reads while receiving only about 56 KiB of total S3
response body. Segment size strongly affects read-byte amplification there:

| Segment Size | Gateway Read Ratio | Request Ratio | Write Ratio |
| --- | ---: | ---: | ---: |
| 512 B | 1.72x | 0.31x | 2.04x |
| 1 KiB | 1.76x | 0.21x | 2.02x |
| 2 KiB | 1.82x | 0.16x | 2.01x |
| 4 KiB | 1.97x | 0.14x | 2.01x |
| 8 KiB | 2.29x | 0.12x | 2.01x |
| 16 KiB | 2.59x | 0.11x | 2.00x |
| 32 KiB | 4.01x | 0.11x | 2.01x |
| 256 KiB | 5.44x | 0.11x | 2.00x |

The result is not evidence that larger restores have high byte overhead. The
larger restore matrix above stayed near baseline. It is evidence that tiny
ranged restores need small segments or an equally effective read coalescing
strategy.

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
