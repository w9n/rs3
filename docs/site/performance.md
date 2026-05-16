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
  --gateway-build-profile release
```

Add `--payload-segment-size 512` only when comparing against the historical
fixed-segment lane.

The lightweight `xtask perf` harness follows the same convention: omit
`--payload-segment-size` for adaptive writer defaults, or set it to force a
fixed segment-size comparison.

The current larger profiles are:

| Profile | Shape |
| --- | --- |
| `medium-restore` | One large file restore profile. |
| `kubernetes-objects` | Many Kubernetes-shaped manifests plus an etcd-like fragment. |
| `kubernetes-objects-large` | Larger Kubernetes-shaped manifest set plus a larger etcd-like fragment. |
| `postgres-pgdata` | Relation files, WAL-shaped files, and a dump-shaped object. |
| `postgres-pgdata-large` | Larger relation/WAL/dump-shaped Postgres data directory. |

The summary includes a `workload_consistency` block. It checks that direct and
gateway lanes see matching source and restored tree statistics for every run
pair before ratios are interpreted. Artifacts are written under
`.local/integration/` and should stay out of Git unless deliberately reviewed and promoted.
The command prints a compact table by default; pass
`--print-summary-json` when a caller needs the full JSON on stdout.

## Current Release Matrix

Run date: 2026-05-13. Gateway profile: release. Payload segment lane:
adaptive writer default. Workload set: `larger-restores`. Each row is the
average of three direct/gateway run pairs. The direct baseline is the straight
RustFS measurement proxy.

Artifact:
`.local/integration/`.

`workload_consistency` passed for every profile and `regression_budgets` passed.

| Profile | Shape | Elapsed Ratio | Backend Requests | Backend Reads | Backend Writes | Gateway CPU | Gateway HWM RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `medium-restore` | one 64 MiB object | 0.88x | 1.16x | 1.01x | 1.00x | 1.32 s | 159.82 MiB |
| `kubernetes-objects` | 1,536 manifests plus a 32 MiB fragment | 0.21x | 0.07x | 1.04x | 1.00x | 0.71 s | 128.37 MiB |
| `kubernetes-objects-large` | 6,144 manifests plus a 128 MiB fragment | 0.12x | 0.03x | 1.02x | 1.00x | 2.06 s | 305.40 MiB |
| `postgres-pgdata` | 96 relation files, 4 WAL segments, and an 8 MiB dump | 1.03x | 1.13x | 1.04x | 1.00x | 1.62 s | 289.71 MiB |
| `postgres-pgdata-large` | larger relation/WAL/dump-shaped Postgres data directory | 1.15x | 1.10x | 1.04x | 1.00x | 3.13 s | 456.04 MiB |

Interpretation:

- Larger restore write bytes stay at about the straight proxy baseline, and
  read bytes stay within about 1.01x to 1.04x in this run.
- Backend request counts are at or below the straight proxy baseline for the
  Kubernetes-shaped profiles and within 1.10x to 1.16x for the medium and
  Postgres-shaped profiles. The highest request ratio remains the one-object
  medium profile, where commit and anchor work has little
  opportunity to amortize.
- Built-in regression budgets passed for request ratios, byte ratios, restore
  phase ratios, and repeated-run stability.
- The Kubernetes-shaped profile is faster in this local harness despite similar
  backend bytes. Treat that as a local RustFS/proxy observation, not a cloud
  provider claim.
- Postgres-shaped elapsed time is now close to the direct path in this local
  harness. Keep tracking snapshot-create and large PUT phases because they
  remain the most visible local latency contributors.

## Expanded Sanity Run

Run date: 2026-05-04. Gateway profile: release. One direct/gateway run pair per
profile, so this historical artifact validated shape and budget wiring before
the five-profile release matrix above.

Artifact:
`.local/integration/`.

`workload_consistency` passed for every profile, and `regression_budgets`
passed.

| Profile | Backend Requests | Backend Reads | Backend Writes |
| --- | ---: | ---: | ---: |
| `medium-restore` | 1.16x | 1.03x | 1.03x |
| `kubernetes-objects` | 1.01x | 1.05x | 1.03x |
| `kubernetes-objects-large` | 1.00x | 1.05x | 1.03x |
| `postgres-pgdata` | 1.10x | 1.03x | 1.03x |
| `postgres-pgdata-large` | 1.10x | 1.03x | 1.03x |

## Primary Ratios

Track these before optimizing:

- gateway backend request count divided by direct backend request count
- gateway backend read bytes divided by direct backend read bytes
- gateway backend write bytes divided by direct backend write bytes
- gateway backend read bytes per returned client `GET` byte
- gateway backend write bytes per client `PUT` request byte
- restore phase elapsed ratio
- gateway commit phase averages, especially stage-lock wait and commit wait
- gateway CPU time and high-water RSS
- variability across repeated runs

Wall-clock time is useful, but it is more environment-sensitive than request
and byte ratios. Treat elapsed time as a regression signal, not a universal
provider claim.

## Current Interpretation

Recent release-profile artifacts show larger restore read and write byte ratios
near the direct baseline. Tiny-file restore profiles are more sensitive to
payload segment size because Kopia can issue many small ranged reads whose
response bodies are only a few dozen or hundred bytes each.

The current writer default is adaptive: small objects keep 512 B segments,
medium objects use 8 KiB segments, and larger objects use 64 KiB segments. The
historical fixed-size matrix below still explains the byte/request tradeoff.

For `v2-preview`, payload bytes live inside signed commit objects. Current
gateway smoke runs on 2026-05-16 show the expected write request floor: one
backend commit PUT per sequential write, with concurrent writes batched into
fewer commit PUTs. Repeated reads of the same object are served from a verified
payload-section cache after the first commit GET; the cache is bounded by the
repository decrypted-segment cache budget and can be disabled by setting that
budget to zero.

## Historical Segment-Size Finding

The `many-small-files` profile is the current edge case because Kopia issued
hundreds of small ranged reads while receiving only about 56 KiB of total S3
response body. Fixed segment size strongly affected read-byte amplification
there:

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

The matrix writes `regression_budgets` and `workload_consistency` blocks. To
turn supported budgets and consistency failures into a command failure:

```sh
cargo run -p xtask --bin xtask --features containers -- integration kopia-measured-matrix \
  --runs 1 \
  --workload-profile small-smoke \
  --gateway-build-profile release \
  --enforce-regression-budgets
```

Budgets focus on request and byte amplification. Larger restore request budgets
allow modest extra requests for v2 commit and anchor writes; byte budgets are
tighter. Cache hit ratios remain reported diagnostics, but are not enforced for
the `many-small-files` profile because that workload can legitimately pass the
request and byte budgets without reusing decrypted payload spans. Elapsed-time
budgets remain reported but should be enforced carefully because local container
and host load can dominate.

## Next Measurements

- Keep run order alternating between direct and gateway lanes.
- Keep measuring variability with at least three runs for release claims.
- Reduce commit stage-lock and commit-wait time without allowing commits to
  race writes whose sequence state is not yet indexed.
- Add provider matrix runs for additional S3-compatible stores after the
  retained-backend retained-version lane remains repeatable.
