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

Run date: 2026-05-09. Gateway profile: release. Payload segment lane: fixed
512 B. Workload set: `larger-restores`. Each row is the average of three
direct/gateway run pairs. The direct baseline is the straight RustFS
measurement proxy.

Artifact:
`.local/integration/`.

`workload_consistency` passed for every profile and `regression_budgets` passed.

| Profile | Shape | Elapsed Ratio | Backend Requests | Backend Reads | Backend Writes | Gateway CPU | Gateway HWM RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `medium-restore` | one 64 MiB object | 1.06x | 1.16x | 1.03x | 1.03x | 1.10 s | 104.40 MiB |
| `kubernetes-objects` | 1,536 manifests plus a 32 MiB fragment | 0.28x | 1.01x | 1.05x | 1.03x | 1.60 s | 103.55 MiB |
| `kubernetes-objects-large` | 6,144 manifests plus a 128 MiB fragment | 0.20x | 1.00x | 1.05x | 1.03x | 5.79 s | 212.13 MiB |
| `postgres-pgdata` | 96 relation files, 4 WAL segments, and an 8 MiB dump | 1.27x | 1.11x | 1.03x | 1.03x | 2.88 s | 213.29 MiB |
| `postgres-pgdata-large` | larger relation/WAL/dump-shaped Postgres data directory | 1.58x | 1.11x | 1.03x | 1.03x | 5.70 s | 313.95 MiB |

Interpretation:

- Larger restore read and write bytes stay close to the straight proxy
  baseline, about 1.03x to 1.05x in these runs.
- Backend request counts are close to the straight proxy baseline, 1.00x to
  1.16x in this run. The highest request ratio is the one-object medium profile,
  where fixed checkpoint and evidence work has less opportunity to amortize.
- Built-in regression budgets passed for request ratios, byte ratios, restore
  phase ratios, and repeated-run stability.
- The Kubernetes-shaped profile is faster in this local harness despite similar
  backend bytes. Treat that as a local RustFS/proxy observation, not a cloud
  provider claim.
- The Postgres-shaped profile has modest byte overhead but slower elapsed time.
  The next performance target is gateway-side request/body handling and commit
  wait around snapshot creation.

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
- gateway commit phase averages, especially stage-lock wait and checkpoint wait
- gateway CPU time and high-water RSS
- variability across repeated runs

Wall-clock time is useful, but it is more environment-sensitive than request
and byte ratios. Treat elapsed time as a regression signal, not a universal
provider claim.

## Current Interpretation

Recent release-profile artifacts show larger restore read and write byte ratios
near the direct baseline, with request counts close to the direct path in the
measured local setup. Tiny-file restore profiles are more sensitive to payload
segment size because Kopia can issue many small ranged reads whose response
bodies are only a few dozen or hundred bytes each.

The current writer default is adaptive: small objects keep 512 B segments,
medium objects use 8 KiB segments, and larger objects use 64 KiB segments. The
historical fixed-size matrix below still explains the byte/request tradeoff, but
external performance claims should wait for a refreshed adaptive matrix with the
decrypted segment cache enabled.

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
allow modest extra requests for checkpoint and evidence writes; byte budgets are
tighter. Elapsed-time budgets remain reported but should be enforced carefully
because local container and host load can dominate.

## Next Measurements

- Refresh the three-run larger restore release matrix with the current adaptive
  writer default and decrypted segment cache enabled.
- Keep run order alternating between direct and gateway lanes.
- Keep measuring variability with at least three runs for release claims.
- Reduce commit stage-lock and checkpoint-wait time without allowing
  checkpoints to race writes whose sequence state is not yet indexed.
- Add provider matrix runs only after local release artifacts are consistent.
