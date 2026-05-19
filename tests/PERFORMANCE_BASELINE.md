# Performance Baseline

This document records local performance evidence for the gateway test harness.
It is not a provider benchmark and should not be used for broad performance
claims.

## Method

Command shape:

```sh
cargo run -p xtask --bin xtask --features containers -- integration kopia-measured-matrix --runs 3 --workload-profile <profile>
```

The larger restore matrix uses the same harness with a profile set:

```sh
cargo run -p xtask --bin xtask --features containers -- integration kopia-measured-matrix \
  --runs 3 \
  --profile-set larger-restores \
  --gateway-build-profile release \
  --payload-segment-size 512
```

For the measured matrix, setting `--payload-segment-size` forces that fixed
gateway segment size. Omit it to measure the current adaptive writer default.
The lightweight `xtask perf` harness uses the same convention.

The harness compares two paths against a disposable local RustFS container:

- direct: Kopia talks to RustFS through the integration storage proxy,
- gateway: Kopia talks to the gateway, and the gateway talks to the same backend
  class.

The measured gateway process uses the Cargo release profile. The summary JSON
records this as `gateway_build_profile: "release"`.

The direct baseline is intentionally a straight TCP measurement proxy, not a
production gateway mode. The proxy lives under `xtask` as
`rs3-integration-storage-proxy`, is built only for integration images, and
records HTTP method, status, request body bytes, response body bytes, transport
bytes, and connection counts while forwarding requests unchanged to RustFS.

New gateway matrix artifacts also record `gateway_process.cpu_*_seconds`,
`gateway_process.vm_hwm_bytes`, and `gateway_process.vm_rss_bytes` from the
measured gateway process. Historical artifacts listed below may predate those
fields.

Gateway backend metrics also include `backend_metrics.by_s3_operation`, a
span-derived breakdown of backend operations and bytes by client S3 operation.
This gives a request-to-backend cost map without recording object keys.

The Prometheus delta includes `prometheus_metrics.storage_provider`, which
summarizes S3 provider operation counts, bytes, and latency from the gateway's
metrics endpoint. It also records
`prometheus_metrics.request_body_collect_duration_seconds` so PUT ingestion time
can be separated from repository sealing, storage writes, and commit publishing.

It also includes `prometheus_metrics.repository`, a path-private repository
breakdown of gateway operation counts, bytes, LIST selectivity, commit batching,
latency, and committed PUT phase timing.

Repository metrics also include
`prometheus_metrics.repository.payload_span_cache_events_by_result` and
`payload_span_cache_bytes_by_result`, which show ciphertext span cache hits,
misses, inserts, evictions, skipped inserts, and bytes without exposing object
keys.

Newer artifacts also include
`prometheus_metrics.repository.decrypted_segment_cache_events_by_result` and
`decrypted_segment_cache_bytes_by_result`, which show process-local decrypted
segment cache behavior without exposing logical paths or backend object IDs.

The matrix comparison block includes derived gateway-internal cost ratios such
as backend read bytes per returned GET byte, backend write bytes per PUT request
byte, payload span cache hit ratios, and decrypted segment cache hit ratios.
These fields are intended to make restore regressions explainable from one
summary artifact.

The matrix command also writes `regression_budgets`. Passing
`--enforce-regression-budgets` turns those built-in byte/request budget checks
into a command failure. The budgets intentionally avoid wall-clock elapsed time,
which is too environment-sensitive for a hard gate in this local harness.

## Historical Small-Profile Results

Run date: 2026-05-03. Payload segment lane: fixed 512 B. Each row is the
average of three direct/gateway run pairs.

| Profile | Direct elapsed | Gateway elapsed | Elapsed ratio | Backend requests | Backend writes | Backend reads |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| small-smoke | 1.66 s | 1.28 s | 0.78x | 0.81x | 1.14x | 1.02x |
| changed-snapshot | 2.02 s | 1.58 s | 0.78x | 0.82x | 1.08x | 1.02x |
| many-small-files | 3.01 s | 1.30 s | 0.43x | 0.31x | 2.04x | 1.72x |
| medium-restore | 2.66 s | 2.75 s | 1.03x | 0.89x | 1.03x | 1.03x |

## Reading The Numbers

Backend request counts are below the straight proxy lane in these refreshed
profiles: about 0.31x to 0.89x versus direct RustFS. Inline checkpoint deltas
removed separate backend index writes, and the ciphertext span cache collapses
repeated small ranged restores into fewer backend GETs.

Backend write-byte amplification is low for the medium and incremental profiles.
The many-small-files profile writes very little data directly, so fixed
metadata, checkpoint, and envelope costs show up more strongly.

Backend read-byte amplification is close to baseline for the small, changed,
and medium profiles. The many-small-files profile remains the current edge case,
but the fixed 512 B segment lane now reads 1.72x backend bytes instead of 4.54x
because repeated tiny client ranges are served from cached ciphertext spans.

Wall-clock results are favorable for the gateway in this local setup, but they
are less portable than request and byte ratios. Treat them as a regression
signal for this harness, not as a general cloud-provider result.

## Larger Restore Matrix

Run date: 2026-05-13. Payload segment lane: adaptive writer default. Workload
set: `larger-restores`. Each row is the average of three direct/gateway run
pairs.
Per-profile values come from
`summary.json.profiles`; the top-level aggregate intentionally mixes profiles
and should only be used as a smoke signal for the whole set.

Raw artifact: retained as ignored local release evidence.

`workload_consistency` passed for every profile and `regression_budgets`
reported `status: "pass"`.

The direct baseline is the same straight integration storage proxy used by the
single-profile rows. The Postgres-shaped profile uses file-specific deterministic
payloads so equal-size relation and WAL files do not collapse into a
deduplicated synthetic best case.

| Profile | Shape | Direct elapsed | Gateway elapsed | Elapsed ratio | Backend requests | Backend writes | Backend reads | Gateway CPU | Gateway HWM RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| medium-restore | one 64 MiB object | 2.79 s | 2.44 s | 0.88x | 1.16x | 1.00x | 1.01x | 1.32 s | 159.82 MiB |
| kubernetes-objects | 1,536 manifests plus a 32 MiB etcd-like fragment | 9.48 s | 2.03 s | 0.21x | 0.07x | 1.00x | 1.04x | 0.71 s | 128.37 MiB |
| kubernetes-objects-large | 6,144 manifests plus a 128 MiB etcd-like fragment | 32.65 s | 4.07 s | 0.12x | 0.03x | 1.00x | 1.02x | 2.06 s | 305.40 MiB |
| postgres-pgdata | 96 relation files, 4 WAL segments, and an 8 MiB dump | 2.73 s | 2.82 s | 1.03x | 1.13x | 1.00x | 1.04x | 1.62 s | 289.71 MiB |
| postgres-pgdata-large | larger relation/WAL/dump-shaped data directory | 3.69 s | 4.24 s | 1.15x | 1.10x | 1.00x | 1.04x | 3.13 s | 456.04 MiB |

Interpretation:

- Larger restore write-byte ratios stay at about the straight proxy baseline.
  Read-byte ratios stay within about 1.01x to 1.04x in these runs.
- Gateway-internal derived byte ratios tell the same story: backend read bytes
  per returned GET byte were about 1.01x to 1.04x, and backend write bytes per
  PUT request byte were about 1.001x to 1.004x.
- Backend request counts are lower than the straight proxy baseline for the
  Kubernetes-shaped profiles and within 1.10x to 1.16x for the medium and
  Postgres-shaped profiles. The highest count remains the one-object medium
  restore profile where checkpoint/evidence work has little opportunity to
  amortize.
- The larger profiles produced little or no payload span cache reuse. The
  Postgres-shaped profile averaged only a 0.29% cache event hit ratio, with
  evictions and skipped-too-large spans visible in the cache metrics. That is
  expected for mostly distinct larger restore ranges.
- Gateway CPU is cumulative process CPU time for the measured gateway run.
  Gateway HWM RSS is the average high-water resident set size across the three
  gateway runs for that profile.
- The Kubernetes-shaped profile is dominated by many small ranged GETs on the
  direct path. The gateway is faster locally despite similar backend bytes, but
  that elapsed ratio should be treated as a local RustFS/proxy observation.
- The Postgres-shaped profiles are now close to the direct path in this local
  harness. Keep tracking snapshot-create and large PUT phases because they
  remain the most visible local latency contributors.

## Expanded Restore Sanity Run

Run date: 2026-05-04. Workload set: `larger-restores`. This older artifact used
one direct/gateway run pair per profile. It validated expanded workload shape
and budget wiring before the five-profile three-run matrix above.

Raw artifact: retained as ignored local release evidence.

`workload_consistency` passed for every profile and `regression_budgets`
reported `status: "pass"`.

| Profile | Shape | Elapsed ratio | Backend requests | Backend reads | Backend writes | Gateway CPU | Gateway HWM RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| medium-restore | one 64 MiB object | 1.04x | 1.16x | 1.03x | 1.03x | 1.15 s | 100.14 MiB |
| kubernetes-objects | 1,536 manifests plus a 32 MiB etcd-like fragment | 0.28x | 1.01x | 1.05x | 1.03x | 1.71 s | 105.40 MiB |
| kubernetes-objects-large | 6,144 manifests plus a 128 MiB etcd-like fragment | 0.20x | 1.00x | 1.05x | 1.03x | 5.99 s | 210.27 MiB |
| postgres-pgdata | 96 relation files, 4 WAL segments, and an 8 MiB dump | 1.25x | 1.10x | 1.03x | 1.03x | 2.99 s | 230.54 MiB |
| postgres-pgdata-large | larger relation/WAL/dump-shaped data directory | 1.62x | 1.10x | 1.03x | 1.03x | 5.93 s | 293.73 MiB |

## Regression Budgets

The measured matrix now emits a `regression_budgets` block. The hard gate is
opt-in:

```sh
cargo run -p xtask --bin xtask --features containers -- integration kopia-measured-matrix \
  --runs 1 \
  --workload-profile small-smoke \
  --gateway-build-profile release \
  --payload-segment-size 512 \
  --enforce-regression-budgets
```

Validation artifact: retained as ignored local release evidence.

The current built-in budgets check backend request, read-byte, and write-byte
ratios for the small and larger profiles. The fixed 512 B `many-small-files`
lane also
checks that read bytes stay below 2.00x, write bytes below 2.25x, requests below
0.50x, and payload span cache event hit ratio above 0.70. Elapsed ratios remain
reported but are not enforced.

## Segment-Size Sweep

Run date: 2026-05-03. Workload: `many-small-files`, because it is the current
restore-heavy Kopia profile with many small ranged reads. Each row is the
average of three direct/gateway run pairs with a fixed segment size. The direct
RustFS baseline is the same straight proxy lane for every row.

Command shape:

```sh
cargo run -p xtask --bin xtask --features containers -- integration kopia-measured-matrix \
  --runs 3 \
  --workload-profile many-small-files \
  --gateway-build-profile release \
  --payload-segment-size <bytes>
```

| Gateway segment size | Direct read | Gateway read | Read ratio | Request ratio | Write ratio | Elapsed ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 512 B | 72.81 KB | 124.93 KB | 1.72x | 0.31x | 2.04x | 0.43x |
| 1 KiB | 72.81 KB | 127.97 KB | 1.76x | 0.21x | 2.02x | 0.43x |
| 2 KiB | 72.81 KB | 132.32 KB | 1.82x | 0.16x | 2.01x | 0.45x |
| 4 KiB | 72.81 KB | 143.65 KB | 1.97x | 0.14x | 2.01x | 0.43x |
| 8 KiB | 72.81 KB | 166.69 KB | 2.29x | 0.12x | 2.01x | 0.43x |
| 16 KiB | 72.81 KB | 188.32 KB | 2.59x | 0.11x | 2.00x | 0.43x |
| 32 KiB | 72.81 KB | 291.93 KB | 4.01x | 0.11x | 2.01x | 0.44x |
| 256 KiB | 72.81 KB | 396.20 KB | 5.44x | 0.11x | 2.00x | 0.44x |

Interpretation:

- Segment size still affects backend read bytes for tiny ranged restores, but
  the ciphertext span cache makes it a much smaller effect. The fixed 512 B lane
  now reads 1.72x the direct baseline, and the 256 KiB lane reads 5.44x.
- The ratio is large because the denominator is small. The profile restores 512
  tiny files; Kopia issued 514 successful ranged GETs but received only about
  56 KB of total S3 response body. At 2 KiB segments each roughly 110-byte
  response still forces at least one authenticated backend segment read on the
  first miss, then later reads can hit the cached ciphertext span.
- Backend request count drops as segment size grows because fewer distinct
  ciphertext spans are fetched: from 0.31x of direct requests at 512 B to 0.11x
  at 32 KiB and 256 KiB. The tradeoff is larger backend reads for each miss.
- Write-byte amplification is also flat because this workload's writes are
  mostly independent of restore segment size, sitting around 2.01x to 2.03x in
  this tiny-data profile.
- Wall-clock remains a weak ranking signal here. The local gateway lane is
  faster than direct RustFS through the proxy for all rows, which should be
  treated as a harness/backend observation rather than a provider claim.
- The adaptive larger restore matrix read about 1.01x to 1.04x backend bytes
  and wrote about 1.00x backend bytes versus direct RustFS. Keep tracking larger
  Postgres-shaped restore elapsed time because large PUT and snapshot-create
  latency are still visible in the local gateway path.

## Lightweight Gateway Perf Smoke

Run date: 2026-05-05. This is a command-level smoke for
`just perf-s3-gateway`, not a replacement for the larger Kopia matrix above.

Raw artifact: retained as ignored local evidence.

Command:

```sh
just perf-s3-gateway --objects 16 --object-size 4096 --reads 16 \
  --range-len 512 --commit-batch-items 8 --concurrency 8 --format jsonl
```

| Scenario | Elapsed | Backend requests/op | Write amp | Read amp |
| --- | ---: | ---: | ---: | ---: |
| write-committed | 447 ms | 3.00 | 2.68x | n/a |
| write-committed-parallel | 153 ms | 1.25 | 2.26x | n/a |
| full-read | 96 ms | 1.00 | n/a | 1.05x |
| range-read | 120 ms | 1.00 | n/a | 1.43x |

## Follow-Up Work

- Add restore-throughput and resource-efficiency columns once enough
  release-profile matrix artifacts include CPU and memory metrics.
- Add a real Velero/Postgres cluster matrix once the smoke lane can scale row
  counts and data volume without changing its correctness proof.
- Keep release-profile gateway execution for performance lanes; debug builds are
  useful for development but distort medium payload timings.
