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
`--enforce-regression-budgets` turns those built-in checks into a command
failure. Larger profiles gate total elapsed ratio, request and byte ratios,
restore ratio, repeated-run stability, and average gateway HWM RSS. Ratios are
local regression signals, not portable provider timing claims.

## Historical July 2026 Lightweight Smoke

Run date: 2026-07-10. These are single-run release-profile smoke measurements,
not a replacement for the three-run Kopia matrix. They were rerun before and
after the dependency remediations in this review; that measured tree showed no
material regression in the small in-memory lane.

Command shape:

```sh
cargo run -p xtask --bin xtask --release -- perf \
  --objects 16 --object-size 4096 --reads 16 --range-len 512 \
  --commit-batch-items 8 --concurrency 8 --format jsonl
```

| Scenario | Elapsed | Backend requests/op | Byte amplification |
| --- | ---: | ---: | ---: |
| write batch | 3.482 ms | 0.0625 | 2.5086x write |
| committed writes, sequential | 186.544 ms | 1.0000 | 3.5374x write |
| committed writes, parallel | 3.628 ms | 0.1250 | 2.6162x write |
| full reads | 0.704 ms | 0.0625 | 0.0656x read |
| range reads | 0.147 ms | 0.5000 | 0.5156x read |

The final release gateway smoke after the S3 client replacement recorded
257.191 ms for sequential committed writes, 25.407 ms for parallel committed
writes, 18.929 ms for full reads, and 30.722 ms for range reads. Request and
byte ratios matched the in-memory lane closely. The gateway executable was
built before the timed run; the current helper otherwise includes Cargo
compilation in its readiness timeout on a cold tree.

### Parallel Write Growth Remediation

The release binary was swept with 512 B objects, a 64-item commit batch, and
concurrency 64. Before the write-state remediation it measured:

| Objects | Elapsed | Throughput | Average latency | p99 latency |
| ---: | ---: | ---: | ---: | ---: |
| 256 | 69 ms | 3,705 ops/s | 10.8 ms | 22.7 ms |
| 1,024 | 818 ms | 1,252 ops/s | 28.4 ms | 88.3 ms |
| 4,096 | 19.61 s | 209 ops/s | 161.3 ms | 655.2 ms |

This 16x object-count increase produced about 284x elapsed time. The write path
was then changed to retain bounded per-mutation undo records, incrementally
apply accepted state, target payload-reference resolution from the pending
delta, and avoid a namespace scan for normal PUT list projection updates.

That historical tree was measured three times with the same command shape.
The table reports median elapsed and latency values:

| Objects | Elapsed | Throughput | Average latency | p99 latency |
| ---: | ---: | ---: | ---: | ---: |
| 256 | 17.0 ms | 15,019 ops/s | 3.68 ms | 5.38 ms |
| 1,024 | 58.1 ms | 17,612 ops/s | 3.20 ms | 5.73 ms |
| 4,096 | 210.0 ms | 19,507 ops/s | 2.89 ms | 3.75 ms |

Elapsed ranges were 14.2-28.4 ms, 51.5-58.3 ms, and 209.4-219.4 ms
respectively. The median 4,096-object lane is about 93.4x faster. A 16x
object-count increase now takes 12.3x elapsed time rather than 284x, closing
the observed near-quadratic hot-path blocker in this measured range.

### Object-Count Scale Evidence

The fixed scale recipes run the release binary three times by default. Each run
writes through the commit coordinator, discards the writer-side repository,
constructs a new repository instance over the same accepted store and anchor,
checks exact prefix cardinality, and reads the first, middle, and last payload.
This keeps a fast write path from masking an unrecoverable repository.

```sh
just perf-scale-10k
just perf-scale-100k
just perf-scale-1m
```

The July 11 ciphertext-only-pack and direct-descriptor rerun produced three
passing release runs per tier. These numbers predate automatic packed-run
compaction and remain direct-descriptor regression evidence, not evidence for
the current compaction schedule:

| Tier | Batch | Result | Elapsed range | Checkpoint range | Reload range | Commit PUTs | Write amplification |
| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 10k | 64 | Pass, 3/3 | 584-601 ms | 197-201 ms | 99-117 ms | 158 | 1.442421x |
| 100k | 1,024 | Pass, 3/3 | 7.30-7.43 s | 2.163-2.275 s | 1.185-1.336 s | 99 | 1.393577x |
| 1M | 1,024 | Pass, 3/3 | 92.27-93.40 s | 25.95-26.86 s | 15.53-15.74 s | 978 | 1.393424x |

The main backend counts and elapsed time include the signed checkpoint PUT and
the checkpoint candidate's internal new-reader verification. The separately
reported reload is excluded from those counts and time. It discards writer-side
state, reloads from the accepted anchor through another same-process repository
instance, verifies exact cardinality, and reads the first, middle, and last
payload. The JSON/TSV artifact records both the requested and actual checkpoint
position. The historical 1,024-item bulk lane uses the same ciphertext-only pack
format; the normal low-latency default remains 64. These pre-maintenance runs
were below the former 1.50x checkpoint-only ceiling. That ceiling was not a
valid lifetime gate once automatic compaction landed. The current wire-v6
recipes retain 1.50x for the 64-item 10k lane and require 1.30x for the
4,096-item 100k and 1M low-amplification lanes. They also fail above
1.04x cold-read byte amplification or one backend request per cold sentinel.
Every run measured exactly three range `GET`s for three sentinel reads and
1.03125x cold-read byte amplification.
The current automatic policy starts at 256 active runs, selects at most the
oldest 128 level-0 runs per pass, and preserves newer level-0 and existing
level-1 shards. Scale reports include `active_index_runs` after fresh recovery
and fail above 255 after the final checkpoint. The harness also records process
high-water RSS and aggregates all gate failures after printing the report.

On 2026-07-12 revision `7023c65` passed three release runs with
1,000,000 512 B objects, batch and concurrency 1,024:

| Run | Elapsed | Recovery | Reload total | Peak RSS | PUT | GET | HEAD | Active runs | Write amplification | Cold read |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 39.135 s | 7.559 s | 7.587 s | 1,953,775,616 B | 1,008 | 3,433 | 806 | 233 | 1.602593008x | 1 GET/read, 1.03125x |
| 2 | 45.049 s | 7.822 s | 7.863 s | 1,953,808,384 B | 1,008 | 3,433 | 806 | 233 | 1.602593008x | 1 GET/read, 1.03125x |
| 3 | 42.664 s | 6.364 s | 6.391 s | 1,953,574,912 B | 1,008 | 3,433 | 806 | 233 | 1.602593008x | 1 GET/read, 1.03125x |

Every run performed six bounded metadata-only compactions, passed the
180-second write/checkpoint, 30-second reload, and 4 GiB resource ceilings,
recovered exactly one million list entries, and verified first, middle, and last
payload bytes. Removing the unused v02 prefix-token projection, sharing ordered
path keys, and structurally sharing exact carrier facts reduced a same-host
100k sample from 282,611,712 B to 193,286,144 B peak RSS and from 823.807 ms to
468.2 ms reload. The process high-water values include the complete in-memory
backend, not only trusted gateway state.

The same revision passed three controlled local-filesystem runs with separate
writer and fresh reader processes:

| Run | Writer elapsed | Checkpoint | Writer RSS | Reader recovery | Reader verification | Reader RSS |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 46.623 s | 7.546 ms | 958,234,624 B | 6.094 s | 6.136 s | 1,138,118,656 B |
| 2 | 44.707 s | 7.157 ms | 957,411,328 B | 6.607 s | 6.647 s | 1,137,709,056 B |
| 3 | 46.835 s | 8.062 ms | 957,632,512 B | 6.009 s | 6.047 s | 1,138,057,216 B |

Every filesystem run recovered the exact million entries and 233 active runs,
and retained the one-GET, 1.03125x cold-read shape. Counts were 1,008 PUTs,
3,433 GETs, and 806 HEADs; the backend recorded 820,502,647 B written,
258,733,774 B read, and 1.602544232x write amplification. This is local
separate-process repository RSS excluding an in-memory backend, not an HTTP
gateway measurement, pinned release-runner timing, or retained-provider
qualification.

Revision `b8b78be` raises the bounded payload-pack and speculative-
overlay ceiling to 4,096 records. At one million unique 512 B objects this
produces 245 runs, below the 256-run compaction trigger, and avoids rewriting
index metadata merely to satisfy the 255-run recovery gate. Three in-memory
release runs produced identical byte and request accounting:

| Run | Elapsed | Recovery | Reload total | Peak RSS | PUT | GET | HEAD | Active runs | Write amplification |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 45.553 s | 5.101 s | 5.141 s | 1,680,826,368 B | 246 | 253 | 248 | 245 | 1.268292436x |
| 2 | 44.902 s | 5.013 s | 5.051 s | 1,681,043,456 B | 246 | 253 | 248 | 245 | 1.268292436x |
| 3 | 44.639 s | 5.056 s | 5.095 s | 1,681,162,240 B | 246 | 253 | 248 | 245 | 1.268292436x |

Three fresh-process ext4 runs of the same committed revision recorded
47.488-48.313 s writer time, 955,772,928-956,428,288 B writer RSS,
5.389-5.558 s recovery, 1,009,971,200-1,010,356,224 B reader RSS,
1.268284240x writes, exact million cardinality, 245 active runs, and one exact
528 B range `GET` per 512 B sentinel. Pinned-runner timing still needs a release
repetition.

### Bounded HTTP full-read evidence

Revision `c51aa24` adds a Docker-free real HTTP gateway lane whose RSS field is
the release gateway child, not the xtask driver. Three runs of three complete
256 MiB restores produced:

| Run | Elapsed, 3 reads | Average read | Plaintext throughput | Gateway peak RSS | Backend GETs | Read amp |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 2.058 s | 664.972 ms | 373.240 MiB/s | 564,801,536 B | 3 | 1.000244420x |
| 2 | 1.894 s | 614.531 ms | 405.552 MiB/s | 564,396,032 B | 3 | 1.000244420x |
| 3 | 1.792 s | 581.727 ms | 428.565 MiB/s | 564,342,784 B | 3 | 1.000244420x |

Each run used exactly one backend GET per restore and read 805,503,201 B for
805,306,368 B of plaintext. The in-memory backend and streamed upload
high-water are included in the gateway RSS, so this qualifies the real HTTP
path, child-process accounting, request shape, and byte amplification. It does
not qualify external-provider memory behavior. Container-backed attempts
failed during RustFS and MinIO readiness before rs3 started, so those attempts
provide no product evidence.

### Payload-size evidence

The same release binary, final signed checkpoint, new-instance reload, exact
cardinality check, and sentinel reads were run three times for two additional
payload sizes:

| Objects | Object size | Batch | Result | Elapsed range | Checkpoint range | Reload range | PUTs | Write amplification |
| ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 10,000 | 4 KiB | 64 | Pass, 3/3 | 806-859 ms | 197-210 ms | 106-142 ms | 158 | 1.055425x |
| 1,024 | 256 KiB | 64 | Pass, 3/3 | 1.85-1.90 s | 10.0-17.7 ms | 8.6-8.8 ms | 17 | 1.001081x |

All six runs used one exact range `GET` per cold sentinel. Cold-read byte
amplification was 1.00390625x for 4 KiB records and 1.000244140625x for 256 KiB
records.

Representative commands, repeated three times, were:

```sh
target/release/xtask perf --scenario write-committed-parallel --objects 10000 --object-size 4096 --commit-batch-items 64 --commit-max-pending-items 64 --concurrency 64 --verify-reload --checkpoint-after-objects 10000 --max-write-amp 1.15 --max-cold-read-amp 1.01 --max-cold-read-requests-per-read 1.0 --format jsonl
target/release/xtask perf --scenario write-committed-parallel --objects 1024 --object-size 262144 --commit-batch-items 64 --commit-max-pending-items 64 --concurrency 64 --verify-reload --checkpoint-after-objects 1024 --max-write-amp 1.03 --max-cold-read-amp 1.001 --max-cold-read-requests-per-read 1.0 --format jsonl
```

## Current July 2026 Larger Restore Matrix

Run date: 2026-07-13. Clean revision: `e35545f`. Gateway profile: release.
Payload segment lane: adaptive writer default. Each row is the average of three
alternating direct/gateway pairs from one bounded candidate profile.

`workload_consistency` and `regression_budgets` both passed with no failures.

| Profile | Direct elapsed | Gateway elapsed | Elapsed ratio | Backend requests | Backend reads | Backend writes | Restore ratio | Gateway CPU | Gateway HWM RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| medium-restore | 3.08 s | 3.26 s | 1.06x | 1.06x | 1.01x | 1.00x | 0.68x | 1.01 s | 169.25 MiB |
| kubernetes-objects | 10.19 s | 3.16 s | 0.31x | 0.06x | 1.02x | 1.00x | 0.11x | 1.14 s | 150.08 MiB |
| kubernetes-objects-large | 35.24 s | 10.34 s | 0.29x | 0.03x | 1.01x | 1.00x | 0.19x | 3.17 s | 336.89 MiB |
| postgres-pgdata | 2.74 s | 4.17 s | 1.52x | 0.99x | 1.04x | 1.00x | 0.77x | 2.74 s | 438.50 MiB |
| postgres-pgdata-large | 4.14 s | 6.70 s | 1.62x | 1.00x | 1.04x | 1.00x | 0.65x | 5.47 s | 633.88 MiB |

Every expanded budget passed. Larger profiles now fail above 1.75x total
elapsed or 1.25 GiB average HWM RSS in addition to the existing request, byte,
restore, and stability gates. The Postgres-shaped profiles restore faster
through the gateway but remain slower end to end because snapshot creation and
commit publication dominate.

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
and medium profiles. The historical many-small-files profile was the edge case,
but the fixed 512 B segment lane now reads 1.72x backend bytes instead of 4.54x
because repeated tiny client ranges are served from cached ciphertext spans.

Wall-clock results are favorable for the gateway in this local setup, but they
are less portable than request and byte ratios. Treat them as a regression
signal for this harness, not as a general cloud-provider result.

## May 2026 Larger Restore Matrix

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
ratios for the small and larger profiles. Larger profiles also gate restore and
total elapsed ratios, repeated-run stability, and average gateway HWM RSS. The
fixed 512 B `many-small-files` lane checks that read bytes stay below 2.00x,
write bytes below 2.25x, and requests below 0.50x.

## Segment-Size Sweep

Run date: 2026-05-03. Workload: `many-small-files`, because it was the historical
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
Older in-process committed-write measurements used the removed v1 repository
stack and are historical only. After the perf harness port to v2, refresh
`just perf-commit` and `just perf-commit-parallel` before using those local
lanes as a baseline.

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
