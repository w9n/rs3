# Performance

The [September 9 history experiment](#retained-history-experiment-september-9-2026)
identifies a default maintenance-budget limit below the format's history ceiling.
The live-backend comparisons below were measured on September 8.

## Backend comparison: September 8, 2026

The completed v03 comparison shows lower written bytes for local scale workloads,
but slower large uploads and PostgreSQL-shaped backups. All 120 Kopia content
checks passed. Two candidate budgets fail: sequential 512 B write amplification
and large-PostgreSQL Kopia total elapsed time. These are measured failures;
their ceilings remain unchanged.

This reference is for operators and reviewers evaluating the preview. Results
come from three samples per lane on a shared host. Measured processes were
restricted to CPUs 4-7 with a 16 GiB memory limit; Docker RustFS providers were
unrestricted. The host was not reserved or verified idle. These results do not
establish dedicated-runner or external-provider performance qualification.

### Revisions and comparisons

| Measurement | Baseline revision | v03 candidate revision |
| --- | --- | --- |
| Standalone S3 uploads and Kopia | `408a3c4` | `453c2ff` |
| Memory/filesystem scale, path lengths and small writes | `408a3c4` | `43c6914` |

Later changes through `6b6fe2a` affect qualification tooling, charts and docs;
they do not change the measured production runtime. The tables retain the
revisions actually measured. The baseline uses the preceding v02 format.

The [numerical summary](assets/performance-2026-09-08.json) contains full revision
IDs, individual sample values, aggregates and manifest/summary hashes. Promoted
records were checked against the retained raw-output hashes; container evidence
also has a completed source/binary integrity audit. Raw logs and build receipts
remain local evidence and are not included in that download.

Two comparisons have different meanings:

- **Candidate versus baseline revision:** compares rs3 before and after the
  rewrite using the same workload. Tables report medians and `[min, max]`.
- **Kopia gateway versus direct RustFS:** compares Kopia through rs3 with Kopia
  through the measurement-only forwarding proxy in the same revision. The
  elapsed budget uses the arithmetic mean of three paired ratios, not the
  ratio of revision medians.

## Retained-history experiment: September 9, 2026

Both controlled 10,000-write workloads restore three sampled historical points
after deletion, repository reopen, and retention renewal. They then reject those
points after authenticated expiry and verify eventual physical GC.
These runs exercise the retained-version profile and the 30-day recovery preset.
Each write publishes a separate 512 B value; automatic metadata compaction adds
commits. One workload repeatedly overwrites one key; the other adds distinct
keys. Both delete the latest value before the maintenance checks.

**At 100,000 writes, both workloads fail the full history walk with
`MaintenanceBudgetExceeded`.** Writes, repository reopen, and three sampled
historical restores succeed first. The larger runs stop at that failure, so
renewal and GC are not qualified at 100,000 writes. The 4.2-million-point format
ceiling is not an operating-capacity claim.

A separate 55,000-overwrite diagnostic isolates the **256 MiB graph-metadata
budget**: the default walk fails, while changing only that budget to 512 MiB
allows the same graph to finish with 272.98 MiB accounted. A fresh writer using
the default budget refuses its next publication before any backend PUT or anchor
advance. Cached coverage can therefore permit growth that a later maintenance
pass or restarted writer cannot handle under the default budget. The diagnostic
does not qualify a larger production configuration or change any runtime limit.

| Measurement at 10,000 writes | Overwrite | Append |
| --- | ---: | ---: |
| Accepted points before expiry, including current | 10,081 | 10,081 |
| Stored bytes after deletion and checkpoint, MiB | 77.45 | 80.43 |
| Referenced payload ciphertext, MiB | 5.04 | 5.04 |
| Body bytes read by one full history graph scan, MiB | 75.00 | 77.97 |
| Accounted graph metadata, MiB | 49.54 | 49.89 |
| Highest observed whole-process RSS, MiB | 138.07 | 177.19 |
| Stored bytes after physical GC, MiB | 0.66 | 28.56 |

| Measurement at 100,000 writes | Overwrite | Append |
| --- | ---: | ---: |
| Anchor sequence after deletion and checkpoint | 100,784 | 100,801 |
| Stored bytes before the failed history scan, MiB | 826.08 | 3,009.57 |
| Body bytes written during growth, MiB | 824.40 | 3,004.79 |
| Body bytes read during growth, MiB | 1,422.38 | 5,743.60 |
| History scan | Budget refusal | Budget refusal |

Submitted plaintext totals 48.83 MiB at 100,000 writes. These are serial,
one-write-per-commit workloads; concurrent batching can reduce history point
counts. The append workload also retains more metadata from index compaction.
Growth counters include automatic compaction and verification, and exclude the
final deletion, forced checkpoint, and diagnostic maintenance scans.

Submitted plaintext totals 4.88 MiB in each workload. The overwrite workload
ends with no live values; append retains 9,999. Most stored bytes before expiry
are commit, index, and recovery metadata. All payload ciphertext remains
referenced through history at that point. Quick reporting, full GC planning,
and renewal each independently traverse that history, so repeated scans add
substantial read traffic even when few retention extensions are needed.

Logical expiry and physical reclamation are separate observations. The expiry
publication can renew the previous accepted graph before advancing the anchor.
These runs reclaim objects only after crossing observed physical lock deadlines,
with another renewal keeping current dependencies protected in the meantime.
They do not establish the earliest possible reclamation time.

The production implementation is based on `0eb5064`; the harness only changes
tests. These are single release-build runs using a controlled in-memory provider
and simulated time, without the HTTP gateway or Kubernetes. A reopen constructs
a new repository instance in the same process. RSS includes the provider,
driver, and allocator state and excludes swapped-out pages. The shared host was
under memory pressure. Graph accounting is a conservative byte budget,
not allocator measurement. Body-byte counters exclude HEAD/LIST response
metadata, transport framing, and provider-internal retries. These measurements
do not establish live-S3 throughput, isolated gateway RAM, or production capacity.

The [numerical record](assets/history-capacity-2026-09-09.json) includes phase
counters, failure outcomes, and hashes binding both harness versions, binaries,
and raw logs. Raw logs remain local run evidence.

To repeat one workload inside `nix develop`:

```sh
RS3_HISTORY_SCALE_WRITES=10000 RS3_HISTORY_SCALE_MODE=overwrite \
  CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=4 cargo test -p rs3-repository \
  --release --lib recovery_history_scale -- --ignored --nocapture --test-threads=1
```

Use `append` for the other mode and run each in a separate process. Successful
runs end with a `HISTORY_SCALE` record whose phase is `complete`. Phase records
include cumulative counters so setup and verification traffic remain visible.
Failures retain the last completed phase and fail the test; increasing the
requested count does not increase production budgets.
For the budget-isolation diagnostic, set `RS3_HISTORY_SCALE_WRITES=55000` and
`RS3_HISTORY_SCALE_DIAGNOSE=1` with `overwrite`. It also tries one read-only graph
walk with a 512 MiB metadata budget and checks fresh-writer refusal under the
default. The test still exits unsuccessfully to preserve the default-budget
failure, even when those diagnostic checks succeed.

## Large uploads

Each command writes eight objects of 67,108,865 bytes each (512 MiB plus eight
bytes), using a release build and a disposable RustFS backend. Gateway lanes
vary concurrent client writes. The repository API lane talks to S3 without the
HTTP gateway; it still performs rs3 encryption, publication and verification.
It is distinct from Kopia's direct forwarding-proxy baseline.

Throughput is aggregate plaintext MiB/s; higher is better. RSS is the median
process high-water mark in MiB: gateway child for gateway lanes, repository
process for the direct API lane. The direct process includes its driver state.

| Path / concurrency | Baseline MiB/s [min, max] | Candidate MiB/s [min, max] | Throughput change | RSS MiB baseline / candidate |
| --- | ---: | ---: | ---: | ---: |
| Gateway / 1 | 176.96 [172.75, 178.09] | 147.20 [144.87, 149.46] | -16.8% | 87.8 / 103.4 |
| Gateway / 2 | 300.80 [299.06, 306.59] | 257.35 [256.49, 258.17] | -14.4% | 150.7 / 136.8 |
| Gateway / 4 | 479.09 [468.98, 480.97] | 416.09 [401.32, 416.97] | -13.1% | 157.4 / 171.2 |
| Gateway / 8 | 636.52 [301.49, 658.18] | 566.49 [565.75, 568.04] | -11.0% | 246.7 / 222.8 |
| Repository API / 8 | 411.99 [405.69, 417.82] | 274.51 [190.86, 285.53] | -33.4% | 422.7 / 429.6 |

All 30 standalone commands pass their absolute limits. The separate concurrency
scaling check fails in one baseline repetition: 301.49 / 178.09 = 1.69x,
below the required 2x. The other two baseline repetitions and all three
candidate repetitions pass. The slow baseline sample remains in the range.

Candidate gateway backend write amplification is 1.000269x and verification-read
amplification is 1.000244x. Total write-path I/O is approximately 2.000514x:
one ciphertext upload and one complete verification read before publication.
Verification reads are reported separately from written bytes.

Gateway throughput medians decline 11-17%; the direct repository lane declines
33%, with substantial spread. Source inspection identifies added plaintext MD5
and gateway checksum work, but no causal CPU profile was taken. Neither
checksum cost nor noisy neighbors is established as the complete explanation.

## Kopia backup and restore

Five workload profiles ran three alternating direct/gateway pairs per revision.
The elapsed column measures the complete client workload, excluding gateway
startup. Backup means `snapshot-create`; repository creation is measured
separately. Restore is the client restore phase. Phase medians need not sum to
the median total. Times below are milliseconds; lower is better.

| Profile | Baseline elapsed [min, max] | Candidate elapsed [min, max] | Candidate / baseline | Backup median baseline / candidate | Restore median baseline / candidate |
| --- | ---: | ---: | ---: | ---: | ---: |
| `medium-restore` | 1,944.00 [1,920.00, 2,132.00] | 1,969.00 [1,963.00, 1,969.00] | 1.013x | 1,162 / 1,220 | 292 / 280 |
| `kubernetes-objects` | 2,099.00 [2,097.00, 2,187.00] | 2,250.00 [2,130.00, 2,258.00] | 1.072x | 911 / 950 | 725 / 783 |
| `kubernetes-objects-large` | 7,924.00 [7,914.00, 8,198.00] | 8,129.00 [8,080.00, 8,130.00] | 1.026x | 1,907 / 2,071 | 5,485 / 5,516 |
| `postgres-pgdata` | 2,939.00 [2,688.00, 3,503.00] | 3,715.00 [3,395.00, 4,416.00] | 1.264x | 2,210 / 2,985 | 250 / 257 |
| `postgres-pgdata-large` | 4,782.00 [4,731.00, 5,227.00] | 6,519.00 [6,462.00, 6,650.00] | 1.363x | 3,827 / 5,545 | 417 / 425 |

The large-PostgreSQL gateway workload is 36.3% slower by revision median. Its
backup phase rises from 3,827 to 5,545 ms; restore remains close at 417 versus
425 ms. Its average gateway/direct elapsed ratio is **1.904731x**, exceeding
the **1.75x** budget. This is the candidate's only failed Kopia budget; baseline
Kopia passes all budgets. Both revisions pass 60/60 content checks each.

Backend counts and bytes below are medians per gateway run. Gateway request
counts use backend operation counters; the direct proxy counts HTTP requests.
They do not separately expose every multipart HTTP request. MiB is 1,048,576
bytes. RSS is sampled gateway high-water memory and excludes the client/proxy.
The last column uses the candidate's own paired direct RustFS reference.

| Profile | Requests baseline / candidate | Written MiB baseline / candidate | Read MiB baseline / candidate | RSS MiB baseline / candidate | Candidate gateway / direct elapsed mean |
| --- | ---: | ---: | ---: | ---: | ---: |
| `medium-restore` | 92 / 92 | 64.09 / 64.09 | 64.72 / 64.72 | 156.9 / 161.8 | 0.971546x |
| `kubernetes-objects` | 96 / 96 | 33.05 / 33.05 | 33.29 / 33.29 | 127.3 / 133.9 | 0.238663x |
| `kubernetes-objects-large` | 165 / 167 | 132.02 / 132.02 | 132.80 / 132.74 | 259.8 / 247.1 | 0.243661x |
| `postgres-pgdata` | 205 / 208 | 168.17 / 168.15 | 174.77 / 174.77 | 266.2 / 283.9 | 1.724441x |
| `postgres-pgdata-large` | 344 / 353 | 352.30 / 352.25 | 365.67 / 365.67 | 376.6 / 394.3 | 1.904731x |

Kubernetes-shaped profiles perform better than the direct proxy in this local
setup. That observation does not predict a cloud backend's latency or throughput.
The workload source-tree sizes and all direct-reference metrics are in the
numerical summary.

## Local scale and path-length costs

All 42 commands in the three-sample memory/filesystem comparison pass their
absolute gates. These repository-level Dev-profile workloads exclude automatic
retained recovery history and do not measure the HTTP gateway. Memory-backend
RSS includes the simulated backend. Filesystem writer and reader are separate
processes; a fresh reader does not imply a cold kernel page cache.

Each row reports baseline / candidate medians. Scale and path rows use 512 B
values; the compaction row uses 1 KiB values and 16-object batches, with three
actual compactions per sample. The 1M lanes use 4,096-object batches and end
with 245 active runs. Exact inputs and sample ranges are in the numerical summary.

| Workload | Elapsed ms baseline / candidate | Written MiB baseline / candidate | Peak RSS MiB baseline / candidate |
| --- | ---: | ---: | ---: |
| 10k objects | 116.35 / 133.10 | 6.425 / 6.215 | 30.16 / 33.18 |
| 10k + compaction | 189.43 / 217.11 | 12.951 / 12.618 | 46.32 / 50.08 |
| 10k, 32 B paths | 115.51 / 131.72 | 6.293 / 6.205 | 29.79 / 32.82 |
| 10k, 256 B paths | 131.91 / 140.16 | 8.583 / 6.382 | 36.61 / 35.32 |
| 10k, 1,024 B paths | 185.84 / 169.39 | 16.367 / 6.957 | 59.86 / 44.09 |
| 1M, memory | 28,262.40 / 31,619.56 | 619.283 / 598.410 | 1609.80 / 1798.38 |
| 1M, filesystem writer | 29,369.11 / 33,185.68 | 619.279 / 598.406 | 917.70 / 1147.56 |
| 1M, filesystem reader recovery | 3,152.63 / 3,496.22 | n/a | 969.24 / 1135.94 |

At 1M objects, written bytes fall about 3.4%, while writer elapsed time rises
12-13%. Filesystem writer RSS rises 25%. The 1,024 B path lane improves elapsed
time by 8.9%, written bytes by 57.5%, and RSS by 26.3%. Lower write volume does
not imply faster execution for every workload.

## Small-write budgets

These candidate-only results use `43c6914`, three samples, 64 objects, and exact
32 B logical paths. Counters start after genesis; no final checkpoint is added.
Batched lanes publish all 64 objects together. The sequential lane waits for
each accepted commit before starting the next write. Write amplification counts
backend bytes written divided by plaintext bytes, excluding verification reads.
Empty values use bytes per object because their plaintext denominator is zero.

| Workload | Measured | Ceiling | Result |
| --- | ---: | ---: | --- |
| Empty batch | 105.734375 B/object | 320 B/object | Pass |
| 4 KiB batch | 1.031673x | 1.15x | Pass |
| 256 KiB batch | 1.000689x | 1.03x | Pass |
| Sequential 512 B writes | 3.918274x | 3x | **Fail** |

The sequential lane writes 128,394 bytes for 32,768 bytes of plaintext,
or 2,006.156 bytes per object. All three samples fail the unchanged 3.0x ceiling.
This deterministic format overhead is separate from timing variability.
Checkpoint-and-compaction-inclusive lifetime costs use separate scale counters.

## Reproduce the measurements

Enter `nix develop` and use a clean committed checkout. The recipes retain
failed samples and enforce their existing gates:

```sh
just perf-small-workloads .local/perf/my-small-run
just perf-standalone-gate
just perf-kopia-profile-candidate postgres-pgdata-large
just perf-scale-10k
just perf-scale-10k-compaction
just perf-scale-path-matrix
just perf-scale-1m
just perf-scale-fs-1m .local/perf/my-filesystem-run
```

Run each listed Kopia profile for complete coverage. For a revision comparison,
use the same inputs, compiler/build profiles, provider image and resource limits
on both revisions, with at least three samples. The commands alone do not
reserve CPUs or constrain Docker provider containers. Keep build work outside
timed intervals; qualification recipes prebuild their gateway/proxy artifacts.
The paired comparison also prebuilt the direct S3 repository harness separately.

The built-in Kopia reference sends requests unchanged through
`rs3-integration-storage-proxy` to RustFS, recording provider traffic. It measures
a different path from the standalone repository API companion. Preserve that
distinction when comparing ratios.

## Remaining qualification and older evidence

The current measurements leave the two candidate budget failures above open.
Further provider, retained-history and dedicated-runner timing qualification
must retain its own revision and environment evidence. Correctness/retention
acceptance is described separately in [Testing](testing.md) and
[Production Preview](production-preview.md); it does not erase a performance miss.

[Earlier performance notes](https://github.com/w9n/rs3/blob/6b6fe2a99842dd53549f222337ed120b0fc4d954/docs/site/performance.md)
remain in Git history. Their July and May numbers are historical evidence and
must not be presented as this v03 candidate's measurements.
