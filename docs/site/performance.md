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
`.local/integration/` and should stay out of Git unless deliberately reviewed
and promoted.
The command prints a compact table by default; pass
`--print-summary-json` when a caller needs the full JSON on stdout.

## July 2026 Lightweight Rerun

A 2026-07-10 release-profile smoke reran the lightweight in-memory,
filesystem, and gateway paths after dependency remediation. The current tree
showed no material regression in the 16-object lane. This was one run per lane,
so it is a regression smoke rather than a release performance claim.

The current in-memory lane recorded 186.544 ms for 16 sequential committed
writes and 3.628 ms for the parallel batched form. Full reads took 0.704 ms and
512 B range reads took 0.147 ms. The final release gateway lane after the S3
client replacement recorded 257.191 ms, 25.407 ms, 18.929 ms, and 30.722 ms
for those scenarios respectively. Request
and byte ratios were consistent between the in-memory and gateway lanes.

A parallel committed-write growth sweep exposed a release blocker. Before the
write-state remediation, it measured:

| Objects | Elapsed | Throughput | Average latency | p99 latency |
| ---: | ---: | ---: | ---: | ---: |
| 256 | 69 ms | 3,705 ops/s | 10.8 ms | 22.7 ms |
| 1,024 | 818 ms | 1,252 ops/s | 28.4 ms | 88.3 ms |
| 4,096 | 19.61 s | 209 ops/s | 161.3 ms | 655.2 ms |

A 16x object-count increase produced about 284x elapsed time. The write path
was changed to retain bounded per-mutation undo records, apply accepted deltas
incrementally, resolve newly accepted payloads from the pending delta, and
update normal PUT list projections without a namespace scan. A final
three-run release-binary sweep after all blocker remediations measured these
medians:

| Objects | Elapsed | Throughput | Average latency | p99 latency |
| ---: | ---: | ---: | ---: | ---: |
| 256 | 17.0 ms | 15,019 ops/s | 3.68 ms | 5.38 ms |
| 1,024 | 58.1 ms | 17,612 ops/s | 3.20 ms | 5.73 ms |
| 4,096 | 210.0 ms | 19,507 ops/s | 2.89 ms | 3.75 ms |

Elapsed ranges were 14.2-28.4 ms, 51.5-58.3 ms, and 209.4-219.4 ms
respectively. The median 4,096-object lane is about 93.4x faster and the 16x
object-count increase now takes 12.3x elapsed time. This closes the observed
near-quadratic hot-path blocker in the measured range. The stable scale recipes
now require a fresh repository reload, exact list cardinality, and full reads
of the first, middle, and last object after every write run. The exact commands
and amplification ratios are recorded in `tests/PERFORMANCE_BASELINE.md`.

The 10k gate passes all three release-profile runs. Write elapsed time was
521-537 ms, fresh reload was 420-433 ms, each run used 157 commit PUTs, and
write amplification was 12.734-12.736x for 512 B objects. The 100k tier writes
successfully but fresh reload fails closed with `v2 recovery replay budget
exceeded`; the 1M tier reaches the same recovery failure. Consequently, 100k
and 1M repository recovery remain production blockers. A successful write-only
million-object run is not accepted as scale evidence.

These measurements were collected against the now-removed `commits/v01`
generation. The transitional `commits/v02` envelope now authenticates index
sections independently and no longer scans payload ciphertext during recovery,
but it retains the prototype delta/snapshot chain and fixed replay-depth budget.
The 100k and 1M tiers must therefore be rerun and are not qualified by the
generation change. Final `v02` qualification must use a fresh process and verify
exact listing cardinality plus first, middle, and last object bytes. Its
descriptor-first reader must retain no cumulative encrypted delta set, read no
payload sections merely to rebuild the index, and use at most 1.25x the index
material required by the accepted catalog. On the documented pinned 4-vCPU,
16-GiB runner, the 1M filesystem recovery budget is 180 seconds and 4 GiB RSS.
Correctness, request, byte, allocation, and amplification bounds apply on every
runner; absolute time gates apply only to pinned runners.

## Current Release Matrix

Run date: 2026-07-10. Gateway profile: release. Payload segment lane:
adaptive writer default. Workload set: `larger-restores`. Each row is the
average of three direct/gateway run pairs. The direct baseline is the straight
RustFS measurement proxy.

Raw artifact: retained as ignored local release evidence.

`workload_consistency` passed for every profile and `regression_budgets` passed.

| Profile | Shape | Elapsed Ratio | Backend Requests | Backend Reads | Backend Writes | Gateway CPU | Gateway HWM RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `medium-restore` | one 64 MiB object | 1.01x | 0.51x | 1.01x | 1.00x | 0.81 s | 146.26 MiB |
| `kubernetes-objects` | 1,536 manifests plus a 32 MiB fragment | 0.30x | 0.03x | 1.02x | 1.01x | 0.83 s | 128.83 MiB |
| `kubernetes-objects-large` | 6,144 manifests plus a 128 MiB fragment | 0.28x | 0.02x | 1.01x | 1.00x | 2.33 s | 273.13 MiB |
| `postgres-pgdata` | 96 relation files, 4 WAL segments, and an 8 MiB dump | 1.26x | 0.75x | 1.04x | 1.00x | 2.22 s | 420.39 MiB |
| `postgres-pgdata-large` | larger relation/WAL/dump-shaped Postgres data directory | 1.39x | 0.83x | 1.04x | 1.00x | 4.20 s | 685.06 MiB |

Interpretation:

- Larger restore write bytes stay at about the straight proxy baseline, and
  read bytes stay within about 1.01x to 1.04x in this run.
- Backend request counts are below the straight proxy baseline for every larger
  profile in this run. The lowest ratios are the Kubernetes-shaped profiles,
  where the gateway's accepted index and decrypted segment cache avoid many
  repeated direct-backend reads.
- Built-in regression budgets passed for request ratios, byte ratios, restore
  phase ratios, and repeated-run stability.
- The Kubernetes-shaped profile had shorter elapsed time in this local harness
  despite similar backend bytes. Treat that as a local RustFS/proxy
  observation, not a cloud provider claim.
- Postgres-shaped restore phases had shorter elapsed time than the direct path
  in this local harness, but full elapsed time is slower because commit
  publication and snapshot-create phases dominate the local run. Keep tracking
  commit wait, stage-lock wait, and large PUT phases. Average commit wait rose
  from 53 ms in `medium-restore` to 383 ms in `postgres-pgdata-large`; average
  stage-lock wait rose from effectively zero to 79 ms.

## Expanded Sanity Run

Run date: 2026-05-04. Gateway profile: release. One direct/gateway run pair per
profile, so this historical artifact validated shape and budget wiring before
the five-profile release matrix above.

Raw artifact: retained as ignored local release evidence.

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
fewer commit PUTs. Payload sections now carry per-payload identities, so range
reads can verify and decrypt the requested payload segments without reading the
whole commit body. New v2 refs carry payload-header facts plus the padded
commit section offset, so hot-path range reads fetch only the required
ciphertext span. Repeated or concurrent overlapping ranges reuse the decrypted
segment cache behind a striped per-payload fill gate, so independent payloads
can still fill in parallel. Full-file reads fetch the named payload section.
Older refs still fall back to bounded commit-header and payload-header probes.
Large streaming PUTs serialize writes while the gateway reads the request body
into the signed multipart commit. `RS3_STREAM_READ_STALL_TIMEOUT_SECS` bounds
how long one stalled client body can hold that write path before the request
fails as incomplete.
The default partial commit-batch wait is now 25 ms. A 2026-05-17 local gateway
smoke recorded the current medium-object shape: sequential 256 KiB writes used
1.0 backend requests per client write, parallel batched writes used 0.125
requests per client write, full reads used 0.016 requests per client read after
cache fill, and 4 KiB range reads used 0.063 requests per client read. Large
67,108,865 B known-length and chunked unknown-length PUTs both used one commit
PUT plus one retained-profile preflight `HEAD`; write-byte amplification was
1.0004x. Eight 4 KiB ranges from a large object used one backend range `GET`
after cache fill, with 2.0005x read-byte amplification from the 64 KiB adaptive
payload segment. The raw JSONL artifacts are retained as ignored local release
evidence and should be copied to release assets only after review.

A local Velero/Postgres smoke on 2026-05-16 exercised the concurrent restore
path after v2 payload-section cache fills were coalesced. The gateway run
completed backup and restore with `v2-preview`, emitted no backend `segments/`
objects, and read 29.0 MB from the backend versus 28.9 MB for the direct RustFS
baseline. Backend request count was lower through the gateway in that smoke:
57 requests versus 708 for direct RustFS. Raw local summaries remain ignored
workspace evidence unless deliberately promoted to a release asset.
Treat this as Velero smoke evidence. The broader release-profile ratios still
come from the Kopia measured matrix above until that matrix is refreshed after
the v2 range-read change.

The three-run 2026-05-16 Kopia matrix after payload-ref metadata, striped v2
range-fill coordination, and 25 ms batching passed budgets. Restore-phase
ratios were 0.04x to 0.65x; full elapsed remained slower for the Postgres
profiles because local commit publication and snapshot-create phases dominated.

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
  retained-version lane remains repeatable.
