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
near-quadratic hot-path blocker in the measured range. The lightweight scale
recipes now require a new repository instance, exact list cardinality, and full
reads of the first, middle, and last object after every write run. The exact
commands and amplification ratios are recorded in
`tests/PERFORMANCE_BASELINE.md`.

Earlier 10k, 100k, and 1M release runs established the direct-descriptor
baseline before automatic packed-run compaction:

| Objects | Batch | Median elapsed | Median checkpoint | Median fresh reload | PUTs | Write amp |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10,000 | 64 | 588 ms | 198 ms | 107 ms | 158 | 1.44242x |
| 100,000 | 1,024 | 7.35 s | 2.169 s | 1.203 s | 99 | 1.39358x |
| 1,000,000 | 1,024 | 92.48 s | 26.37 s | 15.55 s | 978 | 1.39342x |

The current lane keeps one accepted state plus a bounded 1,024-mutation overlay,
shares cloned identifier storage, uses canonical varints for v02 run generation
and length fields, and validates catalog-only rewrites by reading back the exact
signed root and new run bytes. It does not rebuild a second complete namespace
to prove that an immutable catalog still names the same state.

On 2026-07-12 the automatic-compaction 1M lane passed three release
runs with 512 B values, batch and concurrency 1,024, the 180-second elapsed
gate, a 30-second same-process reload gate, and the 4 GiB process high-water
gate:

| Run | Elapsed | Checkpoint | Fresh reload | Peak RSS | PUT | GET | HEAD | Active runs | Write amp | Cold read |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 40.579 s | 1.972 ms | 6.412 s | 2,197,200,896 B | 1,008 | 3,433 | 806 | 233 | 1.602593008x | 1 GET/read, 1.03125x |
| 2 | 40.743 s | 2.181 ms | 6.752 s | 2,197,594,112 B | 1,008 | 3,433 | 806 | 233 | 1.602593008x | 1 GET/read, 1.03125x |
| 3 | 41.200 s | 4.308 ms | 6.955 s | 2,197,561,344 B | 1,008 | 3,433 | 806 | 233 | 1.602593008x | 1 GET/read, 1.03125x |

Each run performed six bounded metadata-only compactions, reloaded exactly one
million entries through a new repository instance, and verified the first,
middle, and last payload. The v02 accepted state no longer derives or retains
the legacy prefix-token projection because v02 listing uses its separate
trusted path-ordered projection. Against a same-host 100k pre-change sample,
that reduced peak RSS from 282,611,712 B to 217,219,072 B and reload from
823.807 ms to 549.552 ms without changing backend bytes, request counts, run
count, or cold-read shape. The in-memory scale process also retains the complete
simulated backend, so its high-water mark is not gateway-only memory. These
same-process results close the automatic-compaction resource gate, but do not
replace the pinned fresh-process filesystem lane.

The current layout removes the pack directory:
encrypted `INDEX_RUN` state authenticates the record's exact physical offset,
length, digest, pack facts, and historical keyring-envelope reference. After a
fresh recovery, each measured 512 B sentinel read used one exact range
`GET` for 528 B of ciphertext, or 1.03125x byte amplification. The scale recipes
enforced at most one backend request per sentinel and 1.04x byte amplification
in every run.

The removed prototype representation had previously failed the small-object
efficiency gate at roughly 12.86x for the 10k lane. Exact accounting of one
representative 64-by-512 B prototype batch found 420,919 backend bytes, or
12.845x:

| Component | Bytes | Bytes per client object |
| --- | ---: | ---: |
| Padded commit header | 8,192 | 128 |
| Encrypted payload sections | 38,400 | 600 |
| Encrypted index section | 374,327 | 5,849 |

The payload cryptography contributed 512 B ciphertext, one 16 B tag, and a
72 B repeated header per object. The dominant failure was the index: its
104,735 B encrypted content expanded into a 374,301 B outer JSON representation
with decimal byte arrays, while each logical object repeated hex prefix tokens,
blind and manifest IDs, full commit and payload identities, key identifiers,
nonce facts, and a nested sealed manifest. Cryptography was not the source of
the 12.8x amplification; the prototype representation was.

The replacement is one value-separated `PAYLOAD_PACK` plus one compact binary
`INDEX_RUN` per batch. The release measurements, including one final signed
catalog checkpoint, recorded 1.44242x for 10k 512 B objects, 1.05542x for 10k
4 KiB objects, and 1.00108x for 1,024 256 KiB objects. The first-principles
floor for the 512 B path is about 1.2x, so the remaining gap is fixed metadata
and authenticated index material, not payload copying.
Cold sentinel reads used one exact range `GET` per record at 1.00390625x for
4 KiB records and 1.000244140625x for 256 KiB records.

Qualification must enforce, not merely report, these initial ceilings:

| Workload | Required backend write bound |
| --- | ---: |
| 64 empty objects | 320 fixed bytes per object |
| 64 objects of 512 B | 1.50x, with a 1.40x engineering target |
| 64 objects of 4 KiB | 1.15x |
| 64 objects of 256 KiB | 1.03x |
| sequential committed 512 B objects | 3.0x |
| checkpoint-and-compaction-inclusive lifetime 512 B lane | 1.65x |

The repository integration suite enforces the physical shape for a 64-object
batch (one single-PUT commit, one payload pack, and one index run) and the 1.50x
hard ceiling for a 32-byte-path lane. The release-binary scale recipes now also
publish a signed root, measure its elapsed time, reload through that root, and
include its bytes in write amplification. After reload they isolate the first,
middle, and last reads from recovery counters, require one exact range `GET`
per object, and enforce at most 1.04x cold-read byte amplification. The
longer-path matrix remains a separate gate.
The 1.50x bound remains the one-batch physical-shape gate. It was not a valid
lifetime scale ceiling because it excluded automatic maintenance; the lifetime
512 B scale gate is 1.65x.
The fixed scale recipes fail when checkpoint-and-compaction-inclusive write
amplification exceeds 1.65x, cold-read byte amplification exceeds 1.04x, or a
sentinel read uses more than one backend request, or fresh recovery reports more
than 255 active index runs; they do not merely print the ratios.

The harness must also vary logical path lengths across 32 B, 256 B, and
1,024 B, and report payload amplification separately from fixed metadata bytes
per object. Pack cleaning is measured separately because its unavoidable copy
cost depends on pack live fraction.

The raw-S3 scale lane and the client workload lane remain separate. A million
512 B S3 objects is an adversarial namespace and recovery test. It is not a
model for a million tiny Kopia source files: Kopia chunks, deduplicates, and
combines its content into larger repository packs before issuing S3 requests.
The real-client gate must therefore use unique tiny source files through
Kopia/Velero, restart from a fresh process, restore verified bytes, record the
client PUT-size histogram, and compare backend requests, bytes, RSS, and time
against the direct path.

The earlier prototype 100k and 1M tiers failed closed at the replay budget.
Those measurements used the removed `commits/v01` generation. The v02 reader's
signed `INDEX_ROOT` path now has passing in-memory 100k and 1M evidence,
including the current automatic-compaction schedule. A successful same-process
run is not final production qualification. Final `v02` qualification must also
use a fresh process and filesystem backend, and verify exact
listing cardinality plus first, middle, and last object bytes.
Its descriptor-first reader must retain no cumulative encrypted delta set, read
no payload sections merely to rebuild the index, and use at most 1.25x the index
material required by the accepted catalog. On the documented pinned 4-vCPU,
16-GiB runner, the 1M filesystem recovery budget is 180 seconds and 4 GiB RSS.
Correctness, request, byte, allocation, and amplification bounds apply on every
runner. The recipes apply generous elapsed and reload ceilings everywhere as
regression tripwires; time results qualify a release only on pinned runners.

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

For `v2-preview`, bounded payload packs and large streamed payloads live inside
signed commit objects. A streamed write now has the canonical section shape
`[PAYLOAD, INDEX_RUN]`, so it enters the same checkpoint, compaction, recovery,
and GC graph as a bounded packed write. Payload sections carry authenticated
per-payload identities and segmented-header facts, so range reads can verify and
decrypt the requested segments without reading the whole commit body. Full-file
reads fetch the named payload section.

Repeated or concurrent overlapping streamed ranges reuse the decrypted-segment
cache behind a striped per-payload fill gate. Its in-memory cache identity binds
repository/keyring context and the exact commit, version, body, section,
payload-header, and content-length facts, while AEAD still uses the actual
payload ID. This hardening changes cache correctness, not the amount of backend
data required for a cache miss. Large streaming PUTs serialize writes while the
gateway reads the request body into the signed multipart commit.
`RS3_STREAM_READ_STALL_TIMEOUT_SECS` bounds how long one stalled client body can
hold that write path before the request fails as incomplete. Checkpoint and
compaction publication are metadata-only for both packed and streamed carriers;
they preserve exact historical references instead of copying payload bytes.

Full streamed-carrier reads still verify the complete signed payload-section
digest before releasing plaintext. The current non-caching opener shares the
owning ciphertext buffer and does not retain a duplicate plaintext segment set,
so its transient data is approximately one ciphertext body plus one plaintext
body and one active segment instead of duplicate full-size ciphertext and
plaintext representations. Response memory remains proportional to object size.
Bounded-memory full responses require a verified ciphertext spool or a wire
change; they are not yet a production claim.

The 2026-05 measurements below predate the current index-run wire version 4
self/external stream-carrier model. They remain historical payload segmentation
and request-shape evidence, not performance qualification for the completed
framed-stream series. The known-length gateway rerun below checks the new write
shape. Post-checkpoint cold reads and mixed pack/stream compaction still need a
measured matrix before making a complete performance claim; EOF-finalized,
zero-length, checkpoint/reload, compaction, and GC correctness are test-backed.

A 2026-07-11 local RustFS gateway rerun covered three independent release-mode
samples of four sequential 32 MiB known-length uploads. Elapsed time was
3.853-9.856 s, plaintext throughput was 12.99-33.22 MiB/s, peak gateway RSS was
71,086,080-71,450,624 B, write amplification was 1.00067675-1.00067697x, and
each upload caused one backend commit `PUT` plus one exact read-back `GET`.
The throughput spread is too wide for a release claim, but the byte and request
shape is stable. The current S3 boundary rejects unsigned HTTP/1.1 chunked
`PutObject` without `Content-Length` with S3 `411 MissingContentLength`, as
required by its S3 parser. The repository's EOF-finalized internal stream path
passes direct tests, but it is not an externally qualified gateway lane.

The default partial commit-batch wait is now 25 ms. A 2026-05-17 local gateway
smoke recorded the current medium-object shape: sequential 256 KiB writes used
1.0 backend requests per client write, parallel batched writes used 0.125
requests per client write, full reads used 0.016 requests per client read after
cache fill, and 4 KiB range reads used 0.063 requests per client read. Large
67,108,865 B known-length and chunked unknown-length PUTs both used one commit
PUT plus one retained-profile preflight `HEAD`; write-byte amplification was
1.0004x under the then-current gateway boundary. The unknown-length result is
historical and is not reproducible through the current S3 parser. Eight 4 KiB
ranges from a large object used one backend range `GET`
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
- Rerun known-length streamed uploads, post-checkpoint cold ranges,
  and mixed pack/stream compaction under wire version 4; report request, byte,
  elapsed, CPU, and RSS results separately from the historical May artifacts.
- Reduce commit stage-lock and commit-wait time without allowing commits to
  race writes whose sequence state is not yet indexed.
- Add provider matrix runs for additional S3-compatible stores after the
  retained-version lane remains repeatable.
