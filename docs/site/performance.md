# Performance

The latest [gateway versus direct S3 comparison](#gateway-versus-direct-s3-september-9-2026)
measures object-store traffic and retained object bytes on a real local backend.
The separate [retained-history efficiency comparison](#retained-history-efficiency-september-9-2026)
compares two rs3 revisions in a controlled storage model. Earlier results retain
their original source bindings below.

## Gateway versus direct S3: September 9, 2026

At `2d284c9`, backup-sized objects have little incremental encoding overhead,
but multipart verification and small serial writes remain material costs.
All **24 runs pass**: three alternating direct/gateway pairs for each of four
workloads, with exact-version retention audits and content recovery checks.
The [numerical evidence](assets/direct-storage-cost-2026-09-09.json) includes
every sample, phase, operation/status count, inventory, client version and
source/binary/helper/log hash. These results use real RustFS and a Kubernetes
Lease on a shared local host; they do not establish external-provider prices.

### Measured storage and backend traffic

Ratios are medians of three paired **gateway/direct** samples. Stored bytes
include all surviving object versions and fixed gateway setup data. Operating
traffic excludes gateway bootstrap and includes the client workload, restores,
one maintenance dry-run/apply and observed automatic background work. The same
HTTP meter counts both paths, including retries and verification requests.

| Workload | Stored object bytes | Uploaded body bytes | Downloaded body bytes | Backend HTTP requests |
| --- | ---: | ---: | ---: | ---: |
| Kubernetes-shaped Kopia, two snapshots | 1.035x | 0.999x | 0.567x | 0.105x |
| PostgreSQL-shaped Kopia, two snapshots | 1.013x | 0.999x | 0.966x | 3.379x |
| Two 100 MiB multipart versions | 1.025x | 1.000x | 2.001x | 24.385x |
| 512 serial overwrites of 512 B | 27.693x | 7.670x | 6,658.494x | 28.259x |

Gateway setup leaves about **5.006 MiB** of object data, chiefly provider
qualification artifacts. It also uses 319 backend requests, approximately
5.007 MiB uploaded and 0.068 MiB downloaded, reported separately from operating
traffic. Subtracting each gateway
initial inventory, incremental stored bytes are **1.00075x** direct for
Kubernetes, **1.00050x** for PostgreSQL, **1.00028x** for multipart and
**7.66875x** for tiny overwrites. This subtraction isolates workload growth;
it does not make the retained setup objects free.

The tiny workload retains 0.250 MiB directly and 6.923 MiB through rs3, including
setup. It downloads only 1,124 B directly versus 7.137 MiB through rs3, so the
large download ratio has a very small denominator. Each overwrite waits for
success before the next starts: these writes cannot share a publication batch.
The results include historical lookup and maintenance costs; they are not a
measurement of concurrent small-write batching.

### Upload verification and restore caching

The multipart write phases send **200.001 MiB** directly versus **200.055 MiB**
through rs3. During those writes, the backend returns about **0.001 MiB** directly
versus **200.070 MiB** through rs3. The gateway reads completed encrypted parts
back before publication. This makes write-path body traffic approximately
**2x direct S3**, independently of later user downloads.

Kopia writes use the packed commit path, whose post-write checks differ from
standalone/multipart body verification. These two-snapshot fixtures upload
about 148 MiB for Kubernetes and 395 MiB for PostgreSQL on either path. The
write phases use 88 versus 355 backend requests for Kubernetes and 100 versus
463 for PostgreSQL, direct versus gateway.

Kopia restores remove its local disk cache before each restore. The gateway
remains running with its default **256 MiB** decrypted-segment cache. That
extra cache is part of the measured service and can reuse data between restores:

| Restore backend downloads, median MiB | Direct A | Gateway A | Direct B | Gateway B |
| --- | ---: | ---: | ---: | ---: |
| Kubernetes-shaped Kopia | 131.624 | 132.716 | 131.642 | 15.971 |
| PostgreSQL-shaped Kopia | 352.045 | 365.410 | 352.045 | 313.965 |

The aggregate download savings do not describe a cold gateway restart. rs3 also
answers client metadata requests from its namespace state, which explains much
of the request reduction for the many-file Kubernetes restore. PostgreSQL has
fewer files, so retained-history and maintenance calls outweigh that benefit.

### Retention cost and comparison limits

Both paths enforce a **30-day protection floor** for newly written data. Direct
S3 uses bucket-default COMPLIANCE retention. rs3 uses explicit version locks,
a 30-day recovery window, a one-day renewal margin and 60-second clock allowance.
The provider adapter rounds retention upward to whole days. Exact-version HEAD
audits observe about **32 days** of protection on rs3 repository objects versus
**30 days** directly. Matching the requested floor does not remove this overhead.

Summing each retained version's bytes times its observed remaining lock duration
gives **1.101x** direct locked byte-days for Kubernetes, **1.080x** for PostgreSQL,
**1.092x** for multipart and **28.205x** for tiny overwrites, including setup.
These are current lock obligations, not an elapsed 30-day storage measurement
or a monthly bill. The JSON also reports a separate constant-size 30-day
projection. Neither projection models future writes, renewals or reclamation.
No provider lifecycle rule or accelerated expiry runs in this fixture; gateway
reclamation is disabled.

The policies are not equivalent for long-lived objects: native bucket defaults
start at version creation, while rs3 maintains dependencies for its recovery
promises. Native S3 Object Lock permits new versions and delete markers while
protecting an older version. See the [S3 Object Lock contract](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html).
Native version retention also lacks rs3's path privacy, external rollback anchor
and authenticated repository recovery points.

### Method and verification

Each lane starts a fresh disposable RustFS instance with the same pinned image,
a 4 GiB memory limit and 3 GiB tmpfs. Gateway lanes use a generated salt and a
real Kind Lease. The source, release executable and helper hashes remain
unchanged throughout all 24 runs. Kopia is version 0.22.3; raw S3 operations use
Boto3 1.42.31. No concurrent benchmark builds run. Shared-host CPU and cache
conditions limit elapsed-time interpretation. Phase times and writer CPU/RSS
are included in the JSON; writer samples exclude bootstrap and historical
reader processes, Kubernetes and provider resources.

The synthetic Kubernetes tree contains 6,144 YAML records and a 128 MiB binary
fragment. The PostgreSQL tree contains 192 one-MiB relation files, eight 16 MiB
WAL-shaped files and a 32 MiB dump-shaped file. Generation B changes about 10%
of records and bulk data, replaces about 1% of records and rotates one WAL file.
Paired source manifests match exactly; independent Kopia repository encryption
and absolute source paths make their repository metadata differ. Every file
and directory in both immutable snapshots is checked after restore. These are
synthetic file backups, not Kubernetes or PostgreSQL consistency qualification.

Raw cases verify latest full/range reads, deletion visibility and recovery of
the original value after overwrite/deletion. Direct S3 selects an old version;
rs3 starts a fresh historical reader. Historical phase timing includes that
reader's startup and shutdown. Kopia source-file churn is not snapshot pruning.

The meter streams both paths with the same close-per-request connection policy.
Counters include decoded HTTP bodies and exclude headers, chunk framing,
TCP/TLS and Kubernetes traffic. Small-request header overhead is therefore
absent from byte totals. The relay also removes fixed-length AWS `aws-chunked` request framing for
counting; it does not authenticate chunk signatures or decode other content
encodings.
Shared bucket provisioning and exact-version inventory audits bypass the meter;
excluded audit request counts are recorded. All observed background backend
traffic remains in the published totals. No transport errors occurred.

Stored object bytes sum exact-version payload lengths, including retained old
versions and qualification artifacts. They exclude provider filesystem metadata,
replication and erasure coding. Delete markers and their UTF-8 key bytes are
counted separately. Provider rates, operation/status billing, transfer placement
and gateway compute must be applied separately to estimate money. Owned
containers and the Kind cluster were removed after the run.

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

## Retained-history efficiency: September 9, 2026

This matched comparison uses production baseline `cdedf39` and candidate
`3e879cb`, with the same instrumented workload on both. Each workload runs once
in a separate release-test process on a shared host. The provider is an
in-memory exact-version retention model, the anchor is in memory, and retention
days are simulated. These results do not measure HTTP, Kubernetes, an external
provider, or isolated gateway RAM.

Both revisions use 256 MiB of history metadata budget at 10,000 writes and an
explicit 1 GiB at 100,000, with a 64 MiB encoded pending-buffer budget throughout.
The same budgets apply to publication, traversal, renewal and GC. Server defaults
remain unchanged; the format's roughly 4.2-million-point ceiling is not an
operating-capacity claim.

Each serial PUT carries 512 plaintext bytes. Overwrite replaces one key; append
adds distinct keys. Compaction adds publications. Reopen creates a new repository
instance in the same test process. A full successful lifecycle includes deletion,
three sampled historical restores, renewal, authenticated expiry, provider-unlock
simulation, eligible exact-version GC and final current-state verification.

Body-byte counters exclude HEAD/LIST response metadata, HTTP framing and SDK
retries. A separate signed-header audit attributes physical storage without
adding to measured traffic. Encoded pending peaks are conservative phase bounds,
not allocator or process-RSS measurements.

All four candidate lifecycles pass. Baseline 100,000-append growth, reopen and
sampled restore pass, but its full history walk fails under the same explicit
1 GiB metadata / 64 MiB pending budgets. Its later renewal and GC phases are
therefore unqualified. The candidate completes those phases without changing
history deadlines or page policy.

### Network and storage results

Values are MiB, shown as **baseline → candidate**. Stored bytes are measured
after deletion and checkpointing, before expiry/GC. Growth includes automatic
compaction and verification; it excludes later maintenance scans.

| Workload | Growth body reads | Growth body writes | Stored bytes |
| --- | ---: | ---: | ---: |
| 10,000 overwrite | 129.57 → 122.76 | 76.18 → 76.18 | 77.45 → 77.45 |
| 10,000 append | 131.51 → 127.27 | 79.05 → 79.05 | 80.43 → 80.43 |
| 100,000 overwrite | 1,422.38 → 1,348.21 | 824.40 → 824.40 | 826.08 → 826.08 |
| 100,000 append | 5,743.60 → 1,686.03 | 3,004.79 → 1,017.38 | 3,009.57 → 1,019.28 |

At 100,000 appends, body reads fall **70.6%**, written bytes **66.1%**, and
stored bytes **66.1%**. Growth GETs fall from 821,344 to 713,182 and PUTs from
103,051 to 101,858. Compaction preserves expensive older shards, reads only
required run sections and avoids repeatedly rewriting live metadata. IndexRun
storage falls from 2,368,221,374 B to 179,780,679 B. Recovery storage grows from
614,382,789 B to 702,192,124 B because the selected compaction schedule publishes
more roots; the recovery-record layout is unchanged.

| Workload | Full history-scan body reads, baseline → candidate (MiB) | Candidate encoded pending bound (MiB) |
| --- | ---: | ---: |
| 10,000 overwrite | 75.00 → 22.43 | 2.58 |
| 10,000 append | 77.97 → 30.03 | 2.58 |
| 100,000 overwrite | 806.84 → 224.69 | 2.60 |
| 100,000 append | incomplete, not comparable → 368.83 | 3.97 |

Candidate traversals release all encoded section buffers by completion. These
bounds exclude decoded namespace/decoder state and are not a process-memory
ceiling. Accounted history metadata at 100,000 writes is 496.98 MiB for overwrite
and 501.75 MiB for append, which explains the explicit 1 GiB configuration.

### Remaining physical overhead

At 100,000 appends, 702,192,124 B of the 1,068,794,750 B pre-GC total belongs to
Recovery sections; submitted plaintext is 51,200,000 B. Retained predecessor
records and immutable carriers still dominate size. Smaller history pages would
consume the fixed page-count capacity sooner, so this change preserves page
policy and retention promises.

After simulated expiry, observed provider unlock and guarded GC, append storage
is 320,909,464 B with 99,999 current keys and two retained points. Live packed
payloads can keep obsolete metadata and unused pack space in their immutable
carriers. Metadata compaction does not clean payload packs. The unused-byte
metrics report unused payload space, not removable metadata or immediate GC
eligibility.

The [numerical evidence](assets/history-efficiency-2026-09-09.json) records full
production revisions, source/binary/manifest/log hashes, exact budgets, phase
counters, inventories and all outcomes. Raw logs and build receipts remain local.
Reproduce each case in a fresh process, selecting `overwrite` or `append`:

```sh
RS3_HISTORY_SCALE_WRITES=100000 \
RS3_HISTORY_SCALE_MODE=append \
RS3_HISTORY_SCALE_METADATA_BYTES=1073741824 \
RS3_HISTORY_SCALE_PENDING_BYTES=67108864 \
cargo test --release --lib -p rs3-repository recovery_history_scale \
  -- --ignored --nocapture --test-threads=1
```

For 10,000 writes, use `RS3_HISTORY_SCALE_WRITES=10000` and
`RS3_HISTORY_SCALE_METADATA_BYTES=268435456`. This controlled lane complements
the local retained-provider checks in [Testing](testing.md); it does not replace
external-provider or dedicated-runner qualification.

## Retained-history experiment: September 9, 2026

This earlier experiment used `0eb5064` and predates the repairs measured above.
Its original default-budget failures remain recorded here.

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
advance. In that measured revision, cached coverage permitted growth that a later
maintenance pass or restarted writer could not handle under the default budget. The diagnostic
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

At 10,000 writes, submitted plaintext totals 4.88 MiB in each workload. The overwrite workload
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

These measurements use production code at `0eb5064` and a test-only harness.
They predate the admission repair described below. These are single release-build runs using a controlled in-memory provider
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
The recorded budget-isolation diagnostic used `RS3_HISTORY_SCALE_WRITES=55000`
and `RS3_HISTORY_SCALE_DIAGNOSE=1` with `overwrite`. On the measured revision it
also tried one read-only graph walk with a 512 MiB metadata budget and checked
fresh-writer refusal under the default. It exited unsuccessfully to preserve
the default-budget failure. That diagnostic option belongs to its recorded
harness revision. The current harness instead accepts explicit shared metadata
and pending budgets for the complete lifecycle; growth can refuse before
reaching the measurement phases.

### Admission repair after the experiment

Retained writers now check conservative graph metadata and exact-target capacity
before accepting a candidate, including when retention coverage is cached.
The [admission contract](reference/repository-format.md#recovery-metadata-admission)
uses the same hard limits as maintenance, with a small foreground reserve for an
expiry root. Ordinary successors update a constant-size certificate without
rereading the old graph. A cold cache or an exhausted estimate requires an exact
candidate graph walk, which adds metadata read traffic near the boundary.

Reduced-budget controlled-provider regressions cover warm growth refusal,
restart, current and historical reads, same-budget renewal, expiry, and eventual
GC. Root and compaction refusals preserve the accepted anchor. The existing
bounded-successor I/O regression remains in place. These checks establish the
metadata admission behavior, not a new production capacity or network benchmark.
Admission also checks encoded pending buffers, including current replay and
read scratch. Historical traversal caches signed headers and downloads required
sections individually. Inventory, startup replay and optional I/O limits remain
independent; there is no general guarantee that every maintenance operation
will fit.
The source-bound tables above remain historical measurements. Existing hard limits, the wire format, retention promises, and the stored-payload
layout are unchanged.

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
