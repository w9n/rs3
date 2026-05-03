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

## Current Results

Run date: 2026-05-03. Each row is the average of three direct/gateway run pairs.

| Profile | Artifact | Direct elapsed | Gateway elapsed | Elapsed ratio | Backend requests | Backend writes | Backend reads |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| small-smoke | `.local/integration/` | 1.84 s | 1.40 s | 0.76x | 1.11x | 1.10x | 1.48x |
| changed-snapshot | `.local/integration/` | 2.19 s | 1.73 s | 0.79x | 1.13x | 1.04x | 1.24x |
| many-small-files | `.local/integration/` | 2.99 s | 1.43 s | 0.49x | 1.02x | 1.91x | 4.54x |
| medium-restore | `.local/integration/` | 2.96 s | 2.51 s | 0.85x | 1.16x | 1.00x | 1.06x |

## Reading The Numbers

Backend request amplification is modest in these profiles: about 1.02x to 1.16x
versus the direct path.

Backend write-byte amplification is low for the medium and incremental profiles.
The many-small-files profile writes very little data directly, so fixed metadata
and envelope costs show up more strongly.

Backend read-byte amplification is the largest current concern. The
many-small-files profile performs many small ranged reads, so the gateway reads
at least one authenticated payload segment for each tiny client-visible range.

Wall-clock results are favorable for the gateway in this local setup, but they
are less portable than request and byte ratios. Treat them as a regression
signal for this harness, not as a general cloud-provider result.

## Larger Restore Matrix

Run date: 2026-05-03. Workload set: `larger-restores`. Each row is the
average of three direct/gateway run pairs. Per-profile values come from
`summary.json.profiles`; the top-level aggregate intentionally mixes profiles
and should only be used as a smoke signal for the whole set.

Artifact:
`.local/integration/`.

The direct baseline is the same straight integration storage proxy used by the
single-profile rows. The Postgres-shaped profile uses file-specific deterministic
payloads so equal-size relation and WAL files do not collapse into a
deduplicated synthetic best case.

| Profile | Shape | Direct elapsed | Gateway elapsed | Elapsed ratio | Backend requests | Backend writes | Backend reads | Gateway CPU | Gateway HWM RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| medium-restore | one 64 MiB object | 2.49 s | 2.73 s | 1.10x | 1.16x | 1.03x | 1.03x | 0.98 s | 99.34 MiB |
| kubernetes-objects | 1,536 manifests plus a 32 MiB etcd-like fragment | 9.15 s | 2.46 s | 0.27x | 1.01x | 1.03x | 1.05x | 1.41 s | 87.49 MiB |
| postgres-pgdata | 96 relation files, 4 WAL segments, and an 8 MiB dump | 2.56 s | 3.37 s | 1.32x | 1.11x | 1.03x | 1.03x | 2.70 s | 194.50 MiB |

Interpretation:

- Larger restore read and write byte ratios stay close to the straight proxy
  baseline, about 1.03x to 1.05x in these runs.
- Gateway CPU is cumulative process CPU time for the measured gateway run.
  Gateway HWM RSS is the average high-water resident set size across the three
  gateway runs for that profile.
- The Kubernetes-shaped profile is dominated by many small ranged GETs on the
  direct path. The gateway is faster locally despite similar backend bytes, but
  that elapsed ratio should be treated as a local RustFS/proxy observation.
- The Postgres-shaped profile now exercises roughly 176 MB of unique backend
  restore reads on the direct baseline. Gateway byte overhead is modest, while
  elapsed time is slower because large PUT tail latency is visible in the local
  gateway path.

## Segment-Size Sweep

Run date: 2026-05-03. Workload: `many-small-files`, because it is the current
restore-heavy Kopia profile with many small ranged reads. Each row is the
average of three direct/gateway run pairs. The direct RustFS baseline is the
same straight proxy lane for every row.

Command shape:

```sh
cargo run -p xtask --bin xtask --features containers -- integration kopia-measured-matrix \
  --runs 3 \
  --workload-profile many-small-files \
  --gateway-build-profile release \
  --payload-segment-size <bytes>
```

| Gateway segment size | Artifact | Direct read | Gateway read | Read ratio | Request ratio | Write ratio | Elapsed ratio |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 512 B | `.local/integration/` | 72.84 KB | 330.67 KB | 4.54x | 1.02x | 1.91x | 0.49x |
| 1 KiB | `.local/integration/` | 72.84 KB | 593.22 KB | 8.14x | 1.02x | 1.89x | 0.46x |
| 2 KiB | `.local/integration/` | 72.84 KB | 1.12 MB | 15.34x | 1.01x | 1.89x | 0.50x |
| 4 KiB | `.local/integration/` | 72.84 KB | 2.17 MB | 29.76x | 1.01x | 1.88x | 0.48x |
| 8 KiB | `.local/integration/` | 72.84 KB | 4.27 MB | 58.67x | 1.02x | 1.88x | 0.48x |
| 16 KiB | `.local/integration/` | 72.84 KB | 8.48 MB | 116.37x | 1.02x | 1.88x | 0.47x |
| 32 KiB | `.local/integration/` | 72.84 KB | 16.88 MB | 231.75x | 1.02x | 1.88x | 0.49x |
| 256 KiB | `.local/integration/` | 72.84 KB | 23.58 MB | 323.75x | 1.02x | 1.88x | 0.48x |

Interpretation:

- Segment size dominates backend read bytes for tiny ranged restores. The 512 B
  lane reads about 13x less backend data than the 8 KiB lane and about 71x less
  than the 256 KiB default-era lane for this profile.
- The ratio is large because the denominator is small. The profile restores 512
  tiny files; Kopia issued 514 successful ranged GETs but received only about
  56 KB of total S3 response body. At 2 KiB segments each roughly 110-byte
  response still forces at least one authenticated backend segment read.
- Backend request amplification is effectively flat in this sweep. The gateway
  issues about 1.02x as many backend operations as the direct proxy baseline.
- Write-byte amplification is also flat because this workload's writes are
  mostly independent of restore segment size, rising only from about 1.88x at
  8 KiB to about 1.91x at 512 B in this tiny-data profile.
- Wall-clock remains a weak ranking signal here. The local gateway lane is
  faster than direct RustFS through the proxy for all rows, which should be
  treated as a harness/backend observation rather than a provider claim.
- A single 512 B `medium-restore` sanity run read 1.03x and wrote 1.03x backend
  bytes versus direct RustFS, but p95/p99 large-object PUT latency was visibly
  higher. Keep 512 B as the current Kopia-first default candidate, and require
  repeated larger restore runs plus CPU/memory capture before treating it as a
  production default.

## Follow-Up Work

- Add restore-throughput and resource-efficiency columns once enough
  release-profile matrix artifacts include CPU and memory metrics.
- Add a real Velero/Postgres cluster matrix once the smoke lane can scale row
  counts and data volume without changing its correctness proof.
- Keep release-profile gateway execution for performance lanes; debug builds are
  useful for development but distort medium payload timings.
