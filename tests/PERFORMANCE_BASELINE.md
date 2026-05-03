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

Gateway backend metrics also include `backend_metrics.by_s3_operation`, a
span-derived breakdown of backend operations and bytes by client S3 operation.
This gives a request-to-backend cost map without recording object keys.

The Prometheus delta includes `prometheus_metrics.storage_provider`, which
summarizes S3 provider operation counts, bytes, and latency from the gateway's
metrics endpoint.

It also includes `prometheus_metrics.repository`, a path-private repository
breakdown of gateway operation counts, bytes, LIST selectivity, commit batching,
and latency.

## Current Results

Run date: 2026-05-03. Each row is the average of three direct/gateway run pairs.

| Profile | Artifact | Direct elapsed | Gateway elapsed | Elapsed ratio | Backend requests | Backend writes | Backend reads |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| small-smoke | `.local/integration/` | 1.57 s | 1.29 s | 0.83x | 0.81x | 1.14x | 1.02x |
| changed-snapshot | `.local/integration/` | 2.07 s | 1.59 s | 0.77x | 0.82x | 1.08x | 1.02x |
| many-small-files | `.local/integration/` | 2.88 s | 1.38 s | 0.48x | 0.98x | 2.03x | 4.54x |
| medium-restore | `.local/integration/` | 2.61 s | 2.79 s | 1.07x | 0.89x | 1.03x | 1.03x |

## Reading The Numbers

Backend request counts are now below the straight proxy lane in these refreshed
profiles: about 0.81x to 0.98x versus direct RustFS. The main improvement came
from sealing committed index deltas inline with checkpoint objects instead of
writing separate backend index objects.

Backend write-byte amplification is low for the medium and incremental profiles.
The many-small-files profile writes very little data directly, so fixed
metadata, checkpoint, and envelope costs show up more strongly.

Backend read-byte amplification is close to baseline for the small, changed,
and medium profiles. The many-small-files profile remains the current edge case:
it performs many tiny ranged reads, so the gateway reads at least one
authenticated payload segment for each tiny client-visible range.

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
| medium-restore | one 64 MiB object | 2.61 s | 2.79 s | 1.07x | 0.89x | 1.03x | 1.03x | 1.03 s | 91.63 MiB |
| kubernetes-objects | 1,536 manifests plus a 32 MiB etcd-like fragment | 9.24 s | 2.51 s | 0.27x | 0.99x | 1.03x | 1.05x | 1.51 s | 91.47 MiB |
| postgres-pgdata | 96 relation files, 4 WAL segments, and an 8 MiB dump | 2.70 s | 3.39 s | 1.26x | 0.99x | 1.03x | 1.03x | 2.74 s | 217.31 MiB |

Interpretation:

- Larger restore read and write byte ratios stay close to the straight proxy
  baseline, about 1.03x to 1.05x in these runs.
- Backend request counts are now at or below the straight proxy baseline in the
  larger profiles after sealed index deltas moved inline with checkpoint
  objects.
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
| 512 B | `.local/integration/` | 72.81 KB | 330.56 KB | 4.54x | 0.98x | 2.03x | 0.48x |
| 1 KiB | `.local/integration/` | 72.81 KB | 592.89 KB | 8.14x | 0.98x | 2.02x | 0.45x |
| 2 KiB | `.local/integration/` | 72.81 KB | 1.12 MB | 15.35x | 0.98x | 2.01x | 0.45x |
| 4 KiB | `.local/integration/` | 72.81 KB | 2.17 MB | 29.77x | 0.98x | 2.01x | 0.46x |
| 8 KiB | `.local/integration/` | 72.81 KB | 4.27 MB | 58.69x | 0.98x | 2.01x | 0.47x |
| 16 KiB | `.local/integration/` | 72.81 KB | 8.48 MB | 116.40x | 0.97x | 2.01x | 0.47x |
| 32 KiB | `.local/integration/` | 72.81 KB | 16.88 MB | 231.83x | 0.98x | 2.01x | 0.47x |
| 256 KiB | `.local/integration/` | 72.81 KB | 23.58 MB | 323.87x | 0.98x | 2.01x | 0.47x |

Interpretation:

- Segment size dominates backend read bytes for tiny ranged restores. The 512 B
  lane reads about 13x less backend data than the 8 KiB lane and about 71x less
  than the 256 KiB default-era lane for this profile.
- The ratio is large because the denominator is small. The profile restores 512
  tiny files; Kopia issued 514 successful ranged GETs but received only about
  56 KB of total S3 response body. At 2 KiB segments each roughly 110-byte
  response still forces at least one authenticated backend segment read.
- Backend request count is effectively flat in this sweep and slightly below the
  direct proxy baseline, about 0.97x to 0.98x after inline checkpoint deltas.
- Write-byte amplification is also flat because this workload's writes are
  mostly independent of restore segment size, sitting around 2.01x to 2.03x in
  this tiny-data profile.
- Wall-clock remains a weak ranking signal here. The local gateway lane is
  faster than direct RustFS through the proxy for all rows, which should be
  treated as a harness/backend observation rather than a provider claim.
- The repeated 512 B larger restore matrix read and wrote about 1.03x to 1.05x
  backend bytes versus direct RustFS. Keep 512 B as the current Kopia-first
  default candidate, but keep tracking larger Postgres-shaped restore elapsed
  time because large PUT tail latency is still visible in the local gateway
  path.

## Follow-Up Work

- Add restore-throughput and resource-efficiency columns once enough
  release-profile matrix artifacts include CPU and memory metrics.
- Add a real Velero/Postgres cluster matrix once the smoke lane can scale row
  counts and data volume without changing its correctness proof.
- Keep release-profile gateway execution for performance lanes; debug builds are
  useful for development but distort medium payload timings.
