# Performance Baseline

This document records local performance evidence for the gateway test harness.
It is not a provider benchmark and should not be used for broad performance
claims.

## Method

Command shape:

```sh
cargo run -p xtask --bin xtask --features containers -- integration kopia-measured-matrix --runs 3 --workload-profile <profile>
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

## Current Results

Run date: 2026-05-03. Each row is the average of three direct/gateway run pairs.

| Profile | Artifact | Direct elapsed | Gateway elapsed | Elapsed ratio | Backend requests | Backend writes | Backend reads |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| small-smoke | `.local/integration/` | 1.84 s | 1.40 s | 0.76x | 1.11x | 1.10x | 1.48x |
| changed-snapshot | `.local/integration/` | 2.19 s | 1.73 s | 0.79x | 1.13x | 1.04x | 1.24x |
| many-small-files | `.local/integration/` | 3.15 s | 1.52 s | 0.48x | 1.02x | 1.88x | 323.75x |
| medium-restore | `.local/integration/` | 2.96 s | 2.51 s | 0.85x | 1.16x | 1.00x | 1.06x |

## Reading The Numbers

Backend request amplification is modest in these profiles: about 1.02x to 1.16x
versus the direct path.

Backend write-byte amplification is low for the medium and incremental profiles.
The many-small-files profile writes very little data directly, so fixed metadata
and envelope costs show up more strongly.

Backend read-byte amplification is the largest current concern. The
many-small-files profile performs many small ranged reads, so the gateway reads
encrypted payload segments that are much larger than the client-visible ranges.

Wall-clock results are favorable for the gateway in this local setup, but they
are less portable than request and byte ratios. Treat them as a regression
signal for this harness, not as a general cloud-provider result.

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

- Add CPU and memory high-water marks to the harness.
- Add larger repeated restore profiles before making release claims.
- Keep release-profile gateway execution for performance lanes; debug builds are
  useful for development but distort medium payload timings.
