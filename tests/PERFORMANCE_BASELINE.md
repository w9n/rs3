# Performance Baseline

This document records local performance evidence for the gateway test harness.
It is not a provider benchmark and should not be used for broad performance
claims.

## Method

Command shape:

```sh
cargo run -p xtask --features containers -- integration kopia-measured-matrix --runs 3 --workload-profile <profile>
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
cargo run -p xtask --features containers -- integration kopia-measured-matrix \
  --runs 3 \
  --workload-profile many-small-files \
  --gateway-build-profile release \
  --payload-segment-size <bytes>
```

| Gateway segment size | Artifact | Direct read | Gateway read | Read ratio | Request ratio | Write ratio | Elapsed ratio |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 8 KiB | `.local/integration/` | 72.84 KB | 4.27 MB | 58.67x | 1.02x | 1.88x | 0.48x |
| 16 KiB | `.local/integration/` | 72.84 KB | 8.48 MB | 116.37x | 1.02x | 1.88x | 0.47x |
| 32 KiB | `.local/integration/` | 72.84 KB | 16.88 MB | 231.75x | 1.02x | 1.88x | 0.49x |
| 256 KiB | `.local/integration/` | 72.84 KB | 23.58 MB | 323.75x | 1.02x | 1.88x | 0.48x |

Interpretation:

- Segment size dominates backend read bytes for tiny ranged restores. The 8 KiB
  lane reads about 5.5x less backend data than the 32 KiB lane and about 5.5x
  less than the 256 KiB default-era lane for this profile.
- Backend request amplification is effectively flat in this sweep. The gateway
  issues about 1.02x as many backend operations as the direct proxy baseline.
- Write-byte amplification is also flat because this workload's writes are
  mostly independent of restore segment size.
- Wall-clock remains a weak ranking signal here. The local gateway lane is
  faster than direct RustFS through the proxy for all four rows, which should be
  treated as a harness/backend observation rather than a provider claim.
- The current data supports 8 KiB as the best read-byte point for
  many-small-file restore behavior, but earlier Velero/Postgres measurements saw
  worse internal gateway range-read time at 8 KiB. Keep 16 KiB as the working
  default candidate until CPU and p95/p99 latency are measured on repeated
  larger restore profiles.

## Follow-Up Work

- Add CPU and memory high-water marks to the harness.
- Add larger repeated restore profiles before making release claims.
- Keep release-profile gateway execution for performance lanes; debug builds are
  useful for development but distort medium payload timings.
