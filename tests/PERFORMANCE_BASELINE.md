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

## Follow-Up Work

- Add segment-size variants to the Kopia matrix, especially for small ranged
  restores.
- Add CPU and memory high-water marks to the harness.
- Add larger repeated restore profiles before making release claims.
- Keep release-profile gateway execution for performance lanes; debug builds are
  useful for development but distort medium payload timings.
