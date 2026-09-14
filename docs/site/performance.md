# Performance

This page summarizes the current local cost evidence for the `v3-preview`
gateway. It is a planning input for a controlled preview, not a provider-price,
dedicated-runner, or external-provider performance claim. The dated reports link
to every sample, revision binding and method detail.

## Current measured costs

### Bounded compaction

At `be30107`, compaction can select 256 small source runs instead of 128 while
keeping the 16 MiB encoded-source and 131,072-mutation limits. The wire format,
recovery promise, publication verification and reader limits do not change.
Three alternating pairs passed for each workload. Stored growth subtracts each
initial inventory; retained setup objects still occupy storage.

| Median metric | 512 B serial overwrites, baseline → candidate | 64 Kopia snapshots, baseline → candidate |
| --- | ---: | ---: |
| Stored growth, bytes | 2,010,316 → 1,659,487 | 1,662,906,181 → 1,662,596,134 |
| Uploaded body bytes | 2,010,775 → 1,659,792 | 1,662,906,486 → 1,662,596,287 |
| Downloaded body bytes | 7,484,177 → 6,000,267 | 286,443,243 → 285,291,645 |
| Backend HTTP requests | 14,610 → 14,669 | 12,965 → 13,286 |

For tiny serial writes, stored growth falls **17.45%**, uploaded body data
17.46%, and downloaded body data 19.83%; requests rise 0.40%. Storage
amplification falls from **7.669x to 6.330x** submitted plaintext. For Kopia,
stored and uploaded bytes fall 0.019%, downloads 0.36% at the paired median,
and requests rise 2.48%. These serial writes cannot share a publication batch.
The [bounded-compaction report](reports/bounded-compaction-cost-2026-09-09.md)
explains the endpoint checkpoint tradeoff and preserves all 12 results.

### Gateway versus direct S3

At `2d284c9`, three alternating direct/gateway pairs passed for each workload.
Ratios are median **gateway/direct** values. Stored bytes include all surviving
versions and gateway setup data; operating traffic excludes bootstrap and
includes workload, restore, maintenance, and observed background activity.

| Workload | Stored bytes | Uploaded body bytes | Downloaded body bytes | Backend requests |
| --- | ---: | ---: | ---: | ---: |
| Kubernetes-shaped Kopia, two snapshots | 1.035x | 0.999x | 0.567x | 0.105x |
| PostgreSQL-shaped Kopia, two snapshots | 1.013x | 0.999x | 0.966x | 3.379x |
| Two 100 MiB multipart versions | 1.025x | 1.000x | 2.001x | 24.385x |
| 512 serial overwrites of 512 B | 27.693x | 7.670x | 6,658.494x | 28.259x |

Gateway setup retains about **5.006 MiB** and uses 319 backend requests,
about 5.007 MiB uploaded and 0.068 MiB downloaded. It remains part of retained
storage even though it is excluded from operating traffic. Tiny-write ratios
have very small direct denominators and do not describe concurrent batching.

## What the ratios include

Standalone and multipart writes read completed ciphertext back once before
publication. Replacing that readback with provider-reported checksums would
change the malicious or eventually inconsistent backend contract. The multipart
write body path is therefore about **2x** direct S3 before later downloads.

Kopia restores clear the client cache; the running gateway keeps its default
256 MiB decrypted-segment cache. Aggregate restore-download reductions are not
cold-gateway-restart results. Direct S3 and rs3 also have different namespace
and historical-read behavior, so request ratios are workload-specific.

Both paths request a 30-day protection floor. Direct S3 uses bucket-default
COMPLIANCE retention; rs3 uses explicit version locks, a 30-day recovery
window, one-day renewal margin and 60-second clock allowance. Whole-day
rounding produced about 32 days of observed rs3 protection versus 30 days
directly. Current locked byte-day obligations are 1.080x–1.101x direct for the
large workloads and 28.205x for tiny overwrites, including setup. They are not
a monthly bill or a 30-day elapsed-storage measurement.

## Method and limits

The current reports use fresh disposable RustFS, real Kind Leases, generated
salts, exact-version retention audits and content recovery checks. The
bounded-compaction comparison uses explicit 30-day COMPLIANCE protection, a
30-day recovery window, one-day margin and 60-second allowance. The direct
comparison uses its distinct direct bucket-default policy and rs3 explicit
locks; the policies provide the same fresh-data floor but are not long-lived
retention equivalents.

Both reports count decoded HTTP bodies and requests with a common streaming
meter. Headers, framing, TCP/TLS, Kubernetes traffic, provider internal storage,
prices, and compute are outside the byte totals. Provisioning and inventory
audits bypass the meter; observed background backend traffic remains included.
Lanes run serially on a shared host without concurrent builds. Elapsed time and
writer CPU/RSS are descriptive, not isolated capacity data.

The [bounded-compaction report](reports/bounded-compaction-cost-2026-09-09.md)
and [gateway/direct report](reports/direct-storage-cost-2026-09-09.md) contain
complete workload shapes, restore checks, phase rules and source/binary/helper
hashes. The corresponding machine-readable records are
[bounded compaction](assets/bounded-compaction-cost-2026-09-09.json) and
[gateway/direct storage](assets/direct-storage-cost-2026-09-09.json).

## Earlier measured comparisons

The [September 8 performance report](reports/performance-2026-09-08.md) retains
all sample tables, revision bindings and reproduction recipes for the previous
v03 comparison and history experiments. Its two open candidate budget failures
remain evidence, not waived limits:

- `453c2ff` sequential 512 B writes measured **3.918274x** backend-write
  amplification against a **3x** ceiling.
- `453c2ff` large PostgreSQL-shaped Kopia measured **1.904731x** gateway/direct
  elapsed time against a **1.75x** ceiling.

It also retains the source-bound history comparison: `cdedf39` baseline and
`3e879cb` candidate used 256 MiB metadata at 10,000 writes and explicit 1 GiB
at 100,000, with a 64 MiB pending buffer. The baseline 100,000-append full
history walk refused those same budgets; the candidate completed its lifecycle.
Those controlled-provider results are not HTTP, Kubernetes, external-provider,
or process-RSS qualification.

Use a clean committed checkout and build outside timed intervals when repeating
a report. Recreate each named revision, input, compiler profile, provider image
and resource envelope; the commands and failure gates are preserved in the
[historical report](reports/performance-2026-09-08.md#reproduce-the-measurements).
Correctness and retention acceptance are described in [Testing](testing.md) and
[Production Preview](production-preview.md). Neither changes a measured cost or
failed budget.
