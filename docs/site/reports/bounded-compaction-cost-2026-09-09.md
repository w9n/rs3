# Bounded compaction cost evidence: September 9, 2026

This dated report preserves the complete measured method, lane-level values, revision binding, artifact link and limits. It is local RustFS evidence, not external-provider pricing or capacity qualification.

For the operator summary, see [Performance](../performance.md).


## Results

At `be30107`, compaction can combine **256 small source runs**, up from 128,
within the same **16 MiB encoded-source and 131,072-mutation limits**. Selection
uses checked running sums to avoid repeated rescanning. Large sources still
force smaller selections. The wire format, recovery promises, publication
verification and reader limits are unchanged; the encoded-byte limit is not a
bound on total process memory.

All **12 runs pass**: three alternating baseline/candidate pairs each for 512
serial overwrites of 512 B and 64 Kubernetes-shaped Kopia snapshots. The baseline
executable is `2d284c9`, whose runtime source is identical to the pre-change
`7f6c231`. The [numerical evidence](../assets/bounded-compaction-cost-2026-09-09.json)
records executable, source and helper hashes, every sample and phase, retention
inventories, operations and verification results.

| Metric, median per variant | Tiny baseline | Tiny candidate | Kopia baseline | Kopia candidate |
| --- | ---: | ---: | ---: | ---: |
| Stored growth, bytes | 2,010,316 | 1,659,487 | 1,662,906,181 | 1,662,596,134 |
| Uploaded body bytes | 2,010,775 | 1,659,792 | 1,662,906,486 | 1,662,596,287 |
| Downloaded body bytes | 7,484,177 | 6,000,267 | 286,443,243 | 285,291,645 |
| Backend HTTP requests | 14,610 | 14,669 | 12,965 | 13,286 |

The tiny workload's storage amplification falls from **7.669x to 6.330x** its
262,144 submitted plaintext bytes: **17.45% less incremental storage**, 17.46%
less uploaded body data and 19.83% less downloaded body data. Request count rises
0.40%. These are serial writes, so they cannot share a publication batch.
Ordinary authenticated commits still dominate the remaining overhead.

For Kopia, stored and uploaded bytes fall only **0.019%**. Paired download
reductions range from 0.29% to 0.45%, with a 0.36% median; requests increase
**2.48%** at the paired median, ranging from 2.47% to 6.55%. This is a small-write
improvement, not evidence of a universal provider-bill reduction.

### Checkpoint and request tradeoff

Larger compactions can avoid a later checkpoint but leave a longer current
commit chain at the measurement endpoint. In the first Kopia pair, the candidate
compacts once and ends with 192 current-chain commits; baseline compacts twice
and ends with 65. The explicit maintenance dry-run/apply replays that chain and
uses 234 more GETs with the candidate. Snapshot-phase requests fall from 5,067
to 5,039, while larger individual compactions cause higher request bursts.
Background traffic between phases is included in totals; its timing contributes
to sample variation and does not identify a completed maintenance pass.

Full standalone/multipart ciphertext readback remains one verification pass.
Replacing it with provider-reported checksums would change the backend trust
contract, so this optimization leaves it intact.

### Method and limits

Both variants use fresh RustFS instances, real Kind Leases, generated salts,
explicit 30-day COMPLIANCE protection, a 30-day recovery window, a one-day renewal
margin and 60-second clock allowance. Exact-version audits confirm the protection
floor. No provider lifecycle, accelerated expiry or gateway reclamation runs.
Stored growth subtracts each initial inventory, including about 5 MiB of setup
objects; those objects still occupy retained storage.

Operating traffic excludes gateway bootstrap and includes writes, restores,
one maintenance dry-run/apply and observed background requests. The common
streaming meter counts decoded HTTP bodies, excluding headers, framing, TCP/TLS
and Kubernetes traffic. Provisioning and inventory audits bypass it. No transport
errors occurred. Provider prices and internal storage overhead are not modeled.

The Kopia fixture evolves 6,144 YAML records and a 128 MiB binary fragment over
64 snapshots, changing about 10% of content and replacing about 1% of records per
generation. Paired source manifests match. Every file and directory in the first
and last snapshots is compared after restore; intermediate snapshots are not
individually restored. Kopia's local cache is cleared before each restore; the
gateway retains its default 256 MiB cache. Raw probes check overwrite, deletion
visibility and historical recovery. This tests synthetic file backup churn,
not application consistency or Kopia snapshot pruning.

The twelve lanes run serially on a shared host, without concurrent builds.
Elapsed times and sampled writer CPU/RSS are descriptive, not isolated capacity
benchmarks. Frozen source, executable and helper hashes remain unchanged during
the run, and owned containers and clusters are removed afterward.
