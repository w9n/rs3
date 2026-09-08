# Testing

Use `just check` for workspace checks and `just fmt` for formatting. Operator
keyring inspection, rewrap and bundle verification live in `rs3-server`;
repository initialization uses `rs3-server init`. The xtask CLI contains
integration lanes, performance tools and the isolated `v2 gc-rehearsal` command.

Testing is part of the architecture because privacy and rollback behavior are
product requirements.

## Default Check

Inside `nix develop`:

```sh
just check
```

This runs formatting, clippy with warnings denied, and workspace tests.

## v03 Codec Fixtures

`cargo test -p rs3-repository --test v03_vectors` checks the signed commit
fixtures. Workspace tests also pin index tables, roots, payload segments,
repository envelopes and recovery bundles against `test-vectors/v03/`.
That directory documents fixture keys, fixed test-only nonces and the named
rejection tests. Fixed fixtures do not change production nonce generation.

Repository multipart completion tests cover empty and detached values, receipt
lookup after overwrite, checkpoint, compaction and restart, publication-time
create-only checks, failed anchor advancement, lost anchor replies and local
installation failure. Adapter tests also cover the five multipart routes, replacement serialization,
parallel parts, completion freeze, duplicate completion, monotonic expiry,
admission limits, cancellation, readonly mode and invalid selected/body facts.
Checksum tests cover all five algorithms, encrypted metadata and completion
receipt persistence, and failed writes that leave the accepted value intact.
MD5/ETag tests cover empty, buffered, known-length, unknown-length and
multipart paths, while `Content-MD5` tests cover canonical parsing, exact EOF
validation, and failures that preserve the accepted object or part.
`cargo test -p rs3-server --test checksum_trailers` sends authenticated SigV4
chunks and trailers through the real listener, including missing and invalid
trailer cases.

Local flexible-checksum qualification covered 100 MiB AWS CLI 2.34.24 ordinary
and multipart uploads with CRC64NVME and SHA256 on memory and RustFS. Velero
1.18.0 with AWS plugin 1.14.0 passed default CRC32 backup and restore after
namespace deletion. Those runs preceded the MD5 ETag format update.

MD5 ETag qualification uses rclone 1.75.0 and AWS CLI 2.34.24 on memory and
RustFS. Direct rclone single PUT validates Content-MD5 and returns the expected
MD5 ETag; `md5sum` and hash-based `check` agree, while a same-size corrupted
local file fails hash comparison. A rejected bad-MD5 overwrite preserves the
accepted ETag and original bytes.

Direct AWS two-part uploads validate each part's Content-MD5 and return the
independently calculated MD5-of-part-MD5s ETag. Bad-MD5 part replacements leave
the prior part usable, and direct rclone `check --download` verifies the
completed bytes. These runs use 100 MiB objects and verify matching ETags from
HEAD, GET and listing responses.

The earlier MD5 qualification used AWS-created multipart objects because
multipart creation then rejected rclone's Mtime metadata. Ordinary PUT and
multipart creation now both accept user metadata without preserving it.
These results qualify byte and ETag behavior, not metadata preservation or all
rclone upload options. At revision `453c2ff`, the
[corrected nightly run](https://github.com/w9n/rs3/actions/runs/34226674202)
passed both the gateway-restart dynamic-PVC and PostgreSQL backup/restore Velero
smokes. This is lane-scoped evidence and does not establish an overall nightly
pass.

`just integration-s3-gateway --tooling-smoke` requires AWS CLI v2, rclone, mc
and restic. The repository's `nix develop` shell supplies these clients. It
uses deterministic incompressible data above 8 MiB, verifies
uploaded and restored bytes, and checks exact length and multipart ETags for
AWS and rclone uploads. AWS uses an isolated configuration with an explicit
8 MiB multipart threshold; rclone uses explicit settings that disable system
metadata and its custom MD5 metadata. Restic initializes, backs up and restores
a repository. A missing tool or failed required upload fails the lane. Generic
user-metadata preservation is outside this preview compatibility contract.

When a gateway exits during startup, the qualification harness attaches the
final 80 captured log lines to that startup failure. When a Helm gateway
installation fails, it attaches a capped failure excerpt containing selected-pod
readiness, namespace events and selected-container logs before deleting the
disposable kind cluster. The Helm excerpt redacts fixture credentials and
configured backend paths; these diagnostics aid failure triage and do not
change readiness timeouts or qualify a provider.

The four-client lane passes against a disposable local RustFS backend with AWS
CLI 2.34.24, rclone 1.75.0, mc RELEASE.2025-08-13 and restic 0.19.1. Both
AWS and rclone return independently verified two-part ETags for the 9 MiB-plus-
one-byte fixture. mc uses ordinary PUT at that size; restic backup and restore
pass without a claim about its internal multipart layout. This lane uses an
in-memory rollback anchor and does not qualify process restart or retention.

Copy qualification uses the final `s3,k8s` release binary with rclone 1.75.0
and AWS CLI 2.34.24. Direct rclone `moveto` passes for a 4 KiB packed object
and an AWS-created 100 MiB multipart object on memory and RustFS. Each move
uses `CopyObject` followed by `DeleteObject`, without payload download/upload
fallback. ETag, SHA256 checksum/type, length and restored bytes remain exact
after source deletion. RustFS provider traces record zero source-payload reads
or writes during both moves; normal encrypted metadata publication still occurs.

A fresh gateway process restores both copied destinations using the unchanged
Kubernetes Lease anchor, with repository initialization disabled. This is a
graceful process-restart check, not crash takeover or retained-provider
qualification. Source-condition mismatch, cross-bucket copy and metadata
`REPLACE` reject without creating destinations. COPY accepts the client's inert
content/user metadata and default `STANDARD` storage class; these results do
not qualify arbitrary metadata preservation or other copy extensions.

`just fuzz-smoke` exercises commit headers/objects, canonical CBOR, both
repository-envelope purposes, recovery bundles, index runs/roots, format roots,
payload packs and detached single-part payloads. It copies raw seeds and frozen
vectors to temporary corpora so fuzzing does not modify the fixtures. Defaults
are 60 seconds per target and a 512 MiB per-target RSS ceiling; use
`RS3_FUZZ_SMOKE_SECONDS` and `RS3_FUZZ_RSS_LIMIT_MB` for an explicit local override.

Strict parent-relative publication-time validation remains unimplemented.
Codec vectors do not establish that runtime history guarantee or replace
retained-provider and complete recovery qualification.

## Important Lanes

| Lane | Command | Scope |
| --- | --- | --- |
| Default | `just check` | Format, clippy, workspace tests. |
| Preview local gate | `just preview-gate-local` | Default checks, S3-feature checks, and dependency policy checks. |
| Storage S3 | `just integration-s3-container` | Storage contract against a disposable S3-compatible provider; `just integration-s3-local --mode provided` runs it against an existing endpoint. |
| Gateway S3 | `just integration-s3-gateway` | Gateway S3 operations through the repository path. |
| Local v2 nightly gate | `just preview-gate-v2-nightly` | Scheduled or release-candidate gate: S3 feature checks plus v2 S3 tooling, Kopia, Kubernetes Lease, Velero dynamic-PVC gateway-restart, and Velero/Postgres lanes against disposable local backends. |
| Live v2 preview gate | `just preview-gate-v2-live <bucket> <endpoint> <region>` | Consolidated retained-backend gate. Generates fresh sub-prefixes and runs v2 provider conformance, Gateway S3, Kopia, Kubernetes Lease, Velero dynamic-PVC gateway-restart, and Velero/Postgres lanes. |
| Live v2 provider conformance | `just check-v2-provider-v2-live <bucket> <endpoint> <region> <fresh-prefix>` | Runs `rs3 check-v2-provider` for the retained-version/Object Lock profile and emits JSON evidence for admin posture or release artifacts. |
| Live v2 Gateway S3 | `just integration-s3-gateway-v2-live --backend-bucket <bucket> --endpoint-url <endpoint> --region <region> --backend-prefix <fresh-prefix>` | v3-preview gateway smoke against an existing retained S3-compatible backend, including `mc`, default `rclone lsf`, and backend key privacy checks. |
| Kopia | `just integration-kopia-gateway` | Real Kopia create, snapshot, and restore through the gateway. |
| Live v2 Kopia | `just integration-kopia-gateway-v2-live --backend-bucket <bucket> --endpoint-url <endpoint> --region <region> --backend-prefix <fresh-prefix>` | Real Kopia create, snapshot, and restore through a v3-preview gateway against an existing retained backend. |
| Kubernetes Lease | `just integration-k8s-gateway` | Image build, kind cluster, Helm install, readiness and S3 smoke, including verification that v03 anchor annotations and repository format generation 3 are written. |
| Kubernetes lifecycle | `just integration-k8s-gateway-lifecycle` | Candidate-only qualification with a generated salt: after the smoke, restarts the gateway, repeats the same Helm command against the live writer (a new Job verifies without qualification), and upgrades to a rebuilt image that requalifies once, reading the earlier object back after every step. |
| Velero/Kopia | `just integration-velero-kopia-smoke` | Velero node-agent/Kopia backup and restore smoke. |
| Live v2 Velero dynamic PVC | `just integration-velero-kopia-dynamic-pvc-gateway-restart-v2-live --backend-bucket <bucket> --backend-endpoint-url <endpoint> --backend-region <region> --backend-prefix <fresh-prefix>` | Velero/Kopia dynamic-PVC backup and restore through a v3-preview gateway after a gateway restart, against an existing retained backend. |
| Live v2 Velero Postgres | `just integration-velero-kopia-postgres-v2-live --backend-bucket <bucket> --backend-endpoint-url <endpoint> --backend-region <region> --backend-prefix <fresh-prefix>` | Velero/Kopia Postgres backup and restore through a v3-preview gateway against an existing retained backend. |
| Preview release gate | `just preview-gate-release` | v2 Kopia gateway, Velero dynamic PVC gateway-restart in normal write mode, and Velero Postgres smoke. The restart lane rejects any gateway container restart during the forced rollout. |
| Velero strict restore-readonly | `just integration-velero-kopia-dynamic-pvc-restore-readonly-smoke` | Incident-restore behavior: restored bytes verify, Velero artifact writes are denied, and backend writes stay at zero during restore. |
| Lightweight perf smoke | `just perf-s3-gateway --format jsonl` | Small gateway scenario metrics and amplification. |
| Gateway perf smoke | `just perf-s3-gateway --objects 32 --object-size 262144 --reads 64 --range-len 4096 --commit-batch-items 8 --concurrency 8 --format jsonl` | Release-profile local gateway run for current v03 request cost, throughput, and amplification. |
| Docker-free HTTP gateway perf | `cargo run -p xtask --features containers -- perf --backend gateway-memory --scenario full-read --object-size 268435456 --reads 3 --gateway-build-profile release --format jsonl` | Spawns a release gateway, drives its real S3 adapter, reports the child process rather than driver RSS, and retains exact generic-storage request/byte counters. `gateway-filesystem` is also available for non-multipart local lanes. Memory-backend RSS includes stored ciphertext. |
| 10k object scale gate | `just perf-scale-10k` | Three release-binary committed-write runs. Every run publishes a final signed checkpoint, discards writer state, reloads through a new repository instance, checks exact list cardinality, reads the first, middle, and last payload, and enforces the 1.50x lifetime write gate, 30-second reload ceiling, 1.04x cold-read byte amplification, one backend request per sentinel read, and at most 255 recovered active index runs. Runs on every CI change. |
| 10k automatic compaction gate | `just perf-scale-10k-compaction` | The same scale gates with 16-item batches, concurrency 16, and 1 KiB objects to amortize the extra per-commit overhead while retaining the 1.50x write limit. Every run must observe at least one accepted active-run count decrease before its final checkpoint. JSONL reports `observed_compactions`, a lower bound for arbitrary concurrency and a per-pass count for this one-run-per-wave lane. Runs next to the ordinary 10k PR gate. |
| 100k object scale gate | `just perf-scale-100k` | Release-binary 4,096-item low-amplification bulk tier with the same final-checkpoint, recovery, cardinality, amplification, direct cold-read, and active-run-count checks. |
| 270k bounded-compaction evidence | `just perf-scale-tier 270000` | Crosses the 256-run watermark with the 1,024-item bulk tier and applies the lifetime amplification, 180-second elapsed, 4 GiB peak-RSS, recovery, cold-read, and active-run gates. The final post-remediation sample completed in 11.655 s at 758,521,856 B peak RSS, 1.505740509x amplification, and 140 recovered runs. |
| 1M object scale gate | `just perf-scale-1m` | Manual in-memory high-capacity tier with the same checks. Historical revision `8f99a8a` passed three wire-v6 4,096-record runs at 44.639-45.553 s, 1,680,826,368-1,681,162,240 B process peak RSS including the in-memory backend, 1.268292436x amplification, 245 recovered runs, and exact sentinel reads. |
| Fresh-process filesystem scale gates | `just perf-scale-fs-10k <root>`, `just perf-scale-fs-100k <root>`, `just perf-scale-fs-1m <root>` | Runs release writer and reader processes over an explicitly selected filesystem. Clean revision `f4d05b0` passed three 1M runs at 955,781,120-956,370,944 B writer RSS, 1,009,922,048-1,010,692,096 B reader RSS, 5.324-5.482 s recovery, 1.268284240x writes, exact cardinality, 245 active runs, and exact sentinel reads. This host was not the pinned release runner. |
| Complete candidate scale sample | `just preview-gate-scale-candidate <root>` | Runs the three-sample path-length matrix plus fresh-process 10k, 100k, and 1M filesystem tiers. Use the documented pinned runner and retain `<root>` with the release record. Reports bind the source revision and mark dirty builds. |
| Kopia measured matrix | `cargo run -p xtask --bin xtask --features containers -- integration kopia-measured-matrix --runs 3 --profile-set larger-restores --gateway-build-profile release --enforce-regression-budgets` | Release-grade Kopia restore comparison against the straight RustFS proxy baseline with current gateway defaults. |
| Revision-bound Kopia candidate profile | `just perf-kopia-profile-candidate <profile>` | Three alternating direct/gateway pairs for one bounded real-client profile, with the exact clean or `-dirty` source revision embedded in `summary.json`. Run all five release-process profiles. |

Expensive lanes emit artifacts under `.local/integration/` by default.
The scale recipes use three runs unless `RS3_SCALE_GATE_RUNS` is set to a
different positive integer. A scale run is successful only after new-instance
reload, cardinality verification, and sentinel payload reads; write throughput
alone is not a recovery or release result. The underlying harness options
`--max-cold-read-amp` and `--max-cold-read-requests-per-read` require
`--verify-reload`. The `--max-active-index-runs` option also requires reload
verification and checks the authenticated recovered catalog, not writer memory.
The in-memory scale recipes also enforce `--max-elapsed-seconds 180`,
`--max-reload-elapsed-seconds 30`, and `--max-peak-rss-bytes 4294967296`.
The filesystem recipes use the same write ceiling, a conservative 180-second
complete reader-verification ceiling, and separate 4 GiB writer and reader RSS
ceilings. Release timing claims still require the documented pinned runner.
Peak RSS comes from the harness process high-water mark, so an over-budget
attempt fails even when all correctness checks pass. The harness prints the
measurement before returning an aggregated gate error, so one expensive run
retains every available failure and its JSON evidence.
After recovery, the harness resets its observation window,
reads the first, middle, and last object, and fails unless those reads use only
the permitted exact range `GET` requests and bytes. JSONL and TSV output report
the cold-read counters separately from recovery.

These lightweight lanes qualify write amplification, bounded recovery, direct
cold sentinel reads, sentinel correctness, and the recovered active-run budget.
Automatic compaction performs bounded passes beginning at 256 active runs,
each selecting at most 128 active runs across levels 0 and 1.
Each window is also capped at 131,072 mutations and 16 MiB of stored run
sections; catalog-only selection favors more runs and lower rewrite cost.
Accepted blinded-key generations identify obsolete upserts after source
validation; winning tombstones and references outside the window remain. A missing guard or fully validated
nonreducing bounded plan may defer and retry at later 64-run boundaries before
pausing at 896. Configured-guard, corruption, storage, anchor, and other
compaction errors poison immediately. The current 4,096-record
low-amplification 1M lane finishes at 245 runs without crossing the trigger.
The earlier 1,024-record adversarial lane crossed six compaction windows and
recovered 233 runs. Keep both lanes; one does not prove the other. Release
timing still requires the documented pinned runner.

`just test-churn-scale` runs 1,024 overwrite/delete/recreate cycles against an
independent fixed-key model. Every cycle asserts one active run after
compaction and fresh recovery, one replay commit, at most 32 compaction GETs,
12 HEADs, 64 KiB read and 16 KiB written. Signed section spans prove zero
payload reads or writes during compaction. Guarded exact-version GC reclaims
obsolete objects while fresh current and protected historical roots still
restore. A 64-cycle variant runs in `just check`. Planner regressions also cover
full older shards that would otherwise block later churn, tombstone masking
and invalid obsolete source facts. These deterministic memory-store checks do
not qualify retained providers or production timing.

The filesystem lane proves a fresh application process with empty rs3 caches;
it does not claim a cold kernel page cache. Use a pinned local-disk mount rather
than `/tmp`, preserve every generated run directory, and record any runner-level
cache-control procedure separately.

The current gateway no longer has a v1 repository runtime. Commands with `v2`
in their names keep their existing harness names, but they exercise the only
supported repository format.

## S3 Provider Qualification

Do not infer production support from S3 compatibility alone. A live provider
trial must choose and verify one storage safety profile:

- `atomic-create`: a second `PutObject` with `If-None-Match: *` for an existing
  current object must fail instead of creating a new version.
- `retained-version`: Object Lock/versioning must return provider version IDs
  for retained writes, block version deletion before expiry, and support
  exact-version reads after a newer latest version exists. Retained multipart
  completion must also return a protected exact version. This profile requires
  read-after-write consistency for the completed retained version, because the
  gateway verifies multipart postconditions immediately and fails closed when
  it cannot read the completed version.

The shared memory, filesystem and live S3 contract checks string prefixes,
complete inventory under raw-member page limits, and consistent range errors.
The versioned tests also delete an unprotected current value above a protected
older version, verify that the older exact version remains readable and cannot
be deleted, and count delete markers when paging the inventory. Multipart tests
check that duplicate or out-of-range internal parts fail without changing the
accepted upload. These internal parts are distinct from client-facing S3
multipart sessions. SDK request fixtures verify that empty or missing-part
completion attempts abort the internal upload without publishing it, including
when cleanup is denied. Cleanup remains best effort; these tests do not prove
cleanup after process cancellation.

SDK response fixtures cover missing or non-advancing pagination cursors,
missing completion flags, delete-marker-only pages and exact full-read lengths.
A successful container run is local provider evidence; repeat these tests on
the configured provider before qualifying a deployment.

`HEAD` before `PUT` is not the production fallback for create-only writes. It is
non-atomic and only useful for a deliberately degraded compatibility mode, which
is not part of the production-preview contract.

Use `--qualification-profile retained-version --object-lock` for providers
where retained version IDs are the safety primitive. The command
rejects `retained-version` without `--object-lock` because the profile is only
meaningful when the retention and exact-version checks run:

```sh
just integration-s3-local --qualification-profile retained-version --object-lock
```

For retained gateway qualification, use the guarded Kubernetes fixture:

```sh
just preview-gate-v2-retained-local
```

This runs direct Object Lock/exact-version checks, then a 30-day COMPLIANCE
repository with journaled initialization, a Kubernetes Lease, and AWS CLI,
rclone, mc and restic round trips. It uses disposable local providers. It does
not qualify an external provider or demonstrate an elapsed retention window.

The legacy `preview-gate-v2-live`, `integration-s3-gateway-v2-live` and
`integration-kopia-gateway-v2-live` recipes still include retained local
memory-anchor launchers. Those launchers cannot meet the current recovery
maintenance-guard requirement and are not current end-to-end qualification
commands. For an external backend, qualify the provider and exercise backup
and restore through a journaled Kubernetes deployment as described in
[Production Preview](production-preview.md). External-provider qualification
remains a separate requirement.

For governance mode, review IAM or bucket policy so normal gateway credentials
cannot bypass governance retention. `RS3_GOVERNANCE_BYPASS_REVIEWED=true` records
that operator assertion; the live Object Lock probe does not establish it.

`integration k8s-gateway --keep-cluster` retains the kind cluster for log and
resource inspection. Its disposable S3 backend is still removed, so the kept
gateway is not usable for further requests.

## Privacy Tests

Features that handle logical names should verify:

- plaintext paths do not appear in backend object IDs
- plaintext paths do not appear in unauthenticated repository metadata
- logs, traces, metrics labels, and errors remain redacted
- generated Kubernetes-like names do not leak into backend storage

## Rollback Tests

Rollback-sensitive changes should cover:

- latest anchored commit accepted
- stale commit rejected after anchor advance
- anchor digest mismatch rejected
- missing configured anchor fails closed
- commit write succeeded but anchor advance failed
- recovery accepts an already-written identical commit object

## Retention Tests

Retention and Object Lock work should cover:

- native conditional create rejects duplicate create-only writes for the
  `atomic-create` profile
- retention extension never shortens existing retention
- retained writes fail when the provider does not return version IDs
- retry after an anchor failure remains safe when a retained-version provider
  appends a same-key version instead of rejecting duplicate create-only writes
- exact-version reads return the anchor-bound object after a newer latest
  version exists
- legal hold blocks destructive cleanup
- provider cannot extend retention
- governance bypass is not present in normal gateway credentials
- garbage collection does not remove reachable or retained objects

The ignored live S3 Object Lock tests exercise provider version IDs against a
real retained bucket. They are the lane for S3-compatible providers where local
RustFS/container tests cannot verify retained version-addressed reads.

## Performance Tests

Performance changes should update the measured matrix when they affect:

- payload segment size
- range `GET`
- namespace listing
- commit batching
- S3 request body handling
- backend storage adapters
- metrics collection overhead
- adaptive payload segment sizing
- decrypted segment cache behavior

Use release-profile gateway runs for performance claims. Debug builds are useful
for development but distort medium and larger payload timings.
