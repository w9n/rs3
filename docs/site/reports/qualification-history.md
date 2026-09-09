# Historical qualification evidence

This archive records earlier gateway, provider and compatibility runs with their
named revisions and limits. It is useful regression and storage-contract
evidence, but it does **not** qualify the current `commits/v03` preview or a
selected provider. Exact backend prefixes and private raw logs are deliberately
not published here.

For the current preview contract and release requirements, see
[Production Preview](../production-preview.md). For current cost evidence, see
[Performance](../performance.md).

## Archived evidence


Release evidence below is maintainer-run evidence. Unless a row explicitly
identifies the current `v03` format and source revision, treat it as historical compatibility,
storage-contract, and gateway regression evidence for the deprecated preview
implementation. Those historical rows predate the generation switch and do not
exercise the current packed-run compaction schedule, automatic watermark
backpressure, or exact catalog-root GC. Exact backend prefixes and
workspace-local artifact paths are not part of the public evidence record
because they are operational identifiers. Preserve raw reports, checksums, and
run logs in release assets or private evidence bundles when independent review
needs them.

At a glance:

- consolidated v2 live preview gate passed against the retained-version profile
- live provider qualification covered exact-version reads, retained multipart
  completion, and retention behavior
- provider conformance can be preserved as JSON and surfaced through admin
  posture without rerunning live probes from status; v2 evidence binds the
  complete check manifest to a path-safe fingerprint of the qualified target
- current retained qualification additionally requires actual provider DELETE
  probes from a separate synthetic namespace; historical local-guard deletion
  checks do not satisfy this requirement
- DR rehearsal verified bundle export, missing-Lease rejection without retention
  context, and anchor import into a new cluster
- 2026-05-18 live checks reran the retained-version gate after adding
  post-complete verification for retained multipart writes
- local performance and compatibility smokes remain release evidence, not a
  provider certification

The then-current v03 performance was reported in [Performance](performance-2026-09-08.md#backend-comparison-september-8-2026):
the September 8 comparison includes three-sample throughput, Kopia backup/restore,
scale, RSS, and byte accounting. All 120 Kopia content checks pass, but sequential
512 B amplification and large-PostgreSQL Kopia elapsed time fail their budgets.
The measurements are shared-host evidence with unrestricted Docker providers,
not dedicated-runner or external-provider qualification.

The older table below retains historical qualification evidence for its named
revisions; it does not establish current candidate performance.

| Evidence | Result |
| --- | --- |
| Historical host-local fresh-process scale | Revision `f4d05b0` passed the complete 10k, 100k, and 1M three-sample filesystem gate plus the path-length matrix on 2026-07-13. The 1M writers completed in 59.589-60.105 s at 955,781,120-956,370,944 B RSS and 1.268284240x writes. Fresh readers recovered in 5.324-5.482 s at 1,009,922,048-1,010,692,096 B RSS, listed exactly one million objects and 245 runs, and used one exact `GET` at 1.03125x per sentinel. This is clean host-local correctness and resource evidence, not pinned-runner timing, HTTP gateway, or provider qualification. |
| Historical candidate-bound Kopia matrix | Revision `7d87f90` passed all five separately bounded three-pair profiles on 2026-07-13 with source-bound summaries, workload consistency, and every expanded regression budget. Backend reads were 1.01-1.04x and writes were approximately 1.00x. Total elapsed was 0.29-1.62x and average gateway HWM RSS was 150.08-633.88 MiB, within the 1.75x and 1.25 GiB gates. This is local RustFS evidence, not a live-provider claim. |
| Historical standalone S3 and gateway baseline | Revision `f4d05b0` passed the equal-work `just perf-standalone-gate` against disposable RustFS on 2026-07-13. Release-gateway throughput at concurrency 1/2/4/8 was 98.50/190.33/281.76/401.28 MiB/s, or 4.07x scaling. Every point stayed at 1.000270x writes, 1.000246x verification reads, and 2.000515x total verified I/O. Peak RSS was 223,387,648/397,221,888/631,521,280/1,006,772,224 B. |
| Historical bounded full-restore HTTP baseline | Revision `765229e` passed three release-gateway runs of three complete 256 MiB restores. Average read latency was 581.727-664.972 ms, plaintext throughput was 373.240-428.565 MiB/s, gateway peak RSS was 564,342,784-564,801,536 B including the in-process ciphertext backend and preceding upload, and every restore used one backend GET at 1.000244420x read amplification. The final candidate must rerun this lane. |
| Historical local Kubernetes release gate | Revision `e16c418` passed the standalone gate, direct Kopia, fresh-kind Velero/Kopia dynamic-PVC gateway-restart restore, and Velero/Postgres restore on 2026-07-12. This remains behavior evidence, but its Kubernetes summaries predate source-bound nested-image reporting and cannot qualify a later candidate. |
| Historical local retained-version and exact-GC gate | Revision `80a51b2` passed `just preview-gate-v2-retained-local` against disposable Object-Lock-enabled RustFS on 2026-07-12. All four live storage tests and the isolated exact-GC rehearsal passed. This remains local regression evidence, not current schema-v5 external-provider, restart, or fault qualification. |
| Live retained-backend v2 preview gate | Passed on 2026-05-18 with `just preview-gate-v2-live`. S3 gateway/tooling, Kopia, Kubernetes Lease, Velero dynamic-PVC gateway-restart, and Velero/Postgres lanes all passed against fresh opaque backend prefixes. |
| Live retained-backend v2 GC rehearsal | Passed on 2026-05-21 with `just v2-gc-rehearsal-live` against a fresh Object Lock prefix. The dry run found two orphan candidates, planned one exact-version delete, treated the retained orphan as protected, applied one unprotected exact-version delete, left the protected candidate blocked, and reloaded the anchor-selected chain. |
| Live retained-backend v2 DR anchor import/export | Passed on 2026-05-18 against fresh v2 Velero dynamic-PVC gateway-restart output. The source backup/restore lane passed, the source bundle verified 34 commits, a new kind cluster with a missing Lease rejected import when the retention context was omitted, import with governance retention recreated the Lease, and the recovered bundle verified the same anchor. |
| Live retained-backend v2 provider conformance | Passed on 2026-05-18 with `rs3 check-v2-provider` for the retained-version/Object Lock profile, including retained multipart completion, exact-version `HEAD`, `GET`, range `GET`, overwrite version survival, retention extension, delete blocking, legal hold, and the governance-bypass review marker. A focused live storage test also confirmed retained multipart exact-version range read and version-delete blocking. A provider-specific SDK probe found that retention metadata may not appear on `HEAD` when retention is supplied only on `CreateMultipartUpload`; rs3 therefore verifies the completed version and applies provider protection to that returned version when required. This evidence predates the current standalone exact-version post-completion horizon renewal and must be rerun. |
| Live retained-backend v2 Velero dynamic-PVC gateway-restart restore | Passed on 2026-05-18 with `just preview-gate-v2-live` against an Object Lock bucket with repository governance retention enabled; backup and restore completed, restored bytes matched, and v2 Lease assertions passed after backup, after gateway restart, and after restore. |
| Live retained-backend v2 Velero/Postgres restore | Passed on 2026-05-18 with `just preview-gate-v2-live` against an Object Lock bucket with repository governance retention enabled; Postgres rows were backed up and restored, and v2 Lease assertions passed after backup and after restore. |
| Live retained-backend v2 Kopia gateway backup/restore | Passed on 2026-05-18 as part of `just preview-gate-v2-live` against an Object Lock bucket with repository governance retention enabled; restored bytes matched. |
| Live retained-backend v2 gateway smoke | Passed on 2026-05-18 as part of `just preview-gate-v2-live` through the local gateway using `mc` and default `rclone lsf` for `PUT`, `HEAD`, `GET`, and prefix listing with governance retention. |
| v2 Kubernetes Lease gateway smoke | Passed on 2026-05-18 as part of `just preview-gate-v2-live`; Helm deployed the then-default v2-preview gateway with Kubernetes Lease anchoring, the S3 smoke passed, and the harness verified v2 Lease annotations. |
| Local v2 streamable payload checks | Passed on 2026-07-11 with focused repository and gateway tests plus `just check-s3`. These checks cover canonical framed known-length, repository-layer EOF-finalized and zero-length streams, signed payload-section validation, checkpoint/reload, metadata-only compaction, GC reachability, and retained multipart Object Lock compile coverage. The public S3 boundary requires a declared or SigV4-decoded length; unsigned HTTP chunked PUT is rejected with `411 MissingContentLength`. |
| Local v2 Velero dynamic-PVC gateway-restart smoke | Passed on 2026-05-17 with `just integration-velero-kopia-dynamic-pvc-gateway-restart-smoke` on a fresh kind cluster. Backup completed, the gateway deployment was restarted, restore completed, restored pod data was verified, and the cluster was deleted. |
| Local v2 Velero/Postgres RustFS smoke | Passed on 2026-05-16 after v2 concurrent payload-section cache fills were coalesced. The gateway run completed backup and restore, wrote no backend `segments/` objects, read 29.0 MB versus 28.9 MB for the direct RustFS baseline, and used 57 backend requests versus 708 for direct RustFS. |
| Local v03 gateway perf baseline | Refreshed on 2026-05-16 with `just perf-s3-gateway --objects 16 --object-size 4096 --reads 16 --range-len 512 --commit-batch-items 8 --concurrency 8 --format jsonl`. Sequential writes emitted one backend commit PUT per client object, parallel writes batched to 2 PUTs for 16 objects, and repeated full/range reads of one object reused a verified payload-section cache after the first commit GET. |
| Local v2 S3 and Kopia gateway smokes | Passed on 2026-05-16 with `just integration-s3-gateway` and `just integration-kopia-gateway` after the v2 read-cache and measurement-surface repairs. |
| Live retained-version S3 qualification | Passed on 2026-05-16 with `xtask integration s3-local --qualification-profile retained-version --object-lock`; Object Lock retention and legal hold checks passed with versioned delete blocking. |

??? note "Background compatibility evidence"
    | Evidence | Result |
    | --- | --- |
    | Live retained-backend Kopia gateway backup/restore | Passed on 2026-05-13 against an Object Lock bucket with repository governance retention enabled. |
    | Live retained-backend Velero dynamic-PVC gateway-restart restore | Passed on 2026-05-13 against an Object Lock bucket with repository governance retention enabled. |
    | Velero dynamic-PVC gateway-restart in `read-write` | Passed on 2026-05-12 with restore status `Completed`. |
    | Velero strict `restore-readonly` incident-restore smoke | Passed on 2026-05-12 with workload verification, expected restore-artifact write denial, and zero backend writes during restore. |
    | Velero/Postgres compatibility smoke | Passed on 2026-05-12. |
    | Larger Kopia restore matrix | Passed on 2026-05-13 with adaptive payload segment sizing, `regression_budgets=pass`, and `workload_consistency=pass`. |

The release evidence is local harness evidence, not a provider certification. A
production-preview trial should still run the selected live S3-compatible
provider with an empty bucket and a deliberately preserved restore bundle. The
provider trial must explicitly choose `atomic-create` or `retained-version`.
The retained-version profile must include Object Lock, retained version IDs, and
exact-version reads after a newer latest object exists.
For governance-mode buckets, also review IAM or bucket policy so normal gateway
credentials cannot use governance-bypass permissions; the live retained-version
test does not replace that credential review.
