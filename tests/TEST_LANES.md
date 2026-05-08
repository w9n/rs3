# Test Lanes

Use this file as the compact map of what each lane proves. Keep detailed setup
notes in the specific harness README or code.

| Lane | Command | Scope | Cost | When |
| --- | --- | --- | --- | --- |
| Format and unit | `just check` | Formatting, clippy, workspace unit tests. | Low | PR/default |
| Preview local gate | `just preview-gate-local` | Default checks, S3-feature checks, and dependency policy checks. | Medium | Preview handoff |
| S3 storage contract | `just integration-s3-local --mode container` | Storage backend contract against a disposable S3-compatible provider. | Medium | PR when storage changes |
| Gateway S3 contract | `just integration-s3-gateway` | Local gateway process, backend provider, S3 object operations through the gateway. | Medium | PR when gateway/repository changes |
| Kopia gateway smoke | `just integration-kopia-gateway` | Real Kopia repository create, snapshot, restore through the local gateway. | Medium | PR when compatibility changes |
| Kubernetes chart smoke | `just integration-k8s-gateway` | Docker image build, kind cluster, Helm install, readiness, S3 smoke through port-forward. | High | Nightly or release-gate |
| Velero Kopia smoke | `just integration-velero-kopia-smoke` | Velero node-agent/Kopia backup and restore of one pod volume through the gateway, with restored file content verification. | High | Nightly first, then selective PR gate |
| Velero Kopia local-PV smoke | `just integration-velero-kopia-local-pv-smoke` | Velero node-agent/Kopia backup and pod-volume data restore for one bound static local PV through the gateway, with original data removed before restore. | High | Nightly/release-gate |
| Velero Kopia dynamic PVC smoke | `just integration-velero-kopia-dynamic-pvc-smoke` | Velero node-agent/Kopia backup and namespace restore for one dynamically provisioned OpenEBS LocalPV PVC through the gateway, with restored file content verification. | Very high | Nightly/release-gate |
| Velero gateway-restart smoke | `just integration-velero-kopia-dynamic-pvc-gateway-restart-smoke` | Same dynamic PVC restore path, but restarts the stateless gateway between backup and restore, switches to `restore-readonly`, verifies restored bytes, and asserts restore traffic made no backend writes. | Very high | Nightly/release-gate |
| Velero Postgres smoke | `just integration-velero-kopia-postgres-smoke` | Small Postgres pod on dynamic PVC, `pg_dump`/checkpoint hook before backup, live SQL verification after restore. Compatibility smoke only; not the production Postgres backup model. | Very high | Nightly/release-gate |
| Preview release gate | `just preview-gate-release` | Kopia gateway, Velero dynamic PVC gateway-restart, and Velero Postgres smoke. | Very high | Manual release candidate |
| Lightweight gateway perf smoke | `just perf-s3-gateway -- --format jsonl` | Small-object gateway request counts, latency, read/write amplification, and throughput. | Medium/High | Nightly and before protocol changes |
| Kopia measured matrix | `cargo run -p xtask --bin xtask --features containers -- integration kopia-measured-matrix --runs 3 --profile-set larger-restores --gateway-build-profile release --payload-segment-size 512 --enforce-regression-budgets` | Release-grade Kopia restore comparison against the straight RustFS proxy baseline with workload consistency and regression budgets. | High | Manual release candidate |

Rules of thumb:

- Default checks should stay deterministic and cheap.
- Every compatibility lane must verify restored bytes or Kubernetes object state, not only command success.
- Expensive lanes emit artifacts under `.local/integration` by default: gateway logs, anchor snapshots, backend operation counts, amplification ratios, latency summaries, and relevant Kubernetes resources.
- Current local performance baseline results are summarized in `tests/PERFORMANCE_BASELINE.md`.
- The Helm chart is the Kubernetes packaging source; tests should install it instead of duplicating manifests.
- Local development can pass `--reuse-kind-cluster --cluster-name <name>` to avoid recreating kind on every run; CI should use disposable clusters unless cleanup is owned by the job.
- CI should use mirrored third-party images through harness image variables instead of relying on anonymous public registry pulls.
