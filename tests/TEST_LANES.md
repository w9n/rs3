# Test Lanes

Use this file as the compact map of what each lane proves. Keep detailed setup
notes in the specific harness README or code.

| Lane | Command | Scope | Cost | When |
| --- | --- | --- | --- | --- |
| Format and unit | `just check` | Formatting, clippy, workspace unit tests. | Low | PR/default |
| S3 storage contract | `just integration-s3-local --mode container` | Storage backend contract against a disposable S3-compatible provider. | Medium | PR when storage changes |
| Gateway S3 contract | `just integration-s3-gateway` | Local gateway process, backend provider, S3 object operations through the gateway. | Medium | PR when gateway/repository changes |
| Kopia gateway smoke | `just integration-kopia-gateway` | Real Kopia repository create, snapshot, restore through the local gateway. | Medium | PR when compatibility changes |
| Kubernetes chart smoke | `just integration-k8s-gateway` | Docker image build, kind cluster, Helm install, readiness, S3 smoke through port-forward. | High | Nightly or release-gate |
| Velero Kopia smoke | `just integration-velero-kopia-smoke` | Velero node-agent/Kopia backup and restore of one pod volume through the gateway, with restored file content verification. | High | Nightly first, then selective PR gate |
| Velero Kopia local-PV smoke | `just integration-velero-kopia-local-pv-smoke` | Velero node-agent/Kopia backup and restore of one static local PV through the gateway, with original data removed before restore. | High | Nightly/release-gate |
| Performance baseline | `just perf-s3-gateway -- --format jsonl` | Backend request counts, latency, read/write amplification, throughput for gateway scenarios. | Medium/High | Nightly and before protocol changes |

Rules of thumb:

- Default checks should stay deterministic and cheap.
- Every compatibility lane must verify restored bytes or Kubernetes object state, not only command success.
- Expensive lanes should emit artifacts: gateway logs, object request counts, latency summaries, and relevant Kubernetes resources.
- The Helm chart is the Kubernetes packaging source; tests should install it instead of duplicating manifests.
