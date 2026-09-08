# rs3-gateway Helm Chart

This chart deploys the `rs3` S3-compatible backup gateway for one repository.
The chart is preview-scoped: keep one read-write gateway per repository, use a
Kubernetes Lease anchor, and provide repository identity plus key material
deliberately.

Follow [Deploy, Back Up, and Restore](../../docs/site/deploy-backup-restore.md)
for one configuration, journaled Helm initialization, and a verified Kopia round
trip.

## Prerequisites

- A Kubernetes cluster with a namespace for the gateway.
- An object-store backend or a local `file://` backend for development.
- Static S3 credentials for backup clients.
- A bearer token Secret for the admin listener health and operator-fact routes.
- Repository ID and keyring wrapping key material. The public salt is
  generated at initialization unless `repositoryKeys.saltHex` pins it.
- Lease RBAC, either created by this chart or managed externally.
- Journaled S3 bootstrap (`bootstrap.enabled=true`), or an existing initialized
  repository and a ConfigMap containing current provider-conformance JSON.

## Local evaluation

For a disposable local filesystem smoke, use the explicit memory-anchor example
in [Getting Started](../../docs/site/getting-started.md#run-a-local-gateway-smoke).
Kubernetes serving refuses `repository.allowInit=true`: use the journaled S3
bootstrap Job below for a new chart deployment. A memory anchor is not durable
recovery authority.

## Production-Like Values

Prefer externally managed Secrets so credentials and wrapping keys do not land in
Helm release history:

```yaml
image:
  repository: registry.example.internal/backup/rs3-server
  digest: sha256:<replace-with-the-published-64-character-digest>

backend:
  endpoint: https://s3.example.internal
  bucket: rs3-backend
  prefix: tenant-a/repository
  region: us-east-1

backendCredentials:
  existingSecret: rs3-backend-credentials

credentials:
  existingSecret: rs3-client-credentials

admin:
  enabled: true
  existingTokenSecret: rs3-admin-token

providerConformance:
  existingConfigMap: rs3-provider-conformance
  reportKey: report.json

maintenance:
  # Empty selects the server default, auto, for read-write gateways.
  mode: ""

alerts:
  enabled: true

metrics:
  enabled: true
  serviceMonitor:
    enabled: true

networkPolicy:
  enabled: true
  ingress:
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: backup-clients
    podSelector: {}
    metrics:
      namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: monitoring
      podSelector:
        matchLabels:
          app.kubernetes.io/name: prometheus
  egress:
    backend:
      to:
        - ipBlock:
            cidr: 10.20.0.0/16
    kubeApi:
      to:
        - ipBlock:
            cidr: 10.30.0.0/24
    dns:
      to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns

repository:
  id: tenant-a-repository
  allowInit: false
  retention:
    mode: governance
    days: 30

repositoryKeys:
  existingSecret: rs3-repository-keys
  envelopeObjectId: ""
  wrappingKeyId: wrap-v1

anchor:
  mode: kubernetes-lease
  namespace: ""
  name: tenant-a-rs3-anchor
```

Expected Secret keys are:

| Values block | Secret keys |
| --- | --- |
| `backendCredentials.existingSecret` | `access-key-id`, `secret-access-key` |
| `credentials.existingSecret` | `access-key-id`, `secret-access-key` |
| `admin.existingTokenSecret` | `bearer-token`; optional `mutation-bearer-token` for maintenance `POST` routes |
| `repositoryKeys.existingSecret` | `wrapping-key-hex`; optional `salt-hex`, `envelope-object-id`, `wrapping-key-id` |

`envelope-object-id` may be omitted to use the default envelope object.
`salt-hex` may be omitted: initialization generates the public salt, journals
it, and the gateway recovers it from the verified envelope on every start.

Kubernetes onboarding and normal serving do not require `recovery.publicKey`.
They use the declared repository-key Secret and live Lease, and bootstrap
verifies a fresh payload restore before admission. `recovery.publicKey` is
optional configuration for portable signed-bundle recovery commands. Preserve
keys, repository configuration and a trusted checkpoint outside the cluster
when total-cluster-loss recovery is required; the bootstrap journal alone does
not provide that capability.

## Operational Notes

- `admin.profile=production` makes chart rendering fail unless the image is
  digest-pinned, the backend endpoint uses HTTPS (or the default AWS `s3`
  endpoint), the admin readiness listener is enabled, and all secret material
  comes from existing Secret references. Use `admin.profile=local` only for
  disposable development fixtures.
- Keep `updateStrategy.type=Recreate` for read-write gateways so rollouts do not
  briefly run two writers against the same repository.
- Keep `gateway.writerGuard=required` with `anchor.mode=kubernetes-lease` for
  read-write deployments.
- Production read-write rendering requires `bootstrap.enabled=true` or
  `providerConformance.existingConfigMap`. For external evidence, generate its `reportKey` with `rs3
  check-v2-provider --format json` against the selected retained backend and
  refresh it before `providerConformance.maxAgeSeconds` expires. The production
  doctor and maintenance engine fail closed on missing, stale, failed, or
  profile-mismatched evidence. The v2 report also requires the complete check
  manifest and a target fingerprint matching the configured endpoint, bucket,
  prefix, and `providerConformance.principalFingerprint`. Governance retention
  requires that fingerprint so rotating to a differently privileged principal
  invalidates old evidence.
- Full maintenance runs inside the gateway. `maintenance.mode=auto` is the
  read-write default; `manual` disables background triggers, and `off` disables
  the supervisor. Inventory ceilings and pacing are configured under the
  `maintenance` values block. Do not deploy a second maintenance writer.
- Lease fencing coordinates writers that share one Kubernetes apiserver and
  anchor Lease. Disconnected read-write gateways that only share or synchronize
  S3 storage remain unsupported: an eventually consistent or malicious backend
  is not a safe lock service. Multiple disconnected `restore-readonly` readers
  are supported when each can verify the accepted anchored state.
- The chart enables the admin listener by default and uses unauthenticated
  `/healthz` for startup and liveness plus `/readyz` for readiness. The startup
  probe allows up to ten minutes for bounded repository recovery before
  liveness can restart the process. Admin fact routes still require the
  configured bearer token.
- `metrics.enabled=true` exposes the gateway metrics listener through the main
  Service. `metrics.serviceMonitor.enabled=true` also renders a Prometheus
  Operator `ServiceMonitor`. With metrics enabled, `alerts.enabled=true` renders
  path-private maintenance `PrometheusRule` alerts.
- The container runs with privilege escalation disabled, a read-only root
  filesystem, all Linux capabilities dropped, and a RuntimeDefault seccomp
  profile. The chart mounts an emptyDir at `/tmp` for scratch space, disables
  Kubernetes service-link environment injection, and mounts a service-account
  token only for Lease-backed deployments.
- Default resources request 512Mi/250m and limit memory to 1536Mi. There is no
  CPU limit by default. Every gateway hardening limit is rendered explicitly,
  including buffered and multipart upload thresholds, upload/download
  admission budgets, connection/request concurrency, request rate, and stream
  stall timeout. The chart rejects upload budgets that cannot simultaneously
  cover the buffered prefix plus multipart and payload-segment encoder working
  sets, enforces S3's 5 MiB through 5 GiB multipart-part range and 10,000-part
  object ceiling, and rejects concurrency values above the runtime semaphore
  capacity.
- Backend connect, first-byte, per-attempt, total-operation, and stalled-stream
  timeouts are finite under `backend.timeouts`. The chart rejects zero values or
  attempt/connect/read relationships that cannot fit within the total timeout.
- `networkPolicy.enabled=true` renders a baseline policy that admits S3 and,
  when enabled, metrics traffic only from their configured selectors. Egress is
  limited to configured backend, Kubernetes API, and cluster-DNS peers; DNS is
  fixed to UDP/TCP 53. The production profile rejects empty or selector-less
  peer entries instead of silently rendering allow-all rules. Empty
  local-profile selectors render deny-all ingress or egress, so configure
  cluster-specific peers before expecting connectivity. CoreDNS labels and
  service routing vary by cluster; verify the DNS peer against your network
  plugin, or replace the template with provider-specific policy such as Cilium
  CNP.
- Use `gateway.mode=restore-readonly` for restore readers that must not mutate
  repository state.
- Do not use `anchor.allowMemory=true` outside local development.
- Backend bucket names, prefixes, Kubernetes namespaces, and repository IDs are
  operator-visible configuration. Plaintext client paths must not appear in
  backend object keys or unauthenticated metadata.

## Validation

Lint the chart with fixture values:

```sh
just helm-lint
```

Render with your values before rollout:

```sh
helm template rs3 charts/rs3-gateway -f values.production.yaml
```

## Journaled S3 initialization

Set `bootstrap.enabled=true` to qualify the configured S3 backend and initialize
an empty repository through a chart-managed Job. Keep `repository.allowInit=false`
for serving. The anchor must use a Kubernetes Lease in the release namespace.
Governance qualification requires `bootstrap.governanceBypassReviewed=true` after
reviewing the configured principal; compliance mode does not use that assertion.

The Job and gateway share the same image, service account, backend credential
references and runtime policy. A read-only init container waits for completed
journal state, a verified and logically removed synthetic restore fixture, and
current evidence before the gateway starts. Evidence projects
from the journal Secret automatically; `providerConformance.existingConfigMap`
continues to select externally managed evidence and is never overwritten.

Every Helm revision creates a new Job and prunes the previous one; the journal
Secret is the durable record. A Job that finds the journal completed under the
current configuration verifies the live anchor and chain read-only, without the
writer Lease, so ordinary upgrades and repeated installs do not contend with a
serving gateway. Only initialization and fresh qualification take the Lease.
While the previous gateway pod still holds it, that Job attempt fails fast
instead of waiting; the required `Recreate` strategy stops the old pod and a
retry acquires the Lease. After an exhausted or failed Job, correct the cause
and repeat the same Helm command. The journal permits at most three complete
probe runs across retries and upgrades. An ambiguous run consumes a reservation; exhaustion requires
reviewed matching external evidence. Retained probe versions, including legal
holds, can remain outside the repository prefix.
The init Job's JSON report and journal retain timestamped aggregate observations
of these versions and their reported protection deadlines. Warnings and
`multipart_sessions_observed=false` expose observation limits. The report is
not a complete inventory or cleanup authorization.

The chart declares a stable journal Secret without templating its runtime data.
It is retained on Helm uninstall. Preserve it and its ownership annotations in
GitOps pruning policies. To use a predeclared dedicated Secret, set
`bootstrap.existingJournalSecret` and annotate it `rs3.rs/bootstrap-journal: v1`.

This opt-in flow automates provider qualification, initialization and a fresh
payload round trip. Independent
off-cluster recovery export and verification remain separate requirements.

## Historical read-only reader

Deploy a separate release with the original external key and credential Secret
references, repository ID, backend, and exact anchor name/namespace. Set
`gateway.mode=restore-readonly`, `bootstrap.enabled=false`,
`repository.allowInit=false`, and leave `maintenance.mode` empty. Set
`recovery.point` to the quoted decimal sequence returned by `recovery-points`;
empty means the current accepted anchor. The chart rejects a historical selector
in read-write mode and rejects values outside the unsigned 64-bit range.

When initialization generated provider evidence, set
`bootstrap.existingJournalSecret` to the original journal name even with
bootstrap disabled. Its evidence remains projected without an init Job, journal
writes, or replacement Secret. An explicit `providerConformance.existingConfigMap`
continues to take precedence. Do not delete the original retained journal when
changing modes. External key Secrets are reused without generating key material.
See the [reader overlay](../../docs/site/deploy-backup-restore.md#recover-an-earlier-gateway-state).
