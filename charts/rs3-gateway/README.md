# rs3-gateway Helm Chart

This chart deploys the `rs3` S3-compatible backup gateway for one repository.
The chart is preview-scoped: keep one read-write gateway per repository, use a
Kubernetes Lease anchor, and provide repository identity plus key material
deliberately.

## Prerequisites

- A Kubernetes cluster with a namespace for the gateway.
- An object-store backend or a local `file://` backend for development.
- Static S3 credentials for backup clients.
- A bearer token Secret for the admin listener health and operator-fact routes.
- Repository ID, salt, and keyring wrapping key material.
- Lease RBAC, either created by this chart or managed externally.

## Local Smoke Install

For a local `file://` backend, enable the PVC and create fixture secrets through
values. This is not a production posture.

```sh
helm upgrade --install rs3 charts/rs3-gateway \
  --set persistence.enabled=true \
  --set credentials.create=true \
  --set-string credentials.accessKeyId=local \
  --set-string credentials.secretAccessKey=local-secret \
  --set admin.createToken=true \
  --set-string admin.bearerToken=local-admin-token-12345 \
  --set repositoryKeys.create=true \
  --set-string repositoryKeys.saltHex=1111111111111111111111111111111111111111111111111111111111111111 \
  --set-string repositoryKeys.wrappingKeyHex=2222222222222222222222222222222222222222222222222222222222222222 \
  --set repository.allowInit=true
```

`repository.allowInit=true` should only be used for a new, empty repository
prefix under operator control.

## Production-Like Values

Prefer externally managed Secrets so credentials and wrapping keys do not land in
Helm release history:

```yaml
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
  egress:
    backend:
      to:
        - ipBlock:
            cidr: 10.20.0.0/16
    kubeApi:
      to:
        - ipBlock:
            cidr: 10.30.0.0/24

repository:
  id: tenant-a-repository
  allowInit: false
  retention:
    mode: governance
    days: 1

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
| `admin.existingTokenSecret` | `bearer-token` |
| `repositoryKeys.existingSecret` | `salt-hex`, `envelope-object-id`, `wrapping-key-id`, `wrapping-key-hex` |

`envelope-object-id` may be omitted to use the default envelope object.

## Operational Notes

- Keep `updateStrategy.type=Recreate` for read-write gateways so rollouts do not
  briefly run two writers against the same repository.
- Keep `gateway.writerGuard=required` with `anchor.mode=kubernetes-lease` for
  read-write deployments.
- The chart enables the admin listener by default and uses unauthenticated
  `/healthz` on the admin port for readiness and liveness probes. Admin fact
  routes still require the configured bearer token.
- `metrics.enabled=true` exposes the gateway metrics listener through the main
  Service. `metrics.serviceMonitor.enabled=true` also renders a Prometheus
  Operator `ServiceMonitor`.
- The container runs with privilege escalation disabled, a read-only root
  filesystem, all Linux capabilities dropped, and a RuntimeDefault seccomp
  profile. The chart mounts an emptyDir at `/tmp` for scratch space.
- Default resources request 512Mi/250m and limit memory to 1536Mi. There is no
  CPU limit by default.
- `networkPolicy.enabled=true` renders a baseline policy that admits S3 traffic
  from the configured namespace/pod selector and allows egress rules for the
  backend endpoint and Kubernetes API. Keep those peers narrow for your cluster,
  or replace the template with provider-specific policy such as Cilium CNP.
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
