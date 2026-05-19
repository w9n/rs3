# Operations

This page describes the current operator-facing shape. Treat it as development
documentation until the repository format and hardened anchor path are stable.

## Runtime Configuration

The gateway reads environment configuration and can validate it without
starting the listener:

```sh
cargo run -p rs3-server -- doctor
```

For production posture checks:

```sh
cargo run -p rs3-server -- doctor --profile production
```

The production profile rejects memory anchors, retention-unsupported local
backends, plaintext S3-compatible backend endpoints, missing gateway
credentials, and missing repository retention for mutation-capable serving.

The gateway enforces finite data-plane limits from its own configuration:
maximum `PutObject` body size, buffered-body threshold, backend multipart part
size, in-flight upload body admission budget, open S3 connections, concurrently
executing S3 operations, and per-process S3 operation rate. Align ingress,
proxy, pod memory, and service mesh limits with the gateway values so oversized or
excessive traffic is rejected before it consumes pod resources. Known-length
`PutObject` bodies above the buffered threshold stream into backend multipart
commit uploads when the backend supports multipart. Unknown-length or chunked
uploads buffer only until the threshold is crossed, then continue through the
same multipart commit path and remain bounded by `RS3_MAX_PUT_OBJECT_BYTES`.

For serving:

```sh
cargo run -p rs3-server -- serve --bind 127.0.0.1:9080
```

The core server library also exposes path-redacted admin reports for operator
tooling. `GET /admin/posture` is cheap enough for routine polling and reports
runtime posture, profile findings, backend and anchor kind, retention settings,
and last persisted provider-conformance evidence. `GET /admin/status` adds
restore-trust and maintenance verification and may touch repository state.
Neither report exposes a path browser, configured bucket names, backend
prefixes, repository IDs, client-visible object paths, or secret material. Treat
these reports as preview fact models, not as stable workflow APIs.

To expose those facts over HTTP for local diagnostics or a tightly controlled
cluster integration, run a separate authenticated admin listener:

```sh
RS3_ADMIN_BIND=127.0.0.1:9082 \
RS3_ADMIN_BEARER_TOKEN=<admin-token> \
cargo run -p rs3-server -- serve --bind 127.0.0.1:9080
```

Then read `GET /admin/posture` for frequent polling and `GET /admin/status`
for deeper verification with a bearer token. Do not reuse Velero/Kopia S3
credentials or backend S3 credentials for this admin channel.

Run the read-only single-gateway console when an operator needs a browser view
of the same path-redacted facts:

```sh
RS3_CONSOLE_BIND=127.0.0.1:9083 \
RS3_CONSOLE_BEARER_TOKEN=<console-token> \
RS3_GATEWAY_ADMIN_URL=http://127.0.0.1:9082 \
RS3_GATEWAY_ADMIN_BEARER_TOKEN=<admin-token> \
cargo run -p rs3-console
```

Open `http://127.0.0.1:9083/` and enter the console token. The browser calls the
console, not the gateway admin listener; the gateway admin bearer token remains
server-side. The console can proxy both `/api/posture` and `/api/status`, stays
read-only, and does not execute recovery, key rotation, deployment, or cleanup
workflows.

See [Configuration](reference/configuration.md) for the environment variable
reference.

## Keys And Bootstrap

The gateway uses an encrypted keyring envelope. Operators provide a stable
repository ID, a stable public salt, and a wrapping-key source. For an anchored
repository, startup reads the accepted v2 anchor, verifies the signed commit
chain and format root, and opens the keyring envelope bound through that format
root. It does not trust S3 listing order or a mutable "latest" object to choose
repository state.

For a first empty repository, startup initializes a new random purpose-specific
keyring and writes the encrypted envelope under a default counted `keyrings/`
object name. `RS3_KEYRING_ENVELOPE_OBJECT_ID` is optional and exists only as an
explicit bootstrap or recovery override.

If the envelope is missing but the prefix already contains repository objects, or
if the anchor already contains an accepted commit position, startup fails
closed. This prevents accidental second-repository initialization on top of
existing backup data.

Operational rules:

- Prefer generated random data keys inside an encrypted keyring envelope.
- Provide a high-entropy wrapping key. If the operator starts from a human
  passphrase, derive the wrapping key outside `rs3` with a KMS, HSM, Vault, or
  password KDF before setting `RS3_KEYRING_WRAPPING_KEY_HEX`.
- Keep wrapping keys, KMS access, HSM access, or Vault tokens outside the object
  store and outside broad cluster write credentials.
- Provide a stable salt once per repository and keep it with trusted repository
  configuration and recovery material.
- Treat salts as public restore metadata, not as second passwords.
- Keep historical keys available for at least the maximum retention window.
- Do not destroy a key while any retained commit can reference data that
  requires it.

For a first empty repository, configure the repository context and wrapping key:

```sh
RS3_REPOSITORY_ID=prod-backups
RS3_REPOSITORY_SALT_HEX=<stable-public-salt-hex>
RS3_KEYRING_WRAPPING_KEY_ID=wrap-2026-05 # optional; defaults to wrap-v1
RS3_KEYRING_WRAPPING_KEY_HEX=<wrapping-key-hex>
```

In Helm, set `repositoryKeys.create=true` or provide
`repositoryKeys.existingSecret`. The required Secret keys are `salt-hex` and
`wrapping-key-hex`; `wrapping-key-id` is optional and defaults to `wrap-v1`;
`envelope-object-id` is an optional override. Helm values stay declarative; the
gateway writes the encrypted envelope object, not mutated chart state.

Set `repository.allowInit=true` only for deliberate first initialization on a
fresh backend prefix. Leave it false for normal serving of an existing
repository and recover a missing anchor from a trusted restore bundle.

Inspect an existing envelope when auditing key lifecycle state:

```sh
cargo run -p xtask --bin xtask -- keyring inspect \
  --repository-id prod-backups \
  --repository-salt-hex <salt-hex> \
  --envelope-object-id <format-bound-envelope-object-id> \
  --wrapping-key-id wrap-2026-05 \
  --wrapping-key-hex-file /run/secrets/rs3-wrap.hex \
  --backend filesystem \
  --backend-dir /var/lib/rs3/backend
```

This opens the envelope and prints public key descriptors only. It does not
print repository data keys or wrapping-key material.

Rewrap the keyring envelope with a new wrapping key without rewriting backup
data:

```sh
cargo run -p xtask --bin xtask -- keyring rewrap \
  --repository-id prod-backups \
  --repository-salt-hex <salt-hex> \
  --envelope-object-id <current-envelope-object-id> \
  --old-wrapping-key-id wrap-2026-05 \
  --old-wrapping-key-hex-file /run/secrets/rs3-wrap-v1.hex \
  --new-wrapping-key-id wrap-2026-06 \
  --generate-new-wrapping-key \
  --envelope-retention-mode compliance \
  --envelope-retention-days 30 \
  --backend filesystem \
  --backend-dir /var/lib/rs3/backend
```

Rewrap is an operational hygiene step, not compromise recovery. It keeps the
same repository data keys and only changes the key-encryption key around the
envelope. If the old wrapping key and old envelope may both have been exposed,
historical backup confidentiality must be treated as lost for data encrypted by
that keyring. A malicious storage backend may also have copied the old envelope
before it was deleted, so deleting or expiring the old envelope is not a
cryptographic revocation mechanism.

Keep the old wrapping-key source available for restore paths that still trust
format roots or commits bound to the old envelope. A newly written rewrapped
envelope only becomes active repository state after a later accepted format or
keyring update binds it.
When writing envelopes outside the gateway, set envelope retention deliberately
with `--envelope-retention-mode` and `--envelope-retention-days`; retention
protects restore metadata from deletion but does not make a leaked old envelope
safe.

Purpose-specific v2 data-key rotation is not exposed as a production-preview
CLI command yet. Do not use older rotation workflows against a
v2 repository. Until v2 rotation is implemented, keep historical keys enabled
and treat wrapping-key rewrap as envelope hygiene only.

Before disabling or retiring a historical key, first verify the trusted anchored
commit chain with `xtask v2 verify-bundle`. That verifies the preserved bundle,
format root, keyring envelope, and reachable commit chain are still usable, but
it is not a data-key retirement decision. v2-aware retirement tooling is not
part of the current production-preview CLI, so keep historical data keys for at
least the maximum provider-retention window.

## Anchors

The memory anchor is only for tests and local development:

```sh
RS3_ANCHOR_MODE=memory
RS3_ALLOW_MEMORY_ANCHOR=true
```

Production-like deployments should use an external anchor mode. The Kubernetes
Lease mode is the intended cluster-native path and requires the gateway to be
built with Kubernetes support:

```sh
RS3_ANCHOR_MODE=kubernetes-lease
RS3_ANCHOR_NAMESPACE=backup
RS3_ANCHOR_NAME=rs3-v2-anchor
RS3_ANCHOR_FIELD_MANAGER=rs3-server
```

If the configured anchor cannot be read or advanced, writes must fail closed.
Do not silently fall back to a memory anchor.

For the production preview, the Kubernetes Lease is the authority for latest
accepted state. Retained commit versions are useful history, not the authority.
If S3 serves an older valid commit, hides the commit named by the Lease, or
contains commits newer than the Lease, the gateway should stop or require a
trusted recovery bundle rather than silently choosing storage state.

An external anchor can distribute trust outside the cluster by storing or
signing the accepted commit position: sequence, commit key, commit object
version ID when available, commit digest, signing key ID, and format-root
reference. It does not need to store the whole repository index.

In Helm deployments, keep `rbac.create=true` unless equivalent Lease
permissions already exist. Set `rbac.existing=true` only for that external-RBAC
case. When the Lease lives outside the release namespace, set `anchor.namespace`
so the generated Role and RoleBinding are created in the Lease namespace.

## Retention

Repository retention is configured with:

```sh
RS3_REPOSITORY_RETENTION_MODE=compliance
RS3_REPOSITORY_RETENTION_DAYS=30
```

Supported modes are `governance` and `compliance`. Compliance mode is the
stronger ransomware-resistance posture where the provider implements it
correctly.

Provider retention is capability-gated. A backend that cannot extend retention
must return an unsupported operation rather than pretending the object is
protected.

## Disaster Recovery Material

Treat the restore bundle as public but integrity-sensitive recovery metadata.
It should live outside the object-store account and outside the cluster whose
Lease it may need to recreate. Backend credentials alone are not enough for
disaster recovery; the bundle, repository ID, public salt, wrapping-key source,
and selected retention context must agree before a new cluster imports an
anchor. The operational procedure is [Restore Under Attack](runbooks/restore-under-attack.md).

## Metrics

Enable the Prometheus/OpenMetrics endpoint:

```sh
RS3_METRICS_BIND=127.0.0.1:19090
```

Metrics should use operation classes, status, result, object class, sizes,
counts, and durations. They must not use logical paths, Kubernetes names,
tenant names, backend object IDs, or secrets as labels.

## Logs And Traces

Use JSON logs when collecting structured runtime evidence:

```sh
RS3_LOG_FORMAT=json
```

Tracing filters use the standard `RUST_LOG` environment variable. Keep
trace-level collection scoped and time-bounded because traces can be high
volume even when labels are redacted.

Startup logs include a path-safe `config_profile` fingerprint over operational
knobs. They do not log configured bucket names, backend prefixes, repository
IDs, or secret material.

The admin posture and status APIs use the same `config_profile` fingerprint and
keep the same redaction boundary as logs and metrics. Treat them as operator
control surfaces, not backup data browsers.

## Restore Posture

For routine restores in a healthy repository, keep the single writer gateway in
`read-write` and use the normal v2 anchor path. Velero writes restore
result artifacts after data restore; in normal operation those writes should be
accepted, committed, and anchored like other repository mutations so Velero
can report `Completed`.

During an incident or disaster-recovery drill, favor read-only restore with a
verified commit chain and external anchor over any mode that repairs state
automatically. If break-glass restore is added, it should require explicit
operator input and leave an audit trail.

!!! note "DR survival kit"
    Keep this material outside the object-store account and outside the namespace
    being protected:

    - repository ID
    - public repository salt
    - wrapping-key source for the keyring envelope
    - trusted v2 anchor position: sequence, commit key, commit object version ID
      when available, commit body digest, signing key ID, and format-root
      reference
    - format-bound keyring-envelope reference
    - backend endpoint, bucket, and prefix
    - restore verification command inputs

    Backend credentials alone are not enough for disaster recovery.

Serve restore traffic with the gateway's read-only posture:

```sh
cargo run -p rs3-server -- serve --gateway-mode restore-readonly
```

This mode refuses first-run repository initialization, requires an accepted
anchor, and rejects supported repository mutations such as PUT, DELETE, and
object legal-hold changes. Pair it with Velero `BackupStorageLocation`
read-only mode, Kopia read-only repository settings where practical, and
backend credentials that cannot write.

!!! note "Velero restore status in strict read-only mode"
    Velero may mark a restore `PartiallyFailed` after the pod-volume data restore
    succeeds because it tries to upload restore result artifacts back to the
    backup storage location. In `restore-readonly`, those `PUT` requests are
    intentionally denied.

    Treat this as acceptable only when Velero logs show denied restore-result
    artifact uploads, pod-volume restore completed, restored data verifies, and
    backend operation counters show no writes during restore. Any other restore
    error remains a failure.

Run only one `read-write` gateway for a repository. Multiple independent
writers cannot safely coordinate repository state without a stronger shared
write protocol. Scaled restore readers should use `restore-readonly`.

Disaster recovery into a new cluster requires the repository ID, public salt,
wrapping-key source, and a trusted v2 anchor position from outside S3. Backend
objects alone are not a latest-state oracle because the backend can hide newer
valid commits and replay older valid commits.

Export the trusted restore bundle from a healthy cluster or regular operations
job and store it outside the object-store account:

```sh
cargo run -p rs3-server -- export-restore-bundle --format json > rs3-restore-bundle.json
```

Machine-readable commands reserve stdout for the report or bundle payload and
write logs to stderr. Do not redirect stderr into preserved JSON artifacts.

Verify the preserved bundle without writing a new anchor:

```sh
cargo run -p xtask --features s3 -- v2 verify-bundle \
  --bundle-file rs3-restore-bundle.json \
  --repository-salt-hex <repository-salt-hex> \
  --wrapping-key-hex-file <wrapping-key-hex-file> \
  --backend s3 \
  --s3-bucket <bucket> \
  --s3-prefix <repository-prefix>
```

The bundle contains public repository restore metadata: repository ID, accepted
commit sequence, commit key, commit object version ID when available, commit
body digest, signing key ID, format-root reference, and weak-subjectivity floor.
It does not contain wrapping-key material. The verifier opens the encrypted
format root and keyring envelope, then verifies the anchor-selected signed
commit chain to the nearest snapshot without mutating storage or the external
anchor.

On a new cluster with a missing anchor, import the trusted v2 anchor from that
bundle after configuring the same repository ID, salt, wrapping-key source,
backend, and retention settings:

```sh
cargo run -p rs3-server -- import-v2-anchor --bundle-file rs3-restore-bundle.json
```

The import path also accepts explicit fields when a workflow cannot pass the
bundle file directly:

```sh
cargo run -p rs3-server -- import-v2-anchor \
  --anchor-sequence <bundle-anchor-sequence> \
  --anchor-commit-key <bundle-anchor-commit-key> \
  --anchor-version-id <bundle-anchor-version-id> \
  --anchor-body-digest <bundle-anchor-body-digest> \
  --signing-key-id <bundle-signing-key-id> \
  --format-generation <bundle-format-generation> \
  --format-digest <bundle-format-digest> \
  --format-object-id <bundle-format-object-id> \
  --format-version-id <bundle-format-version-id> \
  --weak-subjectivity-floor-sequence <bundle-floor-sequence>
```

Do not mix `--bundle-file` and explicit anchor fields. Omit version IDs only
when the trusted bundle has none. Retained/Object Lock repositories should have
commit and format version IDs. The import verifies the named signed commit
chain, format root, and keyring envelope before writing the missing anchor.

Verify a trusted anchor position before relying on it for restore. For v2, the
offline verifier and anchor import path both verify the named signed commit
chain, format root, and keyring envelope. Then run the restore client through
the recovered gateway and verify restored application bytes. Use S3 CLI checks
separately for provider capabilities such as Object Lock headers and raw range
reads.

See [Restore Under Attack](runbooks/restore-under-attack.md) for the incident
runbook.
