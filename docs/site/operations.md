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
backends, missing gateway credentials, and missing repository retention for
mutation-capable serving.

For serving:

```sh
cargo run -p rs3-server -- serve --bind 127.0.0.1:9080
```

The core server library also exposes a path-redacted admin report model for
operator tooling. It reports runtime posture, profile findings, backend and
anchor kind, retention settings, and restore-trust status without exposing a
path browser, configured bucket names, backend prefixes, repository IDs,
client-visible object paths, or secret material. Treat this report as a preview
fact model, not as a stable workflow API.

See [Configuration](reference/configuration.md) for the environment variable
reference.

## Keys And Bootstrap

The gateway uses an encrypted keyring envelope. Operators provide a stable
repository ID, a stable public salt, and a wrapping-key source. For an anchored
repository, startup reads the accepted checkpoint and opens the keyring envelope
bound into that signed checkpoint. It does not trust S3 listing order or a
mutable "latest" object to choose repository state.

For a first empty repository, startup initializes a new random purpose-specific
keyring and writes the encrypted envelope under a default counted `keyrings/`
object name. `RS3_KEYRING_ENVELOPE_OBJECT_ID` is optional and exists only as an
explicit bootstrap or recovery override.

If the envelope is missing but the prefix already contains repository objects, or
if the anchor already contains an accepted checkpoint position, startup fails
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
- Do not destroy a key while any retained checkpoint can reference data that
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

Inspect an existing envelope when auditing key lifecycle state:

```sh
cargo run -p xtask --bin xtask -- keyring inspect \
  --repository-id prod-backups \
  --repository-salt-hex <salt-hex> \
  --envelope-object-id <checkpoint-bound-envelope-object-id> \
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
checkpoints bound to the old envelope. A newly written rewrapped envelope only
becomes active repository state after a later accepted checkpoint binds it.
When writing envelopes outside the gateway, set envelope retention deliberately
with `--envelope-retention-mode` and `--envelope-retention-days`; retention
protects restore evidence from deletion but does not make a leaked old envelope
safe.

Rotate a purpose-specific repository data key through the configured backend
and checkpoint anchor:

```sh
cargo run -p rs3-server -- rotate-key \
  --purpose content \
  --format text
```

Supported purposes are `namespace`, `content`, `metadata`, and `checkpoint`.
The command opens the checkpoint-bound envelope, generates a fresh primary key
for that purpose, demotes the previous primary to enabled historical use, writes
a new encrypted envelope, and publishes a metadata-only checkpoint that binds
the new envelope. This is a first-party operator primitive over the configured
backend and anchor, not an S3 data-plane operation.

Before disabling or retiring a historical key, check a trusted checkpoint chain:

```sh
cargo run -p xtask --bin xtask -- keyring retirement-check \
  --repository-id prod-backups \
  --repository-salt-hex <salt-hex> \
  --envelope-object-id <checkpoint-bound-envelope-object-id> \
  --wrapping-key-id wrap-2026-05 \
  --wrapping-key-hex-file /run/secrets/rs3-wrap.hex \
  --checkpoint-sequence <sequence> \
  --checkpoint-id <checkpoint-id> \
  --checkpoint-digest <checkpoint-digest> \
  --key-id content-v1 \
  --backend filesystem \
  --backend-dir /var/lib/rs3/backend
```

Retirement is safe only when the key is not primary and the verified checkpoint
chain no longer requires it. Keep historical keys for at least the maximum
provider-retention window.

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
RS3_ANCHOR_NAME=rs3-checkpoint
RS3_ANCHOR_FIELD_MANAGER=rs3-server
```

If the configured anchor cannot be read or advanced, writes must fail closed.
Do not silently fall back to a memory anchor.

For the production preview, the Kubernetes Lease is the authority for latest
accepted state. Storage-side checkpoint evidence is the witness. If S3 serves an
older valid checkpoint, hides the checkpoint or evidence named by the Lease, or
presents evidence newer than the Lease, the gateway should stop or require an
explicit recovery workflow rather than silently choosing storage state.

A trusted external anchor can distribute trust outside the cluster by
storing or signing the accepted checkpoint position: sequence, checkpoint ID,
and checkpoint digest. It does not need to store the whole repository index.

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

The admin status API uses the same `config_profile` fingerprint and keeps the
same redaction boundary as logs and metrics. Treat it as an operator control
surface, not a backup data browser.

## Restore Posture

During an incident, favor read-only restore with a verified checkpoint and
external anchor over any mode that repairs state automatically. If break-glass
restore is added, it should require explicit operator input and leave an audit
trail.

!!! note "DR survival kit"
    Keep this material outside the object-store account and outside the namespace
    being protected:

    - repository ID
    - public repository salt
    - wrapping-key source for the keyring envelope
    - trusted checkpoint position: sequence, checkpoint ID, and checkpoint digest
    - checkpoint-bound keyring-envelope reference
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
wrapping-key source, and either a trusted checkpoint position from outside S3 or
an explicit bounded recovery decision. Backend evidence alone is not a perfect
latest-state oracle because the backend can hide newer valid evidence and replay
older valid evidence.

Export the trusted restore bundle from a healthy cluster or regular operations
job and store it outside the object-store account:

```sh
cargo run -p rs3-server -- export-restore-bundle --format json
```

The bundle contains public repository restore metadata: repository ID, public
salt, accepted checkpoint sequence, checkpoint ID, checkpoint digest, and the
checkpoint-bound keyring-envelope reference. It does not contain wrapping-key
material.

On a new cluster with a missing anchor, import the trusted checkpoint position
from that bundle after configuring the same repository ID, salt, and
wrapping-key source:

```sh
cargo run -p rs3-server -- import-anchor \
  --checkpoint-sequence <bundle-sequence> \
  --checkpoint-id <bundle-checkpoint-id> \
  --checkpoint-digest <bundle-checkpoint-digest>
```

The import verifies the checkpoint chain, checkpoint evidence, keyring envelope,
and reachable restore-critical objects before writing the missing anchor.

When the old Kubernetes Lease is gone, use explicit anchor recovery with a
freshness bound:

```sh
cargo run -p rs3-server -- recover-anchor \
  --max-checkpoint-age-seconds 86400 \
  --apply-if-missing \
  --format text
```

The command scans storage evidence, verifies the highest observed valid
checkpoint chain and keyring envelope, rejects it if the signed checkpoint time
is older than the configured bound, and writes the configured anchor only when
it is missing. The report says "highest observed valid" deliberately: a
malicious backend that cannot forge checkpoints may still hide newer valid
ones.

Verify a trusted checkpoint position before relying on it for restore. Build
`xtask` with the S3 feature when verifying an S3-compatible backend:

```sh
cargo run -p xtask --bin xtask --features s3 -- restore verify \
  --repository-id prod-backups \
  --repository-salt-hex <salt-hex> \
  --keyring-envelope-object-id <envelope-object-id> \
  --wrapping-key-id <wrapping-key-id> \
  --wrapping-key-hex-file /run/secrets/rs3-wrap.hex \
  --checkpoint-sequence <anchor-sequence> \
  --checkpoint-id <anchor-checkpoint-id> \
  --checkpoint-digest <anchor-checkpoint-digest> \
  --backend s3 \
  --s3-bucket <bucket> \
  --require-provider-delete-protection \
  --format json
```

This is not just an S3 object listing. It verifies checkpoint signatures,
checkpoint evidence, keyring envelope digest, encrypted index state, sealed
metadata, and payload decryptability. The report also summarizes provider
retention and legal-hold metadata observed on the restore-critical objects it
checked. With `--require-provider-delete-protection`, the command fails unless
every checked restore-critical object is protected by provider retention or
legal hold. Use S3 CLI checks separately for provider capabilities such as
Object Lock headers and raw range reads.

See [Restore Under Attack](runbooks/restore-under-attack.md) for the incident
runbook.
