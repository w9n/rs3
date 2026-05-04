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

The production profile rejects memory anchors, missing repository retention,
retention-unsupported local backends, and missing gateway credentials.

For serving:

```sh
cargo run -p rs3-server -- serve --bind 127.0.0.1:9080
```

See [Configuration](reference/configuration.md) for the environment variable
reference.

## Keys And Bootstrap

The gateway uses an encrypted keyring envelope. Operators provide a stable
repository ID, a stable public salt, a configured envelope object ID, and an
unwrap authority. The gateway opens the envelope if it exists. If it is missing,
startup initializes a new random purpose-specific keyring only when the
configured backend prefix is empty and the anchor is missing.

If the envelope is missing but the prefix already contains repository objects, or
if the anchor already contains an accepted checkpoint position, startup fails
closed. This prevents accidental second-repository initialization on top of
existing backup data.

Operational rules:

- Prefer generated random data keys inside an encrypted keyring envelope.
- Keep wrapping keys, KMS access, HSM access, or Vault tokens outside the object
  store and outside broad cluster write credentials.
- Provide a stable salt once per repository and keep it with trusted repository
  configuration and recovery material.
- Treat salts as public restore metadata, not as second passwords.
- Keep historical keys available for at least the maximum retention window.
- Do not destroy a key while any retained checkpoint can reference data that
  requires it.

For a first empty repository, configure the envelope target and wrapping key:

```sh
RS3_REPOSITORY_ID=prod-backups
RS3_REPOSITORY_SALT_HEX=<stable-public-salt-hex>
RS3_KEYRING_ENVELOPE_OBJECT_ID=keyrings/bootstrap-envelope.json
RS3_KEYRING_WRAPPING_KEY_ID=wrap-2026-05
RS3_KEYRING_WRAPPING_KEY_HEX=<wrapping-key-hex>
```

In Helm, set `repositoryKeys.create=true` or provide
`repositoryKeys.existingSecret`. The Secret keys are `salt-hex`,
`envelope-object-id`, `wrapping-key-id`, and `wrapping-key-hex`. Helm values stay
declarative; the gateway writes the encrypted envelope object, not mutated chart
state.

Rotate the wrapping key without rewriting backup data:

```sh
cargo run -p xtask --bin xtask -- keyring rewrap \
  --repository-id prod-backups \
  --repository-salt-hex <salt-hex> \
  --envelope-object-id <current-envelope-object-id> \
  --old-wrapping-key-id wrap-2026-05 \
  --old-wrapping-key-hex-file /run/secrets/rs3-wrap-v1.hex \
  --new-wrapping-key-id wrap-2026-06 \
  --generate-new-wrapping-key \
  --backend filesystem \
  --backend-dir /var/lib/rs3/backend
```

Keep the old wrapping key available until no retained checkpoint needs an
envelope that was sealed with it.

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

## Restore Posture

During an incident, favor read-only restore with a verified checkpoint and
external anchor over any mode that repairs state automatically. If break-glass
restore is added, it should require explicit operator input and leave an audit
trail.

Disaster recovery into a new cluster requires the repository ID, public salt,
keyring-envelope object ID, unwrap authority, and trusted checkpoint position.
Backend evidence alone is not enough to recreate trust because the backend can
hide or replay evidence.

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
