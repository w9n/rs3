# Operations

This page describes the current operator-facing shape. Treat it as development
documentation until the repository format and hardened anchor path are stable.

## Runtime Configuration

The gateway reads environment configuration and can validate it without
starting the listener:

```sh
cargo run -p rs3-server -- doctor
```

For serving:

```sh
cargo run -p rs3-server -- serve --bind 127.0.0.1:9080
```

See [Configuration](reference/configuration.md) for the environment variable
reference.

## Keys

`RS3_REPOSITORY_MASTER_KEY_HEX` must contain at least 32 bytes of hex-encoded
entropy. `RS3_REPOSITORY_SALT_HEX` must contain a stable 32-byte public salt.
The gateway uses HKDF-SHA-256 to derive purpose-specific repository keys from
the master key, `RS3_REPOSITORY_ID`, and the repository salt.

Operational rules:

- Generate the master key outside the object store.
- Generate the salt once per repository and keep it with trusted repository
  configuration.
- Treat the salt as public restore metadata, not as a second password.
- Do not reuse the same master key, repository id, and salt across repositories.
- Keep historical keys available for at least the maximum retention window.
- Do not destroy a key while any retained checkpoint can reference data that
  requires it.

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

See [Restore Under Attack](runbooks/restore-under-attack.md) for the incident
runbook.
