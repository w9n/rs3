# Changelog

All notable changes to `rs3` are documented here.

This project follows the shape of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The project is still preview-scoped and has not cut a stable release.

## [Unreleased]

### Added

- Added the v2-preview repository path as the only active repository runtime, with signed commit chains, encrypted keyring envelopes, recovery bundles, and Kubernetes Lease anchoring.
- Added recovery tooling under the `rs3` binary for bundle verification, keyring inspection, keyring rewrap, one-shot repository initialization, and doctor probes.
- Added an operator console, admin posture/status reports, Prometheus metrics, and S3 compatibility documentation for supported operations.
- Added fuzz targets and deterministic fault-injection tests for backend-facing parsers and storage-fault invariants.
- Added Helm chart support for Kubernetes deployment, metrics ServiceMonitor rendering, NetworkPolicy, RBAC, resource limits, security contexts, repository-key Secrets, and v2 Lease anchoring.

### Changed

- Hardened v2 commit publishing, rollback recovery, destructive GC prerequisites, retained-object handling, streaming PUT timeouts, and multipart abort observability.
- Hardened S3 gateway behavior for restore-readonly mode, batch deletes, Object Lock operations, request/body limits, static credential handling, and path-redacted diagnostics.
- Simplified operator configuration by keeping `v2-preview` as the only accepted repository format and folding non-operator tuning knobs into internal defaults.
- Improved read-path efficiency with resolved v2 objects, constant-time LRU caches, and lower-overhead metrics on hot paths.

### Removed

- Removed the unshipped v1 repository stack, v1 checkpoint publishing, v1 maintenance/orphan GC, the v1 commit coordinator, and the standalone v1 anchor crate.
- Removed legacy xtask/runtime paths that depended on the v1 repository implementation.

### Security

- Enforced fail-closed behavior for rollback anchors, weak-subjectivity floors, production recovery bundle signatures, writer-lease guard configuration, and provider conformance gates.
- Preserved path privacy by keeping plaintext paths, Kubernetes names, and snapshot names out of backend object keys, unauthenticated metadata, logs, metrics labels, and errors.
- Documented plaintext listener boundaries, keyring envelope handling, retained-version Object Lock assumptions, and restore-under-attack workflows.
