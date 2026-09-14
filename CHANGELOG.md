# Changelog

All notable changes to `rs3` are documented here.

This project follows the shape of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The project is still preview-scoped and has not cut a stable release.

## [Unreleased]

- Fenced Kubernetes writers on the anchor Lease itself using unique process identities, monotonic renewal observation, and per-handoff tokens that every anchor CAS verifies; stale and unfenced writers now fail closed.

### Added

- Added the v3-preview repository path as the only active repository runtime, with signed commit chains, encrypted keyring envelopes, recovery bundles, and Kubernetes Lease anchoring.
- Added recovery tooling under the `rs3` binary for bundle verification, keyring inspection, keyring rewrap, one-shot repository initialization, and doctor probes.
- Added an operator console, admin posture/status reports, Prometheus metrics, and S3 compatibility documentation for supported operations.
- Added fuzz targets and deterministic fault-injection tests for backend-facing parsers and storage-fault invariants.
- Added Helm chart support for Kubernetes deployment, metrics ServiceMonitor rendering, NetworkPolicy, RBAC, resource limits, security contexts, repository-key Secrets, and v03 Lease anchoring.

### Changed

- Cut the preview wire to v03 with canonical CBOR keyring/format envelopes and recovery bundles, attempt-bound ciphertext-only payloads, front-coded listing frames, and explicit generation-3 anchors. Recreate evaluation repositories; there is no migration or dual reader.
- Use random metadata nonces and require complete bounded exact-version ciphertext verification before detached payload publication. Frozen codec vectors and nine fuzz targets cover the current encodings.

- Hardened commit publishing, rollback recovery, destructive GC prerequisites, retained-object handling, streaming PUT timeouts, and multipart abort observability.
- Hardened S3 gateway behavior for restore-readonly mode, batch deletes, Object Lock operations, request/body limits, static credential handling, and path-redacted diagnostics.
- Simplified operator configuration by keeping `v3-preview` as the only accepted repository format and folding non-operator tuning knobs into internal defaults.
- Improved read-path efficiency with resolved repository objects, constant-time LRU caches, and lower-overhead metrics on hot paths.
- Replaced per-write repository snapshots and full accepted-state copies with bounded rollback records and incremental delta acceptance, removing the measured near-quadratic committed-write scaling path.
- Updated the S3 server, object-store client, AWS SDK, metrics, and supporting dependencies to current maintained releases compatible with the workspace MSRV.
- Expanded the default workspace gate to lint and test every feature combination used by release builds.

### Removed

- Removed v02 acceptance, streamed commit payload sections and their headers, and retired JSON keyring/recovery artifacts.

- Removed the unshipped v1 repository stack, v1 checkpoint publishing, v1 maintenance/orphan GC, the v1 commit coordinator, and the standalone v1 anchor crate.
- Removed legacy xtask/runtime paths that depended on the v1 repository implementation.

### Security

- Enforced fail-closed behavior for rollback anchors, weak-subjectivity floors, production recovery bundle signatures, writer-lease guard configuration, and provider conformance gates.
- Preserved path privacy by keeping plaintext paths, Kubernetes names, and snapshot names out of backend object keys, unauthenticated metadata, logs, metrics labels, and errors.
- Restricted runtime tracing to application-owned targets so dependency debug events cannot disclose S3 paths or authentication headers.
- Bounded console-to-gateway admin response collection and applied the request timeout to the complete response body.
- Made startup, disaster-recovery, and maintenance replay range-verify commit bodies under fixed commit-count, cumulative-I/O, retained-index, and per-read memory budgets.
- Documented plaintext listener boundaries, keyring envelope handling, retained-version Object Lock assumptions, and restore-under-attack workflows.
