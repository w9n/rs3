# Evaluation

This page is for platform and security teams deciding whether `rs3` is worth a
deeper technical trial.

## What rs3 Is

`rs3` is an S3-compatible gateway that sits between backup clients and object
storage. It owns repository privacy, checkpoint publication, retention-aware
storage behavior, and observability at the gateway boundary.

The preview compatibility targets are Kopia and Velero with the Kopia uploader.
Kopia defines the lower-level S3 behavior that matters first: `PUT`, `HEAD`,
ranged `GET`, `LIST`, delete/tombstone behavior, and immediate
read/list-after-write semantics. Velero proves the Kubernetes restore workflow
through that storage path.

## What rs3 Is Not

`rs3` is not a generic S3 server, an object-store replacement, or a mature
production backup product today. The current release target is a production
preview for controlled evaluation. The durable format and production
cryptographic choices are still moving.

## Trust Posture

The project is built around an uncomfortable assumption: object storage can be
honest-but-curious, misconfigured, malicious, or controlled by an attacker
during a restore. The design therefore avoids plaintext repository names in
backend-visible places and treats the object store as insufficient for proving
the newest valid checkpoint.

The result is a system that should be evaluated on three axes:

| Axis | Evaluation Question |
| --- | --- |
| Privacy | What can the backend infer from names, sizes, timing, counts, and metadata? |
| Integrity | Can a backend delete, replay, delay, or forge repository state without detection? |
| Operations | Can an operator restore under pressure without bypassing the protection model? |

## Current Strengths

- Path-private repository object IDs and namespace lookup tokens.
- Encrypted payload segments with authenticated object context.
- Random purpose-specific keys sealed in an encrypted keyring envelope, with
  repository ID and public salt bound into the unwrap context.
- Signed checkpoint shape and external-anchor model.
- Kubernetes Lease anchor for the preview deployment model.
- Restore verification for checkpoint chain, reachable objects, decryptability,
  keyring envelope binding, and retention evidence.
- Retention and legal-hold contracts at the storage boundary.
- Kopia measured matrix with a direct RustFS proxy baseline.
- Prometheus metrics and structured traces that avoid path labels.

## Current Product Risks

- The repository format is draft.
- Metadata sealing uses a standard misuse-resistant AEAD, but durable envelope
  compatibility is not stable yet.
- Some leakage is inherent: object counts, sizes, coarse timing, and operation
  cadence remain visible to the backend.
- Storage-side evidence now exists for checkpoint publication, but production
  deletion resistance still depends on provider retention or Object Lock.
- Compatibility beyond the Kopia-focused S3 surface is intentionally limited.

## Evaluation Standard

A useful trial should prove all of the following:

- Kopia can create, snapshot, and restore through the gateway.
- Restored bytes match the source workload.
- Backend objects do not contain plaintext paths or Kubernetes names.
- Rollback-anchor failures fail closed in the selected deployment mode.
- Performance is compared to the straight proxy baseline, not only to an
  absolute wall-clock number.
- Metrics and traces explain restore cost without adding privacy leaks.

See [Production Preview](production-preview.md) for the current release gates.

## Quick Local Evidence Path

Use this path when deciding whether the project deserves a deeper provider trial.
It exercises the current preview contract without changing external
infrastructure.

```sh
nix develop
just preview-gate-local
just preview-gate-release
```

Expected result:

- the local gate passes formatting, tests, S3-feature checks, and dependency
  policy checks
- the release gate passes Kopia gateway restore, Velero dynamic-PVC
  gateway-restart restore through `restore-readonly`, and Velero/Postgres smoke
  restore
- artifacts are written under `.local/integration/`

Run the larger performance matrix when storage or repository behavior changed, or
when refreshing release evidence:

```sh
cargo run -p xtask --bin xtask --features containers -- integration kopia-measured-matrix \
  --runs 3 \
  --profile-set larger-restores \
  --gateway-build-profile release \
  --payload-segment-size 512 \
  --enforce-regression-budgets
```

Expected result:

- `regression_budgets status=pass`
- `workload_consistency status=pass`
- backend read and write bytes remain close to the straight RustFS proxy baseline

After local evidence is green, run a separate live-provider trial with an empty
bucket, preserved restore bundle, and provider retention settings that match the
intended deployment.
