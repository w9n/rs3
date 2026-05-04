# Evaluation

This page is for platform and security teams deciding whether `rs3` is worth a
deeper technical trial.

## What rs3 Is

`rs3` is an S3-compatible gateway that sits between backup clients and object
storage. It owns repository privacy, checkpoint publication, retention-aware
storage behavior, and observability at the gateway boundary.

The first compatibility target is Kopia because it is used by Kubernetes backup
systems and exercises the important S3 behaviors: `PUT`, `HEAD`, ranged `GET`,
`LIST`, delete/tombstone behavior, and immediate read/list-after-write
semantics.

## What rs3 Is Not

`rs3` is not a generic S3 server, an object-store replacement, or a mature
production backup product today. The current code is a serious experimental
base with measured behavior, but the durable format and production
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
- Purpose-specific keys derived from a repository master key.
- Signed checkpoint shape and external-anchor model.
- Retention and legal-hold contracts at the storage boundary.
- Kopia measured matrix with a direct RustFS proxy baseline.
- Prometheus metrics and structured traces that avoid path labels.

## Current Product Risks

- The repository format is draft.
- Metadata sealing uses a standard misuse-resistant AEAD, but durable envelopes
  and checkpoint signatures still need final production-format decisions.
- Some leakage is inherent: object counts, sizes, coarse timing, and operation
  cadence remain visible to the backend.
- Hardened Kubernetes anchor wiring and storage-side evidence need continued
  integration work.
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
