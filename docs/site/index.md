<section class="rv-hero">
  <p class="rv-eyebrow">Kubernetes backup gateway | S3-compatible | production-preview evaluation</p>
  <h1>Path-private S3 backup gateway.</h1>
  <p class="rv-lead">
    <code>rs3</code> is a path-private, tamper-evident S3 gateway for operators
    evaluating Velero/Kopia backup storage on S3-compatible infrastructure that
    may be untrusted or partially compromised.
  </p>
  <div class="rv-actions">
    <a class="md-button md-button--primary" href="evaluation/">Evaluate rs3</a>
    <a class="md-button" href="security-model/">Review the security model</a>
  </div>
  <div class="rv-posture-strip" aria-label="Project posture">
    <span>Path privacy target</span>
    <span>Kopia + Velero focus</span>
    <span>Lease anchor model</span>
    <span>Measured locally</span>
  </div>
</section>

## What It Is

The gateway is designed for teams that need existing S3-oriented backup tools
to work without exposing repository paths, Kubernetes resource names, or
accepted repository state directly to an object-store backend.

<div class="rv-posture-grid">
  <article>
    <p class="rv-card-kicker">Privacy</p>
    <h3>Path and Kubernetes names stay opaque.</h3>
    <p>
      Client paths, Kubernetes object names, namespaces, and snapshot labels are
      treated as secrets at storage and telemetry boundaries.
    </p>
  </article>
  <article>
    <p class="rv-card-kicker">Integrity</p>
    <h3>State is accepted through signed commits.</h3>
    <p>
      Repository changes are committed and anchored instead of trusting a
      latest-object convention in the backend.
    </p>
  </article>
  <article>
    <p class="rv-card-kicker">Operations</p>
    <h3>Restore behavior is measured.</h3>
    <p>
      Kopia runs compare the gateway to a straight proxy baseline and record
      request, byte, CPU, memory, and variability evidence.
    </p>
  </article>
</div>

## Current Status

`rs3` is being prepared for a production preview. The repository contains a
working local gateway path, Kopia and Velero integration harnesses, repository
encryption boundaries, Kubernetes Lease anchoring, signed v2 commit publishing,
restore-bundle workflows, retention-aware storage contracts, metrics, tracing,
and performance measurement against a straight proxy baseline.

The implemented commit generation under `commits/v01/` is now deprecated and
has no production repositories. The replacement `commits/v02` catalog-and-run
format is a design contract and is not implemented. Existing gateway and
provider results remain regression evidence, but a repository release is
blocked until the new format passes recovery, checkpoint, GC, retained-provider,
and 1M-object scale gates. No migration or dual reader is planned.

Do not treat the current repository format, cryptographic formats, or runtime
defaults as production-stable yet.

!!! warning "Production preview, not stable format"
    The project is being built toward a production-preview evaluation target.
    Current docs intentionally separate measured facts from future design
    intent.

## Design Priorities

- Hide client-visible paths and Kubernetes names from backend object keys,
  unauthenticated metadata, metrics labels, traces, and logs.
- Detect rollback through signed commits and an external anchor instead of
  trusting a latest-object convention in the object store.
- Preserve restore correctness for S3 backup clients, starting with Kopia and
  Velero/Kopia.
- Measure request count, read bytes, write bytes, elapsed time, CPU, and memory
  against a straight proxy baseline before optimizing.
- Keep operational failure modes explicit: anchors fail closed, retention is
  provider-capability gated, and recovery modes must be auditable.

## Reader Paths

| Reader | Start Here |
| --- | --- |
| Platform lead | [Evaluation](evaluation.md) |
| Release reviewer | [Production Preview](production-preview.md) |
| Security reviewer | [Security Model](security-model.md) and [Security Review](security-review.md) |
| Operator | [Operations](operations.md) and [Restore Under Attack](runbooks/restore-under-attack.md) |
| Contributor | [Architecture](architecture.md) and [Testing](testing.md) |
| Performance reviewer | [Performance](performance.md) |

## Documentation Structure

The public docs site follows a Diataxis-style split:

- Tutorials and first steps in [Getting Started](getting-started.md).
- How-to operational material in [Operations](operations.md).
- Reference material under [Reference](reference/configuration.md).
- Explanation in [Architecture](architecture.md), [Security Model](security-model.md),
  and [Performance](performance.md).

The MkDocs site builds from `docs/site/`.
