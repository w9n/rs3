# Release Process

This checklist defines the minimum evidence for a production-preview release.
It does not turn `v2-preview` into a stable repository-format promise.

## Owner-Controlled Prerequisites

Do not publish a release until project owners have configured all of these:

- an actionable private vulnerability-reporting route in a top-level
  `SECURITY.md`
- a container registry and immutable repository name
- a release-signing identity and verification policy
- an artifact retention policy for source, binaries, images, Helm charts,
  software bills of materials (SBOMs), provenance, checksums, and test evidence

These values are authority boundaries, not build defaults. Do not substitute a
personal address, temporary registry, generated signing key, or CI principal
without an explicit owner decision.

## Source Candidate

1. Select one reviewed source revision with a clean tracked worktree.
2. Update the workspace version, Helm chart `version` and `appVersion`, image
   build version, and changelog together.
3. Confirm the repository-format and security documentation describes the
   exact candidate. Any undocumented format drift blocks release.
4. Confirm every GitHub Actions dependency and Docker build input is immutable
   or recorded by digest.

## Required Gates

Run the deterministic local gate:

```sh
just preview-gate-local
```

Run the release integration and scheduled hardening gates:

```sh
just preview-gate-release
just preview-gate-v2-nightly
```

On the documented pinned runner, retain a dedicated local-disk evidence root
and run the complete three-sample fresh-process scale gate:

```sh
just preview-gate-scale-candidate /path/to/retained-evidence
```

The scale, path-length, filesystem, and standalone recipes embed the selected
source revision in their reports and append `-dirty` when tracked changes are
present. Dirty evidence is diagnostic only. The filesystem reports live under
the supplied root; capture the JSONL stdout from the path-length and standalone
recipes with the release record.

Run every three-sample measured Kopia profile separately so each command stays
bounded and real-client performance is not inferred from adversarial raw-S3
objects:

```sh
for profile in medium-restore kubernetes-objects kubernetes-objects-large \
  postgres-pgdata postgres-pgdata-large; do
  just perf-kopia-profile-candidate "$profile"
done
```

Each summary binds the selected source revision and carries three alternating
direct/gateway run pairs for its profile.

Also preserve current provider-conformance, Kubernetes backup/restore,
disaster-recovery, and release-profile performance evidence. Schema-v4
provider evidence must match the candidate source revision and reviewed
principal fingerprint. Velero summaries and their nested gateway images must
carry the same revision. A disposable local S3 implementation is useful
regression evidence, but it is not proof of a production provider's retention
or version-addressed-read behavior.

Source binding is necessary but not sufficient for portable timing. Record the
runner identity and CPU allocation, memory, kernel and Nix/toolchain closure,
filesystem device and mount options, cache-control procedure, and exact
provider image digests.

## Build And Publish

Build from the selected revision and pass its version and revision into the
container build:

```sh
docker build \
  --build-arg VERSION=<release-version> \
  --build-arg REVISION=<full-source-revision> \
  --target runtime \
  --tag <owner-selected-registry>/rs3-server:<release-version> \
  .
```

The Dockerfile pins its frontend and base images and includes the AGPL-3.0 license
in the runtime image. The publishing pipeline must additionally:

- generate an SBOM for the exact image and packaged binaries
- record build provenance that binds artifacts to the selected source revision
- scan the exact digest and resolve release-blocking findings
- sign the exact image and chart digests with the owner-approved identity
- publish checksums and verification instructions for non-container artifacts

Publish and deploy by digest. Production Helm values intentionally reject a
mutable image tag and chart-created secret values:

```yaml
image:
  repository: <owner-selected-registry>/rs3-server
  digest: sha256:<published-image-digest>
```

## Release Record

The release record should contain:

- source revision and release version
- image and chart digests
- signatures, provenance, SBOMs, checksums, and scanner results
- exact local, integration, live-provider, restore, DR, and performance gates
- known limitations, including the preview format contract and single
  Kubernetes coordination-domain writer model
- upgrade, rollback, key-recovery, and restore-bundle instructions

If any item is unavailable, describe it as a release blocker. Silence is not a
security control, despite the industry's occasional best efforts.
