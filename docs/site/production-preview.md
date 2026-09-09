# Production Preview

The first release target is a production preview for Kubernetes operators who
store backups on S3-compatible infrastructure they do not fully trust. The main
client is Velero with Kopia uploader; direct Kopia use remains in scope because
it is the compatibility substrate.

The preview defines the behavior to evaluate. It is not a stable
repository-format promise.

!!! danger "Repository release is currently blocked"
    `commits/v01` has been removed and is unsupported; it had no production
    repositories. The runtime now reads and writes the preview-scoped
    `commits/v03` envelope with framed index runs, signed catalogs,
    payload-skipping replay, guarded metadata-only packed-run compaction, and
    automatic active-run watermarks. Existing compatibility and provider
    results are useful gateway regression evidence. New-write protection
    cohorts, exact guarded full GC, the maintenance supervisor, and its fenced
    operator surfaces are implemented. Pinned-runner qualification, current
    retained-provider restart/fault and production-cardinality maintenance
    evidence, owner release infrastructure, and external review still block a
    production repository release. There will be no `v01` migration or
    dual-reader requirement.

## Preview Scope

`rs3` is a path-private, tamper-evident S3 gateway for backup repositories.

It should let an operator put Velero/Kopia backup data on an S3-compatible
store while reducing what that provider can learn or change:

- backend object keys do not reveal backup paths, namespaces, Kubernetes object
  names, snapshot names, or Kopia blob names
- payloads and privacy-sensitive metadata are encrypted and authenticated before
  they reach the backend
- backend-injected objects are ignored unless they are referenced by signed
  repository state
- backend rollback is rejected against the configured external anchor
- retained exact-version objects and trusted recovery bundles help investigate
  whether the backend or anchor service served stale or inconsistent state

`rs3` does not replace Velero, Kopia, database-native backup consistency, or
application-aware restore validation. It protects the object-store boundary and
the repository-state transition model.

## Claim Boundaries

| Evaluated preview behavior | Not a preview claim |
| --- | --- |
| Backend object keys and path-sensitive metadata are opaque to the storage backend. | The backend learns nothing; object counts, sizes, timing, and broad object classes remain visible. |
| Anchored signed commits detect backend rollback against the trusted anchor. | S3 Object Lock or retention alone establishes the latest repository state. |
| `restore-readonly` serves restore reads and rejects supported repository mutations. | Every backup client will report a successful status when its own restore bookkeeping writes are denied. |
| Velero/Kopia and Kopia compatibility are covered by local integration evidence. | Broad generic S3 application compatibility is promised. |
| The preview repository can be evaluated with documented recovery material. | The durable repository format is stable across future releases. |

## Supported Shape

| Area | Preview scope |
| --- | --- |
| Primary client | Velero with Kopia uploader |
| Compatibility client | Kopia |
| Deployment | Kubernetes |
| External anchor | Kubernetes Lease |
| Storage witness | Retained exact-version commit objects; the Kubernetes Lease remains the latest-state authority |
| Backend | S3-compatible retained-version backend; RustFS/local checks for disposable evidence, live checks opt-in |
| Keys | Encrypted keyring envelope |
| Gateway modes | `read-write` for backups and routine restores, `restore-readonly` for incident restore |
| Retention | Provider retention/Object Lock capability checked where configured |

## Trust Model

The preview assumes the S3-compatible backend can read, list, delay, delete,
overwrite, replay, or inject objects unless provider retention prevents it. It
also assumes the Kubernetes API used for the Lease anchor is a separate trust
domain from the storage backend.

That separation is operational, not automatic. If the same compromised control
domain can rewrite the Lease, read the wrapping-key source, alter backend
credentials, and replace preserved restore bundles, the online protection model
is exhausted. Preview deployments should keep those authorities separated
enough for incident recovery and audit.

The Kubernetes Lease is the preview authority for latest accepted repository
state. Retained commit objects are useful history, not the authority. On a
healthy open, the accepted anchor position, signed commit chain, format root,
and keyring envelope reference must agree. If they do not agree, the gateway
must fail closed or enter an explicit recovery workflow.

This means a malicious backend should not be able to make the gateway silently
restore an older valid commit while the in-cluster anchor still records a newer
one. The backend can still deny service by hiding required objects.

## Failure Rules

| Situation | Preview behavior |
| --- | --- |
| Empty backend prefix and no anchor | Startup may initialize one generated keyring envelope only when repository initialization is explicitly enabled using the supplied repository ID and wrapping-key source, with a generated or pinned salt. An envelope object ID is optional override state, not normal Helm state. |
| Existing backend prefix and matching anchor | Open after signed commit-chain, format-root, and envelope validation. |
| Fresh initialization finds unsupported `commits/v01`, `commits/v02` or `objects/v02` objects or ambiguous existing state | Fail closed. `v03` initialization does not import, migrate, overwrite, or adopt the old generation. |
| Backend serves an older commit than the Lease anchor | Fail closed as rollback. |
| Backend hides the commit named by the Lease anchor | Fail closed as unavailable or tampered. |
| Backend adds unrelated objects | Ignore them unless signed and reachable from anchored state. |
| Backend overwrites format, keyring, commit, metadata, or payload bytes | Reject through native create-only write checks, signed/digested state, AEAD authentication, or retained-version exact reads. S3 providers qualify through either `atomic-create` or `retained-version`; `HEAD` before `PUT` is not a production fallback. |
| Backend contains commits newer than the Lease anchor | Do not silently advance. Treat as ambiguous until explicit recovery validates a trusted bundle or a separately approved anchor decision. |
| Lease missing but backend objects exist | Do not silently trust storage. Require a trusted generation-matched recovery bundle and verify the exact catalog, run, and payload graph before recreating the anchor. |
| Multiple gateways serve the same repository as `read-write` | Supported only as failover within one Kubernetes apiserver and anchor-Lease coordination domain. A gateway acquires a unique fenced writer epoch on the anchor Lease itself; every anchor advance verifies that epoch atomically, and the gateway shuts down if renewal is no longer trustworthy. Disconnected writers that only share S3 are unsupported. |
| Gateway started as `restore-readonly` without an accepted anchor | Fail closed. Run explicit anchor recovery first, then serve restore traffic. |
| Healthy Velero restore through the primary path | Run through the single `read-write` gateway so Velero restore-result artifacts are committed and the restore can report `Completed`. |
| Restore client attempts PUT, DELETE, or legal-hold mutation through `restore-readonly` | Reject the request instead of advancing repository state. |
| Velero restore reports `PartiallyFailed` only because restore-result artifact uploads were denied by `restore-readonly` | Accept only after verifying restored data, completed pod-volume restore, and zero backend writes during restore. Treat any other restore error as failure. |
| Lease and backend are both compromised | Online protection is exhausted; recovery needs offline or externally protected authority. |
| Wrapping key and old envelope are both exposed | Rewrap protects only future envelope handling; historical data under that keyring is treated as exposed. |

Kubernetes Lease fencing is not a cross-cluster consensus protocol. S3 object
synchronization, conditional writes, Object Lock, or a newest-looking commit do
not provide a safe writer lock under the malicious and eventually inconsistent
backend threat model. Run disconnected gateways as `restore-readonly` readers;
multiple such readers are supported when each can verify an accepted anchored
state. A future disconnected multi-writer mode would need authenticated
branches, deterministic conflict handling, and a separate repository protocol,
not an S3-sync switch.

Within the active fenced gateway, declared-length large bodies upload in
parallel and serialize only their short signed-reference publications. This is
data-plane concurrency, not disconnected multi-writer support. A stalled upload
does not own the repository publication lock, and a caller cancellation after
the backend may have completed does not make unanchored bytes visible.

## Incomplete Multipart Cleanup

Production-preview retained S3-compatible buckets MUST configure a lifecycle
rule that aborts incomplete multipart uploads. Client disconnects, pod crashes,
or provider-side abort failures can leave temporary multipart parts that are
not committed repository objects, so rs3 repository GC cannot discover or clean
them. Use at least two days after initiation: the gateway permits a 24-hour
client session and needs additional margin for admitted parts and completion.
Read-write S3 startup rejects a shorter overlapping rule, and it also rejects
ordinary age-based expiration that overlaps repository storage.

Example lifecycle shape, adapting the prefix syntax to the selected provider:

```json
{
  "Rules": [
    {
      "ID": "abort-incomplete-rs3-multipart-uploads",
      "Status": "Enabled",
      "Filter": {
        "Prefix": "<backend-prefix>/"
      },
      "AbortIncompleteMultipartUpload": {
        "DaysAfterInitiation": 2
      }
    }
  ]
}
```

## Bootstrap UX

The preview bootstrap path is declarative:

1. Choose a stable `repository.id`.
2. Store the wrapping-key source outside the object store.
3. Deploy the gateway with Kubernetes Lease anchoring.

The public salt is generated by initialization, journaled before the first
artifact is written, and recovered from the verified format root or keyring
envelope on every later start, tool run, and historical read. It needs no
independent custody. `repositoryKeys.saltHex` remains available to pin a known
value; a pinned value that disagrees with the envelope fails startup.

Bootstrap assumes a fresh, randomized backend prefix. The gateway probes the
root and known repository sub-prefixes, including refused legacy generations,
before initializing, but provider `LIST`
semantics are still part of the storage trust boundary. Do not bootstrap over an
old or unknown prefix; recover or import the existing repository instead.

For production-like Helm deployments, values remain declarative. The chart
should consume an existing Secret or explicit values. It should not mutate Helm
values after first run.

Startup bootstrap behavior is:

- if the configured backend prefix is empty, initialize exactly one repository
  using the supplied repository ID, wrapping-key source, and a generated or
  pinned salt
- if the prefix already contains repository state, verify that the configured
  repository ID, any pinned salt, format-bound envelope, wrapping-key source,
  anchor, and commit chain match
- if the prefix is non-empty but cannot be verified, stop with a precise error
  instead of creating new state

## Disaster Recovery

Initial onboarding uses Kubernetes Secret custody and the live Lease anchor.
It verifies a fresh payload restore before admitting clients, without requiring
an offline signer. This proves the configured local recovery path; independent
custody and recovery after total cluster loss are not established by onboarding.

A new cluster needs more than backend credentials:

- repository ID
- wrapping-key source for the envelope
- trusted v03 anchor position and repository format generation: sequence, commit key, commit object version ID
  when available, commit body digest, signing key ID, and format-root reference

The trusted anchor position can come from a recovery bundle or audited export.
Retained backend versions can help establish what existed in storage, but by
themselves they are not a latest-state authority because a malicious backend
can hide newer valid commits or replay older valid commits.

Recovery bundles are weak-subjectivity inputs. Import requires an
operator-supplied `--min-sequence` floor external to the bundle and refuses
older valid bundles below that floor. The portable production bundle-import path also requires an
offline Ed25519 bundle signature verified by `RS3_RECOVERY_PUBLIC_KEY`.
Import scans stored v03 commits and refuses to strand higher commit sequences
unless the operator passes the explicit `--force-rollback` override after
rollback review.
Preserve fresh signed bundles outside the backend and compare the sequence and
commit digest with an external record before anchor import.

Any external anchor should store or sign the accepted commit position, not the
whole repository index. That position already commits to the signed commit
chain and therefore to the repository state reachable from it.

## Release requirements

The implementation is a controlled preview, not a production repository
release. Select one exact clean candidate and retain revision-bound evidence
for all of the following before accepting production data:

- local and scheduled checks, source-bound Kubernetes/Velero recovery, and
  disaster-recovery bundle import;
- retained-provider behavior at the required maintenance cardinality, including
  restart, checkpoint interruption, stale fencing, delayed visibility, renewal,
  guarded exact-version GC and writer handoff;
- a provider profile that explicitly supports either `atomic-create` or
  `retained-version`. The latter requires Object Lock, version IDs and
  exact-version reads after a newer object exists;
- operator-owned governance IAM or bucket-policy review proving ordinary gateway
  credentials cannot bypass governance retention; and
- approved capability, key-provider and compatibility policy, release identity,
  artifact provenance and external cryptographic/security review.

Local RustFS and Kubernetes results are regression evidence. They do not certify
a selected external provider. The [historical qualification report](reports/qualification-history.md)
preserves prior evidence and its limits; [Performance](performance.md) records
current cost results and remaining measured performance failures.

## Release commands

The commands below exercise the preview implementation. They qualify only the
candidate and environment that produce retained, revision-bound evidence.

Run the cheap local regression gate first:

```sh
just preview-gate-local
```

Release candidates should also run the release integration gate:

```sh
just preview-gate-release
```

Scheduled hardening may run the local prototype nightly gate:

```sh
just preview-gate-v3-nightly
```

For gateway regression evidence, run restore traffic through the anchored gateway and
verify the restored bytes against the application workload.

For disaster-recovery evidence, export a trusted restore bundle with
`rs3-server export-restore-bundle` and verify anchor import with
`rs3-server import-anchor` in a new cluster. For retained-version
repositories, first verify that the same bundle is rejected when the matching
retention context is omitted, then import with the configured retention mode
and verify the recovered bundle with `rs3 verify-bundle`.

## Operator configuration

For a controlled prototype deployment only:

- use `RS3_ANCHOR_MODE=kubernetes-lease`
- leave `RS3_WRITER_GUARD=required` enabled for read-write gateways
- place the S3 and admin listeners behind TLS termination, or keep them on
  cluster-local networks protected by NetworkPolicy or equivalent controls
- if you run the separate experimental console, protect its listener and its
  console-to-gateway admin hop with the same controls
- use `repositoryKeys.create=true` or `repositoryKeys.existingSecret` in Helm
- set `repository.allowInit=true` only for deliberate first initialization on a
  fresh backend prefix; turn it off for normal existing-repository serving
- keep Helm `updateStrategy.type=Recreate` for `read-write` gateways so rollouts
  do not overlap two writers
- set a stable `repository.id`
- configure gateway access credentials explicitly
- configure repository retention when retention evidence is part of the trial
- leave `maintenance.mode` unset for the default automatic posture on a
  read-write gateway, or document why `manual` or `off` is operationally safe
- configure a distinct `admin.mutationBearerToken` from an external Secret when
  operators need maintenance mutations; omit it to keep the admin listener
  read-only
- preserve `rs3 check-provider --format json` output and configure
  `RS3_PROVIDER_CONFORMANCE_REPORT_FILE` when exposing admin posture
- set gateway hardening limits for maximum `PutObject` size, buffered upload
  threshold, backend multipart part size, in-flight upload body bytes, open
  connections, concurrent requests, and request rate; align ingress limits with
  them
- use `gateway.mode=restore-readonly` for incident restore deployments
- run `rs3-server doctor --profile production --probe` before exposing the
  gateway
- keep restore verification inputs outside the object-store trust boundary
- collect metrics and logs with path-safe labels only
- treat wrapping-key rewrap as hygiene, not as recovery from a leaked wrapping
  key plus copied envelope

Do not rely on backend state alone. Use the configured anchor position and
restore-verification inputs from a trusted bundle or separate authority. See
[Retention and Object Lock](runbooks/retention-and-object-lock.md) and
[Restore Under Attack](runbooks/restore-under-attack.md) for the operating
procedures behind these constraints.

## Non-goals

The preview does not promise:

- stable repository-format compatibility
- broad generic S3 application compatibility
- external anchor implementation beyond Kubernetes Lease
- replacement of Kopia, Velero, or database-native backup systems
- that Velero application backups are confidential or complete by themselves
