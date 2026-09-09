# Retention And Object Lock

Retention protects object versions. It does not verify that the provider served
the latest valid commit. Use retention for deletion resistance; use signed
commits and anchors for latest-state authority.

## Protected Set

When retention is enabled, protect every object needed for restore:

- keyring envelopes
- format roots
- signed commits, including embedded payload and index sections
- referenced catalog and index runs
- referenced payload packs and standalone streams

If one class is missing, the backup may become retained but unrestorable.

## Configuration

```sh
RS3_REPOSITORY_RETENTION_MODE=compliance
RS3_REPOSITORY_RETENTION_DAYS=30
```

The recovery policy is a separate logical history setting. Its default
`RS3_RECOVERY_WINDOW_DAYS=30` keeps each accepted predecessor selectable for a
30-day recovery window; it is applied to newly published history. The
provider's `RS3_REPOSITORY_RETENTION_DAYS` is a physical protection floor for
backend versions, not a historical selector. It must exceed the automatic
maintenance interval plus its renewal safety horizon, and a provider may impose
a longer floor. Neither setting shortens an already accepted deadline.
Maintenance rounds generated physical coverage targets up to a UTC-day boundary
so an unchanged dry run can be applied without millisecond-by-millisecond
changes to its digest. Crossing that coverage boundary requires a new dry run.
The generated target can be almost one day later than the exact requirement;
the adapter then rounds its relative retention period to whole days. Logical
recovery deadlines remain exact.

A local retained RustFS Object Lock and Kubernetes Lease exercise passed graceful
read-only and writer restarts, historical AWS CLI/rclone copyout and range reads,
and actual compaction after 256 writes. Its dry run followed by an apply with
reclamation disabled made no provider deletes. Deterministic controlled-time tests
cover expiry, renewal, guard faults, and eligible exact-version GC. This is not a
30-day provider-outage exercise or general retained-provider qualification.

Use `compliance` where the provider supports it. Use `governance` only when
privileged bypass is intentional. Normal gateway credentials should not carry
governance bypass permission.

S3 init and read-write startup inspect bucket Lifecycle before writing repository
metadata or genesis. Retained repositories also require enabled Versioning and
Object Lock. Denied or unknown policy inspection stops initialization. The
explicit S3 `NoSuchLifecycleConfiguration` response means no lifecycle policy
is configured. See [GetBucketLifecycleConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLifecycleConfiguration.html)
for the required bucket-policy read permission.

Enabled expiration rules that overlap repository storage are rejected, including
noncurrent-version expiration. A disjoint rule prefix is allowed; tag and size
filters alone cannot prove that future repository objects are excluded.
Expired-delete-marker cleanup and incomplete-multipart cleanup are permitted.
Their presence does not establish a suitable upload timeout or cleanup budget.

Transitions to Standard-IA, One Zone-IA and Glacier Instant Retrieval preserve
direct reads and are permitted. Glacier Flexible Retrieval, Deep Archive,
unknown targets and unqualified Intelligent-Tiering transitions are rejected.
Intelligent-Tiering can include archive tiers that require a separate restore
operation. See [S3 storage classes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage-class-intro.html).
These checks do not qualify renewal permissions, governance bypass or provider
durability; provider conformance and policy review remain required.

Run `rs3 check-v2-provider --legal-hold --format json` with the serving binary
and backend credentials. S3 qualification uses a separate probe prefix in the
same bucket, leaving the repository namespace available for fresh initialization.
Both prefixes must pass Lifecycle inspection. The retained profile sends actual
exact-version DELETE requests for synthetic protected objects and checks an
unprotected deletion control. Bucket default retention can prevent that control
from passing; do not weaken shared bucket protection merely to pass a probe.
Retained and legal-hold probe versions can remain after the command exits.
See [provider evidence configuration](../reference/configuration.md#provider-conformance-evidence)
for prefix constraints and evidence binding. Governance mode additionally needs
the explicit `--governance-bypass-reviewed` policy-review marker.

Restore-only access skips write-policy inspection so recovery credentials do
not need bucket-administration permissions. Exact-version reads and accepted
anchor verification still apply.

## Kopia and Velero retention

Keep snapshot retention and backup TTLs configured in the client. In a
read-write rs3 gateway, client DELETE removes the logical object from the
current namespace even while its backing versions remain protected. The
client policy does not schedule physical deletion of rs3's encrypted objects.

| Setting or action | Responsibility and effect |
| --- | --- |
| Kopia snapshot retention | Kopia expires snapshots and performs its own repository maintenance through the gateway. |
| Velero backup TTL | Velero makes an expired backup eligible for garbage collection and requests deletion through the gateway. |
| `RS3_REPOSITORY_RETENTION_*` | rs3 applies the repository protection policy to restore-critical backend versions. |
| rs3 guarded maintenance | Renews reachable versions and reclaims eligible unreachable versions within its budgets. |
| Backing bucket Lifecycle | A separate provider deletion policy; it cannot determine rs3 graph reachability. |

When Kopia connects to rs3, leave Kopia's S3 Object Lock mode and
`--extend-object-locks` disabled. rs3 does not implement the client
`PutObjectRetention` API, so Kopia cannot renew locks through that interface.
Use rs3's backing-store retention and renewal instead. Kopia's
[Object Lock instructions](https://kopia.io/docs/advanced/ransomware-protection/)
apply to a direct storage connection; do not copy their bucket Lifecycle advice
to rs3's backing repository.

Different Velero TTLs control which backups remain visible to Velero; they do
not configure separate per-backup WORM windows in rs3. Continue running Velero's
[backup garbage collection](https://velero.io/docs/main/how-velero-works/)
and Kopia maintenance. These client jobs and rs3's backend maintenance serve
different purposes and both are needed.

## Backing Object Lock and Lifecycle

Enable and qualify Object Lock on the backing bucket, and configure rs3's
retention policy explicitly. Bucket defaults alone do not renew old shared
objects or prove the effective protection of the complete restore graph.

Object Lock expiry makes a version eligible for deletion; it does not itself
delete that version. S3 Lifecycle expiration is a separate action. With
versioning, expiration can create delete markers, and noncurrent-version
expiration can later remove unlocked versions. See the
[S3 Object Lock considerations](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html).

Do not apply blanket age-based expiration to rs3's repository prefix, including
noncurrent-version expiration. A long-lived format root, keyring or payload can
still be required by the current anchor. An expired lock does not prove that
an object is unreachable. Let guarded rs3 maintenance evaluate reachability
and protection before physical deletion. Configure backing storage through its
operator interface; rs3 does not expose client bucket Lifecycle management.

## Reused data and renewal

Retention follows the newest protected reference:

```text
Day 0:  segment A retain until Day 30
Day 20: new protected snapshot reuses A
Needed: A retain until at least Day 50
```

The gateway must extend reused objects and must never shorten retention. If the
provider cannot extend retention, protected writes fail.

v2 full-GC maintenance reports when current or protected historical-root
versions need renewal. A guarded apply renews and verifies the exact catalog,
run, payload, format-root, and keyring-envelope versions before it attempts any
orphan deletion. It consumes inventory through bounded provider pages, uses one
immutable plan, and fails closed when a page/item budget, exact authority root,
or protection fact is unavailable.
The preview library defaults to at most 4,096 inventory pages and 2,000,000
raw provider inventory members per plan. Filtered members such as S3 delete
markers consume that item budget too. The in-gateway maintenance supervisor
exposes these ceilings as `RS3_MAINTENANCE_MAX_INVENTORY_PAGES` and
`RS3_MAINTENANCE_MAX_INVENTORY_ITEMS`. Require an explicit, reviewed increase
for larger repositories.

Authenticated recovery history has separate byte caps shared by foreground
publication verification and maintenance planning: 256 MiB metadata and 64 MiB
pending sections by default. Configure
`RS3_MAINTENANCE_MAX_HISTORY_METADATA_BYTES=1073741824` to select a 1 GiB
metadata cap explicitly. The server rejects metadata caps below
1 MiB or above 8 GiB, and pending-section caps below 24 MiB or above 1 GiB.

Full-GC planning wraps its store in a read-only ledger. Every logical provider
`HEAD`, bounded range `GET`, and LIST page is charged before it is forwarded,
including commit replay, referenced catalog runs, protected roots, and renewal
inspection. Reports combine those observed reads with the exact planned delete,
retention-extension, and post-extension verification calls. A zero remaining
item budget performs no speculative LIST. Counts do not include retries hidden
inside a provider SDK, so retry policy remains a separate transport control.
The S3 adapter additionally caps each raw list response at 16 MiB before XML
deserialization and rejects returned member counts above the requested
`MaxKeys`; protocol-invalid providers therefore cannot turn a bounded page into
an unbounded allocation.

For retained Object Lock repositories, every accepted successor records its
exact predecessor, policy, and
protection deadline in the encrypted authenticated recovery registry. The
current point is implicit, and the operator can list and select registered
points with the [recovery-point workflow](restore-under-attack.md). A retained
object alone is still insufficient recovery authority: the live anchor and
authenticated registry must agree. Preserve trusted bundles and verify their
complete graphs for recovery when that authority is unavailable. The gateway
does not expose arbitrary historical-root registration, in-place format or
data-key rotation, or an S3 historical-version API.
The registry and operator selection path are preview implementation. A local
retained RustFS Object Lock and Kubernetes Lease exercise covers graceful restart
and selected historical reads; provider-fault and 30-day outage qualification
remain pending.
Repository-level maintenance rejects foreign-format protected roots before any
storage read, and v03 rejects client legal holds. Treat those as unsupported
capabilities. Do not bypass the rejection by omitting a root or mutating Object
Lock metadata outside the documented provider qualification workflow.

The read-write gateway now runs guarded renewal and orphan reclamation as a
background service when `RS3_MAINTENANCE_MODE=auto`, which is the default.
Retained read-write repositories require `auto`; `manual` requires an operator
trigger and `off` disables the supervisor, so neither is a retained-writer
posture. Set `RS3_RECLAMATION_ENABLED=false` when physical orphan deletion must
stay disabled: renewal still runs in `auto`, while eligible garbage is retained.
The supervisor parks rather than running without an enforced maintenance guard.
While parked, it performs neither renewal nor reclamation: locks can expire and
garbage can accumulate. Alert on parked or failed maintenance and on approaching
retention deadlines; a running gateway is not evidence that renewal succeeded.

Size every Object Lock window strictly longer than:

```text
maximum automatic-maintenance interval
+ renewal safety horizon
```

Configure the renewal horizon to cover the longest credible gateway or
control-plane outage plus operator detection and response time. The production
doctor and Helm production profile reject a window that does not exceed the
maximum interval plus that horizon. This margin is not optional. A retention
deadline that lapses during an outage cannot be repaired retroactively. A
failed apply may already have strengthened some exact versions; retention
extension is intentionally irreversible and the run must be retried from a new
dry run.

v2 compaction can rewrite the current live namespace into a protected snapshot
commit after verifying that snapshot with a fresh reader. Old source commits are
not force-deleted by compaction; they remain subject to exact-version orphan GC,
provider retention, legal hold, operator budgets, and any protected historical
roots that have not been explicitly discarded. The legacy mixed-commit snapshot
publisher has a data-dependent write and fresh-reader verification shape, so it
fails finite request, HEAD, range-read, or write-byte ceilings until that
mutation path has its own end-to-end ledger.

## Storage cost and reclamation

For capacity planning, use this rough estimate:

```text
stored bytes ≈ live restore graph + obsolete bytes per day × locked days
```

Count newly written and superseded backend bytes, not just changes in source
file sizes. Shared packs can keep dead records pinned by one live record;
metadata, compaction copies, renewal margins and longer existing locks add
cost. A retention period is a minimum protection duration, not a storage-size
ceiling or a promise to delete on a specific day.

Client expiry alone does not shrink backing storage. Data must become
unreachable, any required compaction must succeed, all protection must permit
deletion, and a guarded maintenance pass must finish within its budgets. The
automatic recovery registry protects its accepted points; a bundle-imported or
operator-supplied external root still requires the explicit protected-root
workflow.

## Cluster Takeover

If an attacker controls Kubernetes but not object-store retention, they may
create bad backups or corrupt the anchor. They should not be able to delete
retained object versions before expiry.

Required posture:

- least-privilege object-store credentials
- retention on all restore-critical classes
- audit logs outside the cluster and storage account
- repository keys protected outside the attacked namespace
- external review of anchor and retained-version divergence

## Provider Gate

A provider must verify:

- retention can be set at write time
- retention can be extended, not shortened
- legal hold blocks deletion
- delete markers do not remove locked historical versions
- retained writes return provider version IDs
- exact-version reads return the requested retained version after a newer
  latest version exists
- retained multipart completion protects the returned version before the write
  is accepted
- normal credentials cannot bypass governance

Native conditional create remains the preferred qualification profile when the
provider supports it. Providers that accept duplicate same-key writes can still
qualify for retained repositories through the retained-version profile, but only
when Object Lock, version IDs, and exact-version reads pass live tests.

Do not infer Object Lock semantics from S3 compatibility alone.
Do not treat `HEAD` before `PUT` as equivalent to native conditional create; it
is not atomic and is not a production-preview safety guarantee.
Do not infer governance-bypass safety from Object Lock alone. For governance
mode, normal gateway credentials must not have `s3:BypassGovernanceRetention`
or provider-equivalent bypass permission. The live retained-version test
verifies retained writes, retained exact-version reads, retention extension,
legal hold, and delete blocking without bypass headers; it does not replace an
IAM or bucket policy review.

Preserve the schema-v5 report produced by the exact Linux executable being
deployed. The gateway checks its executable digest as well as the source
revision, backend target, qualification profile, principal fingerprint and
requested retention mode/days. A different executable or changed qualification
context requires a fresh provider run; sharing a Git revision is insufficient.
The principal fingerprint is operator-declared, not cloud identity attestation.
Retired report schemas are rejected.

During restore verification, `rs3` reports how many verified restore-critical
objects expose retention or legal-hold metadata. Treat that as repository
evidence. Run with `--require-provider-delete-protection` for protected
restores, and use S3 CLI probes to confirm provider behavior before trusting a
new backend.

Before enabling destructive v2 maintenance for a retained backend, run a GC
rehearsal against a fresh prefix after retained-provider conformance has passed:

```sh
just v2-gc-rehearsal-live "$BACKEND_BUCKET" "$ENDPOINT_URL" "$REGION" "$BACKEND_PREFIX"
```

The rehearsal writes a retained anchor, one protected orphan, and one
unprotected exact-version orphan. It dry-runs with a one-delete budget, applies
only the unprotected exact-version delete, verifies the protected candidate
remains blocked, and reloads the anchor-selected chain. The command uses the
dedicated Kubernetes Lease writer fence by default. The xtask
`--unenforced-guard` escape hatch is only for isolated development and does not
qualify a retained provider.

## Incident Rules

- Do not delete retained objects during cleanup.
- Freeze write credentials if bad writes continue.
- Preserve gateway logs, metrics, trusted restore bundles, and anchor state.
- Compare anchor with retained commit versions where configured.
- Restore from a verified v2 anchor using read-only credentials where possible.
