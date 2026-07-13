# Retention And Object Lock

Retention protects object versions. It does not verify that the provider served
the latest valid commit. Use retention for deletion resistance; use signed
commits and anchors for latest-state authority.

## Protected Set

When retention is enabled, protect every object needed for restore:

- keyring envelopes
- format roots
- signed commits, including payload and index-delta sections

If one class is missing, the backup may become retained but unrestorable.

## Configuration

```sh
RS3_REPOSITORY_RETENTION_MODE=compliance
RS3_REPOSITORY_RETENTION_DAYS=30
```

Use `compliance` where the provider supports it. Use `governance` only when
privileged bypass is intentional. Normal gateway credentials should not carry
governance bypass permission.

## Dedup Rule

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

The gateway does not expose historical-root registration or in-place format or
data-key rotation. Automatic maintenance protects the current anchor graph.
Repository-level maintenance rejects foreign-format protected roots before any
storage read, and v02 rejects client legal holds. Treat those as unsupported
capabilities. Do not bypass the rejection by omitting a root or mutating Object
Lock metadata outside the documented provider qualification workflow.

The read-write gateway now runs guarded renewal and orphan reclamation as a
background service when `RS3_MAINTENANCE_MODE=auto`, which is the default.
`manual` requires an operator trigger and `off` disables renewal, so treat both
as an explicit operational exception when retention is enabled. The supervisor
parks rather than running without an enforced maintenance guard.

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
