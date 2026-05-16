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

## Incident Rules

- Do not delete retained objects during cleanup.
- Freeze write credentials if bad writes continue.
- Preserve gateway logs, metrics, trusted restore bundles, and anchor state.
- Compare anchor with retained commit versions where configured.
- Restore from a verified v2 anchor using read-only credentials where possible.
