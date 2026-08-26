# Security Policy

## Supported Versions

`rs3` is preview-scoped and has not cut a stable release. There is no supported
release line yet: the only version that receives fixes is the current tip of
`main`. The preview is explicitly not a stable repository-format or security
guarantee, as described in [`docs/site/production-preview.md`](docs/site/production-preview.md).

## Reporting a Vulnerability

Report suspected vulnerabilities through GitHub's private vulnerability
reporting, from the **Security** tab of this repository. This keeps the report
private until a fix is available.

Please do not open a public issue for a suspected vulnerability.

Because the project is preview-scoped and maintained by a single author, there
is no response-time commitment. Reports are triaged on a best-effort basis.

## Scope

The product requirements are path privacy, rollback resistance, and restore
correctness. Reports that demonstrate a break in any of the following are in
scope:

- plaintext paths, directory names, Kubernetes object names, namespaces, or
  snapshot names becoming visible in object-store keys, unauthenticated
  metadata, logs, metrics labels, or errors
- acceptance of rolled-back or replayed repository state despite signed commits
  and external anchors
- restore producing data that does not match what was backed up
- key handling or envelope construction that weakens the boundaries described
  in [`docs/site/security-model.md`](docs/site/security-model.md)

## Out of Scope

Two categories are already documented rather than unknown:

- **Accepted leakage.** What the object store can legitimately observe is
  enumerated in the *Accepted Leakage* section of
  [`docs/site/security-model.md`](docs/site/security-model.md). Reports that
  restate documented leakage are not vulnerabilities.
- **Known open risks.** The *Current Open Risks* section of the same document
  tracks gaps the project already acknowledges, and
  [`docs/site/security-review.md`](docs/site/security-review.md) records the
  review standard and stop conditions.

Please check both before reporting.
