# Supported S3 Operations

`rs3` implements the S3 subset required by backup and restore clients. It is
not a general-purpose S3 server. Client object keys are accepted and returned
only through the authenticated S3 API; backend keys, logs, metrics, admin
reports, and stored metadata remain path-private.

## Implemented

| Operation | Status | Notes | Client impact |
| --- | --- | --- | --- |
| `HeadBucket` | Implemented | Accepts only the configured public bucket. | Basic SDK bucket probes work. |
| `ListBuckets` | Implemented | Returns the configured public bucket. | Basic SDK account probes work without exposing backend buckets. |
| `GetBucketLocation` | Implemented | Returns the configured S3 region. | SDK region discovery works for the served bucket. |
| `PutObject` | Implemented | Supports normal writes, create-only `If-None-Match: *`, qualified Object Lock retention headers, bounded buffering, and concurrent declared-length large bodies through backend multipart standalone payloads followed by fenced publication. Per-request retention is rejected unless the repository uses the retained-version profile. Legal-hold headers, append offsets, and unsupported conditionals are rejected before repository mutation. | Kopia, Velero, and single-stream upload clients can write through the gateway within configured size and admission budgets. |
| `HeadObject` | Implemented | Returns metadata, ETag, length, last-modified, and supported Object Lock headers. Accepts the current unversioned `versionId=null`; rejects historical IDs and part-number metadata probes. | Metadata-only probes work without reading payload bytes. |
| `GetObject` | Implemented | Supports full-object and byte-range reads. Accepts the current unversioned `versionId=null`; rejects historical IDs and part-number reads. | Restore clients can perform full and ranged reads. |
| `ListObjects` | Implemented | Supports prefix, delimiter, marker, and bounded result pages. | Older S3 clients can list logical prefixes. |
| `ListObjectsV2` | Implemented | Supports prefix, delimiter, continuation tokens, start-after, and bounded result pages. | Modern backup clients can list logical prefixes. |
| `GetBucketVersioning` | Implemented | Returns an empty versioning configuration, with no enabled/suspended status or MFA-delete setting. | Clients can detect the unversioned logical bucket. |
| `ListObjectVersions` | Implemented for the current view | Each live key appears once with `VersionId=null` and `IsLatest=true`; no old values or delete markers. Supports prefix, delimiter, max keys, key markers and URL encoding. | Version-mode listings work for the current namespace. |
| `DeleteObject` | Implemented | Performs a logical tombstone commit. Accepts current `versionId=null`; rejects historical IDs and conditional deletes. | Clients can delete current logical objects; retained backend versions remain protected until maintenance can remove eligible garbage. |
| `DeleteObjects` | Implemented | Performs per-key logical tombstone commits, returns per-key `Deleted` or `Error` entries, and honors quiet mode. Historical version IDs or conditional entries return per-key errors; current `versionId=null` is accepted. | Batch-delete clients such as barman-cloud can clean up logical keys without losing per-object failure detail. |
| `GetObjectLegalHold` | Implemented | Reads the current logical object's legal-hold status. Accepts current `versionId=null`; rejects historical IDs. | Object Lock aware clients can inspect legal hold. |
| `PutObjectLegalHold` | Not implemented | Both setting and clearing legal hold are refused for v03. Restore dependencies do not yet have a complete hold-propagation and guarded-release lifecycle. | Clients must use finite repository retention; legal-hold publication is unavailable in the preview. |

## Guarded Partials

| Surface | Behavior | Client impact |
| --- | --- | --- |
| Restore-readonly mode | Rejects mutating operations including `PutObject`, `PutObjectLegalHold`, `DeleteObject`, and `DeleteObjects`. | Restore gateways can serve reads without accepting repository mutations. |
| Object versions | Provider version IDs protect repository internals. The client-facing bucket remains unversioned and never exposes those IDs. | Literal `versionId=null` addresses the current logical value in supported read/delete operations; other version IDs are rejected. It is not a durable reference across overwrites. |
| Object Lock retention | `PutObject` accepts retention headers only when startup selected and qualified the retained-version profile. An AtomicCreate or development repository cannot be upgraded by one request. Repository retention can strengthen backend commit protection; client-facing retention mutation APIs are not implemented. | Retention is configured at repository initialization or supplied on a qualified retained write, not by later client-side release or shortening. |
| Client multipart upload | Not implemented. Large `PutObject` streams may still use backend multipart internally. | Clients that require S3 multipart upload APIs must use single-stream upload mode or stay under `RS3_MAX_PUT_OBJECT_BYTES`. |

## Explicitly Not Implemented

| Operation family | Examples | Client impact |
| --- | --- | --- |
| Bucket lifecycle and administration | `CreateBucket`, `DeleteBucket`, bucket ACL/policy/CORS/lifecycle/replication/website/encryption/public-access-block APIs | Buckets are provisioned outside the gateway. |
| Client multipart upload | `CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload`, `ListMultipartUploads`, `ListParts` | Backup clients needing multipart APIs are not compatible yet. |
| Copy operations | `CopyObject`, `UploadPartCopy` | Clients must upload bytes through `PutObject`; server-side copy is unavailable. |
| Object tagging and ACLs | `PutObjectTagging`, `GetObjectTagging`, `DeleteObjectTagging`, object ACL APIs | Tags and ACLs are not part of the rs3 repository contract. |
| Object retention mutation APIs | `GetObjectRetention`, `PutObjectRetention` | Retention is surfaced through `HeadObject` and configured write behavior, not post-write mutation. |
| Historical versions and versioning controls | Historical get/head/delete/list, delete-marker APIs, `PutBucketVersioning` | The client API presents only a current unversioned namespace. Repository history and recovery use signed commits and anchors. |

## Unversioned pagination

`ListObjectVersions` uses the same trusted current index as ordinary listing.
Common prefixes consume the page limit. Continue with `NextKeyMarker`; when the
last result is an object, `NextVersionIdMarker` is `null`. A prefix boundary has
no next version marker. A supplied `version-id-marker` must be `null` and include
a nonempty key marker; historical markers are rejected.

With `encoding-type=url`, keys, common prefixes and key-based response bounds
are percent-encoded. Clients must decode those values before using them as
request parameters. Other encodings, expected-owner checks, Requester Pays and
optional listing attributes are unsupported and rejected for these probes.
`GetBucketVersioning` also rejects an expected-owner request it cannot verify.

These probes do not provide historical recovery. In particular, rclone's
`--s3-versions` sees current objects only; `--s3-version-at` cannot reconstruct
older rs3 state. Use the [isolated recovery runbook](../runbooks/restore-under-attack.md)
with a trusted older bundle for incident recovery.
