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
| `PutObject` | Implemented | Supports normal writes, create-only `If-None-Match: *`, Object Lock retention headers, legal-hold-on headers, bounded buffering, and streaming large bodies to backend multipart writes. Rejects append offsets and unsupported conditionals. | Kopia, Velero, and single-stream upload clients can write through the gateway within configured size and admission budgets. |
| `HeadObject` | Implemented | Returns metadata, ETag, length, last-modified, and supported Object Lock headers. Rejects object versions and part-number metadata probes. | Metadata-only probes work without reading payload bytes. |
| `GetObject` | Implemented | Supports full-object and byte-range reads. Rejects object versions and part-number reads. | Restore clients can perform full and ranged reads. |
| `ListObjects` | Implemented | Supports prefix, delimiter, marker, and bounded result pages. | Older S3 clients can list logical prefixes. |
| `ListObjectsV2` | Implemented | Supports prefix, delimiter, continuation tokens, start-after, and bounded result pages. | Modern backup clients can list logical prefixes. |
| `DeleteObject` | Implemented | Performs a logical tombstone commit. Rejects versioned and conditional deletes. | Clients can delete current logical objects; retained backend versions remain protected until maintenance can remove eligible garbage. |
| `DeleteObjects` | Implemented | Performs per-key logical tombstone commits, returns per-key `Deleted` or `Error` entries, and honors quiet mode. Versioned or conditional entries return per-key errors. | Batch-delete clients such as barman-cloud can clean up logical keys without losing per-object failure detail. |
| `GetObjectLegalHold` | Implemented | Reads the current logical object's legal-hold status. Rejects versioned reads. | Object Lock aware clients can inspect legal hold. |
| `PutObjectLegalHold` | Partial | Allows setting legal hold on. Clearing legal hold is refused. Rejects versioned writes. | Operators can add protection through S3-compatible clients; release remains a backend/operator maintenance action. |

## Guarded Partials

| Surface | Behavior | Client impact |
| --- | --- | --- |
| Restore-readonly mode | Rejects mutating operations including `PutObject`, `PutObjectLegalHold`, `DeleteObject`, and `DeleteObjects`. | Restore gateways can serve reads without accepting repository mutations. |
| Object versions | Provider version IDs protect repository internals, but client-facing versioned object operations are not supported. | Clients must address the current logical object, not S3 object versions. |
| Object Lock retention | `PutObject` accepts retention headers and repository retention can strengthen backend commit protection. Client-facing retention mutation APIs are not implemented. | Retention is configured at the gateway and write path, not by later client-side release or shortening. |
| Client multipart upload | Not implemented. Large `PutObject` streams may still use backend multipart internally. | Clients that require S3 multipart upload APIs must use single-stream upload mode or stay under `RS3_MAX_PUT_OBJECT_BYTES`. |

## Explicitly Not Implemented

| Operation family | Examples | Client impact |
| --- | --- | --- |
| Bucket lifecycle and administration | `CreateBucket`, `DeleteBucket`, bucket ACL/policy/CORS/lifecycle/replication/website/encryption/public-access-block APIs | Buckets are provisioned outside the gateway. |
| Client multipart upload | `CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload`, `ListMultipartUploads`, `ListParts` | Backup clients needing multipart APIs are not compatible yet. |
| Copy operations | `CopyObject`, `UploadPartCopy` | Clients must upload bytes through `PutObject`; server-side copy is unavailable. |
| Object tagging and ACLs | `PutObjectTagging`, `GetObjectTagging`, `DeleteObjectTagging`, object ACL APIs | Tags and ACLs are not part of the rs3 repository contract. |
| Object retention mutation APIs | `GetObjectRetention`, `PutObjectRetention` | Retention is surfaced through `HeadObject` and configured write behavior, not post-write mutation. |
| Object version listing and delete-marker APIs | `ListObjectVersions`, version-specific delete/get/head variants | The client API presents a current logical namespace. Repository rollback protection is handled by signed commits and anchors. |
