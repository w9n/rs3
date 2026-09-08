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
| `PutObject` | Implemented | Supports normal writes, create-only `If-None-Match: *`, qualified Object Lock retention headers, bounded buffering, and concurrent declared-length large bodies through backend multipart standalone payloads followed by fenced publication. Validates a full-object CRC32, CRC32C, CRC64NVME, SHA1, or SHA256 checksum from the request header or verified SigV4 trailer. An omitted checksum algorithm uses CRC64NVME. Per-request retention is rejected unless the repository uses the retained-version profile. Legal-hold headers, append offsets, and unsupported conditionals are rejected before repository mutation. | Kopia, Velero, and single-stream upload clients can write through the gateway within configured size and admission budgets. |
| `CreateMultipartUpload` | Implemented | Captures the destination, qualified retention, checksum algorithm, and full-object or composite checksum type before accepting parts; starts an opaque detached carrier. An omitted algorithm uses CRC64NVME with full-object construction. Other supported algorithms default to composite construction. | Supports bounded multipart sessions with immutable checksum policy. |
| `UploadPart` | Implemented | Streams independent parts, validates one full-object part checksum from a header or verified SigV4 trailer, serializes replacement of the same number, and requires a declared plaintext length. | Different numbers upload concurrently without a whole-part buffer. Each accepted part returns its validated checksum. |
| `CompleteMultipartUpload` | Implemented | Validates the exact selected parts, their checksums and order, the optional final checksum, and the selected full-object or composite type; fully verifies ciphertext, then publishes the value and a durable completion receipt. Supports `If-None-Match: *` at publication. | Accepted retries return the original result and checksum without overwriting a newer value. |
| `AbortMultipartUpload` | Implemented | Waits for active part writes and aborts unfinished provider state. | Does not delete any accepted value. |
| `ListParts` | Implemented | Lists current original part numbers and ETags, at most 1,000 per page. | Clients can inspect and paginate unfinished uploads. |
| `HeadObject` | Implemented | Returns metadata, ETag, length, last-modified, supported Object Lock headers, and `Content-Type: application/octet-stream`. With `ChecksumMode: ENABLED`, it also returns the stored checksum and its construction type. Range or part-number metadata probes do not return checksum fields. Accepts the current unversioned `versionId=null`; rejects historical IDs and part-number metadata probes. | Metadata-only probes work without reading payload bytes. |
| `GetObject` | Implemented | Supports full-object and byte-range reads and returns `Content-Type: application/octet-stream`. With `ChecksumMode: ENABLED`, a full-object response returns the stored checksum and its construction type; a partial response omits checksum fields because the checksum does not cover the requested byte range. Accepts the current unversioned `versionId=null`; rejects historical IDs and part-number reads. | Restore clients can perform full and ranged reads. |
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
| Restore-readonly mode | Rejects mutating operations including multipart creation, part upload, completion and abort, `PutObject`, `PutObjectLegalHold`, `DeleteObject`, and `DeleteObjects`. | Restore gateways can serve reads without accepting repository mutations. |
| Object versions | Provider version IDs protect repository internals. The client-facing bucket remains unversioned and never exposes those IDs. | Literal `versionId=null` addresses the current logical value in supported read/delete operations; other version IDs are rejected. It is not a durable reference across overwrites. |
| Object Lock retention | `PutObject` accepts retention headers only when startup selected and qualified the retained-version profile. An AtomicCreate or development repository cannot be upgraded by one request. Repository retention can strengthen backend commit protection; client-facing retention mutation APIs are not implemented. | Retention is configured at repository initialization or supplied on a qualified retained write, not by later client-side release or shortening. |
| Multipart options | `Content-MD5`, nondefault content types, custom metadata, tags, ACLs and explicit SSE options are not implemented. Unsupported options return `NotImplemented`. Request checksums are supported for the five algorithms described below. | Use an omitted or `application/octet-stream` content type and an omitted or `STANDARD` storage class. `Content-MD5` and MD5 ETag behavior remain a later compatibility task. |

## Request checksums

The gateway hashes the plaintext request stream alongside encryption and
completes checksum validation before it accepts repository publication. It
accepts one checksum algorithm per request. `PutObject` is always full-object.
Multipart creation captures the algorithm and construction type before any part
is accepted. Multipart
part checksums always cover that part's bytes. A composite checksum hashes the
selected parts' raw digests; its response value appends the selected part count
as `-N`. A completion request can supply the plain Base64 digest with explicit
`ChecksumType: COMPOSITE`. An optional `-N` suffix must match the selected count.

| Algorithm | Ordinary `PutObject` | Multipart full-object | Multipart composite |
| --- | --- | --- | --- |
| CRC32 | Supported | Supported | Supported |
| CRC32C | Supported | Supported | Supported |
| CRC64NVME | Supported | Supported | Not supported |
| SHA1 | Supported | Not supported | Supported |
| SHA256 | Supported | Not supported | Supported |

Other flexible-checksum algorithms, including SHA512, MD5 and XXHash variants,
are deferred. They are distinct from the separate `Content-MD5` request header
and MD5 ETag behavior.

Checksum headers and verified SigV4 checksum trailers are validated before an
accepted publication. A malformed, mismatched, incomplete, or conflicting
checksum fails the request. The accepted aggregate checksum algorithm,
construction type, and digest are stored in encrypted authenticated repository
metadata and are returned by the corresponding S3 responses. Multipart
selection digests bind the selected part checksum facts; those raw part facts
are not stored as durable standalone records. Checksums are not
provider object keys, backend metadata, ETags, or repository authentication
digests. Qualification covers independent vectors, authenticated HTTP trailer
tests, AWS CLI 2.34.24 CRC64NVME and SHA256 transfers, and Velero 1.18.0 with
AWS plugin 1.14.0 default CRC32 backup and restore.

## Explicitly Not Implemented

| Operation family | Examples | Client impact |
| --- | --- | --- |
| Bucket lifecycle and administration | `CreateBucket`, `DeleteBucket`, bucket ACL/policy/CORS/lifecycle/replication/website/encryption/public-access-block APIs | Buckets are provisioned outside the gateway. |
| Multipart inventory | `ListMultipartUploads` | Only an upload already known to the client can be inspected with `ListParts`. |
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

## Multipart bounds and retries

Unfinished uploads have a 24-hour monotonic lifetime, with at most 128 sessions
and 65,536 part-number entries across the gateway. Each upload permits at most
10,000 original part numbers. Nonfinal selected parts must contain at least
5 MiB of plaintext. The final part may be smaller, including empty. A selection
containing only one zero-byte part publishes an index-only value, but the
completion selection must contain at least one part. Uploads and assembled values must fit
`RS3_MAX_PUT_OBJECT_BYTES`; per-part ciphertext, including one
16-byte tag per 64 KiB segment, must also fit the provider's 5 GiB part limit.

Each active part reserves a 2.25 MiB working set from the existing upload-body
budget. Completed part metadata has a separate bounded entry budget. Completion
XML is capped at 4 MiB before decoding and at 10,000 selected records afterward.
These are gateway bounds, not a promise to hide object lengths or request timing.

The gateway owns admitted upload work across a waiting client's disconnect.
Completion and abort wait for active parts; a failed selection check leaves the
unfinished session usable. A consumed completion can leave a verified but
unaccepted orphan on failure. Expired sessions are aborted by the gateway, and
incomplete sessions are lost on restart. Expiry rejects new requests immediately,
then waits for already admitted part work before aborting provider state. Backend
cleanup must allow at least two days, covering the 24-hour session lifetime plus
in-progress completion margin.
Read-write S3 startup rejects a shorter lifecycle rule that overlaps the
repository prefix, and also rejects ordinary age-based expiration that overlaps
repository storage. Incomplete-upload cleanup is distinct from repository-object
retention and does not authorize repository expiration.

The latest 1,024 accepted completion receipts survive checkpoint, compaction and
restart. Repeat completion with the same upload ID, key and selected-part list
returns the original ETag, even after a later overwrite. An unknown, aborted or
evicted ID cannot initiate a new publication. Unresolved anchor outcomes fail
closed until trusted recovery. Ordinary `PutObject` remains a new write.

Current part ETags are opaque sealing-attempt tokens and completed-object ETags
use the existing rs3 metadata token. They are not plaintext MD5 checksums.
