//! Request and response mapping helpers for S3 object operations.

use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use rs3_repository::{RepositoryError, RepositoryListEntry};
use rs3_storage::StorageError;
use rs3_types::{LegalHoldStatus, LogicalPath, RetentionMode, RetentionPolicy};
use s3s::S3Result;
use s3s::dto::{
    CommonPrefix, DeleteObjectInput, GetObjectInput, GetObjectLegalHoldInput, HeadObjectInput,
    Object, ObjectLockLegalHold, ObjectLockLegalHoldStatus, PutObjectInput,
    PutObjectLegalHoldInput, StreamingBlob, Timestamp,
};
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(super) struct ListPage {
    pub(super) contents: Vec<Object>,
    pub(super) common_prefixes: Vec<CommonPrefix>,
    pub(super) key_count: usize,
    pub(super) next_continuation_token: Option<String>,
}

enum ListItem {
    Object(Box<Object>),
    CommonPrefix(CommonPrefix),
}

#[cfg(test)]
pub(super) async fn collect_body(body: Option<StreamingBlob>, max_bytes: u64) -> S3Result<Bytes> {
    collect_body_reserving(body, max_bytes, |_| Ok(())).await
}

pub(super) async fn collect_body_reserving(
    body: Option<StreamingBlob>,
    max_bytes: u64,
    mut reserve_for_len: impl FnMut(usize) -> S3Result<()>,
) -> S3Result<Bytes> {
    let Some(mut body) = body else {
        return Ok(Bytes::new());
    };
    let mut bytes = BytesMut::new();

    while let Some(chunk) = body.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(error) => {
                let mut s3_error = s3s::s3_error!(IncompleteBody, "failed to read request body");
                s3_error.set_source(error);
                return Err(s3_error);
            }
        };
        let next_len = bytes.len().checked_add(chunk.len()).ok_or_else(|| {
            s3s::s3_error!(
                EntityTooLarge,
                "PutObject body exceeds the configured maximum size"
            )
        })?;
        if u64::try_from(next_len).unwrap_or(u64::MAX) > max_bytes {
            return Err(s3s::s3_error!(
                EntityTooLarge,
                "PutObject body exceeds the configured maximum size"
            ));
        }
        reserve_for_len(next_len)?;
        bytes.extend_from_slice(&chunk);
    }

    Ok(bytes.freeze())
}

pub(super) fn validate_put_object_request(input: &PutObjectInput, max_bytes: u64) -> S3Result<()> {
    if input.if_match.is_some() {
        return Err(s3s::s3_error!(
            InvalidRequest,
            "If-Match is not supported for PutObject"
        ));
    }
    if input.write_offset_bytes.is_some() {
        return Err(s3s::s3_error!(
            NotImplemented,
            "append-style PutObject is not supported"
        ));
    }
    if let Some(content_length) = input.content_length {
        let content_length = u64::try_from(content_length).map_err(|_| {
            s3s::s3_error!(
                InvalidRequest,
                "Content-Length must be a non-negative integer"
            )
        })?;
        if content_length > max_bytes {
            return Err(s3s::s3_error!(
                EntityTooLarge,
                "PutObject body exceeds the configured maximum size"
            ));
        }
    }
    Ok(())
}

pub(super) fn put_object_legal_hold_status(
    input: &PutObjectInput,
) -> S3Result<Option<LegalHoldStatus>> {
    input
        .object_lock_legal_hold_status
        .as_ref()
        .map(legal_hold_status)
        .transpose()
}

pub(super) fn put_object_retention_policy(
    input: &PutObjectInput,
) -> S3Result<Option<RetentionPolicy>> {
    put_object_retention_policy_at(input, SystemTime::now())
}

fn put_object_retention_policy_at(
    input: &PutObjectInput,
    now: SystemTime,
) -> S3Result<Option<RetentionPolicy>> {
    let mode = input.object_lock_mode.as_ref();
    let retain_until = input.object_lock_retain_until_date.as_ref();
    let (Some(mode), Some(retain_until)) = (mode, retain_until) else {
        if mode.is_some() || retain_until.is_some() {
            return Err(s3s::s3_error!(
                InvalidRequest,
                "Object Lock mode and retain-until date must be provided together"
            ));
        }
        return Ok(None);
    };

    let mode = match mode.as_str() {
        s3s::dto::ObjectLockMode::COMPLIANCE => RetentionMode::Compliance,
        s3s::dto::ObjectLockMode::GOVERNANCE => RetentionMode::Governance,
        _ => {
            return Err(s3s::s3_error!(
                InvalidRequest,
                "Object Lock mode is not supported"
            ));
        }
    };
    let retain_until = timestamp_system_time(retain_until)?;
    let duration = retain_until.duration_since(now).map_err(|_| {
        s3s::s3_error!(
            InvalidRequest,
            "Object Lock retain-until date must be in the future"
        )
    })?;
    let retain_days = duration.as_secs().div_ceil(86_400).max(1);
    let retain_days = u32::try_from(retain_days).map_err(|_| {
        s3s::s3_error!(
            InvalidRequest,
            "Object Lock retain-until date exceeds the supported range"
        )
    })?;
    Ok(Some(RetentionPolicy::new(mode, retain_days)))
}

pub(super) fn validate_get_object_request(input: &GetObjectInput) -> S3Result<()> {
    if input.part_number.is_some() || input.version_id.is_some() {
        return Err(s3s::s3_error!(
            NotImplemented,
            "part numbers and object versions are not supported"
        ));
    }
    Ok(())
}

pub(super) fn validate_head_object_request(input: &HeadObjectInput) -> S3Result<()> {
    if input.part_number.is_some() || input.version_id.is_some() {
        return Err(s3s::s3_error!(
            NotImplemented,
            "part numbers and object versions are not supported"
        ));
    }
    Ok(())
}

pub(super) fn validate_delete_object_request(input: &DeleteObjectInput) -> S3Result<()> {
    if input.version_id.is_some()
        || input.if_match.is_some()
        || input.if_match_last_modified_time.is_some()
        || input.if_match_size.is_some()
    {
        return Err(s3s::s3_error!(
            NotImplemented,
            "conditional or versioned DeleteObject is not supported"
        ));
    }
    Ok(())
}

pub(super) fn validate_get_object_legal_hold_request(
    input: &GetObjectLegalHoldInput,
) -> S3Result<()> {
    if input.version_id.is_some() {
        return Err(s3s::s3_error!(
            NotImplemented,
            "versioned GetObjectLegalHold is not supported"
        ));
    }
    Ok(())
}

pub(super) fn put_object_legal_hold_request_status(
    input: &PutObjectLegalHoldInput,
) -> S3Result<LegalHoldStatus> {
    if input.version_id.is_some() {
        return Err(s3s::s3_error!(
            NotImplemented,
            "versioned PutObjectLegalHold is not supported"
        ));
    }
    let status = input
        .legal_hold
        .as_ref()
        .and_then(|legal_hold| legal_hold.status.as_ref())
        .ok_or_else(|| s3s::s3_error!(InvalidRequest, "legal hold status is required"))?;
    legal_hold_status(status)
}

pub(super) fn logical_path(key: String) -> S3Result<LogicalPath> {
    LogicalPath::new(key)
        .map_err(|_error| s3s::s3_error!(InvalidRequest, "object key is not valid"))
}

pub(super) fn resolve_range(
    range: Option<s3s::dto::Range>,
    content_len: u64,
) -> S3Result<Option<std::ops::Range<u64>>> {
    range
        .map(|range| range.check(content_len).map_err(Into::into))
        .transpose()
}

pub(super) fn content_range(start: u64, end: u64, full_len: u64) -> String {
    format!("bytes {}-{}/{full_len}", start, end - 1)
}

pub(super) fn list_page(
    entries: Vec<RepositoryListEntry>,
    prefix: &str,
    delimiter: Option<&str>,
    start_after: Option<&str>,
    max_keys: usize,
) -> S3Result<ListPage> {
    let mut items = BTreeMap::new();

    for entry in entries {
        let key = entry.key.as_str();
        if start_after.is_some_and(|start_after| key <= start_after) {
            continue;
        }

        if let Some(delimiter) = delimiter {
            let remainder = key.strip_prefix(prefix).unwrap_or(key);
            if let Some((component, _)) = remainder.split_once(delimiter) {
                let common_prefix = format!("{prefix}{component}{delimiter}");
                if start_after.is_none_or(|start_after| common_prefix.as_str() > start_after) {
                    items.entry(common_prefix.clone()).or_insert_with(|| {
                        ListItem::CommonPrefix(CommonPrefix {
                            prefix: Some(common_prefix),
                        })
                    });
                }
                continue;
            }
        }

        items.insert(
            key.to_owned(),
            ListItem::Object(Box::new(Object {
                key: Some(key.to_owned()),
                last_modified: Some(timestamp(entry.modified_at_ms)?),
                size: Some(i64_len(entry.content_len)?),
                e_tag: Some(etag(entry.content_len, entry.modified_at_ms)),
                ..Object::default()
            })),
        );
    }

    let mut contents = Vec::new();
    let mut common_prefixes = Vec::new();
    let mut last_returned_key = None;
    let mut next_continuation_token = None;
    let mut key_count = 0usize;

    for (key, item) in items {
        if key_count == max_keys {
            next_continuation_token = last_returned_key;
            break;
        }

        match item {
            ListItem::Object(object) => contents.push(*object),
            ListItem::CommonPrefix(prefix) => common_prefixes.push(prefix),
        }
        last_returned_key = Some(key);
        key_count += 1;
    }

    Ok(ListPage {
        contents,
        common_prefixes,
        key_count,
        next_continuation_token,
    })
}

pub(super) fn max_keys(value: Option<i32>) -> S3Result<usize> {
    match value {
        Some(value) if value < 0 => Err(s3s::s3_error!(
            InvalidRequest,
            "max-keys must not be negative"
        )),
        Some(value) => Ok(usize::try_from(value).unwrap_or(usize::MAX).min(1000)),
        None => Ok(1000),
    }
}

pub(super) fn i64_len(value: u64) -> S3Result<i64> {
    i64::try_from(value).map_err(|_| {
        s3s::s3_error!(
            InternalError,
            "object length exceeds the supported S3 response range"
        )
    })
}

pub(super) fn timestamp(modified_at_ms: i64) -> S3Result<Timestamp> {
    let millis = u64::try_from(modified_at_ms).map_err(|_| {
        s3s::s3_error!(
            InternalError,
            "object timestamp is before the supported S3 response range"
        )
    })?;
    let system_time = UNIX_EPOCH
        .checked_add(Duration::from_millis(millis))
        .ok_or_else(|| s3s::s3_error!(InternalError, "object timestamp is out of range"))?;
    Ok(Timestamp::from(system_time))
}

pub(super) fn retention_headers(
    retention: Option<&RetentionPolicy>,
    modified_at_ms: i64,
) -> S3Result<(
    Option<s3s::dto::ObjectLockMode>,
    Option<s3s::dto::ObjectLockRetainUntilDate>,
)> {
    let Some(retention) =
        retention.filter(|policy| policy.mode != RetentionMode::None && policy.retain_days > 0)
    else {
        return Ok((None, None));
    };
    let mode = match retention.mode {
        RetentionMode::Compliance => {
            s3s::dto::ObjectLockMode::from_static(s3s::dto::ObjectLockMode::COMPLIANCE)
        }
        RetentionMode::Governance => {
            s3s::dto::ObjectLockMode::from_static(s3s::dto::ObjectLockMode::GOVERNANCE)
        }
        RetentionMode::None => return Ok((None, None)),
    };
    let retain_ms = i64::from(retention.retain_days)
        .checked_mul(86_400_000)
        .ok_or_else(|| s3s::s3_error!(InternalError, "retention period is out of range"))?;
    let retain_until_ms = modified_at_ms
        .checked_add(retain_ms)
        .ok_or_else(|| s3s::s3_error!(InternalError, "retention timestamp is out of range"))?;
    Ok((Some(mode), Some(timestamp(retain_until_ms)?)))
}

pub(super) fn legal_hold_header(
    status: Option<LegalHoldStatus>,
) -> Option<ObjectLockLegalHoldStatus> {
    status.map(s3_legal_hold_status)
}

pub(super) fn legal_hold_output(status: Option<LegalHoldStatus>) -> ObjectLockLegalHold {
    ObjectLockLegalHold {
        status: Some(s3_legal_hold_status(status.unwrap_or(LegalHoldStatus::Off))),
    }
}

fn legal_hold_status(status: &ObjectLockLegalHoldStatus) -> S3Result<LegalHoldStatus> {
    match status.as_str() {
        ObjectLockLegalHoldStatus::ON => Ok(LegalHoldStatus::On),
        ObjectLockLegalHoldStatus::OFF => Ok(LegalHoldStatus::Off),
        _ => Err(s3s::s3_error!(
            InvalidRequest,
            "Object Lock legal hold status is not supported"
        )),
    }
}

fn s3_legal_hold_status(status: LegalHoldStatus) -> ObjectLockLegalHoldStatus {
    match status {
        LegalHoldStatus::Off => {
            ObjectLockLegalHoldStatus::from_static(ObjectLockLegalHoldStatus::OFF)
        }
        LegalHoldStatus::On => {
            ObjectLockLegalHoldStatus::from_static(ObjectLockLegalHoldStatus::ON)
        }
    }
}

fn timestamp_system_time(timestamp: &Timestamp) -> S3Result<SystemTime> {
    let date_time: time::OffsetDateTime = timestamp.clone().into();
    let seconds = u64::try_from(date_time.unix_timestamp())
        .map_err(|_| s3s::s3_error!(InvalidRequest, "timestamp is outside the supported range"))?;
    UNIX_EPOCH
        .checked_add(Duration::new(seconds, date_time.nanosecond()))
        .ok_or_else(|| s3s::s3_error!(InvalidRequest, "timestamp is out of range"))
}

pub(super) fn etag(content_len: u64, modified_at_ms: i64) -> s3s::dto::ETag {
    s3s::dto::ETag::Strong(format!("rs3-{modified_at_ms:x}-{content_len:x}"))
}

pub(super) fn repository_error(error: RepositoryError) -> s3s::S3Error {
    match error {
        RepositoryError::NotFound(_) => s3s::s3_error!(NoSuchKey),
        RepositoryError::AlreadyExists(_) => s3s::s3_error!(PreconditionFailed),
        RepositoryError::CommitBackpressure => {
            s3s::s3_error!(ServiceUnavailable, "commit coordinator is overloaded")
        }
        RepositoryError::ObjectTooLarge => s3s::s3_error!(
            EntityTooLarge,
            "PutObject body exceeds the configured maximum size"
        ),
        RepositoryError::ObjectLengthMismatch => {
            s3s::s3_error!(
                IncompleteBody,
                "request body length did not match Content-Length"
            )
        }
        RepositoryError::ObjectBodyReadFailed => {
            s3s::s3_error!(IncompleteBody, "failed to read request body")
        }
        RepositoryError::UnsupportedRepositoryFormat { .. } => s3s::s3_error!(
            NotImplemented,
            "repository format is not supported by this operation"
        ),
        RepositoryError::Storage(StorageError::InvalidRange) => s3s::s3_error!(InvalidRange),
        RepositoryError::Storage(StorageError::LegalHoldBlocked) => {
            s3s::s3_error!(AccessDenied, "object legal hold blocked the operation")
        }
        RepositoryError::Storage(StorageError::LegalHoldUnsupported) => {
            s3s::s3_error!(NotImplemented, "Object Lock legal hold is not supported")
        }
        RepositoryError::Storage(StorageError::RetentionBlocked) => {
            s3s::s3_error!(AccessDenied, "object retention blocked the operation")
        }
        RepositoryError::Storage(StorageError::RetentionExtensionUnsupported) => {
            s3s::s3_error!(NotImplemented, "Object Lock retention is not supported")
        }
        RepositoryError::Storage(StorageError::VersionUnsupported) => {
            s3s::s3_error!(NotImplemented, "object version reads are not supported")
        }
        RepositoryError::Storage(StorageError::MultipartUnsupported) => {
            s3s::s3_error!(
                NotImplemented,
                "multipart upload is not supported by this backend"
            )
        }
        RepositoryError::Storage(StorageError::MissingVersionId(_)) => s3s::s3_error!(
            InternalError,
            "retained repository object is missing provider version metadata"
        ),
        RepositoryError::Type(_) => s3s::s3_error!(InvalidRequest, "invalid repository path"),
        RepositoryError::CommitFailed { .. }
        | RepositoryError::SequenceOverflow
        | RepositoryError::StatePoisoned
        | RepositoryError::Crypto(_)
        | RepositoryError::Storage(StorageError::AlreadyExists(_))
        | RepositoryError::Storage(StorageError::NotFound(_))
        | RepositoryError::Storage(StorageError::Provider(_))
        | RepositoryError::CheckpointEncoding(_)
        | RepositoryError::KeyringEnvelopeObjectConflict { .. }
        | RepositoryError::IndexDeltaObjectConflict { .. }
        | RepositoryError::InvalidObjectFormat { .. } => {
            s3s::s3_error!(InternalError, "repository operation failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::list_page;
    use rs3_repository::RepositoryListEntry;
    use rs3_types::LogicalPath;

    fn entry(key: &str) -> RepositoryListEntry {
        RepositoryListEntry {
            key: LogicalPath::new(key).unwrap_or_else(|error| panic!("{error}")),
            content_len: 1,
            modified_at_ms: 1,
        }
    }

    #[test]
    fn list_page_token_continues_after_last_returned_item() {
        let entries = vec![entry("p/a"), entry("p/b"), entry("p/c")];

        let first = list_page(entries.clone(), "p/", None, None, 1)
            .unwrap_or_else(|error| panic!("{error}"));
        let second = list_page(
            entries,
            "p/",
            None,
            first.next_continuation_token.as_deref(),
            1,
        )
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            first
                .contents
                .first()
                .and_then(|object| object.key.as_deref()),
            Some("p/a")
        );
        assert_eq!(first.next_continuation_token.as_deref(), Some("p/a"));
        assert_eq!(
            second
                .contents
                .first()
                .and_then(|object| object.key.as_deref()),
            Some("p/b")
        );
        assert_eq!(second.next_continuation_token.as_deref(), Some("p/b"));
    }

    #[test]
    fn list_page_token_handles_common_prefixes() {
        let entries = vec![entry("p/a/1"), entry("p/b/1"), entry("p/c/1")];

        let first = list_page(entries.clone(), "p/", Some("/"), None, 1)
            .unwrap_or_else(|error| panic!("{error}"));
        let second = list_page(
            entries,
            "p/",
            Some("/"),
            first.next_continuation_token.as_deref(),
            1,
        )
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            first
                .common_prefixes
                .first()
                .and_then(|prefix| prefix.prefix.as_deref()),
            Some("p/a/")
        );
        assert_eq!(first.next_continuation_token.as_deref(), Some("p/a/"));
        assert_eq!(
            second
                .common_prefixes
                .first()
                .and_then(|prefix| prefix.prefix.as_deref()),
            Some("p/b/")
        );
        assert_eq!(second.next_continuation_token.as_deref(), Some("p/b/"));
    }
}
