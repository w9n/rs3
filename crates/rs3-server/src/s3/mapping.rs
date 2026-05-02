//! Request and response mapping helpers for S3 object operations.

use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use rs3_repository::{RepositoryError, RepositoryListEntry};
use rs3_storage::StorageError;
use rs3_types::LogicalPath;
use s3s::S3Result;
use s3s::dto::{
    CommonPrefix, DeleteObjectInput, GetObjectInput, HeadObjectInput, Object, PutObjectInput,
    StreamingBlob, Timestamp,
};
use std::collections::BTreeMap;
use std::time::{Duration, UNIX_EPOCH};

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

pub(super) async fn collect_body(body: Option<StreamingBlob>) -> S3Result<Bytes> {
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
        bytes.extend_from_slice(&chunk);
    }

    Ok(bytes.freeze())
}

pub(super) fn validate_put_object_request(input: &PutObjectInput) -> S3Result<()> {
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
    if input.object_lock_mode.is_some()
        || input.object_lock_retain_until_date.is_some()
        || input.object_lock_legal_hold_status.is_some()
    {
        return Err(s3s::s3_error!(
            NotImplemented,
            "per-object lock headers are not mapped by this adapter"
        ));
    }
    Ok(())
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
    let mut next_continuation_token = None;
    let mut key_count = 0usize;

    for (key, item) in items {
        if key_count == max_keys {
            next_continuation_token = Some(key);
            break;
        }

        match item {
            ListItem::Object(object) => contents.push(*object),
            ListItem::CommonPrefix(prefix) => common_prefixes.push(prefix),
        }
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
        RepositoryError::Storage(StorageError::InvalidRange) => s3s::s3_error!(InvalidRange),
        RepositoryError::Type(_) => s3s::s3_error!(InvalidRequest, "invalid repository path"),
        RepositoryError::CommitFailed { .. }
        | RepositoryError::SequenceOverflow
        | RepositoryError::StatePoisoned
        | RepositoryError::Crypto(_)
        | RepositoryError::Storage(_)
        | RepositoryError::Anchor(_)
        | RepositoryError::CheckpointEncoding(_)
        | RepositoryError::CheckpointIdMismatch
        | RepositoryError::StaleCheckpoint { .. }
        | RepositoryError::CheckpointConflict { .. }
        | RepositoryError::CheckpointObjectConflict { .. }
        | RepositoryError::IndexDeltaObjectConflict { .. }
        | RepositoryError::InvalidObjectFormat { .. }
        | RepositoryError::CheckpointParentMismatch => {
            s3s::s3_error!(InternalError, "repository operation failed")
        }
    }
}
