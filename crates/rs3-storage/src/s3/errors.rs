use crate::{BlobMetadata, Result, StorageError};
use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use object_store::ObjectMeta;
use rs3_types::{BackendObjectId, BackendVersionId};

pub(super) fn storage_error_result(error: &StorageError) -> &'static str {
    match error {
        StorageError::AlreadyExists(_) => "already_exists",
        StorageError::NotFound(_) => "not_found",
        StorageError::InvalidRange => "invalid_range",
        StorageError::RetentionBlocked => "retention_blocked",
        StorageError::RetentionExtensionUnsupported => "retention_unsupported",
        StorageError::VersionUnsupported => "version_unsupported",
        StorageError::MissingVersionId(_) => "missing_version_id",
        StorageError::LegalHoldBlocked => "legal_hold_blocked",
        StorageError::LegalHoldUnsupported => "legal_hold_unsupported",
        StorageError::MultipartUnsupported => "multipart_unsupported",
        StorageError::Provider(_) => "error",
    }
}

pub(super) fn metadata_from_object_meta(
    object_id: BackendObjectId,
    metadata: ObjectMeta,
) -> Result<BlobMetadata> {
    Ok(BlobMetadata {
        object_id,
        content_len: metadata.size,
        modified_at_ms: Some(metadata.last_modified.timestamp_millis()),
        etag: metadata.e_tag,
        version_id: metadata
            .version
            .map(backend_version_id_from_string)
            .transpose()?,
        retention: None,
        retain_until_ms: None,
        legal_hold: None,
    })
}

pub(super) fn backend_version_id_from_string(value: String) -> Result<BackendVersionId> {
    BackendVersionId::new(value).map_err(|error| StorageError::Provider(error.to_string()))
}

pub(super) fn backend_version_id_from_str(value: &str) -> Result<BackendVersionId> {
    backend_version_id_from_string(value.to_owned())
}

pub(super) fn put_error_result(error: &object_store::Error) -> &'static str {
    match error {
        object_store::Error::AlreadyExists { .. }
        | object_store::Error::Precondition { .. }
        | object_store::Error::NotModified { .. } => "already_exists",
        object_store::Error::NotFound { .. } => "not_found",
        _ => "error",
    }
}

pub(super) fn get_error_result(error: &object_store::Error) -> &'static str {
    match error {
        object_store::Error::NotFound { .. } => "not_found",
        _ => "error",
    }
}

pub(super) fn common_error_result(error: &object_store::Error) -> &'static str {
    match error {
        object_store::Error::NotFound { .. } => "not_found",
        _ => "error",
    }
}

pub(super) fn map_put_error(
    error: object_store::Error,
    object_id: &BackendObjectId,
) -> StorageError {
    match error {
        object_store::Error::AlreadyExists { .. }
        | object_store::Error::Precondition { .. }
        | object_store::Error::NotModified { .. } => StorageError::AlreadyExists(object_id.clone()),
        object_store::Error::NotFound { .. } => StorageError::NotFound(object_id.clone()),
        _ => provider_error(error),
    }
}

pub(super) fn map_get_error(
    error: object_store::Error,
    object_id: &BackendObjectId,
) -> StorageError {
    match error {
        object_store::Error::NotFound { .. } => StorageError::NotFound(object_id.clone()),
        _ => provider_error(error),
    }
}

pub(super) fn map_common_error(
    error: object_store::Error,
    object_id: &BackendObjectId,
) -> StorageError {
    match error {
        object_store::Error::NotFound { .. } => StorageError::NotFound(object_id.clone()),
        _ => provider_error(error),
    }
}

pub(super) fn map_sdk_put_error<E, R>(
    error: SdkError<E, R>,
    object_id: &BackendObjectId,
) -> StorageError
where
    E: ProvideErrorMetadata,
    SdkError<E, R>: std::fmt::Display,
{
    match sdk_error_code(&error) {
        Some("PreconditionFailed" | "ConditionalRequestConflict") => {
            StorageError::AlreadyExists(object_id.clone())
        }
        Some("NoSuchKey" | "NotFound") => StorageError::NotFound(object_id.clone()),
        _ => StorageError::Provider(error.to_string()),
    }
}

pub(super) fn map_sdk_common_error<E, R>(
    error: SdkError<E, R>,
    object_id: &BackendObjectId,
) -> StorageError
where
    E: ProvideErrorMetadata,
    SdkError<E, R>: std::fmt::Display,
{
    match sdk_error_code(&error) {
        Some("NoSuchKey" | "NotFound") => StorageError::NotFound(object_id.clone()),
        _ => StorageError::Provider(error.to_string()),
    }
}

fn sdk_error_code<E, R>(error: &SdkError<E, R>) -> Option<&str>
where
    E: ProvideErrorMetadata,
{
    error
        .as_service_error()
        .and_then(ProvideErrorMetadata::code)
}

pub(super) fn provider_error(error: impl std::error::Error) -> StorageError {
    StorageError::Provider(error.to_string())
}
