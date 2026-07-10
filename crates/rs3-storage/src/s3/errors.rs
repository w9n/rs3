use crate::{Result, StorageError};
use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
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

pub(super) fn backend_version_id_from_string(value: String) -> Result<BackendVersionId> {
    BackendVersionId::new(value).map_err(|error| StorageError::Provider(error.to_string()))
}

pub(super) fn backend_version_id_from_str(value: &str) -> Result<BackendVersionId> {
    backend_version_id_from_string(value.to_owned())
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

pub(super) fn map_sdk_get_error<E, R>(
    error: SdkError<E, R>,
    object_id: &BackendObjectId,
) -> StorageError
where
    E: ProvideErrorMetadata,
    SdkError<E, R>: std::fmt::Display,
{
    match sdk_error_code(&error) {
        Some("InvalidRange" | "RequestedRangeNotSatisfiable") => StorageError::InvalidRange,
        Some("NoSuchKey" | "NoSuchVersion" | "NotFound") => {
            StorageError::NotFound(object_id.clone())
        }
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
        Some("NoSuchKey" | "NoSuchVersion" | "NotFound") => {
            StorageError::NotFound(object_id.clone())
        }
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
