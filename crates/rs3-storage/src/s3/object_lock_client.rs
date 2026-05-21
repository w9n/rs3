use super::S3BlobStore;
use super::errors::{
    backend_version_id_from_str, map_sdk_common_error, map_sdk_put_error, provider_error,
};
use super::object_lock::{
    legal_hold_from_s3_head, legal_hold_from_s3_legal_hold, retain_until_date,
    retain_until_ms_from_s3_head, retention_from_s3_head, retention_is_active,
    retention_mode_label, retention_satisfies, sdk_legal_hold_status, sdk_object_lock_mode,
    sdk_object_lock_retention_mode, verify_legal_hold, verify_retention,
};
use crate::{BlobMetadata, PutOptions, Result, StorageError};
use aws_sdk_s3::primitives::ByteStream as SdkByteStream;
use aws_sdk_s3::types::{
    BucketVersioningStatus, ChecksumAlgorithm, ObjectLockEnabled, ObjectLockLegalHold,
    ObjectLockRetention,
};
use bytes::Bytes;
use rs3_types::{BackendObjectId, BackendVersionId, LegalHoldStatus, RetentionPolicy};

impl S3BlobStore {
    /// Validates that the configured bucket can enforce S3 Object Lock retention.
    ///
    /// This is intended for startup checks when repository-level retention is
    /// enabled. It fails closed if the direct S3 SDK client is unavailable, if
    /// bucket versioning is not enabled, or if Object Lock is not enabled.
    pub async fn validate_retention_support(
        &self,
        retention: Option<&RetentionPolicy>,
    ) -> Result<()> {
        let Some(retention) = retention.filter(|policy| retention_is_active(policy)) else {
            return Ok(());
        };
        let client = self
            .sdk_client
            .as_ref()
            .ok_or(StorageError::RetentionExtensionUnsupported)?;

        let versioning = client
            .get_bucket_versioning()
            .bucket(self.config.bucket.as_str())
            .send()
            .await
            .map_err(|error| {
                StorageError::Provider(format!("failed to read S3 bucket versioning: {error}"))
            })?;
        if versioning
            .status()
            .is_none_or(|status| status != &BucketVersioningStatus::Enabled)
        {
            return Err(StorageError::Provider(
                "S3 Object Lock retention requires bucket versioning to be Enabled".to_owned(),
            ));
        }

        let object_lock = client
            .get_object_lock_configuration()
            .bucket(self.config.bucket.as_str())
            .send()
            .await
            .map_err(|error| {
                StorageError::Provider(format!(
                    "failed to read S3 Object Lock configuration: {error}"
                ))
            })?;
        let object_lock_enabled = object_lock
            .object_lock_configuration()
            .and_then(|configuration| configuration.object_lock_enabled())
            .is_some_and(|enabled| enabled == &ObjectLockEnabled::Enabled);
        if !object_lock_enabled {
            return Err(StorageError::Provider(
                "S3 Object Lock retention requires bucket Object Lock to be Enabled".to_owned(),
            ));
        }

        tracing::info!(
            target: "rs3_storage",
            provider = "s3",
            retention_mode = retention_mode_label(retention.mode),
            retention_days = retention.retain_days,
            "S3 Object Lock retention support validated",
        );
        Ok(())
    }

    pub(super) async fn put_object_lock_object(
        &self,
        object_id: &BackendObjectId,
        body: Bytes,
        options: &PutOptions,
        retention: Option<&RetentionPolicy>,
        legal_hold: Option<LegalHoldStatus>,
    ) -> Result<BlobMetadata> {
        let client = self.sdk_client.as_ref().ok_or_else(|| {
            if retention.is_some() {
                StorageError::RetentionExtensionUnsupported
            } else {
                StorageError::LegalHoldUnsupported
            }
        })?;
        let key = self.config.object_key(object_id);
        let content_len = u64::try_from(body.len())
            .map_err(|_| StorageError::Provider("object length does not fit in u64".to_owned()))?;
        let mut request = client
            .put_object()
            .bucket(self.config.bucket.as_str())
            .key(key)
            .body(SdkByteStream::from(body))
            .checksum_algorithm(ChecksumAlgorithm::Sha256);

        if let Some(retention) = retention {
            request = request
                .object_lock_mode(sdk_object_lock_mode(retention)?)
                .object_lock_retain_until_date(retain_until_date(retention)?);
        }
        if let Some(legal_hold) = legal_hold {
            request = request.object_lock_legal_hold_status(sdk_legal_hold_status(legal_hold));
        }

        if options.do_not_recreate {
            request = request.if_none_match("*");
        }
        if let Some(content_type) = options.content_type.as_deref() {
            request = request.content_type(content_type);
        }

        let output = request
            .send()
            .await
            .map_err(|error| map_sdk_put_error(error, object_id))?;
        let version_id = output
            .version_id()
            .map(backend_version_id_from_str)
            .transpose()?;
        let mut metadata = self.head_with_sdk(object_id, version_id.as_ref()).await?;
        if let Some(retention) = retention {
            verify_retention(metadata.retention.as_ref(), retention)?;
        }
        if let Some(legal_hold) = legal_hold {
            verify_legal_hold(metadata.legal_hold, legal_hold)?;
        }
        metadata.content_len = content_len;
        metadata.etag = output.e_tag().map(str::to_owned).or(metadata.etag);
        metadata.version_id = version_id.or(metadata.version_id);
        Ok(metadata)
    }

    pub(super) async fn head_with_sdk(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
    ) -> Result<BlobMetadata> {
        let client = self
            .sdk_client
            .as_ref()
            .ok_or(StorageError::RetentionExtensionUnsupported)?;
        let mut request = client
            .head_object()
            .bucket(self.config.bucket.as_str())
            .key(self.config.object_key(object_id));
        if let Some(version_id) = version_id {
            request = request.version_id(version_id.as_str());
        }

        let output = request
            .send()
            .await
            .map_err(|error| map_sdk_common_error(error, object_id))?;
        let content_len = output
            .content_length()
            .ok_or_else(|| StorageError::Provider("S3 HEAD omitted content length".to_owned()))
            .and_then(|content_len| {
                u64::try_from(content_len).map_err(|_| {
                    StorageError::Provider("S3 HEAD returned negative content length".to_owned())
                })
            })?;
        let modified_at_ms = output
            .last_modified()
            .map(|modified_at| modified_at.to_millis())
            .transpose()
            .map_err(provider_error)?;
        let retention = retention_from_s3_head(
            output.object_lock_mode(),
            output.object_lock_retain_until_date(),
        )?;
        let retain_until_ms = retain_until_ms_from_s3_head(output.object_lock_retain_until_date())?;
        let legal_hold = legal_hold_from_s3_head(output.object_lock_legal_hold_status())?;

        Ok(BlobMetadata {
            object_id: object_id.clone(),
            content_len,
            modified_at_ms,
            etag: output.e_tag().map(str::to_owned),
            version_id: output
                .version_id()
                .map(backend_version_id_from_str)
                .transpose()?,
            retention,
            retain_until_ms,
            legal_hold,
        })
    }

    pub(super) async fn extend_s3_retention(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        policy: &RetentionPolicy,
    ) -> Result<()> {
        if !retention_is_active(policy) {
            return Ok(());
        }
        let client = self
            .sdk_client
            .as_ref()
            .ok_or(StorageError::RetentionExtensionUnsupported)?;
        let existing = self.head_with_sdk(object_id, version_id).await?;
        if retention_satisfies(existing.retention.as_ref(), policy) {
            return Ok(());
        }

        let retention = ObjectLockRetention::builder()
            .mode(sdk_object_lock_retention_mode(policy)?)
            .retain_until_date(retain_until_date(policy)?)
            .build();
        let mut request = client
            .put_object_retention()
            .bucket(self.config.bucket.as_str())
            .key(self.config.object_key(object_id))
            .retention(retention)
            .checksum_algorithm(ChecksumAlgorithm::Sha256);
        if let Some(version_id) = version_id {
            request = request.version_id(version_id.as_str());
        }
        request
            .send()
            .await
            .map_err(|error| map_sdk_common_error(error, object_id))?;

        let verified = self.head_with_sdk(object_id, version_id).await?;
        verify_retention(verified.retention.as_ref(), policy)
    }

    pub(super) async fn set_s3_legal_hold(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        status: LegalHoldStatus,
    ) -> Result<()> {
        let client = self
            .sdk_client
            .as_ref()
            .ok_or(StorageError::LegalHoldUnsupported)?;
        let legal_hold = ObjectLockLegalHold::builder()
            .status(sdk_legal_hold_status(status))
            .build();
        let mut request = client
            .put_object_legal_hold()
            .bucket(self.config.bucket.as_str())
            .key(self.config.object_key(object_id))
            .legal_hold(legal_hold)
            .checksum_algorithm(ChecksumAlgorithm::Sha256);
        if let Some(version_id) = version_id {
            request = request.version_id(version_id.as_str());
        }
        request
            .send()
            .await
            .map_err(|error| map_sdk_common_error(error, object_id))?;

        let mut request = client
            .get_object_legal_hold()
            .bucket(self.config.bucket.as_str())
            .key(self.config.object_key(object_id));
        if let Some(version_id) = version_id {
            request = request.version_id(version_id.as_str());
        }
        let verified = request
            .send()
            .await
            .map_err(|error| map_sdk_common_error(error, object_id))?;
        verify_legal_hold(
            legal_hold_from_s3_legal_hold(verified.legal_hold())?,
            status,
        )
    }
}
