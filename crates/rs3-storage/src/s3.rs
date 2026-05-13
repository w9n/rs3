//! S3-compatible `BlobStore` implementation.

use crate::{
    BlobMetadata, BlobStore, ByteRange, PutOptions, Result, StorageError, object_kind, prefix_kind,
    record_blob_delete, record_blob_extend_retention, record_blob_get, record_blob_head,
    record_blob_list, record_blob_put, record_blob_set_legal_hold,
};
use async_trait::async_trait;
use aws_sdk_s3::Client as SdkS3Client;
use bytes::Bytes;
use object_store::aws::AmazonS3;
use object_store::list::{PaginatedListOptions, PaginatedListStore};
use object_store::path::Path as ObjectPath;
use object_store::{ObjectStore, ObjectStoreExt};
use rs3_types::{BackendObjectId, BackendVersionId, LegalHoldStatus, RetentionPolicy};
use std::sync::{Arc, RwLock};
use std::time::Instant;

mod client;
mod config;
mod errors;
mod metrics;
mod object_lock;
mod object_lock_client;
mod requests;

pub use config::S3BlobStoreConfig;
pub use metrics::{S3ProviderMetrics, S3ProviderOperationMetrics};

use client::{
    install_rustls_provider, object_store_from_environment, sdk_client_from_environment,
    sdk_client_from_static_environment,
};
use errors::{
    backend_version_id_from_string, common_error_result, get_error_result, map_common_error,
    map_get_error, map_put_error, map_sdk_common_error, metadata_from_object_meta, provider_error,
    put_error_result, storage_error_result,
};
use metrics::S3ProviderOperation;
use object_lock::{
    legal_hold_blocks_delete, provider_legal_hold, retention_blocks_delete, retention_is_active,
};
use requests::{object_get_options, object_path, object_put_options, sdk_range_header};

/// S3-compatible `BlobStore` backed by the Apache Arrow `object_store` crate.
#[derive(Clone, Debug)]
pub struct S3BlobStore {
    store: AmazonS3,
    sdk_client: Option<SdkS3Client>,
    config: S3BlobStoreConfig,
    metrics: Arc<RwLock<S3ProviderMetrics>>,
}

impl S3BlobStore {
    /// Builds an S3 store from the supported AWS environment/config chain.
    ///
    /// # Errors
    ///
    /// Returns a provider error when configuration cannot be constructed.
    pub async fn from_environment(config: S3BlobStoreConfig) -> Result<Self> {
        install_rustls_provider();
        let store = object_store_from_environment(&config)?;
        let sdk_client = Some(sdk_client_from_environment(&config).await?);
        Ok(Self {
            store,
            sdk_client,
            config,
            metrics: Arc::new(RwLock::new(S3ProviderMetrics::default())),
        })
    }

    /// Builds an S3 store synchronously from environment credentials.
    ///
    /// This path only wires the direct SDK retention client when static
    /// `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` values are present. Use
    /// [`Self::from_environment`] for the full AWS provider chain.
    ///
    /// # Errors
    ///
    /// Returns a provider error when configuration cannot be constructed.
    pub fn from_environment_sync(config: S3BlobStoreConfig) -> Result<Self> {
        install_rustls_provider();
        let store = object_store_from_environment(&config)?;
        let sdk_client = sdk_client_from_static_environment(&config)?;
        Ok(Self {
            store,
            sdk_client,
            config,
            metrics: Arc::new(RwLock::new(S3ProviderMetrics::default())),
        })
    }

    /// Builds an S3 blob store from an existing `object_store` S3 client.
    pub fn from_store(store: AmazonS3, config: S3BlobStoreConfig) -> Self {
        Self {
            store,
            sdk_client: None,
            config,
            metrics: Arc::new(RwLock::new(S3ProviderMetrics::default())),
        }
    }

    /// Returns the configured backend bucket.
    pub fn bucket(&self) -> &str {
        &self.config.bucket
    }

    /// Returns a snapshot of S3 provider metrics.
    pub fn provider_metrics(&self) -> Result<S3ProviderMetrics> {
        self.metrics
            .read()
            .map(|metrics| metrics.clone())
            .map_err(|_| StorageError::Provider("S3 metrics lock poisoned".to_owned()))
    }

    /// Resets S3 provider metrics without changing stored objects.
    pub fn reset_provider_metrics(&self) -> Result<()> {
        let mut metrics = self
            .metrics
            .write()
            .map_err(|_| StorageError::Provider("S3 metrics lock poisoned".to_owned()))?;
        *metrics = S3ProviderMetrics::default();
        Ok(())
    }

    fn object_path(&self, object_id: &BackendObjectId) -> Result<ObjectPath> {
        object_path(&self.config.object_key(object_id))
    }
}

#[async_trait]
impl BlobStore for S3BlobStore {
    async fn put(
        &self,
        object_id: &BackendObjectId,
        body: Bytes,
        options: PutOptions,
    ) -> Result<BlobMetadata> {
        let started = Instant::now();
        let object_kind = object_kind(object_id);
        let requested_len = body.len();
        let bytes_sent = u64::try_from(requested_len)
            .map_err(|_| StorageError::Provider("object length does not fit in u64".to_owned()))?;

        let retention = options
            .retention
            .as_ref()
            .filter(|policy| retention_is_active(policy));
        let legal_hold = provider_legal_hold(options.legal_hold);
        if retention.is_some() || legal_hold.is_some() {
            let result = self
                .put_object_lock_object(object_id, body, &options, retention, legal_hold)
                .await;
            let result_label = match &result {
                Ok(_) => "ok",
                Err(error) => storage_error_result(error),
            };
            self.record_provider_operation(
                S3ProviderOperation::Put,
                object_kind,
                result_label,
                bytes_sent,
                0,
                started.elapsed(),
            )?;
            record_blob_put(
                object_kind,
                requested_len,
                true,
                result_label,
                started.elapsed(),
            );
            return result;
        }

        let path = self.object_path(object_id)?;
        let request_options = object_put_options(&options);
        match self
            .store
            .put_opts(&path, body.into(), request_options)
            .await
        {
            Ok(output) => {
                self.record_provider_operation(
                    S3ProviderOperation::Put,
                    object_kind,
                    "ok",
                    bytes_sent,
                    0,
                    started.elapsed(),
                )?;
                record_blob_put(object_kind, requested_len, false, "ok", started.elapsed());
                Ok(BlobMetadata {
                    object_id: object_id.clone(),
                    content_len: bytes_sent,
                    modified_at_ms: None,
                    etag: output.e_tag,
                    version_id: output
                        .version
                        .map(backend_version_id_from_string)
                        .transpose()?,
                    retention: None,
                    legal_hold: None,
                })
            }
            Err(error) => {
                let result = put_error_result(&error);
                self.record_provider_operation(
                    S3ProviderOperation::Put,
                    object_kind,
                    result,
                    bytes_sent,
                    0,
                    started.elapsed(),
                )?;
                record_blob_put(object_kind, requested_len, false, result, started.elapsed());
                Err(map_put_error(error, object_id))
            }
        }
    }

    async fn get_range(&self, object_id: &BackendObjectId, range: ByteRange) -> Result<Bytes> {
        let started = Instant::now();
        let object_kind = object_kind(object_id);
        let path = self.object_path(object_id)?;

        if let ByteRange::Slice { offset, len: 0 } = range {
            let metadata = match self.store.head(&path).await {
                Ok(metadata) => metadata,
                Err(error) => {
                    let result = common_error_result(&error);
                    self.record_provider_operation(
                        S3ProviderOperation::Head,
                        object_kind,
                        result,
                        0,
                        0,
                        started.elapsed(),
                    )?;
                    record_blob_get(object_kind, range, 0, result, started.elapsed());
                    return Err(map_common_error(error, object_id));
                }
            };
            if offset > metadata.size {
                self.record_provider_operation(
                    S3ProviderOperation::Head,
                    object_kind,
                    "invalid_range",
                    0,
                    0,
                    started.elapsed(),
                )?;
                record_blob_get(object_kind, range, 0, "invalid_range", started.elapsed());
                return Err(StorageError::InvalidRange);
            }
            self.record_provider_operation(
                S3ProviderOperation::Head,
                object_kind,
                "ok",
                0,
                0,
                started.elapsed(),
            )?;
            record_blob_get(object_kind, range, 0, "ok", started.elapsed());
            return Ok(Bytes::new());
        }

        let request_options = object_get_options(range)?;
        match self.store.get_opts(&path, request_options).await {
            Ok(output) => {
                let body = output.bytes().await.map_err(provider_error)?;
                let bytes_read = u64::try_from(body.len()).map_err(|_| {
                    StorageError::Provider("read length does not fit in u64".to_owned())
                })?;
                self.record_provider_operation(
                    S3ProviderOperation::Get,
                    object_kind,
                    "ok",
                    0,
                    bytes_read,
                    started.elapsed(),
                )?;
                record_blob_get(object_kind, range, bytes_read, "ok", started.elapsed());
                Ok(body)
            }
            Err(error) => {
                let result = get_error_result(&error);
                self.record_provider_operation(
                    S3ProviderOperation::Get,
                    object_kind,
                    result,
                    0,
                    0,
                    started.elapsed(),
                )?;
                record_blob_get(object_kind, range, 0, result, started.elapsed());
                Err(map_get_error(error, object_id))
            }
        }
    }

    async fn get_range_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        range: ByteRange,
    ) -> Result<Bytes> {
        let Some(version_id) = version_id else {
            return self.get_range(object_id, range).await;
        };

        let started = Instant::now();
        let object_kind = object_kind(object_id);
        let client = self
            .sdk_client
            .as_ref()
            .ok_or(StorageError::VersionUnsupported)?;

        if let ByteRange::Slice { offset, len: 0 } = range {
            let metadata = self.head_with_sdk(object_id, Some(version_id)).await?;
            if offset > metadata.content_len {
                self.record_provider_operation(
                    S3ProviderOperation::Head,
                    object_kind,
                    "invalid_range",
                    0,
                    0,
                    started.elapsed(),
                )?;
                record_blob_get(object_kind, range, 0, "invalid_range", started.elapsed());
                return Err(StorageError::InvalidRange);
            }
            self.record_provider_operation(
                S3ProviderOperation::Head,
                object_kind,
                "ok",
                0,
                0,
                started.elapsed(),
            )?;
            record_blob_get(object_kind, range, 0, "ok", started.elapsed());
            return Ok(Bytes::new());
        }

        let mut request = client
            .get_object()
            .bucket(self.config.bucket.as_str())
            .key(self.config.object_key(object_id))
            .version_id(version_id.as_str());
        if let Some(range_header) = sdk_range_header(range)? {
            request = request.range(range_header);
        }

        match request.send().await {
            Ok(output) => {
                let body = output
                    .body
                    .collect()
                    .await
                    .map_err(provider_error)?
                    .into_bytes();
                let bytes_read = u64::try_from(body.len()).map_err(|_| {
                    StorageError::Provider("read length does not fit in u64".to_owned())
                })?;
                self.record_provider_operation(
                    S3ProviderOperation::Get,
                    object_kind,
                    "ok",
                    0,
                    bytes_read,
                    started.elapsed(),
                )?;
                record_blob_get(object_kind, range, bytes_read, "ok", started.elapsed());
                Ok(body)
            }
            Err(error) => {
                let storage_error = map_sdk_common_error(error, object_id);
                let result = storage_error_result(&storage_error);
                self.record_provider_operation(
                    S3ProviderOperation::Get,
                    object_kind,
                    result,
                    0,
                    0,
                    started.elapsed(),
                )?;
                record_blob_get(object_kind, range, 0, result, started.elapsed());
                Err(storage_error)
            }
        }
    }

    async fn head(&self, object_id: &BackendObjectId) -> Result<BlobMetadata> {
        let started = Instant::now();
        let object_kind = object_kind(object_id);

        if self.sdk_client.is_some() {
            let result = self.head_with_sdk(object_id, None).await;
            let result_label = match &result {
                Ok(_) => "ok",
                Err(error) => storage_error_result(error),
            };
            self.record_provider_operation(
                S3ProviderOperation::Head,
                object_kind,
                result_label,
                0,
                0,
                started.elapsed(),
            )?;
            record_blob_head(object_kind, result_label, started.elapsed());
            return result;
        }

        let path = self.object_path(object_id)?;

        match self.store.head(&path).await {
            Ok(metadata) => {
                self.record_provider_operation(
                    S3ProviderOperation::Head,
                    object_kind,
                    "ok",
                    0,
                    0,
                    started.elapsed(),
                )?;
                record_blob_head(object_kind, "ok", started.elapsed());
                metadata_from_object_meta(object_id.clone(), metadata)
            }
            Err(error) => {
                let result = common_error_result(&error);
                self.record_provider_operation(
                    S3ProviderOperation::Head,
                    object_kind,
                    result,
                    0,
                    0,
                    started.elapsed(),
                )?;
                record_blob_head(object_kind, result, started.elapsed());
                Err(map_common_error(error, object_id))
            }
        }
    }

    async fn head_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
    ) -> Result<BlobMetadata> {
        let Some(version_id) = version_id else {
            return self.head(object_id).await;
        };

        let started = Instant::now();
        let object_kind = object_kind(object_id);
        let result = self.head_with_sdk(object_id, Some(version_id)).await;
        let result_label = match &result {
            Ok(_) => "ok",
            Err(error) => storage_error_result(error),
        };
        self.record_provider_operation(
            S3ProviderOperation::Head,
            object_kind,
            result_label,
            0,
            0,
            started.elapsed(),
        )?;
        record_blob_head(object_kind, result_label, started.elapsed());
        result
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<BlobMetadata>> {
        let started = Instant::now();
        let object_kind = prefix_kind(prefix);
        let key_prefix = self.config.list_key_prefix(prefix);
        let list_prefix = if key_prefix.is_empty() {
            None
        } else {
            Some(key_prefix.as_str())
        };
        let mut options = PaginatedListOptions::default();
        let mut entries = Vec::new();

        loop {
            match self
                .store
                .list_paginated(list_prefix, options.clone())
                .await
            {
                Ok(page) => {
                    self.record_provider_operation(
                        S3ProviderOperation::List,
                        object_kind,
                        "ok",
                        0,
                        0,
                        started.elapsed(),
                    )?;
                    for object in page.result.objects {
                        let Some(object_id) =
                            self.config.object_id_from_key(object.location.as_ref())?
                        else {
                            continue;
                        };
                        entries.push(metadata_from_object_meta(object_id, object)?);
                    }

                    let Some(page_token) = page.page_token else {
                        break;
                    };
                    options.page_token = Some(page_token);
                }
                Err(error) => {
                    let result = common_error_result(&error);
                    self.record_provider_operation(
                        S3ProviderOperation::List,
                        object_kind,
                        result,
                        0,
                        0,
                        started.elapsed(),
                    )?;
                    record_blob_list(object_kind, entries.len(), result, started.elapsed());
                    return Err(provider_error(error));
                }
            }
        }

        entries.sort_by(|left, right| left.object_id.cmp(&right.object_id));
        record_blob_list(object_kind, entries.len(), "ok", started.elapsed());
        Ok(entries)
    }

    async fn delete(&self, object_id: &BackendObjectId) -> Result<()> {
        let started = Instant::now();
        let object_kind = object_kind(object_id);
        let path = self.object_path(object_id)?;

        if self.sdk_client.is_some() {
            match self.head_with_sdk(object_id, None).await {
                Ok(metadata) if retention_blocks_delete(metadata.retention.as_ref()) => {
                    self.record_provider_operation(
                        S3ProviderOperation::Head,
                        object_kind,
                        "retention_blocked",
                        0,
                        0,
                        started.elapsed(),
                    )?;
                    record_blob_delete(object_kind, "retention_blocked", started.elapsed());
                    return Err(StorageError::RetentionBlocked);
                }
                Ok(metadata) if legal_hold_blocks_delete(metadata.legal_hold) => {
                    self.record_provider_operation(
                        S3ProviderOperation::Head,
                        object_kind,
                        "legal_hold_blocked",
                        0,
                        0,
                        started.elapsed(),
                    )?;
                    record_blob_delete(object_kind, "legal_hold_blocked", started.elapsed());
                    return Err(StorageError::LegalHoldBlocked);
                }
                Ok(_) => {
                    self.record_provider_operation(
                        S3ProviderOperation::Head,
                        object_kind,
                        "ok",
                        0,
                        0,
                        started.elapsed(),
                    )?;
                }
                Err(error) => {
                    let result = storage_error_result(&error);
                    self.record_provider_operation(
                        S3ProviderOperation::Head,
                        object_kind,
                        result,
                        0,
                        0,
                        started.elapsed(),
                    )?;
                    record_blob_delete(object_kind, result, started.elapsed());
                    return Err(error);
                }
            }
        } else {
            match self.store.head(&path).await {
                Ok(_) => {
                    self.record_provider_operation(
                        S3ProviderOperation::Head,
                        object_kind,
                        "ok",
                        0,
                        0,
                        started.elapsed(),
                    )?;
                }
                Err(error) => {
                    let result = common_error_result(&error);
                    self.record_provider_operation(
                        S3ProviderOperation::Head,
                        object_kind,
                        result,
                        0,
                        0,
                        started.elapsed(),
                    )?;
                    record_blob_delete(object_kind, result, started.elapsed());
                    return Err(map_common_error(error, object_id));
                }
            }
        }

        match self.store.delete(&path).await {
            Ok(()) => {
                self.record_provider_operation(
                    S3ProviderOperation::Delete,
                    object_kind,
                    "ok",
                    0,
                    0,
                    started.elapsed(),
                )?;
                record_blob_delete(object_kind, "ok", started.elapsed());
                Ok(())
            }
            Err(error) => {
                let result = common_error_result(&error);
                self.record_provider_operation(
                    S3ProviderOperation::Delete,
                    object_kind,
                    result,
                    0,
                    0,
                    started.elapsed(),
                )?;
                record_blob_delete(object_kind, result, started.elapsed());
                Err(map_common_error(error, object_id))
            }
        }
    }

    async fn extend_retention(
        &self,
        object_id: &BackendObjectId,
        policy: RetentionPolicy,
    ) -> Result<()> {
        let started = Instant::now();
        let object_kind = object_kind(object_id);
        let result = self.extend_s3_retention(object_id, None, &policy).await;
        let result_label = match &result {
            Ok(()) => "ok",
            Err(error) => storage_error_result(error),
        };
        self.record_provider_operation(
            S3ProviderOperation::ExtendRetention,
            object_kind,
            result_label,
            0,
            0,
            started.elapsed(),
        )?;
        record_blob_extend_retention(object_kind, result_label, started.elapsed());
        result
    }

    async fn extend_retention_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        policy: RetentionPolicy,
    ) -> Result<()> {
        let started = Instant::now();
        let object_kind = object_kind(object_id);
        let result = self
            .extend_s3_retention(object_id, version_id, &policy)
            .await;
        let result_label = match &result {
            Ok(()) => "ok",
            Err(error) => storage_error_result(error),
        };
        self.record_provider_operation(
            S3ProviderOperation::ExtendRetention,
            object_kind,
            result_label,
            0,
            0,
            started.elapsed(),
        )?;
        record_blob_extend_retention(object_kind, result_label, started.elapsed());
        result
    }

    async fn set_legal_hold(
        &self,
        object_id: &BackendObjectId,
        status: LegalHoldStatus,
    ) -> Result<()> {
        let started = Instant::now();
        let object_kind = object_kind(object_id);
        let result = self.set_s3_legal_hold(object_id, None, status).await;
        let result_label = match &result {
            Ok(()) => "ok",
            Err(error) => storage_error_result(error),
        };
        self.record_provider_operation(
            S3ProviderOperation::SetLegalHold,
            object_kind,
            result_label,
            0,
            0,
            started.elapsed(),
        )?;
        record_blob_set_legal_hold(object_kind, result_label, started.elapsed());
        result
    }

    async fn set_legal_hold_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        status: LegalHoldStatus,
    ) -> Result<()> {
        let started = Instant::now();
        let object_kind = object_kind(object_id);
        let result = self.set_s3_legal_hold(object_id, version_id, status).await;
        let result_label = match &result {
            Ok(()) => "ok",
            Err(error) => storage_error_result(error),
        };
        self.record_provider_operation(
            S3ProviderOperation::SetLegalHold,
            object_kind,
            result_label,
            0,
            0,
            started.elapsed(),
        )?;
        record_blob_set_legal_hold(object_kind, result_label, started.elapsed());
        result
    }

    async fn flush_caches(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::requests::object_get_options;
    use super::{S3BlobStore, S3BlobStoreConfig};
    use crate::{ByteRange, StorageError};
    use object_store::aws::AmazonS3Builder;
    use rs3_types::BackendObjectId;
    use rs3_types::{RetentionMode, RetentionPolicy};

    fn object_id(value: &str) -> BackendObjectId {
        BackendObjectId::new(value).unwrap_or_else(|error| panic!("{error}"))
    }

    #[test]
    fn config_maps_object_ids_under_normalized_prefix() {
        let config = S3BlobStoreConfig::new("bucket")
            .unwrap_or_else(|error| panic!("{error}"))
            .with_prefix(Some("/repo//tenant/".to_owned()));

        assert_eq!(
            config.object_key(&object_id("segments/a")),
            "repo/tenant/segments/a"
        );
        assert_eq!(
            config.object_id_from_key("repo/tenant/segments/a"),
            Ok(Some(object_id("segments/a")))
        );
        assert_eq!(config.object_id_from_key("other/segments/a"), Ok(None));
    }

    #[test]
    fn bounded_range_rejects_zero_length_requests() {
        assert_eq!(
            object_get_options(ByteRange::Slice { offset: 10, len: 0 }).map(|_| ()),
            Err(StorageError::InvalidRange)
        );
    }

    #[tokio::test]
    async fn retention_validation_fails_without_sdk_client() {
        let config = S3BlobStoreConfig::new("bucket")
            .unwrap_or_else(|error| panic!("{error}"))
            .with_endpoint_url(Some("http://127.0.0.1:9".to_owned()))
            .with_allow_http(true);
        let object_store = AmazonS3Builder::new()
            .with_bucket_name("bucket")
            .with_endpoint("http://127.0.0.1:9")
            .with_allow_http(true)
            .with_access_key_id("access")
            .with_secret_access_key("secret")
            .build()
            .unwrap_or_else(|error| panic!("{error}"));
        let store = S3BlobStore::from_store(object_store, config);

        let result = store
            .validate_retention_support(Some(&RetentionPolicy::new(RetentionMode::Compliance, 30)))
            .await;

        assert_eq!(result, Err(StorageError::RetentionExtensionUnsupported));
    }
}
