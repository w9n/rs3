//! S3-compatible `BlobStore` implementation.

use crate::{
    BlobMetadata, BlobStore, ByteRange, PutOptions, Result, StorageError, object_kind, prefix_kind,
    record_blob_delete, record_blob_extend_retention, record_blob_get, record_blob_head,
    record_blob_list, record_blob_put, record_blob_set_legal_hold,
};
use async_trait::async_trait;
use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_s3::primitives::{ByteStream as SdkByteStream, DateTime as SdkDateTime};
use aws_sdk_s3::{
    Client as SdkS3Client,
    config::{BehaviorVersion, Credentials, Region},
    types::{
        BucketVersioningStatus, ChecksumAlgorithm, ObjectLockEnabled, ObjectLockLegalHold,
        ObjectLockLegalHoldStatus as SdkObjectLockLegalHoldStatus,
        ObjectLockMode as SdkObjectLockMode, ObjectLockRetention, ObjectLockRetentionMode,
    },
};
use bytes::Bytes;
use object_store::aws::{AmazonS3, AmazonS3Builder, S3ConditionalPut};
use object_store::list::{PaginatedListOptions, PaginatedListStore};
use object_store::path::Path as ObjectPath;
use object_store::{
    Attribute, Attributes, GetOptions, ObjectMeta, ObjectStore, ObjectStoreExt, PutMode,
    PutOptions as ObjectPutOptions,
};
use rs3_types::{BackendObjectId, LegalHoldStatus, RetentionMode, RetentionPolicy};
use std::sync::{Arc, Once, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static RUSTLS_PROVIDER: Once = Once::new();

/// Configuration for an S3-backed blob store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S3BlobStoreConfig {
    /// Backend bucket containing repository-owned objects.
    pub bucket: String,
    /// Optional key prefix for repository-owned objects inside the bucket.
    pub prefix: Option<String>,
    /// Optional custom endpoint URL for S3-compatible providers.
    pub endpoint_url: Option<String>,
    /// Optional AWS region override.
    pub region: Option<String>,
    /// Allows plain HTTP for local S3-compatible development endpoints.
    pub allow_http: bool,
    /// Uses virtual-hosted bucket addressing instead of path-style addressing.
    pub virtual_hosted_style: bool,
}

impl S3BlobStoreConfig {
    /// Creates S3 backend configuration for a bucket.
    ///
    /// # Errors
    ///
    /// Returns a provider error when the bucket is blank.
    pub fn new(bucket: impl Into<String>) -> Result<Self> {
        let bucket = bucket.into();
        if bucket.trim().is_empty() {
            return Err(StorageError::Provider(
                "S3 backend bucket cannot be empty".to_owned(),
            ));
        }

        Ok(Self {
            bucket,
            prefix: None,
            endpoint_url: None,
            region: None,
            allow_http: false,
            virtual_hosted_style: false,
        })
    }

    /// Sets the repository-owned key prefix.
    pub fn with_prefix(mut self, prefix: Option<String>) -> Self {
        self.prefix = normalize_prefix(prefix);
        self
    }

    /// Sets a custom endpoint URL.
    pub fn with_endpoint_url(mut self, endpoint_url: Option<String>) -> Self {
        self.endpoint_url = endpoint_url.and_then(non_blank);
        self
    }

    /// Sets an AWS region override.
    pub fn with_region(mut self, region: Option<String>) -> Self {
        self.region = region.and_then(non_blank);
        self
    }

    /// Enables or disables plain HTTP endpoints.
    pub fn with_allow_http(mut self, allow_http: bool) -> Self {
        self.allow_http = allow_http;
        self
    }

    /// Enables or disables virtual-hosted bucket addressing.
    pub fn with_virtual_hosted_style(mut self, virtual_hosted_style: bool) -> Self {
        self.virtual_hosted_style = virtual_hosted_style;
        self
    }

    fn base_prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }

    fn object_key(&self, object_id: &BackendObjectId) -> String {
        join_key(self.base_prefix(), object_id.as_str())
    }

    fn list_key_prefix(&self, prefix: &str) -> String {
        join_key(self.base_prefix(), prefix)
    }

    fn object_id_from_key(&self, key: &str) -> Result<Option<BackendObjectId>> {
        let relative = match self.base_prefix() {
            Some(prefix) => {
                let Some(rest) = key.strip_prefix(prefix) else {
                    return Ok(None);
                };
                let Some(rest) = rest.strip_prefix('/') else {
                    return Ok(None);
                };
                rest
            }
            None => key,
        };

        if relative.is_empty() {
            return Ok(None);
        }

        BackendObjectId::new(relative.to_owned())
            .map(Some)
            .map_err(|error| StorageError::Provider(error.to_string()))
    }
}

/// Metrics captured at the S3 provider boundary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct S3ProviderMetrics {
    /// PUT operation metrics.
    pub put: S3ProviderOperationMetrics,
    /// GET operation metrics.
    pub get: S3ProviderOperationMetrics,
    /// HEAD operation metrics.
    pub head: S3ProviderOperationMetrics,
    /// LIST operation metrics.
    pub list: S3ProviderOperationMetrics,
    /// DELETE operation metrics.
    pub delete: S3ProviderOperationMetrics,
    /// Retention-extension operation metrics.
    pub extend_retention: S3ProviderOperationMetrics,
    /// Legal-hold update operation metrics.
    pub set_legal_hold: S3ProviderOperationMetrics,
}

/// Per-operation S3 provider metrics.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct S3ProviderOperationMetrics {
    /// Number of operation attempts sent through the adapter.
    pub requests: u64,
    /// Number of operation attempts that returned success.
    pub successes: u64,
    /// Number of operation attempts that returned an error.
    pub failures: u64,
    /// Bytes sent in successful requests, when known.
    pub bytes_sent: u64,
    /// Bytes received in successful responses, when known.
    pub bytes_received: u64,
    /// Total elapsed time in microseconds across attempts.
    pub elapsed_us: u64,
}

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
            bucket = %self.config.bucket,
            retention_mode = retention_mode_label(retention.mode),
            retention_days = retention.retain_days,
            "S3 Object Lock retention support validated",
        );
        Ok(())
    }

    fn object_path(&self, object_id: &BackendObjectId) -> Result<ObjectPath> {
        object_path(&self.config.object_key(object_id))
    }

    async fn put_object_lock_object(
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
        let version_id = output.version_id().map(str::to_owned);
        let mut metadata = self.head_with_sdk(object_id, version_id.as_deref()).await?;
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

    async fn head_with_sdk(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&str>,
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
            request = request.version_id(version_id);
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
        let legal_hold = legal_hold_from_s3_head(output.object_lock_legal_hold_status())?;

        Ok(BlobMetadata {
            object_id: object_id.clone(),
            content_len,
            modified_at_ms,
            etag: output.e_tag().map(str::to_owned),
            version_id: output.version_id().map(str::to_owned),
            retention,
            legal_hold,
        })
    }

    async fn extend_s3_retention(
        &self,
        object_id: &BackendObjectId,
        policy: &RetentionPolicy,
    ) -> Result<()> {
        if !retention_is_active(policy) {
            return Ok(());
        }
        let client = self
            .sdk_client
            .as_ref()
            .ok_or(StorageError::RetentionExtensionUnsupported)?;
        let existing = self.head_with_sdk(object_id, None).await?;
        if retention_satisfies(existing.retention.as_ref(), policy) {
            return Ok(());
        }

        let retention = ObjectLockRetention::builder()
            .mode(sdk_object_lock_retention_mode(policy)?)
            .retain_until_date(retain_until_date(policy)?)
            .build();
        client
            .put_object_retention()
            .bucket(self.config.bucket.as_str())
            .key(self.config.object_key(object_id))
            .retention(retention)
            .checksum_algorithm(ChecksumAlgorithm::Sha256)
            .send()
            .await
            .map_err(|error| map_sdk_common_error(error, object_id))?;

        let verified = self.head_with_sdk(object_id, None).await?;
        verify_retention(verified.retention.as_ref(), policy)
    }

    async fn set_s3_legal_hold(
        &self,
        object_id: &BackendObjectId,
        status: LegalHoldStatus,
    ) -> Result<()> {
        let client = self
            .sdk_client
            .as_ref()
            .ok_or(StorageError::LegalHoldUnsupported)?;
        let legal_hold = ObjectLockLegalHold::builder()
            .status(sdk_legal_hold_status(status))
            .build();
        client
            .put_object_legal_hold()
            .bucket(self.config.bucket.as_str())
            .key(self.config.object_key(object_id))
            .legal_hold(legal_hold)
            .checksum_algorithm(ChecksumAlgorithm::Sha256)
            .send()
            .await
            .map_err(|error| map_sdk_common_error(error, object_id))?;

        let verified = client
            .get_object_legal_hold()
            .bucket(self.config.bucket.as_str())
            .key(self.config.object_key(object_id))
            .send()
            .await
            .map_err(|error| map_sdk_common_error(error, object_id))?;
        verify_legal_hold(
            legal_hold_from_s3_legal_hold(verified.legal_hold())?,
            status,
        )
    }

    fn record_provider_operation(
        &self,
        operation: S3ProviderOperation,
        object_kind: &str,
        result: &str,
        bytes_sent: u64,
        bytes_received: u64,
        elapsed: Duration,
    ) -> Result<()> {
        let mut metrics = self
            .metrics
            .write()
            .map_err(|_| StorageError::Provider("S3 metrics lock poisoned".to_owned()))?;
        let operation_metrics = match operation {
            S3ProviderOperation::Put => &mut metrics.put,
            S3ProviderOperation::Get => &mut metrics.get,
            S3ProviderOperation::Head => &mut metrics.head,
            S3ProviderOperation::List => &mut metrics.list,
            S3ProviderOperation::Delete => &mut metrics.delete,
            S3ProviderOperation::ExtendRetention => &mut metrics.extend_retention,
            S3ProviderOperation::SetLegalHold => &mut metrics.set_legal_hold,
        };
        operation_metrics.requests = operation_metrics.requests.saturating_add(1);
        if result == "ok" {
            operation_metrics.successes = operation_metrics.successes.saturating_add(1);
            operation_metrics.bytes_sent = operation_metrics.bytes_sent.saturating_add(bytes_sent);
            operation_metrics.bytes_received = operation_metrics
                .bytes_received
                .saturating_add(bytes_received);
        } else {
            operation_metrics.failures = operation_metrics.failures.saturating_add(1);
        }
        operation_metrics.elapsed_us = operation_metrics
            .elapsed_us
            .saturating_add(crate::elapsed_us(elapsed));
        record_s3_provider_metrics(
            operation.as_str(),
            object_kind,
            result,
            bytes_sent,
            bytes_received,
            elapsed,
        );

        tracing::debug!(
            target: "rs3_storage",
            provider = "s3",
            operation = operation.as_str(),
            object_kind,
            result,
            bytes_sent,
            bytes_received,
            elapsed_us = crate::elapsed_us(elapsed),
            "provider blob store operation completed",
        );

        Ok(())
    }
}

fn record_s3_provider_metrics(
    operation: &'static str,
    object_kind: &str,
    result: &str,
    bytes_sent: u64,
    bytes_received: u64,
    elapsed: Duration,
) {
    metrics::counter!(
        "rs3_storage_provider_operations_total",
        "provider" => "s3",
        "operation" => operation,
        "object_kind" => object_kind.to_owned(),
        "result" => result.to_owned(),
    )
    .increment(1);
    metrics::histogram!(
        "rs3_storage_provider_operation_duration_seconds",
        "provider" => "s3",
        "operation" => operation,
        "object_kind" => object_kind.to_owned(),
        "result" => result.to_owned(),
    )
    .record(elapsed.as_secs_f64());

    if result == "ok" {
        metrics::counter!(
            "rs3_storage_provider_bytes_sent_total",
            "provider" => "s3",
            "operation" => operation,
            "object_kind" => object_kind.to_owned(),
        )
        .increment(bytes_sent);
        metrics::counter!(
            "rs3_storage_provider_bytes_received_total",
            "provider" => "s3",
            "operation" => operation,
            "object_kind" => object_kind.to_owned(),
        )
        .increment(bytes_received);
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
                    version_id: output.version,
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
                Ok(metadata_from_object_meta(object_id.clone(), metadata))
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
                        entries.push(metadata_from_object_meta(object_id, object));
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
        let result = self.extend_s3_retention(object_id, &policy).await;
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
        let result = self.set_s3_legal_hold(object_id, status).await;
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

#[derive(Clone, Copy, Debug)]
enum S3ProviderOperation {
    Put,
    Get,
    Head,
    List,
    Delete,
    ExtendRetention,
    SetLegalHold,
}

impl S3ProviderOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Put => "put",
            Self::Get => "get",
            Self::Head => "head",
            Self::List => "list",
            Self::Delete => "delete",
            Self::ExtendRetention => "extend_retention",
            Self::SetLegalHold => "set_legal_hold",
        }
    }
}

fn install_rustls_provider() {
    RUSTLS_PROVIDER.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn object_put_options(options: &PutOptions) -> ObjectPutOptions {
    let mode = if options.do_not_recreate {
        PutMode::Create
    } else {
        PutMode::Overwrite
    };
    let mut attributes = Attributes::new();
    if let Some(content_type) = options.content_type.clone() {
        attributes.insert(Attribute::ContentType, content_type.into());
    }

    ObjectPutOptions {
        mode,
        attributes,
        ..ObjectPutOptions::default()
    }
}

fn object_get_options(range: ByteRange) -> Result<GetOptions> {
    let options = match range {
        ByteRange::Full => GetOptions::default(),
        ByteRange::Slice { offset, len } => {
            let end = offset.checked_add(len).ok_or(StorageError::InvalidRange)?;
            if end <= offset {
                return Err(StorageError::InvalidRange);
            }
            GetOptions::new().with_range(Some(offset..end))
        }
    };
    Ok(options)
}

fn object_path(value: &str) -> Result<ObjectPath> {
    ObjectPath::parse(value).map_err(|error| StorageError::Provider(error.to_string()))
}

fn normalize_prefix(prefix: Option<String>) -> Option<String> {
    prefix.and_then(non_blank).map(|prefix| {
        prefix
            .trim_matches('/')
            .split('/')
            .filter(|component| !component.is_empty())
            .collect::<Vec<_>>()
            .join("/")
    })
}

fn non_blank(value: String) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

fn join_key(prefix: Option<&str>, value: &str) -> String {
    match (prefix, value) {
        (Some(prefix), "") => format!("{prefix}/"),
        (Some(prefix), value) => format!("{prefix}/{value}"),
        (None, value) => value.to_owned(),
    }
}

fn object_store_from_environment(config: &S3BlobStoreConfig) -> Result<AmazonS3> {
    let mut builder = AmazonS3Builder::from_env()
        .with_bucket_name(config.bucket.clone())
        .with_conditional_put(S3ConditionalPut::ETagMatch)
        .with_allow_http(config.allow_http)
        .with_virtual_hosted_style_request(config.virtual_hosted_style);

    if let Some(endpoint_url) = config.endpoint_url.as_deref() {
        builder = builder.with_endpoint(endpoint_url);
    }
    if let Some(region) = config.region.as_deref() {
        builder = builder.with_region(region);
    }

    builder.build().map_err(provider_error)
}

async fn sdk_client_from_environment(config: &S3BlobStoreConfig) -> Result<SdkS3Client> {
    let region = aws_config::meta::region::RegionProviderChain::first_try(
        config.region.clone().map(Region::new),
    )
    .or_default_provider()
    .or_else(Region::new("us-east-1"));
    let shared_config = aws_config::defaults(BehaviorVersion::latest())
        .region(region)
        .load()
        .await;
    let mut builder = aws_sdk_s3::config::Builder::from(&shared_config)
        .force_path_style(!config.virtual_hosted_style);
    if let Some(endpoint_url) = config.endpoint_url.as_deref() {
        builder = builder.endpoint_url(endpoint_url);
    }

    Ok(SdkS3Client::from_conf(builder.build()))
}

fn sdk_client_from_static_environment(config: &S3BlobStoreConfig) -> Result<Option<SdkS3Client>> {
    let access_key = optional_env_value("AWS_ACCESS_KEY_ID")?;
    let secret_key = optional_env_value("AWS_SECRET_ACCESS_KEY")?;
    let (access_key, secret_key) = match (access_key, secret_key) {
        (Some(access_key), Some(secret_key)) => (access_key, secret_key),
        (None, None) => return Ok(None),
        (Some(_), None) | (None, Some(_)) => {
            return Err(StorageError::Provider(
                "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be provided together".to_owned(),
            ));
        }
    };

    let session_token = optional_env_value("AWS_SESSION_TOKEN")?;
    let region = config
        .region
        .clone()
        .or(optional_env_value("AWS_REGION")?)
        .or(optional_env_value("AWS_DEFAULT_REGION")?)
        .unwrap_or_else(|| "us-east-1".to_owned());
    let credentials = Credentials::new(
        access_key,
        secret_key,
        session_token,
        None,
        "rs3-storage-env",
    );
    let mut builder = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(region))
        .force_path_style(!config.virtual_hosted_style)
        .credentials_provider(credentials);

    if let Some(endpoint_url) = config.endpoint_url.as_deref() {
        builder = builder.endpoint_url(endpoint_url);
    }

    Ok(Some(SdkS3Client::from_conf(builder.build())))
}

fn optional_env_value(name: &str) -> Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) => Ok(non_blank(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(StorageError::Provider(format!(
            "{name} must be valid Unicode"
        ))),
    }
}

fn retention_is_active(policy: &RetentionPolicy) -> bool {
    policy.mode != RetentionMode::None && policy.retain_days > 0
}

fn retention_blocks_delete(policy: Option<&RetentionPolicy>) -> bool {
    policy.is_some_and(retention_is_active)
}

fn legal_hold_blocks_delete(status: Option<LegalHoldStatus>) -> bool {
    status == Some(LegalHoldStatus::On)
}

fn provider_legal_hold(status: Option<LegalHoldStatus>) -> Option<LegalHoldStatus> {
    status.filter(|status| *status == LegalHoldStatus::On)
}

fn retain_until_date(policy: &RetentionPolicy) -> Result<SdkDateTime> {
    let now_secs = current_epoch_secs()?;
    let retain_secs = i64::from(policy.retain_days)
        .checked_mul(86_400)
        .ok_or_else(|| StorageError::Provider("retention period is out of range".to_owned()))?;
    let retain_until_secs = now_secs
        .checked_add(retain_secs)
        .ok_or_else(|| StorageError::Provider("retention date is out of range".to_owned()))?;
    Ok(SdkDateTime::from_secs(retain_until_secs))
}

fn current_epoch_secs() -> Result<i64> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| StorageError::Provider(error.to_string()))?
        .as_secs();
    i64::try_from(secs)
        .map_err(|_| StorageError::Provider("current time is out of range".to_owned()))
}

fn sdk_object_lock_mode(policy: &RetentionPolicy) -> Result<SdkObjectLockMode> {
    match policy.mode {
        RetentionMode::Compliance => Ok(SdkObjectLockMode::Compliance),
        RetentionMode::Governance => Ok(SdkObjectLockMode::Governance),
        RetentionMode::None => Err(StorageError::Provider(
            "Object Lock mode cannot be None for retained S3 PUT".to_owned(),
        )),
    }
}

fn sdk_object_lock_retention_mode(policy: &RetentionPolicy) -> Result<ObjectLockRetentionMode> {
    match policy.mode {
        RetentionMode::Compliance => Ok(ObjectLockRetentionMode::Compliance),
        RetentionMode::Governance => Ok(ObjectLockRetentionMode::Governance),
        RetentionMode::None => Err(StorageError::Provider(
            "Object Lock mode cannot be None for retained S3 operation".to_owned(),
        )),
    }
}

fn sdk_legal_hold_status(status: LegalHoldStatus) -> SdkObjectLockLegalHoldStatus {
    match status {
        LegalHoldStatus::Off => SdkObjectLockLegalHoldStatus::Off,
        LegalHoldStatus::On => SdkObjectLockLegalHoldStatus::On,
    }
}

fn retention_from_s3_head(
    mode: Option<&SdkObjectLockMode>,
    retain_until_date: Option<&SdkDateTime>,
) -> Result<Option<RetentionPolicy>> {
    let (Some(mode), Some(retain_until_date)) = (mode, retain_until_date) else {
        if mode.is_some() || retain_until_date.is_some() {
            return Err(StorageError::Provider(
                "S3 HEAD returned partial Object Lock metadata".to_owned(),
            ));
        }
        return Ok(None);
    };

    let mode = match mode {
        SdkObjectLockMode::Compliance => RetentionMode::Compliance,
        SdkObjectLockMode::Governance => RetentionMode::Governance,
        _ => {
            return Err(StorageError::Provider(
                "S3 HEAD returned an unknown Object Lock mode".to_owned(),
            ));
        }
    };
    let now_secs = current_epoch_secs()?;
    let retain_days = if retain_until_date.secs() <= now_secs {
        0
    } else {
        ceil_days_from_seconds(retain_until_date.secs() - now_secs)?
    };
    Ok(Some(RetentionPolicy::new(mode, retain_days)))
}

fn legal_hold_from_s3_head(
    status: Option<&SdkObjectLockLegalHoldStatus>,
) -> Result<Option<LegalHoldStatus>> {
    status.map(legal_hold_from_sdk_status).transpose()
}

fn legal_hold_from_s3_legal_hold(
    legal_hold: Option<&ObjectLockLegalHold>,
) -> Result<Option<LegalHoldStatus>> {
    let Some(legal_hold) = legal_hold else {
        return Ok(None);
    };
    legal_hold
        .status()
        .map(legal_hold_from_sdk_status)
        .transpose()
}

fn legal_hold_from_sdk_status(status: &SdkObjectLockLegalHoldStatus) -> Result<LegalHoldStatus> {
    match status {
        SdkObjectLockLegalHoldStatus::Off => Ok(LegalHoldStatus::Off),
        SdkObjectLockLegalHoldStatus::On => Ok(LegalHoldStatus::On),
        _ => Err(StorageError::Provider(
            "S3 returned an unknown Object Lock legal hold status".to_owned(),
        )),
    }
}

fn ceil_days_from_seconds(seconds: i64) -> Result<u32> {
    let seconds = u64::try_from(seconds)
        .map_err(|_| StorageError::Provider("retention date is before current time".to_owned()))?;
    let days = seconds.div_ceil(86_400);
    u32::try_from(days)
        .map_err(|_| StorageError::Provider("retention period exceeds u32 days".to_owned()))
}

fn verify_retention(actual: Option<&RetentionPolicy>, requested: &RetentionPolicy) -> Result<()> {
    if retention_satisfies(actual, requested) {
        Ok(())
    } else {
        Err(StorageError::Provider(
            "S3 Object Lock verification failed".to_owned(),
        ))
    }
}

fn verify_legal_hold(actual: Option<LegalHoldStatus>, requested: LegalHoldStatus) -> Result<()> {
    if legal_hold_satisfies(actual, requested) {
        Ok(())
    } else {
        Err(StorageError::Provider(
            "S3 Object Lock legal hold verification failed".to_owned(),
        ))
    }
}

fn retention_satisfies(actual: Option<&RetentionPolicy>, requested: &RetentionPolicy) -> bool {
    if !retention_is_active(requested) {
        return true;
    }
    let Some(actual) = actual else {
        return false;
    };
    retention_mode_strength(actual.mode) >= retention_mode_strength(requested.mode)
        && actual.retain_days >= requested.retain_days
}

fn legal_hold_satisfies(actual: Option<LegalHoldStatus>, requested: LegalHoldStatus) -> bool {
    match requested {
        LegalHoldStatus::Off => actual.is_none_or(|actual| actual == LegalHoldStatus::Off),
        LegalHoldStatus::On => actual == Some(LegalHoldStatus::On),
    }
}

fn retention_mode_strength(mode: RetentionMode) -> u8 {
    match mode {
        RetentionMode::None => 0,
        RetentionMode::Governance => 1,
        RetentionMode::Compliance => 2,
    }
}

fn retention_mode_label(mode: RetentionMode) -> &'static str {
    match mode {
        RetentionMode::None => "none",
        RetentionMode::Governance => "governance",
        RetentionMode::Compliance => "compliance",
    }
}

fn storage_error_result(error: &StorageError) -> &'static str {
    match error {
        StorageError::AlreadyExists(_) => "already_exists",
        StorageError::NotFound(_) => "not_found",
        StorageError::InvalidRange => "invalid_range",
        StorageError::RetentionBlocked => "retention_blocked",
        StorageError::RetentionExtensionUnsupported => "retention_unsupported",
        StorageError::LegalHoldBlocked => "legal_hold_blocked",
        StorageError::LegalHoldUnsupported => "legal_hold_unsupported",
        StorageError::Provider(_) => "error",
    }
}

fn metadata_from_object_meta(object_id: BackendObjectId, metadata: ObjectMeta) -> BlobMetadata {
    BlobMetadata {
        object_id,
        content_len: metadata.size,
        modified_at_ms: Some(metadata.last_modified.timestamp_millis()),
        etag: metadata.e_tag,
        version_id: metadata.version,
        retention: None,
        legal_hold: None,
    }
}

fn put_error_result(error: &object_store::Error) -> &'static str {
    match error {
        object_store::Error::AlreadyExists { .. }
        | object_store::Error::Precondition { .. }
        | object_store::Error::NotModified { .. } => "already_exists",
        object_store::Error::NotFound { .. } => "not_found",
        _ => "error",
    }
}

fn get_error_result(error: &object_store::Error) -> &'static str {
    match error {
        object_store::Error::NotFound { .. } => "not_found",
        _ => "error",
    }
}

fn common_error_result(error: &object_store::Error) -> &'static str {
    match error {
        object_store::Error::NotFound { .. } => "not_found",
        _ => "error",
    }
}

fn map_put_error(error: object_store::Error, object_id: &BackendObjectId) -> StorageError {
    match error {
        object_store::Error::AlreadyExists { .. }
        | object_store::Error::Precondition { .. }
        | object_store::Error::NotModified { .. } => StorageError::AlreadyExists(object_id.clone()),
        object_store::Error::NotFound { .. } => StorageError::NotFound(object_id.clone()),
        _ => provider_error(error),
    }
}

fn map_get_error(error: object_store::Error, object_id: &BackendObjectId) -> StorageError {
    match error {
        object_store::Error::NotFound { .. } => StorageError::NotFound(object_id.clone()),
        _ => provider_error(error),
    }
}

fn map_common_error(error: object_store::Error, object_id: &BackendObjectId) -> StorageError {
    match error {
        object_store::Error::NotFound { .. } => StorageError::NotFound(object_id.clone()),
        _ => provider_error(error),
    }
}

fn map_sdk_put_error<E, R>(error: SdkError<E, R>, object_id: &BackendObjectId) -> StorageError
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

fn map_sdk_common_error<E, R>(error: SdkError<E, R>, object_id: &BackendObjectId) -> StorageError
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

fn provider_error(error: impl std::error::Error) -> StorageError {
    StorageError::Provider(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{S3BlobStore, S3BlobStoreConfig, object_get_options};
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
