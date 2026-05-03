//! S3-compatible `BlobStore` implementation.

use crate::{
    BlobMetadata, BlobStore, ByteRange, PutOptions, Result, StorageError, object_kind, prefix_kind,
    record_blob_delete, record_blob_extend_retention, record_blob_get, record_blob_head,
    record_blob_list, record_blob_put,
};
use async_trait::async_trait;
use bytes::Bytes;
use object_store::aws::{AmazonS3, AmazonS3Builder, S3ConditionalPut};
use object_store::list::{PaginatedListOptions, PaginatedListStore};
use object_store::path::Path as ObjectPath;
use object_store::{
    Attribute, Attributes, GetOptions, ObjectMeta, ObjectStore, ObjectStoreExt, PutMode,
    PutOptions as ObjectPutOptions,
};
use rs3_types::{BackendObjectId, RetentionPolicy};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

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
    config: S3BlobStoreConfig,
    metrics: Arc<RwLock<S3ProviderMetrics>>,
}

impl S3BlobStore {
    /// Builds an S3 store from the default AWS environment/config chain.
    ///
    /// # Errors
    ///
    /// Returns a provider error when configuration cannot be constructed.
    pub async fn from_environment(config: S3BlobStoreConfig) -> Result<Self> {
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

        let store = builder.build().map_err(provider_error)?;
        Ok(Self::from_store(store, config))
    }

    /// Builds an S3 blob store from an existing `object_store` S3 client.
    pub fn from_store(store: AmazonS3, config: S3BlobStoreConfig) -> Self {
        Self {
            store,
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

        if options.retention.is_some() {
            self.record_provider_operation(
                S3ProviderOperation::Put,
                object_kind,
                "retention_unsupported",
                bytes_sent,
                0,
                started.elapsed(),
            )?;
            record_blob_put(
                object_kind,
                requested_len,
                true,
                "retention_unsupported",
                started.elapsed(),
            );
            return Err(StorageError::RetentionExtensionUnsupported);
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
        _policy: RetentionPolicy,
    ) -> Result<()> {
        let started = Instant::now();
        let object_kind = object_kind(object_id);
        self.record_provider_operation(
            S3ProviderOperation::ExtendRetention,
            object_kind,
            "unsupported",
            0,
            0,
            started.elapsed(),
        )?;
        record_blob_extend_retention(object_kind, "unsupported", started.elapsed());
        Err(StorageError::RetentionExtensionUnsupported)
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
        }
    }
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

fn metadata_from_object_meta(object_id: BackendObjectId, metadata: ObjectMeta) -> BlobMetadata {
    BlobMetadata {
        object_id,
        content_len: metadata.size,
        modified_at_ms: Some(metadata.last_modified.timestamp_millis()),
        etag: metadata.e_tag,
        version_id: metadata.version,
        retention: None,
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

fn provider_error(error: impl std::error::Error) -> StorageError {
    StorageError::Provider(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{S3BlobStoreConfig, object_get_options};
    use crate::{ByteRange, StorageError};
    use rs3_types::BackendObjectId;

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
}
