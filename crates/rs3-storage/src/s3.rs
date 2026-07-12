//! S3-compatible `BlobStore` implementation.

use crate::read::{BlobReadSource, exact_blob_read};
use crate::{
    BlobMetadata, BlobMultipartUpload, BlobRead, BlobStore, ByteRange, PutOptions, Result,
    StorageError, object_kind, prefix_kind, record_blob_delete, record_blob_extend_retention,
    record_blob_get, record_blob_head, record_blob_list, record_blob_put,
    record_blob_set_legal_hold,
};
use async_trait::async_trait;
use aws_sdk_s3::Client as SdkS3Client;
use aws_sdk_s3::primitives::ByteStream as SdkByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use bytes::Bytes;
use rs3_types::{BackendObjectId, BackendVersionId, LegalHoldStatus, RetentionPolicy};
use std::sync::Arc;
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
    install_rustls_provider, sdk_client_from_environment, sdk_client_from_static_environment,
};
use errors::{
    backend_version_id_from_str, map_sdk_common_error, map_sdk_get_error, map_sdk_put_error,
    provider_error, storage_error_result,
};
use metrics::{S3ProviderMetricCounters, S3ProviderOperation};
use object_lock::{
    legal_hold_blocks_delete, provider_legal_hold, retain_until_date, retention_blocks_delete,
    retention_is_active, retention_satisfies, sdk_legal_hold_status, sdk_object_lock_mode,
    verify_legal_hold, verify_retention,
};
use requests::sdk_range_header;

struct S3ReadSource {
    body: SdkByteStream,
}

#[async_trait]
impl BlobReadSource for S3ReadSource {
    async fn next_source_chunk(&mut self) -> Result<Option<Bytes>> {
        self.body.try_next().await.map_err(provider_error)
    }
}

struct ObservedS3Read {
    inner: Box<dyn BlobRead>,
    store: S3BlobStore,
    object_kind: String,
    range: ByteRange,
    started: Instant,
    bytes_read: u64,
    terminal: bool,
}

#[async_trait]
impl BlobRead for ObservedS3Read {
    fn exact_len(&self) -> u64 {
        self.inner.exact_len()
    }

    async fn next_chunk(&mut self) -> Result<Option<Bytes>> {
        match self.inner.next_chunk().await {
            Ok(Some(chunk)) => {
                self.bytes_read = self.bytes_read.saturating_add(chunk.len() as u64);
                Ok(Some(chunk))
            }
            Ok(None) => {
                self.record("ok")?;
                Ok(None)
            }
            Err(error) => {
                self.record("error")?;
                Err(error)
            }
        }
    }
}

impl ObservedS3Read {
    fn record(&mut self, result: &str) -> Result<()> {
        if self.terminal {
            return Ok(());
        }
        self.terminal = true;
        self.store.record_provider_operation(
            S3ProviderOperation::Get,
            &self.object_kind,
            result,
            0,
            self.bytes_read,
            self.started.elapsed(),
        )?;
        record_blob_get(
            &self.object_kind,
            self.range,
            self.bytes_read,
            result,
            self.started.elapsed(),
        );
        Ok(())
    }
}

impl Drop for ObservedS3Read {
    fn drop(&mut self) {
        let _ = self.record("cancelled");
    }
}

async fn collect_get_body(mut body: SdkByteStream, range: ByteRange) -> Result<Bytes> {
    let ByteRange::Slice { len, .. } = range else {
        return body
            .collect()
            .await
            .map_err(provider_error)
            .map(|body| body.into_bytes());
    };
    let capacity = usize::try_from(len).map_err(|_| StorageError::InvalidRange)?;
    let mut collected = Vec::with_capacity(capacity);
    let mut received = 0_u64;
    while let Some(chunk) = body.try_next().await.map_err(provider_error)? {
        let chunk_len = u64::try_from(chunk.len()).map_err(|_| {
            StorageError::Provider("S3 range response length is out of range".to_owned())
        })?;
        received = received.checked_add(chunk_len).ok_or_else(|| {
            StorageError::Provider("S3 range response length is out of range".to_owned())
        })?;
        if received > len {
            return Err(StorageError::Provider(
                "S3 provider returned more bytes than the requested range".to_owned(),
            ));
        }
        collected.extend_from_slice(&chunk);
    }
    if received != len {
        return Err(StorageError::Provider(
            "S3 provider returned fewer bytes than the requested range".to_owned(),
        ));
    }
    Ok(Bytes::from(collected))
}

/// S3-compatible `BlobStore` backed by the AWS SDK for Rust.
#[derive(Clone, Debug)]
pub struct S3BlobStore {
    client: SdkS3Client,
    config: S3BlobStoreConfig,
    metrics: Arc<S3ProviderMetricCounters>,
}

impl S3BlobStore {
    /// Builds an S3 store from the supported AWS environment/config chain.
    ///
    /// # Errors
    ///
    /// Returns a provider error when configuration cannot be constructed.
    pub async fn from_environment(config: S3BlobStoreConfig) -> Result<Self> {
        install_rustls_provider();
        let client = sdk_client_from_environment(&config).await?;
        Ok(Self {
            client,
            config,
            metrics: Arc::new(S3ProviderMetricCounters::default()),
        })
    }

    /// Builds an S3 store synchronously from environment credentials.
    ///
    /// This path requires static `AWS_ACCESS_KEY_ID` and
    /// `AWS_SECRET_ACCESS_KEY` values. Use [`Self::from_environment`] for the
    /// full asynchronous AWS credential provider chain.
    ///
    /// # Errors
    ///
    /// Returns a provider error when configuration cannot be constructed.
    pub fn from_environment_sync(config: S3BlobStoreConfig) -> Result<Self> {
        install_rustls_provider();
        let client = sdk_client_from_static_environment(&config)?;
        Ok(Self {
            client,
            config,
            metrics: Arc::new(S3ProviderMetricCounters::default()),
        })
    }

    /// Builds an S3 blob store from an existing AWS SDK client.
    pub fn from_client(client: SdkS3Client, config: S3BlobStoreConfig) -> Self {
        Self {
            client,
            config,
            metrics: Arc::new(S3ProviderMetricCounters::default()),
        }
    }

    /// Returns the configured backend bucket.
    pub fn bucket(&self) -> &str {
        &self.config.bucket
    }

    /// Returns a snapshot of S3 provider metrics.
    pub fn provider_metrics(&self) -> Result<S3ProviderMetrics> {
        Ok(self.metrics.snapshot())
    }

    /// Resets S3 provider metrics without changing stored objects.
    pub fn reset_provider_metrics(&self) -> Result<()> {
        self.metrics.reset();
        Ok(())
    }
}

struct S3MultipartUpload {
    store: S3BlobStore,
    client: SdkS3Client,
    object_id: BackendObjectId,
    key: String,
    upload_id: String,
    options: PutOptions,
    parts: Vec<Option<CompletedPart>>,
    content_len: u64,
    started: Instant,
}

#[async_trait]
impl BlobMultipartUpload for S3MultipartUpload {
    async fn put_part(&mut self, part_index: usize, body: Bytes) -> Result<()> {
        let part_number = i32::try_from(part_index.saturating_add(1)).map_err(|_| {
            StorageError::Provider("multipart part number is out of range".to_owned())
        })?;
        let len = u64::try_from(body.len()).map_err(|_| {
            StorageError::Provider("multipart part length is out of range".to_owned())
        })?;
        let output = self
            .client
            .upload_part()
            .bucket(self.store.config.bucket.as_str())
            .key(self.key.as_str())
            .upload_id(self.upload_id.as_str())
            .part_number(part_number)
            .body(SdkByteStream::from(body))
            .send()
            .await
            .map_err(|error| {
                StorageError::Provider(format!("failed to upload multipart part: {error}"))
            })?;
        let completed = CompletedPart::builder()
            .part_number(part_number)
            .set_e_tag(output.e_tag().map(str::to_owned))
            .build();
        if self.parts.len() <= part_index {
            self.parts
                .resize_with(part_index.saturating_add(1), || None);
        }
        if self.parts[part_index].replace(completed).is_some() {
            return Err(StorageError::Provider(
                "multipart part was uploaded twice".to_owned(),
            ));
        }
        self.content_len = self.content_len.saturating_add(len);
        Ok(())
    }

    async fn complete(self: Box<Self>) -> Result<BlobMetadata> {
        let Self {
            store,
            client,
            object_id,
            key,
            upload_id,
            options,
            parts,
            content_len,
            started,
        } = *self;
        let mut completed = Vec::with_capacity(parts.len());
        for part in parts {
            completed.push(part.ok_or_else(|| {
                StorageError::Provider("multipart upload has missing parts".to_owned())
            })?);
        }
        let multipart = CompletedMultipartUpload::builder()
            .set_parts(Some(completed))
            .build();
        let abort_key = key.clone();
        let abort_upload_id = upload_id.clone();
        let mut request = client
            .complete_multipart_upload()
            .bucket(store.config.bucket.as_str())
            .key(key)
            .upload_id(upload_id)
            .multipart_upload(multipart);
        if options.do_not_recreate {
            request = request.if_none_match("*");
        }
        let output = match request.send().await {
            Ok(output) => output,
            Err(error) => {
                let mapped = errors::map_sdk_put_error(error, &object_id);
                if client
                    .abort_multipart_upload()
                    .bucket(store.config.bucket.as_str())
                    .key(abort_key)
                    .upload_id(abort_upload_id)
                    .send()
                    .await
                    .is_err()
                {
                    record_s3_multipart_abort_failure("complete_failed", "provider");
                }
                return Err(mapped);
            }
        };
        let version_id = output
            .version_id()
            .map(errors::backend_version_id_from_str)
            .transpose()?;
        let requested_retention = options.retention.filter(retention_is_active);
        let requested_legal_hold = provider_legal_hold(options.legal_hold);
        if (requested_retention.is_some() || requested_legal_hold.is_some()) && version_id.is_none()
        {
            return Err(StorageError::MissingVersionId(object_id.clone()));
        }
        let mut metadata = store.head_with_sdk(&object_id, version_id.as_ref()).await?;
        if let Some(retention) = requested_retention {
            if !retention_satisfies(metadata.retention.as_ref(), &retention) {
                store
                    .extend_s3_retention(&object_id, version_id.as_ref(), &retention)
                    .await?;
                metadata = store.head_with_sdk(&object_id, version_id.as_ref()).await?;
            }
            verify_retention(metadata.retention.as_ref(), &retention)?;
        }
        if let Some(legal_hold) = requested_legal_hold {
            if metadata.legal_hold != Some(legal_hold) {
                store
                    .set_s3_legal_hold(&object_id, version_id.as_ref(), legal_hold)
                    .await?;
                metadata = store.head_with_sdk(&object_id, version_id.as_ref()).await?;
            }
            verify_legal_hold(metadata.legal_hold, legal_hold)?;
        }
        metadata.content_len = content_len;
        metadata.etag = output.e_tag().map(str::to_owned).or(metadata.etag);
        metadata.version_id = version_id.or(metadata.version_id);
        let object_kind = object_kind(&object_id);
        store.record_provider_operation(
            S3ProviderOperation::Put,
            object_kind,
            "ok",
            content_len,
            0,
            started.elapsed(),
        )?;
        record_blob_put(
            object_kind,
            usize::try_from(content_len).unwrap_or(usize::MAX),
            options.retention.is_some(),
            "ok",
            started.elapsed(),
        );
        Ok(metadata)
    }

    async fn abort(self: Box<Self>) -> Result<()> {
        let Self {
            store,
            client,
            key,
            upload_id,
            ..
        } = *self;
        client
            .abort_multipart_upload()
            .bucket(store.config.bucket.as_str())
            .key(key)
            .upload_id(upload_id)
            .send()
            .await
            .map_err(|error| {
                StorageError::Provider(format!("failed to abort multipart upload: {error}"))
            })?;
        Ok(())
    }
}

fn record_s3_multipart_abort_failure(phase: &'static str, error_class: &'static str) {
    ::metrics::counter!(
        "rs3_storage_s3_multipart_abort_failures_total",
        "phase" => phase,
        "error_class" => error_class,
    )
    .increment(1);
    tracing::warn!(
        target: "rs3_storage",
        provider = "s3",
        operation = "abort_multipart_upload",
        phase,
        error_class,
        result = "failed",
        "failed to abort incomplete S3 multipart upload",
    );
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

        let mut request = self
            .client
            .put_object()
            .bucket(self.config.bucket.as_str())
            .key(self.config.object_key(object_id))
            .body(SdkByteStream::from(body));
        if options.do_not_recreate {
            request = request.if_none_match("*");
        }
        if let Some(content_type) = options.content_type.as_deref() {
            request = request.content_type(content_type);
        }
        match request.send().await {
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
                    etag: output.e_tag().map(str::to_owned),
                    version_id: output
                        .version_id()
                        .map(backend_version_id_from_str)
                        .transpose()?,
                    retention: None,
                    retain_until_ms: None,
                    legal_hold: None,
                })
            }
            Err(error) => {
                let storage_error = map_sdk_put_error(error, object_id);
                let result = storage_error_result(&storage_error);
                self.record_provider_operation(
                    S3ProviderOperation::Put,
                    object_kind,
                    result,
                    bytes_sent,
                    0,
                    started.elapsed(),
                )?;
                record_blob_put(object_kind, requested_len, false, result, started.elapsed());
                Err(storage_error)
            }
        }
    }

    fn supports_multipart_upload(&self) -> bool {
        true
    }

    async fn create_multipart_upload(
        &self,
        object_id: &BackendObjectId,
        options: PutOptions,
    ) -> Result<Box<dyn BlobMultipartUpload>> {
        let client = self.client.clone();
        if options.do_not_recreate {
            match self.head(object_id).await {
                Ok(_) => return Err(StorageError::AlreadyExists(object_id.clone())),
                Err(StorageError::NotFound(_)) => {}
                Err(error) => return Err(error),
            }
        }

        let key = self.config.object_key(object_id);
        let retention = options
            .retention
            .as_ref()
            .filter(|policy| retention_is_active(policy));
        let legal_hold = provider_legal_hold(options.legal_hold);
        let mut request = client
            .create_multipart_upload()
            .bucket(self.config.bucket.as_str())
            .key(key.clone());
        if let Some(content_type) = options.content_type.as_deref() {
            request = request.content_type(content_type);
        }
        if let Some(retention) = retention {
            request = request
                .object_lock_mode(sdk_object_lock_mode(retention)?)
                .object_lock_retain_until_date(retain_until_date(retention)?);
        }
        if let Some(legal_hold) = legal_hold {
            request = request.object_lock_legal_hold_status(sdk_legal_hold_status(legal_hold));
        }

        let output = request.send().await.map_err(|error| {
            StorageError::Provider(format!("failed to create multipart upload: {error}"))
        })?;
        let upload_id = output.upload_id().ok_or_else(|| {
            StorageError::Provider("S3 CreateMultipartUpload omitted upload id".to_owned())
        })?;

        Ok(Box::new(S3MultipartUpload {
            store: self.clone(),
            client,
            object_id: object_id.clone(),
            key,
            upload_id: upload_id.to_owned(),
            options,
            parts: Vec::new(),
            content_len: 0,
            started: Instant::now(),
        }))
    }

    async fn get_range(&self, object_id: &BackendObjectId, range: ByteRange) -> Result<Bytes> {
        let started = Instant::now();
        let object_kind = object_kind(object_id);

        if let ByteRange::Slice { offset, len: 0 } = range {
            let metadata = match self.head_with_sdk(object_id, None).await {
                Ok(metadata) => metadata,
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
                    record_blob_get(object_kind, range, 0, result, started.elapsed());
                    return Err(error);
                }
            };
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

        let mut request = self
            .client
            .get_object()
            .bucket(self.config.bucket.as_str())
            .key(self.config.object_key(object_id));
        if let Some(range_header) = sdk_range_header(range)? {
            request = request.range(range_header);
        }
        match request.send().await {
            Ok(output) => {
                let body = collect_get_body(output.body, range).await?;
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
                let storage_error = map_sdk_get_error(error, object_id);
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

        let mut request = self
            .client
            .get_object()
            .bucket(self.config.bucket.as_str())
            .key(self.config.object_key(object_id))
            .version_id(version_id.as_str());
        if let Some(range_header) = sdk_range_header(range)? {
            request = request.range(range_header);
        }

        match request.send().await {
            Ok(output) => {
                let body = collect_get_body(output.body, range).await?;
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
                let storage_error = map_sdk_get_error(error, object_id);
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

    async fn open_range_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        range: ByteRange,
    ) -> Result<Box<dyn BlobRead>> {
        if matches!(range, ByteRange::Slice { len: 0, .. }) {
            let body = self.get_range_at(object_id, version_id, range).await?;
            return Ok(crate::read::bytes_blob_read(body, 0));
        }

        let started = Instant::now();
        let object_kind = object_kind(object_id).to_owned();
        let mut request = self
            .client
            .get_object()
            .bucket(self.config.bucket.as_str())
            .key(self.config.object_key(object_id));
        if let Some(version_id) = version_id {
            request = request.version_id(version_id.as_str());
        }
        if let Some(range_header) = sdk_range_header(range)? {
            request = request.range(range_header);
        }

        let output = match request.send().await {
            Ok(output) => output,
            Err(error) => {
                let storage_error = map_sdk_get_error(error, object_id);
                let result = storage_error_result(&storage_error);
                self.record_provider_operation(
                    S3ProviderOperation::Get,
                    &object_kind,
                    result,
                    0,
                    0,
                    started.elapsed(),
                )?;
                record_blob_get(&object_kind, range, 0, result, started.elapsed());
                return Err(storage_error);
            }
        };
        let declared_len = output
            .content_length()
            .ok_or_else(|| {
                StorageError::Provider("S3 GET response omitted Content-Length".to_owned())
            })
            .and_then(|length| {
                u64::try_from(length).map_err(|_| {
                    StorageError::Provider(
                        "S3 GET response Content-Length is out of range".to_owned(),
                    )
                })
            });
        let declared_len = match declared_len {
            Ok(declared_len) => declared_len,
            Err(error) => {
                self.record_provider_operation(
                    S3ProviderOperation::Get,
                    &object_kind,
                    "error",
                    0,
                    0,
                    started.elapsed(),
                )?;
                record_blob_get(&object_kind, range, 0, "error", started.elapsed());
                return Err(error);
            }
        };
        let exact_len = match range {
            ByteRange::Full => declared_len,
            ByteRange::Slice { len, .. } => len,
        };
        if declared_len != exact_len {
            self.record_provider_operation(
                S3ProviderOperation::Get,
                &object_kind,
                "error",
                0,
                0,
                started.elapsed(),
            )?;
            record_blob_get(&object_kind, range, 0, "error", started.elapsed());
            return Err(StorageError::Provider(
                "S3 GET response Content-Length did not match the requested range".to_owned(),
            ));
        }

        Ok(Box::new(ObservedS3Read {
            inner: exact_blob_read(S3ReadSource { body: output.body }, exact_len),
            store: self.clone(),
            object_kind,
            range,
            started,
            bytes_read: 0,
            terminal: false,
        }))
    }

    async fn head(&self, object_id: &BackendObjectId) -> Result<BlobMetadata> {
        let started = Instant::now();
        let object_kind = object_kind(object_id);
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
        result
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
        let mut continuation_token = None;
        let mut entries = Vec::new();

        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(self.config.bucket.as_str());
            if !key_prefix.is_empty() {
                request = request.prefix(key_prefix.as_str());
            }
            if let Some(token) = continuation_token.as_deref() {
                request = request.continuation_token(token);
            }
            match request.send().await {
                Ok(page) => {
                    self.record_provider_operation(
                        S3ProviderOperation::List,
                        object_kind,
                        "ok",
                        0,
                        0,
                        started.elapsed(),
                    )?;
                    for object in page.contents() {
                        let Some(key) = object.key() else {
                            continue;
                        };
                        let Some(object_id) = self.config.object_id_from_key(key)? else {
                            continue;
                        };
                        let content_len = object
                            .size()
                            .and_then(|size| u64::try_from(size).ok())
                            .unwrap_or_default();
                        let modified_at_ms = object
                            .last_modified()
                            .map(|modified_at| modified_at.to_millis())
                            .transpose()
                            .map_err(provider_error)?;
                        entries.push(BlobMetadata {
                            object_id,
                            content_len,
                            modified_at_ms,
                            etag: object.e_tag().map(str::to_owned),
                            version_id: None,
                            retention: None,
                            retain_until_ms: None,
                            legal_hold: None,
                        });
                    }

                    if !page.is_truncated().unwrap_or(false) {
                        break;
                    }
                    continuation_token = page.next_continuation_token().map(str::to_owned);
                    if continuation_token.is_none() {
                        let error = StorageError::Provider(
                            "S3 truncated LIST response omitted the continuation token".to_owned(),
                        );
                        let result = storage_error_result(&error);
                        record_blob_list(object_kind, entries.len(), result, started.elapsed());
                        return Err(error);
                    }
                }
                Err(error) => {
                    let storage_error = StorageError::Provider(error.to_string());
                    let result = storage_error_result(&storage_error);
                    self.record_provider_operation(
                        S3ProviderOperation::List,
                        object_kind,
                        result,
                        0,
                        0,
                        started.elapsed(),
                    )?;
                    record_blob_list(object_kind, entries.len(), result, started.elapsed());
                    return Err(storage_error);
                }
            }
        }

        entries.sort_by(|left, right| left.object_id.cmp(&right.object_id));
        record_blob_list(object_kind, entries.len(), "ok", started.elapsed());
        Ok(entries)
    }

    async fn list_prefix_versions(&self, prefix: &str) -> Result<Vec<BlobMetadata>> {
        let started = Instant::now();
        let object_kind = prefix_kind(prefix);
        let key_prefix = self.config.list_key_prefix(prefix);
        let mut key_marker = None;
        let mut version_id_marker = None;
        let mut entries = Vec::new();

        loop {
            let mut request = self
                .client
                .list_object_versions()
                .bucket(self.config.bucket.as_str());
            if !key_prefix.is_empty() {
                request = request.prefix(key_prefix.as_str());
            }
            if let Some(marker) = key_marker.as_deref() {
                request = request.key_marker(marker);
            }
            if let Some(marker) = version_id_marker.as_deref() {
                request = request.version_id_marker(marker);
            }

            let output = match request.send().await {
                Ok(output) => output,
                Err(error) => {
                    let storage_error =
                        StorageError::Provider(format!("failed to list object versions: {error}"));
                    let result = storage_error_result(&storage_error);
                    self.record_provider_operation(
                        S3ProviderOperation::List,
                        object_kind,
                        result,
                        0,
                        0,
                        started.elapsed(),
                    )?;
                    record_blob_list(object_kind, entries.len(), result, started.elapsed());
                    return Err(storage_error);
                }
            };
            self.record_provider_operation(
                S3ProviderOperation::List,
                object_kind,
                "ok",
                0,
                0,
                started.elapsed(),
            )?;

            for version in output.versions() {
                let Some(key) = version.key() else {
                    continue;
                };
                let Some(object_id) = self.config.object_id_from_key(key)? else {
                    continue;
                };
                let Some(version_id) = version.version_id() else {
                    continue;
                };
                let content_len = version
                    .size()
                    .and_then(|size| u64::try_from(size).ok())
                    .unwrap_or_default();
                let modified_at_ms = version
                    .last_modified()
                    .map(|modified_at| modified_at.to_millis())
                    .transpose()
                    .map_err(provider_error)?;
                entries.push(BlobMetadata {
                    object_id,
                    content_len,
                    modified_at_ms,
                    etag: version.e_tag().map(str::to_owned),
                    version_id: Some(backend_version_id_from_str(version_id)?),
                    retention: None,
                    retain_until_ms: None,
                    legal_hold: None,
                });
            }

            key_marker = output.next_key_marker().map(str::to_owned);
            version_id_marker = output.next_version_id_marker().map(str::to_owned);
            if key_marker.is_none() && version_id_marker.is_none() {
                break;
            }
        }

        entries.sort_by(|left, right| {
            left.object_id
                .cmp(&right.object_id)
                .then_with(|| left.version_id.cmp(&right.version_id))
        });
        record_blob_list(object_kind, entries.len(), "ok", started.elapsed());
        Ok(entries)
    }

    async fn delete(&self, object_id: &BackendObjectId) -> Result<()> {
        let started = Instant::now();
        let object_kind = object_kind(object_id);
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

        match self
            .client
            .delete_object()
            .bucket(self.config.bucket.as_str())
            .key(self.config.object_key(object_id))
            .send()
            .await
        {
            Ok(_) => {
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
                let storage_error = map_sdk_common_error(error, object_id);
                let result = storage_error_result(&storage_error);
                self.record_provider_operation(
                    S3ProviderOperation::Delete,
                    object_kind,
                    result,
                    0,
                    0,
                    started.elapsed(),
                )?;
                record_blob_delete(object_kind, result, started.elapsed());
                Err(storage_error)
            }
        }
    }

    async fn delete_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
    ) -> Result<()> {
        let Some(version_id) = version_id else {
            return self.delete(object_id).await;
        };

        let started = Instant::now();
        let object_kind = object_kind(object_id);
        let metadata = self.head_with_sdk(object_id, Some(version_id)).await?;
        if retention_blocks_delete(metadata.retention.as_ref()) {
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
        if legal_hold_blocks_delete(metadata.legal_hold) {
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

        let result = self
            .client
            .delete_object()
            .bucket(self.config.bucket.as_str())
            .key(self.config.object_key(object_id))
            .version_id(version_id.as_str())
            .send()
            .await
            .map_err(|error| map_sdk_common_error(error, object_id));
        let result_label = match &result {
            Ok(_) => "ok",
            Err(error) => storage_error_result(error),
        };
        self.record_provider_operation(
            S3ProviderOperation::Delete,
            object_kind,
            result_label,
            0,
            0,
            started.elapsed(),
        )?;
        record_blob_delete(object_kind, result_label, started.elapsed());
        result.map(|_| ())
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
    use super::requests::sdk_range_header;
    use super::{S3BlobStore, S3BlobStoreConfig, collect_get_body};
    use crate::{ByteRange, StorageError};
    use aws_sdk_s3::Client;
    use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
    use aws_sdk_s3::primitives::ByteStream;
    use bytes::Bytes;
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
            sdk_range_header(ByteRange::Slice { offset: 10, len: 0 }).map(|_| ()),
            Err(StorageError::InvalidRange)
        );
    }

    #[tokio::test]
    async fn bounded_range_collector_accepts_exact_response_length() {
        let body = collect_get_body(
            ByteStream::from(Bytes::from_static(b"exact")),
            ByteRange::Slice { offset: 7, len: 5 },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(body, Bytes::from_static(b"exact"));
    }

    #[tokio::test]
    async fn bounded_range_collector_rejects_provider_overrun() {
        let result = collect_get_body(
            ByteStream::from(Bytes::from_static(b"too long")),
            ByteRange::Slice { offset: 0, len: 3 },
        )
        .await;

        assert!(matches!(result, Err(StorageError::Provider(_))));
    }

    #[tokio::test]
    async fn bounded_range_collector_rejects_truncated_response() {
        let result = collect_get_body(
            ByteStream::from(Bytes::from_static(b"short")),
            ByteRange::Slice { offset: 0, len: 8 },
        )
        .await;

        assert!(matches!(result, Err(StorageError::Provider(_))));
    }

    #[test]
    fn existing_sdk_client_preserves_store_configuration() {
        let config = S3BlobStoreConfig::new("bucket")
            .unwrap_or_else(|error| panic!("{error}"))
            .with_endpoint_url(Some("http://127.0.0.1:9".to_owned()))
            .with_allow_http(true);
        let sdk_config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .endpoint_url("http://127.0.0.1:9")
            .force_path_style(true)
            .credentials_provider(Credentials::new(
                "rs3-fixture-access-key",
                "rs3-fixture-secret-key",
                None,
                None,
                "rs3-storage-test",
            ))
            .build();
        let store = S3BlobStore::from_client(Client::from_conf(sdk_config), config);

        assert_eq!(store.bucket(), "bucket");
    }
}
