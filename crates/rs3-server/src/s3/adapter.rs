//! Typed S3 service adapter backed by repository operations.

use super::S3BoundaryError;
use super::mapping::{
    ListPage, collect_body_reserving, content_range, etag, i64_len, legal_hold_header,
    legal_hold_output, list_page as map_list_page, logical_path, max_keys, next_body_chunk,
    put_object_legal_hold_request_status, put_object_legal_hold_status,
    put_object_retention_policy, repository_error, resolve_range, retention_headers, timestamp,
    validate_delete_object_request, validate_delete_objects_entry, validate_delete_objects_request,
    validate_get_object_legal_hold_request, validate_get_object_request,
    validate_head_object_request, validate_put_object_request,
};
use super::runtime::RuntimeRepository;
use crate::config::configured_streaming_upload_working_set_bytes;
use crate::{AdminReadinessSource, AdminRuntimeFactsSource, GatewayMode, RuntimeConfig};
use bytes::{Bytes, BytesMut};
use futures_util::{Stream, StreamExt, stream};
use rs3_repository::v2::V2AuthenticatedReadBody;
use rs3_repository::{RepositoryError, RepositoryPutOptions};
use rs3_storage::{ByteRange, StorageError};
use rs3_types::{PublicBucket, RetentionMode};
use s3s::dto::{
    Bucket, DeleteObjectInput, DeleteObjectOutput, DeleteObjectsInput, DeleteObjectsOutput,
    DeletedObject, Error as DeleteObjectError, GetBucketLocationInput, GetBucketLocationOutput,
    GetObjectInput, GetObjectLegalHoldInput, GetObjectLegalHoldOutput, GetObjectOutput,
    HeadBucketInput, HeadBucketOutput, HeadObjectInput, HeadObjectOutput, ListBucketsInput,
    ListBucketsOutput, ListObjectsInput, ListObjectsOutput, ListObjectsV2Input,
    ListObjectsV2Output, ObjectIdentifier, Owner, PutObjectInput, PutObjectLegalHoldInput,
    PutObjectLegalHoldOutput, PutObjectOutput, StreamingBlob,
};
use s3s::stream::{ByteStream, DynByteStream, RemainingLength};
use s3s::{Body, S3, S3Request, S3Response, S3Result, StdError};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::Instrument;

#[derive(Clone)]
pub(super) struct GatewayS3Service {
    mode: GatewayMode,
    public_bucket: PublicBucket,
    repository: RuntimeRepository,
    request_sequence: Arc<AtomicU64>,
    max_put_object_bytes: u64,
    buffered_put_object_bytes: u64,
    backend_multipart_part_bytes: u64,
    streaming_upload_working_set_bytes: u64,
    stream_read_stall_timeout: Duration,
    retention_writes_qualified: bool,
    request_slots: Arc<Semaphore>,
    request_rate_limiter: RequestRateLimiter,
    upload_body_budget: UploadBodyBudget,
    download_body_budget: DownloadBodyBudget,
}

impl GatewayS3Service {
    pub(super) async fn from_config(config: &RuntimeConfig) -> Result<Self, S3BoundaryError> {
        let repository = RuntimeRepository::from_config(config).await?;
        Self::from_repository(config, repository).await
    }

    #[cfg(feature = "k8s")]
    pub(super) async fn from_config_with_writer_fence(
        config: &RuntimeConfig,
        writer_fence: rs3_k8s::WriterFence,
    ) -> Result<Self, S3BoundaryError> {
        let repository =
            RuntimeRepository::from_config_with_writer_fence(config, writer_fence).await?;
        Self::from_repository(config, repository).await
    }

    async fn from_repository(
        config: &RuntimeConfig,
        repository: RuntimeRepository,
    ) -> Result<Self, S3BoundaryError> {
        repository
            .validate_backend_retention(config.repository.retention)
            .await?;
        repository.load_accepted_anchor(config.mode).await?;

        Ok(Self {
            mode: config.mode,
            public_bucket: config.public_bucket.clone(),
            repository,
            request_sequence: Arc::new(AtomicU64::new(0)),
            max_put_object_bytes: config.hardening.max_put_object_bytes,
            buffered_put_object_bytes: config.hardening.buffered_put_object_bytes,
            backend_multipart_part_bytes: config.hardening.backend_multipart_part_bytes,
            streaming_upload_working_set_bytes: configured_streaming_upload_working_set_bytes(
                &config.hardening,
                &config.repository,
            ),
            stream_read_stall_timeout: config.hardening.stream_read_stall_timeout,
            retention_writes_qualified: config.repository.retention.is_some_and(|retention| {
                retention.mode != RetentionMode::None && retention.retain_days > 0
            }),
            request_slots: Arc::new(Semaphore::new(config.hardening.max_concurrent_requests)),
            request_rate_limiter: RequestRateLimiter::new(
                config.hardening.request_rate_limit_per_second,
            ),
            upload_body_budget: UploadBodyBudget::new(
                config.hardening.max_in_flight_upload_body_bytes,
            ),
            download_body_budget: DownloadBodyBudget::new(
                config.hardening.max_in_flight_download_body_bytes,
            ),
        })
    }

    pub(super) fn admin_runtime_facts_source(&self) -> Arc<dyn AdminRuntimeFactsSource> {
        self.repository.admin_facts_source()
    }

    pub(super) fn maintenance_runtime(&self) -> Arc<dyn crate::maintenance::MaintenanceRuntime> {
        self.repository.maintenance_runtime()
    }

    pub(super) fn admin_readiness_source(&self) -> Arc<dyn AdminReadinessSource> {
        self.repository.admin_readiness_source()
    }

    fn next_request_id(&self) -> u64 {
        self.request_sequence.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn request_span(
        &self,
        operation: &'static str,
        request_id: u64,
        bucket: Option<&str>,
    ) -> tracing::Span {
        let bucket_scope = self.bucket_scope(bucket);
        tracing::info_span!(
            target: "rs3_server",
            "s3_request",
            operation,
            request_id,
            bucket_scope,
        )
    }

    fn bucket_scope(&self, bucket: Option<&str>) -> &'static str {
        match bucket {
            None => "none",
            Some(bucket) if bucket == self.public_bucket.as_str() => "configured",
            Some(_) => "other",
        }
    }

    fn record_request_result<T>(
        &self,
        operation: &'static str,
        request_id: u64,
        bucket: Option<&str>,
        elapsed: Duration,
        result: &S3Result<S3Response<T>>,
        default_success_status: http::StatusCode,
    ) {
        let bucket_scope = self.bucket_scope(bucket);
        match result {
            Ok(response) => {
                let status = response.status.unwrap_or(default_success_status);
                record_s3_request_metrics(operation, "ok", status, elapsed);
                tracing::debug!(
                    target: "rs3_server",
                    operation,
                    request_id,
                    bucket_scope,
                    result = "ok",
                    status_code = status.as_u16(),
                    elapsed_us = elapsed_us(elapsed),
                    "S3 request completed",
                );
            }
            Err(error) => {
                let status = error
                    .status_code()
                    .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
                record_s3_request_metrics(operation, "error", status, elapsed);
                if status.is_server_error() {
                    tracing::warn!(
                        target: "rs3_server",
                        operation,
                        request_id,
                        bucket_scope,
                        result = "error",
                        status_code = status.as_u16(),
                        error_code = error.code().as_str(),
                        elapsed_us = elapsed_us(elapsed),
                        "S3 request completed",
                    );
                } else {
                    tracing::info!(
                        target: "rs3_server",
                        operation,
                        request_id,
                        bucket_scope,
                        result = "error",
                        status_code = status.as_u16(),
                        error_code = error.code().as_str(),
                        elapsed_us = elapsed_us(elapsed),
                        "S3 request completed",
                    );
                }
            }
        }
    }

    fn check_bucket(&self, bucket: &str) -> S3Result<()> {
        if bucket == self.public_bucket.as_str() {
            Ok(())
        } else {
            Err(s3s::s3_error!(
                AccessDenied,
                "request targets a bucket that is not served by this gateway"
            ))
        }
    }

    fn check_mutation_allowed(&self) -> S3Result<()> {
        if self.mode.allows_mutation() {
            Ok(())
        } else {
            Err(s3s::s3_error!(
                AccessDenied,
                "restore-readonly gateway mode rejects repository mutations"
            ))
        }
    }

    async fn delete_committed_key(&self, key: String) -> S3Result<()> {
        let key = logical_path(key)?;
        self.repository
            .delete_committed(key)
            .await
            .map(|_outcome| ())
            .map_err(repository_error)
    }

    async fn delete_objects_entry(&self, object: ObjectIdentifier) -> S3Result<()> {
        validate_delete_objects_entry(&object)?;
        self.delete_committed_key(object.key).await
    }

    fn admit_request(&self, operation: &'static str) -> S3Result<OwnedSemaphorePermit> {
        let permit = match self.request_slots.clone().try_acquire_owned() {
            Ok(permit) => Ok(permit),
            Err(_error) => {
                record_s3_admission_rejection(operation, "concurrency");
                Err(s3s::s3_error!(
                    SlowDown,
                    "gateway request concurrency limit exceeded"
                ))
            }
        }?;

        if !self.request_rate_limiter.try_admit() {
            record_s3_admission_rejection(operation, "rate");
            return Err(s3s::s3_error!(
                SlowDown,
                "gateway request rate limit exceeded"
            ));
        }

        Ok(permit)
    }

    fn list_page(
        &self,
        prefix: &str,
        delimiter: Option<&str>,
        start_after: Option<&str>,
        max_keys: usize,
    ) -> S3Result<ListPage> {
        if max_keys == 0 {
            return map_list_page(Vec::new(), prefix, delimiter, start_after, max_keys);
        }

        let mut entries = Vec::new();
        let mut repository_start_after = start_after.map(ToOwned::to_owned);
        loop {
            let repository_entries = self
                .repository
                .list_page(prefix, repository_start_after.as_deref(), max_keys)
                .map_err(repository_error)?;
            let repository_has_more = repository_entries.len() > max_keys;
            let next_repository_start_after = repository_entries
                .last()
                .map(|entry| entry.key.as_str().to_owned());
            entries.extend(repository_entries);

            let page = map_list_page(entries.clone(), prefix, delimiter, start_after, max_keys)?;
            if page.next_continuation_token.is_some() || !repository_has_more {
                return Ok(page);
            }

            let Some(next_repository_start_after) = next_repository_start_after else {
                return Ok(page);
            };
            repository_start_after = Some(next_repository_start_after);
        }
    }
}

#[derive(Clone)]
struct UploadBodyBudget {
    max_bytes: u64,
    state: Arc<Mutex<UploadBodyBudgetState>>,
}

struct UploadBodyBudgetState {
    in_flight_bytes: u64,
}

impl UploadBodyBudget {
    fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            state: Arc::new(Mutex::new(UploadBodyBudgetState { in_flight_bytes: 0 })),
        }
    }

    fn reservation(&self) -> UploadBodyReservation {
        UploadBodyReservation {
            budget: self.clone(),
            reserved_bytes: 0,
        }
    }

    fn try_reserve_additional(
        &self,
        operation: &'static str,
        additional_bytes: u64,
    ) -> S3Result<()> {
        if additional_bytes == 0 {
            return Ok(());
        }

        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_error) => {
                record_s3_admission_rejection(operation, "body_budget");
                return Err(s3s::s3_error!(
                    SlowDown,
                    "gateway upload body budget is unavailable"
                ));
            }
        };
        let next_in_flight = state
            .in_flight_bytes
            .checked_add(additional_bytes)
            .ok_or_else(|| {
                record_s3_admission_rejection(operation, "body_budget");
                s3s::s3_error!(SlowDown, "gateway upload body budget exceeded")
            })?;
        if next_in_flight > self.max_bytes {
            record_s3_admission_rejection(operation, "body_budget");
            return Err(s3s::s3_error!(
                SlowDown,
                "gateway upload body budget exceeded"
            ));
        }
        state.in_flight_bytes = next_in_flight;
        Ok(())
    }

    fn release(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        if let Ok(mut state) = self.state.lock() {
            state.in_flight_bytes = state.in_flight_bytes.saturating_sub(bytes);
        }
    }

    #[cfg(test)]
    fn in_flight_bytes(&self) -> u64 {
        match self.state.lock() {
            Ok(state) => state.in_flight_bytes,
            Err(_error) => 0,
        }
    }
}

struct UploadBodyReservation {
    budget: UploadBodyBudget,
    reserved_bytes: u64,
}

impl UploadBodyReservation {
    fn reserve_until(&mut self, operation: &'static str, body_len: u64) -> S3Result<()> {
        if body_len <= self.reserved_bytes {
            return Ok(());
        }
        let additional_bytes = body_len - self.reserved_bytes;
        self.budget
            .try_reserve_additional(operation, additional_bytes)?;
        self.reserved_bytes = body_len;
        Ok(())
    }

    fn reserve_body_len(&mut self, operation: &'static str, body_len: usize) -> S3Result<()> {
        let body_len = u64::try_from(body_len).unwrap_or(u64::MAX);
        self.reserve_until(operation, body_len)
    }
}

impl Drop for UploadBodyReservation {
    fn drop(&mut self) {
        self.budget.release(self.reserved_bytes);
    }
}

#[derive(Clone)]
struct DownloadBodyBudget {
    max_bytes: u64,
    state: Arc<Mutex<DownloadBodyBudgetState>>,
}

struct DownloadBodyBudgetState {
    in_flight_bytes: u64,
}

impl DownloadBodyBudget {
    fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            state: Arc::new(Mutex::new(DownloadBodyBudgetState { in_flight_bytes: 0 })),
        }
    }

    fn reserve(&self, operation: &'static str, body_len: u64) -> S3Result<DownloadBodyReservation> {
        if body_len == 0 {
            return Ok(DownloadBodyReservation {
                budget: self.clone(),
                reserved_bytes: 0,
            });
        }

        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_error) => {
                record_s3_admission_rejection(operation, "body_budget");
                return Err(s3s::s3_error!(
                    SlowDown,
                    "gateway download body budget is unavailable"
                ));
            }
        };
        let next_in_flight = state.in_flight_bytes.checked_add(body_len).ok_or_else(|| {
            record_s3_admission_rejection(operation, "body_budget");
            s3s::s3_error!(SlowDown, "gateway download body budget exceeded")
        })?;
        if next_in_flight > self.max_bytes {
            record_s3_admission_rejection(operation, "body_budget");
            return Err(s3s::s3_error!(
                SlowDown,
                "gateway download body budget exceeded"
            ));
        }
        state.in_flight_bytes = next_in_flight;

        Ok(DownloadBodyReservation {
            budget: self.clone(),
            reserved_bytes: body_len,
        })
    }

    fn release(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        if let Ok(mut state) = self.state.lock() {
            state.in_flight_bytes = state.in_flight_bytes.saturating_sub(bytes);
        }
    }

    #[cfg(test)]
    fn in_flight_bytes(&self) -> u64 {
        match self.state.lock() {
            Ok(state) => state.in_flight_bytes,
            Err(_error) => 0,
        }
    }
}

struct DownloadBodyReservation {
    budget: DownloadBodyBudget,
    reserved_bytes: u64,
}

impl Drop for DownloadBodyReservation {
    fn drop(&mut self) {
        self.budget.release(self.reserved_bytes);
    }
}

struct ReservedDownloadBody {
    body: Option<Bytes>,
    _reservation: DownloadBodyReservation,
}

impl Stream for ReservedDownloadBody {
    type Item = Result<Bytes, StdError>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let item = match self.body.take() {
            Some(body) if !body.is_empty() => Some(Ok(body)),
            Some(_) | None => None,
        };
        Poll::Ready(item)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.body.as_ref().map(Bytes::len).unwrap_or(0);
        (len, Some(len))
    }
}

impl ByteStream for ReservedDownloadBody {
    fn remaining_length(&self) -> RemainingLength {
        RemainingLength::new_exact(self.body.as_ref().map(Bytes::len).unwrap_or(0))
    }
}

fn reserved_download_body(body: Bytes, reservation: DownloadBodyReservation) -> Body {
    Body::from(Box::pin(ReservedDownloadBody {
        body: Some(body),
        _reservation: reservation,
    }) as DynByteStream)
}

struct ReservedAuthenticatedDownloadBody {
    body: Mutex<V2AuthenticatedReadBody>,
    remaining: Option<usize>,
    operation: &'static str,
    _reservation: DownloadBodyReservation,
}

impl Stream for ReservedAuthenticatedDownloadBody {
    type Item = Result<Bytes, StdError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let polled = {
            let mut body = match self.body.lock() {
                Ok(body) => body,
                Err(_) => {
                    return Poll::Ready(Some(Err(Box::new(std::io::Error::other(
                        "authenticated download body lock poisoned",
                    )))));
                }
            };
            Pin::new(&mut *body).poll_next(cx)
        };
        match polled {
            Poll::Ready(Some(Ok(chunk))) => {
                if let Some(remaining) = self.remaining.as_mut() {
                    *remaining = remaining.saturating_sub(chunk.len());
                }
                record_s3_response_body_bytes(self.operation, chunk.len());
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.remaining = Some(0);
                Poll::Ready(Some(Err(Box::new(error))))
            }
            Poll::Ready(None) => {
                self.remaining = Some(0);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl ByteStream for ReservedAuthenticatedDownloadBody {
    fn remaining_length(&self) -> RemainingLength {
        self.remaining
            .map_or_else(RemainingLength::unknown, RemainingLength::new_exact)
    }
}

fn reserved_authenticated_download_body(
    body: V2AuthenticatedReadBody,
    reservation: DownloadBodyReservation,
    operation: &'static str,
) -> Body {
    let remaining = usize::try_from(body.content_len()).ok();
    Body::from(Box::pin(ReservedAuthenticatedDownloadBody {
        body: Mutex::new(body),
        remaining,
        operation,
        _reservation: reservation,
    }) as DynByteStream)
}

#[derive(Clone)]
struct RequestRateLimiter {
    max_per_second: u64,
    state: Arc<Mutex<RequestRateLimiterState>>,
}

struct RequestRateLimiterState {
    tokens: u64,
    last_refill: Instant,
}

impl RequestRateLimiter {
    fn new(max_per_second: u64) -> Self {
        Self {
            max_per_second,
            state: Arc::new(Mutex::new(RequestRateLimiterState {
                tokens: max_per_second,
                last_refill: Instant::now(),
            })),
        }
    }

    fn try_admit(&self) -> bool {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_error) => return false,
        };
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(state.last_refill);
        let refill = elapsed
            .as_nanos()
            .saturating_mul(u128::from(self.max_per_second))
            / 1_000_000_000;
        if refill > 0 {
            let refill = u64::try_from(refill).unwrap_or(u64::MAX);
            state.tokens = state.tokens.saturating_add(refill).min(self.max_per_second);
            state.last_refill = now;
        }
        if state.tokens == 0 {
            return false;
        }
        state.tokens -= 1;
        true
    }
}

#[async_trait::async_trait]
impl S3 for GatewayS3Service {
    async fn head_bucket(
        &self,
        req: S3Request<HeadBucketInput>,
    ) -> S3Result<S3Response<HeadBucketOutput>> {
        const OPERATION: &str = "HeadBucket";
        let request_id = self.next_request_id();
        let started = Instant::now();
        let input = req.input;
        let bucket = input.bucket.clone();
        let span = self.request_span(OPERATION, request_id, Some(&bucket));

        let result = async {
            let _admission = self.admit_request(OPERATION)?;
            self.check_bucket(&input.bucket)?;
            Ok(S3Response::new(HeadBucketOutput::default()))
        }
        .instrument(span)
        .await;
        self.record_request_result(
            OPERATION,
            request_id,
            Some(&bucket),
            started.elapsed(),
            &result,
            http::StatusCode::OK,
        );
        result
    }

    async fn list_buckets(
        &self,
        _req: S3Request<ListBucketsInput>,
    ) -> S3Result<S3Response<ListBucketsOutput>> {
        const OPERATION: &str = "ListBuckets";
        let request_id = self.next_request_id();
        let started = Instant::now();
        let span = self.request_span(OPERATION, request_id, None);

        let result = async {
            let _admission = self.admit_request(OPERATION)?;
            Ok(S3Response::new(ListBucketsOutput {
                buckets: Some(vec![Bucket {
                    name: Some(self.public_bucket.as_str().to_owned()),
                    ..Bucket::default()
                }]),
                owner: Some(Owner {
                    display_name: Some("rs3".to_owned()),
                    id: Some("rs3".to_owned()),
                }),
                ..ListBucketsOutput::default()
            }))
        }
        .instrument(span)
        .await;
        self.record_request_result(
            OPERATION,
            request_id,
            None,
            started.elapsed(),
            &result,
            http::StatusCode::OK,
        );
        result
    }

    async fn get_bucket_location(
        &self,
        req: S3Request<GetBucketLocationInput>,
    ) -> S3Result<S3Response<GetBucketLocationOutput>> {
        const OPERATION: &str = "GetBucketLocation";
        let request_id = self.next_request_id();
        let started = Instant::now();
        let input = req.input;
        let bucket = input.bucket.clone();
        let span = self.request_span(OPERATION, request_id, Some(&bucket));

        let result = async {
            let _admission = self.admit_request(OPERATION)?;
            self.check_bucket(&input.bucket)?;
            Ok(S3Response::new(GetBucketLocationOutput {
                location_constraint: None,
            }))
        }
        .instrument(span)
        .await;
        self.record_request_result(
            OPERATION,
            request_id,
            Some(&bucket),
            started.elapsed(),
            &result,
            http::StatusCode::OK,
        );
        result
    }

    async fn put_object(
        &self,
        req: S3Request<PutObjectInput>,
    ) -> S3Result<S3Response<PutObjectOutput>> {
        const OPERATION: &str = "PutObject";
        let request_id = self.next_request_id();
        let started = Instant::now();
        let input = req.input;
        let bucket = input.bucket.clone();
        let span = self.request_span(OPERATION, request_id, Some(&bucket));

        let result = async {
            let _admission = self.admit_request(OPERATION)?;
            self.check_bucket(&input.bucket)?;
            self.check_mutation_allowed()?;
            validate_put_object_request(&input, self.max_put_object_bytes)?;

            let retention = put_object_retention_policy(&input)?;
            let legal_hold = put_object_legal_hold_status(&input)?;
            if retention.is_some() && !self.retention_writes_qualified {
                return Err(repository_error(RepositoryError::Storage(
                    StorageError::RetentionExtensionUnsupported,
                )));
            }
            if legal_hold.is_some() {
                return Err(s3s::s3_error!(
                    NotImplemented,
                    "v02 legal hold publication is not supported"
                ));
            }
            let key = logical_path(input.key)?;
            let create_only = match input.if_none_match.as_ref() {
                Some(s3s::dto::ETagCondition::Any) => true,
                Some(s3s::dto::ETagCondition::ETag(_)) => {
                    return Err(s3s::s3_error!(
                        InvalidRequest,
                        "only If-None-Match: * is supported"
                    ));
                }
                None => false,
            };
            let declared_len = input
                .content_length
                .map(|content_length| {
                    u64::try_from(content_length).map_err(|_| {
                        s3s::s3_error!(
                            InvalidRequest,
                            "Content-Length must be a non-negative integer"
                        )
                    })
                })
                .transpose()?;
            if declared_len.is_some_and(|len| len > self.buffered_put_object_bytes) {
                if !self.repository.supports_streaming_put() {
                    return Err(s3s::s3_error!(
                        NotImplemented,
                        "large PutObject requires backend multipart upload support"
                    ));
                }
                let declared_len = declared_len.ok_or_else(|| {
                    s3s::s3_error!(
                        InvalidRequest,
                        "Content-Length is required for large streaming PutObject"
                    )
                })?;
                let mut upload_body_reservation = self.upload_body_budget.reservation();
                upload_body_reservation
                    .reserve_until(OPERATION, self.streaming_upload_working_set_bytes)?;
                let body = input
                    .body
                    .unwrap_or_else(|| StreamingBlob::from(Body::from(Bytes::new())));
                let stream =
                    body.map(|chunk| chunk.map_err(|_error| RepositoryError::ObjectBodyReadFailed));
                let committed = self
                    .repository
                    .put_committed_streaming_known_len(
                        key,
                        declared_len,
                        stream,
                        RepositoryPutOptions {
                            create_only,
                            retention,
                            legal_hold,
                        },
                        usize::try_from(self.backend_multipart_part_bytes).map_err(|_| {
                            s3s::s3_error!(
                                InvalidRequest,
                                "backend multipart part size exceeds platform limits"
                            )
                        })?,
                    )
                    .await
                    .map_err(repository_error)?;
                record_s3_request_body_bytes(
                    OPERATION,
                    usize::try_from(declared_len).unwrap_or(usize::MAX),
                );

                return Ok(S3Response::new(PutObjectOutput {
                    e_tag: Some(etag(
                        committed.metadata.content_len,
                        committed.metadata.modified_at_ms,
                    )),
                    ..PutObjectOutput::default()
                }));
            }
            if declared_len.is_none() && self.repository.supports_streaming_put() {
                let body_collect_started = Instant::now();
                let mut upload_body_reservation = self.upload_body_budget.reservation();
                let mut body = input
                    .body
                    .unwrap_or_else(|| StreamingBlob::from(Body::from(Bytes::new())));
                let mut buffered = BytesMut::new();
                while let Some(chunk) =
                    next_body_chunk(&mut body, self.stream_read_stall_timeout).await?
                {
                    let next_len = buffered.len().checked_add(chunk.len()).ok_or_else(|| {
                        s3s::s3_error!(
                            EntityTooLarge,
                            "PutObject body exceeds the configured maximum size"
                        )
                    })?;
                    if u64::try_from(next_len).unwrap_or(u64::MAX) > self.max_put_object_bytes {
                        return Err(s3s::s3_error!(
                            EntityTooLarge,
                            "PutObject body exceeds the configured maximum size"
                        ));
                    }
                    let buffered_len = u64::try_from(buffered.len()).unwrap_or(u64::MAX);
                    let chunk_len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
                    let remaining_buffer_capacity =
                        self.buffered_put_object_bytes.saturating_sub(buffered_len);
                    if chunk_len <= remaining_buffer_capacity {
                        upload_body_reservation.reserve_body_len(OPERATION, next_len)?;
                        buffered.extend_from_slice(&chunk);
                        continue;
                    }

                    let prefix_len = usize::try_from(remaining_buffer_capacity).map_err(|_| {
                        s3s::s3_error!(
                            InvalidRequest,
                            "buffered PutObject threshold exceeds platform limits"
                        )
                    })?;
                    let transition_buffered_len =
                        buffered.len().checked_add(prefix_len).ok_or_else(|| {
                            s3s::s3_error!(
                                EntityTooLarge,
                                "PutObject body exceeds the configured maximum size"
                            )
                        })?;
                    let streaming_budget = self
                        .streaming_upload_working_set_bytes
                        .saturating_add(u64::try_from(transition_buffered_len).unwrap_or(u64::MAX));
                    upload_body_reservation.reserve_until(OPERATION, streaming_budget)?;
                    buffered.extend_from_slice(&chunk[..prefix_len]);
                    let prefix = buffered.freeze();
                    let remainder = chunk.slice(prefix_len..);
                    let initial = [prefix, remainder]
                        .into_iter()
                        .filter(|chunk| !chunk.is_empty())
                        .map(Ok::<Bytes, RepositoryError>);
                    let stream = stream::iter(initial).chain(body.map(|chunk| {
                        chunk.map_err(|_error| RepositoryError::ObjectBodyReadFailed)
                    }));
                    let committed = self
                        .repository
                        .put_committed_streaming_unknown_len(
                            key,
                            stream,
                            RepositoryPutOptions {
                                create_only,
                                retention,
                                legal_hold,
                            },
                            usize::try_from(self.backend_multipart_part_bytes).map_err(|_| {
                                s3s::s3_error!(
                                    InvalidRequest,
                                    "backend multipart part size exceeds platform limits"
                                )
                            })?,
                            self.max_put_object_bytes,
                        )
                        .await
                        .map_err(repository_error)?;
                    record_s3_request_body_bytes(
                        OPERATION,
                        usize::try_from(committed.metadata.content_len).unwrap_or(usize::MAX),
                    );

                    return Ok(S3Response::new(PutObjectOutput {
                        e_tag: Some(etag(
                            committed.metadata.content_len,
                            committed.metadata.modified_at_ms,
                        )),
                        ..PutObjectOutput::default()
                    }));
                }
                let body_collect_elapsed = body_collect_started.elapsed();
                record_s3_request_body_collect_metrics(OPERATION, body_collect_elapsed);
                let body = buffered.freeze();
                record_s3_request_body_bytes(OPERATION, body.len());
                tracing::debug!(
                    target: "rs3_server",
                    operation = OPERATION,
                    request_id,
                    request_body_bytes = body.len(),
                    request_body_collect_elapsed_us = elapsed_us(body_collect_elapsed),
                    create_only,
                    "S3 request body collected",
                );

                let committed = self
                    .repository
                    .put_committed(
                        key,
                        body,
                        RepositoryPutOptions {
                            create_only,
                            retention,
                            legal_hold,
                        },
                    )
                    .await
                    .map_err(repository_error)?;

                return Ok(S3Response::new(PutObjectOutput {
                    e_tag: Some(etag(
                        committed.metadata.content_len,
                        committed.metadata.modified_at_ms,
                    )),
                    ..PutObjectOutput::default()
                }));
            }
            let body_collect_started = Instant::now();
            let mut upload_body_reservation = self.upload_body_budget.reservation();
            if let Some(declared_len) = declared_len {
                upload_body_reservation.reserve_until(OPERATION, declared_len)?;
            }
            let collect_limit = if input.content_length.is_some() {
                self.max_put_object_bytes
            } else {
                self.buffered_put_object_bytes
            };
            let body = collect_body_reserving(
                input.body,
                collect_limit,
                self.stream_read_stall_timeout,
                |body_len| upload_body_reservation.reserve_body_len(OPERATION, body_len),
            )
            .await;
            let body_collect_elapsed = body_collect_started.elapsed();
            record_s3_request_body_collect_metrics(OPERATION, body_collect_elapsed);
            let body = body?;
            record_s3_request_body_bytes(OPERATION, body.len());
            tracing::debug!(
                target: "rs3_server",
                operation = OPERATION,
                request_id,
                request_body_bytes = body.len(),
                request_body_collect_elapsed_us = elapsed_us(body_collect_elapsed),
                create_only,
                "S3 request body collected",
            );

            let committed = self
                .repository
                .put_committed(
                    key,
                    body,
                    RepositoryPutOptions {
                        create_only,
                        retention,
                        legal_hold,
                    },
                )
                .await
                .map_err(repository_error)?;

            Ok(S3Response::new(PutObjectOutput {
                e_tag: Some(etag(
                    committed.metadata.content_len,
                    committed.metadata.modified_at_ms,
                )),
                ..PutObjectOutput::default()
            }))
        }
        .instrument(span)
        .await;
        self.record_request_result(
            OPERATION,
            request_id,
            Some(&bucket),
            started.elapsed(),
            &result,
            http::StatusCode::OK,
        );
        result
    }

    async fn get_object(
        &self,
        req: S3Request<GetObjectInput>,
    ) -> S3Result<S3Response<GetObjectOutput>> {
        const OPERATION: &str = "GetObject";
        let request_id = self.next_request_id();
        let started = Instant::now();
        let input = req.input;
        let bucket = input.bucket.clone();
        let span = self.request_span(OPERATION, request_id, Some(&bucket));

        let result = async {
            let _admission = self.admit_request(OPERATION)?;
            self.check_bucket(&input.bucket)?;
            validate_get_object_request(&input)?;

            let requested_range = input.range.is_some();
            let key = logical_path(input.key)?;
            let resolved = self
                .repository
                .resolve_object(&key)
                .map_err(repository_error)?;
            let metadata = resolved.metadata().clone();
            let resolved_range = resolve_range(input.range, metadata.content_len)?;
            let response_body_len = match resolved_range.as_ref() {
                Some(range) => range.end - range.start,
                None => metadata.content_len,
            };
            let authenticated_stream = if resolved_range.is_none() {
                self.repository
                    .get_resolved_full_stream(&resolved)
                    .await
                    .map_err(repository_error)?
            } else {
                None
            };
            let (response_body, streamed) = match authenticated_stream {
                Some(body) => {
                    let reservation = self
                        .download_body_budget
                        .reserve(OPERATION, body.working_set_bytes())?;
                    (
                        reserved_authenticated_download_body(body, reservation, OPERATION),
                        true,
                    )
                }
                None => {
                    let reservation = self
                        .download_body_budget
                        .reserve(OPERATION, response_body_len)?;
                    let repository_range =
                        repository_read_range(resolved_range.as_ref(), metadata.content_len);
                    let body = self
                        .repository
                        .get_resolved_range(&resolved, repository_range)
                        .await
                        .map_err(repository_error)?;
                    record_s3_response_body_bytes(OPERATION, body.len());
                    (reserved_download_body(body, reservation), false)
                }
            };

            tracing::debug!(
                target: "rs3_server",
                operation = OPERATION,
                request_id,
                requested_range,
                response_body_bytes = response_body_len,
                streamed,
                "S3 response body prepared",
            );
            let content_length = i64_len(response_body_len)?;
            let mut output = GetObjectOutput {
                accept_ranges: Some("bytes".to_owned()),
                body: Some(StreamingBlob::from(response_body)),
                content_length: Some(content_length),
                content_type: Some("application/octet-stream".to_owned()),
                e_tag: Some(etag(metadata.content_len, metadata.modified_at_ms)),
                last_modified: Some(timestamp(metadata.modified_at_ms)?),
                ..GetObjectOutput::default()
            };
            let (object_lock_mode, object_lock_retain_until_date) =
                retention_headers(metadata.retention.as_ref(), metadata.modified_at_ms)?;
            output.object_lock_mode = object_lock_mode;
            output.object_lock_retain_until_date = object_lock_retain_until_date;
            output.object_lock_legal_hold_status = legal_hold_header(metadata.legal_hold);

            let response = if let Some(range) = resolved_range {
                output.content_range =
                    Some(content_range(range.start, range.end, metadata.content_len));
                S3Response::with_status(output, http::StatusCode::PARTIAL_CONTENT)
            } else {
                S3Response::new(output)
            };

            Ok(response)
        }
        .instrument(span)
        .await;
        self.record_request_result(
            OPERATION,
            request_id,
            Some(&bucket),
            started.elapsed(),
            &result,
            http::StatusCode::OK,
        );
        result
    }

    async fn head_object(
        &self,
        req: S3Request<HeadObjectInput>,
    ) -> S3Result<S3Response<HeadObjectOutput>> {
        const OPERATION: &str = "HeadObject";
        let request_id = self.next_request_id();
        let started = Instant::now();
        let input = req.input;
        let bucket = input.bucket.clone();
        let span = self.request_span(OPERATION, request_id, Some(&bucket));

        let result = async {
            let _admission = self.admit_request(OPERATION)?;
            self.check_bucket(&input.bucket)?;
            validate_head_object_request(&input)?;

            let requested_range = input.range.is_some();
            let key = logical_path(input.key)?;
            let metadata = self.repository.head(&key).map_err(repository_error)?;
            let content_length = match resolve_range(input.range, metadata.content_len)? {
                Some(range) => range.end - range.start,
                None => metadata.content_len,
            };

            tracing::debug!(
                target: "rs3_server",
                operation = OPERATION,
                request_id,
                requested_range,
                content_length,
                "S3 object metadata prepared",
            );
            let (object_lock_mode, object_lock_retain_until_date) =
                retention_headers(metadata.retention.as_ref(), metadata.modified_at_ms)?;
            Ok(S3Response::new(HeadObjectOutput {
                accept_ranges: Some("bytes".to_owned()),
                content_length: Some(i64_len(content_length)?),
                content_type: Some("application/octet-stream".to_owned()),
                e_tag: Some(etag(metadata.content_len, metadata.modified_at_ms)),
                last_modified: Some(timestamp(metadata.modified_at_ms)?),
                object_lock_mode,
                object_lock_retain_until_date,
                object_lock_legal_hold_status: legal_hold_header(metadata.legal_hold),
                ..HeadObjectOutput::default()
            }))
        }
        .instrument(span)
        .await;
        self.record_request_result(
            OPERATION,
            request_id,
            Some(&bucket),
            started.elapsed(),
            &result,
            http::StatusCode::OK,
        );
        result
    }

    async fn get_object_legal_hold(
        &self,
        req: S3Request<GetObjectLegalHoldInput>,
    ) -> S3Result<S3Response<GetObjectLegalHoldOutput>> {
        const OPERATION: &str = "GetObjectLegalHold";
        let request_id = self.next_request_id();
        let started = Instant::now();
        let input = req.input;
        let bucket = input.bucket.clone();
        let span = self.request_span(OPERATION, request_id, Some(&bucket));

        let result = async {
            let _admission = self.admit_request(OPERATION)?;
            self.check_bucket(&input.bucket)?;
            validate_get_object_legal_hold_request(&input)?;

            let key = logical_path(input.key)?;
            let metadata = self.repository.head(&key).map_err(repository_error)?;
            Ok(S3Response::new(GetObjectLegalHoldOutput {
                legal_hold: Some(legal_hold_output(metadata.legal_hold)),
            }))
        }
        .instrument(span)
        .await;
        self.record_request_result(
            OPERATION,
            request_id,
            Some(&bucket),
            started.elapsed(),
            &result,
            http::StatusCode::OK,
        );
        result
    }

    async fn put_object_legal_hold(
        &self,
        req: S3Request<PutObjectLegalHoldInput>,
    ) -> S3Result<S3Response<PutObjectLegalHoldOutput>> {
        const OPERATION: &str = "PutObjectLegalHold";
        let request_id = self.next_request_id();
        let started = Instant::now();
        let input = req.input;
        let bucket = input.bucket.clone();
        let span = self.request_span(OPERATION, request_id, Some(&bucket));

        let result = async {
            let _admission = self.admit_request(OPERATION)?;
            self.check_bucket(&input.bucket)?;
            self.check_mutation_allowed()?;
            let _ = put_object_legal_hold_request_status(&input)?;
            Err(s3s::s3_error!(
                NotImplemented,
                "v02 legal hold publication is not supported"
            ))
        }
        .instrument(span)
        .await;
        self.record_request_result(
            OPERATION,
            request_id,
            Some(&bucket),
            started.elapsed(),
            &result,
            http::StatusCode::OK,
        );
        result
    }

    async fn list_objects(
        &self,
        req: S3Request<ListObjectsInput>,
    ) -> S3Result<S3Response<ListObjectsOutput>> {
        const OPERATION: &str = "ListObjects";
        let request_id = self.next_request_id();
        let started = Instant::now();
        let input = req.input;
        let bucket = input.bucket.clone();
        let span = self.request_span(OPERATION, request_id, Some(&bucket));

        let result = async {
            let _admission = self.admit_request(OPERATION)?;
            self.check_bucket(&input.bucket)?;

            let prefix = input.prefix.unwrap_or_default();
            let prefix_present = !prefix.is_empty();
            let max_keys = max_keys(input.max_keys)?;
            let marker = input.marker;
            let delimiter = input.delimiter;
            let page =
                self.list_page(&prefix, delimiter.as_deref(), marker.as_deref(), max_keys)?;

            tracing::debug!(
                target: "rs3_server",
                operation = OPERATION,
                request_id,
                prefix_present,
                max_keys,
                key_count = page.key_count,
                common_prefixes = page.common_prefixes.len(),
                is_truncated = page.next_continuation_token.is_some(),
                "S3 list page prepared",
            );
            Ok(S3Response::new(ListObjectsOutput {
                name: Some(input.bucket),
                prefix: Some(prefix),
                marker,
                max_keys: Some(i32::try_from(max_keys).unwrap_or(i32::MAX)),
                is_truncated: Some(page.next_continuation_token.is_some()),
                contents: (!page.contents.is_empty()).then_some(page.contents),
                common_prefixes: (!page.common_prefixes.is_empty()).then_some(page.common_prefixes),
                delimiter,
                next_marker: page.next_continuation_token,
                ..ListObjectsOutput::default()
            }))
        }
        .instrument(span)
        .await;
        self.record_request_result(
            OPERATION,
            request_id,
            Some(&bucket),
            started.elapsed(),
            &result,
            http::StatusCode::OK,
        );
        result
    }

    async fn list_objects_v2(
        &self,
        req: S3Request<ListObjectsV2Input>,
    ) -> S3Result<S3Response<ListObjectsV2Output>> {
        const OPERATION: &str = "ListObjectsV2";
        let request_id = self.next_request_id();
        let started = Instant::now();
        let input = req.input;
        let bucket = input.bucket.clone();
        let span = self.request_span(OPERATION, request_id, Some(&bucket));

        let result = async {
            let _admission = self.admit_request(OPERATION)?;
            self.check_bucket(&input.bucket)?;

            let prefix = input.prefix.unwrap_or_default();
            let prefix_present = !prefix.is_empty();
            let max_keys = max_keys(input.max_keys)?;
            let start_after = input.continuation_token.or(input.start_after);
            let delimiter = input.delimiter;
            let page = self.list_page(
                &prefix,
                delimiter.as_deref(),
                start_after.as_deref(),
                max_keys,
            )?;

            tracing::debug!(
                target: "rs3_server",
                operation = OPERATION,
                request_id,
                prefix_present,
                max_keys,
                key_count = page.key_count,
                common_prefixes = page.common_prefixes.len(),
                is_truncated = page.next_continuation_token.is_some(),
                "S3 list page prepared",
            );
            Ok(S3Response::new(ListObjectsV2Output {
                name: Some(input.bucket),
                prefix: Some(prefix),
                max_keys: Some(i32::try_from(max_keys).unwrap_or(i32::MAX)),
                key_count: Some(i32::try_from(page.key_count).unwrap_or(i32::MAX)),
                is_truncated: Some(page.next_continuation_token.is_some()),
                next_continuation_token: page.next_continuation_token,
                contents: (!page.contents.is_empty()).then_some(page.contents),
                common_prefixes: (!page.common_prefixes.is_empty()).then_some(page.common_prefixes),
                delimiter,
                start_after,
                ..ListObjectsV2Output::default()
            }))
        }
        .instrument(span)
        .await;
        self.record_request_result(
            OPERATION,
            request_id,
            Some(&bucket),
            started.elapsed(),
            &result,
            http::StatusCode::OK,
        );
        result
    }

    async fn delete_object(
        &self,
        req: S3Request<DeleteObjectInput>,
    ) -> S3Result<S3Response<DeleteObjectOutput>> {
        const OPERATION: &str = "DeleteObject";
        let request_id = self.next_request_id();
        let started = Instant::now();
        let input = req.input;
        let bucket = input.bucket.clone();
        let span = self.request_span(OPERATION, request_id, Some(&bucket));

        let result = async {
            let _admission = self.admit_request(OPERATION)?;
            self.check_bucket(&input.bucket)?;
            self.check_mutation_allowed()?;
            validate_delete_object_request(&input)?;

            self.delete_committed_key(input.key).await?;

            Ok(S3Response::new(DeleteObjectOutput {
                delete_marker: Some(false),
                ..DeleteObjectOutput::default()
            }))
        }
        .instrument(span)
        .await;
        self.record_request_result(
            OPERATION,
            request_id,
            Some(&bucket),
            started.elapsed(),
            &result,
            http::StatusCode::OK,
        );
        result
    }

    async fn delete_objects(
        &self,
        req: S3Request<DeleteObjectsInput>,
    ) -> S3Result<S3Response<DeleteObjectsOutput>> {
        const OPERATION: &str = "DeleteObjects";
        let request_id = self.next_request_id();
        let started = Instant::now();
        let input = req.input;
        let bucket = input.bucket.clone();
        let span = self.request_span(OPERATION, request_id, Some(&bucket));

        let result = async {
            let _admission = self.admit_request(OPERATION)?;
            self.check_bucket(&input.bucket)?;
            self.check_mutation_allowed()?;
            validate_delete_objects_request(&input)?;

            let quiet = input.delete.quiet.unwrap_or(false);
            let mut deleted = Vec::new();
            let mut errors = Vec::new();
            for object in input.delete.objects {
                let key = object.key.clone();
                match self.delete_objects_entry(object).await {
                    Ok(()) => {
                        if !quiet {
                            deleted.push(DeletedObject {
                                delete_marker: Some(false),
                                key: Some(key),
                                ..DeletedObject::default()
                            });
                        }
                    }
                    Err(error) => errors.push(delete_objects_error(key, error)),
                }
            }

            Ok(S3Response::new(DeleteObjectsOutput {
                deleted: (!deleted.is_empty()).then_some(deleted),
                errors: (!errors.is_empty()).then_some(errors),
                ..DeleteObjectsOutput::default()
            }))
        }
        .instrument(span)
        .await;
        self.record_request_result(
            OPERATION,
            request_id,
            Some(&bucket),
            started.elapsed(),
            &result,
            http::StatusCode::OK,
        );
        result
    }
}

fn delete_objects_error(key: String, error: s3s::S3Error) -> DeleteObjectError {
    DeleteObjectError {
        code: Some(error.code().as_str().to_owned()),
        key: Some(key),
        message: error.message().map(str::to_owned),
        ..DeleteObjectError::default()
    }
}

fn elapsed_us(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
}

fn record_s3_request_metrics(
    operation: &'static str,
    result: &'static str,
    status: http::StatusCode,
    elapsed: Duration,
) {
    let status_code = status_code_label(status);
    metrics::counter!(
        "rs3_s3_requests_total",
        "operation" => operation,
        "result" => result,
        "status_code" => status_code,
    )
    .increment(1);
    metrics::histogram!(
        "rs3_s3_request_duration_seconds",
        "operation" => operation,
        "result" => result,
        "status_code" => status_code,
    )
    .record(elapsed.as_secs_f64());
}

fn status_code_label(status: http::StatusCode) -> &'static str {
    match status.as_u16() {
        200 => "200",
        206 => "206",
        400 => "400",
        401 => "401",
        403 => "403",
        404 => "404",
        405 => "405",
        409 => "409",
        411 => "411",
        412 => "412",
        416 => "416",
        500 => "500",
        501 => "501",
        503 => "503",
        _ => "unknown",
    }
}

fn record_s3_admission_rejection(operation: &'static str, reason: &'static str) {
    metrics::counter!(
        "rs3_s3_request_admission_rejections_total",
        "operation" => operation,
        "reason" => reason,
    )
    .increment(1);
}

fn repository_read_range(range: Option<&std::ops::Range<u64>>, content_len: u64) -> ByteRange {
    match range {
        Some(range) if range.start == 0 && range.end == content_len => ByteRange::Full,
        Some(range) => ByteRange::Slice {
            offset: range.start,
            len: range.end - range.start,
        },
        None => ByteRange::Full,
    }
}

fn record_s3_request_body_bytes(operation: &'static str, len: usize) {
    metrics::counter!(
        "rs3_s3_request_body_bytes_total",
        "operation" => operation,
    )
    .increment(u64::try_from(len).unwrap_or(u64::MAX));
}

fn record_s3_request_body_collect_metrics(operation: &'static str, elapsed: Duration) {
    metrics::histogram!(
        "rs3_s3_request_body_collect_duration_seconds",
        "operation" => operation,
    )
    .record(elapsed.as_secs_f64());
}

fn record_s3_response_body_bytes(operation: &'static str, len: usize) {
    metrics::counter!(
        "rs3_s3_response_body_bytes_total",
        "operation" => operation,
    )
    .increment(u64::try_from(len).unwrap_or(u64::MAX));
}

#[cfg(test)]
mod tests {
    use super::{
        DownloadBodyBudget, GatewayS3Service, RequestRateLimiter, UploadBodyBudget,
        status_code_label,
    };
    use crate::GatewayMode;
    use crate::config::configured_streaming_upload_working_set_bytes;
    use crate::s3::mapping::collect_body;
    use crate::s3::test_support::runtime_config;
    use bytes::Bytes;
    use rs3_repository::v2::V2CommitAnchor;
    use rs3_storage::BlobStore;
    use rs3_types::RetentionMode;
    use s3s::dto::{
        Delete, DeleteObjectInput, DeleteObjectsInput, GetBucketLocationInput, GetObjectInput,
        GetObjectLegalHoldInput, HeadBucketInput, HeadObjectInput, ListBucketsInput,
        ListObjectsInput, ListObjectsV2Input, ObjectIdentifier, ObjectLockLegalHold,
        ObjectLockLegalHoldStatus, ObjectLockMode, PutObjectInput, PutObjectLegalHoldInput,
        StreamingBlob, Timestamp,
    };
    use s3s::{Body, S3, S3Request, S3Response};
    use std::time::{Duration, SystemTime};

    async fn gateway_service() -> GatewayS3Service {
        GatewayS3Service::from_config(&runtime_config(true))
            .await
            .unwrap_or_else(|error| {
                panic!("{error}");
            })
    }

    async fn retained_gateway_service() -> GatewayS3Service {
        let mut config = runtime_config(true);
        config.repository.retention = Some(rs3_types::RetentionPolicy::new(
            RetentionMode::Governance,
            1,
        ));
        GatewayS3Service::from_config(&config)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
    }

    #[test]
    fn status_code_metric_labels_are_static_for_known_s3_statuses() {
        assert_eq!(status_code_label(http::StatusCode::OK), "200");
        assert_eq!(status_code_label(http::StatusCode::PARTIAL_CONTENT), "206");
        assert_eq!(
            status_code_label(http::StatusCode::PRECONDITION_FAILED),
            "412"
        );
        assert_eq!(
            status_code_label(http::StatusCode::SERVICE_UNAVAILABLE),
            "503"
        );
        assert_eq!(status_code_label(http::StatusCode::IM_A_TEAPOT), "unknown");
    }

    async fn gateway_service_with_max_put_object_bytes(
        max_put_object_bytes: u64,
    ) -> GatewayS3Service {
        gateway_service_with_put_body_limits(
            max_put_object_bytes,
            max_put_object_bytes,
            5 * 1024 * 1024,
        )
        .await
    }

    async fn gateway_service_with_put_body_limits(
        max_put_object_bytes: u64,
        buffered_put_object_bytes: u64,
        backend_multipart_part_bytes: u64,
    ) -> GatewayS3Service {
        let mut config = runtime_config(true);
        config.hardening.max_put_object_bytes = max_put_object_bytes;
        config.hardening.buffered_put_object_bytes = buffered_put_object_bytes;
        config.hardening.backend_multipart_part_bytes = backend_multipart_part_bytes;
        GatewayS3Service::from_config(&config)
            .await
            .unwrap_or_else(|error| {
                panic!("{error}");
            })
    }

    async fn gateway_service_with_stream_read_stall_timeout(
        stream_read_stall_timeout: Duration,
        buffered_put_object_bytes: u64,
    ) -> GatewayS3Service {
        let mut config = runtime_config(true);
        config.hardening.max_put_object_bytes = 64;
        config.hardening.buffered_put_object_bytes = buffered_put_object_bytes;
        config.hardening.backend_multipart_part_bytes = 5 * 1024 * 1024;
        config.hardening.stream_read_stall_timeout = stream_read_stall_timeout;
        GatewayS3Service::from_config(&config)
            .await
            .unwrap_or_else(|error| {
                panic!("{error}");
            })
    }

    async fn gateway_service_with_max_in_flight_upload_body_bytes(
        max_in_flight_upload_body_bytes: u64,
    ) -> GatewayS3Service {
        let mut config = runtime_config(true);
        config.hardening.max_in_flight_upload_body_bytes = max_in_flight_upload_body_bytes;
        GatewayS3Service::from_config(&config)
            .await
            .unwrap_or_else(|error| {
                panic!("{error}");
            })
    }

    async fn gateway_service_with_max_in_flight_download_body_bytes(
        max_in_flight_download_body_bytes: u64,
    ) -> GatewayS3Service {
        let mut config = runtime_config(true);
        config.hardening.max_in_flight_download_body_bytes = max_in_flight_download_body_bytes;
        GatewayS3Service::from_config(&config)
            .await
            .unwrap_or_else(|error| {
                panic!("{error}");
            })
    }

    fn s3_request<T>(input: T) -> S3Request<T> {
        S3Request {
            input,
            method: http::Method::GET,
            uri: http::Uri::from_static("/"),
            headers: http::HeaderMap::new(),
            extensions: http::Extensions::new(),
            credentials: None,
            region: None,
            service: None,
            trailing_headers: None,
        }
    }

    fn delete_objects_input(
        objects: Vec<ObjectIdentifier>,
        quiet: Option<bool>,
    ) -> DeleteObjectsInput {
        DeleteObjectsInput {
            bucket: "client-bucket".to_owned(),
            bypass_governance_retention: None,
            checksum_algorithm: None,
            delete: Delete { objects, quiet },
            expected_bucket_owner: None,
            mfa: None,
            request_payer: None,
        }
    }

    fn delete_object_identifier(key: &str) -> ObjectIdentifier {
        ObjectIdentifier {
            key: key.to_owned(),
            ..ObjectIdentifier::default()
        }
    }

    async fn response_body<T>(response: S3Response<T>) -> Bytes
    where
        T: Into<GetObjectBody>,
    {
        let body = response.output.into().0;
        collect_body(body, u64::MAX).await.unwrap_or_else(|error| {
            panic!("{error}");
        })
    }

    async fn accepted_v2_sequence(service: &GatewayS3Service) -> u64 {
        service
            .repository
            .memory_v2_anchor()
            .unwrap_or_else(|| panic!("missing v2 memory anchor"))
            .read_v2()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing v2 anchor state"))
            .sequence
            .get()
    }

    async fn accepted_v2_commit_metadata(service: &GatewayS3Service) -> rs3_storage::BlobMetadata {
        let accepted = service
            .repository
            .memory_v2_anchor()
            .unwrap_or_else(|| panic!("missing v2 memory anchor"))
            .read_v2()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing v2 anchor state"));
        service
            .repository
            .memory_store()
            .unwrap_or_else(|| panic!("missing memory store"))
            .head_at(&accepted.commit_key, accepted.version_id.as_ref())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
    }

    struct GetObjectBody(Option<StreamingBlob>);

    impl From<s3s::dto::GetObjectOutput> for GetObjectBody {
        fn from(output: s3s::dto::GetObjectOutput) -> Self {
            Self(output.body)
        }
    }

    #[test]
    fn service_implements_s3_trait() {
        fn assert_s3<T: s3s::S3>() {}

        assert_s3::<GatewayS3Service>();
    }

    #[tokio::test]
    async fn request_bucket_scope_is_path_safe() {
        let service = gateway_service().await;

        assert_eq!(service.bucket_scope(None), "none");
        assert_eq!(service.bucket_scope(Some("client-bucket")), "configured");
        assert_eq!(service.bucket_scope(Some("tenant-a")), "other");
    }

    #[tokio::test]
    async fn head_bucket_accepts_public_bucket() {
        let service = gateway_service().await;
        let response = service
            .head_bucket(s3_request(HeadBucketInput {
                bucket: "client-bucket".to_owned(),
                ..HeadBucketInput::default()
            }))
            .await;

        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn head_bucket_rejects_other_bucket() {
        let service = gateway_service().await;
        let response = service
            .head_bucket(s3_request(HeadBucketInput {
                bucket: "other-bucket".to_owned(),
                ..HeadBucketInput::default()
            }))
            .await;

        assert!(response.is_err());
    }

    #[tokio::test]
    async fn list_buckets_returns_public_bucket() {
        let service = gateway_service().await;
        let response = service
            .list_buckets(s3_request(ListBucketsInput::default()))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let buckets = response.output.buckets.unwrap_or_default();

        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].name.as_deref(), Some("client-bucket"));
    }

    #[tokio::test]
    async fn get_bucket_location_accepts_public_bucket() {
        let service = gateway_service().await;
        let response = service
            .get_bucket_location(s3_request(GetBucketLocationInput {
                bucket: "client-bucket".to_owned(),
                ..GetBucketLocationInput::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(response.output.location_constraint.is_none());
    }

    #[tokio::test]
    async fn get_bucket_location_rejects_other_bucket() {
        let service = gateway_service().await;
        let response = service
            .get_bucket_location(s3_request(GetBucketLocationInput {
                bucket: "other-bucket".to_owned(),
                ..GetBucketLocationInput::default()
            }))
            .await;

        assert!(response.is_err());
    }

    #[tokio::test]
    async fn object_operations_use_repository_mapping() {
        let service = gateway_service().await;

        let put = service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/object.bin".to_owned(),
                body: Some(StreamingBlob::from(Body::from(Bytes::from_static(
                    b"abcdef",
                )))),
                ..PutObjectInput::default()
            }))
            .await;
        assert!(put.is_ok());

        assert_eq!(accepted_v2_sequence(&service).await, 2);

        let backend_objects = service
            .repository
            .memory_store()
            .unwrap_or_else(|| panic!("missing memory store"))
            .list_prefix("commits/v02/")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(backend_objects.len(), 2);
        assert!(
            backend_objects
                .iter()
                .all(|metadata| { !metadata.object_id.as_str().contains("snapshots/object.bin") })
        );

        let head = service
            .head_object(s3_request(HeadObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/object.bin".to_owned(),
                ..HeadObjectInput::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(head.output.content_length, Some(6));

        let get = service
            .get_object(s3_request(GetObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/object.bin".to_owned(),
                ..GetObjectInput::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response_body(get).await, Bytes::from_static(b"abcdef"));

        let range = service
            .get_object(s3_request(GetObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/object.bin".to_owned(),
                range: Some(s3s::dto::Range::Int {
                    first: 2,
                    last: Some(4),
                }),
                ..GetObjectInput::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(range.status, Some(http::StatusCode::PARTIAL_CONTENT));
        assert_eq!(response_body(range).await, Bytes::from_static(b"cde"));

        let listed = service
            .list_objects_v2(s3_request(ListObjectsV2Input {
                bucket: "client-bucket".to_owned(),
                prefix: Some("snapshots/".to_owned()),
                ..ListObjectsV2Input::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let contents = listed.output.contents.unwrap_or_default();
        assert_eq!(contents.len(), 1);
        assert_eq!(
            contents.first().and_then(|object| object.key.as_deref()),
            Some("snapshots/object.bin")
        );

        let listed_v1 = service
            .list_objects(s3_request(ListObjectsInput {
                bucket: "client-bucket".to_owned(),
                prefix: Some("snapshots/".to_owned()),
                ..ListObjectsInput::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let contents = listed_v1.output.contents.unwrap_or_default();
        assert_eq!(contents.len(), 1);
        assert_eq!(
            contents.first().and_then(|object| object.key.as_deref()),
            Some("snapshots/object.bin")
        );

        let delete = service
            .delete_object(s3_request(DeleteObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/object.bin".to_owned(),
                ..DeleteObjectInput::default()
            }))
            .await;
        let delete = delete.unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(delete.output.delete_marker, Some(false));

        assert_eq!(accepted_v2_sequence(&service).await, 3);

        let missing = service
            .head_object(s3_request(HeadObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/object.bin".to_owned(),
                ..HeadObjectInput::default()
            }))
            .await
            .expect_err("deleted object should not be visible through HeadObject");
        assert_eq!(*missing.code(), s3s::S3ErrorCode::NoSuchKey);
    }

    #[tokio::test]
    async fn delete_objects_returns_per_key_successes() {
        let service = gateway_service().await;
        for key in ["snapshots/batch-a.bin", "snapshots/batch-b.bin"] {
            service
                .put_object(s3_request(PutObjectInput {
                    bucket: "client-bucket".to_owned(),
                    key: key.to_owned(),
                    body: Some(StreamingBlob::from(Body::from(Bytes::from_static(
                        b"delete me",
                    )))),
                    ..PutObjectInput::default()
                }))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        }

        let delete = service
            .delete_objects(s3_request(delete_objects_input(
                vec![
                    delete_object_identifier("snapshots/batch-a.bin"),
                    delete_object_identifier("snapshots/batch-b.bin"),
                ],
                None,
            )))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let deleted = delete.output.deleted.unwrap_or_default();
        assert_eq!(deleted.len(), 2);
        assert_eq!(deleted[0].key.as_deref(), Some("snapshots/batch-a.bin"));
        assert_eq!(deleted[0].delete_marker, Some(false));
        assert_eq!(deleted[1].key.as_deref(), Some("snapshots/batch-b.bin"));
        assert_eq!(deleted[1].delete_marker, Some(false));
        assert!(delete.output.errors.is_none());

        for key in ["snapshots/batch-a.bin", "snapshots/batch-b.bin"] {
            let missing = service
                .head_object(s3_request(HeadObjectInput {
                    bucket: "client-bucket".to_owned(),
                    key: key.to_owned(),
                    ..HeadObjectInput::default()
                }))
                .await
                .expect_err("batch-deleted object should be hidden");
            assert_eq!(*missing.code(), s3s::S3ErrorCode::NoSuchKey);
        }
    }

    #[tokio::test]
    async fn delete_objects_quiet_mode_suppresses_success_entries() {
        let service = gateway_service().await;
        service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/quiet-delete.bin".to_owned(),
                body: Some(StreamingBlob::from(Body::from(Bytes::from_static(
                    b"delete me quietly",
                )))),
                ..PutObjectInput::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let delete = service
            .delete_objects(s3_request(delete_objects_input(
                vec![delete_object_identifier("snapshots/quiet-delete.bin")],
                Some(true),
            )))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(delete.output.deleted.is_none());
        assert!(delete.output.errors.is_none());
    }

    #[tokio::test]
    async fn delete_objects_reports_per_key_errors() {
        let service = gateway_service().await;
        service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/batch-good.bin".to_owned(),
                body: Some(StreamingBlob::from(Body::from(Bytes::from_static(
                    b"delete me",
                )))),
                ..PutObjectInput::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut unsupported = delete_object_identifier("snapshots/batch-versioned.bin");
        unsupported.version_id = Some("versioned-delete".to_owned());
        let delete = service
            .delete_objects(s3_request(delete_objects_input(
                vec![
                    delete_object_identifier("snapshots/batch-good.bin"),
                    unsupported,
                ],
                None,
            )))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let deleted = delete.output.deleted.unwrap_or_default();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].key.as_deref(), Some("snapshots/batch-good.bin"));
        let errors = delete.output.errors.unwrap_or_default();
        assert_eq!(errors.len(), 1);
        assert_eq!(
            errors[0].key.as_deref(),
            Some("snapshots/batch-versioned.bin")
        );
        assert_eq!(errors[0].code.as_deref(), Some("NotImplemented"));
        assert!(
            errors[0].message.as_deref().is_some_and(|message| {
                message.contains("conditional or versioned DeleteObjects")
            })
        );
    }

    #[tokio::test]
    async fn list_objects_v2_paginates_common_prefixes_after_duplicate_prefix_entries() {
        let service = gateway_service().await;

        for key in ["snapshots/a/1", "snapshots/a/2", "snapshots/b/1"] {
            service
                .put_object(s3_request(PutObjectInput {
                    bucket: "client-bucket".to_owned(),
                    key: key.to_owned(),
                    body: Some(StreamingBlob::from(Body::from(Bytes::from_static(b"body")))),
                    ..PutObjectInput::default()
                }))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        }

        let first = service
            .list_objects_v2(s3_request(ListObjectsV2Input {
                bucket: "client-bucket".to_owned(),
                prefix: Some("snapshots/".to_owned()),
                delimiter: Some("/".to_owned()),
                max_keys: Some(1),
                ..ListObjectsV2Input::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first.output.is_truncated, Some(true));
        assert_eq!(
            first.output.next_continuation_token.as_deref(),
            Some("snapshots/a/")
        );
        assert_eq!(
            first
                .output
                .common_prefixes
                .as_deref()
                .and_then(|prefixes| prefixes.first())
                .and_then(|prefix| prefix.prefix.as_deref()),
            Some("snapshots/a/")
        );

        let second = service
            .list_objects_v2(s3_request(ListObjectsV2Input {
                bucket: "client-bucket".to_owned(),
                prefix: Some("snapshots/".to_owned()),
                delimiter: Some("/".to_owned()),
                continuation_token: first.output.next_continuation_token,
                max_keys: Some(1),
                ..ListObjectsV2Input::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(second.output.is_truncated, Some(false));
        assert_eq!(second.output.next_continuation_token, None);
        assert_eq!(
            second
                .output
                .common_prefixes
                .as_deref()
                .and_then(|prefixes| prefixes.first())
                .and_then(|prefix| prefix.prefix.as_deref()),
            Some("snapshots/b/")
        );
    }

    #[tokio::test]
    async fn put_object_rejects_body_above_configured_limit() {
        let service = gateway_service_with_max_put_object_bytes(3).await;

        let error = service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/object.bin".to_owned(),
                body: Some(StreamingBlob::from(Body::from(Bytes::from_static(b"abcd")))),
                ..PutObjectInput::default()
            }))
            .await
            .expect_err("oversized PutObject should be rejected");

        assert_eq!(error.code().as_str(), "EntityTooLarge");
        assert_eq!(accepted_v2_sequence(&service).await, 1);
    }

    #[tokio::test]
    async fn put_object_streams_known_body_above_buffered_threshold() {
        let service = gateway_service_with_put_body_limits(64, 3, 5 * 1024 * 1024).await;
        let store = service
            .repository
            .memory_store()
            .unwrap_or_else(|| panic!("missing memory store"));
        store
            .reset_operation_counts()
            .unwrap_or_else(|error| panic!("{error}"));

        let put = service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/streamed.bin".to_owned(),
                content_length: Some(4),
                body: Some(StreamingBlob::from(Body::from(Bytes::from_static(b"abcd")))),
                ..PutObjectInput::default()
            }))
            .await;
        assert!(put.is_ok());

        let get = service
            .get_object(s3_request(GetObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/streamed.bin".to_owned(),
                ..GetObjectInput::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let counts = store
            .operation_counts()
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(response_body(get).await, Bytes::from_static(b"abcd"));
        assert_eq!(counts.multipart_put, 1);
    }

    #[tokio::test]
    async fn put_object_rejects_short_streaming_body_for_declared_length() {
        let service = gateway_service_with_put_body_limits(64, 3, 5 * 1024 * 1024).await;

        let error = service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/short-streamed.bin".to_owned(),
                content_length: Some(4),
                body: Some(StreamingBlob::from(Body::from(Bytes::from_static(b"abc")))),
                ..PutObjectInput::default()
            }))
            .await
            .expect_err("short streaming PutObject body should be rejected");

        assert_eq!(error.code().as_str(), "IncompleteBody");
        assert_eq!(accepted_v2_sequence(&service).await, 1);
    }

    #[tokio::test]
    async fn put_object_rejects_long_streaming_body_for_declared_length() {
        let service = gateway_service_with_put_body_limits(64, 3, 5 * 1024 * 1024).await;

        let error = service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/long-streamed.bin".to_owned(),
                content_length: Some(4),
                body: Some(StreamingBlob::from(Body::from(Bytes::from_static(
                    b"abcde",
                )))),
                ..PutObjectInput::default()
            }))
            .await
            .expect_err("long streaming PutObject body should be rejected");

        assert_eq!(error.code().as_str(), "IncompleteBody");
        assert_eq!(accepted_v2_sequence(&service).await, 1);
    }

    #[tokio::test]
    async fn put_object_rejects_streaming_read_error_for_declared_length() {
        let service = gateway_service_with_put_body_limits(64, 3, 5 * 1024 * 1024).await;
        let body = StreamingBlob::wrap(futures_util::stream::iter([
            Ok::<Bytes, std::io::Error>(Bytes::from_static(b"ab")),
            Err(std::io::Error::other("synthetic body failure")),
        ]));

        let error = service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/read-error-streamed.bin".to_owned(),
                content_length: Some(4),
                body: Some(body),
                ..PutObjectInput::default()
            }))
            .await
            .expect_err("streaming PutObject read error should be rejected");

        assert_eq!(error.code().as_str(), "IncompleteBody");
        assert_eq!(accepted_v2_sequence(&service).await, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn put_object_rejects_stalled_streaming_body_for_declared_length() {
        let service =
            gateway_service_with_stream_read_stall_timeout(Duration::from_secs(1), 3).await;
        let body =
            StreamingBlob::wrap(futures_util::stream::pending::<Result<Bytes, std::io::Error>>());

        let error = service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/stalled-streamed.bin".to_owned(),
                content_length: Some(4),
                body: Some(body),
                ..PutObjectInput::default()
            }))
            .await
            .expect_err("stalled streaming PutObject body should be rejected");

        assert_eq!(error.code().as_str(), "IncompleteBody");
        assert_eq!(accepted_v2_sequence(&service).await, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn put_object_rejects_stalled_buffered_body_for_declared_length() {
        let service =
            gateway_service_with_stream_read_stall_timeout(Duration::from_secs(1), 64).await;
        let body =
            StreamingBlob::wrap(futures_util::stream::pending::<Result<Bytes, std::io::Error>>());

        let error = service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/stalled-buffered.bin".to_owned(),
                content_length: Some(4),
                body: Some(body),
                ..PutObjectInput::default()
            }))
            .await
            .expect_err("stalled buffered PutObject body should be rejected");

        assert_eq!(error.code().as_str(), "IncompleteBody");
        assert_eq!(accepted_v2_sequence(&service).await, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn put_object_rejects_stalled_unknown_length_body_before_streaming_threshold() {
        let service =
            gateway_service_with_stream_read_stall_timeout(Duration::from_secs(1), 3).await;
        let body =
            StreamingBlob::wrap(futures_util::stream::pending::<Result<Bytes, std::io::Error>>());

        let error = service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/stalled-unknown.bin".to_owned(),
                body: Some(body),
                ..PutObjectInput::default()
            }))
            .await
            .expect_err("stalled unknown-length PutObject body should be rejected");

        assert_eq!(error.code().as_str(), "IncompleteBody");
        assert_eq!(accepted_v2_sequence(&service).await, 1);
    }

    #[tokio::test]
    async fn put_object_streams_unknown_length_body_above_buffered_threshold() {
        let service = gateway_service_with_put_body_limits(1024, 3, 5 * 1024 * 1024).await;
        let store = service
            .repository
            .memory_store()
            .unwrap_or_else(|| panic!("missing memory store"));
        store
            .reset_operation_counts()
            .unwrap_or_else(|error| panic!("{error}"));

        let put = service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/unknown-large.bin".to_owned(),
                body: Some(StreamingBlob::from(Body::from(Bytes::from(vec![
                    7_u8;
                    512
                ])))),
                ..PutObjectInput::default()
            }))
            .await;
        assert!(put.is_ok());

        let get = service
            .get_object(s3_request(GetObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/unknown-large.bin".to_owned(),
                ..GetObjectInput::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let counts = store
            .operation_counts()
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(response_body(get).await, Bytes::from(vec![7_u8; 512]));
        assert_eq!(counts.multipart_put, 1);
    }

    #[tokio::test]
    async fn unknown_length_streaming_uses_the_validated_peak_upload_budget() {
        let mut config = runtime_config(true);
        config.hardening.max_put_object_bytes = 1024;
        config.hardening.buffered_put_object_bytes = 3;
        config.hardening.backend_multipart_part_bytes = 5 * 1024 * 1024;
        config.hardening.max_in_flight_upload_body_bytes = config
            .hardening
            .buffered_put_object_bytes
            .saturating_add(configured_streaming_upload_working_set_bytes(
                &config.hardening,
                &config.repository,
            ));
        let service = GatewayS3Service::from_config(&config)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let store = service
            .repository
            .memory_store()
            .unwrap_or_else(|| panic!("missing memory store"));
        store
            .reset_operation_counts()
            .unwrap_or_else(|error| panic!("{error}"));

        let put = service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/unknown-budgeted.bin".to_owned(),
                body: Some(StreamingBlob::from(Body::from(Bytes::from(vec![
                    7_u8;
                    512
                ])))),
                ..PutObjectInput::default()
            }))
            .await;

        assert!(put.is_ok());
        let counts = store
            .operation_counts()
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(counts.multipart_put, 1);
    }

    #[tokio::test]
    async fn unknown_length_streaming_reserves_transition_memory_before_starting_upload() {
        let mut config = runtime_config(true);
        config.hardening.max_put_object_bytes = 1024;
        config.hardening.buffered_put_object_bytes = 3;
        config.hardening.backend_multipart_part_bytes = 5 * 1024 * 1024;
        config.hardening.max_in_flight_upload_body_bytes =
            configured_streaming_upload_working_set_bytes(&config.hardening, &config.repository)
                .saturating_add(2);
        let service = GatewayS3Service::from_config(&config)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let store = service
            .repository
            .memory_store()
            .unwrap_or_else(|| panic!("missing memory store"));
        store
            .reset_operation_counts()
            .unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/unknown-over-budget.bin".to_owned(),
                body: Some(StreamingBlob::from(Body::from(Bytes::from_static(
                    b"abcdef",
                )))),
                ..PutObjectInput::default()
            }))
            .await
            .expect_err("streaming transition above its memory budget must be rejected");
        let counts = store
            .operation_counts()
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(error.code().as_str(), "SlowDown");
        assert_eq!(counts.multipart_create, 0);
        assert_eq!(counts.multipart_put, 0);
        assert_eq!(service.upload_body_budget.in_flight_bytes(), 0);
        assert_eq!(accepted_v2_sequence(&service).await, 1);
    }

    #[tokio::test]
    async fn put_object_rejects_unknown_length_streaming_read_error_after_threshold() {
        let service = gateway_service_with_put_body_limits(64, 3, 5 * 1024 * 1024).await;
        let body = StreamingBlob::wrap(futures_util::stream::iter([
            Ok::<Bytes, std::io::Error>(Bytes::from_static(b"abcd")),
            Err(std::io::Error::other("synthetic body failure")),
        ]));

        let error = service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/unknown-read-error-streamed.bin".to_owned(),
                body: Some(body),
                ..PutObjectInput::default()
            }))
            .await
            .expect_err("unknown-length streaming PutObject read error should be rejected");

        assert_eq!(error.code().as_str(), "IncompleteBody");
        assert_eq!(accepted_v2_sequence(&service).await, 1);
    }

    #[tokio::test]
    async fn put_object_rejects_declared_content_length_above_configured_limit() {
        let service = gateway_service_with_max_put_object_bytes(3).await;

        let error = service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/object.bin".to_owned(),
                content_length: Some(4),
                body: Some(StreamingBlob::from(Body::from(Bytes::from_static(b"")))),
                ..PutObjectInput::default()
            }))
            .await
            .expect_err("oversized declared PutObject length should be rejected");

        assert_eq!(error.code().as_str(), "EntityTooLarge");
        assert_eq!(accepted_v2_sequence(&service).await, 1);
    }

    #[test]
    fn request_rate_limiter_rejects_above_initial_burst() {
        let limiter = RequestRateLimiter::new(2);

        assert!(limiter.try_admit());
        assert!(limiter.try_admit());
        assert!(!limiter.try_admit());
    }

    #[test]
    fn upload_body_budget_rejects_above_limit_and_releases_on_drop() {
        let budget = UploadBodyBudget::new(3);
        {
            let mut reservation = budget.reservation();

            assert!(reservation.reserve_until("PutObject", 2).is_ok());
            assert_eq!(budget.in_flight_bytes(), 2);

            let error = reservation
                .reserve_until("PutObject", 4)
                .expect_err("reservation above body budget should be rejected");
            assert_eq!(error.code().as_str(), "SlowDown");
            assert_eq!(budget.in_flight_bytes(), 2);
        }

        assert_eq!(budget.in_flight_bytes(), 0);
    }

    #[test]
    fn download_body_budget_rejects_above_limit_and_releases_on_drop() {
        let budget = DownloadBodyBudget::new(3);
        {
            let _reservation = budget
                .reserve("GetObject", 2)
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(budget.in_flight_bytes(), 2);

            let error = match budget.reserve("GetObject", 2) {
                Ok(_reservation) => {
                    panic!("overlapping reservation above body budget should be rejected");
                }
                Err(error) => error,
            };
            assert_eq!(error.code().as_str(), "SlowDown");
            assert_eq!(budget.in_flight_bytes(), 2);
        }

        assert_eq!(budget.in_flight_bytes(), 0);
    }

    #[tokio::test]
    async fn put_object_rejects_declared_body_above_in_flight_body_budget() {
        let service = gateway_service_with_max_in_flight_upload_body_bytes(3).await;

        let error = service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/object.bin".to_owned(),
                content_length: Some(4),
                body: Some(StreamingBlob::from(Body::from(Bytes::from_static(b"abcd")))),
                ..PutObjectInput::default()
            }))
            .await
            .expect_err("PutObject above in-flight body budget should be rejected");

        assert_eq!(error.code().as_str(), "SlowDown");
        assert_eq!(accepted_v2_sequence(&service).await, 1);
    }

    #[tokio::test]
    async fn get_object_rejects_body_above_in_flight_body_budget() {
        let service = gateway_service_with_max_in_flight_download_body_bytes(3).await;

        service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/object.bin".to_owned(),
                body: Some(StreamingBlob::from(Body::from(Bytes::from_static(b"abcd")))),
                ..PutObjectInput::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .get_object(s3_request(GetObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/object.bin".to_owned(),
                ..GetObjectInput::default()
            }))
            .await
            .expect_err("GetObject above in-flight body budget should be rejected");

        assert_eq!(error.code().as_str(), "SlowDown");
        assert_eq!(service.download_body_budget.in_flight_bytes(), 0);
    }

    #[tokio::test]
    async fn get_object_reserves_resolved_range_until_body_consumed() {
        let service = gateway_service_with_max_in_flight_download_body_bytes(3).await;

        service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/object.bin".to_owned(),
                body: Some(StreamingBlob::from(Body::from(Bytes::from_static(b"abcd")))),
                ..PutObjectInput::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .get_object(s3_request(GetObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/object.bin".to_owned(),
                range: Some(s3s::dto::Range::Int {
                    first: 1,
                    last: Some(3),
                }),
                ..GetObjectInput::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(response.output.content_length, Some(3));
        assert_eq!(service.download_body_budget.in_flight_bytes(), 3);
        assert_eq!(response_body(response).await, Bytes::from_static(b"bcd"));
        assert_eq!(service.download_body_budget.in_flight_bytes(), 0);
    }

    #[tokio::test]
    async fn get_object_releases_download_budget_when_response_body_is_dropped() {
        let service = gateway_service_with_max_in_flight_download_body_bytes(4).await;

        service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/object.bin".to_owned(),
                body: Some(StreamingBlob::from(Body::from(Bytes::from_static(b"abcd")))),
                ..PutObjectInput::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .get_object(s3_request(GetObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/object.bin".to_owned(),
                ..GetObjectInput::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(service.download_body_budget.in_flight_bytes(), 4);
        drop(response);
        assert_eq!(service.download_body_budget.in_flight_bytes(), 0);
    }

    #[tokio::test]
    async fn streamed_get_uses_bounded_working_set_instead_of_object_length() {
        let mut config = runtime_config(true);
        config.hardening.max_put_object_bytes = 8 * 1024 * 1024;
        config.hardening.buffered_put_object_bytes = 3;
        config.hardening.backend_multipart_part_bytes = 5 * 1024 * 1024;
        config.hardening.max_in_flight_download_body_bytes = 4 * 1024 * 1024;
        let service = GatewayS3Service::from_config(&config)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let body = Bytes::from(vec![0x4d; 5 * 1024 * 1024 + 17]);

        service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/large-stream.bin".to_owned(),
                content_length: Some(body.len() as i64),
                body: Some(StreamingBlob::from(Body::from(body.clone()))),
                ..PutObjectInput::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .get_object(s3_request(GetObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/large-stream.bin".to_owned(),
                ..GetObjectInput::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let reserved = service.download_body_budget.in_flight_bytes();

        assert!(reserved > 0);
        assert!(reserved < body.len() as u64);
        assert_eq!(response_body(response).await, body);
        assert_eq!(service.download_body_budget.in_flight_bytes(), 0);
    }

    #[tokio::test]
    async fn put_object_rejects_streamed_body_above_in_flight_body_budget() {
        let service = gateway_service_with_max_in_flight_upload_body_bytes(3).await;

        let error = service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/object.bin".to_owned(),
                body: Some(StreamingBlob::from(Body::from(Bytes::from_static(b"abcd")))),
                ..PutObjectInput::default()
            }))
            .await
            .expect_err("streamed PutObject above in-flight body budget should be rejected");

        assert_eq!(error.code().as_str(), "SlowDown");
        assert_eq!(accepted_v2_sequence(&service).await, 1);
    }

    #[tokio::test]
    async fn request_admission_rejects_above_concurrency_limit() {
        let mut config = runtime_config(true);
        config.hardening.max_concurrent_requests = 1;
        let service = GatewayS3Service::from_config(&config)
            .await
            .unwrap_or_else(|error| {
                panic!("{error}");
            });
        let _permit = service
            .admit_request("TestOperation")
            .unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .admit_request("TestOperation")
            .expect_err("second admission should be rejected");

        assert_eq!(error.code().as_str(), "SlowDown");
    }

    #[tokio::test]
    async fn full_covering_range_reads_repository_payload_as_full_object() {
        let service = gateway_service().await;
        let body = Bytes::from(vec![42_u8; 1024]);
        service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/full-range.bin".to_owned(),
                body: Some(StreamingBlob::from(Body::from(body.clone()))),
                ..PutObjectInput::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let store = service
            .repository
            .memory_store()
            .unwrap_or_else(|| panic!("missing memory store"));
        store
            .reset_operation_counts()
            .unwrap_or_else(|error| panic!("{error}"));

        let get = service
            .get_object(s3_request(GetObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/full-range.bin".to_owned(),
                range: Some(s3s::dto::Range::Int {
                    first: 0,
                    last: Some(1023),
                }),
                ..GetObjectInput::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let counts = store
            .operation_counts()
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(get.status, Some(http::StatusCode::PARTIAL_CONTENT));
        assert_eq!(response_body(get).await, body);
        assert_eq!(counts.get, 1);
    }

    #[tokio::test]
    async fn restore_readonly_mode_rejects_repository_mutations() {
        let mut service = gateway_service().await;
        let initial_put = service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/restorable.bin".to_owned(),
                body: Some(StreamingBlob::from(Body::from(Bytes::from_static(
                    b"restore me",
                )))),
                ..PutObjectInput::default()
            }))
            .await;
        assert!(initial_put.is_ok());

        service.mode = GatewayMode::RestoreReadOnly;

        let get = service
            .get_object(s3_request(GetObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/restorable.bin".to_owned(),
                ..GetObjectInput::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response_body(get).await, Bytes::from_static(b"restore me"));

        let put = service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/rejected.bin".to_owned(),
                body: Some(StreamingBlob::from(Body::from(Bytes::from_static(
                    b"must not commit",
                )))),
                ..PutObjectInput::default()
            }))
            .await
            .expect_err("restore-readonly mode should reject PutObject");
        assert_eq!(*put.code(), s3s::S3ErrorCode::AccessDenied);

        let legal_hold = service
            .put_object_legal_hold(s3_request(PutObjectLegalHoldInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/restorable.bin".to_owned(),
                legal_hold: Some(ObjectLockLegalHold {
                    status: Some(ObjectLockLegalHoldStatus::from_static(
                        ObjectLockLegalHoldStatus::ON,
                    )),
                }),
                ..PutObjectLegalHoldInput::default()
            }))
            .await
            .expect_err("restore-readonly mode should reject legal-hold mutation");
        assert_eq!(*legal_hold.code(), s3s::S3ErrorCode::AccessDenied);

        let delete = service
            .delete_object(s3_request(DeleteObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/restorable.bin".to_owned(),
                ..DeleteObjectInput::default()
            }))
            .await
            .expect_err("restore-readonly mode should reject DeleteObject");
        assert_eq!(*delete.code(), s3s::S3ErrorCode::AccessDenied);

        let delete_objects = service
            .delete_objects(s3_request(delete_objects_input(
                vec![delete_object_identifier("snapshots/restorable.bin")],
                None,
            )))
            .await
            .expect_err("restore-readonly mode should reject DeleteObjects");
        assert_eq!(*delete_objects.code(), s3s::S3ErrorCode::AccessDenied);

        assert_eq!(accepted_v2_sequence(&service).await, 2);
    }

    #[tokio::test]
    async fn put_object_maps_object_lock_retention() {
        let service = retained_gateway_service().await;
        let retain_until = Timestamp::from(SystemTime::now() + Duration::from_secs(172_801));

        let put = service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/retained.bin".to_owned(),
                body: Some(StreamingBlob::from(Body::from(Bytes::from_static(
                    b"retained",
                )))),
                object_lock_mode: Some(ObjectLockMode::from_static(ObjectLockMode::COMPLIANCE)),
                object_lock_retain_until_date: Some(retain_until),
                ..PutObjectInput::default()
            }))
            .await;
        assert!(put.is_ok());

        let commit = accepted_v2_commit_metadata(&service).await;
        let retention = commit
            .retention
            .as_ref()
            .unwrap_or_else(|| panic!("missing backend retention"));
        assert_eq!(retention.mode, RetentionMode::Compliance);
        assert!(retention.retain_days >= 2);

        let head = service
            .head_object(s3_request(HeadObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/retained.bin".to_owned(),
                ..HeadObjectInput::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            head.output
                .object_lock_mode
                .as_ref()
                .map(|mode| mode.as_str()),
            Some(ObjectLockMode::COMPLIANCE)
        );
        assert!(head.output.object_lock_retain_until_date.is_some());
    }

    #[tokio::test]
    async fn put_object_rejects_retention_for_unqualified_repository() {
        let service = gateway_service().await;
        let retain_until = Timestamp::from(SystemTime::now() + Duration::from_secs(86_401));

        let error = service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/unqualified-retention.bin".to_owned(),
                body: Some(StreamingBlob::from(Body::from(Bytes::from_static(
                    b"must not commit",
                )))),
                object_lock_mode: Some(ObjectLockMode::from_static(ObjectLockMode::COMPLIANCE)),
                object_lock_retain_until_date: Some(retain_until),
                ..PutObjectInput::default()
            }))
            .await
            .expect_err("unqualified retention should be rejected");

        assert_eq!(*error.code(), s3s::S3ErrorCode::NotImplemented);
        assert_eq!(accepted_v2_sequence(&service).await, 1);
    }

    #[tokio::test]
    async fn put_object_rejects_object_lock_legal_hold() {
        let service = gateway_service().await;

        let put = service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/held.bin".to_owned(),
                body: Some(StreamingBlob::from(Body::from(Bytes::from_static(b"held")))),
                object_lock_legal_hold_status: Some(ObjectLockLegalHoldStatus::from_static(
                    ObjectLockLegalHoldStatus::ON,
                )),
                ..PutObjectInput::default()
            }))
            .await;
        let error = put.expect_err("legal-hold PUT should be rejected");
        assert_eq!(*error.code(), s3s::S3ErrorCode::NotImplemented);
    }

    #[tokio::test]
    async fn object_legal_hold_enable_is_rejected_and_read_remains_available() {
        let service = gateway_service().await;
        let put = service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/legal-hold-api.bin".to_owned(),
                body: Some(StreamingBlob::from(Body::from(Bytes::from_static(b"held")))),
                ..PutObjectInput::default()
            }))
            .await;
        assert!(put.is_ok());

        let enable = service
            .put_object_legal_hold(s3_request(PutObjectLegalHoldInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/legal-hold-api.bin".to_owned(),
                legal_hold: Some(ObjectLockLegalHold {
                    status: Some(ObjectLockLegalHoldStatus::from_static(
                        ObjectLockLegalHoldStatus::ON,
                    )),
                }),
                ..PutObjectLegalHoldInput::default()
            }))
            .await;
        let error = enable.expect_err("legal-hold enable should be rejected");
        assert_eq!(*error.code(), s3s::S3ErrorCode::NotImplemented);

        let get = service
            .get_object_legal_hold(s3_request(GetObjectLegalHoldInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/legal-hold-api.bin".to_owned(),
                ..GetObjectLegalHoldInput::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            get.output
                .legal_hold
                .as_ref()
                .and_then(|hold| hold.status.as_ref())
                .map(|status| status.as_str()),
            Some(ObjectLockLegalHoldStatus::OFF)
        );
    }

    #[tokio::test]
    async fn put_object_legal_hold_refuses_release() {
        let service = gateway_service().await;
        let put = service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/legal-hold-release.bin".to_owned(),
                body: Some(StreamingBlob::from(Body::from(Bytes::from_static(b"held")))),
                ..PutObjectInput::default()
            }))
            .await;
        assert!(put.is_ok());

        let release = service
            .put_object_legal_hold(s3_request(PutObjectLegalHoldInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/legal-hold-release.bin".to_owned(),
                legal_hold: Some(ObjectLockLegalHold {
                    status: Some(ObjectLockLegalHoldStatus::from_static(
                        ObjectLockLegalHoldStatus::OFF,
                    )),
                }),
                ..PutObjectLegalHoldInput::default()
            }))
            .await
            .expect_err("gateway should reject legal-hold mutation");

        assert_eq!(*release.code(), s3s::S3ErrorCode::NotImplemented);
    }

    #[tokio::test]
    async fn put_object_honors_create_only_condition() {
        let service = gateway_service().await;
        let input = || PutObjectInput {
            bucket: "client-bucket".to_owned(),
            key: "snapshots/create-only.bin".to_owned(),
            body: Some(StreamingBlob::from(Body::from(Bytes::from_static(b"body")))),
            if_none_match: Some(s3s::dto::ETagCondition::Any),
            ..PutObjectInput::default()
        };

        let first = service.put_object(s3_request(input())).await;
        let second = service.put_object(s3_request(input())).await;

        assert!(first.is_ok());
        assert_eq!(
            *second
                .expect_err("second create-only PutObject should fail")
                .code(),
            s3s::S3ErrorCode::PreconditionFailed
        );
    }
}
