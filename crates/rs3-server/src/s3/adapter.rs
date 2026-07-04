//! Typed S3 service adapter backed by repository operations.

use super::S3BoundaryError;
use super::mapping::{
    collect_body_reserving, content_range, etag, i64_len, legal_hold_header, legal_hold_output,
    list_page, logical_path, max_keys, put_object_legal_hold_request_status,
    put_object_legal_hold_status, put_object_retention_policy, repository_error, resolve_range,
    retention_headers, timestamp, validate_delete_object_request,
    validate_get_object_legal_hold_request, validate_get_object_request,
    validate_head_object_request, validate_put_object_request,
};
use super::runtime::RuntimeRepository;
use crate::{GatewayMode, RuntimeConfig};
use bytes::{Bytes, BytesMut};
use futures_util::{StreamExt, stream};
use rs3_repository::{RepositoryError, RepositoryPutOptions};
use rs3_storage::ByteRange;
use rs3_types::{LegalHoldStatus, PublicBucket};
use s3s::dto::{
    Bucket, DeleteObjectInput, DeleteObjectOutput, GetBucketLocationInput, GetBucketLocationOutput,
    GetObjectInput, GetObjectLegalHoldInput, GetObjectLegalHoldOutput, GetObjectOutput,
    HeadBucketInput, HeadBucketOutput, HeadObjectInput, HeadObjectOutput, ListBucketsInput,
    ListBucketsOutput, ListObjectsInput, ListObjectsOutput, ListObjectsV2Input,
    ListObjectsV2Output, Owner, PutObjectInput, PutObjectLegalHoldInput, PutObjectLegalHoldOutput,
    PutObjectOutput, StreamingBlob,
};
use s3s::{Body, S3, S3Request, S3Response, S3Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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
    request_slots: Arc<Semaphore>,
    request_rate_limiter: RequestRateLimiter,
    upload_body_budget: UploadBodyBudget,
}

impl GatewayS3Service {
    pub(super) async fn from_config(config: &RuntimeConfig) -> Result<Self, S3BoundaryError> {
        let repository = RuntimeRepository::from_config(config).await?;
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
            request_slots: Arc::new(Semaphore::new(config.hardening.max_concurrent_requests)),
            request_rate_limiter: RequestRateLimiter::new(
                config.hardening.request_rate_limit_per_second,
            ),
            upload_body_budget: UploadBodyBudget::new(
                config.hardening.max_in_flight_upload_body_bytes,
            ),
        })
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
                tracing::info!(
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
                let streaming_budget = self
                    .backend_multipart_part_bytes
                    .saturating_mul(2)
                    .saturating_add(4096);
                let mut upload_body_reservation = self.upload_body_budget.reservation();
                upload_body_reservation.reserve_until(OPERATION, streaming_budget)?;
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
                while let Some(chunk) = body.next().await {
                    let chunk = match chunk {
                        Ok(chunk) => chunk,
                        Err(error) => {
                            let mut s3_error =
                                s3s::s3_error!(IncompleteBody, "failed to read request body");
                            s3_error.set_source(error);
                            return Err(s3_error);
                        }
                    };
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
                    upload_body_reservation.reserve_body_len(OPERATION, next_len)?;
                    buffered.extend_from_slice(&chunk);
                    if u64::try_from(buffered.len()).unwrap_or(u64::MAX)
                        <= self.buffered_put_object_bytes
                    {
                        continue;
                    }

                    let streaming_budget = self
                        .backend_multipart_part_bytes
                        .saturating_mul(2)
                        .saturating_add(4096)
                        .saturating_add(u64::try_from(buffered.len()).unwrap_or(u64::MAX));
                    upload_body_reservation.reserve_until(OPERATION, streaming_budget)?;
                    let prefix = buffered.freeze();
                    let stream =
                        stream::iter(std::iter::once(Ok::<Bytes, RepositoryError>(prefix))).chain(
                            body.map(|chunk| {
                                chunk.map_err(|_error| RepositoryError::ObjectBodyReadFailed)
                            }),
                        );
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
            let body = collect_body_reserving(input.body, collect_limit, |body_len| {
                upload_body_reservation.reserve_body_len(OPERATION, body_len)
            })
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
            let metadata = self.repository.head(&key).map_err(repository_error)?;
            let resolved_range = resolve_range(input.range, metadata.content_len)?;
            let repository_range =
                repository_read_range(resolved_range.as_ref(), metadata.content_len);
            let body = self
                .repository
                .get_range(&key, repository_range)
                .await
                .map_err(repository_error)?;
            record_s3_response_body_bytes(OPERATION, body.len());

            tracing::debug!(
                target: "rs3_server",
                operation = OPERATION,
                request_id,
                requested_range,
                response_body_bytes = body.len(),
                "S3 response body prepared",
            );
            let content_length = i64_len(body.len() as u64)?;
            let mut output = GetObjectOutput {
                accept_ranges: Some("bytes".to_owned()),
                body: Some(StreamingBlob::from(Body::from(body))),
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
            let status = put_object_legal_hold_request_status(&input)?;
            if status == LegalHoldStatus::Off {
                return Err(s3s::s3_error!(
                    AccessDenied,
                    "clearing Object Lock legal holds through this gateway is not supported"
                ));
            }

            let key = logical_path(input.key)?;
            self.repository
                .set_legal_hold_committed(key, status)
                .await
                .map_err(repository_error)?;
            Ok(S3Response::new(PutObjectLegalHoldOutput::default()))
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
            let entries = self.repository.list(&prefix).map_err(repository_error)?;
            let page = list_page(
                entries,
                &prefix,
                delimiter.as_deref(),
                marker.as_deref(),
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
            let entries = self.repository.list(&prefix).map_err(repository_error)?;
            let page = list_page(
                entries,
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

            let key = logical_path(input.key)?;
            self.repository
                .delete_committed(key)
                .await
                .map_err(repository_error)?;

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
    let status_code = status.as_u16().to_string();
    metrics::counter!(
        "rs3_s3_requests_total",
        "operation" => operation,
        "result" => result,
        "status_code" => status_code.clone(),
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
    use super::{GatewayS3Service, RequestRateLimiter, UploadBodyBudget};
    use crate::GatewayMode;
    use crate::s3::mapping::collect_body;
    use crate::s3::test_support::runtime_config;
    use bytes::Bytes;
    use rs3_repository::v2::V2CommitAnchor;
    use rs3_storage::BlobStore;
    use rs3_types::{LegalHoldStatus, RetentionMode};
    use s3s::dto::{
        DeleteObjectInput, GetBucketLocationInput, GetObjectInput, GetObjectLegalHoldInput,
        HeadBucketInput, HeadObjectInput, ListBucketsInput, ListObjectsInput, ListObjectsV2Input,
        ObjectLockLegalHold, ObjectLockLegalHoldStatus, ObjectLockMode, PutObjectInput,
        PutObjectLegalHoldInput, StreamingBlob, Timestamp,
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
            .list_prefix("commits/v01/")
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

        assert_eq!(accepted_v2_sequence(&service).await, 2);
    }

    #[tokio::test]
    async fn put_object_maps_object_lock_retention() {
        let service = gateway_service().await;
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
    async fn put_object_maps_object_lock_legal_hold() {
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
        assert!(put.is_ok());

        let commit = accepted_v2_commit_metadata(&service).await;
        assert_eq!(commit.legal_hold, Some(LegalHoldStatus::On));

        let head = service
            .head_object(s3_request(HeadObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/held.bin".to_owned(),
                ..HeadObjectInput::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            head.output
                .object_lock_legal_hold_status
                .as_ref()
                .map(|status| status.as_str()),
            Some(ObjectLockLegalHoldStatus::ON)
        );
    }

    #[tokio::test]
    async fn object_legal_hold_operations_support_enable_and_read() {
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
        assert!(enable.is_ok());

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
            Some(ObjectLockLegalHoldStatus::ON)
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
                object_lock_legal_hold_status: Some(ObjectLockLegalHoldStatus::from_static(
                    ObjectLockLegalHoldStatus::ON,
                )),
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
            .expect_err("gateway should not clear legal hold");

        assert_eq!(*release.code(), s3s::S3ErrorCode::AccessDenied);
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
