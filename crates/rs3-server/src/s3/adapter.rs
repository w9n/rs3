//! Typed S3 service adapter backed by repository operations.

use super::S3BoundaryError;
use super::mapping::{
    collect_body, content_range, etag, i64_len, list_page, logical_path, max_keys,
    put_object_retention_policy, repository_error, resolve_range, retention_headers, timestamp,
    validate_delete_object_request, validate_get_object_request, validate_head_object_request,
    validate_put_object_request,
};
use super::runtime::RuntimeRepository;
use crate::RuntimeConfig;
use rs3_repository::RepositoryPutOptions;
use rs3_storage::ByteRange;
use rs3_types::PublicBucket;
use s3s::dto::{
    Bucket, DeleteObjectInput, DeleteObjectOutput, GetObjectInput, GetObjectOutput,
    HeadBucketInput, HeadBucketOutput, HeadObjectInput, HeadObjectOutput, ListBucketsInput,
    ListBucketsOutput, ListObjectsV2Input, ListObjectsV2Output, Owner, PutObjectInput,
    PutObjectOutput, StreamingBlob,
};
use s3s::{Body, S3, S3Request, S3Response, S3Result};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::Instrument;

#[derive(Clone)]
pub(super) struct GatewayS3Service {
    public_bucket: PublicBucket,
    repository: RuntimeRepository,
    request_sequence: Arc<AtomicU64>,
}

impl GatewayS3Service {
    pub(super) async fn from_config(config: &RuntimeConfig) -> Result<Self, S3BoundaryError> {
        let repository = RuntimeRepository::from_config(config)?;
        repository
            .validate_backend_retention(config.repository.retention)
            .await?;
        repository.load_accepted_checkpoint().await?;

        Ok(Self {
            public_bucket: config.public_bucket.clone(),
            repository,
            request_sequence: Arc::new(AtomicU64::new(0)),
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
        let bucket = bucket.unwrap_or("");
        tracing::info_span!(
            target: "rs3_server",
            "s3_request",
            operation,
            request_id,
            bucket,
        )
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
        let bucket = bucket.unwrap_or("");
        match result {
            Ok(response) => {
                let status = response.status.unwrap_or(default_success_status);
                record_s3_request_metrics(operation, "ok", status, elapsed);
                tracing::info!(
                    target: "rs3_server",
                    operation,
                    request_id,
                    bucket,
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
                    bucket,
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
            self.check_bucket(&input.bucket)?;
            validate_put_object_request(&input)?;

            let retention = put_object_retention_policy(&input)?;
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
            let body_collect_started = Instant::now();
            let body = collect_body(input.body).await;
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
            self.check_bucket(&input.bucket)?;
            validate_get_object_request(&input)?;

            let requested_range = input.range.is_some();
            let key = logical_path(input.key)?;
            let metadata = self.repository.head(&key).map_err(repository_error)?;
            let resolved_range = resolve_range(input.range, metadata.content_len)?;
            let repository_range = resolved_range
                .as_ref()
                .map(|range| ByteRange::Slice {
                    offset: range.start,
                    len: range.end - range.start,
                })
                .unwrap_or(ByteRange::Full);
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
            self.check_bucket(&input.bucket)?;
            validate_delete_object_request(&input)?;

            let key = logical_path(input.key)?;
            self.repository
                .delete_committed(key)
                .await
                .map_err(repository_error)?;

            Ok(S3Response::new(DeleteObjectOutput {
                delete_marker: Some(true),
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
    use super::GatewayS3Service;
    use super::collect_body;
    use crate::s3::test_support::runtime_config;
    use bytes::Bytes;
    use rs3_anchor::CheckpointAnchor;
    use rs3_storage::BlobStore;
    use rs3_types::RetentionMode;
    use s3s::dto::{
        DeleteObjectInput, GetObjectInput, HeadBucketInput, HeadObjectInput, ListBucketsInput,
        ListObjectsV2Input, ObjectLockMode, PutObjectInput, StreamingBlob, Timestamp,
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
        collect_body(body).await.unwrap_or_else(|error| {
            panic!("{error}");
        })
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

        let accepted = service
            .repository
            .memory_anchor()
            .unwrap_or_else(|| panic!("missing memory anchor"))
            .read()
            .await
            .unwrap_or_else(|error| {
                panic!("{error}");
            });
        assert_eq!(accepted.sequence.get(), 1);

        let backend_objects = service
            .repository
            .memory_store()
            .unwrap_or_else(|| panic!("missing memory store"))
            .list_prefix("segments/")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(backend_objects.len(), 1);
        assert!(
            !backend_objects[0]
                .object_id
                .as_str()
                .contains("snapshots/object.bin")
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

        let delete = service
            .delete_object(s3_request(DeleteObjectInput {
                bucket: "client-bucket".to_owned(),
                key: "snapshots/object.bin".to_owned(),
                ..DeleteObjectInput::default()
            }))
            .await;
        assert!(delete.is_ok());

        let accepted = service
            .repository
            .memory_anchor()
            .unwrap_or_else(|| panic!("missing memory anchor"))
            .read()
            .await
            .unwrap_or_else(|error| {
                panic!("{error}");
            });
        assert_eq!(accepted.sequence.get(), 2);

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

        let backend_objects = service
            .repository
            .memory_store()
            .unwrap_or_else(|| panic!("missing memory store"))
            .list_prefix("segments/")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let retention = backend_objects
            .first()
            .and_then(|metadata| metadata.retention.as_ref())
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
