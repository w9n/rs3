//! Typed S3 service adapter backed by repository operations.

use super::S3BoundaryError;
use super::mapping::{
    collect_body, content_range, etag, i64_len, list_page, logical_path, max_keys,
    repository_error, resolve_range, timestamp, validate_delete_object_request,
    validate_get_object_request, validate_head_object_request, validate_put_object_request,
};
use super::runtime::RuntimeRepository;
use crate::RuntimeConfig;
use rs3_repository::RepositoryPutOptions;
use rs3_storage::ByteRange;
use rs3_types::PublicBucket;
use s3s::dto::{
    DeleteObjectInput, DeleteObjectOutput, GetObjectInput, GetObjectOutput, HeadObjectInput,
    HeadObjectOutput, ListObjectsV2Input, ListObjectsV2Output, PutObjectInput, PutObjectOutput,
    StreamingBlob,
};
use s3s::{Body, S3, S3Request, S3Response, S3Result};

#[derive(Clone)]
pub(super) struct GatewayS3Service {
    public_bucket: PublicBucket,
    repository: RuntimeRepository,
}

impl GatewayS3Service {
    pub(super) fn from_config(config: &RuntimeConfig) -> Result<Self, S3BoundaryError> {
        Ok(Self {
            public_bucket: config.public_bucket.clone(),
            repository: RuntimeRepository::from_config(config)?,
        })
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
    async fn put_object(
        &self,
        req: S3Request<PutObjectInput>,
    ) -> S3Result<S3Response<PutObjectOutput>> {
        let input = req.input;
        self.check_bucket(&input.bucket)?;
        validate_put_object_request(&input)?;

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
        let body = collect_body(input.body).await?;

        let committed = self
            .repository
            .put_committed(
                key,
                body,
                RepositoryPutOptions {
                    create_only,
                    retention: None,
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

    async fn get_object(
        &self,
        req: S3Request<GetObjectInput>,
    ) -> S3Result<S3Response<GetObjectOutput>> {
        let input = req.input;
        self.check_bucket(&input.bucket)?;
        validate_get_object_request(&input)?;

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

        let response = if let Some(range) = resolved_range {
            output.content_range =
                Some(content_range(range.start, range.end, metadata.content_len));
            S3Response::with_status(output, http::StatusCode::PARTIAL_CONTENT)
        } else {
            S3Response::new(output)
        };

        Ok(response)
    }

    async fn head_object(
        &self,
        req: S3Request<HeadObjectInput>,
    ) -> S3Result<S3Response<HeadObjectOutput>> {
        let input = req.input;
        self.check_bucket(&input.bucket)?;
        validate_head_object_request(&input)?;

        let key = logical_path(input.key)?;
        let metadata = self.repository.head(&key).map_err(repository_error)?;
        let content_length = match resolve_range(input.range, metadata.content_len)? {
            Some(range) => range.end - range.start,
            None => metadata.content_len,
        };

        Ok(S3Response::new(HeadObjectOutput {
            accept_ranges: Some("bytes".to_owned()),
            content_length: Some(i64_len(content_length)?),
            content_type: Some("application/octet-stream".to_owned()),
            e_tag: Some(etag(metadata.content_len, metadata.modified_at_ms)),
            last_modified: Some(timestamp(metadata.modified_at_ms)?),
            ..HeadObjectOutput::default()
        }))
    }

    async fn list_objects_v2(
        &self,
        req: S3Request<ListObjectsV2Input>,
    ) -> S3Result<S3Response<ListObjectsV2Output>> {
        let input = req.input;
        self.check_bucket(&input.bucket)?;

        let prefix = input.prefix.unwrap_or_default();
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

    async fn delete_object(
        &self,
        req: S3Request<DeleteObjectInput>,
    ) -> S3Result<S3Response<DeleteObjectOutput>> {
        let input = req.input;
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
}

#[cfg(test)]
mod tests {
    use super::GatewayS3Service;
    use super::collect_body;
    use crate::s3::test_support::runtime_config;
    use bytes::Bytes;
    use rs3_anchor::CheckpointAnchor;
    use rs3_storage::BlobStore;
    use s3s::dto::{
        DeleteObjectInput, GetObjectInput, HeadObjectInput, ListObjectsV2Input, PutObjectInput,
        StreamingBlob,
    };
    use s3s::{Body, S3, S3Request, S3Response};

    fn gateway_service() -> GatewayS3Service {
        GatewayS3Service::from_config(&runtime_config(true)).unwrap_or_else(|error| {
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
    async fn object_operations_use_repository_mapping() {
        let service = gateway_service();

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
    async fn put_object_honors_create_only_condition() {
        let service = gateway_service();
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
