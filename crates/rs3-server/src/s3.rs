//! S3 protocol adapter surface.

use crate::{AnchorConfig, RuntimeConfig};
use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use rs3_anchor::MemoryCheckpointAnchor;
use rs3_crypto::{KeyMaterial, KeyRing, SecretBytes};
use rs3_repository::{
    CommitCoordinator, CommitCoordinatorOptions, Repository, RepositoryError, RepositoryPutOptions,
};
use rs3_storage::{ByteRange, MemoryBlobStore, StorageError};
use rs3_types::{KeyDescriptor, KeyId, KeyPurpose, KeyStatus, LogicalPath, PublicBucket};
use s3s::access::{S3Access, S3AccessContext};
use s3s::auth::SimpleAuth;
use s3s::config::{S3Config, StaticConfigProvider};
use s3s::dto::{
    CommonPrefix, DeleteObjectInput, DeleteObjectOutput, GetObjectInput, GetObjectOutput,
    HeadObjectInput, HeadObjectOutput, ListObjectsV2Input, ListObjectsV2Output, Object,
    PutObjectInput, PutObjectOutput, StreamingBlob, Timestamp,
};
use s3s::path::S3Path;
use s3s::service::{S3Service, S3ServiceBuilder};
use s3s::{Body, S3, S3Request, S3Response, S3Result};
use secrecy::ExposeSecret;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};
use thiserror::Error;

type GatewayStore = MemoryBlobStore;
type GatewayAnchor = MemoryCheckpointAnchor;
type GatewayCommitCoordinator = CommitCoordinator<GatewayStore, GatewayAnchor>;

#[derive(Clone)]
struct GatewayS3Service {
    public_bucket: PublicBucket,
    coordinator: Arc<GatewayCommitCoordinator>,
    #[cfg(test)]
    store: GatewayStore,
    #[cfg(test)]
    anchor: GatewayAnchor,
}

impl GatewayS3Service {
    fn from_config(config: &RuntimeConfig) -> Result<Self, S3BoundaryError> {
        if !matches!(config.anchor, AnchorConfig::Memory) {
            return Err(S3BoundaryError::UnsupportedAnchorMode);
        }

        let store = MemoryBlobStore::new();
        let repository = Arc::new(Repository::with_keyring(store.clone(), gateway_keyring()?));
        let anchor = MemoryCheckpointAnchor::new();
        let options =
            CommitCoordinatorOptions::new(config.batching.max_items, config.batching.max_delay)
                .with_max_pending_items(config.batching.max_pending_items);
        let coordinator = Arc::new(CommitCoordinator::with_options(
            repository,
            anchor.clone(),
            options,
        ));

        Ok(Self {
            public_bucket: config.public_bucket.clone(),
            coordinator,
            #[cfg(test)]
            store,
            #[cfg(test)]
            anchor,
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
            .coordinator
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
        let metadata = self
            .coordinator
            .repository()
            .head(&key)
            .map_err(repository_error)?;
        let resolved_range = resolve_range(input.range, metadata.content_len)?;
        let repository_range = resolved_range
            .as_ref()
            .map(|range| ByteRange::Slice {
                offset: range.start,
                len: range.end - range.start,
            })
            .unwrap_or(ByteRange::Full);
        let body = self
            .coordinator
            .repository()
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
        let metadata = self
            .coordinator
            .repository()
            .head(&key)
            .map_err(repository_error)?;
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
        let entries = self
            .coordinator
            .repository()
            .list(&prefix)
            .map_err(repository_error)?;
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
        self.coordinator
            .delete_committed(key)
            .await
            .map_err(repository_error)?;

        Ok(S3Response::new(DeleteObjectOutput {
            delete_marker: Some(true),
            ..DeleteObjectOutput::default()
        }))
    }
}

struct ListPage {
    contents: Vec<Object>,
    common_prefixes: Vec<CommonPrefix>,
    key_count: usize,
    next_continuation_token: Option<String>,
}

enum ListItem {
    Object(Box<Object>),
    CommonPrefix(CommonPrefix),
}

async fn collect_body(body: Option<StreamingBlob>) -> S3Result<Bytes> {
    let Some(mut body) = body else {
        return Ok(Bytes::new());
    };
    let mut bytes = BytesMut::new();

    while let Some(chunk) = body.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(error) => {
                let mut s3_error = s3s::s3_error!(IncompleteBody, "failed to read request body");
                s3_error.set_source(error);
                return Err(s3_error);
            }
        };
        bytes.extend_from_slice(&chunk);
    }

    Ok(bytes.freeze())
}

fn validate_put_object_request(input: &PutObjectInput) -> S3Result<()> {
    if input.if_match.is_some() {
        return Err(s3s::s3_error!(
            InvalidRequest,
            "If-Match is not supported for PutObject"
        ));
    }
    if input.write_offset_bytes.is_some() {
        return Err(s3s::s3_error!(
            NotImplemented,
            "append-style PutObject is not supported"
        ));
    }
    if input.object_lock_mode.is_some()
        || input.object_lock_retain_until_date.is_some()
        || input.object_lock_legal_hold_status.is_some()
    {
        return Err(s3s::s3_error!(
            NotImplemented,
            "per-object lock headers are not mapped by this adapter"
        ));
    }
    Ok(())
}

fn validate_get_object_request(input: &GetObjectInput) -> S3Result<()> {
    if input.part_number.is_some() || input.version_id.is_some() {
        return Err(s3s::s3_error!(
            NotImplemented,
            "part numbers and object versions are not supported"
        ));
    }
    Ok(())
}

fn validate_head_object_request(input: &HeadObjectInput) -> S3Result<()> {
    if input.part_number.is_some() || input.version_id.is_some() {
        return Err(s3s::s3_error!(
            NotImplemented,
            "part numbers and object versions are not supported"
        ));
    }
    Ok(())
}

fn validate_delete_object_request(input: &DeleteObjectInput) -> S3Result<()> {
    if input.version_id.is_some()
        || input.if_match.is_some()
        || input.if_match_last_modified_time.is_some()
        || input.if_match_size.is_some()
    {
        return Err(s3s::s3_error!(
            NotImplemented,
            "conditional or versioned DeleteObject is not supported"
        ));
    }
    Ok(())
}

fn logical_path(key: String) -> S3Result<LogicalPath> {
    LogicalPath::new(key)
        .map_err(|_error| s3s::s3_error!(InvalidRequest, "object key is not valid"))
}

fn resolve_range(
    range: Option<s3s::dto::Range>,
    content_len: u64,
) -> S3Result<Option<std::ops::Range<u64>>> {
    range
        .map(|range| range.check(content_len).map_err(Into::into))
        .transpose()
}

fn content_range(start: u64, end: u64, full_len: u64) -> String {
    format!("bytes {}-{}/{full_len}", start, end - 1)
}

fn list_page(
    entries: Vec<rs3_repository::RepositoryListEntry>,
    prefix: &str,
    delimiter: Option<&str>,
    start_after: Option<&str>,
    max_keys: usize,
) -> S3Result<ListPage> {
    let mut items = BTreeMap::new();

    for entry in entries {
        let key = entry.key.as_str();
        if start_after.is_some_and(|start_after| key <= start_after) {
            continue;
        }

        if let Some(delimiter) = delimiter {
            let remainder = key.strip_prefix(prefix).unwrap_or(key);
            if let Some((component, _)) = remainder.split_once(delimiter) {
                let common_prefix = format!("{prefix}{component}{delimiter}");
                if start_after.is_none_or(|start_after| common_prefix.as_str() > start_after) {
                    items.entry(common_prefix.clone()).or_insert_with(|| {
                        ListItem::CommonPrefix(CommonPrefix {
                            prefix: Some(common_prefix),
                        })
                    });
                }
                continue;
            }
        }

        items.insert(
            key.to_owned(),
            ListItem::Object(Box::new(Object {
                key: Some(key.to_owned()),
                last_modified: Some(timestamp(entry.modified_at_ms)?),
                size: Some(i64_len(entry.content_len)?),
                e_tag: Some(etag(entry.content_len, entry.modified_at_ms)),
                ..Object::default()
            })),
        );
    }

    let mut contents = Vec::new();
    let mut common_prefixes = Vec::new();
    let mut next_continuation_token = None;
    let mut key_count = 0usize;

    for (key, item) in items {
        if key_count == max_keys {
            next_continuation_token = Some(key);
            break;
        }

        match item {
            ListItem::Object(object) => contents.push(*object),
            ListItem::CommonPrefix(prefix) => common_prefixes.push(prefix),
        }
        key_count += 1;
    }

    Ok(ListPage {
        contents,
        common_prefixes,
        key_count,
        next_continuation_token,
    })
}

fn max_keys(value: Option<i32>) -> S3Result<usize> {
    match value {
        Some(value) if value < 0 => Err(s3s::s3_error!(
            InvalidRequest,
            "max-keys must not be negative"
        )),
        Some(value) => Ok(usize::try_from(value).unwrap_or(usize::MAX).min(1000)),
        None => Ok(1000),
    }
}

fn i64_len(value: u64) -> S3Result<i64> {
    i64::try_from(value).map_err(|_| {
        s3s::s3_error!(
            InternalError,
            "object length exceeds the supported S3 response range"
        )
    })
}

fn timestamp(modified_at_ms: i64) -> S3Result<Timestamp> {
    let millis = u64::try_from(modified_at_ms).map_err(|_| {
        s3s::s3_error!(
            InternalError,
            "object timestamp is before the supported S3 response range"
        )
    })?;
    let system_time = UNIX_EPOCH
        .checked_add(Duration::from_millis(millis))
        .ok_or_else(|| s3s::s3_error!(InternalError, "object timestamp is out of range"))?;
    Ok(Timestamp::from(system_time))
}

fn etag(content_len: u64, modified_at_ms: i64) -> s3s::dto::ETag {
    s3s::dto::ETag::Strong(format!("rs3-{modified_at_ms:x}-{content_len:x}"))
}

fn repository_error(error: RepositoryError) -> s3s::S3Error {
    match error {
        RepositoryError::NotFound(_) => s3s::s3_error!(NoSuchKey),
        RepositoryError::AlreadyExists(_) => s3s::s3_error!(PreconditionFailed),
        RepositoryError::CommitBackpressure => {
            s3s::s3_error!(ServiceUnavailable, "commit coordinator is overloaded")
        }
        RepositoryError::Storage(StorageError::InvalidRange) => {
            s3s::s3_error!(InvalidRange)
        }
        RepositoryError::Type(_) => s3s::s3_error!(InvalidRequest, "invalid repository path"),
        RepositoryError::CommitFailed { .. }
        | RepositoryError::SequenceOverflow
        | RepositoryError::StatePoisoned
        | RepositoryError::Crypto(_)
        | RepositoryError::Storage(_)
        | RepositoryError::Anchor(_)
        | RepositoryError::CheckpointEncoding(_)
        | RepositoryError::CheckpointIdMismatch
        | RepositoryError::StaleCheckpoint { .. }
        | RepositoryError::CheckpointConflict { .. }
        | RepositoryError::CheckpointObjectConflict { .. }
        | RepositoryError::IndexDeltaObjectConflict { .. }
        | RepositoryError::InvalidObjectFormat { .. }
        | RepositoryError::CheckpointParentMismatch => {
            s3s::s3_error!(InternalError, "repository operation failed")
        }
    }
}

fn gateway_keyring() -> Result<KeyRing, S3BoundaryError> {
    KeyRing::new(vec![
        key_material("namespace", KeyPurpose::Namespace, "hmac-sha256", 1)?,
        key_material("content", KeyPurpose::Content, "xchacha20poly1305", 2)?,
        key_material("metadata", KeyPurpose::Metadata, "hmac-sha256-seal", 3)?,
        key_material(
            "checkpoint",
            KeyPurpose::CheckpointSigning,
            "hmac-sha256",
            4,
        )?,
    ])
    .map_err(repository_init)
}

fn key_material(
    id: &str,
    purpose: KeyPurpose,
    algorithm: &str,
    secret_byte: u8,
) -> Result<KeyMaterial, S3BoundaryError> {
    Ok(KeyMaterial::new(
        KeyDescriptor {
            id: KeyId::new(id.to_owned()).map_err(repository_init)?,
            purpose,
            algorithm: algorithm.to_owned(),
            status: KeyStatus::Primary,
            created_at_ms: 0,
            not_before_ms: None,
            not_after_ms: None,
            external_kms_uri: None,
        },
        SecretBytes::new(vec![secret_byte; SecretBytes::MIN_LEN]).map_err(repository_init)?,
    ))
}

fn repository_init(error: impl ToString) -> S3BoundaryError {
    S3BoundaryError::RepositoryInit {
        reason: error.to_string(),
    }
}

/// Configured S3 protocol boundary.
///
/// This type is the public construction path for the S3 service. It installs
/// authentication and bucket-scoped access control together before exposing the
/// underlying `s3s` HTTP service.
#[derive(Clone)]
pub struct GatewayS3Boundary {
    config: RuntimeConfig,
    service: S3Service,
    hardening: S3Hardening,
}

impl GatewayS3Boundary {
    /// Builds the S3 boundary from validated runtime configuration.
    ///
    /// Static credentials are currently required because `s3s` only invokes
    /// access control when an authentication provider is configured.
    ///
    /// # Errors
    ///
    /// Returns [`S3BoundaryError::MissingStaticCredentials`] when no static
    /// credentials are configured for the process.
    pub fn build(config: RuntimeConfig) -> Result<Self, S3BoundaryError> {
        let credentials = config
            .static_credentials
            .clone()
            .ok_or(S3BoundaryError::MissingStaticCredentials)?;

        let adapter = GatewayS3Service::from_config(&config)?;
        let mut builder = S3ServiceBuilder::new(adapter);

        let s3_config = Arc::new(S3Config::default());
        builder.set_config(Arc::new(StaticConfigProvider::new(s3_config)));
        builder.set_auth(SimpleAuth::from_single(
            credentials.access_key_id,
            credentials.secret_access_key.expose_secret().to_owned(),
        ));
        builder.set_access(GatewayS3Access::new(config.public_bucket.clone()));

        Ok(Self {
            config,
            service: builder.build(),
            hardening: S3Hardening::required(),
        })
    }

    /// Returns the validated runtime configuration used by this boundary.
    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    /// Returns the client-visible bucket served by this boundary.
    pub fn public_bucket(&self) -> &PublicBucket {
        &self.config.public_bucket
    }

    /// Returns the configured `s3s` HTTP service.
    pub fn service(&self) -> &S3Service {
        &self.service
    }

    /// Consumes this boundary and returns the configured `s3s` HTTP service.
    pub fn into_service(self) -> S3Service {
        self.service
    }

    /// Returns the controls that still need to surround the S3 HTTP service.
    pub fn hardening(&self) -> S3Hardening {
        self.hardening
    }
}

/// S3 boundary construction errors.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum S3BoundaryError {
    /// Static credentials are required before exposing the S3 service.
    #[error("static credentials are required to build the S3 boundary")]
    MissingStaticCredentials,
    /// The configured checkpoint anchor is not wired into the S3 adapter yet.
    #[error("configured checkpoint anchor mode is not supported by the S3 adapter yet")]
    UnsupportedAnchorMode,
    /// Repository state initialization failed.
    #[error("failed to initialize repository state: {reason}")]
    RepositoryInit {
        /// Initialization failure reason.
        reason: String,
    },
}

/// Security and operability controls required around the S3 protocol adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct S3Hardening {
    /// Enforce body limits with awareness of the requested S3 operation.
    pub operation_body_limits: bool,
    /// Enforce admission control before accepting more client work.
    pub backpressure: bool,
    /// Enforce request rate limits at the HTTP/S3 boundary.
    pub rate_limiting: bool,
    /// Attach request traces and structured fields before repository calls.
    pub request_tracing: bool,
    /// Authenticate and authorize requests before deserializing operation input.
    pub authentication: bool,
}

impl S3Hardening {
    /// Returns the full set of required controls for an exposed S3 listener.
    pub const fn required() -> Self {
        Self {
            operation_body_limits: true,
            backpressure: true,
            rate_limiting: true,
            request_tracing: true,
            authentication: true,
        }
    }
}

#[derive(Clone, Debug)]
struct GatewayS3Access {
    public_bucket: PublicBucket,
}

impl GatewayS3Access {
    fn new(public_bucket: PublicBucket) -> Self {
        Self { public_bucket }
    }

    fn check_path(&self, path: &S3Path) -> S3Result<()> {
        let Some(bucket) = path.get_bucket_name() else {
            return Ok(());
        };

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
impl S3Access for GatewayS3Access {
    async fn check(&self, cx: &mut S3AccessContext<'_>) -> S3Result<()> {
        if cx.credentials().is_none() {
            return Err(s3s::s3_error!(AccessDenied, "signature is required"));
        }

        self.check_path(cx.s3_path())
    }
}

#[cfg(test)]
mod tests {
    use super::{GatewayS3Access, GatewayS3Boundary, GatewayS3Service, S3BoundaryError};
    use crate::{AnchorConfig, BackendConfig, BatchConfig, RuntimeConfig, SecretString};
    use bytes::Bytes;
    use rs3_anchor::CheckpointAnchor;
    use rs3_storage::BlobStore;
    use rs3_types::PublicBucket;
    use s3s::dto::{
        DeleteObjectInput, GetObjectInput, HeadObjectInput, ListObjectsV2Input, PutObjectInput,
        StreamingBlob,
    };
    use s3s::path::S3Path;
    use s3s::{Body, S3, S3Request, S3Response};
    use std::time::Duration;

    fn runtime_config(static_credentials: bool) -> RuntimeConfig {
        let bind = match "127.0.0.1:9080".parse() {
            Ok(bind) => bind,
            Err(error) => panic!("{error}"),
        };
        let public_bucket = match PublicBucket::new("client-bucket") {
            Ok(bucket) => bucket,
            Err(error) => panic!("{error}"),
        };

        RuntimeConfig {
            bind,
            public_bucket,
            backend: BackendConfig {
                endpoint: "https://object.example".to_owned(),
                bucket: "backend-bucket".to_owned(),
                prefix: Some("repo".to_owned()),
            },
            anchor: AnchorConfig::Memory,
            batching: BatchConfig {
                max_items: 64,
                max_delay: Duration::from_millis(10),
                max_pending_items: 64,
            },
            static_credentials: static_credentials.then(|| crate::StaticCredentials {
                access_key_id: "access".to_owned(),
                secret_access_key: SecretString::from("secret"),
            }),
        }
    }

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
        super::collect_body(body).await.unwrap_or_else(|error| {
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
    fn boundary_requires_static_credentials() {
        let boundary = GatewayS3Boundary::build(runtime_config(false));

        assert!(matches!(
            boundary,
            Err(S3BoundaryError::MissingStaticCredentials)
        ));
    }

    #[test]
    fn boundary_builds_authenticated_s3_service() {
        let config = runtime_config(true);

        let boundary = match GatewayS3Boundary::build(config.clone()) {
            Ok(boundary) => boundary,
            Err(error) => panic!("{error}"),
        };

        assert_eq!(boundary.config(), &config);
        assert_eq!(boundary.public_bucket().as_str(), "client-bucket");
        assert!(boundary.hardening().operation_body_limits);
        assert!(boundary.hardening().backpressure);
        assert!(boundary.hardening().rate_limiting);
        assert!(boundary.hardening().request_tracing);
        assert!(boundary.hardening().authentication);
        let _service = boundary.service().clone();
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

        let accepted = service.anchor.read().await.unwrap_or_else(|error| {
            panic!("{error}");
        });
        assert_eq!(accepted.sequence.get(), 1);

        let backend_objects = service
            .store
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

        let accepted = service.anchor.read().await.unwrap_or_else(|error| {
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

    #[test]
    fn access_scope_allows_only_configured_bucket() {
        let access = GatewayS3Access::new(
            PublicBucket::new("client-bucket").unwrap_or_else(|error| panic!("{error}")),
        );

        assert!(access.check_path(&S3Path::root()).is_ok());
        assert!(access.check_path(&S3Path::bucket("client-bucket")).is_ok());
        assert!(
            access
                .check_path(&S3Path::object("client-bucket", "object"))
                .is_ok()
        );
        assert!(access.check_path(&S3Path::bucket("other-bucket")).is_err());
        assert!(
            access
                .check_path(&S3Path::object("other-bucket", "object"))
                .is_err()
        );
    }
}
