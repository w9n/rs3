//! Provider-neutral object-store abstractions.

#[cfg(feature = "test-util")]
mod fault;
mod filesystem;
mod read;
#[cfg(feature = "s3")]
mod s3;

use async_trait::async_trait;
use bytes::Bytes;
use rs3_types::{
    BackendObjectId, BackendVersionId, LegalHoldStatus, RetentionMode, RetentionPolicy,
};
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[cfg(feature = "test-util")]
pub use fault::{
    FaultAction, FaultCrashHook, FaultEvent, FaultInjectingBlobStore, FaultMatcher,
    FaultOperationKind, FaultRule,
};
pub use filesystem::FilesystemBlobStore;
pub use read::{BlobRead, MAX_BLOB_READ_CHUNK_BYTES, collect_bounded_blob_read};
#[cfg(feature = "s3")]
pub use s3::{
    S3BlobStore, S3BlobStoreConfig, S3ClientTimeoutConfig, S3ProviderMetrics,
    S3ProviderOperationMetrics,
};

/// Metadata returned by object-store reads and heads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobMetadata {
    /// Opaque backend object identifier.
    pub object_id: BackendObjectId,
    /// Object length in bytes.
    pub content_len: u64,
    /// Provider modification timestamp in milliseconds since the Unix epoch.
    pub modified_at_ms: Option<i64>,
    /// Provider entity tag, when available.
    pub etag: Option<String>,
    /// Provider version identifier, when available.
    pub version_id: Option<BackendVersionId>,
    /// Provider retention policy for this object version, when known.
    pub retention: Option<RetentionPolicy>,
    /// Absolute provider retain-until timestamp in milliseconds since the Unix epoch.
    pub retain_until_ms: Option<i64>,
    /// Provider legal-hold status for this object version, when known.
    pub legal_hold: Option<LegalHoldStatus>,
}

/// Byte range requested from an object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteRange {
    /// Fetch the complete object.
    Full,
    /// Fetch `len` bytes starting at `offset`.
    Slice {
        /// Start offset in bytes.
        offset: u64,
        /// Number of bytes to fetch.
        len: u64,
    },
}

/// Options used when writing an object.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PutOptions {
    /// Optional retention policy for this object version.
    pub retention: Option<RetentionPolicy>,
    /// Optional legal-hold status for this object version.
    pub legal_hold: Option<LegalHoldStatus>,
    /// Optional content type.
    pub content_type: Option<String>,
    /// Reject the write if an object already exists at this backend identifier.
    pub do_not_recreate: bool,
}

/// Errors returned by object-store implementations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum StorageError {
    /// The requested object was not found.
    #[error("object not found: {0}")]
    NotFound(BackendObjectId),
    /// The object already exists and the write requested create-only semantics.
    #[error("object already exists: {0}")]
    AlreadyExists(BackendObjectId),
    /// The requested byte range is outside the object.
    #[error("invalid byte range")]
    InvalidRange,
    /// The provider rejected the operation.
    #[error("provider rejected operation: {0}")]
    Provider(String),
    /// The operation could not be completed because retention policy blocked it.
    #[error("object retention policy blocked the operation")]
    RetentionBlocked,
    /// The provider cannot extend retention for an existing object version.
    #[error("retention extension is unsupported")]
    RetentionExtensionUnsupported,
    /// The provider cannot address exact object versions.
    #[error("version-addressed operation is unsupported")]
    VersionUnsupported,
    /// A retained write did not return the provider version needed for exact restores.
    #[error("provider did not return a version id for retained object: {0}")]
    MissingVersionId(BackendObjectId),
    /// The operation could not be completed because legal hold blocked it.
    #[error("object legal hold blocked the operation")]
    LegalHoldBlocked,
    /// The provider cannot apply legal hold for an existing object version.
    #[error("legal hold is unsupported")]
    LegalHoldUnsupported,
    /// Multipart upload is unsupported for this provider or option set.
    #[error("multipart upload is unsupported")]
    MultipartUnsupported,
    /// The provider cannot expose bounded incremental listings.
    #[error("bounded listing is unsupported")]
    PagedListingUnsupported,
    /// The provider cannot expose a pre-allocation-bounded full-object read.
    #[error("bounded full-object read is unsupported")]
    BoundedReadUnsupported,
    /// A provider returned a listing page that violated the requested bound.
    #[error("provider returned an invalid listing page")]
    InvalidListPage,
    /// An object body exceeded a caller-selected bounded-read ceiling.
    #[error("object body exceeds bounded read limit of {max_bytes} bytes")]
    BoundedReadExceeded {
        /// Maximum accepted body length for this read.
        max_bytes: u64,
    },
}

/// Convenient result alias for storage operations.
pub type Result<T> = std::result::Result<T, StorageError>;

/// Selects whether a bounded listing returns current objects or exact versions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobListMode {
    /// Return only the current version of each object.
    Current,
    /// Return every addressable object version.
    Versions,
}

/// One bounded page of object metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobListPage {
    /// Entries returned by this page.
    pub entries: Vec<BlobMetadata>,
    /// Raw provider members consumed to produce this page.
    ///
    /// This includes filtered members such as S3 delete markers and must be no
    /// smaller than `entries.len()` or greater than the requested page limit.
    pub consumed_items: usize,
    /// Whether the listing has no further pages.
    pub is_complete: bool,
}

/// Provider-private incremental listing session.
///
/// Implementations keep provider cursors private and must perform at most one
/// remote provider LIST request per call.
#[async_trait]
pub trait BlobList: Send {
    /// Consumes and returns at most `max_items` members from the next page.
    async fn next_page(&mut self, max_items: NonZeroUsize) -> Result<BlobListPage>;
}

/// Provider-neutral multipart upload session.
#[async_trait]
pub trait BlobMultipartUpload: Send {
    /// Uploads one zero-based part. Parts may be uploaded out of order.
    async fn put_part(&mut self, part_index: usize, body: Bytes) -> Result<()>;

    /// Completes the upload and returns final object metadata.
    ///
    /// Implementations should release provider-side temporary parts if complete
    /// fails after parts were uploaded.
    async fn complete(self: Box<Self>) -> Result<BlobMetadata>;

    /// Aborts the upload and releases provider-side temporary parts when possible.
    async fn abort(self: Box<Self>) -> Result<()>;
}

/// Minimal object-store contract needed by repository code.
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Writes an object and returns provider metadata.
    async fn put(
        &self,
        object_id: &BackendObjectId,
        body: Bytes,
        options: PutOptions,
    ) -> Result<BlobMetadata>;

    /// Returns whether this store can create provider-side multipart uploads.
    fn supports_multipart_upload(&self) -> bool {
        false
    }

    /// Starts a provider-side multipart upload for one final object.
    async fn create_multipart_upload(
        &self,
        object_id: &BackendObjectId,
        options: PutOptions,
    ) -> Result<Box<dyn BlobMultipartUpload>> {
        let _ = object_id;
        let _ = options;
        Err(StorageError::MultipartUnsupported)
    }

    /// Reads an object or byte range.
    ///
    /// Efficient range reads are required for backup restores that fetch
    /// sections of large data objects instead of whole objects.
    async fn get_range(&self, object_id: &BackendObjectId, range: ByteRange) -> Result<Bytes>;

    /// Reads an object or byte range from a specific provider version.
    async fn get_range_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        range: ByteRange,
    ) -> Result<Bytes> {
        if version_id.is_some() {
            return Err(StorageError::VersionUnsupported);
        }
        self.get_range(object_id, range).await
    }

    /// Opens a bounded incremental read from a specific provider version.
    ///
    /// The default adapter preserves compatibility for stores that only expose
    /// buffered reads. Providers with streaming response bodies should override
    /// this method so large objects do not need to be materialized in memory.
    async fn open_range_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        range: ByteRange,
    ) -> Result<Box<dyn BlobRead>> {
        let body = self.get_range_at(object_id, version_id, range).await?;
        let exact_len = match range {
            ByteRange::Full => u64::try_from(body.len()).map_err(|_| {
                StorageError::Provider("read length does not fit in u64".to_owned())
            })?,
            ByteRange::Slice { len, .. } => len,
        };
        Ok(read::bytes_blob_read(body, exact_len))
    }

    /// Opens a full-object read whose declared length is checked before body allocation.
    ///
    /// Providers must override this method to opt in. The default fails closed
    /// rather than adapting through [`Self::get_range_at`], which may already
    /// have buffered an attacker-controlled body before the caller can apply a
    /// size ceiling.
    async fn open_bounded_full_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        max_bytes: u64,
    ) -> Result<Box<dyn BlobRead>> {
        let _ = (object_id, version_id, max_bytes);
        Err(StorageError::BoundedReadUnsupported)
    }

    /// Reads object metadata without fetching the body.
    async fn head(&self, object_id: &BackendObjectId) -> Result<BlobMetadata>;

    /// Reads object metadata for a specific provider version.
    async fn head_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
    ) -> Result<BlobMetadata> {
        if version_id.is_some() {
            return Err(StorageError::VersionUnsupported);
        }
        self.head(object_id).await
    }

    /// Lists object metadata under an opaque prefix.
    ///
    /// The result must include objects written through the same gateway before
    /// the call starts. This is stronger than many backend object stores but is
    /// required by common object-storage client contracts.
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<BlobMetadata>>;

    /// Lists exact object versions under an opaque prefix.
    ///
    /// Retention-aware maintenance uses this to build an exact-version
    /// inventory before destructive apply. Providers that cannot enumerate
    /// versions must fail closed with [`StorageError::VersionUnsupported`].
    async fn list_prefix_versions(&self, prefix: &str) -> Result<Vec<BlobMetadata>> {
        let _ = prefix;
        Err(StorageError::VersionUnsupported)
    }

    /// Opens a bounded incremental listing without exposing provider cursors.
    ///
    /// Providers must override this method to opt in. The default fails closed
    /// rather than adapting through an unbounded whole-prefix listing.
    async fn open_bounded_list(
        &self,
        prefix: &str,
        mode: BlobListMode,
    ) -> Result<Box<dyn BlobList>> {
        let _ = (prefix, mode);
        Err(StorageError::PagedListingUnsupported)
    }

    /// Deletes an object or writes a provider-specific delete marker.
    async fn delete(&self, object_id: &BackendObjectId) -> Result<()>;

    /// Deletes a specific object version when `version_id` is supplied.
    ///
    /// Passing `None` keeps the historical `delete` behavior. Retained-version
    /// maintenance should pass a concrete version and must not fall back to an
    /// unversioned delete.
    async fn delete_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
    ) -> Result<()> {
        if version_id.is_some() {
            return Err(StorageError::VersionUnsupported);
        }
        self.delete(object_id).await
    }

    /// Extends retention for an existing object version.
    async fn extend_retention(
        &self,
        object_id: &BackendObjectId,
        policy: RetentionPolicy,
    ) -> Result<()>;

    /// Extends retention for a specific existing object version.
    async fn extend_retention_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        policy: RetentionPolicy,
    ) -> Result<()> {
        if version_id.is_some() {
            return Err(StorageError::VersionUnsupported);
        }
        self.extend_retention(object_id, policy).await
    }

    /// Applies or clears legal hold for an existing object version.
    async fn set_legal_hold(
        &self,
        object_id: &BackendObjectId,
        status: LegalHoldStatus,
    ) -> Result<()>;

    /// Applies or clears legal hold for a specific existing object version.
    async fn set_legal_hold_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        status: LegalHoldStatus,
    ) -> Result<()> {
        if version_id.is_some() {
            return Err(StorageError::VersionUnsupported);
        }
        self.set_legal_hold(object_id, status).await
    }

    /// Flushes implementation-local caches before process shutdown or handoff.
    async fn flush_caches(&self) -> Result<()>;
}

/// Reads and collects one complete object under an explicit allocation bound.
///
/// Providers with streaming response bodies enforce the bound before body
/// collection. Exact EOF is still required, so a provider cannot truncate or
/// append bytes relative to its declared response length.
pub async fn read_bounded_full_at<S>(
    store: &S,
    object_id: &BackendObjectId,
    version_id: Option<&BackendVersionId>,
    max_bytes: u64,
) -> Result<Bytes>
where
    S: BlobStore + ?Sized,
{
    let read = store
        .open_bounded_full_at(object_id, version_id, max_bytes)
        .await?;
    collect_bounded_blob_read(read, max_bytes).await
}

/// Operation counters reported by instrumented blob-store implementations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlobOperationCounts {
    /// Number of PUT calls.
    pub put: u64,
    /// Number of GET calls.
    pub get: u64,
    /// Number of HEAD calls.
    pub head: u64,
    /// Number of LIST calls.
    pub list: u64,
    /// Number of DELETE calls.
    pub delete: u64,
    /// Number of retention-extension calls.
    pub extend_retention: u64,
    /// Number of legal-hold update calls.
    pub set_legal_hold: u64,
    /// Number of cache flush calls.
    pub flush: u64,
    /// Number of multipart completions that successfully committed an object.
    pub multipart_put: u64,
    /// Number of wrapper-observed multipart-create request attempts.
    pub multipart_create: u64,
    /// Number of wrapper-observed multipart part-upload request attempts.
    pub multipart_upload_part: u64,
    /// Number of wrapper-observed multipart-complete request attempts.
    pub multipart_complete: u64,
    /// Number of wrapper-observed multipart-abort request attempts.
    pub multipart_abort: u64,
    /// Request-body bytes offered to wrapper-observed PUT and multipart-part attempts.
    ///
    /// This includes failed attempts visible to the wrapper, but cannot include
    /// retries performed internally by a provider SDK.
    pub bytes_uploaded_attempted: u64,
    /// Object bytes committed by successful PUT or multipart-complete calls.
    pub bytes_written: u64,
    /// Bytes returned by successful GET calls.
    pub bytes_read: u64,
}

/// Counting `BlobStore` wrapper for backend pressure and throughput scenarios.
#[derive(Clone, Debug)]
pub struct CountingBlobStore<S> {
    inner: S,
    counts: Arc<RwLock<BlobOperationCounts>>,
}

impl<S> CountingBlobStore<S> {
    /// Wraps an existing blob store and starts counters at zero.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            counts: Arc::new(RwLock::new(BlobOperationCounts::default())),
        }
    }

    /// Returns the wrapped blob store.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Returns a snapshot of operation counters.
    pub fn operation_counts(&self) -> Result<BlobOperationCounts> {
        self.counts
            .read()
            .map(|counts| counts.clone())
            .map_err(|_| StorageError::Provider("counting blob store lock poisoned".to_owned()))
    }

    /// Resets operation counters without changing stored objects.
    pub fn reset_operation_counts(&self) -> Result<()> {
        let mut counts = self
            .counts
            .write()
            .map_err(|_| StorageError::Provider("counting blob store lock poisoned".to_owned()))?;
        *counts = BlobOperationCounts::default();
        Ok(())
    }

    fn mutate_counts(&self, update: impl FnOnce(&mut BlobOperationCounts)) -> Result<()> {
        let mut counts = self
            .counts
            .write()
            .map_err(|_| StorageError::Provider("counting blob store lock poisoned".to_owned()))?;
        update(&mut counts);
        Ok(())
    }
}

#[async_trait]
impl<S> BlobStore for CountingBlobStore<S>
where
    S: BlobStore,
{
    async fn put(
        &self,
        object_id: &BackendObjectId,
        body: Bytes,
        options: PutOptions,
    ) -> Result<BlobMetadata> {
        let attempted_len = u64::try_from(body.len())
            .map_err(|_| StorageError::Provider("upload length does not fit in u64".to_owned()))?;
        self.mutate_counts(|counts| {
            counts.put = counts.put.saturating_add(1);
            counts.bytes_uploaded_attempted = counts
                .bytes_uploaded_attempted
                .saturating_add(attempted_len);
        })?;
        let metadata = self.inner.put(object_id, body, options).await?;
        self.mutate_counts(|counts| {
            counts.bytes_written = counts.bytes_written.saturating_add(metadata.content_len);
        })?;
        Ok(metadata)
    }

    fn supports_multipart_upload(&self) -> bool {
        self.inner.supports_multipart_upload()
    }

    async fn create_multipart_upload(
        &self,
        object_id: &BackendObjectId,
        options: PutOptions,
    ) -> Result<Box<dyn BlobMultipartUpload>> {
        self.mutate_counts(|counts| {
            counts.multipart_create = counts.multipart_create.saturating_add(1);
        })?;
        let upload = self
            .inner
            .create_multipart_upload(object_id, options)
            .await?;
        Ok(Box::new(CountingMultipartUpload {
            inner: upload,
            counts: Arc::clone(&self.counts),
        }))
    }

    async fn get_range(&self, object_id: &BackendObjectId, range: ByteRange) -> Result<Bytes> {
        self.mutate_counts(|counts| {
            counts.get = counts.get.saturating_add(1);
        })?;
        let body = self.inner.get_range(object_id, range).await?;
        let bytes_read = u64::try_from(body.len())
            .map_err(|_| StorageError::Provider("read length does not fit in u64".to_owned()))?;
        self.mutate_counts(|counts| {
            counts.bytes_read = counts.bytes_read.saturating_add(bytes_read);
        })?;
        Ok(body)
    }

    async fn open_range_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        range: ByteRange,
    ) -> Result<Box<dyn BlobRead>> {
        self.mutate_counts(|counts| {
            counts.get = counts.get.saturating_add(1);
        })?;
        let inner = self
            .inner
            .open_range_at(object_id, version_id, range)
            .await?;
        Ok(Box::new(CountingBlobRead {
            inner,
            counts: Arc::clone(&self.counts),
        }))
    }

    async fn open_bounded_full_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        max_bytes: u64,
    ) -> Result<Box<dyn BlobRead>> {
        self.mutate_counts(|counts| {
            counts.get = counts.get.saturating_add(1);
        })?;
        let inner = self
            .inner
            .open_bounded_full_at(object_id, version_id, max_bytes)
            .await?;
        Ok(Box::new(CountingBlobRead {
            inner,
            counts: Arc::clone(&self.counts),
        }))
    }

    async fn get_range_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        range: ByteRange,
    ) -> Result<Bytes> {
        self.mutate_counts(|counts| {
            counts.get = counts.get.saturating_add(1);
        })?;
        let body = self
            .inner
            .get_range_at(object_id, version_id, range)
            .await?;
        let bytes_read = u64::try_from(body.len())
            .map_err(|_| StorageError::Provider("read length does not fit in u64".to_owned()))?;
        self.mutate_counts(|counts| {
            counts.bytes_read = counts.bytes_read.saturating_add(bytes_read);
        })?;
        Ok(body)
    }

    async fn head(&self, object_id: &BackendObjectId) -> Result<BlobMetadata> {
        self.mutate_counts(|counts| {
            counts.head = counts.head.saturating_add(1);
        })?;
        self.inner.head(object_id).await
    }

    async fn head_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
    ) -> Result<BlobMetadata> {
        self.mutate_counts(|counts| {
            counts.head = counts.head.saturating_add(1);
        })?;
        self.inner.head_at(object_id, version_id).await
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<BlobMetadata>> {
        self.mutate_counts(|counts| {
            counts.list = counts.list.saturating_add(1);
        })?;
        self.inner.list_prefix(prefix).await
    }

    async fn list_prefix_versions(&self, prefix: &str) -> Result<Vec<BlobMetadata>> {
        self.mutate_counts(|counts| {
            counts.list = counts.list.saturating_add(1);
        })?;
        self.inner.list_prefix_versions(prefix).await
    }

    async fn open_bounded_list(
        &self,
        prefix: &str,
        mode: BlobListMode,
    ) -> Result<Box<dyn BlobList>> {
        let inner = self.inner.open_bounded_list(prefix, mode).await?;
        Ok(Box::new(CountingBlobList {
            inner,
            counts: Arc::clone(&self.counts),
        }))
    }

    async fn delete(&self, object_id: &BackendObjectId) -> Result<()> {
        self.mutate_counts(|counts| {
            counts.delete = counts.delete.saturating_add(1);
        })?;
        self.inner.delete(object_id).await
    }

    async fn delete_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
    ) -> Result<()> {
        self.mutate_counts(|counts| {
            counts.delete = counts.delete.saturating_add(1);
        })?;
        self.inner.delete_at(object_id, version_id).await
    }

    async fn extend_retention(
        &self,
        object_id: &BackendObjectId,
        policy: RetentionPolicy,
    ) -> Result<()> {
        self.mutate_counts(|counts| {
            counts.extend_retention = counts.extend_retention.saturating_add(1);
        })?;
        self.inner.extend_retention(object_id, policy).await
    }

    async fn extend_retention_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        policy: RetentionPolicy,
    ) -> Result<()> {
        self.mutate_counts(|counts| {
            counts.extend_retention = counts.extend_retention.saturating_add(1);
        })?;
        self.inner
            .extend_retention_at(object_id, version_id, policy)
            .await
    }

    async fn set_legal_hold(
        &self,
        object_id: &BackendObjectId,
        status: LegalHoldStatus,
    ) -> Result<()> {
        self.mutate_counts(|counts| {
            counts.set_legal_hold = counts.set_legal_hold.saturating_add(1);
        })?;
        self.inner.set_legal_hold(object_id, status).await
    }

    async fn set_legal_hold_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        status: LegalHoldStatus,
    ) -> Result<()> {
        self.mutate_counts(|counts| {
            counts.set_legal_hold = counts.set_legal_hold.saturating_add(1);
        })?;
        self.inner
            .set_legal_hold_at(object_id, version_id, status)
            .await
    }

    async fn flush_caches(&self) -> Result<()> {
        self.mutate_counts(|counts| {
            counts.flush = counts.flush.saturating_add(1);
        })?;
        self.inner.flush_caches().await
    }
}

struct CountingBlobRead {
    inner: Box<dyn BlobRead>,
    counts: Arc<RwLock<BlobOperationCounts>>,
}

struct CountingBlobList {
    inner: Box<dyn BlobList>,
    counts: Arc<RwLock<BlobOperationCounts>>,
}

#[async_trait]
impl BlobList for CountingBlobList {
    async fn next_page(&mut self, max_items: NonZeroUsize) -> Result<BlobListPage> {
        {
            let mut counts = self.counts.write().map_err(|_| {
                StorageError::Provider("counting blob store lock poisoned".to_owned())
            })?;
            counts.list = counts.list.saturating_add(1);
        }
        let page = self.inner.next_page(max_items).await?;
        if page.consumed_items < page.entries.len() || page.consumed_items > max_items.get() {
            return Err(StorageError::InvalidListPage);
        }
        Ok(page)
    }
}

#[async_trait]
impl BlobRead for CountingBlobRead {
    fn exact_len(&self) -> u64 {
        self.inner.exact_len()
    }

    async fn next_chunk(&mut self) -> Result<Option<Bytes>> {
        let chunk = self.inner.next_chunk().await?;
        if let Some(chunk) = chunk.as_ref() {
            let chunk_len = u64::try_from(chunk.len()).map_err(|_| {
                StorageError::Provider("read length does not fit in u64".to_owned())
            })?;
            let mut counts = self.counts.write().map_err(|_| {
                StorageError::Provider("counting blob store lock poisoned".to_owned())
            })?;
            counts.bytes_read = counts.bytes_read.saturating_add(chunk_len);
        }
        Ok(chunk)
    }
}

struct CountingMultipartUpload {
    inner: Box<dyn BlobMultipartUpload>,
    counts: Arc<RwLock<BlobOperationCounts>>,
}

#[async_trait]
impl BlobMultipartUpload for CountingMultipartUpload {
    async fn put_part(&mut self, part_index: usize, body: Bytes) -> Result<()> {
        let attempted_len = u64::try_from(body.len())
            .map_err(|_| StorageError::Provider("upload length does not fit in u64".to_owned()))?;
        {
            let mut counts = self.counts.write().map_err(|_| {
                StorageError::Provider("counting blob store lock poisoned".to_owned())
            })?;
            counts.multipart_upload_part = counts.multipart_upload_part.saturating_add(1);
            counts.bytes_uploaded_attempted = counts
                .bytes_uploaded_attempted
                .saturating_add(attempted_len);
        }
        self.inner.put_part(part_index, body).await
    }

    async fn complete(self: Box<Self>) -> Result<BlobMetadata> {
        let Self { inner, counts } = *self;
        {
            let mut counts = counts.write().map_err(|_| {
                StorageError::Provider("counting blob store lock poisoned".to_owned())
            })?;
            counts.multipart_complete = counts.multipart_complete.saturating_add(1);
        }
        let metadata = inner.complete().await?;
        let mut counts = counts
            .write()
            .map_err(|_| StorageError::Provider("counting blob store lock poisoned".to_owned()))?;
        counts.multipart_put = counts.multipart_put.saturating_add(1);
        counts.bytes_written = counts.bytes_written.saturating_add(metadata.content_len);
        Ok(metadata)
    }

    async fn abort(self: Box<Self>) -> Result<()> {
        let Self { inner, counts } = *self;
        {
            let mut counts = counts.write().map_err(|_| {
                StorageError::Provider("counting blob store lock poisoned".to_owned())
            })?;
            counts.multipart_abort = counts.multipart_abort.saturating_add(1);
        }
        inner.abort().await
    }
}

/// In-memory `BlobStore` implementation used for contract tests and local prototypes.
#[derive(Clone, Debug)]
pub struct MemoryBlobStore {
    state: Arc<RwLock<MemoryState>>,
}

#[derive(Clone, Debug)]
struct MemoryObject {
    body: Bytes,
    metadata: BlobMetadata,
}

#[derive(Debug, Default)]
struct MemoryState {
    objects: BTreeMap<BackendObjectId, Vec<MemoryObject>>,
    next_modified_at_ms: i64,
    next_version: u64,
    counts: BlobOperationCounts,
}

impl MemoryBlobStore {
    /// Creates an empty in-memory blob store.
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(MemoryState::default())),
        }
    }

    fn read_state(&self) -> Result<RwLockReadGuard<'_, MemoryState>> {
        self.state
            .read()
            .map_err(|_| StorageError::Provider("memory blob store lock poisoned".to_owned()))
    }

    /// Returns a snapshot of in-memory operation counters.
    pub fn operation_counts(&self) -> Result<BlobOperationCounts> {
        self.read_state().map(|state| state.counts.clone())
    }

    /// Resets operation counters without changing stored objects.
    pub fn reset_operation_counts(&self) -> Result<()> {
        let mut state = self.write_state()?;
        state.counts = BlobOperationCounts::default();
        Ok(())
    }

    fn write_state(&self) -> Result<RwLockWriteGuard<'_, MemoryState>> {
        self.state
            .write()
            .map_err(|_| StorageError::Provider("memory blob store lock poisoned".to_owned()))
    }
}

fn memory_object_at<'a>(
    versions: &'a [MemoryObject],
    version_id: Option<&BackendVersionId>,
) -> Option<&'a MemoryObject> {
    match version_id {
        Some(version_id) => versions
            .iter()
            .find(|object| object.metadata.version_id.as_ref() == Some(version_id)),
        None => versions.last(),
    }
}

fn memory_object_at_mut<'a>(
    versions: &'a mut [MemoryObject],
    version_id: Option<&BackendVersionId>,
) -> Option<&'a mut MemoryObject> {
    match version_id {
        Some(version_id) => versions
            .iter_mut()
            .find(|object| object.metadata.version_id.as_ref() == Some(version_id)),
        None => versions.last_mut(),
    }
}

impl Default for MemoryBlobStore {
    fn default() -> Self {
        Self::new()
    }
}

struct MemoryMultipartUpload {
    store: MemoryBlobStore,
    object_id: BackendObjectId,
    options: PutOptions,
    parts: BTreeMap<usize, Bytes>,
}

struct MemoryBlobList {
    store: MemoryBlobStore,
    prefix: String,
    mode: BlobListMode,
    current_after: Option<BackendObjectId>,
    version_after: Option<(BackendObjectId, usize)>,
    complete: bool,
}

#[async_trait]
impl BlobList for MemoryBlobList {
    async fn next_page(&mut self, max_items: NonZeroUsize) -> Result<BlobListPage> {
        if self.complete {
            return Ok(BlobListPage {
                entries: Vec::new(),
                consumed_items: 0,
                is_complete: true,
            });
        }

        let started = Instant::now();
        let object_kind = prefix_kind(&self.prefix);
        let mut state = self.store.write_state()?;
        state.counts.list = state.counts.list.saturating_add(1);

        let limit = max_items.get();
        let mut entries = Vec::with_capacity(limit.min(1_024));
        let mut has_more = false;
        match self.mode {
            BlobListMode::Current => {
                for (object_id, versions) in &state.objects {
                    if self
                        .current_after
                        .as_ref()
                        .is_some_and(|after| object_id <= after)
                        || !object_id.as_str().starts_with(&self.prefix)
                    {
                        continue;
                    }
                    let Some(object) = versions.last() else {
                        continue;
                    };
                    if entries.len() == limit {
                        has_more = true;
                        break;
                    }
                    self.current_after = Some(object_id.clone());
                    entries.push(object.metadata.clone());
                }
            }
            BlobListMode::Versions => {
                for (object_id, versions) in &state.objects {
                    if !object_id.as_str().starts_with(&self.prefix) {
                        continue;
                    }
                    for (version_index, object) in versions.iter().enumerate() {
                        if self.version_after.as_ref().is_some_and(
                            |(after_object_id, after_version_index)| {
                                object_id < after_object_id
                                    || (object_id == after_object_id
                                        && version_index <= *after_version_index)
                            },
                        ) {
                            continue;
                        }
                        if entries.len() == limit {
                            has_more = true;
                            break;
                        }
                        self.version_after = Some((object_id.clone(), version_index));
                        entries.push(object.metadata.clone());
                    }
                    if has_more {
                        break;
                    }
                }
            }
        }

        self.complete = !has_more;
        record_blob_list(object_kind, entries.len(), "ok", started.elapsed());
        let consumed_items = entries.len();
        Ok(BlobListPage {
            entries,
            consumed_items,
            is_complete: self.complete,
        })
    }
}

#[async_trait]
impl BlobMultipartUpload for MemoryMultipartUpload {
    async fn put_part(&mut self, part_index: usize, body: Bytes) -> Result<()> {
        if self.parts.insert(part_index, body).is_some() {
            return Err(StorageError::Provider(
                "multipart part was uploaded twice".to_owned(),
            ));
        }
        Ok(())
    }

    async fn complete(self: Box<Self>) -> Result<BlobMetadata> {
        let Self {
            store,
            object_id,
            options,
            parts,
        } = *self;
        let mut body = Vec::new();
        for expected in 0..parts.len() {
            let part = parts.get(&expected).ok_or_else(|| {
                StorageError::Provider("multipart upload has missing parts".to_owned())
            })?;
            body.extend_from_slice(part);
        }
        let metadata = store.put(&object_id, Bytes::from(body), options).await?;
        let mut state = store.write_state()?;
        state.counts.multipart_put = state.counts.multipart_put.saturating_add(1);
        Ok(metadata)
    }

    async fn abort(self: Box<Self>) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl BlobStore for MemoryBlobStore {
    async fn put(
        &self,
        object_id: &BackendObjectId,
        body: Bytes,
        options: PutOptions,
    ) -> Result<BlobMetadata> {
        let started = Instant::now();
        let object_kind = object_kind(object_id);
        let requested_len = body.len();
        let retention = options.retention.filter(retention_is_active);
        let retained = retention.is_some();
        let legal_hold = options.legal_hold;
        let mut state = self.write_state()?;
        state.counts.put = state.counts.put.saturating_add(1);

        if options.do_not_recreate && state.objects.contains_key(object_id) {
            record_blob_put(
                object_kind,
                requested_len,
                retained,
                "already_exists",
                started.elapsed(),
            );
            return Err(StorageError::AlreadyExists(object_id.clone()));
        }

        state.next_modified_at_ms = state.next_modified_at_ms.saturating_add(1);
        state.next_version = state.next_version.saturating_add(1);

        let content_len = u64::try_from(body.len())
            .map_err(|_| StorageError::Provider("object length does not fit in u64".to_owned()))?;
        let retain_until_ms = retain_until_ms(retention);
        let metadata = BlobMetadata {
            object_id: object_id.clone(),
            content_len,
            modified_at_ms: Some(state.next_modified_at_ms),
            etag: Some(format!("mem-{}-{}", state.next_version, body.len())),
            version_id: Some(
                BackendVersionId::new(format!("mem-v{}", state.next_version))
                    .map_err(|error| StorageError::Provider(error.to_string()))?,
            ),
            retention,
            retain_until_ms,
            legal_hold,
        };
        state.counts.bytes_written = state.counts.bytes_written.saturating_add(content_len);

        state
            .objects
            .entry(object_id.clone())
            .or_default()
            .push(MemoryObject {
                body,
                metadata: metadata.clone(),
            });

        record_blob_put(
            object_kind,
            requested_len,
            retained,
            "ok",
            started.elapsed(),
        );
        Ok(metadata)
    }

    fn supports_multipart_upload(&self) -> bool {
        true
    }

    async fn create_multipart_upload(
        &self,
        object_id: &BackendObjectId,
        options: PutOptions,
    ) -> Result<Box<dyn BlobMultipartUpload>> {
        Ok(Box::new(MemoryMultipartUpload {
            store: self.clone(),
            object_id: object_id.clone(),
            options,
            parts: BTreeMap::new(),
        }))
    }

    async fn get_range(&self, object_id: &BackendObjectId, range: ByteRange) -> Result<Bytes> {
        let started = Instant::now();
        let object_kind = object_kind(object_id);
        let mut state = self.write_state()?;
        state.counts.get = state.counts.get.saturating_add(1);

        let Some(object) = state
            .objects
            .get(object_id)
            .and_then(|versions| versions.last())
        else {
            record_blob_get(object_kind, range, 0, "not_found", started.elapsed());
            return Err(StorageError::NotFound(object_id.clone()));
        };

        let body = match read_range(&object.body, range) {
            Ok(body) => body,
            Err(error) => {
                record_blob_get(object_kind, range, 0, "invalid_range", started.elapsed());
                return Err(error);
            }
        };
        let bytes_read = u64::try_from(body.len())
            .map_err(|_| StorageError::Provider("read length does not fit in u64".to_owned()))?;
        state.counts.bytes_read = state.counts.bytes_read.saturating_add(bytes_read);

        record_blob_get(object_kind, range, bytes_read, "ok", started.elapsed());
        Ok(body)
    }

    async fn get_range_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        range: ByteRange,
    ) -> Result<Bytes> {
        let started = Instant::now();
        let object_kind = object_kind(object_id);
        let mut state = self.write_state()?;
        state.counts.get = state.counts.get.saturating_add(1);

        let Some(object) = state
            .objects
            .get(object_id)
            .and_then(|versions| memory_object_at(versions, version_id))
        else {
            record_blob_get(object_kind, range, 0, "not_found", started.elapsed());
            return Err(StorageError::NotFound(object_id.clone()));
        };

        let body = match read_range(&object.body, range) {
            Ok(body) => body,
            Err(error) => {
                record_blob_get(object_kind, range, 0, "invalid_range", started.elapsed());
                return Err(error);
            }
        };
        let bytes_read = u64::try_from(body.len())
            .map_err(|_| StorageError::Provider("read length does not fit in u64".to_owned()))?;
        state.counts.bytes_read = state.counts.bytes_read.saturating_add(bytes_read);

        record_blob_get(object_kind, range, bytes_read, "ok", started.elapsed());
        Ok(body)
    }

    async fn open_range_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        range: ByteRange,
    ) -> Result<Box<dyn BlobRead>> {
        let started = Instant::now();
        let kind = object_kind(object_id).to_owned();
        let body = {
            let mut state = self.write_state()?;
            state.counts.get = state.counts.get.saturating_add(1);
            let Some(object) = state
                .objects
                .get(object_id)
                .and_then(|versions| memory_object_at(versions, version_id))
            else {
                record_blob_get(&kind, range, 0, "not_found", started.elapsed());
                return Err(StorageError::NotFound(object_id.clone()));
            };
            match read_range(&object.body, range) {
                Ok(body) => body,
                Err(error) => {
                    record_blob_get(&kind, range, 0, "invalid_range", started.elapsed());
                    return Err(error);
                }
            }
        };
        let exact_len = u64::try_from(body.len())
            .map_err(|_| StorageError::Provider("read length does not fit in u64".to_owned()))?;
        Ok(Box::new(ObservedMemoryRead {
            inner: read::bytes_blob_read(body, exact_len),
            store: self.clone(),
            kind,
            range,
            started,
            bytes_read: 0,
            terminal: false,
        }))
    }

    async fn open_bounded_full_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        max_bytes: u64,
    ) -> Result<Box<dyn BlobRead>> {
        let read = self
            .open_range_at(object_id, version_id, ByteRange::Full)
            .await?;
        read::enforce_full_read_bound(read, max_bytes)
    }

    async fn head(&self, object_id: &BackendObjectId) -> Result<BlobMetadata> {
        let started = Instant::now();
        let object_kind = object_kind(object_id);
        let mut state = self.write_state()?;
        state.counts.head = state.counts.head.saturating_add(1);

        match state
            .objects
            .get(object_id)
            .and_then(|versions| versions.last())
        {
            Some(object) => {
                record_blob_head(object_kind, "ok", started.elapsed());
                Ok(object.metadata.clone())
            }
            None => {
                record_blob_head(object_kind, "not_found", started.elapsed());
                Err(StorageError::NotFound(object_id.clone()))
            }
        }
    }

    async fn head_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
    ) -> Result<BlobMetadata> {
        let started = Instant::now();
        let object_kind = object_kind(object_id);
        let mut state = self.write_state()?;
        state.counts.head = state.counts.head.saturating_add(1);

        match state
            .objects
            .get(object_id)
            .and_then(|versions| memory_object_at(versions, version_id))
        {
            Some(object) => {
                record_blob_head(object_kind, "ok", started.elapsed());
                Ok(object.metadata.clone())
            }
            None => {
                record_blob_head(object_kind, "not_found", started.elapsed());
                Err(StorageError::NotFound(object_id.clone()))
            }
        }
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<BlobMetadata>> {
        let started = Instant::now();
        let object_kind = prefix_kind(prefix);
        let mut state = self.write_state()?;
        state.counts.list = state.counts.list.saturating_add(1);

        let entries = state
            .objects
            .iter()
            .filter(|(object_id, _)| object_id.as_str().starts_with(prefix))
            .filter_map(|(_, versions)| versions.last())
            .map(|object| object.metadata.clone())
            .collect::<Vec<_>>();
        record_blob_list(object_kind, entries.len(), "ok", started.elapsed());

        Ok(entries)
    }

    async fn list_prefix_versions(&self, prefix: &str) -> Result<Vec<BlobMetadata>> {
        let started = Instant::now();
        let object_kind = prefix_kind(prefix);
        let mut state = self.write_state()?;
        state.counts.list = state.counts.list.saturating_add(1);

        let mut entries = state
            .objects
            .iter()
            .filter(|(object_id, _)| object_id.as_str().starts_with(prefix))
            .flat_map(|(_, versions)| versions.iter().map(|object| object.metadata.clone()))
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| {
            left.object_id
                .cmp(&right.object_id)
                .then_with(|| left.version_id.cmp(&right.version_id))
        });
        record_blob_list(object_kind, entries.len(), "ok", started.elapsed());

        Ok(entries)
    }

    async fn open_bounded_list(
        &self,
        prefix: &str,
        mode: BlobListMode,
    ) -> Result<Box<dyn BlobList>> {
        Ok(Box::new(MemoryBlobList {
            store: self.clone(),
            prefix: prefix.to_owned(),
            mode,
            current_after: None,
            version_after: None,
            complete: false,
        }))
    }

    async fn delete(&self, object_id: &BackendObjectId) -> Result<()> {
        let started = Instant::now();
        let object_kind = object_kind(object_id);
        let mut state = self.write_state()?;
        state.counts.delete = state.counts.delete.saturating_add(1);

        let Some(object) = state
            .objects
            .get(object_id)
            .and_then(|versions| versions.last())
        else {
            record_blob_delete(object_kind, "not_found", started.elapsed());
            return Err(StorageError::NotFound(object_id.clone()));
        };

        if retention_blocks_delete(object.metadata.retention.as_ref()) {
            record_blob_delete(object_kind, "retention_blocked", started.elapsed());
            return Err(StorageError::RetentionBlocked);
        }
        if legal_hold_blocks_delete(object.metadata.legal_hold) {
            record_blob_delete(object_kind, "legal_hold_blocked", started.elapsed());
            return Err(StorageError::LegalHoldBlocked);
        }

        state.objects.remove(object_id);
        record_blob_delete(object_kind, "ok", started.elapsed());
        Ok(())
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
        let mut state = self.write_state()?;
        state.counts.delete = state.counts.delete.saturating_add(1);

        let Some(versions) = state.objects.get_mut(object_id) else {
            record_blob_delete(object_kind, "not_found", started.elapsed());
            return Err(StorageError::NotFound(object_id.clone()));
        };
        let Some(index) = versions
            .iter()
            .position(|object| object.metadata.version_id.as_ref() == Some(version_id))
        else {
            record_blob_delete(object_kind, "not_found", started.elapsed());
            return Err(StorageError::NotFound(object_id.clone()));
        };

        let metadata = &versions[index].metadata;
        if retention_blocks_delete(metadata.retention.as_ref()) {
            record_blob_delete(object_kind, "retention_blocked", started.elapsed());
            return Err(StorageError::RetentionBlocked);
        }
        if legal_hold_blocks_delete(metadata.legal_hold) {
            record_blob_delete(object_kind, "legal_hold_blocked", started.elapsed());
            return Err(StorageError::LegalHoldBlocked);
        }

        versions.remove(index);
        if versions.is_empty() {
            state.objects.remove(object_id);
        }
        record_blob_delete(object_kind, "ok", started.elapsed());
        Ok(())
    }

    async fn extend_retention(
        &self,
        object_id: &BackendObjectId,
        policy: RetentionPolicy,
    ) -> Result<()> {
        let started = Instant::now();
        let object_kind = object_kind(object_id);
        let mut state = self.write_state()?;
        state.counts.extend_retention = state.counts.extend_retention.saturating_add(1);

        let Some(object) = state
            .objects
            .get_mut(object_id)
            .and_then(|versions| versions.last_mut())
        else {
            record_blob_extend_retention(object_kind, "not_found", started.elapsed());
            return Err(StorageError::NotFound(object_id.clone()));
        };

        object.metadata.retention =
            Some(merge_retention(object.metadata.retention.as_ref(), policy));
        object.metadata.retain_until_ms = merge_retain_until(
            object.metadata.retain_until_ms,
            retain_until_ms(Some(policy)),
        );

        record_blob_extend_retention(object_kind, "ok", started.elapsed());
        Ok(())
    }

    async fn extend_retention_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        policy: RetentionPolicy,
    ) -> Result<()> {
        let started = Instant::now();
        let object_kind = object_kind(object_id);
        let mut state = self.write_state()?;
        state.counts.extend_retention = state.counts.extend_retention.saturating_add(1);

        let Some(object) = state
            .objects
            .get_mut(object_id)
            .and_then(|versions| memory_object_at_mut(versions, version_id))
        else {
            record_blob_extend_retention(object_kind, "not_found", started.elapsed());
            return Err(StorageError::NotFound(object_id.clone()));
        };

        object.metadata.retention =
            Some(merge_retention(object.metadata.retention.as_ref(), policy));
        object.metadata.retain_until_ms = merge_retain_until(
            object.metadata.retain_until_ms,
            retain_until_ms(Some(policy)),
        );

        record_blob_extend_retention(object_kind, "ok", started.elapsed());
        Ok(())
    }

    async fn set_legal_hold(
        &self,
        object_id: &BackendObjectId,
        status: LegalHoldStatus,
    ) -> Result<()> {
        let started = Instant::now();
        let object_kind = object_kind(object_id);
        let mut state = self.write_state()?;
        state.counts.set_legal_hold = state.counts.set_legal_hold.saturating_add(1);

        let Some(object) = state
            .objects
            .get_mut(object_id)
            .and_then(|versions| versions.last_mut())
        else {
            record_blob_set_legal_hold(object_kind, "not_found", started.elapsed());
            return Err(StorageError::NotFound(object_id.clone()));
        };

        object.metadata.legal_hold = Some(status);

        record_blob_set_legal_hold(object_kind, "ok", started.elapsed());
        Ok(())
    }

    async fn set_legal_hold_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        status: LegalHoldStatus,
    ) -> Result<()> {
        let started = Instant::now();
        let object_kind = object_kind(object_id);
        let mut state = self.write_state()?;
        state.counts.set_legal_hold = state.counts.set_legal_hold.saturating_add(1);

        let Some(object) = state
            .objects
            .get_mut(object_id)
            .and_then(|versions| memory_object_at_mut(versions, version_id))
        else {
            record_blob_set_legal_hold(object_kind, "not_found", started.elapsed());
            return Err(StorageError::NotFound(object_id.clone()));
        };

        object.metadata.legal_hold = Some(status);

        record_blob_set_legal_hold(object_kind, "ok", started.elapsed());
        Ok(())
    }

    async fn flush_caches(&self) -> Result<()> {
        let started = Instant::now();
        let mut state = self.write_state()?;
        state.counts.flush = state.counts.flush.saturating_add(1);
        tracing::debug!(
            target: "rs3_storage",
            operation = "flush_caches",
            result = "ok",
            elapsed_us = elapsed_us(started.elapsed()),
            "blob store operation completed",
        );
        Ok(())
    }
}

struct ObservedMemoryRead {
    inner: Box<dyn BlobRead>,
    store: MemoryBlobStore,
    kind: String,
    range: ByteRange,
    started: Instant,
    bytes_read: u64,
    terminal: bool,
}

#[async_trait]
impl BlobRead for ObservedMemoryRead {
    fn exact_len(&self) -> u64 {
        self.inner.exact_len()
    }

    async fn next_chunk(&mut self) -> Result<Option<Bytes>> {
        match self.inner.next_chunk().await {
            Ok(Some(chunk)) => {
                let chunk_len = u64::try_from(chunk.len()).map_err(|_| {
                    StorageError::Provider("read length does not fit in u64".to_owned())
                })?;
                let mut state = self.store.write_state()?;
                state.counts.bytes_read = state.counts.bytes_read.saturating_add(chunk_len);
                self.bytes_read = self.bytes_read.saturating_add(chunk_len);
                Ok(Some(chunk))
            }
            Ok(None) => {
                self.record("ok");
                Ok(None)
            }
            Err(error) => {
                self.record("error");
                Err(error)
            }
        }
    }
}

impl ObservedMemoryRead {
    fn record(&mut self, result: &str) {
        if self.terminal {
            return;
        }
        self.terminal = true;
        record_blob_get(
            &self.kind,
            self.range,
            self.bytes_read,
            result,
            self.started.elapsed(),
        );
    }
}

impl Drop for ObservedMemoryRead {
    fn drop(&mut self) {
        self.record("cancelled");
    }
}

pub(crate) fn record_blob_put(
    object_kind: &str,
    requested_len: usize,
    retained: bool,
    result: &str,
    elapsed: Duration,
) {
    tracing::debug!(
        target: "rs3_storage",
        operation = "put",
        object_kind,
        requested_len,
        retained,
        result,
        elapsed_us = elapsed_us(elapsed),
        "blob store operation completed",
    );
}

pub(crate) fn record_blob_get(
    object_kind: &str,
    range: ByteRange,
    bytes_read: u64,
    result: &str,
    elapsed: Duration,
) {
    match range {
        ByteRange::Full => tracing::debug!(
            target: "rs3_storage",
            operation = "get_range",
            object_kind,
            range = "full",
            bytes_read,
            result,
            elapsed_us = elapsed_us(elapsed),
            "blob store operation completed",
        ),
        ByteRange::Slice { offset, len } => tracing::debug!(
            target: "rs3_storage",
            operation = "get_range",
            object_kind,
            range = "slice",
            range_offset = offset,
            range_len = len,
            bytes_read,
            result,
            elapsed_us = elapsed_us(elapsed),
            "blob store operation completed",
        ),
    }
}

pub(crate) fn record_blob_head(object_kind: &str, result: &str, elapsed: Duration) {
    tracing::debug!(
        target: "rs3_storage",
        operation = "head",
        object_kind,
        result,
        elapsed_us = elapsed_us(elapsed),
        "blob store operation completed",
    );
}

pub(crate) fn record_blob_list(object_kind: &str, entries: usize, result: &str, elapsed: Duration) {
    tracing::debug!(
        target: "rs3_storage",
        operation = "list_prefix",
        object_kind,
        entries,
        result,
        elapsed_us = elapsed_us(elapsed),
        "blob store operation completed",
    );
}

pub(crate) fn record_blob_delete(object_kind: &str, result: &str, elapsed: Duration) {
    tracing::debug!(
        target: "rs3_storage",
        operation = "delete",
        object_kind,
        result,
        elapsed_us = elapsed_us(elapsed),
        "blob store operation completed",
    );
}

pub(crate) fn record_blob_extend_retention(object_kind: &str, result: &str, elapsed: Duration) {
    tracing::debug!(
        target: "rs3_storage",
        operation = "extend_retention",
        object_kind,
        result,
        elapsed_us = elapsed_us(elapsed),
        "blob store operation completed",
    );
}

pub(crate) fn record_blob_set_legal_hold(object_kind: &str, result: &str, elapsed: Duration) {
    tracing::debug!(
        target: "rs3_storage",
        operation = "set_legal_hold",
        object_kind,
        result,
        elapsed_us = elapsed_us(elapsed),
        "blob store operation completed",
    );
}

pub(crate) fn read_range(body: &Bytes, range: ByteRange) -> Result<Bytes> {
    match range {
        ByteRange::Full => Ok(body.clone()),
        ByteRange::Slice { offset, len } => {
            let start = usize::try_from(offset).map_err(|_| StorageError::InvalidRange)?;
            let length = usize::try_from(len).map_err(|_| StorageError::InvalidRange)?;
            let end = start
                .checked_add(length)
                .ok_or(StorageError::InvalidRange)?;

            if start > body.len() || end > body.len() {
                return Err(StorageError::InvalidRange);
            }

            Ok(body.slice(start..end))
        }
    }
}

fn retention_blocks_delete(policy: Option<&RetentionPolicy>) -> bool {
    policy.is_some_and(retention_is_active)
}

fn legal_hold_blocks_delete(status: Option<LegalHoldStatus>) -> bool {
    status == Some(LegalHoldStatus::On)
}

fn retain_until_ms(policy: Option<RetentionPolicy>) -> Option<i64> {
    let policy = policy?;
    if !retention_is_active(&policy) {
        return None;
    }
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())?;
    let retain_ms = i64::from(policy.retain_days).checked_mul(86_400_000)?;
    now_ms.checked_add(retain_ms)
}

fn retention_is_active(policy: &RetentionPolicy) -> bool {
    policy.mode != RetentionMode::None && policy.retain_days > 0
}

fn merge_retain_until(left: Option<i64>, right: Option<i64>) -> Option<i64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn merge_retention(existing: Option<&RetentionPolicy>, next: RetentionPolicy) -> RetentionPolicy {
    match existing {
        Some(existing) => RetentionPolicy {
            mode: stronger_retention_mode(existing.mode, next.mode),
            retain_days: existing.retain_days.max(next.retain_days),
        },
        None => next,
    }
}

fn stronger_retention_mode(left: RetentionMode, right: RetentionMode) -> RetentionMode {
    match (left, right) {
        (RetentionMode::Compliance, _) | (_, RetentionMode::Compliance) => {
            RetentionMode::Compliance
        }
        (RetentionMode::Governance, _) | (_, RetentionMode::Governance) => {
            RetentionMode::Governance
        }
        (RetentionMode::None, RetentionMode::None) => RetentionMode::None,
    }
}

pub(crate) fn object_kind(object_id: &BackendObjectId) -> &str {
    prefix_kind(object_id.as_str())
}

pub(crate) fn prefix_kind(value: &str) -> &str {
    value.split_once('/').map_or("other", |(prefix, _)| prefix)
}

pub(crate) fn elapsed_us(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{
        BlobListMode, BlobMetadata, BlobStore, ByteRange, CountingBlobStore, MemoryBlobStore,
        PutOptions, Result, StorageError, read_bounded_full_at, read_range,
        retention_blocks_delete,
    };
    #[cfg(feature = "test-util")]
    use super::{
        FaultAction, FaultInjectingBlobStore, FaultMatcher, FaultOperationKind, FaultRule,
    };
    use bytes::Bytes;
    use rs3_types::{BackendObjectId, LegalHoldStatus, RetentionMode, RetentionPolicy};
    use std::num::NonZeroUsize;

    struct LegacyOnlyBlobStore(MemoryBlobStore);

    #[async_trait::async_trait]
    impl BlobStore for LegacyOnlyBlobStore {
        async fn put(
            &self,
            object_id: &BackendObjectId,
            body: Bytes,
            options: PutOptions,
        ) -> Result<BlobMetadata> {
            self.0.put(object_id, body, options).await
        }

        async fn get_range(&self, object_id: &BackendObjectId, range: ByteRange) -> Result<Bytes> {
            self.0.get_range(object_id, range).await
        }

        async fn head(&self, object_id: &BackendObjectId) -> Result<BlobMetadata> {
            self.0.head(object_id).await
        }

        async fn list_prefix(&self, prefix: &str) -> Result<Vec<BlobMetadata>> {
            self.0.list_prefix(prefix).await
        }

        async fn delete(&self, object_id: &BackendObjectId) -> Result<()> {
            self.0.delete(object_id).await
        }

        async fn extend_retention(
            &self,
            object_id: &BackendObjectId,
            policy: RetentionPolicy,
        ) -> Result<()> {
            self.0.extend_retention(object_id, policy).await
        }

        async fn set_legal_hold(
            &self,
            object_id: &BackendObjectId,
            status: LegalHoldStatus,
        ) -> Result<()> {
            self.0.set_legal_hold(object_id, status).await
        }

        async fn flush_caches(&self) -> Result<()> {
            self.0.flush_caches().await
        }
    }

    fn object_id(value: &str) -> BackendObjectId {
        match BackendObjectId::new(value) {
            Ok(object_id) => object_id,
            Err(error) => panic!("{error}"),
        }
    }

    fn counts(store: &MemoryBlobStore) -> super::BlobOperationCounts {
        match store.operation_counts() {
            Ok(counts) => counts,
            Err(error) => panic!("{error}"),
        }
    }

    fn page_size(value: usize) -> NonZeroUsize {
        NonZeroUsize::new(value).unwrap_or_else(|| panic!("page size must be non-zero"))
    }

    #[test]
    fn reads_valid_byte_range() {
        let body = Bytes::from_static(b"hello world");

        let range = read_range(&body, ByteRange::Slice { offset: 6, len: 5 });

        assert_eq!(range, Ok(Bytes::from_static(b"world")));
    }

    #[test]
    fn rejects_invalid_byte_range() {
        let body = Bytes::from_static(b"hello");

        let range = read_range(&body, ByteRange::Slice { offset: 4, len: 2 });

        assert_eq!(range, Err(StorageError::InvalidRange));
    }

    #[test]
    fn retention_policy_blocks_delete() {
        let policy = RetentionPolicy::new(RetentionMode::Compliance, 30);

        assert!(retention_blocks_delete(Some(&policy)));
    }

    #[test]
    fn legal_hold_on_blocks_delete() {
        assert!(super::legal_hold_blocks_delete(Some(LegalHoldStatus::On)));
        assert!(!super::legal_hold_blocks_delete(Some(LegalHoldStatus::Off)));
        assert!(!super::legal_hold_blocks_delete(None));
    }

    #[tokio::test]
    async fn put_then_head_does_not_read_body() {
        let store = MemoryBlobStore::new();
        let object_id = object_id("segments/a");

        let put = store
            .put(
                &object_id,
                Bytes::from_static(b"hello world"),
                PutOptions::default(),
            )
            .await;
        assert!(put.is_ok());

        let head = store.head(&object_id).await;

        assert!(head.is_ok());
        assert_eq!(head.map(|metadata| metadata.content_len), Ok(11));

        let counts = counts(&store);
        assert_eq!(counts.head, 1);
        assert_eq!(counts.get, 0);
    }

    #[tokio::test]
    async fn get_range_returns_requested_slice() {
        let store = MemoryBlobStore::new();
        let object_id = object_id("segments/a");

        let put = store
            .put(
                &object_id,
                Bytes::from_static(b"hello world"),
                PutOptions::default(),
            )
            .await;
        assert!(put.is_ok());

        let body = store
            .get_range(&object_id, ByteRange::Slice { offset: 6, len: 5 })
            .await;

        assert_eq!(body, Ok(Bytes::from_static(b"world")));

        let counts = counts(&store);
        assert_eq!(counts.get, 1);
        assert_eq!(counts.bytes_read, 5);
    }

    #[tokio::test]
    async fn version_addressed_reads_return_requested_memory_version() {
        let store = MemoryBlobStore::new();
        let object_id = object_id("segments/versioned");

        let first = store
            .put(
                &object_id,
                Bytes::from_static(b"first"),
                PutOptions::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let second = store
            .put(
                &object_id,
                Bytes::from_static(b"second"),
                PutOptions::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_ne!(first.version_id, second.version_id);
        let first_version = first
            .version_id
            .as_ref()
            .unwrap_or_else(|| panic!("memory put should return a version id"));

        let latest = store.get_range(&object_id, ByteRange::Full).await;
        let versioned = store
            .get_range_at(&object_id, Some(first_version), ByteRange::Full)
            .await;

        assert_eq!(latest, Ok(Bytes::from_static(b"second")));
        assert_eq!(versioned, Ok(Bytes::from_static(b"first")));
    }

    #[tokio::test]
    async fn create_only_put_rejects_duplicate() {
        let store = MemoryBlobStore::new();
        let object_id = object_id("segments/a");
        let options = PutOptions {
            do_not_recreate: true,
            ..PutOptions::default()
        };

        let first = store
            .put(&object_id, Bytes::from_static(b"first"), options.clone())
            .await;
        let second = store
            .put(&object_id, Bytes::from_static(b"second"), options)
            .await;

        assert!(first.is_ok());
        assert!(matches!(second, Err(StorageError::AlreadyExists(_))));

        let counts = counts(&store);
        assert_eq!(counts.put, 2);
        assert_eq!(counts.bytes_written, 5);
    }

    #[tokio::test]
    async fn operation_counts_can_be_reset_without_removing_objects() {
        let store = MemoryBlobStore::new();
        let object_id = object_id("segments/a");

        let put = store
            .put(
                &object_id,
                Bytes::from_static(b"body"),
                PutOptions::default(),
            )
            .await;
        assert!(put.is_ok());
        let reset = store.reset_operation_counts();
        let head = store.head(&object_id).await;

        assert!(reset.is_ok());
        assert!(head.is_ok());

        let counts = counts(&store);
        assert_eq!(counts.put, 0);
        assert_eq!(counts.head, 1);
        assert_eq!(counts.bytes_written, 0);
    }

    #[tokio::test]
    async fn list_prefix_returns_only_matching_objects() {
        let store = MemoryBlobStore::new();
        for name in ["segments/a", "segments/b", "index/a"] {
            let put = store
                .put(
                    &object_id(name),
                    Bytes::from_static(b"body"),
                    PutOptions::default(),
                )
                .await;
            assert!(put.is_ok());
        }

        let listed = store.list_prefix("segments/").await;
        let object_ids = match listed {
            Ok(metadata) => metadata
                .into_iter()
                .map(|metadata| metadata.object_id)
                .collect::<Vec<_>>(),
            Err(error) => panic!("{error}"),
        };

        assert_eq!(
            object_ids,
            vec![object_id("segments/a"), object_id("segments/b")]
        );
    }

    #[tokio::test]
    async fn bounded_listing_fails_closed_without_provider_support() {
        let store = LegacyOnlyBlobStore(MemoryBlobStore::new());

        let listing = store
            .open_bounded_list("segments/", BlobListMode::Current)
            .await;

        assert!(matches!(
            listing,
            Err(StorageError::PagedListingUnsupported)
        ));
    }

    #[tokio::test]
    async fn bounded_read_fails_closed_without_provider_support_before_buffering() {
        let inner = MemoryBlobStore::new();
        let object_id = object_id("format/root");
        inner
            .put(
                &object_id,
                Bytes::from_static(b"oversized-control-object"),
                PutOptions::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        inner
            .reset_operation_counts()
            .unwrap_or_else(|error| panic!("{error}"));
        let store = LegacyOnlyBlobStore(inner.clone());

        let result = read_bounded_full_at(&store, &object_id, None, 4).await;

        assert_eq!(result, Err(StorageError::BoundedReadUnsupported));
        assert_eq!(counts(&inner).get, 0);
    }

    #[tokio::test]
    async fn memory_store_pages_current_objects_with_a_hard_bound() {
        let store = MemoryBlobStore::new();
        for name in ["segments/a", "segments/b", "segments/c", "index/a"] {
            store
                .put(
                    &object_id(name),
                    Bytes::from_static(b"body"),
                    PutOptions::default(),
                )
                .await
                .unwrap_or_else(|error| panic!("put object: {error}"));
        }
        let mut listing = store
            .open_bounded_list("segments/", BlobListMode::Current)
            .await
            .unwrap_or_else(|error| panic!("open listing: {error}"));

        let first = listing
            .next_page(page_size(2))
            .await
            .unwrap_or_else(|error| panic!("read first page: {error}"));
        let second = listing
            .next_page(page_size(2))
            .await
            .unwrap_or_else(|error| panic!("read second page: {error}"));

        assert_eq!(first.entries.len(), 2);
        assert!(!first.is_complete);
        assert_eq!(second.entries.len(), 1);
        assert!(second.is_complete);
        let object_ids = first
            .entries
            .into_iter()
            .chain(second.entries)
            .map(|metadata| metadata.object_id)
            .collect::<Vec<_>>();
        assert_eq!(
            object_ids,
            vec![
                object_id("segments/a"),
                object_id("segments/b"),
                object_id("segments/c")
            ]
        );
    }

    #[tokio::test]
    async fn memory_store_pages_exact_versions_without_duplicates() {
        let store = MemoryBlobStore::new();
        let first_id = object_id("segments/a");
        for body in [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()] {
            store
                .put(
                    &first_id,
                    Bytes::copy_from_slice(body),
                    PutOptions::default(),
                )
                .await
                .unwrap_or_else(|error| panic!("put version: {error}"));
        }
        store
            .put(
                &object_id("segments/b"),
                Bytes::from_static(b"four"),
                PutOptions::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("put object: {error}"));
        let mut listing = store
            .open_bounded_list("segments/", BlobListMode::Versions)
            .await
            .unwrap_or_else(|error| panic!("open listing: {error}"));
        let mut versions = Vec::new();
        loop {
            let page = listing
                .next_page(page_size(2))
                .await
                .unwrap_or_else(|error| panic!("read page: {error}"));
            assert!(page.entries.len() <= 2);
            versions.extend(
                page.entries
                    .into_iter()
                    .map(|metadata| (metadata.object_id, metadata.version_id)),
            );
            if page.is_complete {
                break;
            }
        }

        assert_eq!(versions.len(), 4);
        let unique = versions.iter().collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique.len(), versions.len());
    }

    #[tokio::test]
    async fn counting_store_counts_each_bounded_list_page() {
        let store = CountingBlobStore::new(MemoryBlobStore::new());
        for name in ["segments/a", "segments/b"] {
            store
                .put(
                    &object_id(name),
                    Bytes::from_static(b"body"),
                    PutOptions::default(),
                )
                .await
                .unwrap_or_else(|error| panic!("put object: {error}"));
        }
        store
            .reset_operation_counts()
            .unwrap_or_else(|error| panic!("reset counts: {error}"));
        let mut listing = store
            .open_bounded_list("segments/", BlobListMode::Current)
            .await
            .unwrap_or_else(|error| panic!("open listing: {error}"));

        let first = listing
            .next_page(page_size(1))
            .await
            .unwrap_or_else(|error| panic!("read first page: {error}"));
        let second = listing
            .next_page(page_size(1))
            .await
            .unwrap_or_else(|error| panic!("read second page: {error}"));

        assert!(!first.is_complete);
        assert!(second.is_complete);
        assert_eq!(store.operation_counts().map(|counts| counts.list), Ok(2));
    }

    #[cfg(feature = "test-util")]
    #[tokio::test]
    async fn fault_store_injects_faults_at_bounded_page_boundaries() {
        let inner = MemoryBlobStore::new();
        inner
            .put(
                &object_id("segments/a"),
                Bytes::from_static(b"body"),
                PutOptions::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("put object: {error}"));
        let store = FaultInjectingBlobStore::new(
            inner,
            vec![FaultRule::new(
                FaultMatcher::operation(FaultOperationKind::ListPrefixPage),
                FaultAction::return_error("page failed"),
            )],
        );
        let mut listing = store
            .open_bounded_list("segments/", BlobListMode::Current)
            .await
            .unwrap_or_else(|error| panic!("open listing: {error}"));

        let page = listing.next_page(page_size(1)).await;

        assert!(matches!(page, Err(StorageError::Provider(_))));
        assert_eq!(
            store
                .operation_log()
                .map(|events| events.first().map(|event| event.kind)),
            Ok(Some(FaultOperationKind::ListPrefixPage))
        );
    }

    #[tokio::test]
    async fn delete_is_blocked_by_active_retention() {
        let store = MemoryBlobStore::new();
        let object_id = object_id("segments/a");
        let options = PutOptions {
            retention: Some(RetentionPolicy::new(RetentionMode::Compliance, 30)),
            ..PutOptions::default()
        };

        let put = store
            .put(&object_id, Bytes::from_static(b"body"), options)
            .await;
        assert!(put.is_ok());

        let delete = store.delete(&object_id).await;

        assert_eq!(delete, Err(StorageError::RetentionBlocked));
    }

    #[tokio::test]
    async fn delete_is_blocked_by_legal_hold() {
        let store = MemoryBlobStore::new();
        let object_id = object_id("segments/a");
        let options = PutOptions {
            legal_hold: Some(LegalHoldStatus::On),
            ..PutOptions::default()
        };

        let put = store
            .put(&object_id, Bytes::from_static(b"body"), options)
            .await;
        assert!(put.is_ok());

        let delete = store.delete(&object_id).await;

        assert_eq!(delete, Err(StorageError::LegalHoldBlocked));
    }

    #[tokio::test]
    async fn legal_hold_can_be_cleared() {
        let store = MemoryBlobStore::new();
        let object_id = object_id("segments/a");
        let options = PutOptions {
            legal_hold: Some(LegalHoldStatus::On),
            ..PutOptions::default()
        };

        let put = store
            .put(&object_id, Bytes::from_static(b"body"), options)
            .await;
        assert!(put.is_ok());
        let clear = store.set_legal_hold(&object_id, LegalHoldStatus::Off).await;
        let delete = store.delete(&object_id).await;

        assert!(clear.is_ok());
        assert!(delete.is_ok());
    }

    #[tokio::test]
    async fn retention_extension_never_shortens_policy() {
        let store = MemoryBlobStore::new();
        let object_id = object_id("segments/a");
        let options = PutOptions {
            retention: Some(RetentionPolicy::new(RetentionMode::Compliance, 30)),
            ..PutOptions::default()
        };

        let put = store
            .put(&object_id, Bytes::from_static(b"body"), options)
            .await;
        assert!(put.is_ok());

        let extend = store
            .extend_retention(
                &object_id,
                RetentionPolicy::new(RetentionMode::Governance, 10),
            )
            .await;
        assert!(extend.is_ok());

        let retention = store
            .head(&object_id)
            .await
            .map(|metadata| metadata.retention);

        assert_eq!(
            retention,
            Ok(Some(RetentionPolicy::new(RetentionMode::Compliance, 30)))
        );
    }

    #[tokio::test]
    async fn delete_removes_unretained_object() {
        let store = MemoryBlobStore::new();
        let object_id = object_id("segments/a");

        let put = store
            .put(
                &object_id,
                Bytes::from_static(b"body"),
                PutOptions::default(),
            )
            .await;
        assert!(put.is_ok());

        let delete = store.delete(&object_id).await;
        let head = store.head(&object_id).await;

        assert!(delete.is_ok());
        assert!(matches!(head, Err(StorageError::NotFound(_))));
    }

    #[tokio::test]
    async fn counting_store_tracks_backend_pressure() {
        let store = CountingBlobStore::new(MemoryBlobStore::new());
        let object_id = object_id("segments/a");

        let put = store
            .put(
                &object_id,
                Bytes::from_static(b"hello world"),
                PutOptions::default(),
            )
            .await;
        let head = store.head(&object_id).await;
        let get = store
            .get_range(&object_id, ByteRange::Slice { offset: 6, len: 5 })
            .await;
        let list = store.list_prefix("segments/").await;

        assert!(put.is_ok());
        assert!(head.is_ok());
        assert_eq!(get, Ok(Bytes::from_static(b"world")));
        assert!(list.is_ok());

        let counts = store
            .operation_counts()
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(counts.put, 1);
        assert_eq!(counts.head, 1);
        assert_eq!(counts.get, 1);
        assert_eq!(counts.list, 1);
        assert_eq!(counts.bytes_uploaded_attempted, 11);
        assert_eq!(counts.bytes_written, 11);
        assert_eq!(counts.bytes_read, 5);
    }

    #[tokio::test]
    async fn counting_store_tracks_every_multipart_attempt_and_committed_bytes() {
        let store = CountingBlobStore::new(MemoryBlobStore::new());
        let object_id = object_id("segments/multipart");
        let mut upload = store
            .create_multipart_upload(&object_id, PutOptions::default())
            .await
            .unwrap_or_else(|error| panic!("create multipart upload: {error}"));

        upload
            .put_part(0, Bytes::from_static(b"hello "))
            .await
            .unwrap_or_else(|error| panic!("put first part: {error}"));
        upload
            .put_part(1, Bytes::from_static(b"world"))
            .await
            .unwrap_or_else(|error| panic!("put second part: {error}"));
        let metadata = upload
            .complete()
            .await
            .unwrap_or_else(|error| panic!("complete multipart upload: {error}"));

        let counts = store
            .operation_counts()
            .unwrap_or_else(|error| panic!("read operation counts: {error}"));
        assert_eq!(metadata.content_len, 11);
        assert_eq!(counts.put, 0);
        assert_eq!(counts.multipart_create, 1);
        assert_eq!(counts.multipart_upload_part, 2);
        assert_eq!(counts.multipart_complete, 1);
        assert_eq!(counts.multipart_abort, 0);
        assert_eq!(counts.multipart_put, 1);
        assert_eq!(counts.bytes_uploaded_attempted, 11);
        assert_eq!(counts.bytes_written, 11);
    }

    #[tokio::test]
    async fn counting_store_keeps_failed_upload_attempts_without_committing_bytes() {
        let store = CountingBlobStore::new(MemoryBlobStore::new());
        let object_id = object_id("segments/failed-multipart");
        let mut upload = store
            .create_multipart_upload(&object_id, PutOptions::default())
            .await
            .unwrap_or_else(|error| panic!("create multipart upload: {error}"));
        upload
            .put_part(0, Bytes::from_static(b"first"))
            .await
            .unwrap_or_else(|error| panic!("put first part: {error}"));
        let duplicate = upload.put_part(0, Bytes::from_static(b"retry")).await;
        assert!(duplicate.is_err());
        upload
            .abort()
            .await
            .unwrap_or_else(|error| panic!("abort multipart upload: {error}"));

        let counts = store
            .operation_counts()
            .unwrap_or_else(|error| panic!("read operation counts: {error}"));
        assert_eq!(counts.multipart_create, 1);
        assert_eq!(counts.multipart_upload_part, 2);
        assert_eq!(counts.multipart_complete, 0);
        assert_eq!(counts.multipart_abort, 1);
        assert_eq!(counts.multipart_put, 0);
        assert_eq!(counts.bytes_uploaded_attempted, 10);
        assert_eq!(counts.bytes_written, 0);
    }

    #[tokio::test]
    async fn streamed_version_read_is_bounded_and_counted_as_consumed() {
        let inner = MemoryBlobStore::new();
        let store = CountingBlobStore::new(inner);
        let object_id = object_id("segments/streamed");
        let first = store
            .put(
                &object_id,
                Bytes::from(vec![1_u8; super::read::BLOB_READ_CHUNK_BYTES + 1]),
                PutOptions::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        store
            .put(
                &object_id,
                Bytes::from_static(b"newer"),
                PutOptions::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        store
            .reset_operation_counts()
            .unwrap_or_else(|error| panic!("{error}"));

        let mut read = store
            .open_range_at(&object_id, first.version_id.as_ref(), ByteRange::Full)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            read.exact_len(),
            (super::read::BLOB_READ_CHUNK_BYTES + 1) as u64
        );
        let first_chunk = read
            .next_chunk()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .expect("first chunk");
        assert_eq!(first_chunk.len(), super::read::BLOB_READ_CHUNK_BYTES);
        assert_eq!(store.operation_counts().map(|counts| counts.get), Ok(1));
        assert_eq!(
            store.operation_counts().map(|counts| counts.bytes_read),
            Ok(super::read::BLOB_READ_CHUNK_BYTES as u64)
        );

        let final_chunk = read
            .next_chunk()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .expect("final chunk");
        assert_eq!(final_chunk, Bytes::from_static(&[1]));
        assert_eq!(read.next_chunk().await, Ok(None));
        assert_eq!(
            store.operation_counts().map(|counts| counts.bytes_read),
            Ok((super::read::BLOB_READ_CHUNK_BYTES + 1) as u64)
        );
    }
}
