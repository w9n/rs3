//! Provider-neutral object-store abstractions.

use async_trait::async_trait;
use bytes::Bytes;
use rs3_types::{BackendObjectId, RetentionMode, RetentionPolicy};
use std::collections::BTreeMap;
#[cfg(test)]
use std::sync::RwLockReadGuard;
use std::sync::{Arc, RwLock, RwLockWriteGuard};
use thiserror::Error;

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
    pub version_id: Option<String>,
    /// Provider retention policy for this object version, when known.
    pub retention: Option<RetentionPolicy>,
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
    /// Optional content type.
    pub content_type: Option<String>,
    /// Reject the write if an object already exists at this logical identifier.
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
}

/// Convenient result alias for storage operations.
pub type Result<T> = std::result::Result<T, StorageError>;

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

    /// Reads an object or byte range.
    ///
    /// Efficient range reads are required for Kopia-compatible restores because
    /// Kopia may fetch sections of data pack blobs instead of whole packs.
    async fn get_range(&self, object_id: &BackendObjectId, range: ByteRange) -> Result<Bytes>;

    /// Reads object metadata without fetching the body.
    async fn head(&self, object_id: &BackendObjectId) -> Result<BlobMetadata>;

    /// Lists object metadata under an opaque prefix.
    ///
    /// The result must include objects written through the same gateway before
    /// the call starts. This is stronger than many backend object stores but is
    /// required by Kopia's blob-storage contract.
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<BlobMetadata>>;

    /// Deletes an object or writes a provider-specific delete marker.
    async fn delete(&self, object_id: &BackendObjectId) -> Result<()>;

    /// Extends retention for an existing object version.
    async fn extend_retention(
        &self,
        object_id: &BackendObjectId,
        policy: RetentionPolicy,
    ) -> Result<()>;

    /// Flushes implementation-local caches before process shutdown or handoff.
    async fn flush_caches(&self) -> Result<()>;
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

#[derive(Clone, Debug, Default)]
struct MemoryOperationCounts {
    put: u64,
    get: u64,
    head: u64,
    list: u64,
    delete: u64,
    extend_retention: u64,
    flush: u64,
}

#[derive(Debug, Default)]
struct MemoryState {
    objects: BTreeMap<BackendObjectId, MemoryObject>,
    next_modified_at_ms: i64,
    next_version: u64,
    counts: MemoryOperationCounts,
}

impl MemoryBlobStore {
    /// Creates an empty in-memory blob store.
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(MemoryState::default())),
        }
    }

    #[cfg(test)]
    fn read_state(&self) -> Result<RwLockReadGuard<'_, MemoryState>> {
        self.state
            .read()
            .map_err(|_| StorageError::Provider("memory blob store lock poisoned".to_owned()))
    }

    fn write_state(&self) -> Result<RwLockWriteGuard<'_, MemoryState>> {
        self.state
            .write()
            .map_err(|_| StorageError::Provider("memory blob store lock poisoned".to_owned()))
    }
}

impl Default for MemoryBlobStore {
    fn default() -> Self {
        Self::new()
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
        let mut state = self.write_state()?;
        state.counts.put = state.counts.put.saturating_add(1);

        if options.do_not_recreate && state.objects.contains_key(object_id) {
            return Err(StorageError::AlreadyExists(object_id.clone()));
        }

        state.next_modified_at_ms = state.next_modified_at_ms.saturating_add(1);
        state.next_version = state.next_version.saturating_add(1);

        let metadata = BlobMetadata {
            object_id: object_id.clone(),
            content_len: u64::try_from(body.len()).map_err(|_| {
                StorageError::Provider("object length does not fit in u64".to_owned())
            })?,
            modified_at_ms: Some(state.next_modified_at_ms),
            etag: Some(format!("mem-{}-{}", state.next_version, body.len())),
            version_id: Some(format!("mem-v{}", state.next_version)),
            retention: options.retention,
        };

        state.objects.insert(
            object_id.clone(),
            MemoryObject {
                body,
                metadata: metadata.clone(),
            },
        );

        Ok(metadata)
    }

    async fn get_range(&self, object_id: &BackendObjectId, range: ByteRange) -> Result<Bytes> {
        let mut state = self.write_state()?;
        state.counts.get = state.counts.get.saturating_add(1);

        let object = state
            .objects
            .get(object_id)
            .ok_or_else(|| StorageError::NotFound(object_id.clone()))?;

        read_range(&object.body, range)
    }

    async fn head(&self, object_id: &BackendObjectId) -> Result<BlobMetadata> {
        let mut state = self.write_state()?;
        state.counts.head = state.counts.head.saturating_add(1);

        state
            .objects
            .get(object_id)
            .map(|object| object.metadata.clone())
            .ok_or_else(|| StorageError::NotFound(object_id.clone()))
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<BlobMetadata>> {
        let mut state = self.write_state()?;
        state.counts.list = state.counts.list.saturating_add(1);

        Ok(state
            .objects
            .iter()
            .filter(|(object_id, _)| object_id.as_str().starts_with(prefix))
            .map(|(_, object)| object.metadata.clone())
            .collect())
    }

    async fn delete(&self, object_id: &BackendObjectId) -> Result<()> {
        let mut state = self.write_state()?;
        state.counts.delete = state.counts.delete.saturating_add(1);

        let object = state
            .objects
            .get(object_id)
            .ok_or_else(|| StorageError::NotFound(object_id.clone()))?;

        if retention_blocks_delete(object.metadata.retention.as_ref()) {
            return Err(StorageError::RetentionBlocked);
        }

        state.objects.remove(object_id);
        Ok(())
    }

    async fn extend_retention(
        &self,
        object_id: &BackendObjectId,
        policy: RetentionPolicy,
    ) -> Result<()> {
        let mut state = self.write_state()?;
        state.counts.extend_retention = state.counts.extend_retention.saturating_add(1);

        let object = state
            .objects
            .get_mut(object_id)
            .ok_or_else(|| StorageError::NotFound(object_id.clone()))?;

        object.metadata.retention =
            Some(merge_retention(object.metadata.retention.as_ref(), policy));

        Ok(())
    }

    async fn flush_caches(&self) -> Result<()> {
        let mut state = self.write_state()?;
        state.counts.flush = state.counts.flush.saturating_add(1);
        Ok(())
    }
}

fn read_range(body: &Bytes, range: ByteRange) -> Result<Bytes> {
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
    match policy {
        Some(policy) => policy.mode != RetentionMode::None && policy.retain_days > 0,
        None => false,
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

#[cfg(test)]
mod tests {
    use super::{
        BlobStore, ByteRange, MemoryBlobStore, PutOptions, StorageError, read_range,
        retention_blocks_delete,
    };
    use bytes::Bytes;
    use rs3_types::{BackendObjectId, RetentionMode, RetentionPolicy};

    fn object_id(value: &str) -> BackendObjectId {
        match BackendObjectId::new(value) {
            Ok(object_id) => object_id,
            Err(error) => panic!("{error}"),
        }
    }

    fn counts(store: &MemoryBlobStore) -> super::MemoryOperationCounts {
        match store.read_state() {
            Ok(state) => state.counts.clone(),
            Err(error) => panic!("{error}"),
        }
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
}
