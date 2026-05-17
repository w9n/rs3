use bytes::Bytes;
use rs3_repository::v2::{V2AnchorState, V2CommitAnchor, V2Result};
use rs3_storage::{BlobMetadata, BlobMultipartUpload, BlobStore, ByteRange, PutOptions};
use std::sync::Arc;

pub(super) type RuntimeStore = DynBlobStore;
pub(super) type RuntimeV2Anchor = DynV2CommitAnchor;

#[derive(Clone)]
pub(super) struct DynBlobStore {
    inner: Arc<dyn BlobStore>,
}

impl DynBlobStore {
    pub(super) fn new(store: impl BlobStore + 'static) -> Self {
        Self {
            inner: Arc::new(store),
        }
    }
}

#[async_trait::async_trait]
impl BlobStore for DynBlobStore {
    async fn put(
        &self,
        object_id: &rs3_types::BackendObjectId,
        body: Bytes,
        options: PutOptions,
    ) -> rs3_storage::Result<BlobMetadata> {
        self.inner.put(object_id, body, options).await
    }

    fn supports_multipart_upload(&self) -> bool {
        self.inner.supports_multipart_upload()
    }

    async fn create_multipart_upload(
        &self,
        object_id: &rs3_types::BackendObjectId,
        options: PutOptions,
    ) -> rs3_storage::Result<Box<dyn BlobMultipartUpload>> {
        self.inner.create_multipart_upload(object_id, options).await
    }

    async fn get_range(
        &self,
        object_id: &rs3_types::BackendObjectId,
        range: ByteRange,
    ) -> rs3_storage::Result<Bytes> {
        self.inner.get_range(object_id, range).await
    }

    async fn get_range_at(
        &self,
        object_id: &rs3_types::BackendObjectId,
        version_id: Option<&rs3_types::BackendVersionId>,
        range: ByteRange,
    ) -> rs3_storage::Result<Bytes> {
        self.inner.get_range_at(object_id, version_id, range).await
    }

    async fn head(
        &self,
        object_id: &rs3_types::BackendObjectId,
    ) -> rs3_storage::Result<BlobMetadata> {
        self.inner.head(object_id).await
    }

    async fn head_at(
        &self,
        object_id: &rs3_types::BackendObjectId,
        version_id: Option<&rs3_types::BackendVersionId>,
    ) -> rs3_storage::Result<BlobMetadata> {
        self.inner.head_at(object_id, version_id).await
    }

    async fn list_prefix(&self, prefix: &str) -> rs3_storage::Result<Vec<BlobMetadata>> {
        self.inner.list_prefix(prefix).await
    }

    async fn delete(&self, object_id: &rs3_types::BackendObjectId) -> rs3_storage::Result<()> {
        self.inner.delete(object_id).await
    }

    async fn extend_retention(
        &self,
        object_id: &rs3_types::BackendObjectId,
        policy: rs3_types::RetentionPolicy,
    ) -> rs3_storage::Result<()> {
        self.inner.extend_retention(object_id, policy).await
    }

    async fn extend_retention_at(
        &self,
        object_id: &rs3_types::BackendObjectId,
        version_id: Option<&rs3_types::BackendVersionId>,
        policy: rs3_types::RetentionPolicy,
    ) -> rs3_storage::Result<()> {
        self.inner
            .extend_retention_at(object_id, version_id, policy)
            .await
    }

    async fn set_legal_hold(
        &self,
        object_id: &rs3_types::BackendObjectId,
        status: rs3_types::LegalHoldStatus,
    ) -> rs3_storage::Result<()> {
        self.inner.set_legal_hold(object_id, status).await
    }

    async fn set_legal_hold_at(
        &self,
        object_id: &rs3_types::BackendObjectId,
        version_id: Option<&rs3_types::BackendVersionId>,
        status: rs3_types::LegalHoldStatus,
    ) -> rs3_storage::Result<()> {
        self.inner
            .set_legal_hold_at(object_id, version_id, status)
            .await
    }

    async fn flush_caches(&self) -> rs3_storage::Result<()> {
        self.inner.flush_caches().await
    }
}

#[derive(Clone)]
pub(super) struct DynV2CommitAnchor {
    inner: Arc<dyn V2CommitAnchor>,
}

impl DynV2CommitAnchor {
    pub(super) fn new(anchor: impl V2CommitAnchor + 'static) -> Self {
        Self {
            inner: Arc::new(anchor),
        }
    }
}

#[async_trait::async_trait]
impl V2CommitAnchor for DynV2CommitAnchor {
    async fn read_v2(&self) -> V2Result<Option<V2AnchorState>> {
        self.inner.read_v2().await
    }

    async fn compare_and_advance_v2(
        &self,
        expected: Option<&V2AnchorState>,
        next: V2AnchorState,
    ) -> V2Result<V2AnchorState> {
        self.inner.compare_and_advance_v2(expected, next).await
    }
}
