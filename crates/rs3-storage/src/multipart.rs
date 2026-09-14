//! Streaming, replaceable multipart parts for client-driven uploads.

use crate::{BlobMetadata, BlobRead, Result, StorageError};
use async_trait::async_trait;
use bytes::Bytes;
use std::sync::Arc;

/// Maximum provider part count. Public S3 numbers are one greater than indices.
pub const MULTIPART_MAX_PARTS: usize = 10_000;
/// Maximum ciphertext bytes in one provider part.
pub const MULTIPART_MAX_PART_BYTES: u64 = 5 * 1024 * 1024 * 1024;
/// Minimum ciphertext bytes in every selected part except the last.
pub const MULTIPART_MIN_PART_BYTES: u64 = 5 * 1024 * 1024;

/// Provider acceptance of one exact part attempt, scoped to its upload session.
///
/// This is process-local upload state, not a durable publication receipt or a
/// client ETag. Repository publication must independently verify stored bytes.
#[derive(Clone)]
pub struct BlobMultipartPart {
    pub(crate) scope: Arc<()>,
    pub(crate) index: usize,
    pub(crate) etag: String,
    pub(crate) content_len: u64,
}

impl std::fmt::Debug for BlobMultipartPart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlobMultipartPart")
            .field("index", &self.index)
            .field("content_len", &self.content_len)
            .finish_non_exhaustive()
    }
}

impl BlobMultipartPart {
    /// Zero-based provider part index.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Accepted ciphertext length, before assembly.
    pub fn content_len(&self) -> u64 {
        self.content_len
    }

    pub(crate) fn new(
        scope: Arc<()>,
        index: usize,
        etag: String,
        content_len: u64,
    ) -> Result<Self> {
        validate_part(index, content_len)?;
        if etag.is_empty() || etag.len() > 1024 {
            return Err(invalid_multipart());
        }
        Ok(Self {
            scope,
            index,
            etag,
            content_len,
        })
    }
}

/// One provider upload with parallel, replaceable parts and explicit completion.
///
/// Upload callers must serialize attempts at the same index and freeze new
/// attempts before completing or aborting. Distinct indices may stream in
/// parallel. Cancellation can leave provider parts for explicit abort/cleanup.
/// Consuming the session requires exclusive ownership after all part calls end.
#[async_trait]
pub trait BlobMultipartSession: Send + Sync {
    /// Replaces a zero-based part with bounded ciphertext and returns its token.
    /// Bodies must report their exact length and reach exact EOF.
    async fn upload_part(&self, index: usize, body: Box<dyn BlobRead>)
    -> Result<BlobMultipartPart>;

    /// Assembles exactly this nonempty, strictly increasing selection.
    /// Stale or foreign part tokens fail. Failure consumes the session; callers
    /// must not infer absence of a completed object from an ambiguous error.
    async fn complete(self: Box<Self>, parts: Vec<BlobMultipartPart>) -> Result<BlobMetadata>;

    /// Releases incomplete provider state after in-flight part calls stop.
    async fn abort(self: Box<Self>) -> Result<()>;
}

pub(crate) fn invalid_multipart() -> StorageError {
    StorageError::Provider("invalid multipart part or selection".to_owned())
}

pub(crate) fn validate_part(index: usize, content_len: u64) -> Result<()> {
    if index >= MULTIPART_MAX_PARTS || content_len > MULTIPART_MAX_PART_BYTES {
        return Err(invalid_multipart());
    }
    Ok(())
}

pub(crate) fn validate_selection(scope: &Arc<()>, parts: &[BlobMultipartPart]) -> Result<u64> {
    if parts.is_empty() || parts.len() > MULTIPART_MAX_PARTS {
        return Err(invalid_multipart());
    }
    let mut previous = None;
    let mut total = 0_u64;
    for (position, part) in parts.iter().enumerate() {
        validate_part(part.index, part.content_len)?;
        if !Arc::ptr_eq(scope, &part.scope)
            || previous.is_some_and(|index| index >= part.index)
            || (position + 1 < parts.len() && part.content_len < MULTIPART_MIN_PART_BYTES)
        {
            return Err(invalid_multipart());
        }
        previous = Some(part.index);
        total = total
            .checked_add(part.content_len)
            .ok_or_else(invalid_multipart)?;
    }
    Ok(total)
}

/// Checks the producer before forwarding bytes, including EOF before the final
/// chunk. An HTTP client may stop polling after its declared Content-Length.
pub(crate) struct PartBody {
    read: Box<dyn BlobRead>,
    remaining: u64,
    terminal: bool,
}

impl PartBody {
    pub(crate) fn new(index: usize, read: Box<dyn BlobRead>) -> Result<Self> {
        validate_part(index, read.exact_len())?;
        Ok(Self {
            remaining: read.exact_len(),
            read,
            terminal: false,
        })
    }

    pub(crate) async fn next_chunk(&mut self) -> Result<Option<Bytes>> {
        if self.terminal {
            return Ok(None);
        }
        // Any error poisons this body; it must never resume after failed EOF.
        self.terminal = true;
        let Some(chunk) = self.read.next_chunk().await? else {
            return if self.remaining == 0 {
                Ok(None)
            } else {
                Err(invalid_multipart())
            };
        };
        if chunk.is_empty() || chunk.len() > crate::MAX_BLOB_READ_CHUNK_BYTES {
            return Err(invalid_multipart());
        }
        let len = u64::try_from(chunk.len()).map_err(|_| invalid_multipart())?;
        self.remaining = self
            .remaining
            .checked_sub(len)
            .ok_or_else(invalid_multipart)?;
        if self.remaining == 0 {
            if self.read.next_chunk().await?.is_some() {
                return Err(invalid_multipart());
            }
        } else {
            self.terminal = false;
        }
        Ok(Some(chunk))
    }
}

pub(crate) struct MemoryMultipartSession {
    pub(crate) store: crate::MemoryBlobStore,
    pub(crate) object_id: rs3_types::BackendObjectId,
    pub(crate) options: crate::PutOptions,
    pub(crate) scope: Arc<()>,
    pub(crate) state: std::sync::Mutex<MemoryParts>,
}

#[derive(Default)]
pub(crate) struct MemoryParts {
    revision: u64,
    parts: std::collections::BTreeMap<usize, (BlobMultipartPart, Bytes)>,
}

#[async_trait]
impl BlobMultipartSession for MemoryMultipartSession {
    async fn upload_part(
        &self,
        index: usize,
        read: Box<dyn BlobRead>,
    ) -> Result<BlobMultipartPart> {
        let content_len = read.exact_len();
        let mut body = PartBody::new(index, read)?;
        // This development provider stores ciphertext in memory by definition.
        // Do not allocate the untrusted declared length before reading it.
        let mut bytes = bytes::BytesMut::new();
        while let Some(chunk) = body.next_chunk().await? {
            bytes.extend_from_slice(&chunk);
        }
        let mut state = self.state.lock().map_err(|_| invalid_multipart())?;
        state.revision = state
            .revision
            .checked_add(1)
            .ok_or_else(invalid_multipart)?;
        let part = BlobMultipartPart::new(
            Arc::clone(&self.scope),
            index,
            state.revision.to_string(),
            content_len,
        )?;
        state.parts.insert(index, (part.clone(), bytes.freeze()));
        Ok(part)
    }

    async fn complete(self: Box<Self>, parts: Vec<BlobMultipartPart>) -> Result<BlobMetadata> {
        use crate::BlobStore as _;
        validate_selection(&self.scope, &parts)?;
        let state = self.state.into_inner().map_err(|_| invalid_multipart())?;
        // Validate every token before constructing any assembled object.
        for part in &parts {
            let (accepted, _) = state.parts.get(&part.index).ok_or_else(invalid_multipart)?;
            if accepted.etag != part.etag || accepted.content_len != part.content_len {
                return Err(invalid_multipart());
            }
        }
        let mut bytes = bytes::BytesMut::new();
        for part in parts {
            let (_, body) = state.parts.get(&part.index).ok_or_else(invalid_multipart)?;
            bytes.extend_from_slice(body);
        }
        let metadata = self
            .store
            .put(&self.object_id, bytes.freeze(), self.options)
            .await?;
        let mut state = self.store.write_state()?;
        state.counts.multipart_put = state.counts.multipart_put.saturating_add(1);
        Ok(metadata)
    }

    async fn abort(self: Box<Self>) -> Result<()> {
        Ok(())
    }
}

pub(crate) struct CountingMultipartSession {
    pub(crate) inner: Box<dyn BlobMultipartSession>,
    pub(crate) counts: Arc<std::sync::RwLock<crate::BlobOperationCounts>>,
}

impl CountingMultipartSession {
    fn count(&self, change: impl FnOnce(&mut crate::BlobOperationCounts)) -> Result<()> {
        let mut counts = self.counts.write().map_err(|_| invalid_multipart())?;
        change(&mut counts);
        Ok(())
    }
}

#[async_trait]
impl BlobMultipartSession for CountingMultipartSession {
    async fn upload_part(
        &self,
        index: usize,
        body: Box<dyn BlobRead>,
    ) -> Result<BlobMultipartPart> {
        self.count(|counts| {
            counts.multipart_upload_part = counts.multipart_upload_part.saturating_add(1);
            counts.bytes_uploaded_attempted = counts
                .bytes_uploaded_attempted
                .saturating_add(body.exact_len());
        })?;
        self.inner.upload_part(index, body).await
    }

    async fn complete(self: Box<Self>, parts: Vec<BlobMultipartPart>) -> Result<BlobMetadata> {
        self.count(|counts| {
            counts.multipart_complete = counts.multipart_complete.saturating_add(1)
        })?;
        let metadata = self.inner.complete(parts).await?;
        let mut counts = self.counts.write().map_err(|_| invalid_multipart())?;
        counts.multipart_put = counts.multipart_put.saturating_add(1);
        counts.bytes_written = counts.bytes_written.saturating_add(metadata.content_len);
        Ok(metadata)
    }

    async fn abort(self: Box<Self>) -> Result<()> {
        self.count(|counts| counts.multipart_abort = counts.multipart_abort.saturating_add(1))?;
        self.inner.abort().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlobStore, ByteRange, MemoryBlobStore, PutOptions};
    use rs3_types::BackendObjectId;

    fn read(bytes: Bytes) -> Box<dyn BlobRead> {
        crate::read::bytes_blob_read(bytes.clone(), bytes.len() as u64)
    }

    struct ConcurrentRead {
        inner: Box<dyn BlobRead>,
        barrier: Option<Arc<tokio::sync::Barrier>>,
    }

    #[async_trait]
    impl BlobRead for ConcurrentRead {
        fn exact_len(&self) -> u64 {
            self.inner.exact_len()
        }
        async fn next_chunk(&mut self) -> Result<Option<Bytes>> {
            if let Some(barrier) = self.barrier.take() {
                barrier.wait().await;
            }
            self.inner.next_chunk().await
        }
    }

    #[tokio::test]
    async fn replacement_and_noncontiguous_selection_publish_only_selected_bytes() {
        let store = MemoryBlobStore::new();
        let key = BackendObjectId::new("objects/v03/test").expect("key");
        let session = store
            .create_multipart_session(&key, PutOptions::default())
            .await
            .expect("start");
        let first = Bytes::from(vec![1; MULTIPART_MIN_PART_BYTES as usize]);
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let concurrent = |bytes| {
            Box::new(ConcurrentRead {
                inner: read(bytes),
                barrier: Some(Arc::clone(&barrier)),
            }) as Box<dyn BlobRead>
        };
        let (first, last) = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            tokio::join!(
                session.upload_part(2, concurrent(first)),
                session.upload_part(8, concurrent(Bytes::from_static(b"old")))
            )
        })
        .await
        .expect("independent parts must reach the barrier together");
        let first = first.expect("parallel first");
        last.expect("parallel last");
        session
            .upload_part(5, read(Bytes::from_static(b"omitted")))
            .await
            .expect("unused part");
        let last = session
            .upload_part(8, read(Bytes::from_static(b"new")))
            .await
            .expect("replace");
        assert!(store.head(&key).await.is_err());
        let metadata = session
            .complete(vec![first, last])
            .await
            .expect("complete selected");
        assert_eq!(metadata.content_len, MULTIPART_MIN_PART_BYTES + 3);
        assert_eq!(
            store
                .get_range(
                    &key,
                    ByteRange::Slice {
                        offset: MULTIPART_MIN_PART_BYTES,
                        len: 3
                    }
                )
                .await
                .expect("tail"),
            "new"
        );
    }

    #[tokio::test]
    async fn stale_foreign_and_invalid_selections_never_create_an_object() {
        for case in 0..6 {
            let store = MemoryBlobStore::new();
            let key = BackendObjectId::new("objects/v03/test").expect("key");
            let session = store
                .create_multipart_session(&key, PutOptions::default())
                .await
                .expect("start");
            let first = session
                .upload_part(1, read(Bytes::from_static(b"old")))
                .await
                .expect("first");
            let second = session
                .upload_part(2, read(Bytes::from_static(b"end")))
                .await
                .expect("second");
            let selected = match case {
                0 => vec![],
                1 => vec![second, first],
                2 => vec![first.clone(), first],
                3 => vec![first, second], // Nonfinal part below provider minimum.
                4 => {
                    session
                        .upload_part(1, read(Bytes::from_static(b"new")))
                        .await
                        .expect("replace");
                    vec![first]
                }
                _ => {
                    let foreign = store
                        .create_multipart_session(&key, PutOptions::default())
                        .await
                        .expect("other session");
                    let part = foreign
                        .upload_part(1, read(Bytes::from_static(b"old")))
                        .await
                        .expect("foreign part");
                    foreign.abort().await.expect("abort");
                    vec![part]
                }
            };
            assert!(session.complete(selected).await.is_err(), "case {case}");
            assert!(store.head(&key).await.is_err(), "case {case}");
        }
    }

    struct ScriptedRead {
        len: u64,
        chunks: std::collections::VecDeque<Result<Option<Bytes>>>,
    }

    #[async_trait]
    impl BlobRead for ScriptedRead {
        fn exact_len(&self) -> u64 {
            self.len
        }
        async fn next_chunk(&mut self) -> Result<Option<Bytes>> {
            self.chunks.pop_front().unwrap_or(Ok(None))
        }
    }

    #[tokio::test]
    async fn streaming_body_rejects_truncation_overflow_and_trailing_data_before_final_chunk() {
        let scenarios = [
            (4, vec![Ok(Some(Bytes::from_static(b"abc"))), Ok(None)]),
            (2, vec![Ok(Some(Bytes::from_static(b"abc")))]),
            (
                3,
                vec![
                    Ok(Some(Bytes::from_static(b"abc"))),
                    Ok(Some(Bytes::from_static(b"x"))),
                ],
            ),
            (
                3,
                vec![
                    Ok(Some(Bytes::from_static(b"abc"))),
                    Err(invalid_multipart()),
                ],
            ),
            (1, vec![Ok(Some(Bytes::new()))]),
            (
                crate::MAX_BLOB_READ_CHUNK_BYTES as u64 + 1,
                vec![Ok(Some(Bytes::from(vec![
                    0;
                    crate::MAX_BLOB_READ_CHUNK_BYTES
                        + 1
                ])))],
            ),
        ];
        for (len, chunks) in scenarios {
            let mut body = PartBody::new(
                0,
                Box::new(ScriptedRead {
                    len,
                    chunks: chunks.into(),
                }),
            )
            .expect("declared bounds");
            let mut emitted = 0;
            loop {
                match body.next_chunk().await {
                    Ok(Some(bytes)) => emitted += bytes.len(),
                    Err(_) => break,
                    Ok(None) => panic!("invalid body was accepted"),
                }
            }
            assert!(
                emitted < len as usize,
                "never forward final bytes before EOF"
            );
            assert!(body.next_chunk().await.expect("terminal").is_none());
        }
        assert!(PartBody::new(10_000, read(Bytes::new())).is_err());
        assert!(
            PartBody::new(
                0,
                Box::new(ScriptedRead {
                    len: MULTIPART_MAX_PART_BYTES + 1,
                    chunks: Default::default()
                })
            )
            .is_err()
        );
    }
    #[tokio::test]
    async fn counters_include_replaced_and_aborted_attempts_but_only_selected_written_bytes() {
        let store = crate::CountingBlobStore::new(MemoryBlobStore::new());
        let key = BackendObjectId::new("objects/v03/test").expect("key");
        let session = store
            .create_multipart_session(&key, PutOptions::default())
            .await
            .expect("start");
        session
            .upload_part(3, read(Bytes::from_static(b"old")))
            .await
            .expect("part");
        let part = session
            .upload_part(3, read(Bytes::from_static(b"new")))
            .await
            .expect("replace");
        session.complete(vec![part]).await.expect("complete");
        store
            .create_multipart_session(&key, PutOptions::default())
            .await
            .expect("start abort")
            .abort()
            .await
            .expect("abort");
        let counts = store.operation_counts().expect("counts");
        assert_eq!(
            (
                counts.multipart_create,
                counts.multipart_upload_part,
                counts.multipart_complete,
                counts.multipart_abort
            ),
            (2, 2, 1, 1)
        );
        assert_eq!(
            (
                counts.multipart_put,
                counts.bytes_uploaded_attempted,
                counts.bytes_written
            ),
            (1, 6, 3)
        );
    }
}
