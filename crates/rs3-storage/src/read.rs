use crate::{Result, StorageError};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};

/// Maximum bytes emitted by one incremental blob-read chunk.
pub const MAX_BLOB_READ_CHUNK_BYTES: usize = 1024 * 1024;
pub(crate) const BLOB_READ_CHUNK_BYTES: usize = MAX_BLOB_READ_CHUNK_BYTES;

/// Incremental body returned by a blob-store read.
///
/// Implementations emit at most the exact number of bytes advertised by
/// [`Self::exact_len`]. Callers must continue through `Ok(None)` so truncated
/// and overlong provider responses are detected.
#[async_trait]
pub trait BlobRead: Send {
    /// Exact number of bytes expected from this read.
    fn exact_len(&self) -> u64;

    /// Returns the next bounded body chunk, or `None` after exact completion.
    async fn next_chunk(&mut self) -> Result<Option<Bytes>>;
}

/// Collects one incremental read without exceeding `max_bytes`.
///
/// The advertised exact length is checked before allocating. The reader is
/// still consumed through its terminal `None` so truncated and overlong
/// provider responses cannot be accepted as complete objects.
pub async fn collect_bounded_blob_read(
    mut read: Box<dyn BlobRead>,
    max_bytes: u64,
) -> Result<Bytes> {
    let exact_len = read.exact_len();
    if exact_len > max_bytes {
        return Err(StorageError::BoundedReadExceeded { max_bytes });
    }
    let capacity = usize::try_from(exact_len).map_err(|_| {
        StorageError::Provider("bounded object length exceeds platform capacity".to_owned())
    })?;
    let mut body = BytesMut::with_capacity(capacity);

    while let Some(chunk) = read.next_chunk().await? {
        let next_len = body
            .len()
            .checked_add(chunk.len())
            .ok_or(StorageError::BoundedReadExceeded { max_bytes })?;
        if u64::try_from(next_len).unwrap_or(u64::MAX) > max_bytes {
            return Err(StorageError::BoundedReadExceeded { max_bytes });
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body.freeze())
}

pub(crate) fn enforce_full_read_bound(
    read: Box<dyn BlobRead>,
    max_bytes: u64,
) -> Result<Box<dyn BlobRead>> {
    if read.exact_len() > max_bytes {
        return Err(StorageError::BoundedReadExceeded { max_bytes });
    }
    Ok(read)
}

#[async_trait]
pub(crate) trait BlobReadSource: Send {
    async fn next_source_chunk(&mut self) -> Result<Option<Bytes>>;
}

pub(crate) fn exact_blob_read<S>(source: S, exact_len: u64) -> Box<dyn BlobRead>
where
    S: BlobReadSource + 'static,
{
    Box::new(ExactBlobRead {
        source,
        exact_len,
        remaining: exact_len,
        pending: Bytes::new(),
        terminal: false,
    })
}

pub(crate) fn bytes_blob_read(body: Bytes, exact_len: u64) -> Box<dyn BlobRead> {
    exact_blob_read(BytesBlobReadSource { body }, exact_len)
}

struct ExactBlobRead<S> {
    source: S,
    exact_len: u64,
    remaining: u64,
    pending: Bytes,
    terminal: bool,
}

#[async_trait]
impl<S> BlobRead for ExactBlobRead<S>
where
    S: BlobReadSource,
{
    fn exact_len(&self) -> u64 {
        self.exact_len
    }

    async fn next_chunk(&mut self) -> Result<Option<Bytes>> {
        if self.terminal {
            return Ok(None);
        }

        let chunk = if self.pending.is_empty() {
            match self.source.next_source_chunk().await {
                Ok(Some(chunk)) if chunk.is_empty() => {
                    self.terminal = true;
                    return Err(invalid_stream_length(
                        "blob read returned an empty body chunk",
                    ));
                }
                Ok(Some(chunk)) => chunk,
                Ok(None) if self.remaining == 0 => {
                    self.terminal = true;
                    return Ok(None);
                }
                Ok(None) => {
                    self.terminal = true;
                    return Err(invalid_stream_length(
                        "blob read ended before its exact length",
                    ));
                }
                Err(error) => {
                    self.terminal = true;
                    return Err(error);
                }
            }
        } else {
            std::mem::take(&mut self.pending)
        };

        let chunk_len = match u64::try_from(chunk.len()) {
            Ok(chunk_len) => chunk_len,
            Err(_error) => {
                self.terminal = true;
                return Err(invalid_stream_length(
                    "blob read chunk length is out of range",
                ));
            }
        };
        if chunk_len > self.remaining {
            self.terminal = true;
            return Err(invalid_stream_length("blob read exceeded its exact length"));
        }
        let mut chunk = chunk;
        if chunk.len() > BLOB_READ_CHUNK_BYTES {
            self.pending = chunk.split_off(BLOB_READ_CHUNK_BYTES);
        }
        self.remaining -= chunk.len() as u64;
        Ok(Some(chunk))
    }
}

struct BytesBlobReadSource {
    body: Bytes,
}

#[async_trait]
impl BlobReadSource for BytesBlobReadSource {
    async fn next_source_chunk(&mut self) -> Result<Option<Bytes>> {
        if self.body.is_empty() {
            return Ok(None);
        }
        let len = self.body.len().min(BLOB_READ_CHUNK_BYTES);
        Ok(Some(self.body.split_to(len)))
    }
}

fn invalid_stream_length(reason: &'static str) -> StorageError {
    StorageError::Provider(reason.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{BlobReadSource, bytes_blob_read, collect_bounded_blob_read, exact_blob_read};
    use crate::{Result, StorageError};
    use async_trait::async_trait;
    use bytes::Bytes;
    use std::collections::VecDeque;

    struct ScriptedSource {
        chunks: VecDeque<Result<Option<Bytes>>>,
    }

    #[async_trait]
    impl BlobReadSource for ScriptedSource {
        async fn next_source_chunk(&mut self) -> Result<Option<Bytes>> {
            self.chunks.pop_front().unwrap_or(Ok(None))
        }
    }

    fn scripted(
        chunks: impl IntoIterator<Item = Result<Option<Bytes>>>,
        len: u64,
    ) -> Box<dyn super::BlobRead> {
        exact_blob_read(
            ScriptedSource {
                chunks: chunks.into_iter().collect(),
            },
            len,
        )
    }

    #[tokio::test]
    async fn exact_reader_requires_complete_eof() {
        let mut read = scripted(
            [
                Ok(Some(Bytes::from_static(b"ab"))),
                Ok(Some(Bytes::from_static(b"cd"))),
                Ok(None),
            ],
            4,
        );

        assert_eq!(read.exact_len(), 4);
        assert_eq!(read.next_chunk().await, Ok(Some(Bytes::from_static(b"ab"))));
        assert_eq!(read.next_chunk().await, Ok(Some(Bytes::from_static(b"cd"))));
        assert_eq!(read.next_chunk().await, Ok(None));
        assert_eq!(read.next_chunk().await, Ok(None));
    }

    #[tokio::test]
    async fn exact_reader_rejects_truncation_and_becomes_terminal() {
        let mut read = scripted([Ok(Some(Bytes::from_static(b"ab"))), Ok(None)], 3);

        assert_eq!(read.next_chunk().await, Ok(Some(Bytes::from_static(b"ab"))));
        assert!(matches!(
            read.next_chunk().await,
            Err(StorageError::Provider(message)) if message.contains("before its exact length")
        ));
        assert_eq!(read.next_chunk().await, Ok(None));
    }

    #[tokio::test]
    async fn exact_reader_never_emits_overlong_chunk() {
        let mut read = scripted([Ok(Some(Bytes::from_static(b"abcd")))], 3);

        assert!(matches!(
            read.next_chunk().await,
            Err(StorageError::Provider(message)) if message.contains("exceeded its exact length")
        ));
        assert_eq!(read.next_chunk().await, Ok(None));
    }

    #[tokio::test]
    async fn exact_reader_rejects_trailing_bytes_after_expected_body() {
        let mut read = scripted(
            [
                Ok(Some(Bytes::from_static(b"abc"))),
                Ok(Some(Bytes::from_static(b"d"))),
            ],
            3,
        );

        assert_eq!(
            read.next_chunk().await,
            Ok(Some(Bytes::from_static(b"abc")))
        );
        assert!(matches!(
            read.next_chunk().await,
            Err(StorageError::Provider(message)) if message.contains("exceeded its exact length")
        ));
    }

    #[tokio::test]
    async fn exact_reader_rejects_empty_nonterminal_chunks() {
        let mut read = scripted([Ok(Some(Bytes::new())), Ok(None)], 0);

        assert!(matches!(
            read.next_chunk().await,
            Err(StorageError::Provider(message)) if message.contains("empty body chunk")
        ));
    }

    #[tokio::test]
    async fn bytes_adapter_chunks_large_buffers_without_copying() {
        let body = Bytes::from(vec![7_u8; super::BLOB_READ_CHUNK_BYTES + 1]);
        let mut read = bytes_blob_read(body.clone(), body.len() as u64);

        let first = read
            .next_chunk()
            .await
            .expect("first read")
            .expect("first chunk");
        let second = read
            .next_chunk()
            .await
            .expect("second read")
            .expect("second chunk");
        assert_eq!(first.len(), super::BLOB_READ_CHUNK_BYTES);
        assert_eq!(second, Bytes::from_static(&[7]));
        assert_eq!(read.next_chunk().await, Ok(None));
    }

    #[tokio::test]
    async fn exact_reader_splits_oversized_provider_chunks() {
        let oversized = Bytes::from(vec![3_u8; super::MAX_BLOB_READ_CHUNK_BYTES + 17]);
        let mut read = scripted(
            [Ok(Some(oversized.clone())), Ok(None)],
            oversized.len() as u64,
        );

        let first = read
            .next_chunk()
            .await
            .expect("first read")
            .expect("first chunk");
        let second = read
            .next_chunk()
            .await
            .expect("second read")
            .expect("second chunk");

        assert_eq!(first.len(), super::MAX_BLOB_READ_CHUNK_BYTES);
        assert_eq!(second.len(), 17);
        assert_eq!(read.next_chunk().await, Ok(None));
    }

    #[tokio::test]
    async fn bounded_collector_rejects_advertised_length_before_reading() {
        let read = scripted([Ok(Some(Bytes::from_static(b"abcd"))), Ok(None)], 4);

        let result = collect_bounded_blob_read(read, 3).await;

        assert_eq!(
            result,
            Err(StorageError::BoundedReadExceeded { max_bytes: 3 })
        );
    }

    #[tokio::test]
    async fn bounded_collector_requires_verified_terminal_eof() {
        let read = scripted(
            [
                Ok(Some(Bytes::from_static(b"abc"))),
                Ok(Some(Bytes::from_static(b"d"))),
            ],
            3,
        );

        let result = collect_bounded_blob_read(read, 3).await;

        assert!(matches!(
            result,
            Err(StorageError::Provider(message)) if message.contains("exceeded its exact length")
        ));
    }
}
