//! Bounded authenticated reads for streamed v2 payload carriers.

use super::{V2FormatError, v2_repository_error};
use crate::error::{RepositoryError, Result};
use crate::payload::{
    SegmentedPayloadLayout, open_segmented_payload_span, segmented_ciphertext_span,
};
use bytes::{Bytes, BytesMut};
use futures_util::{Stream, StreamExt, stream};
use rs3_crypto::KeyRing;
use rs3_crypto::Sha256Hasher;
use rs3_storage::{BlobRead, ByteRange};
use rs3_types::BackendObjectId;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

const TARGET_PLAINTEXT_CHUNK_BYTES: u64 = 1024 * 1024;
const AEAD_TAG_BYTES: u64 = 16;

/// Bounded client-visible body for one exact streamed payload carrier.
pub struct V2AuthenticatedReadBody {
    content_len: u64,
    working_set_bytes: u64,
    inner: Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>>,
}

impl V2AuthenticatedReadBody {
    /// Exact plaintext length emitted by this body.
    pub const fn content_len(&self) -> u64 {
        self.content_len
    }

    /// Conservative memory admission charge while this body is active.
    pub const fn working_set_bytes(&self) -> u64 {
        self.working_set_bytes
    }
}

impl Stream for V2AuthenticatedReadBody {
    type Item = Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

pub(super) async fn open_authenticated_payload_stream(
    reader: Box<dyn BlobRead>,
    keyring: Arc<KeyRing>,
    payload_id: BackendObjectId,
    expected_layout: SegmentedPayloadLayout,
    expected_section_digest: [u8; 32],
    expected_stored_len: u64,
) -> Result<V2AuthenticatedReadBody> {
    if reader.exact_len() != expected_stored_len || expected_layout.plaintext_len == 0 {
        return Err(invalid_payload(&payload_id));
    }

    if crate::payload::total_segmented_payload_len(&expected_layout)? != expected_stored_len {
        return Err(invalid_payload(&payload_id));
    }
    let cursor = BlobCursor::new(reader);
    let chunk_size = expected_layout.chunk_size;
    let segments_per_chunk = TARGET_PLAINTEXT_CHUNK_BYTES
        .checked_div(chunk_size)
        .unwrap_or(0)
        .max(1);
    let total_segments = expected_layout.segment_count();
    let grouped_plaintext_bytes = segments_per_chunk
        .checked_mul(chunk_size)
        .ok_or_else(|| invalid_payload(&payload_id))?;
    let grouped_ciphertext_bytes = grouped_plaintext_bytes
        .checked_add(
            segments_per_chunk
                .checked_mul(AEAD_TAG_BYTES)
                .ok_or_else(|| invalid_payload(&payload_id))?,
        )
        .ok_or_else(|| invalid_payload(&payload_id))?;
    let working_set_bytes = grouped_ciphertext_bytes
        .checked_add(grouped_plaintext_bytes)
        .and_then(|bytes| bytes.checked_add(TARGET_PLAINTEXT_CHUNK_BYTES))
        .and_then(|bytes| bytes.checked_add(expected_layout.retained_bytes()))
        .ok_or_else(|| invalid_payload(&payload_id))?;

    let digest = Sha256Hasher::new();
    let state = AuthenticatedReadState {
        cursor,
        keyring,
        payload_id,
        layout: expected_layout,
        expected_section_digest,
        digest,
        next_segment: 0,
        total_segments,
        segments_per_chunk: usize::try_from(segments_per_chunk)
            .map_err(|_| stream_storage_error())?,
    };
    let content_len = state.layout.plaintext_len;
    let inner = stream::try_unfold(state, |mut state| async move {
        if state.next_segment == state.total_segments {
            return Ok(None);
        }

        let end_segment = state
            .next_segment
            .saturating_add(state.segments_per_chunk)
            .min(state.total_segments);
        let offset = state.layout.plaintext_offset(state.next_segment)?;
        let end = state.layout.plaintext_offset(end_segment)?;
        let range = ByteRange::Slice {
            offset,
            len: end
                .checked_sub(offset)
                .ok_or_else(|| invalid_payload(&state.payload_id))?,
        };
        let span = segmented_ciphertext_span(&state.layout, range)?;
        let ciphertext = state.cursor.take_exact(span.len).await?;
        state.digest.update(&ciphertext);
        let plaintext = open_segmented_payload_span(
            &state.keyring,
            &state.payload_id,
            &state.layout,
            range,
            span,
            ciphertext,
        )?;
        state.next_segment = end_segment;

        if state.next_segment == state.total_segments {
            state.cursor.finish_exact().await?;
            let actual: [u8; 32] = state.digest.clone().finalize();
            if actual != state.expected_section_digest {
                return Err(invalid_payload(&state.payload_id));
            }
        }

        Ok(Some((plaintext, state)))
    });

    // Authenticate the first bounded group before returning a response body.
    // This catches a transplanted descriptor without relying on a public layout.
    let mut inner = Box::pin(inner);
    let first = inner.next().await.ok_or_else(stream_storage_error)??;
    Ok(V2AuthenticatedReadBody {
        content_len,
        working_set_bytes,
        inner: Box::pin(stream::once(async move { Ok(first) }).chain(inner)),
    })
}

struct AuthenticatedReadState {
    cursor: BlobCursor,
    keyring: Arc<KeyRing>,
    payload_id: BackendObjectId,
    layout: SegmentedPayloadLayout,
    expected_section_digest: [u8; 32],
    digest: Sha256Hasher,
    next_segment: usize,
    total_segments: usize,
    segments_per_chunk: usize,
}

struct BlobCursor {
    reader: Box<dyn BlobRead>,
    buffered: Bytes,
}

impl BlobCursor {
    fn new(reader: Box<dyn BlobRead>) -> Self {
        Self {
            reader,
            buffered: Bytes::new(),
        }
    }

    async fn take_exact(&mut self, len: u64) -> Result<Bytes> {
        let len = usize::try_from(len).map_err(|_| stream_storage_error())?;
        if len == 0 {
            return Ok(Bytes::new());
        }
        if self.buffered.len() >= len {
            return Ok(self.buffered.split_to(len));
        }

        let mut output = BytesMut::with_capacity(len);
        if !self.buffered.is_empty() {
            output.extend_from_slice(&std::mem::take(&mut self.buffered));
        }
        while output.len() < len {
            let mut chunk = self
                .reader
                .next_chunk()
                .await
                .map_err(|_| stream_storage_error())?
                .ok_or_else(stream_storage_error)?;
            let needed = len - output.len();
            if chunk.len() > needed {
                output.extend_from_slice(&chunk.split_to(needed));
                self.buffered = chunk;
            } else {
                output.extend_from_slice(&chunk);
            }
        }
        Ok(output.freeze())
    }

    async fn finish_exact(&mut self) -> Result<()> {
        if !self.buffered.is_empty() {
            return Err(stream_storage_error());
        }
        match self
            .reader
            .next_chunk()
            .await
            .map_err(|_| stream_storage_error())?
        {
            None => Ok(()),
            Some(_) => Err(stream_storage_error()),
        }
    }
}

fn invalid_payload(payload_id: &BackendObjectId) -> RepositoryError {
    RepositoryError::InvalidObjectFormat {
        object_id: payload_id.clone(),
    }
}

fn stream_storage_error() -> RepositoryError {
    v2_repository_error(V2FormatError::StorageOperationFailed)
}

#[cfg(test)]
mod tests {
    use super::open_authenticated_payload_stream;
    use crate::payload::seal_payload_object;
    use crate::test_support::{backend_object_id, signing_keyring};
    use async_trait::async_trait;
    use bytes::Bytes;
    use futures_util::StreamExt;
    use rs3_crypto::Sha256Hasher;
    use rs3_storage::BlobRead;
    use std::collections::VecDeque;
    use std::sync::Arc;

    struct ChunkedRead {
        exact_len: u64,
        chunks: VecDeque<Bytes>,
    }

    #[async_trait]
    impl BlobRead for ChunkedRead {
        fn exact_len(&self) -> u64 {
            self.exact_len
        }

        async fn next_chunk(&mut self) -> rs3_storage::Result<Option<Bytes>> {
            Ok(self.chunks.pop_front())
        }
    }

    fn chunked(body: &Bytes) -> Box<dyn BlobRead> {
        Box::new(ChunkedRead {
            exact_len: body.len() as u64,
            chunks: body
                .chunks(256 * 1024)
                .map(Bytes::copy_from_slice)
                .collect(),
        })
    }

    #[tokio::test]
    async fn aggregate_mismatch_withholds_the_final_plaintext_chunk() {
        let keyring = Arc::new(signing_keyring());
        let payload_id = backend_object_id("stream/final-digest");
        let plaintext = Bytes::from(vec![0x5a; 2 * 1024 * 1024 + 17]);
        let (sealed, layout) = seal_payload_object(
            &keyring,
            &payload_id,
            &plaintext,
            64 * 1024,
            b"fixture-context".to_vec(),
            [4; 32],
        )
        .expect("seal fixture");
        let mut wrong_digest: [u8; 32] = Sha256Hasher::digest(&sealed);
        wrong_digest[0] ^= 0x80;
        let mut body = open_authenticated_payload_stream(
            chunked(&sealed),
            keyring,
            payload_id,
            layout,
            wrong_digest,
            sealed.len() as u64,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        let mut emitted = Vec::new();
        let mut terminal_error = None;
        while let Some(chunk) = body.next().await {
            match chunk {
                Ok(chunk) => emitted.extend_from_slice(&chunk),
                Err(error) => {
                    terminal_error = Some(error);
                    break;
                }
            }
        }

        assert_eq!(emitted.len(), 2 * 1024 * 1024);
        assert_eq!(emitted, plaintext[..emitted.len()]);
        assert!(terminal_error.is_some());
    }

    #[tokio::test]
    async fn segment_tampering_never_emits_the_affected_plaintext_group() {
        let keyring = Arc::new(signing_keyring());
        let payload_id = backend_object_id("stream/segment-tamper");
        let plaintext = Bytes::from(vec![0x31; 2 * 1024 * 1024 + 17]);
        let (sealed, layout) = seal_payload_object(
            &keyring,
            &payload_id,
            &plaintext,
            64 * 1024,
            b"fixture-context".to_vec(),
            [4; 32],
        )
        .expect("seal fixture");
        let digest: [u8; 32] = Sha256Hasher::digest(&sealed);
        let mut corrupted = sealed.to_vec();
        let affected = 1024 * 1024 + 16 * 16 + 17;
        corrupted[affected] ^= 0x80;
        let corrupted = Bytes::from(corrupted);
        let mut body = open_authenticated_payload_stream(
            chunked(&corrupted),
            keyring,
            payload_id,
            layout,
            digest,
            corrupted.len() as u64,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        let first = body
            .next()
            .await
            .expect("first group")
            .unwrap_or_else(|error| panic!("{error}"));
        let second = body.next().await.expect("tampered group result");

        assert_eq!(first, plaintext.slice(..1024 * 1024));
        assert!(second.is_err());
    }

    #[tokio::test]
    async fn authenticated_layout_mismatch_fails_before_returning_plaintext() {
        let keyring = Arc::new(signing_keyring());
        let payload_id = backend_object_id("stream/layout-mismatch");
        let plaintext = Bytes::from_static(b"authenticated");
        let (sealed, mut layout) = seal_payload_object(
            &keyring,
            &payload_id,
            &plaintext,
            512,
            b"fixture-context".to_vec(),
            [4; 32],
        )
        .expect("seal fixture");
        let mut reference = layout.reference().clone();
        reference.carrier_id[0] ^= 0x80;
        layout =
            crate::payload::SegmentedPayloadLayout::new(reference, b"fixture-context".to_vec())
                .expect("layout");
        let digest: [u8; 32] = Sha256Hasher::digest(&sealed);

        let body = open_authenticated_payload_stream(
            chunked(&sealed),
            keyring,
            payload_id,
            layout,
            digest,
            sealed.len() as u64,
        )
        .await;

        assert!(body.is_err());
    }
}
