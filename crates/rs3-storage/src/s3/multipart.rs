//! Client multipart sessions share initiation, completion and abort with the
//! internal sequential assembler. Only part transport and selection differ.

use super::{CompletedPart, S3MultipartUpload, SdkByteStream};
use crate::multipart::{PartBody, invalid_multipart, validate_selection};
use crate::{
    BlobMetadata, BlobMultipartPart, BlobMultipartSession, BlobMultipartUpload, BlobRead, Result,
    StorageError,
};
use async_trait::async_trait;
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

pub(super) struct S3MultipartSession {
    pub(super) inner: S3MultipartUpload,
    pub(super) scope: Arc<()>,
}

#[async_trait]
impl BlobMultipartSession for S3MultipartSession {
    async fn upload_part(
        &self,
        index: usize,
        read: Box<dyn BlobRead>,
    ) -> Result<BlobMultipartPart> {
        let len = read.exact_len();
        let verified_eof = Arc::new(AtomicBool::new(false));
        let body = if len == 0 {
            let mut checked = PartBody::new(index, read)?;
            if checked.next_chunk().await?.is_some() {
                return Err(invalid_multipart());
            }
            verified_eof.store(true, Ordering::Release);
            SdkByteStream::from(Bytes::new())
        } else {
            SdkByteStream::from_body_1_x(S3PartBody::new(index, read, Arc::clone(&verified_eof))?)
        };
        let part_number = i32::try_from(index + 1).map_err(|_| invalid_multipart())?;
        let output = self
            .inner
            .client
            .upload_part()
            .bucket(self.inner.store.config.bucket.as_str())
            .key(self.inner.key.as_str())
            .upload_id(self.inner.upload_id.as_str())
            .part_number(part_number)
            .content_length(i64::try_from(len).map_err(|_| invalid_multipart())?)
            .body(body)
            .send()
            .await
            .map_err(|_| StorageError::Provider("failed to upload multipart part".to_owned()))?;
        if !verified_eof.load(Ordering::Acquire) {
            return Err(invalid_multipart());
        }
        let etag = output.e_tag().ok_or_else(invalid_multipart)?;
        BlobMultipartPart::new(Arc::clone(&self.scope), index, etag.to_owned(), len)
    }

    async fn complete(self: Box<Self>, parts: Vec<BlobMultipartPart>) -> Result<BlobMetadata> {
        let len = match validate_selection(&self.scope, &parts) {
            Ok(len) => len,
            Err(error) => {
                // Nothing was published. Preserve validation failure if abort fails.
                if Box::new(self.inner).abort().await.is_err() {
                    super::record_s3_multipart_abort_failure("validation_failed", "provider");
                }
                return Err(error);
            }
        };
        let mut inner = self.inner;
        inner.content_len = len;
        inner.parts = parts
            .into_iter()
            .map(|part| {
                Some(
                    CompletedPart::builder()
                        .part_number((part.index + 1) as i32)
                        .e_tag(part.etag)
                        .build(),
                )
            })
            .collect();
        Box::new(inner).complete().await
    }

    async fn abort(self: Box<Self>) -> Result<()> {
        Box::new(self.inner).abort().await
    }
}

type PartFuture = Pin<Box<dyn Future<Output = (PartBody, Result<Option<Bytes>>)> + Send>>;

struct PartStreamState {
    body: Option<PartBody>,
    future: Option<PartFuture>,
    remaining: u64,
    verified_eof: Arc<AtomicBool>,
}

// The SDK requires Sync even though HTTP polls a body exclusively. A mutex
// supplies that bound without holding a lock across async IO or adding a task.
struct S3PartBody(Mutex<PartStreamState>);

impl S3PartBody {
    fn new(index: usize, read: Box<dyn BlobRead>, verified_eof: Arc<AtomicBool>) -> Result<Self> {
        let remaining = read.exact_len();
        Ok(Self(Mutex::new(PartStreamState {
            body: Some(PartBody::new(index, read)?),
            future: None,
            remaining,
            verified_eof,
        })))
    }
}

impl Body for S3PartBody {
    type Data = Bytes;
    type Error = StorageError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>>>> {
        let Ok(mut state) = self.0.lock() else {
            return Poll::Ready(Some(Err(invalid_multipart())));
        };
        if state.future.is_none() {
            let Some(mut body) = state.body.take() else {
                return Poll::Ready(None);
            };
            state.future = Some(Box::pin(async move {
                let result = body.next_chunk().await;
                (body, result)
            }));
        }
        let Some(future) = state.future.as_mut() else {
            return Poll::Ready(Some(Err(invalid_multipart())));
        };
        match future.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready((body, result)) => {
                state.future = None;
                match result {
                    Ok(Some(bytes)) => {
                        state.remaining = state.remaining.saturating_sub(bytes.len() as u64);
                        if state.remaining == 0 {
                            state.verified_eof.store(true, Ordering::Release);
                        }
                        state.body = Some(body);
                        Poll::Ready(Some(Ok(Frame::data(bytes))))
                    }
                    Ok(None) => Poll::Ready(None),
                    Err(error) => Poll::Ready(Some(Err(error))),
                }
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self.0.lock() {
            Ok(state) => SizeHint::with_exact(state.remaining),
            Err(_) => SizeHint::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt as _;

    #[tokio::test]
    async fn sdk_body_emits_bounded_frames_and_signals_verified_eof() {
        let bytes = Bytes::from(vec![7; crate::MAX_BLOB_READ_CHUNK_BYTES + 3]);
        let done = Arc::new(AtomicBool::new(false));
        let mut body = S3PartBody::new(
            0,
            crate::read::bytes_blob_read(bytes.clone(), bytes.len() as u64),
            Arc::clone(&done),
        )
        .expect("body");
        assert_eq!(body.size_hint().exact(), Some(bytes.len() as u64));
        let first = body
            .frame()
            .await
            .expect("frame")
            .expect("valid")
            .into_data()
            .expect("data");
        assert_eq!(first.len(), crate::MAX_BLOB_READ_CHUNK_BYTES);
        assert!(!done.load(Ordering::Acquire));
        assert_eq!(body.size_hint().exact(), Some(3));
        let last = body
            .frame()
            .await
            .expect("last frame")
            .expect("valid")
            .into_data()
            .expect("data");
        assert_eq!(last.len(), 3);
        assert!(done.load(Ordering::Acquire));
        assert!(body.frame().await.is_none());
    }

    #[tokio::test]
    async fn sdk_body_rejects_wrong_length_without_signaling_verified_eof() {
        for declared in [2, 4] {
            let done = Arc::new(AtomicBool::new(false));
            let mut body = S3PartBody::new(
                0,
                crate::read::bytes_blob_read(Bytes::from_static(b"abc"), declared),
                Arc::clone(&done),
            )
            .expect("body");
            let mut released = 0;
            while let Ok(frame) = body.frame().await.expect("error before EOF") {
                released += frame.into_data().expect("data").len();
            }
            assert!(released < declared as usize);
            assert!(!done.load(Ordering::Acquire));
        }
    }
}
