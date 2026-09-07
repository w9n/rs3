//! One bounded plaintext-to-ciphertext producer, independent of publication.

use super::*;
use rs3_storage::Result as StorageResult;

pub(super) struct EncryptedPartBody {
    sealer: SegmentedPayloadSealer,
    keyring: Arc<KeyRing>,
    object_id: BackendObjectId,
    input: Box<dyn BlobRead>,
    remaining: u64,
    ciphertext_len: u64,
    pending: Bytes,
    segment: usize,
    digest: Sha256Hasher,
    result: Arc<Mutex<Option<[u8; 32]>>>,
    stall_timeout: Duration,
    terminal: bool,
}

fn invalid_body() -> StorageError {
    StorageError::Provider("invalid multipart plaintext body".to_owned())
}

impl EncryptedPartBody {
    pub(super) fn new(
        sealer: SegmentedPayloadSealer,
        keyring: Arc<KeyRing>,
        object_id: BackendObjectId,
        input: Box<dyn BlobRead>,
        ciphertext_len: u64,
        stall_timeout: Duration,
        result: Arc<Mutex<Option<[u8; 32]>>>,
    ) -> Self {
        Self {
            remaining: input.exact_len(),
            sealer,
            keyring,
            object_id,
            input,
            ciphertext_len,
            stall_timeout,
            result,
            pending: Bytes::new(),
            segment: 0,
            digest: Sha256Hasher::new(),
            terminal: false,
        }
    }

    async fn next_input(&mut self) -> StorageResult<Option<Bytes>> {
        tokio::time::timeout(self.stall_timeout, self.input.next_chunk())
            .await
            .map_err(|_| invalid_body())?
    }

    async fn require_eof(&mut self) -> StorageResult<()> {
        if !self.pending.is_empty() || self.next_input().await?.is_some() {
            return Err(invalid_body());
        }
        Ok(())
    }

    fn finish_digest(&self) -> StorageResult<()> {
        *self.result.lock().map_err(|_| invalid_body())? = Some(self.digest.clone().finalize());
        Ok(())
    }
}

#[async_trait]
impl BlobRead for EncryptedPartBody {
    fn exact_len(&self) -> u64 {
        self.ciphertext_len
    }

    async fn next_chunk(&mut self) -> StorageResult<Option<Bytes>> {
        if self.terminal {
            return Ok(None);
        }
        self.terminal = true;
        if self.remaining == 0 {
            self.require_eof().await?;
            self.finish_digest()?;
            return Ok(None);
        }
        let target = self.remaining.min(PART_SEGMENT_BYTES as u64) as usize;
        let mut plaintext = Vec::with_capacity(target);
        while plaintext.len() < target {
            if self.pending.is_empty() {
                self.pending = self.next_input().await?.ok_or_else(invalid_body)?;
                if self.pending.is_empty()
                    || self.pending.len() > rs3_storage::MAX_BLOB_READ_CHUNK_BYTES
                    || self.pending.len() as u64 > self.remaining
                {
                    return Err(invalid_body());
                }
            }
            let len = self.pending.len().min(target - plaintext.len());
            plaintext.extend_from_slice(&self.pending.split_to(len));
            self.remaining -= len as u64;
        }
        let is_final = self.remaining == 0;
        if is_final {
            self.require_eof().await?;
        }
        let bytes = self
            .sealer
            .seal_segment(
                &self.keyring,
                &self.object_id,
                self.segment,
                &plaintext,
                is_final,
            )
            .map_err(|_| invalid_body())?;
        self.digest.update(&bytes);
        self.segment = self.segment.checked_add(1).ok_or_else(invalid_body)?;
        if is_final {
            self.finish_digest()?;
        } else {
            self.terminal = false;
        }
        Ok(Some(bytes))
    }
}
