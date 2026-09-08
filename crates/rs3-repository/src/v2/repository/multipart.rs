//! Independently sealed client parts and verified detached completion.

mod body;
#[cfg(test)]
mod tests;

use super::*;
use crate::payload::SegmentedPayloadLayout;
use crate::{MultipartChecksumPolicy, UploadChecksum};
use rs3_index::{PayloadLayout, PayloadPart};
use rs3_storage::{BlobMultipartPart, BlobMultipartSession, BlobRead};
use rs3_types::{ChecksumType, ObjectChecksum};
use std::sync::Mutex;

const PART_SEGMENT_BYTES: usize = 64 * 1024;

/// One accepted client part attempt. Fields remain private so callers cannot
/// substitute provider tokens, layout context or expected ciphertext digests.
#[derive(Clone)]
pub struct V3UploadedPart {
    scope: Arc<()>,
    backend: BlobMultipartPart,
    part: PayloadPart,
    digest: [u8; 32],
    checksum: Option<ObjectChecksum>,
    md5: rs3_types::Md5Digest,
}

impl V3UploadedPart {
    /// Original one-based client part number.
    pub fn part_number(&self) -> u32 {
        self.part.part_number
    }
    /// Plaintext bytes accepted for this part.
    pub fn plaintext_len(&self) -> u64 {
        self.part.plaintext_len
    }
    /// Verified plaintext checksum, kept independent of the opaque part token.
    pub fn checksum(&self) -> Option<&ObjectChecksum> {
        self.checksum.as_ref()
    }
    pub(in crate::v2) fn selected_attempts_digest(parts: &[Self]) -> [u8; 32] {
        let mut digest = Sha256Hasher::new();
        digest.update(b"rs3:v3-multipart-selected-attempts:v1\0");
        digest.update((parts.len() as u64).to_be_bytes());
        for part in parts {
            digest.update(part.part.part_number.to_be_bytes());
            digest.update(part.part.attempt_id.as_bytes());
            digest.update(part.part.plaintext_len.to_be_bytes());
            digest.update(part.digest);
        }
        digest.finalize()
    }

    /// Plaintext MD5 ETag; internal attempt identity remains independently random.
    pub fn etag(&self) -> String {
        rs3_types::ObjectEtag::single(self.md5).to_s3_string()
    }
}

/// An unpublished opaque carrier. Different part numbers can upload in parallel.
/// The caller serializes replacements of one number and freezes outstanding
/// calls before consuming this session for completion or abort.
pub struct V3MultipartUpload {
    object_id: BackendObjectId,
    keyring: Arc<KeyRing>,
    context: Vec<u8>,
    carrier_id: [u8; 32],
    scope: Arc<()>,
    backend: Box<dyn BlobMultipartSession>,
    inflight: V2InflightStandaloneObject,
    retention: Option<RetentionPolicy>,
    legal_hold: Option<LegalHoldStatus>,
    stall_timeout: Duration,
    checksum_policy: Option<MultipartChecksumPolicy>,
    parts: RwLock<std::collections::BTreeMap<u32, V3UploadedPart>>,
}

/// Fully verified detached bytes awaiting logical, fenced publication.
/// This object carries no authority to acknowledge a successful client write.
pub struct V3VerifiedMultipartUpload {
    pub(crate) etag: rs3_types::ObjectEtag,
    pub(crate) stored: Option<V2StoredStandalonePayload>,
    pub(crate) _inflight: V2InflightStandaloneObject,
}

impl V3VerifiedMultipartUpload {
    /// Total verified plaintext bytes, including an index-only empty result.
    pub fn plaintext_len(&self) -> u64 {
        self.stored
            .as_ref()
            .map_or(0, |stored| stored.payload_layout.plaintext_len)
    }
}

impl V3MultipartUpload {
    /// Encrypts one replacement attempt while streaming bounded plaintext.
    pub async fn upload_part(
        &self,
        part_number: u32,
        read: Box<dyn BlobRead>,
        checksum: Option<UploadChecksum>,
        expected_md5: Option<rs3_types::Md5Digest>,
    ) -> V2Result<V3UploadedPart> {
        if self.checksum_policy.is_some() != checksum.is_some() {
            return Err(V2FormatError::InvalidHeaderField);
        }
        let index = part_number
            .checked_sub(1)
            .ok_or(V2FormatError::InvalidHeaderField)? as usize;
        let plaintext_len = read.exact_len();
        let sealer = SegmentedPayloadSealer::new(
            &self.keyring,
            PART_SEGMENT_BYTES,
            self.context.clone(),
            self.carrier_id,
            part_number,
        )
        .map_err(|_| V2FormatError::InvalidHeaderField)?;
        let ciphertext_len = sealer
            .sealed_len_for_plaintext_len(plaintext_len)
            .map_err(|_| V2FormatError::InvalidHeaderField)?;
        if ciphertext_len > rs3_storage::MULTIPART_MAX_PART_BYTES {
            return Err(V2FormatError::InvalidHeaderField);
        }
        let digest = Arc::new(Mutex::new(None));
        let part = PayloadPart {
            part_number,
            attempt_id: sealer.attempt_id(),
            plaintext_len,
        };
        let body = body::EncryptedPartBody::new(
            sealer,
            Arc::clone(&self.keyring),
            self.object_id.clone(),
            read,
            ciphertext_len,
            self.stall_timeout,
            Arc::clone(&digest),
        )
        .with_expected_md5(expected_md5);
        let backend = self.backend.upload_part(index, Box::new(body)).await;
        let digests = digest
            .lock()
            .map_err(|_| V2FormatError::StorageOperationFailed)?
            .take();
        if digests
            .as_ref()
            .is_some_and(|digests| expected_md5.is_some_and(|expected| expected != digests.md5))
        {
            return Err(V2FormatError::ContentMd5Mismatch);
        }
        let backend = backend.map_err(storage_to_v2)?;
        if backend.index() != index || backend.content_len() != ciphertext_len {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        let digests = digests.ok_or(V2FormatError::ProviderProfileFailed)?;
        // EncryptedPartBody records its digest only after exact plaintext EOF.
        // A trailer handoff is therefore resolved before replacing the current part.
        let checksum = checksum
            .map(|checksum| {
                checksum
                    .get()
                    .map_err(|_| V2FormatError::InvalidHeaderField)
            })
            .transpose()?;
        if checksum.as_ref().is_some_and(|checksum| {
            checksum.kind() != ChecksumType::FullObject
                || self
                    .checksum_policy
                    .is_none_or(|policy| policy.algorithm() != checksum.algorithm())
        }) {
            return Err(V2FormatError::InvalidHeaderField);
        }
        let uploaded = V3UploadedPart {
            scope: Arc::clone(&self.scope),
            backend,
            part,
            digest: digests.ciphertext,
            md5: digests.md5,
            checksum,
        };
        self.parts
            .write()
            .map_err(|_| V2FormatError::StorageOperationFailed)?
            .insert(part_number, uploaded.clone());
        Ok(uploaded)
    }

    pub(in crate::v2) fn list_parts(
        &self,
        after: u32,
        limit: usize,
    ) -> V2Result<Vec<V3UploadedPart>> {
        let parts = self
            .parts
            .read()
            .map_err(|_| V2FormatError::StorageOperationFailed)?;
        Ok(parts
            .range((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded))
            .take(limit.min(1001))
            .map(|(_, part)| part.clone())
            .collect())
    }

    pub(in crate::v2) fn select_parts(
        &self,
        selection: &[(u32, String)],
    ) -> V2Result<Vec<V3UploadedPart>> {
        let current = self
            .parts
            .read()
            .map_err(|_| V2FormatError::StorageOperationFailed)?;
        selection
            .iter()
            .map(|(number, etag)| {
                current
                    .get(number)
                    .filter(|part| part.etag() == *etag)
                    .cloned()
                    .ok_or(V2FormatError::InvalidHeaderField)
            })
            .collect()
    }

    /// Aborts provider temporary state after outstanding part calls stop.
    pub async fn abort(self) -> V2Result<()> {
        abort_client_upload(self.backend).await
    }
}

impl<S: BlobStore> V2CommitStore<S> {
    /// Starts an unpublished client multipart carrier under current protection.
    pub async fn create_client_multipart_upload(
        &self,
        retention: Option<RetentionPolicy>,
        legal_hold: Option<LegalHoldStatus>,
        checksum_policy: Option<MultipartChecksumPolicy>,
    ) -> V2Result<V3MultipartUpload> {
        self.validate_write_protection_profile(retention, legal_hold)?;
        let object_id = super::super::standalone::generate_v2_standalone_object_id()?;
        let inflight = self.claim_inflight_standalone_object(object_id.clone())?;
        let context = super::super::service::packed::repository_context_from_refs(
            &self.options.repository_id,
            &self.options.keyring_envelope_ref,
        )
        .map_err(|_| V2FormatError::InvalidHeaderField)?;
        let carrier_id = super::super::standalone::standalone_carrier_id(&object_id)?;
        let backend = self
            .store
            .create_multipart_session(
                &object_id,
                PutOptions {
                    retention,
                    legal_hold,
                    content_type: Some("application/vnd.rs3.payload.v3".to_owned()),
                    do_not_recreate: self.options.provider_profile
                        != V2ProviderProfile::RetainedVersionObjectLock,
                },
            )
            .await
            .map_err(storage_to_v2)?;
        Ok(V3MultipartUpload {
            object_id,
            inflight,
            context,
            carrier_id,
            backend,
            scope: Arc::new(()),
            keyring: Arc::new(self.keyring.clone()),
            retention,
            legal_hold,
            stall_timeout: self.options.stream_read_stall_timeout,
            checksum_policy,
            parts: RwLock::new(Default::default()),
        })
    }

    /// Verifies every selected ciphertext part before returning publication input.
    /// An error can leave an inert completed orphan; it never publishes a value.
    pub async fn complete_client_multipart_upload(
        &self,
        upload: V3MultipartUpload,
        parts: Vec<V3UploadedPart>,
    ) -> V2Result<V3VerifiedMultipartUpload> {
        let result = self.validate_multipart_selection(&upload, &parts);
        let layout = match result {
            Ok(layout) => layout,
            Err(error) => {
                let _ = abort_client_upload(upload.backend).await;
                return Err(error);
            }
        };
        let etag =
            rs3_crypto::multipart_etag(&parts.iter().map(|part| part.md5).collect::<Vec<_>>())
                .map_err(|_| V2FormatError::InvalidHeaderField)?;
        let Some(layout) = layout else {
            abort_client_upload(upload.backend).await?;
            return Ok(V3VerifiedMultipartUpload {
                etag,
                stored: None,
                _inflight: upload.inflight,
            });
        };
        let expected_len = layout
            .reference()
            .stored_len()
            .ok_or(V2FormatError::InvalidHeaderField)?;
        let selected = parts.iter().map(|part| part.backend.clone()).collect();
        let metadata = upload
            .backend
            .complete(selected)
            .await
            .map_err(storage_to_v2)?;
        if metadata.object_id != upload.object_id || metadata.content_len != expected_len {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        let version = metadata.version_id.as_ref();
        if self.options.provider_profile == V2ProviderProfile::RetainedVersionObjectLock
            && version.is_none()
        {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        let deadline = required_retain_until_ms(upload.retention);
        if deadline.is_some() {
            self.store
                .extend_retention_at(
                    &upload.object_id,
                    version,
                    upload
                        .retention
                        .ok_or(V2FormatError::ProviderProfileFailed)?,
                )
                .await
                .map_err(storage_to_v2)?;
        }
        // Verify trusted expected bytes first, then reuse the common exact-version
        // and protection checks without a redundant aggregate-digest readback.
        let digest = verify_selected_parts(
            &self.store,
            &upload.object_id,
            version,
            expected_len,
            &parts,
        )
        .await?;
        let version_id = self
            .verify_commit_protection_postconditions(
                &upload.object_id,
                &metadata,
                V2WritePostconditions {
                    expected_object_len: expected_len,
                    required_retention: upload.retention,
                    required_retain_until_ms: deadline,
                    required_legal_hold: upload.legal_hold,
                    expected_stored_digest: None,
                },
            )
            .await?;
        Ok(V3VerifiedMultipartUpload {
            etag,
            stored: Some(V2StoredStandalonePayload {
                etag,
                object_id: upload.object_id,
                version_id,
                object_len: expected_len,
                object_digest: digest,
                payload_layout: layout,
            }),
            _inflight: upload.inflight,
        })
    }

    fn validate_multipart_selection(
        &self,
        upload: &V3MultipartUpload,
        parts: &[V3UploadedPart],
    ) -> V2Result<Option<SegmentedPayloadLayout>> {
        let context = super::super::service::packed::repository_context_from_refs(
            &self.options.repository_id,
            &self.options.keyring_envelope_ref,
        )
        .map_err(|_| V2FormatError::InvalidHeaderField)?;
        if context != upload.context
            || !self.is_inflight_standalone_object(&upload.object_id)?
            || parts.is_empty()
            || parts.len() > rs3_index::MAX_PAYLOAD_PARTS
        {
            return Err(V2FormatError::InvalidHeaderField);
        }
        let current = upload
            .parts
            .read()
            .map_err(|_| V2FormatError::StorageOperationFailed)?;
        let mut last = 0;
        let mut plaintext_len = 0_u64;
        for (index, part) in parts.iter().enumerate() {
            if current
                .get(&part.part.part_number)
                .is_none_or(|latest| latest.part.attempt_id != part.part.attempt_id)
                || !Arc::ptr_eq(&upload.scope, &part.scope)
                || part.part.part_number <= last
                || part.part.part_number > 10_000
                || (index + 1 < parts.len()
                    && part.part.plaintext_len < rs3_storage::MULTIPART_MIN_PART_BYTES)
            {
                return Err(V2FormatError::InvalidHeaderField);
            }
            last = part.part.part_number;
            plaintext_len = plaintext_len
                .checked_add(part.part.plaintext_len)
                .ok_or(V2FormatError::InvalidHeaderField)?;
        }
        if plaintext_len == 0 {
            return Ok(None);
        }
        let reference = PayloadLayout {
            chunk_size: PART_SEGMENT_BYTES as u64,
            plaintext_len,
            key_id: upload
                .keyring
                .primary_content_key_id()
                .map_err(|_| V2FormatError::InvalidHeaderField)?,
            carrier_id: upload.carrier_id,
            parts: parts
                .iter()
                .filter(|part| part.part.plaintext_len != 0)
                .map(|part| part.part.clone())
                .collect(),
        };
        SegmentedPayloadLayout::new(reference, context)
            .map(Some)
            .map_err(|_| V2FormatError::InvalidHeaderField)
    }
}

async fn verify_selected_parts<S: BlobStore>(
    store: &S,
    object_id: &BackendObjectId,
    version: Option<&BackendVersionId>,
    expected_len: u64,
    parts: &[V3UploadedPart],
) -> V2Result<[u8; 32]> {
    let mut reader = store
        .open_bounded_full_at(object_id, version, expected_len)
        .await
        .map_err(storage_to_v2)?;
    if reader.exact_len() != expected_len {
        return Err(V2FormatError::ProviderProfileFailed);
    }
    let mut whole = Sha256Hasher::new();
    let mut pending = Bytes::new();
    for part in parts {
        let mut remaining = part.backend.content_len();
        let mut digest = Sha256Hasher::new();
        while remaining != 0 {
            if pending.is_empty() {
                pending = reader
                    .next_chunk()
                    .await
                    .map_err(storage_to_v2)?
                    .ok_or(V2FormatError::ProviderProfileFailed)?;
                if pending.is_empty() || pending.len() > rs3_storage::MAX_BLOB_READ_CHUNK_BYTES {
                    return Err(V2FormatError::ProviderProfileFailed);
                }
            }
            let len = pending
                .len()
                .min(usize::try_from(remaining).unwrap_or(usize::MAX));
            let bytes = pending.split_to(len);
            digest.update(&bytes);
            whole.update(&bytes);
            remaining -= len as u64;
        }
        if digest.finalize() != part.digest {
            return Err(V2FormatError::ProviderProfileFailed);
        }
    }
    if !pending.is_empty() || reader.next_chunk().await.map_err(storage_to_v2)?.is_some() {
        return Err(V2FormatError::ProviderProfileFailed);
    }
    Ok(whole.finalize())
}

async fn abort_client_upload(backend: Box<dyn BlobMultipartSession>) -> V2Result<()> {
    backend.abort().await.map_err(|error| {
        record_multipart_abort_failure(&error, "client_upload");
        storage_to_v2(error)
    })
}
