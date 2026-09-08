//! Client upload identity, immutable request binding, and anchored completion.

use super::*;
use crate::v2::{V3MultipartUpload, V3UploadedPart, V3VerifiedMultipartUpload};
use crate::{MultipartChecksumKind, MultipartChecksumPolicy, UploadChecksum};
use rs3_index::completion::CompletionReceipt;
use rs3_storage::BlobRead;
use rs3_types::{ChecksumType, MultipartUploadId, ObjectChecksum};

/// Canonical selected client part numbers and unquoted ETags, bounded to 10,000.
/// Request identity is independent of the logical key and plaintext equality.
#[derive(Clone)]
pub struct V3MultipartSelection {
    parts: Vec<(u32, String)>,
    digest: [u8; 32],
    declared_checksums: Vec<Option<ObjectChecksum>>,
    expected_checksum: Option<ObjectChecksum>,
    declared_kind: Option<MultipartChecksumKind>,
}

impl V3MultipartSelection {
    /// Rejects empty, unordered, repeated, oversized or malformed selections.
    pub fn new(parts: Vec<(u32, String)>) -> Result<Self> {
        Self::with_checksums(
            parts
                .into_iter()
                .map(|(number, etag)| (number, etag, None))
                .collect(),
            None,
        )
    }

    /// Binds exact declared part and final checksum facts to accepted retries.
    pub fn with_checksums(
        selected: Vec<(u32, String, Option<ObjectChecksum>)>,
        expected_checksum: Option<ObjectChecksum>,
    ) -> Result<Self> {
        Self::with_checksums_and_kind(selected, expected_checksum, None)
    }

    /// Also binds an explicitly declared completion type, even without a digest.
    pub fn with_checksums_and_kind(
        selected: Vec<(u32, String, Option<ObjectChecksum>)>,
        expected_checksum: Option<ObjectChecksum>,
        declared_kind: Option<MultipartChecksumKind>,
    ) -> Result<Self> {
        let (parts, declared_checksums): (Vec<_>, Vec<_>) = selected
            .into_iter()
            .map(|(number, etag, checksum)| ((number, etag), checksum))
            .unzip();
        if parts.is_empty() || parts.len() > rs3_index::MAX_PAYLOAD_PARTS {
            return Err(invalid_completion());
        }
        let mut previous = 0;
        let mut digest = Sha256Hasher::new();
        digest.update(b"rs3:v3-multipart-client-selection:v2\0");
        digest.update((parts.len() as u64).to_be_bytes());
        for (number, etag) in &parts {
            if *number <= previous
                || *number > 10_000
                || etag.is_empty()
                || etag.len() > 128
                || etag.bytes().any(|byte| !(0x21..=0x7e).contains(&byte))
            {
                return Err(invalid_completion());
            }
            previous = *number;
            digest.update(number.to_be_bytes());
            digest.update((etag.len() as u16).to_be_bytes());
            digest.update(etag.as_bytes());
        }
        for checksum in declared_checksums
            .iter()
            .chain(std::iter::once(&expected_checksum))
        {
            if let Some(checksum) = checksum {
                let encoded = checksum.encode();
                digest.update((encoded.len() as u64).to_be_bytes());
                digest.update(encoded);
            } else {
                digest.update(0_u64.to_be_bytes());
            }
        }
        digest.update([match declared_kind {
            None => 0,
            Some(MultipartChecksumKind::FullObject) => 1,
            Some(MultipartChecksumKind::Composite) => 2,
        }]);
        Ok(Self {
            parts,
            digest: digest.finalize(),
            declared_checksums,
            expected_checksum,
            declared_kind,
        })
    }

    /// Digest used to match a retry against an authenticated accepted receipt.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Unpublished upload with its destination and protection fixed at creation.
/// Callers must serialize same-number replacements and freeze part writes before
/// consuming it. The gateway owns admission, age limits and abandoned sessions.
pub struct V3ClientMultipartUpload {
    id: MultipartUploadId,
    key: LogicalPath,
    options: RepositoryPutOptions,
    protection: (Option<RetentionPolicy>, Option<LegalHoldStatus>),
    upload: V3MultipartUpload,
    checksum_policy: Option<MultipartChecksumPolicy>,
}

impl V3ClientMultipartUpload {
    /// Random client identity, independent of provider upload IDs and paths.
    pub fn id(&self) -> MultipartUploadId {
        self.id
    }

    /// Tests a request destination without exposing it through Debug or errors.
    pub fn matches_key(&self, key: &LogicalPath) -> bool {
        self.key == *key
    }

    /// Checksum algorithm and construction fixed when this upload was created.
    pub fn checksum_policy(&self) -> Option<MultipartChecksumPolicy> {
        self.checksum_policy
    }

    /// Streams and seals one independent part attempt.
    pub async fn upload_part(
        &self,
        number: u32,
        body: Box<dyn BlobRead>,
        checksum: Option<UploadChecksum>,
        expected_md5: Option<rs3_types::Md5Digest>,
    ) -> Result<V3UploadedPart> {
        self.upload
            .upload_part(number, body, checksum, expected_md5)
            .await
            .map_err(v2_repository_error)
    }

    /// Checks tokens before the caller removes this unfinished session.
    pub fn validate_selection(&self, selection: &V3MultipartSelection) -> Result<()> {
        let parts = self
            .upload
            .select_parts(&selection.parts)
            .map_err(v2_repository_error)?;
        self.selected_checksum(selection, &parts).map(|_| ())
    }

    fn selected_checksum(
        &self,
        selection: &V3MultipartSelection,
        parts: &[V3UploadedPart],
    ) -> Result<Option<ObjectChecksum>> {
        let Some(policy) = self.checksum_policy else {
            if selection.declared_kind.is_some()
                || selection.expected_checksum.is_some()
                || selection.declared_checksums.iter().any(Option::is_some)
            {
                return Err(invalid_completion());
            }
            return Ok(None);
        };
        if selection
            .declared_kind
            .is_some_and(|kind| kind != policy.kind())
        {
            return Err(invalid_completion());
        }
        let kind = match policy.kind() {
            MultipartChecksumKind::FullObject => ChecksumType::FullObject,
            MultipartChecksumKind::Composite => ChecksumType::Composite {
                parts: parts.len() as u32,
            },
        };
        let mut checksums = Vec::with_capacity(parts.len());
        for (index, (part, declared)) in parts.iter().zip(&selection.declared_checksums).enumerate()
        {
            let actual = part
                .checksum()
                .ok_or(RepositoryError::ObjectChecksumUnavailable)?;
            if actual.algorithm() != policy.algorithm() || actual.kind() != ChecksumType::FullObject
            {
                return Err(invalid_completion());
            }
            if policy.kind() == MultipartChecksumKind::Composite
                && (part.part_number() != index as u32 + 1 || declared.is_none())
            {
                return Err(invalid_completion());
            }
            if let Some(declared) = declared {
                if declared.algorithm() != policy.algorithm()
                    || declared.kind() != ChecksumType::FullObject
                {
                    return Err(invalid_completion());
                }
                if declared != actual {
                    return Err(RepositoryError::ObjectChecksumMismatch);
                }
            }
            checksums.push((actual.digest(), part.plaintext_len()));
        }
        let combined = rs3_crypto::combine_part_checksums(policy.algorithm(), kind, &checksums)
            .map_err(|_| invalid_completion())?;
        if let Some(expected) = &selection.expected_checksum {
            if expected.algorithm() != policy.algorithm() || expected.kind() != kind {
                return Err(invalid_completion());
            }
            if expected != &combined {
                return Err(RepositoryError::ObjectChecksumMismatch);
            }
        }
        Ok(Some(combined))
    }

    /// Returns up to 1001 current parts after a marker for bounded pagination.
    pub fn list_parts(&self, after: u32, limit: usize) -> Result<Vec<V3UploadedPart>> {
        self.upload
            .list_parts(after, limit)
            .map_err(v2_repository_error)
    }

    /// Adds CompleteMultipartUpload's conditional creation requirement. This
    /// cannot weaken the creation-time destination or protection settings.
    pub fn require_absent_at_publication(&mut self) {
        self.options.create_only = true;
    }

    /// Total selected plaintext bytes and minimum nonfinal sizes, checked while
    /// the caller has frozen part writes but before consuming this upload.
    pub fn selected_size(&self, selection: &V3MultipartSelection) -> Result<u64> {
        let parts = self
            .upload
            .select_parts(&selection.parts)
            .map_err(v2_repository_error)?;
        let mut len = 0_u64;
        for (index, part) in parts.iter().enumerate() {
            if index + 1 < parts.len()
                && part.plaintext_len() < rs3_storage::MULTIPART_MIN_PART_BYTES
            {
                return Err(invalid_completion());
            }
            len = len
                .checked_add(part.plaintext_len())
                .ok_or_else(invalid_completion)?;
        }
        Ok(len)
    }

    /// Aborts temporary provider state after outstanding calls stop.
    pub async fn abort(self) -> Result<()> {
        self.upload.abort().await.map_err(v2_repository_error)
    }
}

pub(in crate::v2) struct PreparedMultipartCompletion {
    id: MultipartUploadId,
    key: LogicalPath,
    options: RepositoryPutOptions,
    protection: (Option<RetentionPolicy>, Option<LegalHoldStatus>),
    selection_digest: [u8; 32],
    attempts_digest: [u8; 32],
    verified: V3VerifiedMultipartUpload,
}

impl<S: BlobStore + Clone> V2Repository<S> {
    /// Starts a carrier without taking the short publication window.
    pub async fn create_multipart_upload(
        &self,
        key: LogicalPath,
        options: RepositoryPutOptions,
        checksum_policy: Option<MultipartChecksumPolicy>,
    ) -> Result<V3ClientMultipartUpload> {
        self.ensure_local_state_ready()?;
        self.validate_client_object_lock(&options)?;
        if options.checksum.is_some() || options.expected_md5.is_some() {
            return Err(invalid_completion());
        }
        if key.as_str().len() > 1024 {
            return Err(invalid_completion());
        }
        let id = MultipartUploadId::from_bytes(
            rs3_crypto::random_carrier_id()
                .map_err(|_| v2_repository_error(V2FormatError::RandomnessUnavailable))?,
        );
        let protection = self.effective_put_protection(&options);
        let upload = self
            .commit_store
            .create_client_multipart_upload(protection.0, protection.1, checksum_policy)
            .await
            .map_err(v2_repository_error)?;
        Ok(V3ClientMultipartUpload {
            id,
            key,
            options,
            protection,
            upload,
            checksum_policy,
        })
    }

    /// Returns only an accepted result for this exact destination and selection.
    /// Absence permits NoSuchUpload, never creation of a new write from the ID.
    pub fn accepted_multipart_completion(
        &self,
        id: &MultipartUploadId,
        key: &LogicalPath,
        selection: &V3MultipartSelection,
    ) -> Result<Option<CompletionReceipt>> {
        let receipt = self.completion_receipt(id)?;
        if receipt.as_ref().is_some_and(|receipt| {
            receipt.key != *key || receipt.selection_digest != selection.digest
        }) {
            return Err(invalid_completion());
        }
        Ok(receipt)
    }

    pub(in crate::v2) async fn prepare_multipart_completion(
        &self,
        mut session: V3ClientMultipartUpload,
        selection: V3MultipartSelection,
    ) -> Result<PreparedMultipartCompletion> {
        if self.effective_put_protection(&session.options) != session.protection {
            let _ = session.abort().await;
            return Err(invalid_completion());
        }
        let parts = match session.upload.select_parts(&selection.parts) {
            Ok(parts) => parts,
            Err(error) => {
                let _ = session.abort().await;
                return Err(v2_repository_error(error));
            }
        };
        let checksum = match session.selected_checksum(&selection, &parts) {
            Ok(checksum) => checksum,
            Err(error) => {
                let _ = session.abort().await;
                return Err(error);
            }
        };
        session.options.checksum = checksum.map(UploadChecksum::verified);
        let attempts_digest = V3UploadedPart::selected_attempts_digest(&parts);
        let verified = self
            .commit_store
            .complete_client_multipart_upload(session.upload, parts)
            .await
            .map_err(v2_repository_error)?;
        Ok(PreparedMultipartCompletion {
            id: session.id,
            key: session.key,
            options: session.options,
            protection: session.protection,
            selection_digest: selection.digest,
            attempts_digest,
            verified,
        })
    }

    pub(in crate::v2) async fn publish_multipart_completion<A: V2CommitAnchor>(
        &self,
        mutation: V2CoordinatedMutation<'_, A>,
        completion: PreparedMultipartCompletion,
    ) -> Result<CompletionReceipt> {
        self.validate_coordinator_lease(mutation.lease)?;
        let _guard = self.mutation_lock.lock().await;
        let _publication_guard = self.publication_lock.write().await;
        let base = self.ensure_accepted_anchor_matches(mutation.anchor).await?;
        if self.effective_put_protection(&completion.options) != completion.protection
            || self.completion_receipt(&completion.id)?.is_some()
        {
            return Err(invalid_completion());
        }
        let commit_sequence = base
            .sequence
            .checked_next()
            .ok_or_else(invalid_completion)?;
        let len = completion.verified.plaintext_len();
        let (staged, rollback) = self.stage_put_metadata_sync_with_rollback(
            completion.key,
            len,
            completion.options,
            if len == 0 {
                StagedPayload::Buffered(Bytes::new())
            } else {
                StagedPayload::Detached
            },
            completion.verified.etag,
        )?;
        let receipt = CompletionReceipt {
            checksum: staged.metadata.checksum.clone(),
            upload_id: completion.id,
            commit_sequence,
            selection_digest: completion.selection_digest,
            attempts_digest: completion.attempts_digest,
            key: staged.metadata.key.clone(),
            content_len: len,
            etag: staged.metadata.etag,
        };
        let result = async {
            let mut pending = self.pending_snapshot()?;
            if let Some(stored) = &completion.verified.stored {
                let carrier = Arc::new(V2StandaloneStreamCarrierReference {
                    object_id: stored.object_id.clone(),
                    version_id: stored.version_id.clone(),
                    object_digest: stored.object_digest,
                    stored_len: stored.object_len,
                    keyring_envelope_object_id: self
                        .commit_store
                        .options()
                        .keyring_envelope_ref
                        .object_id
                        .clone(),
                    keyring_envelope_digest: self
                        .commit_store
                        .options()
                        .keyring_envelope_ref
                        .digest,
                    payload_layout: stored.payload_layout.reference().clone(),
                });
                for delta in pending.deltas_mut() {
                    if let IndexDelta::Upsert { entry, .. } = delta
                        && entry.manifest_id == staged.manifest_id
                    {
                        entry.object_id = carrier.object_id.clone();
                        entry.object_version_id = carrier.version_id.clone();
                        entry.payload_ref = Some(PayloadReference::V2StandaloneStream {
                            carrier: Arc::clone(&carrier),
                        });
                    }
                }
            }
            pending.completion_receipt = Some(receipt.clone());
            self.publish_pending_snapshot(mutation.anchor, pending, mutation.guard)
                .await?
                .ok_or_else(invalid_completion)?;
            Ok(receipt)
        }
        .await;
        match result {
            Ok(receipt) => Ok(receipt),
            Err(RepositoryError::AcceptedRecoveryRequired) => {
                Err(RepositoryError::AcceptedRecoveryRequired)
            }
            Err(error) => {
                self.rollback_state_mutations(vec![rollback])?;
                Err(error)
            }
        }
    }
}

fn invalid_completion() -> RepositoryError {
    v2_repository_error(V2FormatError::InvalidHeaderField)
}
