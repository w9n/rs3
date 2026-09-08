//! v2 repository operations over the existing trusted namespace service.

use super::commit::{V2_SECTION_FLAG_COMPRESSED, V2_SECTION_FLAG_MUST_UNDERSTAND};
use super::error::V2FormatError;
use super::repository::{
    V2CommitAnchor, V2CommitSection, V2CommitStore, V2CommitStoreOptions, V2CommitWrite,
    V2MemoryAnchor, V2ReplayChain, V2ReplayCommit, V2StandalonePayloadWrite,
    V2StandaloneUploadCancellation, V2StoredCommit, V2StoredStandalonePayload,
};
use super::{
    V2_INDEX_ROOT_MAX_RUNS, V2EmbeddedIndexRunLocation, V2IndexRoot, V2IndexRootRunRef,
    V2KeyringEnvelopeRef, V2PayloadPackFacts, V2PayloadPackId, V2PayloadPackRecordContext,
    V2PayloadPackRecordRef, V2ProviderProfile, V2SectionType, V2StreamPayloadCacheIdentity,
    V2StreamPayloadCarrierCacheIdentity, digest_v2_section,
    open_v2_payload_pack_cached_record_span, open_v2_payload_pack_record_span_with_segments,
    plan_v2_payload_pack_record_range, seal_v2_index_root,
};
use crate::checkpoint::seal_manifest_record;
use crate::error::{RepositoryError, Result};
use crate::lru::LruCache;
use crate::model::{
    DeleteOutcome, PhysicalDeleteOutcome, RepositoryListEntry, RepositoryObjectMetadata,
    RepositoryPutOptions,
};
use crate::namespace::first_namespace_entry;
use crate::payload::{
    SegmentedPayloadLayout, effective_payload_segment_size, open_payload_object,
    segmented_ciphertext_span, total_segmented_payload_len,
};
use crate::service::{DecryptedSegmentIdentity, RepositoryOptions, RepositoryResources};
use crate::state::{RepositoryState, TrustedManifest, object_material};
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use rs3_crypto::KeyRing;
use rs3_crypto::Sha256Hasher;
use rs3_index::{
    IndexDelta, NamespaceEntry, PayloadLayout, PayloadReference, V2StandaloneStreamCarrierReference,
};
use rs3_storage::strongest_retention_policy;
use rs3_storage::{BlobStore, ByteRange, StorageError};
use rs3_types::{
    BackendObjectId, BackendObjectRef, BackendVersionId, LegalHoldStatus, LogicalPath, ManifestId,
    RetentionMode, RetentionPolicy, Sequence,
};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock as TokioRwLock};

mod compaction;
mod multipart;
pub use multipart::{V3ClientMultipartUpload, V3MultipartSelection};
pub(super) mod packed;
mod packed_compaction;
mod packed_compaction_publish;
mod read_stream;
mod staging;

use super::standalone::{generate_v2_standalone_object_id, validate_v2_standalone_object};
pub use compaction::V2FullMaintenanceReport;
pub use read_stream::V2AuthenticatedReadBody;
use staging::{PendingV2Checkpoint, PendingV2Snapshot, PendingV2State};

const V2_PAYLOAD_FILL_LOCK_STRIPES: usize = 64;

/// Preview v2 repository service.
///
/// This adapter deliberately reuses the existing trusted repository service for
/// path-private namespace indexing, payload encryption, range reads, and list
/// semantics. v2 only changes how the pending sealed index delta becomes
/// durable: it is embedded in a signed v2 commit instead of a v1 checkpoint.
pub struct V2Repository<S> {
    repository: RepositoryResources,
    commit_store: V2CommitStore<S>,
    accepted: StdRwLock<V2AcceptedState>,
    mutation_lock: Mutex<()>,
    publication_lock: TokioRwLock<()>,
    payload_segment_fill_locks: Vec<Mutex<()>>,
    pending: StdMutex<PendingV2State>,
    mutation_owner: Arc<AtomicU8>,
    recovery_required: AtomicBool,
    payload_sections: StdRwLock<V2PayloadSectionCache>,

    #[cfg(test)]
    fail_next_restore: AtomicBool,
    #[cfg(test)]
    fail_next_local_install: AtomicBool,
}

const V2_MUTATION_OWNER_IDLE: u8 = 0;
const V2_MUTATION_OWNER_COORDINATOR: u8 = 1;
const V2_MUTATION_OWNER_DIRECT: u8 = 2;

pub(super) struct V2CoordinatorLease {
    owner: Arc<AtomicU8>,
}

pub(super) struct V2CoordinatedMutation<'a, A> {
    lease: &'a V2CoordinatorLease,
    anchor: &'a A,
}

impl<'a, A> V2CoordinatedMutation<'a, A> {
    pub(super) fn new(lease: &'a V2CoordinatorLease, anchor: &'a A) -> Self {
        Self { lease, anchor }
    }
}

struct V2DirectMutationLease {
    owner: Arc<AtomicU8>,
}

impl Drop for V2CoordinatorLease {
    fn drop(&mut self) {
        self.owner.store(V2_MUTATION_OWNER_IDLE, Ordering::Release);
    }
}

impl Drop for V2DirectMutationLease {
    fn drop(&mut self) {
        self.owner.store(V2_MUTATION_OWNER_IDLE, Ordering::Release);
    }
}

#[derive(Default)]
struct V2AcceptedState {
    repository: RepositoryState,
    runs: Vec<V2IndexRootRunRef>,
    anchor: Option<super::repository::V2AnchorState>,
}

/// Immutable publication input captured before successor staging is admitted.
pub(crate) struct V2PendingPublication {
    snapshot: PendingV2Snapshot,
}

struct PendingV2Install {
    completion_receipts: Option<(Sequence, rs3_index::completion::CompletionReceipts)>,
    sequence: Sequence,
    mutations: Vec<PendingV2InstallMutation>,
    run: Option<V2IndexRootRunRef>,
}

enum PendingV2InstallMutation {
    Upsert {
        entry: Box<NamespaceEntry>,
        manifest: TrustedManifest,
    },
    Tombstone {
        blind_key: rs3_types::BlindIndexKey,
    },
}

#[derive(Clone, Debug)]
struct PendingV2Payload {
    manifest_id: ManifestId,
    body: Bytes,
}

#[derive(Debug)]
pub(crate) struct V2StagedPutRollback {
    checkpoint: PendingV2Checkpoint,
}

#[derive(Clone, Debug)]

struct StagedV2Put {
    metadata: RepositoryObjectMetadata,
    manifest_id: ManifestId,
    content_len: u64,
    sequence: Sequence,
}

pub(super) struct V2StandalonePayloadUpload {
    stored: V2StoredStandalonePayload,
    _inflight: super::repository::V2InflightStandaloneObject,
}

/// Client-visible object resolved against an accepted v2 namespace state.
#[derive(Clone, Debug)]
pub struct V2ResolvedObject {
    metadata: RepositoryObjectMetadata,
    entry: NamespaceEntry,
}

impl V2ResolvedObject {
    /// Trusted metadata for the resolved client-visible object.
    pub fn metadata(&self) -> &RepositoryObjectMetadata {
        &self.metadata
    }
}

struct StreamLength {
    expected: Option<u64>,
    maximum: u64,
}

impl<S> V2Repository<S>
where
    S: BlobStore + Clone,
{
    pub(super) fn validate_client_object_lock(&self, options: &RepositoryPutOptions) -> Result<()> {
        self.ensure_local_state_ready()?;
        let (retention, legal_hold) = self.effective_put_protection(options);
        if legal_hold == Some(LegalHoldStatus::On) {
            return Err(StorageError::LegalHoldUnsupported.into());
        }
        let requests_retention = retention
            .is_some_and(|policy| policy.mode != RetentionMode::None && policy.retain_days > 0);
        if requests_retention
            && self.commit_store.provider_profile() != V2ProviderProfile::RetainedVersionObjectLock
        {
            return Err(StorageError::RetentionExtensionUnsupported.into());
        }
        Ok(())
    }

    pub(super) fn effective_put_protection(
        &self,
        options: &RepositoryPutOptions,
    ) -> (Option<RetentionPolicy>, Option<LegalHoldStatus>) {
        let retention = strongest_retention_policy(
            self.repository.options.default_retention,
            options.retention,
        );
        self.effective_stored_protection(retention, options.legal_hold)
    }

    fn effective_stored_protection(
        &self,
        retention: Option<RetentionPolicy>,
        legal_hold: Option<LegalHoldStatus>,
    ) -> (Option<RetentionPolicy>, Option<LegalHoldStatus>) {
        let retention = strongest_retention_policy(self.commit_store.retention_policy(), retention);
        let legal_hold = if self.commit_store.options().legal_hold == Some(LegalHoldStatus::On)
            || legal_hold == Some(LegalHoldStatus::On)
        {
            Some(LegalHoldStatus::On)
        } else {
            None
        };
        (retention, legal_hold)
    }

    /// Creates a v2 repository service over a blob store.
    pub fn new(
        store: S,
        keyring: KeyRing,
        repository_options: RepositoryOptions,
        commit_options: V2CommitStoreOptions,
    ) -> Self {
        let payload_section_cache_max_bytes = repository_options.decrypted_segment_cache_max_bytes;
        Self {
            repository: RepositoryResources::new(keyring.clone(), repository_options),
            commit_store: V2CommitStore::new(store, keyring, commit_options),
            accepted: StdRwLock::new(V2AcceptedState::default()),
            mutation_lock: Mutex::new(()),
            publication_lock: TokioRwLock::new(()),
            payload_segment_fill_locks: (0..V2_PAYLOAD_FILL_LOCK_STRIPES)
                .map(|_| Mutex::new(()))
                .collect(),
            pending: StdMutex::new(PendingV2State::new(Sequence::ZERO)),
            mutation_owner: Arc::new(AtomicU8::new(V2_MUTATION_OWNER_IDLE)),
            recovery_required: AtomicBool::new(false),
            payload_sections: StdRwLock::new(V2PayloadSectionCache::with_max_bytes(
                payload_section_cache_max_bytes,
            )),

            #[cfg(test)]
            fail_next_restore: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_local_install: AtomicBool::new(false),
        }
    }

    /// Returns the v2 commit store.
    pub fn commit_store(&self) -> &V2CommitStore<S> {
        &self.commit_store
    }

    /// Writes the required empty v2 genesis snapshot.
    pub async fn write_genesis_snapshot<A>(&self, anchor: &A) -> Result<V2StoredCommit>
    where
        A: V2CommitAnchor,
    {
        let _mutation_lease = self.claim_direct_mutation()?;
        let _publication_guard = self.publication_lock.write().await;
        let stored = self
            .commit_store
            .write_genesis_snapshot(anchor)
            .await
            .map_err(v2_repository_error)?;
        match self.accepted.write() {
            Ok(mut accepted) => accepted.anchor = Some(stored.anchor_state.clone()),
            Err(error) => {
                self.mark_local_recovery_required();
                tracing::error!(
                    target: "rs3_repository",
                    operation = "v2_install_genesis",
                    error = %error,
                    "v2 genesis anchor advanced but local state installation failed; restart is required",
                );
                return Err(RepositoryError::AcceptedRecoveryRequired);
            }
        }
        Ok(stored)
    }

    /// Writes a signed catalog checkpoint from the current trusted state.
    pub async fn write_index_snapshot<A>(&self, anchor: &A) -> Result<V2StoredCommit>
    where
        A: V2CommitAnchor,
    {
        let _mutation_lease = self.claim_direct_mutation()?;
        self.write_index_snapshot_inner(anchor).await
    }

    pub(super) async fn write_index_snapshot_coordinated<A>(
        &self,
        mutation: V2CoordinatedMutation<'_, A>,
    ) -> Result<V2StoredCommit>
    where
        A: V2CommitAnchor,
    {
        self.validate_coordinator_lease(mutation.lease)?;
        self.write_index_snapshot_inner(mutation.anchor).await
    }

    async fn write_index_snapshot_inner<A>(&self, anchor: &A) -> Result<V2StoredCommit>
    where
        A: V2CommitAnchor,
    {
        let _guard = self.mutation_lock.lock().await;
        self.publish_pending_index_delta(anchor).await?;
        let base_anchor = anchor
            .read_v2()
            .await
            .map_err(v2_repository_error)?
            .ok_or_else(|| v2_repository_error(V2FormatError::MissingAnchor))?;
        if self
            .accepted
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?
            .anchor
            .as_ref()
            != Some(&base_anchor)
        {
            return Err(v2_repository_error(V2FormatError::StaleAnchor));
        }
        let (covered_generation, expected_live_object_count, expected_runs, receipts) = {
            let accepted = self
                .accepted
                .read()
                .map_err(|_| RepositoryError::StatePoisoned)?;
            (
                accepted.repository.next_sequence,
                u64::try_from(accepted.repository.list_entries.len())
                    .map_err(|_| v2_repository_error(V2FormatError::IndexRootLimitExceeded))?,
                accepted.runs.clone(),
                accepted.repository.completion_receipts.clone(),
            )
        };
        let root = V2IndexRoot::new(
            covered_generation,
            expected_live_object_count,
            self.commit_store.options().format_ref.clone(),
            self.commit_store.options().keyring_envelope_ref.clone(),
            expected_runs.clone(),
        )
        .map_err(v2_repository_error)?
        .with_completion_receipts(receipts);
        let temporary_anchor = V2MemoryAnchor::with_state(base_anchor.clone());
        let keyring = self.repository.keyring()?;
        let context = packed::repository_context_from_refs(
            &self.commit_store.options().repository_id,
            &self.commit_store.options().keyring_envelope_ref,
        )?;
        let uploaded = self
            .commit_store
            .write_child_commit_with(&temporary_anchor, |commit_key| {
                let sealed = seal_v2_index_root(
                    keyring.as_ref(),
                    &context,
                    &commit_key.object_id,
                    0,
                    &root,
                )?;
                Ok(V2CommitWrite::snapshot(vec![V2CommitSection::new(
                    V2SectionType::IndexRoot,
                    V2_SECTION_FLAG_MUST_UNDERSTAND,
                    sealed.bytes().clone(),
                )]))
            })
            .await
            .map_err(v2_repository_error)?;

        let candidate_anchor = temporary_anchor
            .read_v2()
            .await
            .map_err(v2_repository_error)?
            .ok_or_else(|| v2_repository_error(V2FormatError::MissingAnchor))?;
        let candidate_chain = self
            .commit_store
            .load_replay_chain_from_state(&candidate_anchor)
            .await
            .map_err(v2_repository_error)?;
        self.verify_exact_index_root(&candidate_chain, &root)?;
        if anchor.read_v2().await.map_err(v2_repository_error)? != Some(base_anchor) {
            return Err(v2_repository_error(V2FormatError::StaleAnchor));
        }
        let adopted = self
            .commit_store
            .adopt_unanchored_child(
                anchor,
                &uploaded.commit_key.object_id,
                uploaded.version_id.as_ref(),
            )
            .await
            .map_err(v2_repository_error)?;
        match self.accepted.write() {
            Ok(mut accepted) => accepted.anchor = Some(adopted.anchor_state.clone()),
            Err(error) => {
                self.mark_local_recovery_required();
                tracing::error!(
                    target: "rs3_repository",
                    operation = "v2_install_index_snapshot",
                    error = %error,
                    "v2 index-root anchor advanced but local state installation failed; restart is required",
                );
                return Err(RepositoryError::AcceptedRecoveryRequired);
            }
        }
        Ok(adopted)
    }

    fn verify_exact_index_root(&self, chain: &V2ReplayChain, expected: &V2IndexRoot) -> Result<()> {
        let [commit] = chain.commits_newest_first.as_slice() else {
            return Err(v2_repository_error(V2FormatError::InvalidIndexRoot));
        };
        let mut roots = commit
            .parsed_header
            .header
            .section_index
            .iter()
            .enumerate()
            .filter(|(_, section)| section.section_type == V2SectionType::IndexRoot);
        let Some((index, _)) = roots.next() else {
            return Err(v2_repository_error(V2FormatError::InvalidIndexRoot));
        };
        if roots.next().is_some() {
            return Err(v2_repository_error(V2FormatError::InvalidIndexRoot));
        }
        let stored_root = replay_section_bytes(commit, index)?;
        let actual = self
            .commit_store
            .open_index_root_without_replay(
                commit,
                u32::try_from(index)
                    .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?,
                stored_root,
                self.commit_store.options().replay_limits,
            )
            .map_err(v2_repository_error)?;
        if actual != *expected {
            return Err(v2_repository_error(V2FormatError::InvalidIndexRoot));
        }
        Ok(())
    }

    /// Loads and replays the commit chain selected by the v2 anchor.
    pub async fn load_chain_from_anchor<A>(&self, anchor: &A) -> Result<Option<V2ReplayChain>>
    where
        A: V2CommitAnchor,
    {
        let _mutation_lease = self.claim_direct_mutation()?;
        self.load_chain_from_anchor_inner(anchor).await
    }

    pub(super) async fn load_chain_from_anchor_coordinated<A>(
        &self,
        mutation: V2CoordinatedMutation<'_, A>,
    ) -> Result<Option<V2ReplayChain>>
    where
        A: V2CommitAnchor,
    {
        self.validate_coordinator_lease(mutation.lease)?;
        self.load_chain_from_anchor_inner(mutation.anchor).await
    }

    async fn load_chain_from_anchor_inner<A>(&self, anchor: &A) -> Result<Option<V2ReplayChain>>
    where
        A: V2CommitAnchor,
    {
        let _guard = self.mutation_lock.lock().await;
        let _publication_guard = self.publication_lock.write().await;
        let Some(anchor_state) = anchor.read_v2().await.map_err(v2_repository_error)? else {
            return Ok(None);
        };
        let chain = self
            .commit_store
            .load_replay_chain_from_state(&anchor_state)
            .await
            .map_err(v2_repository_error)?;
        let (rebuilt, accepted_runs) = self.replay_bounded_chain_to_state_and_runs(&chain).await?;
        if anchor.read_v2().await.map_err(v2_repository_error)? != Some(anchor_state.clone()) {
            return Err(v2_repository_error(V2FormatError::StaleAnchor));
        }
        let recovered_sequence = rebuilt.next_sequence;
        *self
            .accepted
            .write()
            .map_err(|_| RepositoryError::StatePoisoned)? = V2AcceptedState {
            repository: rebuilt,
            runs: accepted_runs,
            anchor: Some(anchor_state),
        };
        self.pending
            .lock()
            .map_err(|_| RepositoryError::StatePoisoned)?
            .reset_to_accepted_sequence(recovered_sequence)?;
        Ok(Some(chain))
    }

    async fn replay_bounded_chain_to_state_and_runs(
        &self,
        chain: &V2ReplayChain,
    ) -> Result<(RepositoryState, Vec<V2IndexRootRunRef>)> {
        let mut rebuilt = RepositoryState::default();
        let mut accepted_runs = Vec::new();
        let mut previous_published_at_ms = None;
        for commit in chain.commits_newest_first.iter().rev() {
            let published_at_ms = commit.parsed_header.header.publish_time_ms;
            if previous_published_at_ms.is_some_and(|previous| published_at_ms < previous) {
                return Err(v2_repository_error(V2FormatError::StaleAnchor));
            }
            previous_published_at_ms = Some(published_at_ms);
            accepted_runs.extend(
                self.apply_replay_commit_sections(&mut rebuilt, commit)
                    .await?,
            );
        }
        Ok((rebuilt, accepted_runs))
    }

    /// Returns a completion result from the authenticated accepted state.
    /// Missing IDs never authorize creating a replacement publication.
    pub fn completion_receipt(
        &self,
        id: &rs3_types::MultipartUploadId,
    ) -> Result<Option<rs3_index::completion::CompletionReceipt>> {
        self.ensure_local_state_ready()?;
        let accepted = self
            .accepted
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        Ok(accepted.repository.completion_receipts.get(id).cloned())
    }

    /// Writes an object and returns after the covering v2 commit is accepted.
    pub async fn put_committed<A>(
        &self,
        anchor: &A,
        key: LogicalPath,
        body: Bytes,
        options: RepositoryPutOptions,
    ) -> Result<RepositoryObjectMetadata>
    where
        A: V2CommitAnchor,
    {
        let _mutation_lease = self.claim_direct_mutation()?;
        let _guard = self.mutation_lock.lock().await;
        let _publication_guard = self.publication_lock.write().await;
        self.ensure_accepted_anchor_matches(anchor).await?;
        let (metadata, rollback) = self.stage_put_unlocked(key, body, options)?;
        if let Err(error) = self.publish_pending_index_delta_locked(anchor).await {
            self.rollback_staged_puts(vec![rollback])?;
            return Err(error);
        }
        Ok(metadata)
    }

    /// Streams a known-length object into a detached carrier before publication.
    #[cfg(test)]
    pub(crate) async fn put_committed_streaming_known_len<A, St>(
        &self,
        anchor: &A,
        key: LogicalPath,
        plaintext_len: u64,
        stream: St,
        options: RepositoryPutOptions,
        multipart_part_size: usize,
    ) -> Result<RepositoryObjectMetadata>
    where
        A: V2CommitAnchor,
        St: Stream<Item = Result<Bytes>> + Unpin + Send,
    {
        let _mutation_lease = self.claim_direct_mutation()?;
        self.put_committed_streaming_detached(
            anchor,
            key,
            StreamLength {
                expected: Some(plaintext_len),
                maximum: plaintext_len,
            },
            stream,
            options,
            multipart_part_size,
        )
        .await
    }

    pub(super) async fn upload_standalone_streaming_known_len<St>(
        &self,
        plaintext_len: u64,
        stream: St,
        options: &RepositoryPutOptions,
        multipart_part_size: usize,
        cancellation: Arc<V2StandaloneUploadCancellation>,
    ) -> Result<V2StandalonePayloadUpload>
    where
        St: Stream<Item = Result<Bytes>> + Unpin + Send,
    {
        self.upload_standalone_streaming(
            Some(plaintext_len),
            plaintext_len,
            stream,
            options,
            multipart_part_size,
            cancellation,
        )
        .await
    }

    async fn upload_standalone_streaming<St>(
        &self,
        expected_plaintext_len: Option<u64>,
        max_plaintext_len: u64,
        stream: St,
        options: &RepositoryPutOptions,
        multipart_part_size: usize,
        cancellation: Arc<V2StandaloneUploadCancellation>,
    ) -> Result<V2StandalonePayloadUpload>
    where
        St: Stream<Item = Result<Bytes>> + Unpin + Send,
    {
        self.validate_client_object_lock(options)?;
        let object_id = generate_v2_standalone_object_id().map_err(v2_repository_error)?;
        let inflight = self
            .commit_store
            .claim_inflight_standalone_object(object_id.clone())
            .map_err(v2_repository_error)?;
        let retention = strongest_retention_policy(
            strongest_retention_policy(
                self.repository.options.default_retention,
                self.commit_store.retention_policy(),
            ),
            options.retention,
        );
        let legal_hold = if options.legal_hold == Some(LegalHoldStatus::On)
            || self.commit_store.options().legal_hold == Some(LegalHoldStatus::On)
        {
            Some(LegalHoldStatus::On)
        } else {
            options
                .legal_hold
                .or(self.commit_store.options().legal_hold)
        };
        let payload_segment_size = self.payload_segment_size_for_object_len(
            expected_plaintext_len.unwrap_or(max_plaintext_len),
        )?;
        let stored = self
            .commit_store
            .write_standalone_streaming_payload(V2StandalonePayloadWrite {
                object_id,
                expected_plaintext_len,
                max_plaintext_len,
                payload_segment_size,
                stream,
                retention,
                legal_hold,
                multipart_part_size,
                cancellation,
            })
            .await
            .map_err(v2_repository_error)?;
        Ok(V2StandalonePayloadUpload {
            stored,
            _inflight: inflight,
        })
    }

    pub(super) async fn publish_standalone_streaming_known_len_coordinated<A>(
        &self,
        mutation: V2CoordinatedMutation<'_, A>,
        key: LogicalPath,
        plaintext_len: u64,
        upload: V2StandalonePayloadUpload,
        options: RepositoryPutOptions,
    ) -> Result<RepositoryObjectMetadata>
    where
        A: V2CommitAnchor,
    {
        self.validate_coordinator_lease(mutation.lease)?;
        self.publish_standalone_streaming(mutation.anchor, key, plaintext_len, upload, options)
            .await
    }

    async fn publish_standalone_streaming<A>(
        &self,
        anchor: &A,
        key: LogicalPath,
        plaintext_len: u64,
        upload: V2StandalonePayloadUpload,
        options: RepositoryPutOptions,
    ) -> Result<RepositoryObjectMetadata>
    where
        A: V2CommitAnchor,
    {
        let _guard = self.mutation_lock.lock().await;
        let _publication_guard = self.publication_lock.write().await;
        let base_anchor = self.ensure_accepted_anchor_matches(anchor).await?;
        let (staged, rollback) = self.stage_put_metadata_sync_with_rollback(
            key,
            plaintext_len,
            options,
            None,
            upload.stored.etag,
        )?;
        let carrier = Arc::new(V2StandaloneStreamCarrierReference {
            object_id: upload.stored.object_id.clone(),
            version_id: upload.stored.version_id.clone(),
            object_digest: upload.stored.object_digest,
            stored_len: upload.stored.object_len,
            keyring_envelope_object_id: self
                .commit_store
                .options()
                .keyring_envelope_ref
                .object_id
                .clone(),
            keyring_envelope_digest: self.commit_store.options().keyring_envelope_ref.digest,
            payload_layout: upload.stored.payload_layout.reference().clone(),
        });
        let result = self
            .publish_staged_standalone_locked(anchor, &base_anchor, &staged, carrier)
            .await;
        match result {
            Ok(()) => Ok(staged.metadata),
            Err(RepositoryError::AcceptedRecoveryRequired) => {
                Err(RepositoryError::AcceptedRecoveryRequired)
            }
            Err(error) => {
                self.rollback_state_mutations(vec![rollback])?;
                Err(error)
            }
        }
    }

    async fn publish_staged_standalone_locked<A>(
        &self,
        anchor: &A,
        base_anchor: &super::repository::V2AnchorState,
        staged: &StagedV2Put,
        carrier: Arc<V2StandaloneStreamCarrierReference>,
    ) -> Result<()>
    where
        A: V2CommitAnchor,
    {
        validate_v2_standalone_object(&carrier.object_id, carrier.stored_len)
            .map_err(v2_repository_error)?;
        if carrier.payload_layout.plaintext_len != staged.content_len {
            return Err(v2_repository_error(V2FormatError::InvalidHeaderField));
        }
        let mut pending = self.pending_snapshot()?;
        let mut resolved = false;
        for delta in pending.deltas_mut() {
            let IndexDelta::Upsert { entry, .. } = delta else {
                continue;
            };
            if entry.manifest_id != staged.manifest_id {
                continue;
            }
            if resolved || entry.content_len != staged.content_len {
                return Err(v2_repository_error(V2FormatError::InvalidHeaderField));
            }
            entry.object_id = carrier.object_id.clone();
            entry.object_version_id = carrier.version_id.clone();
            entry.payload_ref = Some(PayloadReference::V2StandaloneStream {
                carrier: Arc::clone(&carrier),
            });
            resolved = true;
        }
        if !resolved {
            return Err(v2_repository_error(V2FormatError::InvalidHeaderField));
        }
        let temporary_anchor = V2MemoryAnchor::with_state(base_anchor.clone());
        let mut accepted_run = None;
        let uploaded = self
            .commit_store
            .write_child_commit_with(&temporary_anchor, |commit_key| {
                let packed = self
                    .pending_packed_sections_for_commit(commit_key, &pending)
                    .map_err(|_| V2FormatError::InvalidHeaderField)?
                    .ok_or(V2FormatError::InvalidHeaderField)?;
                accepted_run = Some(packed.run);
                Ok(V2CommitWrite::delta(packed.sections)
                    .with_retention(packed.retention)
                    .with_legal_hold(packed.legal_hold))
            })
            .await
            .map_err(v2_repository_error)?;
        let accepted_run = accepted_run
            .map(|run| self.accepted_run_ref(run, &uploaded))
            .ok_or_else(|| v2_repository_error(V2FormatError::InvalidHeaderField))?;
        self.validate_accepted_run_append(&accepted_run)?;
        let install =
            self.prepare_pending_install(&pending, staged.sequence, Some(accepted_run))?;
        let adopted = self
            .commit_store
            .adopt_verified_unanchored_child(anchor, base_anchor, &uploaded)
            .await
            .map_err(|error| self.publication_error(error))?;
        if let Err(error) = self.install_pending_commit(install, adopted.anchor_state) {
            self.mark_local_recovery_required();
            tracing::error!(
                target: "rs3_repository",
                operation = "v2_install_standalone_commit",
                error = %error,
                "v2 standalone anchor advanced but local state installation failed; restart is required",
            );
            return Err(RepositoryError::AcceptedRecoveryRequired);
        }
        Ok(())
    }

    /// Streams an unknown-length object into a detached carrier before publication.
    pub async fn put_committed_streaming_unknown_len<A, St>(
        &self,
        anchor: &A,
        key: LogicalPath,
        stream: St,
        options: RepositoryPutOptions,
        multipart_part_size: usize,
        max_plaintext_len: u64,
    ) -> Result<RepositoryObjectMetadata>
    where
        A: V2CommitAnchor,
        St: Stream<Item = Result<Bytes>> + Unpin + Send,
    {
        let _mutation_lease = self.claim_direct_mutation()?;
        self.put_committed_streaming_unknown_len_inner(
            anchor,
            key,
            stream,
            options,
            multipart_part_size,
            max_plaintext_len,
        )
        .await
    }

    pub(super) async fn put_committed_streaming_unknown_len_coordinated<A, St>(
        &self,
        mutation: V2CoordinatedMutation<'_, A>,
        key: LogicalPath,
        stream: St,
        options: RepositoryPutOptions,
        multipart_part_size: usize,
        max_plaintext_len: u64,
    ) -> Result<RepositoryObjectMetadata>
    where
        A: V2CommitAnchor,
        St: Stream<Item = Result<Bytes>> + Unpin + Send,
    {
        self.validate_coordinator_lease(mutation.lease)?;
        self.put_committed_streaming_unknown_len_inner(
            mutation.anchor,
            key,
            stream,
            options,
            multipart_part_size,
            max_plaintext_len,
        )
        .await
    }

    async fn put_committed_streaming_unknown_len_inner<A, St>(
        &self,
        anchor: &A,
        key: LogicalPath,
        stream: St,
        options: RepositoryPutOptions,
        multipart_part_size: usize,
        max_plaintext_len: u64,
    ) -> Result<RepositoryObjectMetadata>
    where
        A: V2CommitAnchor,
        St: Stream<Item = Result<Bytes>> + Unpin + Send,
    {
        self.put_committed_streaming_detached(
            anchor,
            key,
            StreamLength {
                expected: None,
                maximum: max_plaintext_len,
            },
            stream,
            options,
            multipart_part_size,
        )
        .await
    }

    async fn put_committed_streaming_detached<A, St>(
        &self,
        anchor: &A,
        key: LogicalPath,
        length: StreamLength,
        mut stream: St,
        options: RepositoryPutOptions,
        multipart_part_size: usize,
    ) -> Result<RepositoryObjectMetadata>
    where
        A: V2CommitAnchor,
        St: Stream<Item = Result<Bytes>> + Unpin + Send,
    {
        let StreamLength {
            expected: expected_plaintext_len,
            maximum: max_plaintext_len,
        } = length;
        self.validate_client_object_lock(&options)?;
        self.ensure_put_create_allowed(&key, &options)?;
        let first = super::repository::next_nonempty_stream_chunk(
            &mut stream,
            self.commit_store.options().stream_read_stall_timeout,
        )
        .await
        .map_err(|_| RepositoryError::ObjectBodyReadFailed)?;
        let Some(first) = first else {
            if expected_plaintext_len.is_some_and(|length| length != 0) {
                return Err(v2_repository_error(V2FormatError::ObjectLengthMismatch));
            }
            let _guard = self.mutation_lock.lock().await;
            let _publication_guard = self.publication_lock.write().await;
            self.ensure_accepted_anchor_matches(anchor).await?;
            let (metadata, rollback) = self.stage_put_unlocked(key, Bytes::new(), options)?;
            if let Err(error) = self.publish_pending_index_delta_locked(anchor).await {
                self.rollback_staged_puts(vec![rollback])?;
                return Err(error);
            }
            return Ok(metadata);
        };
        let first = first?;
        if first.len() as u64 > max_plaintext_len {
            return Err(RepositoryError::ObjectTooLarge);
        }
        let upload = self
            .upload_standalone_streaming(
                expected_plaintext_len,
                max_plaintext_len,
                futures_util::stream::iter([Ok(first)]).chain(stream),
                &options,
                multipart_part_size,
                Arc::new(V2StandaloneUploadCancellation::new()),
            )
            .await?;
        let plaintext_len = upload.stored.payload_layout.plaintext_len;
        self.publish_standalone_streaming(anchor, key, plaintext_len, upload, options)
            .await
    }

    /// Stages an object write without publishing the covering v2 commit.
    ///
    /// This is used by the v2 commit coordinator. Callers must publish the
    /// pending index delta before acknowledging durability.
    pub(crate) async fn stage_put(
        &self,
        key: LogicalPath,
        body: Bytes,
        options: RepositoryPutOptions,
    ) -> Result<(RepositoryObjectMetadata, V2StagedPutRollback)> {
        self.stage_put_unlocked(key, body, options)
    }

    fn stage_put_unlocked(
        &self,
        key: LogicalPath,
        body: Bytes,
        options: RepositoryPutOptions,
    ) -> Result<(RepositoryObjectMetadata, V2StagedPutRollback)> {
        let plaintext_len =
            u64::try_from(body.len()).map_err(|_| RepositoryError::CommitFailed {
                reason: "payload length does not fit in u64".to_owned(),
            })?;
        let etag = rs3_types::ObjectEtag::single(rs3_crypto::md5(&body));
        let (staged, checkpoint) = self.stage_put_metadata_sync_with_rollback(
            key,
            plaintext_len,
            options,
            Some(body),
            etag,
        )?;

        Ok((staged.metadata, V2StagedPutRollback { checkpoint }))
    }

    fn stage_put_metadata_sync_with_rollback(
        &self,
        key: LogicalPath,
        plaintext_len: u64,
        options: RepositoryPutOptions,
        pending_body: Option<Bytes>,
        etag: rs3_types::ObjectEtag,
    ) -> Result<(StagedV2Put, PendingV2Checkpoint)> {
        if options
            .expected_md5
            .is_some_and(|expected| etag.part_count().is_some() || expected != etag.digest())
        {
            return Err(RepositoryError::ContentMd5Mismatch);
        }
        self.validate_client_object_lock(&options)?;
        let retention = strongest_retention_policy(
            self.repository.options.default_retention,
            options.retention,
        );
        let requested_protection = self.effective_stored_protection(retention, options.legal_hold);
        let keyring = self.repository.keyring()?;
        let primary_blind_key = keyring.derive_primary_blind_index_key(&key)?;
        let lookup_blind_keys = keyring.derive_blind_index_keys_for_lookup(&key)?;
        let accepted = self
            .accepted
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        if pending.deltas().iter().any(|delta| {
            let IndexDelta::Upsert { entry, .. } = delta else {
                return false;
            };
            self.effective_stored_protection(entry.retention, entry.legal_hold)
                != requested_protection
        }) {
            return Err(RepositoryError::CommitFailed {
                reason: "v2 pending batch contains an incompatible protection cohort".to_owned(),
            });
        }
        let existing = lookup_blind_keys
            .iter()
            .filter_map(|candidate| {
                pending
                    .effective_head(&accepted.repository, &candidate.blind_key)
                    .live()
                    .map(|entry| (candidate.blind_key.clone(), entry.namespace_key_id.clone()))
            })
            .collect::<Vec<_>>();
        if options.create_only && !existing.is_empty() {
            return Err(RepositoryError::AlreadyExists(key));
        }

        let checksum = options
            .checksum
            .as_ref()
            .map(crate::UploadChecksum::get)
            .transpose()?;
        let sequence = pending.allocate_sequence()?;
        let material = object_material(key.as_str(), sequence);
        let manifest_id = keyring.derive_manifest_id(&material)?;
        let stale_tombstones = existing
            .into_iter()
            .filter(|(blind_key, _)| blind_key != &primary_blind_key.blind_key)
            .collect::<Vec<_>>();

        let pending_object_id = BackendObjectId::new(format!("v2-pending/{}", sequence.get()))?;
        let modified_at_ms = current_time_ms();
        let entry = NamespaceEntry {
            namespace_key_id: primary_blind_key.key_id,
            blind_key: primary_blind_key.blind_key,
            object_id: pending_object_id,
            object_version_id: None,
            payload_ref: Some(PayloadReference::Pending),
            manifest_id: manifest_id.clone(),
            content_len: plaintext_len,
            modified_at_ms,
            generation: sequence,
            retention,
            legal_hold: options.legal_hold,
        };
        let manifest = TrustedManifest {
            etag,
            checksum,
            key: key.clone(),
            content_len: plaintext_len,
            modified_at_ms,
            retention,
            legal_hold: options.legal_hold,
        };
        let sealed_manifest = seal_manifest_record(&keyring, &manifest_id, &manifest)?;

        let mut deltas = Vec::with_capacity(stale_tombstones.len().saturating_add(1));
        for (stale_blind_key, namespace_key_id) in stale_tombstones {
            deltas.push(IndexDelta::Tombstone {
                namespace_key_id,
                blind_key: stale_blind_key,
                path: key.clone(),
                generation: sequence,
            });
        }
        deltas.push(IndexDelta::Upsert {
            entry: Box::new(entry),
            prefix_tokens: Vec::new(),
            sealed_manifest: Box::new(sealed_manifest),
        });
        let payload = pending_body.map(|body| PendingV2Payload {
            manifest_id: manifest_id.clone(),
            body,
        });
        let rollback = pending.append_operation(
            deltas,
            Some((manifest_id.clone(), manifest.clone())),
            payload,
        )?;

        tracing::info!(
            target: "rs3_repository",
            operation = "v2_stage_put",
            plaintext_len,
            sequence = sequence.get(),
            result = "ok",
            "repository operation completed",
        );
        Ok((
            StagedV2Put {
                metadata: manifest.into_metadata(),
                manifest_id,
                content_len: plaintext_len,
                sequence,
            },
            rollback,
        ))
    }

    fn ensure_put_create_allowed(
        &self,
        key: &LogicalPath,
        options: &RepositoryPutOptions,
    ) -> Result<()> {
        if !options.create_only {
            return Ok(());
        }
        let keyring = self.repository.keyring()?;
        let lookup_blind_keys = keyring.derive_blind_index_keys_for_lookup(key)?;
        let accepted = self
            .accepted
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        let pending = self
            .pending
            .lock()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        if lookup_blind_keys.iter().all(|candidate| {
            pending
                .effective_head(&accepted.repository, &candidate.blind_key)
                .live()
                .is_none()
        }) {
            Ok(())
        } else {
            Err(RepositoryError::AlreadyExists(key.clone()))
        }
    }

    /// Reads trusted metadata for a client-visible object.
    pub fn head(&self, key: &LogicalPath) -> Result<RepositoryObjectMetadata> {
        Ok(self.resolve_object(key)?.metadata)
    }

    /// Resolves trusted metadata and the accepted namespace entry once.
    pub fn resolve_object(&self, key: &LogicalPath) -> Result<V2ResolvedObject> {
        let keyring = self.repository.keyring()?;
        let lookup_blind_keys = keyring.derive_blind_index_keys_for_lookup(key)?;
        let state = self
            .accepted
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        let entry = first_namespace_entry(&state.repository.namespace, &lookup_blind_keys)
            .cloned()
            .ok_or_else(|| RepositoryError::NotFound(key.clone()))?;
        let manifest = state
            .repository
            .manifests
            .get(&entry.manifest_id)
            .cloned()
            .ok_or_else(|| v2_repository_error(V2FormatError::InvalidHeaderField))?;
        Ok(V2ResolvedObject {
            metadata: manifest.into_metadata(),
            entry,
        })
    }

    /// Reads a client-visible object or byte range.
    pub async fn get_range(&self, key: &LogicalPath, range: ByteRange) -> Result<Bytes> {
        let resolved = self.resolve_object(key)?;
        self.get_resolved_range(&resolved, range).await
    }

    /// Reads a previously resolved client-visible object or byte range.
    pub async fn get_resolved_range(
        &self,
        resolved: &V2ResolvedObject,
        range: ByteRange,
    ) -> Result<Bytes> {
        let keyring = self.repository.keyring()?;
        let entry = resolved.entry.clone();
        let content_len = entry.content_len;
        if content_len == 0 {
            return match range {
                ByteRange::Full | ByteRange::Slice { offset: 0, len: 0 } => Ok(Bytes::new()),
                ByteRange::Slice { .. } => Err(StorageError::InvalidRange.into()),
            };
        }
        let Some(payload_ref) = entry.payload_ref else {
            return Err(RepositoryError::InvalidObjectFormat {
                object_id: entry.object_id,
            });
        };
        if let PayloadReference::V2Pack { carrier, record } = payload_ref {
            return self
                .read_pack_range_from_commit(
                    &keyring,
                    V2CommitPackRead {
                        commit_key: carrier.commit_key.clone(),
                        commit_version_id: carrier.commit_version_id.clone(),
                        body_digest: carrier.body_digest,
                        commit_stored_len: carrier.commit_stored_len,
                        pack_section_ordinal: carrier.pack_section_ordinal,
                        pack_offset: carrier.pack_offset,
                        length: carrier.length,
                        pack_id: carrier.pack_id,
                        attempt_id: carrier.attempt_id,
                        content_key_id: carrier.content_key_id.clone(),
                        keyring_envelope_object_id: carrier.keyring_envelope_object_id.clone(),
                        keyring_envelope_digest: carrier.keyring_envelope_digest,
                        pack_record_count: carrier.pack_record_count,
                        record_ordinal: record.record_ordinal,
                        record_offset: record.record_offset,
                        content_len,
                    },
                    range,
                )
                .await;
        }
        let Some(payload) = stream_payload_read(payload_ref, content_len) else {
            return Err(RepositoryError::InvalidObjectFormat {
                object_id: entry.object_id,
            });
        };
        let cache_key = payload.section_cache_key();
        if let Some(stored_payload) = self.cached_payload_section(&cache_key)? {
            let payload_layout = self.stream_payload_layout(&payload).await?;
            ensure_payload_layout_matches_content_len(
                &payload_layout,
                content_len,
                payload.payload_id(),
            )?;
            return open_payload_object(
                &keyring,
                payload.payload_id(),
                &payload_layout,
                stored_payload,
                range,
            );
        }

        self.read_stream_payload_range(&keyring, payload, range, cache_key)
            .await
    }

    /// Opens a bounded full-object stream for a streamed payload.
    ///
    /// Packed objects return `None` and should use the bounded pack read path.
    pub async fn get_resolved_full_stream(
        &self,
        resolved: &V2ResolvedObject,
    ) -> Result<Option<V2AuthenticatedReadBody>> {
        let entry = resolved.entry.clone();
        if entry.content_len == 0 {
            return Ok(None);
        }
        let Some(payload_ref) = entry.payload_ref else {
            return Ok(None);
        };
        let Some(payload) = stream_payload_read(payload_ref, entry.content_len) else {
            return Ok(None);
        };
        self.validated_stream_payload_start(&payload).await?;
        let header = self.stream_payload_layout(&payload).await?;
        if total_segmented_payload_len(&header)? != payload.stored_len() {
            return Err(RepositoryError::InvalidObjectFormat {
                object_id: payload.payload_id().clone(),
            });
        }
        ensure_payload_layout_matches_content_len(
            &header,
            payload.content_len(),
            payload.payload_id(),
        )?;
        let reader = self.open_stream_payload(&payload).await?;
        let body = read_stream::open_authenticated_payload_stream(
            reader,
            self.repository.keyring()?,
            payload.payload_id().clone(),
            header,
            payload.stored_digest(),
            payload.stored_len(),
        )
        .await?;
        Ok(Some(body))
    }

    async fn read_pack_range_from_commit(
        &self,
        keyring: &KeyRing,
        pack: V2CommitPackRead,
        range: ByteRange,
    ) -> Result<Bytes> {
        if pack
            .pack_offset
            .checked_add(pack.length)
            .is_none_or(|end| end > pack.commit_stored_len)
        {
            return Err(v2_repository_error(V2FormatError::SectionBounds));
        }
        let pack_stored_len = u32::try_from(pack.length)
            .map_err(|_| v2_repository_error(V2FormatError::InvalidPayloadPack))?;
        let facts = V2PayloadPackFacts::new(
            V2PayloadPackId::from_bytes(pack.pack_id),
            pack.attempt_id,
            pack.content_key_id.clone(),
            pack_stored_len,
            pack.pack_record_count,
        )
        .map_err(v2_repository_error)?;
        let record = V2PayloadPackRecordRef::new(pack.record_ordinal, pack.record_offset);
        let context = packed::repository_context_from_refs(
            &self.commit_store.options().repository_id,
            &V2KeyringEnvelopeRef {
                object_id: pack.keyring_envelope_object_id.clone(),
                digest: pack.keyring_envelope_digest,
            },
        )?;
        let requested = match range {
            ByteRange::Full => 0..pack.content_len,
            ByteRange::Slice { offset, len } => {
                if len == 0 {
                    if offset <= pack.content_len {
                        return Ok(Bytes::new());
                    }
                    return Err(StorageError::InvalidRange.into());
                }
                let end = offset
                    .checked_add(len)
                    .filter(|end| *end <= pack.content_len)
                    .ok_or(StorageError::InvalidRange)?;
                offset..end
            }
        };
        let span = plan_v2_payload_pack_record_range(&facts, &record, pack.content_len, requested)
            .map_err(v2_repository_error)?;
        let payload_cache_ref = pack_payload_cache_ref(&pack, &context)?;
        let start_segment = usize::try_from(span.start_segment)
            .map_err(|_| v2_repository_error(V2FormatError::InvalidPayloadPack))?;
        let segment_count = usize::try_from(span.segment_count)
            .map_err(|_| v2_repository_error(V2FormatError::InvalidPayloadPack))?;
        if let Some(segments) = self.repository.cached_decrypted_segment_span(
            &payload_cache_ref,
            start_segment,
            segment_count,
        )? {
            return open_v2_payload_pack_cached_record_span(
                &facts,
                &record,
                pack.content_len,
                &span,
                &segments,
            )
            .map_err(v2_repository_error);
        }
        let fill_lock_index = payload_fill_lock_index(
            &payload_cache_ref.object_id,
            usize::try_from(span.start_segment)
                .map_err(|_| v2_repository_error(V2FormatError::InvalidPayloadPack))?,
        );
        let _fill_guard = self.payload_segment_fill_locks[fill_lock_index]
            .lock()
            .await;
        if let Some(segments) = self.repository.cached_decrypted_segment_span(
            &payload_cache_ref,
            start_segment,
            segment_count,
        )? {
            return open_v2_payload_pack_cached_record_span(
                &facts,
                &record,
                pack.content_len,
                &span,
                &segments,
            )
            .map_err(v2_repository_error);
        }
        let ciphertext = self
            .commit_store
            .read_commit_range_at(
                &pack.commit_key,
                pack.commit_version_id.as_ref(),
                ByteRange::Slice {
                    offset: pack
                        .pack_offset
                        .checked_add(span.offset)
                        .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))?,
                    len: span.stored_len,
                },
            )
            .await
            .map_err(v2_repository_error)?;
        let record_context = V2PayloadPackRecordContext::new(
            &context,
            &pack.commit_key,
            pack.pack_section_ordinal,
            &facts,
            &record,
            pack.content_len,
        )
        .map_err(v2_repository_error)?;
        let opened = open_v2_payload_pack_record_span_with_segments(
            keyring,
            &record_context,
            &span,
            &ciphertext,
        )
        .map_err(v2_repository_error)?;
        let segments = opened
            .segments
            .iter()
            .map(|(ordinal, plaintext)| {
                usize::try_from(*ordinal)
                    .map(|ordinal| (ordinal, plaintext.clone()))
                    .map_err(|_| v2_repository_error(V2FormatError::InvalidPayloadPack))
            })
            .collect::<Result<Vec<_>>>()?;
        self.repository
            .cache_decrypted_segment_span(&payload_cache_ref, &segments)?;
        Ok(opened.plaintext)
    }

    async fn read_stream_payload_range(
        &self,
        keyring: &KeyRing,
        payload: V2StandalonePayloadRead,
        range: ByteRange,
        cache_key: V2PayloadSectionCacheKey,
    ) -> Result<Bytes> {
        let payload_start = self.validated_stream_payload_start(&payload).await?;

        if range == ByteRange::Full {
            let body = self.read_stream_payload(&payload).await?;
            if digest_v2_section(&body) != payload.stored_digest() {
                return Err(RepositoryError::InvalidObjectFormat {
                    object_id: payload.payload_id().clone(),
                });
            }
            let layout = self.stream_payload_layout(&payload).await?;
            let plaintext =
                open_payload_object(keyring, payload.payload_id(), &layout, body.clone(), range)?;
            if u64::try_from(plaintext.len()).ok() != Some(payload.content_len()) {
                return Err(RepositoryError::InvalidObjectFormat {
                    object_id: payload.payload_id().clone(),
                });
            }
            self.cache_payload_section(cache_key, body)?;
            return Ok(plaintext);
        }

        let payload_layout = self.stream_payload_layout(&payload).await?;
        if total_segmented_payload_len(&payload_layout)? != payload.stored_len() {
            return Err(RepositoryError::InvalidObjectFormat {
                object_id: payload.payload_id().clone(),
            });
        }
        ensure_payload_layout_matches_content_len(
            &payload_layout,
            payload.content_len(),
            payload.payload_id(),
        )?;
        let span = segmented_ciphertext_span(&payload_layout, range)?;
        let keyring_envelope_ref = V2KeyringEnvelopeRef {
            object_id: payload.keyring_envelope_object_id().clone(),
            digest: payload.keyring_envelope_digest(),
        };
        let repository_keyring_context = packed::repository_context_from_refs(
            &self.commit_store.options().repository_id,
            &keyring_envelope_ref,
        )?;
        let payload_layout_ref = payload_layout.reference().clone();
        let carrier = payload.cache_identity(payload_start)?;
        let payload_cache_ref = V2StreamPayloadCacheIdentity {
            repository_keyring_context: &repository_keyring_context,
            carrier,
            payload_id: payload.payload_id(),
            payload_layout: &payload_layout_ref,
            content_len: payload.content_len(),
        }
        .cache_ref()
        .map_err(v2_repository_error)?;
        if let Some(plaintext) = self.repository.open_cached_decrypted_segments(
            DecryptedSegmentIdentity {
                cache_ref: &payload_cache_ref,
                payload_id: payload.payload_id(),
            },
            &payload_layout,
            range,
        )? {
            return Ok(plaintext);
        }
        let fill_lock_index = payload_fill_lock_index(payload.payload_id(), span.start_segment);
        let _fill_guard = self.payload_segment_fill_locks[fill_lock_index]
            .lock()
            .await;
        if let Some(plaintext) = self.repository.open_cached_decrypted_segments(
            DecryptedSegmentIdentity {
                cache_ref: &payload_cache_ref,
                payload_id: payload.payload_id(),
            },
            &payload_layout,
            range,
        )? {
            return Ok(plaintext);
        }
        let ciphertext = if span.len == 0 {
            Bytes::new()
        } else {
            let offset = payload_start
                .checked_add(span.offset)
                .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))?;
            self.read_stream_payload_range_at(&payload, offset, span.len)
                .await?
        };
        self.repository.open_and_cache_decrypted_segments(
            keyring,
            DecryptedSegmentIdentity {
                cache_ref: &payload_cache_ref,
                payload_id: payload.payload_id(),
            },
            &payload_layout,
            range,
            span,
            ciphertext,
        )
    }

    async fn validated_stream_payload_start(
        &self,
        payload: &V2StandalonePayloadRead,
    ) -> Result<u64> {
        validate_v2_standalone_object(&payload.object_id, payload.stored_len)
            .map_err(v2_repository_error)?;
        if self.commit_store.provider_profile()
            == super::provider::V2ProviderProfile::RetainedVersionObjectLock
            && payload.version_id.is_none()
        {
            return Err(v2_repository_error(V2FormatError::InvalidHeaderField));
        }
        let header = self.stream_payload_layout(payload).await?;
        if header.carrier_id
            != super::standalone::standalone_carrier_id(&payload.object_id)
                .map_err(v2_repository_error)?
            || total_segmented_payload_len(&header)? != payload.stored_len
        {
            return Err(v2_repository_error(V2FormatError::InvalidHeaderField));
        }
        ensure_payload_layout_matches_content_len(
            &header,
            payload.content_len,
            &payload.object_id,
        )?;
        Ok(0)
    }

    async fn stream_payload_layout(
        &self,
        payload: &V2StandalonePayloadRead,
    ) -> Result<SegmentedPayloadLayout> {
        let context = packed::repository_context_from_refs(
            &self.commit_store.options().repository_id,
            &V2KeyringEnvelopeRef {
                object_id: payload.keyring_envelope_object_id.clone(),
                digest: payload.keyring_envelope_digest,
            },
        )?;
        SegmentedPayloadLayout::new(payload.payload_layout.clone(), context)
    }

    async fn read_stream_payload(&self, payload: &V2StandalonePayloadRead) -> Result<Bytes> {
        let body = self
            .commit_store
            .store()
            .get_range_at(
                &payload.object_id,
                payload.version_id.as_ref(),
                ByteRange::Full,
            )
            .await
            .map_err(|_| v2_repository_error(V2FormatError::StorageOperationFailed))?;
        if u64::try_from(body.len()).ok() != Some(payload.stored_len) {
            return Err(v2_repository_error(V2FormatError::TruncatedBody));
        }
        Ok(body)
    }

    async fn read_stream_payload_range_at(
        &self,
        payload: &V2StandalonePayloadRead,
        offset: u64,
        len: u64,
    ) -> Result<Bytes> {
        let body = self
            .commit_store
            .store()
            .get_range_at(
                &payload.object_id,
                payload.version_id.as_ref(),
                ByteRange::Slice { offset, len },
            )
            .await
            .map_err(|_| v2_repository_error(V2FormatError::StorageOperationFailed))?;
        if u64::try_from(body.len()).ok() != Some(len) {
            return Err(v2_repository_error(V2FormatError::TruncatedBody));
        }
        Ok(body)
    }

    async fn open_stream_payload(
        &self,
        payload: &V2StandalonePayloadRead,
    ) -> Result<Box<dyn rs3_storage::BlobRead>> {
        let reader = self
            .commit_store
            .store()
            .open_range_at(
                &payload.object_id,
                payload.version_id.as_ref(),
                ByteRange::Full,
            )
            .await
            .map_err(|_| v2_repository_error(V2FormatError::StorageOperationFailed))?;
        if reader.exact_len() != payload.stored_len() {
            return Err(v2_repository_error(V2FormatError::TruncatedBody));
        }
        Ok(reader)
    }

    /// Lists client-visible entries for a prefix.
    pub fn list(&self, prefix: &str) -> Result<Vec<RepositoryListEntry>> {
        self.list_page(prefix, None, usize::MAX)
    }

    /// Lists up to `limit + 1` client-visible entries after `start_after`.
    pub fn list_page(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<RepositoryListEntry>> {
        let state = self
            .accepted
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        Ok(state.repository.list_page(prefix, start_after, limit))
    }

    /// Deletes a client-visible object after the tombstone commit is accepted.
    pub async fn delete_committed<A>(&self, anchor: &A, key: LogicalPath) -> Result<DeleteOutcome>
    where
        A: V2CommitAnchor,
    {
        let _mutation_lease = self.claim_direct_mutation()?;
        self.delete_committed_inner(anchor, key).await
    }

    pub(super) async fn delete_committed_coordinated<A>(
        &self,
        mutation: V2CoordinatedMutation<'_, A>,
        key: LogicalPath,
    ) -> Result<DeleteOutcome>
    where
        A: V2CommitAnchor,
    {
        self.validate_coordinator_lease(mutation.lease)?;
        self.delete_committed_inner(mutation.anchor, key).await
    }

    async fn delete_committed_inner<A>(&self, anchor: &A, key: LogicalPath) -> Result<DeleteOutcome>
    where
        A: V2CommitAnchor,
    {
        let _guard = self.mutation_lock.lock().await;
        let _publication_guard = self.publication_lock.write().await;
        self.ensure_accepted_anchor_matches(anchor).await?;
        let rollback = self.stage_delete(&key)?;
        if let Err(error) = self.publish_pending_index_delta_locked(anchor).await {
            self.rollback_state_mutations(vec![rollback])?;
            return Err(error);
        }
        Ok(DeleteOutcome {
            physical: PhysicalDeleteOutcome::Retained,
        })
    }

    /// Rejects legal-hold mutation until dependency-wide hold lifecycle exists.
    pub async fn set_legal_hold_committed<A>(
        &self,
        anchor: &A,
        key: LogicalPath,
        status: LegalHoldStatus,
    ) -> Result<RepositoryObjectMetadata>
    where
        A: V2CommitAnchor,
    {
        let _ = (anchor, key, status);
        Err(StorageError::LegalHoldUnsupported.into())
    }

    pub(super) async fn set_legal_hold_committed_coordinated<A>(
        &self,
        mutation: V2CoordinatedMutation<'_, A>,
        key: LogicalPath,
        status: LegalHoldStatus,
    ) -> Result<RepositoryObjectMetadata>
    where
        A: V2CommitAnchor,
    {
        self.validate_coordinator_lease(mutation.lease)?;
        let _ = (mutation.anchor, key, status);
        Err(StorageError::LegalHoldUnsupported.into())
    }

    fn stage_delete(&self, key: &LogicalPath) -> Result<PendingV2Checkpoint> {
        let keyring = self.repository.keyring()?;
        let lookup_blind_keys = keyring.derive_blind_index_keys_for_lookup(key)?;
        let accepted = self
            .accepted
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        let live = lookup_blind_keys
            .iter()
            .filter_map(|candidate| {
                pending
                    .effective_head(&accepted.repository, &candidate.blind_key)
                    .live()
                    .map(|entry| (candidate.blind_key.clone(), entry.namespace_key_id.clone()))
            })
            .collect::<Vec<_>>();
        if live.is_empty() {
            return Err(RepositoryError::NotFound(key.clone()));
        }
        let sequence = pending.allocate_sequence()?;
        let deltas = live
            .into_iter()
            .map(|(blind_key, namespace_key_id)| IndexDelta::Tombstone {
                namespace_key_id,
                blind_key,
                path: key.clone(),
                generation: sequence,
            })
            .collect();
        pending.append_operation(deltas, None, None)
    }

    pub(crate) fn rollback_staged_puts(&self, rollbacks: Vec<V2StagedPutRollback>) -> Result<()> {
        #[cfg(test)]
        if self.fail_next_restore.swap(false, Ordering::SeqCst) {
            return Err(RepositoryError::StatePoisoned);
        }

        let mut pending = self
            .pending
            .lock()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        for rollback in rollbacks.into_iter().rev() {
            pending.rollback(rollback.checkpoint)?;
        }
        Ok(())
    }

    fn rollback_state_mutations(&self, rollbacks: Vec<PendingV2Checkpoint>) -> Result<()> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        for rollback in rollbacks.into_iter().rev() {
            pending.rollback(rollback)?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn clear_trusted_manifests_for_tests(&self) -> Result<()> {
        self.accepted
            .write()
            .map_err(|_| RepositoryError::StatePoisoned)?
            .repository
            .manifests
            .clear();
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn fail_next_restore_for_tests(&self) {
        self.fail_next_restore.store(true, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn fail_next_local_install_for_tests(&self) {
        self.fail_next_local_install.store(true, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn pending_operation_count_for_tests(&self) -> Result<usize> {
        self.pending
            .lock()
            .map(|pending| pending.len())
            .map_err(|_| RepositoryError::StatePoisoned)
    }

    #[cfg(test)]
    pub(crate) fn fill_accepted_run_catalog_for_tests(&self) -> Result<()> {
        self.resize_accepted_run_catalog_for_tests(V2_INDEX_ROOT_MAX_RUNS)
    }

    #[cfg(test)]
    pub(crate) fn resize_accepted_run_catalog_for_tests(&self, count: usize) -> Result<()> {
        let mut runs = self
            .accepted
            .write()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        let run = runs
            .runs
            .last()
            .cloned()
            .ok_or(RepositoryError::StatePoisoned)?;
        runs.runs.resize(count, run);
        Ok(())
    }

    /// Returns the path-redacted number of active authenticated index runs.
    pub fn active_index_run_count(&self) -> Result<usize> {
        self.accepted
            .read()
            .map(|accepted| accepted.runs.len())
            .map_err(|_| RepositoryError::StatePoisoned)
    }

    /// Returns the path-redacted number of uncompacted foreground index runs.
    pub(crate) fn active_level_zero_index_run_count(&self) -> Result<usize> {
        self.accepted
            .read()
            .map(|accepted| accepted.runs.iter().filter(|run| run.level == 0).count())
            .map_err(|_| RepositoryError::StatePoisoned)
    }

    fn publication_error(&self, error: V2FormatError) -> RepositoryError {
        if error == V2FormatError::AnchorReconciliationRequired {
            self.mark_local_recovery_required();
            RepositoryError::AcceptedRecoveryRequired
        } else {
            v2_repository_error(error)
        }
    }

    pub(crate) fn freeze_pending_publication(&self) -> Result<V2PendingPublication> {
        let snapshot = self
            .pending
            .lock()
            .map_err(|_| RepositoryError::StatePoisoned)?
            .freeze()?;
        Ok(V2PendingPublication { snapshot })
    }

    pub(crate) async fn publish_frozen_pending_index_delta<A>(
        &self,
        anchor: &A,
        publication: V2PendingPublication,
    ) -> Result<Option<V2StoredCommit>>
    where
        A: V2CommitAnchor,
    {
        let _publication_guard = self.publication_lock.write().await;
        self.publish_pending_snapshot(anchor, publication.snapshot)
            .await
    }

    pub(crate) async fn publish_pending_index_delta<A>(
        &self,
        anchor: &A,
    ) -> Result<Option<V2StoredCommit>>
    where
        A: V2CommitAnchor,
    {
        let _publication_guard = self.publication_lock.write().await;
        self.publish_pending_index_delta_locked(anchor).await
    }

    async fn publish_pending_index_delta_locked<A>(
        &self,
        anchor: &A,
    ) -> Result<Option<V2StoredCommit>>
    where
        A: V2CommitAnchor,
    {
        self.publish_pending_snapshot(anchor, self.pending_snapshot()?)
            .await
    }

    async fn publish_pending_snapshot<A>(
        &self,
        anchor: &A,
        mut pending: PendingV2Snapshot,
    ) -> Result<Option<V2StoredCommit>>
    where
        A: V2CommitAnchor,
    {
        let Some(sequence) = pending.commit_sequence() else {
            return Ok(None);
        };
        let base_anchor = self.ensure_accepted_anchor_matches(anchor).await?;
        let mut accepted_pack_locations = None;
        let mut accepted_run = None;
        let temporary_anchor = V2MemoryAnchor::with_state(base_anchor.clone());
        let uploaded = self
            .commit_store
            .write_child_commit_with(&temporary_anchor, |commit_key| {
                let packed = self
                    .pending_packed_sections_for_commit(commit_key, &pending)
                    .map_err(|_| V2FormatError::InvalidHeaderField)?
                    .ok_or(V2FormatError::ObjectTooLarge)?;
                accepted_pack_locations = Some(packed.locations);
                accepted_run = Some(packed.run);
                Ok(V2CommitWrite::delta(packed.sections)
                    .with_retention(packed.retention)
                    .with_legal_hold(packed.legal_hold))
            })
            .await
            .map_err(v2_repository_error)?;
        let accepted_run = accepted_run.map(|run| self.accepted_run_ref(run, &uploaded));
        if let Some(run) = accepted_run.as_ref() {
            let accepted = self
                .accepted
                .read()
                .map_err(|_| RepositoryError::StatePoisoned)?;
            if accepted.runs.len() >= V2_INDEX_ROOT_MAX_RUNS {
                return Err(v2_repository_error(V2FormatError::IndexRootLimitExceeded));
            }
            if accepted
                .runs
                .last()
                .is_some_and(|previous| previous.maximum_generation >= run.minimum_generation)
            {
                return Err(v2_repository_error(V2FormatError::InvalidIndexRun));
            }
        }
        let locations = accepted_pack_locations
            .as_ref()
            .ok_or_else(|| v2_repository_error(V2FormatError::InvalidHeaderField))?;
        self.resolve_pending_pack_refs(&mut pending, &uploaded, locations)?;
        let install = self.prepare_pending_install(&pending, sequence, accepted_run)?;
        let stored = self
            .commit_store
            .adopt_verified_unanchored_child(anchor, &base_anchor, &uploaded)
            .await
            .map_err(|error| self.publication_error(error))?;
        if let Err(error) = self.install_pending_commit(install, stored.anchor_state.clone()) {
            self.mark_local_recovery_required();
            tracing::error!(
                target: "rs3_repository",
                operation = "v2_install_accepted_commit",
                error = %error,
                "v2 anchor advanced but local state installation failed; restart is required",
            );
            return Err(RepositoryError::AcceptedRecoveryRequired);
        }
        Ok(Some(stored))
    }

    fn accepted_run_ref(
        &self,
        run: packed::PendingV2IndexRunFacts,
        uploaded: &V2StoredCommit,
    ) -> V2IndexRootRunRef {
        V2IndexRootRunRef {
            run_id: run.run_id,
            run_sequence: run.run_sequence,
            minimum_generation: run.minimum_generation,
            maximum_generation: run.maximum_generation,
            mutation_count: run.mutation_count,
            frame_count: run.frame_count,
            level: 0,
            compaction_generation: 0,
            namespace_bounds: run.namespace_bounds,
            listing_bounds: run.listing_bounds,
            keyring_envelope_ref: run.keyring_envelope_ref,
            location: V2EmbeddedIndexRunLocation {
                commit_key: uploaded.anchor_state.commit_key.clone(),
                version_id: uploaded.version_id.clone(),
                commit_stored_len: uploaded.object_len,
                commit_body_digest: uploaded.anchor_state.body_digest,
                sections_start: uploaded.sections_start,
                section_ordinal: run.section_ordinal,
                section_offset: run.section_offset,
                section_len: run.section_len,
                section_digest: run.section_digest,
            },
        }
    }

    fn validate_accepted_run_append(&self, run: &V2IndexRootRunRef) -> Result<()> {
        let accepted = self
            .accepted
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        if accepted.runs.len() >= V2_INDEX_ROOT_MAX_RUNS {
            return Err(v2_repository_error(V2FormatError::IndexRootLimitExceeded));
        }
        if accepted
            .runs
            .last()
            .is_some_and(|previous| previous.maximum_generation >= run.minimum_generation)
        {
            return Err(v2_repository_error(V2FormatError::InvalidIndexRun));
        }
        Ok(())
    }

    async fn ensure_accepted_anchor_matches<A>(
        &self,
        anchor: &A,
    ) -> Result<super::repository::V2AnchorState>
    where
        A: V2CommitAnchor,
    {
        let current = anchor
            .read_v2()
            .await
            .map_err(v2_repository_error)?
            .ok_or_else(|| v2_repository_error(V2FormatError::MissingAnchor))?;
        if self
            .accepted
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?
            .anchor
            .as_ref()
            != Some(&current)
        {
            return Err(v2_repository_error(V2FormatError::StaleAnchor));
        }
        Ok(current)
    }

    fn pending_snapshot(&self) -> Result<PendingV2Snapshot> {
        self.pending
            .lock()
            .map_err(|_| RepositoryError::StatePoisoned)
            .map(|pending| pending.snapshot())
    }

    fn prepare_pending_install(
        &self,
        pending: &PendingV2Snapshot,
        sequence: Sequence,
        run: Option<V2IndexRootRunRef>,
    ) -> Result<PendingV2Install> {
        if pending.commit_sequence() != Some(sequence) {
            return Err(v2_repository_error(V2FormatError::InvalidHeaderField));
        }
        let manifests = pending
            .manifests()
            .iter()
            .map(|(manifest_id, manifest)| (manifest_id, manifest))
            .collect::<BTreeMap<_, _>>();
        let mut mutations = Vec::with_capacity(pending.deltas().len());
        for delta in pending.deltas() {
            match delta {
                IndexDelta::Upsert { entry, .. } => {
                    let manifest = manifests
                        .get(&entry.manifest_id)
                        .ok_or_else(|| v2_repository_error(V2FormatError::InvalidHeaderField))?;
                    if matches!(entry.payload_ref, Some(PayloadReference::Pending))
                        || entry.generation > sequence
                    {
                        return Err(v2_repository_error(V2FormatError::InvalidHeaderField));
                    }
                    mutations.push(PendingV2InstallMutation::Upsert {
                        entry: Box::new((**entry).clone()),
                        manifest: (*manifest).clone(),
                    });
                }
                IndexDelta::Tombstone { blind_key, .. } => {
                    mutations.push(PendingV2InstallMutation::Tombstone {
                        blind_key: blind_key.clone(),
                    })
                }
            }
        }
        let accepted = self
            .accepted
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        if sequence <= accepted.repository.next_sequence {
            return Err(v2_repository_error(V2FormatError::InvalidHeaderField));
        }
        let completion_receipts = if let Some(receipt) = &pending.completion_receipt {
            let mut receipts = accepted.repository.completion_receipts.clone();
            receipts
                .insert(receipt.clone())
                .map_err(|_| v2_repository_error(V2FormatError::InvalidIndexRun))?;
            Some((receipt.commit_sequence, receipts))
        } else {
            None
        };
        drop(accepted);
        self.pending
            .lock()
            .map_err(|_| RepositoryError::StatePoisoned)?
            .validate_snapshot(pending)?;
        Ok(PendingV2Install {
            completion_receipts,
            sequence,
            mutations,
            run,
        })
    }

    fn install_pending_commit(
        &self,
        install: PendingV2Install,
        anchor: super::repository::V2AnchorState,
    ) -> Result<()> {
        #[cfg(test)]
        if self.fail_next_local_install.swap(false, Ordering::SeqCst) {
            return Err(RepositoryError::StatePoisoned);
        }
        let mut accepted = self
            .accepted
            .write()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        if install
            .completion_receipts
            .as_ref()
            .is_some_and(|(sequence, _)| *sequence != anchor.sequence)
        {
            return Err(v2_repository_error(V2FormatError::InvalidIndexRun));
        }
        // A frozen prefix may have bounded successors appended after pre-CAS
        // validation. Consume only that prefix while both state locks are held.
        pending.finish_publication()?;
        for mutation in install.mutations {
            match mutation {
                PendingV2InstallMutation::Upsert { entry, manifest } => {
                    accepted
                        .repository
                        .manifests
                        .insert(entry.manifest_id.clone(), manifest);
                    accepted
                        .repository
                        .upsert_namespace_entry_without_prefixes(*entry);
                }
                PendingV2InstallMutation::Tombstone { blind_key } => {
                    accepted.repository.remove_namespace_entry(blind_key)
                }
            }
        }
        if let Some((_, receipts)) = install.completion_receipts {
            accepted.repository.completion_receipts = receipts;
        }
        accepted.repository.next_sequence = install.sequence;
        if let Some(run) = install.run {
            accepted.runs.push(run);
        }
        accepted.anchor = Some(anchor);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn shorten_accepted_payload_section_for_tests(
        &self,
        content_len: u64,
    ) -> Result<()> {
        let mut accepted = self
            .accepted
            .write()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        let state = &mut accepted.repository;
        let Some(mut entry) = state
            .namespace
            .live_entries()
            .find(|entry| entry.content_len == content_len)
            .cloned()
        else {
            return Err(RepositoryError::StatePoisoned);
        };
        let prefix_tokens = state
            .namespace
            .prefix_tokens(&entry.blind_key)
            .cloned()
            .collect();
        match entry.payload_ref.as_mut() {
            Some(PayloadReference::V2Pack { carrier, .. }) => {
                let carrier = Arc::make_mut(carrier);
                carrier.length = carrier.length.saturating_sub(1);
            }
            _ => {
                return Err(RepositoryError::InvalidObjectFormat {
                    object_id: entry.object_id,
                });
            }
        }
        state.replace_namespace_entry(entry, prefix_tokens);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn shorten_accepted_content_len_for_tests(&self, content_len: u64) -> Result<()> {
        let mut accepted = self
            .accepted
            .write()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        let state = &mut accepted.repository;
        let Some(mut entry) = state
            .namespace
            .live_entries()
            .find(|entry| entry.content_len == content_len)
            .cloned()
        else {
            return Err(RepositoryError::StatePoisoned);
        };
        let prefix_tokens = state
            .namespace
            .prefix_tokens(&entry.blind_key)
            .cloned()
            .collect();
        entry.content_len = entry.content_len.saturating_sub(1);
        state.replace_namespace_entry(entry, prefix_tokens);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn accepted_pack_carrier_counts_for_tests(&self) -> Result<(usize, usize)> {
        let accepted = self
            .accepted
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        let mut total = 0_usize;
        let mut unique = Vec::<Arc<rs3_index::V2PackCarrierReference>>::new();
        for entry in accepted.repository.namespace.live_entries() {
            let Some(PayloadReference::V2Pack { carrier, .. }) = entry.payload_ref.as_ref() else {
                continue;
            };
            total = total.saturating_add(1);
            if !unique
                .iter()
                .any(|candidate| Arc::ptr_eq(candidate, carrier))
            {
                unique.push(Arc::clone(carrier));
            }
        }
        Ok((total, unique.len()))
    }

    fn pending_index_delta_sequence(&self) -> Result<Option<Sequence>> {
        self.pending
            .lock()
            .map_err(|_| RepositoryError::StatePoisoned)
            .map(|pending| pending.snapshot().commit_sequence())
    }

    fn payload_segment_size_for_object(&self, plaintext_len: usize) -> usize {
        effective_payload_segment_size(
            plaintext_len,
            self.repository.options.payload_segment_size,
            self.repository.options.adaptive_payload_segment_size,
        )
    }

    fn payload_segment_size_for_object_len(&self, plaintext_len: u64) -> Result<usize> {
        let plaintext_len =
            usize::try_from(plaintext_len).map_err(|_| RepositoryError::CommitFailed {
                reason: "payload length does not fit in usize".to_owned(),
            })?;
        Ok(self.payload_segment_size_for_object(plaintext_len))
    }

    fn cached_payload_section(&self, key: &V2PayloadSectionCacheKey) -> Result<Option<Bytes>> {
        let payload = self
            .payload_sections
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?
            .peek(key);
        if payload.is_some()
            && let Ok(mut cache) = self.payload_sections.try_write()
        {
            cache.touch(key);
        }
        Ok(payload)
    }

    fn cache_payload_section(&self, key: V2PayloadSectionCacheKey, payload: Bytes) -> Result<()> {
        let mut cache = self
            .payload_sections
            .write()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        cache.insert(key, payload);
        Ok(())
    }

    async fn apply_replay_commit_sections(
        &self,
        state: &mut RepositoryState,
        commit: &V2ReplayCommit,
    ) -> Result<Vec<V2IndexRootRunRef>> {
        let mut accepted_runs = Vec::new();
        for (index, section) in commit.parsed_header.header.section_index.iter().enumerate() {
            if section.flags & V2_SECTION_FLAG_COMPRESSED != 0 {
                return Err(v2_repository_error(V2FormatError::UnsupportedSection));
            }
            match section.section_type {
                V2SectionType::PayloadPack => {}
                V2SectionType::IndexRun => {
                    let section_bytes = replay_section_bytes(commit, index)?;
                    let keyring = self.repository.keyring()?;
                    accepted_runs.push(packed::apply_packed_index_run(
                        keyring.as_ref(),
                        &self.commit_store.options().repository_id,
                        state,
                        packed::V2PackedIndexRunReplay {
                            parsed_header: &commit.parsed_header,
                            version_id: commit.version_id.as_ref(),
                            object_len: commit.object_len,
                            section_ordinal: u32::try_from(index)
                                .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?,
                            stored_run: section_bytes,
                            level: 0,
                            compaction_generation: 0,
                            provider_profile: self.commit_store.provider_profile(),
                        },
                    )?);
                }
                V2SectionType::IndexRoot => {
                    let section_bytes = replay_section_bytes(commit, index)?;
                    accepted_runs = self
                        .commit_store
                        .apply_index_root_to_state(
                            state,
                            commit,
                            u32::try_from(index)
                                .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?,
                            section_bytes,
                            self.commit_store.options().replay_limits,
                        )
                        .await
                        .map_err(v2_repository_error)?
                        .runs;
                }
                _ => return Err(v2_repository_error(V2FormatError::UnsupportedSection)),
            }
        }
        Ok(accepted_runs)
    }
}

impl<S> V2Repository<S> {
    pub(super) fn claim_commit_coordinator(&self) -> Result<Arc<V2CoordinatorLease>> {
        self.ensure_local_state_ready()?;
        self.mutation_owner
            .compare_exchange(
                V2_MUTATION_OWNER_IDLE,
                V2_MUTATION_OWNER_COORDINATOR,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| RepositoryError::CommitFailed {
                reason: "v2 repository already has an active mutation owner".to_owned(),
            })?;
        Ok(Arc::new(V2CoordinatorLease {
            owner: Arc::clone(&self.mutation_owner),
        }))
    }

    fn claim_direct_mutation(&self) -> Result<V2DirectMutationLease> {
        self.ensure_local_state_ready()?;
        self.mutation_owner
            .compare_exchange(
                V2_MUTATION_OWNER_IDLE,
                V2_MUTATION_OWNER_DIRECT,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| RepositoryError::CommitFailed {
                reason: "v2 repository mutation is owned by the active commit coordinator"
                    .to_owned(),
            })?;
        Ok(V2DirectMutationLease {
            owner: Arc::clone(&self.mutation_owner),
        })
    }

    fn validate_coordinator_lease(&self, lease: &V2CoordinatorLease) -> Result<()> {
        self.ensure_local_state_ready()?;
        if Arc::ptr_eq(&self.mutation_owner, &lease.owner)
            && self.mutation_owner.load(Ordering::Acquire) == V2_MUTATION_OWNER_COORDINATOR
        {
            return Ok(());
        }
        Err(RepositoryError::CommitFailed {
            reason: "v2 commit coordinator does not own this repository".to_owned(),
        })
    }

    pub(super) fn local_recovery_required(&self) -> bool {
        self.recovery_required.load(Ordering::Acquire)
    }

    fn mark_local_recovery_required(&self) {
        self.recovery_required.store(true, Ordering::Release);
    }

    fn ensure_local_state_ready(&self) -> Result<()> {
        if self.local_recovery_required() {
            return Err(RepositoryError::AcceptedRecoveryRequired);
        }
        Ok(())
    }
}

fn payload_fill_lock_index(payload_id: &BackendObjectId, start_segment: usize) -> usize {
    let mut digest = Sha256Hasher::new();
    digest.update(payload_id.as_str().as_bytes());
    digest.update((start_segment as u64).to_be_bytes());
    let digest = digest.finalize();
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    (u64::from_be_bytes(prefix) % V2_PAYLOAD_FILL_LOCK_STRIPES as u64) as usize
}

#[derive(Clone, Debug)]
struct V2StandalonePayloadRead {
    object_id: BackendObjectId,
    version_id: Option<BackendVersionId>,
    object_digest: [u8; 32],
    stored_len: u64,
    keyring_envelope_object_id: BackendObjectId,
    keyring_envelope_digest: [u8; 32],
    payload_layout: PayloadLayout,
    content_len: u64,
}

impl V2StandalonePayloadRead {
    fn payload_id(&self) -> &BackendObjectId {
        &self.object_id
    }
    const fn content_len(&self) -> u64 {
        self.content_len
    }
    const fn stored_len(&self) -> u64 {
        self.stored_len
    }
    const fn stored_digest(&self) -> [u8; 32] {
        self.object_digest
    }

    fn keyring_envelope_object_id(&self) -> &BackendObjectId {
        &self.keyring_envelope_object_id
    }
    const fn keyring_envelope_digest(&self) -> [u8; 32] {
        self.keyring_envelope_digest
    }
    fn section_cache_key(&self) -> V2PayloadSectionCacheKey {
        V2PayloadSectionCacheKey {
            carrier: V2PayloadSectionCarrierCacheKey::Standalone {
                object_id: self.object_id.clone(),
                version_id: self.version_id.clone(),
                digest: self.object_digest,
            },
            payload_id: self.object_id.clone(),
            offset: 0,
            length: self.stored_len,
        }
    }
    fn cache_identity(
        &self,
        _payload_start: u64,
    ) -> Result<V2StreamPayloadCarrierCacheIdentity<'_>> {
        Ok(V2StreamPayloadCarrierCacheIdentity::Standalone {
            object_id: &self.object_id,
            version_id: self.version_id.as_ref(),
            object_digest: self.object_digest,
            stored_len: self.stored_len,
        })
    }
}

fn stream_payload_read(
    payload_ref: PayloadReference,
    content_len: u64,
) -> Option<V2StandalonePayloadRead> {
    match payload_ref {
        PayloadReference::V2StandaloneStream { carrier } => {
            let V2StandaloneStreamCarrierReference {
                object_id,
                version_id,
                object_digest,
                stored_len,
                keyring_envelope_object_id,
                keyring_envelope_digest,
                payload_layout,
            } = carrier.as_ref().clone();
            Some(V2StandalonePayloadRead {
                object_id,
                version_id,
                object_digest,
                stored_len,
                keyring_envelope_object_id,
                keyring_envelope_digest,
                payload_layout,
                content_len,
            })
        }
        _ => None,
    }
}

#[derive(Clone, Debug)]
struct V2CommitPackRead {
    commit_key: BackendObjectId,
    commit_version_id: Option<BackendVersionId>,
    body_digest: [u8; 32],
    commit_stored_len: u64,
    pack_section_ordinal: u32,
    pack_offset: u64,
    length: u64,
    pack_id: [u8; 32],
    attempt_id: rs3_types::PayloadAttemptId,
    content_key_id: rs3_types::KeyId,
    keyring_envelope_object_id: BackendObjectId,
    keyring_envelope_digest: [u8; 32],
    pack_record_count: u32,
    record_ordinal: u32,
    record_offset: u32,
    content_len: u64,
}

fn pack_payload_cache_ref(
    pack: &V2CommitPackRead,
    repository_context: &[u8],
) -> Result<BackendObjectRef> {
    let mut digest = Sha256Hasher::new();
    digest.update(b"rs3:v02-pack-segment-cache:v2\n");
    update_cache_digest_field(&mut digest, repository_context)?;
    update_cache_digest_field(&mut digest, pack.commit_key.as_str().as_bytes())?;
    digest.update(pack.body_digest);
    digest.update(pack.commit_stored_len.to_be_bytes());
    digest.update(pack.pack_section_ordinal.to_be_bytes());
    digest.update(pack.pack_offset.to_be_bytes());
    digest.update(pack.length.to_be_bytes());
    digest.update(pack.pack_id);
    digest.update(pack.attempt_id.as_bytes());
    update_cache_digest_field(&mut digest, pack.content_key_id.as_str().as_bytes())?;
    update_cache_digest_field(
        &mut digest,
        pack.keyring_envelope_object_id.as_str().as_bytes(),
    )?;
    digest.update(pack.keyring_envelope_digest);
    digest.update(pack.pack_record_count.to_be_bytes());
    digest.update(pack.record_ordinal.to_be_bytes());
    digest.update(pack.record_offset.to_be_bytes());
    digest.update(pack.content_len.to_be_bytes());
    Ok(BackendObjectRef {
        object_id: BackendObjectId::new(format!(
            "v2-pack-cache/{}",
            hex::encode(digest.finalize())
        ))?,
        version_id: pack.commit_version_id.clone(),
    })
}

fn update_cache_digest_field(digest: &mut Sha256Hasher, value: &[u8]) -> Result<()> {
    let length = u64::try_from(value.len())
        .map_err(|_| v2_repository_error(V2FormatError::InvalidPayloadPack))?;
    digest.update(length.to_be_bytes());
    digest.update(value);
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct V2PayloadSectionCacheKey {
    carrier: V2PayloadSectionCarrierCacheKey,
    payload_id: BackendObjectId,
    offset: u64,
    length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum V2PayloadSectionCarrierCacheKey {
    Standalone {
        object_id: BackendObjectId,
        version_id: Option<BackendVersionId>,
        digest: [u8; 32],
    },
}

#[derive(Debug)]
struct V2PayloadSectionCache {
    sections: LruCache<V2PayloadSectionCacheKey, Bytes>,
    max_entries: usize,
    max_bytes: u64,
    current_bytes: u64,
}

impl V2PayloadSectionCache {
    fn with_max_bytes(max_bytes: u64) -> Self {
        Self {
            sections: LruCache::new(),
            max_entries: 4096,
            max_bytes,
            current_bytes: 0,
        }
    }

    fn peek(&self, key: &V2PayloadSectionCacheKey) -> Option<Bytes> {
        self.sections.peek_cloned(key)
    }

    fn touch(&mut self, key: &V2PayloadSectionCacheKey) {
        self.sections.touch(key);
    }

    fn insert(&mut self, key: V2PayloadSectionCacheKey, payload: Bytes) {
        let bytes = u64::try_from(payload.len()).unwrap_or(u64::MAX);
        if self.max_bytes == 0 || bytes > self.max_bytes {
            return;
        }

        match self.sections.insert(key, payload) {
            Some(previous) => {
                let previous = u64::try_from(previous.len()).unwrap_or(u64::MAX);
                self.current_bytes = self.current_bytes.saturating_sub(previous);
                self.current_bytes = self.current_bytes.saturating_add(bytes);
            }
            None => {
                self.current_bytes = self.current_bytes.saturating_add(bytes);
            }
        }

        self.evict_over_limits();
    }

    fn evict_over_limits(&mut self) {
        while self.sections.len() > self.max_entries || self.current_bytes > self.max_bytes {
            let Some((_evicted_key, payload)) = self.sections.pop_lru() else {
                break;
            };
            let bytes = u64::try_from(payload.len()).unwrap_or(u64::MAX);
            self.current_bytes = self.current_bytes.saturating_sub(bytes);
        }
    }
}

fn replay_section_bytes(commit: &V2ReplayCommit, section_index: usize) -> Result<&[u8]> {
    commit
        .retained_sections
        .get(section_index)
        .and_then(Option::as_deref)
        .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))
}

fn ensure_payload_layout_matches_content_len(
    header: &SegmentedPayloadLayout,
    content_len: u64,
    object_id: &BackendObjectId,
) -> Result<()> {
    if header.plaintext_len == content_len {
        Ok(())
    } else {
        Err(RepositoryError::InvalidObjectFormat {
            object_id: object_id.clone(),
        })
    }
}

fn commit_protection_for_deltas(
    deltas: &[IndexDelta],
) -> (Option<RetentionPolicy>, Option<LegalHoldStatus>) {
    let mut retention = None;
    let mut legal_hold = None;
    for delta in deltas {
        let IndexDelta::Upsert { entry, .. } = delta else {
            continue;
        };
        retention = strongest_retention_policy(retention, entry.retention);
        if entry.legal_hold == Some(LegalHoldStatus::On) {
            legal_hold = Some(LegalHoldStatus::On);
        }
    }
    (retention, legal_hold)
}

fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}

fn v2_repository_error(error: V2FormatError) -> RepositoryError {
    match error {
        V2FormatError::ContentMd5Mismatch => return RepositoryError::ContentMd5Mismatch,
        V2FormatError::ObjectTooLarge => return RepositoryError::ObjectTooLarge,
        V2FormatError::ObjectLengthMismatch => {
            return RepositoryError::ObjectLengthMismatch;
        }
        V2FormatError::ObjectBodyReadFailed => {
            return RepositoryError::ObjectBodyReadFailed;
        }
        _ => {}
    }
    RepositoryError::CommitFailed {
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use crate::v2::service::{V2CommitPackRead, pack_payload_cache_ref};
    use rs3_types::{BackendObjectId, BackendVersionId, KeyId};

    fn object_id(value: &str) -> BackendObjectId {
        BackendObjectId::new(value).expect("test object ID should be valid")
    }

    fn key_id(value: &str) -> KeyId {
        KeyId::new(value).expect("test key ID should be valid")
    }

    fn sample_pack_read() -> V2CommitPackRead {
        V2CommitPackRead {
            commit_key: object_id("commits/v03/opaque"),
            commit_version_id: Some(
                BackendVersionId::new("version-1").expect("test version ID should be valid"),
            ),
            body_digest: [1_u8; 32],
            commit_stored_len: 8_192,
            pack_section_ordinal: 2,
            pack_offset: 1_024,
            length: 4_096,
            pack_id: [2_u8; 32],
            attempt_id: rs3_types::PayloadAttemptId::from_bytes([0xa3; 32]),
            content_key_id: key_id("content-1"),
            keyring_envelope_object_id: object_id("keyrings/envelope-1"),
            keyring_envelope_digest: [3_u8; 32],
            pack_record_count: 64,
            record_ordinal: 7,
            record_offset: 512,
            content_len: 512,
        }
    }

    #[test]
    fn packed_segment_cache_identity_binds_every_record_context_fact() {
        let original = sample_pack_read();
        let mut variants = Vec::new();

        let mut variant = original.clone();
        variant.attempt_id = rs3_types::PayloadAttemptId::from_bytes([0xa4; 32]);
        variants.push(variant);
        let mut variant = original.clone();
        variant.content_key_id = key_id("content-2");
        variants.push(variant);
        let mut variant = original.clone();
        variant.keyring_envelope_object_id = object_id("keyrings/envelope-2");
        variants.push(variant);
        let mut variant = original.clone();
        variant.keyring_envelope_digest[0] ^= 1;
        variants.push(variant);
        let mut variant = original.clone();
        variant.length += 1;
        variants.push(variant);
        let mut variant = original.clone();
        variant.pack_record_count += 1;
        variants.push(variant);
        let mut variant = original.clone();
        variant.record_offset += 1;
        variants.push(variant);
        let mut variant = original.clone();
        variant.content_len += 1;
        variants.push(variant);

        let original_ref = pack_payload_cache_ref(&original, b"repository-context")
            .expect("cache identity should be derivable");
        let mut identities = variants
            .iter()
            .map(|variant| {
                pack_payload_cache_ref(variant, b"repository-context")
                    .expect("cache identity should be derivable")
            })
            .collect::<Vec<_>>();
        identities.push(
            pack_payload_cache_ref(&original, b"other-repository-context")
                .expect("cache identity should be derivable"),
        );

        assert!(identities.iter().all(|identity| identity != &original_ref));
        identities.push(original_ref);
        identities.sort();
        identities.dedup();
        assert_eq!(identities.len(), variants.len() + 2);
    }
}
