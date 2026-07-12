//! v2 repository operations over the existing trusted namespace service.

use super::commit::{V2_SECTION_FLAG_COMPRESSED, V2_SECTION_FLAG_MUST_UNDERSTAND, V2CommitKey};
use super::error::V2FormatError;
use super::repository::{
    V2CommitAnchor, V2CommitChain, V2CommitSection, V2CommitStore, V2CommitStoreOptions,
    V2CommitWrite, V2FinalizedStreamingPayloadWrite, V2MemoryAnchor, V2ReplayChain, V2ReplayCommit,
    V2StoredCommit, V2StreamingPayloadWrite,
};
use super::{
    V2_INDEX_ROOT_MAX_RUNS, V2_MAX_HEADER_SIZE, V2EmbeddedIndexRunLocation, V2IndexRoot,
    V2IndexRootRunRef, V2KeyringEnvelopeRef, V2ParsedCommit, V2ParsedCommitHeader,
    V2PayloadPackFacts, V2PayloadPackId, V2PayloadPackRecordContext, V2PayloadPackRecordRef,
    V2SectionDescriptor, V2SectionType, V2StreamPayloadCacheIdentity, V2UploadMode,
    digest_v2_section, open_v2_payload_pack_cached_record_span,
    open_v2_payload_pack_record_span_with_segments, plan_v2_payload_pack_record_range,
    seal_v2_index_root, validated_v2_stream_payload_start,
};
use crate::checkpoint::{open_index_delta_object, seal_index_delta_object, seal_manifest_record};
use crate::error::{RepositoryError, Result};
use crate::lru::LruCache;
use crate::model::{
    DeleteOutcome, PhysicalDeleteOutcome, RepositoryListEntry, RepositoryObjectMetadata,
    RepositoryPutOptions,
};
use crate::namespace::first_namespace_entry;
use crate::payload::{
    PayloadHeaderProbe, SegmentedPayloadFormat, SegmentedPayloadHeader, SegmentedPayloadSealer,
    adaptive_payload_segment_size, open_payload_object, parse_segmented_payload_header,
    parse_segmented_payload_header_with_total_len, probe_payload_header,
    seal_streamable_payload_object, segmented_ciphertext_span, total_segmented_payload_len,
};
use crate::service::{
    DecryptedSegmentIdentity, Repository, RepositoryOptions, strongest_retention_policy,
};
use crate::state::{RepositoryState, TrustedManifest, apply_index_delta_object, object_material};
use bytes::Bytes;
use futures_util::Stream;
use rs3_crypto::KeyRing;
use rs3_index::{
    INDEX_DELTA_OBJECT_DOMAIN, IndexDelta, IndexDeltaObject, NamespaceEntry,
    PayloadHeaderReference, PayloadReference, index_delta_object_bytes,
};
use rs3_storage::{BlobStore, ByteRange, StorageError};
use rs3_types::{
    BackendObjectId, BackendObjectRef, BackendVersionId, LegalHoldStatus, LogicalPath, ManifestId,
    RetentionPolicy, Sequence,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock as TokioRwLock};

mod compaction;
pub(super) mod packed;
mod packed_compaction;
mod packed_compaction_publish;
mod staging;

use staging::{PendingV2Checkpoint, PendingV2Snapshot, PendingV2State};

const V2_PAYLOAD_FILL_LOCK_STRIPES: usize = 64;
const V2_MAX_PAYLOAD_HEADER_SIZE: u64 = 4 * 1024;

/// Preview v2 repository service.
///
/// This adapter deliberately reuses the existing trusted repository service for
/// path-private namespace indexing, payload encryption, range reads, and list
/// semantics. v2 only changes how the pending sealed index delta becomes
/// durable: it is embedded in a signed v2 commit instead of a v1 checkpoint.
pub struct V2Repository<S> {
    repository: Repository<S>,
    commit_store: V2CommitStore<S>,
    commit_upload_mode: V2UploadMode,
    accepted: StdRwLock<V2AcceptedState>,
    mutation_lock: Mutex<()>,
    publication_lock: TokioRwLock<()>,
    payload_segment_fill_locks: Vec<Mutex<()>>,
    pending: StdMutex<PendingV2State>,
    mutation_owner: Arc<AtomicU8>,
    recovery_required: AtomicBool,
    payload_sections: StdRwLock<V2PayloadSectionCache>,
    commit_headers: StdRwLock<V2CommitHeaderCache>,
    payload_headers: StdRwLock<V2PayloadHeaderCache>,
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

struct PendingV2Install {
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
        generation: Sequence,
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
struct PendingV2PayloadLocation {
    manifest_id: ManifestId,
    payload_id: BackendObjectId,
    payload_header: PayloadHeaderReference,
    section_ordinal: u32,
    section_digest: [u8; 32],
    sections_start: Option<u64>,
    offset: u64,
    length: u64,
}

struct PendingV2CommitSections {
    sections: Vec<V2CommitSection>,
    locations: Vec<PendingV2PayloadLocation>,
    retention: Option<RetentionPolicy>,
    legal_hold: Option<LegalHoldStatus>,
}

struct StagedV2Put {
    metadata: RepositoryObjectMetadata,
    manifest_id: ManifestId,
    content_len: u64,
    sequence: Sequence,
}

struct StreamingV2PutFinalized {
    staged: StagedV2Put,
    location: PendingV2PayloadLocation,
    run: packed::PendingV2IndexRunFacts,
}

struct StreamingV2PayloadFinalized {
    location: PendingV2PayloadLocation,
    run: packed::PendingV2IndexRunFacts,
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

impl<S> V2Repository<S>
where
    S: BlobStore + Clone,
{
    /// Creates a v2 repository service over a blob store.
    pub fn new(
        store: S,
        keyring: KeyRing,
        repository_options: RepositoryOptions,
        commit_options: V2CommitStoreOptions,
    ) -> Self {
        let payload_section_cache_max_bytes = repository_options.decrypted_segment_cache_max_bytes;
        let commit_upload_mode = commit_options.upload_mode;
        Self {
            repository: Repository::with_keyring_and_options(
                store.clone(),
                keyring.clone(),
                repository_options,
            ),
            commit_store: V2CommitStore::new(store, keyring, commit_options),
            commit_upload_mode,
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
            commit_headers: StdRwLock::new(V2CommitHeaderCache::default()),
            payload_headers: StdRwLock::new(V2PayloadHeaderCache::default()),
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
        let (covered_generation, expected_live_object_count, expected_runs) = {
            let accepted = self
                .accepted
                .read()
                .map_err(|_| RepositoryError::StatePoisoned)?;
            (
                accepted.repository.next_sequence,
                u64::try_from(accepted.repository.list_entries.len())
                    .map_err(|_| v2_repository_error(V2FormatError::IndexRootLimitExceeded))?,
                accepted.runs.clone(),
            )
        };
        let root = V2IndexRoot::new(
            covered_generation,
            expected_live_object_count,
            self.commit_store.options().format_ref.clone(),
            self.commit_store.options().keyring_envelope_ref.clone(),
            expected_runs.clone(),
        )
        .map_err(v2_repository_error)?;
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

    async fn replay_bounded_chain_to_state(
        &self,
        chain: &V2ReplayChain,
    ) -> Result<RepositoryState> {
        self.replay_bounded_chain_to_state_and_runs(chain)
            .await
            .map(|(state, _)| state)
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

    /// Loads and replays a supplied v2 commit chain.
    pub fn replay_chain(&self, chain: &V2CommitChain) -> Result<()> {
        let _publication_guard = self
            .publication_lock
            .try_write()
            .map_err(|_| RepositoryError::CommitBackpressure)?;
        let rebuilt = self.replay_chain_to_state(chain)?;
        let recovered_sequence = rebuilt.next_sequence;
        *self
            .accepted
            .write()
            .map_err(|_| RepositoryError::StatePoisoned)? = V2AcceptedState {
            repository: rebuilt,
            runs: Vec::new(),
            anchor: None,
        };
        self.pending
            .lock()
            .map_err(|_| RepositoryError::StatePoisoned)?
            .reset_to_accepted_sequence(recovered_sequence)?;
        Ok(())
    }

    pub(crate) fn replay_chain_to_state(&self, chain: &V2CommitChain) -> Result<RepositoryState> {
        let mut rebuilt = RepositoryState::default();
        let mut previous_published_at_ms = None;
        for commit in chain.commits_newest_first.iter().rev() {
            let published_at_ms = commit.parsed_header.header.publish_time_ms;
            if previous_published_at_ms.is_some_and(|previous| published_at_ms < previous) {
                return Err(v2_repository_error(V2FormatError::StaleAnchor));
            }
            previous_published_at_ms = Some(published_at_ms);
            self.apply_commit_sections(&mut rebuilt, commit)?;
        }

        Ok(rebuilt)
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

    /// Streams a known-length object into one multipart-backed v2 commit.
    pub async fn put_committed_streaming_known_len<A, St>(
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
        self.put_committed_streaming_known_len_inner(
            anchor,
            key,
            plaintext_len,
            stream,
            options,
            multipart_part_size,
        )
        .await
    }

    pub(super) async fn put_committed_streaming_known_len_coordinated<A, St>(
        &self,
        mutation: V2CoordinatedMutation<'_, A>,
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
        self.validate_coordinator_lease(mutation.lease)?;
        self.put_committed_streaming_known_len_inner(
            mutation.anchor,
            key,
            plaintext_len,
            stream,
            options,
            multipart_part_size,
        )
        .await
    }

    async fn put_committed_streaming_known_len_inner<A, St>(
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
        let _guard = self.mutation_lock.lock().await;
        let _publication_guard = self.publication_lock.write().await;
        let base_anchor = self.ensure_accepted_anchor_matches(anchor).await?;
        let (staged, rollback) =
            self.stage_put_metadata_sync_with_rollback(key, plaintext_len, options, None)?;
        let keyring = self.repository.keyring()?;
        let staged_content_len = staged.content_len;
        let staged_manifest_id = staged.manifest_id.clone();
        let staged_retention = staged.metadata.retention;
        let staged_legal_hold = staged.metadata.legal_hold;
        let temporary_anchor = V2MemoryAnchor::with_state(base_anchor.clone());
        let stored = self
            .commit_store
            .write_child_commit_with_streaming_payload(&temporary_anchor, |commit_key| {
                let payload_id =
                    Self::v2_payload_id(commit_key, 0).map_err(|_| V2FormatError::SectionBounds)?;
                let payload_segment_size = self
                    .payload_segment_size_for_object_len(staged_content_len)
                    .map_err(|_| V2FormatError::InvalidHeaderField)?;
                let payload_sealer = SegmentedPayloadSealer::new(&keyring, payload_segment_size)
                    .map_err(|_| V2FormatError::InvalidHeaderField)?;
                let payload_header = payload_header_reference(
                    &payload_sealer
                        .header_reference(staged_content_len)
                        .map_err(|_| V2FormatError::InvalidHeaderField)?,
                )
                .map_err(|_| V2FormatError::InvalidHeaderField)?;
                let payload_len = payload_sealer
                    .sealed_len_for_plaintext_len(staged_content_len)
                    .map_err(|_| V2FormatError::SectionBounds)?;
                let expected_location = PendingV2PayloadLocation {
                    manifest_id: staged_manifest_id.clone(),
                    payload_id: payload_id.clone(),
                    payload_header,
                    section_ordinal: 0,
                    section_digest: [0_u8; 32],
                    sections_start: Self::sections_start_for_upload_mode(self.commit_upload_mode),
                    offset: 0,
                    length: payload_len,
                };
                let commit_key = commit_key.clone();
                let finalize =
                    move |input: super::repository::V2StreamingPayloadFinalizationInput| {
                        if input.plaintext_len != staged_content_len
                            || input.payload_len != expected_location.length
                            || payload_header_reference(&input.payload_header)
                                .map_err(|_| V2FormatError::InvalidHeaderField)?
                                != expected_location.payload_header
                        {
                            return Err(V2FormatError::SectionBounds);
                        }
                        let mut location = expected_location;
                        location.section_digest = input.payload_digest;
                        let pending = self
                            .pending_snapshot()
                            .map_err(|_| V2FormatError::InvalidHeaderField)?;
                        let sealed_run = self
                            .pending_streaming_index_run_for_commit(
                                &commit_key,
                                &location,
                                &pending,
                            )
                            .map_err(|_| V2FormatError::InvalidHeaderField)?;
                        Ok(V2FinalizedStreamingPayloadWrite {
                            index_run: sealed_run.bytes,
                            output: StreamingV2PayloadFinalized {
                                location,
                                run: sealed_run.run,
                            },
                        })
                    };
                Ok(V2StreamingPayloadWrite {
                    payload_id,
                    payload_sealer,
                    expected_plaintext_len: Some(staged_content_len),
                    max_plaintext_len: None,
                    payload_segment_size,
                    stream,
                    finalize,
                    retention: staged_retention,
                    legal_hold: staged_legal_hold,
                    multipart_part_size,
                    _output: PhantomData,
                })
            })
            .await
            .map_err(v2_repository_error);
        let uploaded = match stored {
            Ok(uploaded) => uploaded,
            Err(error) => {
                self.rollback_state_mutations(vec![rollback])?;
                return Err(error);
            }
        };
        let mut output = uploaded.output;
        let accepted_run = match self.verify_streaming_commit_sections(
            &uploaded.stored,
            &uploaded.payload_section,
            &uploaded.index_run_section,
            &mut output.location,
            &output.run,
        ) {
            Ok(()) => {
                let run = self.accepted_run_ref(output.run, &uploaded.stored);
                self.validate_accepted_run_append(&run).map(|()| run)
            }
            Err(error) => Err(error),
        };
        let accepted_run = match accepted_run {
            Ok(run) => run,
            Err(error) => {
                self.rollback_state_mutations(vec![rollback])?;
                return Err(error);
            }
        };
        let mut pending = self.pending_snapshot()?;
        let install = match self.resolve_pending_payload_refs(
            &mut pending,
            &uploaded.stored,
            std::slice::from_ref(&output.location),
        ) {
            Ok(()) => self.prepare_pending_install(&pending, staged.sequence, Some(accepted_run)),
            Err(error) => Err(error),
        };
        let install = match install {
            Ok(install) => install,
            Err(error) => {
                self.rollback_state_mutations(vec![rollback])?;
                return Err(error);
            }
        };
        let adopted = match self
            .commit_store
            .adopt_verified_unanchored_child(anchor, &base_anchor, &uploaded.stored)
            .await
            .map_err(v2_repository_error)
        {
            Ok(stored) => stored,
            Err(error) => {
                self.rollback_state_mutations(vec![rollback])?;
                return Err(error);
            }
        };
        if let Err(error) = self.install_pending_commit(install, adopted.anchor_state) {
            self.mark_local_recovery_required();
            tracing::error!(
                target: "rs3_repository",
                operation = "v2_install_streaming_commit",
                error = %error,
                "v2 streaming anchor advanced but local state installation failed; restart is required",
            );
            return Err(RepositoryError::AcceptedRecoveryRequired);
        }
        Ok(staged.metadata)
    }

    /// Streams an object with unknown length into one multipart-backed v2 commit.
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
        let _guard = self.mutation_lock.lock().await;
        let _publication_guard = self.publication_lock.write().await;
        let base_anchor = self.ensure_accepted_anchor_matches(anchor).await?;
        self.ensure_put_create_allowed(&key, &options)?;
        let keyring = self.repository.keyring()?;
        let payload_segment_size = self.payload_segment_size_for_object_len(max_plaintext_len)?;
        let upload_retention = strongest_retention_policy(
            self.repository.options.default_retention,
            options.retention,
        );
        let upload_legal_hold = options.legal_hold;
        let staged_rollback = StdMutex::new(None);
        let temporary_anchor = V2MemoryAnchor::with_state(base_anchor.clone());
        let stored = self
            .commit_store
            .write_child_commit_with_streaming_payload(&temporary_anchor, |commit_key| {
                let payload_id =
                    Self::v2_payload_id(commit_key, 0).map_err(|_| V2FormatError::SectionBounds)?;
                let payload_sealer = SegmentedPayloadSealer::new(&keyring, payload_segment_size)
                    .map_err(|_| V2FormatError::InvalidHeaderField)?;
                let commit_key = commit_key.clone();
                let key = key.clone();
                let options = options.clone();
                let payload_id_for_location = payload_id.clone();
                let staged_rollback = &staged_rollback;
                let finalize =
                    move |input: super::repository::V2StreamingPayloadFinalizationInput| {
                        let (staged, rollback) = self
                            .stage_put_metadata_sync_with_rollback(
                                key,
                                input.plaintext_len,
                                options,
                                None,
                            )
                            .map_err(|error| match error {
                                RepositoryError::ObjectTooLarge => V2FormatError::ObjectTooLarge,
                                _ => V2FormatError::InvalidHeaderField,
                            })?;
                        *staged_rollback
                            .lock()
                            .map_err(|_| V2FormatError::InvalidHeaderField)? = Some(rollback);
                        let payload_header = payload_header_reference(&input.payload_header)
                            .map_err(|_| V2FormatError::InvalidHeaderField)?;
                        if payload_header.plaintext_len != staged.content_len {
                            return Err(V2FormatError::ObjectLengthMismatch);
                        }
                        let location = PendingV2PayloadLocation {
                            manifest_id: staged.manifest_id.clone(),
                            payload_id: payload_id_for_location,
                            payload_header,
                            section_ordinal: 0,
                            section_digest: input.payload_digest,
                            sections_start: Self::sections_start_for_upload_mode(
                                self.commit_upload_mode,
                            ),
                            offset: 0,
                            length: input.payload_len,
                        };
                        let pending = self
                            .pending_snapshot()
                            .map_err(|_| V2FormatError::InvalidHeaderField)?;
                        let sealed_run = self
                            .pending_streaming_index_run_for_commit(
                                &commit_key,
                                &location,
                                &pending,
                            )
                            .map_err(|_| V2FormatError::InvalidHeaderField)?;
                        Ok(V2FinalizedStreamingPayloadWrite {
                            index_run: sealed_run.bytes,
                            output: StreamingV2PutFinalized {
                                staged,
                                location,
                                run: sealed_run.run,
                            },
                        })
                    };
                Ok(V2StreamingPayloadWrite {
                    payload_id,
                    payload_sealer,
                    expected_plaintext_len: None,
                    max_plaintext_len: Some(max_plaintext_len),
                    payload_segment_size,
                    stream,
                    finalize,
                    retention: upload_retention,
                    legal_hold: upload_legal_hold,
                    multipart_part_size,
                    _output: PhantomData,
                })
            })
            .await
            .map_err(v2_repository_error);
        let uploaded = match stored {
            Ok(uploaded) => uploaded,
            Err(error) => {
                if let Some(rollback) = staged_rollback
                    .lock()
                    .map_err(|_| RepositoryError::StatePoisoned)?
                    .take()
                {
                    self.rollback_state_mutations(vec![rollback])?;
                }
                return Err(error);
            }
        };
        let mut output = uploaded.output;
        let accepted_run = match self.verify_streaming_commit_sections(
            &uploaded.stored,
            &uploaded.payload_section,
            &uploaded.index_run_section,
            &mut output.location,
            &output.run,
        ) {
            Ok(()) => {
                let run = self.accepted_run_ref(output.run, &uploaded.stored);
                self.validate_accepted_run_append(&run).map(|()| run)
            }
            Err(error) => Err(error),
        };
        let accepted_run = match accepted_run {
            Ok(run) => run,
            Err(error) => {
                if let Some(rollback) = staged_rollback
                    .lock()
                    .map_err(|_| RepositoryError::StatePoisoned)?
                    .take()
                {
                    self.rollback_state_mutations(vec![rollback])?;
                }
                return Err(error);
            }
        };
        let sequence = output.staged.sequence;
        let mut pending = self.pending_snapshot()?;
        let install = match self.resolve_pending_payload_refs(
            &mut pending,
            &uploaded.stored,
            std::slice::from_ref(&output.location),
        ) {
            Ok(()) => self.prepare_pending_install(&pending, sequence, Some(accepted_run)),
            Err(error) => Err(error),
        };
        let install = match install {
            Ok(install) => install,
            Err(error) => {
                if let Some(rollback) = staged_rollback
                    .lock()
                    .map_err(|_| RepositoryError::StatePoisoned)?
                    .take()
                {
                    self.rollback_state_mutations(vec![rollback])?;
                }
                return Err(error);
            }
        };
        let adopted = match self
            .commit_store
            .adopt_verified_unanchored_child(anchor, &base_anchor, &uploaded.stored)
            .await
            .map_err(v2_repository_error)
        {
            Ok(stored) => stored,
            Err(error) => {
                if let Some(rollback) = staged_rollback
                    .lock()
                    .map_err(|_| RepositoryError::StatePoisoned)?
                    .take()
                {
                    self.rollback_state_mutations(vec![rollback])?;
                }
                return Err(error);
            }
        };
        if let Err(error) = self.install_pending_commit(install, adopted.anchor_state) {
            self.mark_local_recovery_required();
            tracing::error!(
                target: "rs3_repository",
                operation = "v2_install_streaming_commit",
                error = %error,
                "v2 streaming anchor advanced but local state installation failed; restart is required",
            );
            return Err(RepositoryError::AcceptedRecoveryRequired);
        }
        Ok(output.staged.metadata)
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
        let _publication_guard = self.publication_lock.read().await;
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
        let (staged, checkpoint) =
            self.stage_put_metadata_sync_with_rollback(key, plaintext_len, options, Some(body))?;

        Ok((staged.metadata, V2StagedPutRollback { checkpoint }))
    }

    fn stage_put_metadata_sync_with_rollback(
        &self,
        key: LogicalPath,
        plaintext_len: u64,
        options: RepositoryPutOptions,
        pending_body: Option<Bytes>,
    ) -> Result<(StagedV2Put, PendingV2Checkpoint)> {
        let retention = strongest_retention_policy(
            self.repository.options.default_retention,
            options.retention,
        );
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

        let sequence = pending.allocate_sequence()?;
        let material = object_material(key.as_str(), sequence);
        let manifest_id = keyring.derive_manifest_id(&material)?;
        let stale_tombstones = existing
            .into_iter()
            .filter(|(blind_key, _)| blind_key != &primary_blind_key.blind_key)
            .collect::<Vec<_>>();

        let pending_object_id = BackendObjectId::new(format!("v2-pending/{}", sequence.get()))?;
        let entry_payload_id = pending_object_id.clone();
        let modified_at_ms = current_time_ms();
        let entry = NamespaceEntry {
            namespace_key_id: primary_blind_key.key_id,
            blind_key: primary_blind_key.blind_key,
            object_id: pending_object_id,
            object_version_id: None,
            payload_ref: Some(PayloadReference::V2Self {
                payload_id: entry_payload_id,
                payload_header: None,
                sections_start: None,
                offset: 0,
                length: 0,
            }),
            manifest_id: manifest_id.clone(),
            content_len: plaintext_len,
            modified_at_ms,
            generation: sequence,
            retention,
            legal_hold: options.legal_hold,
        };
        let manifest = TrustedManifest {
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
            .unwrap_or_else(|| TrustedManifest {
                key: key.clone(),
                content_len: entry.content_len,
                modified_at_ms: entry.modified_at_ms,
                retention: entry.retention,
                legal_hold: entry.legal_hold,
            });
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
        if let PayloadReference::V2Pack {
            commit_key,
            commit_version_id,
            body_digest,
            commit_stored_len,
            pack_section_ordinal,
            pack_offset,
            length,
            pack_id,
            content_key_id,
            keyring_envelope_object_id,
            keyring_envelope_digest,
            pack_record_count,
            record_ordinal,
            record_offset,
            plaintext_digest,
        } = payload_ref
        {
            return self
                .read_pack_range_from_commit(
                    &keyring,
                    V2CommitPackRead {
                        commit_key,
                        commit_version_id,
                        body_digest,
                        commit_stored_len,
                        pack_section_ordinal,
                        pack_offset,
                        length,
                        pack_id,
                        content_key_id,
                        keyring_envelope_object_id,
                        keyring_envelope_digest,
                        pack_record_count,
                        record_ordinal,
                        record_offset,
                        plaintext_digest,
                        content_len,
                    },
                    range,
                )
                .await;
        }
        let PayloadReference::V2Commit {
            commit_key,
            commit_version_id,
            body_digest,
            commit_stored_len,
            keyring_envelope_object_id,
            keyring_envelope_digest,
            payload_section_ordinal,
            payload_section_digest,
            payload_id,
            payload_header,
            sections_start,
            offset,
            length,
            ..
        } = payload_ref
        else {
            return Err(RepositoryError::InvalidObjectFormat {
                object_id: entry.object_id,
            });
        };

        let cache_key = V2PayloadSectionCacheKey {
            commit_key: commit_key.clone(),
            commit_version_id: commit_version_id.clone(),
            body_digest,
            payload_id: payload_id.clone(),
            offset,
            length,
        };
        if let Some(payload) = self.cached_payload_section(&cache_key)? {
            let payload_header = parse_segmented_payload_header(&payload_id, &payload)?;
            ensure_payload_header_matches_content_len(&payload_header, content_len, &payload_id)?;
            return open_payload_object(&keyring, &payload_id, payload, range);
        }

        self.read_payload_range_from_commit(
            &keyring,
            V2CommitPayloadRead {
                commit_key,
                commit_version_id,
                body_digest,
                commit_stored_len,
                keyring_envelope_object_id,
                keyring_envelope_digest,
                payload_section_ordinal,
                payload_section_digest,
                payload_id,
                payload_header,
                sections_start,
                offset,
                length,
                content_len,
            },
            range,
            cache_key,
        )
        .await
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
            pack.content_key_id.clone(),
            pack_stored_len,
            pack.pack_record_count,
        )
        .map_err(v2_repository_error)?;
        let record = V2PayloadPackRecordRef::new(
            pack.record_ordinal,
            pack.record_offset,
            pack.plaintext_digest,
        );
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

    async fn read_payload_range_from_commit(
        &self,
        keyring: &KeyRing,
        payload: V2CommitPayloadRead,
        range: ByteRange,
        cache_key: V2PayloadSectionCacheKey,
    ) -> Result<Bytes> {
        let sections_start = match payload.sections_start {
            Some(sections_start) => sections_start,
            None => {
                let commit_header_key = V2CommitHeaderCacheKey {
                    commit_key: payload.commit_key.clone(),
                    commit_version_id: payload.commit_version_id.clone(),
                    body_digest: payload.body_digest,
                };
                let header = self
                    .read_commit_header_for_payload(&commit_header_key)
                    .await?;
                let (section_ordinal, section) =
                    payload_section_descriptor_in_header(&header, payload.offset, payload.length)?;
                if section_ordinal != payload.payload_section_ordinal
                    || section.digest != payload.payload_section_digest
                {
                    return Err(v2_repository_error(V2FormatError::SectionBounds));
                }
                u64::try_from(header.sections_start)
                    .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?
            }
        };
        let payload_start = validated_v2_stream_payload_start(
            sections_start,
            payload.offset,
            payload.length,
            payload.commit_stored_len,
        )
        .map_err(v2_repository_error)?;

        if range == ByteRange::Full {
            let body = self
                .commit_store
                .read_commit_range_at(
                    &payload.commit_key,
                    payload.commit_version_id.as_ref(),
                    ByteRange::Slice {
                        offset: payload_start,
                        len: payload.length,
                    },
                )
                .await
                .map_err(v2_repository_error)?;
            if digest_v2_section(&body) != payload.payload_section_digest {
                return Err(RepositoryError::InvalidObjectFormat {
                    object_id: payload.payload_id.clone(),
                });
            }
            let plaintext = open_payload_object(keyring, &payload.payload_id, body.clone(), range)?;
            if u64::try_from(plaintext.len()).ok() != Some(payload.content_len) {
                return Err(RepositoryError::InvalidObjectFormat {
                    object_id: payload.payload_id.clone(),
                });
            }
            self.cache_payload_section(cache_key, body)?;
            return Ok(plaintext);
        }

        let payload_header = match payload.payload_header.as_ref() {
            Some(reference) => payload_header_from_reference(reference)?,
            None => {
                self.read_payload_header_from_commit(&payload, payload_start, &cache_key)
                    .await?
            }
        };
        if total_segmented_payload_len(&payload_header)? != payload.length {
            return Err(RepositoryError::InvalidObjectFormat {
                object_id: payload.payload_id.clone(),
            });
        }
        ensure_payload_header_matches_content_len(
            &payload_header,
            payload.content_len,
            &payload.payload_id,
        )?;
        let span = segmented_ciphertext_span(&payload_header, range)?;
        let keyring_envelope_ref = V2KeyringEnvelopeRef {
            object_id: payload.keyring_envelope_object_id.clone(),
            digest: payload.keyring_envelope_digest,
        };
        let repository_keyring_context = packed::repository_context_from_refs(
            &self.commit_store.options().repository_id,
            &keyring_envelope_ref,
        )?;
        let payload_header_ref = payload_header_reference(&payload_header)?;
        let payload_cache_ref = V2StreamPayloadCacheIdentity {
            repository_keyring_context: &repository_keyring_context,
            commit_key: &payload.commit_key,
            commit_version_id: payload.commit_version_id.as_ref(),
            commit_body_digest: payload.body_digest,
            commit_stored_len: payload.commit_stored_len,
            payload_section_ordinal: payload.payload_section_ordinal,
            payload_section_digest: payload.payload_section_digest,
            sections_start,
            payload_section_offset: payload.offset,
            payload_section_len: payload.length,
            payload_id: &payload.payload_id,
            payload_header: &payload_header_ref,
            content_len: payload.content_len,
        }
        .cache_ref()
        .map_err(v2_repository_error)?;
        if let Some(plaintext) = self.repository.open_cached_decrypted_segments(
            DecryptedSegmentIdentity {
                cache_ref: &payload_cache_ref,
                payload_id: &payload.payload_id,
            },
            &payload_header,
            range,
        )? {
            return Ok(plaintext);
        }
        let fill_lock_index = payload_fill_lock_index(&payload.payload_id, span.start_segment);
        let _fill_guard = self.payload_segment_fill_locks[fill_lock_index]
            .lock()
            .await;
        if let Some(plaintext) = self.repository.open_cached_decrypted_segments(
            DecryptedSegmentIdentity {
                cache_ref: &payload_cache_ref,
                payload_id: &payload.payload_id,
            },
            &payload_header,
            range,
        )? {
            return Ok(plaintext);
        }
        let ciphertext = if span.len == 0 {
            Bytes::new()
        } else {
            self.commit_store
                .read_commit_range_at(
                    &payload.commit_key,
                    payload.commit_version_id.as_ref(),
                    ByteRange::Slice {
                        offset: payload_start
                            .checked_add(span.offset)
                            .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))?,
                        len: span.len,
                    },
                )
                .await
                .map_err(v2_repository_error)?
        };
        self.repository.open_and_cache_decrypted_segments(
            keyring,
            DecryptedSegmentIdentity {
                cache_ref: &payload_cache_ref,
                payload_id: &payload.payload_id,
            },
            &payload_header,
            range,
            span,
            ciphertext,
        )
    }

    async fn read_commit_header_for_payload(
        &self,
        key: &V2CommitHeaderCacheKey,
    ) -> Result<V2ParsedCommitHeader> {
        if let Some(header) = self.cached_commit_header(key)? {
            return Ok(header);
        }
        let header = self
            .commit_store
            .read_commit_header_at(&key.commit_key, key.commit_version_id.as_ref())
            .await
            .map_err(v2_repository_error)?;
        if header.header.body_digest != key.body_digest {
            return Err(v2_repository_error(V2FormatError::BodyDigestMismatch));
        }
        self.cache_commit_header(key.clone(), header.clone())?;
        Ok(header)
    }

    async fn read_payload_header_from_commit(
        &self,
        payload: &V2CommitPayloadRead,
        payload_start: u64,
        cache_key: &V2PayloadSectionCacheKey,
    ) -> Result<SegmentedPayloadHeader> {
        if let Some(header) = self.cached_payload_header(cache_key)? {
            return Ok(header);
        }
        let initial_len = payload.length.min(crate::payload::PAYLOAD_HEADER_PROBE_LEN);
        let initial = self
            .commit_store
            .read_commit_range_at(
                &payload.commit_key,
                payload.commit_version_id.as_ref(),
                ByteRange::Slice {
                    offset: payload_start,
                    len: initial_len,
                },
            )
            .await
            .map_err(v2_repository_error)?;
        if u64::try_from(initial.len()).ok() != Some(initial_len) {
            return Err(v2_repository_error(V2FormatError::TruncatedBody));
        }
        let header_len = match probe_payload_header(&payload.payload_id, &initial)? {
            PayloadHeaderProbe::Segmented { header_len } => header_len,
            PayloadHeaderProbe::NeedMore { len } => {
                if len > payload.length || len > V2_MAX_PAYLOAD_HEADER_SIZE {
                    return Err(RepositoryError::InvalidObjectFormat {
                        object_id: payload.payload_id.clone(),
                    });
                }
                let header = self
                    .commit_store
                    .read_commit_range_at(
                        &payload.commit_key,
                        payload.commit_version_id.as_ref(),
                        ByteRange::Slice {
                            offset: payload_start,
                            len,
                        },
                    )
                    .await
                    .map_err(v2_repository_error)?;
                if u64::try_from(header.len()).ok() != Some(len) {
                    return Err(v2_repository_error(V2FormatError::TruncatedBody));
                }
                let parsed = parse_segmented_payload_header_with_total_len(
                    &payload.payload_id,
                    &header,
                    payload.length,
                )?;
                self.cache_payload_header(cache_key.clone(), parsed.clone())?;
                return Ok(parsed);
            }
        };
        if u64::try_from(header_len).map_or(true, |len| len > V2_MAX_PAYLOAD_HEADER_SIZE) {
            return Err(RepositoryError::InvalidObjectFormat {
                object_id: payload.payload_id.clone(),
            });
        }
        let parsed = parse_segmented_payload_header_with_total_len(
            &payload.payload_id,
            &initial[..header_len],
            payload.length,
        )?;
        self.cache_payload_header(cache_key.clone(), parsed.clone())?;
        Ok(parsed)
    }

    fn v2_payload_id(commit_key: &V2CommitKey, ordinal: usize) -> Result<BackendObjectId> {
        let ordinal = u64::try_from(ordinal)
            .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?;
        let mut digest = Sha256::new();
        digest.update(b"rs3:v2-payload-id:v1\n");
        digest.update(commit_key.object_id.as_str().as_bytes());
        digest.update(ordinal.to_be_bytes());
        BackendObjectId::new(format!("v2-payload/{}", hex::encode(digest.finalize())))
            .map_err(Into::into)
    }

    fn sections_start_for_upload_mode(upload_mode: V2UploadMode) -> Option<u64> {
        match upload_mode {
            V2UploadMode::MultipartPadded => Some(V2_MAX_HEADER_SIZE as u64),
            V2UploadMode::SinglePut => None,
        }
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

    /// Applies legal hold after the covering v2 commit is accepted.
    pub async fn set_legal_hold_committed<A>(
        &self,
        anchor: &A,
        key: LogicalPath,
        status: LegalHoldStatus,
    ) -> Result<RepositoryObjectMetadata>
    where
        A: V2CommitAnchor,
    {
        let _mutation_lease = self.claim_direct_mutation()?;
        self.set_legal_hold_committed_inner(anchor, key, status)
            .await
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
        self.set_legal_hold_committed_inner(mutation.anchor, key, status)
            .await
    }

    async fn set_legal_hold_committed_inner<A>(
        &self,
        anchor: &A,
        key: LogicalPath,
        status: LegalHoldStatus,
    ) -> Result<RepositoryObjectMetadata>
    where
        A: V2CommitAnchor,
    {
        let _guard = self.mutation_lock.lock().await;
        let _publication_guard = self.publication_lock.write().await;
        self.ensure_accepted_anchor_matches(anchor).await?;
        let (metadata, rollback) = self.stage_legal_hold(&key, status).await?;
        if let Err(error) = self.publish_pending_index_delta_locked(anchor).await {
            self.rollback_state_mutations(vec![rollback])?;
            return Err(error);
        }
        Ok(metadata)
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

    async fn stage_legal_hold(
        &self,
        key: &LogicalPath,
        status: LegalHoldStatus,
    ) -> Result<(RepositoryObjectMetadata, PendingV2Checkpoint)> {
        let keyring = self.repository.keyring()?;
        let lookup_blind_keys = keyring.derive_blind_index_keys_for_lookup(key)?;
        let (original, trusted_manifest) = {
            let accepted = self
                .accepted
                .read()
                .map_err(|_| RepositoryError::StatePoisoned)?;
            let pending = self
                .pending
                .lock()
                .map_err(|_| RepositoryError::StatePoisoned)?;
            let entry = lookup_blind_keys
                .iter()
                .find_map(|candidate| {
                    pending
                        .effective_head(&accepted.repository, &candidate.blind_key)
                        .live()
                })
                .cloned()
                .ok_or_else(|| RepositoryError::NotFound(key.clone()))?;
            let manifest = pending
                .manifest(&accepted.repository, &entry.manifest_id)
                .cloned();
            (entry, manifest)
        };

        self.repository
            .store
            .set_legal_hold_at(
                &original.object_id,
                original.object_version_id.as_ref(),
                status,
            )
            .await?;
        let backend = self
            .repository
            .store
            .head_at(&original.object_id, original.object_version_id.as_ref())
            .await?;

        let accepted = self
            .accepted
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        let current = lookup_blind_keys
            .iter()
            .find_map(|candidate| {
                pending
                    .effective_head(&accepted.repository, &candidate.blind_key)
                    .live()
            })
            .cloned()
            .ok_or_else(|| RepositoryError::NotFound(key.clone()))?;
        if current.manifest_id != original.manifest_id || current.object_id != original.object_id {
            return Err(v2_repository_error(V2FormatError::StaleAnchor));
        }

        let sequence = pending.allocate_sequence()?;
        let manifest_id = keyring.derive_manifest_id(&object_material(key.as_str(), sequence))?;
        let mut updated = current;
        updated.manifest_id = manifest_id.clone();
        updated.generation = sequence;
        updated.legal_hold = backend.legal_hold.or(Some(status));
        updated.object_version_id = backend.version_id.or(updated.object_version_id);
        let manifest = TrustedManifest {
            key: key.clone(),
            content_len: trusted_manifest
                .as_ref()
                .map_or(updated.content_len, |manifest| manifest.content_len),
            modified_at_ms: backend.modified_at_ms.unwrap_or_else(current_time_ms),
            retention: trusted_manifest
                .as_ref()
                .map_or(updated.retention, |manifest| manifest.retention),
            legal_hold: updated.legal_hold,
        };
        updated.content_len = manifest.content_len;
        updated.modified_at_ms = manifest.modified_at_ms;
        updated.retention = manifest.retention;
        let sealed_manifest = seal_manifest_record(&keyring, &manifest_id, &manifest)?;
        let rollback = pending.append_operation(
            vec![IndexDelta::Upsert {
                entry: Box::new(updated),
                prefix_tokens: Vec::new(),
                sealed_manifest: Box::new(sealed_manifest),
            }],
            Some((manifest_id, manifest.clone())),
            None,
        )?;
        Ok((manifest.into_metadata(), rollback))
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
        let mut pending = self.pending_snapshot()?;
        let Some(sequence) = pending.commit_sequence() else {
            return Ok(None);
        };
        let base_anchor = self.ensure_accepted_anchor_matches(anchor).await?;
        let mut accepted_locations = None;
        let mut accepted_pack_locations = None;
        let mut accepted_run = None;
        let temporary_anchor = V2MemoryAnchor::with_state(base_anchor.clone());
        let uploaded = self
            .commit_store
            .write_child_commit_with(&temporary_anchor, |commit_key| {
                if let Some(packed) = self
                    .pending_packed_sections_for_commit(commit_key, &pending)
                    .map_err(|_| V2FormatError::InvalidHeaderField)?
                {
                    accepted_pack_locations = Some(packed.locations);
                    accepted_run = Some(packed.run);
                    let mut write =
                        V2CommitWrite::delta(packed.sections).with_retention(packed.retention);
                    write = write.with_legal_hold(packed.legal_hold);
                    return Ok(write);
                }
                let pending = self
                    .pending_delta_sections_for_commit(commit_key, &pending)
                    .map_err(|_| V2FormatError::InvalidHeaderField)?;
                accepted_locations = Some(pending.locations);
                let mut write =
                    V2CommitWrite::delta(pending.sections).with_retention(pending.retention);
                write = write.with_legal_hold(pending.legal_hold);
                Ok(write)
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
        if let Some(locations) = accepted_pack_locations.as_ref() {
            self.resolve_pending_pack_refs(&mut pending, &uploaded, locations)?;
        } else {
            let locations = accepted_locations
                .as_ref()
                .ok_or_else(|| v2_repository_error(V2FormatError::InvalidHeaderField))?;
            self.resolve_pending_payload_refs(&mut pending, &uploaded, locations)?;
        }
        let install = self.prepare_pending_install(&pending, sequence, accepted_run)?;
        let stored = self
            .commit_store
            .adopt_verified_unanchored_child(anchor, &base_anchor, &uploaded)
            .await
            .map_err(v2_repository_error)?;
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

    fn verify_streaming_commit_sections(
        &self,
        stored: &V2StoredCommit,
        payload_section: &V2SectionDescriptor,
        index_run_section: &V2SectionDescriptor,
        location: &mut PendingV2PayloadLocation,
        run: &packed::PendingV2IndexRunFacts,
    ) -> Result<()> {
        if location.section_ordinal != 0
            || location.offset != 0
            || payload_section.section_type != V2SectionType::Payload
            || payload_section.flags != V2_SECTION_FLAG_MUST_UNDERSTAND
            || payload_section.offset != location.offset
            || payload_section.length != location.length
            || payload_section.digest != location.section_digest
            || run.section_ordinal != 1
            || index_run_section.section_type != V2SectionType::IndexRun
            || index_run_section.flags != V2_SECTION_FLAG_MUST_UNDERSTAND
            || index_run_section.offset != run.section_offset
            || index_run_section.length != run.section_len
            || index_run_section.digest != run.section_digest
            || run.section_offset != location.length
            || run.keyring_envelope_ref != self.commit_store.options().keyring_envelope_ref
            || location
                .sections_start
                .is_some_and(|sections_start| sections_start != stored.sections_start)
        {
            return Err(v2_repository_error(V2FormatError::InvalidIndexRun));
        }
        location.sections_start = Some(stored.sections_start);
        Ok(())
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
                    if matches!(entry.payload_ref, Some(PayloadReference::V2Self { .. }))
                        || entry.generation > sequence
                    {
                        return Err(v2_repository_error(V2FormatError::InvalidHeaderField));
                    }
                    mutations.push(PendingV2InstallMutation::Upsert {
                        entry: Box::new((**entry).clone()),
                        manifest: (*manifest).clone(),
                    });
                }
                IndexDelta::Tombstone {
                    blind_key,
                    generation,
                    ..
                } => mutations.push(PendingV2InstallMutation::Tombstone {
                    blind_key: blind_key.clone(),
                    generation: *generation,
                }),
            }
        }
        let accepted = self
            .accepted
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        if sequence <= accepted.repository.next_sequence {
            return Err(v2_repository_error(V2FormatError::InvalidHeaderField));
        }
        drop(accepted);
        self.pending
            .lock()
            .map_err(|_| RepositoryError::StatePoisoned)?
            .validate_snapshot(pending)?;
        Ok(PendingV2Install {
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
        // The exclusive publication barrier prevents any staged or accepted
        // mutation between pre-CAS validation and this local installation.
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
                PendingV2InstallMutation::Tombstone {
                    blind_key,
                    generation,
                } => accepted
                    .repository
                    .tombstone_namespace_entry(blind_key, generation),
            }
        }
        accepted.repository.next_sequence = install.sequence;
        if let Some(run) = install.run {
            accepted.runs.push(run);
        }
        accepted.anchor = Some(anchor);
        pending.clear_after_validated_publication();
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
            Some(PayloadReference::V2Commit { length, .. }) => {
                *length = (*length).saturating_sub(1);
            }
            Some(PayloadReference::V2Pack { length, .. }) => {
                *length = (*length).saturating_sub(1);
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

    fn pending_index_delta_sequence(&self) -> Result<Option<Sequence>> {
        self.pending
            .lock()
            .map_err(|_| RepositoryError::StatePoisoned)
            .map(|pending| pending.snapshot().commit_sequence())
    }

    fn pending_delta_sections_for_commit(
        &self,
        commit_key: &V2CommitKey,
        pending: &PendingV2Snapshot,
    ) -> Result<PendingV2CommitSections> {
        let keyring = self.repository.keyring()?;
        let mut sections = Vec::with_capacity(pending.payloads().len().saturating_add(1));
        let mut locations = Vec::with_capacity(pending.payloads().len());
        let mut next_offset = 0_u64;

        for (ordinal, pending) in pending.payloads().iter().enumerate() {
            let payload_id = Self::v2_payload_id(commit_key, ordinal)?;
            let payload = seal_streamable_payload_object(
                &keyring,
                &payload_id,
                &pending.body,
                self.payload_segment_size_for_object(pending.body.len()),
            )?;
            let payload_header =
                payload_header_reference(&parse_segmented_payload_header(&payload_id, &payload)?)?;
            let length = u64::try_from(payload.len())
                .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?;
            let section_digest = digest_v2_section(&payload);
            sections.push(V2CommitSection::new(
                V2SectionType::Payload,
                V2_SECTION_FLAG_MUST_UNDERSTAND,
                payload,
            ));
            locations.push(PendingV2PayloadLocation {
                manifest_id: pending.manifest_id.clone(),
                payload_id,
                payload_header,
                section_ordinal: u32::try_from(ordinal)
                    .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?,
                section_digest,
                sections_start: Self::sections_start_for_upload_mode(self.commit_upload_mode),
                offset: next_offset,
                length,
            });
            next_offset = next_offset
                .checked_add(length)
                .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))?;
        }

        let delta = self.pending_index_delta_for_commit(commit_key, &locations, pending)?;
        let (retention, legal_hold) = commit_protection_for_deltas(&delta.deltas);
        let sealed_delta = seal_index_delta_object(&keyring, &delta)?;
        let bytes = Bytes::from(index_delta_object_bytes(&sealed_delta)?);
        sections.push(V2CommitSection::new(
            V2SectionType::IndexDelta,
            V2_SECTION_FLAG_MUST_UNDERSTAND,
            bytes,
        ));

        Ok(PendingV2CommitSections {
            sections,
            locations,
            retention,
            legal_hold,
        })
    }

    fn pending_index_delta_for_commit(
        &self,
        commit_key: &V2CommitKey,
        locations: &[PendingV2PayloadLocation],
        pending: &PendingV2Snapshot,
    ) -> Result<IndexDeltaObject> {
        let mut deltas = pending.deltas().to_vec();
        for delta in &mut deltas {
            let IndexDelta::Upsert { entry, .. } = delta else {
                continue;
            };
            let Some(location) = locations
                .iter()
                .find(|location| location.manifest_id == entry.manifest_id)
            else {
                if matches!(entry.payload_ref, Some(PayloadReference::V2Self { .. })) {
                    return Err(v2_repository_error(V2FormatError::InvalidHeaderField));
                }
                continue;
            };
            entry.object_id = commit_key.object_id.clone();
            entry.object_version_id = None;
            entry.payload_ref = Some(PayloadReference::V2Self {
                payload_id: location.payload_id.clone(),
                payload_header: Some(location.payload_header.clone()),
                sections_start: location.sections_start,
                offset: location.offset,
                length: location.length,
            });
        }

        Ok(IndexDeltaObject {
            sequence: pending
                .commit_sequence()
                .ok_or_else(|| v2_repository_error(V2FormatError::InvalidHeaderField))?,
            deltas,
        })
    }

    fn resolve_pending_payload_refs(
        &self,
        pending: &mut PendingV2Snapshot,
        stored: &V2StoredCommit,
        locations: &[PendingV2PayloadLocation],
    ) -> Result<()> {
        let mut resolved_count = 0_usize;
        for delta in pending.deltas_mut() {
            let IndexDelta::Upsert { entry, .. } = delta else {
                continue;
            };
            let Some(location) = locations
                .iter()
                .find(|location| location.manifest_id == entry.manifest_id)
            else {
                continue;
            };
            entry.object_id = stored.anchor_state.commit_key.clone();
            entry.object_version_id = stored.anchor_state.version_id.clone();
            entry.payload_ref = Some(PayloadReference::V2Commit {
                commit_key: stored.anchor_state.commit_key.clone(),
                commit_version_id: stored.anchor_state.version_id.clone(),
                body_digest: stored.anchor_state.body_digest,
                commit_stored_len: stored.object_len,
                keyring_envelope_object_id: self
                    .commit_store
                    .options()
                    .keyring_envelope_ref
                    .object_id
                    .clone(),
                keyring_envelope_digest: self.commit_store.options().keyring_envelope_ref.digest,
                payload_section_ordinal: location.section_ordinal,
                payload_section_digest: location.section_digest,
                payload_id: location.payload_id.clone(),
                payload_header: Some(location.payload_header.clone()),
                sections_start: location.sections_start,
                offset: location.offset,
                length: location.length,
            });
            resolved_count = resolved_count.saturating_add(1);
        }
        let unresolved_self_refs = pending.deltas().iter().any(|delta| {
            matches!(
                delta,
                IndexDelta::Upsert { entry, .. }
                    if matches!(entry.payload_ref, Some(PayloadReference::V2Self { .. }))
            )
        });
        if resolved_count != locations.len() || unresolved_self_refs {
            return Err(v2_repository_error(V2FormatError::InvalidHeaderField));
        }
        Ok(())
    }

    fn payload_segment_size_for_object(&self, plaintext_len: usize) -> usize {
        if self.repository.options.adaptive_payload_segment_size {
            adaptive_payload_segment_size(
                plaintext_len,
                self.repository.options.payload_segment_size,
            )
        } else {
            self.repository.options.payload_segment_size
        }
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

    fn cached_commit_header(
        &self,
        key: &V2CommitHeaderCacheKey,
    ) -> Result<Option<V2ParsedCommitHeader>> {
        let header = self
            .commit_headers
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?
            .peek(key);
        if header.is_some()
            && let Ok(mut cache) = self.commit_headers.try_write()
        {
            cache.touch(key);
        }
        Ok(header)
    }

    fn cache_commit_header(
        &self,
        key: V2CommitHeaderCacheKey,
        header: V2ParsedCommitHeader,
    ) -> Result<()> {
        let mut cache = self
            .commit_headers
            .write()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        cache.insert(key, header);
        Ok(())
    }

    fn cache_verified_commit_header(&self, commit: &V2ParsedCommit) -> Result<()> {
        let key = V2CommitHeaderCacheKey {
            commit_key: commit.parsed_header.header.self_ref.commit_key.clone(),
            commit_version_id: commit.version_id.clone(),
            body_digest: commit.parsed_header.header.body_digest,
        };
        self.cache_commit_header(key, commit.parsed_header.clone())
    }

    fn cached_payload_header(
        &self,
        key: &V2PayloadSectionCacheKey,
    ) -> Result<Option<SegmentedPayloadHeader>> {
        let header = self
            .payload_headers
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?
            .peek(key);
        if header.is_some()
            && let Ok(mut cache) = self.payload_headers.try_write()
        {
            cache.touch(key);
        }
        Ok(header)
    }

    fn cache_payload_header(
        &self,
        key: V2PayloadSectionCacheKey,
        header: SegmentedPayloadHeader,
    ) -> Result<()> {
        let mut cache = self
            .payload_headers
            .write()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        cache.insert(key, header);
        Ok(())
    }

    fn apply_commit_sections(
        &self,
        state: &mut RepositoryState,
        commit: &V2ParsedCommit,
    ) -> Result<()> {
        self.cache_verified_commit_header(commit)?;
        for (index, section) in commit.parsed_header.header.section_index.iter().enumerate() {
            if section.flags & V2_SECTION_FLAG_COMPRESSED != 0 {
                return Err(v2_repository_error(V2FormatError::UnsupportedSection));
            }
            let section_bytes = commit_section_bytes(commit, index)?;
            match section.section_type {
                V2SectionType::IndexDelta => {
                    let mut delta = self.open_index_delta_section(
                        &commit.parsed_header.header.self_ref.commit_key,
                        index,
                        section_bytes,
                    )?;
                    resolve_self_payload_refs(&mut delta, commit)?;
                    self.repository
                        .load_embedded_manifest_records(state, &delta)?;
                    apply_index_delta_object(state, delta);
                }
                V2SectionType::IndexSnapshot if section_bytes.is_empty() => {
                    *state = RepositoryState::default();
                }
                V2SectionType::IndexSnapshot => {
                    let mut snapshot = self.open_index_delta_section(
                        &commit.parsed_header.header.self_ref.commit_key,
                        index,
                        section_bytes,
                    )?;
                    resolve_self_payload_refs(&mut snapshot, commit)?;
                    *state = RepositoryState::default();
                    self.repository
                        .load_embedded_manifest_records(state, &snapshot)?;
                    apply_index_delta_object(state, snapshot);
                }
                V2SectionType::Payload => {}
                V2SectionType::PayloadPack => {}
                V2SectionType::IndexRun => {
                    let keyring = self.repository.keyring()?;
                    packed::apply_packed_index_run(
                        keyring.as_ref(),
                        &self.commit_store.options().repository_id,
                        state,
                        packed::V2PackedIndexRunReplay {
                            parsed_header: &commit.parsed_header,
                            version_id: commit.version_id.as_ref(),
                            object_len: u64::try_from(commit.body.len())
                                .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?,
                            section_ordinal: u32::try_from(index)
                                .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?,
                            stored_run: section_bytes,
                            level: 0,
                            compaction_generation: 0,
                        },
                    )?;
                }
                V2SectionType::IndexRoot => {
                    return Err(v2_repository_error(V2FormatError::UnsupportedSection));
                }
                V2SectionType::Directives | V2SectionType::Unknown(_) => {
                    if section.flags & V2_SECTION_FLAG_MUST_UNDERSTAND != 0 {
                        return Err(v2_repository_error(V2FormatError::UnsupportedSection));
                    }
                }
            }
        }
        Ok(())
    }

    async fn apply_replay_commit_sections(
        &self,
        state: &mut RepositoryState,
        commit: &V2ReplayCommit,
    ) -> Result<Vec<V2IndexRootRunRef>> {
        let cache_key = V2CommitHeaderCacheKey {
            commit_key: commit.parsed_header.header.self_ref.commit_key.clone(),
            commit_version_id: commit.version_id.clone(),
            body_digest: commit.parsed_header.header.body_digest,
        };
        self.cache_commit_header(cache_key, commit.parsed_header.clone())?;

        let mut accepted_runs = Vec::new();
        for (index, section) in commit.parsed_header.header.section_index.iter().enumerate() {
            if section.flags & V2_SECTION_FLAG_COMPRESSED != 0 {
                return Err(v2_repository_error(V2FormatError::UnsupportedSection));
            }
            match section.section_type {
                V2SectionType::IndexDelta => {
                    let section_bytes = replay_section_bytes(commit, index)?;
                    let mut delta = self.open_index_delta_section(
                        &commit.parsed_header.header.self_ref.commit_key,
                        index,
                        section_bytes,
                    )?;
                    self.resolve_replay_payload_refs(&mut delta, commit).await?;
                    self.repository
                        .load_embedded_manifest_records(state, &delta)?;
                    apply_index_delta_object(state, delta);
                }
                V2SectionType::IndexSnapshot => {
                    let section_bytes = replay_section_bytes(commit, index)?;
                    *state = RepositoryState::default();
                    if !section_bytes.is_empty() {
                        let mut snapshot = self.open_index_delta_section(
                            &commit.parsed_header.header.self_ref.commit_key,
                            index,
                            section_bytes,
                        )?;
                        self.resolve_replay_payload_refs(&mut snapshot, commit)
                            .await?;
                        self.repository
                            .load_embedded_manifest_records(state, &snapshot)?;
                        apply_index_delta_object(state, snapshot);
                    }
                }
                V2SectionType::Payload | V2SectionType::PayloadPack => {}
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
                V2SectionType::Directives | V2SectionType::Unknown(_) => {
                    if section.flags & V2_SECTION_FLAG_MUST_UNDERSTAND != 0 {
                        return Err(v2_repository_error(V2FormatError::UnsupportedSection));
                    }
                }
            }
        }
        Ok(accepted_runs)
    }

    async fn resolve_replay_payload_refs(
        &self,
        delta: &mut IndexDeltaObject,
        commit: &V2ReplayCommit,
    ) -> Result<()> {
        for mutation in &mut delta.deltas {
            let IndexDelta::Upsert { entry, .. } = mutation else {
                continue;
            };
            let Some(PayloadReference::V2Self {
                payload_id,
                payload_header,
                sections_start: _,
                offset,
                length,
            }) = entry.payload_ref.clone()
            else {
                continue;
            };
            let (payload_section_ordinal, payload_section) =
                payload_section_descriptor_in_header(&commit.parsed_header, offset, length)?;
            let payload_header = match payload_header {
                Some(reference) => reference,
                None => {
                    let sections_start = u64::try_from(commit.parsed_header.sections_start)
                        .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?;
                    let payload_start = sections_start
                        .checked_add(offset)
                        .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))?;
                    let cache_key = V2PayloadSectionCacheKey {
                        commit_key: commit.parsed_header.header.self_ref.commit_key.clone(),
                        commit_version_id: commit.version_id.clone(),
                        body_digest: commit.parsed_header.header.body_digest,
                        payload_id: payload_id.clone(),
                        offset,
                        length,
                    };
                    let payload = V2CommitPayloadRead {
                        commit_key: commit.parsed_header.header.self_ref.commit_key.clone(),
                        commit_version_id: commit.version_id.clone(),
                        body_digest: commit.parsed_header.header.body_digest,
                        commit_stored_len: commit.object_len,
                        keyring_envelope_object_id: commit
                            .parsed_header
                            .header
                            .keyring_envelope_ref
                            .object_id
                            .clone(),
                        keyring_envelope_digest: commit
                            .parsed_header
                            .header
                            .keyring_envelope_ref
                            .digest,
                        payload_section_ordinal,
                        payload_section_digest: payload_section.digest,
                        payload_id: payload_id.clone(),
                        payload_header: None,
                        sections_start: Some(sections_start),
                        offset,
                        length,
                        content_len: entry.content_len,
                    };
                    let parsed = self
                        .read_payload_header_from_commit(&payload, payload_start, &cache_key)
                        .await?;
                    payload_header_reference(&parsed)?
                }
            };
            let parsed_payload_header = payload_header_from_reference(&payload_header)?;
            if parsed_payload_header.plaintext_len != entry.content_len
                || total_segmented_payload_len(&parsed_payload_header)? != length
            {
                return Err(RepositoryError::InvalidObjectFormat {
                    object_id: payload_id,
                });
            }
            let sections_start = u64::try_from(commit.parsed_header.sections_start)
                .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?;
            let commit_key = commit.parsed_header.header.self_ref.commit_key.clone();
            entry.object_id = commit_key.clone();
            entry.object_version_id = commit.version_id.clone();
            entry.payload_ref = Some(PayloadReference::V2Commit {
                commit_key,
                commit_version_id: commit.version_id.clone(),
                body_digest: commit.parsed_header.header.body_digest,
                commit_stored_len: commit.object_len,
                keyring_envelope_object_id: commit
                    .parsed_header
                    .header
                    .keyring_envelope_ref
                    .object_id
                    .clone(),
                keyring_envelope_digest: commit.parsed_header.header.keyring_envelope_ref.digest,
                payload_section_ordinal,
                payload_section_digest: payload_section.digest,
                payload_id,
                payload_header: Some(payload_header),
                sections_start: Some(sections_start),
                offset,
                length,
            });
        }
        Ok(())
    }

    fn open_index_delta_section(
        &self,
        commit_key: &BackendObjectId,
        section_index: usize,
        bytes: &[u8],
    ) -> Result<IndexDeltaObject> {
        let Some(payload) = bytes.strip_prefix(INDEX_DELTA_OBJECT_DOMAIN) else {
            return Err(v2_repository_error(V2FormatError::InvalidHeaderField));
        };
        let sealed_delta = serde_json::from_slice(payload)?;
        let object_id = BackendObjectId::new(format!(
            "{}/index-delta-{section_index}",
            commit_key.as_str()
        ))?;
        let keyring = self.repository.keyring()?;
        open_index_delta_object(&keyring, &object_id, &sealed_delta)
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

fn payload_header_reference(header: &SegmentedPayloadHeader) -> Result<PayloadHeaderReference> {
    Ok(PayloadHeaderReference {
        chunk_size: header.chunk_size,
        plaintext_len: header.plaintext_len,
        key_id: header.key_id.clone(),
        nonce_prefix: header.nonce_prefix,
        header_len: u64::try_from(header.header_len)
            .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?,
    })
}

fn payload_header_from_reference(
    reference: &PayloadHeaderReference,
) -> Result<SegmentedPayloadHeader> {
    Ok(SegmentedPayloadHeader {
        format: SegmentedPayloadFormat::Streamable,
        chunk_size: reference.chunk_size,
        plaintext_len: reference.plaintext_len,
        key_id: reference.key_id.clone(),
        nonce_prefix: reference.nonce_prefix,
        header_len: usize::try_from(reference.header_len)
            .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?,
    })
}

fn payload_fill_lock_index(payload_id: &BackendObjectId, start_segment: usize) -> usize {
    let mut digest = Sha256::new();
    digest.update(payload_id.as_str().as_bytes());
    digest.update((start_segment as u64).to_be_bytes());
    let digest = digest.finalize();
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    (u64::from_be_bytes(prefix) % V2_PAYLOAD_FILL_LOCK_STRIPES as u64) as usize
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct V2CommitHeaderCacheKey {
    commit_key: BackendObjectId,
    commit_version_id: Option<BackendVersionId>,
    body_digest: [u8; 32],
}

#[derive(Clone, Debug)]
struct V2CommitPayloadRead {
    commit_key: BackendObjectId,
    commit_version_id: Option<BackendVersionId>,
    body_digest: [u8; 32],
    commit_stored_len: u64,
    keyring_envelope_object_id: BackendObjectId,
    keyring_envelope_digest: [u8; 32],
    payload_section_ordinal: u32,
    payload_section_digest: [u8; 32],
    payload_id: BackendObjectId,
    payload_header: Option<PayloadHeaderReference>,
    sections_start: Option<u64>,
    offset: u64,
    length: u64,
    content_len: u64,
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
    content_key_id: rs3_types::KeyId,
    keyring_envelope_object_id: BackendObjectId,
    keyring_envelope_digest: [u8; 32],
    pack_record_count: u32,
    record_ordinal: u32,
    record_offset: u32,
    plaintext_digest: [u8; 32],
    content_len: u64,
}

fn pack_payload_cache_ref(
    pack: &V2CommitPackRead,
    repository_context: &[u8],
) -> Result<BackendObjectRef> {
    let mut digest = Sha256::new();
    digest.update(b"rs3:v02-pack-segment-cache:v2\n");
    update_cache_digest_field(&mut digest, repository_context)?;
    update_cache_digest_field(&mut digest, pack.commit_key.as_str().as_bytes())?;
    digest.update(pack.body_digest);
    digest.update(pack.commit_stored_len.to_be_bytes());
    digest.update(pack.pack_section_ordinal.to_be_bytes());
    digest.update(pack.pack_offset.to_be_bytes());
    digest.update(pack.length.to_be_bytes());
    digest.update(pack.pack_id);
    update_cache_digest_field(&mut digest, pack.content_key_id.as_str().as_bytes())?;
    update_cache_digest_field(
        &mut digest,
        pack.keyring_envelope_object_id.as_str().as_bytes(),
    )?;
    digest.update(pack.keyring_envelope_digest);
    digest.update(pack.pack_record_count.to_be_bytes());
    digest.update(pack.record_ordinal.to_be_bytes());
    digest.update(pack.record_offset.to_be_bytes());
    digest.update(pack.plaintext_digest);
    digest.update(pack.content_len.to_be_bytes());
    Ok(BackendObjectRef {
        object_id: BackendObjectId::new(format!(
            "v2-pack-cache/{}",
            hex::encode(digest.finalize())
        ))?,
        version_id: pack.commit_version_id.clone(),
    })
}

fn update_cache_digest_field(digest: &mut Sha256, value: &[u8]) -> Result<()> {
    let length = u64::try_from(value.len())
        .map_err(|_| v2_repository_error(V2FormatError::InvalidPayloadPack))?;
    digest.update(length.to_be_bytes());
    digest.update(value);
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct V2PayloadSectionCacheKey {
    commit_key: BackendObjectId,
    commit_version_id: Option<BackendVersionId>,
    body_digest: [u8; 32],
    payload_id: BackendObjectId,
    offset: u64,
    length: u64,
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

#[derive(Debug)]
struct V2CommitHeaderCache {
    headers: LruCache<V2CommitHeaderCacheKey, V2ParsedCommitHeader>,
    max_entries: usize,
}

impl Default for V2CommitHeaderCache {
    fn default() -> Self {
        Self {
            headers: LruCache::new(),
            max_entries: 4096,
        }
    }
}

impl V2CommitHeaderCache {
    fn peek(&self, key: &V2CommitHeaderCacheKey) -> Option<V2ParsedCommitHeader> {
        self.headers.peek_cloned(key)
    }

    fn touch(&mut self, key: &V2CommitHeaderCacheKey) {
        self.headers.touch(key);
    }

    fn insert(&mut self, key: V2CommitHeaderCacheKey, header: V2ParsedCommitHeader) {
        self.headers.insert(key, header);

        while self.headers.len() > self.max_entries {
            if self.headers.pop_lru().is_none() {
                break;
            };
        }
    }
}

#[derive(Debug)]
struct V2PayloadHeaderCache {
    headers: LruCache<V2PayloadSectionCacheKey, SegmentedPayloadHeader>,
    max_entries: usize,
}

impl Default for V2PayloadHeaderCache {
    fn default() -> Self {
        Self {
            headers: LruCache::new(),
            max_entries: 4096,
        }
    }
}

impl V2PayloadHeaderCache {
    fn peek(&self, key: &V2PayloadSectionCacheKey) -> Option<SegmentedPayloadHeader> {
        self.headers.peek_cloned(key)
    }

    fn touch(&mut self, key: &V2PayloadSectionCacheKey) {
        self.headers.touch(key);
    }

    fn insert(&mut self, key: V2PayloadSectionCacheKey, header: SegmentedPayloadHeader) {
        self.headers.insert(key, header);

        while self.headers.len() > self.max_entries {
            if self.headers.pop_lru().is_none() {
                break;
            };
        }
    }
}

fn commit_section_bytes(commit: &V2ParsedCommit, section_index: usize) -> Result<&[u8]> {
    let section = commit
        .parsed_header
        .header
        .section_index
        .get(section_index)
        .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))?;
    let section_region = commit
        .body
        .get(commit.parsed_header.sections_start..)
        .ok_or_else(|| v2_repository_error(V2FormatError::TruncatedBody))?;
    let start = usize::try_from(section.offset)
        .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?;
    let length = usize::try_from(section.length)
        .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?;
    let end = start
        .checked_add(length)
        .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))?;
    section_region
        .get(start..end)
        .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))
}

fn replay_section_bytes(commit: &V2ReplayCommit, section_index: usize) -> Result<&[u8]> {
    commit
        .retained_sections
        .get(section_index)
        .and_then(Option::as_deref)
        .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))
}

fn payload_section_bytes(commit: &V2ParsedCommit, offset: u64, length: u64) -> Result<&[u8]> {
    let section_region = commit
        .body
        .get(commit.parsed_header.sections_start..)
        .ok_or_else(|| v2_repository_error(V2FormatError::TruncatedBody))?;
    let start =
        usize::try_from(offset).map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?;
    let length =
        usize::try_from(length).map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?;
    let end = start
        .checked_add(length)
        .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))?;
    section_region
        .get(start..end)
        .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))
}

fn resolve_self_payload_refs(delta: &mut IndexDeltaObject, commit: &V2ParsedCommit) -> Result<()> {
    for mutation in &mut delta.deltas {
        let IndexDelta::Upsert { entry, .. } = mutation else {
            continue;
        };
        let Some(PayloadReference::V2Self {
            payload_id,
            payload_header,
            sections_start: _,
            offset,
            length,
        }) = entry.payload_ref.clone()
        else {
            continue;
        };
        let (payload_section_ordinal, payload_section) =
            payload_section_descriptor_in_header(&commit.parsed_header, offset, length)?;
        let payload_header = match payload_header {
            Some(reference) => reference,
            None => {
                let payload_bytes = payload_section_bytes(commit, offset, length)?;
                payload_header_reference(&parse_segmented_payload_header(
                    &payload_id,
                    payload_bytes,
                )?)?
            }
        };
        let parsed_payload_header = payload_header_from_reference(&payload_header)?;
        if parsed_payload_header.plaintext_len != entry.content_len
            || total_segmented_payload_len(&parsed_payload_header)? != length
        {
            return Err(RepositoryError::InvalidObjectFormat {
                object_id: payload_id.clone(),
            });
        }
        let sections_start = u64::try_from(commit.parsed_header.sections_start)
            .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?;
        let commit_key = commit.parsed_header.header.self_ref.commit_key.clone();
        entry.object_id = commit_key.clone();
        entry.object_version_id = commit.version_id.clone();
        entry.payload_ref = Some(PayloadReference::V2Commit {
            commit_key,
            commit_version_id: commit.version_id.clone(),
            body_digest: commit.parsed_header.header.body_digest,
            commit_stored_len: u64::try_from(commit.body.len())
                .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?,
            keyring_envelope_object_id: commit
                .parsed_header
                .header
                .keyring_envelope_ref
                .object_id
                .clone(),
            keyring_envelope_digest: commit.parsed_header.header.keyring_envelope_ref.digest,
            payload_section_ordinal,
            payload_section_digest: payload_section.digest,
            payload_id,
            payload_header: Some(payload_header),
            sections_start: Some(sections_start),
            offset,
            length,
        });
    }
    Ok(())
}

fn ensure_payload_header_matches_content_len(
    header: &SegmentedPayloadHeader,
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

fn payload_section_descriptor_in_header(
    header: &V2ParsedCommitHeader,
    offset: u64,
    length: u64,
) -> Result<(u32, &crate::v2::V2SectionDescriptor)> {
    header
        .header
        .section_index
        .iter()
        .enumerate()
        .find(|(_, section)| {
            section.section_type == V2SectionType::Payload
                && section.offset == offset
                && section.length == length
        })
        .map(|(ordinal, section)| {
            u32::try_from(ordinal)
                .map(|ordinal| (ordinal, section))
                .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))
        })
        .transpose()?
        .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))
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
            commit_key: object_id("commits/v02/opaque"),
            commit_version_id: Some(
                BackendVersionId::new("version-1").expect("test version ID should be valid"),
            ),
            body_digest: [1_u8; 32],
            commit_stored_len: 8_192,
            pack_section_ordinal: 2,
            pack_offset: 1_024,
            length: 4_096,
            pack_id: [2_u8; 32],
            content_key_id: key_id("content-1"),
            keyring_envelope_object_id: object_id("keyrings/envelope-1"),
            keyring_envelope_digest: [3_u8; 32],
            pack_record_count: 64,
            record_ordinal: 7,
            record_offset: 512,
            plaintext_digest: [4_u8; 32],
            content_len: 512,
        }
    }

    #[test]
    fn packed_segment_cache_identity_binds_every_record_context_fact() {
        let original = sample_pack_read();
        let mut variants = Vec::new();

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
        variant.plaintext_digest[0] ^= 1;
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
