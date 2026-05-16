//! v2 repository operations over the existing trusted namespace service.

use super::commit::{V2_SECTION_FLAG_COMPRESSED, V2_SECTION_FLAG_MUST_UNDERSTAND};
use super::error::V2FormatError;
use super::repository::{
    V2CommitAnchor, V2CommitChain, V2CommitSection, V2CommitStore, V2CommitStoreOptions,
    V2CommitWrite, V2StoredCommit,
};
use super::{V2ParsedCommit, V2SectionType};
use crate::checkpoint::{open_index_delta_object, seal_index_delta_object, seal_manifest_record};
use crate::error::{RepositoryError, Result};
use crate::model::{
    DeleteOutcome, RepositoryListEntry, RepositoryObjectMetadata, RepositoryPutOptions,
};
use crate::service::{Repository, RepositoryOptions};
use crate::state::{RepositoryState, apply_index_delta_object};
use bytes::Bytes;
use rs3_crypto::KeyRing;
use rs3_index::{
    INDEX_DELTA_OBJECT_DOMAIN, IndexDelta, IndexDeltaObject, index_delta_object_bytes,
};
use rs3_storage::{BlobStore, ByteRange};
use rs3_types::{BackendObjectId, LegalHoldStatus, LogicalPath, Sequence};
use tokio::sync::Mutex;

/// Preview v2 repository service.
///
/// This adapter deliberately reuses the existing trusted repository service for
/// path-private namespace indexing, payload encryption, range reads, and list
/// semantics. v2 only changes how the pending sealed index delta becomes
/// durable: it is embedded in a signed v2 commit instead of a v1 checkpoint.
pub struct V2Repository<S> {
    repository: Repository<S>,
    commit_store: V2CommitStore<S>,
    mutation_lock: Mutex<()>,
}

struct PendingV2IndexDelta {
    sequence: Sequence,
    section: V2CommitSection,
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
        Self {
            repository: Repository::with_keyring_and_options(
                store.clone(),
                keyring.clone(),
                repository_options,
            ),
            commit_store: V2CommitStore::new(store, keyring, commit_options),
            mutation_lock: Mutex::new(()),
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
        self.commit_store
            .write_genesis_snapshot(anchor)
            .await
            .map_err(v2_repository_error)
    }

    /// Writes a full namespace snapshot commit from the current trusted state.
    pub async fn write_index_snapshot<A>(&self, anchor: &A) -> Result<V2StoredCommit>
    where
        A: V2CommitAnchor,
    {
        let _guard = self.mutation_lock.lock().await;
        self.publish_pending_index_delta(anchor).await?;
        let section = self.index_snapshot_section()?;
        self.commit_store
            .write_child_commit(anchor, V2CommitWrite::snapshot(vec![section]))
            .await
            .map_err(v2_repository_error)
    }

    /// Loads and replays the commit chain selected by the v2 anchor.
    pub async fn load_chain_from_anchor<A>(&self, anchor: &A) -> Result<Option<V2CommitChain>>
    where
        A: V2CommitAnchor,
    {
        let chain = self
            .commit_store
            .load_chain_from_anchor(anchor)
            .await
            .map_err(v2_repository_error)?;
        if let Some(chain) = chain.as_ref() {
            self.replay_chain(chain)?;
        }
        Ok(chain)
    }

    /// Loads and replays a supplied v2 commit chain.
    pub fn replay_chain(&self, chain: &V2CommitChain) -> Result<()> {
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

        let mut state = self.repository.write_state()?;
        *state = rebuilt;
        Ok(())
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
        let _guard = self.mutation_lock.lock().await;
        let before = self.snapshot_state()?;
        let metadata = match self.repository.put(key, body, options).await {
            Ok(metadata) => metadata,
            Err(error) => {
                self.restore_state_preserving_sequence(before)?;
                return Err(error);
            }
        };
        if let Err(error) = self.publish_pending_index_delta(anchor).await {
            self.restore_state_preserving_sequence(before)?;
            return Err(error);
        }
        Ok(metadata)
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
    ) -> Result<RepositoryObjectMetadata> {
        self.repository.put(key, body, options).await
    }

    /// Reads trusted metadata for a client-visible object.
    pub fn head(&self, key: &LogicalPath) -> Result<RepositoryObjectMetadata> {
        self.repository.head(key)
    }

    /// Reads a client-visible object or byte range.
    pub async fn get_range(&self, key: &LogicalPath, range: ByteRange) -> Result<Bytes> {
        self.repository.get_range(key, range).await
    }

    /// Lists client-visible entries for a prefix.
    pub fn list(&self, prefix: &str) -> Result<Vec<RepositoryListEntry>> {
        self.repository.list(prefix)
    }

    /// Deletes a client-visible object after the tombstone commit is accepted.
    pub async fn delete_committed<A>(&self, anchor: &A, key: LogicalPath) -> Result<DeleteOutcome>
    where
        A: V2CommitAnchor,
    {
        let _guard = self.mutation_lock.lock().await;
        let before = self.snapshot_state()?;
        let object_id = self.repository.tombstone_namespace_for_delete(&key)?;
        if let Err(error) = self.publish_pending_index_delta(anchor).await {
            self.restore_state_preserving_sequence(before)?;
            return Err(error);
        }
        let physical = self.repository.delete_backend_object(&object_id).await?;
        Ok(DeleteOutcome { physical })
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
        let _guard = self.mutation_lock.lock().await;
        let before = self.snapshot_state()?;
        let metadata = match self.repository.set_legal_hold(&key, status).await {
            Ok(metadata) => metadata,
            Err(error) => {
                self.restore_state_preserving_sequence(before)?;
                return Err(error);
            }
        };
        if let Err(error) = self.publish_pending_index_delta(anchor).await {
            self.restore_state_preserving_sequence(before)?;
            return Err(error);
        }
        Ok(metadata)
    }

    pub(crate) fn snapshot_state(&self) -> Result<RepositoryState> {
        self.repository.read_state().map(|state| state.clone())
    }

    pub(crate) fn restore_state_preserving_sequence(
        &self,
        mut snapshot: RepositoryState,
    ) -> Result<()> {
        let mut state = self.repository.write_state()?;
        snapshot.next_sequence = snapshot.next_sequence.max(state.next_sequence);
        *state = snapshot;
        Ok(())
    }

    pub(crate) async fn publish_pending_index_delta<A>(
        &self,
        anchor: &A,
    ) -> Result<Option<V2StoredCommit>>
    where
        A: V2CommitAnchor,
    {
        let Some(pending) = self.pending_index_delta_section()? else {
            return Ok(None);
        };
        let stored = self
            .commit_store
            .write_child_commit(anchor, V2CommitWrite::delta(vec![pending.section]))
            .await
            .map_err(v2_repository_error)?;
        self.repository
            .mark_index_deltas_published(pending.sequence)?;
        Ok(Some(stored))
    }

    fn pending_index_delta_section(&self) -> Result<Option<PendingV2IndexDelta>> {
        let Some(sealed_delta) = self.repository.pending_index_delta_object()? else {
            return Ok(None);
        };
        let sequence = self.repository.read_state()?.next_sequence;
        let bytes = Bytes::from(index_delta_object_bytes(&sealed_delta)?);
        Ok(Some(PendingV2IndexDelta {
            sequence,
            section: V2CommitSection::new(
                V2SectionType::IndexDelta,
                V2_SECTION_FLAG_MUST_UNDERSTAND,
                bytes,
            ),
        }))
    }

    fn apply_commit_sections(
        &self,
        state: &mut RepositoryState,
        commit: &V2ParsedCommit,
    ) -> Result<()> {
        for (index, section) in commit.parsed_header.header.section_index.iter().enumerate() {
            if section.flags & V2_SECTION_FLAG_COMPRESSED != 0 {
                return Err(v2_repository_error(V2FormatError::UnsupportedSection));
            }
            let section_bytes = commit_section_bytes(commit, index)?;
            match section.section_type {
                V2SectionType::IndexDelta => {
                    let delta = self.open_index_delta_section(
                        &commit.parsed_header.header.self_ref.commit_key,
                        index,
                        section_bytes,
                    )?;
                    self.repository
                        .load_embedded_manifest_records(state, &delta)?;
                    apply_index_delta_object(state, delta);
                }
                V2SectionType::IndexSnapshot if section_bytes.is_empty() => {
                    *state = RepositoryState::default();
                }
                V2SectionType::IndexSnapshot => {
                    let snapshot = self.open_index_delta_section(
                        &commit.parsed_header.header.self_ref.commit_key,
                        index,
                        section_bytes,
                    )?;
                    *state = RepositoryState::default();
                    self.repository
                        .load_embedded_manifest_records(state, &snapshot)?;
                    apply_index_delta_object(state, snapshot);
                }
                V2SectionType::Payload | V2SectionType::Directives | V2SectionType::Unknown(_) => {
                    if section.flags & V2_SECTION_FLAG_MUST_UNDERSTAND != 0 {
                        return Err(v2_repository_error(V2FormatError::UnsupportedSection));
                    }
                }
            }
        }
        Ok(())
    }

    fn index_snapshot_section(&self) -> Result<V2CommitSection> {
        let keyring = self.repository.keyring()?;
        let snapshot = {
            let state = self.repository.read_state()?;
            let mut deltas = Vec::new();
            for (entry, prefix_tokens) in state.namespace.live_entries_with_prefixes() {
                let manifest = state.manifests.get(&entry.manifest_id).ok_or_else(|| {
                    RepositoryError::InvalidObjectFormat {
                        object_id: entry.object_id.clone(),
                    }
                })?;
                let sealed_manifest = seal_manifest_record(&keyring, &entry.manifest_id, manifest)?;
                deltas.push(IndexDelta::Upsert {
                    entry,
                    prefix_tokens,
                    sealed_manifest: Box::new(sealed_manifest),
                });
            }
            IndexDeltaObject {
                sequence: state.next_sequence,
                deltas,
            }
        };
        let sealed_snapshot = seal_index_delta_object(&keyring, &snapshot)?;
        let bytes = Bytes::from(index_delta_object_bytes(&sealed_snapshot)?);
        Ok(V2CommitSection::new(
            V2SectionType::IndexSnapshot,
            V2_SECTION_FLAG_MUST_UNDERSTAND,
            bytes,
        ))
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

fn v2_repository_error(error: V2FormatError) -> RepositoryError {
    RepositoryError::CommitFailed {
        reason: error.to_string(),
    }
}
