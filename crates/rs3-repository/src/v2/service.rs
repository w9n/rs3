//! v2 repository operations over the existing trusted namespace service.

use super::commit::{V2_SECTION_FLAG_COMPRESSED, V2_SECTION_FLAG_MUST_UNDERSTAND, V2CommitKey};
use super::error::V2FormatError;
use super::repository::{
    V2CommitAnchor, V2CommitChain, V2CommitSection, V2CommitStore, V2CommitStoreOptions,
    V2CommitWrite, V2StoredCommit,
};
use super::{V2ParsedCommit, V2SectionType};
use crate::checkpoint::{open_index_delta_object, seal_index_delta_object, seal_manifest_record};
use crate::error::{RepositoryError, Result};
use crate::model::{
    DeleteOutcome, PhysicalDeleteOutcome, RepositoryListEntry, RepositoryObjectMetadata,
    RepositoryPutOptions,
};
use crate::namespace::{existing_blind_keys, first_namespace_entry, prefix_tokens_for_key};
use crate::payload::{adaptive_payload_segment_size, open_payload_object, seal_payload_object};
use crate::service::{Repository, RepositoryOptions, strongest_retention_policy};
use crate::state::{
    RepositoryState, TrustedManifest, apply_index_delta_object, next_sequence, object_material,
};
use bytes::Bytes;
use rs3_crypto::KeyRing;
use rs3_index::{
    INDEX_DELTA_OBJECT_DOMAIN, IndexDelta, IndexDeltaObject, NamespaceEntry, PayloadReference,
    index_delta_object_bytes,
};
use rs3_storage::{BlobStore, ByteRange};
use rs3_types::{
    BackendObjectId, LegalHoldStatus, LogicalPath, ManifestId, RetentionPolicy, Sequence,
};
use std::sync::Mutex as StdMutex;
use std::time::{SystemTime, UNIX_EPOCH};
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
    pending_payloads: StdMutex<Vec<PendingV2Payload>>,
}

#[derive(Clone, Debug)]
pub(crate) struct V2RepositorySnapshot {
    state: RepositoryState,
    pending_payloads: Vec<PendingV2Payload>,
}

#[derive(Clone, Debug)]
struct PendingV2Payload {
    manifest_id: ManifestId,
    body: Bytes,
}

#[derive(Clone, Debug)]
struct PendingV2PayloadLocation {
    manifest_id: ManifestId,
    offset: u64,
    length: u64,
}

struct PendingV2CommitSections {
    sections: Vec<V2CommitSection>,
    locations: Vec<PendingV2PayloadLocation>,
    retention: Option<RetentionPolicy>,
    legal_hold: Option<LegalHoldStatus>,
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
            pending_payloads: StdMutex::new(Vec::new()),
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
        let metadata = match self.stage_put(key, body, options).await {
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
        let plaintext_len =
            u64::try_from(body.len()).map_err(|_| RepositoryError::CommitFailed {
                reason: "payload length does not fit in u64".to_owned(),
            })?;
        let retention = strongest_retention_policy(
            self.repository.options.default_retention,
            options.retention,
        );
        let keyring = self.repository.keyring()?;
        let primary_blind_key = keyring.derive_primary_blind_index_key(&key)?;
        let lookup_blind_keys = keyring.derive_blind_index_keys_for_lookup(&key)?;
        let prefix_tokens =
            prefix_tokens_for_key(&keyring, &primary_blind_key.key_id, key.as_str())?;

        let (sequence, manifest_id, stale_blind_keys) = {
            let mut state = self.repository.write_state()?;
            let existing_blind_keys = existing_blind_keys(&state.namespace, &lookup_blind_keys);
            if options.create_only && !existing_blind_keys.is_empty() {
                return Err(RepositoryError::AlreadyExists(key));
            }

            let sequence = next_sequence(&mut state)?;
            let material = object_material(key.as_str(), sequence);
            let manifest_id = keyring.derive_manifest_id(&material)?;
            let stale_blind_keys = existing_blind_keys
                .into_iter()
                .filter(|blind_key| blind_key != &primary_blind_key.blind_key)
                .collect::<Vec<_>>();

            (sequence, manifest_id, stale_blind_keys)
        };

        let pending_object_id = BackendObjectId::new(format!("v2-pending/{}", sequence.get()))?;
        let modified_at_ms = current_time_ms();
        let entry = NamespaceEntry {
            namespace_key_id: primary_blind_key.key_id,
            blind_key: primary_blind_key.blind_key,
            object_id: pending_object_id,
            object_version_id: None,
            payload_ref: Some(PayloadReference::V2Self {
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

        {
            let mut state = self.repository.write_state()?;
            for stale_blind_key in stale_blind_keys {
                state.namespace.tombstone(stale_blind_key.clone(), sequence);
                state.pending_index_deltas.push(IndexDelta::Tombstone {
                    blind_key: stale_blind_key,
                    generation: sequence,
                });
            }
            state.pending_index_deltas.push(IndexDelta::Upsert {
                entry: Box::new(entry.clone()),
                prefix_tokens: prefix_tokens.clone(),
                sealed_manifest: Box::new(sealed_manifest),
            });
            state.namespace.upsert(entry, prefix_tokens);
            state
                .manifests
                .insert(manifest_id.clone(), manifest.clone());
        }
        self.pending_payloads
            .lock()
            .map_err(|_| RepositoryError::StatePoisoned)?
            .push(PendingV2Payload { manifest_id, body });

        tracing::info!(
            target: "rs3_repository",
            operation = "v2_stage_put",
            plaintext_len,
            sequence = sequence.get(),
            result = "ok",
            "repository operation completed",
        );
        Ok(manifest.into_metadata())
    }

    /// Reads trusted metadata for a client-visible object.
    pub fn head(&self, key: &LogicalPath) -> Result<RepositoryObjectMetadata> {
        self.repository.head(key)
    }

    /// Reads a client-visible object or byte range.
    pub async fn get_range(&self, key: &LogicalPath, range: ByteRange) -> Result<Bytes> {
        let keyring = self.repository.keyring()?;
        let lookup_blind_keys = keyring.derive_blind_index_keys_for_lookup(key)?;
        let entry = {
            let state = self.repository.read_state()?;
            first_namespace_entry(&state.namespace, &lookup_blind_keys)
                .cloned()
                .ok_or_else(|| RepositoryError::NotFound(key.clone()))?
        };
        let Some(PayloadReference::V2Commit {
            commit_key,
            commit_version_id,
            body_digest,
            offset,
            length,
        }) = entry.payload_ref
        else {
            return Err(RepositoryError::InvalidObjectFormat {
                object_id: entry.object_id,
            });
        };

        let commit = self
            .commit_store
            .read_commit_at(&commit_key, commit_version_id.as_ref())
            .await
            .map_err(v2_repository_error)?;
        if commit.parsed_header.header.body_digest != body_digest {
            return Err(v2_repository_error(V2FormatError::BodyDigestMismatch));
        }
        let payload = commit_payload_section_bytes(&commit, offset, length)?;
        open_payload_object(&keyring, &commit_key, payload, range)
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
        self.repository.tombstone_namespace_for_delete(&key)?;
        if let Err(error) = self.publish_pending_index_delta(anchor).await {
            self.restore_state_preserving_sequence(before)?;
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

    pub(crate) fn snapshot_state(&self) -> Result<V2RepositorySnapshot> {
        let state = self.repository.read_state()?.clone();
        let pending_payloads = self
            .pending_payloads
            .lock()
            .map_err(|_| RepositoryError::StatePoisoned)?
            .clone();
        Ok(V2RepositorySnapshot {
            state,
            pending_payloads,
        })
    }

    pub(crate) fn restore_state_preserving_sequence(
        &self,
        mut snapshot: V2RepositorySnapshot,
    ) -> Result<()> {
        let mut state = self.repository.write_state()?;
        snapshot.state.next_sequence = snapshot.state.next_sequence.max(state.next_sequence);
        *state = snapshot.state;
        *self
            .pending_payloads
            .lock()
            .map_err(|_| RepositoryError::StatePoisoned)? = snapshot.pending_payloads;
        Ok(())
    }

    pub(crate) async fn publish_pending_index_delta<A>(
        &self,
        anchor: &A,
    ) -> Result<Option<V2StoredCommit>>
    where
        A: V2CommitAnchor,
    {
        let Some(sequence) = self.pending_index_delta_sequence()? else {
            return Ok(None);
        };
        let pending_payloads = self
            .pending_payloads
            .lock()
            .map_err(|_| RepositoryError::StatePoisoned)?
            .clone();
        let mut accepted_locations = None;
        let stored = self
            .commit_store
            .write_child_commit_with(anchor, |commit_key| {
                let pending = self
                    .pending_delta_sections_for_commit(commit_key, &pending_payloads)
                    .map_err(|_| V2FormatError::InvalidHeaderField)?;
                accepted_locations = Some(pending.locations);
                let mut write =
                    V2CommitWrite::delta(pending.sections).with_retention(pending.retention);
                write = write.with_legal_hold(pending.legal_hold);
                Ok(write)
            })
            .await
            .map_err(v2_repository_error)?;
        let locations = accepted_locations
            .ok_or_else(|| v2_repository_error(V2FormatError::InvalidHeaderField))?;
        self.resolve_accepted_payload_refs(&stored.anchor_state, &locations)?;
        self.repository.mark_index_deltas_published(sequence)?;
        self.pending_payloads
            .lock()
            .map_err(|_| RepositoryError::StatePoisoned)?
            .clear();
        Ok(Some(stored))
    }

    fn pending_index_delta_sequence(&self) -> Result<Option<Sequence>> {
        let state = self.repository.read_state()?;
        Ok((!state.pending_index_deltas.is_empty()).then_some(state.next_sequence))
    }

    fn pending_delta_sections_for_commit(
        &self,
        commit_key: &V2CommitKey,
        pending_payloads: &[PendingV2Payload],
    ) -> Result<PendingV2CommitSections> {
        let keyring = self.repository.keyring()?;
        let mut sections = Vec::with_capacity(pending_payloads.len().saturating_add(1));
        let mut locations = Vec::with_capacity(pending_payloads.len());
        let mut next_offset = 0_u64;

        for pending in pending_payloads {
            let payload = seal_payload_object(
                &keyring,
                &commit_key.object_id,
                &pending.body,
                self.payload_segment_size_for_object(pending.body.len()),
            )?;
            let length = u64::try_from(payload.len())
                .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?;
            sections.push(V2CommitSection::new(
                V2SectionType::Payload,
                V2_SECTION_FLAG_MUST_UNDERSTAND,
                payload,
            ));
            locations.push(PendingV2PayloadLocation {
                manifest_id: pending.manifest_id.clone(),
                offset: next_offset,
                length,
            });
            next_offset = next_offset
                .checked_add(length)
                .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))?;
        }

        let delta = self.pending_index_delta_for_commit(commit_key, &locations)?;
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
    ) -> Result<IndexDeltaObject> {
        let state = self.repository.read_state()?;
        let mut deltas = state.pending_index_deltas.clone();
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
                offset: location.offset,
                length: location.length,
            });
        }

        Ok(IndexDeltaObject {
            sequence: state.next_sequence,
            deltas,
        })
    }

    fn resolve_accepted_payload_refs(
        &self,
        anchor_state: &super::repository::V2AnchorState,
        locations: &[PendingV2PayloadLocation],
    ) -> Result<()> {
        if locations.is_empty() {
            return Ok(());
        }

        let mut state = self.repository.write_state()?;
        let live_entries = state.namespace.live_entries_with_prefixes();
        let mut resolved_count = 0_usize;
        for (mut entry, prefix_tokens) in live_entries {
            let Some(location) = locations
                .iter()
                .find(|location| location.manifest_id == entry.manifest_id)
            else {
                continue;
            };
            entry.object_id = anchor_state.commit_key.clone();
            entry.object_version_id = anchor_state.version_id.clone();
            entry.payload_ref = Some(PayloadReference::V2Commit {
                commit_key: anchor_state.commit_key.clone(),
                commit_version_id: anchor_state.version_id.clone(),
                body_digest: anchor_state.body_digest,
                offset: location.offset,
                length: location.length,
            });
            state.namespace.upsert(entry, prefix_tokens);
            resolved_count = resolved_count.saturating_add(1);
        }

        let unresolved_live_self_refs = state
            .namespace
            .live_entries_with_prefixes()
            .into_iter()
            .any(|(entry, _)| matches!(entry.payload_ref, Some(PayloadReference::V2Self { .. })));
        if resolved_count == 0 || unresolved_live_self_refs {
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
                V2SectionType::Directives | V2SectionType::Unknown(_) => {
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
                    entry: Box::new(entry),
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

fn commit_payload_section_bytes(
    commit: &V2ParsedCommit,
    offset: u64,
    length: u64,
) -> Result<Bytes> {
    ensure_payload_section_declared(commit, offset, length)?;
    let absolute_start = u64::try_from(commit.parsed_header.sections_start)
        .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?
        .checked_add(offset)
        .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))?;
    let absolute_end = absolute_start
        .checked_add(length)
        .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))?;
    let start = usize::try_from(absolute_start)
        .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?;
    let end = usize::try_from(absolute_end)
        .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?;
    commit
        .body
        .get(start..end)
        .map(Bytes::copy_from_slice)
        .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))
}

fn resolve_self_payload_refs(delta: &mut IndexDeltaObject, commit: &V2ParsedCommit) -> Result<()> {
    for mutation in &mut delta.deltas {
        let IndexDelta::Upsert { entry, .. } = mutation else {
            continue;
        };
        let Some(PayloadReference::V2Self { offset, length }) = entry.payload_ref.clone() else {
            continue;
        };
        ensure_payload_section_declared(commit, offset, length)?;
        let commit_key = commit.parsed_header.header.self_ref.commit_key.clone();
        entry.object_id = commit_key.clone();
        entry.object_version_id = commit.version_id.clone();
        entry.payload_ref = Some(PayloadReference::V2Commit {
            commit_key,
            commit_version_id: commit.version_id.clone(),
            body_digest: commit.parsed_header.header.body_digest,
            offset,
            length,
        });
    }
    Ok(())
}

fn ensure_payload_section_declared(
    commit: &V2ParsedCommit,
    offset: u64,
    length: u64,
) -> Result<()> {
    let found = commit
        .parsed_header
        .header
        .section_index
        .iter()
        .any(|section| {
            section.section_type == V2SectionType::Payload
                && section.offset == offset
                && section.length == length
        });
    if found {
        Ok(())
    } else {
        Err(v2_repository_error(V2FormatError::SectionBounds))
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
    RepositoryError::CommitFailed {
        reason: error.to_string(),
    }
}
