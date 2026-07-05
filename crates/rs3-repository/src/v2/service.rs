//! v2 repository operations over the existing trusted namespace service.

use super::commit::{V2_SECTION_FLAG_COMPRESSED, V2_SECTION_FLAG_MUST_UNDERSTAND, V2CommitKey};
use super::error::V2FormatError;
use super::repository::{
    V2CommitAnchor, V2CommitChain, V2CommitSection, V2CommitStore, V2CommitStoreOptions,
    V2CommitWrite, V2FinalizedStreamingPayloadWrite, V2StoredCommit, V2StreamingPayloadWrite,
};
use super::{
    V2_MAX_HEADER_SIZE, V2ParsedCommit, V2ParsedCommitHeader, V2SectionType, V2UploadMode,
};
use crate::checkpoint::{open_index_delta_object, seal_index_delta_object, seal_manifest_record};
use crate::error::{RepositoryError, Result};
use crate::lru::LruCache;
use crate::model::{
    DeleteOutcome, PhysicalDeleteOutcome, RepositoryListEntry, RepositoryObjectMetadata,
    RepositoryPutOptions,
};
use crate::namespace::{existing_blind_keys, first_namespace_entry, prefix_tokens_for_key};
use crate::payload::{
    PayloadHeaderProbe, SegmentedPayloadFormat, SegmentedPayloadHeader, SegmentedPayloadSealer,
    adaptive_payload_segment_size, open_payload_object, parse_segmented_payload_header,
    probe_payload_header, seal_streamable_payload_object, segmented_ciphertext_span,
    total_segmented_payload_len,
};
use crate::service::{Repository, RepositoryOptions, strongest_retention_policy};
use crate::state::{
    RepositoryState, TrustedManifest, apply_index_delta_object, next_sequence, object_material,
};
use bytes::Bytes;
use futures_util::Stream;
use rs3_crypto::KeyRing;
use rs3_index::{
    INDEX_DELTA_OBJECT_DOMAIN, IndexDelta, IndexDeltaObject, NamespaceEntry,
    PayloadHeaderReference, PayloadReference, index_delta_object_bytes,
};
use rs3_storage::{BlobStore, ByteRange};
use rs3_types::{
    BackendObjectId, BackendObjectRef, BackendVersionId, LegalHoldStatus, LogicalPath, ManifestId,
    RetentionPolicy, Sequence,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::marker::PhantomData;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex as StdMutex, RwLock as StdRwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

mod compaction;

const V2_PAYLOAD_FILL_LOCK_STRIPES: usize = 64;

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
    accepted_state: StdRwLock<RepositoryState>,
    mutation_lock: Mutex<()>,
    payload_segment_fill_locks: Vec<Mutex<()>>,
    pending_payloads: StdMutex<Vec<PendingV2Payload>>,
    payload_sections: StdRwLock<V2PayloadSectionCache>,
    commit_headers: StdRwLock<V2CommitHeaderCache>,
    payload_headers: StdRwLock<V2PayloadHeaderCache>,
    #[cfg(test)]
    fail_next_restore: AtomicBool,
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
    payload_id: BackendObjectId,
    payload_header: PayloadHeaderReference,
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
}

struct StreamingV2PutFinalized {
    staged: StagedV2Put,
    location: PendingV2PayloadLocation,
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
            accepted_state: StdRwLock::new(RepositoryState::default()),
            mutation_lock: Mutex::new(()),
            payload_segment_fill_locks: (0..V2_PAYLOAD_FILL_LOCK_STRIPES)
                .map(|_| Mutex::new(()))
                .collect(),
            pending_payloads: StdMutex::new(Vec::new()),
            payload_sections: StdRwLock::new(V2PayloadSectionCache::with_max_bytes(
                payload_section_cache_max_bytes,
            )),
            commit_headers: StdRwLock::new(V2CommitHeaderCache::default()),
            payload_headers: StdRwLock::new(V2PayloadHeaderCache::default()),
            #[cfg(test)]
            fail_next_restore: AtomicBool::new(false),
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
        let chain = self
            .commit_store
            .load_chain_from_anchor(anchor)
            .await
            .map_err(v2_repository_error)?
            .ok_or_else(|| v2_repository_error(V2FormatError::MissingAnchor))?;
        self.ensure_index_snapshot_payload_refs_are_chain_reachable(&chain)?;
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
        let rebuilt = self.replay_chain_to_state(chain)?;
        let accepted = rebuilt.clone();
        let mut state = self.repository.write_state()?;
        *state = rebuilt;
        *self
            .accepted_state
            .write()
            .map_err(|_| RepositoryError::StatePoisoned)? = accepted;
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
        let _guard = self.mutation_lock.lock().await;
        let before = self.snapshot_state()?;
        let staged = match self.stage_put_metadata(key, plaintext_len, options).await {
            Ok(staged) => staged,
            Err(error) => {
                self.restore_state_preserving_sequence(before)?;
                return Err(error);
            }
        };
        let keyring = self.repository.keyring()?;
        let staged_content_len = staged.content_len;
        let staged_manifest_id = staged.manifest_id.clone();
        let staged_retention = staged.metadata.retention;
        let staged_legal_hold = staged.metadata.legal_hold;
        let stored = self
            .commit_store
            .write_child_commit_with_streaming_payload(anchor, |commit_key| {
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
                    sections_start: Self::sections_start_for_upload_mode(self.commit_upload_mode),
                    offset: 0,
                    length: payload_len,
                };
                let commit_key = commit_key.clone();
                let finalizer_keyring = keyring.clone();
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
                        let delta = self
                            .pending_index_delta_for_commit(
                                &commit_key,
                                std::slice::from_ref(&expected_location),
                            )
                            .map_err(|_| V2FormatError::InvalidHeaderField)?;
                        let sealed_delta = seal_index_delta_object(&finalizer_keyring, &delta)
                            .map_err(|_| V2FormatError::InvalidHeaderField)?;
                        let index_delta = Bytes::from(
                            index_delta_object_bytes(&sealed_delta)
                                .map_err(|_| V2FormatError::InvalidHeaderField)?,
                        );
                        Ok(V2FinalizedStreamingPayloadWrite {
                            index_delta,
                            output: expected_location,
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
        let stored = match stored {
            Ok(stored) => stored,
            Err(error) => {
                self.restore_state_preserving_sequence(before)?;
                return Err(error);
            }
        };
        self.resolve_accepted_payload_refs(&stored.stored.anchor_state, &[stored.output])?;
        self.repository
            .mark_index_deltas_published(stored.stored.anchor_state.sequence)?;
        self.accept_current_state()?;
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
        let _guard = self.mutation_lock.lock().await;
        let before = self.snapshot_state()?;
        if let Err(error) = self.ensure_put_create_allowed(&key, &options) {
            self.restore_state_preserving_sequence(before)?;
            return Err(error);
        }
        let keyring = self.repository.keyring()?;
        let payload_segment_size = self.payload_segment_size_for_object_len(max_plaintext_len)?;
        let upload_retention = strongest_retention_policy(
            self.repository.options.default_retention,
            options.retention,
        );
        let upload_legal_hold = options.legal_hold;
        let stored = self
            .commit_store
            .write_child_commit_with_streaming_payload(anchor, |commit_key| {
                let payload_id =
                    Self::v2_payload_id(commit_key, 0).map_err(|_| V2FormatError::SectionBounds)?;
                let payload_sealer = SegmentedPayloadSealer::new(&keyring, payload_segment_size)
                    .map_err(|_| V2FormatError::InvalidHeaderField)?;
                let commit_key = commit_key.clone();
                let finalizer_keyring = keyring.clone();
                let key = key.clone();
                let options = options.clone();
                let payload_id_for_location = payload_id.clone();
                let finalize =
                    move |input: super::repository::V2StreamingPayloadFinalizationInput| {
                        let staged = self
                            .stage_put_metadata_sync(key, input.plaintext_len, options)
                            .map_err(|error| match error {
                                RepositoryError::ObjectTooLarge => V2FormatError::ObjectTooLarge,
                                _ => V2FormatError::InvalidHeaderField,
                            })?;
                        let payload_header = payload_header_reference(&input.payload_header)
                            .map_err(|_| V2FormatError::InvalidHeaderField)?;
                        if payload_header.plaintext_len != staged.content_len {
                            return Err(V2FormatError::ObjectLengthMismatch);
                        }
                        let location = PendingV2PayloadLocation {
                            manifest_id: staged.manifest_id.clone(),
                            payload_id: payload_id_for_location,
                            payload_header,
                            sections_start: Self::sections_start_for_upload_mode(
                                self.commit_upload_mode,
                            ),
                            offset: 0,
                            length: input.payload_len,
                        };
                        let delta = self
                            .pending_index_delta_for_commit(
                                &commit_key,
                                std::slice::from_ref(&location),
                            )
                            .map_err(|_| V2FormatError::InvalidHeaderField)?;
                        let sealed_delta = seal_index_delta_object(&finalizer_keyring, &delta)
                            .map_err(|_| V2FormatError::InvalidHeaderField)?;
                        let index_delta = Bytes::from(
                            index_delta_object_bytes(&sealed_delta)
                                .map_err(|_| V2FormatError::InvalidHeaderField)?,
                        );
                        Ok(V2FinalizedStreamingPayloadWrite {
                            index_delta,
                            output: StreamingV2PutFinalized { staged, location },
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
        let stored = match stored {
            Ok(stored) => stored,
            Err(error) => {
                self.restore_state_preserving_sequence(before)?;
                return Err(error);
            }
        };
        self.resolve_accepted_payload_refs(
            &stored.stored.anchor_state,
            std::slice::from_ref(&stored.output.location),
        )?;
        self.repository
            .mark_index_deltas_published(stored.stored.anchor_state.sequence)?;
        self.accept_current_state()?;
        Ok(stored.output.staged.metadata)
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
        let staged = self.stage_put_metadata(key, plaintext_len, options).await?;
        self.pending_payloads
            .lock()
            .map_err(|_| RepositoryError::StatePoisoned)?
            .push(PendingV2Payload {
                manifest_id: staged.manifest_id,
                body,
            });

        Ok(staged.metadata)
    }

    async fn stage_put_metadata(
        &self,
        key: LogicalPath,
        plaintext_len: u64,
        options: RepositoryPutOptions,
    ) -> Result<StagedV2Put> {
        self.stage_put_metadata_sync(key, plaintext_len, options)
    }

    fn stage_put_metadata_sync(
        &self,
        key: LogicalPath,
        plaintext_len: u64,
        options: RepositoryPutOptions,
    ) -> Result<StagedV2Put> {
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

        {
            let mut state = self.repository.write_state()?;
            for stale_blind_key in stale_blind_keys {
                state.tombstone_namespace_entry(stale_blind_key.clone(), sequence);
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
            state
                .manifests
                .insert(manifest_id.clone(), manifest.clone());
            state.upsert_namespace_entry(entry, prefix_tokens);
        }

        tracing::info!(
            target: "rs3_repository",
            operation = "v2_stage_put",
            plaintext_len,
            sequence = sequence.get(),
            result = "ok",
            "repository operation completed",
        );
        Ok(StagedV2Put {
            metadata: manifest.into_metadata(),
            manifest_id,
            content_len: plaintext_len,
        })
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
        let state = self.repository.read_state()?;
        if existing_blind_keys(&state.namespace, &lookup_blind_keys).is_empty() {
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
            .accepted_state
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        let entry = first_namespace_entry(&state.namespace, &lookup_blind_keys)
            .cloned()
            .ok_or_else(|| RepositoryError::NotFound(key.clone()))?;
        let manifest = state
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
        let Some(PayloadReference::V2Commit {
            commit_key,
            commit_version_id,
            body_digest,
            payload_id,
            payload_header,
            sections_start,
            offset,
            length,
        }) = entry.payload_ref
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
                ensure_payload_section_declared_in_header(&header, payload.offset, payload.length)?;
                u64::try_from(header.sections_start)
                    .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?
            }
        };
        let payload_start = sections_start
            .checked_add(payload.offset)
            .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))?;

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
        let payload_cache_ref = BackendObjectRef {
            object_id: payload.payload_id.clone(),
            version_id: payload.commit_version_id.clone(),
        };
        if let Some(plaintext) = self.repository.open_cached_decrypted_segments(
            &payload_cache_ref,
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
            &payload_cache_ref,
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
            &payload_cache_ref,
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
        let header_len = match probe_payload_header(&payload.payload_id, &initial)? {
            PayloadHeaderProbe::Segmented { header_len } => header_len,
            PayloadHeaderProbe::NeedMore { len } => {
                if len > payload.length {
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
                let parsed = parse_segmented_payload_header(&payload.payload_id, &header)?;
                self.cache_payload_header(cache_key.clone(), parsed.clone())?;
                return Ok(parsed);
            }
        };
        let parsed = parse_segmented_payload_header(&payload.payload_id, &initial[..header_len])?;
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
            .accepted_state
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        Ok(state.list_page(prefix, start_after, limit))
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
        #[cfg(test)]
        if self.fail_next_restore.swap(false, Ordering::SeqCst) {
            return Err(RepositoryError::StatePoisoned);
        }

        let mut state = self.repository.write_state()?;
        snapshot.state.next_sequence = snapshot.state.next_sequence.max(state.next_sequence);
        *state = snapshot.state;
        *self
            .pending_payloads
            .lock()
            .map_err(|_| RepositoryError::StatePoisoned)? = snapshot.pending_payloads;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn fail_next_restore_for_tests(&self) {
        self.fail_next_restore.store(true, Ordering::SeqCst);
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
        self.accept_current_state()?;
        self.pending_payloads
            .lock()
            .map_err(|_| RepositoryError::StatePoisoned)?
            .clear();
        Ok(Some(stored))
    }

    fn accept_current_state(&self) -> Result<()> {
        let state = self.repository.read_state()?.clone();
        *self
            .accepted_state
            .write()
            .map_err(|_| RepositoryError::StatePoisoned)? = state;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn shorten_accepted_payload_section_for_tests(
        &self,
        content_len: u64,
    ) -> Result<()> {
        let mut state = self
            .accepted_state
            .write()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        let Some((mut entry, prefix_tokens)) = state
            .namespace
            .live_entries_with_prefixes()
            .into_iter()
            .find(|(entry, _)| entry.content_len == content_len)
        else {
            return Err(RepositoryError::StatePoisoned);
        };
        match entry.payload_ref.as_mut() {
            Some(PayloadReference::V2Commit { length, .. }) => {
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
        let mut state = self
            .accepted_state
            .write()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        let Some((mut entry, prefix_tokens)) = state
            .namespace
            .live_entries_with_prefixes()
            .into_iter()
            .find(|(entry, _)| entry.content_len == content_len)
        else {
            return Err(RepositoryError::StatePoisoned);
        };
        entry.content_len = entry.content_len.saturating_sub(1);
        state.replace_namespace_entry(entry, prefix_tokens);
        Ok(())
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

        for (ordinal, pending) in pending_payloads.iter().enumerate() {
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
            sections.push(V2CommitSection::new(
                V2SectionType::Payload,
                V2_SECTION_FLAG_MUST_UNDERSTAND,
                payload,
            ));
            locations.push(PendingV2PayloadLocation {
                manifest_id: pending.manifest_id.clone(),
                payload_id,
                payload_header,
                sections_start: Self::sections_start_for_upload_mode(self.commit_upload_mode),
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
                payload_id: location.payload_id.clone(),
                payload_header: Some(location.payload_header.clone()),
                sections_start: location.sections_start,
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
                payload_id: location.payload_id.clone(),
                payload_header: Some(location.payload_header.clone()),
                sections_start: location.sections_start,
                offset: location.offset,
                length: location.length,
            });
            state.replace_namespace_entry(entry, prefix_tokens);
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

    fn ensure_index_snapshot_payload_refs_are_chain_reachable(
        &self,
        chain: &V2CommitChain,
    ) -> Result<()> {
        let reachable = chain
            .commits_newest_first
            .iter()
            .map(|commit| {
                (
                    commit.parsed_header.header.self_ref.commit_key.clone(),
                    commit.version_id.clone(),
                )
            })
            .collect::<BTreeSet<_>>();
        let state = self
            .accepted_state
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?;

        for (entry, _) in state.namespace.live_entries_with_prefixes() {
            let Some(PayloadReference::V2Commit {
                commit_key,
                commit_version_id,
                ..
            }) = entry.payload_ref
            else {
                continue;
            };
            if !reachable.contains(&(commit_key, commit_version_id)) {
                return Err(RepositoryError::CommitFailed {
                    reason: "v2 index snapshot would preserve live payloads outside the snapshot chain; run v2 compaction snapshot instead".to_owned(),
                });
            }
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
    payload_id: BackendObjectId,
    payload_header: Option<PayloadHeaderReference>,
    sections_start: Option<u64>,
    offset: u64,
    length: u64,
    content_len: u64,
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
        ensure_payload_section_declared(commit, offset, length)?;
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

fn ensure_payload_section_declared(
    commit: &V2ParsedCommit,
    offset: u64,
    length: u64,
) -> Result<()> {
    ensure_payload_section_declared_in_header(&commit.parsed_header, offset, length)
}

fn ensure_payload_section_declared_in_header(
    header: &V2ParsedCommitHeader,
    offset: u64,
    length: u64,
) -> Result<()> {
    let found = header.header.section_index.iter().any(|section| {
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
