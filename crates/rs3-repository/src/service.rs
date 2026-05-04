//! Repository service implementation.

use crate::checkpoint::seal_manifest_record;
use crate::error::{RepositoryError, Result};
use crate::model::{
    CommittedPut, DeleteOutcome, PhysicalDeleteOutcome, RepositoryListEntry,
    RepositoryObjectMetadata, RepositoryPutOptions,
};
use crate::namespace::{
    existing_blind_keys, first_namespace_entry, indexed_list_prefix, indexed_list_prefix_mode,
    prefix_tokens_for_key,
};
use crate::payload::{
    DEFAULT_PAYLOAD_SEGMENT_SIZE, PAYLOAD_HEADER_PROBE_LEN, PayloadHeaderProbe,
    SegmentCiphertextSpan, SegmentedPayloadHeader, open_payload_object,
    open_segmented_payload_span, parse_segmented_payload_header, probe_payload_header,
    seal_payload_object, segmented_ciphertext_span,
};
use crate::state::{RepositoryState, TrustedManifest, next_sequence, object_material};
use bytes::Bytes;
use rs3_anchor::CheckpointAnchor;
use rs3_crypto::{KeyRing, NamespaceBlindKey, RepositoryKeyContext, SecretBytes};
use rs3_index::{IndexDelta, KeyringEnvelopeReference, NamespaceEntry};
use rs3_storage::{BlobStore, ByteRange, PutOptions, StorageError};
use rs3_types::{BackendObjectId, LegalHoldStatus, LogicalPath, RetentionMode, RetentionPolicy};
use std::collections::{BTreeMap, VecDeque, btree_map::Entry};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Trusted repository service.
pub struct Repository<S> {
    pub(crate) store: S,
    pub(crate) keyring: RwLock<KeyRing>,
    pub(crate) keyring_envelope: RwLock<Option<KeyringEnvelopeReference>>,
    pub(crate) state: RwLock<RepositoryState>,
    pub(crate) options: RepositoryOptions,
    payload_headers: RwLock<PayloadHeaderCache>,
    payload_spans: RwLock<PayloadSpanCache>,
}

/// Repository runtime options.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepositoryOptions {
    /// Plaintext bytes per independently encrypted payload segment.
    pub payload_segment_size: usize,
    /// Default provider retention policy for repository-owned objects.
    pub default_retention: Option<RetentionPolicy>,
}

impl Default for RepositoryOptions {
    fn default() -> Self {
        Self {
            payload_segment_size: DEFAULT_PAYLOAD_SEGMENT_SIZE,
            default_retention: None,
        }
    }
}

impl<S> Repository<S>
where
    S: BlobStore,
{
    /// Creates a trusted repository service over a blob store.
    ///
    /// The provided secret is a repository master key. Purpose-specific
    /// namespace, content, metadata, and checkpoint keys are derived from it.
    pub fn new(store: S, master_key: SecretBytes) -> Self {
        match Self::from_master_key(store, master_key) {
            Ok(repository) => repository,
            Err(error) => unreachable!("repository master key derivation is infallible: {error}"),
        }
    }

    /// Creates a trusted repository service from a repository master key.
    ///
    /// This compatibility helper uses the legacy default repository context.
    /// Production gateway paths should use [`Self::from_master_key_context`].
    pub fn from_master_key(store: S, master_key: SecretBytes) -> Result<Self> {
        let keyring = KeyRing::from_repository_master_key(&master_key)?;
        Ok(Self::with_keyring(store, keyring))
    }

    /// Creates a trusted repository service from a bound repository key context.
    pub fn from_master_key_context(
        store: S,
        master_key: SecretBytes,
        context: &RepositoryKeyContext,
    ) -> Result<Self> {
        let keyring = KeyRing::from_repository_master_key_for_context(&master_key, context)?;
        Ok(Self::with_keyring(store, keyring))
    }

    /// Creates a trusted repository service with an explicit keyring.
    pub fn with_keyring(store: S, keyring: KeyRing) -> Self {
        Self::with_keyring_and_options(store, keyring, RepositoryOptions::default())
    }

    /// Creates a trusted repository service with an explicit keyring and options.
    pub fn with_keyring_and_options(
        store: S,
        keyring: KeyRing,
        options: RepositoryOptions,
    ) -> Self {
        Self {
            store,
            keyring: RwLock::new(keyring),
            keyring_envelope: RwLock::new(None),
            state: RwLock::new(RepositoryState::default()),
            options,
            payload_headers: RwLock::new(PayloadHeaderCache::default()),
            payload_spans: RwLock::new(PayloadSpanCache::default()),
        }
    }

    /// Replaces the active keyring after a validated rotation update.
    pub fn replace_keyring(&self, keyring: KeyRing) -> Result<()> {
        let mut active = self
            .keyring
            .write()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        *active = keyring;
        Ok(())
    }

    /// Stages a client-visible object and writes its backend payload.
    ///
    /// The staged mutation becomes crash-durable repository state only after an
    /// accepted checkpoint covers it.
    pub async fn put(
        &self,
        key: LogicalPath,
        body: Bytes,
        options: RepositoryPutOptions,
    ) -> Result<RepositoryObjectMetadata> {
        let started = Instant::now();
        let plaintext_len = u64::try_from(body.len())
            .map_err(|_| StorageError::Provider("payload length does not fit in u64".to_owned()))?;
        let create_only = options.create_only;
        let retention =
            strongest_retention_policy(self.options.default_retention, options.retention);
        let requested_retention = retention.is_some();
        let legal_hold = options.legal_hold;
        let requested_legal_hold = legal_hold == Some(LegalHoldStatus::On);
        let keyring = self.keyring()?;
        let primary_blind_key = keyring.derive_primary_blind_index_key(&key)?;
        let lookup_blind_keys = keyring.derive_blind_index_keys_for_lookup(&key)?;
        let prefix_tokens =
            prefix_tokens_for_key(&keyring, &primary_blind_key.key_id, key.as_str())?;

        let (sequence, object_id, manifest_id, stale_blind_keys) = {
            let mut state = self.write_state()?;
            let existing_blind_keys = existing_blind_keys(&state.namespace, &lookup_blind_keys);
            if options.create_only && !existing_blind_keys.is_empty() {
                record_repository_put(RepositoryPutTrace {
                    plaintext_len,
                    backend_len: 0,
                    sequence: 0,
                    stale_entries: existing_blind_keys.len(),
                    create_only,
                    requested_retention,
                    requested_legal_hold,
                    result: "already_exists",
                    elapsed: started.elapsed(),
                });
                return Err(RepositoryError::AlreadyExists(key));
            }

            let sequence = next_sequence(&mut state)?;
            let material = object_material(key.as_str(), sequence);
            let object_id = keyring.derive_backend_object_id("segments", &material)?;
            let manifest_id = keyring.derive_manifest_id(&material)?;
            let stale_blind_keys = existing_blind_keys
                .into_iter()
                .filter(|blind_key| blind_key != &primary_blind_key.blind_key)
                .collect::<Vec<_>>();

            (sequence, object_id, manifest_id, stale_blind_keys)
        };

        let payload = seal_payload_object(
            &keyring,
            &object_id,
            &body,
            self.options.payload_segment_size,
        )?;
        let storage_metadata = self
            .store
            .put(
                &object_id,
                payload,
                PutOptions {
                    retention,
                    legal_hold,
                    content_type: None,
                    do_not_recreate: true,
                },
            )
            .await?;

        let modified_at_ms = modified_at_ms_or_now(storage_metadata.modified_at_ms, sequence);
        let entry = NamespaceEntry {
            namespace_key_id: primary_blind_key.key_id,
            blind_key: primary_blind_key.blind_key,
            object_id,
            manifest_id: manifest_id.clone(),
            content_len: plaintext_len,
            modified_at_ms,
            generation: sequence,
            retention: storage_metadata.retention,
            legal_hold: storage_metadata.legal_hold,
        };
        let manifest = TrustedManifest {
            key: key.clone(),
            content_len: plaintext_len,
            modified_at_ms,
            retention: storage_metadata.retention,
            legal_hold: storage_metadata.legal_hold,
        };
        let sealed_manifest = seal_manifest_record(&keyring, &manifest_id, &manifest)?;
        let stale_entries = stale_blind_keys.len();

        {
            let mut state = self.write_state()?;
            for stale_blind_key in stale_blind_keys {
                state.namespace.tombstone(stale_blind_key.clone(), sequence);
                state.pending_index_deltas.push(IndexDelta::Tombstone {
                    blind_key: stale_blind_key,
                    generation: sequence,
                });
            }
            state.pending_index_deltas.push(IndexDelta::Upsert {
                entry: entry.clone(),
                prefix_tokens: prefix_tokens.clone(),
                sealed_manifest: Box::new(sealed_manifest),
            });
            state.namespace.upsert(entry, prefix_tokens);
            state.manifests.insert(manifest_id, manifest.clone());
        }

        record_repository_put(RepositoryPutTrace {
            plaintext_len,
            backend_len: storage_metadata.content_len,
            sequence: sequence.get(),
            stale_entries,
            create_only,
            requested_retention,
            requested_legal_hold,
            result: "ok",
            elapsed: started.elapsed(),
        });
        Ok(manifest.into_metadata())
    }

    /// Writes a client-visible object and publishes the covering checkpoint.
    pub async fn put_committed<A>(
        &self,
        key: LogicalPath,
        body: Bytes,
        options: RepositoryPutOptions,
        anchor: &A,
    ) -> Result<CommittedPut>
    where
        A: CheckpointAnchor,
    {
        let started = Instant::now();
        let plaintext_len = body.len();
        let metadata = self.put(key, body, options).await?;
        let checkpoint = self.publish_checkpoint(anchor).await?;

        tracing::info!(
            target: "rs3_repository",
            operation = "put_committed",
            result = "ok",
            plaintext_len,
            checkpoint_sequence = checkpoint.sequence.get(),
            elapsed_us = elapsed_us(started.elapsed()),
            "repository operation completed",
        );
        Ok(CommittedPut {
            metadata,
            checkpoint,
        })
    }

    /// Applies legal hold and publishes the covering checkpoint before returning.
    pub async fn set_legal_hold_committed<A>(
        &self,
        key: &LogicalPath,
        status: LegalHoldStatus,
        anchor: &A,
    ) -> Result<RepositoryObjectMetadata>
    where
        A: CheckpointAnchor,
    {
        let metadata = self.set_legal_hold(key, status).await?;
        self.publish_checkpoint(anchor).await?;
        Ok(metadata)
    }

    /// Reads trusted metadata for a client-visible object.
    pub fn head(&self, key: &LogicalPath) -> Result<RepositoryObjectMetadata> {
        let started = Instant::now();
        let keyring = match self.keyring() {
            Ok(keyring) => keyring,
            Err(error) => {
                record_repository_head("keyring_error", started.elapsed());
                return Err(error);
            }
        };
        let lookup_blind_keys = match keyring.derive_blind_index_keys_for_lookup(key) {
            Ok(lookup_blind_keys) => lookup_blind_keys,
            Err(error) => {
                record_repository_head("lookup_error", started.elapsed());
                return Err(error.into());
            }
        };
        let state = match self.read_state() {
            Ok(state) => state,
            Err(error) => {
                record_repository_head("state_error", started.elapsed());
                return Err(error);
            }
        };
        let Some(entry) = first_namespace_entry(&state.namespace, &lookup_blind_keys) else {
            record_repository_head("not_found", started.elapsed());
            return Err(RepositoryError::NotFound(key.clone()));
        };
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

        record_repository_head("ok", started.elapsed());
        Ok(manifest.into_metadata())
    }

    /// Reads a client-visible object or byte range.
    pub async fn get_range(&self, key: &LogicalPath, range: ByteRange) -> Result<Bytes> {
        let started = Instant::now();
        let keyring = self.keyring()?;
        let lookup_blind_keys = keyring.derive_blind_index_keys_for_lookup(key)?;
        let object_id = match self.object_id_for_candidates(key, &lookup_blind_keys) {
            Ok(object_id) => object_id,
            Err(error) => {
                record_repository_get(range, 0, 0, "not_found", started.elapsed());
                return Err(error);
            }
        };
        let read = match self.read_payload_range(&keyring, &object_id, range).await {
            Ok(read) => read,
            Err(error) => {
                record_repository_get(range, 0, 0, "storage_error", started.elapsed());
                return Err(error);
            }
        };
        match read.opened {
            Ok(plaintext) => {
                let returned_len = u64::try_from(plaintext.len()).unwrap_or(u64::MAX);
                record_repository_get(
                    range,
                    read.backend_bytes_read,
                    returned_len,
                    "ok",
                    started.elapsed(),
                );
                Ok(plaintext)
            }
            Err(error) => {
                record_repository_get(
                    range,
                    read.backend_bytes_read,
                    0,
                    "open_error",
                    started.elapsed(),
                );
                Err(error)
            }
        }
    }

    async fn read_payload_range(
        &self,
        keyring: &KeyRing,
        object_id: &BackendObjectId,
        range: ByteRange,
    ) -> Result<PayloadRead> {
        match range {
            ByteRange::Full => self.read_payload_full(keyring, object_id, range).await,
            ByteRange::Slice { .. } => self.read_payload_slice(keyring, object_id, range).await,
        }
    }

    async fn read_payload_full(
        &self,
        keyring: &KeyRing,
        object_id: &BackendObjectId,
        range: ByteRange,
    ) -> Result<PayloadRead> {
        let body = self.store.get_range(object_id, ByteRange::Full).await?;
        let backend_bytes_read = u64::try_from(body.len()).unwrap_or(u64::MAX);
        Ok(PayloadRead {
            backend_bytes_read,
            opened: open_payload_object(keyring, object_id, body, range),
        })
    }

    async fn read_payload_slice(
        &self,
        keyring: &KeyRing,
        object_id: &BackendObjectId,
        range: ByteRange,
    ) -> Result<PayloadRead> {
        let header = match self.cached_payload_header(object_id)? {
            Some(header) => header,
            None => match self
                .read_and_cache_payload_header(keyring, object_id, range)
                .await?
            {
                PayloadHeaderRead::Header(header) => header,
                PayloadHeaderRead::Full(read) => return Ok(read),
            },
        };
        let span = segmented_ciphertext_span(&header.header, range)?;
        let span_read = self
            .read_ciphertext_span(object_id, span, header.prefetched_body.as_ref())
            .await?;
        let backend_bytes_read = header
            .backend_bytes_read
            .saturating_add(span_read.backend_bytes_read);

        Ok(PayloadRead {
            backend_bytes_read,
            opened: open_segmented_payload_span(
                keyring,
                object_id,
                &header.header,
                range,
                span,
                span_read.ciphertext,
            ),
        })
    }

    async fn read_ciphertext_span(
        &self,
        object_id: &BackendObjectId,
        span: SegmentCiphertextSpan,
        prefetched_body: Option<&Bytes>,
    ) -> Result<CiphertextSpanRead> {
        if span.len == 0 {
            return Ok(CiphertextSpanRead {
                backend_bytes_read: 0,
                ciphertext: Bytes::new(),
            });
        }

        if let Some(ciphertext) = self.cached_payload_span(object_id, span)? {
            record_payload_span_cache("hit", span.len);
            return Ok(CiphertextSpanRead {
                backend_bytes_read: 0,
                ciphertext,
            });
        }
        record_payload_span_cache("miss", span.len);

        if let Some(prefetched) = prefetched_body {
            let prefetched_len = u64::try_from(prefetched.len()).unwrap_or(u64::MAX);
            let span_end = span
                .offset
                .checked_add(span.len)
                .ok_or(StorageError::InvalidRange)?;
            if span_end <= prefetched_len {
                let start = usize::try_from(span.offset).map_err(|_| StorageError::InvalidRange)?;
                let end = usize::try_from(span_end).map_err(|_| StorageError::InvalidRange)?;
                let ciphertext = prefetched.slice(start..end);
                self.cache_payload_span(object_id, span, ciphertext.clone())?;
                return Ok(CiphertextSpanRead {
                    backend_bytes_read: 0,
                    ciphertext,
                });
            }

            if span.offset < prefetched_len {
                let prefix_len = prefetched_len
                    .checked_sub(span.offset)
                    .ok_or(StorageError::InvalidRange)?
                    .min(span.len);
                let suffix_offset = span
                    .offset
                    .checked_add(prefix_len)
                    .ok_or(StorageError::InvalidRange)?;
                let suffix_len = span
                    .len
                    .checked_sub(prefix_len)
                    .ok_or(StorageError::InvalidRange)?;
                let suffix = self
                    .store
                    .get_range(
                        object_id,
                        ByteRange::Slice {
                            offset: suffix_offset,
                            len: suffix_len,
                        },
                    )
                    .await?;
                let mut ciphertext = Vec::with_capacity(
                    usize::try_from(span.len).map_err(|_| StorageError::InvalidRange)?,
                );
                let prefix_start =
                    usize::try_from(span.offset).map_err(|_| StorageError::InvalidRange)?;
                ciphertext.extend_from_slice(&prefetched[prefix_start..]);
                ciphertext.extend_from_slice(&suffix);
                let ciphertext = Bytes::from(ciphertext);
                self.cache_payload_span(object_id, span, ciphertext.clone())?;
                return Ok(CiphertextSpanRead {
                    backend_bytes_read: u64::try_from(suffix.len()).unwrap_or(u64::MAX),
                    ciphertext,
                });
            }
        }

        let ciphertext = self
            .store
            .get_range(
                object_id,
                ByteRange::Slice {
                    offset: span.offset,
                    len: span.len,
                },
            )
            .await?;
        self.cache_payload_span(object_id, span, ciphertext.clone())?;
        Ok(CiphertextSpanRead {
            backend_bytes_read: u64::try_from(ciphertext.len()).unwrap_or(u64::MAX),
            ciphertext,
        })
    }

    async fn read_and_cache_payload_header(
        &self,
        keyring: &KeyRing,
        object_id: &BackendObjectId,
        range: ByteRange,
    ) -> Result<PayloadHeaderRead> {
        let probe = match self
            .store
            .get_range(
                object_id,
                ByteRange::Slice {
                    offset: 0,
                    len: PAYLOAD_HEADER_PROBE_LEN,
                },
            )
            .await
        {
            Ok(probe) => probe,
            Err(StorageError::InvalidRange) => {
                return Ok(PayloadHeaderRead::Full(
                    self.read_payload_full(keyring, object_id, range).await?,
                ));
            }
            Err(error) => return Err(error.into()),
        };
        let mut backend_bytes_read = u64::try_from(probe.len()).unwrap_or(u64::MAX);
        let (header_bytes, prefetched_body) = match probe_payload_header(object_id, &probe)? {
            PayloadHeaderProbe::Segmented { header_len } => (probe.slice(..header_len), probe),
            PayloadHeaderProbe::NeedMore { len } => {
                let header = self
                    .store
                    .get_range(object_id, ByteRange::Slice { offset: 0, len })
                    .await?;
                backend_bytes_read = backend_bytes_read
                    .saturating_add(u64::try_from(header.len()).unwrap_or(u64::MAX));
                match probe_payload_header(object_id, &header)? {
                    PayloadHeaderProbe::Segmented { header_len } => {
                        (header.slice(..header_len), header)
                    }
                    PayloadHeaderProbe::NeedMore { .. } => {
                        return Err(RepositoryError::InvalidObjectFormat {
                            object_id: object_id.clone(),
                        });
                    }
                }
            }
        };
        let header = parse_segmented_payload_header(object_id, &header_bytes)?;
        self.cache_payload_header(object_id, header.clone())?;

        Ok(PayloadHeaderRead::Header(CachedPayloadHeader {
            backend_bytes_read,
            header,
            prefetched_body: Some(prefetched_body),
        }))
    }

    fn cached_payload_header(
        &self,
        object_id: &BackendObjectId,
    ) -> Result<Option<CachedPayloadHeader>> {
        let cache = self
            .payload_headers
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        Ok(cache.get(object_id).map(|header| CachedPayloadHeader {
            backend_bytes_read: 0,
            header,
            prefetched_body: None,
        }))
    }

    fn cache_payload_header(
        &self,
        object_id: &BackendObjectId,
        header: SegmentedPayloadHeader,
    ) -> Result<()> {
        let mut cache = self
            .payload_headers
            .write()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        cache.insert(object_id.clone(), header);
        Ok(())
    }

    fn cached_payload_span(
        &self,
        object_id: &BackendObjectId,
        span: SegmentCiphertextSpan,
    ) -> Result<Option<Bytes>> {
        let cache = self
            .payload_spans
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        Ok(cache.get(object_id, span))
    }

    fn cache_payload_span(
        &self,
        object_id: &BackendObjectId,
        span: SegmentCiphertextSpan,
        ciphertext: Bytes,
    ) -> Result<()> {
        let mut cache = self
            .payload_spans
            .write()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        let outcome = cache.insert(object_id.clone(), span, ciphertext);
        match outcome {
            PayloadSpanCacheInsert::Inserted {
                bytes,
                evicted_entries,
                evicted_bytes,
            } => {
                record_payload_span_cache("insert", bytes);
                record_payload_span_cache_many("evict", evicted_entries, evicted_bytes);
            }
            PayloadSpanCacheInsert::SkippedTooLarge { bytes } => {
                record_payload_span_cache("skip_too_large", bytes);
            }
        }
        Ok(())
    }

    /// Lists client-visible entries for a prefix.
    pub fn list(&self, prefix: &str) -> Result<Vec<RepositoryListEntry>> {
        let started = Instant::now();
        let prefix_mode = indexed_list_prefix_mode(prefix).as_str();
        let keyring = match self.keyring() {
            Ok(keyring) => keyring,
            Err(error) => {
                record_repository_list(RepositoryListTrace {
                    prefix_mode,
                    lookup_token_count: 0,
                    candidate_count: 0,
                    manifest_miss_count: 0,
                    prefix_miss_count: 0,
                    returned_count: 0,
                    result: "keyring_error",
                    elapsed: started.elapsed(),
                });
                return Err(error);
            }
        };
        let prefix_tokens =
            match keyring.derive_prefix_tokens_for_lookup(indexed_list_prefix(prefix)) {
                Ok(prefix_tokens) => prefix_tokens,
                Err(error) => {
                    record_repository_list(RepositoryListTrace {
                        prefix_mode,
                        lookup_token_count: 0,
                        candidate_count: 0,
                        manifest_miss_count: 0,
                        prefix_miss_count: 0,
                        returned_count: 0,
                        result: "lookup_error",
                        elapsed: started.elapsed(),
                    });
                    return Err(error.into());
                }
            };
        let lookup_token_count = prefix_tokens.len();
        let state = match self.read_state() {
            Ok(state) => state,
            Err(error) => {
                record_repository_list(RepositoryListTrace {
                    prefix_mode,
                    lookup_token_count,
                    candidate_count: 0,
                    manifest_miss_count: 0,
                    prefix_miss_count: 0,
                    returned_count: 0,
                    result: "state_error",
                    elapsed: started.elapsed(),
                });
                return Err(error);
            }
        };
        let mut entries_by_key = BTreeMap::new();
        let mut candidate_count = 0_usize;
        let mut manifest_miss_count = 0_usize;
        let mut prefix_miss_count = 0_usize;

        for prefix_token in prefix_tokens {
            for entry in state.namespace.list_prefix(&prefix_token.prefix_token) {
                candidate_count = candidate_count.saturating_add(1);
                let Some(manifest) = state.manifests.get(&entry.manifest_id) else {
                    manifest_miss_count = manifest_miss_count.saturating_add(1);
                    continue;
                };
                if !manifest.key.as_str().starts_with(prefix) {
                    prefix_miss_count = prefix_miss_count.saturating_add(1);
                    continue;
                }

                let list_entry = RepositoryListEntry {
                    key: manifest.key.clone(),
                    content_len: manifest.content_len,
                    modified_at_ms: manifest.modified_at_ms,
                };

                match entries_by_key.entry(manifest.key.clone()) {
                    Entry::Vacant(slot) => {
                        slot.insert(list_entry);
                    }
                    Entry::Occupied(mut slot) => {
                        if list_entry.modified_at_ms >= slot.get().modified_at_ms {
                            slot.insert(list_entry);
                        }
                    }
                }
            }
        }

        let returned_count = entries_by_key.len();
        record_repository_list(RepositoryListTrace {
            prefix_mode,
            lookup_token_count,
            candidate_count,
            manifest_miss_count,
            prefix_miss_count,
            returned_count,
            result: "ok",
            elapsed: started.elapsed(),
        });

        Ok(entries_by_key.into_values().collect())
    }

    /// Deletes a client-visible object from the trusted namespace.
    pub async fn delete(&self, key: &LogicalPath) -> Result<DeleteOutcome> {
        let object_id = self.tombstone_namespace_for_delete(key)?;
        let physical = self.delete_backend_object(&object_id).await?;

        Ok(DeleteOutcome { physical })
    }

    /// Deletes a client-visible object and publishes the covering checkpoint before cleanup.
    pub async fn delete_committed<A>(&self, key: &LogicalPath, anchor: &A) -> Result<DeleteOutcome>
    where
        A: CheckpointAnchor,
    {
        let object_id = self.tombstone_namespace_for_delete(key)?;
        self.publish_checkpoint(anchor).await?;
        let physical = self.delete_backend_object(&object_id).await?;

        Ok(DeleteOutcome { physical })
    }

    fn tombstone_namespace_for_delete(&self, key: &LogicalPath) -> Result<BackendObjectId> {
        let keyring = self.keyring()?;
        let lookup_blind_keys = keyring.derive_blind_index_keys_for_lookup(key)?;
        let mut state = self.write_state()?;
        let entry = first_namespace_entry(&state.namespace, &lookup_blind_keys)
            .ok_or_else(|| RepositoryError::NotFound(key.clone()))?
            .clone();
        let object_id = entry.object_id.clone();
        let existing_blind_keys = existing_blind_keys(&state.namespace, &lookup_blind_keys);
        let sequence = next_sequence(&mut state)?;
        for blind_key in existing_blind_keys {
            state.namespace.tombstone(blind_key.clone(), sequence);
            state.pending_index_deltas.push(IndexDelta::Tombstone {
                blind_key,
                generation: sequence,
            });
        }

        Ok(object_id)
    }

    async fn delete_backend_object(
        &self,
        object_id: &BackendObjectId,
    ) -> Result<PhysicalDeleteOutcome> {
        Ok(match self.store.delete(object_id).await {
            Ok(()) => PhysicalDeleteOutcome::Removed,
            Err(StorageError::RetentionBlocked | StorageError::LegalHoldBlocked) => {
                PhysicalDeleteOutcome::Retained
            }
            Err(StorageError::NotFound(_)) => PhysicalDeleteOutcome::AlreadyGone,
            Err(error) => return Err(error.into()),
        })
    }

    /// Extends retention for a client-visible object and its backend payload.
    pub async fn extend_retention(
        &self,
        key: &LogicalPath,
        policy: RetentionPolicy,
    ) -> Result<RepositoryObjectMetadata> {
        let keyring = self.keyring()?;
        let lookup_blind_keys = keyring.derive_blind_index_keys_for_lookup(key)?;
        let object_id = self.object_id_for_candidates(key, &lookup_blind_keys)?;
        self.store.extend_retention(&object_id, policy).await?;
        let backend = self.store.head(&object_id).await?;

        let mut state = self.write_state()?;
        let entry = first_namespace_entry(&state.namespace, &lookup_blind_keys)
            .ok_or_else(|| RepositoryError::NotFound(key.clone()))?
            .clone();
        let content_len = state
            .manifests
            .get(&entry.manifest_id)
            .map(|manifest| manifest.content_len)
            .unwrap_or(entry.content_len);
        let sequence = next_sequence(&mut state)?;
        let material = object_material(key.as_str(), sequence);
        let manifest_id = keyring.derive_manifest_id(&material)?;
        let mut updated = entry;
        updated.manifest_id = manifest_id.clone();
        updated.generation = sequence;
        updated.retention = backend.retention;
        updated.legal_hold = backend.legal_hold.or(updated.legal_hold);
        let prefix_tokens =
            prefix_tokens_for_key(&keyring, &updated.namespace_key_id, key.as_str())?;
        let manifest = TrustedManifest {
            key: key.clone(),
            content_len,
            modified_at_ms: modified_at_ms_or_now(backend.modified_at_ms, sequence),
            retention: backend.retention,
            legal_hold: updated.legal_hold,
        };
        let sealed_manifest = seal_manifest_record(&keyring, &manifest_id, &manifest)?;
        state.pending_index_deltas.push(IndexDelta::Upsert {
            entry: updated.clone(),
            prefix_tokens: prefix_tokens.clone(),
            sealed_manifest: Box::new(sealed_manifest),
        });
        state.namespace.upsert(updated.clone(), prefix_tokens);
        state.manifests.insert(manifest_id, manifest.clone());

        Ok(manifest.into_metadata())
    }

    /// Applies legal hold for a client-visible object and its backend payload.
    pub async fn set_legal_hold(
        &self,
        key: &LogicalPath,
        status: LegalHoldStatus,
    ) -> Result<RepositoryObjectMetadata> {
        let keyring = self.keyring()?;
        let lookup_blind_keys = keyring.derive_blind_index_keys_for_lookup(key)?;
        let object_id = self.object_id_for_candidates(key, &lookup_blind_keys)?;
        self.store.set_legal_hold(&object_id, status).await?;
        let backend = self.store.head(&object_id).await?;

        let mut state = self.write_state()?;
        let entry = first_namespace_entry(&state.namespace, &lookup_blind_keys)
            .ok_or_else(|| RepositoryError::NotFound(key.clone()))?
            .clone();
        let content_len = state
            .manifests
            .get(&entry.manifest_id)
            .map(|manifest| manifest.content_len)
            .unwrap_or(entry.content_len);
        let retention = state
            .manifests
            .get(&entry.manifest_id)
            .map(|manifest| manifest.retention)
            .unwrap_or(entry.retention);
        let sequence = next_sequence(&mut state)?;
        let material = object_material(key.as_str(), sequence);
        let manifest_id = keyring.derive_manifest_id(&material)?;
        let mut updated = entry;
        updated.manifest_id = manifest_id.clone();
        updated.generation = sequence;
        updated.retention = retention;
        updated.legal_hold = backend.legal_hold.or(Some(status));
        let prefix_tokens =
            prefix_tokens_for_key(&keyring, &updated.namespace_key_id, key.as_str())?;
        let manifest = TrustedManifest {
            key: key.clone(),
            content_len,
            modified_at_ms: modified_at_ms_or_now(backend.modified_at_ms, sequence),
            retention,
            legal_hold: updated.legal_hold,
        };
        let sealed_manifest = seal_manifest_record(&keyring, &manifest_id, &manifest)?;
        state.pending_index_deltas.push(IndexDelta::Upsert {
            entry: updated.clone(),
            prefix_tokens: prefix_tokens.clone(),
            sealed_manifest: Box::new(sealed_manifest),
        });
        state.namespace.upsert(updated.clone(), prefix_tokens);
        state.manifests.insert(manifest_id, manifest.clone());

        Ok(manifest.into_metadata())
    }

    fn object_id_for_candidates(
        &self,
        key: &LogicalPath,
        lookup_blind_keys: &[NamespaceBlindKey],
    ) -> Result<BackendObjectId> {
        let state = self.read_state()?;
        first_namespace_entry(&state.namespace, lookup_blind_keys)
            .map(|entry| entry.object_id.clone())
            .ok_or_else(|| RepositoryError::NotFound(key.clone()))
    }

    /// Returns a cloned active keyring.
    pub(crate) fn keyring(&self) -> Result<KeyRing> {
        self.keyring
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)
            .map(|keyring| keyring.clone())
    }

    /// Replaces the keyring envelope reference recorded in future checkpoints.
    pub(crate) fn set_keyring_envelope_reference(
        &self,
        reference: Option<KeyringEnvelopeReference>,
    ) -> Result<()> {
        let mut active = self
            .keyring_envelope
            .write()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        *active = reference;
        Ok(())
    }

    /// Returns the keyring envelope reference recorded in future checkpoints.
    pub(crate) fn keyring_envelope_reference(&self) -> Result<Option<KeyringEnvelopeReference>> {
        self.keyring_envelope
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)
            .map(|reference| reference.clone())
    }

    /// Reads repository state.
    pub(crate) fn read_state(&self) -> Result<RwLockReadGuard<'_, RepositoryState>> {
        self.state
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)
    }

    /// Writes repository state.
    pub(crate) fn write_state(&self) -> Result<RwLockWriteGuard<'_, RepositoryState>> {
        self.state
            .write()
            .map_err(|_| RepositoryError::StatePoisoned)
    }
}

struct PayloadRead {
    backend_bytes_read: u64,
    opened: Result<Bytes>,
}

struct CiphertextSpanRead {
    backend_bytes_read: u64,
    ciphertext: Bytes,
}

enum PayloadHeaderRead {
    Header(CachedPayloadHeader),
    Full(PayloadRead),
}

struct CachedPayloadHeader {
    backend_bytes_read: u64,
    header: SegmentedPayloadHeader,
    prefetched_body: Option<Bytes>,
}

#[derive(Debug)]
struct PayloadHeaderCache {
    headers: BTreeMap<BackendObjectId, SegmentedPayloadHeader>,
    order: VecDeque<BackendObjectId>,
    max_entries: usize,
}

impl Default for PayloadHeaderCache {
    fn default() -> Self {
        Self {
            headers: BTreeMap::new(),
            order: VecDeque::new(),
            max_entries: 1024,
        }
    }
}

impl PayloadHeaderCache {
    fn get(&self, object_id: &BackendObjectId) -> Option<SegmentedPayloadHeader> {
        self.headers.get(object_id).cloned()
    }

    fn insert(&mut self, object_id: BackendObjectId, header: SegmentedPayloadHeader) {
        match self.headers.entry(object_id.clone()) {
            Entry::Occupied(mut entry) => {
                entry.insert(header);
            }
            Entry::Vacant(entry) => {
                self.order.push_back(object_id);
                entry.insert(header);
                while self.headers.len() > self.max_entries {
                    let Some(evicted) = self.order.pop_front() else {
                        break;
                    };
                    self.headers.remove(&evicted);
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct PayloadSpanCacheKey {
    object_id: BackendObjectId,
    offset: u64,
    len: u64,
}

impl PayloadSpanCacheKey {
    fn new(object_id: BackendObjectId, span: SegmentCiphertextSpan) -> Self {
        Self {
            object_id,
            offset: span.offset,
            len: span.len,
        }
    }
}

#[derive(Debug)]
struct PayloadSpanCache {
    spans: BTreeMap<PayloadSpanCacheKey, Bytes>,
    order: VecDeque<PayloadSpanCacheKey>,
    max_entries: usize,
    max_bytes: u64,
    current_bytes: u64,
}

impl Default for PayloadSpanCache {
    fn default() -> Self {
        Self {
            spans: BTreeMap::new(),
            order: VecDeque::new(),
            max_entries: 4096,
            max_bytes: 8 * 1024 * 1024,
            current_bytes: 0,
        }
    }
}

impl PayloadSpanCache {
    fn get(&self, object_id: &BackendObjectId, span: SegmentCiphertextSpan) -> Option<Bytes> {
        let key = PayloadSpanCacheKey::new(object_id.clone(), span);
        self.spans.get(&key).cloned()
    }

    fn insert(
        &mut self,
        object_id: BackendObjectId,
        span: SegmentCiphertextSpan,
        ciphertext: Bytes,
    ) -> PayloadSpanCacheInsert {
        let bytes = u64::try_from(ciphertext.len()).unwrap_or(u64::MAX);
        if bytes > self.max_bytes {
            return PayloadSpanCacheInsert::SkippedTooLarge { bytes };
        }

        let key = PayloadSpanCacheKey::new(object_id, span);
        match self.spans.entry(key.clone()) {
            Entry::Occupied(mut entry) => {
                let previous = u64::try_from(entry.get().len()).unwrap_or(u64::MAX);
                self.current_bytes = self.current_bytes.saturating_sub(previous);
                self.current_bytes = self.current_bytes.saturating_add(bytes);
                entry.insert(ciphertext);
            }
            Entry::Vacant(entry) => {
                self.current_bytes = self.current_bytes.saturating_add(bytes);
                self.order.push_back(key);
                entry.insert(ciphertext);
            }
        }
        let evicted = self.evict_over_limits();
        PayloadSpanCacheInsert::Inserted {
            bytes,
            evicted_entries: evicted.entries,
            evicted_bytes: evicted.bytes,
        }
    }

    fn evict_over_limits(&mut self) -> PayloadSpanCacheEviction {
        let mut evicted = PayloadSpanCacheEviction::default();
        while self.spans.len() > self.max_entries || self.current_bytes > self.max_bytes {
            let Some(evicted_key) = self.order.pop_front() else {
                break;
            };
            if let Some(ciphertext) = self.spans.remove(&evicted_key) {
                let bytes = u64::try_from(ciphertext.len()).unwrap_or(u64::MAX);
                self.current_bytes = self.current_bytes.saturating_sub(bytes);
                evicted.entries = evicted.entries.saturating_add(1);
                evicted.bytes = evicted.bytes.saturating_add(bytes);
            }
        }
        evicted
    }
}

enum PayloadSpanCacheInsert {
    Inserted {
        bytes: u64,
        evicted_entries: u64,
        evicted_bytes: u64,
    },
    SkippedTooLarge {
        bytes: u64,
    },
}

#[derive(Default)]
struct PayloadSpanCacheEviction {
    entries: u64,
    bytes: u64,
}

struct RepositoryPutTrace {
    plaintext_len: u64,
    backend_len: u64,
    sequence: u64,
    stale_entries: usize,
    create_only: bool,
    requested_retention: bool,
    requested_legal_hold: bool,
    result: &'static str,
    elapsed: Duration,
}

struct RepositoryListTrace {
    prefix_mode: &'static str,
    lookup_token_count: usize,
    candidate_count: usize,
    manifest_miss_count: usize,
    prefix_miss_count: usize,
    returned_count: usize,
    result: &'static str,
    elapsed: Duration,
}

fn record_repository_put(record: RepositoryPutTrace) {
    record_repository_operation_metrics("put", record.result, record.elapsed);
    if record.result == "ok" {
        increment_repository_counter(
            "rs3_repository_plaintext_bytes_total",
            "operation",
            "put",
            record.plaintext_len,
        );
        increment_repository_counter(
            "rs3_repository_backend_bytes_written_total",
            "operation",
            "put",
            record.backend_len,
        );
        increment_repository_counter(
            "rs3_repository_stale_entries_total",
            "operation",
            "put",
            usize_to_u64(record.stale_entries),
        );
    }

    tracing::info!(
        target: "rs3_repository",
        operation = "put",
        plaintext_len = record.plaintext_len,
        backend_len = record.backend_len,
        sequence = record.sequence,
        stale_entries = record.stale_entries,
        create_only = record.create_only,
        requested_retention = record.requested_retention,
        requested_legal_hold = record.requested_legal_hold,
        result = record.result,
        elapsed_us = elapsed_us(record.elapsed),
        "repository operation completed",
    );
}

fn record_repository_head(result: &'static str, elapsed: Duration) {
    record_repository_operation_metrics("head", result, elapsed);
    tracing::info!(
        target: "rs3_repository",
        operation = "head",
        result,
        elapsed_us = elapsed_us(elapsed),
        "repository operation completed",
    );
}

fn record_repository_list(record: RepositoryListTrace) {
    record_repository_operation_metrics("list", record.result, record.elapsed);
    metrics::counter!(
        "rs3_repository_list_lookup_tokens_total",
        "prefix_mode" => record.prefix_mode,
        "result" => record.result.to_owned(),
    )
    .increment(usize_to_u64(record.lookup_token_count));
    metrics::counter!(
        "rs3_repository_list_candidates_total",
        "prefix_mode" => record.prefix_mode,
        "result" => record.result.to_owned(),
    )
    .increment(usize_to_u64(record.candidate_count));
    metrics::counter!(
        "rs3_repository_list_manifest_misses_total",
        "prefix_mode" => record.prefix_mode,
        "result" => record.result.to_owned(),
    )
    .increment(usize_to_u64(record.manifest_miss_count));
    metrics::counter!(
        "rs3_repository_list_prefix_misses_total",
        "prefix_mode" => record.prefix_mode,
        "result" => record.result.to_owned(),
    )
    .increment(usize_to_u64(record.prefix_miss_count));
    metrics::counter!(
        "rs3_repository_list_returned_total",
        "prefix_mode" => record.prefix_mode,
        "result" => record.result.to_owned(),
    )
    .increment(usize_to_u64(record.returned_count));

    tracing::info!(
        target: "rs3_repository",
        operation = "list",
        prefix_mode = record.prefix_mode,
        lookup_token_count = record.lookup_token_count,
        candidate_count = record.candidate_count,
        manifest_miss_count = record.manifest_miss_count,
        prefix_miss_count = record.prefix_miss_count,
        returned_count = record.returned_count,
        result = record.result,
        elapsed_us = elapsed_us(record.elapsed),
        "repository operation completed",
    );
}

fn record_repository_get(
    range: ByteRange,
    backend_bytes_read: u64,
    returned_len: u64,
    result: &str,
    elapsed: Duration,
) {
    let range_label = match range {
        ByteRange::Full => "full",
        ByteRange::Slice { .. } => "slice",
    };
    record_repository_operation_metrics("get_range", result, elapsed);
    metrics::counter!(
        "rs3_repository_backend_bytes_read_total",
        "operation" => "get_range",
        "range" => range_label,
        "result" => result.to_owned(),
    )
    .increment(backend_bytes_read);
    if result == "ok" {
        metrics::counter!(
            "rs3_repository_returned_bytes_total",
            "operation" => "get_range",
            "range" => range_label,
        )
        .increment(returned_len);
    }

    match range {
        ByteRange::Full => tracing::info!(
            target: "rs3_repository",
            operation = "get_range",
            range = "full",
            backend_bytes_read,
            returned_len,
            result,
            elapsed_us = elapsed_us(elapsed),
            "repository operation completed",
        ),
        ByteRange::Slice { offset, len } => tracing::info!(
            target: "rs3_repository",
            operation = "get_range",
            range = "slice",
            range_offset = offset,
            range_len = len,
            backend_bytes_read,
            returned_len,
            result,
            elapsed_us = elapsed_us(elapsed),
            "repository operation completed",
        ),
    }
}

fn record_repository_operation_metrics(operation: &'static str, result: &str, elapsed: Duration) {
    metrics::counter!(
        "rs3_repository_operations_total",
        "operation" => operation,
        "result" => result.to_owned(),
    )
    .increment(1);
    metrics::histogram!(
        "rs3_repository_operation_duration_seconds",
        "operation" => operation,
        "result" => result.to_owned(),
    )
    .record(elapsed.as_secs_f64());
}

fn record_payload_span_cache(result: &'static str, bytes: u64) {
    record_payload_span_cache_many(result, 1, bytes);
}

fn record_payload_span_cache_many(result: &'static str, events: u64, bytes: u64) {
    if events == 0 && bytes == 0 {
        return;
    }
    metrics::counter!(
        "rs3_repository_payload_span_cache_events_total",
        "result" => result,
    )
    .increment(events);
    metrics::counter!(
        "rs3_repository_payload_span_cache_bytes_total",
        "result" => result,
    )
    .increment(bytes);
}

fn increment_repository_counter(
    name: &'static str,
    label_name: &'static str,
    label_value: &'static str,
    amount: u64,
) {
    if amount == 0 {
        return;
    }
    metrics::counter!(name, label_name => label_value).increment(amount);
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn elapsed_us(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
}

fn modified_at_ms_or_now(modified_at_ms: Option<i64>, sequence: rs3_types::Sequence) -> i64 {
    modified_at_ms.unwrap_or_else(|| current_time_ms().unwrap_or(sequence.get() as i64))
}

pub(crate) fn strongest_retention_policy(
    left: Option<RetentionPolicy>,
    right: Option<RetentionPolicy>,
) -> Option<RetentionPolicy> {
    match (active_retention(left), active_retention(right)) {
        (Some(left), Some(right)) => Some(RetentionPolicy::new(
            stronger_retention_mode(left.mode, right.mode),
            left.retain_days.max(right.retain_days),
        )),
        (Some(policy), None) | (None, Some(policy)) => Some(policy),
        (None, None) => None,
    }
}

fn active_retention(policy: Option<RetentionPolicy>) -> Option<RetentionPolicy> {
    policy.filter(|policy| policy.mode != RetentionMode::None && policy.retain_days > 0)
}

fn stronger_retention_mode(left: RetentionMode, right: RetentionMode) -> RetentionMode {
    match (left, right) {
        (RetentionMode::Compliance, _) | (_, RetentionMode::Compliance) => {
            RetentionMode::Compliance
        }
        (RetentionMode::Governance, _) | (_, RetentionMode::Governance) => {
            RetentionMode::Governance
        }
        (RetentionMode::None, RetentionMode::None) => RetentionMode::None,
    }
}

fn current_time_ms() -> Option<i64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis();
    i64::try_from(millis).ok()
}

#[cfg(test)]
mod tests {
    use super::{PayloadSpanCache, PayloadSpanCacheInsert, SegmentCiphertextSpan};
    use bytes::Bytes;
    use rs3_types::BackendObjectId;
    use std::collections::{BTreeMap, VecDeque};

    fn object_id(value: &str) -> BackendObjectId {
        match BackendObjectId::new(value.to_owned()) {
            Ok(object_id) => object_id,
            Err(error) => panic!("{error}"),
        }
    }

    fn span(offset: u64, len: u64) -> SegmentCiphertextSpan {
        SegmentCiphertextSpan {
            offset,
            len,
            start_segment: 0,
            segment_count: 1,
        }
    }

    fn cache(max_entries: usize, max_bytes: u64) -> PayloadSpanCache {
        PayloadSpanCache {
            spans: BTreeMap::new(),
            order: VecDeque::new(),
            max_entries,
            max_bytes,
            current_bytes: 0,
        }
    }

    fn inserted(outcome: PayloadSpanCacheInsert) -> (u64, u64, u64) {
        match outcome {
            PayloadSpanCacheInsert::Inserted {
                bytes,
                evicted_entries,
                evicted_bytes,
            } => (bytes, evicted_entries, evicted_bytes),
            PayloadSpanCacheInsert::SkippedTooLarge { bytes } => {
                panic!("insert skipped unexpectedly with {bytes} bytes")
            }
        }
    }

    #[test]
    fn payload_span_cache_reports_entry_evictions() {
        let mut cache = cache(1, 1024);
        let first_span = span(0, 4);
        let second_span = span(4, 4);

        assert_eq!(
            inserted(cache.insert(
                object_id("payload-a"),
                first_span,
                Bytes::from_static(b"aaaa")
            )),
            (4, 0, 0)
        );
        assert_eq!(
            inserted(cache.insert(
                object_id("payload-b"),
                second_span,
                Bytes::from_static(b"bbbb")
            )),
            (4, 1, 4)
        );

        assert!(cache.get(&object_id("payload-a"), first_span).is_none());
        assert_eq!(
            cache.get(&object_id("payload-b"), second_span),
            Some(Bytes::from_static(b"bbbb"))
        );
        assert_eq!(cache.current_bytes, 4);
    }
}
