//! Repository service implementation.

use crate::checkpoint::seal_manifest_record;
use crate::error::{RepositoryError, Result};
use crate::model::{
    CommittedPut, DeleteOutcome, PhysicalDeleteOutcome, RepositoryListEntry,
    RepositoryObjectMetadata, RepositoryPutOptions,
};
use crate::namespace::{existing_blind_keys, first_namespace_entry, prefix_tokens_for_key};
use crate::payload::{open_payload_object, seal_payload_object};
use crate::state::{RepositoryState, TrustedManifest, next_sequence, object_material};
use bytes::Bytes;
use rs3_anchor::CheckpointAnchor;
use rs3_crypto::{KeyRing, NamespaceBlindKey, SecretBytes};
use rs3_index::{IndexDelta, NamespaceEntry};
use rs3_storage::{BlobStore, ByteRange, PutOptions, StorageError};
use rs3_types::{BackendObjectId, LogicalPath, RetentionPolicy};
use std::collections::{BTreeMap, btree_map::Entry};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Trusted repository service.
pub struct Repository<S> {
    pub(crate) store: S,
    pub(crate) keyring: RwLock<KeyRing>,
    pub(crate) state: RwLock<RepositoryState>,
}

impl<S> Repository<S>
where
    S: BlobStore,
{
    /// Creates a trusted repository service over a blob store.
    pub fn new(store: S, secret: SecretBytes) -> Self {
        Self::with_keyring(store, KeyRing::single_namespace(secret))
    }

    /// Creates a trusted repository service with an explicit keyring.
    pub fn with_keyring(store: S, keyring: KeyRing) -> Self {
        Self {
            store,
            keyring: RwLock::new(keyring),
            state: RwLock::new(RepositoryState::default()),
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
        let requested_retention = options.retention.is_some();
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

        let payload = seal_payload_object(&keyring, &object_id, &body)?;
        let storage_metadata = self
            .store
            .put(
                &object_id,
                payload,
                PutOptions {
                    retention: options.retention.clone(),
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
            retention: storage_metadata.retention.clone(),
        };
        let manifest = TrustedManifest {
            key: key.clone(),
            content_len: plaintext_len,
            modified_at_ms,
            retention: storage_metadata.retention,
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

    /// Reads trusted metadata for a client-visible object.
    pub fn head(&self, key: &LogicalPath) -> Result<RepositoryObjectMetadata> {
        let keyring = self.keyring()?;
        let lookup_blind_keys = keyring.derive_blind_index_keys_for_lookup(key)?;
        let state = self.read_state()?;
        let entry = first_namespace_entry(&state.namespace, &lookup_blind_keys)
            .ok_or_else(|| RepositoryError::NotFound(key.clone()))?;
        let manifest = state
            .manifests
            .get(&entry.manifest_id)
            .cloned()
            .unwrap_or_else(|| TrustedManifest {
                key: key.clone(),
                content_len: entry.content_len,
                modified_at_ms: entry.modified_at_ms,
                retention: entry.retention.clone(),
            });

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
        let body = match self.store.get_range(&object_id, ByteRange::Full).await {
            Ok(body) => body,
            Err(error) => {
                record_repository_get(range, 0, 0, "storage_error", started.elapsed());
                return Err(error.into());
            }
        };
        let backend_bytes_read = u64::try_from(body.len()).unwrap_or(u64::MAX);
        match open_payload_object(&keyring, &object_id, body, range) {
            Ok(plaintext) => {
                let returned_len = u64::try_from(plaintext.len()).unwrap_or(u64::MAX);
                record_repository_get(
                    range,
                    backend_bytes_read,
                    returned_len,
                    "ok",
                    started.elapsed(),
                );
                Ok(plaintext)
            }
            Err(error) => {
                record_repository_get(
                    range,
                    backend_bytes_read,
                    0,
                    "open_error",
                    started.elapsed(),
                );
                Err(error)
            }
        }
    }

    /// Lists client-visible entries for a prefix.
    pub fn list(&self, prefix: &str) -> Result<Vec<RepositoryListEntry>> {
        let keyring = self.keyring()?;
        let prefix_tokens = keyring.derive_prefix_tokens_for_lookup(prefix)?;
        let state = self.read_state()?;
        let mut entries_by_key = BTreeMap::new();

        for prefix_token in prefix_tokens {
            for entry in state.namespace.list_prefix(&prefix_token.prefix_token) {
                let Some(manifest) = state.manifests.get(&entry.manifest_id) else {
                    continue;
                };
                if !manifest.key.as_str().starts_with(prefix) {
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
            Err(StorageError::RetentionBlocked) => PhysicalDeleteOutcome::Retained,
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
        self.store
            .extend_retention(&object_id, policy.clone())
            .await?;
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
        updated.retention = backend.retention.clone();
        let prefix_tokens =
            prefix_tokens_for_key(&keyring, &updated.namespace_key_id, key.as_str())?;
        let manifest = TrustedManifest {
            key: key.clone(),
            content_len,
            modified_at_ms: modified_at_ms_or_now(backend.modified_at_ms, sequence),
            retention: backend.retention,
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

struct RepositoryPutTrace {
    plaintext_len: u64,
    backend_len: u64,
    sequence: u64,
    stale_entries: usize,
    create_only: bool,
    requested_retention: bool,
    result: &'static str,
    elapsed: Duration,
}

fn record_repository_put(record: RepositoryPutTrace) {
    tracing::info!(
        target: "rs3_repository",
        operation = "put",
        plaintext_len = record.plaintext_len,
        backend_len = record.backend_len,
        sequence = record.sequence,
        stale_entries = record.stale_entries,
        create_only = record.create_only,
        requested_retention = record.requested_retention,
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

fn elapsed_us(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
}

fn modified_at_ms_or_now(modified_at_ms: Option<i64>, sequence: rs3_types::Sequence) -> i64 {
    modified_at_ms.unwrap_or_else(|| current_time_ms().unwrap_or(sequence.get() as i64))
}

fn current_time_ms() -> Option<i64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis();
    i64::try_from(millis).ok()
}
