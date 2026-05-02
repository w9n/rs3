//! Repository service implementation.

use crate::error::{RepositoryError, Result};
use crate::model::{
    CommittedPut, DeleteOutcome, PhysicalDeleteOutcome, RepositoryListEntry,
    RepositoryObjectMetadata, RepositoryPutOptions,
};
use crate::namespace::{existing_blind_keys, first_namespace_entry, prefix_tokens_for_key};
use crate::state::{RepositoryState, TrustedManifest, next_sequence, object_material};
use bytes::Bytes;
use rs3_anchor::CheckpointAnchor;
use rs3_crypto::{KeyRing, NamespaceBlindKey, SecretBytes};
use rs3_index::{IndexDelta, NamespaceEntry};
use rs3_storage::{BlobStore, ByteRange, PutOptions, StorageError};
use rs3_types::{BackendObjectId, LogicalPath, RetentionPolicy};
use std::collections::{BTreeMap, btree_map::Entry};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

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
        let keyring = self.keyring()?;
        let primary_blind_key = keyring.derive_primary_blind_index_key(&key)?;
        let lookup_blind_keys = keyring.derive_blind_index_keys_for_lookup(&key)?;
        let prefix_tokens =
            prefix_tokens_for_key(&keyring, &primary_blind_key.key_id, key.as_str())?;

        let (sequence, object_id, manifest_id, stale_blind_keys) = {
            let mut state = self.write_state()?;
            let existing_blind_keys = existing_blind_keys(&state.namespace, &lookup_blind_keys);
            if options.create_only && !existing_blind_keys.is_empty() {
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

        let storage_metadata = self
            .store
            .put(
                &object_id,
                body,
                PutOptions {
                    retention: options.retention.clone(),
                    content_type: None,
                    do_not_recreate: true,
                },
            )
            .await?;

        let modified_at_ms = storage_metadata
            .modified_at_ms
            .unwrap_or_else(|| sequence.get() as i64);
        let entry = NamespaceEntry {
            namespace_key_id: primary_blind_key.key_id,
            blind_key: primary_blind_key.blind_key,
            object_id,
            manifest_id: manifest_id.clone(),
            content_len: storage_metadata.content_len,
            modified_at_ms,
            generation: sequence,
            retention: storage_metadata.retention.clone(),
        };
        let manifest = TrustedManifest {
            key: key.clone(),
            content_len: storage_metadata.content_len,
            modified_at_ms,
            retention: storage_metadata.retention,
        };

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
            });
            state.namespace.upsert(entry, prefix_tokens);
            state.manifests.insert(manifest_id, manifest.clone());
        }

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
        let metadata = self.put(key, body, options).await?;
        let checkpoint = self.publish_checkpoint(anchor).await?;

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
        let object_id = self.object_id_for_key(key)?;
        self.store
            .get_range(&object_id, range)
            .await
            .map_err(Into::into)
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
        let keyring = self.keyring()?;
        let lookup_blind_keys = keyring.derive_blind_index_keys_for_lookup(key)?;
        let (object_id, sequence) = {
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
            (object_id, sequence)
        };

        let physical = match self.store.delete(&object_id).await {
            Ok(()) => PhysicalDeleteOutcome::Removed,
            Err(StorageError::RetentionBlocked) => PhysicalDeleteOutcome::Retained,
            Err(StorageError::NotFound(_)) => PhysicalDeleteOutcome::AlreadyGone,
            Err(error) => return Err(error.into()),
        };

        let _ = sequence;
        Ok(DeleteOutcome { physical })
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
        let sequence = next_sequence(&mut state)?;
        let material = object_material(key.as_str(), sequence);
        let manifest_id = keyring.derive_manifest_id(&material)?;
        let mut updated = entry;
        updated.manifest_id = manifest_id.clone();
        updated.generation = sequence;
        updated.retention = backend.retention.clone();
        let prefix_tokens =
            prefix_tokens_for_key(&keyring, &updated.namespace_key_id, key.as_str())?;
        state.pending_index_deltas.push(IndexDelta::Upsert {
            entry: updated.clone(),
            prefix_tokens: prefix_tokens.clone(),
        });
        state.namespace.upsert(updated.clone(), prefix_tokens);
        let manifest = TrustedManifest {
            key: key.clone(),
            content_len: backend.content_len,
            modified_at_ms: backend
                .modified_at_ms
                .unwrap_or_else(|| sequence.get() as i64),
            retention: backend.retention,
        };
        state.manifests.insert(manifest_id, manifest.clone());

        Ok(manifest.into_metadata())
    }

    fn object_id_for_key(&self, key: &LogicalPath) -> Result<BackendObjectId> {
        let keyring = self.keyring()?;
        let lookup_blind_keys = keyring.derive_blind_index_keys_for_lookup(key)?;
        self.object_id_for_candidates(key, &lookup_blind_keys)
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
