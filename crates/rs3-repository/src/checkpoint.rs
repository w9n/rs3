//! Repository checkpoint drafting.

use crate::error::Result;
use crate::model::CheckpointPosition;
use crate::service::{Repository, require_version_for_retained_write, strongest_retention_policy};
use crate::state::{RepositoryState, TrustedManifest, apply_index_delta_object, next_sequence};
use bytes::Bytes;
use rs3_anchor::{AnchorError, CheckpointAnchor};
use rs3_crypto::{
    KeyRing, KeyringEnvelope, derive_checkpoint_id, derive_checkpoint_payload_digest,
    derive_index_delta_object_id,
};
use rs3_index::{
    CHECKPOINT_OBJECT_DOMAIN, Checkpoint, CheckpointEvidence, CommitRecord,
    INDEX_DELTA_OBJECT_DOMAIN, INDEX_DELTA_PLAINTEXT_DOMAIN, IndexDelta, IndexDeltaObject,
    KeyringEnvelopeReference, KeyringSnapshot, MANIFEST_PLAINTEXT_DOMAIN, ManifestObject,
    SealedIndexDeltaObject, canonical_commit_record_bytes, checkpoint_evidence_bytes,
    checkpoint_object_bytes, index_delta_plaintext_bytes, manifest_plaintext_bytes,
};
use rs3_storage::{BlobStore, ByteRange, PutOptions, StorageError};
use rs3_types::{
    BackendObjectId, BackendObjectRef, BackendVersionId, CheckpointId, ManifestId, Sequence,
};
use std::collections::BTreeSet;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) const CHECKPOINT_OBJECT_PREFIX: &str = "checkpoints/";
pub(crate) const CHECKPOINT_EVIDENCE_PREFIX: &str = "evidence/";
const CHECKPOINT_OBJECT_CONTENT_TYPE: &str = "application/vnd.rs3.checkpoint+json";
const CHECKPOINT_EVIDENCE_CONTENT_TYPE: &str = "application/vnd.rs3.checkpoint-evidence+json";
const INDEX_DELTA_ASSOCIATED_DATA: &[u8] = b"rs3:index-delta-object:v1";

pub(crate) struct CheckpointChainEntry {
    pub(crate) checkpoint: Checkpoint,
    pub(crate) version_id: Option<BackendVersionId>,
}

impl<S> Repository<S>
where
    S: BlobStore,
{
    /// Builds the checkpoint payload for the current trusted repository state.
    pub fn draft_commit_record(&self, parent: Option<CheckpointId>) -> Result<CommitRecord> {
        let inline_index_delta = self.pending_index_delta_object()?;
        self.draft_commit_record_with_index_deltas(parent, None, Vec::new(), inline_index_delta)
    }

    fn draft_commit_record_with_index_deltas(
        &self,
        parent: Option<CheckpointId>,
        parent_checkpoint_version_id: Option<BackendVersionId>,
        index_deltas: Vec<BackendObjectRef>,
        inline_index_delta: Option<SealedIndexDeltaObject>,
    ) -> Result<CommitRecord> {
        let keyring = self.keyring()?;
        let mut state = self.write_state()?;
        let published_at_ms = state
            .pending_checkpoint_published_at_ms
            .unwrap_or_else(|| current_time_ms().unwrap_or(state.next_sequence.get() as i64));
        state.pending_checkpoint_published_at_ms = Some(published_at_ms);

        Ok(CommitRecord {
            sequence: state.next_sequence,
            published_at_ms,
            parent,
            parent_checkpoint_version_id,
            index_deltas,
            inline_index_delta,
            compacted_manifests: Vec::new(),
            keyring: KeyringSnapshot::new(keyring.descriptors()),
            keyring_envelope: self.keyring_envelope_reference()?,
        })
    }

    /// Builds and signs a checkpoint for the current trusted repository state.
    pub fn draft_signed_checkpoint(&self, parent: Option<CheckpointId>) -> Result<Checkpoint> {
        let record = self.draft_commit_record(parent)?;
        self.sign_commit_record(record)
    }

    fn sign_commit_record(&self, record: CommitRecord) -> Result<Checkpoint> {
        let canonical_payload = canonical_commit_record_bytes(&record)?;
        let keyring = self.keyring()?;
        let signature = keyring.sign_checkpoint_payload(&canonical_payload)?;
        let id = derive_checkpoint_id(&canonical_payload, &signature.signature)?;

        Ok(Checkpoint {
            id,
            record,
            signature_key_id: signature.key_id,
            signature: signature.signature,
        })
    }

    /// Verifies a signed checkpoint and checks it against an accepted position.
    pub fn verify_signed_checkpoint(
        &self,
        checkpoint: &Checkpoint,
        accepted: Option<&CheckpointPosition>,
    ) -> Result<CheckpointPosition> {
        self.verify_signed_checkpoint_at(checkpoint, accepted, None)
    }

    pub(crate) fn verify_signed_checkpoint_at(
        &self,
        checkpoint: &Checkpoint,
        accepted: Option<&CheckpointPosition>,
        checkpoint_version_id: Option<BackendVersionId>,
    ) -> Result<CheckpointPosition> {
        let canonical_payload = canonical_commit_record_bytes(&checkpoint.record)?;
        let keyring = self.keyring()?;
        keyring.verify_checkpoint_payload(
            &checkpoint.signature_key_id,
            &canonical_payload,
            &checkpoint.signature,
        )?;

        let expected_id = derive_checkpoint_id(&canonical_payload, &checkpoint.signature)?;
        if expected_id != checkpoint.id {
            return Err(crate::RepositoryError::CheckpointIdMismatch);
        }

        let position = CheckpointPosition {
            sequence: checkpoint.sequence(),
            checkpoint_id: checkpoint.id.clone(),
            checkpoint_version_id,
            payload_digest: derive_checkpoint_payload_digest(&canonical_payload),
        };

        validate_position(&checkpoint.record, &position, accepted)?;
        Ok(position)
    }

    /// Drafts, verifies, and advances an external checkpoint anchor.
    pub async fn publish_checkpoint<A>(&self, anchor: &A) -> Result<CheckpointPosition>
    where
        A: CheckpointAnchor,
    {
        let started = Instant::now();
        let accepted = match anchor.read().await {
            Ok(state) => Some(CheckpointPosition::from(state)),
            Err(AnchorError::MissingAnchor) => None,
            Err(error) => {
                record_checkpoint_publish(0, 0, "anchor_read_error", started.elapsed());
                return Err(error.into());
            }
        };

        if let Some(position) = accepted.as_ref() {
            let state = self.read_state()?;
            if state.next_sequence < position.sequence {
                record_checkpoint_publish(state.next_sequence.get(), 0, "stale", started.elapsed());
                return Err(crate::RepositoryError::StaleCheckpoint {
                    sequence: state.next_sequence,
                });
            }
            if state.next_sequence == position.sequence {
                record_checkpoint_publish(
                    position.sequence.get(),
                    0,
                    "idempotent",
                    started.elapsed(),
                );
                return Ok(position.clone());
            }
        }

        let parent = accepted
            .as_ref()
            .map(|position| position.checkpoint_id.clone());
        let parent_checkpoint_version_id = accepted
            .as_ref()
            .and_then(|position| position.checkpoint_version_id.clone());
        let inline_index_delta = self.pending_index_delta_object()?;
        let record = self.draft_commit_record_with_index_deltas(
            parent,
            parent_checkpoint_version_id,
            Vec::new(),
            inline_index_delta,
        )?;
        let checkpoint = self.sign_commit_record(record)?;
        let index_delta_count = checkpoint_index_delta_count(&checkpoint);
        let mut position = self.verify_signed_checkpoint(&checkpoint, accepted.as_ref())?;

        position.checkpoint_version_id = self.persist_signed_checkpoint(&checkpoint).await?;
        self.persist_checkpoint_evidence(&position).await?;

        anchor
            .compare_and_advance(position.clone().into_anchor_state())
            .await?;
        self.mark_index_deltas_published(position.sequence)?;

        record_checkpoint_publish(
            position.sequence.get(),
            index_delta_count,
            "ok",
            started.elapsed(),
        );
        Ok(position)
    }

    /// Loads and replays durable state up to an accepted checkpoint position.
    pub async fn load_checkpoint_position(
        &self,
        accepted: &CheckpointPosition,
    ) -> Result<CheckpointPosition> {
        let checkpoints = self.read_checkpoint_chain(accepted).await?;
        let mut previous = None;
        let mut previous_published_at_ms = None;
        let mut rebuilt = RepositoryState::default();
        let mut loaded_keyring_envelope = None;

        for checkpoint in checkpoints.into_iter().rev() {
            validate_checkpoint_published_at(&checkpoint.checkpoint, previous_published_at_ms)?;
            let position = self.verify_signed_checkpoint_at(
                &checkpoint.checkpoint,
                previous.as_ref(),
                checkpoint.version_id.clone(),
            )?;
            self.apply_checkpoint_deltas(&mut rebuilt, &checkpoint.checkpoint)
                .await?;
            rebuilt.next_sequence = position.sequence;
            loaded_keyring_envelope = checkpoint.checkpoint.record.keyring_envelope.clone();
            previous_published_at_ms = Some(checkpoint.checkpoint.record.published_at_ms);
            previous = Some(position);
        }

        let Some(loaded) = previous else {
            return Err(crate::RepositoryError::CheckpointConflict {
                checkpoint_id: accepted.checkpoint_id.clone(),
            });
        };

        if &loaded != accepted {
            return Err(crate::RepositoryError::CheckpointConflict {
                checkpoint_id: accepted.checkpoint_id.clone(),
            });
        }

        let mut state = self.write_state()?;
        *state = rebuilt;
        drop(state);
        self.set_keyring_envelope_reference(loaded_keyring_envelope)?;
        Ok(loaded)
    }

    /// Stores a new encrypted keyring envelope and stages a metadata-only checkpoint.
    ///
    /// This is used for key lifecycle updates that change checkpoint metadata
    /// but do not necessarily include a client-visible object mutation. The
    /// returned sequence is reserved for the next checkpoint publish.
    pub async fn store_keyring_update(
        &self,
        keyring: KeyRing,
        envelope: &KeyringEnvelope,
    ) -> Result<(KeyringEnvelopeReference, Sequence)> {
        self.replace_keyring(keyring)?;
        let reference = self.store_keyring_envelope(envelope).await?;
        let sequence = self.stage_repository_metadata_checkpoint()?;
        Ok((reference, sequence))
    }

    fn stage_repository_metadata_checkpoint(&self) -> Result<Sequence> {
        let mut state = self.write_state()?;
        next_sequence(&mut state)
    }

    /// Writes a signed checkpoint object if it has not already been written.
    pub(crate) async fn persist_signed_checkpoint(
        &self,
        checkpoint: &Checkpoint,
    ) -> Result<Option<BackendVersionId>> {
        let object_id = checkpoint_object_id(&checkpoint.id)?;
        let body = Bytes::from(checkpoint_object_bytes(checkpoint)?);
        let retention = self.checkpoint_retention_policy()?;
        let legal_hold = self.checkpoint_legal_hold()?;
        let put = self
            .store
            .put(
                &object_id,
                body.clone(),
                PutOptions {
                    retention,
                    legal_hold,
                    content_type: Some(CHECKPOINT_OBJECT_CONTENT_TYPE.to_owned()),
                    do_not_recreate: true,
                },
            )
            .await;

        match put {
            Ok(metadata) => {
                require_version_for_retained_write(&object_id, &metadata, retention, legal_hold)
            }
            Err(StorageError::AlreadyExists(_)) => {
                let existing_metadata = self.store.head(&object_id).await?;
                let existing = self.store.get_range(&object_id, ByteRange::Full).await?;
                if existing == body {
                    require_version_for_retained_write(
                        &object_id,
                        &existing_metadata,
                        retention,
                        legal_hold,
                    )
                } else {
                    Err(crate::RepositoryError::CheckpointObjectConflict { object_id })
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn persist_checkpoint_evidence(&self, position: &CheckpointPosition) -> Result<()> {
        let object_id = checkpoint_evidence_object_id(position)?;
        let evidence = CheckpointEvidence {
            sequence: position.sequence,
            checkpoint_id: position.checkpoint_id.clone(),
            checkpoint_digest: position.payload_digest.clone(),
            checkpoint_object_id: checkpoint_object_id(&position.checkpoint_id)?,
            checkpoint_object_version_id: position.checkpoint_version_id.clone(),
        };
        let body = Bytes::from(checkpoint_evidence_bytes(&evidence)?);
        let retention = self.checkpoint_retention_policy()?;
        let legal_hold = self.checkpoint_legal_hold()?;
        let put = self
            .store
            .put(
                &object_id,
                body.clone(),
                PutOptions {
                    retention,
                    legal_hold,
                    content_type: Some(CHECKPOINT_EVIDENCE_CONTENT_TYPE.to_owned()),
                    do_not_recreate: true,
                },
            )
            .await;

        match put {
            Ok(metadata) => {
                require_version_for_retained_write(&object_id, &metadata, retention, legal_hold)?;
                Ok(())
            }
            Err(StorageError::AlreadyExists(_)) => {
                let existing_metadata = self.store.head(&object_id).await?;
                let existing = self.store.get_range(&object_id, ByteRange::Full).await?;
                if existing == body {
                    require_version_for_retained_write(
                        &object_id,
                        &existing_metadata,
                        retention,
                        legal_hold,
                    )?;
                    Ok(())
                } else {
                    Err(crate::RepositoryError::CheckpointEvidenceObjectConflict { object_id })
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn checkpoint_retention_policy(&self) -> Result<Option<rs3_types::RetentionPolicy>> {
        let state = self.read_state()?;
        let mut retention = self.options.default_retention;
        for delta in &state.pending_index_deltas {
            if let IndexDelta::Upsert { entry, .. } = delta {
                retention = strongest_retention_policy(retention, entry.retention);
            }
        }
        Ok(retention)
    }

    pub(crate) fn checkpoint_legal_hold(&self) -> Result<Option<rs3_types::LegalHoldStatus>> {
        let state = self.read_state()?;
        Ok(state
            .pending_index_deltas
            .iter()
            .find_map(|delta| match delta {
                IndexDelta::Upsert { entry, .. } => entry
                    .legal_hold
                    .filter(|status| *status == rs3_types::LegalHoldStatus::On),
                IndexDelta::Tombstone { .. } => None,
            }))
    }

    pub(crate) fn pending_index_delta_object(&self) -> Result<Option<SealedIndexDeltaObject>> {
        let state = self.read_state()?;
        if state.pending_index_deltas.is_empty() {
            return Ok(None);
        }

        let delta = IndexDeltaObject {
            sequence: state.next_sequence,
            deltas: state.pending_index_deltas.clone(),
        };
        let keyring = self.keyring()?;
        let sealed_delta = seal_index_delta_object(&keyring, &delta)?;
        Ok(Some(sealed_delta))
    }

    pub(crate) fn mark_index_deltas_published(&self, sequence: rs3_types::Sequence) -> Result<()> {
        let mut state = self.write_state()?;
        if state.next_sequence == sequence {
            state.pending_index_deltas.clear();
            state.pending_checkpoint_published_at_ms = None;
        }
        Ok(())
    }

    pub(crate) async fn read_checkpoint_chain(
        &self,
        accepted: &CheckpointPosition,
    ) -> Result<Vec<CheckpointChainEntry>> {
        let mut checkpoints = Vec::new();
        let mut next = accepted.checkpoint_id.clone();
        let mut next_version = accepted.checkpoint_version_id.clone();
        let mut seen = BTreeSet::new();

        loop {
            if !seen.insert(next.clone()) {
                return Err(crate::RepositoryError::CheckpointParentMismatch);
            }

            let current_version = next_version.clone();
            let checkpoint = self
                .read_checkpoint_object_at(&next, current_version.as_ref())
                .await?;
            let parent = checkpoint.record.parent.clone();
            let parent_version = checkpoint.record.parent_checkpoint_version_id.clone();
            checkpoints.push(CheckpointChainEntry {
                checkpoint,
                version_id: current_version,
            });

            let Some(parent) = parent else {
                break;
            };
            next = parent;
            next_version = parent_version;
        }

        Ok(checkpoints)
    }

    pub(crate) async fn read_checkpoint_object_at(
        &self,
        checkpoint_id: &CheckpointId,
        version_id: Option<&BackendVersionId>,
    ) -> Result<Checkpoint> {
        let object_id = checkpoint_object_id(checkpoint_id)?;
        let body = self
            .store
            .get_range_at(&object_id, version_id, ByteRange::Full)
            .await?;
        let Some(payload) = body.as_ref().strip_prefix(CHECKPOINT_OBJECT_DOMAIN) else {
            return Err(crate::RepositoryError::InvalidObjectFormat { object_id });
        };

        serde_json::from_slice(payload).map_err(Into::into)
    }

    async fn apply_checkpoint_deltas(
        &self,
        state: &mut RepositoryState,
        checkpoint: &Checkpoint,
    ) -> Result<()> {
        for object_ref in &checkpoint.record.index_deltas {
            let delta = self.read_index_delta_object(object_ref).await?;
            self.load_embedded_manifest_records(state, &delta)?;
            apply_index_delta_object(state, delta);
        }
        if let Some(delta) = self.open_inline_index_delta_object(checkpoint)? {
            self.load_embedded_manifest_records(state, &delta)?;
            apply_index_delta_object(state, delta);
        }

        Ok(())
    }

    pub(crate) fn open_inline_index_delta_object(
        &self,
        checkpoint: &Checkpoint,
    ) -> Result<Option<IndexDeltaObject>> {
        let Some(sealed_delta) = checkpoint.record.inline_index_delta.as_ref() else {
            return Ok(None);
        };
        let object_id = inline_index_delta_object_id(&checkpoint.id)?;
        let keyring = self.keyring()?;
        open_index_delta_object(&keyring, &object_id, sealed_delta).map(Some)
    }

    pub(crate) async fn read_index_delta_object(
        &self,
        object_ref: &BackendObjectRef,
    ) -> Result<IndexDeltaObject> {
        let sealed_delta = self.read_sealed_index_delta_object(object_ref).await?;
        let keyring = self.keyring()?;

        open_index_delta_object(&keyring, &object_ref.object_id, &sealed_delta)
    }

    pub(crate) async fn read_sealed_index_delta_object(
        &self,
        object_ref: &BackendObjectRef,
    ) -> Result<SealedIndexDeltaObject> {
        let body = self
            .store
            .get_range_at(
                &object_ref.object_id,
                object_ref.version_id.as_ref(),
                ByteRange::Full,
            )
            .await?;
        let expected_object_id = derive_index_delta_object_id(&body)?;
        if expected_object_id != object_ref.object_id {
            return Err(crate::RepositoryError::IndexDeltaObjectConflict {
                object_id: object_ref.object_id.clone(),
            });
        }
        let Some(payload) = body.as_ref().strip_prefix(INDEX_DELTA_OBJECT_DOMAIN) else {
            return Err(crate::RepositoryError::InvalidObjectFormat {
                object_id: object_ref.object_id.clone(),
            });
        };

        serde_json::from_slice(payload).map_err(Into::into)
    }

    pub(crate) fn load_embedded_manifest_records(
        &self,
        state: &mut RepositoryState,
        delta: &IndexDeltaObject,
    ) -> Result<()> {
        let keyring = self.keyring()?;
        for mutation in &delta.deltas {
            let IndexDelta::Upsert {
                entry,
                sealed_manifest,
                ..
            } = mutation
            else {
                continue;
            };

            let manifest = open_manifest_record(&keyring, &entry.manifest_id, sealed_manifest)?;
            state.manifests.insert(entry.manifest_id.clone(), manifest);
        }

        Ok(())
    }
}

pub(crate) fn checkpoint_object_id(checkpoint_id: &CheckpointId) -> Result<BackendObjectId> {
    BackendObjectId::new(format!(
        "{CHECKPOINT_OBJECT_PREFIX}{}",
        checkpoint_id.as_str()
    ))
    .map_err(Into::into)
}

pub(crate) fn checkpoint_evidence_object_id(
    position: &CheckpointPosition,
) -> Result<BackendObjectId> {
    BackendObjectId::new(format!(
        "{CHECKPOINT_EVIDENCE_PREFIX}{:020}/{}",
        position.sequence.get(),
        position.checkpoint_id.as_str()
    ))
    .map_err(Into::into)
}

fn inline_index_delta_object_id(checkpoint_id: &CheckpointId) -> Result<BackendObjectId> {
    BackendObjectId::new(format!(
        "{CHECKPOINT_OBJECT_PREFIX}{}/inline-index-delta",
        checkpoint_id.as_str()
    ))
    .map_err(Into::into)
}

fn checkpoint_index_delta_count(checkpoint: &Checkpoint) -> usize {
    checkpoint.record.index_deltas.len()
        + usize::from(checkpoint.record.inline_index_delta.is_some())
}

fn manifest_associated_data(manifest_id: &ManifestId) -> Vec<u8> {
    format!("rs3:manifest-associated-data:v1:{}", manifest_id.as_str()).into_bytes()
}

pub(crate) fn seal_index_delta_object(
    keyring: &KeyRing,
    delta: &IndexDeltaObject,
) -> Result<SealedIndexDeltaObject> {
    let plaintext = index_delta_plaintext_bytes(delta)?;
    let associated_data = INDEX_DELTA_ASSOCIATED_DATA;
    let sealed = keyring.seal_metadata_payload(associated_data, &plaintext)?;

    Ok(SealedIndexDeltaObject {
        key_id: sealed.key_id,
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
        tag: sealed.tag,
    })
}

pub(crate) fn open_index_delta_object(
    keyring: &KeyRing,
    object_id: &BackendObjectId,
    sealed_delta: &SealedIndexDeltaObject,
) -> Result<IndexDeltaObject> {
    let plaintext = keyring.open_metadata_payload(
        &sealed_delta.key_id,
        INDEX_DELTA_ASSOCIATED_DATA,
        &sealed_delta.nonce,
        &sealed_delta.ciphertext,
        &sealed_delta.tag,
    )?;
    let Some(payload) = plaintext.strip_prefix(INDEX_DELTA_PLAINTEXT_DOMAIN) else {
        return Err(crate::RepositoryError::InvalidObjectFormat {
            object_id: object_id.clone(),
        });
    };

    serde_json::from_slice(payload).map_err(Into::into)
}

pub(crate) fn seal_manifest_record(
    keyring: &KeyRing,
    manifest_id: &ManifestId,
    manifest: &TrustedManifest,
) -> Result<ManifestObject> {
    let plaintext = manifest_plaintext_bytes(&manifest.clone().into_durable())?;
    let sealed =
        keyring.seal_metadata_payload(&manifest_associated_data(manifest_id), &plaintext)?;

    Ok(ManifestObject {
        key_id: sealed.key_id,
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
        tag: sealed.tag,
    })
}

pub(crate) fn open_manifest_record(
    keyring: &KeyRing,
    manifest_id: &ManifestId,
    manifest_object: &ManifestObject,
) -> Result<TrustedManifest> {
    let plaintext = keyring.open_metadata_payload(
        &manifest_object.key_id,
        &manifest_associated_data(manifest_id),
        &manifest_object.nonce,
        &manifest_object.ciphertext,
        &manifest_object.tag,
    )?;
    let object_id = BackendObjectId::new(format!("index-metadata/{}", manifest_id.as_str()))?;
    let Some(payload) = plaintext.strip_prefix(MANIFEST_PLAINTEXT_DOMAIN) else {
        return Err(crate::RepositoryError::InvalidObjectFormat { object_id });
    };
    let manifest = serde_json::from_slice(payload)?;

    Ok(TrustedManifest::from_durable(manifest))
}

fn validate_position(
    record: &CommitRecord,
    position: &CheckpointPosition,
    accepted: Option<&CheckpointPosition>,
) -> Result<()> {
    let Some(accepted) = accepted else {
        return Ok(());
    };

    if position.sequence < accepted.sequence {
        return Err(crate::RepositoryError::StaleCheckpoint {
            sequence: position.sequence,
        });
    }

    if position.sequence == accepted.sequence {
        if position.checkpoint_id == accepted.checkpoint_id
            && position.payload_digest == accepted.payload_digest
            && accepted
                .checkpoint_version_id
                .as_ref()
                .is_none_or(|version_id| {
                    position.checkpoint_version_id.as_ref() == Some(version_id)
                })
        {
            return Ok(());
        }

        return Err(crate::RepositoryError::CheckpointConflict {
            checkpoint_id: position.checkpoint_id.clone(),
        });
    }

    if record.parent.as_ref() != Some(&accepted.checkpoint_id) {
        return Err(crate::RepositoryError::CheckpointParentMismatch);
    }
    if record.parent_checkpoint_version_id != accepted.checkpoint_version_id {
        return Err(crate::RepositoryError::CheckpointParentMismatch);
    }

    Ok(())
}

pub(crate) fn validate_checkpoint_published_at(
    checkpoint: &Checkpoint,
    previous_published_at_ms: Option<i64>,
) -> Result<()> {
    if previous_published_at_ms.is_some_and(|previous| checkpoint.record.published_at_ms < previous)
    {
        return Err(crate::RepositoryError::CheckpointPublishedAtDecreased {
            checkpoint_id: checkpoint.id.clone(),
        });
    }

    Ok(())
}

fn record_checkpoint_publish(
    sequence: u64,
    index_delta_count: usize,
    result: &str,
    elapsed: Duration,
) {
    tracing::info!(
        target: "rs3_repository",
        operation = "publish_checkpoint",
        sequence,
        index_delta_count,
        result,
        elapsed_us = elapsed_us(elapsed),
        "repository operation completed",
    );
}

fn elapsed_us(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
}

fn current_time_ms() -> Option<i64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis();
    i64::try_from(millis).ok()
}
