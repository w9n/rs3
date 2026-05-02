//! Repository checkpoint drafting.

use crate::error::Result;
use crate::model::CheckpointPosition;
use crate::service::Repository;
use crate::state::{RepositoryState, apply_index_delta_object};
use bytes::Bytes;
use rs3_anchor::{AnchorError, CheckpointAnchor};
use rs3_crypto::{
    derive_checkpoint_id, derive_checkpoint_payload_digest, derive_index_delta_object_id,
};
use rs3_index::{
    CHECKPOINT_OBJECT_DOMAIN, Checkpoint, CommitRecord, INDEX_DELTA_OBJECT_DOMAIN,
    IndexDeltaObject, KeyringSnapshot, canonical_commit_record_bytes, checkpoint_object_bytes,
    index_delta_object_bytes,
};
use rs3_storage::{BlobStore, ByteRange, PutOptions, StorageError};
use rs3_types::{BackendObjectId, CheckpointId};
use std::collections::BTreeSet;

pub(crate) const CHECKPOINT_OBJECT_PREFIX: &str = "checkpoints/";
const CHECKPOINT_OBJECT_CONTENT_TYPE: &str = "application/vnd.rs3.checkpoint+json";
const INDEX_DELTA_OBJECT_CONTENT_TYPE: &str = "application/vnd.rs3.index-delta+json";

struct PendingIndexDeltaObject {
    object_id: BackendObjectId,
    body: Bytes,
}

impl<S> Repository<S>
where
    S: BlobStore,
{
    /// Builds the checkpoint payload for the current trusted repository state.
    pub fn draft_commit_record(&self, parent: Option<CheckpointId>) -> Result<CommitRecord> {
        let index_deltas = self.pending_index_delta_ids()?;
        self.draft_commit_record_with_index_deltas(parent, index_deltas)
    }

    fn draft_commit_record_with_index_deltas(
        &self,
        parent: Option<CheckpointId>,
        index_deltas: Vec<BackendObjectId>,
    ) -> Result<CommitRecord> {
        let keyring = self.keyring()?;
        let state = self.read_state()?;

        Ok(CommitRecord {
            sequence: state.next_sequence,
            parent,
            index_deltas,
            compacted_manifests: state.manifests.keys().cloned().collect(),
            keyring: KeyringSnapshot::new(keyring.descriptors()),
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
        let accepted = match anchor.read().await {
            Ok(state) => Some(CheckpointPosition::from(state)),
            Err(AnchorError::MissingAnchor) => None,
            Err(error) => return Err(error.into()),
        };

        if let Some(position) = accepted.as_ref() {
            let state = self.read_state()?;
            if state.next_sequence < position.sequence {
                return Err(crate::RepositoryError::StaleCheckpoint {
                    sequence: state.next_sequence,
                });
            }
            if state.next_sequence == position.sequence {
                return Ok(position.clone());
            }
        }

        let parent = accepted
            .as_ref()
            .map(|position| position.checkpoint_id.clone());
        let pending_index_delta = self.pending_index_delta_object()?;
        if let Some(delta) = pending_index_delta.as_ref() {
            self.persist_index_delta_object(delta).await?;
        }
        let index_deltas = pending_index_delta
            .iter()
            .map(|delta| delta.object_id.clone())
            .collect();

        let record = self.draft_commit_record_with_index_deltas(parent, index_deltas)?;
        let checkpoint = self.sign_commit_record(record)?;
        let position = self.verify_signed_checkpoint(&checkpoint, accepted.as_ref())?;

        self.persist_signed_checkpoint(&checkpoint).await?;

        anchor
            .compare_and_advance(position.clone().into_anchor_state())
            .await?;
        self.mark_index_deltas_published(position.sequence)?;

        Ok(position)
    }

    /// Loads and replays durable state up to an accepted checkpoint position.
    pub async fn load_checkpoint_position(
        &self,
        accepted: &CheckpointPosition,
    ) -> Result<CheckpointPosition> {
        let checkpoints = self.read_checkpoint_chain(&accepted.checkpoint_id).await?;
        let mut previous = None;
        let mut rebuilt = RepositoryState::default();

        for checkpoint in checkpoints.into_iter().rev() {
            let position = self.verify_signed_checkpoint(&checkpoint, previous.as_ref())?;
            self.apply_checkpoint_deltas(&mut rebuilt, &checkpoint)
                .await?;
            rebuilt.next_sequence = position.sequence;
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
        Ok(loaded)
    }

    /// Writes a signed checkpoint object if it has not already been written.
    pub(crate) async fn persist_signed_checkpoint(&self, checkpoint: &Checkpoint) -> Result<()> {
        let object_id = checkpoint_object_id(&checkpoint.id)?;
        let body = Bytes::from(checkpoint_object_bytes(checkpoint)?);
        let put = self
            .store
            .put(
                &object_id,
                body.clone(),
                PutOptions {
                    retention: None,
                    content_type: Some(CHECKPOINT_OBJECT_CONTENT_TYPE.to_owned()),
                    do_not_recreate: true,
                },
            )
            .await;

        match put {
            Ok(_) => Ok(()),
            Err(StorageError::AlreadyExists(_)) => {
                let existing = self.store.get_range(&object_id, ByteRange::Full).await?;
                if existing == body {
                    Ok(())
                } else {
                    Err(crate::RepositoryError::CheckpointObjectConflict { object_id })
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    fn pending_index_delta_ids(&self) -> Result<Vec<BackendObjectId>> {
        self.pending_index_delta_object()
            .map(|delta| delta.into_iter().map(|delta| delta.object_id).collect())
    }

    fn pending_index_delta_object(&self) -> Result<Option<PendingIndexDeltaObject>> {
        let state = self.read_state()?;
        if state.pending_index_deltas.is_empty() {
            return Ok(None);
        }

        let delta = IndexDeltaObject {
            sequence: state.next_sequence,
            deltas: state.pending_index_deltas.clone(),
        };
        let body = Bytes::from(index_delta_object_bytes(&delta)?);
        let object_id = derive_index_delta_object_id(&body)?;

        Ok(Some(PendingIndexDeltaObject { object_id, body }))
    }

    async fn persist_index_delta_object(&self, delta: &PendingIndexDeltaObject) -> Result<()> {
        let put = self
            .store
            .put(
                &delta.object_id,
                delta.body.clone(),
                PutOptions {
                    retention: None,
                    content_type: Some(INDEX_DELTA_OBJECT_CONTENT_TYPE.to_owned()),
                    do_not_recreate: true,
                },
            )
            .await;

        match put {
            Ok(_) => Ok(()),
            Err(StorageError::AlreadyExists(_)) => {
                let existing = self
                    .store
                    .get_range(&delta.object_id, ByteRange::Full)
                    .await?;
                if existing == delta.body {
                    Ok(())
                } else {
                    Err(crate::RepositoryError::IndexDeltaObjectConflict {
                        object_id: delta.object_id.clone(),
                    })
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    fn mark_index_deltas_published(&self, sequence: rs3_types::Sequence) -> Result<()> {
        let mut state = self.write_state()?;
        if state.next_sequence == sequence {
            state.pending_index_deltas.clear();
        }
        Ok(())
    }

    async fn read_checkpoint_chain(&self, latest: &CheckpointId) -> Result<Vec<Checkpoint>> {
        let mut checkpoints = Vec::new();
        let mut next = latest.clone();
        let mut seen = BTreeSet::new();

        loop {
            if !seen.insert(next.clone()) {
                return Err(crate::RepositoryError::CheckpointParentMismatch);
            }

            let checkpoint = self.read_checkpoint_object(&next).await?;
            let parent = checkpoint.record.parent.clone();
            checkpoints.push(checkpoint);

            let Some(parent) = parent else {
                break;
            };
            next = parent;
        }

        Ok(checkpoints)
    }

    async fn read_checkpoint_object(&self, checkpoint_id: &CheckpointId) -> Result<Checkpoint> {
        let object_id = checkpoint_object_id(checkpoint_id)?;
        let body = self.store.get_range(&object_id, ByteRange::Full).await?;
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
        for object_id in &checkpoint.record.index_deltas {
            let body = self.store.get_range(object_id, ByteRange::Full).await?;
            let Some(payload) = body.as_ref().strip_prefix(INDEX_DELTA_OBJECT_DOMAIN) else {
                return Err(crate::RepositoryError::InvalidObjectFormat {
                    object_id: object_id.clone(),
                });
            };
            let delta = serde_json::from_slice::<IndexDeltaObject>(payload)?;
            apply_index_delta_object(state, delta);
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
        if position == accepted {
            return Ok(());
        }

        return Err(crate::RepositoryError::CheckpointConflict {
            checkpoint_id: position.checkpoint_id.clone(),
        });
    }

    if record.parent.as_ref() != Some(&accepted.checkpoint_id) {
        return Err(crate::RepositoryError::CheckpointParentMismatch);
    }

    Ok(())
}
