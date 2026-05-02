//! Repository checkpoint drafting.

use crate::error::Result;
use crate::model::CheckpointPosition;
use crate::service::Repository;
use bytes::Bytes;
use rs3_anchor::{AnchorError, CheckpointAnchor};
use rs3_crypto::{derive_checkpoint_id, derive_checkpoint_payload_digest};
use rs3_index::{
    Checkpoint, CommitRecord, KeyringSnapshot, canonical_commit_record_bytes,
    checkpoint_object_bytes,
};
use rs3_storage::{BlobStore, ByteRange, PutOptions, StorageError};
use rs3_types::{BackendObjectId, CheckpointId};

pub(crate) const CHECKPOINT_OBJECT_PREFIX: &str = "checkpoints/";
const CHECKPOINT_OBJECT_CONTENT_TYPE: &str = "application/vnd.rs3.checkpoint+json";

impl<S> Repository<S>
where
    S: BlobStore,
{
    /// Builds the checkpoint payload for the current trusted repository state.
    pub fn draft_commit_record(&self, parent: Option<CheckpointId>) -> Result<CommitRecord> {
        let keyring = self.keyring()?;
        let state = self.read_state()?;

        Ok(CommitRecord {
            sequence: state.next_sequence,
            parent,
            index_deltas: Vec::new(),
            compacted_manifests: state.manifests.keys().cloned().collect(),
            keyring: KeyringSnapshot::new(keyring.descriptors()),
        })
    }

    /// Builds and signs a checkpoint for the current trusted repository state.
    pub fn draft_signed_checkpoint(&self, parent: Option<CheckpointId>) -> Result<Checkpoint> {
        let record = self.draft_commit_record(parent)?;
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
        let checkpoint = self.draft_signed_checkpoint(parent)?;
        let position = self.verify_signed_checkpoint(&checkpoint, accepted.as_ref())?;

        self.persist_signed_checkpoint(&checkpoint).await?;

        anchor
            .compare_and_advance(position.clone().into_anchor_state())
            .await?;

        Ok(position)
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
