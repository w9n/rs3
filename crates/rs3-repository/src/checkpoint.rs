//! Repository checkpoint drafting.

use crate::error::Result;
use crate::service::Repository;
use rs3_crypto::derive_checkpoint_id;
use rs3_index::{Checkpoint, CommitRecord, KeyringSnapshot, canonical_commit_record_bytes};
use rs3_storage::BlobStore;
use rs3_types::CheckpointId;

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
}
