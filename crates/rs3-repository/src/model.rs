//! Public repository operation models.

use rs3_types::{
    BackendObjectId, CheckpointId, LegalHoldStatus, LogicalPath, RetentionMode, RetentionPolicy,
    Sequence,
};

/// Options for a trusted repository PUT.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepositoryPutOptions {
    /// Reject the write if the client-visible key already exists.
    pub create_only: bool,
    /// Optional retention policy to apply to backend objects.
    pub retention: Option<RetentionPolicy>,
    /// Optional legal-hold status to apply to backend objects.
    pub legal_hold: Option<LegalHoldStatus>,
}

/// Metadata returned for a client-visible object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryObjectMetadata {
    /// Client-visible key inside the trusted boundary.
    pub key: LogicalPath,
    /// Client-visible content length.
    pub content_len: u64,
    /// Last modification timestamp in milliseconds since the Unix epoch.
    pub modified_at_ms: i64,
    /// Effective retention policy, if known.
    pub retention: Option<RetentionPolicy>,
    /// Effective legal-hold status, if known.
    pub legal_hold: Option<LegalHoldStatus>,
}

/// Repository role for a reachable backend object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BackendObjectReferenceKind {
    /// Signed checkpoint object.
    Checkpoint,
    /// Retained checkpoint evidence object.
    CheckpointEvidence,
    /// Encrypted repository keyring envelope.
    KeyringEnvelope,
    /// Durable index delta object referenced by a checkpoint.
    IndexDelta,
    /// Payload object referenced by a durable index delta.
    Payload,
}

/// Backend object proven reachable from an accepted checkpoint chain.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReachableBackendObject {
    /// Opaque backend object identifier.
    pub object_id: BackendObjectId,
    /// Repository role for this object.
    pub kind: BackendObjectReferenceKind,
}

/// Backend object present in storage but not referenced by the accepted chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryOrphanCandidate {
    /// Opaque backend object identifier.
    pub object_id: BackendObjectId,
    /// Repository role inferred from the owned storage prefix.
    pub kind: BackendObjectReferenceKind,
    /// Object length in bytes.
    pub content_len: u64,
    /// Provider retention policy for this object version, when known.
    pub retention: Option<RetentionPolicy>,
    /// True when the known retention policy would block deletion.
    pub delete_blocked_by_retention: bool,
    /// True when legal hold would block deletion.
    pub delete_blocked_by_legal_hold: bool,
}

/// Dry-run report for backend objects under repository-owned prefixes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryOrphanReport {
    /// Objects referenced by the accepted checkpoint chain.
    pub reachable: Vec<ReachableBackendObject>,
    /// Objects under repository-owned prefixes that are not referenced.
    pub candidates: Vec<RepositoryOrphanCandidate>,
}

impl RepositoryOrphanCandidate {
    pub(crate) fn from_metadata(
        metadata: rs3_storage::BlobMetadata,
        kind: BackendObjectReferenceKind,
    ) -> Self {
        let delete_blocked_by_retention = retention_blocks_delete(metadata.retention.as_ref());
        let delete_blocked_by_legal_hold = metadata.legal_hold == Some(LegalHoldStatus::On);
        Self {
            object_id: metadata.object_id,
            kind,
            content_len: metadata.content_len,
            retention: metadata.retention,
            delete_blocked_by_retention,
            delete_blocked_by_legal_hold,
        }
    }
}

fn retention_blocks_delete(policy: Option<&RetentionPolicy>) -> bool {
    match policy {
        Some(policy) => policy.mode != RetentionMode::None && policy.retain_days > 0,
        None => false,
    }
}

/// Result of a PUT that reached an accepted checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedPut {
    /// Client-visible metadata for the written object.
    pub metadata: RepositoryObjectMetadata,
    /// Checkpoint that made the write durable repository state.
    pub checkpoint: CheckpointPosition,
}

/// Entry returned from trusted namespace listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryListEntry {
    /// Client-visible key inside the trusted boundary.
    pub key: LogicalPath,
    /// Client-visible content length.
    pub content_len: u64,
    /// Last modification timestamp in milliseconds since the Unix epoch.
    pub modified_at_ms: i64,
}

/// Result of a logical delete operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeleteOutcome {
    /// What happened to the backend payload object.
    pub physical: PhysicalDeleteOutcome,
}

/// Physical delete result after a namespace tombstone was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhysicalDeleteOutcome {
    /// The backend object was removed.
    Removed,
    /// The backend object is still retained by provider policy.
    Retained,
    /// The backend object was already gone.
    AlreadyGone,
}

/// Accepted checkpoint position used by monotonic validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointPosition {
    /// Accepted checkpoint sequence.
    pub sequence: Sequence,
    /// Accepted checkpoint ID.
    pub checkpoint_id: CheckpointId,
    /// Digest of the canonical checkpoint payload.
    pub payload_digest: String,
}

impl CheckpointPosition {
    /// Converts this position into an external anchor state.
    pub fn into_anchor_state(self) -> rs3_anchor::AnchorState {
        rs3_anchor::AnchorState {
            sequence: self.sequence,
            checkpoint_id: self.checkpoint_id,
            checkpoint_digest: self.payload_digest,
        }
    }
}

impl From<rs3_anchor::AnchorState> for CheckpointPosition {
    fn from(value: rs3_anchor::AnchorState) -> Self {
        Self {
            sequence: value.sequence,
            checkpoint_id: value.checkpoint_id,
            payload_digest: value.checkpoint_digest,
        }
    }
}
