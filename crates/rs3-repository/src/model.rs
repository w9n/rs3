//! Public repository operation models.

use rs3_types::{CheckpointId, LogicalPath, RetentionPolicy, Sequence};

/// Options for a trusted repository PUT.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepositoryPutOptions {
    /// Reject the write if the client-visible key already exists.
    pub create_only: bool,
    /// Optional retention policy to apply to backend objects.
    pub retention: Option<RetentionPolicy>,
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
