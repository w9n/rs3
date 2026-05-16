//! Repository error types.

use rs3_anchor::AnchorError;
use rs3_crypto::CryptoError;
use rs3_storage::StorageError;
use rs3_types::{BackendObjectId, CheckpointId, LogicalPath, Sequence, TypeError};
use thiserror::Error;

/// Repository operation result.
pub type Result<T> = std::result::Result<T, RepositoryError>;

/// Errors returned by trusted repository operations.
#[derive(Debug, Error)]
pub enum RepositoryError {
    /// A client-visible object was not found in the namespace.
    #[error("object not found")]
    NotFound(LogicalPath),
    /// The client-visible object already exists and create-only mode was requested.
    #[error("object already exists")]
    AlreadyExists(LogicalPath),
    /// The selected repository format cannot serve this operation yet.
    #[error("repository format is not supported by this operation: {format}")]
    UnsupportedRepositoryFormat {
        /// Repository format spelling.
        format: &'static str,
    },
    /// Repository sequence allocation overflowed.
    #[error("repository sequence overflow")]
    SequenceOverflow,
    /// The repository lock was poisoned.
    #[error("repository state lock poisoned")]
    StatePoisoned,
    /// Type validation failed.
    #[error(transparent)]
    Type(#[from] TypeError),
    /// Cryptographic derivation failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// Storage operation failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// Checkpoint anchor operation failed.
    #[error(transparent)]
    Anchor(#[from] AnchorError),
    /// Checkpoint canonical encoding failed.
    #[error(transparent)]
    CheckpointEncoding(#[from] serde_json::Error),
    /// A coordinated commit failed and the coordinator stopped accepting writes.
    #[error("commit coordinator failed: {reason}")]
    CommitFailed {
        /// Failure reason.
        reason: String,
    },
    /// Too many writes are waiting for coordinated commit.
    #[error("commit coordinator is overloaded")]
    CommitBackpressure,
    /// The checkpoint ID does not match the signed payload.
    #[error("checkpoint id mismatch")]
    CheckpointIdMismatch,
    /// The checkpoint is older than the accepted position.
    #[error("stale checkpoint sequence: {sequence:?}")]
    StaleCheckpoint {
        /// Stale checkpoint sequence.
        sequence: Sequence,
    },
    /// The checkpoint reuses an accepted sequence with different content.
    #[error("checkpoint conflicts with accepted position: {checkpoint_id}")]
    CheckpointConflict {
        /// Conflicting checkpoint ID.
        checkpoint_id: CheckpointId,
    },
    /// A stored checkpoint object has different content than expected.
    #[error("checkpoint object conflicts with expected content: {object_id}")]
    CheckpointObjectConflict {
        /// Conflicting backend object ID.
        object_id: BackendObjectId,
    },
    /// A stored checkpoint evidence object has different content than expected.
    #[error("checkpoint evidence object conflicts with expected content: {object_id}")]
    CheckpointEvidenceObjectConflict {
        /// Conflicting backend object ID.
        object_id: BackendObjectId,
    },
    /// A stored keyring envelope object has different content than expected.
    #[error("keyring envelope object conflicts with expected content: {object_id}")]
    KeyringEnvelopeObjectConflict {
        /// Conflicting backend object ID.
        object_id: BackendObjectId,
    },
    /// A stored index delta object has different content than expected.
    #[error("index delta object conflicts with expected content: {object_id}")]
    IndexDeltaObjectConflict {
        /// Conflicting backend object ID.
        object_id: BackendObjectId,
    },
    /// A durable object does not match the expected format.
    #[error("invalid durable object format: {object_id}")]
    InvalidObjectFormat {
        /// Invalid backend object ID.
        object_id: BackendObjectId,
    },
    /// The checkpoint does not chain from the accepted position.
    #[error("checkpoint parent mismatch")]
    CheckpointParentMismatch,
    /// A checkpoint chain moves publish time backwards.
    #[error("checkpoint published timestamp decreased: {checkpoint_id}")]
    CheckpointPublishedAtDecreased {
        /// Checkpoint whose publish timestamp moved backwards.
        checkpoint_id: CheckpointId,
    },
}
