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
    #[error("object not found: {0}")]
    NotFound(LogicalPath),
    /// The client-visible object already exists and create-only mode was requested.
    #[error("object already exists: {0}")]
    AlreadyExists(LogicalPath),
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
    /// The checkpoint does not chain from the accepted position.
    #[error("checkpoint parent mismatch")]
    CheckpointParentMismatch,
}
