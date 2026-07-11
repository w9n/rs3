//! Repository error types.

use rs3_crypto::CryptoError;
use rs3_storage::StorageError;
use rs3_types::{BackendObjectId, LogicalPath, TypeError};
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
    /// The object exceeds a configured size limit.
    #[error("object exceeds configured maximum size")]
    ObjectTooLarge,
    /// The object body did not match a declared size.
    #[error("object body length does not match declared size")]
    ObjectLengthMismatch,
    /// The object body stream failed before it could be fully read.
    #[error("object body stream could not be read")]
    ObjectBodyReadFailed,
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
    /// Checkpoint canonical encoding failed.
    #[error(transparent)]
    CheckpointEncoding(#[from] serde_json::Error),
    /// A coordinated commit failed and the coordinator stopped accepting writes.
    #[error("commit coordinator failed: {reason}")]
    CommitFailed {
        /// Failure reason.
        reason: String,
    },
    /// A validated maintenance candidate would not reduce repository metadata.
    #[error("repository maintenance candidate is not reducing")]
    MaintenanceNotBeneficial,
    /// Too many writes are waiting for coordinated commit.
    #[error("commit coordinator is overloaded")]
    CommitBackpressure,
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
}
