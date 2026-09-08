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
    /// The object exceeds a configured size limit.
    #[error("object exceeds configured maximum size")]
    ObjectTooLarge,
    /// The object body did not match a declared size.
    #[error("object body length does not match declared size")]
    ObjectLengthMismatch,
    /// The object body stream failed before it could be fully read.
    #[error("object body stream could not be read")]
    ObjectBodyReadFailed,
    /// A requested checksum was not resolved by the verified request reader.
    #[error("request checksum is not available from a verified complete body")]
    ObjectChecksumUnavailable,
    /// A declared checksum disagrees with verified uploaded content.
    #[error("request checksum did not match verified content")]
    ObjectChecksumMismatch,
    /// Plaintext did not match the declared Content-MD5.
    #[error("content MD5 did not match request body")]
    ContentMd5Mismatch,
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
    /// Publication was accepted or its outcome is unknown; local recovery is required.
    #[error("repository publication requires local recovery before further mutations")]
    AcceptedRecoveryRequired,
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
    /// A durable object does not match the expected format.
    #[error("invalid durable object format: {object_id}")]
    InvalidObjectFormat {
        /// Invalid backend object ID.
        object_id: BackendObjectId,
    },
}
