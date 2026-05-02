//! Repository error types.

use rs3_crypto::CryptoError;
use rs3_storage::StorageError;
use rs3_types::{LogicalPath, TypeError};
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
    /// Checkpoint canonical encoding failed.
    #[error(transparent)]
    CheckpointEncoding(#[from] serde_json::Error),
}
