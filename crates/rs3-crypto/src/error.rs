//! Cryptographic error types.

use rs3_types::{KeyId, KeyPurpose, KeyStatus, TypeError};
use thiserror::Error;

/// Errors returned by cryptographic boundary functions.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Secret material is too short for the requested operation.
    #[error("secret material must be at least {minimum_len} bytes")]
    SecretTooShort {
        /// Minimum accepted secret length.
        minimum_len: usize,
    },
    /// HMAC rejected the supplied key.
    #[error("invalid HMAC key length")]
    InvalidHmacKey,
    /// A derived typed value failed validation.
    #[error(transparent)]
    Type(#[from] TypeError),
    /// Repository key derivation context is empty.
    #[error("repository key derivation context must not be empty")]
    EmptyRepositoryContext,
    /// Repository key derivation salt is too short.
    #[error("repository key derivation salt must be at least {minimum_len} bytes")]
    RepositorySaltTooShort {
        /// Minimum accepted salt length.
        minimum_len: usize,
    },
    /// Repository key derivation failed.
    #[error("repository key derivation failed")]
    KeyDerivationRejected,
    /// No primary key exists for the requested purpose.
    #[error("no primary key for {purpose:?}")]
    NoPrimaryKey {
        /// Key purpose being resolved.
        purpose: KeyPurpose,
    },
    /// More than one primary key exists for the requested purpose.
    #[error("multiple primary keys for {purpose:?}")]
    MultiplePrimaryKeys {
        /// Key purpose being resolved.
        purpose: KeyPurpose,
    },
    /// No enabled key exists for the requested purpose.
    #[error("no enabled key for {purpose:?}")]
    NoEnabledKeys {
        /// Key purpose being resolved.
        purpose: KeyPurpose,
    },
    /// A keyring contains the same key ID more than once.
    #[error("duplicate key id: {key_id}")]
    DuplicateKeyId {
        /// Duplicated key ID.
        key_id: KeyId,
    },
    /// A requested key ID does not exist in the keyring.
    #[error("missing key id: {key_id}")]
    MissingKey {
        /// Missing key ID.
        key_id: KeyId,
    },
    /// A key was used for the wrong cryptographic purpose.
    #[error("key {key_id} has purpose {actual:?}, expected {expected:?}")]
    KeyPurposeMismatch {
        /// Key ID being resolved.
        key_id: KeyId,
        /// Expected purpose.
        expected: KeyPurpose,
        /// Actual purpose.
        actual: KeyPurpose,
    },
    /// A key exists but is not enabled for lookup.
    #[error("key {key_id} has inactive status {status:?}")]
    InactiveKey {
        /// Key ID being resolved.
        key_id: KeyId,
        /// Inactive status.
        status: KeyStatus,
    },
    /// A signature or MAC did not verify.
    #[error("signature verification failed")]
    SignatureMismatch,
    /// Checkpoint signing key material could not produce a signing key.
    #[error("checkpoint signing key material was rejected")]
    CheckpointSigningKeyRejected,
    /// Checkpoint public verification key is malformed.
    #[error("checkpoint public verification key is malformed")]
    CheckpointPublicKeyMalformed,
    /// Authenticated encryption or decryption failed.
    #[error("authenticated encryption operation failed")]
    AeadOperationFailed,
    /// The operating system random source failed.
    #[error("system randomness unavailable")]
    RandomnessUnavailable,
}
