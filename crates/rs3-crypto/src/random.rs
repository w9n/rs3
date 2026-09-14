//! Operating-system randomness for non-secret repository identities.

use crate::CryptoError;

/// Generates 256 random bits for a fresh immutable carrier upload attempt.
pub fn random_carrier_id() -> Result<[u8; 32], CryptoError> {
    random_bytes()
}

/// Generates a fresh identity before sealing a payload or replacement part.
pub fn random_payload_attempt_id() -> Result<rs3_types::PayloadAttemptId, CryptoError> {
    random_bytes().map(rs3_types::PayloadAttemptId::from_bytes)
}

/// Generates a random sort key for hiding logical order inside a payload pack.
pub fn random_physical_order_key() -> Result<[u8; 16], CryptoError> {
    random_bytes()
}

/// Generates a public repository salt for a new repository's envelopes.
///
/// The salt is authenticated envelope context, not key material: envelopes
/// carry it publicly and bind it into their associated data, so a later
/// opener recovers it from a verified envelope instead of configuration.
pub fn random_repository_salt() -> Result<[u8; crate::MIN_REPOSITORY_SALT_LEN], CryptoError> {
    random_bytes()
}

fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|_| CryptoError::RandomnessUnavailable)?;
    Ok(bytes)
}
