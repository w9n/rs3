//! Operating-system randomness for non-secret repository identities.

use crate::CryptoError;
use rs3_types::PAYLOAD_NONCE_PREFIX_LEN;

/// Generates 256 random bits for a fresh immutable carrier upload attempt.
pub fn random_carrier_id() -> Result<[u8; 32], CryptoError> {
    random_bytes()
}

/// Generates a fresh nonce prefix for one segmented or streamable payload.
pub fn random_payload_nonce_prefix() -> Result<[u8; PAYLOAD_NONCE_PREFIX_LEN], CryptoError> {
    random_bytes()
}

/// Generates a random sort key for hiding logical order inside a payload pack.
pub fn random_physical_order_key() -> Result<[u8; 16], CryptoError> {
    random_bytes()
}

fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|_| CryptoError::RandomnessUnavailable)?;
    Ok(bytes)
}
