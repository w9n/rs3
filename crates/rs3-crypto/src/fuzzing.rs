//! Fuzz-only adapters for backend-facing crypto parsers.

use crate::envelope::decode_keyring_plaintext;
use crate::{CryptoError, EnvelopePurpose, KeyRing, RepositoryEnvelope};

/// Decodes a durable envelope of the required authenticated purpose.
pub fn parse_repository_envelope_object(
    input: &[u8],
    purpose: EnvelopePurpose,
) -> Result<RepositoryEnvelope, CryptoError> {
    RepositoryEnvelope::from_object_bytes(input, purpose)
}

/// Decodes keyring plaintext after envelope decryption.
pub fn parse_keyring_plaintext(input: &[u8]) -> Result<KeyRing, CryptoError> {
    decode_keyring_plaintext(input)
}
