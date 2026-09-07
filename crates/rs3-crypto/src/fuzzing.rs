//! Fuzz-only adapters for backend-facing crypto parsers.

use crate::envelope::decode_keyring_plaintext;
use crate::{CryptoError, EnvelopePurpose, KeyRing, RepositoryEnvelope};

/// Decodes a durable keyring envelope object.
pub fn parse_keyring_envelope_object(input: &[u8]) -> Result<RepositoryEnvelope, CryptoError> {
    RepositoryEnvelope::from_object_bytes(input, EnvelopePurpose::Keyring)
}

/// Decodes keyring plaintext after envelope decryption.
pub fn parse_keyring_plaintext(input: &[u8]) -> Result<KeyRing, CryptoError> {
    decode_keyring_plaintext(input)
}
