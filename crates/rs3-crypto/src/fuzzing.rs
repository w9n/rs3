//! Fuzz-only adapters for backend-facing crypto parsers.

use crate::envelope::decode_keyring_plaintext;
use crate::{CryptoError, KeyRing, KeyringEnvelope};

/// Decodes a durable keyring envelope object.
pub fn parse_keyring_envelope_object(input: &[u8]) -> Result<KeyringEnvelope, CryptoError> {
    KeyringEnvelope::from_object_bytes(input)
}

/// Decodes keyring plaintext after envelope decryption.
pub fn parse_keyring_plaintext(input: &[u8]) -> Result<KeyRing, CryptoError> {
    decode_keyring_plaintext(input)
}
