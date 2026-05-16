//! Encrypted repository keyring envelopes.
//!
//! The envelope lets operators rotate a wrapping-key source, such as a
//! KMS/HSM/Vault-derived key or other high-entropy key, without rewriting
//! payload objects. The repository stores only encrypted key material; the
//! wrapping-key source stays outside the object store.

use crate::fingerprint::derive_public_fingerprint;
use crate::keyring::{KeyMaterial, KeyRing, RepositoryKeyContext};
use crate::primitives::derive_hmac;
use crate::{CryptoError, SecretBytes};
use aes_gcm_siv::aead::{AeadInPlace, KeyInit};
use aes_gcm_siv::{Aes256GcmSiv, Nonce, Tag};
use rs3_types::{KeyDescriptor, RepositoryId};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// Current keyring-envelope format version.
pub const KEYRING_ENVELOPE_VERSION: u16 = 1;

const ENVELOPE_NONCE_LEN: usize = 12;
const ENVELOPE_TAG_LEN: usize = 16;
const ENVELOPE_DIGEST_DOMAIN: &[u8] = b"rs3:keyring-envelope-digest:v1";
const ENVELOPE_OBJECT_DOMAIN: &[u8] = b"rs3:keyring-envelope-object:v1\n";
const ENVELOPE_PLAINTEXT_DOMAIN: &[u8] = b"rs3:keyring-envelope-plaintext:v1\n";
const FORMAT_ENVELOPE_DIGEST_DOMAIN: &[u8] = b"rs3:format-envelope-digest:v1";
const FORMAT_ENVELOPE_OBJECT_DOMAIN: &[u8] = b"rs3:format-envelope-object:v1\n";

/// Current format-envelope version.
pub const FORMAT_ENVELOPE_VERSION: u16 = 1;

/// Encrypted repository keyring stored as public repository metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyringEnvelope {
    /// Envelope format version.
    pub version: u16,
    /// Monotonic envelope generation assigned by the operator workflow.
    pub generation: u64,
    /// Repository ID this envelope is bound to.
    pub repository_id: RepositoryId,
    /// Public repository salt this envelope is bound to.
    pub repository_salt: Vec<u8>,
    /// Operator-visible wrapping key identifier.
    pub wrapping_key_id: String,
    /// Random AEAD nonce.
    pub nonce: Vec<u8>,
    /// Encrypted keyring plaintext.
    pub ciphertext: Vec<u8>,
    /// AEAD authentication tag.
    pub tag: Vec<u8>,
}

/// Encrypted v2 format-root metadata stored in the repository.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormatEnvelope {
    /// Envelope format version.
    pub version: u16,
    /// Monotonic format generation assigned by the operator workflow.
    pub generation: u64,
    /// Repository ID this format root is bound to.
    pub repository_id: RepositoryId,
    /// Public repository salt this format root is bound to.
    pub repository_salt: Vec<u8>,
    /// Operator-visible wrapping key identifier.
    pub wrapping_key_id: String,
    /// Random AEAD nonce.
    pub nonce: Vec<u8>,
    /// Encrypted format-root plaintext.
    pub ciphertext: Vec<u8>,
    /// AEAD authentication tag.
    pub tag: Vec<u8>,
}

impl KeyRing {
    /// Encrypts this keyring into a repository-bound envelope.
    pub fn seal_keyring_envelope(
        &self,
        context: &RepositoryKeyContext,
        wrapping_key_id: &str,
        wrapping_key: &SecretBytes,
        generation: u64,
    ) -> Result<KeyringEnvelope, CryptoError> {
        let nonce = random_envelope_nonce()?;
        self.seal_keyring_envelope_with_nonce(
            context,
            wrapping_key_id,
            wrapping_key,
            generation,
            &nonce,
        )
    }

    fn seal_keyring_envelope_with_nonce(
        &self,
        context: &RepositoryKeyContext,
        wrapping_key_id: &str,
        wrapping_key: &SecretBytes,
        generation: u64,
        nonce: &[u8],
    ) -> Result<KeyringEnvelope, CryptoError> {
        validate_wrapping_key_id(wrapping_key_id)?;
        if nonce.len() != ENVELOPE_NONCE_LEN {
            return Err(CryptoError::AeadOperationFailed);
        }

        let mut plaintext = Zeroizing::new(keyring_plaintext_bytes(self)?);
        let mut envelope = KeyringEnvelope {
            version: KEYRING_ENVELOPE_VERSION,
            generation,
            repository_id: context.repository_id().clone(),
            repository_salt: context.salt().to_vec(),
            wrapping_key_id: wrapping_key_id.to_owned(),
            nonce: nonce.to_vec(),
            ciphertext: Vec::new(),
            tag: Vec::new(),
        };
        let associated_data = envelope.associated_data()?;
        let cipher = envelope_cipher(wrapping_key)?;
        let tag = cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(nonce),
                &associated_data,
                plaintext.as_mut(),
            )
            .map_err(|_| CryptoError::AeadOperationFailed)?;
        envelope.ciphertext = plaintext.to_vec();
        envelope.tag = tag.to_vec();

        Ok(envelope)
    }
}

impl FormatEnvelope {
    /// Encrypts a v2 format-root plaintext with the operator wrapping key.
    pub fn seal(
        context: &RepositoryKeyContext,
        wrapping_key_id: &str,
        wrapping_key: &SecretBytes,
        generation: u64,
        plaintext: &[u8],
    ) -> Result<Self, CryptoError> {
        validate_wrapping_key_id(wrapping_key_id)?;
        let nonce = random_envelope_nonce()?;
        let mut envelope = Self {
            version: FORMAT_ENVELOPE_VERSION,
            generation,
            repository_id: context.repository_id().clone(),
            repository_salt: context.salt().to_vec(),
            wrapping_key_id: wrapping_key_id.to_owned(),
            nonce: nonce.to_vec(),
            ciphertext: Vec::new(),
            tag: Vec::new(),
        };
        let associated_data = envelope.associated_data()?;
        let cipher = format_envelope_cipher(wrapping_key)?;
        let mut ciphertext = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &associated_data, &mut ciphertext)
            .map_err(|_| CryptoError::AeadOperationFailed)?;
        envelope.ciphertext = ciphertext;
        envelope.tag = tag.to_vec();
        Ok(envelope)
    }

    /// Opens this format envelope into plaintext bytes.
    pub fn open(
        &self,
        expected_context: &RepositoryKeyContext,
        wrapping_key_id: &str,
        wrapping_key: &SecretBytes,
    ) -> Result<Vec<u8>, CryptoError> {
        self.validate_public_fields(expected_context, wrapping_key_id)?;
        if self.tag.len() != ENVELOPE_TAG_LEN || self.nonce.len() != ENVELOPE_NONCE_LEN {
            return Err(CryptoError::AeadOperationFailed);
        }
        let associated_data = self.associated_data()?;
        let cipher = format_envelope_cipher(wrapping_key)?;
        let mut plaintext = self.ciphertext.clone();
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&self.nonce),
                &associated_data,
                &mut plaintext,
                Tag::from_slice(&self.tag),
            )
            .map_err(|_| CryptoError::AeadOperationFailed)?;
        Ok(plaintext)
    }

    /// Returns a public digest suitable for anchor binding.
    pub fn digest(&self) -> Result<String, CryptoError> {
        let bytes = serde_json::to_vec(self).map_err(format_envelope_codec_error)?;
        Ok(derive_public_fingerprint(
            FORMAT_ENVELOPE_DIGEST_DOMAIN,
            &[bytes.as_slice()],
        ))
    }

    /// Encodes this envelope as a durable repository object.
    pub fn to_object_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let mut bytes = FORMAT_ENVELOPE_OBJECT_DOMAIN.to_vec();
        serde_json::to_writer(&mut bytes, self).map_err(format_envelope_codec_error)?;
        Ok(bytes)
    }

    /// Decodes a durable repository format envelope object.
    pub fn from_object_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let Some(payload) = bytes.strip_prefix(FORMAT_ENVELOPE_OBJECT_DOMAIN) else {
            return Err(invalid_format_envelope(
                "missing format envelope object domain",
            ));
        };
        serde_json::from_slice(payload).map_err(format_envelope_codec_error)
    }

    fn validate_public_fields(
        &self,
        expected_context: &RepositoryKeyContext,
        wrapping_key_id: &str,
    ) -> Result<(), CryptoError> {
        validate_wrapping_key_id(wrapping_key_id)?;
        if self.version != FORMAT_ENVELOPE_VERSION {
            return Err(invalid_format_envelope("unsupported envelope version"));
        }
        if self.repository_id != *expected_context.repository_id()
            || self.repository_salt != expected_context.salt()
        {
            return Err(invalid_format_envelope(
                "repository context does not match format envelope",
            ));
        }
        if self.wrapping_key_id != wrapping_key_id {
            return Err(invalid_format_envelope(
                "wrapping key id does not match format envelope",
            ));
        }
        Ok(())
    }

    fn associated_data(&self) -> Result<Vec<u8>, CryptoError> {
        let fields = EnvelopeAssociatedData {
            version: self.version,
            generation: self.generation,
            repository_id: self.repository_id.clone(),
            repository_salt: self.repository_salt.clone(),
            wrapping_key_id: self.wrapping_key_id.clone(),
            nonce: self.nonce.clone(),
        };
        serde_json::to_vec(&fields).map_err(format_envelope_codec_error)
    }
}

impl KeyringEnvelope {
    /// Opens this envelope into a validated repository keyring.
    pub fn open(
        &self,
        expected_context: &RepositoryKeyContext,
        wrapping_key_id: &str,
        wrapping_key: &SecretBytes,
    ) -> Result<KeyRing, CryptoError> {
        self.validate_public_fields(expected_context, wrapping_key_id)?;
        let associated_data = self.associated_data()?;
        let cipher = envelope_cipher(wrapping_key)?;
        if self.tag.len() != ENVELOPE_TAG_LEN || self.nonce.len() != ENVELOPE_NONCE_LEN {
            return Err(CryptoError::AeadOperationFailed);
        }
        let mut plaintext = Zeroizing::new(self.ciphertext.clone());
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&self.nonce),
                &associated_data,
                plaintext.as_mut(),
                Tag::from_slice(&self.tag),
            )
            .map_err(|_| CryptoError::AeadOperationFailed)?;

        decode_keyring_plaintext(&plaintext)
    }

    /// Re-encrypts this envelope with a new wrapping-key source.
    ///
    /// The repository data keys are preserved. Payload and metadata objects do
    /// not need to be rewritten for normal wrapping-key rewrap.
    pub fn rewrap(
        &self,
        expected_context: &RepositoryKeyContext,
        old_wrapping_key_id: &str,
        old_wrapping_key: &SecretBytes,
        new_wrapping_key_id: &str,
        new_wrapping_key: &SecretBytes,
        new_generation: u64,
    ) -> Result<Self, CryptoError> {
        let keyring = self.open(expected_context, old_wrapping_key_id, old_wrapping_key)?;
        keyring.seal_keyring_envelope(
            expected_context,
            new_wrapping_key_id,
            new_wrapping_key,
            new_generation,
        )
    }

    /// Returns a public digest suitable for checkpoint binding.
    pub fn digest(&self) -> Result<String, CryptoError> {
        let bytes = serde_json::to_vec(self).map_err(envelope_codec_error)?;
        Ok(derive_public_fingerprint(
            ENVELOPE_DIGEST_DOMAIN,
            &[bytes.as_slice()],
        ))
    }

    /// Encodes this envelope as a durable repository object.
    pub fn to_object_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let mut bytes = ENVELOPE_OBJECT_DOMAIN.to_vec();
        serde_json::to_writer(&mut bytes, self).map_err(envelope_codec_error)?;
        Ok(bytes)
    }

    /// Decodes a durable repository envelope object.
    pub fn from_object_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let Some(payload) = bytes.strip_prefix(ENVELOPE_OBJECT_DOMAIN) else {
            return Err(invalid_envelope("missing keyring envelope object domain"));
        };
        serde_json::from_slice(payload).map_err(envelope_codec_error)
    }

    fn validate_public_fields(
        &self,
        expected_context: &RepositoryKeyContext,
        wrapping_key_id: &str,
    ) -> Result<(), CryptoError> {
        validate_wrapping_key_id(wrapping_key_id)?;
        if self.version != KEYRING_ENVELOPE_VERSION {
            return Err(invalid_envelope("unsupported envelope version"));
        }
        if self.repository_id != *expected_context.repository_id()
            || self.repository_salt != expected_context.salt()
        {
            return Err(invalid_envelope(
                "repository context does not match keyring envelope",
            ));
        }
        if self.wrapping_key_id != wrapping_key_id {
            return Err(invalid_envelope("wrapping key id does not match envelope"));
        }
        Ok(())
    }

    fn associated_data(&self) -> Result<Vec<u8>, CryptoError> {
        let fields = EnvelopeAssociatedData {
            version: self.version,
            generation: self.generation,
            repository_id: self.repository_id.clone(),
            repository_salt: self.repository_salt.clone(),
            wrapping_key_id: self.wrapping_key_id.clone(),
            nonce: self.nonce.clone(),
        };
        serde_json::to_vec(&fields).map_err(envelope_codec_error)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct EnvelopeAssociatedData {
    version: u16,
    generation: u64,
    repository_id: RepositoryId,
    repository_salt: Vec<u8>,
    wrapping_key_id: String,
    nonce: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeyringPlaintext {
    version: u16,
    keys: Vec<PlaintextKeyMaterial>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PlaintextKeyMaterial {
    descriptor: KeyDescriptor,
    secret_hex: String,
}

fn keyring_plaintext_bytes(keyring: &KeyRing) -> Result<Vec<u8>, CryptoError> {
    let mut keys = keyring
        .key_materials()
        .iter()
        .map(|key| PlaintextKeyMaterial {
            descriptor: key.descriptor().clone(),
            secret_hex: hex::encode(key.secret.expose()),
        })
        .collect::<Vec<_>>();
    keys.sort_by(|left, right| {
        left.descriptor
            .purpose
            .cmp(&right.descriptor.purpose)
            .then_with(|| left.descriptor.id.cmp(&right.descriptor.id))
    });
    let mut plaintext = KeyringPlaintext {
        version: KEYRING_ENVELOPE_VERSION,
        keys,
    };
    let mut bytes = ENVELOPE_PLAINTEXT_DOMAIN.to_vec();
    serde_json::to_writer(&mut bytes, &plaintext).map_err(envelope_codec_error)?;
    for key in &mut plaintext.keys {
        key.secret_hex.zeroize();
    }
    Ok(bytes)
}

fn decode_keyring_plaintext(plaintext: &[u8]) -> Result<KeyRing, CryptoError> {
    let Some(json) = plaintext.strip_prefix(ENVELOPE_PLAINTEXT_DOMAIN) else {
        return Err(invalid_envelope("missing keyring plaintext domain"));
    };
    let mut plaintext: KeyringPlaintext =
        serde_json::from_slice(json).map_err(envelope_codec_error)?;
    if plaintext.version != KEYRING_ENVELOPE_VERSION {
        return Err(invalid_envelope("unsupported plaintext version"));
    }

    let mut keys = Vec::with_capacity(plaintext.keys.len());
    for key in &mut plaintext.keys {
        let secret = hex::decode(&key.secret_hex)
            .map_err(|_| invalid_envelope("keyring plaintext contains non-hex secret material"))?;
        key.secret_hex.zeroize();
        keys.push(KeyMaterial::new(
            key.descriptor.clone(),
            SecretBytes::new(secret)?,
        ));
    }

    KeyRing::new(keys)
}

fn envelope_cipher(wrapping_key: &SecretBytes) -> Result<Aes256GcmSiv, CryptoError> {
    let key = derive_hmac(
        wrapping_key,
        b"rs3:keyring-envelope-aead-key:v1",
        b"aes-256-gcm-siv",
    )?;
    Aes256GcmSiv::new_from_slice(&key).map_err(|_| CryptoError::AeadOperationFailed)
}

fn format_envelope_cipher(wrapping_key: &SecretBytes) -> Result<Aes256GcmSiv, CryptoError> {
    let key = derive_hmac(
        wrapping_key,
        b"rs3:format-envelope-aead-key:v1",
        b"aes-256-gcm-siv",
    )?;
    Aes256GcmSiv::new_from_slice(&key).map_err(|_| CryptoError::AeadOperationFailed)
}

fn random_envelope_nonce() -> Result<[u8; ENVELOPE_NONCE_LEN], CryptoError> {
    let mut nonce = [0_u8; ENVELOPE_NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| CryptoError::RandomnessUnavailable)?;
    Ok(nonce)
}

fn validate_wrapping_key_id(value: &str) -> Result<(), CryptoError> {
    if value.trim().is_empty() {
        Err(invalid_envelope("wrapping key id must not be empty"))
    } else {
        Ok(())
    }
}

fn envelope_codec_error(error: serde_json::Error) -> CryptoError {
    CryptoError::KeyringEnvelopeCodec {
        reason: error.to_string(),
    }
}

fn format_envelope_codec_error(error: serde_json::Error) -> CryptoError {
    CryptoError::FormatEnvelopeCodec {
        reason: error.to_string(),
    }
}

fn invalid_envelope(reason: &str) -> CryptoError {
    CryptoError::InvalidKeyringEnvelope {
        reason: reason.to_owned(),
    }
}

fn invalid_format_envelope(reason: &str) -> CryptoError {
    CryptoError::InvalidFormatEnvelope {
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::{FormatEnvelope, KEYRING_ENVELOPE_VERSION, KeyringEnvelope};
    use crate::{KeyRing, RepositoryKeyContext, SecretBytes};
    use rs3_types::RepositoryId;

    fn secret(byte: u8) -> SecretBytes {
        SecretBytes::new(vec![byte; SecretBytes::MIN_LEN]).unwrap_or_else(|error| panic!("{error}"))
    }

    fn context(repository_id: &str, salt_byte: u8) -> RepositoryKeyContext {
        let repository_id =
            RepositoryId::new(repository_id).unwrap_or_else(|error| panic!("{error}"));
        RepositoryKeyContext::new(repository_id, vec![salt_byte; 32])
            .unwrap_or_else(|error| panic!("{error}"))
    }

    fn keyring() -> KeyRing {
        KeyRing::generate_random().unwrap_or_else(|error| panic!("{error}"))
    }

    #[test]
    fn keyring_envelope_round_trips_repository_keys() {
        let context = context("repo-a", 2);
        let keyring = keyring();
        let envelope = keyring
            .seal_keyring_envelope(&context, "wrap-v1", &secret(9), 1)
            .unwrap_or_else(|error| panic!("{error}"));

        let opened = envelope
            .open(&context, "wrap-v1", &secret(9))
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(envelope.version, KEYRING_ENVELOPE_VERSION);
        assert_eq!(opened.descriptors(), keyring.descriptors());
        assert_eq!(
            opened
                .derive_backend_object_id("segments", b"same")
                .unwrap_or_else(|error| panic!("{error}")),
            keyring
                .derive_backend_object_id("segments", b"same")
                .unwrap_or_else(|error| panic!("{error}"))
        );
    }

    #[test]
    fn keyring_envelope_rewrap_preserves_data_keys() {
        let context = context("repo-a", 2);
        let keyring = keyring();
        let envelope = keyring
            .seal_keyring_envelope(&context, "wrap-v1", &secret(9), 1)
            .unwrap_or_else(|error| panic!("{error}"));
        let rewrapped = envelope
            .rewrap(&context, "wrap-v1", &secret(9), "wrap-v2", &secret(10), 2)
            .unwrap_or_else(|error| panic!("{error}"));

        let payload = keyring
            .seal_payload(b"associated-data", b"payload")
            .unwrap_or_else(|error| panic!("{error}"));
        let opened = rewrapped
            .open(&context, "wrap-v2", &secret(10))
            .unwrap_or_else(|error| panic!("{error}"));
        let plaintext = opened
            .open_payload(
                &payload.key_id,
                b"associated-data",
                &payload.nonce,
                &payload.ciphertext,
            )
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(rewrapped.generation, 2);
        assert_eq!(rewrapped.wrapping_key_id, "wrap-v2");
        assert_eq!(plaintext, b"payload");
    }

    #[test]
    fn format_envelope_round_trips_and_rejects_wrong_context() {
        let context = context("repo-a", 2);
        let plaintext = b"rs3-format-root";
        let envelope = FormatEnvelope::seal(&context, "wrap-v1", &secret(9), 1, plaintext)
            .unwrap_or_else(|error| panic!("{error}"));
        let bytes = envelope
            .to_object_bytes()
            .unwrap_or_else(|error| panic!("{error}"));
        let decoded =
            FormatEnvelope::from_object_bytes(&bytes).unwrap_or_else(|error| panic!("{error}"));

        let opened = decoded
            .open(&context, "wrap-v1", &secret(9))
            .unwrap_or_else(|error| panic!("{error}"));
        let wrong = RepositoryKeyContext::new(
            RepositoryId::new("other-repository").unwrap_or_else(|error| panic!("{error}")),
            vec![7; 32],
        )
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(opened, plaintext);
        assert!(decoded.digest().is_ok());
        assert!(decoded.open(&wrong, "wrap-v1", &secret(9)).is_err());
    }

    #[test]
    fn keyring_envelope_rejects_wrong_wrapping_key() {
        let context = context("repo-a", 2);
        let envelope = keyring()
            .seal_keyring_envelope(&context, "wrap-v1", &secret(9), 1)
            .unwrap_or_else(|error| panic!("{error}"));

        let opened = envelope.open(&context, "wrap-v1", &secret(8));

        assert!(opened.is_err());
    }

    #[test]
    fn keyring_envelope_rejects_wrong_context() {
        let expected_context = context("repo-a", 2);
        let envelope = keyring()
            .seal_keyring_envelope(&expected_context, "wrap-v1", &secret(9), 1)
            .unwrap_or_else(|error| panic!("{error}"));

        let opened = envelope.open(&context("repo-b", 2), "wrap-v1", &secret(9));

        assert!(opened.is_err());
    }

    #[test]
    fn keyring_envelope_digest_changes_when_public_binding_changes() {
        let context = context("repo-a", 2);
        let envelope = keyring()
            .seal_keyring_envelope(&context, "wrap-v1", &secret(9), 1)
            .unwrap_or_else(|error| panic!("{error}"));
        let mut changed: KeyringEnvelope = envelope.clone();
        changed.generation = 2;

        assert_ne!(
            envelope.digest().unwrap_or_else(|error| panic!("{error}")),
            changed.digest().unwrap_or_else(|error| panic!("{error}"))
        );
    }

    #[test]
    fn keyring_envelope_object_encoding_has_domain_prefix() {
        let context = context("repo-a", 2);
        let envelope = keyring()
            .seal_keyring_envelope(&context, "wrap-v1", &secret(9), 1)
            .unwrap_or_else(|error| panic!("{error}"));
        let body = envelope
            .to_object_bytes()
            .unwrap_or_else(|error| panic!("{error}"));

        let decoded =
            KeyringEnvelope::from_object_bytes(&body).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(decoded, envelope);
    }
}
