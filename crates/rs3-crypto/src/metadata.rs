//! Metadata payload sealing helpers.
//!
//! Metadata uses the `aes-gcm-siv` crate's AES-256-GCM-SIV AEAD. The nonce is
//! deterministically derived from secret key material, associated data, and
//! plaintext so retrying the same manifest/index write is stable. GCM-SIV keeps
//! the metadata boundary on a standard misuse-resistant AEAD construction.

use crate::keyring::KeyRing;
use crate::primitives::derive_hmac;
use crate::{CryptoError, SecretBytes};
use aes_gcm_siv::aead::{AeadInPlace, KeyInit};
use aes_gcm_siv::{Aes256GcmSiv, Nonce, Tag};
use rs3_types::{KeyId, KeyPurpose};

const METADATA_NONCE_LEN: usize = 12;
const METADATA_TAG_LEN: usize = 16;

/// Sealed metadata payload and the key that produced it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataSeal {
    /// Metadata key ID.
    pub key_id: KeyId,
    /// Deterministic nonce for this sealed payload.
    pub nonce: Vec<u8>,
    /// Sealed payload bytes.
    pub ciphertext: Vec<u8>,
    /// Authentication tag over associated data and sealed bytes.
    pub tag: Vec<u8>,
}

impl KeyRing {
    /// Seals metadata bytes with the primary metadata key.
    pub fn seal_metadata_payload(
        &self,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<MetadataSeal, CryptoError> {
        let key = self.primary_key(KeyPurpose::Metadata)?;
        let nonce = metadata_nonce(&key.secret, associated_data, plaintext)?;
        let (ciphertext, tag) =
            encrypt_metadata_with_key(&key.secret, associated_data, &nonce, plaintext)?;

        Ok(MetadataSeal {
            key_id: key.descriptor.id.clone(),
            nonce,
            ciphertext,
            tag,
        })
    }

    /// Opens metadata bytes with an enabled metadata key.
    pub fn open_metadata_payload(
        &self,
        key_id: &KeyId,
        associated_data: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let key = self.enabled_key_by_id(key_id, KeyPurpose::Metadata)?;
        decrypt_metadata_with_key(&key.secret, associated_data, nonce, ciphertext, tag)
    }
}

fn metadata_nonce(
    secret: &SecretBytes,
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let material = nonce_material(associated_data, plaintext);
    let mut nonce = derive_hmac(secret, b"rs3:metadata-aead-nonce:v1", &material)?;
    nonce.truncate(METADATA_NONCE_LEN);
    Ok(nonce)
}

fn encrypt_metadata_with_key(
    secret: &SecretBytes,
    associated_data: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let cipher = metadata_cipher(secret)?;
    if nonce.len() != METADATA_NONCE_LEN {
        return Err(CryptoError::AeadOperationFailed);
    }
    let mut ciphertext = Vec::with_capacity(plaintext.len() + METADATA_TAG_LEN);
    ciphertext.extend_from_slice(plaintext);
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce), associated_data, &mut ciphertext)
        .map_err(|_| CryptoError::AeadOperationFailed)?;
    Ok((ciphertext, tag.to_vec()))
}

fn decrypt_metadata_with_key(
    secret: &SecretBytes,
    associated_data: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = metadata_cipher(secret)?;
    if nonce.len() != METADATA_NONCE_LEN || tag.len() != METADATA_TAG_LEN {
        return Err(CryptoError::AeadOperationFailed);
    }
    let mut plaintext = ciphertext.to_vec();
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(nonce),
            associated_data,
            &mut plaintext,
            Tag::from_slice(tag),
        )
        .map_err(|_| CryptoError::AeadOperationFailed)?;
    Ok(plaintext)
}

fn metadata_cipher(secret: &SecretBytes) -> Result<Aes256GcmSiv, CryptoError> {
    let key = derive_hmac(secret, b"rs3:metadata-aead-key:v2", b"aes-256-gcm-siv")?;
    Aes256GcmSiv::new_from_slice(&key).map_err(|_| CryptoError::AeadOperationFailed)
}

fn nonce_material(associated_data: &[u8], plaintext: &[u8]) -> Vec<u8> {
    framed_pair(associated_data, plaintext)
}

fn framed_pair(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut material = Vec::with_capacity(16 + left.len() + right.len());
    material.extend_from_slice(&(left.len() as u64).to_be_bytes());
    material.extend_from_slice(left);
    material.extend_from_slice(&(right.len() as u64).to_be_bytes());
    material.extend_from_slice(right);
    material
}

#[cfg(test)]
mod tests {
    use super::MetadataSeal;
    use crate::{KeyMaterial, KeyRing, SecretBytes};
    use rs3_types::{KeyDescriptor, KeyId, KeyPurpose, KeyStatus};

    fn secret(byte: u8) -> SecretBytes {
        match SecretBytes::new(vec![byte; SecretBytes::MIN_LEN]) {
            Ok(secret) => secret,
            Err(error) => panic!("{error}"),
        }
    }

    fn key_id(value: &str) -> KeyId {
        match KeyId::new(value) {
            Ok(key_id) => key_id,
            Err(error) => panic!("{error}"),
        }
    }

    fn metadata_key(value: &str, status: KeyStatus, secret_byte: u8) -> KeyMaterial {
        KeyMaterial::new(
            KeyDescriptor {
                id: key_id(value),
                purpose: KeyPurpose::Metadata,
                algorithm: "aes-256-gcm-siv-hmac-sha256-nonce-v1".to_string(),
                status,
                created_at_ms: 0,
                not_before_ms: None,
                not_after_ms: None,
                external_kms_uri: None,
            },
            secret(secret_byte),
        )
    }

    fn namespace_key() -> KeyMaterial {
        KeyMaterial::new(
            KeyDescriptor {
                id: key_id("namespace"),
                purpose: KeyPurpose::Namespace,
                algorithm: "hmac-sha256".to_string(),
                status: KeyStatus::Primary,
                created_at_ms: 0,
                not_before_ms: None,
                not_after_ms: None,
                external_kms_uri: None,
            },
            secret(1),
        )
    }

    fn keyring() -> KeyRing {
        match KeyRing::new(vec![
            namespace_key(),
            metadata_key("metadata", KeyStatus::Primary, 2),
        ]) {
            Ok(keyring) => keyring,
            Err(error) => panic!("{error}"),
        }
    }

    #[test]
    fn sealed_metadata_round_trips() {
        let keyring = keyring();

        let sealed = match keyring.seal_metadata_payload(b"manifest-a", b"client/path") {
            Ok(sealed) => sealed,
            Err(error) => panic!("{error}"),
        };
        let opened = keyring.open_metadata_payload(
            &sealed.key_id,
            b"manifest-a",
            &sealed.nonce,
            &sealed.ciphertext,
            &sealed.tag,
        );

        match opened {
            Ok(opened) => assert_eq!(opened, b"client/path".to_vec()),
            Err(error) => panic!("{error}"),
        }
        assert_ne!(sealed.ciphertext, b"client/path");
    }

    #[test]
    fn sealed_metadata_is_deterministic_for_retry_stability() {
        let keyring = keyring();

        let first = match keyring.seal_metadata_payload(b"manifest-a", b"client/path") {
            Ok(sealed) => sealed,
            Err(error) => panic!("{error}"),
        };
        let second = match keyring.seal_metadata_payload(b"manifest-a", b"client/path") {
            Ok(sealed) => sealed,
            Err(error) => panic!("{error}"),
        };

        assert_eq!(first, second);
        assert_eq!(first.nonce.len(), 12);
        assert_eq!(first.tag.len(), 16);
    }

    #[test]
    fn sealed_metadata_rejects_associated_data_tampering() {
        let keyring = keyring();
        let MetadataSeal {
            key_id,
            nonce,
            ciphertext,
            tag,
        } = match keyring.seal_metadata_payload(b"manifest-a", b"client/path") {
            Ok(sealed) => sealed,
            Err(error) => panic!("{error}"),
        };

        let opened =
            keyring.open_metadata_payload(&key_id, b"manifest-b", &nonce, &ciphertext, &tag);

        assert!(opened.is_err());
    }
}
