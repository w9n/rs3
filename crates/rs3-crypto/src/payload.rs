//! Payload encryption helpers.

use crate::CryptoError;
use crate::keyring::KeyRing;
use crate::primitives::derive_hmac;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rs3_types::{KeyId, KeyPurpose};

const XCHACHA20_NONCE_LEN: usize = 24;

/// Encrypted payload bytes and the key that produced them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadSeal {
    /// Content key ID.
    pub key_id: KeyId,
    /// Random AEAD nonce.
    pub nonce: Vec<u8>,
    /// Authenticated ciphertext and tag.
    pub ciphertext: Vec<u8>,
}

impl KeyRing {
    /// Encrypts payload bytes with the primary content key.
    pub fn seal_payload(
        &self,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<PayloadSeal, CryptoError> {
        let key = self.primary_key(KeyPurpose::Content)?;
        let cipher = payload_cipher(&key.secret)?;
        let nonce = random_payload_nonce()?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoError::AeadOperationFailed)?;

        Ok(PayloadSeal {
            key_id: key.descriptor.id.clone(),
            nonce: nonce.to_vec(),
            ciphertext,
        })
    }

    /// Decrypts payload bytes with an enabled content key.
    pub fn open_payload(
        &self,
        key_id: &KeyId,
        associated_data: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let key = self.enabled_key_by_id(key_id, KeyPurpose::Content)?;
        let cipher = payload_cipher(&key.secret)?;
        if nonce.len() != XCHACHA20_NONCE_LEN {
            return Err(CryptoError::AeadOperationFailed);
        }
        let nonce = XNonce::from_slice(nonce);
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoError::AeadOperationFailed)
    }
}

fn random_payload_nonce() -> Result<[u8; XCHACHA20_NONCE_LEN], CryptoError> {
    let mut nonce = [0_u8; XCHACHA20_NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| CryptoError::RandomnessUnavailable)?;
    Ok(nonce)
}

fn payload_cipher(secret: &crate::SecretBytes) -> Result<XChaCha20Poly1305, CryptoError> {
    let key = derive_hmac(secret, b"rs3:payload-aead-key:v1", b"xchacha20poly1305")?;
    XChaCha20Poly1305::new_from_slice(&key).map_err(|_| CryptoError::AeadOperationFailed)
}

#[cfg(test)]
mod tests {
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

    fn content_key(value: &str, status: KeyStatus, secret_byte: u8) -> KeyMaterial {
        KeyMaterial::new(
            KeyDescriptor {
                id: key_id(value),
                purpose: KeyPurpose::Content,
                algorithm: "xchacha20poly1305".to_string(),
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

    fn keyring(content_secret: u8) -> KeyRing {
        match KeyRing::new(vec![
            namespace_key(),
            content_key("content", KeyStatus::Primary, content_secret),
        ]) {
            Ok(keyring) => keyring,
            Err(error) => panic!("{error}"),
        }
    }

    #[test]
    fn payload_seal_round_trips() {
        let keyring = keyring(2);
        let sealed = match keyring.seal_payload(b"object-a", b"payload bytes") {
            Ok(sealed) => sealed,
            Err(error) => panic!("{error}"),
        };
        let opened = keyring.open_payload(
            &sealed.key_id,
            b"object-a",
            &sealed.nonce,
            &sealed.ciphertext,
        );

        assert_eq!(opened.ok(), Some(b"payload bytes".to_vec()));
        assert_ne!(sealed.ciphertext, b"payload bytes");
    }

    #[test]
    fn payload_seal_rejects_associated_data_tampering() {
        let keyring = keyring(2);
        let sealed = match keyring.seal_payload(b"object-a", b"payload bytes") {
            Ok(sealed) => sealed,
            Err(error) => panic!("{error}"),
        };

        let opened = keyring.open_payload(
            &sealed.key_id,
            b"object-b",
            &sealed.nonce,
            &sealed.ciphertext,
        );

        assert!(opened.is_err());
    }

    #[test]
    fn payload_seal_rejects_wrong_key_material() {
        let writer = keyring(2);
        let reader = keyring(3);
        let sealed = match writer.seal_payload(b"object-a", b"payload bytes") {
            Ok(sealed) => sealed,
            Err(error) => panic!("{error}"),
        };

        let opened = reader.open_payload(
            &sealed.key_id,
            b"object-a",
            &sealed.nonce,
            &sealed.ciphertext,
        );

        assert!(opened.is_err());
    }
}
