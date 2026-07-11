//! Payload encryption helpers.

use crate::CryptoError;
use crate::keyring::KeyRing;
use crate::primitives::derive_hmac;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rs3_types::{KeyId, KeyPurpose};
use sha2::{Digest, Sha256};

const XCHACHA20_NONCE_LEN: usize = 24;
const PAYLOAD_PACK_SEGMENT_NONCE_DOMAIN: &[u8] = b"rs3:payload-pack-segment-nonce:v1";
const SHA256_DIGEST_LEN: usize = 32;

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

/// Encrypted payload-pack segment whose nonce is reproducible from authenticated metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadPackSegmentSeal {
    /// Content key that encrypted the segment.
    pub key_id: KeyId,
    /// Authenticated ciphertext and tag.
    pub ciphertext: Vec<u8>,
}

/// Computes the digest authenticated once by a payload-pack record directory.
pub fn digest_payload_record(plaintext: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
    Sha256::digest(plaintext).into()
}

impl KeyRing {
    /// Encrypts payload bytes with the primary content key.
    pub fn seal_payload(
        &self,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<PayloadSeal, CryptoError> {
        let nonce = random_payload_nonce()?;
        self.seal_payload_with_nonce(associated_data, plaintext, &nonce)
    }

    /// Encrypts payload bytes with the primary content key and a caller-provided nonce.
    ///
    /// The caller must guarantee nonce uniqueness for the active content key.
    pub fn seal_payload_with_nonce(
        &self,
        associated_data: &[u8],
        plaintext: &[u8],
        nonce: &[u8],
    ) -> Result<PayloadSeal, CryptoError> {
        let key = self.primary_key(KeyPurpose::Content)?;
        let ciphertext = encrypt_payload_with_key(&key.secret, associated_data, plaintext, nonce)?;

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
        decrypt_payload_with_key(&key.secret, associated_data, nonce, ciphertext)
    }

    /// Encrypts one payload-pack segment with a deterministic derived nonce.
    ///
    /// `nonce_context` must uniquely identify the pack record and segment for
    /// the active content key. Repeating the same context, associated data,
    /// record digest, and plaintext intentionally produces the same ciphertext
    /// so an interrupted immutable commit assembly can be retried exactly. The
    /// full-record digest must be authenticated by the pack index before it is
    /// used for opening any segment.
    pub fn seal_payload_pack_segment(
        &self,
        associated_data: &[u8],
        nonce_context: &[u8],
        record_digest: &[u8; SHA256_DIGEST_LEN],
        plaintext: &[u8],
    ) -> Result<PayloadPackSegmentSeal, CryptoError> {
        let key = self.primary_key(KeyPurpose::Content)?;
        let nonce = derive_payload_pack_segment_nonce(
            &key.secret,
            associated_data,
            nonce_context,
            record_digest,
        )?;
        let ciphertext = encrypt_payload_with_key(&key.secret, associated_data, plaintext, &nonce)?;

        Ok(PayloadPackSegmentSeal {
            key_id: key.descriptor.id.clone(),
            ciphertext,
        })
    }

    /// Opens one payload-pack segment using its authenticated full-record digest.
    ///
    /// The record digest and `nonce_context` must come from authenticated pack
    /// metadata. AEAD authentication binds each independently readable segment
    /// to those values. After a full-record read, the caller must recompute the
    /// record digest and compare it in constant time.
    pub fn open_payload_pack_segment(
        &self,
        key_id: &KeyId,
        associated_data: &[u8],
        nonce_context: &[u8],
        authenticated_record_digest: &[u8; SHA256_DIGEST_LEN],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let key = self.enabled_key_by_id(key_id, KeyPurpose::Content)?;
        let nonce = derive_payload_pack_segment_nonce(
            &key.secret,
            associated_data,
            nonce_context,
            authenticated_record_digest,
        )?;
        decrypt_payload_with_key(&key.secret, associated_data, &nonce, ciphertext)
    }
}

fn derive_payload_pack_segment_nonce(
    secret: &crate::SecretBytes,
    associated_data: &[u8],
    nonce_context: &[u8],
    record_digest: &[u8; SHA256_DIGEST_LEN],
) -> Result<[u8; XCHACHA20_NONCE_LEN], CryptoError> {
    let associated_data_len =
        u64::try_from(associated_data.len()).map_err(|_| CryptoError::AeadOperationFailed)?;
    let nonce_context_len =
        u64::try_from(nonce_context.len()).map_err(|_| CryptoError::AeadOperationFailed)?;
    let mut material = Vec::with_capacity(
        8_usize
            .saturating_add(associated_data.len())
            .saturating_add(8)
            .saturating_add(nonce_context.len())
            .saturating_add(SHA256_DIGEST_LEN),
    );
    material.extend_from_slice(&associated_data_len.to_be_bytes());
    material.extend_from_slice(associated_data);
    material.extend_from_slice(&nonce_context_len.to_be_bytes());
    material.extend_from_slice(nonce_context);
    material.extend_from_slice(record_digest);
    let derived = derive_hmac(secret, PAYLOAD_PACK_SEGMENT_NONCE_DOMAIN, &material)?;
    derived
        .get(..XCHACHA20_NONCE_LEN)
        .ok_or(CryptoError::AeadOperationFailed)?
        .try_into()
        .map_err(|_| CryptoError::AeadOperationFailed)
}

fn encrypt_payload_with_key(
    secret: &crate::SecretBytes,
    associated_data: &[u8],
    plaintext: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = payload_cipher(secret)?;
    if nonce.len() != XCHACHA20_NONCE_LEN {
        return Err(CryptoError::AeadOperationFailed);
    }
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::AeadOperationFailed)
}

fn decrypt_payload_with_key(
    secret: &crate::SecretBytes,
    associated_data: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = payload_cipher(secret)?;
    if nonce.len() != XCHACHA20_NONCE_LEN {
        return Err(CryptoError::AeadOperationFailed);
    }
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::AeadOperationFailed)
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
                public_key: None,
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
                public_key: None,
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

    #[test]
    fn payload_pack_segment_is_deterministic_and_round_trips() {
        let keyring = keyring(2);
        let record_digest = super::digest_payload_record(b"complete payload pack record");
        let first = match keyring.seal_payload_pack_segment(
            b"commit-and-record-aad",
            b"pack-7/record-3/segment-1",
            &record_digest,
            b"payload pack segment",
        ) {
            Ok(sealed) => sealed,
            Err(error) => panic!("{error}"),
        };
        let second = match keyring.seal_payload_pack_segment(
            b"commit-and-record-aad",
            b"pack-7/record-3/segment-1",
            &record_digest,
            b"payload pack segment",
        ) {
            Ok(sealed) => sealed,
            Err(error) => panic!("{error}"),
        };

        assert_eq!(first, second);
        assert_ne!(first.ciphertext, b"payload pack segment");
        let opened = keyring.open_payload_pack_segment(
            &first.key_id,
            b"commit-and-record-aad",
            b"pack-7/record-3/segment-1",
            &record_digest,
            &first.ciphertext,
        );
        assert_eq!(opened.ok(), Some(b"payload pack segment".to_vec()));
    }

    #[test]
    fn payload_pack_segment_nonce_is_domain_separated_by_context_and_aad() {
        let keyring = keyring(2);
        let record_digest = super::digest_payload_record(b"complete payload pack record");
        let first = match keyring.seal_payload_pack_segment(
            b"record-aad-a",
            b"pack-7/record-3/segment-1",
            &record_digest,
            b"same plaintext",
        ) {
            Ok(sealed) => sealed,
            Err(error) => panic!("{error}"),
        };
        let other_context = match keyring.seal_payload_pack_segment(
            b"record-aad-a",
            b"pack-7/record-3/segment-2",
            &record_digest,
            b"same plaintext",
        ) {
            Ok(sealed) => sealed,
            Err(error) => panic!("{error}"),
        };
        let other_aad = match keyring.seal_payload_pack_segment(
            b"record-aad-b",
            b"pack-7/record-3/segment-1",
            &record_digest,
            b"same plaintext",
        ) {
            Ok(sealed) => sealed,
            Err(error) => panic!("{error}"),
        };

        assert_ne!(first.ciphertext, other_context.ciphertext);
        assert_ne!(first.ciphertext, other_aad.ciphertext);
    }

    #[test]
    fn payload_pack_segment_rejects_authenticated_metadata_changes() {
        let keyring = keyring(2);
        let record_digest = super::digest_payload_record(b"complete payload pack record");
        let sealed = match keyring.seal_payload_pack_segment(
            b"commit-and-record-aad",
            b"pack-7/record-3/segment-1",
            &record_digest,
            b"payload pack segment",
        ) {
            Ok(sealed) => sealed,
            Err(error) => panic!("{error}"),
        };
        let mut wrong_digest = record_digest;
        wrong_digest[0] ^= 0x80;

        assert!(
            keyring
                .open_payload_pack_segment(
                    &sealed.key_id,
                    b"commit-and-record-aad",
                    b"pack-7/record-3/segment-2",
                    &record_digest,
                    &sealed.ciphertext,
                )
                .is_err()
        );
        assert!(
            keyring
                .open_payload_pack_segment(
                    &sealed.key_id,
                    b"different-aad",
                    b"pack-7/record-3/segment-1",
                    &record_digest,
                    &sealed.ciphertext,
                )
                .is_err()
        );
        assert!(
            keyring
                .open_payload_pack_segment(
                    &sealed.key_id,
                    b"commit-and-record-aad",
                    b"pack-7/record-3/segment-1",
                    &wrong_digest,
                    &sealed.ciphertext,
                )
                .is_err()
        );
    }

    #[test]
    fn payload_pack_segment_rejects_ciphertext_tampering() {
        let keyring = keyring(2);
        let record_digest = super::digest_payload_record(b"complete payload pack record");
        let sealed = match keyring.seal_payload_pack_segment(
            b"commit-and-record-aad",
            b"pack-7/record-3/segment-1",
            &record_digest,
            b"payload pack segment",
        ) {
            Ok(sealed) => sealed,
            Err(error) => panic!("{error}"),
        };
        let mut ciphertext = sealed.ciphertext.clone();
        if let Some(first) = ciphertext.first_mut() {
            *first ^= 0x80;
        } else {
            panic!("authenticated ciphertext must contain a tag");
        }

        assert!(
            keyring
                .open_payload_pack_segment(
                    &sealed.key_id,
                    b"commit-and-record-aad",
                    b"pack-7/record-3/segment-1",
                    &record_digest,
                    &ciphertext,
                )
                .is_err()
        );
    }

    #[test]
    fn payload_record_digest_covers_the_complete_record() {
        let first = super::digest_payload_record(b"segment-a|segment-b");
        let same = super::digest_payload_record(b"segment-a|segment-b");
        let changed = super::digest_payload_record(b"segment-a|segment-c");

        assert_eq!(first, same);
        assert_ne!(first, changed);
    }
}
