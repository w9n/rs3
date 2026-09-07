//! Payload encryption helpers.

use crate::CryptoError;
use crate::keyring::KeyRing;
use crate::primitives::derive_hmac;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rs3_types::{KeyId, KeyPurpose};

use rs3_types::PAYLOAD_NONCE_LEN as XCHACHA20_NONCE_LEN;

const PAYLOAD_SEGMENT_NONCE_DOMAIN: &[u8] = b"rs3:payload-segment-nonce:v3";
const PAYLOAD_SEGMENT_AAD_DOMAIN: &[u8] = b"rs3:payload-segment-aad:v3";

/// Authenticated identity of one independently readable payload segment.
///
/// The caller must generate a fresh attempt before sealing changed plaintext.
/// On reads these facts must come from authenticated repository metadata.
#[derive(Clone, Copy)]
pub struct PayloadSegmentContext<'a> {
    /// Canonical repository and historical keyring-envelope identity.
    pub repository_context: &'a [u8],
    /// Exact backend object containing the ciphertext.
    pub containing_object: &'a rs3_types::BackendObjectId,
    /// Embedded pack section, or none for a detached object.
    pub section_ordinal: Option<u32>,
    /// Random immutable pack or detached object identity.
    pub carrier_id: &'a [u8; 32],
    /// Fresh identity for this sealing attempt, including replacement parts.
    pub attempt_id: rs3_types::PayloadAttemptId,
    /// Pack record ordinal or detached client part number.
    pub part_ordinal: u32,
    /// Segment ordinal within this record or part.
    pub segment_ordinal: u64,
    /// Exact plaintext bytes covered by this segment's tag.
    pub plaintext_len: u64,
    /// Whether this is the final segment of its record or part.
    pub is_final: bool,
    /// Canonical carrier-specific layout facts, such as segment size and offsets.
    pub layout_context: &'a [u8],
}

impl PayloadSegmentContext<'_> {
    fn associated_data(&self, key_id: &KeyId) -> Result<Vec<u8>, CryptoError> {
        if self.repository_context.is_empty()
            || self.repository_context.len() > 4096
            || self.containing_object.as_str().len() > 1024
            || self.layout_context.len() > 1024
            || key_id.as_str().len() > 255
            || self.plaintext_len == 0
            || self.plaintext_len > 64 * 1024 * 1024
        {
            return Err(CryptoError::AeadOperationFailed);
        }
        let mut aad = PAYLOAD_SEGMENT_AAD_DOMAIN.to_vec();
        for field in [
            self.repository_context,
            self.containing_object.as_str().as_bytes(),
            key_id.as_str().as_bytes(),
        ] {
            aad.extend_from_slice(&(field.len() as u64).to_be_bytes());
            aad.extend_from_slice(field);
        }
        match self.section_ordinal {
            None => aad.push(0),
            Some(ordinal) => {
                aad.push(1);
                aad.extend_from_slice(&ordinal.to_be_bytes());
            }
        }
        aad.extend_from_slice(&self.nonce_context());
        aad.extend_from_slice(&self.plaintext_len.to_be_bytes());
        aad.push(u8::from(self.is_final));
        aad.extend_from_slice(&(self.layout_context.len() as u64).to_be_bytes());
        aad.extend_from_slice(self.layout_context);
        Ok(aad)
    }

    fn nonce_context(&self) -> [u8; 76] {
        let mut context = [0; 76];
        context[..32].copy_from_slice(self.carrier_id);
        context[32..64].copy_from_slice(self.attempt_id.as_bytes());
        context[64..68].copy_from_slice(&self.part_ordinal.to_be_bytes());
        context[68..].copy_from_slice(&self.segment_ordinal.to_be_bytes());
        context
    }
}

/// Encrypted payload segment whose nonce is reproducible from authenticated metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadSegmentSeal {
    /// Content key that encrypted the segment.
    pub key_id: KeyId,
    /// Authenticated ciphertext and tag.
    pub ciphertext: Vec<u8>,
}

impl KeyRing {
    /// Seals a segment using the shared attempt-bound payload nonce scheme.
    pub fn seal_payload_segment(
        &self,
        context: PayloadSegmentContext<'_>,
        plaintext: &[u8],
    ) -> Result<PayloadSegmentSeal, CryptoError> {
        if plaintext.len() as u64 != context.plaintext_len {
            return Err(CryptoError::AeadOperationFailed);
        }
        let key = self.primary_key(KeyPurpose::Content)?;
        let aad = context.associated_data(&key.descriptor.id)?;
        let nonce = derive_segment_nonce(
            &key.secret,
            &aad,
            &context.nonce_context(),
            PAYLOAD_SEGMENT_NONCE_DOMAIN,
        )?;
        let ciphertext = encrypt_payload_with_key(&key.secret, &aad, plaintext, &nonce)?;
        Ok(PayloadSegmentSeal {
            key_id: key.descriptor.id.clone(),
            ciphertext,
        })
    }

    /// Opens a segment using its authenticated carrier, attempt and layout facts.
    pub fn open_payload_segment(
        &self,
        key_id: &KeyId,
        context: PayloadSegmentContext<'_>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() as u64 != context.plaintext_len.saturating_add(16) {
            return Err(CryptoError::AeadOperationFailed);
        }
        let key = self.enabled_key_by_id(key_id, KeyPurpose::Content)?;
        let aad = context.associated_data(key_id)?;
        let nonce = derive_segment_nonce(
            &key.secret,
            &aad,
            &context.nonce_context(),
            PAYLOAD_SEGMENT_NONCE_DOMAIN,
        )?;
        decrypt_payload_with_key(&key.secret, &aad, &nonce, ciphertext)
    }
}

fn derive_segment_nonce(
    secret: &crate::SecretBytes,
    associated_data: &[u8],
    nonce_context: &[u8],
    domain: &[u8],
) -> Result<[u8; XCHACHA20_NONCE_LEN], CryptoError> {
    let associated_data_len =
        u64::try_from(associated_data.len()).map_err(|_| CryptoError::AeadOperationFailed)?;
    let nonce_context_len =
        u64::try_from(nonce_context.len()).map_err(|_| CryptoError::AeadOperationFailed)?;
    let mut material = Vec::with_capacity(
        8_usize
            .saturating_add(associated_data.len())
            .saturating_add(8)
            .saturating_add(nonce_context.len()),
    );
    material.extend_from_slice(&associated_data_len.to_be_bytes());
    material.extend_from_slice(associated_data);
    material.extend_from_slice(&nonce_context_len.to_be_bytes());
    material.extend_from_slice(nonce_context);
    let derived = derive_hmac(secret, domain, &material)?;
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

fn payload_cipher(secret: &crate::SecretBytes) -> Result<XChaCha20Poly1305, CryptoError> {
    let key = derive_hmac(secret, b"rs3:payload-aead-key:v1", b"xchacha20poly1305")?;
    XChaCha20Poly1305::new_from_slice(&key).map_err(|_| CryptoError::AeadOperationFailed)
}

#[cfg(test)]
mod tests {
    fn segment_context(object: &rs3_types::BackendObjectId) -> super::PayloadSegmentContext<'_> {
        super::PayloadSegmentContext {
            repository_context: b"repository/keyring",
            containing_object: object,
            section_ordinal: Some(0),
            carrier_id: &[7; 32],
            attempt_id: rs3_types::PayloadAttemptId::from_bytes([8; 32]),
            part_ordinal: 1,
            segment_ordinal: 0,
            plaintext_len: 5,
            is_final: true,
            layout_context: b"segment-size-and-record-offset",
        }
    }

    #[test]
    fn shared_segment_nonce_matches_independent_hmac_vector() {
        let object = rs3_types::BackendObjectId::new("opaque-a").expect("object");
        let context = segment_context(&object);
        let aad = context.associated_data(&key_id("content")).expect("aad");
        // Independently encoded with Python struct and hmac.sha256. This pins
        // byte order, field lengths, section option and HMAC domain separator.
        assert_eq!(
            hex::encode(&aad),
            "7273333a7061796c6f61642d7365676d656e742d6161643a763300000000000000127265706f7369746f72792f6b657972696e6700000000000000086f70617175652d610000000000000007636f6e74656e74010000000007070707070707070707070707070707070707070707070707070707070707070808080808080808080808080808080808080808080808080808080808080808000000010000000000000000000000000000000501000000000000001e7365676d656e742d73697a652d616e642d7265636f72642d6f6666736574"
        );
        let nonce = super::derive_segment_nonce(
            &secret(2),
            &aad,
            &context.nonce_context(),
            super::PAYLOAD_SEGMENT_NONCE_DOMAIN,
        )
        .expect("nonce");
        assert_eq!(
            hex::encode(nonce),
            "aebd036b40d9ac8a2b3efa949ce2baf5eeae9ee7c1be1860"
        );
    }

    #[test]
    fn shared_segment_authenticates_every_identity_and_layout_field() {
        let keyring = keyring(2);
        let object = rs3_types::BackendObjectId::new("opaque-a").expect("object");
        let other = rs3_types::BackendObjectId::new("opaque-b").expect("object");
        let context = segment_context(&object);
        let sealed = keyring
            .seal_payload_segment(context, b"hello")
            .expect("seal");
        assert_eq!(
            keyring
                .open_payload_segment(&sealed.key_id, context, &sealed.ciphertext)
                .expect("open"),
            b"hello"
        );
        for changed in [
            super::PayloadSegmentContext {
                repository_context: b"different-repository/keyring",
                ..context
            },
            super::PayloadSegmentContext {
                containing_object: &other,
                ..context
            },
            super::PayloadSegmentContext {
                section_ordinal: None,
                ..context
            },
            super::PayloadSegmentContext {
                section_ordinal: Some(1),
                ..context
            },
            super::PayloadSegmentContext {
                carrier_id: &[9; 32],
                ..context
            },
            super::PayloadSegmentContext {
                attempt_id: rs3_types::PayloadAttemptId::from_bytes([9; 32]),
                ..context
            },
            super::PayloadSegmentContext {
                part_ordinal: 2,
                ..context
            },
            super::PayloadSegmentContext {
                segment_ordinal: 1,
                ..context
            },
            super::PayloadSegmentContext {
                plaintext_len: 4,
                ..context
            },
            super::PayloadSegmentContext {
                is_final: false,
                ..context
            },
            super::PayloadSegmentContext {
                layout_context: b"changed-layout",
                ..context
            },
        ] {
            assert!(
                keyring
                    .open_payload_segment(&sealed.key_id, changed, &sealed.ciphertext)
                    .is_err()
            );
        }
    }

    #[test]
    fn replacement_and_concurrent_segment_attempts_use_distinct_nonces() {
        let keyring = keyring(2);
        let object = rs3_types::BackendObjectId::new("opaque-a").expect("object");
        let context = segment_context(&object);
        let first = keyring
            .seal_payload_segment(context, b"hello")
            .expect("seal");
        assert_eq!(
            first,
            keyring
                .seal_payload_segment(context, b"hello")
                .expect("exact retry")
        );
        let mut ciphertexts = std::collections::BTreeSet::new();
        for _ in 0..32 {
            let fresh = super::PayloadSegmentContext {
                attempt_id: crate::random_payload_attempt_id().expect("random attempt"),
                ..context
            };
            let sealed = keyring
                .seal_payload_segment(fresh, b"hello")
                .expect("fresh seal");
            assert_ne!(sealed.ciphertext, first.ciphertext);
            assert!(ciphertexts.insert(sealed.ciphertext.clone()));
            assert!(
                keyring
                    .open_payload_segment(&sealed.key_id, context, &sealed.ciphertext)
                    .is_err()
            );
        }
        assert!(
            keyring
                .seal_payload_segment(context, b"different length")
                .is_err()
        );
    }

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
                status,
                created_at_ms: 0,
                public_key: None,
            },
            secret(secret_byte),
        )
    }

    fn namespace_key() -> KeyMaterial {
        KeyMaterial::new(
            KeyDescriptor {
                id: key_id("namespace"),
                purpose: KeyPurpose::Namespace,
                status: KeyStatus::Primary,
                created_at_ms: 0,
                public_key: None,
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
    fn shared_segment_rejects_wrong_keys_and_ciphertext_tampering() {
        let writer = keyring(2);
        let object = rs3_types::BackendObjectId::new("opaque-a").expect("object");
        let context = segment_context(&object);
        let sealed = writer
            .seal_payload_segment(context, b"hello")
            .expect("seal");
        assert!(
            keyring(3)
                .open_payload_segment(&sealed.key_id, context, &sealed.ciphertext)
                .is_err()
        );
        for index in 0..sealed.ciphertext.len() {
            let mut changed = sealed.ciphertext.clone();
            changed[index] ^= 0x80;
            assert!(
                writer
                    .open_payload_segment(&sealed.key_id, context, &changed)
                    .is_err()
            );
        }
        for len in [0, 4, 20, 22] {
            assert!(
                writer
                    .open_payload_segment(&sealed.key_id, context, &vec![0; len])
                    .is_err()
            );
        }
    }
}
