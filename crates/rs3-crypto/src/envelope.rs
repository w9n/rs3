//! Purpose-bound canonical CBOR envelopes for repository metadata and keys.

use crate::keyring::{KeyMaterial, KeyRing, RepositoryKeyContext};
use crate::primitives::derive_hmac;
use crate::{CryptoError, SecretBytes, Sha256Hasher};
use aes_gcm_siv::aead::{AeadInPlace, KeyInit};
use aes_gcm_siv::{Aes256GcmSiv, Nonce, Tag};
use rs3_types::cbor::{self, Reader};
use rs3_types::{KeyDescriptor, KeyId, KeyPurpose, KeyStatus, RepositoryId};
use zeroize::Zeroizing;

/// Current canonical envelope and keyring plaintext version.
pub const REPOSITORY_ENVELOPE_VERSION: u16 = 3;
/// Maximum complete encrypted keyring envelope bytes.
pub const MAX_KEYRING_ENVELOPE_OBJECT_BYTES: u64 = 16 * 1024 * 1024;
/// Maximum complete encrypted format envelope bytes.
pub const MAX_FORMAT_ENVELOPE_OBJECT_BYTES: u64 = 1024 * 1024;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MAX_PUBLIC_TEXT: usize = 1024;
const MAX_SALT: usize = 4096;
const MAX_KEYS: usize = 4096;
const MAX_SECRET: usize = 4096;

/// Authenticated purpose, selecting an independent AEAD key and object limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopePurpose {
    /// Encrypted repository key material.
    Keyring,
    /// Encrypted repository format root.
    Format,
}

impl EnvelopePurpose {
    const fn tag(self) -> u64 {
        match self {
            Self::Keyring => 0,
            Self::Format => 1,
        }
    }
    const fn maximum(self) -> u64 {
        match self {
            Self::Keyring => MAX_KEYRING_ENVELOPE_OBJECT_BYTES,
            Self::Format => MAX_FORMAT_ENVELOPE_OBJECT_BYTES,
        }
    }
    const fn key_domain(self) -> &'static [u8] {
        match self {
            Self::Keyring => b"rs3:keyring-envelope-aead-key:v1",
            Self::Format => b"rs3:format-envelope-aead-key:v1",
        }
    }
}

/// One purpose-bound encrypted envelope, encoded as a fixed canonical CBOR map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryEnvelope {
    /// Wire version, checked before cryptographic use.
    pub version: u16,
    /// Authenticated envelope purpose.
    pub purpose: EnvelopePurpose,
    /// Monotonic generation assigned by the operator workflow.
    pub generation: u64,
    /// Bound public repository identity.
    pub repository_id: RepositoryId,
    /// Bound public repository salt.
    pub repository_salt: Vec<u8>,
    /// Operator-visible wrapping key identifier.
    pub wrapping_key_id: String,
    /// Random 12-byte AES-GCM-SIV nonce.
    pub nonce: Vec<u8>,
    /// Encrypted plaintext bytes.
    pub ciphertext: Vec<u8>,
    /// Detached 16-byte authentication tag.
    pub tag: Vec<u8>,
}

impl KeyRing {
    /// Encrypts purpose-sorted key material without exposing plaintext serialization.
    pub fn seal_keyring_envelope(
        &self,
        context: &RepositoryKeyContext,
        wrapping_key_id: &str,
        wrapping_key: &SecretBytes,
        generation: u64,
    ) -> Result<RepositoryEnvelope, CryptoError> {
        let plaintext = keyring_plaintext_bytes(self)?;
        RepositoryEnvelope::seal(
            EnvelopePurpose::Keyring,
            context,
            wrapping_key_id,
            wrapping_key,
            generation,
            &plaintext,
        )
    }
}

impl RepositoryEnvelope {
    /// Seals a format root with a fresh nonce and format-specific key.
    pub fn seal_format(
        context: &RepositoryKeyContext,
        wrapping_key_id: &str,
        wrapping_key: &SecretBytes,
        generation: u64,
        plaintext: &[u8],
    ) -> Result<Self, CryptoError> {
        Self::seal(
            EnvelopePurpose::Format,
            context,
            wrapping_key_id,
            wrapping_key,
            generation,
            plaintext,
        )
    }

    fn seal(
        purpose: EnvelopePurpose,
        context: &RepositoryKeyContext,
        wrapping_key_id: &str,
        wrapping_key: &SecretBytes,
        generation: u64,
        plaintext: &[u8],
    ) -> Result<Self, CryptoError> {
        if plaintext.len() as u64 > purpose.maximum()
            || context.repository_id().as_str().len() > MAX_PUBLIC_TEXT
            || context.salt().len() > MAX_SALT
            || wrapping_key_id.len() > MAX_PUBLIC_TEXT
        {
            return Err(invalid("maximum encoded size exceeded"));
        }
        let mut nonce = vec![0; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| CryptoError::RandomnessUnavailable)?;
        let mut envelope = Self {
            version: REPOSITORY_ENVELOPE_VERSION,
            purpose,
            generation,
            repository_id: context.repository_id().clone(),
            repository_salt: context.salt().to_vec(),
            wrapping_key_id: wrapping_key_id.to_owned(),
            nonce,
            ciphertext: Vec::new(),
            tag: vec![0; TAG_LEN],
        };
        envelope.validate_shape()?;
        let aad = envelope.associated_data();
        // Check the complete encoded size before allocating the plaintext copy.
        let overhead = envelope.to_object_bytes()?.len() as u64 + 8;
        if (plaintext.len() as u64)
            .checked_add(overhead)
            .is_none_or(|len| len > purpose.maximum())
        {
            return Err(invalid("maximum encoded size exceeded"));
        }
        let mut ciphertext = Zeroizing::new(plaintext.to_vec());
        let tag = envelope_cipher(wrapping_key, purpose)?
            .encrypt_in_place_detached(Nonce::from_slice(&envelope.nonce), &aad, &mut ciphertext)
            .map_err(|_| CryptoError::AeadOperationFailed)?;
        envelope.ciphertext = std::mem::take(&mut *ciphertext);
        envelope.tag = tag.to_vec();
        Ok(envelope)
    }

    /// Opens a format envelope into plaintext that zeroizes on drop.
    pub fn open_format(
        &self,
        context: &RepositoryKeyContext,
        wrapping_key_id: &str,
        wrapping_key: &SecretBytes,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.open(
            EnvelopePurpose::Format,
            context,
            wrapping_key_id,
            wrapping_key,
        )
    }

    /// Opens a keyring envelope and validates its bounded canonical key material.
    pub fn open_keyring(
        &self,
        context: &RepositoryKeyContext,
        wrapping_key_id: &str,
        wrapping_key: &SecretBytes,
    ) -> Result<KeyRing, CryptoError> {
        let plaintext = self.open(
            EnvelopePurpose::Keyring,
            context,
            wrapping_key_id,
            wrapping_key,
        )?;
        decode_keyring_plaintext(&plaintext)
    }

    fn open(
        &self,
        purpose: EnvelopePurpose,
        context: &RepositoryKeyContext,
        wrapping_key_id: &str,
        wrapping_key: &SecretBytes,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.validate_shape()?;
        if self.purpose != purpose
            || self.repository_id != *context.repository_id()
            || self.repository_salt != context.salt()
            || self.wrapping_key_id != wrapping_key_id
        {
            return Err(invalid("envelope purpose or public context mismatch"));
        }
        let mut plaintext = Zeroizing::new(self.ciphertext.clone());
        envelope_cipher(wrapping_key, purpose)?
            .decrypt_in_place_detached(
                Nonce::from_slice(&self.nonce),
                &self.associated_data(),
                &mut plaintext,
                Tag::from_slice(&self.tag),
            )
            .map_err(|_| CryptoError::AeadOperationFailed)?;
        Ok(plaintext)
    }

    /// Rewraps a keyring while preserving all repository data keys.
    pub fn rewrap(
        &self,
        context: &RepositoryKeyContext,
        old_wrapping_key_id: &str,
        old_wrapping_key: &SecretBytes,
        new_wrapping_key_id: &str,
        new_wrapping_key: &SecretBytes,
        new_generation: u64,
    ) -> Result<Self, CryptoError> {
        self.open_keyring(context, old_wrapping_key_id, old_wrapping_key)?
            .seal_keyring_envelope(
                context,
                new_wrapping_key_id,
                new_wrapping_key,
                new_generation,
            )
    }

    /// SHA-256 of the exact canonical envelope bytes used for anchor binding.
    pub fn digest(&self) -> Result<String, CryptoError> {
        Ok(hex::encode(Sha256Hasher::digest(&self.to_object_bytes()?)))
    }

    /// Encodes the complete canonical envelope with no JSON or textual prefix.
    pub fn to_object_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        self.validate_shape()?;
        let mut bytes = Vec::new();
        cbor::write_map_len(&mut bytes, 9);
        self.write_public_fields(&mut bytes);
        cbor::write_u64(&mut bytes, 7);
        let mut length_header = Vec::new();
        cbor::write_u64(&mut length_header, self.ciphertext.len() as u64);
        // Byte strings and unsigned integers use the same canonical length width.
        // Include the tag key, its one-byte string header and its fixed body.
        if bytes.len() as u64
            + length_header.len() as u64
            + self.ciphertext.len() as u64
            + 2
            + TAG_LEN as u64
            > self.purpose.maximum()
        {
            return Err(invalid("maximum encoded size exceeded"));
        }
        cbor::write_bytes(&mut bytes, &self.ciphertext);
        cbor::write_u64(&mut bytes, 8);
        cbor::write_bytes(&mut bytes, &self.tag);
        Ok(bytes)
    }

    /// Decodes the requested purpose, bounding fields before allocation and requiring exact EOF.
    pub fn from_object_bytes(bytes: &[u8], purpose: EnvelopePurpose) -> Result<Self, CryptoError> {
        if bytes.len() as u64 > purpose.maximum() {
            return Err(invalid("maximum encoded size exceeded"));
        }
        let mut reader = Reader::new(bytes);
        let decoded = (|| -> Result<Self, rs3_types::cbor::CborError> {
            require(reader.read_map_len()? == 9)?;
            field(&mut reader, 0)?;
            let version = reader.read_u64()?;
            require(version == u64::from(REPOSITORY_ENVELOPE_VERSION))?;
            field(&mut reader, 1)?;
            require(reader.read_u64()? == purpose.tag())?;
            field(&mut reader, 2)?;
            let generation = reader.read_u64()?;
            field(&mut reader, 3)?;
            let repository_id = RepositoryId::new(reader.read_text_bounded(MAX_PUBLIC_TEXT)?)
                .map_err(|_| rs3_types::cbor::CborError::Invalid)?;
            field(&mut reader, 4)?;
            let repository_salt = reader.read_bytes_bounded(MAX_SALT)?;
            field(&mut reader, 5)?;
            let wrapping_key_id = reader.read_text_bounded(MAX_PUBLIC_TEXT)?;
            field(&mut reader, 6)?;
            let nonce = reader.read_bytes_bounded(NONCE_LEN)?;
            field(&mut reader, 7)?;
            let ciphertext = reader.read_bytes_bounded(purpose.maximum() as usize)?;
            field(&mut reader, 8)?;
            let tag = reader.read_bytes_bounded(TAG_LEN)?;
            require(reader.is_finished())?;
            Ok(Self {
                version: REPOSITORY_ENVELOPE_VERSION,
                purpose,
                generation,
                repository_id,
                repository_salt,
                wrapping_key_id,
                nonce,
                ciphertext,
                tag,
            })
        })()
        .map_err(|_| invalid("invalid canonical CBOR envelope"))?;
        decoded.validate_shape()?;
        Ok(decoded)
    }

    fn validate_shape(&self) -> Result<(), CryptoError> {
        if self.version != REPOSITORY_ENVELOPE_VERSION
            || self.repository_id.as_str().len() > MAX_PUBLIC_TEXT
            || self.repository_salt.len() < crate::MIN_REPOSITORY_SALT_LEN
            || self.repository_salt.len() > MAX_SALT
            || self.wrapping_key_id.trim().is_empty()
            || self.wrapping_key_id.len() > MAX_PUBLIC_TEXT
            || self.nonce.len() != NONCE_LEN
            || self.tag.len() != TAG_LEN
            || self.ciphertext.len() as u64 > self.purpose.maximum()
        {
            return Err(invalid("invalid envelope field or bound"));
        }
        Ok(())
    }

    fn associated_data(&self) -> Vec<u8> {
        let mut aad = Vec::new();
        cbor::write_map_len(&mut aad, 7);
        self.write_public_fields(&mut aad);
        aad
    }

    fn write_public_fields(&self, out: &mut Vec<u8>) {
        cbor::write_u64(out, 0);
        cbor::write_u64(out, u64::from(self.version));
        cbor::write_u64(out, 1);
        cbor::write_u64(out, self.purpose.tag());
        cbor::write_u64(out, 2);
        cbor::write_u64(out, self.generation);
        cbor::write_u64(out, 3);
        cbor::write_text(out, self.repository_id.as_str());
        cbor::write_u64(out, 4);
        cbor::write_bytes(out, &self.repository_salt);
        cbor::write_u64(out, 5);
        cbor::write_text(out, &self.wrapping_key_id);
        cbor::write_u64(out, 6);
        cbor::write_bytes(out, &self.nonce);
    }
}

fn keyring_plaintext_bytes(keyring: &KeyRing) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let materials = keyring.key_materials();
    if materials.len() > MAX_KEYS {
        return Err(invalid("key count exceeds bound"));
    }
    let mut keys = materials.iter().collect::<Vec<_>>();
    keys.sort_by_key(|key| (key.descriptor().purpose, &key.descriptor().id));
    // Reserve an upper bound before writing secrets so growth never leaves
    // secret plaintext in an abandoned allocation. Counts and field sizes are
    // bounded before computing this capacity.
    let mut capacity = 16;
    for key in &keys {
        let id_len = key.descriptor().id.as_str().len();
        let secret_len = key.secret.expose().len();
        if id_len > 255 || secret_len > MAX_SECRET {
            return Err(invalid("key material exceeds bound"));
        }
        capacity += 64 + id_len + secret_len;
    }
    if capacity as u64 > MAX_KEYRING_ENVELOPE_OBJECT_BYTES {
        return Err(invalid("key material exceeds bound"));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(capacity));
    cbor::write_array_len(&mut out, 2);
    cbor::write_u64(&mut out, u64::from(REPOSITORY_ENVELOPE_VERSION));
    cbor::write_array_len(&mut out, keys.len());
    for key in keys {
        let descriptor = key.descriptor();
        cbor::write_array_len(&mut out, 6);
        cbor::write_text(&mut out, descriptor.id.as_str());
        cbor::write_u64(&mut out, purpose_tag(descriptor.purpose));
        cbor::write_u64(
            &mut out,
            match descriptor.status {
                KeyStatus::Primary => 0,
                KeyStatus::Enabled => 1,
                KeyStatus::Disabled => 2,
                KeyStatus::Retired => 3,
            },
        );
        cbor::write_i64(&mut out, descriptor.created_at_ms);
        match &descriptor.public_key {
            None => cbor::write_null(&mut out),
            Some(value) => {
                if descriptor.purpose != KeyPurpose::CheckpointSigning {
                    return Err(invalid("public verification key has wrong purpose"));
                }
                let bytes = crate::checkpoint::prefixed_ed25519_public_key_bytes(value)
                    .map_err(|_| invalid("invalid public verification key"))?;
                cbor::write_bytes(&mut out, &bytes);
            }
        }
        cbor::write_bytes(&mut out, key.secret.expose());
        if out.len() as u64 > MAX_KEYRING_ENVELOPE_OBJECT_BYTES {
            return Err(invalid("key material exceeds bound"));
        }
    }
    Ok(out)
}

pub(crate) fn decode_keyring_plaintext(plaintext: &[u8]) -> Result<KeyRing, CryptoError> {
    if plaintext.len() as u64 > MAX_KEYRING_ENVELOPE_OBJECT_BYTES {
        return Err(invalid("key material exceeds bound"));
    }
    let mut reader = Reader::new(plaintext);
    let decode = (|| -> Result<Vec<KeyMaterial>, CryptoError> {
        require(reader.read_array_len()? == 2)?;
        require(reader.read_u64()? == u64::from(REPOSITORY_ENVELOPE_VERSION))?;
        let count = reader.read_array_len()?;
        require(count > 0 && count <= MAX_KEYS && count <= plaintext.len() / 7)?;
        let mut keys = Vec::with_capacity(count);
        let mut previous = None;
        for _ in 0..count {
            require(reader.read_array_len()? == 6)?;
            let id = KeyId::new(reader.read_text_bounded(255)?)
                .map_err(|_| invalid("invalid key id"))?;
            let purpose = match reader.read_u64()? {
                0 => KeyPurpose::Namespace,
                1 => KeyPurpose::Content,
                2 => KeyPurpose::Metadata,
                3 => KeyPurpose::CheckpointSigning,
                _ => return Err(invalid("invalid key purpose")),
            };
            let status = match reader.read_u64()? {
                0 => KeyStatus::Primary,
                1 => KeyStatus::Enabled,
                2 => KeyStatus::Disabled,
                3 => KeyStatus::Retired,
                _ => return Err(invalid("invalid key status")),
            };
            let created_at_ms = reader.read_i64()?;
            let public_key = if reader.next_is_null() {
                reader.read_null()?;
                None
            } else {
                let bytes = reader.read_bytes_bounded(32)?;
                require(bytes.len() == 32 && purpose == KeyPurpose::CheckpointSigning)?;
                Some(format!(
                    "{}{}",
                    crate::checkpoint::CHECKPOINT_PUBLIC_KEY_PREFIX,
                    hex::encode(bytes)
                ))
            };
            let identity = (purpose, id.clone());
            require(previous.as_ref().is_none_or(|old| old < &identity))?;
            previous = Some(identity);
            let secret = Zeroizing::new(reader.read_bytes_bounded(MAX_SECRET)?);
            keys.push(KeyMaterial::new(
                KeyDescriptor {
                    id,
                    purpose,
                    status,
                    created_at_ms,
                    public_key,
                },
                SecretBytes::from_zeroizing(secret)?,
            ));
        }
        require(reader.is_finished())?;
        Ok(keys)
    })()?;
    KeyRing::new(decode)
}

impl From<rs3_types::cbor::CborError> for CryptoError {
    fn from(_: rs3_types::cbor::CborError) -> Self {
        invalid("invalid canonical CBOR")
    }
}

fn purpose_tag(purpose: KeyPurpose) -> u64 {
    match purpose {
        KeyPurpose::Namespace => 0,
        KeyPurpose::Content => 1,
        KeyPurpose::Metadata => 2,
        KeyPurpose::CheckpointSigning => 3,
    }
}
fn require(condition: bool) -> Result<(), rs3_types::cbor::CborError> {
    if condition {
        Ok(())
    } else {
        Err(rs3_types::cbor::CborError::Invalid)
    }
}
fn field(reader: &mut Reader<'_>, key: u64) -> Result<(), rs3_types::cbor::CborError> {
    require(reader.read_u64()? == key)
}
fn envelope_cipher(
    wrapping_key: &SecretBytes,
    purpose: EnvelopePurpose,
) -> Result<Aes256GcmSiv, CryptoError> {
    let key = derive_hmac(wrapping_key, purpose.key_domain(), b"aes-256-gcm-siv")?;
    Aes256GcmSiv::new_from_slice(&key).map_err(|_| CryptoError::AeadOperationFailed)
}
fn invalid(reason: &str) -> CryptoError {
    CryptoError::InvalidRepositoryEnvelope {
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(byte: u8) -> SecretBytes {
        SecretBytes::new(vec![byte; 32]).expect("secret")
    }
    fn context() -> RepositoryKeyContext {
        RepositoryKeyContext::new(RepositoryId::new("repo-a").expect("id"), vec![2; 32])
            .expect("context")
    }
    fn seal(purpose: EnvelopePurpose) -> RepositoryEnvelope {
        match purpose {
            EnvelopePurpose::Keyring => KeyRing::generate_random()
                .expect("keyring")
                .seal_keyring_envelope(&context(), "wrap-v1", &secret(9), 1)
                .expect("seal keyring"),
            EnvelopePurpose::Format => RepositoryEnvelope::seal_format(
                &context(),
                "wrap-v1",
                &secret(9),
                1,
                b"format plaintext",
            )
            .expect("seal format"),
        }
    }

    #[test]
    fn canonical_envelopes_round_trip_with_separate_purposes() {
        for purpose in [EnvelopePurpose::Keyring, EnvelopePurpose::Format] {
            let envelope = seal(purpose);
            let bytes = envelope.to_object_bytes().expect("encode");
            let decoded = RepositoryEnvelope::from_object_bytes(&bytes, purpose).expect("decode");
            assert_eq!(decoded, envelope);
            let plaintext: Zeroizing<Vec<u8>> = decoded
                .open(purpose, &context(), "wrap-v1", &secret(9))
                .expect("open");
            match purpose {
                EnvelopePurpose::Keyring => {
                    decode_keyring_plaintext(&plaintext).expect("keys");
                }
                EnvelopePurpose::Format => assert_eq!(plaintext.as_slice(), b"format plaintext"),
            }
            let other = match purpose {
                EnvelopePurpose::Keyring => EnvelopePurpose::Format,
                EnvelopePurpose::Format => EnvelopePurpose::Keyring,
            };
            assert!(RepositoryEnvelope::from_object_bytes(&bytes, other).is_err());
            assert!(
                decoded
                    .open(other, &context(), "wrap-v1", &secret(9))
                    .is_err()
            );
        }
    }

    #[test]
    fn public_binding_and_ciphertext_tampering_fail_for_both_purposes() {
        for purpose in [EnvelopePurpose::Keyring, EnvelopePurpose::Format] {
            let envelope = seal(purpose);
            for field in 0..8 {
                let mut changed = envelope.clone();
                match field {
                    0 => changed.generation += 1,
                    1 => changed.repository_id = RepositoryId::new("other").expect("id"),
                    2 => changed.repository_salt[0] ^= 1,
                    3 => changed.wrapping_key_id.push('x'),
                    4 => changed.nonce[0] ^= 1,
                    5 => changed.ciphertext[0] ^= 1,
                    6 => changed.tag[0] ^= 1,
                    _ => changed.version += 1,
                }
                assert!(
                    changed
                        .open(purpose, &context(), "wrap-v1", &secret(9))
                        .is_err()
                );
            }
            assert!(
                envelope
                    .open(purpose, &context(), "wrap-v1", &secret(8))
                    .is_err()
            );
            let wrong_context = RepositoryKeyContext::new(
                RepositoryId::new("other-repo").expect("id"),
                vec![2; 32],
            )
            .expect("context");
            assert!(
                envelope
                    .open(purpose, &wrong_context, "wrap-v1", &secret(9))
                    .is_err()
            );
        }
    }

    #[test]
    fn rewrap_preserves_data_keys_and_canonical_key_order() {
        let keyring = KeyRing::generate_random().expect("keyring");
        let reversed = KeyRing::new(keyring.key_materials().iter().rev().cloned().collect())
            .expect("reordered keys");
        assert_eq!(
            keyring_plaintext_bytes(&keyring).expect("encode"),
            keyring_plaintext_bytes(&reversed).expect("reordered encode")
        );
        let envelope = keyring
            .seal_keyring_envelope(&context(), "wrap-v1", &secret(9), 1)
            .expect("seal");
        let rewrapped = envelope
            .rewrap(&context(), "wrap-v1", &secret(9), "wrap-v2", &secret(10), 2)
            .expect("rewrap");
        let opened = rewrapped
            .open_keyring(&context(), "wrap-v2", &secret(10))
            .expect("open");
        assert_eq!(
            keyring_plaintext_bytes(&opened).expect("opened"),
            keyring_plaintext_bytes(&keyring).expect("original")
        );
        assert_ne!(
            rewrapped.digest().expect("digest"),
            envelope.digest().expect("digest")
        );
    }

    #[test]
    fn canonical_digest_is_independent_of_struct_field_order() {
        let envelope = seal(EnvelopePurpose::Format);
        let reordered = RepositoryEnvelope {
            tag: envelope.tag.clone(),
            ciphertext: envelope.ciphertext.clone(),
            nonce: envelope.nonce.clone(),
            wrapping_key_id: envelope.wrapping_key_id.clone(),
            repository_salt: envelope.repository_salt.clone(),
            repository_id: envelope.repository_id.clone(),
            generation: envelope.generation,
            purpose: envelope.purpose,
            version: envelope.version,
        };
        let bytes = reordered.to_object_bytes().expect("encode");
        assert_eq!(
            envelope.digest().expect("digest"),
            hex::encode(Sha256Hasher::digest(&bytes))
        );
        assert_eq!(bytes, envelope.to_object_bytes().expect("encode"));
    }

    #[test]
    fn reject_noncanonical_unknown_duplicate_truncated_and_trailing_fields() {
        let bytes = seal(EnvelopePurpose::Format)
            .to_object_bytes()
            .expect("encode");
        for length in 0..bytes.len() {
            assert!(
                RepositoryEnvelope::from_object_bytes(&bytes[..length], EnvelopePurpose::Format)
                    .is_err()
            );
        }
        let mut candidates = Vec::new();
        let mut duplicate = bytes.clone();
        duplicate[3] = 0;
        candidates.push(duplicate);
        let mut unknown = bytes.clone();
        unknown[1] = 9;
        candidates.push(unknown);
        let mut trailing = bytes.clone();
        trailing.push(0);
        candidates.push(trailing);
        let mut nonminimal = bytes[..2].to_vec();
        nonminimal.extend_from_slice(&[0x18, 3]);
        nonminimal.extend_from_slice(&bytes[3..]);
        candidates.push(nonminimal);
        for candidate in candidates {
            assert!(
                RepositoryEnvelope::from_object_bytes(&candidate, EnvelopePurpose::Format).is_err()
            );
        }
        assert!(
            RepositoryEnvelope::from_object_bytes(br#"{"version":1}"#, EnvelopePurpose::Format)
                .is_err()
        );
    }

    #[test]
    fn envelopes_reject_oversized_objects_and_declared_ciphertext_before_copying() {
        for purpose in [EnvelopePurpose::Keyring, EnvelopePurpose::Format] {
            let oversized = vec![0; purpose.maximum() as usize + 1];
            assert!(RepositoryEnvelope::from_object_bytes(&oversized, purpose).is_err());
            let envelope = seal(purpose);
            let mut declared = Vec::new();
            cbor::write_map_len(&mut declared, 9);
            envelope.write_public_fields(&mut declared);
            cbor::write_u64(&mut declared, 7);
            // Canonical byte-string length beyond either object ceiling, without a body.
            declared.extend_from_slice(&[0x5a, 0x01, 0x00, 0x00, 0x01]);
            assert!(RepositoryEnvelope::from_object_bytes(&declared, purpose).is_err());
        }
    }

    #[test]
    fn keyring_plaintext_rejects_short_secrets_and_unsorted_or_duplicate_keys() {
        let mut short = Vec::new();
        cbor::write_array_len(&mut short, 2);
        cbor::write_u64(&mut short, 3);
        cbor::write_array_len(&mut short, 1);
        cbor::write_array_len(&mut short, 6);
        cbor::write_text(&mut short, "namespace");
        cbor::write_u64(&mut short, 0);
        cbor::write_u64(&mut short, 0);
        cbor::write_i64(&mut short, 0);
        cbor::write_null(&mut short);
        cbor::write_bytes(&mut short, &[0]);
        assert!(matches!(
            decode_keyring_plaintext(&short),
            Err(CryptoError::SecretTooShort { .. })
        ));
        let keyring = KeyRing::generate_random().expect("keyring");
        let encoded = keyring_plaintext_bytes(&keyring).expect("encode");
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_keyring_plaintext(&trailing).is_err());
        for purposes in [[0, 0], [1, 0]] {
            let mut invalid_order = vec![0x82, 0x03, 0x82];
            for purpose in purposes {
                cbor::write_array_len(&mut invalid_order, 6);
                cbor::write_text(&mut invalid_order, "same-id");
                cbor::write_u64(&mut invalid_order, purpose);
                cbor::write_u64(&mut invalid_order, 0);
                cbor::write_i64(&mut invalid_order, 0);
                cbor::write_null(&mut invalid_order);
                cbor::write_bytes(&mut invalid_order, &[5; 32]);
            }
            assert!(decode_keyring_plaintext(&invalid_order).is_err());
        }
        let mut oversized_count = vec![0x82, 0x03];
        cbor::write_array_len(&mut oversized_count, MAX_KEYS + 1);
        assert!(decode_keyring_plaintext(&oversized_count).is_err());
    }
}
