//! Purpose-specific repository keyrings.

use crate::checkpoint::derive_checkpoint_public_key_descriptor;
use crate::{CryptoError, SecretBytes};
use getrandom::fill as fill_random;
use rs3_types::{KeyDescriptor, KeyId, KeyPurpose, KeyStatus, RepositoryId};
use std::collections::BTreeSet;

const NAMESPACE_ALGORITHM: &str = "hmac-sha256";
const CONTENT_ALGORITHM: &str = "xchacha20poly1305";
const METADATA_ALGORITHM: &str = "aes-256-gcm-siv-hmac-sha256-nonce-v1";
const CHECKPOINT_ALGORITHM: &str = "ed25519";

/// Minimum public repository salt length accepted by the production KDF path.
pub const MIN_REPOSITORY_SALT_LEN: usize = 32;

/// Secret-bearing keyring entry.
#[derive(Clone, Debug)]
pub struct KeyMaterial {
    pub(crate) descriptor: KeyDescriptor,
    pub(crate) secret: SecretBytes,
}

impl KeyMaterial {
    /// Creates a keyring entry from public metadata and local secret material.
    pub fn new(descriptor: KeyDescriptor, secret: SecretBytes) -> Self {
        Self { descriptor, secret }
    }

    /// Returns public metadata for this key.
    pub fn descriptor(&self) -> &KeyDescriptor {
        &self.descriptor
    }
}

/// Stable public context that binds derived keys to one repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryKeyContext {
    repository_id: RepositoryId,
    salt: Vec<u8>,
}

impl RepositoryKeyContext {
    /// Creates a production repository key context.
    pub fn new(repository_id: RepositoryId, salt: Vec<u8>) -> Result<Self, CryptoError> {
        if salt.len() < MIN_REPOSITORY_SALT_LEN {
            return Err(CryptoError::RepositorySaltTooShort {
                minimum_len: MIN_REPOSITORY_SALT_LEN,
            });
        }

        Ok(Self {
            repository_id,
            salt,
        })
    }

    /// Returns the public repository identifier bound into derived keys.
    pub fn repository_id(&self) -> &RepositoryId {
        &self.repository_id
    }

    /// Returns the public repository salt bound into derived keys.
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }
}

/// Repository keyring with purpose-specific primary and enabled old keys.
#[derive(Clone, Debug)]
pub struct KeyRing {
    keys: Vec<KeyMaterial>,
}

impl KeyRing {
    /// Creates a validated keyring.
    pub fn new(keys: Vec<KeyMaterial>) -> Result<Self, CryptoError> {
        validate_keyring(&keys)?;
        Ok(Self { keys })
    }

    /// Generates a new keyring from random purpose-specific data keys.
    ///
    /// This is the preferred production bootstrap shape when the generated
    /// keyring is stored in an encrypted keyring envelope.
    pub fn generate_random() -> Result<Self, CryptoError> {
        let checkpoint_secret = random_secret()?;
        Self::new(vec![
            KeyMaterial::new(default_namespace_descriptor(), random_secret()?),
            KeyMaterial::new(default_content_descriptor(), random_secret()?),
            KeyMaterial::new(default_metadata_descriptor(), random_secret()?),
            KeyMaterial::new(
                default_checkpoint_descriptor(&checkpoint_secret)?,
                checkpoint_secret,
            ),
        ])
    }

    /// Creates a single-secret keyring for focused tests.
    pub fn single_namespace(secret: SecretBytes) -> Self {
        Self {
            keys: vec![
                KeyMaterial::new(default_namespace_descriptor(), secret.clone()),
                KeyMaterial::new(default_content_descriptor(), secret.clone()),
                KeyMaterial::new(default_metadata_descriptor(), secret),
            ],
        }
    }

    /// Returns the primary namespace key ID.
    pub fn primary_namespace_key_id(&self) -> Result<KeyId, CryptoError> {
        self.primary_key_id(KeyPurpose::Namespace)
    }

    /// Returns the primary content key ID.
    pub fn primary_content_key_id(&self) -> Result<KeyId, CryptoError> {
        self.primary_key_id(KeyPurpose::Content)
    }

    /// Returns the primary key ID for a cryptographic purpose.
    pub fn primary_key_id(&self, purpose: KeyPurpose) -> Result<KeyId, CryptoError> {
        self.primary_key(purpose)
            .map(|key| key.descriptor.id.clone())
    }

    /// Returns a new keyring with a fresh primary key for `purpose`.
    ///
    /// The previous primary key for the same purpose is demoted to `Enabled`
    /// so retained checkpoint chains and old objects can still be read or
    /// verified. The caller is responsible for storing the returned keyring in
    /// a new envelope and publishing a checkpoint that binds the envelope.
    pub fn rotate_purpose_key(
        &self,
        purpose: KeyPurpose,
        new_key_id: KeyId,
        created_at_ms: i64,
    ) -> Result<Self, CryptoError> {
        let _ = self.primary_key(purpose)?;
        let secret = random_secret()?;
        let descriptor = rotated_descriptor(new_key_id, purpose, created_at_ms, &secret)?;
        let mut keys = self
            .keys
            .iter()
            .cloned()
            .map(|mut key| {
                if key.descriptor.purpose == purpose && key.descriptor.status.is_primary() {
                    key.descriptor.status = KeyStatus::Enabled;
                }
                key
            })
            .collect::<Vec<_>>();
        keys.push(KeyMaterial::new(descriptor, secret));
        Self::new(keys)
    }

    /// Returns public key descriptors sorted for deterministic checkpoints.
    pub fn descriptors(&self) -> Vec<KeyDescriptor> {
        let mut descriptors = self
            .keys
            .iter()
            .map(|key| key.descriptor.clone())
            .collect::<Vec<_>>();
        sort_descriptors(&mut descriptors);
        descriptors
    }

    pub(crate) fn key_materials(&self) -> &[KeyMaterial] {
        &self.keys
    }

    /// Returns the primary key for a cryptographic purpose.
    pub(crate) fn primary_key(&self, purpose: KeyPurpose) -> Result<&KeyMaterial, CryptoError> {
        let mut matches = self
            .keys
            .iter()
            .filter(|key| key.descriptor.purpose == purpose && key.descriptor.status.is_primary());
        let Some(primary) = matches.next() else {
            return Err(CryptoError::NoPrimaryKey { purpose });
        };
        if matches.next().is_some() {
            return Err(CryptoError::MultiplePrimaryKeys { purpose });
        }
        Ok(primary)
    }

    /// Returns enabled keys for read, verify, or lookup.
    pub(crate) fn enabled_keys(
        &self,
        purpose: KeyPurpose,
    ) -> Result<Vec<&KeyMaterial>, CryptoError> {
        let mut primary = Vec::new();
        let mut enabled = Vec::new();

        for key in &self.keys {
            if key.descriptor.purpose != purpose || !key.descriptor.status.is_enabled_for_lookup() {
                continue;
            }

            if key.descriptor.status.is_primary() {
                primary.push(key);
            } else {
                enabled.push(key);
            }
        }

        if primary.len() > 1 {
            return Err(CryptoError::MultiplePrimaryKeys { purpose });
        }

        primary.extend(enabled);
        if primary.is_empty() {
            return Err(CryptoError::NoEnabledKeys { purpose });
        }

        Ok(primary)
    }

    /// Returns a specific enabled key for a cryptographic purpose.
    pub(crate) fn enabled_key_by_id(
        &self,
        key_id: &KeyId,
        expected: KeyPurpose,
    ) -> Result<&KeyMaterial, CryptoError> {
        let key = self
            .keys
            .iter()
            .find(|key| &key.descriptor.id == key_id)
            .ok_or_else(|| CryptoError::MissingKey {
                key_id: key_id.clone(),
            })?;

        if key.descriptor.purpose != expected {
            return Err(CryptoError::KeyPurposeMismatch {
                key_id: key_id.clone(),
                expected,
                actual: key.descriptor.purpose,
            });
        }

        if !key.descriptor.status.is_enabled_for_lookup() {
            return Err(CryptoError::InactiveKey {
                key_id: key_id.clone(),
                status: key.descriptor.status,
            });
        }

        Ok(key)
    }
}

fn validate_keyring(keys: &[KeyMaterial]) -> Result<(), CryptoError> {
    let mut ids = BTreeSet::new();
    for key in keys {
        if !ids.insert(key.descriptor.id.clone()) {
            return Err(CryptoError::DuplicateKeyId {
                key_id: key.descriptor.id.clone(),
            });
        }
    }

    for purpose in [
        KeyPurpose::Namespace,
        KeyPurpose::Content,
        KeyPurpose::Metadata,
        KeyPurpose::CheckpointSigning,
    ] {
        let primary_count = keys
            .iter()
            .filter(|key| key.descriptor.purpose == purpose && key.descriptor.status.is_primary())
            .count();
        if primary_count > 1 {
            return Err(CryptoError::MultiplePrimaryKeys { purpose });
        }
    }

    if !keys.iter().any(|key| {
        key.descriptor.purpose == KeyPurpose::Namespace && key.descriptor.status.is_primary()
    }) {
        return Err(CryptoError::NoPrimaryKey {
            purpose: KeyPurpose::Namespace,
        });
    }

    Ok(())
}

fn random_secret() -> Result<SecretBytes, CryptoError> {
    let mut secret = [0_u8; SecretBytes::MIN_LEN];
    fill_random(&mut secret).map_err(|_| CryptoError::RandomnessUnavailable)?;
    SecretBytes::new(secret.to_vec())
}

fn sort_descriptors(descriptors: &mut [KeyDescriptor]) {
    descriptors.sort_by(|left, right| {
        left.purpose
            .cmp(&right.purpose)
            .then_with(|| left.id.cmp(&right.id))
    });
}

fn default_namespace_descriptor() -> KeyDescriptor {
    KeyDescriptor {
        id: static_key_id("namespace-v1"),
        purpose: KeyPurpose::Namespace,
        algorithm: NAMESPACE_ALGORITHM.to_string(),
        status: KeyStatus::Primary,
        created_at_ms: 0,
        not_before_ms: None,
        not_after_ms: None,
        public_key: None,
        external_kms_uri: None,
    }
}

fn default_metadata_descriptor() -> KeyDescriptor {
    KeyDescriptor {
        id: static_key_id("metadata-v1"),
        purpose: KeyPurpose::Metadata,
        algorithm: METADATA_ALGORITHM.to_string(),
        status: KeyStatus::Primary,
        created_at_ms: 0,
        not_before_ms: None,
        not_after_ms: None,
        public_key: None,
        external_kms_uri: None,
    }
}

fn default_content_descriptor() -> KeyDescriptor {
    KeyDescriptor {
        id: static_key_id("content-v1"),
        purpose: KeyPurpose::Content,
        algorithm: CONTENT_ALGORITHM.to_string(),
        status: KeyStatus::Primary,
        created_at_ms: 0,
        not_before_ms: None,
        not_after_ms: None,
        public_key: None,
        external_kms_uri: None,
    }
}

fn default_checkpoint_descriptor(secret: &SecretBytes) -> Result<KeyDescriptor, CryptoError> {
    Ok(KeyDescriptor {
        id: static_key_id("checkpoint-v1"),
        purpose: KeyPurpose::CheckpointSigning,
        algorithm: CHECKPOINT_ALGORITHM.to_string(),
        status: KeyStatus::Primary,
        created_at_ms: 0,
        not_before_ms: None,
        not_after_ms: None,
        public_key: Some(derive_checkpoint_public_key_descriptor(secret)?),
        external_kms_uri: None,
    })
}

fn rotated_descriptor(
    id: KeyId,
    purpose: KeyPurpose,
    created_at_ms: i64,
    secret: &SecretBytes,
) -> Result<KeyDescriptor, CryptoError> {
    Ok(KeyDescriptor {
        id,
        purpose,
        algorithm: algorithm_for_purpose(purpose).to_owned(),
        status: KeyStatus::Primary,
        created_at_ms,
        not_before_ms: None,
        not_after_ms: None,
        public_key: match purpose {
            KeyPurpose::CheckpointSigning => Some(derive_checkpoint_public_key_descriptor(secret)?),
            KeyPurpose::Namespace | KeyPurpose::Content | KeyPurpose::Metadata => None,
        },
        external_kms_uri: None,
    })
}

fn algorithm_for_purpose(purpose: KeyPurpose) -> &'static str {
    match purpose {
        KeyPurpose::Namespace => NAMESPACE_ALGORITHM,
        KeyPurpose::Content => CONTENT_ALGORITHM,
        KeyPurpose::Metadata => METADATA_ALGORITHM,
        KeyPurpose::CheckpointSigning => CHECKPOINT_ALGORITHM,
    }
}

fn static_key_id(value: &str) -> KeyId {
    match KeyId::new(value) {
        Ok(key_id) => key_id,
        Err(error) => unreachable!("static key id is valid: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyMaterial, KeyRing, RepositoryKeyContext};
    use crate::SecretBytes;
    use rs3_types::{KeyDescriptor, KeyId, KeyPurpose, KeyStatus, RepositoryId};

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

    fn namespace_key(value: &str, status: KeyStatus, secret_byte: u8) -> KeyMaterial {
        KeyMaterial::new(
            KeyDescriptor {
                id: key_id(value),
                purpose: KeyPurpose::Namespace,
                algorithm: "hmac-sha256".to_string(),
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

    fn repository_id(value: &str) -> RepositoryId {
        match RepositoryId::new(value) {
            Ok(repository_id) => repository_id,
            Err(error) => panic!("{error}"),
        }
    }

    #[test]
    fn keyring_rejects_duplicate_key_ids() {
        let keyring = KeyRing::new(vec![
            namespace_key("same", KeyStatus::Primary, 1),
            namespace_key("same", KeyStatus::Enabled, 2),
        ]);

        assert!(keyring.is_err());
    }

    #[test]
    fn keyring_descriptors_are_public_and_deterministic() {
        let keyring = match KeyRing::new(vec![
            namespace_key("old", KeyStatus::Enabled, 1),
            namespace_key("new", KeyStatus::Primary, 2),
        ]) {
            Ok(keyring) => keyring,
            Err(error) => panic!("{error}"),
        };

        let descriptors = keyring.descriptors();

        assert_eq!(
            descriptors
                .into_iter()
                .map(|descriptor| (descriptor.id, descriptor.status))
                .collect::<Vec<_>>(),
            vec![
                (key_id("new"), KeyStatus::Primary),
                (key_id("old"), KeyStatus::Enabled)
            ]
        );
    }

    #[test]
    fn random_keyring_generates_distinct_purpose_keys() {
        let keyring = match KeyRing::generate_random() {
            Ok(keyring) => keyring,
            Err(error) => panic!("{error}"),
        };

        assert_eq!(
            keyring
                .descriptors()
                .into_iter()
                .map(|descriptor| descriptor.purpose)
                .collect::<Vec<_>>(),
            vec![
                KeyPurpose::Namespace,
                KeyPurpose::Content,
                KeyPurpose::Metadata,
                KeyPurpose::CheckpointSigning,
            ]
        );

        let mut secrets = keyring
            .keys
            .iter()
            .map(|key| key.secret.expose().to_vec())
            .collect::<Vec<_>>();
        secrets.sort();
        secrets.dedup();
        assert_eq!(secrets.len(), 4);
    }

    #[test]
    fn rotate_purpose_key_demotes_old_primary_and_adds_new_primary() {
        let keyring = match KeyRing::new(vec![namespace_key("old", KeyStatus::Primary, 1)]) {
            Ok(keyring) => keyring,
            Err(error) => panic!("{error}"),
        };

        let rotated = match keyring.rotate_purpose_key(KeyPurpose::Namespace, key_id("new"), 123) {
            Ok(keyring) => keyring,
            Err(error) => panic!("{error}"),
        };

        let descriptors = rotated.descriptors();
        let primary = match rotated.primary_key_id(KeyPurpose::Namespace) {
            Ok(key_id) => key_id,
            Err(error) => panic!("{error}"),
        };
        assert_eq!(primary, key_id("new"));
        assert_eq!(
            descriptors
                .iter()
                .map(|descriptor| (descriptor.id.clone(), descriptor.status))
                .collect::<Vec<_>>(),
            vec![
                (key_id("new"), KeyStatus::Primary),
                (key_id("old"), KeyStatus::Enabled)
            ]
        );
    }

    #[test]
    fn rotate_checkpoint_signing_key_records_public_verification_key() {
        let keyring = match KeyRing::generate_random() {
            Ok(keyring) => keyring,
            Err(error) => panic!("{error}"),
        };

        let rotated = match keyring.rotate_purpose_key(
            KeyPurpose::CheckpointSigning,
            key_id("checkpoint-v2"),
            123,
        ) {
            Ok(keyring) => keyring,
            Err(error) => panic!("{error}"),
        };

        let descriptor = rotated
            .descriptors()
            .into_iter()
            .find(|descriptor| descriptor.id == key_id("checkpoint-v2"))
            .unwrap_or_else(|| panic!("missing rotated descriptor"));

        assert_eq!(descriptor.purpose, KeyPurpose::CheckpointSigning);
        assert_eq!(descriptor.status, KeyStatus::Primary);
        assert!(descriptor.public_key.is_some());
    }

    #[test]
    fn rotate_purpose_key_rejects_duplicate_key_id() {
        let keyring = match KeyRing::new(vec![namespace_key("old", KeyStatus::Primary, 1)]) {
            Ok(keyring) => keyring,
            Err(error) => panic!("{error}"),
        };

        let rotated = keyring.rotate_purpose_key(KeyPurpose::Namespace, key_id("old"), 123);

        assert!(rotated.is_err());
    }

    #[test]
    fn repository_key_context_rejects_short_salt() {
        let context = RepositoryKeyContext::new(repository_id("repository-a"), vec![7; 31]);

        assert!(context.is_err());
    }
}
