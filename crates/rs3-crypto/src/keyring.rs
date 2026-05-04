//! Purpose-specific repository keyrings.

use crate::primitives::derive_hmac;
use crate::{CryptoError, SecretBytes};
use rs3_types::{KeyDescriptor, KeyId, KeyPurpose, KeyStatus};
use std::collections::BTreeSet;

const NAMESPACE_ALGORITHM: &str = "hmac-sha256";
const CONTENT_ALGORITHM: &str = "xchacha20poly1305";
const METADATA_ALGORITHM: &str = "xchacha20poly1305-hmac-sha256-nonce-v1";
const CHECKPOINT_ALGORITHM: &str = "hmac-sha256";

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

    /// Derives the default purpose-specific keyring from one repository master key.
    ///
    /// This uses a legacy default repository context. Gateway deployments should
    /// use [`Self::from_repository_master_key_for_repository`] with an explicit,
    /// stable repository identifier.
    pub fn from_repository_master_key(master_key: &SecretBytes) -> Result<Self, CryptoError> {
        Self::from_repository_master_key_for_repository(master_key, "default")
    }

    /// Derives the default purpose-specific keyring for one repository.
    pub fn from_repository_master_key_for_repository(
        master_key: &SecretBytes,
        repository_id: &str,
    ) -> Result<Self, CryptoError> {
        if repository_id.is_empty() {
            return Err(CryptoError::EmptyRepositoryContext);
        }
        Self::new(vec![
            KeyMaterial::new(
                default_namespace_descriptor(),
                derive_repository_subkey(master_key, repository_id, b"namespace")?,
            ),
            KeyMaterial::new(
                default_content_descriptor(),
                derive_repository_subkey(master_key, repository_id, b"content")?,
            ),
            KeyMaterial::new(
                default_metadata_descriptor(),
                derive_repository_subkey(master_key, repository_id, b"metadata")?,
            ),
            KeyMaterial::new(
                default_checkpoint_descriptor(),
                derive_repository_subkey(master_key, repository_id, b"checkpoint")?,
            ),
        ])
    }

    /// Creates a legacy single-secret keyring for focused tests.
    ///
    /// Production callers should derive purpose-specific keys from a repository
    /// master key with [`Self::from_repository_master_key`].
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
        self.primary_key(KeyPurpose::Namespace)
            .map(|key| key.descriptor.id.clone())
    }

    /// Returns the primary content key ID.
    pub fn primary_content_key_id(&self) -> Result<KeyId, CryptoError> {
        self.primary_key(KeyPurpose::Content)
            .map(|key| key.descriptor.id.clone())
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

fn derive_repository_subkey(
    master_key: &SecretBytes,
    repository_id: &str,
    purpose: &[u8],
) -> Result<SecretBytes, CryptoError> {
    let mut material = Vec::with_capacity(
        repository_id
            .len()
            .saturating_add(1)
            .saturating_add(purpose.len()),
    );
    material.extend_from_slice(repository_id.as_bytes());
    material.push(0);
    material.extend_from_slice(purpose);

    SecretBytes::new(derive_hmac(
        master_key,
        b"rs3:repository-subkey:v2",
        &material,
    )?)
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
        external_kms_uri: None,
    }
}

fn default_checkpoint_descriptor() -> KeyDescriptor {
    KeyDescriptor {
        id: static_key_id("checkpoint-v1"),
        purpose: KeyPurpose::CheckpointSigning,
        algorithm: CHECKPOINT_ALGORITHM.to_string(),
        status: KeyStatus::Primary,
        created_at_ms: 0,
        not_before_ms: None,
        not_after_ms: None,
        external_kms_uri: None,
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
    use super::{KeyMaterial, KeyRing};
    use crate::SecretBytes;
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
                external_kms_uri: None,
            },
            secret(secret_byte),
        )
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
    fn repository_master_key_derives_purpose_specific_keys() {
        let master_key = secret(9);

        let keyring =
            match KeyRing::from_repository_master_key_for_repository(&master_key, "repository-a") {
                Ok(keyring) => keyring,
                Err(error) => panic!("{error}"),
            };

        assert_eq!(
            keyring
                .descriptors()
                .into_iter()
                .map(|descriptor| (descriptor.id, descriptor.purpose, descriptor.algorithm))
                .collect::<Vec<_>>(),
            vec![
                (
                    key_id("namespace-v1"),
                    KeyPurpose::Namespace,
                    "hmac-sha256".to_owned()
                ),
                (
                    key_id("content-v1"),
                    KeyPurpose::Content,
                    "xchacha20poly1305".to_owned()
                ),
                (
                    key_id("metadata-v1"),
                    KeyPurpose::Metadata,
                    "xchacha20poly1305-hmac-sha256-nonce-v1".to_owned()
                ),
                (
                    key_id("checkpoint-v1"),
                    KeyPurpose::CheckpointSigning,
                    "hmac-sha256".to_owned()
                ),
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
    fn repository_master_key_derivation_is_bound_to_repository_id() {
        let master_key = secret(9);
        let first =
            match KeyRing::from_repository_master_key_for_repository(&master_key, "repository-a") {
                Ok(keyring) => keyring,
                Err(error) => panic!("{error}"),
            };
        let second =
            match KeyRing::from_repository_master_key_for_repository(&master_key, "repository-b") {
                Ok(keyring) => keyring,
                Err(error) => panic!("{error}"),
            };

        assert_ne!(
            first
                .keys
                .iter()
                .map(|key| key.secret.expose().to_vec())
                .collect::<Vec<_>>(),
            second
                .keys
                .iter()
                .map(|key| key.secret.expose().to_vec())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn repository_master_key_derivation_rejects_empty_repository_id() {
        let master_key = secret(9);

        let keyring = KeyRing::from_repository_master_key_for_repository(&master_key, "");

        assert!(keyring.is_err());
    }
}
