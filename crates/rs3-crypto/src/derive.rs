//! Domain-separated identifier derivation.

use crate::keyring::KeyRing;
use crate::primitives::derive_hmac;
use crate::{CryptoError, SecretBytes};
use rs3_types::{
    BackendObjectId, BlindIndexKey, KeyId, KeyPurpose, LogicalPath, ManifestId, PrefixToken,
};

/// Blind key derivation result tied to the namespace key that produced it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamespaceBlindKey {
    /// Namespace key that produced this blind key.
    pub key_id: KeyId,
    /// Derived blind lookup key.
    pub blind_key: BlindIndexKey,
}

/// Prefix token derivation result tied to the namespace key that produced it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamespacePrefixToken {
    /// Namespace key that produced this prefix token.
    pub key_id: KeyId,
    /// Derived prefix lookup token.
    pub prefix_token: PrefixToken,
}

impl KeyRing {
    /// Derives the primary blind index key for a normalized logical path.
    pub fn derive_primary_blind_index_key(
        &self,
        normalized_path: &LogicalPath,
    ) -> Result<NamespaceBlindKey, CryptoError> {
        let key = self.primary_key(KeyPurpose::Namespace)?;
        Ok(NamespaceBlindKey {
            key_id: key.descriptor.id.clone(),
            blind_key: derive_blind_index_key(&key.secret, normalized_path)?,
        })
    }

    /// Derives blind index keys for lookup with every enabled namespace key.
    pub fn derive_blind_index_keys_for_lookup(
        &self,
        normalized_path: &LogicalPath,
    ) -> Result<Vec<NamespaceBlindKey>, CryptoError> {
        self.enabled_keys(KeyPurpose::Namespace)?
            .into_iter()
            .map(|key| {
                Ok(NamespaceBlindKey {
                    key_id: key.descriptor.id.clone(),
                    blind_key: derive_blind_index_key(&key.secret, normalized_path)?,
                })
            })
            .collect()
    }

    /// Derives the primary prefix token for a client-visible prefix.
    pub fn derive_primary_prefix_token(
        &self,
        normalized_prefix: &str,
    ) -> Result<NamespacePrefixToken, CryptoError> {
        let key = self.primary_key(KeyPurpose::Namespace)?;
        Ok(NamespacePrefixToken {
            key_id: key.descriptor.id.clone(),
            prefix_token: derive_prefix_token(&key.secret, normalized_prefix)?,
        })
    }

    /// Derives prefix tokens for lookup with every enabled namespace key.
    pub fn derive_prefix_tokens_for_lookup(
        &self,
        normalized_prefix: &str,
    ) -> Result<Vec<NamespacePrefixToken>, CryptoError> {
        self.enabled_keys(KeyPurpose::Namespace)?
            .into_iter()
            .map(|key| {
                Ok(NamespacePrefixToken {
                    key_id: key.descriptor.id.clone(),
                    prefix_token: derive_prefix_token(&key.secret, normalized_prefix)?,
                })
            })
            .collect()
    }

    /// Derives a prefix token with a specific enabled namespace key.
    pub fn derive_prefix_token_with_namespace_key(
        &self,
        key_id: &KeyId,
        normalized_prefix: &str,
    ) -> Result<PrefixToken, CryptoError> {
        let key = self.enabled_key_by_id(key_id, KeyPurpose::Namespace)?;
        derive_prefix_token(&key.secret, normalized_prefix)
    }

    /// Derives an opaque backend object identifier with the primary namespace key.
    pub fn derive_backend_object_id(
        &self,
        object_class: &str,
        material: &[u8],
    ) -> Result<BackendObjectId, CryptoError> {
        let key = self.primary_key(KeyPurpose::Namespace)?;
        derive_backend_object_id(&key.secret, object_class, material)
    }

    /// Derives an opaque manifest identifier with the primary namespace key.
    pub fn derive_manifest_id(&self, material: &[u8]) -> Result<ManifestId, CryptoError> {
        let key = self.primary_key(KeyPurpose::Namespace)?;
        derive_manifest_id(&key.secret, material)
    }
}

/// Derives a stable blind index key for a normalized logical path.
pub fn derive_blind_index_key(
    repository_secret: &SecretBytes,
    normalized_path: &LogicalPath,
) -> Result<BlindIndexKey, CryptoError> {
    let bytes = derive_hmac(
        repository_secret,
        b"rs3:blind-index:v1",
        normalized_path.as_str().as_bytes(),
    )?;
    BlindIndexKey::new(hex::encode(bytes.as_slice())).map_err(CryptoError::from)
}

/// Derives a stable prefix-list token for a normalized client-visible prefix.
pub fn derive_prefix_token(
    repository_secret: &SecretBytes,
    normalized_prefix: &str,
) -> Result<PrefixToken, CryptoError> {
    let bytes = derive_hmac(
        repository_secret,
        b"rs3:prefix-token:v1",
        normalized_prefix.as_bytes(),
    )?;
    PrefixToken::new(hex::encode(bytes.as_slice())).map_err(CryptoError::from)
}

/// Derives an opaque backend object identifier for a durable object class.
pub fn derive_backend_object_id(
    repository_secret: &SecretBytes,
    object_class: &str,
    material: &[u8],
) -> Result<BackendObjectId, CryptoError> {
    let bytes = derive_hmac(repository_secret, b"rs3:backend-object-id:v1", material)?;
    BackendObjectId::new(format!("{object_class}/{}", hex::encode(bytes.as_slice())))
        .map_err(CryptoError::from)
}

/// Derives an opaque manifest identifier.
pub fn derive_manifest_id(
    repository_secret: &SecretBytes,
    material: &[u8],
) -> Result<ManifestId, CryptoError> {
    let bytes = derive_hmac(repository_secret, b"rs3:manifest-id:v1", material)?;
    ManifestId::new(hex::encode(bytes.as_slice())).map_err(CryptoError::from)
}

#[cfg(test)]
mod tests {
    use super::{
        derive_backend_object_id, derive_blind_index_key, derive_manifest_id, derive_prefix_token,
    };
    use crate::{KeyMaterial, KeyRing, SecretBytes};
    use rs3_types::{KeyDescriptor, KeyId, KeyPurpose, KeyStatus, LogicalPath};

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

    fn path(value: &str) -> LogicalPath {
        match LogicalPath::new(value) {
            Ok(path) => path,
            Err(error) => panic!("{error}"),
        }
    }

    #[test]
    fn blind_index_is_stable_for_same_path() {
        let secret = secret(7);
        let path = path("/namespace/pvc/file");

        let first = derive_blind_index_key(&secret, &path);
        let second = derive_blind_index_key(&secret, &path);

        assert!(first.is_ok());
        assert_eq!(first.ok(), second.ok());
    }

    #[test]
    fn prefix_token_is_domain_separated_from_blind_key() {
        let secret = secret(7);
        let path = path("p/12/abcdef");

        let blind = derive_blind_index_key(&secret, &path);
        let prefix = derive_prefix_token(&secret, path.as_str());

        assert!(blind.is_ok());
        assert!(prefix.is_ok());
        assert_ne!(
            blind.map(|value| value.to_string()).ok(),
            prefix.map(|value| value.to_string()).ok()
        );
    }

    #[test]
    fn opaque_ids_do_not_include_material() {
        let secret = secret(7);
        let object_id = derive_backend_object_id(&secret, "segments", b"p/12/abcdef:1");
        let manifest_id = derive_manifest_id(&secret, b"p/12/abcdef:1");

        assert!(object_id.is_ok());
        assert!(manifest_id.is_ok());
        assert!(
            !object_id
                .map(|value| value.to_string())
                .unwrap_or_default()
                .contains("abcdef")
        );
        assert!(
            !manifest_id
                .map(|value| value.to_string())
                .unwrap_or_default()
                .contains("abcdef")
        );
    }

    #[test]
    fn keyring_lookup_uses_primary_before_enabled_old_keys() {
        let keyring = match KeyRing::new(vec![
            namespace_key("old", KeyStatus::Enabled, 1),
            namespace_key("new", KeyStatus::Primary, 2),
        ]) {
            Ok(keyring) => keyring,
            Err(error) => panic!("{error}"),
        };

        let derived = keyring.derive_blind_index_keys_for_lookup(&path("p/12/abcdef"));

        let key_ids = match derived {
            Ok(derived) => derived
                .into_iter()
                .map(|candidate| candidate.key_id)
                .collect::<Vec<_>>(),
            Err(error) => panic!("{error}"),
        };

        assert_eq!(key_ids, vec![key_id("new"), key_id("old")]);
    }

    #[test]
    fn keyring_skips_disabled_namespace_keys() {
        let keyring = match KeyRing::new(vec![
            namespace_key("old", KeyStatus::Disabled, 1),
            namespace_key("new", KeyStatus::Primary, 2),
        ]) {
            Ok(keyring) => keyring,
            Err(error) => panic!("{error}"),
        };

        let derived = keyring.derive_prefix_tokens_for_lookup("p/12");

        let key_ids = match derived {
            Ok(derived) => derived
                .into_iter()
                .map(|candidate| candidate.key_id)
                .collect::<Vec<_>>(),
            Err(error) => panic!("{error}"),
        };

        assert_eq!(key_ids, vec![key_id("new")]);
    }
}
