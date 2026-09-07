//! v2 format-root metadata.

use super::commit::V2KeyringEnvelopeRef;
use super::error::{V2FormatError, V2Result};
use super::provider::V2ProviderProfile;
use rs3_types::{BackendObjectId, BackendVersionId, KeyId, RepositoryId, RetentionPolicy};
use serde::{Deserialize, Serialize};

const MAX_FORMAT_ROOT_BYTES: usize = 1024 * 1024;
use super::{cbor, wire};

/// Reference to an encrypted v2 format-root object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V2FormatRef {
    /// Monotonic format generation.
    pub generation: u64,
    /// Public digest of the encrypted format envelope.
    pub digest: String,
    /// Backend object storing the encrypted format envelope.
    pub object_id: BackendObjectId,
    /// Provider version ID when exact-version reads are required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<BackendVersionId>,
}

/// Full keyring envelope reference recorded in the encrypted v2 format root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V2KeyringEnvelopeRootRef {
    /// Monotonic keyring-envelope generation.
    pub generation: u64,
    /// Public digest of the encrypted keyring envelope.
    pub digest: String,
    /// Backend object storing the encrypted keyring envelope.
    pub object_id: BackendObjectId,
    /// Provider version ID when exact-version reads are required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<BackendVersionId>,
}

impl V2KeyringEnvelopeRootRef {
    /// Returns the compact commit-header reference for this keyring envelope.
    pub fn commit_ref(&self) -> V2Result<V2KeyringEnvelopeRef> {
        let digest = hex::decode(&self.digest).map_err(|_| V2FormatError::InvalidFormatRoot)?;
        let digest: [u8; 32] = digest
            .try_into()
            .map_err(|_| V2FormatError::InvalidFormatRoot)?;
        Ok(V2KeyringEnvelopeRef {
            object_id: self.object_id.clone(),
            digest,
        })
    }
}

/// Preview v2 format root plaintext before wrapping-key encryption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V2FormatRoot {
    /// Format-root schema version.
    pub format_version: u32,
    /// Repository ID bound into this format root.
    pub repository_id: RepositoryId,
    /// Active encrypted keyring envelope.
    pub active_keyring_envelope_ref: V2KeyringEnvelopeRootRef,
    /// Active commit-signing key ID.
    pub signing_key_id: KeyId,
    /// Selected storage-provider profile.
    pub provider_profile: V2ProviderProfile,
    /// Default retention policy for repository-owned objects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<RetentionPolicy>,
}

impl V2FormatRoot {
    /// Creates a v2 format root for the current preview schema.
    pub fn new(
        repository_id: RepositoryId,
        active_keyring_envelope_ref: V2KeyringEnvelopeRootRef,
        signing_key_id: KeyId,
        provider_profile: V2ProviderProfile,
        retention: Option<RetentionPolicy>,
    ) -> Self {
        Self {
            format_version: 2,
            repository_id,
            active_keyring_envelope_ref,
            signing_key_id,
            provider_profile,
            retention,
        }
    }

    /// Encodes a fixed canonical CBOR format-root schema.
    pub fn to_plaintext_bytes(&self) -> V2Result<Vec<u8>> {
        wire::require(self.format_version == 2)?;
        let mut out = Vec::new();
        cbor::write_array_len(&mut out, 6);
        cbor::write_u64(&mut out, u64::from(self.format_version));
        wire::write_text(&mut out, self.repository_id.as_str(), wire::MAX_WIRE_TEXT)?;
        let keyring = &self.active_keyring_envelope_ref;
        wire::write_envelope_ref(
            &mut out,
            keyring.generation,
            &keyring.digest,
            &keyring.object_id,
            keyring.version_id.as_ref(),
        )?;
        wire::write_text(
            &mut out,
            self.signing_key_id.as_str(),
            wire::MAX_WIRE_KEY_ID,
        )?;
        cbor::write_u64(
            &mut out,
            match self.provider_profile {
                V2ProviderProfile::Dev => 0,
                V2ProviderProfile::AtomicCreate => 1,
                V2ProviderProfile::RetainedVersionObjectLock => 2,
            },
        );
        match self.retention {
            None => cbor::write_null(&mut out),
            Some(policy) => {
                cbor::write_array_len(&mut out, 2);
                cbor::write_u64(
                    &mut out,
                    match policy.mode {
                        rs3_types::RetentionMode::None => 0,
                        rs3_types::RetentionMode::Governance => 1,
                        rs3_types::RetentionMode::Compliance => 2,
                    },
                );
                cbor::write_u64(&mut out, u64::from(policy.retain_days));
            }
        }
        wire::require(out.len() <= MAX_FORMAT_ROOT_BYTES)?;
        Ok(out)
    }

    /// Decodes bounded canonical format metadata and requires exact EOF.
    pub fn from_plaintext_bytes(bytes: &[u8]) -> V2Result<Self> {
        wire::require(bytes.len() <= MAX_FORMAT_ROOT_BYTES)?;
        let mut reader = cbor::Reader::new(bytes);
        wire::require(reader.read_array_len()? == 6 && reader.read_u64()? == 2)?;
        let repository_id = RepositoryId::new(reader.read_text_bounded(wire::MAX_WIRE_TEXT)?)?;
        let (generation, digest, object_id, version_id) = wire::read_envelope_ref(&mut reader)?;
        let active_keyring_envelope_ref = V2KeyringEnvelopeRootRef {
            generation,
            digest,
            object_id,
            version_id,
        };
        let signing_key_id = KeyId::new(reader.read_text_bounded(wire::MAX_WIRE_KEY_ID)?)?;
        let provider_profile = match reader.read_u64()? {
            0 => V2ProviderProfile::Dev,
            1 => V2ProviderProfile::AtomicCreate,
            2 => V2ProviderProfile::RetainedVersionObjectLock,
            _ => return Err(V2FormatError::InvalidFormatRoot),
        };
        let retention = if reader.next_is_null() {
            reader.read_null()?;
            None
        } else {
            wire::require(reader.read_array_len()? == 2)?;
            let mode = match reader.read_u64()? {
                0 => rs3_types::RetentionMode::None,
                1 => rs3_types::RetentionMode::Governance,
                2 => rs3_types::RetentionMode::Compliance,
                _ => return Err(V2FormatError::InvalidFormatRoot),
            };
            let retain_days =
                u32::try_from(reader.read_u64()?).map_err(|_| V2FormatError::InvalidFormatRoot)?;
            Some(RetentionPolicy { mode, retain_days })
        };
        wire::require(reader.is_finished())?;
        Ok(Self {
            format_version: 2,
            repository_id,
            active_keyring_envelope_ref,
            signing_key_id,
            provider_profile,
            retention,
        })
    }
}

/// Builds the backend object ID for an encrypted v2 format root.
pub fn v2_format_object_id(generation: u64, digest: &str) -> V2Result<BackendObjectId> {
    BackendObjectId::new(format!("format/{generation:020}-{digest}")).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rs3_types::RetentionMode;

    #[test]
    fn format_root_cbor_preserves_provider_and_retention_duration() {
        for profile in [
            V2ProviderProfile::Dev,
            V2ProviderProfile::AtomicCreate,
            V2ProviderProfile::RetainedVersionObjectLock,
        ] {
            for retention in [
                None,
                Some(RetentionPolicy::new(RetentionMode::None, 0)),
                Some(RetentionPolicy::new(RetentionMode::Governance, 30)),
                Some(RetentionPolicy::new(RetentionMode::Compliance, u32::MAX)),
            ] {
                let root = V2FormatRoot::new(
                    RepositoryId::new("r").expect("repo"),
                    V2KeyringEnvelopeRootRef {
                        generation: 1,
                        digest: "11".repeat(32),
                        object_id: BackendObjectId::new("k").expect("key"),
                        version_id: None,
                    },
                    KeyId::new("s").expect("key"),
                    profile,
                    retention,
                );
                let bytes = root.to_plaintext_bytes().expect("encode");
                let decoded = V2FormatRoot::from_plaintext_bytes(&bytes).expect("decode");
                assert_eq!(decoded, root);
                assert_eq!(
                    decoded.to_plaintext_bytes().expect("canonical bytes"),
                    bytes
                );
                for len in 0..bytes.len() {
                    assert!(V2FormatRoot::from_plaintext_bytes(&bytes[..len]).is_err());
                }
                let mut trailing = bytes;
                trailing.push(0);
                assert!(V2FormatRoot::from_plaintext_bytes(&trailing).is_err());
            }
        }
        assert!(V2FormatRoot::from_plaintext_bytes(b"{}").is_err());
        assert!(
            V2FormatRoot::from_plaintext_bytes(&[0x86, 2, 0x7a, 0xff, 0xff, 0xff, 0xff]).is_err()
        );
    }
}
