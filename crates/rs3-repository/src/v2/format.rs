//! v2 format-root metadata.

use super::commit::V2KeyringEnvelopeRef;
use super::error::{V2FormatError, V2Result};
use super::provider::V2ProviderProfile;
use rs3_types::{BackendObjectId, BackendVersionId, KeyId, RepositoryId, RetentionPolicy};
use serde::{Deserialize, Serialize};

const FORMAT_ROOT_DOMAIN: &[u8] = b"rs3:format-root:v2-preview\n";

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
    /// Maintenance configuration.
    pub maintenance: V2MaintenanceConfig,
}

/// v2 maintenance thresholds recorded in the format root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V2MaintenanceConfig {
    /// Snapshot threshold by anchored commit count.
    pub snapshot_every_commits: u64,
    /// Snapshot threshold by wall-clock age in days.
    pub snapshot_every_days: u32,
}

impl Default for V2MaintenanceConfig {
    fn default() -> Self {
        Self {
            snapshot_every_commits: 1_000,
            snapshot_every_days: 7,
        }
    }
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
            maintenance: V2MaintenanceConfig::default(),
        }
    }

    /// Encodes this format root into domain-separated plaintext bytes.
    pub fn to_plaintext_bytes(&self) -> V2Result<Vec<u8>> {
        let mut bytes = FORMAT_ROOT_DOMAIN.to_vec();
        serde_json::to_writer(&mut bytes, self).map_err(|_| V2FormatError::FormatEncoding)?;
        Ok(bytes)
    }

    /// Decodes domain-separated format-root plaintext.
    pub fn from_plaintext_bytes(bytes: &[u8]) -> V2Result<Self> {
        let Some(payload) = bytes.strip_prefix(FORMAT_ROOT_DOMAIN) else {
            return Err(V2FormatError::InvalidFormatRoot);
        };
        let root: Self =
            serde_json::from_slice(payload).map_err(|_| V2FormatError::FormatEncoding)?;
        if root.format_version != 2 {
            return Err(V2FormatError::InvalidFormatRoot);
        }
        Ok(root)
    }
}

/// Builds the backend object ID for an encrypted v2 format root.
pub fn v2_format_object_id(generation: u64, digest: &str) -> V2Result<BackendObjectId> {
    BackendObjectId::new(format!("format/{generation:020}-{digest}")).map_err(Into::into)
}
