//! Shared strongly typed identifiers and policy types.

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Result alias for type validation.
pub type Result<T> = std::result::Result<T, TypeError>;

/// Errors returned when constructing strongly typed values.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TypeError {
    /// The provided value was empty or all whitespace.
    #[error("{kind} cannot be empty")]
    Empty {
        /// Human-readable type name.
        kind: &'static str,
    },
}

fn validate_non_empty(kind: &'static str, value: String) -> Result<String> {
    if value.trim().is_empty() {
        Err(TypeError::Empty { kind })
    } else {
        Ok(value)
    }
}

/// Public S3 bucket name presented to clients.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PublicBucket(String);

impl PublicBucket {
    /// Creates a validated public bucket name.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        validate_non_empty("public bucket", value.into()).map(Self)
    }

    /// Returns the bucket as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PublicBucket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Plaintext logical path inside the trusted boundary.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LogicalPath(String);

impl LogicalPath {
    /// Creates a validated logical path.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        validate_non_empty("logical path", value.into()).map(Self)
    }

    /// Returns the logical path as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LogicalPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Secret-keyed lookup token for a logical path.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlindIndexKey(String);

impl BlindIndexKey {
    /// Creates a validated blind index key.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        validate_non_empty("blind index key", value.into()).map(Self)
    }

    /// Returns the key as an encoded string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BlindIndexKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Secret-keyed lookup token for a client-visible prefix.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PrefixToken(String);

impl PrefixToken {
    /// Creates a validated prefix token.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        validate_non_empty("prefix token", value.into()).map(Self)
    }

    /// Returns the token as an encoded string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PrefixToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Opaque object identifier used by the backend store.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BackendObjectId(String);

impl BackendObjectId {
    /// Creates a validated backend object identifier.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        validate_non_empty("backend object id", value.into()).map(Self)
    }

    /// Returns the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BackendObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Identifier for an encrypted manifest.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ManifestId(String);

impl ManifestId {
    /// Creates a validated manifest identifier.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        validate_non_empty("manifest id", value.into()).map(Self)
    }

    /// Returns the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ManifestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Identifier for a signed checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CheckpointId(String);

impl CheckpointId {
    /// Creates a validated checkpoint identifier.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        validate_non_empty("checkpoint id", value.into()).map(Self)
    }

    /// Returns the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CheckpointId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Identifier for a repository root.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RepositoryId(String);

impl RepositoryId {
    /// Creates a validated repository identifier.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        validate_non_empty("repository id", value.into()).map(Self)
    }

    /// Returns the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RepositoryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Identifier for a cryptographic key inside a repository keyring.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct KeyId(String);

impl KeyId {
    /// Creates a validated key identifier.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        validate_non_empty("key id", value.into()).map(Self)
    }

    /// Returns the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Purpose assigned to a keyring key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum KeyPurpose {
    /// Namespace PRF key for blind path and prefix lookup tokens.
    Namespace,
    /// Content encryption or data-key wrapping key.
    Content,
    /// Manifest, index, and metadata encryption key.
    Metadata,
    /// Checkpoint signing or verification key.
    CheckpointSigning,
}

/// Lifecycle status for a keyring key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum KeyStatus {
    /// Primary key used for new writes for its purpose.
    Primary,
    /// Enabled old key accepted for read, verify, or lookup.
    Enabled,
    /// Temporarily disabled key not used for reads or writes.
    Disabled,
    /// Retired key kept only for historical metadata.
    Retired,
}

impl KeyStatus {
    /// Returns true when the key can be used for read, verify, or lookup.
    pub const fn is_enabled_for_lookup(self) -> bool {
        matches!(self, Self::Primary | Self::Enabled)
    }

    /// Returns true when the key is primary for new writes.
    pub const fn is_primary(self) -> bool {
        matches!(self, Self::Primary)
    }
}

/// Public metadata for a keyring key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyDescriptor {
    /// Stable key identifier recorded in repository metadata.
    pub id: KeyId,
    /// Cryptographic purpose of the key.
    pub purpose: KeyPurpose,
    /// Algorithm or provider-specific suite identifier.
    pub algorithm: String,
    /// Key lifecycle state.
    pub status: KeyStatus,
    /// Creation timestamp in milliseconds since the Unix epoch.
    pub created_at_ms: i64,
    /// Optional lower validity bound in milliseconds since the Unix epoch.
    pub not_before_ms: Option<i64>,
    /// Optional upper validity bound in milliseconds since the Unix epoch.
    pub not_after_ms: Option<i64>,
    /// Optional hex-encoded public verification key for asymmetric keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// Optional external KMS key URI when material is provider-managed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_kms_uri: Option<String>,
}

/// Monotonic checkpoint sequence.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct Sequence(u64);

impl Sequence {
    /// Zero sequence used before the first checkpoint.
    pub const ZERO: Self = Self(0);

    /// Creates a sequence from a raw integer.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw integer value.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the next sequence if it does not overflow.
    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

/// Object retention mode requested for protected backend objects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetentionMode {
    /// No object-store retention is requested.
    None,
    /// Governance retention, bypassable only with special provider permission.
    Governance,
    /// Compliance retention, not normally bypassable before expiry.
    Compliance,
}

/// Legal-hold status for backend object versions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LegalHoldStatus {
    /// No provider legal hold is requested.
    Off,
    /// Provider legal hold is requested and should block deletion.
    On,
}

/// Retention policy for backend object versions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Retention mode.
    pub mode: RetentionMode,
    /// Number of days to retain object versions.
    pub retain_days: u32,
}

impl RetentionPolicy {
    /// Creates a retention policy.
    pub const fn new(mode: RetentionMode, retain_days: u32) -> Self {
        Self { mode, retain_days }
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyId, KeyStatus, PrefixToken, PublicBucket, Sequence};

    #[test]
    fn rejects_empty_bucket() {
        assert!(PublicBucket::new("   ").is_err());
    }

    #[test]
    fn rejects_empty_prefix_token() {
        assert!(PrefixToken::new("   ").is_err());
    }

    #[test]
    fn advances_sequence() {
        assert_eq!(Sequence::new(41).checked_next(), Some(Sequence::new(42)));
    }

    #[test]
    fn key_status_lookup_state_is_explicit() {
        assert!(KeyStatus::Primary.is_enabled_for_lookup());
        assert!(KeyStatus::Enabled.is_enabled_for_lookup());
        assert!(!KeyStatus::Disabled.is_enabled_for_lookup());
        assert!(!KeyStatus::Retired.is_enabled_for_lookup());
    }

    #[test]
    fn rejects_empty_key_id() {
        assert!(KeyId::new("   ").is_err());
    }
}
