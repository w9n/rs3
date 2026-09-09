//! Public repository operation models.

use rs3_types::{LegalHoldStatus, LogicalPath, RetentionPolicy};

/// Options for a trusted repository PUT.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepositoryPutOptions {
    /// Optional client MD5 expectation, checked against repository-computed plaintext.
    pub expected_md5: Option<rs3_types::Md5Digest>,
    /// Optional verified checksum, resolved before trusted metadata is staged.
    pub checksum: Option<crate::UploadChecksum>,
    /// Reject the write if the client-visible key already exists.
    pub create_only: bool,
    /// Optional retention policy to apply to backend objects.
    pub retention: Option<RetentionPolicy>,
    /// Optional legal-hold status to apply to backend objects.
    pub legal_hold: Option<LegalHoldStatus>,
}

/// Options for copying one accepted object within a repository.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct RepositoryCopyOptions {
    /// Optional bounded, unquoted source ETag checked at accepted source capture.
    pub source_if_match: Option<String>,
}

impl std::fmt::Debug for RepositoryCopyOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RepositoryCopyOptions")
            .field("source_if_match_present", &self.source_if_match.is_some())
            .finish()
    }
}

impl RepositoryCopyOptions {
    pub(crate) fn validate(&self) -> crate::Result<()> {
        if self.source_if_match.as_ref().is_some_and(|value| {
            value.is_empty()
                || value.len() > 128
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && byte != b'"')
        }) {
            return Err(crate::RepositoryError::InvalidCopyOptions);
        }
        Ok(())
    }
}

/// Metadata returned for a client-visible object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryObjectMetadata {
    /// Accepted plaintext ETag stored inside authenticated encryption.
    pub etag: rs3_types::ObjectEtag,
    /// Verified plaintext checksum stored inside authenticated encryption.
    pub checksum: Option<rs3_types::ObjectChecksum>,
    /// Client-visible key inside the trusted boundary.
    pub key: LogicalPath,
    /// Client-visible content length.
    pub content_len: u64,
    /// Last modification timestamp in milliseconds since the Unix epoch.
    pub modified_at_ms: i64,
    /// Effective retention policy, if known.
    pub retention: Option<RetentionPolicy>,
    /// Effective legal-hold status, if known.
    pub legal_hold: Option<LegalHoldStatus>,
}

/// Entry returned from trusted namespace listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryListEntry {
    /// Accepted plaintext ETag, independent of operation identity.
    pub etag: rs3_types::ObjectEtag,
    /// Client-visible key inside the trusted boundary.
    pub key: LogicalPath,
    /// Client-visible content length.
    pub content_len: u64,
    /// Last modification timestamp in milliseconds since the Unix epoch.
    pub modified_at_ms: i64,
}

/// Result of a logical delete operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeleteOutcome {
    /// What happened to the backend payload object.
    pub physical: PhysicalDeleteOutcome,
}

/// Physical delete result after a namespace tombstone was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhysicalDeleteOutcome {
    /// The backend object was removed.
    Removed,
    /// The backend object is still retained by provider policy.
    Retained,
    /// The backend object was already gone.
    AlreadyGone,
}
