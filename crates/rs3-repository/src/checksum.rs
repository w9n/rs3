//! One-shot handoff from a verified plaintext reader to trusted publication.

use crate::{RepositoryError, Result};
use rs3_types::{ChecksumAlgorithm, ObjectChecksum};
use std::sync::{Arc, OnceLock};

/// Preview checksum handoff for writes whose verified trailer arrives at EOF.
///
/// The trusted transport adapter fills this only after consuming and validating
/// the complete request body. Publication refuses an unresolved handoff. Clones
/// share the same immutable result; this never stores a client path or body.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UploadChecksum(Arc<OnceLock<ObjectChecksum>>);

impl UploadChecksum {
    /// Creates an unresolved checksum handoff for a streaming request.
    pub fn pending() -> Self {
        Self::default()
    }

    /// Wraps a checksum already verified by the trusted caller.
    pub fn verified(checksum: ObjectChecksum) -> Self {
        Self(Arc::new(OnceLock::from(checksum)))
    }

    /// Installs the one verified result. A second installation is an error.
    pub fn finish(&self, checksum: ObjectChecksum) -> Result<()> {
        self.0
            .set(checksum)
            .map_err(|_| RepositoryError::ObjectChecksumUnavailable)
    }

    /// Returns the verified result, refusing publication before verified EOF.
    pub fn get(&self) -> Result<ObjectChecksum> {
        self.0
            .get()
            .cloned()
            .ok_or(RepositoryError::ObjectChecksumUnavailable)
    }
}

/// Checksum construction captured before a multipart upload accepts any parts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultipartChecksumKind {
    /// Combine CRC values over the selected plaintext byte stream.
    FullObject,
    /// Hash the ordered raw part checksums; count is fixed at completion.
    Composite,
}

/// Validated, immutable checksum algorithm and construction for one upload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MultipartChecksumPolicy {
    algorithm: ChecksumAlgorithm,
    kind: MultipartChecksumKind,
}

impl MultipartChecksumPolicy {
    /// Rejects SHA full-object multipart and CRC64 composite construction.
    pub fn new(
        algorithm: ChecksumAlgorithm,
        kind: MultipartChecksumKind,
    ) -> std::result::Result<Self, rs3_types::ChecksumError> {
        if matches!(
            (algorithm, kind),
            (
                ChecksumAlgorithm::Sha1 | ChecksumAlgorithm::Sha256,
                MultipartChecksumKind::FullObject
            ) | (
                ChecksumAlgorithm::Crc64Nvme,
                MultipartChecksumKind::Composite
            )
        ) {
            return Err(rs3_types::ChecksumError::UnsupportedType);
        }
        Ok(Self { algorithm, kind })
    }

    /// Captured algorithm required for every verified part.
    pub fn algorithm(self) -> ChecksumAlgorithm {
        self.algorithm
    }

    /// Captured construction used for the final selected result.
    pub fn kind(self) -> MultipartChecksumKind {
        self.kind
    }
}
