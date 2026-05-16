//! Error taxonomy for repository format v2.

use rs3_crypto::CryptoError;
use rs3_types::TypeError;
use thiserror::Error;

/// High-level class used by v2 operators and conformance checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V2ErrorClass {
    /// The caller may retry with a fresh attempt and no operator action.
    RetryableClient,
    /// The repository must not open, advance, or acknowledge the operation.
    FailClosedSecurity,
    /// The selected storage-provider profile did not pass conformance.
    ProviderConformance,
    /// Human recovery, IAM, retention, or orphan review is required.
    OperatorActionRequired,
    /// Only the explicitly named rollback-unsafe DR mode can proceed.
    RollbackUnsafeDr,
}

/// Result alias for v2 format operations.
pub type V2Result<T> = std::result::Result<T, V2FormatError>;

/// Errors returned by v2 commit-format and protocol-boundary checks.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum V2FormatError {
    /// A random commit key did not have the required shape.
    #[error("invalid v2 commit key")]
    InvalidCommitKey,
    /// The fixed commit meta header was shorter than required.
    #[error("v2 commit fixed header is truncated")]
    TruncatedHeader,
    /// The object body ended before declared sections could be read.
    #[error("v2 commit body is truncated")]
    TruncatedBody,
    /// The format version is not supported by this reader.
    #[error("unsupported v2 commit format version")]
    UnsupportedFormatVersion,
    /// The commit requires a newer reader than this implementation.
    #[error("unsupported v2 commit reader version")]
    UnsupportedReaderVersion,
    /// The commit uses capability bits outside the v01 mask.
    #[error("unsupported v2 commit capability flags")]
    UnsupportedCapabilities,
    /// The fixed header declared an unknown upload mode.
    #[error("unsupported v2 commit upload mode")]
    UnsupportedUploadMode,
    /// Reserved fixed-header bytes were nonzero.
    #[error("nonzero v2 commit reserved bytes")]
    NonzeroReserved,
    /// The CBOR header is larger than v01 permits.
    #[error("v2 commit header is too large")]
    HeaderTooLarge,
    /// The fixed header or CBOR header digest does not match.
    #[error("v2 commit header digest mismatch")]
    HeaderDigestMismatch,
    /// The header CBOR could not be decoded as the v01 structure.
    #[error("malformed v2 commit CBOR header")]
    MalformedCbor,
    /// The header CBOR decoded but was not canonical.
    #[error("non-canonical v2 commit CBOR header")]
    NonCanonicalCbor,
    /// A required header field was absent.
    #[error("missing v2 commit header field")]
    MissingHeaderField,
    /// A header field had an invalid type, length, or value.
    #[error("invalid v2 commit header field")]
    InvalidHeaderField,
    /// The header algorithm identifiers do not exactly match v01.
    #[error("invalid v2 commit algorithm identifiers")]
    InvalidAlgorithms,
    /// The signed self commit key does not match the object key read.
    #[error("v2 commit self key mismatch")]
    SelfKeyMismatch,
    /// The header signature did not verify.
    #[error("v2 commit signature verification failed")]
    SignatureVerification,
    /// Section offsets, lengths, or physical coverage were invalid.
    #[error("invalid v2 commit section layout")]
    SectionBounds,
    /// A section marked must-understand is not supported by this reader.
    #[error("unsupported v2 commit section")]
    UnsupportedSection,
    /// A section set reserved flag bits.
    #[error("reserved v2 commit section flags")]
    ReservedSectionFlags,
    /// The declared body digest does not match the declared sections.
    #[error("v2 commit body digest mismatch")]
    BodyDigestMismatch,
    /// A cryptographic operation other than verification failed.
    #[error("v2 cryptographic operation failed")]
    CryptoOperation,
    /// Strong type construction failed.
    #[error("v2 type validation failed")]
    TypeValidation,
    /// The operating system CSPRNG was unavailable.
    #[error("v2 random commit id generation failed")]
    RandomnessUnavailable,
    /// The v2 commit anchor could not be read.
    #[error("v2 commit anchor read failed")]
    AnchorReadFailed,
    /// The v2 commit anchor could not be advanced.
    #[error("v2 commit anchor advance failed")]
    AnchorAdvanceFailed,
    /// The v2 commit anchor was missing for an operation that requires it.
    #[error("v2 commit anchor is missing")]
    MissingAnchor,
    /// The v2 commit anchor no longer matched the expected state.
    #[error("v2 commit anchor is stale")]
    StaleAnchor,
    /// The backing object store failed a v2 operation.
    #[error("v2 storage operation failed")]
    StorageOperationFailed,
    /// The v2 format root could not be encoded or decoded.
    #[error("v2 format root encoding failed")]
    FormatEncoding,
    /// The v2 format root is missing or invalid.
    #[error("invalid v2 format root")]
    InvalidFormatRoot,
    /// A provider-profile conformance check failed.
    #[error("v2 provider conformance failed")]
    ProviderProfileFailed,
    /// Normal DR cannot proceed without a weak-subjectivity floor.
    #[error("v2 recovery bundle or weak-subjectivity floor is required")]
    RecoveryBundleRequired,
    /// The requested operation is only available as explicit rollback-unsafe DR.
    #[error("v2 rollback-unsafe disaster recovery mode is required")]
    RollbackUnsafeDr,
}

impl V2FormatError {
    /// Returns the operator-facing class for this error.
    pub const fn class(&self) -> V2ErrorClass {
        match self {
            Self::RandomnessUnavailable => V2ErrorClass::RetryableClient,
            Self::ProviderProfileFailed => V2ErrorClass::ProviderConformance,
            Self::RecoveryBundleRequired => V2ErrorClass::OperatorActionRequired,
            Self::RollbackUnsafeDr => V2ErrorClass::RollbackUnsafeDr,
            Self::InvalidCommitKey
            | Self::TruncatedHeader
            | Self::TruncatedBody
            | Self::UnsupportedFormatVersion
            | Self::UnsupportedReaderVersion
            | Self::UnsupportedCapabilities
            | Self::UnsupportedUploadMode
            | Self::NonzeroReserved
            | Self::HeaderTooLarge
            | Self::HeaderDigestMismatch
            | Self::MalformedCbor
            | Self::NonCanonicalCbor
            | Self::MissingHeaderField
            | Self::InvalidHeaderField
            | Self::InvalidAlgorithms
            | Self::SelfKeyMismatch
            | Self::SignatureVerification
            | Self::SectionBounds
            | Self::UnsupportedSection
            | Self::ReservedSectionFlags
            | Self::BodyDigestMismatch
            | Self::CryptoOperation
            | Self::TypeValidation
            | Self::AnchorReadFailed
            | Self::AnchorAdvanceFailed
            | Self::MissingAnchor
            | Self::StaleAnchor
            | Self::StorageOperationFailed
            | Self::FormatEncoding
            | Self::InvalidFormatRoot => V2ErrorClass::FailClosedSecurity,
        }
    }
}

impl From<CryptoError> for V2FormatError {
    fn from(_: CryptoError) -> Self {
        Self::CryptoOperation
    }
}

impl From<TypeError> for V2FormatError {
    fn from(_: TypeError) -> Self {
        Self::TypeValidation
    }
}
