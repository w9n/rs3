//! Error taxonomy for repository format v3.

use rs3_crypto::CryptoError;
use rs3_types::TypeError;
use thiserror::Error;

/// High-level class used by v3 operators and conformance checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V3ErrorClass {
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

/// Result alias for v3 format operations.
pub type V3Result<T> = std::result::Result<T, V3FormatError>;

/// Errors returned by v3 commit-format and protocol-boundary checks.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum V3FormatError {
    /// Plaintext did not match the declared Content-MD5.
    #[error("content MD5 did not match request body")]
    ContentMd5Mismatch,
    /// A random commit key did not have the required shape.
    #[error("invalid v03 commit key")]
    InvalidCommitKey,
    /// The fixed commit meta header was shorter than required.
    #[error("v03 commit fixed header is truncated")]
    TruncatedHeader,
    /// The object body ended before declared sections could be read.
    #[error("v03 commit body is truncated")]
    TruncatedBody,
    /// The format version is not supported by this reader.
    #[error("unsupported v03 commit format version")]
    UnsupportedFormatVersion,
    /// The commit requires a newer reader than this implementation.
    #[error("unsupported v03 commit reader version")]
    UnsupportedReaderVersion,
    /// The commit uses capability bits outside the v03 mask.
    #[error("unsupported v03 commit capability flags")]
    UnsupportedCapabilities,
    /// Reserved fixed-header bytes were nonzero.
    #[error("nonzero v03 commit reserved bytes")]
    NonzeroReserved,
    /// The CBOR header is larger than v03 permits.
    #[error("v03 commit header is too large")]
    HeaderTooLarge,
    /// The header CBOR could not be decoded as the v03 structure.
    #[error("malformed v03 commit CBOR header")]
    MalformedCbor,
    /// The header CBOR decoded but was not canonical.
    #[error("non-canonical v03 commit CBOR header")]
    NonCanonicalCbor,
    /// A required header field was absent.
    #[error("missing v03 commit header field")]
    MissingHeaderField,
    /// A header field had an invalid type, length, or value.
    #[error("invalid v03 commit header field")]
    InvalidHeaderField,
    /// Signed ancestry or the bounded publication clock is invalid.
    #[error("invalid v03 publication time")]
    InvalidPublicationTime,
    /// Authenticated recovery history is missing, malformed or inconsistent.
    #[error("invalid v03 recovery history")]
    InvalidRecoveryHistory,
    /// Recovery history cannot grow without violating fixed resource bounds.
    #[error("v03 recovery history capacity exceeded")]
    RecoveryHistoryCapacity,
    /// Recovery policy is invalid or would silently discard accepted promises.
    #[error("invalid v03 recovery policy")]
    InvalidRecoveryPolicy,
    /// The header algorithm identifiers do not exactly match v03.
    #[error("invalid v03 commit algorithm identifiers")]
    InvalidAlgorithms,
    /// The signed self commit key does not match the object key read.
    #[error("v03 commit self key mismatch")]
    SelfKeyMismatch,
    /// The header signature did not verify.
    #[error("v03 commit signature verification failed")]
    SignatureVerification,
    /// Section offsets, lengths, or physical coverage were invalid.
    #[error("invalid v03 commit section layout")]
    SectionBounds,
    /// A streamed object exceeded the configured maximum plaintext length.
    #[error("v03 streamed object exceeds configured maximum size")]
    ObjectTooLarge,
    /// A streamed object body did not match its declared plaintext length.
    #[error("v03 streamed object length did not match the declared size")]
    ObjectLengthMismatch,
    /// Verified recovery would exceed a configured chain or byte budget.
    #[error("v03 recovery replay budget exceeded")]
    ReplayBudgetExceeded,
    /// A streamed object body could not be read from the caller.
    #[error("v03 streamed object body read failed")]
    ObjectBodyReadFailed,
    /// A section marked must-understand is not supported by this reader.
    #[error("unsupported v03 commit section")]
    UnsupportedSection,
    /// A section set reserved flag bits.
    #[error("reserved v03 commit section flags")]
    ReservedSectionFlags,
    /// The declared body digest does not match the declared sections.
    #[error("v03 commit body digest mismatch")]
    BodyDigestMismatch,
    /// A section's stored bytes do not match its signed descriptor digest.
    #[error("v03 commit section digest mismatch")]
    SectionDigestMismatch,
    /// A framed index run has an invalid, truncated, or ambiguous encoding.
    #[error("invalid v03 framed index run")]
    InvalidIndexRun,
    /// A framed index run exceeds a fixed hostile-input limit.
    #[error("v03 framed index run limit exceeded")]
    IndexRunLimitExceeded,
    /// An index-root catalog has an invalid, truncated, or ambiguous encoding.
    #[error("invalid v03 index root")]
    InvalidIndexRoot,
    /// An index-root catalog exceeds a fixed hostile-input limit.
    #[error("v03 index root limit exceeded")]
    IndexRootLimitExceeded,
    /// A compact payload pack has an invalid, truncated, or ambiguous encoding.
    #[error("invalid v03 payload pack")]
    InvalidPayloadPack,
    /// A compact payload pack exceeds a fixed hostile-input limit.
    #[error("v03 payload pack limit exceeded")]
    PayloadPackLimitExceeded,
    /// A cryptographic operation other than verification failed.
    #[error("v03 cryptographic operation failed")]
    CryptoOperation,
    /// Strong type construction failed.
    #[error("v03 type validation failed")]
    TypeValidation,
    /// The operating system CSPRNG was unavailable.
    #[error("v03 random commit id generation failed")]
    RandomnessUnavailable,
    /// The v3 commit anchor could not be read.
    #[error("v03 commit anchor read failed")]
    AnchorReadFailed,
    /// The v3 commit anchor could not be advanced.
    #[error("v03 commit anchor advance failed")]
    AnchorAdvanceFailed,
    /// An attempted advance could not be reconciled with the exact trusted state.
    #[error("v03 anchor publication outcome requires recovery")]
    AnchorReconciliationRequired,
    /// The v3 commit anchor was missing for an operation that requires it.
    #[error("v03 commit anchor is missing")]
    MissingAnchor,
    /// The v3 commit anchor no longer matched the expected state.
    #[error("v03 commit anchor is stale")]
    StaleAnchor,
    /// An unfinished genesis needs a durably reserved physical upload attempt.
    #[error("v03 bootstrap requires an upload allowance")]
    BootstrapUploadRequired,
    /// The backing object store failed a v3 operation.
    #[error("v03 storage operation failed")]
    StorageOperationFailed,
    /// The v3 format root could not be encoded or decoded.
    #[error("v03 format root encoding failed")]
    FormatEncoding,
    /// The v3 format root is missing or invalid.
    #[error("invalid v03 format root")]
    InvalidFormatRoot,
    /// A provider-profile conformance check failed.
    #[error("v03 provider conformance failed")]
    ProviderProfileFailed,
    /// Normal DR cannot proceed without a weak-subjectivity floor.
    #[error("v03 recovery bundle or weak-subjectivity floor is required")]
    RecoveryBundleRequired,
    /// The requested operation is only available as explicit rollback-unsafe DR.
    #[error("v03 rollback-unsafe disaster recovery mode is required")]
    RollbackUnsafeDr,
    /// Destructive maintenance requires a fenced lease or explicit quiesced mode.
    #[error("v03 maintenance access guard is required")]
    MaintenanceAccessRequired,
    /// Destructive maintenance plan exceeds an operator-supplied budget.
    #[error("v03 maintenance budget exceeded")]
    MaintenanceBudgetExceeded,
    /// The exact private maintenance plan no longer matches the reviewed digest.
    #[error("maintenance plan digest is stale: repository state moved since the dry run")]
    MaintenancePlanChanged,
    /// Destructive orphan GC requires a safer minimum age.
    #[error("v03 orphan GC minimum age is below the production floor")]
    OrphanGcMinAgeTooLow,
    /// Destructive maintenance stopped cleanly at a mutation boundary.
    #[error("v03 maintenance run was cancelled")]
    MaintenanceCancelled,
}

impl V3FormatError {
    /// Returns the operator-facing class for this error.
    pub const fn class(&self) -> V3ErrorClass {
        match self {
            Self::RandomnessUnavailable
            | Self::ObjectTooLarge
            | Self::ObjectLengthMismatch
            | Self::ObjectBodyReadFailed
            | Self::ContentMd5Mismatch
            | Self::MaintenanceCancelled => V3ErrorClass::RetryableClient,
            Self::ProviderProfileFailed => V3ErrorClass::ProviderConformance,
            Self::RecoveryBundleRequired => V3ErrorClass::OperatorActionRequired,
            Self::RollbackUnsafeDr => V3ErrorClass::RollbackUnsafeDr,
            Self::MaintenanceAccessRequired
            | Self::MaintenanceBudgetExceeded
            | Self::MaintenancePlanChanged
            | Self::OrphanGcMinAgeTooLow
            | Self::ReplayBudgetExceeded
            | Self::RecoveryHistoryCapacity
            | Self::InvalidRecoveryPolicy => V3ErrorClass::OperatorActionRequired,
            Self::InvalidCommitKey
            | Self::TruncatedHeader
            | Self::TruncatedBody
            | Self::UnsupportedFormatVersion
            | Self::UnsupportedReaderVersion
            | Self::UnsupportedCapabilities
            | Self::NonzeroReserved
            | Self::HeaderTooLarge
            | Self::MalformedCbor
            | Self::NonCanonicalCbor
            | Self::MissingHeaderField
            | Self::InvalidHeaderField
            | Self::InvalidPublicationTime
            | Self::InvalidRecoveryHistory
            | Self::InvalidAlgorithms
            | Self::SelfKeyMismatch
            | Self::SignatureVerification
            | Self::SectionBounds
            | Self::UnsupportedSection
            | Self::ReservedSectionFlags
            | Self::BodyDigestMismatch
            | Self::SectionDigestMismatch
            | Self::InvalidIndexRun
            | Self::IndexRunLimitExceeded
            | Self::InvalidIndexRoot
            | Self::IndexRootLimitExceeded
            | Self::InvalidPayloadPack
            | Self::PayloadPackLimitExceeded
            | Self::CryptoOperation
            | Self::TypeValidation
            | Self::AnchorReadFailed
            | Self::AnchorAdvanceFailed
            | Self::AnchorReconciliationRequired
            | Self::MissingAnchor
            | Self::StaleAnchor
            | Self::BootstrapUploadRequired
            | Self::StorageOperationFailed
            | Self::FormatEncoding
            | Self::InvalidFormatRoot => V3ErrorClass::FailClosedSecurity,
        }
    }
}

impl From<CryptoError> for V3FormatError {
    fn from(_: CryptoError) -> Self {
        Self::CryptoOperation
    }
}

impl From<TypeError> for V3FormatError {
    fn from(_: TypeError) -> Self {
        Self::TypeValidation
    }
}

impl From<rs3_types::cbor::CborError> for V3FormatError {
    fn from(_: rs3_types::cbor::CborError) -> Self {
        Self::MalformedCbor
    }
}
