//! Repository format v2 primitives.
//!
//! This module contains the strict, preview-scoped v2 commit-key and commit
//! header implementation. It deliberately starts at the wire-format boundary:
//! writers and readers use these helpers so ambiguous object-store behavior
//! fails closed before repository state is trusted.

mod cbor;
mod commit;
mod coordinator;
mod error;
mod format;
mod maintenance;
mod provider;
mod repository;
mod service;

#[cfg(test)]
mod tests;

pub use commit::{
    V2_COMMIT_CONTENT_TYPE, V2_COMMIT_MAGIC, V2_COMMIT_RANDOM_ID_B64_LEN, V2_COMMIT_RANDOM_ID_LEN,
    V2_DIGEST_LEN, V2_FORMAT_VERSION, V2_HEADER_META_LEN, V2_MAX_HEADER_SIZE,
    V2_MIN_READER_VERSION, V2_SECTION_FLAG_COMPRESSED, V2_SECTION_FLAG_MUST_UNDERSTAND,
    V2_SIGNATURE_LEN, V2_SUPPORTED_CAPABILITY_FLAGS, V2Algorithms, V2CommitHeader, V2CommitKey,
    V2CommitParentRef, V2CommitSelfRef, V2KeyringEnvelopeRef, V2ParsedCommit, V2ParsedCommitHeader,
    V2SectionDescriptor, V2SectionType, V2UploadMode, body_digest_for_v2_sections,
    generate_v2_commit_key, parse_v2_commit_header, parse_v2_commit_object,
};
pub use coordinator::{V2CommitCoordinator, V2CommittedPut};
pub use error::{V2ErrorClass, V2FormatError, V2Result};
pub use format::{
    V2FormatRef, V2FormatRoot, V2KeyringEnvelopeRootRef, V2MaintenanceConfig, v2_format_object_id,
};
pub use maintenance::{
    UnenforcedQuiescedMaintenanceGuard, V2FullGcApplyOptions, V2FullGcApplyReport,
    V2FullGcDryRunOptions, V2FullGcDryRunReport, V2MaintenanceBudgets, V2MaintenanceGuard,
    V2MaintenancePlanCost, V2MaintenanceReport, V2OrphanCandidate, V2OrphanGcOptions,
    V2OrphanGcReport, V2OrphanReport,
};
pub use provider::{
    V2ProviderCheckStatus, V2ProviderConformanceCheck, V2ProviderConformanceOptions,
    V2ProviderConformanceReport, V2ProviderProfile, check_v2_provider_conformance,
};
pub use repository::{
    V2AnchorState, V2CommitAnchor, V2CommitChain, V2CommitSection, V2CommitStore,
    V2CommitStoreOptions, V2CommitWrite, V2MemoryAnchor, V2RecoveryBundle, V2StoredCommit,
};
pub use service::V2Repository;
