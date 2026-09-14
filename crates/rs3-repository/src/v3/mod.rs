//! Repository format v3 primitives.
//!
//! This module contains the strict, preview-scoped v3 commit-key and commit
//! header implementation. It deliberately starts at the wire-format boundary:
//! writers and readers use these helpers so ambiguous object-store behavior
//! fails closed before repository state is trusted.

pub(super) use rs3_types::cbor;
mod commit;
mod coordinator;
mod error;
mod format;
#[cfg(feature = "fuzzing")]
pub mod fuzzing;
mod index_root;
mod index_run;
mod maintenance;
mod payload_cache;
mod payload_pack;
mod provider;
mod recovery;
mod repository;
mod service;
mod standalone;

#[cfg(test)]
mod tests;

pub use commit::{
    V3_COMMIT_CONTENT_TYPE, V3_COMMIT_MAGIC, V3_COMMIT_RANDOM_ID_B64_LEN, V3_COMMIT_RANDOM_ID_LEN,
    V3_DIGEST_LEN, V3_FORMAT_VERSION, V3_HEADER_META_LEN, V3_MAX_COMMIT_SECTIONS,
    V3_MAX_HEADER_SIZE, V3_MIN_READER_VERSION, V3_SECTION_FLAG_COMPRESSED,
    V3_SECTION_FLAG_MUST_UNDERSTAND, V3_SIGNATURE_LEN, V3Algorithms, V3CommitHeader, V3CommitKey,
    V3CommitKind, V3CommitParentRef, V3CommitSelfRef, V3KeyringEnvelopeRef, V3ParsedCommit,
    V3ParsedCommitHeader, V3SectionDescriptor, V3SectionType, body_digest_for_v3_sections,
    digest_v3_section, generate_v3_commit_key, parse_v3_commit_header, parse_v3_commit_object,
};
pub use coordinator::{
    V3_INDEX_COMPACTION_PAUSE_RUNS, V3_INDEX_COMPACTION_REQUEST_RUNS, V3CommitCoordinator,
    V3CommitCoordinatorStatus, V3CommittedPut, V3MaintenanceWindow,
};
pub use error::{V3ErrorClass, V3FormatError, V3Result};
pub use format::{V3FormatRef, V3FormatRoot, V3KeyringEnvelopeRootRef, v3_format_object_id};
pub use index_root::{
    V3_INDEX_ROOT_FIXED_HEADER_BYTES, V3_INDEX_ROOT_ID_LEN, V3_INDEX_ROOT_MAX_BYTES,
    V3_INDEX_ROOT_MAX_LEVEL, V3_INDEX_ROOT_MAX_RUNS, V3_INDEX_ROOT_MAX_TOTAL_MUTATIONS,
    V3_INDEX_ROOT_MAX_TOTAL_RUN_BYTES, V3EmbeddedIndexRunLocation, V3IndexRoot, V3IndexRootClaims,
    V3IndexRootId, V3IndexRootRunRef, V3SealedIndexRoot, open_v3_index_root, seal_v3_index_root,
};
pub use index_run::{
    V3_INDEX_RUN_FIXED_HEADER_BYTES, V3_INDEX_RUN_ID_LEN, V3_INDEX_RUN_MAX_FRAME_COUNT,
    V3_INDEX_RUN_MAX_FRAME_PLAINTEXT_BYTES, V3_INDEX_RUN_MAX_OBJECT_BYTES,
    V3IndexRunFrameDescriptor, V3IndexRunHeaderProbe, V3IndexRunId, V3SealedIndexRun,
    V3VerifiedIndexRunDirectory, open_v3_index_run, open_v3_index_run_directory,
    open_v3_index_run_frame, open_v3_index_run_frames, probe_v3_index_run_header,
    seal_v3_index_run,
};
pub use maintenance::{
    DEFAULT_RETENTION_RENEWAL_HORIZON, UnenforcedQuiescedMaintenanceGuard,
    V3_MAINTENANCE_PLAN_STALE_REASON, V3FullGcApplyOptions, V3FullGcApplyReport,
    V3FullGcDryRunOptions, V3FullGcDryRunReport, V3FullGcPlanPreview, V3MaintenanceBudgets,
    V3MaintenanceCancellation, V3MaintenanceGuard, V3MaintenancePlanCost, V3MaintenanceReport,
    V3OrphanCandidate, V3OrphanGcOptions, V3OrphanGcReport, V3OrphanObjectClass, V3OrphanReport,
    V3QuickMaintenanceOptions,
};
pub(crate) use payload_cache::{V3StreamPayloadCacheIdentity, V3StreamPayloadCarrierCacheIdentity};
pub use payload_pack::{
    V3_PAYLOAD_PACK_ID_LEN, V3_PAYLOAD_PACK_MAX_BYTES, V3_PAYLOAD_PACK_MAX_RECORDS,
    V3_PAYLOAD_PACK_SEGMENT_BYTES, V3OpenedPayloadPackRecordSpan, V3PayloadPackFacts,
    V3PayloadPackId, V3PayloadPackLayout, V3PayloadPackRecord, V3PayloadPackRecordContext,
    V3PayloadPackRecordInput, V3PayloadPackRecordRef, V3PayloadPackRecordSpan, V3SealedPayloadPack,
    open_v3_payload_pack_cached_record_span, open_v3_payload_pack_record,
    open_v3_payload_pack_record_range, open_v3_payload_pack_record_span,
    open_v3_payload_pack_record_span_with_segments, plan_v3_payload_pack_record_range,
    seal_v3_payload_pack, validate_v3_payload_pack_record_ref,
};
pub use provider::{
    V3ProviderCheckStatus, V3ProviderConformanceCheck, V3ProviderConformanceOptions,
    V3ProviderConformanceReport, V3ProviderProfile, check_v3_provider_conformance,
    required_v3_provider_check_names,
};
pub use recovery::policy::RecoveryPolicy;
pub use repository::{
    DEFAULT_V3_REPLAY_MAX_COMMITS, DEFAULT_V3_REPLAY_MAX_RETAINED_BYTES,
    DEFAULT_V3_REPLAY_MAX_TOTAL_COMMIT_BYTES, DEFAULT_V3_REPLAY_READ_CHUNK_BYTES,
    DEFAULT_V3_STREAM_READ_STALL_TIMEOUT, V3_RESTORE_BUNDLE_SCHEMA, V3AnchorState, V3CommitAnchor,
    V3CommitSection, V3CommitStore, V3CommitStoreOptions, V3CommitWrite, V3MemoryAnchor,
    V3MultipartUpload, V3PreparedGenesis, V3RecoveryBundle, V3ReplayChain, V3ReplayCommit,
    V3ReplayLimits, V3StoredCommit, V3UploadedPart, V3VerifiedMultipartUpload,
    v3_streaming_upload_working_set_bytes,
};
pub use service::{
    V3AuthenticatedReadBody, V3ClientMultipartUpload, V3FullMaintenanceReport,
    V3MultipartSelection, V3RecoveryCursor, V3RecoveryPointInfo, V3RecoveryPointPage,
    V3RecoveryView, V3Repository, V3ResolvedObject,
};

mod recovery_bundle;
mod wire;
pub use recovery_bundle::MAX_RECOVERY_BUNDLE_BYTES;
