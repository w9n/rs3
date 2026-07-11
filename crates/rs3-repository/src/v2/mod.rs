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
#[cfg(feature = "fuzzing")]
pub mod fuzzing;
mod index_root;
mod index_run;
mod maintenance;
mod payload_pack;
mod provider;
mod repository;
mod service;

#[cfg(test)]
mod tests;

pub use commit::{
    V2_CAPABILITY_COMPACTED_INDEX_RUNS, V2_CAPABILITY_FRAMED_INDEX,
    V2_CAPABILITY_SIGNED_SECTION_DIGESTS, V2_COMMIT_CONTENT_TYPE, V2_COMMIT_MAGIC,
    V2_COMMIT_RANDOM_ID_B64_LEN, V2_COMMIT_RANDOM_ID_LEN, V2_DIGEST_LEN, V2_FORMAT_VERSION,
    V2_HEADER_META_LEN, V2_MAX_COMMIT_SECTIONS, V2_MAX_HEADER_SIZE, V2_MIN_READER_VERSION,
    V2_REQUIRED_CAPABILITY_FLAGS, V2_SECTION_FLAG_COMPRESSED, V2_SECTION_FLAG_MUST_UNDERSTAND,
    V2_SIGNATURE_LEN, V2_SUPPORTED_CAPABILITY_FLAGS, V2Algorithms, V2CommitHeader, V2CommitKey,
    V2CommitKind, V2CommitParentRef, V2CommitSelfRef, V2KeyringEnvelopeRef, V2ParsedCommit,
    V2ParsedCommitHeader, V2SectionDescriptor, V2SectionType, V2UploadMode,
    body_digest_for_v2_sections, digest_v2_section, generate_v2_commit_key, parse_v2_commit_header,
    parse_v2_commit_object,
};
pub use coordinator::{
    V2_INDEX_COMPACTION_PAUSE_RUNS, V2_INDEX_COMPACTION_REQUEST_RUNS, V2CommitCoordinator,
    V2CommitCoordinatorStatus, V2CommittedPut,
};
pub use error::{V2ErrorClass, V2FormatError, V2Result};
pub use format::{
    V2FormatRef, V2FormatRoot, V2KeyringEnvelopeRootRef, V2MaintenanceConfig, v2_format_object_id,
};
pub use index_root::{
    V2_INDEX_ROOT_FIXED_HEADER_BYTES, V2_INDEX_ROOT_ID_LEN, V2_INDEX_ROOT_MAX_BYTES,
    V2_INDEX_ROOT_MAX_LEVEL, V2_INDEX_ROOT_MAX_RUNS, V2_INDEX_ROOT_MAX_TOTAL_MUTATIONS,
    V2_INDEX_ROOT_MAX_TOTAL_RUN_BYTES, V2EmbeddedIndexRunLocation, V2IndexRoot, V2IndexRootClaims,
    V2IndexRootId, V2IndexRootRunRef, V2SealedIndexRoot, open_v2_index_root, seal_v2_index_root,
};
pub use index_run::{
    V2_INDEX_RUN_FIXED_HEADER_BYTES, V2_INDEX_RUN_ID_LEN, V2_INDEX_RUN_MAX_FRAME_COUNT,
    V2_INDEX_RUN_MAX_FRAME_PLAINTEXT_BYTES, V2_INDEX_RUN_MAX_OBJECT_BYTES,
    V2IndexRunFrameDescriptor, V2IndexRunHeaderProbe, V2IndexRunId, V2SealedIndexRun,
    V2VerifiedIndexRunDirectory, open_v2_index_run, open_v2_index_run_directory,
    open_v2_index_run_frame, open_v2_index_run_frames, probe_v2_index_run_header,
    seal_v2_index_run,
};
pub use maintenance::{
    UnenforcedQuiescedMaintenanceGuard, V2FullGcApplyOptions, V2FullGcApplyReport,
    V2FullGcDryRunOptions, V2FullGcDryRunReport, V2MaintenanceBudgets, V2MaintenanceGuard,
    V2MaintenancePlanCost, V2MaintenanceReport, V2OrphanCandidate, V2OrphanGcOptions,
    V2OrphanGcReport, V2OrphanReport,
};
pub use payload_pack::{
    V2_PAYLOAD_PACK_ID_LEN, V2_PAYLOAD_PACK_MAX_BYTES, V2_PAYLOAD_PACK_MAX_RECORDS,
    V2_PAYLOAD_PACK_SEGMENT_BYTES, V2OpenedPayloadPackRecordSpan, V2PayloadPackFacts,
    V2PayloadPackId, V2PayloadPackLayout, V2PayloadPackRecord, V2PayloadPackRecordContext,
    V2PayloadPackRecordInput, V2PayloadPackRecordRef, V2PayloadPackRecordSpan, V2SealedPayloadPack,
    open_v2_payload_pack_cached_record_span, open_v2_payload_pack_record,
    open_v2_payload_pack_record_range, open_v2_payload_pack_record_span,
    open_v2_payload_pack_record_span_with_segments, plan_v2_payload_pack_record_range,
    seal_v2_payload_pack, validate_v2_payload_pack_record_ref,
};
pub use provider::{
    V2ProviderCheckStatus, V2ProviderConformanceCheck, V2ProviderConformanceOptions,
    V2ProviderConformanceReport, V2ProviderProfile, check_v2_provider_conformance,
};
pub use repository::{
    DEFAULT_V2_FULL_CHAIN_MAX_BYTES, DEFAULT_V2_FULL_COMMIT_MAX_BYTES,
    DEFAULT_V2_REPLAY_MAX_COMMITS, DEFAULT_V2_REPLAY_MAX_RETAINED_BYTES,
    DEFAULT_V2_REPLAY_MAX_TOTAL_COMMIT_BYTES, DEFAULT_V2_REPLAY_READ_CHUNK_BYTES,
    DEFAULT_V2_STREAM_READ_STALL_TIMEOUT, V2_RESTORE_BUNDLE_SCHEMA, V2AnchorState, V2CommitAnchor,
    V2CommitChain, V2CommitSection, V2CommitStore, V2CommitStoreOptions, V2CommitWrite,
    V2MemoryAnchor, V2RecoveryBundle, V2ReplayChain, V2ReplayCommit, V2ReplayLimits,
    V2StoredCommit,
};
pub use service::{V2Repository, V2ResolvedObject};
