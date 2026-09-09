//! Preview v2 commit-store workflow.

mod genesis;
mod multipart;
pub use genesis::V2PreparedGenesis;
pub use multipart::{V3MultipartUpload, V3UploadedPart, V3VerifiedMultipartUpload};

use super::commit::{
    V2_COMMIT_CONTENT_TYPE, V2_HEADER_META_LEN, V2_MAX_HEADER_SIZE,
    V2_SECTION_FLAG_MUST_UNDERSTAND, V2CommitHeader, V2CommitKey, V2CommitKind, V2CommitParentRef,
    V2CommitSelfRef, V2KeyringEnvelopeRef, V2ParsedCommit, V2ParsedCommitHeader,
    V2SectionDescriptor, V2SectionType, body_digest_for_v2_sections, digest_v2_section,
    generate_v2_commit_key, parse_v2_commit_header, parse_v2_commit_object,
    v2_commit_header_span_len, validate_commit_section_semantics, validate_v2_commit_object_len,
};
use super::error::{V2FormatError, V2Result};
use super::format::{V2FormatRef, V2KeyringEnvelopeRootRef};
use super::provider::V2ProviderProfile;
use crate::payload::SegmentedPayloadSealer;
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use rs3_crypto::KeyRing;
use rs3_crypto::Sha256Hasher;
use rs3_storage::{
    BlobMetadata, BlobMultipartUpload, BlobStore, ByteRange, PutOptions, StorageError,
};
use rs3_storage::{retention_satisfies, strongest_retention_policy};
use rs3_types::{
    BackendObjectId, BackendVersionId, KeyId, LegalHoldStatus, RepositoryId, RetentionMode,
    RetentionPolicy, Sequence,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::collections::{BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_RANDOM_KEY_ATTEMPTS: usize = 3;
const VERIFIED_PUBLICATION_TIME_CACHE_ENTRIES: usize = 4;

#[derive(Debug)]
pub(super) struct StreamReadStalled;

pub(super) async fn next_nonempty_stream_chunk<St>(
    stream: &mut St,
    stall_timeout: Duration,
) -> Result<Option<crate::Result<Bytes>>, StreamReadStalled>
where
    St: Stream<Item = crate::Result<Bytes>> + Unpin,
{
    let deadline = tokio::time::sleep(stall_timeout);
    tokio::pin!(deadline);

    loop {
        let next = tokio::select! {
            biased;
            () = &mut deadline => return Err(StreamReadStalled),
            next = stream.next() => next,
        };
        match next {
            Some(Ok(chunk)) if chunk.is_empty() => tokio::task::yield_now().await,
            next => return Ok(next),
        }
    }
}

/// Maximum commits traversed during one bounded recovery replay by default.
pub const DEFAULT_V2_REPLAY_MAX_COMMITS: usize = 4_096;
/// Maximum cumulative commit-object bytes verified during one recovery replay.
pub const DEFAULT_V2_REPLAY_MAX_TOTAL_COMMIT_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
/// Maximum encrypted index bytes retained in memory during one recovery replay.
pub const DEFAULT_V2_REPLAY_MAX_RETAINED_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum bytes held by one recovery range read.
pub const DEFAULT_V2_REPLAY_READ_CHUNK_BYTES: u64 = 8 * 1024 * 1024;

/// Schema marker for trusted v2 recovery bundles.
pub const V2_RESTORE_BUNDLE_SCHEMA: &str = "rs3.restore-bundle.v3-preview.v1";

/// Default idle time allowed between streaming request-body chunks.
pub const DEFAULT_V2_STREAM_READ_STALL_TIMEOUT: Duration = Duration::from_secs(30);

const STREAMING_UPLOAD_ACTIVE_MULTIPART_BUFFERS: u64 = 2;
const STREAMING_UPLOAD_FINALIZATION_MULTIPART_BUFFERS: u64 = 3;
const STREAMING_UPLOAD_ACTIVE_SEGMENT_BUFFERS: u64 = 3;
const STREAMING_UPLOAD_FINALIZATION_SEGMENT_BUFFERS: u64 = 1;
const STREAMING_UPLOAD_AUXILIARY_BYTES: u64 = V2_MAX_HEADER_SIZE as u64 + 4096;

/// Returns a conservative peak working set for one v2 multipart streaming encoder.
///
/// The active streaming phase retains the commit assembler's first and current
/// multipart buffers alongside current, pending, and encrypted payload
/// segments. Finalization temporarily retains three multipart-sized buffers
/// while the final segment allocation remains live. Request transport chunks
/// are owned by the HTTP stack and are not included here.
pub const fn v2_streaming_upload_working_set_bytes(
    multipart_part_bytes: u64,
    payload_segment_bytes: u64,
) -> u64 {
    let active_streaming = multipart_part_bytes
        .saturating_mul(STREAMING_UPLOAD_ACTIVE_MULTIPART_BUFFERS)
        .saturating_add(
            payload_segment_bytes.saturating_mul(STREAMING_UPLOAD_ACTIVE_SEGMENT_BUFFERS),
        );
    let finalization = multipart_part_bytes
        .saturating_mul(STREAMING_UPLOAD_FINALIZATION_MULTIPART_BUFFERS)
        .saturating_add(
            payload_segment_bytes.saturating_mul(STREAMING_UPLOAD_FINALIZATION_SEGMENT_BUFFERS),
        );
    let peak = if active_streaming > finalization {
        active_streaming
    } else {
        finalization
    };
    peak.saturating_add(STREAMING_UPLOAD_AUXILIARY_BYTES)
}

/// Accepted v2 commit anchor state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2AnchorState {
    /// Accepted commit sequence.
    pub sequence: Sequence,
    /// Full accepted commit object key.
    pub commit_key: BackendObjectId,
    /// Accepted commit body digest.
    pub body_digest: [u8; 32],
    /// Provider version ID for exact-version reads, when required.
    pub version_id: Option<BackendVersionId>,
    /// Signing key ID used by the accepted commit.
    pub signing_key_id: KeyId,
    /// Active encrypted format-root reference for this accepted head.
    pub format_ref: V2FormatRef,
}

impl Serialize for V2AnchorState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        V2AnchorStateWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for V2AnchorState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        V2AnchorStateWire::deserialize(deserializer)?
            .try_into()
            .map_err(de::Error::custom)
    }
}

#[derive(Serialize, Deserialize)]
struct V2AnchorStateWire {
    format_generation: u32,
    sequence: u64,
    commit_key: String,
    body_digest: String,
    #[serde(default)]
    version_id: Option<String>,
    signing_key_id: String,
    format: V2FormatRefWire,
}

impl From<&V2AnchorState> for V2AnchorStateWire {
    fn from(anchor: &V2AnchorState) -> Self {
        Self {
            format_generation: super::V2_FORMAT_VERSION,
            sequence: anchor.sequence.get(),
            commit_key: anchor.commit_key.as_str().to_owned(),
            body_digest: encode_digest_32(anchor.body_digest),
            version_id: anchor
                .version_id
                .as_ref()
                .map(|version_id| version_id.as_str().to_owned()),
            signing_key_id: anchor.signing_key_id.as_str().to_owned(),
            format: V2FormatRefWire::from(&anchor.format_ref),
        }
    }
}

impl TryFrom<V2AnchorStateWire> for V2AnchorState {
    type Error = de::value::Error;

    fn try_from(wire: V2AnchorStateWire) -> Result<Self, Self::Error> {
        if wire.format_generation != super::V2_FORMAT_VERSION {
            return Err(de::Error::custom(
                "unsupported repository format generation",
            ));
        }
        Ok(Self {
            sequence: Sequence::new(wire.sequence),
            commit_key: BackendObjectId::new(wire.commit_key).map_err(de::Error::custom)?,
            body_digest: decode_digest_32("anchor body digest", &wire.body_digest)?,
            version_id: wire
                .version_id
                .map(BackendVersionId::new)
                .transpose()
                .map_err(de::Error::custom)?,
            signing_key_id: KeyId::new(wire.signing_key_id).map_err(de::Error::custom)?,
            format_ref: wire.format.try_into()?,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct V2FormatRefWire {
    generation: u64,
    digest: String,
    object_id: String,
    #[serde(default)]
    version_id: Option<String>,
}

impl From<&V2FormatRef> for V2FormatRefWire {
    fn from(format_ref: &V2FormatRef) -> Self {
        Self {
            generation: format_ref.generation,
            digest: format_ref.digest.clone(),
            object_id: format_ref.object_id.as_str().to_owned(),
            version_id: format_ref
                .version_id
                .as_ref()
                .map(|version_id| version_id.as_str().to_owned()),
        }
    }
}

impl TryFrom<V2FormatRefWire> for V2FormatRef {
    type Error = de::value::Error;

    fn try_from(wire: V2FormatRefWire) -> Result<Self, Self::Error> {
        Ok(Self {
            generation: wire.generation,
            digest: wire.digest,
            object_id: BackendObjectId::new(wire.object_id).map_err(de::Error::custom)?,
            version_id: wire
                .version_id
                .map(BackendVersionId::new)
                .transpose()
                .map_err(de::Error::custom)?,
        })
    }
}

/// Compare-and-swap anchor used by v2 writers.
#[async_trait]
pub trait V2CommitAnchor: Send + Sync {
    /// Reads the current v2 anchor, returning `None` before genesis.
    async fn read_v2(&self) -> V2Result<Option<V2AnchorState>>;

    /// Advances the v2 anchor only if the current state equals `expected`.
    async fn compare_and_advance_v2(
        &self,
        expected: Option<&V2AnchorState>,
        next: V2AnchorState,
    ) -> V2Result<V2AnchorState>;

    /// Settles an advance whose reply was lost.
    ///
    /// Implementations with asynchronous delivery perform a fencing write
    /// first, so an earlier in-flight update can no longer land after the
    /// returned state was observed. Anchors that apply updates synchronously
    /// simply read. A plain re-read never provides that guarantee.
    async fn fence_and_read_v2(&self) -> V2Result<Option<V2AnchorState>> {
        self.read_v2().await
    }
}

/// In-memory v2 anchor for local tests and preview wiring.
#[derive(Clone, Debug, Default)]
pub struct V2MemoryAnchor {
    state: Arc<RwLock<Option<V2AnchorState>>>,
}

impl V2MemoryAnchor {
    /// Creates an empty in-memory v2 anchor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an in-memory v2 anchor with an initial state.
    pub fn with_state(state: V2AnchorState) -> Self {
        Self {
            state: Arc::new(RwLock::new(Some(state))),
        }
    }
}

#[async_trait]
impl V2CommitAnchor for V2MemoryAnchor {
    async fn read_v2(&self) -> V2Result<Option<V2AnchorState>> {
        self.state
            .read()
            .map_err(|_| V2FormatError::AnchorReadFailed)
            .map(|state| state.clone())
    }

    async fn compare_and_advance_v2(
        &self,
        expected: Option<&V2AnchorState>,
        next: V2AnchorState,
    ) -> V2Result<V2AnchorState> {
        let mut state = self
            .state
            .write()
            .map_err(|_| V2FormatError::AnchorAdvanceFailed)?;
        if state.as_ref() != expected {
            return Err(V2FormatError::StaleAnchor);
        }
        if let Some(current) = state.as_ref()
            && next.sequence <= current.sequence
        {
            return Err(V2FormatError::StaleAnchor);
        }
        *state = Some(next.clone());
        Ok(next)
    }
}

/// Runtime options for the preview v2 commit store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2CommitStoreOptions {
    /// Immutable repository identity bound into framed-section AEAD contexts.
    pub repository_id: RepositoryId,
    /// Authenticated recovery promises. None is explicit native/artifact mode without history claims.
    pub recovery_policy: Option<super::RecoveryPolicy>,
    /// Shared graph and provider-operation limits for publication protection.
    pub recovery_maintenance_budgets: super::V2MaintenanceBudgets,
    /// Provider profile selected for post-write checks.
    pub provider_profile: V2ProviderProfile,
    /// Maximum idle time allowed while reading streamed payload chunks.
    pub stream_read_stall_timeout: Duration,
    /// Retention requested for commit objects.
    pub retention: Option<RetentionPolicy>,
    /// Legal hold requested for commit objects.
    pub legal_hold: Option<LegalHoldStatus>,
    /// Active keyring envelope reference to bind into commits.
    pub keyring_envelope_ref: V2KeyringEnvelopeRef,
    /// Active encrypted format-root reference to bind into anchors.
    pub format_ref: V2FormatRef,
    /// Full active keyring-envelope reference used by retention maintenance.
    pub maintenance_keyring_envelope_ref: Option<V2KeyringEnvelopeRootRef>,
    /// Resource budgets for startup and disaster-recovery replay.
    pub replay_limits: V2ReplayLimits,
}

impl V2CommitStoreOptions {
    /// Creates default options for the selected provider profile.
    pub fn for_profile(
        profile: V2ProviderProfile,
        repository_id: RepositoryId,
        keyring_envelope_ref: V2KeyringEnvelopeRef,
        format_ref: V2FormatRef,
    ) -> Self {
        Self {
            repository_id,
            recovery_policy: None,
            recovery_maintenance_budgets: super::V2MaintenanceBudgets::default(),
            provider_profile: profile,
            stream_read_stall_timeout: DEFAULT_V2_STREAM_READ_STALL_TIMEOUT,
            retention: match profile {
                V2ProviderProfile::RetainedVersionObjectLock => Some(RetentionPolicy::new(
                    rs3_types::RetentionMode::Governance,
                    1,
                )),
                V2ProviderProfile::Dev | V2ProviderProfile::AtomicCreate => None,
            },
            legal_hold: None,
            keyring_envelope_ref,
            format_ref,
            maintenance_keyring_envelope_ref: None,
            replay_limits: V2ReplayLimits::default(),
        }
    }

    /// Enables authenticated recovery-point history for repository publications.
    pub const fn with_recovery_policy(mut self, policy: Option<super::RecoveryPolicy>) -> Self {
        self.recovery_policy = policy;
        self
    }

    /// Shares operator maintenance limits with foreground recovery verification.
    pub const fn with_recovery_maintenance_budgets(
        mut self,
        budgets: super::V2MaintenanceBudgets,
    ) -> Self {
        self.recovery_maintenance_budgets = budgets;
        self
    }

    /// Uses a specific idle timeout for streamed request-body reads.
    pub const fn with_stream_read_stall_timeout(mut self, timeout: Duration) -> Self {
        self.stream_read_stall_timeout = timeout;
        self
    }

    /// Uses a specific retention policy for commit objects.
    pub const fn with_retention(mut self, retention: Option<RetentionPolicy>) -> Self {
        self.retention = retention;
        self
    }

    /// Uses a specific legal-hold status for commit objects.
    pub const fn with_legal_hold(mut self, legal_hold: Option<LegalHoldStatus>) -> Self {
        self.legal_hold = legal_hold;
        self
    }

    /// Supplies the exact active keyring envelope for retention maintenance.
    pub fn with_maintenance_keyring_envelope_ref(
        mut self,
        keyring_envelope_ref: V2KeyringEnvelopeRootRef,
    ) -> Self {
        self.maintenance_keyring_envelope_ref = Some(keyring_envelope_ref);
        self
    }

    /// Uses explicit resource budgets for startup and disaster-recovery replay.
    pub const fn with_replay_limits(mut self, replay_limits: V2ReplayLimits) -> Self {
        self.replay_limits = replay_limits;
        self
    }
}

/// Resource budgets for verified startup and disaster-recovery replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V2ReplayLimits {
    /// Maximum signed commits walked before reaching a snapshot.
    pub max_commits: usize,
    /// Maximum cumulative provider-reported commit-object bytes verified.
    pub max_total_commit_bytes: u64,
    /// Maximum encrypted index-section bytes retained for namespace replay.
    pub max_retained_bytes: u64,
    /// Maximum bytes requested and held by one body-verification range read.
    pub read_chunk_bytes: u64,
}

impl Default for V2ReplayLimits {
    fn default() -> Self {
        Self {
            max_commits: DEFAULT_V2_REPLAY_MAX_COMMITS,
            max_total_commit_bytes: DEFAULT_V2_REPLAY_MAX_TOTAL_COMMIT_BYTES,
            max_retained_bytes: DEFAULT_V2_REPLAY_MAX_RETAINED_BYTES,
            read_chunk_bytes: DEFAULT_V2_REPLAY_READ_CHUNK_BYTES,
        }
    }
}

/// Opaque section bytes included in a v2 commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2CommitSection {
    /// Section type.
    pub section_type: V2SectionType,
    /// Section flags.
    pub flags: u8,
    /// Raw section bytes.
    pub bytes: Bytes,
}

impl V2CommitSection {
    /// Creates a section from raw bytes.
    pub fn new(section_type: V2SectionType, flags: u8, bytes: Bytes) -> Self {
        Self {
            section_type,
            flags,
            bytes,
        }
    }
}

/// Request to write one v2 commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2CommitWrite {
    /// Semantic role of this commit in authenticated history.
    pub kind: V2CommitKind,
    /// Opaque sections to include in physical order.
    pub sections: Vec<V2CommitSection>,
    /// Retention required by objects represented in this commit.
    pub retention: Option<RetentionPolicy>,
    /// Legal hold required by objects represented in this commit.
    pub legal_hold: Option<LegalHoldStatus>,
    /// Absolute physical protection floor, separate from logical object policy.
    pub required_retain_until_ms: Option<i64>,
}

impl V2CommitWrite {
    /// Creates a snapshot commit write request.
    pub fn snapshot(sections: Vec<V2CommitSection>) -> Self {
        Self {
            kind: V2CommitKind::Root,
            sections,
            retention: None,
            legal_hold: None,
            required_retain_until_ms: None,
        }
    }

    /// Creates a delta commit write request.
    pub fn delta(sections: Vec<V2CommitSection>) -> Self {
        Self {
            kind: V2CommitKind::Delta,
            sections,
            retention: None,
            legal_hold: None,
            required_retain_until_ms: None,
        }
    }

    /// Requests at least this retention for the physical commit object.
    pub const fn with_retention(mut self, retention: Option<RetentionPolicy>) -> Self {
        self.retention = retention;
        self
    }

    /// Requests this legal hold for the physical commit object.
    pub const fn with_legal_hold(mut self, legal_hold: Option<LegalHoldStatus>) -> Self {
        self.legal_hold = legal_hold;
        self
    }

    /// Requires exact backend protection through this absolute deadline.
    pub const fn with_required_retain_until_ms(mut self, deadline: Option<i64>) -> Self {
        self.required_retain_until_ms = deadline;
        self
    }
}

/// Complete authenticated facts for one independently uploaded payload object.
pub(crate) struct V2StoredStandalonePayload {
    pub(crate) etag: rs3_types::ObjectEtag,
    pub(crate) object_id: BackendObjectId,
    pub(crate) version_id: Option<BackendVersionId>,
    pub(crate) object_len: u64,
    pub(crate) object_digest: [u8; 32],
    pub(crate) payload_layout: crate::payload::SegmentedPayloadLayout,
}

pub(crate) struct V2StandalonePayloadWrite<St> {
    pub(crate) object_id: BackendObjectId,
    pub(crate) expected_plaintext_len: Option<u64>,
    pub(crate) max_plaintext_len: u64,
    pub(crate) payload_segment_size: usize,
    pub(crate) stream: St,
    pub(crate) retention: Option<RetentionPolicy>,
    pub(crate) legal_hold: Option<LegalHoldStatus>,
    pub(crate) multipart_part_size: usize,
    pub(crate) cancellation: Arc<V2StandaloneUploadCancellation>,
}

#[derive(Clone, Copy)]
struct V2WritePostconditions {
    expected_object_len: u64,
    required_retention: Option<RetentionPolicy>,
    required_retain_until_ms: Option<i64>,
    required_legal_hold: Option<LegalHoldStatus>,
    expected_stored_digest: Option<[u8; 32]>,
}

impl V2WritePostconditions {
    fn commit(
        expected_object_len: u64,
        required_retention: Option<RetentionPolicy>,
        required_legal_hold: Option<LegalHoldStatus>,
        required_retain_until_ms: Option<i64>,
    ) -> Self {
        Self {
            expected_object_len,
            required_retention,
            required_retain_until_ms,
            required_legal_hold,
            expected_stored_digest: None,
        }
    }

    fn verified_object(
        expected_object_len: u64,
        required_retention: Option<RetentionPolicy>,
        required_retain_until_ms: Option<i64>,
        required_legal_hold: Option<LegalHoldStatus>,
        expected_stored_digest: [u8; 32],
    ) -> Self {
        Self {
            expected_object_len,
            required_retention,
            required_retain_until_ms,
            required_legal_hold,
            expected_stored_digest: Some(expected_stored_digest),
        }
    }
}

/// One immutable parent/time choice shared by coverage, metadata encoding and retry.
#[derive(Clone, Debug)]
pub(super) struct V2PublicationPlan {
    pub(super) sampled_now_ms: i64,
    pub(super) parent: V2AnchorState,
    pub(super) parent_publish_time_ms: i64,
    pub(super) publish_time_ms: i64,
}

/// Result of a v2 commit write accepted by the anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2StoredCommit {
    /// Actual protection observed on the exact version during verification.
    pub(crate) verified_retain_until_ms: Option<i64>,
    /// Verified signed publication time, strictly after the accepted parent.
    pub publish_time_ms: i64,
    /// Accepted anchor state.
    pub anchor_state: V2AnchorState,
    /// Full commit key that was written.
    pub commit_key: V2CommitKey,
    /// Provider version ID returned by the write.
    pub version_id: Option<BackendVersionId>,
    /// Provider-reported complete commit-object length.
    pub object_len: u64,
    /// Absolute offset where the commit section region starts.
    pub sections_start: u64,
}

/// Verified v2 commit chain, newest commit first.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(super) struct V2CommitChain {
    /// Verified commits, newest first, ending at the nearest snapshot or genesis.
    pub commits_newest_first: Vec<V2ParsedCommit>,
}

/// One fully verified commit retaining only sections needed for namespace replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2ReplayCommit {
    /// Decoded and cryptographically verified commit header.
    pub parsed_header: V2ParsedCommitHeader,
    /// Provider version identifier used for exact-version reads, when available.
    pub version_id: Option<BackendVersionId>,
    /// Provider-reported complete commit-object length verified by replay.
    pub object_len: u64,
    pub(crate) retained_sections: Vec<Option<Bytes>>,
}

impl V2ReplayCommit {
    /// Drops replay buffers once their namespace and history have been consumed.
    pub(super) fn clear_retained_sections(&mut self) {
        self.retained_sections
            .iter_mut()
            .for_each(|section| *section = None);
    }

    pub(super) fn header_facts(&self) -> Self {
        let mut facts = self.clone();
        facts.clear_retained_sections();
        facts
    }
}

pub(super) fn metadata_section_buffer_bytes(length: u64, read_chunk: u64) -> V2Result<u64> {
    if read_chunk == 0 {
        return Err(V2FormatError::ReplayBudgetExceeded);
    }
    length
        .checked_add(length.min(read_chunk))
        .ok_or(V2FormatError::MaintenanceBudgetExceeded)
}

/// Resource-bounded verified chain used by startup and recovery workflows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2ReplayChain {
    /// Verified commits, newest first, ending at the nearest snapshot or genesis.
    pub commits_newest_first: Vec<V2ReplayCommit>,
}

/// Recovery bundle used as the weak-subjectivity floor for v2 DR.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2RecoveryBundle {
    /// Optional public repository identifier.
    pub repository_id: Option<RepositoryId>,
    /// Optional public repository salt digest.
    pub repository_salt_digest: Option<[u8; 32]>,
    /// Anchor state exported from a trusted anchor authority.
    pub anchor: V2AnchorState,
    /// Minimum sequence this bundle allows normal DR to recreate.
    pub weak_subjectivity_floor_sequence: Sequence,
    /// Bundle export timestamp in milliseconds since Unix epoch.
    pub exported_at_ms: i64,
    /// Optional operator or offline signature over the bundle.
    pub offline_signature: Option<Vec<u8>>,
}

impl Serialize for V2RecoveryBundle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let offline_signature_payload_hex = if self.repository_id.is_some() {
            Some(hex::encode(
                self.offline_signature_payload()
                    .map_err(serde::ser::Error::custom)?,
            ))
        } else {
            None
        };
        let repository =
            self.repository_id
                .as_ref()
                .map(|repository_id| V2RecoveryBundleRepositoryWire {
                    id: repository_id.as_str().to_owned(),
                    salt_digest: self.repository_salt_digest.map(encode_digest_32),
                });
        let repository_salt_digest = if repository.is_none() {
            self.repository_salt_digest.map(encode_digest_32)
        } else {
            None
        };
        let wire = V2RecoveryBundleWire {
            schema: V2_RESTORE_BUNDLE_SCHEMA.to_owned(),
            repository,
            anchor: V2AnchorStateWire::from(&self.anchor),
            weak_subjectivity_floor_sequence: self.weak_subjectivity_floor_sequence.get(),
            format_digest: Some(self.anchor.format_ref.digest.clone()),
            format_generation: Some(self.anchor.format_ref.generation),
            exported_at_ms: self.exported_at_ms,
            offline_signature_payload_hex,
            offline_signature: self.offline_signature.as_ref().map(hex::encode),
            repository_salt_digest,
        };
        wire.serialize(serializer)
    }
}

#[derive(Serialize)]
struct V2RecoveryBundleWire {
    schema: String,
    #[serde(default)]
    repository: Option<V2RecoveryBundleRepositoryWire>,
    anchor: V2AnchorStateWire,
    weak_subjectivity_floor_sequence: u64,
    #[serde(default)]
    format_digest: Option<String>,
    #[serde(default)]
    format_generation: Option<u64>,
    exported_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    offline_signature_payload_hex: Option<String>,
    #[serde(default)]
    offline_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    repository_salt_digest: Option<String>,
}

#[derive(Serialize)]
struct V2RecoveryBundleRepositoryWire {
    id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    salt_digest: Option<String>,
}

impl V2RecoveryBundle {
    /// Creates a recovery bundle from an accepted anchor state.
    pub fn from_anchor(anchor: V2AnchorState, floor: Sequence) -> Self {
        Self {
            repository_id: None,
            repository_salt_digest: None,
            anchor,
            weak_subjectivity_floor_sequence: floor,
            exported_at_ms: current_time_ms(),
            offline_signature: None,
        }
    }

    /// Verifies the offline recovery signature with an operator recovery key.
    pub fn verify_offline_signature(&self, public_key: &str) -> V2Result<()> {
        let signature = self
            .offline_signature
            .as_deref()
            .ok_or(V2FormatError::RecoveryBundleRequired)?;
        rs3_crypto::verify_recovery_signature(
            public_key,
            &self.offline_signature_payload()?,
            signature,
        )
        .map_err(|_| V2FormatError::SignatureVerification)
    }
}

fn encode_digest_32(digest: [u8; 32]) -> String {
    hex::encode(digest)
}

fn decode_digest_32<E>(label: &str, value: &str) -> Result<[u8; 32], E>
where
    E: de::Error,
{
    let bytes =
        hex::decode(value).map_err(|_| E::custom(format!("{label} must be hex encoded")))?;
    if bytes.len() != 32 {
        return Err(E::custom(format!("{label} must be exactly 32 bytes")));
    }
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&bytes);
    Ok(digest)
}

/// Preview v2 commit store over a `BlobStore`.
pub struct V2CommitStore<S> {
    store: S,
    keyring: KeyRing,
    options: V2CommitStoreOptions,
    inflight_standalone_objects: Arc<RwLock<BTreeSet<BackendObjectId>>>,
    verified_publication_times: Arc<RwLock<VecDeque<(V2AnchorState, i64, bool)>>>,
    pub(in crate::v2) recovery_coverage:
        Arc<RwLock<Option<super::maintenance::coverage::RecoveryCoverage>>>,
    pub(in crate::v2) recovery_capacity:
        Arc<RwLock<Option<super::maintenance::capacity::RecoveryCapacity>>>,
    #[cfg(test)]
    publication_time_override: Arc<std::sync::atomic::AtomicI64>,
}

pub(crate) struct V2InflightStandaloneObject {
    object_id: BackendObjectId,
    roots: Arc<RwLock<BTreeSet<BackendObjectId>>>,
}

pub(crate) struct V2StandaloneUploadCancellation {
    cancelled: AtomicBool,
    notify: tokio::sync::Notify,
}

impl V2StandaloneUploadCancellation {
    pub(crate) fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        }
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let notified = self.notify.notified();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }
}

impl Drop for V2InflightStandaloneObject {
    fn drop(&mut self) {
        if let Ok(mut roots) = self.roots.write() {
            roots.remove(&self.object_id);
        }
    }
}

impl<S> V2CommitStore<S>
where
    S: BlobStore,
{
    /// Creates a v2 commit store.
    pub fn new(store: S, keyring: KeyRing, options: V2CommitStoreOptions) -> Self {
        Self {
            store,
            keyring,
            options,
            inflight_standalone_objects: Arc::new(RwLock::new(BTreeSet::new())),
            verified_publication_times: Arc::new(RwLock::new(VecDeque::new())),
            recovery_coverage: Arc::new(RwLock::new(None)),
            recovery_capacity: Arc::new(RwLock::new(None)),
            #[cfg(test)]
            publication_time_override: Arc::new(std::sync::atomic::AtomicI64::new(i64::MIN)),
        }
    }

    pub(super) fn publication_now_ms(&self) -> i64 {
        #[cfg(test)]
        {
            let sample = self.publication_time_override.load(Ordering::Acquire);
            if sample != i64::MIN {
                return sample;
            }
        }
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(elapsed) => i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX),
            Err(_) => -1,
        }
    }

    #[cfg(test)]
    pub(super) fn set_publication_time_for_tests(&self, sample: i64) {
        self.publication_time_override
            .store(sample, Ordering::Release);
    }

    fn remember_verified_publication_time(
        &self,
        anchor: &V2AnchorState,
        time: i64,
        has_recovery: bool,
    ) -> V2Result<()> {
        super::recovery::validate_parent_time(None, time)?;
        let mut cache = self
            .verified_publication_times
            .write()
            .map_err(|_| V2FormatError::StorageOperationFailed)?;
        if let Some(index) = cache
            .iter()
            .position(|(candidate, _, _)| candidate == anchor)
        {
            cache.remove(index);
        }
        cache.push_back((anchor.clone(), time, has_recovery));
        while cache.len() > VERIFIED_PUBLICATION_TIME_CACHE_ENTRIES {
            cache.pop_front();
        }
        Ok(())
    }

    /// Exact signed header facts are cached, never provider timestamps. This
    /// bounded cache also retains the reused base of unrelated compaction siblings.
    pub(super) async fn verified_parent_publish_time(
        &self,
        anchor: &V2AnchorState,
    ) -> V2Result<i64> {
        Ok(self.verified_parent_header_facts(anchor).await?.0)
    }

    async fn verified_parent_header_facts(&self, anchor: &V2AnchorState) -> V2Result<(i64, bool)> {
        {
            let mut cache = self
                .verified_publication_times
                .write()
                .map_err(|_| V2FormatError::StorageOperationFailed)?;
            if let Some(index) = cache
                .iter()
                .position(|(candidate, _, _)| candidate == anchor)
                && let Some(entry) = cache.remove(index)
            {
                let facts = (entry.1, entry.2);
                cache.push_back(entry);
                return Ok(facts);
            }
        }
        let parsed = self
            .read_commit_header_at(&anchor.commit_key, anchor.version_id.as_ref())
            .await?;
        let header = &parsed.header;
        if header.self_ref.sequence != anchor.sequence
            || header.body_digest != anchor.body_digest
            || header.signing_key_id != anchor.signing_key_id
        {
            return Err(V2FormatError::StaleAnchor);
        }
        let time = header.publish_time_ms;
        let has_recovery = header
            .section_index
            .iter()
            .any(|section| section.section_type == V2SectionType::Recovery);
        self.remember_verified_publication_time(anchor, time, has_recovery)?;
        Ok((time, has_recovery))
    }

    pub(crate) fn claim_inflight_standalone_object(
        &self,
        object_id: BackendObjectId,
    ) -> V2Result<V2InflightStandaloneObject> {
        // This process-local root closes the online race with maintenance run by
        // this store instance, including test rehearsals with a zero minimum age.
        // Destructive external maintenance is separately fenced by
        // V2MaintenanceGuard quiescence, so it cannot race the single writer.
        let mut roots = self
            .inflight_standalone_objects
            .write()
            .map_err(|_| V2FormatError::StorageOperationFailed)?;
        if !roots.insert(object_id.clone()) {
            return Err(V2FormatError::InvalidHeaderField);
        }
        drop(roots);
        Ok(V2InflightStandaloneObject {
            object_id,
            roots: Arc::clone(&self.inflight_standalone_objects),
        })
    }

    pub(crate) fn is_inflight_standalone_object(
        &self,
        object_id: &BackendObjectId,
    ) -> V2Result<bool> {
        self.inflight_standalone_objects
            .read()
            .map(|roots| roots.contains(object_id))
            .map_err(|_| V2FormatError::StorageOperationFailed)
    }

    /// Returns the backing store.
    pub fn store(&self) -> &S {
        &self.store
    }

    pub(super) fn rebind_store<T>(&self, store: T) -> V2CommitStore<T> {
        V2CommitStore {
            store,
            keyring: self.keyring.clone(),
            options: self.options.clone(),
            inflight_standalone_objects: Arc::clone(&self.inflight_standalone_objects),
            verified_publication_times: Arc::clone(&self.verified_publication_times),
            recovery_coverage: Arc::clone(&self.recovery_coverage),
            recovery_capacity: Arc::clone(&self.recovery_capacity),
            #[cfg(test)]
            publication_time_override: Arc::clone(&self.publication_time_override),
        }
    }

    /// Returns the configured provider profile.
    pub(super) const fn provider_profile(&self) -> V2ProviderProfile {
        self.options.provider_profile
    }

    /// Returns the configured commit retention policy.
    pub(super) const fn retention_policy(&self) -> Option<RetentionPolicy> {
        self.options.retention
    }

    /// Returns the configured commit-store options.
    pub(super) const fn options(&self) -> &V2CommitStoreOptions {
        &self.options
    }

    pub(super) fn keyring(&self) -> &KeyRing {
        &self.keyring
    }

    fn validate_write_protection_profile(
        &self,
        retention: Option<RetentionPolicy>,
        legal_hold: Option<LegalHoldStatus>,
    ) -> V2Result<()> {
        if legal_hold == Some(LegalHoldStatus::On) {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        let active_retention = retention
            .is_some_and(|policy| policy.mode != RetentionMode::None && policy.retain_days > 0);
        if active_retention
            && self.options.provider_profile != V2ProviderProfile::RetainedVersionObjectLock
        {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        Ok(())
    }

    /// Writes and anchors the required genesis snapshot commit.
    pub async fn write_genesis_snapshot<A>(&self, anchor: &A) -> V2Result<V2StoredCommit>
    where
        A: V2CommitAnchor,
    {
        let current = anchor.read_v2().await?;
        if current.is_some() {
            return Err(V2FormatError::StaleAnchor);
        }
        let prepared = self.prepare_genesis_snapshot()?;
        self.publish_prepared_genesis(anchor, &prepared, true).await
    }

    /// Writes and anchors a native artifact child without recovery history.
    /// History-enabled repositories must publish through the repository service.
    pub async fn write_child_commit<A>(
        &self,
        anchor: &A,
        write: V2CommitWrite,
    ) -> V2Result<V2StoredCommit>
    where
        A: V2CommitAnchor,
    {
        if self.options.recovery_policy.is_some() {
            return Err(V2FormatError::InvalidRecoveryHistory);
        }
        let current = anchor.read_v2().await?;
        let Some(current) = current else {
            return Err(V2FormatError::MissingAnchor);
        };
        if self.verified_parent_header_facts(&current).await?.1 {
            return Err(V2FormatError::InvalidRecoveryHistory);
        }
        let next_sequence = current
            .sequence
            .checked_next()
            .ok_or(V2FormatError::InvalidHeaderField)?;
        if write
            .sections
            .iter()
            .any(|section| section.section_type == V2SectionType::Recovery)
        {
            return Err(V2FormatError::InvalidRecoveryHistory);
        }
        self.write_commit_with_expected_anchor(anchor, Some(current), next_sequence, write)
            .await
    }

    /// Writes a native artifact child whose sections depend on its generated key.
    /// History-enabled repositories must publish through the repository service.
    pub async fn write_child_commit_with<A, F>(
        &self,
        anchor: &A,
        mut build: F,
    ) -> V2Result<V2StoredCommit>
    where
        A: V2CommitAnchor,
        F: FnMut(&V2CommitKey) -> V2Result<V2CommitWrite>,
    {
        if self.options.recovery_policy.is_some() {
            return Err(V2FormatError::InvalidRecoveryHistory);
        }
        let current = anchor.read_v2().await?;
        let Some(current) = current else {
            return Err(V2FormatError::MissingAnchor);
        };
        if self.verified_parent_header_facts(&current).await?.1 {
            return Err(V2FormatError::InvalidRecoveryHistory);
        }
        let next_sequence = current
            .sequence
            .checked_next()
            .ok_or(V2FormatError::InvalidHeaderField)?;
        self.write_commit_with_expected_anchor_builder(
            anchor,
            Some(current),
            next_sequence,
            None,
            |key| {
                let write = build(key)?;
                if write
                    .sections
                    .iter()
                    .any(|section| section.section_type == V2SectionType::Recovery)
                {
                    return Err(V2FormatError::InvalidRecoveryHistory);
                }
                Ok(write)
            },
        )
        .await
    }

    /// Captures time before asynchronous recovery protection and section encoding.
    pub(super) async fn prepare_child_publication(
        &self,
        parent: &V2AnchorState,
    ) -> V2Result<V2PublicationPlan> {
        let parent_publish_time_ms = self.verified_parent_publish_time(parent).await?;
        let sampled_now_ms = self.publication_now_ms();
        let publish_time_ms =
            super::recovery::choose_publish_time(sampled_now_ms, Some(parent_publish_time_ms))?;
        Ok(V2PublicationPlan {
            sampled_now_ms,
            parent: parent.clone(),
            parent_publish_time_ms,
            publish_time_ms,
        })
    }

    /// Publishes with the exact time already used to prepare authenticated history.
    pub(super) async fn write_prepared_child_commit_with<A, F>(
        &self,
        anchor: &A,
        plan: &V2PublicationPlan,
        build: F,
    ) -> V2Result<V2StoredCommit>
    where
        A: V2CommitAnchor,
        F: FnMut(&V2CommitKey) -> V2Result<V2CommitWrite>,
    {
        if anchor.read_v2().await?.as_ref() != Some(&plan.parent)
            || self.verified_parent_publish_time(&plan.parent).await? != plan.parent_publish_time_ms
        {
            return Err(V2FormatError::StaleAnchor);
        }
        let sequence = plan
            .parent
            .sequence
            .checked_next()
            .ok_or(V2FormatError::InvalidHeaderField)?;
        self.write_commit_with_expected_anchor_builder(
            anchor,
            Some(plan.parent.clone()),
            sequence,
            Some(plan.publish_time_ms),
            build,
        )
        .await
    }

    /// Reads and verifies the commit currently selected by the anchor.
    pub async fn read_anchor_head<A>(&self, anchor: &A) -> V2Result<Option<V2ReplayCommit>>
    where
        A: V2CommitAnchor,
    {
        let Some(state) = anchor.read_v2().await? else {
            return Ok(None);
        };
        self.read_commit_from_anchor_state(&state).await.map(Some)
    }

    // Test inspection only. Production replay retains metadata and never whole commit bodies.
    #[cfg(test)]
    pub(super) async fn load_chain_from_anchor<A: V2CommitAnchor>(
        &self,
        anchor: &A,
    ) -> V2Result<Option<V2CommitChain>> {
        let Some(chain) = self.load_replay_chain_from_anchor(anchor).await? else {
            return Ok(None);
        };
        let mut commits = Vec::new();
        for commit in chain.commits_newest_first {
            let key = &commit.parsed_header.header.self_ref.commit_key;
            let body = self
                .store
                .get_range_at(key, commit.version_id.as_ref(), ByteRange::Full)
                .await
                .map_err(|_| V2FormatError::StorageOperationFailed)?;
            let mut parsed = parse_v2_commit_object(key, body, &self.keyring)?;
            parsed.version_id = commit.version_id;
            commits.push(parsed);
        }
        Ok(Some(V2CommitChain {
            commits_newest_first: commits,
        }))
    }

    /// Range-verifies the anchor-selected chain while retaining only encrypted
    /// index sections required to rebuild trusted namespace state.
    pub async fn load_replay_chain_from_anchor<A>(
        &self,
        anchor: &A,
    ) -> V2Result<Option<V2ReplayChain>>
    where
        A: V2CommitAnchor,
    {
        let Some(anchor_state) = anchor.read_v2().await? else {
            return Ok(None);
        };
        self.load_replay_chain_from_state(&anchor_state)
            .await
            .map(Some)
    }

    /// Range-verifies a supplied anchor state under explicit recovery budgets.
    pub async fn load_replay_chain_from_state(
        &self,
        anchor_state: &V2AnchorState,
    ) -> V2Result<V2ReplayChain> {
        self.load_replay_chain_from_state_with_limits(anchor_state, self.options.replay_limits)
            .await
    }

    pub(crate) async fn load_replay_chain_from_state_with_limits(
        &self,
        anchor_state: &V2AnchorState,
        limits: V2ReplayLimits,
    ) -> V2Result<V2ReplayChain> {
        self.load_replay_chain_with_pending_limit(anchor_state, limits, u64::MAX)
            .await
    }

    pub(super) async fn load_replay_chain_with_pending_limit(
        &self,
        anchor_state: &V2AnchorState,
        limits: V2ReplayLimits,
        pending_limit: u64,
    ) -> V2Result<V2ReplayChain> {
        if limits.max_commits == 0
            || limits.max_total_commit_bytes == 0
            || limits.max_retained_bytes == 0
            || limits.read_chunk_bytes == 0
        {
            return Err(V2FormatError::ReplayBudgetExceeded);
        }

        let mut commits = Vec::new();
        let mut next_key = anchor_state.commit_key.clone();
        let mut next_version = anchor_state.version_id.clone();
        let mut next_digest = Some(anchor_state.body_digest);
        let mut next_sequence = Some(anchor_state.sequence);
        let mut seen = BTreeSet::new();
        let mut total_commit_bytes = 0_u64;
        let mut retained_bytes = 0_u64;
        let mut child_publish_time = None;

        loop {
            if commits.len() >= limits.max_commits {
                return Err(V2FormatError::ReplayBudgetExceeded);
            }
            if !seen.insert(next_key.clone()) {
                return Err(V2FormatError::StaleAnchor);
            }

            let metadata = self
                .store
                .head_at(&next_key, next_version.as_ref())
                .await
                .map_err(|_| V2FormatError::StorageOperationFailed)?;
            total_commit_bytes = total_commit_bytes
                .checked_add(metadata.content_len)
                .filter(|total| *total <= limits.max_total_commit_bytes)
                .ok_or(V2FormatError::ReplayBudgetExceeded)?;

            let parsed_header = self
                .read_commit_header_at(&next_key, next_version.as_ref())
                .await?;
            if let Some(expected_sequence) = next_sequence
                && parsed_header.header.self_ref.sequence != expected_sequence
            {
                return Err(V2FormatError::SelfKeyMismatch);
            }
            if let Some(expected_digest) = next_digest
                && parsed_header.header.body_digest != expected_digest
            {
                return Err(V2FormatError::BodyDigestMismatch);
            }
            validate_v2_commit_object_len(&parsed_header, metadata.content_len)?;
            if let Some(child_time) = child_publish_time {
                super::recovery::validate_parent_time(
                    Some(parsed_header.header.publish_time_ms),
                    child_time,
                )?;
            }
            child_publish_time = Some(parsed_header.header.publish_time_ms);

            let retained_sections = self
                .verify_replay_sections(
                    &next_key,
                    next_version.as_ref(),
                    &parsed_header,
                    &mut retained_bytes,
                    limits,
                    pending_limit,
                )
                .await?;
            let is_root = parsed_header.header.kind == V2CommitKind::Root;
            let parent = parsed_header.header.parent.clone();
            commits.push(V2ReplayCommit {
                parsed_header,
                version_id: next_version.clone(),
                object_len: metadata.content_len,
                retained_sections,
            });
            if is_root {
                // The trusted exact root cuts replay; its predecessor may have
                // been reclaimed. Check that edge at publication/adoption, not
                // by requiring old payload carriers during checkpoint restart.
                break;
            }
            let Some(parent) = parent else {
                return Err(V2FormatError::InvalidHeaderField);
            };
            next_key = parent.commit_key;
            next_version = parent.version_id;
            next_digest = Some(parent.body_digest);
            next_sequence = Some(parent.sequence);
        }

        let head = commits.first().ok_or(V2FormatError::MissingAnchor)?;
        if head.parsed_header.header.signing_key_id != anchor_state.signing_key_id {
            return Err(V2FormatError::StaleAnchor);
        }
        self.remember_verified_publication_time(
            anchor_state,
            head.parsed_header.header.publish_time_ms,
            head.parsed_header
                .header
                .section_index
                .iter()
                .any(|section| section.section_type == V2SectionType::Recovery),
        )?;
        Ok(V2ReplayChain {
            commits_newest_first: commits,
        })
    }

    async fn verify_replay_sections(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        parsed_header: &V2ParsedCommitHeader,
        retained_bytes: &mut u64,
        limits: V2ReplayLimits,
        pending_limit: u64,
    ) -> V2Result<Vec<Option<Bytes>>> {
        let sections_start = u64::try_from(parsed_header.sections_start)
            .map_err(|_| V2FormatError::SectionBounds)?;
        let mut retained_sections = vec![None; parsed_header.header.section_index.len()];

        for (index, section) in parsed_header.header.section_index.iter().enumerate() {
            let retain = matches!(
                section.section_type,
                V2SectionType::IndexRun | V2SectionType::IndexRoot | V2SectionType::Recovery
            );
            if !retain {
                continue;
            }
            if section.section_type == V2SectionType::Recovery
                && section.length > super::recovery::section::MAX_RECOVERY_SECTION_BYTES as u64
            {
                return Err(V2FormatError::RecoveryHistoryCapacity);
            }
            *retained_bytes = retained_bytes
                .checked_add(section.length)
                .filter(|total| *total <= limits.max_retained_bytes)
                .ok_or(V2FormatError::ReplayBudgetExceeded)?;
            if retained_bytes
                .checked_add(section.length.min(limits.read_chunk_bytes))
                .is_none_or(|bytes| bytes > pending_limit)
            {
                return Err(V2FormatError::MaintenanceBudgetExceeded);
            }
            let capacity =
                usize::try_from(section.length).map_err(|_| V2FormatError::ReplayBudgetExceeded)?;
            let mut retained = Vec::with_capacity(capacity);
            let mut section_digest = Sha256Hasher::new();
            let mut offset = sections_start
                .checked_add(section.offset)
                .ok_or(V2FormatError::SectionBounds)?;
            let mut remaining = section.length;

            while remaining > 0 {
                let read_len = remaining.min(limits.read_chunk_bytes);
                let bytes = self
                    .read_commit_range_at(
                        object_id,
                        version_id,
                        ByteRange::Slice {
                            offset,
                            len: read_len,
                        },
                    )
                    .await?;
                if u64::try_from(bytes.len()).ok() != Some(read_len) {
                    return Err(V2FormatError::TruncatedBody);
                }
                section_digest.update(&bytes);
                retained.extend_from_slice(&bytes);
                offset = offset
                    .checked_add(read_len)
                    .ok_or(V2FormatError::SectionBounds)?;
                remaining -= read_len;
            }

            let actual: [u8; 32] = section_digest.finalize();
            if actual != section.digest {
                return Err(V2FormatError::SectionDigestMismatch);
            }
            retained_sections[index] = Some(Bytes::from(retained));
        }
        Ok(retained_sections)
    }

    async fn verify_full_commit_sections(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        parsed_header: &V2ParsedCommitHeader,
    ) -> V2Result<()> {
        let chunk_len = self.options.replay_limits.read_chunk_bytes;
        if chunk_len == 0 {
            return Err(V2FormatError::ReplayBudgetExceeded);
        }
        let sections_start = u64::try_from(parsed_header.sections_start)
            .map_err(|_| V2FormatError::SectionBounds)?;
        let mut body_digest = Sha256Hasher::new();

        for section in &parsed_header.header.section_index {
            let mut section_digest = Sha256Hasher::new();
            let mut offset = sections_start
                .checked_add(section.offset)
                .ok_or(V2FormatError::SectionBounds)?;
            let mut remaining = section.length;
            while remaining > 0 {
                let read_len = remaining.min(chunk_len);
                let bytes = self
                    .read_commit_range_at(
                        object_id,
                        version_id,
                        ByteRange::Slice {
                            offset,
                            len: read_len,
                        },
                    )
                    .await?;
                if u64::try_from(bytes.len()).ok() != Some(read_len) {
                    return Err(V2FormatError::TruncatedBody);
                }
                section_digest.update(&bytes);
                body_digest.update(&bytes);
                offset = offset
                    .checked_add(read_len)
                    .ok_or(V2FormatError::SectionBounds)?;
                remaining -= read_len;
            }
            let actual: [u8; 32] = section_digest.finalize();
            if actual != section.digest {
                return Err(V2FormatError::SectionDigestMismatch);
            }
        }

        let actual: [u8; 32] = body_digest.finalize();
        if actual != parsed_header.header.body_digest {
            return Err(V2FormatError::BodyDigestMismatch);
        }
        Ok(())
    }

    /// Exact immutable facts without downloading unrelated metadata sections.
    pub(super) async fn read_commit_facts_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
    ) -> V2Result<V2ReplayCommit> {
        let limits = self.options.replay_limits;
        if limits.max_commits == 0
            || limits.max_total_commit_bytes == 0
            || limits.max_retained_bytes == 0
            || limits.read_chunk_bytes == 0
        {
            return Err(V2FormatError::ReplayBudgetExceeded);
        }
        let metadata = self
            .store
            .head_at(object_id, version_id)
            .await
            .map_err(|_| V2FormatError::StorageOperationFailed)?;
        if metadata.content_len > limits.max_total_commit_bytes {
            return Err(V2FormatError::ReplayBudgetExceeded);
        }
        if metadata.object_id != *object_id
            || version_id.is_some() && metadata.version_id.as_ref() != version_id
        {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        let parsed_header = self.read_commit_header_at(object_id, version_id).await?;
        validate_v2_commit_object_len(&parsed_header, metadata.content_len)?;
        let retained_sections = vec![None; parsed_header.header.section_index.len()];
        Ok(V2ReplayCommit {
            parsed_header,
            version_id: version_id.cloned(),
            object_len: metadata.content_len,
            retained_sections,
        })
    }

    /// Verifies one required metadata range, checking its bound before the read.
    pub(super) async fn read_metadata_section(
        &self,
        commit: &V2ReplayCommit,
        ordinal: u32,
        pending_limit: u64,
    ) -> V2Result<Bytes> {
        let descriptor = commit
            .parsed_header
            .header
            .section_index
            .get(ordinal as usize)
            .ok_or(V2FormatError::SectionBounds)?;
        let format_limit = match descriptor.section_type {
            V2SectionType::IndexRun => super::index_run::V2_INDEX_RUN_MAX_OBJECT_BYTES,
            V2SectionType::IndexRoot => super::index_root::V2_INDEX_ROOT_MAX_BYTES,
            V2SectionType::Recovery => super::recovery::section::MAX_RECOVERY_SECTION_BYTES,
            _ => return Err(V2FormatError::UnsupportedSection),
        };
        let chunk = self.options.replay_limits.read_chunk_bytes;
        if descriptor.section_type == V2SectionType::Recovery
            && descriptor.length > format_limit as u64
        {
            return Err(V2FormatError::RecoveryHistoryCapacity);
        }
        if metadata_section_buffer_bytes(descriptor.length, chunk)? > pending_limit
            || descriptor.length > format_limit as u64
        {
            return Err(V2FormatError::MaintenanceBudgetExceeded);
        }
        let mut offset = (commit.parsed_header.sections_start as u64)
            .checked_add(descriptor.offset)
            .ok_or(V2FormatError::SectionBounds)?;
        let mut remaining = descriptor.length;
        let capacity = usize::try_from(remaining).map_err(|_| V2FormatError::SectionBounds)?;
        let mut stored = Vec::with_capacity(capacity);
        let mut digest = Sha256Hasher::new();
        while remaining > 0 {
            let length = remaining.min(chunk);
            let bytes = self
                .read_commit_range_at(
                    &commit.parsed_header.header.self_ref.commit_key,
                    commit.version_id.as_ref(),
                    ByteRange::Slice {
                        offset,
                        len: length,
                    },
                )
                .await?;
            if bytes.len() as u64 != length {
                return Err(V2FormatError::TruncatedBody);
            }
            digest.update(&bytes);
            stored.extend_from_slice(&bytes);
            offset = offset
                .checked_add(length)
                .ok_or(V2FormatError::SectionBounds)?;
            remaining -= length;
        }
        let actual: [u8; 32] = digest.finalize();
        if actual != descriptor.digest {
            return Err(V2FormatError::SectionDigestMismatch);
        }
        Ok(Bytes::from(stored))
    }

    pub(super) async fn read_replay_commit_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
    ) -> V2Result<V2ReplayCommit> {
        let limits = self.options.replay_limits;
        if limits.max_commits == 0
            || limits.max_total_commit_bytes == 0
            || limits.max_retained_bytes == 0
            || limits.read_chunk_bytes == 0
        {
            return Err(V2FormatError::ReplayBudgetExceeded);
        }
        let metadata = self
            .store
            .head_at(object_id, version_id)
            .await
            .map_err(|_| V2FormatError::StorageOperationFailed)?;
        if metadata.content_len > limits.max_total_commit_bytes {
            return Err(V2FormatError::ReplayBudgetExceeded);
        }
        let parsed_header = self.read_commit_header_at(object_id, version_id).await?;
        validate_v2_commit_object_len(&parsed_header, metadata.content_len)?;
        let mut retained_bytes = 0_u64;
        let retained_sections = self
            .verify_replay_sections(
                object_id,
                version_id,
                &parsed_header,
                &mut retained_bytes,
                limits,
                u64::MAX,
            )
            .await?;
        Ok(V2ReplayCommit {
            parsed_header,
            version_id: version_id.cloned(),
            object_len: metadata.content_len,
            retained_sections,
        })
    }

    /// Reads and verifies only the signed commit header at a key and version.
    pub(crate) async fn read_commit_header_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
    ) -> V2Result<V2ParsedCommitHeader> {
        if self.options.provider_profile == V2ProviderProfile::RetainedVersionObjectLock
            && version_id.is_none()
        {
            return Err(V2FormatError::InvalidHeaderField);
        }
        // The configured upload mode is a writer preference, not a promise
        // about every historical object. Probe the authenticated fixed header
        // first so compact single-PUT commits never incur a failed 64 KiB read.
        let prefix = self
            .store
            .get_range_at(
                object_id,
                version_id,
                ByteRange::Slice {
                    offset: 0,
                    len: V2_HEADER_META_LEN as u64,
                },
            )
            .await
            .map_err(|_| V2FormatError::StorageOperationFailed)?;
        let header_span_len = v2_commit_header_span_len(&prefix)?;
        let header_bytes = if header_span_len == V2_HEADER_META_LEN {
            prefix
        } else {
            let remaining_len = header_span_len
                .checked_sub(V2_HEADER_META_LEN)
                .ok_or(V2FormatError::HeaderTooLarge)?;
            let remaining = self
                .store
                .get_range_at(
                    object_id,
                    version_id,
                    ByteRange::Slice {
                        offset: V2_HEADER_META_LEN as u64,
                        len: remaining_len as u64,
                    },
                )
                .await
                .map_err(|_| V2FormatError::StorageOperationFailed)?;
            let mut bytes = Vec::with_capacity(header_span_len);
            bytes.extend_from_slice(&prefix);
            bytes.extend_from_slice(&remaining);
            Bytes::from(bytes)
        };
        let parsed = parse_v2_commit_header(object_id, &header_bytes, &self.keyring)?;
        super::recovery::validate_parent_time(None, parsed.header.publish_time_ms)?;
        Ok(parsed)
    }

    /// Reads commit bytes from a key and version without requiring a full object read.
    pub(crate) async fn read_commit_range_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        range: ByteRange,
    ) -> V2Result<Bytes> {
        if self.options.provider_profile == V2ProviderProfile::RetainedVersionObjectLock
            && version_id.is_none()
        {
            return Err(V2FormatError::InvalidHeaderField);
        }
        self.store
            .get_range_at(object_id, version_id, range)
            .await
            .map_err(|_| V2FormatError::StorageOperationFailed)
    }

    async fn read_commit_from_anchor_state(
        &self,
        state: &V2AnchorState,
    ) -> V2Result<V2ReplayCommit> {
        let parsed = self
            .read_replay_commit_at(&state.commit_key, state.version_id.as_ref())
            .await?;
        if parsed.parsed_header.header.self_ref.sequence != state.sequence {
            return Err(V2FormatError::SelfKeyMismatch);
        }
        if parsed.parsed_header.header.body_digest != state.body_digest {
            return Err(V2FormatError::BodyDigestMismatch);
        }
        Ok(parsed)
    }

    /// Strictly adopts an uploaded but unanchored child commit after an
    /// ambiguous upload result.
    pub async fn adopt_unanchored_child<A>(
        &self,
        anchor: &A,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
    ) -> V2Result<V2StoredCommit>
    where
        A: V2CommitAnchor,
    {
        let Some(current) = anchor.read_v2().await? else {
            return Err(V2FormatError::MissingAnchor);
        };
        // History publication needs the private captured predecessor and exact
        // graph-coverage proof. Generic ambiguous artifact adoption cannot supply it.
        if self.options.recovery_policy.is_some() {
            return Err(V2FormatError::InvalidRecoveryHistory);
        }
        let accepted_header = self
            .read_commit_header_at(&current.commit_key, current.version_id.as_ref())
            .await?;
        if accepted_header.header.body_digest != current.body_digest
            || accepted_header.header.self_ref.sequence != current.sequence
            || accepted_header.header.signing_key_id != current.signing_key_id
        {
            return Err(V2FormatError::StaleAnchor);
        }
        if accepted_header
            .header
            .section_index
            .iter()
            .any(|section| section.section_type == V2SectionType::Recovery)
        {
            return Err(V2FormatError::InvalidRecoveryHistory);
        }
        let parsed = self.read_replay_commit_at(object_id, version_id).await?;
        if parsed
            .parsed_header
            .header
            .section_index
            .iter()
            .any(|section| section.section_type == V2SectionType::Recovery)
        {
            return Err(V2FormatError::InvalidRecoveryHistory);
        }
        self.verify_full_commit_sections(object_id, version_id, &parsed.parsed_header)
            .await?;
        let header = &parsed.parsed_header.header;
        let Some(parent) = header.parent.as_ref() else {
            return Err(V2FormatError::InvalidHeaderField);
        };
        if header.self_ref.sequence <= current.sequence {
            return Err(V2FormatError::StaleAnchor);
        }
        if parent.sequence != current.sequence
            || parent.commit_key != current.commit_key
            || parent.body_digest != current.body_digest
            || parent.version_id != current.version_id
        {
            return Err(V2FormatError::StaleAnchor);
        }

        let parent_time = self.verified_parent_publish_time(&current).await?;
        super::recovery::validate_parent_time(Some(parent_time), header.publish_time_ms)?;
        super::recovery::validate_publication_time(
            self.publication_now_ms(),
            header.publish_time_ms,
        )?;
        let verified_retain_until_ms = self
            .verify_existing_commit_postconditions(object_id, version_id)
            .await?;
        let commit_key = V2CommitKey::parse(object_id)?;
        let version_id = version_id.cloned();
        let object_len = parsed.object_len;
        let sections_start = u64::try_from(parsed.parsed_header.sections_start)
            .map_err(|_| V2FormatError::SectionBounds)?;
        let anchor_state = V2AnchorState {
            sequence: header.self_ref.sequence,
            commit_key: object_id.clone(),
            body_digest: header.body_digest,
            version_id: version_id.clone(),
            signing_key_id: header.signing_key_id.clone(),
            format_ref: current.format_ref.clone(),
        };
        self.remember_verified_publication_time(&anchor_state, header.publish_time_ms, false)?;
        anchor
            .compare_and_advance_v2(Some(&current), anchor_state.clone())
            .await?;
        Ok(V2StoredCommit {
            verified_retain_until_ms,
            publish_time_ms: header.publish_time_ms,
            anchor_state,
            commit_key,
            version_id,
            object_len,
            sections_start,
        })
    }

    /// Adopts a child returned by this store after publication through a
    /// temporary anchor bound to `expected_parent`.
    ///
    /// Unlike ambiguous-upload recovery, this path does not re-read payload
    /// sections. The typed result was produced only after the original write's
    /// length, visibility, and provider-profile checks succeeded. The real
    /// anchor CAS supplies the remaining stale-writer exclusion.
    pub(crate) async fn adopt_verified_unanchored_child<A>(
        &self,
        anchor: &A,
        expected_parent: &V2AnchorState,
        uploaded: &V2StoredCommit,
        history_uncertainty_ms: Option<u32>,
    ) -> V2Result<V2StoredCommit>
    where
        A: V2CommitAnchor,
    {
        let current = anchor.read_v2().await?;
        if current.as_ref() != Some(expected_parent)
            || expected_parent.sequence.checked_next() != Some(uploaded.anchor_state.sequence)
            || uploaded.commit_key.sequence != uploaded.anchor_state.sequence
            || uploaded.commit_key.object_id != uploaded.anchor_state.commit_key
            || uploaded.version_id != uploaded.anchor_state.version_id
            || uploaded.anchor_state.format_ref != expected_parent.format_ref
            || uploaded.anchor_state.format_ref != self.options.format_ref
            || uploaded.sections_start > uploaded.object_len
        {
            return Err(V2FormatError::StaleAnchor);
        }
        let parent_time = self.verified_parent_publish_time(expected_parent).await?;
        super::recovery::validate_parent_time(Some(parent_time), uploaded.publish_time_ms)?;
        super::recovery::validate_publication_time(
            self.publication_now_ms(),
            uploaded.publish_time_ms,
        )?;
        let verified_retain_until_ms = self
            .verify_existing_commit_postconditions(
                &uploaded.commit_key.object_id,
                uploaded.version_id.as_ref(),
            )
            .await?;
        if self
            .verified_parent_header_facts(&uploaded.anchor_state)
            .await?
            .0
            != uploaded.publish_time_ms
        {
            return Err(V2FormatError::StaleAnchor);
        }
        if let Some(uncertainty) = history_uncertainty_ms {
            super::recovery::validate_history_publication_freshness(
                self.publication_now_ms(),
                uploaded.publish_time_ms,
                uncertainty,
            )?;
        }
        let advance = anchor
            .compare_and_advance_v2(Some(expected_parent), uploaded.anchor_state.clone())
            .await;
        match advance {
            Ok(accepted) if accepted == uploaded.anchor_state => {}
            result => {
                // A lost CAS reply may still cover an accepted publication, and
                // the update may still land after any plain re-read. Settle it
                // under a fencing write: the state that write observes is final
                // because the earlier request can no longer apply. If even the
                // fencing write fails, the outcome is unknown and mutations
                // stay blocked until explicit reconciliation.
                match anchor.fence_and_read_v2().await {
                    Ok(Some(accepted)) if accepted == uploaded.anchor_state => {}
                    Ok(Some(current)) if current == *expected_parent => {
                        return Err(result.err().unwrap_or(V2FormatError::StaleAnchor));
                    }
                    _ => return Err(V2FormatError::AnchorReconciliationRequired),
                }
            }
        }
        let mut accepted = uploaded.clone();
        accepted.verified_retain_until_ms = verified_retain_until_ms;
        Ok(accepted)
    }

    /// Verifies a recovery bundle and recreates a missing anchor from it.
    pub async fn recreate_anchor_from_recovery_bundle<A>(
        &self,
        anchor: &A,
        bundle: &V2RecoveryBundle,
        min_sequence: Sequence,
    ) -> V2Result<V2ReplayChain>
    where
        A: V2CommitAnchor,
    {
        if bundle.repository_id.as_ref() != Some(&self.options.repository_id)
            || bundle.anchor.sequence < bundle.weak_subjectivity_floor_sequence
            || bundle.anchor.sequence < min_sequence
        {
            return Err(V2FormatError::RecoveryBundleRequired);
        }
        if anchor.read_v2().await?.is_some() {
            return Err(V2FormatError::StaleAnchor);
        }
        let chain = self.load_replay_chain_from_state(&bundle.anchor).await?;
        anchor
            .compare_and_advance_v2(None, bundle.anchor.clone())
            .await?;
        Ok(chain)
    }

    async fn write_commit_with_expected_anchor<A>(
        &self,
        anchor: &A,
        expected: Option<V2AnchorState>,
        sequence: Sequence,
        write: V2CommitWrite,
    ) -> V2Result<V2StoredCommit>
    where
        A: V2CommitAnchor,
    {
        self.write_commit_with_expected_anchor_builder(anchor, expected, sequence, None, |_| {
            Ok(write.clone())
        })
        .await
    }

    async fn write_commit_with_expected_anchor_builder<A, F>(
        &self,
        anchor: &A,
        expected: Option<V2AnchorState>,
        sequence: Sequence,
        selected_time: Option<i64>,
        mut build: F,
    ) -> V2Result<V2StoredCommit>
    where
        A: V2CommitAnchor,
        F: FnMut(&V2CommitKey) -> V2Result<V2CommitWrite>,
    {
        let parent = expected.as_ref().map(|state| V2CommitParentRef {
            sequence: state.sequence,
            commit_key: state.commit_key.clone(),
            body_digest: state.body_digest,
            version_id: state.version_id.clone(),
        });

        let parent_time = match expected.as_ref() {
            Some(anchor) => Some(self.verified_parent_publish_time(anchor).await?),
            None => None,
        };
        let publish_time_ms = match selected_time {
            Some(chosen) => {
                super::recovery::validate_parent_time(parent_time, chosen)?;
                super::recovery::validate_publication_time(self.publication_now_ms(), chosen)?;
                chosen
            }
            None => super::recovery::choose_publish_time(self.publication_now_ms(), parent_time)?,
        };
        let mut last_collision = false;
        for _ in 0..MAX_RANDOM_KEY_ATTEMPTS {
            let commit_key = generate_v2_commit_key(sequence)?;
            let write = build(&commit_key)?;
            let commit_retention = super::recovery::policy::physical_retention_for_deadline(
                strongest_retention_policy(self.options.retention, write.retention),
                write.required_retain_until_ms,
                self.publication_now_ms(),
            )?;
            let commit_legal_hold = strongest_legal_hold(self.options.legal_hold, write.legal_hold);
            self.validate_write_protection_profile(commit_retention, commit_legal_hold)?;
            let (section_index, section_region) = build_section_region(&write.sections)?;
            let body_digest = body_digest_for_v2_sections(&section_index, &section_region)?;
            let header = self.build_header(
                &commit_key,
                parent.clone(),
                &write,
                section_index.clone(),
                body_digest,
                publish_time_ms,
            )?;
            let object_body = header.encode_object(&section_region)?;
            let object_len =
                u64::try_from(object_body.len()).map_err(|_| V2FormatError::SectionBounds)?;
            let sections_start = object_len
                .checked_sub(
                    u64::try_from(section_region.len())
                        .map_err(|_| V2FormatError::SectionBounds)?,
                )
                .ok_or(V2FormatError::SectionBounds)?;
            let put = self
                .put_commit_object(
                    &commit_key.object_id,
                    object_body,
                    commit_retention,
                    commit_legal_hold,
                )
                .await;
            let metadata = match put {
                Ok(metadata) => metadata,
                Err(StorageError::AlreadyExists(_)) => {
                    last_collision = true;
                    continue;
                }
                Err(_) => return Err(V2FormatError::StorageOperationFailed),
            };
            let verified = self
                .verify_commit_postconditions(
                    &commit_key.object_id,
                    &metadata,
                    V2WritePostconditions::commit(
                        object_len,
                        commit_retention,
                        commit_legal_hold,
                        write.required_retain_until_ms,
                    ),
                )
                .await?;
            let version_id = verified.version_id.clone();
            let anchor_state = V2AnchorState {
                sequence,
                commit_key: commit_key.object_id.clone(),
                body_digest,
                version_id: version_id.clone(),
                signing_key_id: header.signing_key_id,
                format_ref: self.options.format_ref.clone(),
            };
            // Cache verified header facts before CAS; cache failure must not turn
            // an accepted publication into an apparently unaccepted write failure.
            self.remember_verified_publication_time(
                &anchor_state,
                publish_time_ms,
                section_index
                    .iter()
                    .any(|section| section.section_type == V2SectionType::Recovery),
            )?;
            anchor
                .compare_and_advance_v2(expected.as_ref(), anchor_state.clone())
                .await?;
            return Ok(V2StoredCommit {
                verified_retain_until_ms: verified.retain_until_ms,
                publish_time_ms,
                anchor_state,
                commit_key,
                version_id,
                object_len,
                sections_start,
            });
        }

        if last_collision {
            Err(V2FormatError::RandomnessUnavailable)
        } else {
            Err(V2FormatError::StorageOperationFailed)
        }
    }

    fn build_header(
        &self,
        commit_key: &V2CommitKey,
        parent: Option<V2CommitParentRef>,
        write: &V2CommitWrite,
        section_index: Vec<V2SectionDescriptor>,
        body_digest: [u8; 32],
        publish_time_ms: i64,
    ) -> V2Result<V2CommitHeader> {
        let header = V2CommitHeader {
            self_ref: V2CommitSelfRef {
                sequence: commit_key.sequence,
                commit_key: commit_key.object_id.clone(),
            },
            parent,
            publish_time_ms,
            kind: write.kind,
            algorithms: Default::default(),
            keyring_envelope_ref: self.options.keyring_envelope_ref.clone(),
            section_index,
            body_digest,
            signature: [0_u8; 64],
            signing_key_id: self
                .keyring
                .primary_key_id(rs3_types::KeyPurpose::CheckpointSigning)?,
        };
        validate_commit_section_semantics(&header)?;
        header.sign_with_keyring(&self.keyring)
    }

    /// Encrypts and uploads one immutable standalone payload without touching repository state.
    pub(crate) async fn write_standalone_streaming_payload<St>(
        &self,
        write: V2StandalonePayloadWrite<St>,
    ) -> V2Result<V2StoredStandalonePayload>
    where
        St: Stream<Item = crate::Result<Bytes>> + Unpin + Send,
    {
        let V2StandalonePayloadWrite {
            object_id,
            expected_plaintext_len,
            max_plaintext_len,
            payload_segment_size,
            mut stream,
            retention,
            legal_hold,
            multipart_part_size,
            cancellation,
        } = write;
        self.validate_write_protection_profile(retention, legal_hold)?;
        if cancellation.is_cancelled() {
            return Err(V2FormatError::ObjectBodyReadFailed);
        }
        let repository_context = super::service::packed::repository_context_from_refs(
            &self.options.repository_id,
            &self.options.keyring_envelope_ref,
        )
        .map_err(|_| V2FormatError::InvalidHeaderField)?;
        let payload_sealer = SegmentedPayloadSealer::new(
            &self.keyring,
            payload_segment_size,
            repository_context,
            super::standalone::standalone_carrier_id(&object_id)?,
            1,
        )
        .map_err(|_| V2FormatError::InvalidHeaderField)?;
        let mut assembler = MultipartObjectAssembler::new(multipart_part_size)?;
        let mut multipart = self
            .create_standalone_multipart_upload(&object_id, retention, legal_hold)
            .await
            .map_err(storage_to_v2)?;
        let mut object_digest = Sha256Hasher::new();
        if cancellation.is_cancelled() {
            abort_v2_commit_multipart(multipart, "standalone_cancelled").await;
            return Err(V2FormatError::ObjectBodyReadFailed);
        }

        let mut plaintext_md5 = rs3_crypto::Md5Hasher::new();
        let mut plaintext_seen = 0_u64;
        let mut next_segment_index = 0_usize;
        let mut segment = Vec::with_capacity(payload_segment_size);
        let mut pending_segment: Option<(usize, Vec<u8>)> = None;
        let segment_auth = StreamingPayloadSegmentAuth {
            keyring: &self.keyring,
            payload_sealer: &payload_sealer,
            payload_id: &object_id,
        };
        loop {
            let next_chunk = match tokio::select! {
                () = cancellation.cancelled() => {
                    abort_v2_commit_multipart(multipart, "standalone_cancelled").await;
                    return Err(V2FormatError::ObjectBodyReadFailed);
                }
                next = next_nonempty_stream_chunk(
                    &mut stream,
                    self.options.stream_read_stall_timeout,
                ) => next,
            } {
                Ok(next_chunk) => next_chunk,
                Err(_elapsed) => {
                    abort_v2_commit_multipart(multipart, "standalone_stream_timeout").await;
                    return Err(V2FormatError::ObjectBodyReadFailed);
                }
            };
            let Some(chunk) = next_chunk else {
                break;
            };
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(crate::RepositoryError::ObjectBodyReadFailed) => {
                    abort_v2_commit_multipart(multipart, "standalone_stream_read").await;
                    return Err(V2FormatError::ObjectBodyReadFailed);
                }
                Err(_error) => {
                    abort_v2_commit_multipart(multipart, "standalone_stream_read").await;
                    return Err(V2FormatError::StorageOperationFailed);
                }
            };
            plaintext_seen = plaintext_seen
                .checked_add(u64::try_from(chunk.len()).map_err(|_| V2FormatError::SectionBounds)?)
                .ok_or(V2FormatError::SectionBounds)?;
            if plaintext_seen > max_plaintext_len {
                abort_v2_commit_multipart(multipart, "standalone_plaintext_length").await;
                return Err(if expected_plaintext_len.is_some() {
                    V2FormatError::ObjectLengthMismatch
                } else {
                    V2FormatError::ObjectTooLarge
                });
            }
            plaintext_md5.update(&chunk);
            let mut remaining = chunk.as_ref();
            while !remaining.is_empty() {
                let take = payload_segment_size
                    .saturating_sub(segment.len())
                    .min(remaining.len());
                segment.extend_from_slice(&remaining[..take]);
                remaining = &remaining[take..];
                if segment.len() == payload_segment_size {
                    if let Some((ready_index, ready_segment)) = pending_segment.take()
                        && push_standalone_payload_segment(
                            &segment_auth,
                            &mut StandalonePayloadSegmentWriter {
                                object_digest: &mut object_digest,
                                assembler: &mut assembler,
                                multipart: &mut multipart,
                            },
                            ready_index,
                            &ready_segment,
                            false,
                        )
                        .await
                        .is_err()
                    {
                        abort_v2_commit_multipart(multipart, "standalone_payload_segment").await;
                        return Err(V2FormatError::StorageOperationFailed);
                    }
                    pending_segment = Some((next_segment_index, std::mem::take(&mut segment)));
                    next_segment_index = next_segment_index
                        .checked_add(1)
                        .ok_or(V2FormatError::SectionBounds)?;
                    segment = Vec::with_capacity(payload_segment_size);
                }
            }
        }
        if expected_plaintext_len.is_some_and(|expected| plaintext_seen != expected) {
            abort_v2_commit_multipart(multipart, "standalone_plaintext_length").await;
            return Err(V2FormatError::ObjectLengthMismatch);
        }
        if !segment.is_empty() {
            if let Some((ready_index, ready_segment)) = pending_segment.take()
                && push_standalone_payload_segment(
                    &segment_auth,
                    &mut StandalonePayloadSegmentWriter {
                        object_digest: &mut object_digest,
                        assembler: &mut assembler,
                        multipart: &mut multipart,
                    },
                    ready_index,
                    &ready_segment,
                    false,
                )
                .await
                .is_err()
            {
                abort_v2_commit_multipart(multipart, "standalone_payload_segment").await;
                return Err(V2FormatError::StorageOperationFailed);
            }
            if push_standalone_payload_segment(
                &segment_auth,
                &mut StandalonePayloadSegmentWriter {
                    object_digest: &mut object_digest,
                    assembler: &mut assembler,
                    multipart: &mut multipart,
                },
                next_segment_index,
                &segment,
                true,
            )
            .await
            .is_err()
            {
                abort_v2_commit_multipart(multipart, "standalone_payload_segment").await;
                return Err(V2FormatError::StorageOperationFailed);
            }
        } else if let Some((ready_index, ready_segment)) = pending_segment.take()
            && push_standalone_payload_segment(
                &segment_auth,
                &mut StandalonePayloadSegmentWriter {
                    object_digest: &mut object_digest,
                    assembler: &mut assembler,
                    multipart: &mut multipart,
                },
                ready_index,
                &ready_segment,
                true,
            )
            .await
            .is_err()
        {
            abort_v2_commit_multipart(multipart, "standalone_payload_segment").await;
            return Err(V2FormatError::StorageOperationFailed);
        }

        let payload_layout = payload_sealer
            .layout_reference(plaintext_seen)
            .map_err(|_| V2FormatError::InvalidHeaderField)?;
        let object_len = payload_sealer
            .sealed_len_for_plaintext_len(plaintext_seen)
            .map_err(|_| V2FormatError::SectionBounds)?;
        if cancellation.is_cancelled() {
            abort_v2_commit_multipart(multipart, "standalone_cancelled").await;
            return Err(V2FormatError::ObjectBodyReadFailed);
        }
        if assembler.flush_final_part(&mut multipart).await.is_err() {
            abort_v2_commit_multipart(multipart, "standalone_final_part").await;
            return Err(V2FormatError::StorageOperationFailed);
        }
        if cancellation.is_cancelled() {
            abort_v2_commit_multipart(multipart, "standalone_cancelled").await;
            return Err(V2FormatError::ObjectBodyReadFailed);
        }
        let metadata = assembler.complete(multipart).await.map_err(storage_to_v2)?;
        if metadata.object_id != object_id || metadata.content_len != object_len {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        let retention_version = match self.options.provider_profile {
            V2ProviderProfile::RetainedVersionObjectLock => Some(
                metadata
                    .version_id
                    .as_ref()
                    .ok_or(V2FormatError::ProviderProfileFailed)?,
            ),
            V2ProviderProfile::Dev | V2ProviderProfile::AtomicCreate => {
                metadata.version_id.as_ref()
            }
        };
        let required_retain_until_ms = required_retain_until_ms(retention);
        if required_retain_until_ms.is_some() {
            let retention = retention.ok_or(V2FormatError::ProviderProfileFailed)?;
            self.store
                .extend_retention_at(&object_id, retention_version, retention)
                .await
                .map_err(storage_to_v2)?;
        }
        let object_digest: [u8; 32] = object_digest.finalize();
        let verified = self
            .verify_commit_postconditions(
                &object_id,
                &metadata,
                V2WritePostconditions::verified_object(
                    object_len,
                    retention,
                    required_retain_until_ms,
                    legal_hold,
                    object_digest,
                ),
            )
            .await?;
        Ok(V2StoredStandalonePayload {
            etag: rs3_types::ObjectEtag::single(plaintext_md5.finalize()),
            object_id,
            version_id: verified.version_id,
            object_len,
            object_digest,
            payload_layout,
        })
    }

    async fn create_standalone_multipart_upload(
        &self,
        object_id: &BackendObjectId,
        retention: Option<RetentionPolicy>,
        legal_hold: Option<LegalHoldStatus>,
    ) -> rs3_storage::Result<Box<dyn rs3_storage::BlobMultipartUpload>> {
        if self.options.provider_profile == V2ProviderProfile::RetainedVersionObjectLock {
            match self.store.head(object_id).await {
                Ok(_) => return Err(StorageError::AlreadyExists(object_id.clone())),
                Err(StorageError::NotFound(_)) => {}
                Err(error) => return Err(error),
            }
        }
        self.store
            .create_multipart_upload(
                object_id,
                PutOptions {
                    retention,
                    legal_hold,
                    content_type: Some("application/vnd.rs3.payload.v3".to_owned()),
                    do_not_recreate: self.options.provider_profile
                        != V2ProviderProfile::RetainedVersionObjectLock,
                },
            )
            .await
    }

    async fn put_commit_object(
        &self,
        object_id: &BackendObjectId,
        body: Bytes,
        retention: Option<RetentionPolicy>,
        legal_hold: Option<LegalHoldStatus>,
    ) -> rs3_storage::Result<BlobMetadata> {
        if self.options.provider_profile == V2ProviderProfile::RetainedVersionObjectLock {
            match self.store.head(object_id).await {
                Ok(_) => return Err(StorageError::AlreadyExists(object_id.clone())),
                Err(StorageError::NotFound(_)) => {}
                Err(error) => return Err(error),
            }
        }
        self.store
            .put(
                object_id,
                body,
                PutOptions {
                    retention,
                    legal_hold,
                    content_type: Some(V2_COMMIT_CONTENT_TYPE.to_owned()),
                    do_not_recreate: self.options.provider_profile
                        != V2ProviderProfile::RetainedVersionObjectLock,
                },
            )
            .await
    }

    async fn verify_commit_postconditions(
        &self,
        object_id: &BackendObjectId,
        metadata: &BlobMetadata,
        postconditions: V2WritePostconditions,
    ) -> V2Result<BlobMetadata> {
        let exact = self
            .verify_commit_protection_postconditions(object_id, metadata, postconditions)
            .await?;
        let version_id = exact.version_id.as_ref();
        if let Some(expected_digest) = postconditions.expected_stored_digest {
            self.verify_exact_stored_object_digest(
                object_id,
                version_id,
                postconditions.expected_object_len,
                expected_digest,
            )
            .await?;
        } else {
            let visible = self
                .store
                .get_range_at(
                    object_id,
                    version_id,
                    ByteRange::Slice { offset: 0, len: 1 },
                )
                .await
                .map_err(|_| V2FormatError::ProviderProfileFailed)?;
            if visible.len() != 1 {
                return Err(V2FormatError::ProviderProfileFailed);
            }
        }
        Ok(exact)
    }

    async fn verify_commit_protection_postconditions(
        &self,
        object_id: &BackendObjectId,
        metadata: &BlobMetadata,
        postconditions: V2WritePostconditions,
    ) -> V2Result<BlobMetadata> {
        if metadata.content_len != postconditions.expected_object_len
            || postconditions.expected_object_len == 0
        {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        let exact = self
            .store
            .head_at(object_id, metadata.version_id.as_ref())
            .await
            .map_err(|_| V2FormatError::ProviderProfileFailed)?;
        if exact.object_id != *object_id
            || exact.version_id != metadata.version_id
            || exact.content_len != postconditions.expected_object_len
        {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        if postconditions
            .required_retain_until_ms
            .is_some_and(|required| exact.retain_until_ms.is_none_or(|actual| actual < required))
        {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        match self.options.provider_profile {
            V2ProviderProfile::Dev | V2ProviderProfile::AtomicCreate => Ok(exact),
            V2ProviderProfile::RetainedVersionObjectLock => {
                if postconditions.required_retention.is_none()
                    && postconditions.required_legal_hold != Some(LegalHoldStatus::On)
                {
                    return Err(V2FormatError::ProviderProfileFailed);
                }
                if exact.version_id.is_none() {
                    return Err(V2FormatError::ProviderProfileFailed);
                }
                if let Some(retention) = postconditions.required_retention
                    && !retention_satisfies(exact.retention.as_ref(), &retention)
                {
                    return Err(V2FormatError::ProviderProfileFailed);
                }
                if postconditions.required_legal_hold == Some(LegalHoldStatus::On)
                    && exact.legal_hold != Some(LegalHoldStatus::On)
                {
                    return Err(V2FormatError::ProviderProfileFailed);
                }
                Ok(exact)
            }
        }
    }

    async fn verify_exact_stored_object_digest(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        expected_object_len: u64,
        expected_digest: [u8; 32],
    ) -> V2Result<()> {
        let mut digest = Sha256Hasher::new();
        let mut reader = self
            .store
            .open_bounded_full_at(object_id, version_id, expected_object_len)
            .await
            .map_err(|_| V2FormatError::ProviderProfileFailed)?;
        if reader.exact_len() != expected_object_len {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        let mut bytes_read = 0_u64;
        while let Some(bytes) = reader
            .next_chunk()
            .await
            .map_err(|_| V2FormatError::ProviderProfileFailed)?
        {
            let chunk_len =
                u64::try_from(bytes.len()).map_err(|_| V2FormatError::ProviderProfileFailed)?;
            if chunk_len == 0 || bytes.len() > rs3_storage::MAX_BLOB_READ_CHUNK_BYTES {
                return Err(V2FormatError::ProviderProfileFailed);
            }
            bytes_read = bytes_read
                .checked_add(chunk_len)
                .ok_or(V2FormatError::ProviderProfileFailed)?;
            if bytes_read > expected_object_len {
                return Err(V2FormatError::ProviderProfileFailed);
            }
            digest.update(&bytes);
        }
        let actual_digest: [u8; 32] = digest.finalize();
        if bytes_read != expected_object_len || actual_digest != expected_digest {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        Ok(())
    }

    async fn verify_existing_commit_postconditions(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
    ) -> V2Result<Option<i64>> {
        match self.options.provider_profile {
            V2ProviderProfile::Dev | V2ProviderProfile::AtomicCreate => Ok(None),
            V2ProviderProfile::RetainedVersionObjectLock => {
                if self.options.retention.is_none()
                    && self.options.legal_hold != Some(LegalHoldStatus::On)
                {
                    return Err(V2FormatError::ProviderProfileFailed);
                }
                let Some(version_id) = version_id else {
                    return Err(V2FormatError::ProviderProfileFailed);
                };
                let metadata = self
                    .store
                    .head_at(object_id, Some(version_id))
                    .await
                    .map_err(|_| V2FormatError::ProviderProfileFailed)?;
                if metadata.object_id != *object_id
                    || metadata.version_id.as_ref() != Some(version_id)
                    || metadata.content_len == 0
                {
                    return Err(V2FormatError::ProviderProfileFailed);
                }
                if let Some(retention) = self.options.retention
                    && !retention_satisfies(metadata.retention.as_ref(), &retention)
                {
                    return Err(V2FormatError::ProviderProfileFailed);
                }
                self.store
                    .get_range_at(
                        object_id,
                        Some(version_id),
                        ByteRange::Slice { offset: 0, len: 1 },
                    )
                    .await
                    .map_err(|_| V2FormatError::ProviderProfileFailed)?;
                Ok(metadata.retain_until_ms)
            }
        }
    }
}

fn build_section_region(
    sections: &[V2CommitSection],
) -> V2Result<(Vec<V2SectionDescriptor>, Bytes)> {
    let mut section_index = Vec::with_capacity(sections.len());
    let mut region = Vec::new();
    for section in sections {
        let offset = u64::try_from(region.len()).map_err(|_| V2FormatError::SectionBounds)?;
        region.extend_from_slice(&section.bytes);
        let length =
            u64::try_from(section.bytes.len()).map_err(|_| V2FormatError::SectionBounds)?;
        section_index.push(V2SectionDescriptor {
            section_type: section.section_type,
            offset,
            length,
            flags: section.flags,
            digest: digest_v2_section(&section.bytes),
        });
    }
    Ok((section_index, Bytes::from(region)))
}

async fn abort_v2_commit_multipart(multipart: Box<dyn BlobMultipartUpload>, phase: &'static str) {
    if let Err(error) = multipart.abort().await {
        record_multipart_abort_failure(&error, phase);
    }
}

fn record_multipart_abort_failure(error: &StorageError, phase: &'static str) {
    let error_class = storage_error_class(error);
    metrics::counter!(
        "rs3_repository_v2_multipart_abort_failures_total",
        "phase" => phase,
        "error_class" => error_class,
    )
    .increment(1);
    tracing::warn!(
        target: "rs3_repository", operation = "v2_multipart_abort",
        phase, error_class, result = "failed",
        "failed to abort incomplete multipart upload",
    );
}

fn storage_error_class(error: &StorageError) -> &'static str {
    match error {
        StorageError::NotFound(_) => "not_found",
        StorageError::AlreadyExists(_) => "already_exists",
        StorageError::InvalidRange => "invalid_range",
        StorageError::Provider(_) => "provider",
        StorageError::RetentionBlocked => "retention_blocked",
        StorageError::RetentionExtensionUnsupported => "retention_extension_unsupported",
        StorageError::VersionUnsupported => "version_unsupported",
        StorageError::MissingVersionId(_) => "missing_version_id",
        StorageError::LegalHoldBlocked => "legal_hold_blocked",
        StorageError::LegalHoldUnsupported => "legal_hold_unsupported",
        StorageError::MultipartUnsupported => "multipart_unsupported",
        StorageError::PagedListingUnsupported => "paged_listing_unsupported",
        StorageError::BoundedReadUnsupported => "bounded_read_unsupported",
        StorageError::InvalidListPage => "invalid_list_page",
        StorageError::BoundedReadExceeded { .. } => "bounded_read_exceeded",
    }
}

fn storage_to_v2(_error: StorageError) -> V2FormatError {
    V2FormatError::StorageOperationFailed
}

struct StreamingPayloadSegmentAuth<'a> {
    keyring: &'a KeyRing,
    payload_sealer: &'a SegmentedPayloadSealer,
    payload_id: &'a BackendObjectId,
}

struct StandalonePayloadSegmentWriter<'a> {
    object_digest: &'a mut Sha256Hasher,
    assembler: &'a mut MultipartObjectAssembler,
    multipart: &'a mut Box<dyn BlobMultipartUpload>,
}

async fn push_standalone_payload_segment(
    auth: &StreamingPayloadSegmentAuth<'_>,
    writer: &mut StandalonePayloadSegmentWriter<'_>,
    segment_index: usize,
    plaintext: &[u8],
    is_final: bool,
) -> V2Result<()> {
    let ciphertext = auth
        .payload_sealer
        .seal_segment(
            auth.keyring,
            auth.payload_id,
            segment_index,
            plaintext,
            is_final,
        )
        .map_err(|_| V2FormatError::StorageOperationFailed)?;
    writer.object_digest.update(&ciphertext);
    writer
        .assembler
        .push_bytes(writer.multipart, &ciphertext)
        .await
        .map_err(storage_to_v2)
}

struct MultipartObjectAssembler {
    part_size: usize,
    current_part_index: usize,
    current_part: Vec<u8>,
}

impl MultipartObjectAssembler {
    fn new(part_size: usize) -> V2Result<Self> {
        if part_size == 0 {
            return Err(V2FormatError::SectionBounds);
        }
        Ok(Self {
            part_size,
            current_part_index: 0,
            current_part: Vec::with_capacity(part_size),
        })
    }

    async fn push_bytes(
        &mut self,
        upload: &mut Box<dyn BlobMultipartUpload>,
        mut bytes: &[u8],
    ) -> rs3_storage::Result<()> {
        while !bytes.is_empty() {
            let take = (self.part_size - self.current_part.len()).min(bytes.len());
            self.current_part.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.current_part.len() == self.part_size {
                let part = Bytes::from(std::mem::take(&mut self.current_part));
                upload.put_part(self.current_part_index, part).await?;
                self.current_part_index =
                    self.current_part_index.checked_add(1).ok_or_else(|| {
                        StorageError::Provider("multipart part index overflow".to_owned())
                    })?;
                self.current_part = Vec::with_capacity(self.part_size);
            }
        }
        Ok(())
    }

    async fn flush_final_part(
        &mut self,
        upload: &mut Box<dyn BlobMultipartUpload>,
    ) -> rs3_storage::Result<()> {
        if !self.current_part.is_empty() {
            upload
                .put_part(
                    self.current_part_index,
                    Bytes::from(std::mem::take(&mut self.current_part)),
                )
                .await?;
        }
        Ok(())
    }

    async fn complete(
        self,
        upload: Box<dyn BlobMultipartUpload>,
    ) -> rs3_storage::Result<BlobMetadata> {
        upload.complete().await
    }
}

fn strongest_legal_hold(
    left: Option<LegalHoldStatus>,
    right: Option<LegalHoldStatus>,
) -> Option<LegalHoldStatus> {
    if left == Some(LegalHoldStatus::On) || right == Some(LegalHoldStatus::On) {
        Some(LegalHoldStatus::On)
    } else {
        left.or(right)
    }
}

fn current_time_ms() -> i64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis();
    i64::try_from(millis).unwrap_or(i64::MAX)
}

fn required_retain_until_ms(retention: Option<RetentionPolicy>) -> Option<i64> {
    let retention = retention?;
    if retention.mode == rs3_types::RetentionMode::None || retention.retain_days == 0 {
        return None;
    }
    current_time_ms().checked_add(i64::from(retention.retain_days).checked_mul(86_400_000)?)
}

#[cfg(test)]
mod tests {
    use super::next_nonempty_stream_chunk;
    use bytes::Bytes;
    use futures_util::{StreamExt, stream};
    use std::time::Duration;

    #[tokio::test(start_paused = true)]
    async fn empty_stream_chunks_do_not_refresh_the_progress_deadline() {
        let delayed_empty = stream::once(async {
            tokio::time::sleep(Duration::from_millis(600)).await;
            Ok::<Bytes, crate::RepositoryError>(Bytes::new())
        });
        let stalled = stream::pending::<crate::Result<Bytes>>();
        let mut stream = Box::pin(delayed_empty.chain(stalled));
        let started = tokio::time::Instant::now();

        let result = next_nonempty_stream_chunk(&mut stream, Duration::from_secs(1)).await;

        assert!(result.is_err());
        assert_eq!(started.elapsed(), Duration::from_secs(1));
    }
}
