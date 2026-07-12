//! Preview v2 commit-store workflow.

use super::cbor;
use super::commit::{
    V2_COMMIT_CONTENT_TYPE, V2_HEADER_META_LEN, V2_MAX_HEADER_SIZE,
    V2_SECTION_FLAG_MUST_UNDERSTAND, V2CommitHeader, V2CommitKey, V2CommitKind, V2CommitParentRef,
    V2CommitSelfRef, V2KeyringEnvelopeRef, V2ParsedCommit, V2ParsedCommitHeader,
    V2SectionDescriptor, V2SectionType, V2UploadMode, body_digest_for_v2_sections,
    digest_v2_section, generate_v2_commit_key, parse_v2_commit_header, parse_v2_commit_object,
    v2_commit_header_span_len, validate_commit_section_semantics, validate_v2_commit_object_len,
};
use super::error::{V2FormatError, V2Result};
use super::format::V2FormatRef;
use super::provider::V2ProviderProfile;
use crate::payload::SegmentedPayloadSealer;
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use rs3_crypto::KeyRing;
use rs3_storage::{
    BlobMetadata, BlobMultipartUpload, BlobRead, BlobStore, ByteRange, PutOptions, StorageError,
};
use rs3_types::{
    BackendObjectId, BackendVersionId, KeyId, LegalHoldStatus, RepositoryId, RetentionPolicy,
    Sequence,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_RANDOM_KEY_ATTEMPTS: usize = 3;

/// Maximum commits traversed during one bounded recovery replay by default.
pub const DEFAULT_V2_REPLAY_MAX_COMMITS: usize = 4_096;
/// Maximum cumulative commit-object bytes verified during one recovery replay.
pub const DEFAULT_V2_REPLAY_MAX_TOTAL_COMMIT_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
/// Maximum encrypted index bytes retained in memory during one recovery replay.
pub const DEFAULT_V2_REPLAY_MAX_RETAINED_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum bytes held by one recovery range read.
pub const DEFAULT_V2_REPLAY_READ_CHUNK_BYTES: u64 = 8 * 1024 * 1024;
/// Maximum one complete commit body a legacy full-body reader may allocate.
pub const DEFAULT_V2_FULL_COMMIT_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum cumulative commit bodies a legacy full-chain reader may retain.
pub const DEFAULT_V2_FULL_CHAIN_MAX_BYTES: u64 = 128 * 1024 * 1024;

/// Schema marker for trusted v2 recovery bundles.
pub const V2_RESTORE_BUNDLE_SCHEMA: &str = "rs3.restore-bundle.v2-preview.v1";

/// Default idle time allowed between streaming request-body chunks.
pub const DEFAULT_V2_STREAM_READ_STALL_TIMEOUT: Duration = Duration::from_secs(30);

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
    /// Commit upload mode to use for new writes.
    pub upload_mode: V2UploadMode,
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
            upload_mode: V2UploadMode::MultipartPadded,
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
            replay_limits: V2ReplayLimits::default(),
        }
    }

    /// Uses a specific upload mode for new commits.
    pub const fn with_upload_mode(mut self, upload_mode: V2UploadMode) -> Self {
        self.upload_mode = upload_mode;
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
    /// Maximum one complete commit body a legacy full-body reader may allocate.
    pub max_full_commit_bytes: u64,
    /// Maximum cumulative commit bodies a legacy full-chain reader may retain.
    pub max_full_chain_bytes: u64,
}

impl Default for V2ReplayLimits {
    fn default() -> Self {
        Self {
            max_commits: DEFAULT_V2_REPLAY_MAX_COMMITS,
            max_total_commit_bytes: DEFAULT_V2_REPLAY_MAX_TOTAL_COMMIT_BYTES,
            max_retained_bytes: DEFAULT_V2_REPLAY_MAX_RETAINED_BYTES,
            read_chunk_bytes: DEFAULT_V2_REPLAY_READ_CHUNK_BYTES,
            max_full_commit_bytes: DEFAULT_V2_FULL_COMMIT_MAX_BYTES,
            max_full_chain_bytes: DEFAULT_V2_FULL_CHAIN_MAX_BYTES,
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
}

impl V2CommitWrite {
    /// Creates a snapshot commit write request.
    pub fn snapshot(sections: Vec<V2CommitSection>) -> Self {
        Self {
            kind: V2CommitKind::Root,
            sections,
            retention: None,
            legal_hold: None,
        }
    }

    /// Creates a delta commit write request.
    pub fn delta(sections: Vec<V2CommitSection>) -> Self {
        Self {
            kind: V2CommitKind::Delta,
            sections,
            retention: None,
            legal_hold: None,
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
}

/// Streaming payload included as the first section of a delta commit.
pub(crate) struct V2StreamingPayloadWrite<St, Finalize, Output> {
    pub(crate) payload_id: BackendObjectId,
    pub(crate) payload_sealer: SegmentedPayloadSealer,
    pub(crate) expected_plaintext_len: Option<u64>,
    pub(crate) max_plaintext_len: Option<u64>,
    pub(crate) payload_segment_size: usize,
    pub(crate) stream: St,
    pub(crate) finalize: Finalize,
    pub(crate) retention: Option<RetentionPolicy>,
    pub(crate) legal_hold: Option<LegalHoldStatus>,
    pub(crate) multipart_part_size: usize,
    pub(crate) _output: PhantomData<fn() -> Output>,
}

/// Facts available once a streaming payload has reached EOF.
#[derive(Clone, Debug)]
pub(crate) struct V2StreamingPayloadFinalizationInput {
    pub(crate) plaintext_len: u64,
    pub(crate) payload_len: u64,
    pub(crate) payload_digest: [u8; 32],
    pub(crate) payload_header: crate::payload::SegmentedPayloadHeader,
}

/// Finalized framed index-run bytes and caller-owned output for a streamed payload.
#[derive(Clone, Debug)]
pub(crate) struct V2FinalizedStreamingPayloadWrite<Output> {
    pub(crate) index_run: Bytes,
    pub(crate) output: Output,
}

/// Complete authenticated facts for one independently uploaded payload object.
pub(crate) struct V2StoredStandalonePayload {
    pub(crate) object_id: BackendObjectId,
    pub(crate) version_id: Option<BackendVersionId>,
    pub(crate) object_len: u64,
    pub(crate) object_digest: [u8; 32],
    pub(crate) payload_header: crate::payload::SegmentedPayloadHeader,
}

pub(crate) struct V2StandalonePayloadWrite<St> {
    pub(crate) object_id: BackendObjectId,
    pub(crate) plaintext_len: u64,
    pub(crate) payload_segment_size: usize,
    pub(crate) stream: St,
    pub(crate) retention: Option<RetentionPolicy>,
    pub(crate) legal_hold: Option<LegalHoldStatus>,
    pub(crate) multipart_part_size: usize,
    pub(crate) cancellation: Arc<V2StandaloneUploadCancellation>,
}

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
    ) -> Self {
        Self {
            expected_object_len,
            required_retention,
            required_retain_until_ms: None,
            required_legal_hold,
            expected_stored_digest: None,
        }
    }

    fn standalone(
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

/// Result of a v2 commit write accepted by the anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2StoredCommit {
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

pub(crate) struct V2StoredStreamingCommit<Output> {
    pub(crate) stored: V2StoredCommit,
    pub(crate) payload_section: V2SectionDescriptor,
    pub(crate) index_run_section: V2SectionDescriptor,
    pub(crate) output: Output,
}

/// Verified v2 commit chain, newest commit first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2CommitChain {
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
    /// Optional active format blob digest.
    pub format_digest: Option<[u8; 32]>,
    /// Optional active format generation.
    pub format_generation: Option<u64>,
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
            format_digest: self.format_digest.map(encode_digest_32),
            format_generation: self.format_generation,
            exported_at_ms: self.exported_at_ms,
            offline_signature_payload_hex,
            offline_signature: self.offline_signature.as_ref().map(hex::encode),
            repository_salt_digest,
        };
        wire.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for V2RecoveryBundle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = V2RecoveryBundleWire::deserialize(deserializer)?;
        if wire.schema != V2_RESTORE_BUNDLE_SCHEMA {
            return Err(de::Error::custom(format!(
                "unsupported restore bundle schema {}",
                wire.schema
            )));
        }

        let repository_id = wire
            .repository
            .as_ref()
            .map(|repository| RepositoryId::new(repository.id.clone()))
            .transpose()
            .map_err(de::Error::custom)?;
        let repository_salt_digest = wire
            .repository_salt_digest
            .as_deref()
            .or_else(|| {
                wire.repository
                    .as_ref()
                    .and_then(|repository| repository.salt_digest.as_deref())
            })
            .map(|digest| decode_digest_32("repository salt digest", digest))
            .transpose()?;
        let anchor: V2AnchorState = wire.anchor.try_into().map_err(de::Error::custom)?;
        if let Some(format_generation) = wire.format_generation
            && format_generation != anchor.format_ref.generation
        {
            return Err(de::Error::custom(
                "bundle format_generation does not match anchor format generation",
            ));
        }
        if let Some(format_digest) = wire.format_digest.as_ref()
            && format_digest != &anchor.format_ref.digest
        {
            return Err(de::Error::custom(
                "bundle format_digest does not match anchor format digest",
            ));
        }
        let format_digest = wire
            .format_digest
            .as_deref()
            .map(|digest| decode_digest_32("format digest", digest))
            .transpose()?;
        let offline_signature = wire
            .offline_signature
            .as_deref()
            .map(|signature| {
                hex::decode(signature)
                    .map_err(|_| de::Error::custom("offline signature must be hex encoded"))
            })
            .transpose()?;

        Ok(Self {
            repository_id,
            repository_salt_digest,
            anchor,
            format_digest,
            format_generation: wire.format_generation,
            weak_subjectivity_floor_sequence: Sequence::new(wire.weak_subjectivity_floor_sequence),
            exported_at_ms: wire.exported_at_ms,
            offline_signature,
        })
    }
}

#[derive(Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
struct V2RecoveryBundleRepositoryWire {
    id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    salt_digest: Option<String>,
}

impl V2RecoveryBundle {
    /// Creates a recovery bundle from an accepted anchor state.
    pub fn from_anchor(anchor: V2AnchorState, floor: Sequence) -> Self {
        let format_digest = hex::decode(&anchor.format_ref.digest)
            .ok()
            .and_then(|digest| digest.try_into().ok());
        let format_generation = Some(anchor.format_ref.generation);
        Self {
            repository_id: None,
            repository_salt_digest: None,
            anchor,
            format_digest,
            format_generation,
            weak_subjectivity_floor_sequence: floor,
            exported_at_ms: current_time_ms(),
            offline_signature: None,
        }
    }

    /// Returns the canonical bytes covered by the offline recovery signature.
    pub fn offline_signature_payload(&self) -> V2Result<Vec<u8>> {
        let repository_id = self
            .repository_id
            .as_ref()
            .ok_or(V2FormatError::RecoveryBundleRequired)?;
        Ok(canonical_recovery_signature_payload(
            repository_id,
            &self.anchor,
        ))
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

fn canonical_recovery_signature_payload(
    repository_id: &RepositoryId,
    anchor: &V2AnchorState,
) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::write_array_len(&mut out, 8);
    cbor::write_text(&mut out, "rs3:v2-recovery-bundle-offline-signature:v1");
    cbor::write_text(&mut out, repository_id.as_str());
    cbor::write_u64(&mut out, anchor.sequence.get());
    cbor::write_text(&mut out, anchor.commit_key.as_str());
    write_optional_text(
        &mut out,
        anchor.version_id.as_ref().map(BackendVersionId::as_str),
    );
    cbor::write_bytes(&mut out, &anchor.body_digest);
    cbor::write_text(&mut out, anchor.signing_key_id.as_str());
    cbor::write_array_len(&mut out, 4);
    cbor::write_u64(&mut out, anchor.format_ref.generation);
    cbor::write_text(&mut out, &anchor.format_ref.digest);
    cbor::write_text(&mut out, anchor.format_ref.object_id.as_str());
    write_optional_text(
        &mut out,
        anchor
            .format_ref
            .version_id
            .as_ref()
            .map(BackendVersionId::as_str),
    );
    out
}

fn write_optional_text(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => cbor::write_text(out, value),
        None => cbor::write_null(out),
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
        }
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

    /// Writes and anchors the required genesis snapshot commit.
    pub async fn write_genesis_snapshot<A>(&self, anchor: &A) -> V2Result<V2StoredCommit>
    where
        A: V2CommitAnchor,
    {
        let current = anchor.read_v2().await?;
        if current.is_some() {
            return Err(V2FormatError::StaleAnchor);
        }
        let write = V2CommitWrite::snapshot(vec![V2CommitSection::new(
            V2SectionType::IndexSnapshot,
            V2_SECTION_FLAG_MUST_UNDERSTAND,
            Bytes::new(),
        )]);
        self.write_commit_with_expected_anchor(anchor, None, Sequence::new(1), write)
            .await
    }

    /// Writes and anchors a child commit from the current anchor.
    pub async fn write_child_commit<A>(
        &self,
        anchor: &A,
        write: V2CommitWrite,
    ) -> V2Result<V2StoredCommit>
    where
        A: V2CommitAnchor,
    {
        let current = anchor.read_v2().await?;
        let Some(current) = current else {
            return Err(V2FormatError::MissingAnchor);
        };
        let next_sequence = current
            .sequence
            .checked_next()
            .ok_or(V2FormatError::InvalidHeaderField)?;
        self.write_commit_with_expected_anchor(anchor, Some(current), next_sequence, write)
            .await
    }

    /// Writes and anchors a child commit whose sections depend on the generated commit key.
    pub async fn write_child_commit_with<A, F>(
        &self,
        anchor: &A,
        build: F,
    ) -> V2Result<V2StoredCommit>
    where
        A: V2CommitAnchor,
        F: FnMut(&V2CommitKey) -> V2Result<V2CommitWrite>,
    {
        let current = anchor.read_v2().await?;
        let Some(current) = current else {
            return Err(V2FormatError::MissingAnchor);
        };
        let next_sequence = current
            .sequence
            .checked_next()
            .ok_or(V2FormatError::InvalidHeaderField)?;
        self.write_commit_with_expected_anchor_builder(anchor, Some(current), next_sequence, build)
            .await
    }

    /// Writes and anchors a child commit whose first payload section is streamed.
    pub(crate) async fn write_child_commit_with_streaming_payload<A, F, St, Finalize, Output>(
        &self,
        anchor: &A,
        build: F,
    ) -> V2Result<V2StoredStreamingCommit<Output>>
    where
        A: V2CommitAnchor,
        F: FnOnce(&V2CommitKey) -> V2Result<V2StreamingPayloadWrite<St, Finalize, Output>>,
        Finalize: FnOnce(
            V2StreamingPayloadFinalizationInput,
        ) -> V2Result<V2FinalizedStreamingPayloadWrite<Output>>,
        St: Stream<Item = crate::Result<Bytes>> + Unpin + Send,
    {
        let current = anchor.read_v2().await?;
        let Some(current) = current else {
            return Err(V2FormatError::MissingAnchor);
        };
        let next_sequence = current
            .sequence
            .checked_next()
            .ok_or(V2FormatError::InvalidHeaderField)?;
        self.write_commit_streaming_payload_with_expected_anchor(
            anchor,
            current,
            next_sequence,
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

    /// Reads and verifies a commit chain from the anchor to the nearest snapshot.
    pub async fn load_chain_from_anchor<A>(&self, anchor: &A) -> V2Result<Option<V2CommitChain>>
    where
        A: V2CommitAnchor,
    {
        let Some(anchor_state) = anchor.read_v2().await? else {
            return Ok(None);
        };
        self.load_chain_from_state(&anchor_state).await.map(Some)
    }

    /// Reads and verifies a commit chain from a supplied anchor state.
    pub async fn load_chain_from_state(
        &self,
        anchor_state: &V2AnchorState,
    ) -> V2Result<V2CommitChain> {
        let limits = self.options.replay_limits;
        if limits.max_commits == 0
            || limits.read_chunk_bytes == 0
            || limits.max_full_commit_bytes == 0
            || limits.max_full_chain_bytes == 0
        {
            return Err(V2FormatError::ReplayBudgetExceeded);
        }
        let mut commits = Vec::new();
        let mut next_key = anchor_state.commit_key.clone();
        let mut next_version = anchor_state.version_id.clone();
        let mut next_digest = Some(anchor_state.body_digest);
        let mut next_sequence = Some(anchor_state.sequence);
        let mut seen = BTreeSet::new();
        let mut full_chain_bytes = 0_u64;

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
            if metadata.content_len > limits.max_full_commit_bytes {
                return Err(V2FormatError::ReplayBudgetExceeded);
            }
            full_chain_bytes = full_chain_bytes
                .checked_add(metadata.content_len)
                .filter(|total| *total <= limits.max_full_chain_bytes)
                .ok_or(V2FormatError::ReplayBudgetExceeded)?;
            let parsed = self
                .read_commit_at_with_len(&next_key, next_version.as_ref(), metadata.content_len)
                .await?;
            if let Some(expected_sequence) = next_sequence
                && parsed.parsed_header.header.self_ref.sequence != expected_sequence
            {
                return Err(V2FormatError::SelfKeyMismatch);
            }
            if let Some(expected_digest) = next_digest
                && parsed.parsed_header.header.body_digest != expected_digest
            {
                return Err(V2FormatError::BodyDigestMismatch);
            }
            let is_root = parsed.parsed_header.header.kind == V2CommitKind::Root;
            let parent = parsed.parsed_header.header.parent.clone();
            commits.push(parsed);
            if is_root {
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

        Ok(V2CommitChain {
            commits_newest_first: commits,
        })
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
        if limits.max_commits == 0
            || limits.max_total_commit_bytes == 0
            || limits.max_retained_bytes == 0
            || limits.read_chunk_bytes == 0
            || limits.max_full_commit_bytes == 0
            || limits.max_full_chain_bytes == 0
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

            let retained_sections = self
                .verify_replay_sections(
                    &next_key,
                    next_version.as_ref(),
                    &parsed_header,
                    &mut retained_bytes,
                    limits,
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
    ) -> V2Result<Vec<Option<Bytes>>> {
        let sections_start = u64::try_from(parsed_header.sections_start)
            .map_err(|_| V2FormatError::SectionBounds)?;
        let mut retained_sections = vec![None; parsed_header.header.section_index.len()];

        for (index, section) in parsed_header.header.section_index.iter().enumerate() {
            let retain = matches!(
                section.section_type,
                V2SectionType::IndexDelta
                    | V2SectionType::IndexSnapshot
                    | V2SectionType::IndexRun
                    | V2SectionType::IndexRoot
            );
            if !retain {
                continue;
            }
            *retained_bytes = retained_bytes
                .checked_add(section.length)
                .filter(|total| *total <= limits.max_retained_bytes)
                .ok_or(V2FormatError::ReplayBudgetExceeded)?;
            let capacity =
                usize::try_from(section.length).map_err(|_| V2FormatError::ReplayBudgetExceeded)?;
            let mut retained = Vec::with_capacity(capacity);
            let mut section_digest = Sha256::new();
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

            let actual: [u8; 32] = section_digest.finalize().into();
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
        let mut body_digest = Sha256::new();

        for section in &parsed_header.header.section_index {
            let mut section_digest = Sha256::new();
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
            let actual: [u8; 32] = section_digest.finalize().into();
            if actual != section.digest {
                return Err(V2FormatError::SectionDigestMismatch);
            }
        }

        let actual: [u8; 32] = body_digest.finalize().into();
        if actual != parsed_header.header.body_digest {
            return Err(V2FormatError::BodyDigestMismatch);
        }
        Ok(())
    }

    /// Reads and verifies a single commit at a key and optional provider version.
    pub async fn read_commit_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
    ) -> V2Result<V2ParsedCommit> {
        if self.options.provider_profile == V2ProviderProfile::RetainedVersionObjectLock
            && version_id.is_none()
        {
            return Err(V2FormatError::InvalidHeaderField);
        }
        let content_len = self
            .store
            .head_at(object_id, version_id)
            .await
            .map_err(|_| V2FormatError::StorageOperationFailed)?
            .content_len;
        if content_len > self.options.replay_limits.max_full_commit_bytes {
            return Err(V2FormatError::ReplayBudgetExceeded);
        }
        self.read_commit_at_with_len(object_id, version_id, content_len)
            .await
    }

    async fn read_commit_at_with_len(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        content_len: u64,
    ) -> V2Result<V2ParsedCommit> {
        if self.options.provider_profile == V2ProviderProfile::RetainedVersionObjectLock
            && version_id.is_none()
        {
            return Err(V2FormatError::InvalidHeaderField);
        }
        let chunk_len = self.options.replay_limits.read_chunk_bytes;
        if chunk_len == 0 || content_len > self.options.replay_limits.max_full_commit_bytes {
            return Err(V2FormatError::ReplayBudgetExceeded);
        }
        let capacity =
            usize::try_from(content_len).map_err(|_| V2FormatError::ReplayBudgetExceeded)?;
        let mut body = Vec::with_capacity(capacity);
        let mut offset = 0_u64;
        while offset < content_len {
            let len = content_len.saturating_sub(offset).min(chunk_len);
            let bytes = self
                .read_commit_range_at(object_id, version_id, ByteRange::Slice { offset, len })
                .await?;
            if u64::try_from(bytes.len()).ok() != Some(len) {
                return Err(V2FormatError::TruncatedBody);
            }
            body.extend_from_slice(&bytes);
            offset = offset
                .checked_add(len)
                .ok_or(V2FormatError::SectionBounds)?;
        }
        let mut parsed = parse_v2_commit_object(object_id, Bytes::from(body), &self.keyring)?;
        parsed.version_id = version_id.cloned();
        Ok(parsed)
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
            || limits.max_full_commit_bytes == 0
            || limits.max_full_chain_bytes == 0
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
        parse_v2_commit_header(object_id, &header_bytes, &self.keyring)
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

    /// Opens exact commit bytes without buffering the complete requested range.
    pub(crate) async fn open_commit_range_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        range: ByteRange,
    ) -> V2Result<Box<dyn BlobRead>> {
        if self.options.provider_profile == V2ProviderProfile::RetainedVersionObjectLock
            && version_id.is_none()
        {
            return Err(V2FormatError::InvalidHeaderField);
        }
        self.store
            .open_range_at(object_id, version_id, range)
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
        let parsed = self.read_replay_commit_at(object_id, version_id).await?;
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

        self.verify_existing_commit_postconditions(object_id, version_id)
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
        anchor
            .compare_and_advance_v2(Some(&current), anchor_state.clone())
            .await?;

        Ok(V2StoredCommit {
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
        self.verify_existing_commit_postconditions(
            &uploaded.commit_key.object_id,
            uploaded.version_id.as_ref(),
        )
        .await?;
        anchor
            .compare_and_advance_v2(Some(expected_parent), uploaded.anchor_state.clone())
            .await?;
        Ok(uploaded.clone())
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
        self.write_commit_with_expected_anchor_builder(anchor, expected, sequence, |_| {
            Ok(write.clone())
        })
        .await
    }

    async fn write_commit_with_expected_anchor_builder<A, F>(
        &self,
        anchor: &A,
        expected: Option<V2AnchorState>,
        sequence: Sequence,
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

        let mut last_collision = false;
        for _ in 0..MAX_RANDOM_KEY_ATTEMPTS {
            let commit_key = generate_v2_commit_key(sequence)?;
            let write = build(&commit_key)?;
            let commit_retention =
                strongest_retention_policy(self.options.retention, write.retention);
            let commit_legal_hold = strongest_legal_hold(self.options.legal_hold, write.legal_hold);
            let (section_index, section_region) = build_section_region(&write.sections)?;
            let body_digest = body_digest_for_v2_sections(&section_index, &section_region)?;
            let upload_mode = if write
                .sections
                .iter()
                .any(|section| section.section_type == V2SectionType::IndexRun)
            {
                V2UploadMode::SinglePut
            } else {
                self.options.upload_mode
            };
            let header = self.build_header(
                &commit_key,
                parent.clone(),
                &write,
                section_index.clone(),
                body_digest,
                upload_mode,
            )?;
            let object_body = header.encode_object(upload_mode, &section_region)?;
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
            let version_id = self
                .verify_commit_postconditions(
                    &commit_key.object_id,
                    &metadata,
                    V2WritePostconditions::commit(object_len, commit_retention, commit_legal_hold),
                )
                .await?;
            let anchor_state = V2AnchorState {
                sequence,
                commit_key: commit_key.object_id.clone(),
                body_digest,
                version_id: version_id.clone(),
                signing_key_id: header.signing_key_id,
                format_ref: self.options.format_ref.clone(),
            };
            anchor
                .compare_and_advance_v2(expected.as_ref(), anchor_state.clone())
                .await?;
            return Ok(V2StoredCommit {
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

    async fn write_commit_streaming_payload_with_expected_anchor<A, F, St, Finalize, Output>(
        &self,
        anchor: &A,
        expected: V2AnchorState,
        sequence: Sequence,
        build: F,
    ) -> V2Result<V2StoredStreamingCommit<Output>>
    where
        A: V2CommitAnchor,
        F: FnOnce(&V2CommitKey) -> V2Result<V2StreamingPayloadWrite<St, Finalize, Output>>,
        Finalize: FnOnce(
            V2StreamingPayloadFinalizationInput,
        ) -> V2Result<V2FinalizedStreamingPayloadWrite<Output>>,
        St: Stream<Item = crate::Result<Bytes>> + Unpin + Send,
    {
        let parent = V2CommitParentRef {
            sequence: expected.sequence,
            commit_key: expected.commit_key.clone(),
            body_digest: expected.body_digest,
            version_id: expected.version_id.clone(),
        };
        let commit_key = generate_v2_commit_key(sequence)?;
        let write = build(&commit_key)?;
        let commit_retention = strongest_retention_policy(self.options.retention, write.retention);
        let commit_legal_hold = strongest_legal_hold(self.options.legal_hold, write.legal_hold);
        let written = self
            .put_streaming_payload_commit_object(
                &commit_key,
                Some(parent),
                write,
                commit_retention,
                commit_legal_hold,
            )
            .await?;
        let output = written.output;
        let version_id = self
            .verify_commit_postconditions(
                &commit_key.object_id,
                &written.metadata,
                V2WritePostconditions::commit(
                    written.object_len,
                    commit_retention,
                    commit_legal_hold,
                ),
            )
            .await?;
        let anchor_state = V2AnchorState {
            sequence,
            commit_key: commit_key.object_id.clone(),
            body_digest: written.body_digest,
            version_id: version_id.clone(),
            signing_key_id: written.signing_key_id,
            format_ref: self.options.format_ref.clone(),
        };
        anchor
            .compare_and_advance_v2(Some(&expected), anchor_state.clone())
            .await?;
        Ok(V2StoredStreamingCommit {
            stored: V2StoredCommit {
                anchor_state,
                commit_key,
                version_id,
                object_len: written.object_len,
                sections_start: V2_MAX_HEADER_SIZE as u64,
            },
            payload_section: written.payload_section,
            index_run_section: written.index_run_section,
            output,
        })
    }

    fn build_header(
        &self,
        commit_key: &V2CommitKey,
        parent: Option<V2CommitParentRef>,
        write: &V2CommitWrite,
        section_index: Vec<V2SectionDescriptor>,
        body_digest: [u8; 32],
        upload_mode: V2UploadMode,
    ) -> V2Result<V2CommitHeader> {
        let header = V2CommitHeader {
            self_ref: V2CommitSelfRef {
                sequence: commit_key.sequence,
                commit_key: commit_key.object_id.clone(),
            },
            parent,
            publish_time_ms: current_time_ms(),
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
        header.sign_with_keyring(&self.keyring, upload_mode)
    }

    async fn put_streaming_payload_commit_object<St, Finalize, Output>(
        &self,
        commit_key: &V2CommitKey,
        parent: Option<V2CommitParentRef>,
        mut write: V2StreamingPayloadWrite<St, Finalize, Output>,
        retention: Option<RetentionPolicy>,
        legal_hold: Option<LegalHoldStatus>,
    ) -> V2Result<V2StreamingCommitWriteResult<Output>>
    where
        St: Stream<Item = crate::Result<Bytes>> + Unpin + Send,
        Finalize: FnOnce(
            V2StreamingPayloadFinalizationInput,
        ) -> V2Result<V2FinalizedStreamingPayloadWrite<Output>>,
    {
        if self.options.upload_mode != V2UploadMode::MultipartPadded {
            return Err(V2FormatError::UnsupportedUploadMode);
        }
        let mut assembler = MultipartCommitAssembler::new(write.multipart_part_size)?;
        let mut multipart = self
            .create_commit_multipart_upload(&commit_key.object_id, retention, legal_hold)
            .await
            .map_err(storage_to_v2)?;
        let mut body_digest = Sha256::new();
        let mut payload_digest = Sha256::new();
        let payload_header = write.payload_sealer.header();
        body_digest.update(&payload_header);
        payload_digest.update(&payload_header);
        if assembler
            .push_section_bytes(&mut multipart, &payload_header)
            .await
            .is_err()
        {
            abort_v2_commit_multipart(multipart, "payload_header").await;
            return Err(V2FormatError::StorageOperationFailed);
        }

        let mut plaintext_seen = 0_u64;
        let mut next_segment_index = 0_usize;
        let mut segment = Vec::with_capacity(write.payload_segment_size);
        let mut pending_segment: Option<(usize, Vec<u8>)> = None;
        let segment_auth = StreamingPayloadSegmentAuth {
            keyring: &self.keyring,
            payload_sealer: &write.payload_sealer,
            payload_id: &write.payload_id,
        };
        loop {
            let next_chunk = match tokio::time::timeout(
                self.options.stream_read_stall_timeout,
                write.stream.next(),
            )
            .await
            {
                Ok(next_chunk) => next_chunk,
                Err(_elapsed) => {
                    abort_v2_commit_multipart(multipart, "stream_timeout").await;
                    return Err(V2FormatError::ObjectBodyReadFailed);
                }
            };
            let Some(chunk) = next_chunk else {
                break;
            };
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(crate::RepositoryError::ObjectBodyReadFailed) => {
                    abort_v2_commit_multipart(multipart, "stream_read").await;
                    return Err(V2FormatError::ObjectBodyReadFailed);
                }
                Err(_error) => {
                    abort_v2_commit_multipart(multipart, "stream_read").await;
                    return Err(V2FormatError::StorageOperationFailed);
                }
            };
            let chunk_len = u64::try_from(chunk.len()).map_err(|_| V2FormatError::SectionBounds)?;
            plaintext_seen = plaintext_seen
                .checked_add(chunk_len)
                .ok_or(V2FormatError::SectionBounds)?;
            if let Some(max_plaintext_len) = write.max_plaintext_len
                && plaintext_seen > max_plaintext_len
            {
                abort_v2_commit_multipart(multipart, "plaintext_limit").await;
                return Err(V2FormatError::ObjectTooLarge);
            }
            if let Some(expected_plaintext_len) = write.expected_plaintext_len
                && plaintext_seen > expected_plaintext_len
            {
                abort_v2_commit_multipart(multipart, "plaintext_length").await;
                return Err(V2FormatError::ObjectLengthMismatch);
            }
            let mut remaining = chunk.as_ref();
            while !remaining.is_empty() {
                let need = write.payload_segment_size.saturating_sub(segment.len());
                let take = need.min(remaining.len());
                segment.extend_from_slice(&remaining[..take]);
                remaining = &remaining[take..];
                if segment.len() == write.payload_segment_size {
                    if let Some((ready_index, ready_segment)) = pending_segment.take()
                        && {
                            let mut segment_writer = StreamingPayloadSegmentWriter {
                                body_digest: &mut body_digest,
                                payload_digest: &mut payload_digest,
                                assembler: &mut assembler,
                                multipart: &mut multipart,
                            };
                            push_streaming_payload_segment(
                                &segment_auth,
                                &mut segment_writer,
                                ready_index,
                                &ready_segment,
                                false,
                            )
                            .await
                            .is_err()
                        }
                    {
                        abort_v2_commit_multipart(multipart, "payload_segment").await;
                        return Err(V2FormatError::StorageOperationFailed);
                    }
                    pending_segment = Some((next_segment_index, std::mem::take(&mut segment)));
                    next_segment_index = match next_segment_index.checked_add(1) {
                        Some(next_segment_index) => next_segment_index,
                        None => {
                            abort_v2_commit_multipart(multipart, "segment_index").await;
                            return Err(V2FormatError::SectionBounds);
                        }
                    };
                    segment = Vec::with_capacity(write.payload_segment_size);
                }
            }
        }
        if let Some(expected_plaintext_len) = write.expected_plaintext_len
            && plaintext_seen != expected_plaintext_len
        {
            abort_v2_commit_multipart(multipart, "plaintext_length").await;
            return Err(V2FormatError::ObjectLengthMismatch);
        }
        if !segment.is_empty() {
            if let Some((ready_index, ready_segment)) = pending_segment.take()
                && {
                    let mut segment_writer = StreamingPayloadSegmentWriter {
                        body_digest: &mut body_digest,
                        payload_digest: &mut payload_digest,
                        assembler: &mut assembler,
                        multipart: &mut multipart,
                    };
                    push_streaming_payload_segment(
                        &segment_auth,
                        &mut segment_writer,
                        ready_index,
                        &ready_segment,
                        false,
                    )
                    .await
                    .is_err()
                }
            {
                abort_v2_commit_multipart(multipart, "payload_segment").await;
                return Err(V2FormatError::StorageOperationFailed);
            }
            let final_segment_failed = {
                let mut segment_writer = StreamingPayloadSegmentWriter {
                    body_digest: &mut body_digest,
                    payload_digest: &mut payload_digest,
                    assembler: &mut assembler,
                    multipart: &mut multipart,
                };
                push_streaming_payload_segment(
                    &segment_auth,
                    &mut segment_writer,
                    next_segment_index,
                    &segment,
                    true,
                )
                .await
                .is_err()
            };
            if final_segment_failed {
                abort_v2_commit_multipart(multipart, "payload_segment").await;
                return Err(V2FormatError::StorageOperationFailed);
            }
        } else if let Some((ready_index, ready_segment)) = pending_segment.take()
            && {
                let mut segment_writer = StreamingPayloadSegmentWriter {
                    body_digest: &mut body_digest,
                    payload_digest: &mut payload_digest,
                    assembler: &mut assembler,
                    multipart: &mut multipart,
                };
                push_streaming_payload_segment(
                    &segment_auth,
                    &mut segment_writer,
                    ready_index,
                    &ready_segment,
                    true,
                )
                .await
                .is_err()
            }
        {
            abort_v2_commit_multipart(multipart, "payload_segment").await;
            return Err(V2FormatError::StorageOperationFailed);
        }

        let payload_header = write
            .payload_sealer
            .header_reference(plaintext_seen)
            .map_err(|_| V2FormatError::InvalidHeaderField)?;
        let payload_len = write
            .payload_sealer
            .sealed_len_for_plaintext_len(plaintext_seen)
            .map_err(|_| V2FormatError::SectionBounds)?;
        let finalized = match (write.finalize)(V2StreamingPayloadFinalizationInput {
            plaintext_len: plaintext_seen,
            payload_len,
            payload_digest: payload_digest.clone().finalize().into(),
            payload_header,
        }) {
            Ok(finalized) => finalized,
            Err(error) => {
                abort_v2_commit_multipart(multipart, "finalize").await;
                return Err(error);
            }
        };
        let run_len =
            u64::try_from(finalized.index_run.len()).map_err(|_| V2FormatError::SectionBounds)?;
        let object_len = (V2_MAX_HEADER_SIZE as u64)
            .checked_add(payload_len)
            .and_then(|length| length.checked_add(run_len))
            .ok_or(V2FormatError::SectionBounds)?;
        let payload_section = V2SectionDescriptor {
            section_type: V2SectionType::Payload,
            offset: 0,
            length: payload_len,
            flags: V2_SECTION_FLAG_MUST_UNDERSTAND,
            digest: payload_digest.finalize().into(),
        };
        let index_run_section = V2SectionDescriptor {
            section_type: V2SectionType::IndexRun,
            offset: payload_len,
            length: run_len,
            flags: V2_SECTION_FLAG_MUST_UNDERSTAND,
            digest: digest_v2_section(&finalized.index_run),
        };
        let section_index = vec![payload_section.clone(), index_run_section.clone()];

        body_digest.update(&finalized.index_run);
        if assembler
            .push_section_bytes(&mut multipart, &finalized.index_run)
            .await
            .is_err()
        {
            abort_v2_commit_multipart(multipart, "index_run").await;
            return Err(V2FormatError::StorageOperationFailed);
        }
        let body_digest = body_digest.finalize().into();
        let header = match self.build_header(
            commit_key,
            parent,
            &V2CommitWrite::delta(Vec::new())
                .with_retention(write.retention)
                .with_legal_hold(write.legal_hold),
            section_index,
            body_digest,
            self.options.upload_mode,
        ) {
            Ok(header) => header,
            Err(error) => {
                abort_v2_commit_multipart(multipart, "header").await;
                return Err(error);
            }
        };
        let header_span = match header.encode_header_span(self.options.upload_mode) {
            Ok(header_span) => header_span,
            Err(error) => {
                abort_v2_commit_multipart(multipart, "header").await;
                return Err(error);
            }
        };
        let metadata = assembler
            .complete(multipart, header_span)
            .await
            .map_err(|_| V2FormatError::StorageOperationFailed)?;
        Ok(V2StreamingCommitWriteResult {
            metadata,
            object_len,
            body_digest,
            signing_key_id: header.signing_key_id,
            payload_section,
            index_run_section,
            output: finalized.output,
        })
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
            plaintext_len: expected_plaintext_len,
            payload_segment_size,
            mut stream,
            retention,
            legal_hold,
            multipart_part_size,
            cancellation,
        } = write;
        if cancellation.is_cancelled() {
            return Err(V2FormatError::ObjectBodyReadFailed);
        }
        let payload_sealer = SegmentedPayloadSealer::new(&self.keyring, payload_segment_size)
            .map_err(|_| V2FormatError::InvalidHeaderField)?;
        let mut assembler = MultipartObjectAssembler::new(multipart_part_size)?;
        let mut multipart = self
            .create_standalone_multipart_upload(&object_id, retention, legal_hold)
            .await
            .map_err(storage_to_v2)?;
        let mut object_digest = Sha256::new();
        let payload_header = payload_sealer.header();
        object_digest.update(&payload_header);
        if assembler
            .push_bytes(&mut multipart, &payload_header)
            .await
            .is_err()
        {
            abort_v2_commit_multipart(multipart, "standalone_header").await;
            return Err(V2FormatError::StorageOperationFailed);
        }
        if cancellation.is_cancelled() {
            abort_v2_commit_multipart(multipart, "standalone_cancelled").await;
            return Err(V2FormatError::ObjectBodyReadFailed);
        }

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
                next = tokio::time::timeout(
                    self.options.stream_read_stall_timeout,
                    stream.next(),
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
            if plaintext_seen > expected_plaintext_len {
                abort_v2_commit_multipart(multipart, "standalone_plaintext_length").await;
                return Err(V2FormatError::ObjectLengthMismatch);
            }
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
        if plaintext_seen != expected_plaintext_len {
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

        let payload_header = payload_sealer
            .header_reference(plaintext_seen)
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
        let object_digest: [u8; 32] = object_digest.finalize().into();
        let version_id = self
            .verify_commit_postconditions(
                &object_id,
                &metadata,
                V2WritePostconditions::standalone(
                    object_len,
                    retention,
                    required_retain_until_ms,
                    legal_hold,
                    object_digest,
                ),
            )
            .await?;
        Ok(V2StoredStandalonePayload {
            object_id,
            version_id,
            object_len,
            object_digest,
            payload_header,
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
                    content_type: Some("application/vnd.rs3.payload.v02".to_owned()),
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

    async fn create_commit_multipart_upload(
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
    ) -> V2Result<Option<BackendVersionId>> {
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
        if let Some(expected_digest) = postconditions.expected_stored_digest {
            self.verify_exact_stored_object_digest(
                object_id,
                exact.version_id.as_ref(),
                postconditions.expected_object_len,
                expected_digest,
            )
            .await?;
        } else {
            let visible = self
                .store
                .get_range_at(
                    object_id,
                    exact.version_id.as_ref(),
                    ByteRange::Slice { offset: 0, len: 1 },
                )
                .await
                .map_err(|_| V2FormatError::ProviderProfileFailed)?;
            if visible.len() != 1 {
                return Err(V2FormatError::ProviderProfileFailed);
            }
        }
        if postconditions
            .required_retain_until_ms
            .is_some_and(|required| exact.retain_until_ms.is_none_or(|actual| actual < required))
        {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        match self.options.provider_profile {
            V2ProviderProfile::Dev | V2ProviderProfile::AtomicCreate => Ok(exact.version_id),
            V2ProviderProfile::RetainedVersionObjectLock => {
                if postconditions.required_retention.is_none()
                    && postconditions.required_legal_hold != Some(LegalHoldStatus::On)
                {
                    return Err(V2FormatError::ProviderProfileFailed);
                }
                let Some(version_id) = exact.version_id.clone() else {
                    return Err(V2FormatError::ProviderProfileFailed);
                };
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
                Ok(Some(version_id))
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
        let mut digest = Sha256::new();
        let mut reader = self
            .store
            .open_range_at(object_id, version_id, ByteRange::Full)
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
            if chunk_len == 0 {
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
        let actual_digest: [u8; 32] = digest.finalize().into();
        if bytes_read != expected_object_len || actual_digest != expected_digest {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        Ok(())
    }

    async fn verify_existing_commit_postconditions(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
    ) -> V2Result<()> {
        match self.options.provider_profile {
            V2ProviderProfile::Dev | V2ProviderProfile::AtomicCreate => Ok(()),
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
                Ok(())
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
        let error_class = storage_error_class(&error);
        metrics::counter!(
            "rs3_repository_v2_multipart_abort_failures_total",
            "phase" => phase,
            "error_class" => error_class,
        )
        .increment(1);
        tracing::warn!(
            target: "rs3_repository",
            operation = "v2_multipart_abort",
            phase,
            error_class,
            result = "failed",
            "failed to abort incomplete v2 multipart upload",
        );
    }
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

struct StreamingPayloadSegmentWriter<'a> {
    body_digest: &'a mut Sha256,
    payload_digest: &'a mut Sha256,
    assembler: &'a mut MultipartCommitAssembler,
    multipart: &'a mut Box<dyn rs3_storage::BlobMultipartUpload>,
}

struct StandalonePayloadSegmentWriter<'a> {
    object_digest: &'a mut Sha256,
    assembler: &'a mut MultipartObjectAssembler,
    multipart: &'a mut Box<dyn BlobMultipartUpload>,
}

async fn push_streaming_payload_segment(
    auth: &StreamingPayloadSegmentAuth<'_>,
    writer: &mut StreamingPayloadSegmentWriter<'_>,
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
    writer.body_digest.update(&ciphertext);
    writer.payload_digest.update(&ciphertext);
    writer
        .assembler
        .push_section_bytes(writer.multipart, &ciphertext)
        .await
        .map_err(|_| V2FormatError::StorageOperationFailed)
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

struct V2StreamingCommitWriteResult<Output> {
    metadata: BlobMetadata,
    object_len: u64,
    body_digest: [u8; 32],
    signing_key_id: KeyId,
    payload_section: V2SectionDescriptor,
    index_run_section: V2SectionDescriptor,
    output: Output,
}

struct MultipartCommitAssembler {
    part_size: usize,
    first_section_capacity: usize,
    first_section_bytes: Vec<u8>,
    current_part_index: usize,
    current_part: Vec<u8>,
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

impl MultipartCommitAssembler {
    fn new(part_size: usize) -> V2Result<Self> {
        if part_size <= V2_MAX_HEADER_SIZE {
            return Err(V2FormatError::SectionBounds);
        }
        Ok(Self {
            part_size,
            first_section_capacity: part_size - V2_MAX_HEADER_SIZE,
            first_section_bytes: Vec::with_capacity(part_size - V2_MAX_HEADER_SIZE),
            current_part_index: 1,
            current_part: Vec::with_capacity(part_size),
        })
    }

    async fn push_section_bytes(
        &mut self,
        upload: &mut Box<dyn rs3_storage::BlobMultipartUpload>,
        mut bytes: &[u8],
    ) -> rs3_storage::Result<()> {
        if self.first_section_bytes.len() < self.first_section_capacity {
            let take =
                (self.first_section_capacity - self.first_section_bytes.len()).min(bytes.len());
            self.first_section_bytes.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
        }
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

    async fn complete(
        self,
        mut upload: Box<dyn rs3_storage::BlobMultipartUpload>,
        header_span: Bytes,
    ) -> rs3_storage::Result<BlobMetadata> {
        let mut first_part = Vec::with_capacity(header_span.len() + self.first_section_bytes.len());
        first_part.extend_from_slice(&header_span);
        first_part.extend_from_slice(&self.first_section_bytes);
        if let Err(error) = upload.put_part(0, Bytes::from(first_part)).await {
            abort_v2_commit_multipart(upload, "assembler_first_part").await;
            return Err(error);
        }
        if !self.current_part.is_empty()
            && let Err(error) = upload
                .put_part(self.current_part_index, Bytes::from(self.current_part))
                .await
        {
            abort_v2_commit_multipart(upload, "assembler_final_part").await;
            return Err(error);
        }
        upload.complete().await
    }
}

fn strongest_retention_policy(
    left: Option<RetentionPolicy>,
    right: Option<RetentionPolicy>,
) -> Option<RetentionPolicy> {
    crate::service::strongest_retention_policy(left, right)
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

fn retention_satisfies(actual: Option<&RetentionPolicy>, requested: &RetentionPolicy) -> bool {
    let Some(actual) = actual else {
        return false;
    };
    retention_mode_strength(actual.mode) >= retention_mode_strength(requested.mode)
        && actual.retain_days >= requested.retain_days
}

fn retention_mode_strength(mode: rs3_types::RetentionMode) -> u8 {
    match mode {
        rs3_types::RetentionMode::None => 0,
        rs3_types::RetentionMode::Governance => 1,
        rs3_types::RetentionMode::Compliance => 2,
    }
}
