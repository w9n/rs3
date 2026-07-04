//! Preview v2 commit-store workflow.

use super::commit::{
    V2_COMMIT_CONTENT_TYPE, V2_HEADER_META_LEN, V2_MAX_HEADER_SIZE,
    V2_SECTION_FLAG_MUST_UNDERSTAND, V2CommitHeader, V2CommitKey, V2CommitParentRef,
    V2CommitSelfRef, V2KeyringEnvelopeRef, V2ParsedCommit, V2ParsedCommitHeader,
    V2SectionDescriptor, V2SectionType, V2UploadMode, body_digest_for_v2_sections,
    generate_v2_commit_key, parse_v2_commit_header, parse_v2_commit_object,
    v2_commit_header_span_len,
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
    BlobMetadata, BlobMultipartUpload, BlobStore, ByteRange, PutOptions, StorageError,
};
use rs3_types::{
    BackendObjectId, BackendVersionId, KeyId, LegalHoldStatus, RepositoryId, RetentionPolicy,
    Sequence,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_RANDOM_KEY_ATTEMPTS: usize = 3;

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
}

impl V2CommitStoreOptions {
    /// Creates default options for the selected provider profile.
    pub fn for_profile(
        profile: V2ProviderProfile,
        keyring_envelope_ref: V2KeyringEnvelopeRef,
        format_ref: V2FormatRef,
    ) -> Self {
        Self {
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
    /// True when this commit is a namespace snapshot.
    pub is_snapshot: bool,
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
            is_snapshot: true,
            sections,
            retention: None,
            legal_hold: None,
        }
    }

    /// Creates a delta commit write request.
    pub fn delta(sections: Vec<V2CommitSection>) -> Self {
        Self {
            is_snapshot: false,
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
    pub(crate) payload_header: crate::payload::SegmentedPayloadHeader,
}

/// Finalized index delta bytes and caller-owned output for a streamed payload.
#[derive(Clone, Debug)]
pub(crate) struct V2FinalizedStreamingPayloadWrite<Output> {
    pub(crate) index_delta: Bytes,
    pub(crate) output: Output,
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
}

pub(crate) struct V2StoredStreamingCommit<Output> {
    pub(crate) stored: V2StoredCommit,
    pub(crate) output: Output,
}

/// Verified v2 commit chain, newest commit first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2CommitChain {
    /// Verified commits, newest first, ending at the nearest snapshot or genesis.
    pub commits_newest_first: Vec<V2ParsedCommit>,
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
}

/// Preview v2 commit store over a `BlobStore`.
pub struct V2CommitStore<S> {
    store: S,
    keyring: KeyRing,
    options: V2CommitStoreOptions,
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
        }
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
            0,
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
    pub async fn read_anchor_head<A>(&self, anchor: &A) -> V2Result<Option<V2ParsedCommit>>
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
        let mut commits = Vec::new();
        let mut next_key = anchor_state.commit_key.clone();
        let mut next_version = anchor_state.version_id.clone();
        let mut next_digest = Some(anchor_state.body_digest);
        let mut next_sequence = Some(anchor_state.sequence);
        let mut seen = BTreeSet::new();

        loop {
            if !seen.insert(next_key.clone()) {
                return Err(V2FormatError::StaleAnchor);
            }
            let parsed = self
                .read_commit_at(&next_key, next_version.as_ref())
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
            let is_snapshot = parsed.parsed_header.header.is_snapshot;
            let parent = parsed.parsed_header.header.parent.clone();
            commits.push(parsed);
            if is_snapshot {
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
        let body = self
            .store
            .get_range_at(object_id, version_id, ByteRange::Full)
            .await
            .map_err(|_| V2FormatError::StorageOperationFailed)?;
        let mut parsed = parse_v2_commit_object(object_id, body, &self.keyring)?;
        if parsed.parsed_header.header.keyring_envelope_ref != self.options.keyring_envelope_ref {
            return Err(V2FormatError::InvalidHeaderField);
        }
        parsed.version_id = version_id.cloned();
        Ok(parsed)
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
        if self.options.upload_mode == V2UploadMode::MultipartPadded {
            let header_bytes = self
                .store
                .get_range_at(
                    object_id,
                    version_id,
                    ByteRange::Slice {
                        offset: 0,
                        len: V2_MAX_HEADER_SIZE as u64,
                    },
                )
                .await;
            if let Ok(header_bytes) = header_bytes {
                let parsed = parse_v2_commit_header(object_id, &header_bytes, &self.keyring)?;
                if parsed.header.keyring_envelope_ref != self.options.keyring_envelope_ref {
                    return Err(V2FormatError::InvalidHeaderField);
                }
                return Ok(parsed);
            }
        }

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
        if parsed.header.keyring_envelope_ref != self.options.keyring_envelope_ref {
            return Err(V2FormatError::InvalidHeaderField);
        }
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
    ) -> V2Result<V2ParsedCommit> {
        let parsed = self
            .read_commit_at(&state.commit_key, state.version_id.as_ref())
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
        let parsed = self.read_commit_at(object_id, version_id).await?;
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
        })
    }

    /// Verifies a recovery bundle and recreates a missing anchor from it.
    pub async fn recreate_anchor_from_recovery_bundle<A>(
        &self,
        anchor: &A,
        bundle: &V2RecoveryBundle,
    ) -> V2Result<V2CommitChain>
    where
        A: V2CommitAnchor,
    {
        if bundle.anchor.sequence < bundle.weak_subjectivity_floor_sequence {
            return Err(V2FormatError::RecoveryBundleRequired);
        }
        if anchor.read_v2().await?.is_some() {
            return Err(V2FormatError::StaleAnchor);
        }
        let chain = self.load_chain_from_state(&bundle.anchor).await?;
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
            let header = self.build_header(
                &commit_key,
                parent.clone(),
                &write,
                section_index.clone(),
                body_digest,
            )?;
            let object_body = header.encode_object(self.options.upload_mode, &section_region)?;
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
                    commit_retention,
                    commit_legal_hold,
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
                commit_retention,
                commit_legal_hold,
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
            },
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
    ) -> V2Result<V2CommitHeader> {
        let header = V2CommitHeader {
            self_ref: V2CommitSelfRef {
                sequence: commit_key.sequence,
                commit_key: commit_key.object_id.clone(),
            },
            parent,
            publish_time_ms: current_time_ms(),
            is_snapshot: write.is_snapshot,
            algorithms: Default::default(),
            keyring_envelope_ref: self.options.keyring_envelope_ref.clone(),
            section_index,
            body_digest,
            signature: [0_u8; 64],
            signing_key_id: self
                .keyring
                .primary_key_id(rs3_types::KeyPurpose::CheckpointSigning)?,
        };
        header.sign_with_keyring(&self.keyring, self.options.upload_mode)
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
        let payload_header = write.payload_sealer.header();
        body_digest.update(&payload_header);
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
            payload_header,
        }) {
            Ok(finalized) => finalized,
            Err(error) => {
                abort_v2_commit_multipart(multipart, "finalize").await;
                return Err(error);
            }
        };
        let delta_len =
            u64::try_from(finalized.index_delta.len()).map_err(|_| V2FormatError::SectionBounds)?;
        let section_index = vec![
            V2SectionDescriptor {
                section_type: V2SectionType::Payload,
                offset: 0,
                length: payload_len,
                flags: V2_SECTION_FLAG_MUST_UNDERSTAND,
            },
            V2SectionDescriptor {
                section_type: V2SectionType::IndexDelta,
                offset: payload_len,
                length: delta_len,
                flags: V2_SECTION_FLAG_MUST_UNDERSTAND,
            },
        ];

        body_digest.update(&finalized.index_delta);
        if assembler
            .push_section_bytes(&mut multipart, &finalized.index_delta)
            .await
            .is_err()
        {
            abort_v2_commit_multipart(multipart, "index_delta").await;
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
            body_digest,
            signing_key_id: header.signing_key_id,
            output: finalized.output,
        })
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
        retention: Option<RetentionPolicy>,
        legal_hold: Option<LegalHoldStatus>,
    ) -> V2Result<Option<BackendVersionId>> {
        match self.options.provider_profile {
            V2ProviderProfile::Dev | V2ProviderProfile::AtomicCreate => {
                Ok(metadata.version_id.clone())
            }
            V2ProviderProfile::RetainedVersionObjectLock => {
                if retention.is_none() && legal_hold != Some(LegalHoldStatus::On) {
                    return Err(V2FormatError::ProviderProfileFailed);
                }
                let Some(version_id) = metadata.version_id.clone() else {
                    return Err(V2FormatError::ProviderProfileFailed);
                };
                if let Some(retention) = retention
                    && !retention_satisfies(metadata.retention.as_ref(), &retention)
                {
                    return Err(V2FormatError::ProviderProfileFailed);
                }
                if legal_hold == Some(LegalHoldStatus::On)
                    && metadata.legal_hold != Some(LegalHoldStatus::On)
                {
                    return Err(V2FormatError::ProviderProfileFailed);
                }
                self.store
                    .get_range_at(
                        object_id,
                        Some(&version_id),
                        ByteRange::Slice { offset: 0, len: 1 },
                    )
                    .await
                    .map_err(|_| V2FormatError::ProviderProfileFailed)?;
                Ok(Some(version_id))
            }
        }
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
    assembler: &'a mut MultipartCommitAssembler,
    multipart: &'a mut Box<dyn rs3_storage::BlobMultipartUpload>,
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
    writer
        .assembler
        .push_section_bytes(writer.multipart, &ciphertext)
        .await
        .map_err(|_| V2FormatError::StorageOperationFailed)
}

struct V2StreamingCommitWriteResult<Output> {
    metadata: BlobMetadata,
    body_digest: [u8; 32],
    signing_key_id: KeyId,
    output: Output,
}

struct MultipartCommitAssembler {
    part_size: usize,
    first_section_capacity: usize,
    first_section_bytes: Vec<u8>,
    current_part_index: usize,
    current_part: Vec<u8>,
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
