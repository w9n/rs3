//! Preview v2 commit-store workflow.

use super::commit::{
    V2_COMMIT_CONTENT_TYPE, V2CommitHeader, V2CommitKey, V2CommitParentRef, V2CommitSelfRef,
    V2KeyringEnvelopeRef, V2ParsedCommit, V2SectionDescriptor, V2SectionType, V2UploadMode,
    body_digest_for_v2_sections, generate_v2_commit_key, parse_v2_commit_object,
};
use super::error::{V2FormatError, V2Result};
use super::format::V2FormatRef;
use super::provider::V2ProviderProfile;
use async_trait::async_trait;
use bytes::Bytes;
use rs3_crypto::KeyRing;
use rs3_storage::{BlobMetadata, BlobStore, ByteRange, PutOptions, StorageError};
use rs3_types::{
    BackendObjectId, BackendVersionId, KeyId, LegalHoldStatus, RepositoryId, RetentionPolicy,
    Sequence,
};
use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_RANDOM_KEY_ATTEMPTS: usize = 3;

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
            upload_mode: V2UploadMode::SinglePut,
            provider_profile: profile,
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

/// Unanchored v2 commit object discovered by orphan reporting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2OrphanCandidate {
    /// Opaque backend object ID.
    pub object_id: BackendObjectId,
    /// Provider version ID visible in listing, when available.
    pub version_id: Option<BackendVersionId>,
    /// Listed object length.
    pub content_len: u64,
    /// Provider modification timestamp in milliseconds since the Unix epoch.
    pub modified_at_ms: Option<i64>,
    /// Parsed sequence when the object key has a valid v2 commit shape.
    pub sequence: Option<Sequence>,
    /// True when the candidate has the same sequence as the anchor head.
    pub same_sequence_as_anchor: bool,
    /// Provider retention policy visible in listing, when available.
    pub retention: Option<RetentionPolicy>,
    /// True when known retention should block deletion.
    pub delete_blocked_by_retention: bool,
    /// True when known legal hold should block deletion.
    pub delete_blocked_by_legal_hold: bool,
    /// True when the selected provider profile requires protection metadata but it was not visible.
    pub delete_blocked_by_unknown_protection: bool,
}

/// Redacted v2 orphan report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2OrphanReport {
    /// Reachable commit object count in the verified anchor chain.
    pub reachable_commit_count: usize,
    /// Candidate commits under `commits/v01/` that are not anchor-reachable.
    pub candidates: Vec<V2OrphanCandidate>,
}

/// Conservative v2 orphan garbage-collection policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V2OrphanGcOptions {
    /// Minimum provider-observed age before an unanchored commit may be deleted.
    pub min_age: Duration,
    /// Whether same-sequence candidates may be deleted after normal checks pass.
    pub delete_same_sequence: bool,
}

impl V2OrphanGcOptions {
    /// Creates conservative orphan-GC options.
    pub const fn new(min_age: Duration) -> Self {
        Self {
            min_age,
            delete_same_sequence: false,
        }
    }

    /// Allows deletion of same-sequence candidates after age/protection checks.
    pub const fn with_same_sequence_deletion(mut self, enabled: bool) -> Self {
        self.delete_same_sequence = enabled;
        self
    }
}

/// Result of one conservative v2 orphan garbage-collection pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct V2OrphanGcReport {
    /// Orphan candidates inspected.
    pub scanned_count: usize,
    /// Candidates deleted by this pass.
    pub deleted_count: usize,
    /// Candidates already gone before deletion.
    pub already_gone_count: usize,
    /// Candidates skipped because provider retention or legal hold was visible.
    pub protected_count: usize,
    /// Candidates skipped because they were too young or had no usable age.
    pub age_skipped_count: usize,
    /// Same-sequence candidates skipped by conservative default policy.
    pub same_sequence_skipped_count: usize,
    /// Delete calls that failed for reasons other than known protection or not found.
    pub failed_delete_count: usize,
}

/// Redacted v2 quick-maintenance report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2MaintenanceReport {
    /// True when an anchor was present.
    pub anchor_present: bool,
    /// Verified commit count in the anchor-selected chain.
    pub verified_commit_count: usize,
    /// Orphan candidate count under the v2 commit prefix.
    pub orphan_candidate_count: usize,
    /// Orphan candidates blocked by retention or legal hold.
    pub protected_orphan_candidate_count: usize,
    /// Oldest visible orphan age in milliseconds, when provider timestamps exist.
    pub oldest_orphan_age_ms: Option<u128>,
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
        let mut seen = BTreeSet::new();

        loop {
            if !seen.insert(next_key.clone()) {
                return Err(V2FormatError::StaleAnchor);
            }
            let parsed = self
                .read_commit_at(&next_key, next_version.as_ref())
                .await?;
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
        parsed.version_id = version_id.cloned();
        Ok(parsed)
    }

    async fn read_commit_from_anchor_state(
        &self,
        state: &V2AnchorState,
    ) -> V2Result<V2ParsedCommit> {
        let parsed = self
            .read_commit_at(&state.commit_key, state.version_id.as_ref())
            .await?;
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

    /// Reports unanchored commit objects without deleting anything.
    pub async fn report_orphans<A>(&self, anchor: &A) -> V2Result<V2OrphanReport>
    where
        A: V2CommitAnchor,
    {
        let anchor_state = anchor.read_v2().await?;
        let mut reachable = BTreeSet::new();
        let mut anchor_sequence = None;
        if let Some(state) = anchor_state.as_ref() {
            anchor_sequence = Some(state.sequence);
            let chain = self.load_chain_from_state(state).await?;
            for commit in &chain.commits_newest_first {
                reachable.insert(commit.parsed_header.header.self_ref.commit_key.clone());
            }
        }

        let listed = self
            .store
            .list_prefix("commits/v01/")
            .await
            .map_err(|_| V2FormatError::StorageOperationFailed)?;
        let mut candidates = Vec::new();
        for metadata in listed {
            if reachable.contains(&metadata.object_id) {
                continue;
            }
            let parsed_key = V2CommitKey::parse(&metadata.object_id).ok();
            let sequence = parsed_key.as_ref().map(|key| key.sequence);
            let delete_blocked_by_unknown_protection = self.options.provider_profile
                == V2ProviderProfile::RetainedVersionObjectLock
                && (metadata.retention.is_none() || metadata.legal_hold.is_none());
            candidates.push(V2OrphanCandidate {
                object_id: metadata.object_id,
                version_id: metadata.version_id,
                content_len: metadata.content_len,
                modified_at_ms: metadata.modified_at_ms,
                sequence,
                same_sequence_as_anchor: sequence
                    .zip(anchor_sequence)
                    .is_some_and(|(left, right)| left == right),
                retention: metadata.retention,
                delete_blocked_by_retention: retention_blocks_delete(metadata.retention.as_ref()),
                delete_blocked_by_legal_hold: metadata.legal_hold == Some(LegalHoldStatus::On),
                delete_blocked_by_unknown_protection,
            });
        }

        Ok(V2OrphanReport {
            reachable_commit_count: reachable.len(),
            candidates,
        })
    }

    /// Deletes expired, unprotected v2 orphan commits.
    ///
    /// This pass is intentionally conservative: reachable commits are discovered
    /// from the anchor-selected chain, retained or legally held objects are
    /// skipped, candidates without a usable provider timestamp are skipped, and
    /// same-sequence candidates are skipped unless explicitly enabled.
    pub async fn delete_expired_orphans<A>(
        &self,
        anchor: &A,
        options: V2OrphanGcOptions,
    ) -> V2Result<V2OrphanGcReport>
    where
        A: V2CommitAnchor,
    {
        let report = self.report_orphans(anchor).await?;
        let now_ms = current_time_ms();
        let min_age_ms = options.min_age.as_millis();
        let mut gc = V2OrphanGcReport {
            scanned_count: report.candidates.len(),
            ..V2OrphanGcReport::default()
        };

        for candidate in report.candidates {
            if candidate.delete_blocked_by_retention
                || candidate.delete_blocked_by_legal_hold
                || candidate.delete_blocked_by_unknown_protection
            {
                gc.protected_count += 1;
                continue;
            }
            if candidate.same_sequence_as_anchor && !options.delete_same_sequence {
                gc.same_sequence_skipped_count += 1;
                continue;
            }
            let Some(age_ms) = candidate_age_ms(now_ms, candidate.modified_at_ms) else {
                gc.age_skipped_count += 1;
                continue;
            };
            if age_ms < min_age_ms {
                gc.age_skipped_count += 1;
                continue;
            }

            match self.store.delete(&candidate.object_id).await {
                Ok(()) => gc.deleted_count += 1,
                Err(StorageError::NotFound(_)) => gc.already_gone_count += 1,
                Err(StorageError::RetentionBlocked | StorageError::LegalHoldBlocked) => {
                    gc.protected_count += 1;
                }
                Err(_) => gc.failed_delete_count += 1,
            }
        }

        Ok(gc)
    }

    /// Runs read-only quick maintenance checks.
    pub async fn quick_maintenance<A>(&self, anchor: &A) -> V2Result<V2MaintenanceReport>
    where
        A: V2CommitAnchor,
    {
        let chain = self.load_chain_from_anchor(anchor).await?;
        let verified_commit_count = chain
            .as_ref()
            .map(|chain| chain.commits_newest_first.len())
            .unwrap_or_default();
        let orphans = self.report_orphans(anchor).await?;
        let protected_orphan_candidate_count = orphans
            .candidates
            .iter()
            .filter(|candidate| {
                candidate.delete_blocked_by_retention
                    || candidate.delete_blocked_by_legal_hold
                    || candidate.delete_blocked_by_unknown_protection
            })
            .count();
        let now_ms = current_time_ms();
        let oldest_orphan_age_ms = orphans
            .candidates
            .iter()
            .filter_map(|candidate| candidate_age_ms(now_ms, candidate.modified_at_ms))
            .max();
        Ok(V2MaintenanceReport {
            anchor_present: chain.is_some(),
            verified_commit_count,
            orphan_candidate_count: orphans.candidates.len(),
            protected_orphan_candidate_count,
            oldest_orphan_age_ms,
        })
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

fn candidate_age_ms(now_ms: i64, modified_at_ms: Option<i64>) -> Option<u128> {
    let modified_at_ms = modified_at_ms?;
    let age_ms = now_ms.checked_sub(modified_at_ms)?;
    u128::try_from(age_ms).ok()
}

fn retention_satisfies(actual: Option<&RetentionPolicy>, requested: &RetentionPolicy) -> bool {
    let Some(actual) = actual else {
        return false;
    };
    retention_mode_strength(actual.mode) >= retention_mode_strength(requested.mode)
        && actual.retain_days >= requested.retain_days
}

fn retention_blocks_delete(policy: Option<&RetentionPolicy>) -> bool {
    match policy {
        Some(policy) => policy.mode != rs3_types::RetentionMode::None && policy.retain_days > 0,
        None => false,
    }
}

fn retention_mode_strength(mode: rs3_types::RetentionMode) -> u8 {
    match mode {
        rs3_types::RetentionMode::None => 0,
        rs3_types::RetentionMode::Governance => 1,
        rs3_types::RetentionMode::Compliance => 2,
    }
}
