//! v2 maintenance planning and conservative apply paths.

use super::commit::{V2_SECTION_FLAG_MUST_UNDERSTAND, V2CommitKey};
use super::error::{V2FormatError, V2Result};
use super::provider::V2ProviderProfile;
use super::repository::{
    V2AnchorState, V2CommitAnchor, V2CommitStore, V2ReplayChain, V2ReplayCommit, V2ReplayLimits,
};
use super::service::packed::{
    V2PackedIndexRunReplay, apply_packed_index_run, repository_context_from_refs,
};
use super::{
    V2_CAPABILITY_COMPACTED_INDEX_RUNS, V2_CAPABILITY_FRAMED_INDEX, V2_SUPPORTED_CAPABILITY_FLAGS,
    V2CommitKind, V2IndexRoot, V2IndexRootRunRef, V2SectionType, open_v2_index_root,
};
use crate::checkpoint::open_index_delta_object;
use crate::state::{RepositoryState, apply_index_delta_object};
use async_trait::async_trait;
use rs3_index::{
    INDEX_DELTA_OBJECT_DOMAIN, IndexDelta, IndexDeltaObject, PayloadReference,
    SealedIndexDeltaObject,
};
use rs3_storage::BlobMetadata;
use rs3_storage::{BlobStore, StorageError};
use rs3_types::{
    BackendObjectId, BackendVersionId, LegalHoldStatus, RetentionMode, RetentionPolicy, Sequence,
};
use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_RETENTION_RENEWAL_HORIZON: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const MIN_ORPHAN_GC_AGE: Duration = Duration::from_secs(60 * 60);

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
    /// Provider retain-until timestamp in milliseconds since the Unix epoch, when available.
    pub retain_until_ms: Option<i64>,
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
    /// Candidate commits under `commits/v02/` that are not anchor-reachable.
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
    pub fn new(min_age: Duration) -> V2Result<Self> {
        if min_age < MIN_ORPHAN_GC_AGE {
            return Err(V2FormatError::OrphanGcMinAgeTooLow);
        }
        Ok(Self {
            min_age,
            delete_same_sequence: false,
        })
    }

    /// Creates orphan-GC options without the production age floor.
    ///
    /// This is only for deterministic tests and isolated rehearsal harnesses
    /// that create disposable objects inside an empty target prefix.
    pub const fn new_for_test_rehearsal(min_age: Duration) -> Self {
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
    /// Mid-pass abort reason after a partial destructive pass.
    pub aborted: Option<V2FormatError>,
}

/// Redacted v2 quick-maintenance report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2MaintenanceReport {
    /// True when an anchor was present.
    pub anchor_present: bool,
    /// Verified commit count in the anchor-selected chain.
    pub verified_commit_count: usize,
    /// Age of the accepted chain head in milliseconds.
    pub last_anchored_commit_age_ms: Option<u128>,
    /// Orphan candidate count under the v2 commit prefix.
    pub orphan_candidate_count: usize,
    /// Total bytes held by orphan candidates under the v2 commit prefix.
    pub orphan_candidate_bytes: u64,
    /// Orphan candidates blocked by retention or legal hold.
    pub protected_orphan_candidate_count: usize,
    /// Oldest visible orphan age in milliseconds, when provider timestamps exist.
    pub oldest_orphan_age_ms: Option<u128>,
    /// Live commit versions that should have retention extended within the default renewal horizon.
    pub retention_renewal_commit_count: usize,
    /// Live commit bytes covered by planned retention renewal.
    pub retention_renewal_bytes: u64,
    /// Live commit versions whose renewal could not be planned from available metadata.
    pub retention_renewal_blocked_count: usize,
    /// Live commit bytes whose renewal could not be planned from available metadata.
    pub retention_renewal_blocked_bytes: u64,
}

/// Operator-accepted budgets for v2 full-maintenance dry runs and apply plans.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct V2MaintenanceBudgets {
    /// Maximum planned backend requests.
    pub max_request_count: Option<u64>,
    /// Maximum planned version-list requests.
    pub max_version_list_count: Option<u64>,
    /// Maximum planned exact HEAD requests.
    pub max_head_count: Option<u64>,
    /// Maximum planned range-read bytes.
    pub max_range_read_bytes: Option<u64>,
    /// Maximum planned write bytes.
    pub max_write_bytes: Option<u64>,
    /// Maximum planned exact-version deletes.
    pub max_delete_count: Option<u64>,
    /// Maximum planned retention-extension calls.
    pub max_retention_extend_count: Option<u64>,
}

/// Request and byte estimates for a v2 full-maintenance plan.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct V2MaintenancePlanCost {
    /// Planned backend requests across verification, inventory, and mutation.
    pub request_count: u64,
    /// Planned version-list requests.
    pub version_list_count: u64,
    /// Planned exact HEAD requests.
    pub head_count: u64,
    /// Planned range-read bytes.
    pub range_read_bytes: u64,
    /// Planned write bytes.
    pub write_bytes: u64,
    /// Planned exact-version delete calls.
    pub delete_count: u64,
    /// Planned retention-extension calls.
    pub retention_extend_count: u64,
}

impl V2MaintenancePlanCost {
    /// Returns true when this plan fits the supplied operator budgets.
    pub fn fits_budgets(self, budgets: V2MaintenanceBudgets) -> bool {
        budget_allows(budgets.max_request_count, self.request_count)
            && budget_allows(budgets.max_version_list_count, self.version_list_count)
            && budget_allows(budgets.max_head_count, self.head_count)
            && budget_allows(budgets.max_range_read_bytes, self.range_read_bytes)
            && budget_allows(budgets.max_write_bytes, self.write_bytes)
            && budget_allows(budgets.max_delete_count, self.delete_count)
            && budget_allows(
                budgets.max_retention_extend_count,
                self.retention_extend_count,
            )
    }
}

/// Options for v2 full-maintenance dry runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2FullGcDryRunOptions {
    /// Operator request and byte budgets.
    pub budgets: V2MaintenanceBudgets,
    /// Plan live commit retention renewal when retain-until is within this horizon.
    pub retention_renewal_horizon: Duration,
    /// Additional trusted historical roots that must remain reachable.
    pub protected_roots: Vec<V2AnchorState>,
}

impl Default for V2FullGcDryRunOptions {
    fn default() -> Self {
        Self {
            budgets: V2MaintenanceBudgets::default(),
            retention_renewal_horizon: DEFAULT_RETENTION_RENEWAL_HORIZON,
            protected_roots: Vec::new(),
        }
    }
}

/// Path-redacted v2 full-maintenance dry-run report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2FullGcDryRunReport {
    /// Anchor sequence the dry run was based on, if an anchor exists.
    pub base_sequence: Option<Sequence>,
    /// Verified chain-live commits needed for current anchor replay.
    pub chain_live_commit_count: usize,
    /// Operator-supplied historical roots included in reachability.
    pub protected_root_count: usize,
    /// Unique commit versions included through historical roots.
    pub protected_commit_count: usize,
    /// Unanchored commit candidates inspected.
    pub candidate_commit_count: usize,
    /// Fully dead commit candidates outside provider protection.
    pub fully_dead_commit_count: usize,
    /// Mixed accepted commit count selected for repack.
    pub mixed_commit_count: usize,
    /// Bytes in unanchored commits that can become reclaimable by exact delete.
    pub dead_bytes_reclaimable: u64,
    /// Live bytes that would be copied by repack.
    pub live_bytes_to_copy: u64,
    /// Dead bytes inside mixed accepted commits that repack could make reclaimable.
    pub mixed_dead_bytes_repackable: u64,
    /// Dead bytes blocked by active provider retention.
    pub retention_blocked_bytes: u64,
    /// Dead bytes blocked by legal hold.
    pub legal_hold_blocked_bytes: u64,
    /// Dead bytes blocked by missing exact version or protection metadata.
    pub unknown_protection_blocked_bytes: u64,
    /// Live commit versions that should have retention extended within the requested horizon.
    pub retention_renewal_commit_count: usize,
    /// Live commit bytes covered by planned retention renewal.
    pub retention_renewal_bytes: u64,
    /// Live commit versions whose renewal could not be planned from available metadata.
    pub retention_renewal_blocked_count: usize,
    /// Live commit bytes whose renewal could not be planned from available metadata.
    pub retention_renewal_blocked_bytes: u64,
    /// Planned request and byte cost.
    pub planned_cost: V2MaintenancePlanCost,
    /// True when the planned cost fits the supplied budgets.
    pub fits_budgets: bool,
    /// True when this dry run includes only exact-version deletion candidates.
    pub exact_version_apply_ready: bool,
}

/// Guard required before destructive v2 maintenance can mutate storage.
#[async_trait]
pub trait V2MaintenanceGuard: Send + Sync {
    /// Verifies that the maintenance process still owns its exclusion window.
    async fn verify_v2_maintenance(&self, base_anchor: Option<&V2AnchorState>) -> V2Result<()>;
}

/// Unenforced guard for externally quiesced maintenance windows.
///
/// This is an honor-system escape hatch for tests and isolated rehearsals until
/// the Lease-backed guard ships. Production operators must supply a real guard.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnenforcedQuiescedMaintenanceGuard;

#[async_trait]
impl V2MaintenanceGuard for UnenforcedQuiescedMaintenanceGuard {
    async fn verify_v2_maintenance(&self, _base_anchor: Option<&V2AnchorState>) -> V2Result<()> {
        Ok(())
    }
}

/// Options for destructive v2 full-maintenance apply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2FullGcApplyOptions {
    /// Dry-run budgets that must pass before apply.
    pub dry_run: V2FullGcDryRunOptions,
    /// Conservative orphan deletion policy.
    pub orphan_gc: V2OrphanGcOptions,
    /// Whether retained-version provider conformance has passed for this run.
    pub retained_provider_conformance_passed: bool,
}

/// Result of destructive v2 full-maintenance apply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2FullGcApplyReport {
    /// Dry-run report used as the apply preflight.
    pub dry_run: V2FullGcDryRunReport,
    /// Exact deletion result for fully dead orphan commits.
    pub orphan_gc: V2OrphanGcReport,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct V2RetentionRenewalPlan {
    commit_count: usize,
    bytes: u64,
    blocked_count: usize,
    blocked_bytes: u64,
    head_count: u64,
    extend_count: u64,
}

#[derive(Clone, Debug, Default)]
struct V2ReachabilityState {
    anchor_state: Option<V2AnchorState>,
    current_chain: Option<V2ReplayChain>,
    reachable: BTreeSet<BackendObjectId>,
    reachable_versions: BTreeSet<(BackendObjectId, Option<BackendVersionId>)>,
    renewal_commits: Vec<V2ReplayCommit>,
    renewal_seen: BTreeSet<(BackendObjectId, Option<BackendVersionId>)>,
    protected_versions: BTreeSet<(BackendObjectId, Option<BackendVersionId>)>,
    chain_get_count: u64,
    chain_read_bytes: u64,
    chain_retained_bytes: u64,
}

pub(crate) struct V2ResolvedIndexRoot {
    pub(crate) runs: Vec<V2IndexRootRunRef>,
    referenced_commits: Vec<V2ReplayCommit>,
}

impl V2ReachabilityState {
    fn include_chain(&mut self, chain: &V2ReplayChain, protected: bool) {
        self.chain_get_count = self
            .chain_get_count
            .saturating_add(usize_to_u64(chain.commits_newest_first.len()));
        for commit in &chain.commits_newest_first {
            self.chain_read_bytes = self.chain_read_bytes.saturating_add(commit.object_len);
            self.chain_retained_bytes = commit
                .retained_sections
                .iter()
                .flatten()
                .fold(self.chain_retained_bytes, |total, section| {
                    total.saturating_add(usize_to_u64(section.len()))
                });
            let object_id = commit.parsed_header.header.self_ref.commit_key.clone();
            let version_key = (object_id.clone(), commit.version_id.clone());
            self.reachable.insert(object_id);
            self.reachable_versions.insert(version_key.clone());
            if self.renewal_seen.insert(version_key.clone()) {
                self.renewal_commits.push(commit.clone());
            }
            if protected {
                self.protected_versions.insert(version_key);
            }
        }
    }
}

impl<S> V2CommitStore<S>
where
    S: BlobStore,
{
    pub(crate) fn open_index_root_without_replay(
        &self,
        containing_commit: &V2ReplayCommit,
        section_ordinal: u32,
        stored_root: &[u8],
        limits: V2ReplayLimits,
    ) -> V2Result<V2IndexRoot> {
        let header = &containing_commit.parsed_header.header;
        let context = repository_context_from_refs(
            &self.options().repository_id,
            &header.keyring_envelope_ref,
        )
        .map_err(|_| V2FormatError::InvalidIndexRoot)?;
        let root = open_v2_index_root(
            self.keyring(),
            &context,
            &header.self_ref.commit_key,
            section_ordinal,
            stored_root,
        )?;
        if root.keyring_envelope_ref() != &header.keyring_envelope_ref
            || root.format_ref() != &self.options().format_ref
            || root.required_capabilities() & !V2_SUPPORTED_CAPABILITY_FLAGS != 0
            || root.required_capabilities() & V2_CAPABILITY_FRAMED_INDEX == 0
            || root.required_capabilities() & V2_CAPABILITY_COMPACTED_INDEX_RUNS == 0
        {
            return Err(V2FormatError::InvalidIndexRoot);
        }
        match header.parent.as_ref() {
            Some(_) => {}
            None if header.self_ref.sequence == Sequence::new(1)
                && root.covered_generation() == Sequence::ZERO
                && root.runs().is_empty() => {}
            _ => return Err(V2FormatError::InvalidIndexRoot),
        }
        let referenced_commit_bytes = root.runs().iter().try_fold(0_u64, |total, run| {
            total.checked_add(run.location.commit_stored_len)
        });
        if root.runs().len() > limits.max_commits
            || root.claims().total_stored_run_bytes() > limits.max_total_commit_bytes
            || referenced_commit_bytes.is_none_or(|bytes| bytes > limits.max_total_commit_bytes)
        {
            return Err(V2FormatError::ReplayBudgetExceeded);
        }
        Ok(root)
    }

    pub(crate) async fn apply_index_root_to_state(
        &self,
        state: &mut RepositoryState,
        containing_commit: &V2ReplayCommit,
        section_ordinal: u32,
        stored_root: &[u8],
        limits: V2ReplayLimits,
    ) -> V2Result<V2ResolvedIndexRoot> {
        let header = &containing_commit.parsed_header.header;
        let root = self.open_index_root_without_replay(
            containing_commit,
            section_ordinal,
            stored_root,
            limits,
        )?;
        let covered_parent_sequence = match header.parent.as_ref() {
            Some(parent) => parent.sequence,
            None if header.self_ref.sequence == Sequence::new(1)
                && root.covered_generation() == Sequence::ZERO
                && root.runs().is_empty() =>
            {
                Sequence::ZERO
            }
            _ => return Err(V2FormatError::InvalidIndexRoot),
        };
        let mut ordered_runs = root.runs().to_vec();
        ordered_runs.sort_by_key(|run| (run.minimum_generation, run.run_sequence, run.run_id));
        *state = RepositoryState::default();
        let mut runs = Vec::with_capacity(ordered_runs.len());
        let mut referenced_commits = Vec::with_capacity(ordered_runs.len());
        for expected in ordered_runs {
            let location = &expected.location;
            let replay = self
                .read_replay_commit_at(&location.commit_key, location.version_id.as_ref())
                .await?;
            let referenced_header = &replay.parsed_header.header;
            let descriptor_index = usize::try_from(location.section_ordinal)
                .map_err(|_| V2FormatError::SectionBounds)?;
            let descriptor = referenced_header
                .section_index
                .get(descriptor_index)
                .ok_or(V2FormatError::InvalidIndexRoot)?;
            let compacted = expected.level > 0;
            let referenced_sequence = referenced_header.self_ref.sequence;
            let valid_lineage = if compacted {
                expected.compaction_generation == referenced_sequence.get()
                    && referenced_sequence <= header.self_ref.sequence
                    && referenced_header.parent.is_some()
                    && referenced_header.section_index.len() == 1
                    && descriptor_index == 0
                    && if referenced_sequence == header.self_ref.sequence {
                        referenced_header.parent == header.parent
                    } else {
                        referenced_sequence <= covered_parent_sequence
                    }
            } else {
                expected.compaction_generation == 0
                    && referenced_sequence <= covered_parent_sequence
            };
            if replay.version_id != location.version_id
                || replay.object_len != location.commit_stored_len
                || replay.parsed_header.sections_start
                    != usize::try_from(location.sections_start)
                        .map_err(|_| V2FormatError::SectionBounds)?
                || referenced_header.kind != V2CommitKind::Delta
                || !valid_lineage
                || referenced_header.body_digest != location.commit_body_digest
                || referenced_header.keyring_envelope_ref != expected.keyring_envelope_ref
                || descriptor.section_type != V2SectionType::IndexRun
                || descriptor.flags != V2_SECTION_FLAG_MUST_UNDERSTAND
                || descriptor.offset != location.section_offset
                || descriptor.length != location.section_len
                || descriptor.digest != location.section_digest
            {
                return Err(V2FormatError::InvalidIndexRoot);
            }
            let stored_run = commit_section_bytes(&replay, descriptor_index)?;
            let actual = apply_packed_index_run(
                self.keyring(),
                &self.options().repository_id,
                state,
                V2PackedIndexRunReplay {
                    parsed_header: &replay.parsed_header,
                    version_id: replay.version_id.as_ref(),
                    object_len: replay.object_len,
                    section_ordinal: location.section_ordinal,
                    stored_run,
                    level: expected.level,
                    compaction_generation: expected.compaction_generation,
                },
            )
            .map_err(|_| V2FormatError::InvalidIndexRun)?;
            if actual != expected {
                return Err(V2FormatError::InvalidIndexRoot);
            }
            runs.push(actual);
            referenced_commits.push(replay);
        }
        if state.next_sequence != root.covered_generation()
            || u64::try_from(state.list_entries.len())
                .map_err(|_| V2FormatError::IndexRootLimitExceeded)?
                != root.expected_live_object_count()
        {
            return Err(V2FormatError::InvalidIndexRoot);
        }
        Ok(V2ResolvedIndexRoot {
            runs,
            referenced_commits,
        })
    }

    /// Reports unanchored commit objects without deleting anything.
    pub async fn report_orphans<A>(&self, anchor: &A) -> V2Result<V2OrphanReport>
    where
        A: V2CommitAnchor,
    {
        self.report_orphans_with_protected_roots(anchor, &[]).await
    }

    /// Reports unanchored commit objects while preserving supplied historical roots.
    pub async fn report_orphans_with_protected_roots<A>(
        &self,
        anchor: &A,
        protected_roots: &[V2AnchorState],
    ) -> V2Result<V2OrphanReport>
    where
        A: V2CommitAnchor,
    {
        let reachability = self
            .load_reachability(anchor, protected_roots, V2MaintenanceBudgets::default())
            .await?;
        self.report_orphans_from_reachability(&reachability).await
    }

    async fn report_orphans_from_reachability(
        &self,
        reachability: &V2ReachabilityState,
    ) -> V2Result<V2OrphanReport> {
        let anchor_sequence = reachability
            .anchor_state
            .as_ref()
            .map(|anchor| anchor.sequence);

        let retained_profile =
            self.provider_profile() == V2ProviderProfile::RetainedVersionObjectLock;
        let listed = if retained_profile {
            self.store()
                .list_prefix_versions("commits/v02/")
                .await
                .map_err(|_| V2FormatError::StorageOperationFailed)?
        } else {
            self.store()
                .list_prefix("commits/v02/")
                .await
                .map_err(|_| V2FormatError::StorageOperationFailed)?
        };
        let mut candidates = Vec::new();
        let now_ms = current_time_ms();
        for mut metadata in listed {
            let exact_reachable = reachability
                .reachable_versions
                .contains(&(metadata.object_id.clone(), metadata.version_id.clone()));
            let mut exact_protection_checked = !retained_profile;
            if retained_profile {
                if exact_reachable {
                    continue;
                }
                if let Some(version_id) = metadata.version_id.as_ref()
                    && let Ok(head) = self
                        .store()
                        .head_at(&metadata.object_id, Some(version_id))
                        .await
                {
                    metadata = head;
                    exact_protection_checked = true;
                }
            } else if reachability.reachable.contains(&metadata.object_id) {
                continue;
            }
            let parsed_key = V2CommitKey::parse(&metadata.object_id).ok();
            let sequence = parsed_key.as_ref().map(|key| key.sequence);
            let delete_blocked_by_unknown_protection =
                retained_profile && (metadata.version_id.is_none() || !exact_protection_checked);
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
                retain_until_ms: metadata.retain_until_ms,
                delete_blocked_by_retention: retention_blocks_delete(
                    metadata.retention.as_ref(),
                    metadata.retain_until_ms,
                    now_ms,
                ),
                delete_blocked_by_legal_hold: metadata.legal_hold == Some(LegalHoldStatus::On),
                delete_blocked_by_unknown_protection,
            });
        }

        Ok(V2OrphanReport {
            reachable_commit_count: reachability.reachable.len(),
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
        guard: &impl V2MaintenanceGuard,
        options: V2OrphanGcOptions,
    ) -> V2Result<V2OrphanGcReport>
    where
        A: V2CommitAnchor,
    {
        guard.verify_v2_maintenance(None).await?;
        let base_anchor = anchor.read_v2().await?;
        guard.verify_v2_maintenance(base_anchor.as_ref()).await?;
        let report = self.report_orphans(anchor).await?;
        self.delete_expired_orphan_candidates(
            anchor,
            guard,
            base_anchor.as_ref(),
            report,
            options,
            None,
        )
        .await
    }

    /// Deletes expired orphan commits while preserving supplied historical roots.
    pub async fn delete_expired_orphans_with_protected_roots<A>(
        &self,
        anchor: &A,
        guard: &impl V2MaintenanceGuard,
        protected_roots: &[V2AnchorState],
        options: V2OrphanGcOptions,
    ) -> V2Result<V2OrphanGcReport>
    where
        A: V2CommitAnchor,
    {
        guard.verify_v2_maintenance(None).await?;
        let base_anchor = anchor.read_v2().await?;
        guard.verify_v2_maintenance(base_anchor.as_ref()).await?;
        let report = self
            .report_orphans_with_protected_roots(anchor, protected_roots)
            .await?;
        self.delete_expired_orphan_candidates(
            anchor,
            guard,
            base_anchor.as_ref(),
            report,
            options,
            None,
        )
        .await
    }

    async fn delete_expired_orphan_candidates<A>(
        &self,
        anchor: &A,
        guard: &impl V2MaintenanceGuard,
        base_anchor: Option<&V2AnchorState>,
        report: V2OrphanReport,
        options: V2OrphanGcOptions,
        max_delete_count: Option<u64>,
    ) -> V2Result<V2OrphanGcReport>
    where
        A: V2CommitAnchor,
    {
        let now_ms = current_time_ms();
        let min_age_ms = options.min_age.as_millis();
        let mut gc = V2OrphanGcReport {
            scanned_count: report.candidates.len(),
            ..V2OrphanGcReport::default()
        };
        let mut delete_attempt_count = 0_u64;

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
            let Some(age_ms) = age_since_ms(now_ms, candidate.modified_at_ms) else {
                gc.age_skipped_count += 1;
                continue;
            };
            if age_ms < min_age_ms {
                gc.age_skipped_count += 1;
                continue;
            }
            if max_delete_count.is_some_and(|max| delete_attempt_count >= max) {
                break;
            }
            if let Err(error) = guard.verify_v2_maintenance(base_anchor).await {
                gc.aborted = Some(error);
                return Ok(gc);
            }
            if anchor.read_v2().await? != base_anchor.cloned() {
                gc.aborted = Some(V2FormatError::StaleAnchor);
                return Ok(gc);
            }

            let delete = if self.provider_profile() == V2ProviderProfile::RetainedVersionObjectLock
            {
                let Some(version_id) = candidate.version_id.as_ref() else {
                    gc.protected_count += 1;
                    continue;
                };
                self.store()
                    .delete_at(&candidate.object_id, Some(version_id))
                    .await
            } else {
                self.store().delete(&candidate.object_id).await
            };
            delete_attempt_count = delete_attempt_count.saturating_add(1);

            match delete {
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

    async fn load_reachability<A>(
        &self,
        anchor: &A,
        protected_roots: &[V2AnchorState],
        budgets: V2MaintenanceBudgets,
    ) -> V2Result<V2ReachabilityState>
    where
        A: V2CommitAnchor,
    {
        let anchor_state = anchor.read_v2().await?;
        let mut reachability = V2ReachabilityState {
            anchor_state: anchor_state.clone(),
            ..V2ReachabilityState::default()
        };

        if let Some(state) = anchor_state.as_ref() {
            let chain = self
                .load_maintenance_chain(state, &reachability, budgets)
                .await?;
            reachability.include_chain(&chain, false);
            self.include_live_payload_roots(&mut reachability, &chain, false, budgets)
                .await?;
            reachability.current_chain = Some(chain);
        }

        for protected_root in protected_roots {
            let chain = self
                .load_maintenance_chain(protected_root, &reachability, budgets)
                .await?;
            reachability.include_chain(&chain, true);
            self.include_live_payload_roots(&mut reachability, &chain, true, budgets)
                .await?;
        }

        Ok(reachability)
    }

    async fn load_maintenance_chain(
        &self,
        root: &V2AnchorState,
        reachability: &V2ReachabilityState,
        budgets: V2MaintenanceBudgets,
    ) -> V2Result<V2ReplayChain> {
        let configured = self.options().replay_limits;
        let used_commits = usize::try_from(reachability.chain_get_count)
            .map_err(|_| V2FormatError::MaintenanceBudgetExceeded)?;
        let mut max_commits = configured
            .max_commits
            .checked_sub(used_commits)
            .ok_or(V2FormatError::ReplayBudgetExceeded)?;
        if let Some(max_requests) = budgets.max_request_count {
            let remaining = max_requests
                .checked_sub(reachability.chain_get_count)
                .ok_or(V2FormatError::MaintenanceBudgetExceeded)?;
            max_commits = max_commits.min(
                usize::try_from(remaining).map_err(|_| V2FormatError::MaintenanceBudgetExceeded)?,
            );
        }

        let mut max_total_commit_bytes = configured
            .max_total_commit_bytes
            .checked_sub(reachability.chain_read_bytes)
            .ok_or(V2FormatError::ReplayBudgetExceeded)?;
        if let Some(max_bytes) = budgets.max_range_read_bytes {
            let remaining = max_bytes
                .checked_sub(reachability.chain_read_bytes)
                .ok_or(V2FormatError::MaintenanceBudgetExceeded)?;
            max_total_commit_bytes = max_total_commit_bytes.min(remaining);
        }
        let max_retained_bytes = configured
            .max_retained_bytes
            .checked_sub(reachability.chain_retained_bytes)
            .ok_or(V2FormatError::ReplayBudgetExceeded)?;

        if max_commits == 0 || max_total_commit_bytes == 0 || max_retained_bytes == 0 {
            return Err(V2FormatError::MaintenanceBudgetExceeded);
        }
        self.load_replay_chain_from_state_with_limits(
            root,
            V2ReplayLimits {
                max_commits,
                max_total_commit_bytes,
                max_retained_bytes,
                ..configured
            },
        )
        .await
    }

    async fn include_live_payload_roots(
        &self,
        reachability: &mut V2ReachabilityState,
        chain: &V2ReplayChain,
        protected: bool,
        budgets: V2MaintenanceBudgets,
    ) -> V2Result<()> {
        let limits = self.remaining_graph_limits(reachability, budgets)?;
        let (live_payload_roots, referenced_run_commits) =
            self.live_payload_roots_from_chain(chain, limits).await?;
        if !referenced_run_commits.is_empty() {
            reachability.include_chain(
                &V2ReplayChain {
                    commits_newest_first: referenced_run_commits,
                },
                protected,
            );
        }
        for root in live_payload_roots {
            let version_key = (root.commit_key.clone(), root.version_id.clone());
            if reachability.reachable_versions.contains(&version_key) {
                continue;
            }
            let commit = self
                .read_replay_commit_at(&root.commit_key, root.version_id.as_ref())
                .await?;
            if commit.parsed_header.header.self_ref.sequence != root.sequence
                || commit.parsed_header.header.body_digest != root.body_digest
                || commit.version_id != root.version_id
            {
                return Err(V2FormatError::BodyDigestMismatch);
            }
            reachability.include_chain(
                &V2ReplayChain {
                    commits_newest_first: vec![commit],
                },
                protected,
            );
        }

        Ok(())
    }

    fn remaining_graph_limits(
        &self,
        reachability: &V2ReachabilityState,
        budgets: V2MaintenanceBudgets,
    ) -> V2Result<V2ReplayLimits> {
        let configured = self.options().replay_limits;
        let used_commits = usize::try_from(reachability.chain_get_count)
            .map_err(|_| V2FormatError::MaintenanceBudgetExceeded)?;
        let mut max_commits = configured
            .max_commits
            .checked_sub(used_commits)
            .ok_or(V2FormatError::ReplayBudgetExceeded)?;
        if let Some(max_requests) = budgets.max_request_count {
            let remaining = max_requests
                .checked_sub(reachability.chain_get_count)
                .ok_or(V2FormatError::MaintenanceBudgetExceeded)?;
            max_commits = max_commits.min(
                usize::try_from(remaining).map_err(|_| V2FormatError::MaintenanceBudgetExceeded)?,
            );
        }
        let mut max_total_commit_bytes = configured
            .max_total_commit_bytes
            .checked_sub(reachability.chain_read_bytes)
            .ok_or(V2FormatError::ReplayBudgetExceeded)?;
        if let Some(max_bytes) = budgets.max_range_read_bytes {
            max_total_commit_bytes = max_total_commit_bytes.min(
                max_bytes
                    .checked_sub(reachability.chain_read_bytes)
                    .ok_or(V2FormatError::MaintenanceBudgetExceeded)?,
            );
        }
        let max_retained_bytes = configured
            .max_retained_bytes
            .checked_sub(reachability.chain_retained_bytes)
            .ok_or(V2FormatError::ReplayBudgetExceeded)?;
        Ok(V2ReplayLimits {
            max_commits,
            max_total_commit_bytes,
            max_retained_bytes,
            ..configured
        })
    }

    async fn live_payload_roots_from_chain(
        &self,
        chain: &V2ReplayChain,
        limits: V2ReplayLimits,
    ) -> V2Result<(Vec<V2AnchorState>, Vec<V2ReplayCommit>)> {
        let (state, referenced_run_commits) =
            self.replay_chain_to_namespace_state(chain, limits).await?;
        let signing_key_id = chain
            .commits_newest_first
            .first()
            .ok_or(V2FormatError::InvalidHeaderField)?
            .parsed_header
            .header
            .signing_key_id
            .clone();
        let mut roots = Vec::new();

        for entry in state.namespace.live_entries() {
            let (commit_key, commit_version_id, body_digest) = match &entry.payload_ref {
                Some(PayloadReference::V2Commit {
                    commit_key,
                    commit_version_id,
                    body_digest,
                    ..
                })
                | Some(PayloadReference::V2Pack {
                    commit_key,
                    commit_version_id,
                    body_digest,
                    ..
                }) => (commit_key.clone(), commit_version_id.clone(), *body_digest),
                None => continue,
                Some(PayloadReference::V2Self { .. } | PayloadReference::V2PackSelf { .. }) => {
                    return Err(V2FormatError::InvalidHeaderField);
                }
            };
            let parsed_key = V2CommitKey::parse(&commit_key)?;
            roots.push(V2AnchorState {
                sequence: parsed_key.sequence,
                commit_key,
                body_digest,
                version_id: commit_version_id,
                signing_key_id: signing_key_id.clone(),
                format_ref: self.options().format_ref.clone(),
            });
        }

        Ok((roots, referenced_run_commits))
    }

    async fn replay_chain_to_namespace_state(
        &self,
        chain: &V2ReplayChain,
        limits: V2ReplayLimits,
    ) -> V2Result<(RepositoryState, Vec<V2ReplayCommit>)> {
        let mut state = RepositoryState::default();
        let mut referenced_run_commits = Vec::new();
        let mut previous_published_at_ms = None;
        for commit in chain.commits_newest_first.iter().rev() {
            let published_at_ms = commit.parsed_header.header.publish_time_ms;
            if previous_published_at_ms.is_some_and(|previous| published_at_ms < previous) {
                return Err(V2FormatError::StaleAnchor);
            }
            previous_published_at_ms = Some(published_at_ms);
            referenced_run_commits.extend(
                self.apply_commit_sections_to_namespace_state(&mut state, commit, limits)
                    .await?,
            );
        }
        Ok((state, referenced_run_commits))
    }

    async fn apply_commit_sections_to_namespace_state(
        &self,
        state: &mut RepositoryState,
        commit: &V2ReplayCommit,
        limits: V2ReplayLimits,
    ) -> V2Result<Vec<V2ReplayCommit>> {
        let mut referenced_run_commits = Vec::new();
        for (index, section) in commit.parsed_header.header.section_index.iter().enumerate() {
            match section.section_type {
                V2SectionType::IndexDelta => {
                    let section_bytes = commit_section_bytes(commit, index)?;
                    let mut delta = self.open_index_delta_section(
                        &commit.parsed_header.header.self_ref.commit_key,
                        index,
                        section_bytes,
                        section.flags,
                    )?;
                    if let Some(delta) = delta.as_mut() {
                        resolve_self_payload_refs(delta, commit)?;
                    }
                    if let Some(delta) = delta {
                        apply_index_delta_object(state, delta);
                    }
                }
                V2SectionType::IndexSnapshot => {
                    let section_bytes = commit_section_bytes(commit, index)?;
                    if section_bytes.is_empty() {
                        *state = RepositoryState::default();
                        continue;
                    }
                    let mut snapshot = self.open_index_delta_section(
                        &commit.parsed_header.header.self_ref.commit_key,
                        index,
                        section_bytes,
                        section.flags,
                    )?;
                    if let Some(snapshot) = snapshot.as_mut() {
                        resolve_self_payload_refs(snapshot, commit)?;
                    }
                    if let Some(snapshot) = snapshot {
                        *state = RepositoryState::default();
                        apply_index_delta_object(state, snapshot);
                    }
                }
                V2SectionType::Payload | V2SectionType::PayloadPack => {}
                V2SectionType::IndexRun => {
                    let section_bytes = commit_section_bytes(commit, index)?;
                    apply_packed_index_run(
                        self.keyring(),
                        &self.options().repository_id,
                        state,
                        V2PackedIndexRunReplay {
                            parsed_header: &commit.parsed_header,
                            version_id: commit.version_id.as_ref(),
                            object_len: commit.object_len,
                            section_ordinal: u32::try_from(index)
                                .map_err(|_| V2FormatError::SectionBounds)?,
                            stored_run: section_bytes,
                            level: 0,
                            compaction_generation: 0,
                        },
                    )
                    .map_err(|_| V2FormatError::InvalidIndexRun)?;
                }
                V2SectionType::IndexRoot => {
                    let section_bytes = commit_section_bytes(commit, index)?;
                    let resolved = self
                        .apply_index_root_to_state(
                            state,
                            commit,
                            u32::try_from(index).map_err(|_| V2FormatError::SectionBounds)?,
                            section_bytes,
                            limits,
                        )
                        .await?;
                    referenced_run_commits.extend(resolved.referenced_commits);
                }
                V2SectionType::Directives | V2SectionType::Unknown(_) => {
                    if section.flags & V2_SECTION_FLAG_MUST_UNDERSTAND != 0 {
                        return Err(V2FormatError::UnsupportedSection);
                    }
                }
            }
        }
        Ok(referenced_run_commits)
    }

    fn open_index_delta_section(
        &self,
        commit_key: &BackendObjectId,
        section_index: usize,
        bytes: &[u8],
        flags: u8,
    ) -> V2Result<Option<IndexDeltaObject>> {
        let Some(payload) = bytes.strip_prefix(INDEX_DELTA_OBJECT_DOMAIN) else {
            return if flags & V2_SECTION_FLAG_MUST_UNDERSTAND != 0 {
                Err(V2FormatError::InvalidHeaderField)
            } else {
                Ok(None)
            };
        };
        let sealed_delta = serde_json::from_slice::<SealedIndexDeltaObject>(payload)
            .map_err(|_| V2FormatError::InvalidHeaderField)?;
        let object_id = BackendObjectId::new(format!(
            "{}/index-delta-{section_index}",
            commit_key.as_str()
        ))
        .map_err(|_| V2FormatError::TypeValidation)?;
        open_index_delta_object(self.keyring(), &object_id, &sealed_delta)
            .map_err(|_| V2FormatError::InvalidHeaderField)
            .map(Some)
    }

    /// Runs read-only quick maintenance checks.
    pub async fn quick_maintenance<A>(&self, anchor: &A) -> V2Result<V2MaintenanceReport>
    where
        A: V2CommitAnchor,
    {
        let chain = self.load_replay_chain_from_anchor(anchor).await?;
        let verified_commit_count = chain
            .as_ref()
            .map(|chain| chain.commits_newest_first.len())
            .unwrap_or_default();
        let now_ms = current_time_ms();
        let last_anchored_commit_age_ms = chain
            .as_ref()
            .and_then(|chain| chain.commits_newest_first.first())
            .and_then(|commit| {
                age_since_ms(now_ms, Some(commit.parsed_header.header.publish_time_ms))
            });
        let orphans = self.report_orphans(anchor).await?;
        let orphan_candidate_bytes = orphans.candidates.iter().fold(0_u64, |total, candidate| {
            total.saturating_add(candidate.content_len)
        });
        let protected_orphan_candidate_count = orphans
            .candidates
            .iter()
            .filter(|candidate| {
                candidate.delete_blocked_by_retention
                    || candidate.delete_blocked_by_legal_hold
                    || candidate.delete_blocked_by_unknown_protection
            })
            .count();
        let oldest_orphan_age_ms = orphans
            .candidates
            .iter()
            .filter_map(|candidate| age_since_ms(now_ms, candidate.modified_at_ms))
            .max();
        let retention_renewal = if let Some(chain) = chain.as_ref() {
            self.plan_retention_renewal(
                &chain.commits_newest_first,
                DEFAULT_RETENTION_RENEWAL_HORIZON,
            )
            .await?
        } else {
            V2RetentionRenewalPlan::default()
        };
        Ok(V2MaintenanceReport {
            anchor_present: chain.is_some(),
            verified_commit_count,
            last_anchored_commit_age_ms,
            orphan_candidate_count: orphans.candidates.len(),
            orphan_candidate_bytes,
            protected_orphan_candidate_count,
            oldest_orphan_age_ms,
            retention_renewal_commit_count: retention_renewal.commit_count,
            retention_renewal_bytes: retention_renewal.bytes,
            retention_renewal_blocked_count: retention_renewal.blocked_count,
            retention_renewal_blocked_bytes: retention_renewal.blocked_bytes,
        })
    }

    /// Builds a path-redacted full-maintenance dry-run plan.
    ///
    /// This first-stage planner is intentionally limited to commit-object
    /// inventory and fully dead orphan deletion. Mixed accepted-commit repack
    /// details are filled by the repository service after namespace replay.
    pub async fn full_gc_dry_run<A>(
        &self,
        anchor: &A,
        options: V2FullGcDryRunOptions,
    ) -> V2Result<V2FullGcDryRunReport>
    where
        A: V2CommitAnchor,
    {
        let reachability = self
            .load_reachability(anchor, &options.protected_roots, options.budgets)
            .await?;
        let chain_live_commit_count = reachability
            .current_chain
            .as_ref()
            .map(|chain| chain.commits_newest_first.len())
            .unwrap_or_default();
        let orphans = self.report_orphans_from_reachability(&reachability).await?;
        let retained_profile =
            self.provider_profile() == V2ProviderProfile::RetainedVersionObjectLock;
        let retention_renewal = self
            .plan_retention_renewal(
                &reachability.renewal_commits,
                options.retention_renewal_horizon,
            )
            .await?;

        let mut fully_dead_commit_count = 0;
        let mut dead_bytes_reclaimable = 0_u64;
        let mut retention_blocked_bytes = 0_u64;
        let mut legal_hold_blocked_bytes = 0_u64;
        let mut unknown_protection_blocked_bytes = 0_u64;
        let mut delete_count = 0_u64;
        let mut head_count = 0_u64;

        for candidate in &orphans.candidates {
            if retained_profile && candidate.version_id.is_some() {
                head_count = head_count.saturating_add(1);
            }
            if candidate.delete_blocked_by_retention {
                retention_blocked_bytes =
                    retention_blocked_bytes.saturating_add(candidate.content_len);
                continue;
            }
            if candidate.delete_blocked_by_legal_hold {
                legal_hold_blocked_bytes =
                    legal_hold_blocked_bytes.saturating_add(candidate.content_len);
                continue;
            }
            if candidate.delete_blocked_by_unknown_protection {
                unknown_protection_blocked_bytes =
                    unknown_protection_blocked_bytes.saturating_add(candidate.content_len);
                continue;
            }

            fully_dead_commit_count += 1;
            dead_bytes_reclaimable = dead_bytes_reclaimable.saturating_add(candidate.content_len);
            delete_count = delete_count.saturating_add(1);
        }

        let version_list_count = u64::from(retained_profile);
        let prefix_list_count = u64::from(!retained_profile);
        let chain_get_count = reachability.chain_get_count;
        let planned_cost = V2MaintenancePlanCost {
            request_count: version_list_count
                .saturating_add(prefix_list_count)
                .saturating_add(chain_get_count)
                .saturating_add(head_count)
                .saturating_add(delete_count)
                .saturating_add(retention_renewal.head_count)
                .saturating_add(retention_renewal.extend_count),
            version_list_count,
            head_count: head_count.saturating_add(retention_renewal.head_count),
            range_read_bytes: reachability.chain_read_bytes,
            write_bytes: 0,
            delete_count,
            retention_extend_count: retention_renewal.extend_count,
        };
        let fits_budgets = planned_cost.fits_budgets(options.budgets);
        let exact_version_apply_ready = !retained_profile
            || orphans.candidates.iter().all(|candidate| {
                candidate.version_id.is_some() || candidate.delete_blocked_by_unknown_protection
            });

        Ok(V2FullGcDryRunReport {
            base_sequence: reachability
                .anchor_state
                .as_ref()
                .map(|anchor| anchor.sequence),
            chain_live_commit_count,
            protected_root_count: options.protected_roots.len(),
            protected_commit_count: reachability.protected_versions.len(),
            candidate_commit_count: orphans.candidates.len(),
            fully_dead_commit_count,
            mixed_commit_count: 0,
            dead_bytes_reclaimable,
            live_bytes_to_copy: 0,
            mixed_dead_bytes_repackable: 0,
            retention_blocked_bytes,
            legal_hold_blocked_bytes,
            unknown_protection_blocked_bytes,
            retention_renewal_commit_count: retention_renewal.commit_count,
            retention_renewal_bytes: retention_renewal.bytes,
            retention_renewal_blocked_count: retention_renewal.blocked_count,
            retention_renewal_blocked_bytes: retention_renewal.blocked_bytes,
            planned_cost,
            fits_budgets,
            exact_version_apply_ready,
        })
    }

    /// Applies the first destructive full-maintenance stage: fully dead orphan
    /// commit deletion.
    ///
    /// This does not repack mixed accepted commits. It fails closed unless the
    /// dry-run budget passes, retained-version provider conformance is supplied
    /// for retained repositories, and the maintenance guard plus base anchor are
    /// still valid before each exact-version delete.
    pub async fn apply_fully_dead_orphans<A, G>(
        &self,
        anchor: &A,
        guard: &G,
        options: V2FullGcApplyOptions,
    ) -> V2Result<V2FullGcApplyReport>
    where
        A: V2CommitAnchor,
        G: V2MaintenanceGuard,
    {
        guard.verify_v2_maintenance(None).await?;
        let base_anchor = anchor.read_v2().await?;
        guard.verify_v2_maintenance(base_anchor.as_ref()).await?;

        if self.provider_profile() == V2ProviderProfile::RetainedVersionObjectLock
            && !options.retained_provider_conformance_passed
        {
            return Err(V2FormatError::ProviderProfileFailed);
        }

        let dry_run = self
            .full_gc_dry_run(anchor, options.dry_run.clone())
            .await?;
        if !dry_run.fits_budgets {
            return Err(V2FormatError::MaintenanceBudgetExceeded);
        }
        if !dry_run.exact_version_apply_ready {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        if anchor.read_v2().await? != base_anchor {
            return Err(V2FormatError::StaleAnchor);
        }

        let orphans = self
            .report_orphans_with_protected_roots(anchor, &options.dry_run.protected_roots)
            .await?;
        let gc = self
            .delete_expired_orphan_candidates(
                anchor,
                guard,
                base_anchor.as_ref(),
                orphans,
                options.orphan_gc,
                Some(dry_run.planned_cost.delete_count),
            )
            .await?;

        Ok(V2FullGcApplyReport {
            dry_run,
            orphan_gc: gc,
        })
    }

    async fn plan_retention_renewal(
        &self,
        commits: &[V2ReplayCommit],
        horizon: Duration,
    ) -> V2Result<V2RetentionRenewalPlan> {
        let Some(policy) = active_retention(self.retention_policy()) else {
            return Ok(V2RetentionRenewalPlan::default());
        };
        if commits.is_empty() {
            return Ok(V2RetentionRenewalPlan::default());
        }
        let retained_profile =
            self.provider_profile() == V2ProviderProfile::RetainedVersionObjectLock;
        let renew_before_ms =
            current_time_ms().saturating_add(duration_millis_i64_saturating(horizon));
        let mut plan = V2RetentionRenewalPlan::default();

        for commit in commits {
            let object_id = &commit.parsed_header.header.self_ref.commit_key;
            let version_id = commit.version_id.as_ref();
            if retained_profile && version_id.is_none() {
                plan.blocked_count = plan.blocked_count.saturating_add(1);
                plan.blocked_bytes = plan.blocked_bytes.saturating_add(commit.object_len);
                continue;
            }

            plan.head_count = plan.head_count.saturating_add(1);
            let metadata = if retained_profile {
                self.store().head_at(object_id, version_id).await
            } else {
                self.store().head(object_id).await
            }
            .map_err(|_| V2FormatError::StorageOperationFailed)?;

            if retention_renewal_needed(&metadata, policy, renew_before_ms) {
                plan.commit_count = plan.commit_count.saturating_add(1);
                plan.bytes = plan.bytes.saturating_add(metadata.content_len);
                plan.extend_count = plan.extend_count.saturating_add(1);
            }
        }

        Ok(plan)
    }
}

fn current_time_ms() -> i64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis();
    i64::try_from(millis).unwrap_or(i64::MAX)
}

fn age_since_ms(now_ms: i64, timestamp_ms: Option<i64>) -> Option<u128> {
    let timestamp_ms = timestamp_ms?;
    let age_ms = now_ms.checked_sub(timestamp_ms)?;
    u128::try_from(age_ms).ok()
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn budget_allows(limit: Option<u64>, value: u64) -> bool {
    limit.is_none_or(|limit| value <= limit)
}

fn active_retention(policy: Option<RetentionPolicy>) -> Option<RetentionPolicy> {
    policy.filter(|policy| policy.mode != RetentionMode::None && policy.retain_days > 0)
}

fn retention_renewal_needed(
    metadata: &BlobMetadata,
    requested: RetentionPolicy,
    renew_before_ms: i64,
) -> bool {
    !retention_satisfies(metadata.retention.as_ref(), &requested)
        || metadata
            .retain_until_ms
            .is_none_or(|retain_until_ms| retain_until_ms <= renew_before_ms)
}

fn retention_satisfies(actual: Option<&RetentionPolicy>, requested: &RetentionPolicy) -> bool {
    let Some(actual) = actual else {
        return false;
    };
    retention_mode_strength(actual.mode) >= retention_mode_strength(requested.mode)
        && actual.retain_days >= requested.retain_days
}

fn retention_mode_strength(mode: RetentionMode) -> u8 {
    match mode {
        RetentionMode::None => 0,
        RetentionMode::Governance => 1,
        RetentionMode::Compliance => 2,
    }
}

fn retention_blocks_delete(
    policy: Option<&RetentionPolicy>,
    retain_until_ms: Option<i64>,
    now_ms: i64,
) -> bool {
    match policy {
        Some(policy) if policy.mode != RetentionMode::None && policy.retain_days > 0 => {
            retain_until_ms.is_none_or(|retain_until_ms| retain_until_ms > now_ms)
        }
        Some(_) | None => false,
    }
}

fn duration_millis_i64_saturating(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

fn commit_section_bytes(commit: &V2ReplayCommit, index: usize) -> V2Result<&[u8]> {
    commit
        .retained_sections
        .get(index)
        .and_then(Option::as_deref)
        .ok_or(V2FormatError::SectionBounds)
}

fn resolve_self_payload_refs(
    delta: &mut IndexDeltaObject,
    commit: &V2ReplayCommit,
) -> V2Result<()> {
    for mutation in &mut delta.deltas {
        let IndexDelta::Upsert { entry, .. } = mutation else {
            continue;
        };
        let Some(PayloadReference::V2Self {
            payload_id,
            payload_header,
            sections_start: _,
            offset,
            length,
        }) = entry.payload_ref.clone()
        else {
            continue;
        };
        let (payload_section_ordinal, payload_section_digest) =
            payload_section_facts(commit, offset, length)?;
        let sections_start = u64::try_from(commit.parsed_header.sections_start)
            .map_err(|_| V2FormatError::SectionBounds)?;
        let commit_key = commit.parsed_header.header.self_ref.commit_key.clone();
        entry.object_id = commit_key.clone();
        entry.object_version_id = commit.version_id.clone();
        entry.payload_ref = Some(PayloadReference::V2Commit {
            commit_key,
            commit_version_id: commit.version_id.clone(),
            body_digest: commit.parsed_header.header.body_digest,
            commit_stored_len: commit.object_len,
            keyring_envelope_object_id: commit
                .parsed_header
                .header
                .keyring_envelope_ref
                .object_id
                .clone(),
            keyring_envelope_digest: commit.parsed_header.header.keyring_envelope_ref.digest,
            payload_section_ordinal,
            payload_section_digest,
            payload_id,
            payload_header,
            sections_start: Some(sections_start),
            offset,
            length,
        });
    }
    Ok(())
}

fn payload_section_facts(
    commit: &V2ReplayCommit,
    offset: u64,
    length: u64,
) -> V2Result<(u32, [u8; 32])> {
    commit
        .parsed_header
        .header
        .section_index
        .iter()
        .enumerate()
        .find(|(_, section)| {
            section.section_type == V2SectionType::Payload
                && section.offset == offset
                && section.length == length
        })
        .map(|(ordinal, section)| {
            u32::try_from(ordinal)
                .map(|ordinal| (ordinal, section.digest))
                .map_err(|_| V2FormatError::SectionBounds)
        })
        .transpose()?
        .ok_or(V2FormatError::SectionBounds)
}
