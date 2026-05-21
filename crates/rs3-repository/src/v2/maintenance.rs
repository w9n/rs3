//! v2 maintenance planning and conservative apply paths.

use super::commit::{V2CommitKey, V2ParsedCommit};
use super::error::{V2FormatError, V2Result};
use super::provider::V2ProviderProfile;
use super::repository::{V2AnchorState, V2CommitAnchor, V2CommitChain, V2CommitStore};
use async_trait::async_trait;
use rs3_storage::BlobMetadata;
use rs3_storage::{BlobStore, StorageError};
use rs3_types::{
    BackendObjectId, BackendVersionId, LegalHoldStatus, RetentionMode, RetentionPolicy, Sequence,
};
use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_RETENTION_RENEWAL_HORIZON: Duration = Duration::from_secs(7 * 24 * 60 * 60);

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

/// Explicit guard for operator-quiesced maintenance windows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct V2QuiescedMaintenanceGuard;

#[async_trait]
impl V2MaintenanceGuard for V2QuiescedMaintenanceGuard {
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
    current_chain: Option<V2CommitChain>,
    reachable: BTreeSet<BackendObjectId>,
    reachable_versions: BTreeSet<(BackendObjectId, Option<BackendVersionId>)>,
    renewal_commits: Vec<V2ParsedCommit>,
    renewal_seen: BTreeSet<(BackendObjectId, Option<BackendVersionId>)>,
    protected_versions: BTreeSet<(BackendObjectId, Option<BackendVersionId>)>,
    chain_get_count: u64,
    chain_read_bytes: u64,
}

impl V2ReachabilityState {
    fn include_chain(&mut self, chain: &V2CommitChain, protected: bool) {
        self.chain_get_count = self
            .chain_get_count
            .saturating_add(usize_to_u64(chain.commits_newest_first.len()));
        for commit in &chain.commits_newest_first {
            self.chain_read_bytes = self
                .chain_read_bytes
                .saturating_add(usize_to_u64(commit.body.len()));
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
        let reachability = self.load_reachability(anchor, protected_roots).await?;
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
                .list_prefix_versions("commits/v01/")
                .await
                .map_err(|_| V2FormatError::StorageOperationFailed)?
        } else {
            self.store()
                .list_prefix("commits/v01/")
                .await
                .map_err(|_| V2FormatError::StorageOperationFailed)?
        };
        let mut candidates = Vec::new();
        for mut metadata in listed {
            let exact_reachable = reachability
                .reachable_versions
                .contains(&(metadata.object_id.clone(), metadata.version_id.clone()));
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
                }
            } else if reachability.reachable.contains(&metadata.object_id) {
                continue;
            }
            let parsed_key = V2CommitKey::parse(&metadata.object_id).ok();
            let sequence = parsed_key.as_ref().map(|key| key.sequence);
            let delete_blocked_by_unknown_protection = retained_profile
                && (metadata.version_id.is_none()
                    || (metadata.retention.is_none() && metadata.legal_hold.is_none()));
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
        options: V2OrphanGcOptions,
    ) -> V2Result<V2OrphanGcReport>
    where
        A: V2CommitAnchor,
    {
        let report = self.report_orphans(anchor).await?;
        self.delete_expired_orphan_candidates(report, options).await
    }

    /// Deletes expired orphan commits while preserving supplied historical roots.
    pub async fn delete_expired_orphans_with_protected_roots<A>(
        &self,
        anchor: &A,
        protected_roots: &[V2AnchorState],
        options: V2OrphanGcOptions,
    ) -> V2Result<V2OrphanGcReport>
    where
        A: V2CommitAnchor,
    {
        let report = self
            .report_orphans_with_protected_roots(anchor, protected_roots)
            .await?;
        self.delete_expired_orphan_candidates(report, options).await
    }

    async fn delete_expired_orphan_candidates(
        &self,
        report: V2OrphanReport,
        options: V2OrphanGcOptions,
    ) -> V2Result<V2OrphanGcReport> {
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
            let chain = self.load_chain_from_state(state).await?;
            reachability.include_chain(&chain, false);
            reachability.current_chain = Some(chain);
        }

        for protected_root in protected_roots {
            let chain = self.load_chain_from_state(protected_root).await?;
            reachability.include_chain(&chain, true);
        }

        Ok(reachability)
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
            orphan_candidate_count: orphans.candidates.len(),
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
            .load_reachability(anchor, &options.protected_roots)
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
        let now_ms = current_time_ms();
        let min_age_ms = options.orphan_gc.min_age.as_millis();
        let mut gc = V2OrphanGcReport {
            scanned_count: orphans.candidates.len(),
            ..V2OrphanGcReport::default()
        };

        for candidate in orphans.candidates {
            if candidate.delete_blocked_by_retention
                || candidate.delete_blocked_by_legal_hold
                || candidate.delete_blocked_by_unknown_protection
            {
                gc.protected_count += 1;
                continue;
            }
            if candidate.same_sequence_as_anchor && !options.orphan_gc.delete_same_sequence {
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

            guard.verify_v2_maintenance(base_anchor.as_ref()).await?;
            if anchor.read_v2().await? != base_anchor {
                return Err(V2FormatError::StaleAnchor);
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

            match delete {
                Ok(()) => gc.deleted_count += 1,
                Err(StorageError::NotFound(_)) => gc.already_gone_count += 1,
                Err(StorageError::RetentionBlocked | StorageError::LegalHoldBlocked) => {
                    gc.protected_count += 1;
                }
                Err(_) => gc.failed_delete_count += 1,
            }
        }

        Ok(V2FullGcApplyReport {
            dry_run,
            orphan_gc: gc,
        })
    }

    async fn plan_retention_renewal(
        &self,
        commits: &[V2ParsedCommit],
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
                plan.blocked_bytes = plan
                    .blocked_bytes
                    .saturating_add(usize_to_u64(commit.body.len()));
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

fn candidate_age_ms(now_ms: i64, modified_at_ms: Option<i64>) -> Option<u128> {
    let modified_at_ms = modified_at_ms?;
    let age_ms = now_ms.checked_sub(modified_at_ms)?;
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

fn retention_blocks_delete(policy: Option<&RetentionPolicy>) -> bool {
    match policy {
        Some(policy) => policy.mode != RetentionMode::None && policy.retain_days > 0,
        None => false,
    }
}

fn duration_millis_i64_saturating(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}
