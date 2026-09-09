//! v3 full-maintenance dry-run and compaction snapshot orchestration.

use super::super::error::V3FormatError;
use super::super::repository::{V3CommitAnchor, V3ReplayChain};
use super::super::{
    V3_PAYLOAD_PACK_SEGMENT_BYTES, V3FullGcApplyOptions, V3FullGcApplyReport,
    V3FullGcDryRunOptions, V3FullGcDryRunReport, V3FullGcPlanPreview, V3MaintenanceCancellation,
    V3MaintenanceGuard, V3SectionType,
};
use super::{V3Repository, v3_repository_error};
use crate::error::Result;
use crate::state::RepositoryState;
use rs3_index::PayloadReference;
use rs3_storage::BlobStore;
use rs3_types::{BackendObjectId, BackendVersionId};
use std::collections::BTreeSet;

/// Outcome of one quiesced in-process v3 full-maintenance run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V3FullMaintenanceReport {
    /// Budgeted service-level dry run captured inside the exclusion window.
    ///
    /// This report overlays mixed-commit repack candidates for observability
    /// only. The apply pass below never repacks, so its own engine-level
    /// preflight remains the budget gate for the mutations it performs.
    pub dry_run: V3FullGcDryRunReport,
    /// Destructive renewal-then-delete outcome, including the engine preflight.
    pub apply: V3FullGcApplyReport,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct V3LivePayloadPackRecordKey {
    commit_key: BackendObjectId,
    commit_version_id: Option<BackendVersionId>,
    body_digest: [u8; 32],
    pack_section_ordinal: u32,
    pack_record_count: u32,
    record_ordinal: u32,
    content_len: u64,
}

impl<S> V3Repository<S>
where
    S: BlobStore + Clone,
{
    /// Builds a path-redacted full-maintenance dry-run plan from current
    /// trusted namespace state.
    pub async fn full_gc_dry_run<A>(
        &self,
        anchor: &A,
        options: V3FullGcDryRunOptions,
    ) -> Result<V3FullGcDryRunReport>
    where
        A: V3CommitAnchor,
    {
        let (report, current) = self
            .commit_store
            .full_gc_dry_run_with_state(anchor, options.clone())
            .await
            .map_err(v3_repository_error)?;
        let current = current.as_ref().map(|(chain, state)| (chain, state));
        self.overlay_full_gc_service_report(report, current, options.budgets)
    }

    /// Builds a repository-owned preview digest for the exact private apply plan.
    pub async fn preview_full_gc_plan<A>(
        &self,
        anchor: &A,
        options: V3FullGcApplyOptions,
    ) -> Result<V3FullGcPlanPreview>
    where
        A: V3CommitAnchor,
    {
        let prepared = self
            .commit_store
            .prepare_full_gc_plan(anchor, options.clone())
            .await
            .map_err(v3_repository_error)?;
        let report = self.overlay_full_gc_service_report(
            prepared.report().clone(),
            prepared.current(),
            options.dry_run.budgets,
        )?;
        Ok(V3FullGcPlanPreview {
            report,
            plan_digest: prepared.plan_digest,
        })
    }

    fn overlay_full_gc_service_report(
        &self,
        mut report: V3FullGcDryRunReport,
        current: Option<(&V3ReplayChain, &RepositoryState)>,
        budgets: super::super::V3MaintenanceBudgets,
    ) -> Result<V3FullGcDryRunReport> {
        let Some((chain, state)) = current else {
            return Ok(report);
        };
        let (mixed_count, live_bytes_to_copy, mixed_dead_bytes_repackable) =
            self.current_head_mixed_payload_summary(state, chain)?;
        report.mixed_commit_count = mixed_count;
        report.live_bytes_to_copy = live_bytes_to_copy;
        report.mixed_dead_bytes_repackable = mixed_dead_bytes_repackable;
        if live_bytes_to_copy > 0 {
            report.planned_cost.request_count = report.planned_cost.request_count.saturating_add(1);
            report.planned_cost.write_bytes = report
                .planned_cost
                .write_bytes
                .saturating_add(live_bytes_to_copy);
            report.fits_budgets = report.planned_cost.fits_budgets(budgets);
            if budgets.max_request_count.is_some()
                || budgets.max_head_count.is_some()
                || budgets.max_range_read_bytes.is_some()
                || budgets.max_write_bytes.is_some()
            {
                // Snapshot publication and fresh-reader verification have a
                // data-dependent request shape. Finite I/O ceilings fail closed
                // until that separate mutation path is metered end to end.
                report.fits_budgets = false;
            }
        }
        Ok(report)
    }

    /// Runs budgeted retention renewal plus orphan deletion for one quiesced
    /// exclusion window.
    ///
    /// The caller must hold a window that excludes concurrent v2 publications
    /// for the whole call, normally
    /// [`super::super::V3CommitCoordinator::begin_maintenance_window`], and
    /// must pass that window's verified guard. The engine keeps its existing
    /// invariants: renewal runs strictly before deletion, and every mutation
    /// rechecks the maintenance guard plus the base anchor and fails closed on
    /// loss. The cancellation signal is honored between mutations only; a
    /// cancelled or aborted run leaves a re-runnable plan behind. Mixed-commit
    /// repack is out of scope for this pass and stays on the separate guarded
    /// compaction-snapshot path.
    pub async fn apply_full_gc_quiesced<A, G>(
        &self,
        anchor: &A,
        guard: &G,
        options: V3FullGcApplyOptions,
        cancellation: &V3MaintenanceCancellation,
    ) -> Result<V3FullMaintenanceReport>
    where
        A: V3CommitAnchor,
        G: V3MaintenanceGuard,
    {
        self.apply_full_gc_quiesced_expected(anchor, guard, options, None, cancellation)
            .await
    }

    /// Applies the exact private plan prepared and optionally digest-checked in
    /// this quiesced call, without reopening a planning gap before mutation.
    pub async fn apply_full_gc_quiesced_expected<A, G>(
        &self,
        anchor: &A,
        guard: &G,
        options: V3FullGcApplyOptions,
        expected_plan_digest: Option<&str>,
        cancellation: &V3MaintenanceCancellation,
    ) -> Result<V3FullMaintenanceReport>
    where
        A: V3CommitAnchor,
        G: V3MaintenanceGuard,
    {
        let prepared = self
            .commit_store
            .prepare_full_gc_plan(anchor, options.clone())
            .await
            .map_err(v3_repository_error)?;
        if expected_plan_digest.is_some_and(|expected| prepared.plan_digest != expected) {
            return Err(v3_repository_error(V3FormatError::MaintenancePlanChanged));
        }
        let dry_run = self.overlay_full_gc_service_report(
            prepared.report().clone(),
            prepared.current(),
            options.dry_run.budgets,
        )?;
        let apply = self
            .commit_store
            .apply_prepared_full_gc_cancellable(anchor, guard, prepared, cancellation)
            .await
            .map_err(v3_repository_error)?;
        Ok(V3FullMaintenanceReport { dry_run, apply })
    }

    fn current_head_mixed_payload_summary(
        &self,
        state: &crate::state::RepositoryState,
        chain: &V3ReplayChain,
    ) -> Result<(usize, u64, u64)> {
        let live_pack_records = Self::live_payload_refs_from_state(state)?;
        let mut mixed_commit_count = 0_usize;
        let mut live_bytes_to_copy = 0_u64;
        let mut mixed_dead_bytes_repackable = 0_u64;

        for commit in &chain.commits_newest_first {
            let mut commit_live_bytes = 0_u64;
            let mut commit_dead_bytes = 0_u64;
            let header = &commit.parsed_header.header;
            for (section_ordinal, section) in header.section_index.iter().enumerate() {
                if section.section_type == V3SectionType::PayloadPack {
                    let section_ordinal = u32::try_from(section_ordinal)
                        .map_err(|_| v3_repository_error(V3FormatError::SectionBounds))?;
                    let records = live_pack_records
                        .iter()
                        .filter(|record| {
                            record.commit_key == header.self_ref.commit_key
                                && record.commit_version_id == commit.version_id
                                && record.body_digest == header.body_digest
                                && record.pack_section_ordinal == section_ordinal
                        })
                        .collect::<Vec<_>>();
                    let live_stored_bytes = records.iter().fold(0_u64, |total, record| {
                        let segment_count = record
                            .content_len
                            .saturating_add(V3_PAYLOAD_PACK_SEGMENT_BYTES as u64 - 1)
                            / V3_PAYLOAD_PACK_SEGMENT_BYTES as u64;
                        total.saturating_add(
                            record
                                .content_len
                                .saturating_add(segment_count.saturating_mul(16)),
                        )
                    });
                    let record_count = records.first().map_or(0, |record| record.pack_record_count);
                    if records.iter().any(|record| {
                        record.pack_record_count != record_count
                            || record.record_ordinal >= record.pack_record_count
                    }) || u32::try_from(records.len())
                        .ok()
                        .is_some_and(|count| count > record_count)
                    {
                        return Err(v3_repository_error(V3FormatError::InvalidPayloadPack));
                    }
                    if records.is_empty() {
                        commit_dead_bytes = commit_dead_bytes.saturating_add(section.length);
                    } else if u32::try_from(records.len()).ok() == Some(record_count) {
                        commit_live_bytes = commit_live_bytes.saturating_add(section.length);
                        live_bytes_to_copy = live_bytes_to_copy.saturating_add(section.length);
                    } else {
                        commit_live_bytes = commit_live_bytes.saturating_add(live_stored_bytes);
                        live_bytes_to_copy = live_bytes_to_copy.saturating_add(live_stored_bytes);
                        commit_dead_bytes = commit_dead_bytes
                            .saturating_add(section.length.saturating_sub(live_stored_bytes));
                    }
                }
            }
            if commit_live_bytes > 0 && commit_dead_bytes > 0 {
                mixed_commit_count = mixed_commit_count.saturating_add(1);
                mixed_dead_bytes_repackable =
                    mixed_dead_bytes_repackable.saturating_add(commit_dead_bytes);
            }
        }

        Ok((
            mixed_commit_count,
            live_bytes_to_copy,
            mixed_dead_bytes_repackable,
        ))
    }

    fn live_payload_refs_from_state(
        state: &crate::state::RepositoryState,
    ) -> Result<BTreeSet<V3LivePayloadPackRecordKey>> {
        let mut pack_records = BTreeSet::new();
        for entry in state.namespace.live_entries() {
            match &entry.payload_ref {
                Some(PayloadReference::V3Pack { carrier, record }) => {
                    pack_records.insert(V3LivePayloadPackRecordKey {
                        commit_key: carrier.commit_key.clone(),
                        commit_version_id: carrier.commit_version_id.clone(),
                        body_digest: carrier.body_digest,
                        pack_section_ordinal: carrier.pack_section_ordinal,
                        pack_record_count: carrier.pack_record_count,
                        record_ordinal: record.record_ordinal,
                        content_len: entry.content_len,
                    });
                }
                None => {}
                Some(PayloadReference::Pending | PayloadReference::V3PackSelf { .. }) => {
                    return Err(v3_repository_error(V3FormatError::InvalidHeaderField));
                }
                Some(PayloadReference::V3StandaloneStream { .. }) => {}
            }
        }
        Ok(pack_records)
    }
}
