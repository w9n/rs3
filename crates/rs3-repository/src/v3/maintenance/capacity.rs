//! Admission bounds for recovery graph metadata, independent of retention proof.
//!
//! A small immutable certificate covers a conservative closure of the accepted
//! graph. Candidate additions are charged without rereading that graph. At a
//! boundary (or after cache loss), the exact candidate is walked before CAS.
//! Encoded pending buffers have a separate phase bound: current replay plus one
//! catalog run, then one historical section. Inventory and optional I/O caps
//! remain independent; decoder working state has its own format bounds.

use super::*;
use crate::v3::commit::V3ParsedCommitHeader;
use crate::v3::repository::V3StoredCommit;

// Leave room for a metadata-only expiry root after foreground admission stops.
// A root may use the hard cap; repeated nonreducing roots can consume this margin.
const EXPIRY_ROOT_METADATA_RESERVE: u64 = 128 * 1024;

#[derive(Clone, Debug)]
pub(in crate::v3) struct RecoveryCapacity {
    anchor: V3AnchorState,
    budgets: V3MaintenanceBudgets,
    metadata_bytes: u64,
    targets: u64,
    current_replay_bytes: u64,
    current_max_section_bytes: u64,
    read_chunk_bytes: u64,
    catalog_max_run_bytes: u64,
    history_max_section_bytes: u64,
}

impl RecoveryCapacity {
    fn fits(&self) -> bool {
        self.metadata_bytes <= self.budgets.max_history_metadata_bytes
            && self.targets <= self.budgets.max_inventory_item_count
            && self
                .pending_bytes()
                .is_some_and(|bytes| bytes <= self.budgets.max_history_pending_bytes)
    }

    fn pending_bytes(&self) -> Option<u64> {
        let section = |length| {
            super::super::repository::metadata_section_buffer_bytes(length, self.read_chunk_bytes)
                .ok()
        };
        let current = self.current_replay_bytes.checked_add(
            section(self.catalog_max_run_bytes)?
                .max(self.current_max_section_bytes.min(self.read_chunk_bytes)),
        )?;
        Some(current.max(section(self.history_max_section_bytes)?))
    }

    fn fits_publication(&self, kind: V3CommitKind) -> bool {
        if kind == V3CommitKind::Root {
            return self.fits();
        }
        self.fits()
            && self
                .metadata_bytes
                .checked_add(EXPIRY_ROOT_METADATA_RESERVE)
                .is_some_and(|bytes| bytes <= self.budgets.max_history_metadata_bytes)
            && self.targets < self.budgets.max_inventory_item_count
    }

    fn charge(&mut self, bytes: u64, targets: u64) -> Option<()> {
        self.metadata_bytes = self.metadata_bytes.checked_add(bytes)?;
        self.targets = self.targets.checked_add(targets)?;
        self.fits().then_some(())
    }

    fn commit(
        &mut self,
        object: &BackendObjectId,
        version: Option<&BackendVersionId>,
        header_len: u64,
        runs: u64,
    ) -> Option<()> {
        let bytes = recovery::target_fact_bytes(&(object.clone(), version.cloned()))
            .checked_add(recovery::commit_header_fact_bytes(header_len))?
            .checked_add(recovery::run_fact_bytes(header_len).checked_mul(runs)?)?;
        self.charge(bytes, 1)
    }

    fn successor(
        mut self,
        uploaded: &V3StoredCommit,
        header: &V3ParsedCommitHeader,
        entries: &[&NamespaceEntry],
        new_runs: &[V3IndexRootRunRef],
    ) -> Option<Self> {
        let mut replay_bytes = 0_u64;
        let mut max_section = 0_u64;
        for section in &header.header.section_index {
            if matches!(
                section.section_type,
                V3SectionType::IndexRun | V3SectionType::IndexRoot | V3SectionType::Recovery
            ) {
                replay_bytes = replay_bytes.checked_add(section.length)?;
                max_section = max_section.max(section.length);
                self.history_max_section_bytes = self.history_max_section_bytes.max(section.length);
            }
            if section.section_type == V3SectionType::IndexRun {
                self.catalog_max_run_bytes = self.catalog_max_run_bytes.max(section.length);
            }
        }
        self.current_max_section_bytes = if header.header.kind == V3CommitKind::Root {
            max_section
        } else {
            self.current_max_section_bytes.max(max_section)
        };
        self.current_replay_bytes = if header.header.kind == V3CommitKind::Root {
            replay_bytes
        } else {
            self.current_replay_bytes.checked_add(replay_bytes)?
        };
        let runs = header
            .header
            .section_index
            .iter()
            .filter(|section| section.section_type == V3SectionType::IndexRun)
            .count();
        self.commit(
            &uploaded.anchor_state.commit_key,
            uploaded.version_id.as_ref(),
            usize_to_u64(header.header_len),
            usize_to_u64(runs),
        )?;
        for run in new_runs {
            self.catalog_max_run_bytes = self.catalog_max_run_bytes.max(run.location.section_len);
            self.history_max_section_bytes =
                self.history_max_section_bytes.max(run.location.section_len);
            // The complete header span bounds its CBOR header length. Duplicate
            // carrier references may overcount; only a full walk releases credit.
            self.commit(
                &run.location.commit_key,
                run.location.version_id.as_ref(),
                run.location.sections_start,
                1,
            )?;
        }
        for entry in entries {
            match &entry.payload_ref {
                Some(PayloadReference::V3Pack { carrier, .. }) => {
                    self.charge(packed_usage::pack_fact_bytes(carrier), 0)?;
                    if carrier.commit_key != uploaded.anchor_state.commit_key
                        || carrier.commit_version_id != uploaded.version_id
                    {
                        // Copies normally reuse a counted carrier. Conservatively
                        // reserve even that duplicate instead of caching identities.
                        self.commit(
                            &carrier.commit_key,
                            carrier.commit_version_id.as_ref(),
                            super::super::commit::V3_MAX_HEADER_SIZE as u64,
                            1,
                        )?;
                    }
                }
                Some(PayloadReference::V3StandaloneStream { carrier }) => {
                    let key = (carrier.object_id.clone(), carrier.version_id.clone());
                    self.charge(
                        recovery::target_fact_bytes(&key)
                            .checked_add(recovery::standalone_fact_bytes())?,
                        1,
                    )?;
                }
                None if entry.content_len == 0 => {}
                _ => return None,
            }
        }
        // Compaction only introduces run carriers: all of their payload records
        // come from the already counted current closure. Ordinary upserts above
        // include every newly introduced span or detached reference.
        self.anchor = uploaded.anchor_state.clone();
        Some(self)
    }
}

impl<S: BlobStore> V3CommitStore<S> {
    pub(in crate::v3) async fn verify_recovery_capacity(
        &self,
        base: &V3AnchorState,
        uploaded: &V3StoredCommit,
        header: &V3ParsedCommitHeader,
        entries: &[&NamespaceEntry],
        new_runs: &[V3IndexRootRunRef],
    ) -> V3Result<RecoveryCapacity> {
        let budgets = self.options().recovery_maintenance_budgets;
        let cached = self
            .recovery_capacity
            .read()
            .map_err(|_| V3FormatError::StorageOperationFailed)?
            .clone();
        if let Some(cached) = cached
            && cached.anchor == *base
            && cached.budgets == budgets
            && let Some(next) = cached.successor(uploaded, header, entries, new_runs)
            && next.fits_publication(header.header.kind)
        {
            return Ok(next);
        }
        // A conservative estimate is not a refusal: expiry or compaction may
        // reduce the exact candidate graph. Inspect it under the unchanged caps.
        let budgeted = V3MaintenanceBudgetedStore::new(self.store(), budgets);
        let usage = budgeted.clone();
        let reader = self.rebind_store(budgeted);
        let result = reader
            .load_reachability_from_state(
                Some(uploaded.anchor_state.clone()),
                &[],
                budgets,
                true,
                true,
                true,
            )
            .await;
        if usage
            .usage()
            .map_err(|_| V3FormatError::StorageOperationFailed)?
            .exhausted
        {
            return Err(V3FormatError::MaintenanceBudgetExceeded);
        }
        let graph = result?;
        let mut capacity = RecoveryCapacity {
            anchor: uploaded.anchor_state.clone(),
            budgets,
            metadata_bytes: graph.history_metadata_bytes,
            targets: usize_to_u64(graph.renewal_targets.len()),
            current_replay_bytes: graph.chain_retained_bytes,
            current_max_section_bytes: graph.current_max_section_bytes,
            read_chunk_bytes: self.options().replay_limits.read_chunk_bytes,
            catalog_max_run_bytes: graph.current_catalog_max_run_bytes,
            history_max_section_bytes: graph.history_max_section_bytes,
        };
        // Current standalone facts are seeded before the historical walker.
        // Reserve their promotion charge even if some were already historical.
        let promotion = recovery::standalone_fact_bytes()
            .checked_mul(usize_to_u64(graph.standalone_facts.len()))
            .ok_or(V3FormatError::MaintenanceBudgetExceeded)?;
        capacity
            .charge(promotion, 0)
            .ok_or(V3FormatError::MaintenanceBudgetExceeded)?;
        // Restore envelope targets enter after historical accounting. Reserve
        // them too; page-only carriers have already been charged by the walker.
        for key in graph.renewal_targets.keys().filter(|key| {
            key.0 == self.options().format_ref.object_id
                || self
                    .options()
                    .maintenance_keyring_envelope_ref
                    .as_ref()
                    .is_some_and(|reference| key.0 == reference.object_id)
        }) {
            capacity
                .charge(recovery::target_fact_bytes(key), 0)
                .ok_or(V3FormatError::MaintenanceBudgetExceeded)?;
        }
        if !capacity.fits_publication(header.header.kind) {
            return Err(V3FormatError::MaintenanceBudgetExceeded);
        }
        Ok(capacity)
    }

    /// Only the common service post-CAS, post-install hook may install evidence.
    pub(in crate::v3) fn install_recovery_capacity(
        &self,
        capacity: &RecoveryCapacity,
        accepted: &V3AnchorState,
    ) {
        if let Ok(mut cached) = self.recovery_capacity.write() {
            *cached = (capacity.anchor == *accepted).then(|| capacity.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_capacity_expiry_reserve_covers_bounded_root_facts() {
        let header_bound = crate::v3::commit::V3_MAX_HEADER_SIZE;
        let key = V3CommitKey::from_parts(Sequence::new(u64::MAX), [0x43; 32])
            .expect("bounded commit key")
            .object_id;
        // A version embedded in a subsequent signed parent reference must fit
        // inside that bounded header, even before its other mandatory fields.
        let version = BackendVersionId::new("v".repeat(header_bound)).expect("version");
        let bytes = recovery::target_fact_bytes(&(key, Some(version)))
            + recovery::commit_header_fact_bytes(header_bound as u64);
        assert!(bytes < EXPIRY_ROOT_METADATA_RESERVE);
    }
}
