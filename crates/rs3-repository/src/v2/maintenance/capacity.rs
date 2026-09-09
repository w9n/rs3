//! Admission bounds for recovery graph metadata, independent of retention proof.
//!
//! A small immutable certificate covers a conservative closure of the accepted
//! graph. Candidate additions are charged without rereading that graph. At a
//! boundary (or after cache loss), the exact candidate is walked before CAS.
//! This does not certify pending-section peaks, inventory or optional I/O caps.

use super::*;
use crate::v2::commit::V2ParsedCommitHeader;
use crate::v2::repository::V2StoredCommit;

// Leave room for a metadata-only expiry root after foreground admission stops.
// A root may use the hard cap; repeated nonreducing roots can consume this margin.
const EXPIRY_ROOT_METADATA_RESERVE: u64 = 128 * 1024;

#[derive(Clone, Debug)]
pub(in crate::v2) struct RecoveryCapacity {
    anchor: V2AnchorState,
    budgets: V2MaintenanceBudgets,
    metadata_bytes: u64,
    targets: u64,
}

impl RecoveryCapacity {
    fn fits(&self) -> bool {
        self.metadata_bytes <= self.budgets.max_history_metadata_bytes
            && self.targets <= self.budgets.max_inventory_item_count
    }

    fn fits_publication(&self, kind: V2CommitKind) -> bool {
        if kind == V2CommitKind::Root {
            return self.fits();
        }
        self.metadata_bytes
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
        uploaded: &V2StoredCommit,
        header: &V2ParsedCommitHeader,
        entries: &[&NamespaceEntry],
        new_runs: &[V2IndexRootRunRef],
    ) -> Option<Self> {
        let runs = header
            .header
            .section_index
            .iter()
            .filter(|section| section.section_type == V2SectionType::IndexRun)
            .count();
        self.commit(
            &uploaded.anchor_state.commit_key,
            uploaded.version_id.as_ref(),
            usize_to_u64(header.header_len),
            usize_to_u64(runs),
        )?;
        for run in new_runs {
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
                Some(PayloadReference::V2Pack { carrier, .. }) => {
                    self.charge(packed_usage::pack_fact_bytes(carrier), 0)?;
                    if carrier.commit_key != uploaded.anchor_state.commit_key
                        || carrier.commit_version_id != uploaded.version_id
                    {
                        // Copies normally reuse a counted carrier. Conservatively
                        // reserve even that duplicate instead of caching identities.
                        self.commit(
                            &carrier.commit_key,
                            carrier.commit_version_id.as_ref(),
                            super::super::commit::V2_MAX_HEADER_SIZE as u64,
                            1,
                        )?;
                    }
                }
                Some(PayloadReference::V2StandaloneStream { carrier }) => {
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

impl<S: BlobStore> V2CommitStore<S> {
    pub(in crate::v2) async fn verify_recovery_capacity(
        &self,
        base: &V2AnchorState,
        uploaded: &V2StoredCommit,
        header: &V2ParsedCommitHeader,
        entries: &[&NamespaceEntry],
        new_runs: &[V2IndexRootRunRef],
    ) -> V2Result<RecoveryCapacity> {
        let budgets = self.options().recovery_maintenance_budgets;
        let cached = self
            .recovery_capacity
            .read()
            .map_err(|_| V2FormatError::StorageOperationFailed)?
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
        let budgeted = V2MaintenanceBudgetedStore::new(self.store(), budgets);
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
            .map_err(|_| V2FormatError::StorageOperationFailed)?
            .exhausted
        {
            return Err(V2FormatError::MaintenanceBudgetExceeded);
        }
        let graph = result?;
        let mut capacity = RecoveryCapacity {
            anchor: uploaded.anchor_state.clone(),
            budgets,
            metadata_bytes: graph.history_metadata_bytes,
            targets: usize_to_u64(graph.renewal_targets.len()),
        };
        // Current standalone facts are seeded before the historical walker.
        // Reserve their promotion charge even if some were already historical.
        let promotion = recovery::standalone_fact_bytes()
            .checked_mul(usize_to_u64(graph.standalone_facts.len()))
            .ok_or(V2FormatError::MaintenanceBudgetExceeded)?;
        capacity
            .charge(promotion, 0)
            .ok_or(V2FormatError::MaintenanceBudgetExceeded)?;
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
                .ok_or(V2FormatError::MaintenanceBudgetExceeded)?;
        }
        if !capacity.fits_publication(header.header.kind) {
            return Err(V2FormatError::MaintenanceBudgetExceeded);
        }
        Ok(capacity)
    }

    /// Only the common service post-CAS, post-install hook may install evidence.
    pub(in crate::v2) fn install_recovery_capacity(
        &self,
        capacity: &RecoveryCapacity,
        accepted: &V2AnchorState,
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
        let header_bound = crate::v2::commit::V2_MAX_HEADER_SIZE;
        let key = V2CommitKey::from_parts(Sequence::new(u64::MAX), [0x43; 32])
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
