//! Bounded, metadata-only union of referenced physical pack record spans.

use super::*;
use crate::v2::payload_pack::{
    V2PayloadPackFacts, V2PayloadPackId, V2PayloadPackRecordRef, plan_v2_payload_pack_record_range,
};
use rs3_index::V2PackCarrierReference;

type PackKey = (BackendObjectId, Option<BackendVersionId>, u32);

#[derive(Clone, Debug)]
struct PackUsage {
    carrier: Arc<V2PackCarrierReference>,
    spans: BTreeSet<(u64, u64)>,
}

#[derive(Clone, Debug, Default)]
pub(super) struct PackedUsage {
    pub(super) enabled: bool,
    packs: BTreeMap<PackKey, PackUsage>,
}

impl V2ReachabilityState {
    pub(super) fn include_packed_usage(
        &mut self,
        entry: &NamespaceEntry,
        budgets: V2MaintenanceBudgets,
    ) -> V2Result<()> {
        if !self.packed_usage.enabled {
            return Ok(());
        }
        let Some(PayloadReference::V2Pack { carrier, record }) = &entry.payload_ref else {
            return Ok(());
        };
        let key = (
            carrier.commit_key.clone(),
            carrier.commit_version_id.clone(),
            carrier.pack_section_ordinal,
        );
        let commit = self
            .verified_commits
            .get(&(key.0.clone(), key.1.clone()))
            .ok_or(V2FormatError::InvalidPayloadPack)?;
        let section = commit
            .parsed_header
            .header
            .section_index
            .get(carrier.pack_section_ordinal as usize)
            .ok_or(V2FormatError::InvalidPayloadPack)?;
        if commit.parsed_header.header.body_digest != carrier.body_digest
            || commit.object_len != carrier.commit_stored_len
            || section.section_type != V2SectionType::PayloadPack
            || usize_to_u64(commit.parsed_header.sections_start).checked_add(section.offset)
                != Some(carrier.pack_offset)
            || section.length != carrier.length
        {
            return Err(V2FormatError::InvalidPayloadPack);
        }
        let facts = V2PayloadPackFacts::new(
            V2PayloadPackId::from_bytes(carrier.pack_id),
            carrier.attempt_id,
            carrier.content_key_id.clone(),
            u32::try_from(carrier.length).map_err(|_| V2FormatError::InvalidPayloadPack)?,
            carrier.pack_record_count,
        )?;
        let span = plan_v2_payload_pack_record_range(
            &facts,
            &V2PayloadPackRecordRef::new(record.record_ordinal, record.record_offset),
            entry.content_len,
            0..entry.content_len,
        )?;
        let span = (
            span.offset,
            span.offset
                .checked_add(span.stored_len)
                .ok_or(V2FormatError::InvalidPayloadPack)?,
        );
        let new_pack = match self.packed_usage.packs.get(&key) {
            Some(usage) if usage.carrier != *carrier => {
                return Err(V2FormatError::InvalidPayloadPack);
            }
            Some(usage) if usage.spans.contains(&span) => return Ok(()),
            Some(_) => false,
            None => true,
        };
        // Charge before growing either tree. The fixed allowances include
        // B-tree node slack; dynamic carrier/key strings are charged twice.
        let bytes = if new_pack {
            512 + usize_to_u64(std::mem::size_of::<V2PackCarrierReference>())
                + 2 * usize_to_u64(
                    carrier.commit_key.as_str().len()
                        + carrier
                            .commit_version_id
                            .as_ref()
                            .map_or(0, |id| id.as_str().len())
                        + carrier.content_key_id.as_str().len()
                        + carrier.keyring_envelope_object_id.as_str().len(),
                )
        } else {
            128
        };
        recovery::charge_history_metadata(self, bytes, budgets)?;
        self.packed_usage
            .packs
            .entry(key)
            .or_insert_with(|| PackUsage {
                carrier: Arc::clone(carrier),
                spans: BTreeSet::new(),
            })
            .spans
            .insert(span);
        Ok(())
    }
}

impl PackedUsage {
    pub(super) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            packs: BTreeMap::new(),
        }
    }

    pub(super) fn totals(&self) -> V2Result<(u64, u64)> {
        let mut stored = 0_u64;
        let mut referenced = 0_u64;
        for usage in self.packs.values() {
            stored = stored
                .checked_add(usage.carrier.length)
                .ok_or(V2FormatError::MaintenanceBudgetExceeded)?;
            let mut covered_end = 0;
            for &(start, end) in &usage.spans {
                let newly_covered = end.saturating_sub(start.max(covered_end));
                referenced = referenced
                    .checked_add(newly_covered)
                    .ok_or(V2FormatError::MaintenanceBudgetExceeded)?;
                covered_end = covered_end.max(end);
            }
        }
        Ok((stored, referenced))
    }
}

#[cfg(test)]
impl<S: BlobStore> V2CommitStore<S> {
    pub(in crate::v2) async fn packed_usage_mark_for_tests<A: V2CommitAnchor>(
        &self,
        anchor: &A,
        enabled: bool,
    ) -> V2Result<(u64, u64)> {
        self.load_reachability(anchor, &[], V2MaintenanceBudgets::default(), true, enabled)
            .await?
            .packed_usage
            .totals()
    }
}
