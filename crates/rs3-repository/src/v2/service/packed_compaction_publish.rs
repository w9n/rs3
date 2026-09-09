//! Guarded publication of metadata-only packed index-run compaction.

mod selection;

use selection::cost_aware_compaction_plan;

use super::packed::{
    V2PackedIndexRunReplay, apply_packed_index_run, index_run_bounds, repository_context_from_refs,
};
use super::packed_compaction::{PackedCompactionSourceRun, plan_packed_run_compaction};
use super::{V2CoordinatedMutation, V2Repository, v2_repository_error};
use crate::error::{RepositoryError, Result};
use crate::state::RepositoryState;
use crate::v2::{
    V2_SECTION_FLAG_MUST_UNDERSTAND, V2CommitAnchor, V2CommitParentRef, V2CommitSection,
    V2CommitWrite, V2EmbeddedIndexRunLocation, V2FormatError, V2IndexRoot, V2IndexRootRunRef,
    V2MaintenanceGuard, V2MemoryAnchor, V2SectionType, V2StoredCommit, digest_v2_section,
    open_v2_index_run, probe_v2_index_run_header, seal_v2_index_root, seal_v2_index_run,
};
use rs3_index::run::{IndexRun, IndexRunContainer, IndexRunKeyringRef, IndexRunLimits};
use rs3_storage::BlobStore;
use rs3_storage::strongest_retention_policy;
use rs3_types::{LegalHoldStatus, RetentionPolicy};

const V2_PACKED_COMPACTION_MAX_SOURCE_RUNS: usize = 128;
const V2_PACKED_COMPACTION_MAX_SOURCE_MUTATIONS: u64 = 131_072;
const V2_PACKED_COMPACTION_MAX_SOURCE_BYTES: u64 = 16 * 1024 * 1024;

/// Choose a contiguous window using authenticated catalog facts only. Prefer
/// more source runs, then fewer mutations and bytes, then the oldest window.
/// Full live older shards must not starve reducible newer churn. Two maximum
/// runs fit the byte/mutation ceilings, so even full obsolete shards can merge.
fn compaction_window(sizes: &[(u32, u64)]) -> crate::v2::V2Result<std::ops::Range<usize>> {
    // The production caller already validated the accepted root. Keep this
    // planning boundary fail-closed too, before selecting or skipping any run.
    if sizes.iter().any(|&(mutations, bytes)| {
        mutations == 0
            || u64::from(mutations) > V2_PACKED_COMPACTION_MAX_SOURCE_MUTATIONS / 2
            || bytes == 0
            || bytes > V2_PACKED_COMPACTION_MAX_SOURCE_BYTES / 2
    }) {
        return Err(V2FormatError::InvalidIndexRoot);
    }
    let mut best = 0..0;
    let mut best_cost = (u64::MAX, u64::MAX);
    for start in 0..sizes.len() {
        let mut mutations = 0_u64;
        let mut bytes = 0_u64;
        for (offset, &(run_mutations, run_bytes)) in sizes[start..]
            .iter()
            .take(V2_PACKED_COMPACTION_MAX_SOURCE_RUNS)
            .enumerate()
        {
            mutations = mutations
                .checked_add(u64::from(run_mutations))
                .ok_or(V2FormatError::IndexRootLimitExceeded)?;
            bytes = bytes
                .checked_add(run_bytes)
                .ok_or(V2FormatError::IndexRootLimitExceeded)?;
            if mutations > V2_PACKED_COMPACTION_MAX_SOURCE_MUTATIONS
                || bytes > V2_PACKED_COMPACTION_MAX_SOURCE_BYTES
            {
                break;
            }
            let candidate = start..start + offset + 1;
            if candidate.len() > best.len()
                || (candidate.len() == best.len() && (mutations, bytes) < best_cost)
            {
                best = candidate;
                best_cost = (mutations, bytes);
            }
        }
    }
    Ok(best)
}

impl<S> V2Repository<S>
where
    S: BlobStore + Clone,
{
    /// Replaces a bounded contiguous window of active runs with fewer metadata-only runs.
    ///
    /// Candidate run commits and the candidate root are direct siblings of the
    /// accepted base. Exact read-back authenticates every new run and the root
    /// before one compare-and-swap advances the real anchor to the root.
    pub async fn compact_packed_index_runs<A, G>(
        &self,
        anchor: &A,
        guard: &G,
    ) -> Result<V2StoredCommit>
    where
        A: V2CommitAnchor,
        G: V2MaintenanceGuard + ?Sized,
    {
        let _mutation_lease = self.claim_direct_mutation()?;
        self.compact_packed_index_runs_inner(anchor, guard).await
    }

    pub(in crate::v2) async fn compact_packed_index_runs_coordinated<A, G>(
        &self,
        mutation: V2CoordinatedMutation<'_, A>,
        guard: &G,
    ) -> Result<V2StoredCommit>
    where
        A: V2CommitAnchor,
        G: V2MaintenanceGuard + ?Sized,
    {
        self.validate_coordinator_lease(mutation.lease)?;
        self.compact_packed_index_runs_inner(mutation.anchor, guard)
            .await
    }

    async fn compact_packed_index_runs_inner<A, G>(
        &self,
        anchor: &A,
        guard: &G,
    ) -> Result<V2StoredCommit>
    where
        A: V2CommitAnchor,
        G: V2MaintenanceGuard + ?Sized,
    {
        let _mutation_guard = self.mutation_lock.lock().await;
        let _publication_guard = self.publication_lock.write().await;
        if self.pending_index_delta_sequence()?.is_some() {
            return Err(RepositoryError::CommitFailed {
                reason: "packed index compaction requires no pending mutations".to_owned(),
            });
        }

        guard
            .verify_v2_maintenance(None)
            .await
            .map_err(v2_repository_error)?;
        let base_anchor = self.ensure_accepted_anchor_matches(anchor).await?;
        guard
            .verify_v2_maintenance(Some(&base_anchor))
            .await
            .map_err(v2_repository_error)?;

        let (covered_generation, expected_live_object_count, protection) = {
            let accepted = self
                .accepted
                .read()
                .map_err(|_| RepositoryError::StatePoisoned)?;
            let state = &accepted.repository;
            (
                state.next_sequence,
                u64::try_from(state.list_entries.len())
                    .map_err(|_| v2_repository_error(V2FormatError::IndexRootLimitExceeded))?,
                represented_state_protection(state),
            )
        };
        let accepted_refs = self
            .accepted
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?
            .runs
            .clone();
        let mut ordered_refs = accepted_refs.clone();
        ordered_refs.sort_by_key(|run| (run.minimum_generation, run.run_sequence, run.run_id));
        let sizes = ordered_refs
            .iter()
            .map(|run| (run.mutation_count, run.location.section_len))
            .collect::<Vec<_>>();
        let window = compaction_window(&sizes).map_err(v2_repository_error)?;
        let source_refs = &ordered_refs[window.clone()];
        if source_refs.len() < 2 {
            return Err(v2_repository_error(
                V2FormatError::MaintenanceBudgetExceeded,
            ));
        }

        let keyring = self.repository.keyring();
        let (selected, output_runs) = cost_aware_compaction_plan(
            &sizes[window.clone()],
            |range| self.load_compaction_sources(keyring.as_ref(), &source_refs[range]),
            |sources| {
                let accepted = self
                    .accepted
                    .read()
                    .map_err(|_| RepositoryError::StatePoisoned)?;
                Ok(plan_packed_run_compaction(
                    sources,
                    &IndexRunLimits::default(),
                    Some(&accepted.repository.namespace),
                ))
            },
        )
        .await?;
        drop(ordered_refs.drain(window.start + selected.start..window.start + selected.end));
        let retained_refs = ordered_refs;
        // Level is a storage tier, not a compaction epoch. Both foreground and
        // older compacted runs share this bounded contiguous generation window;
        // every output stays level one. Other exact run references are unchanged.
        let output_level = 1;
        let compaction_generation = base_anchor
            .sequence
            .checked_next()
            .ok_or_else(|| v2_repository_error(V2FormatError::InvalidIndexRoot))?;
        let context = repository_context_from_refs(
            &self.commit_store.options().repository_id,
            &self.commit_store.options().keyring_envelope_ref,
        )?;
        let expected_parent = V2CommitParentRef {
            sequence: base_anchor.sequence,
            commit_key: base_anchor.commit_key.clone(),
            body_digest: base_anchor.body_digest,
            version_id: base_anchor.version_id.clone(),
        };

        let mut compacted_refs = Vec::with_capacity(output_runs.len());
        for run in output_runs {
            let temporary_anchor = V2MemoryAnchor::with_state(base_anchor.clone());
            let sibling_plan = self
                .commit_store
                .prepare_child_publication(&base_anchor)
                .await
                .map_err(v2_repository_error)?;
            let mut sealed_facts = None;
            let uploaded = self
                .commit_store
                .write_prepared_child_commit_with(&temporary_anchor, &sibling_plan, |commit_key| {
                    let sealed = seal_v2_index_run(
                        keyring.as_ref(),
                        &context,
                        &commit_key.object_id,
                        0,
                        &run,
                        &IndexRunLimits::default(),
                    )?;
                    let probe = probe_v2_index_run_header(sealed.bytes())?;
                    let bounds = index_run_bounds(&run.mutations)
                        .map_err(|_| V2FormatError::InvalidIndexRun)?;
                    sealed_facts = Some((
                        *sealed.run_id().as_bytes(),
                        probe.frame_count(),
                        bounds,
                        u64::try_from(sealed.bytes().len())
                            .map_err(|_| V2FormatError::IndexRunLimitExceeded)?,
                        digest_v2_section(sealed.bytes()),
                    ));
                    let mut write = V2CommitWrite::delta(vec![V2CommitSection::new(
                        V2SectionType::IndexRun,
                        V2_SECTION_FLAG_MUST_UNDERSTAND,
                        sealed.into_bytes(),
                    )])
                    .with_retention(protection.0);
                    write = write.with_legal_hold(protection.1);
                    Ok(write)
                })
                .await
                .map_err(v2_repository_error)?;
            let (run_id, frame_count, bounds, section_len, section_digest) =
                sealed_facts.ok_or_else(|| v2_repository_error(V2FormatError::InvalidIndexRun))?;
            let replay = self
                .commit_store
                .read_replay_commit_at(
                    &uploaded.anchor_state.commit_key,
                    uploaded.version_id.as_ref(),
                )
                .await
                .map_err(v2_repository_error)?;
            let [descriptor] = replay.parsed_header.header.section_index.as_slice() else {
                return Err(v2_repository_error(V2FormatError::InvalidIndexRun));
            };
            let stored_run = replay
                .retained_sections
                .first()
                .and_then(Option::as_deref)
                .ok_or_else(|| v2_repository_error(V2FormatError::InvalidIndexRun))?;
            if replay.version_id != uploaded.version_id
                || replay.object_len != uploaded.object_len
                || replay.parsed_header.header.self_ref.sequence != compaction_generation
                || replay.parsed_header.header.parent.as_ref() != Some(&expected_parent)
                || descriptor.section_type != V2SectionType::IndexRun
                || descriptor.flags != V2_SECTION_FLAG_MUST_UNDERSTAND
                || descriptor.offset != 0
                || descriptor.length != section_len
                || descriptor.digest != section_digest
            {
                return Err(v2_repository_error(V2FormatError::InvalidIndexRun));
            }
            let verified_run = open_v2_index_run(
                keyring.as_ref(),
                &context,
                &uploaded.anchor_state.commit_key,
                0,
                stored_run,
                &IndexRunLimits::default(),
            )
            .map_err(v2_repository_error)?;
            if verified_run != run {
                return Err(v2_repository_error(V2FormatError::InvalidIndexRun));
            }
            compacted_refs.push(V2IndexRootRunRef {
                run_id,
                run_sequence: run.sequence,
                minimum_generation: bounds.minimum_generation,
                maximum_generation: bounds.maximum_generation,
                mutation_count: u32::try_from(run.mutations.len())
                    .map_err(|_| v2_repository_error(V2FormatError::IndexRunLimitExceeded))?,
                frame_count,
                level: output_level,
                compaction_generation: compaction_generation.get(),
                namespace_bounds: bounds.namespace,
                listing_bounds: bounds.listing,
                keyring_envelope_ref: self.commit_store.options().keyring_envelope_ref.clone(),
                location: V2EmbeddedIndexRunLocation {
                    commit_key: uploaded.anchor_state.commit_key.clone(),
                    version_id: uploaded.version_id.clone(),
                    commit_stored_len: uploaded.object_len,
                    commit_body_digest: uploaded.anchor_state.body_digest,
                    sections_start: uploaded.sections_start,
                    section_ordinal: 0,
                    section_offset: 0,
                    section_len,
                    section_digest,
                },
            });
        }

        let introduced_runs = compacted_refs.clone();
        let mut candidate_refs = retained_refs;
        candidate_refs.extend(compacted_refs);
        let root = V2IndexRoot::new(
            covered_generation,
            expected_live_object_count,
            self.commit_store.options().format_ref.clone(),
            self.commit_store.options().keyring_envelope_ref.clone(),
            candidate_refs.clone(),
        )
        .map_err(v2_repository_error)?
        .with_completion_receipts(
            self.accepted
                .read()
                .map_err(|_| RepositoryError::StatePoisoned)?
                .repository
                .completion_receipts
                .clone(),
        );
        let mut prepared = self
            .prepare_service_publication(anchor, &base_anchor, true, Some(guard))
            .await?;
        let root_anchor = V2MemoryAnchor::with_state(base_anchor.clone());
        let uploaded_root = self
            .commit_store
            .write_prepared_child_commit_with(&root_anchor, &prepared.plan, |commit_key| {
                let sealed = seal_v2_index_root(
                    keyring.as_ref(),
                    &context,
                    &commit_key.object_id,
                    0,
                    &root,
                )?;
                let mut write = V2CommitWrite::snapshot(vec![V2CommitSection::new(
                    V2SectionType::IndexRoot,
                    V2_SECTION_FLAG_MUST_UNDERSTAND,
                    sealed.into_bytes(),
                )])
                .with_retention(protection.0);
                write = write.with_legal_hold(protection.1);
                self.append_recovery_section(write, commit_key, &prepared)
            })
            .await
            .map_err(v2_repository_error)?;

        let candidate_anchor = root_anchor
            .read_v2()
            .await
            .map_err(v2_repository_error)?
            .ok_or_else(|| v2_repository_error(V2FormatError::MissingAnchor))?;
        let candidate_chain = self
            .commit_store
            .load_replay_chain_from_state(&candidate_anchor)
            .await
            .map_err(v2_repository_error)?;
        self.verify_exact_index_root(&candidate_chain, &root)?;
        let recovery = self
            .verify_recovery_publication(
                anchor,
                Some(guard),
                &mut prepared,
                &uploaded_root,
                &[],
                &introduced_runs,
            )
            .await?;
        if root_anchor.read_v2().await.map_err(v2_repository_error)? != Some(candidate_anchor) {
            return Err(v2_repository_error(V2FormatError::StaleAnchor));
        }
        candidate_refs.sort_by_key(|run| (run.minimum_generation, run.run_sequence, run.run_id));
        {
            let accepted = self
                .accepted
                .read()
                .map_err(|_| RepositoryError::StatePoisoned)?;
            if accepted.repository.next_sequence != covered_generation
                || accepted.runs != accepted_refs
            {
                return Err(v2_repository_error(V2FormatError::StaleAnchor));
            }
        }
        guard
            .verify_v2_maintenance(Some(&base_anchor))
            .await
            .map_err(v2_repository_error)?;
        if anchor.read_v2().await.map_err(v2_repository_error)? != Some(base_anchor.clone()) {
            return Err(v2_repository_error(V2FormatError::StaleAnchor));
        }
        self.validate_recovery_publication_freshness(&prepared)?;
        let adopted = self
            .commit_store
            .adopt_verified_unanchored_child(
                anchor,
                &base_anchor,
                &uploaded_root,
                prepared.history_uncertainty_ms(),
            )
            .await
            .map_err(v2_repository_error)?;
        match self.accepted.write() {
            Ok(mut accepted) => {
                accepted.recovery = recovery;
                accepted.runs = candidate_refs;
                accepted.anchor = Some(adopted.anchor_state.clone());
            }
            Err(error) => {
                self.mark_local_recovery_required();
                tracing::error!(
                    target: "rs3_repository",
                    operation = "v2_install_packed_compaction",
                    error = %error,
                    "v2 compaction anchor advanced but local state installation failed; restart is required",
                );
                return Err(RepositoryError::AcceptedRecoveryRequired);
            }
        }
        self.advance_service_recovery_coverage(&prepared, &adopted.anchor_state);
        Ok(adopted)
    }

    async fn load_compaction_sources(
        &self,
        keyring: &rs3_crypto::KeyRing,
        source_refs: &[V2IndexRootRunRef],
    ) -> Result<Vec<PackedCompactionSourceRun>> {
        let mut ordered = source_refs.to_vec();
        ordered.sort_by_key(|run| (run.minimum_generation, run.run_sequence, run.run_id));
        let mut sources = Vec::with_capacity(ordered.len());
        for expected in ordered {
            let mut scratch = RepositoryState::default();
            let location = &expected.location;
            let replay = self
                .commit_store
                .read_commit_facts_at(&location.commit_key, location.version_id.as_ref())
                .await
                .map_err(v2_repository_error)?;
            let descriptor_index = usize::try_from(location.section_ordinal)
                .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?;
            let descriptor = replay
                .parsed_header
                .header
                .section_index
                .get(descriptor_index)
                .ok_or_else(|| v2_repository_error(V2FormatError::InvalidIndexRoot))?;
            if replay.version_id != location.version_id
                || replay.object_len != location.commit_stored_len
                || u64::try_from(replay.parsed_header.sections_start).ok()
                    != Some(location.sections_start)
                || replay.parsed_header.header.body_digest != location.commit_body_digest
                || replay.parsed_header.header.keyring_envelope_ref != expected.keyring_envelope_ref
                || descriptor.section_type != V2SectionType::IndexRun
                || descriptor.flags != V2_SECTION_FLAG_MUST_UNDERSTAND
                || descriptor.offset != location.section_offset
                || descriptor.length != location.section_len
                || descriptor.digest != location.section_digest
            {
                return Err(v2_repository_error(V2FormatError::InvalidIndexRoot));
            }
            let pending_limit = self
                .commit_store
                .options()
                .replay_limits
                .max_retained_bytes
                .min(
                    self.commit_store
                        .options()
                        .recovery_maintenance_budgets
                        .max_history_pending_bytes,
                );
            let stored_run = self
                .commit_store
                .read_metadata_section(&replay, location.section_ordinal, pending_limit)
                .await
                .map_err(v2_repository_error)?;
            let actual = apply_packed_index_run(
                keyring,
                &self.commit_store.options().repository_id,
                &mut scratch,
                V2PackedIndexRunReplay {
                    parsed_header: &replay.parsed_header,
                    version_id: replay.version_id.as_ref(),
                    object_len: replay.object_len,
                    section_ordinal: location.section_ordinal,
                    stored_run: &stored_run,
                    level: expected.level,
                    compaction_generation: expected.compaction_generation,
                    provider_profile: self.commit_store.provider_profile(),
                },
            )?;
            if actual != expected {
                return Err(v2_repository_error(V2FormatError::InvalidIndexRoot));
            }
            let context = repository_context_from_refs(
                &self.commit_store.options().repository_id,
                &replay.parsed_header.header.keyring_envelope_ref,
            )?;
            let run = open_v2_index_run(
                keyring,
                &context,
                &replay.parsed_header.header.self_ref.commit_key,
                location.section_ordinal,
                &stored_run,
                &IndexRunLimits::default(),
            )
            .map_err(v2_repository_error)?;
            let self_pack_container = source_self_pack_container(&run, &replay)?;
            sources.push(PackedCompactionSourceRun {
                run,
                self_pack_container,
            });
        }
        Ok(sources)
    }
}

fn source_self_pack_container(
    run: &IndexRun,
    replay: &crate::v2::repository::V2ReplayCommit,
) -> Result<Option<IndexRunContainer>> {
    let Some(pack) = run.self_pack.as_ref() else {
        return Ok(None);
    };
    let mut matches = replay
        .parsed_header
        .header
        .section_index
        .iter()
        .enumerate()
        .filter(|(_, section)| section.section_type == V2SectionType::PayloadPack);
    let Some((ordinal, section)) = matches.next() else {
        return Err(v2_repository_error(V2FormatError::InvalidIndexRun));
    };
    if matches.next().is_some()
        || section.length != pack.stored_len
        || section.flags != V2_SECTION_FLAG_MUST_UNDERSTAND
    {
        return Err(v2_repository_error(V2FormatError::InvalidIndexRun));
    }
    let sections_start = u64::try_from(replay.parsed_header.sections_start)
        .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?;
    Ok(Some(IndexRunContainer {
        object_id: replay.parsed_header.header.self_ref.commit_key.clone(),
        version_id: replay.version_id.clone(),
        stored_len: replay.object_len,
        commit_body_digest: replay.parsed_header.header.body_digest,
        keyring_envelope: IndexRunKeyringRef {
            object_id: replay
                .parsed_header
                .header
                .keyring_envelope_ref
                .object_id
                .clone(),
            digest: replay.parsed_header.header.keyring_envelope_ref.digest,
        },
        pack_section_offset: sections_start
            .checked_add(section.offset)
            .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))?,
        pack_section_ordinal: u32::try_from(ordinal)
            .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?,
        pack_section_len: section.length,
        pack_id: pack.pack_id,
        attempt_id: pack.attempt_id,
        content_key_id: pack.content_key_id.clone(),
        pack_record_count: pack.record_count,
    }))
}

fn represented_state_protection(
    state: &RepositoryState,
) -> (Option<RetentionPolicy>, Option<LegalHoldStatus>) {
    state
        .namespace
        .live_entries()
        .fold((None, None), |(retention, legal_hold), entry| {
            (
                strongest_retention_policy(retention, entry.retention),
                if entry.legal_hold == Some(LegalHoldStatus::On) {
                    Some(LegalHoldStatus::On)
                } else {
                    legal_hold
                },
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_live_older_shards_do_not_starve_newer_churn() {
        let full = (65_536, 8 * 1024 * 1024);
        let small = (1, 1024);
        assert_eq!(
            compaction_window(&[full, full, small, small, small]),
            Ok(1..5)
        );
        // One full shard plus the small tail still reduces; the full prefix
        // pair cannot prevent that larger, bounded window from being selected.
        assert_eq!(compaction_window(&[full, full, small, small]), Ok(1..4));
        assert_eq!(compaction_window(&[full, full, small]), Ok(1..3));
        assert_eq!(compaction_window(&[full, full]), Ok(0..2));
    }

    #[test]
    fn invalid_catalog_costs_fail_before_any_window_is_selected() {
        assert_eq!(
            compaction_window(&[(1, u64::MAX), (1, 1024), (1, 1024)]),
            Err(V2FormatError::InvalidIndexRoot)
        );
        assert_eq!(
            compaction_window(&[(u32::MAX, 1024)]),
            Err(V2FormatError::InvalidIndexRoot)
        );
    }

    #[test]
    fn selection_respects_all_budgets_and_never_skips_an_interior_run() {
        let small = (1, 1024);
        assert_eq!(compaction_window(&vec![small; 256]), Ok(0..128));
        assert_eq!(compaction_window(&[(65_536, 1024); 3]), Ok(0..2));
        assert_eq!(compaction_window(&[(1, 8 * 1024 * 1024); 3]), Ok(0..2));
        assert_eq!(
            compaction_window(&[small, (65_536, 8 * 1024 * 1024), small]),
            Ok(0..3)
        );
    }
}
