//! Marks only the registry authenticated by the current accepted chain. Old
//! Recovery sections are data carriers, never another source of history roots.

use super::*;
use crate::v2::recovery::history::{RecoveryPageLocation, RecoveryPageRef, RecoveryPoint};

type ExactVersion = (BackendObjectId, Option<BackendVersionId>);
type RunLocation = (BackendObjectId, Option<BackendVersionId>, u32);

enum HistoryBlock<'a> {
    Tail(&'a [RecoveryPoint]),
    Page(&'a RecoveryPageRef),
}

struct HistoryRun<'a> {
    commit: &'a V2ReplayCommit,
    ordinal: u32,
    expected: Option<&'a V2IndexRootRunRef>,
    deadline: i64,
}

#[derive(Default)]
struct HistoryWalk {
    // Points are visited by descending deadline, so a previously visited edge
    // already has at least the deadline required by every subsequent visitor.
    chains: BTreeSet<ExactVersion>,
    runs: BTreeMap<RunLocation, V2IndexRootRunRef>,
    represented_retention: Option<RetentionPolicy>,
}

impl<S: BlobStore> V2CommitStore<S> {
    pub(super) async fn include_recovery_history(
        &self,
        reachability: &mut V2ReachabilityState,
        budgets: V2MaintenanceBudgets,
    ) -> V2Result<()> {
        let Some(chain) = reachability.current_chain.as_ref() else {
            return Ok(());
        };
        let accepted = self.replay_recovery_history(chain)?;
        let Some(accepted) = accepted else {
            return if self.options().recovery_policy.is_some() {
                Err(V2FormatError::InvalidRecoveryHistory)
            } else {
                Ok(())
            };
        };
        reachability.recovery_recoverable_point_count = 1;
        reachability.recovery_oldest_recoverable_publish_time_ms = Some(
            chain
                .commits_newest_first
                .first()
                .ok_or(V2FormatError::InvalidRecoveryHistory)?
                .parsed_header
                .header
                .publish_time_ms,
        );
        reachability.recovery_clock_uncertainty_ms = Some(accepted.policy.clock_uncertainty_ms());
        let current_floor = (self.provider_profile()
            == V2ProviderProfile::RetainedVersionObjectLock)
            .then(|| {
                accepted
                    .policy
                    .coverage_until_ms(self.publication_now_ms())
                    .and_then(super::super::recovery::policy::ceil_physical_deadline_ms)
            })
            .transpose()?;
        reachability.current_recovery_floor_ms = current_floor;
        let snapshot = &accepted.snapshot;
        snapshot.validate_normalized()?;
        let cutoff = snapshot.expire_before_ms;
        reachability.recovery_expire_before_ms = Some(cutoff);
        reachability.history_metadata_bytes = reachability
            .renewal_targets
            .keys()
            .try_fold(0_u64, |total, key| {
                total.checked_add(target_fact_bytes(key))
            })
            .ok_or(V2FormatError::MaintenanceBudgetExceeded)?;
        for commit in reachability.verified_commits.values() {
            reachability.history_metadata_bytes = reachability
                .history_metadata_bytes
                .checked_add(commit_fact_bytes(commit))
                .ok_or(V2FormatError::MaintenanceBudgetExceeded)?;
            reachability.history_pending_bytes = reachability
                .history_pending_bytes
                .checked_add(retained_bytes(commit))
                .ok_or(V2FormatError::MaintenanceBudgetExceeded)?;
        }
        self.check_history_graph_bounds(reachability, budgets)?;
        let mut next_expiry = snapshot
            .tail
            .iter()
            .filter(|point| point.protected_until_ms > cutoff)
            .map(|point| point.protected_until_ms)
            .min();
        // At most 1025 small block references and one decoded page are live.
        // A block's maximum deadline conservatively protects its <=4096 points.
        // Descending block order means every dependency is visited strongest first.
        let mut blocks = Vec::with_capacity(snapshot.pages.len() + 1);
        if let Some(deadline) = snapshot
            .tail
            .iter()
            .filter(|point| point.protected_until_ms > cutoff)
            .map(|point| point.protected_until_ms)
            .max()
        {
            blocks.push((deadline, HistoryBlock::Tail(&snapshot.tail)));
        }
        for reference in &snapshot.pages {
            if reference.claims.maximum_deadline_ms <= cutoff {
                return Err(V2FormatError::InvalidRecoveryHistory);
            }
            let known_expiry = if reference.claims.minimum_deadline_ms > cutoff {
                reference.claims.minimum_deadline_ms
            } else {
                reference.claims.maximum_deadline_ms
            };
            next_expiry =
                Some(next_expiry.map_or(known_expiry, |previous| previous.min(known_expiry)));
            blocks.push((
                reference.claims.maximum_deadline_ms,
                HistoryBlock::Page(reference),
            ));
        }
        reachability.recovery_next_expiry_ms = next_expiry;
        reachability.recovery_expiry_due_ms = next_expiry
            .map(|deadline| {
                deadline
                    .checked_add(i64::from(accepted.policy.clock_uncertainty_ms()))
                    .ok_or(V2FormatError::InvalidRecoveryHistory)
            })
            .transpose()?;
        blocks.sort_unstable_by(|left, right| right.0.cmp(&left.0));
        let mut walk = HistoryWalk::default();
        for (deadline, block) in blocks {
            match block {
                HistoryBlock::Tail(points) => {
                    for point in points
                        .iter()
                        .filter(|point| point.protected_until_ms > cutoff)
                    {
                        include_recovery_point_facts(reachability, point)?;
                        let mut demand = point.clone();
                        demand.protected_until_ms = deadline;
                        self.walk_recovery_point(reachability, &mut walk, demand, budgets)
                            .await?;
                    }
                }
                HistoryBlock::Page(reference) => {
                    let RecoveryPageLocation::Exact { anchor, .. } = &reference.location else {
                        return Err(V2FormatError::InvalidRecoveryHistory);
                    };
                    if anchor.format_ref != self.options().format_ref {
                        return Err(V2FormatError::InvalidFormatRoot);
                    }
                    let page = self.read_recovery_page(reference).await?;
                    self.include_history_page_carrier(reachability, anchor, deadline, budgets)
                        .await?;
                    for point in page
                        .points
                        .into_iter()
                        .filter(|point| point.protected_until_ms > cutoff)
                    {
                        include_recovery_point_facts(reachability, &point)?;
                        let mut demand = point;
                        demand.protected_until_ms = deadline;
                        self.walk_recovery_point(reachability, &mut walk, demand, budgets)
                            .await?;
                    }
                }
            }
        }
        reachability.recovery_historical_exact_bytes = reachability
            .renewal_targets
            .values()
            .filter(|target| target.required_deadline.is_some())
            .try_fold(0_u64, |total, target| total.checked_add(target.stored_len))
            .ok_or(V2FormatError::MaintenanceBudgetExceeded)?;
        // A conservative union can retain overwritten upserts too. Apply the
        // strongest represented mode to its metadata dependencies as well as
        // payloads, while keeping each version's immutable absolute floor.
        for key in &reachability.protected_versions {
            if let Some(target) = reachability.renewal_targets.get_mut(key) {
                target.required_retention =
                    strongest_retention(target.required_retention, walk.represented_retention);
            }
        }
        // The implicit current point never expires. Renew its actual namespace
        // dependencies ahead of supersession, without moving old point promises.
        if let Some(current_floor) = current_floor {
            for target in reachability
                .renewal_targets
                .values_mut()
                .filter(|target| target.current_recovery_dependency)
            {
                target.required_deadline = target.required_deadline.max(Some(current_floor));
            }
        }
        Ok(())
    }

    fn check_history_graph_bounds(
        &self,
        state: &V2ReachabilityState,
        budgets: V2MaintenanceBudgets,
    ) -> V2Result<()> {
        if state.history_metadata_bytes > budgets.max_history_metadata_bytes
            || state.history_pending_bytes > budgets.max_history_pending_bytes
            || usize_to_u64(state.renewal_targets.len()) > budgets.max_inventory_item_count
        {
            return Err(V2FormatError::MaintenanceBudgetExceeded);
        }
        Ok(())
    }

    async fn history_commit(
        &self,
        state: &mut V2ReachabilityState,
        key: &BackendObjectId,
        version: Option<&BackendVersionId>,
        budgets: V2MaintenanceBudgets,
    ) -> V2Result<Arc<V2ReplayCommit>> {
        let exact = (key.clone(), version.cloned());
        if let Some(commit) = state.verified_commits.get(&exact) {
            return Ok(Arc::clone(commit));
        }
        self.check_history_graph_bounds(state, budgets)?;
        if usize_to_u64(state.renewal_targets.len()) >= budgets.max_inventory_item_count {
            return Err(V2FormatError::MaintenanceBudgetExceeded);
        }
        // The decoder independently bounds the one active commit. Cache limits
        // are checked before insertion; completed nodes retain only signed facts.
        let commit = self.read_replay_commit_at(key, version).await?;
        let metadata_bytes = commit_fact_bytes(&commit)
            .checked_add(if state.renewal_targets.contains_key(&exact) {
                0
            } else {
                target_fact_bytes(&exact)
            })
            .ok_or(V2FormatError::MaintenanceBudgetExceeded)?;
        charge_history_metadata(state, metadata_bytes, budgets)?;
        state.history_pending_bytes = state
            .history_pending_bytes
            .checked_add(retained_bytes(&commit))
            .filter(|bytes| *bytes <= budgets.max_history_pending_bytes)
            .ok_or(V2FormatError::MaintenanceBudgetExceeded)?;
        state.include_chain(
            &V2ReplayChain {
                commits_newest_first: vec![commit],
            },
            true,
            None,
            None,
        )?;
        state
            .verified_commits
            .get(&exact)
            .cloned()
            .ok_or(V2FormatError::InvalidRecoveryHistory)
    }

    async fn include_history_page_carrier(
        &self,
        state: &mut V2ReachabilityState,
        anchor: &V2AnchorState,
        deadline: i64,
        budgets: V2MaintenanceBudgets,
    ) -> V2Result<()> {
        let key = (anchor.commit_key.clone(), anchor.version_id.clone());
        if let Some(target) = state.renewal_targets.get_mut(&key) {
            target.required_deadline = target.required_deadline.max(Some(deadline));
        } else {
            if usize_to_u64(state.renewal_targets.len()) >= budgets.max_inventory_item_count {
                return Err(V2FormatError::MaintenanceBudgetExceeded);
            }
            charge_history_metadata(state, target_fact_bytes(&key), budgets)?;
            let exact = self
                .store()
                .head_at(&anchor.commit_key, anchor.version_id.as_ref())
                .await
                .map_err(|_| V2FormatError::StorageOperationFailed)?;
            state.graph_head_count = state.graph_head_count.saturating_add(1);
            if exact.object_id != anchor.commit_key
                || exact.version_id != anchor.version_id
                || exact.content_len == 0
            {
                return Err(V2FormatError::ProviderProfileFailed);
            }
            state.include_renewal_target(
                anchor.commit_key.clone(),
                anchor.version_id.clone(),
                exact.content_len,
                self.retention_policy(),
                None,
                Some(deadline),
            )?;
        }
        state.reachable.insert(anchor.commit_key.clone());
        state.reachable_versions.insert(key.clone());
        state.reachable_commit_versions.insert(key.clone());
        state.protected_versions.insert(key);
        Ok(())
    }

    async fn walk_recovery_point(
        &self,
        state: &mut V2ReachabilityState,
        walk: &mut HistoryWalk,
        point: RecoveryPoint,
        budgets: V2MaintenanceBudgets,
    ) -> V2Result<()> {
        if point.anchor.format_ref != self.options().format_ref {
            return Err(V2FormatError::InvalidFormatRoot);
        }
        let mut key = point.anchor.commit_key.clone();
        let mut version = point.anchor.version_id.clone();
        let mut sequence = point.anchor.sequence;
        let mut digest = point.anchor.body_digest;
        let mut child_time = None;
        loop {
            let commit = self
                .history_commit(state, &key, version.as_ref(), budgets)
                .await?;
            let header = &commit.parsed_header.header;
            if header.self_ref.sequence != sequence
                || header.body_digest != digest
                || commit.version_id != version
            {
                return Err(V2FormatError::InvalidRecoveryHistory);
            }
            if let Some(child) = child_time {
                crate::v2::recovery::validate_parent_time(Some(header.publish_time_ms), child)?;
            } else if header.publish_time_ms != point.publish_time_ms
                || header.signing_key_id != point.anchor.signing_key_id
            {
                return Err(V2FormatError::InvalidRecoveryHistory);
            }
            mark_history_deadline(state, &key, version.as_ref(), point.protected_until_ms)?;
            if !walk.chains.insert((key.clone(), version.clone())) {
                break;
            }
            for (ordinal, section) in header.section_index.iter().enumerate() {
                let ordinal = u32::try_from(ordinal).map_err(|_| V2FormatError::SectionBounds)?;
                match section.section_type {
                    V2SectionType::IndexRun => {
                        self.include_history_run(
                            state,
                            walk,
                            HistoryRun {
                                commit: &commit,
                                ordinal,
                                expected: None,
                                deadline: point.protected_until_ms,
                            },
                            budgets,
                        )
                        .await?;
                    }
                    V2SectionType::IndexRoot => {
                        let root = self.open_index_root_without_replay(
                            &commit,
                            ordinal,
                            commit_section_bytes(&commit, ordinal as usize)?,
                            V2ReplayLimits {
                                max_commits: usize::try_from(budgets.max_inventory_item_count)
                                    .map_err(|_| V2FormatError::MaintenanceBudgetExceeded)?,
                                max_total_commit_bytes: u64::MAX,
                                max_retained_bytes: budgets.max_history_pending_bytes,
                                ..self.options().replay_limits
                            },
                        )?;
                        for expected in root.runs() {
                            let run = self
                                .history_commit(
                                    state,
                                    &expected.location.commit_key,
                                    expected.location.version_id.as_ref(),
                                    budgets,
                                )
                                .await?;
                            validate_catalog_edge(&commit, &run, expected)?;
                            mark_history_deadline(
                                state,
                                &expected.location.commit_key,
                                expected.location.version_id.as_ref(),
                                point.protected_until_ms,
                            )?;
                            self.include_history_run(
                                state,
                                walk,
                                HistoryRun {
                                    commit: &run,
                                    ordinal: expected.location.section_ordinal,
                                    expected: Some(expected),
                                    deadline: point.protected_until_ms,
                                },
                                budgets,
                            )
                            .await?;
                        }
                    }
                    V2SectionType::PayloadPack | V2SectionType::Recovery => {}
                    _ => return Err(V2FormatError::UnsupportedSection),
                }
            }
            if header.kind == V2CommitKind::Root {
                release_history_sections(state, &key, version.as_ref());
                break;
            }
            let parent = header
                .parent
                .as_ref()
                .ok_or(V2FormatError::InvalidRecoveryHistory)?;
            key = parent.commit_key.clone();
            version = parent.version_id.clone();
            sequence = parent.sequence;
            digest = parent.body_digest;
            child_time = Some(header.publish_time_ms);
        }
        Ok(())
    }

    async fn include_history_run(
        &self,
        state: &mut V2ReachabilityState,
        walk: &mut HistoryWalk,
        run: HistoryRun<'_>,
        budgets: V2MaintenanceBudgets,
    ) -> V2Result<()> {
        let HistoryRun {
            commit,
            ordinal,
            expected,
            deadline,
        } = run;
        let key = (
            commit.parsed_header.header.self_ref.commit_key.clone(),
            commit.version_id.clone(),
            ordinal,
        );
        if let Some(previous) = walk.runs.get(&key) {
            if expected.is_some_and(|expected| expected != previous) {
                return Err(V2FormatError::InvalidIndexRoot);
            }
            return Ok(());
        }
        // Replay one unique run, not one namespace per historical point. This
        // reuses all blind-key, pointer, self-pack and catalog-claim validation.
        let mut run_state = RepositoryState::default();
        let actual = apply_packed_index_run(
            self.keyring(),
            &self.options().repository_id,
            &mut run_state,
            V2PackedIndexRunReplay {
                parsed_header: &commit.parsed_header,
                version_id: commit.version_id.as_ref(),
                object_len: commit.object_len,
                section_ordinal: ordinal,
                stored_run: commit_section_bytes(commit, ordinal as usize)?,
                level: expected.map_or(0, |run| run.level),
                compaction_generation: expected.map_or(0, |run| run.compaction_generation),
                provider_profile: self.provider_profile(),
            },
        )
        .map_err(|_| V2FormatError::InvalidIndexRun)?;
        if expected.is_some_and(|expected| expected != &actual) {
            return Err(V2FormatError::InvalidIndexRoot);
        }
        charge_history_metadata(
            state,
            usize_to_u64(std::mem::size_of::<V2IndexRootRunRef>())
                .saturating_add(2 * usize_to_u64(commit.parsed_header.header_len)),
            budgets,
        )?;
        walk.runs.insert(key, actual);
        for entry in run_state.namespace.live_entries() {
            walk.represented_retention =
                strongest_retention(walk.represented_retention, entry.retention);
            match &entry.payload_ref {
                Some(PayloadReference::V2Pack { carrier, .. }) => {
                    let payload = self
                        .history_commit(
                            state,
                            &carrier.commit_key,
                            carrier.commit_version_id.as_ref(),
                            budgets,
                        )
                        .await?;
                    if payload.parsed_header.header.body_digest != carrier.body_digest
                        || payload.object_len != carrier.commit_stored_len
                    {
                        return Err(V2FormatError::BodyDigestMismatch);
                    }
                    state.include_required_protection(
                        &carrier.commit_key,
                        carrier.commit_version_id.as_ref(),
                        entry.retention,
                        entry.legal_hold,
                    )?;
                    mark_history_deadline(
                        state,
                        &carrier.commit_key,
                        carrier.commit_version_id.as_ref(),
                        deadline,
                    )?;
                }
                Some(PayloadReference::V2StandaloneStream { carrier }) => {
                    let root = standalone_payload_root(carrier);
                    validate_standalone_payload_root(&root)?;
                    let key = (root.object_id.clone(), root.version_id.clone());
                    if let Some(previous) = state.standalone_facts.get(&key) {
                        if previous != &root {
                            return Err(V2FormatError::InvalidHeaderField);
                        }
                    } else {
                        if usize_to_u64(state.renewal_targets.len())
                            >= budgets.max_inventory_item_count
                        {
                            return Err(V2FormatError::MaintenanceBudgetExceeded);
                        }
                        charge_history_metadata(
                            state,
                            target_fact_bytes(&key)
                                .saturating_add(usize_to_u64(std::mem::size_of::<
                                    V2StandalonePayloadRoot,
                                >()))
                                .saturating_add(1024),
                            budgets,
                        )?;
                        let metadata = self
                            .store()
                            .head_at(&root.object_id, root.version_id.as_ref())
                            .await
                            .map_err(|_| V2FormatError::StorageOperationFailed)?;
                        state.graph_head_count = state.graph_head_count.saturating_add(1);
                        if metadata.object_id != root.object_id
                            || metadata.version_id != root.version_id
                            || metadata.content_len != root.stored_len
                        {
                            return Err(V2FormatError::ProviderProfileFailed);
                        }
                    }
                    state.include_standalone(root, true, entry.retention, entry.legal_hold)?;
                    mark_history_deadline(state, &key.0, key.1.as_ref(), deadline)?;
                }
                None => {}
                Some(PayloadReference::Pending | PayloadReference::V2PackSelf { .. }) => {
                    return Err(V2FormatError::InvalidHeaderField);
                }
            }
        }
        release_history_sections(
            state,
            &commit.parsed_header.header.self_ref.commit_key,
            commit.version_id.as_ref(),
        );
        Ok(())
    }
}

fn include_recovery_point_facts(
    state: &mut V2ReachabilityState,
    point: &RecoveryPoint,
) -> V2Result<()> {
    state.recovery_recoverable_point_count = state
        .recovery_recoverable_point_count
        .checked_add(1)
        .ok_or(V2FormatError::MaintenanceBudgetExceeded)?;
    state.recovery_oldest_recoverable_publish_time_ms = Some(
        state
            .recovery_oldest_recoverable_publish_time_ms
            .map_or(point.publish_time_ms, |previous| {
                previous.min(point.publish_time_ms)
            }),
    );
    Ok(())
}

fn retained_bytes(commit: &V2ReplayCommit) -> u64 {
    commit
        .retained_sections
        .iter()
        .flatten()
        .fold(0_u64, |total, bytes| {
            total.saturating_add(usize_to_u64(bytes.len()))
        })
}

fn target_fact_bytes(key: &ExactVersion) -> u64 {
    // Account repeated exact keys in reachability, target and visited maps,
    // including tree nodes. This is an input-size bound, not an allocator meter.
    1024_u64
        .saturating_add(usize_to_u64(key.0.as_str().len()).saturating_mul(8))
        .saturating_add(key.1.as_ref().map_or(0, |version| {
            usize_to_u64(version.as_str().len()).saturating_mul(8)
        }))
}

fn commit_fact_bytes(commit: &V2ReplayCommit) -> u64 {
    usize_to_u64(std::mem::size_of::<V2ReplayCommit>())
        .saturating_add(2 * usize_to_u64(commit.parsed_header.header_len))
}

fn charge_history_metadata(
    state: &mut V2ReachabilityState,
    bytes: u64,
    budgets: V2MaintenanceBudgets,
) -> V2Result<()> {
    state.history_metadata_bytes = state
        .history_metadata_bytes
        .checked_add(bytes)
        .filter(|total| *total <= budgets.max_history_metadata_bytes)
        .ok_or(V2FormatError::MaintenanceBudgetExceeded)?;
    Ok(())
}

fn release_history_sections(
    state: &mut V2ReachabilityState,
    key: &BackendObjectId,
    version: Option<&BackendVersionId>,
) {
    if let Some(commit) = state
        .verified_commits
        .get_mut(&(key.clone(), version.cloned()))
    {
        state.history_pending_bytes = state
            .history_pending_bytes
            .saturating_sub(retained_bytes(commit));
        let facts = Arc::make_mut(commit);
        facts
            .retained_sections
            .iter_mut()
            .for_each(|section| *section = None);
    }
}

fn mark_history_deadline(
    state: &mut V2ReachabilityState,
    key: &BackendObjectId,
    version: Option<&BackendVersionId>,
    deadline: i64,
) -> V2Result<()> {
    let exact = (key.clone(), version.cloned());
    let target = state
        .renewal_targets
        .get_mut(&exact)
        .ok_or(V2FormatError::InvalidRecoveryHistory)?;
    target.required_deadline = target.required_deadline.max(Some(deadline));
    state.protected_versions.insert(exact);
    Ok(())
}

fn validate_catalog_edge(
    containing: &V2ReplayCommit,
    run: &V2ReplayCommit,
    expected: &V2IndexRootRunRef,
) -> V2Result<()> {
    let header = &containing.parsed_header.header;
    let referenced = &run.parsed_header.header;
    let location = &expected.location;
    let ordinal =
        usize::try_from(location.section_ordinal).map_err(|_| V2FormatError::SectionBounds)?;
    let descriptor = referenced
        .section_index
        .get(ordinal)
        .ok_or(V2FormatError::InvalidIndexRoot)?;
    let covered_parent = header
        .parent
        .as_ref()
        .map_or(Sequence::ZERO, |parent| parent.sequence);
    let lineage = if expected.level > 0 {
        expected.compaction_generation == referenced.self_ref.sequence.get()
            && referenced.self_ref.sequence <= header.self_ref.sequence
            && referenced.parent.is_some()
            && referenced.section_index.len() == 1
            && ordinal == 0
            && if referenced.self_ref.sequence == header.self_ref.sequence {
                referenced.parent == header.parent
            } else {
                referenced.self_ref.sequence <= covered_parent
            }
    } else {
        expected.compaction_generation == 0 && referenced.self_ref.sequence <= covered_parent
    };
    if run.version_id != location.version_id
        || run.object_len != location.commit_stored_len
        || run.parsed_header.sections_start as u64 != location.sections_start
        || referenced.kind != V2CommitKind::Delta
        || !lineage
        || referenced.body_digest != location.commit_body_digest
        || referenced.keyring_envelope_ref != expected.keyring_envelope_ref
        || descriptor.section_type != V2SectionType::IndexRun
        || descriptor.flags != V2_SECTION_FLAG_MUST_UNDERSTAND
        || descriptor.offset != location.section_offset
        || descriptor.length != location.section_len
        || descriptor.digest != location.section_digest
    {
        return Err(V2FormatError::InvalidIndexRoot);
    }
    Ok(())
}

#[cfg(test)]
pub(in crate::v2) struct RecoveryMarkObservation {
    pub targets: BTreeMap<ExactVersion, Option<i64>>,
    pub cutoff: Option<i64>,
    pub expiry_due: Option<i64>,
    pub accounted_metadata_bytes: u64,
    pub pending_section_bytes: u64,
    pub point_count: u64,
    pub oldest_publish_time_ms: Option<i64>,
    pub historical_exact_bytes: u64,
    pub clock_uncertainty_ms: Option<u32>,
}

#[cfg(test)]
impl<S: BlobStore> V2CommitStore<S> {
    pub(in crate::v2) async fn recovery_mark_for_tests<A: V2CommitAnchor>(
        &self,
        anchor: &A,
        budgets: V2MaintenanceBudgets,
    ) -> V2Result<RecoveryMarkObservation> {
        let reader = self.rebind_store(V2MaintenanceBudgetedStore::new(self.store(), budgets));
        let graph = reader
            .load_reachability(anchor, &[], budgets, false)
            .await?;
        Ok(RecoveryMarkObservation {
            targets: graph
                .renewal_targets
                .into_iter()
                .map(|(key, target)| (key, target.required_deadline))
                .collect(),
            cutoff: graph.recovery_expire_before_ms,
            expiry_due: graph.recovery_expiry_due_ms,
            accounted_metadata_bytes: graph.history_metadata_bytes,
            pending_section_bytes: graph.history_pending_bytes,
            point_count: graph.recovery_recoverable_point_count,
            oldest_publish_time_ms: graph.recovery_oldest_recoverable_publish_time_ms,
            historical_exact_bytes: graph.recovery_historical_exact_bytes,
            clock_uncertainty_ms: graph.recovery_clock_uncertainty_ms,
        })
    }
}
