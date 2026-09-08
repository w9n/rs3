//! Bounded exact protection for references introduced by a verified publication.

use super::*;
use crate::v2::recovery::publication::CapturedRecoveryPublication;
use crate::v2::repository::V2StoredCommit;

pub(in crate::v2) struct RecoveryIntroduced<'a> {
    pub uploaded: &'a V2StoredCommit,
    pub entries: &'a [&'a NamespaceEntry],
    pub new_runs: &'a [V2IndexRootRunRef],
    pub budgets: V2MaintenanceBudgets,
}

impl<S: BlobStore> V2CommitStore<S> {
    pub(in crate::v2) async fn protect_recovery_introduced<A, G>(
        &self,
        anchor: &A,
        guard: &G,
        capture: &CapturedRecoveryPublication,
        introduced: RecoveryIntroduced<'_>,
    ) -> V2Result<i64>
    where
        A: V2CommitAnchor,
        G: V2MaintenanceGuard + ?Sized,
    {
        let RecoveryIntroduced {
            uploaded,
            entries,
            new_runs,
            budgets,
        } = introduced;
        if self.provider_profile() != V2ProviderProfile::RetainedVersionObjectLock
            || entries.len() > rs3_index::run::INDEX_PACK_MAX_RECORDS as usize
            || new_runs.len() > super::super::V2_INDEX_ROOT_MAX_RUNS
        {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        let mut floor = uploaded
            .verified_retain_until_ms
            .filter(|floor| *floor >= capture.required_coverage_until_ms)
            .ok_or(V2FormatError::ProviderProfileFailed)?;
        let mut targets: BTreeMap<(BackendObjectId, Option<BackendVersionId>), V2RetentionTarget> =
            BTreeMap::new();
        for entry in entries {
            let reference = match &entry.payload_ref {
                Some(PayloadReference::V2Pack { carrier, .. }) => Some((
                    carrier.commit_key.clone(),
                    carrier.commit_version_id.clone(),
                    carrier.commit_stored_len,
                    &carrier.content_key_id,
                )),
                Some(PayloadReference::V2StandaloneStream { carrier }) => Some((
                    carrier.object_id.clone(),
                    carrier.version_id.clone(),
                    carrier.stored_len,
                    &carrier.payload_layout.key_id,
                )),
                None if entry.content_len == 0 => None,
                _ => return Err(V2FormatError::InvalidRecoveryHistory),
            };
            if let Some((object_id, version_id, stored_len, key_id)) = reference {
                if !self.keyring().descriptors().iter().any(|key| {
                    &key.id == key_id
                        && key.purpose == rs3_types::KeyPurpose::Content
                        && key.status.is_enabled_for_lookup()
                }) {
                    return Err(V2FormatError::ProviderProfileFailed);
                }
                add_target(
                    &mut targets,
                    uploaded,
                    V2RetentionTarget {
                        object_id,
                        version_id,
                        stored_len,
                        required_retention: strongest_retention(
                            self.retention_policy(),
                            entry.retention,
                        ),
                        required_legal_hold: entry.legal_hold,
                        required_deadline: Some(capture.required_coverage_until_ms),
                        current_recovery_dependency: false,
                    },
                )?;
            }
        }
        for run in new_runs {
            add_target(
                &mut targets,
                uploaded,
                V2RetentionTarget {
                    object_id: run.location.commit_key.clone(),
                    version_id: run.location.version_id.clone(),
                    stored_len: run.location.commit_stored_len,
                    required_retention: self.retention_policy(),
                    required_legal_hold: None,
                    required_deadline: Some(capture.required_coverage_until_ms),
                    current_recovery_dependency: false,
                },
            )?;
        }
        let budgeted = V2MaintenanceBudgetedStore::new(self.store(), budgets);
        let mut extensions = 0_u64;
        for target in targets.values_mut() {
            guard
                .verify_v2_maintenance(Some(&capture.publication.parent))
                .await?;
            if anchor.read_v2().await?.as_ref() != Some(&capture.publication.parent) {
                return Err(V2FormatError::StaleAnchor);
            }
            let observed = budgeted
                .head_at(&target.object_id, target.version_id.as_ref())
                .await
                .map_err(|_| {
                    if budgeted.usage().is_ok_and(|usage| usage.exhausted) {
                        V2FormatError::MaintenanceBudgetExceeded
                    } else {
                        V2FormatError::StorageOperationFailed
                    }
                })?;
            if observed.object_id != target.object_id
                || observed.version_id != target.version_id
                || observed.content_len != target.stored_len
            {
                return Err(V2FormatError::ProviderProfileFailed);
            }
            let policy = active_retention(strongest_retention(
                target.required_retention,
                observed.retention,
            ))
            .ok_or(V2FormatError::ProviderProfileFailed)?;
            let observed_floor = observed
                .retain_until_ms
                .ok_or(V2FormatError::ProviderProfileFailed)?;
            target.required_retention = Some(policy);
            target.required_deadline = Some(capture.required_coverage_until_ms.max(observed_floor));
            if observed.legal_hold == Some(LegalHoldStatus::On) {
                target.required_legal_hold = observed.legal_hold;
            }
            let actual = if observed_floor >= capture.required_coverage_until_ms
                && retention_satisfies(observed.retention.as_ref(), &policy)
                && (target.required_legal_hold != Some(LegalHoldStatus::On)
                    || observed.legal_hold == Some(LegalHoldStatus::On))
            {
                observed_floor
            } else {
                extensions = extensions
                    .checked_add(1)
                    .ok_or(V2FormatError::MaintenanceBudgetExceeded)?;
                if !budget_allows(budgets.max_retention_extend_count, extensions) {
                    return Err(V2FormatError::MaintenanceBudgetExceeded);
                }
                // Reserve the executor's extension and exact verification HEAD
                // before mutation; the planning wrapper remains read-only.
                budgeted
                    .charge(0, 0, None)
                    .and_then(|_| budgeted.charge(1, 0, None))
                    .map_err(|_| V2FormatError::MaintenanceBudgetExceeded)?;
                self.extend_and_verify_retention_target(
                    anchor,
                    guard,
                    Some(&capture.publication.parent),
                    target,
                )
                .await?
            };
            floor = floor.min(actual);
        }
        guard
            .verify_v2_maintenance(Some(&capture.publication.parent))
            .await?;
        if anchor.read_v2().await?.as_ref() != Some(&capture.publication.parent) {
            return Err(V2FormatError::StaleAnchor);
        }
        Ok(floor)
    }
}

fn add_target(
    targets: &mut BTreeMap<(BackendObjectId, Option<BackendVersionId>), V2RetentionTarget>,
    uploaded: &V2StoredCommit,
    target: V2RetentionTarget,
) -> V2Result<()> {
    if target.version_id.is_none() || target.stored_len == 0 {
        return Err(V2FormatError::ProviderProfileFailed);
    }
    if target.object_id == uploaded.anchor_state.commit_key
        && target.version_id == uploaded.version_id
    {
        if target.stored_len != uploaded.object_len {
            return Err(V2FormatError::InvalidRecoveryHistory);
        }
        return Ok(());
    }
    let key = (target.object_id.clone(), target.version_id.clone());
    if let Some(previous) = targets.get_mut(&key) {
        if previous.stored_len != target.stored_len {
            return Err(V2FormatError::InvalidRecoveryHistory);
        }
        previous.required_retention =
            strongest_retention(previous.required_retention, target.required_retention);
        previous.required_deadline = previous.required_deadline.max(target.required_deadline);
        if target.required_legal_hold == Some(LegalHoldStatus::On) {
            previous.required_legal_hold = target.required_legal_hold;
        }
    } else {
        targets.insert(key, target);
    }
    Ok(())
}
