//! Bounded exact protection for references introduced by a verified publication.

use super::*;
use crate::v3::recovery::publication::CapturedRecoveryPublication;
use crate::v3::repository::V3StoredCommit;

pub(in crate::v3) struct RecoveryIntroduced<'a> {
    pub uploaded: &'a V3StoredCommit,
    pub entries: &'a [&'a NamespaceEntry],
    pub new_runs: &'a [V3IndexRootRunRef],
    pub budgets: V3MaintenanceBudgets,
}

impl<S: BlobStore> V3CommitStore<S> {
    pub(in crate::v3) async fn protect_recovery_introduced<A, G>(
        &self,
        anchor: &A,
        guard: &G,
        capture: &CapturedRecoveryPublication,
        introduced: RecoveryIntroduced<'_>,
    ) -> V3Result<i64>
    where
        A: V3CommitAnchor,
        G: V3MaintenanceGuard + ?Sized,
    {
        let RecoveryIntroduced {
            uploaded,
            entries,
            new_runs,
            budgets,
        } = introduced;
        if self.provider_profile() != V3ProviderProfile::RetainedVersionObjectLock
            || entries.len() > rs3_index::run::INDEX_PACK_MAX_RECORDS as usize
            || new_runs.len() > super::super::V3_INDEX_ROOT_MAX_RUNS
        {
            return Err(V3FormatError::ProviderProfileFailed);
        }
        let mut floor = uploaded
            .verified_retain_until_ms
            .filter(|floor| *floor >= capture.required_coverage_until_ms)
            .ok_or(V3FormatError::ProviderProfileFailed)?;
        let mut targets: BTreeMap<(BackendObjectId, Option<BackendVersionId>), V3RetentionTarget> =
            BTreeMap::new();
        for entry in entries {
            let reference = match &entry.payload_ref {
                Some(PayloadReference::V3Pack { carrier, .. }) => Some((
                    carrier.commit_key.clone(),
                    carrier.commit_version_id.clone(),
                    carrier.commit_stored_len,
                    &carrier.content_key_id,
                )),
                Some(PayloadReference::V3StandaloneStream { carrier }) => Some((
                    carrier.object_id.clone(),
                    carrier.version_id.clone(),
                    carrier.stored_len,
                    &carrier.payload_layout.key_id,
                )),
                None if entry.content_len == 0 => None,
                _ => return Err(V3FormatError::InvalidRecoveryHistory),
            };
            if let Some((object_id, version_id, stored_len, key_id)) = reference {
                if !self.keyring().descriptors().iter().any(|key| {
                    &key.id == key_id
                        && key.purpose == rs3_types::KeyPurpose::Content
                        && key.status.is_enabled_for_lookup()
                }) {
                    return Err(V3FormatError::ProviderProfileFailed);
                }
                add_target(
                    &mut targets,
                    uploaded,
                    V3RetentionTarget {
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
                V3RetentionTarget {
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
        let budgeted = V3MaintenanceBudgetedStore::new(self.store(), budgets);
        let mut extensions = 0_u64;
        for target in targets.values_mut() {
            guard
                .verify_v3_maintenance(Some(&capture.publication.parent))
                .await?;
            if anchor.read_v3().await?.as_ref() != Some(&capture.publication.parent) {
                return Err(V3FormatError::StaleAnchor);
            }
            let observed = budgeted
                .head_at(&target.object_id, target.version_id.as_ref())
                .await
                .map_err(|_| {
                    if budgeted.usage().is_ok_and(|usage| usage.exhausted) {
                        V3FormatError::MaintenanceBudgetExceeded
                    } else {
                        V3FormatError::StorageOperationFailed
                    }
                })?;
            if observed.object_id != target.object_id
                || observed.version_id != target.version_id
                || observed.content_len != target.stored_len
            {
                return Err(V3FormatError::ProviderProfileFailed);
            }
            let policy = active_retention(strongest_retention(
                target.required_retention,
                observed.retention,
            ))
            .ok_or(V3FormatError::ProviderProfileFailed)?;
            let observed_floor = observed
                .retain_until_ms
                .ok_or(V3FormatError::ProviderProfileFailed)?;
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
                    .ok_or(V3FormatError::MaintenanceBudgetExceeded)?;
                if !budget_allows(budgets.max_retention_extend_count, extensions) {
                    return Err(V3FormatError::MaintenanceBudgetExceeded);
                }
                // Reserve the executor's extension and exact verification HEAD
                // before mutation; the planning wrapper remains read-only.
                budgeted
                    .charge(0, 0, None)
                    .and_then(|_| budgeted.charge(1, 0, None))
                    .map_err(|_| V3FormatError::MaintenanceBudgetExceeded)?;
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
            .verify_v3_maintenance(Some(&capture.publication.parent))
            .await?;
        if anchor.read_v3().await?.as_ref() != Some(&capture.publication.parent) {
            return Err(V3FormatError::StaleAnchor);
        }
        Ok(floor)
    }
}

fn add_target(
    targets: &mut BTreeMap<(BackendObjectId, Option<BackendVersionId>), V3RetentionTarget>,
    uploaded: &V3StoredCommit,
    target: V3RetentionTarget,
) -> V3Result<()> {
    if target.version_id.is_none() || target.stored_len == 0 {
        return Err(V3FormatError::ProviderProfileFailed);
    }
    if target.object_id == uploaded.anchor_state.commit_key
        && target.version_id == uploaded.version_id
    {
        if target.stored_len != uploaded.object_len {
            return Err(V3FormatError::InvalidRecoveryHistory);
        }
        return Ok(());
    }
    let key = (target.object_id.clone(), target.version_id.clone());
    if let Some(previous) = targets.get_mut(&key) {
        if previous.stored_len != target.stored_len {
            return Err(V3FormatError::InvalidRecoveryHistory);
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
