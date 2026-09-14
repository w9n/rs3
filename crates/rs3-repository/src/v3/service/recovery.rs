//! Accepted recovery transition preparation and pre-CAS readback.

use super::*;
use crate::v3::maintenance::capacity::RecoveryCapacity;
use crate::v3::maintenance::coverage::RecoveryCoverage;
use crate::v3::maintenance::introduced::RecoveryIntroduced;
use crate::v3::recovery::publication::CapturedRecoveryPublication;
use crate::v3::repository::{V3AnchorState, V3PublicationPlan};

pub(super) struct PreparedServicePublication {
    pub plan: V3PublicationPlan,
    pub recovery: Option<CapturedRecoveryPublication>,
    coverage: Option<RecoveryCoverage>,
    introduced_floor: Option<i64>,
    capacity: Option<RecoveryCapacity>,
}

impl PreparedServicePublication {
    pub(super) fn history_uncertainty_ms(&self) -> Option<u32> {
        self.recovery.as_ref().map(|capture| {
            capture
                .previous
                .policy
                .clock_uncertainty_ms()
                .min(capture.current_policy.clock_uncertainty_ms())
        })
    }
}

impl<S: BlobStore + Clone> V3Repository<S> {
    pub(super) async fn prepare_service_publication<
        A: V3CommitAnchor,
        G: V3MaintenanceGuard + ?Sized,
    >(
        &self,
        anchor: &A,
        base: &V3AnchorState,
        is_root: bool,
        guard: Option<&G>,
    ) -> Result<PreparedServicePublication> {
        let previous = {
            let accepted = self
                .accepted
                .read()
                .map_err(|_| RepositoryError::StatePoisoned)?;
            if accepted.anchor.as_ref() != Some(base) {
                return Err(v3_repository_error(V3FormatError::StaleAnchor));
            }
            accepted.recovery.clone()
        };
        let plan = self
            .commit_store
            .prepare_child_publication(base)
            .await
            .map_err(v3_repository_error)?;
        let recovery = match (previous, self.commit_store.options().recovery_policy) {
            (None, None) => None,
            (Some(previous), Some(policy)) => Some(
                CapturedRecoveryPublication::new(plan.clone(), previous, policy, is_root)
                    .map_err(v3_repository_error)?,
            ),
            _ => return Err(v3_repository_error(V3FormatError::InvalidRecoveryHistory)),
        };
        let coverage = if let Some(capture) = recovery.as_ref()
            && self.commit_store.provider_profile() == V3ProviderProfile::RetainedVersionObjectLock
        {
            let guard =
                guard.ok_or_else(|| v3_repository_error(V3FormatError::ProviderProfileFailed))?;
            Some(
                self.commit_store
                    .protect_recovery_publication(
                        anchor,
                        guard,
                        capture,
                        self.commit_store.options().recovery_maintenance_budgets,
                    )
                    .await
                    .map_err(v3_repository_error)?,
            )
        } else {
            None
        };
        if recovery.is_some() {
            if let Some(guard) = guard {
                guard
                    .verify_v3_maintenance(Some(base))
                    .await
                    .map_err(v3_repository_error)?;
            }
            if anchor
                .read_v3()
                .await
                .map_err(v3_repository_error)?
                .as_ref()
                != Some(base)
            {
                return Err(v3_repository_error(V3FormatError::StaleAnchor));
            }
        }
        Ok(PreparedServicePublication {
            plan,
            recovery,
            coverage,
            introduced_floor: None,
            capacity: None,
        })
    }

    pub(super) fn append_recovery_section(
        &self,
        mut write: V3CommitWrite,
        key: &super::super::V3CommitKey,
        prepared: &PreparedServicePublication,
    ) -> super::super::V3Result<V3CommitWrite> {
        if let Some(capture) = &prepared.recovery {
            let ordinal =
                u32::try_from(write.sections.len()).map_err(|_| V3FormatError::SectionBounds)?;
            let context = packed::repository_context_from_refs(
                &self.commit_store.options().repository_id,
                &self.commit_store.options().keyring_envelope_ref,
            )
            .map_err(|_| V3FormatError::InvalidRecoveryHistory)?;
            let bytes = super::super::recovery::section::seal(
                self.commit_store.keyring(),
                &context,
                &key.object_id,
                ordinal,
                &capture.section.encode()?,
            )?;
            if self.commit_store.provider_profile() == V3ProviderProfile::RetainedVersionObjectLock
            {
                write =
                    write.with_required_retain_until_ms(Some(capture.required_coverage_until_ms));
            }
            write.sections.push(V3CommitSection::new(
                V3SectionType::Recovery,
                V3_SECTION_FLAG_MUST_UNDERSTAND,
                bytes,
            ));
        }
        Ok(write)
    }

    pub(super) fn advance_service_recovery_coverage(
        &self,
        prepared: &PreparedServicePublication,
        accepted: &V3AnchorState,
    ) {
        if let Some(capacity) = &prepared.capacity {
            self.commit_store
                .install_recovery_capacity(capacity, accepted);
        }
        if let (Some(base), Some(introduced)) = (&prepared.coverage, prepared.introduced_floor) {
            self.commit_store
                .advance_recovery_coverage(base, accepted, introduced);
        }
    }

    pub(super) fn pending_recovery_entries(pending: &PendingV3Snapshot) -> Vec<&NamespaceEntry> {
        pending
            .deltas()
            .iter()
            .filter_map(|delta| match delta {
                IndexDelta::Upsert { entry, .. } => Some(entry.as_ref()),
                IndexDelta::Tombstone { .. } => None,
            })
            .collect()
    }

    pub(super) fn validate_recovery_publication_freshness(
        &self,
        prepared: &PreparedServicePublication,
    ) -> Result<()> {
        if let Some(capture) = &prepared.recovery {
            super::super::recovery::validate_history_publication_freshness(
                self.commit_store.publication_now_ms(),
                capture.publication.publish_time_ms,
                capture
                    .previous
                    .policy
                    .clock_uncertainty_ms()
                    .min(capture.current_policy.clock_uncertainty_ms()),
            )
            .map_err(v3_repository_error)?;
        }
        Ok(())
    }

    pub(super) async fn verify_recovery_publication<
        A: V3CommitAnchor,
        G: V3MaintenanceGuard + ?Sized,
    >(
        &self,
        anchor: &A,
        guard: Option<&G>,
        prepared: &mut PreparedServicePublication,
        uploaded: &V3StoredCommit,
        entries: &[&NamespaceEntry],
        new_runs: &[V3IndexRootRunRef],
    ) -> Result<Option<AcceptedRecoveryState>> {
        let Some(capture) = &prepared.recovery else {
            return Ok(None);
        };
        let authenticated = self
            .commit_store
            .read_published_recovery(uploaded, &capture.publication)
            .await
            .map_err(v3_repository_error)?;
        let ordinal = authenticated.ordinal;
        let section = authenticated.section;
        if section != capture.section {
            return Err(v3_repository_error(V3FormatError::InvalidRecoveryHistory));
        }
        section
            .validate_for_commit(
                Some((
                    &capture.publication.parent,
                    capture.publication.parent_publish_time_ms,
                    &capture.previous.policy,
                )),
                capture.publication.publish_time_ms,
                authenticated.kind == super::super::V3CommitKind::Root,
                capture.previous.snapshot.expire_before_ms.max(
                    capture
                        .current_policy
                        .expiry_cutoff_ms(capture.publication.sampled_now_ms)
                        .map_err(v3_repository_error)?,
                ),
            )
            .map_err(v3_repository_error)?;
        let snapshot = section
            .apply_delta(&capture.previous.snapshot, &uploaded.anchor_state, ordinal)
            .map_err(v3_repository_error)?;
        if prepared.coverage.is_some() {
            let guard =
                guard.ok_or_else(|| v3_repository_error(V3FormatError::ProviderProfileFailed))?;
            prepared.introduced_floor = Some(
                self.commit_store
                    .protect_recovery_introduced(
                        anchor,
                        guard,
                        capture,
                        RecoveryIntroduced {
                            uploaded,
                            entries,
                            new_runs,
                            budgets: self.commit_store.options().recovery_maintenance_budgets,
                        },
                    )
                    .await
                    .map_err(v3_repository_error)?,
            );
        }
        if prepared.coverage.is_some() {
            prepared.capacity = Some(
                self.commit_store
                    .verify_recovery_capacity(
                        &capture.publication.parent,
                        uploaded,
                        &authenticated.header,
                        entries,
                        new_runs,
                    )
                    .await
                    .map_err(v3_repository_error)?,
            );
            let guard =
                guard.ok_or_else(|| v3_repository_error(V3FormatError::ProviderProfileFailed))?;
            guard
                .verify_v3_maintenance(Some(&capture.publication.parent))
                .await
                .map_err(v3_repository_error)?;
            if anchor
                .read_v3()
                .await
                .map_err(v3_repository_error)?
                .as_ref()
                != Some(&capture.publication.parent)
            {
                return Err(v3_repository_error(V3FormatError::StaleAnchor));
            }
        }
        Ok(Some(AcceptedRecoveryState {
            policy: section.current_policy,
            snapshot: Arc::new(snapshot),
        }))
    }
}
