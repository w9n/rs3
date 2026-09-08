//! Verified recovery protection reused between accepted publications.

use super::*;
use crate::v2::recovery::publication::CapturedRecoveryPublication;

/// This proof can only be constructed after exact-version protection checks.
/// The anchor authenticates both the namespace and its recovery registry.
/// The floor covers the current graph; historical dependencies are separately
/// verified through their immutable promises, avoiding sliding old deadlines.
#[derive(Clone, Debug)]
pub(in crate::v2) struct RecoveryCoverage {
    base_anchor: V2AnchorState,
    protected_until_ms: i64,
}

impl<S: BlobStore> V2CommitStore<S> {
    /// Genesis has exactly three restore dependencies and no inherited proof.
    pub(in crate::v2) async fn protect_recovery_genesis<A: V2CommitAnchor>(
        &self,
        anchor: &A,
        guard: &dyn V2MaintenanceGuard,
        genesis: &V2AnchorState,
        stored_len: u64,
        required_until_ms: i64,
    ) -> V2Result<()> {
        let keyring = self
            .options()
            .maintenance_keyring_envelope_ref
            .as_ref()
            .ok_or(V2FormatError::ProviderProfileFailed)?;
        if keyring.commit_ref()? != self.options().keyring_envelope_ref {
            return Err(V2FormatError::InvalidFormatRoot);
        }
        let policy = active_retention(self.retention_policy())
            .ok_or(V2FormatError::ProviderProfileFailed)?;
        let targets = [
            (
                &genesis.commit_key,
                genesis.version_id.as_ref(),
                Some(stored_len),
            ),
            (
                &self.options().format_ref.object_id,
                self.options().format_ref.version_id.as_ref(),
                None,
            ),
            (&keyring.object_id, keyring.version_id.as_ref(), None),
        ];
        if targets
            .iter()
            .any(|(_, version, len)| version.is_none() || *len == Some(0))
        {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        for (id, version, len) in targets {
            guard.verify_v2_maintenance(None).await?;
            if anchor.read_v2().await?.is_some() {
                return Err(V2FormatError::StaleAnchor);
            }
            let exact = self
                .store()
                .head_at(id, version)
                .await
                .map_err(|_| V2FormatError::StorageOperationFailed)?;
            if exact.object_id != *id
                || exact.version_id.as_ref() != version
                || exact.content_len == 0
                || len.is_some_and(|len| len != exact.content_len)
            {
                return Err(V2FormatError::ProviderProfileFailed);
            }
            let required = strongest_retention(Some(policy), exact.retention)
                .ok_or(V2FormatError::ProviderProfileFailed)?;
            if exact
                .retain_until_ms
                .is_some_and(|floor| floor >= required_until_ms)
                && retention_satisfies(exact.retention.as_ref(), &required)
            {
                continue;
            }
            let target = V2RetentionTarget {
                object_id: id.clone(),
                version_id: version.cloned(),
                stored_len: exact.content_len,
                required_retention: Some(required),
                required_legal_hold: exact.legal_hold,
                required_deadline: Some(required_until_ms.max(exact.retain_until_ms.unwrap_or(0))),
                current_recovery_dependency: false,
            };
            self.extend_and_verify_retention_target(anchor, guard, None, &target)
                .await?;
        }
        guard.verify_v2_maintenance(None).await?;
        if anchor.read_v2().await?.is_some() {
            return Err(V2FormatError::StaleAnchor);
        }
        Ok(())
    }

    pub(in crate::v2) async fn protect_recovery_publication<A, G>(
        &self,
        anchor: &A,
        guard: &G,
        capture: &CapturedRecoveryPublication,
        budgets: V2MaintenanceBudgets,
    ) -> V2Result<RecoveryCoverage>
    where
        A: V2CommitAnchor,
        G: V2MaintenanceGuard + ?Sized,
    {
        let base = &capture.publication.parent;
        guard.verify_v2_maintenance(Some(base)).await?;
        if anchor.read_v2().await?.as_ref() != Some(base) {
            return Err(V2FormatError::StaleAnchor);
        }
        if self.provider_profile() != V2ProviderProfile::RetainedVersionObjectLock {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        // Reuse the outage margin. Requiring a newly shifted renewal horizon
        // here would perform a full graph walk on every ordinary write.
        let admission = capture
            .previous
            .policy
            .promised_until_ms(capture.publication.publish_time_ms)?
            .max(
                capture
                    .current_policy
                    .promised_until_ms(capture.publication.publish_time_ms)?,
            );
        let cached = self
            .recovery_coverage
            .read()
            .map_err(|_| V2FormatError::StorageOperationFailed)?
            .clone();
        if let Some(proof) = cached
            && proof.base_anchor == *base
            && proof.protected_until_ms >= admission
        {
            return Ok(proof);
        }

        let budgeted_store = V2MaintenanceBudgetedStore::new(self.store(), budgets);
        let usage_handle = budgeted_store.clone();
        let reader = self.rebind_store(budgeted_store);
        let required = capture.required_coverage_until_ms;
        let result = async {
            let mut graph = reader.load_reachability(anchor, &[], budgets, true).await?;
            if graph.anchor_state.as_ref() != Some(base) {
                return Err(V2FormatError::StaleAnchor);
            }
            let retention = active_retention(self.retention_policy())
                .ok_or(V2FormatError::ProviderProfileFailed)?;
            if !graph
                .renewal_targets
                .values()
                .any(|target| target.current_recovery_dependency)
            {
                return Err(V2FormatError::InvalidRecoveryHistory);
            }
            for target in graph.renewal_targets.values_mut() {
                if target.current_recovery_dependency {
                    target.required_deadline = target.required_deadline.max(Some(required));
                }
                target.required_retention =
                    strongest_retention(target.required_retention, Some(retention));
            }
            reader
                .plan_retention_renewal(
                    graph.renewal_targets.values(),
                    Duration::ZERO,
                    budgets,
                    graph.chain_get_count.saturating_add(graph.graph_head_count),
                    graph.graph_head_count,
                )
                .await
        }
        .await;
        // Drop graph working memory before the potentially slow mutation pass.
        // Preserve the actual metering error even if a decoder mapped the
        // underlying storage failure into a more general format error.
        let usage = usage_handle
            .usage()
            .map_err(|_| V2FormatError::StorageOperationFailed)?;
        if usage.exhausted {
            return Err(V2FormatError::MaintenanceBudgetExceeded);
        }
        let renewal = result?;
        if renewal.blocked_count != 0 {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        let cost = V2MaintenancePlanCost {
            request_count: usage
                .request_count
                .saturating_add(renewal.extend_count.saturating_mul(2)),
            head_count: usage.head_count.saturating_add(renewal.extend_count),
            range_read_bytes: usage.range_read_bytes,
            retention_extend_count: renewal.extend_count,
            ..V2MaintenancePlanCost::default()
        };
        if usage.exhausted || !cost.fits_budgets(budgets) {
            return Err(V2FormatError::MaintenanceBudgetExceeded);
        }
        for target in renewal.targets {
            self.extend_and_verify_retention_target(anchor, guard, Some(base), &target)
                .await?;
        }
        guard.verify_v2_maintenance(Some(base)).await?;
        if anchor.read_v2().await?.as_ref() != Some(base) {
            return Err(V2FormatError::StaleAnchor);
        }
        let proof = RecoveryCoverage {
            base_anchor: base.clone(),
            protected_until_ms: required,
        };
        // Cache loss affects efficiency only; it never converts an incomplete
        // verification into authority or turns an accepted write into failure.
        if let Ok(mut cached) = self.recovery_coverage.write() {
            *cached = Some(proof.clone());
        }
        Ok(proof)
    }

    /// Called only after a complete existing maintenance plan has verified every
    /// current and historical target under its unchanged accepted anchor.
    pub(in crate::v2) fn cache_verified_recovery_coverage(
        &self,
        accepted: &V2AnchorState,
        verified_current_floor_ms: i64,
    ) {
        if let Ok(mut cached) = self.recovery_coverage.write() {
            *cached = (verified_current_floor_ms >= 0).then(|| RecoveryCoverage {
                base_anchor: accepted.clone(),
                protected_until_ms: verified_current_floor_ms,
            });
        }
    }

    pub(in crate::v2) fn advance_recovery_coverage(
        &self,
        inherited: &RecoveryCoverage,
        accepted: &V2AnchorState,
        introduced_floor: i64,
    ) {
        if let Ok(mut cached) = self.recovery_coverage.write() {
            // Exact next ancestry is checked before CAS by the publication path.
            // A caller must install only after that publication is accepted.
            *cached = (accepted.sequence > inherited.base_anchor.sequence
                && accepted.format_ref == inherited.base_anchor.format_ref
                && introduced_floor >= 0)
                .then(|| RecoveryCoverage {
                    base_anchor: accepted.clone(),
                    protected_until_ms: inherited.protected_until_ms.min(introduced_floor),
                });
        }
    }
}
