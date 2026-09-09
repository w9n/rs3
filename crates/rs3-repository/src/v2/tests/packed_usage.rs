use super::*;
use crate::v2::{RecoveryPolicy, V2QuickMaintenanceOptions};

async fn mixed_pack(history: bool) {
    let store = CountingBlobStore::new(MemoryBlobStore::new());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    )
    .with_recovery_policy(history.then_some(RecoveryPolicy::PRESET));
    let repository = Arc::new(V2Repository::new(
        store.clone(),
        must_crypto(KeyRing::generate_random()),
        RepositoryOptions::default(),
        options,
    ));
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    let first = must_type(LogicalPath::new("accounting/first"));
    let second = must_type(LogicalPath::new("accounting/second"));
    for (key, len) in [(first.clone(), 100), (second.clone(), 200)] {
        must_repo(
            repository
                .stage_put(
                    key,
                    Bytes::from(vec![7; len]),
                    RepositoryPutOptions::default(),
                )
                .await,
        );
    }
    must_repo(repository.publish_pending_index_delta(&anchor, None).await);
    let report = must_v2(repository.commit_store().quick_maintenance(&anchor).await);
    // Each small record has one 16-byte authentication tag. Headers and
    // encrypted index sections are outside the measured pack section.
    assert_eq!(report.packed_payload_stored_bytes, 332);
    assert_eq!(report.packed_payload_referenced_bytes, 332);

    let coordinator = must_repo(V2CommitCoordinator::with_options(
        Arc::clone(&repository),
        anchor.clone(),
        CommitCoordinatorOptions::new(1, Duration::ZERO),
    ))
    .with_maintenance_guard(UnenforcedQuiescedMaintenanceGuard);
    must_repo(
        coordinator
            .copy_committed(
                second.clone(),
                must_type(LogicalPath::new("accounting/alias")),
                crate::RepositoryCopyOptions::default(),
            )
            .await,
    );
    let alias_report = must_v2(repository.commit_store().quick_maintenance(&anchor).await);
    assert_eq!(alias_report.packed_payload_stored_bytes, 332);
    assert_eq!(alias_report.packed_payload_referenced_bytes, 332);

    must_repo(coordinator.delete_committed(first).await);
    must_repo(coordinator.write_index_snapshot().await);
    let report = must_v2(repository.commit_store().quick_maintenance(&anchor).await);
    assert_eq!(report.packed_payload_stored_bytes, 332);
    assert_eq!(
        report.packed_payload_referenced_bytes,
        if history { 332 } else { 216 },
        "a history-protected record is not reported as unreferenced ciphertext"
    );
    let mut io = Vec::new();
    for enabled in [false, true] {
        let before = store.operation_counts().expect("counts");
        let totals = must_v2(
            repository
                .commit_store()
                .packed_usage_mark_for_tests(&anchor, enabled)
                .await,
        );
        if enabled {
            assert_eq!(totals, (332, if history { 332 } else { 216 }));
        }
        let after = store.operation_counts().expect("counts");
        io.push((
            after.get - before.get,
            after.head - before.head,
            after.list - before.list,
            after.bytes_read - before.bytes_read,
            after.put - before.put,
            after.delete - before.delete,
            after.extend_retention - before.extend_retention,
        ));
    }
    assert_eq!(
        io[0], io[1],
        "accounting adds neither requests nor read bytes"
    );
    must_repo(coordinator.delete_committed(second).await);
    must_repo(
        coordinator
            .delete_committed(must_type(LogicalPath::new("accounting/alias")))
            .await,
    );
    let report = must_v2(repository.commit_store().quick_maintenance(&anchor).await);
    assert_eq!(
        report.packed_payload_stored_bytes,
        if history { 332 } else { 0 }
    );
    assert_eq!(
        report.packed_payload_referenced_bytes,
        if history { 332 } else { 0 }
    );
}

#[tokio::test]
async fn packed_usage_counts_mixed_ciphertext_and_deduplicates_copy_aliases() {
    mixed_pack(false).await;
}

#[tokio::test]
async fn packed_usage_includes_protected_history_without_duplicate_record_bytes() {
    mixed_pack(true).await;
}

#[tokio::test]
async fn packed_usage_budget_exhaustion_returns_no_partial_report() {
    let repository = V2Repository::new(
        MemoryBlobStore::new(),
        must_crypto(KeyRing::generate_random()),
        RepositoryOptions::default(),
        V2CommitStoreOptions::for_profile(
            V2ProviderProfile::Dev,
            sample_repository_id(),
            sample_keyring_envelope_ref(),
            sample_format_ref(),
        ),
    );
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(
        repository
            .put_committed(
                &anchor,
                must_type(LogicalPath::new("accounting/bounded")),
                Bytes::from_static(b"payload"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    let error = repository
        .commit_store()
        .quick_maintenance_with_options(
            &anchor,
            V2QuickMaintenanceOptions {
                budgets: V2MaintenanceBudgets {
                    max_history_metadata_bytes: 0,
                    ..V2MaintenanceBudgets::default()
                },
                ..V2QuickMaintenanceOptions::default()
            },
        )
        .await
        .expect_err("packed bookkeeping must honor the byte budget without history");
    assert_eq!(error, V2FormatError::MaintenanceBudgetExceeded);
    assert!(
        repository
            .commit_store()
            .report_orphans(&anchor)
            .await
            .is_ok()
    );
}
