use super::*;

#[tokio::test]
async fn recovery_acceptance_reviewed_plan_survives_same_bucket_time_with_zero_and_due_renewal() {
    for due in [false, true] {
        let fixture = Fixture::new(RecoveryPolicy::PRESET).await;
        fixture
            .put(
                "acceptance/reviewed-plan",
                b"live bytes under reviewed maintenance",
            )
            .await;
        let noon = (fixture.store.inner().now() / DAY + 1) * DAY + DAY / 2;
        fixture.advance_to(noon);
        must_v2(
            fixture
                .repository
                .commit_store()
                .apply_full_gc(
                    &fixture.anchor,
                    &UnenforcedQuiescedMaintenanceGuard,
                    apply_options(false),
                )
                .await,
        );
        if due {
            fixture.advance_to(noon + 2 * DAY);
        }
        let orphan = fixture.orphan(if due { 932 } else { 931 }, None).await;
        let preview = must_repo(
            fixture
                .repository
                .preview_full_gc_plan(&fixture.anchor, apply_options(true))
                .await,
        );
        assert_eq!(
            preview.report.retention_renewal_commit_count > 0,
            due,
            "exercise both empty and nonempty renewal target plans"
        );
        let anchor = fixture.current().await;
        fixture.advance_to(fixture.store.inner().now() + 10_000);
        let applied = must_repo(
            fixture
                .repository
                .apply_full_gc_quiesced_expected(
                    &fixture.anchor,
                    &UnenforcedQuiescedMaintenanceGuard,
                    apply_options(true),
                    Some(&preview.plan_digest),
                    &V2MaintenanceCancellation::new(),
                )
                .await,
        );
        assert_eq!(applied.apply.retention_renewed_object_count > 0, due);
        assert_eq!(applied.apply.orphan_gc.deleted_count, 1);
        assert!(matches!(
            fixture
                .store
                .head_at(&orphan.object_id, orphan.version_id.as_ref())
                .await,
            Err(StorageError::NotFound(_))
        ));
        assert_eq!(fixture.current().await, anchor);
    }
}

#[tokio::test]
async fn recovery_acceptance_ambiguous_renewal_prevents_deletion_and_retry_is_safe() {
    let fixture = Fixture::new(RecoveryPolicy::PRESET).await;
    let original = fixture
        .put("acceptance/ambiguous", b"live during ambiguous renewal")
        .await;
    let orphan = fixture.orphan(920, None).await;
    fixture.advance_to(fixture.store.inner().now() + 2 * DAY);
    let before = fixture.current().await;
    let baseline = fixture.store.inner().events().len();
    let before_inventory = fixture
        .store
        .list_prefix_versions("")
        .await
        .expect("pre-renewal exact inventory");
    fixture
        .store
        .push_rule(FaultRule::new(
            FaultMatcher::operation(FaultOperationKind::ExtendRetentionAt),
            FaultAction::error_after_write("lost renewal response"),
        ))
        .expect("one-shot ambiguity");
    let result = fixture
        .repository
        .commit_store()
        .apply_full_gc(
            &fixture.anchor,
            &UnenforcedQuiescedMaintenanceGuard,
            apply_options(true),
        )
        .await;
    assert!(matches!(result, Err(V2FormatError::StorageOperationFailed)));
    let events = fixture.store.inner().events();
    let [Mutation::Extend(extended)] = &events[baseline..] else {
        panic!("exactly one actual extension, no delete, before lost response")
    };
    let actual = fixture
        .store
        .head_at(&extended.object_id, extended.version_id.as_ref())
        .await
        .expect("extension really persisted");
    assert_eq!(actual.retain_until_ms, extended.retain_until_ms);
    let prior = before_inventory
        .iter()
        .find(|metadata| {
            metadata.object_id == extended.object_id && metadata.version_id == extended.version_id
        })
        .expect("same exact version before renewal");
    assert!(
        actual.retain_until_ms > prior.retain_until_ms,
        "ambiguous operation really strengthened its previous exact deadline"
    );
    assert!(actual.retain_until_ms.expect("deadline") > fixture.store.inner().now() + 30 * DAY);
    assert_eq!(fixture.current().await, before);
    assert!(
        fixture
            .store
            .head_at(&orphan.object_id, orphan.version_id.as_ref())
            .await
            .is_ok()
    );

    let retry = must_v2(
        fixture
            .repository
            .commit_store()
            .apply_full_gc(
                &fixture.anchor,
                &UnenforcedQuiescedMaintenanceGuard,
                apply_options(true),
            )
            .await,
    );
    assert!(retry.retention_renewed_object_count > 0);
    assert_eq!(retry.orphan_gc.deleted_count, 1);
    assert!(matches!(
        fixture
            .store
            .head_at(&orphan.object_id, orphan.version_id.as_ref())
            .await,
        Err(StorageError::NotFound(_))
    ));
    fixture
        .restore(
            &original,
            "acceptance/ambiguous",
            b"live during ambiguous renewal",
        )
        .await;
}

#[tokio::test]
async fn recovery_acceptance_interrupted_renewal_and_stale_history_plan_cannot_delete() {
    let mut fixture = Fixture::new(RecoveryPolicy::PRESET).await;
    fixture.put("acceptance/stale", b"initial bytes").await;
    let orphan = fixture.orphan(921, None).await;
    fixture.advance_to(fixture.store.inner().now() + 2 * DAY);
    let prepared = must_v2(
        fixture
            .repository
            .commit_store()
            .prepare_full_gc_plan(&fixture.anchor, apply_options(true))
            .await,
    );
    assert!(prepared.report().retention_renewal_commit_count > 1);
    let baseline = fixture.store.inner().events().len();
    // Two checks enter apply, then one precedes the first renewal. Lose the
    // fence between exact-version targets after one real extension succeeded.
    let guard = FailsAfterMaintenanceGuard::new(3);
    let interrupted = fixture
        .repository
        .commit_store()
        .apply_prepared_full_gc_cancellable(
            &fixture.anchor,
            &guard,
            prepared,
            &V2MaintenanceCancellation::new(),
        )
        .await;
    assert!(matches!(
        interrupted,
        Err(V2FormatError::MaintenanceAccessRequired)
    ));
    assert!(
        matches!(
            &fixture.store.inner().events()[baseline..],
            [Mutation::Extend(_)]
        ),
        "interruption occurred after one successful extension"
    );
    assert!(
        !fixture.store.inner().events()[baseline..]
            .iter()
            .any(|event| matches!(event, Mutation::Delete(_)))
    );
    assert!(
        fixture
            .store
            .head_at(&orphan.object_id, orphan.version_id.as_ref())
            .await
            .is_ok()
    );

    let stale = must_v2(
        fixture
            .repository
            .commit_store()
            .prepare_full_gc_plan(&fixture.anchor, apply_options(true))
            .await,
    );
    fixture
        .restart(must_v2(RecoveryPolicy::new(1, 120, 60_000)))
        .await;
    fixture
        .put(
            "acceptance/stale",
            b"accepted successor with reduced policy",
        )
        .await;
    let new_authority = fixture.current().await;
    let baseline = fixture.store.inner().events().len();
    let rejected = fixture
        .repository
        .commit_store()
        .apply_prepared_full_gc_cancellable(
            &fixture.anchor,
            &UnenforcedQuiescedMaintenanceGuard,
            stale,
            &V2MaintenanceCancellation::new(),
        )
        .await;
    assert!(matches!(rejected, Err(V2FormatError::StaleAnchor)));
    assert_eq!(
        fixture.store.inner().events().len(),
        baseline,
        "stale authenticated base rejects before any renewal or delete"
    );
    assert_eq!(fixture.current().await, new_authority);
    assert!(
        fixture
            .store
            .head_at(&orphan.object_id, orphan.version_id.as_ref())
            .await
            .is_ok()
    );
    let retry = must_v2(
        fixture
            .repository
            .commit_store()
            .apply_full_gc(
                &fixture.anchor,
                &UnenforcedQuiescedMaintenanceGuard,
                apply_options(true),
            )
            .await,
    );
    assert_eq!(retry.orphan_gc.deleted_count, 1);
}
