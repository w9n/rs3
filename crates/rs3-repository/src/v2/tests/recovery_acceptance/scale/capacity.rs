//! Admission boundary tests use the same small budgets before and after restart.
use super::*;

fn options(budgets: V2MaintenanceBudgets, reclaim: bool) -> V2FullGcApplyOptions {
    let mut options = apply_options(reclaim);
    options.dry_run.budgets = budgets;
    options
}

async fn check_graph(scale: &Scale, budgets: V2MaintenanceBudgets) {
    must_v2(
        scale
            .repository
            .commit_store()
            .quick_maintenance_with_options(
                &scale.anchor,
                crate::v2::V2QuickMaintenanceOptions {
                    budgets,
                    ..crate::v2::V2QuickMaintenanceOptions::default()
                },
            )
            .await,
    );
}

async fn fill(
    mode: &'static str,
    budgets: V2MaintenanceBudgets,
) -> (Scale, V2AnchorState, LogicalPath, Bytes) {
    let scale = Scale::with_budgets(mode, budgets).await;
    let coordinator = scale.coordinator();
    let mut last = None;
    for index in 0..200 {
        scale.advance(scale.start + index * 10);
        let key = must_type(LogicalPath::new(format!(
            "capacity/{}",
            if mode == "append" { index } else { 0 }
        )));
        let body = Bytes::from(vec![index as u8; 512]);
        let before = must_v2(scale.anchor.read_v2().await);
        match coordinator
            .put_committed(key.clone(), body.clone(), RepositoryPutOptions::default())
            .await
        {
            Ok(write) => {
                last = Some((write.anchor_state, key, body));
                check_graph(&scale, budgets).await;
            }
            Err(error) => {
                assert!(
                    error.to_string().contains("maintenance budget exceeded"),
                    "{error}"
                );
                assert_eq!(must_v2(scale.anchor.read_v2().await), before);
                assert_eq!(coordinator.pending_item_count_for_tests().await, 0);
                let (anchor, key, body) = last.expect("several writes fit before capacity refusal");
                assert!(anchor.sequence.get() > 3);
                assert_eq!(
                    must_repo(scale.repository.get_range(&key, ByteRange::Full).await),
                    body
                );
                drop(coordinator);
                return (scale, anchor, key, body);
            }
        }
    }
    panic!("growth must encounter the deliberately small capacity limit")
}

#[tokio::test]
async fn recovery_capacity_warm_and_restarted_writers_preserve_maintainable_head() {
    for mode in ["overwrite", "append"] {
        let budgets = V2MaintenanceBudgets {
            max_history_metadata_bytes: 256 * 1024,
            ..V2MaintenanceBudgets::default()
        };
        let (mut scale, last, key, body) = fill(mode, budgets).await;
        scale.restart().await;
        assert_eq!(
            must_repo(scale.repository.get_range(&key, ByteRange::Full).await),
            body
        );
        scale.restore(&last, &key, &body).await;
        check_graph(&scale, budgets).await;
        let coordinator = scale.coordinator();
        let before = must_v2(scale.anchor.read_v2().await);
        let result = coordinator
            .put_committed(
                key.clone(),
                Bytes::from_static(b"must not overflow"),
                RepositoryPutOptions::default(),
            )
            .await;
        // Cache loss may release conservative credit. Either outcome must leave
        // a head that still fits the identical graph and maintenance budgets.
        if result.is_err() {
            assert_eq!(must_v2(scale.anchor.read_v2().await), before);
            assert_eq!(
                must_repo(scale.repository.get_range(&key, ByteRange::Full).await),
                body
            );
        }
        drop(coordinator);
        check_graph(&scale, budgets).await;
        scale.advance(scale.start + 2 * DAY);
        let report = must_v2(
            scale
                .repository
                .commit_store()
                .apply_full_gc(
                    &scale.anchor,
                    &UnenforcedQuiescedMaintenanceGuard,
                    options(budgets, false),
                )
                .await,
        );
        assert!(report.retention_renewed_object_count > 0);
        scale.restore(&last, &key, &body).await;
    }
}

#[tokio::test]
async fn recovery_capacity_exact_target_ceiling_applies_to_cached_growth() {
    let budgets = V2MaintenanceBudgets {
        max_inventory_item_count: 14,
        ..V2MaintenanceBudgets::default()
    };
    let (mut scale, last, key, body) = fill("overwrite", budgets).await;
    scale.restart().await;
    assert_eq!(must_v2(scale.anchor.read_v2().await), Some(last));
    check_graph(&scale, budgets).await;
    assert_eq!(
        must_repo(scale.repository.get_range(&key, ByteRange::Full).await),
        body
    );
    // The reachable-target cap is not a promise that orphan/provider inventory
    // fits the same item cap. Failed candidates are real unanchored versions.
}

#[tokio::test]
async fn recovery_capacity_expiry_releases_credit_and_gc_preserves_current_value() {
    let budgets = V2MaintenanceBudgets {
        max_history_metadata_bytes: 256 * 1024,
        ..V2MaintenanceBudgets::default()
    };
    let (mut scale, selected, key, body) = fill("overwrite", budgets).await;
    // Foreground admission leaves a root publication opportunity. Fold the
    // active runs so expired historical graphs can later become unreachable.
    let coordinator = scale.coordinator();
    must_repo(coordinator.write_index_snapshot().await);
    drop(coordinator);
    must_repo(
        scale
            .repository
            .compact_packed_index_runs(&scale.anchor, &UnenforcedQuiescedMaintenanceGuard)
            .await,
    );
    scale.restart().await;
    scale.restore(&selected, &key, &body).await;
    for day in [2, 30] {
        scale.advance(scale.start + day * DAY);
        must_v2(
            scale
                .repository
                .commit_store()
                .apply_full_gc(
                    &scale.anchor,
                    &UnenforcedQuiescedMaintenanceGuard,
                    options(budgets, false),
                )
                .await,
        );
    }
    scale.advance(scale.start + 35 * DAY);
    let coordinator = scale.coordinator();
    // The full candidate fallback must release expired credit instead of
    // treating the conservative parent estimate as a permanent refusal.
    must_repo(coordinator.write_index_snapshot().await);
    assert!(
        scale
            .repository
            .open_recovery_point(&scale.anchor, selected.sequence)
            .await
            .is_err()
    );
    must_repo(
        coordinator
            .put_committed(key.clone(), body.clone(), RepositoryPutOptions::default())
            .await,
    );
    drop(coordinator);
    check_graph(&scale, budgets).await;
    must_v2(
        scale
            .repository
            .commit_store()
            .apply_full_gc(
                &scale.anchor,
                &UnenforcedQuiescedMaintenanceGuard,
                options(budgets, true),
            )
            .await,
    );
    let unlock = scale.backend.latest_deadline();
    scale.advance(unlock - DAY / 2);
    must_v2(
        scale
            .repository
            .commit_store()
            .apply_full_gc(
                &scale.anchor,
                &UnenforcedQuiescedMaintenanceGuard,
                options(budgets, false),
            )
            .await,
    );
    scale.advance(unlock + 1);
    let reclaimed = must_v2(
        scale
            .repository
            .commit_store()
            .apply_full_gc(
                &scale.anchor,
                &UnenforcedQuiescedMaintenanceGuard,
                options(budgets, true),
            )
            .await,
    );
    assert!(reclaimed.orphan_gc.deleted_count > 0);
    scale.restart().await;
    assert_eq!(
        must_repo(scale.repository.get_range(&key, ByteRange::Full).await),
        body
    );
    check_graph(&scale, budgets).await;
}

#[tokio::test]
async fn recovery_capacity_root_and_compaction_refusal_leave_authority_unchanged() {
    let budgets = V2MaintenanceBudgets {
        max_inventory_item_count: 14,
        ..V2MaintenanceBudgets::default()
    };
    let (scale, _, key, body) = fill("overwrite", budgets).await;
    let coordinator = scale.coordinator();
    // One target is reserved for a root. A second nonreducing root cannot
    // silently advance beyond the hard cap through the common verification hook.
    must_repo(coordinator.write_index_snapshot().await);
    let before = must_v2(scale.anchor.read_v2().await);
    let error = coordinator
        .write_index_snapshot()
        .await
        .expect_err("root target ceiling");
    assert!(error.to_string().contains("maintenance budget exceeded"));
    assert_eq!(must_v2(scale.anchor.read_v2().await), before);
    drop(coordinator);
    let error = scale
        .repository
        .compact_packed_index_runs(&scale.anchor, &UnenforcedQuiescedMaintenanceGuard)
        .await
        .expect_err("new compaction sibling and root exceed target ceiling");
    assert!(error.to_string().contains("maintenance budget exceeded"));
    assert_eq!(must_v2(scale.anchor.read_v2().await), before);
    assert_eq!(
        must_repo(scale.repository.get_range(&key, ByteRange::Full).await),
        body
    );
    let graph = must_v2(
        scale
            .repository
            .commit_store()
            .recovery_mark_for_tests(&scale.anchor, budgets)
            .await,
    );
    // The graph-only observer omits the fixture's two restore envelopes.
    // Quick reporting also inventories the failed candidate uploads, which is
    // intentionally outside this reachable-target admission guarantee.
    assert!(graph.targets.len() as u64 + 2 <= budgets.max_inventory_item_count);
}

struct LoseGuardDuringCandidate {
    store: ScaleStore,
    get_threshold: u64,
}

#[async_trait::async_trait]
impl V2MaintenanceGuard for LoseGuardDuringCandidate {
    async fn verify_v2_maintenance(
        &self,
        _base: Option<&V2AnchorState>,
    ) -> crate::v2::V2Result<()> {
        if self.store.operation_counts().expect("counts").get > self.get_threshold {
            return Err(crate::v2::V2FormatError::MaintenanceAccessRequired);
        }
        Ok(())
    }
}

#[tokio::test]
async fn recovery_capacity_guard_loss_during_candidate_walk_never_installs_credit() {
    let scale = Scale::new("overwrite").await;
    let key = must_type(LogicalPath::new("capacity/guard"));
    let body = Bytes::from_static(b"accepted");
    let coordinator = scale.coordinator();
    for _ in 0..8 {
        must_repo(
            coordinator
                .put_committed(key.clone(), body.clone(), RepositoryPutOptions::default())
                .await,
        );
    }
    drop(coordinator);
    // Keep verified retention coverage, but force the next candidate through a
    // complete capacity traversal. Ordinary successor verification uses<=6 GETs.
    *scale
        .repository
        .commit_store()
        .recovery_capacity
        .write()
        .expect("capacity cache") = None;
    let before = must_v2(scale.anchor.read_v2().await);
    let threshold = scale.counts().get + 12;
    let coordinator = must_repo(V2CommitCoordinator::with_options(
        Arc::clone(&scale.repository),
        scale.anchor.clone(),
        CommitCoordinatorOptions::new(1, Duration::ZERO),
    ))
    .with_maintenance_guard(LoseGuardDuringCandidate {
        store: scale.store.clone(),
        get_threshold: threshold,
    });
    let error = coordinator
        .put_committed(
            key.clone(),
            Bytes::from_static(b"refused"),
            RepositoryPutOptions::default(),
        )
        .await
        .expect_err("guard is lost during the full candidate walk");
    assert!(error.to_string().contains("maintenance"), "{error}");
    assert!(scale.counts().get > threshold);
    assert_eq!(must_v2(scale.anchor.read_v2().await), before);
    assert!(
        scale
            .repository
            .commit_store()
            .recovery_capacity
            .read()
            .expect("capacity cache")
            .is_none()
    );
    assert_eq!(coordinator.pending_item_count_for_tests().await, 0);
    assert_eq!(
        must_repo(scale.repository.get_range(&key, ByteRange::Full).await),
        body
    );
    drop(coordinator);
    let coordinator = scale.coordinator();
    must_repo(
        coordinator
            .put_committed(key.clone(), body.clone(), RepositoryPutOptions::default())
            .await,
    );
    assert!(
        scale
            .repository
            .commit_store()
            .recovery_capacity
            .read()
            .expect("capacity cache")
            .is_some()
    );
    check_graph(&scale, V2MaintenanceBudgets::default()).await;
}
