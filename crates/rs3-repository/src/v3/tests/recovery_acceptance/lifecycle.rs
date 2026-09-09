use super::*;

async fn apply(fixture: &Fixture, reclaim: bool) -> crate::v3::V3FullGcApplyReport {
    must_v3(
        fixture
            .repository
            .commit_store()
            .apply_full_gc(
                &fixture.anchor,
                &UnenforcedQuiescedMaintenanceGuard,
                apply_options(reclaim),
            )
            .await,
    )
}

async fn carrier(fixture: &Fixture, anchor: &V3AnchorState) -> BlobMetadata {
    fixture
        .store
        .head_at(&anchor.commit_key, anchor.version_id.as_ref())
        .await
        .expect("exact carrier")
}

#[tokio::test]
async fn recovery_acceptance_old_current_data_gets_full_supersession_window_and_decoded_restore() {
    let policy = RecoveryPolicy::PRESET;
    let mut fixture = Fixture::new(policy).await;
    let start = fixture.store.inner().now();
    let original = fixture
        .put("acceptance/aged", b"original bytes surviving creation age")
        .await;
    let created_deadline = carrier(&fixture, &original)
        .await
        .retain_until_ms
        .expect("physical deadline");

    for day in [20, 35] {
        fixture.advance_to(start + day * DAY);
        let report = apply(&fixture, false).await;
        assert!(
            report.retention_renewed_object_count > 0,
            "quiet current dependency must renew"
        );
        assert_eq!(report.orphan_gc.deleted_count, 0);
        assert!(
            carrier(&fixture, &original)
                .await
                .retain_until_ms
                .expect("renewed deadline")
                > created_deadline
        );
        assert_eq!(
            must_repo(
                fixture
                    .repository
                    .get_range(
                        &must_type(LogicalPath::new("acceptance/aged")),
                        ByteRange::Full
                    )
                    .await
            ),
            Bytes::from_static(b"original bytes surviving creation age")
        );
    }
    assert!(
        fixture.store.inner().now() > created_deadline,
        "current value survived its initial physical coverage"
    );

    fixture.advance_to(start + 40 * DAY);
    let reduced = must_v3(RecoveryPolicy::new(1, 120, 60_000));
    fixture.restart(reduced).await;
    let replacement = fixture.put("acceptance/aged", b"replacement bytes").await;
    let chain = must_v3(
        fixture
            .repository
            .commit_store()
            .load_replay_chain_from_state(&replacement)
            .await,
    );
    let history = must_v3(
        fixture
            .repository
            .commit_store()
            .replay_recovery_history(&chain),
    )
    .expect("accepted history");
    let point = history
        .snapshot
        .tail
        .iter()
        .find(|point| point.anchor == original)
        .expect("original point remains registered");
    let superseded_at = chain.commits_newest_first[0]
        .parsed_header
        .header
        .publish_time_ms;
    assert_eq!(
        point.protected_until_ms,
        must_v3(policy.promised_until_ms(superseded_at))
    );
    assert!(
        carrier(&fixture, &original)
            .await
            .retain_until_ms
            .expect("physical promise")
            >= point.protected_until_ms
    );
    fixture.delete("acceptance/aged").await;
    assert!(
        fixture
            .repository
            .head(&must_type(LogicalPath::new("acceptance/aged")))
            .is_err()
    );

    fixture.advance_to(start + 69 * DAY);
    fixture.restart(reduced).await;
    let runs = must_repo(fixture.repository.active_index_run_count());
    assert!(runs > 1);
    must_repo(
        fixture
            .repository
            .compact_packed_index_runs(&fixture.anchor, &UnenforcedQuiescedMaintenanceGuard)
            .await,
    );
    assert!(
        must_repo(fixture.repository.active_index_run_count()) < runs,
        "actual index-run compaction occurred"
    );
    fixture.restart(reduced).await;
    fixture
        .restore(
            &original,
            "acceptance/aged",
            b"original bytes surviving creation age",
        )
        .await;
}

#[tokio::test]
async fn recovery_acceptance_disabled_reclamation_renews_and_acknowledges_logical_delete() {
    let fixture = Fixture::new(RecoveryPolicy::PRESET).await;
    let original = fixture
        .put("acceptance/disabled", b"retained logical deletion")
        .await;
    let initial_floor = carrier(&fixture, &original)
        .await
        .retain_until_ms
        .expect("initial floor");
    let orphan = fixture.orphan(900, None).await;
    fixture.advance_to(fixture.store.inner().now() + 2 * DAY);
    let baseline = fixture.store.inner().events().len();
    let report = apply(&fixture, false).await;
    assert!(report.retention_renewed_object_count > 0);
    assert_eq!(report.orphan_gc.deleted_count, 0);
    assert!(
        carrier(&fixture, &original)
            .await
            .retain_until_ms
            .expect("renewed exact floor")
            > initial_floor
    );
    let events = fixture.store.inner().events();
    assert!(events[baseline..].iter().any(|event| matches!(event, Mutation::Extend(metadata) if metadata.object_id == original.commit_key && metadata.version_id == original.version_id)));
    assert!(
        !events[baseline..]
            .iter()
            .any(|event| matches!(event, Mutation::Delete(_)))
    );
    fixture.delete("acceptance/disabled").await;
    assert!(
        fixture
            .repository
            .head(&must_type(LogicalPath::new("acceptance/disabled")))
            .is_err()
    );
    fixture
        .restore(
            &original,
            "acceptance/disabled",
            b"retained logical deletion",
        )
        .await;
    assert!(
        fixture
            .store
            .head_at(&orphan.object_id, orphan.version_id.as_ref())
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn recovery_acceptance_expiry_reclaims_only_unlocked_unreachable_exact_carriers() {
    let mut fixture = Fixture::new(RecoveryPolicy::PRESET).await;
    for (path, bytes) in [
        ("acceptance/shared-dead", b"shared first".as_slice()),
        ("acceptance/shared-live", b"shared second".as_slice()),
    ] {
        must_repo(
            fixture
                .repository
                .stage_put(
                    must_type(LogicalPath::new(path)),
                    Bytes::from_static(bytes),
                    RepositoryPutOptions::default(),
                )
                .await,
        );
    }
    must_repo(
        fixture
            .repository
            .publish_pending_index_delta(&fixture.anchor, Some(&UnenforcedQuiescedMaintenanceGuard))
            .await,
    );
    let shared = fixture.current().await;
    let dead = fixture
        .put("acceptance/entirely-dead", b"separate historical carrier")
        .await;
    fixture.delete("acceptance/shared-dead").await;
    fixture.delete("acceptance/entirely-dead").await;
    must_repo(
        fixture
            .repository
            .compact_packed_index_runs(&fixture.anchor, &UnenforcedQuiescedMaintenanceGuard)
            .await,
    );
    let held = fixture.orphan(901, Some(LegalHoldStatus::On)).await;
    let dead_floor = carrier(&fixture, &dead)
        .await
        .retain_until_ms
        .expect("historical floor");

    // A late point has its own full promise beyond the earlier carrier's expiry.
    fixture.advance_to(dead_floor - DAY);
    let later = fixture
        .put(
            "acceptance/later-point",
            b"another point still needs this carrier",
        )
        .await;
    fixture.delete("acceptance/later-point").await;
    must_repo(
        fixture
            .repository
            .compact_packed_index_runs(&fixture.anchor, &UnenforcedQuiescedMaintenanceGuard)
            .await,
    );
    // Publication may conservatively extend dependencies of the predecessor
    // root. Observe the actual deadline instead of assuming logical expiry
    // alone is sufficient for physical eligibility.
    let dead_floor = carrier(&fixture, &dead)
        .await
        .retain_until_ms
        .expect("final old floor");
    fixture.advance_to(dead_floor + 1);
    fixture.expire().await;
    let chain = must_v3(
        fixture
            .repository
            .commit_store()
            .load_replay_chain_from_state(&fixture.current().await)
            .await,
    );
    let history = must_v3(
        fixture
            .repository
            .commit_store()
            .replay_recovery_history(&chain),
    )
    .expect("authenticated expiry");
    assert!(history.snapshot.expire_before_ms > 0);
    assert!(
        !history
            .snapshot
            .tail
            .iter()
            .any(|point| point.anchor == dead),
        "ordinary successor or expiry checkpoint authenticated the old point's expiry"
    );
    let report = apply(&fixture, true).await;
    assert!(
        report.orphan_gc.deleted_count > 0,
        "positive history-driven reclamation"
    );
    assert!(fixture.store.inner().events().iter().any(|event| matches!(event, Mutation::Delete(metadata) if metadata.object_id == dead.commit_key && metadata.version_id == dead.version_id)), "provider deleted the exact expired historical carrier");
    assert!(
        matches!(
            fixture
                .store
                .head_at(&dead.commit_key, dead.version_id.as_ref())
                .await,
            Err(StorageError::NotFound(_))
        ),
        "expired historical-only carrier was physically removed"
    );
    assert!(
        fixture
            .store
            .head_at(&shared.commit_key, shared.version_id.as_ref())
            .await
            .is_ok(),
        "partially live shared pack survives"
    );
    assert!(
        fixture
            .store
            .head_at(&held.object_id, held.version_id.as_ref())
            .await
            .is_ok(),
        "On hold survives"
    );
    fixture
        .restore(
            &later,
            "acceptance/later-point",
            b"another point still needs this carrier",
        )
        .await;
    assert_eq!(
        must_repo(
            fixture
                .repository
                .get_range(
                    &must_type(LogicalPath::new("acceptance/shared-live")),
                    ByteRange::Full
                )
                .await
        ),
        Bytes::from_static(b"shared second")
    );

    fixture.delete("acceptance/shared-live").await;
    must_repo(
        fixture
            .repository
            .compact_packed_index_runs(&fixture.anchor, &UnenforcedQuiescedMaintenanceGuard)
            .await,
    );
    let shared_floor = carrier(&fixture, &shared)
        .await
        .retain_until_ms
        .expect("last shared promise floor");
    fixture.advance_to(shared_floor + 2 * DAY);
    assert!(
        fixture.expire().await,
        "final shared promise publishes an expiry checkpoint"
    );
    // Preparing the expiry successor protects its still-authoritative parent
    // registry before CAS. That may safely extend a soon-expired historical
    // dependency once more. Logical expiry alone cannot bypass this observed
    // provider floor; let it elapse without publishing another successor.
    let final_physical_floor = carrier(&fixture, &shared)
        .await
        .retain_until_ms
        .expect("post-expiry provider deadline");
    fixture.advance_to(fixture.store.inner().now().max(final_physical_floor + 1));
    let report = apply(&fixture, true).await;
    assert!(
        report.orphan_gc.deleted_count > 0,
        "final shared reclamation: {report:?}; shared={:?}",
        carrier(&fixture, &shared).await
    );
    assert!(
        matches!(
            fixture
                .store
                .head_at(&shared.commit_key, shared.version_id.as_ref())
                .await,
            Err(StorageError::NotFound(_))
        ),
        "shared pack releases only after its final live and historical dependencies end"
    );
    assert!(
        fixture
            .store
            .head_at(&held.object_id, held.version_id.as_ref())
            .await
            .is_ok()
    );
    fixture.restart(RecoveryPolicy::PRESET).await;
    assert!(
        fixture
            .repository
            .head(&must_type(LogicalPath::new("acceptance/shared-live")))
            .is_err()
    );
}
