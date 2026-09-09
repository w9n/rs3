//! Opt-in growth experiment using production algorithms and a controlled provider.
//! Run one workload per process: RSS includes the in-memory provider and test driver.
use super::*;
use rs3_storage::BlobOperationCounts;
use serde_json::json;
use std::time::Instant;

mod capacity;
mod inventory;

type ScaleStore = CountingBlobStore<ControlledDeadlineStore>;

struct Scale {
    backend: ControlledDeadlineStore,
    store: ScaleStore,
    repository: Arc<V2Repository<ScaleStore>>,
    anchor: V2MemoryAnchor,
    start: i64,
    mode: &'static str,
}

impl Scale {
    async fn new(mode: &'static str) -> Self {
        Self::with_budgets(mode, V2MaintenanceBudgets::default()).await
    }

    async fn with_budgets(mode: &'static str, budgets: V2MaintenanceBudgets) -> Self {
        let start = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_millis(),
        )
        .expect("timestamp");
        let backend = ControlledDeadlineStore::for_scale(start);
        let store = CountingBlobStore::new(backend.clone());
        let options = commit_store_options_with_maintenance_roots(
            &store,
            V2ProviderProfile::RetainedVersionObjectLock,
            Some(RetentionPolicy::new(RetentionMode::Compliance, 1)),
        )
        .await
        .with_recovery_policy(Some(RecoveryPolicy::PRESET))
        .with_recovery_maintenance_budgets(budgets);
        let repository = Arc::new(V2Repository::new(
            store.clone(),
            must_crypto(KeyRing::generate_random()),
            RepositoryOptions::default(),
            options,
        ));
        repository
            .commit_store()
            .set_publication_time_for_tests(start);
        let anchor = V2MemoryAnchor::new();
        must_repo(
            repository
                .write_genesis_snapshot_with_guard(
                    &anchor,
                    Some(&UnenforcedQuiescedMaintenanceGuard),
                )
                .await,
        );
        Self {
            backend,
            store,
            repository,
            anchor,
            start,
            mode,
        }
    }

    fn coordinator(&self) -> V2CommitCoordinator<ScaleStore, V2MemoryAnchor> {
        must_repo(V2CommitCoordinator::with_options(
            Arc::clone(&self.repository),
            self.anchor.clone(),
            CommitCoordinatorOptions::new(1, Duration::ZERO),
        ))
        .with_maintenance_guard(UnenforcedQuiescedMaintenanceGuard)
    }

    fn advance(&self, now: i64) {
        self.backend.advance_to(now);
        self.repository
            .commit_store()
            .set_publication_time_for_tests(now);
    }

    fn counts(&self) -> BlobOperationCounts {
        self.store.operation_counts().expect("operation counts")
    }

    async fn record(
        &self,
        phase: &str,
        writes: usize,
        since: Instant,
        before: &BlobOperationCounts,
        outcome: &str,
    ) {
        let after = self.counts();
        let (versions, stored_bytes) = self.backend.occupancy();
        let sequence = must_v2(self.anchor.read_v2().await)
            .expect("anchor")
            .sequence
            .get();
        println!(
            "HISTORY_SCALE {}",
            json!({
                "schema": 1, "mode": self.mode, "phase": phase, "writes": writes,
                "sequence": sequence, "outcome": outcome, "elapsed_ms": since.elapsed().as_millis(),
                "stored_versions": versions, "stored_bytes": stored_bytes,
                "process_rss_bytes": proc_memory("VmRSS:"),
                "process_peak_rss_bytes": proc_memory("VmHWM:"),
                "put": after.put - before.put, "get": after.get - before.get,
                "head": after.head - before.head, "list": after.list - before.list,
                "delete": after.delete - before.delete,
                "extend_retention": after.extend_retention - before.extend_retention,
            "bytes_read": after.bytes_read - before.bytes_read,
            "bytes_written": after.bytes_written - before.bytes_written,
            "cumulative": { "put":after.put, "get":after.get, "head":after.head,
                "list":after.list, "delete":after.delete, "extend_retention":after.extend_retention,
                "bytes_read":after.bytes_read, "bytes_written":after.bytes_written },
            })
        );
    }

    async fn restore(&self, selected: &V2AnchorState, key: &LogicalPath, expected: &[u8]) {
        let before = must_v2(self.anchor.read_v2().await);
        let view = must_repo(
            self.repository
                .open_recovery_point(&self.anchor, selected.sequence)
                .await,
        );
        let object = must_repo(view.resolve_object(key));
        assert_eq!(
            must_repo(view.get_resolved_range(&object, ByteRange::Full).await).as_ref(),
            expected
        );
        assert_eq!(
            must_v2(self.anchor.read_v2().await),
            before,
            "restore cannot change authority"
        );
    }

    async fn restart(&mut self) {
        let repository = Arc::new(V2Repository::new(
            self.store.clone(),
            self.repository.commit_store().keyring().clone(),
            RepositoryOptions::default(),
            self.repository.commit_store().options().clone(),
        ));
        repository
            .commit_store()
            .set_publication_time_for_tests(self.backend.now());
        self.repository = repository;
        // Drop the old namespace before replay; do not measure two live readers.
        must_repo(self.repository.load_chain_from_anchor(&self.anchor).await);
    }
}

fn proc_memory(field: &str) -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find(|line| line.starts_with(field))?
        .split_whitespace()
        .nth(1)?
        .parse::<u64>()
        .ok()?
        .checked_mul(1024)
}

async fn run(mode: &'static str, writes: usize, budgets: V2MaintenanceBudgets) {
    assert!((4..=1_000_000).contains(&writes));
    let mut scale = Scale::with_budgets(mode, budgets).await;
    println!(
        "HISTORY_SCALE {}",
        json!({"phase":"configuration", "mode":mode,
        "writes":writes, "history_metadata_budget_bytes":budgets.max_history_metadata_bytes,
        "history_pending_budget_bytes":budgets.max_history_pending_bytes})
    );
    let coordinator = scale.coordinator();
    let mut samples = Vec::new();
    let mut since = Instant::now();
    let mut before = scale.counts();
    for index in 0..writes {
        scale.advance(scale.start + i64::try_from(index).expect("index") * 10);
        let key = must_type(LogicalPath::new(format!(
            "scale/{:020}",
            if mode == "append" { index } else { 0 }
        )));
        let body = Bytes::from(vec![u8::try_from(index % 251).expect("byte"); 512]);
        let result = coordinator
            .put_committed(key.clone(), body.clone(), RepositoryPutOptions::default())
            .await;
        if let Err(error) = &result {
            scale
                .record("growth", index, since, &before, &error.to_string())
                .await;
        }
        let accepted = must_repo(result);
        if index == 0 || index == writes / 2 || index == writes - 1 {
            samples.push((accepted.anchor_state, key, body));
        }
        if (index + 1) % 1000 == 0 || index + 1 == writes {
            scale
                .record("growth", index + 1, since, &before, "ok")
                .await;
            since = Instant::now();
            before = scale.counts();
        }
    }
    // Delete the latest selected value so historical restore tests cover deletion.
    must_repo(
        coordinator
            .delete_committed(samples.last().expect("latest").1.clone())
            .await,
    );
    must_repo(coordinator.write_index_snapshot().await);
    drop(coordinator);
    // Fold remaining runs so current reachability need not keep dead foreground runs.
    must_repo(
        scale
            .repository
            .compact_packed_index_runs(&scale.anchor, &UnenforcedQuiescedMaintenanceGuard)
            .await,
    );
    scale
        .record("delete_checkpoint", writes, since, &before, "ok")
        .await;

    scale.record_inventory("before_reopen").await;
    let since = Instant::now();
    let before = scale.counts();
    scale.restart().await;
    for (anchor, key, body) in &samples {
        scale.restore(anchor, key, body).await;
    }
    scale
        .record("cold_reopen_restore", writes, since, &before, "ok")
        .await;

    let since = Instant::now();
    let before = scale.counts();
    let graph = scale
        .repository
        .commit_store()
        .recovery_mark_for_tests(&scale.anchor, budgets)
        .await;
    scale
        .record(
            "history_graph",
            writes,
            since,
            &before,
            if graph.is_ok() { "ok" } else { "failed" },
        )
        .await;
    let graph = must_v2(graph);
    println!(
        "HISTORY_SCALE {}",
        json!({"phase":"graph_size", "mode":mode,
        "points":graph.point_count, "targets":graph.targets.len(),
        "accounted_metadata_bytes":graph.accounted_metadata_bytes,
        "final_pending_section_bytes":graph.pending_section_bytes,
        "peak_pending_section_bytes":graph.peak_pending_section_bytes})
    );
    drop(graph);

    let since = Instant::now();
    let before = scale.counts();
    let report = scale
        .repository
        .commit_store()
        .quick_maintenance_with_options(
            &scale.anchor,
            crate::v2::V2QuickMaintenanceOptions {
                budgets,
                ..Default::default()
            },
        )
        .await;
    scale
        .record(
            "quick",
            writes,
            since,
            &before,
            if report.is_ok() { "ok" } else { "failed" },
        )
        .await;
    let report = must_v2(report);
    println!(
        "HISTORY_SCALE {}",
        json!({"phase":"history", "mode":mode,
        "points":report.recovery_recoverable_point_count,
        "historical_exact_bytes":report.recovery_historical_exact_bytes,
        "pack_stored_bytes":report.packed_payload_stored_bytes,
        "pack_referenced_bytes":report.packed_payload_referenced_bytes})
    );
    assert!(report.recovery_recoverable_point_count >= writes as u64);

    let since = Instant::now();
    let before = scale.counts();
    let plan = scale
        .repository
        .commit_store()
        .full_gc_dry_run(
            &scale.anchor,
            V2FullGcDryRunOptions {
                budgets,
                ..Default::default()
            },
        )
        .await;
    scale
        .record(
            "gc_plan",
            writes,
            since,
            &before,
            if plan.is_ok() { "ok" } else { "failed" },
        )
        .await;
    must_v2(plan);

    // Cross the renewal margin while every point remains inside the 30-day window.
    scale.advance(scale.start + 2 * DAY);
    let since = Instant::now();
    let before = scale.counts();
    let renewed = scale
        .repository
        .commit_store()
        .apply_full_gc(
            &scale.anchor,
            &UnenforcedQuiescedMaintenanceGuard,
            capacity::options(budgets, false),
        )
        .await;
    scale
        .record(
            "renewal",
            writes,
            since,
            &before,
            if renewed.is_ok() { "ok" } else { "failed" },
        )
        .await;
    assert!(must_v2(renewed).retention_renewed_object_count > 0);
    let since = Instant::now();
    let before = scale.counts();
    for (anchor, key, body) in &samples {
        scale.restore(anchor, key, body).await;
    }
    scale
        .record("restore_after_renewal", writes, since, &before, "ok")
        .await;

    // Keep current dependencies protected before the old physical locks run out.
    scale.advance(scale.start + 30 * DAY);
    let since = Instant::now();
    let before = scale.counts();
    must_v2(
        scale
            .repository
            .commit_store()
            .apply_full_gc(
                &scale.anchor,
                &UnenforcedQuiescedMaintenanceGuard,
                capacity::options(budgets, false),
            )
            .await,
    );
    scale
        .record("quiet_renewal", writes, since, &before, "ok")
        .await;
    scale.advance(scale.start + 35 * DAY);
    let since = Instant::now();
    let before = scale.counts();
    let coordinator = scale.coordinator();
    must_repo(coordinator.write_index_snapshot().await);
    drop(coordinator);
    for (anchor, _, _) in &samples {
        assert!(
            scale
                .repository
                .open_recovery_point(&scale.anchor, anchor.sequence)
                .await
                .is_err(),
            "anchored expiry must reject old selected points even though wall-clock test time has not advanced"
        );
    }
    let reclaimed = scale
        .repository
        .commit_store()
        .apply_full_gc(
            &scale.anchor,
            &UnenforcedQuiescedMaintenanceGuard,
            capacity::options(budgets, true),
        )
        .await;
    scale
        .record(
            "logical_expiry_gc",
            writes,
            since,
            &before,
            if reclaimed.is_ok() { "ok" } else { "failed" },
        )
        .await;
    must_v2(reclaimed);
    // Expiry publication may first renew the previous registry. Logical expiry
    // therefore does not prove that the old carrier locks have already expired.
    // Use observed deadlines, and keep the current graph covered before crossing.
    let unlock = scale.backend.latest_deadline();
    println!(
        "HISTORY_SCALE {}",
        json!({"phase":"physical_unlock", "mode":mode,
        "delay_after_logical_expiry_ms": unlock - scale.backend.now()})
    );
    scale.advance(unlock - DAY / 2);
    let since = Instant::now();
    let before = scale.counts();
    must_v2(
        scale
            .repository
            .commit_store()
            .apply_full_gc(
                &scale.anchor,
                &UnenforcedQuiescedMaintenanceGuard,
                capacity::options(budgets, false),
            )
            .await,
    );
    scale
        .record("pre_unlock_renewal", writes, since, &before, "ok")
        .await;
    scale.advance(unlock + 1);
    let since = Instant::now();
    let before = scale.counts();
    let stored_before = scale.backend.occupancy().1;
    let reclaimed = scale
        .repository
        .commit_store()
        .apply_full_gc(
            &scale.anchor,
            &UnenforcedQuiescedMaintenanceGuard,
            capacity::options(budgets, true),
        )
        .await;
    scale
        .record(
            "physical_gc",
            writes,
            since,
            &before,
            if reclaimed.is_ok() { "ok" } else { "failed" },
        )
        .await;
    assert!(must_v2(reclaimed).orphan_gc.deleted_count > 0);
    assert!(scale.backend.occupancy().1 < stored_before);
    let since = Instant::now();
    let before = scale.counts();
    scale.restart().await;
    assert!(
        scale
            .repository
            .head(&samples.last().expect("latest").1)
            .is_err()
    );
    if mode == "append" {
        let (_, key, expected) = &samples[0];
        assert_eq!(
            must_repo(scale.repository.get_range(key, ByteRange::Full).await),
            *expected
        );
    }
    let quick = must_v2(
        scale
            .repository
            .commit_store()
            .quick_maintenance_with_options(
                &scale.anchor,
                crate::v2::V2QuickMaintenanceOptions {
                    budgets,
                    ..Default::default()
                },
            )
            .await,
    );
    assert!(quick.recovery_recoverable_point_count < report.recovery_recoverable_point_count);
    scale
        .record("final_reopen_verify", writes, since, &before, "ok")
        .await;
    scale.record_inventory("after_gc").await;
    println!(
        "HISTORY_SCALE {}",
        json!({"phase":"complete", "mode":mode, "writes":writes,
        "remaining_points":quick.recovery_recoverable_point_count, "outcome":"ok"})
    );
}

#[tokio::test]
async fn recovery_scale_smoke_overwrite() {
    run("overwrite", 40, V2MaintenanceBudgets::default()).await;
}

#[tokio::test]
async fn recovery_scale_smoke_append() {
    run("append", 40, V2MaintenanceBudgets::default()).await;
}

/// RS3_HISTORY_SCALE_WRITES=10000 RS3_HISTORY_SCALE_MODE=overwrite cargo test
/// -p rs3-repository --release recovery_history_scale -- --ignored --nocapture
#[tokio::test]
#[ignore = "opt-in retained history growth experiment; run each mode in a separate process"]
async fn recovery_history_scale() {
    let writes = std::env::var("RS3_HISTORY_SCALE_WRITES")
        .expect("explicit write count")
        .parse()
        .expect("integer write count");
    let mode = match std::env::var("RS3_HISTORY_SCALE_MODE")
        .expect("explicit mode")
        .as_str()
    {
        "append" => "append",
        "overwrite" => "overwrite",
        _ => panic!("append or overwrite"),
    };
    let mut budgets = V2MaintenanceBudgets::default();
    if let Ok(value) = std::env::var("RS3_HISTORY_SCALE_METADATA_BYTES") {
        budgets.max_history_metadata_bytes = value.parse().expect("integer metadata budget");
    }
    if let Ok(value) = std::env::var("RS3_HISTORY_SCALE_PENDING_BYTES") {
        budgets.max_history_pending_bytes = value.parse().expect("integer pending budget");
    }
    run(mode, writes, budgets).await;
}
