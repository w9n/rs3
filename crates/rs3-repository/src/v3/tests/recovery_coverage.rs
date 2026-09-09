//! Retained-provider recovery coverage integration tests.

use super::*;
use crate::v3::RecoveryPolicy;
use rs3_storage::{
    FaultAction, FaultInjectingBlobStore, FaultMatcher, FaultOperationKind, FaultRule,
};

type TrackedStore = FaultInjectingBlobStore<CountingBlobStore<MemoryBlobStore>>;

async fn retained_fixture(
    policy: RecoveryPolicy,
) -> (
    TrackedStore,
    Arc<V3Repository<TrackedStore>>,
    V3MemoryAnchor,
    V3CommitCoordinator<TrackedStore, V3MemoryAnchor>,
) {
    let memory = MemoryBlobStore::new();
    let options = commit_store_options_with_maintenance_roots(
        &memory,
        V3ProviderProfile::RetainedVersionObjectLock,
        Some(RetentionPolicy::new(RetentionMode::Compliance, 1)),
    )
    .await
    .with_recovery_policy(Some(policy));
    let store = FaultInjectingBlobStore::new(CountingBlobStore::new(memory), Vec::new());
    let repository = Arc::new(V3Repository::new(
        store.clone(),
        must_crypto(KeyRing::generate_random()),
        RepositoryOptions::default(),
        options,
    ));
    let anchor = V3MemoryAnchor::new();
    let guard = UnenforcedQuiescedMaintenanceGuard;
    must_repo(
        repository
            .write_genesis_snapshot_with_guard(&anchor, Some(&guard))
            .await,
    );
    let coordinator = must_repo(V3CommitCoordinator::with_options(
        Arc::clone(&repository),
        anchor.clone(),
        CommitCoordinatorOptions::new(1, Duration::ZERO),
    ))
    .with_maintenance_guard(UnenforcedQuiescedMaintenanceGuard);
    (store, repository, anchor, coordinator)
}

fn key(index: usize) -> LogicalPath {
    must_type(LogicalPath::new(format!("recovery/packed-{index}")))
}

fn renewal_due_time() -> i64 {
    let now_ms = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_millis(),
    )
    .expect("timestamp fits i64");
    now_ms.saturating_add(2 * 86_400_000)
}

async fn faulted_fixture(
    policy: RecoveryPolicy,
) -> (
    FaultInjectingBlobStore<MemoryBlobStore>,
    V3MemoryAnchor,
    V3CommitCoordinator<FaultInjectingBlobStore<MemoryBlobStore>, V3MemoryAnchor>,
) {
    let memory = MemoryBlobStore::new();
    let options = commit_store_options_with_maintenance_roots(
        &memory,
        V3ProviderProfile::RetainedVersionObjectLock,
        Some(RetentionPolicy::new(RetentionMode::Compliance, 1)),
    )
    .await
    .with_recovery_policy(Some(policy));
    let keys = must_crypto(KeyRing::generate_random());
    let setup = V3Repository::new(
        memory.clone(),
        keys.clone(),
        RepositoryOptions::default(),
        options.clone(),
    );
    let anchor = V3MemoryAnchor::new();
    let guard = UnenforcedQuiescedMaintenanceGuard;
    must_repo(
        setup
            .write_genesis_snapshot_with_guard(&anchor, Some(&guard))
            .await,
    );

    let store = FaultInjectingBlobStore::new(memory, Vec::new());
    let repository = Arc::new(V3Repository::new(
        store.clone(),
        keys,
        RepositoryOptions::default(),
        options,
    ));
    must_repo(repository.load_chain_from_anchor(&anchor).await);
    // Genesis has covered its roots at the original current time. Advance the
    // next sampled publication enough that coverage must renew them again.
    repository
        .commit_store()
        .set_publication_time_for_tests(renewal_due_time());
    let coordinator = must_repo(V3CommitCoordinator::with_options(
        repository,
        anchor.clone(),
        CommitCoordinatorOptions::new(1, Duration::ZERO),
    ))
    .with_maintenance_guard(UnenforcedQuiescedMaintenanceGuard);
    (store, anchor, coordinator)
}

#[tokio::test]
async fn retained_packed_successors_reuse_coverage_and_restart_rebuilds_it() {
    let (store, repository, anchor, coordinator) = retained_fixture(RecoveryPolicy::PRESET).await;
    let genesis = must_v3(anchor.read_v3().await).expect("genesis anchor");
    let first = must_repo(
        coordinator
            .put_committed(
                key(0),
                Bytes::from_static(b"first packed payload"),
                RepositoryPutOptions::default(),
            )
            .await,
    );

    store
        .inner()
        .reset_operation_counts()
        .expect("reset successor operation counts");
    let event_start = store.operation_log().expect("initial operation log").len();
    let second = must_repo(
        coordinator
            .put_committed(
                key(1),
                Bytes::from_static(b"second packed payload"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    let cached = store
        .inner()
        .operation_counts()
        .expect("cached successor counts");
    assert_eq!(
        cached.list, 0,
        "covered publication must not list old graph"
    );
    assert_eq!(
        cached.extend_retention, 0,
        "covered publication must not renew old graph versions"
    );
    assert!(
        cached.get <= 6 && cached.head <= 4,
        "only bounded successor verification is allowed: {cached:?}"
    );
    assert_no_prior_graph_io(
        &store,
        event_start,
        [&genesis, &first.anchor_state],
        "covered packed successor",
    );

    drop(coordinator);
    let options = repository.commit_store().options().clone();
    let keyring = repository.commit_store().keyring().clone();
    drop(repository);
    let restarted = Arc::new(V3Repository::new(
        store.clone(),
        keyring,
        RepositoryOptions::default(),
        options,
    ));
    must_repo(restarted.load_chain_from_anchor(&anchor).await);
    let restarted_coordinator = must_repo(V3CommitCoordinator::with_options(
        Arc::clone(&restarted),
        anchor,
        CommitCoordinatorOptions::new(1, Duration::ZERO),
    ))
    .with_maintenance_guard(UnenforcedQuiescedMaintenanceGuard);

    store
        .inner()
        .reset_operation_counts()
        .expect("reset restart operation counts");
    let third = must_repo(
        restarted_coordinator
            .put_committed(
                key(2),
                Bytes::from_static(b"restart packed payload"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    let rebuilt = store
        .inner()
        .operation_counts()
        .expect("restart rebuild counts");
    assert!(
        rebuilt.get > cached.get
            || rebuilt.head > cached.head
            || rebuilt.extend_retention > cached.extend_retention,
        "restart must rebuild verified recovery coverage: cached={cached:?}, rebuilt={rebuilt:?}"
    );

    store
        .inner()
        .reset_operation_counts()
        .expect("reset post-rebuild operation counts");
    let recached_event_start = store.operation_log().expect("recached operation log").len();
    must_repo(
        restarted_coordinator
            .put_committed(
                key(3),
                Bytes::from_static(b"post-rebuild packed payload"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    let recached = store
        .inner()
        .operation_counts()
        .expect("post-rebuild cached counts");
    assert_eq!(recached.list, 0);
    assert_eq!(recached.extend_retention, 0);
    assert!(
        recached.get <= 6 && recached.head <= 4,
        "recovered cache must retain bounded successor verification: {recached:?}"
    );
    assert_no_prior_graph_io(
        &store,
        recached_event_start,
        [
            &genesis,
            &first.anchor_state,
            &second.anchor_state,
            &third.anchor_state,
        ],
        "recovered packed successor",
    );
}

#[tokio::test]
async fn retained_coverage_exact_head_or_renewal_failure_blocks_successor_anchor() {
    for operation in [
        FaultOperationKind::HeadAt,
        FaultOperationKind::ExtendRetentionAt,
    ] {
        let (store, anchor, coordinator) = faulted_fixture(RecoveryPolicy::PRESET).await;
        let before = must_v3(anchor.read_v3().await).expect("genesis anchor");
        store
            .push_rule(FaultRule::new(
                FaultMatcher::operation(operation),
                FaultAction::return_error("recovery coverage fault"),
            ))
            .expect("install recovery coverage fault");

        assert!(
            coordinator
                .put_committed(
                    key(10),
                    Bytes::from_static(b"blocked packed payload"),
                    RepositoryPutOptions::default(),
                )
                .await
                .is_err(),
            "{operation:?} fault must reject successor publication"
        );
        assert_eq!(
            must_v3(anchor.read_v3().await),
            Some(before),
            "{operation:?} fault must leave the accepted anchor unchanged"
        );
        assert!(
            store
                .operation_log()
                .expect("fault operation log")
                .iter()
                .any(|event| event.kind == operation),
            "expected {operation:?} during recovery coverage"
        );
    }
}

async fn publish_time(repository: &V3Repository<TrackedStore>, anchor: &V3AnchorState) -> i64 {
    must_v3(
        repository
            .commit_store()
            .read_replay_commit_at(&anchor.commit_key, anchor.version_id.as_ref())
            .await,
    )
    .parsed_header
    .header
    .publish_time_ms
}

#[tokio::test]
async fn retained_overwrite_delete_preserve_old_packed_bytes_across_policy_reduction() {
    let old_policy = RecoveryPolicy::PRESET;
    let (store, repository, anchor, coordinator) = retained_fixture(old_policy).await;
    let object = key(20);
    let original = must_repo(
        coordinator
            .put_committed(
                object.clone(),
                Bytes::from_static(b"original packed bytes"),
                RepositoryPutOptions::default(),
            )
            .await,
    );

    let reduced_policy = must_v3(RecoveryPolicy::new(1, 86_400, 60_000));
    drop(coordinator);
    let options = repository
        .commit_store()
        .options()
        .clone()
        .with_recovery_policy(Some(reduced_policy));
    let keys = repository.commit_store().keyring().clone();
    drop(repository);
    let restarted = Arc::new(V3Repository::new(
        store.clone(),
        keys,
        RepositoryOptions::default(),
        options,
    ));
    must_repo(restarted.load_chain_from_anchor(&anchor).await);
    let coordinator = must_repo(V3CommitCoordinator::with_options(
        Arc::clone(&restarted),
        anchor.clone(),
        CommitCoordinatorOptions::new(1, Duration::ZERO),
    ))
    .with_maintenance_guard(UnenforcedQuiescedMaintenanceGuard);

    let replacement = must_repo(
        coordinator
            .put_committed(
                object.clone(),
                Bytes::from_static(b"replacement packed bytes"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    let original_floor = must_v3(
        old_policy.coverage_until_ms(publish_time(&restarted, &replacement.anchor_state).await),
    );
    let original_metadata = store
        .inner()
        .inner()
        .head_at(
            &original.anchor_state.commit_key,
            original.anchor_state.version_id.as_ref(),
        )
        .await
        .expect("original packed commit remains exact-addressable");
    assert!(
        original_metadata
            .retain_until_ms
            .is_some_and(|deadline| deadline >= original_floor),
        "reduced policy must not shorten the original supersession coverage"
    );
    assert!(
        !store
            .inner()
            .inner()
            .get_range_at(
                &original.anchor_state.commit_key,
                original.anchor_state.version_id.as_ref(),
                ByteRange::Full,
            )
            .await
            .expect("original packed bytes remain readable")
            .is_empty()
    );

    must_repo(coordinator.delete_committed(object).await);
    let deleted = must_v3(anchor.read_v3().await).expect("delete anchor");
    let replacement_floor =
        must_v3(reduced_policy.coverage_until_ms(publish_time(&restarted, &deleted).await));
    let replacement_metadata = store
        .inner()
        .inner()
        .head_at(
            &replacement.anchor_state.commit_key,
            replacement.anchor_state.version_id.as_ref(),
        )
        .await
        .expect("replacement packed commit remains exact-addressable");
    assert!(
        replacement_metadata
            .retain_until_ms
            .is_some_and(|deadline| deadline >= replacement_floor),
        "delete must preserve replacement bytes through its supersession promise"
    );
    assert!(
        !store
            .inner()
            .inner()
            .get_range_at(
                &replacement.anchor_state.commit_key,
                replacement.anchor_state.version_id.as_ref(),
                ByteRange::Full,
            )
            .await
            .expect("replacement packed bytes remain readable")
            .is_empty()
    );
}

fn assert_no_prior_graph_io<const N: usize>(
    store: &TrackedStore,
    start: usize,
    anchors: [&V3AnchorState; N],
    operation: &str,
) {
    let prior_keys = anchors
        .iter()
        .map(|anchor| &anchor.commit_key)
        .collect::<Vec<_>>();
    assert!(
        !store
            .operation_log()
            .expect("tracked operation log")
            .into_iter()
            .skip(start)
            .any(|event| {
                event.object_id.as_ref().is_some_and(|object_id| {
                    prior_keys.contains(&object_id)
                        && matches!(
                            event.kind,
                            FaultOperationKind::GetRange
                                | FaultOperationKind::GetRangeAt
                                | FaultOperationKind::Head
                                | FaultOperationKind::HeadAt
                                | FaultOperationKind::ExtendRetention
                                | FaultOperationKind::ExtendRetentionAt
                        )
                })
            }),
        "{operation} must not rewalk a prior accepted graph"
    );
}
