use super::*;

#[tokio::test]
async fn commit_coordinator_fails_all_batch_waiters_when_checkpoint_put_fails() {
    let inner = MemoryBlobStore::new();
    let store = FailOncePutStore::new(inner.clone(), CHECKPOINT_OBJECT_PREFIX);
    let keyring = signing_keyring();
    let repository = Arc::new(Repository::with_keyring(store, keyring.clone()));
    let anchor = MemoryCheckpointAnchor::new();
    let coordinator = Arc::new(CommitCoordinator::with_options(
        repository,
        anchor.clone(),
        CommitCoordinatorOptions::new(2, std::time::Duration::from_secs(60)),
    ));
    let first_key = key("p/12/failed-a");
    let second_key = key("p/12/failed-b");

    let first = {
        let coordinator = Arc::clone(&coordinator);
        let key = first_key.clone();
        async move {
            coordinator
                .put_committed(
                    key,
                    Bytes::from_static(b"first"),
                    RepositoryPutOptions::default(),
                )
                .await
        }
    };
    let second = {
        let coordinator = Arc::clone(&coordinator);
        let key = second_key.clone();
        async move {
            coordinator
                .put_committed(
                    key,
                    Bytes::from_static(b"second"),
                    RepositoryPutOptions::default(),
                )
                .await
        }
    };

    let (first, second) = tokio::join!(first, second);
    let fresh = Repository::with_keyring(inner, keyring);
    let later = coordinator
        .put_committed(
            key("p/12/later"),
            Bytes::from_static(b"later"),
            RepositoryPutOptions::default(),
        )
        .await;

    assert!(matches!(first, Err(RepositoryError::CommitFailed { .. })));
    assert!(matches!(second, Err(RepositoryError::CommitFailed { .. })));
    assert!(matches!(later, Err(RepositoryError::CommitFailed { .. })));
    assert!(matches!(
        anchor.read().await,
        Err(AnchorError::MissingAnchor)
    ));
    assert!(matches!(
        fresh.head(&first_key),
        Err(RepositoryError::NotFound(_))
    ));
    assert!(matches!(
        fresh.head(&second_key),
        Err(RepositoryError::NotFound(_))
    ));
}

#[tokio::test]
async fn commit_coordinator_batches_concurrent_committed_puts() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let repository = Arc::new(Repository::with_keyring(store.clone(), keyring.clone()));
    let anchor = MemoryCheckpointAnchor::new();
    let coordinator = Arc::new(CommitCoordinator::with_options(
        repository,
        anchor.clone(),
        CommitCoordinatorOptions::new(2, std::time::Duration::from_secs(60)),
    ));
    let first_key = key("p/12/a");
    let second_key = key("p/12/b");

    let first = {
        let coordinator = Arc::clone(&coordinator);
        let key = first_key.clone();
        async move {
            coordinator
                .put_committed(
                    key,
                    Bytes::from_static(b"first"),
                    RepositoryPutOptions::default(),
                )
                .await
        }
    };
    let second = {
        let coordinator = Arc::clone(&coordinator);
        let key = second_key.clone();
        async move {
            coordinator
                .put_committed(
                    key,
                    Bytes::from_static(b"second"),
                    RepositoryPutOptions::default(),
                )
                .await
        }
    };

    let (first, second) = tokio::join!(first, second);
    let first = must(first);
    let second = must(second);
    let accepted = match anchor.read().await {
        Ok(anchor) => CheckpointPosition::from(anchor),
        Err(error) => panic!("{error}"),
    };
    let reloaded = Repository::with_keyring(store, keyring);
    let loaded = must(reloaded.load_checkpoint_position(&accepted).await);
    let listed = must(reloaded.list("p/12"));

    assert_eq!(first.checkpoint, second.checkpoint);
    assert_eq!(accepted.sequence, Sequence::new(2));
    assert_eq!(loaded, accepted);
    assert_eq!(
        listed
            .into_iter()
            .map(|entry| entry.key)
            .collect::<Vec<_>>(),
        vec![first_key, second_key]
    );
}

#[tokio::test]
async fn commit_coordinator_does_not_publish_while_stage_write_is_in_flight() {
    let inner = MemoryBlobStore::new();
    let store = PauseFirstSegmentPutStore::new(inner.clone());
    let keyring = signing_keyring();
    let repository = Arc::new(Repository::with_keyring(store.clone(), keyring.clone()));
    let anchor = MemoryCheckpointAnchor::new();
    let coordinator = Arc::new(CommitCoordinator::with_options(
        repository,
        anchor.clone(),
        CommitCoordinatorOptions::new(2, std::time::Duration::from_secs(60)),
    ));
    let first_key = key("p/12/paused-a");
    let second_key = key("p/12/paused-b");

    let first = {
        let coordinator = Arc::clone(&coordinator);
        let key = first_key.clone();
        tokio::spawn(async move {
            coordinator
                .put_committed(
                    key,
                    Bytes::from_static(b"first"),
                    RepositoryPutOptions::default(),
                )
                .await
        })
    };
    store.wait_until_paused().await;

    let second = {
        let coordinator = Arc::clone(&coordinator);
        let key = second_key.clone();
        tokio::spawn(async move {
            coordinator
                .put_committed(
                    key,
                    Bytes::from_static(b"second"),
                    RepositoryPutOptions::default(),
                )
                .await
        })
    };

    tokio::task::yield_now().await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert!(matches!(
        anchor.read().await,
        Err(AnchorError::MissingAnchor)
    ));

    store.release();
    let (first, second) = tokio::join!(first, second);
    let first = match first {
        Ok(result) => must(result),
        Err(error) => panic!("{error}"),
    };
    let second = match second {
        Ok(result) => must(result),
        Err(error) => panic!("{error}"),
    };
    let accepted = match anchor.read().await {
        Ok(anchor) => CheckpointPosition::from(anchor),
        Err(error) => panic!("{error}"),
    };
    let reloaded = Repository::with_keyring(inner, keyring);
    let loaded = must(reloaded.load_checkpoint_position(&accepted).await);
    let listed = must(reloaded.list("p/12"));

    assert_eq!(first.checkpoint, second.checkpoint);
    assert_eq!(accepted.sequence, Sequence::new(2));
    assert_eq!(loaded, accepted);
    assert_eq!(
        listed
            .into_iter()
            .map(|entry| entry.key)
            .collect::<Vec<_>>(),
        vec![first_key, second_key]
    );
}

#[tokio::test]
async fn commit_coordinator_publishes_single_write_after_delay() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let repository = Arc::new(Repository::with_keyring(store.clone(), keyring));
    let coordinator = CommitCoordinator::with_options(
        repository,
        MemoryCheckpointAnchor::new(),
        CommitCoordinatorOptions::new(8, std::time::Duration::from_millis(5)),
    );

    let committed = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        coordinator.put_committed(
            key("p/12/quiet"),
            Bytes::from_static(b"quiet"),
            RepositoryPutOptions::default(),
        ),
    )
    .await;

    let committed = match committed {
        Ok(result) => must(result),
        Err(error) => panic!("{error}"),
    };
    let counts = must_storage(store.operation_counts());
    let indexes = must_storage(store.list_prefix("index/").await);
    let checkpoints = must_storage(store.list_prefix(CHECKPOINT_OBJECT_PREFIX).await);
    let evidence = must_storage(store.list_prefix(CHECKPOINT_EVIDENCE_PREFIX).await);

    assert_eq!(committed.checkpoint.sequence, Sequence::new(1));
    assert_eq!(counts.put, 3);
    assert!(indexes.is_empty());
    assert_eq!(checkpoints.len(), 1);
    assert_eq!(evidence.len(), 1);
}

#[tokio::test]
async fn commit_coordinator_applies_backpressure_before_writing_payload() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let repository = Arc::new(Repository::with_keyring(store.clone(), keyring));
    let coordinator = Arc::new(CommitCoordinator::with_options(
        repository,
        MemoryCheckpointAnchor::new(),
        CommitCoordinatorOptions::new(8, std::time::Duration::from_millis(25))
            .with_max_pending_items(1),
    ));

    let first = {
        let coordinator = Arc::clone(&coordinator);
        tokio::spawn(async move {
            coordinator
                .put_committed(
                    key("p/12/first"),
                    Bytes::from_static(b"first"),
                    RepositoryPutOptions::default(),
                )
                .await
        })
    };

    for _ in 0..100 {
        let payloads = must_storage(store.list_prefix("segments/").await);
        if payloads.len() == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }

    let rejected = coordinator
        .put_committed(
            key("p/12/rejected"),
            Bytes::from_static(b"rejected"),
            RepositoryPutOptions::default(),
        )
        .await;
    let payloads_after_rejection = must_storage(store.list_prefix("segments/").await);
    let first = tokio::time::timeout(std::time::Duration::from_secs(1), first).await;

    assert!(matches!(rejected, Err(RepositoryError::CommitBackpressure)));
    assert_eq!(payloads_after_rejection.len(), 1);
    match first {
        Ok(joined) => assert!(matches!(joined, Ok(Ok(_)))),
        Err(error) => panic!("{error}"),
    }
}

#[tokio::test]
async fn operation_counts_show_checkpoint_batch_reduces_backend_puts() {
    let single_store = MemoryBlobStore::new();
    let single_repository = Arc::new(Repository::with_keyring(
        single_store.clone(),
        signing_keyring(),
    ));
    let single = CommitCoordinator::new(single_repository, MemoryCheckpointAnchor::new());
    let keys = [key("p/12/a"), key("p/12/b"), key("p/12/c")];

    for (index, key) in keys.iter().enumerate() {
        let committed = single
            .put_committed(
                key.clone(),
                Bytes::from(format!("single-{index}")),
                RepositoryPutOptions::default(),
            )
            .await;
        assert!(committed.is_ok());
    }

    let single_counts = must_storage(single_store.operation_counts());
    let single_payloads = must_storage(single_store.list_prefix("segments/").await);
    let single_manifests = must_storage(single_store.list_prefix("manifests/").await);
    let single_indexes = must_storage(single_store.list_prefix("index/").await);
    let single_checkpoints = must_storage(single_store.list_prefix(CHECKPOINT_OBJECT_PREFIX).await);
    let single_evidence = must_storage(single_store.list_prefix(CHECKPOINT_EVIDENCE_PREFIX).await);

    let batch_store = MemoryBlobStore::new();
    let batch_repo = Repository::with_keyring(batch_store.clone(), signing_keyring());
    let batch_anchor = MemoryCheckpointAnchor::new();

    for (index, key) in keys.iter().enumerate() {
        let put = batch_repo
            .put(
                key.clone(),
                Bytes::from(format!("batch-{index}")),
                RepositoryPutOptions::default(),
            )
            .await;
        assert!(put.is_ok());
    }
    let published = batch_repo.publish_checkpoint(&batch_anchor).await;
    assert!(published.is_ok());

    let batch_counts = must_storage(batch_store.operation_counts());
    let batch_payloads = must_storage(batch_store.list_prefix("segments/").await);
    let batch_manifests = must_storage(batch_store.list_prefix("manifests/").await);
    let batch_indexes = must_storage(batch_store.list_prefix("index/").await);
    let batch_checkpoints = must_storage(batch_store.list_prefix(CHECKPOINT_OBJECT_PREFIX).await);
    let batch_evidence = must_storage(batch_store.list_prefix(CHECKPOINT_EVIDENCE_PREFIX).await);

    let grouped_store = MemoryBlobStore::new();
    let grouped_repository = Arc::new(Repository::with_keyring(
        grouped_store.clone(),
        signing_keyring(),
    ));
    let grouped = Arc::new(CommitCoordinator::with_options(
        grouped_repository,
        MemoryCheckpointAnchor::new(),
        CommitCoordinatorOptions::new(3, std::time::Duration::from_secs(60)),
    ));
    let grouped_a = {
        let grouped = Arc::clone(&grouped);
        let key = keys[0].clone();
        async move {
            grouped
                .put_committed(
                    key,
                    Bytes::from_static(b"grouped-a"),
                    RepositoryPutOptions::default(),
                )
                .await
        }
    };
    let grouped_b = {
        let grouped = Arc::clone(&grouped);
        let key = keys[1].clone();
        async move {
            grouped
                .put_committed(
                    key,
                    Bytes::from_static(b"grouped-b"),
                    RepositoryPutOptions::default(),
                )
                .await
        }
    };
    let grouped_c = {
        let grouped = Arc::clone(&grouped);
        let key = keys[2].clone();
        async move {
            grouped
                .put_committed(
                    key,
                    Bytes::from_static(b"grouped-c"),
                    RepositoryPutOptions::default(),
                )
                .await
        }
    };

    let grouped_results = tokio::join!(grouped_a, grouped_b, grouped_c);
    assert!(grouped_results.0.is_ok());
    assert!(grouped_results.1.is_ok());
    assert!(grouped_results.2.is_ok());

    let grouped_counts = must_storage(grouped_store.operation_counts());
    let grouped_payloads = must_storage(grouped_store.list_prefix("segments/").await);
    let grouped_indexes = must_storage(grouped_store.list_prefix("index/").await);
    let grouped_checkpoints =
        must_storage(grouped_store.list_prefix(CHECKPOINT_OBJECT_PREFIX).await);
    let grouped_evidence =
        must_storage(grouped_store.list_prefix(CHECKPOINT_EVIDENCE_PREFIX).await);

    assert_eq!(single_counts.put, 9);
    assert_eq!(batch_counts.put, 5);
    assert_eq!(grouped_counts.put, 5);
    assert_eq!(single_counts.get, 0);
    assert_eq!(batch_counts.get, 0);
    assert_eq!(grouped_counts.get, 0);
    assert_eq!(single_payloads.len(), 3);
    assert_eq!(single_manifests.len(), 0);
    assert!(single_indexes.is_empty());
    assert_eq!(single_checkpoints.len(), 3);
    assert_eq!(single_evidence.len(), 3);
    assert_eq!(batch_payloads.len(), 3);
    assert_eq!(batch_manifests.len(), 0);
    assert!(batch_indexes.is_empty());
    assert_eq!(batch_checkpoints.len(), 1);
    assert_eq!(batch_evidence.len(), 1);
    assert_eq!(grouped_payloads.len(), 3);
    assert!(grouped_indexes.is_empty());
    assert_eq!(grouped_checkpoints.len(), 1);
    assert_eq!(grouped_evidence.len(), 1);
}
