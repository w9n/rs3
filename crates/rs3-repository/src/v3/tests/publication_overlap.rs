use super::*;

struct Fixture {
    store: SlowCommitGetStore,
    keyring: KeyRing,
    options: V3CommitStoreOptions,
    repository: Arc<V3Repository<SlowCommitGetStore>>,
    anchor: V3MemoryAnchor,
    coordinator: Arc<V3CommitCoordinator<SlowCommitGetStore, V3MemoryAnchor>>,
}

impl Fixture {
    async fn new() -> Self {
        Self::with_profile(V3ProviderProfile::Dev).await
    }

    async fn with_profile(profile: V3ProviderProfile) -> Self {
        let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
        let keyring = must_crypto(KeyRing::generate_random());
        let options = V3CommitStoreOptions::for_profile(
            profile,
            sample_repository_id(),
            sample_keyring_envelope_ref(),
            sample_format_ref(),
        );
        let repository = Arc::new(V3Repository::new(
            store.clone(),
            keyring.clone(),
            RepositoryOptions::default(),
            options.clone(),
        ));
        let anchor = V3MemoryAnchor::new();
        must_repo(repository.write_genesis_snapshot(&anchor).await);
        must_repo(
            repository
                .put_committed(
                    &anchor,
                    key("shared"),
                    Bytes::from_static(b"base"),
                    RepositoryPutOptions::default(),
                )
                .await,
        );
        let coordinator = Arc::new(
            must_repo(V3CommitCoordinator::with_options(
                Arc::clone(&repository),
                anchor.clone(),
                CommitCoordinatorOptions::new(1, Duration::ZERO).with_max_pending_items(2),
            ))
            .with_maintenance_guard(UnenforcedQuiescedMaintenanceGuard),
        );
        Self {
            store,
            keyring,
            options,
            repository,
            anchor,
            coordinator,
        }
    }

    fn put(
        &self,
        name: &str,
        bytes: &'static [u8],
    ) -> tokio::task::JoinHandle<crate::Result<super::super::V3CommittedPut>> {
        let coordinator = Arc::clone(&self.coordinator);
        let key = key(name);
        tokio::spawn(async move {
            coordinator
                .put_committed(
                    key,
                    Bytes::from_static(bytes),
                    RepositoryPutOptions::default(),
                )
                .await
        })
    }

    async fn pause(
        &self,
        fail: bool,
    ) -> tokio::task::JoinHandle<crate::Result<super::super::V3CommittedPut>> {
        self.store
            .commit_put_pause
            .mode
            .store(if fail { 2 } else { 1 }, Ordering::SeqCst);
        let first = self.put("shared", b"first");
        bounded(self.store.commit_put_pause.entered.notified()).await;
        first
    }

    async fn staged_successor(&self) {
        bounded(async {
            while self.coordinator.pending_item_count_for_tests().await != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await;
    }

    async fn reopened(&self, anchor: V3AnchorState) -> V3Repository<SlowCommitGetStore> {
        let fresh = V3Repository::new(
            self.store.clone(),
            self.keyring.clone(),
            RepositoryOptions::default(),
            self.options.clone(),
        );
        must_repo(
            fresh
                .load_chain_from_anchor(&V3MemoryAnchor::with_state(anchor))
                .await,
        );
        fresh
    }
}

fn key(name: &str) -> LogicalPath {
    must_type(LogicalPath::new(format!("overlap/{name}")))
}

async fn bounded<F: std::future::Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .expect("overlap operation must terminate")
}

#[tokio::test]
async fn staging_overlaps_upload_with_one_publisher_and_a_shared_admission_limit() {
    let f = Fixture::new().await;
    f.store.commit_put_pause.mode.store(1, Ordering::SeqCst);
    let first = f.put("created", b"first");
    bounded(f.store.commit_put_pause.entered.notified()).await;
    let attempt = f.store.commit_put_pause.attempts.load(Ordering::SeqCst);
    let conflict = bounded(f.coordinator.put_committed(
        key("created"),
        Bytes::from_static(b"conflict"),
        RepositoryPutOptions {
            create_only: true,
            ..RepositoryPutOptions::default()
        },
    ))
    .await;
    assert!(
        matches!(conflict, Err(RepositoryError::AlreadyExists(_))),
        "create-only sees the frozen prefix"
    );
    let successor = f.put("created", b"successor");
    f.staged_successor().await;
    assert!(!first.is_finished());
    assert!(!successor.is_finished());
    assert!(
        matches!(
            f.repository.head(&key("created")),
            Err(RepositoryError::NotFound(_))
        ),
        "an unaccepted create is not visible to readers"
    );
    assert_eq!(
        f.store.commit_put_pause.attempts.load(Ordering::SeqCst),
        attempt,
        "successor cannot upload before predecessor resolves"
    );
    let overflow = f.coordinator.put_committed(
        key("overflow"),
        Bytes::new(),
        RepositoryPutOptions::default(),
    );
    tokio::pin!(overflow);
    assert!(
        futures_util::poll!(&mut overflow).is_pending(),
        "full publishing capacity waits without staging another write"
    );
    assert_eq!(
        must_repo(f.repository.pending_operation_count_for_tests()),
        2
    );
    f.store.commit_put_pause.release.notify_one();
    let first = must_repo(bounded(first).await.expect("first task"));
    let successor = must_repo(bounded(successor).await.expect("successor task"));
    assert_eq!(
        successor.anchor_state.sequence,
        first
            .anchor_state
            .sequence
            .checked_next()
            .expect("next commit")
    );
    let old = f.reopened(first.anchor_state).await;
    assert_eq!(
        must_repo(old.get_range(&key("created"), ByteRange::Full).await),
        Bytes::from_static(b"first")
    );
    let fresh = f.reopened(successor.anchor_state).await;
    assert_eq!(
        must_repo(fresh.get_range(&key("created"), ByteRange::Full).await),
        Bytes::from_static(b"successor")
    );
    assert!(!f.coordinator.status().poisoned);
    must_repo(bounded(overflow).await);
}

#[tokio::test]
async fn failed_prefix_rejects_successor_and_preserves_retryable_base() {
    let f = Fixture::new().await;
    let before = must_v3(f.anchor.read_v3().await);
    let first = f.pause(true).await;
    let successor = f.put("shared", b"successor");
    f.staged_successor().await;
    f.store.commit_put_pause.release.notify_one();
    assert!(matches!(
        bounded(first).await.expect("first task"),
        Err(RepositoryError::CommitFailed { .. })
    ));
    assert!(matches!(
        bounded(successor).await.expect("successor task"),
        Err(RepositoryError::CommitFailed { .. })
    ));
    assert_eq!(must_v3(f.anchor.read_v3().await), before);
    assert_eq!(
        must_repo(f.repository.pending_operation_count_for_tests()),
        0
    );
    assert_eq!(
        must_repo(
            f.repository
                .get_range(&key("shared"), ByteRange::Full)
                .await
        ),
        Bytes::from_static(b"base")
    );
    assert!(!f.coordinator.status().poisoned);
    let retry = must_repo(
        bounded(f.put("shared", b"retry"))
            .await
            .expect("retry task"),
    );
    let fresh = f.reopened(retry.anchor_state).await;
    assert_eq!(
        must_repo(fresh.get_range(&key("shared"), ByteRange::Full).await),
        Bytes::from_static(b"retry")
    );
}

#[tokio::test]
async fn canceled_waiter_does_not_cancel_owned_prefix_publication() {
    let f = Fixture::new().await;
    let before = must_v3(f.anchor.read_v3().await).expect("base anchor");
    let first = f.pause(false).await;
    first.abort();
    assert!(
        bounded(first)
            .await
            .expect_err("canceled waiter")
            .is_cancelled()
    );
    let successor = f.put("next", b"successor");
    f.staged_successor().await;
    f.store.commit_put_pause.release.notify_one();
    let successor = must_repo(bounded(successor).await.expect("successor task"));
    assert_eq!(
        successor.anchor_state.sequence.get(),
        before.sequence.get() + 2
    );
    let fresh = f.reopened(successor.anchor_state).await;
    assert_eq!(
        must_repo(fresh.get_range(&key("shared"), ByteRange::Full).await),
        Bytes::from_static(b"first")
    );
    assert_eq!(
        must_repo(fresh.get_range(&key("next"), ByteRange::Full).await),
        Bytes::from_static(b"successor")
    );
}

#[tokio::test]
async fn maintenance_drains_successor_without_inverting_publication_locks() {
    let f = Fixture::new().await;
    let first = f.pause(false).await;
    let maintenance = f.coordinator.begin_maintenance_window();
    tokio::pin!(maintenance);
    assert!(futures_util::poll!(&mut maintenance).is_pending());
    let successor = f.put("next", b"successor");
    f.staged_successor().await;
    f.store.commit_put_pause.release.notify_one();
    let window = must_repo(bounded(maintenance).await);
    must_repo(bounded(first).await.expect("first task"));
    must_repo(bounded(successor).await.expect("successor drained"));
    let attempts = f.store.commit_put_pause.attempts.load(Ordering::SeqCst);
    let put = f.coordinator.put_committed(
        key("after-window"),
        Bytes::from_static(b"later"),
        RepositoryPutOptions::default(),
    );
    tokio::pin!(put);
    assert!(futures_util::poll!(&mut put).is_pending());
    assert_eq!(
        f.store.commit_put_pause.attempts.load(Ordering::SeqCst),
        attempts
    );
    drop(window);
    let later = must_repo(bounded(put).await);
    let fresh = f.reopened(later.anchor_state).await;
    assert_eq!(
        must_repo(fresh.get_range(&key("next"), ByteRange::Full).await),
        Bytes::from_static(b"successor")
    );
    assert!(fresh.head(&key("after-window")).is_ok());
}

#[tokio::test]
async fn accepted_prefix_install_failure_poison_rejects_unpublished_successor() {
    let f = Fixture::new().await;
    let first = f.pause(false).await;
    let successor = f.put("next", b"must not publish");
    f.staged_successor().await;
    f.repository.fail_next_local_install_for_tests();
    let attempts = f.store.commit_put_pause.attempts.load(Ordering::SeqCst);
    f.store.commit_put_pause.release.notify_one();
    assert!(matches!(
        bounded(first).await.expect("first task"),
        Err(RepositoryError::AcceptedRecoveryRequired)
    ));
    assert!(matches!(
        bounded(successor).await.expect("successor task"),
        Err(RepositoryError::AcceptedRecoveryRequired)
    ));
    assert!(f.coordinator.status().poisoned);
    assert_eq!(
        f.store.commit_put_pause.attempts.load(Ordering::SeqCst),
        attempts
    );
    let fresh = f
        .reopened(must_v3(f.anchor.read_v3().await).expect("accepted prefix"))
        .await;
    assert_eq!(
        must_repo(fresh.get_range(&key("shared"), ByteRange::Full).await),
        Bytes::from_static(b"first")
    );
    assert!(matches!(
        fresh.head(&key("next")),
        Err(RepositoryError::NotFound(_))
    ));
}

struct LostAdvanceReply {
    inner: V3MemoryAnchor,
    lose_next: std::sync::atomic::AtomicBool,
    lose_reconciliation: bool,
    unreadable: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl V3CommitAnchor for LostAdvanceReply {
    async fn read_v3(&self) -> super::super::V3Result<Option<V3AnchorState>> {
        if self.unreadable.load(Ordering::SeqCst) {
            return Err(V3FormatError::AnchorReadFailed);
        }
        self.inner.read_v3().await
    }

    async fn compare_and_advance_v3(
        &self,
        expected: Option<&V3AnchorState>,
        next: V3AnchorState,
    ) -> super::super::V3Result<V3AnchorState> {
        let accepted = self.inner.compare_and_advance_v3(expected, next).await?;
        if self.lose_next.swap(false, Ordering::SeqCst) {
            self.unreadable
                .store(self.lose_reconciliation, Ordering::SeqCst);
            return Err(V3FormatError::AnchorAdvanceFailed);
        }
        Ok(accepted)
    }
}

#[tokio::test]
async fn ambiguous_prefix_is_reconciled_before_any_successor_publication() {
    for lose_reconciliation in [false, true] {
        let Fixture {
            store,
            keyring,
            options,
            repository,
            anchor,
            coordinator,
        } = Fixture::new().await;
        drop(coordinator);
        let coordinator = Arc::new(must_repo(V3CommitCoordinator::with_options(
            Arc::clone(&repository),
            LostAdvanceReply {
                inner: anchor.clone(),
                lose_next: std::sync::atomic::AtomicBool::new(true),
                lose_reconciliation,
                unreadable: std::sync::atomic::AtomicBool::new(false),
            },
            CommitCoordinatorOptions::new(1, Duration::ZERO).with_max_pending_items(2),
        )));
        store.commit_put_pause.mode.store(1, Ordering::SeqCst);
        let first = tokio::spawn({
            let c = Arc::clone(&coordinator);
            async move {
                c.put_committed(
                    key("shared"),
                    Bytes::from_static(b"accepted once"),
                    RepositoryPutOptions::default(),
                )
                .await
            }
        });
        bounded(store.commit_put_pause.entered.notified()).await;
        let attempts = store.commit_put_pause.attempts.load(Ordering::SeqCst);
        let successor = tokio::spawn({
            let c = Arc::clone(&coordinator);
            async move {
                c.put_committed(
                    key("next"),
                    Bytes::from_static(b"next"),
                    RepositoryPutOptions::default(),
                )
                .await
            }
        });
        bounded(async {
            while coordinator.pending_item_count_for_tests().await != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        store.commit_put_pause.release.notify_one();
        let first = bounded(first).await.expect("first task");
        let successor = bounded(successor).await.expect("successor task");
        if lose_reconciliation {
            assert!(matches!(
                first,
                Err(RepositoryError::AcceptedRecoveryRequired)
            ));
            assert!(matches!(
                successor,
                Err(RepositoryError::AcceptedRecoveryRequired)
            ));
            assert!(coordinator.status().poisoned);
            assert_eq!(
                store.commit_put_pause.attempts.load(Ordering::SeqCst),
                attempts
            );
            drop(coordinator);
            assert!(
                matches!(
                    V3CommitCoordinator::new(Arc::clone(&repository), anchor.clone()),
                    Err(RepositoryError::AcceptedRecoveryRequired)
                ),
                "dropping the coordinator does not clear unknown acceptance"
            );
        } else {
            let first = must_repo(first);
            let successor = must_repo(successor);
            assert_eq!(
                successor.anchor_state.sequence.get(),
                first.anchor_state.sequence.get() + 1
            );
            assert_eq!(
                store.commit_put_pause.attempts.load(Ordering::SeqCst),
                attempts + 1,
                "only the successor adds an upload"
            );
            assert!(!coordinator.status().poisoned);
        }
        let fresh = V3Repository::new(store, keyring, RepositoryOptions::default(), options);
        must_repo(fresh.load_chain_from_anchor(&anchor).await);
        assert_eq!(
            must_repo(fresh.get_range(&key("shared"), ByteRange::Full).await),
            Bytes::from_static(b"accepted once")
        );
        assert_eq!(fresh.head(&key("next")).is_ok(), !lose_reconciliation);
    }
}

#[tokio::test]
async fn incompatible_protection_waits_for_frozen_prefix() {
    let f = Fixture::with_profile(V3ProviderProfile::RetainedVersionObjectLock).await;
    let first = f.pause(false).await;
    let strong = f.coordinator.put_committed(
        key("strong"),
        Bytes::from_static(b"strong"),
        RepositoryPutOptions {
            retention: Some(RetentionPolicy::new(RetentionMode::Compliance, 30)),
            ..RepositoryPutOptions::default()
        },
    );
    tokio::pin!(strong);
    assert!(futures_util::poll!(&mut strong).is_pending());
    assert_eq!(
        must_repo(f.repository.pending_operation_count_for_tests()),
        1,
        "incompatible successor must not enter the frozen protection cohort"
    );
    f.store.commit_put_pause.release.notify_one();
    let first = must_repo(bounded(first).await.expect("first task"));
    let strong = must_repo(bounded(strong).await);
    assert_eq!(
        strong.anchor_state.sequence.get(),
        first.anchor_state.sequence.get() + 1
    );
    assert_eq!(
        strong.metadata.retention,
        Some(RetentionPolicy::new(RetentionMode::Compliance, 30))
    );
    let fresh = f.reopened(strong.anchor_state).await;
    assert_eq!(
        must_repo(fresh.head(&key("strong"))).retention,
        strong.metadata.retention
    );
}

#[tokio::test]
async fn failed_prefix_rollback_poison_also_rejects_successor() {
    let f = Fixture::new().await;
    let before = must_v3(f.anchor.read_v3().await);
    let first = f.pause(true).await;
    let successor = f.put("next", b"dependent");
    f.staged_successor().await;
    f.repository.fail_next_restore_for_tests();
    f.store.commit_put_pause.release.notify_one();
    assert!(bounded(first).await.expect("first task").is_err());
    assert!(bounded(successor).await.expect("successor task").is_err());
    assert!(f.coordinator.status().poisoned);
    assert_eq!(must_v3(f.anchor.read_v3().await), before);
    assert!(
        bounded(f.put("later", b"refused"))
            .await
            .expect("later task")
            .is_err()
    );
}

#[tokio::test]
async fn canceled_immediate_publisher_keeps_ownership_until_resolution() {
    let f = Fixture::new().await;
    let first = f.pause(false).await;
    first.abort();
    assert!(bounded(first).await.is_err());
    let Fixture {
        store,
        repository,
        anchor,
        coordinator,
        ..
    } = f;
    drop(coordinator);
    assert!(V3CommitCoordinator::new(Arc::clone(&repository), anchor.clone()).is_err());
    store.commit_put_pause.release.notify_one();
    let replacement = bounded(async {
        loop {
            match V3CommitCoordinator::new(Arc::clone(&repository), anchor.clone()) {
                Ok(value) => break value,
                Err(RepositoryError::CommitFailed { .. }) => tokio::task::yield_now().await,
                Err(error) => panic!("unexpected replacement error: {error}"),
            }
        }
    })
    .await;
    assert!(!replacement.status().poisoned);
    assert_eq!(
        must_repo(repository.get_range(&key("shared"), ByteRange::Full).await),
        Bytes::from_static(b"first")
    );
}

#[tokio::test]
async fn copy_successor_binds_accepted_source_while_overwrite_is_publishing() {
    let f = Fixture::new().await;
    let original = must_repo(f.repository.head(&key("shared")));
    let first = f.pause(false).await;
    let copy = tokio::spawn({
        let c = Arc::clone(&f.coordinator);
        async move {
            c.copy_committed(
                key("shared"),
                key("copied"),
                crate::RepositoryCopyOptions {
                    source_if_match: Some(original.etag.to_s3_string()),
                },
            )
            .await
        }
    });
    f.staged_successor().await;
    assert!(matches!(
        f.repository.head(&key("copied")),
        Err(RepositoryError::NotFound(_))
    ));
    f.store.commit_put_pause.release.notify_one();
    must_repo(bounded(first).await.expect("overwriting put"));
    let copied = must_repo(bounded(copy).await.expect("copy task"));
    assert_eq!(copied.metadata.etag, original.etag);
    let fresh = f.reopened(copied.anchor_state).await;
    assert_eq!(
        must_repo(fresh.get_range(&key("shared"), ByteRange::Full).await),
        Bytes::from_static(b"first")
    );
    assert_eq!(
        must_repo(fresh.get_range(&key("copied"), ByteRange::Full).await),
        Bytes::from_static(b"base")
    );
}

#[tokio::test]
async fn copy_successor_rolls_back_with_failed_prefix_and_cancelled_waiter_remains_owned() {
    for fail_prefix in [true, false] {
        let f = Fixture::new().await;
        let first = f.pause(fail_prefix).await;
        let copy = tokio::spawn({
            let c = Arc::clone(&f.coordinator);
            async move {
                c.copy_committed(key("shared"), key("copied"), Default::default())
                    .await
            }
        });
        f.staged_successor().await;
        if !fail_prefix {
            copy.abort();
        }
        f.store.commit_put_pause.release.notify_one();
        let result = bounded(first).await.expect("prefix task");
        if fail_prefix {
            assert!(result.is_err());
            assert!(bounded(copy).await.expect("copy task").is_err());
            assert!(matches!(
                f.repository.head(&key("copied")),
                Err(RepositoryError::NotFound(_))
            ));
            assert_eq!(
                must_repo(f.repository.pending_operation_count_for_tests()),
                0
            );
        } else {
            must_repo(result);
            must_repo(bounded(f.coordinator.write_index_snapshot()).await);
            assert_eq!(
                must_repo(
                    f.repository
                        .get_range(&key("copied"), ByteRange::Full)
                        .await
                ),
                Bytes::from_static(b"base")
            );
        }
    }
}

#[tokio::test]
async fn copy_waits_for_maintenance_exclusion_and_unpublished_source_becomes_exact_before_capture()
{
    let f = Fixture::new().await;
    let window = must_repo(f.coordinator.begin_maintenance_window().await);
    let copy = f
        .coordinator
        .copy_committed(key("shared"), key("copied"), Default::default());
    tokio::pin!(copy);
    assert!(futures_util::poll!(&mut copy).is_pending());
    assert_eq!(
        must_repo(f.repository.pending_operation_count_for_tests()),
        0
    );
    drop(window);
    must_repo(bounded(copy).await);
    f.store.commit_put_pause.mode.store(1, Ordering::SeqCst);
    let source = f.put("new-source", b"new accepted bytes");
    bounded(f.store.commit_put_pause.entered.notified()).await;
    let second_copy = tokio::spawn({
        let c = Arc::clone(&f.coordinator);
        async move {
            c.copy_committed(key("new-source"), key("new-copy"), Default::default())
                .await
        }
    });
    assert!(matches!(
        f.repository.head(&key("new-source")),
        Err(RepositoryError::NotFound(_))
    ));
    f.store.commit_put_pause.release.notify_one();
    must_repo(bounded(source).await.expect("source task"));
    must_repo(bounded(second_copy).await.expect("copy task"));
    assert_eq!(
        must_repo(
            f.repository
                .get_range(&key("new-copy"), ByteRange::Full)
                .await
        ),
        Bytes::from_static(b"new accepted bytes")
    );
}
