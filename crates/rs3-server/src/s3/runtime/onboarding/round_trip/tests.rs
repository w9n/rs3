use super::super::tests::{Guard, MemoryJournal};
use super::*;
use rs3_repository::v3::V3MemoryAnchor;
use rs3_storage::{CountingBlobStore, MemoryBlobStore};

async fn bootstrap_fixture(
    config: &RuntimeConfig,
    store: &RuntimeStore,
    anchor: &RuntimeV3Anchor,
    backing: &mut MemoryJournal,
) -> V3RepositoryInitReport {
    let mut journal = OnboardingJournal::open(backing, config, None).expect("journal");
    let handoff = journal.salt.clone();
    bootstrap::initialize(
        config,
        store,
        anchor,
        &Guard::default(),
        &mut journal,
        Some(handoff),
    )
    .await
    .expect("bootstrap")
}

#[tokio::test]
async fn every_restore_journal_boundary_resumes_without_duplicate_publication() {
    for retained in [false, true] {
        for at in 1..=5 {
            for after in [false, true] {
                let mut config = crate::s3::test_support::runtime_config(true);
                config.repository.retention =
                    retained.then_some(RetentionPolicy::new(RetentionMode::Compliance, 1));
                let storage = CountingBlobStore::new(MemoryBlobStore::new());
                let store = RuntimeStore::new(storage.clone());
                let anchor = RuntimeV3Anchor::new(V3MemoryAnchor::new());
                let mut backing = MemoryJournal::default();
                let mut report = bootstrap_fixture(&config, &store, &anchor, &mut backing).await;
                let genesis = report.anchor.clone();
                backing.fail = Some((backing.saves + at, after));
                {
                    let mut journal =
                        OnboardingJournal::open(&mut backing, &config, None).expect("journal");
                    assert!(
                        verify(
                            &config,
                            &store,
                            &anchor,
                            &Guard::default(),
                            &mut journal,
                            &mut report
                        )
                        .await
                        .is_err(),
                        "at {at}, after {after}"
                    );
                }
                backing.fail = None;
                // Real retry reloads accepted state before any new publication.
                report = bootstrap_fixture(&config, &store, &anchor, &mut backing).await;
                let mut journal =
                    OnboardingJournal::open(&mut backing, &config, None).expect("journal");
                verify(
                    &config,
                    &store,
                    &anchor,
                    &Guard::default(),
                    &mut journal,
                    &mut report,
                )
                .await
                .expect("resume");
                assert!(
                    journal
                        .record
                        .round_trip
                        .as_ref()
                        .is_some_and(State::complete)
                );
                assert_eq!(report.anchor.sequence.get(), genesis.sequence.get() + 2);
                let (key, _) = fixture(&journal.record.probe_root).expect("key");
                let (reader, _, _) = reopen(&config, &store, &anchor)
                    .await
                    .expect("fresh reader");
                assert!(matches!(
                    reader.head(&key),
                    Err(RepositoryError::NotFound(_))
                ));
                let counts = storage.operation_counts().expect("counts");
                verify(
                    &config,
                    &store,
                    &anchor,
                    &Guard::default(),
                    &mut journal,
                    &mut report,
                )
                .await
                .expect("reuse");
                assert_eq!(
                    storage.operation_counts().expect("counts"),
                    counts,
                    "complete step does no IO"
                );
            }
        }
    }
}

#[tokio::test]
async fn rejected_puts_exhaust_the_durable_budget_and_writer_loss_prevents_io() {
    use rs3_storage::{
        FaultAction, FaultInjectingBlobStore, FaultMatcher, FaultOperationKind, FaultRule,
    };
    use std::sync::atomic::Ordering;
    let config = crate::s3::test_support::runtime_config(true);
    let faults = FaultInjectingBlobStore::new(MemoryBlobStore::new(), vec![]);
    let storage = CountingBlobStore::new(faults.clone());
    let store = RuntimeStore::new(storage.clone());
    let anchor = RuntimeV3Anchor::new(V3MemoryAnchor::new());
    let mut backing = MemoryJournal::default();
    let mut report = bootstrap_fixture(&config, &store, &anchor, &mut backing).await;
    let baseline = report.anchor.clone();
    for remaining in (0..3).rev() {
        faults
            .push_rule(FaultRule::new(
                FaultMatcher::operation(FaultOperationKind::Put),
                FaultAction::return_error("fixture write denied"),
            ))
            .expect("fault");
        let mut journal = OnboardingJournal::open(&mut backing, &config, None).expect("journal");
        assert!(
            verify(
                &config,
                &store,
                &anchor,
                &Guard::default(),
                &mut journal,
                &mut report
            )
            .await
            .is_err()
        );
        assert!(
            matches!(journal.record.round_trip, Some(State::Planned { remaining: actual, .. }) if actual == remaining)
        );
    }
    let puts = storage.operation_counts().expect("counts").put;
    let mut journal = OnboardingJournal::open(&mut backing, &config, None).expect("journal");
    assert!(
        verify(
            &config,
            &store,
            &anchor,
            &Guard::default(),
            &mut journal,
            &mut report
        )
        .await
        .is_err()
    );
    assert_eq!(storage.operation_counts().expect("counts").put, puts);
    assert_eq!(anchor.read_v3().await.expect("anchor"), Some(baseline));
    let guard = Guard::default();
    guard.0.store(false, Ordering::SeqCst);
    let counts = storage.operation_counts().expect("counts");
    assert!(
        verify(&config, &store, &anchor, &guard, &mut journal, &mut report)
            .await
            .is_err()
    );
    assert_eq!(storage.operation_counts().expect("counts"), counts);
}

#[tokio::test]
async fn unexpected_fixture_bytes_are_not_overwritten_or_deleted() {
    let config = crate::s3::test_support::runtime_config(true);
    let storage = CountingBlobStore::new(MemoryBlobStore::new());
    let store = RuntimeStore::new(storage.clone());
    let anchor = RuntimeV3Anchor::new(V3MemoryAnchor::new());
    let mut backing = MemoryJournal::default();
    let mut report = bootstrap_fixture(&config, &store, &anchor, &mut backing).await;
    // Stop after publication/readback, before recording verification.
    backing.fail = Some((backing.saves + 3, false));
    let key;
    let body;
    {
        let mut journal = OnboardingJournal::open(&mut backing, &config, None).expect("journal");
        (key, body) = fixture(&journal.record.probe_root).expect("fixture");
        assert!(
            verify(
                &config,
                &store,
                &anchor,
                &Guard::default(),
                &mut journal,
                &mut report
            )
            .await
            .is_err()
        );
    }
    backing.fail = None;
    let (repository, _, _) = reopen(&config, &store, &anchor).await.expect("reopen");
    let replacement = Bytes::from(vec![b'X'; body.len()]);
    repository
        .put_committed(
            &anchor,
            key.clone(),
            replacement.clone(),
            RepositoryPutOptions::default(),
        )
        .await
        .expect("different same-length bytes");
    let before = storage.operation_counts().expect("counts").put;
    let mut journal = OnboardingJournal::open(&mut backing, &config, None).expect("journal");
    assert!(
        verify(
            &config,
            &store,
            &anchor,
            &Guard::default(),
            &mut journal,
            &mut report
        )
        .await
        .is_err()
    );
    assert_eq!(storage.operation_counts().expect("counts").put, before);
    assert_eq!(
        repository
            .get_range(&key, ByteRange::Full)
            .await
            .expect("untouched replacement"),
        replacement
    );
    assert!(
        !journal
            .record
            .round_trip
            .as_ref()
            .is_some_and(State::complete)
    );
}

#[derive(Clone)]
struct LostReply {
    inner: V3MemoryAnchor,
    fail_at: Sequence,
    fail_read: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait::async_trait]
impl V3CommitAnchor for LostReply {
    async fn read_v3(&self) -> rs3_repository::v3::V3Result<Option<V3AnchorState>> {
        if self
            .fail_read
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(rs3_repository::v3::V3FormatError::AnchorReadFailed);
        }
        self.inner.read_v3().await
    }
    async fn compare_and_advance_v3(
        &self,
        expected: Option<&V3AnchorState>,
        next: V3AnchorState,
    ) -> rs3_repository::v3::V3Result<V3AnchorState> {
        let accepted = self.inner.compare_and_advance_v3(expected, next).await?;
        if accepted.sequence == self.fail_at {
            self.fail_read
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Err(rs3_repository::v3::V3FormatError::AnchorAdvanceFailed)
        } else {
            Ok(accepted)
        }
    }
}

#[tokio::test]
async fn lost_publication_replies_reconcile_before_another_write() {
    for delta in [1, 2] {
        let config = crate::s3::test_support::runtime_config(true);
        let storage = CountingBlobStore::new(MemoryBlobStore::new());
        let store = RuntimeStore::new(storage.clone());
        let inner = V3MemoryAnchor::new();
        let mut anchor = RuntimeV3Anchor::new(inner.clone());
        let mut backing = MemoryJournal::default();
        let mut report = bootstrap_fixture(&config, &store, &anchor, &mut backing).await;
        let genesis = report.anchor.clone();
        anchor = RuntimeV3Anchor::new(LostReply {
            inner,
            fail_at: Sequence::new(genesis.sequence.get() + delta),
            fail_read: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        });
        {
            let mut journal =
                OnboardingJournal::open(&mut backing, &config, None).expect("journal");
            assert!(
                verify(
                    &config,
                    &store,
                    &anchor,
                    &Guard::default(),
                    &mut journal,
                    &mut report
                )
                .await
                .is_err()
            );
        }
        report = bootstrap_fixture(&config, &store, &anchor, &mut backing).await;
        let mut journal = OnboardingJournal::open(&mut backing, &config, None).expect("journal");
        verify(
            &config,
            &store,
            &anchor,
            &Guard::default(),
            &mut journal,
            &mut report,
        )
        .await
        .expect("resume accepted state");
        assert_eq!(report.anchor.sequence.get(), genesis.sequence.get() + 2);
        assert!(
            journal
                .record
                .round_trip
                .as_ref()
                .is_some_and(State::complete)
        );
    }
}

#[tokio::test]
async fn corrupt_ciphertext_blocks_restore_even_when_authenticated_metadata_opens() {
    use rs3_repository::v3::{V3SectionType, parse_v3_commit_header};
    let config = crate::s3::test_support::runtime_config(true);
    let directory = super::super::super::tests::TestDir::new();
    let storage = CountingBlobStore::new(
        rs3_storage::FilesystemBlobStore::new(directory.path()).expect("filesystem store"),
    );
    let store = RuntimeStore::new(storage.clone());
    let anchor = RuntimeV3Anchor::new(V3MemoryAnchor::new());
    let mut backing = MemoryJournal::default();
    let mut report = bootstrap_fixture(&config, &store, &anchor, &mut backing).await;
    backing.fail = Some((backing.saves + 3, false));
    let key;
    {
        let mut journal = OnboardingJournal::open(&mut backing, &config, None).expect("journal");
        key = fixture(&journal.record.probe_root).expect("fixture").0;
        assert!(
            verify(
                &config,
                &store,
                &anchor,
                &Guard::default(),
                &mut journal,
                &mut report
            )
            .await
            .is_err()
        );
    }
    backing.fail = None;
    let accepted = anchor
        .read_v3()
        .await
        .expect("anchor")
        .expect("accepted PUT");
    let loaded = load_existing_v3_repository(&store, &config.repository_keys, &accepted, &config)
        .await
        .expect("keys");
    let mut bytes = storage
        .get_range(&accepted.commit_key, ByteRange::Full)
        .await
        .expect("commit")
        .to_vec();
    let parsed =
        parse_v3_commit_header(&accepted.commit_key, &bytes, &loaded.keyring).expect("header");
    let payload = parsed
        .header
        .section_index
        .iter()
        .find(|section| section.section_type == V3SectionType::PayloadPack)
        .expect("payload section");
    let last = parsed.sections_start
        + usize::try_from(payload.offset + payload.length).expect("payload end")
        - 1;
    bytes[last] ^= 1;
    // Model a malicious unretained backend without altering the signed header
    // or encrypted namespace index. A metadata-only test would still pass.
    storage
        .put(
            &accepted.commit_key,
            Bytes::from(bytes),
            PutOptions::default(),
        )
        .await
        .expect("corrupt payload only");
    let (reader, _, _) = reopen(&config, &store, &anchor)
        .await
        .expect("authenticated metadata opens");
    reader.head(&key).expect("HEAD still succeeds");
    let before = storage.operation_counts().expect("counts").put;
    let mut journal = OnboardingJournal::open(&mut backing, &config, None).expect("journal");
    assert!(
        verify(
            &config,
            &store,
            &anchor,
            &Guard::default(),
            &mut journal,
            &mut report
        )
        .await
        .is_err()
    );
    assert_eq!(storage.operation_counts().expect("counts").put, before);
    assert!(
        !journal
            .record
            .round_trip
            .as_ref()
            .is_some_and(State::complete)
    );
}

#[tokio::test]
async fn failed_tombstone_publications_exhaust_the_delete_budget_without_readiness() {
    use rs3_storage::{
        FaultAction, FaultInjectingBlobStore, FaultMatcher, FaultOperationKind, FaultRule,
    };
    let config = crate::s3::test_support::runtime_config(true);
    let faults = FaultInjectingBlobStore::new(MemoryBlobStore::new(), vec![]);
    let storage = CountingBlobStore::new(faults.clone());
    let store = RuntimeStore::new(storage.clone());
    let anchor = RuntimeV3Anchor::new(V3MemoryAnchor::new());
    let mut backing = MemoryJournal::default();
    let mut report = bootstrap_fixture(&config, &store, &anchor, &mut backing).await;
    backing.fail = Some((backing.saves + 3, true));
    {
        let mut journal = OnboardingJournal::open(&mut backing, &config, None).expect("journal");
        assert!(
            verify(
                &config,
                &store,
                &anchor,
                &Guard::default(),
                &mut journal,
                &mut report
            )
            .await
            .is_err()
        );
    }
    backing.fail = None;
    let accepted = anchor.read_v3().await.expect("accepted PUT");
    for remaining in (0..3).rev() {
        faults
            .push_rule(FaultRule::new(
                FaultMatcher::operation(FaultOperationKind::Put),
                FaultAction::return_error("tombstone denied"),
            ))
            .expect("fault");
        let mut journal = OnboardingJournal::open(&mut backing, &config, None).expect("journal");
        assert!(
            verify(
                &config,
                &store,
                &anchor,
                &Guard::default(),
                &mut journal,
                &mut report
            )
            .await
            .is_err()
        );
        assert!(
            matches!(journal.record.round_trip, Some(State::Verified { remaining: actual, .. }) if actual == remaining)
        );
    }
    let puts = storage.operation_counts().expect("counts").put;
    let mut journal = OnboardingJournal::open(&mut backing, &config, None).expect("journal");
    assert!(
        verify(
            &config,
            &store,
            &anchor,
            &Guard::default(),
            &mut journal,
            &mut report
        )
        .await
        .is_err()
    );
    assert_eq!(storage.operation_counts().expect("counts").put, puts);
    assert_eq!(
        anchor.read_v3().await.expect("unchanged accepted state"),
        accepted
    );
    assert!(
        !journal
            .record
            .round_trip
            .as_ref()
            .is_some_and(State::complete)
    );
}
