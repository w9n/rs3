use super::*;
use crate::s3::test_support::runtime_config;
use rs3_repository::v2::{V2MemoryAnchor, V2Result};
use rs3_storage::{
    CountingBlobStore, FaultAction, FaultInjectingBlobStore, FaultMatcher, FaultOperationKind,
    FaultRule, MemoryBlobStore,
};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Default)]
struct MemoryJournal {
    bytes: Option<Vec<u8>>,
    saves: usize,
    fail: Option<(usize, bool)>,
    lose_guard: Option<(usize, Arc<AtomicBool>)>,
}

#[async_trait::async_trait]
impl Journal for MemoryJournal {
    fn state(&self) -> Result<Option<&[u8]>, S3BoundaryError> {
        Ok(self.bytes.as_deref())
    }
    async fn save(&mut self, bytes: &[u8], _evidence: Option<&str>) -> Result<(), S3BoundaryError> {
        self.saves += 1;
        if self.fail == Some((self.saves, false)) {
            return Err(invalid());
        }
        self.bytes = Some(bytes.to_vec());
        if let Some((at, live)) = &self.lose_guard
            && *at == self.saves
        {
            live.store(false, Ordering::SeqCst);
        }
        if self.fail == Some((self.saves, true)) {
            return Err(invalid());
        }
        Ok(())
    }
}

struct Guard(Arc<AtomicBool>);
impl Default for Guard {
    fn default() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }
}
#[async_trait::async_trait]
impl V2MaintenanceGuard for Guard {
    async fn verify_v2_maintenance(&self, _: Option<&V2AnchorState>) -> V2Result<()> {
        if self.0.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(V2FormatError::MaintenanceAccessRequired)
        }
    }
}

async fn run(
    config: &RuntimeConfig,
    store: &RuntimeStore,
    anchor: &RuntimeV2Anchor,
    journal: &mut MemoryJournal,
    guard: &Guard,
) -> Result<V2RepositoryInitReport, S3BoundaryError> {
    Bootstrap {
        config,
        store,
        anchor,
        guard,
        journal,
    }
    .run()
    .await
}

fn config(retained: bool) -> RuntimeConfig {
    let mut config = runtime_config(true);
    config.repository.retention =
        retained.then_some(RetentionPolicy::new(RetentionMode::Compliance, 1));
    config
}

#[tokio::test]
async fn every_journal_boundary_resumes_without_replacing_published_artifacts() {
    for retained in [false, true] {
        for save_at in 1..=7 {
            for after in [false, true] {
                let config = config(retained);
                let storage = CountingBlobStore::new(MemoryBlobStore::new());
                let store = RuntimeStore::new(storage.clone());
                let anchor = RuntimeV2Anchor::new(V2MemoryAnchor::new());
                let mut journal = MemoryJournal {
                    fail: Some((save_at, after)),
                    ..Default::default()
                };
                let guard = Guard::default();
                assert!(
                    run(&config, &store, &anchor, &mut journal, &guard)
                        .await
                        .is_err(),
                    "save {save_at} after={after}"
                );
                let existing = storage.list_prefix_versions("").await.expect("inventory");
                journal.fail = None;
                let report = run(&config, &store, &anchor, &mut journal, &guard)
                    .await
                    .expect("resume");
                assert_eq!(report.verified_commit_count, 1);
                let versions = storage.list_prefix_versions("").await.expect("versions");
                assert_eq!(
                    versions.len(),
                    3,
                    "three physical artifacts after save {save_at}"
                );
                assert_eq!(storage.operation_counts().expect("counts").put, 3);
                for previous in existing {
                    assert!(
                        versions
                            .iter()
                            .any(|entry| entry.object_id == previous.object_id
                                && entry.version_id == previous.version_id)
                    );
                }
                let again = run(&config, &store, &anchor, &mut journal, &guard)
                    .await
                    .expect("completed repeat");
                assert!(!again.initialized);
                assert_eq!(again.anchor, report.anchor);
                assert_eq!(storage.operation_counts().expect("counts").put, 3);
            }
        }
    }
}

#[tokio::test]
async fn each_artifact_put_reconciles_lost_reply_or_resumes_failed_attempt() {
    for prefix in ["keyrings/", "format/", "commits/"] {
        for after in [false, true] {
            let config = config(true);
            let storage = CountingBlobStore::new(MemoryBlobStore::new());
            let fault = FaultInjectingBlobStore::new(
                storage.clone(),
                vec![FaultRule::new(
                    FaultMatcher::operation(FaultOperationKind::Put).with_object_prefix(prefix),
                    if after {
                        FaultAction::error_after_write("fixture lost reply")
                    } else {
                        FaultAction::return_error("fixture unavailable")
                    },
                )],
            );
            let store = RuntimeStore::new(fault);
            let anchor = RuntimeV2Anchor::new(V2MemoryAnchor::new());
            let mut journal = MemoryJournal::default();
            let guard = Guard::default();
            let first = run(&config, &store, &anchor, &mut journal, &guard).await;
            assert_eq!(first.is_ok(), after);
            run(&config, &store, &anchor, &mut journal, &guard)
                .await
                .expect("resume");
            assert_eq!(storage.operation_counts().expect("counts").put, 3);
            assert_eq!(
                storage
                    .list_prefix_versions("")
                    .await
                    .expect("versions")
                    .len(),
                3
            );
        }
    }
}

#[tokio::test]
async fn lost_writer_guard_after_reservation_prevents_the_dependent_put() {
    for (save_at, written) in [(2, 0), (4, 1), (6, 2)] {
        let config = config(false);
        let storage = CountingBlobStore::new(MemoryBlobStore::new());
        let store = RuntimeStore::new(storage.clone());
        let anchor = RuntimeV2Anchor::new(V2MemoryAnchor::new());
        let guard = Guard::default();
        let mut journal = MemoryJournal {
            lose_guard: Some((save_at, Arc::clone(&guard.0))),
            ..Default::default()
        };
        assert!(
            run(&config, &store, &anchor, &mut journal, &guard)
                .await
                .is_err()
        );
        assert_eq!(storage.operation_counts().expect("counts").put, written);
        assert!(anchor.read_v2().await.expect("anchor").is_none());
        guard.0.store(true, Ordering::SeqCst);
        journal.lose_guard = None;
        run(&config, &store, &anchor, &mut journal, &guard)
            .await
            .expect("new holder resumes");
        assert_eq!(storage.operation_counts().expect("counts").put, 3);
    }
}

#[tokio::test]
async fn exhausted_artifact_budgets_allow_reconciliation_but_never_new_puts() {
    for save_at in [2, 4, 6] {
        let config = config(true);
        let storage = CountingBlobStore::new(MemoryBlobStore::new());
        let store = RuntimeStore::new(storage.clone());
        let anchor = RuntimeV2Anchor::new(V2MemoryAnchor::new());
        let guard = Guard::default();
        let mut journal = MemoryJournal {
            fail: Some((save_at, true)),
            ..Default::default()
        };
        assert!(
            run(&config, &store, &anchor, &mut journal, &guard)
                .await
                .is_err()
        );
        let intent = journal.bytes.clone().expect("persisted intent");
        let mut record = decode(&intent, &context(&config).expect("context")).expect("record");
        match &mut record.phase {
            Phase::Keyring { artifact } | Phase::Format { artifact, .. } => artifact.remaining = 0,
            Phase::Genesis { remaining, .. } => *remaining = 0,
            _ => panic!("unfinished phase"),
        }
        journal.fail = None;
        save(&mut journal, &record)
            .await
            .expect("fixture exhausted budget");
        let before = storage.operation_counts().expect("counts").put;
        for _ in 0..4 {
            assert!(
                run(&config, &store, &anchor, &mut journal, &guard)
                    .await
                    .is_err()
            );
        }
        assert_eq!(storage.operation_counts().expect("counts").put, before);
        // Simulate the reserved in-flight PUT becoming visible after stale NotFound.
        match &record.phase {
            Phase::Keyring { artifact } | Phase::Format { artifact, .. } => {
                store
                    .put(
                        &artifact.object_id,
                        Bytes::copy_from_slice(&artifact.body),
                        PutOptions {
                            retention: config.repository.retention,
                            ..Default::default()
                        },
                    )
                    .await
                    .expect("delayed PUT");
            }
            Phase::Genesis {
                keyring,
                format,
                intent,
                ..
            } => {
                let root = open_format_root(&store, &config.repository_keys, format)
                    .await
                    .expect("format");
                let engine = Bootstrap {
                    config: &config,
                    store: &store,
                    anchor: &anchor,
                    guard: &guard,
                    journal: &mut journal,
                };
                let loaded = engine
                    .load_dependencies(keyring, &root, format)
                    .await
                    .expect("dependencies");
                let options = bootstrap_commit_options(&config, &loaded).expect("options");
                let commits = V2CommitStore::new(store.clone(), loaded.keyring, options);
                let prepared = commits.open_prepared_genesis(intent).expect("intent");
                commits
                    .publish_prepared_genesis_with_guard(&anchor, &prepared, true, &guard)
                    .await
                    .expect("delayed publication");
            }
            _ => panic!("unfinished phase"),
        }
        run(&config, &store, &anchor, &mut journal, &guard)
            .await
            .expect("zero-budget reconciliation");
        assert_eq!(
            storage
                .list_prefix_versions("")
                .await
                .expect("versions")
                .len(),
            3
        );
    }
}

#[tokio::test]
async fn missing_anchor_or_journal_requires_recovery_and_changed_context_never_writes() {
    let config = config(false);
    let storage = CountingBlobStore::new(MemoryBlobStore::new());
    let store = RuntimeStore::new(storage.clone());
    let anchor = RuntimeV2Anchor::new(V2MemoryAnchor::new());
    let guard = Guard::default();
    let mut journal = MemoryJournal {
        fail: Some((2, false)),
        ..Default::default()
    };
    assert!(
        run(&config, &store, &anchor, &mut journal, &guard)
            .await
            .is_err()
    );
    journal.fail = None;
    let original = journal.bytes.clone();
    for field in 0..7 {
        let mut changed = config.clone();
        match field {
            0 => changed.backend.bucket.push_str("different"),
            1 => changed.backend.prefix = Some("different".to_owned()),
            2 => changed
                .repository_keys
                .wrapping_key_id
                .push_str("different"),
            3 => {
                changed.repository_keys.wrapping_key_hex =
                    secrecy::SecretString::from("77".repeat(32))
            }
            4 => changed.repository_keys.repository_salt_hex = "33".repeat(32),
            5 => changed.provider_conformance.principal_fingerprint = Some("ab".repeat(32)),
            6 => {
                changed.repository.retention =
                    Some(RetentionPolicy::new(RetentionMode::Compliance, 1))
            }
            _ => unreachable!(),
        }
        assert!(
            run(&changed, &store, &anchor, &mut journal, &guard)
                .await
                .is_err()
        );
        assert_eq!(journal.bytes, original);
        assert_eq!(storage.operation_counts().expect("counts").put, 0);
    }
    let report = run(&config, &store, &anchor, &mut journal, &guard)
        .await
        .expect("initialize");
    let missing = RuntimeV2Anchor::new(V2MemoryAnchor::new());
    assert!(
        run(&config, &store, &missing, &mut journal, &guard)
            .await
            .is_err()
    );
    let mut blank = MemoryJournal::default();
    assert!(
        run(&config, &store, &missing, &mut blank, &guard)
            .await
            .is_err()
    );
    assert!(blank.bytes.is_none());
    let existing = run(&config, &store, &anchor, &mut blank, &guard)
        .await
        .expect("trusted existing anchor");
    assert!(!existing.initialized);
    assert_eq!(existing.anchor, report.anchor);
    assert_eq!(storage.operation_counts().expect("counts").put, 3);
}

#[test]
fn journal_decode_rejects_oversize_unknown_schema_fields_and_budget() {
    let record = Record {
        schema: SCHEMA.to_owned(),
        context: "context".to_owned(),
        phase: Phase::Keyring {
            artifact: Artifact::new(BackendObjectId::new("opaque").expect("id"), vec![1]),
        },
    };
    let value = serde_json::to_value(&record).expect("JSON");
    for field in ["schema", "context", "extra"] {
        let mut changed = value.clone();
        changed[field] = serde_json::json!("wrong");
        assert!(decode(&serde_json::to_vec(&changed).expect("bytes"), "context").is_err());
    }
    let mut record = record;
    if let Phase::Keyring { artifact } = &mut record.phase {
        artifact.remaining = WRITE_ATTEMPTS + 1;
    }
    assert!(decode(&serde_json::to_vec(&record).expect("bytes"), "context").is_err());
    assert!(decode(&vec![b' '; MAX_BOOTSTRAP_JOURNAL_BYTES + 1], "context").is_err());
}

#[tokio::test]
async fn failed_put_attempts_exhaust_the_persisted_budget_across_restarts() {
    for (save_at, prefix) in [(2, "keyrings/"), (4, "format/"), (6, "commits/")] {
        let config = config(true);
        let memory = MemoryBlobStore::new();
        let store = RuntimeStore::new(memory.clone());
        let anchor = RuntimeV2Anchor::new(V2MemoryAnchor::new());
        let guard = Guard::default();
        // Stop before the first reservation is persisted for this stage.
        let mut journal = MemoryJournal {
            fail: Some((save_at, false)),
            ..Default::default()
        };
        assert!(
            run(&config, &store, &anchor, &mut journal, &guard)
                .await
                .is_err()
        );
        journal.fail = None;
        let faults = FaultInjectingBlobStore::new(
            memory.clone(),
            (0..WRITE_ATTEMPTS)
                .map(|_| {
                    FaultRule::new(
                        FaultMatcher::operation(FaultOperationKind::Put).with_object_prefix(prefix),
                        FaultAction::return_error("fixture PUT unavailable"),
                    )
                })
                .collect(),
        );
        let attempts = CountingBlobStore::new(faults);
        let store = RuntimeStore::new(attempts.clone());
        for expected in 1..=WRITE_ATTEMPTS {
            assert!(
                run(&config, &store, &anchor, &mut journal, &guard)
                    .await
                    .is_err()
            );
            assert_eq!(
                attempts.operation_counts().expect("counts").put,
                u64::from(expected)
            );
        }
        // The next provider PUT would succeed, but no allowance remains.
        for _ in 0..3 {
            let error = run(&config, &store, &anchor, &mut journal, &guard)
                .await
                .expect_err("exhausted budget");
            assert!(error.to_string().contains("budget exhausted"));
        }
        assert_eq!(
            attempts.operation_counts().expect("counts").put,
            u64::from(WRITE_ATTEMPTS)
        );
        assert!(anchor.read_v2().await.expect("anchor").is_none());
    }
}

#[tokio::test]
async fn corrupted_planned_artifacts_fail_before_dependent_writes() {
    for save_at in [2, 4, 6] {
        let config = config(false);
        let storage = CountingBlobStore::new(MemoryBlobStore::new());
        let store = RuntimeStore::new(storage.clone());
        let anchor = RuntimeV2Anchor::new(V2MemoryAnchor::new());
        let guard = Guard::default();
        let mut journal = MemoryJournal {
            fail: Some((save_at, false)),
            ..Default::default()
        };
        assert!(
            run(&config, &store, &anchor, &mut journal, &guard)
                .await
                .is_err()
        );
        let mut record = decode(
            journal.bytes.as_deref().expect("intent"),
            &context(&config).expect("context"),
        )
        .expect("record");
        match &mut record.phase {
            Phase::Keyring { artifact } | Phase::Format { artifact, .. } => {
                let last = artifact.body.last_mut().expect("body");
                *last ^= 1;
            }
            Phase::Genesis { intent, .. } => {
                let last = intent.last_mut().expect("intent");
                *last ^= 1;
            }
            _ => panic!("unfinished phase"),
        }
        journal.fail = None;
        save(&mut journal, &record)
            .await
            .expect("corrupted fixture");
        let before = storage.operation_counts().expect("counts");
        assert!(
            run(&config, &store, &anchor, &mut journal, &guard)
                .await
                .is_err()
        );
        let after = storage.operation_counts().expect("counts");
        assert_eq!(after.put, before.put);
        assert!(anchor.read_v2().await.expect("anchor").is_none());
    }
}

struct LostReply {
    inner: V2MemoryAnchor,
    next_read_fails: AtomicBool,
}
#[async_trait::async_trait]
impl V2CommitAnchor for LostReply {
    async fn read_v2(&self) -> V2Result<Option<V2AnchorState>> {
        if self.next_read_fails.swap(false, Ordering::SeqCst) {
            return Err(V2FormatError::AnchorReadFailed);
        }
        self.inner.read_v2().await
    }
    async fn compare_and_advance_v2(
        &self,
        expected: Option<&V2AnchorState>,
        next: V2AnchorState,
    ) -> V2Result<V2AnchorState> {
        self.inner.compare_and_advance_v2(expected, next).await?;
        self.next_read_fails.store(true, Ordering::SeqCst);
        Err(V2FormatError::AnchorAdvanceFailed)
    }
}

#[tokio::test]
async fn journal_resumes_after_lost_anchor_reply_and_failed_reconciliation() {
    let config = config(true);
    let storage = CountingBlobStore::new(MemoryBlobStore::new());
    let store = RuntimeStore::new(storage.clone());
    let inner = V2MemoryAnchor::new();
    let anchor = RuntimeV2Anchor::new(LostReply {
        inner: inner.clone(),
        next_read_fails: AtomicBool::new(false),
    });
    let guard = Guard::default();
    let mut journal = MemoryJournal::default();
    assert!(
        run(&config, &store, &anchor, &mut journal, &guard)
            .await
            .is_err()
    );
    let accepted = inner
        .read_v2()
        .await
        .expect("actual accepted state")
        .expect("genesis");
    let report = run(&config, &store, &anchor, &mut journal, &guard)
        .await
        .expect("reconcile");
    assert_eq!(report.anchor, accepted);
    assert_eq!(storage.operation_counts().expect("counts").put, 3);
    assert_eq!(
        storage
            .list_prefix_versions("")
            .await
            .expect("versions")
            .len(),
        3
    );
}
