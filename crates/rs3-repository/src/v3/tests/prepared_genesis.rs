//! Prepared bootstrap tests cross real storage, encoding and anchor boundaries.

use super::*;
use rs3_storage::{
    FaultAction, FaultInjectingBlobStore, FaultMatcher, FaultOperationKind, FaultRule,
};
use std::sync::atomic::AtomicBool;

fn options(retained: bool) -> V3CommitStoreOptions {
    V3CommitStoreOptions::for_profile(
        if retained {
            V3ProviderProfile::RetainedVersionObjectLock
        } else {
            V3ProviderProfile::Dev
        },
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    )
    .with_retention(retained.then_some(RetentionPolicy::new(RetentionMode::Compliance, 1)))
}

#[tokio::test]
async fn prepared_genesis_without_upload_allowance_only_reconciles_existing_data() {
    for retained in [false, true] {
        let store = CountingBlobStore::new(MemoryBlobStore::new());
        let writer = V3CommitStore::new(store.clone(), signing_keyring(), options(retained));
        let prepared = must_v3(writer.prepare_genesis_snapshot());
        let anchor = V3MemoryAnchor::new();
        for _ in 0..4 {
            assert_eq!(
                writer
                    .publish_prepared_genesis(&anchor, &prepared, false)
                    .await,
                Err(V3FormatError::BootstrapUploadRequired)
            );
        }
        assert_eq!(store.operation_counts().expect("counts").put, 0);
        assert!(must_v3(anchor.read_v3().await).is_none());
        let accepted = must_v3(
            writer
                .publish_prepared_genesis(&anchor, &prepared, true)
                .await,
        );
        let reconciled = must_v3(
            writer
                .publish_prepared_genesis(&anchor, &prepared, false)
                .await,
        );
        assert_eq!(reconciled, accepted);
        assert_eq!(store.operation_counts().expect("counts").put, 1);
    }
}

struct LostReplyAnchor {
    inner: V3MemoryAnchor,
    fail_reconciliation: bool,
    next_read_fails: AtomicBool,
    advances: AtomicUsize,
}

#[async_trait::async_trait]
impl V3CommitAnchor for LostReplyAnchor {
    async fn read_v3(&self) -> super::super::V3Result<Option<V3AnchorState>> {
        if self.next_read_fails.swap(false, Ordering::SeqCst) {
            return Err(V3FormatError::AnchorReadFailed);
        }
        self.inner.read_v3().await
    }

    async fn compare_and_advance_v3(
        &self,
        expected: Option<&V3AnchorState>,
        next: V3AnchorState,
    ) -> super::super::V3Result<V3AnchorState> {
        self.advances.fetch_add(1, Ordering::SeqCst);
        self.inner.compare_and_advance_v3(expected, next).await?;
        self.next_read_fails
            .store(self.fail_reconciliation, Ordering::SeqCst);
        Err(V3FormatError::AnchorAdvanceFailed)
    }
}

#[tokio::test]
async fn prepared_genesis_reconciles_lost_anchor_reply_without_overwriting_newer_state() {
    for fail_reconciliation in [false, true] {
        let store = CountingBlobStore::new(MemoryBlobStore::new());
        let writer = V3CommitStore::new(store.clone(), signing_keyring(), options(true));
        let prepared = must_v3(writer.prepare_genesis_snapshot());
        let encoded = must_v3(prepared.to_journal_bytes());
        assert_eq!(
            store.operation_counts().expect("counts"),
            Default::default()
        );
        let anchor = LostReplyAnchor {
            inner: V3MemoryAnchor::new(),
            fail_reconciliation,
            next_read_fails: AtomicBool::new(false),
            advances: AtomicUsize::new(0),
        };
        let first = writer
            .publish_prepared_genesis(&anchor, &prepared, true)
            .await;
        assert_eq!(first.is_err(), fail_reconciliation);
        if fail_reconciliation {
            assert_eq!(first, Err(V3FormatError::AnchorReadFailed));
        }
        let reader = V3CommitStore::new(store.clone(), signing_keyring(), options(true));
        let restored = must_v3(reader.open_prepared_genesis(&encoded));
        assert_eq!(must_v3(restored.to_journal_bytes()), encoded);
        let accepted = must_v3(
            reader
                .publish_prepared_genesis(&anchor, &restored, false)
                .await,
        );
        assert_eq!(store.operation_counts().expect("counts").put, 1);
        assert_eq!(anchor.advances.load(Ordering::SeqCst), 1);
        assert_eq!(must_v3(anchor.read_v3().await), Some(accepted.anchor_state));

        let child = must_v3(
            reader
                .write_child_commit(
                    &anchor.inner,
                    V3CommitWrite::delta(vec![V3CommitSection::new(
                        V3SectionType::IndexRun,
                        V3_SECTION_FLAG_MUST_UNDERSTAND,
                        Bytes::from_static(b"new state"),
                    )]),
                )
                .await,
        );
        let before = store.operation_counts().expect("counts");
        assert_eq!(
            reader
                .publish_prepared_genesis(&anchor, &restored, false)
                .await,
            Err(V3FormatError::StaleAnchor)
        );
        assert_eq!(store.operation_counts().expect("counts"), before);
        assert_eq!(must_v3(anchor.read_v3().await), Some(child.anchor_state));
    }
}

#[tokio::test]
async fn prepared_genesis_resumes_after_upload_without_another_physical_version() {
    for retained in [false, true] {
        let store = CountingBlobStore::new(MemoryBlobStore::new());
        let writer = V3CommitStore::new(store.clone(), signing_keyring(), options(retained));
        let prepared = must_v3(writer.prepare_genesis_snapshot());
        let journal = must_v3(prepared.to_journal_bytes());
        let anchor = FailOnceV3Anchor::new(V3MemoryAnchor::new());
        assert_eq!(
            writer
                .publish_prepared_genesis(&anchor, &prepared, true)
                .await,
            Err(V3FormatError::AnchorAdvanceFailed)
        );
        assert_eq!(store.operation_counts().expect("counts").put, 1);
        assert!(must_v3(anchor.read_v3().await).is_none());
        drop(writer);
        let restarted = V3CommitStore::new(store.clone(), signing_keyring(), options(retained));
        let recovered = must_v3(restarted.open_prepared_genesis(&journal));
        let accepted = must_v3(
            restarted
                .publish_prepared_genesis(&anchor, &recovered, false)
                .await,
        );
        assert_eq!(store.operation_counts().expect("counts").put, 1);
        assert_eq!(
            must_v3(restarted.read_anchor_head(&anchor).await)
                .expect("commit")
                .version_id,
            accepted.version_id
        );
    }
}

#[tokio::test]
async fn prepared_genesis_reconciles_ambiguous_retained_put_by_exact_bytes() {
    let store = CountingBlobStore::new(MemoryBlobStore::new());
    let faulty = FaultInjectingBlobStore::new(
        store.clone(),
        vec![FaultRule::new(
            FaultMatcher::operation(FaultOperationKind::Put),
            FaultAction::error_after_write("lost fixture PUT reply"),
        )],
    );
    let writer = V3CommitStore::new(faulty, signing_keyring(), options(true));
    let anchor = V3MemoryAnchor::new();
    let prepared = must_v3(writer.prepare_genesis_snapshot());
    let accepted = must_v3(
        writer
            .publish_prepared_genesis(&anchor, &prepared, true)
            .await,
    );
    assert!(accepted.version_id.is_some());
    assert_eq!(store.operation_counts().expect("counts").put, 1);
    assert_eq!(must_v3(anchor.read_v3().await), Some(accepted.anchor_state));
}

#[tokio::test]
async fn prepared_genesis_rejects_corrupt_backend_and_never_recreates_accepted_data() {
    let store = CountingBlobStore::new(MemoryBlobStore::new());
    let writer = V3CommitStore::new(store.clone(), signing_keyring(), options(false));
    let anchor = FailOnceV3Anchor::new(V3MemoryAnchor::new());
    let prepared = must_v3(writer.prepare_genesis_snapshot());
    let journal: serde_json::Value =
        serde_json::from_slice(&must_v3(prepared.to_journal_bytes())).expect("journal JSON");
    let key = object_id(journal["object_id"].as_str().expect("opaque key"));
    assert!(
        writer
            .publish_prepared_genesis(&anchor, &prepared, true)
            .await
            .is_err()
    );
    let body = store
        .get_range(&key, ByteRange::Full)
        .await
        .expect("uploaded body");
    let mut corrupt = body.to_vec();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    store
        .put(&key, Bytes::from(corrupt), PutOptions::default())
        .await
        .expect("fixture corruption");
    let before = store.operation_counts().expect("counts").put;
    assert!(
        writer
            .publish_prepared_genesis(&anchor, &prepared, true)
            .await
            .is_err()
    );
    assert!(must_v3(anchor.read_v3().await).is_none());
    assert_eq!(store.operation_counts().expect("counts").put, before);

    store
        .put(&key, body, PutOptions::default())
        .await
        .expect("repair fixture");
    let accepted = must_v3(
        writer
            .publish_prepared_genesis(&anchor, &prepared, true)
            .await,
    );
    store
        .delete_at(&key, accepted.version_id.as_ref())
        .await
        .expect("fixture deletion");
    let before = store.operation_counts().expect("counts").put;
    // Missing accepted data is never recreated, with or without an allowance.
    for allowance in [false, true] {
        assert!(
            writer
                .publish_prepared_genesis(&anchor, &prepared, allowance)
                .await
                .is_err()
        );
    }
    assert_eq!(store.operation_counts().expect("counts").put, before);
    assert_eq!(must_v3(anchor.read_v3().await), Some(accepted.anchor_state));
}

#[test]
fn prepared_genesis_rejects_corrupt_oversized_and_cross_context_journals() {
    let store = CountingBlobStore::new(MemoryBlobStore::new());
    let writer = V3CommitStore::new(store.clone(), signing_keyring(), options(false));
    let prepared = must_v3(writer.prepare_genesis_snapshot());
    let encoded = must_v3(prepared.to_journal_bytes());
    let source: serde_json::Value = serde_json::from_slice(&encoded).expect("journal JSON");
    for name in ["schema", "repository_id", "object_id", "body", "extra"] {
        let mut changed = source.clone();
        changed[name] = serde_json::json!("wrong");
        assert!(
            writer
                .open_prepared_genesis(&serde_json::to_vec(&changed).expect("JSON"))
                .is_err()
        );
    }
    assert!(
        writer
            .open_prepared_genesis(&vec![b' '; 64 * 1024 + 1])
            .is_err()
    );
    let mut different = options(false);
    different.format_ref.digest = "00".repeat(32);
    let other = V3CommitStore::new(store.clone(), signing_keyring(), different);
    assert!(other.open_prepared_genesis(&encoded).is_err());
    let other = V3CommitStore::new(store.clone(), signing_keyring(), options(true));
    assert!(other.open_prepared_genesis(&encoded).is_err());
    let other = V3CommitStore::new(
        store.clone(),
        must_crypto(KeyRing::generate_random()),
        options(false),
    );
    assert!(other.open_prepared_genesis(&encoded).is_err());
    assert_eq!(
        store.operation_counts().expect("counts"),
        Default::default()
    );
}

#[tokio::test]
async fn prepared_genesis_repeat_uses_accepted_version_after_latest_is_replaced() {
    let store = CountingBlobStore::new(MemoryBlobStore::new());
    let writer = V3CommitStore::new(store.clone(), signing_keyring(), options(true));
    let anchor = V3MemoryAnchor::new();
    let prepared = must_v3(writer.prepare_genesis_snapshot());
    let accepted = must_v3(
        writer
            .publish_prepared_genesis(&anchor, &prepared, true)
            .await,
    );
    let replacement = store
        .put(
            &accepted.anchor_state.commit_key,
            Bytes::from_static(b"untrusted latest version"),
            PutOptions::default(),
        )
        .await
        .expect("fixture replacement");
    assert_ne!(replacement.version_id, accepted.version_id);
    let before = store.operation_counts().expect("counts").put;
    assert_eq!(
        must_v3(
            writer
                .publish_prepared_genesis(&anchor, &prepared, true)
                .await
        ),
        accepted
    );
    assert_eq!(store.operation_counts().expect("counts").put, before);
}

#[tokio::test]
async fn prepared_recovery_genesis_retry_checks_guard_before_repair_and_preserves_observed_protection()
 {
    let store = MemoryBlobStore::new();
    let policy = crate::v3::RecoveryPolicy::PRESET;
    let options = commit_store_options_with_maintenance_roots(
        &store,
        V3ProviderProfile::RetainedVersionObjectLock,
        Some(RetentionPolicy::new(RetentionMode::Governance, 1)),
    )
    .await
    .with_recovery_policy(Some(policy));
    let writer = V3CommitStore::new(store.clone(), signing_keyring(), options);
    let prepared = must_v3(writer.prepare_genesis_snapshot());
    let journal: serde_json::Value =
        serde_json::from_slice(&must_v3(prepared.to_journal_bytes())).expect("trusted journal");
    let id = object_id(journal["object_id"].as_str().expect("opaque candidate key"));
    let body: Vec<u8> = serde_json::from_value(journal["body"].clone()).expect("candidate bytes");
    // Model an unfinished bootstrap retry whose immutable candidate already
    // has a stronger mode and hold, but not the full recovery window yet.
    let prior = store
        .put(
            &id,
            Bytes::from(body),
            PutOptions {
                retention: Some(RetentionPolicy::new(RetentionMode::Compliance, 1)),
                legal_hold: Some(LegalHoldStatus::On),
                ..PutOptions::default()
            },
        )
        .await
        .expect("pre-existing exact candidate");
    let anchor = V3MemoryAnchor::new();
    let before = store.operation_counts().expect("counts");
    assert_eq!(
        writer
            .publish_prepared_genesis_with_guard(
                &anchor,
                &prepared,
                false,
                &FailsAfterMaintenanceGuard::new(1),
            )
            .await,
        Err(V3FormatError::MaintenanceAccessRequired)
    );
    let failed = store.operation_counts().expect("counts");
    assert_eq!(failed.put, before.put);
    assert_eq!(failed.extend_retention, before.extend_retention);
    assert_eq!(must_v3(anchor.read_v3().await), None);

    let minimum_floor = must_v3(policy.coverage_until_ms(writer.publication_now_ms()));
    let accepted = must_v3(
        writer
            .publish_prepared_genesis_with_guard(
                &anchor,
                &prepared,
                false,
                &UnenforcedQuiescedMaintenanceGuard,
            )
            .await,
    );
    let exact = store
        .head_at(&id, prior.version_id.as_ref())
        .await
        .expect("accepted exact candidate");
    assert_eq!(accepted.version_id, prior.version_id);
    assert_eq!(store.operation_counts().expect("counts").put, before.put);
    assert_eq!(
        exact.retention.map(|retention| retention.mode),
        Some(RetentionMode::Compliance)
    );
    assert_eq!(exact.legal_hold, Some(LegalHoldStatus::On));
    assert!(
        exact
            .retain_until_ms
            .is_some_and(|floor| floor >= minimum_floor)
    );
    assert_eq!(accepted.verified_retain_until_ms, exact.retain_until_ms);
    assert_eq!(must_v3(anchor.read_v3().await), Some(accepted.anchor_state));
}
