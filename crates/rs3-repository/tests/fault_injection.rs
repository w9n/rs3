//! Deterministic fault-injection invariants for v2 repository workflows.

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream;
use rs3_crypto::{KeyMaterial, KeyRing, SecretBytes};
use rs3_repository::v2::{
    UnenforcedQuiescedMaintenanceGuard, V2_MAX_HEADER_SIZE, V2CommitAnchor, V2CommitCoordinator,
    V2CommitSection, V2CommitStore, V2CommitStoreOptions, V2CommitWrite, V2FormatError,
    V2FormatRef, V2FullGcApplyOptions, V2FullGcDryRunOptions, V2KeyringEnvelopeRef,
    V2KeyringEnvelopeRootRef, V2MaintenanceBudgets, V2MemoryAnchor, V2OrphanGcOptions,
    V2ProviderProfile, V2RecoveryBundle, V2SectionType,
};
use rs3_repository::{RepositoryError, RepositoryOptions, RepositoryPutOptions};
use rs3_storage::{
    BlobStore, ByteRange, FaultAction, FaultCrashHook, FaultInjectingBlobStore, FaultMatcher,
    FaultOperationKind, FaultRule, MemoryBlobStore, PutOptions,
};
use rs3_types::{
    BackendObjectId, KeyDescriptor, KeyId, KeyPurpose, KeyStatus, LogicalPath, RetentionMode,
    RetentionPolicy, Sequence,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Barrier;

#[tokio::test]
async fn commit_publish_fault_sweep_never_exposes_half_visible_write() {
    for offset in 0..sweep_len(6, 18) {
        for fault in [
            PublishFault::BeforeOperation,
            PublishFault::AfterSuccessfulWrite,
        ] {
            let inner = MemoryBlobStore::new();
            let keyring = signing_keyring();
            let options = commit_options();
            let anchor = V2MemoryAnchor::new();
            let setup = make_repository(inner.clone(), keyring.clone(), options.clone());
            setup
                .write_genesis_snapshot(&anchor)
                .await
                .expect("genesis should write");

            let store = FaultInjectingBlobStore::new(inner.clone(), Vec::new());
            let repository = make_repository(store.clone(), keyring.clone(), options.clone());
            repository
                .load_chain_from_anchor(&anchor)
                .await
                .expect("fresh repository should replay genesis");
            let fault_index = store
                .next_operation_index()
                .expect("fault index should be readable")
                .saturating_add(offset);
            store
                .push_rule(FaultRule::new(
                    FaultMatcher::operation_index(fault_index),
                    fault.action(),
                ))
                .expect("fault rule should install");

            let key = logical_path(&format!(
                "snapshots/fault-publish-{offset}-{}.bin",
                fault.name()
            ));
            let body = Bytes::from(format!("publish-fault-{offset}-{}", fault.name()));
            let result = repository
                .put_committed(
                    &anchor,
                    key.clone(),
                    body.clone(),
                    RepositoryPutOptions::default(),
                )
                .await;
            let recovered = make_repository(inner.clone(), keyring, options);
            recovered
                .load_chain_from_anchor(&anchor)
                .await
                .expect("recovery replay should fail closed or load accepted state");
            let recovered_body = recovered.get_range(&key, ByteRange::Full).await;

            if result.is_ok() {
                assert_eq!(
                    recovered_body.expect("accepted write should be readable"),
                    body
                );
            } else {
                assert!(
                    matches!(recovered_body, Err(RepositoryError::NotFound(_))),
                    "failed write at operation {fault_index} must not become client-visible"
                );
            }
        }
    }
}

#[tokio::test]
async fn gc_stale_list_preserves_live_payload_refs_and_protected_roots() {
    let inner = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let options = commit_options();
    let repository = make_repository(inner.clone(), keyring.clone(), options.clone());
    let anchor = V2MemoryAnchor::new();
    let first_key = logical_path("snapshots/gc-stale-live-one.bin");
    let second_key = logical_path("snapshots/gc-stale-live-two.bin");
    let first_body = Bytes::from_static(b"live before stale list snapshot one");
    let second_body = Bytes::from_static(b"live before stale list snapshot two");

    repository
        .write_genesis_snapshot(&anchor)
        .await
        .expect("genesis should write");
    repository
        .put_committed(
            &anchor,
            first_key.clone(),
            first_body.clone(),
            RepositoryPutOptions::default(),
        )
        .await
        .expect("first live payload should commit");
    repository
        .put_committed(
            &anchor,
            second_key.clone(),
            second_body.clone(),
            RepositoryPutOptions::default(),
        )
        .await
        .expect("second live payload should commit");
    let protected_root = anchor
        .read_v2()
        .await
        .expect("anchor should read")
        .expect("anchor should exist");
    repository
        .write_index_snapshot(&anchor)
        .await
        .expect("index snapshot should commit");

    let store = FaultInjectingBlobStore::new(
        inner.clone(),
        vec![FaultRule::new(
            FaultMatcher::operation(FaultOperationKind::ListPrefixPage),
            FaultAction::stale_list(1),
        )],
    );
    let gc_repository = make_repository(store.clone(), keyring.clone(), options.clone());
    gc_repository
        .load_chain_from_anchor(&anchor)
        .await
        .expect("fresh repository should replay snapshot");
    let apply = gc_repository
        .commit_store()
        .apply_full_gc(
            &anchor,
            &UnenforcedQuiescedMaintenanceGuard,
            V2FullGcApplyOptions {
                dry_run: V2FullGcDryRunOptions {
                    protected_roots: vec![protected_root],
                    ..V2FullGcDryRunOptions::default()
                },
                orphan_gc: rs3_repository::v2::V2OrphanGcOptions::new_for_test_rehearsal(
                    Duration::ZERO,
                ),
                retained_provider_conformance_passed: false,
            },
        )
        .await
        .expect("GC should tolerate stale list omissions");
    let recovered = make_repository(inner, keyring, options);
    recovered
        .load_chain_from_anchor(&anchor)
        .await
        .expect("recovery replay should preserve live refs");

    assert_eq!(apply.orphan_gc.deleted_count, 0);
    assert!(
        store
            .operation_log()
            .expect("operation log should be readable")
            .iter()
            .any(|event| event.kind == FaultOperationKind::ListPrefixPage)
    );
    assert_eq!(
        recovered
            .get_range(&first_key, ByteRange::Full)
            .await
            .expect("first live payload should remain readable"),
        first_body
    );
    assert_eq!(
        recovered
            .get_range(&second_key, ByteRange::Full)
            .await
            .expect("second live payload should remain readable"),
        second_body
    );
}

#[tokio::test]
async fn streaming_put_fault_sweep_never_exposes_partial_object_and_aborts_parts() {
    for offset in 0..sweep_len(10, 28) {
        let inner = MemoryBlobStore::new();
        let keyring = signing_keyring();
        let options = commit_options();
        let anchor = V2MemoryAnchor::new();
        let setup = make_repository(inner.clone(), keyring.clone(), options.clone());
        setup
            .write_genesis_snapshot(&anchor)
            .await
            .expect("genesis should write");

        let store = FaultInjectingBlobStore::new(inner.clone(), Vec::new());
        let repository = Arc::new(make_repository(
            store.clone(),
            keyring.clone(),
            options.clone(),
        ));
        repository
            .load_chain_from_anchor(&anchor)
            .await
            .expect("fresh repository should replay genesis");
        let coordinator = V2CommitCoordinator::new(Arc::clone(&repository), anchor.clone())
            .expect("coordinator should start");
        let fault_index = store
            .next_operation_index()
            .expect("fault index should be readable")
            .saturating_add(offset);
        store
            .push_rule(FaultRule::new(
                FaultMatcher::operation_index(fault_index),
                FaultAction::return_error("streaming fault"),
            ))
            .expect("fault rule should install");

        let key = logical_path(&format!("snapshots/stream-fault-{offset}.bin"));
        let body = Bytes::from(vec![offset as u8; 3072]);
        let chunks = vec![
            Ok(Bytes::copy_from_slice(&body[..1024])),
            Ok(Bytes::copy_from_slice(&body[1024..2048])),
            Ok(Bytes::copy_from_slice(&body[2048..])),
        ];
        let result = coordinator
            .put_committed_streaming_known_len(
                key.clone(),
                body.len() as u64,
                stream::iter(chunks),
                RepositoryPutOptions::default(),
                V2_MAX_HEADER_SIZE + 512,
            )
            .await;
        let log = store
            .operation_log()
            .expect("operation log should be readable");
        let faulted = log
            .iter()
            .find(|event| event.operation_index == fault_index)
            .cloned();
        let recovered = make_repository(inner, keyring, options);
        recovered
            .load_chain_from_anchor(&anchor)
            .await
            .expect("recovery replay should load the last accepted anchor");
        let recovered_body = recovered.get_range(&key, ByteRange::Full).await;

        if result.is_ok() {
            assert_eq!(
                recovered_body.expect("accepted streaming write should be readable"),
                body
            );
        } else {
            assert!(
                matches!(recovered_body, Err(RepositoryError::NotFound(_))),
                "failed streaming write at operation {fault_index} must not become visible"
            );
            if faulted.is_some_and(|event| event.kind == FaultOperationKind::MultipartPutPart) {
                assert!(
                    log.iter()
                        .any(|event| event.kind == FaultOperationKind::MultipartAbort),
                    "multipart part failure should attempt abort"
                );
            }
        }
    }
}

#[tokio::test]
async fn ambiguous_multipart_completion_leaves_only_an_invisible_gc_orphan() {
    let inner = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let options = commit_options();
    let anchor = V2MemoryAnchor::new();
    make_repository(inner.clone(), keyring.clone(), options.clone())
        .write_genesis_snapshot(&anchor)
        .await
        .expect("genesis should write");
    let store = FaultInjectingBlobStore::new(
        inner.clone(),
        vec![FaultRule::new(
            FaultMatcher::operation(FaultOperationKind::MultipartComplete),
            FaultAction::error_after_write("ambiguous multipart completion"),
        )],
    );
    let repository = Arc::new(make_repository(store, keyring.clone(), options.clone()));
    repository
        .load_chain_from_anchor(&anchor)
        .await
        .expect("repository should load genesis");
    let coordinator = V2CommitCoordinator::new(Arc::clone(&repository), anchor.clone())
        .expect("coordinator should start");
    let key = logical_path("snapshots/ambiguous-complete.bin");
    let result = coordinator
        .put_committed_streaming_known_len(
            key.clone(),
            4096,
            stream::iter([Ok::<Bytes, RepositoryError>(Bytes::from(vec![0x4a; 4096]))]),
            RepositoryPutOptions::default(),
            V2_MAX_HEADER_SIZE + 512,
        )
        .await;
    assert!(result.is_err());

    let recovered = make_repository(inner.clone(), keyring, options);
    recovered
        .load_chain_from_anchor(&anchor)
        .await
        .expect("recovery should retain genesis");
    assert!(matches!(
        recovered.get_range(&key, ByteRange::Full).await,
        Err(RepositoryError::NotFound(_))
    ));
    let orphans = recovered
        .commit_store()
        .report_orphans(&anchor)
        .await
        .expect("orphan report should succeed");
    assert_eq!(
        orphans
            .candidates
            .iter()
            .filter(|candidate| {
                candidate.object_class == rs3_repository::v2::V2OrphanObjectClass::Object
            })
            .count(),
        1
    );
}

#[tokio::test]
async fn ambiguous_retention_renewal_aborts_before_any_orphan_delete() {
    let inner = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let retention = RetentionPolicy::new(RetentionMode::Compliance, 1);
    let mut options = V2CommitStoreOptions {
        provider_profile: V2ProviderProfile::RetainedVersionObjectLock,
        retention: Some(retention),
        ..commit_options()
    };
    let keyring_metadata = inner
        .put(
            &options.keyring_envelope_ref.object_id,
            Bytes::from_static(b"encrypted-keyring-envelope"),
            PutOptions {
                retention: Some(retention),
                ..PutOptions::default()
            },
        )
        .await
        .expect("keyring root should write");
    let format_metadata = inner
        .put(
            &options.format_ref.object_id,
            Bytes::from_static(b"encrypted-format-root"),
            PutOptions {
                retention: Some(retention),
                ..PutOptions::default()
            },
        )
        .await
        .expect("format root should write");
    options.format_ref.version_id = format_metadata.version_id;
    options.maintenance_keyring_envelope_ref = Some(V2KeyringEnvelopeRootRef {
        generation: 1,
        digest: hex::encode(options.keyring_envelope_ref.digest),
        object_id: options.keyring_envelope_ref.object_id.clone(),
        version_id: keyring_metadata.version_id,
    });
    let anchor = V2MemoryAnchor::new();
    let setup = V2CommitStore::new(inner.clone(), keyring.clone(), options.clone());
    let genesis = setup
        .write_genesis_snapshot(&anchor)
        .await
        .expect("retained genesis should write");
    let orphan =
        object_id("commits/v02/00000000000000000099/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    inner
        .put(
            &orphan,
            Bytes::from_static(b"delete only after renewal"),
            PutOptions::default(),
        )
        .await
        .expect("orphan should write");
    let store = FaultInjectingBlobStore::new(
        inner.clone(),
        vec![FaultRule::new(
            FaultMatcher::operation(FaultOperationKind::ExtendRetentionAt),
            FaultAction::error_after_write("ambiguous retention renewal"),
        )],
    );
    let repository = V2CommitStore::new(store, keyring, options);
    let result = repository
        .apply_full_gc(
            &anchor,
            &UnenforcedQuiescedMaintenanceGuard,
            V2FullGcApplyOptions {
                dry_run: V2FullGcDryRunOptions {
                    budgets: V2MaintenanceBudgets {
                        max_retention_extend_count: Some(3),
                        ..V2MaintenanceBudgets::default()
                    },
                    retention_renewal_horizon: Duration::from_secs(2 * 24 * 60 * 60),
                    ..V2FullGcDryRunOptions::default()
                },
                orphan_gc: V2OrphanGcOptions::new_for_test_rehearsal(Duration::ZERO),
                retained_provider_conformance_passed: true,
            },
        )
        .await;
    assert_eq!(result, Err(V2FormatError::StorageOperationFailed));
    assert!(inner.head(&orphan).await.is_ok());
    let exact = inner
        .head_at(&genesis.commit_key.object_id, genesis.version_id.as_ref())
        .await
        .expect("ambiguous renewal may safely have strengthened exact retention");
    assert_eq!(
        exact.retention,
        Some(RetentionPolicy::new(RetentionMode::Compliance, 1))
    );
}

#[tokio::test]
async fn weak_subjectivity_floor_rejects_rollback_before_storage_faults() {
    let inner = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let options = commit_options();
    let repository = V2CommitStore::new(inner.clone(), keyring.clone(), options.clone());
    let anchor = V2MemoryAnchor::new();

    let genesis = repository
        .write_genesis_snapshot(&anchor)
        .await
        .expect("genesis should write");
    let old_bundle = V2RecoveryBundle::from_anchor(genesis.anchor_state, Sequence::new(1));
    repository
        .write_child_commit(
            &anchor,
            V2CommitWrite::delta(vec![V2CommitSection::new(
                V2SectionType::IndexDelta,
                0,
                Bytes::from_static(b"newer state blocks rollback"),
            )]),
        )
        .await
        .expect("newer child should commit");

    let crash_hook = FaultCrashHook::new();
    let faulted_store = FaultInjectingBlobStore::new(
        inner,
        vec![FaultRule::new(
            FaultMatcher::operation_index(0),
            FaultAction::crash_point(crash_hook.clone()),
        )],
    );
    let recovery_repository = V2CommitStore::new(faulted_store, keyring, options);
    let recovered_anchor = V2MemoryAnchor::new();
    let result = recovery_repository
        .recreate_anchor_from_recovery_bundle(&recovered_anchor, &old_bundle, Sequence::new(2))
        .await;

    assert_eq!(result, Err(V2FormatError::RecoveryBundleRequired));
    assert_eq!(crash_hook.hit_count(), 0);
    assert_eq!(
        recovered_anchor
            .read_v2()
            .await
            .expect("recovered anchor should read"),
        None
    );
}

#[tokio::test]
async fn anchor_cas_conflict_storm_accepts_one_child_per_sequence() {
    let store = MemoryBlobStore::new();
    let repository = Arc::new(V2CommitStore::new(
        store,
        signing_keyring(),
        commit_options(),
    ));
    let anchor = V2MemoryAnchor::new();
    repository
        .write_genesis_snapshot(&anchor)
        .await
        .expect("genesis should write");

    for round in 0..sweep_len(3, 8) {
        let before = anchor
            .read_v2()
            .await
            .expect("anchor should read")
            .expect("anchor should exist");
        let contenders = if full_sweep_enabled() { 8 } else { 4 };
        let conflict_anchor = BarrierAdvanceAnchor::new(anchor.clone(), contenders);
        let mut tasks = Vec::new();
        for contender in 0..contenders {
            let repository = Arc::clone(&repository);
            let anchor = conflict_anchor.clone();
            tasks.push(tokio::spawn(async move {
                repository
                    .write_child_commit(
                        &anchor,
                        V2CommitWrite::delta(vec![V2CommitSection::new(
                            V2SectionType::IndexDelta,
                            0,
                            Bytes::from(format!("round-{round}-contender-{contender}")),
                        )]),
                    )
                    .await
            }));
        }

        let mut accepted = 0_usize;
        let mut stale = 0_usize;
        for task in tasks {
            match task.await.expect("writer task should not panic") {
                Ok(_) => accepted = accepted.saturating_add(1),
                Err(V2FormatError::StaleAnchor) => stale = stale.saturating_add(1),
                Err(error) => panic!("unexpected CAS storm error: {error}"),
            }
        }
        let after = anchor
            .read_v2()
            .await
            .expect("anchor should read")
            .expect("anchor should exist");
        let chain = repository
            .load_chain_from_anchor(&anchor)
            .await
            .expect("anchor-selected chain should verify")
            .expect("anchor-selected chain should exist");

        assert_eq!(accepted, 1);
        assert_eq!(stale, contenders - 1);
        assert_eq!(
            after.sequence,
            before
                .sequence
                .checked_next()
                .expect("test sequence should not overflow")
        );
        assert_eq!(
            chain.commits_newest_first[0]
                .parsed_header
                .header
                .self_ref
                .sequence,
            after.sequence
        );
    }
}

#[derive(Clone, Copy)]
enum PublishFault {
    BeforeOperation,
    AfterSuccessfulWrite,
}

impl PublishFault {
    fn action(self) -> FaultAction {
        match self {
            Self::BeforeOperation => FaultAction::return_error("publish fault"),
            Self::AfterSuccessfulWrite => FaultAction::error_after_write("ambiguous publish fault"),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::BeforeOperation => "before",
            Self::AfterSuccessfulWrite => "after-write",
        }
    }
}

fn make_repository<S>(
    store: S,
    keyring: KeyRing,
    commit_options: V2CommitStoreOptions,
) -> rs3_repository::v2::V2Repository<S>
where
    S: BlobStore + Clone,
{
    rs3_repository::v2::V2Repository::new(
        store,
        keyring,
        RepositoryOptions::default(),
        commit_options,
    )
}

fn commit_options() -> V2CommitStoreOptions {
    V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        V2KeyringEnvelopeRef {
            object_id: object_id("keyrings/00000000000000000001-fault-test"),
            digest: [6_u8; 32],
        },
        V2FormatRef {
            generation: 1,
            digest: hex::encode([7_u8; 32]),
            object_id: object_id(&format!("format/{:020}-{}", 1_u64, hex::encode([7_u8; 32]))),
            version_id: None,
        },
    )
}

fn sample_repository_id() -> rs3_types::RepositoryId {
    rs3_types::RepositoryId::new("rs3-fault-injection-test")
        .unwrap_or_else(|error| panic!("{error}"))
}

fn sweep_len(default: u64, full: u64) -> u64 {
    if full_sweep_enabled() { full } else { default }
}

fn full_sweep_enabled() -> bool {
    std::env::var_os("RS3_FAULT_INJECTION_FULL_SWEEP").is_some()
}

fn logical_path(value: &str) -> LogicalPath {
    LogicalPath::new(value).expect("test logical path should be valid")
}

fn object_id(value: &str) -> BackendObjectId {
    BackendObjectId::new(value).expect("test object id should be valid")
}

fn key_id(value: &str) -> KeyId {
    KeyId::new(value).expect("test key id should be valid")
}

fn secret(byte: u8) -> SecretBytes {
    SecretBytes::new(vec![byte; SecretBytes::MIN_LEN]).expect("test secret should be valid")
}

fn key_material(
    id: &str,
    purpose: KeyPurpose,
    status: KeyStatus,
    algorithm: &str,
    byte: u8,
) -> KeyMaterial {
    KeyMaterial::new(
        KeyDescriptor {
            id: key_id(id),
            purpose,
            algorithm: algorithm.to_owned(),
            status,
            created_at_ms: 0,
            not_before_ms: None,
            not_after_ms: None,
            public_key: None,
            external_kms_uri: None,
        },
        secret(byte),
    )
}

fn signing_keyring() -> KeyRing {
    KeyRing::new(vec![
        key_material(
            "namespace",
            KeyPurpose::Namespace,
            KeyStatus::Primary,
            "hmac-sha256",
            1,
        ),
        key_material(
            "metadata",
            KeyPurpose::Metadata,
            KeyStatus::Primary,
            "aes-256-gcm-siv-hmac-sha256-nonce-v1",
            2,
        ),
        key_material(
            "signing",
            KeyPurpose::CheckpointSigning,
            KeyStatus::Primary,
            "ed25519",
            3,
        ),
        key_material(
            "content",
            KeyPurpose::Content,
            KeyStatus::Primary,
            "xchacha20poly1305",
            4,
        ),
    ])
    .expect("test keyring should be valid")
}

#[derive(Clone)]
struct BarrierAdvanceAnchor {
    inner: V2MemoryAnchor,
    barrier: Arc<Barrier>,
}

impl BarrierAdvanceAnchor {
    fn new(inner: V2MemoryAnchor, parties: usize) -> Self {
        Self {
            inner,
            barrier: Arc::new(Barrier::new(parties)),
        }
    }
}

#[async_trait]
impl V2CommitAnchor for BarrierAdvanceAnchor {
    async fn read_v2(
        &self,
    ) -> rs3_repository::v2::V2Result<Option<rs3_repository::v2::V2AnchorState>> {
        self.inner.read_v2().await
    }

    async fn compare_and_advance_v2(
        &self,
        expected: Option<&rs3_repository::v2::V2AnchorState>,
        next: rs3_repository::v2::V2AnchorState,
    ) -> rs3_repository::v2::V2Result<rs3_repository::v2::V2AnchorState> {
        self.barrier.wait().await;
        self.inner.compare_and_advance_v2(expected, next).await
    }
}
