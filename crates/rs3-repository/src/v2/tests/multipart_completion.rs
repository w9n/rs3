use super::*;
use crate::v2::{V3ClientMultipartUpload, V3MultipartSelection};

struct Fixture {
    store: MemoryBlobStore,
    keyring: KeyRing,
    options: V2CommitStoreOptions,
    repository: Arc<V2Repository<MemoryBlobStore>>,
    anchor: V2MemoryAnchor,
}

impl Fixture {
    async fn new() -> Self {
        Self::with_keyring(must_crypto(KeyRing::generate_random())).await
    }

    async fn with_keyring(keyring: KeyRing) -> Self {
        let store = MemoryBlobStore::new();
        let options = V2CommitStoreOptions::for_profile(
            V2ProviderProfile::Dev,
            sample_repository_id(),
            sample_keyring_envelope_ref(),
            sample_format_ref(),
        );
        let repository = Arc::new(V2Repository::new(
            store.clone(),
            keyring.clone(),
            RepositoryOptions::default(),
            options.clone(),
        ));
        let anchor = V2MemoryAnchor::new();
        must_repo(repository.write_genesis_snapshot(&anchor).await);
        Self {
            store,
            keyring,
            options,
            repository,
            anchor,
        }
    }

    fn coordinator(&self) -> V2CommitCoordinator<MemoryBlobStore, V2MemoryAnchor> {
        must_repo(V2CommitCoordinator::with_options(
            Arc::clone(&self.repository),
            self.anchor.clone(),
            CommitCoordinatorOptions::new(1, Duration::ZERO),
        ))
    }

    async fn upload(
        &self,
        bytes: &'static [u8],
        create_only: bool,
    ) -> (V3ClientMultipartUpload, V3MultipartSelection) {
        let upload = must_repo(
            self.repository
                .create_multipart_upload(
                    key(),
                    RepositoryPutOptions {
                        create_only,
                        ..Default::default()
                    },
                )
                .await,
        );
        let part = must_repo(
            upload
                .upload_part(3, Box::new(Body(Bytes::from_static(bytes))))
                .await,
        );
        let selection = must_repo(V3MultipartSelection::new(vec![(3, part.etag())]));
        (upload, selection)
    }

    async fn reopen(&self) -> V2Repository<MemoryBlobStore> {
        let fresh = V2Repository::new(
            self.store.clone(),
            self.keyring.clone(),
            RepositoryOptions::default(),
            self.options.clone(),
        );
        must_repo(fresh.load_chain_from_anchor(&self.anchor).await);
        fresh
    }
}

struct Body(Bytes);
#[async_trait::async_trait]
impl rs3_storage::BlobRead for Body {
    fn exact_len(&self) -> u64 {
        self.0.len() as u64
    }
    async fn next_chunk(&mut self) -> rs3_storage::Result<Option<Bytes>> {
        Ok((!self.0.is_empty()).then(|| self.0.split_to(self.0.len())))
    }
}
fn key() -> LogicalPath {
    must_type(LogicalPath::new("private/multipart-key"))
}

#[tokio::test]
async fn multipart_overwrite_after_namespace_rotation_replays_its_receipt() {
    let keyring = |rotated: bool| {
        let mut keys = vec![
            key_material(
                "namespace-old",
                KeyPurpose::Namespace,
                if rotated {
                    KeyStatus::Enabled
                } else {
                    KeyStatus::Primary
                },
                1,
            ),
            key_material("content", KeyPurpose::Content, KeyStatus::Primary, 2),
            key_material("metadata", KeyPurpose::Metadata, KeyStatus::Primary, 3),
            key_material(
                "signing",
                KeyPurpose::CheckpointSigning,
                KeyStatus::Primary,
                4,
            ),
        ];
        if rotated {
            keys.push(key_material(
                "namespace-new",
                KeyPurpose::Namespace,
                KeyStatus::Primary,
                5,
            ));
        }
        must_crypto(KeyRing::new(keys))
    };
    let mut f = Fixture::with_keyring(keyring(false)).await;
    let coordinator = f.coordinator();
    must_repo(
        coordinator
            .put_committed(
                key(),
                Bytes::from_static(b"old"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    drop(coordinator);
    f.keyring = keyring(true);
    f.repository = Arc::new(f.reopen().await);
    let coordinator = f.coordinator();
    let (upload, selection) = f.upload(b"replacement", false).await;
    let id = upload.id();
    let receipt = must_repo(
        coordinator
            .complete_multipart_upload(upload, selection.clone())
            .await,
    );
    for checkpoint in [false, true] {
        if checkpoint {
            must_repo(coordinator.write_index_snapshot().await);
        }
        let fresh = f.reopen().await;
        assert_eq!(
            must_repo(fresh.get_range(&key(), ByteRange::Full).await),
            Bytes::from_static(b"replacement")
        );
        assert_eq!(
            must_repo(fresh.accepted_multipart_completion(&id, &key(), &selection)),
            Some(receipt.clone())
        );
    }
}

#[tokio::test]
async fn multipart_receipt_survives_overwrite_checkpoint_compaction_and_restart() {
    for empty in [false, true] {
        let f = Fixture::new().await;
        let coordinator = f.coordinator();
        let body = if empty {
            b"".as_slice()
        } else {
            b"original".as_slice()
        };
        let (upload, selection) = f.upload(body, false).await;
        let id = upload.id();
        let receipt = must_repo(
            coordinator
                .complete_multipart_upload(upload, selection.clone())
                .await,
        );
        let anchor = must_v2(f.anchor.read_v2().await).expect("accepted");
        assert_eq!(receipt.commit_sequence, anchor.sequence);
        assert_eq!(receipt.content_len, body.len() as u64);
        assert_eq!(
            must_repo(f.repository.get_range(&key(), ByteRange::Full).await).as_ref(),
            body
        );
        let cold_tail = f.reopen().await;
        assert_eq!(
            must_repo(cold_tail.accepted_multipart_completion(&id, &key(), &selection)),
            Some(receipt.clone())
        );
        must_repo(
            coordinator
                .put_committed(
                    key(),
                    Bytes::from_static(b"newer"),
                    RepositoryPutOptions::default(),
                )
                .await,
        );
        let overwritten = must_v2(f.anchor.read_v2().await).expect("newer");
        assert_eq!(
            must_repo(
                f.repository
                    .accepted_multipart_completion(&id, &key(), &selection)
            ),
            Some(receipt.clone())
        );
        assert_eq!(must_v2(f.anchor.read_v2().await), Some(overwritten));
        must_repo(coordinator.write_index_snapshot().await);
        let fresh = f.reopen().await;
        assert_eq!(
            must_repo(fresh.accepted_multipart_completion(&id, &key(), &selection)),
            Some(receipt.clone())
        );
        drop(coordinator);
        must_repo(
            f.repository
                .compact_packed_index_runs(&f.anchor, &UnenforcedQuiescedMaintenanceGuard)
                .await,
        );
        let compacted = f.reopen().await;
        assert_eq!(
            must_repo(compacted.accepted_multipart_completion(&id, &key(), &selection)),
            Some(receipt)
        );
        assert_eq!(
            must_repo(compacted.get_range(&key(), ByteRange::Full).await),
            Bytes::from_static(b"newer")
        );
        assert!(
            compacted
                .accepted_multipart_completion(
                    &id,
                    &must_type(LogicalPath::new("wrong/key")),
                    &selection
                )
                .is_err()
        );
        let wrong = must_repo(V3MultipartSelection::new(vec![(3, "other-part".into())]));
        assert!(
            compacted
                .accepted_multipart_completion(&id, &key(), &wrong)
                .is_err()
        );
        assert!(
            must_repo(compacted.accepted_multipart_completion(
                &rs3_types::MultipartUploadId::from_bytes([0; 32]),
                &key(),
                &selection
            ))
            .is_none()
        );
    }
}

#[tokio::test]
async fn multipart_create_only_is_checked_at_publication_without_a_receipt_on_failure() {
    let f = Fixture::new().await;
    let coordinator = f.coordinator();
    let (upload, selection) = f.upload(b"stale", true).await;
    let id = upload.id();
    must_repo(
        coordinator
            .put_committed(
                key(),
                Bytes::from_static(b"newer"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    let before = must_v2(f.anchor.read_v2().await);
    assert!(matches!(
        coordinator
            .complete_multipart_upload(upload, selection.clone())
            .await,
        Err(RepositoryError::AlreadyExists(_))
    ));
    assert_eq!(must_v2(f.anchor.read_v2().await), before);
    assert!(
        must_repo(
            f.repository
                .accepted_multipart_completion(&id, &key(), &selection)
        )
        .is_none()
    );
    assert_eq!(
        must_repo(f.repository.get_range(&key(), ByteRange::Full).await),
        Bytes::from_static(b"newer")
    );
}

#[tokio::test]
async fn multipart_failed_anchor_publishes_neither_value_nor_receipt() {
    let f = Fixture::new().await;
    let coordinator = must_repo(V2CommitCoordinator::new(
        Arc::clone(&f.repository),
        FailOnceV2Anchor::new(f.anchor.clone()),
    ));
    let (upload, selection) = f.upload(b"unaccepted", false).await;
    let id = upload.id();
    assert!(
        coordinator
            .complete_multipart_upload(upload, selection.clone())
            .await
            .is_err()
    );
    assert!(matches!(
        f.repository.head(&key()),
        Err(RepositoryError::NotFound(_))
    ));
    assert!(
        must_repo(
            f.repository
                .accepted_multipart_completion(&id, &key(), &selection)
        )
        .is_none()
    );
    let fresh = f.reopen().await;
    assert!(must_repo(fresh.accepted_multipart_completion(&id, &key(), &selection)).is_none());
    // The rejected staged prefix must not leak into the next accepted write.
    must_repo(
        coordinator
            .put_committed(
                key(),
                Bytes::from_static(b"later"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    assert!(
        must_repo(
            f.repository
                .accepted_multipart_completion(&id, &key(), &selection)
        )
        .is_none()
    );
}

#[tokio::test]
async fn multipart_local_install_failure_recovers_receipt_with_accepted_value() {
    let f = Fixture::new().await;
    let coordinator = f.coordinator();
    let (upload, selection) = f.upload(b"accepted", false).await;
    let id = upload.id();
    f.repository.fail_next_local_install_for_tests();
    assert!(matches!(
        coordinator
            .complete_multipart_upload(upload, selection.clone())
            .await,
        Err(RepositoryError::AcceptedRecoveryRequired)
    ));
    let fresh = f.reopen().await;
    assert!(must_repo(fresh.accepted_multipart_completion(&id, &key(), &selection)).is_some());
    assert_eq!(
        must_repo(fresh.get_range(&key(), ByteRange::Full).await),
        Bytes::from_static(b"accepted")
    );
    assert!(
        coordinator
            .put_committed(
                key(),
                Bytes::from_static(b"blocked"),
                RepositoryPutOptions::default()
            )
            .await
            .is_err()
    );
}

#[test]
fn multipart_selection_digest_binds_numbers_order_and_exact_etags() {
    let valid = must_repo(V3MultipartSelection::new(vec![
        (1, "a".into()),
        (3, "b".into()),
    ]));
    for parts in [
        vec![],
        vec![(0, "a".into())],
        vec![(10_001, "a".into())],
        vec![(3, "a".into()), (1, "b".into())],
        vec![(1, "a".into()), (1, "b".into())],
        vec![(1, "bad\r\nheader".into())],
        vec![(1, "a".repeat(129))],
    ] {
        assert!(V3MultipartSelection::new(parts).is_err());
    }
    for parts in [
        vec![(1, "a".into()), (2, "b".into())],
        vec![(1, "b".into()), (3, "a".into())],
        vec![(1, "ab".into()), (3, "b".into())],
    ] {
        assert_ne!(
            valid.digest(),
            must_repo(V3MultipartSelection::new(parts)).digest()
        );
    }
}

struct LostCompletionReply {
    inner: V2MemoryAnchor,
    lose_reconciliation: bool,
    advanced: std::sync::atomic::AtomicBool,
}
#[async_trait::async_trait]
impl V2CommitAnchor for LostCompletionReply {
    async fn read_v2(&self) -> super::super::V2Result<Option<V2AnchorState>> {
        if self.lose_reconciliation && self.advanced.load(Ordering::SeqCst) {
            return Err(V2FormatError::AnchorReadFailed);
        }
        self.inner.read_v2().await
    }
    async fn compare_and_advance_v2(
        &self,
        expected: Option<&V2AnchorState>,
        next: V2AnchorState,
    ) -> super::super::V2Result<V2AnchorState> {
        self.inner.compare_and_advance_v2(expected, next).await?;
        self.advanced.store(true, Ordering::SeqCst);
        Err(V2FormatError::AnchorAdvanceFailed)
    }
}

#[tokio::test]
async fn multipart_lost_anchor_reply_is_reconciled_or_requires_recovery() {
    for lose_reconciliation in [false, true] {
        let f = Fixture::new().await;
        let coordinator = must_repo(V2CommitCoordinator::new(
            Arc::clone(&f.repository),
            LostCompletionReply {
                inner: f.anchor.clone(),
                lose_reconciliation,
                advanced: std::sync::atomic::AtomicBool::new(false),
            },
        ));
        let (upload, selection) = f.upload(b"accepted once", false).await;
        let id = upload.id();
        let result = coordinator
            .complete_multipart_upload(upload, selection.clone())
            .await;
        let accepted = must_v2(f.anchor.read_v2().await).expect("accepted");
        assert_eq!(accepted.sequence, Sequence::new(2));
        if lose_reconciliation {
            assert!(matches!(
                result,
                Err(RepositoryError::AcceptedRecoveryRequired)
            ));
            assert!(
                f.repository
                    .accepted_multipart_completion(&id, &key(), &selection)
                    .is_err()
            );
        } else {
            let receipt = must_repo(result);
            assert_eq!(
                must_repo(
                    f.repository
                        .accepted_multipart_completion(&id, &key(), &selection)
                ),
                Some(receipt)
            );
        }
        let fresh = f.reopen().await;
        let receipt = must_repo(fresh.accepted_multipart_completion(&id, &key(), &selection))
            .expect("durable result");
        assert_eq!(receipt.commit_sequence, Sequence::new(2));
        assert_eq!(
            must_repo(fresh.get_range(&key(), ByteRange::Full).await),
            Bytes::from_static(b"accepted once")
        );
        assert_eq!(must_v2(f.anchor.read_v2().await), Some(accepted));
    }
}

#[tokio::test]
async fn multipart_receipt_eviction_survives_automatic_compaction_and_root_replay() {
    let f = Fixture::new().await;
    let coordinator = f
        .coordinator()
        .with_maintenance_guard(UnenforcedQuiescedMaintenanceGuard);
    let (upload, selection) = f.upload(b"first", false).await;
    let first_id = upload.id();
    must_repo(
        coordinator
            .complete_multipart_upload(upload, selection.clone())
            .await,
    );
    let mut latest = None;
    for _ in 0..rs3_index::completion::MAX_COMPLETION_RECEIPTS {
        let (upload, selected) = f.upload(b"next", false).await;
        let id = upload.id();
        let receipt = must_repo(
            coordinator
                .complete_multipart_upload(upload, selected.clone())
                .await,
        );
        latest = Some((id, selected, receipt));
    }
    assert!(
        must_repo(
            f.repository
                .accepted_multipart_completion(&first_id, &key(), &selection)
        )
        .is_none()
    );
    must_repo(coordinator.write_index_snapshot().await);
    let fresh = f.reopen().await;
    assert!(
        must_repo(fresh.accepted_multipart_completion(&first_id, &key(), &selection)).is_none()
    );
    let (id, selected, receipt) = latest.expect("latest");
    assert_eq!(
        must_repo(fresh.accepted_multipart_completion(&id, &key(), &selected)),
        Some(receipt)
    );
    assert_eq!(
        must_repo(fresh.get_range(&key(), ByteRange::Full).await),
        Bytes::from_static(b"next")
    );
}
