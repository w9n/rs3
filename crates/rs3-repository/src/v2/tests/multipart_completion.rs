use super::*;
use crate::v2::{V3ClientMultipartUpload, V3MultipartSelection};
use crate::{MultipartChecksumKind, MultipartChecksumPolicy, UploadChecksum};
use rs3_types::{ChecksumAlgorithm, ChecksumType, ObjectChecksum};

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
                    Some(policy(
                        ChecksumAlgorithm::Crc64Nvme,
                        MultipartChecksumKind::FullObject,
                    )),
                )
                .await,
        );
        let part = must_repo(
            upload
                .upload_part(
                    3,
                    Box::new(Body(Bytes::from_static(bytes))),
                    Some(UploadChecksum::verified(checksum(
                        ChecksumAlgorithm::Crc64Nvme,
                        bytes,
                    ))),
                    None,
                )
                .await,
        );
        let selection = must_repo(V3MultipartSelection::with_checksums(
            vec![(3, part.etag(), part.checksum().cloned())],
            part.checksum().cloned(),
        ));
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
        Ok((!self.0.is_empty()).then(|| self.0.split_to(self.0.len().min(64 * 1024))))
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
            receipt.etag.to_s3_string(),
            if empty {
                "59adb24ef3cdbe0297f05b395827453f-1"
            } else {
                "ea630fc1df1b4960edd2b2deaecc8582-1"
            }
        );
        assert_eq!(must_repo(f.repository.head(&key())).etag, receipt.etag);
        assert_eq!(must_repo(f.repository.list(""))[0].etag, receipt.etag);
        assert_eq!(
            receipt.checksum,
            Some(checksum(ChecksumAlgorithm::Crc64Nvme, body))
        );
        assert_eq!(
            must_repo(f.repository.head(&key())).checksum,
            receipt.checksum
        );
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

fn policy(algorithm: ChecksumAlgorithm, kind: MultipartChecksumKind) -> MultipartChecksumPolicy {
    MultipartChecksumPolicy::new(algorithm, kind).expect("supported multipart policy")
}

fn checksum(algorithm: ChecksumAlgorithm, bytes: &[u8]) -> ObjectChecksum {
    let mut hasher = rs3_crypto::ChecksumHasher::new(algorithm);
    hasher.update(bytes);
    ObjectChecksum::new(algorithm, ChecksumType::FullObject, hasher.finalize()).expect("checksum")
}

#[tokio::test]
async fn multipart_checksum_combination_matches_selected_bytes_and_rejects_bad_final_before_consumption()
 {
    for algorithm in [
        ChecksumAlgorithm::Crc32,
        ChecksumAlgorithm::Crc32c,
        ChecksumAlgorithm::Crc64Nvme,
    ] {
        let f = Fixture::new().await;
        let coordinator = f.coordinator();
        let upload = must_repo(
            f.repository
                .create_multipart_upload(
                    key(),
                    RepositoryPutOptions::default(),
                    Some(policy(algorithm, MultipartChecksumKind::FullObject)),
                )
                .await,
        );
        let prefix = Bytes::from(vec![7; rs3_storage::MULTIPART_MIN_PART_BYTES as usize]);
        let first_checksum = checksum(algorithm, &prefix);
        let first = must_repo(
            upload
                .upload_part(
                    2,
                    Box::new(Body(prefix.clone())),
                    Some(UploadChecksum::verified(first_checksum)),
                    None,
                )
                .await,
        );
        let last_checksum = checksum(algorithm, b"tail");
        let last = must_repo(
            upload
                .upload_part(
                    7,
                    Box::new(Body(Bytes::from_static(b"tail"))),
                    Some(UploadChecksum::verified(last_checksum)),
                    None,
                )
                .await,
        );
        let mut bytes = prefix.to_vec();
        bytes.extend_from_slice(b"tail");
        let expected = checksum(algorithm, &bytes);
        let pairs = vec![(2, first.etag(), None), (7, last.etag(), None)];
        let bad = must_repo(V3MultipartSelection::with_checksums(
            pairs.clone(),
            Some(checksum(algorithm, b"wrong")),
        ));
        let before = must_v2(f.anchor.read_v2().await);
        assert!(matches!(
            upload.validate_selection(&bad),
            Err(RepositoryError::ObjectChecksumMismatch)
        ));
        assert_eq!(must_v2(f.anchor.read_v2().await), before);
        assert!(f.repository.head(&key()).is_err());
        let selection = must_repo(V3MultipartSelection::with_checksums(
            pairs,
            Some(expected.clone()),
        ));
        must_repo(upload.validate_selection(&selection));
        let id = upload.id();
        let receipt = must_repo(
            coordinator
                .complete_multipart_upload(upload, selection.clone())
                .await,
        );
        assert_eq!(receipt.checksum, Some(expected));
        assert!(
            f.repository
                .accepted_multipart_completion(&id, &key(), &bad)
                .is_err()
        );
        assert_eq!(
            must_repo(
                f.reopen()
                    .await
                    .accepted_multipart_completion(&id, &key(), &selection)
            ),
            Some(receipt)
        );
    }
}

#[tokio::test]
async fn multipart_composite_requires_exact_part_facts_and_consecutive_numbers() {
    for algorithm in [
        ChecksumAlgorithm::Crc32,
        ChecksumAlgorithm::Crc32c,
        ChecksumAlgorithm::Sha1,
        ChecksumAlgorithm::Sha256,
    ] {
        let f = Fixture::new().await;
        let coordinator = f.coordinator();
        let upload = must_repo(
            f.repository
                .create_multipart_upload(
                    key(),
                    RepositoryPutOptions::default(),
                    Some(policy(algorithm, MultipartChecksumKind::Composite)),
                )
                .await,
        );
        let actual = checksum(algorithm, b"abc");
        let first = must_repo(
            upload
                .upload_part(
                    1,
                    Box::new(Body(Bytes::from_static(b"abc"))),
                    Some(UploadChecksum::verified(actual.clone())),
                    None,
                )
                .await,
        );
        let skipped = must_repo(
            upload
                .upload_part(
                    3,
                    Box::new(Body(Bytes::from_static(b"abc"))),
                    Some(UploadChecksum::verified(actual.clone())),
                    None,
                )
                .await,
        );
        let gap = must_repo(V3MultipartSelection::with_checksums(
            vec![(3, skipped.etag(), Some(actual.clone()))],
            None,
        ));
        assert!(upload.validate_selection(&gap).is_err());
        let missing = must_repo(V3MultipartSelection::new(vec![(1, first.etag())]));
        assert!(upload.validate_selection(&missing).is_err());
        let wrong = must_repo(V3MultipartSelection::with_checksums(
            vec![(1, first.etag(), Some(checksum(algorithm, b"wrong")))],
            None,
        ));
        assert!(matches!(
            upload.validate_selection(&wrong),
            Err(RepositoryError::ObjectChecksumMismatch)
        ));
        let mut hasher = rs3_crypto::ChecksumHasher::new(algorithm);
        hasher.update(actual.digest());
        let expected = ObjectChecksum::new(
            algorithm,
            ChecksumType::Composite { parts: 1 },
            hasher.finalize(),
        )
        .expect("composite");
        let selection = must_repo(V3MultipartSelection::with_checksums(
            vec![(1, first.etag(), Some(actual))],
            Some(expected.clone()),
        ));
        let id = upload.id();
        let receipt = must_repo(
            coordinator
                .complete_multipart_upload(upload, selection.clone())
                .await,
        );
        assert_eq!(receipt.checksum, Some(expected));
        for changed in [gap, missing, wrong] {
            assert!(
                f.repository
                    .accepted_multipart_completion(&id, &key(), &changed)
                    .is_err()
            );
        }
        assert_eq!(
            must_repo(
                f.reopen()
                    .await
                    .accepted_multipart_completion(&id, &key(), &selection)
            ),
            Some(receipt)
        );
    }
}

#[tokio::test]
async fn multipart_authoritative_checksum_failure_publishes_neither_object_nor_receipt() {
    let f = Fixture::new().await;
    let coordinator = f.coordinator();
    let (upload, selection) = f.upload(b"original", false).await;
    let id = upload.id();
    let part = must_repo(upload.list_parts(0, 10)).remove(0);
    let changed = must_repo(V3MultipartSelection::with_checksums(
        vec![(3, part.etag(), part.checksum().cloned())],
        Some(checksum(ChecksumAlgorithm::Crc64Nvme, b"wrong")),
    ));
    let before = must_v2(f.anchor.read_v2().await);
    assert!(matches!(
        coordinator.complete_multipart_upload(upload, changed).await,
        Err(RepositoryError::ObjectChecksumMismatch)
    ));
    assert_eq!(must_v2(f.anchor.read_v2().await), before);
    assert!(f.repository.head(&key()).is_err());
    assert!(
        must_repo(
            f.repository
                .accepted_multipart_completion(&id, &key(), &selection)
        )
        .is_none()
    );
}

#[test]
fn multipart_policy_rejects_unsupported_constructions() {
    for algorithm in [ChecksumAlgorithm::Sha1, ChecksumAlgorithm::Sha256] {
        assert!(
            MultipartChecksumPolicy::new(algorithm, MultipartChecksumKind::FullObject).is_err()
        );
    }
    assert!(
        MultipartChecksumPolicy::new(
            ChecksumAlgorithm::Crc64Nvme,
            MultipartChecksumKind::Composite
        )
        .is_err()
    );
}

#[tokio::test]
async fn multipart_retry_digest_binds_checksum_presence_and_explicit_kind() {
    let f = Fixture::new().await;
    let coordinator = f.coordinator();
    let (upload, _) = f.upload(b"abc", false).await;
    let part = must_repo(upload.list_parts(0, 1)).remove(0);
    let pairs = vec![(3, part.etag(), part.checksum().cloned())];
    let selection = must_repo(V3MultipartSelection::with_checksums_and_kind(
        pairs.clone(),
        part.checksum().cloned(),
        Some(MultipartChecksumKind::FullObject),
    ));
    let wrong_kind = must_repo(V3MultipartSelection::with_checksums_and_kind(
        pairs.clone(),
        None,
        Some(MultipartChecksumKind::Composite),
    ));
    assert!(upload.validate_selection(&wrong_kind).is_err());
    let id = upload.id();
    must_repo(
        coordinator
            .complete_multipart_upload(upload, selection.clone())
            .await,
    );
    let changed = [
        must_repo(V3MultipartSelection::with_checksums(
            pairs.clone(),
            part.checksum().cloned(),
        )),
        must_repo(V3MultipartSelection::with_checksums_and_kind(
            pairs,
            None,
            Some(MultipartChecksumKind::FullObject),
        )),
        must_repo(V3MultipartSelection::with_checksums_and_kind(
            vec![(3, part.etag(), None)],
            part.checksum().cloned(),
            Some(MultipartChecksumKind::FullObject),
        )),
        wrong_kind,
    ];
    let fresh = f.reopen().await;
    for changed in changed {
        assert_ne!(selection.digest(), changed.digest());
        assert!(
            fresh
                .accepted_multipart_completion(&id, &key(), &changed)
                .is_err()
        );
    }
}

#[tokio::test]
async fn native_md5_etags_cover_buffered_known_unknown_and_empty_without_optional_handoff() {
    for mode in 0..3 {
        for bytes in [b"abc".as_slice(), b"".as_slice()] {
            let f = Fixture::new().await;
            let options = RepositoryPutOptions::default();
            let metadata = match mode {
                0 => must_repo(
                    f.repository
                        .put_committed(&f.anchor, key(), Bytes::copy_from_slice(bytes), options)
                        .await,
                ),
                1 => must_repo(
                    f.repository
                        .put_committed_streaming_known_len(
                            &f.anchor,
                            key(),
                            bytes.len() as u64,
                            futures_util::stream::iter(
                                bytes
                                    .chunks(1)
                                    .map(|chunk| Ok(Bytes::copy_from_slice(chunk))),
                            ),
                            options,
                            5 * 1024 * 1024,
                        )
                        .await,
                ),
                _ => must_repo(
                    f.repository
                        .put_committed_streaming_unknown_len(
                            &f.anchor,
                            key(),
                            futures_util::stream::iter(
                                bytes
                                    .chunks(1)
                                    .map(|chunk| Ok(Bytes::copy_from_slice(chunk))),
                            ),
                            options,
                            5 * 1024 * 1024,
                            10,
                        )
                        .await,
                ),
            };
            let expected = if bytes.is_empty() {
                "d41d8cd98f00b204e9800998ecf8427e"
            } else {
                "900150983cd24fb0d6963f7d28e17f72"
            };
            assert_eq!(metadata.etag.to_s3_string(), expected);
            assert!(metadata.checksum.is_none());
            assert_eq!(must_repo(f.repository.head(&key())).etag, metadata.etag);
            assert_eq!(must_repo(f.repository.list(""))[0].etag, metadata.etag);
            let fresh = f.reopen().await;
            assert_eq!(must_repo(fresh.head(&key())).etag, metadata.etag);
            assert_eq!(must_repo(fresh.list(""))[0].etag, metadata.etag);
        }
    }
}

#[tokio::test]
async fn native_content_md5_mismatch_never_replaces_accepted_value_on_any_write_path() {
    for mode in 0..3 {
        let f = Fixture::new().await;
        let original = must_repo(
            f.repository
                .put_committed(
                    &f.anchor,
                    key(),
                    Bytes::from_static(b"abc"),
                    RepositoryPutOptions::default(),
                )
                .await,
        );
        let before = must_v2(f.anchor.read_v2().await);
        let options = RepositoryPutOptions {
            expected_md5: Some(original.etag.digest()),
            ..Default::default()
        };
        let stream = || futures_util::stream::iter([Ok(Bytes::from_static(b"bad"))]);
        let result = match mode {
            0 => {
                f.repository
                    .put_committed(&f.anchor, key(), Bytes::from_static(b"bad"), options)
                    .await
            }
            1 => {
                f.repository
                    .put_committed_streaming_known_len(
                        &f.anchor,
                        key(),
                        3,
                        stream(),
                        options,
                        5 * 1024 * 1024,
                    )
                    .await
            }
            _ => {
                f.repository
                    .put_committed_streaming_unknown_len(
                        &f.anchor,
                        key(),
                        stream(),
                        options,
                        5 * 1024 * 1024,
                        10,
                    )
                    .await
            }
        };
        assert!(matches!(result, Err(RepositoryError::ContentMd5Mismatch)));
        assert_eq!(must_v2(f.anchor.read_v2().await), before);
        assert_eq!(must_repo(f.repository.head(&key())).etag, original.etag);
        assert_eq!(
            must_repo(f.reopen().await.get_range(&key(), ByteRange::Full).await),
            Bytes::from_static(b"abc")
        );
    }
}

#[tokio::test]
async fn missing_trusted_manifest_cannot_synthesize_object_metadata_or_etag() {
    let f = Fixture::new().await;
    must_repo(
        f.repository
            .put_committed(
                &f.anchor,
                key(),
                Bytes::from_static(b"abc"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    must_repo(f.repository.clear_trusted_manifests_for_tests());
    assert!(f.repository.head(&key()).is_err());
    assert!(
        f.repository
            .get_range(&key(), ByteRange::Full)
            .await
            .is_err()
    );
}
