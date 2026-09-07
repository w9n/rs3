use super::*;
use rs3_storage::{CountingBlobStore, MemoryBlobStore};

fn repository<S: BlobStore>(store: S) -> V2CommitStore<S> {
    V2CommitStore::new(
        store,
        KeyRing::generate_random().expect("keys"),
        V2CommitStoreOptions::for_profile(
            V2ProviderProfile::Dev,
            RepositoryId::new("multipart-fixture").expect("repo"),
            V2KeyringEnvelopeRef {
                object_id: BackendObjectId::new("keyrings/fixture").expect("key"),
                digest: [1; 32],
            },
            V2FormatRef {
                generation: 1,
                digest: hex::encode([2; 32]),
                object_id: BackendObjectId::new("format/fixture").expect("format"),
                version_id: None,
            },
        ),
    )
}

struct Plaintext {
    bytes: Bytes,
    declared: u64,
}

#[async_trait]
impl BlobRead for Plaintext {
    fn exact_len(&self) -> u64 {
        self.declared
    }
    async fn next_chunk(&mut self) -> rs3_storage::Result<Option<Bytes>> {
        if self.bytes.is_empty() {
            return Ok(None);
        }
        Ok(Some(self.bytes.split_to(self.bytes.len().min(4096))))
    }
}

fn plaintext(bytes: Bytes) -> Box<dyn BlobRead> {
    Box::new(Plaintext {
        declared: bytes.len() as u64,
        bytes,
    })
}

#[tokio::test]
async fn multipart_selected_attempts_restore_across_part_boundaries_with_one_readback() {
    let store = CountingBlobStore::new(MemoryBlobStore::new());
    let repo = repository(store.clone());
    let upload = repo
        .create_client_multipart_upload(None, None)
        .await
        .expect("create");
    let object_id = upload.object_id.clone();
    assert!(
        repo.is_inflight_standalone_object(&object_id)
            .expect("root")
    );
    let prefix = Bytes::from(vec![7; rs3_storage::MULTIPART_MIN_PART_BYTES as usize]);
    let (first, old) = tokio::join!(
        upload.upload_part(2, plaintext(prefix)),
        upload.upload_part(7, plaintext(Bytes::from_static(b"tail")))
    );
    let first = first.expect("first");
    let old = old.expect("old");
    let last = upload
        .upload_part(7, plaintext(Bytes::from_static(b"tail")))
        .await
        .expect("replacement");
    assert_ne!(
        old.etag(),
        last.etag(),
        "equal plaintext is a fresh sealing attempt"
    );
    assert_ne!(old.digest, last.digest);
    upload
        .upload_part(5, plaintext(Bytes::from_static(b"omitted")))
        .await
        .expect("unused");
    store.reset_operation_counts().expect("reset");
    let verified = repo
        .complete_client_multipart_upload(upload, vec![first, last])
        .await
        .expect("verified");
    assert_eq!(
        verified.plaintext_len(),
        rs3_storage::MULTIPART_MIN_PART_BYTES + 4
    );
    let stored = verified.stored.as_ref().expect("carrier");
    let counts = store.operation_counts().expect("counts");
    assert_eq!(
        counts.get, 1,
        "one complete readback without a visibility sample"
    );
    assert_eq!(counts.bytes_read, stored.object_len);
    assert_eq!(counts.put, 0, "verification does not publish a commit");
    let bytes = store
        .get_range_at(&object_id, stored.version_id.as_ref(), ByteRange::Full)
        .await
        .expect("ciphertext");
    assert_eq!(Sha256Hasher::digest(&bytes), stored.object_digest);
    assert_eq!(
        stored
            .payload_layout
            .parts
            .iter()
            .map(|part| part.part_number)
            .collect::<Vec<_>>(),
        vec![2, 7]
    );
    let opened = crate::payload::open_payload_object(
        &repo.keyring,
        &object_id,
        &stored.payload_layout,
        bytes,
        ByteRange::Slice {
            offset: rs3_storage::MULTIPART_MIN_PART_BYTES - 2,
            len: 6,
        },
    )
    .expect("cross-part range");
    assert_eq!(opened.as_ref(), b"\x07\x07tail");
    assert!(
        repo.is_inflight_standalone_object(&object_id)
            .expect("protected until publication")
    );
    drop(verified);
    assert!(
        !repo
            .is_inflight_standalone_object(&object_id)
            .expect("released")
    );
}

#[tokio::test]
async fn multipart_empty_and_stale_zero_length_selections_have_no_carrier() {
    let repo = repository(MemoryBlobStore::new());
    let upload = repo
        .create_client_multipart_upload(None, None)
        .await
        .expect("create");
    let id = upload.object_id.clone();
    let part = upload
        .upload_part(10_000, plaintext(Bytes::new()))
        .await
        .expect("empty");
    let verified = repo
        .complete_client_multipart_upload(upload, vec![part])
        .await
        .expect("empty complete");
    assert_eq!(verified.plaintext_len(), 0);
    assert!(verified.stored.is_none());
    assert!(repo.store.head(&id).await.is_err());
    let upload = repo
        .create_client_multipart_upload(None, None)
        .await
        .expect("new");
    let empty = upload
        .upload_part(1, plaintext(Bytes::new()))
        .await
        .expect("empty");
    upload
        .upload_part(1, plaintext(Bytes::from_static(b"new")))
        .await
        .expect("replacement");
    assert!(
        repo.complete_client_multipart_upload(upload, vec![empty])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn multipart_small_nonfinal_foreign_and_corrupt_expected_parts_fail_closed() {
    for case in 0..4 {
        let repo = repository(MemoryBlobStore::new());
        let upload = repo
            .create_client_multipart_upload(None, None)
            .await
            .expect("create");
        let id = upload.object_id.clone();
        let mut part = upload
            .upload_part(1, plaintext(Bytes::from_static(b"abc")))
            .await
            .expect("part");
        let selected = match case {
            0 => vec![
                part,
                upload
                    .upload_part(2, plaintext(Bytes::from_static(b"tail")))
                    .await
                    .expect("tail"),
            ],
            1 => {
                let other = repo
                    .create_client_multipart_upload(None, None)
                    .await
                    .expect("other");
                let foreign = other
                    .upload_part(1, plaintext(Bytes::new()))
                    .await
                    .expect("foreign empty");
                other.abort().await.expect("abort");
                vec![foreign]
            }
            2 => {
                part.digest[31] ^= 1;
                vec![part]
            }
            _ => {
                upload
                    .upload_part(1, plaintext(Bytes::from_static(b"new")))
                    .await
                    .expect("replace");
                vec![part]
            }
        };
        assert!(
            repo.complete_client_multipart_upload(upload, selected)
                .await
                .is_err(),
            "case {case}"
        );
        assert!(!repo.is_inflight_standalone_object(&id).expect("released"));
        assert_eq!(
            repo.store.head(&id).await.is_ok(),
            case == 2,
            "only post-completion mismatch leaves a carrier orphan"
        );
    }
}

#[tokio::test]
async fn multipart_plaintext_length_errors_never_accept_a_part() {
    let repo = repository(MemoryBlobStore::new());
    let upload = repo
        .create_client_multipart_upload(None, None)
        .await
        .expect("create");
    for declared in [0, 2, 4] {
        let read = Plaintext {
            bytes: Bytes::from_static(b"abc"),
            declared,
        };
        assert!(upload.upload_part(1, Box::new(read)).await.is_err());
    }
    assert!(upload.parts.read().expect("parts").is_empty());
    assert!(
        upload
            .upload_part(0, plaintext(Bytes::new()))
            .await
            .is_err()
    );
    assert!(
        upload
            .upload_part(10_001, plaintext(Bytes::new()))
            .await
            .is_err()
    );
    assert!(
        upload
            .upload_part(
                1,
                Box::new(Plaintext {
                    bytes: Bytes::new(),
                    declared: rs3_storage::MULTIPART_MAX_PART_BYTES
                })
            )
            .await
            .is_err(),
        "encryption overhead exceeds provider part ceiling"
    );
    upload.abort().await.expect("abort");
}

#[tokio::test]
async fn multipart_ambiguous_completion_returns_no_publication_input() {
    use rs3_storage::{
        FaultAction, FaultInjectingBlobStore, FaultMatcher, FaultOperationKind, FaultRule,
    };
    let memory = MemoryBlobStore::new();
    let fault = FaultInjectingBlobStore::new(
        memory.clone(),
        vec![FaultRule::new(
            FaultMatcher::operation(FaultOperationKind::MultipartComplete),
            FaultAction::error_after_write("lost completion response"),
        )],
    );
    let repo = repository(fault);
    let upload = repo
        .create_client_multipart_upload(None, None)
        .await
        .expect("create");
    let id = upload.object_id.clone();
    let part = upload
        .upload_part(1, plaintext(Bytes::from_static(b"abc")))
        .await
        .expect("part");
    assert!(
        repo.complete_client_multipart_upload(upload, vec![part])
            .await
            .is_err()
    );
    assert!(
        memory.head(&id).await.is_ok(),
        "completed opaque orphan is not an accepted logical value"
    );
    assert!(!repo.is_inflight_standalone_object(&id).expect("released"));
}

#[tokio::test]
async fn multipart_retained_completion_preserves_exact_version_and_full_post_completion_horizon() {
    let mut repo = repository(CountingBlobStore::new(MemoryBlobStore::new()));
    repo.options.provider_profile = V2ProviderProfile::RetainedVersionObjectLock;
    let retention = RetentionPolicy::new(RetentionMode::Governance, 30);
    let upload = repo
        .create_client_multipart_upload(Some(retention), None)
        .await
        .expect("retained create");
    let part = upload
        .upload_part(1, plaintext(Bytes::from_static(b"retained")))
        .await
        .expect("part");
    let floor = required_retain_until_ms(Some(retention)).expect("horizon");
    let verified = repo
        .complete_client_multipart_upload(upload, vec![part])
        .await
        .expect("verified");
    let stored = verified.stored.as_ref().expect("carrier");
    assert!(stored.version_id.is_some());
    let metadata = repo
        .store
        .head_at(&stored.object_id, stored.version_id.as_ref())
        .await
        .expect("exact protected version");
    assert!(
        metadata
            .retain_until_ms
            .is_some_and(|deadline| deadline >= floor)
    );
    assert_eq!(metadata.retention, Some(retention));
    let counts = repo.store.operation_counts().expect("counts");
    assert_eq!(counts.extend_retention, 1);
}

#[tokio::test]
async fn multipart_zero_length_final_part_does_not_enter_ciphertext_layout() {
    let repo = repository(MemoryBlobStore::new());
    let upload = repo
        .create_client_multipart_upload(None, None)
        .await
        .expect("create");
    let first = upload
        .upload_part(
            1,
            plaintext(Bytes::from(vec![
                3;
                rs3_storage::MULTIPART_MIN_PART_BYTES
                    as usize
            ])),
        )
        .await
        .expect("first");
    let empty = upload
        .upload_part(9, plaintext(Bytes::new()))
        .await
        .expect("empty final");
    let verified = repo
        .complete_client_multipart_upload(upload, vec![first, empty])
        .await
        .expect("complete");
    let stored = verified.stored.as_ref().expect("carrier");
    assert_eq!(stored.payload_layout.parts.len(), 1);
    assert_eq!(stored.payload_layout.parts[0].part_number, 1);
    assert_eq!(
        stored.payload_layout.plaintext_len,
        rs3_storage::MULTIPART_MIN_PART_BYTES
    );
}

#[tokio::test]
async fn multipart_stalled_input_does_not_accept_part_and_can_abort() {
    struct Stalled;
    #[async_trait]
    impl BlobRead for Stalled {
        fn exact_len(&self) -> u64 {
            1
        }
        async fn next_chunk(&mut self) -> rs3_storage::Result<Option<Bytes>> {
            std::future::pending().await
        }
    }
    let mut repo = repository(MemoryBlobStore::new());
    repo.options.stream_read_stall_timeout = Duration::from_millis(5);
    let upload = repo
        .create_client_multipart_upload(None, None)
        .await
        .expect("create");
    let id = upload.object_id.clone();
    assert!(
        tokio::time::timeout(
            Duration::from_secs(1),
            upload.upload_part(1, Box::new(Stalled))
        )
        .await
        .expect("bounded stall")
        .is_err()
    );
    assert!(upload.parts.read().expect("parts").is_empty());
    upload.abort().await.expect("abort");
    assert!(!repo.is_inflight_standalone_object(&id).expect("released"));
}
