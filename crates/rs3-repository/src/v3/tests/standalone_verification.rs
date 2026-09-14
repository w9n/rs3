use super::*;
use rs3_storage::MAX_BLOB_READ_CHUNK_BYTES;
use std::sync::atomic::AtomicBool;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum ReadbackFault {
    #[default]
    None,
    Corrupt(usize),
    Truncated,
    Unreadable,
    Trailing,
    AdvertisedLength,
    WrongVersion,
    OversizedChunk,
    Unsupported,
}

#[derive(Default)]
pub(super) struct ReadbackProbe {
    fault: Mutex<ReadbackFault>,
    pub opens: AtomicUsize,
    bytes: AtomicUsize,
    maximum_chunk: AtomicUsize,
    terminal: AtomicBool,
}

impl ReadbackProbe {
    pub fn fault(&self) -> ReadbackFault {
        *self.fault.lock().expect("readback fault lock")
    }
}

pub(super) struct ObservedReadback {
    inner: Box<dyn BlobRead>,
    probe: Arc<ReadbackProbe>,
    fault: ReadbackFault,
    offset: usize,
}

impl ObservedReadback {
    pub fn new(inner: Box<dyn BlobRead>, probe: Arc<ReadbackProbe>, corrupt: bool) -> Self {
        let fault = if corrupt {
            ReadbackFault::Corrupt(0)
        } else {
            probe.fault()
        };
        Self {
            inner,
            probe,
            fault,
            offset: 0,
        }
    }
}

#[async_trait::async_trait]
impl BlobRead for ObservedReadback {
    fn exact_len(&self) -> u64 {
        self.inner.exact_len() + u64::from(self.fault == ReadbackFault::AdvertisedLength)
    }

    async fn next_chunk(&mut self) -> rs3_storage::Result<Option<Bytes>> {
        if self.offset > 0 {
            match self.fault {
                ReadbackFault::Truncated => return Ok(None),
                ReadbackFault::Unreadable => {
                    return Err(StorageError::Provider(
                        "injected readback failure".to_owned(),
                    ));
                }
                _ => {}
            }
        }
        let Some(mut chunk) = self.inner.next_chunk().await? else {
            if self.fault == ReadbackFault::Trailing {
                return Ok(Some(Bytes::from_static(b"x")));
            }
            self.probe.terminal.store(true, Ordering::SeqCst);
            return Ok(None);
        };
        if let ReadbackFault::Corrupt(offset) = self.fault
            && (self.offset..self.offset + chunk.len()).contains(&offset)
        {
            let mut bytes = chunk.to_vec();
            bytes[offset - self.offset] ^= 0x80;
            chunk = Bytes::from(bytes);
        }
        if self.fault == ReadbackFault::OversizedChunk {
            chunk = Bytes::from(vec![0; MAX_BLOB_READ_CHUNK_BYTES + 1]);
        }
        self.offset += chunk.len();
        self.probe.bytes.fetch_add(chunk.len(), Ordering::SeqCst);
        self.probe
            .maximum_chunk
            .fetch_max(chunk.len(), Ordering::SeqCst);
        Ok(Some(chunk))
    }
}

#[tokio::test]
async fn standalone_publication_requires_complete_bounded_exact_version_readback() {
    let body_len = 2 * MAX_BLOB_READ_CHUNK_BYTES + 17;
    // Three segments at the repository's one-MiB default, each with a 16-byte tag.
    let stored_len = body_len + 3 * 16;
    for fault in [
        ReadbackFault::None,
        ReadbackFault::Corrupt(0),
        ReadbackFault::Corrupt(MAX_BLOB_READ_CHUNK_BYTES + 3),
        ReadbackFault::Corrupt(stored_len - 1),
        ReadbackFault::Truncated,
        ReadbackFault::Unreadable,
        ReadbackFault::Trailing,
        ReadbackFault::AdvertisedLength,
        ReadbackFault::WrongVersion,
        ReadbackFault::OversizedChunk,
        ReadbackFault::Unsupported,
    ] {
        let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
        let repository = Arc::new(V3Repository::new(
            store.clone(),
            must_crypto(KeyRing::generate_random()),
            RepositoryOptions {
                payload_segment_size: MAX_BLOB_READ_CHUNK_BYTES,
                adaptive_payload_segment_size: false,
                ..RepositoryOptions::default()
            },
            V3CommitStoreOptions::for_profile(
                V3ProviderProfile::Dev,
                sample_repository_id(),
                sample_keyring_envelope_ref(),
                sample_format_ref(),
            ),
        ));
        let anchor = V3MemoryAnchor::new();
        must_repo(repository.write_genesis_snapshot(&anchor).await);
        let accepted = must_v3(anchor.read_v3().await);
        let coordinator = must_repo(V3CommitCoordinator::new(
            Arc::clone(&repository),
            anchor.clone(),
        ));
        *store.readback_probe.fault.lock().expect("fault lock") = fault;
        let key = must_type(LogicalPath::new("private/readback-test"));
        let body = Bytes::from(vec![0x5a; body_len]);
        let result = coordinator
            .put_committed_streaming_known_len(
                key.clone(),
                body_len as u64,
                stream::iter(vec![Ok::<Bytes, RepositoryError>(body)]),
                RepositoryPutOptions::default(),
                MAX_BLOB_READ_CHUNK_BYTES,
            )
            .await;
        let objects = store
            .inner
            .list_prefix_versions("objects/v03/")
            .await
            .expect("payload inventory");
        assert_eq!(
            objects.len(),
            1,
            "completed payload remains present for {fault:?}"
        );
        assert_eq!(objects[0].content_len, stored_len as u64);
        if fault == ReadbackFault::None {
            assert!(result.is_ok(), "valid upload: {result:?}");
            assert_ne!(must_v3(anchor.read_v3().await), accepted);
            assert!(repository.head(&key).is_ok());
            assert_eq!(store.readback_probe.opens.load(Ordering::SeqCst), 1);
            assert_eq!(
                store.readback_probe.bytes.load(Ordering::SeqCst),
                stored_len
            );
            assert_eq!(
                store.readback_probe.maximum_chunk.load(Ordering::SeqCst),
                MAX_BLOB_READ_CHUNK_BYTES
            );
            assert!(store.readback_probe.terminal.load(Ordering::SeqCst));
        } else {
            assert!(result.is_err(), "accepted {fault:?}");
            assert_eq!(
                must_v3(anchor.read_v3().await),
                accepted,
                "published {fault:?}"
            );
            assert!(repository.head(&key).is_err(), "visible {fault:?}");
            assert_eq!(
                store
                    .inner
                    .list_prefix("commits/v03/")
                    .await
                    .expect("commits")
                    .len(),
                1,
                "no commit for {fault:?}"
            );
        }
    }
}
