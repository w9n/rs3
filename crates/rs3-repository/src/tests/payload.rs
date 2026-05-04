use super::*;

#[tokio::test]
async fn backend_payload_does_not_store_plaintext() {
    let store = MemoryBlobStore::new();
    let repo = Repository::with_keyring(store.clone(), signing_keyring());
    let client_key = key("p/12/encrypted-client-blob");
    let plaintext = Bytes::from_static(b"very sensitive payload marker");

    let put = repo
        .put(
            client_key.clone(),
            plaintext.clone(),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(put.is_ok());

    let payload = must_storage(store.list_prefix("segments/").await)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing payload object"));
    let backend_body = must_storage(store.get_range(&payload.object_id, ByteRange::Full).await);
    let repository_body = repo.get_range(&client_key, ByteRange::Full).await;
    let head = repo.head(&client_key);

    assert_ne!(backend_body, plaintext);
    assert_body_does_not_contain(&backend_body, &["very sensitive payload marker"]);
    assert_eq!(must(repository_body), plaintext);
    assert_eq!(must(head).content_len, 29);
    assert!(payload.content_len > 29);
}

#[tokio::test]
async fn tampered_backend_payload_fails_repository_read() {
    let store = MemoryBlobStore::new();
    let repo = Repository::with_keyring(store.clone(), signing_keyring());
    let client_key = key("p/12/tampered");

    let put = repo
        .put(
            client_key.clone(),
            Bytes::from_static(b"payload"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(put.is_ok());

    let payload = must_storage(store.list_prefix("segments/").await)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing payload object"));
    let mut backend_body =
        must_storage(store.get_range(&payload.object_id, ByteRange::Full).await).to_vec();
    let last = backend_body
        .last_mut()
        .unwrap_or_else(|| panic!("payload object is empty"));
    *last ^= 0x01;

    let overwrite = store
        .put(
            &payload.object_id,
            Bytes::from(backend_body),
            PutOptions::default(),
        )
        .await;
    assert!(overwrite.is_ok());

    let read = repo.get_range(&client_key, ByteRange::Full).await;

    assert!(matches!(read, Err(RepositoryError::Crypto(_))));
}

#[tokio::test]
async fn range_get_uses_repository_mapping() {
    let repo = Repository::with_keyring(MemoryBlobStore::new(), signing_keyring());
    let key = key("p/12/abcdef");

    let put = repo
        .put(
            key.clone(),
            Bytes::from_static(b"hello world"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(put.is_ok());

    let body = repo
        .get_range(&key, ByteRange::Slice { offset: 6, len: 5 })
        .await;

    assert_eq!(must(body), Bytes::from_static(b"world"));
}

#[tokio::test]
async fn large_range_get_reads_only_header_and_selected_segment() {
    let store = MemoryBlobStore::new();
    let repo = Repository::with_keyring(store.clone(), signing_keyring());
    let key = key("p/12/large-range");
    let body = Bytes::from(vec![42_u8; 1024 * 1024]);

    let put = repo
        .put(key.clone(), body, RepositoryPutOptions::default())
        .await;
    assert!(put.is_ok());
    must_storage(store.reset_operation_counts());

    let read = repo
        .get_range(
            &key,
            ByteRange::Slice {
                offset: 512 * 1024,
                len: 8192,
            },
        )
        .await;
    let counts = must_storage(store.operation_counts());

    assert_eq!(must(read), Bytes::from(vec![42_u8; 8192]));
    assert_eq!(counts.get, 2);
    assert!(counts.bytes_read < 300 * 1024);
}

#[tokio::test]
async fn repeated_large_range_gets_reuse_payload_header() {
    let store = MemoryBlobStore::new();
    let repo = Repository::with_keyring(store.clone(), signing_keyring());
    let key = key("p/12/repeated-large-range");
    let body = Bytes::from(vec![91_u8; 1024 * 1024]);

    let put = repo
        .put(key.clone(), body, RepositoryPutOptions::default())
        .await;
    assert!(put.is_ok());
    must_storage(store.reset_operation_counts());

    for offset in [256 * 1024, 512 * 1024] {
        let read = repo
            .get_range(&key, ByteRange::Slice { offset, len: 8192 })
            .await;
        assert_eq!(must(read), Bytes::from(vec![91_u8; 8192]));
    }

    let counts = must_storage(store.operation_counts());
    assert_eq!(counts.get, 3);
    assert!(counts.bytes_read < 600 * 1024);
}

#[tokio::test]
async fn repeated_same_segment_range_gets_reuse_ciphertext_span() {
    let store = MemoryBlobStore::new();
    let repo = Repository::with_keyring(store.clone(), signing_keyring());
    let key = key("p/12/repeated-same-segment-range");
    let body = Bytes::from(vec![37_u8; 1024 * 1024]);

    let put = repo
        .put(key.clone(), body, RepositoryPutOptions::default())
        .await;
    assert!(put.is_ok());
    must_storage(store.reset_operation_counts());

    for _ in 0..3 {
        let read = repo
            .get_range(
                &key,
                ByteRange::Slice {
                    offset: 512 * 1024,
                    len: 64,
                },
            )
            .await;
        assert_eq!(must(read), Bytes::from(vec![37_u8; 64]));
    }

    let counts = must_storage(store.operation_counts());
    assert_eq!(counts.get, 2);
    assert!(counts.bytes_read < 1024);
}

#[tokio::test]
async fn first_segment_range_reuses_header_probe_ciphertext() {
    let store = MemoryBlobStore::new();
    let repo = Repository::with_keyring(store.clone(), signing_keyring());
    let key = key("p/12/first-segment-prefetch");
    let body = Bytes::from(vec![11_u8; 256]);

    let put = repo
        .put(key.clone(), body, RepositoryPutOptions::default())
        .await;
    assert!(put.is_ok());
    let payload = must_storage(store.list_prefix("segments/").await)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing payload object"));
    assert!(payload.content_len > PAYLOAD_HEADER_PROBE_LEN);
    must_storage(store.reset_operation_counts());

    let read = repo
        .get_range(&key, ByteRange::Slice { offset: 0, len: 32 })
        .await;
    let counts = must_storage(store.operation_counts());

    assert_eq!(must(read), Bytes::from(vec![11_u8; 32]));
    assert_eq!(counts.get, 2);
    assert_eq!(counts.bytes_read, payload.content_len);
}

#[tokio::test]
async fn range_read_amplification_tracks_payload_segment_size() {
    let object_size = 4 * 1024 * 1024;
    let range_len = 8 * 1024;
    let reads = 96;

    let large = range_read_pressure(256 * 1024, object_size, range_len, reads).await;
    let medium = range_read_pressure(32 * 1024, object_size, range_len, reads).await;
    let small = range_read_pressure(8 * 1024, object_size, range_len, reads).await;

    assert!(
        large.gets < reads as u64 + 1,
        "large segment cache did not reduce backend GETs: {}",
        large.gets
    );
    assert!(
        medium.gets <= reads as u64 + 1,
        "medium segment GETs exceeded one span read per request plus header: {}",
        medium.gets
    );
    assert!(
        small.gets <= reads as u64 + 1,
        "small segment GETs exceeded one span read per request plus header: {}",
        small.gets
    );
    assert_eq!(large.returned_bytes, small.returned_bytes);
    assert!(large.bytes_read > medium.bytes_read);
    assert!(medium.bytes_read > small.bytes_read);
    assert!(
        large.read_amp() > 5.0,
        "large segment amp was {}",
        large.read_amp()
    );
    assert!(
        medium.read_amp() < 6.5,
        "medium segment amp was {}",
        medium.read_amp()
    );
    assert!(
        small.read_amp() < 2.5,
        "small segment amp was {}",
        small.read_amp()
    );
}

struct RangeReadPressure {
    gets: u64,
    bytes_read: u64,
    returned_bytes: u64,
}

impl RangeReadPressure {
    fn read_amp(&self) -> f64 {
        self.bytes_read as f64 / self.returned_bytes as f64
    }
}

async fn range_read_pressure(
    payload_segment_size: usize,
    object_size: usize,
    range_len: usize,
    reads: usize,
) -> RangeReadPressure {
    let store = MemoryBlobStore::new();
    let repo = repository_with_payload_segment_size(store.clone(), payload_segment_size);
    let key = key(&format!("p/12/range-pressure-{payload_segment_size}"));
    let body = Bytes::from(vec![17_u8; object_size]);
    must(
        repo.put(key.clone(), body, RepositoryPutOptions::default())
            .await,
    );
    must_storage(store.reset_operation_counts());

    let offset_window = object_size.saturating_sub(range_len);
    let mut returned_bytes = 0_u64;
    for index in 0..reads {
        let offset = if offset_window == 0 {
            0
        } else {
            index.wrapping_mul(65_537).wrapping_add(index / 7 * 4_096) % (offset_window + 1)
        };
        let body = must(
            repo.get_range(
                &key,
                ByteRange::Slice {
                    offset: offset as u64,
                    len: range_len as u64,
                },
            )
            .await,
        );
        assert_eq!(body.len(), range_len);
        returned_bytes = returned_bytes.saturating_add(body.len() as u64);
    }

    let counts = must_storage(store.operation_counts());
    RangeReadPressure {
        gets: counts.get,
        bytes_read: counts.bytes_read,
        returned_bytes,
    }
}
