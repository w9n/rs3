use super::*;

#[tokio::test]
async fn put_then_head_get_and_list() {
    let store = MemoryBlobStore::new();
    let repo = Repository::new(store, secret());
    let key = key("p/12/abcdef");

    let put = repo
        .put(
            key.clone(),
            Bytes::from_static(b"hello world"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(put.is_ok());

    let head = repo.head(&key);
    let body = repo.get_range(&key, ByteRange::Full).await;
    let listed = repo.list("p/12");

    assert_eq!(must(head).content_len, 11);
    assert_eq!(must(body), Bytes::from_static(b"hello world"));
    assert_eq!(
        must(listed)
            .into_iter()
            .map(|entry| entry.key)
            .collect::<Vec<_>>(),
        vec![key]
    );
}

#[tokio::test]
async fn list_preserves_arbitrary_prefix_semantics_with_delimiter_index() {
    let store = MemoryBlobStore::new();
    let repo = Repository::new(store, secret());
    let first = key("p/12/a");
    let second = key("p/123/b");

    for key in [first.clone(), second.clone()] {
        let put = repo
            .put(
                key,
                Bytes::from_static(b"body"),
                RepositoryPutOptions::default(),
            )
            .await;
        assert!(put.is_ok());
    }

    let arbitrary_prefix = repo.list("p/12");
    let delimiter_prefix = repo.list("p/12/");

    assert_eq!(
        must(arbitrary_prefix)
            .into_iter()
            .map(|entry| entry.key)
            .collect::<Vec<_>>(),
        vec![first.clone(), second]
    );
    assert_eq!(
        must(delimiter_prefix)
            .into_iter()
            .map(|entry| entry.key)
            .collect::<Vec<_>>(),
        vec![first]
    );
}

#[tokio::test]
async fn put_uses_wall_clock_when_backend_omits_put_timestamp() {
    let repo = Repository::new(
        NoPutTimestampStore {
            inner: MemoryBlobStore::new(),
        },
        secret(),
    );
    let key = key("p/12/no-provider-timestamp");
    let before = now_ms();

    let put = repo
        .put(
            key.clone(),
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
        )
        .await;
    let after = now_ms();
    let head = repo.head(&key);

    assert!(put.is_ok());
    let modified_at_ms = must(head).modified_at_ms;
    assert!(modified_at_ms >= before);
    assert!(modified_at_ms <= after);
}

#[tokio::test]
async fn create_only_rejects_existing_namespace_entry() {
    let repo = Repository::new(MemoryBlobStore::new(), secret());
    let key = key("p/12/abcdef");
    let options = RepositoryPutOptions {
        create_only: true,
        retention: None,
        legal_hold: None,
    };

    let first = repo
        .put(key.clone(), Bytes::from_static(b"first"), options.clone())
        .await;
    let second = repo
        .put(key.clone(), Bytes::from_static(b"second"), options)
        .await;

    assert!(first.is_ok());
    assert!(matches!(second, Err(RepositoryError::AlreadyExists(_))));
}
