use super::*;

#[tokio::test]
async fn draft_signed_checkpoint_has_verifiable_signature() {
    let active_keyring = keyring(vec![
        namespace_key("namespace", KeyStatus::Primary, 1),
        checkpoint_key("signing", KeyStatus::Primary, 2),
    ]);
    let verifier = active_keyring.clone();
    let repo = Repository::with_keyring(MemoryBlobStore::new(), active_keyring);
    let key = key("p/12/abcdef");

    let put = repo
        .put(
            key,
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(put.is_ok());

    let checkpoint = must(repo.draft_signed_checkpoint(None));
    let canonical_payload =
        canonical_commit_record_bytes(&checkpoint.record).unwrap_or_else(|error| {
            panic!("{error}");
        });
    let verified = verifier.verify_checkpoint_payload(
        &checkpoint.signature_key_id,
        &canonical_payload,
        &checkpoint.signature,
    );

    assert_eq!(checkpoint.signature_key_id, key_id("signing"));
    assert_eq!(checkpoint.sequence(), Sequence::new(1));
    assert!(verified.is_ok());
}

#[tokio::test]
async fn verify_signed_checkpoint_returns_checkpoint_position() {
    let active_keyring = keyring(vec![
        namespace_key("namespace", KeyStatus::Primary, 1),
        checkpoint_key("signing", KeyStatus::Primary, 2),
    ]);
    let repo = Repository::with_keyring(MemoryBlobStore::new(), active_keyring);

    let put = repo
        .put(
            key("p/12/abcdef"),
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(put.is_ok());

    let checkpoint = must(repo.draft_signed_checkpoint(None));
    let position = must(repo.verify_signed_checkpoint(&checkpoint, None));

    assert_eq!(position.sequence, Sequence::new(1));
    assert_eq!(position.checkpoint_id, checkpoint.id);
    assert!(!position.payload_digest.is_empty());
}

#[tokio::test]
async fn verify_signed_checkpoint_rejects_tampered_record() {
    let active_keyring = keyring(vec![
        namespace_key("namespace", KeyStatus::Primary, 1),
        checkpoint_key("signing", KeyStatus::Primary, 2),
    ]);
    let repo = Repository::with_keyring(MemoryBlobStore::new(), active_keyring);

    let put = repo
        .put(
            key("p/12/abcdef"),
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(put.is_ok());

    let mut checkpoint = must(repo.draft_signed_checkpoint(None));
    checkpoint.record.sequence = Sequence::new(99);

    let verified = repo.verify_signed_checkpoint(&checkpoint, None);

    assert!(verified.is_err());
}

#[tokio::test]
async fn verify_signed_checkpoint_rejects_id_mismatch() {
    let active_keyring = keyring(vec![
        namespace_key("namespace", KeyStatus::Primary, 1),
        checkpoint_key("signing", KeyStatus::Primary, 2),
    ]);
    let repo = Repository::with_keyring(MemoryBlobStore::new(), active_keyring);

    let put = repo
        .put(
            key("p/12/abcdef"),
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(put.is_ok());

    let mut checkpoint = must(repo.draft_signed_checkpoint(None));
    checkpoint.id = checkpoint_id("wrong-checkpoint-id");

    let verified = repo.verify_signed_checkpoint(&checkpoint, None);

    assert!(matches!(
        verified,
        Err(RepositoryError::CheckpointIdMismatch)
    ));
}

#[tokio::test]
async fn verify_signed_checkpoint_rejects_stale_sequence() {
    let active_keyring = keyring(vec![
        namespace_key("namespace", KeyStatus::Primary, 1),
        checkpoint_key("signing", KeyStatus::Primary, 2),
    ]);
    let repo = Repository::with_keyring(MemoryBlobStore::new(), active_keyring);

    let put = repo
        .put(
            key("p/12/abcdef"),
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(put.is_ok());

    let checkpoint = must(repo.draft_signed_checkpoint(None));
    let accepted = CheckpointPosition {
        sequence: Sequence::new(2),
        checkpoint_id: checkpoint_id("newer"),
        payload_digest: "newer".to_string(),
    };

    let verified = repo.verify_signed_checkpoint(&checkpoint, Some(&accepted));

    assert!(matches!(
        verified,
        Err(RepositoryError::StaleCheckpoint { .. })
    ));
}

#[tokio::test]
async fn verify_signed_checkpoint_requires_parent_when_advancing() {
    let active_keyring = keyring(vec![
        namespace_key("namespace", KeyStatus::Primary, 1),
        checkpoint_key("signing", KeyStatus::Primary, 2),
    ]);
    let repo = Repository::with_keyring(MemoryBlobStore::new(), active_keyring);

    let first_put = repo
        .put(
            key("p/12/first"),
            Bytes::from_static(b"first"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(first_put.is_ok());

    let first = must(repo.draft_signed_checkpoint(None));
    let accepted = must(repo.verify_signed_checkpoint(&first, None));

    let second_put = repo
        .put(
            key("p/12/second"),
            Bytes::from_static(b"second"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(second_put.is_ok());

    let wrong_parent = must(repo.draft_signed_checkpoint(None));
    let rejected = repo.verify_signed_checkpoint(&wrong_parent, Some(&accepted));
    assert!(matches!(
        rejected,
        Err(RepositoryError::CheckpointParentMismatch)
    ));

    let chained = must(repo.draft_signed_checkpoint(Some(accepted.checkpoint_id.clone())));
    let advanced = repo.verify_signed_checkpoint(&chained, Some(&accepted));
    assert!(advanced.is_ok());
}

#[tokio::test]
async fn publish_checkpoint_initializes_empty_anchor() {
    let repo = Repository::with_keyring(MemoryBlobStore::new(), signing_keyring());
    let anchor = MemoryCheckpointAnchor::new();

    let put = repo
        .put(
            key("p/12/abcdef"),
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(put.is_ok());

    let published = repo.publish_checkpoint(&anchor).await;

    let position = must(published);
    assert_eq!(position.sequence, Sequence::new(1));
    assert!(!position.payload_digest.is_empty());
}

#[tokio::test]
async fn publish_checkpoint_persists_signed_checkpoint_before_anchor_advance() {
    let store = MemoryBlobStore::new();
    let repo = Repository::with_keyring(store.clone(), signing_keyring());
    let anchor = CheckpointMustExistAnchor::new(store.clone());

    let put = repo
        .put(
            key("p/12/abcdef"),
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(put.is_ok());

    let position = must(repo.publish_checkpoint(&anchor).await);
    let checkpoint_object_id = must(checkpoint_object_id(&position.checkpoint_id));
    let body = must_storage(
        store
            .get_range(&checkpoint_object_id, ByteRange::Full)
            .await,
    );
    let checkpoint = decode_checkpoint_object(body);
    let verified = repo.verify_signed_checkpoint(&checkpoint, None);

    assert_eq!(checkpoint.id, position.checkpoint_id);
    assert_eq!(verified.ok(), Some(position));
}

#[tokio::test]
async fn put_committed_returns_after_anchor_accepts_checkpoint() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let repo = Repository::with_keyring(store.clone(), keyring.clone());
    let anchor = CheckpointMustExistAnchor::new(store.clone());
    let client_key = key("p/12/committed");

    let committed = must(
        repo.put_committed(
            client_key.clone(),
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
            &anchor,
        )
        .await,
    );
    let anchored = match anchor.read().await {
        Ok(anchored) => anchored,
        Err(error) => panic!("{error}"),
    };
    let reloaded = Repository::with_keyring(store, keyring);
    let loaded = must(
        reloaded
            .load_checkpoint_position(&committed.checkpoint)
            .await,
    );
    let body = must(reloaded.get_range(&client_key, ByteRange::Full).await);

    assert_eq!(committed.metadata.content_len, 4);
    assert_eq!(committed.checkpoint.sequence, Sequence::new(1));
    assert_eq!(anchored.checkpoint_id, committed.checkpoint.checkpoint_id);
    assert_eq!(loaded, committed.checkpoint);
    assert_eq!(body, Bytes::from_static(b"body"));
}

#[tokio::test]
async fn put_committed_does_not_accept_write_when_checkpoint_put_fails() {
    let inner = MemoryBlobStore::new();
    let store = FailOncePutStore::new(inner.clone(), CHECKPOINT_OBJECT_PREFIX);
    let keyring = signing_keyring();
    let repo = Repository::with_keyring(store, keyring.clone());
    let anchor = MemoryCheckpointAnchor::new();
    let client_key = key("p/12/unaccepted");

    let committed = repo
        .put_committed(
            client_key.clone(),
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
            &anchor,
        )
        .await;
    let fresh = Repository::with_keyring(inner, keyring);
    let fresh_head = fresh.head(&client_key);

    assert!(matches!(
        committed,
        Err(RepositoryError::Storage(StorageError::Provider(_)))
    ));
    assert!(matches!(
        anchor.read().await,
        Err(AnchorError::MissingAnchor)
    ));
    assert!(matches!(fresh_head, Err(RepositoryError::NotFound(_))));
}

#[tokio::test]
async fn multiple_pending_puts_publish_as_one_checkpoint_batch() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let repo = Repository::with_keyring(store.clone(), keyring.clone());
    let anchor = MemoryCheckpointAnchor::new();
    let keys = [key("p/12/a"), key("p/12/b"), key("p/12/c")];

    for (index, key) in keys.iter().enumerate() {
        let put = repo
            .put(
                key.clone(),
                Bytes::from(format!("body-{index}")),
                RepositoryPutOptions::default(),
            )
            .await;
        assert!(put.is_ok());
    }

    let position = must(repo.publish_checkpoint(&anchor).await);
    let checkpoint_objects = must_storage(store.list_prefix(CHECKPOINT_OBJECT_PREFIX).await);
    let index_delta_objects = must_storage(store.list_prefix("index/").await);
    let payload_objects = must_storage(store.list_prefix("segments/").await);
    let reloaded = Repository::with_keyring(store, keyring);
    let loaded = must(reloaded.load_checkpoint_position(&position).await);
    let listed = must(reloaded.list("p/12"));

    assert_eq!(loaded, position);
    assert_eq!(checkpoint_objects.len(), 1);
    assert!(index_delta_objects.is_empty());
    assert_eq!(payload_objects.len(), keys.len());
    assert_eq!(
        listed
            .into_iter()
            .map(|entry| entry.key)
            .collect::<Vec<_>>(),
        keys
    );
}

#[tokio::test]
async fn load_checkpoint_position_replays_checkpoint_chain_for_head_and_get() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let repo = Repository::with_keyring(store.clone(), keyring.clone());
    let anchor = MemoryCheckpointAnchor::new();
    let first_key = key("p/12/first");
    let second_key = key("p/12/second");

    let first_put = repo
        .put(
            first_key.clone(),
            Bytes::from_static(b"first"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(first_put.is_ok());
    let first_publish = repo.publish_checkpoint(&anchor).await;
    assert!(first_publish.is_ok());

    let second_put = repo
        .put(
            second_key.clone(),
            Bytes::from_static(b"second"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(second_put.is_ok());
    let latest = must(repo.publish_checkpoint(&anchor).await);

    let reloaded = Repository::with_keyring(store.clone(), keyring);
    let loaded = must(reloaded.load_checkpoint_position(&latest).await);
    let first_head = reloaded.head(&first_key);
    let first_body = reloaded.get_range(&first_key, ByteRange::Full).await;
    let second_head = reloaded.head(&second_key);
    let second_body = reloaded.get_range(&second_key, ByteRange::Full).await;
    let listed = reloaded.list("p/12");

    assert_eq!(loaded, latest);
    assert_eq!(must(first_head).content_len, 5);
    assert_eq!(must(first_body), Bytes::from_static(b"first"));
    assert_eq!(must(second_head).content_len, 6);
    assert_eq!(must(second_body), Bytes::from_static(b"second"));
    assert_eq!(
        must(listed)
            .into_iter()
            .map(|entry| entry.key)
            .collect::<Vec<_>>(),
        vec![first_key, second_key]
    );
}

#[tokio::test]
async fn filesystem_store_reloads_checkpoint_chain_for_head_get_and_list() {
    let dir = TestDir::new();
    let store = FilesystemBlobStore::new(dir.path()).unwrap_or_else(|error| panic!("{error}"));
    let keyring = signing_keyring();
    let repo = Repository::with_keyring(store, keyring.clone());
    let anchor = MemoryCheckpointAnchor::new();
    let first_key = key("p/12/first");
    let second_key = key("p/12/second");

    let first_put = repo
        .put(
            first_key.clone(),
            Bytes::from_static(b"first"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(first_put.is_ok());
    let first_publish = repo.publish_checkpoint(&anchor).await;
    assert!(first_publish.is_ok());

    let second_put = repo
        .put(
            second_key.clone(),
            Bytes::from_static(b"second"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(second_put.is_ok());
    let latest = must(repo.publish_checkpoint(&anchor).await);

    let reloaded_store =
        FilesystemBlobStore::new(dir.path()).unwrap_or_else(|error| panic!("{error}"));
    let reloaded = Repository::with_keyring(reloaded_store, keyring);
    let loaded = must(reloaded.load_checkpoint_position(&latest).await);
    let first_head = reloaded.head(&first_key);
    let first_body = reloaded.get_range(&first_key, ByteRange::Full).await;
    let second_head = reloaded.head(&second_key);
    let second_body = reloaded.get_range(&second_key, ByteRange::Full).await;
    let listed = reloaded.list("p/12");

    assert_eq!(loaded, latest);
    assert_eq!(must(first_head).content_len, 5);
    assert_eq!(must(first_body), Bytes::from_static(b"first"));
    assert_eq!(must(second_head).content_len, 6);
    assert_eq!(must(second_body), Bytes::from_static(b"second"));
    assert_eq!(
        must(listed)
            .into_iter()
            .map(|entry| entry.key)
            .collect::<Vec<_>>(),
        vec![first_key, second_key]
    );
}

#[tokio::test]
async fn load_checkpoint_position_rejects_tampered_inline_index_delta() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let repo = Repository::with_keyring(store.clone(), keyring.clone());
    let anchor = MemoryCheckpointAnchor::new();

    let put = repo
        .put(
            key("p/12/abcdef"),
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(put.is_ok());
    let latest = must(repo.publish_checkpoint(&anchor).await);
    let checkpoint_object = must(checkpoint_object_id(&latest.checkpoint_id));
    let checkpoint_body = must_storage(store.get_range(&checkpoint_object, ByteRange::Full).await);
    let mut checkpoint = decode_checkpoint_object(checkpoint_body);
    let Some(inline_delta) = checkpoint.record.inline_index_delta.as_mut() else {
        panic!("missing inline index delta");
    };
    let Some(first_byte) = inline_delta.ciphertext.first_mut() else {
        panic!("inline index delta ciphertext is empty");
    };
    *first_byte ^= 1;
    let mut tampered_body = CHECKPOINT_OBJECT_DOMAIN.to_vec();
    if let Err(error) = serde_json::to_writer(&mut tampered_body, &checkpoint) {
        panic!("{error}");
    }
    let overwrite = store
        .put(
            &checkpoint_object,
            Bytes::from(tampered_body),
            PutOptions::default(),
        )
        .await;
    assert!(overwrite.is_ok());

    let reloaded = Repository::with_keyring(store, keyring);
    let loaded = reloaded.load_checkpoint_position(&latest).await;

    assert!(matches!(
        loaded,
        Err(RepositoryError::Crypto(_) | RepositoryError::CheckpointIdMismatch)
    ));
}

#[tokio::test]
async fn failed_checkpoint_put_leaves_batch_unaccepted_and_retryable() {
    let inner = MemoryBlobStore::new();
    let store = FailOncePutStore::new(inner.clone(), CHECKPOINT_OBJECT_PREFIX);
    let keyring = signing_keyring();
    let repo = Repository::with_keyring(store, keyring.clone());
    let anchor = MemoryCheckpointAnchor::new();
    let client_key = key("p/12/committed-after-retry");

    let put = repo
        .put(
            client_key.clone(),
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(put.is_ok());

    let first_publish = repo.publish_checkpoint(&anchor).await;
    let checkpoint_objects_after_failure =
        must_storage(inner.list_prefix(CHECKPOINT_OBJECT_PREFIX).await);
    let index_objects_after_failure = must_storage(inner.list_prefix("index/").await);
    let payload_objects_after_failure = must_storage(inner.list_prefix("segments/").await);
    let fresh = Repository::with_keyring(inner.clone(), keyring.clone());
    let fresh_head = fresh.head(&client_key);

    assert!(matches!(
        first_publish,
        Err(RepositoryError::Storage(StorageError::Provider(_)))
    ));
    assert!(matches!(
        anchor.read().await,
        Err(AnchorError::MissingAnchor)
    ));
    assert!(checkpoint_objects_after_failure.is_empty());
    assert!(index_objects_after_failure.is_empty());
    assert_eq!(payload_objects_after_failure.len(), 1);
    assert!(matches!(fresh_head, Err(RepositoryError::NotFound(_))));

    let position = must(repo.publish_checkpoint(&anchor).await);
    let reloaded = Repository::with_keyring(inner, keyring);
    let loaded = must(reloaded.load_checkpoint_position(&position).await);
    let body = must(reloaded.get_range(&client_key, ByteRange::Full).await);

    assert_eq!(loaded, position);
    assert_eq!(body, Bytes::from_static(b"body"));
}

#[tokio::test]
async fn publish_checkpoint_retries_after_anchor_failure_without_rewriting_checkpoint() {
    let store = MemoryBlobStore::new();
    let repo = Repository::with_keyring(store.clone(), signing_keyring());
    let anchor = FailOnceAnchor::new();

    let put = repo
        .put(
            key("p/12/abcdef"),
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(put.is_ok());

    let first = repo.publish_checkpoint(&anchor).await;
    let after_first = must_storage(store.list_prefix(CHECKPOINT_OBJECT_PREFIX).await);
    let second = must(repo.publish_checkpoint(&anchor).await);
    let after_second = must_storage(store.list_prefix(CHECKPOINT_OBJECT_PREFIX).await);

    assert!(matches!(
        first,
        Err(RepositoryError::Anchor(AnchorError::Backend(_)))
    ));
    assert_eq!(after_first.len(), 1);
    assert_eq!(second.sequence, Sequence::new(1));
    assert_eq!(after_second.len(), 1);
}

#[tokio::test]
async fn publish_checkpoint_is_idempotent_without_changes() {
    let repo = Repository::with_keyring(MemoryBlobStore::new(), signing_keyring());
    let anchor = MemoryCheckpointAnchor::new();

    let put = repo
        .put(
            key("p/12/abcdef"),
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(put.is_ok());

    let first = must(repo.publish_checkpoint(&anchor).await);
    let second = must(repo.publish_checkpoint(&anchor).await);

    assert_eq!(first, second);
}

#[tokio::test]
async fn publish_checkpoint_advances_existing_anchor() {
    let repo = Repository::with_keyring(MemoryBlobStore::new(), signing_keyring());
    let anchor = MemoryCheckpointAnchor::new();

    let first_put = repo
        .put(
            key("p/12/first"),
            Bytes::from_static(b"first"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(first_put.is_ok());
    let first = must(repo.publish_checkpoint(&anchor).await);

    let second_put = repo
        .put(
            key("p/12/second"),
            Bytes::from_static(b"second"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(second_put.is_ok());
    let second = must(repo.publish_checkpoint(&anchor).await);

    assert_eq!(first.sequence, Sequence::new(1));
    assert_eq!(second.sequence, Sequence::new(2));
    assert_ne!(first.checkpoint_id, second.checkpoint_id);
}

#[tokio::test]
async fn publish_checkpoint_rejects_stale_external_anchor() {
    let repo = Repository::with_keyring(MemoryBlobStore::new(), signing_keyring());
    let anchor = MemoryCheckpointAnchor::with_state(anchor_state(5, "newer"));

    let put = repo
        .put(
            key("p/12/abcdef"),
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(put.is_ok());

    let published = repo.publish_checkpoint(&anchor).await;

    assert!(matches!(
        published,
        Err(RepositoryError::StaleCheckpoint { .. })
    ));
}
