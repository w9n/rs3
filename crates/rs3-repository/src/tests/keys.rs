use super::*;

#[tokio::test]
async fn stored_keyring_envelope_is_bound_into_signed_checkpoints() {
    let store = MemoryBlobStore::new();
    let repository_id = match RepositoryId::new("repository-a") {
        Ok(repository_id) => repository_id,
        Err(error) => panic!("{error}"),
    };
    let context = match RepositoryKeyContext::new(repository_id, vec![7; 32]) {
        Ok(context) => context,
        Err(error) => panic!("{error}"),
    };
    let active_keyring = signing_keyring();
    let envelope =
        match active_keyring.seal_keyring_envelope(&context, "wrap-v1", &secret_with_byte(12), 1) {
            Ok(envelope) => envelope,
            Err(error) => panic!("{error}"),
        };
    let repo = Repository::with_keyring(store.clone(), active_keyring);
    let anchor = MemoryCheckpointAnchor::new();

    let reference = must(repo.store_keyring_envelope(&envelope).await);
    let put = repo
        .put(
            key("p/12/enveloped"),
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(put.is_ok());
    let position = must(repo.publish_checkpoint(&anchor).await);
    let checkpoint_object = match checkpoint_object_id(&position.checkpoint_id) {
        Ok(object_id) => object_id,
        Err(error) => panic!("{error}"),
    };
    let checkpoint = decode_checkpoint_object(must_storage(
        store.get_range(&checkpoint_object, ByteRange::Full).await,
    ));

    let envelope_digest = match envelope.digest() {
        Ok(digest) => digest,
        Err(error) => panic!("{error}"),
    };
    assert_eq!(reference.digest, envelope_digest);
    assert_eq!(checkpoint.record.keyring_envelope, Some(reference));
}

#[tokio::test]
async fn metadata_key_rotation_replays_old_and_new_checkpoint_state() {
    let store = MemoryBlobStore::new();
    let anchor = MemoryCheckpointAnchor::new();
    let context = repository_key_context();
    let initial_keyring = signing_keyring();
    let repo = Repository::with_keyring(store.clone(), initial_keyring.clone());
    let initial_envelope = must_crypto(initial_keyring.seal_keyring_envelope(
        &context,
        "wrap-v1",
        &secret_with_byte(12),
        1,
    ));
    must(repo.store_keyring_envelope(&initial_envelope).await);

    let old_key = key("p/12/metadata-old");
    let new_key = key("p/12/metadata-new");
    let old_put = repo
        .put(
            old_key.clone(),
            Bytes::from_static(b"old"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(old_put.is_ok());
    let first = must(repo.publish_checkpoint(&anchor).await);

    let rotated_keyring = must_crypto(initial_keyring.rotate_purpose_key(
        KeyPurpose::Metadata,
        key_id("metadata-v2"),
        now_ms(),
    ));
    let rotated_envelope = must_crypto(rotated_keyring.seal_keyring_envelope(
        &context,
        "wrap-v1",
        &secret_with_byte(12),
        2,
    ));
    let (_, staged_sequence) = must(
        repo.store_keyring_update(rotated_keyring.clone(), &rotated_envelope)
            .await,
    );
    assert_eq!(staged_sequence, Sequence::new(first.sequence.get() + 1));
    let metadata_checkpoint = must(repo.publish_checkpoint(&anchor).await);

    let new_put = repo
        .put(
            new_key.clone(),
            Bytes::from_static(b"new"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(new_put.is_ok());
    let latest = must(repo.publish_checkpoint(&anchor).await);

    let fresh = Repository::with_keyring(store.clone(), rotated_keyring.clone());
    let loaded = must(fresh.load_checkpoint_position(&latest).await);
    let old_body = fresh.get_range(&old_key, ByteRange::Full).await;
    let new_body = fresh.get_range(&new_key, ByteRange::Full).await;

    assert_eq!(loaded, latest);
    assert_eq!(
        metadata_checkpoint.sequence,
        Sequence::new(first.sequence.get() + 1)
    );
    assert_eq!(must(old_body), Bytes::from_static(b"old"));
    assert_eq!(must(new_body), Bytes::from_static(b"new"));
}

#[tokio::test]
async fn checkpoint_signing_rotation_verifies_mixed_signing_chain() {
    let store = MemoryBlobStore::new();
    let anchor = MemoryCheckpointAnchor::new();
    let context = repository_key_context();
    let initial_keyring = signing_keyring();
    let repo = Repository::with_keyring(store.clone(), initial_keyring.clone());
    let initial_envelope = must_crypto(initial_keyring.seal_keyring_envelope(
        &context,
        "wrap-v1",
        &secret_with_byte(12),
        1,
    ));
    must(repo.store_keyring_envelope(&initial_envelope).await);

    let put = repo
        .put(
            key("p/12/signed-before-rotation"),
            Bytes::from_static(b"old"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(put.is_ok());
    let first = must(repo.publish_checkpoint(&anchor).await);
    let first_checkpoint = checkpoint_from_store(&store, &first).await;
    assert_eq!(first_checkpoint.signature_key_id, key_id("signing"));

    let rotated_keyring = must_crypto(initial_keyring.rotate_purpose_key(
        KeyPurpose::CheckpointSigning,
        key_id("signing-v2"),
        now_ms(),
    ));
    let rotated_envelope = must_crypto(rotated_keyring.seal_keyring_envelope(
        &context,
        "wrap-v1",
        &secret_with_byte(12),
        2,
    ));
    must(
        repo.store_keyring_update(rotated_keyring.clone(), &rotated_envelope)
            .await,
    );
    let latest = must(repo.publish_checkpoint(&anchor).await);
    let latest_checkpoint = checkpoint_from_store(&store, &latest).await;

    let fresh = Repository::with_keyring(store.clone(), rotated_keyring);
    let loaded = must(fresh.load_checkpoint_position(&latest).await);

    assert_eq!(loaded, latest);
    assert_eq!(latest_checkpoint.signature_key_id, key_id("signing-v2"));
}

#[tokio::test]
async fn namespace_rotation_keeps_old_objects_readable_and_listable() {
    let repo = Repository::with_keyring(
        MemoryBlobStore::new(),
        keyring(vec![namespace_key("old", KeyStatus::Primary, 1)]),
    );
    let old_key = key("p/12/old");
    let new_key = key("p/12/new");

    let old_put = repo
        .put(
            old_key.clone(),
            Bytes::from_static(b"old"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(old_put.is_ok());

    let rotated = keyring(vec![
        namespace_key("old", KeyStatus::Enabled, 1),
        namespace_key("new", KeyStatus::Primary, 2),
    ]);
    let replace = repo.replace_keyring(rotated);
    assert!(replace.is_ok());

    let old_body = repo.get_range(&old_key, ByteRange::Full).await;
    let new_put = repo
        .put(
            new_key.clone(),
            Bytes::from_static(b"new"),
            RepositoryPutOptions::default(),
        )
        .await;
    let listed = repo.list("p/12");

    assert_eq!(must(old_body), Bytes::from_static(b"old"));
    assert!(new_put.is_ok());
    assert_eq!(
        must(listed)
            .into_iter()
            .map(|entry| entry.key)
            .collect::<Vec<_>>(),
        vec![new_key, old_key]
    );
}

#[tokio::test]
async fn content_rotation_reads_old_enabled_payloads_and_uses_primary_for_new_writes() {
    let repo = Repository::with_keyring(
        MemoryBlobStore::new(),
        keyring(vec![
            namespace_key("namespace", KeyStatus::Primary, 1),
            content_key("old-content", KeyStatus::Primary, 4),
        ]),
    );
    let old_key = key("p/12/old-content");
    let new_key = key("p/12/new-content");

    let old_put = repo
        .put(
            old_key.clone(),
            Bytes::from_static(b"old"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(old_put.is_ok());

    let rotate = repo.replace_keyring(keyring(vec![
        namespace_key("namespace", KeyStatus::Primary, 1),
        content_key("old-content", KeyStatus::Enabled, 4),
        content_key("new-content", KeyStatus::Primary, 5),
    ]));
    assert!(rotate.is_ok());

    let old_body_while_enabled = repo.get_range(&old_key, ByteRange::Full).await;
    let new_put = repo
        .put(
            new_key.clone(),
            Bytes::from_static(b"new"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(new_put.is_ok());

    let disable_old = repo.replace_keyring(keyring(vec![
        namespace_key("namespace", KeyStatus::Primary, 1),
        content_key("old-content", KeyStatus::Disabled, 4),
        content_key("new-content", KeyStatus::Primary, 5),
    ]));
    assert!(disable_old.is_ok());

    let old_body_after_disable = repo.get_range(&old_key, ByteRange::Full).await;
    let new_body = repo.get_range(&new_key, ByteRange::Full).await;

    assert_eq!(must(old_body_while_enabled), Bytes::from_static(b"old"));
    assert!(matches!(
        old_body_after_disable,
        Err(RepositoryError::Crypto(_))
    ));
    assert_eq!(must(new_body), Bytes::from_static(b"new"));
}

#[tokio::test]
async fn create_only_rejects_existing_entry_under_old_namespace_key() {
    let repo = Repository::with_keyring(
        MemoryBlobStore::new(),
        keyring(vec![namespace_key("old", KeyStatus::Primary, 1)]),
    );
    let key = key("p/12/abcdef");

    let first = repo
        .put(
            key.clone(),
            Bytes::from_static(b"old"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(first.is_ok());

    let replace = repo.replace_keyring(keyring(vec![
        namespace_key("old", KeyStatus::Enabled, 1),
        namespace_key("new", KeyStatus::Primary, 2),
    ]));
    assert!(replace.is_ok());

    let second = repo
        .put(
            key,
            Bytes::from_static(b"new"),
            RepositoryPutOptions {
                create_only: true,
                retention: None,
                legal_hold: None,
            },
        )
        .await;

    assert!(matches!(second, Err(RepositoryError::AlreadyExists(_))));
}

#[tokio::test]
async fn overwrite_after_rotation_moves_lookup_to_primary_namespace_key() {
    let repo = Repository::with_keyring(
        MemoryBlobStore::new(),
        keyring(vec![namespace_key("old", KeyStatus::Primary, 1)]),
    );
    let key = key("p/12/same");

    let old_put = repo
        .put(
            key.clone(),
            Bytes::from_static(b"old"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(old_put.is_ok());

    let replace = repo.replace_keyring(keyring(vec![
        namespace_key("old", KeyStatus::Enabled, 1),
        namespace_key("new", KeyStatus::Primary, 2),
    ]));
    assert!(replace.is_ok());

    let overwrite = repo
        .put(
            key.clone(),
            Bytes::from_static(b"new"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(overwrite.is_ok());

    let disable_old = repo.replace_keyring(keyring(vec![
        namespace_key("old", KeyStatus::Disabled, 1),
        namespace_key("new", KeyStatus::Primary, 2),
    ]));
    assert!(disable_old.is_ok());

    let body = repo.get_range(&key, ByteRange::Full).await;
    let listed = repo.list("p/12");

    assert_eq!(must(body), Bytes::from_static(b"new"));
    assert_eq!(must(listed).len(), 1);
}

#[tokio::test]
async fn draft_commit_record_contains_rotated_keyring_metadata() {
    let repo = Repository::with_keyring(
        MemoryBlobStore::new(),
        keyring(vec![
            namespace_key("old", KeyStatus::Primary, 1),
            content_key("old-content", KeyStatus::Primary, 4),
        ]),
    );
    let old_key = key("p/12/old");
    let new_key = key("p/12/new");

    let old_put = repo
        .put(
            old_key,
            Bytes::from_static(b"old"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(old_put.is_ok());

    let replace = repo.replace_keyring(keyring(vec![
        namespace_key("old", KeyStatus::Enabled, 1),
        namespace_key("new", KeyStatus::Primary, 2),
        content_key("old-content", KeyStatus::Enabled, 4),
        content_key("new-content", KeyStatus::Primary, 5),
    ]));
    assert!(replace.is_ok());

    let new_put = repo
        .put(
            new_key,
            Bytes::from_static(b"new"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(new_put.is_ok());

    let record = must(repo.draft_commit_record(None));

    assert_eq!(record.sequence, Sequence::new(2));
    assert!(record.index_deltas.is_empty());
    assert!(record.inline_index_delta.is_some());
    assert!(record.compacted_manifests.is_empty());
    assert_eq!(
        record
            .keyring
            .primary_for(KeyPurpose::Namespace)
            .map(|descriptor| descriptor.id.clone()),
        Some(key_id("new"))
    );
    assert_eq!(
        record
            .keyring
            .enabled_for(KeyPurpose::Namespace)
            .into_iter()
            .map(|descriptor| descriptor.id.clone())
            .collect::<Vec<_>>(),
        vec![key_id("new"), key_id("old")]
    );
    assert_eq!(
        record
            .keyring
            .primary_for(KeyPurpose::Content)
            .map(|descriptor| descriptor.id.clone()),
        Some(key_id("new-content"))
    );
    assert_eq!(
        record
            .keyring
            .enabled_for(KeyPurpose::Content)
            .into_iter()
            .map(|descriptor| descriptor.id.clone())
            .collect::<Vec<_>>(),
        vec![key_id("new-content"), key_id("old-content")]
    );
}

#[test]
fn draft_signed_checkpoint_requires_primary_signing_key() {
    let repo = Repository::with_keyring(
        MemoryBlobStore::new(),
        keyring(vec![namespace_key("namespace", KeyStatus::Primary, 1)]),
    );

    let checkpoint = repo.draft_signed_checkpoint(None);

    assert!(checkpoint.is_err());
}

#[tokio::test]
async fn disabled_old_namespace_key_stops_lookup() {
    let repo = Repository::with_keyring(
        MemoryBlobStore::new(),
        keyring(vec![namespace_key("old", KeyStatus::Primary, 1)]),
    );
    let key = key("p/12/old-only");

    let put = repo
        .put(
            key.clone(),
            Bytes::from_static(b"old"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(put.is_ok());

    let replace = repo.replace_keyring(keyring(vec![
        namespace_key("old", KeyStatus::Disabled, 1),
        namespace_key("new", KeyStatus::Primary, 2),
    ]));
    assert!(replace.is_ok());

    let head = repo.head(&key);
    let listed = repo.list("p/12");

    assert!(matches!(head, Err(RepositoryError::NotFound(_))));
    assert!(must(listed).is_empty());
}

fn repository_key_context() -> RepositoryKeyContext {
    let repository_id = match RepositoryId::new("repository-a") {
        Ok(repository_id) => repository_id,
        Err(error) => panic!("{error}"),
    };
    match RepositoryKeyContext::new(repository_id, vec![7; 32]) {
        Ok(context) => context,
        Err(error) => panic!("{error}"),
    }
}

async fn checkpoint_from_store(
    store: &MemoryBlobStore,
    position: &CheckpointPosition,
) -> rs3_index::Checkpoint {
    let object_id = match checkpoint_object_id(&position.checkpoint_id) {
        Ok(object_id) => object_id,
        Err(error) => panic!("{error}"),
    };
    decode_checkpoint_object(must_storage(
        store.get_range(&object_id, ByteRange::Full).await,
    ))
}

fn must_crypto<T>(result: std::result::Result<T, rs3_crypto::CryptoError>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{error}"),
    }
}
