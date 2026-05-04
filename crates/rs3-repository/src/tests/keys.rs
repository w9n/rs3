use super::*;

#[test]
fn repository_new_derives_purpose_specific_keys_from_master_key() {
    let repo = Repository::new(MemoryBlobStore::new(), secret());
    let keyring = match repo.keyring.read() {
        Ok(keyring) => keyring,
        Err(error) => panic!("{error}"),
    };

    assert_eq!(
        keyring
            .descriptors()
            .into_iter()
            .map(|descriptor| (descriptor.id, descriptor.purpose, descriptor.algorithm))
            .collect::<Vec<_>>(),
        vec![
            (
                key_id("namespace-v1"),
                KeyPurpose::Namespace,
                "hmac-sha256".to_owned()
            ),
            (
                key_id("content-v1"),
                KeyPurpose::Content,
                "xchacha20poly1305".to_owned()
            ),
            (
                key_id("metadata-v1"),
                KeyPurpose::Metadata,
                "aes-256-gcm-siv-hmac-sha256-nonce-v1".to_owned()
            ),
            (
                key_id("checkpoint-v1"),
                KeyPurpose::CheckpointSigning,
                "ed25519".to_owned()
            ),
        ]
    );
}

#[test]
fn repository_from_master_key_context_binds_to_repository_salt() {
    let repository_id = match RepositoryId::new("repository-a") {
        Ok(repository_id) => repository_id,
        Err(error) => panic!("{error}"),
    };
    let first_context = match RepositoryKeyContext::new(repository_id.clone(), vec![1; 32]) {
        Ok(context) => context,
        Err(error) => panic!("{error}"),
    };
    let second_context = match RepositoryKeyContext::new(repository_id, vec![2; 32]) {
        Ok(context) => context,
        Err(error) => panic!("{error}"),
    };
    let first =
        match Repository::from_master_key_context(MemoryBlobStore::new(), secret(), &first_context)
        {
            Ok(repository) => repository,
            Err(error) => panic!("{error}"),
        };
    let second = match Repository::from_master_key_context(
        MemoryBlobStore::new(),
        secret(),
        &second_context,
    ) {
        Ok(repository) => repository,
        Err(error) => panic!("{error}"),
    };
    let first_id = match first.keyring.read() {
        Ok(keyring) => keyring.derive_backend_object_id("segments", b"same"),
        Err(error) => panic!("{error}"),
    };
    let second_id = match second.keyring.read() {
        Ok(keyring) => keyring.derive_backend_object_id("segments", b"same"),
        Err(error) => panic!("{error}"),
    };

    let first_id = match first_id {
        Ok(object_id) => object_id,
        Err(error) => panic!("{error}"),
    };
    let second_id = match second_id {
        Ok(object_id) => object_id,
        Err(error) => panic!("{error}"),
    };

    assert_ne!(first_id, second_id);
}

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
    let active_keyring =
        match KeyRing::from_repository_master_key_for_context(&secret_with_byte(11), &context) {
            Ok(keyring) => keyring,
            Err(error) => panic!("{error}"),
        };
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
