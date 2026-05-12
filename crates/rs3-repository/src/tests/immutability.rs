use super::*;

#[tokio::test]
async fn delete_tombstones_namespace_and_retains_locked_backend_object() {
    let store = MemoryBlobStore::new();
    let repo = Repository::with_keyring(store.clone(), signing_keyring());
    let key = key("p/12/abcdef");
    let options = RepositoryPutOptions {
        create_only: true,
        retention: Some(RetentionPolicy::new(RetentionMode::Compliance, 30)),
        legal_hold: None,
    };

    let put = repo
        .put(key.clone(), Bytes::from_static(b"locked"), options)
        .await;
    assert!(put.is_ok());

    let delete = repo.delete(&key).await;
    let listed = repo.list("p/12");
    let retained = store.list_prefix("segments/").await;

    assert_eq!(must(delete).physical, PhysicalDeleteOutcome::Retained);
    assert_eq!(must(listed).len(), 0);
    assert_eq!(must_storage(retained).len(), 1);
}

#[tokio::test]
async fn delete_tombstones_namespace_and_retains_legal_held_backend_object() {
    let store = MemoryBlobStore::new();
    let repo = Repository::with_keyring(store.clone(), signing_keyring());
    let key = key("p/12/held");
    let options = RepositoryPutOptions {
        create_only: true,
        retention: None,
        legal_hold: Some(LegalHoldStatus::On),
    };

    let put = repo
        .put(key.clone(), Bytes::from_static(b"held"), options)
        .await;
    assert!(put.is_ok());

    let delete = repo.delete(&key).await;
    let listed = repo.list("p/12");
    let retained = store.list_prefix("segments/").await;

    assert_eq!(must(delete).physical, PhysicalDeleteOutcome::Retained);
    assert_eq!(must(listed).len(), 0);
    assert_eq!(must_storage(retained).len(), 1);
}

#[tokio::test]
async fn legal_hold_update_updates_repository_metadata() {
    let repo = Repository::with_keyring(MemoryBlobStore::new(), signing_keyring());
    let key = key("p/12/legal-hold");

    let put = repo
        .put(
            key.clone(),
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(put.is_ok());

    let held = repo.set_legal_hold(&key, LegalHoldStatus::On).await;
    let head = repo.head(&key);

    assert_eq!(must(held).legal_hold, Some(LegalHoldStatus::On));
    assert_eq!(must(head).legal_hold, Some(LegalHoldStatus::On));
}

#[tokio::test]
async fn default_retention_applies_to_payload_and_checkpoint() {
    let store = MemoryBlobStore::new();
    let repo = Repository::with_keyring_and_options(
        store.clone(),
        signing_keyring(),
        crate::RepositoryOptions {
            payload_segment_size: crate::DEFAULT_PAYLOAD_SEGMENT_SIZE,
            adaptive_payload_segment_size: true,
            decrypted_segment_cache_max_bytes: crate::DEFAULT_DECRYPTED_SEGMENT_CACHE_MAX_BYTES,
            default_retention: Some(RetentionPolicy::new(RetentionMode::Compliance, 30)),
        },
    );
    let anchor = MemoryCheckpointAnchor::new();

    let put = repo
        .put_committed(
            key("p/12/default-retention"),
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
            &anchor,
        )
        .await;
    assert!(put.is_ok());

    let payloads = store
        .list_prefix("segments/")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let checkpoints = store
        .list_prefix(CHECKPOINT_OBJECT_PREFIX)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let evidence = store
        .list_prefix(CHECKPOINT_EVIDENCE_PREFIX)
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(
        payloads.first().and_then(|metadata| metadata.retention),
        Some(RetentionPolicy::new(RetentionMode::Compliance, 30))
    );
    assert_eq!(
        checkpoints.first().and_then(|metadata| metadata.retention),
        Some(RetentionPolicy::new(RetentionMode::Compliance, 30))
    );
    assert_eq!(
        evidence.first().and_then(|metadata| metadata.retention),
        Some(RetentionPolicy::new(RetentionMode::Compliance, 30))
    );
}

#[tokio::test]
async fn legal_hold_applies_to_payload_and_checkpoint() {
    let store = MemoryBlobStore::new();
    let repo = Repository::with_keyring(store.clone(), signing_keyring());
    let anchor = MemoryCheckpointAnchor::new();

    let put = repo
        .put_committed(
            key("p/12/legal-hold-checkpoint"),
            Bytes::from_static(b"body"),
            RepositoryPutOptions {
                create_only: false,
                retention: None,
                legal_hold: Some(LegalHoldStatus::On),
            },
            &anchor,
        )
        .await;
    assert!(put.is_ok());

    let payloads = store
        .list_prefix("segments/")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let checkpoints = store
        .list_prefix(CHECKPOINT_OBJECT_PREFIX)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let evidence = store
        .list_prefix(CHECKPOINT_EVIDENCE_PREFIX)
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(
        payloads.first().and_then(|metadata| metadata.legal_hold),
        Some(LegalHoldStatus::On)
    );
    assert_eq!(
        checkpoints.first().and_then(|metadata| metadata.legal_hold),
        Some(LegalHoldStatus::On)
    );
    assert_eq!(
        evidence.first().and_then(|metadata| metadata.legal_hold),
        Some(LegalHoldStatus::On)
    );
}

#[tokio::test]
async fn retention_extension_updates_repository_metadata() {
    let repo = Repository::with_keyring(MemoryBlobStore::new(), signing_keyring());
    let key = key("p/12/abcdef");

    let put = repo
        .put(
            key.clone(),
            Bytes::from_static(b"body"),
            RepositoryPutOptions {
                create_only: true,
                retention: Some(RetentionPolicy::new(RetentionMode::Governance, 10)),
                legal_hold: None,
            },
        )
        .await;
    assert!(put.is_ok());

    let extended = repo
        .extend_retention(&key, RetentionPolicy::new(RetentionMode::Compliance, 30))
        .await;

    assert_eq!(
        must(extended).retention,
        Some(RetentionPolicy::new(RetentionMode::Compliance, 30))
    );
}
