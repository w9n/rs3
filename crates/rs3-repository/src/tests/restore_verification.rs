use super::*;
use rs3_crypto::SecretBytes;
use rs3_types::BackendObjectId;

#[tokio::test]
async fn verify_restore_reports_checkpoint_evidence_and_payloads() {
    let store = MemoryBlobStore::new();
    let repo = Repository::with_keyring(store, signing_keyring());
    let anchor = MemoryCheckpointAnchor::new();

    let first = repo
        .put_committed(
            key("restore/first"),
            Bytes::from_static(b"a"),
            RepositoryPutOptions::default(),
            &anchor,
        )
        .await;
    assert!(first.is_ok());
    let second = must(
        repo.put_committed(
            key("restore/second"),
            Bytes::from_static(b"bb"),
            RepositoryPutOptions::default(),
            &anchor,
        )
        .await,
    );

    let report = must(repo.verify_restore(&second.checkpoint).await);
    let required_key_ids = report
        .required_key_ids
        .iter()
        .map(|key_id| key_id.as_str())
        .collect::<Vec<_>>();

    assert_eq!(report.checkpoint_count, 2);
    assert_eq!(report.checkpoint_evidence_count, 2);
    assert_eq!(report.index_delta_object_count, 0);
    assert_eq!(report.inline_index_delta_count, 2);
    assert_eq!(report.keyring_envelope_count, 0);
    assert_eq!(report.payload_object_count, 2);
    assert_eq!(report.payload_plaintext_bytes, 3);
    assert!(required_key_ids.contains(&"namespace"));
    assert!(required_key_ids.contains(&"metadata"));
    assert!(required_key_ids.contains(&"content"));
    assert!(required_key_ids.contains(&"signing"));
}

#[tokio::test]
async fn verify_restore_reports_retention_protection_summary() {
    let store = MemoryBlobStore::new();
    let repo = Repository::with_keyring_and_options(
        store,
        signing_keyring(),
        RepositoryOptions {
            payload_segment_size: crate::DEFAULT_PAYLOAD_SEGMENT_SIZE,
            adaptive_payload_segment_size: true,
            decrypted_segment_cache_max_bytes: crate::DEFAULT_DECRYPTED_SEGMENT_CACHE_MAX_BYTES,
            default_retention: Some(RetentionPolicy::new(RetentionMode::Compliance, 30)),
        },
    );
    let anchor = MemoryCheckpointAnchor::new();
    let committed = must(
        repo.put_committed(
            key("restore/retained"),
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
            &anchor,
        )
        .await,
    );

    let report = must(repo.verify_restore(&committed.checkpoint).await);

    assert_eq!(report.protection.checked_object_count, 3);
    assert_eq!(report.protection.retention_object_count, 3);
    assert_eq!(report.protection.retention_delete_blocked_count, 3);
    assert_eq!(report.protection.legal_hold_object_count, 0);
    assert_eq!(report.protection.delete_protected_object_count, 3);
    assert_eq!(report.protection.minimum_retention_days, Some(30));
}

#[tokio::test]
async fn verify_restore_rejects_tampered_checkpoint_evidence() {
    let store = MemoryBlobStore::new();
    let repo = Repository::with_keyring(store.clone(), signing_keyring());
    let anchor = MemoryCheckpointAnchor::new();
    let committed = must(
        repo.put_committed(
            key("restore/evidence"),
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
            &anchor,
        )
        .await,
    );
    let evidence_id = must(checkpoint_evidence_object_id(&committed.checkpoint));
    let put = store
        .put(
            &evidence_id,
            Bytes::from_static(b"tampered-evidence"),
            PutOptions::default(),
        )
        .await;
    assert!(put.is_ok());

    let verified = repo.verify_restore(&committed.checkpoint).await;

    assert!(matches!(
        verified,
        Err(RepositoryError::CheckpointEvidenceObjectConflict { object_id })
            if object_id == evidence_id
    ));
}

#[tokio::test]
async fn verify_restore_rejects_tampered_payload() {
    let versioned_backend = MemoryBlobStore::new();
    let store = DropPutVersionStore {
        backend: versioned_backend.clone(),
    };
    let repo = Repository::with_keyring(store.clone(), signing_keyring());
    let anchor = MemoryCheckpointAnchor::new();
    let committed = must(
        repo.put_committed(
            key("restore/payload"),
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
            &anchor,
        )
        .await,
    );
    let payload_id = only_object_with_prefix(&versioned_backend, "segments/").await;
    let body = must_storage(
        versioned_backend
            .get_range(&payload_id, ByteRange::Full)
            .await,
    );
    let mut tampered = body.to_vec();
    let last = tampered
        .last_mut()
        .unwrap_or_else(|| panic!("payload body should not be empty"));
    *last ^= 0x01;
    let put = versioned_backend
        .put(&payload_id, Bytes::from(tampered), PutOptions::default())
        .await;
    assert!(put.is_ok());

    let verified = repo.verify_restore(&committed.checkpoint).await;

    assert!(verified.is_err());
}

#[tokio::test]
async fn verify_restore_checks_keyring_envelope_digest() {
    let versioned_backend = MemoryBlobStore::new();
    let store = DropPutVersionStore {
        backend: versioned_backend.clone(),
    };
    let keyring = KeyRing::generate_random().unwrap_or_else(|error| panic!("{error}"));
    let repo = Repository::with_keyring(store.clone(), keyring.clone());
    let context = RepositoryKeyContext::new(
        RepositoryId::new("restore-envelope").unwrap_or_else(|error| panic!("{error}")),
        vec![2; 32],
    )
    .unwrap_or_else(|error| panic!("{error}"));
    let wrapping_key =
        SecretBytes::new(vec![8; SecretBytes::MIN_LEN]).unwrap_or_else(|error| panic!("{error}"));
    let envelope = keyring
        .seal_keyring_envelope(&context, "wrap-v1", &wrapping_key, 1)
        .unwrap_or_else(|error| panic!("{error}"));
    let reference = must(repo.store_keyring_envelope(&envelope).await);
    let anchor = MemoryCheckpointAnchor::new();
    let committed = must(
        repo.put_committed(
            key("restore/envelope"),
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
            &anchor,
        )
        .await,
    );

    let report = must(repo.verify_restore(&committed.checkpoint).await);
    assert_eq!(report.keyring_envelope_count, 1);

    let mut changed = envelope.clone();
    changed.generation = 2;
    let put = versioned_backend
        .put(
            &reference.object_id,
            Bytes::from(
                changed
                    .to_object_bytes()
                    .unwrap_or_else(|error| panic!("{error}")),
            ),
            PutOptions::default(),
        )
        .await;
    assert!(put.is_ok());

    let verified = repo.verify_restore(&committed.checkpoint).await;

    assert!(matches!(
        verified,
        Err(RepositoryError::KeyringEnvelopeObjectConflict { object_id })
            if object_id == reference.object_id
    ));
}

#[tokio::test]
async fn restore_uses_checkpoint_bound_payload_version_after_latest_poisoning() {
    let store = MemoryBlobStore::new();
    let repo = Repository::with_keyring(store.clone(), signing_keyring());
    let anchor = MemoryCheckpointAnchor::new();
    let committed = must(
        repo.put_committed(
            key("restore/version-bound-payload"),
            Bytes::from_static(b"original"),
            RepositoryPutOptions::default(),
            &anchor,
        )
        .await,
    );
    let payload_id = only_object_with_prefix(&store, "segments/").await;
    let poison = store
        .put(
            &payload_id,
            Bytes::from_static(b"poisoned-latest"),
            PutOptions::default(),
        )
        .await;
    assert!(poison.is_ok());

    let report = must(repo.verify_restore(&committed.checkpoint).await);
    assert_eq!(report.payload_plaintext_bytes, 8);

    let restored = must(
        repo.get_range(&key("restore/version-bound-payload"), ByteRange::Full)
            .await,
    );
    assert_eq!(restored, Bytes::from_static(b"original"));

    let fresh = Repository::with_keyring(store, signing_keyring());
    let loaded = must(fresh.load_checkpoint_position(&committed.checkpoint).await);
    assert_eq!(loaded, committed.checkpoint);
    let restored = must(
        fresh
            .get_range(&key("restore/version-bound-payload"), ByteRange::Full)
            .await,
    );
    assert_eq!(restored, Bytes::from_static(b"original"));
}

#[tokio::test]
async fn retained_write_requires_provider_version_id() {
    let versioned_backend = MemoryBlobStore::new();
    let store = DropPutVersionStore {
        backend: versioned_backend,
    };
    let repo = Repository::with_keyring_and_options(
        store,
        signing_keyring(),
        RepositoryOptions {
            payload_segment_size: crate::DEFAULT_PAYLOAD_SEGMENT_SIZE,
            adaptive_payload_segment_size: true,
            decrypted_segment_cache_max_bytes: crate::DEFAULT_DECRYPTED_SEGMENT_CACHE_MAX_BYTES,
            default_retention: Some(RetentionPolicy::new(RetentionMode::Compliance, 30)),
        },
    );

    let written = repo
        .put(
            key("restore/retained-without-version"),
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
        )
        .await;

    assert!(matches!(
        written,
        Err(RepositoryError::Storage(StorageError::MissingVersionId(_)))
    ));
}

async fn only_object_with_prefix(store: &MemoryBlobStore, prefix: &str) -> BackendObjectId {
    let objects = must_storage(store.list_prefix(prefix).await);
    let mut ids = objects
        .into_iter()
        .map(|metadata| metadata.object_id)
        .collect::<Vec<_>>();
    assert_eq!(ids.len(), 1);
    ids.pop()
        .unwrap_or_else(|| panic!("missing object under prefix {prefix}"))
}
