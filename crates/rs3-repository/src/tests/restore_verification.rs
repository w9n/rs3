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
    let store = MemoryBlobStore::new();
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
    let payload_id = only_object_with_prefix(&store, "segments/").await;
    let body = must_storage(store.get_range(&payload_id, ByteRange::Full).await);
    let mut tampered = body.to_vec();
    let last = tampered
        .last_mut()
        .unwrap_or_else(|| panic!("payload body should not be empty"));
    *last ^= 0x01;
    let put = store
        .put(&payload_id, Bytes::from(tampered), PutOptions::default())
        .await;
    assert!(put.is_ok());

    let verified = repo.verify_restore(&committed.checkpoint).await;

    assert!(verified.is_err());
}

#[tokio::test]
async fn verify_restore_checks_keyring_envelope_digest() {
    let store = MemoryBlobStore::new();
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
    let put = store
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
