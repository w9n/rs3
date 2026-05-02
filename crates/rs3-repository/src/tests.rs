//! Repository behavior tests.

use crate::namespace::prefix_tokens_for_key;
use crate::{
    CheckpointPosition, PhysicalDeleteOutcome, Repository, RepositoryError, RepositoryPutOptions,
    Result,
};
use bytes::Bytes;
use rs3_crypto::{KeyMaterial, KeyRing, SecretBytes};
use rs3_index::canonical_commit_record_bytes;
use rs3_k8s::{AnchorState, MemoryCheckpointAnchor};
use rs3_storage::{BlobStore, ByteRange, MemoryBlobStore};
use rs3_types::{
    CheckpointId, KeyDescriptor, KeyId, KeyPurpose, KeyStatus, LogicalPath, RetentionMode,
    RetentionPolicy, Sequence,
};

fn secret() -> SecretBytes {
    secret_with_byte(9)
}

fn secret_with_byte(byte: u8) -> SecretBytes {
    match SecretBytes::new(vec![byte; SecretBytes::MIN_LEN]) {
        Ok(secret) => secret,
        Err(error) => panic!("{error}"),
    }
}

fn key(value: &str) -> LogicalPath {
    match LogicalPath::new(value) {
        Ok(key) => key,
        Err(error) => panic!("{error}"),
    }
}

fn key_id(value: &str) -> KeyId {
    match KeyId::new(value) {
        Ok(key_id) => key_id,
        Err(error) => panic!("{error}"),
    }
}

fn checkpoint_id(value: &str) -> CheckpointId {
    match CheckpointId::new(value) {
        Ok(checkpoint_id) => checkpoint_id,
        Err(error) => panic!("{error}"),
    }
}

fn anchor_state(sequence: u64, id: &str) -> AnchorState {
    AnchorState {
        sequence: Sequence::new(sequence),
        checkpoint_id: checkpoint_id(id),
        checkpoint_digest: format!("digest-{id}"),
    }
}

fn namespace_key(value: &str, status: KeyStatus, secret_byte: u8) -> KeyMaterial {
    key_material(
        value,
        KeyPurpose::Namespace,
        status,
        "hmac-sha256",
        secret_byte,
    )
}

fn checkpoint_key(value: &str, status: KeyStatus, secret_byte: u8) -> KeyMaterial {
    key_material(
        value,
        KeyPurpose::CheckpointSigning,
        status,
        "hmac-sha256",
        secret_byte,
    )
}

fn key_material(
    value: &str,
    purpose: KeyPurpose,
    status: KeyStatus,
    algorithm: &str,
    secret_byte: u8,
) -> KeyMaterial {
    KeyMaterial::new(
        KeyDescriptor {
            id: key_id(value),
            purpose,
            algorithm: algorithm.to_string(),
            status,
            created_at_ms: 0,
            not_before_ms: None,
            not_after_ms: None,
            external_kms_uri: None,
        },
        secret_with_byte(secret_byte),
    )
}

fn keyring(keys: Vec<KeyMaterial>) -> KeyRing {
    match KeyRing::new(keys) {
        Ok(keyring) => keyring,
        Err(error) => panic!("{error}"),
    }
}

fn signing_keyring() -> KeyRing {
    keyring(vec![
        namespace_key("namespace", KeyStatus::Primary, 1),
        checkpoint_key("signing", KeyStatus::Primary, 2),
    ])
}

fn primary_key_id(keyring: &KeyRing) -> KeyId {
    match keyring.primary_namespace_key_id() {
        Ok(key_id) => key_id,
        Err(error) => panic!("{error}"),
    }
}

fn must<T>(result: Result<T>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{error}"),
    }
}

fn must_storage<T>(result: rs3_storage::Result<T>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{error}"),
    }
}

#[test]
fn prefix_tokens_include_root_and_arbitrary_prefixes() {
    let keyring = KeyRing::single_namespace(secret());
    let tokens = prefix_tokens_for_key(&keyring, &primary_key_id(&keyring), "p/12")
        .unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(tokens.len(), 5);
}

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
async fn backend_object_ids_do_not_contain_client_key() {
    let store = MemoryBlobStore::new();
    let repo = Repository::new(store.clone(), secret());
    let client_key = key("p/12/very-secret-kopia-blob");

    let put = repo
        .put(
            client_key,
            Bytes::from_static(b"hello"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(put.is_ok());

    let backend_objects = store.list_prefix("segments/").await;
    let object_ids = must_storage(backend_objects)
        .into_iter()
        .map(|metadata| metadata.object_id.to_string())
        .collect::<Vec<_>>();

    assert_eq!(object_ids.len(), 1);
    assert!(!object_ids[0].contains("very-secret"));
    assert!(!object_ids[0].contains("kopia"));
}

#[tokio::test]
async fn range_get_uses_repository_mapping() {
    let repo = Repository::new(MemoryBlobStore::new(), secret());
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
async fn create_only_rejects_existing_namespace_entry() {
    let repo = Repository::new(MemoryBlobStore::new(), secret());
    let key = key("p/12/abcdef");
    let options = RepositoryPutOptions {
        create_only: true,
        retention: None,
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
        keyring(vec![namespace_key("old", KeyStatus::Primary, 1)]),
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
    assert_eq!(record.compacted_manifests.len(), 2);
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
}

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

#[tokio::test]
async fn delete_tombstones_namespace_and_retains_locked_backend_object() {
    let store = MemoryBlobStore::new();
    let repo = Repository::new(store.clone(), secret());
    let key = key("p/12/abcdef");
    let options = RepositoryPutOptions {
        create_only: true,
        retention: Some(RetentionPolicy::new(RetentionMode::Compliance, 30)),
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
async fn retention_extension_updates_repository_metadata() {
    let repo = Repository::new(MemoryBlobStore::new(), secret());
    let key = key("p/12/abcdef");

    let put = repo
        .put(
            key.clone(),
            Bytes::from_static(b"body"),
            RepositoryPutOptions {
                create_only: true,
                retention: Some(RetentionPolicy::new(RetentionMode::Governance, 10)),
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
