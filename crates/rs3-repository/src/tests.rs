//! Repository behavior tests.

use crate::checkpoint::{CHECKPOINT_OBJECT_PREFIX, MANIFEST_OBJECT_PREFIX, checkpoint_object_id};
use crate::namespace::prefix_tokens_for_key;
use crate::{
    CheckpointPosition, PhysicalDeleteOutcome, Repository, RepositoryError, RepositoryPutOptions,
    Result,
};
use async_trait::async_trait;
use bytes::Bytes;
use rs3_anchor::{AnchorError, AnchorState, CheckpointAnchor, MemoryCheckpointAnchor};
use rs3_crypto::{KeyMaterial, KeyRing, SecretBytes};
use rs3_index::{
    CHECKPOINT_OBJECT_DOMAIN, Checkpoint, INDEX_DELTA_OBJECT_DOMAIN, MANIFEST_OBJECT_DOMAIN,
    canonical_commit_record_bytes,
};
use rs3_storage::{BlobStore, ByteRange, MemoryBlobStore, PutOptions};
use rs3_types::{
    CheckpointId, KeyDescriptor, KeyId, KeyPurpose, KeyStatus, LogicalPath, RetentionMode,
    RetentionPolicy, Sequence,
};
use std::sync::{Arc, Mutex};

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

fn metadata_key(value: &str, status: KeyStatus, secret_byte: u8) -> KeyMaterial {
    key_material(
        value,
        KeyPurpose::Metadata,
        status,
        "hmac-sha256-seal",
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
        metadata_key("metadata", KeyStatus::Primary, 2),
        checkpoint_key("signing", KeyStatus::Primary, 3),
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

fn decode_checkpoint_object(body: Bytes) -> Checkpoint {
    let Some(payload) = body.as_ref().strip_prefix(CHECKPOINT_OBJECT_DOMAIN) else {
        panic!("checkpoint object is missing domain prefix");
    };

    match serde_json::from_slice(payload) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("{error}"),
    }
}

fn assert_body_does_not_contain(body: &Bytes, needles: &[&str]) {
    let body = String::from_utf8_lossy(body);
    for needle in needles {
        assert!(!body.contains(needle));
    }
}

struct CheckpointMustExistAnchor {
    inner: MemoryCheckpointAnchor,
    store: MemoryBlobStore,
}

impl CheckpointMustExistAnchor {
    fn new(store: MemoryBlobStore) -> Self {
        Self {
            inner: MemoryCheckpointAnchor::new(),
            store,
        }
    }
}

#[async_trait]
impl CheckpointAnchor for CheckpointMustExistAnchor {
    async fn read(&self) -> rs3_anchor::Result<AnchorState> {
        self.inner.read().await
    }

    async fn compare_and_advance(&self, next: AnchorState) -> rs3_anchor::Result<AnchorState> {
        let object_id = checkpoint_object_id(&next.checkpoint_id)
            .map_err(|error| AnchorError::Backend(error.to_string()))?;
        self.store
            .head(&object_id)
            .await
            .map_err(|error| AnchorError::Backend(error.to_string()))?;
        self.inner.compare_and_advance(next).await
    }
}

struct FailOnceAnchor {
    inner: MemoryCheckpointAnchor,
    fail_next: Arc<Mutex<bool>>,
}

impl FailOnceAnchor {
    fn new() -> Self {
        Self {
            inner: MemoryCheckpointAnchor::new(),
            fail_next: Arc::new(Mutex::new(true)),
        }
    }
}

#[async_trait]
impl CheckpointAnchor for FailOnceAnchor {
    async fn read(&self) -> rs3_anchor::Result<AnchorState> {
        self.inner.read().await
    }

    async fn compare_and_advance(&self, next: AnchorState) -> rs3_anchor::Result<AnchorState> {
        let should_fail = {
            let mut fail_next = self
                .fail_next
                .lock()
                .map_err(|_| AnchorError::StatePoisoned)?;
            let should_fail = *fail_next;
            *fail_next = false;
            should_fail
        };

        if should_fail {
            return Err(AnchorError::Backend("transient anchor failure".to_owned()));
        }

        self.inner.compare_and_advance(next).await
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
    let client_key = key("p/12/sensitive-client-blob");

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
    assert!(!object_ids[0].contains("sensitive"));
    assert!(!object_ids[0].contains("client-blob"));
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
    assert_eq!(record.index_deltas.len(), 1);
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
async fn publish_checkpoint_persists_index_delta_without_client_key_material() {
    let store = MemoryBlobStore::new();
    let repo = Repository::with_keyring(store.clone(), signing_keyring());
    let anchor = MemoryCheckpointAnchor::new();
    let client_key = key("p/12/sensitive-client-blob");

    let put = repo
        .put(
            client_key,
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(put.is_ok());

    let position = must(repo.publish_checkpoint(&anchor).await);
    let checkpoint_object_id = must(checkpoint_object_id(&position.checkpoint_id));
    let checkpoint_body = must_storage(
        store
            .get_range(&checkpoint_object_id, ByteRange::Full)
            .await,
    );
    let checkpoint = decode_checkpoint_object(checkpoint_body.clone());
    let delta_objects = must_storage(store.list_prefix("index/").await);
    let manifest_objects = must_storage(store.list_prefix(MANIFEST_OBJECT_PREFIX).await);

    assert_eq!(checkpoint.record.index_deltas.len(), 1);
    assert_eq!(delta_objects.len(), 1);
    assert_eq!(manifest_objects.len(), 1);
    assert_eq!(
        checkpoint.record.index_deltas[0],
        delta_objects[0].object_id
    );

    let delta_body = must_storage(
        store
            .get_range(&delta_objects[0].object_id, ByteRange::Full)
            .await,
    );
    let manifest_body = must_storage(
        store
            .get_range(&manifest_objects[0].object_id, ByteRange::Full)
            .await,
    );
    assert!(delta_body.starts_with(INDEX_DELTA_OBJECT_DOMAIN));
    assert!(manifest_body.starts_with(MANIFEST_OBJECT_DOMAIN));
    assert_body_does_not_contain(&checkpoint_body, &["sensitive", "client-blob", "p/12"]);
    assert_body_does_not_contain(&delta_body, &["sensitive", "client-blob", "p/12"]);
    assert_body_does_not_contain(&manifest_body, &["sensitive", "client-blob", "p/12"]);
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
async fn load_checkpoint_position_rejects_tampered_index_delta_object() {
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

    let delta_object = must_storage(store.list_prefix("index/").await)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing index delta object"));
    let overwrite = store
        .put(
            &delta_object.object_id,
            Bytes::from_static(b"rs3:index-delta-object:v1\n{}"),
            PutOptions::default(),
        )
        .await;
    assert!(overwrite.is_ok());

    let reloaded = Repository::with_keyring(store, keyring);
    let loaded = reloaded.load_checkpoint_position(&latest).await;

    assert!(matches!(
        loaded,
        Err(RepositoryError::IndexDeltaObjectConflict { .. })
    ));
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
