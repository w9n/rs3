//! Repository behavior tests.

use crate::checkpoint::{CHECKPOINT_OBJECT_PREFIX, checkpoint_object_id};
use crate::namespace::prefix_tokens_for_key;
use crate::{
    BackendObjectReferenceKind, CheckpointPosition, CommitCoordinator, CommitCoordinatorOptions,
    PhysicalDeleteOutcome, Repository, RepositoryError, RepositoryPutOptions, Result,
};
use async_trait::async_trait;
use bytes::Bytes;
use rs3_anchor::{AnchorError, AnchorState, CheckpointAnchor, MemoryCheckpointAnchor};
use rs3_crypto::{KeyMaterial, KeyRing, SecretBytes};
use rs3_index::{
    CHECKPOINT_OBJECT_DOMAIN, Checkpoint, INDEX_DELTA_OBJECT_DOMAIN, canonical_commit_record_bytes,
};
use rs3_storage::{BlobMetadata, BlobStore, ByteRange, MemoryBlobStore, PutOptions, StorageError};
use rs3_types::{
    BackendObjectId, CheckpointId, KeyDescriptor, KeyId, KeyPurpose, KeyStatus, LogicalPath,
    RetentionMode, RetentionPolicy, Sequence,
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

fn backend_object_id(value: &str) -> BackendObjectId {
    match BackendObjectId::new(value) {
        Ok(object_id) => object_id,
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

fn keyring(mut keys: Vec<KeyMaterial>) -> KeyRing {
    if !keys
        .iter()
        .any(|key| key.descriptor().purpose == KeyPurpose::Metadata)
    {
        keys.push(metadata_key("metadata", KeyStatus::Primary, 2));
    }

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

#[derive(Clone, Debug)]
struct FailOncePutStore {
    inner: MemoryBlobStore,
    prefix: &'static str,
    fail_next: Arc<Mutex<bool>>,
}

impl FailOncePutStore {
    fn new(inner: MemoryBlobStore, prefix: &'static str) -> Self {
        Self {
            inner,
            prefix,
            fail_next: Arc::new(Mutex::new(true)),
        }
    }

    fn should_fail(&self, object_id: &rs3_types::BackendObjectId) -> rs3_storage::Result<bool> {
        if !object_id.as_str().starts_with(self.prefix) {
            return Ok(false);
        }

        let mut fail_next = self
            .fail_next
            .lock()
            .map_err(|_| StorageError::Provider("fail store lock poisoned".to_owned()))?;
        let should_fail = *fail_next;
        *fail_next = false;
        Ok(should_fail)
    }
}

#[async_trait]
impl BlobStore for FailOncePutStore {
    async fn put(
        &self,
        object_id: &rs3_types::BackendObjectId,
        body: Bytes,
        options: PutOptions,
    ) -> rs3_storage::Result<BlobMetadata> {
        if self.should_fail(object_id)? {
            return Err(StorageError::Provider(format!(
                "injected put failure for {}",
                self.prefix
            )));
        }

        self.inner.put(object_id, body, options).await
    }

    async fn get_range(
        &self,
        object_id: &rs3_types::BackendObjectId,
        range: ByteRange,
    ) -> rs3_storage::Result<Bytes> {
        self.inner.get_range(object_id, range).await
    }

    async fn head(
        &self,
        object_id: &rs3_types::BackendObjectId,
    ) -> rs3_storage::Result<BlobMetadata> {
        self.inner.head(object_id).await
    }

    async fn list_prefix(&self, prefix: &str) -> rs3_storage::Result<Vec<BlobMetadata>> {
        self.inner.list_prefix(prefix).await
    }

    async fn delete(&self, object_id: &rs3_types::BackendObjectId) -> rs3_storage::Result<()> {
        self.inner.delete(object_id).await
    }

    async fn extend_retention(
        &self,
        object_id: &rs3_types::BackendObjectId,
        policy: RetentionPolicy,
    ) -> rs3_storage::Result<()> {
        self.inner.extend_retention(object_id, policy).await
    }

    async fn flush_caches(&self) -> rs3_storage::Result<()> {
        self.inner.flush_caches().await
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
    let manifest_objects = must_storage(store.list_prefix("manifests/").await);

    assert_eq!(checkpoint.record.index_deltas.len(), 1);
    assert_eq!(delta_objects.len(), 1);
    assert!(manifest_objects.is_empty());
    assert_eq!(
        checkpoint.record.index_deltas[0],
        delta_objects[0].object_id
    );

    let delta_body = must_storage(
        store
            .get_range(&delta_objects[0].object_id, ByteRange::Full)
            .await,
    );
    assert!(delta_body.starts_with(INDEX_DELTA_OBJECT_DOMAIN));
    assert_body_does_not_contain(&checkpoint_body, &["sensitive", "client-blob", "p/12"]);
    assert_body_does_not_contain(&delta_body, &["sensitive", "client-blob", "p/12"]);
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
async fn commit_coordinator_fails_all_batch_waiters_when_checkpoint_put_fails() {
    let inner = MemoryBlobStore::new();
    let store = FailOncePutStore::new(inner.clone(), CHECKPOINT_OBJECT_PREFIX);
    let keyring = signing_keyring();
    let repository = Arc::new(Repository::with_keyring(store, keyring.clone()));
    let anchor = MemoryCheckpointAnchor::new();
    let coordinator = Arc::new(CommitCoordinator::with_options(
        repository,
        anchor.clone(),
        CommitCoordinatorOptions::new(2, std::time::Duration::from_secs(60)),
    ));
    let first_key = key("p/12/failed-a");
    let second_key = key("p/12/failed-b");

    let first = {
        let coordinator = Arc::clone(&coordinator);
        let key = first_key.clone();
        async move {
            coordinator
                .put_committed(
                    key,
                    Bytes::from_static(b"first"),
                    RepositoryPutOptions::default(),
                )
                .await
        }
    };
    let second = {
        let coordinator = Arc::clone(&coordinator);
        let key = second_key.clone();
        async move {
            coordinator
                .put_committed(
                    key,
                    Bytes::from_static(b"second"),
                    RepositoryPutOptions::default(),
                )
                .await
        }
    };

    let (first, second) = tokio::join!(first, second);
    let fresh = Repository::with_keyring(inner, keyring);
    let later = coordinator
        .put_committed(
            key("p/12/later"),
            Bytes::from_static(b"later"),
            RepositoryPutOptions::default(),
        )
        .await;

    assert!(matches!(first, Err(RepositoryError::CommitFailed { .. })));
    assert!(matches!(second, Err(RepositoryError::CommitFailed { .. })));
    assert!(matches!(later, Err(RepositoryError::CommitFailed { .. })));
    assert!(matches!(
        anchor.read().await,
        Err(AnchorError::MissingAnchor)
    ));
    assert!(matches!(
        fresh.head(&first_key),
        Err(RepositoryError::NotFound(_))
    ));
    assert!(matches!(
        fresh.head(&second_key),
        Err(RepositoryError::NotFound(_))
    ));
}

#[tokio::test]
async fn commit_coordinator_batches_concurrent_committed_puts() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let repository = Arc::new(Repository::with_keyring(store.clone(), keyring.clone()));
    let anchor = MemoryCheckpointAnchor::new();
    let coordinator = Arc::new(CommitCoordinator::with_options(
        repository,
        anchor.clone(),
        CommitCoordinatorOptions::new(2, std::time::Duration::from_secs(60)),
    ));
    let first_key = key("p/12/a");
    let second_key = key("p/12/b");

    let first = {
        let coordinator = Arc::clone(&coordinator);
        let key = first_key.clone();
        async move {
            coordinator
                .put_committed(
                    key,
                    Bytes::from_static(b"first"),
                    RepositoryPutOptions::default(),
                )
                .await
        }
    };
    let second = {
        let coordinator = Arc::clone(&coordinator);
        let key = second_key.clone();
        async move {
            coordinator
                .put_committed(
                    key,
                    Bytes::from_static(b"second"),
                    RepositoryPutOptions::default(),
                )
                .await
        }
    };

    let (first, second) = tokio::join!(first, second);
    let first = must(first);
    let second = must(second);
    let accepted = match anchor.read().await {
        Ok(anchor) => CheckpointPosition::from(anchor),
        Err(error) => panic!("{error}"),
    };
    let reloaded = Repository::with_keyring(store, keyring);
    let loaded = must(reloaded.load_checkpoint_position(&accepted).await);
    let listed = must(reloaded.list("p/12"));

    assert_eq!(first.checkpoint, second.checkpoint);
    assert_eq!(accepted.sequence, Sequence::new(2));
    assert_eq!(loaded, accepted);
    assert_eq!(
        listed
            .into_iter()
            .map(|entry| entry.key)
            .collect::<Vec<_>>(),
        vec![first_key, second_key]
    );
}

#[tokio::test]
async fn commit_coordinator_publishes_single_write_after_delay() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let repository = Arc::new(Repository::with_keyring(store.clone(), keyring));
    let coordinator = CommitCoordinator::with_options(
        repository,
        MemoryCheckpointAnchor::new(),
        CommitCoordinatorOptions::new(8, std::time::Duration::from_millis(5)),
    );

    let committed = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        coordinator.put_committed(
            key("p/12/quiet"),
            Bytes::from_static(b"quiet"),
            RepositoryPutOptions::default(),
        ),
    )
    .await;

    let committed = match committed {
        Ok(result) => must(result),
        Err(error) => panic!("{error}"),
    };
    let counts = must_storage(store.operation_counts());
    let indexes = must_storage(store.list_prefix("index/").await);
    let checkpoints = must_storage(store.list_prefix(CHECKPOINT_OBJECT_PREFIX).await);

    assert_eq!(committed.checkpoint.sequence, Sequence::new(1));
    assert_eq!(counts.put, 3);
    assert_eq!(indexes.len(), 1);
    assert_eq!(checkpoints.len(), 1);
}

#[tokio::test]
async fn commit_coordinator_applies_backpressure_before_writing_payload() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let repository = Arc::new(Repository::with_keyring(store.clone(), keyring));
    let coordinator = Arc::new(CommitCoordinator::with_options(
        repository,
        MemoryCheckpointAnchor::new(),
        CommitCoordinatorOptions::new(8, std::time::Duration::from_millis(25))
            .with_max_pending_items(1),
    ));

    let first = {
        let coordinator = Arc::clone(&coordinator);
        tokio::spawn(async move {
            coordinator
                .put_committed(
                    key("p/12/first"),
                    Bytes::from_static(b"first"),
                    RepositoryPutOptions::default(),
                )
                .await
        })
    };

    for _ in 0..100 {
        let payloads = must_storage(store.list_prefix("segments/").await);
        if payloads.len() == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }

    let rejected = coordinator
        .put_committed(
            key("p/12/rejected"),
            Bytes::from_static(b"rejected"),
            RepositoryPutOptions::default(),
        )
        .await;
    let payloads_after_rejection = must_storage(store.list_prefix("segments/").await);
    let first = tokio::time::timeout(std::time::Duration::from_secs(1), first).await;

    assert!(matches!(rejected, Err(RepositoryError::CommitBackpressure)));
    assert_eq!(payloads_after_rejection.len(), 1);
    match first {
        Ok(joined) => assert!(matches!(joined, Ok(Ok(_)))),
        Err(error) => panic!("{error}"),
    }
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
    assert_eq!(index_delta_objects.len(), 1);
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
async fn operation_counts_show_checkpoint_batch_reduces_backend_puts() {
    let single_store = MemoryBlobStore::new();
    let single_repository = Arc::new(Repository::with_keyring(
        single_store.clone(),
        signing_keyring(),
    ));
    let single = CommitCoordinator::new(single_repository, MemoryCheckpointAnchor::new());
    let keys = [key("p/12/a"), key("p/12/b"), key("p/12/c")];

    for (index, key) in keys.iter().enumerate() {
        let committed = single
            .put_committed(
                key.clone(),
                Bytes::from(format!("single-{index}")),
                RepositoryPutOptions::default(),
            )
            .await;
        assert!(committed.is_ok());
    }

    let single_counts = must_storage(single_store.operation_counts());
    let single_payloads = must_storage(single_store.list_prefix("segments/").await);
    let single_manifests = must_storage(single_store.list_prefix("manifests/").await);
    let single_indexes = must_storage(single_store.list_prefix("index/").await);
    let single_checkpoints = must_storage(single_store.list_prefix(CHECKPOINT_OBJECT_PREFIX).await);

    let batch_store = MemoryBlobStore::new();
    let batch_repo = Repository::with_keyring(batch_store.clone(), signing_keyring());
    let batch_anchor = MemoryCheckpointAnchor::new();

    for (index, key) in keys.iter().enumerate() {
        let put = batch_repo
            .put(
                key.clone(),
                Bytes::from(format!("batch-{index}")),
                RepositoryPutOptions::default(),
            )
            .await;
        assert!(put.is_ok());
    }
    let published = batch_repo.publish_checkpoint(&batch_anchor).await;
    assert!(published.is_ok());

    let batch_counts = must_storage(batch_store.operation_counts());
    let batch_payloads = must_storage(batch_store.list_prefix("segments/").await);
    let batch_manifests = must_storage(batch_store.list_prefix("manifests/").await);
    let batch_indexes = must_storage(batch_store.list_prefix("index/").await);
    let batch_checkpoints = must_storage(batch_store.list_prefix(CHECKPOINT_OBJECT_PREFIX).await);

    let grouped_store = MemoryBlobStore::new();
    let grouped_repository = Arc::new(Repository::with_keyring(
        grouped_store.clone(),
        signing_keyring(),
    ));
    let grouped = Arc::new(CommitCoordinator::with_options(
        grouped_repository,
        MemoryCheckpointAnchor::new(),
        CommitCoordinatorOptions::new(3, std::time::Duration::from_secs(60)),
    ));
    let grouped_a = {
        let grouped = Arc::clone(&grouped);
        let key = keys[0].clone();
        async move {
            grouped
                .put_committed(
                    key,
                    Bytes::from_static(b"grouped-a"),
                    RepositoryPutOptions::default(),
                )
                .await
        }
    };
    let grouped_b = {
        let grouped = Arc::clone(&grouped);
        let key = keys[1].clone();
        async move {
            grouped
                .put_committed(
                    key,
                    Bytes::from_static(b"grouped-b"),
                    RepositoryPutOptions::default(),
                )
                .await
        }
    };
    let grouped_c = {
        let grouped = Arc::clone(&grouped);
        let key = keys[2].clone();
        async move {
            grouped
                .put_committed(
                    key,
                    Bytes::from_static(b"grouped-c"),
                    RepositoryPutOptions::default(),
                )
                .await
        }
    };

    let grouped_results = tokio::join!(grouped_a, grouped_b, grouped_c);
    assert!(grouped_results.0.is_ok());
    assert!(grouped_results.1.is_ok());
    assert!(grouped_results.2.is_ok());

    let grouped_counts = must_storage(grouped_store.operation_counts());
    let grouped_payloads = must_storage(grouped_store.list_prefix("segments/").await);
    let grouped_indexes = must_storage(grouped_store.list_prefix("index/").await);
    let grouped_checkpoints =
        must_storage(grouped_store.list_prefix(CHECKPOINT_OBJECT_PREFIX).await);

    assert_eq!(single_counts.put, 9);
    assert_eq!(batch_counts.put, 5);
    assert_eq!(grouped_counts.put, 5);
    assert_eq!(single_counts.get, 0);
    assert_eq!(batch_counts.get, 0);
    assert_eq!(grouped_counts.get, 0);
    assert_eq!(single_payloads.len(), 3);
    assert_eq!(single_manifests.len(), 0);
    assert_eq!(single_indexes.len(), 3);
    assert_eq!(single_checkpoints.len(), 3);
    assert_eq!(batch_payloads.len(), 3);
    assert_eq!(batch_manifests.len(), 0);
    assert_eq!(batch_indexes.len(), 1);
    assert_eq!(batch_checkpoints.len(), 1);
    assert_eq!(grouped_payloads.len(), 3);
    assert_eq!(grouped_indexes.len(), 1);
    assert_eq!(grouped_checkpoints.len(), 1);
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
    assert_eq!(index_objects_after_failure.len(), 1);
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
async fn orphan_report_is_empty_for_accepted_repository_objects() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let repo = Repository::with_keyring(store, keyring);
    let anchor = MemoryCheckpointAnchor::new();

    let first = repo
        .put_committed(
            key("p/12/a"),
            Bytes::from_static(b"a"),
            RepositoryPutOptions::default(),
            &anchor,
        )
        .await;
    assert!(first.is_ok());
    let second = must(
        repo.put_committed(
            key("p/12/b"),
            Bytes::from_static(b"b"),
            RepositoryPutOptions::default(),
            &anchor,
        )
        .await,
    );

    let report = must(repo.orphan_report(&second.checkpoint).await);

    assert!(report.candidates.is_empty());
    assert_eq!(
        report
            .reachable
            .iter()
            .filter(|object| object.kind == BackendObjectReferenceKind::Checkpoint)
            .count(),
        2
    );
    assert_eq!(
        report
            .reachable
            .iter()
            .filter(|object| object.kind == BackendObjectReferenceKind::IndexDelta)
            .count(),
        2
    );
    assert_eq!(
        report
            .reachable
            .iter()
            .filter(|object| object.kind == BackendObjectReferenceKind::Payload)
            .count(),
        2
    );
}

#[tokio::test]
async fn orphan_report_finds_unaccepted_payload_and_index_objects() {
    let inner = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let anchor = MemoryCheckpointAnchor::new();
    let accepted_repo = Repository::with_keyring(inner.clone(), keyring.clone());
    let accepted = must(
        accepted_repo
            .put_committed(
                key("p/12/accepted"),
                Bytes::from_static(b"accepted"),
                RepositoryPutOptions::default(),
                &anchor,
            )
            .await,
    );
    let failing_store = FailOncePutStore::new(inner.clone(), CHECKPOINT_OBJECT_PREFIX);
    let writer = Repository::with_keyring(failing_store, keyring.clone());
    let loaded = writer.load_checkpoint_position(&accepted.checkpoint).await;
    assert!(loaded.is_ok());
    let staged = writer
        .put(
            key("p/12/unaccepted"),
            Bytes::from_static(b"unaccepted"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(staged.is_ok());

    let failed = writer.publish_checkpoint(&anchor).await;
    let current_anchor = match anchor.read().await {
        Ok(anchor) => CheckpointPosition::from(anchor),
        Err(error) => panic!("{error}"),
    };
    let report_repo = Repository::with_keyring(inner, keyring);
    let report = must(report_repo.orphan_report(&accepted.checkpoint).await);
    let candidate_ids = report
        .candidates
        .iter()
        .map(|candidate| candidate.object_id.as_str())
        .collect::<Vec<_>>();

    assert!(matches!(
        failed,
        Err(RepositoryError::Storage(StorageError::Provider(_)))
    ));
    assert_eq!(current_anchor, accepted.checkpoint);
    assert_eq!(report.candidates.len(), 2);
    assert!(
        report
            .candidates
            .iter()
            .any(|candidate| candidate.kind == BackendObjectReferenceKind::IndexDelta)
    );
    assert!(
        report
            .candidates
            .iter()
            .any(|candidate| candidate.kind == BackendObjectReferenceKind::Payload)
    );
    assert!(
        candidate_ids
            .iter()
            .all(|id| id.starts_with("index/") || id.starts_with("segments/"))
    );
}

#[tokio::test]
async fn orphan_report_marks_retention_blocked_candidates() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let repo = Repository::with_keyring(store.clone(), keyring);
    let anchor = MemoryCheckpointAnchor::new();
    let committed = must(
        repo.put_committed(
            key("p/12/accepted"),
            Bytes::from_static(b"accepted"),
            RepositoryPutOptions::default(),
            &anchor,
        )
        .await,
    );
    let retained_object = backend_object_id("segments/manual-retained");
    let retention = RetentionPolicy::new(RetentionMode::Compliance, 30);
    let put = store
        .put(
            &retained_object,
            Bytes::from_static(b"retained"),
            PutOptions {
                retention: Some(retention.clone()),
                ..PutOptions::default()
            },
        )
        .await;
    assert!(put.is_ok());

    let report = must(repo.orphan_report(&committed.checkpoint).await);
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.object_id == retained_object)
        .unwrap_or_else(|| panic!("missing retained candidate"));

    assert_eq!(candidate.retention, Some(retention));
    assert!(candidate.delete_blocked_by_retention);
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
