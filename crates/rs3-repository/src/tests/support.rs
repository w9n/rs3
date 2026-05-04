use crate::checkpoint::checkpoint_object_id;
use crate::{Repository, RepositoryOptions, Result};
use async_trait::async_trait;
use bytes::Bytes;
use rs3_anchor::{AnchorError, AnchorState, CheckpointAnchor, MemoryCheckpointAnchor};
use rs3_crypto::{KeyMaterial, KeyRing, SecretBytes};
use rs3_index::{CHECKPOINT_OBJECT_DOMAIN, Checkpoint};
use rs3_storage::{BlobMetadata, BlobStore, ByteRange, MemoryBlobStore, PutOptions, StorageError};
use rs3_types::{
    BackendObjectId, CheckpointId, KeyDescriptor, KeyId, KeyPurpose, KeyStatus, LegalHoldStatus,
    LogicalPath, RetentionPolicy, Sequence,
};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;

pub(super) fn secret() -> SecretBytes {
    secret_with_byte(9)
}

pub(super) fn secret_with_byte(byte: u8) -> SecretBytes {
    match SecretBytes::new(vec![byte; SecretBytes::MIN_LEN]) {
        Ok(secret) => secret,
        Err(error) => panic!("{error}"),
    }
}

pub(super) fn key(value: &str) -> LogicalPath {
    match LogicalPath::new(value) {
        Ok(key) => key,
        Err(error) => panic!("{error}"),
    }
}

pub(crate) fn backend_object_id(value: &str) -> BackendObjectId {
    match BackendObjectId::new(value) {
        Ok(object_id) => object_id,
        Err(error) => panic!("{error}"),
    }
}

pub(super) fn key_id(value: &str) -> KeyId {
    match KeyId::new(value) {
        Ok(key_id) => key_id,
        Err(error) => panic!("{error}"),
    }
}

pub(super) fn checkpoint_id(value: &str) -> CheckpointId {
    match CheckpointId::new(value) {
        Ok(checkpoint_id) => checkpoint_id,
        Err(error) => panic!("{error}"),
    }
}

pub(super) fn anchor_state(sequence: u64, id: &str) -> AnchorState {
    AnchorState {
        sequence: Sequence::new(sequence),
        checkpoint_id: checkpoint_id(id),
        checkpoint_digest: format!("digest-{id}"),
    }
}

pub(super) fn namespace_key(value: &str, status: KeyStatus, secret_byte: u8) -> KeyMaterial {
    key_material(
        value,
        KeyPurpose::Namespace,
        status,
        "hmac-sha256",
        secret_byte,
    )
}

pub(super) fn checkpoint_key(value: &str, status: KeyStatus, secret_byte: u8) -> KeyMaterial {
    key_material(
        value,
        KeyPurpose::CheckpointSigning,
        status,
        "ed25519",
        secret_byte,
    )
}

pub(super) fn content_key(value: &str, status: KeyStatus, secret_byte: u8) -> KeyMaterial {
    key_material(
        value,
        KeyPurpose::Content,
        status,
        "xchacha20poly1305",
        secret_byte,
    )
}

pub(super) fn metadata_key(value: &str, status: KeyStatus, secret_byte: u8) -> KeyMaterial {
    key_material(
        value,
        KeyPurpose::Metadata,
        status,
        "aes-256-gcm-siv-hmac-sha256-nonce-v1",
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
            public_key: None,
            external_kms_uri: None,
        },
        secret_with_byte(secret_byte),
    )
}

pub(super) fn keyring(mut keys: Vec<KeyMaterial>) -> KeyRing {
    if !keys
        .iter()
        .any(|key| key.descriptor().purpose == KeyPurpose::Content)
    {
        keys.push(content_key("content", KeyStatus::Primary, 4));
    }
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

pub(crate) fn signing_keyring() -> KeyRing {
    keyring(vec![
        namespace_key("namespace", KeyStatus::Primary, 1),
        metadata_key("metadata", KeyStatus::Primary, 2),
        checkpoint_key("signing", KeyStatus::Primary, 3),
        content_key("content", KeyStatus::Primary, 4),
    ])
}

pub(super) fn repository_with_payload_segment_size(
    store: MemoryBlobStore,
    payload_segment_size: usize,
) -> Repository<MemoryBlobStore> {
    Repository::with_keyring_and_options(
        store,
        signing_keyring(),
        RepositoryOptions {
            payload_segment_size,
            default_retention: None,
        },
    )
}

pub(crate) fn wrong_content_keyring() -> KeyRing {
    keyring(vec![
        namespace_key("namespace", KeyStatus::Primary, 1),
        metadata_key("metadata", KeyStatus::Primary, 2),
        checkpoint_key("signing", KeyStatus::Primary, 3),
        content_key("content", KeyStatus::Primary, 44),
    ])
}

pub(super) fn primary_key_id(keyring: &KeyRing) -> KeyId {
    match keyring.primary_namespace_key_id() {
        Ok(key_id) => key_id,
        Err(error) => panic!("{error}"),
    }
}

pub(super) fn must<T>(result: Result<T>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{error}"),
    }
}

pub(super) fn must_storage<T>(result: rs3_storage::Result<T>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{error}"),
    }
}

pub(super) fn now_ms() -> i64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis();
    i64::try_from(millis).unwrap_or(i64::MAX)
}

pub(super) fn decode_checkpoint_object(body: Bytes) -> Checkpoint {
    let Some(payload) = body.as_ref().strip_prefix(CHECKPOINT_OBJECT_DOMAIN) else {
        panic!("checkpoint object is missing domain prefix");
    };

    match serde_json::from_slice(payload) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("{error}"),
    }
}

pub(super) struct TestDir {
    path: PathBuf,
}

impl TestDir {
    pub(super) fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rs3-repository-test-{}-{nanos}",
            std::process::id()
        ));
        Self { path }
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

pub(super) fn assert_body_does_not_contain(body: &Bytes, needles: &[&str]) {
    let body = String::from_utf8_lossy(body);
    for needle in needles {
        assert!(!body.contains(needle));
    }
}

pub(super) struct CheckpointMustExistAnchor {
    inner: MemoryCheckpointAnchor,
    store: MemoryBlobStore,
}

impl CheckpointMustExistAnchor {
    pub(super) fn new(store: MemoryBlobStore) -> Self {
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

pub(super) struct FailOnceAnchor {
    inner: MemoryCheckpointAnchor,
    fail_next: Arc<Mutex<bool>>,
}

impl FailOnceAnchor {
    pub(super) fn new() -> Self {
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
pub(super) struct FailOncePutStore {
    inner: MemoryBlobStore,
    prefix: &'static str,
    fail_next: Arc<Mutex<bool>>,
}

impl FailOncePutStore {
    pub(super) fn new(inner: MemoryBlobStore, prefix: &'static str) -> Self {
        Self {
            inner,
            prefix,
            fail_next: Arc::new(Mutex::new(true)),
        }
    }

    fn should_fail(&self, object_id: &BackendObjectId) -> rs3_storage::Result<bool> {
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
        object_id: &BackendObjectId,
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
        object_id: &BackendObjectId,
        range: ByteRange,
    ) -> rs3_storage::Result<Bytes> {
        self.inner.get_range(object_id, range).await
    }

    async fn head(&self, object_id: &BackendObjectId) -> rs3_storage::Result<BlobMetadata> {
        self.inner.head(object_id).await
    }

    async fn list_prefix(&self, prefix: &str) -> rs3_storage::Result<Vec<BlobMetadata>> {
        self.inner.list_prefix(prefix).await
    }

    async fn delete(&self, object_id: &BackendObjectId) -> rs3_storage::Result<()> {
        self.inner.delete(object_id).await
    }

    async fn extend_retention(
        &self,
        object_id: &BackendObjectId,
        policy: RetentionPolicy,
    ) -> rs3_storage::Result<()> {
        self.inner.extend_retention(object_id, policy).await
    }

    async fn set_legal_hold(
        &self,
        object_id: &BackendObjectId,
        status: LegalHoldStatus,
    ) -> rs3_storage::Result<()> {
        self.inner.set_legal_hold(object_id, status).await
    }

    async fn flush_caches(&self) -> rs3_storage::Result<()> {
        self.inner.flush_caches().await
    }
}

#[derive(Clone)]
pub(super) struct PauseFirstSegmentPutStore {
    inner: MemoryBlobStore,
    state: Arc<PauseFirstSegmentPutState>,
}

struct PauseFirstSegmentPutState {
    pause_next_segment_put: Mutex<bool>,
    entered: Notify,
    release: Notify,
}

impl PauseFirstSegmentPutStore {
    pub(super) fn new(inner: MemoryBlobStore) -> Self {
        Self {
            inner,
            state: Arc::new(PauseFirstSegmentPutState {
                pause_next_segment_put: Mutex::new(true),
                entered: Notify::new(),
                release: Notify::new(),
            }),
        }
    }

    pub(super) async fn wait_until_paused(&self) {
        self.state.entered.notified().await;
    }

    pub(super) fn release(&self) {
        self.state.release.notify_waiters();
    }

    fn should_pause(&self, object_id: &BackendObjectId) -> rs3_storage::Result<bool> {
        if !object_id.as_str().starts_with("segments/") {
            return Ok(false);
        }

        let mut pause_next = self
            .state
            .pause_next_segment_put
            .lock()
            .map_err(|_| StorageError::Provider("pause store lock poisoned".to_owned()))?;
        let should_pause = *pause_next;
        *pause_next = false;
        Ok(should_pause)
    }
}

#[async_trait]
impl BlobStore for PauseFirstSegmentPutStore {
    async fn put(
        &self,
        object_id: &BackendObjectId,
        body: Bytes,
        options: PutOptions,
    ) -> rs3_storage::Result<BlobMetadata> {
        if self.should_pause(object_id)? {
            self.state.entered.notify_one();
            self.state.release.notified().await;
        }

        self.inner.put(object_id, body, options).await
    }

    async fn get_range(
        &self,
        object_id: &BackendObjectId,
        range: ByteRange,
    ) -> rs3_storage::Result<Bytes> {
        self.inner.get_range(object_id, range).await
    }

    async fn head(&self, object_id: &BackendObjectId) -> rs3_storage::Result<BlobMetadata> {
        self.inner.head(object_id).await
    }

    async fn list_prefix(&self, prefix: &str) -> rs3_storage::Result<Vec<BlobMetadata>> {
        self.inner.list_prefix(prefix).await
    }

    async fn delete(&self, object_id: &BackendObjectId) -> rs3_storage::Result<()> {
        self.inner.delete(object_id).await
    }

    async fn extend_retention(
        &self,
        object_id: &BackendObjectId,
        policy: RetentionPolicy,
    ) -> rs3_storage::Result<()> {
        self.inner.extend_retention(object_id, policy).await
    }

    async fn set_legal_hold(
        &self,
        object_id: &BackendObjectId,
        status: LegalHoldStatus,
    ) -> rs3_storage::Result<()> {
        self.inner.set_legal_hold(object_id, status).await
    }

    async fn flush_caches(&self) -> rs3_storage::Result<()> {
        self.inner.flush_caches().await
    }
}

#[derive(Clone, Debug)]
pub(super) struct NoPutTimestampStore {
    pub(super) inner: MemoryBlobStore,
}

#[async_trait]
impl BlobStore for NoPutTimestampStore {
    async fn put(
        &self,
        object_id: &BackendObjectId,
        body: Bytes,
        options: PutOptions,
    ) -> rs3_storage::Result<BlobMetadata> {
        let mut metadata = self.inner.put(object_id, body, options).await?;
        metadata.modified_at_ms = None;
        Ok(metadata)
    }

    async fn get_range(
        &self,
        object_id: &BackendObjectId,
        range: ByteRange,
    ) -> rs3_storage::Result<Bytes> {
        self.inner.get_range(object_id, range).await
    }

    async fn head(&self, object_id: &BackendObjectId) -> rs3_storage::Result<BlobMetadata> {
        self.inner.head(object_id).await
    }

    async fn list_prefix(&self, prefix: &str) -> rs3_storage::Result<Vec<BlobMetadata>> {
        self.inner.list_prefix(prefix).await
    }

    async fn delete(&self, object_id: &BackendObjectId) -> rs3_storage::Result<()> {
        self.inner.delete(object_id).await
    }

    async fn extend_retention(
        &self,
        object_id: &BackendObjectId,
        policy: RetentionPolicy,
    ) -> rs3_storage::Result<()> {
        self.inner.extend_retention(object_id, policy).await
    }

    async fn set_legal_hold(
        &self,
        object_id: &BackendObjectId,
        status: LegalHoldStatus,
    ) -> rs3_storage::Result<()> {
        self.inner.set_legal_hold(object_id, status).await
    }

    async fn flush_caches(&self) -> rs3_storage::Result<()> {
        self.inner.flush_caches().await
    }
}
