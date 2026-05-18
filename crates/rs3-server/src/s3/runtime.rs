//! Runtime repository construction for the S3 service.

use super::S3BoundaryError;
use crate::{GatewayMode, RuntimeConfig};
use bytes::Bytes;
use futures_util::Stream;
use rs3_repository::{
    DeleteOutcome, RepositoryError, RepositoryListEntry, RepositoryObjectMetadata,
    RepositoryPutOptions,
};
use rs3_storage::ByteRange;
#[cfg(test)]
use rs3_storage::MemoryBlobStore;
use rs3_types::{LegalHoldStatus, LogicalPath, RetentionPolicy};
use std::sync::Arc;

use super::runtime_v2::RuntimeV2Repository;

#[derive(Clone)]
pub(super) struct RuntimeRepository {
    inner: Arc<RuntimeV2Repository>,
}

pub(super) struct RuntimeCommittedPut {
    pub(super) metadata: RepositoryObjectMetadata,
}

impl RuntimeRepository {
    pub(super) async fn from_config(config: &RuntimeConfig) -> Result<Self, S3BoundaryError> {
        let inner = Arc::new(RuntimeV2Repository::from_config(config).await?);
        Ok(Self { inner })
    }

    pub(super) async fn load_accepted_anchor(
        &self,
        mode: GatewayMode,
    ) -> Result<(), S3BoundaryError> {
        self.inner.load_accepted_anchor(mode).await
    }

    pub(super) async fn validate_backend_retention(
        &self,
        retention: Option<RetentionPolicy>,
    ) -> Result<(), S3BoundaryError> {
        self.inner.validate_backend_retention(retention).await
    }

    pub(super) async fn put_committed(
        &self,
        key: LogicalPath,
        body: Bytes,
        options: RepositoryPutOptions,
    ) -> Result<RuntimeCommittedPut, RepositoryError> {
        self.inner
            .put_committed(key, body, options)
            .await
            .map(|metadata| RuntimeCommittedPut { metadata })
    }

    pub(super) fn supports_streaming_put(&self) -> bool {
        self.inner.supports_streaming_put()
    }

    pub(super) async fn put_committed_streaming_known_len<St>(
        &self,
        key: LogicalPath,
        plaintext_len: u64,
        stream: St,
        options: RepositoryPutOptions,
        multipart_part_size: usize,
    ) -> Result<RuntimeCommittedPut, RepositoryError>
    where
        St: Stream<Item = Result<Bytes, RepositoryError>> + Unpin + Send,
    {
        self.inner
            .put_committed_streaming_known_len(
                key,
                plaintext_len,
                stream,
                options,
                multipart_part_size,
            )
            .await
            .map(|metadata| RuntimeCommittedPut { metadata })
    }

    pub(super) async fn put_committed_streaming_unknown_len<St>(
        &self,
        key: LogicalPath,
        stream: St,
        options: RepositoryPutOptions,
        multipart_part_size: usize,
        max_plaintext_len: u64,
    ) -> Result<RuntimeCommittedPut, RepositoryError>
    where
        St: Stream<Item = Result<Bytes, RepositoryError>> + Unpin + Send,
    {
        self.inner
            .put_committed_streaming_unknown_len(
                key,
                stream,
                options,
                multipart_part_size,
                max_plaintext_len,
            )
            .await
            .map(|metadata| RuntimeCommittedPut { metadata })
    }

    pub(super) fn head(
        &self,
        key: &LogicalPath,
    ) -> Result<RepositoryObjectMetadata, RepositoryError> {
        self.inner.head(key)
    }

    pub(super) async fn get_range(
        &self,
        key: &LogicalPath,
        range: ByteRange,
    ) -> Result<Bytes, RepositoryError> {
        self.inner.get_range(key, range).await
    }

    pub(super) fn list(&self, prefix: &str) -> Result<Vec<RepositoryListEntry>, RepositoryError> {
        self.inner.list(prefix)
    }

    pub(super) async fn delete_committed(
        &self,
        key: LogicalPath,
    ) -> Result<DeleteOutcome, RepositoryError> {
        self.inner.delete_committed(key).await
    }

    pub(super) async fn set_legal_hold_committed(
        &self,
        key: LogicalPath,
        status: LegalHoldStatus,
    ) -> Result<RepositoryObjectMetadata, RepositoryError> {
        self.inner.set_legal_hold_committed(key, status).await
    }

    #[cfg(test)]
    pub(super) fn memory_store(&self) -> Option<&MemoryBlobStore> {
        self.inner.memory_store()
    }

    #[cfg(test)]
    pub(super) fn memory_v2_anchor(&self) -> Option<&rs3_repository::v2::V2MemoryAnchor> {
        self.inner.memory_anchor()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "s3")]
    use super::super::runtime_builders::s3_backend_config;
    use super::super::runtime_handles::RuntimeStore;
    use super::super::runtime_keyring::unanchored_gateway_keyring;
    use super::RuntimeRepository;
    #[cfg(not(feature = "k8s"))]
    use crate::AnchorConfig;
    use crate::s3::S3BoundaryError;
    use crate::s3::test_support::runtime_config;
    use crate::{BatchConfig, GatewayMode, RepositoryFormat, RepositoryKeysConfig};
    use bytes::Bytes;
    use rs3_crypto::{KeyRing, RepositoryKeyContext, SecretBytes};
    use rs3_repository::RepositoryPutOptions;
    use rs3_repository::v2::V2CommitAnchor;
    use rs3_storage::{BlobStore, ByteRange, FilesystemBlobStore, MemoryBlobStore, PutOptions};
    use rs3_types::{BackendObjectId, LogicalPath, RepositoryId, RetentionMode, RetentionPolicy};
    use secrecy::SecretString;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new() -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "rs3-server-runtime-test-{}-{nanos}",
                std::process::id()
            ));
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[tokio::test]
    async fn runtime_factory_builds_memory_repository() {
        let runtime = RuntimeRepository::from_config(&runtime_config(true))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(runtime.memory_store().is_some());
        assert!(runtime.memory_v2_anchor().is_some());
    }

    #[tokio::test]
    async fn runtime_factory_builds_v2_preview_repository() {
        let mut config = runtime_config(true);
        config.repository.format = RepositoryFormat::V2Preview;
        let runtime = RuntimeRepository::from_config(&config)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let store = runtime
            .memory_store()
            .unwrap_or_else(|| panic!("missing memory store"));
        let format_roots = store
            .list_prefix("format/")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let commits = store
            .list_prefix("commits/v01/")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let v2_anchor = runtime
            .memory_v2_anchor()
            .unwrap_or_else(|| panic!("missing v2 memory anchor"));

        assert_eq!(format_roots.len(), 1);
        assert_eq!(commits.len(), 1);
        assert!(
            v2_anchor
                .read_v2()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_some()
        );
        runtime
            .load_accepted_anchor(GatewayMode::ReadWrite)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let key =
            LogicalPath::new("snapshots/v2-preview.bin").unwrap_or_else(|error| panic!("{error}"));
        let committed = runtime
            .put_committed(
                key.clone(),
                Bytes::from_static(b"body"),
                RepositoryPutOptions::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let head = runtime.head(&key).unwrap_or_else(|error| panic!("{error}"));
        let body = runtime
            .get_range(&key, ByteRange::Full)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let list = runtime
            .list("snapshots/")
            .unwrap_or_else(|error| panic!("{error}"));
        let commits = store
            .list_prefix("commits/v01/")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let backend_objects = store
            .list_prefix("")
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(committed.metadata.content_len, 4);
        assert_eq!(head.content_len, 4);
        assert_eq!(body, Bytes::from_static(b"body"));
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].key, key);
        assert_eq!(commits.len(), 2);
        for metadata in backend_objects {
            assert!(!metadata.object_id.as_str().contains("snapshots"));
            assert!(!metadata.object_id.as_str().contains("v2-preview"));
        }
    }

    #[tokio::test]
    async fn runtime_factory_initializes_default_keyring_envelope_in_empty_repository() {
        let config = runtime_config(true);

        let runtime = RuntimeRepository::from_config(&config)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let keyrings = runtime
            .memory_store()
            .unwrap_or_else(|| panic!("missing memory store"))
            .list_prefix("keyrings/")
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(keyrings.len(), 1);
        assert!(
            keyrings[0]
                .object_id
                .as_str()
                .starts_with("keyrings/00000000000000000001-")
        );
    }

    #[tokio::test]
    async fn runtime_factory_requires_explicit_repository_init() {
        let mut config = runtime_config(true);
        config.repository.allow_init = false;

        let runtime = RuntimeRepository::from_config(&config).await;

        assert!(
            matches!(runtime, Err(S3BoundaryError::RepositoryInit { reason }) if reason.contains("RS3_ALLOW_REPOSITORY_INIT=true"))
        );
    }

    #[tokio::test]
    async fn runtime_factory_rejects_missing_keyring_envelope_when_repository_is_not_empty() {
        let dir = TestDir::new();
        let mut config = runtime_config(true);
        config.backend.endpoint = format!("file://{}", dir.path().display());
        let store_root = dir
            .path()
            .join(&config.backend.bucket)
            .join(config.backend.prefix.as_deref().unwrap_or(""));
        let store = FilesystemBlobStore::new(&store_root).unwrap_or_else(|error| panic!("{error}"));
        let object_id =
            BackendObjectId::new("commits/preexisting").unwrap_or_else(|error| panic!("{error}"));
        store
            .put(
                &object_id,
                Bytes::from_static(b"preexisting"),
                PutOptions {
                    retention: None,
                    legal_hold: None,
                    content_type: None,
                    do_not_recreate: true,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let runtime = RuntimeRepository::from_config(&config).await;

        assert!(
            matches!(runtime, Err(S3BoundaryError::RepositoryInit { reason }) if reason.contains("already exist"))
        );
    }

    #[tokio::test]
    async fn restore_readonly_runtime_refuses_empty_repository_bootstrap() {
        let dir = TestDir::new();
        let mut config = runtime_config(true);
        config.mode = GatewayMode::RestoreReadOnly;
        config.backend.endpoint = format!("file://{}", dir.path().display());

        let runtime = RuntimeRepository::from_config(&config).await;

        assert!(
            matches!(runtime, Err(S3BoundaryError::RepositoryInit { reason }) if reason.contains("restore-readonly"))
        );

        let store_root = dir
            .path()
            .join(&config.backend.bucket)
            .join(config.backend.prefix.as_deref().unwrap_or(""));
        let store = FilesystemBlobStore::new(&store_root).unwrap_or_else(|error| panic!("{error}"));
        let keyrings = store
            .list_prefix("keyrings/")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(keyrings.is_empty());
    }

    #[tokio::test]
    async fn startup_validation_rejects_missing_accepted_v2_commit() {
        let runtime = RuntimeRepository::from_config(&runtime_config(true))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let accepted = runtime
            .memory_v2_anchor()
            .unwrap_or_else(|| panic!("missing v2 memory anchor"))
            .read_v2()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing v2 anchor state"));
        runtime
            .memory_store()
            .unwrap_or_else(|| panic!("missing memory store"))
            .delete(&accepted.commit_key)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let loaded = runtime.load_accepted_anchor(GatewayMode::ReadWrite).await;

        assert!(
            matches!(loaded, Err(S3BoundaryError::RepositoryInit { reason }) if reason.contains("storage operation failed"))
        );
    }

    #[tokio::test]
    async fn runtime_repository_default_retention_applies_to_writes() {
        let mut config = runtime_config(true);
        config.repository.retention = Some(RetentionPolicy::new(RetentionMode::Compliance, 30));
        let runtime = RuntimeRepository::from_config(&config)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let put = runtime
            .put_committed(
                LogicalPath::new("snapshots/retained-default.bin")
                    .unwrap_or_else(|error| panic!("{error}")),
                Bytes::from_static(b"body"),
                RepositoryPutOptions::default(),
            )
            .await;
        assert!(put.is_ok());

        let accepted = runtime
            .memory_v2_anchor()
            .unwrap_or_else(|| panic!("missing v2 memory anchor"))
            .read_v2()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing v2 anchor state"));
        let commit = runtime
            .memory_store()
            .unwrap_or_else(|| panic!("missing memory store"))
            .head_at(&accepted.commit_key, accepted.version_id.as_ref())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            commit.retention,
            Some(RetentionPolicy::new(RetentionMode::Compliance, 30))
        );
    }

    #[tokio::test]
    async fn runtime_keyring_can_open_encrypted_envelope_source() {
        let repository_id =
            RepositoryId::new("test-repository").unwrap_or_else(|error| panic!("{error}"));
        let context = RepositoryKeyContext::new(repository_id.clone(), vec![2; 32])
            .unwrap_or_else(|error| panic!("{error}"));
        let keyring = KeyRing::generate_random().unwrap_or_else(|error| panic!("{error}"));
        let wrapping_key = SecretBytes::new(vec![12; SecretBytes::MIN_LEN])
            .unwrap_or_else(|error| panic!("{error}"));
        let envelope = keyring
            .seal_keyring_envelope(&context, "wrap-v1", &wrapping_key, 1)
            .unwrap_or_else(|error| panic!("{error}"));
        let object_id = BackendObjectId::new("keyrings/test-envelope.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let memory = MemoryBlobStore::new();
        memory
            .put(
                &object_id,
                Bytes::from(
                    envelope
                        .to_object_bytes()
                        .unwrap_or_else(|error| panic!("{error}")),
                ),
                PutOptions {
                    retention: None,
                    legal_hold: None,
                    content_type: None,
                    do_not_recreate: true,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let store = RuntimeStore::new(memory);
        let expected_object_id = object_id.clone();
        let keys = RepositoryKeysConfig {
            repository_id,
            repository_salt_hex: "0202020202020202020202020202020202020202020202020202020202020202"
                .to_owned(),
            envelope_object_id: Some(object_id),
            wrapping_key_id: "wrap-v1".to_owned(),
            wrapping_key_hex: SecretString::from(
                "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            ),
        };

        let opened = unanchored_gateway_keyring(&store, &keys, None, true)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(opened.keyring.descriptors(), keyring.descriptors());
        assert_eq!(
            opened
                .keyring
                .derive_backend_object_id("commits", b"same")
                .unwrap_or_else(|error| panic!("{error}")),
            keyring
                .derive_backend_object_id("commits", b"same")
                .unwrap_or_else(|error| panic!("{error}"))
        );
        assert_eq!(
            opened
                .envelope_reference
                .as_ref()
                .map(|reference| reference.object_id.clone()),
            Some(expected_object_id)
        );
    }

    #[tokio::test]
    async fn runtime_v2_format_root_binds_configured_keyring_envelope() {
        let dir = TestDir::new();
        let mut config = runtime_config(true);
        config.backend.endpoint = format!("file://{}", dir.path().display());
        config.batching = BatchConfig {
            max_items: 1,
            max_delay: Duration::from_millis(10),
            max_pending_items: 1,
        };

        let repository_id = config.repository_keys.repository_id.clone();
        let repository_salt = hex::decode(&config.repository_keys.repository_salt_hex)
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RepositoryKeyContext::new(repository_id, repository_salt)
            .unwrap_or_else(|error| panic!("{error}"));
        let keyring = KeyRing::generate_random().unwrap_or_else(|error| panic!("{error}"));
        let wrapping_key = SecretBytes::new(vec![12; SecretBytes::MIN_LEN])
            .unwrap_or_else(|error| panic!("{error}"));
        let envelope = keyring
            .seal_keyring_envelope(&context, "wrap-v1", &wrapping_key, 7)
            .unwrap_or_else(|error| panic!("{error}"));
        let envelope_object_id = BackendObjectId::new("keyrings/runtime-envelope.json")
            .unwrap_or_else(|error| panic!("{error}"));
        config.repository_keys.envelope_object_id = Some(envelope_object_id.clone());
        config.repository_keys.wrapping_key_id = "wrap-v1".to_owned();
        config.repository_keys.wrapping_key_hex =
            SecretString::from("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");

        let store_root = dir
            .path()
            .join(&config.backend.bucket)
            .join(config.backend.prefix.as_deref().unwrap_or(""));
        let store = FilesystemBlobStore::new(&store_root).unwrap_or_else(|error| panic!("{error}"));
        store
            .put(
                &envelope_object_id,
                Bytes::from(
                    envelope
                        .to_object_bytes()
                        .unwrap_or_else(|error| panic!("{error}")),
                ),
                PutOptions {
                    retention: None,
                    legal_hold: None,
                    content_type: None,
                    do_not_recreate: true,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let runtime = RuntimeRepository::from_config(&config)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        runtime
            .put_committed(
                LogicalPath::new("snapshots/enveloped.bin")
                    .unwrap_or_else(|error| panic!("{error}")),
                Bytes::from_static(b"body"),
                RepositoryPutOptions::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let accepted = runtime
            .memory_v2_anchor()
            .unwrap_or_else(|| panic!("missing v2 memory anchor"))
            .read_v2()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing v2 anchor state"));
        let body = store
            .get_range(&accepted.format_ref.object_id, ByteRange::Full)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let format_envelope =
            rs3_crypto::FormatEnvelope::from_object_bytes(&body).unwrap_or_else(|error| {
                panic!("{error}");
            });
        let plaintext = format_envelope
            .open(
                &context,
                &config.repository_keys.wrapping_key_id,
                &wrapping_key,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let format_root = rs3_repository::v2::V2FormatRoot::from_plaintext_bytes(&plaintext)
            .unwrap_or_else(|error| panic!("{error}"));
        let reference = format_root.active_keyring_envelope_ref;

        assert_eq!(reference.generation, 7);
        assert_eq!(reference.object_id, envelope_object_id);
        assert_eq!(
            reference.digest,
            envelope.digest().unwrap_or_else(|error| panic!("{error}"))
        );
    }

    #[tokio::test]
    async fn runtime_factory_builds_file_repository() {
        let dir = TestDir::new();
        let mut config = runtime_config(true);
        config.backend.endpoint = format!("file://{}", dir.path().display());
        config.batching = BatchConfig {
            max_items: 1,
            max_delay: Duration::from_millis(10),
            max_pending_items: 1,
        };
        let runtime = RuntimeRepository::from_config(&config)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let key = LogicalPath::new("snapshots/file.bin").unwrap_or_else(|error| {
            panic!("{error}");
        });

        let put = runtime
            .put_committed(
                key.clone(),
                Bytes::from_static(b"file-backed body"),
                RepositoryPutOptions::default(),
            )
            .await;
        assert!(put.is_ok());

        let head = runtime.head(&key).unwrap_or_else(|error| {
            panic!("{error}");
        });
        let commits_root = dir
            .path()
            .join("backend-bucket")
            .join("repo")
            .join("commits")
            .join("v01");

        assert_eq!(head.content_len, 16);
        assert!(commits_root.is_dir());
    }

    #[tokio::test]
    async fn runtime_factory_rejects_unwired_backend() {
        let mut config = runtime_config(true);
        config.backend.endpoint = "unsupported://object.example".to_owned();

        let runtime = RuntimeRepository::from_config(&config).await;

        assert!(matches!(
            runtime,
            Err(S3BoundaryError::UnsupportedBackendMode)
        ));
    }

    #[cfg(feature = "s3")]
    #[test]
    fn runtime_factory_maps_http_endpoint_to_s3_backend_config() {
        let mut config = runtime_config(true);
        config.backend.endpoint = "http://127.0.0.1:9000".to_owned();
        config.backend.bucket = "backup-data".to_owned();
        config.backend.prefix = Some("repo".to_owned());

        let store_config = s3_backend_config(&config.backend)
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("expected S3 backend config"));

        assert_eq!(store_config.bucket, "backup-data");
        assert_eq!(store_config.prefix.as_deref(), Some("repo"));
        assert_eq!(
            store_config.endpoint_url.as_deref(),
            Some("http://127.0.0.1:9000")
        );
        assert!(store_config.allow_http);
        assert!(!store_config.virtual_hosted_style);
    }

    #[cfg(not(feature = "k8s"))]
    #[tokio::test]
    async fn runtime_factory_rejects_unwired_anchor() {
        let mut config = runtime_config(true);
        config.anchor = AnchorConfig::KubernetesLease {
            namespace: "backup".to_owned(),
            name: "v2-anchor".to_owned(),
            field_manager: "rs3-server".to_owned(),
        };

        let runtime = RuntimeRepository::from_config(&config).await;

        assert!(matches!(
            runtime,
            Err(S3BoundaryError::UnsupportedAnchorMode)
        ));
    }
}
