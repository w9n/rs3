//! Runtime repository construction for the S3 service.

use super::S3BoundaryError;
use crate::config::REPOSITORY_MASTER_KEY_HEX_ENV;
use crate::{AnchorConfig, BackendConfig, BatchConfig, RepositoryKeysConfig, RuntimeConfig};
use bytes::Bytes;
use rs3_anchor::{AnchorError, AnchorState, CheckpointAnchor, MemoryCheckpointAnchor};
use rs3_crypto::{KeyRing, SecretBytes};
#[cfg(feature = "k8s")]
use rs3_k8s::{KubernetesLeaseAnchor, LeaseSettings};
use rs3_repository::{
    CheckpointPosition, CommitCoordinator, CommitCoordinatorOptions, CommittedPut, DeleteOutcome,
    Repository, RepositoryError, RepositoryListEntry, RepositoryObjectMetadata, RepositoryOptions,
    RepositoryPutOptions,
};
use rs3_storage::{
    BlobMetadata, BlobStore, ByteRange, FilesystemBlobStore, MemoryBlobStore, PutOptions,
};
#[cfg(feature = "s3")]
use rs3_storage::{S3BlobStore, S3BlobStoreConfig};
use rs3_types::{LegalHoldStatus, LogicalPath, RetentionPolicy};
use secrecy::{ExposeSecret, SecretString};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

type RuntimeStore = DynBlobStore;
type RuntimeAnchor = DynCheckpointAnchor;
type RuntimeCommitCoordinator = CommitCoordinator<RuntimeStore, RuntimeAnchor>;

#[derive(Clone)]
pub(super) struct RuntimeRepository {
    coordinator: Arc<RuntimeCommitCoordinator>,
    #[cfg(feature = "s3")]
    s3_store: Option<S3BlobStore>,
    #[cfg(test)]
    memory_store: Option<MemoryBlobStore>,
    #[cfg(test)]
    memory_anchor: Option<MemoryCheckpointAnchor>,
}

impl RuntimeRepository {
    pub(super) async fn from_config(config: &RuntimeConfig) -> Result<Self, S3BoundaryError> {
        let store = build_store(&config.backend).await?;
        let anchor = build_anchor(&config.anchor)?;
        let repository = Arc::new(Repository::with_keyring_and_options(
            store.handle.clone(),
            gateway_keyring(&config.repository_keys)?,
            RepositoryOptions {
                payload_segment_size: config.repository.payload_segment_size,
                default_retention: config.repository.retention,
            },
        ));
        let coordinator = Arc::new(CommitCoordinator::with_options(
            repository,
            anchor.handle.clone(),
            coordinator_options(config.batching),
        ));

        Ok(Self {
            coordinator,
            #[cfg(feature = "s3")]
            s3_store: store.s3_store,
            #[cfg(test)]
            memory_store: store.memory_store,
            #[cfg(test)]
            memory_anchor: anchor.memory_anchor,
        })
    }

    pub(super) async fn load_accepted_checkpoint(&self) -> Result<(), S3BoundaryError> {
        let accepted = match self.coordinator.anchor().read().await {
            Ok(state) => CheckpointPosition::from(state),
            Err(AnchorError::MissingAnchor) => return Ok(()),
            Err(error) => return Err(repository_init(error)),
        };

        self.coordinator
            .repository()
            .load_checkpoint_position(&accepted)
            .await
            .map_err(repository_init)?;
        tracing::info!(
            target: "rs3_repository",
            checkpoint_sequence = accepted.sequence.get(),
            checkpoint_id = %accepted.checkpoint_id,
            "repository checkpoint loaded from external anchor",
        );
        Ok(())
    }

    pub(super) async fn validate_backend_retention(
        &self,
        retention: Option<RetentionPolicy>,
    ) -> Result<(), S3BoundaryError> {
        #[cfg(feature = "s3")]
        if let Some(store) = self.s3_store.as_ref() {
            return store
                .validate_retention_support(retention.as_ref())
                .await
                .map_err(repository_init);
        }

        let _ = retention;
        Ok(())
    }

    pub(super) async fn put_committed(
        &self,
        key: LogicalPath,
        body: Bytes,
        options: RepositoryPutOptions,
    ) -> Result<CommittedPut, RepositoryError> {
        self.coordinator.put_committed(key, body, options).await
    }

    pub(super) fn head(
        &self,
        key: &LogicalPath,
    ) -> Result<RepositoryObjectMetadata, RepositoryError> {
        self.coordinator.repository().head(key)
    }

    pub(super) async fn get_range(
        &self,
        key: &LogicalPath,
        range: ByteRange,
    ) -> Result<Bytes, RepositoryError> {
        self.coordinator.repository().get_range(key, range).await
    }

    pub(super) fn list(&self, prefix: &str) -> Result<Vec<RepositoryListEntry>, RepositoryError> {
        self.coordinator.repository().list(prefix)
    }

    pub(super) async fn delete_committed(
        &self,
        key: LogicalPath,
    ) -> Result<DeleteOutcome, RepositoryError> {
        self.coordinator.delete_committed(key).await
    }

    pub(super) async fn set_legal_hold_committed(
        &self,
        key: LogicalPath,
        status: LegalHoldStatus,
    ) -> Result<RepositoryObjectMetadata, RepositoryError> {
        self.coordinator.set_legal_hold_committed(key, status).await
    }

    #[cfg(test)]
    pub(super) fn memory_store(&self) -> Option<&MemoryBlobStore> {
        self.memory_store.as_ref()
    }

    #[cfg(test)]
    pub(super) fn memory_anchor(&self) -> Option<&MemoryCheckpointAnchor> {
        self.memory_anchor.as_ref()
    }
}

struct StoreBuild {
    handle: RuntimeStore,
    #[cfg(feature = "s3")]
    s3_store: Option<S3BlobStore>,
    #[cfg(test)]
    memory_store: Option<MemoryBlobStore>,
}

struct AnchorBuild {
    handle: RuntimeAnchor,
    #[cfg(test)]
    memory_anchor: Option<MemoryCheckpointAnchor>,
}

async fn build_store(config: &BackendConfig) -> Result<StoreBuild, S3BoundaryError> {
    if is_memory_backend(config) {
        let store = MemoryBlobStore::new();
        return Ok(StoreBuild {
            handle: RuntimeStore::new(store.clone()),
            #[cfg(feature = "s3")]
            s3_store: None,
            #[cfg(test)]
            memory_store: Some(store),
        });
    }

    if let Some(root) = filesystem_backend_root(config)? {
        let store = FilesystemBlobStore::new(root).map_err(repository_init)?;
        return Ok(StoreBuild {
            handle: RuntimeStore::new(store),
            #[cfg(feature = "s3")]
            s3_store: None,
            #[cfg(test)]
            memory_store: None,
        });
    }

    #[cfg(feature = "s3")]
    if let Some(store) = s3_backend_store(config).await? {
        return Ok(StoreBuild {
            handle: RuntimeStore::new(store.clone()),
            s3_store: Some(store),
            #[cfg(test)]
            memory_store: None,
        });
    }

    Err(S3BoundaryError::UnsupportedBackendMode)
}

fn is_memory_backend(config: &BackendConfig) -> bool {
    config.endpoint == "memory" || config.endpoint.starts_with("memory://")
}

fn filesystem_backend_root(config: &BackendConfig) -> Result<Option<PathBuf>, S3BoundaryError> {
    let Some(endpoint_path) = config.endpoint.strip_prefix("file://") else {
        return Ok(None);
    };
    if endpoint_path.is_empty() {
        return Err(repository_init("file backend endpoint must include a path"));
    }

    let mut root = PathBuf::from(endpoint_path);
    push_relative_component(&mut root, &config.bucket)?;
    if let Some(prefix) = config.prefix.as_deref() {
        push_relative_component(&mut root, prefix)?;
    }

    Ok(Some(root))
}

#[cfg(feature = "s3")]
async fn s3_backend_store(config: &BackendConfig) -> Result<Option<S3BlobStore>, S3BoundaryError> {
    let Some(store_config) = s3_backend_config(config)? else {
        return Ok(None);
    };

    S3BlobStore::from_environment(store_config)
        .await
        .map(Some)
        .map_err(repository_init)
}

#[cfg(feature = "s3")]
fn s3_backend_config(config: &BackendConfig) -> Result<Option<S3BlobStoreConfig>, S3BoundaryError> {
    let endpoint_url = match config.endpoint.as_str() {
        "s3" | "s3://" | "s3://aws" => None,
        endpoint if endpoint.starts_with("https://") || endpoint.starts_with("http://") => {
            Some(endpoint.to_owned())
        }
        _ => return Ok(None),
    };
    let allow_http = endpoint_url
        .as_deref()
        .is_some_and(|endpoint| endpoint.starts_with("http://"));
    let config = S3BlobStoreConfig::new(config.bucket.clone())
        .map_err(repository_init)?
        .with_prefix(config.prefix.clone())
        .with_endpoint_url(endpoint_url)
        .with_region(None)
        .with_allow_http(allow_http)
        .with_virtual_hosted_style(false);

    Ok(Some(config))
}

fn push_relative_component(root: &mut PathBuf, value: &str) -> Result<(), S3BoundaryError> {
    for component in Path::new(value).components() {
        match component {
            Component::Normal(component) => root.push(component),
            Component::CurDir => {}
            Component::RootDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(repository_init(
                    "file backend bucket and prefix must be relative paths",
                ));
            }
        }
    }
    Ok(())
}

fn build_anchor(config: &AnchorConfig) -> Result<AnchorBuild, S3BoundaryError> {
    match config {
        AnchorConfig::Memory => {
            let anchor = MemoryCheckpointAnchor::new();
            Ok(AnchorBuild {
                handle: RuntimeAnchor::new(anchor.clone()),
                #[cfg(test)]
                memory_anchor: Some(anchor),
            })
        }
        AnchorConfig::KubernetesLease {
            namespace,
            name,
            field_manager,
        } => {
            #[cfg(feature = "k8s")]
            {
                Ok(AnchorBuild {
                    handle: RuntimeAnchor::new(KubernetesLeaseAnchor::new(LeaseSettings {
                        namespace: namespace.clone(),
                        name: name.clone(),
                        field_manager: field_manager.clone(),
                    })),
                    #[cfg(test)]
                    memory_anchor: None,
                })
            }
            #[cfg(not(feature = "k8s"))]
            {
                let _ = (namespace, name, field_manager);
                Err(S3BoundaryError::UnsupportedAnchorMode)
            }
        }
    }
}

fn coordinator_options(config: BatchConfig) -> CommitCoordinatorOptions {
    CommitCoordinatorOptions::new(config.max_items, config.max_delay)
        .with_max_pending_items(config.max_pending_items)
}

#[derive(Clone)]
struct DynBlobStore {
    inner: Arc<dyn BlobStore>,
}

impl DynBlobStore {
    fn new(store: impl BlobStore + 'static) -> Self {
        Self {
            inner: Arc::new(store),
        }
    }
}

#[async_trait::async_trait]
impl BlobStore for DynBlobStore {
    async fn put(
        &self,
        object_id: &rs3_types::BackendObjectId,
        body: Bytes,
        options: PutOptions,
    ) -> rs3_storage::Result<BlobMetadata> {
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
        policy: rs3_types::RetentionPolicy,
    ) -> rs3_storage::Result<()> {
        self.inner.extend_retention(object_id, policy).await
    }

    async fn set_legal_hold(
        &self,
        object_id: &rs3_types::BackendObjectId,
        status: rs3_types::LegalHoldStatus,
    ) -> rs3_storage::Result<()> {
        self.inner.set_legal_hold(object_id, status).await
    }

    async fn flush_caches(&self) -> rs3_storage::Result<()> {
        self.inner.flush_caches().await
    }
}

#[derive(Clone)]
struct DynCheckpointAnchor {
    inner: Arc<dyn CheckpointAnchor>,
}

impl DynCheckpointAnchor {
    fn new(anchor: impl CheckpointAnchor + 'static) -> Self {
        Self {
            inner: Arc::new(anchor),
        }
    }
}

#[async_trait::async_trait]
impl CheckpointAnchor for DynCheckpointAnchor {
    async fn read(&self) -> rs3_anchor::Result<AnchorState> {
        self.inner.read().await
    }

    async fn compare_and_advance(&self, next: AnchorState) -> rs3_anchor::Result<AnchorState> {
        self.inner.compare_and_advance(next).await
    }
}

fn gateway_keyring(keys: &RepositoryKeysConfig) -> Result<KeyRing, S3BoundaryError> {
    let master_key = repository_master_key(&keys.master_key_hex)?;
    KeyRing::from_repository_master_key_for_repository(&master_key, &keys.repository_id)
        .map_err(repository_init)
}

fn repository_master_key(secret_hex: &SecretString) -> Result<SecretBytes, S3BoundaryError> {
    let bytes = hex::decode(secret_hex.expose_secret()).map_err(|error| {
        repository_init(format!(
            "{REPOSITORY_MASTER_KEY_HEX_ENV} must be hex-encoded repository key material: {error}",
        ))
    })?;
    SecretBytes::new(bytes).map_err(|error| {
        repository_init(format!(
            "{REPOSITORY_MASTER_KEY_HEX_ENV} is not usable: {error}",
        ))
    })
}

fn repository_init(error: impl ToString) -> S3BoundaryError {
    S3BoundaryError::RepositoryInit {
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::RuntimeRepository;
    #[cfg(feature = "s3")]
    use super::s3_backend_config;
    #[cfg(not(feature = "k8s"))]
    use crate::AnchorConfig;
    use crate::BatchConfig;
    use crate::s3::S3BoundaryError;
    use crate::s3::test_support::runtime_config;
    use bytes::Bytes;
    use rs3_repository::RepositoryPutOptions;
    use rs3_storage::BlobStore;
    use rs3_types::{LogicalPath, RetentionMode, RetentionPolicy};
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
        assert!(runtime.memory_anchor().is_some());
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

        let payloads = runtime
            .memory_store()
            .unwrap_or_else(|| panic!("missing memory store"))
            .list_prefix("segments/")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            payloads.first().and_then(|metadata| metadata.retention),
            Some(RetentionPolicy::new(RetentionMode::Compliance, 30))
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
        let payload_root = dir
            .path()
            .join("backend-bucket")
            .join("repo")
            .join("segments");

        assert_eq!(head.content_len, 16);
        assert!(payload_root.is_dir());
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
            name: "checkpoint".to_owned(),
            field_manager: "rs3-server".to_owned(),
        };

        let runtime = RuntimeRepository::from_config(&config).await;

        assert!(matches!(
            runtime,
            Err(S3BoundaryError::UnsupportedAnchorMode)
        ));
    }
}
