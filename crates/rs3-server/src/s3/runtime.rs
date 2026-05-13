//! Runtime repository construction for the S3 service.

use super::S3BoundaryError;
use crate::{GatewayMode, RuntimeConfig};
use bytes::Bytes;
#[cfg(test)]
use rs3_anchor::MemoryCheckpointAnchor;
use rs3_anchor::{AnchorError, CheckpointAnchor};
use rs3_index::KeyringEnvelopeReference;
use rs3_repository::{
    CheckpointPosition, CommitCoordinator, CommittedPut, DeleteOutcome, Repository,
    RepositoryError, RepositoryListEntry, RepositoryObjectMetadata, RepositoryOptions,
    RepositoryPutOptions,
};
use rs3_storage::ByteRange;
#[cfg(test)]
use rs3_storage::MemoryBlobStore;
#[cfg(feature = "s3")]
use rs3_storage::S3BlobStore;
use rs3_types::{LegalHoldStatus, LogicalPath, RetentionPolicy};
use std::sync::Arc;

use super::repository_init;
use super::runtime_builders::{build_anchor, build_store, coordinator_options};
use super::runtime_checkpoints::{repository_has_committed_objects, validate_storage_evidence};
use super::runtime_handles::{RuntimeAnchor, RuntimeStore};
use super::runtime_keyring::gateway_keyring;
use super::runtime_keyring::retained_version_required;

type RuntimeCommitCoordinator = CommitCoordinator<RuntimeStore, RuntimeAnchor>;

#[derive(Clone)]
pub(super) struct RuntimeRepository {
    coordinator: Arc<RuntimeCommitCoordinator>,
    store: RuntimeStore,
    pending_envelope_override: Option<KeyringEnvelopeReference>,
    require_anchor_checkpoint_version: bool,
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
        let store_handle = store.handle().clone();
        let anchor_handle = anchor.handle().clone();
        let loaded_keyring = gateway_keyring(
            &store_handle,
            &anchor_handle,
            &config.repository_keys,
            config.repository.retention,
            config.mode.allows_bootstrap(),
        )
        .await?;
        let repository = Arc::new(Repository::with_keyring_and_options(
            store_handle.clone(),
            loaded_keyring.keyring,
            RepositoryOptions {
                payload_segment_size: config.repository.payload_segment_size,
                adaptive_payload_segment_size: config.repository.adaptive_payload_segment_size,
                decrypted_segment_cache_max_bytes: config
                    .repository
                    .decrypted_segment_cache_max_bytes,
                default_retention: config.repository.retention,
            },
        ));
        repository
            .set_keyring_envelope_reference(loaded_keyring.envelope_reference)
            .map_err(repository_init)?;
        let coordinator = Arc::new(CommitCoordinator::with_options(
            repository,
            anchor_handle,
            coordinator_options(config.batching),
        ));
        #[cfg(feature = "s3")]
        let s3_store = store.s3_store().cloned();
        #[cfg(test)]
        let memory_store = store.memory_store().cloned();
        #[cfg(test)]
        let memory_anchor = anchor.memory_anchor().cloned();

        Ok(Self {
            coordinator,
            store: store_handle,
            pending_envelope_override: loaded_keyring.pending_envelope_override,
            require_anchor_checkpoint_version: retained_version_required(
                config.repository.retention,
                None,
            ),
            #[cfg(feature = "s3")]
            s3_store,
            #[cfg(test)]
            memory_store,
            #[cfg(test)]
            memory_anchor,
        })
    }

    pub(super) async fn load_accepted_checkpoint(
        &self,
        mode: GatewayMode,
    ) -> Result<(), S3BoundaryError> {
        let accepted = match self.coordinator.anchor().read().await {
            Ok(state) => CheckpointPosition::from(state),
            Err(AnchorError::MissingAnchor) => {
                if repository_has_committed_objects(&self.store).await? {
                    return Err(repository_init(
                        "checkpoint anchor is missing but repository objects already exist; restore or repair the anchor before starting",
                    ));
                }
                if mode.requires_anchor() {
                    return Err(repository_init(
                        "restore-readonly gateway mode requires an accepted checkpoint anchor; run explicit anchor recovery before serving restore",
                    ));
                }
                return Ok(());
            }
            Err(error) => return Err(repository_init(error)),
        };
        if self.require_anchor_checkpoint_version && accepted.checkpoint_version_id.is_none() {
            return Err(repository_init(
                "retained repository anchor is missing the checkpoint object version id",
            ));
        }

        validate_storage_evidence(&self.store, &accepted).await?;
        self.coordinator
            .repository()
            .load_checkpoint_position(&accepted)
            .await
            .map_err(repository_init)?;
        if let Some(reference) = self.pending_envelope_override.clone() {
            self.coordinator
                .repository()
                .set_keyring_envelope_reference(Some(reference.clone()))
                .map_err(repository_init)?;
            tracing::info!(
                target: "rs3_repository",
                keyring_envelope_generation = reference.generation,
                "validated configured keyring envelope override and staged it for the next checkpoint",
            );
        }
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

#[cfg(test)]
mod tests {
    #[cfg(feature = "s3")]
    use super::super::runtime_builders::s3_backend_config;
    use super::super::runtime_checkpoints::{checkpoint_evidence_object_id, checkpoint_object_id};
    use super::super::runtime_handles::{RuntimeAnchor, RuntimeStore};
    use super::super::runtime_keyring::gateway_keyring;
    use super::RuntimeRepository;
    #[cfg(not(feature = "k8s"))]
    use crate::AnchorConfig;
    use crate::s3::S3BoundaryError;
    use crate::s3::test_support::runtime_config;
    use crate::{BatchConfig, GatewayMode, RepositoryKeysConfig};
    use bytes::Bytes;
    use rs3_anchor::{CheckpointAnchor, MemoryCheckpointAnchor};
    use rs3_crypto::{KeyRing, RepositoryKeyContext, SecretBytes};
    use rs3_index::{
        CHECKPOINT_OBJECT_DOMAIN, Checkpoint, CheckpointEvidence, checkpoint_evidence_bytes,
    };
    use rs3_repository::RepositoryPutOptions;
    use rs3_storage::{BlobStore, ByteRange, FilesystemBlobStore, MemoryBlobStore, PutOptions};
    use rs3_types::{
        BackendObjectId, LogicalPath, RepositoryId, RetentionMode, RetentionPolicy, Sequence,
    };
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
        assert!(runtime.memory_anchor().is_some());
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
            BackendObjectId::new("segments/preexisting").unwrap_or_else(|error| panic!("{error}"));
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
    async fn startup_validation_rejects_missing_accepted_checkpoint_evidence() {
        let runtime = RuntimeRepository::from_config(&runtime_config(true))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let committed = runtime
            .put_committed(
                LogicalPath::new("snapshots/evidence-missing.bin")
                    .unwrap_or_else(|error| panic!("{error}")),
                Bytes::from_static(b"body"),
                RepositoryPutOptions::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let evidence_id = checkpoint_evidence_object_id(&committed.checkpoint)
            .unwrap_or_else(|error| panic!("{error}"));
        runtime
            .memory_store()
            .unwrap_or_else(|| panic!("missing memory store"))
            .delete(&evidence_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let loaded = runtime
            .load_accepted_checkpoint(GatewayMode::ReadWrite)
            .await;

        assert!(
            matches!(loaded, Err(S3BoundaryError::RepositoryInit { reason }) if reason.contains("evidence"))
        );
    }

    #[tokio::test]
    async fn startup_validation_rejects_evidence_newer_than_anchor() {
        let runtime = RuntimeRepository::from_config(&runtime_config(true))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let committed = runtime
            .put_committed(
                LogicalPath::new("snapshots/evidence-ahead.bin")
                    .unwrap_or_else(|error| panic!("{error}")),
                Bytes::from_static(b"body"),
                RepositoryPutOptions::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let future = rs3_repository::CheckpointPosition {
            sequence: Sequence::new(committed.checkpoint.sequence.get() + 1),
            checkpoint_id: committed.checkpoint.checkpoint_id.clone(),
            checkpoint_version_id: committed.checkpoint.checkpoint_version_id.clone(),
            payload_digest: committed.checkpoint.payload_digest.clone(),
        };
        let future_evidence_id =
            checkpoint_evidence_object_id(&future).unwrap_or_else(|error| panic!("{error}"));
        let future_evidence = checkpoint_evidence_bytes(&CheckpointEvidence {
            sequence: future.sequence,
            checkpoint_id: future.checkpoint_id.clone(),
            checkpoint_digest: future.payload_digest.clone(),
            checkpoint_object_id: checkpoint_object_id(&future.checkpoint_id)
                .unwrap_or_else(|error| panic!("{error}")),
            checkpoint_object_version_id: future.checkpoint_version_id.clone(),
        })
        .unwrap_or_else(|error| panic!("{error}"));
        runtime
            .memory_store()
            .unwrap_or_else(|| panic!("missing memory store"))
            .put(
                &future_evidence_id,
                Bytes::from(future_evidence),
                PutOptions {
                    retention: None,
                    legal_hold: None,
                    content_type: None,
                    do_not_recreate: true,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let loaded = runtime
            .load_accepted_checkpoint(GatewayMode::ReadWrite)
            .await;

        assert!(
            matches!(loaded, Err(S3BoundaryError::RepositoryInit { reason }) if reason.contains("newer than the accepted anchor"))
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

        let anchor = RuntimeAnchor::new(MemoryCheckpointAnchor::new());
        let opened = gateway_keyring(&store, &anchor, &keys, None, true)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(opened.keyring.descriptors(), keyring.descriptors());
        assert_eq!(
            opened
                .keyring
                .derive_backend_object_id("segments", b"same")
                .unwrap_or_else(|error| panic!("{error}")),
            keyring
                .derive_backend_object_id("segments", b"same")
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
    async fn runtime_keyring_uses_anchor_checkpoint_envelope_without_configured_object_id() {
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
        let memory = MemoryBlobStore::new();
        let repo = rs3_repository::Repository::with_keyring(memory.clone(), keyring.clone());
        let reference = repo
            .store_keyring_envelope(&envelope)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let anchor = MemoryCheckpointAnchor::new();
        repo.put_committed(
            LogicalPath::new("snapshots/anchored.bin").unwrap_or_else(|error| panic!("{error}")),
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
            &anchor,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let accepted = anchor
            .read()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let store = RuntimeStore::new(memory);
        let keys = RepositoryKeysConfig {
            repository_id,
            repository_salt_hex: "0202020202020202020202020202020202020202020202020202020202020202"
                .to_owned(),
            envelope_object_id: None,
            wrapping_key_id: "wrap-v1".to_owned(),
            wrapping_key_hex: SecretString::from(
                "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            ),
        };

        let opened = gateway_keyring(
            &store,
            &RuntimeAnchor::new(MemoryCheckpointAnchor::with_state(accepted)),
            &keys,
            None,
            true,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(opened.keyring.descriptors(), keyring.descriptors());
        assert_eq!(opened.envelope_reference, Some(reference));
    }

    #[tokio::test]
    async fn runtime_checkpoints_bind_configured_keyring_envelope() {
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
            .memory_anchor()
            .unwrap_or_else(|| panic!("missing memory anchor"))
            .read()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let checkpoint_object_id =
            BackendObjectId::new(format!("checkpoints/{}", accepted.checkpoint_id.as_str()))
                .unwrap_or_else(|error| panic!("{error}"));
        let body = store
            .get_range(&checkpoint_object_id, ByteRange::Full)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = body
            .strip_prefix(CHECKPOINT_OBJECT_DOMAIN)
            .unwrap_or_else(|| panic!("checkpoint object missing domain"));
        let checkpoint: Checkpoint =
            serde_json::from_slice(payload).unwrap_or_else(|error| panic!("{error}"));
        let reference = checkpoint
            .record
            .keyring_envelope
            .unwrap_or_else(|| panic!("missing keyring envelope reference"));

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
