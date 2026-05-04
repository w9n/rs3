//! Runtime repository construction for the S3 service.

use super::S3BoundaryError;
use crate::config::{KEYRING_WRAPPING_KEY_HEX_ENV, REPOSITORY_SALT_HEX_ENV};
use crate::{AnchorConfig, BackendConfig, BatchConfig, RepositoryKeysConfig, RuntimeConfig};
use bytes::Bytes;
use rs3_anchor::{AnchorError, AnchorState, CheckpointAnchor, MemoryCheckpointAnchor};
use rs3_crypto::{
    KeyRing, KeyringEnvelope, RepositoryKeyContext, SecretBytes, derive_checkpoint_id,
    derive_checkpoint_payload_digest,
};
use rs3_index::{
    CHECKPOINT_OBJECT_DOMAIN, Checkpoint, KeyringEnvelopeReference, canonical_commit_record_bytes,
};
#[cfg(feature = "k8s")]
use rs3_k8s::{KubernetesLeaseAnchor, LeaseSettings};
use rs3_repository::{
    CheckpointPosition, CommitCoordinator, CommitCoordinatorOptions, CommittedPut, DeleteOutcome,
    Repository, RepositoryError, RepositoryListEntry, RepositoryObjectMetadata, RepositoryOptions,
    RepositoryPutOptions,
};
use rs3_storage::{
    BlobMetadata, BlobStore, ByteRange, FilesystemBlobStore, MemoryBlobStore, PutOptions,
    StorageError,
};
#[cfg(feature = "s3")]
use rs3_storage::{S3BlobStore, S3BlobStoreConfig};
use rs3_types::{BackendObjectId, LegalHoldStatus, LogicalPath, RetentionPolicy};
use secrecy::{ExposeSecret, SecretString};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

pub(super) type RuntimeStore = DynBlobStore;
pub(super) type RuntimeAnchor = DynCheckpointAnchor;
type RuntimeCommitCoordinator = CommitCoordinator<RuntimeStore, RuntimeAnchor>;
const KEYRING_ENVELOPE_OBJECT_CONTENT_TYPE: &str = "application/vnd.rs3.keyring-envelope+json";

#[derive(Clone)]
pub(super) struct RuntimeRepository {
    coordinator: Arc<RuntimeCommitCoordinator>,
    store: RuntimeStore,
    pending_envelope_override: Option<KeyringEnvelopeReference>,
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
        let loaded_keyring = gateway_keyring(
            &store.handle,
            &anchor.handle,
            &config.repository_keys,
            config.repository.retention,
        )
        .await?;
        let repository = Arc::new(Repository::with_keyring_and_options(
            store.handle.clone(),
            loaded_keyring.keyring,
            RepositoryOptions {
                payload_segment_size: config.repository.payload_segment_size,
                default_retention: config.repository.retention,
            },
        ));
        repository
            .set_keyring_envelope_reference(loaded_keyring.envelope_reference)
            .map_err(repository_init)?;
        let coordinator = Arc::new(CommitCoordinator::with_options(
            repository,
            anchor.handle.clone(),
            coordinator_options(config.batching),
        ));

        Ok(Self {
            coordinator,
            store: store.handle,
            pending_envelope_override: loaded_keyring.pending_envelope_override,
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
            Err(AnchorError::MissingAnchor) => {
                if repository_has_committed_objects(&self.store).await? {
                    return Err(repository_init(
                        "checkpoint anchor is missing but repository objects already exist; restore or repair the anchor before starting",
                    ));
                }
                return Ok(());
            }
            Err(error) => return Err(repository_init(error)),
        };

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

pub(super) struct StoreBuild {
    pub(super) handle: RuntimeStore,
    #[cfg(feature = "s3")]
    s3_store: Option<S3BlobStore>,
    #[cfg(test)]
    memory_store: Option<MemoryBlobStore>,
}

pub(super) struct AnchorBuild {
    pub(super) handle: RuntimeAnchor,
    #[cfg(test)]
    memory_anchor: Option<MemoryCheckpointAnchor>,
}

pub(super) async fn build_store(config: &BackendConfig) -> Result<StoreBuild, S3BoundaryError> {
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

pub(super) fn build_anchor(config: &AnchorConfig) -> Result<AnchorBuild, S3BoundaryError> {
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
pub(super) struct DynBlobStore {
    inner: Arc<dyn BlobStore>,
}

impl DynBlobStore {
    pub(super) fn new(store: impl BlobStore + 'static) -> Self {
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
pub(super) struct DynCheckpointAnchor {
    inner: Arc<dyn CheckpointAnchor>,
}

impl DynCheckpointAnchor {
    pub(super) fn new(anchor: impl CheckpointAnchor + 'static) -> Self {
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

async fn gateway_keyring(
    store: &RuntimeStore,
    anchor: &RuntimeAnchor,
    keys: &RepositoryKeysConfig,
    retention: Option<RetentionPolicy>,
) -> Result<LoadedGatewayKeyring, S3BoundaryError> {
    match anchor.read().await {
        Ok(state) => {
            let accepted = CheckpointPosition::from(state);
            let reference = checkpoint_keyring_envelope_reference(store, &accepted).await?;
            let mut loaded = open_gateway_keyring_reference(store, keys, &reference).await?;
            loaded.pending_envelope_override =
                configured_envelope_override(store, keys, &loaded.keyring, &reference).await?;
            Ok(loaded)
        }
        Err(AnchorError::MissingAnchor) => unanchored_gateway_keyring(store, keys, retention).await,
        Err(error) => Err(repository_init(error)),
    }
}

async fn unanchored_gateway_keyring(
    store: &RuntimeStore,
    keys: &RepositoryKeysConfig,
    retention: Option<RetentionPolicy>,
) -> Result<LoadedGatewayKeyring, S3BoundaryError> {
    if let Some(object_id) = keys.envelope_object_id.as_ref() {
        return match store.get_range(object_id, ByteRange::Full).await {
            Ok(body) => open_gateway_keyring_object(keys, object_id.clone(), body),
            Err(StorageError::NotFound(_)) => {
                bootstrap_missing_keyring_envelope(store, keys, Some(object_id.clone()), retention)
                    .await
            }
            Err(error) => Err(repository_init(error)),
        };
    }

    if repository_has_committed_objects(store).await? {
        return Err(repository_init(
            "checkpoint anchor is missing but repository objects already exist; run explicit anchor recovery instead of choosing a backend checkpoint",
        ));
    }

    let keyrings = store
        .list_prefix("keyrings/")
        .await
        .map_err(repository_init)?;
    match keyrings.as_slice() {
        [] => bootstrap_missing_keyring_envelope(store, keys, None, retention).await,
        [metadata] => {
            let body = store
                .get_range(&metadata.object_id, ByteRange::Full)
                .await
                .map_err(repository_init)?;
            open_gateway_keyring_object(keys, metadata.object_id.clone(), body)
        }
        _ => Err(repository_init(
            "checkpoint anchor is missing and multiple unanchored keyring envelopes exist; provide an explicit envelope override or recover the anchor",
        )),
    }
}

fn open_gateway_keyring(
    keys: &RepositoryKeysConfig,
    object_id: BackendObjectId,
    envelope: KeyringEnvelope,
) -> Result<LoadedGatewayKeyring, S3BoundaryError> {
    let context = repository_key_context(keys)?;
    let wrapping_key = secret_hex(KEYRING_WRAPPING_KEY_HEX_ENV, &keys.wrapping_key_hex)?;
    let keyring = envelope
        .open(&context, &keys.wrapping_key_id, &wrapping_key)
        .map_err(repository_init)?;
    let reference = KeyringEnvelopeReference {
        generation: envelope.generation,
        digest: envelope.digest().map_err(repository_init)?,
        object_id,
    };
    Ok(LoadedGatewayKeyring {
        keyring,
        envelope_reference: Some(reference),
        pending_envelope_override: None,
    })
}

fn open_gateway_keyring_object(
    keys: &RepositoryKeysConfig,
    object_id: BackendObjectId,
    body: Bytes,
) -> Result<LoadedGatewayKeyring, S3BoundaryError> {
    let envelope = KeyringEnvelope::from_object_bytes(&body).map_err(repository_init)?;
    open_gateway_keyring(keys, object_id, envelope)
}

pub(super) async fn open_gateway_keyring_reference(
    store: &RuntimeStore,
    keys: &RepositoryKeysConfig,
    reference: &KeyringEnvelopeReference,
) -> Result<LoadedGatewayKeyring, S3BoundaryError> {
    let body = store
        .get_range(&reference.object_id, ByteRange::Full)
        .await
        .map_err(repository_init)?;
    let envelope = KeyringEnvelope::from_object_bytes(&body).map_err(repository_init)?;
    let digest = envelope.digest().map_err(repository_init)?;
    if envelope.generation != reference.generation || digest != reference.digest {
        return Err(repository_init(format!(
            "keyring envelope object {} does not match the checkpoint-bound envelope reference",
            reference.object_id
        )));
    }
    open_gateway_keyring(keys, reference.object_id.clone(), envelope)
}

async fn configured_envelope_override(
    store: &RuntimeStore,
    keys: &RepositoryKeysConfig,
    active_keyring: &KeyRing,
    active_reference: &KeyringEnvelopeReference,
) -> Result<Option<KeyringEnvelopeReference>, S3BoundaryError> {
    let Some(object_id) = keys.envelope_object_id.as_ref() else {
        return Ok(None);
    };
    if object_id == &active_reference.object_id {
        return Ok(None);
    }

    let loaded = match store.get_range(object_id, ByteRange::Full).await {
        Ok(body) => open_gateway_keyring_object(keys, object_id.clone(), body)?,
        Err(StorageError::NotFound(_)) => {
            return Err(repository_init(
                "configured keyring envelope override is missing",
            ));
        }
        Err(error) => return Err(repository_init(error)),
    };
    if loaded.keyring.descriptors() != active_keyring.descriptors() {
        return Err(repository_init(
            "configured keyring envelope override opens to different repository keys",
        ));
    }

    Ok(loaded.envelope_reference)
}

async fn bootstrap_missing_keyring_envelope(
    store: &RuntimeStore,
    keys: &RepositoryKeysConfig,
    configured_object_id: Option<BackendObjectId>,
    retention: Option<RetentionPolicy>,
) -> Result<LoadedGatewayKeyring, S3BoundaryError> {
    if repository_prefix_has_objects(store).await? {
        return Err(repository_init(
            "keyring envelope is missing and repository prefix is not empty; refusing to initialize a new keyring",
        ));
    }

    let context = repository_key_context(keys)?;
    let wrapping_key = secret_hex(KEYRING_WRAPPING_KEY_HEX_ENV, &keys.wrapping_key_hex)?;
    let keyring = KeyRing::generate_random().map_err(repository_init)?;
    let envelope = keyring
        .seal_keyring_envelope(&context, &keys.wrapping_key_id, &wrapping_key, 1)
        .map_err(repository_init)?;
    let reference = if let Some(object_id) = configured_object_id {
        store_configured_keyring_envelope(store, &object_id, &envelope, retention).await?
    } else {
        let repository = Repository::with_keyring_and_options(
            store.clone(),
            keyring.clone(),
            RepositoryOptions {
                default_retention: retention,
                ..RepositoryOptions::default()
            },
        );
        repository
            .store_keyring_envelope(&envelope)
            .await
            .map_err(repository_init)?
    };

    tracing::info!(
        target: "rs3_repository",
        keyring_envelope_generation = reference.generation,
        "initialized keyring envelope in empty repository",
    );

    Ok(LoadedGatewayKeyring {
        keyring,
        envelope_reference: Some(reference),
        pending_envelope_override: None,
    })
}

async fn store_configured_keyring_envelope(
    store: &RuntimeStore,
    object_id: &BackendObjectId,
    envelope: &KeyringEnvelope,
    retention: Option<RetentionPolicy>,
) -> Result<KeyringEnvelopeReference, S3BoundaryError> {
    let digest = envelope.digest().map_err(repository_init)?;
    let body = Bytes::from(envelope.to_object_bytes().map_err(repository_init)?);
    let put = store
        .put(
            object_id,
            body.clone(),
            PutOptions {
                retention,
                legal_hold: None,
                content_type: Some(KEYRING_ENVELOPE_OBJECT_CONTENT_TYPE.to_owned()),
                do_not_recreate: true,
            },
        )
        .await;

    match put {
        Ok(_) => Ok(KeyringEnvelopeReference {
            generation: envelope.generation,
            digest,
            object_id: object_id.clone(),
        }),
        Err(StorageError::AlreadyExists(_)) => {
            let existing = store
                .get_range(object_id, ByteRange::Full)
                .await
                .map_err(repository_init)?;
            if existing != body {
                return Err(repository_init(format!(
                    "keyring envelope object conflicts with expected content: {object_id}",
                )));
            }
            Ok(KeyringEnvelopeReference {
                generation: envelope.generation,
                digest,
                object_id: object_id.clone(),
            })
        }
        Err(error) => Err(repository_init(error)),
    }
}

pub(super) async fn checkpoint_keyring_envelope_reference(
    store: &RuntimeStore,
    accepted: &CheckpointPosition,
) -> Result<KeyringEnvelopeReference, S3BoundaryError> {
    let checkpoint = read_checkpoint_for_position(store, accepted).await?;
    checkpoint.record.keyring_envelope.ok_or_else(|| {
        repository_init("anchor-bound checkpoint does not contain a keyring envelope reference")
    })
}

pub(super) async fn read_checkpoint_for_position(
    store: &RuntimeStore,
    accepted: &CheckpointPosition,
) -> Result<Checkpoint, S3BoundaryError> {
    let object_id = checkpoint_object_id(&accepted.checkpoint_id)?;
    let body = store
        .get_range(&object_id, ByteRange::Full)
        .await
        .map_err(repository_init)?;
    let Some(payload) = body.as_ref().strip_prefix(CHECKPOINT_OBJECT_DOMAIN) else {
        return Err(repository_init(format!(
            "invalid checkpoint object format: {object_id}"
        )));
    };
    let checkpoint: Checkpoint = serde_json::from_slice(payload).map_err(repository_init)?;
    let canonical_payload =
        canonical_commit_record_bytes(&checkpoint.record).map_err(repository_init)?;
    let payload_digest = derive_checkpoint_payload_digest(&canonical_payload);
    let expected_id =
        derive_checkpoint_id(&canonical_payload, &checkpoint.signature).map_err(repository_init)?;

    if checkpoint.record.sequence != accepted.sequence
        || checkpoint.id != accepted.checkpoint_id
        || expected_id != checkpoint.id
        || payload_digest != accepted.payload_digest
    {
        return Err(repository_init(
            "checkpoint object does not match the accepted anchor position",
        ));
    }

    Ok(checkpoint)
}

pub(super) fn checkpoint_object_id(
    checkpoint_id: &rs3_types::CheckpointId,
) -> Result<BackendObjectId, S3BoundaryError> {
    BackendObjectId::new(format!("checkpoints/{}", checkpoint_id.as_str())).map_err(repository_init)
}

async fn repository_has_committed_objects(store: &RuntimeStore) -> Result<bool, S3BoundaryError> {
    for prefix in ["checkpoints/", "evidence/", "index/", "segments/"] {
        if !store
            .list_prefix(prefix)
            .await
            .map_err(repository_init)?
            .is_empty()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn repository_prefix_has_objects(store: &RuntimeStore) -> Result<bool, S3BoundaryError> {
    Ok(!store
        .list_prefix("")
        .await
        .map_err(repository_init)?
        .is_empty())
}

pub(super) struct LoadedGatewayKeyring {
    pub(super) keyring: KeyRing,
    pub(super) envelope_reference: Option<KeyringEnvelopeReference>,
    pub(super) pending_envelope_override: Option<KeyringEnvelopeReference>,
}

fn repository_key_context(
    keys: &RepositoryKeysConfig,
) -> Result<RepositoryKeyContext, S3BoundaryError> {
    let salt = repository_salt(&keys.repository_salt_hex)?;
    RepositoryKeyContext::new(keys.repository_id.clone(), salt).map_err(repository_init)
}

fn secret_hex(
    env_name: &'static str,
    secret_hex: &SecretString,
) -> Result<SecretBytes, S3BoundaryError> {
    let bytes = hex::decode(secret_hex.expose_secret()).map_err(|error| {
        repository_init(format!(
            "{env_name} must be hex-encoded repository key material: {error}",
        ))
    })?;
    SecretBytes::new(bytes)
        .map_err(|error| repository_init(format!("{env_name} is not usable: {error}",)))
}

fn repository_salt(salt_hex: &str) -> Result<Vec<u8>, S3BoundaryError> {
    hex::decode(salt_hex).map_err(|error| {
        repository_init(format!(
            "{REPOSITORY_SALT_HEX_ENV} must be hex-encoded repository salt: {error}",
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
    #[cfg(feature = "s3")]
    use super::s3_backend_config;
    use super::{RuntimeAnchor, RuntimeRepository, RuntimeStore, gateway_keyring};
    #[cfg(not(feature = "k8s"))]
    use crate::AnchorConfig;
    use crate::s3::S3BoundaryError;
    use crate::s3::test_support::runtime_config;
    use crate::{BatchConfig, RepositoryKeysConfig};
    use bytes::Bytes;
    use rs3_anchor::{CheckpointAnchor, MemoryCheckpointAnchor};
    use rs3_crypto::{KeyRing, RepositoryKeyContext, SecretBytes};
    use rs3_index::{CHECKPOINT_OBJECT_DOMAIN, Checkpoint};
    use rs3_repository::RepositoryPutOptions;
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
        let opened = gateway_keyring(&store, &anchor, &keys, None)
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
