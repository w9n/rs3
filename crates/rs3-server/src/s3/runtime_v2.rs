//! Runtime repository construction for preview v2 format roots and commits.

use super::S3BoundaryError;
use super::repository_init;
use super::runtime_builders::{build_store, build_v2_anchor, coordinator_options};
use super::runtime_handles::{RuntimeStore, RuntimeV2Anchor};
use super::runtime_keyring::{
    open_gateway_keyring_reference, repository_key_context, retained_version_id,
    retained_version_required, secret_hex, unanchored_gateway_keyring,
};
use crate::config::KEYRING_WRAPPING_KEY_HEX_ENV;
use crate::{BackendConfig, GatewayMode, RepositoryFormat, RepositoryKeysConfig, RuntimeConfig};
use bytes::Bytes;
use futures_util::Stream;
use rs3_crypto::{FormatEnvelope, KeyRing};
use rs3_index::KeyringEnvelopeReference;
use rs3_repository::v2::{
    V2AnchorState, V2CommitAnchor, V2CommitCoordinator, V2CommitStore, V2CommitStoreOptions,
    V2FormatRef, V2FormatRoot, V2KeyringEnvelopeRootRef, V2ProviderConformanceOptions,
    V2ProviderConformanceReport, V2ProviderProfile, V2RecoveryBundle, V2Repository,
    check_v2_provider_conformance, v2_format_object_id,
};
use rs3_repository::{
    DeleteOutcome, RepositoryError, RepositoryListEntry, RepositoryObjectMetadata,
    RepositoryOptions, RepositoryPutOptions,
};
#[cfg(test)]
use rs3_storage::MemoryBlobStore;
#[cfg(feature = "s3")]
use rs3_storage::S3BlobStore;
use rs3_storage::{BlobMetadata, BlobStore, ByteRange, PutOptions, StorageError};
use rs3_types::{
    BackendObjectId, KeyPurpose, LegalHoldStatus, LogicalPath, RetentionMode, RetentionPolicy,
    Sequence,
};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const V2_FORMAT_ENVELOPE_CONTENT_TYPE: &str = "application/vnd.rs3.v2-format-envelope+json";
/// Schema marker printed with trusted v2 recovery bundles.
pub const V2_RESTORE_BUNDLE_SCHEMA: &str = "rs3.restore-bundle.v2-preview.v1";

/// Result of importing a trusted v2 anchor bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2AnchorImportReport {
    /// Verified anchor state named by the trusted bundle.
    pub anchor: V2AnchorState,
    /// True when this call recreated a missing anchor.
    pub applied: bool,
    /// Number of commits verified from the imported anchor to the nearest snapshot.
    pub verified_commit_count: usize,
}

/// Operator-provided options for v2 anchor import.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2AnchorImportOptions {
    /// External weak-subjectivity floor that the imported anchor must satisfy.
    pub min_sequence: Sequence,
}

/// Runtime options for v2 provider conformance probes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuntimeV2ProviderConformanceOptions {
    /// Opaque probe object prefix. If absent, a run-specific prefix is used.
    pub probe_prefix: Option<String>,
    /// Whether legal-hold add/verify probes should run.
    pub legal_hold: bool,
    /// Whether an operator has reviewed governance-retention bypass permissions.
    pub governance_bypass_reviewed: bool,
}

pub(super) struct RuntimeV2Repository {
    repository: Arc<V2Repository<RuntimeStore>>,
    coordinator: Arc<V2CommitCoordinator<RuntimeStore, RuntimeV2Anchor>>,
    anchor: RuntimeV2Anchor,
    require_anchor_version: bool,
    #[cfg(feature = "s3")]
    s3_store: Option<S3BlobStore>,
    #[cfg(test)]
    memory_store: Option<MemoryBlobStore>,
    #[cfg(test)]
    memory_anchor: Option<rs3_repository::v2::V2MemoryAnchor>,
}

struct LoadedV2Repository {
    keyring: KeyRing,
    keyring_ref: V2KeyringEnvelopeRootRef,
    format_ref: V2FormatRef,
    anchor_present: bool,
}

impl RuntimeV2Repository {
    pub(super) async fn from_config(config: &RuntimeConfig) -> Result<Self, S3BoundaryError> {
        let store = build_store(&config.backend).await?;
        let anchor = build_v2_anchor(&config.anchor)?;
        let store_handle = store.handle().clone();
        let anchor_handle = anchor.handle().clone();
        let provider_profile = v2_provider_profile(&config.backend, config.repository.retention);
        let loaded = load_or_bootstrap_v2_repository(
            &store_handle,
            &anchor_handle,
            config,
            provider_profile,
        )
        .await?;
        let commit_ref = loaded.keyring_ref.commit_ref().map_err(repository_init)?;
        let commit_options =
            V2CommitStoreOptions::for_profile(provider_profile, commit_ref, loaded.format_ref)
                .with_retention(config.repository.retention)
                .with_stream_read_stall_timeout(config.hardening.stream_read_stall_timeout);
        let repository = Arc::new(V2Repository::new(
            store_handle.clone(),
            loaded.keyring,
            RepositoryOptions {
                payload_segment_size: config.repository.payload_segment_size,
                adaptive_payload_segment_size: config.repository.adaptive_payload_segment_size,
                decrypted_segment_cache_max_bytes: config
                    .repository
                    .decrypted_segment_cache_max_bytes,
                default_retention: config.repository.retention,
            },
            commit_options,
        ));

        if loaded.anchor_present {
            repository
                .load_chain_from_anchor(&anchor_handle)
                .await
                .map_err(repository_init)?;
        } else {
            repository
                .write_genesis_snapshot(&anchor_handle)
                .await
                .map_err(repository_init)?;
        }
        let coordinator = Arc::new(V2CommitCoordinator::with_options(
            Arc::clone(&repository),
            anchor_handle.clone(),
            coordinator_options(config.batching),
        ));

        #[cfg(feature = "s3")]
        let s3_store = store.s3_store().cloned();
        #[cfg(test)]
        let memory_store = store.memory_store().cloned();
        #[cfg(test)]
        let memory_anchor = anchor.memory_anchor().cloned();

        Ok(Self {
            repository,
            coordinator,
            anchor: anchor_handle,
            require_anchor_version: retained_version_required(config.repository.retention, None),
            #[cfg(feature = "s3")]
            s3_store,
            #[cfg(test)]
            memory_store,
            #[cfg(test)]
            memory_anchor,
        })
    }

    pub(super) async fn load_accepted_anchor(
        &self,
        _mode: GatewayMode,
    ) -> Result<(), S3BoundaryError> {
        let Some(anchor_state) = self.anchor.read_v2().await.map_err(repository_init)? else {
            return Err(repository_init("v2-preview repository anchor is missing"));
        };
        if self.require_anchor_version && anchor_state.version_id.is_none() {
            return Err(repository_init(
                "retained v2 repository anchor is missing the commit object version id",
            ));
        }
        let chain = self
            .repository
            .commit_store()
            .load_chain_from_state(&anchor_state)
            .await
            .map_err(repository_init)?;
        self.repository
            .replay_chain(&chain)
            .map_err(repository_init)?;
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
    ) -> Result<RepositoryObjectMetadata, RepositoryError> {
        self.coordinator
            .put_committed(key, body, options)
            .await
            .map(|committed| committed.metadata)
    }

    pub(super) fn supports_streaming_put(&self) -> bool {
        self.repository
            .commit_store()
            .store()
            .supports_multipart_upload()
    }

    pub(super) async fn put_committed_streaming_known_len<St>(
        &self,
        key: LogicalPath,
        plaintext_len: u64,
        stream: St,
        options: RepositoryPutOptions,
        multipart_part_size: usize,
    ) -> Result<RepositoryObjectMetadata, RepositoryError>
    where
        St: Stream<Item = Result<Bytes, RepositoryError>> + Unpin + Send,
    {
        self.coordinator
            .put_committed_streaming_known_len(
                key,
                plaintext_len,
                stream,
                options,
                multipart_part_size,
            )
            .await
            .map(|committed| committed.metadata)
    }

    pub(super) async fn put_committed_streaming_unknown_len<St>(
        &self,
        key: LogicalPath,
        stream: St,
        options: RepositoryPutOptions,
        multipart_part_size: usize,
        max_plaintext_len: u64,
    ) -> Result<RepositoryObjectMetadata, RepositoryError>
    where
        St: Stream<Item = Result<Bytes, RepositoryError>> + Unpin + Send,
    {
        self.coordinator
            .put_committed_streaming_unknown_len(
                key,
                stream,
                options,
                multipart_part_size,
                max_plaintext_len,
            )
            .await
            .map(|committed| committed.metadata)
    }

    pub(super) fn head(
        &self,
        key: &LogicalPath,
    ) -> Result<RepositoryObjectMetadata, RepositoryError> {
        self.repository.head(key)
    }

    pub(super) async fn get_range(
        &self,
        key: &LogicalPath,
        range: ByteRange,
    ) -> Result<Bytes, RepositoryError> {
        self.repository.get_range(key, range).await
    }

    pub(super) fn list(&self, prefix: &str) -> Result<Vec<RepositoryListEntry>, RepositoryError> {
        self.repository.list(prefix)
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
    pub(super) fn memory_anchor(&self) -> Option<&rs3_repository::v2::V2MemoryAnchor> {
        self.memory_anchor.as_ref()
    }
}

pub(crate) async fn v2_quick_maintenance_from_config(
    config: &RuntimeConfig,
) -> Result<rs3_repository::v2::V2MaintenanceReport, S3BoundaryError> {
    if config.repository.format != RepositoryFormat::V2Preview {
        return Err(repository_init(
            "v2 maintenance requires RS3_REPOSITORY_FORMAT=v2-preview",
        ));
    }
    let store = build_store(&config.backend).await?;
    let anchor = build_v2_anchor(&config.anchor)?;
    let anchor_handle = anchor.handle().clone();
    let Some(anchor_state) = anchor_handle.read_v2().await.map_err(repository_init)? else {
        return Err(repository_init(
            "v2-preview maintenance requires an accepted anchor",
        ));
    };
    let provider_profile = v2_provider_profile(&config.backend, config.repository.retention);
    let loaded = load_existing_v2_repository(
        store.handle(),
        &config.repository_keys,
        &anchor_state,
        config,
    )
    .await?;
    let commit_ref = loaded.keyring_ref.commit_ref().map_err(repository_init)?;
    let commit_options =
        V2CommitStoreOptions::for_profile(provider_profile, commit_ref, loaded.format_ref)
            .with_retention(config.repository.retention);
    let commit_store = V2CommitStore::new(store.into_handle(), loaded.keyring, commit_options);
    commit_store
        .quick_maintenance(&anchor_handle)
        .await
        .map_err(repository_init)
}

/// Exports a trusted v2 recovery bundle after verifying the anchor-selected chain.
pub async fn export_v2_recovery_bundle_from_config(
    config: &RuntimeConfig,
) -> Result<V2RecoveryBundle, S3BoundaryError> {
    if config.repository.format != RepositoryFormat::V2Preview {
        return Err(repository_init(
            "v2 recovery bundle export requires RS3_REPOSITORY_FORMAT=v2-preview",
        ));
    }
    let store = build_store(&config.backend).await?;
    let anchor = build_v2_anchor(&config.anchor)?;
    let anchor_handle = anchor.handle().clone();
    let Some(anchor_state) = anchor_handle.read_v2().await.map_err(repository_init)? else {
        return Err(repository_init(
            "v2-preview recovery bundle export requires an accepted anchor",
        ));
    };
    let provider_profile = v2_provider_profile(&config.backend, config.repository.retention);
    let loaded = load_existing_v2_repository(
        store.handle(),
        &config.repository_keys,
        &anchor_state,
        config,
    )
    .await?;
    let commit_ref = loaded.keyring_ref.commit_ref().map_err(repository_init)?;
    let commit_options =
        V2CommitStoreOptions::for_profile(provider_profile, commit_ref, loaded.format_ref)
            .with_retention(config.repository.retention);
    let commit_store = V2CommitStore::new(store.into_handle(), loaded.keyring, commit_options);
    commit_store
        .load_chain_from_state(&anchor_state)
        .await
        .map_err(repository_init)?;

    let mut bundle = V2RecoveryBundle::from_anchor(anchor_state.clone(), anchor_state.sequence);
    bundle.repository_id = Some(config.repository_keys.repository_id.clone());
    Ok(bundle)
}

/// Writes a full v2 index snapshot from the configured repository state.
pub async fn write_v2_index_snapshot_from_config(
    config: &RuntimeConfig,
) -> Result<V2AnchorState, S3BoundaryError> {
    if config.repository.format != RepositoryFormat::V2Preview {
        return Err(repository_init(
            "v2 index snapshots require RS3_REPOSITORY_FORMAT=v2-preview",
        ));
    }
    if config.mode == GatewayMode::RestoreReadOnly {
        return Err(repository_init(
            "restore-readonly gateway mode cannot write a v2 index snapshot",
        ));
    }
    let repository = RuntimeV2Repository::from_config(config).await?;
    repository
        .validate_backend_retention(config.repository.retention)
        .await?;
    repository
        .coordinator
        .write_index_snapshot()
        .await
        .map_err(repository_init)
}

/// Imports a trusted v2 recovery bundle when the configured anchor is missing.
pub async fn import_v2_anchor_from_config(
    config: &RuntimeConfig,
    bundle: V2RecoveryBundle,
    options: V2AnchorImportOptions,
) -> Result<V2AnchorImportReport, S3BoundaryError> {
    if config.repository.format != RepositoryFormat::V2Preview {
        return Err(repository_init(
            "v2 anchor import requires RS3_REPOSITORY_FORMAT=v2-preview",
        ));
    }
    let store = build_store(&config.backend).await?;
    let anchor = build_v2_anchor(&config.anchor)?;
    let anchor_handle = anchor.handle().clone();
    let provider_profile = v2_provider_profile(&config.backend, config.repository.retention);
    verify_recovery_bundle_trust(
        &bundle,
        provider_profile,
        options.min_sequence,
        config.recovery.public_key.as_deref(),
    )?;
    let loaded = load_existing_v2_repository(
        store.handle(),
        &config.repository_keys,
        &bundle.anchor,
        config,
    )
    .await?;
    let commit_ref = loaded.keyring_ref.commit_ref().map_err(repository_init)?;
    let commit_options =
        V2CommitStoreOptions::for_profile(provider_profile, commit_ref, loaded.format_ref)
            .with_retention(config.repository.retention);
    let commit_store = V2CommitStore::new(store.into_handle(), loaded.keyring, commit_options);

    if let Some(current) = anchor_handle.read_v2().await.map_err(repository_init)? {
        if current != bundle.anchor {
            return Err(repository_init(
                "configured v2 anchor already exists and differs from the trusted bundle",
            ));
        }
        let chain = commit_store
            .load_chain_from_state(&current)
            .await
            .map_err(repository_init)?;
        return Ok(V2AnchorImportReport {
            anchor: current,
            applied: false,
            verified_commit_count: chain.commits_newest_first.len(),
        });
    }

    let chain = commit_store
        .recreate_anchor_from_recovery_bundle(&anchor_handle, &bundle, options.min_sequence)
        .await
        .map_err(repository_init)?;
    Ok(V2AnchorImportReport {
        anchor: bundle.anchor,
        applied: true,
        verified_commit_count: chain.commits_newest_first.len(),
    })
}

fn verify_recovery_bundle_trust(
    bundle: &V2RecoveryBundle,
    provider_profile: V2ProviderProfile,
    min_sequence: Sequence,
    recovery_public_key: Option<&str>,
) -> Result<(), S3BoundaryError> {
    if bundle.anchor.sequence < min_sequence {
        return Err(repository_init(
            "trusted v2 restore bundle anchor sequence is below --min-sequence",
        ));
    }

    if provider_profile != V2ProviderProfile::Dev && bundle.offline_signature.is_none() {
        return Err(repository_init(
            "production v2 anchor import requires an offline bundle signature",
        ));
    }

    match recovery_public_key {
        Some(public_key) => bundle
            .verify_offline_signature(public_key)
            .map_err(repository_init),
        None if provider_profile == V2ProviderProfile::Dev => Ok(()),
        None => Err(repository_init(
            "production v2 anchor import requires RS3_RECOVERY_PUBLIC_KEY",
        )),
    }?;

    Ok(())
}

/// Runs v2 provider conformance checks for the configured backend/profile.
pub async fn check_v2_provider_conformance_from_config(
    config: &RuntimeConfig,
    options: RuntimeV2ProviderConformanceOptions,
) -> Result<V2ProviderConformanceReport, S3BoundaryError> {
    if config.repository.format != RepositoryFormat::V2Preview {
        return Err(repository_init(
            "v2 provider conformance requires RS3_REPOSITORY_FORMAT=v2-preview",
        ));
    }
    let store = build_store(&config.backend).await?;
    let profile = v2_provider_profile(&config.backend, config.repository.retention);
    let mut conformance = V2ProviderConformanceOptions::new(
        profile,
        options
            .probe_prefix
            .unwrap_or_else(default_v2_provider_probe_prefix),
    )
    .with_legal_hold(options.legal_hold)
    .with_governance_bypass_reviewed(options.governance_bypass_reviewed);
    if let Some(retention) = config.repository.retention {
        conformance = conformance.with_retention(retention);
    }
    check_v2_provider_conformance(store.handle(), &conformance)
        .await
        .map_err(repository_init)
}

async fn load_or_bootstrap_v2_repository(
    store: &RuntimeStore,
    anchor: &RuntimeV2Anchor,
    config: &RuntimeConfig,
    provider_profile: V2ProviderProfile,
) -> Result<LoadedV2Repository, S3BoundaryError> {
    match anchor.read_v2().await.map_err(repository_init)? {
        Some(anchor_state) => {
            load_existing_v2_repository(store, &config.repository_keys, &anchor_state, config).await
        }
        None => {
            bootstrap_v2_repository(store, &config.repository_keys, config, provider_profile).await
        }
    }
}

async fn bootstrap_v2_repository(
    store: &RuntimeStore,
    keys: &RepositoryKeysConfig,
    config: &RuntimeConfig,
    provider_profile: V2ProviderProfile,
) -> Result<LoadedV2Repository, S3BoundaryError> {
    if config.mode.requires_anchor() {
        return Err(repository_init(
            "restore-readonly gateway mode requires an accepted v2 commit anchor; run explicit anchor recovery before serving restore",
        ));
    }
    if !config.repository.allow_init {
        return Err(repository_init(
            "v2 repository initialization requires RS3_ALLOW_REPOSITORY_INIT=true; use explicit anchor recovery for existing repositories",
        ));
    }

    let loaded_keyring =
        unanchored_gateway_keyring(store, keys, config.repository.retention, true).await?;
    reject_v2_bootstrap_with_foreign_objects(
        store,
        loaded_keyring
            .envelope_reference
            .as_ref()
            .map(|reference| &reference.object_id),
    )
    .await?;

    let keyring_ref =
        v2_keyring_root_ref(loaded_keyring.envelope_reference.as_ref().ok_or_else(|| {
            repository_init("v2 bootstrap requires a keyring envelope reference")
        })?);
    let signing_key_id = loaded_keyring
        .keyring
        .primary_key_id(KeyPurpose::CheckpointSigning)
        .map_err(repository_init)?;
    let format_root = V2FormatRoot::new(
        keys.repository_id.clone(),
        keyring_ref.clone(),
        signing_key_id,
        provider_profile,
        config.repository.retention,
    );
    let format_ref =
        store_format_root(store, keys, &format_root, config.repository.retention).await?;

    tracing::info!(
        target: "rs3_repository",
        repository_format = "v2-preview",
        format_generation = format_ref.generation,
        "initialized v2 format root in empty repository",
    );

    Ok(LoadedV2Repository {
        keyring: loaded_keyring.keyring,
        keyring_ref,
        format_ref,
        anchor_present: false,
    })
}

async fn load_existing_v2_repository(
    store: &RuntimeStore,
    keys: &RepositoryKeysConfig,
    anchor_state: &V2AnchorState,
    config: &RuntimeConfig,
) -> Result<LoadedV2Repository, S3BoundaryError> {
    let format_root = open_format_root(store, keys, &anchor_state.format_ref).await?;
    if format_root.repository_id != keys.repository_id
        || format_root.provider_profile
            != v2_provider_profile(&config.backend, config.repository.retention)
        || format_root.retention != config.repository.retention
        || format_root.signing_key_id != anchor_state.signing_key_id
    {
        return Err(repository_init(
            "v2 format root does not match the configured repository context",
        ));
    }

    let keyring_reference = keyring_reference_from_v2(&format_root.active_keyring_envelope_ref);
    let loaded_keyring = open_gateway_keyring_reference(store, keys, &keyring_reference).await?;
    Ok(LoadedV2Repository {
        keyring: loaded_keyring.keyring,
        keyring_ref: format_root.active_keyring_envelope_ref,
        format_ref: anchor_state.format_ref.clone(),
        anchor_present: true,
    })
}

async fn store_format_root(
    store: &RuntimeStore,
    keys: &RepositoryKeysConfig,
    root: &V2FormatRoot,
    retention: Option<RetentionPolicy>,
) -> Result<V2FormatRef, S3BoundaryError> {
    let context = repository_key_context(keys)?;
    let wrapping_key = secret_hex(KEYRING_WRAPPING_KEY_HEX_ENV, &keys.wrapping_key_hex)?;
    let plaintext = root.to_plaintext_bytes().map_err(repository_init)?;
    let envelope = FormatEnvelope::seal(
        &context,
        &keys.wrapping_key_id,
        &wrapping_key,
        1,
        &plaintext,
    )
    .map_err(repository_init)?;
    let digest = envelope.digest().map_err(repository_init)?;
    let object_id = v2_format_object_id(envelope.generation, &digest).map_err(repository_init)?;
    let body = Bytes::from(envelope.to_object_bytes().map_err(repository_init)?);
    let metadata = put_format_envelope(store, &object_id, body, retention).await?;
    let version_id =
        retained_version_id(&object_id, &metadata, retention, None).map_err(repository_init)?;

    Ok(V2FormatRef {
        generation: envelope.generation,
        digest,
        object_id,
        version_id,
    })
}

async fn put_format_envelope(
    store: &RuntimeStore,
    object_id: &BackendObjectId,
    body: Bytes,
    retention: Option<RetentionPolicy>,
) -> Result<BlobMetadata, S3BoundaryError> {
    let put = store
        .put(
            object_id,
            body.clone(),
            PutOptions {
                retention,
                legal_hold: None,
                content_type: Some(V2_FORMAT_ENVELOPE_CONTENT_TYPE.to_owned()),
                do_not_recreate: !retained_version_required(retention, None),
            },
        )
        .await;
    match put {
        Ok(metadata) => Ok(metadata),
        Err(StorageError::AlreadyExists(_)) => {
            let metadata = store.head(object_id).await.map_err(repository_init)?;
            let existing = store
                .get_range_at(object_id, metadata.version_id.as_ref(), ByteRange::Full)
                .await
                .map_err(repository_init)?;
            if existing != body {
                return Err(repository_init(
                    "v2 format root object conflicts with expected content",
                ));
            }
            Ok(metadata)
        }
        Err(error) => Err(repository_init(error)),
    }
}

async fn open_format_root(
    store: &RuntimeStore,
    keys: &RepositoryKeysConfig,
    reference: &V2FormatRef,
) -> Result<V2FormatRoot, S3BoundaryError> {
    let body = store
        .get_range_at(
            &reference.object_id,
            reference.version_id.as_ref(),
            ByteRange::Full,
        )
        .await
        .map_err(repository_init)?;
    let envelope = FormatEnvelope::from_object_bytes(&body).map_err(repository_init)?;
    if envelope.generation != reference.generation
        || envelope.digest().map_err(repository_init)? != reference.digest
    {
        return Err(repository_init(
            "v2 format root object does not match the anchor-bound reference",
        ));
    }
    let context = repository_key_context(keys)?;
    let wrapping_key = secret_hex(KEYRING_WRAPPING_KEY_HEX_ENV, &keys.wrapping_key_hex)?;
    let plaintext = envelope
        .open(&context, &keys.wrapping_key_id, &wrapping_key)
        .map_err(repository_init)?;
    V2FormatRoot::from_plaintext_bytes(&plaintext).map_err(repository_init)
}

async fn reject_v2_bootstrap_with_foreign_objects(
    store: &RuntimeStore,
    allowed_keyring: Option<&BackendObjectId>,
) -> Result<(), S3BoundaryError> {
    const BOOTSTRAP_EMPTY_CHECK_PREFIXES: &[&str] =
        &["", "format/", "commits/", "keyrings/", "checkpoints/"];

    for prefix in BOOTSTRAP_EMPTY_CHECK_PREFIXES {
        let objects = store.list_prefix(prefix).await.map_err(repository_init)?;
        let has_foreign_object = objects
            .iter()
            .any(|metadata| Some(&metadata.object_id) != allowed_keyring);
        if has_foreign_object {
            return Err(repository_init(
                "v2-preview bootstrap requires an empty repository prefix except for the configured keyring envelope",
            ));
        }
    }
    Ok(())
}

fn v2_keyring_root_ref(reference: &KeyringEnvelopeReference) -> V2KeyringEnvelopeRootRef {
    V2KeyringEnvelopeRootRef {
        generation: reference.generation,
        digest: reference.digest.clone(),
        object_id: reference.object_id.clone(),
        version_id: reference.version_id.clone(),
    }
}

fn keyring_reference_from_v2(reference: &V2KeyringEnvelopeRootRef) -> KeyringEnvelopeReference {
    KeyringEnvelopeReference {
        generation: reference.generation,
        digest: reference.digest.clone(),
        object_id: reference.object_id.clone(),
        version_id: reference.version_id.clone(),
    }
}

fn v2_provider_profile(
    backend: &BackendConfig,
    retention: Option<RetentionPolicy>,
) -> V2ProviderProfile {
    if retention.is_some_and(|policy| policy.mode != RetentionMode::None && policy.retain_days > 0)
    {
        V2ProviderProfile::RetainedVersionObjectLock
    } else if is_s3_backend(backend) {
        V2ProviderProfile::AtomicCreate
    } else {
        V2ProviderProfile::Dev
    }
}

fn is_s3_backend(config: &BackendConfig) -> bool {
    matches!(config.endpoint.as_str(), "s3" | "s3://" | "s3://aws")
        || config.endpoint.starts_with("https://")
        || config.endpoint.starts_with("http://")
}

fn default_v2_provider_probe_prefix() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis();
    format!("v2-provider/{millis}-{}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::{V2ProviderProfile, V2RecoveryBundle, verify_recovery_bundle_trust};
    use rs3_crypto::KeyRing;
    use rs3_repository::v2::{V2AnchorState, V2FormatRef};
    use rs3_types::{BackendObjectId, BackendVersionId, KeyId, KeyPurpose, RepositoryId, Sequence};

    #[test]
    fn recovery_trust_rejects_bundle_below_external_floor() {
        let bundle = sample_bundle();

        let error = match verify_recovery_bundle_trust(
            &bundle,
            V2ProviderProfile::Dev,
            Sequence::new(8),
            None,
        ) {
            Ok(_) => panic!("below-floor recovery bundle should be rejected"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("below --min-sequence"));
    }

    #[test]
    fn production_recovery_trust_rejects_absent_signature() {
        let bundle = sample_bundle();

        let error = match verify_recovery_bundle_trust(
            &bundle,
            V2ProviderProfile::AtomicCreate,
            Sequence::new(7),
            Some(&recovery_public_key()),
        ) {
            Ok(_) => panic!("production recovery bundle without signature should be rejected"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("offline bundle signature"));
    }

    #[test]
    fn production_recovery_trust_rejects_bad_signature() {
        let mut bundle = sample_bundle();
        let public_key = sign_bundle(&mut bundle);
        if let Some(signature) = bundle.offline_signature.as_mut() {
            signature[0] ^= 0x80;
        }

        let error = match verify_recovery_bundle_trust(
            &bundle,
            V2ProviderProfile::AtomicCreate,
            Sequence::new(7),
            Some(&public_key),
        ) {
            Ok(_) => panic!("production recovery bundle with bad signature should be rejected"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("signature"));
    }

    #[test]
    fn production_recovery_trust_accepts_current_valid_signature() {
        let mut bundle = sample_bundle();
        let public_key = sign_bundle(&mut bundle);

        verify_recovery_bundle_trust(
            &bundle,
            V2ProviderProfile::AtomicCreate,
            Sequence::new(7),
            Some(&public_key),
        )
        .unwrap_or_else(|error| panic!("{error}"));
    }

    fn sample_bundle() -> V2RecoveryBundle {
        V2RecoveryBundle {
            repository_id: Some(
                RepositoryId::new("test-repository").unwrap_or_else(|error| panic!("{error}")),
            ),
            repository_salt_digest: None,
            anchor: V2AnchorState {
                sequence: Sequence::new(7),
                commit_key: BackendObjectId::new(
                    "commits/v01/00000000000000000007/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                )
                .unwrap_or_else(|error| panic!("{error}")),
                body_digest: [0x11; 32],
                version_id: Some(
                    BackendVersionId::new("commit-version-a")
                        .unwrap_or_else(|error| panic!("{error}")),
                ),
                signing_key_id: KeyId::new("checkpoint-v1")
                    .unwrap_or_else(|error| panic!("{error}")),
                format_ref: V2FormatRef {
                    generation: 1,
                    digest: "2222222222222222222222222222222222222222222222222222222222222222"
                        .to_owned(),
                    object_id: BackendObjectId::new("format/00000000000000000001/root")
                        .unwrap_or_else(|error| panic!("{error}")),
                    version_id: Some(
                        BackendVersionId::new("format-version-a")
                            .unwrap_or_else(|error| panic!("{error}")),
                    ),
                },
            },
            format_digest: Some([0x22; 32]),
            format_generation: Some(1),
            weak_subjectivity_floor_sequence: Sequence::new(7),
            exported_at_ms: 42,
            offline_signature: None,
        }
    }

    fn sign_bundle(bundle: &mut V2RecoveryBundle) -> String {
        let keyring = KeyRing::generate_random().unwrap_or_else(|error| panic!("{error}"));
        let payload = bundle
            .offline_signature_payload()
            .unwrap_or_else(|error| panic!("{error}"));
        let signature = keyring
            .sign_checkpoint_payload(&payload)
            .unwrap_or_else(|error| panic!("{error}"));
        let public_key = keyring
            .descriptors()
            .into_iter()
            .find(|descriptor| descriptor.purpose == KeyPurpose::CheckpointSigning)
            .and_then(|descriptor| descriptor.public_key)
            .unwrap_or_else(|| panic!("missing recovery public key"));
        bundle.offline_signature = Some(signature.signature);
        public_key
    }

    fn recovery_public_key() -> String {
        let mut bundle = sample_bundle();
        sign_bundle(&mut bundle)
    }
}
