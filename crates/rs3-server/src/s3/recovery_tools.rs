//! Operator recovery and keyring maintenance helpers.

use super::runtime::v2_provider_profile;
use super::runtime_builders::build_store;
use super::{S3BoundaryError, repository_init};
use crate::{RepositoryFormat, RepositoryKeyContextConfig, RepositoryToolConfig};
use rs3_crypto::{FormatEnvelope, KeyRing, KeyringEnvelope, RepositoryKeyContext, SecretBytes};
use rs3_repository::store_keyring_envelope;
use rs3_repository::v2::{
    V2AnchorState, V2CommitStore, V2CommitStoreOptions, V2FormatRef, V2FormatRoot,
    V2KeyringEnvelopeRootRef, V2ProviderProfile, V2RecoveryBundle, V2ReplayChain,
};
use rs3_storage::{BlobStore, ByteRange};
use rs3_types::{BackendObjectId, KeyDescriptor, RepositoryId, RetentionPolicy, Sequence};

/// Options for offline v2 restore-bundle verification.
#[derive(Clone, Debug)]
pub struct V2RecoveryBundleVerificationOptions {
    /// External weak-subjectivity floor accepted by the operator.
    pub min_sequence: Sequence,
    /// Wrapping key used to open the format root and active keyring envelope.
    pub wrapping_key: SecretBytes,
}

/// Report emitted after a restore bundle, format root, keyring envelope, and chain verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2RecoveryBundleVerificationReport {
    /// Repository ID bound to the verified chain.
    pub repository_id: RepositoryId,
    /// Trusted anchor state from the restore bundle.
    pub anchor: V2AnchorState,
    /// Weak-subjectivity floor recorded in the restore bundle.
    pub weak_subjectivity_floor_sequence: Sequence,
    /// Number of commits verified from the anchor to the nearest snapshot.
    pub verified_commit_count: usize,
    /// Sequence of the nearest verified snapshot.
    pub snapshot_sequence: Sequence,
    /// Active keyring envelope reference from the verified format root.
    pub keyring_envelope_ref: V2KeyringEnvelopeRootRef,
    /// Provider profile recorded in the verified format root.
    pub provider_profile: V2ProviderProfile,
    /// Retention policy recorded in the verified format root.
    pub retention: Option<RetentionPolicy>,
    /// Export timestamp from the restore bundle.
    pub exported_at_ms: i64,
    /// Whether the restore bundle carried an offline signature.
    pub offline_signature_present: bool,
}

/// Options for opening an encrypted keyring envelope.
#[derive(Clone, Debug)]
pub struct KeyringEnvelopeInspectOptions {
    /// Envelope object to open. Defaults to `RS3_KEYRING_ENVELOPE_OBJECT_ID` when unset.
    pub envelope_object_id: Option<BackendObjectId>,
    /// Wrapping key used to open the envelope.
    pub wrapping_key: SecretBytes,
}

/// Public keyring envelope metadata and descriptors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyringEnvelopeInspectReport {
    /// Repository ID bound into the envelope.
    pub repository_id: RepositoryId,
    /// Public repository salt bound into the envelope.
    pub repository_salt_hex: String,
    /// Envelope object that was opened.
    pub envelope_object_id: BackendObjectId,
    /// Digest of the opened envelope object.
    pub envelope_digest: String,
    /// Monotonic envelope generation.
    pub generation: u64,
    /// Wrapping key ID used to open the envelope.
    pub wrapping_key_id: String,
    /// Public descriptors for keys inside the keyring.
    pub keys: Vec<KeyDescriptor>,
}

/// Options for re-encrypting an existing keyring envelope with a new wrapping key.
#[derive(Clone, Debug)]
pub struct KeyringEnvelopeRewrapOptions {
    /// Envelope object to rewrap. Defaults to `RS3_KEYRING_ENVELOPE_OBJECT_ID` when unset.
    pub envelope_object_id: Option<BackendObjectId>,
    /// Current wrapping key used to open the existing envelope.
    pub old_wrapping_key: SecretBytes,
    /// New operator-visible wrapping key identifier.
    pub new_wrapping_key_id: String,
    /// New wrapping key used to seal the replacement envelope.
    pub new_wrapping_key: SecretBytes,
    /// New monotonic generation. Defaults to existing generation plus one.
    pub new_generation: Option<u64>,
}

/// Report emitted after a keyring envelope rewrap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyringEnvelopeRewrapReport {
    /// Repository ID bound into the replacement envelope.
    pub repository_id: RepositoryId,
    /// Public repository salt bound into the replacement envelope.
    pub repository_salt_hex: String,
    /// Newly written envelope object.
    pub envelope_object_id: BackendObjectId,
    /// Digest of the newly written envelope object.
    pub envelope_digest: String,
    /// Monotonic envelope generation.
    pub generation: u64,
    /// New wrapping key ID used by the replacement envelope.
    pub wrapping_key_id: String,
    /// Retention policy applied to the newly written envelope.
    pub envelope_retention: Option<RetentionPolicy>,
}

/// Verifies a v2 restore bundle using backend settings from a repository tool config.
pub async fn verify_v2_recovery_bundle_from_tool_config(
    config: &RepositoryToolConfig,
    bundle: V2RecoveryBundle,
    options: V2RecoveryBundleVerificationOptions,
) -> Result<V2RecoveryBundleVerificationReport, S3BoundaryError> {
    require_v2_preview(config.repository_format, "v2 restore bundle verification")?;
    let store = build_store(&config.backend).await?;
    verify_v2_recovery_bundle_with_store(store.into_handle(), config, bundle, options).await
}

/// Verifies a v2 restore bundle against an already constructed blob store.
pub async fn verify_v2_recovery_bundle_with_store<S>(
    store: S,
    config: &RepositoryToolConfig,
    mut bundle: V2RecoveryBundle,
    options: V2RecoveryBundleVerificationOptions,
) -> Result<V2RecoveryBundleVerificationReport, S3BoundaryError>
where
    S: BlobStore,
{
    if bundle.anchor.sequence < bundle.weak_subjectivity_floor_sequence {
        return Err(repository_init(
            "trusted v2 restore bundle anchor sequence is below the bundle weak-subjectivity floor",
        ));
    }
    if bundle.anchor.sequence < options.min_sequence {
        return Err(repository_init(
            "trusted v2 restore bundle anchor sequence is below --min-sequence",
        ));
    }

    let repository_id = config.repository_keys.repository_id.clone();
    if let Some(bundle_repository_id) = bundle.repository_id.as_ref() {
        if bundle_repository_id != &repository_id {
            return Err(repository_init(
                "restore bundle repository ID does not match configured repository ID",
            ));
        }
    } else {
        bundle.repository_id = Some(repository_id.clone());
    }

    let expected_profile = v2_provider_profile(&config.backend, config.repository_retention);
    verify_recovery_bundle_signature(
        &bundle,
        expected_profile,
        config.recovery.public_key.as_deref(),
    )?;

    let context = repository_key_context(&config.repository_keys)?;
    let format_root = open_format_root(
        &store,
        &context,
        &config.repository_keys.wrapping_key_id,
        &options.wrapping_key,
        &bundle.anchor.format_ref,
    )
    .await?;
    if format_root.repository_id != repository_id
        || format_root.provider_profile != expected_profile
        || format_root.retention != config.repository_retention
        || format_root.signing_key_id != bundle.anchor.signing_key_id
    {
        return Err(repository_init(
            "v2 format root does not match the configured repository context",
        ));
    }

    let keyring = open_v2_keyring_envelope(
        &store,
        &context,
        &config.repository_keys.wrapping_key_id,
        &options.wrapping_key,
        &format_root.active_keyring_envelope_ref,
    )
    .await?;
    let commit_ref = format_root
        .active_keyring_envelope_ref
        .commit_ref()
        .map_err(repository_init)?;
    let commit_options = V2CommitStoreOptions::for_profile(
        format_root.provider_profile,
        repository_id.clone(),
        commit_ref,
        bundle.anchor.format_ref.clone(),
    )
    .with_retention(format_root.retention);
    let commit_store = V2CommitStore::new(store, keyring, commit_options);
    let chain = commit_store
        .load_replay_chain_from_state(&bundle.anchor)
        .await
        .map_err(repository_init)?;

    Ok(verification_report(
        repository_id,
        &bundle,
        &format_root,
        &chain,
    ))
}

/// Opens a keyring envelope using backend settings from a repository tool config.
pub async fn inspect_keyring_envelope_from_tool_config(
    config: &RepositoryToolConfig,
    options: KeyringEnvelopeInspectOptions,
) -> Result<KeyringEnvelopeInspectReport, S3BoundaryError> {
    let store = build_store(&config.backend).await?;
    inspect_keyring_envelope_with_store(store.into_handle(), &config.repository_keys, options).await
}

/// Opens a keyring envelope against an already constructed blob store.
pub async fn inspect_keyring_envelope_with_store<S>(
    store: S,
    keys: &RepositoryKeyContextConfig,
    options: KeyringEnvelopeInspectOptions,
) -> Result<KeyringEnvelopeInspectReport, S3BoundaryError>
where
    S: BlobStore,
{
    let opened = open_keyring_envelope(
        &store,
        keys,
        options.envelope_object_id,
        &keys.wrapping_key_id,
        &options.wrapping_key,
    )
    .await?;

    Ok(KeyringEnvelopeInspectReport {
        repository_id: keys.repository_id.clone(),
        repository_salt_hex: keys.repository_salt_hex.clone(),
        envelope_object_id: opened.object_id,
        envelope_digest: opened.envelope.digest().map_err(repository_init)?,
        generation: opened.envelope.generation,
        wrapping_key_id: keys.wrapping_key_id.clone(),
        keys: opened.keyring.descriptors(),
    })
}

/// Rewraps a keyring envelope using backend settings from a repository tool config.
pub async fn rewrap_keyring_envelope_from_tool_config(
    config: &RepositoryToolConfig,
    options: KeyringEnvelopeRewrapOptions,
) -> Result<KeyringEnvelopeRewrapReport, S3BoundaryError> {
    let store = build_store(&config.backend).await?;
    rewrap_keyring_envelope_with_store(
        store.into_handle(),
        &config.repository_keys,
        config.repository_retention,
        options,
    )
    .await
}

/// Rewraps a keyring envelope against an already constructed blob store.
pub async fn rewrap_keyring_envelope_with_store<S>(
    store: S,
    keys: &RepositoryKeyContextConfig,
    retention: Option<RetentionPolicy>,
    options: KeyringEnvelopeRewrapOptions,
) -> Result<KeyringEnvelopeRewrapReport, S3BoundaryError>
where
    S: BlobStore,
{
    let opened = open_keyring_envelope(
        &store,
        keys,
        options.envelope_object_id,
        &keys.wrapping_key_id,
        &options.old_wrapping_key,
    )
    .await?;
    let new_generation = options
        .new_generation
        .unwrap_or_else(|| opened.envelope.generation.saturating_add(1));
    if new_generation <= opened.envelope.generation {
        return Err(repository_init(format!(
            "--new-generation must be greater than existing envelope generation {}",
            opened.envelope.generation
        )));
    }

    let context = repository_key_context(keys)?;
    let rewrapped = opened
        .envelope
        .rewrap(
            &context,
            &keys.wrapping_key_id,
            &options.old_wrapping_key,
            &options.new_wrapping_key_id,
            &options.new_wrapping_key,
            new_generation,
        )
        .map_err(repository_init)?;
    rewrapped
        .open(
            &context,
            &options.new_wrapping_key_id,
            &options.new_wrapping_key,
        )
        .map_err(repository_init)?;
    let reference = store_keyring_envelope(&store, &rewrapped, retention, None)
        .await
        .map_err(repository_init)?;

    Ok(KeyringEnvelopeRewrapReport {
        repository_id: keys.repository_id.clone(),
        repository_salt_hex: keys.repository_salt_hex.clone(),
        envelope_object_id: reference.object_id,
        envelope_digest: reference.digest,
        generation: reference.generation,
        wrapping_key_id: options.new_wrapping_key_id,
        envelope_retention: retention,
    })
}

fn require_v2_preview(
    format: RepositoryFormat,
    operation: &'static str,
) -> Result<(), S3BoundaryError> {
    if format != RepositoryFormat::V2Preview {
        return Err(repository_init(format!(
            "{operation} requires the v2-preview repository format",
        )));
    }
    Ok(())
}

fn verify_recovery_bundle_signature(
    bundle: &V2RecoveryBundle,
    provider_profile: V2ProviderProfile,
    recovery_public_key: Option<&str>,
) -> Result<(), S3BoundaryError> {
    if provider_profile != V2ProviderProfile::Dev && bundle.offline_signature.is_none() {
        return Err(repository_init(
            "production v2 restore bundle verification requires an offline bundle signature",
        ));
    }

    match recovery_public_key {
        Some(public_key) => bundle
            .verify_offline_signature(public_key)
            .map_err(repository_init),
        None if provider_profile == V2ProviderProfile::Dev => Ok(()),
        None => Err(repository_init(
            "production v2 restore bundle verification requires RS3_RECOVERY_PUBLIC_KEY",
        )),
    }
}

fn verification_report(
    repository_id: RepositoryId,
    bundle: &V2RecoveryBundle,
    format_root: &V2FormatRoot,
    chain: &V2ReplayChain,
) -> V2RecoveryBundleVerificationReport {
    let snapshot_sequence = chain
        .commits_newest_first
        .last()
        .map(|commit| commit.parsed_header.header.self_ref.sequence)
        .unwrap_or(bundle.anchor.sequence);
    V2RecoveryBundleVerificationReport {
        repository_id,
        anchor: bundle.anchor.clone(),
        weak_subjectivity_floor_sequence: bundle.weak_subjectivity_floor_sequence,
        verified_commit_count: chain.commits_newest_first.len(),
        snapshot_sequence,
        keyring_envelope_ref: format_root.active_keyring_envelope_ref.clone(),
        provider_profile: format_root.provider_profile,
        retention: format_root.retention,
        exported_at_ms: bundle.exported_at_ms,
        offline_signature_present: bundle.offline_signature.is_some(),
    }
}

async fn open_format_root<S>(
    store: &S,
    context: &RepositoryKeyContext,
    wrapping_key_id: &str,
    wrapping_key: &SecretBytes,
    reference: &V2FormatRef,
) -> Result<V2FormatRoot, S3BoundaryError>
where
    S: BlobStore,
{
    let body = store
        .get_range_at(
            &reference.object_id,
            reference.version_id.as_ref(),
            ByteRange::Full,
        )
        .await
        .map_err(repository_init)?;
    let envelope = FormatEnvelope::from_object_bytes(body.as_ref()).map_err(repository_init)?;
    if envelope.generation != reference.generation
        || envelope.digest().map_err(repository_init)? != reference.digest
    {
        return Err(repository_init(
            "v2 format root object does not match the bundle reference",
        ));
    }
    let plaintext = envelope
        .open(context, wrapping_key_id, wrapping_key)
        .map_err(repository_init)?;
    V2FormatRoot::from_plaintext_bytes(&plaintext).map_err(repository_init)
}

async fn open_v2_keyring_envelope<S>(
    store: &S,
    context: &RepositoryKeyContext,
    wrapping_key_id: &str,
    wrapping_key: &SecretBytes,
    reference: &V2KeyringEnvelopeRootRef,
) -> Result<KeyRing, S3BoundaryError>
where
    S: BlobStore,
{
    let body = store
        .get_range_at(
            &reference.object_id,
            reference.version_id.as_ref(),
            ByteRange::Full,
        )
        .await
        .map_err(repository_init)?;
    let envelope = KeyringEnvelope::from_object_bytes(body.as_ref()).map_err(repository_init)?;
    if envelope.generation != reference.generation
        || envelope.digest().map_err(repository_init)? != reference.digest
    {
        return Err(repository_init(
            "v2 keyring envelope does not match the format-root reference",
        ));
    }
    envelope
        .open(context, wrapping_key_id, wrapping_key)
        .map_err(repository_init)
}

struct OpenedKeyringEnvelope {
    object_id: BackendObjectId,
    envelope: KeyringEnvelope,
    keyring: KeyRing,
}

async fn open_keyring_envelope<S>(
    store: &S,
    keys: &RepositoryKeyContextConfig,
    envelope_object_id: Option<BackendObjectId>,
    wrapping_key_id: &str,
    wrapping_key: &SecretBytes,
) -> Result<OpenedKeyringEnvelope, S3BoundaryError>
where
    S: BlobStore,
{
    let object_id = envelope_object_id
        .or_else(|| keys.envelope_object_id.clone())
        .ok_or_else(|| {
            repository_init(
                "keyring envelope object id is required via --envelope-object-id or RS3_KEYRING_ENVELOPE_OBJECT_ID",
            )
        })?;
    let context = repository_key_context(keys)?;
    let body = store
        .get_range(&object_id, ByteRange::Full)
        .await
        .map_err(repository_init)?;
    let envelope = KeyringEnvelope::from_object_bytes(&body).map_err(repository_init)?;
    let keyring = envelope
        .open(&context, wrapping_key_id, wrapping_key)
        .map_err(repository_init)?;

    Ok(OpenedKeyringEnvelope {
        object_id,
        envelope,
        keyring,
    })
}

fn repository_key_context(
    keys: &RepositoryKeyContextConfig,
) -> Result<RepositoryKeyContext, S3BoundaryError> {
    let salt = hex::decode(&keys.repository_salt_hex).map_err(|error| {
        repository_init(format!(
            "RS3_REPOSITORY_SALT_HEX must be hex-encoded repository salt: {error}",
        ))
    })?;
    RepositoryKeyContext::new(keys.repository_id.clone(), salt).map_err(repository_init)
}

#[cfg(test)]
mod tests {
    use super::{
        KeyringEnvelopeInspectOptions, KeyringEnvelopeRewrapOptions,
        V2RecoveryBundleVerificationOptions, inspect_keyring_envelope_with_store,
        rewrap_keyring_envelope_with_store, verify_v2_recovery_bundle_with_store,
    };
    use crate::{
        BackendConfig, RecoveryConfig, RepositoryFormat, RepositoryKeyContextConfig,
        RepositoryToolConfig,
    };
    use bytes::Bytes;
    use rs3_crypto::{FormatEnvelope, KeyRing, RepositoryKeyContext, SecretBytes};
    use rs3_repository::store_keyring_envelope;
    use rs3_repository::v2::{
        V2CommitStore, V2CommitStoreOptions, V2FormatRoot, V2KeyringEnvelopeRootRef,
        V2MemoryAnchor, V2ProviderProfile, V2RecoveryBundle, v2_format_object_id,
    };
    use rs3_storage::{BlobStore, MemoryBlobStore, PutOptions};
    use rs3_types::{KeyPurpose, RepositoryId, Sequence};

    const SALT_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const OLD_WRAP_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const NEW_WRAP_HEX: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    #[tokio::test]
    async fn keyring_inspect_and_rewrap_use_shared_envelope_storage() {
        let store = MemoryBlobStore::new();
        let keys = key_context();
        let context = crypto_context();
        let old_wrapping_key = secret(OLD_WRAP_HEX);
        let new_wrapping_key = secret(NEW_WRAP_HEX);
        let keyring = KeyRing::generate_random().unwrap_or_else(|error| panic!("{error}"));
        let envelope = keyring
            .seal_keyring_envelope(&context, "wrap-v1", &old_wrapping_key, 1)
            .unwrap_or_else(|error| panic!("{error}"));
        let reference = store_keyring_envelope(&store, &envelope, None, None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let inspect = inspect_keyring_envelope_with_store(
            store.clone(),
            &keys,
            KeyringEnvelopeInspectOptions {
                envelope_object_id: Some(reference.object_id.clone()),
                wrapping_key: old_wrapping_key.clone(),
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let rewrap = rewrap_keyring_envelope_with_store(
            store.clone(),
            &keys,
            None,
            KeyringEnvelopeRewrapOptions {
                envelope_object_id: Some(reference.object_id),
                old_wrapping_key,
                new_wrapping_key_id: "wrap-v2".to_owned(),
                new_wrapping_key,
                new_generation: None,
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(inspect.generation, 1);
        assert_eq!(rewrap.generation, 2);
        assert_eq!(rewrap.wrapping_key_id, "wrap-v2");
        assert_eq!(inspect.keys, keyring.descriptors());
    }

    #[tokio::test]
    async fn verify_bundle_checks_format_root_keyring_and_commit_chain() {
        let store = MemoryBlobStore::new();
        let repository_id = repository_id();
        let context = crypto_context();
        let wrapping_key = secret(OLD_WRAP_HEX);
        let keyring = KeyRing::generate_random().unwrap_or_else(|error| panic!("{error}"));
        let keyring_ref = write_keyring_ref(&store, &keyring, &context, &wrapping_key).await;
        let signing_key_id = keyring
            .primary_key_id(KeyPurpose::CheckpointSigning)
            .unwrap_or_else(|error| panic!("{error}"));
        let format_root = V2FormatRoot::new(
            repository_id.clone(),
            keyring_ref,
            signing_key_id,
            V2ProviderProfile::Dev,
            None,
        );
        let format_ref = write_format_root(&store, &context, &wrapping_key, &format_root).await;
        let commit_ref = format_root
            .active_keyring_envelope_ref
            .commit_ref()
            .unwrap_or_else(|error| panic!("{error}"));
        let commit_options = V2CommitStoreOptions::for_profile(
            V2ProviderProfile::Dev,
            repository_id.clone(),
            commit_ref,
            format_ref,
        );
        let commit_store = V2CommitStore::new(store.clone(), keyring, commit_options);
        let anchor = V2MemoryAnchor::new();
        let genesis = commit_store
            .write_genesis_snapshot(&anchor)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let mut bundle = V2RecoveryBundle::from_anchor(genesis.anchor_state, Sequence::new(1));
        bundle.repository_id = Some(repository_id);
        bundle.exported_at_ms = 42;

        let report = verify_v2_recovery_bundle_with_store(
            store,
            &tool_config(),
            bundle,
            V2RecoveryBundleVerificationOptions {
                min_sequence: Sequence::new(1),
                wrapping_key,
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(report.verified_commit_count, 1);
        assert_eq!(report.snapshot_sequence, Sequence::new(1));
        assert_eq!(report.provider_profile, V2ProviderProfile::Dev);
    }

    fn tool_config() -> RepositoryToolConfig {
        RepositoryToolConfig {
            backend: BackendConfig {
                endpoint: "memory://local".to_owned(),
                bucket: "repository".to_owned(),
                prefix: None,
            },
            repository_format: RepositoryFormat::V2Preview,
            repository_retention: None,
            recovery: RecoveryConfig::default(),
            repository_keys: key_context(),
        }
    }

    fn key_context() -> RepositoryKeyContextConfig {
        RepositoryKeyContextConfig {
            repository_id: repository_id(),
            repository_salt_hex: SALT_HEX.to_owned(),
            envelope_object_id: None,
            wrapping_key_id: "wrap-v1".to_owned(),
        }
    }

    fn repository_id() -> RepositoryId {
        RepositoryId::new("repo-a").unwrap_or_else(|error| panic!("{error}"))
    }

    fn crypto_context() -> RepositoryKeyContext {
        RepositoryKeyContext::new(
            repository_id(),
            hex::decode(SALT_HEX).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"))
    }

    fn secret(hex_value: &str) -> SecretBytes {
        SecretBytes::new(hex::decode(hex_value).unwrap_or_else(|error| panic!("{error}")))
            .unwrap_or_else(|error| panic!("{error}"))
    }

    async fn write_keyring_ref(
        store: &MemoryBlobStore,
        keyring: &KeyRing,
        context: &RepositoryKeyContext,
        wrapping_key: &SecretBytes,
    ) -> V2KeyringEnvelopeRootRef {
        let envelope = keyring
            .seal_keyring_envelope(context, "wrap-v1", wrapping_key, 1)
            .unwrap_or_else(|error| panic!("{error}"));
        let reference = store_keyring_envelope(store, &envelope, None, None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        V2KeyringEnvelopeRootRef {
            generation: reference.generation,
            digest: reference.digest,
            object_id: reference.object_id,
            version_id: reference.version_id,
        }
    }

    async fn write_format_root(
        store: &MemoryBlobStore,
        context: &RepositoryKeyContext,
        wrapping_key: &SecretBytes,
        root: &V2FormatRoot,
    ) -> rs3_repository::v2::V2FormatRef {
        let plaintext = root
            .to_plaintext_bytes()
            .unwrap_or_else(|error| panic!("{error}"));
        let envelope = FormatEnvelope::seal(context, "wrap-v1", wrapping_key, 1, &plaintext)
            .unwrap_or_else(|error| panic!("{error}"));
        let digest = envelope.digest().unwrap_or_else(|error| panic!("{error}"));
        let object_id = v2_format_object_id(envelope.generation, &digest)
            .unwrap_or_else(|error| panic!("{error}"));
        let body = Bytes::from(
            envelope
                .to_object_bytes()
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let metadata = store
            .put(&object_id, body, PutOptions::default())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        rs3_repository::v2::V2FormatRef {
            generation: envelope.generation,
            digest,
            object_id,
            version_id: metadata.version_id,
        }
    }
}
