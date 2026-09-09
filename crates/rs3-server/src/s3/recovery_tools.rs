//! Operator recovery and keyring maintenance helpers.

use super::bounded_io::read_bounded_object_at;
use super::runtime::v3_provider_profile;
use super::runtime_builders::build_store;
use super::{S3BoundaryError, repository_init};
use crate::{RepositoryFormat, RepositoryKeyContextConfig, RepositoryToolConfig};
use rs3_crypto::{
    KeyRing, MAX_FORMAT_ENVELOPE_OBJECT_BYTES, MAX_KEYRING_ENVELOPE_OBJECT_BYTES,
    RepositoryEnvelope, RepositoryKeyContext, SecretBytes,
};
use rs3_repository::store_keyring_envelope;
use rs3_repository::v3::{
    V3AnchorState, V3CommitStore, V3CommitStoreOptions, V3FormatRef, V3FormatRoot,
    V3KeyringEnvelopeRootRef, V3ProviderProfile, V3RecoveryBundle, V3ReplayChain,
};
use rs3_storage::BlobStore;
use rs3_types::{BackendObjectId, KeyDescriptor, RepositoryId, RetentionPolicy, Sequence};

/// Options for offline v3 restore-bundle verification.
#[derive(Clone, Debug)]
pub struct V3RecoveryBundleVerificationOptions {
    /// External weak-subjectivity floor accepted by the operator.
    pub min_sequence: Sequence,
    /// Wrapping key used to open the format root and active keyring envelope.
    pub wrapping_key: SecretBytes,
}

/// Report emitted after a restore bundle, format root, keyring envelope, and chain verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V3RecoveryBundleVerificationReport {
    /// Repository ID bound to the verified chain.
    pub repository_id: RepositoryId,
    /// Trusted anchor state from the restore bundle.
    pub anchor: V3AnchorState,
    /// Weak-subjectivity floor recorded in the restore bundle.
    pub weak_subjectivity_floor_sequence: Sequence,
    /// Number of commits verified from the anchor to the nearest snapshot.
    pub verified_commit_count: usize,
    /// Sequence of the nearest verified snapshot.
    pub snapshot_sequence: Sequence,
    /// Active keyring envelope reference from the verified format root.
    pub keyring_envelope_ref: V3KeyringEnvelopeRootRef,
    /// Provider profile recorded in the verified format root.
    pub provider_profile: V3ProviderProfile,
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

/// Verifies a v3 restore bundle using backend settings from a repository tool config.
pub async fn verify_v3_recovery_bundle_from_tool_config(
    config: &RepositoryToolConfig,
    bundle: V3RecoveryBundle,
    options: V3RecoveryBundleVerificationOptions,
) -> Result<V3RecoveryBundleVerificationReport, S3BoundaryError> {
    require_v3_preview(config.repository_format, "v03 restore bundle verification")?;
    let store = build_store(&config.backend).await?;
    verify_v3_recovery_bundle_with_store(store.into_handle(), config, bundle, options).await
}

/// Verifies a v3 restore bundle against an already constructed blob store.
pub async fn verify_v3_recovery_bundle_with_store<S>(
    store: S,
    config: &RepositoryToolConfig,
    mut bundle: V3RecoveryBundle,
    options: V3RecoveryBundleVerificationOptions,
) -> Result<V3RecoveryBundleVerificationReport, S3BoundaryError>
where
    S: BlobStore,
{
    if bundle.anchor.sequence < bundle.weak_subjectivity_floor_sequence {
        return Err(repository_init(
            "trusted v03 restore bundle anchor sequence is below the bundle weak-subjectivity floor",
        ));
    }
    if bundle.anchor.sequence < options.min_sequence {
        return Err(repository_init(
            "trusted v03 restore bundle anchor sequence is below --min-sequence",
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

    let expected_profile = v3_provider_profile(&config.backend, config.repository_retention);
    verify_recovery_bundle_signature(
        &bundle,
        expected_profile,
        config.recovery.public_key.as_deref(),
    )?;

    let (format_root, context) = open_format_root(
        &store,
        &config.repository_keys,
        &config.repository_keys.wrapping_key_id,
        &options.wrapping_key,
        &bundle.anchor.format_ref,
    )
    .await?;
    match bundle.repository_salt_digest {
        None => {
            return Err(repository_init(
                "restore bundle lacks the repository salt digest; export it again with this release",
            ));
        }
        Some(digest) if digest != rs3_crypto::Sha256Hasher::digest(context.salt()) => {
            return Err(repository_init(
                "restore bundle salt digest does not match the format root its anchor binds",
            ));
        }
        Some(_) => {}
    }
    if format_root.repository_id != repository_id
        || format_root.provider_profile != expected_profile
        || format_root.retention != config.repository_retention
        || format_root.signing_key_id != bundle.anchor.signing_key_id
    {
        return Err(repository_init(
            "v03 format root does not match the configured repository context",
        ));
    }

    let keyring = open_v3_keyring_envelope(
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
    let commit_options = V3CommitStoreOptions::for_profile(
        format_root.provider_profile,
        repository_id.clone(),
        commit_ref,
        bundle.anchor.format_ref.clone(),
    )
    .with_retention(format_root.retention);
    let commit_store = V3CommitStore::new(store, keyring, commit_options);
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
        repository_salt_hex: hex::encode(&opened.envelope.repository_salt),
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

    let context = repository_key_context_for_envelope(keys, &opened.envelope)?;
    let repository_salt_hex = hex::encode(&opened.envelope.repository_salt);
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
        .open_keyring(
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
        repository_salt_hex,
        envelope_object_id: reference.object_id,
        envelope_digest: reference.digest,
        generation: reference.generation,
        wrapping_key_id: options.new_wrapping_key_id,
        envelope_retention: retention,
    })
}

fn require_v3_preview(
    format: RepositoryFormat,
    operation: &'static str,
) -> Result<(), S3BoundaryError> {
    if format != RepositoryFormat::V3Preview {
        return Err(repository_init(format!(
            "{operation} requires the v3-preview repository format",
        )));
    }
    Ok(())
}

fn verify_recovery_bundle_signature(
    bundle: &V3RecoveryBundle,
    provider_profile: V3ProviderProfile,
    recovery_public_key: Option<&str>,
) -> Result<(), S3BoundaryError> {
    if provider_profile != V3ProviderProfile::Dev && bundle.offline_signature.is_none() {
        return Err(repository_init(
            "production v03 restore bundle verification requires an offline bundle signature",
        ));
    }

    match recovery_public_key {
        Some(public_key) => bundle
            .verify_offline_signature(public_key)
            .map_err(repository_init),
        None if provider_profile == V3ProviderProfile::Dev => Ok(()),
        None => Err(repository_init(
            "production v03 restore bundle verification requires RS3_RECOVERY_PUBLIC_KEY",
        )),
    }
}

fn verification_report(
    repository_id: RepositoryId,
    bundle: &V3RecoveryBundle,
    format_root: &V3FormatRoot,
    chain: &V3ReplayChain,
) -> V3RecoveryBundleVerificationReport {
    let snapshot_sequence = chain
        .commits_newest_first
        .last()
        .map(|commit| commit.parsed_header.header.self_ref.sequence)
        .unwrap_or(bundle.anchor.sequence);
    V3RecoveryBundleVerificationReport {
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
    keys: &RepositoryKeyContextConfig,
    wrapping_key_id: &str,
    wrapping_key: &SecretBytes,
    reference: &V3FormatRef,
) -> Result<(V3FormatRoot, RepositoryKeyContext), S3BoundaryError>
where
    S: BlobStore,
{
    let body = read_bounded_object_at(
        store,
        &reference.object_id,
        reference.version_id.as_ref(),
        MAX_FORMAT_ENVELOPE_OBJECT_BYTES,
    )
    .await?;
    let envelope =
        RepositoryEnvelope::from_object_bytes(body.as_ref(), rs3_crypto::EnvelopePurpose::Format)
            .map_err(repository_init)?;
    if envelope.generation != reference.generation
        || envelope.digest().map_err(repository_init)? != reference.digest
    {
        return Err(repository_init(
            "v03 format root object does not match the bundle reference",
        ));
    }
    // The bundle reference digest ties this envelope to the trusted anchor,
    // so its public salt is recovered context rather than backend discovery.
    let context = repository_key_context_for_envelope(keys, &envelope)?;
    let plaintext = envelope
        .open_format(&context, wrapping_key_id, wrapping_key)
        .map_err(repository_init)?;
    Ok((
        V3FormatRoot::from_plaintext_bytes(&plaintext).map_err(repository_init)?,
        context,
    ))
}

async fn open_v3_keyring_envelope<S>(
    store: &S,
    context: &RepositoryKeyContext,
    wrapping_key_id: &str,
    wrapping_key: &SecretBytes,
    reference: &V3KeyringEnvelopeRootRef,
) -> Result<KeyRing, S3BoundaryError>
where
    S: BlobStore,
{
    if reference.object_id.as_str().ends_with(".json") {
        return Err(repository_init("retired keyring object format"));
    }
    let body = read_bounded_object_at(
        store,
        &reference.object_id,
        reference.version_id.as_ref(),
        MAX_KEYRING_ENVELOPE_OBJECT_BYTES,
    )
    .await?;
    let envelope =
        RepositoryEnvelope::from_object_bytes(body.as_ref(), rs3_crypto::EnvelopePurpose::Keyring)
            .map_err(repository_init)?;
    if envelope.generation != reference.generation
        || envelope.digest().map_err(repository_init)? != reference.digest
    {
        return Err(repository_init(
            "v03 keyring envelope does not match the format-root reference",
        ));
    }
    envelope
        .open_keyring(context, wrapping_key_id, wrapping_key)
        .map_err(repository_init)
}

struct OpenedKeyringEnvelope {
    object_id: BackendObjectId,
    envelope: RepositoryEnvelope,
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
    if object_id.as_str().ends_with(".json") {
        return Err(repository_init("retired keyring object format"));
    }
    let body =
        read_bounded_object_at(store, &object_id, None, MAX_KEYRING_ENVELOPE_OBJECT_BYTES).await?;
    let envelope =
        RepositoryEnvelope::from_object_bytes(&body, rs3_crypto::EnvelopePurpose::Keyring)
            .map_err(repository_init)?;
    // Without an anchor, the wrapping key is what authenticates this envelope
    // and its public salt; opening below enforces that binding.
    let context = repository_key_context_for_envelope(keys, &envelope)?;
    let keyring = envelope
        .open_keyring(&context, wrapping_key_id, wrapping_key)
        .map_err(repository_init)?;

    Ok(OpenedKeyringEnvelope {
        object_id,
        envelope,
        keyring,
    })
}

/// Builds the envelope context from an envelope's public salt, insisting that
/// an operator-pinned salt agrees with it.
fn repository_key_context_for_envelope(
    keys: &RepositoryKeyContextConfig,
    envelope: &RepositoryEnvelope,
) -> Result<RepositoryKeyContext, S3BoundaryError> {
    if let Some(configured) = keys.repository_salt_hex.as_deref() {
        let configured = hex::decode(configured).map_err(|error| {
            repository_init(format!(
                "RS3_REPOSITORY_SALT_HEX must be hex-encoded repository salt: {error}",
            ))
        })?;
        if configured != envelope.repository_salt {
            return Err(repository_init(
                "RS3_REPOSITORY_SALT_HEX does not match the public salt bound into the repository envelope; unset it to recover the salt from the verified envelope, or supply the recorded value",
            ));
        }
    }
    RepositoryKeyContext::new(keys.repository_id.clone(), envelope.repository_salt.clone())
        .map_err(repository_init)
}

#[cfg(test)]
mod tests {
    use super::{
        KeyringEnvelopeInspectOptions, KeyringEnvelopeRewrapOptions,
        V3RecoveryBundleVerificationOptions, inspect_keyring_envelope_with_store,
        rewrap_keyring_envelope_with_store, verify_v3_recovery_bundle_with_store,
    };
    use crate::{
        BackendConfig, RecoveryConfig, RepositoryFormat, RepositoryKeyContextConfig,
        RepositoryToolConfig,
    };
    use bytes::Bytes;
    use rs3_crypto::{KeyRing, RepositoryEnvelope, RepositoryKeyContext, SecretBytes};
    use rs3_repository::store_keyring_envelope;
    use rs3_repository::v3::{
        V3CommitStore, V3CommitStoreOptions, V3FormatRoot, V3KeyringEnvelopeRootRef,
        V3MemoryAnchor, V3ProviderProfile, V3RecoveryBundle, v3_format_object_id,
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

    async fn verification_fixture(
        profile: V3ProviderProfile,
    ) -> (MemoryBlobStore, V3RecoveryBundle, SecretBytes) {
        let store = MemoryBlobStore::new();
        let repository_id = repository_id();
        let context = crypto_context();
        let wrapping_key = secret(OLD_WRAP_HEX);
        let keyring = KeyRing::generate_random().unwrap_or_else(|error| panic!("{error}"));
        let keyring_ref = write_keyring_ref(&store, &keyring, &context, &wrapping_key).await;
        let signing_key_id = keyring
            .primary_key_id(KeyPurpose::CheckpointSigning)
            .unwrap_or_else(|error| panic!("{error}"));
        let format_root = V3FormatRoot::new(
            repository_id.clone(),
            keyring_ref,
            signing_key_id,
            profile,
            None,
        );
        let format_ref = write_format_root(&store, &context, &wrapping_key, &format_root).await;
        let commit_ref = format_root
            .active_keyring_envelope_ref
            .commit_ref()
            .unwrap_or_else(|error| panic!("{error}"));
        let commit_options = V3CommitStoreOptions::for_profile(
            profile,
            repository_id.clone(),
            commit_ref,
            format_ref,
        );
        let commit_store = V3CommitStore::new(store.clone(), keyring, commit_options);
        let anchor = V3MemoryAnchor::new();
        let genesis = commit_store
            .write_genesis_snapshot(&anchor)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let mut bundle = V3RecoveryBundle::from_anchor(genesis.anchor_state, Sequence::new(1));
        bundle.repository_id = Some(repository_id);
        bundle.repository_salt_digest = Some(rs3_crypto::Sha256Hasher::digest(
            hex::decode(SALT_HEX).unwrap_or_else(|error| panic!("{error}")),
        ));
        bundle.exported_at_ms = 42;

        (store, bundle, wrapping_key)
    }

    #[tokio::test]
    async fn verify_bundle_checks_format_root_keyring_and_commit_chain() {
        let (store, bundle, wrapping_key) = verification_fixture(V3ProviderProfile::Dev).await;
        let report = verify_v3_recovery_bundle_with_store(
            store,
            &tool_config(),
            bundle,
            V3RecoveryBundleVerificationOptions {
                min_sequence: Sequence::new(1),
                wrapping_key,
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(report.verified_commit_count, 1);
        assert_eq!(report.snapshot_sequence, Sequence::new(1));
        assert_eq!(report.provider_profile, V3ProviderProfile::Dev);
    }

    #[tokio::test]
    async fn keyring_inspect_recovers_the_envelope_salt_and_rejects_a_pinned_mismatch() {
        let store = MemoryBlobStore::new();
        let context = crypto_context();
        let wrapping_key = secret(OLD_WRAP_HEX);
        let keyring = KeyRing::generate_random().unwrap_or_else(|error| panic!("{error}"));
        let envelope = keyring
            .seal_keyring_envelope(&context, "wrap-v1", &wrapping_key, 1)
            .unwrap_or_else(|error| panic!("{error}"));
        let reference = store_keyring_envelope(&store, &envelope, None, None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let mut keys = key_context();
        keys.repository_salt_hex = None;
        let inspect = inspect_keyring_envelope_with_store(
            store.clone(),
            &keys,
            KeyringEnvelopeInspectOptions {
                envelope_object_id: Some(reference.object_id.clone()),
                wrapping_key: wrapping_key.clone(),
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(inspect.repository_salt_hex, SALT_HEX);

        keys.repository_salt_hex = Some("33".repeat(32));
        let error = inspect_keyring_envelope_with_store(
            store,
            &keys,
            KeyringEnvelopeInspectOptions {
                envelope_object_id: Some(reference.object_id),
                wrapping_key,
            },
        )
        .await
        .expect_err("pinned salt must match the envelope");
        assert!(error.to_string().contains("does not match the public salt"));
    }

    #[tokio::test]
    async fn verify_bundle_checks_the_salt_digest_against_the_anchored_format_root() {
        let (store, mut bundle, wrapping_key) = verification_fixture(V3ProviderProfile::Dev).await;
        let mut config = tool_config();
        config.repository_keys.repository_salt_hex = None;
        let report = verify_v3_recovery_bundle_with_store(
            store.clone(),
            &config,
            bundle.clone(),
            V3RecoveryBundleVerificationOptions {
                min_sequence: Sequence::new(1),
                wrapping_key: wrapping_key.clone(),
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(report.verified_commit_count, 1);

        let verify = |bundle| {
            verify_v3_recovery_bundle_with_store(
                store.clone(),
                &config,
                bundle,
                V3RecoveryBundleVerificationOptions {
                    min_sequence: Sequence::new(1),
                    wrapping_key: wrapping_key.clone(),
                },
            )
        };
        bundle.repository_salt_digest = Some([9; 32]);
        let error = verify(bundle.clone())
            .await
            .expect_err("a foreign salt digest is rejected");
        assert!(error.to_string().contains("salt digest"));
        bundle.repository_salt_digest = None;
        let error = verify(bundle)
            .await
            .expect_err("the digest is part of the bundle contract");
        assert!(
            error
                .to_string()
                .contains("lacks the repository salt digest")
        );
    }

    #[tokio::test]
    async fn verify_bundle_rejects_anchor_below_external_floor() {
        let (store, bundle, wrapping_key) = verification_fixture(V3ProviderProfile::Dev).await;
        let error = verify_v3_recovery_bundle_with_store(
            store,
            &tool_config(),
            bundle,
            V3RecoveryBundleVerificationOptions {
                min_sequence: Sequence::new(2),
                wrapping_key,
            },
        )
        .await
        .expect_err("external floor must reject older anchor");
        assert!(error.to_string().contains("below --min-sequence"));
    }

    #[tokio::test]
    async fn verify_bundle_requires_a_valid_offline_signature_for_production() {
        let (store, mut bundle, wrapping_key) =
            verification_fixture(V3ProviderProfile::AtomicCreate).await;
        let signer = KeyRing::generate_random().expect("recovery signer");
        let public_key = signer
            .descriptors()
            .into_iter()
            .find(|descriptor| descriptor.purpose == KeyPurpose::CheckpointSigning)
            .and_then(|descriptor| descriptor.public_key)
            .expect("recovery public key");
        let mut config = tool_config();
        config.backend.endpoint = "https://storage.example.invalid".to_owned();
        config.recovery.public_key = Some(public_key);
        let verify = |bundle| {
            verify_v3_recovery_bundle_with_store(
                store.clone(),
                &config,
                bundle,
                V3RecoveryBundleVerificationOptions {
                    min_sequence: Sequence::new(1),
                    wrapping_key: wrapping_key.clone(),
                },
            )
        };
        assert!(
            verify(bundle.clone()).await.is_err(),
            "unsigned production bundle"
        );
        bundle.offline_signature = Some(
            signer
                .sign_checkpoint_payload(
                    &bundle
                        .offline_signature_payload()
                        .expect("signature payload"),
                )
                .expect("sign bundle")
                .signature,
        );
        let report = verify(bundle.clone())
            .await
            .expect("valid signed production bundle");
        assert_eq!(report.provider_profile, V3ProviderProfile::AtomicCreate);
        assert_eq!(report.verified_commit_count, 1);
        bundle.anchor.body_digest[0] ^= 1;
        assert!(verify(bundle).await.is_err(), "tampered signed anchor");
    }

    fn tool_config() -> RepositoryToolConfig {
        RepositoryToolConfig {
            backend: BackendConfig {
                endpoint: "memory://local".to_owned(),
                bucket: "repository".to_owned(),
                prefix: None,
                timeouts: Default::default(),
            },
            repository_format: RepositoryFormat::V3Preview,
            repository_retention: None,
            recovery: RecoveryConfig::default(),
            repository_keys: key_context(),
        }
    }

    fn key_context() -> RepositoryKeyContextConfig {
        RepositoryKeyContextConfig {
            repository_id: repository_id(),
            repository_salt_hex: Some(SALT_HEX.to_owned()),
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
    ) -> V3KeyringEnvelopeRootRef {
        let envelope = keyring
            .seal_keyring_envelope(context, "wrap-v1", wrapping_key, 1)
            .unwrap_or_else(|error| panic!("{error}"));
        let reference = store_keyring_envelope(store, &envelope, None, None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        V3KeyringEnvelopeRootRef {
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
        root: &V3FormatRoot,
    ) -> rs3_repository::v3::V3FormatRef {
        let plaintext = root
            .to_plaintext_bytes()
            .unwrap_or_else(|error| panic!("{error}"));
        let envelope =
            RepositoryEnvelope::seal_format(context, "wrap-v1", wrapping_key, 1, &plaintext)
                .unwrap_or_else(|error| panic!("{error}"));
        let digest = envelope.digest().unwrap_or_else(|error| panic!("{error}"));
        let object_id = v3_format_object_id(envelope.generation, &digest)
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
        rs3_repository::v3::V3FormatRef {
            generation: envelope.generation,
            digest,
            object_id,
            version_id: metadata.version_id,
        }
    }
}
