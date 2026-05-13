use super::runtime_checkpoints::{
    checkpoint_keyring_envelope_reference, repository_has_committed_objects,
};
use super::runtime_handles::{RuntimeAnchor, RuntimeStore};
use super::{S3BoundaryError, repository_init};
use crate::RepositoryKeysConfig;
use crate::config::{KEYRING_WRAPPING_KEY_HEX_ENV, REPOSITORY_SALT_HEX_ENV};
use bytes::Bytes;
use rs3_anchor::{AnchorError, CheckpointAnchor};
use rs3_crypto::{KeyRing, KeyringEnvelope, RepositoryKeyContext, SecretBytes};
use rs3_index::KeyringEnvelopeReference;
use rs3_repository::{CheckpointPosition, Repository, RepositoryOptions};
use rs3_storage::{BlobMetadata, BlobStore, ByteRange, PutOptions, StorageError};
use rs3_types::{BackendObjectId, LegalHoldStatus, RetentionMode, RetentionPolicy};
use secrecy::{ExposeSecret, SecretString};

const KEYRING_ENVELOPE_OBJECT_CONTENT_TYPE: &str = "application/vnd.rs3.keyring-envelope+json";

pub(super) async fn gateway_keyring(
    store: &RuntimeStore,
    anchor: &RuntimeAnchor,
    keys: &RepositoryKeysConfig,
    retention: Option<RetentionPolicy>,
    allow_bootstrap: bool,
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
        Err(AnchorError::MissingAnchor) => {
            unanchored_gateway_keyring(store, keys, retention, allow_bootstrap).await
        }
        Err(error) => Err(repository_init(error)),
    }
}

async fn unanchored_gateway_keyring(
    store: &RuntimeStore,
    keys: &RepositoryKeysConfig,
    retention: Option<RetentionPolicy>,
    allow_bootstrap: bool,
) -> Result<LoadedGatewayKeyring, S3BoundaryError> {
    if let Some(object_id) = keys.envelope_object_id.as_ref() {
        return match store.head(object_id).await {
            Ok(metadata) => {
                let body = store
                    .get_range_at(object_id, metadata.version_id.as_ref(), ByteRange::Full)
                    .await
                    .map_err(repository_init)?;
                open_gateway_keyring_object(keys, object_id.clone(), metadata.version_id, body)
            }
            Err(StorageError::NotFound(_)) => {
                if !allow_bootstrap {
                    return Err(repository_init(
                        "restore-readonly gateway mode refuses to initialize a missing keyring envelope",
                    ));
                }
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

    if !allow_bootstrap {
        return Err(repository_init(
            "restore-readonly gateway mode refuses first-run repository initialization",
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
                .get_range_at(
                    &metadata.object_id,
                    metadata.version_id.as_ref(),
                    ByteRange::Full,
                )
                .await
                .map_err(repository_init)?;
            open_gateway_keyring_object(
                keys,
                metadata.object_id.clone(),
                metadata.version_id.clone(),
                body,
            )
        }
        _ => Err(repository_init(
            "checkpoint anchor is missing and multiple unanchored keyring envelopes exist; provide an explicit envelope override or recover the anchor",
        )),
    }
}

fn open_gateway_keyring(
    keys: &RepositoryKeysConfig,
    object_id: BackendObjectId,
    version_id: Option<rs3_types::BackendVersionId>,
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
        version_id,
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
    version_id: Option<rs3_types::BackendVersionId>,
    body: Bytes,
) -> Result<LoadedGatewayKeyring, S3BoundaryError> {
    let envelope = KeyringEnvelope::from_object_bytes(&body).map_err(repository_init)?;
    open_gateway_keyring(keys, object_id, version_id, envelope)
}

pub(super) async fn open_gateway_keyring_reference(
    store: &RuntimeStore,
    keys: &RepositoryKeysConfig,
    reference: &KeyringEnvelopeReference,
) -> Result<LoadedGatewayKeyring, S3BoundaryError> {
    let body = store
        .get_range_at(
            &reference.object_id,
            reference.version_id.as_ref(),
            ByteRange::Full,
        )
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
    open_gateway_keyring(
        keys,
        reference.object_id.clone(),
        reference.version_id.clone(),
        envelope,
    )
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

    let loaded = match store.head(object_id).await {
        Ok(metadata) => {
            let body = store
                .get_range_at(object_id, metadata.version_id.as_ref(), ByteRange::Full)
                .await
                .map_err(repository_init)?;
            open_gateway_keyring_object(keys, object_id.clone(), metadata.version_id, body)?
        }
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
        Ok(metadata) => {
            let version_id = retained_version_id(object_id, &metadata, retention, None)
                .map_err(repository_init)?;
            Ok(KeyringEnvelopeReference {
                generation: envelope.generation,
                digest,
                object_id: object_id.clone(),
                version_id,
            })
        }
        Err(StorageError::AlreadyExists(_)) => {
            let metadata = store.head(object_id).await.map_err(repository_init)?;
            let existing = store
                .get_range_at(object_id, metadata.version_id.as_ref(), ByteRange::Full)
                .await
                .map_err(repository_init)?;
            if existing != body {
                return Err(repository_init(format!(
                    "keyring envelope object conflicts with expected content: {object_id}",
                )));
            }
            let version_id = retained_version_id(object_id, &metadata, retention, None)
                .map_err(repository_init)?;
            Ok(KeyringEnvelopeReference {
                generation: envelope.generation,
                digest,
                object_id: object_id.clone(),
                version_id,
            })
        }
        Err(error) => Err(repository_init(error)),
    }
}

fn retained_version_id(
    object_id: &BackendObjectId,
    metadata: &BlobMetadata,
    retention: Option<RetentionPolicy>,
    legal_hold: Option<LegalHoldStatus>,
) -> rs3_storage::Result<Option<rs3_types::BackendVersionId>> {
    if retained_version_required(retention, legal_hold) && metadata.version_id.is_none() {
        return Err(StorageError::MissingVersionId(object_id.clone()));
    }
    Ok(metadata.version_id.clone())
}

pub(super) fn retained_version_required(
    retention: Option<RetentionPolicy>,
    legal_hold: Option<LegalHoldStatus>,
) -> bool {
    retention.is_some_and(|policy| policy.mode != RetentionMode::None && policy.retain_days > 0)
        || legal_hold == Some(LegalHoldStatus::On)
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

pub(super) fn repository_key_context(
    keys: &RepositoryKeysConfig,
) -> Result<RepositoryKeyContext, S3BoundaryError> {
    let salt = repository_salt(&keys.repository_salt_hex)?;
    RepositoryKeyContext::new(keys.repository_id.clone(), salt).map_err(repository_init)
}

pub(super) fn secret_hex(
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
