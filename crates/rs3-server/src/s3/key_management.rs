//! Explicit repository key lifecycle operations.

use super::runtime_builders::{build_anchor, build_store};
use super::runtime_checkpoints::{read_checkpoint_for_position, validate_storage_evidence};
use super::runtime_handles::{RuntimeAnchor, RuntimeStore};
use super::runtime_keyring::{gateway_keyring, repository_key_context, secret_hex};
use super::{S3BoundaryError, repository_init};
use crate::RuntimeConfig;
use crate::config::KEYRING_WRAPPING_KEY_HEX_ENV;
use rs3_anchor::{AnchorError, CheckpointAnchor};
use rs3_crypto::CryptoError;
use rs3_index::KeyringEnvelopeReference;
use rs3_repository::{CheckpointPosition, Repository, RepositoryError, RepositoryOptions};
use rs3_types::{KeyId, KeyPurpose, Sequence};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Options for a repository data-key rotation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRotationOptions {
    /// Purpose to rotate.
    pub purpose: KeyPurpose,
    /// Optional operator-selected key ID. When omitted, rs3 derives one from
    /// the purpose and next envelope generation.
    pub new_key_id: Option<KeyId>,
}

/// Result of an accepted key rotation checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRotationReport {
    /// Rotated key purpose.
    pub purpose: KeyPurpose,
    /// Previous primary key ID, now enabled for historical reads or verification.
    pub old_primary_key_id: KeyId,
    /// New primary key ID used for future writes or signatures.
    pub new_primary_key_id: KeyId,
    /// Sequence reserved for the metadata-only keyring checkpoint.
    pub staged_sequence: Sequence,
    /// Checkpoint that made the keyring update accepted repository state.
    pub checkpoint: CheckpointPosition,
    /// Signed checkpoint publish timestamp.
    pub published_at_ms: i64,
    /// Keyring envelope bound by the accepted checkpoint.
    pub keyring_envelope: RotatedKeyringEnvelope,
}

/// Public keyring-envelope reference for a rotation report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotatedKeyringEnvelope {
    /// Envelope generation.
    pub generation: u64,
    /// Backend object containing the encrypted keyring envelope.
    pub object_id: rs3_types::BackendObjectId,
    /// Provider version identifier for exact envelope restore reads, when available.
    pub version_id: Option<rs3_types::BackendVersionId>,
    /// Expected envelope digest.
    pub digest: String,
}

/// Errors returned by key lifecycle operations.
#[derive(Debug, Error)]
pub enum KeyRotationError {
    /// Runtime construction or validation failed.
    #[error(transparent)]
    Runtime(#[from] S3BoundaryError),
    /// The configured anchor could not be read or advanced.
    #[error(transparent)]
    Anchor(#[from] AnchorError),
    /// Repository verification or checkpoint publication failed.
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    /// Keyring rotation or envelope sealing failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// Rotates one purpose-specific repository key and publishes the checkpoint.
pub async fn rotate_key_from_config(
    config: &RuntimeConfig,
    options: KeyRotationOptions,
) -> Result<KeyRotationReport, KeyRotationError> {
    let store = build_store(&config.backend).await?;
    let anchor = build_anchor(&config.anchor)?;
    rotate_key(config, store.into_handle(), anchor.into_handle(), options).await
}

async fn rotate_key(
    config: &RuntimeConfig,
    store: RuntimeStore,
    anchor: RuntimeAnchor,
    options: KeyRotationOptions,
) -> Result<KeyRotationReport, KeyRotationError> {
    if !config.mode.allows_mutation() {
        return Err(repository_init(
            "key rotation requires read-write gateway mode because it publishes a checkpoint",
        )
        .into());
    }

    let accepted = match anchor.read().await {
        Ok(state) => CheckpointPosition::from(state),
        Err(AnchorError::MissingAnchor) => {
            return Err(
                repository_init("key rotation requires an accepted checkpoint anchor").into(),
            );
        }
        Err(error) => return Err(error.into()),
    };

    validate_storage_evidence(&store, &accepted).await?;
    let loaded = gateway_keyring(
        &store,
        &anchor,
        &config.repository_keys,
        config.repository.retention,
        false,
    )
    .await?;
    if loaded.pending_envelope_override.is_some() {
        return Err(repository_init(
            "configured keyring envelope override is not checkpoint-bound; clear or publish it before rotating data keys",
        )
        .into());
    }
    let active_reference = loaded
        .envelope_reference
        .clone()
        .ok_or_else(|| repository_init("accepted checkpoint did not bind a keyring envelope"))?;

    let repository = Repository::with_keyring_and_options(
        store.clone(),
        loaded.keyring.clone(),
        RepositoryOptions {
            payload_segment_size: config.repository.payload_segment_size,
            adaptive_payload_segment_size: config.repository.adaptive_payload_segment_size,
            decrypted_segment_cache_max_bytes: config.repository.decrypted_segment_cache_max_bytes,
            default_retention: config.repository.retention,
        },
    );
    repository.set_keyring_envelope_reference(Some(active_reference.clone()))?;
    repository.load_checkpoint_position(&accepted).await?;

    let old_primary_key_id = loaded.keyring.primary_key_id(options.purpose)?;
    let new_generation = active_reference
        .generation
        .checked_add(1)
        .ok_or_else(|| repository_init("keyring envelope generation overflowed"))?;
    let new_key_id = match options.new_key_id {
        Some(key_id) => key_id,
        None => default_rotated_key_id(options.purpose, new_generation)?,
    };
    let rotated_keyring = loaded.keyring.rotate_purpose_key(
        options.purpose,
        new_key_id.clone(),
        current_time_ms(),
    )?;
    let context = repository_key_context(&config.repository_keys)?;
    let wrapping_key = secret_hex(
        KEYRING_WRAPPING_KEY_HEX_ENV,
        &config.repository_keys.wrapping_key_hex,
    )?;
    let envelope = rotated_keyring.seal_keyring_envelope(
        &context,
        &config.repository_keys.wrapping_key_id,
        &wrapping_key,
        new_generation,
    )?;
    let (reference, staged_sequence) = repository
        .store_keyring_update(rotated_keyring, &envelope)
        .await?;
    let checkpoint = repository.publish_checkpoint(&anchor).await?;
    if checkpoint.sequence != staged_sequence {
        return Err(repository_init(
            "key rotation checkpoint sequence differed from the staged metadata sequence",
        )
        .into());
    }
    let checkpoint_object = read_checkpoint_for_position(&store, &checkpoint).await?;

    Ok(KeyRotationReport {
        purpose: options.purpose,
        old_primary_key_id,
        new_primary_key_id: new_key_id,
        staged_sequence,
        checkpoint,
        published_at_ms: checkpoint_object.record.published_at_ms,
        keyring_envelope: envelope_report(reference),
    })
}

fn envelope_report(reference: KeyringEnvelopeReference) -> RotatedKeyringEnvelope {
    RotatedKeyringEnvelope {
        generation: reference.generation,
        object_id: reference.object_id,
        version_id: reference.version_id,
        digest: reference.digest,
    }
}

fn default_rotated_key_id(purpose: KeyPurpose, generation: u64) -> Result<KeyId, KeyRotationError> {
    KeyId::new(format!("{}-v{generation}", purpose_name(purpose))).map_err(|error| {
        KeyRotationError::Runtime(repository_init(format!(
            "failed to create default rotated key id: {error}"
        )))
    })
}

pub(crate) fn purpose_name(purpose: KeyPurpose) -> &'static str {
    match purpose {
        KeyPurpose::Namespace => "namespace",
        KeyPurpose::Content => "content",
        KeyPurpose::Metadata => "metadata",
        KeyPurpose::CheckpointSigning => "checkpoint",
    }
}

fn current_time_ms() -> i64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis();
    i64::try_from(millis).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{KeyRotationOptions, rotate_key};
    use crate::config::KEYRING_WRAPPING_KEY_HEX_ENV;
    use crate::s3::runtime_checkpoints::read_checkpoint_for_position;
    use crate::s3::runtime_handles::{RuntimeAnchor, RuntimeStore};
    use crate::s3::runtime_keyring::{repository_key_context, secret_hex};
    use crate::s3::test_support::runtime_config;
    use bytes::Bytes;
    use rs3_anchor::MemoryCheckpointAnchor;
    use rs3_crypto::KeyRing;
    use rs3_repository::{Repository, RepositoryOptions, RepositoryPutOptions};
    use rs3_storage::MemoryBlobStore;
    use rs3_types::{KeyId, KeyPurpose, LogicalPath, Sequence};

    #[tokio::test]
    async fn rotate_key_publishes_checkpoint_bound_envelope() {
        let config = runtime_config(false);
        let store = RuntimeStore::new(MemoryBlobStore::new());
        let anchor = RuntimeAnchor::new(MemoryCheckpointAnchor::new());
        let initial_keyring = match KeyRing::generate_random() {
            Ok(keyring) => keyring,
            Err(error) => panic!("{error}"),
        };
        let context = match repository_key_context(&config.repository_keys) {
            Ok(context) => context,
            Err(error) => panic!("{error}"),
        };
        let wrapping_key = match secret_hex(
            KEYRING_WRAPPING_KEY_HEX_ENV,
            &config.repository_keys.wrapping_key_hex,
        ) {
            Ok(secret) => secret,
            Err(error) => panic!("{error}"),
        };
        let envelope = match initial_keyring.seal_keyring_envelope(
            &context,
            &config.repository_keys.wrapping_key_id,
            &wrapping_key,
            1,
        ) {
            Ok(envelope) => envelope,
            Err(error) => panic!("{error}"),
        };
        let repository = Repository::with_keyring_and_options(
            store.clone(),
            initial_keyring,
            RepositoryOptions {
                payload_segment_size: config.repository.payload_segment_size,
                adaptive_payload_segment_size: config.repository.adaptive_payload_segment_size,
                decrypted_segment_cache_max_bytes: config
                    .repository
                    .decrypted_segment_cache_max_bytes,
                default_retention: config.repository.retention,
            },
        );
        let reference = match repository.store_keyring_envelope(&envelope).await {
            Ok(reference) => reference,
            Err(error) => panic!("{error}"),
        };
        assert_eq!(reference.generation, 1);
        let key = match LogicalPath::new("p/12/seed") {
            Ok(key) => key,
            Err(error) => panic!("{error}"),
        };
        let put = repository
            .put(
                key,
                Bytes::from_static(b"seed"),
                RepositoryPutOptions::default(),
            )
            .await;
        assert!(put.is_ok());
        let first = match repository.publish_checkpoint(&anchor).await {
            Ok(position) => position,
            Err(error) => panic!("{error}"),
        };
        assert_eq!(first.sequence, Sequence::new(1));

        let report = match rotate_key(
            &config,
            store.clone(),
            anchor.clone(),
            KeyRotationOptions {
                purpose: KeyPurpose::Content,
                new_key_id: None,
            },
        )
        .await
        {
            Ok(report) => report,
            Err(error) => panic!("{error}"),
        };

        let checkpoint = match read_checkpoint_for_position(&store, &report.checkpoint).await {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("{error}"),
        };

        assert_eq!(report.old_primary_key_id, key_id("content-v1"));
        assert_eq!(report.new_primary_key_id, key_id("content-v2"));
        assert_eq!(report.staged_sequence, Sequence::new(2));
        assert_eq!(report.checkpoint.sequence, Sequence::new(2));
        assert_eq!(report.keyring_envelope.generation, 2);
        assert_eq!(
            checkpoint
                .record
                .keyring
                .primary_for(KeyPurpose::Content)
                .map(|descriptor| descriptor.id.clone()),
            Some(key_id("content-v2"))
        );
        assert_eq!(
            checkpoint.record.keyring_envelope.as_ref().map(|envelope| {
                (
                    envelope.generation,
                    envelope.object_id.clone(),
                    envelope.version_id.clone(),
                    envelope.digest.clone(),
                )
            }),
            Some((
                report.keyring_envelope.generation,
                report.keyring_envelope.object_id.clone(),
                report.keyring_envelope.version_id.clone(),
                report.keyring_envelope.digest.clone(),
            ))
        );
    }

    fn key_id(value: &str) -> KeyId {
        match KeyId::new(value) {
            Ok(key_id) => key_id,
            Err(error) => panic!("{error}"),
        }
    }
}
