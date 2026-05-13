//! Explicit checkpoint-anchor recovery from retained backend evidence.

use super::S3BoundaryError;
use super::runtime_builders::{build_anchor, build_store};
use super::runtime_checkpoints::{checkpoint_object_id, read_checkpoint_for_position};
use super::runtime_handles::{RuntimeAnchor, RuntimeStore};
use super::runtime_keyring::open_gateway_keyring_reference;
use crate::RuntimeConfig;
use rs3_anchor::{AnchorError, CheckpointAnchor};
use rs3_index::{
    CHECKPOINT_EVIDENCE_DOMAIN, Checkpoint, CheckpointEvidence, KeyringEnvelopeReference,
};
use rs3_repository::{CheckpointPosition, Repository, RepositoryError, RepositoryOptions};
use rs3_storage::{BlobStore, ByteRange, StorageError};
use rs3_types::{BackendObjectId, RepositoryId};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Schema marker printed with trusted restore bundles.
pub const RESTORE_BUNDLE_SCHEMA: &str = "rs3.restore-bundle.v1";

/// Options for explicit checkpoint-anchor recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorRecoveryOptions {
    /// Maximum accepted age for the signed checkpoint timestamp.
    pub max_checkpoint_age: Duration,
    /// When true, write the validated checkpoint to the configured anchor if it is missing.
    pub apply_if_missing: bool,
}

/// Result of an anchor recovery scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorRecoveryReport {
    /// Highest observed valid checkpoint accepted by the recovery policy.
    pub checkpoint: CheckpointPosition,
    /// Signed checkpoint publish timestamp.
    pub published_at_ms: i64,
    /// Observed evidence objects under `evidence/`.
    pub observed_evidence_objects: usize,
    /// Candidate evidence records that parsed as checkpoint positions.
    pub candidate_count: usize,
    /// True when the configured anchor was written.
    pub applied: bool,
}

/// Trusted restore metadata exported from the configured anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreTrustBundle {
    /// Stable repository identifier bound into keyring unwrap context.
    pub repository_id: RepositoryId,
    /// Stable public repository salt, hex-encoded.
    pub repository_salt_hex: String,
    /// Trusted accepted checkpoint position.
    pub checkpoint: CheckpointPosition,
    /// Signed checkpoint publish timestamp.
    pub published_at_ms: i64,
    /// Active keyring envelope reference bound into the checkpoint.
    pub keyring_envelope: Option<RestoreBundleKeyringEnvelope>,
    /// Bundle creation timestamp.
    pub generated_at_ms: i64,
}

/// Keyring-envelope reference captured in a restore trust bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreBundleKeyringEnvelope {
    /// Envelope generation.
    pub generation: u64,
    /// Backend object containing the encrypted keyring envelope.
    pub object_id: BackendObjectId,
    /// Provider version identifier for exact envelope restore reads, when available.
    pub version_id: Option<rs3_types::BackendVersionId>,
    /// Expected envelope digest.
    pub digest: String,
}

/// Result of importing a trusted checkpoint position into a missing anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorImportReport {
    /// Imported checkpoint position.
    pub checkpoint: CheckpointPosition,
    /// Signed checkpoint publish timestamp.
    pub published_at_ms: i64,
    /// True when the configured anchor was written.
    pub applied: bool,
}

/// Errors returned by explicit anchor recovery.
#[derive(Debug, Error)]
pub enum AnchorRecoveryError {
    /// Runtime construction or repository bootstrap failed.
    #[error(transparent)]
    Runtime(#[from] S3BoundaryError),
    /// The backend did not expose a valid checkpoint candidate.
    #[error("no valid checkpoint evidence was observed in backend storage")]
    NoValidCheckpoint,
    /// The highest valid checkpoint exceeded the configured age bound.
    #[error(
        "highest observed valid checkpoint is too old: age_ms={age_ms}, max_age_ms={max_age_ms}"
    )]
    CheckpointTooOld {
        /// Observed signed checkpoint age in milliseconds.
        age_ms: u128,
        /// Configured maximum age in milliseconds.
        max_age_ms: u128,
    },
    /// The configured anchor already has state.
    #[error(
        "configured checkpoint anchor already exists; recovery apply only writes missing anchors"
    )]
    AnchorAlreadyExists,
    /// The anchor backend rejected recovery.
    #[error(transparent)]
    Anchor(#[from] AnchorError),
    /// Repository verification rejected the candidate.
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

/// Exports a trusted restore bundle from the configured anchor and backend.
pub async fn export_restore_bundle_from_config(
    config: &RuntimeConfig,
) -> Result<RestoreTrustBundle, AnchorRecoveryError> {
    let store = build_store(&config.backend).await?;
    let anchor = build_anchor(&config.anchor)?;
    let position = CheckpointPosition::from(anchor.handle().read().await?);
    restore_bundle_for_position(config, store.handle(), position).await
}

/// Imports a trusted checkpoint position into the configured anchor if it is missing.
pub async fn import_anchor_from_config(
    config: &RuntimeConfig,
    position: CheckpointPosition,
) -> Result<AnchorImportReport, AnchorRecoveryError> {
    let store = build_store(&config.backend).await?;
    let anchor = build_anchor(&config.anchor)?;
    import_anchor_position(config, store.handle(), anchor.handle(), position).await
}

/// Scans backend evidence and optionally writes a missing anchor.
pub async fn recover_anchor_from_config(
    config: &RuntimeConfig,
    options: AnchorRecoveryOptions,
) -> Result<AnchorRecoveryReport, AnchorRecoveryError> {
    let store = build_store(&config.backend).await?;
    let candidates = observed_checkpoint_candidates(store.handle()).await?;
    let observed_evidence_objects = candidates.observed_evidence_objects;
    let candidate_count = candidates.positions.len();

    let mut selected = None;
    for position in candidates.positions {
        match validate_candidate(config, store.handle(), position).await {
            Ok((checkpoint, position)) => {
                selected = Some((checkpoint, position));
                break;
            }
            Err(error) => {
                tracing::warn!(
                    target: "rs3_repository",
                    error = %error,
                    "ignored invalid checkpoint candidate during anchor recovery",
                );
            }
        }
    }

    let Some((checkpoint, position)) = selected else {
        return Err(AnchorRecoveryError::NoValidCheckpoint);
    };
    let age_ms = checkpoint_age_ms(checkpoint.record.published_at_ms);
    let max_age_ms = options.max_checkpoint_age.as_millis();
    if age_ms > max_age_ms {
        return Err(AnchorRecoveryError::CheckpointTooOld { age_ms, max_age_ms });
    }

    let applied = if options.apply_if_missing {
        let anchor = build_anchor(&config.anchor)?;
        write_missing_anchor(anchor.handle(), &position).await?;
        true
    } else {
        false
    };

    Ok(AnchorRecoveryReport {
        checkpoint: position,
        published_at_ms: checkpoint.record.published_at_ms,
        observed_evidence_objects,
        candidate_count,
        applied,
    })
}

async fn restore_bundle_for_position(
    config: &RuntimeConfig,
    store: &RuntimeStore,
    position: CheckpointPosition,
) -> Result<RestoreTrustBundle, AnchorRecoveryError> {
    let (checkpoint, position) = validate_candidate(config, store, position).await?;
    Ok(RestoreTrustBundle {
        repository_id: config.repository_keys.repository_id.clone(),
        repository_salt_hex: config.repository_keys.repository_salt_hex.clone(),
        checkpoint: position,
        published_at_ms: checkpoint.record.published_at_ms,
        keyring_envelope: checkpoint
            .record
            .keyring_envelope
            .as_ref()
            .map(restore_bundle_envelope),
        generated_at_ms: current_time_ms().unwrap_or(checkpoint.record.published_at_ms),
    })
}

fn restore_bundle_envelope(reference: &KeyringEnvelopeReference) -> RestoreBundleKeyringEnvelope {
    RestoreBundleKeyringEnvelope {
        generation: reference.generation,
        object_id: reference.object_id.clone(),
        version_id: reference.version_id.clone(),
        digest: reference.digest.clone(),
    }
}

async fn import_anchor_position(
    config: &RuntimeConfig,
    store: &RuntimeStore,
    anchor: &RuntimeAnchor,
    position: CheckpointPosition,
) -> Result<AnchorImportReport, AnchorRecoveryError> {
    let (checkpoint, position) = validate_candidate(config, store, position).await?;
    write_missing_anchor(anchor, &position).await?;
    Ok(AnchorImportReport {
        checkpoint: position,
        published_at_ms: checkpoint.record.published_at_ms,
        applied: true,
    })
}

async fn write_missing_anchor(
    anchor: &RuntimeAnchor,
    position: &CheckpointPosition,
) -> Result<(), AnchorRecoveryError> {
    match anchor.read().await {
        Ok(_) => return Err(AnchorRecoveryError::AnchorAlreadyExists),
        Err(AnchorError::MissingAnchor) => {}
        Err(error) => return Err(error.into()),
    }
    let advanced = anchor
        .compare_and_advance(position.clone().into_anchor_state())
        .await?;
    if CheckpointPosition::from(advanced) != *position {
        return Err(AnchorRecoveryError::Anchor(AnchorError::Backend(
            "checkpoint anchor accepted a different position".to_owned(),
        )));
    }
    Ok(())
}

struct ObservedCandidates {
    observed_evidence_objects: usize,
    positions: Vec<CheckpointPosition>,
}

async fn observed_checkpoint_candidates(
    store: &RuntimeStore,
) -> Result<ObservedCandidates, AnchorRecoveryError> {
    let evidence = store
        .list_prefix("evidence/")
        .await
        .map_err(storage_runtime_error)?;
    let observed_evidence_objects = evidence.len();
    let mut positions = Vec::new();

    for metadata in evidence {
        let body = store
            .get_range(&metadata.object_id, ByteRange::Full)
            .await
            .map_err(storage_runtime_error)?;
        match checkpoint_position_from_evidence(&body) {
            Ok(position) => positions.push(position),
            Err(error) => {
                tracing::warn!(
                    target: "rs3_repository",
                    object_class = "checkpoint_evidence",
                    error = %error,
                    "ignored malformed checkpoint evidence during anchor recovery",
                );
            }
        }
    }

    positions.sort_by(|left, right| {
        right
            .sequence
            .cmp(&left.sequence)
            .then_with(|| right.checkpoint_id.cmp(&left.checkpoint_id))
    });
    positions.dedup();

    Ok(ObservedCandidates {
        observed_evidence_objects,
        positions,
    })
}

fn checkpoint_position_from_evidence(body: &[u8]) -> Result<CheckpointPosition, S3BoundaryError> {
    let Some(payload) = body.strip_prefix(CHECKPOINT_EVIDENCE_DOMAIN) else {
        return Err(runtime_init("invalid checkpoint evidence object format"));
    };
    let evidence: CheckpointEvidence = serde_json::from_slice(payload).map_err(runtime_init)?;
    let expected_object = checkpoint_object_id(&evidence.checkpoint_id)?;
    if evidence.checkpoint_object_id != expected_object {
        return Err(runtime_init(
            "checkpoint evidence points at an unexpected checkpoint object",
        ));
    }

    Ok(CheckpointPosition {
        sequence: evidence.sequence,
        checkpoint_id: evidence.checkpoint_id,
        checkpoint_version_id: evidence.checkpoint_object_version_id,
        payload_digest: evidence.checkpoint_digest,
    })
}

async fn validate_candidate(
    config: &RuntimeConfig,
    store: &RuntimeStore,
    position: CheckpointPosition,
) -> Result<(Checkpoint, CheckpointPosition), AnchorRecoveryError> {
    let checkpoint = read_checkpoint_for_position(store, &position).await?;
    let reference = checkpoint
        .record
        .keyring_envelope
        .as_ref()
        .ok_or_else(|| runtime_init("checkpoint does not bind a keyring envelope"))?;
    let loaded = open_gateway_keyring_reference(store, &config.repository_keys, reference).await?;
    let repository = Repository::with_keyring_and_options(
        store.clone(),
        loaded.keyring,
        RepositoryOptions {
            payload_segment_size: config.repository.payload_segment_size,
            adaptive_payload_segment_size: config.repository.adaptive_payload_segment_size,
            decrypted_segment_cache_max_bytes: config.repository.decrypted_segment_cache_max_bytes,
            default_retention: config.repository.retention,
        },
    );
    repository
        .set_keyring_envelope_reference(Some(reference.clone()))
        .map_err(AnchorRecoveryError::Repository)?;
    repository.verify_restore(&position).await?;

    Ok((checkpoint, position))
}

fn checkpoint_age_ms(published_at_ms: i64) -> u128 {
    let Some(now_ms) = current_time_ms() else {
        return u128::MAX;
    };
    if published_at_ms >= now_ms {
        return 0;
    }
    u128::try_from(now_ms.saturating_sub(published_at_ms)).unwrap_or(u128::MAX)
}

fn current_time_ms() -> Option<i64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis();
    i64::try_from(millis).ok()
}

fn storage_runtime_error(error: StorageError) -> AnchorRecoveryError {
    runtime_init(error).into()
}

fn runtime_init(error: impl ToString) -> S3BoundaryError {
    S3BoundaryError::RepositoryInit {
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RuntimeAnchor, RuntimeStore, import_anchor_position, observed_checkpoint_candidates,
        restore_bundle_for_position, validate_candidate,
    };
    use crate::s3::test_support::runtime_config;
    use bytes::Bytes;
    use rs3_anchor::{CheckpointAnchor, MemoryCheckpointAnchor};
    use rs3_crypto::{KeyRing, RepositoryKeyContext, SecretBytes};
    use rs3_repository::{Repository, RepositoryOptions, RepositoryPutOptions};
    use rs3_storage::MemoryBlobStore;
    use rs3_types::{LogicalPath, Sequence};

    const WRAPPING_KEY_HEX: &str =
        "3333333333333333333333333333333333333333333333333333333333333333";

    #[tokio::test]
    async fn recovery_scan_finds_highest_observed_valid_checkpoint() {
        let mut config = runtime_config(true);
        config.repository_keys.wrapping_key_hex = secrecy::SecretString::from(WRAPPING_KEY_HEX);
        let store = MemoryBlobStore::new();
        let keyring = KeyRing::generate_random().unwrap_or_else(|error| panic!("{error}"));
        let context = RepositoryKeyContext::new(
            config.repository_keys.repository_id.clone(),
            hex::decode(&config.repository_keys.repository_salt_hex)
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let wrapping_key = SecretBytes::new(
            hex::decode(WRAPPING_KEY_HEX).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let envelope = keyring
            .seal_keyring_envelope(&context, "wrap-v1", &wrapping_key, 1)
            .unwrap_or_else(|error| panic!("{error}"));
        let repo = Repository::with_keyring_and_options(
            store.clone(),
            keyring,
            RepositoryOptions {
                payload_segment_size: config.repository.payload_segment_size,
                adaptive_payload_segment_size: config.repository.adaptive_payload_segment_size,
                decrypted_segment_cache_max_bytes: config
                    .repository
                    .decrypted_segment_cache_max_bytes,
                default_retention: config.repository.retention,
            },
        );
        repo.store_keyring_envelope(&envelope)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let anchor = MemoryCheckpointAnchor::new();
        repo.put_committed(
            LogicalPath::new("backup/a").unwrap_or_else(|error| panic!("{error}")),
            Bytes::from_static(b"a"),
            RepositoryPutOptions::default(),
            &anchor,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let second = repo
            .put_committed(
                LogicalPath::new("backup/b").unwrap_or_else(|error| panic!("{error}")),
                Bytes::from_static(b"b"),
                RepositoryPutOptions::default(),
                &anchor,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime_store = RuntimeStore::new(store);

        let candidates = observed_checkpoint_candidates(&runtime_store)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let (checkpoint, position) = validate_candidate(
            &config,
            &runtime_store,
            candidates
                .positions
                .first()
                .cloned()
                .unwrap_or_else(|| panic!("missing recovery candidate")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let report = super::AnchorRecoveryReport {
            checkpoint: position,
            published_at_ms: checkpoint.record.published_at_ms,
            observed_evidence_objects: candidates.observed_evidence_objects,
            candidate_count: candidates.positions.len(),
            applied: false,
        };

        assert_eq!(report.checkpoint.sequence, Sequence::new(2));
        assert_eq!(report.checkpoint, second.checkpoint);
        assert!(!report.applied);

        let bundle =
            restore_bundle_for_position(&config, &runtime_store, second.checkpoint.clone())
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(bundle.checkpoint, second.checkpoint);
        assert_eq!(
            bundle.repository_salt_hex,
            config.repository_keys.repository_salt_hex
        );
        assert!(bundle.keyring_envelope.is_some());

        let import_anchor = RuntimeAnchor::new(MemoryCheckpointAnchor::new());
        let imported = import_anchor_position(
            &config,
            &runtime_store,
            &import_anchor,
            bundle.checkpoint.clone(),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(imported.checkpoint, bundle.checkpoint);
        let imported_anchor_state = import_anchor
            .read()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            rs3_repository::CheckpointPosition::from(imported_anchor_state),
            bundle.checkpoint
        );
    }
}
