//! Explicit checkpoint-anchor recovery from retained backend evidence.

use super::S3BoundaryError;
use super::runtime::{
    RuntimeStore, build_anchor, build_store, checkpoint_object_id, open_gateway_keyring_reference,
    read_checkpoint_for_position,
};
use crate::RuntimeConfig;
use rs3_anchor::{AnchorError, CheckpointAnchor};
use rs3_index::{CHECKPOINT_EVIDENCE_DOMAIN, Checkpoint, CheckpointEvidence};
use rs3_repository::{CheckpointPosition, Repository, RepositoryError, RepositoryOptions};
use rs3_storage::{BlobStore, ByteRange, StorageError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

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

/// Scans backend evidence and optionally writes a missing anchor.
pub async fn recover_anchor_from_config(
    config: &RuntimeConfig,
    options: AnchorRecoveryOptions,
) -> Result<AnchorRecoveryReport, AnchorRecoveryError> {
    let store = build_store(&config.backend).await?;
    let candidates = observed_checkpoint_candidates(&store.handle).await?;
    let observed_evidence_objects = candidates.observed_evidence_objects;
    let candidate_count = candidates.positions.len();

    let mut selected = None;
    for position in candidates.positions {
        match validate_candidate(config, &store.handle, position).await {
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
        match anchor.handle.read().await {
            Ok(_) => return Err(AnchorRecoveryError::AnchorAlreadyExists),
            Err(AnchorError::MissingAnchor) => {}
            Err(error) => return Err(error.into()),
        }
        let advanced = anchor
            .handle
            .compare_and_advance(position.clone().into_anchor_state())
            .await?;
        if CheckpointPosition::from(advanced) != position {
            return Err(AnchorRecoveryError::Anchor(AnchorError::Backend(
                "checkpoint anchor accepted a different position".to_owned(),
            )));
        }
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
    use super::{RuntimeStore, observed_checkpoint_candidates, validate_candidate};
    use crate::s3::test_support::runtime_config;
    use bytes::Bytes;
    use rs3_anchor::MemoryCheckpointAnchor;
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
    }
}
