use super::runtime_handles::RuntimeStore;
use super::{S3BoundaryError, repository_init};
use rs3_crypto::{derive_checkpoint_id, derive_checkpoint_payload_digest};
use rs3_index::{
    CHECKPOINT_EVIDENCE_DOMAIN, CHECKPOINT_OBJECT_DOMAIN, Checkpoint, CheckpointEvidence,
    KeyringEnvelopeReference, canonical_commit_record_bytes, checkpoint_evidence_bytes,
};
use rs3_repository::CheckpointPosition;
use rs3_storage::{BlobStore, ByteRange};
use rs3_types::BackendObjectId;

const CHECKPOINT_EVIDENCE_OBJECT_PREFIX: &str = "evidence/";

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
        .get_range_at(
            &object_id,
            accepted.checkpoint_version_id.as_ref(),
            ByteRange::Full,
        )
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

pub(super) fn checkpoint_evidence_object_id(
    position: &CheckpointPosition,
) -> Result<BackendObjectId, S3BoundaryError> {
    BackendObjectId::new(format!(
        "{CHECKPOINT_EVIDENCE_OBJECT_PREFIX}{:020}/{}",
        position.sequence.get(),
        position.checkpoint_id.as_str()
    ))
    .map_err(repository_init)
}

pub(super) async fn validate_storage_evidence(
    store: &RuntimeStore,
    accepted: &CheckpointPosition,
) -> Result<(), S3BoundaryError> {
    verify_checkpoint_evidence_object(store, accepted).await?;
    reject_newer_storage_evidence(store, accepted).await
}

async fn verify_checkpoint_evidence_object(
    store: &RuntimeStore,
    accepted: &CheckpointPosition,
) -> Result<(), S3BoundaryError> {
    let object_id = checkpoint_evidence_object_id(accepted)?;
    let expected = checkpoint_evidence_body(accepted)?;
    let body = store
        .get_range(&object_id, ByteRange::Full)
        .await
        .map_err(repository_init)?;
    if !body.starts_with(CHECKPOINT_EVIDENCE_DOMAIN) || body.as_ref() != expected.as_slice() {
        return Err(repository_init(
            "checkpoint evidence object does not match the accepted anchor position",
        ));
    }
    Ok(())
}

async fn reject_newer_storage_evidence(
    store: &RuntimeStore,
    accepted: &CheckpointPosition,
) -> Result<(), S3BoundaryError> {
    let evidence = store
        .list_prefix(CHECKPOINT_EVIDENCE_OBJECT_PREFIX)
        .await
        .map_err(repository_init)?;
    for metadata in evidence {
        if evidence_object_sequence(&metadata.object_id)
            .is_none_or(|sequence| sequence <= accepted.sequence.get())
        {
            continue;
        }
        let body = store
            .get_range(&metadata.object_id, ByteRange::Full)
            .await
            .map_err(repository_init)?;
        match checkpoint_position_from_evidence_object(&metadata.object_id, &body) {
            Ok(position) if position.sequence.get() > accepted.sequence.get() => {
                return Err(repository_init(
                    "storage checkpoint evidence is newer than the accepted anchor position; run explicit recovery before serving",
                ));
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    target: "rs3_repository",
                    object_class = "checkpoint_evidence",
                    object_id = metadata.object_id.as_str(),
                    error = %error,
                    "ignored malformed newer checkpoint evidence during startup validation",
                );
            }
        }
    }
    Ok(())
}

fn checkpoint_evidence_body(position: &CheckpointPosition) -> Result<Vec<u8>, S3BoundaryError> {
    checkpoint_evidence_bytes(&CheckpointEvidence {
        sequence: position.sequence,
        checkpoint_id: position.checkpoint_id.clone(),
        checkpoint_digest: position.payload_digest.clone(),
        checkpoint_object_id: checkpoint_object_id(&position.checkpoint_id)?,
        checkpoint_object_version_id: position.checkpoint_version_id.clone(),
    })
    .map_err(repository_init)
}

fn checkpoint_position_from_evidence_object(
    object_id: &BackendObjectId,
    body: &[u8],
) -> Result<CheckpointPosition, S3BoundaryError> {
    let Some(payload) = body.strip_prefix(CHECKPOINT_EVIDENCE_DOMAIN) else {
        return Err(repository_init("invalid checkpoint evidence object format"));
    };
    let evidence: CheckpointEvidence = serde_json::from_slice(payload).map_err(repository_init)?;
    let position = CheckpointPosition {
        sequence: evidence.sequence,
        checkpoint_id: evidence.checkpoint_id,
        checkpoint_version_id: evidence.checkpoint_object_version_id,
        payload_digest: evidence.checkpoint_digest,
    };
    if evidence.checkpoint_object_id != checkpoint_object_id(&position.checkpoint_id)?
        || checkpoint_evidence_object_id(&position)? != *object_id
    {
        return Err(repository_init(
            "checkpoint evidence object does not match its object name",
        ));
    }
    Ok(position)
}

fn evidence_object_sequence(object_id: &BackendObjectId) -> Option<u64> {
    object_id
        .as_str()
        .strip_prefix(CHECKPOINT_EVIDENCE_OBJECT_PREFIX)?
        .split_once('/')?
        .0
        .parse()
        .ok()
}

pub(super) async fn repository_has_committed_objects(
    store: &RuntimeStore,
) -> Result<bool, S3BoundaryError> {
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
