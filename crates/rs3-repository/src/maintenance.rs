//! Dry-run repository maintenance reports.

use crate::checkpoint::{
    CHECKPOINT_EVIDENCE_PREFIX, CHECKPOINT_OBJECT_PREFIX, KEYRING_ENVELOPE_OBJECT_PREFIX,
    checkpoint_evidence_object_id, checkpoint_object_id, open_index_delta_object,
    open_manifest_record, validate_checkpoint_published_at,
};
use crate::error::{RepositoryError, Result};
use crate::model::{
    BackendObjectReferenceKind, CheckpointPosition, ReachableBackendObject,
    RepositoryOrphanCandidate, RepositoryOrphanDeleteReport, RepositoryOrphanReport,
    RestoreProtectionSummary, RestoreVerificationReport,
};
use crate::payload::{open_payload_object, parse_segmented_payload_header};
use crate::service::Repository;
use rs3_crypto::KeyringEnvelope;
use rs3_index::{
    CHECKPOINT_EVIDENCE_DOMAIN, CheckpointEvidence, IndexDelta, IndexDeltaObject,
    checkpoint_evidence_bytes,
};
use rs3_storage::{BlobStore, ByteRange, StorageError};
use rs3_types::{BackendObjectId, KeyId, LegalHoldStatus, RetentionMode};
use std::collections::BTreeSet;

const INDEX_DELTA_OBJECT_PREFIX: &str = "index/";
const PAYLOAD_OBJECT_PREFIX: &str = "segments/";

impl<S> Repository<S>
where
    S: BlobStore,
{
    /// Returns backend objects referenced by an accepted checkpoint chain.
    pub async fn reachable_backend_objects(
        &self,
        accepted: &CheckpointPosition,
    ) -> Result<Vec<ReachableBackendObject>> {
        let checkpoints = self.read_checkpoint_chain(&accepted.checkpoint_id).await?;
        let mut previous = None;
        let mut reachable = BTreeSet::new();

        for checkpoint in checkpoints.into_iter().rev() {
            let position = self.verify_signed_checkpoint(&checkpoint, previous.as_ref())?;
            reachable.insert(ReachableBackendObject {
                object_id: checkpoint_object_id(&checkpoint.id)?,
                kind: BackendObjectReferenceKind::Checkpoint,
            });
            reachable.insert(ReachableBackendObject {
                object_id: checkpoint_evidence_object_id(&position)?,
                kind: BackendObjectReferenceKind::CheckpointEvidence,
            });

            for object_id in &checkpoint.record.index_deltas {
                reachable.insert(ReachableBackendObject {
                    object_id: object_id.clone(),
                    kind: BackendObjectReferenceKind::IndexDelta,
                });

                let delta = self.read_index_delta_object(object_id).await?;
                insert_delta_payload_references(&mut reachable, delta);
            }

            if let Some(delta) = self.open_inline_index_delta_object(&checkpoint)? {
                insert_delta_payload_references(&mut reachable, delta);
            }

            if let Some(envelope) = checkpoint.record.keyring_envelope.as_ref() {
                reachable.insert(ReachableBackendObject {
                    object_id: envelope.object_id.clone(),
                    kind: BackendObjectReferenceKind::KeyringEnvelope,
                });
            }

            previous = Some(position);
        }

        let Some(loaded) = previous else {
            return Err(RepositoryError::CheckpointConflict {
                checkpoint_id: accepted.checkpoint_id.clone(),
            });
        };

        if &loaded != accepted {
            return Err(RepositoryError::CheckpointConflict {
                checkpoint_id: accepted.checkpoint_id.clone(),
            });
        }

        Ok(reachable.into_iter().collect())
    }

    /// Builds a dry-run report for objects not referenced by an accepted chain.
    pub async fn orphan_report(
        &self,
        accepted: &CheckpointPosition,
    ) -> Result<RepositoryOrphanReport> {
        let reachable = self.reachable_backend_objects(accepted).await?;
        let reachable_ids = reachable
            .iter()
            .map(|object| object.object_id.clone())
            .collect::<BTreeSet<BackendObjectId>>();
        let mut candidates = Vec::new();

        for (prefix, kind) in [
            (
                CHECKPOINT_OBJECT_PREFIX,
                BackendObjectReferenceKind::Checkpoint,
            ),
            (
                CHECKPOINT_EVIDENCE_PREFIX,
                BackendObjectReferenceKind::CheckpointEvidence,
            ),
            (
                KEYRING_ENVELOPE_OBJECT_PREFIX,
                BackendObjectReferenceKind::KeyringEnvelope,
            ),
            (
                INDEX_DELTA_OBJECT_PREFIX,
                BackendObjectReferenceKind::IndexDelta,
            ),
            (PAYLOAD_OBJECT_PREFIX, BackendObjectReferenceKind::Payload),
        ] {
            for metadata in self.store.list_prefix(prefix).await? {
                if !reachable_ids.contains(&metadata.object_id) {
                    candidates.push(RepositoryOrphanCandidate::from_metadata(metadata, kind));
                }
            }
        }

        candidates.sort_by(|left, right| left.object_id.cmp(&right.object_id));

        Ok(RepositoryOrphanReport {
            reachable,
            candidates,
        })
    }

    /// Deletes orphan candidates that are not protected by retention or legal hold.
    ///
    /// Reachability is derived from the accepted checkpoint chain before any
    /// delete is attempted. Objects with known retention or legal hold are
    /// skipped, and provider-reported retention or legal-hold failures are
    /// counted as blocked rather than escalated.
    pub async fn delete_unprotected_orphans(
        &self,
        accepted: &CheckpointPosition,
    ) -> Result<RepositoryOrphanDeleteReport> {
        let report = self.orphan_report(accepted).await?;
        let mut delete_report = RepositoryOrphanDeleteReport {
            reachable_count: report.reachable.len(),
            candidate_count: report.candidates.len(),
            deleted_count: 0,
            already_gone_count: 0,
            retention_blocked_count: 0,
            legal_hold_blocked_count: 0,
        };

        for candidate in report.candidates {
            if candidate.delete_blocked_by_retention {
                delete_report.retention_blocked_count =
                    delete_report.retention_blocked_count.saturating_add(1);
                continue;
            }
            if candidate.delete_blocked_by_legal_hold {
                delete_report.legal_hold_blocked_count =
                    delete_report.legal_hold_blocked_count.saturating_add(1);
                continue;
            }

            match self.store.delete(&candidate.object_id).await {
                Ok(()) => {
                    delete_report.deleted_count = delete_report.deleted_count.saturating_add(1);
                }
                Err(StorageError::NotFound(_)) => {
                    delete_report.already_gone_count =
                        delete_report.already_gone_count.saturating_add(1);
                }
                Err(StorageError::RetentionBlocked) => {
                    delete_report.retention_blocked_count =
                        delete_report.retention_blocked_count.saturating_add(1);
                }
                Err(StorageError::LegalHoldBlocked) => {
                    delete_report.legal_hold_blocked_count =
                        delete_report.legal_hold_blocked_count.saturating_add(1);
                }
                Err(error) => return Err(error.into()),
            }
        }

        Ok(delete_report)
    }

    /// Verifies that an accepted checkpoint chain can be used for restore.
    ///
    /// This reads and verifies every checkpoint, checkpoint evidence object,
    /// referenced keyring envelope, index delta, embedded manifest, and unique
    /// payload object reachable from the accepted checkpoint chain. The report
    /// intentionally contains counts, byte totals, and key IDs, not logical
    /// paths or backend object IDs.
    pub async fn verify_restore(
        &self,
        accepted: &CheckpointPosition,
    ) -> Result<RestoreVerificationReport> {
        let checkpoints = self.read_checkpoint_chain(&accepted.checkpoint_id).await?;
        let keyring = self.keyring()?;
        let mut previous = None;
        let mut previous_published_at_ms = None;
        let mut checkpoint_count = 0;
        let mut checkpoint_evidence_count = 0;
        let mut index_delta_object_count = 0;
        let mut inline_index_delta_count = 0;
        let mut verified_keyring_envelopes = BTreeSet::new();
        let mut verified_payloads = BTreeSet::new();
        let mut payload_plaintext_bytes = 0_u64;
        let mut required_key_ids = BTreeSet::new();
        let mut protection = RestoreProtectionSummary::default();

        for checkpoint in checkpoints.into_iter().rev() {
            validate_checkpoint_published_at(&checkpoint, previous_published_at_ms)?;
            let position = self.verify_signed_checkpoint(&checkpoint, previous.as_ref())?;
            let checkpoint_backend_object_id = checkpoint_object_id(&checkpoint.id)?;
            summarize_object_protection(self, &checkpoint_backend_object_id, &mut protection)
                .await?;
            required_key_ids.insert(checkpoint.signature_key_id.clone());
            let evidence_object_id = verify_checkpoint_evidence_object(self, &position).await?;
            summarize_object_protection(self, &evidence_object_id, &mut protection).await?;
            checkpoint_count += 1;
            checkpoint_evidence_count += 1;

            if let Some(envelope) = checkpoint.record.keyring_envelope.as_ref()
                && verified_keyring_envelopes.insert(envelope.object_id.clone())
            {
                verify_keyring_envelope_object(self, envelope).await?;
                summarize_object_protection(self, &envelope.object_id, &mut protection).await?;
            }

            for object_id in &checkpoint.record.index_deltas {
                summarize_object_protection(self, object_id, &mut protection).await?;
                let sealed_delta = self.read_sealed_index_delta_object(object_id).await?;
                required_key_ids.insert(sealed_delta.key_id.clone());
                let delta = open_index_delta_object(&keyring, object_id, &sealed_delta)?;
                verify_index_delta_payloads(
                    self,
                    &keyring,
                    delta,
                    &mut verified_payloads,
                    &mut payload_plaintext_bytes,
                    &mut required_key_ids,
                    &mut protection,
                )
                .await?;
                index_delta_object_count += 1;
            }

            if let Some(sealed_delta) = checkpoint.record.inline_index_delta.as_ref() {
                required_key_ids.insert(sealed_delta.key_id.clone());
                let delta = self.open_inline_index_delta_object(&checkpoint)?;
                let Some(delta) = delta else {
                    return Err(RepositoryError::InvalidObjectFormat {
                        object_id: checkpoint_object_id(&checkpoint.id)?,
                    });
                };
                verify_index_delta_payloads(
                    self,
                    &keyring,
                    delta,
                    &mut verified_payloads,
                    &mut payload_plaintext_bytes,
                    &mut required_key_ids,
                    &mut protection,
                )
                .await?;
                inline_index_delta_count += 1;
            }

            previous_published_at_ms = Some(checkpoint.record.published_at_ms);
            previous = Some(position);
        }

        let Some(loaded) = previous else {
            return Err(RepositoryError::CheckpointConflict {
                checkpoint_id: accepted.checkpoint_id.clone(),
            });
        };

        if &loaded != accepted {
            return Err(RepositoryError::CheckpointConflict {
                checkpoint_id: accepted.checkpoint_id.clone(),
            });
        }

        Ok(RestoreVerificationReport {
            accepted: loaded,
            checkpoint_count,
            checkpoint_evidence_count,
            index_delta_object_count,
            inline_index_delta_count,
            keyring_envelope_count: verified_keyring_envelopes.len(),
            payload_object_count: verified_payloads.len(),
            payload_plaintext_bytes,
            required_key_ids: required_key_ids.into_iter().collect(),
            protection,
        })
    }
}

fn insert_delta_payload_references(
    reachable: &mut BTreeSet<ReachableBackendObject>,
    delta: rs3_index::IndexDeltaObject,
) {
    for mutation in delta.deltas {
        if let IndexDelta::Upsert { entry, .. } = mutation {
            reachable.insert(ReachableBackendObject {
                object_id: entry.object_id,
                kind: BackendObjectReferenceKind::Payload,
            });
        }
    }
}

async fn verify_checkpoint_evidence_object<S>(
    repo: &Repository<S>,
    position: &CheckpointPosition,
) -> Result<BackendObjectId>
where
    S: BlobStore,
{
    let object_id = checkpoint_evidence_object_id(position)?;
    let expected = checkpoint_evidence_bytes(&CheckpointEvidence {
        sequence: position.sequence,
        checkpoint_id: position.checkpoint_id.clone(),
        checkpoint_digest: position.payload_digest.clone(),
        checkpoint_object_id: checkpoint_object_id(&position.checkpoint_id)?,
    })?;
    let body = repo.store.get_range(&object_id, ByteRange::Full).await?;
    if !body.starts_with(CHECKPOINT_EVIDENCE_DOMAIN) || body.as_ref() != expected.as_slice() {
        return Err(RepositoryError::CheckpointEvidenceObjectConflict { object_id });
    }

    Ok(object_id)
}

async fn verify_keyring_envelope_object<S>(
    repo: &Repository<S>,
    reference: &rs3_index::KeyringEnvelopeReference,
) -> Result<()>
where
    S: BlobStore,
{
    let body = repo
        .store
        .get_range(&reference.object_id, ByteRange::Full)
        .await?;
    let envelope = KeyringEnvelope::from_object_bytes(&body)?;
    let digest = envelope.digest()?;
    if envelope.generation != reference.generation || digest != reference.digest {
        return Err(RepositoryError::KeyringEnvelopeObjectConflict {
            object_id: reference.object_id.clone(),
        });
    }

    Ok(())
}

async fn verify_index_delta_payloads<S>(
    repo: &Repository<S>,
    keyring: &rs3_crypto::KeyRing,
    delta: IndexDeltaObject,
    verified_payloads: &mut BTreeSet<BackendObjectId>,
    payload_plaintext_bytes: &mut u64,
    required_key_ids: &mut BTreeSet<KeyId>,
    protection: &mut RestoreProtectionSummary,
) -> Result<()>
where
    S: BlobStore,
{
    for mutation in delta.deltas {
        let IndexDelta::Upsert {
            entry,
            sealed_manifest,
            ..
        } = mutation
        else {
            continue;
        };
        required_key_ids.insert(entry.namespace_key_id);
        required_key_ids.insert(sealed_manifest.key_id.clone());
        let manifest = open_manifest_record(keyring, &entry.manifest_id, &sealed_manifest)?;
        if manifest.content_len != entry.content_len {
            return Err(RepositoryError::InvalidObjectFormat {
                object_id: entry.object_id,
            });
        }
        if !verified_payloads.insert(entry.object_id.clone()) {
            continue;
        }

        let body = repo
            .store
            .get_range(&entry.object_id, ByteRange::Full)
            .await?;
        let header = parse_segmented_payload_header(&entry.object_id, &body)?;
        required_key_ids.insert(header.key_id.clone());
        let plaintext = open_payload_object(keyring, &entry.object_id, body, ByteRange::Full)?;
        let plaintext_len =
            u64::try_from(plaintext.len()).map_err(|_| RepositoryError::InvalidObjectFormat {
                object_id: entry.object_id.clone(),
            })?;
        if plaintext_len != entry.content_len {
            return Err(RepositoryError::InvalidObjectFormat {
                object_id: entry.object_id,
            });
        }
        summarize_object_protection(repo, &entry.object_id, protection).await?;
        *payload_plaintext_bytes = payload_plaintext_bytes.saturating_add(plaintext_len);
    }

    Ok(())
}

async fn summarize_object_protection<S>(
    repo: &Repository<S>,
    object_id: &BackendObjectId,
    summary: &mut RestoreProtectionSummary,
) -> Result<()>
where
    S: BlobStore,
{
    let metadata = repo.store.head(object_id).await?;
    summary.checked_object_count = summary.checked_object_count.saturating_add(1);
    let mut delete_protected = false;
    if let Some(policy) = metadata.retention {
        summary.retention_object_count = summary.retention_object_count.saturating_add(1);
        summary.minimum_retention_days = Some(match summary.minimum_retention_days {
            Some(existing) => existing.min(policy.retain_days),
            None => policy.retain_days,
        });
        if policy.mode != RetentionMode::None && policy.retain_days > 0 {
            summary.retention_delete_blocked_count =
                summary.retention_delete_blocked_count.saturating_add(1);
            delete_protected = true;
        }
    }
    if metadata.legal_hold == Some(LegalHoldStatus::On) {
        summary.legal_hold_object_count = summary.legal_hold_object_count.saturating_add(1);
        delete_protected = true;
    }
    if delete_protected {
        summary.delete_protected_object_count =
            summary.delete_protected_object_count.saturating_add(1);
    }

    Ok(())
}
