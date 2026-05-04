//! Dry-run repository maintenance reports.

use crate::checkpoint::{
    CHECKPOINT_EVIDENCE_PREFIX, CHECKPOINT_OBJECT_PREFIX, checkpoint_evidence_object_id,
    checkpoint_object_id,
};
use crate::error::{RepositoryError, Result};
use crate::model::{
    BackendObjectReferenceKind, CheckpointPosition, ReachableBackendObject,
    RepositoryOrphanCandidate, RepositoryOrphanReport,
};
use crate::service::Repository;
use rs3_index::IndexDelta;
use rs3_storage::BlobStore;
use rs3_types::BackendObjectId;
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
