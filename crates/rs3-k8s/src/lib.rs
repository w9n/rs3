//! Kubernetes integration contracts.

use async_trait::async_trait;
use rs3_types::{CheckpointId, Sequence};
use std::sync::{Arc, RwLock};
use thiserror::Error;

/// Latest checkpoint state anchored outside the object store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorState {
    /// Highest accepted checkpoint sequence.
    pub sequence: Sequence,
    /// Identifier of the accepted checkpoint.
    pub checkpoint_id: CheckpointId,
    /// Digest of the accepted checkpoint payload.
    pub checkpoint_digest: String,
}

/// Kubernetes object settings used for checkpoint anchoring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseSettings {
    /// Namespace that stores the anchor object.
    pub namespace: String,
    /// Name of the anchor object.
    pub name: String,
    /// Field manager used by server-side apply.
    pub field_manager: String,
}

/// Errors returned by Kubernetes anchor implementations.
#[derive(Debug, Error)]
pub enum K8sError {
    /// The anchor object is missing.
    #[error("checkpoint anchor is missing")]
    MissingAnchor,
    /// The proposed checkpoint does not advance the anchor.
    #[error("checkpoint sequence is stale")]
    StaleSequence,
    /// The Kubernetes API rejected the operation.
    #[error("kubernetes API error: {0}")]
    Api(String),
    /// The in-memory anchor lock was poisoned.
    #[error("checkpoint anchor state lock poisoned")]
    StatePoisoned,
}

/// Convenient result alias for Kubernetes integration.
pub type Result<T> = std::result::Result<T, K8sError>;

/// External monotonic anchor used to detect object-store rollback.
#[async_trait]
pub trait CheckpointAnchor: Send + Sync {
    /// Reads the current anchor state.
    async fn read(&self) -> Result<AnchorState>;

    /// Advances the anchor if `next` is newer than the current state.
    async fn compare_and_advance(&self, next: AnchorState) -> Result<AnchorState>;
}

/// In-memory checkpoint anchor for local tests and protocol wiring.
#[derive(Clone, Debug, Default)]
pub struct MemoryCheckpointAnchor {
    state: Arc<RwLock<Option<AnchorState>>>,
}

impl MemoryCheckpointAnchor {
    /// Creates an empty in-memory checkpoint anchor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an in-memory checkpoint anchor with an initial state.
    pub fn with_state(state: AnchorState) -> Self {
        Self {
            state: Arc::new(RwLock::new(Some(state))),
        }
    }
}

#[async_trait]
impl CheckpointAnchor for MemoryCheckpointAnchor {
    async fn read(&self) -> Result<AnchorState> {
        self.state
            .read()
            .map_err(|_| K8sError::StatePoisoned)?
            .clone()
            .ok_or(K8sError::MissingAnchor)
    }

    async fn compare_and_advance(&self, next: AnchorState) -> Result<AnchorState> {
        let mut state = self.state.write().map_err(|_| K8sError::StatePoisoned)?;

        match state.as_ref() {
            Some(current) if next == *current => Ok(current.clone()),
            Some(current) if next.sequence <= current.sequence => Err(K8sError::StaleSequence),
            _ => {
                *state = Some(next.clone());
                Ok(next)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AnchorState, CheckpointAnchor, K8sError, MemoryCheckpointAnchor};
    use rs3_types::{CheckpointId, Sequence};

    fn checkpoint_id(value: &str) -> CheckpointId {
        match CheckpointId::new(value) {
            Ok(checkpoint_id) => checkpoint_id,
            Err(error) => panic!("{error}"),
        }
    }

    fn anchor_state(sequence: u64, id: &str) -> AnchorState {
        AnchorState {
            sequence: Sequence::new(sequence),
            checkpoint_id: checkpoint_id(id),
            checkpoint_digest: format!("digest-{id}"),
        }
    }

    #[tokio::test]
    async fn memory_anchor_starts_missing() {
        let anchor = MemoryCheckpointAnchor::new();

        let read = anchor.read().await;

        assert!(matches!(read, Err(K8sError::MissingAnchor)));
    }

    #[tokio::test]
    async fn memory_anchor_advances_monotonically() {
        let anchor = MemoryCheckpointAnchor::new();
        let first_state = anchor_state(1, "first");

        let first = anchor.compare_and_advance(first_state.clone()).await;
        let idempotent = anchor.compare_and_advance(first_state).await;
        let stale = anchor
            .compare_and_advance(anchor_state(1, "same-sequence"))
            .await;
        let second = anchor.compare_and_advance(anchor_state(2, "second")).await;

        assert!(first.is_ok());
        assert!(idempotent.is_ok());
        assert!(matches!(stale, Err(K8sError::StaleSequence)));
        assert_eq!(
            second.map(|state| state.checkpoint_id).ok(),
            Some(checkpoint_id("second"))
        );
    }
}
