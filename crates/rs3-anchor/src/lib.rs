//! Checkpoint anchoring contracts.

use async_trait::async_trait;
use rs3_types::{BackendVersionId, CheckpointId, Sequence};
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
    /// Provider version identifier for the accepted checkpoint object, when available.
    pub checkpoint_version_id: Option<BackendVersionId>,
}

/// Errors returned by checkpoint anchor implementations.
#[derive(Debug, Error)]
pub enum AnchorError {
    /// The anchor object is missing.
    #[error("checkpoint anchor is missing")]
    MissingAnchor,
    /// The proposed checkpoint does not advance the anchor.
    #[error("checkpoint sequence is stale")]
    StaleSequence,
    /// The anchor backend rejected the operation.
    #[error("checkpoint anchor backend error: {0}")]
    Backend(String),
    /// The in-memory anchor lock was poisoned.
    #[error("checkpoint anchor state lock poisoned")]
    StatePoisoned,
}

/// Convenient result alias for checkpoint anchors.
pub type Result<T> = std::result::Result<T, AnchorError>;

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
            .map_err(|_| AnchorError::StatePoisoned)?
            .clone()
            .ok_or(AnchorError::MissingAnchor)
    }

    async fn compare_and_advance(&self, next: AnchorState) -> Result<AnchorState> {
        let mut state = self.state.write().map_err(|_| AnchorError::StatePoisoned)?;

        match state.as_ref() {
            Some(current) if next == *current => Ok(current.clone()),
            Some(current) if next.sequence <= current.sequence => Err(AnchorError::StaleSequence),
            _ => {
                *state = Some(next.clone());
                Ok(next)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AnchorError, AnchorState, CheckpointAnchor, MemoryCheckpointAnchor};
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
            checkpoint_version_id: None,
        }
    }

    #[tokio::test]
    async fn memory_anchor_starts_missing() {
        let anchor = MemoryCheckpointAnchor::new();

        let read = anchor.read().await;

        assert!(matches!(read, Err(AnchorError::MissingAnchor)));
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
        assert!(matches!(stale, Err(AnchorError::StaleSequence)));
        assert_eq!(
            second.map(|state| state.checkpoint_id).ok(),
            Some(checkpoint_id("second"))
        );
    }
}
