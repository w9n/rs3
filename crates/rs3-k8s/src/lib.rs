//! Kubernetes integration contracts.

use async_trait::async_trait;
use rs3_types::{CheckpointId, Sequence};
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
