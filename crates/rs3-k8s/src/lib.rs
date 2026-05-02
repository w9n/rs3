//! Kubernetes integration contracts.

pub use rs3_anchor::{AnchorError, AnchorState, CheckpointAnchor};

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
