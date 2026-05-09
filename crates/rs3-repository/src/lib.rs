//! Trusted repository workflow above storage and namespace indexes.

mod checkpoint;
mod commit;
mod error;
mod maintenance;
mod model;
mod namespace;
mod payload;
mod service;
mod state;

#[cfg(test)]
mod tests;

pub use commit::{CommitCoordinator, CommitCoordinatorOptions};
pub use error::{RepositoryError, Result};
pub use model::{
    BackendObjectReferenceKind, CheckpointPosition, CommittedPut, DeleteOutcome,
    PhysicalDeleteOutcome, ReachableBackendObject, RepositoryListEntry, RepositoryObjectMetadata,
    RepositoryOrphanCandidate, RepositoryOrphanDeleteReport, RepositoryOrphanReport,
    RepositoryPutOptions, RestoreProtectionSummary, RestoreVerificationReport,
};
pub use payload::DEFAULT_PAYLOAD_SEGMENT_SIZE;
pub use service::{Repository, RepositoryOptions};
