//! Trusted repository workflow above storage and namespace indexes.

mod checkpoint;
mod commit;
mod error;
mod maintenance;
mod model;
mod namespace;
mod service;
mod state;

#[cfg(test)]
mod tests;

pub use commit::{CommitCoordinator, CommitCoordinatorOptions};
pub use error::{RepositoryError, Result};
pub use model::{
    BackendObjectReferenceKind, CheckpointPosition, CommittedPut, DeleteOutcome,
    PhysicalDeleteOutcome, ReachableBackendObject, RepositoryListEntry, RepositoryObjectMetadata,
    RepositoryOrphanCandidate, RepositoryOrphanReport, RepositoryPutOptions,
};
pub use service::Repository;
