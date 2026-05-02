//! Trusted repository workflow above storage and namespace indexes.

mod checkpoint;
mod commit;
mod error;
mod model;
mod namespace;
mod service;
mod state;

#[cfg(test)]
mod tests;

pub use commit::CommitCoordinator;
pub use error::{RepositoryError, Result};
pub use model::{
    CheckpointPosition, CommittedPut, DeleteOutcome, PhysicalDeleteOutcome, RepositoryListEntry,
    RepositoryObjectMetadata, RepositoryPutOptions,
};
pub use service::Repository;
