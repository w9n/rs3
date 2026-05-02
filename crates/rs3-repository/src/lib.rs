//! Trusted repository workflow above storage and namespace indexes.

mod checkpoint;
mod error;
mod model;
mod namespace;
mod service;
mod state;

#[cfg(test)]
mod tests;

pub use error::{RepositoryError, Result};
pub use model::{
    DeleteOutcome, PhysicalDeleteOutcome, RepositoryListEntry, RepositoryObjectMetadata,
    RepositoryPutOptions,
};
pub use service::Repository;
