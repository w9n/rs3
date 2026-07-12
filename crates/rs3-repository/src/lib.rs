//! Trusted repository workflow above storage and namespace indexes.

mod checkpoint;
mod commit_options;
mod error;
mod keyring_envelope;
mod lru;
mod model;
mod namespace;
mod payload;
mod service;
mod state;
pub mod v2;

#[cfg(test)]
mod test_support;

pub use commit_options::CommitCoordinatorOptions;
pub use error::{RepositoryError, Result};
pub use keyring_envelope::{KEYRING_ENVELOPE_OBJECT_CONTENT_TYPE, store_keyring_envelope};
pub use model::{
    DeleteOutcome, PhysicalDeleteOutcome, RepositoryListEntry, RepositoryObjectMetadata,
    RepositoryPutOptions,
};
pub use payload::{DEFAULT_PAYLOAD_SEGMENT_SIZE, MAX_PAYLOAD_SEGMENT_SIZE};
pub use service::{DEFAULT_DECRYPTED_SEGMENT_CACHE_MAX_BYTES, Repository, RepositoryOptions};
