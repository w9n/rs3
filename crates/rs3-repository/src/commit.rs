//! Commit coordination for client-visible repository writes.

use crate::error::Result;
use crate::model::{CommittedPut, RepositoryPutOptions};
use crate::service::Repository;
use bytes::Bytes;
use rs3_anchor::CheckpointAnchor;
use rs3_storage::BlobStore;
use rs3_types::LogicalPath;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Serializes repository writes that must not be acknowledged before checkpoint commit.
pub struct CommitCoordinator<S, A> {
    repository: Arc<Repository<S>>,
    anchor: A,
    commit_lock: Mutex<()>,
}

impl<S, A> CommitCoordinator<S, A>
where
    S: BlobStore,
    A: CheckpointAnchor,
{
    /// Creates a commit coordinator for a repository and its checkpoint anchor.
    pub fn new(repository: Arc<Repository<S>>, anchor: A) -> Self {
        Self {
            repository,
            anchor,
            commit_lock: Mutex::new(()),
        }
    }

    /// Returns the coordinated repository.
    pub fn repository(&self) -> &Arc<Repository<S>> {
        &self.repository
    }

    /// Writes an object and returns only after its checkpoint is accepted.
    pub async fn put_committed(
        &self,
        key: LogicalPath,
        body: Bytes,
        options: RepositoryPutOptions,
    ) -> Result<CommittedPut> {
        let _commit = self.commit_lock.lock().await;
        self.repository
            .put_committed(key, body, options, &self.anchor)
            .await
    }
}
