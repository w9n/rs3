//! Shared commit batching options.

use std::time::Duration;

/// Batching policy for coordinated commits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitCoordinatorOptions {
    /// Maximum number of staged writes covered by one commit.
    pub max_batch_items: usize,
    /// Maximum time to wait for more staged writes before publishing.
    pub max_batch_delay: Duration,
    /// Maximum number of staged writes allowed to wait for commit.
    pub max_pending_items: usize,
}

impl CommitCoordinatorOptions {
    /// Creates commit coordinator options.
    pub const fn new(max_batch_items: usize, max_batch_delay: Duration) -> Self {
        Self {
            max_batch_items,
            max_batch_delay,
            max_pending_items: max_batch_items,
        }
    }

    /// Sets the maximum number of staged writes allowed to wait for commit.
    pub const fn with_max_pending_items(mut self, max_pending_items: usize) -> Self {
        self.max_pending_items = max_pending_items;
        self
    }

    pub(crate) fn normalized(self) -> Self {
        Self {
            max_batch_items: self.max_batch_items.max(1),
            max_batch_delay: self.max_batch_delay,
            max_pending_items: self.max_pending_items.max(1),
        }
    }
}

impl Default for CommitCoordinatorOptions {
    fn default() -> Self {
        Self {
            max_batch_items: 64,
            max_batch_delay: Duration::from_millis(25),
            max_pending_items: 64,
        }
    }
}
