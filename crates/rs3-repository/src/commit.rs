//! Commit coordination for client-visible repository writes.

use crate::error::{RepositoryError, Result};
use crate::model::{
    CheckpointPosition, CommittedPut, DeleteOutcome, RepositoryObjectMetadata, RepositoryPutOptions,
};
use crate::service::Repository;
use bytes::Bytes;
use rs3_anchor::CheckpointAnchor;
use rs3_storage::BlobStore;
use rs3_types::{LegalHoldStatus, LogicalPath};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, oneshot};
use tokio::time::sleep;

/// Batching policy for coordinated commits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitCoordinatorOptions {
    /// Maximum number of staged writes covered by one checkpoint.
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

    fn normalized(self) -> Self {
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
            max_batch_delay: Duration::from_millis(10),
            max_pending_items: 64,
        }
    }
}

/// Coordinates repository writes that must not be acknowledged before checkpoint commit.
pub struct CommitCoordinator<S, A> {
    repository: Arc<Repository<S>>,
    anchor: Arc<A>,
    options: CommitCoordinatorOptions,
    stage_lock: Arc<Mutex<()>>,
    batch: Arc<Mutex<PendingBatch>>,
}

#[derive(Default)]
struct PendingBatch {
    waiters: Vec<CommitWaiter>,
    publishing: bool,
    generation: u64,
    failed: Option<String>,
}

struct CommitWaiter {
    tx: oneshot::Sender<std::result::Result<CheckpointPosition, String>>,
}

impl<S, A> CommitCoordinator<S, A>
where
    S: BlobStore + 'static,
    A: CheckpointAnchor + 'static,
{
    /// Creates a commit coordinator for a repository and its checkpoint anchor.
    pub fn new(repository: Arc<Repository<S>>, anchor: A) -> Self {
        Self::with_options(repository, anchor, CommitCoordinatorOptions::default())
    }

    /// Creates a commit coordinator with explicit batching options.
    pub fn with_options(
        repository: Arc<Repository<S>>,
        anchor: A,
        options: CommitCoordinatorOptions,
    ) -> Self {
        Self {
            repository,
            anchor: Arc::new(anchor),
            options: options.normalized(),
            stage_lock: Arc::new(Mutex::new(())),
            batch: Arc::new(Mutex::new(PendingBatch::default())),
        }
    }

    /// Returns the coordinated repository.
    pub fn repository(&self) -> &Arc<Repository<S>> {
        &self.repository
    }

    /// Returns the checkpoint anchor used by this coordinator.
    pub fn anchor(&self) -> &Arc<A> {
        &self.anchor
    }

    /// Writes an object and returns only after a covering checkpoint is accepted.
    pub async fn put_committed(
        &self,
        key: LogicalPath,
        body: Bytes,
        options: RepositoryPutOptions,
    ) -> Result<CommittedPut> {
        let (metadata, rx, delayed_publish_generation, should_publish_now) = {
            let stage_lock_started = Instant::now();
            let _stage = self.stage_lock.lock().await;
            record_commit_put_phase_duration("stage_lock_wait", stage_lock_started.elapsed());
            let should_start_timer = {
                let batch = self.batch.lock().await;
                if let Some(reason) = batch.failed.as_ref() {
                    record_commit_enqueue("failed", batch.waiters.len());
                    tracing::warn!(
                        target: "rs3_repository",
                        operation = "put_committed_enqueue",
                        result = "failed",
                        "commit coordinator rejected write",
                    );
                    return Err(RepositoryError::CommitFailed {
                        reason: reason.clone(),
                    });
                }
                if batch.waiters.len() >= self.options.max_pending_items {
                    record_commit_enqueue("backpressure", batch.waiters.len());
                    tracing::warn!(
                        target: "rs3_repository",
                        operation = "put_committed_enqueue",
                        pending_items = batch.waiters.len(),
                        max_pending_items = self.options.max_pending_items,
                        result = "backpressure",
                        "commit coordinator rejected write",
                    );
                    return Err(RepositoryError::CommitBackpressure);
                }
                batch.waiters.is_empty()
            };

            let stage_write_started = Instant::now();
            let metadata = self.repository.put(key, body, options).await;
            record_commit_put_phase_duration("stage_write", stage_write_started.elapsed());
            let metadata = metadata?;
            let (tx, rx) = oneshot::channel();
            let mut batch = self.batch.lock().await;
            let delayed_publish_generation = if should_start_timer {
                batch.generation = batch.generation.wrapping_add(1);
                Some(batch.generation)
            } else {
                None
            };

            batch.waiters.push(CommitWaiter { tx });
            let should_publish_now = batch.waiters.len() >= self.options.max_batch_items;
            record_commit_enqueue("ok", batch.waiters.len());
            tracing::debug!(
                target: "rs3_repository",
                operation = "put_committed_enqueue",
                pending_items = batch.waiters.len(),
                max_batch_items = self.options.max_batch_items,
                result = "ok",
                "commit coordinator queued write",
            );

            if let Some(generation) = delayed_publish_generation.filter(|_| !should_publish_now) {
                spawn_delayed_publish(
                    Arc::clone(&self.repository),
                    Arc::clone(&self.anchor),
                    Arc::clone(&self.stage_lock),
                    Arc::clone(&self.batch),
                    generation,
                    self.options.max_batch_delay,
                );
            }

            (metadata, rx, delayed_publish_generation, should_publish_now)
        };

        let checkpoint_wait_started = Instant::now();
        if should_publish_now {
            publish_pending_batch(
                Arc::clone(&self.repository),
                Arc::clone(&self.anchor),
                Arc::clone(&self.stage_lock),
                Arc::clone(&self.batch),
                delayed_publish_generation,
            )
            .await;
        }

        let checkpoint = match rx.await {
            Ok(Ok(checkpoint)) => {
                record_commit_put_phase_duration(
                    "checkpoint_wait",
                    checkpoint_wait_started.elapsed(),
                );
                checkpoint
            }
            Ok(Err(reason)) => {
                record_commit_put_phase_duration(
                    "checkpoint_wait",
                    checkpoint_wait_started.elapsed(),
                );
                return Err(RepositoryError::CommitFailed { reason });
            }
            Err(_) => {
                record_commit_put_phase_duration(
                    "checkpoint_wait",
                    checkpoint_wait_started.elapsed(),
                );
                return Err(commit_failed("commit waiter was dropped"));
            }
        };

        Ok(CommittedPut {
            metadata,
            checkpoint,
        })
    }

    /// Deletes an object and returns only after the tombstone checkpoint is accepted.
    pub async fn delete_committed(&self, key: LogicalPath) -> Result<DeleteOutcome> {
        let _stage = self.stage_lock.lock().await;
        self.publish_locked_batch().await?;
        self.repository
            .delete_committed(&key, self.anchor.as_ref())
            .await
    }

    /// Applies legal hold and returns only after the covering checkpoint is accepted.
    pub async fn set_legal_hold_committed(
        &self,
        key: LogicalPath,
        status: LegalHoldStatus,
    ) -> Result<RepositoryObjectMetadata> {
        let _stage = self.stage_lock.lock().await;
        self.publish_locked_batch().await?;
        self.repository
            .set_legal_hold_committed(&key, status, self.anchor.as_ref())
            .await
    }

    async fn publish_locked_batch(&self) -> Result<()> {
        let waiters = {
            let mut batch = self.batch.lock().await;
            if let Some(reason) = batch.failed.as_ref() {
                return Err(RepositoryError::CommitFailed {
                    reason: reason.clone(),
                });
            }
            if batch.waiters.is_empty() {
                return Ok(());
            }
            batch.publishing = true;
            std::mem::take(&mut batch.waiters)
        };

        let waiter_count = waiters.len();
        let started = Instant::now();
        let result = self
            .repository
            .publish_checkpoint(self.anchor.as_ref())
            .await
            .map_err(|error| error.to_string());
        let result_label = if result.is_ok() { "ok" } else { "error" };
        record_commit_batch_publish(waiter_count, result_label, started.elapsed());

        tracing::info!(
            target: "rs3_repository",
            operation = "commit_batch_publish",
            waiters = waiter_count,
            result = result_label,
            elapsed_us = elapsed_us(started.elapsed()),
            "commit coordinator publish completed",
        );

        let failure = result.as_ref().err().cloned();
        for waiter in waiters {
            let _ = waiter.tx.send(result.clone());
        }

        let mut batch = self.batch.lock().await;
        batch.publishing = false;
        if let Some(reason) = failure {
            batch.failed = Some(reason.clone());
            return Err(RepositoryError::CommitFailed { reason });
        }

        Ok(())
    }
}

fn spawn_delayed_publish<S, A>(
    repository: Arc<Repository<S>>,
    anchor: Arc<A>,
    stage_lock: Arc<Mutex<()>>,
    batch: Arc<Mutex<PendingBatch>>,
    generation: u64,
    delay: Duration,
) where
    S: BlobStore + 'static,
    A: CheckpointAnchor + 'static,
{
    tokio::spawn(async move {
        sleep(delay).await;
        publish_pending_batch(repository, anchor, stage_lock, batch, Some(generation)).await;
    });
}

async fn publish_pending_batch<S, A>(
    repository: Arc<Repository<S>>,
    anchor: Arc<A>,
    stage_lock: Arc<Mutex<()>>,
    batch: Arc<Mutex<PendingBatch>>,
    expected_generation: Option<u64>,
) where
    S: BlobStore + 'static,
    A: CheckpointAnchor + 'static,
{
    let _stage = stage_lock.lock().await;
    let waiters = {
        let mut batch = batch.lock().await;
        if expected_generation.is_some_and(|expected| batch.generation != expected) {
            return;
        }
        if batch.publishing || batch.waiters.is_empty() || batch.failed.is_some() {
            return;
        }
        batch.publishing = true;
        std::mem::take(&mut batch.waiters)
    };

    let waiter_count = waiters.len();
    let started = Instant::now();
    let result = repository
        .publish_checkpoint(anchor.as_ref())
        .await
        .map_err(|error| error.to_string());
    let result_label = if result.is_ok() { "ok" } else { "error" };
    record_commit_batch_publish(waiter_count, result_label, started.elapsed());

    tracing::info!(
        target: "rs3_repository",
        operation = "commit_batch_publish",
        waiters = waiter_count,
        result = result_label,
        elapsed_us = elapsed_us(started.elapsed()),
        "commit coordinator publish completed",
    );

    let failure = result.as_ref().err().cloned();
    for waiter in waiters {
        let _ = waiter.tx.send(result.clone());
    }

    let mut batch = batch.lock().await;
    batch.publishing = false;
    if let Some(reason) = failure {
        batch.failed = Some(reason);
    }
}

fn commit_failed(reason: &str) -> RepositoryError {
    RepositoryError::CommitFailed {
        reason: reason.to_owned(),
    }
}

fn record_commit_enqueue(result: &'static str, pending_items: usize) {
    metrics::counter!("rs3_repository_commit_enqueues_total", "result" => result).increment(1);
    metrics::counter!(
        "rs3_repository_commit_enqueue_pending_items_total",
        "result" => result,
    )
    .increment(usize_to_u64(pending_items));
}

fn record_commit_batch_publish(waiter_count: usize, result: &'static str, elapsed: Duration) {
    metrics::counter!(
        "rs3_repository_commit_batch_publishes_total",
        "result" => result,
    )
    .increment(1);
    metrics::counter!(
        "rs3_repository_commit_batch_waiters_total",
        "result" => result,
    )
    .increment(usize_to_u64(waiter_count));
    metrics::histogram!(
        "rs3_repository_commit_batch_waiters_per_publish",
        "result" => result,
    )
    .record(waiter_count as f64);
    metrics::histogram!(
        "rs3_repository_commit_batch_publish_duration_seconds",
        "result" => result,
    )
    .record(elapsed.as_secs_f64());
}

fn record_commit_put_phase_duration(phase: &'static str, elapsed: Duration) {
    metrics::histogram!(
        "rs3_repository_commit_put_phase_duration_seconds",
        "phase" => phase,
    )
    .record(elapsed.as_secs_f64());
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn elapsed_us(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
}
