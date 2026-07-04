//! Commit coordination for preview v2 repository writes.

use super::repository::{V2AnchorState, V2CommitAnchor};
use super::service::{V2Repository, V2RepositorySnapshot};
use crate::CommitCoordinatorOptions;
use crate::error::{RepositoryError, Result};
use crate::model::{DeleteOutcome, RepositoryObjectMetadata, RepositoryPutOptions};
use bytes::Bytes;
use futures_util::Stream;
use rs3_storage::BlobStore;
use rs3_types::{LegalHoldStatus, LogicalPath};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, oneshot};
use tokio::time::sleep;

/// Result of a v2 write accepted by the external anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2CommittedPut {
    /// Client-visible object metadata.
    pub metadata: RepositoryObjectMetadata,
    /// Accepted v2 anchor state covering this write.
    pub anchor_state: V2AnchorState,
}

/// Coordinates v2 repository writes that must not be acknowledged before commit.
pub struct V2CommitCoordinator<S, A> {
    repository: Arc<V2Repository<S>>,
    anchor: Arc<A>,
    options: CommitCoordinatorOptions,
    stage_lock: Arc<Mutex<()>>,
    batch: Arc<Mutex<PendingBatch>>,
}

#[derive(Default)]
struct PendingBatch {
    waiters: Vec<CommitWaiter>,
    rollback_snapshot: Option<V2RepositorySnapshot>,
    publishing: bool,
    generation: u64,
    failed: Option<String>,
}

struct CommitWaiter {
    tx: oneshot::Sender<std::result::Result<V2AnchorState, String>>,
}

impl<S, A> V2CommitCoordinator<S, A>
where
    S: BlobStore + Clone + 'static,
    A: V2CommitAnchor + 'static,
{
    /// Creates a v2 commit coordinator for a repository and anchor.
    pub fn new(repository: Arc<V2Repository<S>>, anchor: A) -> Self {
        Self::with_options(repository, anchor, CommitCoordinatorOptions::default())
    }

    /// Creates a v2 commit coordinator with explicit batching options.
    pub fn with_options(
        repository: Arc<V2Repository<S>>,
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

    /// Returns the coordinated v2 repository.
    pub fn repository(&self) -> &Arc<V2Repository<S>> {
        &self.repository
    }

    /// Returns the v2 anchor used by this coordinator.
    pub fn anchor(&self) -> &Arc<A> {
        &self.anchor
    }

    /// Writes an object and returns only after a covering v2 commit is accepted.
    pub async fn put_committed(
        &self,
        key: LogicalPath,
        body: Bytes,
        options: RepositoryPutOptions,
    ) -> Result<V2CommittedPut> {
        let (metadata, rx, delayed_publish_generation, should_publish_now) = {
            let stage_lock_started = Instant::now();
            let _stage = self.stage_lock.lock().await;
            record_v2_commit_put_phase_duration("stage_lock_wait", stage_lock_started.elapsed());
            let should_start_timer = {
                let batch = self.batch.lock().await;
                if let Some(reason) = batch.failed.as_ref() {
                    record_v2_commit_enqueue("failed", batch.waiters.len());
                    tracing::warn!(
                        target: "rs3_repository",
                        operation = "v2_put_committed_enqueue",
                        result = "failed",
                        "v2 commit coordinator rejected write",
                    );
                    return Err(RepositoryError::CommitFailed {
                        reason: reason.clone(),
                    });
                }
                if batch.waiters.len() >= self.options.max_pending_items {
                    record_v2_commit_enqueue("backpressure", batch.waiters.len());
                    tracing::warn!(
                        target: "rs3_repository",
                        operation = "v2_put_committed_enqueue",
                        pending_items = batch.waiters.len(),
                        max_pending_items = self.options.max_pending_items,
                        result = "backpressure",
                        "v2 commit coordinator rejected write",
                    );
                    return Err(RepositoryError::CommitBackpressure);
                }
                batch.waiters.is_empty()
            };

            let stage_snapshot = self.repository.snapshot_state()?;
            let stage_write_started = Instant::now();
            let metadata = self.repository.stage_put(key, body, options).await;
            record_v2_commit_put_phase_duration("stage_write", stage_write_started.elapsed());
            let metadata = match metadata {
                Ok(metadata) => metadata,
                Err(error) => {
                    self.repository
                        .restore_state_preserving_sequence(stage_snapshot)?;
                    return Err(error);
                }
            };
            let (tx, rx) = oneshot::channel();
            let mut batch = self.batch.lock().await;
            let delayed_publish_generation = if should_start_timer {
                batch.generation = batch.generation.wrapping_add(1);
                batch.rollback_snapshot = Some(stage_snapshot);
                Some(batch.generation)
            } else {
                None
            };

            batch.waiters.push(CommitWaiter { tx });
            let should_publish_now = batch.waiters.len() >= self.options.max_batch_items;
            record_v2_commit_enqueue("ok", batch.waiters.len());
            tracing::debug!(
                target: "rs3_repository",
                operation = "v2_put_committed_enqueue",
                pending_items = batch.waiters.len(),
                max_batch_items = self.options.max_batch_items,
                result = "ok",
                "v2 commit coordinator queued write",
            );

            if let Some(generation) = delayed_publish_generation.filter(|_| !should_publish_now) {
                spawn_delayed_v2_publish(
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

        let commit_wait_started = Instant::now();
        if should_publish_now {
            publish_pending_v2_batch(
                Arc::clone(&self.repository),
                Arc::clone(&self.anchor),
                Arc::clone(&self.stage_lock),
                Arc::clone(&self.batch),
                delayed_publish_generation,
            )
            .await;
        }

        let anchor_state = match rx.await {
            Ok(Ok(anchor_state)) => {
                record_v2_commit_put_phase_duration("commit_wait", commit_wait_started.elapsed());
                anchor_state
            }
            Ok(Err(reason)) => {
                record_v2_commit_put_phase_duration("commit_wait", commit_wait_started.elapsed());
                return Err(RepositoryError::CommitFailed { reason });
            }
            Err(_) => {
                record_v2_commit_put_phase_duration("commit_wait", commit_wait_started.elapsed());
                return Err(commit_failed("v2 commit waiter was dropped"));
            }
        };

        Ok(V2CommittedPut {
            metadata,
            anchor_state,
        })
    }

    /// Writes one known-length streamed object after flushing pending batches.
    pub async fn put_committed_streaming_known_len<St>(
        &self,
        key: LogicalPath,
        plaintext_len: u64,
        stream: St,
        options: RepositoryPutOptions,
        multipart_part_size: usize,
    ) -> Result<V2CommittedPut>
    where
        St: Stream<Item = Result<Bytes>> + Unpin + Send,
    {
        let _stage = self.stage_lock.lock().await;
        self.publish_locked_batch().await?;
        let metadata = self
            .repository
            .put_committed_streaming_known_len(
                self.anchor.as_ref(),
                key,
                plaintext_len,
                stream,
                options,
                multipart_part_size,
            )
            .await?;
        let anchor_state = self
            .anchor
            .read_v2()
            .await
            .map_err(v2_commit_error)?
            .ok_or_else(|| commit_failed("v2 anchor is missing after streamed commit"))?;
        Ok(V2CommittedPut {
            metadata,
            anchor_state,
        })
    }

    /// Writes one unknown-length streamed object after flushing pending batches.
    pub async fn put_committed_streaming_unknown_len<St>(
        &self,
        key: LogicalPath,
        stream: St,
        options: RepositoryPutOptions,
        multipart_part_size: usize,
        max_plaintext_len: u64,
    ) -> Result<V2CommittedPut>
    where
        St: Stream<Item = Result<Bytes>> + Unpin + Send,
    {
        let _stage = self.stage_lock.lock().await;
        self.publish_locked_batch().await?;
        let metadata = self
            .repository
            .put_committed_streaming_unknown_len(
                self.anchor.as_ref(),
                key,
                stream,
                options,
                multipart_part_size,
                max_plaintext_len,
            )
            .await?;
        let anchor_state = self
            .anchor
            .read_v2()
            .await
            .map_err(v2_commit_error)?
            .ok_or_else(|| commit_failed("v2 anchor is missing after streamed commit"))?;
        Ok(V2CommittedPut {
            metadata,
            anchor_state,
        })
    }

    /// Deletes an object after flushing any pending staged v2 write batch.
    pub async fn delete_committed(&self, key: LogicalPath) -> Result<DeleteOutcome> {
        let _stage = self.stage_lock.lock().await;
        self.publish_locked_batch().await?;
        self.repository
            .delete_committed(self.anchor.as_ref(), key)
            .await
    }

    /// Applies legal hold after flushing any pending staged v2 write batch.
    pub async fn set_legal_hold_committed(
        &self,
        key: LogicalPath,
        status: LegalHoldStatus,
    ) -> Result<RepositoryObjectMetadata> {
        let _stage = self.stage_lock.lock().await;
        self.publish_locked_batch().await?;
        self.repository
            .set_legal_hold_committed(self.anchor.as_ref(), key, status)
            .await
    }

    /// Flushes pending writes and publishes a full v2 index snapshot commit.
    pub async fn write_index_snapshot(&self) -> Result<V2AnchorState> {
        let _stage = self.stage_lock.lock().await;
        self.publish_locked_batch().await?;
        self.repository
            .write_index_snapshot(self.anchor.as_ref())
            .await
            .map(|stored| stored.anchor_state)
    }

    async fn publish_locked_batch(&self) -> Result<()> {
        let pending = {
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
            PendingPublish {
                waiters: std::mem::take(&mut batch.waiters),
                rollback_snapshot: batch.rollback_snapshot.take(),
            }
        };

        let result = publish_v2_waiters(
            &self.repository,
            self.anchor.as_ref(),
            pending.waiters,
            pending.rollback_snapshot,
        )
        .await;
        let mut batch = self.batch.lock().await;
        batch.publishing = false;
        if let Err(reason) = result {
            batch.failed = Some(reason.clone());
            return Err(RepositoryError::CommitFailed { reason });
        }
        Ok(())
    }
}

struct PendingPublish {
    waiters: Vec<CommitWaiter>,
    rollback_snapshot: Option<V2RepositorySnapshot>,
}

fn spawn_delayed_v2_publish<S, A>(
    repository: Arc<V2Repository<S>>,
    anchor: Arc<A>,
    stage_lock: Arc<Mutex<()>>,
    batch: Arc<Mutex<PendingBatch>>,
    generation: u64,
    delay: Duration,
) where
    S: BlobStore + Clone + 'static,
    A: V2CommitAnchor + 'static,
{
    tokio::spawn(async move {
        sleep(delay).await;
        publish_pending_v2_batch(repository, anchor, stage_lock, batch, Some(generation)).await;
    });
}

async fn publish_pending_v2_batch<S, A>(
    repository: Arc<V2Repository<S>>,
    anchor: Arc<A>,
    stage_lock: Arc<Mutex<()>>,
    batch: Arc<Mutex<PendingBatch>>,
    expected_generation: Option<u64>,
) where
    S: BlobStore + Clone + 'static,
    A: V2CommitAnchor + 'static,
{
    let _stage = stage_lock.lock().await;
    let pending = {
        let mut batch = batch.lock().await;
        if expected_generation.is_some_and(|expected| batch.generation != expected) {
            return;
        }
        if batch.publishing || batch.waiters.is_empty() || batch.failed.is_some() {
            return;
        }
        batch.publishing = true;
        PendingPublish {
            waiters: std::mem::take(&mut batch.waiters),
            rollback_snapshot: batch.rollback_snapshot.take(),
        }
    };

    let result = publish_v2_waiters(
        &repository,
        anchor.as_ref(),
        pending.waiters,
        pending.rollback_snapshot,
    )
    .await;
    let mut batch = batch.lock().await;
    batch.publishing = false;
    if let Err(reason) = result {
        batch.failed = Some(reason);
    }
}

async fn publish_v2_waiters<S, A>(
    repository: &V2Repository<S>,
    anchor: &A,
    waiters: Vec<CommitWaiter>,
    rollback_snapshot: Option<V2RepositorySnapshot>,
) -> std::result::Result<(), String>
where
    S: BlobStore + Clone + 'static,
    A: V2CommitAnchor + 'static,
{
    let waiter_count = waiters.len();
    let started = Instant::now();
    let result = match repository.publish_pending_index_delta(anchor).await {
        Ok(Some(stored)) => Ok(stored.anchor_state),
        Ok(None) => Err("v2 commit batch had no pending index delta".to_owned()),
        Err(error) => Err(error.to_string()),
    };
    let result_label = if result.is_ok() { "ok" } else { "error" };
    record_v2_commit_batch_publish(waiter_count, result_label, started.elapsed());

    tracing::info!(
        target: "rs3_repository",
        operation = "v2_commit_batch_publish",
        waiters = waiter_count,
        result = result_label,
        elapsed_us = elapsed_us(started.elapsed()),
        "v2 commit coordinator publish completed",
    );

    let failure = result.as_ref().err().cloned();
    if failure.is_some()
        && let Some(snapshot) = rollback_snapshot
        && let Err(error) = repository.restore_state_preserving_sequence(snapshot)
    {
        tracing::error!(
            target: "rs3_repository",
            operation = "v2_commit_batch_rollback",
            error = %error,
            "v2 commit coordinator failed to restore unaccepted state",
        );
    }

    for waiter in waiters {
        let _ = waiter.tx.send(result.clone());
    }

    match failure {
        Some(reason) => Err(reason),
        None => Ok(()),
    }
}

fn commit_failed(reason: &str) -> RepositoryError {
    RepositoryError::CommitFailed {
        reason: reason.to_owned(),
    }
}

fn v2_commit_error(error: super::error::V2FormatError) -> RepositoryError {
    RepositoryError::CommitFailed {
        reason: error.to_string(),
    }
}

fn record_v2_commit_enqueue(result: &'static str, pending_items: usize) {
    metrics::counter!("rs3_repository_v2_commit_enqueues_total", "result" => result).increment(1);
    metrics::counter!(
        "rs3_repository_v2_commit_enqueue_pending_items_total",
        "result" => result,
    )
    .increment(usize_to_u64(pending_items));
}

fn record_v2_commit_batch_publish(waiter_count: usize, result: &'static str, elapsed: Duration) {
    metrics::counter!(
        "rs3_repository_v2_commit_batch_publishes_total",
        "result" => result,
    )
    .increment(1);
    metrics::counter!(
        "rs3_repository_v2_commit_batch_waiters_total",
        "result" => result,
    )
    .increment(usize_to_u64(waiter_count));
    metrics::histogram!(
        "rs3_repository_v2_commit_batch_waiters_per_publish",
        "result" => result,
    )
    .record(waiter_count as f64);
    metrics::histogram!(
        "rs3_repository_v2_commit_batch_publish_duration_seconds",
        "result" => result,
    )
    .record(elapsed.as_secs_f64());
}

fn record_v2_commit_put_phase_duration(phase: &'static str, elapsed: Duration) {
    metrics::histogram!(
        "rs3_repository_v2_commit_put_phase_duration_seconds",
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
