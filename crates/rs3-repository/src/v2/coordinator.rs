//! Commit coordination for preview v2 repository writes.

use super::repository::{
    V2AnchorState, V2CommitAnchor, V2ReplayChain, V2StandaloneUploadCancellation,
};
use super::service::{
    V2CoordinatedMutation, V2CoordinatorLease, V2Repository, V2StagedPutRollback,
};
use super::{V2FormatError, V2MaintenanceGuard};
use crate::CommitCoordinatorOptions;
use crate::error::{RepositoryError, Result};
use crate::model::{DeleteOutcome, RepositoryObjectMetadata, RepositoryPutOptions};
use bytes::Bytes;
use futures_util::Stream;
use rs3_storage::BlobStore;
use rs3_types::{LegalHoldStatus, LogicalPath, RetentionPolicy};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, oneshot};
use tokio::time::sleep;

/// Active-run count at which a guarded coordinator first requests compaction.
pub const V2_INDEX_COMPACTION_REQUEST_RUNS: usize = 256;
/// Active-run count at which writes pause unless guarded compaction succeeds.
pub const V2_INDEX_COMPACTION_PAUSE_RUNS: usize = 896;
const V2_INDEX_COMPACTION_RETRY_INTERVAL_RUNS: usize = 64;

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
    status: Arc<CoordinatorStatus>,
    lease: Arc<V2CoordinatorLease>,
    maintenance_guard: Option<Arc<dyn V2MaintenanceGuard>>,
}

#[derive(Default)]
struct PendingBatch {
    waiters: Vec<CommitWaiter>,
    rollback_log: Vec<V2StagedPutRollback>,
    publishing: bool,
    generation: u64,
    failed: Option<String>,
    protection: Option<V2ProtectionCohort>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct V2ProtectionCohort {
    retention: Option<RetentionPolicy>,
    legal_hold: Option<LegalHoldStatus>,
}

struct CommitWaiter {
    tx: oneshot::Sender<std::result::Result<V2AnchorState, CommitWaiterError>>,
}

struct CancelStandaloneUploadOnDrop {
    cancellation: Arc<V2StandaloneUploadCancellation>,
    armed: bool,
}

impl CancelStandaloneUploadOnDrop {
    fn new(cancellation: Arc<V2StandaloneUploadCancellation>) -> Self {
        Self {
            cancellation,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CancelStandaloneUploadOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.cancellation.cancel();
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CommitWaiterError {
    Failed(String),
    AcceptedRecoveryRequired,
}

impl CommitWaiterError {
    fn into_repository_error(self) -> RepositoryError {
        match self {
            Self::Failed(reason) => RepositoryError::CommitFailed { reason },
            Self::AcceptedRecoveryRequired => RepositoryError::AcceptedRecoveryRequired,
        }
    }

    fn reason(&self) -> String {
        match self {
            Self::Failed(reason) => reason.clone(),
            Self::AcceptedRecoveryRequired => RepositoryError::AcceptedRecoveryRequired.to_string(),
        }
    }
}

/// Live v2 commit coordinator state safe for path-redacted operator reports.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct V2CommitCoordinatorStatus {
    /// Whether the coordinator is permanently refusing new writes.
    pub poisoned: bool,
    /// Path-redacted reason for a permanent poison state.
    pub poison_reason: Option<String>,
}

#[derive(Default)]
struct CoordinatorStatus {
    state: RwLock<V2CommitCoordinatorStatus>,
}

impl CoordinatorStatus {
    fn snapshot(&self) -> V2CommitCoordinatorStatus {
        match self.state.read() {
            Ok(state) => state.clone(),
            Err(_error) => V2CommitCoordinatorStatus {
                poisoned: true,
                poison_reason: Some("v2 commit coordinator status lock poisoned".to_owned()),
            },
        }
    }

    fn set_healthy(&self) {
        match self.state.write() {
            Ok(mut state) => *state = V2CommitCoordinatorStatus::default(),
            Err(error) => {
                tracing::error!(
                    target: "rs3_repository",
                    operation = "v2_commit_coordinator_status",
                    error = %error,
                    "v2 commit coordinator could not clear status",
                );
            }
        }
        record_v2_commit_coordinator_poisoned(false);
    }

    fn set_poisoned(&self, reason: String) {
        match self.state.write() {
            Ok(mut state) => {
                *state = V2CommitCoordinatorStatus {
                    poisoned: true,
                    poison_reason: Some(reason),
                };
            }
            Err(error) => {
                tracing::error!(
                    target: "rs3_repository",
                    operation = "v2_commit_coordinator_status",
                    error = %error,
                    "v2 commit coordinator could not record poisoned status",
                );
            }
        }
        record_v2_commit_coordinator_poisoned(true);
    }
}

impl<S, A> V2CommitCoordinator<S, A>
where
    S: BlobStore + Clone + 'static,
    A: V2CommitAnchor + 'static,
{
    /// Creates a v2 commit coordinator for a repository and anchor.
    pub fn new(repository: Arc<V2Repository<S>>, anchor: A) -> Result<Self> {
        Self::with_options(repository, anchor, CommitCoordinatorOptions::default())
    }

    /// Creates a v2 commit coordinator with explicit batching options.
    pub fn with_options(
        repository: Arc<V2Repository<S>>,
        anchor: A,
        options: CommitCoordinatorOptions,
    ) -> Result<Self> {
        let lease = repository.claim_commit_coordinator()?;
        record_v2_commit_coordinator_poisoned(false);
        Ok(Self {
            repository,
            anchor: Arc::new(anchor),
            options: options.normalized(),
            stage_lock: Arc::new(Mutex::new(())),
            batch: Arc::new(Mutex::new(PendingBatch::default())),
            status: Arc::new(CoordinatorStatus::default()),
            lease,
            maintenance_guard: None,
        })
    }

    /// Enables automatic metadata-only index compaction at catalog watermarks.
    pub fn with_maintenance_guard<G>(mut self, guard: G) -> Self
    where
        G: V2MaintenanceGuard + 'static,
    {
        self.maintenance_guard = Some(Arc::new(guard));
        self
    }

    /// Returns the coordinated v2 repository.
    pub fn repository(&self) -> &Arc<V2Repository<S>> {
        &self.repository
    }

    /// Returns the v2 anchor used by this coordinator.
    pub fn anchor(&self) -> &Arc<A> {
        &self.anchor
    }

    /// Returns the live coordinator status for path-redacted operator reports.
    pub fn status(&self) -> V2CommitCoordinatorStatus {
        self.status.snapshot()
    }

    #[cfg(test)]
    pub(crate) async fn pending_item_count_for_tests(&self) -> usize {
        self.batch.lock().await.waiters.len()
    }

    fn clone_for_owned_task(&self) -> Self {
        Self {
            repository: Arc::clone(&self.repository),
            anchor: Arc::clone(&self.anchor),
            options: self.options,
            stage_lock: Arc::clone(&self.stage_lock),
            batch: Arc::clone(&self.batch),
            status: Arc::clone(&self.status),
            lease: Arc::clone(&self.lease),
            maintenance_guard: self.maintenance_guard.clone(),
        }
    }

    /// Writes an object and returns only after a covering v2 commit is accepted.
    pub async fn put_committed(
        &self,
        key: LogicalPath,
        body: Bytes,
        options: RepositoryPutOptions,
    ) -> Result<V2CommittedPut> {
        self.repository.validate_client_object_lock(&options)?;
        let (retention, legal_hold) = self.repository.effective_put_protection(&options);
        let protection = V2ProtectionCohort {
            retention,
            legal_hold,
        };
        let (metadata, rx, delayed_publish_generation, should_publish_now) = {
            let stage_lock_started = Instant::now();
            let _stage = self.stage_lock.lock().await;
            record_v2_commit_put_phase_duration("stage_lock_wait", stage_lock_started.elapsed());
            let incompatible_pending = {
                let batch = self.batch.lock().await;
                !batch.waiters.is_empty() && batch.protection != Some(protection)
            };
            if incompatible_pending {
                self.publish_locked_batch().await?;
            }
            self.prepare_index_catalog_for_growth_locked().await?;
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

            let stage_write_started = Instant::now();
            let staged = self.repository.stage_put(key, body, options).await;
            record_v2_commit_put_phase_duration("stage_write", stage_write_started.elapsed());
            let (metadata, rollback) = staged?;
            let (tx, rx) = oneshot::channel();
            let mut batch = self.batch.lock().await;
            if batch.waiters.is_empty() {
                batch.protection = Some(protection);
            } else if batch.protection != Some(protection) {
                return Err(commit_failed(
                    "v2 commit batch contains incompatible protection cohorts",
                ));
            }
            let delayed_publish_generation = if should_start_timer {
                batch.generation = batch.generation.wrapping_add(1);
                Some(batch.generation)
            } else {
                None
            };

            batch.waiters.push(CommitWaiter { tx });
            batch.rollback_log.push(rollback);
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
                    DelayedPublishContext {
                        repository: Arc::clone(&self.repository),
                        anchor: Arc::clone(&self.anchor),
                        stage_lock: Arc::clone(&self.stage_lock),
                        batch: Arc::clone(&self.batch),
                        status: Arc::clone(&self.status),
                        lease: Arc::clone(&self.lease),
                    },
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
                Arc::clone(&self.status),
                delayed_publish_generation,
            )
            .await;
        }

        let anchor_state = match rx.await {
            Ok(Ok(anchor_state)) => {
                record_v2_commit_put_phase_duration("commit_wait", commit_wait_started.elapsed());
                anchor_state
            }
            Ok(Err(error)) => {
                record_v2_commit_put_phase_duration("commit_wait", commit_wait_started.elapsed());
                return Err(error.into_repository_error());
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

    /// Uploads one known-length payload outside the publication lease, then
    /// publishes its exact immutable object reference in a short fenced batch.
    pub async fn put_committed_streaming_known_len<St>(
        &self,
        key: LogicalPath,
        plaintext_len: u64,
        stream: St,
        options: RepositoryPutOptions,
        multipart_part_size: usize,
    ) -> Result<V2CommittedPut>
    where
        St: Stream<Item = Result<Bytes>> + Unpin + Send + 'static,
    {
        self.repository.validate_client_object_lock(&options)?;
        let cancellation = Arc::new(V2StandaloneUploadCancellation::new());
        let mut cancel_on_drop = CancelStandaloneUploadOnDrop::new(Arc::clone(&cancellation));
        let repository = Arc::clone(&self.repository);
        let upload_options = options.clone();
        let upload_task = tokio::spawn(async move {
            repository
                .upload_standalone_streaming_known_len(
                    plaintext_len,
                    stream,
                    &upload_options,
                    multipart_part_size,
                    cancellation,
                )
                .await
        });
        let upload = upload_task
            .await
            .map_err(|_| commit_failed("v2 standalone upload task failed"))??;
        let owned = self.clone_for_owned_task();
        let publication_task = tokio::spawn(async move {
            let _stage = owned.stage_lock.lock().await;
            owned.publish_locked_batch().await?;
            owned.prepare_index_catalog_for_growth_locked().await?;
            let metadata = owned
                .repository
                .publish_standalone_streaming_known_len_coordinated(
                    V2CoordinatedMutation::new(&owned.lease, owned.anchor.as_ref()),
                    key,
                    plaintext_len,
                    upload,
                    options,
                )
                .await?;
            let anchor_state = owned
                .anchor
                .read_v2()
                .await
                .map_err(v2_commit_error)?
                .ok_or_else(|| commit_failed("v2 anchor is missing after streamed commit"))?;
            Ok(V2CommittedPut {
                metadata,
                anchor_state,
            })
        });
        cancel_on_drop.disarm();
        publication_task
            .await
            .map_err(|_| commit_failed("v2 standalone publication task failed"))?
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
        self.repository.validate_client_object_lock(&options)?;
        let _stage = self.stage_lock.lock().await;
        self.publish_locked_batch().await?;
        self.prepare_index_catalog_for_growth_locked().await?;
        let metadata = self
            .repository
            .put_committed_streaming_unknown_len_coordinated(
                V2CoordinatedMutation::new(&self.lease, self.anchor.as_ref()),
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
        self.prepare_index_catalog_for_growth_locked().await?;
        self.repository
            .delete_committed_coordinated(
                V2CoordinatedMutation::new(&self.lease, self.anchor.as_ref()),
                key,
            )
            .await
    }

    /// Rejects legal-hold mutation until dependency-wide hold lifecycle exists.
    pub async fn set_legal_hold_committed(
        &self,
        key: LogicalPath,
        status: LegalHoldStatus,
    ) -> Result<RepositoryObjectMetadata> {
        self.repository
            .set_legal_hold_committed_coordinated(
                V2CoordinatedMutation::new(&self.lease, self.anchor.as_ref()),
                key,
                status,
            )
            .await
    }

    /// Flushes pending writes and publishes a full v2 index snapshot commit.
    pub async fn write_index_snapshot(&self) -> Result<V2AnchorState> {
        let _stage = self.stage_lock.lock().await;
        self.publish_locked_batch().await?;
        if self.prepare_index_catalog_for_growth_locked().await? {
            return self
                .anchor
                .read_v2()
                .await
                .map_err(v2_commit_error)?
                .ok_or_else(|| commit_failed("v2 anchor is missing after index compaction"));
        }
        self.repository
            .write_index_snapshot_coordinated(V2CoordinatedMutation::new(
                &self.lease,
                self.anchor.as_ref(),
            ))
            .await
            .map(|stored| stored.anchor_state)
    }

    /// Flushes pending writes and reloads accepted state from the external anchor.
    pub async fn reload_from_anchor(&self) -> Result<Option<V2ReplayChain>> {
        let _stage = self.stage_lock.lock().await;
        self.publish_locked_batch().await?;
        self.repository
            .load_chain_from_anchor_coordinated(V2CoordinatedMutation::new(
                &self.lease,
                self.anchor.as_ref(),
            ))
            .await
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
                rollback_log: std::mem::take(&mut batch.rollback_log),
            }
        };

        let result = publish_v2_waiters(
            &self.repository,
            self.anchor.as_ref(),
            pending.waiters,
            pending.rollback_log,
        )
        .await;
        let mut batch = self.batch.lock().await;
        batch.publishing = false;
        batch.protection = None;
        if let Err(failure) = result {
            if let Some(poison_reason) = failure.poison_reason.clone() {
                batch.failed = Some(poison_reason.clone());
                self.status.set_poisoned(poison_reason);
            } else {
                self.status.set_healthy();
            }
            return Err(RepositoryError::CommitFailed {
                reason: failure.reason,
            });
        }
        self.status.set_healthy();
        Ok(())
    }

    async fn prepare_index_catalog_for_growth_locked(&self) -> Result<bool> {
        let initial_count = self.repository.active_index_run_count()?;
        if initial_count < V2_INDEX_COMPACTION_REQUEST_RUNS {
            return Ok(false);
        }
        let should_attempt = initial_count >= V2_INDEX_COMPACTION_PAUSE_RUNS
            || initial_count % V2_INDEX_COMPACTION_RETRY_INTERVAL_RUNS == 0;
        if !should_attempt {
            return Ok(false);
        }

        // Another caller can stage the next batch before this task acquires
        // the stage lock. Publish it first so compaction never folds
        // unanchored mutations into a candidate root.
        self.publish_locked_batch().await?;
        let count = self.repository.active_index_run_count()?;
        let level_zero_count = self.repository.active_level_zero_index_run_count()?;
        if level_zero_count < 2 {
            if count < V2_INDEX_COMPACTION_PAUSE_RUNS {
                return Ok(false);
            }
            return self
                .poison_for_compaction_failure(V2FormatError::MaintenanceBudgetExceeded.to_string())
                .await;
        }
        if let Some(guard) = self.maintenance_guard.as_deref() {
            match self
                .repository
                .compact_packed_index_runs_coordinated(
                    V2CoordinatedMutation::new(&self.lease, self.anchor.as_ref()),
                    guard,
                )
                .await
            {
                Ok(_) => return Ok(true),
                Err(RepositoryError::MaintenanceNotBeneficial)
                    if count < V2_INDEX_COMPACTION_PAUSE_RUNS =>
                {
                    tracing::warn!(
                        target: "rs3_repository",
                        operation = "v2_index_auto_compaction",
                        active_runs = count,
                        result = "not_reducing",
                        "v2 writer will retry bounded index compaction at a later watermark",
                    );
                    return Ok(false);
                }
                Err(error) => {
                    return self.poison_for_compaction_failure(error.to_string()).await;
                }
            }
        }
        if count < V2_INDEX_COMPACTION_PAUSE_RUNS {
            tracing::warn!(
                target: "rs3_repository",
                operation = "v2_index_auto_compaction",
                active_runs = count,
                result = "guard_unavailable",
                "v2 index compaction is due but no maintenance guard is configured",
            );
            return Ok(false);
        }
        self.poison_for_compaction_failure(V2FormatError::MaintenanceAccessRequired.to_string())
            .await
    }

    async fn poison_for_compaction_failure<T>(&self, reason: String) -> Result<T> {
        let reason = format!("automatic v2 index compaction failed: {reason}");
        {
            let mut batch = self.batch.lock().await;
            batch.failed = Some(reason.clone());
        }
        self.status.set_poisoned(reason.clone());
        Err(RepositoryError::CommitFailed { reason })
    }
}

struct PendingPublish {
    waiters: Vec<CommitWaiter>,
    rollback_log: Vec<V2StagedPutRollback>,
}

struct DelayedPublishContext<S, A> {
    repository: Arc<V2Repository<S>>,
    anchor: Arc<A>,
    stage_lock: Arc<Mutex<()>>,
    batch: Arc<Mutex<PendingBatch>>,
    status: Arc<CoordinatorStatus>,
    lease: Arc<V2CoordinatorLease>,
}

fn spawn_delayed_v2_publish<S, A>(
    context: DelayedPublishContext<S, A>,
    generation: u64,
    delay: Duration,
) where
    S: BlobStore + Clone + 'static,
    A: V2CommitAnchor + 'static,
{
    tokio::spawn(async move {
        let _lease = context.lease;
        sleep(delay).await;
        publish_pending_v2_batch(
            context.repository,
            context.anchor,
            context.stage_lock,
            context.batch,
            context.status,
            Some(generation),
        )
        .await;
    });
}

async fn publish_pending_v2_batch<S, A>(
    repository: Arc<V2Repository<S>>,
    anchor: Arc<A>,
    stage_lock: Arc<Mutex<()>>,
    batch: Arc<Mutex<PendingBatch>>,
    status: Arc<CoordinatorStatus>,
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
            rollback_log: std::mem::take(&mut batch.rollback_log),
        }
    };

    let result = publish_v2_waiters(
        &repository,
        anchor.as_ref(),
        pending.waiters,
        pending.rollback_log,
    )
    .await;
    let mut batch = batch.lock().await;
    batch.publishing = false;
    batch.protection = None;
    if let Err(failure) = result {
        if let Some(poison_reason) = failure.poison_reason {
            batch.failed = Some(poison_reason.clone());
            status.set_poisoned(poison_reason);
        } else {
            status.set_healthy();
        }
    } else {
        status.set_healthy();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PublishFailure {
    reason: String,
    poison_reason: Option<String>,
}

async fn publish_v2_waiters<S, A>(
    repository: &V2Repository<S>,
    anchor: &A,
    waiters: Vec<CommitWaiter>,
    rollback_log: Vec<V2StagedPutRollback>,
) -> std::result::Result<(), PublishFailure>
where
    S: BlobStore + Clone + 'static,
    A: V2CommitAnchor + 'static,
{
    let waiter_count = waiters.len();
    let started = Instant::now();
    let published = repository.publish_pending_index_delta(anchor).await;
    let accepted_recovery_required =
        matches!(&published, Err(RepositoryError::AcceptedRecoveryRequired));
    let result = match published {
        Ok(Some(stored)) => Ok(stored.anchor_state),
        Ok(None) => Err(CommitWaiterError::Failed(
            "v2 commit batch had no pending index delta".to_owned(),
        )),
        Err(RepositoryError::AcceptedRecoveryRequired) => {
            Err(CommitWaiterError::AcceptedRecoveryRequired)
        }
        Err(error) => Err(CommitWaiterError::Failed(error.to_string())),
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

    let mut failure = result.as_ref().err().map(|error| {
        let reason = error.reason();
        record_v2_commit_batch_publish_failure("publish");
        PublishFailure {
            reason,
            poison_reason: None,
        }
    });
    if accepted_recovery_required {
        let reason = "v2 commit was accepted but local state recovery is required".to_owned();
        record_v2_commit_batch_publish_failure("local_install");
        failure = Some(PublishFailure {
            reason: reason.clone(),
            poison_reason: Some(reason),
        });
    }
    if result.is_err()
        && !accepted_recovery_required
        && let Err(error) = repository.rollback_staged_puts(rollback_log)
    {
        let poison_reason = match failure.as_ref() {
            Some(failure) => format!(
                "v2 commit batch publish failed: {}; rollback failed: {}",
                failure.reason, error
            ),
            None => format!("v2 commit batch rollback failed: {error}"),
        };
        if let Some(failure) = failure.as_mut() {
            failure.poison_reason = Some(poison_reason.clone());
        }
        record_v2_commit_batch_publish_failure("rollback");
        tracing::error!(
            target: "rs3_repository",
            operation = "v2_commit_batch_rollback",
            error = %error,
            reason = %poison_reason,
            "v2 commit coordinator failed to restore unaccepted state",
        );
    }

    for waiter in waiters {
        let _ = waiter.tx.send(result.clone());
    }

    match failure {
        Some(failure) => Err(failure),
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

fn record_v2_commit_batch_publish_failure(stage: &'static str) {
    metrics::counter!(
        "rs3_repository_v2_commit_batch_publish_failures_total",
        "stage" => stage,
    )
    .increment(1);
}

fn record_v2_commit_coordinator_poisoned(poisoned: bool) {
    metrics::gauge!("rs3_repository_v2_commit_coordinator_poisoned").set(if poisoned {
        1.0
    } else {
        0.0
    });
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
