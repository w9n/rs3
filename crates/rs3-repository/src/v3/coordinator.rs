//! Commit coordination for preview v3 repository writes.

use super::repository::{
    V3AnchorState, V3CommitAnchor, V3ReplayChain, V3StandaloneUploadCancellation, V3StoredCommit,
};
use super::service::{
    V3CoordinatedMutation, V3CoordinatorLease, V3FullMaintenanceReport, V3Repository,
    V3StagedPutRollback,
};
use super::{V3FormatError, V3FullGcApplyOptions, V3MaintenanceCancellation, V3MaintenanceGuard};
use crate::CommitCoordinatorOptions;
use crate::error::{RepositoryError, Result};
use crate::model::{
    DeleteOutcome, RepositoryCopyOptions, RepositoryObjectMetadata, RepositoryPutOptions,
};
use bytes::Bytes;
use futures_util::Stream;
use rs3_storage::BlobStore;
use rs3_types::{LegalHoldStatus, LogicalPath, RetentionPolicy};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Notify, OwnedMutexGuard, oneshot};
use tokio::time::sleep;

/// Active-run count at which a guarded coordinator first requests compaction.
pub const V3_INDEX_COMPACTION_REQUEST_RUNS: usize = 256;
/// Active-run count at which writes pause unless guarded compaction succeeds.
pub const V3_INDEX_COMPACTION_PAUSE_RUNS: usize = 896;
const V3_INDEX_COMPACTION_RETRY_INTERVAL_RUNS: usize = 64;

/// Result of a v3 write accepted by the external anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V3CommittedPut {
    /// Client-visible object metadata.
    pub metadata: RepositoryObjectMetadata,
    /// Accepted v3 anchor state covering this write.
    pub anchor_state: V3AnchorState,
}

/// Exclusive in-process v3 maintenance window over a drained coordinator.
///
/// While this window is held the coordinator staging lock stays locked, so no
/// new publication, staged put, streamed write, or delete can start. Staged
/// writers block on the same staging lock they already use for ordinary
/// publication stalls instead of being queued or rejected differently, and
/// they resume unchanged once the window is dropped. A window is only handed
/// out after pending commit batches are drained and the configured
/// maintenance guard verified the base anchor, so destructive maintenance
/// never starts against an unverified or half-published world.
pub struct V3MaintenanceWindow {
    guard: Arc<dyn V3MaintenanceGuard>,
    base_anchor: Option<V3AnchorState>,
    _stage: OwnedMutexGuard<()>,
    _publisher: OwnedMutexGuard<()>,
}

impl std::fmt::Debug for V3MaintenanceWindow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("V2MaintenanceWindow")
            .field(
                "base_sequence",
                &self.base_anchor.as_ref().map(|anchor| anchor.sequence),
            )
            .finish_non_exhaustive()
    }
}

impl V3MaintenanceWindow {
    /// Returns the verified maintenance guard bound to this window.
    pub fn guard(&self) -> &Arc<dyn V3MaintenanceGuard> {
        &self.guard
    }

    /// Returns the anchor state observed when the window was verified.
    pub fn base_anchor(&self) -> Option<&V3AnchorState> {
        self.base_anchor.as_ref()
    }
}

/// Coordinates v3 repository writes that must not be acknowledged before commit.
pub struct V3CommitCoordinator<S, A> {
    repository: Arc<V3Repository<S>>,
    anchor: Arc<A>,
    options: CommitCoordinatorOptions,
    stage_lock: Arc<Mutex<()>>,
    publisher: Arc<Mutex<()>>,
    capacity_changed: Arc<Notify>,
    batch: Arc<Mutex<PendingBatch>>,
    status: Arc<CoordinatorStatus>,
    lease: Arc<V3CoordinatorLease>,
    maintenance_guard: Option<Arc<dyn V3MaintenanceGuard>>,
}

#[derive(Default)]
struct PendingBatch {
    waiters: Vec<CommitWaiter>,
    rollback_log: Vec<V3StagedPutRollback>,
    publishing: bool,
    publishing_items: usize,
    generation: u64,
    failed: Option<String>,
    protection: Option<V3ProtectionCohort>,
    #[cfg(test)]
    force_cohort_mismatch_for_tests: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct V3ProtectionCohort {
    retention: Option<RetentionPolicy>,
    legal_hold: Option<LegalHoldStatus>,
}

enum CoordinatedWrite {
    Put {
        key: LogicalPath,
        body: Bytes,
        options: RepositoryPutOptions,
    },
    Copy {
        source: LogicalPath,
        destination: LogicalPath,
        options: RepositoryCopyOptions,
    },
}

struct CommitWaiter {
    tx: oneshot::Sender<std::result::Result<V3AnchorState, CommitWaiterError>>,
}

struct CancelStandaloneUploadOnDrop {
    cancellation: Arc<V3StandaloneUploadCancellation>,
    armed: bool,
}

impl CancelStandaloneUploadOnDrop {
    fn new(cancellation: Arc<V3StandaloneUploadCancellation>) -> Self {
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

/// Live v3 commit coordinator state safe for path-redacted operator reports.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct V3CommitCoordinatorStatus {
    /// Whether the coordinator is permanently refusing new writes.
    pub poisoned: bool,
    /// Path-redacted reason for a permanent poison state.
    pub poison_reason: Option<String>,
}

#[derive(Default)]
struct CoordinatorStatus {
    state: RwLock<V3CommitCoordinatorStatus>,
}

impl CoordinatorStatus {
    fn snapshot(&self) -> V3CommitCoordinatorStatus {
        match self.state.read() {
            Ok(state) => state.clone(),
            Err(_error) => V3CommitCoordinatorStatus {
                poisoned: true,
                poison_reason: Some("v2 commit coordinator status lock poisoned".to_owned()),
            },
        }
    }

    fn set_healthy(&self) {
        match self.state.write() {
            Ok(mut state) => *state = V3CommitCoordinatorStatus::default(),
            Err(error) => {
                tracing::error!(
                    target: "rs3_repository",
                    operation = "v2_commit_coordinator_status",
                    error = %error,
                    "v2 commit coordinator could not clear status",
                );
            }
        }
        record_v3_commit_coordinator_poisoned(false);
    }

    fn set_poisoned(&self, reason: String) {
        match self.state.write() {
            Ok(mut state) => {
                *state = V3CommitCoordinatorStatus {
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
        record_v3_commit_coordinator_poisoned(true);
    }
}

impl<S, A> V3CommitCoordinator<S, A>
where
    S: BlobStore + Clone + 'static,
    A: V3CommitAnchor + 'static,
{
    /// Creates a v3 commit coordinator for a repository and anchor.
    pub fn new(repository: Arc<V3Repository<S>>, anchor: A) -> Result<Self> {
        Self::with_options(repository, anchor, CommitCoordinatorOptions::default())
    }

    /// Creates a v3 commit coordinator with explicit batching options.
    pub fn with_options(
        repository: Arc<V3Repository<S>>,
        anchor: A,
        options: CommitCoordinatorOptions,
    ) -> Result<Self> {
        let lease = repository.claim_commit_coordinator()?;
        record_v3_commit_coordinator_poisoned(false);
        Ok(Self {
            repository,
            anchor: Arc::new(anchor),
            options: options.normalized(),
            stage_lock: Arc::new(Mutex::new(())),
            publisher: Arc::new(Mutex::new(())),
            capacity_changed: Arc::new(Notify::new()),
            batch: Arc::new(Mutex::new(PendingBatch::default())),
            status: Arc::new(CoordinatorStatus::default()),
            lease,
            maintenance_guard: None,
        })
    }

    /// Enables automatic metadata-only index compaction at catalog watermarks.
    pub fn with_maintenance_guard<G>(mut self, guard: G) -> Self
    where
        G: V3MaintenanceGuard + 'static,
    {
        self.maintenance_guard = Some(Arc::new(guard));
        self
    }

    /// Returns the coordinated v3 repository.
    pub fn repository(&self) -> &Arc<V3Repository<S>> {
        &self.repository
    }

    /// Returns the v3 anchor used by this coordinator.
    pub fn anchor(&self) -> &Arc<A> {
        &self.anchor
    }

    /// Returns the live coordinator status for path-redacted operator reports.
    pub fn status(&self) -> V3CommitCoordinatorStatus {
        self.status.snapshot()
    }

    /// Returns whether a maintenance guard is configured on this coordinator.
    ///
    /// Without a configured guard every maintenance window request fails
    /// closed, so callers can use this to park automation instead of spinning
    /// failing runs.
    pub fn has_maintenance_guard(&self) -> bool {
        self.maintenance_guard.is_some()
    }

    /// Opens a drained, guard-verified exclusion window for full maintenance.
    ///
    /// This waits for any in-flight batch publication, publishes the pending
    /// batch, and then holds the staging lock so no new publication can start
    /// until the returned window is dropped. It fails closed when no
    /// maintenance guard is configured, when the coordinator is poisoned or
    /// the pending batch cannot be drained, or when the configured guard
    /// cannot verify the base anchor.
    pub async fn begin_maintenance_window(&self) -> Result<V3MaintenanceWindow> {
        let Some(guard) = self.maintenance_guard.clone() else {
            return Err(v3_commit_error(V3FormatError::MaintenanceAccessRequired));
        };
        let publisher = Arc::clone(&self.publisher).lock_owned().await;
        let stage = Arc::clone(&self.stage_lock).lock_owned().await;
        self.publish_locked_batch().await?;
        guard
            .verify_v3_maintenance(None)
            .await
            .map_err(v3_commit_error)?;
        let base_anchor = self.anchor.read_v3().await.map_err(v3_commit_error)?;
        guard
            .verify_v3_maintenance(base_anchor.as_ref())
            .await
            .map_err(v3_commit_error)?;
        Ok(V3MaintenanceWindow {
            guard,
            base_anchor,
            _stage: stage,
            _publisher: publisher,
        })
    }

    /// Runs budgeted v3 full maintenance inside a drained exclusion window.
    ///
    /// Automatic runs may first publish a recovery-expiry checkpoint when an
    /// authenticated history record has actually expired. The full-GC plan is
    /// then prepared from that accepted anchor. A digest-bound operator apply
    /// deliberately skips this automatic transition so it can only apply the
    /// exact plan the operator reviewed.
    pub async fn run_full_maintenance(
        &self,
        options: V3FullGcApplyOptions,
        cancellation: &V3MaintenanceCancellation,
    ) -> Result<V3FullMaintenanceReport> {
        self.run_full_maintenance_expected(options, None, cancellation, &|| {})
            .await
    }

    /// Runs full maintenance with an optional operator-reviewed plan digest.
    ///
    /// See [`Self::run_full_maintenance`] for the recovery-expiry behavior.
    /// Supplying `expected_plan_digest` prevents an automatic checkpoint from
    /// changing the reviewed plan before its stale-plan comparison.
    pub async fn run_full_maintenance_expected(
        &self,
        options: V3FullGcApplyOptions,
        expected_plan_digest: Option<&str>,
        cancellation: &V3MaintenanceCancellation,
        on_applying: &(dyn Fn() + Send + Sync),
    ) -> Result<V3FullMaintenanceReport> {
        let window = self.begin_maintenance_window().await?;
        let report = async {
            if expected_plan_digest.is_none() {
                self.repository
                    .maybe_publish_recovery_expiry_checkpoint_coordinated(
                        V3CoordinatedMutation::new(&self.lease, self.anchor.as_ref())
                            .with_guard(Some(window.guard())),
                    )
                    .await?;
            }
            on_applying();
            self.repository
                .apply_full_gc_quiesced_expected(
                    self.anchor.as_ref(),
                    window.guard(),
                    options,
                    expected_plan_digest,
                    cancellation,
                )
                .await
        }
        .await;
        drop(window);
        report
    }

    #[cfg(test)]
    pub(crate) async fn pending_item_count_for_tests(&self) -> usize {
        self.batch.lock().await.waiters.len()
    }

    /// Makes the next enqueue take the defensive cohort-mismatch branch.
    #[cfg(test)]
    pub(crate) async fn force_cohort_mismatch_for_tests(&self) {
        self.batch.lock().await.force_cohort_mismatch_for_tests = true;
    }

    fn clone_for_owned_task(&self) -> Self {
        Self {
            repository: Arc::clone(&self.repository),
            anchor: Arc::clone(&self.anchor),
            options: self.options,
            stage_lock: Arc::clone(&self.stage_lock),
            publisher: Arc::clone(&self.publisher),
            capacity_changed: Arc::clone(&self.capacity_changed),
            batch: Arc::clone(&self.batch),
            status: Arc::clone(&self.status),
            lease: Arc::clone(&self.lease),
            maintenance_guard: self.maintenance_guard.clone(),
        }
    }

    fn publication_context(&self) -> PublicationContext<S, A> {
        PublicationContext {
            repository: Arc::clone(&self.repository),
            anchor: Arc::clone(&self.anchor),
            stage_lock: Arc::clone(&self.stage_lock),
            publisher: Arc::clone(&self.publisher),
            capacity_changed: Arc::clone(&self.capacity_changed),
            batch: Arc::clone(&self.batch),
            status: Arc::clone(&self.status),
            lease: Arc::clone(&self.lease),
            maintenance_guard: self.maintenance_guard.clone(),
        }
    }

    /// Writes an object and returns only after a covering v3 commit is accepted.
    pub async fn put_committed(
        &self,
        key: LogicalPath,
        body: Bytes,
        options: RepositoryPutOptions,
    ) -> Result<V3CommittedPut> {
        self.repository.validate_client_object_lock(&options)?;
        self.enqueue_write(CoordinatedWrite::Put { key, body, options })
            .await
    }

    /// Copies the exact accepted source reference without reading payload bytes.
    /// Source conditions are checked at capture; success waits for anchored publication.
    pub async fn copy_committed(
        &self,
        source: LogicalPath,
        destination: LogicalPath,
        options: RepositoryCopyOptions,
    ) -> Result<V3CommittedPut> {
        options.validate()?;
        self.enqueue_write(CoordinatedWrite::Copy {
            source,
            destination,
            options,
        })
        .await
    }

    async fn enqueue_write(&self, write: CoordinatedWrite) -> Result<V3CommittedPut> {
        let (metadata, rx, publish_generation, should_publish_now) = {
            let stage_lock_started = Instant::now();
            let mut compaction_checked = false;
            let (_stage, copy_source, protection) = loop {
                // Register before checking capacity, so publication cannot signal
                // between releasing staging and starting the wait.
                let changed = self.capacity_changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                let stage = self.stage_lock.lock().await;
                let copy_source = match &write {
                    CoordinatedWrite::Copy {
                        source, options, ..
                    } => match self.repository.capture_copy_source(source, options) {
                        Ok(source) => Some(source),
                        Err(RepositoryError::NotFound(_))
                            if {
                                let batch = self.batch.lock().await;
                                batch.publishing || !batch.waiters.is_empty()
                            } =>
                        {
                            drop(stage);
                            let _publisher = self.publisher.lock().await;
                            let _stage = self.stage_lock.lock().await;
                            self.publish_locked_batch().await?;
                            continue;
                        }
                        Err(error) => return Err(error),
                    },
                    CoordinatedWrite::Put { .. } => None,
                };
                let (retention, legal_hold) = match (&write, &copy_source) {
                    (CoordinatedWrite::Put { options, .. }, _) => {
                        self.repository.effective_put_protection(options)
                    }
                    (_, Some(source)) => {
                        (source.metadata().retention, source.metadata().legal_hold)
                    }
                    _ => return Err(commit_failed("copy source capture missing")),
                };
                let protection = V3ProtectionCohort {
                    retention,
                    legal_hold,
                };
                let retained_copy = copy_source.is_some()
                    && (retention.is_some_and(|policy| {
                        policy.mode != rs3_types::RetentionMode::None && policy.retain_days > 0
                    }) || legal_hold == Some(LegalHoldStatus::On));
                let (wait_for_capacity, needs_barrier) = {
                    let batch = self.batch.lock().await;
                    let occupied = batch.publishing || !batch.waiters.is_empty();
                    let wait_for_capacity = batch.failed.is_none()
                        && ((batch.publishing
                            && batch.waiters.len().saturating_add(batch.publishing_items)
                                >= self.options.max_pending_items)
                            || batch.waiters.len() >= self.options.max_batch_items);
                    (
                        wait_for_capacity,
                        (occupied && batch.protection != Some(protection))
                            || (retained_copy && batch.publishing)
                            || (!compaction_checked
                                && index_compaction_due(self.repository.active_index_run_count()?)),
                    )
                };
                if wait_for_capacity {
                    drop(stage);
                    changed.await;
                    continue;
                }
                if needs_barrier {
                    drop(stage);
                    let _publisher = self.publisher.lock().await;
                    let _stage = self.stage_lock.lock().await;
                    self.publish_locked_batch().await?;
                    self.prepare_index_catalog_for_growth_locked().await?;
                    compaction_checked = true;
                    continue;
                }
                break (stage, copy_source, protection);
            };
            record_v3_commit_put_phase_duration("stage_lock_wait", stage_lock_started.elapsed());
            let should_start_timer = {
                let batch = self.batch.lock().await;
                if let Some(reason) = batch.failed.as_ref() {
                    record_v3_commit_enqueue("failed", batch.waiters.len());
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
                let pending_items = batch.waiters.len().saturating_add(batch.publishing_items);
                if pending_items >= self.options.max_pending_items {
                    record_v3_commit_enqueue("backpressure", pending_items);
                    tracing::warn!(
                        target: "rs3_repository",
                        operation = "v2_put_committed_enqueue",
                        pending_items,
                        max_pending_items = self.options.max_pending_items,
                        result = "backpressure",
                        "v2 commit coordinator rejected write",
                    );
                    return Err(RepositoryError::CommitBackpressure);
                }
                batch.waiters.is_empty()
            };

            let stage_write_started = Instant::now();
            let staged = match write {
                CoordinatedWrite::Put { key, body, options } => {
                    self.repository.stage_put(key, body, options).await
                }
                CoordinatedWrite::Copy { destination, .. } => {
                    let source =
                        copy_source.ok_or_else(|| commit_failed("copy source capture missing"))?;
                    self.repository
                        .stage_copy_coordinated(
                            V3CoordinatedMutation::new(&self.lease, self.anchor.as_ref()),
                            source,
                            destination,
                            self.maintenance_guard.as_deref(),
                        )
                        .await
                }
            };
            record_v3_commit_put_phase_duration("stage_write", stage_write_started.elapsed());
            let (metadata, rollback) = staged?;
            let (tx, rx) = oneshot::channel();
            let mut batch = self.batch.lock().await;
            #[cfg(test)]
            let forced_mismatch = std::mem::take(&mut batch.force_cohort_mismatch_for_tests);
            #[cfg(not(test))]
            let forced_mismatch = false;
            if !forced_mismatch && batch.waiters.is_empty() && !batch.publishing {
                batch.protection = Some(protection);
            } else if forced_mismatch || batch.protection != Some(protection) {
                drop(batch);
                // The staged overlay entry must not outlive a rejected enqueue,
                // or the next batch publishes a write whose client saw failure.
                self.repository.rollback_staged_puts(vec![rollback])?;
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
            record_v3_commit_enqueue("ok", batch.waiters.len());
            tracing::debug!(
                target: "rs3_repository",
                operation = "v2_put_committed_enqueue",
                pending_items = batch.waiters.len(),
                max_batch_items = self.options.max_batch_items,
                result = "ok",
                "v2 commit coordinator queued write",
            );

            if let Some(generation) = delayed_publish_generation.filter(|_| !should_publish_now) {
                spawn_delayed_v3_publish(
                    self.publication_context(),
                    generation,
                    self.options.max_batch_delay,
                );
            }

            (metadata, rx, Some(batch.generation), should_publish_now)
        };

        let commit_wait_started = Instant::now();
        if should_publish_now {
            tokio::spawn(publish_pending_v3_batch(
                self.publication_context(),
                publish_generation,
            ));
        }

        let anchor_state = match rx.await {
            Ok(Ok(anchor_state)) => {
                record_v3_commit_put_phase_duration("commit_wait", commit_wait_started.elapsed());
                anchor_state
            }
            Ok(Err(error)) => {
                record_v3_commit_put_phase_duration("commit_wait", commit_wait_started.elapsed());
                return Err(error.into_repository_error());
            }
            Err(_) => {
                record_v3_commit_put_phase_duration("commit_wait", commit_wait_started.elapsed());
                return Err(commit_failed("v2 commit waiter was dropped"));
            }
        };

        Ok(V3CommittedPut {
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
    ) -> Result<V3CommittedPut>
    where
        St: Stream<Item = Result<Bytes>> + Unpin + Send + 'static,
    {
        self.repository.validate_client_object_lock(&options)?;
        let cancellation = Arc::new(V3StandaloneUploadCancellation::new());
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
            let _publisher = owned.publisher.lock().await;
            let _stage = owned.stage_lock.lock().await;
            owned.publish_locked_batch().await?;
            owned.prepare_index_catalog_for_growth_locked().await?;
            let metadata = owned
                .repository
                .publish_standalone_streaming_known_len_coordinated(
                    V3CoordinatedMutation::new(&owned.lease, owned.anchor.as_ref())
                        .with_guard(owned.maintenance_guard.as_deref()),
                    key,
                    plaintext_len,
                    upload,
                    options,
                )
                .await?;
            let anchor_state = owned
                .anchor
                .read_v3()
                .await
                .map_err(v3_commit_error)?
                .ok_or_else(|| commit_failed("v2 anchor is missing after streamed commit"))?;
            Ok(V3CommittedPut {
                metadata,
                anchor_state,
            })
        });
        cancel_on_drop.disarm();
        publication_task
            .await
            .map_err(|_| commit_failed("v2 standalone publication task failed"))?
    }

    /// Completes and verifies the detached carrier, then owns the short fenced
    /// publication even if the waiting client disconnects. Retry callers first
    /// consult the repository's authenticated completion receipt.
    pub async fn complete_multipart_upload(
        &self,
        upload: super::V3ClientMultipartUpload,
        selection: super::V3MultipartSelection,
    ) -> Result<rs3_index::completion::CompletionReceipt> {
        let owned = self.clone_for_owned_task();
        tokio::spawn(async move {
            let prepared = owned
                .repository
                .prepare_multipart_completion(upload, selection)
                .await?;
            let _publisher = owned.publisher.lock().await;
            let _stage = owned.stage_lock.lock().await;
            owned.publish_locked_batch().await?;
            owned.prepare_index_catalog_for_growth_locked().await?;
            owned
                .repository
                .publish_multipart_completion(
                    V3CoordinatedMutation::new(&owned.lease, owned.anchor.as_ref())
                        .with_guard(owned.maintenance_guard.as_deref()),
                    prepared,
                )
                .await
        })
        .await
        .map_err(|_| commit_failed("multipart completion task failed"))?
    }

    /// Writes one unknown-length streamed object after flushing pending batches.
    pub async fn put_committed_streaming_unknown_len<St>(
        &self,
        key: LogicalPath,
        stream: St,
        options: RepositoryPutOptions,
        multipart_part_size: usize,
        max_plaintext_len: u64,
    ) -> Result<V3CommittedPut>
    where
        St: Stream<Item = Result<Bytes>> + Unpin + Send,
    {
        self.repository.validate_client_object_lock(&options)?;
        let _publisher = self.publisher.lock().await;
        let _stage = self.stage_lock.lock().await;
        self.publish_locked_batch().await?;
        self.prepare_index_catalog_for_growth_locked().await?;
        let metadata = self
            .repository
            .put_committed_streaming_unknown_len_coordinated(
                V3CoordinatedMutation::new(&self.lease, self.anchor.as_ref())
                    .with_guard(self.maintenance_guard.as_deref()),
                key,
                stream,
                options,
                multipart_part_size,
                max_plaintext_len,
            )
            .await?;
        let anchor_state = self
            .anchor
            .read_v3()
            .await
            .map_err(v3_commit_error)?
            .ok_or_else(|| commit_failed("v2 anchor is missing after streamed commit"))?;
        Ok(V3CommittedPut {
            metadata,
            anchor_state,
        })
    }

    /// Deletes an object after flushing any pending staged v3 write batch.
    pub async fn delete_committed(&self, key: LogicalPath) -> Result<DeleteOutcome> {
        let _publisher = self.publisher.lock().await;
        let _stage = self.stage_lock.lock().await;
        self.publish_locked_batch().await?;
        self.prepare_index_catalog_for_growth_locked().await?;
        self.repository
            .delete_committed_coordinated(
                V3CoordinatedMutation::new(&self.lease, self.anchor.as_ref())
                    .with_guard(self.maintenance_guard.as_deref()),
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
                V3CoordinatedMutation::new(&self.lease, self.anchor.as_ref())
                    .with_guard(self.maintenance_guard.as_deref()),
                key,
                status,
            )
            .await
    }

    /// Flushes pending writes and publishes a full v3 index snapshot commit.
    pub async fn write_index_snapshot(&self) -> Result<V3AnchorState> {
        let _publisher = self.publisher.lock().await;
        let _stage = self.stage_lock.lock().await;
        self.publish_locked_batch().await?;
        if self.prepare_index_catalog_for_growth_locked().await? {
            return self
                .anchor
                .read_v3()
                .await
                .map_err(v3_commit_error)?
                .ok_or_else(|| commit_failed("v2 anchor is missing after index compaction"));
        }
        self.repository
            .write_index_snapshot_coordinated(
                V3CoordinatedMutation::new(&self.lease, self.anchor.as_ref())
                    .with_guard(self.maintenance_guard.as_deref()),
            )
            .await
            .map(|stored| stored.anchor_state)
    }

    /// Flushes pending writes and reloads accepted state from the external anchor.
    pub async fn reload_from_anchor(&self) -> Result<Option<V3ReplayChain>> {
        let _publisher = self.publisher.lock().await;
        let _stage = self.stage_lock.lock().await;
        self.publish_locked_batch().await?;
        self.repository
            .load_chain_from_anchor_coordinated(
                V3CoordinatedMutation::new(&self.lease, self.anchor.as_ref())
                    .with_guard(self.maintenance_guard.as_deref()),
            )
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
            batch.publishing_items = batch.waiters.len();
            PendingPublish {
                waiters: std::mem::take(&mut batch.waiters),
                rollback_log: std::mem::take(&mut batch.rollback_log),
            }
        };

        let started = Instant::now();
        let published = self
            .repository
            .publish_pending_index_delta(self.anchor.as_ref(), self.maintenance_guard.as_deref())
            .await;
        let result = finish_v3_waiters(
            &self.repository,
            pending.waiters,
            pending.rollback_log,
            published,
            started,
        );
        let mut batch = self.batch.lock().await;
        batch.publishing = false;
        batch.publishing_items = 0;
        batch.protection = None;
        self.capacity_changed.notify_waiters();
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
        if initial_count < V3_INDEX_COMPACTION_REQUEST_RUNS {
            return Ok(false);
        }
        if !index_compaction_due(initial_count) {
            return Ok(false);
        }

        // Another caller can stage the next batch before this task acquires
        // the stage lock. Publish it first so compaction never folds
        // unanchored mutations into a candidate root.
        self.publish_locked_batch().await?;
        let count = self.repository.active_index_run_count()?;
        let level_zero_count = self.repository.active_level_zero_index_run_count()?;
        if level_zero_count < 2 {
            if count < V3_INDEX_COMPACTION_PAUSE_RUNS {
                return Ok(false);
            }
            return self
                .poison_for_compaction_failure(V3FormatError::MaintenanceBudgetExceeded.to_string())
                .await;
        }
        if let Some(guard) = self.maintenance_guard.as_deref() {
            match self
                .repository
                .compact_packed_index_runs_coordinated(
                    V3CoordinatedMutation::new(&self.lease, self.anchor.as_ref())
                        .with_guard(Some(guard)),
                    guard,
                )
                .await
            {
                Ok(_) => return Ok(true),
                Err(RepositoryError::MaintenanceNotBeneficial)
                    if count < V3_INDEX_COMPACTION_PAUSE_RUNS =>
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
        if count < V3_INDEX_COMPACTION_PAUSE_RUNS {
            tracing::warn!(
                target: "rs3_repository",
                operation = "v2_index_auto_compaction",
                active_runs = count,
                result = "guard_unavailable",
                "v2 index compaction is due but no maintenance guard is configured",
            );
            return Ok(false);
        }
        self.poison_for_compaction_failure(V3FormatError::MaintenanceAccessRequired.to_string())
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
    rollback_log: Vec<V3StagedPutRollback>,
}

struct PublicationContext<S, A> {
    repository: Arc<V3Repository<S>>,
    anchor: Arc<A>,
    stage_lock: Arc<Mutex<()>>,
    publisher: Arc<Mutex<()>>,
    capacity_changed: Arc<Notify>,
    batch: Arc<Mutex<PendingBatch>>,
    status: Arc<CoordinatorStatus>,
    lease: Arc<V3CoordinatorLease>,
    maintenance_guard: Option<Arc<dyn V3MaintenanceGuard>>,
}

fn spawn_delayed_v3_publish<S, A>(
    context: PublicationContext<S, A>,
    generation: u64,
    delay: Duration,
) where
    S: BlobStore + Clone + 'static,
    A: V3CommitAnchor + 'static,
{
    tokio::spawn(async move {
        sleep(delay).await;
        publish_pending_v3_batch(context, Some(generation)).await;
    });
}

async fn publish_pending_v3_batch<S, A>(
    context: PublicationContext<S, A>,
    expected_generation: Option<u64>,
) where
    S: BlobStore + Clone + 'static,
    A: V3CommitAnchor + 'static,
{
    let PublicationContext {
        repository,
        anchor,
        stage_lock,
        publisher,
        capacity_changed,
        batch,
        status,
        lease: _lease,
        maintenance_guard,
    } = context;
    let _publisher = publisher.lock().await;
    let stage = stage_lock.lock().await;
    let mut pending = {
        let mut batch = batch.lock().await;
        if expected_generation.is_some_and(|expected| batch.generation != expected) {
            return;
        }
        if batch.publishing || batch.waiters.is_empty() || batch.failed.is_some() {
            return;
        }
        batch.publishing = true;
        batch.publishing_items = batch.waiters.len();
        PendingPublish {
            waiters: std::mem::take(&mut batch.waiters),
            rollback_log: std::mem::take(&mut batch.rollback_log),
        }
    };
    let publication = repository.freeze_pending_publication();
    drop(stage);
    capacity_changed.notify_waiters();
    let started = Instant::now();
    let published = match publication {
        Ok(publication) => {
            repository
                .publish_frozen_pending_index_delta(
                    anchor.as_ref(),
                    publication,
                    maintenance_guard.as_deref(),
                )
                .await
        }
        Err(error) => Err(error),
    };
    let _stage = stage_lock.lock().await;
    let mut batch = batch.lock().await;
    if !matches!(&published, Ok(Some(_))) {
        // A successor's conditions were evaluated against the failed prefix.
        // Reject and roll back both drafts before another writer is admitted.
        pending.waiters.append(&mut batch.waiters);
        pending.rollback_log.append(&mut batch.rollback_log);
    }
    let result = finish_v3_waiters(
        &repository,
        pending.waiters,
        pending.rollback_log,
        published,
        started,
    );
    batch.publishing = false;
    batch.publishing_items = 0;
    capacity_changed.notify_waiters();
    if batch.waiters.is_empty() {
        batch.protection = None;
    }
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

fn finish_v3_waiters<S>(
    repository: &V3Repository<S>,
    waiters: Vec<CommitWaiter>,
    rollback_log: Vec<V3StagedPutRollback>,
    published: Result<Option<V3StoredCommit>>,
    started: Instant,
) -> std::result::Result<(), PublishFailure>
where
    S: BlobStore + Clone + 'static,
{
    let waiter_count = waiters.len();
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
    record_v3_commit_batch_publish(waiter_count, result_label, started.elapsed());

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
        record_v3_commit_batch_publish_failure("publish");
        PublishFailure {
            reason,
            poison_reason: None,
        }
    });
    if accepted_recovery_required {
        let reason = "v2 publication requires recovery before further mutations".to_owned();
        record_v3_commit_batch_publish_failure("local_install");
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
        record_v3_commit_batch_publish_failure("rollback");
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

fn index_compaction_due(count: usize) -> bool {
    count >= V3_INDEX_COMPACTION_REQUEST_RUNS
        && (count >= V3_INDEX_COMPACTION_PAUSE_RUNS
            || count.is_multiple_of(V3_INDEX_COMPACTION_RETRY_INTERVAL_RUNS))
}

fn commit_failed(reason: &str) -> RepositoryError {
    RepositoryError::CommitFailed {
        reason: reason.to_owned(),
    }
}

fn v3_commit_error(error: super::error::V3FormatError) -> RepositoryError {
    RepositoryError::CommitFailed {
        reason: error.to_string(),
    }
}

fn record_v3_commit_enqueue(result: &'static str, pending_items: usize) {
    metrics::counter!("rs3_repository_v2_commit_enqueues_total", "result" => result).increment(1);
    metrics::counter!(
        "rs3_repository_v2_commit_enqueue_pending_items_total",
        "result" => result,
    )
    .increment(usize_to_u64(pending_items));
}

fn record_v3_commit_batch_publish(waiter_count: usize, result: &'static str, elapsed: Duration) {
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

fn record_v3_commit_batch_publish_failure(stage: &'static str) {
    metrics::counter!(
        "rs3_repository_v2_commit_batch_publish_failures_total",
        "stage" => stage,
    )
    .increment(1);
}

fn record_v3_commit_coordinator_poisoned(poisoned: bool) {
    metrics::gauge!("rs3_repository_v2_commit_coordinator_poisoned").set(if poisoned {
        1.0
    } else {
        0.0
    });
}

fn record_v3_commit_put_phase_duration(phase: &'static str, elapsed: Duration) {
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
