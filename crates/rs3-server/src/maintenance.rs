//! In-gateway maintenance supervisor.
//!
//! Runs v2 full maintenance (retention renewal plus orphan GC) automatically
//! inside the read-write gateway with autovacuum-style behavior: threshold and
//! deadline triggers, jitter, cooldown, exponential backoff, and single-flight
//! execution. The supervisor depends only on the repository runtime surface;
//! it never touches Kubernetes types.

use crate::config::{MaintenanceConfig, MaintenanceMode};
use async_trait::async_trait;
use rs3_repository::RepositoryError;
use rs3_repository::v2::{
    V2FullGcApplyOptions, V2FullGcDryRunOptions, V2FullGcDryRunReport, V2FullGcPlanPreview,
    V2MaintenanceCancellation, V2MaintenanceReport, V2OrphanGcOptions, V2QuickMaintenanceOptions,
};
use rs3_repository::v2::{V2FullGcApplyReport, V2FullMaintenanceReport};
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::{Notify, oneshot, watch};

/// Refresh interval for trigger inputs when no trigger is due sooner.
const MAINTENANCE_POLL_INTERVAL: Duration = Duration::from_secs(15 * 60);
/// Upper bound for the renewal-deadline scheduling jitter.
const MAX_RENEWAL_JITTER: Duration = Duration::from_secs(60 * 60);
/// Minimum provider-observed orphan age before automatic deletion.
///
/// Conservative floor against eventually consistent listings; break-glass and
/// test paths can supply their own [`V2OrphanGcOptions`].
const DEFAULT_AUTO_ORPHAN_GC_MIN_AGE: Duration = Duration::from_secs(24 * 60 * 60);

const OUTCOME_OK: &str = "ok";
const OUTCOME_FAILED: &str = "failed";
const OUTCOME_CANCELLED: &str = "cancelled";
const OUTCOME_REJECTED: &str = "rejected";
const OUTCOME_STALE_PLAN: &str = "stale-plan";

const PARKED_REASON_GUARD_MISSING: &str = "maintenance-guard-missing";

/// Bounded number of maintenance operations kept in the in-memory history.
const MAINTENANCE_OPERATION_HISTORY_LIMIT: usize = 32;

/// Path-safe failure reason emitted when an apply plan digest no longer
/// matches the fresh in-window plan. Repository state moved between the
/// operator dry run and the apply; the operator must re-run the dry run.
pub const MAINTENANCE_PLAN_STALE_REASON: &str =
    "maintenance plan digest is stale: repository state moved since the dry run";

/// Clock used by the supervisor so tests can run against simulated time.
#[async_trait]
pub trait MaintenanceClock: Send + Sync {
    /// Returns the current time in milliseconds since the Unix epoch.
    fn now_ms(&self) -> i64;
    /// Sleeps for the given duration on this clock.
    async fn sleep(&self, duration: Duration);
}

/// Wall-clock implementation of [`MaintenanceClock`].
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemMaintenanceClock;

#[async_trait]
impl MaintenanceClock for SystemMaintenanceClock {
    fn now_ms(&self) -> i64 {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis();
        i64::try_from(millis).unwrap_or(i64::MAX)
    }

    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

/// Coarse phase of one supervised full-maintenance run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaintenanceRunPhase {
    /// Draining pending commits and verifying the maintenance guard.
    Quiescing,
    /// Running the budgeted dry run plus the destructive apply.
    Applying,
}

/// Repository-facing surface the supervisor schedules maintenance through.
///
/// Implementations depend only on the v2 repository handle and coordinator;
/// no Kubernetes types appear on this boundary.
#[async_trait]
pub trait MaintenanceRuntime: Send + Sync {
    /// Returns whether a maintenance guard is configured for this gateway.
    fn maintenance_guard_configured(&self) -> bool;

    /// Runs the read-only quick maintenance report used for trigger inputs.
    async fn quick_maintenance_report(&self) -> Result<V2MaintenanceReport, RepositoryError>;

    /// Runs the quick report under explicit supervisor limits.
    async fn quick_maintenance_report_with_options(
        &self,
        _options: V2QuickMaintenanceOptions,
    ) -> Result<V2MaintenanceReport, RepositoryError> {
        self.quick_maintenance_report().await
    }

    /// Runs the budgeted read-only full-GC dry run without a maintenance window.
    async fn full_gc_dry_run(
        &self,
        options: V2FullGcDryRunOptions,
    ) -> Result<V2FullGcDryRunReport, RepositoryError>;

    /// Previews an exact repository-owned apply plan and digest.
    async fn preview_full_gc_plan(
        &self,
        _options: V2FullGcApplyOptions,
    ) -> Result<V2FullGcPlanPreview, RepositoryError> {
        Err(RepositoryError::CommitFailed {
            reason: "exact maintenance plan previews are unavailable".to_owned(),
        })
    }

    /// Runs quiesced full maintenance, reporting coarse phases as it goes.
    ///
    /// When `expected_plan_digest` is supplied, the implementation must
    /// re-plan inside the exclusion window before mutating and fail closed
    /// with [`MAINTENANCE_PLAN_STALE_REASON`] when the fresh repository-owned
    /// exact-plan digest does not match the supplied value.
    async fn run_full_maintenance(
        &self,
        options: V2FullGcApplyOptions,
        expected_plan_digest: Option<&str>,
        cancellation: &V2MaintenanceCancellation,
        on_phase: &(dyn Fn(MaintenanceRunPhase) + Send + Sync),
    ) -> Result<V2FullMaintenanceReport, RepositoryError>;
}

/// Supervisor state machine position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaintenanceSupervisorState {
    /// Waiting for the next trigger.
    Idle,
    /// Refreshing trigger inputs through the quick maintenance report.
    Planning,
    /// Draining pending commits and verifying the maintenance guard.
    Quiescing,
    /// Running the budgeted dry run plus the destructive apply.
    Applying,
    /// Refreshing post-run facts before entering cooldown.
    Verifying,
    /// Between runs inside the configured minimum cooldown.
    Cooldown,
    /// Last run failed; automatic triggers are held back by backoff.
    Failed,
    /// Last run was cancelled at a mutation boundary.
    Cancelled,
    /// Supervisor refuses to run because a precondition is missing.
    Parked,
}

impl MaintenanceSupervisorState {
    /// Returns the stable path-safe spelling used in reports and metrics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Planning => "planning",
            Self::Quiescing => "quiescing",
            Self::Applying => "applying",
            Self::Verifying => "verifying",
            Self::Cooldown => "cooldown",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Parked => "parked",
        }
    }
}

/// Why a maintenance run was or will be started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaintenanceTriggerReason {
    /// The nearest retain-until deadline entered the renewal horizon.
    RenewalDeadline,
    /// Orphan bytes, count, or age crossed a pressure threshold.
    OrphanPressure,
    /// The maximum interval since the last run elapsed.
    MaxInterval,
    /// An operator or admin API requested a run.
    Manual,
}

impl MaintenanceTriggerReason {
    /// Returns the stable path-safe spelling used in reports and metrics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RenewalDeadline => "renewal-deadline",
            Self::OrphanPressure => "orphan-pressure",
            Self::MaxInterval => "max-interval",
            Self::Manual => "manual",
        }
    }
}

/// Path-redacted summary of the most recent supervised run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaintenanceRunSummary {
    /// Trigger that started the run.
    pub trigger: &'static str,
    /// Run outcome: `ok`, `failed`, `cancelled`, or `rejected`.
    pub outcome: &'static str,
    /// Run start time in milliseconds since the Unix epoch.
    pub started_at_ms: i64,
    /// Wall-clock run duration in milliseconds.
    pub duration_ms: u64,
    /// Live object versions whose retention was renewed and verified.
    pub renewed_object_count: usize,
    /// Live object bytes covered by verified retention renewal.
    pub renewed_bytes: u64,
    /// Orphan objects deleted by the run.
    pub deleted_object_count: usize,
    /// Dead bytes the accepted plan considered reclaimable.
    pub reclaimable_bytes: u64,
    /// Path-redacted failure reason, when the run did not complete cleanly.
    pub failure_reason: Option<String>,
}

/// Origin of a maintenance operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaintenanceOperationSource {
    /// The supervisor scheduler started the operation.
    Auto,
    /// An operator submitted the operation over the admin HTTP surface.
    ManualHttp,
    /// An operator submitted the operation through the CLI.
    ManualCli,
}

impl MaintenanceOperationSource {
    /// Returns the stable path-safe spelling used in reports and audit logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::ManualHttp => "manual-http",
            Self::ManualCli => "manual-cli",
        }
    }
}

/// Path-redacted record of one maintenance operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MaintenanceOperationRecord {
    /// Server-generated random operation identifier.
    pub id: String,
    /// Operation kind: `run`, `dry-run`, `apply`, `cancel`, `pause`, `resume`.
    pub kind: &'static str,
    /// Trigger source: `auto`, `manual-http`, or `manual-cli`.
    pub source: &'static str,
    /// Submission time in milliseconds since the Unix epoch.
    pub submitted_at_ms: i64,
    /// Execution start time in milliseconds since the Unix epoch.
    pub started_at_ms: Option<i64>,
    /// Completion time in milliseconds since the Unix epoch.
    pub finished_at_ms: Option<i64>,
    /// Outcome: `ok`, `failed`, `cancelled`, `rejected`, or `stale-plan`.
    pub outcome: Option<&'static str>,
    /// Live object versions whose retention was renewed by the operation.
    pub renewed_object_count: usize,
    /// Live object bytes covered by verified retention renewal.
    pub renewed_bytes: u64,
    /// Orphan objects deleted by the operation.
    pub deleted_object_count: usize,
    /// Dead bytes the accepted plan considered reclaimable.
    pub reclaimable_bytes: u64,
    /// Deterministic plan digest bound to the operation, when present.
    pub plan_digest: Option<String>,
    /// Path-redacted failure reason, when the operation did not succeed.
    pub failure_reason: Option<String>,
}

impl MaintenanceOperationRecord {
    fn submitted(
        id: String,
        kind: &'static str,
        source: MaintenanceOperationSource,
        submitted_at_ms: i64,
    ) -> Self {
        Self {
            id,
            kind,
            source: source.as_str(),
            submitted_at_ms,
            started_at_ms: None,
            finished_at_ms: None,
            outcome: None,
            renewed_object_count: 0,
            renewed_bytes: 0,
            deleted_object_count: 0,
            reclaimable_bytes: 0,
            plan_digest: None,
            failure_reason: None,
        }
    }
}

/// Cheap path-redacted snapshot of supervisor posture and history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaintenanceStatusSnapshot {
    /// Configured supervisor mode.
    pub mode: &'static str,
    /// Current state machine position.
    pub state: &'static str,
    /// Stable reason code when the supervisor is parked.
    pub parked_reason: Option<&'static str>,
    /// Whether the automatic scheduler is paused by an operator.
    pub paused: bool,
    /// Next scheduled trigger time in milliseconds since the Unix epoch.
    pub next_trigger_at_ms: Option<i64>,
    /// Reason associated with the next scheduled trigger.
    pub next_trigger_reason: Option<&'static str>,
    /// Consecutive failed runs since the last success.
    pub consecutive_failures: u32,
    /// Timestamp of the last successful run in milliseconds since the epoch.
    pub last_success_at_ms: Option<i64>,
    /// Nearest provider retain-until deadline observed by planning.
    pub nearest_retain_until_ms: Option<i64>,
    /// Summary of the most recent run attempt.
    pub last_run: Option<MaintenanceRunSummary>,
    /// Bounded history of recent maintenance operations, newest first.
    pub operations: Vec<MaintenanceOperationRecord>,
}

impl MaintenanceStatusSnapshot {
    fn initial(mode: MaintenanceMode) -> Self {
        Self {
            mode: mode.as_str(),
            state: MaintenanceSupervisorState::Idle.as_str(),
            parked_reason: None,
            paused: false,
            next_trigger_at_ms: None,
            next_trigger_reason: None,
            consecutive_failures: 0,
            last_success_at_ms: None,
            nearest_retain_until_ms: None,
            last_run: None,
            operations: Vec::new(),
        }
    }
}

/// Cloneable, cheap handle to the live supervisor status snapshot.
#[derive(Clone)]
pub struct MaintenanceStatusHandle {
    inner: Arc<RwLock<MaintenanceStatusSnapshot>>,
}

impl MaintenanceStatusHandle {
    fn new(snapshot: MaintenanceStatusSnapshot) -> Self {
        Self {
            inner: Arc::new(RwLock::new(snapshot)),
        }
    }

    /// Returns the current status snapshot.
    pub fn snapshot(&self) -> MaintenanceStatusSnapshot {
        match self.inner.read() {
            Ok(snapshot) => snapshot.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn update(&self, mutate: impl FnOnce(&mut MaintenanceStatusSnapshot)) {
        let mut snapshot = match self.inner.write() {
            Ok(snapshot) => snapshot,
            Err(poisoned) => poisoned.into_inner(),
        };
        mutate(&mut snapshot);
    }

    fn set_state(&self, state: MaintenanceSupervisorState) {
        self.update(|snapshot| snapshot.state = state.as_str());
    }

    /// Records a new operation at the front of the bounded history.
    fn record_operation(&self, record: MaintenanceOperationRecord) {
        self.update(|snapshot| {
            snapshot.operations.insert(0, record);
            snapshot
                .operations
                .truncate(MAINTENANCE_OPERATION_HISTORY_LIMIT);
        });
    }

    /// Updates a recorded operation in place, if it is still in the history.
    fn finish_operation(&self, id: &str, mutate: impl FnOnce(&mut MaintenanceOperationRecord)) {
        self.update(|snapshot| {
            if let Some(record) = snapshot
                .operations
                .iter_mut()
                .find(|record| record.id == id)
            {
                mutate(record);
            }
        });
    }
}

/// Generates a random hexadecimal operation identifier.
fn generate_operation_id() -> String {
    static FALLBACK_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let mut bytes = [0_u8; 16];
    if getrandom::fill(&mut bytes).is_ok() {
        return hex::encode(bytes);
    }
    // getrandom failure is not a reason to refuse an operation: fall back to
    // a time-plus-sequence identifier that stays unique within this process.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let sequence = FALLBACK_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!(
        "{:016x}{:016x}",
        u64::try_from(now.as_nanos() & u128::from(u64::MAX)).unwrap_or(0),
        sequence
    )
}

/// Programmatic trigger handle for the supervisor.
///
/// Phase 3 surfaces this over the admin mutation API; triggers are coalesced
/// into at most one pending run and never start concurrent maintenance.
#[derive(Clone)]
pub struct MaintenanceTriggerHandle {
    requested: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    pending_run: Arc<StdMutex<Option<PendingSupervisedRun>>>,
    notify: Arc<Notify>,
}

/// Operator-submitted run waiting for the supervisor loop, with its reply
/// channel. At most one pending run exists at a time.
struct PendingSupervisedRun {
    operation_id: String,
    source: MaintenanceOperationSource,
    submitted_at_ms: i64,
    plan_digest: String,
    responder: oneshot::Sender<MaintenanceOperationRecord>,
}

impl MaintenanceTriggerHandle {
    fn new() -> Self {
        Self {
            requested: Arc::new(AtomicBool::new(false)),
            paused: Arc::new(AtomicBool::new(false)),
            pending_run: Arc::new(StdMutex::new(None)),
            notify: Arc::new(Notify::new()),
        }
    }

    /// Requests a full-maintenance run at the next scheduling opportunity.
    pub fn trigger(&self) {
        self.requested.store(true, Ordering::Release);
        self.notify.notify_one();
    }

    fn take_requested(&self) -> bool {
        self.requested.swap(false, Ordering::AcqRel)
    }

    fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }

    fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Acquire)
    }

    fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::Release);
        self.notify.notify_one();
    }

    fn pending_lock(&self) -> std::sync::MutexGuard<'_, Option<PendingSupervisedRun>> {
        match self.pending_run.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Queues an operator apply run; fails when a run is already pending.
    fn submit_pending(&self, pending: PendingSupervisedRun) -> Result<(), PendingSupervisedRun> {
        {
            let mut slot = self.pending_lock();
            if slot.is_some() {
                return Err(pending);
            }
            *slot = Some(pending);
        }
        self.notify.notify_one();
        Ok(())
    }

    fn take_pending(&self) -> Option<PendingSupervisedRun> {
        self.pending_lock().take()
    }

    fn has_pending(&self) -> bool {
        self.pending_lock().is_some()
    }
}

/// Maintenance control operation errors.
#[derive(Debug, Error)]
pub enum MaintenanceControlError {
    /// The supplied plan digest is not a 64-character lowercase hex string.
    #[error("maintenance plan digest must be 64 lowercase hex characters")]
    InvalidPlanDigest,
    /// A maintenance run or pending apply already holds the single-flight slot.
    #[error("another maintenance run is already in flight")]
    RunInFlight,
    /// The supervisor is parked and refuses destructive operations.
    #[error("maintenance supervisor is parked: {reason}")]
    Parked {
        /// Stable parked reason code.
        reason: &'static str,
    },
    /// No maintenance run is currently in flight.
    #[error("no maintenance run is in flight")]
    NoRunInFlight,
    /// The supervisor task is no longer serving operations.
    #[error("maintenance supervisor is unavailable")]
    SupervisorUnavailable,
    /// The budgeted read-only dry run failed.
    #[error("maintenance dry run failed: {reason}")]
    DryRunFailed {
        /// Path-redacted failure reason.
        reason: String,
    },
}

/// Outcome of a supervised read-only dry run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaintenanceDryRunOutcome {
    /// Server-generated operation identifier.
    pub operation_id: String,
    /// Deterministic digest identifying the produced plan.
    pub plan_digest: String,
    /// The budgeted read-only dry-run report.
    pub report: V2FullGcDryRunReport,
}

/// Operator control surface for the running maintenance supervisor.
///
/// Dry runs execute inline on the caller's task (they are budgeted and
/// read-only and never take the maintenance window). Apply runs are queued to
/// the supervisor loop so they stay single-flight with automatic runs.
#[derive(Clone)]
pub struct MaintenanceControlHandle {
    status: MaintenanceStatusHandle,
    trigger: MaintenanceTriggerHandle,
    runtime: Arc<dyn MaintenanceRuntime>,
    clock: Arc<dyn MaintenanceClock>,
    active_cancellation: Arc<RwLock<Option<Arc<V2MaintenanceCancellation>>>>,
    dry_run_lock: Arc<tokio::sync::Mutex<()>>,
    maintenance: MaintenanceConfig,
    orphan_gc: V2OrphanGcOptions,
    retained_provider_conformance: Arc<dyn Fn() -> bool + Send + Sync>,
}

impl MaintenanceControlHandle {
    /// Returns the current supervisor status snapshot.
    pub fn status_snapshot(&self) -> MaintenanceStatusSnapshot {
        self.status.snapshot()
    }

    /// Pauses the automatic scheduler.
    ///
    /// Manual operations remain allowed while paused; only automatic triggers
    /// are held back. Returns the recorded operation.
    pub fn pause(&self, source: MaintenanceOperationSource) -> MaintenanceOperationRecord {
        self.set_paused(true, "pause", source)
    }

    /// Resumes the automatic scheduler after a pause.
    pub fn resume(&self, source: MaintenanceOperationSource) -> MaintenanceOperationRecord {
        self.set_paused(false, "resume", source)
    }

    fn set_paused(
        &self,
        paused: bool,
        kind: &'static str,
        source: MaintenanceOperationSource,
    ) -> MaintenanceOperationRecord {
        let now_ms = self.clock.now_ms();
        self.trigger.set_paused(paused);
        metrics::gauge!("rs3_maintenance_paused").set(if paused { 1.0 } else { 0.0 });
        let mut record =
            MaintenanceOperationRecord::submitted(generate_operation_id(), kind, source, now_ms);
        record.started_at_ms = Some(now_ms);
        record.finished_at_ms = Some(now_ms);
        record.outcome = Some(OUTCOME_OK);
        self.status.update(|snapshot| snapshot.paused = paused);
        self.status.record_operation(record.clone());
        record
    }

    /// Requests cancellation of the in-flight maintenance run.
    ///
    /// Cancellation is honored at the next mutation boundary. This is distinct
    /// from shutdown: the supervisor keeps running and scheduling afterwards.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceControlError::NoRunInFlight`] when no run is
    /// currently executing.
    pub fn cancel(
        &self,
        source: MaintenanceOperationSource,
    ) -> Result<MaintenanceOperationRecord, MaintenanceControlError> {
        let cancellation = match self.active_cancellation.read() {
            Ok(slot) => slot.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        let Some(cancellation) = cancellation else {
            return Err(MaintenanceControlError::NoRunInFlight);
        };
        cancellation.cancel();
        let now_ms = self.clock.now_ms();
        let mut record = MaintenanceOperationRecord::submitted(
            generate_operation_id(),
            "cancel",
            source,
            now_ms,
        );
        record.started_at_ms = Some(now_ms);
        record.finished_at_ms = Some(now_ms);
        record.outcome = Some(OUTCOME_OK);
        self.status.record_operation(record.clone());
        Ok(record)
    }

    /// Runs the budgeted read-only dry run and returns its plan digest.
    ///
    /// The dry run never takes the maintenance window; it is safe to run while
    /// the scheduler is paused or a run is in flight. Dry runs are serialized
    /// among themselves.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceControlError::DryRunFailed`] when planning fails.
    pub async fn dry_run(
        &self,
        source: MaintenanceOperationSource,
    ) -> Result<MaintenanceDryRunOutcome, MaintenanceControlError> {
        let _serialize = self.dry_run_lock.lock().await;
        let operation_id = generate_operation_id();
        let submitted_at_ms = self.clock.now_ms();
        let mut record = MaintenanceOperationRecord::submitted(
            operation_id.clone(),
            "dry-run",
            source,
            submitted_at_ms,
        );
        record.started_at_ms = Some(submitted_at_ms);
        self.status.record_operation(record);

        let options = V2FullGcApplyOptions {
            dry_run: V2FullGcDryRunOptions {
                budgets: self.maintenance.budgets(),
                retention_renewal_horizon: self.maintenance.renewal_horizon,
                protected_roots: Vec::new(),
            },
            orphan_gc: self.orphan_gc,
            retained_provider_conformance_passed: (self.retained_provider_conformance)(),
        };
        let result = self.runtime.preview_full_gc_plan(options).await;
        let finished_at_ms = self.clock.now_ms();
        match result {
            Ok(preview) => {
                let V2FullGcPlanPreview {
                    report,
                    plan_digest,
                } = preview;
                let digest_for_record = plan_digest.clone();
                self.status.finish_operation(&operation_id, |record| {
                    record.finished_at_ms = Some(finished_at_ms);
                    record.outcome = Some(OUTCOME_OK);
                    record.reclaimable_bytes = report.dead_bytes_reclaimable;
                    record.plan_digest = Some(digest_for_record);
                });
                Ok(MaintenanceDryRunOutcome {
                    operation_id,
                    plan_digest,
                    report,
                })
            }
            Err(error) => {
                let reason = error.to_string();
                let record_reason = reason.clone();
                self.status.finish_operation(&operation_id, |record| {
                    record.finished_at_ms = Some(finished_at_ms);
                    record.outcome = Some(OUTCOME_FAILED);
                    record.failure_reason = Some(record_reason);
                });
                Err(MaintenanceControlError::DryRunFailed { reason })
            }
        }
    }

    /// Queues a destructive apply bound to a prior dry-run plan digest and
    /// waits for its outcome.
    ///
    /// The supervisor re-plans inside the maintenance window and fails closed
    /// with outcome `stale-plan` when the fresh digest no longer matches.
    /// Apply runs share the supervisor's single-flight execution with
    /// automatic runs.
    ///
    /// # Errors
    ///
    /// Fails when the digest is malformed, another run or pending apply is in
    /// flight, the supervisor is parked, or the supervisor stopped.
    pub async fn apply(
        &self,
        plan_digest: &str,
        source: MaintenanceOperationSource,
    ) -> Result<MaintenanceOperationRecord, MaintenanceControlError> {
        if plan_digest.len() != 64
            || !plan_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(MaintenanceControlError::InvalidPlanDigest);
        }
        let snapshot = self.status.snapshot();
        if snapshot.state == MaintenanceSupervisorState::Parked.as_str() {
            return Err(MaintenanceControlError::Parked {
                reason: snapshot
                    .parked_reason
                    .unwrap_or(PARKED_REASON_GUARD_MISSING),
            });
        }
        if self.run_in_flight() || self.trigger.has_pending() {
            return Err(MaintenanceControlError::RunInFlight);
        }

        let operation_id = generate_operation_id();
        let submitted_at_ms = self.clock.now_ms();
        let (responder, outcome) = oneshot::channel();
        let pending = PendingSupervisedRun {
            operation_id,
            source,
            submitted_at_ms,
            plan_digest: plan_digest.to_owned(),
            responder,
        };
        if self.trigger.submit_pending(pending).is_err() {
            return Err(MaintenanceControlError::RunInFlight);
        }
        outcome
            .await
            .map_err(|_closed| MaintenanceControlError::SupervisorUnavailable)
    }

    fn run_in_flight(&self) -> bool {
        match self.active_cancellation.read() {
            Ok(slot) => slot.is_some(),
            Err(poisoned) => poisoned.into_inner().is_some(),
        }
    }
}

/// Static inputs for one supervisor instance.
#[derive(Clone)]
pub struct MaintenanceSupervisorConfig {
    /// Validated maintenance settings from runtime configuration.
    pub maintenance: MaintenanceConfig,
    /// Whether repository retention is configured on this gateway.
    pub retention_configured: bool,
    /// Orphan deletion policy applied by supervised runs.
    pub orphan_gc: V2OrphanGcOptions,
    /// Returns current retained-provider conformance evidence state.
    ///
    /// Re-evaluated before every destructive run so refreshed evidence files
    /// are honored without a restart. Ignored for non-retained profiles.
    pub retained_provider_conformance: Arc<dyn Fn() -> bool + Send + Sync>,
}

impl MaintenanceSupervisorConfig {
    /// Builds supervisor inputs from validated runtime configuration.
    pub fn from_runtime(
        maintenance: MaintenanceConfig,
        retention_configured: bool,
        retained_provider_conformance: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Self {
        Self {
            maintenance,
            retention_configured,
            orphan_gc: default_auto_orphan_gc_options(),
            retained_provider_conformance,
        }
    }
}

/// Default conservative orphan deletion policy for maintenance runs.
///
/// Shared by the in-gateway supervisor and the offline break-glass command so
/// both apply the same eventually-consistent-listing age floor.
pub fn default_maintenance_orphan_gc_options() -> V2OrphanGcOptions {
    default_auto_orphan_gc_options()
}

fn default_auto_orphan_gc_options() -> V2OrphanGcOptions {
    // The production constructor fails closed below its one-hour floor; the
    // default supervisor floor is far above it, so this cannot fail. Fall
    // back to the floor itself if the invariant ever changes.
    V2OrphanGcOptions::new(DEFAULT_AUTO_ORPHAN_GC_MIN_AGE)
        .unwrap_or_else(|_| V2OrphanGcOptions::new_for_test_rehearsal(Duration::from_secs(60 * 60)))
}

/// Running supervisor handle with status, trigger, and shutdown control.
pub struct MaintenanceSupervisorHandle {
    status: MaintenanceStatusHandle,
    trigger: MaintenanceTriggerHandle,
    shutdown: watch::Sender<bool>,
    active_cancellation: Arc<RwLock<Option<Arc<V2MaintenanceCancellation>>>>,
    control: MaintenanceControlHandle,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl MaintenanceSupervisorHandle {
    /// Returns the cloneable status snapshot handle.
    pub fn status(&self) -> MaintenanceStatusHandle {
        self.status.clone()
    }

    /// Returns the cloneable programmatic trigger handle.
    pub fn trigger_handle(&self) -> MaintenanceTriggerHandle {
        self.trigger.clone()
    }

    /// Returns the cloneable operator control handle.
    pub fn control(&self) -> MaintenanceControlHandle {
        self.control.clone()
    }

    /// Requests a graceful stop and waits for the supervisor task to finish.
    ///
    /// An in-flight run is cancelled at its next mutation boundary; the task
    /// is aborted only if it does not stop within the grace period.
    pub async fn shutdown(mut self) {
        let _ = self.shutdown.send(true);
        {
            let cancellation = match self.active_cancellation.read() {
                Ok(slot) => slot.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            };
            if let Some(cancellation) = cancellation {
                cancellation.cancel();
            }
        }
        let Some(mut task) = self.task.take() else {
            return;
        };
        if tokio::time::timeout(Duration::from_secs(30), &mut task)
            .await
            .is_err()
        {
            task.abort();
            tracing::warn!(
                target: "rs3_server",
                operation = "maintenance_supervisor_shutdown",
                result = "timeout",
                "maintenance supervisor did not stop within the grace period",
            );
        }
    }
}

impl Drop for MaintenanceSupervisorHandle {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        let cancellation = match self.active_cancellation.read() {
            Ok(slot) => slot.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        if let Some(cancellation) = cancellation {
            cancellation.cancel();
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Background maintenance supervisor factory.
pub struct MaintenanceSupervisor;

impl MaintenanceSupervisor {
    /// Spawns the supervisor task and returns its control handle.
    pub fn start(
        config: MaintenanceSupervisorConfig,
        runtime: Arc<dyn MaintenanceRuntime>,
        clock: Arc<dyn MaintenanceClock>,
    ) -> MaintenanceSupervisorHandle {
        let status = MaintenanceStatusHandle::new(MaintenanceStatusSnapshot::initial(
            config.maintenance.mode,
        ));
        let trigger = MaintenanceTriggerHandle::new();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let active_cancellation: Arc<RwLock<Option<Arc<V2MaintenanceCancellation>>>> =
            Arc::new(RwLock::new(None));
        let jitter =
            sample_renewal_jitter(renewal_jitter_ceiling(config.maintenance.renewal_horizon));
        let control = MaintenanceControlHandle {
            status: status.clone(),
            trigger: trigger.clone(),
            runtime: Arc::clone(&runtime),
            clock: Arc::clone(&clock),
            active_cancellation: Arc::clone(&active_cancellation),
            dry_run_lock: Arc::new(tokio::sync::Mutex::new(())),
            maintenance: config.maintenance,
            orphan_gc: config.orphan_gc,
            retained_provider_conformance: Arc::clone(&config.retained_provider_conformance),
        };

        let task = tokio::spawn(
            SupervisorTask {
                config,
                runtime,
                clock,
                status: status.clone(),
                trigger: trigger.clone(),
                shutdown: shutdown_rx,
                active_cancellation: Arc::clone(&active_cancellation),
                renewal_jitter: jitter,
                consecutive_failures: 0,
                last_finished_at_ms: None,
                backoff_until_ms: None,
                started_at_ms: None,
            }
            .run(),
        );

        MaintenanceSupervisorHandle {
            status,
            trigger,
            shutdown: shutdown_tx,
            active_cancellation,
            control,
            task: Some(task),
        }
    }
}

/// Returns the jitter ceiling for renewal-deadline scheduling.
fn renewal_jitter_ceiling(horizon: Duration) -> Duration {
    (horizon / 16).min(MAX_RENEWAL_JITTER)
}

/// Samples a uniform jitter in `[0, ceiling]` from process randomness.
fn sample_renewal_jitter(ceiling: Duration) -> Duration {
    let ceiling_ms = u64::try_from(ceiling.as_millis()).unwrap_or(u64::MAX);
    if ceiling_ms == 0 {
        return Duration::ZERO;
    }
    let mut bytes = [0_u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        return Duration::ZERO;
    }
    Duration::from_millis(u64::from_le_bytes(bytes) % ceiling_ms.saturating_add(1))
}

struct PlannedTrigger {
    due_at_ms: i64,
    latest_safe_at_ms: Option<i64>,
    reason: MaintenanceTriggerReason,
}

struct SupervisorTask {
    config: MaintenanceSupervisorConfig,
    runtime: Arc<dyn MaintenanceRuntime>,
    clock: Arc<dyn MaintenanceClock>,
    status: MaintenanceStatusHandle,
    trigger: MaintenanceTriggerHandle,
    shutdown: watch::Receiver<bool>,
    active_cancellation: Arc<RwLock<Option<Arc<V2MaintenanceCancellation>>>>,
    renewal_jitter: Duration,
    consecutive_failures: u32,
    last_finished_at_ms: Option<i64>,
    backoff_until_ms: Option<i64>,
    started_at_ms: Option<i64>,
}

impl SupervisorTask {
    async fn run(mut self) {
        self.started_at_ms = Some(self.clock.now_ms());
        initialize_supervisor_metrics();
        if !self.runtime.maintenance_guard_configured() {
            self.park_without_guard().await;
            return;
        }

        loop {
            if self.shutdown_requested() {
                return;
            }
            let now_ms = self.clock.now_ms();
            if self.trigger.is_requested() || self.trigger.has_pending() {
                let planned = PlannedTrigger {
                    due_at_ms: now_ms,
                    latest_safe_at_ms: None,
                    reason: MaintenanceTriggerReason::Manual,
                };
                self.publish_schedule(Some(&planned), now_ms);
                self.execute_run(MaintenanceTriggerReason::Manual).await;
                continue;
            }
            if self.config.maintenance.mode != MaintenanceMode::Auto || self.trigger.is_paused() {
                self.publish_schedule(None, now_ms);
                if self.wait_for_wake(MAINTENANCE_POLL_INTERVAL).await {
                    return;
                }
                continue;
            }

            self.status.set_state(MaintenanceSupervisorState::Planning);
            let report = match self
                .runtime
                .quick_maintenance_report_with_options(self.quick_report_options())
                .await
            {
                Ok(report) => {
                    record_report_gauges(&report, self.clock.now_ms());
                    let nearest_retain_until_ms = report.nearest_retain_until_ms;
                    self.status.update(|snapshot| {
                        snapshot.nearest_retain_until_ms = nearest_retain_until_ms;
                    });
                    report
                }
                Err(error) => {
                    tracing::warn!(
                        target: "rs3_server",
                        operation = "maintenance_supervisor_plan",
                        result = "error",
                        error = %error,
                        "maintenance planning report failed",
                    );
                    let now_ms = self.clock.now_ms();
                    self.record_planning_failure(&error, now_ms);
                    let planned = self.plan_next_trigger(None, now_ms);
                    self.publish_schedule(planned.as_ref(), now_ms);
                    if let Some(planned) = planned
                        && planned.due_at_ms <= now_ms
                    {
                        self.execute_run(planned.reason).await;
                        continue;
                    }
                    let retry_at_ms = self.backoff_until_ms.unwrap_or_else(|| {
                        now_ms.saturating_add(duration_ms(MAINTENANCE_POLL_INTERVAL))
                    });
                    let wait = ms_until(now_ms, retry_at_ms);
                    if self.wait_for_wake(wait).await {
                        return;
                    }
                    continue;
                }
            };

            let now_ms = self.clock.now_ms();
            let planned = self.plan_next_trigger(Some(&report), now_ms);
            self.publish_schedule(planned.as_ref(), now_ms);

            match planned {
                Some(planned) if planned.due_at_ms <= now_ms => {
                    self.execute_run(planned.reason).await;
                }
                planned => {
                    let due_in = planned
                        .map(|planned| ms_until(now_ms, planned.due_at_ms))
                        .unwrap_or(MAINTENANCE_POLL_INTERVAL);
                    let wait = due_in.min(MAINTENANCE_POLL_INTERVAL);
                    if self.wait_for_wake(wait).await {
                        return;
                    }
                }
            }
        }
    }

    async fn park_without_guard(mut self) {
        tracing::warn!(
            target: "rs3_server",
            operation = "maintenance_supervisor_park",
            reason = PARKED_REASON_GUARD_MISSING,
            "maintenance supervisor parked: no maintenance guard is configured",
        );
        self.status.update(|snapshot| {
            snapshot.state = MaintenanceSupervisorState::Parked.as_str();
            snapshot.parked_reason = Some(PARKED_REASON_GUARD_MISSING);
        });
        metrics::gauge!("rs3_maintenance_parked").set(1.0);

        loop {
            if self.shutdown_requested() {
                return;
            }
            if let Some(pending) = self.trigger.take_pending() {
                let now_ms = self.clock.now_ms();
                let mut record = MaintenanceOperationRecord::submitted(
                    pending.operation_id,
                    "apply",
                    pending.source,
                    pending.submitted_at_ms,
                );
                record.started_at_ms = Some(now_ms);
                record.finished_at_ms = Some(now_ms);
                record.outcome = Some(OUTCOME_REJECTED);
                record.plan_digest = Some(pending.plan_digest);
                record.failure_reason =
                    Some("maintenance guard is not configured; supervisor is parked".to_owned());
                record_run_outcome(OUTCOME_REJECTED);
                self.status.record_operation(record.clone());
                let _ = pending.responder.send(record);
            }
            if self.trigger.take_requested() {
                let now_ms = self.clock.now_ms();
                record_run_outcome(OUTCOME_REJECTED);
                self.status.update(|snapshot| {
                    snapshot.last_run = Some(MaintenanceRunSummary {
                        trigger: MaintenanceTriggerReason::Manual.as_str(),
                        outcome: OUTCOME_REJECTED,
                        started_at_ms: now_ms,
                        duration_ms: 0,
                        renewed_object_count: 0,
                        renewed_bytes: 0,
                        deleted_object_count: 0,
                        reclaimable_bytes: 0,
                        failure_reason: Some(
                            "maintenance guard is not configured; supervisor is parked".to_owned(),
                        ),
                    });
                });
            }
            if self.wait_for_wake(MAINTENANCE_POLL_INTERVAL).await {
                return;
            }
        }
    }

    fn shutdown_requested(&self) -> bool {
        *self.shutdown.borrow() || self.shutdown.has_changed().is_err()
    }

    /// Sleeps until the duration elapses, a trigger arrives, or shutdown.
    ///
    /// Returns true when shutdown was requested.
    async fn wait_for_wake(&mut self, duration: Duration) -> bool {
        if self.trigger.is_requested() || self.trigger.has_pending() {
            return self.shutdown_requested();
        }
        let sleep = self.clock.sleep(duration);
        tokio::pin!(sleep);
        tokio::select! {
            _ = &mut sleep => {}
            _ = self.trigger.notify.notified() => {}
            changed = self.shutdown.changed() => {
                if changed.is_err() {
                    return true;
                }
            }
        }
        self.shutdown_requested()
    }

    fn quick_report_options(&self) -> V2QuickMaintenanceOptions {
        V2QuickMaintenanceOptions {
            budgets: self.config.maintenance.budgets(),
            retention_renewal_horizon: self.config.maintenance.renewal_horizon,
            orphan_gc: self.config.orphan_gc,
        }
    }

    fn plan_next_trigger(
        &self,
        report: Option<&V2MaintenanceReport>,
        now_ms: i64,
    ) -> Option<PlannedTrigger> {
        let mut candidates: Vec<PlannedTrigger> = Vec::new();

        // Operator-submitted runs come first so an equal due time resolves in
        // their favor; they bypass cooldown, backoff, and the pause switch.
        if self.trigger.is_requested() || self.trigger.has_pending() {
            candidates.push(PlannedTrigger {
                due_at_ms: now_ms,
                latest_safe_at_ms: None,
                reason: MaintenanceTriggerReason::Manual,
            });
        }

        if self.config.maintenance.mode == MaintenanceMode::Auto && !self.trigger.is_paused() {
            let mut automatic: Vec<PlannedTrigger> = Vec::new();
            let nearest_retain_until_ms = report
                .and_then(|report| report.nearest_retain_until_ms)
                .or_else(|| self.status.snapshot().nearest_retain_until_ms);
            if self.config.retention_configured
                && let Some(nearest) = nearest_retain_until_ms
            {
                let horizon_ms = duration_ms(self.config.maintenance.renewal_horizon);
                let jitter_ms = duration_ms(self.renewal_jitter);
                let latest_safe_at_ms = nearest.saturating_sub(horizon_ms);
                automatic.push(PlannedTrigger {
                    due_at_ms: latest_safe_at_ms.saturating_sub(jitter_ms),
                    latest_safe_at_ms: Some(latest_safe_at_ms),
                    reason: MaintenanceTriggerReason::RenewalDeadline,
                });
            }
            if report.is_some_and(|report| self.orphan_pressure_due(report)) {
                automatic.push(PlannedTrigger {
                    due_at_ms: now_ms,
                    latest_safe_at_ms: None,
                    reason: MaintenanceTriggerReason::OrphanPressure,
                });
            }
            let interval_base = self
                .last_finished_at_ms
                .or(self.started_at_ms)
                .unwrap_or(now_ms);
            automatic.push(PlannedTrigger {
                due_at_ms: interval_base
                    .saturating_add(duration_ms(self.config.maintenance.max_interval)),
                latest_safe_at_ms: None,
                reason: MaintenanceTriggerReason::MaxInterval,
            });

            // Automatic triggers respect the cooldown and failure backoff
            // floors; a manual trigger deliberately bypasses both.
            let cooldown_floor = self.last_finished_at_ms.map(|finished| {
                finished.saturating_add(duration_ms(self.config.maintenance.min_cooldown))
            });
            for candidate in &mut automatic {
                if let Some(floor) = cooldown_floor {
                    candidate.due_at_ms = candidate.due_at_ms.max(floor);
                }
                if let Some(backoff_until) = self.backoff_until_ms {
                    candidate.due_at_ms = candidate.due_at_ms.max(backoff_until);
                }
                if let Some(latest_safe_at_ms) = candidate.latest_safe_at_ms {
                    candidate.due_at_ms = candidate.due_at_ms.min(latest_safe_at_ms);
                }
            }
            candidates.extend(automatic);
        }

        // Stable selection: earliest due time wins; earlier list position
        // wins ties, which encodes the manual > renewal > orphan > interval
        // priority.
        candidates.into_iter().reduce(|best, candidate| {
            if candidate.due_at_ms < best.due_at_ms {
                candidate
            } else {
                best
            }
        })
    }

    fn orphan_pressure_due(&self, report: &V2MaintenanceReport) -> bool {
        let maintenance = &self.config.maintenance;
        let count = u64::try_from(report.reclaimable_orphan_candidate_count).unwrap_or(u64::MAX);
        if report.reclaimable_orphan_candidate_bytes >= maintenance.orphan_pressure_bytes {
            return true;
        }
        if count >= maintenance.orphan_pressure_count {
            return true;
        }
        report
            .oldest_reclaimable_orphan_age_ms
            .is_some_and(|age_ms| age_ms >= maintenance.orphan_pressure_max_age.as_millis())
    }

    fn publish_schedule(&self, planned: Option<&PlannedTrigger>, now_ms: i64) {
        let in_cooldown = self.last_finished_at_ms.is_some_and(|finished| {
            now_ms < finished.saturating_add(duration_ms(self.config.maintenance.min_cooldown))
        });
        let idle_state = if self.backoff_until_ms.is_some_and(|until| now_ms < until) {
            MaintenanceSupervisorState::Failed
        } else if in_cooldown {
            MaintenanceSupervisorState::Cooldown
        } else {
            MaintenanceSupervisorState::Idle
        };
        self.status.update(|snapshot| {
            snapshot.state = idle_state.as_str();
            snapshot.next_trigger_at_ms = planned.map(|planned| planned.due_at_ms.max(now_ms));
            snapshot.next_trigger_reason = planned.map(|planned| planned.reason.as_str());
        });
    }

    async fn execute_run(&mut self, reason: MaintenanceTriggerReason) {
        // Any run satisfies manual requests received before it started, so
        // repeated triggers coalesce into at most one pending follow-up run.
        self.trigger.take_requested();
        let pending = if reason == MaintenanceTriggerReason::Manual {
            self.trigger.take_pending()
        } else {
            None
        };
        let started_at_ms = self.clock.now_ms();
        let (mut operation, expected_plan_digest, responder) = match pending {
            Some(pending) => {
                let mut record = MaintenanceOperationRecord::submitted(
                    pending.operation_id,
                    "apply",
                    pending.source,
                    pending.submitted_at_ms,
                );
                record.plan_digest = Some(pending.plan_digest.clone());
                (record, Some(pending.plan_digest), Some(pending.responder))
            }
            None => (
                MaintenanceOperationRecord::submitted(
                    generate_operation_id(),
                    "run",
                    MaintenanceOperationSource::Auto,
                    started_at_ms,
                ),
                None,
                None,
            ),
        };
        operation.started_at_ms = Some(started_at_ms);
        self.status.record_operation(operation.clone());
        let cancellation = Arc::new(V2MaintenanceCancellation::new());
        self.set_active_cancellation(Some(Arc::clone(&cancellation)));

        let options = V2FullGcApplyOptions {
            dry_run: V2FullGcDryRunOptions {
                budgets: self.config.maintenance.budgets(),
                retention_renewal_horizon: self.config.maintenance.renewal_horizon,
                protected_roots: Vec::new(),
            },
            orphan_gc: self.config.orphan_gc,
            retained_provider_conformance_passed: (self.config.retained_provider_conformance)(),
        };

        self.status.set_state(MaintenanceSupervisorState::Quiescing);
        let phase_status = self.status.clone();
        let on_phase = move |phase: MaintenanceRunPhase| {
            phase_status.set_state(match phase {
                MaintenanceRunPhase::Quiescing => MaintenanceSupervisorState::Quiescing,
                MaintenanceRunPhase::Applying => MaintenanceSupervisorState::Applying,
            });
        };
        let result = self
            .runtime
            .run_full_maintenance(
                options,
                expected_plan_digest.as_deref(),
                cancellation.as_ref(),
                &on_phase,
            )
            .await;
        self.set_active_cancellation(None);

        let finished_at_ms = self.clock.now_ms();
        let duration_ms_elapsed =
            u64::try_from(finished_at_ms.saturating_sub(started_at_ms)).unwrap_or(0);
        metrics::histogram!("rs3_maintenance_window_duration_seconds")
            .record(duration_ms_elapsed as f64 / 1000.0);
        self.last_finished_at_ms = Some(finished_at_ms);

        let (summary, next_state) = match result {
            Ok(report) => self.summarize_completed_run(
                reason,
                started_at_ms,
                duration_ms_elapsed,
                finished_at_ms,
                &report,
            ),
            Err(error) => self.summarize_failed_run(
                reason,
                started_at_ms,
                duration_ms_elapsed,
                finished_at_ms,
                &error,
            ),
        };
        record_run_outcome(summary.outcome);
        metrics::gauge!("rs3_maintenance_consecutive_failures")
            .set(self.consecutive_failures as f64);
        tracing::info!(
            target: "rs3_server",
            operation = "maintenance_supervisor_run",
            trigger = summary.trigger,
            result = summary.outcome,
            duration_ms = summary.duration_ms,
            renewed_object_count = summary.renewed_object_count,
            renewed_bytes = summary.renewed_bytes,
            deleted_object_count = summary.deleted_object_count,
            reclaimable_bytes = summary.reclaimable_bytes,
            consecutive_failures = self.consecutive_failures,
            "maintenance supervisor run finished",
        );
        operation.finished_at_ms = Some(finished_at_ms);
        operation.outcome = Some(summary.outcome);
        operation.renewed_object_count = summary.renewed_object_count;
        operation.renewed_bytes = summary.renewed_bytes;
        operation.deleted_object_count = summary.deleted_object_count;
        operation.reclaimable_bytes = summary.reclaimable_bytes;
        operation.failure_reason = summary.failure_reason.clone();
        let finished_operation = operation.clone();
        self.status.finish_operation(&operation.id, move |record| {
            *record = finished_operation;
        });
        if let Some(responder) = responder {
            let _ = responder.send(operation);
        }

        let consecutive_failures = self.consecutive_failures;
        let last_success_at_ms = if summary.outcome == OUTCOME_OK {
            Some(finished_at_ms)
        } else {
            None
        };
        self.status.update(|snapshot| {
            snapshot.state = next_state.as_str();
            snapshot.consecutive_failures = consecutive_failures;
            if let Some(success) = last_success_at_ms {
                snapshot.last_success_at_ms = Some(success);
            }
            snapshot.last_run = Some(summary);
        });

        if next_state == MaintenanceSupervisorState::Verifying {
            // The outer scheduler loop refreshes the report once. Avoid a
            // duplicate full inventory scan at the end of every successful run.
            self.status.set_state(MaintenanceSupervisorState::Cooldown);
        }
    }

    fn summarize_completed_run(
        &mut self,
        reason: MaintenanceTriggerReason,
        started_at_ms: i64,
        duration_ms_elapsed: u64,
        finished_at_ms: i64,
        report: &V2FullMaintenanceReport,
    ) -> (MaintenanceRunSummary, MaintenanceSupervisorState) {
        let apply = &report.apply;
        let aborted = apply.orphan_gc.aborted.as_ref();
        let cancelled = aborted.is_some_and(|error| {
            matches!(
                error,
                rs3_repository::v2::V2FormatError::MaintenanceCancelled
            )
        });
        let (outcome, next_state, failure_reason) = if cancelled {
            (
                OUTCOME_CANCELLED,
                MaintenanceSupervisorState::Cancelled,
                aborted.map(|error| error.to_string()),
            )
        } else if let Some(error) = aborted {
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            self.backoff_until_ms =
                Some(finished_at_ms.saturating_add(duration_ms(self.failure_backoff())));
            (
                OUTCOME_FAILED,
                MaintenanceSupervisorState::Failed,
                Some(error.to_string()),
            )
        } else {
            self.consecutive_failures = 0;
            self.backoff_until_ms = None;
            metrics::gauge!("rs3_maintenance_last_success_timestamp_seconds")
                .set(finished_at_ms as f64 / 1000.0);
            (OUTCOME_OK, MaintenanceSupervisorState::Verifying, None)
        };
        (
            MaintenanceRunSummary {
                trigger: reason.as_str(),
                outcome,
                started_at_ms,
                duration_ms: duration_ms_elapsed,
                renewed_object_count: apply.retention_renewed_object_count,
                renewed_bytes: apply.retention_renewed_bytes,
                deleted_object_count: apply.orphan_gc.deleted_count,
                reclaimable_bytes: reclaimable_bytes(apply),
                failure_reason,
            },
            next_state,
        )
    }

    fn summarize_failed_run(
        &mut self,
        reason: MaintenanceTriggerReason,
        started_at_ms: i64,
        duration_ms_elapsed: u64,
        finished_at_ms: i64,
        error: &RepositoryError,
    ) -> (MaintenanceRunSummary, MaintenanceSupervisorState) {
        let failure_reason = error.to_string();
        let cancelled = failure_reason.contains("cancelled");
        let stale_plan = failure_reason.contains(MAINTENANCE_PLAN_STALE_REASON);
        let (outcome, next_state) = if stale_plan {
            // A stale plan is an operator-visible rejection, not an engine
            // failure: nothing was mutated, so no backoff is warranted.
            (OUTCOME_STALE_PLAN, MaintenanceSupervisorState::Idle)
        } else if cancelled {
            (OUTCOME_CANCELLED, MaintenanceSupervisorState::Cancelled)
        } else {
            if failure_reason.contains("maintenance budget exceeded") {
                metrics::counter!("rs3_maintenance_budget_exceeded_total").increment(1);
            }
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            self.backoff_until_ms =
                Some(finished_at_ms.saturating_add(duration_ms(self.failure_backoff())));
            (OUTCOME_FAILED, MaintenanceSupervisorState::Failed)
        };
        (
            MaintenanceRunSummary {
                trigger: reason.as_str(),
                outcome,
                started_at_ms,
                duration_ms: duration_ms_elapsed,
                renewed_object_count: 0,
                renewed_bytes: 0,
                deleted_object_count: 0,
                reclaimable_bytes: 0,
                failure_reason: Some(failure_reason),
            },
            next_state,
        )
    }

    /// Returns the exponential failure backoff, capped by the max interval.
    fn failure_backoff(&self) -> Duration {
        let base = self
            .config
            .maintenance
            .min_cooldown
            .max(Duration::from_secs(1));
        let exponent = self.consecutive_failures.saturating_sub(1).min(16);
        let backoff = base.saturating_mul(1_u32 << exponent.min(31));
        backoff.min(self.config.maintenance.max_interval)
    }

    fn record_planning_failure(&mut self, error: &RepositoryError, failed_at_ms: i64) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.backoff_until_ms =
            Some(failed_at_ms.saturating_add(duration_ms(self.failure_backoff())));
        metrics::counter!("rs3_maintenance_planning_failures_total").increment(1);
        if error.to_string().contains("maintenance budget exceeded") {
            metrics::counter!("rs3_maintenance_budget_exceeded_total").increment(1);
        }
        metrics::gauge!("rs3_maintenance_consecutive_failures")
            .set(self.consecutive_failures as f64);
        let consecutive_failures = self.consecutive_failures;
        self.status.update(|snapshot| {
            snapshot.state = MaintenanceSupervisorState::Failed.as_str();
            snapshot.consecutive_failures = consecutive_failures;
        });
    }

    fn set_active_cancellation(&self, cancellation: Option<Arc<V2MaintenanceCancellation>>) {
        let mut slot = match self.active_cancellation.write() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        *slot = cancellation;
    }
}

fn reclaimable_bytes(apply: &V2FullGcApplyReport) -> u64 {
    apply.dry_run.dead_bytes_reclaimable
}

fn record_report_gauges(report: &V2MaintenanceReport, now_ms: i64) {
    metrics::gauge!("rs3_maintenance_orphan_candidate_bytes")
        .set(report.reclaimable_orphan_candidate_bytes as f64);
    metrics::gauge!("rs3_maintenance_orphan_candidate_count")
        .set(report.reclaimable_orphan_candidate_count as f64);
    let seconds_to_deadline = report
        .nearest_retain_until_ms
        .map(|nearest| nearest.saturating_sub(now_ms) as f64 / 1000.0)
        .unwrap_or(f64::INFINITY);
    metrics::gauge!("rs3_maintenance_seconds_to_nearest_renewal_deadline").set(seconds_to_deadline);
}

fn initialize_supervisor_metrics() {
    for outcome in [
        OUTCOME_OK,
        OUTCOME_FAILED,
        OUTCOME_CANCELLED,
        OUTCOME_REJECTED,
        OUTCOME_STALE_PLAN,
    ] {
        metrics::counter!("rs3_maintenance_runs_total", "outcome" => outcome).increment(0);
    }
    metrics::counter!("rs3_maintenance_budget_exceeded_total").increment(0);
    metrics::counter!("rs3_maintenance_planning_failures_total").increment(0);
    metrics::gauge!("rs3_maintenance_consecutive_failures").set(0.0);
    metrics::gauge!("rs3_maintenance_orphan_candidate_bytes").set(0.0);
    metrics::gauge!("rs3_maintenance_orphan_candidate_count").set(0.0);
    metrics::gauge!("rs3_maintenance_seconds_to_nearest_renewal_deadline").set(f64::INFINITY);
    metrics::gauge!("rs3_maintenance_paused").set(0.0);
    metrics::gauge!("rs3_maintenance_parked").set(0.0);
}

fn record_run_outcome(outcome: &'static str) {
    metrics::counter!("rs3_maintenance_runs_total", "outcome" => outcome).increment(1);
}

fn duration_ms(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

fn ms_until(now_ms: i64, due_at_ms: i64) -> Duration {
    let delta = due_at_ms.saturating_sub(now_ms);
    if delta <= 0 {
        Duration::ZERO
    } else {
        Duration::from_millis(u64::try_from(delta).unwrap_or(u64::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MaintenanceClock, MaintenanceControlError, MaintenanceOperationSource, MaintenanceRunPhase,
        MaintenanceRuntime, MaintenanceStatusSnapshot, MaintenanceSupervisor,
        MaintenanceSupervisorConfig, MaintenanceSupervisorHandle, renewal_jitter_ceiling,
        sample_renewal_jitter,
    };
    use crate::config::{MaintenanceConfig, MaintenanceMode};
    use async_trait::async_trait;
    use rs3_repository::RepositoryError;
    use rs3_repository::v2::{
        V2FullGcApplyOptions, V2FullGcApplyReport, V2FullGcDryRunOptions, V2FullGcDryRunReport,
        V2FullGcPlanPreview, V2FullMaintenanceReport, V2MaintenanceCancellation,
        V2MaintenancePlanCost, V2MaintenanceReport, V2OrphanGcOptions, V2OrphanGcReport,
    };
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::Duration;
    use tokio::sync::watch;

    const START_MS: i64 = 1_750_000_000_000;

    struct SimulatedClock {
        now: watch::Sender<i64>,
    }

    impl SimulatedClock {
        fn new(start_ms: i64) -> Self {
            let (now, _) = watch::channel(start_ms);
            Self { now }
        }

        fn advance(&self, duration: Duration) {
            let millis = i64::try_from(duration.as_millis()).expect("advance fits in i64");
            self.now
                .send_modify(|now| *now = now.saturating_add(millis));
        }
    }

    #[async_trait]
    impl MaintenanceClock for SimulatedClock {
        fn now_ms(&self) -> i64 {
            *self.now.borrow()
        }

        async fn sleep(&self, duration: Duration) {
            let millis = i64::try_from(duration.as_millis()).unwrap_or(i64::MAX);
            let deadline = self.now_ms().saturating_add(millis);
            let mut updates = self.now.subscribe();
            loop {
                if *updates.borrow_and_update() >= deadline {
                    return;
                }
                if updates.changed().await.is_err() {
                    return;
                }
            }
        }
    }

    fn quick_report() -> V2MaintenanceReport {
        V2MaintenanceReport {
            anchor_present: true,
            verified_commit_count: 1,
            last_anchored_commit_age_ms: Some(0),
            orphan_candidate_count: 0,
            orphan_candidate_bytes: 0,
            protected_orphan_candidate_count: 0,
            oldest_orphan_age_ms: None,
            reclaimable_orphan_candidate_count: 0,
            reclaimable_orphan_candidate_bytes: 0,
            oldest_reclaimable_orphan_age_ms: None,
            retention_renewal_commit_count: 0,
            retention_renewal_bytes: 0,
            retention_renewal_blocked_count: 0,
            retention_renewal_blocked_bytes: 0,
            nearest_retain_until_ms: None,
        }
    }

    fn dry_run_report() -> V2FullGcDryRunReport {
        V2FullGcDryRunReport {
            base_sequence: None,
            chain_live_commit_count: 1,
            protected_root_count: 0,
            protected_commit_count: 0,
            candidate_commit_count: 1,
            fully_dead_commit_count: 1,
            mixed_commit_count: 0,
            dead_bytes_reclaimable: 64,
            live_bytes_to_copy: 0,
            mixed_dead_bytes_repackable: 0,
            retention_blocked_bytes: 0,
            legal_hold_blocked_bytes: 0,
            unknown_protection_blocked_bytes: 0,
            retention_renewal_commit_count: 1,
            retention_renewal_bytes: 32,
            retention_renewal_blocked_count: 0,
            retention_renewal_blocked_bytes: 0,
            planned_cost: V2MaintenancePlanCost::default(),
            fits_budgets: true,
            exact_version_apply_ready: true,
        }
    }

    fn full_report() -> V2FullMaintenanceReport {
        V2FullMaintenanceReport {
            dry_run: dry_run_report(),
            apply: V2FullGcApplyReport {
                dry_run: dry_run_report(),
                retention_renewed_object_count: 1,
                retention_renewed_bytes: 32,
                orphan_gc: V2OrphanGcReport {
                    scanned_count: 1,
                    deleted_count: 1,
                    ..V2OrphanGcReport::default()
                },
            },
        }
    }

    fn mock_plan_digest(report: &V2FullGcDryRunReport) -> String {
        rs3_crypto::derive_public_fingerprint(
            b"rs3.maintenance.mock-plan.v1",
            &[
                &report.dead_bytes_reclaimable.to_be_bytes(),
                &u64::try_from(report.retention_renewal_commit_count)
                    .unwrap_or(u64::MAX)
                    .to_be_bytes(),
            ],
        )
    }

    struct MockRuntime {
        guard_configured: bool,
        clock: Arc<SimulatedClock>,
        report: StdMutex<V2MaintenanceReport>,
        dry_run: StdMutex<V2FullGcDryRunReport>,
        queued_results: StdMutex<VecDeque<Result<V2FullMaintenanceReport, RepositoryError>>>,
        always_fail: bool,
        hold_gate: Option<Arc<tokio::sync::Semaphore>>,
        wait_for_cancellation: bool,
        run_started_at_ms: StdMutex<Vec<i64>>,
        concurrent: AtomicUsize,
        max_concurrent: AtomicUsize,
        quick_report_count: AtomicUsize,
        fail_quick_report: AtomicBool,
    }

    impl MockRuntime {
        fn new(clock: Arc<SimulatedClock>) -> Self {
            Self {
                guard_configured: true,
                clock,
                report: StdMutex::new(quick_report()),
                dry_run: StdMutex::new(dry_run_report()),
                queued_results: StdMutex::new(VecDeque::new()),
                always_fail: false,
                hold_gate: None,
                wait_for_cancellation: false,
                run_started_at_ms: StdMutex::new(Vec::new()),
                concurrent: AtomicUsize::new(0),
                max_concurrent: AtomicUsize::new(0),
                quick_report_count: AtomicUsize::new(0),
                fail_quick_report: AtomicBool::new(false),
            }
        }

        fn set_report(&self, report: V2MaintenanceReport) {
            *self.report.lock().expect("mock report lock") = report;
        }

        fn set_dry_run_report(&self, report: V2FullGcDryRunReport) {
            *self.dry_run.lock().expect("mock dry-run lock") = report;
        }

        fn run_count(&self) -> usize {
            self.run_started_at_ms.lock().expect("mock run lock").len()
        }

        fn run_started_at_ms(&self) -> Vec<i64> {
            self.run_started_at_ms
                .lock()
                .expect("mock run lock")
                .clone()
        }
    }

    #[async_trait]
    impl MaintenanceRuntime for MockRuntime {
        fn maintenance_guard_configured(&self) -> bool {
            self.guard_configured
        }

        async fn quick_maintenance_report(&self) -> Result<V2MaintenanceReport, RepositoryError> {
            self.quick_report_count.fetch_add(1, Ordering::SeqCst);
            if self.fail_quick_report.load(Ordering::SeqCst) {
                return Err(RepositoryError::CommitFailed {
                    reason: "quick maintenance planning failed for test".to_owned(),
                });
            }
            Ok(self.report.lock().expect("mock report lock").clone())
        }

        async fn full_gc_dry_run(
            &self,
            _options: V2FullGcDryRunOptions,
        ) -> Result<V2FullGcDryRunReport, RepositoryError> {
            Ok(self.dry_run.lock().expect("mock dry-run lock").clone())
        }

        async fn preview_full_gc_plan(
            &self,
            _options: V2FullGcApplyOptions,
        ) -> Result<V2FullGcPlanPreview, RepositoryError> {
            let report = self.dry_run.lock().expect("mock dry-run lock").clone();
            Ok(V2FullGcPlanPreview {
                plan_digest: mock_plan_digest(&report),
                report,
            })
        }

        async fn run_full_maintenance(
            &self,
            _options: V2FullGcApplyOptions,
            expected_plan_digest: Option<&str>,
            cancellation: &V2MaintenanceCancellation,
            on_phase: &(dyn Fn(MaintenanceRunPhase) + Send + Sync),
        ) -> Result<V2FullMaintenanceReport, RepositoryError> {
            self.run_started_at_ms
                .lock()
                .expect("mock run lock")
                .push(self.clock.now_ms());
            let concurrent = self.concurrent.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_concurrent.fetch_max(concurrent, Ordering::SeqCst);
            on_phase(MaintenanceRunPhase::Quiescing);
            if let Some(expected) = expected_plan_digest {
                let fresh = mock_plan_digest(&self.dry_run.lock().expect("mock dry-run"));
                if fresh != expected {
                    self.concurrent.fetch_sub(1, Ordering::SeqCst);
                    return Err(RepositoryError::CommitFailed {
                        reason: super::MAINTENANCE_PLAN_STALE_REASON.to_owned(),
                    });
                }
            }
            on_phase(MaintenanceRunPhase::Applying);
            if let Some(gate) = self.hold_gate.as_ref() {
                let permit = gate.acquire().await.expect("mock gate should stay open");
                permit.forget();
            }
            if self.wait_for_cancellation {
                while !cancellation.is_cancelled() {
                    tokio::task::yield_now().await;
                }
                self.concurrent.fetch_sub(1, Ordering::SeqCst);
                return Err(RepositoryError::CommitFailed {
                    reason: "v2 maintenance run was cancelled".to_owned(),
                });
            }
            self.concurrent.fetch_sub(1, Ordering::SeqCst);
            if self.always_fail {
                return Err(RepositoryError::CommitFailed {
                    reason: "v2 maintenance run failed for test".to_owned(),
                });
            }
            self.queued_results
                .lock()
                .expect("mock result lock")
                .pop_front()
                .unwrap_or_else(|| Ok(full_report()))
        }
    }

    fn supervisor_config(maintenance: MaintenanceConfig) -> MaintenanceSupervisorConfig {
        MaintenanceSupervisorConfig {
            maintenance,
            retention_configured: true,
            orphan_gc: V2OrphanGcOptions::new_for_test_rehearsal(Duration::ZERO),
            retained_provider_conformance: Arc::new(|| true),
        }
    }

    fn test_maintenance_config() -> MaintenanceConfig {
        MaintenanceConfig {
            mode: MaintenanceMode::Auto,
            renewal_horizon: Duration::from_secs(24 * 60 * 60),
            orphan_pressure_bytes: 1024 * 1024,
            orphan_pressure_count: 5,
            orphan_pressure_max_age: Duration::from_secs(48 * 60 * 60),
            max_interval: Duration::from_secs(2 * 60 * 60),
            min_cooldown: Duration::from_secs(60 * 60),
            pacing_delay: None,
            ..MaintenanceConfig::default()
        }
    }

    async fn wait_until<F>(condition: F)
    where
        F: Fn() -> bool,
    {
        tokio::time::timeout(Duration::from_secs(10), async {
            while !condition() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("condition should hold before the test timeout");
    }

    fn start(
        config: MaintenanceSupervisorConfig,
        runtime: Arc<MockRuntime>,
        clock: Arc<SimulatedClock>,
    ) -> MaintenanceSupervisorHandle {
        MaintenanceSupervisor::start(config, runtime, clock)
    }

    fn snapshot_of(handle: &MaintenanceSupervisorHandle) -> MaintenanceStatusSnapshot {
        handle.status().snapshot()
    }

    #[tokio::test]
    async fn renewal_deadline_trigger_schedules_within_jitter_bounds() {
        let clock = Arc::new(SimulatedClock::new(START_MS));
        let mut report = quick_report();
        let horizon = Duration::from_secs(24 * 60 * 60);
        let nearest = START_MS + 10 * 24 * 60 * 60 * 1000;
        report.nearest_retain_until_ms = Some(nearest);
        let runtime = Arc::new(MockRuntime::new(Arc::clone(&clock)));
        runtime.set_report(report);
        let mut maintenance = test_maintenance_config();
        maintenance.max_interval = Duration::from_secs(30 * 24 * 60 * 60);
        let handle = start(
            supervisor_config(maintenance),
            Arc::clone(&runtime),
            Arc::clone(&clock),
        );

        wait_until(|| snapshot_of(&handle).next_trigger_reason == Some("renewal-deadline")).await;

        let snapshot = snapshot_of(&handle);
        let due = snapshot
            .next_trigger_at_ms
            .expect("renewal trigger should be scheduled");
        let horizon_ms = i64::try_from(horizon.as_millis()).expect("horizon fits in i64");
        let jitter_ceiling_ms = i64::try_from(renewal_jitter_ceiling(horizon).as_millis())
            .expect("jitter ceiling fits in i64");
        assert!(due <= nearest - horizon_ms, "due {due} nearest {nearest}");
        assert!(
            due >= nearest - horizon_ms - jitter_ceiling_ms,
            "due {due} outside jitter window"
        );
        assert_eq!(runtime.run_count(), 0, "far deadline must not run yet");
        handle.shutdown().await;
    }

    #[test]
    fn jitter_sampling_stays_within_ceiling() {
        let ceiling = renewal_jitter_ceiling(Duration::from_secs(7 * 24 * 60 * 60));
        assert_eq!(ceiling, super::MAX_RENEWAL_JITTER);
        let small = renewal_jitter_ceiling(Duration::from_secs(160));
        assert_eq!(small, Duration::from_secs(10));
        for _ in 0..64 {
            assert!(sample_renewal_jitter(ceiling) <= ceiling);
            assert!(sample_renewal_jitter(Duration::ZERO) == Duration::ZERO);
        }
    }

    #[tokio::test]
    async fn orphan_pressure_triggers_immediate_run() {
        let clock = Arc::new(SimulatedClock::new(START_MS));
        let runtime = Arc::new(MockRuntime::new(Arc::clone(&clock)));
        let mut report = quick_report();
        report.orphan_candidate_count = 5;
        report.reclaimable_orphan_candidate_count = 5;
        runtime.set_report(report);
        let handle = start(
            supervisor_config(test_maintenance_config()),
            Arc::clone(&runtime),
            Arc::clone(&clock),
        );

        wait_until(|| {
            snapshot_of(&handle)
                .last_run
                .as_ref()
                .is_some_and(|run| run.outcome == "ok")
        })
        .await;

        let snapshot = snapshot_of(&handle);
        let last_run = snapshot.last_run.expect("run summary should be recorded");
        assert_eq!(last_run.trigger, "orphan-pressure");
        assert_eq!(last_run.renewed_object_count, 1);
        assert_eq!(last_run.deleted_object_count, 1);
        assert_eq!(snapshot.consecutive_failures, 0);
        assert!(snapshot.last_success_at_ms.is_some());
        assert_eq!(runtime.run_count(), 1);
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn manual_mode_does_not_run_background_inventory_scans() {
        let clock = Arc::new(SimulatedClock::new(START_MS));
        let runtime = Arc::new(MockRuntime::new(Arc::clone(&clock)));
        let mut maintenance = test_maintenance_config();
        maintenance.mode = MaintenanceMode::Manual;
        let handle = start(
            supervisor_config(maintenance),
            Arc::clone(&runtime),
            Arc::clone(&clock),
        );

        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        clock.advance(Duration::from_secs(24 * 60 * 60));
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        assert_eq!(runtime.quick_report_count.load(Ordering::SeqCst), 0);
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn planning_failures_back_off_but_keep_the_interval_schedule_visible() {
        let clock = Arc::new(SimulatedClock::new(START_MS));
        let runtime = Arc::new(MockRuntime::new(Arc::clone(&clock)));
        runtime.fail_quick_report.store(true, Ordering::SeqCst);
        let handle = start(
            supervisor_config(test_maintenance_config()),
            Arc::clone(&runtime),
            Arc::clone(&clock),
        );

        wait_until(|| snapshot_of(&handle).state == "failed").await;
        let snapshot = snapshot_of(&handle);
        assert_eq!(snapshot.consecutive_failures, 1);
        assert_eq!(snapshot.next_trigger_reason, Some("max-interval"));
        assert_eq!(runtime.quick_report_count.load(Ordering::SeqCst), 1);

        clock.advance(Duration::from_secs(30 * 60));
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        assert_eq!(runtime.quick_report_count.load(Ordering::SeqCst), 1);

        clock.advance(Duration::from_secs(31 * 60));
        wait_until(|| runtime.quick_report_count.load(Ordering::SeqCst) == 2).await;
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn max_interval_cap_triggers_run_and_cooldown_floors_the_next_one() {
        let clock = Arc::new(SimulatedClock::new(START_MS));
        let runtime = Arc::new(MockRuntime::new(Arc::clone(&clock)));
        let handle = start(
            supervisor_config(test_maintenance_config()),
            Arc::clone(&runtime),
            Arc::clone(&clock),
        );

        wait_until(|| snapshot_of(&handle).next_trigger_reason == Some("max-interval")).await;
        assert_eq!(runtime.run_count(), 0);

        clock.advance(Duration::from_secs(2 * 60 * 60 + 60));
        wait_until(|| runtime.run_count() == 1).await;
        wait_until(|| {
            snapshot_of(&handle)
                .last_run
                .as_ref()
                .is_some_and(|run| run.outcome == "ok" && run.trigger == "max-interval")
        })
        .await;
        let finished_floor = snapshot_of(&handle)
            .last_success_at_ms
            .expect("first run should have succeeded");

        // Orphan pressure becomes due immediately, but the cooldown floor
        // must hold the next run back for the full minimum cooldown.
        let mut pressured = quick_report();
        pressured.orphan_candidate_count = 5;
        pressured.reclaimable_orphan_candidate_count = 5;
        runtime.set_report(pressured);
        // Advance past the poll interval so the supervisor replans with the
        // refreshed report.
        clock.advance(Duration::from_secs(16 * 60));
        wait_until(|| snapshot_of(&handle).next_trigger_reason == Some("orphan-pressure")).await;
        let next = snapshot_of(&handle)
            .next_trigger_at_ms
            .expect("pressure trigger should be scheduled");
        assert!(
            next >= finished_floor + 60 * 60 * 1000,
            "cooldown floor must delay the orphan run"
        );
        assert_eq!(runtime.run_count(), 1);

        clock.advance(Duration::from_secs(60 * 60 + 60));
        wait_until(|| runtime.run_count() == 2).await;
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn failed_runs_back_off_exponentially() {
        let clock = Arc::new(SimulatedClock::new(START_MS));
        let mut runtime = MockRuntime::new(Arc::clone(&clock));
        runtime.always_fail = true;
        let mut report = quick_report();
        report.orphan_candidate_count = 100;
        report.reclaimable_orphan_candidate_count = 100;
        runtime.set_report(report);
        let runtime = Arc::new(runtime);
        let mut maintenance = test_maintenance_config();
        maintenance.min_cooldown = Duration::from_secs(100);
        maintenance.max_interval = Duration::from_secs(100_000);
        let handle = start(
            supervisor_config(maintenance),
            Arc::clone(&runtime),
            Arc::clone(&clock),
        );

        wait_until(|| runtime.run_count() == 1).await;
        wait_until(|| snapshot_of(&handle).consecutive_failures == 1).await;

        // Backoff after one failure is one cooldown; 100s later a second run
        // starts and fails, doubling the backoff to 200s.
        clock.advance(Duration::from_secs(101));
        wait_until(|| runtime.run_count() == 2).await;
        wait_until(|| snapshot_of(&handle).consecutive_failures == 2).await;

        clock.advance(Duration::from_secs(101));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            runtime.run_count(),
            2,
            "doubled backoff must hold the third run back"
        );

        clock.advance(Duration::from_secs(101));
        wait_until(|| runtime.run_count() == 3).await;

        let started = runtime.run_started_at_ms();
        assert!(started[1] - started[0] >= 100 * 1000);
        assert!(started[2] - started[1] >= 200 * 1000);
        let snapshot = snapshot_of(&handle);
        assert_eq!(snapshot.consecutive_failures, 3);
        let last_run = snapshot.last_run.expect("failed run summary");
        assert_eq!(last_run.outcome, "failed");
        assert!(
            last_run
                .failure_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("failed for test"))
        );
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn manual_triggers_are_single_flight_and_coalesced() {
        let clock = Arc::new(SimulatedClock::new(START_MS));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let mut runtime = MockRuntime::new(Arc::clone(&clock));
        runtime.hold_gate = Some(Arc::clone(&gate));
        let runtime = Arc::new(runtime);
        let mut maintenance = test_maintenance_config();
        maintenance.mode = MaintenanceMode::Manual;
        let handle = start(
            supervisor_config(maintenance),
            Arc::clone(&runtime),
            Arc::clone(&clock),
        );
        let trigger = handle.trigger_handle();

        trigger.trigger();
        wait_until(|| runtime.run_count() == 1).await;

        // Triggers during an in-flight run coalesce into one follow-up run.
        trigger.trigger();
        trigger.trigger();
        trigger.trigger();
        gate.add_permits(1);
        wait_until(|| runtime.run_count() == 2).await;
        gate.add_permits(1);
        wait_until(|| {
            snapshot_of(&handle)
                .last_run
                .as_ref()
                .is_some_and(|run| run.outcome == "ok" && run.trigger == "manual")
        })
        .await;

        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        assert_eq!(runtime.run_count(), 2, "triggers must coalesce");
        assert_eq!(
            runtime.max_concurrent.load(Ordering::SeqCst),
            1,
            "maintenance runs must be single-flight"
        );
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_cancels_an_in_flight_run_at_a_mutation_boundary() {
        let clock = Arc::new(SimulatedClock::new(START_MS));
        let mut runtime = MockRuntime::new(Arc::clone(&clock));
        runtime.wait_for_cancellation = true;
        let mut report = quick_report();
        report.orphan_candidate_count = 100;
        report.reclaimable_orphan_candidate_count = 100;
        runtime.set_report(report);
        let runtime = Arc::new(runtime);
        let handle = start(
            supervisor_config(test_maintenance_config()),
            Arc::clone(&runtime),
            Arc::clone(&clock),
        );
        let status = handle.status();

        wait_until(|| runtime.run_count() == 1).await;
        handle.shutdown().await;

        let snapshot = status.snapshot();
        let last_run = snapshot.last_run.expect("cancelled run summary");
        assert_eq!(last_run.outcome, "cancelled");
        assert!(
            last_run
                .failure_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("cancelled"))
        );
        assert_eq!(snapshot.consecutive_failures, 0);
    }

    #[tokio::test]
    async fn parks_without_a_configured_maintenance_guard() {
        let clock = Arc::new(SimulatedClock::new(START_MS));
        let mut runtime = MockRuntime::new(Arc::clone(&clock));
        runtime.guard_configured = false;
        let mut report = quick_report();
        report.orphan_candidate_count = 100;
        report.reclaimable_orphan_candidate_count = 100;
        runtime.set_report(report);
        let runtime = Arc::new(runtime);
        let handle = start(
            supervisor_config(test_maintenance_config()),
            Arc::clone(&runtime),
            Arc::clone(&clock),
        );

        wait_until(|| snapshot_of(&handle).state == "parked").await;
        let snapshot = snapshot_of(&handle);
        assert_eq!(snapshot.parked_reason, Some("maintenance-guard-missing"));
        assert_eq!(runtime.run_count(), 0);

        // Manual triggers are rejected instead of spinning failing runs.
        handle.trigger_handle().trigger();
        wait_until(|| {
            snapshot_of(&handle)
                .last_run
                .as_ref()
                .is_some_and(|run| run.outcome == "rejected")
        })
        .await;
        assert_eq!(runtime.run_count(), 0);
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn pause_blocks_auto_triggers_but_not_manual_operations() {
        let clock = Arc::new(SimulatedClock::new(START_MS));
        let runtime = Arc::new(MockRuntime::new(Arc::clone(&clock)));
        let handle = start(
            supervisor_config(test_maintenance_config()),
            Arc::clone(&runtime),
            Arc::clone(&clock),
        );
        let control = handle.control();

        wait_until(|| snapshot_of(&handle).next_trigger_reason == Some("max-interval")).await;
        let record = control.pause(MaintenanceOperationSource::ManualHttp);
        assert_eq!(record.outcome, Some("ok"));
        wait_until(|| snapshot_of(&handle).paused).await;
        let reports_before_pause = runtime.quick_report_count.load(Ordering::SeqCst);

        // Orphan pressure and the interval cap both become due, but the
        // paused scheduler must not start an automatic run.
        let mut pressured = quick_report();
        pressured.orphan_candidate_count = 100;
        pressured.reclaimable_orphan_candidate_count = 100;
        runtime.set_report(pressured);
        clock.advance(Duration::from_secs(3 * 60 * 60));
        wait_until(|| snapshot_of(&handle).next_trigger_reason.is_none()).await;
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        assert_eq!(runtime.run_count(), 0, "paused scheduler must not run");
        assert_eq!(
            runtime.quick_report_count.load(Ordering::SeqCst),
            reports_before_pause,
            "paused scheduler must not inventory the repository"
        );

        // Manual operations stay allowed while paused.
        handle.trigger_handle().trigger();
        wait_until(|| runtime.run_count() == 1).await;

        let record = control.resume(MaintenanceOperationSource::ManualCli);
        assert_eq!(record.outcome, Some("ok"));
        wait_until(|| !snapshot_of(&handle).paused).await;
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn control_dry_run_returns_stable_digest_and_records_history() {
        let clock = Arc::new(SimulatedClock::new(START_MS));
        let runtime = Arc::new(MockRuntime::new(Arc::clone(&clock)));
        let mut maintenance = test_maintenance_config();
        maintenance.mode = MaintenanceMode::Manual;
        let handle = start(
            supervisor_config(maintenance),
            Arc::clone(&runtime),
            Arc::clone(&clock),
        );
        let control = handle.control();

        let first = control
            .dry_run(MaintenanceOperationSource::ManualHttp)
            .await
            .expect("dry run should succeed");
        let second = control
            .dry_run(MaintenanceOperationSource::ManualCli)
            .await
            .expect("dry run should succeed");

        assert_eq!(first.plan_digest, second.plan_digest);
        assert_ne!(first.operation_id, second.operation_id);
        assert_eq!(first.operation_id.len(), 32);
        assert_eq!(first.report, dry_run_report());
        assert_eq!(runtime.run_count(), 0, "dry runs never take the window");

        let snapshot = snapshot_of(&handle);
        let dry_runs: Vec<_> = snapshot
            .operations
            .iter()
            .filter(|record| record.kind == "dry-run")
            .collect();
        assert_eq!(dry_runs.len(), 2);
        assert_eq!(dry_runs[0].source, "manual-cli");
        assert_eq!(dry_runs[1].source, "manual-http");
        assert!(dry_runs.iter().all(|record| {
            record.outcome == Some("ok")
                && record.plan_digest.as_deref() == Some(first.plan_digest.as_str())
        }));
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn apply_happy_path_binds_plan_digest() {
        let clock = Arc::new(SimulatedClock::new(START_MS));
        let runtime = Arc::new(MockRuntime::new(Arc::clone(&clock)));
        let mut maintenance = test_maintenance_config();
        maintenance.mode = MaintenanceMode::Manual;
        let handle = start(
            supervisor_config(maintenance),
            Arc::clone(&runtime),
            Arc::clone(&clock),
        );
        let control = handle.control();

        let dry_run = control
            .dry_run(MaintenanceOperationSource::ManualHttp)
            .await
            .expect("dry run should succeed");
        let record = control
            .apply(&dry_run.plan_digest, MaintenanceOperationSource::ManualHttp)
            .await
            .expect("apply should be accepted");

        assert_eq!(record.kind, "apply");
        assert_eq!(record.outcome, Some("ok"));
        assert_eq!(record.source, "manual-http");
        assert_eq!(
            record.plan_digest.as_deref(),
            Some(dry_run.plan_digest.as_str())
        );
        assert_eq!(record.renewed_object_count, 1);
        assert_eq!(record.deleted_object_count, 1);
        assert!(record.finished_at_ms.is_some());
        assert_eq!(runtime.run_count(), 1);

        let snapshot = snapshot_of(&handle);
        assert!(
            snapshot
                .operations
                .iter()
                .any(|operation| { operation.id == record.id && operation.outcome == Some("ok") })
        );
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn apply_with_stale_digest_fails_closed_without_backoff() {
        let clock = Arc::new(SimulatedClock::new(START_MS));
        let runtime = Arc::new(MockRuntime::new(Arc::clone(&clock)));
        let mut maintenance = test_maintenance_config();
        maintenance.mode = MaintenanceMode::Manual;
        let handle = start(
            supervisor_config(maintenance),
            Arc::clone(&runtime),
            Arc::clone(&clock),
        );
        let control = handle.control();

        let dry_run = control
            .dry_run(MaintenanceOperationSource::ManualCli)
            .await
            .expect("dry run should succeed");
        // Repository state moves after the operator reviewed the plan.
        let mut moved = dry_run_report();
        moved.dead_bytes_reclaimable += 4096;
        runtime.set_dry_run_report(moved);

        let record = control
            .apply(&dry_run.plan_digest, MaintenanceOperationSource::ManualCli)
            .await
            .expect("apply should resolve with a stale-plan outcome");

        assert_eq!(record.outcome, Some("stale-plan"));
        assert!(
            record
                .failure_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("stale"))
        );
        let snapshot = snapshot_of(&handle);
        assert_eq!(
            snapshot.consecutive_failures, 0,
            "stale plan must not trigger failure backoff"
        );
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn apply_rejects_malformed_digests_and_concurrent_runs() {
        let clock = Arc::new(SimulatedClock::new(START_MS));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let mut runtime = MockRuntime::new(Arc::clone(&clock));
        runtime.hold_gate = Some(Arc::clone(&gate));
        let runtime = Arc::new(runtime);
        let mut maintenance = test_maintenance_config();
        maintenance.mode = MaintenanceMode::Manual;
        let handle = start(
            supervisor_config(maintenance),
            Arc::clone(&runtime),
            Arc::clone(&clock),
        );
        let control = handle.control();

        let malformed = control
            .apply("not-a-digest", MaintenanceOperationSource::ManualHttp)
            .await;
        assert!(matches!(
            malformed,
            Err(MaintenanceControlError::InvalidPlanDigest)
        ));

        handle.trigger_handle().trigger();
        wait_until(|| runtime.run_count() == 1).await;
        let digest = "ab".repeat(32);
        let in_flight = control
            .apply(&digest, MaintenanceOperationSource::ManualHttp)
            .await;
        assert!(matches!(
            in_flight,
            Err(MaintenanceControlError::RunInFlight)
        ));

        gate.add_permits(1);
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn cancel_stops_the_in_flight_run_without_shutdown() {
        let clock = Arc::new(SimulatedClock::new(START_MS));
        let mut runtime = MockRuntime::new(Arc::clone(&clock));
        runtime.wait_for_cancellation = true;
        let runtime = Arc::new(runtime);
        let mut maintenance = test_maintenance_config();
        maintenance.mode = MaintenanceMode::Manual;
        let handle = start(
            supervisor_config(maintenance),
            Arc::clone(&runtime),
            Arc::clone(&clock),
        );
        let control = handle.control();

        let idle_cancel = control.cancel(MaintenanceOperationSource::ManualHttp);
        assert!(matches!(
            idle_cancel,
            Err(MaintenanceControlError::NoRunInFlight)
        ));

        handle.trigger_handle().trigger();
        wait_until(|| runtime.run_count() == 1).await;
        let record = control
            .cancel(MaintenanceOperationSource::ManualHttp)
            .expect("cancel should find the in-flight run");
        assert_eq!(record.kind, "cancel");
        assert_eq!(record.outcome, Some("ok"));

        wait_until(|| {
            snapshot_of(&handle)
                .last_run
                .as_ref()
                .is_some_and(|run| run.outcome == "cancelled")
        })
        .await;
        // Cancel is distinct from shutdown: the supervisor still serves
        // status snapshots and records the cancellation in history.
        let snapshot = snapshot_of(&handle);
        assert!(snapshot.operations.iter().any(|op| op.kind == "cancel"));
        assert_eq!(snapshot.consecutive_failures, 0);
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn operation_history_is_bounded() {
        let clock = Arc::new(SimulatedClock::new(START_MS));
        let runtime = Arc::new(MockRuntime::new(Arc::clone(&clock)));
        let mut maintenance = test_maintenance_config();
        maintenance.mode = MaintenanceMode::Manual;
        let handle = start(
            supervisor_config(maintenance),
            Arc::clone(&runtime),
            Arc::clone(&clock),
        );
        let control = handle.control();

        for _ in 0..20 {
            control.pause(MaintenanceOperationSource::ManualHttp);
            control.resume(MaintenanceOperationSource::ManualHttp);
        }

        let snapshot = snapshot_of(&handle);
        assert_eq!(snapshot.operations.len(), 32);
        assert_eq!(snapshot.operations[0].kind, "resume");
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn apply_is_rejected_while_parked() {
        let clock = Arc::new(SimulatedClock::new(START_MS));
        let mut runtime = MockRuntime::new(Arc::clone(&clock));
        runtime.guard_configured = false;
        let runtime = Arc::new(runtime);
        let handle = start(
            supervisor_config(test_maintenance_config()),
            Arc::clone(&runtime),
            Arc::clone(&clock),
        );
        let control = handle.control();

        wait_until(|| snapshot_of(&handle).state == "parked").await;
        let digest = "cd".repeat(32);
        let parked = control
            .apply(&digest, MaintenanceOperationSource::ManualHttp)
            .await;
        assert!(matches!(
            parked,
            Err(MaintenanceControlError::Parked { .. })
        ));
        assert_eq!(runtime.run_count(), 0);
        handle.shutdown().await;
    }
}

#[cfg(test)]
mod integration_tests {
    use super::{
        MaintenanceOperationSource, MaintenanceRunPhase, MaintenanceRuntime, MaintenanceSupervisor,
        MaintenanceSupervisorConfig, SystemMaintenanceClock,
    };
    use crate::config::{MaintenanceConfig, MaintenanceMode};
    use async_trait::async_trait;
    use bytes::Bytes;
    use rs3_crypto::KeyRing;
    use rs3_repository::v2::{
        UnenforcedQuiescedMaintenanceGuard, V2AnchorState, V2CommitAnchor, V2CommitCoordinator,
        V2CommitSection, V2CommitStore, V2CommitStoreOptions, V2CommitWrite, V2FormatError,
        V2FormatRef, V2FullGcApplyOptions, V2FullMaintenanceReport, V2KeyringEnvelopeRef,
        V2KeyringEnvelopeRootRef, V2MaintenanceCancellation, V2MaintenanceReport, V2MemoryAnchor,
        V2OrphanGcOptions, V2ProviderProfile, V2Repository, V2Result, V2SectionType,
    };
    use rs3_repository::{
        CommitCoordinatorOptions, RepositoryError, RepositoryOptions, RepositoryPutOptions,
    };
    use rs3_storage::{BlobStore, MemoryBlobStore, PutOptions};
    use rs3_types::{BackendObjectId, LogicalPath, RepositoryId, RetentionMode, RetentionPolicy};
    use std::sync::Arc;
    use std::time::Duration;

    struct FailingAdvanceAnchor {
        inner: V2MemoryAnchor,
    }

    #[async_trait]
    impl V2CommitAnchor for FailingAdvanceAnchor {
        async fn read_v2(&self) -> V2Result<Option<V2AnchorState>> {
            self.inner.read_v2().await
        }

        async fn compare_and_advance_v2(
            &self,
            _expected: Option<&V2AnchorState>,
            _next: V2AnchorState,
        ) -> V2Result<V2AnchorState> {
            Err(V2FormatError::AnchorAdvanceFailed)
        }
    }

    struct LocalMaintenanceRuntime {
        repository: Arc<V2Repository<MemoryBlobStore>>,
        anchor: V2MemoryAnchor,
        coordinator: Arc<V2CommitCoordinator<MemoryBlobStore, V2MemoryAnchor>>,
    }

    #[async_trait]
    impl MaintenanceRuntime for LocalMaintenanceRuntime {
        fn maintenance_guard_configured(&self) -> bool {
            self.coordinator.has_maintenance_guard()
        }

        async fn quick_maintenance_report(&self) -> Result<V2MaintenanceReport, RepositoryError> {
            self.repository
                .commit_store()
                .quick_maintenance(&self.anchor)
                .await
                .map_err(|error| RepositoryError::CommitFailed {
                    reason: error.to_string(),
                })
        }

        async fn full_gc_dry_run(
            &self,
            options: rs3_repository::v2::V2FullGcDryRunOptions,
        ) -> Result<rs3_repository::v2::V2FullGcDryRunReport, RepositoryError> {
            self.repository.full_gc_dry_run(&self.anchor, options).await
        }

        async fn preview_full_gc_plan(
            &self,
            options: V2FullGcApplyOptions,
        ) -> Result<rs3_repository::v2::V2FullGcPlanPreview, RepositoryError> {
            self.repository
                .preview_full_gc_plan(&self.anchor, options)
                .await
        }

        async fn run_full_maintenance(
            &self,
            options: V2FullGcApplyOptions,
            expected_plan_digest: Option<&str>,
            cancellation: &V2MaintenanceCancellation,
            on_phase: &(dyn Fn(MaintenanceRunPhase) + Send + Sync),
        ) -> Result<V2FullMaintenanceReport, RepositoryError> {
            on_phase(MaintenanceRunPhase::Quiescing);
            let window = self.coordinator.begin_maintenance_window().await?;
            on_phase(MaintenanceRunPhase::Applying);
            let report = self
                .repository
                .apply_full_gc_quiesced_expected(
                    &self.anchor,
                    window.guard(),
                    options,
                    expected_plan_digest,
                    cancellation,
                )
                .await;
            drop(window);
            report
        }
    }

    fn object_id(value: &str) -> BackendObjectId {
        BackendObjectId::new(value).expect("test object ID should be valid")
    }

    async fn commit_store_options(
        store: &MemoryBlobStore,
        profile: V2ProviderProfile,
        retention: Option<RetentionPolicy>,
    ) -> V2CommitStoreOptions {
        let keyring_ref = V2KeyringEnvelopeRef {
            object_id: object_id("keyrings/00000000000000000001-bootstrap"),
            digest: [6_u8; 32],
        };
        let keyring_metadata = store
            .put(
                &keyring_ref.object_id,
                Bytes::from_static(b"encrypted-keyring-envelope"),
                PutOptions {
                    retention,
                    ..PutOptions::default()
                },
            )
            .await
            .expect("keyring root put should succeed");
        let mut format_ref = V2FormatRef {
            generation: 1,
            digest: hex::encode([7_u8; 32]),
            object_id: object_id(&format!("format/{:020}-{}", 1_u64, hex::encode([7_u8; 32]))),
            version_id: None,
        };
        let format_metadata = store
            .put(
                &format_ref.object_id,
                Bytes::from_static(b"encrypted-format-root"),
                PutOptions {
                    retention,
                    ..PutOptions::default()
                },
            )
            .await
            .expect("format root put should succeed");
        format_ref.version_id = format_metadata.version_id.clone();
        let keyring_root = V2KeyringEnvelopeRootRef {
            generation: 1,
            digest: hex::encode(keyring_ref.digest),
            object_id: keyring_ref.object_id.clone(),
            version_id: keyring_metadata.version_id,
        };
        V2CommitStoreOptions::for_profile(
            profile,
            RepositoryId::new("supervisor-test-repository").expect("repository ID"),
            keyring_ref,
            format_ref,
        )
        .with_maintenance_keyring_envelope_ref(keyring_root)
        .with_retention(retention)
    }

    #[tokio::test]
    async fn supervisor_auto_cycle_renews_retention_and_deletes_orphans() {
        let store = MemoryBlobStore::new();
        let keyring = KeyRing::generate_random().expect("test keyring");
        let retention = Some(RetentionPolicy::new(RetentionMode::Governance, 30));
        let options = commit_store_options(
            &store,
            V2ProviderProfile::RetainedVersionObjectLock,
            retention,
        )
        .await;
        let repository = Arc::new(V2Repository::new(
            store.clone(),
            keyring.clone(),
            RepositoryOptions {
                default_retention: retention,
                ..RepositoryOptions::default()
            },
            options,
        ));
        let anchor = V2MemoryAnchor::new();
        repository
            .write_genesis_snapshot(&anchor)
            .await
            .expect("genesis snapshot");
        repository
            .put_committed(
                &anchor,
                LogicalPath::new("snapshots/supervisor-live.bin").expect("logical path"),
                Bytes::from_static(b"supervisor-live"),
                RepositoryPutOptions::default(),
            )
            .await
            .expect("live put");

        // An unretained commit whose anchor advance failed is a deletable
        // orphan; live commits above keep provider retention.
        let orphan_writer = V2CommitStore::new(
            store.clone(),
            keyring.clone(),
            commit_store_options(&store, V2ProviderProfile::Dev, None).await,
        );
        let forked = anchor
            .read_v2()
            .await
            .expect("anchor read")
            .expect("anchor state");
        let failed = orphan_writer
            .write_child_commit(
                &FailingAdvanceAnchor {
                    inner: V2MemoryAnchor::with_state(forked),
                },
                V2CommitWrite::delta(vec![V2CommitSection::new(
                    V2SectionType::IndexDelta,
                    0,
                    Bytes::from_static(b"supervisor-orphan"),
                )]),
            )
            .await;
        assert!(matches!(failed, Err(V2FormatError::AnchorAdvanceFailed)));

        let coordinator = Arc::new(
            V2CommitCoordinator::with_options(
                Arc::clone(&repository),
                anchor.clone(),
                CommitCoordinatorOptions::new(1, Duration::ZERO),
            )
            .expect("coordinator")
            .with_maintenance_guard(UnenforcedQuiescedMaintenanceGuard),
        );
        let runtime = Arc::new(LocalMaintenanceRuntime {
            repository: Arc::clone(&repository),
            anchor: anchor.clone(),
            coordinator: Arc::clone(&coordinator),
        });

        let maintenance = MaintenanceConfig {
            mode: MaintenanceMode::Auto,
            renewal_horizon: Duration::from_secs(31 * 24 * 60 * 60),
            orphan_pressure_bytes: u64::MAX,
            orphan_pressure_count: 1,
            orphan_pressure_max_age: Duration::from_secs(365 * 24 * 60 * 60),
            max_interval: Duration::from_secs(60 * 60),
            min_cooldown: Duration::from_secs(1),
            pacing_delay: Some(Duration::from_millis(1)),
            ..MaintenanceConfig::default()
        };
        let handle = MaintenanceSupervisor::start(
            MaintenanceSupervisorConfig {
                maintenance,
                retention_configured: true,
                orphan_gc: V2OrphanGcOptions::new_for_test_rehearsal(Duration::ZERO),
                retained_provider_conformance: Arc::new(|| true),
            },
            runtime,
            Arc::new(SystemMaintenanceClock),
        );
        let status = handle.status();

        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let snapshot = status.snapshot();
                if snapshot
                    .last_run
                    .as_ref()
                    .is_some_and(|run| run.outcome == "ok")
                {
                    return snapshot;
                }
                if let Some(run) = snapshot.last_run.as_ref() {
                    assert_eq!(
                        run.outcome, "ok",
                        "unexpected run outcome: {:?}",
                        run.failure_reason
                    );
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("supervised auto cycle should complete");

        let snapshot = status.snapshot();
        let run = snapshot.last_run.expect("run summary");
        assert_eq!(run.outcome, "ok");
        assert_eq!(run.deleted_object_count, 1, "orphan must be deleted");
        assert!(
            run.renewed_object_count >= 1,
            "live retention must be renewed"
        );
        assert_eq!(snapshot.consecutive_failures, 0);

        let orphans = repository
            .commit_store()
            .report_orphans(&anchor)
            .await
            .expect("post-run orphan report");
        assert_eq!(orphans.candidates.len(), 0, "orphan must be gone");

        // Client writes resume unchanged after the maintenance window.
        coordinator
            .put_committed(
                LogicalPath::new("snapshots/supervisor-after.bin").expect("logical path"),
                Bytes::from_static(b"after-maintenance"),
                RepositoryPutOptions::default(),
            )
            .await
            .expect("post-maintenance write");

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn control_dry_run_then_apply_reclaims_orphans_on_memory_backend() {
        let store = MemoryBlobStore::new();
        let keyring = KeyRing::generate_random().expect("test keyring");
        let options = commit_store_options(&store, V2ProviderProfile::Dev, None).await;
        let repository = Arc::new(V2Repository::new(
            store.clone(),
            keyring.clone(),
            RepositoryOptions::default(),
            options,
        ));
        let anchor = V2MemoryAnchor::new();
        repository
            .write_genesis_snapshot(&anchor)
            .await
            .expect("genesis snapshot");
        repository
            .put_committed(
                &anchor,
                LogicalPath::new("snapshots/control-live.bin").expect("logical path"),
                Bytes::from_static(b"control-live"),
                RepositoryPutOptions::default(),
            )
            .await
            .expect("live put");

        let orphan_writer = V2CommitStore::new(
            store.clone(),
            keyring.clone(),
            commit_store_options(&store, V2ProviderProfile::Dev, None).await,
        );
        let forked = anchor
            .read_v2()
            .await
            .expect("anchor read")
            .expect("anchor state");
        let failed = orphan_writer
            .write_child_commit(
                &FailingAdvanceAnchor {
                    inner: V2MemoryAnchor::with_state(forked),
                },
                V2CommitWrite::delta(vec![V2CommitSection::new(
                    V2SectionType::IndexDelta,
                    0,
                    Bytes::from_static(b"control-orphan"),
                )]),
            )
            .await;
        assert!(matches!(failed, Err(V2FormatError::AnchorAdvanceFailed)));

        let coordinator = Arc::new(
            V2CommitCoordinator::with_options(
                Arc::clone(&repository),
                anchor.clone(),
                CommitCoordinatorOptions::new(1, Duration::ZERO),
            )
            .expect("coordinator")
            .with_maintenance_guard(UnenforcedQuiescedMaintenanceGuard),
        );
        let runtime = Arc::new(LocalMaintenanceRuntime {
            repository: Arc::clone(&repository),
            anchor: anchor.clone(),
            coordinator: Arc::clone(&coordinator),
        });

        let maintenance = MaintenanceConfig {
            mode: MaintenanceMode::Manual,
            ..MaintenanceConfig::default()
        };
        let handle = MaintenanceSupervisor::start(
            MaintenanceSupervisorConfig {
                maintenance,
                retention_configured: false,
                orphan_gc: V2OrphanGcOptions::new_for_test_rehearsal(Duration::ZERO),
                retained_provider_conformance: Arc::new(|| true),
            },
            runtime,
            Arc::new(SystemMaintenanceClock),
        );
        let control = handle.control();

        let dry_run = control
            .dry_run(MaintenanceOperationSource::ManualCli)
            .await
            .expect("dry run should plan against the memory backend");
        assert!(dry_run.report.fits_budgets);
        assert_eq!(dry_run.report.candidate_commit_count, 1);
        assert_eq!(dry_run.plan_digest.len(), 64);

        let record = control
            .apply(&dry_run.plan_digest, MaintenanceOperationSource::ManualCli)
            .await
            .expect("apply should be accepted");
        assert_eq!(record.outcome, Some("ok"), "{:?}", record.failure_reason);
        assert_eq!(record.deleted_object_count, 1);

        let orphans = repository
            .commit_store()
            .report_orphans(&anchor)
            .await
            .expect("post-apply orphan report");
        assert_eq!(orphans.candidates.len(), 0, "orphan must be reclaimed");

        // The reviewed plan is now stale: re-applying the same digest must
        // fail closed inside the window without mutating anything.
        let stale = control
            .apply(&dry_run.plan_digest, MaintenanceOperationSource::ManualCli)
            .await
            .expect("stale apply should resolve with an outcome");
        assert_eq!(stale.outcome, Some("stale-plan"));

        handle.shutdown().await;
    }
}
