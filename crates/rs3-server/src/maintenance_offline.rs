//! Break-glass offline maintenance orchestration.
//!
//! Used when the gateway cannot run. The orchestration core executes
//! fence-acquire, repository open, dry-run or apply, and fence release
//! against the abstract [`OfflineMaintenanceEnvironment`] boundary and the
//! repository maintenance surface. Kubernetes writer-fence construction lives
//! only in the feature-gated CLI wiring; no Kubernetes types appear here.

use crate::maintenance::{MAINTENANCE_PLAN_STALE_REASON, MaintenanceRuntime};
use async_trait::async_trait;
use rs3_repository::RepositoryError;
use rs3_repository::v2::{
    V2FullGcApplyOptions, V2FullGcApplyReport, V2FullGcDryRunOptions, V2FullGcDryRunReport,
    V2MaintenanceCancellation, V2OrphanGcOptions,
};
use std::sync::Arc;
use thiserror::Error;

/// Offline break-glass maintenance operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OfflineMaintenanceCommand {
    /// Fence the repository and run the budgeted read-only plan.
    DryRun,
    /// Fence the repository and apply a previously reviewed plan digest.
    Apply {
        /// Plan digest produced by a prior offline dry run.
        plan_digest: String,
    },
}

/// Inputs for one offline break-glass maintenance invocation.
#[derive(Clone, Debug)]
pub struct OfflineMaintenanceRequest {
    /// Operation to perform once the fence is held.
    pub command: OfflineMaintenanceCommand,
    /// Budgeted dry-run options shared by planning and the apply preflight.
    pub dry_run: V2FullGcDryRunOptions,
    /// Conservative orphan deletion policy for apply.
    pub orphan_gc: V2OrphanGcOptions,
    /// Whether retained-version provider conformance evidence passed.
    pub retained_provider_conformance_passed: bool,
}

/// Result of one offline break-glass maintenance invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfflineMaintenanceOutcome {
    /// Deterministic digest identifying the produced or applied plan.
    pub plan_digest: String,
    /// Budgeted read-only dry-run report backing this outcome.
    pub dry_run: V2FullGcDryRunReport,
    /// Destructive apply report, present for apply invocations only.
    pub apply: Option<V2FullGcApplyReport>,
}

/// Errors from the offline break-glass maintenance path.
#[derive(Debug, Error)]
pub enum OfflineMaintenanceError {
    /// A live writer renewed the fence during takeover observation.
    #[error(
        "a live writer is renewing the writer fence; stop the gateway before \
         offline maintenance: {reason}"
    )]
    LiveWriterPresent {
        /// Path-redacted fence observation detail.
        reason: String,
    },
    /// Exclusive fence ownership could not be established.
    #[error("failed to acquire the offline writer fence: {reason}")]
    FenceUnavailable {
        /// Path-redacted acquisition failure detail.
        reason: String,
    },
    /// The repository could not be opened under the acquired fence.
    #[error("failed to open the repository for offline maintenance: {reason}")]
    OpenFailed {
        /// Path-redacted open failure detail.
        reason: String,
    },
    /// The supplied plan digest is not a 64-character lowercase hex string.
    #[error("offline maintenance plan digest must be 64 lowercase hex characters")]
    InvalidPlanDigest,
    /// The fresh in-window plan no longer matches the reviewed digest.
    #[error("{MAINTENANCE_PLAN_STALE_REASON}")]
    StalePlan,
    /// The dry run or apply failed inside the maintenance window.
    #[error("offline maintenance run failed: {reason}")]
    RunFailed {
        /// Path-redacted run failure detail.
        reason: String,
    },
    /// The fence could not be released during orderly command exit.
    #[error("failed to release the offline writer fence: {reason}")]
    ReleaseFailed {
        /// Path-redacted release failure detail.
        reason: String,
    },
}

/// One acquired exclusive offline maintenance fence.
#[async_trait]
pub trait OfflineMaintenanceFence: Send + Sync {
    /// Releases exclusive ownership during orderly command exit.
    ///
    /// Called on every exit path, including run failures, so a crashed run is
    /// the only way to leave the fence to expire through its lease duration.
    async fn release(&self) -> Result<(), OfflineMaintenanceError>;
}

/// Backend wiring boundary for offline break-glass maintenance.
///
/// Implementations construct the concrete fence and repository runtime. The
/// orchestration core depends only on this trait, [`OfflineMaintenanceFence`],
/// and [`MaintenanceRuntime`], so fence semantics stay testable without any
/// Kubernetes machinery.
#[async_trait]
pub trait OfflineMaintenanceEnvironment: Send + Sync {
    /// Acquires exclusive writer-fence ownership through the anchor backend.
    ///
    /// Must fail closed with [`OfflineMaintenanceError::LiveWriterPresent`]
    /// when a live writer renews the fence, and may take over a dead holder
    /// only after the guard's full monotonic observation window.
    async fn acquire_fence(
        &self,
    ) -> Result<Box<dyn OfflineMaintenanceFence>, OfflineMaintenanceError>;

    /// Opens the repository maintenance surface under the acquired fence.
    async fn open_runtime(&self) -> Result<Arc<dyn MaintenanceRuntime>, OfflineMaintenanceError>;
}

/// Runs one offline break-glass maintenance operation end to end.
///
/// Order: fence acquire, repository open, dry run or digest-verified apply,
/// fence release. The fence is released on every exit path after acquisition;
/// a release failure after a successful run is surfaced so the operator knows
/// the Lease still names this process until it expires.
pub async fn run_offline_maintenance(
    environment: &dyn OfflineMaintenanceEnvironment,
    request: OfflineMaintenanceRequest,
) -> Result<OfflineMaintenanceOutcome, OfflineMaintenanceError> {
    if let OfflineMaintenanceCommand::Apply { plan_digest } = &request.command
        && !is_plan_digest(plan_digest)
    {
        return Err(OfflineMaintenanceError::InvalidPlanDigest);
    }

    let fence = environment.acquire_fence().await?;
    let run = run_fenced(environment, &request).await;
    let release = fence.release().await;
    match run {
        Ok(outcome) => {
            release?;
            Ok(outcome)
        }
        Err(error) => {
            if let Err(release_error) = release {
                tracing::warn!(
                    target: "rs3_server",
                    operation = "offline_maintenance_release",
                    %release_error,
                    "offline maintenance fence release failed after a failed run",
                );
            }
            Err(error)
        }
    }
}

async fn run_fenced(
    environment: &dyn OfflineMaintenanceEnvironment,
    request: &OfflineMaintenanceRequest,
) -> Result<OfflineMaintenanceOutcome, OfflineMaintenanceError> {
    let runtime = environment.open_runtime().await?;
    let apply_options = V2FullGcApplyOptions {
        dry_run: request.dry_run.clone(),
        orphan_gc: request.orphan_gc,
        retained_provider_conformance_passed: request.retained_provider_conformance_passed,
    };
    match &request.command {
        OfflineMaintenanceCommand::DryRun => {
            let preview = runtime
                .preview_full_gc_plan(apply_options)
                .await
                .map_err(run_failed)?;
            Ok(OfflineMaintenanceOutcome {
                plan_digest: preview.plan_digest,
                dry_run: preview.report,
                apply: None,
            })
        }
        OfflineMaintenanceCommand::Apply { plan_digest } => {
            // The engine re-plans inside the exclusion window, fails closed on
            // digest drift, renews retention strictly before deletion, and
            // rechecks the guard and anchor before every mutation.
            let cancellation = V2MaintenanceCancellation::new();
            let report = runtime
                .run_full_maintenance(
                    apply_options,
                    Some(plan_digest),
                    &cancellation,
                    &|_phase| {},
                )
                .await
                .map_err(run_failed)?;
            if let Some(aborted) = report.apply.orphan_gc.aborted.as_ref() {
                return Err(OfflineMaintenanceError::RunFailed {
                    reason: format!("orphan deletion aborted before completion: {aborted}"),
                });
            }
            Ok(OfflineMaintenanceOutcome {
                plan_digest: plan_digest.clone(),
                dry_run: report.dry_run,
                apply: Some(report.apply),
            })
        }
    }
}

fn run_failed(error: RepositoryError) -> OfflineMaintenanceError {
    if matches!(
        &error,
        RepositoryError::CommitFailed { reason } if reason == MAINTENANCE_PLAN_STALE_REASON
    ) {
        return OfflineMaintenanceError::StalePlan;
    }
    OfflineMaintenanceError::RunFailed {
        reason: error.to_string(),
    }
}

fn is_plan_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{
        OfflineMaintenanceCommand, OfflineMaintenanceEnvironment, OfflineMaintenanceError,
        OfflineMaintenanceFence, OfflineMaintenanceRequest, run_offline_maintenance,
    };
    use crate::maintenance::{MaintenanceRunPhase, MaintenanceRuntime};
    use async_trait::async_trait;
    use bytes::Bytes;
    use rs3_crypto::KeyRing;
    use rs3_repository::v2::{
        UnenforcedQuiescedMaintenanceGuard, V2AnchorState, V2CommitAnchor, V2CommitCoordinator,
        V2CommitSection, V2CommitStore, V2CommitStoreOptions, V2CommitWrite, V2FormatError,
        V2FormatRef, V2FullGcApplyOptions, V2FullGcDryRunOptions, V2FullGcPlanPreview,
        V2FullMaintenanceReport, V2KeyringEnvelopeRef, V2KeyringEnvelopeRootRef,
        V2MaintenanceCancellation, V2MaintenanceReport, V2MemoryAnchor, V2OrphanGcOptions,
        V2ProviderProfile, V2Repository, V2Result, V2SectionType,
    };
    use rs3_repository::{
        CommitCoordinatorOptions, RepositoryError, RepositoryOptions, RepositoryPutOptions,
    };
    use rs3_storage::{BlobStore, MemoryBlobStore, PutOptions};
    use rs3_types::{BackendObjectId, LogicalPath, RepositoryId};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    struct RecordingFence {
        releases: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl OfflineMaintenanceFence for RecordingFence {
        async fn release(&self) -> Result<(), OfflineMaintenanceError> {
            self.releases.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct FakeEnvironment {
        runtime: Option<Arc<dyn MaintenanceRuntime>>,
        live_writer: bool,
        releases: Arc<AtomicUsize>,
        opens: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl OfflineMaintenanceEnvironment for FakeEnvironment {
        async fn acquire_fence(
            &self,
        ) -> Result<Box<dyn OfflineMaintenanceFence>, OfflineMaintenanceError> {
            if self.live_writer {
                return Err(OfflineMaintenanceError::LiveWriterPresent {
                    reason: "lease is held by a live writer that renewed during takeover \
                             observation"
                        .to_owned(),
                });
            }
            Ok(Box::new(RecordingFence {
                releases: Arc::clone(&self.releases),
            }))
        }

        async fn open_runtime(
            &self,
        ) -> Result<Arc<dyn MaintenanceRuntime>, OfflineMaintenanceError> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            self.runtime
                .clone()
                .ok_or(OfflineMaintenanceError::OpenFailed {
                    reason: "test environment has no runtime".to_owned(),
                })
        }
    }

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

    struct MemoryOfflineRuntime {
        repository: Arc<V2Repository<MemoryBlobStore>>,
        anchor: V2MemoryAnchor,
        coordinator: Arc<V2CommitCoordinator<MemoryBlobStore, V2MemoryAnchor>>,
    }

    #[async_trait]
    impl MaintenanceRuntime for MemoryOfflineRuntime {
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
            options: V2FullGcDryRunOptions,
        ) -> Result<rs3_repository::v2::V2FullGcDryRunReport, RepositoryError> {
            self.repository.full_gc_dry_run(&self.anchor, options).await
        }

        async fn preview_full_gc_plan(
            &self,
            options: V2FullGcApplyOptions,
        ) -> Result<V2FullGcPlanPreview, RepositoryError> {
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

    async fn commit_store_options(store: &MemoryBlobStore) -> V2CommitStoreOptions {
        let keyring_ref = V2KeyringEnvelopeRef {
            object_id: object_id("keyrings/00000000000000000001-bootstrap"),
            digest: [6_u8; 32],
        };
        let keyring_metadata = store
            .put(
                &keyring_ref.object_id,
                Bytes::from_static(b"encrypted-keyring-envelope"),
                PutOptions::default(),
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
                PutOptions::default(),
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
            V2ProviderProfile::Dev,
            RepositoryId::new("offline-test-repository").expect("repository ID"),
            keyring_ref,
            format_ref,
        )
        .with_maintenance_keyring_envelope_ref(keyring_root)
    }

    /// Memory-backed environment with one reclaimable orphan seeded.
    async fn memory_environment_with_orphan() -> (FakeEnvironment, Arc<MemoryOfflineRuntime>) {
        let store = MemoryBlobStore::new();
        let keyring = KeyRing::generate_random().expect("test keyring");
        let options = commit_store_options(&store).await;
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
                LogicalPath::new("snapshots/offline-live.bin").expect("logical path"),
                Bytes::from_static(b"offline-live"),
                RepositoryPutOptions::default(),
            )
            .await
            .expect("live put");

        let orphan_writer = V2CommitStore::new(
            store.clone(),
            keyring.clone(),
            commit_store_options(&store).await,
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
                    Bytes::from_static(b"offline-orphan"),
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
        let runtime = Arc::new(MemoryOfflineRuntime {
            repository,
            anchor,
            coordinator,
        });
        let environment = FakeEnvironment {
            runtime: Some(Arc::clone(&runtime) as Arc<dyn MaintenanceRuntime>),
            live_writer: false,
            releases: Arc::new(AtomicUsize::new(0)),
            opens: Arc::new(AtomicUsize::new(0)),
        };
        (environment, runtime)
    }

    fn request(command: OfflineMaintenanceCommand) -> OfflineMaintenanceRequest {
        OfflineMaintenanceRequest {
            command,
            dry_run: V2FullGcDryRunOptions::default(),
            orphan_gc: V2OrphanGcOptions::new_for_test_rehearsal(Duration::ZERO),
            retained_provider_conformance_passed: true,
        }
    }

    #[tokio::test]
    async fn offline_dry_run_then_apply_reclaims_orphans_and_releases_the_fence() {
        let (environment, runtime) = memory_environment_with_orphan().await;

        let dry_run =
            run_offline_maintenance(&environment, request(OfflineMaintenanceCommand::DryRun))
                .await
                .expect("offline dry run should plan against the memory backend");
        assert_eq!(dry_run.plan_digest.len(), 64);
        assert_eq!(dry_run.dry_run.candidate_commit_count, 1);
        assert!(dry_run.apply.is_none());
        assert_eq!(environment.releases.load(Ordering::SeqCst), 1);

        let applied = run_offline_maintenance(
            &environment,
            request(OfflineMaintenanceCommand::Apply {
                plan_digest: dry_run.plan_digest.clone(),
            }),
        )
        .await
        .expect("offline apply should be accepted");
        let apply = applied.apply.expect("apply report");
        assert_eq!(apply.orphan_gc.deleted_count, 1);
        assert_eq!(environment.releases.load(Ordering::SeqCst), 2);

        let orphans = runtime
            .repository
            .commit_store()
            .report_orphans(&runtime.anchor)
            .await
            .expect("post-apply orphan report");
        assert_eq!(orphans.candidates.len(), 0, "orphan must be reclaimed");

        // The reviewed plan is now stale: re-applying the same digest fails
        // closed inside the window and still releases the fence.
        let stale = run_offline_maintenance(
            &environment,
            request(OfflineMaintenanceCommand::Apply {
                plan_digest: dry_run.plan_digest,
            }),
        )
        .await;
        assert!(matches!(stale, Err(OfflineMaintenanceError::StalePlan)));
        assert_eq!(environment.releases.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn offline_command_refuses_while_a_live_writer_renews_the_fence() {
        let environment = FakeEnvironment {
            runtime: None,
            live_writer: true,
            releases: Arc::new(AtomicUsize::new(0)),
            opens: Arc::new(AtomicUsize::new(0)),
        };

        let refused =
            run_offline_maintenance(&environment, request(OfflineMaintenanceCommand::DryRun)).await;

        assert!(matches!(
            refused,
            Err(OfflineMaintenanceError::LiveWriterPresent { .. })
        ));
        assert_eq!(
            environment.opens.load(Ordering::SeqCst),
            0,
            "the repository must not be opened without the fence"
        );
        assert_eq!(environment.releases.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn offline_failure_paths_still_release_the_fence() {
        // Open failure after a successful fence acquisition.
        let environment = FakeEnvironment {
            runtime: None,
            live_writer: false,
            releases: Arc::new(AtomicUsize::new(0)),
            opens: Arc::new(AtomicUsize::new(0)),
        };
        let failed =
            run_offline_maintenance(&environment, request(OfflineMaintenanceCommand::DryRun)).await;
        assert!(matches!(
            failed,
            Err(OfflineMaintenanceError::OpenFailed { .. })
        ));
        assert_eq!(environment.releases.load(Ordering::SeqCst), 1);

        // A malformed digest fails before the fence is ever taken.
        let invalid = run_offline_maintenance(
            &environment,
            request(OfflineMaintenanceCommand::Apply {
                plan_digest: "not-a-digest".to_owned(),
            }),
        )
        .await;
        assert!(matches!(
            invalid,
            Err(OfflineMaintenanceError::InvalidPlanDigest)
        ));
        assert_eq!(environment.releases.load(Ordering::SeqCst), 1);
    }
}
