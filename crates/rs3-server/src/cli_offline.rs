//! Offline maintenance CLI execution and writer-fence acquisition.

use super::{
    MaintenanceOfflineArgs, MaintenanceOfflineCommand, MaintenanceOutputFormat, log_runtime_config,
};
#[cfg(feature = "k8s")]
use super::{WRITER_LEASE_DURATION, WRITER_LEASE_RENEW_INTERVAL, random_hex};
#[cfg(feature = "k8s")]
use anyhow::Context;
use anyhow::{Result, bail};
#[cfg(feature = "k8s")]
use rs3_k8s::{KubernetesLeaseGuard, LeaseGuardError, LeaseSettings};
use rs3_repository::v3::{
    UnenforcedQuiescedMaintenanceGuard, V3FullGcDryRunOptions, V3FullGcDryRunReport,
};
use rs3_server::{
    AnchorConfig, OfflineMaintenanceEnvironment, OfflineMaintenanceError, OfflineMaintenanceFence,
    OfflineMaintenanceOutcome, OfflineMaintenanceRequest, RuntimeConfig,
    default_maintenance_orphan_gc_options, offline_maintenance_runtime_from_config,
    provider_conformance_evidence_passed, run_offline_maintenance,
};

/// Poll interval while the offline fence observes a held Lease.
#[cfg(feature = "k8s")]
const OFFLINE_FENCE_ACQUIRE_POLL: std::time::Duration = std::time::Duration::from_secs(1);
/// Upper bound on the offline fence takeover observation loop.
#[cfg(feature = "k8s")]
const OFFLINE_FENCE_ACQUIRE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(4 * WRITER_LEASE_DURATION.as_secs());

/// Runs one break-glass offline maintenance subcommand.
pub(super) async fn run(args: MaintenanceOfflineArgs) -> Result<()> {
    let config = RuntimeConfig::from_env()?;
    log_runtime_config(&config);
    if !config.mode.allows_mutation() {
        bail!("offline maintenance requires a mutation-capable gateway mode");
    }

    let command = match &args.command {
        MaintenanceOfflineCommand::DryRun => rs3_server::OfflineMaintenanceCommand::DryRun,
        MaintenanceOfflineCommand::Apply { plan_digest } => {
            rs3_server::OfflineMaintenanceCommand::Apply {
                plan_digest: plan_digest.clone(),
            }
        }
    };
    let request = OfflineMaintenanceRequest {
        command,
        dry_run: V3FullGcDryRunOptions {
            budgets: config.maintenance.budgets(),
            retention_renewal_horizon: config.maintenance.renewal_horizon,
            protected_roots: Vec::new(),
        },
        orphan_gc: default_maintenance_orphan_gc_options(),
        retained_provider_conformance_passed: provider_conformance_evidence_passed(&config),
        reclamation_enabled: config.maintenance.reclamation_enabled,
    };

    let outcome = match &config.anchor {
        AnchorConfig::Memory => {
            // The memory anchor cannot host a real writer fence; RS3_ALLOW_MEMORY_ANCHOR
            // already gated this configuration at parse time.
            tracing::warn!(
                "offline maintenance on the memory anchor uses the unenforced honor-system \
                 guard; development use only",
            );
            let environment = MemoryOfflineMaintenanceEnvironment {
                config: config.clone(),
            };
            run_offline_maintenance(&environment, request).await?
        }
        AnchorConfig::KubernetesLease {
            namespace,
            name,
            field_manager,
        } => {
            #[cfg(feature = "k8s")]
            {
                let hostname = std::env::var("HOSTNAME").context(
                    "offline maintenance needs HOSTNAME to identify this operator process",
                )?;
                // Same holder-identity pattern as the gateway writer guard,
                // with a marker suffix so operators can tell a break-glass
                // holder apart in the Lease.
                let holder_identity = format!("{hostname}/{}/offline-maintenance", random_hex(16)?);
                let lease_guard = KubernetesLeaseGuard::new(
                    LeaseSettings {
                        namespace: namespace.clone(),
                        name: name.clone(),
                        field_manager: field_manager.clone(),
                    },
                    holder_identity,
                    WRITER_LEASE_DURATION,
                )
                .context("failed to configure offline writer lease guard")?;
                let environment = KubernetesOfflineMaintenanceEnvironment {
                    config: config.clone(),
                    lease_guard: std::sync::Arc::new(lease_guard),
                };
                run_offline_maintenance(&environment, request).await?
            }
            #[cfg(not(feature = "k8s"))]
            {
                let _ = (namespace, name, field_manager);
                bail!("offline maintenance on a kubernetes-lease anchor requires the k8s feature");
            }
        }
    };

    print_offline_maintenance_outcome(&outcome, args.format)
}

/// Offline environment for the development memory anchor.
struct MemoryOfflineMaintenanceEnvironment {
    config: RuntimeConfig,
}

/// No-op fence used with the memory anchor; there is nothing to release.
struct MemoryOfflineFence;

#[async_trait::async_trait]
impl OfflineMaintenanceFence for MemoryOfflineFence {
    async fn release(&self) -> Result<(), OfflineMaintenanceError> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl OfflineMaintenanceEnvironment for MemoryOfflineMaintenanceEnvironment {
    async fn acquire_fence(
        &self,
    ) -> Result<Box<dyn OfflineMaintenanceFence>, OfflineMaintenanceError> {
        Ok(Box::new(MemoryOfflineFence))
    }

    async fn open_runtime(
        &self,
    ) -> Result<std::sync::Arc<dyn rs3_server::MaintenanceRuntime>, OfflineMaintenanceError> {
        offline_maintenance_runtime_from_config(
            &self.config,
            std::sync::Arc::new(UnenforcedQuiescedMaintenanceGuard),
        )
        .await
        .map_err(|error| OfflineMaintenanceError::OpenFailed {
            reason: error.to_string(),
        })
    }
}

/// Offline environment fenced through the Kubernetes anchor Lease.
#[cfg(feature = "k8s")]
struct KubernetesOfflineMaintenanceEnvironment {
    config: RuntimeConfig,
    lease_guard: std::sync::Arc<KubernetesLeaseGuard>,
}

#[cfg(feature = "k8s")]
struct KubernetesOfflineFence {
    lease_guard: std::sync::Arc<KubernetesLeaseGuard>,
    renew_task: tokio::task::JoinHandle<()>,
}

#[cfg(feature = "k8s")]
#[async_trait::async_trait]
impl OfflineMaintenanceFence for KubernetesOfflineFence {
    async fn release(&self) -> Result<(), OfflineMaintenanceError> {
        self.renew_task.abort();
        self.lease_guard
            .release()
            .await
            .map_err(|error| OfflineMaintenanceError::ReleaseFailed {
                reason: error.to_string(),
            })
    }
}

#[cfg(feature = "k8s")]
#[async_trait::async_trait]
impl OfflineMaintenanceEnvironment for KubernetesOfflineMaintenanceEnvironment {
    async fn acquire_fence(
        &self,
    ) -> Result<Box<dyn OfflineMaintenanceFence>, OfflineMaintenanceError> {
        let deadline = std::time::Instant::now() + OFFLINE_FENCE_ACQUIRE_TIMEOUT;
        loop {
            match self.lease_guard.try_acquire().await {
                Ok(_state) => break,
                Err(LeaseGuardError::HeldByOther) => {
                    // An unchanged holder is still under monotonic takeover
                    // observation; keep watching for the full lease duration.
                    if std::time::Instant::now() >= deadline {
                        return Err(OfflineMaintenanceError::FenceUnavailable {
                            reason: "writer fence takeover observation did not resolve in time"
                                .to_owned(),
                        });
                    }
                    tokio::time::sleep(OFFLINE_FENCE_ACQUIRE_POLL).await;
                }
                Err(error @ LeaseGuardError::HeldByLiveWriter) => {
                    return Err(OfflineMaintenanceError::LiveWriterPresent {
                        reason: error.to_string(),
                    });
                }
                Err(error) => {
                    return Err(OfflineMaintenanceError::FenceUnavailable {
                        reason: error.to_string(),
                    });
                }
            }
        }
        tracing::info!("offline maintenance writer fence acquired");
        let renew_task = tokio::spawn(renew_offline_writer_fence(std::sync::Arc::clone(
            &self.lease_guard,
        )));
        Ok(Box::new(KubernetesOfflineFence {
            lease_guard: std::sync::Arc::clone(&self.lease_guard),
            renew_task,
        }))
    }

    async fn open_runtime(
        &self,
    ) -> Result<std::sync::Arc<dyn rs3_server::MaintenanceRuntime>, OfflineMaintenanceError> {
        let writer_fence = self.lease_guard.writer_fence().map_err(|error| {
            OfflineMaintenanceError::OpenFailed {
                reason: error.to_string(),
            }
        })?;
        rs3_server::offline_maintenance_runtime_from_writer_fence(&self.config, writer_fence)
            .await
            .map_err(|error| OfflineMaintenanceError::OpenFailed {
                reason: error.to_string(),
            })
    }
}

/// Renews the offline writer fence until release or loss of ownership.
///
/// On loss of ownership the local fence goes dead and the engine's
/// per-mutation guard and anchor rechecks fail closed at the next boundary.
#[cfg(feature = "k8s")]
async fn renew_offline_writer_fence(lease_guard: std::sync::Arc<KubernetesLeaseGuard>) {
    loop {
        tokio::time::sleep(WRITER_LEASE_RENEW_INTERVAL).await;
        if let Err(error) = lease_guard.renew().await {
            tracing::warn!(%error, "offline maintenance writer fence renewal failed");
            if matches!(
                error,
                LeaseGuardError::HeldByOther
                    | LeaseGuardError::HeldByLiveWriter
                    | LeaseGuardError::LostLease
            ) {
                break;
            }
        }
    }
}

/// Prints one offline maintenance outcome in the selected format.
fn print_offline_maintenance_outcome(
    outcome: &OfflineMaintenanceOutcome,
    format: MaintenanceOutputFormat,
) -> Result<()> {
    match format {
        MaintenanceOutputFormat::Json => {
            let apply = outcome.apply.as_ref().map(|apply| {
                serde_json::json!({
                    "retention_renewed_object_count": apply.retention_renewed_object_count,
                    "retention_renewed_bytes": apply.retention_renewed_bytes,
                    "deleted_object_count": apply.orphan_gc.deleted_count,
                    "protected_object_count": apply.orphan_gc.protected_count,
                    "failed_delete_count": apply.orphan_gc.failed_delete_count,
                })
            });
            let report = serde_json::json!({
                "schema": "rs3.maintenance-offline.v1",
                "command": if outcome.apply.is_some() { "apply" } else { "dry-run" },
                "plan_digest": outcome.plan_digest,
                "report": offline_dry_run_report_json(&outcome.dry_run),
                "apply": apply,
            });
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        MaintenanceOutputFormat::Text => {
            println!("plan digest: {}", outcome.plan_digest);
            println!("fits budgets: {}", outcome.dry_run.fits_budgets);
            println!(
                "reclaimable dead bytes: {}",
                outcome.dry_run.dead_bytes_reclaimable
            );
            println!(
                "renewal targets: {} objects / {} bytes",
                outcome.dry_run.retention_renewal_commit_count,
                outcome.dry_run.retention_renewal_bytes
            );
            if let Some(apply) = outcome.apply.as_ref() {
                println!(
                    "renewed: {} objects / {} bytes",
                    apply.retention_renewed_object_count, apply.retention_renewed_bytes
                );
                println!("deleted orphans: {}", apply.orphan_gc.deleted_count);
                println!("protected orphans: {}", apply.orphan_gc.protected_count);
            }
        }
    }
    Ok(())
}

/// Path-redacted JSON view of one dry-run report, matching the admin schema.
fn offline_dry_run_report_json(report: &V3FullGcDryRunReport) -> serde_json::Value {
    serde_json::json!({
        "base_sequence": report.base_sequence.map(|sequence| sequence.get()),
        "chain_live_commit_count": report.chain_live_commit_count,
        "candidate_commit_count": report.candidate_commit_count,
        "fully_dead_commit_count": report.fully_dead_commit_count,
        "mixed_commit_count": report.mixed_commit_count,
        "dead_bytes_reclaimable": report.dead_bytes_reclaimable,
        "retention_blocked_bytes": report.retention_blocked_bytes,
        "legal_hold_blocked_bytes": report.legal_hold_blocked_bytes,
        "unknown_protection_blocked_bytes": report.unknown_protection_blocked_bytes,
        "retention_renewal_commit_count": report.retention_renewal_commit_count,
        "retention_renewal_bytes": report.retention_renewal_bytes,
        "retention_renewal_blocked_count": report.retention_renewal_blocked_count,
        "retention_renewal_blocked_bytes": report.retention_renewal_blocked_bytes,
        "fits_budgets": report.fits_budgets,
        "exact_version_apply_ready": report.exact_version_apply_ready,
    })
}
