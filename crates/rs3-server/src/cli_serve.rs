//! Serve startup and orderly listener shutdown.

use super::cli_writer_guard::{WriterGuardRuntime, acquire};
use super::{DoctorProfile, GatewayModeArg, log_runtime_config};
use anyhow::Result;
use metrics_exporter_prometheus::PrometheusBuilder;
use rs3_server::{
    AdminBearerToken, AdminHttpAuth, AdminHttpConfig, AdminHttpServer, AdminReportProfile,
    GatewayServer, MaintenanceMode, RuntimeConfig, doctor_findings,
};
use std::net::SocketAddr;
use tokio::sync::watch;

pub(super) async fn run(
    bind: Option<SocketAddr>,
    metrics_bind: Option<SocketAddr>,
    gateway_mode: Option<GatewayModeArg>,
    admin_bind: Option<SocketAddr>,
    admin_bearer_token: Option<String>,
    admin_mutation_bearer_token: Option<String>,
    admin_profile: DoctorProfile,
) -> Result<()> {
    let mut config = RuntimeConfig::from_env_with_mode_override(gateway_mode.map(Into::into))?;
    if let Some(bind) = bind {
        config.bind = bind;
    }
    if let Some(metrics_bind) = metrics_bind {
        config.metrics.bind = Some(metrics_bind);
    }
    config.validate()?;
    let admin_config = admin_http_config(
        admin_bind,
        admin_bearer_token,
        admin_mutation_bearer_token,
        admin_profile,
    )?;
    enforce_serve_profile(&config, admin_profile, admin_config.is_some())?;
    install_metrics(config.metrics.bind)?;
    log_runtime_config(&config);
    let writer_guard = acquire(&config).await?;
    let server = match bind_gateway(config.clone(), &writer_guard).await {
        Ok(server) => server,
        Err(error) => {
            if let Err(release_error) = writer_guard.release().await {
                return Err(anyhow::anyhow!(
                    "failed to bind gateway listener: {error}; writer fence release also failed: {release_error}"
                ));
            }
            return Err(error);
        }
    };
    tracing::info!(bind = %server.local_addr(), "gateway S3 listener started");
    let mut maintenance_supervisor = start_maintenance_supervisor(&config, &server);
    let run_result = match admin_config {
        Some(admin_config) => {
            let admin_runtime_facts = maintenance_aware_facts_source(
                server.admin_runtime_facts_source(),
                maintenance_supervisor.as_ref(),
            );
            let admin_readiness = writer_guard.readiness_source(server.admin_readiness_source());
            let admin_server = AdminHttpServer::bind_with_runtime_sources(
                config,
                admin_config,
                admin_runtime_facts,
                admin_readiness,
            )
            .await;
            let mut admin_server = match admin_server {
                Ok(admin_server) => admin_server,
                Err(error) => {
                    if let Some(supervisor) = maintenance_supervisor.take() {
                        supervisor.shutdown().await;
                    }
                    if let Err(release_error) = writer_guard.release().await {
                        return Err(anyhow::anyhow!(
                            "failed to bind admin listener: {error}; writer fence release also failed: {release_error}"
                        ));
                    }
                    return Err(error.into());
                }
            };
            if let Some(supervisor) = maintenance_supervisor.as_ref() {
                admin_server = admin_server.with_maintenance_control(supervisor.control());
            }
            tracing::info!(
                bind = %admin_server.local_addr(),
                "gateway admin listener started",
            );
            run_gateway_and_admin(server, admin_server, writer_guard.shutdown()).await
        }
        None => server
            .run_until_shutdown(shutdown_signal_or_writer_guard(writer_guard.shutdown()))
            .await
            .map_err(anyhow::Error::from),
    };
    if let Some(maintenance_supervisor) = maintenance_supervisor {
        maintenance_supervisor.shutdown().await;
    }
    let release_result = writer_guard.release().await;
    run_result?;
    release_result?;
    Ok(())
}

pub(super) fn enforce_serve_profile(
    config: &RuntimeConfig,
    profile: DoctorProfile,
    admin_listener_configured: bool,
) -> Result<()> {
    if profile == DoctorProfile::Local {
        tracing::warn!(
            "local serve profile bypasses production posture enforcement; do not expose this listener",
        );
        return Ok(());
    }

    if !admin_listener_configured {
        anyhow::bail!(
            "production serve profile requires RS3_ADMIN_BIND and RS3_ADMIN_BEARER_TOKEN for readiness and operator status",
        );
    }

    let findings = doctor_findings(config, AdminReportProfile::Production);
    for finding in findings.iter().filter(|finding| !finding.is_blocking()) {
        tracing::warn!(
            code = finding.code,
            message = finding.message,
            remediation = finding.remediation,
            "production serve posture warning",
        );
    }
    let findings = findings
        .into_iter()
        .filter(|finding| finding.is_blocking())
        .collect::<Vec<_>>();
    if findings.is_empty() {
        return Ok(());
    }

    let codes = findings
        .iter()
        .map(|finding| finding.code)
        .collect::<Vec<_>>()
        .join(",");
    anyhow::bail!(
        "production serve posture failed ({codes}); run `rs3-server doctor --profile production` for remediation",
    )
}

fn admin_http_config(
    bind: Option<SocketAddr>,
    bearer_token: Option<String>,
    mutation_bearer_token: Option<String>,
    profile: DoctorProfile,
) -> Result<Option<AdminHttpConfig>> {
    let Some(bind) = bind else {
        return Ok(None);
    };
    let Some(bearer_token) = bearer_token else {
        anyhow::bail!("RS3_ADMIN_BEARER_TOKEN is required when RS3_ADMIN_BIND is set");
    };
    let token = AdminBearerToken::new(bearer_token)?;
    // Without a distinct mutation token, the admin listener stays read-only
    // and POST maintenance routes are disabled.
    let auth = match mutation_bearer_token {
        Some(mutation_bearer_token) => {
            let mutation = AdminBearerToken::new(mutation_bearer_token)?;
            AdminHttpAuth::bearer_with_mutation(token, mutation)?
        }
        None => AdminHttpAuth::bearer(token),
    };
    Ok(Some(AdminHttpConfig::new(bind, auth, profile.into())))
}

/// Starts the in-gateway maintenance supervisor for mutation-capable modes.
///
/// Restore-readonly gateways force maintenance off at configuration time, and
/// `RS3_MAINTENANCE_MODE=off` keeps the supervisor from starting at all.
fn start_maintenance_supervisor(
    config: &RuntimeConfig,
    server: &GatewayServer,
) -> Option<rs3_server::MaintenanceSupervisorHandle> {
    if !config.mode.allows_mutation() || config.maintenance.mode == MaintenanceMode::Off {
        return None;
    }
    let conformance_config = config.clone();
    let supervisor_config = rs3_server::MaintenanceSupervisorConfig::from_runtime(
        config.maintenance,
        config.repository.retention.is_some(),
        std::sync::Arc::new(move || {
            rs3_server::provider_conformance_evidence_passed(&conformance_config)
        }),
    );
    let handle = rs3_server::MaintenanceSupervisor::start(
        supervisor_config,
        server.maintenance_runtime(),
        std::sync::Arc::new(rs3_server::SystemMaintenanceClock),
    );
    tracing::info!(
        maintenance_mode = config.maintenance.mode.as_str(),
        "maintenance supervisor started",
    );
    Some(handle)
}

/// Wraps the gateway facts source so admin reports include supervisor status.
fn maintenance_aware_facts_source(
    inner: std::sync::Arc<dyn rs3_server::AdminRuntimeFactsSource>,
    supervisor: Option<&rs3_server::MaintenanceSupervisorHandle>,
) -> std::sync::Arc<dyn rs3_server::AdminRuntimeFactsSource> {
    let Some(supervisor) = supervisor else {
        return inner;
    };
    std::sync::Arc::new(MaintenanceAwareFactsSource {
        inner,
        status: supervisor.status(),
    })
}

struct MaintenanceAwareFactsSource {
    inner: std::sync::Arc<dyn rs3_server::AdminRuntimeFactsSource>,
    status: rs3_server::MaintenanceStatusHandle,
}

impl rs3_server::AdminRuntimeFactsSource for MaintenanceAwareFactsSource {
    fn snapshot(&self) -> rs3_server::AdminRuntimeFacts {
        let mut facts = self.inner.snapshot();
        facts.maintenance_supervisor = Some(rs3_server::AdminMaintenanceSupervisorSummary::from(
            &self.status.snapshot(),
        ));
        facts
    }
}

async fn bind_gateway(
    config: RuntimeConfig,
    _writer_guard: &WriterGuardRuntime,
) -> Result<GatewayServer> {
    #[cfg(feature = "k8s")]
    if let Some(writer_fence) = _writer_guard.writer_fence() {
        return GatewayServer::bind_with_writer_fence(config, writer_fence)
            .await
            .map_err(anyhow::Error::from);
    }
    GatewayServer::bind(config)
        .await
        .map_err(anyhow::Error::from)
}

async fn run_gateway_and_admin(
    gateway: GatewayServer,
    admin: AdminHttpServer,
    writer_guard_shutdown: Option<watch::Receiver<bool>>,
) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let gateway_shutdown = shutdown_rx.clone();
    let admin_shutdown = shutdown_rx;

    if let Some(writer_guard_shutdown) = writer_guard_shutdown {
        let writer_guard_shutdown_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            wait_for_shutdown(writer_guard_shutdown).await;
            let _ = writer_guard_shutdown_tx.send(true);
        });
    }

    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    let gateway_task = async move {
        gateway
            .run_until_shutdown(wait_for_shutdown(gateway_shutdown))
            .await
            .map_err(anyhow::Error::from)
    };
    let admin_task = async move {
        admin
            .run_until_shutdown(wait_for_shutdown(admin_shutdown))
            .await
            .map_err(anyhow::Error::from)
    };

    tokio::try_join!(gateway_task, admin_task)?;
    Ok(())
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            break;
        }
    }
}

async fn shutdown_signal_or_writer_guard(writer_guard_shutdown: Option<watch::Receiver<bool>>) {
    let Some(writer_guard_shutdown) = writer_guard_shutdown else {
        shutdown_signal().await;
        return;
    };
    tokio::select! {
        _ = shutdown_signal() => {}
        _ = wait_for_shutdown(writer_guard_shutdown) => {}
    }
}

fn install_metrics(bind: Option<SocketAddr>) -> Result<()> {
    let Some(bind) = bind else {
        return Ok(());
    };
    PrometheusBuilder::new()
        .with_http_listener(bind)
        .install()?;
    tracing::info!(bind = %bind, "gateway metrics listener started");
    Ok(())
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::warn!(%error, "failed to install Ctrl+C shutdown handler");
    }
}
