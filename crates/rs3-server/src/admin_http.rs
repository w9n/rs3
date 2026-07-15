//! Authenticated HTTP listener for path-redacted gateway admin facts.

use crate::admin::{
    admin_maintenance_summary, admin_status_report_with_runtime_facts_and_maintenance,
};
use crate::maintenance::{
    MaintenanceControlError, MaintenanceControlHandle, MaintenanceOperationRecord,
    MaintenanceOperationSource,
};
use crate::{
    AdminMaintenanceSummary, AdminMaintenanceSupervisorSummary, AdminReadinessSource,
    AdminReportProfile, AdminRuntimeFacts, AdminRuntimeFactsSource, RuntimeConfig,
    admin_posture_report_with_runtime_facts,
};
use bytes::Bytes;
use http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, WWW_AUTHENTICATE};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Body;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as ConnectionBuilder;
use hyper_util::server::graceful::GracefulShutdown;
use rs3_crypto::ct_eq;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use serde_json::json;
use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};

const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(not(test))]
const HTTP_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
const HTTP_HEADER_READ_TIMEOUT: Duration = Duration::from_millis(20);
const ADMIN_CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const ADMIN_REQUEST_BODY_READ_TIMEOUT: Duration = Duration::from_secs(10);
const MAINTENANCE_SUMMARY_TTL: Duration = Duration::from_secs(60);
const MAX_ADMIN_CONNECTIONS: usize = 64;
const ADMIN_REALM: &str = "Bearer realm=\"rs3-admin\"";
const ADMIN_MAINTENANCE_SCHEMA: &str = "rs3.admin-maintenance.preview.v1";
const ADMIN_MAINTENANCE_DRY_RUN_SCHEMA: &str = "rs3.admin-maintenance-dry-run.preview.v1";
const ADMIN_MAINTENANCE_OPERATION_SCHEMA: &str = "rs3.admin-maintenance-operation.preview.v1";
/// Header a caller may set to identify itself as the rs3 CLI in audit logs.
const ADMIN_SOURCE_HEADER: &str = "x-rs3-admin-source";
/// Maximum accepted JSON body size for admin mutation requests.
const MAX_ADMIN_REQUEST_BODY_BYTES: usize = 4 * 1024;

/// Redacted bearer token for the gateway admin listener.
#[derive(Clone)]
pub struct AdminBearerToken(SecretString);

impl AdminBearerToken {
    /// Creates a validated admin bearer token.
    ///
    /// # Errors
    ///
    /// Returns an error when the token is too short or contains whitespace or
    /// control characters.
    pub fn new(value: impl Into<String>) -> Result<Self, AdminHttpAuthError> {
        let value = value.into();
        if value.len() < 16 {
            return Err(AdminHttpAuthError::TokenTooShort);
        }
        if value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(AdminHttpAuthError::TokenHasInvalidCharacters);
        }

        Ok(Self(SecretString::from(value)))
    }

    fn matches_presented(&self, presented: &str) -> bool {
        ct_eq(self.0.expose_secret().as_bytes(), presented.as_bytes())
    }
}

impl fmt::Debug for AdminBearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdminBearerToken([redacted])")
    }
}

impl PartialEq for AdminBearerToken {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(
            self.0.expose_secret().as_bytes(),
            other.0.expose_secret().as_bytes(),
        )
    }
}

impl Eq for AdminBearerToken {}

/// Access level granted to one authenticated admin request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdminAccessLevel {
    /// Read-only access: GET routes only.
    Read,
    /// Mutation access: GET and POST routes.
    Mutate,
}

/// Authentication mode for gateway admin HTTP routes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminHttpAuth {
    /// Read-only bearer-token authentication; POST routes stay disabled.
    Bearer(AdminBearerToken),
    /// Separate read and mutation bearer tokens.
    ///
    /// The read token grants GET routes only; the mutation token grants GET
    /// and POST routes. The two token values must be distinct.
    BearerWithMutation {
        /// Read-only bearer token.
        read: AdminBearerToken,
        /// Mutation bearer token.
        mutation: AdminBearerToken,
    },
}

impl AdminHttpAuth {
    /// Builds bearer-token admin authentication without mutation access.
    pub fn bearer(token: AdminBearerToken) -> Self {
        Self::Bearer(token)
    }

    /// Builds admin authentication with a separate mutation bearer token.
    ///
    /// # Errors
    ///
    /// Returns an error when the mutation token equals the read token; the
    /// mutation grant must not be obtainable from the read credential.
    pub fn bearer_with_mutation(
        read: AdminBearerToken,
        mutation: AdminBearerToken,
    ) -> Result<Self, AdminHttpAuthError> {
        if read == mutation {
            return Err(AdminHttpAuthError::MutationTokenNotDistinct);
        }
        Ok(Self::BearerWithMutation { read, mutation })
    }

    /// Returns whether a mutation token is configured.
    fn mutation_configured(&self) -> bool {
        matches!(self, Self::BearerWithMutation { .. })
    }

    fn access_level(&self, headers: &HeaderMap) -> Option<AdminAccessLevel> {
        let presented = presented_bearer_token(headers)?;
        match self {
            Self::Bearer(token) => token
                .matches_presented(presented)
                .then_some(AdminAccessLevel::Read),
            Self::BearerWithMutation { read, mutation } => {
                // Evaluate both constant-time comparisons unconditionally so
                // the grant decision does not shortcut on the first match.
                let is_read = read.matches_presented(presented);
                let is_mutation = mutation.matches_presented(presented);
                if is_mutation {
                    Some(AdminAccessLevel::Mutate)
                } else if is_read {
                    Some(AdminAccessLevel::Read)
                } else {
                    None
                }
            }
        }
    }
}

/// Admin HTTP authentication configuration errors.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AdminHttpAuthError {
    /// Bearer token is too short.
    #[error("admin bearer token must be at least 16 bytes")]
    TokenTooShort,
    /// Bearer token contains whitespace or control characters.
    #[error("admin bearer token must not contain whitespace or control characters")]
    TokenHasInvalidCharacters,
    /// Mutation bearer token equals the read bearer token.
    #[error("admin mutation bearer token must differ from the read bearer token")]
    MutationTokenNotDistinct,
}

/// Gateway admin listener configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminHttpConfig {
    /// Socket address for the admin listener.
    pub bind: SocketAddr,
    /// Authentication required for admin routes.
    pub auth: AdminHttpAuth,
    /// Status report profile returned by `/admin/status`.
    pub profile: AdminReportProfile,
}

impl AdminHttpConfig {
    /// Creates admin listener configuration.
    pub fn new(bind: SocketAddr, auth: AdminHttpAuth, profile: AdminReportProfile) -> Self {
        Self {
            bind,
            auth,
            profile,
        }
    }
}

/// Hyper-compatible service for gateway admin facts.
#[derive(Clone)]
pub struct AdminHttpService {
    config: RuntimeConfig,
    auth: AdminHttpAuth,
    profile: AdminReportProfile,
    runtime_facts: Option<Arc<dyn AdminRuntimeFactsSource>>,
    readiness: Option<Arc<dyn AdminReadinessSource>>,
    maintenance_control: Option<MaintenanceControlHandle>,
    process_started_at_ms: i64,
    maintenance_cache: Arc<Mutex<Option<AdminMaintenanceSummary>>>,
}

impl AdminHttpService {
    /// Creates an admin service from validated gateway runtime configuration.
    pub fn new(config: RuntimeConfig, auth: AdminHttpAuth, profile: AdminReportProfile) -> Self {
        Self {
            config,
            auth,
            profile,
            runtime_facts: None,
            readiness: None,
            maintenance_control: None,
            process_started_at_ms: current_time_ms(),
            maintenance_cache: Arc::new(Mutex::new(None)),
        }
    }

    /// Creates an admin service with live runtime facts attached to reports.
    pub fn new_with_runtime_sources(
        config: RuntimeConfig,
        auth: AdminHttpAuth,
        profile: AdminReportProfile,
        runtime_facts: Arc<dyn AdminRuntimeFactsSource>,
        readiness: Arc<dyn AdminReadinessSource>,
    ) -> Self {
        Self {
            config,
            auth,
            profile,
            runtime_facts: Some(runtime_facts),
            readiness: Some(readiness),
            maintenance_control: None,
            process_started_at_ms: current_time_ms(),
            maintenance_cache: Arc::new(Mutex::new(None)),
        }
    }

    /// Attaches the live maintenance supervisor control handle.
    ///
    /// Without a control handle, `GET /admin/maintenance` reports the
    /// supervisor as unavailable and mutation routes return 503.
    #[must_use]
    pub fn with_maintenance_control(mut self, control: MaintenanceControlHandle) -> Self {
        self.maintenance_control = Some(control);
        self
    }

    /// Handles one admin HTTP request.
    ///
    /// Mutation routes run inline: `POST /admin/maintenance/dry-run` executes
    /// the budgeted read-only plan and returns it directly, and
    /// `POST /admin/maintenance/apply` waits for the queued run to finish so
    /// digest staleness surfaces as a synchronous conflict response.
    pub async fn handle<B>(&self, request: Request<B>) -> Response<Full<Bytes>>
    where
        B: Body,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let (parts, body) = request.into_parts();

        if parts.method == Method::GET && parts.uri.path() == "/healthz" {
            return json_response(StatusCode::OK, json!({ "status": "ok" }));
        }

        if parts.method == Method::GET && parts.uri.path() == "/readyz" {
            let readiness = match self.readiness.as_ref() {
                Some(source) => source.check_readiness().await,
                None => crate::AdminReadiness::unavailable("readiness.source-unavailable"),
            };
            let status = if readiness.ready {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            return json_response(
                status,
                json!({
                    "status": if readiness.ready { "ready" } else { "not-ready" },
                    "reason_code": readiness.reason_code,
                }),
            );
        }

        let Some(access) = self.auth.access_level(&parts.headers) else {
            return unauthorized_response();
        };

        match (parts.method, parts.uri.path()) {
            (Method::GET, "/admin/posture") => {
                let runtime_facts = self.runtime_facts();
                let report = admin_posture_report_with_runtime_facts(
                    &self.config,
                    self.profile,
                    &runtime_facts,
                );
                json_response(StatusCode::OK, report)
            }
            (Method::GET, "/admin/status") => {
                let runtime_facts = self.runtime_facts();
                let maintenance = self.cached_maintenance_summary().await;
                let report = admin_status_report_with_runtime_facts_and_maintenance(
                    &self.config,
                    self.profile,
                    &runtime_facts,
                    maintenance,
                )
                .await;
                json_response(StatusCode::OK, report)
            }
            (Method::GET, "/admin/maintenance") => self.maintenance_report(),
            (Method::POST, path) if path.starts_with("/admin/maintenance/") => {
                if let Some(rejection) = self.mutation_rejection(access) {
                    return rejection;
                }
                self.handle_maintenance_mutation(path, &parts.headers, body)
                    .await
            }
            (Method::GET, _) => json_response(
                StatusCode::NOT_FOUND,
                json!({ "error": { "code": "not-found", "message": "admin route not found" } }),
            ),
            _ => json_response(
                StatusCode::METHOD_NOT_ALLOWED,
                json!({ "error": { "code": "method-not-allowed", "message": "admin route method is not allowed" } }),
            ),
        }
    }

    fn runtime_facts(&self) -> AdminRuntimeFacts {
        let mut facts = self
            .runtime_facts
            .as_ref()
            .map_or_else(AdminRuntimeFacts::default, |source| source.snapshot());
        if facts.process_started_at_ms.is_none() {
            facts.process_started_at_ms = Some(self.process_started_at_ms);
        }
        facts
    }

    async fn cached_maintenance_summary(&self) -> AdminMaintenanceSummary {
        let now_ms = current_time_ms();
        let mut cache = self.maintenance_cache.lock().await;
        if let Some(summary) = cache.as_ref()
            && maintenance_summary_is_fresh(summary.computed_at_ms, now_ms)
        {
            return summary.clone();
        }
        let summary = admin_maintenance_summary(&self.config).await;
        *cache = Some(summary.clone());
        summary
    }

    /// Returns the rejection response when the request may not mutate.
    fn mutation_rejection(&self, access: AdminAccessLevel) -> Option<Response<Full<Bytes>>> {
        if !self.auth.mutation_configured() {
            return Some(json_response(
                StatusCode::FORBIDDEN,
                json!({
                    "error": {
                        "code": "mutation-not-configured",
                        "message": "admin mutation bearer token is not configured; POST maintenance routes are disabled",
                    },
                }),
            ));
        }
        if access != AdminAccessLevel::Mutate {
            return Some(json_response(
                StatusCode::FORBIDDEN,
                json!({
                    "error": {
                        "code": "mutation-token-required",
                        "message": "admin mutation routes require the mutation bearer token",
                    },
                }),
            ));
        }
        None
    }

    /// Builds the path-redacted `GET /admin/maintenance` report.
    fn maintenance_report(&self) -> Response<Full<Bytes>> {
        let snapshot = self
            .maintenance_control
            .as_ref()
            .map(MaintenanceControlHandle::status_snapshot);
        let maintenance = &self.config.maintenance;
        let mutation_enabled = self.auth.mutation_configured() && snapshot.is_some();
        let mut notes: Vec<&'static str> = Vec::new();
        if !self.auth.mutation_configured() {
            notes.push(
                "admin mutation bearer token is not configured; POST maintenance routes are disabled",
            );
        }
        if snapshot.is_none() {
            notes.push("maintenance supervisor is not running on this gateway");
        }
        let supervisor = snapshot
            .as_ref()
            .map(AdminMaintenanceSupervisorSummary::from);
        let next_trigger = snapshot.as_ref().and_then(|snapshot| {
            snapshot.next_trigger_at_ms.map(|at_ms| {
                json!({
                    "at_ms": at_ms,
                    "reason": snapshot.next_trigger_reason,
                })
            })
        });
        let operations = snapshot
            .map(|snapshot| snapshot.operations)
            .unwrap_or_default();

        json_response(
            StatusCode::OK,
            json!({
                "schema": ADMIN_MAINTENANCE_SCHEMA,
                "generated_at_ms": current_time_ms(),
                "mutation_enabled": mutation_enabled,
                "notes": notes,
                "config": {
                    "mode": maintenance.mode.as_str(),
                    "renewal_horizon_seconds": maintenance.renewal_horizon.as_secs(),
                    "orphan_pressure_bytes": maintenance.orphan_pressure_bytes,
                    "orphan_pressure_count": maintenance.orphan_pressure_count,
                    "orphan_pressure_max_age_seconds": maintenance.orphan_pressure_max_age.as_secs(),
                    "max_interval_seconds": maintenance.max_interval.as_secs(),
                    "min_cooldown_seconds": maintenance.min_cooldown.as_secs(),
                    "pacing_delay_ms": maintenance
                        .pacing_delay
                        .map(|delay| u64::try_from(delay.as_millis()).unwrap_or(u64::MAX)),
                    "max_inventory_pages": maintenance.max_inventory_pages,
                    "max_inventory_items": maintenance.max_inventory_items,
                },
                "supervisor": supervisor,
                "next_trigger": next_trigger,
                "operations": operations,
            }),
        )
    }

    async fn handle_maintenance_mutation<B>(
        &self,
        path: &str,
        headers: &HeaderMap,
        body: B,
    ) -> Response<Full<Bytes>>
    where
        B: Body,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let kind = match path {
            "/admin/maintenance/dry-run" => "dry-run",
            "/admin/maintenance/apply" => "apply",
            "/admin/maintenance/cancel" => "cancel",
            "/admin/maintenance/pause" => "pause",
            "/admin/maintenance/resume" => "resume",
            _ => {
                return json_response(
                    StatusCode::NOT_FOUND,
                    json!({ "error": { "code": "not-found", "message": "admin route not found" } }),
                );
            }
        };
        let source = presented_operation_source(headers);
        let Some(control) = self.maintenance_control.clone() else {
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({
                    "error": {
                        "code": "maintenance-supervisor-unavailable",
                        "message": "maintenance supervisor is not running on this gateway",
                    },
                }),
            );
        };
        tracing::info!(
            target: "rs3_server",
            operation = "admin_maintenance_mutation",
            kind,
            source = source.as_str(),
            "admin maintenance mutation received",
        );
        let started = std::time::Instant::now();
        let response = match kind {
            "dry-run" => self.maintenance_dry_run(&control, source).await,
            "apply" => self.maintenance_apply(&control, source, body).await,
            "cancel" => match control.cancel(source) {
                Ok(record) => operation_response(StatusCode::OK, &record),
                Err(error) => control_error_response(&error),
            },
            "pause" => operation_response(StatusCode::OK, &control.pause(source)),
            _ => operation_response(StatusCode::OK, &control.resume(source)),
        };
        tracing::info!(
            target: "rs3_server",
            operation = "admin_maintenance_mutation_finished",
            kind,
            source = source.as_str(),
            result = response.status().as_u16(),
            duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "admin maintenance mutation finished",
        );
        response
    }

    async fn maintenance_dry_run(
        &self,
        control: &MaintenanceControlHandle,
        source: MaintenanceOperationSource,
    ) -> Response<Full<Bytes>> {
        match control.dry_run(source).await {
            Ok(outcome) => {
                let report = &outcome.report;
                audit_operation_result(
                    "dry-run",
                    source,
                    &outcome.operation_id,
                    "ok",
                    Some(&outcome.plan_digest),
                    None,
                );
                json_response(
                    StatusCode::OK,
                    json!({
                        "schema": ADMIN_MAINTENANCE_DRY_RUN_SCHEMA,
                        "operation_id": outcome.operation_id,
                        "plan_digest": outcome.plan_digest,
                        "report": {
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
                        },
                    }),
                )
            }
            Err(error) => control_error_response(&error),
        }
    }

    async fn maintenance_apply<B>(
        &self,
        control: &MaintenanceControlHandle,
        source: MaintenanceOperationSource,
        body: B,
    ) -> Response<Full<Bytes>>
    where
        B: Body,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let Ok(bytes) = read_limited_body(body).await else {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({
                    "error": {
                        "code": "invalid-request-body",
                        "message": "apply request body must be JSON no larger than the admin body limit",
                    },
                }),
            );
        };
        let Ok(request) = serde_json::from_slice::<MaintenanceApplyRequest>(&bytes) else {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({
                    "error": {
                        "code": "invalid-request-body",
                        "message": "apply request body must be a JSON object with a plan_digest field",
                    },
                }),
            );
        };
        match control.apply(&request.plan_digest, source).await {
            Ok(record) => {
                audit_operation_result(
                    "apply",
                    source,
                    &record.id,
                    record.outcome.unwrap_or("unknown"),
                    record.plan_digest.as_deref(),
                    Some(&record),
                );
                match record.outcome {
                    Some("ok") => operation_response(StatusCode::OK, &record),
                    Some("stale-plan") => conflict_response(
                        "plan-digest-stale",
                        "repository state moved since the dry run; run a fresh dry run",
                        &record,
                    ),
                    Some("cancelled") => conflict_response(
                        "maintenance-cancelled",
                        "the maintenance run was cancelled at a mutation boundary",
                        &record,
                    ),
                    Some("rejected") => conflict_response(
                        "maintenance-parked",
                        "the maintenance supervisor rejected the run",
                        &record,
                    ),
                    _ => operation_response(StatusCode::INTERNAL_SERVER_ERROR, &record),
                }
            }
            Err(error) => control_error_response(&error),
        }
    }
}

/// Bound gateway admin HTTP server.
pub struct AdminHttpServer {
    service: AdminHttpService,
    listener: TcpListener,
    local_addr: SocketAddr,
}

impl AdminHttpServer {
    /// Binds the gateway admin listener.
    ///
    /// # Errors
    ///
    /// Returns an error when the listener cannot be bound or its local address
    /// cannot be read.
    pub async fn bind(
        config: RuntimeConfig,
        admin_config: AdminHttpConfig,
    ) -> Result<Self, AdminHttpServerError> {
        Self::bind_inner(config, admin_config, None, None).await
    }

    /// Binds the gateway admin listener with live runtime facts attached to reports.
    ///
    /// # Errors
    ///
    /// Returns an error when the listener cannot be bound or its local address
    /// cannot be read.
    pub async fn bind_with_runtime_sources(
        config: RuntimeConfig,
        admin_config: AdminHttpConfig,
        runtime_facts: Arc<dyn AdminRuntimeFactsSource>,
        readiness: Arc<dyn AdminReadinessSource>,
    ) -> Result<Self, AdminHttpServerError> {
        Self::bind_inner(config, admin_config, Some(runtime_facts), Some(readiness)).await
    }

    async fn bind_inner(
        config: RuntimeConfig,
        admin_config: AdminHttpConfig,
        runtime_facts: Option<Arc<dyn AdminRuntimeFactsSource>>,
        readiness: Option<Arc<dyn AdminReadinessSource>>,
    ) -> Result<Self, AdminHttpServerError> {
        let listener = TcpListener::bind(admin_config.bind)
            .await
            .map_err(|source| AdminHttpServerError::Bind {
                bind: admin_config.bind,
                source,
            })?;
        let local_addr = listener
            .local_addr()
            .map_err(AdminHttpServerError::LocalAddr)?;
        let service = match (runtime_facts, readiness) {
            (Some(runtime_facts), Some(readiness)) => AdminHttpService::new_with_runtime_sources(
                config,
                admin_config.auth,
                admin_config.profile,
                runtime_facts,
                readiness,
            ),
            _ => AdminHttpService::new(config, admin_config.auth, admin_config.profile),
        };

        Ok(Self {
            service,
            listener,
            local_addr,
        })
    }

    /// Returns the address actually bound by the listener.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Attaches the live maintenance supervisor control handle.
    #[must_use]
    pub fn with_maintenance_control(mut self, control: MaintenanceControlHandle) -> Self {
        self.service = self.service.with_maintenance_control(control);
        self
    }

    /// Serves admin connections until the provided shutdown future resolves.
    ///
    /// # Errors
    ///
    /// Returns an error when accepting a connection fails or graceful shutdown
    /// does not finish before the timeout.
    pub async fn run_until_shutdown<F>(self, shutdown: F) -> Result<(), AdminHttpServerError>
    where
        F: Future<Output = ()>,
    {
        let Self {
            service, listener, ..
        } = self;
        let graceful = GracefulShutdown::new();
        let mut shutdown = std::pin::pin!(shutdown);
        let connection_slots = Arc::new(Semaphore::new(MAX_ADMIN_CONNECTIONS));

        loop {
            let (stream, remote_addr) = tokio::select! {
                result = listener.accept() => {
                    result.map_err(AdminHttpServerError::Accept)?
                }
                () = shutdown.as_mut() => {
                    break;
                }
            };

            let connection_permit = match connection_slots.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_error) => {
                    tracing::debug!(
                        %remote_addr,
                        "admin HTTP connection rejected by connection limit",
                    );
                    continue;
                }
            };
            let service = service.clone();
            let connection_watcher = graceful.watcher();

            tokio::spawn(async move {
                let _connection_permit = connection_permit;
                if !wait_for_first_client_byte(&stream, remote_addr).await {
                    return;
                }
                let mut connection_builder = ConnectionBuilder::new(TokioExecutor::new());
                connection_builder
                    .http1()
                    .timer(TokioTimer::new())
                    .header_read_timeout(HTTP_HEADER_READ_TIMEOUT);
                let activity = Arc::new(AdminConnectionActivity::default());
                let connection_activity = Arc::clone(&activity);
                let connection = connection_builder.serve_connection(
                    TokioIo::new(stream),
                    service_fn(move |request| {
                        let service = service.clone();
                        let active_request = connection_activity.start_request();
                        async move {
                            let response = service.handle(request).await;
                            drop(active_request);
                            Ok::<_, Infallible>(response)
                        }
                    }),
                );
                let mut connection =
                    std::pin::pin!(connection_watcher.watch(connection.into_owned()));
                let idle_timeout = tokio::time::sleep(ADMIN_CONNECTION_IDLE_TIMEOUT);
                tokio::pin!(idle_timeout);
                loop {
                    tokio::select! {
                        result = connection.as_mut() => {
                            if let Err(error) = result {
                                tracing::debug!(
                                    %remote_addr,
                                    %error,
                                    "admin HTTP connection ended with error",
                                );
                            }
                            break;
                        }
                        () = activity.changed() => {
                            if !activity.has_active_requests() {
                                idle_timeout.as_mut().reset(
                                    tokio::time::Instant::now() + ADMIN_CONNECTION_IDLE_TIMEOUT,
                                );
                            }
                        }
                        () = idle_timeout.as_mut() => {
                            if activity.has_active_requests() {
                                idle_timeout.as_mut().reset(
                                    tokio::time::Instant::now() + ADMIN_CONNECTION_IDLE_TIMEOUT,
                                );
                                continue;
                            }
                            tracing::debug!(
                                %remote_addr,
                                timeout_seconds = ADMIN_CONNECTION_IDLE_TIMEOUT.as_secs(),
                                "admin HTTP connection exceeded idle timeout",
                            );
                            break;
                        }
                    }
                }
            });
        }

        tokio::select! {
            () = graceful.shutdown() => Ok(()),
            () = tokio::time::sleep(GRACEFUL_SHUTDOWN_TIMEOUT) => {
                Err(AdminHttpServerError::ShutdownTimeout {
                    timeout: GRACEFUL_SHUTDOWN_TIMEOUT,
                })
            }
        }
    }
}

/// Tracks active requests so the connection timeout applies only to idle
/// keep-alive connections, never to an authenticated maintenance operation.
#[derive(Default)]
struct AdminConnectionActivity {
    active_requests: AtomicUsize,
    changed: tokio::sync::Notify,
}

impl AdminConnectionActivity {
    fn start_request(self: &Arc<Self>) -> ActiveAdminRequest {
        self.active_requests.fetch_add(1, Ordering::AcqRel);
        self.changed.notify_one();
        ActiveAdminRequest {
            activity: Arc::clone(self),
        }
    }

    fn has_active_requests(&self) -> bool {
        self.active_requests.load(Ordering::Acquire) != 0
    }

    async fn changed(&self) {
        self.changed.notified().await;
    }
}

struct ActiveAdminRequest {
    activity: Arc<AdminConnectionActivity>,
}

impl Drop for ActiveAdminRequest {
    fn drop(&mut self) {
        self.activity.active_requests.fetch_sub(1, Ordering::AcqRel);
        self.activity.changed.notify_one();
    }
}

async fn wait_for_first_client_byte(stream: &TcpStream, remote_addr: SocketAddr) -> bool {
    let mut first_byte = [0_u8; 1];
    match tokio::time::timeout(HTTP_HEADER_READ_TIMEOUT, stream.peek(&mut first_byte)).await {
        Ok(Ok(0)) => false,
        Ok(Ok(_read)) => true,
        Ok(Err(error)) => {
            tracing::debug!(
                %remote_addr,
                %error,
                "admin HTTP connection ended before request bytes arrived",
            );
            false
        }
        Err(_elapsed) => {
            tracing::debug!(
                %remote_addr,
                timeout_ms = HTTP_HEADER_READ_TIMEOUT.as_millis(),
                "admin HTTP connection closed after idle header timeout",
            );
            false
        }
    }
}

/// Admin server binding and serving errors.
#[derive(Debug, Error)]
pub enum AdminHttpServerError {
    /// TCP listener bind failed.
    #[error("failed to bind admin listener at {bind}: {source}")]
    Bind {
        /// Requested bind address.
        bind: SocketAddr,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Reading the listener's local address failed.
    #[error("failed to read admin listener address: {0}")]
    LocalAddr(#[source] std::io::Error),
    /// Accepting a connection failed.
    #[error("failed to accept admin connection: {0}")]
    Accept(#[source] std::io::Error),
    /// Graceful shutdown exceeded the configured timeout.
    #[error("admin server shutdown did not finish within {timeout:?}")]
    ShutdownTimeout {
        /// Graceful shutdown timeout.
        timeout: Duration,
    },
}

/// JSON body accepted by `POST /admin/maintenance/apply`.
#[derive(serde::Deserialize)]
struct MaintenanceApplyRequest {
    /// Plan digest returned by a prior dry run.
    plan_digest: String,
}

/// Reads a request body while enforcing the admin body size limit.
async fn read_limited_body<B>(body: B) -> Result<Bytes, ()>
where
    B: Body,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    use http_body_util::BodyExt;
    let limited = http_body_util::Limited::new(body, MAX_ADMIN_REQUEST_BODY_BYTES);
    tokio::time::timeout(ADMIN_REQUEST_BODY_READ_TIMEOUT, limited.collect())
        .await
        .map_err(|_elapsed| ())?
        .map(|collected| collected.to_bytes())
        .map_err(|_error| ())
}

/// Maps the optional operator source header to an audit source label.
///
/// The header only distinguishes CLI submissions from other HTTP clients in
/// audit logs; it grants nothing.
fn presented_operation_source(headers: &HeaderMap) -> MaintenanceOperationSource {
    let is_cli = headers
        .get(ADMIN_SOURCE_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("cli"));
    if is_cli {
        MaintenanceOperationSource::ManualCli
    } else {
        MaintenanceOperationSource::ManualHttp
    }
}

/// Emits the per-completion audit event for one maintenance operation.
fn audit_operation_result(
    kind: &'static str,
    source: MaintenanceOperationSource,
    operation_id: &str,
    outcome: &str,
    plan_digest: Option<&str>,
    record: Option<&MaintenanceOperationRecord>,
) {
    tracing::info!(
        target: "rs3_server",
        operation = "admin_maintenance_operation",
        kind,
        source = source.as_str(),
        operation_id,
        result = outcome,
        plan_digest = plan_digest.unwrap_or(""),
        renewed_object_count = record.map(|record| record.renewed_object_count).unwrap_or(0),
        renewed_bytes = record.map(|record| record.renewed_bytes).unwrap_or(0),
        deleted_object_count = record.map(|record| record.deleted_object_count).unwrap_or(0),
        reclaimable_bytes = record.map(|record| record.reclaimable_bytes).unwrap_or(0),
        "admin maintenance operation completed",
    );
}

fn operation_response(
    status: StatusCode,
    record: &MaintenanceOperationRecord,
) -> Response<Full<Bytes>> {
    json_response(
        status,
        json!({
            "schema": ADMIN_MAINTENANCE_OPERATION_SCHEMA,
            "operation": record,
        }),
    )
}

fn conflict_response(
    code: &'static str,
    message: &'static str,
    record: &MaintenanceOperationRecord,
) -> Response<Full<Bytes>> {
    json_response(
        StatusCode::CONFLICT,
        json!({
            "schema": ADMIN_MAINTENANCE_OPERATION_SCHEMA,
            "error": { "code": code, "message": message },
            "operation": record,
        }),
    )
}

fn control_error_response(error: &MaintenanceControlError) -> Response<Full<Bytes>> {
    let (status, code) = match error {
        MaintenanceControlError::InvalidPlanDigest => {
            (StatusCode::BAD_REQUEST, "invalid-plan-digest")
        }
        MaintenanceControlError::RunInFlight => (StatusCode::CONFLICT, "maintenance-run-in-flight"),
        MaintenanceControlError::Parked { .. } => (StatusCode::CONFLICT, "maintenance-parked"),
        MaintenanceControlError::NoRunInFlight => (StatusCode::CONFLICT, "no-run-in-flight"),
        MaintenanceControlError::SupervisorUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "maintenance-supervisor-unavailable",
        ),
        MaintenanceControlError::DryRunFailed { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "maintenance-dry-run-failed",
        ),
    };
    json_response(
        status,
        json!({
            "error": { "code": code, "message": error.to_string() },
        }),
    )
}

fn presented_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?;
    let value = value.to_str().ok()?;
    value.strip_prefix("Bearer ")
}

fn unauthorized_response() -> Response<Full<Bytes>> {
    let mut response = json_response(
        StatusCode::UNAUTHORIZED,
        json!({
            "error": {
                "code": "unauthorized",
                "message": "valid bearer token required",
            },
        }),
    );
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static(ADMIN_REALM));
    response
}

fn json_response(body_status: StatusCode, body: impl Serialize) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&body).unwrap_or_else(|_error| {
        br#"{"error":{"code":"serialization-failed","message":"failed to serialize response"}}"#
            .to_vec()
    });
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = body_status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn maintenance_summary_is_fresh(computed_at_ms: i64, now_ms: i64) -> bool {
    let ttl_ms = i64::try_from(MAINTENANCE_SUMMARY_TTL.as_millis()).unwrap_or(i64::MAX);
    now_ms.saturating_sub(computed_at_ms) <= ttl_ms
}

fn current_time_ms() -> i64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis();
    i64::try_from(millis).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{
        AdminBearerToken, AdminConnectionActivity, AdminHttpAuth, AdminHttpConfig, AdminHttpServer,
        AdminHttpService,
    };
    use crate::{
        AdminReadiness, AdminReadinessSource, AdminReportProfile, AdminRuntimeFacts,
        AdminRuntimeFactsSource, AnchorConfig, BackendConfig, BatchConfig, GatewayMode,
        HardeningConfig, MaintenanceConfig, MetricsConfig, ProviderConformanceConfig,
        RecoveryConfig, RepositoryConfig, RepositoryFormat, RepositoryKeysConfig, RuntimeConfig,
        StaticCredentials, WriterGuardConfig,
    };
    use bytes::Bytes;
    use http::header::AUTHORIZATION;
    use http::{Request, StatusCode};
    use http_body_util::{BodyExt, Full};
    use rs3_types::{BackendObjectId, PublicBucket, RepositoryId};
    use secrecy::SecretString;
    use std::io::ErrorKind;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;

    fn runtime_config() -> RuntimeConfig {
        let bind = match "127.0.0.1:0".parse() {
            Ok(bind) => bind,
            Err(error) => panic!("{error}"),
        };
        let public_bucket = match PublicBucket::new("client-bucket") {
            Ok(bucket) => bucket,
            Err(error) => panic!("{error}"),
        };

        RuntimeConfig {
            mode: GatewayMode::ReadWrite,
            bind,
            metrics: MetricsConfig { bind: None },
            hardening: HardeningConfig::default(),
            public_bucket,
            backend: BackendConfig {
                endpoint: "memory://local".to_owned(),
                bucket: "backend-bucket".to_owned(),
                prefix: Some("repo-prefix".to_owned()),
                timeouts: Default::default(),
            },
            anchor: AnchorConfig::Memory,
            writer_guard: WriterGuardConfig::Off,
            batching: BatchConfig {
                max_items: 64,
                max_delay: Duration::from_millis(10),
                max_pending_items: 64,
            },
            repository: RepositoryConfig {
                format: RepositoryFormat::V2Preview,
                payload_segment_size: rs3_repository::DEFAULT_PAYLOAD_SEGMENT_SIZE,
                adaptive_payload_segment_size: true,
                decrypted_segment_cache_max_bytes:
                    rs3_repository::DEFAULT_DECRYPTED_SEGMENT_CACHE_MAX_BYTES,
                retention: None,
                allow_init: true,
            },
            maintenance: MaintenanceConfig::default(),
            provider_conformance: ProviderConformanceConfig::default(),
            recovery: RecoveryConfig::default(),
            repository_keys: RepositoryKeysConfig {
                repository_id: RepositoryId::new("test-repository")
                    .unwrap_or_else(|error| panic!("{error}")),
                repository_salt_hex:
                    "2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
                envelope_object_id: Some(
                    BackendObjectId::new("keyrings/test-envelope.json")
                        .unwrap_or_else(|error| panic!("{error}")),
                ),
                wrapping_key_id: "wrap-v1".to_owned(),
                wrapping_key_hex: SecretString::from(
                    "3333333333333333333333333333333333333333333333333333333333333333",
                ),
            },
            static_credentials: Some(StaticCredentials {
                access_key_id: "backup-client".to_owned(),
                secret_access_key: SecretString::from("client-secret"),
            }),
        }
    }

    fn admin_token() -> AdminBearerToken {
        AdminBearerToken::new("admin-token-12345").unwrap_or_else(|error| panic!("{error}"))
    }

    fn bind_addr() -> std::net::SocketAddr {
        "127.0.0.1:0"
            .parse()
            .unwrap_or_else(|error| panic!("{error}"))
    }

    #[test]
    fn active_request_suspends_connection_idle_timeout() {
        let activity = Arc::new(AdminConnectionActivity::default());
        assert!(!activity.has_active_requests());

        let request = activity.start_request();
        assert!(activity.has_active_requests());

        drop(request);
        assert!(!activity.has_active_requests());
    }

    async fn assert_peer_closes(stream: &mut TcpStream) {
        let mut buffer = [0_u8; 1];
        match tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buffer)).await {
            Ok(Ok(0)) => {}
            Ok(Err(error)) if error.kind() == ErrorKind::ConnectionReset => {}
            Ok(Ok(read)) => panic!("idle connection produced {read} bytes before closing"),
            Ok(Err(error)) => panic!("{error}"),
            Err(_elapsed) => panic!("idle connection did not close after header timeout"),
        }
    }

    async fn admin_server() -> AdminHttpServer {
        let admin_config = AdminHttpConfig::new(
            bind_addr(),
            AdminHttpAuth::bearer(admin_token()),
            AdminReportProfile::Production,
        );
        AdminHttpServer::bind(runtime_config(), admin_config)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
    }

    fn service() -> AdminHttpService {
        AdminHttpService::new(
            runtime_config(),
            AdminHttpAuth::bearer(admin_token()),
            AdminReportProfile::Production,
        )
    }

    struct TestRuntimeSources {
        readiness: AdminReadiness,
    }

    impl AdminRuntimeFactsSource for TestRuntimeSources {
        fn snapshot(&self) -> AdminRuntimeFacts {
            AdminRuntimeFacts::default()
        }
    }

    #[async_trait::async_trait]
    impl AdminReadinessSource for TestRuntimeSources {
        async fn check_readiness(&self) -> AdminReadiness {
            self.readiness.clone()
        }
    }

    fn service_with_readiness(readiness: AdminReadiness) -> AdminHttpService {
        let sources = Arc::new(TestRuntimeSources { readiness });
        AdminHttpService::new_with_runtime_sources(
            runtime_config(),
            AdminHttpAuth::bearer(admin_token()),
            AdminReportProfile::Production,
            sources.clone(),
            sources,
        )
    }

    async fn body_string(response: http::Response<Full<Bytes>>) -> String {
        let status = response.status();
        let bytes = match response.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(error) => panic!("{error}"),
        };
        let body = String::from_utf8_lossy(&bytes).into_owned();
        assert!(
            !body.is_empty() || status == StatusCode::NO_CONTENT,
            "empty body for {status}"
        );
        body
    }

    #[tokio::test]
    async fn admin_status_requires_bearer() {
        let response = service()
            .handle(
                Request::builder()
                    .uri("/admin/status")
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_status_returns_path_redacted_report() {
        let response = service()
            .handle(
                Request::builder()
                    .uri("/admin/status")
                    .header(AUTHORIZATION, "Bearer admin-token-12345")
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_string(response).await;
        assert!(body.contains("rs3.admin-status.preview.v1"));
        assert!(body.contains("read-write"));
        assert!(!body.contains("backend-bucket"));
        assert!(!body.contains("repo-prefix"));
        assert!(!body.contains("test-repository"));
        assert!(!body.contains("client-secret"));
    }

    #[tokio::test]
    async fn admin_status_reuses_cached_maintenance_summary_inside_ttl() {
        let service = service();
        let first = service
            .handle(
                Request::builder()
                    .uri("/admin/status")
                    .header(AUTHORIZATION, "Bearer admin-token-12345")
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .await;
        tokio::time::sleep(Duration::from_millis(5)).await;
        let second = service
            .handle(
                Request::builder()
                    .uri("/admin/status")
                    .header(AUTHORIZATION, "Bearer admin-token-12345")
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .await;

        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::OK);
        let first: serde_json::Value = serde_json::from_str(&body_string(first).await)
            .unwrap_or_else(|error| panic!("{error}"));
        let second: serde_json::Value = serde_json::from_str(&body_string(second).await)
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            first["maintenance"]["computed_at_ms"],
            second["maintenance"]["computed_at_ms"]
        );
        assert_eq!(first["runtime"]["build_version"], env!("CARGO_PKG_VERSION"));
        assert!(first["runtime"]["process_started_at_ms"].as_i64().is_some());
    }

    #[tokio::test]
    async fn admin_posture_returns_path_redacted_cheap_report() {
        let response = service()
            .handle(
                Request::builder()
                    .uri("/admin/posture")
                    .header(AUTHORIZATION, "Bearer admin-token-12345")
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_string(response).await;
        assert!(body.contains("rs3.admin-posture.preview.v1"));
        assert!(!body.contains("\"restore\""));
        assert!(!body.contains("\"maintenance\""));
        assert!(!body.contains("backend-bucket"));
        assert!(!body.contains("repo-prefix"));
        assert!(!body.contains("test-repository"));
    }

    #[tokio::test]
    async fn health_route_is_unauthenticated() {
        let response = service()
            .handle(
                Request::builder()
                    .uri("/healthz")
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn readiness_route_reflects_live_sources_without_authentication() {
        let ready = service_with_readiness(AdminReadiness::ready())
            .handle(
                Request::builder()
                    .uri("/readyz")
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .await;
        assert_eq!(ready.status(), StatusCode::OK);
        assert!(body_string(ready).await.contains("\"status\":\"ready\""));

        let unavailable = service_with_readiness(AdminReadiness::unavailable("anchor.unavailable"))
            .handle(
                Request::builder()
                    .uri("/readyz")
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .await;
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body_string(unavailable).await;
        assert!(body.contains("anchor.unavailable"));
        assert!(!body.contains("backend-bucket"));
    }

    #[tokio::test]
    async fn readiness_without_live_source_fails_closed() {
        let response = service()
            .handle(
                Request::builder()
                    .uri("/readyz")
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn idle_admin_connection_is_closed_after_header_timeout() {
        let server = admin_server().await;
        let addr = server.local_addr();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(server.run_until_shutdown(async move {
            let _ = shutdown_rx.await;
        }));

        let mut stream = TcpStream::connect(addr)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_peer_closes(&mut stream).await;

        let _ = shutdown_tx.send(());
        handle
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|error| panic!("{error}"));
    }

    mod maintenance_mutation {
        use super::{admin_token, body_string, runtime_config, service};
        use crate::admin_http::{AdminBearerToken, AdminHttpAuth, AdminHttpAuthError};
        use crate::maintenance::{
            MaintenanceRunPhase, MaintenanceRuntime, MaintenanceSupervisor,
            MaintenanceSupervisorConfig, MaintenanceSupervisorHandle, SystemMaintenanceClock,
        };
        use crate::{AdminHttpService, AdminReportProfile, MaintenanceConfig, MaintenanceMode};
        use async_trait::async_trait;
        use bytes::Bytes;
        use http::header::AUTHORIZATION;
        use http::{Method, Request, StatusCode};
        use http_body_util::Full;
        use rs3_repository::RepositoryError;
        use rs3_repository::v2::{
            V2FullGcApplyOptions, V2FullGcApplyReport, V2FullGcDryRunOptions, V2FullGcDryRunReport,
            V2FullGcPlanPreview, V2FullMaintenanceReport, V2MaintenanceCancellation,
            V2MaintenancePlanCost, V2MaintenanceReport, V2OrphanGcOptions, V2OrphanGcReport,
        };
        use serde_json::Value;
        use std::sync::{Arc, Mutex as StdMutex};
        use std::time::Duration;

        fn mutation_token() -> AdminBearerToken {
            AdminBearerToken::new("mutation-token-12345").unwrap_or_else(|error| panic!("{error}"))
        }

        fn mutation_auth() -> AdminHttpAuth {
            AdminHttpAuth::bearer_with_mutation(admin_token(), mutation_token())
                .unwrap_or_else(|error| panic!("{error}"))
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
                dead_bytes_reclaimable: 128,
                live_bytes_to_copy: 0,
                mixed_dead_bytes_repackable: 0,
                retention_blocked_bytes: 0,
                legal_hold_blocked_bytes: 0,
                unknown_protection_blocked_bytes: 0,
                retention_renewal_commit_count: 1,
                retention_renewal_bytes: 64,
                retention_renewal_blocked_count: 0,
                retention_renewal_blocked_bytes: 0,
                planned_cost: V2MaintenancePlanCost::default(),
                fits_budgets: true,
                exact_version_apply_ready: true,
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

        fn mock_plan_digest(report: &V2FullGcDryRunReport) -> String {
            rs3_crypto::derive_public_fingerprint(
                b"rs3.admin-http.mock-plan.v1",
                &[&report.dead_bytes_reclaimable.to_be_bytes()],
            )
        }

        struct StaticMaintenanceRuntime {
            guard_configured: bool,
            dry_run: StdMutex<V2FullGcDryRunReport>,
        }

        impl StaticMaintenanceRuntime {
            fn new() -> Self {
                Self {
                    guard_configured: true,
                    dry_run: StdMutex::new(dry_run_report()),
                }
            }

            fn move_state(&self) {
                let mut report = self.dry_run.lock().expect("mock dry-run lock");
                report.dead_bytes_reclaimable += 1;
            }
        }

        #[async_trait]
        impl MaintenanceRuntime for StaticMaintenanceRuntime {
            fn maintenance_guard_configured(&self) -> bool {
                self.guard_configured
            }

            async fn quick_maintenance_report(
                &self,
            ) -> Result<V2MaintenanceReport, RepositoryError> {
                Ok(quick_report())
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
                _cancellation: &V2MaintenanceCancellation,
                on_phase: &(dyn Fn(MaintenanceRunPhase) + Send + Sync),
            ) -> Result<V2FullMaintenanceReport, RepositoryError> {
                on_phase(MaintenanceRunPhase::Quiescing);
                let fresh = self.dry_run.lock().expect("mock dry-run lock").clone();
                if let Some(expected) = expected_plan_digest
                    && mock_plan_digest(&fresh) != expected
                {
                    return Err(RepositoryError::CommitFailed {
                        reason: crate::maintenance::MAINTENANCE_PLAN_STALE_REASON.to_owned(),
                    });
                }
                on_phase(MaintenanceRunPhase::Applying);
                Ok(V2FullMaintenanceReport {
                    dry_run: fresh.clone(),
                    apply: V2FullGcApplyReport {
                        dry_run: fresh,
                        retention_renewed_object_count: 1,
                        retention_renewed_bytes: 64,
                        orphan_gc: V2OrphanGcReport {
                            scanned_count: 1,
                            deleted_count: 1,
                            ..V2OrphanGcReport::default()
                        },
                    },
                })
            }
        }

        fn start_supervisor(runtime: Arc<StaticMaintenanceRuntime>) -> MaintenanceSupervisorHandle {
            MaintenanceSupervisor::start(
                MaintenanceSupervisorConfig {
                    maintenance: MaintenanceConfig {
                        mode: MaintenanceMode::Manual,
                        ..MaintenanceConfig::default()
                    },
                    retention_configured: false,
                    orphan_gc: V2OrphanGcOptions::new_for_test_rehearsal(Duration::ZERO),
                    retained_provider_conformance: Arc::new(|| true),
                },
                runtime,
                Arc::new(SystemMaintenanceClock),
            )
        }

        fn mutation_service(
            handle: &MaintenanceSupervisorHandle,
            auth: AdminHttpAuth,
        ) -> AdminHttpService {
            AdminHttpService::new(runtime_config(), auth, AdminReportProfile::Production)
                .with_maintenance_control(handle.control())
        }

        async fn send(
            service: &AdminHttpService,
            method: Method,
            path: &str,
            token: &str,
            body: &str,
        ) -> (StatusCode, Value) {
            let response = service
                .handle(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header(AUTHORIZATION, format!("Bearer {token}"))
                        .body(Full::new(Bytes::from(body.to_owned())))
                        .unwrap_or_else(|error| panic!("{error}")),
                )
                .await;
            let status = response.status();
            let body = body_string(response).await;
            let value: Value =
                serde_json::from_str(&body).unwrap_or_else(|error| panic!("{error}: {body}"));
            (status, value)
        }

        #[test]
        fn equal_read_and_mutation_tokens_are_rejected() {
            let error = AdminHttpAuth::bearer_with_mutation(admin_token(), admin_token())
                .expect_err("equal read and mutation tokens must be rejected");
            assert_eq!(error, AdminHttpAuthError::MutationTokenNotDistinct);
        }

        #[tokio::test]
        async fn read_token_cannot_post_maintenance_mutations() {
            let runtime = Arc::new(StaticMaintenanceRuntime::new());
            let handle = start_supervisor(Arc::clone(&runtime));
            let service = mutation_service(&handle, mutation_auth());

            let (status, body) = send(
                &service,
                Method::POST,
                "/admin/maintenance/pause",
                "admin-token-12345",
                "",
            )
            .await;

            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(body["error"]["code"], "mutation-token-required");

            // The read token still serves GET routes.
            let (status, body) = send(
                &service,
                Method::GET,
                "/admin/maintenance",
                "admin-token-12345",
                "",
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["schema"], "rs3.admin-maintenance.preview.v1");
            assert_eq!(body["mutation_enabled"], true);
            handle.shutdown().await;
        }

        #[tokio::test]
        async fn missing_mutation_token_disables_post_with_posture_note() {
            let runtime = Arc::new(StaticMaintenanceRuntime::new());
            let handle = start_supervisor(Arc::clone(&runtime));
            let service = mutation_service(&handle, AdminHttpAuth::bearer(admin_token()));

            let (status, body) = send(
                &service,
                Method::POST,
                "/admin/maintenance/pause",
                "admin-token-12345",
                "",
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(body["error"]["code"], "mutation-not-configured");

            let (status, body) = send(
                &service,
                Method::GET,
                "/admin/maintenance",
                "admin-token-12345",
                "",
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["mutation_enabled"], false);
            let notes = body["notes"]
                .as_array()
                .unwrap_or_else(|| panic!("notes should be an array"));
            assert!(
                notes
                    .iter()
                    .any(|note| note.as_str().is_some_and(|note| note.contains("disabled")))
            );
            handle.shutdown().await;
        }

        #[tokio::test]
        async fn mutation_token_grants_get_and_post() {
            let runtime = Arc::new(StaticMaintenanceRuntime::new());
            let handle = start_supervisor(Arc::clone(&runtime));
            let service = mutation_service(&handle, mutation_auth());

            let (status, body) = send(
                &service,
                Method::POST,
                "/admin/maintenance/pause",
                "mutation-token-12345",
                "",
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["schema"], "rs3.admin-maintenance-operation.preview.v1");
            assert_eq!(body["operation"]["kind"], "pause");
            assert_eq!(body["operation"]["outcome"], "ok");

            let (status, body) = send(
                &service,
                Method::GET,
                "/admin/maintenance",
                "mutation-token-12345",
                "",
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["supervisor"]["paused"], true);

            let (status, _body) = send(
                &service,
                Method::POST,
                "/admin/maintenance/resume",
                "mutation-token-12345",
                "",
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            handle.shutdown().await;
        }

        #[tokio::test]
        async fn dry_run_and_apply_roundtrip_with_stale_digest_conflict() {
            let runtime = Arc::new(StaticMaintenanceRuntime::new());
            let handle = start_supervisor(Arc::clone(&runtime));
            let service = mutation_service(&handle, mutation_auth());

            let (status, first) = send(
                &service,
                Method::POST,
                "/admin/maintenance/dry-run",
                "mutation-token-12345",
                "",
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(first["schema"], "rs3.admin-maintenance-dry-run.preview.v1");
            assert_eq!(first["report"]["fits_budgets"], true);
            let digest = first["plan_digest"]
                .as_str()
                .unwrap_or_else(|| panic!("plan digest should be a string"))
                .to_owned();
            assert_eq!(digest.len(), 64);

            // Unchanged state produces the same digest.
            let (_status, second) = send(
                &service,
                Method::POST,
                "/admin/maintenance/dry-run",
                "mutation-token-12345",
                "",
            )
            .await;
            assert_eq!(second["plan_digest"], first["plan_digest"]);

            let apply_body = format!("{{\"plan_digest\":\"{digest}\"}}");
            let (status, applied) = send(
                &service,
                Method::POST,
                "/admin/maintenance/apply",
                "mutation-token-12345",
                &apply_body,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{applied}");
            assert_eq!(applied["operation"]["outcome"], "ok");
            assert_eq!(applied["operation"]["kind"], "apply");
            assert_eq!(applied["operation"]["renewed_object_count"], 1);

            // Repository state moves; the reviewed digest is now stale.
            runtime.move_state();
            let (status, stale) = send(
                &service,
                Method::POST,
                "/admin/maintenance/apply",
                "mutation-token-12345",
                &apply_body,
            )
            .await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(stale["error"]["code"], "plan-digest-stale");
            assert_eq!(stale["operation"]["outcome"], "stale-plan");

            let (status, malformed) = send(
                &service,
                Method::POST,
                "/admin/maintenance/apply",
                "mutation-token-12345",
                "{\"plan_digest\":\"nope\"}",
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(malformed["error"]["code"], "invalid-plan-digest");

            let (status, history) = send(
                &service,
                Method::GET,
                "/admin/maintenance",
                "admin-token-12345",
                "",
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let operations = history["operations"]
                .as_array()
                .unwrap_or_else(|| panic!("operations should be an array"));
            assert!(operations.len() >= 4);
            assert!(operations.iter().any(|op| op["kind"] == "dry-run"));
            assert!(
                operations
                    .iter()
                    .any(|op| op["kind"] == "apply" && op["outcome"] == "stale-plan")
            );
            handle.shutdown().await;
        }

        #[tokio::test]
        async fn apply_conflicts_when_parked_and_cancel_without_run() {
            let runtime = Arc::new(StaticMaintenanceRuntime {
                guard_configured: false,
                dry_run: StdMutex::new(dry_run_report()),
            });
            let handle = start_supervisor(Arc::clone(&runtime));
            let service = mutation_service(&handle, mutation_auth());

            // Whether the parked state is already observable or the pending
            // run is drained by the parked loop, apply resolves to the same
            // maintenance-parked conflict.
            let digest = "ab".repeat(32);
            let apply_body = format!("{{\"plan_digest\":\"{digest}\"}}");
            let (status, body) = send(
                &service,
                Method::POST,
                "/admin/maintenance/apply",
                "mutation-token-12345",
                &apply_body,
            )
            .await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(body["error"]["code"], "maintenance-parked");

            let (status, body) = send(
                &service,
                Method::POST,
                "/admin/maintenance/cancel",
                "mutation-token-12345",
                "",
            )
            .await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(body["error"]["code"], "no-run-in-flight");
            handle.shutdown().await;
        }

        #[tokio::test]
        async fn post_without_supervisor_is_unavailable() {
            let service = service();

            let response = service
                .handle(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/admin/maintenance/pause")
                        .header(AUTHORIZATION, "Bearer admin-token-12345")
                        .body(Full::new(Bytes::new()))
                        .unwrap_or_else(|error| panic!("{error}")),
                )
                .await;

            // A read-only auth configuration rejects mutations before the
            // missing supervisor is consulted.
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
    }
}
