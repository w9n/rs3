//! Path-redacted operator report facts.
//!
//! These reports are preview-scoped facts for local tooling and management
//! integrations. They are intentionally not a complete workflow API; mutating
//! workflows require a separate authorization and audit model.

use crate::maintenance::MaintenanceStatusSnapshot;
use crate::{
    AnchorConfig, BackendConfig, MaintenanceMode, ProviderConformanceConfig, RuntimeConfig,
    V2ProviderCheckConfig, WriterGuardConfig,
};
use async_trait::async_trait;
use rs3_crypto::derive_public_fingerprint;
use rs3_repository::v2::{V2ProviderProfile, required_v2_provider_check_names};
use rs3_types::RetentionMode;
use serde::{Deserialize, Serialize};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

const ADMIN_STATUS_SCHEMA: &str = "rs3.admin-status.preview.v1";
const ADMIN_POSTURE_SCHEMA: &str = "rs3.admin-posture.preview.v1";
const PROVIDER_CONFORMANCE_SCHEMA: &str = "rs3.v2-provider-conformance.v3";
const PROVIDER_EVIDENCE_MAX_FUTURE_SKEW_MS: i64 = 5 * 60 * 1_000;

/// Derives the path-safe identity of the exact backend target qualified by a
/// persisted provider-conformance report.
pub fn provider_conformance_target_fingerprint(config: &V2ProviderCheckConfig) -> String {
    derive_public_fingerprint(
        b"rs3.provider-conformance.target.v2",
        &[
            config.backend.endpoint.as_bytes(),
            config.backend.bucket.as_bytes(),
            config.backend.prefix.as_deref().unwrap_or("").as_bytes(),
            config
                .principal_fingerprint
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
        ],
    )
}

/// Admin report profile.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminReportProfile {
    /// Local development profile.
    Local,
    /// Production posture profile.
    Production,
}

impl AdminReportProfile {
    /// Returns the stable profile spelling used in reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Production => "production",
        }
    }
}

/// Source of live in-process facts for path-redacted admin reports.
pub trait AdminRuntimeFactsSource: Send + Sync {
    /// Returns a current snapshot of live runtime facts.
    fn snapshot(&self) -> AdminRuntimeFacts;
}

/// Live readiness probe source for the gateway admin listener.
#[async_trait]
pub trait AdminReadinessSource: Send + Sync {
    /// Checks the dependencies required to serve correct S3 responses now.
    async fn check_readiness(&self) -> AdminReadiness;
}

/// Path-safe result of a live gateway readiness check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminReadiness {
    /// Whether the gateway can currently serve its configured mode safely.
    pub ready: bool,
    /// Stable path-safe reason when the gateway is not ready.
    pub reason_code: Option<&'static str>,
}

impl AdminReadiness {
    /// Returns a successful readiness result.
    pub const fn ready() -> Self {
        Self {
            ready: true,
            reason_code: None,
        }
    }

    /// Returns a failed readiness result with a stable path-safe reason.
    pub const fn unavailable(reason_code: &'static str) -> Self {
        Self {
            ready: false,
            reason_code: Some(reason_code),
        }
    }
}

/// Live in-process facts attached to admin reports when a gateway is running.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdminRuntimeFacts {
    /// Process start time in milliseconds since the Unix epoch, when known.
    pub process_started_at_ms: Option<i64>,
    /// Live repository facts.
    pub repository: AdminRepositoryRuntimeFacts,
    /// Live maintenance supervisor posture, when the supervisor is running.
    pub maintenance_supervisor: Option<AdminMaintenanceSupervisorSummary>,
}

/// Live repository facts safe to surface through admin reports.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdminRepositoryRuntimeFacts {
    /// Live v2 commit-coordinator status, when the report is attached to a running gateway.
    pub v2_commit_coordinator: Option<AdminV2CommitCoordinatorSummary>,
}

/// Preview path-redacted operator status fact report.
///
/// This is a low-level report for doctor-style checks and external control
/// planes. It is not a stable workflow API.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdminStatusReport {
    /// Report schema marker.
    pub schema: &'static str,
    /// Report profile used for posture checks.
    pub profile: &'static str,
    /// Report generation timestamp in milliseconds since the Unix epoch.
    pub generated_at_ms: i64,
    /// Runtime posture summary.
    pub runtime: AdminRuntimeSummary,
    /// Backend posture summary.
    pub backend: AdminBackendSummary,
    /// Provider conformance posture summary.
    pub provider: AdminProviderSummary,
    /// Anchor posture summary.
    pub anchor: AdminAnchorSummary,
    /// Repository behavior summary.
    pub repository: AdminRepositorySummary,
    /// Security boundary summary.
    pub security: AdminSecuritySummary,
    /// Restore-trust summary derived from the configured anchor when available.
    pub restore: AdminRestoreSummary,
    /// Read-only maintenance summary.
    pub maintenance: AdminMaintenanceSummary,
    /// Profile findings. Empty means the selected profile passed.
    pub findings: Vec<AdminFinding>,
}

/// Cheap path-redacted operator posture report.
///
/// Unlike [`AdminStatusReport`], this report does not verify repository state
/// and is suitable for frequent polling.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdminPostureReport {
    /// Report schema marker.
    pub schema: &'static str,
    /// Report profile used for posture checks.
    pub profile: &'static str,
    /// Report generation timestamp in milliseconds since the Unix epoch.
    pub generated_at_ms: i64,
    /// Runtime posture summary.
    pub runtime: AdminRuntimeSummary,
    /// Backend posture summary.
    pub backend: AdminBackendSummary,
    /// Provider conformance posture summary.
    pub provider: AdminProviderSummary,
    /// Anchor posture summary.
    pub anchor: AdminAnchorSummary,
    /// Repository behavior summary.
    pub repository: AdminRepositorySummary,
    /// Security boundary summary.
    pub security: AdminSecuritySummary,
    /// Profile findings. Empty means the selected profile passed.
    pub findings: Vec<AdminFinding>,
}

/// Runtime posture fields that are safe to show in operator reports.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdminRuntimeSummary {
    /// Build version of the reporting binary.
    pub build_version: &'static str,
    /// Process start time in milliseconds since the Unix epoch, when known.
    pub process_started_at_ms: Option<i64>,
    /// Gateway mutation mode.
    pub gateway_mode: &'static str,
    /// Path-safe runtime configuration fingerprint.
    pub config_profile: String,
    /// Whether the S3 listener has static credentials configured.
    pub static_credentials_configured: bool,
    /// Whether the metrics listener is configured.
    pub metrics_configured: bool,
}

/// Backend posture fields that avoid bucket, endpoint, and prefix names.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdminBackendSummary {
    /// Provider-neutral backend kind.
    pub kind: &'static str,
    /// Whether the selected backend is durable enough for non-test use.
    pub durable: bool,
    /// Provider retention capability from the runtime configuration shape.
    pub retention_capability: &'static str,
}

/// Provider conformance fields that avoid configured provider names and paths.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdminProviderSummary {
    /// Provider profile selected from runtime configuration.
    pub selected_profile: &'static str,
    /// Last persisted conformance evidence, when configured.
    pub conformance: AdminProviderConformanceSummary,
}

/// Redacted provider-conformance evidence summary.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdminProviderConformanceSummary {
    /// Evidence state: `passed`, `failed`, `missing`, `stale`, or `invalid`.
    pub state: &'static str,
    /// Machine-readable reason for unavailable or invalid evidence.
    pub reason_code: Option<&'static str>,
    /// Provider profile named by the evidence file.
    pub profile: Option<String>,
    /// Evidence report generation timestamp in milliseconds.
    pub generated_at_ms: Option<i64>,
    /// Total number of checks in the evidence file.
    pub check_count: usize,
    /// Number of failed checks in the evidence file.
    pub failed_check_count: usize,
    /// Whether legal-hold checks are present in the evidence file.
    pub legal_hold_checked: bool,
    /// Whether governance-bypass review is present and passed in the evidence file.
    pub governance_bypass_reviewed: bool,
}

/// Anchor posture fields that avoid Kubernetes object names.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdminAnchorSummary {
    /// Configured anchor kind.
    pub kind: &'static str,
    /// Whether the configured anchor is external to this process.
    pub external: bool,
}

/// Repository behavior fields that are safe to show in operator reports.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdminRepositorySummary {
    /// Durable repository format selected by the runtime.
    pub format: &'static str,
    /// Plaintext payload segment size in bytes.
    pub payload_segment_size_bytes: usize,
    /// Whether payload segment size is adapted upward for medium and large objects.
    pub adaptive_payload_segment_size: bool,
    /// Maximum plaintext bytes retained in the decrypted segment LRU cache.
    pub decrypted_segment_cache_max_bytes: u64,
    /// Maximum staged writes covered by one commit batch.
    pub commit_max_batch_items: usize,
    /// Maximum commit batch delay in milliseconds.
    pub commit_max_batch_delay_ms: u128,
    /// Maximum writes waiting for commit before backpressure.
    pub commit_max_pending_items: usize,
    /// Configured default retention mode, or `none`.
    pub retention_mode: &'static str,
    /// Configured default retention duration in days.
    pub retention_days: u32,
    /// Whether first-run initialization is allowed when the anchor is missing.
    pub allow_init: bool,
    /// Live v2 commit-coordinator status, when the report is attached to a running gateway.
    pub v2_commit_coordinator: Option<AdminV2CommitCoordinatorSummary>,
}

/// Live v2 commit coordinator summary.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdminV2CommitCoordinatorSummary {
    /// Whether the coordinator is permanently refusing new writes.
    pub poisoned: bool,
    /// Path-redacted reason for a permanent poison state.
    pub poison_reason: Option<String>,
}

/// Security boundary fields for operator reports.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdminSecuritySummary {
    /// Whether the reporting surface exposes client-visible path browsing.
    pub path_browsing_enabled: bool,
    /// Whether report responses include configured secret material.
    pub secrets_exposed: bool,
    /// Maximum accepted `PutObject` request body size.
    pub max_put_object_bytes: u64,
    /// Largest `PutObject` body buffered as a single repository write.
    pub buffered_put_object_bytes: u64,
    /// Provider multipart part size for large streaming `PutObject` writes.
    pub backend_multipart_part_bytes: u64,
    /// Admission budget for request body bytes held by in-flight upload operations.
    pub max_in_flight_upload_body_bytes: u64,
    /// Admission budget for response body bytes held by in-flight download operations.
    pub max_in_flight_download_body_bytes: u64,
    /// Maximum simultaneously open S3 listener connections.
    pub max_concurrent_connections: usize,
    /// Maximum concurrently executing S3 operations.
    pub max_concurrent_requests: usize,
    /// Per-process S3 operation admission limit per second.
    pub request_rate_limit_per_second: u64,
    /// Core report action posture.
    pub action_posture: &'static str,
}

/// Restore trust status shown by operator reports.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdminRestoreSummary {
    /// Restore trust state: `verified` or `unavailable`.
    pub state: &'static str,
    /// Machine-readable reason code when restore trust is unavailable.
    pub reason_code: Option<&'static str>,
    /// Accepted v2 anchor summary when available.
    pub v2_anchor: Option<AdminV2RestoreSummary>,
}

/// Read-only maintenance status shown by operator reports.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdminMaintenanceSummary {
    /// Maintenance trust state: `verified`, `unavailable`, or `not-applicable`.
    pub state: &'static str,
    /// Maintenance summary computation timestamp in milliseconds since the Unix epoch.
    pub computed_at_ms: i64,
    /// Machine-readable reason code when maintenance facts are unavailable.
    pub reason_code: Option<&'static str>,
    /// v2 maintenance facts, when the configured repository format is v2.
    pub v2: Option<AdminV2MaintenanceSummary>,
    /// Live maintenance supervisor posture, when the supervisor is running.
    pub supervisor: Option<AdminMaintenanceSupervisorSummary>,
}

/// Path-redacted maintenance supervisor posture and history.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdminMaintenanceSupervisorSummary {
    /// Configured supervisor mode.
    pub mode: &'static str,
    /// Current supervisor state machine position.
    pub state: &'static str,
    /// Stable reason code when the supervisor is parked.
    pub parked_reason: Option<&'static str>,
    /// Whether the automatic scheduler is paused by an operator.
    pub paused: bool,
    /// Nearest provider retain-until deadline observed by planning.
    pub nearest_retain_until_ms: Option<i64>,
    /// Next scheduled trigger time in milliseconds since the Unix epoch.
    pub next_trigger_at_ms: Option<i64>,
    /// Reason associated with the next scheduled trigger.
    pub next_trigger_reason: Option<&'static str>,
    /// Consecutive failed runs since the last success.
    pub consecutive_failures: u32,
    /// Timestamp of the last successful run in milliseconds since the epoch.
    pub last_success_at_ms: Option<i64>,
    /// Outcome of the most recent run attempt.
    pub last_run_outcome: Option<&'static str>,
    /// Trigger of the most recent run attempt.
    pub last_run_trigger: Option<&'static str>,
    /// Start time of the most recent run attempt in milliseconds.
    pub last_run_started_at_ms: Option<i64>,
    /// Duration of the most recent run attempt in milliseconds.
    pub last_run_duration_ms: Option<u64>,
    /// Objects renewed by the most recent run attempt.
    pub last_run_renewed_object_count: Option<usize>,
    /// Bytes renewed by the most recent run attempt.
    pub last_run_renewed_bytes: Option<u64>,
    /// Orphans deleted by the most recent run attempt.
    pub last_run_deleted_object_count: Option<usize>,
}

impl From<&MaintenanceStatusSnapshot> for AdminMaintenanceSupervisorSummary {
    fn from(snapshot: &MaintenanceStatusSnapshot) -> Self {
        let last_run = snapshot.last_run.as_ref();
        Self {
            mode: snapshot.mode,
            state: snapshot.state,
            parked_reason: snapshot.parked_reason,
            paused: snapshot.paused,
            nearest_retain_until_ms: snapshot.nearest_retain_until_ms,
            next_trigger_at_ms: snapshot.next_trigger_at_ms,
            next_trigger_reason: snapshot.next_trigger_reason,
            consecutive_failures: snapshot.consecutive_failures,
            last_success_at_ms: snapshot.last_success_at_ms,
            last_run_outcome: last_run.map(|run| run.outcome),
            last_run_trigger: last_run.map(|run| run.trigger),
            last_run_started_at_ms: last_run.map(|run| run.started_at_ms),
            last_run_duration_ms: last_run.map(|run| run.duration_ms),
            last_run_renewed_object_count: last_run.map(|run| run.renewed_object_count),
            last_run_renewed_bytes: last_run.map(|run| run.renewed_bytes),
            last_run_deleted_object_count: last_run.map(|run| run.deleted_object_count),
        }
    }
}

/// Path-redacted v2 maintenance facts.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdminV2MaintenanceSummary {
    /// Whether the v2 anchor is present.
    pub anchor_present: bool,
    /// Verified commit count in the anchor-selected chain.
    pub verified_commit_count: usize,
    /// Age of the accepted chain head in milliseconds.
    pub last_anchored_commit_age_ms: Option<u128>,
    /// Unanchored v2 commit candidates observed under the commit prefix.
    pub orphan_candidate_count: usize,
    /// Total bytes held by unanchored v2 commit candidates.
    pub orphan_candidate_bytes: u64,
    /// Orphan candidates blocked by retention or legal hold.
    pub protected_orphan_candidate_count: usize,
    /// Oldest visible orphan age in milliseconds, when provider timestamps exist.
    pub oldest_orphan_age_ms: Option<u128>,
    /// Live commit versions that should have retention extended within the default renewal horizon.
    pub retention_renewal_commit_count: usize,
    /// Live commit bytes covered by planned retention renewal.
    pub retention_renewal_bytes: u64,
    /// Live commit versions whose renewal could not be planned from available metadata.
    pub retention_renewal_blocked_count: usize,
    /// Live commit bytes whose renewal could not be planned from available metadata.
    pub retention_renewal_blocked_bytes: u64,
}

/// Accepted v2 anchor summary.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdminV2RestoreSummary {
    /// Accepted v2 commit sequence.
    pub sequence: u64,
    /// Accepted v2 commit body digest.
    pub body_digest: String,
    /// Whether the accepted commit is bound to a provider version ID.
    pub version_bound: bool,
    /// Active format generation bound into the anchor.
    pub format_generation: u64,
    /// Active format digest bound into the anchor.
    pub format_digest: String,
    /// Bundle export timestamp in milliseconds since the Unix epoch.
    pub exported_at_ms: i64,
}

/// Admin posture finding.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdminFinding {
    /// Finding severity.
    pub severity: &'static str,
    /// Stable finding code.
    pub code: &'static str,
    /// Operator-facing finding message.
    pub message: &'static str,
    /// Operator-facing remediation hint.
    pub remediation: &'static str,
}

impl AdminFinding {
    fn error(code: &'static str, message: &'static str, remediation: &'static str) -> Self {
        Self {
            severity: "error",
            code,
            message,
            remediation,
        }
    }

    fn warning(code: &'static str, message: &'static str, remediation: &'static str) -> Self {
        Self {
            severity: "warning",
            code,
            message,
            remediation,
        }
    }

    /// Returns whether this finding blocks the selected posture.
    pub fn is_blocking(&self) -> bool {
        self.severity == "error"
    }
}

/// Builds a preview path-redacted status fact report from runtime configuration.
///
/// The report is deliberately read-only and orchestration-free. External admin
/// code should wrap these facts in its own authorization, audit, approval, and
/// workflow model.
pub async fn admin_status_report(
    config: &RuntimeConfig,
    profile: AdminReportProfile,
) -> AdminStatusReport {
    admin_status_report_with_runtime_facts(config, profile, &AdminRuntimeFacts::default()).await
}

/// Builds a status report with live in-process runtime facts attached.
pub async fn admin_status_report_with_runtime_facts(
    config: &RuntimeConfig,
    profile: AdminReportProfile,
    runtime_facts: &AdminRuntimeFacts,
) -> AdminStatusReport {
    let maintenance = maintenance_summary(config).await;
    admin_status_report_with_runtime_facts_and_maintenance(
        config,
        profile,
        runtime_facts,
        maintenance,
    )
    .await
}

pub(crate) async fn admin_status_report_with_runtime_facts_and_maintenance(
    config: &RuntimeConfig,
    profile: AdminReportProfile,
    runtime_facts: &AdminRuntimeFacts,
    mut maintenance: AdminMaintenanceSummary,
) -> AdminStatusReport {
    if maintenance.supervisor.is_none() {
        maintenance.supervisor = runtime_facts.maintenance_supervisor.clone();
    }
    let restore = restore_summary(config).await;
    admin_report_builder(config, profile, runtime_facts).status(restore, maintenance)
}

/// Builds the cheap path-redacted status report that does not verify repository state.
pub fn admin_posture_report(
    config: &RuntimeConfig,
    profile: AdminReportProfile,
) -> AdminPostureReport {
    admin_posture_report_with_runtime_facts(config, profile, &AdminRuntimeFacts::default())
}

/// Builds a cheap posture report with live in-process runtime facts attached.
pub fn admin_posture_report_with_runtime_facts(
    config: &RuntimeConfig,
    profile: AdminReportProfile,
    runtime_facts: &AdminRuntimeFacts,
) -> AdminPostureReport {
    admin_report_builder(config, profile, runtime_facts).posture()
}

struct AdminReportBuilder {
    profile: &'static str,
    generated_at_ms: i64,
    runtime: AdminRuntimeSummary,
    backend: AdminBackendSummary,
    provider: AdminProviderSummary,
    anchor: AdminAnchorSummary,
    repository: AdminRepositorySummary,
    security: AdminSecuritySummary,
    findings: Vec<AdminFinding>,
}

impl AdminReportBuilder {
    fn status(
        self,
        restore: AdminRestoreSummary,
        maintenance: AdminMaintenanceSummary,
    ) -> AdminStatusReport {
        AdminStatusReport {
            schema: ADMIN_STATUS_SCHEMA,
            profile: self.profile,
            generated_at_ms: self.generated_at_ms,
            runtime: self.runtime,
            backend: self.backend,
            provider: self.provider,
            anchor: self.anchor,
            repository: self.repository,
            security: self.security,
            restore,
            maintenance,
            findings: self.findings,
        }
    }

    fn posture(self) -> AdminPostureReport {
        AdminPostureReport {
            schema: ADMIN_POSTURE_SCHEMA,
            profile: self.profile,
            generated_at_ms: self.generated_at_ms,
            runtime: self.runtime,
            backend: self.backend,
            provider: self.provider,
            anchor: self.anchor,
            repository: self.repository,
            security: self.security,
            findings: self.findings,
        }
    }
}

fn admin_report_builder(
    config: &RuntimeConfig,
    profile: AdminReportProfile,
    runtime_facts: &AdminRuntimeFacts,
) -> AdminReportBuilder {
    AdminReportBuilder {
        profile: profile.as_str(),
        generated_at_ms: current_time_ms().unwrap_or(0),
        runtime: runtime_summary(config, runtime_facts),
        backend: backend_summary(&config.backend),
        provider: provider_summary(config),
        anchor: anchor_summary(&config.anchor),
        repository: repository_summary(config, runtime_facts),
        security: security_summary(config),
        findings: doctor_findings(config, profile),
    }
}

fn runtime_summary(
    config: &RuntimeConfig,
    runtime_facts: &AdminRuntimeFacts,
) -> AdminRuntimeSummary {
    AdminRuntimeSummary {
        build_version: env!("CARGO_PKG_VERSION"),
        process_started_at_ms: runtime_facts.process_started_at_ms,
        gateway_mode: config.mode.as_str(),
        config_profile: runtime_config_profile(config),
        static_credentials_configured: config.static_credentials.is_some(),
        metrics_configured: config.metrics.bind.is_some(),
    }
}

fn backend_summary(backend: &BackendConfig) -> AdminBackendSummary {
    AdminBackendSummary {
        kind: backend_kind(&backend.endpoint),
        durable: backend_is_durable(backend),
        retention_capability: retention_capability(backend),
    }
}

fn anchor_summary(anchor: &AnchorConfig) -> AdminAnchorSummary {
    AdminAnchorSummary {
        kind: anchor_kind(anchor),
        external: !matches!(anchor, AnchorConfig::Memory),
    }
}

fn security_summary(config: &RuntimeConfig) -> AdminSecuritySummary {
    AdminSecuritySummary {
        path_browsing_enabled: false,
        secrets_exposed: false,
        max_put_object_bytes: config.hardening.max_put_object_bytes,
        buffered_put_object_bytes: config.hardening.buffered_put_object_bytes,
        backend_multipart_part_bytes: config.hardening.backend_multipart_part_bytes,
        max_in_flight_upload_body_bytes: config.hardening.max_in_flight_upload_body_bytes,
        max_in_flight_download_body_bytes: config.hardening.max_in_flight_download_body_bytes,
        max_concurrent_connections: config.hardening.max_concurrent_connections,
        max_concurrent_requests: config.hardening.max_concurrent_requests,
        request_rate_limit_per_second: config.hardening.request_rate_limit_per_second,
        action_posture: "report-only",
    }
}

fn repository_summary(
    config: &RuntimeConfig,
    runtime_facts: &AdminRuntimeFacts,
) -> AdminRepositorySummary {
    AdminRepositorySummary {
        format: config.repository.format.as_str(),
        payload_segment_size_bytes: config.repository.payload_segment_size,
        adaptive_payload_segment_size: config.repository.adaptive_payload_segment_size,
        decrypted_segment_cache_max_bytes: config.repository.decrypted_segment_cache_max_bytes,
        commit_max_batch_items: config.batching.max_items,
        commit_max_batch_delay_ms: config.batching.max_delay.as_millis(),
        commit_max_pending_items: config.batching.max_pending_items,
        retention_mode: retention_mode(config),
        retention_days: config
            .repository
            .retention
            .map(|policy| policy.retain_days)
            .unwrap_or(0),
        allow_init: config.repository.allow_init,
        v2_commit_coordinator: runtime_facts.repository.v2_commit_coordinator.clone(),
    }
}

/// Returns path-redacted posture findings for the selected profile.
pub fn doctor_findings(config: &RuntimeConfig, profile: AdminReportProfile) -> Vec<AdminFinding> {
    match profile {
        AdminReportProfile::Local => Vec::new(),
        AdminReportProfile::Production => production_doctor_findings(config),
    }
}

fn production_doctor_findings(config: &RuntimeConfig) -> Vec<AdminFinding> {
    let mut findings = Vec::new();

    if matches!(config.anchor, AnchorConfig::Memory) {
        findings.push(AdminFinding::error(
            "anchor.memory",
            "production profile requires a durable external v2 commit anchor",
            "configure RS3_ANCHOR_MODE=kubernetes-lease before exposing the gateway",
        ));
    }

    if config.mode.allows_mutation() && config.repository.retention.is_none() {
        findings.push(AdminFinding::error(
            "retention.missing",
            "production profile requires repository retention",
            "set RS3_REPOSITORY_RETENTION_MODE and RS3_REPOSITORY_RETENTION_DAYS for mutation-capable production serving",
        ));
    }

    if config.mode.allows_mutation() && config.writer_guard != WriterGuardConfig::Required {
        findings.push(AdminFinding::error(
            "writer-guard.required",
            "production read-write serving requires the Kubernetes writer guard",
            "set RS3_WRITER_GUARD=required and use a Kubernetes Lease anchor before serving mutations",
        ));
    }

    if config.repository.allow_init {
        findings.push(AdminFinding::error(
            "repository.init-enabled",
            "production profile requires RS3_ALLOW_REPOSITORY_INIT=false outside deliberate bootstrap",
            "run rs3 init for bootstrap, then set RS3_ALLOW_REPOSITORY_INIT=false before serving",
        ));
    }

    match backend_kind(&config.backend.endpoint) {
        "memory" => findings.push(AdminFinding::error(
            "backend.memory",
            "production profile requires a durable object-store backend",
            "set RS3_BACKEND_ENDPOINT to a durable S3-compatible backend",
        )),
        "filesystem" => findings.push(AdminFinding::error(
            "retention.backend-unsupported",
            "filesystem backend cannot enforce provider retention",
            "use an S3-compatible backend with object-lock retention for production evidence",
        )),
        "unknown" => findings.push(AdminFinding::error(
            "backend.unknown",
            "configured backend is not supported by the gateway runtime",
            "set RS3_BACKEND_ENDPOINT to memory://local, file://..., s3://aws, or an HTTPS S3-compatible endpoint",
        )),
        "s3-compatible" => {}
        _ => {}
    }

    if config.backend.endpoint.starts_with("http://") {
        findings.push(AdminFinding::error(
            "backend.plain-http",
            "production profile requires TLS for S3-compatible backend endpoints",
            "use an HTTPS S3-compatible backend endpoint",
        ));
    }

    if config.static_credentials.is_none() {
        findings.push(AdminFinding::error(
            "auth.credentials-missing",
            "production profile requires configured gateway credentials",
            "set RS3_STATIC_ACCESS_KEY_ID and RS3_STATIC_SECRET_ACCESS_KEY before serving S3",
        ));
    }

    if config.recovery.public_key.is_none() {
        findings.push(AdminFinding::error(
            "recovery.public-key",
            "production profile requires RS3_RECOVERY_PUBLIC_KEY for signed restore bundles",
            "configure RS3_RECOVERY_PUBLIC_KEY with the trusted offline signing key before production restore workflows",
        ));
    }

    if config.mode.allows_mutation()
        && config.maintenance.mode == MaintenanceMode::Off
        && config.repository.retention.is_some()
    {
        findings.push(AdminFinding::error(
            "maintenance.disabled",
            "retention is configured but automatic maintenance is off, so retention renewal will lapse",
            "set RS3_MAINTENANCE_MODE=auto (or manual with an external renewal process) before serving retained repositories",
        ));
    }

    if config.mode.allows_mutation() && config.maintenance.mode == MaintenanceMode::Manual {
        findings.push(AdminFinding::warning(
            "maintenance.manual",
            "maintenance runs only when triggered manually; renewal deadlines and orphan pressure are not serviced automatically",
            "set RS3_MAINTENANCE_MODE=auto unless an external process owns full maintenance",
        ));
    }

    if config.mode.allows_mutation()
        && config.maintenance.mode != MaintenanceMode::Off
        && config.writer_guard != WriterGuardConfig::Required
    {
        findings.push(AdminFinding::warning(
            "maintenance.guard-missing",
            "no maintenance guard is available, so the maintenance supervisor will park instead of running",
            "set RS3_WRITER_GUARD=required with a Kubernetes Lease anchor so the writer fence can guard maintenance",
        ));
    }

    if config.mode.allows_mutation()
        && config.maintenance.mode != MaintenanceMode::Off
        && config.repository.retention.is_some()
        && !provider_conformance_evidence_passed(config)
    {
        findings.push(AdminFinding::error(
            "maintenance.provider-conformance",
            "retained maintenance requires current provider-conformance evidence for the selected profile",
            "run rs3 check-v2-provider --format json against the retained backend, store the report outside that backend, and configure RS3_PROVIDER_CONFORMANCE_REPORT_FILE",
        ));
    }

    if config.repository.retention.is_some_and(|retention| {
        retention.mode == RetentionMode::Governance && retention.retain_days > 0
    }) && config.provider_conformance.principal_fingerprint.is_none()
    {
        findings.push(AdminFinding::error(
            "provider-conformance.principal-unbound",
            "governance-mode evidence is not bound to the backend credential principal",
            "set RS3_PROVIDER_PRINCIPAL_FINGERPRINT to a stable SHA-256 fingerprint of the reviewed credential principal and regenerate provider evidence",
        ));
    }

    if config.mode.allows_mutation()
        && config.maintenance.mode == MaintenanceMode::Auto
        && let Some(retention) = config.repository.retention
    {
        let retention_seconds = u64::from(retention.retain_days).saturating_mul(24 * 60 * 60);
        let automatic_safety_seconds = config
            .maintenance
            .max_interval
            .as_secs()
            .saturating_add(config.maintenance.renewal_horizon.as_secs());
        if retention_seconds <= automatic_safety_seconds {
            findings.push(AdminFinding::error(
                "maintenance.retention-window",
                "the retention window does not exceed the automatic maintenance interval plus renewal safety horizon",
                "increase RS3_REPOSITORY_RETENTION_DAYS or reduce RS3_MAINTENANCE_MAX_INTERVAL_SECONDS after accounting for the longest credible outage and operator response time",
            ));
        }
    }

    findings
}

fn provider_summary(config: &RuntimeConfig) -> AdminProviderSummary {
    let target_fingerprint =
        provider_conformance_target_fingerprint(&V2ProviderCheckConfig::from(config));
    AdminProviderSummary {
        selected_profile: selected_provider_profile(config),
        conformance: provider_conformance_summary(
            &config.provider_conformance,
            selected_provider_profile(config),
            &target_fingerprint,
        ),
    }
}

fn selected_provider_profile(config: &RuntimeConfig) -> &'static str {
    if config
        .repository
        .retention
        .is_some_and(|policy| policy.mode != RetentionMode::None && policy.retain_days > 0)
    {
        "retained-version-object-lock"
    } else if backend_kind(&config.backend.endpoint) == "s3-compatible" {
        "atomic-create"
    } else {
        "dev"
    }
}

fn provider_conformance_summary(
    config: &ProviderConformanceConfig,
    selected_profile: &'static str,
    expected_target_fingerprint: &str,
) -> AdminProviderConformanceSummary {
    let Some(path) = config.report_file.as_ref() else {
        return provider_conformance_unavailable("missing", "provider-conformance.not-configured");
    };
    let Ok(body) = fs::read_to_string(path) else {
        return provider_conformance_unavailable("missing", "provider-conformance.unreadable");
    };
    let Ok(report) = serde_json::from_str::<ProviderConformanceReportJson>(&body) else {
        return provider_conformance_unavailable("invalid", "provider-conformance.invalid-json");
    };
    if report.schema != PROVIDER_CONFORMANCE_SCHEMA {
        return provider_conformance_unavailable("invalid", "provider-conformance.schema");
    }
    if report.target_fingerprint != expected_target_fingerprint {
        return provider_conformance_unavailable("invalid", "provider-conformance.target-mismatch");
    }
    let report_profile = match report.profile.as_str() {
        "dev" => V2ProviderProfile::Dev,
        "atomic-create" => V2ProviderProfile::AtomicCreate,
        "retained-version-object-lock" => V2ProviderProfile::RetainedVersionObjectLock,
        _ => {
            return provider_conformance_unavailable("invalid", "provider-conformance.profile");
        }
    };
    let required_checks = required_v2_provider_check_names(report_profile);
    let mut observed_checks = report
        .checks
        .iter()
        .map(|check| check.name.as_str())
        .collect::<Vec<_>>();
    observed_checks.sort_unstable();
    let mut expected_checks = required_checks;
    expected_checks.sort_unstable();
    if observed_checks != expected_checks {
        return provider_conformance_unavailable("invalid", "provider-conformance.check-manifest");
    }
    let failed_check_count = report
        .checks
        .iter()
        .filter(|check| check.status != "passed")
        .count();
    let legal_hold_checked = report
        .checks
        .iter()
        .any(|check| check.name.starts_with("legal-hold-"));
    let governance_bypass_reviewed = report
        .checks
        .iter()
        .any(|check| check.name == "retained-governance-bypass-review" && check.status == "passed");
    let mut state = if report.passed && failed_check_count == 0 {
        "passed"
    } else {
        "failed"
    };
    let mut reason_code = None;

    if report.profile != selected_profile {
        state = "invalid";
        reason_code = Some("provider-conformance.profile-mismatch");
    } else if provider_conformance_is_from_future(report.generated_at_ms) {
        state = "invalid";
        reason_code = Some("provider-conformance.future-timestamp");
    } else if state == "passed" && provider_conformance_is_stale(report.generated_at_ms, config) {
        state = "stale";
        reason_code = Some("provider-conformance.stale");
    }

    AdminProviderConformanceSummary {
        state,
        reason_code,
        profile: Some(report.profile),
        generated_at_ms: report.generated_at_ms,
        check_count: report.checks.len(),
        failed_check_count,
        legal_hold_checked,
        governance_bypass_reviewed,
    }
}

fn provider_conformance_is_stale(
    generated_at_ms: Option<i64>,
    config: &ProviderConformanceConfig,
) -> bool {
    let Some(generated_at_ms) = generated_at_ms else {
        return true;
    };
    let Some(now_ms) = current_time_ms() else {
        return true;
    };
    let max_age_ms = i64::try_from(config.max_age.as_millis()).unwrap_or(i64::MAX);
    now_ms.saturating_sub(generated_at_ms) > max_age_ms
}

fn provider_conformance_is_from_future(generated_at_ms: Option<i64>) -> bool {
    let (Some(generated_at_ms), Some(now_ms)) = (generated_at_ms, current_time_ms()) else {
        return true;
    };
    generated_at_ms > now_ms.saturating_add(PROVIDER_EVIDENCE_MAX_FUTURE_SKEW_MS)
}

fn provider_conformance_unavailable(
    state: &'static str,
    reason_code: &'static str,
) -> AdminProviderConformanceSummary {
    AdminProviderConformanceSummary {
        state,
        reason_code: Some(reason_code),
        profile: None,
        generated_at_ms: None,
        check_count: 0,
        failed_check_count: 0,
        legal_hold_checked: false,
        governance_bypass_reviewed: false,
    }
}

#[derive(Deserialize, Serialize)]
struct ProviderConformanceReportJson {
    schema: String,
    target_fingerprint: String,
    profile: String,
    passed: bool,
    #[serde(default)]
    generated_at_ms: Option<i64>,
    checks: Vec<ProviderConformanceCheckJson>,
}

#[derive(Deserialize, Serialize)]
struct ProviderConformanceCheckJson {
    name: String,
    status: String,
}

async fn restore_summary(config: &RuntimeConfig) -> AdminRestoreSummary {
    restore_summary_v2(config).await
}

async fn restore_summary_v2(config: &RuntimeConfig) -> AdminRestoreSummary {
    match crate::s3::export_v2_recovery_bundle_from_config(config).await {
        Ok(bundle) => AdminRestoreSummary {
            state: "verified",
            reason_code: None,
            v2_anchor: Some(AdminV2RestoreSummary {
                sequence: bundle.anchor.sequence.get(),
                body_digest: hex::encode(bundle.anchor.body_digest),
                version_bound: bundle.anchor.version_id.is_some(),
                format_generation: bundle.anchor.format_ref.generation,
                format_digest: bundle.anchor.format_ref.digest,
                exported_at_ms: bundle.exported_at_ms,
            }),
        },
        Err(error) => AdminRestoreSummary {
            state: "unavailable",
            reason_code: Some(runtime_error_code(&error)),
            v2_anchor: None,
        },
    }
}

pub(crate) async fn admin_maintenance_summary(config: &RuntimeConfig) -> AdminMaintenanceSummary {
    maintenance_summary(config).await
}

async fn maintenance_summary(config: &RuntimeConfig) -> AdminMaintenanceSummary {
    let computed_at_ms = current_time_ms().unwrap_or(0);
    match crate::s3::v2_quick_maintenance_from_config(config).await {
        Ok(report) => AdminMaintenanceSummary {
            state: "verified",
            computed_at_ms,
            reason_code: None,
            v2: Some(AdminV2MaintenanceSummary {
                anchor_present: report.anchor_present,
                verified_commit_count: report.verified_commit_count,
                last_anchored_commit_age_ms: report.last_anchored_commit_age_ms,
                orphan_candidate_count: report.orphan_candidate_count,
                orphan_candidate_bytes: report.orphan_candidate_bytes,
                protected_orphan_candidate_count: report.protected_orphan_candidate_count,
                oldest_orphan_age_ms: report.oldest_orphan_age_ms,
                retention_renewal_commit_count: report.retention_renewal_commit_count,
                retention_renewal_bytes: report.retention_renewal_bytes,
                retention_renewal_blocked_count: report.retention_renewal_blocked_count,
                retention_renewal_blocked_bytes: report.retention_renewal_blocked_bytes,
            }),
            supervisor: None,
        },
        Err(error) => AdminMaintenanceSummary {
            state: "unavailable",
            computed_at_ms,
            reason_code: Some(runtime_error_code(&error)),
            v2: None,
            supervisor: None,
        },
    }
}

/// Returns whether persisted provider-conformance evidence currently passes.
///
/// The maintenance supervisor re-evaluates this before every destructive run
/// on retained-version provider profiles.
pub fn provider_conformance_evidence_passed(config: &RuntimeConfig) -> bool {
    let target_fingerprint =
        provider_conformance_target_fingerprint(&V2ProviderCheckConfig::from(config));
    provider_conformance_summary(
        &config.provider_conformance,
        selected_provider_profile(config),
        &target_fingerprint,
    )
    .state
        == "passed"
}

fn runtime_error_code(error: &crate::S3BoundaryError) -> &'static str {
    match error {
        crate::S3BoundaryError::MissingStaticCredentials => "runtime.missing-static-credentials",
        crate::S3BoundaryError::UnsupportedAnchorMode => "runtime.unsupported-anchor-mode",
        crate::S3BoundaryError::UnsupportedBackendMode => "runtime.unsupported-backend-mode",
        crate::S3BoundaryError::RepositoryInit { reason } => repository_init_error_code(reason),
    }
}

fn repository_init_error_code(reason: &str) -> &'static str {
    if reason.contains("requires an accepted anchor")
        || reason.contains("v2 commit anchor is missing")
    {
        "runtime.anchor-missing"
    } else if reason.contains("storage operation failed")
        || reason.contains("failed to create S3 backend")
    {
        "runtime.backend-unreachable"
    } else if reason.contains("v2 commit")
        || reason.contains("v2 format root")
        || reason.contains("stale v2 anchor")
        || reason.contains("signature verification failed")
    {
        "runtime.chain-verification"
    } else {
        "runtime.repository-init"
    }
}

/// Returns the path-safe backend kind used in reports and startup logs.
pub fn backend_kind(endpoint: &str) -> &'static str {
    if endpoint == "memory" || endpoint.starts_with("memory://") {
        "memory"
    } else if endpoint.starts_with("file://") {
        "filesystem"
    } else if endpoint == "s3"
        || endpoint.starts_with("https://")
        || endpoint.starts_with("http://")
    {
        "s3-compatible"
    } else {
        "unknown"
    }
}

fn anchor_kind(anchor: &AnchorConfig) -> &'static str {
    match anchor {
        AnchorConfig::Memory => "memory",
        AnchorConfig::KubernetesLease { .. } => "kubernetes-lease",
    }
}

fn backend_is_durable(backend: &BackendConfig) -> bool {
    matches!(
        backend_kind(&backend.endpoint),
        "filesystem" | "s3-compatible"
    )
}

fn retention_capability(backend: &BackendConfig) -> &'static str {
    match backend_kind(&backend.endpoint) {
        "s3-compatible" => "provider-gated",
        "memory" => "test-only",
        "filesystem" | "unknown" => "unsupported",
        _ => "unknown",
    }
}

fn retention_mode(config: &RuntimeConfig) -> &'static str {
    config
        .repository
        .retention
        .map(|policy| match policy.mode {
            RetentionMode::None => "none",
            RetentionMode::Governance => "governance",
            RetentionMode::Compliance => "compliance",
        })
        .unwrap_or("none")
}

/// Returns a path-safe fingerprint over operational runtime settings.
pub fn runtime_config_profile(config: &RuntimeConfig) -> String {
    let anchor = anchor_kind(&config.anchor).to_owned();
    let metrics = config.metrics.bind.is_some().to_string();
    let gateway_mode = config.mode.as_str().to_owned();
    let writer_guard = config.writer_guard.as_str().to_owned();
    let backend_kind = backend_kind(&config.backend.endpoint).to_owned();
    let repository_format = config.repository.format.as_str().to_owned();
    let batch_max_items = config.batching.max_items.to_string();
    let batch_max_delay_ms = config.batching.max_delay.as_millis().to_string();
    let batch_max_pending_items = config.batching.max_pending_items.to_string();
    let payload_segment_size = config.repository.payload_segment_size.to_string();
    let adaptive_payload_segment_size = config.repository.adaptive_payload_segment_size.to_string();
    let decrypted_segment_cache_max_bytes = config
        .repository
        .decrypted_segment_cache_max_bytes
        .to_string();
    let retention_mode = retention_mode(config).to_owned();
    let retention_days = config
        .repository
        .retention
        .map(|policy| policy.retain_days)
        .unwrap_or(0)
        .to_string();
    let allow_repository_init = config.repository.allow_init.to_string();
    let provider_conformance_report_configured = config
        .provider_conformance
        .report_file
        .is_some()
        .to_string();
    let provider_conformance_max_age_seconds =
        config.provider_conformance.max_age.as_secs().to_string();
    let recovery_public_key = config.recovery.public_key.is_some().to_string();
    let static_credentials = config.static_credentials.is_some().to_string();
    let max_put_object_bytes = config.hardening.max_put_object_bytes.to_string();
    let buffered_put_object_bytes = config.hardening.buffered_put_object_bytes.to_string();
    let backend_multipart_part_bytes = config.hardening.backend_multipart_part_bytes.to_string();
    let max_in_flight_upload_body_bytes =
        config.hardening.max_in_flight_upload_body_bytes.to_string();
    let max_in_flight_download_body_bytes = config
        .hardening
        .max_in_flight_download_body_bytes
        .to_string();
    let max_concurrent_connections = config.hardening.max_concurrent_connections.to_string();
    let max_concurrent_requests = config.hardening.max_concurrent_requests.to_string();
    let request_rate_limit_per_second = config.hardening.request_rate_limit_per_second.to_string();
    let fields = [
        anchor.as_bytes(),
        gateway_mode.as_bytes(),
        writer_guard.as_bytes(),
        metrics.as_bytes(),
        backend_kind.as_bytes(),
        repository_format.as_bytes(),
        batch_max_items.as_bytes(),
        batch_max_delay_ms.as_bytes(),
        batch_max_pending_items.as_bytes(),
        payload_segment_size.as_bytes(),
        adaptive_payload_segment_size.as_bytes(),
        decrypted_segment_cache_max_bytes.as_bytes(),
        retention_mode.as_bytes(),
        retention_days.as_bytes(),
        allow_repository_init.as_bytes(),
        provider_conformance_report_configured.as_bytes(),
        provider_conformance_max_age_seconds.as_bytes(),
        recovery_public_key.as_bytes(),
        static_credentials.as_bytes(),
        max_put_object_bytes.as_bytes(),
        buffered_put_object_bytes.as_bytes(),
        backend_multipart_part_bytes.as_bytes(),
        max_in_flight_upload_body_bytes.as_bytes(),
        max_in_flight_download_body_bytes.as_bytes(),
        max_concurrent_connections.as_bytes(),
        max_concurrent_requests.as_bytes(),
        request_rate_limit_per_second.as_bytes(),
    ];

    derive_public_fingerprint(b"rs3:server-runtime-config-profile:v1", &fields)
}

fn current_time_ms() -> Option<i64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis();
    i64::try_from(millis).ok()
}

#[cfg(test)]
mod tests {
    use super::{
        AdminReportProfile, AdminRepositoryRuntimeFacts, AdminRuntimeFacts,
        AdminV2CommitCoordinatorSummary, ProviderConformanceCheckJson,
        ProviderConformanceReportJson, admin_posture_report,
        admin_posture_report_with_runtime_facts, admin_status_report,
        admin_status_report_with_runtime_facts, backend_kind, current_time_ms, doctor_findings,
        provider_conformance_target_fingerprint, runtime_config_profile, runtime_error_code,
    };
    use crate::{
        AnchorConfig, BackendConfig, BatchConfig, GatewayMode, HardeningConfig, MaintenanceConfig,
        MetricsConfig, ProviderConformanceConfig, RecoveryConfig, RepositoryConfig,
        RepositoryFormat, RepositoryKeysConfig, RuntimeConfig, StaticCredentials,
        V2ProviderCheckConfig, WriterGuardConfig,
    };
    use rs3_types::{BackendObjectId, PublicBucket, RepositoryId, RetentionMode, RetentionPolicy};
    use secrecy::SecretString;
    use std::fs;
    use std::time::Duration;

    fn runtime_config() -> RuntimeConfig {
        RuntimeConfig {
            mode: GatewayMode::ReadWrite,
            bind: "127.0.0.1:0"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
            metrics: MetricsConfig { bind: None },
            hardening: HardeningConfig::default(),
            public_bucket: PublicBucket::new("client-private-bucket")
                .unwrap_or_else(|error| panic!("{error}")),
            backend: BackendConfig {
                endpoint: "memory://local-sensitive-endpoint".to_owned(),
                bucket: "backend-secret-bucket".to_owned(),
                prefix: Some("tenant/private/prefix".to_owned()),
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
                retention: Some(RetentionPolicy {
                    mode: RetentionMode::Compliance,
                    retain_days: 30,
                }),
                allow_init: true,
            },
            maintenance: MaintenanceConfig::default(),
            provider_conformance: ProviderConformanceConfig::default(),
            recovery: RecoveryConfig::default(),
            repository_keys: RepositoryKeysConfig {
                repository_id: RepositoryId::new("repo-secret-id")
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
                access_key_id: "access-secret-id".to_owned(),
                secret_access_key: SecretString::from("secret-value"),
            }),
        }
    }

    #[test]
    fn backend_kind_is_path_safe() {
        assert_eq!(backend_kind("memory://local"), "memory");
        assert_eq!(backend_kind("file:///var/lib/private"), "filesystem");
        assert_eq!(backend_kind("https://provider.example"), "s3-compatible");
        assert_eq!(backend_kind("unsupported"), "unknown");
    }

    #[test]
    fn production_doctor_reports_preview_blockers() {
        let mut config = runtime_config();
        config.repository.retention = None;
        config.static_credentials = None;

        let findings = doctor_findings(&config, AdminReportProfile::Production);
        let codes = findings
            .iter()
            .map(|finding| finding.code)
            .collect::<Vec<_>>();

        assert!(codes.contains(&"anchor.memory"));
        assert!(codes.contains(&"retention.missing"));
        assert!(codes.contains(&"backend.memory"));
        assert!(codes.contains(&"auth.credentials-missing"));
        assert!(codes.contains(&"recovery.public-key"));
        assert!(codes.contains(&"repository.init-enabled"));
        assert!(codes.contains(&"writer-guard.required"));
        assert!(
            findings
                .iter()
                .all(|finding| !finding.remediation.is_empty())
        );
    }

    #[test]
    fn production_doctor_rejects_maintenance_off_with_configured_retention() {
        let mut config = runtime_config();
        config.maintenance.mode = crate::MaintenanceMode::Off;

        let findings = doctor_findings(&config, AdminReportProfile::Production);
        let finding = findings
            .iter()
            .find(|finding| finding.code == "maintenance.disabled")
            .unwrap_or_else(|| panic!("expected maintenance.disabled finding"));

        assert_eq!(finding.severity, "error");
        assert!(finding.is_blocking());

        // Without configured retention there is no renewal deadline to lapse.
        config.repository.retention = None;
        let findings = doctor_findings(&config, AdminReportProfile::Production);
        assert!(
            findings
                .iter()
                .all(|finding| finding.code != "maintenance.disabled")
        );
    }

    #[test]
    fn production_doctor_requires_retained_provider_evidence() {
        let config = runtime_config();

        let findings = doctor_findings(&config, AdminReportProfile::Production);
        let finding = findings
            .iter()
            .find(|finding| finding.code == "maintenance.provider-conformance")
            .unwrap_or_else(|| panic!("expected maintenance.provider-conformance finding"));

        assert_eq!(finding.severity, "error");
        assert!(finding.is_blocking());
    }

    #[test]
    fn production_doctor_requires_governance_evidence_principal_binding() {
        let mut config = runtime_config();
        config.repository.retention = Some(RetentionPolicy::new(RetentionMode::Governance, 30));

        let findings = doctor_findings(&config, AdminReportProfile::Production);
        let finding = findings
            .iter()
            .find(|finding| finding.code == "provider-conformance.principal-unbound")
            .unwrap_or_else(|| panic!("expected principal binding finding"));

        assert_eq!(finding.severity, "error");
        assert!(finding.is_blocking());

        config.provider_conformance.principal_fingerprint = Some("a".repeat(64));
        let findings = doctor_findings(&config, AdminReportProfile::Production);
        assert!(
            findings
                .iter()
                .all(|finding| finding.code != "provider-conformance.principal-unbound")
        );
    }

    #[test]
    fn provider_target_fingerprint_binds_credential_principal() {
        let config = runtime_config();
        let mut first = V2ProviderCheckConfig::from(&config);
        first.principal_fingerprint = Some("a".repeat(64));
        let mut second = first.clone();
        second.principal_fingerprint = Some("b".repeat(64));

        assert_ne!(
            provider_conformance_target_fingerprint(&first),
            provider_conformance_target_fingerprint(&second)
        );
    }

    #[test]
    fn production_doctor_rejects_unsafe_automatic_retention_window() {
        let mut config = runtime_config();
        config.repository.retention = Some(RetentionPolicy::new(RetentionMode::Compliance, 14));

        let findings = doctor_findings(&config, AdminReportProfile::Production);
        let finding = findings
            .iter()
            .find(|finding| finding.code == "maintenance.retention-window")
            .unwrap_or_else(|| panic!("expected maintenance.retention-window finding"));

        assert_eq!(finding.severity, "error");
        assert!(finding.is_blocking());
    }

    #[test]
    fn production_doctor_warns_on_manual_maintenance_mode() {
        let mut config = runtime_config();
        config.maintenance.mode = crate::MaintenanceMode::Manual;

        let findings = doctor_findings(&config, AdminReportProfile::Production);
        let finding = findings
            .iter()
            .find(|finding| finding.code == "maintenance.manual")
            .unwrap_or_else(|| panic!("expected maintenance.manual finding"));

        assert_eq!(finding.severity, "warning");
        assert!(!finding.is_blocking());
    }

    #[test]
    fn production_doctor_warns_when_maintenance_guard_is_unavailable() {
        let config = runtime_config();
        assert_eq!(config.writer_guard, WriterGuardConfig::Off);

        let findings = doctor_findings(&config, AdminReportProfile::Production);
        let finding = findings
            .iter()
            .find(|finding| finding.code == "maintenance.guard-missing")
            .unwrap_or_else(|| panic!("expected maintenance.guard-missing finding"));

        assert_eq!(finding.severity, "warning");
        assert!(!finding.is_blocking());

        let mut guarded = runtime_config();
        guarded.writer_guard = WriterGuardConfig::Required;
        let findings = doctor_findings(&guarded, AdminReportProfile::Production);
        assert!(
            findings
                .iter()
                .all(|finding| finding.code != "maintenance.guard-missing")
        );
    }

    #[tokio::test]
    async fn admin_status_attaches_maintenance_supervisor_facts() {
        let config = runtime_config();
        let runtime_facts = AdminRuntimeFacts {
            process_started_at_ms: Some(123),
            repository: AdminRepositoryRuntimeFacts {
                v2_commit_coordinator: None,
            },
            maintenance_supervisor: Some(crate::AdminMaintenanceSupervisorSummary {
                mode: "auto",
                state: "parked",
                parked_reason: Some("maintenance-guard-missing"),
                paused: false,
                nearest_retain_until_ms: None,
                next_trigger_at_ms: None,
                next_trigger_reason: None,
                consecutive_failures: 0,
                last_success_at_ms: None,
                last_run_outcome: None,
                last_run_trigger: None,
                last_run_started_at_ms: None,
                last_run_duration_ms: None,
                last_run_renewed_object_count: None,
                last_run_renewed_bytes: None,
                last_run_deleted_object_count: None,
            }),
        };

        let report = admin_status_report_with_runtime_facts(
            &config,
            AdminReportProfile::Production,
            &runtime_facts,
        )
        .await;

        let supervisor = report
            .maintenance
            .supervisor
            .clone()
            .unwrap_or_else(|| panic!("supervisor facts should be attached"));
        assert_eq!(supervisor.state, "parked");
        assert_eq!(supervisor.parked_reason, Some("maintenance-guard-missing"));
        let json =
            serde_json::to_string(&report.maintenance).unwrap_or_else(|error| panic!("{error}"));
        assert!(!json.contains("client-private-bucket"));
        assert!(!json.contains("backend-secret-bucket"));
        assert!(!json.contains("tenant/private/prefix"));
    }

    #[test]
    fn production_doctor_rejects_plain_http_backend_endpoint() {
        let mut config = runtime_config();
        config.backend.endpoint = "http://storage.example".to_owned();
        config.anchor = AnchorConfig::KubernetesLease {
            namespace: "backup".to_owned(),
            name: "v2-anchor".to_owned(),
            field_manager: "rs3-server".to_owned(),
        };
        config.static_credentials = Some(StaticCredentials {
            access_key_id: "rs3-fixture-access-key".to_owned(),
            secret_access_key: SecretString::from("rs3-fixture-secret-key"),
        });

        let findings = doctor_findings(&config, AdminReportProfile::Production);
        let codes = findings
            .iter()
            .map(|finding| finding.code)
            .collect::<Vec<_>>();

        assert!(codes.contains(&"backend.plain-http"));
    }

    #[test]
    fn runtime_error_code_splits_repository_init_failures() {
        assert_eq!(
            runtime_error_code(&crate::S3BoundaryError::RepositoryInit {
                reason: "v2-preview maintenance requires an accepted anchor".to_owned(),
            }),
            "runtime.anchor-missing"
        );
        assert_eq!(
            runtime_error_code(&crate::S3BoundaryError::RepositoryInit {
                reason: "v2 storage operation failed".to_owned(),
            }),
            "runtime.backend-unreachable"
        );
        assert_eq!(
            runtime_error_code(&crate::S3BoundaryError::RepositoryInit {
                reason: "v2 commit body digest mismatch".to_owned(),
            }),
            "runtime.chain-verification"
        );
    }

    #[test]
    fn config_profile_ignores_configured_names() {
        let mut first = runtime_config();
        let mut second = runtime_config();
        second.public_bucket =
            PublicBucket::new("other-public").unwrap_or_else(|error| panic!("{error}"));
        second.backend.bucket = "other-backend".to_owned();
        second.backend.prefix = Some("other/prefix".to_owned());
        second.repository_keys.repository_id =
            RepositoryId::new("other-repository").unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            runtime_config_profile(&first),
            runtime_config_profile(&second)
        );

        first.repository.payload_segment_size = 2048;
        assert_ne!(
            runtime_config_profile(&first),
            runtime_config_profile(&second)
        );
    }

    #[tokio::test]
    async fn admin_status_report_redacts_config_names_and_secrets() {
        let config = runtime_config();
        let report = admin_status_report(&config, AdminReportProfile::Production).await;
        let json = serde_json::to_string(&report).unwrap_or_else(|error| panic!("{error}"));

        assert!(!json.contains("client-private-bucket"));
        assert!(!json.contains("backend-secret-bucket"));
        assert!(!json.contains("tenant/private/prefix"));
        assert!(!json.contains("repo-secret-id"));
        assert!(!json.contains("secret-value"));
        assert!(!report.security.path_browsing_enabled);
        assert!(!report.security.secrets_exposed);
        assert_eq!(report.security.action_posture, "report-only");
        assert_eq!(report.schema, "rs3.admin-status.preview.v1");
        assert!(report.restore.v2_anchor.is_none());
        assert_eq!(report.maintenance.state, "unavailable");
        assert!(report.maintenance.v2.is_none());
    }

    #[tokio::test]
    async fn admin_status_and_posture_share_common_builder_fields() {
        let config = runtime_config();
        let runtime_facts = AdminRuntimeFacts {
            process_started_at_ms: Some(123),
            repository: AdminRepositoryRuntimeFacts {
                v2_commit_coordinator: Some(AdminV2CommitCoordinatorSummary {
                    poisoned: true,
                    poison_reason: Some("test-poison".to_owned()),
                }),
            },
            maintenance_supervisor: None,
        };

        let status = admin_status_report_with_runtime_facts(
            &config,
            AdminReportProfile::Production,
            &runtime_facts,
        )
        .await;
        let posture = admin_posture_report_with_runtime_facts(
            &config,
            AdminReportProfile::Production,
            &runtime_facts,
        );

        assert_eq!(status.profile, posture.profile);
        assert_eq!(status.runtime, posture.runtime);
        assert_eq!(status.runtime.process_started_at_ms, Some(123));
        assert_eq!(status.backend, posture.backend);
        assert_eq!(status.provider, posture.provider);
        assert_eq!(status.anchor, posture.anchor);
        assert_eq!(status.repository, posture.repository);
        assert_eq!(status.security, posture.security);
        assert_eq!(status.findings, posture.findings);
    }

    #[tokio::test]
    async fn admin_status_reports_v2_maintenance_without_paths_when_unavailable() {
        let config = runtime_config();
        let report = admin_status_report(&config, AdminReportProfile::Production).await;
        let json = serde_json::to_string(&report).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(report.maintenance.state, "unavailable");
        assert_eq!(
            report.maintenance.reason_code,
            Some("runtime.anchor-missing")
        );
        assert_eq!(report.restore.reason_code, Some("runtime.anchor-missing"));
        assert!(report.restore.v2_anchor.is_none());
        assert!(report.maintenance.v2.is_none());
        assert!(!json.contains("client-private-bucket"));
        assert!(!json.contains("backend-secret-bucket"));
        assert!(!json.contains("tenant/private/prefix"));
        assert!(!json.contains("repo-secret-id"));
    }

    #[test]
    fn admin_posture_reports_redacted_provider_conformance_evidence() {
        let mut config = runtime_config();
        config.backend.endpoint = "https://storage.example".to_owned();
        let evidence = retained_provider_evidence(&config);
        config.provider_conformance.report_file = Some(provider_report_file(
            &serde_json::to_string(&evidence).unwrap_or_else(|error| panic!("{error}")),
        ));

        let report = admin_posture_report(&config, AdminReportProfile::Production);
        let json = serde_json::to_string(&report).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(report.schema, "rs3.admin-posture.preview.v1");
        assert_eq!(
            report.provider.selected_profile,
            "retained-version-object-lock"
        );
        assert_eq!(report.provider.conformance.state, "passed");
        assert_eq!(report.provider.conformance.check_count, 29);
        assert!(report.provider.conformance.legal_hold_checked);
        assert!(report.provider.conformance.governance_bypass_reviewed);
        assert!(!json.contains("storage.example"));
        assert!(!json.contains("backend-secret-bucket"));
        assert!(!json.contains("tenant/private/prefix"));
    }

    #[test]
    fn provider_evidence_rejects_incomplete_wrong_target_and_future_reports() {
        let mut config = runtime_config();

        let mut incomplete = retained_provider_evidence(&config);
        incomplete.checks.clear();
        config.provider_conformance.report_file = Some(provider_report_file(
            &serde_json::to_string(&incomplete).unwrap_or_else(|error| panic!("{error}")),
        ));
        let report = admin_posture_report(&config, AdminReportProfile::Production);
        assert_eq!(
            report.provider.conformance.reason_code,
            Some("provider-conformance.check-manifest")
        );

        let mut wrong_target = retained_provider_evidence(&config);
        wrong_target.target_fingerprint = "0".repeat(64);
        config.provider_conformance.report_file = Some(provider_report_file(
            &serde_json::to_string(&wrong_target).unwrap_or_else(|error| panic!("{error}")),
        ));
        let report = admin_posture_report(&config, AdminReportProfile::Production);
        assert_eq!(
            report.provider.conformance.reason_code,
            Some("provider-conformance.target-mismatch")
        );

        let mut future = retained_provider_evidence(&config);
        future.generated_at_ms = current_time_ms().map(|now| now.saturating_add(10 * 60 * 1_000));
        config.provider_conformance.report_file = Some(provider_report_file(
            &serde_json::to_string(&future).unwrap_or_else(|error| panic!("{error}")),
        ));
        let report = admin_posture_report(&config, AdminReportProfile::Production);
        assert_eq!(
            report.provider.conformance.reason_code,
            Some("provider-conformance.future-timestamp")
        );
    }

    #[test]
    fn admin_posture_reports_live_commit_coordinator_poison_fact() {
        let config = runtime_config();
        let runtime_facts = AdminRuntimeFacts {
            process_started_at_ms: Some(123),
            repository: AdminRepositoryRuntimeFacts {
                v2_commit_coordinator: Some(AdminV2CommitCoordinatorSummary {
                    poisoned: true,
                    poison_reason: Some("v2 commit batch rollback failed".to_owned()),
                }),
            },
            maintenance_supervisor: None,
        };

        let report = admin_posture_report_with_runtime_facts(
            &config,
            AdminReportProfile::Production,
            &runtime_facts,
        );
        let coordinator = report
            .repository
            .v2_commit_coordinator
            .unwrap_or_else(|| panic!("coordinator fact should be attached"));

        assert!(coordinator.poisoned);
        assert_eq!(
            coordinator.poison_reason.as_deref(),
            Some("v2 commit batch rollback failed")
        );
    }

    fn provider_report_file(body: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "rs3-provider-report-{}-{}.json",
            std::process::id(),
            current_time_ms().unwrap_or(0)
        ));
        fs::write(&path, body).unwrap_or_else(|error| panic!("{error}"));
        path
    }

    fn retained_provider_evidence(config: &RuntimeConfig) -> ProviderConformanceReportJson {
        let target_fingerprint =
            provider_conformance_target_fingerprint(&V2ProviderCheckConfig::from(config));
        let checks = rs3_repository::v2::required_v2_provider_check_names(
            rs3_repository::v2::V2ProviderProfile::RetainedVersionObjectLock,
        )
        .into_iter()
        .map(|name| ProviderConformanceCheckJson {
            name: name.to_owned(),
            status: "passed".to_owned(),
        })
        .collect();
        ProviderConformanceReportJson {
            schema: "rs3.v2-provider-conformance.v3".to_owned(),
            target_fingerprint,
            profile: "retained-version-object-lock".to_owned(),
            passed: true,
            generated_at_ms: current_time_ms(),
            checks,
        }
    }
}
