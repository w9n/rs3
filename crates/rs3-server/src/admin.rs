//! Path-redacted operator report facts.
//!
//! These reports are preview-scoped facts for local tooling and external
//! management integrations. They are intentionally not a complete workflow API:
//! orchestration, approvals, management workflows, multi-management workflows, and audit model
//! require a separate documented authorization and audit design and stabilization decision.

use crate::{AnchorConfig, BackendConfig, RuntimeConfig};
use rs3_crypto::derive_public_fingerprint;
use rs3_types::RetentionMode;
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

const ADMIN_STATUS_SCHEMA: &str = "rs3.admin-status.preview.v1";

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

/// Runtime posture fields that are safe to show in operator reports.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdminRuntimeSummary {
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
    /// Machine-readable reason code when maintenance facts are unavailable.
    pub reason_code: Option<&'static str>,
    /// v2 maintenance facts, when the configured repository format is v2.
    pub v2: Option<AdminV2MaintenanceSummary>,
}

/// Path-redacted v2 maintenance facts.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdminV2MaintenanceSummary {
    /// Whether the v2 anchor is present.
    pub anchor_present: bool,
    /// Verified commit count in the anchor-selected chain.
    pub verified_commit_count: usize,
    /// Unanchored v2 commit candidates observed under the commit prefix.
    pub orphan_candidate_count: usize,
    /// Orphan candidates blocked by retention or legal hold.
    pub protected_orphan_candidate_count: usize,
    /// Oldest visible orphan age in milliseconds, when provider timestamps exist.
    pub oldest_orphan_age_ms: Option<u128>,
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
}

impl AdminFinding {
    fn error(code: &'static str, message: &'static str) -> Self {
        Self {
            severity: "error",
            code,
            message,
        }
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
    let restore = restore_summary(config).await;
    let maintenance = maintenance_summary(config).await;
    AdminStatusReport {
        schema: ADMIN_STATUS_SCHEMA,
        profile: profile.as_str(),
        generated_at_ms: current_time_ms().unwrap_or(0),
        runtime: AdminRuntimeSummary {
            gateway_mode: config.mode.as_str(),
            config_profile: runtime_config_profile(config),
            static_credentials_configured: config.static_credentials.is_some(),
            metrics_configured: config.metrics.bind.is_some(),
        },
        backend: AdminBackendSummary {
            kind: backend_kind(&config.backend.endpoint),
            durable: backend_is_durable(&config.backend),
            retention_capability: retention_capability(&config.backend),
        },
        anchor: AdminAnchorSummary {
            kind: anchor_kind(&config.anchor),
            external: !matches!(config.anchor, AnchorConfig::Memory),
        },
        repository: AdminRepositorySummary {
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
        },
        security: AdminSecuritySummary {
            path_browsing_enabled: false,
            secrets_exposed: false,
            max_put_object_bytes: config.hardening.max_put_object_bytes,
            buffered_put_object_bytes: config.hardening.buffered_put_object_bytes,
            backend_multipart_part_bytes: config.hardening.backend_multipart_part_bytes,
            max_in_flight_upload_body_bytes: config.hardening.max_in_flight_upload_body_bytes,
            max_concurrent_connections: config.hardening.max_concurrent_connections,
            max_concurrent_requests: config.hardening.max_concurrent_requests,
            request_rate_limit_per_second: config.hardening.request_rate_limit_per_second,
            action_posture: "report-only",
        },
        restore,
        maintenance,
        findings: doctor_findings(config, profile),
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
        ));
    }

    if config.mode.allows_mutation() && config.repository.retention.is_none() {
        findings.push(AdminFinding::error(
            "retention.missing",
            "production profile requires repository retention",
        ));
    }

    match backend_kind(&config.backend.endpoint) {
        "memory" => findings.push(AdminFinding::error(
            "backend.memory",
            "production profile requires a durable object-store backend",
        )),
        "filesystem" => findings.push(AdminFinding::error(
            "retention.backend-unsupported",
            "filesystem backend cannot enforce provider retention",
        )),
        "unknown" => findings.push(AdminFinding::error(
            "backend.unknown",
            "configured backend is not supported by the gateway runtime",
        )),
        "s3-compatible" => {}
        _ => {}
    }

    if config.backend.endpoint.starts_with("http://") {
        findings.push(AdminFinding::error(
            "backend.plain-http",
            "production profile requires TLS for S3-compatible backend endpoints",
        ));
    }

    if config.static_credentials.is_none() {
        findings.push(AdminFinding::error(
            "auth.static-credentials",
            "production profile requires configured gateway credentials",
        ));
    }

    findings
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

async fn maintenance_summary(config: &RuntimeConfig) -> AdminMaintenanceSummary {
    match crate::s3::v2_quick_maintenance_from_config(config).await {
        Ok(report) => AdminMaintenanceSummary {
            state: "verified",
            reason_code: None,
            v2: Some(AdminV2MaintenanceSummary {
                anchor_present: report.anchor_present,
                verified_commit_count: report.verified_commit_count,
                orphan_candidate_count: report.orphan_candidate_count,
                protected_orphan_candidate_count: report.protected_orphan_candidate_count,
                oldest_orphan_age_ms: report.oldest_orphan_age_ms,
            }),
        },
        Err(error) => AdminMaintenanceSummary {
            state: "unavailable",
            reason_code: Some(runtime_error_code(&error)),
            v2: None,
        },
    }
}

fn runtime_error_code(error: &crate::S3BoundaryError) -> &'static str {
    match error {
        crate::S3BoundaryError::MissingStaticCredentials => "runtime.missing-static-credentials",
        crate::S3BoundaryError::UnsupportedAnchorMode => "runtime.unsupported-anchor-mode",
        crate::S3BoundaryError::UnsupportedBackendMode => "runtime.unsupported-backend-mode",
        crate::S3BoundaryError::RepositoryInit { .. } => "runtime.repository-init",
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
    let static_credentials = config.static_credentials.is_some().to_string();
    let max_put_object_bytes = config.hardening.max_put_object_bytes.to_string();
    let buffered_put_object_bytes = config.hardening.buffered_put_object_bytes.to_string();
    let backend_multipart_part_bytes = config.hardening.backend_multipart_part_bytes.to_string();
    let max_in_flight_upload_body_bytes =
        config.hardening.max_in_flight_upload_body_bytes.to_string();
    let max_concurrent_connections = config.hardening.max_concurrent_connections.to_string();
    let max_concurrent_requests = config.hardening.max_concurrent_requests.to_string();
    let request_rate_limit_per_second = config.hardening.request_rate_limit_per_second.to_string();
    let fields = [
        anchor.as_bytes(),
        gateway_mode.as_bytes(),
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
        static_credentials.as_bytes(),
        max_put_object_bytes.as_bytes(),
        buffered_put_object_bytes.as_bytes(),
        backend_multipart_part_bytes.as_bytes(),
        max_in_flight_upload_body_bytes.as_bytes(),
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
        AdminReportProfile, admin_status_report, backend_kind, doctor_findings,
        runtime_config_profile,
    };
    use crate::{
        AnchorConfig, BackendConfig, BatchConfig, GatewayMode, HardeningConfig, MetricsConfig,
        RepositoryConfig, RepositoryFormat, RepositoryKeysConfig, RuntimeConfig, SecretString,
        StaticCredentials,
    };
    use rs3_types::{BackendObjectId, PublicBucket, RepositoryId, RetentionMode, RetentionPolicy};
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
            },
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
        assert!(codes.contains(&"auth.static-credentials"));
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
            access_key_id: "access".to_owned(),
            secret_access_key: SecretString::from("secret"),
        });

        let findings = doctor_findings(&config, AdminReportProfile::Production);
        let codes = findings
            .iter()
            .map(|finding| finding.code)
            .collect::<Vec<_>>();

        assert!(codes.contains(&"backend.plain-http"));
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
    async fn admin_status_reports_v2_maintenance_without_paths_when_unavailable() {
        let config = runtime_config();
        let report = admin_status_report(&config, AdminReportProfile::Production).await;
        let json = serde_json::to_string(&report).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(report.maintenance.state, "unavailable");
        assert_eq!(
            report.maintenance.reason_code,
            Some("runtime.repository-init")
        );
        assert_eq!(report.restore.reason_code, Some("runtime.repository-init"));
        assert!(report.restore.v2_anchor.is_none());
        assert!(report.maintenance.v2.is_none());
        assert!(!json.contains("client-private-bucket"));
        assert!(!json.contains("backend-secret-bucket"));
        assert!(!json.contains("tenant/private/prefix"));
        assert!(!json.contains("repo-secret-id"));
    }
}
