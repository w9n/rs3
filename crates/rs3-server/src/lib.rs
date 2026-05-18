//! Server-side runtime configuration and request identity contracts.

mod admin;
mod admin_http;
mod config;
mod identity;
mod s3;
mod server;

pub use admin::{
    AdminAnchorSummary, AdminBackendSummary, AdminFinding, AdminMaintenanceSummary,
    AdminPostureReport, AdminProviderConformanceSummary, AdminProviderSummary, AdminReportProfile,
    AdminRepositorySummary, AdminRestoreSummary, AdminRuntimeSummary, AdminSecuritySummary,
    AdminStatusReport, AdminV2MaintenanceSummary, AdminV2RestoreSummary, admin_posture_report,
    admin_status_report, backend_kind, doctor_findings, runtime_config_profile,
};
pub use admin_http::{
    AdminBearerToken, AdminHttpAuth, AdminHttpAuthError, AdminHttpConfig, AdminHttpServer,
    AdminHttpServerError, AdminHttpService,
};
pub use config::{
    AnchorConfig, BackendConfig, BatchConfig, ConfigError, GatewayMode, HardeningConfig,
    MetricsConfig, ProviderConformanceConfig, RepositoryConfig, RepositoryFormat,
    RepositoryKeysConfig, RuntimeConfig,
};
pub use identity::{
    AuthError, Authorizer, Identity, IdentityProvider, RequestAction, StaticCredentialProvider,
    StaticCredentials,
};
pub use rs3_repository::v2::{
    V2AnchorState, V2ProviderCheckStatus, V2ProviderConformanceCheck, V2ProviderConformanceReport,
    V2ProviderProfile, V2RecoveryBundle,
};
pub use s3::{
    GatewayS3Boundary, RuntimeV2ProviderConformanceOptions, S3BoundaryError, S3Hardening,
    V2_RESTORE_BUNDLE_SCHEMA, V2AnchorImportReport, check_v2_provider_conformance_from_config,
    export_v2_recovery_bundle_from_config, import_v2_anchor_from_config,
    write_v2_index_snapshot_from_config,
};
pub use secrecy::SecretString;
pub use server::{GatewayServer, GatewayServerError};
