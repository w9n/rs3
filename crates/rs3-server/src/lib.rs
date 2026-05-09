//! Server-side runtime configuration and request identity contracts.

mod admin;
mod admin_http;
mod config;
mod identity;
mod s3;
mod server;

pub use admin::{
    AdminAnchorSummary, AdminBackendSummary, AdminCheckpointSummary, AdminFinding,
    AdminKeyringEnvelopeSummary, AdminReportProfile, AdminRepositorySummary, AdminRestoreSummary,
    AdminRuntimeSummary, AdminSecuritySummary, AdminStatusReport, admin_status_report,
    backend_kind, doctor_findings, runtime_config_profile,
};
pub use admin_http::{
    AdminBearerToken, AdminHttpAuth, AdminHttpAuthError, AdminHttpConfig, AdminHttpServer,
    AdminHttpServerError, AdminHttpService,
};
pub use config::{
    AnchorConfig, BackendConfig, BatchConfig, ConfigError, GatewayMode, MetricsConfig,
    RepositoryConfig, RepositoryKeysConfig, RuntimeConfig,
};
pub use identity::{
    AuthError, Authorizer, Identity, IdentityProvider, RequestAction, StaticCredentialProvider,
    StaticCredentials,
};
pub use s3::{
    AnchorImportReport, AnchorRecoveryError, AnchorRecoveryOptions, AnchorRecoveryReport,
    GatewayS3Boundary, KeyRotationError, KeyRotationOptions, KeyRotationReport,
    RESTORE_BUNDLE_SCHEMA, RestoreBundleKeyringEnvelope, RestoreTrustBundle,
    RotatedKeyringEnvelope, S3BoundaryError, S3Hardening, export_restore_bundle_from_config,
    import_anchor_from_config, recover_anchor_from_config, rotate_key_from_config,
};
pub use secrecy::SecretString;
pub use server::{GatewayServer, GatewayServerError};
