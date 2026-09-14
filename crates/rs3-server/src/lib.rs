//! Server-side runtime configuration and request identity contracts.

mod admin;
mod admin_http;
mod config;
mod identity;
mod maintenance;
mod maintenance_offline;
mod s3;
mod server;

pub use admin::{
    AdminAnchorSummary, AdminBackendSummary, AdminFinding, AdminMaintenanceSummary,
    AdminMaintenanceSupervisorSummary, AdminPostureReport, AdminProviderConformanceSummary,
    AdminProviderSummary, AdminReadiness, AdminReadinessSource, AdminReportProfile,
    AdminRepositoryRuntimeFacts, AdminRepositorySummary, AdminRestoreSummary, AdminRuntimeFacts,
    AdminRuntimeFactsSource, AdminRuntimeSummary, AdminSecuritySummary, AdminStatusReport,
    AdminV3CommitCoordinatorSummary, AdminV3MaintenanceSummary, AdminV3RestoreSummary,
    PROVIDER_CONFORMANCE_SCHEMA, admin_posture_report, admin_posture_report_with_runtime_facts,
    admin_status_report, admin_status_report_with_runtime_facts, backend_kind, doctor_findings,
    encode_provider_conformance_evidence, provider_conformance_evidence_passed,
    provider_conformance_implementation_fingerprint, provider_conformance_target_fingerprint,
    runtime_config_profile,
};
pub use admin_http::{
    AdminBearerToken, AdminHttpAuth, AdminHttpAuthError, AdminHttpConfig, AdminHttpServer,
    AdminHttpServerError, AdminHttpService,
};
pub use config::{
    AnchorConfig, BackendConfig, BackendTimeoutConfig, BatchConfig, ConfigError, GatewayMode,
    HardeningConfig, MaintenanceConfig, MaintenanceMode, MetricsConfig, ProviderConformanceConfig,
    RecoveryConfig, RepositoryConfig, RepositoryFormat, RepositoryKeyContextConfig,
    RepositoryKeysConfig, RepositoryToolConfig, RuntimeConfig, V3ProviderCheckConfig,
    WriterGuardConfig,
};
pub use identity::{
    AuthError, Authorizer, Identity, IdentityProvider, RequestAction, StaticCredentialProvider,
    StaticCredentials,
};
pub use maintenance::{
    MAINTENANCE_PLAN_STALE_REASON, MaintenanceClock, MaintenanceControlError,
    MaintenanceControlHandle, MaintenanceDryRunOutcome, MaintenanceOperationRecord,
    MaintenanceOperationSource, MaintenanceRunPhase, MaintenanceRunSummary, MaintenanceRuntime,
    MaintenanceStatusHandle, MaintenanceStatusSnapshot, MaintenanceSupervisor,
    MaintenanceSupervisorConfig, MaintenanceSupervisorHandle, MaintenanceSupervisorState,
    MaintenanceTriggerHandle, MaintenanceTriggerReason, SystemMaintenanceClock,
    default_maintenance_orphan_gc_options,
};
pub use maintenance_offline::{
    OfflineMaintenanceCommand, OfflineMaintenanceEnvironment, OfflineMaintenanceError,
    OfflineMaintenanceFence, OfflineMaintenanceOutcome, OfflineMaintenanceRequest,
    run_offline_maintenance,
};
#[cfg(feature = "k8s")]
pub use s3::offline_maintenance_runtime_from_writer_fence;
#[cfg(feature = "k8s")]
pub use s3::v3_bootstrap_journal_state;
pub use s3::{
    DoctorProbeCheck, DoctorProbeReport, GatewayS3Boundary, KeyringEnvelopeInspectOptions,
    KeyringEnvelopeInspectReport, KeyringEnvelopeRewrapOptions, KeyringEnvelopeRewrapReport,
    RuntimeV3ProviderConformanceOptions, S3BoundaryError, S3Hardening, V3_RESTORE_BUNDLE_SCHEMA,
    V3AnchorImportOptions, V3AnchorImportReport, V3PreparedRepositoryInit, V3ProbeObservation,
    V3RecoveryBundleVerificationOptions, V3RecoveryBundleVerificationReport,
    V3RepositoryInitReport, check_v3_provider_conformance_from_config,
    check_v3_provider_conformance_from_provider_config, doctor_probe_from_config,
    export_v3_recovery_bundle_from_config, import_v3_anchor_from_config,
    init_v3_repository_from_config, inspect_keyring_envelope_from_tool_config,
    inspect_keyring_envelope_with_store, offline_maintenance_runtime_from_config,
    recovery_points_from_config, rewrap_keyring_envelope_from_tool_config,
    rewrap_keyring_envelope_with_store, v3_bootstrap_journal_is_initialized,
    verify_v3_recovery_bundle_from_tool_config, verify_v3_recovery_bundle_with_store,
};
pub use server::{GatewayServer, GatewayServerError};
