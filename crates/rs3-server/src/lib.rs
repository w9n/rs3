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
    AdminV2CommitCoordinatorSummary, AdminV2MaintenanceSummary, AdminV2RestoreSummary,
    admin_posture_report, admin_posture_report_with_runtime_facts, admin_status_report,
    admin_status_report_with_runtime_facts, backend_kind, doctor_findings,
    provider_conformance_evidence_passed, provider_conformance_target_fingerprint,
    runtime_config_profile,
};
pub use admin_http::{
    AdminBearerToken, AdminHttpAuth, AdminHttpAuthError, AdminHttpConfig, AdminHttpServer,
    AdminHttpServerError, AdminHttpService,
};
pub use config::{
    AnchorConfig, BackendConfig, BatchConfig, ConfigError, GatewayMode, HardeningConfig,
    MaintenanceConfig, MaintenanceMode, MetricsConfig, ProviderConformanceConfig, RecoveryConfig,
    RepositoryConfig, RepositoryFormat, RepositoryKeyContextConfig, RepositoryKeysConfig,
    RepositoryToolConfig, RuntimeConfig, V2ProviderCheckConfig, WriterGuardConfig,
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
pub use s3::{
    DoctorProbeCheck, DoctorProbeReport, GatewayS3Boundary, KeyringEnvelopeInspectOptions,
    KeyringEnvelopeInspectReport, KeyringEnvelopeRewrapOptions, KeyringEnvelopeRewrapReport,
    RuntimeV2ProviderConformanceOptions, S3BoundaryError, S3Hardening, V2_RESTORE_BUNDLE_SCHEMA,
    V2AnchorImportOptions, V2AnchorImportReport, V2RecoveryBundleVerificationOptions,
    V2RecoveryBundleVerificationReport, V2RepositoryInitReport,
    check_v2_provider_conformance_from_config, check_v2_provider_conformance_from_provider_config,
    doctor_probe_from_config, export_v2_recovery_bundle_from_config, import_v2_anchor_from_config,
    init_v2_repository_from_config, inspect_keyring_envelope_from_tool_config,
    inspect_keyring_envelope_with_store, offline_maintenance_runtime_from_config,
    rewrap_keyring_envelope_from_tool_config, rewrap_keyring_envelope_with_store,
    verify_v2_recovery_bundle_from_tool_config, verify_v2_recovery_bundle_with_store,
    write_v2_index_snapshot_from_config,
};
pub use server::{GatewayServer, GatewayServerError};
