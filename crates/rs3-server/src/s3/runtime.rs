//! Runtime repository construction for the S3 service.

use super::S3BoundaryError;
use super::bounded_io::{
    BoundedListing, CONTROL_LIST_BUDGET, prefix_has_any_object, read_bounded_object_at,
};
use super::repository_init;
#[cfg(feature = "k8s")]
use super::runtime_builders::build_v3_anchor_with_writer_fence;
use super::runtime_builders::{StoreBuild, build_store, build_v3_anchor, coordinator_options};
use super::runtime_handles::{RuntimeStore, RuntimeV3Anchor};
use super::runtime_keyring::{
    open_gateway_keyring_reference, repository_key_context_for_envelope,
    repository_key_context_for_salt, retained_version_id, retained_version_required, secret_hex,
    unanchored_gateway_keyring,
};
use crate::admin::{
    AdminReadiness, AdminReadinessSource, AdminRepositoryRuntimeFacts, AdminRuntimeFacts,
    AdminRuntimeFactsSource, AdminV3CommitCoordinatorSummary,
};
use crate::config::KEYRING_WRAPPING_KEY_HEX_ENV;
use crate::maintenance::{MaintenanceRunPhase, MaintenanceRuntime};
use crate::{
    BackendConfig, GatewayMode, RepositoryFormat, RepositoryKeysConfig, RuntimeConfig,
    V3ProviderCheckConfig,
};
use bytes::Bytes;
use futures_util::Stream;
use rs3_crypto::{KeyRing, MAX_FORMAT_ENVELOPE_OBJECT_BYTES, RepositoryEnvelope};
use rs3_index::KeyringEnvelopeReference;
#[cfg(feature = "k8s")]
use rs3_k8s::WriterFence;
pub use rs3_repository::v3::V3_RESTORE_BUNDLE_SCHEMA;
use rs3_repository::v3::{
    V3AnchorState, V3AuthenticatedReadBody, V3CommitAnchor, V3CommitCoordinator, V3CommitKey,
    V3CommitStore, V3CommitStoreOptions, V3FormatRef, V3FormatRoot, V3FullGcApplyOptions,
    V3FullGcDryRunOptions, V3FullGcDryRunReport, V3FullGcPlanPreview, V3FullMaintenanceReport,
    V3KeyringEnvelopeRootRef, V3MaintenanceCancellation, V3MaintenanceGuard, V3MaintenanceReport,
    V3ProviderConformanceOptions, V3ProviderConformanceReport, V3ProviderProfile,
    V3QuickMaintenanceOptions, V3RecoveryBundle, V3Repository, V3ResolvedObject,
    check_v3_provider_conformance, v3_format_object_id,
};
use rs3_repository::{
    DeleteOutcome, RepositoryCopyOptions, RepositoryError, RepositoryListEntry,
    RepositoryObjectMetadata, RepositoryOptions, RepositoryPutOptions,
};
#[cfg(test)]
use rs3_storage::MemoryBlobStore;
use rs3_storage::{BlobListMode, BlobMetadata, BlobStore, ByteRange, PutOptions, StorageError};
use rs3_types::{
    BackendObjectId, KeyPurpose, LogicalPath, RetentionMode, RetentionPolicy, Sequence,
};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(feature = "k8s")]
mod bootstrap;
#[cfg(feature = "k8s")]
mod onboarding;

mod recovery_view;
pub use recovery_view::recovery_points_from_config;

const V3_FORMAT_ENVELOPE_CONTENT_TYPE: &str = "application/vnd.rs3.format-envelope+cbor";

/// Result of importing a trusted v3 anchor bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V3AnchorImportReport {
    /// Verified anchor state named by the trusted bundle.
    pub anchor: V3AnchorState,
    /// True when this call recreated a missing anchor.
    pub applied: bool,
    /// Number of commits verified from the imported anchor to the nearest snapshot.
    pub verified_commit_count: usize,
}

/// Result of one-shot v3 repository initialization or verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V3RepositoryInitReport {
    /// Anchor state verified after initialization.
    pub anchor: V3AnchorState,
    /// True when this run completed an unfinished repository initialization.
    pub initialized: bool,
    /// Number of commits verified from the anchor to the nearest snapshot.
    pub verified_commit_count: usize,
    /// Complete provider-probe runs durably reserved by this onboarding journal.
    pub probe_attempts: u8,
    /// Whether journaled bootstrap verified and removed its synthetic payload.
    pub payload_restore_verified: bool,
    /// Last bounded observation of synthetic probe versions, if available.
    pub probe_observation: Option<V3ProbeObservation>,
}

/// Advisory, path-redacted facts about a bounded synthetic probe inventory.
/// Counts are observations, never completeness or deletion authority. Incomplete
/// multipart sessions are not covered by object-version listing.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V3ProbeObservation {
    /// Reserved attempts included in this observation's namespace.
    pub attempts_covered: u8,
    /// Time of observation, in Unix milliseconds; reused reports keep this time.
    pub observed_at_ms: i64,
    /// Whether the provider's bounded listing ended, not proof of completeness.
    pub listing_exhausted: bool,
    /// Distinct versions observed through LIST.
    pub observed_versions: u32,
    /// Versions whose exact HEAD identity was verified.
    pub verified_metadata_versions: u32,
    /// Sum of lengths from verified metadata, excluding unavailable versions.
    pub observed_bytes: u64,
    /// Versions with a reported retention mode and absolute deadline.
    pub retention_reported_versions: u32,
    /// Versions reporting legal hold ON, potentially indefinitely protected.
    pub legal_hold_on_versions: u32,
    /// Versions without an observed retention deadline or legal hold ON,
    /// including unavailable exact HEAD metadata.
    pub unknown_protection_versions: u32,
    /// Earliest reported retention deadline, which alone does not permit deletion.
    pub earliest_retain_until_ms: Option<i64>,
    /// Latest reported retention deadline, excluding indefinite legal holds.
    pub latest_retain_until_ms: Option<i64>,
    /// Explicitly false: object-version listing cannot inventory unfinished MPUs.
    pub multipart_sessions_observed: bool,
    /// Bounded warning code when the observation is interrupted or incomplete.
    pub warning: Option<String>,
}

/// Result of an opt-in live doctor probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoctorProbeReport {
    /// Individual path-redacted probe checks.
    pub checks: Vec<DoctorProbeCheck>,
}

impl DoctorProbeReport {
    /// True when every probe passed.
    pub fn passed(&self) -> bool {
        self.checks.iter().all(DoctorProbeCheck::is_passed)
    }

    /// Count of failed probe checks.
    pub fn failed_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|check| !check.is_passed())
            .count()
    }
}

/// Single path-redacted doctor probe result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoctorProbeCheck {
    /// Stable probe code.
    pub code: &'static str,
    /// True when the live check succeeded.
    pub passed: bool,
    /// Operator-facing probe message.
    pub message: &'static str,
    /// Operator-facing remediation hint for failed probes.
    pub remediation: &'static str,
}

impl DoctorProbeCheck {
    fn ok(code: &'static str, message: &'static str) -> Self {
        Self {
            code,
            passed: true,
            message,
            remediation: "",
        }
    }

    fn failed(code: &'static str, message: &'static str, remediation: &'static str) -> Self {
        Self {
            code,
            passed: false,
            message,
            remediation,
        }
    }

    /// True when the probe passed.
    pub fn is_passed(&self) -> bool {
        self.passed
    }
}

/// Operator-provided options for v3 anchor import.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V3AnchorImportOptions {
    /// External weak-subjectivity floor that the imported anchor must satisfy.
    pub min_sequence: Sequence,
    /// Allow importing an anchor below newer commit objects seen in storage.
    pub force_rollback: bool,
}

/// Runtime options for v3 provider conformance probes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuntimeV3ProviderConformanceOptions {
    /// Disjoint S3 backend prefix for synthetic probes. A random prefix is the default.
    pub probe_prefix: Option<String>,
    /// Whether legal-hold add/verify probes should run.
    pub legal_hold: bool,
    /// Whether an operator has reviewed governance-retention bypass permissions.
    pub governance_bypass_reviewed: bool,
}

#[derive(Clone)]
pub(super) struct RuntimeRepository {
    store: RuntimeStore,
    repository: Arc<V3Repository<RuntimeStore>>,
    recovery_view: Option<Arc<rs3_repository::v3::V3RecoveryView<RuntimeStore>>>,
    coordinator: Arc<V3CommitCoordinator<RuntimeStore, RuntimeV3Anchor>>,
    anchor: RuntimeV3Anchor,
    initialized: bool,
    require_anchor_version: bool,
    #[cfg(test)]
    memory_store: Option<MemoryBlobStore>,
    #[cfg(test)]
    memory_anchor: Option<rs3_repository::v3::V3MemoryAnchor>,
}

#[derive(Clone)]
pub(crate) struct RuntimeRepositoryAdminFacts {
    repository: RuntimeRepository,
    process_started_at_ms: i64,
}

pub(super) struct RuntimeCommittedPut {
    pub(super) metadata: RepositoryObjectMetadata,
}

pub(super) struct RuntimeResolvedObject {
    inner: V3ResolvedObject,
}

impl RuntimeResolvedObject {
    pub(super) fn metadata(&self) -> &RepositoryObjectMetadata {
        self.inner.metadata()
    }
}

struct LoadedV3Repository {
    keyring: KeyRing,
    keyring_ref: V3KeyringEnvelopeRootRef,
    format_ref: V3FormatRef,
    anchor_present: bool,
    /// Public salt bound into the format root and keyring envelope.
    repository_salt: Vec<u8>,
}

/// A decrypted format root together with the public salt its envelope carried.
struct OpenedFormatRoot {
    root: V3FormatRoot,
    repository_salt: Vec<u8>,
}

fn bootstrap_commit_options(
    config: &RuntimeConfig,
    loaded: &LoadedV3Repository,
) -> Result<V3CommitStoreOptions, S3BoundaryError> {
    let provider_profile = v3_provider_profile(&config.backend, config.repository.retention);
    // Recovery history records exact protected object versions. Only the
    // retained profile establishes that provider contract at the gateway
    // boundary; Dev and AtomicCreate retain their native publication path.
    let recovery_policy = (provider_profile == V3ProviderProfile::RetainedVersionObjectLock)
        .then_some(config.recovery.policy);
    Ok(V3CommitStoreOptions::for_profile(
        provider_profile,
        config.repository_keys.repository_id.clone(),
        loaded.keyring_ref.commit_ref().map_err(repository_init)?,
        loaded.format_ref.clone(),
    )
    .with_maintenance_keyring_envelope_ref(loaded.keyring_ref.clone())
    .with_recovery_policy(recovery_policy)
    .with_recovery_maintenance_budgets(config.maintenance.budgets())
    .with_retention(config.repository.retention)
    .with_stream_read_stall_timeout(config.hardening.stream_read_stall_timeout))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RuntimeStartup {
    Current,
    HistoryOnly,
}

impl RuntimeRepository {
    pub(super) async fn from_config(config: &RuntimeConfig) -> Result<Self, S3BoundaryError> {
        Self::from_config_inner(config, None, None, RuntimeStartup::Current).await
    }

    #[cfg(feature = "k8s")]
    pub(super) async fn from_config_with_writer_fence(
        config: &RuntimeConfig,
        writer_fence: WriterFence,
    ) -> Result<Self, S3BoundaryError> {
        let maintenance_guard: Arc<dyn V3MaintenanceGuard> = Arc::new(writer_fence.clone());
        Self::from_config_inner(
            config,
            Some(writer_fence),
            Some(maintenance_guard),
            RuntimeStartup::Current,
        )
        .await
    }

    pub(super) async fn from_config_with_maintenance_guard(
        config: &RuntimeConfig,
        maintenance_guard: Arc<dyn V3MaintenanceGuard>,
    ) -> Result<Self, S3BoundaryError> {
        Self::from_config_inner(
            config,
            None,
            Some(maintenance_guard),
            RuntimeStartup::Current,
        )
        .await
    }

    async fn from_config_inner(
        config: &RuntimeConfig,
        #[cfg(feature = "k8s")] writer_fence: Option<WriterFence>,
        #[cfg(not(feature = "k8s"))] _writer_fence: Option<()>,
        maintenance_guard: Option<Arc<dyn V3MaintenanceGuard>>,
        startup: RuntimeStartup,
    ) -> Result<Self, S3BoundaryError> {
        let store = build_store(&config.backend).await?;
        store
            .validate_write_policy(config.mode, config.repository.retention)
            .await?;
        #[cfg(not(feature = "k8s"))]
        let writer_fence = _writer_fence;
        Self::from_preflighted_store(config, store, writer_fence, maintenance_guard, startup).await
    }

    async fn from_preflighted_store(
        config: &RuntimeConfig,
        store: StoreBuild,
        #[cfg(feature = "k8s")] writer_fence: Option<WriterFence>,
        #[cfg(not(feature = "k8s"))] _writer_fence: Option<()>,
        maintenance_guard: Option<Arc<dyn V3MaintenanceGuard>>,
        startup: RuntimeStartup,
    ) -> Result<Self, S3BoundaryError> {
        if startup == RuntimeStartup::HistoryOnly && config.mode != GatewayMode::RestoreReadOnly {
            return Err(repository_init(
                "history startup requires restore-readonly mode",
            ));
        }

        #[cfg(feature = "k8s")]
        if config.mode.allows_mutation()
            && config.repository.allow_init
            && matches!(config.anchor, crate::AnchorConfig::KubernetesLease { .. })
        {
            return Err(repository_init(
                "Kubernetes initialization requires journaled init; disable initialization for serving",
            ));
        }
        if let Some(guard) = maintenance_guard.as_ref() {
            guard
                .verify_v3_maintenance(None)
                .await
                .map_err(repository_init)?;
        }
        #[cfg(feature = "k8s")]
        let anchor = build_v3_anchor_with_writer_fence(&config.anchor, writer_fence)?;
        #[cfg(not(feature = "k8s"))]
        let anchor = build_v3_anchor(&config.anchor)?;
        let store_handle = store.handle().clone();
        let anchor_handle = anchor.handle().clone();
        let provider_profile = v3_provider_profile(&config.backend, config.repository.retention);
        let loaded = load_or_bootstrap_v3_repository(
            &store_handle,
            &anchor_handle,
            config,
            provider_profile,
        )
        .await?;
        let initialized = !loaded.anchor_present;
        let commit_options = bootstrap_commit_options(config, &loaded)?;
        let repository = Arc::new(V3Repository::new(
            store_handle.clone(),
            loaded.keyring,
            RepositoryOptions {
                payload_segment_size: config.repository.payload_segment_size,
                adaptive_payload_segment_size: config.repository.adaptive_payload_segment_size,
                decrypted_segment_cache_max_bytes: config
                    .repository
                    .decrypted_segment_cache_max_bytes,
                default_retention: config.repository.retention,
            },
            commit_options,
        ));

        if loaded.anchor_present {
            if startup == RuntimeStartup::Current {
                repository
                    .load_chain_from_anchor(&anchor_handle)
                    .await
                    .map_err(repository_init)?;
            }
        } else {
            if startup == RuntimeStartup::HistoryOnly {
                return Err(repository_init(
                    "history startup requires a current accepted anchor",
                ));
            }
            repository
                .write_genesis_snapshot_with_guard(&anchor_handle, maintenance_guard.as_deref())
                .await
                .map_err(repository_init)?;
        }
        let coordinator = V3CommitCoordinator::with_options(
            Arc::clone(&repository),
            anchor_handle.clone(),
            coordinator_options(config.batching),
        )
        .map_err(repository_init)?;
        let coordinator = match maintenance_guard {
            Some(guard) => coordinator.with_maintenance_guard(guard),
            None => coordinator,
        };
        let coordinator = Arc::new(coordinator);

        #[cfg(test)]
        let memory_store = store.memory_store().cloned();
        #[cfg(test)]
        let memory_anchor = anchor.memory_anchor().cloned();

        Ok(Self {
            store: store_handle,
            repository,
            recovery_view: None,
            coordinator,
            anchor: anchor_handle,
            initialized,
            require_anchor_version: retained_version_required(config.repository.retention, None),
            #[cfg(test)]
            memory_store,
            #[cfg(test)]
            memory_anchor,
        })
    }

    pub(super) async fn load_accepted_anchor(
        &self,
        _mode: GatewayMode,
    ) -> Result<(), S3BoundaryError> {
        if self.recovery_view.is_some() {
            return self
                .check_recovery_authority()
                .await
                .map_err(repository_init);
        }
        let Some(anchor_state) = self.anchor.read_v3().await.map_err(repository_init)? else {
            return Err(repository_init("v3-preview repository anchor is missing"));
        };
        if self.require_anchor_version && anchor_state.version_id.is_none() {
            return Err(repository_init(
                "retained v2 repository anchor is missing the commit object version id",
            ));
        }
        self.coordinator
            .reload_from_anchor()
            .await
            .map_err(repository_init)?
            .ok_or_else(|| repository_init("v3-preview repository anchor is missing"))?;
        Ok(())
    }

    pub(super) async fn put_committed(
        &self,
        key: LogicalPath,
        body: Bytes,
        options: RepositoryPutOptions,
    ) -> Result<RuntimeCommittedPut, RepositoryError> {
        self.coordinator
            .put_committed(key, body, options)
            .await
            .map(|committed| RuntimeCommittedPut {
                metadata: committed.metadata,
            })
    }

    pub(super) async fn copy_committed(
        &self,
        source: LogicalPath,
        destination: LogicalPath,
        options: RepositoryCopyOptions,
    ) -> Result<RuntimeCommittedPut, RepositoryError> {
        self.coordinator
            .copy_committed(source, destination, options)
            .await
            .map(|committed| RuntimeCommittedPut {
                metadata: committed.metadata,
            })
    }

    pub(super) async fn create_multipart_upload(
        &self,
        key: LogicalPath,
        options: RepositoryPutOptions,
        checksum_policy: Option<rs3_repository::MultipartChecksumPolicy>,
    ) -> Result<rs3_repository::v3::V3ClientMultipartUpload, RepositoryError> {
        self.repository
            .create_multipart_upload(key, options, checksum_policy)
            .await
    }

    pub(super) fn accepted_multipart_completion(
        &self,
        id: &rs3_types::MultipartUploadId,
        key: &LogicalPath,
        selection: &rs3_repository::v3::V3MultipartSelection,
    ) -> Result<Option<rs3_index::completion::CompletionReceipt>, RepositoryError> {
        self.repository
            .accepted_multipart_completion(id, key, selection)
    }

    pub(super) async fn complete_multipart_upload(
        &self,
        upload: rs3_repository::v3::V3ClientMultipartUpload,
        selection: rs3_repository::v3::V3MultipartSelection,
    ) -> Result<rs3_index::completion::CompletionReceipt, RepositoryError> {
        self.coordinator
            .complete_multipart_upload(upload, selection)
            .await
    }

    pub(super) fn supports_streaming_put(&self) -> bool {
        self.repository
            .commit_store()
            .store()
            .supports_multipart_upload()
    }

    pub(super) async fn put_committed_streaming_known_len<St>(
        &self,
        key: LogicalPath,
        plaintext_len: u64,
        stream: St,
        options: RepositoryPutOptions,
        multipart_part_size: usize,
    ) -> Result<RuntimeCommittedPut, RepositoryError>
    where
        St: Stream<Item = Result<Bytes, RepositoryError>> + Unpin + Send + 'static,
    {
        self.coordinator
            .put_committed_streaming_known_len(
                key,
                plaintext_len,
                stream,
                options,
                multipart_part_size,
            )
            .await
            .map(|committed| RuntimeCommittedPut {
                metadata: committed.metadata,
            })
    }

    pub(super) async fn put_committed_streaming_unknown_len<St>(
        &self,
        key: LogicalPath,
        stream: St,
        options: RepositoryPutOptions,
        multipart_part_size: usize,
        max_plaintext_len: u64,
    ) -> Result<RuntimeCommittedPut, RepositoryError>
    where
        St: Stream<Item = Result<Bytes, RepositoryError>> + Unpin + Send,
    {
        self.coordinator
            .put_committed_streaming_unknown_len(
                key,
                stream,
                options,
                multipart_part_size,
                max_plaintext_len,
            )
            .await
            .map(|committed| RuntimeCommittedPut {
                metadata: committed.metadata,
            })
    }

    pub(super) fn head(
        &self,
        key: &LogicalPath,
    ) -> Result<RepositoryObjectMetadata, RepositoryError> {
        match &self.recovery_view {
            Some(view) => view.head(key),
            None => self.repository.head(key),
        }
    }

    pub(super) fn resolve_object(
        &self,
        key: &LogicalPath,
    ) -> Result<RuntimeResolvedObject, RepositoryError> {
        match &self.recovery_view {
            Some(view) => view.resolve_object(key),
            None => self.repository.resolve_object(key),
        }
        .map(|inner| RuntimeResolvedObject { inner })
    }

    #[cfg(test)]
    pub(super) async fn get_range(
        &self,
        key: &LogicalPath,
        range: ByteRange,
    ) -> Result<Bytes, RepositoryError> {
        let resolved = self.resolve_object(key)?;
        self.get_resolved_range(&resolved, range).await
    }

    pub(super) async fn get_resolved_range(
        &self,
        resolved: &RuntimeResolvedObject,
        range: ByteRange,
    ) -> Result<Bytes, RepositoryError> {
        match &self.recovery_view {
            Some(view) => view.get_resolved_range(&resolved.inner, range).await,
            None => {
                self.repository
                    .get_resolved_range(&resolved.inner, range)
                    .await
            }
        }
    }

    pub(super) async fn get_resolved_full_stream(
        &self,
        resolved: &RuntimeResolvedObject,
    ) -> Result<Option<V3AuthenticatedReadBody>, RepositoryError> {
        match &self.recovery_view {
            Some(view) => view.get_resolved_full_stream(&resolved.inner).await,
            None => {
                self.repository
                    .get_resolved_full_stream(&resolved.inner)
                    .await
            }
        }
    }

    pub(super) fn list_page(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<RepositoryListEntry>, RepositoryError> {
        match &self.recovery_view {
            Some(view) => view.list_page(prefix, start_after, limit),
            None => self.repository.list_page(prefix, start_after, limit),
        }
    }

    pub(super) async fn delete_committed(
        &self,
        key: LogicalPath,
    ) -> Result<DeleteOutcome, RepositoryError> {
        self.coordinator.delete_committed(key).await
    }

    pub(super) fn maintenance_runtime(&self) -> Arc<dyn MaintenanceRuntime> {
        Arc::new(self.clone())
    }

    pub(super) fn admin_facts_source(&self) -> Arc<dyn AdminRuntimeFactsSource> {
        Arc::new(RuntimeRepositoryAdminFacts {
            repository: self.clone(),
            process_started_at_ms: current_time_ms(),
        })
    }

    pub(super) fn admin_readiness_source(&self) -> Arc<dyn AdminReadinessSource> {
        Arc::new(RuntimeRepositoryAdminFacts {
            repository: self.clone(),
            process_started_at_ms: current_time_ms(),
        })
    }

    #[cfg(test)]
    pub(super) fn memory_store(&self) -> Option<&MemoryBlobStore> {
        self.memory_store.as_ref()
    }

    #[cfg(test)]
    pub(super) fn memory_v3_anchor(&self) -> Option<&rs3_repository::v3::V3MemoryAnchor> {
        self.memory_anchor.as_ref()
    }
}

#[async_trait::async_trait]
impl MaintenanceRuntime for RuntimeRepository {
    fn maintenance_guard_configured(&self) -> bool {
        self.coordinator.has_maintenance_guard()
    }

    async fn quick_maintenance_report(&self) -> Result<V3MaintenanceReport, RepositoryError> {
        self.repository
            .commit_store()
            .quick_maintenance(&self.anchor)
            .await
            .map_err(|error| RepositoryError::CommitFailed {
                reason: error.to_string(),
            })
    }

    async fn quick_maintenance_report_with_options(
        &self,
        options: V3QuickMaintenanceOptions,
    ) -> Result<V3MaintenanceReport, RepositoryError> {
        self.repository
            .commit_store()
            .quick_maintenance_with_options(&self.anchor, options)
            .await
            .map_err(|error| RepositoryError::CommitFailed {
                reason: error.to_string(),
            })
    }

    async fn full_gc_dry_run(
        &self,
        options: V3FullGcDryRunOptions,
    ) -> Result<V3FullGcDryRunReport, RepositoryError> {
        self.repository.full_gc_dry_run(&self.anchor, options).await
    }

    async fn preview_full_gc_plan(
        &self,
        options: V3FullGcApplyOptions,
    ) -> Result<V3FullGcPlanPreview, RepositoryError> {
        self.repository
            .preview_full_gc_plan(&self.anchor, options)
            .await
    }

    async fn run_full_maintenance(
        &self,
        options: V3FullGcApplyOptions,
        expected_plan_digest: Option<&str>,
        cancellation: &V3MaintenanceCancellation,
        on_phase: &(dyn Fn(MaintenanceRunPhase) + Send + Sync),
    ) -> Result<V3FullMaintenanceReport, RepositoryError> {
        on_phase(MaintenanceRunPhase::Quiescing);
        self.coordinator
            .run_full_maintenance_expected(options, expected_plan_digest, cancellation, &|| {
                on_phase(MaintenanceRunPhase::Applying)
            })
            .await
    }
}

impl AdminRuntimeFactsSource for RuntimeRepositoryAdminFacts {
    fn snapshot(&self) -> AdminRuntimeFacts {
        let status = self.repository.coordinator.status();
        AdminRuntimeFacts {
            process_started_at_ms: Some(self.process_started_at_ms),
            repository: AdminRepositoryRuntimeFacts {
                v3_commit_coordinator: Some(AdminV3CommitCoordinatorSummary {
                    poisoned: status.poisoned,
                    poison_reason: status.poison_reason,
                }),
            },
            maintenance_supervisor: None,
        }
    }
}

#[async_trait::async_trait]
impl AdminReadinessSource for RuntimeRepositoryAdminFacts {
    async fn check_readiness(&self) -> AdminReadiness {
        if self.repository.check_recovery_authority().await.is_err() {
            return AdminReadiness::unavailable("recovery.point-unavailable");
        }
        if self.repository.coordinator.status().poisoned {
            return AdminReadiness::unavailable("repository.coordinator-poisoned");
        }

        let anchor = match self.repository.anchor.read_v3().await {
            Ok(Some(anchor)) => anchor,
            Ok(None) => return AdminReadiness::unavailable("anchor.missing"),
            Err(_) => return AdminReadiness::unavailable("anchor.unavailable"),
        };
        if self.repository.require_anchor_version && anchor.version_id.is_none() {
            return AdminReadiness::unavailable("anchor.version-missing");
        }
        if self
            .repository
            .store
            .head_at(&anchor.commit_key, anchor.version_id.as_ref())
            .await
            .is_err()
        {
            return AdminReadiness::unavailable("backend.anchor-head-unavailable");
        }

        AdminReadiness::ready()
    }
}

/// Storage preflight and immutable settings for one preview initialization.
///
/// Prepare before acquiring the writer Lease, then consume under that fence.
/// This handle neither creates repository objects nor changes the anchor.
pub struct V3PreparedRepositoryInit {
    config: RuntimeConfig,
    store: StoreBuild,
}

/// Checks a trusted projected S3 onboarding journal without backend or Lease IO.
/// True means initialization finished with current matching provider evidence;
/// normal serving must still verify its live anchor and accepted repository.
pub fn v3_bootstrap_journal_is_initialized(
    config: &RuntimeConfig,
    bytes: &[u8],
) -> Result<bool, S3BoundaryError> {
    if !config.backend.is_s3()
        || !matches!(config.anchor, crate::AnchorConfig::KubernetesLease { .. })
    {
        return Err(repository_init(
            "projected onboarding state requires S3 and a Kubernetes anchor",
        ));
    }
    #[cfg(feature = "k8s")]
    return onboarding::is_initialized(config, bytes);
    #[cfg(not(feature = "k8s"))]
    {
        let _ = bytes;
        Err(S3BoundaryError::UnsupportedAnchorMode)
    }
}

/// Reads the declared bootstrap journal Secret without claiming it.
///
/// This lets a one-shot initializer decide whether the repository already
/// completed initialization under this configuration before it contends for
/// the writer Lease. A completed record never authorizes writes on its own.
#[cfg(feature = "k8s")]
pub async fn v3_bootstrap_journal_state(
    config: &RuntimeConfig,
    journal_secret: &str,
) -> Result<Option<Vec<u8>>, S3BoundaryError> {
    let crate::AnchorConfig::KubernetesLease {
        namespace,
        name,
        field_manager,
    } = &config.anchor
    else {
        return Err(repository_init(
            "journaled initialization requires a Kubernetes anchor",
        ));
    };
    rs3_k8s::KubernetesBootstrapJournal::read_state(
        rs3_k8s::LeaseSettings {
            namespace: namespace.clone(),
            name: name.clone(),
            field_manager: field_manager.clone(),
        },
        journal_secret.to_owned(),
    )
    .await
    .map_err(repository_init)
}

impl V3PreparedRepositoryInit {
    /// Verifies an already initialized repository without the writer Lease.
    ///
    /// The live anchor and its accepted chain are read exactly as a
    /// restore-readonly gateway reads them; nothing is written and a missing
    /// anchor fails closed toward explicit recovery.
    pub async fn verify_initialized(self) -> Result<V3RepositoryInitReport, S3BoundaryError> {
        let mut config = self.config;
        config.mode = GatewayMode::RestoreReadOnly;
        config.repository.allow_init = false;
        let runtime = RuntimeRepository::from_preflighted_store(
            &config,
            self.store,
            None,
            None,
            RuntimeStartup::Current,
        )
        .await?;
        verified_init_report(runtime).await
    }

    /// Checks repository format and backend write policy without initialization.
    pub async fn prepare(config: &RuntimeConfig) -> Result<Self, S3BoundaryError> {
        if config.repository.format != RepositoryFormat::V3Preview {
            return Err(repository_init(
                "v2 repository initialization requires the v3-preview repository format",
            ));
        }
        let store = build_store(&config.backend).await?;
        store
            .validate_write_policy(config.mode, config.repository.retention)
            .await?;
        Ok(Self {
            config: config.clone(),
            store,
        })
    }

    /// Initializes local development storage, or verifies a read-only repository.
    /// Mutation-capable Kubernetes initialization requires the fenced method.
    pub async fn initialize(self) -> Result<V3RepositoryInitReport, S3BoundaryError> {
        if self.config.mode.allows_mutation()
            && !matches!(self.config.anchor, crate::AnchorConfig::Memory)
        {
            return Err(repository_init(
                "Kubernetes repository initialization requires an acquired writer fence",
            ));
        }
        let runtime = RuntimeRepository::from_preflighted_store(
            &self.config,
            self.store,
            None,
            None,
            RuntimeStartup::Current,
        )
        .await?;
        verified_init_report(runtime).await
    }

    /// Resumes initialization through a declared journal under the writer fence.
    /// The Secret must be in the anchor namespace and owned by bootstrap.
    #[cfg(feature = "k8s")]
    pub async fn initialize_with_writer_fence(
        self,
        writer_fence: WriterFence,
        journal_secret: &str,
        governance_bypass_reviewed: bool,
    ) -> Result<V3RepositoryInitReport, S3BoundaryError> {
        let crate::AnchorConfig::KubernetesLease {
            namespace,
            name,
            field_manager,
        } = &self.config.anchor
        else {
            return Err(repository_init(
                "fenced repository initialization requires a Kubernetes anchor",
            ));
        };
        if !self.config.mode.allows_mutation() || journal_secret.is_empty() {
            return Err(repository_init(
                "journaled initialization requires writable mode and a declared journal Secret",
            ));
        }
        let mut journal = rs3_k8s::KubernetesBootstrapJournal::claim(
            rs3_k8s::LeaseSettings {
                namespace: namespace.clone(),
                name: name.clone(),
                field_manager: field_manager.clone(),
            },
            journal_secret.to_owned(),
            writer_fence.clone(),
        )
        .await
        .map_err(repository_init)?;
        let anchor =
            build_v3_anchor_with_writer_fence(&self.config.anchor, Some(writer_fence.clone()))?;
        if self.config.backend.is_s3() {
            return onboarding::initialize(
                &self.config,
                &self.store,
                anchor.handle(),
                &writer_fence,
                &mut journal,
                governance_bypass_reviewed,
            )
            .await;
        }
        bootstrap::initialize(
            &self.config,
            self.store.handle(),
            anchor.handle(),
            &writer_fence,
            &mut journal,
            None,
        )
        .await
    }
}

/// Initializes a local v3 repository, then verifies its accepted chain.
/// Kubernetes writers must prepare and initialize under an acquired fence.
pub async fn init_v3_repository_from_config(
    config: &RuntimeConfig,
) -> Result<V3RepositoryInitReport, S3BoundaryError> {
    V3PreparedRepositoryInit::prepare(config)
        .await?
        .initialize()
        .await
}

async fn verified_init_report(
    runtime: RuntimeRepository,
) -> Result<V3RepositoryInitReport, S3BoundaryError> {
    let Some(anchor) = runtime.anchor.read_v3().await.map_err(repository_init)? else {
        return Err(repository_init(
            "v2 repository initialization did not produce an accepted anchor",
        ));
    };
    let chain = runtime
        .coordinator
        .reload_from_anchor()
        .await
        .map_err(repository_init)?
        .ok_or_else(|| {
            repository_init("v2 repository initialization could not verify the accepted anchor")
        })?;
    Ok(V3RepositoryInitReport {
        anchor,
        initialized: runtime.initialized,
        verified_commit_count: chain.commits_newest_first.len(),
        probe_attempts: 0,
        payload_restore_verified: false,
        probe_observation: None,
    })
}

/// Opens the repository maintenance surface for offline break-glass
/// maintenance with an explicitly supplied maintenance guard.
///
/// This path exists for the development memory anchor and tests only, and it
/// fails closed when the configured anchor is not the memory anchor: every
/// other anchor backend must acquire a real writer fence and go through
/// [`offline_maintenance_runtime_from_writer_fence`] so anchor advances stay
/// fenced in the same compare-and-swap.
pub async fn offline_maintenance_runtime_from_config(
    config: &RuntimeConfig,
    maintenance_guard: Arc<dyn V3MaintenanceGuard>,
) -> Result<Arc<dyn MaintenanceRuntime>, S3BoundaryError> {
    if !matches!(config.anchor, crate::AnchorConfig::Memory) {
        return Err(repository_init(
            "offline maintenance with an explicit guard supports the memory anchor only; \
             kubernetes-lease anchors require writer-fence acquisition",
        ));
    }
    let runtime =
        RuntimeRepository::from_config_with_maintenance_guard(config, maintenance_guard).await?;
    Ok(runtime.maintenance_runtime())
}

/// Opens the repository maintenance surface for offline break-glass
/// maintenance under an acquired Kubernetes writer fence.
///
/// The fence is wired into both the commit anchor (so every anchor advance
/// validates it in the same resourceVersion compare-and-swap) and the
/// coordinator maintenance guard used for per-mutation rechecks.
#[cfg(feature = "k8s")]
pub async fn offline_maintenance_runtime_from_writer_fence(
    config: &RuntimeConfig,
    writer_fence: WriterFence,
) -> Result<Arc<dyn MaintenanceRuntime>, S3BoundaryError> {
    let runtime = RuntimeRepository::from_config_with_writer_fence(config, writer_fence).await?;
    Ok(runtime.maintenance_runtime())
}

/// Runs opt-in live doctor probes against configured runtime dependencies.
pub async fn doctor_probe_from_config(config: &RuntimeConfig) -> DoctorProbeReport {
    let mut checks = Vec::new();

    let store = match build_store(&config.backend).await {
        Ok(store) => match prefix_has_any_object(store.handle(), "", BlobListMode::Current).await {
            Ok(_) => {
                checks.push(DoctorProbeCheck::ok(
                    "probe.backend-reachable",
                    "backend reachability probe passed",
                ));
                Some(store)
            }
            Err(_) => {
                checks.push(DoctorProbeCheck::failed(
                    "probe.backend-reachable",
                    "backend reachability probe failed",
                    "check backend endpoint, credentials, bucket, and network access, then rerun rs3 doctor --probe",
                ));
                None
            }
        },
        Err(_) => {
            checks.push(DoctorProbeCheck::failed(
                "probe.backend-reachable",
                "backend reachability probe failed",
                "check backend endpoint, credentials, bucket, and network access, then rerun rs3 doctor --probe",
            ));
            None
        }
    };

    let mut anchor_was_read = false;
    let anchor_state = match build_v3_anchor(&config.anchor) {
        Ok(anchor) => match anchor.handle().read_v3().await {
            Ok(state) => {
                anchor_was_read = true;
                checks.push(DoctorProbeCheck::ok(
                    "probe.anchor-readable",
                    "v2 anchor read probe passed",
                ));
                state
            }
            Err(_) => {
                checks.push(DoctorProbeCheck::failed(
                    "probe.anchor-readable",
                    "v2 anchor read probe failed",
                    "check Kubernetes Lease access and anchor configuration, then rerun rs3 doctor --probe",
                ));
                None
            }
        },
        Err(_) => {
            checks.push(DoctorProbeCheck::failed(
                "probe.anchor-readable",
                "v2 anchor read probe failed",
                "check Kubernetes Lease access and anchor configuration, then rerun rs3 doctor --probe",
            ));
            None
        }
    };

    let keyring_result = match store.as_ref() {
        Some(store) if anchor_was_read => match anchor_state.as_ref() {
            Some(anchor_state) => load_existing_v3_repository(
                store.handle(),
                &config.repository_keys,
                anchor_state,
                config,
            )
            .await
            .map(|_| ()),
            None => unanchored_gateway_keyring(
                store.handle(),
                &config.repository_keys,
                config.repository.retention,
                false,
            )
            .await
            .map(|_| ()),
        },
        _ => Err(repository_init(
            "keyring envelope probe requires readable backend and anchor dependencies",
        )),
    };
    match keyring_result {
        Ok(()) => checks.push(DoctorProbeCheck::ok(
            "probe.keyring-readable",
            "keyring envelope readability probe passed",
        )),
        Err(_) => checks.push(DoctorProbeCheck::failed(
            "probe.keyring-readable",
            "keyring envelope readability probe failed",
            "check repository ID, salt, wrapping key ID, wrapping key material, accepted anchor, and keyring envelope object configuration",
        )),
    }

    DoctorProbeReport { checks }
}

pub(crate) async fn v3_quick_maintenance_from_config(
    config: &RuntimeConfig,
) -> Result<rs3_repository::v3::V3MaintenanceReport, S3BoundaryError> {
    if config.repository.format != RepositoryFormat::V3Preview {
        return Err(repository_init(
            "v2 maintenance requires the v3-preview repository format",
        ));
    }
    let store = build_store(&config.backend).await?;
    let anchor = build_v3_anchor(&config.anchor)?;
    let anchor_handle = anchor.handle().clone();
    let Some(anchor_state) = anchor_handle.read_v3().await.map_err(repository_init)? else {
        return Err(repository_init(
            "v3-preview maintenance requires an accepted anchor",
        ));
    };
    let loaded = load_existing_v3_repository(
        store.handle(),
        &config.repository_keys,
        &anchor_state,
        config,
    )
    .await?;
    let commit_options = bootstrap_commit_options(config, &loaded)?;
    let commit_store = V3CommitStore::new(store.into_handle(), loaded.keyring, commit_options);
    commit_store
        .quick_maintenance_with_options(
            &anchor_handle,
            V3QuickMaintenanceOptions {
                budgets: config.maintenance.budgets(),
                retention_renewal_horizon: config.maintenance.renewal_horizon,
                ..V3QuickMaintenanceOptions::default()
            },
        )
        .await
        .map_err(repository_init)
}

/// Exports a trusted v3 recovery bundle after verifying the anchor-selected chain.
pub async fn export_v3_recovery_bundle_from_config(
    config: &RuntimeConfig,
) -> Result<V3RecoveryBundle, S3BoundaryError> {
    if config.repository.format != RepositoryFormat::V3Preview {
        return Err(repository_init(
            "v2 recovery bundle export requires the v3-preview repository format",
        ));
    }
    let store = build_store(&config.backend).await?;
    let anchor = build_v3_anchor(&config.anchor)?;
    let anchor_handle = anchor.handle().clone();
    let Some(anchor_state) = anchor_handle.read_v3().await.map_err(repository_init)? else {
        return Err(repository_init(
            "v3-preview recovery bundle export requires an accepted anchor",
        ));
    };
    let provider_profile = v3_provider_profile(&config.backend, config.repository.retention);
    let loaded = load_existing_v3_repository(
        store.handle(),
        &config.repository_keys,
        &anchor_state,
        config,
    )
    .await?;
    let commit_ref = loaded.keyring_ref.commit_ref().map_err(repository_init)?;
    let maintenance_keyring_ref = loaded.keyring_ref.clone();
    let repository_salt_digest = rs3_crypto::Sha256Hasher::digest(&loaded.repository_salt);
    let commit_options = V3CommitStoreOptions::for_profile(
        provider_profile,
        config.repository_keys.repository_id.clone(),
        commit_ref,
        loaded.format_ref,
    )
    .with_maintenance_keyring_envelope_ref(maintenance_keyring_ref)
    .with_retention(config.repository.retention);
    let commit_store = V3CommitStore::new(store.into_handle(), loaded.keyring, commit_options);
    commit_store
        .load_replay_chain_from_state(&anchor_state)
        .await
        .map_err(repository_init)?;

    let mut bundle = V3RecoveryBundle::from_anchor(anchor_state.clone(), anchor_state.sequence);
    bundle.repository_id = Some(config.repository_keys.repository_id.clone());
    // The signed bundle cross-checks the salt of the anchored format root, so
    // an unconfigured opener still detects a bundle from another lineage.
    bundle.repository_salt_digest = Some(repository_salt_digest);
    Ok(bundle)
}

/// Imports a trusted v3 recovery bundle when the configured anchor is missing.
pub async fn import_v3_anchor_from_config(
    config: &RuntimeConfig,
    bundle: V3RecoveryBundle,
    options: V3AnchorImportOptions,
) -> Result<V3AnchorImportReport, S3BoundaryError> {
    if config.repository.format != RepositoryFormat::V3Preview {
        return Err(repository_init(
            "v2 anchor import requires the v3-preview repository format",
        ));
    }
    let store = build_store(&config.backend).await?;
    let anchor = build_v3_anchor(&config.anchor)?;
    let anchor_handle = anchor.handle().clone();
    let provider_profile = v3_provider_profile(&config.backend, config.repository.retention);
    if bundle.repository_id.as_ref() != Some(&config.repository_keys.repository_id) {
        return Err(repository_init(
            "trusted v2 restore bundle repository identity is missing or does not match configuration",
        ));
    }
    verify_recovery_bundle_trust(
        &bundle,
        provider_profile,
        options.min_sequence,
        config.recovery.public_key.as_deref(),
    )?;
    reject_import_stranding_newer_commits(
        store.handle(),
        provider_profile,
        bundle.anchor.sequence,
        options.force_rollback,
    )
    .await?;
    let loaded = load_existing_v3_repository(
        store.handle(),
        &config.repository_keys,
        &bundle.anchor,
        config,
    )
    .await?;
    reject_bundle_salt_mismatch(bundle.repository_salt_digest, &loaded.repository_salt)?;
    let commit_ref = loaded.keyring_ref.commit_ref().map_err(repository_init)?;
    let maintenance_keyring_ref = loaded.keyring_ref.clone();
    let commit_options = V3CommitStoreOptions::for_profile(
        provider_profile,
        config.repository_keys.repository_id.clone(),
        commit_ref,
        loaded.format_ref,
    )
    .with_maintenance_keyring_envelope_ref(maintenance_keyring_ref)
    .with_retention(config.repository.retention);
    let commit_store = V3CommitStore::new(store.into_handle(), loaded.keyring, commit_options);

    if let Some(current) = anchor_handle.read_v3().await.map_err(repository_init)? {
        if current != bundle.anchor {
            return Err(repository_init(
                "configured v2 anchor already exists and differs from the trusted bundle",
            ));
        }
        let chain = commit_store
            .load_replay_chain_from_state(&current)
            .await
            .map_err(repository_init)?;
        return Ok(V3AnchorImportReport {
            anchor: current,
            applied: false,
            verified_commit_count: chain.commits_newest_first.len(),
        });
    }

    let chain = commit_store
        .recreate_anchor_from_recovery_bundle(&anchor_handle, &bundle, options.min_sequence)
        .await
        .map_err(repository_init)?;
    Ok(V3AnchorImportReport {
        anchor: bundle.anchor,
        applied: true,
        verified_commit_count: chain.commits_newest_first.len(),
    })
}

fn verify_recovery_bundle_trust(
    bundle: &V3RecoveryBundle,
    provider_profile: V3ProviderProfile,
    min_sequence: Sequence,
    recovery_public_key: Option<&str>,
) -> Result<(), S3BoundaryError> {
    if bundle.anchor.sequence < min_sequence {
        return Err(repository_init(
            "trusted v2 restore bundle anchor sequence is below --min-sequence",
        ));
    }

    if provider_profile != V3ProviderProfile::Dev && bundle.offline_signature.is_none() {
        return Err(repository_init(
            "production v2 anchor import requires an offline bundle signature",
        ));
    }

    match recovery_public_key {
        Some(public_key) => bundle
            .verify_offline_signature(public_key)
            .map_err(repository_init),
        None if provider_profile == V3ProviderProfile::Dev => Ok(()),
        None => Err(repository_init(
            "production v2 anchor import requires RS3_RECOVERY_PUBLIC_KEY",
        )),
    }?;

    Ok(())
}

async fn reject_import_stranding_newer_commits<S>(
    store: &S,
    provider_profile: V3ProviderProfile,
    import_sequence: Sequence,
    force_rollback: bool,
) -> Result<(), S3BoundaryError>
where
    S: BlobStore,
{
    let mode = if provider_profile == V3ProviderProfile::RetainedVersionObjectLock {
        BlobListMode::Versions
    } else {
        BlobListMode::Current
    };
    let mut listing =
        BoundedListing::open(store, "commits/v03/", mode, CONTROL_LIST_BUDGET).await?;
    let mut highest_seen = None;
    while let Some(page) = listing.next_page().await? {
        for metadata in page.entries {
            let Ok(commit_key) = V3CommitKey::parse(&metadata.object_id) else {
                continue;
            };
            highest_seen = Some(
                highest_seen.map_or(commit_key.sequence, |highest: Sequence| {
                    highest.max(commit_key.sequence)
                }),
            );
        }
    }
    if let Some(highest_seen) = highest_seen
        && highest_seen > import_sequence
    {
        tracing::warn!(
            highest_seen_sequence = highest_seen.get(),
            import_sequence = import_sequence.get(),
            force_rollback,
            "v2 anchor import observed newer commit objects than the trusted bundle"
        );
        if !force_rollback {
            return Err(repository_init(
                "v2 anchor import would strand newer commit objects; pass --force-rollback only after rollback review",
            ));
        }
    }

    Ok(())
}

/// Runs v3 provider conformance checks for the configured backend/profile.
pub async fn check_v3_provider_conformance_from_config(
    config: &RuntimeConfig,
    options: RuntimeV3ProviderConformanceOptions,
) -> Result<V3ProviderConformanceReport, S3BoundaryError> {
    check_v3_provider_conformance_from_provider_config(
        &V3ProviderCheckConfig::from(config),
        options,
    )
    .await
}

/// Runs v3 provider conformance checks without requiring full gateway config.
pub async fn check_v3_provider_conformance_from_provider_config(
    config: &V3ProviderCheckConfig,
    options: RuntimeV3ProviderConformanceOptions,
) -> Result<V3ProviderConformanceReport, S3BoundaryError> {
    let store = build_store(&config.backend).await?;
    check_v3_provider_conformance_with_store(config, options, &store).await
}

async fn check_v3_provider_conformance_with_store(
    config: &V3ProviderCheckConfig,
    options: RuntimeV3ProviderConformanceOptions,
    store: &StoreBuild,
) -> Result<V3ProviderConformanceReport, S3BoundaryError> {
    if config.repository_format != RepositoryFormat::V3Preview {
        return Err(repository_init(
            "v2 provider conformance requires the v3-preview repository format",
        ));
    }
    if config.repository_retention.is_some_and(|retention| {
        retention.mode == rs3_types::RetentionMode::Governance && retention.retain_days > 0
    }) && config.principal_fingerprint.is_none()
    {
        return Err(repository_init(
            "governance provider conformance requires RS3_PROVIDER_PRINCIPAL_FINGERPRINT",
        ));
    }
    store
        .validate_write_policy(GatewayMode::ReadWrite, config.repository_retention)
        .await?;
    let profile = v3_provider_profile(&config.backend, config.repository_retention);
    let prefix = match options.probe_prefix {
        Some(prefix) => prefix,
        None => default_v3_provider_probe_prefix()?,
    };
    let probe = store
        .provider_probe_store(prefix.clone(), config.repository_retention)
        .await?;
    let relative_prefix = if config.backend.is_s3() {
        "checks".to_owned()
    } else {
        prefix
    };
    let mut conformance = V3ProviderConformanceOptions::new(profile, relative_prefix)
        .with_legal_hold(options.legal_hold)
        .with_governance_bypass_reviewed(options.governance_bypass_reviewed);
    if let Some(retention) = config.repository_retention {
        conformance = conformance.with_retention(retention);
    }
    check_v3_provider_conformance(&probe, &conformance)
        .await
        .map_err(repository_init)
}

async fn load_or_bootstrap_v3_repository(
    store: &RuntimeStore,
    anchor: &RuntimeV3Anchor,
    config: &RuntimeConfig,
    provider_profile: V3ProviderProfile,
) -> Result<LoadedV3Repository, S3BoundaryError> {
    match anchor.read_v3().await.map_err(repository_init)? {
        Some(anchor_state) => {
            load_existing_v3_repository(store, &config.repository_keys, &anchor_state, config).await
        }
        None => {
            bootstrap_v3_repository(store, &config.repository_keys, config, provider_profile).await
        }
    }
}

async fn bootstrap_v3_repository(
    store: &RuntimeStore,
    keys: &RepositoryKeysConfig,
    config: &RuntimeConfig,
    provider_profile: V3ProviderProfile,
) -> Result<LoadedV3Repository, S3BoundaryError> {
    if config.mode.requires_anchor() {
        return Err(repository_init(
            "restore-readonly gateway mode requires an accepted v2 commit anchor; run explicit anchor recovery before serving restore",
        ));
    }
    if !config.repository.allow_init {
        return Err(repository_init(
            "v2 repository initialization requires RS3_ALLOW_REPOSITORY_INIT=true; use explicit anchor recovery for existing repositories",
        ));
    }

    let loaded_keyring =
        unanchored_gateway_keyring(store, keys, config.repository.retention, true).await?;
    reject_v3_bootstrap_with_foreign_objects(
        store,
        provider_profile,
        loaded_keyring
            .envelope_reference
            .as_ref()
            .map(|reference| &reference.object_id),
    )
    .await?;

    let keyring_ref =
        v3_keyring_root_ref(loaded_keyring.envelope_reference.as_ref().ok_or_else(|| {
            repository_init("v2 bootstrap requires a keyring envelope reference")
        })?);
    let signing_key_id = loaded_keyring
        .keyring
        .primary_key_id(KeyPurpose::CheckpointSigning)
        .map_err(repository_init)?;
    let format_root = V3FormatRoot::new(
        keys.repository_id.clone(),
        keyring_ref.clone(),
        signing_key_id,
        provider_profile,
        config.repository.retention,
    );
    let format_ref = store_format_root(
        store,
        keys,
        &format_root,
        config.repository.retention,
        &loaded_keyring.repository_salt,
    )
    .await?;

    tracing::info!(
        target: "rs3_repository",
        repository_format = "v3-preview",
        format_generation = format_ref.generation,
        "initialized v2 format root in empty repository",
    );

    Ok(LoadedV3Repository {
        keyring: loaded_keyring.keyring,
        keyring_ref,
        format_ref,
        anchor_present: false,
        repository_salt: loaded_keyring.repository_salt,
    })
}

async fn load_existing_v3_repository(
    store: &RuntimeStore,
    keys: &RepositoryKeysConfig,
    anchor_state: &V3AnchorState,
    config: &RuntimeConfig,
) -> Result<LoadedV3Repository, S3BoundaryError> {
    let OpenedFormatRoot {
        root: format_root,
        repository_salt,
    } = open_format_root(store, keys, &anchor_state.format_ref).await?;
    if format_root.repository_id != keys.repository_id
        || format_root.provider_profile
            != v3_provider_profile(&config.backend, config.repository.retention)
        || format_root.retention != config.repository.retention
        || format_root.signing_key_id != anchor_state.signing_key_id
    {
        return Err(repository_init(
            "v2 format root does not match the configured repository context",
        ));
    }

    let keyring_reference = keyring_reference_from_v3(&format_root.active_keyring_envelope_ref);
    reject_unbound_keyring_override(
        keys.envelope_object_id.as_ref(),
        &keyring_reference.object_id,
    )?;
    let loaded_keyring = open_gateway_keyring_reference(store, keys, &keyring_reference).await?;
    reject_salt_disagreement(&repository_salt, &loaded_keyring.repository_salt)?;
    Ok(LoadedV3Repository {
        keyring: loaded_keyring.keyring,
        keyring_ref: format_root.active_keyring_envelope_ref,
        format_ref: anchor_state.format_ref.clone(),
        anchor_present: true,
        repository_salt,
    })
}

async fn store_format_root(
    store: &RuntimeStore,
    keys: &RepositoryKeysConfig,
    root: &V3FormatRoot,
    retention: Option<RetentionPolicy>,
    repository_salt: &[u8],
) -> Result<V3FormatRef, S3BoundaryError> {
    let envelope = prepare_format_root(keys, root, repository_salt)?;
    let digest = envelope.digest().map_err(repository_init)?;
    let object_id = v3_format_object_id(envelope.generation, &digest).map_err(repository_init)?;
    let body = Bytes::from(envelope.to_object_bytes().map_err(repository_init)?);
    let metadata = put_format_envelope(store, &object_id, body, retention).await?;
    let version_id =
        retained_version_id(&object_id, &metadata, retention, None).map_err(repository_init)?;

    Ok(V3FormatRef {
        generation: envelope.generation,
        digest,
        object_id,
        version_id,
    })
}

fn prepare_format_root(
    keys: &RepositoryKeysConfig,
    root: &V3FormatRoot,
    repository_salt: &[u8],
) -> Result<RepositoryEnvelope, S3BoundaryError> {
    let context = repository_key_context_for_salt(keys, repository_salt)?;
    let wrapping_key = secret_hex(KEYRING_WRAPPING_KEY_HEX_ENV, &keys.wrapping_key_hex)?;
    let plaintext = root.to_plaintext_bytes().map_err(repository_init)?;
    let envelope = RepositoryEnvelope::seal_format(
        &context,
        &keys.wrapping_key_id,
        &wrapping_key,
        1,
        &plaintext,
    )
    .map_err(repository_init)?;
    Ok(envelope)
}

async fn put_format_envelope(
    store: &RuntimeStore,
    object_id: &BackendObjectId,
    body: Bytes,
    retention: Option<RetentionPolicy>,
) -> Result<BlobMetadata, S3BoundaryError> {
    let put = store
        .put(
            object_id,
            body.clone(),
            PutOptions {
                retention,
                legal_hold: None,
                content_type: Some(V3_FORMAT_ENVELOPE_CONTENT_TYPE.to_owned()),
                do_not_recreate: !retained_version_required(retention, None),
            },
        )
        .await;
    match put {
        Ok(metadata) => Ok(metadata),
        Err(StorageError::AlreadyExists(_)) => {
            let metadata = store.head(object_id).await.map_err(repository_init)?;
            let existing = read_bounded_object_at(
                store,
                object_id,
                metadata.version_id.as_ref(),
                MAX_FORMAT_ENVELOPE_OBJECT_BYTES,
            )
            .await?;
            if existing != body {
                return Err(repository_init(
                    "v2 format root object conflicts with expected content",
                ));
            }
            Ok(metadata)
        }
        Err(error) => Err(repository_init(error)),
    }
}

async fn open_format_root(
    store: &RuntimeStore,
    keys: &RepositoryKeysConfig,
    reference: &V3FormatRef,
) -> Result<OpenedFormatRoot, S3BoundaryError> {
    let body = read_bounded_object_at(
        store,
        &reference.object_id,
        reference.version_id.as_ref(),
        MAX_FORMAT_ENVELOPE_OBJECT_BYTES,
    )
    .await?;
    open_format_root_body(keys, reference, &body)
}

fn open_format_root_body(
    keys: &RepositoryKeysConfig,
    reference: &V3FormatRef,
    body: &[u8],
) -> Result<OpenedFormatRoot, S3BoundaryError> {
    let envelope = RepositoryEnvelope::from_object_bytes(body, rs3_crypto::EnvelopePurpose::Format)
        .map_err(repository_init)?;
    if envelope.generation != reference.generation
        || envelope.digest().map_err(repository_init)? != reference.digest
    {
        return Err(repository_init(
            "v2 format root object does not match the anchor-bound reference",
        ));
    }
    // The reference digest above ties this envelope to the anchor, so its
    // public salt is trusted context rather than backend discovery.
    let context = repository_key_context_for_envelope(keys, &envelope)?;
    let wrapping_key = secret_hex(KEYRING_WRAPPING_KEY_HEX_ENV, &keys.wrapping_key_hex)?;
    let plaintext = envelope
        .open_format(&context, &keys.wrapping_key_id, &wrapping_key)
        .map_err(repository_init)?;
    Ok(OpenedFormatRoot {
        root: V3FormatRoot::from_plaintext_bytes(&plaintext).map_err(repository_init)?,
        repository_salt: envelope.repository_salt,
    })
}

/// The format root and the keyring envelope it binds must carry one salt.
fn reject_salt_disagreement(
    format_salt: &[u8],
    keyring_salt: &[u8],
) -> Result<(), S3BoundaryError> {
    if format_salt != keyring_salt {
        return Err(repository_init(
            "v2 format root and its bound keyring envelope disagree on the public repository salt",
        ));
    }
    Ok(())
}

/// A trusted bundle must carry the salt digest of the lineage it describes.
fn reject_bundle_salt_mismatch(
    digest: Option<[u8; 32]>,
    repository_salt: &[u8],
) -> Result<(), S3BoundaryError> {
    match digest {
        None => Err(repository_init(
            "trusted v2 restore bundle lacks the repository salt digest; export it again with this release",
        )),
        Some(digest) if digest != rs3_crypto::Sha256Hasher::digest(repository_salt) => {
            Err(repository_init(
                "trusted v2 restore bundle salt digest does not match the anchored format root",
            ))
        }
        Some(_) => Ok(()),
    }
}

async fn reject_v3_bootstrap_with_foreign_objects<S>(
    store: &S,
    provider_profile: V3ProviderProfile,
    allowed_keyring: Option<&BackendObjectId>,
) -> Result<(), S3BoundaryError>
where
    S: BlobStore,
{
    if allowed_keyring.is_some_and(|key| key.as_str().ends_with(".json")) {
        return Err(repository_init("retired keyring object format"));
    }
    const BOOTSTRAP_EMPTY_CHECK_PREFIXES: &[&str] =
        &["", "format/", "commits/", "keyrings/", "checkpoints/"];

    // This is an early hygiene check, not a synchronization primitive. The
    // first commit's anchor compare-and-advance remains the bootstrap safety
    // boundary on eventually consistent object stores.
    for prefix in BOOTSTRAP_EMPTY_CHECK_PREFIXES {
        let mode = if provider_profile == V3ProviderProfile::RetainedVersionObjectLock {
            BlobListMode::Versions
        } else {
            BlobListMode::Current
        };
        let mut listing = BoundedListing::open(store, prefix, mode, CONTROL_LIST_BUDGET).await?;
        while let Some(page) = listing.next_page().await? {
            // Version inventories may hide delete markers, which still prove
            // prior repository activity. Current inventories also count local
            // traversal work (directories and temporary files); that count is
            // a work budget, not evidence of an addressable object or version.
            let filtered_provider_members =
                mode == BlobListMode::Versions && page.consumed_items > page.entries.len();
            let has_foreign_object = filtered_provider_members
                || page
                    .entries
                    .iter()
                    .any(|metadata| Some(&metadata.object_id) != allowed_keyring);
            if has_foreign_object {
                return Err(repository_init(
                    "v3-preview bootstrap requires an empty repository prefix except for the configured keyring envelope",
                ));
            }
        }
    }
    Ok(())
}

fn v3_keyring_root_ref(reference: &KeyringEnvelopeReference) -> V3KeyringEnvelopeRootRef {
    V3KeyringEnvelopeRootRef {
        generation: reference.generation,
        digest: reference.digest.clone(),
        object_id: reference.object_id.clone(),
        version_id: reference.version_id.clone(),
    }
}

/// An anchored repository opens only the envelope its format root binds.
///
/// A configured override naming another object, typically a rewrapped
/// envelope, is an activation this preview does not support. Refusing it is
/// better than silently opening the old envelope while the operator believes
/// the new wrapping key is in use.
fn reject_unbound_keyring_override(
    configured: Option<&BackendObjectId>,
    bound: &BackendObjectId,
) -> Result<(), S3BoundaryError> {
    match configured {
        Some(configured) if configured != bound => Err(repository_init(
            "RS3_KEYRING_ENVELOPE_OBJECT_ID names a keyring envelope that the anchored format root does not bind; a rewrapped envelope stays inactive until a format update binds it and this preview provides no such activation, so unset the override or keep the bound envelope and its wrapping key",
        )),
        _ => Ok(()),
    }
}

fn keyring_reference_from_v3(reference: &V3KeyringEnvelopeRootRef) -> KeyringEnvelopeReference {
    KeyringEnvelopeReference {
        generation: reference.generation,
        digest: reference.digest.clone(),
        object_id: reference.object_id.clone(),
        version_id: reference.version_id.clone(),
    }
}

pub(super) fn v3_provider_profile(
    backend: &BackendConfig,
    retention: Option<RetentionPolicy>,
) -> V3ProviderProfile {
    if retention.is_some_and(|policy| policy.mode != RetentionMode::None && policy.retain_days > 0)
    {
        V3ProviderProfile::RetainedVersionObjectLock
    } else if backend.is_s3() {
        V3ProviderProfile::AtomicCreate
    } else {
        V3ProviderProfile::Dev
    }
}

fn default_v3_provider_probe_prefix() -> Result<String, S3BoundaryError> {
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce)
        .map_err(|_| repository_init("provider probe identity generation failed"))?;
    Ok(format!("rs3-probes/{}", hex::encode(nonce)))
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
    #[cfg(feature = "s3")]
    use super::super::runtime_builders::s3_backend_config;
    use super::super::runtime_handles::RuntimeStore;
    use super::super::runtime_keyring::unanchored_gateway_keyring;
    use super::{
        RuntimeRepository, V3ProviderProfile, V3RecoveryBundle, doctor_probe_from_config,
        init_v3_repository_from_config, reject_import_stranding_newer_commits,
        reject_v3_bootstrap_with_foreign_objects, verify_recovery_bundle_trust,
    };
    #[cfg(not(feature = "k8s"))]
    use crate::AnchorConfig;
    use crate::s3::S3BoundaryError;
    use crate::s3::test_support::runtime_config;
    use crate::{BatchConfig, GatewayMode, RepositoryFormat, RepositoryKeysConfig};
    use bytes::Bytes;
    use rs3_crypto::{KeyRing, RepositoryKeyContext, SecretBytes};
    use rs3_repository::RepositoryPutOptions;
    use rs3_repository::v3::{V3AnchorState, V3CommitAnchor, V3FormatRef};
    use rs3_storage::{
        BlobList, BlobListMode, BlobListPage, BlobMetadata, BlobStore, ByteRange,
        FilesystemBlobStore, MemoryBlobStore, PutOptions, StorageError,
    };
    use rs3_types::{
        BackendObjectId, BackendVersionId, KeyId, KeyPurpose, LegalHoldStatus, LogicalPath,
        RepositoryId, RetentionMode, RetentionPolicy, Sequence,
    };
    use secrecy::SecretString;
    use std::num::NonZeroUsize;
    use std::path::{Path, PathBuf};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub(super) struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        pub(super) fn new() -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "rs3-server-runtime-test-{}-{nanos}",
                std::process::id()
            ));
            Self { path }
        }

        pub(super) fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[tokio::test]
    async fn prepared_init_is_read_only_until_consumed_and_keeps_its_configuration() {
        let mut config = runtime_config(true);
        let prepared = super::V3PreparedRepositoryInit::prepare(&config)
            .await
            .expect("preflight");
        let store = prepared
            .store
            .memory_store()
            .expect("memory fixture")
            .clone();
        assert!(store.list_prefix("").await.expect("inventory").is_empty());
        config.repository.allow_init = false;
        config.backend.endpoint = "invalid://changed-after-preflight".to_owned();
        let report = prepared
            .initialize()
            .await
            .expect("consume original settings");
        assert!(report.initialized);
        assert!(report.verified_commit_count > 0);
        assert!(!store.list_prefix("").await.expect("inventory").is_empty());
    }

    #[test]
    fn anchored_repositories_refuse_unbound_keyring_overrides() {
        let bound = BackendObjectId::new("keyrings/bound.cbor").expect("object id");
        let rewrapped = BackendObjectId::new("keyrings/rewrapped.cbor").expect("object id");
        assert!(super::reject_unbound_keyring_override(None, &bound).is_ok());
        assert!(super::reject_unbound_keyring_override(Some(&bound), &bound).is_ok());
        let error = super::reject_unbound_keyring_override(Some(&rewrapped), &bound)
            .expect_err("a rewrapped envelope is not activated by configuration");
        assert!(error.to_string().contains("does not bind"));
    }

    #[tokio::test]
    async fn prepared_verification_never_initializes_and_reports_missing_anchors() {
        // An empty memory anchor over an empty store is the cluster-loss
        // shape: verification must fail closed instead of initializing.
        let config = runtime_config(true);
        let prepared = super::V3PreparedRepositoryInit::prepare(&config)
            .await
            .expect("storage preflight");
        let store = prepared
            .store
            .memory_store()
            .expect("memory fixture")
            .clone();
        let error = prepared
            .verify_initialized()
            .await
            .expect_err("empty repository is not verified into existence");
        assert!(
            error.to_string().contains("restore-readonly"),
            "unexpected error: {error}"
        );
        assert!(store.list_prefix("").await.expect("no writes").is_empty());
    }

    #[tokio::test]
    async fn prepared_init_rejects_unfenced_kubernetes_writes_without_repository_objects() {
        let mut config = runtime_config(true);
        config.anchor = crate::AnchorConfig::KubernetesLease {
            namespace: "fixture".to_owned(),
            name: "fixture".to_owned(),
            field_manager: "fixture".to_owned(),
        };
        let prepared = super::V3PreparedRepositoryInit::prepare(&config)
            .await
            .expect("storage preflight");
        let store = prepared
            .store
            .memory_store()
            .expect("memory fixture")
            .clone();
        let error = prepared.initialize().await.expect_err("missing fence");
        assert!(error.to_string().contains("acquired writer fence"));
        assert!(store.list_prefix("").await.expect("no writes").is_empty());
        let prepared = super::V3PreparedRepositoryInit::prepare(&config)
            .await
            .expect("preflight again");
        let store = prepared
            .store
            .memory_store()
            .expect("memory fixture")
            .clone();
        let error = RuntimeRepository::from_preflighted_store(
            &prepared.config,
            prepared.store,
            None,
            None,
            super::RuntimeStartup::Current,
        )
        .await
        .err()
        .expect("common runtime cannot bypass journaled bootstrap");
        #[cfg(feature = "k8s")]
        assert!(error.to_string().contains("journaled init"));
        #[cfg(not(feature = "k8s"))]
        assert!(matches!(error, S3BoundaryError::UnsupportedAnchorMode));
        assert!(
            store
                .list_prefix("")
                .await
                .expect("no bypass writes")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn runtime_factory_builds_memory_repository() {
        let runtime = RuntimeRepository::from_config(&runtime_config(true))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(runtime.memory_store().is_some());
        assert!(runtime.memory_v3_anchor().is_some());
    }

    #[tokio::test]
    async fn runtime_readiness_checks_anchor_and_backend_head() {
        let runtime = RuntimeRepository::from_config(&runtime_config(true))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let readiness = runtime.admin_readiness_source();

        assert!(readiness.check_readiness().await.ready);

        let anchor = runtime
            .memory_v3_anchor()
            .unwrap_or_else(|| panic!("memory anchor should exist"))
            .read_v3()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("accepted anchor should exist"));
        runtime
            .memory_store()
            .unwrap_or_else(|| panic!("memory store should exist"))
            .delete(&anchor.commit_key)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(readiness.check_readiness().await.ready);
        runtime
            .memory_store()
            .expect("memory store")
            .delete_at(&anchor.commit_key, anchor.version_id.as_ref())
            .await
            .expect("delete exact anchored version");

        let unavailable = readiness.check_readiness().await;
        assert!(!unavailable.ready);
        assert_eq!(
            unavailable.reason_code,
            Some("backend.anchor-head-unavailable")
        );
    }

    #[tokio::test]
    async fn offline_runtime_from_config_runs_guarded_maintenance_on_memory_anchor() {
        let runtime = super::offline_maintenance_runtime_from_config(
            &runtime_config(false),
            Arc::new(rs3_repository::v3::UnenforcedQuiescedMaintenanceGuard),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(runtime.maintenance_guard_configured());

        let options = rs3_repository::v3::V3FullGcApplyOptions {
            dry_run: rs3_repository::v3::V3FullGcDryRunOptions::default(),
            orphan_gc: rs3_repository::v3::V3OrphanGcOptions::new_for_test_rehearsal(
                Duration::ZERO,
            ),
            retained_provider_conformance_passed: true,
            reclamation_enabled: true,
        };
        let preview = runtime
            .preview_full_gc_plan(options.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let cancellation = rs3_repository::v3::V3MaintenanceCancellation::new();
        let report = runtime
            .run_full_maintenance(
                options.clone(),
                Some(&preview.plan_digest),
                &cancellation,
                &|_phase| {},
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(report.apply.orphan_gc.aborted.is_none());

        let stale = runtime
            .run_full_maintenance(options, Some(&"ab".repeat(32)), &cancellation, &|_phase| {})
            .await;
        assert!(matches!(
            stale,
            Err(rs3_repository::RepositoryError::CommitFailed { reason })
                if reason == crate::maintenance::MAINTENANCE_PLAN_STALE_REASON
        ));
    }

    #[tokio::test]
    async fn offline_runtime_with_explicit_guard_rejects_non_memory_anchors() {
        let mut config = runtime_config(false);
        config.anchor = crate::AnchorConfig::KubernetesLease {
            namespace: "backup".to_owned(),
            name: "v2-anchor".to_owned(),
            field_manager: "rs3-server".to_owned(),
        };

        let rejected = super::offline_maintenance_runtime_from_config(
            &config,
            Arc::new(rs3_repository::v3::UnenforcedQuiescedMaintenanceGuard),
        )
        .await;

        assert!(rejected.is_err(), "non-memory anchors must be rejected");
    }

    #[tokio::test]
    async fn init_command_initializes_and_verifies_without_static_credentials() {
        let config = runtime_config(false);

        let report = init_v3_repository_from_config(&config)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(report.initialized);
        assert_eq!(report.anchor.sequence, Sequence::new(1));
        assert_eq!(report.verified_commit_count, 1);
    }

    #[tokio::test]
    async fn doctor_probe_checks_backend_anchor_and_keyring_readability() {
        let report = doctor_probe_from_config(&runtime_config(false)).await;
        let backend = report
            .checks
            .iter()
            .find(|check| check.code == "probe.backend-reachable")
            .unwrap_or_else(|| panic!("missing backend probe"));
        let anchor = report
            .checks
            .iter()
            .find(|check| check.code == "probe.anchor-readable")
            .unwrap_or_else(|| panic!("missing anchor probe"));
        let keyring = report
            .checks
            .iter()
            .find(|check| check.code == "probe.keyring-readable")
            .unwrap_or_else(|| panic!("missing keyring probe"));

        assert!(backend.is_passed());
        assert!(anchor.is_passed());
        assert!(!keyring.is_passed());
        assert!(!keyring.remediation.is_empty());
        assert_eq!(report.failed_count(), 1);
    }

    #[tokio::test]
    async fn runtime_factory_builds_v3_preview_repository() {
        let mut config = runtime_config(true);
        config.repository.format = RepositoryFormat::V3Preview;
        let runtime = RuntimeRepository::from_config(&config)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let store = runtime
            .memory_store()
            .unwrap_or_else(|| panic!("missing memory store"));
        let format_roots = store
            .list_prefix("format/")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let commits = store
            .list_prefix("commits/v03/")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let v3_anchor = runtime
            .memory_v3_anchor()
            .unwrap_or_else(|| panic!("missing v2 memory anchor"));

        assert_eq!(format_roots.len(), 1);
        assert_eq!(commits.len(), 1);
        assert!(
            v3_anchor
                .read_v3()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_some()
        );
        runtime
            .load_accepted_anchor(GatewayMode::ReadWrite)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let key =
            LogicalPath::new("snapshots/v3-preview.bin").unwrap_or_else(|error| panic!("{error}"));
        let committed = runtime
            .put_committed(
                key.clone(),
                Bytes::from_static(b"body"),
                RepositoryPutOptions::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let head = runtime.head(&key).unwrap_or_else(|error| panic!("{error}"));
        let body = runtime
            .get_range(&key, ByteRange::Full)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let list = runtime
            .list_page("snapshots/", None, 1000)
            .unwrap_or_else(|error| panic!("{error}"));
        let commits = store
            .list_prefix("commits/v03/")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let backend_objects = store
            .list_prefix("")
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(committed.metadata.content_len, 4);
        assert_eq!(head.content_len, 4);
        assert_eq!(body, Bytes::from_static(b"body"));
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].key, key);
        assert_eq!(commits.len(), 2);
        for metadata in backend_objects {
            assert!(!metadata.object_id.as_str().contains("snapshots"));
            assert!(!metadata.object_id.as_str().contains("v3-preview"));
        }
    }

    #[tokio::test]
    async fn runtime_factory_initializes_default_keyring_envelope_in_empty_repository() {
        let config = runtime_config(true);

        let runtime = RuntimeRepository::from_config(&config)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let keyrings = runtime
            .memory_store()
            .unwrap_or_else(|| panic!("missing memory store"))
            .list_prefix("keyrings/")
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(keyrings.len(), 1);
        assert!(
            keyrings[0]
                .object_id
                .as_str()
                .starts_with("keyrings/00000000000000000001-")
        );
    }

    #[tokio::test]
    async fn runtime_factory_requires_explicit_repository_init() {
        let mut config = runtime_config(true);
        config.repository.allow_init = false;

        let runtime = RuntimeRepository::from_config(&config).await;

        assert!(
            matches!(runtime, Err(S3BoundaryError::RepositoryInit { reason }) if reason.contains("RS3_ALLOW_REPOSITORY_INIT=true"))
        );
    }

    #[tokio::test]
    async fn runtime_factory_rejects_missing_keyring_envelope_when_repository_is_not_empty() {
        let dir = TestDir::new();
        let mut config = runtime_config(true);
        config.backend.endpoint = format!("file://{}", dir.path().display());
        let store_root = dir
            .path()
            .join(&config.backend.bucket)
            .join(config.backend.prefix.as_deref().unwrap_or(""));
        let store = FilesystemBlobStore::new(&store_root).unwrap_or_else(|error| panic!("{error}"));
        let object_id =
            BackendObjectId::new("commits/preexisting").unwrap_or_else(|error| panic!("{error}"));
        store
            .put(
                &object_id,
                Bytes::from_static(b"preexisting"),
                PutOptions {
                    retention: None,
                    legal_hold: None,
                    content_type: None,
                    do_not_recreate: true,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let runtime = RuntimeRepository::from_config(&config).await;

        assert!(
            matches!(runtime, Err(S3BoundaryError::RepositoryInit { reason }) if reason.contains("already exist"))
        );
    }

    #[tokio::test]
    async fn restore_readonly_runtime_refuses_empty_repository_bootstrap() {
        let dir = TestDir::new();
        let mut config = runtime_config(true);
        config.mode = GatewayMode::RestoreReadOnly;
        config.backend.endpoint = format!("file://{}", dir.path().display());

        let runtime = RuntimeRepository::from_config(&config).await;

        assert!(
            matches!(runtime, Err(S3BoundaryError::RepositoryInit { reason }) if reason.contains("restore-readonly"))
        );

        let store_root = dir
            .path()
            .join(&config.backend.bucket)
            .join(config.backend.prefix.as_deref().unwrap_or(""));
        let store = FilesystemBlobStore::new(&store_root).unwrap_or_else(|error| panic!("{error}"));
        let keyrings = store
            .list_prefix("keyrings/")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(keyrings.is_empty());
    }

    #[tokio::test]
    async fn startup_validation_rejects_missing_accepted_v3_commit() {
        let runtime = RuntimeRepository::from_config(&runtime_config(true))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let accepted = runtime
            .memory_v3_anchor()
            .unwrap_or_else(|| panic!("missing v2 memory anchor"))
            .read_v3()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing v2 anchor state"));
        runtime
            .memory_store()
            .unwrap_or_else(|| panic!("missing memory store"))
            .delete(&accepted.commit_key)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        runtime
            .load_accepted_anchor(GatewayMode::ReadWrite)
            .await
            .expect("a delete marker cannot hide the exact accepted version");
        runtime
            .memory_store()
            .expect("memory store")
            .delete_at(&accepted.commit_key, accepted.version_id.as_ref())
            .await
            .expect("delete exact accepted version");

        let loaded = runtime.load_accepted_anchor(GatewayMode::ReadWrite).await;

        assert!(
            matches!(loaded, Err(S3BoundaryError::RepositoryInit { reason }) if reason.contains("storage operation failed"))
        );
    }

    #[tokio::test]
    async fn runtime_repository_default_retention_applies_to_writes() {
        let mut config = runtime_config(true);
        config.repository.retention = Some(RetentionPolicy::new(RetentionMode::Compliance, 30));
        let runtime = RuntimeRepository::from_config_with_maintenance_guard(
            &config,
            Arc::new(rs3_repository::v3::UnenforcedQuiescedMaintenanceGuard),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        let put = runtime
            .put_committed(
                LogicalPath::new("snapshots/retained-default.bin")
                    .unwrap_or_else(|error| panic!("{error}")),
                Bytes::from_static(b"body"),
                RepositoryPutOptions::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            put.metadata.retention,
            Some(RetentionPolicy::new(RetentionMode::Compliance, 30))
        );

        let accepted = runtime
            .memory_v3_anchor()
            .unwrap_or_else(|| panic!("missing v2 memory anchor"))
            .read_v3()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing v2 anchor state"));
        let commit = runtime
            .memory_store()
            .unwrap_or_else(|| panic!("missing memory store"))
            .head_at(&accepted.commit_key, accepted.version_id.as_ref())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let retention = commit
            .retention
            .unwrap_or_else(|| panic!("missing backend retention"));
        assert_eq!(retention.mode, RetentionMode::Compliance);
        assert!(retention.retain_days >= 30);
    }

    #[tokio::test]
    async fn runtime_keyring_can_open_encrypted_envelope_source() {
        let repository_id =
            RepositoryId::new("test-repository").unwrap_or_else(|error| panic!("{error}"));
        let context = RepositoryKeyContext::new(repository_id.clone(), vec![2; 32])
            .unwrap_or_else(|error| panic!("{error}"));
        let keyring = KeyRing::generate_random().unwrap_or_else(|error| panic!("{error}"));
        let wrapping_key = SecretBytes::new(vec![12; SecretBytes::MIN_LEN])
            .unwrap_or_else(|error| panic!("{error}"));
        let envelope = keyring
            .seal_keyring_envelope(&context, "wrap-v1", &wrapping_key, 1)
            .unwrap_or_else(|error| panic!("{error}"));
        let object_id = BackendObjectId::new("keyrings/test-envelope.cbor")
            .unwrap_or_else(|error| panic!("{error}"));
        let memory = MemoryBlobStore::new();
        memory
            .put(
                &object_id,
                Bytes::from(
                    envelope
                        .to_object_bytes()
                        .unwrap_or_else(|error| panic!("{error}")),
                ),
                PutOptions {
                    retention: None,
                    legal_hold: None,
                    content_type: None,
                    do_not_recreate: true,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let store = RuntimeStore::new(memory);
        let expected_object_id = object_id.clone();
        let keys = RepositoryKeysConfig {
            repository_id,
            repository_salt_hex: Some(
                "0202020202020202020202020202020202020202020202020202020202020202".to_owned(),
            ),
            envelope_object_id: Some(object_id),
            wrapping_key_id: "wrap-v1".to_owned(),
            wrapping_key_hex: SecretString::from(
                "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            ),
        };

        let opened = unanchored_gateway_keyring(&store, &keys, None, true)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(opened.keyring.descriptors(), keyring.descriptors());
        assert_eq!(
            opened
                .keyring
                .derive_primary_blind_index_key(&rs3_types::LogicalPath::new("same").expect("path"))
                .unwrap_or_else(|error| panic!("{error}")),
            keyring
                .derive_primary_blind_index_key(&rs3_types::LogicalPath::new("same").expect("path"))
                .unwrap_or_else(|error| panic!("{error}"))
        );
        assert_eq!(
            opened
                .envelope_reference
                .as_ref()
                .map(|reference| reference.object_id.clone()),
            Some(expected_object_id)
        );
        assert_eq!(opened.repository_salt, vec![2; 32]);

        // Without a configured salt the verified envelope supplies it.
        let mut recovering = keys.clone();
        recovering.repository_salt_hex = None;
        let recovered = unanchored_gateway_keyring(&store, &recovering, None, true)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(recovered.repository_salt, vec![2; 32]);
        assert_eq!(recovered.keyring.descriptors(), keyring.descriptors());

        // A configured salt that disagrees with the envelope is an explicit
        // error, never a silent fallback to the envelope's value.
        let mut mismatched = keys.clone();
        mismatched.repository_salt_hex = Some("03".repeat(32));
        let error = match unanchored_gateway_keyring(&store, &mismatched, None, true).await {
            Ok(_) => panic!("configured salt must match the envelope"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("does not match the public salt"),
            "{error}"
        );
    }

    #[test]
    fn bundle_salt_digest_must_match_the_anchored_salt_when_present() {
        let salt = vec![5; 32];
        let digest = rs3_crypto::Sha256Hasher::digest(&salt);
        let missing = super::reject_bundle_salt_mismatch(None, &salt)
            .expect_err("the digest is part of the bundle contract");
        assert!(
            missing
                .to_string()
                .contains("lacks the repository salt digest")
        );
        assert!(super::reject_bundle_salt_mismatch(Some(digest), &salt).is_ok());
        let error =
            super::reject_bundle_salt_mismatch(Some([9; 32]), &salt).expect_err("foreign lineage");
        assert!(error.to_string().contains("salt digest"));
        assert!(super::reject_salt_disagreement(&salt, &salt).is_ok());
        assert!(super::reject_salt_disagreement(&salt, &[6; 32]).is_err());
    }

    #[tokio::test]
    async fn runtime_v3_format_root_binds_configured_keyring_envelope() {
        let dir = TestDir::new();
        let mut config = runtime_config(true);
        config.backend.endpoint = format!("file://{}", dir.path().display());
        config.batching = BatchConfig {
            max_items: 1,
            max_delay: Duration::from_millis(10),
            max_pending_items: 1,
        };

        let repository_id = config.repository_keys.repository_id.clone();
        let repository_salt = hex::decode(
            config
                .repository_keys
                .repository_salt_hex
                .as_deref()
                .expect("fixture salt"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let context = RepositoryKeyContext::new(repository_id, repository_salt)
            .unwrap_or_else(|error| panic!("{error}"));
        let keyring = KeyRing::generate_random().unwrap_or_else(|error| panic!("{error}"));
        let wrapping_key = SecretBytes::new(vec![12; SecretBytes::MIN_LEN])
            .unwrap_or_else(|error| panic!("{error}"));
        let envelope = keyring
            .seal_keyring_envelope(&context, "wrap-v1", &wrapping_key, 7)
            .unwrap_or_else(|error| panic!("{error}"));
        let envelope_object_id = BackendObjectId::new("keyrings/runtime-envelope.cbor")
            .unwrap_or_else(|error| panic!("{error}"));
        config.repository_keys.envelope_object_id = Some(envelope_object_id.clone());
        config.repository_keys.wrapping_key_id = "wrap-v1".to_owned();
        config.repository_keys.wrapping_key_hex =
            SecretString::from("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");

        let store_root = dir
            .path()
            .join(&config.backend.bucket)
            .join(config.backend.prefix.as_deref().unwrap_or(""));
        let store = FilesystemBlobStore::new(&store_root).unwrap_or_else(|error| panic!("{error}"));
        store
            .put(
                &envelope_object_id,
                Bytes::from(
                    envelope
                        .to_object_bytes()
                        .unwrap_or_else(|error| panic!("{error}")),
                ),
                PutOptions {
                    retention: None,
                    legal_hold: None,
                    content_type: None,
                    do_not_recreate: true,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let runtime = RuntimeRepository::from_config(&config)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        runtime
            .put_committed(
                LogicalPath::new("snapshots/enveloped.bin")
                    .unwrap_or_else(|error| panic!("{error}")),
                Bytes::from_static(b"body"),
                RepositoryPutOptions::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let accepted = runtime
            .memory_v3_anchor()
            .unwrap_or_else(|| panic!("missing v2 memory anchor"))
            .read_v3()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing v2 anchor state"));
        let body = store
            .get_range(&accepted.format_ref.object_id, ByteRange::Full)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let format_envelope = rs3_crypto::RepositoryEnvelope::from_object_bytes(
            &body,
            rs3_crypto::EnvelopePurpose::Format,
        )
        .unwrap_or_else(|error| {
            panic!("{error}");
        });
        let plaintext = format_envelope
            .open_format(
                &context,
                &config.repository_keys.wrapping_key_id,
                &wrapping_key,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let format_root = rs3_repository::v3::V3FormatRoot::from_plaintext_bytes(&plaintext)
            .unwrap_or_else(|error| panic!("{error}"));
        let reference = format_root.active_keyring_envelope_ref;

        assert_eq!(reference.generation, 7);
        assert_eq!(reference.object_id, envelope_object_id);
        assert_eq!(
            reference.digest,
            envelope.digest().unwrap_or_else(|error| panic!("{error}"))
        );
    }

    #[tokio::test]
    async fn runtime_factory_builds_file_repository() {
        let dir = TestDir::new();
        let mut config = runtime_config(true);
        config.backend.endpoint = format!("file://{}", dir.path().display());
        config.batching = BatchConfig {
            max_items: 1,
            max_delay: Duration::from_millis(10),
            max_pending_items: 1,
        };
        let runtime = RuntimeRepository::from_config(&config)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let key = LogicalPath::new("snapshots/file.bin").unwrap_or_else(|error| {
            panic!("{error}");
        });

        let put = runtime
            .put_committed(
                key.clone(),
                Bytes::from_static(b"file-backed body"),
                RepositoryPutOptions::default(),
            )
            .await;
        assert!(put.is_ok());

        let head = runtime.head(&key).unwrap_or_else(|error| {
            panic!("{error}");
        });
        let commits_root = dir
            .path()
            .join("backend-bucket")
            .join("repo")
            .join("commits")
            .join("v03");

        assert_eq!(head.content_len, 16);
        assert!(commits_root.is_dir());
    }

    #[tokio::test]
    async fn runtime_factory_rejects_unwired_backend() {
        let mut config = runtime_config(true);
        config.backend.endpoint = "unsupported://object.example".to_owned();

        let runtime = RuntimeRepository::from_config(&config).await;

        assert!(matches!(
            runtime,
            Err(S3BoundaryError::UnsupportedBackendMode)
        ));
    }

    #[cfg(feature = "s3")]
    #[test]
    fn runtime_factory_maps_http_endpoint_to_s3_backend_config() {
        let mut config = runtime_config(true);
        config.backend.endpoint = "http://127.0.0.1:9000".to_owned();
        config.backend.bucket = "backup-data".to_owned();
        config.backend.prefix = Some("repo".to_owned());

        let store_config = s3_backend_config(&config.backend)
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("expected S3 backend config"));

        assert_eq!(store_config.bucket, "backup-data");
        assert_eq!(store_config.prefix.as_deref(), Some("repo"));
        assert_eq!(
            store_config.endpoint_url.as_deref(),
            Some("http://127.0.0.1:9000")
        );
        assert!(store_config.allow_http);
        assert!(!store_config.virtual_hosted_style);
    }

    #[cfg(not(feature = "k8s"))]
    #[tokio::test]
    async fn runtime_factory_rejects_unwired_anchor() {
        let mut config = runtime_config(true);
        config.anchor = AnchorConfig::KubernetesLease {
            namespace: "backup".to_owned(),
            name: "v2-anchor".to_owned(),
            field_manager: "rs3-server".to_owned(),
        };

        let runtime = RuntimeRepository::from_config(&config).await;

        assert!(matches!(
            runtime,
            Err(S3BoundaryError::UnsupportedAnchorMode)
        ));
    }

    #[test]
    fn recovery_trust_rejects_bundle_below_external_floor() {
        let bundle = sample_bundle();

        let error = match verify_recovery_bundle_trust(
            &bundle,
            V3ProviderProfile::Dev,
            Sequence::new(8),
            None,
        ) {
            Ok(_) => panic!("below-floor recovery bundle should be rejected"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("below --min-sequence"));
    }

    #[test]
    fn production_recovery_trust_rejects_absent_signature() {
        let bundle = sample_bundle();

        let error = match verify_recovery_bundle_trust(
            &bundle,
            V3ProviderProfile::AtomicCreate,
            Sequence::new(7),
            Some(&recovery_public_key()),
        ) {
            Ok(_) => panic!("production recovery bundle without signature should be rejected"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("offline bundle signature"));
    }

    #[test]
    fn production_recovery_trust_rejects_bad_signature() {
        let mut bundle = sample_bundle();
        let public_key = sign_bundle(&mut bundle);
        if let Some(signature) = bundle.offline_signature.as_mut() {
            signature[0] ^= 0x80;
        }

        let error = match verify_recovery_bundle_trust(
            &bundle,
            V3ProviderProfile::AtomicCreate,
            Sequence::new(7),
            Some(&public_key),
        ) {
            Ok(_) => panic!("production recovery bundle with bad signature should be rejected"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("signature"));
    }

    #[test]
    fn production_recovery_trust_accepts_current_valid_signature() {
        let mut bundle = sample_bundle();
        let public_key = sign_bundle(&mut bundle);

        verify_recovery_bundle_trust(
            &bundle,
            V3ProviderProfile::AtomicCreate,
            Sequence::new(7),
            Some(&public_key),
        )
        .unwrap_or_else(|error| panic!("{error}"));
    }

    #[tokio::test]
    async fn import_newer_commit_scan_rejects_higher_sequence() {
        let store = MemoryBlobStore::new();
        store
            .put(
                &commit_object_id(8),
                Bytes::from_static(b"newer-commit-placeholder"),
                PutOptions::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = match reject_import_stranding_newer_commits(
            &store,
            V3ProviderProfile::Dev,
            Sequence::new(7),
            false,
        )
        .await
        {
            Ok(_) => panic!("newer commit sequence should block import"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("strand newer commit"));
    }

    #[tokio::test]
    async fn import_newer_commit_scan_allows_explicit_force_rollback() {
        let store = MemoryBlobStore::new();
        store
            .put(
                &commit_object_id(8),
                Bytes::from_static(b"newer-commit-placeholder"),
                PutOptions::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        reject_import_stranding_newer_commits(
            &store,
            V3ProviderProfile::RetainedVersionObjectLock,
            Sequence::new(7),
            true,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    }

    #[tokio::test]
    async fn bootstrap_empty_check_uses_version_listing_for_retained_profile() {
        let store = VersionOnlyListStore::new(commit_object_id(8));

        let error = match reject_v3_bootstrap_with_foreign_objects(
            &store,
            V3ProviderProfile::RetainedVersionObjectLock,
            None,
        )
        .await
        {
            Ok(_) => panic!("hidden commit version should block bootstrap"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("empty repository prefix"));
        assert_eq!(store.current_list_count(), 0);
        assert_eq!(store.version_list_count(), 1);
    }

    #[tokio::test]
    async fn bootstrap_refuses_every_retired_object_class_including_allowed_json_keyring() {
        for profile in [
            V3ProviderProfile::Dev,
            V3ProviderProfile::RetainedVersionObjectLock,
        ] {
            for key in ["commits/v02/old", "objects/v02/old", "keyrings/old.json"] {
                let store = MemoryBlobStore::new();
                let object_id = BackendObjectId::new(key).expect("object key");
                store
                    .put(
                        &object_id,
                        Bytes::from_static(b"retired"),
                        PutOptions::default(),
                    )
                    .await
                    .expect("fixture");
                assert!(
                    reject_v3_bootstrap_with_foreign_objects(&store, profile, None)
                        .await
                        .is_err()
                );
                if key.ends_with(".json") {
                    assert!(
                        reject_v3_bootstrap_with_foreign_objects(&store, profile, Some(&object_id))
                            .await
                            .is_err()
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn bootstrap_empty_check_rejects_a_prefix_containing_only_a_delete_marker() {
        let store = MemoryBlobStore::new();
        let key = commit_object_id(8);
        let object = store
            .put(&key, Bytes::from_static(b"old"), PutOptions::default())
            .await
            .expect("old version");
        store.delete(&key).await.expect("delete marker");
        store
            .delete_at(&key, object.version_id.as_ref())
            .await
            .expect("remove old version");
        assert!(
            store
                .list_prefix_versions("")
                .await
                .expect("no live versions")
                .is_empty()
        );

        assert!(
            super::prefix_has_any_object(&store, "", BlobListMode::Versions)
                .await
                .expect("version history probe")
        );
        assert!(
            !super::prefix_has_any_object(&store, "", BlobListMode::Current)
                .await
                .expect("current object probe")
        );

        let result = reject_v3_bootstrap_with_foreign_objects(
            &store,
            V3ProviderProfile::RetainedVersionObjectLock,
            None,
        )
        .await;
        assert!(
            matches!(result, Err(S3BoundaryError::RepositoryInit { reason })
            if reason.contains("empty repository prefix"))
        );
    }

    #[tokio::test]
    async fn filesystem_presence_probe_skips_directories_and_temporary_files() {
        let dir = TestDir::new();
        let store = FilesystemBlobStore::new(dir.path()).expect("filesystem store");
        std::fs::create_dir_all(dir.path().join("objects/empty")).expect("empty directory");
        std::fs::write(dir.path().join("objects/.rs3-tmp-fixture"), b"incomplete")
            .expect("temporary file");
        assert!(
            !super::prefix_has_any_object(&store, "", BlobListMode::Current)
                .await
                .expect("empty object inventory")
        );
        let key = BackendObjectId::new("objects/empty/object").expect("key");
        store
            .put(&key, Bytes::from_static(b"complete"), PutOptions::default())
            .await
            .expect("object");
        assert!(
            super::prefix_has_any_object(&store, "", BlobListMode::Current)
                .await
                .expect("object behind directory traversal")
        );
    }

    #[derive(Clone)]
    struct VersionOnlyListStore {
        object: BlobMetadata,
        current_lists: Arc<AtomicUsize>,
        version_lists: Arc<AtomicUsize>,
    }

    impl VersionOnlyListStore {
        fn new(object_id: BackendObjectId) -> Self {
            Self {
                object: BlobMetadata {
                    object_id,
                    content_len: 1,
                    modified_at_ms: Some(1),
                    etag: None,
                    version_id: Some(
                        BackendVersionId::new("hidden-version")
                            .unwrap_or_else(|error| panic!("{error}")),
                    ),
                    retention: None,
                    retain_until_ms: None,
                    legal_hold: None,
                },
                current_lists: Arc::new(AtomicUsize::new(0)),
                version_lists: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn current_list_count(&self) -> usize {
            self.current_lists.load(Ordering::SeqCst)
        }

        fn version_list_count(&self) -> usize {
            self.version_lists.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl BlobStore for VersionOnlyListStore {
        async fn put(
            &self,
            _object_id: &BackendObjectId,
            _body: Bytes,
            _options: PutOptions,
        ) -> rs3_storage::Result<BlobMetadata> {
            unsupported_store_operation()
        }

        async fn get_range(
            &self,
            _object_id: &BackendObjectId,
            _range: ByteRange,
        ) -> rs3_storage::Result<Bytes> {
            unsupported_store_operation()
        }

        async fn head(&self, _object_id: &BackendObjectId) -> rs3_storage::Result<BlobMetadata> {
            unsupported_store_operation()
        }

        async fn list_prefix(&self, _prefix: &str) -> rs3_storage::Result<Vec<BlobMetadata>> {
            unsupported_store_operation()
        }

        async fn list_prefix_versions(
            &self,
            prefix: &str,
        ) -> rs3_storage::Result<Vec<BlobMetadata>> {
            let _ = prefix;
            unsupported_store_operation()
        }

        async fn open_bounded_list(
            &self,
            prefix: &str,
            mode: BlobListMode,
        ) -> rs3_storage::Result<Box<dyn BlobList>> {
            match mode {
                BlobListMode::Current => {
                    self.current_lists.fetch_add(1, Ordering::SeqCst);
                    Ok(Box::new(VersionOnlyList { object: None }))
                }
                BlobListMode::Versions => {
                    self.version_lists.fetch_add(1, Ordering::SeqCst);
                    let object = self
                        .object
                        .object_id
                        .as_str()
                        .starts_with(prefix)
                        .then(|| self.object.clone());
                    Ok(Box::new(VersionOnlyList { object }))
                }
            }
        }

        async fn delete(&self, _object_id: &BackendObjectId) -> rs3_storage::Result<()> {
            unsupported_store_operation()
        }

        async fn extend_retention(
            &self,
            _object_id: &BackendObjectId,
            _policy: RetentionPolicy,
        ) -> rs3_storage::Result<()> {
            unsupported_store_operation()
        }

        async fn set_legal_hold(
            &self,
            _object_id: &BackendObjectId,
            _status: LegalHoldStatus,
        ) -> rs3_storage::Result<()> {
            unsupported_store_operation()
        }

        async fn flush_caches(&self) -> rs3_storage::Result<()> {
            Ok(())
        }
    }

    struct VersionOnlyList {
        object: Option<BlobMetadata>,
    }

    #[async_trait::async_trait]
    impl BlobList for VersionOnlyList {
        async fn next_page(
            &mut self,
            _max_items: NonZeroUsize,
        ) -> rs3_storage::Result<BlobListPage> {
            let entries = self.object.take().into_iter().collect::<Vec<_>>();
            Ok(BlobListPage {
                consumed_items: entries.len(),
                entries,
                is_complete: true,
            })
        }
    }

    fn unsupported_store_operation<T>() -> rs3_storage::Result<T> {
        Err(StorageError::Provider(
            "version-only list store does not implement this operation".to_owned(),
        ))
    }

    fn sample_bundle() -> V3RecoveryBundle {
        V3RecoveryBundle {
            repository_id: Some(
                RepositoryId::new("test-repository").unwrap_or_else(|error| panic!("{error}")),
            ),
            repository_salt_digest: None,
            anchor: V3AnchorState {
                sequence: Sequence::new(7),
                commit_key: BackendObjectId::new(
                    "commits/v03/00000000000000000007/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                )
                .unwrap_or_else(|error| panic!("{error}")),
                body_digest: [0x11; 32],
                version_id: Some(
                    BackendVersionId::new("commit-version-a")
                        .unwrap_or_else(|error| panic!("{error}")),
                ),
                signing_key_id: KeyId::new("checkpoint-v1")
                    .unwrap_or_else(|error| panic!("{error}")),
                format_ref: V3FormatRef {
                    generation: 1,
                    digest: "2222222222222222222222222222222222222222222222222222222222222222"
                        .to_owned(),
                    object_id: BackendObjectId::new("format/00000000000000000001/root")
                        .unwrap_or_else(|error| panic!("{error}")),
                    version_id: Some(
                        BackendVersionId::new("format-version-a")
                            .unwrap_or_else(|error| panic!("{error}")),
                    ),
                },
            },
            weak_subjectivity_floor_sequence: Sequence::new(7),
            exported_at_ms: 42,
            offline_signature: None,
        }
    }

    fn sign_bundle(bundle: &mut V3RecoveryBundle) -> String {
        let keyring = KeyRing::generate_random().unwrap_or_else(|error| panic!("{error}"));
        let payload = bundle
            .offline_signature_payload()
            .unwrap_or_else(|error| panic!("{error}"));
        let signature = keyring
            .sign_checkpoint_payload(&payload)
            .unwrap_or_else(|error| panic!("{error}"));
        let public_key = keyring
            .descriptors()
            .into_iter()
            .find(|descriptor| descriptor.purpose == KeyPurpose::CheckpointSigning)
            .and_then(|descriptor| descriptor.public_key)
            .unwrap_or_else(|| panic!("missing recovery public key"));
        bundle.offline_signature = Some(signature.signature);
        public_key
    }

    fn recovery_public_key() -> String {
        let mut bundle = sample_bundle();
        sign_bundle(&mut bundle)
    }

    fn commit_object_id(sequence: u64) -> BackendObjectId {
        BackendObjectId::new(format!(
            "commits/v03/{sequence:020}/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ))
        .unwrap_or_else(|error| panic!("{error}"))
    }
}

#[cfg(all(test, feature = "s3"))]
#[path = "preflight_tests.rs"]
mod preflight_tests;
