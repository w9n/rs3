//! Runtime configuration loaded from process environment.

use crate::identity::StaticCredentials;
use rs3_crypto::{MIN_REPOSITORY_SALT_LEN, SecretBytes, ct_eq, validate_recovery_public_key};
use rs3_repository::v2::{DEFAULT_RETENTION_RENEWAL_HORIZON, V2MaintenanceBudgets};
use rs3_repository::{DEFAULT_PAYLOAD_SEGMENT_SIZE, v2::DEFAULT_V2_STREAM_READ_STALL_TIMEOUT};
use rs3_types::{BackendObjectId, PublicBucket, RepositoryId, RetentionMode, RetentionPolicy};
use secrecy::{ExposeSecret, SecretString};
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Semaphore;

const DEFAULT_BIND: &str = "127.0.0.1:9080";
const DEFAULT_ANCHOR_FIELD_MANAGER: &str = "rs3-server";
pub const DEFAULT_KEYRING_WRAPPING_KEY_ID: &str = "wrap-v1";
const DEFAULT_BATCH_ITEMS: usize = 64;
const DEFAULT_BATCH_DELAY_MS: u64 = 25;
const DEFAULT_MAX_PUT_OBJECT_BYTES: u64 = 5 * 1024 * 1024 * 1024;
const DEFAULT_BUFFERED_PUT_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_BACKEND_MULTIPART_PART_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_MAX_IN_FLIGHT_DOWNLOAD_BODY_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_MAX_CONCURRENT_CONNECTIONS: usize = 1024;
const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 256;
const DEFAULT_REQUEST_RATE_LIMIT_PER_SECOND: u64 = 1024;
const DEFAULT_BACKEND_CONNECT_TIMEOUT_SECONDS: u64 = 5;
const DEFAULT_BACKEND_READ_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_BACKEND_OPERATION_ATTEMPT_TIMEOUT_SECONDS: u64 = 120;
const DEFAULT_BACKEND_OPERATION_TIMEOUT_SECONDS: u64 = 300;
const DEFAULT_BACKEND_STALLED_STREAM_GRACE_SECONDS: u64 = 30;
const DEFAULT_PROVIDER_CONFORMANCE_MAX_AGE_SECONDS: u64 = 7 * 24 * 60 * 60;
const MIN_BACKEND_MULTIPART_PART_BYTES: u64 = 5 * 1024 * 1024;
const MAX_BACKEND_MULTIPART_PART_BYTES: u64 = 5 * 1024 * 1024 * 1024;
const REDACTED_SECRET_VALUE: &str = "<redacted>";
const MIN_REPOSITORY_KEY_HEX_LEN: usize = SecretBytes::MIN_LEN * 2;
const MIN_REPOSITORY_SALT_HEX_LEN: usize = MIN_REPOSITORY_SALT_LEN * 2;
const REPOSITORY_RETENTION_MODE_ENV: &str = "RS3_REPOSITORY_RETENTION_MODE";
const REPOSITORY_RETENTION_DAYS_ENV: &str = "RS3_REPOSITORY_RETENTION_DAYS";
const REPOSITORY_FORMAT_ENV: &str = "RS3_REPOSITORY_FORMAT";
const ALLOW_REPOSITORY_INIT_ENV: &str = "RS3_ALLOW_REPOSITORY_INIT";
const BACKEND_PREFIX_ENV: &str = "RS3_BACKEND_PREFIX";
const ANCHOR_NAMESPACE_ENV: &str = "RS3_ANCHOR_NAMESPACE";
const ANCHOR_NAME_ENV: &str = "RS3_ANCHOR_NAME";
const ANCHOR_FIELD_MANAGER_ENV: &str = "RS3_ANCHOR_FIELD_MANAGER";
const STATIC_ACCESS_KEY_ID_ENV: &str = "RS3_STATIC_ACCESS_KEY_ID";
const STATIC_SECRET_ACCESS_KEY_ENV: &str = "RS3_STATIC_SECRET_ACCESS_KEY";
const PROVIDER_CONFORMANCE_REPORT_FILE_ENV: &str = "RS3_PROVIDER_CONFORMANCE_REPORT_FILE";
const PROVIDER_CONFORMANCE_MAX_AGE_SECONDS_ENV: &str = "RS3_PROVIDER_CONFORMANCE_MAX_AGE_SECONDS";
const PROVIDER_PRINCIPAL_FINGERPRINT_ENV: &str = "RS3_PROVIDER_PRINCIPAL_FINGERPRINT";
pub(crate) const RECOVERY_PUBLIC_KEY_ENV: &str = "RS3_RECOVERY_PUBLIC_KEY";

pub(crate) const REPOSITORY_SALT_HEX_ENV: &str = "RS3_REPOSITORY_SALT_HEX";
pub(crate) const KEYRING_ENVELOPE_OBJECT_ID_ENV: &str = "RS3_KEYRING_ENVELOPE_OBJECT_ID";
pub(crate) const KEYRING_WRAPPING_KEY_HEX_ENV: &str = "RS3_KEYRING_WRAPPING_KEY_HEX";
pub(crate) const KEYRING_WRAPPING_KEY_ID_ENV: &str = "RS3_KEYRING_WRAPPING_KEY_ID";
const REPOSITORY_ID_ENV: &str = "RS3_REPOSITORY_ID";
const ALLOW_MEMORY_ANCHOR_ENV: &str = "RS3_ALLOW_MEMORY_ANCHOR";
const WRITER_GUARD_ENV: &str = "RS3_WRITER_GUARD";
const MAINTENANCE_MODE_ENV: &str = "RS3_MAINTENANCE_MODE";
const MAINTENANCE_RENEWAL_HORIZON_SECONDS_ENV: &str = "RS3_MAINTENANCE_RENEWAL_HORIZON_SECONDS";
const MAINTENANCE_ORPHAN_PRESSURE_BYTES_ENV: &str = "RS3_MAINTENANCE_ORPHAN_PRESSURE_BYTES";
const MAINTENANCE_ORPHAN_PRESSURE_COUNT_ENV: &str = "RS3_MAINTENANCE_ORPHAN_PRESSURE_COUNT";
const MAINTENANCE_ORPHAN_PRESSURE_MAX_AGE_SECONDS_ENV: &str =
    "RS3_MAINTENANCE_ORPHAN_PRESSURE_MAX_AGE_SECONDS";
const MAINTENANCE_MAX_INTERVAL_SECONDS_ENV: &str = "RS3_MAINTENANCE_MAX_INTERVAL_SECONDS";
const MAINTENANCE_MIN_COOLDOWN_SECONDS_ENV: &str = "RS3_MAINTENANCE_MIN_COOLDOWN_SECONDS";
const MAINTENANCE_PACING_DELAY_MS_ENV: &str = "RS3_MAINTENANCE_PACING_DELAY_MS";
const MAINTENANCE_MAX_INVENTORY_PAGES_ENV: &str = "RS3_MAINTENANCE_MAX_INVENTORY_PAGES";
const MAINTENANCE_MAX_INVENTORY_ITEMS_ENV: &str = "RS3_MAINTENANCE_MAX_INVENTORY_ITEMS";
const DEFAULT_MAINTENANCE_ORPHAN_PRESSURE_BYTES: u64 = 1024 * 1024 * 1024;
const DEFAULT_MAINTENANCE_ORPHAN_PRESSURE_COUNT: u64 = 512;
const DEFAULT_MAINTENANCE_ORPHAN_PRESSURE_MAX_AGE_SECONDS: u64 = 48 * 60 * 60;
const DEFAULT_MAINTENANCE_MAX_INTERVAL_SECONDS: u64 = 7 * 24 * 60 * 60;
const DEFAULT_MAINTENANCE_MIN_COOLDOWN_SECONDS: u64 = 60 * 60;

/// Complete runtime configuration for the gateway process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeConfig {
    /// Gateway mutation posture.
    pub mode: GatewayMode,
    /// Socket address the gateway should bind to.
    pub bind: SocketAddr,
    /// Metrics exporter settings.
    pub metrics: MetricsConfig,
    /// Data-plane hardening limits.
    pub hardening: HardeningConfig,
    /// Client-visible bucket served by this process.
    pub public_bucket: PublicBucket,
    /// Backend object-store settings.
    pub backend: BackendConfig,
    /// Checkpoint anchor settings.
    pub anchor: AnchorConfig,
    /// Single-writer guard settings.
    pub writer_guard: WriterGuardConfig,
    /// Coordinated commit batching settings.
    pub batching: BatchConfig,
    /// Repository object layout settings.
    pub repository: RepositoryConfig,
    /// In-gateway maintenance supervisor settings.
    pub maintenance: MaintenanceConfig,
    /// Last provider-conformance evidence settings.
    pub provider_conformance: ProviderConformanceConfig,
    /// Disaster-recovery trust settings.
    pub recovery: RecoveryConfig,
    /// Repository cryptographic key material.
    pub repository_keys: RepositoryKeysConfig,
    /// Optional static credentials accepted by the server.
    pub static_credentials: Option<StaticCredentials>,
}

/// Minimal configuration needed to probe v2 provider behavior.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2ProviderCheckConfig {
    /// Backend object-store settings.
    pub backend: BackendConfig,
    /// Durable repository format selected for the provider check.
    pub repository_format: RepositoryFormat,
    /// Default provider retention policy for repository-owned objects.
    pub repository_retention: Option<RetentionPolicy>,
    /// Operator-derived fingerprint of the backend credential principal.
    pub principal_fingerprint: Option<String>,
}

/// Minimal repository context needed by operator maintenance tools.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryToolConfig {
    /// Backend object-store settings.
    pub backend: BackendConfig,
    /// Durable repository format selected for the tool operation.
    pub repository_format: RepositoryFormat,
    /// Default provider retention policy for repository-owned objects.
    pub repository_retention: Option<RetentionPolicy>,
    /// Disaster-recovery trust settings.
    pub recovery: RecoveryConfig,
    /// Repository key context without the wrapping-key secret.
    pub repository_keys: RepositoryKeyContextConfig,
}

/// Repository key context used by commands that read wrapping-key material separately.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryKeyContextConfig {
    /// Stable repository derivation context.
    pub repository_id: RepositoryId,
    /// Stable public salt used with the repository ID when opening envelopes.
    pub repository_salt_hex: String,
    /// Optional bootstrap or recovery override for an encrypted keyring envelope object.
    pub envelope_object_id: Option<BackendObjectId>,
    /// Operator-visible wrapping key identifier.
    pub wrapping_key_id: String,
}

impl From<&RuntimeConfig> for V2ProviderCheckConfig {
    fn from(config: &RuntimeConfig) -> Self {
        Self {
            backend: config.backend.clone(),
            repository_format: config.repository.format,
            repository_retention: config.repository.retention,
            principal_fingerprint: config.provider_conformance.principal_fingerprint.clone(),
        }
    }
}

impl From<&RuntimeConfig> for RepositoryToolConfig {
    fn from(config: &RuntimeConfig) -> Self {
        Self {
            backend: config.backend.clone(),
            repository_format: config.repository.format,
            repository_retention: config.repository.retention,
            recovery: config.recovery.clone(),
            repository_keys: RepositoryKeyContextConfig::from(&config.repository_keys),
        }
    }
}

impl From<&RepositoryKeysConfig> for RepositoryKeyContextConfig {
    fn from(config: &RepositoryKeysConfig) -> Self {
        Self {
            repository_id: config.repository_id.clone(),
            repository_salt_hex: config.repository_salt_hex.clone(),
            envelope_object_id: config.envelope_object_id.clone(),
            wrapping_key_id: config.wrapping_key_id.clone(),
        }
    }
}

/// Gateway mutation posture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayMode {
    /// Serve reads and accept committed repository mutations.
    ReadWrite,
    /// Serve restore reads only; reject repository mutations and do not bootstrap.
    RestoreReadOnly,
}

impl GatewayMode {
    /// Returns the environment/configuration spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadWrite => "read-write",
            Self::RestoreReadOnly => "restore-readonly",
        }
    }

    /// Returns whether this mode accepts client-visible repository mutations.
    pub const fn allows_mutation(self) -> bool {
        matches!(self, Self::ReadWrite)
    }

    pub(crate) const fn requires_anchor(self) -> bool {
        matches!(self, Self::RestoreReadOnly)
    }
}

/// Single-writer runtime guard posture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriterGuardConfig {
    /// Acquire and renew a Kubernetes writer Lease before serving writes.
    Required,
    /// Do not acquire a writer Lease.
    Off,
}

impl WriterGuardConfig {
    /// Returns the environment/configuration spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Off => "off",
        }
    }
}

/// Backend object-store settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendConfig {
    /// Backend object-store endpoint.
    pub endpoint: String,
    /// Backend bucket that stores repository objects.
    pub bucket: String,
    /// Optional backend prefix for repository-owned objects.
    pub prefix: Option<String>,
    /// Finite provider operation and stream-progress timeouts.
    pub timeouts: BackendTimeoutConfig,
}

/// Provider-neutral timeout policy for backend operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackendTimeoutConfig {
    /// Maximum time to establish a backend socket connection.
    pub connect: Duration,
    /// Maximum time from request initiation to the first response byte.
    pub read: Duration,
    /// Maximum duration of one backend request attempt.
    pub operation_attempt: Duration,
    /// Maximum total duration across all attempts and retries.
    pub operation: Duration,
    /// Maximum time an upload or download stream may stop making progress.
    pub stalled_stream_grace: Duration,
}

impl Default for BackendTimeoutConfig {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(DEFAULT_BACKEND_CONNECT_TIMEOUT_SECONDS),
            read: Duration::from_secs(DEFAULT_BACKEND_READ_TIMEOUT_SECONDS),
            operation_attempt: Duration::from_secs(
                DEFAULT_BACKEND_OPERATION_ATTEMPT_TIMEOUT_SECONDS,
            ),
            operation: Duration::from_secs(DEFAULT_BACKEND_OPERATION_TIMEOUT_SECONDS),
            stalled_stream_grace: Duration::from_secs(DEFAULT_BACKEND_STALLED_STREAM_GRACE_SECONDS),
        }
    }
}

/// Metrics exporter settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetricsConfig {
    /// Optional Prometheus/OpenMetrics scrape listener.
    pub bind: Option<SocketAddr>,
}

/// Data-plane hardening limits enforced by the gateway process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HardeningConfig {
    /// Maximum accepted `PutObject` request body size.
    pub max_put_object_bytes: u64,
    /// Largest `PutObject` body buffered as a single repository write.
    pub buffered_put_object_bytes: u64,
    /// Provider multipart part size for large streaming `PutObject` writes.
    pub backend_multipart_part_bytes: u64,
    /// Maximum idle time between streamed request-body chunks.
    pub stream_read_stall_timeout: Duration,
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
}

impl Default for HardeningConfig {
    fn default() -> Self {
        Self {
            max_put_object_bytes: DEFAULT_MAX_PUT_OBJECT_BYTES,
            buffered_put_object_bytes: DEFAULT_BUFFERED_PUT_OBJECT_BYTES,
            backend_multipart_part_bytes: DEFAULT_BACKEND_MULTIPART_PART_BYTES,
            stream_read_stall_timeout: DEFAULT_V2_STREAM_READ_STALL_TIMEOUT,
            max_in_flight_upload_body_bytes: DEFAULT_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES,
            max_in_flight_download_body_bytes: DEFAULT_MAX_IN_FLIGHT_DOWNLOAD_BODY_BYTES,
            max_concurrent_connections: DEFAULT_MAX_CONCURRENT_CONNECTIONS,
            max_concurrent_requests: DEFAULT_MAX_CONCURRENT_REQUESTS,
            request_rate_limit_per_second: DEFAULT_REQUEST_RATE_LIMIT_PER_SECOND,
        }
    }
}

/// Checkpoint anchor settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorConfig {
    /// In-process anchor for local development and tests.
    Memory,
    /// Kubernetes Lease object used as the monotonic v2 commit anchor.
    KubernetesLease {
        /// Kubernetes namespace containing the Lease.
        namespace: String,
        /// Kubernetes Lease name.
        name: String,
        /// Server-side apply field manager.
        field_manager: String,
    },
}

/// Coordinated commit batching settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchConfig {
    /// Maximum number of staged writes covered by one commit.
    pub max_items: usize,
    /// Maximum delay before publishing a partial batch.
    pub max_delay: Duration,
    /// Maximum number of writes waiting for commit before backpressure.
    pub max_pending_items: usize,
}

/// Repository object layout settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepositoryConfig {
    /// Durable repository format selected by this runtime.
    pub format: RepositoryFormat,
    /// Plaintext bytes per independently encrypted payload segment.
    pub payload_segment_size: usize,
    /// Whether the gateway adapts payload segment size upward by object size.
    pub adaptive_payload_segment_size: bool,
    /// Maximum plaintext bytes retained in the decrypted segment LRU cache.
    pub decrypted_segment_cache_max_bytes: u64,
    /// Default provider retention policy for repository-owned objects.
    pub retention: Option<RetentionPolicy>,
    /// Allows first-run repository initialization when the configured anchor is missing.
    pub allow_init: bool,
}

/// In-gateway maintenance supervisor posture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaintenanceMode {
    /// Run full maintenance automatically from supervisor triggers.
    Auto,
    /// Keep the supervisor idle until an operator trigger arrives.
    Manual,
    /// Do not run the maintenance supervisor at all.
    Off,
}

impl MaintenanceMode {
    /// Returns the environment/configuration spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Manual => "manual",
            Self::Off => "off",
        }
    }
}

/// In-gateway maintenance supervisor settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaintenanceConfig {
    /// Supervisor posture. Forced off for restore-readonly gateways.
    pub mode: MaintenanceMode,
    /// Lead time before the nearest provider retain-until deadline.
    pub renewal_horizon: Duration,
    /// Orphan bytes at which a full-maintenance run becomes due.
    pub orphan_pressure_bytes: u64,
    /// Orphan candidate count at which a full-maintenance run becomes due.
    pub orphan_pressure_count: u64,
    /// Oldest orphan age at which a full-maintenance run becomes due.
    pub orphan_pressure_max_age: Duration,
    /// Maximum interval between automatic full-maintenance runs.
    pub max_interval: Duration,
    /// Minimum cooldown between full-maintenance runs.
    pub min_cooldown: Duration,
    /// Optional pacing delay between maintenance backend operations.
    pub pacing_delay: Option<Duration>,
    /// Maximum provider pages consumed while building maintenance inventory.
    pub max_inventory_pages: u64,
    /// Maximum raw provider members consumed while building maintenance inventory.
    pub max_inventory_items: u64,
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        let budget_defaults = V2MaintenanceBudgets::default();
        Self {
            mode: MaintenanceMode::Auto,
            renewal_horizon: DEFAULT_RETENTION_RENEWAL_HORIZON,
            orphan_pressure_bytes: DEFAULT_MAINTENANCE_ORPHAN_PRESSURE_BYTES,
            orphan_pressure_count: DEFAULT_MAINTENANCE_ORPHAN_PRESSURE_COUNT,
            orphan_pressure_max_age: Duration::from_secs(
                DEFAULT_MAINTENANCE_ORPHAN_PRESSURE_MAX_AGE_SECONDS,
            ),
            max_interval: Duration::from_secs(DEFAULT_MAINTENANCE_MAX_INTERVAL_SECONDS),
            min_cooldown: Duration::from_secs(DEFAULT_MAINTENANCE_MIN_COOLDOWN_SECONDS),
            pacing_delay: None,
            max_inventory_pages: budget_defaults.max_inventory_page_count,
            max_inventory_items: budget_defaults.max_inventory_item_count,
        }
    }
}

impl MaintenanceConfig {
    /// Returns the forced posture for restore-readonly gateways.
    pub fn forced_off() -> Self {
        Self {
            mode: MaintenanceMode::Off,
            ..Self::default()
        }
    }

    /// Returns maintenance I/O budgets derived from these settings.
    pub fn budgets(&self) -> V2MaintenanceBudgets {
        V2MaintenanceBudgets {
            max_inventory_page_count: self.max_inventory_pages,
            max_inventory_item_count: self.max_inventory_items,
            op_pacing_delay: self.pacing_delay,
            ..V2MaintenanceBudgets::default()
        }
    }
}

/// Provider-conformance evidence settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderConformanceConfig {
    /// Optional JSON report emitted by `rs3 check-v2-provider`.
    pub report_file: Option<PathBuf>,
    /// Maximum accepted report age before status marks the evidence stale.
    pub max_age: Duration,
    /// Operator-derived fingerprint of the backend credential principal.
    pub principal_fingerprint: Option<String>,
}

/// Disaster-recovery trust settings.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecoveryConfig {
    /// Operator-controlled public key used to verify recovery bundle signatures.
    pub public_key: Option<String>,
}

impl Default for ProviderConformanceConfig {
    fn default() -> Self {
        Self {
            report_file: None,
            max_age: Duration::from_secs(DEFAULT_PROVIDER_CONFORMANCE_MAX_AGE_SECONDS),
            principal_fingerprint: None,
        }
    }
}

/// Durable repository format selected by this runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepositoryFormat {
    /// Production-preview format for new repositories.
    V2Preview,
}

impl RepositoryFormat {
    /// Returns the environment/configuration spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V2Preview => "v2-preview",
        }
    }
}

/// Encrypted repository keyring envelope settings.
#[derive(Clone)]
pub struct RepositoryKeysConfig {
    /// Stable repository derivation context.
    pub repository_id: RepositoryId,
    /// Stable public salt used with the repository ID when opening the envelope.
    pub repository_salt_hex: String,
    /// Optional bootstrap or recovery override for the encrypted keyring envelope.
    pub envelope_object_id: Option<BackendObjectId>,
    /// Operator-visible wrapping key identifier.
    pub wrapping_key_id: String,
    /// Wrapping key used to decrypt the keyring envelope.
    pub wrapping_key_hex: SecretString,
}

impl fmt::Debug for RepositoryKeysConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepositoryKeysConfig")
            .field("repository_id", &"<configured>")
            .field("repository_salt_hex", &"<configured>")
            .field("envelope_object_id", &"<configured>")
            .field("wrapping_key_id", &"<configured>")
            .field("wrapping_key_hex", &REDACTED_SECRET_VALUE)
            .finish()
    }
}

impl PartialEq for RepositoryKeysConfig {
    fn eq(&self, other: &Self) -> bool {
        self.repository_id == other.repository_id
            && self.repository_salt_hex == other.repository_salt_hex
            && self.envelope_object_id == other.envelope_object_id
            && self.wrapping_key_id == other.wrapping_key_id
            && secret_string_eq(&self.wrapping_key_hex, &other.wrapping_key_hex)
    }
}

impl Eq for RepositoryKeysConfig {}

/// Runtime configuration errors.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    /// Multiple independent configuration errors were found.
    #[error(
        "runtime configuration has {count} errors:{messages}",
        count = errors.len(),
        messages = format_config_errors(errors)
    )]
    Multiple {
        /// Collected configuration errors.
        errors: Vec<ConfigError>,
    },
    /// A required environment variable is missing or blank.
    #[error(
        "missing required environment variable: {key}; see docs/site/reference/configuration.md for expected rs3 environment configuration"
    )]
    Missing {
        /// Environment variable name.
        key: &'static str,
    },
    /// An environment variable has an invalid value.
    #[error("invalid environment variable {key}={value:?}: {reason}")]
    Invalid {
        /// Environment variable name.
        key: &'static str,
        /// Provided value.
        value: String,
        /// Validation failure reason.
        reason: String,
    },
    /// Static access key and secret key must be configured together.
    #[error("{access_key_id} and {secret_access_key} must be set together")]
    PartialStaticCredentials {
        /// Access key ID environment variable name.
        access_key_id: &'static str,
        /// Secret access key environment variable name.
        secret_access_key: &'static str,
    },
}

fn config_error_list(errors: Vec<ConfigError>) -> ConfigError {
    match errors.as_slice() {
        [error] => error.clone(),
        _ => ConfigError::Multiple { errors },
    }
}

fn format_config_errors(errors: &[ConfigError]) -> String {
    let mut message = String::new();
    for error in errors {
        message.push_str("\n  - ");
        message.push_str(&error.to_string());
    }
    message
}

impl RuntimeConfig {
    /// Loads runtime configuration from the current process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_source(&ProcessEnv)
    }

    /// Validates invariants required by every runtime construction path.
    ///
    /// This must be called for programmatically assembled configurations as
    /// well as environment-derived configurations. Public server constructors
    /// enforce it before allocating runtime resources.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut errors = Vec::new();
        validate_runtime_backend(&mut errors, &self.backend);
        validate_runtime_anchor(&mut errors, &self.anchor);
        validate_runtime_hardening(&mut errors, &self.hardening);
        validate_runtime_batching(&mut errors, &self.batching);
        validate_runtime_repository(&mut errors, &self.repository);
        validate_runtime_maintenance(&mut errors, self.mode, &self.maintenance);
        validate_runtime_provider_conformance(&mut errors, &self.provider_conformance);
        validate_runtime_writer_guard(&mut errors, &self.anchor, self.writer_guard);
        validate_runtime_repository_keys(&mut errors, &self.repository_keys);
        validate_runtime_recovery(&mut errors, &self.recovery);
        validate_runtime_static_credentials(&mut errors, self.static_credentials.as_ref());
        validate_upload_memory_budget(&mut errors, &self.hardening, &self.repository);

        if errors.is_empty() {
            Ok(())
        } else {
            Err(config_error_list(errors))
        }
    }

    fn from_source(source: &impl ConfigSource) -> Result<Self, ConfigError> {
        let mut errors = Vec::new();
        let mode = collect_config_error(&mut errors, parse_gateway_mode(source));
        let bind = collect_config_error(
            &mut errors,
            parse_socket_addr(
                "RS3_BIND",
                source
                    .value("RS3_BIND")
                    .unwrap_or_else(|| DEFAULT_BIND.to_owned()),
            ),
        );
        let metrics = collect_config_error(&mut errors, parse_metrics_config(source));
        let hardening = collect_config_error(&mut errors, parse_hardening_config(source));
        let public_bucket_value =
            collect_config_error(&mut errors, required_value(source, "RS3_PUBLIC_BUCKET"));
        let public_bucket = public_bucket_value
            .map(|value| {
                collect_config_error(&mut errors, parse_public_bucket("RS3_PUBLIC_BUCKET", value))
            })
            .unwrap_or(None);
        let backend = collect_config_error(&mut errors, parse_backend_config(source));
        let anchor = collect_config_error(&mut errors, parse_anchor_config(source));
        let writer_guard = match anchor.as_ref() {
            Some(anchor) => {
                collect_config_error(&mut errors, parse_writer_guard_config(source, anchor))
            }
            None => collect_config_error(&mut errors, parse_writer_guard_value(source))
                .map(|value| value.unwrap_or(WriterGuardConfig::Off)),
        };
        let batching = collect_config_error(&mut errors, parse_batch_config(source));
        let repository = collect_config_error(&mut errors, parse_repository_config(source));
        let maintenance = collect_config_error(
            &mut errors,
            parse_maintenance_config(source, mode.unwrap_or(GatewayMode::ReadWrite)),
        );
        let provider_conformance =
            collect_config_error(&mut errors, parse_provider_conformance_config(source));
        let recovery = collect_config_error(&mut errors, parse_recovery_config(source));
        let repository_keys =
            collect_config_error(&mut errors, parse_repository_keys_config(source));
        let static_credentials =
            collect_config_error(&mut errors, parse_static_credentials(source));

        if !errors.is_empty() {
            return Err(config_error_list(errors));
        }

        let config = Self {
            mode: require_collected_config(mode)?,
            bind: require_collected_config(bind)?,
            metrics: require_collected_config(metrics)?,
            hardening: require_collected_config(hardening)?,
            public_bucket: require_collected_config(public_bucket)?,
            backend: require_collected_config(backend)?,
            anchor: require_collected_config(anchor)?,
            writer_guard: require_collected_config(writer_guard)?,
            batching: require_collected_config(batching)?,
            repository: require_collected_config(repository)?,
            maintenance: require_collected_config(maintenance)?,
            provider_conformance: require_collected_config(provider_conformance)?,
            recovery: require_collected_config(recovery)?,
            repository_keys: require_collected_config(repository_keys)?,
            static_credentials: require_collected_config(static_credentials)?,
        };
        config.validate()?;
        Ok(config)
    }
}

impl V2ProviderCheckConfig {
    /// Loads v2 provider check configuration from the current process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_source(&ProcessEnv)
    }

    fn from_source(source: &impl ConfigSource) -> Result<Self, ConfigError> {
        let mut errors = Vec::new();
        let backend = collect_config_error(&mut errors, parse_backend_config(source));
        let repository_format = collect_config_error(&mut errors, parse_repository_format(source));
        let repository_retention =
            collect_config_error(&mut errors, parse_retention_policy(source));
        let principal_fingerprint =
            collect_config_error(&mut errors, parse_provider_principal_fingerprint(source));

        if !errors.is_empty() {
            return Err(config_error_list(errors));
        }

        Ok(Self {
            backend: require_collected_config(backend)?,
            repository_format: require_collected_config(repository_format)?,
            repository_retention: require_collected_config(repository_retention)?,
            principal_fingerprint: require_collected_config(principal_fingerprint)?,
        })
    }
}

impl RepositoryToolConfig {
    /// Loads repository maintenance tool configuration from the current process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_source(&ProcessEnv)
    }

    fn from_source(source: &impl ConfigSource) -> Result<Self, ConfigError> {
        let mut errors = Vec::new();
        let backend = collect_config_error(&mut errors, parse_backend_config(source));
        let repository_format = collect_config_error(&mut errors, parse_repository_format(source));
        let repository_retention =
            collect_config_error(&mut errors, parse_retention_policy(source));
        let recovery = collect_config_error(&mut errors, parse_recovery_config(source));
        let repository_keys =
            collect_config_error(&mut errors, parse_repository_key_context_config(source));

        if !errors.is_empty() {
            return Err(config_error_list(errors));
        }

        Ok(Self {
            backend: require_collected_config(backend)?,
            repository_format: require_collected_config(repository_format)?,
            repository_retention: require_collected_config(repository_retention)?,
            recovery: require_collected_config(recovery)?,
            repository_keys: require_collected_config(repository_keys)?,
        })
    }
}

fn collect_config_error<T>(
    errors: &mut Vec<ConfigError>,
    result: Result<T, ConfigError>,
) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(ConfigError::Multiple { errors: collected }) => {
            errors.extend(collected);
            None
        }
        Err(error) => {
            errors.push(error);
            None
        }
    }
}

fn require_collected_config<T>(value: Option<T>) -> Result<T, ConfigError> {
    value.ok_or_else(|| ConfigError::Invalid {
        key: "RS3_CONFIG",
        value: REDACTED_SECRET_VALUE.to_owned(),
        reason: "internal parser failed to collect a configuration error".to_owned(),
    })
}

fn parse_backend_config(source: &impl ConfigSource) -> Result<BackendConfig, ConfigError> {
    let mut errors = Vec::new();
    let endpoint =
        collect_config_error(&mut errors, required_value(source, "RS3_BACKEND_ENDPOINT"));
    let bucket = collect_config_error(&mut errors, required_value(source, "RS3_BACKEND_BUCKET"));
    let timeouts = collect_config_error(&mut errors, parse_backend_timeout_config(source));

    if !errors.is_empty() {
        return Err(config_error_list(errors));
    }

    Ok(BackendConfig {
        endpoint: require_collected_config(endpoint)?,
        bucket: require_collected_config(bucket)?,
        prefix: optional_value(source, BACKEND_PREFIX_ENV),
        timeouts: require_collected_config(timeouts)?,
    })
}

fn parse_backend_timeout_config(
    source: &impl ConfigSource,
) -> Result<BackendTimeoutConfig, ConfigError> {
    let mut errors = Vec::new();
    let connect = collect_config_error(
        &mut errors,
        parse_positive_u64(
            "RS3_BACKEND_CONNECT_TIMEOUT_SECS",
            source.value("RS3_BACKEND_CONNECT_TIMEOUT_SECS"),
            DEFAULT_BACKEND_CONNECT_TIMEOUT_SECONDS,
        ),
    );
    let read = collect_config_error(
        &mut errors,
        parse_positive_u64(
            "RS3_BACKEND_READ_TIMEOUT_SECS",
            source.value("RS3_BACKEND_READ_TIMEOUT_SECS"),
            DEFAULT_BACKEND_READ_TIMEOUT_SECONDS,
        ),
    );
    let operation_attempt = collect_config_error(
        &mut errors,
        parse_positive_u64(
            "RS3_BACKEND_OPERATION_ATTEMPT_TIMEOUT_SECS",
            source.value("RS3_BACKEND_OPERATION_ATTEMPT_TIMEOUT_SECS"),
            DEFAULT_BACKEND_OPERATION_ATTEMPT_TIMEOUT_SECONDS,
        ),
    );
    let operation = collect_config_error(
        &mut errors,
        parse_positive_u64(
            "RS3_BACKEND_OPERATION_TIMEOUT_SECS",
            source.value("RS3_BACKEND_OPERATION_TIMEOUT_SECS"),
            DEFAULT_BACKEND_OPERATION_TIMEOUT_SECONDS,
        ),
    );
    let stalled_stream_grace = collect_config_error(
        &mut errors,
        parse_positive_u64(
            "RS3_BACKEND_STALLED_STREAM_GRACE_SECS",
            source.value("RS3_BACKEND_STALLED_STREAM_GRACE_SECS"),
            DEFAULT_BACKEND_STALLED_STREAM_GRACE_SECONDS,
        ),
    );

    if let (Some(connect), Some(operation_attempt)) = (connect, operation_attempt)
        && connect > operation_attempt
    {
        errors.push(ConfigError::Invalid {
            key: "RS3_BACKEND_CONNECT_TIMEOUT_SECS",
            value: connect.to_string(),
            reason: "must be less than or equal to RS3_BACKEND_OPERATION_ATTEMPT_TIMEOUT_SECS"
                .to_owned(),
        });
    }
    if let (Some(read), Some(operation_attempt)) = (read, operation_attempt)
        && read > operation_attempt
    {
        errors.push(ConfigError::Invalid {
            key: "RS3_BACKEND_READ_TIMEOUT_SECS",
            value: read.to_string(),
            reason: "must be less than or equal to RS3_BACKEND_OPERATION_ATTEMPT_TIMEOUT_SECS"
                .to_owned(),
        });
    }
    if let (Some(operation_attempt), Some(operation)) = (operation_attempt, operation)
        && operation_attempt > operation
    {
        errors.push(ConfigError::Invalid {
            key: "RS3_BACKEND_OPERATION_ATTEMPT_TIMEOUT_SECS",
            value: operation_attempt.to_string(),
            reason: "must be less than or equal to RS3_BACKEND_OPERATION_TIMEOUT_SECS".to_owned(),
        });
    }

    if !errors.is_empty() {
        return Err(config_error_list(errors));
    }

    Ok(BackendTimeoutConfig {
        connect: Duration::from_secs(require_collected_config(connect)?),
        read: Duration::from_secs(require_collected_config(read)?),
        operation_attempt: Duration::from_secs(require_collected_config(operation_attempt)?),
        operation: Duration::from_secs(require_collected_config(operation)?),
        stalled_stream_grace: Duration::from_secs(require_collected_config(stalled_stream_grace)?),
    })
}

fn parse_gateway_mode(source: &impl ConfigSource) -> Result<GatewayMode, ConfigError> {
    let value =
        optional_value(source, "RS3_GATEWAY_MODE").unwrap_or_else(|| "read-write".to_owned());
    match value.as_str() {
        "read-write" => Ok(GatewayMode::ReadWrite),
        "restore-readonly" => Ok(GatewayMode::RestoreReadOnly),
        _ => Err(ConfigError::Invalid {
            key: "RS3_GATEWAY_MODE",
            value,
            reason: "expected read-write or restore-readonly".to_owned(),
        }),
    }
}

fn parse_metrics_config(source: &impl ConfigSource) -> Result<MetricsConfig, ConfigError> {
    let bind = match optional_value(source, "RS3_METRICS_BIND") {
        Some(value) => Some(parse_socket_addr("RS3_METRICS_BIND", value)?),
        None => None,
    };
    Ok(MetricsConfig { bind })
}

fn parse_hardening_config(source: &impl ConfigSource) -> Result<HardeningConfig, ConfigError> {
    let mut errors = Vec::new();
    let max_put_object_bytes = collect_config_error(
        &mut errors,
        parse_positive_u64(
            "RS3_MAX_PUT_OBJECT_BYTES",
            source.value("RS3_MAX_PUT_OBJECT_BYTES"),
            DEFAULT_MAX_PUT_OBJECT_BYTES,
        ),
    );
    let buffered_put_object_bytes = collect_config_error(
        &mut errors,
        parse_positive_u64(
            "RS3_BUFFERED_PUT_OBJECT_BYTES",
            source.value("RS3_BUFFERED_PUT_OBJECT_BYTES"),
            DEFAULT_BUFFERED_PUT_OBJECT_BYTES,
        ),
    );
    let backend_multipart_part_bytes = collect_config_error(
        &mut errors,
        parse_positive_u64(
            "RS3_BACKEND_MULTIPART_PART_BYTES",
            source.value("RS3_BACKEND_MULTIPART_PART_BYTES"),
            DEFAULT_BACKEND_MULTIPART_PART_BYTES,
        ),
    );
    if let Some(backend_multipart_part_bytes) = backend_multipart_part_bytes
        && backend_multipart_part_bytes < MIN_BACKEND_MULTIPART_PART_BYTES
    {
        errors.push(ConfigError::Invalid {
            key: "RS3_BACKEND_MULTIPART_PART_BYTES",
            value: backend_multipart_part_bytes.to_string(),
            reason: "must be at least 5 MiB (5242880 bytes)".to_owned(),
        });
    }
    if let Some(backend_multipart_part_bytes) = backend_multipart_part_bytes
        && backend_multipart_part_bytes > MAX_BACKEND_MULTIPART_PART_BYTES
    {
        errors.push(ConfigError::Invalid {
            key: "RS3_BACKEND_MULTIPART_PART_BYTES",
            value: backend_multipart_part_bytes.to_string(),
            reason: "must be at most 5 GiB (5368709120 bytes)".to_owned(),
        });
    }
    if let (Some(max_put_object_bytes), Some(backend_multipart_part_bytes)) =
        (max_put_object_bytes, backend_multipart_part_bytes)
    {
        let max_multipart_object_bytes = backend_multipart_part_bytes.saturating_mul(10_000);
        if max_put_object_bytes > max_multipart_object_bytes {
            errors.push(ConfigError::Invalid {
                key: "RS3_MAX_PUT_OBJECT_BYTES",
                value: max_put_object_bytes.to_string(),
                reason: "must be less than or equal to 10000 * RS3_BACKEND_MULTIPART_PART_BYTES"
                    .to_owned(),
            });
        }
    }
    let stream_read_stall_timeout = collect_config_error(
        &mut errors,
        parse_positive_u64(
            "RS3_STREAM_READ_STALL_TIMEOUT_SECS",
            source.value("RS3_STREAM_READ_STALL_TIMEOUT_SECS"),
            DEFAULT_V2_STREAM_READ_STALL_TIMEOUT.as_secs(),
        ),
    )
    .map(Duration::from_secs);
    let max_in_flight_upload_body_bytes = collect_config_error(
        &mut errors,
        parse_positive_u64(
            "RS3_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES",
            source.value("RS3_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES"),
            DEFAULT_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES,
        ),
    );
    let max_in_flight_download_body_bytes = collect_config_error(
        &mut errors,
        parse_positive_u64(
            "RS3_MAX_IN_FLIGHT_DOWNLOAD_BODY_BYTES",
            source.value("RS3_MAX_IN_FLIGHT_DOWNLOAD_BODY_BYTES"),
            DEFAULT_MAX_IN_FLIGHT_DOWNLOAD_BODY_BYTES,
        ),
    );
    let request_rate_limit_per_second = collect_config_error(
        &mut errors,
        parse_positive_u64(
            "RS3_REQUEST_RATE_LIMIT_PER_SECOND",
            source.value("RS3_REQUEST_RATE_LIMIT_PER_SECOND"),
            DEFAULT_REQUEST_RATE_LIMIT_PER_SECOND,
        ),
    );
    let max_concurrent_connections = collect_config_error(
        &mut errors,
        parse_positive_usize(
            "RS3_MAX_CONCURRENT_CONNECTIONS",
            source.value("RS3_MAX_CONCURRENT_CONNECTIONS"),
            DEFAULT_MAX_CONCURRENT_CONNECTIONS,
        ),
    );
    let max_concurrent_requests = collect_config_error(
        &mut errors,
        parse_positive_usize(
            "RS3_MAX_CONCURRENT_REQUESTS",
            source.value("RS3_MAX_CONCURRENT_REQUESTS"),
            DEFAULT_MAX_CONCURRENT_REQUESTS,
        ),
    );

    for (key, value) in [
        ("RS3_MAX_CONCURRENT_CONNECTIONS", max_concurrent_connections),
        ("RS3_MAX_CONCURRENT_REQUESTS", max_concurrent_requests),
    ] {
        if let Some(value) = value
            && value > Semaphore::MAX_PERMITS
        {
            errors.push(ConfigError::Invalid {
                key,
                value: value.to_string(),
                reason: format!("must be less than or equal to {}", Semaphore::MAX_PERMITS),
            });
        }
    }

    if let (Some(buffered), Some(max_put)) = (buffered_put_object_bytes, max_put_object_bytes)
        && buffered > max_put
    {
        errors.push(ConfigError::Invalid {
            key: "RS3_BUFFERED_PUT_OBJECT_BYTES",
            value: buffered.to_string(),
            reason: "must be less than or equal to RS3_MAX_PUT_OBJECT_BYTES".to_owned(),
        });
    }
    if !errors.is_empty() {
        return Err(config_error_list(errors));
    }

    Ok(HardeningConfig {
        max_put_object_bytes: require_collected_config(max_put_object_bytes)?,
        buffered_put_object_bytes: require_collected_config(buffered_put_object_bytes)?,
        backend_multipart_part_bytes: require_collected_config(backend_multipart_part_bytes)?,
        stream_read_stall_timeout: require_collected_config(stream_read_stall_timeout)?,
        max_in_flight_upload_body_bytes: require_collected_config(max_in_flight_upload_body_bytes)?,
        max_in_flight_download_body_bytes: require_collected_config(
            max_in_flight_download_body_bytes,
        )?,
        max_concurrent_connections: require_collected_config(max_concurrent_connections)?,
        max_concurrent_requests: require_collected_config(max_concurrent_requests)?,
        request_rate_limit_per_second: require_collected_config(request_rate_limit_per_second)?,
    })
}

fn push_runtime_invalid(
    errors: &mut Vec<ConfigError>,
    key: &'static str,
    value: impl ToString,
    reason: impl Into<String>,
) {
    errors.push(ConfigError::Invalid {
        key,
        value: value.to_string(),
        reason: reason.into(),
    });
}

fn validate_runtime_backend(errors: &mut Vec<ConfigError>, backend: &BackendConfig) {
    if backend.endpoint.trim().is_empty() {
        push_runtime_invalid(
            errors,
            "RS3_BACKEND_ENDPOINT",
            REDACTED_SECRET_VALUE,
            "must not be blank",
        );
    }
    if backend.bucket.trim().is_empty() {
        push_runtime_invalid(
            errors,
            "RS3_BACKEND_BUCKET",
            REDACTED_SECRET_VALUE,
            "must not be blank",
        );
    }
    if backend
        .prefix
        .as_deref()
        .is_some_and(|prefix| prefix.trim().is_empty())
    {
        push_runtime_invalid(
            errors,
            BACKEND_PREFIX_ENV,
            REDACTED_SECRET_VALUE,
            "must be omitted or nonblank",
        );
    }

    let timeouts = backend.timeouts;
    for (key, value) in [
        ("RS3_BACKEND_CONNECT_TIMEOUT_SECS", timeouts.connect),
        ("RS3_BACKEND_READ_TIMEOUT_SECS", timeouts.read),
        (
            "RS3_BACKEND_OPERATION_ATTEMPT_TIMEOUT_SECS",
            timeouts.operation_attempt,
        ),
        ("RS3_BACKEND_OPERATION_TIMEOUT_SECS", timeouts.operation),
        (
            "RS3_BACKEND_STALLED_STREAM_GRACE_SECS",
            timeouts.stalled_stream_grace,
        ),
    ] {
        if value.is_zero() {
            push_runtime_invalid(
                errors,
                key,
                format!("{value:?}"),
                "must be greater than zero",
            );
        }
    }
    if timeouts.connect > timeouts.operation_attempt {
        push_runtime_invalid(
            errors,
            "RS3_BACKEND_CONNECT_TIMEOUT_SECS",
            format!("{:?}", timeouts.connect),
            "must be less than or equal to RS3_BACKEND_OPERATION_ATTEMPT_TIMEOUT_SECS",
        );
    }
    if timeouts.read > timeouts.operation_attempt {
        push_runtime_invalid(
            errors,
            "RS3_BACKEND_READ_TIMEOUT_SECS",
            format!("{:?}", timeouts.read),
            "must be less than or equal to RS3_BACKEND_OPERATION_ATTEMPT_TIMEOUT_SECS",
        );
    }
    if timeouts.operation_attempt > timeouts.operation {
        push_runtime_invalid(
            errors,
            "RS3_BACKEND_OPERATION_ATTEMPT_TIMEOUT_SECS",
            format!("{:?}", timeouts.operation_attempt),
            "must be less than or equal to RS3_BACKEND_OPERATION_TIMEOUT_SECS",
        );
    }
}

fn validate_runtime_anchor(errors: &mut Vec<ConfigError>, anchor: &AnchorConfig) {
    let AnchorConfig::KubernetesLease {
        namespace,
        name,
        field_manager,
    } = anchor
    else {
        return;
    };

    for (key, value) in [
        (ANCHOR_NAMESPACE_ENV, namespace),
        (ANCHOR_NAME_ENV, name),
        (ANCHOR_FIELD_MANAGER_ENV, field_manager),
    ] {
        if value.trim().is_empty() {
            push_runtime_invalid(errors, key, REDACTED_SECRET_VALUE, "must not be blank");
        }
    }
}

fn validate_runtime_hardening(errors: &mut Vec<ConfigError>, hardening: &HardeningConfig) {
    for (key, value) in [
        ("RS3_MAX_PUT_OBJECT_BYTES", hardening.max_put_object_bytes),
        (
            "RS3_BUFFERED_PUT_OBJECT_BYTES",
            hardening.buffered_put_object_bytes,
        ),
        (
            "RS3_BACKEND_MULTIPART_PART_BYTES",
            hardening.backend_multipart_part_bytes,
        ),
        (
            "RS3_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES",
            hardening.max_in_flight_upload_body_bytes,
        ),
        (
            "RS3_MAX_IN_FLIGHT_DOWNLOAD_BODY_BYTES",
            hardening.max_in_flight_download_body_bytes,
        ),
        (
            "RS3_REQUEST_RATE_LIMIT_PER_SECOND",
            hardening.request_rate_limit_per_second,
        ),
    ] {
        if value == 0 {
            push_runtime_invalid(errors, key, value, "must be greater than zero");
        }
    }
    if hardening.stream_read_stall_timeout.is_zero() {
        push_runtime_invalid(
            errors,
            "RS3_STREAM_READ_STALL_TIMEOUT_SECS",
            format!("{:?}", hardening.stream_read_stall_timeout),
            "must be greater than zero",
        );
    }
    if hardening.backend_multipart_part_bytes < MIN_BACKEND_MULTIPART_PART_BYTES {
        push_runtime_invalid(
            errors,
            "RS3_BACKEND_MULTIPART_PART_BYTES",
            hardening.backend_multipart_part_bytes,
            "must be at least 5 MiB (5242880 bytes)",
        );
    }
    if hardening.backend_multipart_part_bytes > MAX_BACKEND_MULTIPART_PART_BYTES {
        push_runtime_invalid(
            errors,
            "RS3_BACKEND_MULTIPART_PART_BYTES",
            hardening.backend_multipart_part_bytes,
            "must be at most 5 GiB (5368709120 bytes)",
        );
    }
    if hardening.max_put_object_bytes
        > hardening
            .backend_multipart_part_bytes
            .saturating_mul(10_000)
    {
        push_runtime_invalid(
            errors,
            "RS3_MAX_PUT_OBJECT_BYTES",
            hardening.max_put_object_bytes,
            "must be less than or equal to 10000 * RS3_BACKEND_MULTIPART_PART_BYTES",
        );
    }
    if hardening.buffered_put_object_bytes > hardening.max_put_object_bytes {
        push_runtime_invalid(
            errors,
            "RS3_BUFFERED_PUT_OBJECT_BYTES",
            hardening.buffered_put_object_bytes,
            "must be less than or equal to RS3_MAX_PUT_OBJECT_BYTES",
        );
    }
    for (key, value) in [
        (
            "RS3_MAX_CONCURRENT_CONNECTIONS",
            hardening.max_concurrent_connections,
        ),
        (
            "RS3_MAX_CONCURRENT_REQUESTS",
            hardening.max_concurrent_requests,
        ),
    ] {
        if value == 0 {
            push_runtime_invalid(errors, key, value, "must be greater than zero");
        } else if value > Semaphore::MAX_PERMITS {
            push_runtime_invalid(
                errors,
                key,
                value,
                format!("must be less than or equal to {}", Semaphore::MAX_PERMITS),
            );
        }
    }
}

fn validate_runtime_batching(errors: &mut Vec<ConfigError>, batching: &BatchConfig) {
    for (key, value) in [
        ("RS3_COMMIT_MAX_BATCH_ITEMS", batching.max_items),
        ("RS3_COMMIT_MAX_PENDING_ITEMS", batching.max_pending_items),
    ] {
        if value == 0 {
            push_runtime_invalid(errors, key, value, "must be greater than zero");
        }
    }
}

fn validate_runtime_repository(errors: &mut Vec<ConfigError>, repository: &RepositoryConfig) {
    if repository.payload_segment_size == 0
        || repository.payload_segment_size > rs3_repository::MAX_PAYLOAD_SEGMENT_SIZE
    {
        push_runtime_invalid(
            errors,
            "RS3_PAYLOAD_SEGMENT_SIZE_BYTES",
            repository.payload_segment_size,
            format!(
                "must be between 1 and {} bytes",
                rs3_repository::MAX_PAYLOAD_SEGMENT_SIZE
            ),
        );
    }
    if let Some(retention) = repository.retention {
        if retention.mode == RetentionMode::None {
            push_runtime_invalid(
                errors,
                REPOSITORY_RETENTION_MODE_ENV,
                "none",
                "expected governance or compliance when retention is configured",
            );
        }
        if retention.retain_days == 0 {
            push_runtime_invalid(
                errors,
                REPOSITORY_RETENTION_DAYS_ENV,
                retention.retain_days,
                "must be greater than zero when retention is configured",
            );
        }
    }
}

fn validate_runtime_maintenance(
    errors: &mut Vec<ConfigError>,
    mode: GatewayMode,
    maintenance: &MaintenanceConfig,
) {
    if mode == GatewayMode::RestoreReadOnly && maintenance.mode != MaintenanceMode::Off {
        push_runtime_invalid(
            errors,
            MAINTENANCE_MODE_ENV,
            maintenance.mode.as_str(),
            "restore-readonly gateways require maintenance to be off",
        );
    }
    for (key, value) in [
        (
            MAINTENANCE_RENEWAL_HORIZON_SECONDS_ENV,
            maintenance.renewal_horizon,
        ),
        (
            MAINTENANCE_ORPHAN_PRESSURE_MAX_AGE_SECONDS_ENV,
            maintenance.orphan_pressure_max_age,
        ),
        (
            MAINTENANCE_MAX_INTERVAL_SECONDS_ENV,
            maintenance.max_interval,
        ),
        (
            MAINTENANCE_MIN_COOLDOWN_SECONDS_ENV,
            maintenance.min_cooldown,
        ),
    ] {
        if value.is_zero() {
            push_runtime_invalid(
                errors,
                key,
                format!("{value:?}"),
                "must be greater than zero",
            );
        }
    }
    for (key, value) in [
        (
            MAINTENANCE_ORPHAN_PRESSURE_BYTES_ENV,
            maintenance.orphan_pressure_bytes,
        ),
        (
            MAINTENANCE_ORPHAN_PRESSURE_COUNT_ENV,
            maintenance.orphan_pressure_count,
        ),
        (
            MAINTENANCE_MAX_INVENTORY_PAGES_ENV,
            maintenance.max_inventory_pages,
        ),
        (
            MAINTENANCE_MAX_INVENTORY_ITEMS_ENV,
            maintenance.max_inventory_items,
        ),
    ] {
        if value == 0 {
            push_runtime_invalid(errors, key, value, "must be greater than zero");
        }
    }
    if maintenance.min_cooldown > maintenance.max_interval {
        push_runtime_invalid(
            errors,
            MAINTENANCE_MIN_COOLDOWN_SECONDS_ENV,
            format!("{:?}", maintenance.min_cooldown),
            format!("must be less than or equal to {MAINTENANCE_MAX_INTERVAL_SECONDS_ENV}"),
        );
    }
    if maintenance
        .pacing_delay
        .is_some_and(|delay| delay.is_zero())
    {
        push_runtime_invalid(
            errors,
            MAINTENANCE_PACING_DELAY_MS_ENV,
            "0ns",
            "must be greater than zero when configured",
        );
    }
}

fn validate_runtime_provider_conformance(
    errors: &mut Vec<ConfigError>,
    provider: &ProviderConformanceConfig,
) {
    if provider
        .report_file
        .as_ref()
        .is_some_and(|path| path.as_os_str().is_empty())
    {
        push_runtime_invalid(
            errors,
            PROVIDER_CONFORMANCE_REPORT_FILE_ENV,
            REDACTED_SECRET_VALUE,
            "must be omitted or nonblank",
        );
    }
    if provider.max_age.is_zero() {
        push_runtime_invalid(
            errors,
            PROVIDER_CONFORMANCE_MAX_AGE_SECONDS_ENV,
            format!("{:?}", provider.max_age),
            "must be greater than zero",
        );
    }
    if let Some(fingerprint) = provider.principal_fingerprint.as_deref()
        && (fingerprint.len() != 64
            || !fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    {
        push_runtime_invalid(
            errors,
            PROVIDER_PRINCIPAL_FINGERPRINT_ENV,
            REDACTED_SECRET_VALUE,
            "expected a lowercase 64-character SHA-256 fingerprint",
        );
    }
}

fn validate_runtime_static_credentials(
    errors: &mut Vec<ConfigError>,
    credentials: Option<&StaticCredentials>,
) {
    let Some(credentials) = credentials else {
        return;
    };
    if credentials.access_key_id.trim().is_empty() {
        push_runtime_invalid(
            errors,
            STATIC_ACCESS_KEY_ID_ENV,
            REDACTED_SECRET_VALUE,
            "must not be blank",
        );
    }
    if credentials
        .secret_access_key
        .expose_secret()
        .trim()
        .is_empty()
    {
        push_runtime_invalid(
            errors,
            STATIC_SECRET_ACCESS_KEY_ENV,
            REDACTED_SECRET_VALUE,
            "must not be blank",
        );
    }
}

fn validate_runtime_writer_guard(
    errors: &mut Vec<ConfigError>,
    anchor: &AnchorConfig,
    writer_guard: WriterGuardConfig,
) {
    if writer_guard == WriterGuardConfig::Required
        && !matches!(anchor, AnchorConfig::KubernetesLease { .. })
    {
        push_runtime_invalid(
            errors,
            WRITER_GUARD_ENV,
            writer_guard.as_str(),
            "required needs RS3_ANCHOR_MODE=kubernetes-lease",
        );
    }
}

fn validate_runtime_repository_keys(errors: &mut Vec<ConfigError>, keys: &RepositoryKeysConfig) {
    if let Err(error) =
        validate_repository_salt_hex(REPOSITORY_SALT_HEX_ENV, &keys.repository_salt_hex)
    {
        errors.push(error);
    }
    if let Err(error) = validate_repository_key_hex(
        KEYRING_WRAPPING_KEY_HEX_ENV,
        keys.wrapping_key_hex.expose_secret(),
    ) {
        errors.push(error);
    }
    if keys.wrapping_key_id.trim().is_empty() {
        push_runtime_invalid(
            errors,
            KEYRING_WRAPPING_KEY_ID_ENV,
            REDACTED_SECRET_VALUE,
            "must not be blank",
        );
    }
}

fn validate_runtime_recovery(errors: &mut Vec<ConfigError>, recovery: &RecoveryConfig) {
    if let Some(public_key) = recovery.public_key.as_deref()
        && let Err(error) = validate_recovery_public_key(public_key)
    {
        push_runtime_invalid(
            errors,
            RECOVERY_PUBLIC_KEY_ENV,
            public_key,
            error.to_string(),
        );
    }
}

fn validate_upload_memory_budget(
    errors: &mut Vec<ConfigError>,
    hardening: &HardeningConfig,
    repository: &RepositoryConfig,
) {
    let required = required_upload_memory_budget(hardening, repository);
    if hardening.max_in_flight_upload_body_bytes < required {
        errors.push(ConfigError::Invalid {
            key: "RS3_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES",
            value: hardening.max_in_flight_upload_body_bytes.to_string(),
            reason: format!(
                "must be at least {required} bytes for the configured buffered, multipart, and payload-segment PutObject paths"
            ),
        });
    }
}

fn required_upload_memory_budget(
    hardening: &HardeningConfig,
    repository: &RepositoryConfig,
) -> u64 {
    if hardening.max_put_object_bytes <= hardening.buffered_put_object_bytes {
        return hardening.buffered_put_object_bytes;
    }
    hardening.buffered_put_object_bytes.saturating_add(
        configured_streaming_upload_working_set_bytes(hardening, repository),
    )
}

pub(crate) fn configured_streaming_upload_working_set_bytes(
    hardening: &HardeningConfig,
    repository: &RepositoryConfig,
) -> u64 {
    let max_plaintext_len = usize::try_from(hardening.max_put_object_bytes).unwrap_or(usize::MAX);
    let payload_segment_bytes = rs3_repository::effective_payload_segment_size(
        max_plaintext_len,
        repository.payload_segment_size,
        repository.adaptive_payload_segment_size,
    );
    rs3_repository::v2::v2_streaming_upload_working_set_bytes(
        hardening.backend_multipart_part_bytes,
        u64::try_from(payload_segment_bytes).unwrap_or(u64::MAX),
    )
}

fn parse_anchor_config(source: &impl ConfigSource) -> Result<AnchorConfig, ConfigError> {
    let mode = required_value(source, "RS3_ANCHOR_MODE")?;

    match mode.as_str() {
        "memory" => {
            if parse_bool(
                ALLOW_MEMORY_ANCHOR_ENV,
                source.value(ALLOW_MEMORY_ANCHOR_ENV),
                false,
            )? {
                Ok(AnchorConfig::Memory)
            } else {
                Err(ConfigError::Invalid {
                    key: "RS3_ANCHOR_MODE",
                    value: mode,
                    reason: format!("memory anchor requires {ALLOW_MEMORY_ANCHOR_ENV}=true"),
                })
            }
        }
        "kubernetes-lease" => {
            let mut errors = Vec::new();
            let namespace =
                collect_config_error(&mut errors, required_value(source, ANCHOR_NAMESPACE_ENV));
            let name = collect_config_error(&mut errors, required_value(source, ANCHOR_NAME_ENV));
            if !errors.is_empty() {
                return Err(config_error_list(errors));
            }
            Ok(AnchorConfig::KubernetesLease {
                namespace: require_collected_config(namespace)?,
                name: require_collected_config(name)?,
                field_manager: optional_value(source, ANCHOR_FIELD_MANAGER_ENV)
                    .unwrap_or_else(|| DEFAULT_ANCHOR_FIELD_MANAGER.to_owned()),
            })
        }
        _ => Err(ConfigError::Invalid {
            key: "RS3_ANCHOR_MODE",
            value: mode,
            reason: "expected memory or kubernetes-lease".to_owned(),
        }),
    }
}

fn parse_writer_guard_config(
    source: &impl ConfigSource,
    anchor: &AnchorConfig,
) -> Result<WriterGuardConfig, ConfigError> {
    let value = parse_writer_guard_value(source)?;
    let writer_guard = value.unwrap_or({
        if matches!(anchor, AnchorConfig::KubernetesLease { .. }) {
            WriterGuardConfig::Required
        } else {
            WriterGuardConfig::Off
        }
    });

    if writer_guard == WriterGuardConfig::Required
        && !matches!(anchor, AnchorConfig::KubernetesLease { .. })
    {
        return Err(ConfigError::Invalid {
            key: WRITER_GUARD_ENV,
            value: writer_guard.as_str().to_owned(),
            reason: "required needs RS3_ANCHOR_MODE=kubernetes-lease".to_owned(),
        });
    }

    Ok(writer_guard)
}

fn parse_writer_guard_value(
    source: &impl ConfigSource,
) -> Result<Option<WriterGuardConfig>, ConfigError> {
    let value = optional_value(source, WRITER_GUARD_ENV);
    match value.as_deref() {
        Some("required") => Ok(Some(WriterGuardConfig::Required)),
        Some("off") => Ok(Some(WriterGuardConfig::Off)),
        Some(_) => Err(ConfigError::Invalid {
            key: WRITER_GUARD_ENV,
            value: value.unwrap_or_default(),
            reason: "expected required or off".to_owned(),
        }),
        None => Ok(None),
    }
}

fn parse_batch_config(source: &impl ConfigSource) -> Result<BatchConfig, ConfigError> {
    let mut errors = Vec::new();
    let max_items = collect_config_error(
        &mut errors,
        parse_positive_usize(
            "RS3_COMMIT_MAX_BATCH_ITEMS",
            source.value("RS3_COMMIT_MAX_BATCH_ITEMS"),
            DEFAULT_BATCH_ITEMS,
        ),
    );
    let max_pending_items_default = max_items.unwrap_or(DEFAULT_BATCH_ITEMS);
    let max_pending_items = collect_config_error(
        &mut errors,
        parse_positive_usize(
            "RS3_COMMIT_MAX_PENDING_ITEMS",
            source.value("RS3_COMMIT_MAX_PENDING_ITEMS"),
            max_pending_items_default,
        ),
    );
    let max_delay_ms = collect_config_error(
        &mut errors,
        parse_u64(
            "RS3_COMMIT_MAX_BATCH_DELAY_MS",
            source.value("RS3_COMMIT_MAX_BATCH_DELAY_MS"),
            DEFAULT_BATCH_DELAY_MS,
        ),
    );

    if !errors.is_empty() {
        return Err(config_error_list(errors));
    }

    Ok(BatchConfig {
        max_items: require_collected_config(max_items)?,
        max_delay: Duration::from_millis(require_collected_config(max_delay_ms)?),
        max_pending_items: require_collected_config(max_pending_items)?,
    })
}

fn parse_repository_config(source: &impl ConfigSource) -> Result<RepositoryConfig, ConfigError> {
    let mut errors = Vec::new();
    let format = collect_config_error(&mut errors, parse_repository_format(source));
    let payload_segment_size_value = source.value("RS3_PAYLOAD_SEGMENT_SIZE_BYTES");
    let adaptive_payload_segment_size = payload_segment_size_value.is_none();
    let payload_segment_size = collect_config_error(
        &mut errors,
        (|| {
            let size = parse_positive_usize(
                "RS3_PAYLOAD_SEGMENT_SIZE_BYTES",
                payload_segment_size_value,
                DEFAULT_PAYLOAD_SEGMENT_SIZE,
            )?;
            if size > rs3_repository::MAX_PAYLOAD_SEGMENT_SIZE {
                return Err(ConfigError::Invalid {
                    key: "RS3_PAYLOAD_SEGMENT_SIZE_BYTES",
                    value: size.to_string(),
                    reason: format!(
                        "expected at most {} bytes",
                        rs3_repository::MAX_PAYLOAD_SEGMENT_SIZE
                    ),
                });
            }
            Ok(size)
        })(),
    );
    let decrypted_segment_cache_max_bytes = collect_config_error(
        &mut errors,
        parse_u64(
            "RS3_DECRYPTED_SEGMENT_CACHE_MAX_BYTES",
            source.value("RS3_DECRYPTED_SEGMENT_CACHE_MAX_BYTES"),
            rs3_repository::DEFAULT_DECRYPTED_SEGMENT_CACHE_MAX_BYTES,
        ),
    );
    let retention = collect_config_error(&mut errors, parse_retention_policy(source));
    let allow_init = collect_config_error(
        &mut errors,
        parse_bool(
            ALLOW_REPOSITORY_INIT_ENV,
            source.value(ALLOW_REPOSITORY_INIT_ENV),
            false,
        ),
    );

    if !errors.is_empty() {
        return Err(config_error_list(errors));
    }

    Ok(RepositoryConfig {
        format: require_collected_config(format)?,
        payload_segment_size: require_collected_config(payload_segment_size)?,
        adaptive_payload_segment_size,
        decrypted_segment_cache_max_bytes: require_collected_config(
            decrypted_segment_cache_max_bytes,
        )?,
        retention: require_collected_config(retention)?,
        allow_init: require_collected_config(allow_init)?,
    })
}

fn parse_maintenance_config(
    source: &impl ConfigSource,
    mode: GatewayMode,
) -> Result<MaintenanceConfig, ConfigError> {
    let maintenance_mode_value = optional_value(source, MAINTENANCE_MODE_ENV);
    if mode == GatewayMode::RestoreReadOnly {
        if let Some(value) = maintenance_mode_value {
            return Err(ConfigError::Invalid {
                key: MAINTENANCE_MODE_ENV,
                value,
                reason: "restore-readonly gateways force maintenance off; unset this variable"
                    .to_owned(),
            });
        }
        return Ok(MaintenanceConfig::forced_off());
    }

    let maintenance_mode = match maintenance_mode_value.as_deref() {
        None | Some("auto") => MaintenanceMode::Auto,
        Some("manual") => MaintenanceMode::Manual,
        Some("off") => MaintenanceMode::Off,
        Some(_) => {
            return Err(ConfigError::Invalid {
                key: MAINTENANCE_MODE_ENV,
                value: maintenance_mode_value.unwrap_or_default(),
                reason: "expected auto, manual, or off".to_owned(),
            });
        }
    };

    let mut errors = Vec::new();
    let defaults = MaintenanceConfig::default();
    let renewal_horizon = collect_config_error(
        &mut errors,
        parse_positive_u64(
            MAINTENANCE_RENEWAL_HORIZON_SECONDS_ENV,
            source.value(MAINTENANCE_RENEWAL_HORIZON_SECONDS_ENV),
            defaults.renewal_horizon.as_secs(),
        ),
    )
    .map(Duration::from_secs);
    let orphan_pressure_bytes = collect_config_error(
        &mut errors,
        parse_positive_u64(
            MAINTENANCE_ORPHAN_PRESSURE_BYTES_ENV,
            source.value(MAINTENANCE_ORPHAN_PRESSURE_BYTES_ENV),
            defaults.orphan_pressure_bytes,
        ),
    );
    let orphan_pressure_count = collect_config_error(
        &mut errors,
        parse_positive_u64(
            MAINTENANCE_ORPHAN_PRESSURE_COUNT_ENV,
            source.value(MAINTENANCE_ORPHAN_PRESSURE_COUNT_ENV),
            defaults.orphan_pressure_count,
        ),
    );
    let orphan_pressure_max_age = collect_config_error(
        &mut errors,
        parse_positive_u64(
            MAINTENANCE_ORPHAN_PRESSURE_MAX_AGE_SECONDS_ENV,
            source.value(MAINTENANCE_ORPHAN_PRESSURE_MAX_AGE_SECONDS_ENV),
            defaults.orphan_pressure_max_age.as_secs(),
        ),
    )
    .map(Duration::from_secs);
    let max_interval = collect_config_error(
        &mut errors,
        parse_positive_u64(
            MAINTENANCE_MAX_INTERVAL_SECONDS_ENV,
            source.value(MAINTENANCE_MAX_INTERVAL_SECONDS_ENV),
            defaults.max_interval.as_secs(),
        ),
    )
    .map(Duration::from_secs);
    let min_cooldown = collect_config_error(
        &mut errors,
        parse_positive_u64(
            MAINTENANCE_MIN_COOLDOWN_SECONDS_ENV,
            source.value(MAINTENANCE_MIN_COOLDOWN_SECONDS_ENV),
            defaults.min_cooldown.as_secs(),
        ),
    )
    .map(Duration::from_secs);
    let pacing_delay = match optional_value(source, MAINTENANCE_PACING_DELAY_MS_ENV) {
        Some(value) => collect_config_error(
            &mut errors,
            parse_positive_u64(MAINTENANCE_PACING_DELAY_MS_ENV, Some(value), 1),
        )
        .map(|millis| Some(Duration::from_millis(millis))),
        None => Some(None),
    };
    let max_inventory_pages = collect_config_error(
        &mut errors,
        parse_positive_u64(
            MAINTENANCE_MAX_INVENTORY_PAGES_ENV,
            source.value(MAINTENANCE_MAX_INVENTORY_PAGES_ENV),
            defaults.max_inventory_pages,
        ),
    );
    let max_inventory_items = collect_config_error(
        &mut errors,
        parse_positive_u64(
            MAINTENANCE_MAX_INVENTORY_ITEMS_ENV,
            source.value(MAINTENANCE_MAX_INVENTORY_ITEMS_ENV),
            defaults.max_inventory_items,
        ),
    );
    if let (Some(min_cooldown), Some(max_interval)) = (min_cooldown, max_interval)
        && min_cooldown > max_interval
    {
        errors.push(ConfigError::Invalid {
            key: MAINTENANCE_MIN_COOLDOWN_SECONDS_ENV,
            value: min_cooldown.as_secs().to_string(),
            reason: format!("must be less than or equal to {MAINTENANCE_MAX_INTERVAL_SECONDS_ENV}"),
        });
    }

    if !errors.is_empty() {
        return Err(config_error_list(errors));
    }

    Ok(MaintenanceConfig {
        mode: maintenance_mode,
        renewal_horizon: require_collected_config(renewal_horizon)?,
        orphan_pressure_bytes: require_collected_config(orphan_pressure_bytes)?,
        orphan_pressure_count: require_collected_config(orphan_pressure_count)?,
        orphan_pressure_max_age: require_collected_config(orphan_pressure_max_age)?,
        max_interval: require_collected_config(max_interval)?,
        min_cooldown: require_collected_config(min_cooldown)?,
        pacing_delay: require_collected_config(pacing_delay)?,
        max_inventory_pages: require_collected_config(max_inventory_pages)?,
        max_inventory_items: require_collected_config(max_inventory_items)?,
    })
}

fn parse_provider_conformance_config(
    source: &impl ConfigSource,
) -> Result<ProviderConformanceConfig, ConfigError> {
    let report_file =
        optional_value(source, PROVIDER_CONFORMANCE_REPORT_FILE_ENV).map(PathBuf::from);
    let max_age_seconds = parse_positive_u64(
        PROVIDER_CONFORMANCE_MAX_AGE_SECONDS_ENV,
        source.value(PROVIDER_CONFORMANCE_MAX_AGE_SECONDS_ENV),
        DEFAULT_PROVIDER_CONFORMANCE_MAX_AGE_SECONDS,
    )?;
    let principal_fingerprint = parse_provider_principal_fingerprint(source)?;
    Ok(ProviderConformanceConfig {
        report_file,
        max_age: Duration::from_secs(max_age_seconds),
        principal_fingerprint,
    })
}

fn parse_provider_principal_fingerprint(
    source: &impl ConfigSource,
) -> Result<Option<String>, ConfigError> {
    let Some(value) = optional_value(source, PROVIDER_PRINCIPAL_FINGERPRINT_ENV) else {
        return Ok(None);
    };
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ConfigError::Invalid {
            key: PROVIDER_PRINCIPAL_FINGERPRINT_ENV,
            value: REDACTED_SECRET_VALUE.to_owned(),
            reason: "expected a lowercase 64-character SHA-256 fingerprint".to_owned(),
        });
    }
    Ok(Some(value))
}

fn parse_recovery_config(source: &impl ConfigSource) -> Result<RecoveryConfig, ConfigError> {
    let public_key = optional_value(source, RECOVERY_PUBLIC_KEY_ENV)
        .map(|value| {
            validate_recovery_public_key(&value).map_err(|error| ConfigError::Invalid {
                key: RECOVERY_PUBLIC_KEY_ENV,
                value: value.clone(),
                reason: error.to_string(),
            })?;
            Ok(value)
        })
        .transpose()?;
    Ok(RecoveryConfig { public_key })
}

fn parse_repository_format(source: &impl ConfigSource) -> Result<RepositoryFormat, ConfigError> {
    match optional_value(source, REPOSITORY_FORMAT_ENV) {
        None => Ok(RepositoryFormat::V2Preview),
        Some(value) if value == RepositoryFormat::V2Preview.as_str() => {
            Ok(RepositoryFormat::V2Preview)
        }
        Some(value) => Err(ConfigError::Invalid {
            key: REPOSITORY_FORMAT_ENV,
            value,
            reason: "omit this compatibility variable or set v2-preview".to_owned(),
        }),
    }
}

fn parse_retention_policy(
    source: &impl ConfigSource,
) -> Result<Option<RetentionPolicy>, ConfigError> {
    let mode = optional_value(source, REPOSITORY_RETENTION_MODE_ENV);
    let days = optional_value(source, REPOSITORY_RETENTION_DAYS_ENV);
    let Some(mode) = mode else {
        if let Some(value) = days {
            return Err(ConfigError::Invalid {
                key: REPOSITORY_RETENTION_DAYS_ENV,
                value,
                reason: format!("{REPOSITORY_RETENTION_MODE_ENV} must also be set"),
            });
        }
        return Ok(None);
    };

    let retention_mode = match mode.as_str() {
        "governance" => RetentionMode::Governance,
        "compliance" => RetentionMode::Compliance,
        _ => {
            return Err(ConfigError::Invalid {
                key: REPOSITORY_RETENTION_MODE_ENV,
                value: mode,
                reason: "expected governance or compliance".to_owned(),
            });
        }
    };
    let retain_days = parse_positive_u32(
        REPOSITORY_RETENTION_DAYS_ENV,
        days,
        format!("{REPOSITORY_RETENTION_DAYS_ENV} is required when repository retention is enabled"),
    )?;
    Ok(Some(RetentionPolicy::new(retention_mode, retain_days)))
}

fn parse_repository_keys_config(
    source: &impl ConfigSource,
) -> Result<RepositoryKeysConfig, ConfigError> {
    let mut errors = Vec::new();
    let context = collect_config_error(&mut errors, parse_repository_key_context_config(source));
    let wrapping_key_hex = collect_config_error(
        &mut errors,
        required_secret_hex(source, KEYRING_WRAPPING_KEY_HEX_ENV),
    );

    if !errors.is_empty() {
        return Err(config_error_list(errors));
    }

    let context = require_collected_config(context)?;
    Ok(RepositoryKeysConfig {
        repository_id: context.repository_id,
        repository_salt_hex: context.repository_salt_hex,
        envelope_object_id: context.envelope_object_id,
        wrapping_key_id: context.wrapping_key_id,
        wrapping_key_hex: require_collected_config(wrapping_key_hex)?,
    })
}

fn parse_repository_key_context_config(
    source: &impl ConfigSource,
) -> Result<RepositoryKeyContextConfig, ConfigError> {
    let mut errors = Vec::new();
    let repository_id_value =
        collect_config_error(&mut errors, required_value(source, REPOSITORY_ID_ENV));
    let repository_id = repository_id_value
        .map(|value| collect_config_error(&mut errors, parse_repository_id(value)))
        .unwrap_or(None);
    let repository_salt_hex = collect_config_error(
        &mut errors,
        required_repository_salt_hex(source, REPOSITORY_SALT_HEX_ENV),
    );
    let envelope_object_id = match optional_value(source, KEYRING_ENVELOPE_OBJECT_ID_ENV) {
        Some(value) => collect_config_error(
            &mut errors,
            parse_backend_object_id(KEYRING_ENVELOPE_OBJECT_ID_ENV, value),
        )
        .map(Some),
        None => Some(None),
    };

    if !errors.is_empty() {
        return Err(config_error_list(errors));
    }

    Ok(RepositoryKeyContextConfig {
        repository_id: require_collected_config(repository_id)?,
        repository_salt_hex: require_collected_config(repository_salt_hex)?,
        envelope_object_id: require_collected_config(envelope_object_id)?,
        wrapping_key_id: optional_value(source, KEYRING_WRAPPING_KEY_ID_ENV)
            .unwrap_or_else(|| DEFAULT_KEYRING_WRAPPING_KEY_ID.to_owned()),
    })
}

fn parse_repository_id(value: String) -> Result<RepositoryId, ConfigError> {
    RepositoryId::new(value.clone()).map_err(|error| ConfigError::Invalid {
        key: REPOSITORY_ID_ENV,
        value,
        reason: error.to_string(),
    })
}

fn parse_backend_object_id(
    key: &'static str,
    value: String,
) -> Result<BackendObjectId, ConfigError> {
    BackendObjectId::new(value.clone()).map_err(|error| ConfigError::Invalid {
        key,
        value,
        reason: error.to_string(),
    })
}

fn required_repository_salt_hex(
    source: &impl ConfigSource,
    key: &'static str,
) -> Result<String, ConfigError> {
    let value = required_value(source, key)?;
    validate_repository_salt_hex(key, &value)?;
    Ok(value)
}

fn required_secret_hex(
    source: &impl ConfigSource,
    key: &'static str,
) -> Result<SecretString, ConfigError> {
    let value = required_value(source, key)?;
    validate_repository_key_hex(key, &value)?;
    Ok(SecretString::from(value))
}

fn validate_repository_key_hex(key: &'static str, value: &str) -> Result<(), ConfigError> {
    if value.len() < MIN_REPOSITORY_KEY_HEX_LEN {
        return Err(invalid_repository_key(
            key,
            "expected at least 32 bytes of hex-encoded key material",
        ));
    }
    if !value.len().is_multiple_of(2) {
        return Err(invalid_repository_key(
            key,
            "expected even-length hexadecimal text",
        ));
    }
    if !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(invalid_repository_key(
            key,
            "expected hexadecimal text only",
        ));
    }

    Ok(())
}

fn validate_repository_salt_hex(key: &'static str, value: &str) -> Result<(), ConfigError> {
    if value.len() < MIN_REPOSITORY_SALT_HEX_LEN {
        return Err(invalid_repository_key(
            key,
            "expected at least 32 bytes of hex-encoded repository salt",
        ));
    }
    if !value.len().is_multiple_of(2) {
        return Err(invalid_repository_key(
            key,
            "expected even-length hexadecimal text",
        ));
    }
    if !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(invalid_repository_key(
            key,
            "expected hexadecimal text only",
        ));
    }

    Ok(())
}

fn invalid_repository_key(key: &'static str, reason: &str) -> ConfigError {
    ConfigError::Invalid {
        key,
        value: REDACTED_SECRET_VALUE.to_owned(),
        reason: reason.to_owned(),
    }
}

fn parse_static_credentials(
    source: &impl ConfigSource,
) -> Result<Option<StaticCredentials>, ConfigError> {
    let access_key_id = optional_value(source, STATIC_ACCESS_KEY_ID_ENV);
    let secret_access_key = optional_value(source, STATIC_SECRET_ACCESS_KEY_ENV);

    match (access_key_id, secret_access_key) {
        (Some(access_key_id), Some(secret_access_key)) => Ok(Some(StaticCredentials {
            access_key_id,
            secret_access_key: SecretString::from(secret_access_key),
        })),
        (None, None) => Ok(None),
        _ => Err(ConfigError::PartialStaticCredentials {
            access_key_id: STATIC_ACCESS_KEY_ID_ENV,
            secret_access_key: STATIC_SECRET_ACCESS_KEY_ENV,
        }),
    }
}

trait ConfigSource {
    fn value(&self, key: &'static str) -> Option<String>;
}

struct ProcessEnv;

impl ConfigSource for ProcessEnv {
    fn value(&self, key: &'static str) -> Option<String> {
        std::env::var(key).ok().and_then(non_blank)
    }
}

fn required_value(source: &impl ConfigSource, key: &'static str) -> Result<String, ConfigError> {
    source.value(key).ok_or(ConfigError::Missing { key })
}

fn optional_value(source: &impl ConfigSource, key: &'static str) -> Option<String> {
    source.value(key)
}

fn non_blank(value: String) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

fn parse_socket_addr(key: &'static str, value: String) -> Result<SocketAddr, ConfigError> {
    value.parse().map_err(|error| ConfigError::Invalid {
        key,
        value: value.clone(),
        reason: format!("expected host:port, e.g. 0.0.0.0:9080: {error}"),
    })
}

fn parse_public_bucket(key: &'static str, value: String) -> Result<PublicBucket, ConfigError> {
    PublicBucket::new(value.clone()).map_err(|error| ConfigError::Invalid {
        key,
        value,
        reason: error.to_string(),
    })
}

fn parse_positive_usize(
    key: &'static str,
    value: Option<String>,
    default: usize,
) -> Result<usize, ConfigError> {
    let Some(value) = value else {
        return Ok(default);
    };
    let parsed = value
        .parse::<usize>()
        .map_err(|error| ConfigError::Invalid {
            key,
            value: value.clone(),
            reason: format!("expected positive integer: {error}"),
        })?;
    if parsed == 0 {
        return Err(ConfigError::Invalid {
            key,
            value,
            reason: "expected value greater than zero".to_owned(),
        });
    }

    Ok(parsed)
}

fn parse_positive_u32(
    key: &'static str,
    value: Option<String>,
    missing_reason: String,
) -> Result<u32, ConfigError> {
    let Some(value) = value else {
        return Err(ConfigError::Invalid {
            key,
            value: String::new(),
            reason: missing_reason,
        });
    };
    let parsed = value.parse::<u32>().map_err(|error| ConfigError::Invalid {
        key,
        value: value.clone(),
        reason: format!("expected positive integer: {error}"),
    })?;
    if parsed == 0 {
        return Err(ConfigError::Invalid {
            key,
            value,
            reason: "expected value greater than zero".to_owned(),
        });
    }

    Ok(parsed)
}

fn parse_u64(key: &'static str, value: Option<String>, default: u64) -> Result<u64, ConfigError> {
    let Some(value) = value else {
        return Ok(default);
    };

    value.parse::<u64>().map_err(|error| ConfigError::Invalid {
        key,
        value: value.clone(),
        reason: format!("expected unsigned integer: {error}"),
    })
}

fn parse_positive_u64(
    key: &'static str,
    value: Option<String>,
    default: u64,
) -> Result<u64, ConfigError> {
    let parsed = parse_u64(key, value, default)?;
    if parsed == 0 {
        return Err(ConfigError::Invalid {
            key,
            value: "0".to_owned(),
            reason: "expected value greater than zero".to_owned(),
        });
    }

    Ok(parsed)
}

fn parse_bool(
    key: &'static str,
    value: Option<String>,
    default: bool,
) -> Result<bool, ConfigError> {
    let Some(value) = value else {
        return Ok(default);
    };

    match value.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(ConfigError::Invalid {
            key,
            value,
            reason: "expected true or false".to_owned(),
        }),
    }
}

fn secret_string_eq(left: &SecretString, right: &SecretString) -> bool {
    ct_eq(
        left.expose_secret().as_bytes(),
        right.expose_secret().as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        AnchorConfig, BatchConfig, ConfigError, ConfigSource, GatewayMode, HardeningConfig,
        MaintenanceConfig, MetricsConfig, RecoveryConfig, RepositoryConfig, RepositoryFormat,
        RepositoryKeyContextConfig, RepositoryKeysConfig, RepositoryToolConfig, RuntimeConfig,
        StaticCredentials, V2ProviderCheckConfig, WriterGuardConfig,
    };
    use rs3_types::{RetentionMode, RetentionPolicy};
    use secrecy::SecretString;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::time::Duration;

    const WRAPPING_KEY_HEX: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";
    const REPOSITORY_SALT_HEX: &str =
        "2222222222222222222222222222222222222222222222222222222222222222";

    #[derive(Clone, Default)]
    struct TestSource(BTreeMap<&'static str, String>);

    impl TestSource {
        fn with(mut self, key: &'static str, value: &str) -> Self {
            self.0.insert(key, value.to_owned());
            self
        }

        fn without(mut self, key: &'static str) -> Self {
            self.0.remove(key);
            self
        }
    }

    impl ConfigSource for TestSource {
        fn value(&self, key: &'static str) -> Option<String> {
            self.0.get(key).cloned().and_then(super::non_blank)
        }
    }

    fn minimal_source() -> TestSource {
        TestSource::default()
            .with("RS3_PUBLIC_BUCKET", "client-bucket")
            .with("RS3_BACKEND_ENDPOINT", "https://object.example")
            .with("RS3_BACKEND_BUCKET", "backend-bucket")
            .with("RS3_ANCHOR_MODE", "memory")
            .with(super::ALLOW_MEMORY_ANCHOR_ENV, "true")
            .with(super::REPOSITORY_ID_ENV, "test-repository")
            .with(super::REPOSITORY_SALT_HEX_ENV, REPOSITORY_SALT_HEX)
            .with(super::KEYRING_WRAPPING_KEY_HEX_ENV, WRAPPING_KEY_HEX)
    }

    fn repository_keys_config() -> RepositoryKeysConfig {
        RepositoryKeysConfig {
            repository_id: rs3_types::RepositoryId::new("test-repository")
                .unwrap_or_else(|error| panic!("{error}")),
            repository_salt_hex: REPOSITORY_SALT_HEX.to_owned(),
            envelope_object_id: None,
            wrapping_key_id: super::DEFAULT_KEYRING_WRAPPING_KEY_ID.to_owned(),
            wrapping_key_hex: SecretString::from(WRAPPING_KEY_HEX),
        }
    }

    fn config_error_keys(error: &ConfigError) -> Vec<&'static str> {
        match error {
            ConfigError::Multiple { errors } => errors.iter().flat_map(config_error_keys).collect(),
            ConfigError::Missing { key } | ConfigError::Invalid { key, .. } => vec![*key],
            ConfigError::PartialStaticCredentials {
                access_key_id,
                secret_access_key,
            } => vec![*access_key_id, *secret_access_key],
        }
    }

    #[test]
    fn parses_minimal_runtime_config() {
        let config = RuntimeConfig::from_source(&minimal_source());

        let config = match config {
            Ok(config) => config,
            Err(error) => panic!("{error}"),
        };
        assert_eq!(config.mode, GatewayMode::ReadWrite);
        assert_eq!(config.bind.to_string(), "127.0.0.1:9080");
        assert_eq!(config.metrics, MetricsConfig { bind: None });
        assert_eq!(config.hardening, HardeningConfig::default());
        assert_eq!(config.public_bucket.as_str(), "client-bucket");
        assert_eq!(config.backend.endpoint, "https://object.example");
        assert_eq!(config.backend.bucket, "backend-bucket");
        assert_eq!(config.anchor, AnchorConfig::Memory);
        assert_eq!(config.writer_guard, WriterGuardConfig::Off);
        assert_eq!(
            config.batching,
            BatchConfig {
                max_items: 64,
                max_delay: Duration::from_millis(25),
                max_pending_items: 64,
            }
        );
        assert_eq!(
            config.repository,
            RepositoryConfig {
                format: RepositoryFormat::V2Preview,
                payload_segment_size: 512,
                adaptive_payload_segment_size: true,
                decrypted_segment_cache_max_bytes:
                    rs3_repository::DEFAULT_DECRYPTED_SEGMENT_CACHE_MAX_BYTES,
                retention: None,
                allow_init: false,
            }
        );
        assert_eq!(
            config.provider_conformance,
            super::ProviderConformanceConfig::default()
        );
        assert_eq!(config.recovery, RecoveryConfig::default());
        assert_eq!(config.repository_keys, repository_keys_config());
        assert!(config.static_credentials.is_none());
    }

    #[test]
    fn provider_check_config_requires_only_backend_and_retention() {
        let source = TestSource::default()
            .with("RS3_BACKEND_ENDPOINT", "https://object.example")
            .with("RS3_BACKEND_BUCKET", "backend-bucket")
            .with("RS3_BACKEND_PREFIX", "provider-check")
            .with(super::REPOSITORY_RETENTION_MODE_ENV, "governance")
            .with(super::REPOSITORY_RETENTION_DAYS_ENV, "7");

        let config =
            V2ProviderCheckConfig::from_source(&source).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(config.backend.endpoint, "https://object.example");
        assert_eq!(config.backend.bucket, "backend-bucket");
        assert_eq!(config.backend.prefix.as_deref(), Some("provider-check"));
        assert_eq!(config.repository_format, RepositoryFormat::V2Preview);
        assert_eq!(
            config.repository_retention,
            Some(RetentionPolicy::new(RetentionMode::Governance, 7))
        );
    }

    #[test]
    fn provider_check_config_still_requires_backend() {
        let error = V2ProviderCheckConfig::from_source(&TestSource::default())
            .expect_err("provider check needs a backend to probe");

        assert_eq!(
            config_error_keys(&error),
            vec!["RS3_BACKEND_ENDPOINT", "RS3_BACKEND_BUCKET"]
        );
    }

    #[test]
    fn repository_tool_config_requires_only_backend_and_repository_context() {
        let source = TestSource::default()
            .with("RS3_BACKEND_ENDPOINT", "https://object.example")
            .with("RS3_BACKEND_BUCKET", "backend-bucket")
            .with("RS3_BACKEND_PREFIX", "repository")
            .with(super::REPOSITORY_ID_ENV, "test-repository")
            .with(super::REPOSITORY_SALT_HEX_ENV, REPOSITORY_SALT_HEX)
            .with(
                super::KEYRING_ENVELOPE_OBJECT_ID_ENV,
                "keyrings/bootstrap-envelope.json",
            )
            .with(super::KEYRING_WRAPPING_KEY_ID_ENV, "wrap-custom")
            .with(super::REPOSITORY_RETENTION_MODE_ENV, "compliance")
            .with(super::REPOSITORY_RETENTION_DAYS_ENV, "30")
            .with(
                super::RECOVERY_PUBLIC_KEY_ENV,
                "ed25519:1111111111111111111111111111111111111111111111111111111111111111",
            );

        let config =
            RepositoryToolConfig::from_source(&source).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(config.backend.endpoint, "https://object.example");
        assert_eq!(config.backend.bucket, "backend-bucket");
        assert_eq!(config.backend.prefix.as_deref(), Some("repository"));
        assert_eq!(config.repository_format, RepositoryFormat::V2Preview);
        assert_eq!(
            config.repository_retention,
            Some(RetentionPolicy::new(RetentionMode::Compliance, 30))
        );
        assert_eq!(
            config.recovery.public_key.as_deref(),
            Some("ed25519:1111111111111111111111111111111111111111111111111111111111111111")
        );
        assert_eq!(
            config.repository_keys,
            RepositoryKeyContextConfig {
                repository_id: rs3_types::RepositoryId::new("test-repository")
                    .unwrap_or_else(|error| panic!("{error}")),
                repository_salt_hex: REPOSITORY_SALT_HEX.to_owned(),
                envelope_object_id: Some(
                    rs3_types::BackendObjectId::new("keyrings/bootstrap-envelope.json")
                        .unwrap_or_else(|error| panic!("{error}")),
                ),
                wrapping_key_id: "wrap-custom".to_owned(),
            }
        );
    }

    #[test]
    fn repository_tool_config_still_requires_backend_and_repository_context() {
        let error = RepositoryToolConfig::from_source(&TestSource::default())
            .expect_err("repository tools need backend and repository context");

        assert_eq!(
            config_error_keys(&error),
            vec![
                "RS3_BACKEND_ENDPOINT",
                "RS3_BACKEND_BUCKET",
                super::REPOSITORY_ID_ENV,
                super::REPOSITORY_SALT_HEX_ENV,
            ]
        );
    }

    #[test]
    fn accepts_legacy_repository_format_v2_preview() {
        let source = minimal_source().with(super::REPOSITORY_FORMAT_ENV, "v2-preview");

        let config = RuntimeConfig::from_source(&source);

        assert_eq!(
            config.map(|config| config.repository.format),
            Ok(RepositoryFormat::V2Preview)
        );
    }

    #[test]
    fn rejects_invalid_repository_format() {
        let source = minimal_source().with(super::REPOSITORY_FORMAT_ENV, "stable");

        let config = RuntimeConfig::from_source(&source);

        assert!(
            matches!(config, Err(ConfigError::Invalid { key, .. }) if key == super::REPOSITORY_FORMAT_ENV)
        );
    }

    #[test]
    fn parses_restore_readonly_gateway_mode() {
        let source = minimal_source().with("RS3_GATEWAY_MODE", "restore-readonly");

        let config = RuntimeConfig::from_source(&source);

        assert_eq!(
            config.map(|config| config.mode),
            Ok(GatewayMode::RestoreReadOnly)
        );
    }

    #[test]
    fn rejects_invalid_gateway_mode() {
        let source = minimal_source().with("RS3_GATEWAY_MODE", "readonly");

        let config = RuntimeConfig::from_source(&source);

        assert!(
            matches!(config, Err(ConfigError::Invalid { key, .. }) if key == "RS3_GATEWAY_MODE")
        );
    }

    #[test]
    fn parses_metrics_bind() {
        let source = minimal_source().with("RS3_METRICS_BIND", "127.0.0.1:19090");

        let config = RuntimeConfig::from_source(&source);

        assert_eq!(
            config.map(|config| config.metrics.bind.map(|bind| bind.to_string())),
            Ok(Some("127.0.0.1:19090".to_owned()))
        );
    }

    #[test]
    fn rejects_invalid_metrics_bind() {
        let source = minimal_source().with("RS3_METRICS_BIND", "nope");

        let config = RuntimeConfig::from_source(&source);

        let error = match config {
            Ok(config) => panic!("unexpected config: {config:?}"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ConfigError::Invalid { key, .. } if key == "RS3_METRICS_BIND"
        ));
        let message = error.to_string();
        assert!(message.contains(r#"RS3_METRICS_BIND="nope""#));
        assert!(message.contains("expected host:port, e.g. 0.0.0.0:9080"));
    }

    #[test]
    fn parses_hardening_limits() {
        let source = minimal_source()
            .with("RS3_MAX_PUT_OBJECT_BYTES", "8388608")
            .with("RS3_BUFFERED_PUT_OBJECT_BYTES", "1048576")
            .with("RS3_BACKEND_MULTIPART_PART_BYTES", "5242880")
            .with("RS3_STREAM_READ_STALL_TIMEOUT_SECS", "2")
            .with("RS3_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES", "20971520")
            .with("RS3_MAX_IN_FLIGHT_DOWNLOAD_BODY_BYTES", "3145728")
            .with("RS3_MAX_CONCURRENT_CONNECTIONS", "64")
            .with("RS3_MAX_CONCURRENT_REQUESTS", "32")
            .with("RS3_REQUEST_RATE_LIMIT_PER_SECOND", "128");

        let config = RuntimeConfig::from_source(&source);

        assert_eq!(
            config.map(|config| config.hardening),
            Ok(HardeningConfig {
                max_put_object_bytes: 8_388_608,
                buffered_put_object_bytes: 1_048_576,
                backend_multipart_part_bytes: 5_242_880,
                stream_read_stall_timeout: Duration::from_secs(2),
                max_in_flight_upload_body_bytes: 20_971_520,
                max_in_flight_download_body_bytes: 3_145_728,
                max_concurrent_connections: 64,
                max_concurrent_requests: 32,
                request_rate_limit_per_second: 128,
            })
        );
    }

    #[test]
    fn rejects_zero_hardening_limits() {
        for key in [
            "RS3_MAX_PUT_OBJECT_BYTES",
            "RS3_BUFFERED_PUT_OBJECT_BYTES",
            "RS3_BACKEND_MULTIPART_PART_BYTES",
            "RS3_STREAM_READ_STALL_TIMEOUT_SECS",
            "RS3_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES",
            "RS3_MAX_IN_FLIGHT_DOWNLOAD_BODY_BYTES",
            "RS3_MAX_CONCURRENT_CONNECTIONS",
            "RS3_MAX_CONCURRENT_REQUESTS",
            "RS3_REQUEST_RATE_LIMIT_PER_SECOND",
        ] {
            let source = minimal_source().with(key, "0");

            let config = RuntimeConfig::from_source(&source);

            assert!(
                matches!(config, Err(ConfigError::Invalid { key: invalid_key, .. }) if invalid_key == key)
            );
        }
    }

    #[test]
    fn rejects_invalid_hardening_relationships() {
        let part = RuntimeConfig::from_source(
            &minimal_source().with("RS3_BACKEND_MULTIPART_PART_BYTES", "1048576"),
        );
        assert!(
            matches!(part, Err(ConfigError::Invalid { key, .. }) if key == "RS3_BACKEND_MULTIPART_PART_BYTES")
        );

        let oversized_part = RuntimeConfig::from_source(
            &minimal_source().with("RS3_BACKEND_MULTIPART_PART_BYTES", "5368709121"),
        );
        assert!(
            matches!(oversized_part, Err(ConfigError::Invalid { key, .. }) if key == "RS3_BACKEND_MULTIPART_PART_BYTES")
        );

        let max_put = RuntimeConfig::from_source(
            &minimal_source()
                .with("RS3_BACKEND_MULTIPART_PART_BYTES", "5242880")
                .with("RS3_MAX_PUT_OBJECT_BYTES", "52428800001"),
        );
        assert!(
            matches!(max_put, Err(ConfigError::Invalid { key, .. }) if key == "RS3_MAX_PUT_OBJECT_BYTES")
        );

        let buffered = RuntimeConfig::from_source(
            &minimal_source()
                .with("RS3_MAX_PUT_OBJECT_BYTES", "8388608")
                .with("RS3_BUFFERED_PUT_OBJECT_BYTES", "8388609"),
        );
        assert!(
            matches!(buffered, Err(ConfigError::Invalid { key, .. }) if key == "RS3_BUFFERED_PUT_OBJECT_BYTES")
        );

        let upload_budget = RuntimeConfig::from_source(
            &minimal_source().with("RS3_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES", "16777215"),
        );
        assert!(
            matches!(upload_budget, Err(ConfigError::Invalid { key, .. }) if key == "RS3_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES")
        );

        let overlapping_buffer_and_streaming_budget = RuntimeConfig::from_source(
            &minimal_source()
                .with("RS3_MAX_PUT_OBJECT_BYTES", "104857600")
                .with("RS3_BUFFERED_PUT_OBJECT_BYTES", "10485760")
                .with("RS3_BACKEND_MULTIPART_PART_BYTES", "5242880")
                .with("RS3_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES", "20971520"),
        );
        assert!(
            matches!(overlapping_buffer_and_streaming_budget, Err(ConfigError::Invalid { key, .. }) if key == "RS3_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES")
        );

        let excessive_permits = tokio::sync::Semaphore::MAX_PERMITS + 1;
        for key in [
            "RS3_MAX_CONCURRENT_CONNECTIONS",
            "RS3_MAX_CONCURRENT_REQUESTS",
        ] {
            let config = RuntimeConfig::from_source(
                &minimal_source().with(key, &excessive_permits.to_string()),
            );
            assert!(
                matches!(config, Err(ConfigError::Invalid { key: invalid_key, .. }) if invalid_key == key)
            );
        }
    }

    #[test]
    fn validates_programmatically_assembled_runtime_config() {
        let mut config =
            RuntimeConfig::from_source(&minimal_source()).unwrap_or_else(|error| panic!("{error}"));
        config.hardening.max_concurrent_requests = tokio::sync::Semaphore::MAX_PERMITS + 1;
        config.hardening.backend_multipart_part_bytes = super::MAX_BACKEND_MULTIPART_PART_BYTES + 1;
        config.backend.prefix = Some(" ".to_owned());
        config.anchor = AnchorConfig::KubernetesLease {
            namespace: " ".to_owned(),
            name: String::new(),
            field_manager: "\t".to_owned(),
        };
        config.repository.retention = Some(RetentionPolicy::new(RetentionMode::None, 0));
        config.provider_conformance.report_file = Some(PathBuf::new());
        config.static_credentials = Some(StaticCredentials {
            access_key_id: " ".to_owned(),
            secret_access_key: SecretString::from("\t"),
        });

        let error = config
            .validate()
            .expect_err("invalid programmatic fields must be rejected");

        let keys = config_error_keys(&error);
        for key in [
            "RS3_MAX_CONCURRENT_REQUESTS",
            "RS3_BACKEND_MULTIPART_PART_BYTES",
            super::BACKEND_PREFIX_ENV,
            super::ANCHOR_NAMESPACE_ENV,
            super::ANCHOR_NAME_ENV,
            super::ANCHOR_FIELD_MANAGER_ENV,
            super::REPOSITORY_RETENTION_MODE_ENV,
            super::REPOSITORY_RETENTION_DAYS_ENV,
            super::PROVIDER_CONFORMANCE_REPORT_FILE_ENV,
            super::STATIC_ACCESS_KEY_ID_ENV,
            super::STATIC_SECRET_ACCESS_KEY_ENV,
        ] {
            assert!(
                keys.contains(&key),
                "missing programmatic validation for {key}"
            );
        }
    }

    #[test]
    fn upload_budget_accounts_for_configured_payload_segment_buffers() {
        const REQUIRED_UPLOAD_BUDGET: u64 = 212_873_216;
        let source = minimal_source()
            .with("RS3_MAX_PUT_OBJECT_BYTES", "104857600")
            .with("RS3_BUFFERED_PUT_OBJECT_BYTES", "1048576")
            .with("RS3_BACKEND_MULTIPART_PART_BYTES", "5242880")
            .with("RS3_PAYLOAD_SEGMENT_SIZE_BYTES", "67108864");

        let insufficient = RuntimeConfig::from_source(&source.clone().with(
            "RS3_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES",
            &(REQUIRED_UPLOAD_BUDGET - 1).to_string(),
        ));
        assert!(
            matches!(insufficient, Err(ConfigError::Invalid { key, .. }) if key == "RS3_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES")
        );

        let exact = RuntimeConfig::from_source(&source.with(
            "RS3_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES",
            &REQUIRED_UPLOAD_BUDGET.to_string(),
        ));
        assert!(exact.is_ok());
    }

    #[test]
    fn parses_backend_timeouts() {
        let source = minimal_source()
            .with("RS3_BACKEND_CONNECT_TIMEOUT_SECS", "2")
            .with("RS3_BACKEND_READ_TIMEOUT_SECS", "10")
            .with("RS3_BACKEND_OPERATION_ATTEMPT_TIMEOUT_SECS", "40")
            .with("RS3_BACKEND_OPERATION_TIMEOUT_SECS", "90")
            .with("RS3_BACKEND_STALLED_STREAM_GRACE_SECS", "12");

        let config = RuntimeConfig::from_source(&source).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(config.backend.timeouts.connect, Duration::from_secs(2));
        assert_eq!(config.backend.timeouts.read, Duration::from_secs(10));
        assert_eq!(
            config.backend.timeouts.operation_attempt,
            Duration::from_secs(40)
        );
        assert_eq!(config.backend.timeouts.operation, Duration::from_secs(90));
        assert_eq!(
            config.backend.timeouts.stalled_stream_grace,
            Duration::from_secs(12)
        );
    }

    #[test]
    fn rejects_zero_and_incoherent_backend_timeouts() {
        for key in [
            "RS3_BACKEND_CONNECT_TIMEOUT_SECS",
            "RS3_BACKEND_READ_TIMEOUT_SECS",
            "RS3_BACKEND_OPERATION_ATTEMPT_TIMEOUT_SECS",
            "RS3_BACKEND_OPERATION_TIMEOUT_SECS",
            "RS3_BACKEND_STALLED_STREAM_GRACE_SECS",
        ] {
            let config = RuntimeConfig::from_source(&minimal_source().with(key, "0"));
            assert!(
                matches!(config, Err(ConfigError::Invalid { key: invalid_key, .. }) if invalid_key == key)
            );
        }

        for (key, value) in [
            ("RS3_BACKEND_CONNECT_TIMEOUT_SECS", "121"),
            ("RS3_BACKEND_READ_TIMEOUT_SECS", "121"),
            ("RS3_BACKEND_OPERATION_ATTEMPT_TIMEOUT_SECS", "301"),
        ] {
            let config = RuntimeConfig::from_source(&minimal_source().with(key, value));
            assert!(
                matches!(config, Err(ConfigError::Invalid { key: invalid_key, .. }) if invalid_key == key)
            );
        }
    }

    #[test]
    fn parses_repository_payload_segment_size() {
        let source = minimal_source().with("RS3_PAYLOAD_SEGMENT_SIZE_BYTES", "65536");

        let config = RuntimeConfig::from_source(&source);

        assert_eq!(
            config.map(|config| config.repository),
            Ok(RepositoryConfig {
                format: RepositoryFormat::V2Preview,
                payload_segment_size: 65536,
                adaptive_payload_segment_size: false,
                decrypted_segment_cache_max_bytes:
                    rs3_repository::DEFAULT_DECRYPTED_SEGMENT_CACHE_MAX_BYTES,
                retention: None,
                allow_init: false,
            })
        );
    }

    #[test]
    fn rejects_unbounded_repository_payload_segment_size() {
        let source = minimal_source().with("RS3_PAYLOAD_SEGMENT_SIZE_BYTES", "67108865");

        let config = RuntimeConfig::from_source(&source);

        assert!(
            matches!(config, Err(ConfigError::Invalid { key, .. }) if key == "RS3_PAYLOAD_SEGMENT_SIZE_BYTES")
        );
    }

    #[test]
    fn parses_decrypted_segment_cache_size() {
        let source = minimal_source().with("RS3_DECRYPTED_SEGMENT_CACHE_MAX_BYTES", "0");

        let config = RuntimeConfig::from_source(&source);

        assert_eq!(
            config.map(|config| config.repository.decrypted_segment_cache_max_bytes),
            Ok(0)
        );
    }

    #[test]
    fn parses_repository_retention_policy() {
        let source = minimal_source()
            .with(super::REPOSITORY_RETENTION_MODE_ENV, "compliance")
            .with(super::REPOSITORY_RETENTION_DAYS_ENV, "30");

        let config = RuntimeConfig::from_source(&source);

        assert_eq!(
            config.map(|config| config.repository.retention),
            Ok(Some(rs3_types::RetentionPolicy::new(
                rs3_types::RetentionMode::Compliance,
                30
            )))
        );
    }

    #[test]
    fn parses_explicit_repository_init_gate() {
        let source = minimal_source().with(super::ALLOW_REPOSITORY_INIT_ENV, "true");

        let config = RuntimeConfig::from_source(&source);

        assert_eq!(config.map(|config| config.repository.allow_init), Ok(true));
    }

    #[test]
    fn parses_default_maintenance_config() {
        let config = RuntimeConfig::from_source(&minimal_source());

        let maintenance = match config {
            Ok(config) => config.maintenance,
            Err(error) => panic!("{error}"),
        };
        assert_eq!(maintenance, MaintenanceConfig::default());
        assert_eq!(maintenance.mode, super::MaintenanceMode::Auto);
        assert_eq!(
            maintenance.renewal_horizon,
            Duration::from_secs(7 * 24 * 60 * 60)
        );
        assert_eq!(maintenance.orphan_pressure_bytes, 1024 * 1024 * 1024);
        assert_eq!(maintenance.orphan_pressure_count, 512);
        assert_eq!(
            maintenance.orphan_pressure_max_age,
            Duration::from_secs(48 * 60 * 60)
        );
        assert_eq!(
            maintenance.max_interval,
            Duration::from_secs(7 * 24 * 60 * 60)
        );
        assert_eq!(maintenance.min_cooldown, Duration::from_secs(60 * 60));
        assert_eq!(maintenance.pacing_delay, None);
        let budgets = maintenance.budgets();
        assert_eq!(budgets.op_pacing_delay, None);
        assert_eq!(
            budgets.max_inventory_page_count,
            rs3_repository::v2::V2MaintenanceBudgets::default().max_inventory_page_count
        );
        assert_eq!(
            budgets.max_inventory_item_count,
            rs3_repository::v2::V2MaintenanceBudgets::default().max_inventory_item_count
        );
    }

    #[test]
    fn parses_maintenance_overrides() {
        let source = minimal_source()
            .with(super::MAINTENANCE_MODE_ENV, "manual")
            .with(super::MAINTENANCE_RENEWAL_HORIZON_SECONDS_ENV, "86400")
            .with(super::MAINTENANCE_ORPHAN_PRESSURE_BYTES_ENV, "1048576")
            .with(super::MAINTENANCE_ORPHAN_PRESSURE_COUNT_ENV, "9")
            .with(
                super::MAINTENANCE_ORPHAN_PRESSURE_MAX_AGE_SECONDS_ENV,
                "7200",
            )
            .with(super::MAINTENANCE_MAX_INTERVAL_SECONDS_ENV, "259200")
            .with(super::MAINTENANCE_MIN_COOLDOWN_SECONDS_ENV, "600")
            .with(super::MAINTENANCE_PACING_DELAY_MS_ENV, "25")
            .with(super::MAINTENANCE_MAX_INVENTORY_PAGES_ENV, "128")
            .with(super::MAINTENANCE_MAX_INVENTORY_ITEMS_ENV, "4096");

        let config = RuntimeConfig::from_source(&source);

        let maintenance = match config {
            Ok(config) => config.maintenance,
            Err(error) => panic!("{error}"),
        };
        assert_eq!(maintenance.mode, super::MaintenanceMode::Manual);
        assert_eq!(maintenance.renewal_horizon, Duration::from_secs(86_400));
        assert_eq!(maintenance.orphan_pressure_bytes, 1_048_576);
        assert_eq!(maintenance.orphan_pressure_count, 9);
        assert_eq!(
            maintenance.orphan_pressure_max_age,
            Duration::from_secs(7_200)
        );
        assert_eq!(maintenance.max_interval, Duration::from_secs(259_200));
        assert_eq!(maintenance.min_cooldown, Duration::from_secs(600));
        assert_eq!(maintenance.pacing_delay, Some(Duration::from_millis(25)));
        assert_eq!(maintenance.max_inventory_pages, 128);
        assert_eq!(maintenance.max_inventory_items, 4_096);
        let budgets = maintenance.budgets();
        assert_eq!(budgets.op_pacing_delay, Some(Duration::from_millis(25)));
        assert_eq!(budgets.max_inventory_page_count, 128);
        assert_eq!(budgets.max_inventory_item_count, 4_096);
    }

    #[test]
    fn rejects_invalid_maintenance_mode() {
        let source = minimal_source().with(super::MAINTENANCE_MODE_ENV, "always");

        let config = RuntimeConfig::from_source(&source);

        assert!(
            matches!(config, Err(ConfigError::Invalid { key, .. }) if key == super::MAINTENANCE_MODE_ENV)
        );
    }

    #[test]
    fn rejects_zero_maintenance_limits() {
        for key in [
            super::MAINTENANCE_RENEWAL_HORIZON_SECONDS_ENV,
            super::MAINTENANCE_ORPHAN_PRESSURE_BYTES_ENV,
            super::MAINTENANCE_ORPHAN_PRESSURE_COUNT_ENV,
            super::MAINTENANCE_ORPHAN_PRESSURE_MAX_AGE_SECONDS_ENV,
            super::MAINTENANCE_MAX_INTERVAL_SECONDS_ENV,
            super::MAINTENANCE_MIN_COOLDOWN_SECONDS_ENV,
            super::MAINTENANCE_PACING_DELAY_MS_ENV,
            super::MAINTENANCE_MAX_INVENTORY_PAGES_ENV,
            super::MAINTENANCE_MAX_INVENTORY_ITEMS_ENV,
        ] {
            let source = minimal_source().with(key, "0");

            let config = RuntimeConfig::from_source(&source);

            assert!(
                matches!(config, Err(ConfigError::Invalid { key: invalid_key, .. }) if invalid_key == key),
                "expected zero rejection for {key}"
            );
        }
    }

    #[test]
    fn rejects_maintenance_cooldown_above_max_interval() {
        let source = minimal_source()
            .with(super::MAINTENANCE_MAX_INTERVAL_SECONDS_ENV, "600")
            .with(super::MAINTENANCE_MIN_COOLDOWN_SECONDS_ENV, "601");

        let config = RuntimeConfig::from_source(&source);

        assert!(
            matches!(config, Err(ConfigError::Invalid { key, .. }) if key == super::MAINTENANCE_MIN_COOLDOWN_SECONDS_ENV)
        );
    }

    #[test]
    fn forces_maintenance_off_for_restore_readonly() {
        let source = minimal_source().with("RS3_GATEWAY_MODE", "restore-readonly");

        let config = RuntimeConfig::from_source(&source);

        let maintenance = match config {
            Ok(config) => config.maintenance,
            Err(error) => panic!("{error}"),
        };
        assert_eq!(maintenance.mode, super::MaintenanceMode::Off);
    }

    #[test]
    fn rejects_maintenance_mode_for_restore_readonly() {
        for value in ["auto", "manual", "off"] {
            let source = minimal_source()
                .with("RS3_GATEWAY_MODE", "restore-readonly")
                .with(super::MAINTENANCE_MODE_ENV, value);

            let config = RuntimeConfig::from_source(&source);

            assert!(
                matches!(config, Err(ConfigError::Invalid { key, .. }) if key == super::MAINTENANCE_MODE_ENV),
                "expected rejection for RS3_MAINTENANCE_MODE={value} in restore-readonly mode"
            );
        }
    }

    #[test]
    fn parses_provider_conformance_evidence_config() {
        let source = minimal_source()
            .with(
                super::PROVIDER_CONFORMANCE_REPORT_FILE_ENV,
                "/var/lib/rs3/provider-report.json",
            )
            .with(super::PROVIDER_CONFORMANCE_MAX_AGE_SECONDS_ENV, "3600")
            .with(
                super::PROVIDER_PRINCIPAL_FINGERPRINT_ENV,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            );

        let config = RuntimeConfig::from_source(&source);

        let config = config.unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            config.provider_conformance.report_file.as_deref(),
            Some(std::path::Path::new("/var/lib/rs3/provider-report.json"))
        );
        assert_eq!(
            config.provider_conformance.max_age,
            Duration::from_secs(3600)
        );
        assert_eq!(
            config.provider_conformance.principal_fingerprint.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    }

    #[test]
    fn rejects_malformed_provider_principal_fingerprint_without_echoing_it() {
        let source = minimal_source().with(super::PROVIDER_PRINCIPAL_FINGERPRINT_ENV, "tenant-a");

        let error = RuntimeConfig::from_source(&source)
            .expect_err("malformed principal fingerprint should fail closed");

        assert!(config_error_keys(&error).contains(&super::PROVIDER_PRINCIPAL_FINGERPRINT_ENV));
        assert!(!error.to_string().contains("tenant-a"));
    }

    #[test]
    fn parses_recovery_public_key_config() {
        let source = minimal_source().with(
            super::RECOVERY_PUBLIC_KEY_ENV,
            "ed25519:1111111111111111111111111111111111111111111111111111111111111111",
        );

        let config = RuntimeConfig::from_source(&source);

        assert_eq!(
            config.map(|config| config.recovery.public_key),
            Ok(Some(
                "ed25519:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_owned()
            ))
        );
    }

    #[test]
    fn rejects_malformed_recovery_public_key() {
        let source = minimal_source().with(super::RECOVERY_PUBLIC_KEY_ENV, "not-ed25519");

        let config = RuntimeConfig::from_source(&source);

        assert!(
            matches!(config, Err(ConfigError::Invalid { key, .. }) if key == super::RECOVERY_PUBLIC_KEY_ENV)
        );
    }

    #[test]
    fn rejects_partial_repository_retention_policy() {
        let source = minimal_source().with(super::REPOSITORY_RETENTION_DAYS_ENV, "30");

        let config = RuntimeConfig::from_source(&source);

        assert!(
            matches!(config, Err(ConfigError::Invalid { key, .. }) if key == super::REPOSITORY_RETENTION_DAYS_ENV)
        );
    }

    #[test]
    fn parses_default_keyring_envelope_key_source() {
        let source = minimal_source();

        let config = RuntimeConfig::from_source(&source);

        let keys = match config {
            Ok(config) => config.repository_keys,
            Err(error) => panic!("{error}"),
        };
        assert_eq!(keys.envelope_object_id, None);
        assert_eq!(keys.wrapping_key_id, super::DEFAULT_KEYRING_WRAPPING_KEY_ID);
        assert!(super::secret_string_eq(
            &keys.wrapping_key_hex,
            &SecretString::from(WRAPPING_KEY_HEX)
        ));
    }

    #[test]
    fn parses_keyring_envelope_override() {
        let source = minimal_source()
            .with(
                super::KEYRING_ENVELOPE_OBJECT_ID_ENV,
                "keyrings/bootstrap-envelope.json",
            )
            .with(super::KEYRING_WRAPPING_KEY_ID_ENV, "wrap-custom");

        let config = RuntimeConfig::from_source(&source);

        let keys = match config {
            Ok(config) => config.repository_keys,
            Err(error) => panic!("{error}"),
        };
        assert_eq!(
            keys.envelope_object_id.as_ref().map(|id| id.as_str()),
            Some("keyrings/bootstrap-envelope.json")
        );
        assert_eq!(keys.wrapping_key_id, "wrap-custom");
    }

    #[test]
    fn rejects_missing_repository_id() {
        let source = minimal_source().without(super::REPOSITORY_ID_ENV);

        let config = RuntimeConfig::from_source(&source);

        let error = match config {
            Ok(config) => panic!("unexpected config: {config:?}"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ConfigError::Missing { key } if key == super::REPOSITORY_ID_ENV
        ));
        assert!(
            error
                .to_string()
                .contains("docs/site/reference/configuration.md")
        );
    }

    #[test]
    fn rejects_missing_repository_salt() {
        let source = minimal_source().without(super::REPOSITORY_SALT_HEX_ENV);

        let config = RuntimeConfig::from_source(&source);

        assert!(
            matches!(config, Err(ConfigError::Missing { key }) if key == super::REPOSITORY_SALT_HEX_ENV)
        );
    }

    #[test]
    fn rejects_malformed_wrapping_key_hex() {
        let source = minimal_source().with(super::KEYRING_WRAPPING_KEY_HEX_ENV, "not-hex");

        let config = RuntimeConfig::from_source(&source);

        assert!(
            matches!(config, Err(ConfigError::Invalid { key, value, .. }) if key == super::KEYRING_WRAPPING_KEY_HEX_ENV && value == "<redacted>")
        );
    }

    #[test]
    fn rejects_short_wrapping_key_hex() {
        let source = minimal_source().with(super::KEYRING_WRAPPING_KEY_HEX_ENV, "aa");

        let config = RuntimeConfig::from_source(&source);

        assert!(
            matches!(config, Err(ConfigError::Invalid { key, value, .. }) if key == super::KEYRING_WRAPPING_KEY_HEX_ENV && value == "<redacted>")
        );
    }

    #[test]
    fn rejects_malformed_repository_salt_hex() {
        let source = minimal_source().with(super::REPOSITORY_SALT_HEX_ENV, "not-hex");

        let config = RuntimeConfig::from_source(&source);

        assert!(
            matches!(config, Err(ConfigError::Invalid { key, value, .. }) if key == super::REPOSITORY_SALT_HEX_ENV && value == "<redacted>")
        );
    }

    #[test]
    fn rejects_short_repository_salt_hex() {
        let source = minimal_source().with(super::REPOSITORY_SALT_HEX_ENV, "aa");

        let config = RuntimeConfig::from_source(&source);

        assert!(
            matches!(config, Err(ConfigError::Invalid { key, value, .. }) if key == super::REPOSITORY_SALT_HEX_ENV && value == "<redacted>")
        );
    }

    #[test]
    fn parses_kubernetes_anchor_config() {
        let source = minimal_source()
            .with("RS3_ANCHOR_MODE", "kubernetes-lease")
            .with("RS3_ANCHOR_NAMESPACE", "backup")
            .with("RS3_ANCHOR_NAME", "v2-anchor")
            .with("RS3_ANCHOR_FIELD_MANAGER", "rs3-controller");

        let config = RuntimeConfig::from_source(&source);

        assert_eq!(
            config.map(|config| config.anchor),
            Ok(AnchorConfig::KubernetesLease {
                namespace: "backup".to_owned(),
                name: "v2-anchor".to_owned(),
                field_manager: "rs3-controller".to_owned(),
            })
        );
    }

    #[test]
    fn defaults_writer_guard_required_for_kubernetes_anchor() {
        let source = minimal_source()
            .with("RS3_ANCHOR_MODE", "kubernetes-lease")
            .with("RS3_ANCHOR_NAMESPACE", "backup")
            .with("RS3_ANCHOR_NAME", "v2-anchor");

        let config = RuntimeConfig::from_source(&source);

        assert_eq!(
            config.map(|config| config.writer_guard),
            Ok(WriterGuardConfig::Required)
        );
    }

    #[test]
    fn parses_writer_guard_off_for_kubernetes_anchor() {
        let source = minimal_source()
            .with("RS3_ANCHOR_MODE", "kubernetes-lease")
            .with("RS3_ANCHOR_NAMESPACE", "backup")
            .with("RS3_ANCHOR_NAME", "v2-anchor")
            .with(super::WRITER_GUARD_ENV, "off");

        let config = RuntimeConfig::from_source(&source);

        assert_eq!(
            config.map(|config| config.writer_guard),
            Ok(WriterGuardConfig::Off)
        );
    }

    #[test]
    fn rejects_required_writer_guard_without_kubernetes_anchor() {
        let source = minimal_source().with(super::WRITER_GUARD_ENV, "required");

        let config = RuntimeConfig::from_source(&source);

        assert!(
            matches!(config, Err(ConfigError::Invalid { key, .. }) if key == super::WRITER_GUARD_ENV)
        );
    }

    #[test]
    fn rejects_invalid_writer_guard_config() {
        let source = minimal_source().with(super::WRITER_GUARD_ENV, "mandatory");

        let config = RuntimeConfig::from_source(&source);

        assert!(
            matches!(config, Err(ConfigError::Invalid { key, .. }) if key == super::WRITER_GUARD_ENV)
        );
    }

    #[test]
    fn rejects_missing_anchor_mode() {
        let source = minimal_source().without("RS3_ANCHOR_MODE");

        let config = RuntimeConfig::from_source(&source);

        assert!(matches!(config, Err(ConfigError::Missing { key }) if key == "RS3_ANCHOR_MODE"));
    }

    #[test]
    fn rejects_memory_anchor_without_explicit_allowance() {
        let source = minimal_source().without(super::ALLOW_MEMORY_ANCHOR_ENV);

        let config = RuntimeConfig::from_source(&source);

        assert!(
            matches!(config, Err(ConfigError::Invalid { key, .. }) if key == "RS3_ANCHOR_MODE")
        );
    }

    #[test]
    fn rejects_invalid_memory_anchor_allowance() {
        let source = minimal_source().with(super::ALLOW_MEMORY_ANCHOR_ENV, "yes");

        let config = RuntimeConfig::from_source(&source);

        assert!(
            matches!(config, Err(ConfigError::Invalid { key, .. }) if key == super::ALLOW_MEMORY_ANCHOR_ENV)
        );
    }

    #[test]
    fn rejects_partial_static_credentials() {
        let source = minimal_source().with("RS3_STATIC_ACCESS_KEY_ID", "rs3-fixture-access-key");

        let config = RuntimeConfig::from_source(&source);

        assert!(matches!(
            config,
            Err(ConfigError::PartialStaticCredentials { .. })
        ));
    }

    #[test]
    fn rejects_zero_batch_limit() {
        let source = minimal_source().with("RS3_COMMIT_MAX_PENDING_ITEMS", "0");

        let config = RuntimeConfig::from_source(&source);

        assert!(
            matches!(config, Err(ConfigError::Invalid { key, .. }) if key == "RS3_COMMIT_MAX_PENDING_ITEMS")
        );
    }

    #[test]
    fn rejects_zero_payload_segment_size() {
        let source = minimal_source().with("RS3_PAYLOAD_SEGMENT_SIZE_BYTES", "0");

        let config = RuntimeConfig::from_source(&source);

        assert!(
            matches!(config, Err(ConfigError::Invalid { key, .. }) if key == "RS3_PAYLOAD_SEGMENT_SIZE_BYTES")
        );
    }

    #[test]
    fn static_secret_is_redacted_in_debug_output() {
        let source = minimal_source()
            .with("RS3_STATIC_ACCESS_KEY_ID", "rs3-fixture-access-key")
            .with("RS3_STATIC_SECRET_ACCESS_KEY", "super-secret");

        let config = RuntimeConfig::from_source(&source);
        let debug = match config {
            Ok(config) => format!("{config:?}"),
            Err(error) => panic!("{error}"),
        };

        assert!(debug.contains("rs3-fixture-access-key"));
        assert!(!debug.contains("super-secret"));
        assert!(!debug.contains("test-repository"));
        assert!(!debug.contains(REPOSITORY_SALT_HEX));
        assert!(!debug.contains(WRAPPING_KEY_HEX));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn reports_multiple_config_errors_at_once() {
        let source = minimal_source()
            .without("RS3_BACKEND_BUCKET")
            .without(super::REPOSITORY_ID_ENV)
            .with("RS3_GATEWAY_MODE", "readonly")
            .with("RS3_METRICS_BIND", "nope")
            .with("RS3_REQUEST_RATE_LIMIT_PER_SECOND", "0")
            .with("RS3_COMMIT_MAX_BATCH_ITEMS", "0")
            .with(super::REPOSITORY_FORMAT_ENV, "stable")
            .with(super::KEYRING_WRAPPING_KEY_HEX_ENV, "not-hex")
            .with("RS3_STATIC_ACCESS_KEY_ID", "rs3-fixture-access-key");

        let error = RuntimeConfig::from_source(&source)
            .expect_err("invalid source should report collected config errors");

        let ConfigError::Multiple { errors } = &error else {
            panic!("expected multiple errors, got {error:?}");
        };
        assert!(errors.len() >= 8);
        let keys = config_error_keys(&error);
        for key in [
            "RS3_BACKEND_BUCKET",
            super::REPOSITORY_ID_ENV,
            "RS3_GATEWAY_MODE",
            "RS3_METRICS_BIND",
            "RS3_REQUEST_RATE_LIMIT_PER_SECOND",
            "RS3_COMMIT_MAX_BATCH_ITEMS",
            super::REPOSITORY_FORMAT_ENV,
            super::KEYRING_WRAPPING_KEY_HEX_ENV,
            "RS3_STATIC_ACCESS_KEY_ID",
            "RS3_STATIC_SECRET_ACCESS_KEY",
        ] {
            assert!(keys.contains(&key), "missing collected error for {key}");
        }
        let message = error.to_string();
        assert!(message.contains("runtime configuration has"));
        assert!(message.contains("RS3_METRICS_BIND=\"nope\""));
        assert!(message.contains("RS3_GATEWAY_MODE=\"readonly\""));
        assert!(message.contains(super::KEYRING_WRAPPING_KEY_HEX_ENV));
        assert!(message.contains(super::REDACTED_SECRET_VALUE));
        assert!(!message.contains("not-hex"));
    }
}
