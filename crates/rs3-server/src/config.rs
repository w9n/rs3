//! Runtime configuration loaded from process environment.

use crate::identity::StaticCredentials;
use rs3_crypto::{MIN_REPOSITORY_SALT_LEN, SecretBytes};
use rs3_repository::DEFAULT_PAYLOAD_SEGMENT_SIZE;
use rs3_types::{BackendObjectId, PublicBucket, RepositoryId, RetentionMode, RetentionPolicy};
use secrecy::{ExposeSecret, SecretString};
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;

const DEFAULT_BIND: &str = "127.0.0.1:9080";
const DEFAULT_ANCHOR_FIELD_MANAGER: &str = "rs3-server";
pub const DEFAULT_KEYRING_WRAPPING_KEY_ID: &str = "wrap-v1";
const DEFAULT_BATCH_ITEMS: usize = 64;
const DEFAULT_BATCH_DELAY_MS: u64 = 25;
const DEFAULT_MAX_PUT_OBJECT_BYTES: u64 = 5 * 1024 * 1024 * 1024;
const DEFAULT_BUFFERED_PUT_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_BACKEND_MULTIPART_PART_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_MAX_CONCURRENT_CONNECTIONS: usize = 1024;
const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 256;
const DEFAULT_REQUEST_RATE_LIMIT_PER_SECOND: u64 = 1024;
const MIN_BACKEND_MULTIPART_PART_BYTES: u64 = 5 * 1024 * 1024;
const REDACTED_SECRET_VALUE: &str = "<redacted>";
const MIN_REPOSITORY_KEY_HEX_LEN: usize = SecretBytes::MIN_LEN * 2;
const MIN_REPOSITORY_SALT_HEX_LEN: usize = MIN_REPOSITORY_SALT_LEN * 2;
const REPOSITORY_RETENTION_MODE_ENV: &str = "RS3_REPOSITORY_RETENTION_MODE";
const REPOSITORY_RETENTION_DAYS_ENV: &str = "RS3_REPOSITORY_RETENTION_DAYS";
const REPOSITORY_FORMAT_ENV: &str = "RS3_REPOSITORY_FORMAT";
const DEFAULT_REPOSITORY_FORMAT: RepositoryFormat = RepositoryFormat::V2Preview;

pub(crate) const REPOSITORY_SALT_HEX_ENV: &str = "RS3_REPOSITORY_SALT_HEX";
pub(crate) const KEYRING_ENVELOPE_OBJECT_ID_ENV: &str = "RS3_KEYRING_ENVELOPE_OBJECT_ID";
pub(crate) const KEYRING_WRAPPING_KEY_HEX_ENV: &str = "RS3_KEYRING_WRAPPING_KEY_HEX";
pub(crate) const KEYRING_WRAPPING_KEY_ID_ENV: &str = "RS3_KEYRING_WRAPPING_KEY_ID";
const REPOSITORY_ID_ENV: &str = "RS3_REPOSITORY_ID";
const ALLOW_MEMORY_ANCHOR_ENV: &str = "RS3_ALLOW_MEMORY_ANCHOR";

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
    /// Coordinated commit batching settings.
    pub batching: BatchConfig,
    /// Repository object layout settings.
    pub repository: RepositoryConfig,
    /// Repository cryptographic key material.
    pub repository_keys: RepositoryKeysConfig,
    /// Optional static credentials accepted by the server.
    pub static_credentials: Option<StaticCredentials>,
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

    pub(crate) const fn allows_bootstrap(self) -> bool {
        matches!(self, Self::ReadWrite)
    }

    pub(crate) const fn requires_anchor(self) -> bool {
        matches!(self, Self::RestoreReadOnly)
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
    /// Admission budget for request body bytes held by in-flight upload operations.
    pub max_in_flight_upload_body_bytes: u64,
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
            max_in_flight_upload_body_bytes: DEFAULT_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES,
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
    /// A required environment variable is missing or blank.
    #[error("missing required environment variable: {key}")]
    Missing {
        /// Environment variable name.
        key: &'static str,
    },
    /// An environment variable has an invalid value.
    #[error("invalid environment variable {key}: {reason}")]
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

impl RuntimeConfig {
    /// Loads runtime configuration from the current process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_source(&ProcessEnv)
    }

    fn from_source(source: &impl ConfigSource) -> Result<Self, ConfigError> {
        let mode = parse_gateway_mode(source)?;
        let bind = parse_socket_addr(
            "RS3_BIND",
            source
                .value("RS3_BIND")
                .unwrap_or_else(|| DEFAULT_BIND.to_owned()),
        )?;
        let metrics = parse_metrics_config(source)?;
        let hardening = parse_hardening_config(source)?;
        let public_bucket = parse_public_bucket(
            "RS3_PUBLIC_BUCKET",
            required_value(source, "RS3_PUBLIC_BUCKET")?,
        )?;
        let backend = BackendConfig {
            endpoint: required_value(source, "RS3_BACKEND_ENDPOINT")?,
            bucket: required_value(source, "RS3_BACKEND_BUCKET")?,
            prefix: optional_value(source, "RS3_BACKEND_PREFIX"),
        };
        let anchor = parse_anchor_config(source)?;
        let batching = parse_batch_config(source)?;
        let repository = parse_repository_config(source)?;
        let repository_keys = parse_repository_keys_config(source)?;
        let static_credentials = parse_static_credentials(source)?;

        Ok(Self {
            mode,
            bind,
            metrics,
            hardening,
            public_bucket,
            backend,
            anchor,
            batching,
            repository,
            repository_keys,
            static_credentials,
        })
    }
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
    let max_put_object_bytes = parse_positive_u64(
        "RS3_MAX_PUT_OBJECT_BYTES",
        source.value("RS3_MAX_PUT_OBJECT_BYTES"),
        DEFAULT_MAX_PUT_OBJECT_BYTES,
    )?;
    let buffered_put_object_bytes = parse_positive_u64(
        "RS3_BUFFERED_PUT_OBJECT_BYTES",
        source.value("RS3_BUFFERED_PUT_OBJECT_BYTES"),
        DEFAULT_BUFFERED_PUT_OBJECT_BYTES,
    )?;
    let backend_multipart_part_bytes = parse_positive_u64(
        "RS3_BACKEND_MULTIPART_PART_BYTES",
        source.value("RS3_BACKEND_MULTIPART_PART_BYTES"),
        DEFAULT_BACKEND_MULTIPART_PART_BYTES,
    )?;
    if buffered_put_object_bytes > max_put_object_bytes {
        return Err(ConfigError::Invalid {
            key: "RS3_BUFFERED_PUT_OBJECT_BYTES",
            value: buffered_put_object_bytes.to_string(),
            reason: "must be less than or equal to RS3_MAX_PUT_OBJECT_BYTES".to_owned(),
        });
    }
    if backend_multipart_part_bytes < MIN_BACKEND_MULTIPART_PART_BYTES {
        return Err(ConfigError::Invalid {
            key: "RS3_BACKEND_MULTIPART_PART_BYTES",
            value: backend_multipart_part_bytes.to_string(),
            reason: "must be at least 5242880 bytes".to_owned(),
        });
    }
    let max_in_flight_upload_body_bytes = parse_positive_u64(
        "RS3_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES",
        source.value("RS3_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES"),
        DEFAULT_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES,
    )?;
    let max_concurrent_connections = parse_positive_usize(
        "RS3_MAX_CONCURRENT_CONNECTIONS",
        source.value("RS3_MAX_CONCURRENT_CONNECTIONS"),
        DEFAULT_MAX_CONCURRENT_CONNECTIONS,
    )?;
    let max_concurrent_requests = parse_positive_usize(
        "RS3_MAX_CONCURRENT_REQUESTS",
        source.value("RS3_MAX_CONCURRENT_REQUESTS"),
        DEFAULT_MAX_CONCURRENT_REQUESTS,
    )?;
    let request_rate_limit_per_second = parse_positive_u64(
        "RS3_REQUEST_RATE_LIMIT_PER_SECOND",
        source.value("RS3_REQUEST_RATE_LIMIT_PER_SECOND"),
        DEFAULT_REQUEST_RATE_LIMIT_PER_SECOND,
    )?;

    Ok(HardeningConfig {
        max_put_object_bytes,
        buffered_put_object_bytes,
        backend_multipart_part_bytes,
        max_in_flight_upload_body_bytes,
        max_concurrent_connections,
        max_concurrent_requests,
        request_rate_limit_per_second,
    })
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
        "kubernetes-lease" => Ok(AnchorConfig::KubernetesLease {
            namespace: required_value(source, "RS3_ANCHOR_NAMESPACE")?,
            name: required_value(source, "RS3_ANCHOR_NAME")?,
            field_manager: optional_value(source, "RS3_ANCHOR_FIELD_MANAGER")
                .unwrap_or_else(|| DEFAULT_ANCHOR_FIELD_MANAGER.to_owned()),
        }),
        _ => Err(ConfigError::Invalid {
            key: "RS3_ANCHOR_MODE",
            value: mode,
            reason: "expected memory or kubernetes-lease".to_owned(),
        }),
    }
}

fn parse_batch_config(source: &impl ConfigSource) -> Result<BatchConfig, ConfigError> {
    let max_items = parse_positive_usize(
        "RS3_COMMIT_MAX_BATCH_ITEMS",
        source.value("RS3_COMMIT_MAX_BATCH_ITEMS"),
        DEFAULT_BATCH_ITEMS,
    )?;
    let max_pending_items = parse_positive_usize(
        "RS3_COMMIT_MAX_PENDING_ITEMS",
        source.value("RS3_COMMIT_MAX_PENDING_ITEMS"),
        max_items,
    )?;
    let max_delay_ms = parse_u64(
        "RS3_COMMIT_MAX_BATCH_DELAY_MS",
        source.value("RS3_COMMIT_MAX_BATCH_DELAY_MS"),
        DEFAULT_BATCH_DELAY_MS,
    )?;

    Ok(BatchConfig {
        max_items,
        max_delay: Duration::from_millis(max_delay_ms),
        max_pending_items,
    })
}

fn parse_repository_config(source: &impl ConfigSource) -> Result<RepositoryConfig, ConfigError> {
    let format = parse_repository_format(source)?;
    let payload_segment_size_value = source.value("RS3_PAYLOAD_SEGMENT_SIZE_BYTES");
    let adaptive_payload_segment_size = payload_segment_size_value.is_none();
    let payload_segment_size = parse_positive_usize(
        "RS3_PAYLOAD_SEGMENT_SIZE_BYTES",
        payload_segment_size_value,
        DEFAULT_PAYLOAD_SEGMENT_SIZE,
    )?;
    let decrypted_segment_cache_max_bytes = parse_u64(
        "RS3_DECRYPTED_SEGMENT_CACHE_MAX_BYTES",
        source.value("RS3_DECRYPTED_SEGMENT_CACHE_MAX_BYTES"),
        rs3_repository::DEFAULT_DECRYPTED_SEGMENT_CACHE_MAX_BYTES,
    )?;
    let retention = parse_retention_policy(source)?;

    Ok(RepositoryConfig {
        format,
        payload_segment_size,
        adaptive_payload_segment_size,
        decrypted_segment_cache_max_bytes,
        retention,
    })
}

fn parse_repository_format(source: &impl ConfigSource) -> Result<RepositoryFormat, ConfigError> {
    let value = optional_value(source, REPOSITORY_FORMAT_ENV)
        .unwrap_or_else(|| DEFAULT_REPOSITORY_FORMAT.as_str().to_owned());
    match value.as_str() {
        "v2-preview" => Ok(RepositoryFormat::V2Preview),
        _ => Err(ConfigError::Invalid {
            key: REPOSITORY_FORMAT_ENV,
            value,
            reason: "expected v2-preview".to_owned(),
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
    Ok(RepositoryKeysConfig {
        repository_id: parse_repository_id(required_value(source, REPOSITORY_ID_ENV)?)?,
        repository_salt_hex: required_repository_salt_hex(source, REPOSITORY_SALT_HEX_ENV)?,
        envelope_object_id: optional_value(source, KEYRING_ENVELOPE_OBJECT_ID_ENV)
            .map(|value| parse_backend_object_id(KEYRING_ENVELOPE_OBJECT_ID_ENV, value))
            .transpose()?,
        wrapping_key_id: optional_value(source, KEYRING_WRAPPING_KEY_ID_ENV)
            .unwrap_or_else(|| DEFAULT_KEYRING_WRAPPING_KEY_ID.to_owned()),
        wrapping_key_hex: required_secret_hex(source, KEYRING_WRAPPING_KEY_HEX_ENV)?,
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
    let access_key_id = optional_value(source, "RS3_STATIC_ACCESS_KEY_ID");
    let secret_access_key = optional_value(source, "RS3_STATIC_SECRET_ACCESS_KEY");

    match (access_key_id, secret_access_key) {
        (Some(access_key_id), Some(secret_access_key)) => Ok(Some(StaticCredentials {
            access_key_id,
            secret_access_key: SecretString::from(secret_access_key),
        })),
        (None, None) => Ok(None),
        _ => Err(ConfigError::PartialStaticCredentials {
            access_key_id: "RS3_STATIC_ACCESS_KEY_ID",
            secret_access_key: "RS3_STATIC_SECRET_ACCESS_KEY",
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
        reason: format!("expected socket address: {error}"),
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
    constant_time_eq(
        left.expose_secret().as_bytes(),
        right.expose_secret().as_bytes(),
    )
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let diff = left
        .iter()
        .zip(right.iter())
        .fold(0_u8, |diff, (left, right)| diff | (left ^ right));
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::{
        AnchorConfig, BatchConfig, ConfigError, ConfigSource, GatewayMode, HardeningConfig,
        MetricsConfig, RepositoryConfig, RepositoryFormat, RepositoryKeysConfig, RuntimeConfig,
    };
    use secrecy::SecretString;
    use std::collections::BTreeMap;
    use std::time::Duration;

    const WRAPPING_KEY_HEX: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";
    const REPOSITORY_SALT_HEX: &str =
        "2222222222222222222222222222222222222222222222222222222222222222";

    #[derive(Default)]
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
            }
        );
        assert_eq!(config.repository_keys, repository_keys_config());
        assert!(config.static_credentials.is_none());
    }

    #[test]
    fn parses_repository_format_v2_preview() {
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

        assert!(
            matches!(config, Err(ConfigError::Invalid { key, .. }) if key == "RS3_METRICS_BIND")
        );
    }

    #[test]
    fn parses_hardening_limits() {
        let source = minimal_source()
            .with("RS3_MAX_PUT_OBJECT_BYTES", "8388608")
            .with("RS3_BUFFERED_PUT_OBJECT_BYTES", "1048576")
            .with("RS3_BACKEND_MULTIPART_PART_BYTES", "5242880")
            .with("RS3_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES", "2097152")
            .with("RS3_MAX_CONCURRENT_CONNECTIONS", "32")
            .with("RS3_MAX_CONCURRENT_REQUESTS", "16")
            .with("RS3_REQUEST_RATE_LIMIT_PER_SECOND", "128");

        let config = RuntimeConfig::from_source(&source);

        assert_eq!(
            config.map(|config| config.hardening),
            Ok(HardeningConfig {
                max_put_object_bytes: 8_388_608,
                buffered_put_object_bytes: 1_048_576,
                backend_multipart_part_bytes: 5_242_880,
                max_in_flight_upload_body_bytes: 2_097_152,
                max_concurrent_connections: 32,
                max_concurrent_requests: 16,
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
            "RS3_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES",
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
        let buffered = RuntimeConfig::from_source(
            &minimal_source()
                .with("RS3_MAX_PUT_OBJECT_BYTES", "1024")
                .with("RS3_BUFFERED_PUT_OBJECT_BYTES", "2048"),
        );
        assert!(
            matches!(buffered, Err(ConfigError::Invalid { key, .. }) if key == "RS3_BUFFERED_PUT_OBJECT_BYTES")
        );

        let part = RuntimeConfig::from_source(
            &minimal_source().with("RS3_BACKEND_MULTIPART_PART_BYTES", "1048576"),
        );
        assert!(
            matches!(part, Err(ConfigError::Invalid { key, .. }) if key == "RS3_BACKEND_MULTIPART_PART_BYTES")
        );
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
            })
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

        assert!(
            matches!(config, Err(ConfigError::Missing { key }) if key == super::REPOSITORY_ID_ENV)
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
        let source = minimal_source().with("RS3_STATIC_ACCESS_KEY_ID", "access");

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
            .with("RS3_STATIC_ACCESS_KEY_ID", "access")
            .with("RS3_STATIC_SECRET_ACCESS_KEY", "super-secret");

        let config = RuntimeConfig::from_source(&source);
        let debug = match config {
            Ok(config) => format!("{config:?}"),
            Err(error) => panic!("{error}"),
        };

        assert!(debug.contains("access"));
        assert!(!debug.contains("super-secret"));
        assert!(!debug.contains("test-repository"));
        assert!(!debug.contains(REPOSITORY_SALT_HEX));
        assert!(!debug.contains(WRAPPING_KEY_HEX));
        assert!(debug.contains("<redacted>"));
    }
}
