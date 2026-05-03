//! Runtime configuration loaded from process environment.

use crate::identity::StaticCredentials;
use rs3_repository::DEFAULT_PAYLOAD_SEGMENT_SIZE;
use rs3_types::PublicBucket;
use secrecy::SecretString;
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;

const DEFAULT_BIND: &str = "127.0.0.1:9080";
const DEFAULT_ANCHOR_MODE: &str = "memory";
const DEFAULT_ANCHOR_FIELD_MANAGER: &str = "rs3-server";
const DEFAULT_BATCH_ITEMS: usize = 64;
const DEFAULT_BATCH_DELAY_MS: u64 = 10;

/// Complete runtime configuration for the gateway process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeConfig {
    /// Socket address the gateway should bind to.
    pub bind: SocketAddr,
    /// Metrics exporter settings.
    pub metrics: MetricsConfig,
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
    /// Optional static credentials accepted by the server.
    pub static_credentials: Option<StaticCredentials>,
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

/// Checkpoint anchor settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorConfig {
    /// In-process anchor for local development and tests.
    Memory,
    /// Kubernetes Lease object used as the monotonic checkpoint anchor.
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
    /// Maximum number of staged writes covered by one checkpoint.
    pub max_items: usize,
    /// Maximum delay before publishing a partial batch.
    pub max_delay: Duration,
    /// Maximum number of writes waiting for commit before backpressure.
    pub max_pending_items: usize,
}

/// Repository object layout settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepositoryConfig {
    /// Plaintext bytes per independently encrypted payload segment.
    pub payload_segment_size: usize,
}

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
        let bind = parse_socket_addr(
            "RS3_BIND",
            source
                .value("RS3_BIND")
                .unwrap_or_else(|| DEFAULT_BIND.to_owned()),
        )?;
        let metrics = parse_metrics_config(source)?;
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
        let static_credentials = parse_static_credentials(source)?;

        Ok(Self {
            bind,
            metrics,
            public_bucket,
            backend,
            anchor,
            batching,
            repository,
            static_credentials,
        })
    }
}

fn parse_metrics_config(source: &impl ConfigSource) -> Result<MetricsConfig, ConfigError> {
    let bind = match optional_value(source, "RS3_METRICS_BIND") {
        Some(value) => Some(parse_socket_addr("RS3_METRICS_BIND", value)?),
        None => None,
    };
    Ok(MetricsConfig { bind })
}

fn parse_anchor_config(source: &impl ConfigSource) -> Result<AnchorConfig, ConfigError> {
    let mode = source
        .value("RS3_ANCHOR_MODE")
        .unwrap_or_else(|| DEFAULT_ANCHOR_MODE.to_owned());

    match mode.as_str() {
        "memory" => Ok(AnchorConfig::Memory),
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
    let payload_segment_size = parse_positive_usize(
        "RS3_PAYLOAD_SEGMENT_SIZE_BYTES",
        source.value("RS3_PAYLOAD_SEGMENT_SIZE_BYTES"),
        DEFAULT_PAYLOAD_SEGMENT_SIZE,
    )?;

    Ok(RepositoryConfig {
        payload_segment_size,
    })
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

#[cfg(test)]
mod tests {
    use super::{
        AnchorConfig, BatchConfig, ConfigError, ConfigSource, MetricsConfig, RepositoryConfig,
        RuntimeConfig,
    };
    use std::collections::BTreeMap;
    use std::time::Duration;

    #[derive(Default)]
    struct TestSource(BTreeMap<&'static str, String>);

    impl TestSource {
        fn with(mut self, key: &'static str, value: &str) -> Self {
            self.0.insert(key, value.to_owned());
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
    }

    #[test]
    fn parses_minimal_runtime_config() {
        let config = RuntimeConfig::from_source(&minimal_source());

        let config = match config {
            Ok(config) => config,
            Err(error) => panic!("{error}"),
        };
        assert_eq!(config.bind.to_string(), "127.0.0.1:9080");
        assert_eq!(config.metrics, MetricsConfig { bind: None });
        assert_eq!(config.public_bucket.as_str(), "client-bucket");
        assert_eq!(config.backend.endpoint, "https://object.example");
        assert_eq!(config.backend.bucket, "backend-bucket");
        assert_eq!(config.anchor, AnchorConfig::Memory);
        assert_eq!(
            config.batching,
            BatchConfig {
                max_items: 64,
                max_delay: Duration::from_millis(10),
                max_pending_items: 64,
            }
        );
        assert_eq!(
            config.repository,
            RepositoryConfig {
                payload_segment_size: 512,
            }
        );
        assert!(config.static_credentials.is_none());
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
    fn parses_repository_payload_segment_size() {
        let source = minimal_source().with("RS3_PAYLOAD_SEGMENT_SIZE_BYTES", "65536");

        let config = RuntimeConfig::from_source(&source);

        assert_eq!(
            config.map(|config| config.repository),
            Ok(RepositoryConfig {
                payload_segment_size: 65536,
            })
        );
    }

    #[test]
    fn parses_kubernetes_anchor_config() {
        let source = minimal_source()
            .with("RS3_ANCHOR_MODE", "kubernetes-lease")
            .with("RS3_ANCHOR_NAMESPACE", "backup")
            .with("RS3_ANCHOR_NAME", "checkpoint")
            .with("RS3_ANCHOR_FIELD_MANAGER", "rs3-controller");

        let config = RuntimeConfig::from_source(&source);

        assert_eq!(
            config.map(|config| config.anchor),
            Ok(AnchorConfig::KubernetesLease {
                namespace: "backup".to_owned(),
                name: "checkpoint".to_owned(),
                field_manager: "rs3-controller".to_owned(),
            })
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
        assert!(debug.contains("<redacted>"));
    }
}
