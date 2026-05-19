//! S3 protocol adapter surface.

mod adapter;
mod boundary;
mod mapping;
mod runtime;
mod runtime_builders;
mod runtime_handles;
mod runtime_keyring;
mod runtime_v2;

pub use boundary::{GatewayS3Boundary, S3Hardening};
pub(crate) use runtime_v2::v2_quick_maintenance_from_config;
pub use runtime_v2::{
    RuntimeV2ProviderConformanceOptions, V2_RESTORE_BUNDLE_SCHEMA, V2AnchorImportReport,
    check_v2_provider_conformance_from_config, export_v2_recovery_bundle_from_config,
    import_v2_anchor_from_config, write_v2_index_snapshot_from_config,
};
use thiserror::Error;

/// S3 boundary construction errors.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum S3BoundaryError {
    /// Static credentials are required before exposing the S3 service.
    #[error("static credentials are required to build the S3 boundary")]
    MissingStaticCredentials,
    /// The configured v2 commit anchor is not wired into the S3 adapter yet.
    #[error("configured v2 commit anchor mode is not supported by the S3 adapter yet")]
    UnsupportedAnchorMode,
    /// The configured backend object store is not wired into the runtime yet.
    #[error("configured backend object store is not supported by the S3 runtime yet")]
    UnsupportedBackendMode,
    /// Repository state initialization failed.
    #[error("failed to initialize repository state: {reason}")]
    RepositoryInit {
        /// Initialization failure reason.
        reason: String,
    },
}

pub(super) fn repository_init(error: impl ToString) -> S3BoundaryError {
    S3BoundaryError::RepositoryInit {
        reason: error.to_string(),
    }
}

#[cfg(test)]
pub(super) mod test_support {
    use crate::GatewayMode;
    use crate::{
        AnchorConfig, BackendConfig, BatchConfig, HardeningConfig, MetricsConfig,
        ProviderConformanceConfig, RepositoryConfig, RepositoryKeysConfig, RuntimeConfig,
        SecretString,
    };
    use rs3_types::{PublicBucket, RepositoryId};
    use std::time::Duration;

    pub(super) fn runtime_config(static_credentials: bool) -> RuntimeConfig {
        let bind = match "127.0.0.1:9080".parse() {
            Ok(bind) => bind,
            Err(error) => panic!("{error}"),
        };
        let public_bucket = match PublicBucket::new("client-bucket") {
            Ok(bucket) => bucket,
            Err(error) => panic!("{error}"),
        };

        RuntimeConfig {
            mode: GatewayMode::ReadWrite,
            bind,
            metrics: MetricsConfig { bind: None },
            hardening: HardeningConfig::default(),
            public_bucket,
            backend: BackendConfig {
                endpoint: "memory://local".to_owned(),
                bucket: "backend-bucket".to_owned(),
                prefix: Some("repo".to_owned()),
            },
            anchor: AnchorConfig::Memory,
            batching: BatchConfig {
                max_items: 64,
                max_delay: Duration::from_millis(10),
                max_pending_items: 64,
            },
            repository: RepositoryConfig {
                format: crate::RepositoryFormat::V2Preview,
                payload_segment_size: rs3_repository::DEFAULT_PAYLOAD_SEGMENT_SIZE,
                adaptive_payload_segment_size: true,
                decrypted_segment_cache_max_bytes:
                    rs3_repository::DEFAULT_DECRYPTED_SEGMENT_CACHE_MAX_BYTES,
                retention: None,
                allow_init: true,
            },
            provider_conformance: ProviderConformanceConfig::default(),
            repository_keys: RepositoryKeysConfig {
                repository_id: RepositoryId::new("test-repository")
                    .unwrap_or_else(|error| panic!("{error}")),
                repository_salt_hex:
                    "2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
                envelope_object_id: None,
                wrapping_key_id: "wrap-v1".to_owned(),
                wrapping_key_hex: SecretString::from(
                    "3333333333333333333333333333333333333333333333333333333333333333",
                ),
            },
            static_credentials: static_credentials.then(|| crate::StaticCredentials {
                access_key_id: "rs3-fixture-access-key".to_owned(),
                secret_access_key: SecretString::from("rs3-fixture-secret-key"),
            }),
        }
    }
}
