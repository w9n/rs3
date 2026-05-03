//! S3 protocol adapter surface.

mod adapter;
mod boundary;
mod mapping;
mod runtime;

pub use boundary::{GatewayS3Boundary, S3Hardening};
use thiserror::Error;

/// S3 boundary construction errors.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum S3BoundaryError {
    /// Static credentials are required before exposing the S3 service.
    #[error("static credentials are required to build the S3 boundary")]
    MissingStaticCredentials,
    /// The configured checkpoint anchor is not wired into the S3 adapter yet.
    #[error("configured checkpoint anchor mode is not supported by the S3 adapter yet")]
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

#[cfg(test)]
pub(super) mod test_support {
    use crate::{
        AnchorConfig, BackendConfig, BatchConfig, RepositoryConfig, RuntimeConfig, SecretString,
    };
    use rs3_types::PublicBucket;
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
            bind,
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
                payload_segment_size: 256 * 1024,
            },
            static_credentials: static_credentials.then(|| crate::StaticCredentials {
                access_key_id: "access".to_owned(),
                secret_access_key: SecretString::from("secret"),
            }),
        }
    }
}
