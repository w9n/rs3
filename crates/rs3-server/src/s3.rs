//! S3 protocol adapter surface.

use crate::RuntimeConfig;
use rs3_types::PublicBucket;
use s3s::S3;

/// Thin `s3s` service implementation used as the gateway protocol boundary.
///
/// The HTTP service that wraps this adapter must install authentication,
/// operation-aware body limits, rate limiting, backpressure, and request
/// tracing before it is exposed to clients.
#[derive(Clone, Debug)]
pub struct GatewayS3Service {
    config: RuntimeConfig,
}

impl GatewayS3Service {
    /// Creates a protocol adapter from validated runtime configuration.
    pub fn new(config: RuntimeConfig) -> Self {
        Self { config }
    }

    /// Returns the validated runtime configuration used by this adapter.
    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    /// Returns the client-visible bucket served by this adapter.
    pub fn public_bucket(&self) -> &PublicBucket {
        &self.config.public_bucket
    }

    /// Returns the hardening requirements that must be enforced by the caller.
    pub fn hardening(&self) -> S3Hardening {
        S3Hardening::required()
    }
}

impl S3 for GatewayS3Service {}

/// Security and operability controls required around the S3 protocol adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct S3Hardening {
    /// Enforce body limits with awareness of the requested S3 operation.
    pub operation_body_limits: bool,
    /// Enforce admission control before accepting more client work.
    pub backpressure: bool,
    /// Enforce request rate limits at the HTTP/S3 boundary.
    pub rate_limiting: bool,
    /// Attach request traces and structured fields before repository calls.
    pub request_tracing: bool,
    /// Authenticate and authorize requests before deserializing operation input.
    pub authentication: bool,
}

impl S3Hardening {
    /// Returns the full set of required controls for an exposed S3 listener.
    pub const fn required() -> Self {
        Self {
            operation_body_limits: true,
            backpressure: true,
            rate_limiting: true,
            request_tracing: true,
            authentication: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{GatewayS3Service, S3Hardening};
    use crate::{AnchorConfig, BackendConfig, BatchConfig, RuntimeConfig};
    use rs3_types::PublicBucket;
    use std::time::Duration;

    fn runtime_config() -> RuntimeConfig {
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
                endpoint: "https://object.example".to_owned(),
                bucket: "backend-bucket".to_owned(),
                prefix: Some("repo".to_owned()),
            },
            anchor: AnchorConfig::Memory,
            batching: BatchConfig {
                max_items: 64,
                max_delay: Duration::from_millis(10),
                max_pending_items: 64,
            },
            static_credentials: None,
        }
    }

    #[test]
    fn service_keeps_validated_runtime_config() {
        let config = runtime_config();
        let service = GatewayS3Service::new(config.clone());

        assert_eq!(service.config(), &config);
        assert_eq!(service.public_bucket().as_str(), "client-bucket");
    }

    #[test]
    fn service_declares_required_boundary_hardening() {
        let service = GatewayS3Service::new(runtime_config());

        assert_eq!(service.hardening(), S3Hardening::required());
        assert!(service.hardening().operation_body_limits);
        assert!(service.hardening().backpressure);
        assert!(service.hardening().rate_limiting);
        assert!(service.hardening().request_tracing);
        assert!(service.hardening().authentication);
    }

    #[test]
    fn service_implements_s3_trait() {
        fn assert_s3<T: s3s::S3>() {}

        assert_s3::<GatewayS3Service>();
    }
}
