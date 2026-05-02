//! Authenticated S3 service construction and access control.

use super::S3BoundaryError;
use super::adapter::GatewayS3Service;
use crate::RuntimeConfig;
use rs3_types::PublicBucket;
use s3s::S3Result;
use s3s::access::{S3Access, S3AccessContext};
use s3s::auth::SimpleAuth;
use s3s::config::{S3Config, StaticConfigProvider};
use s3s::path::S3Path;
use s3s::service::{S3Service, S3ServiceBuilder};
use secrecy::ExposeSecret;
use std::sync::Arc;

/// Configured S3 protocol boundary.
///
/// This type is the public construction path for the S3 service. It installs
/// authentication and bucket-scoped access control together before exposing the
/// underlying `s3s` HTTP service.
#[derive(Clone)]
pub struct GatewayS3Boundary {
    config: RuntimeConfig,
    service: S3Service,
    hardening: S3Hardening,
}

impl GatewayS3Boundary {
    /// Builds the S3 boundary from validated runtime configuration.
    ///
    /// Static credentials are currently required because `s3s` only invokes
    /// access control when an authentication provider is configured.
    ///
    /// # Errors
    ///
    /// Returns [`S3BoundaryError::MissingStaticCredentials`] when no static
    /// credentials are configured for the process.
    pub fn build(config: RuntimeConfig) -> Result<Self, S3BoundaryError> {
        let credentials = config
            .static_credentials
            .clone()
            .ok_or(S3BoundaryError::MissingStaticCredentials)?;

        let adapter = GatewayS3Service::from_config(&config)?;
        let mut builder = S3ServiceBuilder::new(adapter);

        let s3_config = Arc::new(S3Config::default());
        builder.set_config(Arc::new(StaticConfigProvider::new(s3_config)));
        builder.set_auth(SimpleAuth::from_single(
            credentials.access_key_id,
            credentials.secret_access_key.expose_secret().to_owned(),
        ));
        builder.set_access(GatewayS3Access::new(config.public_bucket.clone()));

        Ok(Self {
            config,
            service: builder.build(),
            hardening: S3Hardening::required(),
        })
    }

    /// Returns the validated runtime configuration used by this boundary.
    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    /// Returns the client-visible bucket served by this boundary.
    pub fn public_bucket(&self) -> &PublicBucket {
        &self.config.public_bucket
    }

    /// Returns the configured `s3s` HTTP service.
    pub fn service(&self) -> &S3Service {
        &self.service
    }

    /// Consumes this boundary and returns the configured `s3s` HTTP service.
    pub fn into_service(self) -> S3Service {
        self.service
    }

    /// Returns the controls that still need to surround the S3 HTTP service.
    pub fn hardening(&self) -> S3Hardening {
        self.hardening
    }
}

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

#[derive(Clone, Debug)]
struct GatewayS3Access {
    public_bucket: PublicBucket,
}

impl GatewayS3Access {
    fn new(public_bucket: PublicBucket) -> Self {
        Self { public_bucket }
    }

    fn check_path(&self, path: &S3Path) -> S3Result<()> {
        let Some(bucket) = path.get_bucket_name() else {
            return Ok(());
        };

        if bucket == self.public_bucket.as_str() {
            Ok(())
        } else {
            Err(s3s::s3_error!(
                AccessDenied,
                "request targets a bucket that is not served by this gateway"
            ))
        }
    }
}

#[async_trait::async_trait]
impl S3Access for GatewayS3Access {
    async fn check(&self, cx: &mut S3AccessContext<'_>) -> S3Result<()> {
        if cx.credentials().is_none() {
            return Err(s3s::s3_error!(AccessDenied, "signature is required"));
        }

        self.check_path(cx.s3_path())
    }
}

#[cfg(test)]
mod tests {
    use super::{GatewayS3Access, GatewayS3Boundary};
    use crate::s3::S3BoundaryError;
    use crate::s3::test_support::runtime_config;
    use rs3_types::PublicBucket;
    use s3s::path::S3Path;

    #[test]
    fn boundary_requires_static_credentials() {
        let boundary = GatewayS3Boundary::build(runtime_config(false));

        assert!(matches!(
            boundary,
            Err(S3BoundaryError::MissingStaticCredentials)
        ));
    }

    #[test]
    fn boundary_builds_authenticated_s3_service() {
        let config = runtime_config(true);

        let boundary = match GatewayS3Boundary::build(config.clone()) {
            Ok(boundary) => boundary,
            Err(error) => panic!("{error}"),
        };

        assert_eq!(boundary.config(), &config);
        assert_eq!(boundary.public_bucket().as_str(), "client-bucket");
        assert!(boundary.hardening().operation_body_limits);
        assert!(boundary.hardening().backpressure);
        assert!(boundary.hardening().rate_limiting);
        assert!(boundary.hardening().request_tracing);
        assert!(boundary.hardening().authentication);
        let _service = boundary.service().clone();
    }

    #[test]
    fn access_scope_allows_only_configured_bucket() {
        let access = GatewayS3Access::new(
            PublicBucket::new("client-bucket").unwrap_or_else(|error| panic!("{error}")),
        );

        assert!(access.check_path(&S3Path::root()).is_ok());
        assert!(access.check_path(&S3Path::bucket("client-bucket")).is_ok());
        assert!(
            access
                .check_path(&S3Path::object("client-bucket", "object"))
                .is_ok()
        );
        assert!(access.check_path(&S3Path::bucket("other-bucket")).is_err());
        assert!(
            access
                .check_path(&S3Path::object("other-bucket", "object"))
                .is_err()
        );
    }
}
