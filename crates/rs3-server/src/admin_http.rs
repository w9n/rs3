//! Authenticated HTTP listener for path-redacted gateway admin facts.

use crate::{AdminReportProfile, RuntimeConfig, admin_status_report};
use bytes::Bytes;
use http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, WWW_AUTHENTICATE};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Body;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnectionBuilder;
use hyper_util::server::graceful::GracefulShutdown;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use serde_json::json;
use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;
use tokio::net::TcpListener;

const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const ADMIN_REALM: &str = "Bearer realm=\"rs3-admin\"";

/// Redacted bearer token for the gateway admin listener.
#[derive(Clone)]
pub struct AdminBearerToken(SecretString);

impl AdminBearerToken {
    /// Creates a validated admin bearer token.
    ///
    /// # Errors
    ///
    /// Returns an error when the token is too short or contains whitespace or
    /// control characters.
    pub fn new(value: impl Into<String>) -> Result<Self, AdminHttpAuthError> {
        let value = value.into();
        if value.len() < 16 {
            return Err(AdminHttpAuthError::TokenTooShort);
        }
        if value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(AdminHttpAuthError::TokenHasInvalidCharacters);
        }

        Ok(Self(SecretString::from(value)))
    }

    fn matches_presented(&self, presented: &str) -> bool {
        constant_time_eq(self.0.expose_secret().as_bytes(), presented.as_bytes())
    }
}

impl fmt::Debug for AdminBearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdminBearerToken([redacted])")
    }
}

impl PartialEq for AdminBearerToken {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(
            self.0.expose_secret().as_bytes(),
            other.0.expose_secret().as_bytes(),
        )
    }
}

impl Eq for AdminBearerToken {}

/// Authentication mode for gateway admin HTTP routes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminHttpAuth {
    /// Bearer-token authentication.
    Bearer(AdminBearerToken),
}

impl AdminHttpAuth {
    /// Builds bearer-token admin authentication.
    pub fn bearer(token: AdminBearerToken) -> Self {
        Self::Bearer(token)
    }

    fn authorize(&self, headers: &HeaderMap) -> bool {
        match self {
            Self::Bearer(token) => presented_bearer_token(headers)
                .is_some_and(|presented| token.matches_presented(presented)),
        }
    }
}

/// Admin HTTP authentication configuration errors.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AdminHttpAuthError {
    /// Bearer token is too short.
    #[error("admin bearer token must be at least 16 bytes")]
    TokenTooShort,
    /// Bearer token contains whitespace or control characters.
    #[error("admin bearer token must not contain whitespace or control characters")]
    TokenHasInvalidCharacters,
}

/// Gateway admin listener configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminHttpConfig {
    /// Socket address for the admin listener.
    pub bind: SocketAddr,
    /// Authentication required for admin routes.
    pub auth: AdminHttpAuth,
    /// Status report profile returned by `/admin/status`.
    pub profile: AdminReportProfile,
}

impl AdminHttpConfig {
    /// Creates admin listener configuration.
    pub fn new(bind: SocketAddr, auth: AdminHttpAuth, profile: AdminReportProfile) -> Self {
        Self {
            bind,
            auth,
            profile,
        }
    }
}

/// Hyper-compatible service for gateway admin facts.
#[derive(Clone, Debug)]
pub struct AdminHttpService {
    config: RuntimeConfig,
    auth: AdminHttpAuth,
    profile: AdminReportProfile,
}

impl AdminHttpService {
    /// Creates an admin service from validated gateway runtime configuration.
    pub fn new(config: RuntimeConfig, auth: AdminHttpAuth, profile: AdminReportProfile) -> Self {
        Self {
            config,
            auth,
            profile,
        }
    }

    /// Handles one admin HTTP request.
    pub async fn handle<B>(&self, request: Request<B>) -> Response<Full<Bytes>>
    where
        B: Body,
    {
        let (parts, _body) = request.into_parts();

        if parts.method == Method::GET && parts.uri.path() == "/healthz" {
            return json_response(StatusCode::OK, json!({ "status": "ok" }));
        }

        if !self.auth.authorize(&parts.headers) {
            return unauthorized_response();
        }

        match (parts.method, parts.uri.path()) {
            (Method::GET, "/admin/status") => {
                let report = admin_status_report(&self.config, self.profile).await;
                json_response(StatusCode::OK, report)
            }
            (Method::GET, _) => json_response(
                StatusCode::NOT_FOUND,
                json!({ "error": { "code": "not-found", "message": "admin route not found" } }),
            ),
            _ => json_response(
                StatusCode::METHOD_NOT_ALLOWED,
                json!({ "error": { "code": "method-not-allowed", "message": "admin route method is not allowed" } }),
            ),
        }
    }
}

/// Bound gateway admin HTTP server.
pub struct AdminHttpServer {
    service: AdminHttpService,
    listener: TcpListener,
    local_addr: SocketAddr,
}

impl AdminHttpServer {
    /// Binds the gateway admin listener.
    ///
    /// # Errors
    ///
    /// Returns an error when the listener cannot be bound or its local address
    /// cannot be read.
    pub async fn bind(
        config: RuntimeConfig,
        admin_config: AdminHttpConfig,
    ) -> Result<Self, AdminHttpServerError> {
        let listener = TcpListener::bind(admin_config.bind)
            .await
            .map_err(|source| AdminHttpServerError::Bind {
                bind: admin_config.bind,
                source,
            })?;
        let local_addr = listener
            .local_addr()
            .map_err(AdminHttpServerError::LocalAddr)?;
        let service = AdminHttpService::new(config, admin_config.auth, admin_config.profile);

        Ok(Self {
            service,
            listener,
            local_addr,
        })
    }

    /// Returns the address actually bound by the listener.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Serves admin connections until the provided shutdown future resolves.
    ///
    /// # Errors
    ///
    /// Returns an error when accepting a connection fails or graceful shutdown
    /// does not finish before the timeout.
    pub async fn run_until_shutdown<F>(self, shutdown: F) -> Result<(), AdminHttpServerError>
    where
        F: Future<Output = ()>,
    {
        let Self {
            service, listener, ..
        } = self;
        let connection_builder = ConnectionBuilder::new(TokioExecutor::new());
        let graceful = GracefulShutdown::new();
        let mut shutdown = std::pin::pin!(shutdown);

        loop {
            let (stream, remote_addr) = tokio::select! {
                result = listener.accept() => {
                    result.map_err(AdminHttpServerError::Accept)?
                }
                () = shutdown.as_mut() => {
                    break;
                }
            };

            let service = service.clone();
            let connection = connection_builder.serve_connection(
                TokioIo::new(stream),
                service_fn(move |request| {
                    let service = service.clone();
                    async move { Ok::<_, Infallible>(service.handle(request).await) }
                }),
            );
            let connection = graceful.watch(connection.into_owned());

            tokio::spawn(async move {
                if let Err(error) = connection.await {
                    tracing::debug!(
                        %remote_addr,
                        %error,
                        "admin HTTP connection ended with error",
                    );
                }
            });
        }

        tokio::select! {
            () = graceful.shutdown() => Ok(()),
            () = tokio::time::sleep(GRACEFUL_SHUTDOWN_TIMEOUT) => {
                Err(AdminHttpServerError::ShutdownTimeout {
                    timeout: GRACEFUL_SHUTDOWN_TIMEOUT,
                })
            }
        }
    }
}

/// Admin server binding and serving errors.
#[derive(Debug, Error)]
pub enum AdminHttpServerError {
    /// TCP listener bind failed.
    #[error("failed to bind admin listener at {bind}: {source}")]
    Bind {
        /// Requested bind address.
        bind: SocketAddr,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Reading the listener's local address failed.
    #[error("failed to read admin listener address: {0}")]
    LocalAddr(#[source] std::io::Error),
    /// Accepting a connection failed.
    #[error("failed to accept admin connection: {0}")]
    Accept(#[source] std::io::Error),
    /// Graceful shutdown exceeded the configured timeout.
    #[error("admin server shutdown did not finish within {timeout:?}")]
    ShutdownTimeout {
        /// Graceful shutdown timeout.
        timeout: Duration,
    },
}

fn presented_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?;
    let value = value.to_str().ok()?;
    value.strip_prefix("Bearer ")
}

fn unauthorized_response() -> Response<Full<Bytes>> {
    let mut response = json_response(
        StatusCode::UNAUTHORIZED,
        json!({
            "error": {
                "code": "unauthorized",
                "message": "valid bearer token required",
            },
        }),
    );
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static(ADMIN_REALM));
    response
}

fn json_response(body_status: StatusCode, body: impl Serialize) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&body).unwrap_or_else(|_error| {
        br#"{"error":{"code":"serialization-failed","message":"failed to serialize response"}}"#
            .to_vec()
    });
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = body_status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    let max_len = left.len().max(right.len());

    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(left_byte ^ right_byte);
    }

    diff == 0
}

#[cfg(test)]
mod tests {
    use super::{AdminBearerToken, AdminHttpAuth, AdminHttpService};
    use crate::{
        AdminReportProfile, AnchorConfig, BackendConfig, BatchConfig, GatewayMode, HardeningConfig,
        MetricsConfig, RepositoryConfig, RepositoryFormat, RepositoryKeysConfig, RuntimeConfig,
        SecretString, StaticCredentials,
    };
    use bytes::Bytes;
    use http::header::AUTHORIZATION;
    use http::{Request, StatusCode};
    use http_body_util::{BodyExt, Full};
    use rs3_types::{BackendObjectId, PublicBucket, RepositoryId};
    use std::time::Duration;

    fn runtime_config() -> RuntimeConfig {
        let bind = match "127.0.0.1:0".parse() {
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
                prefix: Some("repo-prefix".to_owned()),
            },
            anchor: AnchorConfig::Memory,
            batching: BatchConfig {
                max_items: 64,
                max_delay: Duration::from_millis(10),
                max_pending_items: 64,
            },
            repository: RepositoryConfig {
                format: RepositoryFormat::V2Preview,
                payload_segment_size: rs3_repository::DEFAULT_PAYLOAD_SEGMENT_SIZE,
                adaptive_payload_segment_size: true,
                decrypted_segment_cache_max_bytes:
                    rs3_repository::DEFAULT_DECRYPTED_SEGMENT_CACHE_MAX_BYTES,
                retention: None,
            },
            repository_keys: RepositoryKeysConfig {
                repository_id: RepositoryId::new("test-repository")
                    .unwrap_or_else(|error| panic!("{error}")),
                repository_salt_hex:
                    "2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
                envelope_object_id: Some(
                    BackendObjectId::new("keyrings/test-envelope.json")
                        .unwrap_or_else(|error| panic!("{error}")),
                ),
                wrapping_key_id: "wrap-v1".to_owned(),
                wrapping_key_hex: SecretString::from(
                    "3333333333333333333333333333333333333333333333333333333333333333",
                ),
            },
            static_credentials: Some(StaticCredentials {
                access_key_id: "backup-client".to_owned(),
                secret_access_key: SecretString::from("client-secret"),
            }),
        }
    }

    fn service() -> AdminHttpService {
        let token =
            AdminBearerToken::new("admin-token-12345").unwrap_or_else(|error| panic!("{error}"));
        AdminHttpService::new(
            runtime_config(),
            AdminHttpAuth::bearer(token),
            AdminReportProfile::Production,
        )
    }

    async fn body_string(response: http::Response<Full<Bytes>>) -> String {
        let status = response.status();
        let bytes = match response.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(error) => panic!("{error}"),
        };
        let body = String::from_utf8_lossy(&bytes).into_owned();
        assert!(
            !body.is_empty() || status == StatusCode::NO_CONTENT,
            "empty body for {status}"
        );
        body
    }

    #[tokio::test]
    async fn admin_status_requires_bearer() {
        let response = service()
            .handle(
                Request::builder()
                    .uri("/admin/status")
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_status_returns_path_redacted_report() {
        let response = service()
            .handle(
                Request::builder()
                    .uri("/admin/status")
                    .header(AUTHORIZATION, "Bearer admin-token-12345")
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_string(response).await;
        assert!(body.contains("rs3.admin-status.preview.v1"));
        assert!(body.contains("read-write"));
        assert!(!body.contains("backend-bucket"));
        assert!(!body.contains("repo-prefix"));
        assert!(!body.contains("test-repository"));
        assert!(!body.contains("client-secret"));
    }

    #[tokio::test]
    async fn health_route_is_unauthenticated() {
        let response = service()
            .handle(
                Request::builder()
                    .uri("/healthz")
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .await;

        assert_eq!(response.status(), StatusCode::OK);
    }
}
