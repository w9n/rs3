//! Authenticated HTTP listener for path-redacted gateway admin facts.

use crate::{
    AdminReportProfile, AdminRuntimeFacts, AdminRuntimeFactsSource, RuntimeConfig,
    admin_posture_report_with_runtime_facts, admin_status_report_with_runtime_facts,
};
use bytes::Bytes;
use http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, WWW_AUTHENTICATE};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Body;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as ConnectionBuilder;
use hyper_util::server::graceful::GracefulShutdown;
use rs3_crypto::ct_eq;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use serde_json::json;
use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(not(test))]
const HTTP_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
const HTTP_HEADER_READ_TIMEOUT: Duration = Duration::from_millis(20);
const MAX_ADMIN_CONNECTION_LIFETIME: Duration = Duration::from_secs(60);
const MAX_ADMIN_CONNECTIONS: usize = 64;
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
        ct_eq(self.0.expose_secret().as_bytes(), presented.as_bytes())
    }
}

impl fmt::Debug for AdminBearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdminBearerToken([redacted])")
    }
}

impl PartialEq for AdminBearerToken {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(
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
#[derive(Clone)]
pub struct AdminHttpService {
    config: RuntimeConfig,
    auth: AdminHttpAuth,
    profile: AdminReportProfile,
    runtime_facts: Option<Arc<dyn AdminRuntimeFactsSource>>,
}

impl AdminHttpService {
    /// Creates an admin service from validated gateway runtime configuration.
    pub fn new(config: RuntimeConfig, auth: AdminHttpAuth, profile: AdminReportProfile) -> Self {
        Self {
            config,
            auth,
            profile,
            runtime_facts: None,
        }
    }

    /// Creates an admin service with live runtime facts attached to reports.
    pub fn new_with_runtime_facts(
        config: RuntimeConfig,
        auth: AdminHttpAuth,
        profile: AdminReportProfile,
        runtime_facts: Arc<dyn AdminRuntimeFactsSource>,
    ) -> Self {
        Self {
            config,
            auth,
            profile,
            runtime_facts: Some(runtime_facts),
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
            (Method::GET, "/admin/posture") => {
                let runtime_facts = self.runtime_facts();
                let report = admin_posture_report_with_runtime_facts(
                    &self.config,
                    self.profile,
                    &runtime_facts,
                );
                json_response(StatusCode::OK, report)
            }
            (Method::GET, "/admin/status") => {
                let runtime_facts = self.runtime_facts();
                let report = admin_status_report_with_runtime_facts(
                    &self.config,
                    self.profile,
                    &runtime_facts,
                )
                .await;
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

    fn runtime_facts(&self) -> AdminRuntimeFacts {
        self.runtime_facts
            .as_ref()
            .map_or_else(AdminRuntimeFacts::default, |source| source.snapshot())
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
        Self::bind_inner(config, admin_config, None).await
    }

    /// Binds the gateway admin listener with live runtime facts attached to reports.
    ///
    /// # Errors
    ///
    /// Returns an error when the listener cannot be bound or its local address
    /// cannot be read.
    pub async fn bind_with_runtime_facts(
        config: RuntimeConfig,
        admin_config: AdminHttpConfig,
        runtime_facts: Arc<dyn AdminRuntimeFactsSource>,
    ) -> Result<Self, AdminHttpServerError> {
        Self::bind_inner(config, admin_config, Some(runtime_facts)).await
    }

    async fn bind_inner(
        config: RuntimeConfig,
        admin_config: AdminHttpConfig,
        runtime_facts: Option<Arc<dyn AdminRuntimeFactsSource>>,
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
        let service = match runtime_facts {
            Some(runtime_facts) => AdminHttpService::new_with_runtime_facts(
                config,
                admin_config.auth,
                admin_config.profile,
                runtime_facts,
            ),
            None => AdminHttpService::new(config, admin_config.auth, admin_config.profile),
        };

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
        let graceful = GracefulShutdown::new();
        let mut shutdown = std::pin::pin!(shutdown);
        let connection_slots = Arc::new(Semaphore::new(MAX_ADMIN_CONNECTIONS));

        loop {
            let (stream, remote_addr) = tokio::select! {
                result = listener.accept() => {
                    result.map_err(AdminHttpServerError::Accept)?
                }
                () = shutdown.as_mut() => {
                    break;
                }
            };

            let connection_permit = match connection_slots.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_error) => {
                    tracing::debug!(
                        %remote_addr,
                        "admin HTTP connection rejected by connection limit",
                    );
                    continue;
                }
            };
            let service = service.clone();
            let connection_watcher = graceful.watcher();

            tokio::spawn(async move {
                let _connection_permit = connection_permit;
                if !wait_for_first_client_byte(&stream, remote_addr).await {
                    return;
                }
                let mut connection_builder = ConnectionBuilder::new(TokioExecutor::new());
                connection_builder
                    .http1()
                    .timer(TokioTimer::new())
                    .header_read_timeout(HTTP_HEADER_READ_TIMEOUT);
                let connection = connection_builder.serve_connection(
                    TokioIo::new(stream),
                    service_fn(move |request| {
                        let service = service.clone();
                        async move { Ok::<_, Infallible>(service.handle(request).await) }
                    }),
                );
                let connection = connection_watcher.watch(connection.into_owned());
                match tokio::time::timeout(MAX_ADMIN_CONNECTION_LIFETIME, connection).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::debug!(
                            %remote_addr,
                            %error,
                            "admin HTTP connection ended with error",
                        );
                    }
                    Err(_elapsed) => {
                        tracing::debug!(
                            %remote_addr,
                            timeout_seconds = MAX_ADMIN_CONNECTION_LIFETIME.as_secs(),
                            "admin HTTP connection exceeded maximum lifetime",
                        );
                    }
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

async fn wait_for_first_client_byte(stream: &TcpStream, remote_addr: SocketAddr) -> bool {
    let mut first_byte = [0_u8; 1];
    match tokio::time::timeout(HTTP_HEADER_READ_TIMEOUT, stream.peek(&mut first_byte)).await {
        Ok(Ok(0)) => false,
        Ok(Ok(_read)) => true,
        Ok(Err(error)) => {
            tracing::debug!(
                %remote_addr,
                %error,
                "admin HTTP connection ended before request bytes arrived",
            );
            false
        }
        Err(_elapsed) => {
            tracing::debug!(
                %remote_addr,
                timeout_ms = HTTP_HEADER_READ_TIMEOUT.as_millis(),
                "admin HTTP connection closed after idle header timeout",
            );
            false
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

#[cfg(test)]
mod tests {
    use super::{
        AdminBearerToken, AdminHttpAuth, AdminHttpConfig, AdminHttpServer, AdminHttpService,
    };
    use crate::{
        AdminReportProfile, AnchorConfig, BackendConfig, BatchConfig, GatewayMode, HardeningConfig,
        MetricsConfig, ProviderConformanceConfig, RecoveryConfig, RepositoryConfig,
        RepositoryFormat, RepositoryKeysConfig, RuntimeConfig, StaticCredentials,
        WriterGuardConfig,
    };
    use bytes::Bytes;
    use http::header::AUTHORIZATION;
    use http::{Request, StatusCode};
    use http_body_util::{BodyExt, Full};
    use rs3_types::{BackendObjectId, PublicBucket, RepositoryId};
    use secrecy::SecretString;
    use std::io::ErrorKind;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;

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
            writer_guard: WriterGuardConfig::Off,
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
                allow_init: true,
            },
            provider_conformance: ProviderConformanceConfig::default(),
            recovery: RecoveryConfig::default(),
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

    fn admin_token() -> AdminBearerToken {
        AdminBearerToken::new("admin-token-12345").unwrap_or_else(|error| panic!("{error}"))
    }

    fn bind_addr() -> std::net::SocketAddr {
        "127.0.0.1:0"
            .parse()
            .unwrap_or_else(|error| panic!("{error}"))
    }

    async fn assert_peer_closes(stream: &mut TcpStream) {
        let mut buffer = [0_u8; 1];
        match tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buffer)).await {
            Ok(Ok(0)) => {}
            Ok(Err(error)) if error.kind() == ErrorKind::ConnectionReset => {}
            Ok(Ok(read)) => panic!("idle connection produced {read} bytes before closing"),
            Ok(Err(error)) => panic!("{error}"),
            Err(_elapsed) => panic!("idle connection did not close after header timeout"),
        }
    }

    async fn admin_server() -> AdminHttpServer {
        let admin_config = AdminHttpConfig::new(
            bind_addr(),
            AdminHttpAuth::bearer(admin_token()),
            AdminReportProfile::Production,
        );
        AdminHttpServer::bind(runtime_config(), admin_config)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
    }

    fn service() -> AdminHttpService {
        AdminHttpService::new(
            runtime_config(),
            AdminHttpAuth::bearer(admin_token()),
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
    async fn admin_posture_returns_path_redacted_cheap_report() {
        let response = service()
            .handle(
                Request::builder()
                    .uri("/admin/posture")
                    .header(AUTHORIZATION, "Bearer admin-token-12345")
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_string(response).await;
        assert!(body.contains("rs3.admin-posture.preview.v1"));
        assert!(!body.contains("\"restore\""));
        assert!(!body.contains("\"maintenance\""));
        assert!(!body.contains("backend-bucket"));
        assert!(!body.contains("repo-prefix"));
        assert!(!body.contains("test-repository"));
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

    #[tokio::test]
    async fn idle_admin_connection_is_closed_after_header_timeout() {
        let server = admin_server().await;
        let addr = server.local_addr();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(server.run_until_shutdown(async move {
            let _ = shutdown_rx.await;
        }));

        let mut stream = TcpStream::connect(addr)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_peer_closes(&mut stream).await;

        let _ = shutdown_tx.send(());
        handle
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|error| panic!("{error}"));
    }
}
