use crate::admin_client::{GatewayAdminClient, GatewayAdminClientError};
use crate::ui_assets::ui_asset_response;
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
use serde_json::{Value, json};
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
const MAX_CONSOLE_CONNECTION_LIFETIME: Duration = Duration::from_secs(60);
const MAX_CONSOLE_CONNECTIONS: usize = 64;
const CONSOLE_REALM: &str = "Bearer realm=\"rs3-console\"";

/// Redacted bearer token for console API routes.
#[derive(Clone)]
pub struct ConsoleBearerToken(SecretString);

impl ConsoleBearerToken {
    /// Creates a validated console bearer token.
    ///
    /// # Errors
    ///
    /// Returns an error when the token is too short or contains whitespace or
    /// control characters.
    pub fn new(value: impl Into<String>) -> Result<Self, ConsoleHttpAuthError> {
        let value = value.into();
        if value.len() < 16 {
            return Err(ConsoleHttpAuthError::TokenTooShort);
        }
        if value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(ConsoleHttpAuthError::TokenHasInvalidCharacters);
        }
        Ok(Self(SecretString::from(value)))
    }

    fn matches_presented(&self, presented: &str) -> bool {
        ct_eq(self.0.expose_secret().as_bytes(), presented.as_bytes())
    }
}

impl fmt::Debug for ConsoleBearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConsoleBearerToken([redacted])")
    }
}

impl PartialEq for ConsoleBearerToken {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(
            self.0.expose_secret().as_bytes(),
            other.0.expose_secret().as_bytes(),
        )
    }
}

impl Eq for ConsoleBearerToken {}

/// Authentication mode for console API routes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsoleHttpAuth {
    /// Bearer-token authentication.
    Bearer(ConsoleBearerToken),
}

impl ConsoleHttpAuth {
    /// Builds bearer-token console authentication.
    pub fn bearer(token: ConsoleBearerToken) -> Self {
        Self::Bearer(token)
    }

    fn authorize(&self, headers: &HeaderMap) -> bool {
        match self {
            Self::Bearer(token) => presented_bearer_token(headers)
                .is_some_and(|presented| token.matches_presented(presented)),
        }
    }
}

/// Console authentication configuration errors.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ConsoleHttpAuthError {
    /// Bearer token is too short.
    #[error("console bearer token must be at least 16 bytes")]
    TokenTooShort,
    /// Bearer token contains whitespace or control characters.
    #[error("console bearer token must not contain whitespace or control characters")]
    TokenHasInvalidCharacters,
}

/// Hyper-compatible read-only console service.
#[derive(Clone, Debug)]
pub struct ConsoleHttpService {
    admin_client: GatewayAdminClient,
    auth: ConsoleHttpAuth,
}

impl ConsoleHttpService {
    /// Creates a console service.
    pub fn new(admin_client: GatewayAdminClient, auth: ConsoleHttpAuth) -> Self {
        Self { admin_client, auth }
    }

    /// Handles one console HTTP request.
    pub async fn handle<B>(&self, request: Request<B>) -> Response<Full<Bytes>>
    where
        B: Body,
    {
        let (parts, _body) = request.into_parts();
        let path = parts.uri.path();

        if parts.method == Method::GET && path == "/healthz" {
            return json_response(StatusCode::OK, json!({ "status": "ok" }));
        }
        if let Some(response) = ui_asset_response(&parts.method, path) {
            return response;
        }
        if path == "/api/status" || path == "/api/posture" {
            if !self.auth.authorize(&parts.headers) {
                return unauthorized_response();
            }
            if parts.method != Method::GET {
                return json_response(
                    StatusCode::METHOD_NOT_ALLOWED,
                    json!({
                        "error": {
                            "code": "method-not-allowed",
                            "message": "console route method is not allowed",
                        },
                    }),
                );
            }
            if path == "/api/posture" {
                return self.posture_response().await;
            }
            return self.status_response().await;
        }
        json_response(
            StatusCode::NOT_FOUND,
            json!({ "error": { "code": "not-found", "message": "console route not found" } }),
        )
    }

    async fn status_response(&self) -> Response<Full<Bytes>> {
        match self.admin_client.fetch_status().await {
            Ok(status) => json_response(StatusCode::OK, status),
            Err(error) => gateway_error_response(&error),
        }
    }

    async fn posture_response(&self) -> Response<Full<Bytes>> {
        match self.admin_client.fetch_posture().await {
            Ok(posture) => json_response(StatusCode::OK, posture),
            Err(error) => gateway_error_response(&error),
        }
    }
}

/// Bound console HTTP server.
pub struct ConsoleHttpServer {
    service: ConsoleHttpService,
    listener: TcpListener,
    local_addr: SocketAddr,
}

impl ConsoleHttpServer {
    /// Binds the console listener.
    ///
    /// # Errors
    ///
    /// Returns an error when the listener cannot be bound or its local address
    /// cannot be read.
    pub async fn bind_service(
        bind: SocketAddr,
        service: ConsoleHttpService,
    ) -> Result<Self, ConsoleHttpServerError> {
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|source| ConsoleHttpServerError::Bind { bind, source })?;
        let local_addr = listener
            .local_addr()
            .map_err(ConsoleHttpServerError::LocalAddr)?;

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

    /// Serves console requests until the provided shutdown future resolves.
    ///
    /// # Errors
    ///
    /// Returns an error when accepting a connection fails or graceful shutdown
    /// does not finish before the timeout.
    pub async fn run_until_shutdown<F>(self, shutdown: F) -> Result<(), ConsoleHttpServerError>
    where
        F: Future<Output = ()>,
    {
        let Self {
            service, listener, ..
        } = self;
        let graceful = GracefulShutdown::new();
        let mut shutdown = std::pin::pin!(shutdown);
        let connection_slots = Arc::new(Semaphore::new(MAX_CONSOLE_CONNECTIONS));

        loop {
            let (stream, remote_addr) = tokio::select! {
                result = listener.accept() => {
                    result.map_err(ConsoleHttpServerError::Accept)?
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
                        "console HTTP connection rejected by connection limit",
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
                match tokio::time::timeout(MAX_CONSOLE_CONNECTION_LIFETIME, connection).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::debug!(
                            %remote_addr,
                            %error,
                            "console HTTP connection ended with error",
                        );
                    }
                    Err(_elapsed) => {
                        tracing::debug!(
                            %remote_addr,
                            timeout_seconds = MAX_CONSOLE_CONNECTION_LIFETIME.as_secs(),
                            "console HTTP connection exceeded maximum lifetime",
                        );
                    }
                }
            });
        }

        tokio::select! {
            () = graceful.shutdown() => Ok(()),
            () = tokio::time::sleep(GRACEFUL_SHUTDOWN_TIMEOUT) => {
                Err(ConsoleHttpServerError::ShutdownTimeout {
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
                "console HTTP connection ended before request bytes arrived",
            );
            false
        }
        Err(_elapsed) => {
            tracing::debug!(
                %remote_addr,
                timeout_ms = HTTP_HEADER_READ_TIMEOUT.as_millis(),
                "console HTTP connection closed after idle header timeout",
            );
            false
        }
    }
}

/// Console server binding and serving errors.
#[derive(Debug, Error)]
pub enum ConsoleHttpServerError {
    /// TCP listener bind failed.
    #[error("failed to bind console listener at {bind}: {source}")]
    Bind {
        /// Requested bind address.
        bind: SocketAddr,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Reading the listener's local address failed.
    #[error("failed to read console listener address: {0}")]
    LocalAddr(#[source] std::io::Error),
    /// Accepting a connection failed.
    #[error("failed to accept console connection: {0}")]
    Accept(#[source] std::io::Error),
    /// Graceful shutdown exceeded the configured timeout.
    #[error("console server shutdown did not finish within {timeout:?}")]
    ShutdownTimeout {
        /// Graceful shutdown timeout.
        timeout: Duration,
    },
}

fn gateway_error_response(error: &GatewayAdminClientError) -> Response<Full<Bytes>> {
    let (status, code, message) = match error {
        GatewayAdminClientError::GatewayStatus(StatusCode::UNAUTHORIZED)
        | GatewayAdminClientError::GatewayStatus(StatusCode::FORBIDDEN) => (
            StatusCode::BAD_GATEWAY,
            "gateway-admin-rejected",
            "gateway admin listener rejected the console request",
        ),
        GatewayAdminClientError::GatewayStatus(_) => (
            StatusCode::BAD_GATEWAY,
            "gateway-admin-unavailable",
            "gateway admin listener returned an unexpected status",
        ),
        GatewayAdminClientError::InvalidSchema | GatewayAdminClientError::Json(_) => (
            StatusCode::BAD_GATEWAY,
            "gateway-admin-invalid",
            "gateway admin listener returned an invalid status report",
        ),
        GatewayAdminClientError::ResponseTooLarge { .. } => (
            StatusCode::BAD_GATEWAY,
            "gateway-admin-too-large",
            "gateway admin listener returned too much data",
        ),
        _ => (
            StatusCode::BAD_GATEWAY,
            "gateway-admin-unavailable",
            "gateway admin listener could not be reached",
        ),
    };
    tracing::debug!(%error, code, "gateway admin status fetch failed");
    json_response(
        status,
        json!({
            "error": {
                "code": code,
                "message": message,
            },
        }),
    )
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
                "message": "valid console bearer token required",
            },
        }),
    );
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static(CONSOLE_REALM));
    response
}

fn json_response(body_status: StatusCode, body: Value) -> Response<Full<Bytes>> {
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
    use super::{ConsoleBearerToken, ConsoleHttpAuth, ConsoleHttpServer, ConsoleHttpService};
    use crate::{
        GatewayAdminBearerToken, GatewayAdminClient, GatewayAdminClientConfig, GatewayAdminEndpoint,
    };
    use bytes::Bytes;
    use http::header::AUTHORIZATION;
    use http::{Request, StatusCode};
    use http_body_util::{BodyExt, Full};
    use serde_json::Value;
    use std::io::ErrorKind;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn auth() -> ConsoleHttpAuth {
        ConsoleHttpAuth::bearer(
            ConsoleBearerToken::new("console-token-12345")
                .unwrap_or_else(|error| panic!("{error}")),
        )
    }

    fn unused_admin_client() -> GatewayAdminClient {
        let endpoint = GatewayAdminEndpoint::parse("http://127.0.0.1:9")
            .unwrap_or_else(|error| panic!("{error}"));
        let token = GatewayAdminBearerToken::new("gateway-admin-token-12345")
            .unwrap_or_else(|error| panic!("{error}"));
        GatewayAdminClient::new(GatewayAdminClientConfig::new(endpoint, token))
    }

    async fn assert_peer_closes(stream: &mut TcpStream) {
        let mut buffer = [0_u8; 1];
        match tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut buffer))
            .await
        {
            Ok(Ok(0)) => {}
            Ok(Err(error)) if error.kind() == ErrorKind::ConnectionReset => {}
            Ok(Ok(read)) => panic!("idle connection produced {read} bytes before closing"),
            Ok(Err(error)) => panic!("{error}"),
            Err(_elapsed) => panic!("idle connection did not close after header timeout"),
        }
    }

    async fn service() -> (ConsoleHttpService, tokio::task::JoinHandle<String>) {
        service_with_gateway_body(
            r#"{"schema":"rs3.admin-status.preview.v1","runtime":{"gateway_mode":"read-write"},"security":{"secrets_exposed":false}}"#,
        )
        .await
    }

    async fn service_with_gateway_body(
        body: &'static str,
    ) -> (ConsoleHttpService, tokio::task::JoinHandle<String>) {
        let (addr, request) = MockAdmin::start(StatusCode::OK, body).await;
        let endpoint = GatewayAdminEndpoint::parse(&format!("http://{addr}"))
            .unwrap_or_else(|error| panic!("{error}"));
        let token = GatewayAdminBearerToken::new("gateway-admin-token-12345")
            .unwrap_or_else(|error| panic!("{error}"));
        let client = GatewayAdminClient::new(GatewayAdminClientConfig::new(endpoint, token));

        (ConsoleHttpService::new(client, auth()), request)
    }

    async fn body_json(response: http::Response<Full<Bytes>>) -> Value {
        let bytes = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("{error}"))
    }

    #[tokio::test]
    async fn api_status_requires_console_bearer() {
        let (service, _request) = service().await;
        let response = service
            .handle(
                Request::builder()
                    .uri("/api/status")
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn api_status_fetches_gateway_admin_status() {
        let (service, request) = service().await;
        let response = service
            .handle(
                Request::builder()
                    .uri("/api/status")
                    .header(AUTHORIZATION, "Bearer console-token-12345")
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["schema"], "rs3.admin-status.preview.v1");
        assert_eq!(body["runtime"]["gateway_mode"], "read-write");
        let request = request.await.unwrap_or_else(|error| panic!("{error}"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer gateway-admin-token-12345")
        );
    }

    #[tokio::test]
    async fn api_posture_fetches_gateway_admin_posture() {
        let (service, request) = service_with_gateway_body(
            r#"{"schema":"rs3.admin-posture.preview.v1","runtime":{"gateway_mode":"read-write"}}"#,
        )
        .await;
        let response = service
            .handle(
                Request::builder()
                    .uri("/api/posture")
                    .header(AUTHORIZATION, "Bearer console-token-12345")
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["schema"], "rs3.admin-posture.preview.v1");
        let request = request.await.unwrap_or_else(|error| panic!("{error}"));
        assert!(request.contains("GET /admin/posture HTTP/1.1"));
    }

    #[tokio::test]
    async fn health_and_ui_are_served_without_console_bearer() {
        let (service, _request) = service().await;
        let health = service
            .handle(
                Request::builder()
                    .uri("/healthz")
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .await;
        assert_eq!(health.status(), StatusCode::OK);

        let ui = service
            .handle(
                Request::builder()
                    .uri("/")
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .await;
        assert_eq!(ui.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn idle_console_connection_is_closed_after_header_timeout() {
        let server = ConsoleHttpServer::bind_service(
            "127.0.0.1:0"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
            ConsoleHttpService::new(unused_admin_client(), auth()),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
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

    struct MockAdmin;

    impl MockAdmin {
        async fn start(
            status: StatusCode,
            body: &'static str,
        ) -> (std::net::SocketAddr, tokio::task::JoinHandle<String>) {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let addr = listener
                .local_addr()
                .unwrap_or_else(|error| panic!("{error}"));
            let handle = tokio::spawn(async move {
                let (mut stream, _peer) = listener
                    .accept()
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                loop {
                    let read = stream
                        .read(&mut buffer)
                        .await
                        .unwrap_or_else(|error| panic!("{error}"));
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let response = format!(
                    "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status.as_u16(),
                    status.canonical_reason().unwrap_or(""),
                    body.len(),
                    body
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
                String::from_utf8_lossy(&request).into_owned()
            });
            (addr, handle)
        }
    }
}
