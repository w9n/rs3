use bytes::Bytes;
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH};
use http::{HeaderValue, Request, StatusCode, Uri};
use http_body_util::{BodyExt, Empty};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rs3_crypto::ct_eq;
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;
use std::fmt;
use std::time::Duration;
use thiserror::Error;

const ADMIN_STATUS_SCHEMA: &str = "rs3.admin-status.preview.v1";
const ADMIN_POSTURE_SCHEMA: &str = "rs3.admin-posture.preview.v1";
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_MAX_RESPONSE_BYTES: usize = 512 * 1024;

/// Parsed gateway admin endpoint for the single-gateway console.
#[derive(Clone, PartialEq, Eq)]
pub struct GatewayAdminEndpoint {
    scheme: GatewayAdminScheme,
    host: String,
    port: u16,
}

impl GatewayAdminEndpoint {
    /// Parses a gateway admin endpoint.
    ///
    /// `http://` and `https://` origins are accepted. Plain HTTP is intended
    /// only for cluster-local or otherwise isolated console-to-gateway hops.
    ///
    /// # Errors
    ///
    /// Returns an error when the endpoint is malformed, is not `http://` or
    /// `https://`, uses credentials, or includes a path/query.
    pub fn parse(value: &str) -> Result<Self, GatewayAdminEndpointError> {
        let uri: Uri = value
            .parse()
            .map_err(|_source| GatewayAdminEndpointError::InvalidUri)?;
        let scheme = match uri.scheme_str() {
            Some("http") => GatewayAdminScheme::Http,
            Some("https") => GatewayAdminScheme::Https,
            _ => return Err(GatewayAdminEndpointError::UnsupportedScheme),
        };
        let authority = uri
            .authority()
            .ok_or(GatewayAdminEndpointError::MissingAuthority)?;
        if authority.as_str().contains('@') {
            return Err(GatewayAdminEndpointError::CredentialsNotAllowed);
        }
        let path = uri.path();
        if path != "/" || uri.query().is_some() {
            return Err(GatewayAdminEndpointError::PathNotAllowed);
        }
        let host = uri
            .host()
            .ok_or(GatewayAdminEndpointError::MissingAuthority)?
            .to_owned();
        let port = uri.port_u16().unwrap_or_else(|| scheme.default_port());

        Ok(Self { scheme, host, port })
    }

    fn status_uri(&self) -> Result<Uri, GatewayAdminClientError> {
        self.admin_uri("/admin/status")
    }

    fn posture_uri(&self) -> Result<Uri, GatewayAdminClientError> {
        self.admin_uri("/admin/posture")
    }

    fn admin_uri(&self, path: &'static str) -> Result<Uri, GatewayAdminClientError> {
        Uri::builder()
            .scheme(self.scheme.as_str())
            .authority(self.authority())
            .path_and_query(path)
            .build()
            .map_err(GatewayAdminClientError::RequestBuild)
    }

    fn authority(&self) -> String {
        format!("{}:{}", self.authority_host(), self.port)
    }

    fn authority_host(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        }
    }
}

impl fmt::Debug for GatewayAdminEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GatewayAdminEndpoint([redacted])")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GatewayAdminScheme {
    Http,
    Https,
}

impl GatewayAdminScheme {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    const fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

/// Gateway admin endpoint parsing errors.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum GatewayAdminEndpointError {
    /// Endpoint URI is malformed.
    #[error("gateway admin URL must be a valid http or https origin")]
    InvalidUri,
    /// Endpoint does not use the supported scheme.
    #[error("gateway admin URL must use http or https")]
    UnsupportedScheme,
    /// Endpoint does not include host information.
    #[error("gateway admin URL must include a host")]
    MissingAuthority,
    /// Endpoint includes userinfo credentials.
    #[error("gateway admin URL must not include credentials")]
    CredentialsNotAllowed,
    /// Endpoint includes a path or query string.
    #[error("gateway admin URL must be an origin without a path or query")]
    PathNotAllowed,
}

/// Redacted bearer token for the gateway admin listener.
#[derive(Clone)]
pub struct GatewayAdminBearerToken(SecretString);

impl GatewayAdminBearerToken {
    /// Creates a validated gateway admin bearer token.
    ///
    /// # Errors
    ///
    /// Returns an error when the token is too short or contains whitespace or
    /// control characters.
    pub fn new(value: impl Into<String>) -> Result<Self, GatewayAdminClientError> {
        let value = value.into();
        if value.len() < 16 {
            return Err(GatewayAdminClientError::TokenTooShort);
        }
        if value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(GatewayAdminClientError::TokenHasInvalidCharacters);
        }
        Ok(Self(SecretString::from(value)))
    }

    fn authorization_header(&self) -> Result<HeaderValue, GatewayAdminClientError> {
        let value = format!("Bearer {}", self.0.expose_secret());
        HeaderValue::from_str(&value).map_err(|_error| GatewayAdminClientError::InvalidHeader)
    }
}

impl fmt::Debug for GatewayAdminBearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GatewayAdminBearerToken([redacted])")
    }
}

impl PartialEq for GatewayAdminBearerToken {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(
            self.0.expose_secret().as_bytes(),
            other.0.expose_secret().as_bytes(),
        )
    }
}

impl Eq for GatewayAdminBearerToken {}

/// Gateway admin client configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct GatewayAdminClientConfig {
    /// Gateway admin endpoint.
    pub endpoint: GatewayAdminEndpoint,
    /// Gateway admin bearer token.
    pub token: GatewayAdminBearerToken,
    /// Request timeout.
    pub request_timeout: Duration,
    /// Maximum accepted JSON response body size.
    pub max_response_bytes: usize,
}

impl GatewayAdminClientConfig {
    /// Creates gateway admin client configuration with conservative defaults.
    pub fn new(endpoint: GatewayAdminEndpoint, token: GatewayAdminBearerToken) -> Self {
        Self {
            endpoint,
            token,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }

    /// Sets the request timeout.
    pub fn with_request_timeout(mut self, request_timeout: Duration) -> Self {
        self.request_timeout = request_timeout;
        self
    }

    /// Sets the maximum accepted response body size.
    pub fn with_max_response_bytes(mut self, max_response_bytes: usize) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }
}

impl fmt::Debug for GatewayAdminClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayAdminClientConfig")
            .field("endpoint", &self.endpoint)
            .field("token", &self.token)
            .field("request_timeout", &self.request_timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

/// HTTP client for the gateway admin status endpoint.
#[derive(Clone)]
pub struct GatewayAdminClient {
    config: GatewayAdminClientConfig,
    client: Client<HttpsConnector<HttpConnector>, Empty<Bytes>>,
}

impl GatewayAdminClient {
    /// Creates a gateway admin client.
    ///
    /// # Errors
    ///
    /// Returns an error when native TLS root configuration fails.
    pub fn new(config: GatewayAdminClientConfig) -> Result<Self, GatewayAdminClientError> {
        let mut connector = HttpConnector::new();
        connector.enforce_http(false);
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_provider_and_native_roots(rustls::crypto::aws_lc_rs::default_provider())
            .map_err(GatewayAdminClientError::TlsConfig)?
            .https_or_http()
            .enable_http1()
            .wrap_connector(connector);
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Ok(Self { config, client })
    }

    /// Fetches and validates the gateway admin status report.
    ///
    /// # Errors
    ///
    /// Returns an error when the gateway admin listener is unavailable, rejects
    /// the request, returns too much data, or returns an unexpected JSON shape.
    pub async fn fetch_status(&self) -> Result<Value, GatewayAdminClientError> {
        self.fetch_report(self.config.endpoint.status_uri()?, ADMIN_STATUS_SCHEMA)
            .await
    }

    /// Fetches and validates the cheap gateway admin posture report.
    ///
    /// # Errors
    ///
    /// Returns an error when the gateway admin listener is unavailable, rejects
    /// the request, returns too much data, or returns an unexpected JSON shape.
    pub async fn fetch_posture(&self) -> Result<Value, GatewayAdminClientError> {
        self.fetch_report(self.config.endpoint.posture_uri()?, ADMIN_POSTURE_SCHEMA)
            .await
    }

    async fn fetch_report(
        &self,
        uri: Uri,
        expected_schema: &'static str,
    ) -> Result<Value, GatewayAdminClientError> {
        tokio::time::timeout(
            self.config.request_timeout,
            self.fetch_report_before_deadline(uri, expected_schema),
        )
        .await
        .map_err(|_elapsed| GatewayAdminClientError::RequestTimedOut)?
    }

    async fn fetch_report_before_deadline(
        &self,
        uri: Uri,
        expected_schema: &'static str,
    ) -> Result<Value, GatewayAdminClientError> {
        let request = Request::builder()
            .method("GET")
            .uri(uri)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, self.config.token.authorization_header()?)
            .body(Empty::<Bytes>::new())
            .map_err(GatewayAdminClientError::RequestBuild)?;
        let response = self
            .client
            .request(request)
            .await
            .map_err(GatewayAdminClientError::Request)?;
        let status = response.status();
        if status != StatusCode::OK {
            return Err(GatewayAdminClientError::GatewayStatus(status));
        }
        if content_length_exceeds(response.headers(), self.config.max_response_bytes) {
            return Err(GatewayAdminClientError::ResponseTooLarge {
                limit: self.config.max_response_bytes,
            });
        }
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(GatewayAdminClientError::Body)?;
            let Ok(data) = frame.into_data() else {
                continue;
            };
            let Some(remaining) = self.config.max_response_bytes.checked_sub(bytes.len()) else {
                return Err(GatewayAdminClientError::ResponseTooLarge {
                    limit: self.config.max_response_bytes,
                });
            };
            if data.len() > remaining {
                return Err(GatewayAdminClientError::ResponseTooLarge {
                    limit: self.config.max_response_bytes,
                });
            }
            bytes.extend_from_slice(&data);
        }
        let value: Value = serde_json::from_slice(&bytes).map_err(GatewayAdminClientError::Json)?;
        if value.get("schema").and_then(Value::as_str) != Some(expected_schema) {
            return Err(GatewayAdminClientError::InvalidSchema);
        }
        Ok(value)
    }
}

impl fmt::Debug for GatewayAdminClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayAdminClient")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Gateway admin client errors.
#[derive(Debug, Error)]
pub enum GatewayAdminClientError {
    /// Bearer token is too short.
    #[error("gateway admin bearer token must be at least 16 bytes")]
    TokenTooShort,
    /// Bearer token contains whitespace or control characters.
    #[error("gateway admin bearer token must not contain whitespace or control characters")]
    TokenHasInvalidCharacters,
    /// Validated token could not be converted to an HTTP header.
    #[error("gateway admin bearer token could not be encoded as an HTTP header")]
    InvalidHeader,
    /// HTTP request construction failed.
    #[error("failed to build gateway admin request")]
    RequestBuild(#[source] http::Error),
    /// TLS connector configuration failed.
    #[error("failed to configure gateway admin TLS roots")]
    TlsConfig(#[source] std::io::Error),
    /// Gateway admin request failed.
    #[error("gateway admin request failed")]
    Request(#[source] hyper_util::client::legacy::Error),
    /// Gateway admin request timed out.
    #[error("gateway admin request timed out")]
    RequestTimedOut,
    /// Gateway admin response body failed.
    #[error("gateway admin response body failed")]
    Body(#[source] hyper::Error),
    /// Gateway admin listener returned a non-success status.
    #[error("gateway admin listener returned HTTP {0}")]
    GatewayStatus(StatusCode),
    /// Gateway admin response body is too large.
    #[error("gateway admin response body exceeds {limit} bytes")]
    ResponseTooLarge {
        /// Configured size limit.
        limit: usize,
    },
    /// Gateway admin response is invalid JSON.
    #[error("gateway admin response is invalid JSON")]
    Json(#[source] serde_json::Error),
    /// Gateway admin response is not the expected admin-status schema.
    #[error("gateway admin response uses an unexpected schema")]
    InvalidSchema,
}

fn content_length_exceeds(headers: &http::HeaderMap, limit: usize) -> bool {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > limit)
}

#[cfg(test)]
mod tests {
    use super::{
        GatewayAdminBearerToken, GatewayAdminClient, GatewayAdminClientConfig,
        GatewayAdminClientError, GatewayAdminEndpoint, GatewayAdminEndpointError,
    };
    use http::StatusCode;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn endpoint_accepts_http_and_https_origins() {
        let endpoint = GatewayAdminEndpoint::parse("http://127.0.0.1:9082")
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(endpoint.authority(), "127.0.0.1:9082");

        let endpoint = GatewayAdminEndpoint::parse("https://admin.example")
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(endpoint.authority(), "admin.example:443");

        let error = match GatewayAdminEndpoint::parse("ftp://127.0.0.1:9082") {
            Ok(endpoint) => panic!("unexpected endpoint: {endpoint:?}"),
            Err(error) => error,
        };
        assert_eq!(error, GatewayAdminEndpointError::UnsupportedScheme);

        let error = match GatewayAdminEndpoint::parse("http://127.0.0.1:9082/admin") {
            Ok(endpoint) => panic!("unexpected endpoint: {endpoint:?}"),
            Err(error) => error,
        };
        assert_eq!(error, GatewayAdminEndpointError::PathNotAllowed);
    }

    #[tokio::test]
    async fn client_fetches_path_redacted_status_json() {
        let (addr, request) = MockAdmin::start(
            StatusCode::OK,
            r#"{"schema":"rs3.admin-status.preview.v1","runtime":{"gateway_mode":"read-write"}}"#,
        )
        .await;
        let endpoint = GatewayAdminEndpoint::parse(&format!("http://{addr}"))
            .unwrap_or_else(|error| panic!("{error}"));
        let token = GatewayAdminBearerToken::new("gateway-admin-token-12345")
            .unwrap_or_else(|error| panic!("{error}"));
        let client = GatewayAdminClient::new(GatewayAdminClientConfig::new(endpoint, token))
            .unwrap_or_else(|error| panic!("{error}"));

        let status = client
            .fetch_status()
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(status["schema"], "rs3.admin-status.preview.v1");
        let request = request.await.unwrap_or_else(|error| panic!("{error}"));
        assert!(request.contains("GET /admin/status HTTP/1.1"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer gateway-admin-token-12345")
        );
    }

    #[tokio::test]
    async fn client_fetches_path_redacted_posture_json() {
        let (addr, request) = MockAdmin::start(
            StatusCode::OK,
            r#"{"schema":"rs3.admin-posture.preview.v1","runtime":{"gateway_mode":"read-write"}}"#,
        )
        .await;
        let endpoint = GatewayAdminEndpoint::parse(&format!("http://{addr}"))
            .unwrap_or_else(|error| panic!("{error}"));
        let token = GatewayAdminBearerToken::new("gateway-admin-token-12345")
            .unwrap_or_else(|error| panic!("{error}"));
        let client = GatewayAdminClient::new(GatewayAdminClientConfig::new(endpoint, token))
            .unwrap_or_else(|error| panic!("{error}"));

        let posture = client
            .fetch_posture()
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(posture["schema"], "rs3.admin-posture.preview.v1");
        let request = request.await.unwrap_or_else(|error| panic!("{error}"));
        assert!(request.contains("GET /admin/posture HTTP/1.1"));
    }

    #[tokio::test]
    async fn client_rejects_unexpected_schema() {
        let (addr, _request) = MockAdmin::start(StatusCode::OK, r#"{"schema":"other"}"#).await;
        let endpoint = GatewayAdminEndpoint::parse(&format!("http://{addr}"))
            .unwrap_or_else(|error| panic!("{error}"));
        let token = GatewayAdminBearerToken::new("gateway-admin-token-12345")
            .unwrap_or_else(|error| panic!("{error}"));
        let client = GatewayAdminClient::new(GatewayAdminClientConfig::new(endpoint, token))
            .unwrap_or_else(|error| panic!("{error}"));

        let error = match client.fetch_status().await {
            Ok(status) => panic!("unexpected status: {status:?}"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("schema"));
    }

    #[tokio::test]
    async fn client_bounds_chunked_response_while_reading() {
        let (addr, _request) = MockAdmin::start_chunked(&[b"12345678", b"9"]).await;
        let endpoint = GatewayAdminEndpoint::parse(&format!("http://{addr}"))
            .unwrap_or_else(|error| panic!("{error}"));
        let token = GatewayAdminBearerToken::new("gateway-admin-token-12345")
            .unwrap_or_else(|error| panic!("{error}"));
        let config = GatewayAdminClientConfig::new(endpoint, token).with_max_response_bytes(8);
        let client = GatewayAdminClient::new(config).unwrap_or_else(|error| panic!("{error}"));

        let error = client
            .fetch_status()
            .await
            .expect_err("oversized chunked response should fail");

        assert!(matches!(
            error,
            GatewayAdminClientError::ResponseTooLarge { limit: 8 }
        ));
    }

    #[tokio::test]
    async fn client_times_out_while_reading_response_body() {
        let (addr, _request) = MockAdmin::start_stalled_body().await;
        let endpoint = GatewayAdminEndpoint::parse(&format!("http://{addr}"))
            .unwrap_or_else(|error| panic!("{error}"));
        let token = GatewayAdminBearerToken::new("gateway-admin-token-12345")
            .unwrap_or_else(|error| panic!("{error}"));
        let config = GatewayAdminClientConfig::new(endpoint, token)
            .with_request_timeout(Duration::from_millis(50));
        let client = GatewayAdminClient::new(config).unwrap_or_else(|error| panic!("{error}"));

        let error = client
            .fetch_status()
            .await
            .expect_err("stalled response body should time out");

        assert!(matches!(error, GatewayAdminClientError::RequestTimedOut));
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
                let request = read_request_headers(&mut stream).await;
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
                request
            });
            (addr, handle)
        }

        async fn start_chunked(
            chunks: &'static [&'static [u8]],
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
                let request = read_request_headers(&mut stream).await;
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
                for chunk in chunks {
                    let encoded = format!("{:x}\r\n", chunk.len());
                    stream
                        .write_all(encoded.as_bytes())
                        .await
                        .unwrap_or_else(|error| panic!("{error}"));
                    stream
                        .write_all(chunk)
                        .await
                        .unwrap_or_else(|error| panic!("{error}"));
                    stream
                        .write_all(b"\r\n")
                        .await
                        .unwrap_or_else(|error| panic!("{error}"));
                }
                stream
                    .write_all(b"0\r\n\r\n")
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
                request
            });
            (addr, handle)
        }

        async fn start_stalled_body() -> (std::net::SocketAddr, tokio::task::JoinHandle<String>) {
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
                let request = read_request_headers(&mut stream).await;
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 64\r\nConnection: close\r\n\r\n{",
                    )
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
                tokio::time::sleep(Duration::from_secs(1)).await;
                request
            });
            (addr, handle)
        }
    }

    async fn read_request_headers(stream: &mut tokio::net::TcpStream) -> String {
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
        String::from_utf8_lossy(&request).into_owned()
    }
}
