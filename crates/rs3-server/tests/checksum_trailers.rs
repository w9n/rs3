//! Authenticated aws-chunked checksum-trailer coverage for the listener.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, Mac};
use rs3_crypto::ChecksumHasher;
use rs3_server::{
    AnchorConfig, BackendConfig, BatchConfig, GatewayMode, GatewayServer, GatewayServerError,
    HardeningConfig, MaintenanceConfig, MetricsConfig, ProviderConformanceConfig, RecoveryConfig,
    RepositoryConfig, RepositoryKeysConfig, RuntimeConfig, StaticCredentials, WriterGuardConfig,
};
use rs3_types::{BackendObjectId, ChecksumAlgorithm, PublicBucket, RepositoryId};
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

const ACCESS_KEY: &str = "rs3-fixture-access-key";
const SECRET_KEY: &str = "rs3-fixture-secret-key";
const REGION: &str = "us-east-1";
const SERVICE: &str = "s3";
const STREAMING_TRAILER: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

type HmacSha256 = Hmac<Sha256>;

struct TestServer {
    addr: SocketAddr,
    shutdown: oneshot::Sender<()>,
    handle: JoinHandle<Result<(), GatewayServerError>>,
}

impl TestServer {
    async fn start() -> Self {
        let server = GatewayServer::bind(runtime_config())
            .await
            .unwrap_or_else(|error| panic!("failed to bind test server: {error}"));
        let addr = server.local_addr();
        let (shutdown, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            server
                .run_until_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });
        Self {
            addr,
            shutdown,
            handle,
        }
    }

    async fn request(&self, request: &[u8]) -> String {
        let mut stream = TcpStream::connect(self.addr)
            .await
            .unwrap_or_else(|error| panic!("failed to connect test server: {error}"));
        stream
            .write_all(request)
            .await
            .unwrap_or_else(|error| panic!("failed to write request: {error}"));
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for HTTP response"))
            .unwrap_or_else(|error| panic!("failed to read response: {error}"));
        String::from_utf8_lossy(&response).into_owned()
    }

    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        self.handle
            .await
            .unwrap_or_else(|error| panic!("test server task failed: {error}"))
            .unwrap_or_else(|error| panic!("test server shutdown failed: {error}"));
    }
}

#[derive(Clone, Copy)]
enum TrailerMode {
    Correct,
    WrongDigest,
    Missing,
}

#[derive(Clone, Copy)]
enum ChunkMode {
    Valid,
    InvalidSignature,
    MalformedSignature,
}

#[tokio::test]
async fn signed_trailer_checksum_is_verified_and_returned_by_head() {
    let server = TestServer::start().await;
    let body = b"verified trailer body";
    let response = server
        .request(&signed_chunked_put(
            server.addr,
            "trailer-success",
            body,
            TrailerMode::Correct,
            ChunkMode::Valid,
        ))
        .await;
    assert!(response.starts_with("HTTP/1.1 200"));

    let expected = crc32(body);
    let response = server
        .request(&signed_head(server.addr, "trailer-success"))
        .await;
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.contains(&format!("x-amz-checksum-crc32: {expected}")));
    assert!(response.contains("x-amz-checksum-type: FULL_OBJECT"));
    server.shutdown().await;
}

#[tokio::test]
async fn bad_signed_trailer_digest_does_not_replace_existing_object() {
    let server = TestServer::start().await;
    let original = b"original trailer object";
    let initial = server
        .request(&signed_chunked_put(
            server.addr,
            "trailer-retained",
            original,
            TrailerMode::Correct,
            ChunkMode::Valid,
        ))
        .await;
    assert!(initial.starts_with("HTTP/1.1 200"));

    let rejected = server
        .request(&signed_chunked_put(
            server.addr,
            "trailer-retained",
            b"replacement must not publish",
            TrailerMode::WrongDigest,
            ChunkMode::Valid,
        ))
        .await;
    assert!(rejected.starts_with("HTTP/1.1 400"));
    assert!(rejected.contains("BadDigest"));

    let expected = crc32(original);
    let response = server
        .request(&signed_head(server.addr, "trailer-retained"))
        .await;
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.contains(&format!("x-amz-checksum-crc32: {expected}")));
    server.shutdown().await;
}

#[tokio::test]
async fn signed_missing_declared_trailer_is_rejected() {
    let server = TestServer::start().await;
    let response = server
        .request(&signed_chunked_put(
            server.addr,
            "trailer-missing",
            b"declared trailer is absent",
            TrailerMode::Missing,
            ChunkMode::Valid,
        ))
        .await;
    assert!(response.starts_with("HTTP/1.1 400"));
    assert!(response.contains("InvalidRequest"));
    let response = server
        .request(&signed_head(server.addr, "trailer-missing"))
        .await;
    assert!(response.starts_with("HTTP/1.1 404"));
    server.shutdown().await;
}

#[tokio::test]
async fn signed_invalid_or_malformed_chunk_signature_is_refused() {
    let server = TestServer::start().await;
    for (key, mode) in [
        ("trailer-invalid-chunk", ChunkMode::InvalidSignature),
        ("trailer-malformed-chunk", ChunkMode::MalformedSignature),
    ] {
        let response = server
            .request(&signed_chunked_put(
                server.addr,
                key,
                b"untrusted chunk",
                TrailerMode::Correct,
                mode,
            ))
            .await;
        assert!(!response.starts_with("HTTP/1.1 2"));
        let response = server.request(&signed_head(server.addr, key)).await;
        assert!(response.starts_with("HTTP/1.1 404"));
    }
    server.shutdown().await;
}

#[tokio::test]
async fn signed_content_md5_rejects_bad_replacements_and_keeps_the_trusted_etag() {
    let server = TestServer::start().await;
    let body = b"signed md5 body";
    let digest = md5_base64(body);
    let etag = md5_hex(body);
    let response = server
        .request(&signed_regular_put(
            server.addr,
            "content-md5-http",
            body,
            body.len(),
            &digest,
        ))
        .await;
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.contains(&etag));

    let response = server
        .request(&signed_regular_put(
            server.addr,
            "content-md5-http",
            b"replacement",
            b"replacement".len(),
            &digest,
        ))
        .await;
    assert!(response.starts_with("HTTP/1.1 400"));
    assert!(response.contains("BadDigest"));

    let response = server
        .request(&signed_regular_put(
            server.addr,
            "content-md5-malformed",
            body,
            body.len(),
            "not-canonical-base64",
        ))
        .await;
    assert!(response.starts_with("HTTP/1.1 400"));
    assert!(response.contains("InvalidDigest"));

    let response = server
        .request(&signed_head(server.addr, "content-md5-http"))
        .await;
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.contains(&etag));
    server.shutdown().await;
}

fn signed_chunked_put(
    addr: SocketAddr,
    key: &str,
    payload: &[u8],
    trailer_mode: TrailerMode,
    chunk_mode: ChunkMode,
) -> Vec<u8> {
    let path = format!("/client-bucket/{key}");
    let timestamp = timestamp();
    let date = &timestamp[..8];
    let checksum = match trailer_mode {
        TrailerMode::Correct | TrailerMode::Missing => crc32(payload),
        TrailerMode::WrongDigest => crc32(b"different body"),
    };
    let placeholder = "0".repeat(64);
    let body_length =
        chunked_body(payload, &checksum, trailer_mode, &timestamp, &placeholder).len();
    let host = addr.to_string();
    let headers = streaming_headers(&host, &timestamp, payload.len(), body_length);
    let seed_signature = request_signature("PUT", &path, &headers, date, STREAMING_TRAILER);
    let mut body = chunked_body(
        payload,
        &checksum,
        trailer_mode,
        &timestamp,
        &seed_signature,
    );
    apply_chunk_mode(&mut body, chunk_mode);
    debug_assert_eq!(body.len(), body_length);
    http_request("PUT", &path, headers, &body, date, STREAMING_TRAILER)
}

fn signed_regular_put(
    addr: SocketAddr,
    key: &str,
    body: &[u8],
    declared_len: usize,
    content_md5: &str,
) -> Vec<u8> {
    let path = format!("/client-bucket/{key}");
    let timestamp = timestamp();
    let date = timestamp[..8].to_owned();
    let payload_hash = hex::encode(Sha256::digest(body));
    let headers = vec![
        ("content-length".to_owned(), declared_len.to_string()),
        ("content-md5".to_owned(), content_md5.to_owned()),
        ("host".to_owned(), addr.to_string()),
        ("x-amz-content-sha256".to_owned(), payload_hash.clone()),
        ("x-amz-date".to_owned(), timestamp),
    ];
    http_request("PUT", &path, headers, body, &date, &payload_hash)
}

fn signed_head(addr: SocketAddr, key: &str) -> Vec<u8> {
    let path = format!("/client-bucket/{key}");
    let timestamp = timestamp();
    let date = timestamp[..8].to_owned();
    let headers = vec![
        ("host".to_owned(), addr.to_string()),
        (
            "x-amz-content-sha256".to_owned(),
            "UNSIGNED-PAYLOAD".to_owned(),
        ),
        ("x-amz-date".to_owned(), timestamp),
        ("x-amz-checksum-mode".to_owned(), "ENABLED".to_owned()),
    ];
    http_request("HEAD", &path, headers, &[], &date, "UNSIGNED-PAYLOAD")
}

fn streaming_headers(
    host: &str,
    timestamp: &str,
    decoded_length: usize,
    body_length: usize,
) -> Vec<(String, String)> {
    vec![
        ("content-encoding".to_owned(), "aws-chunked".to_owned()),
        ("content-length".to_owned(), body_length.to_string()),
        ("host".to_owned(), host.to_owned()),
        ("x-amz-checksum-algorithm".to_owned(), "CRC32".to_owned()),
        (
            "x-amz-content-sha256".to_owned(),
            STREAMING_TRAILER.to_owned(),
        ),
        ("x-amz-date".to_owned(), timestamp.to_owned()),
        (
            "x-amz-decoded-content-length".to_owned(),
            decoded_length.to_string(),
        ),
        (
            "x-amz-trailer".to_owned(),
            "x-amz-checksum-crc32".to_owned(),
        ),
    ]
}

fn http_request(
    method: &str,
    path: &str,
    mut headers: Vec<(String, String)>,
    body: &[u8],
    date: &str,
    payload_hash: &str,
) -> Vec<u8> {
    let signature = request_signature(method, path, &headers, date, payload_hash);
    let signed_headers = signed_header_names(&headers);
    headers.push((
        "authorization".to_owned(),
        format!(
            "AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/{date}/{REGION}/{SERVICE}/aws4_request, SignedHeaders={signed_headers}, Signature={signature}"
        ),
    ));
    headers.push(("connection".to_owned(), "close".to_owned()));

    let mut request = format!("{method} {path} HTTP/1.1\r\n").into_bytes();
    for (name, value) in headers {
        request.extend_from_slice(name.as_bytes());
        request.extend_from_slice(b": ");
        request.extend_from_slice(value.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(body);
    request
}

fn request_signature(
    method: &str,
    path: &str,
    headers: &[(String, String)],
    date: &str,
    payload_hash: &str,
) -> String {
    let canonical_headers = canonical_headers(headers);
    let signed_headers = signed_header_names(headers);
    let canonical_request =
        format!("{method}\n{path}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}",);
    let canonical_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let timestamp = headers
        .iter()
        .find(|(name, _)| name == "x-amz-date")
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("signed request must contain x-amz-date"));
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{timestamp}\n{date}/{REGION}/{SERVICE}/aws4_request\n{canonical_hash}"
    );
    hex::encode(signing_hmac(date.as_bytes(), string_to_sign.as_bytes()))
}

fn chunked_body(
    payload: &[u8],
    checksum: &str,
    trailer_mode: TrailerMode,
    timestamp: &str,
    seed_signature: &str,
) -> Vec<u8> {
    let date = &timestamp[..8];
    let mut body = Vec::new();
    let payload_signature = chunk_signature(timestamp, date, seed_signature, payload);
    body.extend_from_slice(
        format!(
            "{:x};chunk-signature={payload_signature}\r\n",
            payload.len()
        )
        .as_bytes(),
    );
    body.extend_from_slice(payload);
    body.extend_from_slice(b"\r\n");

    let final_signature = chunk_signature(timestamp, date, &payload_signature, &[]);
    body.extend_from_slice(format!("0;chunk-signature={final_signature}\r\n\r\n").as_bytes());
    if !matches!(trailer_mode, TrailerMode::Missing) {
        let canonical_trailer = format!("x-amz-checksum-crc32:{checksum}\n");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256-TRAILER\n{timestamp}\n{date}/{REGION}/{SERVICE}/aws4_request\n{final_signature}\n{}",
            hex::encode(Sha256::digest(canonical_trailer.as_bytes()))
        );
        let trailer_signature =
            hex::encode(signing_hmac(date.as_bytes(), string_to_sign.as_bytes()));
        body.extend_from_slice(
            format!(
                "x-amz-checksum-crc32:{checksum}\r\nx-amz-trailer-signature:{trailer_signature}"
            )
            .as_bytes(),
        );
    }
    body
}

fn chunk_signature(timestamp: &str, date: &str, previous: &str, payload: &[u8]) -> String {
    let payload_hash = hex::encode(Sha256::digest(payload));
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256-PAYLOAD\n{timestamp}\n{date}/{REGION}/{SERVICE}/aws4_request\n{previous}\n{EMPTY_SHA256}\n{payload_hash}"
    );
    hex::encode(signing_hmac(date.as_bytes(), string_to_sign.as_bytes()))
}

fn signing_hmac(date: &[u8], message: &[u8]) -> Vec<u8> {
    let date_key = hmac(&format!("AWS4{SECRET_KEY}").into_bytes(), date);
    let region_key = hmac(&date_key, REGION.as_bytes());
    let service_key = hmac(&region_key, SERVICE.as_bytes());
    let signing_key = hmac(&service_key, b"aws4_request");
    hmac(&signing_key, message)
}

fn hmac(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key)
        .unwrap_or_else(|_| panic!("HMAC accepts arbitrary-length fixture keys"));
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn canonical_headers(headers: &[(String, String)]) -> String {
    let mut headers = headers.to_vec();
    headers.sort_by(|left, right| left.0.cmp(&right.0));
    headers
        .into_iter()
        .map(|(name, value)| format!("{name}:{}\n", value.trim()))
        .collect()
}

fn signed_header_names(headers: &[(String, String)]) -> String {
    let mut names: Vec<_> = headers.iter().map(|(name, _)| name.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    names.join(";")
}

fn apply_chunk_mode(body: &mut [u8], mode: ChunkMode) {
    if matches!(mode, ChunkMode::Valid) {
        return;
    }
    let prefix = b"chunk-signature=";
    let offset = body
        .windows(prefix.len())
        .position(|window| window == prefix)
        .unwrap_or_else(|| panic!("generated fixture must contain a chunk signature"))
        + prefix.len();
    match mode {
        ChunkMode::Valid => {}
        ChunkMode::InvalidSignature => {
            body[offset] = if body[offset] == b'0' { b'1' } else { b'0' }
        }
        ChunkMode::MalformedSignature => body[offset + 64] = b'x',
    }
}

fn crc32(body: &[u8]) -> String {
    let mut hasher = ChecksumHasher::new(ChecksumAlgorithm::Crc32);
    hasher.update(body);
    STANDARD.encode(hasher.finalize())
}

fn md5_base64(body: &[u8]) -> String {
    STANDARD.encode(rs3_crypto::md5(body).as_bytes())
}

fn md5_hex(body: &[u8]) -> String {
    hex::encode(rs3_crypto::md5(body).as_bytes())
}

fn timestamp() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

fn runtime_config() -> RuntimeConfig {
    let bind = "127.0.0.1:0"
        .parse()
        .unwrap_or_else(|error| panic!("invalid test bind address: {error}"));
    let public_bucket = PublicBucket::new("client-bucket")
        .unwrap_or_else(|error| panic!("invalid test public bucket: {error}"));
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
            timeouts: Default::default(),
        },
        anchor: AnchorConfig::Memory,
        writer_guard: WriterGuardConfig::Off,
        batching: BatchConfig {
            max_items: 64,
            max_delay: Duration::from_millis(10),
            max_pending_items: 64,
        },
        repository: RepositoryConfig {
            format: rs3_server::RepositoryFormat::V3Preview,
            payload_segment_size: rs3_repository::DEFAULT_PAYLOAD_SEGMENT_SIZE,
            adaptive_payload_segment_size: true,
            decrypted_segment_cache_max_bytes:
                rs3_repository::DEFAULT_DECRYPTED_SEGMENT_CACHE_MAX_BYTES,
            retention: None,
            allow_init: true,
        },
        maintenance: MaintenanceConfig::default(),
        provider_conformance: ProviderConformanceConfig::default(),
        recovery: RecoveryConfig::default(),
        repository_keys: RepositoryKeysConfig {
            repository_id: RepositoryId::new("test-repository")
                .unwrap_or_else(|error| panic!("invalid test repository id: {error}")),
            repository_salt_hex: Some(
                "2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
            ),
            envelope_object_id: Some(
                BackendObjectId::new("keyrings/test-envelope.cbor")
                    .unwrap_or_else(|error| panic!("invalid test envelope object id: {error}")),
            ),
            wrapping_key_id: "wrap-v1".to_owned(),
            wrapping_key_hex: SecretString::from(
                "3333333333333333333333333333333333333333333333333333333333333333",
            ),
        },
        static_credentials: Some(StaticCredentials {
            access_key_id: ACCESS_KEY.to_owned(),
            secret_access_key: SecretString::from(SECRET_KEY),
        }),
    }
}
