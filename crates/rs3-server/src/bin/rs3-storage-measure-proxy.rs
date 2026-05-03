//! Test-only TCP measurement proxy for S3-compatible storage backends.

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::{Value, json};
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing_subscriber::EnvFilter;

type SharedMetrics = Arc<Mutex<ProxyMetrics>>;

#[derive(Debug, Parser)]
#[command(name = "rs3-storage-measure-proxy")]
#[command(about = "TCP measurement proxy for integration baselines")]
struct Cli {
    #[arg(long)]
    bind: SocketAddr,
    #[arg(long)]
    target: String,
    #[arg(long, default_value_t = 5)]
    report_interval_secs: u64,
}

#[derive(Default)]
struct ProxyMetrics {
    accepted_connections: u64,
    active_connections: u64,
    failed_connections: u64,
    bytes_to_backend: u64,
    bytes_from_backend: u64,
    request_body_bytes: u64,
    response_body_bytes: u64,
    requests: u64,
    responses: u64,
    methods: BTreeMap<String, u64>,
    statuses: BTreeMap<String, u64>,
}

impl ProxyMetrics {
    fn to_json(&self) -> Value {
        json!({
            "accepted_connections": self.accepted_connections,
            "active_connections": self.active_connections,
            "failed_connections": self.failed_connections,
            "bytes_to_backend": self.bytes_to_backend,
            "bytes_from_backend": self.bytes_from_backend,
            "request_body_bytes": self.request_body_bytes,
            "response_body_bytes": self.response_body_bytes,
            "requests": self.requests,
            "responses": self.responses,
            "methods": self.methods,
            "statuses": self.statuses,
        })
    }
}

#[derive(Default)]
struct ParserDelta {
    body_bytes: u64,
    requests: Vec<RequestInfo>,
    responses: Vec<u16>,
}

#[derive(Clone)]
struct RequestInfo {
    method: String,
}

#[derive(Default)]
struct RequestParser {
    buffer: Vec<u8>,
    body_remaining: u64,
    opaque_body: bool,
}

impl RequestParser {
    fn observe(&mut self, bytes: &[u8]) -> ParserDelta {
        let mut delta = ParserDelta::default();
        if self.opaque_body {
            delta.body_bytes = usize_to_u64(bytes.len());
            return delta;
        }

        self.buffer.extend_from_slice(bytes);
        loop {
            if self.consume_body(&mut delta) {
                continue;
            }

            let Some(header_end) = header_end(&self.buffer) else {
                break;
            };
            let header = self.buffer[..header_end].to_vec();
            self.buffer.drain(..header_end + 4);

            if let Some(request) = parse_request_header(&header) {
                delta.requests.push(RequestInfo {
                    method: request.method,
                });
                if let Some(content_length) = request.content_length {
                    self.body_remaining = content_length;
                } else if request.chunked {
                    self.opaque_body = true;
                }
            }
        }

        delta
    }

    fn consume_body(&mut self, delta: &mut ParserDelta) -> bool {
        if self.body_remaining == 0 {
            return false;
        }
        let take = self.body_remaining.min(usize_to_u64(self.buffer.len()));
        if take == 0 {
            return false;
        }
        let take = take as usize;
        self.buffer.drain(..take);
        self.body_remaining = self.body_remaining.saturating_sub(usize_to_u64(take));
        delta.body_bytes = delta.body_bytes.saturating_add(usize_to_u64(take));
        !self.buffer.is_empty()
    }
}

#[derive(Default)]
struct ResponseParser {
    buffer: Vec<u8>,
    body_remaining: u64,
    opaque_body: bool,
}

impl ResponseParser {
    fn observe(&mut self, bytes: &[u8], pending: &mut VecDeque<RequestInfo>) -> ParserDelta {
        let mut delta = ParserDelta::default();
        if self.opaque_body {
            delta.body_bytes = usize_to_u64(bytes.len());
            return delta;
        }

        self.buffer.extend_from_slice(bytes);
        loop {
            if self.consume_body(&mut delta) {
                continue;
            }

            let Some(header_end) = header_end(&self.buffer) else {
                break;
            };
            let header = self.buffer[..header_end].to_vec();
            self.buffer.drain(..header_end + 4);

            let Some(response) = parse_response_header(&header) else {
                continue;
            };
            delta.responses.push(response.status);

            let method = if is_informational(response.status) {
                None
            } else {
                pending.pop_front().map(|request| request.method)
            };
            if response_has_body(method.as_deref(), response.status) {
                if let Some(content_length) = response.content_length {
                    self.body_remaining = content_length;
                } else if response.chunked {
                    self.opaque_body = true;
                }
            }
        }

        delta
    }

    fn consume_body(&mut self, delta: &mut ParserDelta) -> bool {
        if self.body_remaining == 0 {
            return false;
        }
        let take = self.body_remaining.min(usize_to_u64(self.buffer.len()));
        if take == 0 {
            return false;
        }
        let take = take as usize;
        self.buffer.drain(..take);
        self.body_remaining = self.body_remaining.saturating_sub(usize_to_u64(take));
        delta.body_bytes = delta.body_bytes.saturating_add(usize_to_u64(take));
        !self.buffer.is_empty()
    }
}

struct RequestHeader {
    method: String,
    content_length: Option<u64>,
    chunked: bool,
}

struct ResponseHeader {
    status: u16,
    content_length: Option<u64>,
    chunked: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let report_interval = Duration::from_secs(cli.report_interval_secs.max(1));
    run(cli.bind, cli.target, report_interval, shutdown_signal()).await
}

async fn run<F>(
    bind: SocketAddr,
    target: String,
    report_interval: Duration,
    shutdown: F,
) -> Result<()>
where
    F: Future<Output = ()>,
{
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("failed to bind storage measurement proxy at {bind}"))?;
    let local_addr = listener
        .local_addr()
        .context("failed to read storage measurement proxy bind address")?;
    tracing::info!(bind = %local_addr, target = %target, "storage measurement proxy started");

    let metrics = Arc::new(Mutex::new(ProxyMetrics::default()));
    let reporter = tokio::spawn(report_metrics(metrics.clone(), report_interval));
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (client, remote_addr) = accepted.context("failed to accept storage measurement proxy connection")?;
                let target = target.clone();
                let metrics = metrics.clone();
                tokio::spawn(async move {
                    if let Err(error) = proxy_connection(client, &target, metrics).await {
                        tracing::debug!(%remote_addr, %error, "storage measurement proxy connection ended with error");
                    }
                });
            }
            () = shutdown.as_mut() => {
                break;
            }
        }
    }

    reporter.abort();
    emit_metrics(&metrics);
    Ok(())
}

async fn proxy_connection(client: TcpStream, target: &str, metrics: SharedMetrics) -> Result<()> {
    let _active = ActiveConnection::new(metrics.clone());
    let backend = match TcpStream::connect(target).await {
        Ok(backend) => backend,
        Err(error) => {
            with_metrics(&metrics, |metrics| {
                metrics.failed_connections = metrics.failed_connections.saturating_add(1);
            });
            return Err(error).with_context(|| {
                format!("failed to connect storage measurement proxy target {target}")
            });
        }
    };
    let (mut client_reader, mut client_writer) = client.into_split();
    let (mut backend_reader, mut backend_writer) = backend.into_split();
    let mut request_parser = RequestParser::default();
    let mut response_parser = ResponseParser::default();
    let mut pending = VecDeque::new();
    let mut client_open = true;
    let mut backend_open = true;
    let mut client_buffer = [0_u8; 16 * 1024];
    let mut backend_buffer = [0_u8; 16 * 1024];

    while client_open || backend_open {
        tokio::select! {
            read = client_reader.read(&mut client_buffer), if client_open => {
                let read = read.context("failed to read from storage measurement proxy client")?;
                if read == 0 {
                    client_open = false;
                    backend_writer.shutdown().await.context("failed to close storage measurement proxy backend write side")?;
                    continue;
                }

                let bytes = &client_buffer[..read];
                backend_writer.write_all(bytes).await.context("failed to write to storage measurement proxy backend")?;
                let delta = request_parser.observe(bytes);
                for request in &delta.requests {
                    pending.push_back(request.clone());
                }
                record_request_delta(&metrics, usize_to_u64(read), delta);
            }
            read = backend_reader.read(&mut backend_buffer), if backend_open => {
                let read = read.context("failed to read from storage measurement proxy backend")?;
                if read == 0 {
                    backend_open = false;
                    client_writer.shutdown().await.context("failed to close storage measurement proxy client write side")?;
                    continue;
                }

                let bytes = &backend_buffer[..read];
                client_writer.write_all(bytes).await.context("failed to write to storage measurement proxy client")?;
                let delta = response_parser.observe(bytes, &mut pending);
                record_response_delta(&metrics, usize_to_u64(read), delta);
            }
        }
    }

    Ok(())
}

struct ActiveConnection {
    metrics: SharedMetrics,
}

impl ActiveConnection {
    fn new(metrics: SharedMetrics) -> Self {
        with_metrics(&metrics, |metrics| {
            metrics.accepted_connections = metrics.accepted_connections.saturating_add(1);
            metrics.active_connections = metrics.active_connections.saturating_add(1);
        });
        Self { metrics }
    }
}

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        with_metrics(&self.metrics, |metrics| {
            metrics.active_connections = metrics.active_connections.saturating_sub(1);
        });
    }
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::warn!(%error, "failed to install Ctrl+C shutdown handler");
    }
}

async fn report_metrics(metrics: SharedMetrics, report_interval: Duration) {
    let mut interval = tokio::time::interval(report_interval);
    loop {
        interval.tick().await;
        emit_metrics(&metrics);
    }
}

fn emit_metrics(metrics: &SharedMetrics) {
    let fields = with_metrics(metrics, |metrics| metrics.to_json());
    println!(
        "{}",
        json!({
            "target": "rs3_storage_measure",
            "fields": fields,
        })
    );
}

fn record_request_delta(metrics: &SharedMetrics, bytes_to_backend: u64, delta: ParserDelta) {
    with_metrics(metrics, |metrics| {
        metrics.bytes_to_backend = metrics.bytes_to_backend.saturating_add(bytes_to_backend);
        metrics.request_body_bytes = metrics.request_body_bytes.saturating_add(delta.body_bytes);
        for request in delta.requests {
            metrics.requests = metrics.requests.saturating_add(1);
            let count = metrics.methods.entry(request.method).or_default();
            *count = count.saturating_add(1);
        }
    });
}

fn record_response_delta(metrics: &SharedMetrics, bytes_from_backend: u64, delta: ParserDelta) {
    with_metrics(metrics, |metrics| {
        metrics.bytes_from_backend = metrics
            .bytes_from_backend
            .saturating_add(bytes_from_backend);
        metrics.response_body_bytes = metrics.response_body_bytes.saturating_add(delta.body_bytes);
        for status in delta.responses {
            metrics.responses = metrics.responses.saturating_add(1);
            let count = metrics.statuses.entry(status.to_string()).or_default();
            *count = count.saturating_add(1);
        }
    });
}

fn with_metrics<T>(metrics: &SharedMetrics, apply: impl FnOnce(&mut ProxyMetrics) -> T) -> T {
    match metrics.lock() {
        Ok(mut guard) => apply(&mut guard),
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            apply(&mut guard)
        }
    }
}

fn parse_request_header(header: &[u8]) -> Option<RequestHeader> {
    let text = std::str::from_utf8(header).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let method = request_line.split_whitespace().next()?.to_ascii_uppercase();
    let (content_length, chunked) = parse_entity_headers(lines);
    Some(RequestHeader {
        method,
        content_length,
        chunked,
    })
}

fn parse_response_header(header: &[u8]) -> Option<ResponseHeader> {
    let text = std::str::from_utf8(header).ok()?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next()?;
    let status = status_line.split_whitespace().nth(1)?.parse().ok()?;
    let (content_length, chunked) = parse_entity_headers(lines);
    Some(ResponseHeader {
        status,
        content_length,
        chunked,
    })
}

fn parse_entity_headers<'a>(lines: impl Iterator<Item = &'a str>) -> (Option<u64>, bool) {
    let mut content_length = None;
    let mut chunked = false;

    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        }
    }

    (content_length, chunked)
}

fn header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn response_has_body(method: Option<&str>, status: u16) -> bool {
    method != Some("HEAD") && !is_informational(status) && status != 204 && status != 304
}

fn is_informational(status: u16) -> bool {
    (100..200).contains(&status)
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{RequestInfo, RequestParser, ResponseParser};
    use std::collections::VecDeque;

    #[test]
    fn request_parser_counts_content_length_body() {
        let mut parser = RequestParser::default();
        let delta = parser.observe(b"PUT /bucket/key HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello");

        assert_eq!(delta.requests.len(), 1);
        assert_eq!(delta.requests[0].method, "PUT");
        assert_eq!(delta.body_bytes, 5);
    }

    #[test]
    fn response_parser_ignores_head_body_length() {
        let mut parser = ResponseParser::default();
        let mut pending = VecDeque::from([RequestInfo {
            method: "HEAD".to_owned(),
        }]);
        let delta = parser.observe(
            b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
            &mut pending,
        );

        assert_eq!(delta.responses, vec![200, 204]);
        assert_eq!(delta.body_bytes, 0);
    }
}
