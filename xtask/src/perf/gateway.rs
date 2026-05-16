//! Gateway-backed performance scenarios.

use super::{
    GatewayBuildProfile, OperationLatencyStats, PerfArgs, PerfReport, PerfScenario, ReportFormat,
    body, checked_mul, commit_batch_items, commit_max_pending_items, concurrency, print_header,
};
use crate::integration::s3_container;
use anyhow::{Context, Result};
use aws_sdk_s3::primitives::ByteStream;
use bytes::Bytes;
use rs3_storage::BlobOperationCounts;
use serde_json::Value;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpListener};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;

const GATEWAY_PUBLIC_BUCKET: &str = "client-bucket";
const GATEWAY_ACCESS_KEY_ID: &str = "access";
const GATEWAY_SECRET_ACCESS_KEY: &str = "secret";
const GATEWAY_KEYRING_ENVELOPE_OBJECT_ID: &str = "keyrings/bootstrap-envelope.json";
const GATEWAY_KEYRING_WRAPPING_KEY_HEX: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";
const GATEWAY_KEYRING_WRAPPING_KEY_ID: &str = "wrap-integration";
const GATEWAY_REPOSITORY_SALT_HEX: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";
const GATEWAY_START_TIMEOUT: Duration = Duration::from_secs(120);

pub(super) fn run_s3_gateway_container_perf(args: &PerfArgs) -> Result<()> {
    let scenarios = gateway_perf_scenarios(args.scenario)?;
    let target = s3_container::start_s3_container(
        args.container_provider,
        args.s3_bucket.clone(),
        args.s3_region.clone(),
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build gateway perf runtime")?;

    runtime.block_on(async {
        let backend_prefix = args
            .s3_prefix
            .clone()
            .unwrap_or_else(default_gateway_prefix);
        let mut gateway = RunningPerfGateway::start(&target, args, backend_prefix).await?;
        let client = s3_container::s3_client(
            &format!("http://{}", gateway.addr),
            &target.region,
            GATEWAY_ACCESS_KEY_ID,
            GATEWAY_SECRET_ACCESS_KEY,
        );

        if args.format == ReportFormat::Tsv {
            print_header();
        }
        for scenario in scenarios {
            let report = run_gateway_perf_scenario(args, scenario, &client, &gateway).await?;
            report.print(args.format)?;
        }

        gateway.shutdown()?;
        Ok(())
    })
}

fn gateway_perf_scenarios(scenario: PerfScenario) -> Result<Vec<PerfScenario>> {
    match scenario {
        PerfScenario::All => Ok(vec![
            PerfScenario::WriteCommitted,
            PerfScenario::WriteCommittedParallel,
            PerfScenario::FullRead,
            PerfScenario::RangeRead,
        ]),
        PerfScenario::WriteBatch => {
            anyhow::bail!(
                "write-batch is not a client-visible gateway scenario; use write-committed"
            )
        }
        scenario => Ok(vec![scenario]),
    }
}

async fn run_gateway_perf_scenario(
    args: &PerfArgs,
    scenario: PerfScenario,
    client: &aws_sdk_s3::Client,
    gateway: &RunningPerfGateway,
) -> Result<PerfReport> {
    match scenario {
        PerfScenario::All => unreachable!("expanded before dispatch"),
        PerfScenario::WriteBatch => unreachable!("rejected before dispatch"),
        PerfScenario::WriteCommitted => gateway_write_committed(args, client, gateway).await,
        PerfScenario::WriteCommittedParallel => {
            gateway_write_committed_parallel(args, client, gateway).await
        }
        PerfScenario::FullRead => gateway_full_read(args, client, gateway).await,
        PerfScenario::RangeRead => gateway_range_read(args, client, gateway).await,
    }
}

async fn gateway_write_committed(
    args: &PerfArgs,
    client: &aws_sdk_s3::Client,
    gateway: &RunningPerfGateway,
) -> Result<PerfReport> {
    let body = body(args.object_size);
    let mut latencies = Vec::with_capacity(args.objects);
    gateway.reset_captured_metrics().await?;
    let started = Instant::now();

    for index in 0..args.objects {
        let operation_started = Instant::now();
        gateway_put_object(
            client,
            format!("perf/write-committed/object-{index:08}"),
            body.clone(),
        )
        .await
        .with_context(|| format!("gateway PutObject failed for object {index}"))?;
        latencies.push(operation_started.elapsed());
    }

    let elapsed = started.elapsed();
    let counts = gateway.backend_operation_counts().await?;
    gateway_write_report(
        args,
        "write-committed",
        args.objects,
        args.objects,
        latencies,
        elapsed,
        counts,
    )
}

async fn gateway_write_committed_parallel(
    args: &PerfArgs,
    client: &aws_sdk_s3::Client,
    gateway: &RunningPerfGateway,
) -> Result<PerfReport> {
    let body = body(args.object_size);
    let parallelism = concurrency(args);
    let mut latencies = Vec::with_capacity(args.objects);
    gateway.reset_captured_metrics().await?;
    let started = Instant::now();

    let mut next = 0;
    while next < args.objects {
        let end = next.saturating_add(parallelism).min(args.objects);
        let mut handles = Vec::with_capacity(end - next);
        for index in next..end {
            let client = client.clone();
            let body = body.clone();
            handles.push(tokio::spawn(async move {
                let operation_started = Instant::now();
                gateway_put_object(
                    &client,
                    format!("perf/write-committed-parallel/object-{index:08}"),
                    body,
                )
                .await
                .with_context(|| format!("gateway PutObject failed for object {index}"))?;
                Ok::<Duration, anyhow::Error>(operation_started.elapsed())
            }));
        }
        for handle in handles {
            let latency = handle
                .await
                .context("gateway write task did not complete")??;
            latencies.push(latency);
        }
        next = end;
    }

    let elapsed = started.elapsed();
    let counts = gateway.backend_operation_counts().await?;
    gateway_write_report(
        args,
        "write-committed-parallel",
        args.objects,
        args.objects,
        latencies,
        elapsed,
        counts,
    )
}

async fn gateway_full_read(
    args: &PerfArgs,
    client: &aws_sdk_s3::Client,
    gateway: &RunningPerfGateway,
) -> Result<PerfReport> {
    let key = "perf/read/full-object";
    gateway_put_object(client, key, body(args.object_size))
        .await
        .context("failed to prepare gateway full-read object")?;
    gateway.reset_captured_metrics().await?;

    let mut latencies = Vec::with_capacity(args.reads);
    let started = Instant::now();
    for index in 0..args.reads {
        let operation_started = Instant::now();
        let body = gateway_get_object(client, key, None)
            .await
            .with_context(|| format!("gateway GetObject failed for read {index}"))?;
        if body.len() != args.object_size {
            anyhow::bail!(
                "gateway full-read returned {} bytes, expected {}",
                body.len(),
                args.object_size
            );
        }
        latencies.push(operation_started.elapsed());
    }

    let elapsed = started.elapsed();
    let counts = gateway.backend_operation_counts().await?;
    Ok(PerfReport {
        scenario: "full-read",
        backend: args.backend,
        repository_format: Some(args.repository_format),
        objects: 1,
        object_size: args.object_size,
        operations: args.reads,
        requested_plaintext_write_bytes: 0,
        requested_plaintext_read_bytes: checked_mul(args.reads, args.object_size)?,
        commit_batch_items: commit_batch_items(args),
        commit_batch_delay_ms: args.commit_batch_delay_ms,
        commit_max_pending_items: commit_max_pending_items(args),
        payload_segment_size: args.payload_segment_size,
        adaptive_payload_segment_size: adaptive_payload_segment_size(args),
        concurrency: concurrency(args),
        operation_latency: OperationLatencyStats::from_samples(latencies),
        elapsed,
        counts,
    })
}

async fn gateway_range_read(
    args: &PerfArgs,
    client: &aws_sdk_s3::Client,
    gateway: &RunningPerfGateway,
) -> Result<PerfReport> {
    let range_len = args.range_len.min(args.object_size);
    if range_len == 0 {
        anyhow::bail!("gateway range-read requires non-zero object size and range length");
    }

    let key = "perf/read/range-object";
    gateway_put_object(client, key, body(args.object_size))
        .await
        .context("failed to prepare gateway range-read object")?;
    gateway.reset_captured_metrics().await?;

    let offset_window = args.object_size.saturating_sub(range_len);
    let mut latencies = Vec::with_capacity(args.reads);
    let started = Instant::now();
    for index in 0..args.reads {
        let offset = if offset_window == 0 {
            0
        } else {
            index.wrapping_mul(range_len) % (offset_window + 1)
        };
        let end = offset + range_len - 1;
        let range = format!("bytes={offset}-{end}");
        let operation_started = Instant::now();
        let body = gateway_get_object(client, key, Some(range))
            .await
            .with_context(|| format!("gateway ranged GetObject failed for read {index}"))?;
        if body.len() != range_len {
            anyhow::bail!(
                "gateway range-read returned {} bytes, expected {range_len}",
                body.len()
            );
        }
        latencies.push(operation_started.elapsed());
    }

    let elapsed = started.elapsed();
    let counts = gateway.backend_operation_counts().await?;
    Ok(PerfReport {
        scenario: "range-read",
        backend: args.backend,
        repository_format: Some(args.repository_format),
        objects: 1,
        object_size: args.object_size,
        operations: args.reads,
        requested_plaintext_write_bytes: 0,
        requested_plaintext_read_bytes: checked_mul(args.reads, range_len)?,
        commit_batch_items: commit_batch_items(args),
        commit_batch_delay_ms: args.commit_batch_delay_ms,
        commit_max_pending_items: commit_max_pending_items(args),
        payload_segment_size: args.payload_segment_size,
        adaptive_payload_segment_size: adaptive_payload_segment_size(args),
        concurrency: concurrency(args),
        operation_latency: OperationLatencyStats::from_samples(latencies),
        elapsed,
        counts,
    })
}

fn gateway_write_report(
    args: &PerfArgs,
    scenario: &'static str,
    objects: usize,
    operations: usize,
    latencies: Vec<Duration>,
    elapsed: Duration,
    counts: BlobOperationCounts,
) -> Result<PerfReport> {
    Ok(PerfReport {
        scenario,
        backend: args.backend,
        repository_format: Some(args.repository_format),
        objects,
        object_size: args.object_size,
        operations,
        requested_plaintext_write_bytes: checked_mul(objects, args.object_size)?,
        requested_plaintext_read_bytes: 0,
        commit_batch_items: commit_batch_items(args),
        commit_batch_delay_ms: args.commit_batch_delay_ms,
        commit_max_pending_items: commit_max_pending_items(args),
        payload_segment_size: args.payload_segment_size,
        adaptive_payload_segment_size: adaptive_payload_segment_size(args),
        concurrency: concurrency(args),
        operation_latency: OperationLatencyStats::from_samples(latencies),
        elapsed,
        counts,
    })
}

async fn gateway_put_object(
    client: &aws_sdk_s3::Client,
    key: impl Into<String>,
    body: Bytes,
) -> Result<()> {
    client
        .put_object()
        .bucket(GATEWAY_PUBLIC_BUCKET)
        .key(key.into())
        .body(ByteStream::from(body))
        .send()
        .await
        .context("gateway PutObject request failed")?;
    Ok(())
}

async fn gateway_get_object(
    client: &aws_sdk_s3::Client,
    key: &str,
    range: Option<String>,
) -> Result<Bytes> {
    let mut request = client
        .get_object()
        .bucket(GATEWAY_PUBLIC_BUCKET)
        .key(key.to_owned());
    if let Some(range) = range {
        request = request.range(range);
    }
    let output = request
        .send()
        .await
        .context("gateway GetObject request failed")?;
    let body = output
        .body
        .collect()
        .await
        .context("failed to collect gateway GetObject body")?
        .into_bytes();
    Ok(body)
}

struct RunningPerfGateway {
    addr: SocketAddr,
    child: Child,
    logs: Arc<Mutex<Vec<String>>>,
    readers: Vec<JoinHandle<()>>,
}

impl RunningPerfGateway {
    async fn start(
        backend: &s3_container::RunningS3Container,
        args: &PerfArgs,
        backend_prefix: String,
    ) -> Result<Self> {
        let addr = reserve_gateway_addr()?;
        let mut child = Command::new("cargo");
        child
            .arg("run")
            .args(["-p", "rs3-server", "--features", "s3"]);
        if args.gateway_build_profile == GatewayBuildProfile::Release {
            child.arg("--release");
        }
        child
            .args([
                "--",
                "--log-format",
                "json",
                "serve",
                "--bind",
                &addr.to_string(),
            ])
            .env("RUST_LOG", "rs3_storage=debug,rs3_repository=info,info")
            .env("RS3_PUBLIC_BUCKET", GATEWAY_PUBLIC_BUCKET)
            .env("RS3_REPOSITORY_FORMAT", args.repository_format.as_env())
            .env("RS3_BACKEND_ENDPOINT", &backend.endpoint_url)
            .env("RS3_BACKEND_BUCKET", &backend.bucket)
            .env("RS3_BACKEND_PREFIX", backend_prefix)
            .env("RS3_ANCHOR_MODE", "memory")
            .env("RS3_ALLOW_MEMORY_ANCHOR", "true")
            .env("RS3_REPOSITORY_ID", "rs3-gateway-perf-repository")
            .env(
                "RS3_KEYRING_ENVELOPE_OBJECT_ID",
                GATEWAY_KEYRING_ENVELOPE_OBJECT_ID,
            )
            .env(
                "RS3_KEYRING_WRAPPING_KEY_ID",
                GATEWAY_KEYRING_WRAPPING_KEY_ID,
            )
            .env(
                "RS3_KEYRING_WRAPPING_KEY_HEX",
                GATEWAY_KEYRING_WRAPPING_KEY_HEX,
            )
            .env("RS3_REPOSITORY_SALT_HEX", GATEWAY_REPOSITORY_SALT_HEX)
            .env(
                "RS3_COMMIT_MAX_BATCH_ITEMS",
                commit_batch_items(args).to_string(),
            )
            .env(
                "RS3_COMMIT_MAX_BATCH_DELAY_MS",
                args.commit_batch_delay_ms.to_string(),
            )
            .env(
                "RS3_COMMIT_MAX_PENDING_ITEMS",
                commit_max_pending_items(args).to_string(),
            )
            .env("RS3_STATIC_ACCESS_KEY_ID", GATEWAY_ACCESS_KEY_ID)
            .env("RS3_STATIC_SECRET_ACCESS_KEY", GATEWAY_SECRET_ACCESS_KEY)
            .env("AWS_ACCESS_KEY_ID", &backend.access_key_id)
            .env("AWS_SECRET_ACCESS_KEY", &backend.secret_access_key)
            .env("AWS_DEFAULT_REGION", &backend.region)
            .env_remove("AWS_SESSION_TOKEN")
            .env_remove("AWS_PROFILE")
            .env_remove("AWS_WEB_IDENTITY_TOKEN_FILE")
            .env_remove("AWS_ROLE_ARN")
            .env_remove("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
            .env_remove("AWS_CONTAINER_CREDENTIALS_FULL_URI")
            .env_remove("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(payload_segment_size) = args.payload_segment_size {
            child.env(
                "RS3_PAYLOAD_SEGMENT_SIZE_BYTES",
                payload_segment_size.to_string(),
            );
        }

        let mut child = child
            .spawn()
            .context("failed to start rs3-server process")?;
        let stdout = child
            .stdout
            .take()
            .context("gateway stdout was not captured")?;
        let stderr = child
            .stderr
            .take()
            .context("gateway stderr was not captured")?;
        let logs = Arc::new(Mutex::new(Vec::new()));
        let mirror_logs = args.trace;
        let readers = vec![
            spawn_gateway_log_reader(stdout, Arc::clone(&logs), mirror_logs),
            spawn_gateway_log_reader(stderr, Arc::clone(&logs), mirror_logs),
        ];

        let mut gateway = Self {
            addr,
            child,
            logs,
            readers,
        };
        if let Err(error) = wait_for_gateway(addr, &mut gateway).await {
            let _ = gateway.shutdown();
            return Err(error);
        }
        gateway.reset_captured_metrics().await?;

        Ok(gateway)
    }

    async fn reset_captured_metrics(&self) -> Result<()> {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut logs = self
            .logs
            .lock()
            .map_err(|_| anyhow::anyhow!("gateway log capture lock poisoned"))?;
        logs.clear();
        Ok(())
    }

    async fn backend_operation_counts(&self) -> Result<BlobOperationCounts> {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let logs = self
            .logs
            .lock()
            .map_err(|_| anyhow::anyhow!("gateway log capture lock poisoned"))?;
        Ok(parse_gateway_backend_counts(&logs))
    }

    fn captured_log_tail(&self, max_lines: usize) -> Result<String> {
        let logs = self
            .logs
            .lock()
            .map_err(|_| anyhow::anyhow!("gateway log capture lock poisoned"))?;
        if logs.is_empty() {
            return Ok("gateway log tail:\n<empty>\n".to_owned());
        }

        let mut out = String::from("gateway log tail:\n");
        let start = logs.len().saturating_sub(max_lines);
        for line in &logs[start..] {
            out.push_str(line);
            out.push('\n');
        }
        Ok(out)
    }

    fn shutdown(&mut self) -> Result<()> {
        if self
            .child
            .try_wait()
            .context("failed to inspect gateway process")?
            .is_none()
        {
            self.child
                .kill()
                .context("failed to stop gateway process")?;
        }
        let _status = self
            .child
            .wait()
            .context("failed to reap gateway process")?;
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
        Ok(())
    }
}

fn adaptive_payload_segment_size(args: &PerfArgs) -> bool {
    args.payload_segment_size.is_none()
}

fn spawn_gateway_log_reader<R>(
    reader: R,
    logs: Arc<Mutex<Vec<String>>>,
    mirror_logs: bool,
) -> JoinHandle<()>
where
    R: std::io::Read + Send + 'static,
{
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            let Ok(line) = line else {
                break;
            };
            if mirror_logs {
                eprintln!("{line}");
            }
            if let Ok(mut captured) = logs.lock() {
                captured.push(line);
            }
        }
    })
}

impl Drop for RunningPerfGateway {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn parse_gateway_backend_counts(logs: &[String]) -> BlobOperationCounts {
    let mut counts = BlobOperationCounts::default();
    for line in logs {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let fields = value.get("fields").unwrap_or(&value);
        if json_field_str(fields, "provider") != Some("s3") {
            continue;
        }
        let Some(operation) = json_field_str(fields, "operation") else {
            continue;
        };
        match operation {
            "put" => counts.put = counts.put.saturating_add(1),
            "get" => counts.get = counts.get.saturating_add(1),
            "head" => counts.head = counts.head.saturating_add(1),
            "list" => counts.list = counts.list.saturating_add(1),
            "delete" => counts.delete = counts.delete.saturating_add(1),
            "extend_retention" => {
                counts.extend_retention = counts.extend_retention.saturating_add(1);
            }
            "set_legal_hold" => {
                counts.set_legal_hold = counts.set_legal_hold.saturating_add(1);
            }
            _ => continue,
        }

        if json_field_str(fields, "result") == Some("ok") {
            counts.bytes_written = counts
                .bytes_written
                .saturating_add(json_field_u64(fields, "bytes_sent"));
            counts.bytes_read = counts
                .bytes_read
                .saturating_add(json_field_u64(fields, "bytes_received"));
        }
    }
    counts
}

fn json_field_str<'a>(fields: &'a Value, key: &str) -> Option<&'a str> {
    fields.get(key).and_then(Value::as_str)
}

fn json_field_u64(fields: &Value, key: &str) -> u64 {
    fields
        .get(key)
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        })
        .unwrap_or(0)
}

fn reserve_gateway_addr() -> Result<SocketAddr> {
    let listener =
        TcpListener::bind("127.0.0.1:0").context("failed to reserve gateway listen port")?;
    let addr = listener
        .local_addr()
        .context("failed to read reserved gateway listen port")?;
    drop(listener);
    Ok(addr)
}

async fn wait_for_gateway(addr: SocketAddr, gateway: &mut RunningPerfGateway) -> Result<()> {
    let started = Instant::now();
    loop {
        if let Some(status) = gateway
            .child
            .try_wait()
            .context("failed to inspect gateway process")?
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
            anyhow::bail!(
                "gateway process exited before accepting connections: {status}\n{}",
                gateway.captured_log_tail(80)?
            );
        }

        if TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        if started.elapsed() >= GATEWAY_START_TIMEOUT {
            anyhow::bail!(
                "gateway did not start accepting connections at {addr} within {:?}\n{}",
                GATEWAY_START_TIMEOUT,
                gateway.captured_log_tail(80)?
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn default_gateway_prefix() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    format!("rs3-gateway-perf-{}-{millis}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::parse_gateway_backend_counts;

    #[test]
    fn parses_gateway_backend_counts_from_json_logs() {
        let logs = vec![
            r#"{"target":"rs3_storage","fields":{"provider":"s3","operation":"put","result":"ok","bytes_sent":12,"bytes_received":0}}"#.to_owned(),
            r#"{"target":"rs3_storage","fields":{"provider":"s3","operation":"get","result":"ok","bytes_sent":0,"bytes_received":7}}"#.to_owned(),
            r#"{"target":"rs3_storage","fields":{"provider":"s3","operation":"head","result":"not_found","bytes_sent":0,"bytes_received":0}}"#.to_owned(),
            r#"{"target":"other","fields":{"provider":"memory","operation":"put","result":"ok","bytes_sent":99,"bytes_received":0}}"#.to_owned(),
            "not json".to_owned(),
        ];

        let counts = parse_gateway_backend_counts(&logs);

        assert_eq!(counts.put, 1);
        assert_eq!(counts.get, 1);
        assert_eq!(counts.head, 1);
        assert_eq!(counts.bytes_written, 12);
        assert_eq!(counts.bytes_read, 7);
    }
}
