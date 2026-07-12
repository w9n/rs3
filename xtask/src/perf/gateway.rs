//! Gateway-backed performance scenarios.

use super::{
    GatewayBuildProfile, OperationLatencyStats, PERF_REPOSITORY_FORMAT, PerfArgs, PerfReport,
    PerfScenario, ReportFormat, TemporaryBackendDir, body, checked_mul, commit_batch_items,
    commit_max_pending_items, concurrency, print_header, process_peak_rss_bytes_for_pid,
};
use crate::integration::s3_container;
use anyhow::{Context, Result};
use aws_sdk_s3::primitives::ByteStream;
use bytes::Bytes;
use rs3_storage::BlobOperationCounts;
use serde_json::Value;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpListener};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;

const GATEWAY_PUBLIC_BUCKET: &str = "client-bucket";
const GATEWAY_ACCESS_KEY_ID: &str = "rs3-fixture-access-key";
const GATEWAY_SECRET_ACCESS_KEY: &str = "rs3-fixture-secret-key";
const GATEWAY_KEYRING_ENVELOPE_OBJECT_ID: &str = "keyrings/bootstrap-envelope.json";
const GATEWAY_KEYRING_WRAPPING_KEY_HEX: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";
const GATEWAY_KEYRING_WRAPPING_KEY_ID: &str = "wrap-integration";
const GATEWAY_REPOSITORY_SALT_HEX: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";
const GATEWAY_START_TIMEOUT: Duration = Duration::from_secs(120);
const GATEWAY_OPERATION_TIMEOUT: Duration = Duration::from_secs(240);
const GATEWAY_BUFFERED_PUT_OBJECT_BYTES: usize = 64 * 1024 * 1024;
const GATEWAY_LOCAL_BUCKET: &str = "local-backend";
const GATEWAY_LOCAL_REGION: &str = "us-east-1";

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
        let standalone_prefix = format!("{}/objects/v02/", backend_prefix.trim_end_matches('/'));
        let backend_client = s3_container::s3_client_with_timeout(
            &target.endpoint_url,
            &target.region,
            &target.access_key_id,
            &target.secret_access_key,
            GATEWAY_OPERATION_TIMEOUT,
        );
        let backend = GatewayBackend::s3_container(&target, backend_prefix);
        let mut gateway = RunningPerfGateway::start(backend, args).await?;
        let client = s3_container::s3_client_with_timeout(
            &format!("http://{}", gateway.addr),
            &target.region,
            GATEWAY_ACCESS_KEY_ID,
            GATEWAY_SECRET_ACCESS_KEY,
            GATEWAY_OPERATION_TIMEOUT,
        );

        if args.format == ReportFormat::Tsv {
            print_header();
        }
        for scenario in scenarios {
            let report = run_gateway_perf_scenario(args, scenario, &client, &gateway).await?;
            if scenario == PerfScenario::WriteStandaloneParallel {
                enforce_standalone_backend_shape(
                    &backend_client,
                    &target.bucket,
                    &standalone_prefix,
                    args.objects,
                )
                .await?;
            }
            let peak_rss_bytes = gateway.peak_rss_bytes();
            enforce_gateway_report(args, &report, peak_rss_bytes)?;
            report.print_with_peak_rss(args.format, peak_rss_bytes)?;
        }

        gateway.shutdown()?;
        Ok(())
    })
}

async fn enforce_standalone_backend_shape(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    prefix: &str,
    expected_objects: usize,
) -> Result<()> {
    let output = client
        .list_objects_v2()
        .bucket(bucket)
        .prefix(prefix)
        .send()
        .await
        .context("failed to inspect standalone backend shape")?;
    if output.is_truncated() == Some(true) {
        anyhow::bail!("standalone backend-shape check exceeded one bounded page");
    }
    let actual_objects = output.contents().len();
    if actual_objects != expected_objects {
        anyhow::bail!(
            "standalone backend-shape mismatch: found {actual_objects} opaque payload objects, expected {expected_objects}"
        );
    }
    Ok(())
}

pub(super) fn run_gateway_filesystem_perf(args: &PerfArgs) -> Result<()> {
    let backend_root = TemporaryBackendDir::new()?;
    run_local_gateway_perf(args, GatewayBackend::filesystem(backend_root.path()))
}

pub(super) fn run_gateway_memory_perf(args: &PerfArgs) -> Result<()> {
    run_local_gateway_perf(args, GatewayBackend::memory())
}

fn run_local_gateway_perf(args: &PerfArgs, backend: GatewayBackend) -> Result<()> {
    let scenarios = gateway_perf_scenarios(args.scenario)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build gateway perf runtime")?;

    runtime.block_on(async {
        let mut gateway = RunningPerfGateway::start(backend, args).await?;
        let client = s3_container::s3_client_with_timeout(
            &format!("http://{}", gateway.addr),
            &gateway.region,
            GATEWAY_ACCESS_KEY_ID,
            GATEWAY_SECRET_ACCESS_KEY,
            GATEWAY_OPERATION_TIMEOUT,
        );

        if args.format == ReportFormat::Tsv {
            print_header();
        }
        for scenario in scenarios {
            let report = run_gateway_perf_scenario(args, scenario, &client, &gateway).await?;
            let peak_rss_bytes = gateway.peak_rss_bytes();
            enforce_gateway_report(args, &report, peak_rss_bytes)?;
            report.print_with_peak_rss(args.format, peak_rss_bytes)?;
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
        PerfScenario::WriteStandaloneParallel => Ok(vec![PerfScenario::WriteStandaloneParallel]),
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
        PerfScenario::WriteStandaloneParallel => {
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
            gateway.addr,
            &gateway.region,
            super::perf_object_path(index, args.logical_path_len)?
                .as_str()
                .to_owned(),
            body.clone(),
            args.gateway_unknown_length_put,
        )
        .await
        .with_context(|| format!("gateway PutObject failed for object {index}"))?;
        latencies.push(operation_started.elapsed());
    }

    let elapsed = started.elapsed();
    let counts = gateway.backend_operation_counts().await?;
    gateway_write_report(
        args,
        if args.gateway_unknown_length_put {
            "write-committed-unknown-length"
        } else {
            "write-committed"
        },
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
    if args.scenario == PerfScenario::WriteStandaloneParallel {
        if args.gateway_unknown_length_put {
            anyhow::bail!("write-standalone-parallel requires known-length gateway PUTs");
        }
        if args.object_size <= GATEWAY_BUFFERED_PUT_OBJECT_BYTES {
            anyhow::bail!(
                "write-standalone-parallel requires --object-size greater than {} bytes",
                GATEWAY_BUFFERED_PUT_OBJECT_BYTES
            );
        }
    }
    let body = body(args.object_size);
    let parallelism = concurrency(args);
    let unknown_length = args.gateway_unknown_length_put;
    let gateway_addr = gateway.addr;
    let gateway_region = gateway.region.clone();
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
            let gateway_region = gateway_region.clone();
            let key = super::perf_object_path(index, args.logical_path_len)?
                .as_str()
                .to_owned();
            handles.push(tokio::spawn(async move {
                let operation_started = Instant::now();
                gateway_put_object(
                    &client,
                    gateway_addr,
                    &gateway_region,
                    key,
                    body,
                    unknown_length,
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
        if args.scenario == PerfScenario::WriteStandaloneParallel {
            "write-standalone-parallel"
        } else if args.gateway_unknown_length_put {
            "write-committed-parallel-unknown-length"
        } else {
            "write-committed-parallel"
        },
        args.objects,
        args.objects,
        latencies,
        elapsed,
        counts,
    )
}

fn enforce_gateway_report(
    args: &PerfArgs,
    report: &PerfReport,
    peak_rss_bytes: Option<u64>,
) -> Result<()> {
    report.enforce_max_write_amplification(args.max_write_amp)?;
    report.enforce_max_verification_read_amplification(args.max_verification_read_amp)?;
    report.enforce_max_total_write_io_amplification(args.max_total_write_io_amp)?;
    report.enforce_exact_multipart_counts(args.expected_multipart_parts_per_object)?;
    report.enforce_resource_limits(
        args.max_elapsed_seconds,
        args.max_peak_rss_bytes,
        peak_rss_bytes,
    )
}

async fn gateway_full_read(
    args: &PerfArgs,
    client: &aws_sdk_s3::Client,
    gateway: &RunningPerfGateway,
) -> Result<PerfReport> {
    let key = "perf/read/full-object";
    gateway_put_object(
        client,
        gateway.addr,
        &gateway.region,
        key,
        body(args.object_size),
        false,
    )
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
        repository_format: PERF_REPOSITORY_FORMAT,
        objects: 1,
        object_size: args.object_size,
        logical_path_len: None,
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
        checkpoint: None,
        reload_verification: None,
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
    gateway_put_object(
        client,
        gateway.addr,
        &gateway.region,
        key,
        body(args.object_size),
        false,
    )
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
        repository_format: PERF_REPOSITORY_FORMAT,
        objects: 1,
        object_size: args.object_size,
        logical_path_len: None,
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
        checkpoint: None,
        reload_verification: None,
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
        repository_format: PERF_REPOSITORY_FORMAT,
        objects,
        object_size: args.object_size,
        logical_path_len: Some(args.logical_path_len),
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
        checkpoint: None,
        reload_verification: None,
    })
}

async fn gateway_put_object(
    client: &aws_sdk_s3::Client,
    gateway_addr: SocketAddr,
    gateway_region: &str,
    key: impl Into<String>,
    body: Bytes,
    unknown_length: bool,
) -> Result<()> {
    let key = key.into();
    if unknown_length {
        let gateway_region = gateway_region.to_owned();
        tokio::task::spawn_blocking(move || {
            gateway_put_object_unknown_len_with_curl(gateway_addr, &gateway_region, key, body)
        })
        .await
        .context("unknown-length gateway PutObject task did not complete")??;
        return Ok(());
    }

    client
        .put_object()
        .bucket(GATEWAY_PUBLIC_BUCKET)
        .key(key)
        .body(ByteStream::from(body))
        .send()
        .await
        .context("gateway PutObject request failed")?;
    Ok(())
}

fn gateway_put_object_unknown_len_with_curl(
    gateway_addr: SocketAddr,
    gateway_region: &str,
    key: String,
    body: Bytes,
) -> Result<()> {
    let url = format!("http://{gateway_addr}/{GATEWAY_PUBLIC_BUCKET}/{key}");
    let sigv4 = format!("aws:amz:{gateway_region}:s3");
    let user = format!("{GATEWAY_ACCESS_KEY_ID}:{GATEWAY_SECRET_ACCESS_KEY}");
    let mut child = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--http1.1",
            "--aws-sigv4",
            &sigv4,
            "--user",
            &user,
            "--upload-file",
            "-",
            "--header",
            "x-amz-content-sha256: UNSIGNED-PAYLOAD",
            "--header",
            "Transfer-Encoding: chunked",
            "--header",
            "Content-Length:",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            &url,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to start curl for unknown-length gateway PutObject")?;
    let mut stdin = child.stdin.take().context("curl stdin was not captured")?;
    let write_error = stdin.write_all(&body).err().map(|error| error.to_string());
    drop(stdin);

    let output = child
        .wait_with_output()
        .context("failed to wait for curl unknown-length PutObject")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if write_error.is_none() && output.status.success() && stdout.trim() == "200" {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    anyhow::bail!(
        "curl unknown-length PutObject failed with status {} write_error {:?} stdout {:?} stderr {:?}",
        output.status,
        write_error,
        stdout.trim(),
        stderr.trim()
    );
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
    region: String,
    child: Child,
    metrics_source: GatewayMetricsSource,
    logs: Arc<Mutex<Vec<String>>>,
    readers: Vec<JoinHandle<()>>,
}

#[derive(Clone, Copy)]
enum GatewayMetricsSource {
    S3Provider,
    GenericStorage,
}

struct GatewayBackend {
    endpoint: String,
    bucket: String,
    prefix: String,
    region: String,
    credentials: Option<(String, String)>,
    enable_s3_feature: bool,
    metrics_source: GatewayMetricsSource,
}

impl GatewayBackend {
    fn s3_container(backend: &s3_container::RunningS3Container, prefix: String) -> Self {
        Self {
            endpoint: backend.endpoint_url.clone(),
            bucket: backend.bucket.clone(),
            prefix,
            region: backend.region.clone(),
            credentials: Some((
                backend.access_key_id.clone(),
                backend.secret_access_key.clone(),
            )),
            enable_s3_feature: true,
            metrics_source: GatewayMetricsSource::S3Provider,
        }
    }

    fn filesystem(root: &std::path::Path) -> Self {
        Self {
            endpoint: format!("file://{}", root.display()),
            bucket: GATEWAY_LOCAL_BUCKET.to_owned(),
            prefix: default_gateway_prefix(),
            region: GATEWAY_LOCAL_REGION.to_owned(),
            credentials: None,
            enable_s3_feature: false,
            metrics_source: GatewayMetricsSource::GenericStorage,
        }
    }

    fn memory() -> Self {
        Self {
            endpoint: "memory://local".to_owned(),
            bucket: GATEWAY_LOCAL_BUCKET.to_owned(),
            prefix: default_gateway_prefix(),
            region: GATEWAY_LOCAL_REGION.to_owned(),
            credentials: None,
            enable_s3_feature: false,
            metrics_source: GatewayMetricsSource::GenericStorage,
        }
    }
}

impl RunningPerfGateway {
    async fn start(backend: GatewayBackend, args: &PerfArgs) -> Result<Self> {
        let addr = reserve_gateway_addr()?;
        let mut child = Command::new("cargo");
        child.arg("run").args(["-p", "rs3-server"]);
        if backend.enable_s3_feature {
            child.args(["--features", "s3"]);
        }
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
            .env("RS3_BACKEND_ENDPOINT", &backend.endpoint)
            .env("RS3_BACKEND_BUCKET", &backend.bucket)
            .env("RS3_BACKEND_PREFIX", &backend.prefix)
            .env("RS3_ANCHOR_MODE", "memory")
            .env("RS3_ALLOW_MEMORY_ANCHOR", "true")
            .env("RS3_ADMIN_PROFILE", "local")
            .env("RS3_ALLOW_REPOSITORY_INIT", "true")
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
        if let Some((access_key_id, secret_access_key)) = &backend.credentials {
            child
                .env("AWS_ACCESS_KEY_ID", access_key_id)
                .env("AWS_SECRET_ACCESS_KEY", secret_access_key);
        } else {
            child
                .env_remove("AWS_ACCESS_KEY_ID")
                .env_remove("AWS_SECRET_ACCESS_KEY");
        }
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
            region: backend.region,
            child,
            metrics_source: backend.metrics_source,
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
        let counts = parse_gateway_backend_counts(&logs, self.metrics_source);
        counts.context("gateway backend emitted no matching rs3_storage operation evidence")
    }

    fn peak_rss_bytes(&self) -> Option<u64> {
        process_peak_rss_bytes_for_pid(self.child.id())
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

fn parse_gateway_backend_counts(
    logs: &[String],
    metrics_source: GatewayMetricsSource,
) -> Option<BlobOperationCounts> {
    let mut counts = BlobOperationCounts::default();
    let mut observed_operation = false;
    for line in logs {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let fields = value.get("fields").unwrap_or(&value);
        let Some(operation) = json_field_str(fields, "operation") else {
            continue;
        };
        match metrics_source {
            GatewayMetricsSource::S3Provider => {
                if json_field_str(fields, "provider") != Some("s3") {
                    continue;
                }
                if !count_backend_operation(&mut counts, operation) {
                    continue;
                }
                observed_operation = true;
                if operation == "put" {
                    counts.bytes_uploaded_attempted = counts
                        .bytes_uploaded_attempted
                        .saturating_add(json_field_u64(fields, "bytes_sent"));
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
            GatewayMetricsSource::GenericStorage => {
                if fields.get("provider").is_some() {
                    continue;
                }
                if !count_generic_storage_operation(&mut counts, operation) {
                    continue;
                }
                observed_operation = true;
                if operation == "put" {
                    counts.bytes_uploaded_attempted = counts
                        .bytes_uploaded_attempted
                        .saturating_add(json_field_u64(fields, "requested_len"));
                }
                if json_field_str(fields, "result") == Some("ok") {
                    if operation == "put" {
                        counts.bytes_written = counts
                            .bytes_written
                            .saturating_add(json_field_u64(fields, "requested_len"));
                    } else if operation == "get_range" {
                        counts.bytes_read = counts
                            .bytes_read
                            .saturating_add(json_field_u64(fields, "bytes_read"));
                    }
                }
            }
        }
    }
    observed_operation.then_some(counts)
}

fn count_backend_operation(counts: &mut BlobOperationCounts, operation: &str) -> bool {
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
        _ => return false,
    }
    true
}

fn count_generic_storage_operation(counts: &mut BlobOperationCounts, operation: &str) -> bool {
    let provider_operation = match operation {
        "get_range" => "get",
        "list_prefix" => "list",
        operation => operation,
    };
    count_backend_operation(counts, provider_operation)
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
    use super::{GatewayMetricsSource, parse_gateway_backend_counts};

    #[test]
    fn parses_gateway_backend_counts_from_json_logs() {
        let logs = vec![
            r#"{"target":"rs3_storage","fields":{"provider":"s3","operation":"put","result":"ok","bytes_sent":12,"bytes_received":0}}"#.to_owned(),
            r#"{"target":"rs3_storage","fields":{"provider":"s3","operation":"get","result":"ok","bytes_sent":0,"bytes_received":7}}"#.to_owned(),
            r#"{"target":"rs3_storage","fields":{"provider":"s3","operation":"head","result":"not_found","bytes_sent":0,"bytes_received":0}}"#.to_owned(),
            r#"{"target":"other","fields":{"provider":"memory","operation":"put","result":"ok","bytes_sent":99,"bytes_received":0}}"#.to_owned(),
            "not json".to_owned(),
        ];

        let counts = parse_gateway_backend_counts(&logs, GatewayMetricsSource::S3Provider)
            .unwrap_or_else(|| panic!("expected S3 provider operation evidence"));

        assert_eq!(counts.put, 1);
        assert_eq!(counts.get, 1);
        assert_eq!(counts.head, 1);
        assert_eq!(counts.bytes_uploaded_attempted, 12);
        assert_eq!(counts.bytes_written, 12);
        assert_eq!(counts.bytes_read, 7);
    }

    #[test]
    fn parses_gateway_backend_counts_from_generic_storage_logs() {
        let logs = vec![
            r#"{"target":"rs3_storage","fields":{"operation":"put","requested_len":12,"result":"ok"}}"#.to_owned(),
            r#"{"target":"rs3_storage","fields":{"operation":"get_range","bytes_read":7,"result":"ok"}}"#.to_owned(),
            r#"{"target":"rs3_storage","fields":{"operation":"head","result":"not_found"}}"#.to_owned(),
            r#"{"target":"rs3_storage","fields":{"operation":"list_prefix","result":"ok"}}"#.to_owned(),
            r#"{"target":"rs3_storage","fields":{"provider":"s3","operation":"put","result":"ok","bytes_sent":99}}"#.to_owned(),
        ];

        let counts = parse_gateway_backend_counts(&logs, GatewayMetricsSource::GenericStorage)
            .unwrap_or_else(|| panic!("expected generic storage operation evidence"));

        assert_eq!(counts.put, 1);
        assert_eq!(counts.get, 1);
        assert_eq!(counts.head, 1);
        assert_eq!(counts.list, 1);
        assert_eq!(counts.bytes_uploaded_attempted, 12);
        assert_eq!(counts.bytes_written, 12);
        assert_eq!(counts.bytes_read, 7);
    }

    #[test]
    fn generic_storage_counts_are_unavailable_without_operation_evidence() {
        let logs = vec!["not json".to_owned()];

        assert!(
            parse_gateway_backend_counts(&logs, GatewayMetricsSource::GenericStorage).is_none()
        );
    }
}
