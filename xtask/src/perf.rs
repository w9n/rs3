//! Performance scenario harness.

#[cfg(feature = "containers")]
mod gateway;

#[cfg(feature = "containers")]
use crate::integration::{S3ContainerProvider, s3_container};
use anyhow::{Context, Result};
use bytes::Bytes;
use clap::{Args, ValueEnum};
use rs3_crypto::{KeyMaterial, KeyRing, SecretBytes};
use rs3_repository::v2::{
    UnenforcedQuiescedMaintenanceGuard, V2CommitCoordinator, V2CommitStoreOptions, V2FormatRef,
    V2KeyringEnvelopeRef, V2MemoryAnchor, V2ProviderProfile, V2Repository,
};
use rs3_repository::{
    CommitCoordinatorOptions, DEFAULT_PAYLOAD_SEGMENT_SIZE, RepositoryOptions, RepositoryPutOptions,
};
use rs3_storage::{
    BlobOperationCounts, BlobStore, ByteRange, CountingBlobStore, FilesystemBlobStore,
    MemoryBlobStore,
};
#[cfg(feature = "s3")]
use rs3_storage::{S3BlobStore, S3BlobStoreConfig};
use rs3_types::{
    BackendObjectId, BackendVersionId, KeyDescriptor, KeyId, KeyPurpose, KeyStatus, LogicalPath,
    RepositoryId,
};
use std::path::{Path, PathBuf};
#[cfg(feature = "containers")]
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing_subscriber::EnvFilter;

pub(super) const PERF_REPOSITORY_FORMAT: &str = "v2-preview";

/// Runs lightweight repository performance scenarios.
#[derive(Debug, Args)]
pub(crate) struct PerfArgs {
    /// Scenario to run.
    #[arg(long, value_enum, default_value_t = PerfScenario::All)]
    scenario: PerfScenario,
    /// Number of objects written by write scenarios.
    #[arg(long, default_value_t = 32)]
    objects: usize,
    /// Plaintext object size in bytes.
    #[arg(long, default_value_t = 1024 * 1024)]
    object_size: usize,
    /// Maximum number of committed writes covered by one repository commit.
    #[arg(long, default_value_t = 64)]
    commit_batch_items: usize,
    /// Maximum commit batching delay in milliseconds.
    #[arg(long, default_value_t = 10)]
    commit_batch_delay_ms: u64,
    /// Maximum committed writes allowed to wait for repository commit publication.
    #[arg(long)]
    commit_max_pending_items: Option<usize>,
    /// Parallel client writes used by parallel scenarios.
    #[arg(long, default_value_t = 8)]
    concurrency: usize,
    /// Reload and verify parallel committed writes through a new repository instance.
    #[arg(long)]
    verify_reload: bool,
    /// Publish one signed index-root checkpoint after at least this many writes.
    #[arg(long, requires = "verify_reload")]
    checkpoint_after_objects: Option<usize>,
    /// Fail a write scenario when backend bytes exceed this plaintext ratio.
    #[arg(long)]
    max_write_amp: Option<f64>,
    /// Fail a scenario when its elapsed time exceeds this many seconds.
    #[arg(long)]
    max_elapsed_seconds: Option<f64>,
    /// Fail a scenario when the harness process peak RSS exceeds this many bytes.
    #[arg(long)]
    max_peak_rss_bytes: Option<u64>,
    /// Fail reload verification when cold-read bytes exceed this plaintext ratio.
    #[arg(long, requires = "verify_reload")]
    max_cold_read_amp: Option<f64>,
    /// Fail reload verification above this many backend requests per cold read.
    #[arg(long, requires = "verify_reload")]
    max_cold_read_requests_per_read: Option<f64>,
    /// Fail reload verification above this many active authenticated index runs.
    #[arg(long, requires = "verify_reload")]
    max_active_index_runs: Option<usize>,
    /// Number of read operations in read scenarios.
    #[arg(long, default_value_t = 128)]
    reads: usize,
    /// Plaintext range length in bytes for range-read scenarios.
    #[arg(long, default_value_t = 4 * 1024)]
    range_len: usize,
    /// Force a fixed payload segment size. Omit to use adaptive per-object sizing.
    #[arg(long)]
    payload_segment_size: Option<usize>,
    /// Backend implementation used by the scenario.
    #[arg(long, value_enum, default_value_t = PerfBackend::Memory)]
    backend: PerfBackend,
    /// Gateway process build profile used by gateway-backed scenarios.
    #[arg(long, value_enum, default_value_t = GatewayBuildProfile::Dev)]
    gateway_build_profile: GatewayBuildProfile,
    /// Send gateway write-scenario PUT bodies without a known Content-Length.
    #[arg(long)]
    gateway_unknown_length_put: bool,
    /// Filesystem backend root used with `--backend filesystem`.
    #[arg(long)]
    backend_dir: Option<PathBuf>,
    /// S3 bucket used with `--backend s3`.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_PERF_S3_BUCKET")]
    s3_bucket: Option<String>,
    /// S3 key prefix used with `--backend s3`.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_PERF_S3_PREFIX")]
    s3_prefix: Option<String>,
    /// Custom S3 endpoint URL used with `--backend s3`.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_PERF_S3_ENDPOINT_URL")]
    s3_endpoint_url: Option<String>,
    /// AWS region override used with `--backend s3`.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_PERF_S3_REGION")]
    s3_region: Option<String>,
    /// Allow plain HTTP for local S3-compatible endpoints used with `--backend s3`.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_PERF_S3_ALLOW_HTTP", default_value_t = false)]
    s3_allow_http: bool,
    /// Use virtual-hosted bucket addressing instead of path-style addressing.
    #[cfg(feature = "s3")]
    #[arg(
        long,
        env = "RS3_PERF_S3_VIRTUAL_HOSTED_STYLE",
        default_value_t = false
    )]
    s3_virtual_hosted_style: bool,
    /// Local S3-compatible container provider used with `--backend s3-container`.
    #[cfg(feature = "containers")]
    #[arg(long, value_enum, default_value_t = S3ContainerProvider::Rustfs)]
    container_provider: S3ContainerProvider,
    /// Output format for scenario reports.
    #[arg(long, value_enum, default_value_t = ReportFormat::Tsv)]
    format: ReportFormat,
    /// Enable tracing subscriber output while scenarios run.
    #[arg(long)]
    trace: bool,
    /// Tracing filter used when `--trace` is enabled.
    #[arg(long, default_value = "rs3_repository=info,rs3_storage=debug")]
    trace_filter: String,
    /// Tracing output format used when `--trace` is enabled.
    #[arg(long, value_enum, default_value_t = TraceFormat::Plain)]
    trace_format: TraceFormat,
}

/// Available performance scenarios.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum PerfScenario {
    /// Run every built-in scenario.
    All,
    /// Stage many objects and publish one repository commit.
    WriteBatch,
    /// Write objects through the commit coordinator sequentially.
    WriteCommitted,
    /// Write objects through the commit coordinator concurrently.
    WriteCommittedParallel,
    /// Repeatedly read a full object.
    FullRead,
    /// Repeatedly read plaintext ranges from one object.
    RangeRead,
}

/// Backend implementation used by performance scenarios.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum PerfBackend {
    /// In-memory backend.
    Memory,
    /// Local filesystem backend.
    Filesystem,
    /// S3-compatible backend using the default environment/config chain.
    #[cfg(feature = "s3")]
    S3,
    /// Ephemeral local S3-compatible container.
    #[cfg(feature = "containers")]
    S3Container,
    /// Gateway process backed by an ephemeral local S3-compatible container.
    #[cfg(feature = "containers")]
    S3GatewayContainer,
}

impl PerfBackend {
    fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Filesystem => "filesystem",
            #[cfg(feature = "s3")]
            Self::S3 => "s3",
            #[cfg(feature = "containers")]
            Self::S3Container => "s3-container",
            #[cfg(feature = "containers")]
            Self::S3GatewayContainer => "s3-gateway-container",
        }
    }
}

/// Gateway process build profile used by gateway-backed performance scenarios.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum GatewayBuildProfile {
    /// Cargo dev profile.
    Dev,
    /// Cargo release profile.
    Release,
}

#[cfg(feature = "containers")]
impl GatewayBuildProfile {
    pub(crate) const fn as_cli_value(self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Release => "release",
        }
    }
}

#[cfg(feature = "containers")]
impl PerfScenario {
    fn as_cli_value(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::WriteBatch => "write-batch",
            Self::WriteCommitted => "write-committed",
            Self::WriteCommittedParallel => "write-committed-parallel",
            Self::FullRead => "full-read",
            Self::RangeRead => "range-read",
        }
    }
}

/// Machine-readable report output options.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum ReportFormat {
    /// Tab-separated table.
    Tsv,
    /// One JSON object per scenario.
    Jsonl,
}

#[cfg(feature = "containers")]
impl ReportFormat {
    fn as_cli_value(self) -> &'static str {
        match self {
            Self::Tsv => "tsv",
            Self::Jsonl => "jsonl",
        }
    }
}

/// Trace subscriber output options.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum TraceFormat {
    /// Human-readable tracing output.
    Plain,
    /// JSON tracing output.
    Json,
}

#[cfg(feature = "containers")]
impl TraceFormat {
    fn as_cli_value(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Json => "json",
        }
    }
}

pub(crate) fn run(args: PerfArgs) -> Result<()> {
    let cold_read_limits_requested =
        args.max_cold_read_amp.is_some() || args.max_cold_read_requests_per_read.is_some();
    let reload_limits_requested =
        cold_read_limits_requested || args.max_active_index_runs.is_some();
    if reload_limits_requested && !args.verify_reload {
        anyhow::bail!("reload limits require --verify-reload");
    }
    if args.verify_reload
        && !matches!(
            args.scenario,
            PerfScenario::All | PerfScenario::WriteCommittedParallel
        )
    {
        anyhow::bail!(
            "--verify-reload requires --scenario write-committed-parallel (or --scenario all)"
        );
    }
    if args
        .checkpoint_after_objects
        .is_some_and(|objects| objects == 0 || objects > args.objects)
    {
        anyhow::bail!("--checkpoint-after-objects must be between 1 and --objects");
    }
    if args
        .max_write_amp
        .is_some_and(|limit| !limit.is_finite() || limit <= 0.0)
    {
        anyhow::bail!("--max-write-amp must be finite and greater than zero");
    }
    if args
        .max_elapsed_seconds
        .is_some_and(|limit| !limit.is_finite() || limit <= 0.0)
    {
        anyhow::bail!("--max-elapsed-seconds must be finite and greater than zero");
    }
    if args.max_peak_rss_bytes == Some(0) {
        anyhow::bail!("--max-peak-rss-bytes must be greater than zero");
    }
    if args
        .max_cold_read_amp
        .is_some_and(|limit| !limit.is_finite() || limit <= 0.0)
    {
        anyhow::bail!("--max-cold-read-amp must be finite and greater than zero");
    }
    if args
        .max_cold_read_requests_per_read
        .is_some_and(|limit| !limit.is_finite() || limit <= 0.0)
    {
        anyhow::bail!("--max-cold-read-requests-per-read must be finite and greater than zero");
    }
    if cold_read_limits_requested && args.objects == 0 {
        anyhow::bail!("cold-read limits require at least one object");
    }
    if args.max_cold_read_amp.is_some() && args.object_size == 0 {
        anyhow::bail!("--max-cold-read-amp requires a non-empty object");
    }
    if args.max_active_index_runs == Some(0) {
        anyhow::bail!("--max-active-index-runs must be greater than zero");
    }
    #[cfg(feature = "containers")]
    if args.verify_reload && args.backend == PerfBackend::S3GatewayContainer {
        anyhow::bail!("--verify-reload is not supported by the gateway-backed perf harness");
    }

    if args.trace {
        init_tracing(&args.trace_filter, args.trace_format)?;
    }

    #[cfg(feature = "containers")]
    if args.backend == PerfBackend::S3Container {
        return run_s3_container_perf(&args);
    }
    #[cfg(feature = "containers")]
    if args.backend == PerfBackend::S3GatewayContainer {
        return gateway::run_s3_gateway_container_perf(&args);
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build perf runtime")?;
    runtime.block_on(run_async(args))
}

async fn run_async(args: PerfArgs) -> Result<()> {
    let scenarios = match args.scenario {
        PerfScenario::All => vec![
            PerfScenario::WriteBatch,
            PerfScenario::WriteCommitted,
            PerfScenario::WriteCommittedParallel,
            PerfScenario::FullRead,
            PerfScenario::RangeRead,
        ],
        scenario => vec![scenario],
    };

    if args.format == ReportFormat::Tsv {
        print_header();
    }
    let reload_limits_requested = args.max_cold_read_amp.is_some()
        || args.max_cold_read_requests_per_read.is_some()
        || args.max_active_index_runs.is_some();
    let mut reload_gate_evaluated = false;
    for scenario in scenarios {
        let report = match scenario {
            PerfScenario::All => unreachable!("expanded above"),
            PerfScenario::WriteBatch => write_batch(&args).await?,
            PerfScenario::WriteCommitted => write_committed(&args).await?,
            PerfScenario::WriteCommittedParallel => write_committed_parallel(&args).await?,
            PerfScenario::FullRead => full_read(&args).await?,
            PerfScenario::RangeRead => range_read(&args).await?,
        };
        let peak_rss_bytes = process_peak_rss_bytes();
        report.enforce_max_write_amplification(args.max_write_amp)?;
        report.enforce_resource_limits(
            args.max_elapsed_seconds,
            args.max_peak_rss_bytes,
            peak_rss_bytes,
        )?;
        if report.reload_verification.is_some() {
            report.enforce_cold_read_limits(
                args.max_cold_read_amp,
                args.max_cold_read_requests_per_read,
            )?;
            report.enforce_active_index_run_limit(args.max_active_index_runs)?;
            reload_gate_evaluated = reload_limits_requested;
        }
        report.print_with_peak_rss(args.format, peak_rss_bytes)?;
    }
    if reload_limits_requested && !reload_gate_evaluated {
        anyhow::bail!("reload limits did not receive verification evidence");
    }

    Ok(())
}

#[cfg(feature = "containers")]
fn run_s3_container_perf(args: &PerfArgs) -> Result<()> {
    let target = s3_container::start_s3_container(
        args.container_provider,
        args.s3_bucket.clone(),
        args.s3_region.clone(),
    )?;
    let mut command = Command::new("cargo");
    command.args(["run", "-p", "xtask", "--features", "s3", "--", "perf"]);
    add_perf_args(&mut command, args, &target);
    command.env("AWS_ACCESS_KEY_ID", &target.access_key_id);
    command.env("AWS_SECRET_ACCESS_KEY", &target.secret_access_key);
    command.env("AWS_DEFAULT_REGION", &target.region);
    command.env_remove("AWS_SESSION_TOKEN");
    command.env_remove("AWS_PROFILE");
    command.env_remove("AWS_WEB_IDENTITY_TOKEN_FILE");
    command.env_remove("AWS_ROLE_ARN");
    command.env_remove("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI");
    command.env_remove("AWS_CONTAINER_CREDENTIALS_FULL_URI");
    command.env_remove("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE");

    let status = command
        .status()
        .context("failed to start container-backed S3 perf run")?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("container-backed S3 perf run exited with {status}");
    }
}

#[cfg(feature = "containers")]
fn add_perf_args(
    command: &mut Command,
    args: &PerfArgs,
    target: &s3_container::RunningS3Container,
) {
    command.args(["--scenario", args.scenario.as_cli_value()]);
    command.args(["--objects", &args.objects.to_string()]);
    command.args(["--object-size", &args.object_size.to_string()]);
    command.args([
        "--gateway-build-profile",
        args.gateway_build_profile.as_cli_value(),
    ]);
    if args.gateway_unknown_length_put {
        command.arg("--gateway-unknown-length-put");
    }
    command.args(["--commit-batch-items", &args.commit_batch_items.to_string()]);
    command.args([
        "--commit-batch-delay-ms",
        &args.commit_batch_delay_ms.to_string(),
    ]);
    if let Some(max_pending_items) = args.commit_max_pending_items {
        command.args(["--commit-max-pending-items", &max_pending_items.to_string()]);
    }
    command.args(["--concurrency", &args.concurrency.to_string()]);
    if args.verify_reload {
        command.arg("--verify-reload");
    }
    if let Some(checkpoint_after_objects) = args.checkpoint_after_objects {
        command.args([
            "--checkpoint-after-objects",
            &checkpoint_after_objects.to_string(),
        ]);
    }
    if let Some(max_write_amp) = args.max_write_amp {
        command.args(["--max-write-amp", &max_write_amp.to_string()]);
    }
    if let Some(limit) = args.max_elapsed_seconds {
        command.args(["--max-elapsed-seconds", &limit.to_string()]);
    }
    if let Some(limit) = args.max_peak_rss_bytes {
        command.args(["--max-peak-rss-bytes", &limit.to_string()]);
    }
    if let Some(max_cold_read_amp) = args.max_cold_read_amp {
        command.args(["--max-cold-read-amp", &max_cold_read_amp.to_string()]);
    }
    if let Some(limit) = args.max_cold_read_requests_per_read {
        command.args(["--max-cold-read-requests-per-read", &limit.to_string()]);
    }
    if let Some(limit) = args.max_active_index_runs {
        command.args(["--max-active-index-runs", &limit.to_string()]);
    }
    command.args(["--reads", &args.reads.to_string()]);
    command.args(["--range-len", &args.range_len.to_string()]);
    if let Some(payload_segment_size) = args.payload_segment_size {
        command.args(["--payload-segment-size", &payload_segment_size.to_string()]);
    }
    command.args(["--backend", "s3"]);
    command.args(["--s3-bucket", &target.bucket]);
    command.args(["--s3-endpoint-url", &target.endpoint_url]);
    command.args(["--s3-region", &target.region]);
    if let Some(prefix) = args.s3_prefix.as_deref() {
        command.args(["--s3-prefix", prefix]);
    }
    command.arg("--s3-allow-http");
    command.args(["--format", args.format.as_cli_value()]);
    if args.trace {
        command.arg("--trace");
        command.args(["--trace-filter", &args.trace_filter]);
        command.args(["--trace-format", args.trace_format.as_cli_value()]);
    }
}

async fn write_batch(args: &PerfArgs) -> Result<PerfReport> {
    match args.backend {
        PerfBackend::Memory => write_batch_with_store(args, memory_store()).await,
        PerfBackend::Filesystem => {
            let (_dir, store) = filesystem_store(args)?;
            write_batch_with_store(args, store).await
        }
        #[cfg(feature = "s3")]
        PerfBackend::S3 => write_batch_with_store(args, s3_store(args).await?).await,
        #[cfg(feature = "containers")]
        PerfBackend::S3Container | PerfBackend::S3GatewayContainer => {
            unreachable!("handled before scenario dispatch")
        }
    }
}

async fn write_batch_with_store<S>(
    args: &PerfArgs,
    store: CountingBlobStore<S>,
) -> Result<PerfReport>
where
    S: BlobStore + Clone + Send + Sync + 'static,
{
    let (repo, anchor) = v2_repository_with_store(args, store.clone()).await?;
    let batch_items = args.objects.max(1);
    let coordinator = Arc::new(
        V2CommitCoordinator::with_options(
            repo,
            anchor,
            CommitCoordinatorOptions::new(
                batch_items,
                Duration::from_millis(args.commit_batch_delay_ms),
            )
            .with_max_pending_items(batch_items),
        )
        .with_maintenance_guard(UnenforcedQuiescedMaintenanceGuard),
    );
    store
        .reset_operation_counts()
        .context("failed to reset operation counts")?;
    let body = body(args.object_size);
    let mut latencies = Vec::with_capacity(args.objects);
    let started = Instant::now();

    let mut handles = Vec::with_capacity(args.objects);
    for index in 0..args.objects {
        let coordinator = Arc::clone(&coordinator);
        let body = body.clone();
        handles.push(tokio::spawn(async move {
            let operation_started = Instant::now();
            coordinator
                .put_committed(
                    path(&format!("perf/write-batch/object-{index:08}"))?,
                    body,
                    RepositoryPutOptions::default(),
                )
                .await
                .with_context(|| format!("failed to write object {index}"))?;
            Ok::<Duration, anyhow::Error>(operation_started.elapsed())
        }));
    }
    for handle in handles {
        let latency = handle
            .await
            .context("batched v2 write task did not complete")??;
        latencies.push(latency);
    }

    let elapsed = started.elapsed();
    let counts = store
        .operation_counts()
        .context("failed to read operation counts")?;
    Ok(PerfReport {
        scenario: "write-batch",
        backend: args.backend,
        repository_format: PERF_REPOSITORY_FORMAT,
        objects: args.objects,
        object_size: args.object_size,
        operations: args.objects,
        requested_plaintext_write_bytes: checked_mul(args.objects, args.object_size)?,
        requested_plaintext_read_bytes: 0,
        commit_batch_items: batch_items,
        commit_batch_delay_ms: args.commit_batch_delay_ms,
        commit_max_pending_items: batch_items,
        payload_segment_size: args.payload_segment_size,
        adaptive_payload_segment_size: adaptive_payload_segment_size(args),
        concurrency: concurrency(args),
        operation_latency: OperationLatencyStats::from_samples(latencies),
        elapsed,
        counts,
        reload_verification: None,
    })
}

async fn write_committed(args: &PerfArgs) -> Result<PerfReport> {
    match args.backend {
        PerfBackend::Memory => write_committed_with_store(args, memory_store()).await,
        PerfBackend::Filesystem => {
            let (_dir, store) = filesystem_store(args)?;
            write_committed_with_store(args, store).await
        }
        #[cfg(feature = "s3")]
        PerfBackend::S3 => write_committed_with_store(args, s3_store(args).await?).await,
        #[cfg(feature = "containers")]
        PerfBackend::S3Container | PerfBackend::S3GatewayContainer => {
            unreachable!("handled before scenario dispatch")
        }
    }
}

async fn write_committed_with_store<S>(
    args: &PerfArgs,
    store: CountingBlobStore<S>,
) -> Result<PerfReport>
where
    S: BlobStore + Clone + 'static,
{
    let (repo, anchor) = v2_repository_with_store(args, store.clone()).await?;
    let coordinator = V2CommitCoordinator::with_options(repo, anchor, commit_options(args))
        .with_maintenance_guard(UnenforcedQuiescedMaintenanceGuard);
    store
        .reset_operation_counts()
        .context("failed to reset operation counts")?;
    let body = body(args.object_size);
    let mut latencies = Vec::with_capacity(args.objects);
    let started = Instant::now();

    for index in 0..args.objects {
        let operation_started = Instant::now();
        coordinator
            .put_committed(
                path(&format!("perf/write-committed/object-{index:08}"))?,
                body.clone(),
                RepositoryPutOptions::default(),
            )
            .await
            .with_context(|| format!("failed to commit object {index}"))?;
        latencies.push(operation_started.elapsed());
    }

    let elapsed = started.elapsed();
    let counts = store
        .operation_counts()
        .context("failed to read operation counts")?;
    Ok(PerfReport {
        scenario: "write-committed",
        backend: args.backend,
        repository_format: PERF_REPOSITORY_FORMAT,
        objects: args.objects,
        object_size: args.object_size,
        operations: args.objects,
        requested_plaintext_write_bytes: checked_mul(args.objects, args.object_size)?,
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
        reload_verification: None,
    })
}

async fn write_committed_parallel(args: &PerfArgs) -> Result<PerfReport> {
    match args.backend {
        PerfBackend::Memory => write_committed_parallel_with_store(args, memory_store()).await,
        PerfBackend::Filesystem => {
            let (_dir, store) = filesystem_store(args)?;
            write_committed_parallel_with_store(args, store).await
        }
        #[cfg(feature = "s3")]
        PerfBackend::S3 => write_committed_parallel_with_store(args, s3_store(args).await?).await,
        #[cfg(feature = "containers")]
        PerfBackend::S3Container | PerfBackend::S3GatewayContainer => {
            unreachable!("handled before scenario dispatch")
        }
    }
}

async fn write_committed_parallel_with_store<S>(
    args: &PerfArgs,
    store: CountingBlobStore<S>,
) -> Result<PerfReport>
where
    S: BlobStore + Clone + Send + Sync + 'static,
{
    let (repo, anchor) = v2_repository_with_store(args, store.clone()).await?;
    let verification_anchor = anchor.clone();
    let coordinator = Arc::new(
        V2CommitCoordinator::with_options(repo, anchor, commit_options(args))
            .with_maintenance_guard(UnenforcedQuiescedMaintenanceGuard),
    );
    store
        .reset_operation_counts()
        .context("failed to reset operation counts")?;
    let body = body(args.object_size);
    let parallelism = concurrency(args);
    let mut latencies = Vec::with_capacity(args.objects);
    let started = Instant::now();
    let mut checkpoint = None;

    let mut next = 0;
    while next < args.objects {
        let end = next.saturating_add(parallelism).min(args.objects);
        let mut handles = Vec::with_capacity(end - next);
        for index in next..end {
            let coordinator = Arc::clone(&coordinator);
            let body = body.clone();
            handles.push(tokio::spawn(async move {
                let operation_started = Instant::now();
                coordinator
                    .put_committed(
                        path(&format!("perf/write-committed-parallel/object-{index:08}"))?,
                        body,
                        RepositoryPutOptions::default(),
                    )
                    .await
                    .with_context(|| format!("failed to commit object {index}"))?;
                Ok::<Duration, anyhow::Error>(operation_started.elapsed())
            }));
        }
        for handle in handles {
            let latency = handle
                .await
                .context("committed write task did not complete")??;
            latencies.push(latency);
        }
        next = end;
        if let Some(requested_after_objects) =
            checkpoint_due(args.checkpoint_after_objects, checkpoint.is_some(), next)
        {
            let checkpoint_started = Instant::now();
            coordinator
                .write_index_snapshot()
                .await
                .context("failed to publish the scale-gate index root")?;
            checkpoint = Some(CheckpointMeasurement {
                requested_after_objects,
                actual_after_objects: next,
                elapsed: checkpoint_started.elapsed(),
            });
        }
    }

    let elapsed = started.elapsed();
    let counts = store
        .operation_counts()
        .context("failed to read operation counts")?;
    drop(coordinator);
    let reload_verification = if args.verify_reload {
        Some(
            verify_parallel_reload(args, store, &verification_anchor, &body, checkpoint)
                .await
                .context("new repository instance verification failed")?,
        )
    } else {
        None
    };
    Ok(PerfReport {
        scenario: "write-committed-parallel",
        backend: args.backend,
        repository_format: PERF_REPOSITORY_FORMAT,
        objects: args.objects,
        object_size: args.object_size,
        operations: args.objects,
        requested_plaintext_write_bytes: checked_mul(args.objects, args.object_size)?,
        requested_plaintext_read_bytes: 0,
        commit_batch_items: commit_batch_items(args),
        commit_batch_delay_ms: args.commit_batch_delay_ms,
        commit_max_pending_items: commit_max_pending_items(args),
        payload_segment_size: args.payload_segment_size,
        adaptive_payload_segment_size: adaptive_payload_segment_size(args),
        concurrency: parallelism,
        operation_latency: OperationLatencyStats::from_samples(latencies),
        elapsed,
        counts,
        reload_verification,
    })
}

async fn verify_parallel_reload<S>(
    args: &PerfArgs,
    store: CountingBlobStore<S>,
    anchor: &V2MemoryAnchor,
    expected_body: &Bytes,
    checkpoint: Option<CheckpointMeasurement>,
) -> Result<ReloadVerification>
where
    S: BlobStore + Clone,
{
    let started = Instant::now();
    let repository = v2_repository(args, store.clone())?;
    repository
        .load_chain_from_anchor(anchor)
        .await
        .context("failed to reload the accepted commit chain")?
        .context("the repository anchor did not select a commit chain")?;
    let active_index_runs = repository
        .active_index_run_count()
        .context("failed to read the recovered active index-run count")?;

    let entries = repository
        .list("perf/write-committed-parallel/")
        .context("failed to list reloaded objects")?;
    if entries.len() != args.objects {
        anyhow::bail!(
            "reloaded object count mismatch: expected {}, found {}",
            args.objects,
            entries.len()
        );
    }

    let checked_indices = verification_indices(args.objects);
    let cold_read_counts_before = store
        .operation_counts()
        .context("failed to capture pre-read backend counts")?;
    let cold_read_started = Instant::now();
    for index in &checked_indices {
        let key = path(&format!("perf/write-committed-parallel/object-{index:08}"))?;
        let actual = repository
            .get_range(&key, ByteRange::Full)
            .await
            .with_context(|| format!("failed to read reloaded object {index}"))?;
        if actual != *expected_body {
            anyhow::bail!("reloaded object {index} did not match its written payload");
        }
    }
    let cold_read_elapsed = cold_read_started.elapsed();
    let cold_read_counts_after = store
        .operation_counts()
        .context("failed to capture post-read backend counts")?;
    let cold_read_counts =
        operation_counts_delta(&cold_read_counts_after, &cold_read_counts_before)?;
    let requested_plaintext_bytes = checked_indices
        .len()
        .checked_mul(expected_body.len())
        .context("cold-read plaintext byte count overflowed usize")?;
    validate_cold_read_counts(&cold_read_counts, checked_indices.len())?;

    Ok(ReloadVerification {
        checkpoint,
        elapsed: started.elapsed(),
        expected_objects: args.objects,
        listed_objects: entries.len(),
        checked_objects: checked_indices.len(),
        active_index_runs,
        cold_reads: ColdReadMeasurement {
            elapsed: cold_read_elapsed,
            logical_reads: checked_indices.len(),
            requested_plaintext_bytes,
            counts: cold_read_counts,
        },
    })
}

fn checkpoint_due(
    requested_after_objects: Option<usize>,
    already_published: bool,
    completed_objects: usize,
) -> Option<usize> {
    if already_published {
        return None;
    }
    requested_after_objects.filter(|requested| completed_objects >= *requested)
}

fn verification_indices(objects: usize) -> Vec<usize> {
    if objects == 0 {
        return Vec::new();
    }
    let mut indices = vec![0, objects / 2, objects - 1];
    indices.sort_unstable();
    indices.dedup();
    indices
}

async fn full_read(args: &PerfArgs) -> Result<PerfReport> {
    match args.backend {
        PerfBackend::Memory => full_read_with_store(args, memory_store()).await,
        PerfBackend::Filesystem => {
            let (_dir, store) = filesystem_store(args)?;
            full_read_with_store(args, store).await
        }
        #[cfg(feature = "s3")]
        PerfBackend::S3 => full_read_with_store(args, s3_store(args).await?).await,
        #[cfg(feature = "containers")]
        PerfBackend::S3Container | PerfBackend::S3GatewayContainer => {
            unreachable!("handled before scenario dispatch")
        }
    }
}

async fn full_read_with_store<S>(args: &PerfArgs, store: CountingBlobStore<S>) -> Result<PerfReport>
where
    S: BlobStore + Clone,
{
    let (repo, anchor) = v2_repository_with_store(args, store.clone()).await?;
    let key = path("perf/read/full-object")?;
    let body = body(args.object_size);
    repo.put_committed(&anchor, key.clone(), body, RepositoryPutOptions::default())
        .await
        .context("failed to prepare full-read object")?;
    store
        .reset_operation_counts()
        .context("failed to reset operation counts")?;

    let mut latencies = Vec::with_capacity(args.reads);
    let started = Instant::now();
    for _ in 0..args.reads {
        let operation_started = Instant::now();
        repo.get_range(&key, ByteRange::Full)
            .await
            .context("failed to read full object")?;
        latencies.push(operation_started.elapsed());
    }

    let elapsed = started.elapsed();
    let counts = store
        .operation_counts()
        .context("failed to read operation counts")?;
    Ok(PerfReport {
        scenario: "full-read",
        backend: args.backend,
        repository_format: PERF_REPOSITORY_FORMAT,
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
        reload_verification: None,
    })
}

async fn range_read(args: &PerfArgs) -> Result<PerfReport> {
    match args.backend {
        PerfBackend::Memory => range_read_with_store(args, memory_store()).await,
        PerfBackend::Filesystem => {
            let (_dir, store) = filesystem_store(args)?;
            range_read_with_store(args, store).await
        }
        #[cfg(feature = "s3")]
        PerfBackend::S3 => range_read_with_store(args, s3_store(args).await?).await,
        #[cfg(feature = "containers")]
        PerfBackend::S3Container | PerfBackend::S3GatewayContainer => {
            unreachable!("handled before scenario dispatch")
        }
    }
}

async fn range_read_with_store<S>(
    args: &PerfArgs,
    store: CountingBlobStore<S>,
) -> Result<PerfReport>
where
    S: BlobStore + Clone,
{
    let (repo, anchor) = v2_repository_with_store(args, store.clone()).await?;
    let key = path("perf/read/range-object")?;
    let body = body(args.object_size);
    repo.put_committed(&anchor, key.clone(), body, RepositoryPutOptions::default())
        .await
        .context("failed to prepare range-read object")?;
    store
        .reset_operation_counts()
        .context("failed to reset operation counts")?;

    let range_len = args.range_len.min(args.object_size);
    let offset_window = args.object_size.saturating_sub(range_len);
    let mut latencies = Vec::with_capacity(args.reads);
    let started = Instant::now();
    for index in 0..args.reads {
        let offset = if offset_window == 0 {
            0
        } else {
            index.wrapping_mul(range_len) % (offset_window + 1)
        };
        let operation_started = Instant::now();
        repo.get_range(
            &key,
            ByteRange::Slice {
                offset: offset as u64,
                len: range_len as u64,
            },
        )
        .await
        .with_context(|| format!("failed to read range {index}"))?;
        latencies.push(operation_started.elapsed());
    }

    let elapsed = started.elapsed();
    let counts = store
        .operation_counts()
        .context("failed to read operation counts")?;
    Ok(PerfReport {
        scenario: "range-read",
        backend: args.backend,
        repository_format: PERF_REPOSITORY_FORMAT,
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
        reload_verification: None,
    })
}

struct PerfReport {
    scenario: &'static str,
    backend: PerfBackend,
    repository_format: &'static str,
    objects: usize,
    object_size: usize,
    operations: usize,
    requested_plaintext_write_bytes: usize,
    requested_plaintext_read_bytes: usize,
    commit_batch_items: usize,
    commit_batch_delay_ms: u64,
    commit_max_pending_items: usize,
    payload_segment_size: Option<usize>,
    adaptive_payload_segment_size: bool,
    concurrency: usize,
    operation_latency: OperationLatencyStats,
    elapsed: Duration,
    counts: BlobOperationCounts,
    reload_verification: Option<ReloadVerification>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReloadVerification {
    checkpoint: Option<CheckpointMeasurement>,
    elapsed: Duration,
    expected_objects: usize,
    listed_objects: usize,
    checked_objects: usize,
    active_index_runs: usize,
    cold_reads: ColdReadMeasurement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CheckpointMeasurement {
    requested_after_objects: usize,
    actual_after_objects: usize,
    elapsed: Duration,
}

#[derive(Clone, Debug, serde::Serialize)]
struct ReloadVerificationReport {
    verified: bool,
    checkpoint: Option<CheckpointMeasurementReport>,
    elapsed_ms: f64,
    expected_objects: usize,
    listed_objects: usize,
    checked_objects: usize,
    active_index_runs: usize,
    cold_reads: ColdReadMeasurementReport,
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
struct CheckpointMeasurementReport {
    requested_after_objects: usize,
    actual_after_objects: usize,
    elapsed_ms: f64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ColdReadMeasurement {
    elapsed: Duration,
    logical_reads: usize,
    requested_plaintext_bytes: usize,
    counts: BlobOperationCounts,
}

#[derive(Clone, Debug, serde::Serialize)]
struct ColdReadMeasurementReport {
    cache_state: &'static str,
    elapsed_ms: f64,
    logical_reads: usize,
    requested_plaintext_bytes: usize,
    backend_requests: u64,
    requests_per_read: Option<f64>,
    gets: u64,
    heads: u64,
    lists: u64,
    bytes_read: u64,
    byte_amplification: Option<f64>,
}

impl ReloadVerification {
    fn report(&self) -> ReloadVerificationReport {
        ReloadVerificationReport {
            verified: true,
            checkpoint: self.checkpoint.map(CheckpointMeasurement::report),
            elapsed_ms: self.elapsed.as_secs_f64() * 1_000.0,
            expected_objects: self.expected_objects,
            listed_objects: self.listed_objects,
            checked_objects: self.checked_objects,
            active_index_runs: self.active_index_runs,
            cold_reads: self.cold_reads.report(),
        }
    }
}

impl CheckpointMeasurement {
    fn report(self) -> CheckpointMeasurementReport {
        CheckpointMeasurementReport {
            requested_after_objects: self.requested_after_objects,
            actual_after_objects: self.actual_after_objects,
            elapsed_ms: self.elapsed.as_secs_f64() * 1_000.0,
        }
    }
}

impl ColdReadMeasurement {
    fn report(&self) -> ColdReadMeasurementReport {
        let backend_requests = backend_request_count(&self.counts);
        ColdReadMeasurementReport {
            cache_state: "fresh-post-recovery",
            elapsed_ms: self.elapsed.as_secs_f64() * 1_000.0,
            logical_reads: self.logical_reads,
            requested_plaintext_bytes: self.requested_plaintext_bytes,
            backend_requests,
            requests_per_read: ratio_optional(backend_requests, self.logical_reads as u64),
            gets: self.counts.get,
            heads: self.counts.head,
            lists: self.counts.list,
            bytes_read: self.counts.bytes_read,
            byte_amplification: ratio_optional(
                self.counts.bytes_read,
                self.requested_plaintext_bytes as u64,
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct OperationLatencyStats {
    samples: usize,
    min_ns: u128,
    avg_ns: f64,
    p50_ns: u128,
    p95_ns: u128,
    p99_ns: u128,
    max_ns: u128,
}

impl OperationLatencyStats {
    fn from_samples(mut samples: Vec<Duration>) -> Self {
        if samples.is_empty() {
            return Self::default();
        }

        samples.sort_unstable();
        let count = samples.len();
        let total_ns = samples.iter().map(Duration::as_nanos).sum::<u128>();

        Self {
            samples: count,
            min_ns: samples[0].as_nanos(),
            avg_ns: total_ns as f64 / count as f64,
            p50_ns: percentile_duration(&samples, 0.50).as_nanos(),
            p95_ns: percentile_duration(&samples, 0.95).as_nanos(),
            p99_ns: percentile_duration(&samples, 0.99).as_nanos(),
            max_ns: samples[count - 1].as_nanos(),
        }
    }
}

impl PerfReport {
    fn enforce_max_write_amplification(&self, limit: Option<f64>) -> Result<()> {
        let Some(limit) = limit else {
            return Ok(());
        };
        let Some(actual) = ratio_optional(
            self.counts.bytes_written,
            self.requested_plaintext_write_bytes as u64,
        ) else {
            return Ok(());
        };
        if actual > limit {
            anyhow::bail!(
                "{} write amplification {actual:.6}x exceeds {limit:.6}x",
                self.scenario
            );
        }
        Ok(())
    }

    fn enforce_resource_limits(
        &self,
        max_elapsed_seconds: Option<f64>,
        max_peak_rss_bytes: Option<u64>,
        peak_rss_bytes: Option<u64>,
    ) -> Result<()> {
        enforce_max_elapsed_seconds(self.scenario, self.elapsed, max_elapsed_seconds)?;
        enforce_max_peak_rss_bytes(self.scenario, peak_rss_bytes, max_peak_rss_bytes)
    }

    fn enforce_cold_read_limits(
        &self,
        byte_limit: Option<f64>,
        request_limit: Option<f64>,
    ) -> Result<()> {
        if byte_limit.is_none() && request_limit.is_none() {
            return Ok(());
        }
        let verification = self
            .reload_verification
            .as_ref()
            .context("cold-read limits require reload verification evidence")?;
        let cold = &verification.cold_reads;
        if let Some(limit) = byte_limit {
            let actual = ratio_optional(
                cold.counts.bytes_read,
                cold.requested_plaintext_bytes as u64,
            )
            .context("cold-read byte limit requires non-empty plaintext evidence")?;
            if actual > limit {
                anyhow::bail!(
                    "{} cold-read amplification {actual:.6}x exceeds {limit:.6}x",
                    self.scenario
                );
            }
        }
        if let Some(limit) = request_limit {
            let actual = ratio_optional(
                backend_request_count(&cold.counts),
                cold.logical_reads as u64,
            )
            .context("cold-read request limit requires at least one logical read")?;
            if actual > limit {
                anyhow::bail!(
                    "{} cold-read requests {actual:.6} per read exceeds {limit:.6}",
                    self.scenario
                );
            }
        }
        Ok(())
    }

    fn enforce_active_index_run_limit(&self, limit: Option<usize>) -> Result<()> {
        let Some(limit) = limit else {
            return Ok(());
        };
        let actual = self
            .reload_verification
            .as_ref()
            .context("active index-run limit requires reload verification evidence")?
            .active_index_runs;
        if actual > limit {
            anyhow::bail!(
                "{} recovered {actual} active index runs, exceeding limit {limit}",
                self.scenario
            );
        }
        Ok(())
    }

    #[cfg(feature = "containers")]
    fn print(&self, format: ReportFormat) -> Result<()> {
        self.print_with_peak_rss(format, process_peak_rss_bytes())
    }

    fn print_with_peak_rss(&self, format: ReportFormat, peak_rss_bytes: Option<u64>) -> Result<()> {
        match format {
            ReportFormat::Tsv => {
                self.print_tsv(peak_rss_bytes);
                Ok(())
            }
            ReportFormat::Jsonl => self.print_jsonl(peak_rss_bytes),
        }
    }

    fn print_tsv(&self, peak_rss_bytes: Option<u64>) {
        let elapsed_ms = self.elapsed.as_secs_f64() * 1_000.0;
        let requested_plaintext_bytes = self.requested_plaintext_bytes();
        let throughput_mib_s = mib_per_second(requested_plaintext_bytes, self.elapsed);
        let backend_bytes = self.backend_bytes();
        let backend_mib_s = mib_per_second(backend_bytes as usize, self.elapsed);
        let read_amplification = format_amp(ratio_optional(
            self.counts.bytes_read,
            self.requested_plaintext_read_bytes as u64,
        ));
        let write_amplification = format_amp(ratio_optional(
            self.counts.bytes_written,
            self.requested_plaintext_write_bytes as u64,
        ));
        let backend_requests = self.backend_requests();
        let backend_requests_per_s = per_second(backend_requests, self.elapsed);
        let backend_requests_per_operation =
            ratio_optional(backend_requests, self.operations as u64);
        let latency = self.operation_latency;
        let reload_verification = self.reload_verification.as_ref();
        let checkpoint = reload_verification.and_then(|verification| verification.checkpoint);
        let cold_reads = reload_verification.map(|verification| &verification.cold_reads);

        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.3}\t{}\t{}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.2}\t{:.2}\t{}\t{:.2}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.3}\t{}\t{}\t{}\t{}\t{}\t{:.3}\t{:.3}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.scenario,
            self.backend.as_str(),
            self.repository_format,
            self.objects,
            self.object_size,
            self.operations,
            self.commit_batch_items,
            self.commit_batch_delay_ms,
            self.commit_max_pending_items,
            payload_segment_size_label(self.payload_segment_size),
            self.adaptive_payload_segment_size,
            self.concurrency,
            elapsed_ms,
            format_optional_u64(peak_rss_bytes),
            latency.samples,
            ns_to_ms(latency.min_ns),
            ns_f64_to_ms(latency.avg_ns),
            ns_to_ms(latency.p50_ns),
            ns_to_ms(latency.p95_ns),
            ns_to_ms(latency.p99_ns),
            ns_to_ms(latency.max_ns),
            throughput_mib_s,
            backend_mib_s,
            backend_requests,
            backend_requests_per_s,
            format_amp(backend_requests_per_operation),
            self.counts.put,
            self.counts.get,
            self.counts.head,
            self.counts.list,
            self.counts.delete,
            self.counts.extend_retention,
            self.counts.set_legal_hold,
            self.counts.flush,
            backend_bytes,
            self.counts.bytes_written,
            self.counts.bytes_read,
            requested_plaintext_bytes,
            self.requested_plaintext_write_bytes,
            self.requested_plaintext_read_bytes,
            write_amplification,
            read_amplification,
            reload_verification.is_some(),
            reload_verification.map_or(0.0, |verification| {
                verification.elapsed.as_secs_f64() * 1_000.0
            }),
            reload_verification.map_or(0, |verification| verification.expected_objects),
            reload_verification.map_or(0, |verification| verification.listed_objects),
            reload_verification.map_or(0, |verification| verification.checked_objects),
            checkpoint.map_or(0, |measurement| measurement.requested_after_objects),
            checkpoint.map_or(0, |measurement| measurement.actual_after_objects),
            checkpoint.map_or(0.0, |measurement| {
                measurement.elapsed.as_secs_f64() * 1_000.0
            }),
            cold_reads.map_or(0.0, |measurement| {
                measurement.elapsed.as_secs_f64() * 1_000.0
            }),
            cold_reads.map_or(0, |measurement| measurement.logical_reads),
            cold_reads.map_or(0, |measurement| backend_request_count(&measurement.counts)),
            format_amp(cold_reads.and_then(|measurement| {
                ratio_optional(
                    backend_request_count(&measurement.counts),
                    measurement.logical_reads as u64,
                )
            })),
            cold_reads.map_or(0, |measurement| measurement.counts.bytes_read),
            format_amp(cold_reads.and_then(|measurement| {
                ratio_optional(
                    measurement.counts.bytes_read,
                    measurement.requested_plaintext_bytes as u64,
                )
            })),
            reload_verification.map_or(0, |verification| verification.active_index_runs),
        );
    }

    fn print_jsonl(&self, peak_rss_bytes: Option<u64>) -> Result<()> {
        let requested_plaintext_bytes = self.requested_plaintext_bytes();
        let backend_bytes = self.backend_bytes();
        let backend_requests = self.backend_requests();
        let report = serde_json::json!({
            "scenario": self.scenario,
            "backend_name": self.backend.as_str(),
            "repository_format": self.repository_format,
            "objects": self.objects,
            "object_size": self.object_size,
            "operations": self.operations,
            "commit": {
                "batch_items": self.commit_batch_items,
                "batch_delay_ms": self.commit_batch_delay_ms,
                "max_pending_items": self.commit_max_pending_items,
                "concurrency": self.concurrency,
            },
            "payload_segment_size": self.payload_segment_size,
            "adaptive_payload_segment_size": self.adaptive_payload_segment_size,
            "elapsed_ms": self.elapsed.as_secs_f64() * 1_000.0,
            "peak_rss_bytes": peak_rss_bytes,
            "operation_latency": {
                "samples": self.operation_latency.samples,
                "min_ms": ns_to_ms(self.operation_latency.min_ns),
                "avg_ms": ns_f64_to_ms(self.operation_latency.avg_ns),
                "p50_ms": ns_to_ms(self.operation_latency.p50_ns),
                "p95_ms": ns_to_ms(self.operation_latency.p95_ns),
                "p99_ms": ns_to_ms(self.operation_latency.p99_ns),
                "max_ms": ns_to_ms(self.operation_latency.max_ns),
            },
            "plaintext_mib_s": mib_per_second(requested_plaintext_bytes, self.elapsed),
            "backend_mib_s": mib_per_second(backend_bytes as usize, self.elapsed),
            "backend": {
                "requests": backend_requests,
                "requests_per_s": per_second(backend_requests, self.elapsed),
                "requests_per_operation": ratio_optional(backend_requests, self.operations as u64),
                "puts": self.counts.put,
                "gets": self.counts.get,
                "heads": self.counts.head,
                "lists": self.counts.list,
                "deletes": self.counts.delete,
                "extend_retention": self.counts.extend_retention,
                "set_legal_hold": self.counts.set_legal_hold,
                "flushes": self.counts.flush,
                "bytes": backend_bytes,
                "bytes_written": self.counts.bytes_written,
                "bytes_read": self.counts.bytes_read,
            },
            "requested_plaintext_bytes": requested_plaintext_bytes,
            "requested_plaintext_write_bytes": self.requested_plaintext_write_bytes,
            "requested_plaintext_read_bytes": self.requested_plaintext_read_bytes,
            "write_amp": ratio_optional(
                self.counts.bytes_written,
                self.requested_plaintext_write_bytes as u64,
            ),
            "read_amp": ratio_optional(
                self.counts.bytes_read,
                self.requested_plaintext_read_bytes as u64,
            ),
            "reload_verification": self.reload_verification.as_ref().map(ReloadVerification::report),
        });
        println!("{}", serde_json::to_string(&report)?);
        Ok(())
    }

    fn requested_plaintext_bytes(&self) -> usize {
        self.requested_plaintext_write_bytes
            .saturating_add(self.requested_plaintext_read_bytes)
    }

    fn backend_bytes(&self) -> u64 {
        self.counts
            .bytes_written
            .saturating_add(self.counts.bytes_read)
    }

    fn backend_requests(&self) -> u64 {
        self.counts
            .put
            .saturating_add(self.counts.get)
            .saturating_add(self.counts.head)
            .saturating_add(self.counts.list)
            .saturating_add(self.counts.delete)
            .saturating_add(self.counts.extend_retention)
            .saturating_add(self.counts.set_legal_hold)
            .saturating_add(self.counts.flush)
    }
}

fn print_header() {
    println!(
        "scenario\tbackend\trepository_format\tobjects\tobject_size\toperations\tcommit_batch_items\tcommit_batch_delay_ms\tcommit_max_pending_items\tpayload_segment_size\tadaptive_payload_segment_size\tconcurrency\telapsed_ms\tpeak_rss_bytes\toperation_latency_samples\toperation_latency_min_ms\toperation_latency_avg_ms\toperation_latency_p50_ms\toperation_latency_p95_ms\toperation_latency_p99_ms\toperation_latency_max_ms\tplaintext_mib_s\tbackend_mib_s\tbackend_requests\tbackend_requests_per_s\tbackend_requests_per_operation\tputs\tgets\theads\tlists\tdeletes\textend_retention\tset_legal_hold\tflushes\tbackend_bytes\tbackend_bytes_written\tbackend_bytes_read\trequested_plaintext_bytes\trequested_plaintext_write_bytes\trequested_plaintext_read_bytes\twrite_amp\tread_amp\treload_verified\treload_elapsed_ms\treload_expected_objects\treload_listed_objects\treload_checked_objects\tcheckpoint_requested_after_objects\tcheckpoint_actual_after_objects\tcheckpoint_elapsed_ms\tcold_read_elapsed_ms\tcold_read_logical_reads\tcold_read_backend_requests\tcold_read_requests_per_read\tcold_read_backend_bytes\tcold_read_amp\tactive_index_runs"
    );
}

fn memory_store() -> CountingBlobStore<MemoryBlobStore> {
    CountingBlobStore::new(MemoryBlobStore::new())
}

async fn v2_repository_with_store<S>(
    args: &PerfArgs,
    store: CountingBlobStore<S>,
) -> Result<(Arc<V2Repository<CountingBlobStore<S>>>, V2MemoryAnchor)>
where
    S: BlobStore + Clone,
{
    let repository = v2_repository(args, store)?;
    let anchor = V2MemoryAnchor::new();
    repository
        .write_genesis_snapshot(&anchor)
        .await
        .context("failed to write v2 genesis snapshot")?;
    Ok((repository, anchor))
}

fn v2_repository<S>(
    args: &PerfArgs,
    store: CountingBlobStore<S>,
) -> Result<Arc<V2Repository<CountingBlobStore<S>>>>
where
    S: BlobStore + Clone,
{
    if args.payload_segment_size == Some(0) {
        anyhow::bail!("--payload-segment-size must be greater than zero");
    }
    Ok(Arc::new(V2Repository::new(
        store,
        keyring()?,
        RepositoryOptions {
            payload_segment_size: effective_payload_segment_size(args),
            adaptive_payload_segment_size: adaptive_payload_segment_size(args),
            decrypted_segment_cache_max_bytes:
                rs3_repository::DEFAULT_DECRYPTED_SEGMENT_CACHE_MAX_BYTES,
            default_retention: None,
        },
        V2CommitStoreOptions::for_profile(
            V2ProviderProfile::Dev,
            perf_repository_id()?,
            perf_keyring_envelope_ref()?,
            perf_format_ref()?,
        ),
    )))
}

fn adaptive_payload_segment_size(args: &PerfArgs) -> bool {
    args.payload_segment_size.is_none()
}

fn effective_payload_segment_size(args: &PerfArgs) -> usize {
    args.payload_segment_size
        .unwrap_or(DEFAULT_PAYLOAD_SEGMENT_SIZE)
}

fn payload_segment_size_label(payload_segment_size: Option<usize>) -> String {
    payload_segment_size
        .map(|value| value.to_string())
        .unwrap_or_else(|| "adaptive".to_owned())
}

fn filesystem_store(
    args: &PerfArgs,
) -> Result<(
    Option<TemporaryBackendDir>,
    CountingBlobStore<FilesystemBlobStore>,
)> {
    let (root, temporary) = match args.backend_dir.as_ref() {
        Some(path) => (path.clone(), None),
        None => {
            let temporary = TemporaryBackendDir::new()?;
            (temporary.path().to_path_buf(), Some(temporary))
        }
    };
    let store = FilesystemBlobStore::new(root).context("failed to create filesystem backend")?;
    Ok((temporary, CountingBlobStore::new(store)))
}

#[cfg(feature = "s3")]
async fn s3_store(args: &PerfArgs) -> Result<CountingBlobStore<S3BlobStore>> {
    let bucket = args
        .s3_bucket
        .clone()
        .context("--s3-bucket or RS3_PERF_S3_BUCKET is required with --backend s3")?;
    let config = S3BlobStoreConfig::new(bucket)
        .context("failed to create S3 backend config")?
        .with_prefix(args.s3_prefix.clone())
        .with_endpoint_url(args.s3_endpoint_url.clone())
        .with_region(args.s3_region.clone())
        .with_allow_http(args.s3_allow_http)
        .with_virtual_hosted_style(args.s3_virtual_hosted_style);
    let store = S3BlobStore::from_environment(config)
        .await
        .context("failed to create S3 backend")?;
    Ok(CountingBlobStore::new(store))
}

struct TemporaryBackendDir {
    path: PathBuf,
}

impl TemporaryBackendDir {
    fn new() -> Result<Self> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("rs3-perf-backend-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).context("failed to create temporary backend directory")?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryBackendDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn body(size: usize) -> Bytes {
    let bytes = (0..size)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    Bytes::from(bytes)
}

fn path(value: &str) -> Result<LogicalPath> {
    LogicalPath::new(value.to_owned()).map_err(Into::into)
}

fn perf_repository_id() -> Result<RepositoryId> {
    RepositoryId::new("rs3-xtask-perf").map_err(Into::into)
}

fn perf_keyring_envelope_ref() -> Result<V2KeyringEnvelopeRef> {
    Ok(V2KeyringEnvelopeRef {
        object_id: BackendObjectId::new("keyrings/perf-bootstrap")
            .context("invalid perf keyring envelope object id")?,
        digest: [6_u8; 32],
    })
}

fn perf_format_ref() -> Result<V2FormatRef> {
    Ok(V2FormatRef {
        generation: 1,
        digest: hex::encode([7_u8; 32]),
        object_id: BackendObjectId::new(format!(
            "format/{:020}-{}",
            1_u64,
            hex::encode([7_u8; 32])
        ))
        .context("invalid perf format object id")?,
        version_id: Some(
            BackendVersionId::new("perf-format-version-1")
                .context("invalid perf format version id")?,
        ),
    })
}

fn commit_options(args: &PerfArgs) -> CommitCoordinatorOptions {
    CommitCoordinatorOptions::new(
        commit_batch_items(args),
        Duration::from_millis(args.commit_batch_delay_ms),
    )
    .with_max_pending_items(commit_max_pending_items(args))
}

fn commit_batch_items(args: &PerfArgs) -> usize {
    args.commit_batch_items.max(1)
}

fn commit_max_pending_items(args: &PerfArgs) -> usize {
    args.commit_max_pending_items
        .unwrap_or_else(|| commit_batch_items(args).max(concurrency(args)))
        .max(1)
}

fn concurrency(args: &PerfArgs) -> usize {
    args.concurrency.max(1)
}

fn keyring() -> Result<KeyRing> {
    KeyRing::new(vec![
        key_material(
            "namespace",
            KeyPurpose::Namespace,
            KeyStatus::Primary,
            "hmac-sha256",
            1,
        )?,
        key_material(
            "metadata",
            KeyPurpose::Metadata,
            KeyStatus::Primary,
            "aes-256-gcm-siv-hmac-sha256-nonce-v1",
            2,
        )?,
        key_material(
            "signing",
            KeyPurpose::CheckpointSigning,
            KeyStatus::Primary,
            "ed25519",
            3,
        )?,
        key_material(
            "content",
            KeyPurpose::Content,
            KeyStatus::Primary,
            "xchacha20poly1305",
            4,
        )?,
    ])
    .map_err(Into::into)
}

fn key_material(
    value: &str,
    purpose: KeyPurpose,
    status: KeyStatus,
    algorithm: &str,
    secret_byte: u8,
) -> Result<KeyMaterial> {
    Ok(KeyMaterial::new(
        KeyDescriptor {
            id: KeyId::new(value.to_owned())?,
            purpose,
            algorithm: algorithm.to_owned(),
            status,
            created_at_ms: 0,
            not_before_ms: None,
            not_after_ms: None,
            public_key: None,
            external_kms_uri: None,
        },
        SecretBytes::new(vec![secret_byte; SecretBytes::MIN_LEN])?,
    ))
}

fn checked_mul(left: usize, right: usize) -> Result<usize> {
    left.checked_mul(right)
        .context("scenario byte count overflowed usize")
}

fn operation_counts_delta(
    after: &BlobOperationCounts,
    before: &BlobOperationCounts,
) -> Result<BlobOperationCounts> {
    let delta = |field: &'static str, after: u64, before: u64| {
        after
            .checked_sub(before)
            .with_context(|| format!("backend {field} counter decreased during measurement"))
    };
    Ok(BlobOperationCounts {
        put: delta("PUT", after.put, before.put)?,
        get: delta("GET", after.get, before.get)?,
        head: delta("HEAD", after.head, before.head)?,
        list: delta("LIST", after.list, before.list)?,
        delete: delta("DELETE", after.delete, before.delete)?,
        extend_retention: delta(
            "retention extension",
            after.extend_retention,
            before.extend_retention,
        )?,
        set_legal_hold: delta(
            "legal-hold update",
            after.set_legal_hold,
            before.set_legal_hold,
        )?,
        flush: delta("cache flush", after.flush, before.flush)?,
        multipart_put: delta(
            "multipart completion",
            after.multipart_put,
            before.multipart_put,
        )?,
        bytes_written: delta("written-byte", after.bytes_written, before.bytes_written)?,
        bytes_read: delta("read-byte", after.bytes_read, before.bytes_read)?,
    })
}

fn backend_request_count(counts: &BlobOperationCounts) -> u64 {
    counts
        .put
        .saturating_add(counts.get)
        .saturating_add(counts.head)
        .saturating_add(counts.list)
        .saturating_add(counts.delete)
        .saturating_add(counts.extend_retention)
        .saturating_add(counts.set_legal_hold)
        .saturating_add(counts.flush)
        .saturating_add(counts.multipart_put)
}

fn validate_cold_read_counts(counts: &BlobOperationCounts, logical_reads: usize) -> Result<()> {
    let expected_gets =
        u64::try_from(logical_reads).context("cold-read logical read count does not fit in u64")?;
    let request_count = backend_request_count(counts);
    if counts.get != expected_gets || request_count != expected_gets {
        anyhow::bail!(
            "cold reads required {request_count} backend operations and {} GETs for {logical_reads} records",
            counts.get,
        );
    }
    Ok(())
}

fn mib_per_second(bytes: usize, elapsed: Duration) -> f64 {
    if elapsed.is_zero() {
        return 0.0;
    }

    bytes as f64 / 1_048_576.0 / elapsed.as_secs_f64()
}

fn per_second(count: u64, elapsed: Duration) -> f64 {
    if elapsed.is_zero() {
        return 0.0;
    }

    count as f64 / elapsed.as_secs_f64()
}

fn ratio_optional(numerator: u64, denominator: u64) -> Option<f64> {
    if denominator == 0 {
        return None;
    }

    Some(numerator as f64 / denominator as f64)
}

fn enforce_max_elapsed_seconds(
    scenario: &str,
    elapsed: Duration,
    limit: Option<f64>,
) -> Result<()> {
    let Some(limit) = limit else {
        return Ok(());
    };
    let actual = elapsed.as_secs_f64();
    if actual > limit {
        anyhow::bail!("{scenario} elapsed time {actual:.3}s exceeds {limit:.3}s");
    }
    Ok(())
}

fn enforce_max_peak_rss_bytes(
    scenario: &str,
    actual: Option<u64>,
    limit: Option<u64>,
) -> Result<()> {
    let Some(limit) = limit else {
        return Ok(());
    };
    let actual = actual
        .context("maximum peak RSS requires process VmHWM evidence from /proc/self/status")?;
    if actual > limit {
        anyhow::bail!("{scenario} process peak RSS {actual} bytes exceeds {limit} bytes");
    }
    Ok(())
}

fn process_peak_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        parse_proc_status_peak_rss(&status).ok().flatten()
    }

    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn parse_proc_status_peak_rss(status: &str) -> Result<Option<u64>> {
    let Some(value) = status.lines().find_map(|line| line.strip_prefix("VmHWM:")) else {
        return Ok(None);
    };
    let mut fields = value.split_whitespace();
    let kibibytes = fields
        .next()
        .context("VmHWM is missing its numeric value")?
        .parse::<u64>()
        .context("VmHWM has an invalid numeric value")?;
    let unit = fields.next().context("VmHWM is missing its unit")?;
    if unit != "kB" || fields.next().is_some() {
        anyhow::bail!("VmHWM must contain exactly one value in kB");
    }
    kibibytes
        .checked_mul(1024)
        .map(Some)
        .context("VmHWM byte count overflowed u64")
}

fn percentile_duration(samples: &[Duration], quantile: f64) -> Duration {
    let index = ((samples.len() as f64 * quantile).ceil() as usize)
        .saturating_sub(1)
        .min(samples.len() - 1);
    samples[index]
}

fn ns_to_ms(value: u128) -> f64 {
    value as f64 / 1_000_000.0
}

fn ns_f64_to_ms(value: f64) -> f64 {
    value / 1_000_000.0
}

fn format_amp(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_owned(), |value| format!("{value:.3}"))
}

fn format_optional_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "n/a".to_owned(), |value| value.to_string())
}

fn init_tracing(filter: &str, format: TraceFormat) -> Result<()> {
    let filter = EnvFilter::try_new(filter).context("invalid tracing filter")?;
    match format {
        TraceFormat::Plain => tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .try_init()
            .map_err(|error| anyhow::anyhow!("failed to initialize tracing subscriber: {error}"))?,
        TraceFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .try_init()
            .map_err(|error| anyhow::anyhow!("failed to initialize tracing subscriber: {error}"))?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        backend_request_count, checkpoint_due, enforce_max_elapsed_seconds,
        enforce_max_peak_rss_bytes, operation_counts_delta, parse_proc_status_peak_rss,
        validate_cold_read_counts, verification_indices,
    };
    use rs3_storage::BlobOperationCounts;
    use std::time::Duration;

    #[test]
    fn checkpoint_threshold_fires_once_at_the_first_completed_batch() {
        assert_eq!(checkpoint_due(None, false, 64), None);
        assert_eq!(checkpoint_due(Some(100), false, 64), None);
        assert_eq!(checkpoint_due(Some(100), false, 128), Some(100));
        assert_eq!(checkpoint_due(Some(100), true, 192), None);
    }

    #[test]
    fn reload_verification_checks_distinct_boundaries() {
        assert_eq!(verification_indices(0), Vec::<usize>::new());
        assert_eq!(verification_indices(1), vec![0]);
        assert_eq!(verification_indices(2), vec![0, 1]);
        assert_eq!(verification_indices(5), vec![0, 2, 4]);
    }

    #[test]
    fn operation_count_delta_covers_every_counter() {
        let before = BlobOperationCounts {
            put: 1,
            get: 2,
            head: 3,
            list: 4,
            delete: 5,
            extend_retention: 6,
            set_legal_hold: 7,
            flush: 8,
            multipart_put: 9,
            bytes_written: 10,
            bytes_read: 11,
        };
        let after = BlobOperationCounts {
            put: 2,
            get: 4,
            head: 6,
            list: 8,
            delete: 10,
            extend_retention: 12,
            set_legal_hold: 14,
            flush: 16,
            multipart_put: 18,
            bytes_written: 20,
            bytes_read: 22,
        };

        let delta = operation_counts_delta(&after, &before)
            .unwrap_or_else(|error| panic!("compute operation counter delta: {error}"));

        assert_eq!(delta, before);
    }

    #[test]
    fn operation_count_delta_rejects_a_decreasing_counter() {
        let before = BlobOperationCounts {
            get: 2,
            ..BlobOperationCounts::default()
        };
        let after = BlobOperationCounts {
            get: 1,
            ..BlobOperationCounts::default()
        };

        let error = operation_counts_delta(&after, &before)
            .expect_err("a decreasing counter must invalidate the measurement");

        assert!(error.to_string().contains("GET counter decreased"));
    }

    #[test]
    fn cold_read_count_validation_accepts_only_one_get_per_read() {
        let counts = BlobOperationCounts {
            get: 3,
            bytes_read: 1_584,
            ..BlobOperationCounts::default()
        };

        validate_cold_read_counts(&counts, 3)
            .unwrap_or_else(|error| panic!("validate direct cold reads: {error}"));
        assert_eq!(backend_request_count(&counts), 3);
    }

    #[test]
    fn cold_read_count_validation_rejects_hidden_non_get_work() {
        let counts = BlobOperationCounts {
            get: 3,
            multipart_put: 1,
            ..BlobOperationCounts::default()
        };

        let error = validate_cold_read_counts(&counts, 3)
            .expect_err("non-GET backend work must invalidate the cold-read gate");

        assert!(error.to_string().contains("4 backend operations"));
    }

    #[test]
    fn elapsed_gate_accepts_equality_and_rejects_over_limit() {
        enforce_max_elapsed_seconds("scale", Duration::from_secs(180), Some(180.0))
            .unwrap_or_else(|error| panic!("accept elapsed time at limit: {error}"));

        let error =
            enforce_max_elapsed_seconds("scale", Duration::from_millis(180_001), Some(180.0))
                .expect_err("elapsed time over the limit must fail");
        assert!(error.to_string().contains("180.001s exceeds 180.000s"));
    }

    #[test]
    fn peak_rss_gate_accepts_equality_and_rejects_over_limit() {
        enforce_max_peak_rss_bytes("scale", Some(4_096), Some(4_096))
            .unwrap_or_else(|error| panic!("accept peak RSS at limit: {error}"));

        let error = enforce_max_peak_rss_bytes("scale", Some(4_097), Some(4_096))
            .expect_err("peak RSS over the limit must fail");
        assert!(error.to_string().contains("4097 bytes exceeds 4096 bytes"));
    }

    #[test]
    fn peak_rss_gate_rejects_missing_evidence() {
        let error = enforce_max_peak_rss_bytes("scale", None, Some(4_096))
            .expect_err("an RSS gate without evidence must fail closed");

        assert!(
            error
                .to_string()
                .contains("requires process VmHWM evidence")
        );
    }

    #[test]
    fn proc_status_peak_rss_parser_converts_kibibytes_to_bytes() {
        let status = "Name:\txtask\nVmPeak:\t999 kB\nVmHWM:\t4096 kB\nVmRSS:\t1024 kB\n";

        assert_eq!(
            parse_proc_status_peak_rss(status)
                .unwrap_or_else(|error| panic!("parse VmHWM: {error}")),
            Some(4_194_304)
        );
        assert_eq!(
            parse_proc_status_peak_rss("Name:\txtask\n")
                .unwrap_or_else(|error| panic!("accept missing VmHWM: {error}")),
            None
        );
        assert!(parse_proc_status_peak_rss("VmHWM:\t4096 MB\n").is_err());
    }
}
