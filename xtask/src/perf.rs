//! Performance scenario harness.

#[cfg(feature = "containers")]
mod gateway;

#[cfg(feature = "containers")]
use crate::integration::{S3ContainerProvider, s3_container};
use anyhow::{Context, Result};
use bytes::Bytes;
use clap::{Args, ValueEnum};
use rs3_anchor::MemoryCheckpointAnchor;
use rs3_crypto::{KeyMaterial, KeyRing, SecretBytes};
use rs3_repository::{
    CommitCoordinator, CommitCoordinatorOptions, DEFAULT_PAYLOAD_SEGMENT_SIZE, Repository,
    RepositoryOptions, RepositoryPutOptions,
};
use rs3_storage::{
    BlobOperationCounts, BlobStore, ByteRange, CountingBlobStore, FilesystemBlobStore,
    MemoryBlobStore,
};
#[cfg(feature = "s3")]
use rs3_storage::{S3BlobStore, S3BlobStoreConfig};
use rs3_types::{KeyDescriptor, KeyId, KeyPurpose, KeyStatus, LogicalPath};
use std::path::{Path, PathBuf};
#[cfg(feature = "containers")]
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing_subscriber::EnvFilter;

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
    /// Maximum number of committed writes covered by one checkpoint.
    #[arg(long, default_value_t = 64)]
    commit_batch_items: usize,
    /// Maximum commit batching delay in milliseconds.
    #[arg(long, default_value_t = 10)]
    commit_batch_delay_ms: u64,
    /// Maximum committed writes allowed to wait for checkpoint publication.
    #[arg(long)]
    commit_max_pending_items: Option<usize>,
    /// Parallel client writes used by parallel scenarios.
    #[arg(long, default_value_t = 8)]
    concurrency: usize,
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
    /// Repository format used by gateway-backed scenarios.
    #[arg(long, env = "RS3_REPOSITORY_FORMAT", value_enum, default_value_t = PerfRepositoryFormat::V2Preview)]
    repository_format: PerfRepositoryFormat,
    /// Gateway process build profile used by gateway-backed scenarios.
    #[arg(long, value_enum, default_value_t = GatewayBuildProfile::Dev)]
    gateway_build_profile: GatewayBuildProfile,
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
    /// Stage many objects and publish one checkpoint.
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

/// Repository format used by gateway-backed performance scenarios.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum PerfRepositoryFormat {
    /// Legacy preview repository format.
    V1Preview,
    /// Primary v2 preview repository format.
    V2Preview,
}

impl PerfRepositoryFormat {
    pub(crate) const fn as_env(self) -> &'static str {
        match self {
            Self::V1Preview => "v1-preview",
            Self::V2Preview => "v2-preview",
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
    for scenario in scenarios {
        let report = match scenario {
            PerfScenario::All => unreachable!("expanded above"),
            PerfScenario::WriteBatch => write_batch(&args).await?,
            PerfScenario::WriteCommitted => write_committed(&args).await?,
            PerfScenario::WriteCommittedParallel => write_committed_parallel(&args).await?,
            PerfScenario::FullRead => full_read(&args).await?,
            PerfScenario::RangeRead => range_read(&args).await?,
        };
        report.print(args.format)?;
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
    command.args(["--repository-format", args.repository_format.as_env()]);
    command.args([
        "--gateway-build-profile",
        args.gateway_build_profile.as_cli_value(),
    ]);
    command.args(["--commit-batch-items", &args.commit_batch_items.to_string()]);
    command.args([
        "--commit-batch-delay-ms",
        &args.commit_batch_delay_ms.to_string(),
    ]);
    if let Some(max_pending_items) = args.commit_max_pending_items {
        command.args(["--commit-max-pending-items", &max_pending_items.to_string()]);
    }
    command.args(["--concurrency", &args.concurrency.to_string()]);
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
    S: BlobStore + Clone,
{
    let repo = repository_with_store(args, store.clone())?;
    let anchor = MemoryCheckpointAnchor::new();
    let body = body(args.object_size);
    let mut latencies = Vec::with_capacity(args.objects);
    let started = Instant::now();

    for index in 0..args.objects {
        let operation_started = Instant::now();
        repo.put(
            path(&format!("perf/write-batch/object-{index:08}"))?,
            body.clone(),
            RepositoryPutOptions::default(),
        )
        .await
        .with_context(|| format!("failed to write object {index}"))?;
        latencies.push(operation_started.elapsed());
    }
    repo.publish_checkpoint(&anchor)
        .await
        .context("failed to publish checkpoint")?;

    let elapsed = started.elapsed();
    let counts = store
        .operation_counts()
        .context("failed to read operation counts")?;
    Ok(PerfReport {
        scenario: "write-batch",
        backend: args.backend,
        repository_format: None,
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
    let repo = Arc::new(repository_with_store(args, store.clone())?);
    let anchor = MemoryCheckpointAnchor::new();
    let coordinator = CommitCoordinator::with_options(repo, anchor, commit_options(args));
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
        repository_format: None,
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
    let repo = Arc::new(repository_with_store(args, store.clone())?);
    let anchor = MemoryCheckpointAnchor::new();
    let coordinator = Arc::new(CommitCoordinator::with_options(
        repo,
        anchor,
        commit_options(args),
    ));
    let body = body(args.object_size);
    let parallelism = concurrency(args);
    let mut latencies = Vec::with_capacity(args.objects);
    let started = Instant::now();

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
    }

    let elapsed = started.elapsed();
    let counts = store
        .operation_counts()
        .context("failed to read operation counts")?;
    Ok(PerfReport {
        scenario: "write-committed-parallel",
        backend: args.backend,
        repository_format: None,
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
    })
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
    let repo = repository_with_store(args, store.clone())?;
    let key = path("perf/read/full-object")?;
    let body = body(args.object_size);
    repo.put(key.clone(), body, RepositoryPutOptions::default())
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
        repository_format: None,
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
    let repo = repository_with_store(args, store.clone())?;
    let key = path("perf/read/range-object")?;
    let body = body(args.object_size);
    repo.put(key.clone(), body, RepositoryPutOptions::default())
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
        repository_format: None,
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

struct PerfReport {
    scenario: &'static str,
    backend: PerfBackend,
    repository_format: Option<PerfRepositoryFormat>,
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
    fn print(&self, format: ReportFormat) -> Result<()> {
        match format {
            ReportFormat::Tsv => {
                self.print_tsv();
                Ok(())
            }
            ReportFormat::Jsonl => self.print_jsonl(),
        }
    }

    fn print_tsv(&self) {
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

        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.3}\t{}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.2}\t{:.2}\t{}\t{:.2}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.scenario,
            self.backend.as_str(),
            repository_format_label(self.repository_format),
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
        );
    }

    fn print_jsonl(&self) -> Result<()> {
        let requested_plaintext_bytes = self.requested_plaintext_bytes();
        let backend_bytes = self.backend_bytes();
        let backend_requests = self.backend_requests();
        let repository_format = self.repository_format.map(PerfRepositoryFormat::as_env);
        let report = serde_json::json!({
            "scenario": self.scenario,
            "backend_name": self.backend.as_str(),
            "repository_format": repository_format,
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
        "scenario\tbackend\trepository_format\tobjects\tobject_size\toperations\tcommit_batch_items\tcommit_batch_delay_ms\tcommit_max_pending_items\tpayload_segment_size\tadaptive_payload_segment_size\tconcurrency\telapsed_ms\toperation_latency_samples\toperation_latency_min_ms\toperation_latency_avg_ms\toperation_latency_p50_ms\toperation_latency_p95_ms\toperation_latency_p99_ms\toperation_latency_max_ms\tplaintext_mib_s\tbackend_mib_s\tbackend_requests\tbackend_requests_per_s\tbackend_requests_per_operation\tputs\tgets\theads\tlists\tdeletes\textend_retention\tset_legal_hold\tflushes\tbackend_bytes\tbackend_bytes_written\tbackend_bytes_read\trequested_plaintext_bytes\trequested_plaintext_write_bytes\trequested_plaintext_read_bytes\twrite_amp\tread_amp"
    );
}

fn memory_store() -> CountingBlobStore<MemoryBlobStore> {
    CountingBlobStore::new(MemoryBlobStore::new())
}

fn repository_with_store<S>(args: &PerfArgs, store: S) -> Result<Repository<S>>
where
    S: BlobStore,
{
    if args.payload_segment_size == Some(0) {
        anyhow::bail!("--payload-segment-size must be greater than zero");
    }
    Ok(Repository::with_keyring_and_options(
        store,
        keyring()?,
        RepositoryOptions {
            payload_segment_size: effective_payload_segment_size(args),
            adaptive_payload_segment_size: adaptive_payload_segment_size(args),
            decrypted_segment_cache_max_bytes:
                rs3_repository::DEFAULT_DECRYPTED_SEGMENT_CACHE_MAX_BYTES,
            default_retention: None,
        },
    ))
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

fn repository_format_label(repository_format: Option<PerfRepositoryFormat>) -> &'static str {
    repository_format
        .map(PerfRepositoryFormat::as_env)
        .unwrap_or("repository-core")
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
