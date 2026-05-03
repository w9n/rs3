//! Performance scenario harness.

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::{Args, ValueEnum};
use rs3_anchor::MemoryCheckpointAnchor;
use rs3_crypto::{KeyMaterial, KeyRing, SecretBytes};
use rs3_repository::{Repository, RepositoryPutOptions};
use rs3_storage::{
    BlobOperationCounts, BlobStore, ByteRange, CountingBlobStore, FilesystemBlobStore,
    MemoryBlobStore,
};
#[cfg(feature = "s3")]
use rs3_storage::{S3BlobStore, S3BlobStoreConfig};
use rs3_types::{KeyDescriptor, KeyId, KeyPurpose, KeyStatus, LogicalPath};
use std::path::{Path, PathBuf};
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
    /// Number of read operations in read scenarios.
    #[arg(long, default_value_t = 128)]
    reads: usize,
    /// Plaintext range length in bytes for range-read scenarios.
    #[arg(long, default_value_t = 4 * 1024)]
    range_len: usize,
    /// Backend implementation used by the scenario.
    #[arg(long, value_enum, default_value_t = PerfBackend::Memory)]
    backend: PerfBackend,
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
}

impl PerfBackend {
    fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Filesystem => "filesystem",
            #[cfg(feature = "s3")]
            Self::S3 => "s3",
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

/// Trace subscriber output options.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum TraceFormat {
    /// Human-readable tracing output.
    Plain,
    /// JSON tracing output.
    Json,
}

pub(crate) async fn run(args: PerfArgs) -> Result<()> {
    if args.trace {
        init_tracing(&args.trace_filter, args.trace_format)?;
    }

    let scenarios = match args.scenario {
        PerfScenario::All => vec![
            PerfScenario::WriteBatch,
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
            PerfScenario::FullRead => full_read(&args).await?,
            PerfScenario::RangeRead => range_read(&args).await?,
        };
        report.print(args.format)?;
    }

    Ok(())
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
    }
}

async fn write_batch_with_store<S>(
    args: &PerfArgs,
    store: CountingBlobStore<S>,
) -> Result<PerfReport>
where
    S: BlobStore + Clone,
{
    let repo = Repository::with_keyring(store.clone(), keyring()?);
    let anchor = MemoryCheckpointAnchor::new();
    let body = body(args.object_size);
    let started = Instant::now();

    for index in 0..args.objects {
        repo.put(
            path(&format!("perf/write-batch/object-{index:08}"))?,
            body.clone(),
            RepositoryPutOptions::default(),
        )
        .await
        .with_context(|| format!("failed to write object {index}"))?;
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
        objects: args.objects,
        object_size: args.object_size,
        operations: args.objects,
        requested_plaintext_write_bytes: checked_mul(args.objects, args.object_size)?,
        requested_plaintext_read_bytes: 0,
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
    }
}

async fn full_read_with_store<S>(args: &PerfArgs, store: CountingBlobStore<S>) -> Result<PerfReport>
where
    S: BlobStore + Clone,
{
    let repo = Repository::with_keyring(store.clone(), keyring()?);
    let key = path("perf/read/full-object")?;
    let body = body(args.object_size);
    repo.put(key.clone(), body, RepositoryPutOptions::default())
        .await
        .context("failed to prepare full-read object")?;
    store
        .reset_operation_counts()
        .context("failed to reset operation counts")?;

    let started = Instant::now();
    for _ in 0..args.reads {
        repo.get_range(&key, ByteRange::Full)
            .await
            .context("failed to read full object")?;
    }

    let elapsed = started.elapsed();
    let counts = store
        .operation_counts()
        .context("failed to read operation counts")?;
    Ok(PerfReport {
        scenario: "full-read",
        backend: args.backend,
        objects: 1,
        object_size: args.object_size,
        operations: args.reads,
        requested_plaintext_write_bytes: 0,
        requested_plaintext_read_bytes: checked_mul(args.reads, args.object_size)?,
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
    }
}

async fn range_read_with_store<S>(
    args: &PerfArgs,
    store: CountingBlobStore<S>,
) -> Result<PerfReport>
where
    S: BlobStore + Clone,
{
    let repo = Repository::with_keyring(store.clone(), keyring()?);
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
    let started = Instant::now();
    for index in 0..args.reads {
        let offset = if offset_window == 0 {
            0
        } else {
            index.wrapping_mul(range_len) % (offset_window + 1)
        };
        repo.get_range(
            &key,
            ByteRange::Slice {
                offset: offset as u64,
                len: range_len as u64,
            },
        )
        .await
        .with_context(|| format!("failed to read range {index}"))?;
    }

    let elapsed = started.elapsed();
    let counts = store
        .operation_counts()
        .context("failed to read operation counts")?;
    Ok(PerfReport {
        scenario: "range-read",
        backend: args.backend,
        objects: 1,
        object_size: args.object_size,
        operations: args.reads,
        requested_plaintext_write_bytes: 0,
        requested_plaintext_read_bytes: checked_mul(args.reads, range_len)?,
        elapsed,
        counts,
    })
}

struct PerfReport {
    scenario: &'static str,
    backend: PerfBackend,
    objects: usize,
    object_size: usize,
    operations: usize,
    requested_plaintext_write_bytes: usize,
    requested_plaintext_read_bytes: usize,
    elapsed: Duration,
    counts: BlobOperationCounts,
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

        println!(
            "{}\t{}\t{}\t{}\t{}\t{:.3}\t{:.2}\t{:.2}\t{}\t{:.2}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.scenario,
            self.backend.as_str(),
            self.objects,
            self.object_size,
            self.operations,
            elapsed_ms,
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
        let report = serde_json::json!({
            "scenario": self.scenario,
            "backend_name": self.backend.as_str(),
            "objects": self.objects,
            "object_size": self.object_size,
            "operations": self.operations,
            "elapsed_ms": self.elapsed.as_secs_f64() * 1_000.0,
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
            .saturating_add(self.counts.flush)
    }
}

fn print_header() {
    println!(
        "scenario\tbackend\tobjects\tobject_size\toperations\telapsed_ms\tplaintext_mib_s\tbackend_mib_s\tbackend_requests\tbackend_requests_per_s\tbackend_requests_per_operation\tputs\tgets\theads\tlists\tdeletes\textend_retention\tflushes\tbackend_bytes\tbackend_bytes_written\tbackend_bytes_read\trequested_plaintext_bytes\trequested_plaintext_write_bytes\trequested_plaintext_read_bytes\twrite_amp\tread_amp"
    );
}

fn memory_store() -> CountingBlobStore<MemoryBlobStore> {
    CountingBlobStore::new(MemoryBlobStore::new())
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
            "hmac-sha256-seal",
            2,
        )?,
        key_material(
            "signing",
            KeyPurpose::CheckpointSigning,
            KeyStatus::Primary,
            "hmac-sha256",
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
