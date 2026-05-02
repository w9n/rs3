//! Performance scenario harness.

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::{Args, ValueEnum};
use rs3_anchor::MemoryCheckpointAnchor;
use rs3_crypto::{KeyMaterial, KeyRing, SecretBytes};
use rs3_repository::{Repository, RepositoryPutOptions};
use rs3_storage::{BlobOperationCounts, ByteRange, MemoryBlobStore};
use rs3_types::{KeyDescriptor, KeyId, KeyPurpose, KeyStatus, LogicalPath};
use std::time::{Duration, Instant};

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

pub(crate) async fn run(args: PerfArgs) -> Result<()> {
    let scenarios = match args.scenario {
        PerfScenario::All => vec![
            PerfScenario::WriteBatch,
            PerfScenario::FullRead,
            PerfScenario::RangeRead,
        ],
        scenario => vec![scenario],
    };

    print_header();
    for scenario in scenarios {
        let report = match scenario {
            PerfScenario::All => unreachable!("expanded above"),
            PerfScenario::WriteBatch => write_batch(&args).await?,
            PerfScenario::FullRead => full_read(&args).await?,
            PerfScenario::RangeRead => range_read(&args).await?,
        };
        report.print();
    }

    Ok(())
}

async fn write_batch(args: &PerfArgs) -> Result<PerfReport> {
    let store = MemoryBlobStore::new();
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
        objects: args.objects,
        object_size: args.object_size,
        operations: args.objects,
        requested_plaintext_bytes: checked_mul(args.objects, args.object_size)?,
        elapsed,
        counts,
    })
}

async fn full_read(args: &PerfArgs) -> Result<PerfReport> {
    let store = MemoryBlobStore::new();
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
        objects: 1,
        object_size: args.object_size,
        operations: args.reads,
        requested_plaintext_bytes: checked_mul(args.reads, args.object_size)?,
        elapsed,
        counts,
    })
}

async fn range_read(args: &PerfArgs) -> Result<PerfReport> {
    let store = MemoryBlobStore::new();
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
        objects: 1,
        object_size: args.object_size,
        operations: args.reads,
        requested_plaintext_bytes: checked_mul(args.reads, range_len)?,
        elapsed,
        counts,
    })
}

struct PerfReport {
    scenario: &'static str,
    objects: usize,
    object_size: usize,
    operations: usize,
    requested_plaintext_bytes: usize,
    elapsed: Duration,
    counts: BlobOperationCounts,
}

impl PerfReport {
    fn print(&self) {
        let elapsed_ms = self.elapsed.as_secs_f64() * 1_000.0;
        let throughput_mib_s = mib_per_second(self.requested_plaintext_bytes, self.elapsed);
        let read_amplification = ratio(
            self.counts.bytes_read,
            self.requested_plaintext_bytes as u64,
        );
        let write_amplification = ratio(
            self.counts.bytes_written,
            self.requested_plaintext_bytes as u64,
        );

        println!(
            "{}\t{}\t{}\t{}\t{:.3}\t{:.2}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.3}\t{:.3}",
            self.scenario,
            self.objects,
            self.object_size,
            self.operations,
            elapsed_ms,
            throughput_mib_s,
            self.counts.put,
            self.counts.get,
            self.counts.head,
            self.counts.list,
            self.counts.bytes_written,
            self.counts.bytes_read,
            self.requested_plaintext_bytes,
            write_amplification,
            read_amplification,
        );
    }
}

fn print_header() {
    println!(
        "scenario\tobjects\tobject_size\toperations\telapsed_ms\tplaintext_mib_s\tputs\tgets\theads\tlists\tbackend_bytes_written\tbackend_bytes_read\trequested_plaintext_bytes\twrite_amp\tread_amp"
    );
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

fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        return 0.0;
    }

    numerator as f64 / denominator as f64
}
