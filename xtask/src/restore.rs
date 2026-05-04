//! Restore verification automation.

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand, ValueEnum};
use rs3_crypto::{KeyRing, KeyringEnvelope, RepositoryKeyContext, SecretBytes};
use rs3_repository::{CheckpointPosition, Repository, RestoreVerificationReport};
use rs3_storage::{BlobStore, ByteRange, FilesystemBlobStore};
#[cfg(feature = "s3")]
use rs3_storage::{S3BlobStore, S3BlobStoreConfig};
use rs3_types::{BackendObjectId, CheckpointId, RepositoryId, Sequence};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Verifies restore-critical repository state.
#[derive(Debug, Args)]
pub(crate) struct RestoreArgs {
    #[command(subcommand)]
    command: RestoreCommand,
}

#[derive(Debug, Subcommand)]
enum RestoreCommand {
    /// Verify an accepted checkpoint chain and reachable encrypted payloads.
    Verify(Box<RestoreVerifyArgs>),
}

#[derive(Debug, Args)]
struct RestoreVerifyArgs {
    /// Stable repository identifier bound into key derivation.
    #[arg(long, env = "RS3_REPOSITORY_ID")]
    repository_id: String,
    /// Hex-encoded public repository salt bound into key derivation.
    #[arg(long, env = "RS3_REPOSITORY_SALT_HEX")]
    repository_salt_hex: String,
    /// Accepted checkpoint sequence from the trusted anchor.
    #[arg(long)]
    checkpoint_sequence: u64,
    /// Accepted checkpoint identifier from the trusted anchor.
    #[arg(long)]
    checkpoint_id: String,
    /// Accepted checkpoint payload digest from the trusted anchor.
    #[arg(long)]
    checkpoint_digest: String,
    /// Repository key source.
    #[command(flatten)]
    keys: RestoreKeySourceArgs,
    /// Backend object-store target.
    #[command(flatten)]
    backend: RestoreBackendArgs,
    /// Output format.
    #[arg(long, value_enum, default_value_t = RestoreReportFormat::Json)]
    format: RestoreReportFormat,
}

#[derive(Clone, Debug, Args)]
struct RestoreKeySourceArgs {
    /// Hex-encoded repository master key.
    #[arg(long, env = "RS3_REPOSITORY_MASTER_KEY_HEX", hide_env_values = true)]
    master_key_hex: Option<String>,
    /// File containing the hex-encoded repository master key.
    #[arg(long)]
    master_key_hex_file: Option<PathBuf>,
    /// Backend object containing the encrypted keyring envelope.
    #[arg(long, env = "RS3_KEYRING_ENVELOPE_OBJECT_ID")]
    keyring_envelope_object_id: Option<String>,
    /// Operator-visible wrapping key identifier expected by the envelope.
    #[arg(long, env = "RS3_KEYRING_WRAPPING_KEY_ID")]
    wrapping_key_id: Option<String>,
    /// Hex-encoded high-entropy wrapping key.
    #[arg(long, env = "RS3_KEYRING_WRAPPING_KEY_HEX", hide_env_values = true)]
    wrapping_key_hex: Option<String>,
    /// File containing the hex-encoded high-entropy wrapping key.
    #[arg(long)]
    wrapping_key_hex_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Args)]
struct RestoreBackendArgs {
    /// Backend implementation used by verification.
    #[arg(long, value_enum, default_value_t = RestoreBackend::Filesystem)]
    backend: RestoreBackend,
    /// Filesystem backend root used with `--backend filesystem`.
    #[arg(long)]
    backend_dir: Option<PathBuf>,
    /// S3 bucket used with `--backend s3`.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_RESTORE_S3_BUCKET")]
    s3_bucket: Option<String>,
    /// S3 key prefix used with `--backend s3`.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_RESTORE_S3_PREFIX")]
    s3_prefix: Option<String>,
    /// Custom S3 endpoint URL used with `--backend s3`.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_RESTORE_S3_ENDPOINT_URL")]
    s3_endpoint_url: Option<String>,
    /// AWS region override used with `--backend s3`.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_RESTORE_S3_REGION")]
    s3_region: Option<String>,
    /// Allow plain HTTP for local S3-compatible endpoints used with `--backend s3`.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_RESTORE_S3_ALLOW_HTTP", default_value_t = false)]
    s3_allow_http: bool,
    /// Use virtual-hosted bucket addressing instead of path-style addressing.
    #[cfg(feature = "s3")]
    #[arg(
        long,
        env = "RS3_RESTORE_S3_VIRTUAL_HOSTED_STYLE",
        default_value_t = false
    )]
    s3_virtual_hosted_style: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum RestoreBackend {
    /// Local filesystem backend.
    Filesystem,
    /// S3-compatible backend using the default environment/config chain.
    #[cfg(feature = "s3")]
    S3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum RestoreReportFormat {
    /// JSON object.
    Json,
    /// Human-readable summary.
    Text,
}

pub(crate) fn run(args: RestoreArgs) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build restore verification runtime")?;
    runtime.block_on(run_async(args))
}

async fn run_async(args: RestoreArgs) -> Result<()> {
    match args.command {
        RestoreCommand::Verify(args) => {
            let format = args.format;
            let report = verify(*args).await?;
            print_report(&report, format)?;
        }
    }
    Ok(())
}

async fn verify(args: RestoreVerifyArgs) -> Result<RestoreVerificationReport> {
    match args.backend.backend {
        RestoreBackend::Filesystem => {
            let store = filesystem_store(&args.backend)?;
            verify_with_store(args, store).await
        }
        #[cfg(feature = "s3")]
        RestoreBackend::S3 => {
            let store = s3_store(&args.backend).await?;
            verify_with_store(args, store).await
        }
    }
}

async fn verify_with_store<S>(
    args: RestoreVerifyArgs,
    store: S,
) -> Result<RestoreVerificationReport>
where
    S: BlobStore,
{
    let repository_id = RepositoryId::new(args.repository_id.clone())?;
    let repository_salt =
        hex::decode(&args.repository_salt_hex).context("repository salt must be hex encoded")?;
    let context = RepositoryKeyContext::new(repository_id, repository_salt)?;
    let accepted = CheckpointPosition {
        sequence: Sequence::new(args.checkpoint_sequence),
        checkpoint_id: CheckpointId::new(args.checkpoint_id)?,
        payload_digest: args.checkpoint_digest,
    };
    let keyring = keyring_from_source(&store, &context, &args.keys).await?;
    let repository = Repository::with_keyring(store, keyring);

    repository
        .verify_restore(&accepted)
        .await
        .context("restore verification failed")
}

async fn keyring_from_source<S>(
    store: &S,
    context: &RepositoryKeyContext,
    args: &RestoreKeySourceArgs,
) -> Result<KeyRing>
where
    S: BlobStore,
{
    let has_master = args.master_key_hex.is_some() || args.master_key_hex_file.is_some();
    let has_envelope = args.keyring_envelope_object_id.is_some()
        || args.wrapping_key_id.is_some()
        || args.wrapping_key_hex.is_some()
        || args.wrapping_key_hex_file.is_some();
    match (has_master, has_envelope) {
        (true, false) => {
            let master_key = secret_input(
                args.master_key_hex.clone(),
                args.master_key_hex_file.as_deref(),
                "--master-key-hex",
                "--master-key-hex-file",
            )?;
            KeyRing::from_repository_master_key_for_context(&master_key, context)
                .map_err(Into::into)
        }
        (false, true) => keyring_from_envelope(store, context, args).await,
        (true, true) => {
            bail!("master-key source cannot be combined with keyring-envelope source")
        }
        (false, false) => bail!("repository master key or keyring envelope source is required"),
    }
}

async fn keyring_from_envelope<S>(
    store: &S,
    context: &RepositoryKeyContext,
    args: &RestoreKeySourceArgs,
) -> Result<KeyRing>
where
    S: BlobStore,
{
    let object_id = BackendObjectId::new(
        args.keyring_envelope_object_id
            .clone()
            .context("--keyring-envelope-object-id is required")?,
    )?;
    let wrapping_key_id = args
        .wrapping_key_id
        .as_deref()
        .context("--wrapping-key-id is required")?;
    let wrapping_key = secret_input(
        args.wrapping_key_hex.clone(),
        args.wrapping_key_hex_file.as_deref(),
        "--wrapping-key-hex",
        "--wrapping-key-hex-file",
    )?;
    let body = store
        .get_range(&object_id, ByteRange::Full)
        .await
        .context("failed to read keyring envelope")?;
    let envelope = KeyringEnvelope::from_object_bytes(&body)?;

    envelope
        .open(context, wrapping_key_id, &wrapping_key)
        .map_err(Into::into)
}

fn filesystem_store(args: &RestoreBackendArgs) -> Result<FilesystemBlobStore> {
    let root = args
        .backend_dir
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--backend-dir is required with --backend filesystem"))?;
    FilesystemBlobStore::new(root).context("failed to create filesystem backend")
}

#[cfg(feature = "s3")]
async fn s3_store(args: &RestoreBackendArgs) -> Result<S3BlobStore> {
    let bucket = args
        .s3_bucket
        .clone()
        .context("--s3-bucket or RS3_RESTORE_S3_BUCKET is required with --backend s3")?;
    let config = S3BlobStoreConfig::new(bucket)
        .context("failed to create S3 backend config")?
        .with_prefix(args.s3_prefix.clone())
        .with_endpoint_url(args.s3_endpoint_url.clone())
        .with_region(args.s3_region.clone())
        .with_allow_http(args.s3_allow_http)
        .with_virtual_hosted_style(args.s3_virtual_hosted_style);
    S3BlobStore::from_environment(config)
        .await
        .context("failed to create S3 backend")
}

fn secret_input(
    provided_hex: Option<String>,
    provided_file: Option<&Path>,
    provided_flag: &str,
    file_flag: &str,
) -> Result<SecretBytes> {
    match (provided_hex, provided_file) {
        (Some(_), Some(_)) => bail!("{provided_flag} cannot be combined with {file_flag}"),
        (Some(hex), None) => secret_from_hex(provided_flag, &hex),
        (None, Some(path)) => {
            let hex = read_secret_hex_file(file_flag, path)?;
            secret_from_hex(file_flag, &hex)
        }
        (None, None) => bail!("{provided_flag} or {file_flag} is required"),
    }
}

fn secret_from_hex(label: &str, value: &str) -> Result<SecretBytes> {
    let bytes =
        Zeroizing::new(hex::decode(value).with_context(|| format!("{label} must be hex encoded"))?);
    SecretBytes::new(bytes.to_vec()).with_context(|| format!("{label} is not usable"))
}

fn read_secret_hex_file(label: &str, path: &Path) -> Result<Zeroizing<String>> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {label} {}", path.display()))?;
    Ok(Zeroizing::new(contents.trim().to_owned()))
}

fn print_report(report: &RestoreVerificationReport, format: RestoreReportFormat) -> Result<()> {
    match format {
        RestoreReportFormat::Json => print_report_json(report),
        RestoreReportFormat::Text => {
            print_report_text(report);
            Ok(())
        }
    }
}

fn print_report_json(report: &RestoreVerificationReport) -> Result<()> {
    let required_key_ids = report
        .required_key_ids
        .iter()
        .map(|key_id| key_id.as_str())
        .collect::<Vec<_>>();
    let report = serde_json::json!({
        "accepted": {
            "sequence": report.accepted.sequence.get(),
            "checkpoint_id": report.accepted.checkpoint_id.as_str(),
            "checkpoint_digest": report.accepted.payload_digest,
        },
        "verified": {
            "checkpoints": report.checkpoint_count,
            "checkpoint_evidence": report.checkpoint_evidence_count,
            "index_delta_objects": report.index_delta_object_count,
            "inline_index_deltas": report.inline_index_delta_count,
            "keyring_envelopes": report.keyring_envelope_count,
            "payload_objects": report.payload_object_count,
            "payload_plaintext_bytes": report.payload_plaintext_bytes,
            "required_key_ids": required_key_ids,
        },
        "protection": {
            "checked_objects": report.protection.checked_object_count,
            "retention_objects": report.protection.retention_object_count,
            "retention_delete_blocked_objects": report.protection.retention_delete_blocked_count,
            "legal_hold_objects": report.protection.legal_hold_object_count,
            "minimum_retention_days": report.protection.minimum_retention_days,
        },
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn print_report_text(report: &RestoreVerificationReport) {
    println!("rs3 restore verification: ok");
    println!("checkpoint_sequence={}", report.accepted.sequence.get());
    println!("checkpoint_id={}", report.accepted.checkpoint_id.as_str());
    println!("checkpoints={}", report.checkpoint_count);
    println!("checkpoint_evidence={}", report.checkpoint_evidence_count);
    println!("index_delta_objects={}", report.index_delta_object_count);
    println!("inline_index_deltas={}", report.inline_index_delta_count);
    println!("keyring_envelopes={}", report.keyring_envelope_count);
    println!("payload_objects={}", report.payload_object_count);
    println!("payload_plaintext_bytes={}", report.payload_plaintext_bytes);
    println!(
        "protection_checked_objects={}",
        report.protection.checked_object_count
    );
    println!(
        "protection_retention_objects={}",
        report.protection.retention_object_count
    );
    println!(
        "protection_retention_delete_blocked_objects={}",
        report.protection.retention_delete_blocked_count
    );
    println!(
        "protection_legal_hold_objects={}",
        report.protection.legal_hold_object_count
    );
    if let Some(days) = report.protection.minimum_retention_days {
        println!("protection_minimum_retention_days={days}");
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RestoreBackend, RestoreBackendArgs, RestoreKeySourceArgs, RestoreReportFormat,
        RestoreVerifyArgs, secret_from_hex, verify_with_store,
    };
    use bytes::Bytes;
    use rs3_anchor::MemoryCheckpointAnchor;
    use rs3_crypto::{KeyRing, RepositoryKeyContext, SecretBytes};
    use rs3_repository::{Repository, RepositoryPutOptions};
    use rs3_storage::MemoryBlobStore;
    use rs3_types::RepositoryId;

    const MASTER_KEY_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const SALT_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    #[tokio::test]
    async fn restore_verify_command_uses_supplied_checkpoint_position() {
        let store = MemoryBlobStore::new();
        let context = RepositoryKeyContext::new(
            RepositoryId::new("restore-cli").unwrap_or_else(|error| panic!("{error}")),
            hex::decode(SALT_HEX).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let master_key =
            SecretBytes::new(hex::decode(MASTER_KEY_HEX).unwrap_or_else(|error| panic!("{error}")))
                .unwrap_or_else(|error| panic!("{error}"));
        let keyring = KeyRing::from_repository_master_key_for_context(&master_key, &context)
            .unwrap_or_else(|error| panic!("{error}"));
        let repo = Repository::with_keyring(store.clone(), keyring);
        let anchor = MemoryCheckpointAnchor::new();
        let committed = repo
            .put_committed(
                rs3_types::LogicalPath::new("restore/cli")
                    .unwrap_or_else(|error| panic!("{error}")),
                Bytes::from_static(b"body"),
                RepositoryPutOptions::default(),
                &anchor,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let args = RestoreVerifyArgs {
            repository_id: "restore-cli".to_owned(),
            repository_salt_hex: SALT_HEX.to_owned(),
            checkpoint_sequence: committed.checkpoint.sequence.get(),
            checkpoint_id: committed.checkpoint.checkpoint_id.as_str().to_owned(),
            checkpoint_digest: committed.checkpoint.payload_digest.clone(),
            keys: RestoreKeySourceArgs {
                master_key_hex: Some(MASTER_KEY_HEX.to_owned()),
                master_key_hex_file: None,
                keyring_envelope_object_id: None,
                wrapping_key_id: None,
                wrapping_key_hex: None,
                wrapping_key_hex_file: None,
            },
            backend: RestoreBackendArgs {
                backend: RestoreBackend::Filesystem,
                backend_dir: None,
                #[cfg(feature = "s3")]
                s3_bucket: None,
                #[cfg(feature = "s3")]
                s3_prefix: None,
                #[cfg(feature = "s3")]
                s3_endpoint_url: None,
                #[cfg(feature = "s3")]
                s3_region: None,
                #[cfg(feature = "s3")]
                s3_allow_http: false,
                #[cfg(feature = "s3")]
                s3_virtual_hosted_style: false,
            },
            format: RestoreReportFormat::Json,
        };

        let report = verify_with_store(args, store)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(report.payload_object_count, 1);
        assert_eq!(report.payload_plaintext_bytes, 4);
    }

    #[test]
    fn restore_verify_rejects_bad_secret_hex() {
        assert!(secret_from_hex("--master-key-hex", "not-hex").is_err());
        assert!(secret_from_hex("--master-key-hex", "11").is_err());
    }
}
