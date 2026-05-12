//! Restore verification automation.

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand, ValueEnum};
use rs3_crypto::{KeyRing, KeyringEnvelope, RepositoryKeyContext, SecretBytes};
use rs3_repository::{CheckpointPosition, Repository, RestoreVerificationReport};
use rs3_storage::{BlobStore, ByteRange, FilesystemBlobStore};
#[cfg(feature = "s3")]
use rs3_storage::{S3BlobStore, S3BlobStoreConfig};
use rs3_types::{BackendObjectId, BackendVersionId, CheckpointId, RepositoryId, Sequence};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Verifies restore-critical repository state.
#[derive(Args)]
pub(crate) struct RestoreArgs {
    #[command(subcommand)]
    command: RestoreCommand,
}

#[derive(Subcommand)]
enum RestoreCommand {
    /// Verify an accepted checkpoint chain and reachable encrypted payloads.
    Verify(Box<RestoreVerifyArgs>),
}

#[derive(Args)]
struct RestoreVerifyArgs {
    /// Stable repository identifier bound into the keyring envelope context.
    #[arg(long, env = "RS3_REPOSITORY_ID")]
    repository_id: String,
    /// Hex-encoded public repository salt bound into the keyring envelope context.
    #[arg(long, env = "RS3_REPOSITORY_SALT_HEX")]
    repository_salt_hex: String,
    /// Accepted checkpoint sequence from the trusted anchor.
    #[arg(long)]
    checkpoint_sequence: u64,
    /// Accepted checkpoint identifier from the trusted anchor.
    #[arg(long)]
    checkpoint_id: String,
    /// Provider version identifier for the accepted checkpoint object, when available.
    #[arg(long)]
    checkpoint_version_id: Option<String>,
    /// Accepted checkpoint payload digest from the trusted anchor.
    #[arg(long)]
    checkpoint_digest: String,
    /// Repository key source.
    #[command(flatten)]
    keys: RestoreKeySourceArgs,
    /// Backend object-store target.
    #[command(flatten)]
    backend: RestoreBackendArgs,
    /// Fail unless every restore-critical object is protected by provider retention or legal hold.
    #[arg(long, default_value_t = false)]
    require_provider_delete_protection: bool,
    /// Output format.
    #[arg(long, value_enum, default_value_t = RestoreReportFormat::Json)]
    format: RestoreReportFormat,
}

#[derive(Clone, Args)]
struct RestoreKeySourceArgs {
    /// Backend object containing the encrypted keyring envelope.
    #[arg(long, env = "RS3_KEYRING_ENVELOPE_OBJECT_ID")]
    keyring_envelope_object_id: String,
    /// Operator-visible wrapping key identifier expected by the envelope.
    #[arg(long, env = "RS3_KEYRING_WRAPPING_KEY_ID", default_value = "wrap-v1")]
    wrapping_key_id: String,
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
        checkpoint_version_id: args
            .checkpoint_version_id
            .map(BackendVersionId::new)
            .transpose()?,
        payload_digest: args.checkpoint_digest,
    };
    let keyring = keyring_from_envelope(&store, &context, &args.keys).await?;
    let repository = Repository::with_keyring(store, keyring);

    let report = repository
        .verify_restore(&accepted)
        .await
        .context("restore verification failed")?;

    if args.require_provider_delete_protection
        && report.protection.delete_protected_object_count != report.protection.checked_object_count
    {
        let missing = report
            .protection
            .checked_object_count
            .saturating_sub(report.protection.delete_protected_object_count);
        bail!(
            "provider delete protection missing on {missing}/{} restore-critical object(s)",
            report.protection.checked_object_count
        );
    }

    Ok(report)
}

async fn keyring_from_envelope<S>(
    store: &S,
    context: &RepositoryKeyContext,
    args: &RestoreKeySourceArgs,
) -> Result<KeyRing>
where
    S: BlobStore,
{
    let object_id = BackendObjectId::new(args.keyring_envelope_object_id.clone())?;
    let wrapping_key_id = args.wrapping_key_id.as_str();
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
            "checkpoint_version_id": report.accepted.checkpoint_version_id.as_ref().map(BackendVersionId::as_str),
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
            "delete_protected_objects": report.protection.delete_protected_object_count,
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
    if let Some(version_id) = report.accepted.checkpoint_version_id.as_ref() {
        println!("checkpoint_version_id={}", version_id.as_str());
    }
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
    println!(
        "protection_delete_protected_objects={}",
        report.protection.delete_protected_object_count
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
    use rs3_repository::{CheckpointPosition, Repository, RepositoryOptions, RepositoryPutOptions};
    use rs3_storage::MemoryBlobStore;
    use rs3_types::{BackendObjectId, RepositoryId, RetentionMode, RetentionPolicy};

    const SALT_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const WRAPPING_KEY_HEX: &str =
        "3333333333333333333333333333333333333333333333333333333333333333";
    const WRAPPING_KEY_ID: &str = "wrap-test";

    fn test_context() -> RepositoryKeyContext {
        RepositoryKeyContext::new(
            RepositoryId::new("restore-cli").unwrap_or_else(|error| panic!("{error}")),
            hex::decode(SALT_HEX).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"))
    }

    fn wrapping_key() -> SecretBytes {
        SecretBytes::new(hex::decode(WRAPPING_KEY_HEX).unwrap_or_else(|error| panic!("{error}")))
            .unwrap_or_else(|error| panic!("{error}"))
    }

    fn test_keyring() -> KeyRing {
        KeyRing::generate_random().unwrap_or_else(|error| panic!("{error}"))
    }

    async fn store_keyring_envelope<S>(repo: &Repository<S>, keyring: &KeyRing) -> BackendObjectId
    where
        S: rs3_storage::BlobStore,
    {
        let envelope = keyring
            .seal_keyring_envelope(&test_context(), WRAPPING_KEY_ID, &wrapping_key(), 1)
            .unwrap_or_else(|error| panic!("{error}"));
        let reference = repo
            .store_keyring_envelope(&envelope)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        reference.object_id
    }

    fn restore_verify_args(
        checkpoint: &CheckpointPosition,
        keyring_envelope_object_id: &BackendObjectId,
        require_provider_delete_protection: bool,
    ) -> RestoreVerifyArgs {
        RestoreVerifyArgs {
            repository_id: "restore-cli".to_owned(),
            repository_salt_hex: SALT_HEX.to_owned(),
            checkpoint_sequence: checkpoint.sequence.get(),
            checkpoint_id: checkpoint.checkpoint_id.as_str().to_owned(),
            checkpoint_version_id: checkpoint
                .checkpoint_version_id
                .as_ref()
                .map(|version_id| version_id.as_str().to_owned()),
            checkpoint_digest: checkpoint.payload_digest.clone(),
            keys: RestoreKeySourceArgs {
                keyring_envelope_object_id: keyring_envelope_object_id.as_str().to_owned(),
                wrapping_key_id: WRAPPING_KEY_ID.to_owned(),
                wrapping_key_hex: Some(WRAPPING_KEY_HEX.to_owned()),
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
            require_provider_delete_protection,
            format: RestoreReportFormat::Json,
        }
    }

    #[tokio::test]
    async fn restore_verify_command_uses_supplied_checkpoint_position() {
        let store = MemoryBlobStore::new();
        let keyring = test_keyring();
        let repo = Repository::with_keyring(store.clone(), keyring.clone());
        let envelope_object_id = store_keyring_envelope(&repo, &keyring).await;
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
        let args = restore_verify_args(&committed.checkpoint, &envelope_object_id, false);

        let report = verify_with_store(args, store)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(report.payload_object_count, 1);
        assert_eq!(report.payload_plaintext_bytes, 4);
    }

    #[tokio::test]
    async fn restore_verify_can_require_provider_delete_protection() {
        let store = MemoryBlobStore::new();
        let keyring = test_keyring();
        let repo = Repository::with_keyring_and_options(
            store.clone(),
            keyring.clone(),
            RepositoryOptions {
                payload_segment_size: rs3_repository::DEFAULT_PAYLOAD_SEGMENT_SIZE,
                default_retention: Some(RetentionPolicy::new(RetentionMode::Compliance, 30)),
            },
        );
        let envelope_object_id = store_keyring_envelope(&repo, &keyring).await;
        let anchor = MemoryCheckpointAnchor::new();
        let committed = repo
            .put_committed(
                rs3_types::LogicalPath::new("restore/protected")
                    .unwrap_or_else(|error| panic!("{error}")),
                Bytes::from_static(b"body"),
                RepositoryPutOptions::default(),
                &anchor,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let args = restore_verify_args(&committed.checkpoint, &envelope_object_id, true);

        let report = verify_with_store(args, store)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            report.protection.delete_protected_object_count,
            report.protection.checked_object_count
        );
    }

    #[tokio::test]
    async fn restore_verify_rejects_missing_provider_delete_protection_when_required() {
        let store = MemoryBlobStore::new();
        let keyring = test_keyring();
        let repo = Repository::with_keyring(store.clone(), keyring.clone());
        let envelope_object_id = store_keyring_envelope(&repo, &keyring).await;
        let anchor = MemoryCheckpointAnchor::new();
        let committed = repo
            .put_committed(
                rs3_types::LogicalPath::new("restore/unprotected")
                    .unwrap_or_else(|error| panic!("{error}")),
                Bytes::from_static(b"body"),
                RepositoryPutOptions::default(),
                &anchor,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let args = restore_verify_args(&committed.checkpoint, &envelope_object_id, true);

        let error = match verify_with_store(args, store).await {
            Ok(report) => panic!("restore verification unexpectedly passed: {report:?}"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("provider delete protection missing")
        );
    }

    #[test]
    fn restore_verify_rejects_bad_secret_hex() {
        assert!(secret_from_hex("--wrapping-key-hex", "not-hex").is_err());
        assert!(secret_from_hex("--wrapping-key-hex", "11").is_err());
    }
}
