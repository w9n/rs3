//! Repository keyring envelope automation.

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand, ValueEnum};
use rs3_crypto::{
    KeyRing, KeyringEnvelope, MIN_REPOSITORY_SALT_LEN, RepositoryKeyContext, SecretBytes,
};
use rs3_repository::{Repository, RepositoryOptions};
use rs3_storage::{BlobStore, ByteRange, FilesystemBlobStore};
#[cfg(feature = "s3")]
use rs3_storage::{S3BlobStore, S3BlobStoreConfig};
use rs3_types::{BackendObjectId, RepositoryId, RetentionMode, RetentionPolicy};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Creates and rewraps encrypted repository keyring envelopes.
#[derive(Debug, Args)]
pub(crate) struct KeyringArgs {
    #[command(subcommand)]
    command: KeyringCommand,
}

#[derive(Debug, Subcommand)]
enum KeyringCommand {
    /// Generate random repository data keys and store a keyring envelope.
    Init(Box<KeyringInitArgs>),
    /// Re-encrypt an existing keyring envelope with a new wrapping key.
    ///
    /// This does not rotate repository data keys and is not compromise recovery
    /// if the old wrapping key and old envelope may have been exposed together.
    Rewrap(Box<KeyringRewrapArgs>),
}

#[derive(Debug, Args)]
struct KeyringInitArgs {
    /// Stable repository identifier bound into the envelope.
    #[arg(long, env = "RS3_REPOSITORY_ID")]
    repository_id: String,
    /// Hex-encoded public repository salt. Generated when omitted.
    #[arg(long, env = "RS3_REPOSITORY_SALT_HEX")]
    repository_salt_hex: Option<String>,
    /// Operator-visible wrapping key identifier.
    #[arg(long, env = "RS3_KEYRING_WRAPPING_KEY_ID")]
    wrapping_key_id: String,
    /// Hex-encoded high-entropy wrapping key.
    #[arg(long, env = "RS3_KEYRING_WRAPPING_KEY_HEX", hide_env_values = true)]
    wrapping_key_hex: Option<String>,
    /// File containing the hex-encoded high-entropy wrapping key.
    #[arg(long)]
    wrapping_key_hex_file: Option<PathBuf>,
    /// Generate and print a new high-entropy wrapping key.
    #[arg(long, default_value_t = false)]
    generate_wrapping_key: bool,
    /// Monotonic envelope generation.
    #[arg(long, default_value_t = 1)]
    generation: u64,
    /// Backend object-store target.
    #[command(flatten)]
    backend: KeyringBackendArgs,
    /// Optional provider retention for the newly written envelope object.
    #[command(flatten)]
    retention: KeyringRetentionArgs,
    /// Output format.
    #[arg(long, value_enum, default_value_t = KeyringReportFormat::Json)]
    format: KeyringReportFormat,
}

#[derive(Debug, Args)]
struct KeyringRewrapArgs {
    /// Stable repository identifier bound into the envelope.
    #[arg(long, env = "RS3_REPOSITORY_ID")]
    repository_id: String,
    /// Hex-encoded public repository salt bound into the envelope.
    #[arg(long, env = "RS3_REPOSITORY_SALT_HEX")]
    repository_salt_hex: String,
    /// Existing envelope object identifier.
    #[arg(long, env = "RS3_KEYRING_ENVELOPE_OBJECT_ID")]
    envelope_object_id: String,
    /// Current wrapping key identifier.
    #[arg(long, env = "RS3_KEYRING_WRAPPING_KEY_ID")]
    old_wrapping_key_id: String,
    /// Hex-encoded current wrapping key.
    #[arg(long, env = "RS3_KEYRING_WRAPPING_KEY_HEX", hide_env_values = true)]
    old_wrapping_key_hex: Option<String>,
    /// File containing the hex-encoded current wrapping key.
    #[arg(long)]
    old_wrapping_key_hex_file: Option<PathBuf>,
    /// New operator-visible wrapping key identifier.
    #[arg(long)]
    new_wrapping_key_id: String,
    /// Hex-encoded new high-entropy wrapping key.
    #[arg(long, hide_env_values = true)]
    new_wrapping_key_hex: Option<String>,
    /// File containing the hex-encoded new high-entropy wrapping key.
    #[arg(long)]
    new_wrapping_key_hex_file: Option<PathBuf>,
    /// Generate and print a new high-entropy wrapping key.
    #[arg(long, default_value_t = false)]
    generate_new_wrapping_key: bool,
    /// New monotonic envelope generation. Defaults to existing generation + 1.
    #[arg(long)]
    new_generation: Option<u64>,
    /// Backend object-store target.
    #[command(flatten)]
    backend: KeyringBackendArgs,
    /// Optional provider retention for the newly written envelope object.
    #[command(flatten)]
    retention: KeyringRetentionArgs,
    /// Output format.
    #[arg(long, value_enum, default_value_t = KeyringReportFormat::Json)]
    format: KeyringReportFormat,
}

#[derive(Clone, Debug, Args)]
struct KeyringBackendArgs {
    /// Backend implementation used by the keyring operation.
    #[arg(long, value_enum, default_value_t = KeyringBackend::Filesystem)]
    backend: KeyringBackend,
    /// Filesystem backend root used with `--backend filesystem`.
    #[arg(long)]
    backend_dir: Option<PathBuf>,
    /// S3 bucket used with `--backend s3`.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_KEYRING_S3_BUCKET")]
    s3_bucket: Option<String>,
    /// S3 key prefix used with `--backend s3`.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_KEYRING_S3_PREFIX")]
    s3_prefix: Option<String>,
    /// Custom S3 endpoint URL used with `--backend s3`.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_KEYRING_S3_ENDPOINT_URL")]
    s3_endpoint_url: Option<String>,
    /// AWS region override used with `--backend s3`.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_KEYRING_S3_REGION")]
    s3_region: Option<String>,
    /// Allow plain HTTP for local S3-compatible endpoints used with `--backend s3`.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_KEYRING_S3_ALLOW_HTTP", default_value_t = false)]
    s3_allow_http: bool,
    /// Use virtual-hosted bucket addressing instead of path-style addressing.
    #[cfg(feature = "s3")]
    #[arg(
        long,
        env = "RS3_KEYRING_S3_VIRTUAL_HOSTED_STYLE",
        default_value_t = false
    )]
    s3_virtual_hosted_style: bool,
}

#[derive(Clone, Debug, Default, Args)]
struct KeyringRetentionArgs {
    /// Provider retention mode for the newly written envelope object.
    #[arg(long, value_enum)]
    envelope_retention_mode: Option<KeyringRetentionMode>,
    /// Provider retention duration in days for the newly written envelope object.
    #[arg(long)]
    envelope_retention_days: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum KeyringRetentionMode {
    /// Governance retention, bypassable only with special provider permission.
    Governance,
    /// Compliance retention, not normally bypassable before expiry.
    Compliance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum KeyringBackend {
    /// Local filesystem backend.
    Filesystem,
    /// S3-compatible backend using the default environment/config chain.
    #[cfg(feature = "s3")]
    S3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum KeyringReportFormat {
    /// JSON object.
    Json,
    /// Environment-variable assignment lines.
    Env,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct KeyringReport {
    repository_id: String,
    repository_salt_hex: String,
    envelope_object_id: String,
    envelope_digest: String,
    generation: u64,
    wrapping_key_id: String,
    envelope_retention: Option<RetentionPolicy>,
    generated_wrapping_key_hex: Option<String>,
}

pub(crate) fn run(args: KeyringArgs) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build keyring runtime")?;
    runtime.block_on(run_async(args))
}

async fn run_async(args: KeyringArgs) -> Result<()> {
    match args.command {
        KeyringCommand::Init(args) => {
            let format = args.format;
            let report = init(*args).await?;
            report.print(format)?;
        }
        KeyringCommand::Rewrap(args) => {
            let format = args.format;
            let report = rewrap(*args).await?;
            report.print(format)?;
        }
    }
    Ok(())
}

async fn init(args: KeyringInitArgs) -> Result<KeyringReport> {
    match args.backend.backend {
        KeyringBackend::Filesystem => {
            let store = filesystem_store(&args.backend)?;
            init_with_store(args, store).await
        }
        #[cfg(feature = "s3")]
        KeyringBackend::S3 => {
            let store = s3_store(&args.backend).await?;
            init_with_store(args, store).await
        }
    }
}

async fn init_with_store<S>(args: KeyringInitArgs, store: S) -> Result<KeyringReport>
where
    S: BlobStore,
{
    let repository_id = repository_id(&args.repository_id)?;
    let repository_salt_hex = match args.repository_salt_hex {
        Some(value) => value,
        None => random_hex(MIN_REPOSITORY_SALT_LEN)?,
    };
    let context = repository_context(repository_id, &repository_salt_hex)?;
    let wrapping_key = wrapping_key_input(
        args.wrapping_key_hex,
        args.wrapping_key_hex_file,
        args.generate_wrapping_key,
        "--wrapping-key-hex",
        "--wrapping-key-hex-file",
        "--generate-wrapping-key",
    )?;
    let keyring = KeyRing::generate_random()?;
    let envelope = keyring.seal_keyring_envelope(
        &context,
        &args.wrapping_key_id,
        &wrapping_key.secret,
        args.generation,
    )?;
    let envelope_retention = args.retention.policy()?;
    let repository = repository_with_keyring(store, keyring, envelope_retention);
    let reference = repository.store_keyring_envelope(&envelope).await?;

    Ok(KeyringReport {
        repository_id: context.repository_id().as_str().to_owned(),
        repository_salt_hex,
        envelope_object_id: reference.object_id.as_str().to_owned(),
        envelope_digest: reference.digest,
        generation: reference.generation,
        wrapping_key_id: args.wrapping_key_id,
        envelope_retention,
        generated_wrapping_key_hex: wrapping_key.generated_hex,
    })
}

async fn rewrap(args: KeyringRewrapArgs) -> Result<KeyringReport> {
    match args.backend.backend {
        KeyringBackend::Filesystem => {
            let store = filesystem_store(&args.backend)?;
            rewrap_with_store(args, store).await
        }
        #[cfg(feature = "s3")]
        KeyringBackend::S3 => {
            let store = s3_store(&args.backend).await?;
            rewrap_with_store(args, store).await
        }
    }
}

async fn rewrap_with_store<S>(args: KeyringRewrapArgs, store: S) -> Result<KeyringReport>
where
    S: BlobStore,
{
    let repository_id = repository_id(&args.repository_id)?;
    let context = repository_context(repository_id, &args.repository_salt_hex)?;
    let envelope_object_id = BackendObjectId::new(args.envelope_object_id.clone())?;
    let old_wrapping_key = wrapping_key_input(
        args.old_wrapping_key_hex,
        args.old_wrapping_key_hex_file,
        false,
        "--old-wrapping-key-hex",
        "--old-wrapping-key-hex-file",
        "--generate-new-wrapping-key",
    )?
    .secret;
    let new_wrapping_key = wrapping_key_input(
        args.new_wrapping_key_hex,
        args.new_wrapping_key_hex_file,
        args.generate_new_wrapping_key,
        "--new-wrapping-key-hex",
        "--new-wrapping-key-hex-file",
        "--generate-new-wrapping-key",
    )?;
    let body = store
        .get_range(&envelope_object_id, ByteRange::Full)
        .await
        .context("failed to read existing keyring envelope")?;
    let envelope = KeyringEnvelope::from_object_bytes(&body)?;
    let new_generation = args
        .new_generation
        .unwrap_or_else(|| envelope.generation.saturating_add(1));
    if new_generation <= envelope.generation {
        bail!(
            "--new-generation must be greater than existing envelope generation {}",
            envelope.generation
        );
    }
    let rewrapped = envelope.rewrap(
        &context,
        &args.old_wrapping_key_id,
        &old_wrapping_key,
        &args.new_wrapping_key_id,
        &new_wrapping_key.secret,
        new_generation,
    )?;
    let keyring = rewrapped.open(
        &context,
        &args.new_wrapping_key_id,
        &new_wrapping_key.secret,
    )?;
    let envelope_retention = args.retention.policy()?;
    let repository = repository_with_keyring(store, keyring, envelope_retention);
    let reference = repository.store_keyring_envelope(&rewrapped).await?;

    Ok(KeyringReport {
        repository_id: context.repository_id().as_str().to_owned(),
        repository_salt_hex: args.repository_salt_hex,
        envelope_object_id: reference.object_id.as_str().to_owned(),
        envelope_digest: reference.digest,
        generation: reference.generation,
        wrapping_key_id: args.new_wrapping_key_id,
        envelope_retention,
        generated_wrapping_key_hex: new_wrapping_key.generated_hex,
    })
}

fn repository_with_keyring<S>(
    store: S,
    keyring: KeyRing,
    default_retention: Option<RetentionPolicy>,
) -> Repository<S>
where
    S: BlobStore,
{
    Repository::with_keyring_and_options(
        store,
        keyring,
        RepositoryOptions {
            default_retention,
            ..RepositoryOptions::default()
        },
    )
}

fn filesystem_store(args: &KeyringBackendArgs) -> Result<FilesystemBlobStore> {
    let root = args
        .backend_dir
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--backend-dir is required with --backend filesystem"))?;
    FilesystemBlobStore::new(root).context("failed to create filesystem backend")
}

#[cfg(feature = "s3")]
async fn s3_store(args: &KeyringBackendArgs) -> Result<S3BlobStore> {
    let bucket = args
        .s3_bucket
        .clone()
        .context("--s3-bucket or RS3_KEYRING_S3_BUCKET is required with --backend s3")?;
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

fn repository_id(value: &str) -> Result<RepositoryId> {
    RepositoryId::new(value.to_owned()).map_err(Into::into)
}

fn repository_context(
    repository_id: RepositoryId,
    repository_salt_hex: &str,
) -> Result<RepositoryKeyContext> {
    let salt = hex::decode(repository_salt_hex).context("repository salt must be hex encoded")?;
    RepositoryKeyContext::new(repository_id, salt).map_err(Into::into)
}

impl KeyringRetentionArgs {
    fn policy(&self) -> Result<Option<RetentionPolicy>> {
        match (self.envelope_retention_mode, self.envelope_retention_days) {
            (None, None) => Ok(None),
            (Some(_), None) => {
                bail!("--envelope-retention-days is required with --envelope-retention-mode")
            }
            (None, Some(_)) => {
                bail!("--envelope-retention-mode is required with --envelope-retention-days")
            }
            (Some(_), Some(0)) => {
                bail!("--envelope-retention-days must be greater than zero")
            }
            (Some(mode), Some(days)) => Ok(Some(RetentionPolicy::new(mode.into(), days))),
        }
    }
}

impl From<KeyringRetentionMode> for RetentionMode {
    fn from(mode: KeyringRetentionMode) -> Self {
        match mode {
            KeyringRetentionMode::Governance => Self::Governance,
            KeyringRetentionMode::Compliance => Self::Compliance,
        }
    }
}

struct WrappingKeyInput {
    secret: SecretBytes,
    generated_hex: Option<String>,
}

fn wrapping_key_input(
    provided_hex: Option<String>,
    provided_file: Option<PathBuf>,
    generate: bool,
    provided_flag: &str,
    file_flag: &str,
    generate_flag: &str,
) -> Result<WrappingKeyInput> {
    let input_count = usize::from(provided_hex.is_some())
        + usize::from(provided_file.is_some())
        + usize::from(generate);
    if input_count != 1 {
        bail!("exactly one of {provided_flag}, {file_flag}, or {generate_flag} is required");
    }

    if let Some(hex) = provided_hex {
        Ok(WrappingKeyInput {
            secret: secret_from_hex(provided_flag, &hex)?,
            generated_hex: None,
        })
    } else if let Some(path) = provided_file {
        let hex = read_secret_hex_file(file_flag, &path)?;
        Ok(WrappingKeyInput {
            secret: secret_from_hex(file_flag, &hex)?,
            generated_hex: None,
        })
    } else {
        if !generate {
            bail!("{generate_flag} was not selected");
        }
        {
            let hex = random_hex(SecretBytes::MIN_LEN)?;
            Ok(WrappingKeyInput {
                secret: secret_from_hex(generate_flag, &hex)?,
                generated_hex: Some(hex),
            })
        }
    }
}

fn read_secret_hex_file(label: &str, path: &Path) -> Result<Zeroizing<String>> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {label} {}", path.display()))?;
    Ok(Zeroizing::new(contents.trim().to_owned()))
}

fn secret_from_hex(label: &str, value: &str) -> Result<SecretBytes> {
    let bytes =
        Zeroizing::new(hex::decode(value).with_context(|| format!("{label} must be hex encoded"))?);
    SecretBytes::new(bytes.to_vec()).with_context(|| format!("{label} is not usable"))
}

fn random_hex(len: usize) -> Result<String> {
    let mut bytes = Zeroizing::new(vec![0_u8; len]);
    getrandom::fill(bytes.as_mut_slice())
        .map_err(|error| anyhow::anyhow!("failed to read random bytes: {error}"))?;
    Ok(hex::encode(bytes.as_slice()))
}

impl KeyringReport {
    fn print(&self, format: KeyringReportFormat) -> Result<()> {
        match format {
            KeyringReportFormat::Json => self.print_json(),
            KeyringReportFormat::Env => {
                self.print_env();
                Ok(())
            }
        }
    }

    fn print_json(&self) -> Result<()> {
        let report = serde_json::json!({
            "repository_id": self.repository_id,
            "repository_salt_hex": self.repository_salt_hex,
            "keyring_envelope": {
                "object_id": self.envelope_object_id,
                "digest": self.envelope_digest,
                "generation": self.generation,
                "retention": self.envelope_retention.map(|retention| {
                    serde_json::json!({
                        "mode": retention_mode_name(retention.mode),
                        "days": retention.retain_days,
                    })
                }),
            },
            "wrapping_key": {
                "id": self.wrapping_key_id,
                "generated_key_hex": self.generated_wrapping_key_hex,
            },
            "server_env": self.server_env(),
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
        Ok(())
    }

    fn print_env(&self) {
        println!("RS3_REPOSITORY_ID={}", shell_quote(&self.repository_id));
        println!(
            "RS3_REPOSITORY_SALT_HEX={}",
            shell_quote(&self.repository_salt_hex)
        );
        println!(
            "RS3_KEYRING_ENVELOPE_OBJECT_ID={}",
            shell_quote(&self.envelope_object_id)
        );
        println!(
            "RS3_KEYRING_WRAPPING_KEY_ID={}",
            shell_quote(&self.wrapping_key_id)
        );
        if let Some(secret) = self.generated_wrapping_key_hex.as_ref() {
            println!("RS3_KEYRING_WRAPPING_KEY_HEX={}", shell_quote(secret));
        } else {
            println!("RS3_KEYRING_WRAPPING_KEY_HEX=<external-secret>");
        }
    }

    fn server_env(&self) -> serde_json::Value {
        let mut env = serde_json::Map::new();
        env.insert(
            "RS3_REPOSITORY_ID".to_owned(),
            serde_json::Value::String(self.repository_id.clone()),
        );
        env.insert(
            "RS3_REPOSITORY_SALT_HEX".to_owned(),
            serde_json::Value::String(self.repository_salt_hex.clone()),
        );
        env.insert(
            "RS3_KEYRING_ENVELOPE_OBJECT_ID".to_owned(),
            serde_json::Value::String(self.envelope_object_id.clone()),
        );
        env.insert(
            "RS3_KEYRING_WRAPPING_KEY_ID".to_owned(),
            serde_json::Value::String(self.wrapping_key_id.clone()),
        );
        if let Some(secret) = self.generated_wrapping_key_hex.as_ref() {
            env.insert(
                "RS3_KEYRING_WRAPPING_KEY_HEX".to_owned(),
                serde_json::Value::String(secret.clone()),
            );
        }
        serde_json::Value::Object(env)
    }
}

fn retention_mode_name(mode: RetentionMode) -> &'static str {
    match mode {
        RetentionMode::None => "none",
        RetentionMode::Governance => "governance",
        RetentionMode::Compliance => "compliance",
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::{
        KeyringInitArgs, KeyringReportFormat, KeyringRetentionArgs, KeyringRetentionMode,
        KeyringRewrapArgs, init_with_store, rewrap_with_store, secret_from_hex,
    };
    use crate::keyring::{KeyringBackend, KeyringBackendArgs};
    use rs3_crypto::{KeyringEnvelope, RepositoryKeyContext, SecretBytes};
    use rs3_storage::{BlobStore, ByteRange, MemoryBlobStore};
    use rs3_types::{BackendObjectId, RepositoryId, RetentionMode, RetentionPolicy};

    const SALT_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const OLD_WRAP_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const NEW_WRAP_HEX: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    #[tokio::test]
    async fn keyring_init_stores_openable_envelope() {
        let store = MemoryBlobStore::new();
        let args = KeyringInitArgs {
            repository_id: "repo-a".to_owned(),
            repository_salt_hex: Some(SALT_HEX.to_owned()),
            wrapping_key_id: "wrap-v1".to_owned(),
            wrapping_key_hex: Some(OLD_WRAP_HEX.to_owned()),
            wrapping_key_hex_file: None,
            generate_wrapping_key: false,
            generation: 1,
            backend: backend_args(),
            retention: KeyringRetentionArgs::default(),
            format: KeyringReportFormat::Json,
        };

        let report = init_with_store(args, store.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let body = store
            .get_range(
                &rs3_types::BackendObjectId::new(report.envelope_object_id)
                    .unwrap_or_else(|error| panic!("{error}")),
                ByteRange::Full,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(body.starts_with(b"rs3:keyring-envelope-object:v1\n"));
        assert_eq!(report.generation, 1);
        assert!(report.generated_wrapping_key_hex.is_none());
    }

    #[tokio::test]
    async fn keyring_rewrap_preserves_existing_data_keys() {
        let store = MemoryBlobStore::new();
        let init_report = init_with_store(init_args(), store.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let old_envelope = envelope_from_store(&store, &init_report.envelope_object_id).await;
        let context = context();
        let old_keyring = old_envelope
            .open(&context, "wrap-v1", &secret(OLD_WRAP_HEX))
            .unwrap_or_else(|error| panic!("{error}"));
        let rewrap = KeyringRewrapArgs {
            repository_id: "repo-a".to_owned(),
            repository_salt_hex: SALT_HEX.to_owned(),
            envelope_object_id: init_report.envelope_object_id,
            old_wrapping_key_id: "wrap-v1".to_owned(),
            old_wrapping_key_hex: Some(OLD_WRAP_HEX.to_owned()),
            old_wrapping_key_hex_file: None,
            new_wrapping_key_id: "wrap-v2".to_owned(),
            new_wrapping_key_hex: Some(NEW_WRAP_HEX.to_owned()),
            new_wrapping_key_hex_file: None,
            generate_new_wrapping_key: false,
            new_generation: None,
            backend: backend_args(),
            retention: KeyringRetentionArgs::default(),
            format: KeyringReportFormat::Json,
        };

        let rewrapped_report = rewrap_with_store(rewrap, store.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let new_envelope = envelope_from_store(&store, &rewrapped_report.envelope_object_id).await;
        let new_keyring = new_envelope
            .open(&context, "wrap-v2", &secret(NEW_WRAP_HEX))
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(rewrapped_report.generation, 2);
        assert_eq!(new_keyring.descriptors(), old_keyring.descriptors());
        assert_eq!(
            new_keyring
                .derive_backend_object_id("segments", b"same")
                .unwrap_or_else(|error| panic!("{error}")),
            old_keyring
                .derive_backend_object_id("segments", b"same")
                .unwrap_or_else(|error| panic!("{error}"))
        );
    }

    #[tokio::test]
    async fn keyring_rewrap_applies_configured_envelope_retention() {
        let store = MemoryBlobStore::new();
        let init_report = init_with_store(init_args(), store.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let rewrap = KeyringRewrapArgs {
            repository_id: "repo-a".to_owned(),
            repository_salt_hex: SALT_HEX.to_owned(),
            envelope_object_id: init_report.envelope_object_id,
            old_wrapping_key_id: "wrap-v1".to_owned(),
            old_wrapping_key_hex: Some(OLD_WRAP_HEX.to_owned()),
            old_wrapping_key_hex_file: None,
            new_wrapping_key_id: "wrap-v2".to_owned(),
            new_wrapping_key_hex: Some(NEW_WRAP_HEX.to_owned()),
            new_wrapping_key_hex_file: None,
            generate_new_wrapping_key: false,
            new_generation: None,
            backend: backend_args(),
            retention: KeyringRetentionArgs {
                envelope_retention_mode: Some(KeyringRetentionMode::Compliance),
                envelope_retention_days: Some(30),
            },
            format: KeyringReportFormat::Json,
        };

        let rewrapped_report = rewrap_with_store(rewrap, store.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let object_id = BackendObjectId::new(rewrapped_report.envelope_object_id)
            .unwrap_or_else(|error| panic!("{error}"));
        let metadata = store
            .head(&object_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            metadata.retention,
            Some(RetentionPolicy::new(RetentionMode::Compliance, 30))
        );
        assert_eq!(
            rewrapped_report.envelope_retention,
            Some(RetentionPolicy::new(RetentionMode::Compliance, 30))
        );
    }

    #[test]
    fn wrapping_key_requires_hex_secret_material() {
        assert!(secret_from_hex("--wrapping-key-hex", "not-hex").is_err());
        assert!(secret_from_hex("--wrapping-key-hex", "11").is_err());
    }

    fn init_args() -> KeyringInitArgs {
        KeyringInitArgs {
            repository_id: "repo-a".to_owned(),
            repository_salt_hex: Some(SALT_HEX.to_owned()),
            wrapping_key_id: "wrap-v1".to_owned(),
            wrapping_key_hex: Some(OLD_WRAP_HEX.to_owned()),
            wrapping_key_hex_file: None,
            generate_wrapping_key: false,
            generation: 1,
            backend: backend_args(),
            retention: KeyringRetentionArgs::default(),
            format: KeyringReportFormat::Json,
        }
    }

    fn backend_args() -> KeyringBackendArgs {
        KeyringBackendArgs {
            backend: KeyringBackend::Filesystem,
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
        }
    }

    async fn envelope_from_store(store: &MemoryBlobStore, object_id: &str) -> KeyringEnvelope {
        let object_id =
            BackendObjectId::new(object_id.to_owned()).unwrap_or_else(|error| panic!("{error}"));
        let body = store
            .get_range(&object_id, ByteRange::Full)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        KeyringEnvelope::from_object_bytes(&body).unwrap_or_else(|error| panic!("{error}"))
    }

    fn context() -> RepositoryKeyContext {
        let repository_id = RepositoryId::new("repo-a").unwrap_or_else(|error| panic!("{error}"));
        RepositoryKeyContext::new(
            repository_id,
            hex::decode(SALT_HEX).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"))
    }

    fn secret(value: &str) -> SecretBytes {
        SecretBytes::new(hex::decode(value).unwrap_or_else(|error| panic!("{error}")))
            .unwrap_or_else(|error| panic!("{error}"))
    }
}
