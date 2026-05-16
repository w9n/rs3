//! v2 repository operations that are safe to run outside the gateway.

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand, ValueEnum};
use rs3_crypto::{FormatEnvelope, KeyRing, KeyringEnvelope, RepositoryKeyContext, SecretBytes};
use rs3_repository::v2::{
    V2AnchorState, V2CommitChain, V2CommitStore, V2CommitStoreOptions, V2FormatRef, V2FormatRoot,
    V2KeyringEnvelopeRootRef, V2ProviderProfile, V2RecoveryBundle,
};
use rs3_storage::{BlobStore, ByteRange, FilesystemBlobStore};
#[cfg(feature = "s3")]
use rs3_storage::{S3BlobStore, S3BlobStoreConfig};
use rs3_types::{
    BackendObjectId, BackendVersionId, KeyId, RepositoryId, RetentionMode, RetentionPolicy,
    Sequence,
};
use serde::Deserialize;
use std::io::Read;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const V2_RESTORE_BUNDLE_SCHEMA: &str = "rs3.restore-bundle.v2-preview.v1";
const V2_VERIFY_BUNDLE_SCHEMA: &str = "rs3.xtask.v2-verify-bundle.v1";

/// v2 repository automation.
#[derive(Args)]
pub(crate) struct V2Args {
    #[command(subcommand)]
    command: V2Command,
}

#[derive(Subcommand)]
enum V2Command {
    /// Verify a trusted v2 restore bundle without writing an anchor.
    VerifyBundle(Box<V2VerifyBundleArgs>),
}

#[derive(Args)]
struct V2VerifyBundleArgs {
    /// JSON bundle from `rs3-server export-restore-bundle`; use `-` for stdin.
    #[arg(long)]
    bundle_file: String,
    /// Stable repository identifier. Defaults to the repository ID inside the bundle.
    #[arg(long, env = "RS3_REPOSITORY_ID")]
    repository_id: Option<String>,
    /// Hex-encoded public repository salt bound into the v2 format root.
    #[arg(long, env = "RS3_REPOSITORY_SALT_HEX")]
    repository_salt_hex: String,
    /// Wrapping key identifier recorded in the v2 format and keyring envelopes.
    #[arg(long, env = "RS3_KEYRING_WRAPPING_KEY_ID", default_value = "wrap-v1")]
    wrapping_key_id: String,
    /// Hex-encoded high-entropy wrapping key.
    #[arg(long, env = "RS3_KEYRING_WRAPPING_KEY_HEX", hide_env_values = true)]
    wrapping_key_hex: Option<String>,
    /// File containing the hex-encoded high-entropy wrapping key.
    #[arg(long)]
    wrapping_key_hex_file: Option<PathBuf>,
    /// Backend object-store target.
    #[command(flatten)]
    backend: V2BackendArgs,
    /// Output format.
    #[arg(long, value_enum, default_value_t = V2ReportFormat::Json)]
    format: V2ReportFormat,
}

#[derive(Clone, Debug, Args)]
struct V2BackendArgs {
    /// Backend implementation used by verification.
    #[arg(long, value_enum, default_value_t = V2Backend::Filesystem)]
    backend: V2Backend,
    /// Filesystem backend root used with `--backend filesystem`.
    #[arg(long)]
    backend_dir: Option<PathBuf>,
    /// S3 bucket used with `--backend s3`.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_V2_S3_BUCKET")]
    s3_bucket: Option<String>,
    /// S3 key prefix used with `--backend s3`.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_V2_S3_PREFIX")]
    s3_prefix: Option<String>,
    /// Custom S3 endpoint URL used with `--backend s3`.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_V2_S3_ENDPOINT_URL")]
    s3_endpoint_url: Option<String>,
    /// AWS region override used with `--backend s3`.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_V2_S3_REGION")]
    s3_region: Option<String>,
    /// Allow plain HTTP for local S3-compatible endpoints used with `--backend s3`.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_V2_S3_ALLOW_HTTP", default_value_t = false)]
    s3_allow_http: bool,
    /// Use virtual-hosted bucket addressing instead of path-style addressing.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_V2_S3_VIRTUAL_HOSTED_STYLE", default_value_t = false)]
    s3_virtual_hosted_style: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum V2Backend {
    /// Local filesystem backend.
    Filesystem,
    /// S3-compatible backend using the default environment/config chain.
    #[cfg(feature = "s3")]
    S3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum V2ReportFormat {
    /// JSON object.
    Json,
    /// Human-readable key-value lines.
    Text,
}

#[derive(Clone)]
struct V2VerifyBundleInput {
    bundle: V2RecoveryBundle,
    repository_id: RepositoryId,
    repository_salt_hex: String,
    wrapping_key_id: String,
    wrapping_key: SecretBytes,
}

#[derive(Clone, PartialEq, Eq)]
struct V2VerifyBundleReport {
    repository_id: String,
    anchor_sequence: u64,
    anchor_commit_key: String,
    anchor_version_id: Option<String>,
    anchor_body_digest: String,
    weak_subjectivity_floor_sequence: u64,
    verified_commit_count: usize,
    snapshot_sequence: u64,
    format_generation: u64,
    format_digest: String,
    format_object_id: String,
    format_version_id: Option<String>,
    keyring_generation: u64,
    keyring_digest: String,
    keyring_object_id: String,
    keyring_version_id: Option<String>,
    signing_key_id: String,
    provider_profile: V2ProviderProfile,
    retention: Option<RetentionPolicy>,
    exported_at_ms: i64,
    offline_signature_present: bool,
}

#[derive(Deserialize)]
struct BundleJson {
    schema: String,
    #[serde(default)]
    repository: Option<BundleRepositoryJson>,
    anchor: BundleAnchorJson,
    weak_subjectivity_floor_sequence: u64,
    #[serde(default)]
    format_digest: Option<String>,
    #[serde(default)]
    format_generation: Option<u64>,
    exported_at_ms: i64,
    #[serde(default)]
    offline_signature: Option<String>,
    #[serde(default)]
    repository_salt_digest: Option<String>,
}

#[derive(Deserialize)]
struct BundleRepositoryJson {
    id: String,
    #[serde(default)]
    salt_digest: Option<String>,
}

#[derive(Deserialize)]
struct BundleAnchorJson {
    sequence: u64,
    commit_key: String,
    body_digest: String,
    #[serde(default)]
    version_id: Option<String>,
    signing_key_id: String,
    format: BundleFormatJson,
}

#[derive(Deserialize)]
struct BundleFormatJson {
    generation: u64,
    digest: String,
    object_id: String,
    #[serde(default)]
    version_id: Option<String>,
}

pub(crate) fn run(args: V2Args) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build v2 automation runtime")?;
    runtime.block_on(run_async(args))
}

async fn run_async(args: V2Args) -> Result<()> {
    match args.command {
        V2Command::VerifyBundle(args) => {
            let format = args.format;
            let report = verify_bundle(*args).await?;
            report.print(format)?;
        }
    }
    Ok(())
}

async fn verify_bundle(args: V2VerifyBundleArgs) -> Result<V2VerifyBundleReport> {
    match args.backend.backend {
        V2Backend::Filesystem => {
            let store = filesystem_store(&args.backend)?;
            verify_bundle_with_selected_store(args, store).await
        }
        #[cfg(feature = "s3")]
        V2Backend::S3 => {
            let store = s3_store(&args.backend).await?;
            verify_bundle_with_selected_store(args, store).await
        }
    }
}

async fn verify_bundle_with_selected_store<S>(
    args: V2VerifyBundleArgs,
    store: S,
) -> Result<V2VerifyBundleReport>
where
    S: BlobStore,
{
    let parsed = read_recovery_bundle_json(&args.bundle_file)?;
    let repository_id =
        resolve_repository_id(args.repository_id, parsed.bundle.repository_id.as_ref())?;
    let wrapping_key = secret_input(
        args.wrapping_key_hex,
        args.wrapping_key_hex_file.as_deref(),
        "--wrapping-key-hex",
        "--wrapping-key-hex-file",
    )?;
    let input = V2VerifyBundleInput {
        bundle: parsed.bundle,
        repository_id,
        repository_salt_hex: args.repository_salt_hex,
        wrapping_key_id: args.wrapping_key_id,
        wrapping_key,
    };
    verify_bundle_with_store(input, store).await
}

async fn verify_bundle_with_store<S>(
    input: V2VerifyBundleInput,
    store: S,
) -> Result<V2VerifyBundleReport>
where
    S: BlobStore,
{
    if input.bundle.anchor.sequence < input.bundle.weak_subjectivity_floor_sequence {
        bail!("bundle anchor sequence is below the weak-subjectivity floor");
    }
    if let Some(bundle_repository_id) = input.bundle.repository_id.as_ref()
        && bundle_repository_id != &input.repository_id
    {
        bail!("bundle repository ID does not match the configured repository ID");
    }

    let context = repository_context(input.repository_id.clone(), &input.repository_salt_hex)?;
    let format_root = open_format_root(
        &store,
        &context,
        &input.wrapping_key_id,
        &input.wrapping_key,
        &input.bundle.anchor.format_ref,
    )
    .await?;
    if format_root.repository_id != input.repository_id
        || format_root.signing_key_id != input.bundle.anchor.signing_key_id
    {
        bail!("v2 format root does not match the trusted bundle context");
    }

    let keyring = open_keyring_envelope(
        &store,
        &context,
        &input.wrapping_key_id,
        &input.wrapping_key,
        &format_root.active_keyring_envelope_ref,
    )
    .await?;
    let commit_ref = format_root
        .active_keyring_envelope_ref
        .commit_ref()
        .context("invalid v2 keyring envelope reference")?;
    let commit_options = V2CommitStoreOptions::for_profile(
        format_root.provider_profile,
        commit_ref,
        input.bundle.anchor.format_ref.clone(),
    )
    .with_retention(format_root.retention);
    let commit_store = V2CommitStore::new(store, keyring, commit_options);
    let chain = commit_store
        .load_chain_from_state(&input.bundle.anchor)
        .await
        .context("failed to verify v2 commit chain from bundle anchor")?;

    Ok(report_from_verified_bundle(&input, &format_root, &chain))
}

fn report_from_verified_bundle(
    input: &V2VerifyBundleInput,
    format_root: &V2FormatRoot,
    chain: &V2CommitChain,
) -> V2VerifyBundleReport {
    let snapshot_sequence = chain
        .commits_newest_first
        .last()
        .map(|commit| commit.parsed_header.header.self_ref.sequence.get())
        .unwrap_or(input.bundle.anchor.sequence.get());
    V2VerifyBundleReport {
        repository_id: input.repository_id.as_str().to_owned(),
        anchor_sequence: input.bundle.anchor.sequence.get(),
        anchor_commit_key: input.bundle.anchor.commit_key.as_str().to_owned(),
        anchor_version_id: input
            .bundle
            .anchor
            .version_id
            .as_ref()
            .map(|version_id| version_id.as_str().to_owned()),
        anchor_body_digest: hex::encode(input.bundle.anchor.body_digest),
        weak_subjectivity_floor_sequence: input.bundle.weak_subjectivity_floor_sequence.get(),
        verified_commit_count: chain.commits_newest_first.len(),
        snapshot_sequence,
        format_generation: input.bundle.anchor.format_ref.generation,
        format_digest: input.bundle.anchor.format_ref.digest.clone(),
        format_object_id: input.bundle.anchor.format_ref.object_id.as_str().to_owned(),
        format_version_id: input
            .bundle
            .anchor
            .format_ref
            .version_id
            .as_ref()
            .map(|version_id| version_id.as_str().to_owned()),
        keyring_generation: format_root.active_keyring_envelope_ref.generation,
        keyring_digest: format_root.active_keyring_envelope_ref.digest.clone(),
        keyring_object_id: format_root
            .active_keyring_envelope_ref
            .object_id
            .as_str()
            .to_owned(),
        keyring_version_id: format_root
            .active_keyring_envelope_ref
            .version_id
            .as_ref()
            .map(|version_id| version_id.as_str().to_owned()),
        signing_key_id: input.bundle.anchor.signing_key_id.as_str().to_owned(),
        provider_profile: format_root.provider_profile,
        retention: format_root.retention,
        exported_at_ms: input.bundle.exported_at_ms,
        offline_signature_present: input.bundle.offline_signature.is_some(),
    }
}

async fn open_format_root<S>(
    store: &S,
    context: &RepositoryKeyContext,
    wrapping_key_id: &str,
    wrapping_key: &SecretBytes,
    reference: &V2FormatRef,
) -> Result<V2FormatRoot>
where
    S: BlobStore,
{
    let body = store
        .get_range_at(
            &reference.object_id,
            reference.version_id.as_ref(),
            ByteRange::Full,
        )
        .await
        .context("failed to read v2 format root envelope")?;
    let envelope = FormatEnvelope::from_object_bytes(body.as_ref())
        .context("failed to decode v2 format root envelope")?;
    if envelope.generation != reference.generation || envelope.digest()? != reference.digest {
        bail!("v2 format root object does not match the bundle reference");
    }
    let plaintext = envelope
        .open(context, wrapping_key_id, wrapping_key)
        .context("failed to open v2 format root envelope")?;
    V2FormatRoot::from_plaintext_bytes(&plaintext).context("failed to decode v2 format root")
}

async fn open_keyring_envelope<S>(
    store: &S,
    context: &RepositoryKeyContext,
    wrapping_key_id: &str,
    wrapping_key: &SecretBytes,
    reference: &V2KeyringEnvelopeRootRef,
) -> Result<KeyRing>
where
    S: BlobStore,
{
    let body = store
        .get_range_at(
            &reference.object_id,
            reference.version_id.as_ref(),
            ByteRange::Full,
        )
        .await
        .context("failed to read v2 keyring envelope")?;
    let envelope = KeyringEnvelope::from_object_bytes(body.as_ref())
        .context("failed to decode keyring envelope")?;
    if envelope.generation != reference.generation || envelope.digest()? != reference.digest {
        bail!("v2 keyring envelope does not match the format-root reference");
    }
    envelope
        .open(context, wrapping_key_id, wrapping_key)
        .context("failed to open v2 keyring envelope")
}

struct ParsedRecoveryBundle {
    bundle: V2RecoveryBundle,
}

fn read_recovery_bundle_json(path: &str) -> Result<ParsedRecoveryBundle> {
    let mut input = String::new();
    if path == "-" {
        std::io::stdin()
            .read_to_string(&mut input)
            .context("failed to read restore bundle from stdin")?;
    } else {
        input = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read restore bundle {}", path))?;
    }
    parse_recovery_bundle_json(&input)
}

fn parse_recovery_bundle_json(input: &str) -> Result<ParsedRecoveryBundle> {
    let decoded: BundleJson =
        serde_json::from_str(input).context("failed to parse v2 restore bundle JSON")?;
    if decoded.schema != V2_RESTORE_BUNDLE_SCHEMA {
        bail!("unsupported restore bundle schema {}", decoded.schema);
    }

    let repository_id = decoded
        .repository
        .as_ref()
        .map(|repository| RepositoryId::new(repository.id.clone()))
        .transpose()?;
    let repository_salt_digest = decoded
        .repository_salt_digest
        .or_else(|| {
            decoded
                .repository
                .as_ref()
                .and_then(|repository| repository.salt_digest.clone())
        })
        .map(|digest| decode_digest_32("repository salt digest", &digest))
        .transpose()?;
    let format_ref = V2FormatRef {
        generation: decoded.anchor.format.generation,
        digest: decoded.anchor.format.digest,
        object_id: BackendObjectId::new(decoded.anchor.format.object_id)?,
        version_id: decoded
            .anchor
            .format
            .version_id
            .map(BackendVersionId::new)
            .transpose()?,
    };
    if let Some(format_generation) = decoded.format_generation
        && format_generation != format_ref.generation
    {
        bail!("bundle format_generation does not match anchor format generation");
    }
    if let Some(format_digest) = decoded.format_digest.as_ref()
        && format_digest != &format_ref.digest
    {
        bail!("bundle format_digest does not match anchor format digest");
    }
    let anchor = V2AnchorState {
        sequence: Sequence::new(decoded.anchor.sequence),
        commit_key: BackendObjectId::new(decoded.anchor.commit_key)?,
        body_digest: decode_digest_32("anchor body digest", &decoded.anchor.body_digest)?,
        version_id: decoded
            .anchor
            .version_id
            .map(BackendVersionId::new)
            .transpose()?,
        signing_key_id: KeyId::new(decoded.anchor.signing_key_id)?,
        format_ref,
    };
    let offline_signature = decoded
        .offline_signature
        .map(|signature| hex::decode(signature).context("offline signature must be hex encoded"))
        .transpose()?;

    Ok(ParsedRecoveryBundle {
        bundle: V2RecoveryBundle {
            repository_id,
            repository_salt_digest,
            anchor,
            format_digest: decoded
                .format_digest
                .map(|digest| decode_digest_32("format digest", &digest))
                .transpose()?,
            format_generation: decoded.format_generation,
            weak_subjectivity_floor_sequence: Sequence::new(
                decoded.weak_subjectivity_floor_sequence,
            ),
            exported_at_ms: decoded.exported_at_ms,
            offline_signature,
        },
    })
}

fn resolve_repository_id(
    configured: Option<String>,
    bundled: Option<&RepositoryId>,
) -> Result<RepositoryId> {
    match (configured, bundled) {
        (Some(value), Some(bundled)) => {
            let configured = RepositoryId::new(value)?;
            if &configured != bundled {
                bail!("configured repository ID does not match restore bundle");
            }
            Ok(configured)
        }
        (Some(value), None) => RepositoryId::new(value).map_err(Into::into),
        (None, Some(value)) => Ok(value.clone()),
        (None, None) => bail!("--repository-id is required when the bundle omits repository.id"),
    }
}

fn repository_context(
    repository_id: RepositoryId,
    repository_salt_hex: &str,
) -> Result<RepositoryKeyContext> {
    let salt = hex::decode(repository_salt_hex).context("repository salt must be hex encoded")?;
    RepositoryKeyContext::new(repository_id, salt).map_err(Into::into)
}

fn decode_digest_32(label: &str, value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).with_context(|| format!("{label} must be hex encoded"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} must be exactly 32 bytes"))
}

fn secret_input(
    provided_hex: Option<String>,
    provided_file: Option<&Path>,
    provided_flag: &str,
    file_flag: &str,
) -> Result<SecretBytes> {
    match (provided_hex, provided_file) {
        (Some(_), Some(_)) => bail!("exactly one of {provided_flag} or {file_flag} is required"),
        (Some(hex), None) => secret_from_hex(provided_flag, &hex),
        (None, Some(path)) => {
            let hex = read_secret_hex_file(file_flag, path)?;
            secret_from_hex(file_flag, &hex)
        }
        (None, None) => bail!("one of {provided_flag} or {file_flag} is required"),
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

fn filesystem_store(args: &V2BackendArgs) -> Result<FilesystemBlobStore> {
    let root = args
        .backend_dir
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--backend-dir is required with --backend filesystem"))?;
    FilesystemBlobStore::new(root).context("failed to create filesystem backend")
}

#[cfg(feature = "s3")]
async fn s3_store(args: &V2BackendArgs) -> Result<S3BlobStore> {
    let bucket = args
        .s3_bucket
        .clone()
        .context("--s3-bucket or RS3_V2_S3_BUCKET is required with --backend s3")?;
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

impl V2VerifyBundleReport {
    fn print(&self, format: V2ReportFormat) -> Result<()> {
        match format {
            V2ReportFormat::Json => {
                let report = serde_json::json!({
                    "schema": V2_VERIFY_BUNDLE_SCHEMA,
                    "verified": true,
                    "repository": {
                        "id": self.repository_id,
                    },
                    "anchor": {
                        "sequence": self.anchor_sequence,
                        "commit_key": self.anchor_commit_key,
                        "version_id": self.anchor_version_id,
                        "body_digest": self.anchor_body_digest,
                        "signing_key_id": self.signing_key_id,
                        "format": {
                            "generation": self.format_generation,
                            "digest": self.format_digest,
                            "object_id": self.format_object_id,
                            "version_id": self.format_version_id,
                        },
                    },
                    "restore": {
                        "weak_subjectivity_floor_sequence": self.weak_subjectivity_floor_sequence,
                        "verified_commit_count": self.verified_commit_count,
                        "snapshot_sequence": self.snapshot_sequence,
                        "exported_at_ms": self.exported_at_ms,
                        "offline_signature_present": self.offline_signature_present,
                    },
                    "format_root": {
                        "provider_profile": provider_profile_name(self.provider_profile),
                        "retention": self.retention.map(retention_json),
                        "keyring_envelope": {
                            "generation": self.keyring_generation,
                            "digest": self.keyring_digest,
                            "object_id": self.keyring_object_id,
                            "version_id": self.keyring_version_id,
                        },
                    },
                });
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            V2ReportFormat::Text => {
                println!("schema={V2_VERIFY_BUNDLE_SCHEMA}");
                println!("verified=true");
                println!("repository_id={}", self.repository_id);
                println!("anchor_sequence={}", self.anchor_sequence);
                println!("anchor_commit_key={}", self.anchor_commit_key);
                if let Some(version_id) = self.anchor_version_id.as_ref() {
                    println!("anchor_version_id={version_id}");
                }
                println!("anchor_body_digest={}", self.anchor_body_digest);
                println!("signing_key_id={}", self.signing_key_id);
                println!("format_generation={}", self.format_generation);
                println!("format_digest={}", self.format_digest);
                println!("format_object_id={}", self.format_object_id);
                if let Some(version_id) = self.format_version_id.as_ref() {
                    println!("format_version_id={version_id}");
                }
                println!(
                    "weak_subjectivity_floor_sequence={}",
                    self.weak_subjectivity_floor_sequence
                );
                println!("verified_commit_count={}", self.verified_commit_count);
                println!("snapshot_sequence={}", self.snapshot_sequence);
                println!(
                    "provider_profile={}",
                    provider_profile_name(self.provider_profile)
                );
                if let Some(retention) = self.retention {
                    println!("retention_mode={}", retention_mode_name(retention.mode));
                    println!("retention_days={}", retention.retain_days);
                }
                println!("keyring_generation={}", self.keyring_generation);
                println!("keyring_digest={}", self.keyring_digest);
                println!("keyring_object_id={}", self.keyring_object_id);
                if let Some(version_id) = self.keyring_version_id.as_ref() {
                    println!("keyring_version_id={version_id}");
                }
                println!("exported_at_ms={}", self.exported_at_ms);
                println!(
                    "offline_signature_present={}",
                    self.offline_signature_present
                );
            }
        }
        Ok(())
    }
}

fn retention_json(retention: RetentionPolicy) -> serde_json::Value {
    serde_json::json!({
        "mode": retention_mode_name(retention.mode),
        "days": retention.retain_days,
    })
}

fn provider_profile_name(profile: V2ProviderProfile) -> &'static str {
    match profile {
        V2ProviderProfile::Dev => "dev",
        V2ProviderProfile::AtomicCreate => "atomic-create",
        V2ProviderProfile::RetainedVersionObjectLock => "retained-version-object-lock",
    }
}

fn retention_mode_name(mode: RetentionMode) -> &'static str {
    match mode {
        RetentionMode::None => "none",
        RetentionMode::Governance => "governance",
        RetentionMode::Compliance => "compliance",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BundleJson, V2VerifyBundleInput, parse_recovery_bundle_json, secret_from_hex,
        verify_bundle_with_store,
    };
    use bytes::Bytes;
    use rs3_crypto::{FormatEnvelope, KeyRing, RepositoryKeyContext};
    use rs3_repository::Repository;
    use rs3_repository::v2::{
        V2CommitStore, V2CommitStoreOptions, V2FormatRoot, V2KeyringEnvelopeRootRef,
        V2MemoryAnchor, V2ProviderProfile, V2RecoveryBundle, v2_format_object_id,
    };
    use rs3_storage::{BlobStore, MemoryBlobStore, PutOptions};
    use rs3_types::{KeyPurpose, RepositoryId, Sequence};

    const SALT_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const WRAP_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn parser_accepts_export_restore_bundle_shape() {
        let input = serde_json::json!({
            "schema": "rs3.restore-bundle.v2-preview.v1",
            "repository": {
                "id": "repo-a"
            },
            "anchor": {
                "sequence": 7,
                "commit_key": "commits/v01/00000000000000000007/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "body_digest": "11".repeat(32),
                "version_id": "version-a",
                "signing_key_id": "checkpoint-v1",
                "format": {
                    "generation": 1,
                    "digest": "22".repeat(32),
                    "object_id": "format/00000000000000000001/abc",
                    "version_id": "format-version-a"
                }
            },
            "weak_subjectivity_floor_sequence": 7,
            "format_digest": "22".repeat(32),
            "format_generation": 1,
            "exported_at_ms": 42,
            "offline_signature": null
        })
        .to_string();

        let parsed = parse_recovery_bundle_json(&input).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(parsed.bundle.anchor.sequence.get(), 7);
        assert_eq!(
            parsed
                .bundle
                .repository_id
                .as_ref()
                .map(RepositoryId::as_str),
            Some("repo-a")
        );
        assert_eq!(parsed.bundle.format_generation, Some(1));
    }

    #[tokio::test]
    async fn verify_bundle_checks_format_root_keyring_and_commit_chain() {
        let store = MemoryBlobStore::new();
        let repository_id = RepositoryId::new("repo-a").unwrap_or_else(|error| panic!("{error}"));
        let salt = hex::decode(SALT_HEX).unwrap_or_else(|error| panic!("{error}"));
        let context = RepositoryKeyContext::new(repository_id.clone(), salt)
            .unwrap_or_else(|error| panic!("{error}"));
        let wrapping_key = secret_from_hex("--wrapping-key-hex", WRAP_HEX)
            .unwrap_or_else(|error| panic!("{error}"));
        let keyring = KeyRing::generate_random().unwrap_or_else(|error| panic!("{error}"));
        let keyring_ref = store_keyring_envelope(&store, &keyring, &context, &wrapping_key).await;
        let signing_key_id = keyring
            .primary_key_id(KeyPurpose::CheckpointSigning)
            .unwrap_or_else(|error| panic!("{error}"));
        let format_root = V2FormatRoot::new(
            repository_id.clone(),
            keyring_ref,
            signing_key_id,
            V2ProviderProfile::Dev,
            None,
        );
        let format_ref = store_format_root(&store, &context, &wrapping_key, &format_root).await;
        let commit_ref = format_root
            .active_keyring_envelope_ref
            .commit_ref()
            .unwrap_or_else(|error| panic!("{error}"));
        let commit_options =
            V2CommitStoreOptions::for_profile(V2ProviderProfile::Dev, commit_ref, format_ref);
        let commit_store = V2CommitStore::new(store.clone(), keyring, commit_options);
        let anchor = V2MemoryAnchor::new();
        let genesis = commit_store
            .write_genesis_snapshot(&anchor)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let mut bundle = V2RecoveryBundle::from_anchor(genesis.anchor_state, Sequence::new(1));
        bundle.repository_id = Some(repository_id.clone());
        bundle.exported_at_ms = 42;
        let input = V2VerifyBundleInput {
            bundle,
            repository_id,
            repository_salt_hex: SALT_HEX.to_owned(),
            wrapping_key_id: "wrap-v1".to_owned(),
            wrapping_key,
        };

        let report = verify_bundle_with_store(input, store)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(report.verified_commit_count, 1);
        assert_eq!(report.snapshot_sequence, 1);
        assert_eq!(report.provider_profile, V2ProviderProfile::Dev);
    }

    async fn store_keyring_envelope(
        store: &MemoryBlobStore,
        keyring: &KeyRing,
        context: &RepositoryKeyContext,
        wrapping_key: &rs3_crypto::SecretBytes,
    ) -> V2KeyringEnvelopeRootRef {
        let envelope = keyring
            .seal_keyring_envelope(context, "wrap-v1", wrapping_key, 1)
            .unwrap_or_else(|error| panic!("{error}"));
        let repository = Repository::with_keyring(store.clone(), keyring.clone());
        let reference = repository
            .store_keyring_envelope(&envelope)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        V2KeyringEnvelopeRootRef {
            generation: reference.generation,
            digest: reference.digest,
            object_id: reference.object_id,
            version_id: reference.version_id,
        }
    }

    async fn store_format_root(
        store: &MemoryBlobStore,
        context: &RepositoryKeyContext,
        wrapping_key: &rs3_crypto::SecretBytes,
        root: &V2FormatRoot,
    ) -> rs3_repository::v2::V2FormatRef {
        let plaintext = root
            .to_plaintext_bytes()
            .unwrap_or_else(|error| panic!("{error}"));
        let envelope = FormatEnvelope::seal(context, "wrap-v1", wrapping_key, 1, &plaintext)
            .unwrap_or_else(|error| panic!("{error}"));
        let digest = envelope.digest().unwrap_or_else(|error| panic!("{error}"));
        let object_id = v2_format_object_id(envelope.generation, &digest)
            .unwrap_or_else(|error| panic!("{error}"));
        let body = Bytes::from(
            envelope
                .to_object_bytes()
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let metadata = store
            .put(&object_id, body, PutOptions::default())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        rs3_repository::v2::V2FormatRef {
            generation: envelope.generation,
            digest,
            object_id,
            version_id: metadata.version_id,
        }
    }

    #[allow(dead_code)]
    fn _bundle_json_type_check(_: BundleJson) {}
}
