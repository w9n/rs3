//! Command-line entry point for the rs3 gateway.

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use metrics_exporter_prometheus::PrometheusBuilder;
use rs3_crypto::SecretBytes;
use rs3_repository::v2::{
    V2AnchorState, V2ProviderCheckStatus, V2ProviderConformanceReport, V2ProviderProfile,
    V2RecoveryBundle,
};
use rs3_server::{
    AdminBearerToken, AdminHttpAuth, AdminHttpConfig, AdminHttpServer, AdminReadiness,
    AdminReadinessSource, AdminReportProfile, AnchorConfig, GatewayMode, GatewayServer,
    RepositoryToolConfig, RuntimeConfig, RuntimeV2ProviderConformanceOptions,
    V2_RESTORE_BUNDLE_SCHEMA, V2AnchorImportOptions, V2AnchorImportReport, V2ProviderCheckConfig,
    V2RecoveryBundleVerificationOptions, V2RecoveryBundleVerificationReport,
    V2RepositoryInitReport, WriterGuardConfig, backend_kind,
    check_v2_provider_conformance_from_provider_config, doctor_findings, doctor_probe_from_config,
    export_v2_recovery_bundle_from_config, import_v2_anchor_from_config,
    init_v2_repository_from_config, inspect_keyring_envelope_from_tool_config,
    rewrap_keyring_envelope_from_tool_config, runtime_config_profile,
    verify_v2_recovery_bundle_from_tool_config, write_v2_index_snapshot_from_config,
};
use rs3_server::{
    KeyringEnvelopeInspectOptions, KeyringEnvelopeInspectReport, KeyringEnvelopeRewrapOptions,
    KeyringEnvelopeRewrapReport,
};
use rs3_types::{BackendObjectId, KeyDescriptor, KeyPurpose, KeyStatus, RetentionMode, Sequence};
use secrecy::{ExposeSecret, SecretString};
use std::io::{self, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
#[cfg(any(feature = "s3", feature = "k8s"))]
use std::sync::Once;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tracing_subscriber::filter::{EnvFilter, FilterExt, filter_fn};
use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use zeroize::Zeroizing;

#[cfg(feature = "k8s")]
use rs3_k8s::{KubernetesLeaseGuard, LeaseGuardError, LeaseSettings, WriterFence};

#[cfg(any(feature = "s3", feature = "k8s"))]
static RUSTLS_PROVIDER: Once = Once::new();

#[cfg(feature = "k8s")]
const WRITER_LEASE_DURATION: std::time::Duration = std::time::Duration::from_secs(30);
#[cfg(feature = "k8s")]
const WRITER_LEASE_RENEW_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
const VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_GIT_SHA: Option<&str> = option_env!("RS3_BUILD_GIT_SHA");

#[derive(Debug, Parser)]
#[command(name = "rs3")]
#[command(version)]
#[command(about = "Path-private S3-compatible backup gateway")]
struct Cli {
    #[arg(long, env = "RS3_LOG_FORMAT", default_value = "plain")]
    log_format: LogFormat,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum LogFormat {
    Plain,
    Json,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run the S3-compatible gateway and optional admin API.
    Serve {
        #[arg(long)]
        bind: Option<SocketAddr>,
        #[arg(long, env = "RS3_METRICS_BIND")]
        metrics_bind: Option<SocketAddr>,
        #[arg(long, value_enum)]
        gateway_mode: Option<GatewayModeArg>,
        #[arg(long, env = "RS3_ADMIN_BIND")]
        admin_bind: Option<SocketAddr>,
        #[arg(long, env = "RS3_ADMIN_BEARER_TOKEN")]
        admin_bearer_token: Option<String>,
        #[arg(long, env = "RS3_ADMIN_PROFILE", value_enum, default_value_t = DoctorProfile::Production)]
        admin_profile: DoctorProfile,
    },
    /// Validate runtime configuration against a local or production posture.
    Doctor {
        #[arg(long, env = "RS3_DOCTOR_PROFILE", value_enum, default_value_t = DoctorProfile::Local)]
        profile: DoctorProfile,
        /// Also probe live backend, anchor, and keyring-envelope dependencies.
        #[arg(long)]
        probe: bool,
    },
    /// Export a signed restore bundle for offline recovery.
    ExportRestoreBundle {
        #[arg(long, value_enum, default_value_t = RecoveryReportFormat::Json)]
        format: RecoveryReportFormat,
    },
    /// Verify a trusted v2 restore bundle without writing an anchor.
    VerifyBundle(Box<VerifyBundleArgs>),
    /// Inspect or rewrap encrypted repository keyring envelopes.
    Keyring(Box<KeyringArgs>),
    /// Initialize a missing v2 repository, verify it, then exit.
    Init {
        #[arg(long, value_enum, default_value_t = RecoveryReportFormat::Json)]
        format: RecoveryReportFormat,
    },
    /// Write a v2 index snapshot and report the accepted anchor state.
    WriteIndexSnapshot {
        #[arg(long, value_enum, default_value_t = RecoveryReportFormat::Json)]
        format: RecoveryReportFormat,
    },
    /// Probe v2 object-store behavior required by the repository format.
    CheckV2Provider {
        #[arg(long)]
        probe_prefix: Option<String>,
        #[arg(long, default_value_t = false)]
        legal_hold: bool,
        #[arg(long, default_value_t = false)]
        governance_bypass_reviewed: bool,
        #[arg(long, value_enum, default_value_t = RecoveryReportFormat::Json)]
        format: RecoveryReportFormat,
    },
    /// Import a trusted v2 anchor after operator recovery review.
    ImportV2Anchor(Box<ImportV2AnchorArgs>),
}

#[derive(Debug, Args)]
struct ImportV2AnchorArgs {
    /// JSON bundle from `export-restore-bundle`; use `-` for stdin.
    #[arg(long)]
    bundle_file: String,
    /// External weak-subjectivity floor accepted by the operator.
    #[arg(long)]
    min_sequence: u64,
    /// Allow importing an anchor below newer commit objects seen in storage.
    #[arg(long, default_value_t = false)]
    force_rollback: bool,
    /// Output format.
    #[arg(long, value_enum, default_value_t = RecoveryReportFormat::Json)]
    format: RecoveryReportFormat,
}

#[derive(Debug, Args)]
struct VerifyBundleArgs {
    /// JSON bundle from `export-restore-bundle`; use `-` for stdin.
    #[arg(long)]
    bundle_file: String,
    /// External weak-subjectivity floor accepted by the operator.
    #[arg(long)]
    min_sequence: u64,
    /// Wrapping key identifier recorded in the format root and keyring envelope.
    #[arg(long, env = "RS3_KEYRING_WRAPPING_KEY_ID")]
    wrapping_key_id: Option<String>,
    /// Hex-encoded wrapping key.
    #[arg(long, env = "RS3_KEYRING_WRAPPING_KEY_HEX", hide_env_values = true)]
    wrapping_key_hex: Option<String>,
    /// File containing the hex-encoded wrapping key.
    #[arg(long)]
    wrapping_key_hex_file: Option<PathBuf>,
    /// Output format.
    #[arg(long, value_enum, default_value_t = RecoveryReportFormat::Json)]
    format: RecoveryReportFormat,
}

/// Repository keyring envelope maintenance commands.
#[derive(Debug, Args)]
struct KeyringArgs {
    #[command(subcommand)]
    command: KeyringCommand,
}

#[derive(Debug, Subcommand)]
enum KeyringCommand {
    /// Open an existing keyring envelope and print public key descriptors.
    Inspect(Box<KeyringInspectArgs>),
    /// Re-encrypt an existing keyring envelope with a new wrapping key.
    Rewrap(Box<KeyringRewrapArgs>),
}

#[derive(Debug, Args)]
struct KeyringInspectArgs {
    /// Existing envelope object identifier.
    #[arg(long, env = "RS3_KEYRING_ENVELOPE_OBJECT_ID")]
    envelope_object_id: Option<String>,
    /// Wrapping key identifier recorded in the envelope.
    #[arg(long, env = "RS3_KEYRING_WRAPPING_KEY_ID")]
    wrapping_key_id: Option<String>,
    /// Hex-encoded wrapping key.
    #[arg(long, env = "RS3_KEYRING_WRAPPING_KEY_HEX", hide_env_values = true)]
    wrapping_key_hex: Option<String>,
    /// File containing the hex-encoded wrapping key.
    #[arg(long)]
    wrapping_key_hex_file: Option<PathBuf>,
    /// Output format.
    #[arg(long, value_enum, default_value_t = KeyringInspectFormat::Json)]
    format: KeyringInspectFormat,
}

#[derive(Debug, Args)]
struct KeyringRewrapArgs {
    /// Existing envelope object identifier.
    #[arg(long, env = "RS3_KEYRING_ENVELOPE_OBJECT_ID")]
    envelope_object_id: Option<String>,
    /// Current wrapping key identifier.
    #[arg(long, env = "RS3_KEYRING_WRAPPING_KEY_ID")]
    old_wrapping_key_id: Option<String>,
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
    /// Output format.
    #[arg(long, value_enum, default_value_t = KeyringReportFormat::Json)]
    format: KeyringReportFormat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum GatewayModeArg {
    ReadWrite,
    RestoreReadonly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum DoctorProfile {
    Local,
    Production,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum RecoveryReportFormat {
    Json,
    Text,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum KeyringReportFormat {
    Json,
    Env,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum KeyringInspectFormat {
    Json,
    Text,
}

#[tokio::main]
async fn main() -> Result<()> {
    install_rustls_provider();
    let cli = Cli::parse();
    init_tracing(cli.log_format);

    match cli.command {
        Commands::Serve {
            bind,
            metrics_bind,
            gateway_mode,
            admin_bind,
            admin_bearer_token,
            admin_profile,
        } => {
            let mut config = RuntimeConfig::from_env()?;
            if let Some(bind) = bind {
                config.bind = bind;
            }
            if let Some(metrics_bind) = metrics_bind {
                config.metrics.bind = Some(metrics_bind);
            }
            if let Some(gateway_mode) = gateway_mode {
                config.mode = gateway_mode.into();
            }
            let admin_config = admin_http_config(admin_bind, admin_bearer_token, admin_profile)?;
            enforce_serve_profile(&config, admin_profile, admin_config.is_some())?;
            install_metrics(config.metrics.bind)?;
            log_runtime_config(&config);
            let writer_guard = start_writer_guard(&config).await?;
            let server = bind_gateway(config.clone(), &writer_guard).await?;
            tracing::info!(bind = %server.local_addr(), "gateway S3 listener started");
            let run_result = match admin_config {
                Some(admin_config) => {
                    let admin_runtime_facts = server.admin_runtime_facts_source();
                    let admin_readiness =
                        writer_guard.readiness_source(server.admin_readiness_source());
                    let admin_server = AdminHttpServer::bind_with_runtime_sources(
                        config,
                        admin_config,
                        admin_runtime_facts,
                        admin_readiness,
                    )
                    .await?;
                    tracing::info!(
                        bind = %admin_server.local_addr(),
                        "gateway admin listener started",
                    );
                    run_gateway_and_admin(server, admin_server, writer_guard.shutdown()).await
                }
                None => server
                    .run_until_shutdown(shutdown_signal_or_writer_guard(writer_guard.shutdown()))
                    .await
                    .map_err(anyhow::Error::from),
            };
            let release_result = writer_guard.release().await;
            run_result?;
            release_result?;
        }
        Commands::Doctor { profile, probe } => {
            let config = RuntimeConfig::from_env()?;
            log_runtime_config(&config);
            run_doctor(&config, profile, probe).await?;
        }
        Commands::ExportRestoreBundle { format } => {
            let config = RuntimeConfig::from_env()?;
            log_runtime_config(&config);
            let bundle = export_v2_recovery_bundle_from_config(&config).await?;
            print_v2_restore_bundle(&bundle, format)?;
        }
        Commands::VerifyBundle(args) => {
            let VerifyBundleArgs {
                bundle_file,
                min_sequence,
                wrapping_key_id,
                wrapping_key_hex,
                wrapping_key_hex_file,
                format,
            } = *args;
            let mut config = RepositoryToolConfig::from_env()?;
            if let Some(wrapping_key_id) = wrapping_key_id.as_ref() {
                config
                    .repository_keys
                    .wrapping_key_id
                    .clone_from(wrapping_key_id);
            }
            log_repository_tool_config(&config);
            let bundle = read_v2_recovery_bundle_json(&bundle_file)?;
            let wrapping_key = required_wrapping_key_input(
                wrapping_key_hex,
                wrapping_key_hex_file.as_deref(),
                "--wrapping-key-hex",
                "--wrapping-key-hex-file",
            )?;
            let report = verify_v2_recovery_bundle_from_tool_config(
                &config,
                bundle,
                V2RecoveryBundleVerificationOptions {
                    min_sequence: Sequence::new(min_sequence),
                    wrapping_key,
                },
            )
            .await?;
            print_v2_recovery_bundle_verification_report(&report, format)?;
        }
        Commands::Keyring(args) => {
            run_keyring_command(*args).await?;
        }
        Commands::Init { format } => {
            let config = RuntimeConfig::from_env()?;
            log_runtime_config(&config);
            let report = init_v2_repository_from_config(&config).await?;
            print_v2_repository_init_report(&report, format)?;
        }
        Commands::WriteIndexSnapshot { format } => {
            let config = RuntimeConfig::from_env()?;
            log_runtime_config(&config);
            let anchor = write_v2_index_snapshot_from_config(&config).await?;
            print_v2_anchor_state("rs3.v2-index-snapshot.v1", &anchor, format)?;
        }
        Commands::CheckV2Provider {
            probe_prefix,
            legal_hold,
            governance_bypass_reviewed,
            format,
        } => {
            let config = V2ProviderCheckConfig::from_env()?;
            log_v2_provider_check_config(&config);
            let report = check_v2_provider_conformance_from_provider_config(
                &config,
                RuntimeV2ProviderConformanceOptions {
                    probe_prefix,
                    legal_hold,
                    governance_bypass_reviewed,
                },
            )
            .await?;
            let passed = report.passed();
            print_v2_provider_conformance_report(&report, format)?;
            if !passed {
                anyhow::bail!("v2 provider conformance failed");
            }
        }
        Commands::ImportV2Anchor(args) => {
            let config = RuntimeConfig::from_env()?;
            log_runtime_config(&config);
            let format = args.format;
            let (bundle, options) = recovery_bundle_from_import_args(&config, *args)?;
            let report = import_v2_anchor_from_config(&config, bundle, options).await?;
            print_v2_anchor_import_report(&report, format)?;
        }
    }

    Ok(())
}

async fn run_keyring_command(args: KeyringArgs) -> Result<()> {
    match args.command {
        KeyringCommand::Inspect(args) => {
            let KeyringInspectArgs {
                envelope_object_id,
                wrapping_key_id,
                wrapping_key_hex,
                wrapping_key_hex_file,
                format,
            } = *args;
            let mut config = RepositoryToolConfig::from_env()?;
            if let Some(wrapping_key_id) = wrapping_key_id.as_ref() {
                config
                    .repository_keys
                    .wrapping_key_id
                    .clone_from(wrapping_key_id);
            }
            log_repository_tool_config(&config);
            let envelope_object_id =
                optional_backend_object_id("--envelope-object-id", envelope_object_id)?;
            let wrapping_key = required_wrapping_key_input(
                wrapping_key_hex,
                wrapping_key_hex_file.as_deref(),
                "--wrapping-key-hex",
                "--wrapping-key-hex-file",
            )?;
            let report = inspect_keyring_envelope_from_tool_config(
                &config,
                KeyringEnvelopeInspectOptions {
                    envelope_object_id,
                    wrapping_key,
                },
            )
            .await?;
            print_keyring_inspect_report(&report, format)?;
        }
        KeyringCommand::Rewrap(args) => {
            let KeyringRewrapArgs {
                envelope_object_id,
                old_wrapping_key_id,
                old_wrapping_key_hex,
                old_wrapping_key_hex_file,
                new_wrapping_key_id,
                new_wrapping_key_hex,
                new_wrapping_key_hex_file,
                generate_new_wrapping_key,
                new_generation,
                format,
            } = *args;
            let mut config = RepositoryToolConfig::from_env()?;
            if let Some(wrapping_key_id) = old_wrapping_key_id.as_ref() {
                config
                    .repository_keys
                    .wrapping_key_id
                    .clone_from(wrapping_key_id);
            }
            log_repository_tool_config(&config);
            let envelope_object_id =
                optional_backend_object_id("--envelope-object-id", envelope_object_id)?;
            let old_wrapping_key = required_wrapping_key_input(
                old_wrapping_key_hex,
                old_wrapping_key_hex_file.as_deref(),
                "--old-wrapping-key-hex",
                "--old-wrapping-key-hex-file",
            )?;
            let new_wrapping_key = wrapping_key_input(
                new_wrapping_key_hex,
                new_wrapping_key_hex_file.as_deref(),
                generate_new_wrapping_key,
                "--new-wrapping-key-hex",
                "--new-wrapping-key-hex-file",
                "--generate-new-wrapping-key",
            )?;
            let report = rewrap_keyring_envelope_from_tool_config(
                &config,
                KeyringEnvelopeRewrapOptions {
                    envelope_object_id,
                    old_wrapping_key,
                    new_wrapping_key_id,
                    new_wrapping_key: new_wrapping_key.secret,
                    new_generation,
                },
            )
            .await?;
            print_keyring_rewrap_report(&report, new_wrapping_key.generated_hex, format)?;
        }
    }
    Ok(())
}

fn recovery_bundle_from_import_args(
    config: &RuntimeConfig,
    args: ImportV2AnchorArgs,
) -> Result<(V2RecoveryBundle, V2AnchorImportOptions)> {
    let options = V2AnchorImportOptions {
        min_sequence: Sequence::new(args.min_sequence),
        force_rollback: args.force_rollback,
    };
    let bundle = read_restore_bundle_json(&args.bundle_file, config)?;
    Ok((bundle, options))
}

fn read_restore_bundle_json(path: &str, config: &RuntimeConfig) -> Result<V2RecoveryBundle> {
    let mut input = String::new();
    if path == "-" {
        std::io::stdin()
            .read_to_string(&mut input)
            .context("failed to read restore bundle from stdin")?;
    } else {
        input = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read restore bundle {path}"))?;
    }
    parse_restore_bundle_json(&input, config)
}

fn read_v2_recovery_bundle_json(path: &str) -> Result<V2RecoveryBundle> {
    let mut input = String::new();
    if path == "-" {
        std::io::stdin()
            .read_to_string(&mut input)
            .context("failed to read restore bundle from stdin")?;
    } else {
        input = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read restore bundle {path}"))?;
    }
    serde_json::from_str(&input).context("failed to parse v2 restore bundle JSON")
}

fn parse_restore_bundle_json(input: &str, config: &RuntimeConfig) -> Result<V2RecoveryBundle> {
    let mut bundle: V2RecoveryBundle =
        serde_json::from_str(input).context("failed to parse v2 restore bundle JSON")?;
    if let Some(repository_id) = bundle.repository_id.as_ref()
        && repository_id != &config.repository_keys.repository_id
    {
        bail!("restore bundle repository ID does not match configured repository ID");
    }
    if bundle.repository_id.is_none() {
        bundle.repository_id = Some(config.repository_keys.repository_id.clone());
    }
    Ok(bundle)
}

fn optional_backend_object_id(
    label: &'static str,
    value: Option<String>,
) -> Result<Option<BackendObjectId>> {
    value
        .map(|value| {
            BackendObjectId::new(value)
                .with_context(|| format!("{label} must be a valid backend object identifier"))
        })
        .transpose()
}

struct WrappingKeyInput {
    secret: SecretBytes,
    generated_hex: Option<String>,
}

fn wrapping_key_input(
    provided_hex: Option<String>,
    provided_file: Option<&Path>,
    generate: bool,
    provided_flag: &'static str,
    file_flag: &'static str,
    generate_flag: &'static str,
) -> Result<WrappingKeyInput> {
    let input_count = usize::from(provided_hex.is_some())
        + usize::from(provided_file.is_some())
        + usize::from(generate);
    if input_count != 1 {
        bail!("exactly one of {provided_flag}, {file_flag}, or {generate_flag} is required");
    }

    if let Some(hex) = provided_hex {
        Ok(WrappingKeyInput {
            secret: secret_from_hex(provided_flag, SecretString::from(hex))?,
            generated_hex: None,
        })
    } else if let Some(path) = provided_file {
        Ok(WrappingKeyInput {
            secret: secret_from_hex(file_flag, read_secret_hex_file(file_flag, path)?)?,
            generated_hex: None,
        })
    } else {
        if !generate {
            bail!("{generate_flag} was not selected");
        }
        let hex = random_hex(SecretBytes::MIN_LEN)?;
        Ok(WrappingKeyInput {
            secret: secret_from_hex(generate_flag, SecretString::from(hex.clone()))?,
            generated_hex: Some(hex),
        })
    }
}

fn required_wrapping_key_input(
    provided_hex: Option<String>,
    provided_file: Option<&Path>,
    provided_flag: &'static str,
    file_flag: &'static str,
) -> Result<SecretBytes> {
    match (provided_hex, provided_file) {
        (Some(_), Some(_)) => {
            bail!("exactly one of {provided_flag} or {file_flag} is required")
        }
        (Some(hex), None) => secret_from_hex(provided_flag, SecretString::from(hex)),
        (None, Some(path)) => secret_from_hex(file_flag, read_secret_hex_file(file_flag, path)?),
        (None, None) => bail!("one of {provided_flag} or {file_flag} is required"),
    }
}

fn read_secret_hex_file(label: &'static str, path: &Path) -> Result<SecretString> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {label} {}", path.display()))?;
    Ok(SecretString::from(contents.trim().to_owned()))
}

fn secret_from_hex(label: &'static str, value: SecretString) -> Result<SecretBytes> {
    let bytes = hex::decode(value.expose_secret())
        .with_context(|| format!("{label} must be hex encoded"))?;
    SecretBytes::new(bytes).with_context(|| format!("{label} is not usable"))
}

fn random_hex(len: usize) -> Result<String> {
    let mut bytes = Zeroizing::new(vec![0_u8; len]);
    getrandom::fill(bytes.as_mut_slice())
        .map_err(|error| anyhow::anyhow!("failed to read random bytes: {error}"))?;
    Ok(hex::encode(bytes.as_slice()))
}

#[cfg(any(feature = "s3", feature = "k8s"))]
fn install_rustls_provider() {
    RUSTLS_PROVIDER.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

#[cfg(not(any(feature = "s3", feature = "k8s")))]
fn install_rustls_provider() {}

fn print_v2_anchor_import_report(
    report: &V2AnchorImportReport,
    format: RecoveryReportFormat,
) -> Result<()> {
    match format {
        RecoveryReportFormat::Json => {
            let report_json = serde_json::json!({
                "schema": "rs3.v2-anchor-import.v1",
                "applied": report.applied,
                "verified_commit_count": report.verified_commit_count,
                "anchor": serde_json::to_value(&report.anchor)?,
            });
            println!("{}", serde_json::to_string_pretty(&report_json)?);
        }
        RecoveryReportFormat::Text => {
            println!("schema=rs3.v2-anchor-import.v1");
            println!("applied={}", report.applied);
            println!("verified_commit_count={}", report.verified_commit_count);
            print_v2_anchor_text(&report.anchor);
        }
    }
    Ok(())
}

fn print_v2_repository_init_report(
    report: &V2RepositoryInitReport,
    format: RecoveryReportFormat,
) -> Result<()> {
    match format {
        RecoveryReportFormat::Json => {
            let report_json = serde_json::json!({
                "schema": "rs3.v2-init.v1",
                "initialized": report.initialized,
                "verified_commit_count": report.verified_commit_count,
                "anchor": serde_json::to_value(&report.anchor)?,
            });
            println!("{}", serde_json::to_string_pretty(&report_json)?);
        }
        RecoveryReportFormat::Text => {
            println!("schema=rs3.v2-init.v1");
            println!("initialized={}", report.initialized);
            println!("verified_commit_count={}", report.verified_commit_count);
            print_v2_anchor_text(&report.anchor);
        }
    }
    Ok(())
}

fn print_v2_recovery_bundle_verification_report(
    report: &V2RecoveryBundleVerificationReport,
    format: RecoveryReportFormat,
) -> Result<()> {
    match format {
        RecoveryReportFormat::Json => {
            let report_json = serde_json::json!({
                "schema": "rs3.v2-verify-bundle.v1",
                "verified": true,
                "repository": {
                    "id": report.repository_id.as_str(),
                },
                "anchor": {
                    "sequence": report.anchor.sequence.get(),
                    "commit_key": report.anchor.commit_key.as_str(),
                    "version_id": report.anchor.version_id.as_ref().map(|version_id| version_id.as_str()),
                    "body_digest": hex::encode(report.anchor.body_digest),
                    "signing_key_id": report.anchor.signing_key_id.as_str(),
                    "format": {
                        "generation": report.anchor.format_ref.generation,
                        "digest": report.anchor.format_ref.digest,
                        "object_id": report.anchor.format_ref.object_id.as_str(),
                        "version_id": report.anchor.format_ref.version_id.as_ref().map(|version_id| version_id.as_str()),
                    },
                },
                "restore": {
                    "weak_subjectivity_floor_sequence": report.weak_subjectivity_floor_sequence.get(),
                    "verified_commit_count": report.verified_commit_count,
                    "snapshot_sequence": report.snapshot_sequence.get(),
                    "exported_at_ms": report.exported_at_ms,
                    "offline_signature_present": report.offline_signature_present,
                },
                "format_root": {
                    "provider_profile": provider_profile_name(report.provider_profile),
                    "retention": report.retention.map(retention_json),
                    "keyring_envelope": {
                        "generation": report.keyring_envelope_ref.generation,
                        "digest": report.keyring_envelope_ref.digest,
                        "object_id": report.keyring_envelope_ref.object_id.as_str(),
                        "version_id": report.keyring_envelope_ref.version_id.as_ref().map(|version_id| version_id.as_str()),
                    },
                },
            });
            println!("{}", serde_json::to_string_pretty(&report_json)?);
        }
        RecoveryReportFormat::Text => {
            println!("schema=rs3.v2-verify-bundle.v1");
            println!("verified=true");
            println!("repository_id={}", report.repository_id.as_str());
            print_v2_anchor_text(&report.anchor);
            println!(
                "weak_subjectivity_floor_sequence={}",
                report.weak_subjectivity_floor_sequence.get()
            );
            println!("verified_commit_count={}", report.verified_commit_count);
            println!("snapshot_sequence={}", report.snapshot_sequence.get());
            println!(
                "provider_profile={}",
                provider_profile_name(report.provider_profile)
            );
            if let Some(retention) = report.retention {
                println!("retention_mode={}", retention_mode_name(retention.mode));
                println!("retention_days={}", retention.retain_days);
            }
            println!(
                "keyring_generation={}",
                report.keyring_envelope_ref.generation
            );
            println!("keyring_digest={}", report.keyring_envelope_ref.digest);
            println!(
                "keyring_object_id={}",
                report.keyring_envelope_ref.object_id.as_str()
            );
            if let Some(version_id) = report.keyring_envelope_ref.version_id.as_ref() {
                println!("keyring_version_id={}", version_id.as_str());
            }
            println!("exported_at_ms={}", report.exported_at_ms);
            println!(
                "offline_signature_present={}",
                report.offline_signature_present
            );
        }
    }
    Ok(())
}

fn print_keyring_inspect_report(
    report: &KeyringEnvelopeInspectReport,
    format: KeyringInspectFormat,
) -> Result<()> {
    match format {
        KeyringInspectFormat::Json => {
            let report_json = serde_json::json!({
                "repository_id": report.repository_id.as_str(),
                "repository_salt_hex": report.repository_salt_hex,
                "keyring_envelope": {
                    "object_id": report.envelope_object_id.as_str(),
                    "digest": report.envelope_digest,
                    "generation": report.generation,
                },
                "wrapping_key": {
                    "id": report.wrapping_key_id,
                },
                "keys": report.keys.iter().map(key_descriptor_json).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&report_json)?);
        }
        KeyringInspectFormat::Text => {
            println!("repository_id={}", report.repository_id.as_str());
            println!("repository_salt_hex={}", report.repository_salt_hex);
            println!(
                "keyring_envelope_object_id={}",
                report.envelope_object_id.as_str()
            );
            println!("keyring_envelope_digest={}", report.envelope_digest);
            println!("keyring_envelope_generation={}", report.generation);
            println!("wrapping_key_id={}", report.wrapping_key_id);
            for key in &report.keys {
                println!(
                    "key id={} purpose={} status={} algorithm={}",
                    key.id.as_str(),
                    key_purpose_name(key.purpose),
                    key_status_name(key.status),
                    key.algorithm
                );
            }
        }
    }
    Ok(())
}

fn print_keyring_rewrap_report(
    report: &KeyringEnvelopeRewrapReport,
    generated_wrapping_key_hex: Option<String>,
    format: KeyringReportFormat,
) -> Result<()> {
    match format {
        KeyringReportFormat::Json => {
            let server_env = keyring_server_env(report, generated_wrapping_key_hex.as_deref());
            let report_json = serde_json::json!({
                "repository_id": report.repository_id.as_str(),
                "repository_salt_hex": report.repository_salt_hex,
                "keyring_envelope": {
                    "object_id": report.envelope_object_id.as_str(),
                    "digest": report.envelope_digest,
                    "generation": report.generation,
                    "retention": report.envelope_retention.map(retention_json),
                },
                "wrapping_key": {
                    "id": report.wrapping_key_id,
                    "generated_key_hex": generated_wrapping_key_hex,
                },
                "server_env": server_env,
            });
            println!("{}", serde_json::to_string_pretty(&report_json)?);
        }
        KeyringReportFormat::Env => {
            println!(
                "RS3_REPOSITORY_ID={}",
                shell_quote(report.repository_id.as_str())
            );
            println!(
                "RS3_REPOSITORY_SALT_HEX={}",
                shell_quote(&report.repository_salt_hex)
            );
            println!(
                "RS3_KEYRING_ENVELOPE_OBJECT_ID={}",
                shell_quote(report.envelope_object_id.as_str())
            );
            println!(
                "RS3_KEYRING_WRAPPING_KEY_ID={}",
                shell_quote(&report.wrapping_key_id)
            );
            if let Some(secret) = generated_wrapping_key_hex.as_ref() {
                println!("RS3_KEYRING_WRAPPING_KEY_HEX={}", shell_quote(secret));
            } else {
                println!("RS3_KEYRING_WRAPPING_KEY_HEX=<external-secret>");
            }
        }
    }
    Ok(())
}

fn print_v2_provider_conformance_report(
    report: &V2ProviderConformanceReport,
    format: RecoveryReportFormat,
) -> Result<()> {
    match format {
        RecoveryReportFormat::Json => {
            let checks = report
                .checks
                .iter()
                .map(|check| {
                    serde_json::json!({
                        "name": check.name,
                        "status": provider_check_status_name(check.status),
                        "reason": check.reason,
                    })
                })
                .collect::<Vec<_>>();
            let report_json = serde_json::json!({
                "schema": "rs3.v2-provider-conformance.v1",
                "generated_at_ms": current_time_ms().unwrap_or(0),
                "profile": provider_profile_name(report.profile),
                "passed": report.passed(),
                "checks": checks,
            });
            println!("{}", serde_json::to_string_pretty(&report_json)?);
        }
        RecoveryReportFormat::Text => {
            println!("schema=rs3.v2-provider-conformance.v1");
            println!("generated_at_ms={}", current_time_ms().unwrap_or(0));
            println!("profile={}", provider_profile_name(report.profile));
            println!("passed={}", report.passed());
            for check in &report.checks {
                match check.reason {
                    Some(reason) => println!(
                        "check={} status={} reason={}",
                        check.name,
                        provider_check_status_name(check.status),
                        reason
                    ),
                    None => println!(
                        "check={} status={}",
                        check.name,
                        provider_check_status_name(check.status)
                    ),
                }
            }
        }
    }
    Ok(())
}

fn print_v2_restore_bundle(bundle: &V2RecoveryBundle, format: RecoveryReportFormat) -> Result<()> {
    match format {
        RecoveryReportFormat::Json => {
            println!("{}", serde_json::to_string_pretty(bundle)?);
        }
        RecoveryReportFormat::Text => {
            println!("schema={V2_RESTORE_BUNDLE_SCHEMA}");
            if let Some(repository_id) = bundle.repository_id.as_ref() {
                println!("repository_id={}", repository_id.as_str());
            }
            print_v2_anchor_text(&bundle.anchor);
            println!(
                "weak_subjectivity_floor_sequence={}",
                bundle.weak_subjectivity_floor_sequence.get()
            );
            println!("exported_at_ms={}", bundle.exported_at_ms);
            println!(
                "offline_signature_payload_hex={}",
                hex::encode(bundle.offline_signature_payload()?)
            );
            if let Some(signature) = bundle.offline_signature.as_ref() {
                println!("offline_signature={}", hex::encode(signature));
            }
        }
    }
    Ok(())
}

fn print_v2_anchor_state(
    schema: &'static str,
    anchor: &V2AnchorState,
    format: RecoveryReportFormat,
) -> Result<()> {
    match format {
        RecoveryReportFormat::Json => {
            let report = serde_json::json!({
                "schema": schema,
                "anchor": serde_json::to_value(anchor)?,
            });
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        RecoveryReportFormat::Text => {
            println!("schema={schema}");
            print_v2_anchor_text(anchor);
        }
    }
    Ok(())
}

fn print_v2_anchor_text(anchor: &V2AnchorState) {
    println!("anchor_sequence={}", anchor.sequence.get());
    println!("anchor_commit_key={}", anchor.commit_key.as_str());
    println!("anchor_body_digest={}", hex::encode(anchor.body_digest));
    if let Some(version_id) = anchor.version_id.as_ref() {
        println!("anchor_version_id={}", version_id.as_str());
    }
    println!("signing_key_id={}", anchor.signing_key_id.as_str());
    println!("format_generation={}", anchor.format_ref.generation);
    println!("format_digest={}", anchor.format_ref.digest);
    println!("format_object_id={}", anchor.format_ref.object_id.as_str());
    if let Some(version_id) = anchor.format_ref.version_id.as_ref() {
        println!("format_version_id={}", version_id.as_str());
    }
}

fn keyring_server_env(
    report: &KeyringEnvelopeRewrapReport,
    generated_wrapping_key_hex: Option<&str>,
) -> serde_json::Value {
    let mut env = serde_json::Map::new();
    env.insert(
        "RS3_REPOSITORY_ID".to_owned(),
        serde_json::Value::String(report.repository_id.as_str().to_owned()),
    );
    env.insert(
        "RS3_REPOSITORY_SALT_HEX".to_owned(),
        serde_json::Value::String(report.repository_salt_hex.clone()),
    );
    env.insert(
        "RS3_KEYRING_ENVELOPE_OBJECT_ID".to_owned(),
        serde_json::Value::String(report.envelope_object_id.as_str().to_owned()),
    );
    env.insert(
        "RS3_KEYRING_WRAPPING_KEY_ID".to_owned(),
        serde_json::Value::String(report.wrapping_key_id.clone()),
    );
    if let Some(secret) = generated_wrapping_key_hex {
        env.insert(
            "RS3_KEYRING_WRAPPING_KEY_HEX".to_owned(),
            serde_json::Value::String(secret.to_owned()),
        );
    }
    serde_json::Value::Object(env)
}

fn key_descriptor_json(descriptor: &KeyDescriptor) -> serde_json::Value {
    serde_json::json!({
        "id": descriptor.id.as_str(),
        "purpose": key_purpose_name(descriptor.purpose),
        "algorithm": descriptor.algorithm.as_str(),
        "status": key_status_name(descriptor.status),
        "created_at_ms": descriptor.created_at_ms,
        "not_before_ms": descriptor.not_before_ms,
        "not_after_ms": descriptor.not_after_ms,
        "public_key": descriptor.public_key.as_deref(),
        "external_kms_uri": descriptor.external_kms_uri.as_deref(),
    })
}

fn key_purpose_name(purpose: KeyPurpose) -> &'static str {
    match purpose {
        KeyPurpose::Namespace => "namespace",
        KeyPurpose::Content => "content",
        KeyPurpose::Metadata => "metadata",
        KeyPurpose::CheckpointSigning => "checkpoint",
    }
}

fn key_status_name(status: KeyStatus) -> &'static str {
    match status {
        KeyStatus::Primary => "primary",
        KeyStatus::Enabled => "enabled",
        KeyStatus::Disabled => "disabled",
        KeyStatus::Retired => "retired",
    }
}

fn retention_json(retention: rs3_types::RetentionPolicy) -> serde_json::Value {
    serde_json::json!({
        "mode": retention_mode_name(retention.mode),
        "days": retention.retain_days,
    })
}

async fn run_doctor(config: &RuntimeConfig, profile: DoctorProfile, probe: bool) -> Result<()> {
    let findings = doctor_findings(config, profile.into());
    let probe_report = if probe {
        Some(doctor_probe_from_config(config).await)
    } else {
        None
    };

    for finding in &findings {
        eprintln!(
            "rs3 doctor [{}]: {}; remediation: {}",
            finding.code, finding.message, finding.remediation
        );
    }

    if let Some(probe_report) = &probe_report {
        for check in &probe_report.checks {
            if check.is_passed() {
                println!("rs3 doctor probe [{}]: ok", check.code);
            } else {
                eprintln!(
                    "rs3 doctor probe [{}]: {}; remediation: {}",
                    check.code, check.message, check.remediation
                );
            }
        }
    }

    let probe_failure_count = probe_report
        .as_ref()
        .map_or(0, |probe_report| probe_report.failed_count());
    let finding_count = findings.len() + probe_failure_count;
    if finding_count == 0 {
        println!("rs3 doctor: {} profile ok", profile.as_str());
        return Ok(());
    }

    anyhow::bail!(
        "rs3 doctor: {} profile failed with {} finding(s)",
        profile.as_str(),
        finding_count
    )
}

fn enforce_serve_profile(
    config: &RuntimeConfig,
    profile: DoctorProfile,
    admin_listener_configured: bool,
) -> Result<()> {
    if profile == DoctorProfile::Local {
        tracing::warn!(
            "local serve profile bypasses production posture enforcement; do not expose this listener",
        );
        return Ok(());
    }

    if !admin_listener_configured {
        anyhow::bail!(
            "production serve profile requires RS3_ADMIN_BIND and RS3_ADMIN_BEARER_TOKEN for readiness and operator status",
        );
    }

    let findings = doctor_findings(config, AdminReportProfile::Production);
    if findings.is_empty() {
        return Ok(());
    }

    let codes = findings
        .iter()
        .map(|finding| finding.code)
        .collect::<Vec<_>>()
        .join(",");
    anyhow::bail!(
        "production serve posture failed ({codes}); run `rs3-server doctor --profile production` for remediation",
    )
}

fn admin_http_config(
    bind: Option<SocketAddr>,
    bearer_token: Option<String>,
    profile: DoctorProfile,
) -> Result<Option<AdminHttpConfig>> {
    let Some(bind) = bind else {
        return Ok(None);
    };
    let Some(bearer_token) = bearer_token else {
        anyhow::bail!("RS3_ADMIN_BEARER_TOKEN is required when RS3_ADMIN_BIND is set");
    };
    let token = AdminBearerToken::new(bearer_token)?;
    Ok(Some(AdminHttpConfig::new(
        bind,
        AdminHttpAuth::bearer(token),
        profile.into(),
    )))
}

struct WriterGuardRuntime {
    shutdown: Option<watch::Receiver<bool>>,
    held: std::sync::Arc<std::sync::atomic::AtomicBool>,
    required: bool,
    #[cfg(feature = "k8s")]
    writer_fence: Option<WriterFence>,
    #[cfg(feature = "k8s")]
    lease_guard: Option<std::sync::Arc<KubernetesLeaseGuard>>,
    renew_task: Option<tokio::task::JoinHandle<()>>,
}

impl WriterGuardRuntime {
    fn disabled() -> Self {
        Self {
            shutdown: None,
            held: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            required: false,
            #[cfg(feature = "k8s")]
            writer_fence: None,
            #[cfg(feature = "k8s")]
            lease_guard: None,
            renew_task: None,
        }
    }

    fn shutdown(&self) -> Option<watch::Receiver<bool>> {
        self.shutdown.clone()
    }

    fn readiness_source(
        &self,
        repository: std::sync::Arc<dyn AdminReadinessSource>,
    ) -> std::sync::Arc<dyn AdminReadinessSource> {
        std::sync::Arc::new(ServeReadinessSource {
            repository,
            writer_guard_held: std::sync::Arc::clone(&self.held),
            writer_guard_required: self.required,
            #[cfg(feature = "k8s")]
            writer_fence: self.writer_fence.clone(),
        })
    }

    async fn release(&self) -> Result<()> {
        if let Some(renew_task) = self.renew_task.as_ref() {
            renew_task.abort();
        }
        #[cfg(feature = "k8s")]
        if let Some(lease_guard) = self.lease_guard.as_ref() {
            lease_guard
                .release()
                .await
                .context("failed to release writer fence during orderly shutdown")?;
        }
        Ok(())
    }
}

async fn bind_gateway(
    config: RuntimeConfig,
    _writer_guard: &WriterGuardRuntime,
) -> Result<GatewayServer> {
    #[cfg(feature = "k8s")]
    if let Some(writer_fence) = _writer_guard.writer_fence.clone() {
        return GatewayServer::bind_with_writer_fence(config, writer_fence)
            .await
            .map_err(anyhow::Error::from);
    }
    GatewayServer::bind(config)
        .await
        .map_err(anyhow::Error::from)
}

struct ServeReadinessSource {
    repository: std::sync::Arc<dyn AdminReadinessSource>,
    writer_guard_held: std::sync::Arc<std::sync::atomic::AtomicBool>,
    writer_guard_required: bool,
    #[cfg(feature = "k8s")]
    writer_fence: Option<WriterFence>,
}

#[async_trait::async_trait]
impl AdminReadinessSource for ServeReadinessSource {
    async fn check_readiness(&self) -> AdminReadiness {
        if self.writer_guard_required
            && (!self
                .writer_guard_held
                .load(std::sync::atomic::Ordering::Acquire)
                || !writer_fence_is_live(self))
        {
            return AdminReadiness::unavailable("writer-guard.not-held");
        }
        self.repository.check_readiness().await
    }
}

fn writer_fence_is_live(_readiness: &ServeReadinessSource) -> bool {
    #[cfg(feature = "k8s")]
    {
        _readiness
            .writer_fence
            .as_ref()
            .is_some_and(WriterFence::is_live)
    }
    #[cfg(not(feature = "k8s"))]
    {
        true
    }
}

async fn start_writer_guard(config: &RuntimeConfig) -> Result<WriterGuardRuntime> {
    if !config.mode.allows_mutation() || config.writer_guard == WriterGuardConfig::Off {
        return Ok(WriterGuardRuntime::disabled());
    }

    let AnchorConfig::KubernetesLease {
        namespace,
        name,
        field_manager,
    } = &config.anchor
    else {
        bail!("RS3_WRITER_GUARD=required needs RS3_ANCHOR_MODE=kubernetes-lease");
    };

    #[cfg(feature = "k8s")]
    {
        let hostname = std::env::var("HOSTNAME")
            .context("RS3_WRITER_GUARD=required needs HOSTNAME to identify this writer pod")?;
        let holder_identity = format!("{hostname}/{}", random_hex(16)?);
        let lease_guard = KubernetesLeaseGuard::new(
            LeaseSettings {
                namespace: namespace.clone(),
                name: name.clone(),
                field_manager: field_manager.clone(),
            },
            holder_identity,
            WRITER_LEASE_DURATION,
        )
        .context("failed to configure writer lease guard")?;

        lease_guard
            .acquire()
            .await
            .context("failed to acquire writer lease guard")?;
        let writer_fence = lease_guard
            .writer_fence()
            .context("failed to establish writer fencing token")?;
        tracing::info!("writer lease guard acquired");

        let lease_guard = std::sync::Arc::new(lease_guard);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let held = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let renew_task = tokio::spawn(renew_writer_guard(
            std::sync::Arc::clone(&lease_guard),
            shutdown_tx,
            std::sync::Arc::clone(&held),
        ));

        Ok(WriterGuardRuntime {
            shutdown: Some(shutdown_rx),
            held,
            required: true,
            writer_fence: Some(writer_fence),
            lease_guard: Some(lease_guard),
            renew_task: Some(renew_task),
        })
    }

    #[cfg(not(feature = "k8s"))]
    {
        let _ = namespace;
        let _ = name;
        let _ = field_manager;
        bail!("RS3_WRITER_GUARD=required needs the k8s feature");
    }
}

#[cfg(feature = "k8s")]
async fn renew_writer_guard(
    lease_guard: std::sync::Arc<KubernetesLeaseGuard>,
    shutdown_tx: watch::Sender<bool>,
    held: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let mut last_success = std::time::Instant::now();
    loop {
        tokio::time::sleep(WRITER_LEASE_RENEW_INTERVAL).await;
        match lease_guard.renew().await {
            Ok(_) => {
                last_success = std::time::Instant::now();
            }
            Err(error) => {
                let elapsed = last_success.elapsed();
                tracing::warn!(
                    %error,
                    elapsed_ms = elapsed.as_millis(),
                    "writer lease renewal failed",
                );
                if matches!(
                    error,
                    LeaseGuardError::HeldByOther | LeaseGuardError::LostLease
                ) {
                    held.store(false, std::sync::atomic::Ordering::Release);
                    tracing::error!(
                        "writer lease is held by another live identity; initiating graceful shutdown",
                    );
                    let _ = shutdown_tx.send(true);
                    break;
                }
                if elapsed >= WRITER_LEASE_DURATION {
                    held.store(false, std::sync::atomic::Ordering::Release);
                    tracing::error!(
                        "writer lease renewal failed past the lease duration; initiating graceful shutdown",
                    );
                    let _ = shutdown_tx.send(true);
                    break;
                }
            }
        }
    }
}

async fn run_gateway_and_admin(
    gateway: GatewayServer,
    admin: AdminHttpServer,
    writer_guard_shutdown: Option<watch::Receiver<bool>>,
) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let gateway_shutdown = shutdown_rx.clone();
    let admin_shutdown = shutdown_rx;

    if let Some(writer_guard_shutdown) = writer_guard_shutdown {
        let writer_guard_shutdown_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            wait_for_shutdown(writer_guard_shutdown).await;
            let _ = writer_guard_shutdown_tx.send(true);
        });
    }

    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    let gateway_task = async move {
        gateway
            .run_until_shutdown(wait_for_shutdown(gateway_shutdown))
            .await
            .map_err(anyhow::Error::from)
    };
    let admin_task = async move {
        admin
            .run_until_shutdown(wait_for_shutdown(admin_shutdown))
            .await
            .map_err(anyhow::Error::from)
    };

    tokio::try_join!(gateway_task, admin_task)?;
    Ok(())
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            break;
        }
    }
}

async fn shutdown_signal_or_writer_guard(writer_guard_shutdown: Option<watch::Receiver<bool>>) {
    let Some(writer_guard_shutdown) = writer_guard_shutdown else {
        shutdown_signal().await;
        return;
    };
    tokio::select! {
        _ = shutdown_signal() => {}
        _ = wait_for_shutdown(writer_guard_shutdown) => {}
    }
}

impl From<GatewayModeArg> for GatewayMode {
    fn from(value: GatewayModeArg) -> Self {
        match value {
            GatewayModeArg::ReadWrite => Self::ReadWrite,
            GatewayModeArg::RestoreReadonly => Self::RestoreReadOnly,
        }
    }
}

impl From<DoctorProfile> for AdminReportProfile {
    fn from(value: DoctorProfile) -> Self {
        match value {
            DoctorProfile::Local => Self::Local,
            DoctorProfile::Production => Self::Production,
        }
    }
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

fn provider_check_status_name(status: V2ProviderCheckStatus) -> &'static str {
    match status {
        V2ProviderCheckStatus::Passed => "passed",
        V2ProviderCheckStatus::Failed => "failed",
    }
}

fn current_time_ms() -> Option<i64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis();
    i64::try_from(millis).ok()
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

impl DoctorProfile {
    fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Production => "production",
        }
    }
}

fn install_metrics(bind: Option<SocketAddr>) -> Result<()> {
    let Some(bind) = bind else {
        return Ok(());
    };
    PrometheusBuilder::new()
        .with_http_listener(bind)
        .install()?;
    tracing::info!(bind = %bind, "gateway metrics listener started");
    Ok(())
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::warn!(%error, "failed to install Ctrl+C shutdown handler");
    }
}

fn log_runtime_config(config: &RuntimeConfig) {
    let anchor = match &config.anchor {
        AnchorConfig::Memory => "memory",
        AnchorConfig::KubernetesLease { .. } => "kubernetes-lease",
    };
    let backend_kind = backend_kind(&config.backend.endpoint);
    let repository_retention_mode = config
        .repository
        .retention
        .map(|policy| match policy.mode {
            RetentionMode::None => "none",
            RetentionMode::Governance => "governance",
            RetentionMode::Compliance => "compliance",
        })
        .unwrap_or("none");
    let repository_retention_days = config
        .repository
        .retention
        .map(|policy| policy.retain_days)
        .unwrap_or(0);
    let config_profile = runtime_config_profile(config);

    tracing::info!(
        version = VERSION,
        build_git_sha = build_git_sha(),
        gateway_mode = config.mode.as_str(),
        writer_guard = config.writer_guard.as_str(),
        bind = %config.bind,
        metrics_bind = ?config.metrics.bind,
        backend_kind,
        anchor,
        batch_max_items = config.batching.max_items,
        batch_max_delay_ms = config.batching.max_delay.as_millis(),
        batch_max_pending_items = config.batching.max_pending_items,
        payload_segment_size = config.repository.payload_segment_size,
        adaptive_payload_segment_size = config.repository.adaptive_payload_segment_size,
        repository_retention_mode,
        repository_retention_days,
        static_credentials = config.static_credentials.is_some(),
        config_profile,
        "gateway runtime configuration validated",
    );
}

fn log_v2_provider_check_config(config: &V2ProviderCheckConfig) {
    let backend_kind = backend_kind(&config.backend.endpoint);
    let repository_retention_mode = config
        .repository_retention
        .map(|policy| match policy.mode {
            RetentionMode::None => "none",
            RetentionMode::Governance => "governance",
            RetentionMode::Compliance => "compliance",
        })
        .unwrap_or("none");
    let repository_retention_days = config
        .repository_retention
        .map(|policy| policy.retain_days)
        .unwrap_or(0);

    tracing::info!(
        version = VERSION,
        build_git_sha = build_git_sha(),
        backend_kind,
        repository_retention_mode,
        repository_retention_days,
        "v2 provider check configuration validated",
    );
}

fn log_repository_tool_config(config: &RepositoryToolConfig) {
    let backend_kind = backend_kind(&config.backend.endpoint);
    let repository_retention_mode = config
        .repository_retention
        .map(|policy| retention_mode_name(policy.mode))
        .unwrap_or("none");
    let repository_retention_days = config
        .repository_retention
        .map(|policy| policy.retain_days)
        .unwrap_or(0);

    tracing::info!(
        version = VERSION,
        build_git_sha = build_git_sha(),
        backend_kind,
        repository_format = config.repository_format.as_str(),
        repository_retention_mode,
        repository_retention_days,
        recovery_public_key = config.recovery.public_key.is_some(),
        keyring_envelope_object_id = config.repository_keys.envelope_object_id.is_some(),
        "repository tool configuration validated",
    );
}

fn build_git_sha() -> &'static str {
    BUILD_GIT_SHA.unwrap_or("unknown")
}

fn init_tracing(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let filter = filter.and(filter_fn(|metadata| {
        is_path_safe_tracing_target(metadata.target())
    }));

    match format {
        LogFormat::Plain => tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(io::stderr)
                    .with_filter(filter),
            )
            .init(),
        LogFormat::Json => tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(io::stderr)
                    .with_filter(filter),
            )
            .init(),
    }
}

fn is_path_safe_tracing_target(target: &str) -> bool {
    const ALLOWED_TARGETS: &[&str] = &[
        "rs3_crypto",
        "rs3_index",
        "rs3_k8s",
        "rs3_repository",
        "rs3_server",
        "rs3_storage",
        "rs3_types",
    ];

    ALLOWED_TARGETS.iter().any(|allowed| {
        target == *allowed
            || target
                .strip_prefix(allowed)
                .is_some_and(|suffix| suffix.starts_with("::"))
    })
}

#[cfg(test)]
mod tests {
    use super::{
        DoctorProfile, ImportV2AnchorArgs, RecoveryReportFormat, backend_kind, doctor_findings,
        enforce_serve_profile, is_path_safe_tracing_target, parse_restore_bundle_json,
        recovery_bundle_from_import_args, runtime_config_profile,
    };
    use rs3_server::{
        AnchorConfig, BackendConfig, BatchConfig, GatewayMode, HardeningConfig, MetricsConfig,
        ProviderConformanceConfig, RecoveryConfig, RepositoryConfig, RepositoryFormat,
        RepositoryKeysConfig, RuntimeConfig, StaticCredentials, WriterGuardConfig,
    };
    use rs3_types::{BackendObjectId, PublicBucket, RepositoryId, RetentionMode, RetentionPolicy};
    use secrecy::SecretString;
    use std::time::Duration;

    fn runtime_config() -> RuntimeConfig {
        let bind = match "127.0.0.1:9080".parse() {
            Ok(bind) => bind,
            Err(error) => panic!("{error}"),
        };
        let public_bucket = match PublicBucket::new("tenant-backups") {
            Ok(bucket) => bucket,
            Err(error) => panic!("{error}"),
        };
        let repository_id = match RepositoryId::new("tenant-repository") {
            Ok(repository_id) => repository_id,
            Err(error) => panic!("{error}"),
        };

        RuntimeConfig {
            mode: GatewayMode::ReadWrite,
            bind,
            metrics: MetricsConfig { bind: None },
            hardening: HardeningConfig::default(),
            public_bucket,
            backend: BackendConfig {
                endpoint: "https://storage.example".to_owned(),
                bucket: "tenant-backend-bucket".to_owned(),
                prefix: Some("tenant/prefix".to_owned()),
            },
            anchor: AnchorConfig::Memory,
            writer_guard: WriterGuardConfig::Off,
            batching: BatchConfig {
                max_items: 64,
                max_delay: Duration::from_millis(10),
                max_pending_items: 64,
            },
            repository: RepositoryConfig {
                format: RepositoryFormat::V2Preview,
                payload_segment_size: rs3_repository::DEFAULT_PAYLOAD_SEGMENT_SIZE,
                adaptive_payload_segment_size: true,
                decrypted_segment_cache_max_bytes:
                    rs3_repository::DEFAULT_DECRYPTED_SEGMENT_CACHE_MAX_BYTES,
                retention: None,
                allow_init: true,
            },
            provider_conformance: ProviderConformanceConfig::default(),
            recovery: RecoveryConfig::default(),
            repository_keys: RepositoryKeysConfig {
                repository_id,
                repository_salt_hex:
                    "2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
                envelope_object_id: Some(
                    BackendObjectId::new("keyrings/00000000000000000001-digest.json")
                        .unwrap_or_else(|error| panic!("{error}")),
                ),
                wrapping_key_id: "wrap-v1".to_owned(),
                wrapping_key_hex: SecretString::from(
                    "3333333333333333333333333333333333333333333333333333333333333333",
                ),
            },
            static_credentials: None,
        }
    }

    #[test]
    fn tracing_filter_allows_application_targets_and_blocks_dependencies() {
        assert!(is_path_safe_tracing_target("rs3_server"));
        assert!(is_path_safe_tracing_target("rs3_storage::s3"));
        assert!(!is_path_safe_tracing_target("s3s::service"));
        assert!(!is_path_safe_tracing_target("hyper::proto"));
        assert!(!is_path_safe_tracing_target("aws_sdk_s3"));
    }

    #[test]
    fn backend_kind_redacts_endpoint_details() {
        assert_eq!(backend_kind("memory://local"), "memory");
        assert_eq!(backend_kind("file:///data/repo"), "filesystem");
        assert_eq!(backend_kind("https://storage.example"), "s3-compatible");
    }

    #[test]
    fn runtime_config_profile_is_stable_and_path_safe() {
        let first = runtime_config();
        let second = runtime_config();
        let fingerprint = runtime_config_profile(&first);

        assert_eq!(fingerprint, runtime_config_profile(&second));
        assert_eq!(fingerprint.len(), 64);
        assert!(!fingerprint.contains("tenant"));
        assert!(!fingerprint.contains("storage.example"));
    }

    #[test]
    fn runtime_config_profile_changes_for_operational_knobs() {
        let first = runtime_config();
        let mut second = runtime_config();
        second.repository.payload_segment_size += 1;

        assert_ne!(
            runtime_config_profile(&first),
            runtime_config_profile(&second)
        );
    }

    #[test]
    fn runtime_config_profile_changes_for_gateway_mode() {
        let first = runtime_config();
        let mut second = runtime_config();
        second.mode = GatewayMode::RestoreReadOnly;

        assert_ne!(
            runtime_config_profile(&first),
            runtime_config_profile(&second)
        );
    }

    #[test]
    fn local_doctor_allows_local_development_config() {
        let findings = doctor_findings(&runtime_config(), DoctorProfile::Local.into());

        assert!(findings.is_empty());
    }

    #[test]
    fn production_doctor_rejects_dev_only_posture() {
        let findings = doctor_findings(&runtime_config(), DoctorProfile::Production.into());
        let codes = findings
            .iter()
            .map(|finding| finding.code)
            .collect::<Vec<_>>();

        assert!(codes.contains(&"anchor.memory"));
        assert!(codes.contains(&"retention.missing"));
        assert!(codes.contains(&"auth.credentials-missing"));
        assert!(codes.contains(&"recovery.public-key"));
        assert!(codes.contains(&"repository.init-enabled"));
        assert!(codes.contains(&"writer-guard.required"));
    }

    #[test]
    fn production_doctor_does_not_require_write_retention_for_restore_readonly() {
        let mut config = runtime_config();
        config.mode = GatewayMode::RestoreReadOnly;
        config.anchor = AnchorConfig::KubernetesLease {
            namespace: "backup".to_owned(),
            name: "v2-anchor".to_owned(),
            field_manager: "rs3-server".to_owned(),
        };
        config.static_credentials = Some(StaticCredentials {
            access_key_id: "rs3-fixture-access-key".to_owned(),
            secret_access_key: SecretString::from("rs3-fixture-secret-key"),
        });
        config.recovery.public_key = Some(
            "ed25519:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
        );

        let findings = doctor_findings(&config, DoctorProfile::Production.into());
        let codes = findings
            .iter()
            .map(|finding| finding.code)
            .collect::<Vec<_>>();

        assert!(!codes.contains(&"retention.missing"));
    }

    #[test]
    fn production_doctor_accepts_envelope_anchor_retention_and_auth() {
        let mut config = runtime_config();
        config.anchor = AnchorConfig::KubernetesLease {
            namespace: "backup".to_owned(),
            name: "v2-anchor".to_owned(),
            field_manager: "rs3-server".to_owned(),
        };
        config.repository.retention = Some(RetentionPolicy::new(RetentionMode::Compliance, 30));
        config.repository.allow_init = false;
        config.writer_guard = WriterGuardConfig::Required;
        config.static_credentials = Some(StaticCredentials {
            access_key_id: "rs3-fixture-access-key".to_owned(),
            secret_access_key: SecretString::from("rs3-fixture-secret-key"),
        });
        config.recovery.public_key = Some(
            "ed25519:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
        );

        let findings = doctor_findings(&config, DoctorProfile::Production.into());

        assert!(findings.is_empty());
        assert!(enforce_serve_profile(&config, DoctorProfile::Production, true).is_ok());
    }

    #[test]
    fn production_serve_rejects_findings_and_missing_admin_listener() {
        let config = runtime_config();

        let findings = enforce_serve_profile(&config, DoctorProfile::Production, true)
            .expect_err("production serve should reject doctor findings")
            .to_string();
        assert!(findings.contains("anchor.memory"));
        assert!(!findings.contains("tenant"));

        let missing_admin = enforce_serve_profile(&config, DoctorProfile::Production, false)
            .expect_err("production serve should require the admin listener")
            .to_string();
        assert!(missing_admin.contains("RS3_ADMIN_BIND"));
    }

    #[test]
    fn local_serve_profile_is_explicit_escape_hatch() {
        assert!(enforce_serve_profile(&runtime_config(), DoctorProfile::Local, false).is_ok());
    }

    #[test]
    fn import_bundle_parser_accepts_export_restore_bundle_shape() {
        let config = runtime_config();
        let input = serde_json::json!({
            "schema": "rs3.restore-bundle.v2-preview.v1",
            "repository": {
                "id": "tenant-repository",
                "salt_digest": "33".repeat(32)
            },
            "anchor": {
                "sequence": 7,
                "commit_key": "commits/v02/00000000000000000007/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
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

        let bundle =
            parse_restore_bundle_json(&input, &config).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(bundle.anchor.sequence.get(), 7);
        assert_eq!(
            bundle.repository_id.as_ref().map(RepositoryId::as_str),
            Some("tenant-repository")
        );
        assert_eq!(bundle.format_generation, Some(1));
        assert_eq!(
            bundle.anchor.version_id.as_ref().map(|id| id.as_str()),
            Some("version-a")
        );
        assert_eq!(bundle.repository_salt_digest, Some([0x33; 32]));
    }

    #[test]
    fn import_bundle_parser_rejects_wrong_repository() {
        let config = runtime_config();
        let input = serde_json::json!({
            "schema": "rs3.restore-bundle.v2-preview.v1",
            "repository": {
                "id": "other-repository"
            },
            "anchor": {
                "sequence": 7,
                "commit_key": "commits/v02/00000000000000000007/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "body_digest": "11".repeat(32),
                "signing_key_id": "checkpoint-v1",
                "format": {
                    "generation": 1,
                    "digest": "22".repeat(32),
                    "object_id": "format/00000000000000000001/abc"
                }
            },
            "weak_subjectivity_floor_sequence": 7,
            "format_digest": "22".repeat(32),
            "format_generation": 1,
            "exported_at_ms": 42,
            "offline_signature": null
        })
        .to_string();

        let error = match parse_restore_bundle_json(&input, &config) {
            Ok(_) => panic!("wrong-repository restore bundle should be rejected"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("repository ID does not match"));
    }

    #[test]
    fn import_v2_anchor_reads_bundle_file_and_preserves_operator_options() {
        let config = runtime_config();
        let input = serde_json::json!({
            "schema": "rs3.restore-bundle.v2-preview.v1",
            "repository": {
                "id": "tenant-repository"
            },
            "anchor": {
                "sequence": 7,
                "commit_key": "commits/v02/00000000000000000007/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "body_digest": "11".repeat(32),
                "signing_key_id": "checkpoint-v1",
                "format": {
                    "generation": 1,
                    "digest": "22".repeat(32),
                    "object_id": "format/00000000000000000001/abc"
                }
            },
            "weak_subjectivity_floor_sequence": 7,
            "format_digest": "22".repeat(32),
            "format_generation": 1,
            "exported_at_ms": 42,
            "offline_signature": null
        })
        .to_string();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|error| panic!("{error}"))
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rs3-import-v2-anchor-test-{}-{unique}.json",
            std::process::id()
        ));
        std::fs::write(&path, input).unwrap_or_else(|error| panic!("{error}"));
        let args = ImportV2AnchorArgs {
            bundle_file: path.to_string_lossy().into_owned(),
            min_sequence: 5,
            force_rollback: true,
            format: RecoveryReportFormat::Json,
        };

        let (bundle, options) = recovery_bundle_from_import_args(&config, args)
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = std::fs::remove_file(path);

        assert_eq!(bundle.anchor.sequence.get(), 7);
        assert_eq!(options.min_sequence.get(), 5);
        assert!(options.force_rollback);
    }
}
