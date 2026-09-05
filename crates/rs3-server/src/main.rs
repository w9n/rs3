//! Command-line entry point for the rs3 gateway.

mod cli_offline;
mod cli_serve;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use rs3_crypto::SecretBytes;
use rs3_repository::v2::{
    V2AnchorState, V2ProviderCheckStatus, V2ProviderConformanceReport, V2ProviderProfile,
    V2RecoveryBundle,
};
use rs3_server::{
    AdminReportProfile, AnchorConfig, GatewayMode, PROVIDER_CONFORMANCE_SCHEMA,
    RepositoryToolConfig, RuntimeConfig, RuntimeV2ProviderConformanceOptions,
    V2_RESTORE_BUNDLE_SCHEMA, V2AnchorImportOptions, V2AnchorImportReport, V2ProviderCheckConfig,
    V2RecoveryBundleVerificationOptions, V2RecoveryBundleVerificationReport,
    V2RepositoryInitReport, backend_kind, check_v2_provider_conformance_from_provider_config,
    doctor_findings, doctor_probe_from_config, export_v2_recovery_bundle_from_config,
    import_v2_anchor_from_config, init_v2_repository_from_config,
    inspect_keyring_envelope_from_tool_config, provider_conformance_target_fingerprint,
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
use tracing_subscriber::filter::{EnvFilter, FilterExt, filter_fn};
use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use zeroize::Zeroizing;

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
        #[arg(long, env = "RS3_ADMIN_BEARER_TOKEN", hide_env_values = true)]
        admin_bearer_token: Option<String>,
        #[arg(long, env = "RS3_ADMIN_MUTATION_BEARER_TOKEN", hide_env_values = true)]
        admin_mutation_bearer_token: Option<String>,
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
    /// Operate the in-gateway maintenance supervisor over the admin API.
    Maintenance(Box<MaintenanceArgs>),
    /// Break-glass maintenance for when the gateway cannot run.
    MaintenanceOffline(Box<MaintenanceOfflineArgs>),
}

/// Break-glass offline maintenance against a stopped gateway.
///
/// Unlike `maintenance`, this never talks to a live gateway: it builds the
/// backend and anchor from the same environment configuration as `serve`,
/// acquires exclusive writer-fence ownership through the anchor backend, and
/// fails closed while a live writer is renewing the fence.
#[derive(Debug, Args)]
struct MaintenanceOfflineArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = MaintenanceOutputFormat::Text, global = true)]
    format: MaintenanceOutputFormat,
    #[command(subcommand)]
    command: MaintenanceOfflineCommand,
}

#[derive(Clone, Debug, Subcommand, PartialEq, Eq)]
enum MaintenanceOfflineCommand {
    /// Fence the repository and run the budgeted read-only plan.
    DryRun,
    /// Fence the repository and apply a plan digest from a prior offline dry-run.
    Apply {
        /// Plan digest from `maintenance-offline dry-run`.
        #[arg(long)]
        plan_digest: String,
    },
}

/// Maintenance operations proxied through the gateway admin listener.
///
/// The CLI never touches the object store directly; every subcommand calls
/// the authenticated admin HTTP surface of a live gateway.
#[derive(Debug, Args)]
struct MaintenanceArgs {
    /// Gateway admin API origin, for example `http://127.0.0.1:9082`.
    #[arg(long, env = "RS3_ADMIN_URL", global = true)]
    admin_url: Option<String>,
    /// Read bearer token for `maintenance status`.
    #[arg(
        long,
        env = "RS3_ADMIN_BEARER_TOKEN",
        hide_env_values = true,
        global = true
    )]
    admin_bearer_token: Option<String>,
    /// Mutation bearer token for destructive maintenance subcommands.
    #[arg(
        long,
        env = "RS3_ADMIN_MUTATION_BEARER_TOKEN",
        hide_env_values = true,
        global = true
    )]
    admin_mutation_bearer_token: Option<String>,
    /// Output format.
    #[arg(long, value_enum, default_value_t = MaintenanceOutputFormat::Text, global = true)]
    format: MaintenanceOutputFormat,
    #[command(subcommand)]
    command: MaintenanceCommand,
}

#[derive(Clone, Debug, Subcommand, PartialEq, Eq)]
enum MaintenanceCommand {
    /// Show supervisor state, schedule, configuration, and history.
    Status,
    /// Run the budgeted read-only plan and print its plan digest.
    DryRun,
    /// Apply a plan digest produced by a prior dry-run.
    Apply {
        /// Plan digest from `maintenance dry-run`.
        #[arg(long)]
        plan_digest: String,
    },
    /// Cancel the in-flight maintenance run at its next mutation boundary.
    Cancel,
    /// Pause the automatic maintenance scheduler.
    Pause,
    /// Resume the automatic maintenance scheduler.
    Resume,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum MaintenanceOutputFormat {
    Text,
    Json,
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
            admin_mutation_bearer_token,
            admin_profile,
        } => {
            cli_serve::run(
                bind,
                metrics_bind,
                gateway_mode,
                admin_bind,
                admin_bearer_token,
                admin_mutation_bearer_token,
                admin_profile,
            )
            .await?;
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
            let target_fingerprint = provider_conformance_target_fingerprint(&config);
            print_v2_provider_conformance_report(&report, &target_fingerprint, format)?;
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
        Commands::Maintenance(args) => {
            run_maintenance_command(*args).await?;
        }
        Commands::MaintenanceOffline(args) => {
            cli_offline::run(*args).await?;
        }
    }

    Ok(())
}

/// Maximum accepted admin response size for maintenance CLI calls.
const MAINTENANCE_CLI_MAX_RESPONSE_BYTES: usize = 512 * 1024;

/// Runs one maintenance subcommand against the gateway admin listener.
async fn run_maintenance_command(args: MaintenanceArgs) -> Result<()> {
    let MaintenanceArgs {
        admin_url,
        admin_bearer_token,
        admin_mutation_bearer_token,
        format,
        command,
    } = args;
    let admin_url =
        admin_url.context("--admin-url or RS3_ADMIN_URL is required for maintenance commands")?;
    let origin = parse_admin_origin(&admin_url)?;

    let (method, path, body) = match &command {
        MaintenanceCommand::Status => (http::Method::GET, "/admin/maintenance", None),
        MaintenanceCommand::DryRun => (http::Method::POST, "/admin/maintenance/dry-run", None),
        MaintenanceCommand::Apply { plan_digest } => (
            http::Method::POST,
            "/admin/maintenance/apply",
            Some(serde_json::json!({ "plan_digest": plan_digest }).to_string()),
        ),
        MaintenanceCommand::Cancel => (http::Method::POST, "/admin/maintenance/cancel", None),
        MaintenanceCommand::Pause => (http::Method::POST, "/admin/maintenance/pause", None),
        MaintenanceCommand::Resume => (http::Method::POST, "/admin/maintenance/resume", None),
    };
    let token = if method == http::Method::POST {
        admin_mutation_bearer_token.context(
            "--admin-mutation-bearer-token or RS3_ADMIN_MUTATION_BEARER_TOKEN is required for maintenance mutations",
        )?
    } else {
        admin_bearer_token
            .or(admin_mutation_bearer_token)
            .context("--admin-bearer-token or RS3_ADMIN_BEARER_TOKEN is required")?
    };

    let uri: http::Uri = format!("{origin}{path}")
        .parse()
        .context("failed to build admin request URI")?;
    let mut request = http::Request::builder()
        .method(method)
        .uri(uri)
        .header(http::header::ACCEPT, "application/json")
        .header(http::header::AUTHORIZATION, format!("Bearer {token}"))
        .header("x-rs3-admin-source", "cli");
    if body.is_some() {
        request = request.header(http::header::CONTENT_TYPE, "application/json");
    }
    let request = request
        .body(http_body_util::Full::new(bytes::Bytes::from(
            body.unwrap_or_default(),
        )))
        .context("failed to build admin request")?;

    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build_http::<http_body_util::Full<bytes::Bytes>>();
    let response =
        tokio::time::timeout(std::time::Duration::from_secs(600), client.request(request))
            .await
            .context("gateway admin request timed out")?
            .context("gateway admin request failed; is the gateway admin listener reachable?")?;
    let status = response.status();
    let bytes = read_admin_response_body(response.into_body()).await?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).context("gateway admin response is not valid JSON")?;

    match format {
        MaintenanceOutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&value)
                    .context("failed to render admin response JSON")?
            );
        }
        MaintenanceOutputFormat::Text => print_maintenance_text(&command, &value),
    }
    if !status.is_success() {
        let code = value["error"]["code"].as_str().unwrap_or("unknown");
        let message = value["error"]["message"].as_str().unwrap_or("");
        anyhow::bail!("maintenance {command:?} failed with HTTP {status}: {code} {message}");
    }
    Ok(())
}

/// Reads a bounded admin response body.
async fn read_admin_response_body(body: hyper::body::Incoming) -> Result<bytes::Bytes> {
    use http_body_util::BodyExt;
    let limited = http_body_util::Limited::new(body, MAINTENANCE_CLI_MAX_RESPONSE_BYTES);
    match limited.collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(_error) => anyhow::bail!(
            "gateway admin response failed or exceeded {MAINTENANCE_CLI_MAX_RESPONSE_BYTES} bytes"
        ),
    }
}

/// Validates the maintenance CLI admin origin.
///
/// Only plain `http://` origins are accepted; the admin listener is expected
/// to be cluster-local or otherwise isolated. TLS origins are served by the
/// read-only console instead.
fn parse_admin_origin(value: &str) -> Result<String> {
    let uri: http::Uri = value
        .parse()
        .context("RS3_ADMIN_URL must be a valid http origin")?;
    if uri.scheme_str() != Some("http") {
        anyhow::bail!("maintenance commands support http:// admin origins only");
    }
    let authority = uri
        .authority()
        .context("RS3_ADMIN_URL must include a host")?;
    if authority.as_str().contains('@') {
        anyhow::bail!("RS3_ADMIN_URL must not include credentials");
    }
    if (!uri.path().is_empty() && uri.path() != "/") || uri.query().is_some() {
        anyhow::bail!("RS3_ADMIN_URL must be an origin without a path or query");
    }
    Ok(format!("http://{authority}"))
}

/// Prints a human-readable summary of one maintenance admin response.
fn print_maintenance_text(command: &MaintenanceCommand, value: &serde_json::Value) {
    if let Some(error) = value.get("error") {
        println!(
            "error: {} ({})",
            error["message"].as_str().unwrap_or("unknown"),
            error["code"].as_str().unwrap_or("unknown"),
        );
    }
    match command {
        MaintenanceCommand::Status => {
            let supervisor = &value["supervisor"];
            println!(
                "state: {}",
                supervisor["state"].as_str().unwrap_or("unavailable")
            );
            println!("mode: {}", supervisor["mode"].as_str().unwrap_or("unknown"));
            println!(
                "paused: {}",
                supervisor["paused"].as_bool().unwrap_or(false)
            );
            println!(
                "mutation enabled: {}",
                value["mutation_enabled"].as_bool().unwrap_or(false)
            );
            println!(
                "consecutive failures: {}",
                supervisor["consecutive_failures"].as_u64().unwrap_or(0)
            );
            if let Some(at_ms) = value["next_trigger"]["at_ms"].as_i64() {
                println!(
                    "next trigger: {} at {}",
                    value["next_trigger"]["reason"]
                        .as_str()
                        .unwrap_or("unknown"),
                    at_ms
                );
            } else {
                println!("next trigger: none");
            }
            if let Some(deadline) = supervisor["nearest_retain_until_ms"].as_i64() {
                println!("nearest renewal deadline (ms): {deadline}");
            }
            let operations = value["operations"].as_array().map_or(0, Vec::len);
            println!("recorded operations: {operations}");
            for note in value["notes"].as_array().into_iter().flatten() {
                if let Some(note) = note.as_str() {
                    println!("note: {note}");
                }
            }
        }
        MaintenanceCommand::DryRun => {
            if let Some(digest) = value["plan_digest"].as_str() {
                println!("plan digest: {digest}");
            }
            let report = &value["report"];
            println!(
                "fits budgets: {}",
                report["fits_budgets"].as_bool().unwrap_or(false)
            );
            println!(
                "reclaimable dead bytes: {}",
                report["dead_bytes_reclaimable"].as_u64().unwrap_or(0)
            );
            println!(
                "renewal targets: {} objects / {} bytes",
                report["retention_renewal_commit_count"]
                    .as_u64()
                    .unwrap_or(0),
                report["retention_renewal_bytes"].as_u64().unwrap_or(0)
            );
        }
        MaintenanceCommand::Apply { .. }
        | MaintenanceCommand::Cancel
        | MaintenanceCommand::Pause
        | MaintenanceCommand::Resume => {
            let operation = &value["operation"];
            if operation.is_object() {
                println!(
                    "operation {}: {}",
                    operation["id"].as_str().unwrap_or("unknown"),
                    operation["outcome"].as_str().unwrap_or("pending")
                );
                if matches!(command, MaintenanceCommand::Apply { .. }) {
                    println!(
                        "renewed: {} objects / {} bytes",
                        operation["renewed_object_count"].as_u64().unwrap_or(0),
                        operation["renewed_bytes"].as_u64().unwrap_or(0)
                    );
                    println!(
                        "deleted orphans: {}",
                        operation["deleted_object_count"].as_u64().unwrap_or(0)
                    );
                }
            }
        }
    }
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
    target_fingerprint: &str,
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
                "schema": PROVIDER_CONFORMANCE_SCHEMA,
                "source_revision": build_source_revision(),
                "target_fingerprint": target_fingerprint,
                "generated_at_ms": current_time_ms().unwrap_or(0),
                "profile": provider_profile_name(report.profile),
                "passed": report.passed(),
                "checks": checks,
            });
            println!("{}", serde_json::to_string_pretty(&report_json)?);
        }
        RecoveryReportFormat::Text => {
            println!("schema={PROVIDER_CONFORMANCE_SCHEMA}");
            println!("source_revision={}", build_source_revision());
            println!("target_fingerprint={target_fingerprint}");
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

fn build_source_revision() -> &'static str {
    option_env!("RS3_BUILD_GIT_SHA").unwrap_or("unknown")
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
            "rs3 doctor [{}] ({}): {}; remediation: {}",
            finding.code, finding.severity, finding.message, finding.remediation
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
    let blocking_finding_count = findings
        .iter()
        .filter(|finding| finding.is_blocking())
        .count();
    let finding_count = blocking_finding_count + probe_failure_count;
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
    use super::cli_serve::enforce_serve_profile;
    use super::{
        DoctorProfile, ImportV2AnchorArgs, MaintenanceArgs, MaintenanceCommand,
        MaintenanceOutputFormat, PROVIDER_CONFORMANCE_SCHEMA, RecoveryReportFormat, backend_kind,
        doctor_findings, is_path_safe_tracing_target, parse_admin_origin,
        parse_restore_bundle_json, provider_conformance_target_fingerprint,
        recovery_bundle_from_import_args, run_maintenance_command, runtime_config_profile,
    };
    use rs3_server::{
        AnchorConfig, BackendConfig, BatchConfig, GatewayMode, HardeningConfig, MaintenanceConfig,
        MetricsConfig, ProviderConformanceConfig, RecoveryConfig, RepositoryConfig,
        RepositoryFormat, RepositoryKeysConfig, RuntimeConfig, StaticCredentials,
        V2ProviderCheckConfig, WriterGuardConfig,
    };
    use rs3_types::{BackendObjectId, PublicBucket, RepositoryId, RetentionMode, RetentionPolicy};
    use secrecy::SecretString;
    use serde::Serialize;
    use std::fs;
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
                timeouts: Default::default(),
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
            maintenance: MaintenanceConfig::default(),
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

    #[derive(Serialize)]
    struct TestProviderEvidence {
        schema: &'static str,
        source_revision: &'static str,
        target_fingerprint: String,
        generated_at_ms: Option<i64>,
        profile: &'static str,
        passed: bool,
        checks: Vec<TestProviderCheck>,
    }

    #[derive(Serialize)]
    struct TestProviderCheck {
        name: &'static str,
        status: &'static str,
        reason: Option<&'static str>,
    }

    #[test]
    fn admin_origin_parser_accepts_http_origins_only() {
        assert_eq!(
            parse_admin_origin("http://127.0.0.1:9082").unwrap_or_else(|error| panic!("{error}")),
            "http://127.0.0.1:9082"
        );
        assert!(parse_admin_origin("https://admin.example").is_err());
        assert!(parse_admin_origin("http://user:pw@host:1").is_err());
        assert!(parse_admin_origin("http://127.0.0.1:9082/admin").is_err());
    }

    struct CliMockMaintenanceRuntime {
        dry_run: rs3_repository::v2::V2FullGcDryRunReport,
    }

    impl CliMockMaintenanceRuntime {
        fn new() -> Self {
            Self {
                dry_run: rs3_repository::v2::V2FullGcDryRunReport {
                    base_sequence: None,
                    chain_live_commit_count: 1,
                    protected_root_count: 0,
                    protected_commit_count: 0,
                    candidate_commit_count: 0,
                    fully_dead_commit_count: 0,
                    mixed_commit_count: 0,
                    dead_bytes_reclaimable: 0,
                    live_bytes_to_copy: 0,
                    mixed_dead_bytes_repackable: 0,
                    retention_blocked_bytes: 0,
                    legal_hold_blocked_bytes: 0,
                    unknown_protection_blocked_bytes: 0,
                    retention_renewal_commit_count: 0,
                    retention_renewal_bytes: 0,
                    retention_renewal_blocked_count: 0,
                    retention_renewal_blocked_bytes: 0,
                    planned_cost: rs3_repository::v2::V2MaintenancePlanCost::default(),
                    fits_budgets: true,
                    exact_version_apply_ready: true,
                },
            }
        }

        fn plan_digest(&self) -> String {
            rs3_crypto::derive_public_fingerprint(
                b"rs3.cli.mock-plan.v1",
                &[&self.dry_run.dead_bytes_reclaimable.to_be_bytes()],
            )
        }
    }

    #[async_trait::async_trait]
    impl rs3_server::MaintenanceRuntime for CliMockMaintenanceRuntime {
        fn maintenance_guard_configured(&self) -> bool {
            true
        }

        async fn quick_maintenance_report(
            &self,
        ) -> Result<rs3_repository::v2::V2MaintenanceReport, rs3_repository::RepositoryError>
        {
            Ok(rs3_repository::v2::V2MaintenanceReport {
                anchor_present: true,
                verified_commit_count: 1,
                last_anchored_commit_age_ms: Some(0),
                orphan_candidate_count: 0,
                orphan_candidate_bytes: 0,
                protected_orphan_candidate_count: 0,
                oldest_orphan_age_ms: None,
                reclaimable_orphan_candidate_count: 0,
                reclaimable_orphan_candidate_bytes: 0,
                oldest_reclaimable_orphan_age_ms: None,
                retention_renewal_commit_count: 0,
                retention_renewal_bytes: 0,
                retention_renewal_blocked_count: 0,
                retention_renewal_blocked_bytes: 0,
                nearest_retain_until_ms: None,
            })
        }

        async fn full_gc_dry_run(
            &self,
            _options: rs3_repository::v2::V2FullGcDryRunOptions,
        ) -> Result<rs3_repository::v2::V2FullGcDryRunReport, rs3_repository::RepositoryError>
        {
            Ok(self.dry_run.clone())
        }

        async fn preview_full_gc_plan(
            &self,
            _options: rs3_repository::v2::V2FullGcApplyOptions,
        ) -> Result<rs3_repository::v2::V2FullGcPlanPreview, rs3_repository::RepositoryError>
        {
            Ok(rs3_repository::v2::V2FullGcPlanPreview {
                report: self.dry_run.clone(),
                plan_digest: self.plan_digest(),
            })
        }

        async fn run_full_maintenance(
            &self,
            _options: rs3_repository::v2::V2FullGcApplyOptions,
            expected_plan_digest: Option<&str>,
            _cancellation: &rs3_repository::v2::V2MaintenanceCancellation,
            on_phase: &(dyn Fn(rs3_server::MaintenanceRunPhase) + Send + Sync),
        ) -> Result<rs3_repository::v2::V2FullMaintenanceReport, rs3_repository::RepositoryError>
        {
            on_phase(rs3_server::MaintenanceRunPhase::Quiescing);
            if let Some(expected) = expected_plan_digest
                && self.plan_digest() != expected
            {
                return Err(rs3_repository::RepositoryError::CommitFailed {
                    reason: rs3_server::MAINTENANCE_PLAN_STALE_REASON.to_owned(),
                });
            }
            on_phase(rs3_server::MaintenanceRunPhase::Applying);
            Ok(rs3_repository::v2::V2FullMaintenanceReport {
                dry_run: self.dry_run.clone(),
                apply: rs3_repository::v2::V2FullGcApplyReport {
                    dry_run: self.dry_run.clone(),
                    retention_renewed_object_count: 0,
                    retention_renewed_bytes: 0,
                    orphan_gc: rs3_repository::v2::V2OrphanGcReport::default(),
                },
            })
        }
    }

    fn maintenance_cli_args(
        addr: std::net::SocketAddr,
        command: MaintenanceCommand,
        format: MaintenanceOutputFormat,
    ) -> MaintenanceArgs {
        MaintenanceArgs {
            admin_url: Some(format!("http://{addr}")),
            admin_bearer_token: Some("cli-read-token-12345".to_owned()),
            admin_mutation_bearer_token: Some("cli-mutation-token-1".to_owned()),
            format,
            command,
        }
    }

    #[tokio::test]
    async fn maintenance_cli_smoke_against_ephemeral_admin_listener() {
        let supervisor = rs3_server::MaintenanceSupervisor::start(
            rs3_server::MaintenanceSupervisorConfig {
                maintenance: rs3_server::MaintenanceConfig {
                    mode: rs3_server::MaintenanceMode::Manual,
                    ..rs3_server::MaintenanceConfig::default()
                },
                retention_configured: false,
                orphan_gc: rs3_repository::v2::V2OrphanGcOptions::new_for_test_rehearsal(
                    Duration::ZERO,
                ),
                retained_provider_conformance: std::sync::Arc::new(|| true),
            },
            std::sync::Arc::new(CliMockMaintenanceRuntime::new()),
            std::sync::Arc::new(rs3_server::SystemMaintenanceClock),
        );
        let auth = rs3_server::AdminHttpAuth::bearer_with_mutation(
            rs3_server::AdminBearerToken::new("cli-read-token-12345")
                .unwrap_or_else(|error| panic!("{error}")),
            rs3_server::AdminBearerToken::new("cli-mutation-token-1")
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let admin_config = rs3_server::AdminHttpConfig::new(
            "127.0.0.1:0"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
            auth,
            rs3_server::AdminReportProfile::Production,
        );
        let server = rs3_server::AdminHttpServer::bind(runtime_config(), admin_config)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .with_maintenance_control(supervisor.control());
        let addr = server.local_addr();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server_task = tokio::spawn(server.run_until_shutdown(async move {
            let _ = shutdown_rx.await;
        }));

        run_maintenance_command(maintenance_cli_args(
            addr,
            MaintenanceCommand::Status,
            MaintenanceOutputFormat::Text,
        ))
        .await
        .unwrap_or_else(|error| panic!("maintenance status failed: {error}"));

        run_maintenance_command(maintenance_cli_args(
            addr,
            MaintenanceCommand::DryRun,
            MaintenanceOutputFormat::Json,
        ))
        .await
        .unwrap_or_else(|error| panic!("maintenance dry-run failed: {error}"));

        run_maintenance_command(maintenance_cli_args(
            addr,
            MaintenanceCommand::Pause,
            MaintenanceOutputFormat::Text,
        ))
        .await
        .unwrap_or_else(|error| panic!("maintenance pause failed: {error}"));
        assert!(supervisor.control().status_snapshot().paused);

        run_maintenance_command(maintenance_cli_args(
            addr,
            MaintenanceCommand::Resume,
            MaintenanceOutputFormat::Text,
        ))
        .await
        .unwrap_or_else(|error| panic!("maintenance resume failed: {error}"));

        // Cancel without an in-flight run surfaces the admin conflict.
        let error = run_maintenance_command(maintenance_cli_args(
            addr,
            MaintenanceCommand::Cancel,
            MaintenanceOutputFormat::Text,
        ))
        .await
        .expect_err("cancel without a run should fail");
        assert!(error.to_string().contains("no-run-in-flight"));

        // The read token is rejected for mutations end to end.
        let mut read_only = maintenance_cli_args(
            addr,
            MaintenanceCommand::Pause,
            MaintenanceOutputFormat::Text,
        );
        read_only.admin_mutation_bearer_token = Some("cli-read-token-12345".to_owned());
        let error = run_maintenance_command(read_only)
            .await
            .expect_err("read token must not authorize mutations");
        assert!(error.to_string().contains("mutation-token-required"));

        let _ = shutdown_tx.send(());
        server_task
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|error| panic!("{error}"));
        supervisor.shutdown().await;
    }

    #[test]
    fn maintenance_offline_cli_is_a_distinct_subcommand_with_digest_bound_apply() {
        use clap::Parser;

        let dry_run = super::Cli::try_parse_from(["rs3", "maintenance-offline", "dry-run"])
            .unwrap_or_else(|error| panic!("{error}"));
        let super::Commands::MaintenanceOffline(args) = dry_run.command else {
            panic!("expected maintenance-offline command");
        };
        assert_eq!(args.command, super::MaintenanceOfflineCommand::DryRun);

        let apply = super::Cli::try_parse_from([
            "rs3",
            "maintenance-offline",
            "apply",
            "--plan-digest",
            "abcd",
            "--format",
            "json",
        ])
        .unwrap_or_else(|error| panic!("{error}"));
        let super::Commands::MaintenanceOffline(args) = apply.command else {
            panic!("expected maintenance-offline command");
        };
        assert_eq!(
            args.command,
            super::MaintenanceOfflineCommand::Apply {
                plan_digest: "abcd".to_owned(),
            }
        );
        assert_eq!(args.format, super::MaintenanceOutputFormat::Json);

        // Apply without a reviewed plan digest must not parse.
        assert!(super::Cli::try_parse_from(["rs3", "maintenance-offline", "apply"]).is_err());
        // The live-gateway `maintenance` command remains a separate surface.
        assert!(super::Cli::try_parse_from(["rs3", "maintenance", "offline"]).is_err());
    }

    #[test]
    fn serve_help_hides_admin_bearer_token_environment_value() {
        use clap::CommandFactory;

        let command = super::Cli::command();
        let serve = command
            .get_subcommands()
            .find(|subcommand| subcommand.get_name() == "serve")
            .unwrap_or_else(|| panic!("serve subcommand must exist"));
        let admin_bearer_token = serve
            .get_arguments()
            .find(|argument| argument.get_id() == "admin_bearer_token")
            .unwrap_or_else(|| panic!("serve admin bearer token argument must exist"));

        assert!(admin_bearer_token.is_hide_env_values_set());
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
        let provider_report = std::env::temp_dir().join(format!(
            "rs3-doctor-provider-report-{}.json",
            std::process::id()
        ));
        let target_fingerprint =
            provider_conformance_target_fingerprint(&V2ProviderCheckConfig::from(&config));
        let checks = rs3_repository::v2::required_v2_provider_check_names(
            rs3_repository::v2::V2ProviderProfile::RetainedVersionObjectLock,
        )
        .into_iter()
        .map(|name| TestProviderCheck {
            name,
            status: "passed",
            reason: None,
        })
        .collect::<Vec<_>>();
        let evidence = TestProviderEvidence {
            schema: PROVIDER_CONFORMANCE_SCHEMA,
            source_revision: super::build_source_revision(),
            target_fingerprint,
            generated_at_ms: super::current_time_ms(),
            profile: "retained-version-object-lock",
            passed: true,
            checks,
        };
        fs::write(
            &provider_report,
            serde_json::to_string(&evidence).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        config.provider_conformance.report_file = Some(provider_report.clone());

        let findings = doctor_findings(&config, DoctorProfile::Production.into());

        assert!(findings.is_empty());
        assert!(enforce_serve_profile(&config, DoctorProfile::Production, true).is_ok());
        fs::remove_file(provider_report).unwrap_or_else(|error| panic!("{error}"));
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
