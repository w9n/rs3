//! Command-line entry point for the rs3 gateway.

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use metrics_exporter_prometheus::PrometheusBuilder;
use rs3_repository::v2::{
    V2AnchorState, V2ProviderCheckStatus, V2ProviderConformanceReport, V2ProviderProfile,
    V2RecoveryBundle,
};
use rs3_server::{
    AdminBearerToken, AdminHttpAuth, AdminHttpConfig, AdminHttpServer, AdminReportProfile,
    AnchorConfig, GatewayMode, GatewayServer, RuntimeConfig, RuntimeV2ProviderConformanceOptions,
    V2_RESTORE_BUNDLE_SCHEMA, V2AnchorImportOptions, V2AnchorImportReport, backend_kind,
    check_v2_provider_conformance_from_config, doctor_findings,
    export_v2_recovery_bundle_from_config, import_v2_anchor_from_config, runtime_config_profile,
    write_v2_index_snapshot_from_config,
};
use rs3_types::{BackendObjectId, BackendVersionId, KeyId, RetentionMode, Sequence};
use serde::Deserialize;
use std::io::{self, Read};
use std::net::SocketAddr;
#[cfg(any(feature = "s3", feature = "k8s"))]
use std::sync::Once;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

#[cfg(any(feature = "s3", feature = "k8s"))]
static RUSTLS_PROVIDER: Once = Once::new();

#[derive(Debug, Parser)]
#[command(name = "rs3")]
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
    Doctor {
        #[arg(long, env = "RS3_DOCTOR_PROFILE", value_enum, default_value_t = DoctorProfile::Local)]
        profile: DoctorProfile,
    },
    ExportRestoreBundle {
        #[arg(long, value_enum, default_value_t = RecoveryReportFormat::Json)]
        format: RecoveryReportFormat,
    },
    WriteIndexSnapshot {
        #[arg(long, value_enum, default_value_t = RecoveryReportFormat::Json)]
        format: RecoveryReportFormat,
    },
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
    ImportV2Anchor(Box<ImportV2AnchorArgs>),
}

#[derive(Debug, Args)]
struct ImportV2AnchorArgs {
    /// JSON bundle from `export-restore-bundle`; use `-` for stdin.
    #[arg(long)]
    bundle_file: Option<String>,
    /// External weak-subjectivity floor accepted by the operator.
    #[arg(long)]
    min_sequence: u64,
    /// Accepted anchor sequence from a trusted bundle.
    #[arg(long)]
    anchor_sequence: Option<u64>,
    /// Accepted commit key from a trusted bundle.
    #[arg(long)]
    anchor_commit_key: Option<String>,
    /// Provider version identifier for the accepted commit object, when available.
    #[arg(long)]
    anchor_version_id: Option<String>,
    /// Accepted commit body digest from a trusted bundle.
    #[arg(long)]
    anchor_body_digest: Option<String>,
    /// Commit-signing key ID from a trusted bundle.
    #[arg(long)]
    signing_key_id: Option<String>,
    /// Format-root generation from a trusted bundle.
    #[arg(long)]
    format_generation: Option<u64>,
    /// Format-root digest from a trusted bundle.
    #[arg(long)]
    format_digest: Option<String>,
    /// Format-root object ID from a trusted bundle.
    #[arg(long)]
    format_object_id: Option<String>,
    /// Format-root version ID from a trusted bundle, when available.
    #[arg(long)]
    format_version_id: Option<String>,
    /// Weak-subjectivity floor sequence. Defaults to `--anchor-sequence`.
    #[arg(long)]
    weak_subjectivity_floor_sequence: Option<u64>,
    /// Offline recovery signature from a trusted bundle, as hex.
    #[arg(long)]
    offline_signature: Option<String>,
    /// Output format.
    #[arg(long, value_enum, default_value_t = RecoveryReportFormat::Json)]
    format: RecoveryReportFormat,
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
            install_metrics(config.metrics.bind)?;
            log_runtime_config(&config);
            let server = GatewayServer::bind(config.clone()).await?;
            tracing::info!(bind = %server.local_addr(), "gateway S3 listener started");
            match admin_config {
                Some(admin_config) => {
                    let admin_server = AdminHttpServer::bind(config, admin_config).await?;
                    tracing::info!(
                        bind = %admin_server.local_addr(),
                        "gateway admin listener started",
                    );
                    run_gateway_and_admin(server, admin_server).await?;
                }
                None => {
                    server.run_until_shutdown(shutdown_signal()).await?;
                }
            }
        }
        Commands::Doctor { profile } => {
            let config = RuntimeConfig::from_env()?;
            log_runtime_config(&config);
            run_doctor(&config, profile)?;
        }
        Commands::ExportRestoreBundle { format } => {
            let config = RuntimeConfig::from_env()?;
            log_runtime_config(&config);
            let bundle = export_v2_recovery_bundle_from_config(&config).await?;
            print_v2_restore_bundle(&bundle, format)?;
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
            let config = RuntimeConfig::from_env()?;
            log_runtime_config(&config);
            let report = check_v2_provider_conformance_from_config(
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

#[derive(Deserialize)]
struct RestoreBundleJson {
    schema: String,
    #[serde(default)]
    repository: Option<RestoreBundleRepositoryJson>,
    anchor: RestoreBundleAnchorJson,
    weak_subjectivity_floor_sequence: u64,
    #[serde(default)]
    format_digest: Option<String>,
    #[serde(default)]
    format_generation: Option<u64>,
    exported_at_ms: i64,
    #[serde(default)]
    offline_signature: Option<String>,
}

#[derive(Deserialize)]
struct RestoreBundleRepositoryJson {
    id: String,
}

#[derive(Deserialize)]
struct RestoreBundleAnchorJson {
    sequence: u64,
    commit_key: String,
    body_digest: String,
    #[serde(default)]
    version_id: Option<String>,
    signing_key_id: String,
    format: RestoreBundleFormatJson,
}

#[derive(Deserialize)]
struct RestoreBundleFormatJson {
    generation: u64,
    digest: String,
    object_id: String,
    #[serde(default)]
    version_id: Option<String>,
}

fn recovery_bundle_from_import_args(
    config: &RuntimeConfig,
    args: ImportV2AnchorArgs,
) -> Result<(V2RecoveryBundle, V2AnchorImportOptions)> {
    let explicit_field_count = usize::from(args.anchor_sequence.is_some())
        + usize::from(args.anchor_commit_key.is_some())
        + usize::from(args.anchor_body_digest.is_some())
        + usize::from(args.signing_key_id.is_some())
        + usize::from(args.format_generation.is_some())
        + usize::from(args.format_digest.is_some())
        + usize::from(args.format_object_id.is_some())
        + usize::from(args.weak_subjectivity_floor_sequence.is_some())
        + usize::from(args.anchor_version_id.is_some())
        + usize::from(args.format_version_id.is_some())
        + usize::from(args.offline_signature.is_some());
    let options = V2AnchorImportOptions {
        min_sequence: Sequence::new(args.min_sequence),
    };
    let bundle = match args.bundle_file.clone() {
        Some(path) => {
            if explicit_field_count > 0 {
                bail!("--bundle-file cannot be combined with explicit anchor fields");
            }
            read_restore_bundle_json(&path, config)?
        }
        None => recovery_bundle_from_explicit_args(config, args)?,
    };
    Ok((bundle, options))
}

fn recovery_bundle_from_explicit_args(
    config: &RuntimeConfig,
    args: ImportV2AnchorArgs,
) -> Result<V2RecoveryBundle> {
    let anchor_sequence = require_arg(args.anchor_sequence, "--anchor-sequence")?;
    let anchor_sequence = Sequence::new(anchor_sequence);
    let floor_sequence = Sequence::new(
        args.weak_subjectivity_floor_sequence
            .unwrap_or(anchor_sequence.get()),
    );
    let format_generation = require_arg(args.format_generation, "--format-generation")?;
    let format_digest = require_arg(args.format_digest, "--format-digest")?;
    let anchor = V2AnchorState {
        sequence: anchor_sequence,
        commit_key: BackendObjectId::new(require_arg(
            args.anchor_commit_key,
            "--anchor-commit-key",
        )?)?,
        body_digest: decode_sha256_hex(&require_arg(
            args.anchor_body_digest,
            "--anchor-body-digest",
        )?)?,
        version_id: args
            .anchor_version_id
            .map(BackendVersionId::new)
            .transpose()?,
        signing_key_id: KeyId::new(require_arg(args.signing_key_id, "--signing-key-id")?)?,
        format_ref: rs3_repository::v2::V2FormatRef {
            generation: format_generation,
            digest: format_digest.clone(),
            object_id: BackendObjectId::new(require_arg(
                args.format_object_id,
                "--format-object-id",
            )?)?,
            version_id: args
                .format_version_id
                .map(BackendVersionId::new)
                .transpose()?,
        },
    };
    Ok(V2RecoveryBundle {
        repository_id: Some(config.repository_keys.repository_id.clone()),
        repository_salt_digest: None,
        format_digest: Some(decode_sha256_hex(&format_digest)?),
        format_generation: Some(format_generation),
        anchor,
        weak_subjectivity_floor_sequence: floor_sequence,
        exported_at_ms: 0,
        offline_signature: args
            .offline_signature
            .map(|signature| {
                hex::decode(signature).context("offline signature must be hex encoded")
            })
            .transpose()?,
    })
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

fn parse_restore_bundle_json(input: &str, config: &RuntimeConfig) -> Result<V2RecoveryBundle> {
    let decoded: RestoreBundleJson =
        serde_json::from_str(input).context("failed to parse v2 restore bundle JSON")?;
    if decoded.schema != V2_RESTORE_BUNDLE_SCHEMA {
        bail!("unsupported restore bundle schema {}", decoded.schema);
    }
    let repository_id = decoded
        .repository
        .as_ref()
        .map(|repository| rs3_types::RepositoryId::new(repository.id.clone()))
        .transpose()?;
    if let Some(repository_id) = repository_id.as_ref()
        && repository_id != &config.repository_keys.repository_id
    {
        bail!("restore bundle repository ID does not match configured repository ID");
    }
    let format_ref = rs3_repository::v2::V2FormatRef {
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
        body_digest: decode_sha256_hex(&decoded.anchor.body_digest)?,
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

    Ok(V2RecoveryBundle {
        repository_id: Some(
            repository_id.unwrap_or_else(|| config.repository_keys.repository_id.clone()),
        ),
        repository_salt_digest: None,
        format_digest: decoded
            .format_digest
            .map(|digest| decode_sha256_hex(&digest))
            .transpose()?,
        format_generation: decoded.format_generation,
        anchor,
        weak_subjectivity_floor_sequence: Sequence::new(decoded.weak_subjectivity_floor_sequence),
        exported_at_ms: decoded.exported_at_ms,
        offline_signature,
    })
}

fn require_arg<T>(value: Option<T>, flag: &'static str) -> Result<T> {
    value.ok_or_else(|| anyhow::anyhow!("{flag} is required without --bundle-file"))
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
                "anchor": {
                    "sequence": report.anchor.sequence.get(),
                    "commit_key": report.anchor.commit_key.as_str(),
                    "body_digest": hex::encode(report.anchor.body_digest),
                    "version_id": report.anchor.version_id.as_ref().map(|version_id| version_id.as_str()),
                    "signing_key_id": report.anchor.signing_key_id.as_str(),
                    "format": {
                        "generation": report.anchor.format_ref.generation,
                        "digest": report.anchor.format_ref.digest,
                        "object_id": report.anchor.format_ref.object_id.as_str(),
                        "version_id": report.anchor.format_ref.version_id.as_ref().map(|version_id| version_id.as_str()),
                    },
                },
            });
            println!("{}", serde_json::to_string_pretty(&report_json)?);
        }
        RecoveryReportFormat::Text => {
            println!("schema=rs3.v2-anchor-import.v1");
            println!("applied={}", report.applied);
            println!("verified_commit_count={}", report.verified_commit_count);
            println!("anchor_sequence={}", report.anchor.sequence.get());
            println!("anchor_commit_key={}", report.anchor.commit_key.as_str());
            println!(
                "anchor_body_digest={}",
                hex::encode(report.anchor.body_digest)
            );
            if let Some(version_id) = report.anchor.version_id.as_ref() {
                println!("anchor_version_id={}", version_id.as_str());
            }
            println!("signing_key_id={}", report.anchor.signing_key_id.as_str());
            println!("format_generation={}", report.anchor.format_ref.generation);
            println!("format_digest={}", report.anchor.format_ref.digest);
            println!(
                "format_object_id={}",
                report.anchor.format_ref.object_id.as_str()
            );
            if let Some(version_id) = report.anchor.format_ref.version_id.as_ref() {
                println!("format_version_id={}", version_id.as_str());
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
            let repository = bundle.repository_id.as_ref().map(|repository_id| {
                serde_json::json!({
                    "id": repository_id.as_str(),
                })
            });
            let offline_signature = bundle.offline_signature.as_ref().map(hex::encode);
            let offline_signature_payload_hex = hex::encode(bundle.offline_signature_payload()?);
            let bundle_json = serde_json::json!({
                "schema": V2_RESTORE_BUNDLE_SCHEMA,
                "repository": repository,
                "anchor": {
                    "sequence": bundle.anchor.sequence.get(),
                    "commit_key": bundle.anchor.commit_key.as_str(),
                    "body_digest": hex::encode(bundle.anchor.body_digest),
                    "version_id": bundle.anchor.version_id.as_ref().map(|version_id| version_id.as_str()),
                    "signing_key_id": bundle.anchor.signing_key_id.as_str(),
                    "format": {
                        "generation": bundle.anchor.format_ref.generation,
                        "digest": bundle.anchor.format_ref.digest,
                        "object_id": bundle.anchor.format_ref.object_id.as_str(),
                        "version_id": bundle.anchor.format_ref.version_id.as_ref().map(|version_id| version_id.as_str()),
                    },
                },
                "weak_subjectivity_floor_sequence": bundle.weak_subjectivity_floor_sequence.get(),
                "format_digest": bundle.format_digest.map(hex::encode),
                "format_generation": bundle.format_generation,
                "exported_at_ms": bundle.exported_at_ms,
                "offline_signature_payload_hex": offline_signature_payload_hex,
                "offline_signature": offline_signature,
            });
            println!("{}", serde_json::to_string_pretty(&bundle_json)?);
        }
        RecoveryReportFormat::Text => {
            println!("schema={V2_RESTORE_BUNDLE_SCHEMA}");
            if let Some(repository_id) = bundle.repository_id.as_ref() {
                println!("repository_id={}", repository_id.as_str());
            }
            println!("anchor_sequence={}", bundle.anchor.sequence.get());
            println!("anchor_commit_key={}", bundle.anchor.commit_key.as_str());
            println!(
                "anchor_body_digest={}",
                hex::encode(bundle.anchor.body_digest)
            );
            if let Some(version_id) = bundle.anchor.version_id.as_ref() {
                println!("anchor_version_id={}", version_id.as_str());
            }
            println!("signing_key_id={}", bundle.anchor.signing_key_id.as_str());
            println!("format_generation={}", bundle.anchor.format_ref.generation);
            println!("format_digest={}", bundle.anchor.format_ref.digest);
            println!(
                "format_object_id={}",
                bundle.anchor.format_ref.object_id.as_str()
            );
            if let Some(version_id) = bundle.anchor.format_ref.version_id.as_ref() {
                println!("format_version_id={}", version_id.as_str());
            }
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
                "anchor": {
                    "sequence": anchor.sequence.get(),
                    "commit_key": anchor.commit_key.as_str(),
                    "body_digest": hex::encode(anchor.body_digest),
                    "version_id": anchor.version_id.as_ref().map(|version_id| version_id.as_str()),
                    "signing_key_id": anchor.signing_key_id.as_str(),
                    "format": {
                        "generation": anchor.format_ref.generation,
                        "digest": anchor.format_ref.digest,
                        "object_id": anchor.format_ref.object_id.as_str(),
                        "version_id": anchor.format_ref.version_id.as_ref().map(|version_id| version_id.as_str()),
                    },
                },
            });
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        RecoveryReportFormat::Text => {
            println!("schema={schema}");
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
    }
    Ok(())
}

fn run_doctor(config: &RuntimeConfig, profile: DoctorProfile) -> Result<()> {
    let findings = doctor_findings(config, profile.into());
    if findings.is_empty() {
        println!("rs3 doctor: {} profile ok", profile.as_str());
        return Ok(());
    }

    for finding in &findings {
        eprintln!("rs3 doctor [{}]: {}", finding.code, finding.message);
    }
    anyhow::bail!(
        "rs3 doctor: {} profile failed with {} finding(s)",
        profile.as_str(),
        findings.len()
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

async fn run_gateway_and_admin(gateway: GatewayServer, admin: AdminHttpServer) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let gateway_shutdown = shutdown_rx.clone();
    let admin_shutdown = shutdown_rx;

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
        gateway_mode = config.mode.as_str(),
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

fn init_tracing(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    match format {
        LogFormat::Plain => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(io::stderr)
            .init(),
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .with_writer(io::stderr)
            .init(),
    }
}

fn decode_sha256_hex(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value)?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected a 32-byte hex digest"))
}

#[cfg(test)]
mod tests {
    use super::{
        DoctorProfile, ImportV2AnchorArgs, RecoveryReportFormat, backend_kind, doctor_findings,
        parse_restore_bundle_json, recovery_bundle_from_import_args, runtime_config_profile,
    };
    use rs3_server::{
        AnchorConfig, BackendConfig, BatchConfig, GatewayMode, HardeningConfig, MetricsConfig,
        ProviderConformanceConfig, RecoveryConfig, RepositoryConfig, RepositoryFormat,
        RepositoryKeysConfig, RuntimeConfig, StaticCredentials,
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
        assert!(codes.contains(&"auth.static-credentials"));
        assert!(codes.contains(&"recovery.public-key"));
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
        config.static_credentials = Some(StaticCredentials {
            access_key_id: "rs3-fixture-access-key".to_owned(),
            secret_access_key: SecretString::from("rs3-fixture-secret-key"),
        });
        config.recovery.public_key = Some(
            "ed25519:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
        );

        let findings = doctor_findings(&config, DoctorProfile::Production.into());

        assert!(findings.is_empty());
    }

    #[test]
    fn import_bundle_parser_accepts_export_restore_bundle_shape() {
        let config = runtime_config();
        let input = serde_json::json!({
            "schema": "rs3.restore-bundle.v2-preview.v1",
            "repository": {
                "id": "tenant-repository"
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
                "commit_key": "commits/v01/00000000000000000007/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
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
    fn import_v2_anchor_rejects_mixed_bundle_and_explicit_fields() {
        let config = runtime_config();
        let args = ImportV2AnchorArgs {
            bundle_file: Some("bundle.json".to_owned()),
            min_sequence: 1,
            anchor_sequence: Some(1),
            anchor_commit_key: None,
            anchor_version_id: None,
            anchor_body_digest: None,
            signing_key_id: None,
            format_generation: None,
            format_digest: None,
            format_object_id: None,
            format_version_id: None,
            weak_subjectivity_floor_sequence: None,
            offline_signature: None,
            format: RecoveryReportFormat::Json,
        };

        let error = match recovery_bundle_from_import_args(&config, args) {
            Ok(_) => panic!("mixed bundle-file and explicit fields should be rejected"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("cannot be combined"));
    }
}
