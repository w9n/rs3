//! Command-line entry point for the rs3 gateway.

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use metrics_exporter_prometheus::PrometheusBuilder;
use rs3_server::{
    AdminBearerToken, AdminHttpAuth, AdminHttpConfig, AdminHttpServer, AdminReportProfile,
    AnchorConfig, AnchorImportReport, AnchorRecoveryOptions, AnchorRecoveryReport, GatewayMode,
    GatewayServer, KeyRotationOptions, KeyRotationReport, RESTORE_BUNDLE_SCHEMA, RepositoryFormat,
    RestoreTrustBundle, RuntimeConfig, RuntimeV2ProviderConformanceOptions,
    V2_RESTORE_BUNDLE_SCHEMA, V2AnchorImportReport, V2AnchorState, V2ProviderCheckStatus,
    V2ProviderConformanceReport, V2ProviderProfile, V2RecoveryBundle, backend_kind,
    check_v2_provider_conformance_from_config, doctor_findings, export_restore_bundle_from_config,
    export_v2_recovery_bundle_from_config, import_anchor_from_config, import_v2_anchor_from_config,
    recover_anchor_from_config, rotate_key_from_config, runtime_config_profile,
    write_v2_index_snapshot_from_config,
};
use rs3_types::{
    BackendObjectId, BackendVersionId, CheckpointId, KeyId, KeyPurpose, RetentionMode, Sequence,
};
use std::net::SocketAddr;
#[cfg(any(feature = "s3", feature = "k8s"))]
use std::sync::Once;
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
    RecoverAnchor {
        #[arg(long, env = "RS3_RECOVERY_MAX_CHECKPOINT_AGE_SECONDS")]
        max_checkpoint_age_seconds: u64,
        #[arg(long, default_value_t = false)]
        apply_if_missing: bool,
        #[arg(long, value_enum, default_value_t = RecoveryReportFormat::Json)]
        format: RecoveryReportFormat,
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
    ImportAnchor {
        #[arg(long)]
        checkpoint_sequence: u64,
        #[arg(long)]
        checkpoint_id: String,
        #[arg(long)]
        checkpoint_version_id: Option<String>,
        #[arg(long)]
        checkpoint_digest: String,
        #[arg(long, value_enum, default_value_t = RecoveryReportFormat::Json)]
        format: RecoveryReportFormat,
    },
    ImportV2Anchor {
        #[arg(long)]
        anchor_sequence: u64,
        #[arg(long)]
        anchor_commit_key: String,
        #[arg(long)]
        anchor_version_id: Option<String>,
        #[arg(long)]
        anchor_body_digest: String,
        #[arg(long)]
        signing_key_id: String,
        #[arg(long)]
        format_generation: u64,
        #[arg(long)]
        format_digest: String,
        #[arg(long)]
        format_object_id: String,
        #[arg(long)]
        format_version_id: Option<String>,
        #[arg(long)]
        weak_subjectivity_floor_sequence: Option<u64>,
        #[arg(long, value_enum, default_value_t = RecoveryReportFormat::Json)]
        format: RecoveryReportFormat,
    },
    RotateKey {
        #[arg(long, value_enum)]
        purpose: KeyPurposeArg,
        #[arg(long)]
        new_key_id: Option<String>,
        #[arg(long, value_enum, default_value_t = RecoveryReportFormat::Json)]
        format: RecoveryReportFormat,
    },
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
enum KeyPurposeArg {
    Namespace,
    Content,
    Metadata,
    Checkpoint,
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
        Commands::RecoverAnchor {
            max_checkpoint_age_seconds,
            apply_if_missing,
            format,
        } => {
            let config = RuntimeConfig::from_env()?;
            log_runtime_config(&config);
            if max_checkpoint_age_seconds == 0 {
                anyhow::bail!("--max-checkpoint-age-seconds must be greater than zero");
            }
            let report = recover_anchor_from_config(
                &config,
                AnchorRecoveryOptions {
                    max_checkpoint_age: std::time::Duration::from_secs(max_checkpoint_age_seconds),
                    apply_if_missing,
                },
            )
            .await?;
            print_recovery_report(&report, format)?;
        }
        Commands::ExportRestoreBundle { format } => {
            let config = RuntimeConfig::from_env()?;
            log_runtime_config(&config);
            match config.repository.format {
                RepositoryFormat::V1Preview => {
                    let bundle = export_restore_bundle_from_config(&config).await?;
                    print_restore_bundle(&bundle, format)?;
                }
                RepositoryFormat::V2Preview => {
                    let bundle = export_v2_recovery_bundle_from_config(&config).await?;
                    print_v2_restore_bundle(&bundle, format)?;
                }
            }
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
        Commands::ImportAnchor {
            checkpoint_sequence,
            checkpoint_id,
            checkpoint_version_id,
            checkpoint_digest,
            format,
        } => {
            let config = RuntimeConfig::from_env()?;
            log_runtime_config(&config);
            let report = import_anchor_from_config(
                &config,
                rs3_repository::CheckpointPosition {
                    sequence: Sequence::new(checkpoint_sequence),
                    checkpoint_id: CheckpointId::new(checkpoint_id)?,
                    checkpoint_version_id: checkpoint_version_id
                        .map(rs3_types::BackendVersionId::new)
                        .transpose()?,
                    payload_digest: checkpoint_digest,
                },
            )
            .await?;
            print_import_report(&report, format)?;
        }
        Commands::ImportV2Anchor {
            anchor_sequence,
            anchor_commit_key,
            anchor_version_id,
            anchor_body_digest,
            signing_key_id,
            format_generation,
            format_digest,
            format_object_id,
            format_version_id,
            weak_subjectivity_floor_sequence,
            format,
        } => {
            let config = RuntimeConfig::from_env()?;
            log_runtime_config(&config);
            let anchor_sequence = Sequence::new(anchor_sequence);
            let floor_sequence =
                Sequence::new(weak_subjectivity_floor_sequence.unwrap_or(anchor_sequence.get()));
            let anchor = V2AnchorState {
                sequence: anchor_sequence,
                commit_key: BackendObjectId::new(anchor_commit_key)?,
                body_digest: decode_sha256_hex(&anchor_body_digest)?,
                version_id: anchor_version_id.map(BackendVersionId::new).transpose()?,
                signing_key_id: KeyId::new(signing_key_id)?,
                format_ref: rs3_repository::v2::V2FormatRef {
                    generation: format_generation,
                    digest: format_digest.clone(),
                    object_id: BackendObjectId::new(format_object_id)?,
                    version_id: format_version_id.map(BackendVersionId::new).transpose()?,
                },
            };
            let bundle = V2RecoveryBundle {
                repository_id: Some(config.repository_keys.repository_id.clone()),
                repository_salt_digest: None,
                format_digest: Some(decode_sha256_hex(&format_digest)?),
                format_generation: Some(format_generation),
                anchor,
                weak_subjectivity_floor_sequence: floor_sequence,
                exported_at_ms: 0,
                offline_signature: None,
            };
            let report = import_v2_anchor_from_config(&config, bundle).await?;
            print_v2_anchor_import_report(&report, format)?;
        }
        Commands::RotateKey {
            purpose,
            new_key_id,
            format,
        } => {
            let config = RuntimeConfig::from_env()?;
            log_runtime_config(&config);
            let report = rotate_key_from_config(
                &config,
                KeyRotationOptions {
                    purpose: purpose.into(),
                    new_key_id: new_key_id.map(KeyId::new).transpose()?,
                },
            )
            .await?;
            print_key_rotation_report(&report, format)?;
        }
    }

    Ok(())
}

#[cfg(any(feature = "s3", feature = "k8s"))]
fn install_rustls_provider() {
    RUSTLS_PROVIDER.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

#[cfg(not(any(feature = "s3", feature = "k8s")))]
fn install_rustls_provider() {}

fn print_key_rotation_report(
    report: &KeyRotationReport,
    format: RecoveryReportFormat,
) -> Result<()> {
    match format {
        RecoveryReportFormat::Json => {
            let report = serde_json::json!({
                "purpose": key_purpose_name(report.purpose),
                "old_primary_key_id": report.old_primary_key_id.as_str(),
                "new_primary_key_id": report.new_primary_key_id.as_str(),
                "staged_sequence": report.staged_sequence.get(),
                "checkpoint": {
                    "sequence": report.checkpoint.sequence.get(),
                    "checkpoint_id": report.checkpoint.checkpoint_id.as_str(),
                    "checkpoint_version_id": report.checkpoint.checkpoint_version_id.as_ref().map(|version_id| version_id.as_str()),
                    "checkpoint_digest": report.checkpoint.payload_digest,
                    "published_at_ms": report.published_at_ms,
                },
                "keyring_envelope": {
                    "generation": report.keyring_envelope.generation,
                    "object_id": report.keyring_envelope.object_id.as_str(),
                    "version_id": report.keyring_envelope.version_id.as_ref().map(|version_id| version_id.as_str()),
                    "digest": report.keyring_envelope.digest,
                },
            });
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        RecoveryReportFormat::Text => {
            println!("rs3 key rotation: accepted checkpoint published");
            println!("purpose={}", key_purpose_name(report.purpose));
            println!("old_primary_key_id={}", report.old_primary_key_id.as_str());
            println!("new_primary_key_id={}", report.new_primary_key_id.as_str());
            println!("staged_sequence={}", report.staged_sequence.get());
            println!("checkpoint_sequence={}", report.checkpoint.sequence.get());
            println!("checkpoint_id={}", report.checkpoint.checkpoint_id.as_str());
            if let Some(version_id) = report.checkpoint.checkpoint_version_id.as_ref() {
                println!("checkpoint_version_id={}", version_id.as_str());
            }
            println!("checkpoint_digest={}", report.checkpoint.payload_digest);
            println!("published_at_ms={}", report.published_at_ms);
            println!(
                "keyring_envelope_generation={}",
                report.keyring_envelope.generation
            );
            println!(
                "keyring_envelope_object_id={}",
                report.keyring_envelope.object_id.as_str()
            );
            if let Some(version_id) = report.keyring_envelope.version_id.as_ref() {
                println!("keyring_envelope_version_id={}", version_id.as_str());
            }
            println!("keyring_envelope_digest={}", report.keyring_envelope.digest);
        }
    }
    Ok(())
}

fn print_restore_bundle(bundle: &RestoreTrustBundle, format: RecoveryReportFormat) -> Result<()> {
    match format {
        RecoveryReportFormat::Json => {
            let keyring_envelope = bundle.keyring_envelope.as_ref().map(|envelope| {
                serde_json::json!({
                    "generation": envelope.generation,
                    "object_id": envelope.object_id.as_str(),
                    "version_id": envelope.version_id.as_ref().map(|version_id| version_id.as_str()),
                    "digest": envelope.digest,
                })
            });
            let bundle = serde_json::json!({
                "schema": RESTORE_BUNDLE_SCHEMA,
                "repository": {
                    "id": bundle.repository_id.as_str(),
                    "salt_hex": bundle.repository_salt_hex,
                },
                "checkpoint": {
                    "sequence": bundle.checkpoint.sequence.get(),
                    "checkpoint_id": bundle.checkpoint.checkpoint_id.as_str(),
                    "checkpoint_version_id": bundle.checkpoint.checkpoint_version_id.as_ref().map(|version_id| version_id.as_str()),
                    "checkpoint_digest": bundle.checkpoint.payload_digest,
                    "published_at_ms": bundle.published_at_ms,
                },
                "keyring_envelope": keyring_envelope,
                "generated_at_ms": bundle.generated_at_ms,
            });
            println!("{}", serde_json::to_string_pretty(&bundle)?);
        }
        RecoveryReportFormat::Text => {
            println!("schema={RESTORE_BUNDLE_SCHEMA}");
            println!("repository_id={}", bundle.repository_id.as_str());
            println!("repository_salt_hex={}", bundle.repository_salt_hex);
            println!("checkpoint_sequence={}", bundle.checkpoint.sequence.get());
            println!("checkpoint_id={}", bundle.checkpoint.checkpoint_id.as_str());
            if let Some(version_id) = bundle.checkpoint.checkpoint_version_id.as_ref() {
                println!("checkpoint_version_id={}", version_id.as_str());
            }
            println!("checkpoint_digest={}", bundle.checkpoint.payload_digest);
            println!("published_at_ms={}", bundle.published_at_ms);
            if let Some(envelope) = bundle.keyring_envelope.as_ref() {
                println!("keyring_envelope_generation={}", envelope.generation);
                println!("keyring_envelope_object_id={}", envelope.object_id.as_str());
                if let Some(version_id) = envelope.version_id.as_ref() {
                    println!("keyring_envelope_version_id={}", version_id.as_str());
                }
                println!("keyring_envelope_digest={}", envelope.digest);
            }
            println!("generated_at_ms={}", bundle.generated_at_ms);
        }
    }
    Ok(())
}

fn print_import_report(report: &AnchorImportReport, format: RecoveryReportFormat) -> Result<()> {
    match format {
        RecoveryReportFormat::Json => {
            let report = serde_json::json!({
                "checkpoint": {
                    "sequence": report.checkpoint.sequence.get(),
                    "checkpoint_id": report.checkpoint.checkpoint_id.as_str(),
                    "checkpoint_version_id": report.checkpoint.checkpoint_version_id.as_ref().map(|version_id| version_id.as_str()),
                    "checkpoint_digest": report.checkpoint.payload_digest,
                    "published_at_ms": report.published_at_ms,
                },
                "applied": report.applied,
            });
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        RecoveryReportFormat::Text => {
            println!("rs3 anchor import: trusted checkpoint applied");
            println!("checkpoint_sequence={}", report.checkpoint.sequence.get());
            println!("checkpoint_id={}", report.checkpoint.checkpoint_id.as_str());
            if let Some(version_id) = report.checkpoint.checkpoint_version_id.as_ref() {
                println!("checkpoint_version_id={}", version_id.as_str());
            }
            println!("checkpoint_digest={}", report.checkpoint.payload_digest);
            println!("published_at_ms={}", report.published_at_ms);
            println!("applied={}", report.applied);
        }
    }
    Ok(())
}

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
                "profile": provider_profile_name(report.profile),
                "passed": report.passed(),
                "checks": checks,
            });
            println!("{}", serde_json::to_string_pretty(&report_json)?);
        }
        RecoveryReportFormat::Text => {
            println!("schema=rs3.v2-provider-conformance.v1");
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

fn print_recovery_report(
    report: &AnchorRecoveryReport,
    format: RecoveryReportFormat,
) -> Result<()> {
    match format {
        RecoveryReportFormat::Json => {
            let report = serde_json::json!({
                "checkpoint": {
                    "sequence": report.checkpoint.sequence.get(),
                    "checkpoint_id": report.checkpoint.checkpoint_id.as_str(),
                    "checkpoint_version_id": report.checkpoint.checkpoint_version_id.as_ref().map(|version_id| version_id.as_str()),
                    "checkpoint_digest": report.checkpoint.payload_digest,
                    "published_at_ms": report.published_at_ms,
                },
                "observed": {
                    "evidence_objects": report.observed_evidence_objects,
                    "candidate_checkpoints": report.candidate_count,
                },
                "applied": report.applied,
            });
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        RecoveryReportFormat::Text => {
            println!("rs3 anchor recovery: highest observed valid checkpoint");
            println!("checkpoint_sequence={}", report.checkpoint.sequence.get());
            println!("checkpoint_id={}", report.checkpoint.checkpoint_id.as_str());
            if let Some(version_id) = report.checkpoint.checkpoint_version_id.as_ref() {
                println!("checkpoint_version_id={}", version_id.as_str());
            }
            println!("checkpoint_digest={}", report.checkpoint.payload_digest);
            println!("published_at_ms={}", report.published_at_ms);
            println!(
                "observed_evidence_objects={}",
                report.observed_evidence_objects
            );
            println!("candidate_checkpoints={}", report.candidate_count);
            println!("applied={}", report.applied);
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

impl From<KeyPurposeArg> for KeyPurpose {
    fn from(value: KeyPurposeArg) -> Self {
        match value {
            KeyPurposeArg::Namespace => Self::Namespace,
            KeyPurposeArg::Content => Self::Content,
            KeyPurposeArg::Metadata => Self::Metadata,
            KeyPurposeArg::Checkpoint => Self::CheckpointSigning,
        }
    }
}

fn key_purpose_name(purpose: KeyPurpose) -> &'static str {
    match purpose {
        KeyPurpose::Namespace => "namespace",
        KeyPurpose::Content => "content",
        KeyPurpose::Metadata => "metadata",
        KeyPurpose::CheckpointSigning => "checkpoint",
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
        LogFormat::Plain => tracing_subscriber::fmt().with_env_filter(filter).init(),
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
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
    use super::{DoctorProfile, backend_kind, doctor_findings, runtime_config_profile};
    use rs3_server::{
        AnchorConfig, BackendConfig, BatchConfig, GatewayMode, MetricsConfig, RepositoryConfig,
        RepositoryFormat, RepositoryKeysConfig, RuntimeConfig, SecretString, StaticCredentials,
    };
    use rs3_types::{BackendObjectId, PublicBucket, RepositoryId, RetentionMode, RetentionPolicy};
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
                format: RepositoryFormat::V1Preview,
                payload_segment_size: rs3_repository::DEFAULT_PAYLOAD_SEGMENT_SIZE,
                adaptive_payload_segment_size: true,
                decrypted_segment_cache_max_bytes:
                    rs3_repository::DEFAULT_DECRYPTED_SEGMENT_CACHE_MAX_BYTES,
                retention: None,
            },
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
    }

    #[test]
    fn production_doctor_does_not_require_write_retention_for_restore_readonly() {
        let mut config = runtime_config();
        config.mode = GatewayMode::RestoreReadOnly;
        config.anchor = AnchorConfig::KubernetesLease {
            namespace: "backup".to_owned(),
            name: "checkpoint".to_owned(),
            field_manager: "rs3-server".to_owned(),
        };
        config.static_credentials = Some(StaticCredentials {
            access_key_id: "access".to_owned(),
            secret_access_key: SecretString::from("secret"),
        });

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
            name: "checkpoint".to_owned(),
            field_manager: "rs3-server".to_owned(),
        };
        config.repository.retention = Some(RetentionPolicy::new(RetentionMode::Compliance, 30));
        config.static_credentials = Some(StaticCredentials {
            access_key_id: "access".to_owned(),
            secret_access_key: SecretString::from("secret"),
        });

        let findings = doctor_findings(&config, DoctorProfile::Production.into());

        assert!(findings.is_empty());
    }
}
