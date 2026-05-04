//! Command-line entry point for the rs3 gateway.

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use metrics_exporter_prometheus::PrometheusBuilder;
use rs3_crypto::derive_public_fingerprint;
use rs3_server::{
    AnchorConfig, AnchorRecoveryOptions, AnchorRecoveryReport, GatewayMode, GatewayServer,
    RuntimeConfig, recover_anchor_from_config,
};
use rs3_types::RetentionMode;
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

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
    let cli = Cli::parse();
    init_tracing(cli.log_format);

    match cli.command {
        Commands::Serve {
            bind,
            metrics_bind,
            gateway_mode,
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
            install_metrics(config.metrics.bind)?;
            log_runtime_config(&config);
            let server = GatewayServer::bind(config).await?;
            tracing::info!(bind = %server.local_addr(), "gateway S3 listener started");
            server.run_until_shutdown(shutdown_signal()).await?;
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
    let findings = doctor_findings(config, profile);
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

fn doctor_findings(config: &RuntimeConfig, profile: DoctorProfile) -> Vec<DoctorFinding> {
    match profile {
        DoctorProfile::Local => Vec::new(),
        DoctorProfile::Production => production_doctor_findings(config),
    }
}

fn production_doctor_findings(config: &RuntimeConfig) -> Vec<DoctorFinding> {
    let mut findings = Vec::new();

    if matches!(config.anchor, AnchorConfig::Memory) {
        findings.push(DoctorFinding::new(
            "anchor.memory",
            "production profile requires a durable external checkpoint anchor",
        ));
    }

    if config.mode.allows_mutation() && config.repository.retention.is_none() {
        findings.push(DoctorFinding::new(
            "retention.missing",
            "production profile requires repository retention",
        ));
    }

    match backend_kind(&config.backend.endpoint) {
        "memory" => findings.push(DoctorFinding::new(
            "backend.memory",
            "production profile requires a durable object-store backend",
        )),
        "filesystem" => findings.push(DoctorFinding::new(
            "retention.backend-unsupported",
            "filesystem backend cannot enforce provider retention",
        )),
        "unknown" => findings.push(DoctorFinding::new(
            "backend.unknown",
            "configured backend is not supported by the gateway runtime",
        )),
        "s3-compatible" => {}
        _ => {}
    }

    if config.static_credentials.is_none() {
        findings.push(DoctorFinding::new(
            "auth.static-credentials",
            "production profile requires configured gateway credentials",
        ));
    }

    findings
}

impl From<GatewayModeArg> for GatewayMode {
    fn from(value: GatewayModeArg) -> Self {
        match value {
            GatewayModeArg::ReadWrite => Self::ReadWrite,
            GatewayModeArg::RestoreReadonly => Self::RestoreReadOnly,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DoctorFinding {
    code: &'static str,
    message: &'static str,
}

impl DoctorFinding {
    fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
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
        repository_retention_mode,
        repository_retention_days,
        static_credentials = config.static_credentials.is_some(),
        config_profile,
        "gateway runtime configuration validated",
    );
}

fn backend_kind(endpoint: &str) -> &'static str {
    if endpoint == "memory" || endpoint.starts_with("memory://") {
        "memory"
    } else if endpoint.starts_with("file://") {
        "filesystem"
    } else if endpoint == "s3"
        || endpoint.starts_with("https://")
        || endpoint.starts_with("http://")
    {
        "s3-compatible"
    } else {
        "unknown"
    }
}

fn runtime_config_profile(config: &RuntimeConfig) -> String {
    let anchor = match &config.anchor {
        AnchorConfig::Memory => "memory".to_owned(),
        AnchorConfig::KubernetesLease { .. } => "kubernetes-lease".to_owned(),
    };
    let metrics = config.metrics.bind.is_some().to_string();
    let gateway_mode = config.mode.as_str().to_owned();
    let backend_kind = backend_kind(&config.backend.endpoint).to_owned();
    let batch_max_items = config.batching.max_items.to_string();
    let batch_max_delay_ms = config.batching.max_delay.as_millis().to_string();
    let batch_max_pending_items = config.batching.max_pending_items.to_string();
    let payload_segment_size = config.repository.payload_segment_size.to_string();
    let retention_mode = config
        .repository
        .retention
        .map(|policy| match policy.mode {
            RetentionMode::None => "none",
            RetentionMode::Governance => "governance",
            RetentionMode::Compliance => "compliance",
        })
        .unwrap_or("none")
        .to_owned();
    let retention_days = config
        .repository
        .retention
        .map(|policy| policy.retain_days)
        .unwrap_or(0)
        .to_string();
    let static_credentials = config.static_credentials.is_some().to_string();
    let fields = [
        anchor.as_bytes(),
        gateway_mode.as_bytes(),
        metrics.as_bytes(),
        backend_kind.as_bytes(),
        batch_max_items.as_bytes(),
        batch_max_delay_ms.as_bytes(),
        batch_max_pending_items.as_bytes(),
        payload_segment_size.as_bytes(),
        retention_mode.as_bytes(),
        retention_days.as_bytes(),
        static_credentials.as_bytes(),
    ];

    derive_public_fingerprint(b"rs3:server-runtime-config-profile:v1", &fields)
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

#[cfg(test)]
mod tests {
    use super::{DoctorProfile, backend_kind, doctor_findings, runtime_config_profile};
    use rs3_server::{
        AnchorConfig, BackendConfig, BatchConfig, GatewayMode, MetricsConfig, RepositoryConfig,
        RepositoryKeysConfig, RuntimeConfig, SecretString, StaticCredentials,
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
                payload_segment_size: rs3_repository::DEFAULT_PAYLOAD_SEGMENT_SIZE,
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
        let findings = doctor_findings(&runtime_config(), DoctorProfile::Local);

        assert!(findings.is_empty());
    }

    #[test]
    fn production_doctor_rejects_dev_only_posture() {
        let findings = doctor_findings(&runtime_config(), DoctorProfile::Production);
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

        let findings = doctor_findings(&config, DoctorProfile::Production);
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

        let findings = doctor_findings(&config, DoctorProfile::Production);

        assert!(findings.is_empty());
    }
}
