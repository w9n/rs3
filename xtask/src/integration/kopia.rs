//! Kopia compatibility integration command.

use super::S3ContainerProvider;
#[cfg(feature = "containers")]
use super::gateway_process::{
    ACCESS_KEY_ID, GatewayBackend, GatewayBuildProfile, GatewayProcessOptions, PUBLIC_BUCKET,
    RunningGateway, SECRET_ACCESS_KEY,
};
#[cfg(feature = "containers")]
use super::s3_container;
use anyhow::Result;
#[cfg(feature = "containers")]
use anyhow::{Context, bail};
use clap::{Args, ValueEnum};
#[cfg(any(feature = "containers", test))]
#[path = "kopia/budgets.rs"]
mod budgets;
#[cfg(feature = "containers")]
#[path = "kopia/measurement.rs"]
mod measurement;
#[path = "kopia/workload.rs"]
mod workload;
#[cfg(feature = "containers")]
use budgets::{regression_budgets_json, value_f64_at};
#[cfg(feature = "containers")]
use measurement::{
    RunningStorageProxy, aggregate_runs, compare_runs, endpoint_authority,
    gateway_backend_metrics_json, gateway_client_metrics_json, measurement_json, now_millis,
    prometheus_metrics_delta_json, scrape_prometheus_metrics, wait_for_storage_proxy_metrics,
    workload_consistency_json,
};
#[cfg(feature = "containers")]
use std::collections::BTreeMap;
#[cfg(feature = "containers")]
use std::ffi::{OsStr, OsString};
#[cfg(feature = "containers")]
use std::fs;
#[cfg(feature = "containers")]
use std::path::Path;
use std::path::PathBuf;
#[cfg(feature = "containers")]
use std::process::{Command, Stdio};
#[cfg(feature = "containers")]
use std::time::{Duration, Instant};
use workload::KopiaWorkloadProfile;
#[cfg(feature = "containers")]
use workload::KopiaWorkspace;

#[cfg(feature = "containers")]
const KOPIA_PASSWORD: &str = "rs3-local-integration-password";

#[derive(Debug, Args)]
pub(crate) struct KopiaGatewayArgs {
    /// Backend mode for the gateway under test.
    #[arg(long, value_enum, default_value_t = KopiaGatewayMode::Container)]
    mode: KopiaGatewayMode,
    /// Container provider used as the gateway backend.
    #[arg(long, value_enum, default_value_t = S3ContainerProvider::Rustfs)]
    container_provider: S3ContainerProvider,
    /// Existing backend bucket. If omitted, a temporary bucket is created.
    #[arg(long, env = "RS3_TEST_S3_BUCKET")]
    backend_bucket: Option<String>,
    /// Backend S3 signing region.
    #[arg(long, env = "RS3_TEST_S3_REGION")]
    region: Option<String>,
    /// Provided S3-compatible endpoint URL used with `--mode provided`.
    #[arg(long, env = "RS3_TEST_S3_ENDPOINT_URL")]
    endpoint_url: Option<String>,
    /// Backend prefix for repository-owned objects.
    #[arg(long, env = "RS3_TEST_S3_PREFIX", default_value = "rs3-kopia")]
    backend_prefix: String,
    /// Kopia executable to run.
    #[arg(long, env = "RS3_TEST_KOPIA_BIN", default_value = "kopia")]
    kopia_bin: String,
    /// Repository format used by the gateway process.
    #[arg(long, env = "RS3_REPOSITORY_FORMAT", value_enum, default_value_t = KopiaGatewayRepositoryFormat::V2Preview)]
    repository_format: KopiaGatewayRepositoryFormat,
    /// Repository retention mode for repository-owned backend objects.
    #[arg(long, env = "RS3_REPOSITORY_RETENTION_MODE", value_enum)]
    retention_mode: Option<KopiaGatewayRetentionMode>,
    /// Repository retention duration in days.
    #[arg(long, env = "RS3_REPOSITORY_RETENTION_DAYS")]
    retention_days: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum KopiaGatewayMode {
    /// Start a disposable local S3-compatible backend.
    Container,
    /// Use an already provisioned S3-compatible backend.
    Provided,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum KopiaGatewayRepositoryFormat {
    /// v2 production-preview repository format.
    V2Preview,
}

#[cfg(feature = "containers")]
impl KopiaGatewayRepositoryFormat {
    const fn as_env(self) -> &'static str {
        match self {
            Self::V2Preview => "v2-preview",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum KopiaGatewayRetentionMode {
    Governance,
    Compliance,
}

#[cfg(feature = "containers")]
impl KopiaGatewayRetentionMode {
    const fn as_env(self) -> &'static str {
        match self {
            Self::Governance => "governance",
            Self::Compliance => "compliance",
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct KopiaMatrixArgs {
    /// Container provider used as the gateway backend.
    #[arg(long, value_enum, default_value_t = S3ContainerProvider::Rustfs)]
    container_provider: S3ContainerProvider,
    /// Existing backend bucket. If omitted, a temporary bucket is created.
    #[arg(long, env = "RS3_TEST_S3_BUCKET")]
    backend_bucket: Option<String>,
    /// Backend S3 signing region.
    #[arg(long, env = "RS3_TEST_S3_REGION")]
    region: Option<String>,
    /// Backend prefix for repository-owned objects.
    #[arg(long, env = "RS3_TEST_S3_PREFIX", default_value = "rs3-kopia-matrix")]
    backend_prefix: String,
    /// Kopia executable to run.
    #[arg(long, env = "RS3_TEST_KOPIA_BIN", default_value = "kopia")]
    kopia_bin: String,
    /// Workload shape to snapshot and restore.
    #[arg(long, value_enum, default_value_t = KopiaWorkloadProfile::SmallSmoke)]
    workload_profile: KopiaWorkloadProfile,
    /// Named set of workload profiles to run.
    #[arg(long, value_enum, default_value_t = KopiaMatrixProfileSet::Single)]
    profile_set: KopiaMatrixProfileSet,
    /// Number of direct/gateway run pairs to execute.
    #[arg(long, default_value_t = 1)]
    runs: usize,
    /// Directory where the matrix summary JSON is written.
    #[arg(long, env = "RS3_TEST_ARTIFACT_DIR")]
    artifact_dir: Option<PathBuf>,
    /// Cargo profile used for the gateway process under measurement.
    #[cfg(feature = "containers")]
    #[arg(long, value_enum, default_value_t = GatewayBuildProfile::Release)]
    gateway_build_profile: GatewayBuildProfile,
    /// Force a fixed gateway payload segment size. Omit to use adaptive per-object sizing.
    #[arg(long)]
    payload_segment_size: Option<usize>,
    /// Override gateway commit batch size for measured gateway runs.
    #[arg(long)]
    commit_batch_items: Option<usize>,
    /// Override gateway commit batch delay in milliseconds for measured gateway runs.
    #[arg(long)]
    commit_batch_delay_ms: Option<u64>,
    /// Override gateway commit pending-item backpressure limit for measured gateway runs.
    #[arg(long)]
    commit_max_pending_items: Option<usize>,
    /// Fail the command when built-in comparison budgets are exceeded.
    #[arg(long)]
    enforce_regression_budgets: bool,
    /// Print the full summary JSON to stdout instead of the compact table.
    #[arg(long)]
    print_summary_json: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum KopiaMatrixProfileSet {
    /// Run only `--workload-profile`.
    Single,
    /// Run larger restore profiles shaped like Kubernetes and Postgres backups.
    LargerRestores,
}

impl KopiaMatrixProfileSet {
    #[cfg(feature = "containers")]
    fn as_str(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::LargerRestores => "larger-restores",
        }
    }

    #[cfg(any(feature = "containers", test))]
    fn profiles(self, single: KopiaWorkloadProfile) -> Vec<KopiaWorkloadProfile> {
        match self {
            Self::Single => vec![single],
            Self::LargerRestores => vec![
                KopiaWorkloadProfile::MediumRestore,
                KopiaWorkloadProfile::KubernetesObjects,
                KopiaWorkloadProfile::KubernetesObjectsLarge,
                KopiaWorkloadProfile::PostgresPgdata,
                KopiaWorkloadProfile::PostgresPgdataLarge,
            ],
        }
    }
}

#[cfg(any(feature = "containers", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MatrixStoragePath {
    DirectRustfs,
    Gateway,
}

#[cfg(any(feature = "containers", test))]
impl MatrixStoragePath {
    fn as_str(self) -> &'static str {
        match self {
            Self::DirectRustfs => "direct-rustfs",
            Self::Gateway => "gateway",
        }
    }
}

#[cfg(any(feature = "containers", test))]
fn measured_run_order(run_index: usize) -> [MatrixStoragePath; 2] {
    if run_index.is_multiple_of(2) {
        [MatrixStoragePath::Gateway, MatrixStoragePath::DirectRustfs]
    } else {
        [MatrixStoragePath::DirectRustfs, MatrixStoragePath::Gateway]
    }
}

#[cfg(not(feature = "containers"))]
pub(crate) fn run_kopia_gateway(args: KopiaGatewayArgs) -> Result<()> {
    anyhow::bail!(
        "Kopia gateway integration for {:?} requires `cargo run -p xtask --bin xtask --features containers -- integration kopia-gateway`",
        args.container_provider,
    )
}

#[cfg(not(feature = "containers"))]
pub(crate) fn run_kopia_measured_matrix(args: KopiaMatrixArgs) -> Result<()> {
    anyhow::bail!(
        "Kopia measured matrix integration for {:?} requires `cargo run -p xtask --bin xtask --features containers -- integration kopia-measured-matrix`",
        args.container_provider,
    )
}

#[cfg(feature = "containers")]
pub(crate) fn run_kopia_gateway(args: KopiaGatewayArgs) -> Result<()> {
    validate_kopia_gateway_args(&args)?;
    let kopia_bin = args.kopia_bin.clone();
    let backend_prefix = args.backend_prefix.clone();
    let process_options = kopia_gateway_process_options(&args);
    let mut container_backend = None;
    let backend = match args.mode {
        KopiaGatewayMode::Container => {
            let running = s3_container::start_s3_container_with_options(
                args.container_provider,
                args.backend_bucket,
                args.region,
                s3_container::S3ContainerOptions {
                    object_lock: args.retention_mode.is_some(),
                },
            )?;
            let backend = GatewayBackend::from_container(&running);
            container_backend = Some(running);
            backend
        }
        KopiaGatewayMode::Provided => provided_gateway_backend(&args)?,
    };
    let workspace = KopiaWorkspace::new()?;
    workspace.populate_source(KopiaWorkloadProfile::SmallSmoke)?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build Kopia integration runtime")?;

    let container_backend_guard = container_backend;
    let result = runtime.block_on(async {
        let mut gateway = RunningGateway::start_for_backend_with_options(
            &backend,
            backend_prefix,
            process_options,
        )
        .await?;
        let target = KopiaS3Target {
            bucket: PUBLIC_BUCKET.to_owned(),
            endpoint_authority: gateway.endpoint_authority(),
            access_key_id: ACCESS_KEY_ID.to_owned(),
            secret_access_key: SECRET_ACCESS_KEY.to_owned(),
            region: backend.region.clone(),
            prefix: "kopia/".to_owned(),
        };
        let result = run_kopia_smoke(
            &kopia_bin,
            &workspace,
            &target,
            KopiaWorkloadProfile::SmallSmoke,
        );
        let shutdown = gateway.shutdown();

        result?;
        shutdown?;
        Ok(())
    });
    drop(container_backend_guard);
    result
}

#[cfg(feature = "containers")]
fn validate_kopia_gateway_args(args: &KopiaGatewayArgs) -> Result<()> {
    if args.retention_mode.is_some() && args.retention_days.is_none() {
        bail!("--retention-days is required when --retention-mode is set");
    }
    if args.retention_days.is_some() && args.retention_mode.is_none() {
        bail!("--retention-mode is required when --retention-days is set");
    }
    Ok(())
}

#[cfg(feature = "containers")]
fn kopia_gateway_process_options(args: &KopiaGatewayArgs) -> GatewayProcessOptions {
    GatewayProcessOptions {
        repository_format: Some(args.repository_format.as_env()),
        repository_retention_mode: args.retention_mode.map(KopiaGatewayRetentionMode::as_env),
        repository_retention_days: args.retention_days,
        ..GatewayProcessOptions::default()
    }
}

#[cfg(feature = "containers")]
fn provided_gateway_backend(args: &KopiaGatewayArgs) -> Result<GatewayBackend> {
    let endpoint_url = args
        .endpoint_url
        .clone()
        .context("--endpoint-url or RS3_TEST_S3_ENDPOINT_URL is required with --mode provided")?;
    let bucket = args
        .backend_bucket
        .clone()
        .context("--backend-bucket or RS3_TEST_S3_BUCKET is required with --mode provided")?;
    let region = args
        .region
        .clone()
        .unwrap_or_else(|| "us-east-1".to_owned());
    let access_key_id = std::env::var("AWS_ACCESS_KEY_ID")
        .context("AWS_ACCESS_KEY_ID is required with --mode provided")?;
    let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY")
        .context("AWS_SECRET_ACCESS_KEY is required with --mode provided")?;

    Ok(GatewayBackend {
        endpoint_url,
        bucket,
        region,
        access_key_id,
        secret_access_key,
    })
}

#[cfg(feature = "containers")]
pub(crate) fn run_kopia_measured_matrix(args: KopiaMatrixArgs) -> Result<()> {
    if args.runs == 0 {
        bail!("--runs must be at least 1");
    }
    if args.payload_segment_size == Some(0) {
        bail!("--payload-segment-size must be greater than zero");
    }
    if args.commit_batch_items == Some(0) {
        bail!("--commit-batch-items must be greater than zero");
    }
    if args.commit_max_pending_items == Some(0) {
        bail!("--commit-max-pending-items must be greater than zero");
    }
    let run_id = now_millis();
    let backend_prefix = args.backend_prefix.trim_end_matches('/').to_owned();
    let profiles = args.profile_set.profiles(args.workload_profile);
    let artifact_dir = args.artifact_dir.clone().unwrap_or_else(|| {
        PathBuf::from(".local")
            .join("integration")
            .join(format!("kopia-measured-matrix-{run_id}"))
    });
    fs::create_dir_all(&artifact_dir)
        .with_context(|| format!("failed to create {}", artifact_dir.display()))?;

    let backend = s3_container::start_s3_container(
        args.container_provider,
        args.backend_bucket,
        args.region,
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build Kopia matrix runtime")?;

    let runs = runtime.block_on(async {
        let mut runs = Vec::with_capacity(args.runs.saturating_mul(profiles.len()));
        for profile in profiles.iter().copied() {
            for run_index in 1..=args.runs {
                let order = measured_run_order(run_index);
                let mut direct = None;
                let mut gateway = None;
                for storage_path in order {
                    match storage_path {
                        MatrixStoragePath::DirectRustfs => {
                            direct = Some(
                                run_measured_direct_kopia(
                                    &args.kopia_bin,
                                    &backend,
                                    &backend_prefix,
                                    run_id,
                                    run_index,
                                    profile,
                                )
                                .await?,
                            );
                        }
                        MatrixStoragePath::Gateway => {
                            gateway = Some(
                                run_measured_gateway_kopia(MeasuredGatewayRun {
                                    kopia_bin: &args.kopia_bin,
                                    backend: &backend,
                                    backend_prefix: &backend_prefix,
                                    run_id,
                                    run_index,
                                    profile,
                                    gateway_build_profile: args.gateway_build_profile,
                                    payload_segment_size: args.payload_segment_size,
                                    commit_batch_items: args.commit_batch_items,
                                    commit_batch_delay_ms: args.commit_batch_delay_ms,
                                    commit_max_pending_items: args.commit_max_pending_items,
                                })
                                .await?,
                            );
                        }
                    }
                }
                let direct = direct.context("measured run did not produce a direct report")?;
                let gateway = gateway.context("measured run did not produce a gateway report")?;
                runs.push(serde_json::json!({
                    "profile": profile.as_str(),
                    "run": run_index,
                    "run_order": order.map(MatrixStoragePath::as_str).to_vec(),
                    "reports": [direct, gateway],
                }));
            }
        }
        Ok::<_, anyhow::Error>(runs)
    })?;

    let aggregate = aggregate_runs(&runs);
    let comparison = compare_runs(&runs);
    let profiles_summary = profile_summaries(&runs);
    let workload_consistency = workload_consistency_json(&runs);
    let regression_budgets = regression_budgets_json(&profiles_summary, args.payload_segment_size);

    let summary = serde_json::json!({
        "scenario": "kopia-measured-matrix",
        "run_id": run_id,
        "runs": args.runs,
        "run_pairs_per_profile": args.runs,
        "total_run_pairs": runs.len(),
        "profile_set": args.profile_set.as_str(),
        "workload_profile": args.workload_profile.as_str(),
        "workload_profiles": profiles.iter().map(|profile| profile.as_str()).collect::<Vec<_>>(),
        "backend_provider": args.container_provider.as_label(),
        "backend_bucket": backend.bucket,
        "backend_region": backend.region,
        "gateway_build_profile": args.gateway_build_profile.as_str(),
        "payload_segment_size": args.payload_segment_size,
        "adaptive_payload_segment_size": args.payload_segment_size.is_none(),
        "commit_batch": {
            "max_items": args.commit_batch_items,
            "max_delay_ms": args.commit_batch_delay_ms,
            "max_pending_items": args.commit_max_pending_items,
        },
        "aggregate": aggregate,
        "comparison": comparison,
        "profiles": profiles_summary,
        "workload_consistency": workload_consistency,
        "regression_budgets": regression_budgets,
        "run_reports": runs,
    });
    let multi_profile = profiles.len() > 1;
    for run in summary["run_reports"]
        .as_array()
        .context("summary run_reports was not an array")?
    {
        let run_index = run["run"]
            .as_u64()
            .context("run report did not include numeric run index")?;
        let file_name = if multi_profile {
            let profile = run["profile"]
                .as_str()
                .context("run report did not include profile")?;
            format!("{profile}-run-{run_index:03}.json")
        } else {
            format!("run-{run_index:03}.json")
        };
        write_json_file(&artifact_dir.join(file_name), run)?;
    }
    let summary_path = artifact_dir.join("summary.json");
    write_json_file(&summary_path, &summary)?;
    eprintln!(
        "wrote Kopia measured matrix summary to {}",
        summary_path.display()
    );
    if args.print_summary_json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        print_matrix_summary(&summary, &profiles);
    }
    if args.enforce_regression_budgets {
        let failed = check_failure_count(&summary["regression_budgets"])
            + check_failure_count(&summary["workload_consistency"]);
        if failed > 0 {
            bail!(
                "Kopia measured matrix exceeded {failed} regression or consistency check(s); summary written to {}",
                summary_path.display()
            );
        }
    }
    Ok(())
}

#[cfg(feature = "containers")]
fn profile_summaries(runs: &[serde_json::Value]) -> serde_json::Value {
    let mut runs_by_profile: BTreeMap<String, Vec<serde_json::Value>> = BTreeMap::new();
    for run in runs {
        let Some(profile) = run.get("profile").and_then(serde_json::Value::as_str) else {
            continue;
        };
        runs_by_profile
            .entry(profile.to_owned())
            .or_default()
            .push(run.clone());
    }

    serde_json::Value::Object(
        runs_by_profile
            .into_iter()
            .map(|(profile, runs)| {
                (
                    profile,
                    serde_json::json!({
                        "runs": runs.len(),
                        "aggregate": aggregate_runs(&runs),
                        "comparison": compare_runs(&runs),
                    }),
                )
            })
            .collect(),
    )
}

#[cfg(feature = "containers")]
fn check_failure_count(check_report: &serde_json::Value) -> usize {
    check_report
        .get("checks")
        .and_then(serde_json::Value::as_array)
        .map(|checks| {
            checks
                .iter()
                .filter(|check| {
                    check.get("status").and_then(serde_json::Value::as_str) == Some("fail")
                })
                .count()
        })
        .unwrap_or(1)
}

#[cfg(feature = "containers")]
fn print_matrix_summary(summary: &serde_json::Value, profiles: &[KopiaWorkloadProfile]) {
    println!(
        "profile\tbackend_requests\tbackend_reads\tbackend_writes\trestore_elapsed\tstage_lock_wait\tcheckpoint_wait"
    );
    for profile in profiles {
        let profile_summary = &summary["profiles"][profile.as_str()];
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            profile.as_str(),
            format_ratio(value_f64_at(
                profile_summary,
                &[
                    "comparison",
                    "gateway_vs_direct",
                    "backend_request_count_ratio",
                    "avg"
                ],
            )),
            format_ratio(value_f64_at(
                profile_summary,
                &[
                    "comparison",
                    "gateway_vs_direct",
                    "backend_read_bytes_ratio",
                    "avg"
                ],
            )),
            format_ratio(value_f64_at(
                profile_summary,
                &[
                    "comparison",
                    "gateway_vs_direct",
                    "backend_write_bytes_ratio",
                    "avg"
                ],
            )),
            format_ratio(value_f64_at(
                profile_summary,
                &[
                    "comparison",
                    "gateway_vs_direct",
                    "phase_elapsed_ms_ratio",
                    "restore",
                    "avg"
                ],
            )),
            format_seconds(value_f64_at(
                profile_summary,
                &[
                    "comparison",
                    "gateway_internal",
                    "commit_put_phase_avg_seconds",
                    "stage_lock_wait",
                    "avg"
                ],
            )),
            format_seconds(value_f64_at(
                profile_summary,
                &[
                    "comparison",
                    "gateway_internal",
                    "commit_put_phase_avg_seconds",
                    "checkpoint_wait",
                    "avg"
                ],
            )),
        );
    }
    println!(
        "regression_budgets\tstatus={}\tfailed={}",
        summary_status(&summary["regression_budgets"]),
        summary_failed(&summary["regression_budgets"]),
    );
    println!(
        "workload_consistency\tstatus={}\tfailed={}",
        summary_status(&summary["workload_consistency"]),
        summary_failed(&summary["workload_consistency"]),
    );
}

#[cfg(feature = "containers")]
fn format_ratio(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.2}x"))
        .unwrap_or_else(|| "n/a".to_owned())
}

#[cfg(feature = "containers")]
fn format_seconds(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.3}s"))
        .unwrap_or_else(|| "n/a".to_owned())
}

#[cfg(feature = "containers")]
fn summary_status(value: &serde_json::Value) -> &str {
    value
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("missing")
}

#[cfg(feature = "containers")]
fn summary_failed(value: &serde_json::Value) -> u64 {
    value
        .get("failed")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(1)
}

#[cfg(feature = "containers")]
struct MeasuredGatewayRun<'a> {
    kopia_bin: &'a str,
    backend: &'a s3_container::RunningS3Container,
    backend_prefix: &'a str,
    run_id: u128,
    run_index: usize,
    profile: KopiaWorkloadProfile,
    gateway_build_profile: GatewayBuildProfile,
    payload_segment_size: Option<usize>,
    commit_batch_items: Option<usize>,
    commit_batch_delay_ms: Option<u64>,
    commit_max_pending_items: Option<usize>,
}

#[cfg(feature = "containers")]
async fn run_measured_gateway_kopia(args: MeasuredGatewayRun<'_>) -> Result<serde_json::Value> {
    let workspace = KopiaWorkspace::new()?;
    workspace.populate_source(args.profile)?;
    let mut gateway = RunningGateway::start_with_log_capture_options(
        args.backend,
        format!(
            "{}/{}/run-{run_index:03}/gateway-{run_id}",
            args.backend_prefix,
            args.profile.as_str(),
            run_index = args.run_index,
            run_id = args.run_id
        ),
        "rs3_storage=debug,rs3_repository=info,info",
        GatewayProcessOptions {
            build_profile: args.gateway_build_profile,
            payload_segment_size: args.payload_segment_size,
            commit_batch_items: args.commit_batch_items,
            commit_batch_delay_ms: args.commit_batch_delay_ms,
            commit_max_pending_items: args.commit_max_pending_items,
            ..GatewayProcessOptions::default()
        },
    )
    .await?;
    gateway.clear_captured_logs()?;
    let metrics_authority = gateway
        .metrics_endpoint_authority()
        .context("gateway metrics endpoint was not enabled for measured run")?;
    let prometheus_before = scrape_prometheus_metrics(&metrics_authority).await?;
    let target = KopiaS3Target {
        bucket: PUBLIC_BUCKET.to_owned(),
        endpoint_authority: gateway.endpoint_authority(),
        access_key_id: ACCESS_KEY_ID.to_owned(),
        secret_access_key: SECRET_ACCESS_KEY.to_owned(),
        region: args.backend.region.clone(),
        prefix: "kopia/".to_owned(),
    };
    let stats = run_kopia_smoke(args.kopia_bin, &workspace, &target, args.profile);
    std::thread::sleep(Duration::from_millis(100));
    let prometheus_after = scrape_prometheus_metrics(&metrics_authority).await?;
    let logs = gateway.captured_logs()?;
    let process_metrics = gateway.process_metrics_json();
    let shutdown = gateway.shutdown();
    let stats = stats?;
    shutdown?;
    let mut report = measurement_json("gateway", stats, gateway_backend_metrics_json(&logs));
    report["client_metrics"] = gateway_client_metrics_json(&logs);
    report["prometheus_metrics"] =
        prometheus_metrics_delta_json(&prometheus_before, &prometheus_after);
    report["gateway_process"] = process_metrics;
    Ok(report)
}

#[cfg(feature = "containers")]
async fn run_measured_direct_kopia(
    kopia_bin: &str,
    backend: &s3_container::RunningS3Container,
    backend_prefix: &str,
    run_id: u128,
    run_index: usize,
    profile: KopiaWorkloadProfile,
) -> Result<serde_json::Value> {
    let workspace = KopiaWorkspace::new()?;
    workspace.populate_source(profile)?;
    let target_authority = endpoint_authority(&backend.endpoint_url)?;
    let mut proxy = RunningStorageProxy::start(&target_authority).await?;
    proxy.clear_logs()?;
    let target = KopiaS3Target {
        bucket: backend.bucket.clone(),
        endpoint_authority: proxy.endpoint_authority(),
        access_key_id: backend.access_key_id.clone(),
        secret_access_key: backend.secret_access_key.clone(),
        region: backend.region.clone(),
        prefix: format!(
            "{}/{}/run-{run_index:03}/direct-{run_id}/kopia/",
            backend_prefix,
            profile.as_str()
        ),
    };
    let stats = run_kopia_smoke(kopia_bin, &workspace, &target, profile);
    if stats.is_ok() {
        proxy.clear_logs()?;
    }
    let metrics = wait_for_storage_proxy_metrics(&proxy);
    let shutdown = proxy.shutdown();
    let stats = stats?;
    let metrics = metrics?;
    shutdown?;
    Ok(measurement_json("direct-rustfs", stats, metrics))
}

#[cfg(feature = "containers")]
fn run_kopia_smoke(
    kopia_bin: &str,
    workspace: &KopiaWorkspace,
    target: &KopiaS3Target,
    profile: KopiaWorkloadProfile,
) -> Result<KopiaRunStats> {
    require_kopia(kopia_bin)?;
    let started = Instant::now();
    let mut phases = Vec::new();

    phases.push(run_kopia_phase(
        kopia_bin,
        workspace,
        "repository-create",
        vec![
            os("repository"),
            os("create"),
            os("s3"),
            os("--bucket"),
            os(&target.bucket),
            os("--endpoint"),
            os(&target.endpoint_authority),
            os("--access-key"),
            os(&target.access_key_id),
            os("--secret-access-key"),
            os(&target.secret_access_key),
            os("--region"),
            os(&target.region),
            os("--disable-tls"),
            os("--prefix"),
            os(&target.prefix),
            os("--cache-directory"),
            workspace.cache_dir().into_os_string(),
            os("--override-hostname"),
            os("rs3-integration"),
            os("--override-username"),
            os("rs3"),
        ],
    )?);

    phases.push(run_kopia_phase(
        kopia_bin,
        workspace,
        "snapshot-create",
        vec![
            os("snapshot"),
            os("create"),
            workspace.source_dir().into_os_string(),
        ],
    )?);

    if matches!(profile, KopiaWorkloadProfile::ChangedSnapshot) {
        phases.push(run_local_phase("mutate-source", || {
            workspace.mutate_source_for_second_snapshot()
        })?);
        phases.push(run_kopia_phase(
            kopia_bin,
            workspace,
            "snapshot-create-after-change",
            vec![
                os("snapshot"),
                os("create"),
                workspace.source_dir().into_os_string(),
            ],
        )?);
    }

    let source_tree = workspace.source_tree_stats()?;
    phases.push(run_kopia_phase(
        kopia_bin,
        workspace,
        "restore",
        vec![
            os("restore"),
            workspace.source_dir().into_os_string(),
            workspace.restore_dir().into_os_string(),
        ],
    )?);

    phases.push(run_local_phase("assert-restored", || {
        workspace.assert_restored()
    })?);
    let restored_tree = workspace.restore_tree_stats()?;
    Ok(KopiaRunStats {
        elapsed: started.elapsed(),
        phases,
        source_tree,
        restored_tree,
    })
}

#[cfg(feature = "containers")]
struct KopiaS3Target {
    bucket: String,
    endpoint_authority: String,
    access_key_id: String,
    secret_access_key: String,
    region: String,
    prefix: String,
}

#[cfg(feature = "containers")]
struct KopiaRunStats {
    elapsed: Duration,
    phases: Vec<KopiaPhaseTiming>,
    source_tree: workload::KopiaTreeStats,
    restored_tree: workload::KopiaTreeStats,
}

#[cfg(feature = "containers")]
struct KopiaPhaseTiming {
    name: &'static str,
    elapsed: Duration,
}

#[cfg(feature = "containers")]
fn run_kopia_phase(
    kopia_bin: &str,
    workspace: &KopiaWorkspace,
    name: &'static str,
    command_args: Vec<OsString>,
) -> Result<KopiaPhaseTiming> {
    run_local_phase(name, || run_kopia(kopia_bin, workspace, command_args))
}

#[cfg(feature = "containers")]
fn run_local_phase(
    name: &'static str,
    phase: impl FnOnce() -> Result<()>,
) -> Result<KopiaPhaseTiming> {
    let started = Instant::now();
    phase()?;
    Ok(KopiaPhaseTiming {
        name,
        elapsed: started.elapsed(),
    })
}

#[cfg(feature = "containers")]
fn require_kopia(kopia_bin: &str) -> Result<()> {
    let status = Command::new(kopia_bin)
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| {
            format!("failed to start `{kopia_bin}`; install Kopia or set --kopia-bin")
        })?;

    if status.success() {
        Ok(())
    } else {
        bail!("`{kopia_bin} --help` exited with {status}");
    }
}

#[cfg(feature = "containers")]
fn run_kopia(
    kopia_bin: &str,
    workspace: &KopiaWorkspace,
    command_args: Vec<OsString>,
) -> Result<()> {
    let mut command = Command::new(kopia_bin);
    command
        .arg("--config-file")
        .arg(workspace.config_file())
        .arg("--password")
        .arg(KOPIA_PASSWORD)
        .arg("--no-progress")
        .arg("--log-level")
        .arg("warning")
        .arg("--no-use-keyring");
    command.args(command_args);

    let output = command
        .output()
        .with_context(|| format!("failed to start `{kopia_bin}`"))?;

    if output.status.success() {
        return Ok(());
    }

    bail!(
        "`{}` exited with {}\nstdout:\n{}\nstderr:\n{}",
        kopia_bin,
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[cfg(feature = "containers")]
fn os(value: impl AsRef<OsStr>) -> OsString {
    value.as_ref().to_owned()
}

#[cfg(feature = "containers")]
fn write_json_file(path: &Path, value: &serde_json::Value) -> Result<()> {
    fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))
        .with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::{
        KopiaMatrixProfileSet, KopiaWorkloadProfile, MatrixStoragePath, measured_run_order,
    };

    #[test]
    fn larger_restore_profile_set_has_stable_order() {
        assert_eq!(
            KopiaMatrixProfileSet::LargerRestores
                .profiles(KopiaWorkloadProfile::SmallSmoke)
                .into_iter()
                .map(KopiaWorkloadProfile::as_str)
                .collect::<Vec<_>>(),
            vec![
                "medium-restore",
                "kubernetes-objects",
                "kubernetes-objects-large",
                "postgres-pgdata",
                "postgres-pgdata-large",
            ]
        );
    }

    #[test]
    fn single_profile_set_preserves_selected_profile() {
        assert_eq!(
            KopiaMatrixProfileSet::Single.profiles(KopiaWorkloadProfile::ManySmallFiles),
            vec![KopiaWorkloadProfile::ManySmallFiles]
        );
    }

    #[test]
    fn measured_matrix_alternates_storage_path_order() {
        assert_eq!(
            measured_run_order(1),
            [MatrixStoragePath::DirectRustfs, MatrixStoragePath::Gateway]
        );
        assert_eq!(
            measured_run_order(2),
            [MatrixStoragePath::Gateway, MatrixStoragePath::DirectRustfs]
        );
        assert_eq!(MatrixStoragePath::Gateway.as_str(), "gateway");
        assert_eq!(MatrixStoragePath::DirectRustfs.as_str(), "direct-rustfs");
    }

    #[cfg(feature = "containers")]
    #[test]
    fn matrix_summary_formats_ratios_compactly() {
        assert_eq!(super::format_ratio(Some(1.234)), "1.23x");
        assert_eq!(super::format_ratio(None), "n/a");
        assert_eq!(super::format_seconds(Some(0.1234)), "0.123s");
        assert_eq!(super::format_seconds(None), "n/a");
    }
}
