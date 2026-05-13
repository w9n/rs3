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
#[cfg(feature = "containers")]
#[path = "kopia/measurement.rs"]
mod measurement;
#[path = "kopia/workload.rs"]
mod workload;
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum KopiaGatewayMode {
    /// Start a disposable local S3-compatible backend.
    Container,
    /// Use an already provisioned S3-compatible backend.
    Provided,
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
    let kopia_bin = args.kopia_bin.clone();
    let backend_prefix = args.backend_prefix.clone();
    let mut container_backend = None;
    let backend = match args.mode {
        KopiaGatewayMode::Container => {
            let running = s3_container::start_s3_container(
                args.container_provider,
                args.backend_bucket,
                args.region,
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
        let mut gateway = RunningGateway::start_for_backend(&backend, backend_prefix).await?;
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

#[cfg(any(feature = "containers", test))]
fn regression_budgets_json(
    profile_summaries: &serde_json::Value,
    payload_segment_size: Option<usize>,
) -> serde_json::Value {
    let mut checks = Vec::new();
    let Some(profiles) = profile_summaries.as_object() else {
        return serde_json::json!({
            "status": "missing",
            "failed": 1,
            "checks": [{
                "profile": "",
                "metric": "profiles",
                "operator": "present",
                "status": "fail",
                "reason": "profile summaries were not an object",
            }],
        });
    };

    for (profile, summary) in profiles {
        add_common_budget_checks(profile, summary, &mut checks);
        match profile.as_str() {
            "many-small-files"
                if payload_segment_size.unwrap_or(rs3_repository::DEFAULT_PAYLOAD_SEGMENT_SIZE)
                    <= 512 =>
            {
                push_max_budget(
                    &mut checks,
                    profile,
                    summary,
                    "gateway_vs_direct.backend_request_count_ratio",
                    &[
                        "comparison",
                        "gateway_vs_direct",
                        "backend_request_count_ratio",
                        "avg",
                    ],
                    0.50,
                );
                push_max_budget(
                    &mut checks,
                    profile,
                    summary,
                    "gateway_vs_direct.backend_read_bytes_ratio",
                    &[
                        "comparison",
                        "gateway_vs_direct",
                        "backend_read_bytes_ratio",
                        "avg",
                    ],
                    2.00,
                );
                push_max_budget(
                    &mut checks,
                    profile,
                    summary,
                    "gateway_vs_direct.backend_write_bytes_ratio",
                    &[
                        "comparison",
                        "gateway_vs_direct",
                        "backend_write_bytes_ratio",
                        "avg",
                    ],
                    2.25,
                );
                push_min_budget(
                    &mut checks,
                    profile,
                    summary,
                    "gateway_internal.payload_span_cache_event_hit_ratio",
                    &[
                        "comparison",
                        "gateway_internal",
                        "payload_span_cache_event_hit_ratio",
                        "avg",
                    ],
                    0.70,
                );
            }
            _ => {}
        }
    }

    let failed = checks
        .iter()
        .filter(|check| check.get("status").and_then(serde_json::Value::as_str) == Some("fail"))
        .count();

    serde_json::json!({
        "status": if failed == 0 { "pass" } else { "fail" },
        "failed": failed,
        "checks": checks,
    })
}

#[cfg(any(feature = "containers", test))]
fn add_common_budget_checks(
    profile: &str,
    summary: &serde_json::Value,
    checks: &mut Vec<serde_json::Value>,
) {
    match profile {
        "small-smoke" | "changed-snapshot" => {
            push_max_budget(
                checks,
                profile,
                summary,
                "gateway_vs_direct.backend_request_count_ratio",
                &[
                    "comparison",
                    "gateway_vs_direct",
                    "backend_request_count_ratio",
                    "avg",
                ],
                0.90,
            );
            push_max_budget(
                checks,
                profile,
                summary,
                "gateway_vs_direct.backend_read_bytes_ratio",
                &[
                    "comparison",
                    "gateway_vs_direct",
                    "backend_read_bytes_ratio",
                    "avg",
                ],
                1.10,
            );
            push_max_budget(
                checks,
                profile,
                summary,
                "gateway_vs_direct.backend_write_bytes_ratio",
                &[
                    "comparison",
                    "gateway_vs_direct",
                    "backend_write_bytes_ratio",
                    "avg",
                ],
                1.20,
            );
        }
        "medium-restore"
        | "kubernetes-objects"
        | "kubernetes-objects-large"
        | "postgres-pgdata"
        | "postgres-pgdata-large" => {
            push_max_budget(
                checks,
                profile,
                summary,
                "gateway_vs_direct.backend_request_count_ratio",
                &[
                    "comparison",
                    "gateway_vs_direct",
                    "backend_request_count_ratio",
                    "avg",
                ],
                1.20,
            );
            push_max_budget(
                checks,
                profile,
                summary,
                "gateway_vs_direct.backend_read_bytes_ratio",
                &[
                    "comparison",
                    "gateway_vs_direct",
                    "backend_read_bytes_ratio",
                    "avg",
                ],
                1.10,
            );
            push_max_budget(
                checks,
                profile,
                summary,
                "gateway_vs_direct.backend_write_bytes_ratio",
                &[
                    "comparison",
                    "gateway_vs_direct",
                    "backend_write_bytes_ratio",
                    "avg",
                ],
                1.10,
            );
            push_max_budget(
                checks,
                profile,
                summary,
                "gateway_vs_direct.phase_elapsed_ms_ratio.restore",
                &[
                    "comparison",
                    "gateway_vs_direct",
                    "phase_elapsed_ms_ratio",
                    "restore",
                    "avg",
                ],
                1.50,
            );
            push_max_budget(
                checks,
                profile,
                summary,
                "gateway_internal.backend_read_bytes_per_client_get_response_byte",
                &[
                    "comparison",
                    "gateway_internal",
                    "backend_read_bytes_per_client_get_response_byte",
                    "avg",
                ],
                1.10,
            );
            push_max_budget(
                checks,
                profile,
                summary,
                "gateway_internal.backend_write_bytes_per_client_put_request_byte",
                &[
                    "comparison",
                    "gateway_internal",
                    "backend_write_bytes_per_client_put_request_byte",
                    "avg",
                ],
                1.10,
            );
            push_optional_max_budget(
                checks,
                profile,
                summary,
                "gateway_vs_direct.backend_request_count_ratio.relative_stddev",
                &[
                    "comparison",
                    "gateway_vs_direct",
                    "backend_request_count_ratio",
                    "relative_stddev",
                ],
                0.05,
            );
            push_optional_max_budget(
                checks,
                profile,
                summary,
                "gateway_vs_direct.backend_read_bytes_ratio.relative_stddev",
                &[
                    "comparison",
                    "gateway_vs_direct",
                    "backend_read_bytes_ratio",
                    "relative_stddev",
                ],
                0.05,
            );
            push_optional_max_budget(
                checks,
                profile,
                summary,
                "gateway_internal.backend_read_bytes_per_client_get_response_byte.relative_stddev",
                &[
                    "comparison",
                    "gateway_internal",
                    "backend_read_bytes_per_client_get_response_byte",
                    "relative_stddev",
                ],
                0.05,
            );
            push_optional_max_budget(
                checks,
                profile,
                summary,
                "gateway_vs_direct.phase_elapsed_ms_ratio.restore.relative_stddev",
                &[
                    "comparison",
                    "gateway_vs_direct",
                    "phase_elapsed_ms_ratio",
                    "restore",
                    "relative_stddev",
                ],
                0.35,
            );
        }
        _ => {}
    }
}

#[cfg(any(feature = "containers", test))]
fn push_max_budget(
    checks: &mut Vec<serde_json::Value>,
    profile: &str,
    summary: &serde_json::Value,
    metric: &'static str,
    path: &[&str],
    limit: f64,
) {
    push_budget(checks, profile, summary, metric, path, "<=", limit);
}

#[cfg(any(feature = "containers", test))]
fn push_min_budget(
    checks: &mut Vec<serde_json::Value>,
    profile: &str,
    summary: &serde_json::Value,
    metric: &'static str,
    path: &[&str],
    limit: f64,
) {
    push_budget(checks, profile, summary, metric, path, ">=", limit);
}

#[cfg(any(feature = "containers", test))]
fn push_optional_max_budget(
    checks: &mut Vec<serde_json::Value>,
    profile: &str,
    summary: &serde_json::Value,
    metric: &'static str,
    path: &[&str],
    limit: f64,
) {
    let observed = value_f64_at(summary, path);
    let status = match observed {
        Some(observed) if observed <= limit => "pass",
        Some(_) => "fail",
        None => "skip",
    };
    checks.push(serde_json::json!({
        "profile": profile,
        "metric": metric,
        "operator": "<=",
        "limit": limit,
        "observed_avg": observed,
        "observed": observed,
        "status": status,
        "reason": if observed.is_none() {
            Some("metric unavailable")
        } else {
            None
        },
    }));
}

#[cfg(any(feature = "containers", test))]
fn push_budget(
    checks: &mut Vec<serde_json::Value>,
    profile: &str,
    summary: &serde_json::Value,
    metric: &'static str,
    path: &[&str],
    operator: &'static str,
    limit: f64,
) {
    let observed = value_f64_at(summary, path);
    let passed = match (operator, observed) {
        ("<=", Some(observed)) => observed <= limit,
        (">=", Some(observed)) => observed >= limit,
        _ => false,
    };
    checks.push(serde_json::json!({
        "profile": profile,
        "metric": metric,
        "operator": operator,
        "limit": limit,
        "observed_avg": observed,
        "observed": observed,
        "status": if observed.is_none() {
            "fail"
        } else if passed {
            "pass"
        } else {
            "fail"
        },
        "reason": if observed.is_none() {
            Some("metric unavailable")
        } else {
            None
        },
    }));
}

#[cfg(any(feature = "containers", test))]
fn value_f64_at(value: &serde_json::Value, path: &[&str]) -> Option<f64> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    current.as_f64()
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
        regression_budgets_json,
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

    #[test]
    fn larger_restore_budgets_pass_for_close_backend_ratios() {
        let profiles = serde_json::json!({
            "postgres-pgdata": {
                "comparison": {
                    "gateway_vs_direct": {
                        "backend_request_count_ratio": { "avg": 1.00 },
                        "backend_read_bytes_ratio": { "avg": 1.04 },
                        "backend_write_bytes_ratio": { "avg": 1.04 },
                        "phase_elapsed_ms_ratio": {
                            "restore": { "avg": 1.04 }
                        }
                    },
                    "gateway_internal": {
                        "backend_read_bytes_per_client_get_response_byte": { "avg": 1.04 },
                        "backend_write_bytes_per_client_put_request_byte": { "avg": 1.04 }
                    }
                }
            }
        });

        let budgets = regression_budgets_json(&profiles, Some(512));

        assert_eq!(budgets["status"], serde_json::json!("pass"));
        assert_eq!(budgets["failed"], serde_json::json!(0));
    }

    #[test]
    fn larger_restore_budgets_allow_checkpoint_evidence_request_overhead() {
        let profiles = serde_json::json!({
            "postgres-pgdata-large": {
                "comparison": {
                    "gateway_vs_direct": {
                        "backend_request_count_ratio": { "avg": 1.16 },
                        "backend_read_bytes_ratio": { "avg": 1.04 },
                        "backend_write_bytes_ratio": { "avg": 1.04 },
                        "phase_elapsed_ms_ratio": {
                            "restore": { "avg": 1.04 }
                        }
                    },
                    "gateway_internal": {
                        "backend_read_bytes_per_client_get_response_byte": { "avg": 1.04 },
                        "backend_write_bytes_per_client_put_request_byte": { "avg": 1.04 }
                    }
                }
            }
        });

        let budgets = regression_budgets_json(&profiles, Some(512));

        assert_eq!(budgets["status"], serde_json::json!("pass"));
        assert_eq!(budgets["failed"], serde_json::json!(0));
    }

    #[test]
    fn larger_restore_budgets_skip_stability_without_repeated_samples() {
        let profiles = serde_json::json!({
            "kubernetes-objects": {
                "comparison": {
                    "gateway_vs_direct": {
                        "backend_request_count_ratio": {
                            "avg": 1.00,
                            "relative_stddev": null
                        },
                        "backend_read_bytes_ratio": {
                            "avg": 1.04,
                            "relative_stddev": null
                        },
                        "backend_write_bytes_ratio": { "avg": 1.04 },
                        "phase_elapsed_ms_ratio": {
                            "restore": {
                                "avg": 1.04,
                                "relative_stddev": null
                            }
                        }
                    },
                    "gateway_internal": {
                        "backend_read_bytes_per_client_get_response_byte": {
                            "avg": 1.04,
                            "relative_stddev": null
                        },
                        "backend_write_bytes_per_client_put_request_byte": { "avg": 1.04 }
                    }
                }
            }
        });

        let budgets = regression_budgets_json(&profiles, Some(512));

        assert_eq!(budgets["status"], serde_json::json!("pass"));
        assert_eq!(budgets["failed"], serde_json::json!(0));
        assert!(
            budgets["checks"]
                .as_array()
                .unwrap_or_else(|| panic!("checks should be an array"))
                .iter()
                .any(|check| {
                    check["metric"]
                        == serde_json::json!(
                            "gateway_vs_direct.backend_read_bytes_ratio.relative_stddev"
                        )
                        && check["status"] == serde_json::json!("skip")
                })
        );
    }

    #[test]
    fn larger_restore_budgets_fail_unstable_repeated_metrics() {
        let profiles = serde_json::json!({
            "postgres-pgdata": {
                "comparison": {
                    "gateway_vs_direct": {
                        "backend_request_count_ratio": {
                            "avg": 1.00,
                            "relative_stddev": 0.01
                        },
                        "backend_read_bytes_ratio": {
                            "avg": 1.04,
                            "relative_stddev": 0.12
                        },
                        "backend_write_bytes_ratio": { "avg": 1.04 },
                        "phase_elapsed_ms_ratio": {
                            "restore": {
                                "avg": 1.04,
                                "relative_stddev": 0.10
                            }
                        }
                    },
                    "gateway_internal": {
                        "backend_read_bytes_per_client_get_response_byte": {
                            "avg": 1.04,
                            "relative_stddev": 0.02
                        },
                        "backend_write_bytes_per_client_put_request_byte": { "avg": 1.04 }
                    }
                }
            }
        });

        let budgets = regression_budgets_json(&profiles, Some(512));

        assert_eq!(budgets["status"], serde_json::json!("fail"));
        assert_eq!(budgets["failed"], serde_json::json!(1));
        assert!(
            budgets["checks"]
                .as_array()
                .unwrap_or_else(|| panic!("checks should be an array"))
                .iter()
                .any(|check| {
                    check["metric"]
                        == serde_json::json!(
                            "gateway_vs_direct.backend_read_bytes_ratio.relative_stddev"
                        )
                        && check["status"] == serde_json::json!("fail")
                })
        );
    }

    #[test]
    fn many_small_512_budget_fails_without_cache_hit_ratio() {
        let profiles = serde_json::json!({
            "many-small-files": {
                "comparison": {
                    "gateway_vs_direct": {
                        "backend_request_count_ratio": { "avg": 0.31 },
                        "backend_read_bytes_ratio": { "avg": 1.72 },
                        "backend_write_bytes_ratio": { "avg": 2.04 }
                    },
                    "gateway_internal": {
                        "payload_span_cache_event_hit_ratio": { "avg": 0.10 }
                    }
                }
            }
        });

        let budgets = regression_budgets_json(&profiles, Some(512));

        assert_eq!(budgets["status"], serde_json::json!("fail"));
        assert_eq!(budgets["failed"], serde_json::json!(1));
        assert_eq!(
            budgets["checks"][3]["metric"],
            serde_json::json!("gateway_internal.payload_span_cache_event_hit_ratio")
        );
    }
}
