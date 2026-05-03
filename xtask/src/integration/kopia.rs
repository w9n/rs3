//! Kopia compatibility integration command.

use super::S3ContainerProvider;
#[cfg(feature = "containers")]
use super::gateway_process::{
    ACCESS_KEY_ID, GatewayBuildProfile, GatewayProcessOptions, PUBLIC_BUCKET, RunningGateway,
    SECRET_ACCESS_KEY,
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
    #[arg(long, env = "RS3_TEST_S3_PREFIX", default_value = "rs3-kopia")]
    backend_prefix: String,
    /// Kopia executable to run.
    #[arg(long, env = "RS3_TEST_KOPIA_BIN", default_value = "kopia")]
    kopia_bin: String,
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
    /// Plaintext bytes per encrypted gateway payload segment.
    #[arg(long, default_value_t = rs3_repository::DEFAULT_PAYLOAD_SEGMENT_SIZE)]
    payload_segment_size: usize,
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
                KopiaWorkloadProfile::PostgresPgdata,
            ],
        }
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
    let kopia_bin = args.kopia_bin;
    let backend_prefix = args.backend_prefix;
    let backend = s3_container::start_s3_container(
        args.container_provider,
        args.backend_bucket,
        args.region,
    )?;
    let workspace = KopiaWorkspace::new()?;
    workspace.populate_source(KopiaWorkloadProfile::SmallSmoke)?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build Kopia integration runtime")?;

    runtime.block_on(async {
        let mut gateway = RunningGateway::start(&backend, backend_prefix).await?;
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
    })
}

#[cfg(feature = "containers")]
pub(crate) fn run_kopia_measured_matrix(args: KopiaMatrixArgs) -> Result<()> {
    if args.runs == 0 {
        bail!("--runs must be at least 1");
    }
    if args.payload_segment_size == 0 {
        bail!("--payload-segment-size must be greater than zero");
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
                let direct = run_measured_direct_kopia(
                    &args.kopia_bin,
                    &backend,
                    &backend_prefix,
                    run_id,
                    run_index,
                    profile,
                )
                .await?;
                let gateway = run_measured_gateway_kopia(MeasuredGatewayRun {
                    kopia_bin: &args.kopia_bin,
                    backend: &backend,
                    backend_prefix: &backend_prefix,
                    run_id,
                    run_index,
                    profile,
                    gateway_build_profile: args.gateway_build_profile,
                    payload_segment_size: args.payload_segment_size,
                })
                .await?;
                runs.push(serde_json::json!({
                    "profile": profile.as_str(),
                    "run": run_index,
                    "reports": [direct, gateway],
                }));
            }
        }
        Ok::<_, anyhow::Error>(runs)
    })?;

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
        "aggregate": aggregate_runs(&runs),
        "comparison": compare_runs(&runs),
        "profiles": profile_summaries(&runs),
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
    println!("{}", serde_json::to_string_pretty(&summary)?);
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
struct MeasuredGatewayRun<'a> {
    kopia_bin: &'a str,
    backend: &'a s3_container::RunningS3Container,
    backend_prefix: &'a str,
    run_id: u128,
    run_index: usize,
    profile: KopiaWorkloadProfile,
    gateway_build_profile: GatewayBuildProfile,
    payload_segment_size: usize,
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
            payload_segment_size: Some(args.payload_segment_size),
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
    let shutdown = gateway.shutdown();
    let stats = stats?;
    shutdown?;
    let mut report = measurement_json("gateway", stats, gateway_backend_metrics_json(&logs));
    report["client_metrics"] = gateway_client_metrics_json(&logs);
    report["prometheus_metrics"] =
        prometheus_metrics_delta_json(&prometheus_before, &prometheus_after);
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
    Ok(KopiaRunStats {
        elapsed: started.elapsed(),
        phases,
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
    use super::{KopiaMatrixProfileSet, KopiaWorkloadProfile};

    #[test]
    fn larger_restore_profile_set_has_stable_order() {
        assert_eq!(
            KopiaMatrixProfileSet::LargerRestores
                .profiles(KopiaWorkloadProfile::SmallSmoke)
                .into_iter()
                .map(KopiaWorkloadProfile::as_str)
                .collect::<Vec<_>>(),
            vec!["medium-restore", "kubernetes-objects", "postgres-pgdata"]
        );
    }

    #[test]
    fn single_profile_set_preserves_selected_profile() {
        assert_eq!(
            KopiaMatrixProfileSet::Single.profiles(KopiaWorkloadProfile::ManySmallFiles),
            vec![KopiaWorkloadProfile::ManySmallFiles]
        );
    }
}
