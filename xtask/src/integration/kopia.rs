//! Kopia compatibility integration command.

use super::S3ContainerProvider;
#[cfg(feature = "containers")]
use super::gateway_process::{ACCESS_KEY_ID, PUBLIC_BUCKET, RunningGateway, SECRET_ACCESS_KEY};
#[cfg(feature = "containers")]
use super::s3_container;
use anyhow::Result;
#[cfg(feature = "containers")]
use anyhow::{Context, bail};
use clap::Args;
#[cfg(feature = "containers")]
#[path = "kopia/measurement.rs"]
mod measurement;
#[path = "kopia/workload.rs"]
mod workload;
#[cfg(feature = "containers")]
use measurement::{
    RunningStorageProxy, aggregate_runs, endpoint_authority, gateway_backend_metrics_json,
    measurement_json, now_millis, wait_for_storage_proxy_metrics,
};
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
    /// Number of direct/gateway run pairs to execute.
    #[arg(long, default_value_t = 1)]
    runs: usize,
    /// Directory where the matrix summary JSON is written.
    #[arg(long, env = "RS3_TEST_ARTIFACT_DIR")]
    artifact_dir: Option<PathBuf>,
}

#[cfg(not(feature = "containers"))]
pub(crate) fn run_kopia_gateway(args: KopiaGatewayArgs) -> Result<()> {
    anyhow::bail!(
        "Kopia gateway integration for {:?} requires `cargo run -p xtask --features containers -- integration kopia-gateway`",
        args.container_provider,
    )
}

#[cfg(not(feature = "containers"))]
pub(crate) fn run_kopia_measured_matrix(args: KopiaMatrixArgs) -> Result<()> {
    anyhow::bail!(
        "Kopia measured matrix integration for {:?} requires `cargo run -p xtask --features containers -- integration kopia-measured-matrix`",
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
    let run_id = now_millis();
    let backend_prefix = args.backend_prefix.trim_end_matches('/').to_owned();
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
        let mut runs = Vec::with_capacity(args.runs);
        for run_index in 1..=args.runs {
            let direct = run_measured_direct_kopia(
                &args.kopia_bin,
                &backend,
                &backend_prefix,
                run_id,
                run_index,
                args.workload_profile,
            )
            .await?;
            let gateway = run_measured_gateway_kopia(
                &args.kopia_bin,
                &backend,
                &backend_prefix,
                run_id,
                run_index,
                args.workload_profile,
            )
            .await?;
            runs.push(serde_json::json!({
                "run": run_index,
                "reports": [direct, gateway],
            }));
        }
        Ok::<_, anyhow::Error>(runs)
    })?;

    let summary = serde_json::json!({
        "scenario": "kopia-measured-matrix",
        "run_id": run_id,
        "runs": args.runs,
        "workload_profile": args.workload_profile.as_str(),
        "backend_provider": args.container_provider.as_label(),
        "backend_bucket": backend.bucket,
        "backend_region": backend.region,
        "aggregate": aggregate_runs(&runs),
        "run_reports": runs,
    });
    for run in summary["run_reports"]
        .as_array()
        .context("summary run_reports was not an array")?
    {
        let run_index = run["run"]
            .as_u64()
            .context("run report did not include numeric run index")?;
        write_json_file(&artifact_dir.join(format!("run-{run_index:03}.json")), run)?;
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
async fn run_measured_gateway_kopia(
    kopia_bin: &str,
    backend: &s3_container::RunningS3Container,
    backend_prefix: &str,
    run_id: u128,
    run_index: usize,
    profile: KopiaWorkloadProfile,
) -> Result<serde_json::Value> {
    let workspace = KopiaWorkspace::new()?;
    workspace.populate_source(profile)?;
    let mut gateway = RunningGateway::start_with_log_capture(
        backend,
        format!(
            "{}/{}/run-{run_index:03}/gateway-{run_id}",
            backend_prefix,
            profile.as_str()
        ),
        "rs3_storage=debug,rs3_repository=info,info",
    )
    .await?;
    gateway.clear_captured_logs()?;
    let target = KopiaS3Target {
        bucket: PUBLIC_BUCKET.to_owned(),
        endpoint_authority: gateway.endpoint_authority(),
        access_key_id: ACCESS_KEY_ID.to_owned(),
        secret_access_key: SECRET_ACCESS_KEY.to_owned(),
        region: backend.region.clone(),
        prefix: "kopia/".to_owned(),
    };
    let stats = run_kopia_smoke(kopia_bin, &workspace, &target, profile);
    std::thread::sleep(Duration::from_millis(100));
    let logs = gateway.captured_logs()?;
    let shutdown = gateway.shutdown();
    let stats = stats?;
    shutdown?;
    Ok(measurement_json(
        "gateway",
        stats,
        gateway_backend_metrics_json(&logs),
    ))
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
