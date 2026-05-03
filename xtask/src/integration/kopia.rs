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
use std::ffi::{OsStr, OsString};
#[cfg(feature = "containers")]
use std::fs;
#[cfg(feature = "containers")]
use std::io::{BufRead, BufReader};
#[cfg(feature = "containers")]
use std::net::{SocketAddr, TcpListener};
#[cfg(feature = "containers")]
use std::path::Path;
use std::path::PathBuf;
#[cfg(feature = "containers")]
use std::process::{Command, Stdio};
#[cfg(feature = "containers")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "containers")]
use std::thread::JoinHandle;
#[cfg(feature = "containers")]
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[cfg(feature = "containers")]
use tokio::net::TcpStream;

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
    workspace.populate_source()?;

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
        let result = run_kopia_smoke(&kopia_bin, &workspace, &target);
        let shutdown = gateway.shutdown();

        result?;
        shutdown?;
        Ok(())
    })
}

#[cfg(feature = "containers")]
pub(crate) fn run_kopia_measured_matrix(args: KopiaMatrixArgs) -> Result<()> {
    let run_id = now_millis();
    let backend_prefix = args.backend_prefix.trim_end_matches('/').to_owned();
    let backend = s3_container::start_s3_container(
        args.container_provider,
        args.backend_bucket,
        args.region,
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build Kopia matrix runtime")?;

    let reports = runtime.block_on(async {
        let direct =
            run_measured_direct_kopia(&args.kopia_bin, &backend, &backend_prefix, run_id).await?;
        let gateway =
            run_measured_gateway_kopia(&args.kopia_bin, &backend, &backend_prefix, run_id).await?;
        Ok::<_, anyhow::Error>(vec![direct, gateway])
    })?;

    let summary = serde_json::json!({
        "scenario": "kopia-measured-matrix",
        "backend_provider": args.container_provider.as_label(),
        "backend_bucket": backend.bucket,
        "backend_region": backend.region,
        "reports": reports,
    });
    let artifact_dir = args.artifact_dir.unwrap_or_else(|| {
        PathBuf::from(".local")
            .join("integration")
            .join(format!("kopia-measured-matrix-{run_id}"))
    });
    fs::create_dir_all(&artifact_dir)
        .with_context(|| format!("failed to create {}", artifact_dir.display()))?;
    let summary_path = artifact_dir.join("summary.json");
    fs::write(
        &summary_path,
        format!("{}\n", serde_json::to_string_pretty(&summary)?),
    )
    .with_context(|| format!("failed to write {}", summary_path.display()))?;
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
) -> Result<serde_json::Value> {
    let workspace = KopiaWorkspace::new()?;
    workspace.populate_source()?;
    let mut gateway = RunningGateway::start_with_log_capture(
        backend,
        format!("{backend_prefix}/gateway-{run_id}"),
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
    let stats = run_kopia_smoke(kopia_bin, &workspace, &target);
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
) -> Result<serde_json::Value> {
    let workspace = KopiaWorkspace::new()?;
    workspace.populate_source()?;
    let target_authority = endpoint_authority(&backend.endpoint_url)?;
    let mut proxy = RunningStorageProxy::start(&target_authority).await?;
    proxy.clear_logs()?;
    let target = KopiaS3Target {
        bucket: backend.bucket.clone(),
        endpoint_authority: proxy.endpoint_authority(),
        access_key_id: backend.access_key_id.clone(),
        secret_access_key: backend.secret_access_key.clone(),
        region: backend.region.clone(),
        prefix: format!("{backend_prefix}/direct-{run_id}/kopia/"),
    };
    let stats = run_kopia_smoke(kopia_bin, &workspace, &target);
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
struct RunningStorageProxy {
    addr: SocketAddr,
    child: std::process::Child,
    logs: Arc<Mutex<Vec<String>>>,
    readers: Vec<JoinHandle<()>>,
}

#[cfg(feature = "containers")]
impl RunningStorageProxy {
    async fn start(target: &str) -> Result<Self> {
        let addr = reserve_proxy_addr()?;
        let bind = addr.to_string();
        let mut child = Command::new("cargo");
        child
            .args([
                "run",
                "-p",
                "rs3-server",
                "--features",
                "integration-tools",
                "--bin",
                "rs3-integration-storage-proxy",
                "--",
                "--bind",
                bind.as_str(),
                "--target",
                target,
                "--report-interval-secs",
                "1",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = child
            .spawn()
            .context("failed to start integration storage proxy")?;
        let stdout = child
            .stdout
            .take()
            .context("storage proxy stdout was not captured")?;
        let stderr = child
            .stderr
            .take()
            .context("storage proxy stderr was not captured")?;
        let logs = Arc::new(Mutex::new(Vec::new()));
        let readers = vec![
            spawn_log_reader(stdout, Arc::clone(&logs)),
            spawn_log_reader(stderr, Arc::clone(&logs)),
        ];
        let mut proxy = Self {
            addr,
            child,
            logs,
            readers,
        };
        if let Err(error) = wait_for_process_port(addr, &mut proxy.child).await {
            let _ = proxy.shutdown();
            return Err(error);
        }
        proxy.clear_logs()?;
        Ok(proxy)
    }

    fn endpoint_authority(&self) -> String {
        self.addr.to_string()
    }

    fn clear_logs(&self) -> Result<()> {
        let mut logs = self
            .logs
            .lock()
            .map_err(|_| anyhow::anyhow!("storage proxy log capture lock poisoned"))?;
        logs.clear();
        Ok(())
    }

    fn captured_logs(&self) -> Result<Vec<String>> {
        let logs = self
            .logs
            .lock()
            .map_err(|_| anyhow::anyhow!("storage proxy log capture lock poisoned"))?;
        Ok(logs.clone())
    }

    fn shutdown(&mut self) -> Result<()> {
        if self
            .child
            .try_wait()
            .context("failed to inspect storage proxy process")?
            .is_none()
        {
            self.child
                .kill()
                .context("failed to stop storage proxy process")?;
        }
        let _status = self
            .child
            .wait()
            .context("failed to reap storage proxy process")?;
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
        Ok(())
    }
}

#[cfg(feature = "containers")]
impl Drop for RunningStorageProxy {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[cfg(feature = "containers")]
fn measurement_json(
    storage_path: &'static str,
    stats: KopiaRunStats,
    backend_metrics: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "storage_path": storage_path,
        "elapsed_ms": duration_ms(stats.elapsed),
        "phase_timings": stats.phases.iter().map(|phase| serde_json::json!({
            "name": phase.name,
            "elapsed_ms": duration_ms(phase.elapsed),
        })).collect::<Vec<_>>(),
        "backend_metrics": backend_metrics,
    })
}

#[cfg(feature = "containers")]
fn gateway_backend_metrics_json(logs: &[String]) -> serde_json::Value {
    let counts = parse_gateway_backend_counts(logs);
    serde_json::json!({
        "source": "gateway-storage-logs",
        "counts": {
            "put": counts.put,
            "get": counts.get,
            "head": counts.head,
            "list": counts.list,
            "delete": counts.delete,
            "extend_retention": counts.extend_retention,
            "bytes_written": counts.bytes_written,
            "bytes_read": counts.bytes_read,
        }
    })
}

#[cfg(feature = "containers")]
fn parse_gateway_backend_counts(logs: &[String]) -> rs3_storage::BlobOperationCounts {
    let mut counts = rs3_storage::BlobOperationCounts::default();
    for line in logs {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let fields = value.get("fields").unwrap_or(&value);
        if json_field_str(fields, "provider") != Some("s3") {
            continue;
        }
        let Some(operation) = json_field_str(fields, "operation") else {
            continue;
        };
        match operation {
            "put" => counts.put = counts.put.saturating_add(1),
            "get" => counts.get = counts.get.saturating_add(1),
            "head" => counts.head = counts.head.saturating_add(1),
            "list" => counts.list = counts.list.saturating_add(1),
            "delete" => counts.delete = counts.delete.saturating_add(1),
            "extend_retention" => {
                counts.extend_retention = counts.extend_retention.saturating_add(1);
            }
            _ => continue,
        }

        if json_field_str(fields, "result") == Some("ok") {
            counts.bytes_written = counts
                .bytes_written
                .saturating_add(json_field_u64(fields, "bytes_sent"));
            counts.bytes_read = counts
                .bytes_read
                .saturating_add(json_field_u64(fields, "bytes_received"));
        }
    }
    counts
}

#[cfg(feature = "containers")]
fn wait_for_storage_proxy_metrics(proxy: &RunningStorageProxy) -> Result<serde_json::Value> {
    let started = Instant::now();
    loop {
        let logs = proxy.captured_logs()?;
        if let Some(metrics) = storage_proxy_metrics_json(&logs) {
            return Ok(metrics);
        }
        if started.elapsed() >= Duration::from_secs(3) {
            bail!("storage proxy did not emit metrics");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(feature = "containers")]
fn storage_proxy_metrics_json(logs: &[String]) -> Option<serde_json::Value> {
    let mut latest = None;
    for line in logs {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if value.get("target").and_then(serde_json::Value::as_str) == Some("rs3_storage_measure") {
            latest = value.get("fields").cloned();
        }
    }
    let fields = latest?;
    Some(serde_json::json!({
        "source": "integration-storage-proxy",
        "counts": {
            "requests": json_field_u64(&fields, "requests"),
            "responses": json_field_u64(&fields, "responses"),
            "bytes_written": json_field_u64(&fields, "request_body_bytes"),
            "bytes_read": json_field_u64(&fields, "response_body_bytes"),
        },
        "transport": {
            "bytes_to_backend": json_field_u64(&fields, "bytes_to_backend"),
            "bytes_from_backend": json_field_u64(&fields, "bytes_from_backend"),
            "accepted_connections": json_field_u64(&fields, "accepted_connections"),
            "active_connections": json_field_u64(&fields, "active_connections"),
            "failed_connections": json_field_u64(&fields, "failed_connections"),
        },
        "methods": fields.get("methods").cloned().unwrap_or_else(|| serde_json::json!({})),
        "statuses": fields.get("statuses").cloned().unwrap_or_else(|| serde_json::json!({})),
    }))
}

#[cfg(feature = "containers")]
fn endpoint_authority(endpoint_url: &str) -> Result<String> {
    let authority = endpoint_url
        .strip_prefix("http://")
        .or_else(|| endpoint_url.strip_prefix("https://"))
        .unwrap_or(endpoint_url);
    if authority.contains('/') {
        bail!("endpoint URL `{endpoint_url}` contains a path; expected only scheme and authority");
    }
    Ok(authority.to_owned())
}

#[cfg(feature = "containers")]
fn reserve_proxy_addr() -> Result<SocketAddr> {
    let listener =
        TcpListener::bind("127.0.0.1:0").context("failed to reserve storage proxy listen port")?;
    let addr = listener
        .local_addr()
        .context("failed to read storage proxy listen port")?;
    drop(listener);
    Ok(addr)
}

#[cfg(feature = "containers")]
async fn wait_for_process_port(addr: SocketAddr, child: &mut std::process::Child) -> Result<()> {
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .context("failed to inspect integration process")?
        {
            bail!("integration process exited before accepting connections: {status}");
        }
        if TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        if started.elapsed() >= Duration::from_secs(30) {
            bail!("integration process did not start accepting connections at {addr}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(feature = "containers")]
fn spawn_log_reader<R>(reader: R, logs: Arc<Mutex<Vec<String>>>) -> JoinHandle<()>
where
    R: std::io::Read + Send + 'static,
{
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            let Ok(line) = line else {
                break;
            };
            if let Ok(mut captured) = logs.lock() {
                captured.push(line);
            }
        }
    })
}

#[cfg(feature = "containers")]
fn json_field_str<'a>(fields: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    fields.get(key).and_then(serde_json::Value::as_str)
}

#[cfg(feature = "containers")]
fn json_field_u64(fields: &serde_json::Value, key: &str) -> u64 {
    fields
        .get(key)
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        })
        .unwrap_or(0)
}

#[cfg(feature = "containers")]
fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(feature = "containers")]
fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
}

#[cfg(feature = "containers")]
struct KopiaWorkspace {
    root: PathBuf,
}

#[cfg(feature = "containers")]
impl KopiaWorkspace {
    fn new() -> Result<Self> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "rs3-kopia-integration-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&root).with_context(|| {
            format!(
                "failed to create Kopia integration workspace {}",
                root.display()
            )
        })?;
        Ok(Self { root })
    }

    fn config_file(&self) -> PathBuf {
        self.root.join("repository.config")
    }

    fn cache_dir(&self) -> PathBuf {
        self.root.join("cache")
    }

    fn source_dir(&self) -> PathBuf {
        self.root.join("source")
    }

    fn restore_dir(&self) -> PathBuf {
        self.root.join("restore")
    }

    fn populate_source(&self) -> Result<()> {
        let nested = self.source_dir().join("nested");
        fs::create_dir_all(&nested).context("failed to create Kopia source tree")?;
        fs::write(self.source_dir().join("alpha.txt"), b"alpha\n")
            .context("failed to write Kopia source file")?;
        fs::write(nested.join("beta.txt"), b"beta\n")
            .context("failed to write nested Kopia source file")?;
        fs::write(
            self.source_dir().join("large.bin"),
            deterministic_bytes(1024 * 1024),
        )
        .context("failed to write large Kopia source file")?;
        Ok(())
    }

    fn assert_restored(&self) -> Result<()> {
        assert_file_eq(
            &self.source_dir().join("alpha.txt"),
            &self.restore_dir().join("alpha.txt"),
        )?;
        assert_file_eq(
            &self.source_dir().join("nested").join("beta.txt"),
            &self.restore_dir().join("nested").join("beta.txt"),
        )?;
        assert_file_eq(
            &self.source_dir().join("large.bin"),
            &self.restore_dir().join("large.bin"),
        )?;
        Ok(())
    }
}

#[cfg(feature = "containers")]
impl Drop for KopiaWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(feature = "containers")]
fn deterministic_bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| index.wrapping_mul(31).wrapping_add(17) as u8)
        .collect()
}

#[cfg(feature = "containers")]
fn assert_file_eq(expected: &Path, actual: &Path) -> Result<()> {
    let expected_body =
        fs::read(expected).with_context(|| format!("failed to read {}", expected.display()))?;
    let actual_body =
        fs::read(actual).with_context(|| format!("failed to read {}", actual.display()))?;
    if expected_body != actual_body {
        bail!(
            "restored file {} did not match source {}",
            actual.display(),
            expected.display()
        );
    }
    Ok(())
}
