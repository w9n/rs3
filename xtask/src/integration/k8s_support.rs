//! Shared Kubernetes integration helpers.

use anyhow::{Context, Result, bail};
use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;

pub(crate) const ACCESS_KEY_ID: &str = "access";
pub(crate) const CHART_NAME: &str = "rs3-gateway";
pub(crate) const CHART_PATH: &str = "charts/rs3-gateway";
pub(crate) const DEFAULT_PUBLIC_BUCKET: &str = "client-bucket";
pub(crate) const GATEWAY_PORT: u16 = 9080;
pub(crate) const SECRET_ACCESS_KEY: &str = "secret";

pub(crate) struct GatewayChartValues<'a> {
    pub(crate) release_name: &'a str,
    pub(crate) namespace: &'a str,
    pub(crate) image_repository: &'a str,
    pub(crate) image_tag: &'a str,
    pub(crate) public_bucket: &'a str,
    pub(crate) wait_secs: u64,
}

pub(crate) fn helm_install_gateway(
    helm_bin: &str,
    kubeconfig_path: &Path,
    values: &GatewayChartValues<'_>,
) -> Result<()> {
    let kubeconfig = path_str(kubeconfig_path)?;
    let timeout = format!("{}s", values.wait_secs);
    run_command(
        helm_bin,
        &[
            "--kubeconfig",
            kubeconfig,
            "upgrade",
            "--install",
            values.release_name,
            CHART_PATH,
            "--namespace",
            values.namespace,
            "--create-namespace",
            "--wait",
            "--timeout",
            timeout.as_str(),
            "--set-string",
            &format!("image.repository={}", values.image_repository),
            "--set-string",
            &format!("image.tag={}", values.image_tag),
            "--set-string",
            &format!("publicBucket={}", values.public_bucket),
        ],
    )
    .context("failed to install gateway Helm chart")
}

pub(crate) fn helm_fullname(release_name: &str) -> String {
    format!("{release_name}-{CHART_NAME}")
}

pub(crate) struct PortForward {
    endpoint_url: String,
    child: Child,
}

impl PortForward {
    pub(crate) async fn start(
        kubectl_bin: &str,
        kubeconfig_path: &Path,
        namespace: &str,
        service: &str,
        remote_port: u16,
        wait_secs: u64,
    ) -> Result<Self> {
        let local_port = reserve_local_port()?;
        let mut child = Command::new(kubectl_bin)
            .args([
                "--kubeconfig",
                path_str(kubeconfig_path)?,
                "-n",
                namespace,
                "port-forward",
                &format!("service/{service}"),
                &format!("{local_port}:{remote_port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to start kubectl port-forward")?;
        let addr = format!("127.0.0.1:{local_port}")
            .parse::<SocketAddr>()
            .context("failed to parse local port-forward address")?;

        wait_for_tcp(&addr, &mut child, wait_secs).await?;
        Ok(Self {
            endpoint_url: format!("http://{addr}"),
            child,
        })
    }

    pub(crate) fn endpoint_url(&self) -> String {
        self.endpoint_url.clone()
    }

    pub(crate) fn shutdown(&mut self) -> Result<()> {
        if self
            .child
            .try_wait()
            .context("failed to inspect kubectl port-forward")?
            .is_some()
        {
            return Ok(());
        }
        self.child
            .kill()
            .context("failed to stop kubectl port-forward")?;
        let _status = self
            .child
            .wait()
            .context("failed to reap kubectl port-forward")?;
        Ok(())
    }
}

impl Drop for PortForward {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

async fn wait_for_tcp(addr: &SocketAddr, child: &mut Child, wait_secs: u64) -> Result<()> {
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .context("failed to inspect kubectl port-forward")?
        {
            bail!("kubectl port-forward exited before accepting connections: {status}");
        }
        if TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        if started.elapsed() > Duration::from_secs(wait_secs) {
            bail!("kubectl port-forward did not accept connections within {wait_secs}s");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn reserve_local_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("failed to reserve local port")?;
    let port = listener
        .local_addr()
        .context("failed to read reserved local port")?
        .port();
    drop(listener);
    Ok(port)
}

pub(crate) struct KindCluster {
    kind_bin: String,
    name: String,
    kubeconfig_path: PathBuf,
    keep: bool,
    deleted: bool,
}

impl KindCluster {
    pub(crate) fn create(
        kind_bin: String,
        name: String,
        kubeconfig_path: PathBuf,
        keep: bool,
        wait_secs: u64,
    ) -> Result<Self> {
        let wait = format!("{wait_secs}s");
        run_command(
            &kind_bin,
            &[
                "create",
                "cluster",
                "--name",
                name.as_str(),
                "--kubeconfig",
                path_str(&kubeconfig_path)?,
                "--wait",
                wait.as_str(),
            ],
        )
        .with_context(|| format!("failed to create kind cluster `{name}`"))?;

        Ok(Self {
            kind_bin,
            name,
            kubeconfig_path,
            keep,
            deleted: false,
        })
    }

    pub(crate) fn kubeconfig_path(&self) -> &Path {
        &self.kubeconfig_path
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn load_image(&self, image: &str) -> Result<()> {
        run_command(
            &self.kind_bin,
            &["load", "docker-image", image, "--name", self.name.as_str()],
        )
        .with_context(|| format!("failed to load image `{image}` into kind"))?;
        Ok(())
    }

    pub(crate) fn delete(&mut self) -> Result<()> {
        if self.deleted || self.keep {
            return Ok(());
        }
        run_command(
            &self.kind_bin,
            &["delete", "cluster", "--name", self.name.as_str()],
        )
        .with_context(|| format!("failed to delete kind cluster `{}`", self.name))?;
        self.deleted = true;
        Ok(())
    }
}

impl Drop for KindCluster {
    fn drop(&mut self) {
        let _ = self.delete();
    }
}

pub(crate) struct K8sWorkspace {
    root: PathBuf,
}

impl K8sWorkspace {
    pub(crate) fn new(label: &str) -> Result<Self> {
        let root =
            std::env::temp_dir().join(format!("{label}-{}-{}", std::process::id(), now_millis(),));
        fs::create_dir_all(&root)
            .with_context(|| format!("failed to create {}", root.display()))?;
        Ok(Self { root })
    }

    pub(crate) fn kubeconfig_path(&self) -> PathBuf {
        self.root.join("kubeconfig")
    }

    pub(crate) fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for K8sWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub(crate) fn split_image_ref(image: &str) -> (String, String) {
    let slash = image.rfind('/');
    let colon = image.rfind(':');
    match colon {
        Some(colon) if slash.is_none_or(|slash| colon > slash) => {
            (image[..colon].to_owned(), image[colon + 1..].to_owned())
        }
        _ => (image.to_owned(), "latest".to_owned()),
    }
}

pub(crate) fn default_cluster_name(prefix: &str) -> String {
    format!("{prefix}-{}-{}", std::process::id(), now_millis())
}

pub(crate) fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
}

pub(crate) fn path_str(path: &Path) -> Result<&str> {
    path.to_str().context("path is not valid UTF-8")
}

pub(crate) fn require_command(program: &str, args: &[&str]) -> Result<()> {
    run_command(program, args)
        .with_context(|| format!("required command `{program}` is unavailable"))
}

pub(crate) fn run_command(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("failed to start `{program}`"))?;
    if status.success() {
        Ok(())
    } else {
        bail!("`{program}` exited with {status}");
    }
}

pub(crate) fn run_command_capture(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to start `{program}`"))?;
    if !output.status.success() {
        bail!(
            "`{program}` exited with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    String::from_utf8(output.stdout).context("command stdout was not valid UTF-8")
}
