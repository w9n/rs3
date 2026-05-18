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
pub(crate) const KEYRING_ENVELOPE_OBJECT_ID: &str = "keyrings/bootstrap-envelope.json";
pub(crate) const KEYRING_WRAPPING_KEY_HEX: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";
pub(crate) const KEYRING_WRAPPING_KEY_ID: &str = "wrap-integration";
pub(crate) const REPOSITORY_ID: &str = "rs3-integration-repository";
pub(crate) const REPOSITORY_SALT_HEX: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";
pub(crate) const SECRET_ACCESS_KEY: &str = "secret";

pub(crate) struct GatewayChartValues<'a> {
    pub(crate) release_name: &'a str,
    pub(crate) namespace: &'a str,
    pub(crate) image_repository: &'a str,
    pub(crate) image_tag: &'a str,
    pub(crate) gateway_mode: &'a str,
    pub(crate) public_bucket: &'a str,
    pub(crate) backend_endpoint: &'a str,
    pub(crate) backend_bucket: &'a str,
    pub(crate) backend_prefix: &'a str,
    pub(crate) backend_region: &'a str,
    pub(crate) backend_access_key_id: Option<&'a str>,
    pub(crate) backend_secret_access_key: Option<&'a str>,
    pub(crate) anchor_mode: &'a str,
    pub(crate) anchor_name: &'a str,
    pub(crate) log_format: &'a str,
    pub(crate) rust_log: &'a str,
    pub(crate) repository_format: &'a str,
    pub(crate) payload_segment_size: Option<usize>,
    pub(crate) retention_mode: Option<&'a str>,
    pub(crate) retention_days: Option<u32>,
    pub(crate) repository_id: &'a str,
    pub(crate) repository_salt_hex: &'a str,
    pub(crate) keyring_envelope_object_id: &'a str,
    pub(crate) keyring_wrapping_key_id: &'a str,
    pub(crate) keyring_wrapping_key_hex: &'a str,
    pub(crate) persistence_enabled: bool,
    pub(crate) wait_secs: u64,
}

pub(crate) fn helm_install_gateway(
    helm_bin: &str,
    kubeconfig_path: &Path,
    values: &GatewayChartValues<'_>,
) -> Result<()> {
    let kubeconfig = path_str(kubeconfig_path)?;
    let timeout = format!("{}s", values.wait_secs);
    let payload_segment_size = values
        .payload_segment_size
        .map(|value| value.to_string())
        .unwrap_or_default();
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
            &helm_set_string("gateway.mode", values.gateway_mode),
            "--set-string",
            &format!("publicBucket={}", values.public_bucket),
            "--set-string",
            &helm_set_string("backend.endpoint", values.backend_endpoint),
            "--set-string",
            &helm_set_string("backend.bucket", values.backend_bucket),
            "--set-string",
            &helm_set_string("backend.prefix", values.backend_prefix),
            "--set-string",
            &helm_set_string("backend.region", values.backend_region),
            "--set",
            &format!(
                "backendCredentials.create={}",
                values.backend_access_key_id.is_some()
            ),
            "--set-string",
            &helm_set_string(
                "backendCredentials.accessKeyId",
                values.backend_access_key_id.unwrap_or_default(),
            ),
            "--set-string",
            &helm_set_string(
                "backendCredentials.secretAccessKey",
                values.backend_secret_access_key.unwrap_or_default(),
            ),
            "--set-string",
            &helm_set_string("anchor.mode", values.anchor_mode),
            "--set-string",
            &helm_set_string("anchor.name", values.anchor_name),
            "--set-string",
            &format!("logging.format={}", values.log_format),
            "--set-string",
            &helm_set_string("logging.rustLog", values.rust_log),
            "--set-string",
            &helm_set_string("repository.format", values.repository_format),
            "--set",
            "repository.allowInit=true",
            "--set-string",
            &helm_set_string("repository.payloadSegmentSizeBytes", &payload_segment_size),
            "--set-string",
            &helm_set_string(
                "repository.retention.mode",
                values.retention_mode.unwrap_or_default(),
            ),
            "--set",
            &format!(
                "repository.retention.days={}",
                values.retention_days.unwrap_or_default()
            ),
            "--set-string",
            &helm_set_string("repository.id", values.repository_id),
            "--set",
            "repositoryKeys.create=true",
            "--set-string",
            &helm_set_string("repositoryKeys.saltHex", values.repository_salt_hex),
            "--set-string",
            &helm_set_string(
                "repositoryKeys.envelopeObjectId",
                values.keyring_envelope_object_id,
            ),
            "--set-string",
            &helm_set_string(
                "repositoryKeys.wrappingKeyId",
                values.keyring_wrapping_key_id,
            ),
            "--set-string",
            &helm_set_string(
                "repositoryKeys.wrappingKeyHex",
                values.keyring_wrapping_key_hex,
            ),
            "--set",
            &format!("anchor.allowMemory={}", values.anchor_mode == "memory"),
            "--set",
            &format!("persistence.enabled={}", values.persistence_enabled),
        ],
    )
    .context("failed to install gateway Helm chart")
}

pub(crate) fn helm_set_gateway_mode(
    helm_bin: &str,
    kubeconfig_path: &Path,
    release_name: &str,
    namespace: &str,
    gateway_mode: &str,
    wait_secs: u64,
) -> Result<()> {
    let kubeconfig = path_str(kubeconfig_path)?;
    let timeout = format!("{wait_secs}s");
    run_command(
        helm_bin,
        &[
            "--kubeconfig",
            kubeconfig,
            "upgrade",
            release_name,
            CHART_PATH,
            "--namespace",
            namespace,
            "--reuse-values",
            "--wait",
            "--timeout",
            timeout.as_str(),
            "--set-string",
            &helm_set_string("gateway.mode", gateway_mode),
        ],
    )
    .context("failed to update gateway Helm mode")
}

pub(crate) fn helm_lint_gateway(helm_bin: &str) -> Result<()> {
    let salt = helm_set_string("repositoryKeys.saltHex", REPOSITORY_SALT_HEX);
    let envelope = helm_set_string(
        "repositoryKeys.envelopeObjectId",
        KEYRING_ENVELOPE_OBJECT_ID,
    );
    let wrapping_key_id = helm_set_string("repositoryKeys.wrappingKeyId", KEYRING_WRAPPING_KEY_ID);
    let wrapping_key_hex =
        helm_set_string("repositoryKeys.wrappingKeyHex", KEYRING_WRAPPING_KEY_HEX);
    run_command(
        helm_bin,
        &[
            "lint",
            CHART_PATH,
            "--set",
            "repositoryKeys.create=true",
            "--set-string",
            salt.as_str(),
            "--set-string",
            envelope.as_str(),
            "--set-string",
            wrapping_key_id.as_str(),
            "--set-string",
            wrapping_key_hex.as_str(),
        ],
    )
    .context("gateway Helm chart lint failed")
}

pub(crate) fn assert_v2_lease_anchor(
    kubectl_bin: &str,
    kubeconfig_path: &Path,
    namespace: &str,
    anchor_name: &str,
) -> Result<()> {
    let kubeconfig = path_str(kubeconfig_path)?;
    let lease = run_command_capture(
        kubectl_bin,
        &[
            "--kubeconfig",
            kubeconfig,
            "-n",
            namespace,
            "get",
            "lease",
            anchor_name,
            "-o",
            "json",
        ],
    )
    .with_context(|| format!("failed to read v2 Lease anchor `{anchor_name}`"))?;
    let lease: serde_json::Value =
        serde_json::from_str(&lease).context("Lease anchor JSON was not valid")?;
    let annotations = lease
        .pointer("/metadata/annotations")
        .and_then(serde_json::Value::as_object)
        .context("Lease anchor is missing annotations")?;

    for key in [
        "rs3.rs/v2-commit-key",
        "rs3.rs/v2-body-digest",
        "rs3.rs/v2-signing-key-id",
        "rs3.rs/v2-format-digest",
        "rs3.rs/v2-format-object-id",
    ] {
        let Some(value) = annotations.get(key).and_then(serde_json::Value::as_str) else {
            bail!("Lease anchor is missing `{key}`");
        };
        if value.is_empty() {
            bail!("Lease anchor annotation `{key}` is empty");
        }
    }

    let sequence = required_u64_annotation(annotations, "rs3.rs/v2-sequence")?;
    if sequence == 0 {
        bail!("Lease anchor v2 sequence must be greater than zero");
    }
    let generation = required_u64_annotation(annotations, "rs3.rs/v2-format-generation")?;
    if generation == 0 {
        bail!("Lease anchor v2 format generation must be greater than zero");
    }

    Ok(())
}

fn required_u64_annotation(
    annotations: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u64> {
    let value = annotations
        .get(key)
        .and_then(serde_json::Value::as_str)
        .with_context(|| format!("Lease anchor is missing `{key}`"))?;
    value
        .parse::<u64>()
        .with_context(|| format!("Lease anchor annotation `{key}` is not an integer"))
}

fn helm_set_string(key: &str, value: &str) -> String {
    format!("{key}={}", value.replace('\\', "\\\\").replace(',', "\\,"))
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

    pub(crate) fn reuse(kind_bin: String, name: String, kubeconfig_path: PathBuf) -> Result<Self> {
        let kubeconfig =
            run_command_capture(&kind_bin, &["get", "kubeconfig", "--name", name.as_str()])
                .with_context(|| {
                    format!("failed to get kubeconfig for existing kind cluster `{name}`")
                })?;
        fs::write(&kubeconfig_path, kubeconfig)
            .with_context(|| format!("failed to write {}", kubeconfig_path.display()))?;

        Ok(Self {
            kind_bin,
            name,
            kubeconfig_path,
            keep: true,
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
