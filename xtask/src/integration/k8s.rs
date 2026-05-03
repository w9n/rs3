//! Kubernetes integration harness.

use anyhow::Result;
use clap::Args;

#[derive(Debug, Args)]
pub(crate) struct K8sGatewayArgs {
    /// kind cluster name. Defaults to a unique disposable name.
    #[arg(long)]
    cluster_name: Option<String>,
    /// Kubernetes namespace used by the smoke test.
    #[arg(long, default_value = "rs3-ci")]
    namespace: String,
    /// Helm release name.
    #[arg(long, default_value = "rs3")]
    release_name: String,
    /// Gateway image tag to build, load, and deploy.
    #[arg(long, default_value = "rs3-server:ci")]
    image: String,
    /// kind executable.
    #[arg(long, env = "RS3_TEST_KIND_BIN", default_value = "kind")]
    kind_bin: String,
    /// docker executable.
    #[arg(long, env = "RS3_TEST_DOCKER_BIN", default_value = "docker")]
    docker_bin: String,
    /// helm executable.
    #[arg(long, env = "RS3_TEST_HELM_BIN", default_value = "helm")]
    helm_bin: String,
    /// kubectl executable.
    #[arg(long, env = "RS3_TEST_KUBECTL_BIN", default_value = "kubectl")]
    kubectl_bin: String,
    /// Do not build the gateway container image.
    #[arg(long)]
    skip_image_build: bool,
    /// Do not load the gateway image into kind.
    #[arg(long)]
    skip_image_load: bool,
    /// Keep the kind cluster after the run for manual inspection.
    #[arg(long)]
    keep_cluster: bool,
    /// Readiness timeout in seconds.
    #[arg(long, default_value_t = 180)]
    wait_secs: u64,
}

#[cfg(not(feature = "k8s"))]
pub(crate) fn run_k8s_gateway(_args: K8sGatewayArgs) -> Result<()> {
    anyhow::bail!(
        "Kubernetes gateway integration requires `cargo run -p xtask --features k8s -- integration k8s-gateway`",
    )
}

#[cfg(feature = "k8s")]
pub(crate) fn run_k8s_gateway(args: K8sGatewayArgs) -> Result<()> {
    imp::run(args)
}

#[cfg(feature = "k8s")]
mod imp {
    use super::K8sGatewayArgs;
    use anyhow::{Context, Result, bail};
    use aws_sdk_s3::{
        Client,
        config::{BehaviorVersion, Credentials, Region, timeout::TimeoutConfig},
        primitives::ByteStream,
    };
    use std::fs;
    use std::net::{SocketAddr, TcpListener};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use tokio::net::TcpStream;

    const CHART_PATH: &str = "charts/rs3-gateway";
    const CHART_NAME: &str = "rs3-gateway";
    const PUBLIC_BUCKET: &str = "client-bucket";
    const ACCESS_KEY_ID: &str = "access";
    const SECRET_ACCESS_KEY: &str = "secret";
    const GATEWAY_PORT: u16 = 9080;

    pub(super) fn run(args: K8sGatewayArgs) -> Result<()> {
        require_command(&args.kind_bin, &["version"])?;
        require_command(&args.kubectl_bin, &["version", "--client"])?;
        require_command(&args.helm_bin, &["version", "--short"])?;
        require_command(&args.docker_bin, &["version"])?;
        run_command(&args.helm_bin, &["lint", CHART_PATH])
            .context("gateway Helm chart lint failed")?;

        if !args.skip_image_build {
            run_command(&args.docker_bin, &["build", "-t", args.image.as_str(), "."])
                .context("failed to build gateway image")?;
        }

        let workspace = K8sWorkspace::new()?;
        let cluster_name = args
            .cluster_name
            .clone()
            .unwrap_or_else(default_cluster_name);
        let mut cluster = KindCluster::create(
            args.kind_bin.clone(),
            cluster_name,
            workspace.kubeconfig_path(),
            args.keep_cluster,
            args.wait_secs,
        )?;

        if !args.skip_image_load {
            cluster.load_image(&args.image)?;
        }

        let (image_repository, image_tag) = split_image_ref(&args.image);
        helm_install_gateway(
            &args.helm_bin,
            cluster.kubeconfig_path(),
            &args.release_name,
            &args.namespace,
            &image_repository,
            &image_tag,
            args.wait_secs,
        )?;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to build Kubernetes integration runtime")?;

        let service_name = helm_fullname(&args.release_name);
        let result = runtime.block_on(async {
            let mut port_forward = PortForward::start(
                &args.kubectl_bin,
                cluster.kubeconfig_path(),
                &args.namespace,
                &service_name,
                GATEWAY_PORT,
                args.wait_secs,
            )
            .await?;
            let smoke = run_s3_smoke(port_forward.endpoint_url()).await;
            let shutdown = port_forward.shutdown();

            smoke?;
            shutdown?;
            Ok(())
        });

        if result.is_ok() {
            cluster.delete()?;
        }

        result
    }

    fn helm_install_gateway(
        helm_bin: &str,
        kubeconfig_path: &Path,
        release_name: &str,
        namespace: &str,
        image_repository: &str,
        image_tag: &str,
        wait_secs: u64,
    ) -> Result<()> {
        let kubeconfig = kubeconfig_path
            .to_str()
            .context("kubeconfig path is not valid UTF-8")?;
        let timeout = format!("{wait_secs}s");
        run_command(
            helm_bin,
            &[
                "--kubeconfig",
                kubeconfig,
                "upgrade",
                "--install",
                release_name,
                CHART_PATH,
                "--namespace",
                namespace,
                "--create-namespace",
                "--wait",
                "--timeout",
                timeout.as_str(),
                "--set-string",
                &format!("image.repository={image_repository}"),
                "--set-string",
                &format!("image.tag={image_tag}"),
            ],
        )
        .context("failed to install gateway Helm chart")
    }

    async fn run_s3_smoke(endpoint_url: String) -> Result<()> {
        let client = s3_client(&endpoint_url);
        let key = "smoke/object.txt";
        let expected = b"hello from kind";

        client
            .put_object()
            .bucket(PUBLIC_BUCKET)
            .key(key)
            .body(ByteStream::from_static(expected))
            .send()
            .await
            .context("Kubernetes gateway PutObject failed")?;

        let head = client
            .head_object()
            .bucket(PUBLIC_BUCKET)
            .key(key)
            .send()
            .await
            .context("Kubernetes gateway HeadObject failed")?;
        if head.content_length() != Some(expected.len() as i64) {
            bail!(
                "Kubernetes gateway HeadObject returned content length {:?}, expected {}",
                head.content_length(),
                expected.len(),
            );
        }

        let get = client
            .get_object()
            .bucket(PUBLIC_BUCKET)
            .key(key)
            .send()
            .await
            .context("Kubernetes gateway GetObject failed")?;
        let actual = get
            .body
            .collect()
            .await
            .context("failed to collect Kubernetes gateway GetObject body")?
            .into_bytes();
        if actual.as_ref() != expected {
            bail!("Kubernetes gateway GetObject body mismatch");
        }

        let listed = client
            .list_objects_v2()
            .bucket(PUBLIC_BUCKET)
            .prefix("smoke/")
            .send()
            .await
            .context("Kubernetes gateway ListObjectsV2 failed")?;
        let listed = listed
            .contents()
            .iter()
            .filter_map(|object| object.key())
            .any(|listed_key| listed_key == key);
        if !listed {
            bail!("Kubernetes gateway ListObjectsV2 did not include {key}");
        }

        Ok(())
    }

    fn s3_client(endpoint_url: &str) -> Client {
        let timeout_config = TimeoutConfig::builder()
            .operation_attempt_timeout(Duration::from_secs(10))
            .operation_timeout(Duration::from_secs(30))
            .build();
        let config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .endpoint_url(endpoint_url.to_owned())
            .credentials_provider(Credentials::new(
                ACCESS_KEY_ID,
                SECRET_ACCESS_KEY,
                None,
                None,
                "rs3-xtask",
            ))
            .force_path_style(true)
            .timeout_config(timeout_config)
            .build();
        Client::from_conf(config)
    }

    struct PortForward {
        endpoint_url: String,
        child: Child,
    }

    impl PortForward {
        async fn start(
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
                    kubeconfig_path
                        .to_str()
                        .context("kubeconfig path is not valid UTF-8")?,
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

        fn endpoint_url(&self) -> String {
            self.endpoint_url.clone()
        }

        fn shutdown(&mut self) -> Result<()> {
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

    struct KindCluster {
        kind_bin: String,
        name: String,
        kubeconfig_path: PathBuf,
        keep: bool,
        deleted: bool,
    }

    impl KindCluster {
        fn create(
            kind_bin: String,
            name: String,
            kubeconfig_path: PathBuf,
            keep: bool,
            wait_secs: u64,
        ) -> Result<Self> {
            let wait = format!("{wait_secs}s");
            let kubeconfig = kubeconfig_path
                .to_str()
                .context("kubeconfig path is not valid UTF-8")?;
            run_command(
                &kind_bin,
                &[
                    "create",
                    "cluster",
                    "--name",
                    name.as_str(),
                    "--kubeconfig",
                    kubeconfig,
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

        fn kubeconfig_path(&self) -> &Path {
            &self.kubeconfig_path
        }

        fn load_image(&self, image: &str) -> Result<()> {
            run_command(
                &self.kind_bin,
                &["load", "docker-image", image, "--name", self.name.as_str()],
            )
            .with_context(|| format!("failed to load image `{image}` into kind"))?;
            Ok(())
        }

        fn delete(&mut self) -> Result<()> {
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

    struct K8sWorkspace {
        root: PathBuf,
    }

    impl K8sWorkspace {
        fn new() -> Result<Self> {
            let root = std::env::temp_dir().join(format!(
                "rs3-k8s-integration-{}-{}",
                std::process::id(),
                now_millis(),
            ));
            fs::create_dir_all(&root)
                .with_context(|| format!("failed to create {}", root.display()))?;
            Ok(Self { root })
        }

        fn kubeconfig_path(&self) -> PathBuf {
            self.root.join("kubeconfig")
        }
    }

    impl Drop for K8sWorkspace {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn split_image_ref(image: &str) -> (String, String) {
        let slash = image.rfind('/');
        let colon = image.rfind(':');
        match colon {
            Some(colon) if slash.is_none_or(|slash| colon > slash) => {
                (image[..colon].to_owned(), image[colon + 1..].to_owned())
            }
            _ => (image.to_owned(), "latest".to_owned()),
        }
    }

    fn helm_fullname(release_name: &str) -> String {
        format!("{release_name}-{CHART_NAME}")
    }

    fn default_cluster_name() -> String {
        format!("rs3-ci-{}-{}", std::process::id(), now_millis())
    }

    fn now_millis() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis()
    }

    fn require_command(program: &str, args: &[&str]) -> Result<()> {
        run_command(program, args)
            .with_context(|| format!("required command `{program}` is unavailable"))
    }

    fn run_command(program: &str, args: &[&str]) -> Result<()> {
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
}
