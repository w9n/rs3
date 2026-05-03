//! Kubernetes gateway integration harness.

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
    use crate::integration::k8s_support::{
        ACCESS_KEY_ID, CHART_PATH, DEFAULT_PUBLIC_BUCKET, GATEWAY_PORT, GatewayChartValues,
        K8sWorkspace, KindCluster, PortForward, SECRET_ACCESS_KEY, default_cluster_name,
        helm_fullname, helm_install_gateway, require_command, run_command, split_image_ref,
    };
    use anyhow::{Context, Result, bail};
    use aws_sdk_s3::{
        Client,
        config::{BehaviorVersion, Credentials, Region, timeout::TimeoutConfig},
        primitives::ByteStream,
    };
    use std::time::Duration;

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

        let workspace = K8sWorkspace::new("rs3-k8s-integration")?;
        let cluster_name = args
            .cluster_name
            .clone()
            .unwrap_or_else(|| default_cluster_name("rs3-ci"));
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
            &GatewayChartValues {
                release_name: &args.release_name,
                namespace: &args.namespace,
                image_repository: &image_repository,
                image_tag: &image_tag,
                public_bucket: DEFAULT_PUBLIC_BUCKET,
                wait_secs: args.wait_secs,
            },
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

    async fn run_s3_smoke(endpoint_url: String) -> Result<()> {
        let client = s3_client(&endpoint_url);
        let key = "smoke/object.txt";
        let expected = b"hello from kind";

        client
            .head_bucket()
            .bucket(DEFAULT_PUBLIC_BUCKET)
            .send()
            .await
            .context("Kubernetes gateway HeadBucket failed")?;

        client
            .put_object()
            .bucket(DEFAULT_PUBLIC_BUCKET)
            .key(key)
            .body(ByteStream::from_static(expected))
            .send()
            .await
            .context("Kubernetes gateway PutObject failed")?;

        let head = client
            .head_object()
            .bucket(DEFAULT_PUBLIC_BUCKET)
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
            .bucket(DEFAULT_PUBLIC_BUCKET)
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
            .bucket(DEFAULT_PUBLIC_BUCKET)
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
}
