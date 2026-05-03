//! Kubernetes gateway integration harness.

use anyhow::Result;
use clap::Args;

#[derive(Debug, Args)]
pub(crate) struct K8sGatewayArgs {
    /// kind cluster name. Defaults to a unique disposable name.
    #[arg(long)]
    cluster_name: Option<String>,
    /// Reuse an existing kind cluster instead of creating and deleting one.
    #[arg(long)]
    reuse_kind_cluster: bool,
    /// Kubernetes namespace used by the smoke test.
    #[arg(long, default_value = "rs3-ci")]
    namespace: String,
    /// Helm release name.
    #[arg(long, default_value = "rs3")]
    release_name: String,
    /// Gateway image tag to build, load, and deploy.
    #[arg(long, default_value = "rs3-server:ci")]
    image: String,
    /// Plaintext bytes per encrypted payload segment.
    #[arg(long, default_value_t = rs3_repository::DEFAULT_PAYLOAD_SEGMENT_SIZE)]
    payload_segment_size: usize,
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
        let mut cluster = if args.reuse_kind_cluster {
            let cluster_name = args
                .cluster_name
                .clone()
                .unwrap_or_else(|| "kind".to_owned());
            KindCluster::reuse(
                args.kind_bin.clone(),
                cluster_name,
                workspace.kubeconfig_path(),
            )?
        } else {
            let cluster_name = args
                .cluster_name
                .clone()
                .unwrap_or_else(|| default_cluster_name("rs3-ci"));
            KindCluster::create(
                args.kind_bin.clone(),
                cluster_name,
                workspace.kubeconfig_path(),
                args.keep_cluster,
                args.wait_secs,
            )?
        };

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
                backend_endpoint: "file:///data",
                backend_bucket: "backend",
                backend_prefix: "repository",
                backend_region: "us-east-1",
                backend_access_key_id: None,
                backend_secret_access_key: None,
                anchor_mode: "memory",
                anchor_name: "checkpoint",
                log_format: "plain",
                rust_log: "info",
                payload_segment_size: args.payload_segment_size,
                persistence_enabled: false,
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
            let smoke = run_s3_smoke(port_forward.endpoint_url(), args.payload_segment_size).await;
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

    async fn run_s3_smoke(endpoint_url: String, payload_segment_size: usize) -> Result<()> {
        if payload_segment_size == 0 {
            bail!("payload segment size must be greater than zero");
        }
        let client = s3_client(&endpoint_url);
        let key = "smoke/object.txt";
        let body_len = payload_segment_size
            .checked_mul(2)
            .and_then(|len| len.checked_add(123))
            .filter(|len| *len <= 8 * 1024 * 1024)
            .context("payload segment size is too large for the Kubernetes smoke body")?;
        let expected = deterministic_body(body_len);

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
            .body(ByteStream::from(expected.clone()))
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
        if actual.as_ref() != expected.as_slice() {
            bail!("Kubernetes gateway GetObject body mismatch");
        }

        let range_start = payload_segment_size.saturating_sub(17);
        let range_len = 64_usize.min(expected.len() - range_start);
        let range_end = range_start + range_len - 1;
        let range = client
            .get_object()
            .bucket(DEFAULT_PUBLIC_BUCKET)
            .key(key)
            .range(format!("bytes={range_start}-{range_end}"))
            .send()
            .await
            .context("Kubernetes gateway ranged GetObject failed")?;
        let actual_range = range
            .body
            .collect()
            .await
            .context("failed to collect Kubernetes gateway ranged GetObject body")?
            .into_bytes();
        if actual_range.as_ref() != &expected[range_start..=range_end] {
            bail!("Kubernetes gateway ranged GetObject body mismatch");
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

    fn deterministic_body(len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| {
                let mixed = index.wrapping_mul(31).wrapping_add(index / 251);
                (mixed % 251) as u8
            })
            .collect()
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
