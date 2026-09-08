//! Kubernetes gateway integration harness.

use super::S3ContainerProvider;
use anyhow::Result;
#[cfg(any(feature = "k8s", test))]
use anyhow::bail;
use clap::{Args, ValueEnum};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum K8sGatewayRetentionMode {
    Compliance,
    Governance,
}

#[cfg(feature = "k8s")]
impl K8sGatewayRetentionMode {
    const fn as_env(self) -> &'static str {
        match self {
            Self::Compliance => "compliance",
            Self::Governance => "governance",
        }
    }
}

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
    /// Container provider used as the journaled S3 backend.
    #[arg(long, value_enum, default_value_t = S3ContainerProvider::Rustfs)]
    container_provider: S3ContainerProvider,
    /// Repository retention mode for journaled backend objects.
    #[arg(long, value_enum)]
    retention_mode: Option<K8sGatewayRetentionMode>,
    /// Repository retention duration in days.
    #[arg(long)]
    retention_days: Option<u32>,
    /// Exercise AWS CLI, rclone, mc, and restic through the guarded gateway.
    #[arg(long, default_value_t = false)]
    tooling_smoke: bool,
    /// Force a fixed payload segment size. Omit to use adaptive per-object sizing.
    #[arg(long)]
    payload_segment_size: Option<usize>,
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
    /// Keep the kind cluster after the run for manual inspection; the temporary S3 backend is removed.
    #[arg(long)]
    keep_cluster: bool,
    /// Readiness timeout in seconds.
    #[arg(long, default_value_t = 180)]
    wait_secs: u64,
}

#[cfg(not(feature = "k8s"))]
pub(crate) fn run_k8s_gateway(_args: K8sGatewayArgs) -> Result<()> {
    anyhow::bail!(
        "Kubernetes gateway integration requires `cargo run -p xtask --bin xtask --features k8s -- integration k8s-gateway`",
    )
}

#[cfg(feature = "k8s")]
pub(crate) fn run_k8s_gateway(args: K8sGatewayArgs) -> Result<()> {
    validate_k8s_gateway_args(&args)?;
    imp::run(args)
}

#[cfg(any(feature = "k8s", test))]
fn validate_k8s_gateway_args(args: &K8sGatewayArgs) -> Result<()> {
    match (args.retention_mode, args.retention_days) {
        (Some(K8sGatewayRetentionMode::Governance), _) => bail!(
            "the guarded Kubernetes fixture does not assert governance-bypass IAM review; use --retention-mode compliance or a separately qualified governance provider"
        ),
        (Some(_), Some(days)) if days > 0 => Ok(()),
        (Some(_), None) => bail!("--retention-days is required when --retention-mode is set"),
        (None, Some(_)) => bail!("--retention-mode is required when --retention-days is set"),
        (Some(_), Some(_)) => bail!("--retention-days must be greater than zero"),
        (None, None) => Ok(()),
    }
}

#[cfg(feature = "k8s")]
mod imp {
    use super::{K8sGatewayArgs, K8sGatewayRetentionMode};
    use crate::integration::k8s_support::{
        ACCESS_KEY_ID, DEFAULT_PUBLIC_BUCKET, GATEWAY_PORT, GatewayChartValues, K8sWorkspace,
        KEYRING_ENVELOPE_OBJECT_ID, KEYRING_WRAPPING_KEY_HEX, KEYRING_WRAPPING_KEY_ID, KindCluster,
        PortForward, REPOSITORY_ID, REPOSITORY_SALT_HEX, SECRET_ACCESS_KEY, assert_v2_lease_anchor,
        build_source_revision, default_cluster_name, helm_fullname, helm_install_gateway,
        helm_lint_gateway, require_command, run_command, split_image_ref,
    };
    use crate::integration::{s3_container, s3_gateway};
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
        helm_lint_gateway(&args.helm_bin)?;

        if !args.skip_image_build {
            let revision_arg = format!("REVISION={}", build_source_revision());
            run_command(
                &args.docker_bin,
                &[
                    "build",
                    "--build-arg",
                    revision_arg.as_str(),
                    "-t",
                    args.image.as_str(),
                    ".",
                ],
            )
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
                args.docker_bin.clone(),
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
                args.docker_bin.clone(),
                cluster_name,
                workspace.kubeconfig_path(),
                args.keep_cluster,
                args.wait_secs,
            )?
        };

        if !args.skip_image_load {
            cluster.load_image(&args.image)?;
        }

        let backend = s3_container::start_s3_container_with_options(
            args.container_provider,
            None,
            None,
            s3_container::S3ContainerOptions {
                object_lock: args.retention_mode.is_some(),
                network: Some(cluster.docker_network()),
            },
        )?;
        let backend_endpoint = backend.network_endpoint_url()?.to_owned();
        let (image_repository, image_tag) = split_image_ref(&args.image);
        let anchor_mode = "kubernetes-lease";
        helm_install_gateway(
            &args.helm_bin,
            &args.kubectl_bin,
            cluster.kubeconfig_path(),
            &GatewayChartValues {
                release_name: &args.release_name,
                namespace: &args.namespace,
                image_repository: &image_repository,
                image_tag: &image_tag,
                gateway_mode: "read-write",
                public_bucket: DEFAULT_PUBLIC_BUCKET,
                backend_endpoint: &backend_endpoint,
                backend_bucket: &backend.bucket,
                backend_prefix: "repository",
                backend_region: &backend.region,
                backend_access_key_id: Some(&backend.access_key_id),
                backend_secret_access_key: Some(&backend.secret_access_key),
                anchor_mode,
                anchor_name: "checkpoint",
                log_format: "plain",
                rust_log: "info",
                payload_segment_size: args.payload_segment_size,
                retention_mode: args.retention_mode.map(K8sGatewayRetentionMode::as_env),
                retention_days: args.retention_days,
                repository_id: REPOSITORY_ID,
                repository_salt_hex: REPOSITORY_SALT_HEX,
                keyring_envelope_object_id: KEYRING_ENVELOPE_OBJECT_ID,
                keyring_wrapping_key_id: KEYRING_WRAPPING_KEY_ID,
                keyring_wrapping_key_hex: KEYRING_WRAPPING_KEY_HEX,
                persistence_enabled: false,
                wait_secs: args.wait_secs,
                governance_review: None,
            },
        )?;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to build Kubernetes integration runtime")?;

        let service_name = helm_fullname(&args.release_name);
        let result = runtime
            .block_on(async {
                let mut port_forward = PortForward::start(
                    &args.kubectl_bin,
                    cluster.kubeconfig_path(),
                    &args.namespace,
                    &service_name,
                    GATEWAY_PORT,
                    args.wait_secs,
                )
                .await?;
                let endpoint = port_forward.endpoint_url();
                let smoke = async {
                    run_s3_smoke(endpoint.clone(), args.payload_segment_size).await?;
                    if args.tooling_smoke {
                        s3_gateway::assert_operator_tooling_smoke(&endpoint).await?;
                    }
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                let shutdown = port_forward.shutdown();

                smoke?;
                shutdown?;
                Ok(())
            })
            .and_then(|_| {
                assert_v2_lease_anchor(
                    &args.kubectl_bin,
                    cluster.kubeconfig_path(),
                    &args.namespace,
                    "checkpoint",
                )?;
                Ok(())
            });

        drop(backend);
        if result.is_ok() {
            cluster.delete()?;
        }

        result
    }

    async fn run_s3_smoke(endpoint_url: String, payload_segment_size: Option<usize>) -> Result<()> {
        let payload_segment_size =
            payload_segment_size.unwrap_or(rs3_repository::DEFAULT_PAYLOAD_SEGMENT_SIZE);
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

#[cfg(test)]
mod tests {
    use super::{K8sGatewayArgs, K8sGatewayRetentionMode, validate_k8s_gateway_args};
    use crate::integration::S3ContainerProvider;

    fn args(
        retention_mode: Option<K8sGatewayRetentionMode>,
        retention_days: Option<u32>,
    ) -> K8sGatewayArgs {
        K8sGatewayArgs {
            cluster_name: None,
            reuse_kind_cluster: false,
            namespace: "rs3-ci".to_owned(),
            release_name: "rs3".to_owned(),
            image: "rs3-server:ci".to_owned(),
            container_provider: S3ContainerProvider::Rustfs,
            retention_mode,
            retention_days,
            tooling_smoke: false,
            payload_segment_size: None,
            kind_bin: "kind".to_owned(),
            docker_bin: "docker".to_owned(),
            helm_bin: "helm".to_owned(),
            kubectl_bin: "kubectl".to_owned(),
            skip_image_build: false,
            skip_image_load: false,
            keep_cluster: false,
            wait_secs: 180,
        }
    }

    #[test]
    fn retention_mode_requires_a_positive_duration() {
        for (mode, days) in [
            (Some(K8sGatewayRetentionMode::Compliance), None),
            (None, Some(1)),
            (Some(K8sGatewayRetentionMode::Compliance), Some(0)),
            (Some(K8sGatewayRetentionMode::Governance), Some(1)),
        ] {
            assert!(validate_k8s_gateway_args(&args(mode, days)).is_err());
        }
        assert!(
            validate_k8s_gateway_args(&args(Some(K8sGatewayRetentionMode::Compliance), Some(1),))
                .is_ok()
        );
    }
}
