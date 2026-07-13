//! Velero/Kopia restore integration harness.

use anyhow::Result;
use clap::{Args, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Args)]
pub(crate) struct VeleroKopiaSmokeArgs {
    /// Backend mode used behind the gateway.
    #[arg(long, value_enum, default_value_t = VeleroBackendMode::ClusterRustfs)]
    backend_mode: VeleroBackendMode,
    /// Provided S3-compatible backend endpoint URL.
    #[arg(long, env = "RS3_TEST_S3_ENDPOINT_URL")]
    backend_endpoint_url: Option<String>,
    /// Provided S3-compatible backend bucket.
    #[arg(long, env = "RS3_TEST_S3_BUCKET")]
    backend_bucket: Option<String>,
    /// Backend prefix for repository-owned objects. Defaults to a fresh prefix.
    #[arg(long, env = "RS3_TEST_S3_PREFIX")]
    backend_prefix: Option<String>,
    /// Provided S3-compatible backend signing region.
    #[arg(long, env = "RS3_TEST_S3_REGION")]
    backend_region: Option<String>,
    /// Retention mode applied by the gateway to repository objects.
    #[arg(long, env = "RS3_REPOSITORY_RETENTION_MODE")]
    repository_retention_mode: Option<String>,
    /// Retention duration in days when repository retention mode is set.
    #[arg(long, env = "RS3_REPOSITORY_RETENTION_DAYS")]
    repository_retention_days: Option<u32>,
    /// kind cluster name. Defaults to a unique disposable name.
    #[arg(long)]
    cluster_name: Option<String>,
    /// Reuse an existing kind cluster instead of creating and deleting one.
    #[arg(long)]
    reuse_kind_cluster: bool,
    /// Kubernetes namespace used for the gateway.
    #[arg(long, default_value = "rs3-ci")]
    gateway_namespace: String,
    /// Kubernetes namespace used for the workload under backup.
    #[arg(long, default_value = "rs3-velero-smoke")]
    workload_namespace: String,
    /// Kubernetes namespace used for Velero.
    #[arg(long, default_value = "velero")]
    velero_namespace: String,
    /// Helm release name for the gateway chart.
    #[arg(long, default_value = "rs3")]
    release_name: String,
    /// Gateway image tag to build, load, and deploy.
    #[arg(long, default_value = "rs3-server:ci")]
    image: String,
    /// Force a fixed payload segment size. Omit to use adaptive per-object sizing.
    #[arg(long)]
    payload_segment_size: Option<usize>,
    /// Workload image used for the volume restore check. Defaults to the gateway image.
    #[arg(long)]
    workload_image: Option<String>,
    /// Velero server/node-agent image.
    #[arg(
        long,
        env = "RS3_TEST_VELERO_IMAGE",
        default_value = "velero/velero:v1.18.0"
    )]
    velero_image: String,
    /// Velero AWS plugin image matching the local Velero major/minor.
    #[arg(
        long,
        env = "RS3_TEST_VELERO_AWS_PLUGIN_IMAGE",
        default_value = "velero/velero-plugin-for-aws:v1.14.0"
    )]
    velero_aws_plugin_image: String,
    /// Helm chart reference used for the OpenEBS LocalPV dynamic PVC lane.
    #[arg(
        long,
        env = "RS3_TEST_OPENEBS_CHART",
        default_value = "https://openebs.github.io/dynamic-localpv-provisioner/localpv-provisioner-4.4.0.tgz"
    )]
    openebs_chart: String,
    /// Kubernetes namespace used for OpenEBS LocalPV.
    #[arg(long, default_value = "openebs")]
    openebs_namespace: String,
    /// Helm release name for OpenEBS LocalPV.
    #[arg(long, default_value = "rs3-openebs")]
    openebs_release_name: String,
    /// StorageClass name created by the OpenEBS LocalPV chart.
    #[arg(long, default_value = "rs3-openebs-hostpath")]
    openebs_storage_class: String,
    /// OpenEBS LocalPV provisioner image.
    #[arg(
        long,
        env = "RS3_TEST_OPENEBS_PROVISIONER_IMAGE",
        default_value = "openebs/provisioner-localpv:4.4.0"
    )]
    openebs_provisioner_image: String,
    /// OpenEBS helper image used by the provisioner.
    #[arg(
        long,
        env = "RS3_TEST_OPENEBS_HELPER_IMAGE",
        default_value = "openebs/linux-utils:4.3.0"
    )]
    openebs_helper_image: String,
    /// Postgres image used by the database restore lane.
    #[arg(
        long,
        env = "RS3_TEST_POSTGRES_IMAGE",
        default_value = "postgres:17-alpine"
    )]
    postgres_image: String,
    /// Rows inserted into the Postgres proof table.
    #[arg(long, default_value_t = 128)]
    postgres_row_count: u32,
    /// Repetitions of md5(row id) stored as padding in each Postgres proof row.
    #[arg(long, default_value_t = 1)]
    postgres_padding_repeat: u32,
    /// S3-compatible backend image used behind the gateway for Velero lanes.
    #[arg(
        long,
        env = "RS3_TEST_RUSTFS_IMAGE",
        default_value = "rustfs/rustfs:latest"
    )]
    rustfs_image: String,
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
    /// velero executable.
    #[arg(long, env = "RS3_TEST_VELERO_BIN", default_value = "velero")]
    velero_bin: String,
    /// Do not build the gateway container image.
    #[arg(long)]
    skip_image_build: bool,
    /// Do not load the gateway image into kind.
    #[arg(long)]
    skip_image_load: bool,
    /// Pull missing Velero images into the local Docker daemon before loading them into kind.
    #[arg(long)]
    pull_velero_images: bool,
    /// Do not require or load Velero images from the local Docker daemon.
    #[arg(long)]
    skip_velero_image_load: bool,
    /// Pull missing OpenEBS images into the local Docker daemon before loading them into kind.
    #[arg(long)]
    pull_openebs_images: bool,
    /// Do not require or load OpenEBS images from the local Docker daemon.
    #[arg(long)]
    skip_openebs_image_load: bool,
    /// Pull the missing Postgres image into the local Docker daemon before loading it into kind.
    #[arg(long)]
    pull_postgres_image: bool,
    /// Do not require or load the Postgres image from the local Docker daemon.
    #[arg(long)]
    skip_postgres_image_load: bool,
    /// Pull the missing RustFS image into the local Docker daemon before loading it into kind.
    #[arg(long)]
    pull_rustfs_image: bool,
    /// Do not require or load the RustFS image from the local Docker daemon.
    #[arg(long)]
    skip_rustfs_image_load: bool,
    /// Directory for persisted integration artifacts. Defaults under `.local/integration`.
    #[arg(long)]
    artifact_dir: Option<PathBuf>,
    /// Do not collect diagnostics and metrics artifacts.
    #[arg(long)]
    skip_artifacts: bool,
    /// Keep the kind cluster after the run for manual inspection.
    #[arg(long)]
    keep_cluster: bool,
    /// Readiness and operation timeout in seconds.
    #[arg(long, default_value_t = 600)]
    wait_secs: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum VeleroBackendMode {
    /// Deploy a disposable RustFS backend inside the test cluster.
    ClusterRustfs,
    /// Use an already provisioned S3-compatible backend.
    Provided,
}

#[cfg(not(feature = "k8s"))]
pub(crate) fn run_velero_kopia_smoke(_args: VeleroKopiaSmokeArgs) -> Result<()> {
    anyhow::bail!(
        "Velero Kopia smoke integration requires `cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-smoke`",
    )
}

#[cfg(not(feature = "k8s"))]
pub(crate) fn run_velero_kopia_local_pv_smoke(_args: VeleroKopiaSmokeArgs) -> Result<()> {
    anyhow::bail!(
        "Velero Kopia local-PV smoke integration requires `cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-local-pv-smoke`",
    )
}

#[cfg(not(feature = "k8s"))]
pub(crate) fn run_velero_kopia_dynamic_pvc_smoke(_args: VeleroKopiaSmokeArgs) -> Result<()> {
    anyhow::bail!(
        "Velero Kopia dynamic-PVC smoke integration requires `cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-dynamic-pvc-smoke`",
    )
}

#[cfg(not(feature = "k8s"))]
pub(crate) fn run_velero_kopia_dynamic_pvc_gateway_restart_smoke(
    _args: VeleroKopiaSmokeArgs,
) -> Result<()> {
    anyhow::bail!(
        "Velero Kopia dynamic-PVC gateway-restart smoke integration requires `cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-dynamic-pvc-gateway-restart-smoke`",
    )
}

#[cfg(not(feature = "k8s"))]
pub(crate) fn run_velero_kopia_dynamic_pvc_restore_readonly_smoke(
    _args: VeleroKopiaSmokeArgs,
) -> Result<()> {
    anyhow::bail!(
        "Velero Kopia dynamic-PVC restore-readonly smoke integration requires `cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-dynamic-pvc-restore-readonly-smoke`",
    )
}

#[cfg(not(feature = "k8s"))]
pub(crate) fn run_velero_kopia_postgres_smoke(_args: VeleroKopiaSmokeArgs) -> Result<()> {
    anyhow::bail!(
        "Velero Kopia Postgres smoke integration requires `cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-postgres-smoke`",
    )
}

#[cfg(not(feature = "k8s"))]
pub(crate) fn run_velero_kopia_postgres_direct_smoke(_args: VeleroKopiaSmokeArgs) -> Result<()> {
    anyhow::bail!(
        "Velero Kopia Postgres direct RustFS smoke integration requires `cargo run -p xtask --bin xtask --features k8s -- integration velero-kopia-postgres-direct-smoke`",
    )
}

#[cfg(feature = "k8s")]
pub(crate) fn run_velero_kopia_smoke(args: VeleroKopiaSmokeArgs) -> Result<()> {
    imp::run_empty_dir(args)
}

#[cfg(feature = "k8s")]
pub(crate) fn run_velero_kopia_local_pv_smoke(args: VeleroKopiaSmokeArgs) -> Result<()> {
    imp::run_local_pv(args)
}

#[cfg(feature = "k8s")]
pub(crate) fn run_velero_kopia_dynamic_pvc_smoke(args: VeleroKopiaSmokeArgs) -> Result<()> {
    imp::run_dynamic_pvc(args)
}

#[cfg(feature = "k8s")]
pub(crate) fn run_velero_kopia_dynamic_pvc_gateway_restart_smoke(
    args: VeleroKopiaSmokeArgs,
) -> Result<()> {
    imp::run_dynamic_pvc_gateway_restart(args)
}

#[cfg(feature = "k8s")]
pub(crate) fn run_velero_kopia_dynamic_pvc_restore_readonly_smoke(
    args: VeleroKopiaSmokeArgs,
) -> Result<()> {
    imp::run_dynamic_pvc_restore_readonly(args)
}

#[cfg(feature = "k8s")]
pub(crate) fn run_velero_kopia_postgres_smoke(args: VeleroKopiaSmokeArgs) -> Result<()> {
    imp::run_postgres(args)
}

#[cfg(feature = "k8s")]
pub(crate) fn run_velero_kopia_postgres_direct_smoke(args: VeleroKopiaSmokeArgs) -> Result<()> {
    imp::run_postgres_direct(args)
}

#[cfg(feature = "k8s")]
mod imp {
    #[path = "velero_artifacts.rs"]
    mod artifacts;
    #[path = "images.rs"]
    mod images;
    #[path = "integration_storage_proxy.rs"]
    mod integration_storage_proxy;
    #[path = "rustfs_backend.rs"]
    mod rustfs_backend;
    #[path = "scenario.rs"]
    mod scenario;
    #[path = "velero_cli.rs"]
    mod velero_cli;
    #[path = "workload.rs"]
    mod workload;

    use super::{VeleroBackendMode, VeleroKopiaSmokeArgs};
    use crate::integration::k8s_support::{
        GatewayChartValues, K8sWorkspace, KEYRING_ENVELOPE_OBJECT_ID, KEYRING_WRAPPING_KEY_HEX,
        KEYRING_WRAPPING_KEY_ID, KindCluster, REPOSITORY_ID, REPOSITORY_SALT_HEX,
        assert_v2_lease_anchor, build_source_revision, default_cluster_name, helm_fullname,
        helm_install_gateway, helm_lint_gateway, helm_set_gateway_mode, now_millis, path_str,
        require_command, run_command, run_command_capture, split_image_ref,
    };
    use anyhow::{Context, Result, bail};
    use artifacts::{ArtifactCollector, gateway_backend_counts};
    use images::{
        prepare_openebs_images, prepare_postgres_image, prepare_rustfs_image, prepare_velero_images,
    };
    use rs3_storage::BlobOperationCounts;
    use rustfs_backend::{
        BACKEND_BUCKET, BACKEND_REGION, RUSTFS_ACCESS_KEY_ID, RUSTFS_SECRET_ACCESS_KEY,
    };
    use scenario::{RunState, Scenario, WorkloadKind, WorkloadVolume};
    use std::env;
    use std::path::{Path, PathBuf};
    use std::time::Instant;
    use velero_cli::{
        assert_pod_volume_backup_completed, assert_pod_volume_restore_completed,
        assert_restore_phase, assert_velero_phase, create_backup, create_restore, install_velero,
        set_backup_storage_location_access_mode, velero_s3_target, write_velero_credentials,
    };
    use workload::{
        apply_workload, assert_workload_proof, delete_workload_namespace, delete_workload_pod,
        prepare_local_pv_path, remove_workload_proof, wait_for_restored_proof,
        wait_for_workload_available, write_workload_proof,
    };

    const VELERO_BUCKET: &str = "velero";
    const GATEWAY_RUST_LOG: &str = "rs3_storage=debug,rs3_repository=info,rs3_server=info,info";

    pub(super) fn run_empty_dir(args: VeleroKopiaSmokeArgs) -> Result<()> {
        run(args, Scenario::empty_dir())
    }

    pub(super) fn run_local_pv(args: VeleroKopiaSmokeArgs) -> Result<()> {
        run(args, Scenario::local_pv())
    }

    pub(super) fn run_dynamic_pvc(args: VeleroKopiaSmokeArgs) -> Result<()> {
        run(args, Scenario::dynamic_pvc())
    }

    pub(super) fn run_dynamic_pvc_gateway_restart(args: VeleroKopiaSmokeArgs) -> Result<()> {
        run(args, Scenario::dynamic_pvc_gateway_restart())
    }

    pub(super) fn run_dynamic_pvc_restore_readonly(args: VeleroKopiaSmokeArgs) -> Result<()> {
        run(args, Scenario::dynamic_pvc_restore_readonly())
    }

    pub(super) fn run_postgres(args: VeleroKopiaSmokeArgs) -> Result<()> {
        run(args, Scenario::postgres())
    }

    pub(super) fn run_postgres_direct(args: VeleroKopiaSmokeArgs) -> Result<()> {
        run(args, Scenario::postgres_direct_rustfs())
    }

    struct RunContext<'a> {
        kubeconfig_path: PathBuf,
        workspace: &'a K8sWorkspace,
    }

    struct BackendTarget {
        endpoint: String,
        bucket: String,
        prefix: String,
        region: String,
        access_key_id: Option<String>,
        secret_access_key: Option<String>,
    }

    impl<'a> RunContext<'a> {
        fn new(kubeconfig_path: &Path, workspace: &'a K8sWorkspace) -> Self {
            Self {
                kubeconfig_path: kubeconfig_path.to_path_buf(),
                workspace,
            }
        }

        fn kubeconfig_path(&self) -> &Path {
            &self.kubeconfig_path
        }

        fn workspace(&self) -> &K8sWorkspace {
            self.workspace
        }
    }

    fn run_phase<T>(
        state: &mut RunState,
        name: &'static str,
        phase: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let started = Instant::now();
        let result = phase();
        state.record_phase(name, started.elapsed(), result.is_ok());
        result
    }

    fn backend_target(args: &VeleroKopiaSmokeArgs) -> Result<BackendTarget> {
        let prefix = args
            .backend_prefix
            .clone()
            .unwrap_or_else(|| format!("repository-{}", now_millis()));
        match (
            &args.repository_retention_mode,
            args.repository_retention_days,
        ) {
            (Some(_), Some(_)) | (None, None) => {}
            (Some(_), None) => bail!("--repository-retention-days is required with retention mode"),
            (None, Some(_)) => bail!("--repository-retention-mode is required with retention days"),
        }

        match args.backend_mode {
            VeleroBackendMode::ClusterRustfs => Ok(BackendTarget {
                endpoint: rustfs_backend::service_endpoint(&args.gateway_namespace),
                bucket: BACKEND_BUCKET.to_owned(),
                prefix,
                region: BACKEND_REGION.to_owned(),
                access_key_id: Some(RUSTFS_ACCESS_KEY_ID.to_owned()),
                secret_access_key: Some(RUSTFS_SECRET_ACCESS_KEY.to_owned()),
            }),
            VeleroBackendMode::Provided => {
                let endpoint = args.backend_endpoint_url.clone().context(
                    "--backend-endpoint-url or RS3_TEST_S3_ENDPOINT_URL is required with --backend-mode provided",
                )?;
                let bucket = args.backend_bucket.clone().context(
                    "--backend-bucket or RS3_TEST_S3_BUCKET is required with --backend-mode provided",
                )?;
                let region = args
                    .backend_region
                    .clone()
                    .unwrap_or_else(|| "us-east-1".to_owned());
                let access_key_id = env::var("AWS_ACCESS_KEY_ID")
                    .context("AWS_ACCESS_KEY_ID is required with --backend-mode provided")?;
                let secret_access_key = env::var("AWS_SECRET_ACCESS_KEY")
                    .context("AWS_SECRET_ACCESS_KEY is required with --backend-mode provided")?;
                Ok(BackendTarget {
                    endpoint,
                    bucket,
                    prefix,
                    region,
                    access_key_id: Some(access_key_id),
                    secret_access_key: Some(secret_access_key),
                })
            }
        }
    }

    fn run(args: VeleroKopiaSmokeArgs, scenario: Scenario) -> Result<()> {
        if scenario.storage_path.uses_integration_storage_proxy()
            && args.backend_mode != VeleroBackendMode::ClusterRustfs
        {
            bail!("direct RustFS scenarios require --backend-mode cluster-rustfs");
        }
        let backend = backend_target(&args)?;
        require_command(&args.kind_bin, &["version"])?;
        require_command(&args.kubectl_bin, &["version", "--client"])?;
        require_command(&args.helm_bin, &["version", "--short"])?;
        require_command(&args.docker_bin, &["version"])?;
        require_command(&args.velero_bin, &["version", "--client-only"])?;
        if scenario.storage_path.uses_gateway() {
            helm_lint_gateway(&args.helm_bin)?;
        }
        prepare_velero_images(&args)?;
        if args.backend_mode == VeleroBackendMode::ClusterRustfs {
            prepare_rustfs_image(&args)?;
        }
        if matches!(scenario.volume, WorkloadVolume::DynamicPvc) {
            prepare_openebs_images(&args)?;
        }
        if matches!(scenario.workload, WorkloadKind::Postgres) {
            if args.postgres_row_count == 0 {
                bail!("--postgres-row-count must be greater than zero");
            }
            prepare_postgres_image(&args)?;
        }

        if scenario.storage_path.uses_rs3_image() && !args.skip_image_build {
            let target = if scenario.storage_path.uses_integration_storage_proxy() {
                "integration-tools"
            } else {
                "runtime"
            };
            let revision_arg = format!("REVISION={}", build_source_revision());
            run_command(
                &args.docker_bin,
                &[
                    "build",
                    "--build-arg",
                    revision_arg.as_str(),
                    "--target",
                    target,
                    "-t",
                    args.image.as_str(),
                    ".",
                ],
            )
            .context("failed to build gateway image")?;
        }

        let workspace = K8sWorkspace::new("rs3-velero-kopia-smoke")?;
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
                .unwrap_or_else(|| default_cluster_name("rs3-velero-ci"));
            KindCluster::create(
                args.kind_bin.clone(),
                cluster_name,
                workspace.kubeconfig_path(),
                args.keep_cluster,
                args.wait_secs,
            )?
        };
        if args.reuse_kind_cluster {
            reset_reused_cluster(&args, cluster.kubeconfig_path())?;
        }

        if scenario.storage_path.uses_rs3_image() && !args.skip_image_load {
            cluster.load_image(&args.image)?;
        }
        if !args.skip_velero_image_load {
            cluster.load_image(&args.velero_image)?;
            cluster.load_image(&args.velero_aws_plugin_image)?;
        }
        if args.backend_mode == VeleroBackendMode::ClusterRustfs && !args.skip_rustfs_image_load {
            cluster.load_image(&args.rustfs_image)?;
        }
        if matches!(scenario.volume, WorkloadVolume::DynamicPvc) && !args.skip_openebs_image_load {
            cluster.load_image(&args.openebs_provisioner_image)?;
            cluster.load_image(&args.openebs_helper_image)?;
        }
        if matches!(scenario.workload, WorkloadKind::Postgres) && !args.skip_postgres_image_load {
            cluster.load_image(&args.postgres_image)?;
        }
        if matches!(scenario.volume, WorkloadVolume::LocalPv) {
            prepare_local_pv_path(&args, cluster.name())?;
        }
        let context = RunContext::new(cluster.kubeconfig_path(), &workspace);

        let backend_prefix = backend.prefix.clone();
        let backend_endpoint = backend.endpoint.clone();
        let rustfs_host_port = rustfs_backend::service_host_port(&args.gateway_namespace);
        let anchor_name = format!("{}-checkpoint", helm_fullname(&args.release_name));
        let velero_target = velero_s3_target(&args, scenario.storage_path);
        let artifacts = ArtifactCollector::new(&args, scenario.label)?;
        let mut state = RunState::new(scenario, anchor_name.clone(), backend_prefix.clone());
        let result = (|| -> Result<()> {
            let kubeconfig_path = context.kubeconfig_path();
            let workspace = context.workspace();

            if args.backend_mode == VeleroBackendMode::ClusterRustfs {
                run_phase(&mut state, "install-rustfs", || {
                    rustfs_backend::install(&args, kubeconfig_path, workspace)
                })?;
                run_phase(&mut state, "create-backend-bucket", || {
                    rustfs_backend::create_bucket(&args, kubeconfig_path)
                })?;
            }
            if scenario.storage_path.uses_integration_storage_proxy() {
                run_phase(&mut state, "install-integration-storage-proxy", || {
                    integration_storage_proxy::install(
                        &args,
                        kubeconfig_path,
                        workspace,
                        &rustfs_host_port,
                    )
                })?;
            }
            if scenario.storage_path.uses_gateway() {
                run_phase(&mut state, "install-gateway", || {
                    let (image_repository, image_tag) = split_image_ref(&args.image);
                    helm_install_gateway(
                        &args.helm_bin,
                        kubeconfig_path,
                        &GatewayChartValues {
                            release_name: &args.release_name,
                            namespace: &args.gateway_namespace,
                            image_repository: &image_repository,
                            image_tag: &image_tag,
                            gateway_mode: "read-write",
                            public_bucket: VELERO_BUCKET,
                            backend_endpoint: &backend_endpoint,
                            backend_bucket: &backend.bucket,
                            backend_prefix: &backend_prefix,
                            backend_region: &backend.region,
                            backend_access_key_id: backend.access_key_id.as_deref(),
                            backend_secret_access_key: backend.secret_access_key.as_deref(),
                            anchor_mode: "kubernetes-lease",
                            anchor_name: &anchor_name,
                            log_format: "json",
                            rust_log: GATEWAY_RUST_LOG,
                            payload_segment_size: args.payload_segment_size,
                            retention_mode: args.repository_retention_mode.as_deref(),
                            retention_days: args.repository_retention_days,
                            repository_id: REPOSITORY_ID,
                            repository_salt_hex: REPOSITORY_SALT_HEX,
                            keyring_envelope_object_id: KEYRING_ENVELOPE_OBJECT_ID,
                            keyring_wrapping_key_id: KEYRING_WRAPPING_KEY_ID,
                            keyring_wrapping_key_hex: KEYRING_WRAPPING_KEY_HEX,
                            persistence_enabled: false,
                            wait_secs: args.wait_secs,
                        },
                    )
                })?;
            }

            if matches!(scenario.volume, WorkloadVolume::DynamicPvc) {
                run_phase(&mut state, "install-openebs", || {
                    install_openebs(&args, kubeconfig_path)
                })?;
            }

            run_phase(&mut state, "install-velero", || {
                let credentials_path = workspace.path("credentials-velero");
                write_velero_credentials(&credentials_path, &velero_target)?;
                install_velero(&args, kubeconfig_path, &credentials_path, &velero_target)
            })?;
            run_phase(&mut state, "apply-workload", || {
                apply_workload(&args, kubeconfig_path, workspace, scenario)
            })?;
            run_phase(&mut state, "write-workload-proof", || {
                write_workload_proof(&args, kubeconfig_path, scenario.workload)
            })?;
            run_phase(&mut state, "verify-workload-proof", || {
                assert_workload_proof(&args, kubeconfig_path, scenario.workload)
            })?;

            let backup_name = format!("rs3-smoke-{}", now_millis());
            let restore_name = format!("rs3-restore-{}", now_millis());
            state.backup_name = Some(backup_name.clone());
            state.restore_name = Some(restore_name.clone());
            run_phase(&mut state, "backup", || {
                create_backup(&args, kubeconfig_path, &backup_name)?;
                assert_velero_phase(
                    &args.kubectl_bin,
                    kubeconfig_path,
                    &args.velero_namespace,
                    "backups.velero.io",
                    &backup_name,
                    "Completed",
                )?;
                assert_pod_volume_backup_completed(&args, kubeconfig_path, &backup_name)
            })?;
            if let Err(error) =
                artifacts.collect_checkpoint(&args, kubeconfig_path, &state, "after-backup")
            {
                eprintln!("failed to collect after-backup checkpoint artifacts: {error:#}");
            }
            if scenario.storage_path.uses_gateway() {
                let anchor_name = state.anchor_name.clone();
                run_phase(&mut state, "assert-v2-anchor-after-backup", || {
                    assert_v2_gateway_anchor(&args, kubeconfig_path, &anchor_name)
                })?;
            }

            run_phase(&mut state, "delete-workload", || match scenario.volume {
                WorkloadVolume::EmptyDir | WorkloadVolume::DynamicPvc => {
                    delete_workload_namespace(&args, kubeconfig_path)
                }
                WorkloadVolume::LocalPv => {
                    remove_workload_proof(&args, kubeconfig_path, scenario.workload)?;
                    delete_workload_pod(&args, kubeconfig_path)
                }
            })?;
            if scenario.restart_gateway_before_restore && scenario.storage_path.uses_gateway() {
                if let Err(error) = artifacts.collect_checkpoint(
                    &args,
                    kubeconfig_path,
                    &state,
                    "before-gateway-restart",
                ) {
                    eprintln!("failed to collect pre-restart checkpoint artifacts: {error:#}");
                }
                run_phase(&mut state, "restart-gateway", || {
                    restart_gateway(&args, kubeconfig_path)
                })?;
                if let Err(error) = artifacts.collect_checkpoint(
                    &args,
                    kubeconfig_path,
                    &state,
                    "after-gateway-restart",
                ) {
                    eprintln!("failed to collect post-restart checkpoint artifacts: {error:#}");
                }
                if scenario.storage_path.uses_gateway() {
                    let anchor_name = state.anchor_name.clone();
                    run_phase(&mut state, "assert-v2-anchor-after-gateway-restart", || {
                        assert_v2_gateway_anchor(&args, kubeconfig_path, &anchor_name)
                    })?;
                }
            }
            let restore_readonly_counts_before = if scenario.restore_readonly_before_restore
                && scenario.storage_path.uses_gateway()
            {
                run_phase(&mut state, "switch-gateway-restore-readonly", || {
                    set_backup_storage_location_access_mode(&args, kubeconfig_path, "ReadOnly")?;
                    helm_set_gateway_mode(
                        &args.helm_bin,
                        kubeconfig_path,
                        &args.release_name,
                        &args.gateway_namespace,
                        "restore-readonly",
                        args.wait_secs,
                    )?;
                    wait_for_gateway_rollout(&args, kubeconfig_path)?;
                    gateway_backend_counts(&args, kubeconfig_path)
                })
                .map(Some)?
            } else {
                None
            };
            run_phase(&mut state, "restore", || {
                create_restore(&args, kubeconfig_path, &backup_name, &restore_name)?;
                assert_restore_phase(
                    &args,
                    kubeconfig_path,
                    &restore_name,
                    scenario.restore_readonly_before_restore,
                )?;
                assert_pod_volume_restore_completed(&args, kubeconfig_path, &restore_name)
            })?;
            if let Some(before) = restore_readonly_counts_before {
                run_phase(&mut state, "assert-restore-readonly-backend-writes", || {
                    let after = gateway_backend_counts(&args, kubeconfig_path)?;
                    assert_no_backend_writes_during_restore(&before, &after)
                })?;
            }
            run_phase(&mut state, "verify-restored-workload", || {
                wait_for_workload_available(&args, kubeconfig_path)?;
                wait_for_restored_proof(&args, kubeconfig_path, scenario.workload)
            })?;
            if let Err(error) =
                artifacts.collect_checkpoint(&args, kubeconfig_path, &state, "after-restore")
            {
                eprintln!("failed to collect after-restore checkpoint artifacts: {error:#}");
            }
            if scenario.storage_path.uses_gateway() {
                let anchor_name = state.anchor_name.clone();
                run_phase(&mut state, "assert-v2-anchor-after-restore", || {
                    assert_v2_gateway_anchor(&args, kubeconfig_path, &anchor_name)
                })?;
            }

            Ok(())
        })();

        if let Err(error) = artifacts.collect(&args, context.kubeconfig_path(), &state) {
            eprintln!("failed to collect Velero integration artifacts: {error:#}");
        }

        result?;
        cluster.delete()
    }

    fn assert_v2_gateway_anchor(
        args: &VeleroKopiaSmokeArgs,
        kubeconfig_path: &Path,
        anchor_name: &str,
    ) -> Result<()> {
        assert_v2_lease_anchor(
            &args.kubectl_bin,
            kubeconfig_path,
            &args.gateway_namespace,
            anchor_name,
        )
    }

    fn reset_reused_cluster(args: &VeleroKopiaSmokeArgs, kubeconfig_path: &Path) -> Result<()> {
        let timeout = timeout_arg(args.wait_secs);
        kubectl(
            &args.kubectl_bin,
            kubeconfig_path,
            &[
                "delete",
                "crd",
                "backuprepositories.velero.io",
                "backups.velero.io",
                "backupstoragelocations.velero.io",
                "deletebackuprequests.velero.io",
                "downloadrequests.velero.io",
                "podvolumebackups.velero.io",
                "podvolumerestores.velero.io",
                "restores.velero.io",
                "schedules.velero.io",
                "serverstatusrequests.velero.io",
                "volumesnapshotlocations.velero.io",
                "datadownloads.velero.io",
                "datauploads.velero.io",
                "--ignore-not-found=true",
                "--wait=true",
                "--timeout",
                timeout.as_str(),
            ],
        )
        .context("failed to delete old Velero CRDs in reused cluster")?;
        kubectl(
            &args.kubectl_bin,
            kubeconfig_path,
            &[
                "delete",
                "clusterrolebinding",
                "velero",
                "--ignore-not-found=true",
                "--wait=true",
                "--timeout",
                timeout.as_str(),
            ],
        )
        .context("failed to delete old Velero ClusterRoleBinding in reused cluster")?;
        kubectl(
            &args.kubectl_bin,
            kubeconfig_path,
            &[
                "delete",
                "clusterrole",
                "velero",
                "--ignore-not-found=true",
                "--wait=true",
                "--timeout",
                timeout.as_str(),
            ],
        )
        .context("failed to delete old Velero ClusterRole in reused cluster")?;
        kubectl(
            &args.kubectl_bin,
            kubeconfig_path,
            &[
                "delete",
                "namespace",
                &args.workload_namespace,
                &args.velero_namespace,
                &args.gateway_namespace,
                &args.openebs_namespace,
                "--ignore-not-found=true",
                "--wait=true",
                "--timeout",
                timeout.as_str(),
            ],
        )
        .context("failed to delete old namespaces in reused cluster")
    }

    fn install_openebs(args: &VeleroKopiaSmokeArgs, kubeconfig_path: &Path) -> Result<()> {
        let timeout = timeout_arg(args.wait_secs);
        let provisioner = chart_image(&args.openebs_provisioner_image)?;
        let helper = chart_image(&args.openebs_helper_image)?;
        run_command(
            &args.helm_bin,
            &[
                "--kubeconfig",
                path_str(kubeconfig_path)?,
                "upgrade",
                "--install",
                &args.openebs_release_name,
                &args.openebs_chart,
                "--namespace",
                &args.openebs_namespace,
                "--create-namespace",
                "--wait",
                "--timeout",
                timeout.as_str(),
                "--set-string",
                "global.imageRegistry=",
                "--set-string",
                "analytics.enabled=false",
                "--set-string",
                &format!("hostpathClass.name={}", args.openebs_storage_class),
                "--set-string",
                &format!("localpv.image.registry={}", provisioner.registry),
                "--set-string",
                &format!("localpv.image.repository={}", provisioner.repository),
                "--set-string",
                &format!("localpv.image.tag={}", provisioner.tag),
                "--set-string",
                &format!("helperPod.image.registry={}", helper.registry),
                "--set-string",
                &format!("helperPod.image.repository={}", helper.repository),
                "--set-string",
                &format!("helperPod.image.tag={}", helper.tag),
            ],
        )
        .context("failed to install OpenEBS LocalPV chart")?;

        kubectl(
            &args.kubectl_bin,
            kubeconfig_path,
            &[
                "-n",
                &args.openebs_namespace,
                "rollout",
                "status",
                &format!(
                    "deployment/{}-localpv-provisioner",
                    args.openebs_release_name
                ),
                "--timeout",
                timeout.as_str(),
            ],
        )
        .context("OpenEBS LocalPV provisioner did not become ready")?;
        kubectl(
            &args.kubectl_bin,
            kubeconfig_path,
            &["get", "storageclass", &args.openebs_storage_class],
        )
        .with_context(|| {
            format!(
                "OpenEBS StorageClass `{}` is unavailable",
                args.openebs_storage_class
            )
        })
    }

    struct ChartImage {
        registry: String,
        repository: String,
        tag: String,
    }

    fn chart_image(image: &str) -> Result<ChartImage> {
        let (repository, tag) = split_image_ref(image);
        if repository.contains('@') || tag.contains('@') {
            bail!("OpenEBS chart image `{image}` must use a tag, not a digest");
        }
        let (registry, repository) = repository.split_once('/').map_or_else(
            || ("", repository.as_str()),
            |(first, rest)| {
                if first == "localhost" || first.contains('.') || first.contains(':') {
                    (first, rest)
                } else {
                    ("", repository.as_str())
                }
            },
        );
        Ok(ChartImage {
            registry: registry.to_owned(),
            repository: repository.to_owned(),
            tag,
        })
    }

    fn restart_gateway(args: &VeleroKopiaSmokeArgs, kubeconfig_path: &Path) -> Result<()> {
        let deployment = format!("deployment/{}", helm_fullname(&args.release_name));
        kubectl(
            &args.kubectl_bin,
            kubeconfig_path,
            &[
                "-n",
                &args.gateway_namespace,
                "rollout",
                "restart",
                &deployment,
            ],
        )
        .context("failed to restart gateway deployment")?;
        wait_for_gateway_rollout(args, kubeconfig_path)?;
        assert_gateway_containers_never_restarted(args, kubeconfig_path)
    }

    fn wait_for_gateway_rollout(args: &VeleroKopiaSmokeArgs, kubeconfig_path: &Path) -> Result<()> {
        let timeout = timeout_arg(args.wait_secs);
        let deployment = format!("deployment/{}", helm_fullname(&args.release_name));
        kubectl(
            &args.kubectl_bin,
            kubeconfig_path,
            &[
                "-n",
                &args.gateway_namespace,
                "rollout",
                "status",
                &deployment,
                "--timeout",
                timeout.as_str(),
            ],
        )
        .context("gateway deployment did not become ready after restart")
    }

    fn assert_gateway_containers_never_restarted(
        args: &VeleroKopiaSmokeArgs,
        kubeconfig_path: &Path,
    ) -> Result<()> {
        let selector = format!(
            "app.kubernetes.io/name=rs3-gateway,app.kubernetes.io/instance={}",
            args.release_name
        );
        let output = kubectl_capture(
            &args.kubectl_bin,
            kubeconfig_path,
            &[
                "-n",
                &args.gateway_namespace,
                "get",
                "pods",
                "-l",
                &selector,
                "-o",
                r#"jsonpath={range .items[*].status.containerStatuses[*]}{.restartCount}{"\n"}{end}"#,
            ],
        )
        .context("failed to inspect gateway container restart counts")?;

        let mut observed = false;
        for raw_count in output.lines() {
            let count = raw_count.trim().parse::<u64>().with_context(|| {
                format!("gateway restart count `{raw_count}` was not an integer")
            })?;
            observed = true;
            if count != 0 {
                bail!("gateway container restarted {count} time(s) during rollout");
            }
        }
        if !observed {
            bail!("gateway rollout exposed no container restart count");
        }
        Ok(())
    }

    fn assert_no_backend_writes_during_restore(
        before: &BlobOperationCounts,
        after: &BlobOperationCounts,
    ) -> Result<()> {
        let put = after.put.saturating_sub(before.put);
        let delete = after.delete.saturating_sub(before.delete);
        let extend_retention = after
            .extend_retention
            .saturating_sub(before.extend_retention);
        let set_legal_hold = after.set_legal_hold.saturating_sub(before.set_legal_hold);
        let bytes_written = after.bytes_written.saturating_sub(before.bytes_written);
        if put == 0
            && delete == 0
            && extend_retention == 0
            && set_legal_hold == 0
            && bytes_written == 0
        {
            return Ok(());
        }
        bail!(
            "restore-readonly restore wrote to backend: put={put} delete={delete} extend_retention={extend_retention} set_legal_hold={set_legal_hold} bytes_written={bytes_written}"
        )
    }

    fn kubectl(kubectl_bin: &str, kubeconfig_path: &Path, args: &[&str]) -> Result<()> {
        let mut full_args = Vec::with_capacity(args.len() + 2);
        full_args.push("--kubeconfig");
        full_args.push(path_str(kubeconfig_path)?);
        full_args.extend_from_slice(args);
        run_command(kubectl_bin, &full_args)
    }

    fn kubectl_capture(kubectl_bin: &str, kubeconfig_path: &Path, args: &[&str]) -> Result<String> {
        let mut full_args = Vec::with_capacity(args.len() + 2);
        full_args.push("--kubeconfig");
        full_args.push(path_str(kubeconfig_path)?);
        full_args.extend_from_slice(args);
        run_command_capture(kubectl_bin, &full_args)
    }

    fn timeout_arg(wait_secs: u64) -> String {
        format!("{wait_secs}s")
    }
}
