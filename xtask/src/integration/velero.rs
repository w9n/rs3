//! Velero/Kopia restore integration harness.

use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

#[derive(Debug, Args)]
pub(crate) struct VeleroKopiaSmokeArgs {
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
    /// Plaintext bytes per encrypted payload segment.
    #[arg(long, default_value_t = rs3_repository::DEFAULT_PAYLOAD_SEGMENT_SIZE)]
    payload_segment_size: usize,
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

#[cfg(not(feature = "k8s"))]
pub(crate) fn run_velero_kopia_smoke(_args: VeleroKopiaSmokeArgs) -> Result<()> {
    anyhow::bail!(
        "Velero Kopia smoke integration requires `cargo run -p xtask --features k8s -- integration velero-kopia-smoke`",
    )
}

#[cfg(not(feature = "k8s"))]
pub(crate) fn run_velero_kopia_local_pv_smoke(_args: VeleroKopiaSmokeArgs) -> Result<()> {
    anyhow::bail!(
        "Velero Kopia local-PV smoke integration requires `cargo run -p xtask --features k8s -- integration velero-kopia-local-pv-smoke`",
    )
}

#[cfg(not(feature = "k8s"))]
pub(crate) fn run_velero_kopia_dynamic_pvc_smoke(_args: VeleroKopiaSmokeArgs) -> Result<()> {
    anyhow::bail!(
        "Velero Kopia dynamic-PVC smoke integration requires `cargo run -p xtask --features k8s -- integration velero-kopia-dynamic-pvc-smoke`",
    )
}

#[cfg(not(feature = "k8s"))]
pub(crate) fn run_velero_kopia_dynamic_pvc_gateway_restart_smoke(
    _args: VeleroKopiaSmokeArgs,
) -> Result<()> {
    anyhow::bail!(
        "Velero Kopia dynamic-PVC gateway-restart smoke integration requires `cargo run -p xtask --features k8s -- integration velero-kopia-dynamic-pvc-gateway-restart-smoke`",
    )
}

#[cfg(not(feature = "k8s"))]
pub(crate) fn run_velero_kopia_postgres_smoke(_args: VeleroKopiaSmokeArgs) -> Result<()> {
    anyhow::bail!(
        "Velero Kopia Postgres smoke integration requires `cargo run -p xtask --features k8s -- integration velero-kopia-postgres-smoke`",
    )
}

#[cfg(not(feature = "k8s"))]
pub(crate) fn run_velero_kopia_postgres_direct_smoke(_args: VeleroKopiaSmokeArgs) -> Result<()> {
    anyhow::bail!(
        "Velero Kopia Postgres direct RustFS smoke integration requires `cargo run -p xtask --features k8s -- integration velero-kopia-postgres-direct-smoke`",
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

    use super::VeleroKopiaSmokeArgs;
    use crate::integration::k8s_support::{
        CHART_PATH, GatewayChartValues, K8sWorkspace, KindCluster, default_cluster_name,
        helm_fullname, helm_install_gateway, now_millis, path_str, require_command, run_command,
        run_command_capture, split_image_ref,
    };
    use anyhow::{Context, Result, bail};
    use artifacts::ArtifactCollector;
    use images::{
        prepare_openebs_images, prepare_postgres_image, prepare_rustfs_image, prepare_velero_images,
    };
    use rustfs_backend::{
        BACKEND_BUCKET, BACKEND_REGION, RUSTFS_ACCESS_KEY_ID, RUSTFS_SECRET_ACCESS_KEY,
    };
    use scenario::{RunState, Scenario, WorkloadKind, WorkloadVolume};
    use std::path::{Path, PathBuf};
    use velero_cli::{
        assert_pod_volume_backup_completed, assert_pod_volume_restore_completed,
        assert_velero_phase, create_backup, create_restore, install_velero, velero_s3_target,
        write_velero_credentials,
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

    fn run(args: VeleroKopiaSmokeArgs, scenario: Scenario) -> Result<()> {
        require_command(&args.kind_bin, &["version"])?;
        require_command(&args.kubectl_bin, &["version", "--client"])?;
        require_command(&args.helm_bin, &["version", "--short"])?;
        require_command(&args.docker_bin, &["version"])?;
        require_command(&args.velero_bin, &["version", "--client-only"])?;
        if scenario.storage_path.uses_gateway() {
            run_command(&args.helm_bin, &["lint", CHART_PATH])
                .context("gateway Helm chart lint failed")?;
        }
        prepare_velero_images(&args)?;
        prepare_rustfs_image(&args)?;
        if matches!(scenario.volume, WorkloadVolume::DynamicPvc) {
            prepare_openebs_images(&args)?;
        }
        if matches!(scenario.workload, WorkloadKind::Postgres) {
            prepare_postgres_image(&args)?;
        }

        if scenario.storage_path.uses_rs3_image() && !args.skip_image_build {
            let mut build_args = vec!["build"];
            if scenario.storage_path.uses_integration_storage_proxy() {
                build_args.extend(["--target", "integration-tools"]);
            }
            build_args.extend(["-t", args.image.as_str(), "."]);
            run_command(&args.docker_bin, &build_args).context("failed to build gateway image")?;
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
        if !args.skip_rustfs_image_load {
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

        let backend_prefix = format!("repository-{}", now_millis());
        let backend_endpoint = rustfs_backend::service_endpoint(&args.gateway_namespace);
        let backend_target = rustfs_backend::service_host_port(&args.gateway_namespace);
        let anchor_name = format!("{}-checkpoint", helm_fullname(&args.release_name));
        let velero_target = velero_s3_target(&args, scenario.storage_path);
        let artifacts = ArtifactCollector::new(&args, scenario.label)?;
        let mut state = RunState::new(scenario, anchor_name.clone(), backend_prefix.clone());
        let result = (|| -> Result<()> {
            let kubeconfig_path = context.kubeconfig_path();
            let workspace = context.workspace();

            rustfs_backend::install(&args, kubeconfig_path, workspace)?;
            rustfs_backend::create_bucket(&args, kubeconfig_path)?;
            if scenario.storage_path.uses_integration_storage_proxy() {
                integration_storage_proxy::install(
                    &args,
                    kubeconfig_path,
                    workspace,
                    &backend_target,
                )?;
            }
            if scenario.storage_path.uses_gateway() {
                let (image_repository, image_tag) = split_image_ref(&args.image);
                helm_install_gateway(
                    &args.helm_bin,
                    kubeconfig_path,
                    &GatewayChartValues {
                        release_name: &args.release_name,
                        namespace: &args.gateway_namespace,
                        image_repository: &image_repository,
                        image_tag: &image_tag,
                        public_bucket: VELERO_BUCKET,
                        backend_endpoint: &backend_endpoint,
                        backend_bucket: BACKEND_BUCKET,
                        backend_prefix: &backend_prefix,
                        backend_region: BACKEND_REGION,
                        backend_access_key_id: Some(RUSTFS_ACCESS_KEY_ID),
                        backend_secret_access_key: Some(RUSTFS_SECRET_ACCESS_KEY),
                        anchor_mode: "kubernetes-lease",
                        anchor_name: &anchor_name,
                        log_format: "json",
                        rust_log: GATEWAY_RUST_LOG,
                        payload_segment_size: args.payload_segment_size,
                        persistence_enabled: false,
                        wait_secs: args.wait_secs,
                    },
                )?;
            }

            if matches!(scenario.volume, WorkloadVolume::DynamicPvc) {
                install_openebs(&args, kubeconfig_path)?;
            }

            let credentials_path = workspace.path("credentials-velero");
            write_velero_credentials(&credentials_path, &velero_target)?;
            install_velero(&args, kubeconfig_path, &credentials_path, &velero_target)?;
            apply_workload(&args, kubeconfig_path, workspace, scenario)?;
            write_workload_proof(&args, kubeconfig_path, scenario.workload)?;
            assert_workload_proof(&args, kubeconfig_path, scenario.workload)?;

            let backup_name = format!("rs3-smoke-{}", now_millis());
            let restore_name = format!("rs3-restore-{}", now_millis());
            state.backup_name = Some(backup_name.clone());
            state.restore_name = Some(restore_name.clone());
            create_backup(&args, kubeconfig_path, &backup_name)?;
            assert_velero_phase(
                &args.kubectl_bin,
                kubeconfig_path,
                &args.velero_namespace,
                "backups.velero.io",
                &backup_name,
                "Completed",
            )?;
            assert_pod_volume_backup_completed(&args, kubeconfig_path, &backup_name)?;
            if let Err(error) =
                artifacts.collect_checkpoint(&args, kubeconfig_path, &state, "after-backup")
            {
                eprintln!("failed to collect after-backup checkpoint artifacts: {error:#}");
            }

            match scenario.volume {
                WorkloadVolume::EmptyDir | WorkloadVolume::DynamicPvc => {
                    delete_workload_namespace(&args, kubeconfig_path)?;
                }
                WorkloadVolume::LocalPv => {
                    remove_workload_proof(&args, kubeconfig_path, scenario.workload)?;
                    delete_workload_pod(&args, kubeconfig_path)?;
                }
            }
            if scenario.restart_gateway_before_restore && scenario.storage_path.uses_gateway() {
                if let Err(error) = artifacts.collect_checkpoint(
                    &args,
                    kubeconfig_path,
                    &state,
                    "before-gateway-restart",
                ) {
                    eprintln!("failed to collect pre-restart checkpoint artifacts: {error:#}");
                }
                restart_gateway(&args, kubeconfig_path)?;
                if let Err(error) = artifacts.collect_checkpoint(
                    &args,
                    kubeconfig_path,
                    &state,
                    "after-gateway-restart",
                ) {
                    eprintln!("failed to collect post-restart checkpoint artifacts: {error:#}");
                }
            }
            create_restore(&args, kubeconfig_path, &backup_name, &restore_name)?;
            assert_velero_phase(
                &args.kubectl_bin,
                kubeconfig_path,
                &args.velero_namespace,
                "restores.velero.io",
                &restore_name,
                "Completed",
            )?;
            assert_pod_volume_restore_completed(&args, kubeconfig_path, &restore_name)?;
            wait_for_workload_available(&args, kubeconfig_path)?;
            wait_for_restored_proof(&args, kubeconfig_path, scenario.workload)?;
            if let Err(error) =
                artifacts.collect_checkpoint(&args, kubeconfig_path, &state, "after-restore")
            {
                eprintln!("failed to collect after-restore checkpoint artifacts: {error:#}");
            }

            Ok(())
        })();

        if let Err(error) = artifacts.collect(&args, context.kubeconfig_path(), &state) {
            eprintln!("failed to collect Velero integration artifacts: {error:#}");
        }

        result?;
        cluster.delete()
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
        let timeout = timeout_arg(args.wait_secs);
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
