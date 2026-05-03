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
mod imp {
    #[path = "velero_artifacts.rs"]
    mod artifacts;
    #[path = "rustfs_backend.rs"]
    mod rustfs_backend;

    use super::VeleroKopiaSmokeArgs;
    use crate::integration::k8s_support::{
        ACCESS_KEY_ID, CHART_PATH, GATEWAY_PORT, GatewayChartValues, K8sWorkspace, KindCluster,
        SECRET_ACCESS_KEY, default_cluster_name, helm_fullname, helm_install_gateway, now_millis,
        path_str, require_command, run_command, run_command_capture, split_image_ref,
    };
    use anyhow::{Context, Result, bail};
    use artifacts::ArtifactCollector;
    use rustfs_backend::{
        BACKEND_BUCKET, BACKEND_REGION, RUSTFS_ACCESS_KEY_ID, RUSTFS_SECRET_ACCESS_KEY,
    };
    use std::fs;
    use std::path::Path;
    use std::thread;
    use std::time::{Duration, Instant};

    const VELERO_BUCKET: &str = "velero";
    const WORKLOAD_NAME: &str = "rs3-velero-smoke";
    const LOCAL_PV_NAME: &str = "rs3-velero-smoke-local-pv";
    const LOCAL_STORAGE_CLASS: &str = "rs3-local";
    const LOCAL_PV_PATH: &str = "/var/local/rs3-velero-smoke-data";
    const PROOF_PATH: &str = "/data/proof.txt";
    const POSTGRES_DATA_PATH: &str = "/var/lib/postgresql/data";
    const POSTGRES_DUMP_PATH: &str = "/var/lib/postgresql/data/rs3-proof.sql";
    const POSTGRES_DB: &str = "rs3";
    const EXPECTED_CONTENT: &str = "rs3 velero kopia smoke\n";
    const GATEWAY_RUST_LOG: &str = "rs3_storage=debug,rs3_repository=info,rs3_server=info,info";

    #[derive(Clone, Copy, Debug)]
    enum WorkloadVolume {
        EmptyDir,
        LocalPv,
        DynamicPvc,
    }

    #[derive(Clone, Copy, Debug)]
    enum WorkloadKind {
        ProofFile,
        Postgres,
    }

    #[derive(Clone, Copy, Debug)]
    struct Scenario {
        label: &'static str,
        volume: WorkloadVolume,
        workload: WorkloadKind,
        restart_gateway_before_restore: bool,
    }

    #[derive(Debug)]
    struct RunState {
        scenario_label: &'static str,
        anchor_name: String,
        backend_prefix: String,
        backup_name: Option<String>,
        restore_name: Option<String>,
        started: Instant,
    }

    pub(super) fn run_empty_dir(args: VeleroKopiaSmokeArgs) -> Result<()> {
        run(
            args,
            Scenario {
                label: "empty-dir",
                volume: WorkloadVolume::EmptyDir,
                workload: WorkloadKind::ProofFile,
                restart_gateway_before_restore: false,
            },
        )
    }

    pub(super) fn run_local_pv(args: VeleroKopiaSmokeArgs) -> Result<()> {
        run(
            args,
            Scenario {
                label: "local-pv",
                volume: WorkloadVolume::LocalPv,
                workload: WorkloadKind::ProofFile,
                restart_gateway_before_restore: false,
            },
        )
    }

    pub(super) fn run_dynamic_pvc(args: VeleroKopiaSmokeArgs) -> Result<()> {
        run(
            args,
            Scenario {
                label: "dynamic-pvc",
                volume: WorkloadVolume::DynamicPvc,
                workload: WorkloadKind::ProofFile,
                restart_gateway_before_restore: false,
            },
        )
    }

    pub(super) fn run_dynamic_pvc_gateway_restart(args: VeleroKopiaSmokeArgs) -> Result<()> {
        run(
            args,
            Scenario {
                label: "dynamic-pvc-gateway-restart",
                volume: WorkloadVolume::DynamicPvc,
                workload: WorkloadKind::ProofFile,
                restart_gateway_before_restore: true,
            },
        )
    }

    pub(super) fn run_postgres(args: VeleroKopiaSmokeArgs) -> Result<()> {
        run(
            args,
            Scenario {
                label: "postgres",
                volume: WorkloadVolume::DynamicPvc,
                workload: WorkloadKind::Postgres,
                restart_gateway_before_restore: false,
            },
        )
    }

    fn run(args: VeleroKopiaSmokeArgs, scenario: Scenario) -> Result<()> {
        require_command(&args.kind_bin, &["version"])?;
        require_command(&args.kubectl_bin, &["version", "--client"])?;
        require_command(&args.helm_bin, &["version", "--short"])?;
        require_command(&args.docker_bin, &["version"])?;
        require_command(&args.velero_bin, &["version", "--client-only"])?;
        run_command(&args.helm_bin, &["lint", CHART_PATH])
            .context("gateway Helm chart lint failed")?;
        prepare_velero_images(&args)?;
        prepare_rustfs_image(&args)?;
        if matches!(scenario.volume, WorkloadVolume::DynamicPvc) {
            prepare_openebs_images(&args)?;
        }
        if matches!(scenario.workload, WorkloadKind::Postgres) {
            prepare_postgres_image(&args)?;
        }

        if !args.skip_image_build {
            run_command(&args.docker_bin, &["build", "-t", args.image.as_str(), "."])
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

        if !args.skip_image_load {
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

        let (image_repository, image_tag) = split_image_ref(&args.image);
        let backend_prefix = format!("repository-{}", now_millis());
        let backend_endpoint = rustfs_backend::service_endpoint(&args.gateway_namespace);
        let anchor_name = format!("{}-checkpoint", helm_fullname(&args.release_name));
        let artifacts = ArtifactCollector::new(&args, scenario.label)?;
        let mut state = RunState {
            scenario_label: scenario.label,
            anchor_name: anchor_name.clone(),
            backend_prefix: backend_prefix.clone(),
            backup_name: None,
            restore_name: None,
            started: Instant::now(),
        };
        let result = (|| -> Result<()> {
            rustfs_backend::install(&args, cluster.kubeconfig_path(), &workspace)?;
            rustfs_backend::create_bucket(&args, cluster.kubeconfig_path())?;
            helm_install_gateway(
                &args.helm_bin,
                cluster.kubeconfig_path(),
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
                    persistence_enabled: false,
                    wait_secs: args.wait_secs,
                },
            )?;

            if matches!(scenario.volume, WorkloadVolume::DynamicPvc) {
                install_openebs(&args, cluster.kubeconfig_path())?;
            }

            let credentials_path = workspace.path("credentials-velero");
            write_velero_credentials(&credentials_path)?;
            install_velero(&args, cluster.kubeconfig_path(), &credentials_path)?;
            apply_workload(&args, cluster.kubeconfig_path(), &workspace, scenario)?;
            write_workload_proof(&args, cluster.kubeconfig_path(), scenario.workload)?;
            assert_workload_proof(&args, cluster.kubeconfig_path(), scenario.workload)?;

            let backup_name = format!("rs3-smoke-{}", now_millis());
            let restore_name = format!("rs3-restore-{}", now_millis());
            state.backup_name = Some(backup_name.clone());
            state.restore_name = Some(restore_name.clone());
            create_backup(&args, cluster.kubeconfig_path(), &backup_name)?;
            assert_velero_phase(
                &args.kubectl_bin,
                cluster.kubeconfig_path(),
                &args.velero_namespace,
                "backups.velero.io",
                &backup_name,
                "Completed",
            )?;
            assert_pod_volume_backup_completed(&args, cluster.kubeconfig_path(), &backup_name)?;
            if let Err(error) = artifacts.collect_checkpoint(
                &args,
                cluster.kubeconfig_path(),
                &state,
                "after-backup",
            ) {
                eprintln!("failed to collect after-backup checkpoint artifacts: {error:#}");
            }

            match scenario.volume {
                WorkloadVolume::EmptyDir | WorkloadVolume::DynamicPvc => {
                    delete_workload_namespace(&args, cluster.kubeconfig_path())?;
                }
                WorkloadVolume::LocalPv => {
                    remove_workload_proof(&args, cluster.kubeconfig_path(), scenario.workload)?;
                    delete_workload_pod(&args, cluster.kubeconfig_path())?;
                }
            }
            if scenario.restart_gateway_before_restore {
                if let Err(error) = artifacts.collect_checkpoint(
                    &args,
                    cluster.kubeconfig_path(),
                    &state,
                    "before-gateway-restart",
                ) {
                    eprintln!("failed to collect pre-restart checkpoint artifacts: {error:#}");
                }
                restart_gateway(&args, cluster.kubeconfig_path())?;
                if let Err(error) = artifacts.collect_checkpoint(
                    &args,
                    cluster.kubeconfig_path(),
                    &state,
                    "after-gateway-restart",
                ) {
                    eprintln!("failed to collect post-restart checkpoint artifacts: {error:#}");
                }
            }
            create_restore(
                &args,
                cluster.kubeconfig_path(),
                &backup_name,
                &restore_name,
            )?;
            assert_velero_phase(
                &args.kubectl_bin,
                cluster.kubeconfig_path(),
                &args.velero_namespace,
                "restores.velero.io",
                &restore_name,
                "Completed",
            )?;
            assert_pod_volume_restore_completed(&args, cluster.kubeconfig_path(), &restore_name)?;
            wait_for_workload_available(&args, cluster.kubeconfig_path())?;
            wait_for_restored_proof(&args, cluster.kubeconfig_path(), scenario.workload)?;
            if let Err(error) = artifacts.collect_checkpoint(
                &args,
                cluster.kubeconfig_path(),
                &state,
                "after-restore",
            ) {
                eprintln!("failed to collect after-restore checkpoint artifacts: {error:#}");
            }

            Ok(())
        })();

        if let Err(error) = artifacts.collect(&args, cluster.kubeconfig_path(), &state) {
            eprintln!("failed to collect Velero integration artifacts: {error:#}");
        }

        result?;
        cluster.delete()
    }

    fn prepare_velero_images(args: &VeleroKopiaSmokeArgs) -> Result<()> {
        if args.skip_velero_image_load {
            return Ok(());
        }

        for image in [&args.velero_image, &args.velero_aws_plugin_image] {
            if docker_image_exists(&args.docker_bin, image)? {
                continue;
            }
            if args.pull_velero_images {
                run_command(&args.docker_bin, &["pull", image]).with_context(|| {
                    format!(
                        "failed to pull Velero image `{image}`; authenticate Docker or pass a mirror image if the registry rate-limits pulls",
                    )
                })?;
                continue;
            }

            bail!(
                "Velero image `{image}` is not present locally. Pull or mirror it first, pass `--pull-velero-images`, or pass `--skip-velero-image-load` to let the cluster pull it directly."
            );
        }

        Ok(())
    }

    fn prepare_rustfs_image(args: &VeleroKopiaSmokeArgs) -> Result<()> {
        if args.skip_rustfs_image_load {
            return Ok(());
        }
        if docker_image_exists(&args.docker_bin, &args.rustfs_image)? {
            return Ok(());
        }
        if args.pull_rustfs_image {
            run_command(&args.docker_bin, &["pull", &args.rustfs_image]).with_context(|| {
                format!(
                    "failed to pull RustFS image `{}`; authenticate Docker or pass a mirror image if the registry rate-limits pulls",
                    args.rustfs_image,
                )
            })?;
            return Ok(());
        }

        bail!(
            "RustFS image `{}` is not present locally. Pull or mirror it first, pass `--pull-rustfs-image`, or pass `--skip-rustfs-image-load` to let the cluster pull it directly.",
            args.rustfs_image,
        );
    }

    fn prepare_openebs_images(args: &VeleroKopiaSmokeArgs) -> Result<()> {
        if args.skip_openebs_image_load {
            return Ok(());
        }

        for image in [&args.openebs_provisioner_image, &args.openebs_helper_image] {
            if docker_image_exists(&args.docker_bin, image)? {
                continue;
            }
            if args.pull_openebs_images {
                run_command(&args.docker_bin, &["pull", image]).with_context(|| {
                    format!(
                        "failed to pull OpenEBS image `{image}`; authenticate Docker or pass a mirror image if the registry rate-limits pulls",
                    )
                })?;
                continue;
            }

            bail!(
                "OpenEBS image `{image}` is not present locally. Pull or mirror it first, pass `--pull-openebs-images`, or pass `--skip-openebs-image-load` to let the cluster pull it directly."
            );
        }

        Ok(())
    }

    fn prepare_postgres_image(args: &VeleroKopiaSmokeArgs) -> Result<()> {
        if args.skip_postgres_image_load || args.postgres_image == args.image {
            return Ok(());
        }
        if docker_image_exists(&args.docker_bin, &args.postgres_image)? {
            return Ok(());
        }
        if args.pull_postgres_image {
            run_command(&args.docker_bin, &["pull", &args.postgres_image]).with_context(|| {
                format!(
                    "failed to pull Postgres image `{}`; authenticate Docker or pass a mirror image if the registry rate-limits pulls",
                    args.postgres_image,
                )
            })?;
            return Ok(());
        }

        bail!(
            "Postgres image `{}` is not present locally. Pull or mirror it first, pass `--pull-postgres-image`, or pass `--skip-postgres-image-load` to let the cluster pull it directly.",
            args.postgres_image,
        );
    }

    fn docker_image_exists(docker_bin: &str, image: &str) -> Result<bool> {
        let result = run_command_capture(
            docker_bin,
            &["image", "inspect", image, "--format", "{{.Id}}"],
        );
        match result {
            Ok(_) => Ok(true),
            Err(error) => {
                let message = error.to_string();
                if message.contains("No such image") || message.contains("No such object") {
                    Ok(false)
                } else {
                    Err(error).with_context(|| format!("failed to inspect Docker image `{image}`"))
                }
            }
        }
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

    fn prepare_local_pv_path(args: &VeleroKopiaSmokeArgs, cluster_name: &str) -> Result<()> {
        let node_container = format!("{cluster_name}-control-plane");
        run_command(
            &args.docker_bin,
            &["exec", &node_container, "mkdir", "-p", LOCAL_PV_PATH],
        )
        .with_context(|| format!("failed to create local PV path in `{node_container}`"))?;
        run_command(
            &args.docker_bin,
            &["exec", &node_container, "chmod", "0777", LOCAL_PV_PATH],
        )
        .with_context(|| format!("failed to make local PV path writable in `{node_container}`"))
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

    fn write_velero_credentials(path: &Path) -> Result<()> {
        fs::write(
            path,
            format!(
                "[default]\naws_access_key_id={ACCESS_KEY_ID}\naws_secret_access_key={SECRET_ACCESS_KEY}\n"
            ),
        )
        .with_context(|| format!("failed to write {}", path.display()))
    }

    fn install_velero(
        args: &VeleroKopiaSmokeArgs,
        kubeconfig_path: &Path,
        credentials_path: &Path,
    ) -> Result<()> {
        let service_name = helm_fullname(&args.release_name);
        let s3_url = format!(
            "http://{}.{gateway_namespace}.svc:{GATEWAY_PORT}",
            service_name,
            gateway_namespace = args.gateway_namespace
        );
        let backup_location_config =
            format!("region=us-east-1,s3ForcePathStyle=true,s3Url={s3_url},checksumAlgorithm=");

        velero(
            &args.velero_bin,
            kubeconfig_path,
            &[
                "install",
                "--namespace",
                &args.velero_namespace,
                "--image",
                &args.velero_image,
                "--provider",
                "aws",
                "--plugins",
                &args.velero_aws_plugin_image,
                "--bucket",
                VELERO_BUCKET,
                "--secret-file",
                path_str(credentials_path)?,
                "--use-volume-snapshots=false",
                "--use-node-agent",
                "--uploader-type",
                "kopia",
                "--wait",
                "--backup-location-config",
                &backup_location_config,
            ],
        )
        .context("failed to install Velero")?;

        let timeout = timeout_arg(args.wait_secs);
        kubectl(
            &args.kubectl_bin,
            kubeconfig_path,
            &[
                "-n",
                &args.velero_namespace,
                "rollout",
                "status",
                "daemonset/node-agent",
                "--timeout",
                timeout.as_str(),
            ],
        )
        .context("Velero node-agent did not become ready")?;
        kubectl(
            &args.kubectl_bin,
            kubeconfig_path,
            &[
                "-n",
                &args.velero_namespace,
                "wait",
                "--for=jsonpath={.status.phase}=Available",
                "backupstoragelocations.velero.io/default",
                "--timeout",
                timeout.as_str(),
            ],
        )
        .context("Velero backup storage location did not become available")
    }

    fn apply_workload(
        args: &VeleroKopiaSmokeArgs,
        kubeconfig_path: &Path,
        workspace: &K8sWorkspace,
        scenario: Scenario,
    ) -> Result<()> {
        let manifest_path = workspace.path("workload.yaml");
        let node_name = match scenario.volume {
            WorkloadVolume::EmptyDir | WorkloadVolume::DynamicPvc => None,
            WorkloadVolume::LocalPv => Some(first_node_name(args, kubeconfig_path)?),
        };
        fs::write(
            &manifest_path,
            workload_manifest(args, scenario, node_name.as_deref()),
        )
        .with_context(|| format!("failed to write {}", manifest_path.display()))?;
        kubectl(
            &args.kubectl_bin,
            kubeconfig_path,
            &["apply", "-f", path_str(&manifest_path)?],
        )
        .context("failed to apply Velero smoke workload")?;
        wait_for_workload_available(args, kubeconfig_path)
    }

    fn first_node_name(args: &VeleroKopiaSmokeArgs, kubeconfig_path: &Path) -> Result<String> {
        let node_name = kubectl_capture(
            &args.kubectl_bin,
            kubeconfig_path,
            &["get", "nodes", "-o", "jsonpath={.items[0].metadata.name}"],
        )
        .context("failed to read kind node name")?;
        if node_name.trim().is_empty() {
            bail!("cluster has no Kubernetes nodes");
        }
        Ok(node_name)
    }

    fn workload_manifest(
        args: &VeleroKopiaSmokeArgs,
        scenario: Scenario,
        node_name: Option<&str>,
    ) -> String {
        let workload_image = workload_image(args, scenario.workload);
        let volume_resources = match scenario.volume {
            WorkloadVolume::EmptyDir => String::new(),
            WorkloadVolume::LocalPv => local_pv_resources(args, node_name.expect("node name")),
            WorkloadVolume::DynamicPvc => dynamic_pvc_resources(args),
        };
        let volume_spec = match scenario.volume {
            WorkloadVolume::EmptyDir => "emptyDir: {}".to_owned(),
            WorkloadVolume::LocalPv | WorkloadVolume::DynamicPvc => {
                "persistentVolumeClaim:\n        claimName: data".to_owned()
            }
        };
        let annotations = workload_annotations(scenario.workload);
        let container_spec = workload_container_spec(scenario.workload, workload_image);
        format!(
            r#"apiVersion: v1
kind: Namespace
metadata:
  name: {namespace}
{volume_resources}
---
apiVersion: v1
kind: Pod
metadata:
  name: {name}
  namespace: {namespace}
  annotations:
{annotations}
  labels:
    app.kubernetes.io/name: {name}
spec:
  containers:
{container_spec}
  volumes:
    - name: data
      {volume_spec}
"#,
            annotations = annotations,
            container_spec = container_spec,
            name = WORKLOAD_NAME,
            namespace = args.workload_namespace,
            volume_resources = volume_resources,
            volume_spec = volume_spec,
        )
    }

    fn workload_image(args: &VeleroKopiaSmokeArgs, workload: WorkloadKind) -> &str {
        match workload {
            WorkloadKind::ProofFile => args.workload_image.as_deref().unwrap_or(&args.image),
            WorkloadKind::Postgres => args
                .workload_image
                .as_deref()
                .unwrap_or(&args.postgres_image),
        }
    }

    fn workload_annotations(workload: WorkloadKind) -> &'static str {
        match workload {
            WorkloadKind::ProofFile => "    backup.velero.io/backup-volumes: data",
            WorkloadKind::Postgres => {
                r#"    backup.velero.io/backup-volumes: data
    pre.hook.backup.velero.io/container: postgres
    pre.hook.backup.velero.io/command: '["/bin/sh","-c","psql -U postgres -d rs3 -v ON_ERROR_STOP=1 -c \"CHECKPOINT\" && pg_dump -U postgres -d rs3 -f /var/lib/postgresql/data/rs3-proof.sql && sync"]'
    pre.hook.backup.velero.io/timeout: 60s"#
            }
        }
    }

    fn workload_container_spec(workload: WorkloadKind, image: &str) -> String {
        match workload {
            WorkloadKind::ProofFile => format!(
                r#"    - name: workload
      image: {image}
      imagePullPolicy: IfNotPresent
      command:
        - /bin/sh
        - -c
        - sleep 3600
      volumeMounts:
        - name: data
          mountPath: /data"#,
            ),
            WorkloadKind::Postgres => format!(
                r#"    - name: postgres
      image: {image}
      imagePullPolicy: IfNotPresent
      env:
        - name: POSTGRES_DB
          value: {db}
        - name: POSTGRES_USER
          value: postgres
        - name: POSTGRES_HOST_AUTH_METHOD
          value: trust
        - name: PGDATA
          value: {data_path}/pgdata
      ports:
        - name: postgres
          containerPort: 5432
      readinessProbe:
        exec:
          command:
            - pg_isready
            - -U
            - postgres
            - -d
            - {db}
        periodSeconds: 2
        failureThreshold: 30
      volumeMounts:
        - name: data
          mountPath: {data_path}"#,
                data_path = POSTGRES_DATA_PATH,
                db = POSTGRES_DB,
            ),
        }
    }

    fn dynamic_pvc_resources(args: &VeleroKopiaSmokeArgs) -> String {
        format!(
            r#"
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: data
  namespace: {namespace}
  labels:
    app.kubernetes.io/name: {name}
spec:
  storageClassName: {storage_class}
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 64Mi
"#,
            name = WORKLOAD_NAME,
            namespace = args.workload_namespace,
            storage_class = args.openebs_storage_class,
        )
    }

    fn local_pv_resources(args: &VeleroKopiaSmokeArgs, node_name: &str) -> String {
        format!(
            r#"
---
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: {storage_class}
provisioner: kubernetes.io/no-provisioner
volumeBindingMode: WaitForFirstConsumer
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: {pv_name}
  labels:
    app.kubernetes.io/name: {name}
spec:
  capacity:
    storage: 64Mi
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Retain
  storageClassName: {storage_class}
  local:
    path: {local_path}
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
            - key: kubernetes.io/hostname
              operator: In
              values:
                - {node_name}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: data
  namespace: {namespace}
  labels:
    app.kubernetes.io/name: {name}
spec:
  storageClassName: {storage_class}
  volumeName: {pv_name}
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 64Mi
"#,
            local_path = LOCAL_PV_PATH,
            name = WORKLOAD_NAME,
            namespace = args.workload_namespace,
            node_name = node_name,
            pv_name = LOCAL_PV_NAME,
            storage_class = LOCAL_STORAGE_CLASS,
        )
    }

    fn wait_for_workload_available(
        args: &VeleroKopiaSmokeArgs,
        kubeconfig_path: &Path,
    ) -> Result<()> {
        let timeout = timeout_arg(args.wait_secs);
        kubectl(
            &args.kubectl_bin,
            kubeconfig_path,
            &[
                "-n",
                &args.workload_namespace,
                "wait",
                "--for=condition=Ready",
                &format!("pod/{WORKLOAD_NAME}"),
                "--timeout",
                timeout.as_str(),
            ],
        )
        .context("Velero smoke workload did not become available")
    }

    fn write_workload_proof(
        args: &VeleroKopiaSmokeArgs,
        kubeconfig_path: &Path,
        workload: WorkloadKind,
    ) -> Result<()> {
        match workload {
            WorkloadKind::ProofFile => kubectl(
                &args.kubectl_bin,
                kubeconfig_path,
                &[
                    "-n",
                    &args.workload_namespace,
                    "exec",
                    &format!("pod/{WORKLOAD_NAME}"),
                    "--",
                    "/bin/sh",
                    "-c",
                    &format!("printf '{EXPECTED_CONTENT}' > {PROOF_PATH} && sync"),
                ],
            )
            .context("failed to write Velero smoke proof file"),
            WorkloadKind::Postgres => kubectl(
                &args.kubectl_bin,
                kubeconfig_path,
                &[
                    "-n",
                    &args.workload_namespace,
                    "exec",
                    &format!("pod/{WORKLOAD_NAME}"),
                    "-c",
                    "postgres",
                    "--",
                    "/bin/sh",
                    "-c",
                    &postgres_write_script(),
                ],
            )
            .context("failed to write Postgres smoke proof data"),
        }
    }

    fn assert_workload_proof(
        args: &VeleroKopiaSmokeArgs,
        kubeconfig_path: &Path,
        workload: WorkloadKind,
    ) -> Result<()> {
        let actual = read_workload_proof(args, kubeconfig_path, workload)
            .context("failed to read Velero smoke proof")?;
        match workload {
            WorkloadKind::ProofFile if actual != EXPECTED_CONTENT => {
                bail!("Velero smoke proof file mismatch before backup");
            }
            WorkloadKind::Postgres if actual.trim() != "ok" => {
                bail!("Postgres smoke proof mismatch before backup: {actual:?}");
            }
            _ => {}
        }
        Ok(())
    }

    fn read_workload_proof(
        args: &VeleroKopiaSmokeArgs,
        kubeconfig_path: &Path,
        workload: WorkloadKind,
    ) -> Result<String> {
        match workload {
            WorkloadKind::ProofFile => kubectl_capture(
                &args.kubectl_bin,
                kubeconfig_path,
                &[
                    "-n",
                    &args.workload_namespace,
                    "exec",
                    &format!("pod/{WORKLOAD_NAME}"),
                    "--",
                    "cat",
                    PROOF_PATH,
                ],
            ),
            WorkloadKind::Postgres => kubectl_capture(
                &args.kubectl_bin,
                kubeconfig_path,
                &[
                    "-n",
                    &args.workload_namespace,
                    "exec",
                    &format!("pod/{WORKLOAD_NAME}"),
                    "-c",
                    "postgres",
                    "--",
                    "/bin/sh",
                    "-c",
                    &postgres_verify_script(),
                ],
            ),
        }
    }

    fn remove_workload_proof(
        args: &VeleroKopiaSmokeArgs,
        kubeconfig_path: &Path,
        workload: WorkloadKind,
    ) -> Result<()> {
        match workload {
            WorkloadKind::ProofFile => kubectl(
                &args.kubectl_bin,
                kubeconfig_path,
                &[
                    "-n",
                    &args.workload_namespace,
                    "exec",
                    &format!("pod/{WORKLOAD_NAME}"),
                    "--",
                    "rm",
                    "-f",
                    PROOF_PATH,
                ],
            )
            .context("failed to remove original local-PV proof file before restore"),
            WorkloadKind::Postgres => kubectl(
                &args.kubectl_bin,
                kubeconfig_path,
                &[
                    "-n",
                    &args.workload_namespace,
                    "exec",
                    &format!("pod/{WORKLOAD_NAME}"),
                    "-c",
                    "postgres",
                    "--",
                    "/bin/sh",
                    "-c",
                    "rm -f /var/lib/postgresql/data/rs3-proof.sql",
                ],
            )
            .context("failed to remove original Postgres proof file before restore"),
        }
    }

    fn postgres_write_script() -> String {
        format!(
            "psql -U postgres -d {POSTGRES_DB} -v ON_ERROR_STOP=1 -c \"DROP TABLE IF EXISTS proof; CREATE TABLE proof(id integer PRIMARY KEY, value text NOT NULL); INSERT INTO proof SELECT i, 'row-' || lpad(i::text, 4, '0') FROM generate_series(0, 127) AS i; CHECKPOINT;\" && pg_dump -U postgres -d {POSTGRES_DB} -f {POSTGRES_DUMP_PATH} && sync",
        )
    }

    fn postgres_verify_script() -> String {
        format!(
            "test -s {POSTGRES_DUMP_PATH} && psql -U postgres -d {POSTGRES_DB} -v ON_ERROR_STOP=1 -At -c \"SELECT CASE WHEN (SELECT count(*) FROM proof) = 128 AND (SELECT md5(string_agg(value, ',' ORDER BY id)) FROM proof) = (SELECT md5(string_agg('row-' || lpad(i::text, 4, '0'), ',' ORDER BY i)) FROM generate_series(0, 127) AS i) THEN 'ok' ELSE 'bad' END;\"",
        )
    }

    fn create_backup(
        args: &VeleroKopiaSmokeArgs,
        kubeconfig_path: &Path,
        backup_name: &str,
    ) -> Result<()> {
        velero(
            &args.velero_bin,
            kubeconfig_path,
            &[
                "--namespace",
                &args.velero_namespace,
                "backup",
                "create",
                backup_name,
                "--include-namespaces",
                &args.workload_namespace,
                "--snapshot-volumes=false",
                "--default-volumes-to-fs-backup",
                "--wait",
            ],
        )
        .context("Velero backup failed")
    }

    fn delete_workload_namespace(
        args: &VeleroKopiaSmokeArgs,
        kubeconfig_path: &Path,
    ) -> Result<()> {
        let timeout = timeout_arg(args.wait_secs);
        kubectl(
            &args.kubectl_bin,
            kubeconfig_path,
            &[
                "delete",
                "namespace",
                &args.workload_namespace,
                "--wait=true",
                "--timeout",
                timeout.as_str(),
            ],
        )
        .context("failed to delete Velero smoke workload namespace")
    }

    fn delete_workload_pod(args: &VeleroKopiaSmokeArgs, kubeconfig_path: &Path) -> Result<()> {
        let timeout = timeout_arg(args.wait_secs);
        kubectl(
            &args.kubectl_bin,
            kubeconfig_path,
            &[
                "-n",
                &args.workload_namespace,
                "delete",
                "pod",
                WORKLOAD_NAME,
                "--wait=true",
                "--timeout",
                timeout.as_str(),
            ],
        )
        .context("failed to delete Velero smoke workload pod")
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

    fn create_restore(
        args: &VeleroKopiaSmokeArgs,
        kubeconfig_path: &Path,
        backup_name: &str,
        restore_name: &str,
    ) -> Result<()> {
        velero(
            &args.velero_bin,
            kubeconfig_path,
            &[
                "--namespace",
                &args.velero_namespace,
                "restore",
                "create",
                restore_name,
                "--from-backup",
                backup_name,
                "--wait",
            ],
        )
        .context("Velero restore failed")
    }

    fn assert_pod_volume_backup_completed(
        args: &VeleroKopiaSmokeArgs,
        kubeconfig_path: &Path,
        backup_name: &str,
    ) -> Result<()> {
        let phases = pod_volume_phases(
            args,
            kubeconfig_path,
            "podvolumebackups.velero.io",
            "velero.io/backup-name",
            backup_name,
        )
        .context("failed to read Velero pod volume backup status")?;
        if has_completed_phase(&phases) {
            return Ok(());
        }

        let diagnostics = velero_diagnostics(args, kubeconfig_path)?;
        bail!(
            "Velero backup {backup_name} completed without a completed pod-volume backup\npodvolumebackups:\n{phases}\n{diagnostics}"
        );
    }

    fn assert_pod_volume_restore_completed(
        args: &VeleroKopiaSmokeArgs,
        kubeconfig_path: &Path,
        restore_name: &str,
    ) -> Result<()> {
        let phases = pod_volume_phases(
            args,
            kubeconfig_path,
            "podvolumerestores.velero.io",
            "velero.io/restore-name",
            restore_name,
        )
        .context("failed to read Velero pod volume restore status")?;
        if has_completed_phase(&phases) {
            return Ok(());
        }

        let diagnostics = velero_diagnostics(args, kubeconfig_path)?;
        bail!(
            "Velero restore {restore_name} completed without a completed pod-volume restore\npodvolumerestores:\n{phases}\n{diagnostics}"
        );
    }

    fn pod_volume_phases(
        args: &VeleroKopiaSmokeArgs,
        kubeconfig_path: &Path,
        resource: &str,
        label: &str,
        label_value: &str,
    ) -> Result<String> {
        let output = kubectl_capture(
            &args.kubectl_bin,
            kubeconfig_path,
            &[
                "-n",
                &args.velero_namespace,
                "get",
                resource,
                "-l",
                &format!("{label}={label_value}"),
                "-o",
                "jsonpath={range .items[*]}{.metadata.name}:{.status.phase}{\"\\n\"}{end}",
            ],
        )?;
        Ok(if output.trim().is_empty() {
            "<none>\n".to_owned()
        } else {
            output
        })
    }

    fn has_completed_phase(phases: &str) -> bool {
        phases.lines().any(|line| {
            line.split_once(':')
                .is_some_and(|(_, phase)| phase == "Completed")
        })
    }

    fn wait_for_restored_proof(
        args: &VeleroKopiaSmokeArgs,
        kubeconfig_path: &Path,
        workload: WorkloadKind,
    ) -> Result<()> {
        let started = Instant::now();
        loop {
            match read_workload_proof(args, kubeconfig_path, workload) {
                Ok(actual) if proof_matches(workload, &actual) => return Ok(()),
                Ok(_) | Err(_) if started.elapsed() <= Duration::from_secs(args.wait_secs) => {
                    thread::sleep(Duration::from_secs(2));
                }
                Ok(_) => bail!("restored Velero smoke proof file had unexpected content"),
                Err(error) => {
                    let diagnostics =
                        velero_diagnostics(args, kubeconfig_path).unwrap_or_else(|diag_error| {
                            format!("diagnostics unavailable: {diag_error:#}")
                        });
                    return Err(error).context(format!(
                        "failed to read restored Velero proof file\n{diagnostics}"
                    ));
                }
            }
        }
    }

    fn proof_matches(workload: WorkloadKind, actual: &str) -> bool {
        match workload {
            WorkloadKind::ProofFile => actual == EXPECTED_CONTENT,
            WorkloadKind::Postgres => actual.trim() == "ok",
        }
    }

    fn velero_diagnostics(args: &VeleroKopiaSmokeArgs, kubeconfig_path: &Path) -> Result<String> {
        let mut out = String::new();
        append_diagnostic(
            &mut out,
            "pod-volume resources",
            kubectl_capture(
                &args.kubectl_bin,
                kubeconfig_path,
                &[
                    "-n",
                    &args.velero_namespace,
                    "get",
                    "podvolumebackups.velero.io,podvolumerestores.velero.io,backuprepositories.velero.io",
                    "-o",
                    "wide",
                ],
            ),
        );
        append_diagnostic(
            &mut out,
            "workload pods",
            kubectl_capture(
                &args.kubectl_bin,
                kubeconfig_path,
                &["-n", &args.workload_namespace, "get", "pods", "-o", "wide"],
            ),
        );
        append_diagnostic(
            &mut out,
            "velero log tail",
            kubectl_capture(
                &args.kubectl_bin,
                kubeconfig_path,
                &[
                    "-n",
                    &args.velero_namespace,
                    "logs",
                    "deployment/velero",
                    "--tail=120",
                ],
            ),
        );
        append_diagnostic(
            &mut out,
            "node-agent log tail",
            kubectl_capture(
                &args.kubectl_bin,
                kubeconfig_path,
                &[
                    "-n",
                    &args.velero_namespace,
                    "logs",
                    "daemonset/node-agent",
                    "--tail=120",
                ],
            ),
        );
        Ok(out)
    }

    fn append_diagnostic(out: &mut String, title: &str, result: Result<String>) {
        out.push_str("\n== ");
        out.push_str(title);
        out.push_str(" ==\n");
        match result {
            Ok(value) if value.trim().is_empty() => out.push_str("<empty>\n"),
            Ok(value) => out.push_str(&value),
            Err(error) => out.push_str(&format!("unavailable: {error:#}\n")),
        }
    }

    fn assert_velero_phase(
        kubectl_bin: &str,
        kubeconfig_path: &Path,
        namespace: &str,
        resource: &str,
        name: &str,
        expected: &str,
    ) -> Result<()> {
        let phase = kubectl_capture(
            kubectl_bin,
            kubeconfig_path,
            &[
                "-n",
                namespace,
                "get",
                resource,
                name,
                "-o",
                "jsonpath={.status.phase}",
            ],
        )
        .with_context(|| format!("failed to read phase for {resource}/{name}"))?;
        if phase != expected {
            bail!("{resource}/{name} phase was {phase:?}, expected {expected:?}");
        }
        Ok(())
    }

    fn velero(velero_bin: &str, kubeconfig_path: &Path, args: &[&str]) -> Result<()> {
        let mut full_args = Vec::with_capacity(args.len() + 2);
        full_args.push("--kubeconfig");
        full_args.push(path_str(kubeconfig_path)?);
        full_args.extend_from_slice(args);
        run_command(velero_bin, &full_args)
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
