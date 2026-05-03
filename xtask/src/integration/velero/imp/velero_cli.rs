//! Velero CLI orchestration and diagnostics for integration lanes.

use super::integration_storage_proxy;
use super::rustfs_backend::{BACKEND_BUCKET, RUSTFS_ACCESS_KEY_ID, RUSTFS_SECRET_ACCESS_KEY};
use super::scenario::StoragePath;
use super::{VELERO_BUCKET, kubectl, kubectl_capture, timeout_arg};
use crate::integration::k8s_support::{
    ACCESS_KEY_ID, GATEWAY_PORT, SECRET_ACCESS_KEY, helm_fullname, path_str, run_command,
};
use crate::integration::velero::VeleroKopiaSmokeArgs;
use anyhow::{Context, Result, bail};
use std::fs;
use std::path::Path;

pub(super) struct VeleroS3Target {
    bucket: &'static str,
    endpoint_url: String,
    access_key_id: &'static str,
    secret_access_key: &'static str,
}

pub(super) fn velero_s3_target(
    args: &VeleroKopiaSmokeArgs,
    storage_path: StoragePath,
) -> VeleroS3Target {
    match storage_path {
        StoragePath::Gateway => {
            let service_name = helm_fullname(&args.release_name);
            VeleroS3Target {
                bucket: VELERO_BUCKET,
                endpoint_url: format!(
                    "http://{}.{gateway_namespace}.svc:{GATEWAY_PORT}",
                    service_name,
                    gateway_namespace = args.gateway_namespace
                ),
                access_key_id: ACCESS_KEY_ID,
                secret_access_key: SECRET_ACCESS_KEY,
            }
        }
        StoragePath::DirectRustfs => VeleroS3Target {
            bucket: BACKEND_BUCKET,
            endpoint_url: integration_storage_proxy::service_endpoint(&args.gateway_namespace),
            access_key_id: RUSTFS_ACCESS_KEY_ID,
            secret_access_key: RUSTFS_SECRET_ACCESS_KEY,
        },
    }
}

pub(super) fn write_velero_credentials(path: &Path, target: &VeleroS3Target) -> Result<()> {
    fs::write(
        path,
        format!(
            "[default]\naws_access_key_id={}\naws_secret_access_key={}\n",
            target.access_key_id, target.secret_access_key
        ),
    )
    .with_context(|| format!("failed to write {}", path.display()))
}

pub(super) fn install_velero(
    args: &VeleroKopiaSmokeArgs,
    kubeconfig_path: &Path,
    credentials_path: &Path,
    target: &VeleroS3Target,
) -> Result<()> {
    let backup_location_config = format!(
        "region=us-east-1,s3ForcePathStyle=true,s3Url={},checksumAlgorithm=",
        target.endpoint_url
    );

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
            target.bucket,
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

pub(super) fn create_backup(
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

pub(super) fn create_restore(
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

pub(super) fn assert_pod_volume_backup_completed(
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

pub(super) fn assert_pod_volume_restore_completed(
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

pub(super) fn assert_velero_phase(
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

pub(super) fn velero_diagnostics(
    args: &VeleroKopiaSmokeArgs,
    kubeconfig_path: &Path,
) -> Result<String> {
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

fn velero(velero_bin: &str, kubeconfig_path: &Path, args: &[&str]) -> Result<()> {
    let mut full_args = Vec::with_capacity(args.len() + 2);
    full_args.push("--kubeconfig");
    full_args.push(path_str(kubeconfig_path)?);
    full_args.extend_from_slice(args);
    run_command(velero_bin, &full_args)
}
