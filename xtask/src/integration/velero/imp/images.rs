//! Container image preparation for Velero integration lanes.

use crate::integration::k8s_support::{run_command, run_command_capture};
use crate::integration::velero::VeleroKopiaSmokeArgs;
use anyhow::{Context, Result, bail};

pub(super) fn prepare_velero_images(args: &VeleroKopiaSmokeArgs) -> Result<()> {
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

pub(super) fn prepare_rustfs_image(args: &VeleroKopiaSmokeArgs) -> Result<()> {
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

pub(super) fn prepare_openebs_images(args: &VeleroKopiaSmokeArgs) -> Result<()> {
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

pub(super) fn prepare_postgres_image(args: &VeleroKopiaSmokeArgs) -> Result<()> {
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
