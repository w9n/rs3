//! Integration harness entrypoints.

#[cfg(feature = "containers")]
mod gateway_process;
mod k8s;
#[cfg(feature = "k8s")]
mod k8s_support;
mod kopia;
mod s3;
#[cfg(feature = "containers")]
pub(crate) mod s3_container;
mod s3_gateway;
mod velero;

use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};

/// Integration harness arguments.
#[derive(Debug, Args)]
pub(crate) struct IntegrationArgs {
    #[command(subcommand)]
    command: IntegrationCommand,
}

#[derive(Debug, Subcommand)]
enum IntegrationCommand {
    /// Run the storage contract against an S3-compatible backend.
    S3Local(s3::S3LocalArgs),
    /// Run the gateway through its S3-compatible HTTP boundary.
    S3Gateway(s3_gateway::S3GatewayArgs),
    /// Run a real Kopia S3 smoke test through the local gateway.
    KopiaGateway(kopia::KopiaGatewayArgs),
    /// Run Kopia through direct storage and gateway paths with backend measurements.
    KopiaMeasuredMatrix(kopia::KopiaMatrixArgs),
    /// Run the gateway inside a disposable kind cluster.
    K8sGateway(k8s::K8sGatewayArgs),
    /// Run a Velero node-agent/Kopia backup and restore through the gateway.
    VeleroKopiaSmoke(velero::VeleroKopiaSmokeArgs),
    /// Run a Velero node-agent/Kopia local-PV backup and restore through the gateway.
    VeleroKopiaLocalPvSmoke(velero::VeleroKopiaSmokeArgs),
    /// Run a Velero node-agent/Kopia dynamic-PVC backup and restore through the gateway.
    VeleroKopiaDynamicPvcSmoke(velero::VeleroKopiaSmokeArgs),
    /// Run a Velero dynamic-PVC restore after restarting the gateway.
    VeleroKopiaDynamicPvcGatewayRestartSmoke(velero::VeleroKopiaSmokeArgs),
    /// Run a Velero dynamic-PVC restore through strict restore-readonly mode.
    VeleroKopiaDynamicPvcRestoreReadonlySmoke(velero::VeleroKopiaSmokeArgs),
    /// Run a Velero node-agent/Kopia Postgres restore smoke through the gateway.
    VeleroKopiaPostgresSmoke(velero::VeleroKopiaSmokeArgs),
    /// Run a Velero node-agent/Kopia Postgres restore smoke directly against RustFS.
    VeleroKopiaPostgresDirectSmoke(velero::VeleroKopiaSmokeArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum S3ContainerProvider {
    /// RustFS local object storage.
    Rustfs,
    /// MinIO local object storage.
    Minio,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum GatewayRepositoryFormat {
    /// Legacy production-preview repository format.
    V1Preview,
    /// Primary production-preview repository format.
    V2Preview,
}

#[cfg(feature = "k8s")]
impl GatewayRepositoryFormat {
    pub(crate) const fn as_env(self) -> &'static str {
        match self {
            Self::V1Preview => "v1-preview",
            Self::V2Preview => "v2-preview",
        }
    }

    pub(crate) const fn is_v2(self) -> bool {
        matches!(self, Self::V2Preview)
    }
}

#[cfg(feature = "containers")]
impl S3ContainerProvider {
    pub(crate) fn as_label(self) -> &'static str {
        match self {
            Self::Rustfs => "rustfs",
            Self::Minio => "minio",
        }
    }
}

/// Runs an integration harness command.
pub(crate) fn run(args: IntegrationArgs) -> Result<()> {
    match args.command {
        IntegrationCommand::S3Local(args) => s3::run_s3_local(args),
        IntegrationCommand::S3Gateway(args) => s3_gateway::run_s3_gateway(args),
        IntegrationCommand::KopiaGateway(args) => kopia::run_kopia_gateway(args),
        IntegrationCommand::KopiaMeasuredMatrix(args) => kopia::run_kopia_measured_matrix(args),
        IntegrationCommand::K8sGateway(args) => k8s::run_k8s_gateway(args),
        IntegrationCommand::VeleroKopiaSmoke(args) => velero::run_velero_kopia_smoke(args),
        IntegrationCommand::VeleroKopiaLocalPvSmoke(args) => {
            velero::run_velero_kopia_local_pv_smoke(args)
        }
        IntegrationCommand::VeleroKopiaDynamicPvcSmoke(args) => {
            velero::run_velero_kopia_dynamic_pvc_smoke(args)
        }
        IntegrationCommand::VeleroKopiaDynamicPvcGatewayRestartSmoke(args) => {
            velero::run_velero_kopia_dynamic_pvc_gateway_restart_smoke(args)
        }
        IntegrationCommand::VeleroKopiaDynamicPvcRestoreReadonlySmoke(args) => {
            velero::run_velero_kopia_dynamic_pvc_restore_readonly_smoke(args)
        }
        IntegrationCommand::VeleroKopiaPostgresSmoke(args) => {
            velero::run_velero_kopia_postgres_smoke(args)
        }
        IntegrationCommand::VeleroKopiaPostgresDirectSmoke(args) => {
            velero::run_velero_kopia_postgres_direct_smoke(args)
        }
    }
}
