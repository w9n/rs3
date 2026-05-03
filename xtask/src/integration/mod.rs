//! Integration harness entrypoints.

#[cfg(feature = "containers")]
mod gateway_process;
mod k8s;
mod kopia;
mod s3;
#[cfg(feature = "containers")]
pub(crate) mod s3_container;
mod s3_gateway;

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
    /// Run the gateway inside a disposable kind cluster.
    K8sGateway(k8s::K8sGatewayArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum S3ContainerProvider {
    /// RustFS local object storage.
    Rustfs,
}

#[cfg(feature = "containers")]
impl S3ContainerProvider {
    pub(crate) fn as_label(self) -> &'static str {
        match self {
            Self::Rustfs => "rustfs",
        }
    }
}

/// Runs an integration harness command.
pub(crate) fn run(args: IntegrationArgs) -> Result<()> {
    match args.command {
        IntegrationCommand::S3Local(args) => s3::run_s3_local(args),
        IntegrationCommand::S3Gateway(args) => s3_gateway::run_s3_gateway(args),
        IntegrationCommand::KopiaGateway(args) => kopia::run_kopia_gateway(args),
        IntegrationCommand::K8sGateway(args) => k8s::run_k8s_gateway(args),
    }
}
