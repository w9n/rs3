//! Command-line entry point for the rs3 gateway.

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use rs3_server::{AnchorConfig, GatewayServer, RuntimeConfig};
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "rs3")]
#[command(about = "Path-private S3-compatible backup gateway")]
struct Cli {
    #[arg(long, env = "RS3_LOG_FORMAT", default_value = "plain")]
    log_format: LogFormat,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum LogFormat {
    Plain,
    Json,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Serve {
        #[arg(long)]
        bind: Option<SocketAddr>,
    },
    Doctor,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.log_format);

    match cli.command {
        Commands::Serve { bind } => {
            let mut config = RuntimeConfig::from_env()?;
            if let Some(bind) = bind {
                config.bind = bind;
            }
            log_runtime_config(&config);
            let server = GatewayServer::bind(config).await?;
            tracing::info!(bind = %server.local_addr(), "gateway S3 listener started");
            server.run_until_shutdown(shutdown_signal()).await?;
        }
        Commands::Doctor => {
            let config = RuntimeConfig::from_env()?;
            log_runtime_config(&config);
            println!("rs3 doctor: runtime config ok");
        }
    }

    Ok(())
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::warn!(%error, "failed to install Ctrl+C shutdown handler");
    }
}

fn log_runtime_config(config: &RuntimeConfig) {
    let anchor = match &config.anchor {
        AnchorConfig::Memory => "memory",
        AnchorConfig::KubernetesLease { .. } => "kubernetes-lease",
    };

    tracing::info!(
        bind = %config.bind,
        public_bucket = %config.public_bucket,
        backend_endpoint = %config.backend.endpoint,
        backend_bucket = %config.backend.bucket,
        backend_prefix = ?config.backend.prefix,
        anchor,
        batch_max_items = config.batching.max_items,
        batch_max_delay_ms = config.batching.max_delay.as_millis(),
        batch_max_pending_items = config.batching.max_pending_items,
        static_credentials = config.static_credentials.is_some(),
        "gateway runtime configuration validated",
    );
}

fn init_tracing(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    match format {
        LogFormat::Plain => tracing_subscriber::fmt().with_env_filter(filter).init(),
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init(),
    }
}
