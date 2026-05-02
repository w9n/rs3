//! Command-line entry point for the rs3 gateway.

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
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
        #[arg(long, env = "RS3_BIND", default_value = "127.0.0.1:9080")]
        bind: SocketAddr,
    },
    Doctor,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.log_format);

    match cli.command {
        Commands::Serve { bind } => {
            tracing::info!(%bind, "gateway scaffold ready");
        }
        Commands::Doctor => {
            println!("rs3 doctor: scaffold ok");
        }
    }

    Ok(())
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
