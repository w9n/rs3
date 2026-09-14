//! Local automation for rs3.

mod integration;
mod perf;
mod repository;

use anyhow::Result;
use clap::{Parser, Subcommand};
#[cfg(any(feature = "containers", feature = "k8s"))]
use std::sync::Once;

#[cfg(any(feature = "containers", feature = "k8s"))]
static RUSTLS_PROVIDER: Once = Once::new();

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "Repository automation")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Integration(Box<integration::IntegrationArgs>),
    Perf(Box<perf::PerfArgs>),
    Repository(Box<repository::RepositoryArgs>),
}

fn main() -> Result<()> {
    install_rustls_provider();
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Integration(args)) => {
            integration::run(*args)?;
        }
        Some(Commands::Perf(args)) => {
            perf::run(*args)?;
        }
        Some(Commands::Repository(args)) => {
            repository::run(*args)?;
        }
        None => {
            println!("usage: cargo xtask <integration|perf|repository>");
        }
    }

    Ok(())
}

#[cfg(any(feature = "containers", feature = "k8s"))]
fn install_rustls_provider() {
    RUSTLS_PROVIDER.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

#[cfg(not(any(feature = "containers", feature = "k8s")))]
fn install_rustls_provider() {}
