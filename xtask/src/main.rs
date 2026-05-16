//! Local automation for rs3.

mod integration;
mod keyring;
mod perf;
mod v2;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::process::Command;
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
    Check,
    Fmt,
    Integration(Box<integration::IntegrationArgs>),
    Keyring(Box<keyring::KeyringArgs>),
    Perf(Box<perf::PerfArgs>),
    Test,
    V2(Box<v2::V2Args>),
}

fn main() -> Result<()> {
    install_rustls_provider();
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Check) => {
            run("cargo", &["fmt", "--all", "--check"])?;
            run(
                "cargo",
                &[
                    "clippy",
                    "--workspace",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            run("cargo", &["test", "--workspace"])?;
        }
        Some(Commands::Fmt) => {
            run("cargo", &["fmt", "--all"])?;
        }
        Some(Commands::Integration(args)) => {
            integration::run(*args)?;
        }
        Some(Commands::Keyring(args)) => {
            keyring::run(*args)?;
        }
        Some(Commands::Perf(args)) => {
            perf::run(*args)?;
        }
        Some(Commands::Test) => {
            run("cargo", &["test", "--workspace"])?;
        }
        Some(Commands::V2(args)) => {
            v2::run(*args)?;
        }
        None => {
            println!("usage: cargo xtask <check|fmt|integration|keyring|perf|test|v2>");
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

fn run(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("failed to start {program}"))?;

    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("{program} exited with {status}");
    }
}
