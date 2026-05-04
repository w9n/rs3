//! Local automation for rs3.

mod integration;
mod keyring;
mod perf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::process::Command;

#[derive(Debug, Parser)]
#[command(name = "xtask")]
#[command(about = "Repository automation")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Check,
    Fmt,
    Integration(Box<integration::IntegrationArgs>),
    Keyring(Box<keyring::KeyringArgs>),
    Perf(Box<perf::PerfArgs>),
    Test,
}

fn main() -> Result<()> {
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
        None => {
            println!("usage: cargo xtask <check|fmt|integration|keyring|perf|test>");
        }
    }

    Ok(())
}

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
