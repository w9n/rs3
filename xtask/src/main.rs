//! Local automation for rs3.

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
        Some(Commands::Test) => {
            run("cargo", &["test", "--workspace"])?;
        }
        None => {
            println!("usage: cargo xtask <check|fmt|test>");
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
