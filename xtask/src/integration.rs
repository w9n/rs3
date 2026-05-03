//! Integration harness entrypoints.

use anyhow::{Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use std::process::Command;

/// Integration harness arguments.
#[derive(Debug, Args)]
pub(crate) struct IntegrationArgs {
    #[command(subcommand)]
    command: IntegrationCommand,
}

#[derive(Debug, Subcommand)]
enum IntegrationCommand {
    /// Run the storage contract against a provided S3-compatible endpoint.
    S3Local(S3LocalArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum S3LocalMode {
    /// Use an already running endpoint and bucket.
    Provided,
}

#[derive(Debug, Args)]
struct S3LocalArgs {
    /// Integration mode. Container and Kubernetes modes will be added here later.
    #[arg(long, value_enum, default_value_t = S3LocalMode::Provided)]
    mode: S3LocalMode,
    /// Provider label used only in test object prefixes and output.
    #[arg(long, env = "RS3_TEST_S3_PROVIDER", default_value = "s3-compatible")]
    provider: String,
    /// Existing test bucket. If omitted, the live test compiles and skips.
    #[arg(long, env = "RS3_TEST_S3_BUCKET")]
    bucket: Option<String>,
    /// S3-compatible endpoint URL. Omit for the default AWS endpoint.
    #[arg(long, env = "RS3_TEST_S3_ENDPOINT_URL")]
    endpoint_url: Option<String>,
    /// S3 signing region.
    #[arg(long, env = "RS3_TEST_S3_REGION")]
    region: Option<String>,
    /// Prefix for objects created by this test run.
    #[arg(long, env = "RS3_TEST_S3_PREFIX")]
    prefix: Option<String>,
    /// Allow plain HTTP endpoints.
    #[arg(long, env = "RS3_TEST_S3_ALLOW_HTTP")]
    allow_http: Option<bool>,
    /// Use virtual-hosted-style S3 requests.
    #[arg(long, env = "RS3_TEST_S3_VIRTUAL_HOSTED_STYLE")]
    virtual_hosted_style: Option<bool>,
}

/// Runs an integration harness command.
pub(crate) fn run(args: IntegrationArgs) -> Result<()> {
    match args.command {
        IntegrationCommand::S3Local(args) => run_s3_local(args),
    }
}

fn run_s3_local(args: S3LocalArgs) -> Result<()> {
    match args.mode {
        S3LocalMode::Provided => run_provided_s3(args),
    }
}

fn run_provided_s3(args: S3LocalArgs) -> Result<()> {
    let mut command = Command::new("cargo");
    command.args([
        "test",
        "-p",
        "rs3-storage",
        "--features",
        "s3",
        "--test",
        "s3_live",
        "--",
        "--ignored",
        "--nocapture",
    ]);
    command.env("RS3_TEST_S3_PROVIDER", args.provider);
    set_env(&mut command, "RS3_TEST_S3_BUCKET", args.bucket);
    set_env(&mut command, "RS3_TEST_S3_ENDPOINT_URL", args.endpoint_url);
    set_env(&mut command, "RS3_TEST_S3_REGION", args.region);
    set_env(&mut command, "RS3_TEST_S3_PREFIX", args.prefix);
    set_env_bool(&mut command, "RS3_TEST_S3_ALLOW_HTTP", args.allow_http);
    set_env_bool(
        &mut command,
        "RS3_TEST_S3_VIRTUAL_HOSTED_STYLE",
        args.virtual_hosted_style,
    );

    let status = command
        .status()
        .context("failed to start live S3 integration test")?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("live S3 integration test exited with {status}");
    }
}

fn set_env(command: &mut Command, key: &'static str, value: Option<String>) {
    if let Some(value) = value {
        command.env(key, value);
    }
}

fn set_env_bool(command: &mut Command, key: &'static str, value: Option<bool>) {
    if let Some(value) = value {
        command.env(key, if value { "true" } else { "false" });
    }
}
