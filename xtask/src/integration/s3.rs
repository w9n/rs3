//! Storage-level S3 integration command.

use super::S3ContainerProvider;
#[cfg(feature = "containers")]
use super::s3_container;
use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use std::process::Command;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum S3LocalMode {
    /// Use an already running endpoint and bucket.
    Provided,
    /// Start a local S3-compatible container for the contract run.
    Container,
}

#[derive(Debug, Args)]
pub(crate) struct S3LocalArgs {
    /// Integration mode.
    #[arg(long, value_enum, default_value_t = S3LocalMode::Provided)]
    mode: S3LocalMode,
    /// Container provider used when --mode container is selected.
    #[arg(long, value_enum, default_value_t = S3ContainerProvider::Rustfs)]
    container_provider: S3ContainerProvider,
    /// Provider label used only in test object prefixes and output. Defaults by mode.
    #[arg(long, env = "RS3_TEST_S3_PROVIDER")]
    provider: Option<String>,
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

pub(crate) fn run_s3_local(args: S3LocalArgs) -> Result<()> {
    match args.mode {
        S3LocalMode::Provided => run_provided_s3(args),
        S3LocalMode::Container => run_container_s3(args),
    }
}

fn run_provided_s3(args: S3LocalArgs) -> Result<()> {
    run_live_s3_contract(LiveS3Contract {
        provider: args.provider.unwrap_or_else(|| "s3-compatible".to_owned()),
        bucket: args.bucket,
        endpoint_url: args.endpoint_url,
        region: args.region,
        prefix: args.prefix,
        allow_http: args.allow_http,
        virtual_hosted_style: args.virtual_hosted_style,
        credentials: None,
    })
}

#[cfg(not(feature = "containers"))]
fn run_container_s3(args: S3LocalArgs) -> Result<()> {
    anyhow::bail!(
        "container integration for {:?} requires `cargo run -p xtask --features containers -- integration s3-local --mode container`",
        args.container_provider,
    )
}

#[cfg(feature = "containers")]
fn run_container_s3(args: S3LocalArgs) -> Result<()> {
    let target =
        s3_container::start_s3_container(args.container_provider, args.bucket, args.region)?;

    run_live_s3_contract(LiveS3Contract {
        provider: args
            .provider
            .unwrap_or_else(|| target.provider.as_label().to_owned()),
        bucket: Some(target.bucket),
        endpoint_url: Some(target.endpoint_url),
        region: Some(target.region),
        prefix: args.prefix,
        allow_http: Some(true),
        virtual_hosted_style: Some(false),
        credentials: Some(AwsCredentials {
            access_key_id: target.access_key_id,
            secret_access_key: target.secret_access_key,
        }),
    })
}

struct LiveS3Contract {
    provider: String,
    bucket: Option<String>,
    endpoint_url: Option<String>,
    region: Option<String>,
    prefix: Option<String>,
    allow_http: Option<bool>,
    virtual_hosted_style: Option<bool>,
    credentials: Option<AwsCredentials>,
}

struct AwsCredentials {
    access_key_id: String,
    secret_access_key: String,
}

fn run_live_s3_contract(contract: LiveS3Contract) -> Result<()> {
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
    command.env("RS3_TEST_S3_PROVIDER", contract.provider);
    set_env(&mut command, "RS3_TEST_S3_BUCKET", contract.bucket);
    set_env(
        &mut command,
        "RS3_TEST_S3_ENDPOINT_URL",
        contract.endpoint_url,
    );
    set_env(&mut command, "RS3_TEST_S3_REGION", contract.region.clone());
    set_env(&mut command, "RS3_TEST_S3_PREFIX", contract.prefix);
    set_env_bool(&mut command, "RS3_TEST_S3_ALLOW_HTTP", contract.allow_http);
    set_env_bool(
        &mut command,
        "RS3_TEST_S3_VIRTUAL_HOSTED_STYLE",
        contract.virtual_hosted_style,
    );
    if let Some(credentials) = contract.credentials {
        command.env("AWS_ACCESS_KEY_ID", credentials.access_key_id);
        command.env("AWS_SECRET_ACCESS_KEY", credentials.secret_access_key);
        set_env(&mut command, "AWS_DEFAULT_REGION", contract.region);
        command.env_remove("AWS_SESSION_TOKEN");
        command.env_remove("AWS_PROFILE");
        command.env_remove("AWS_WEB_IDENTITY_TOKEN_FILE");
        command.env_remove("AWS_ROLE_ARN");
        command.env_remove("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI");
        command.env_remove("AWS_CONTAINER_CREDENTIALS_FULL_URI");
        command.env_remove("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE");
    }

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
