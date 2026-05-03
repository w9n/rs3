//! Integration harness entrypoints.

use anyhow::{Context, Result};
#[cfg(feature = "containers")]
use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Credentials, Region, timeout::TimeoutConfig},
    error::ProvideErrorMetadata,
};
use clap::{Args, Subcommand, ValueEnum};
use std::process::Command;
#[cfg(feature = "containers")]
use std::time::{Duration, Instant};
#[cfg(feature = "containers")]
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(feature = "containers")]
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor, wait::HttpWaitStrategy},
    runners::SyncRunner,
};

#[cfg(feature = "containers")]
const RUSTFS_ACCESS_KEY_ID: &str = "rustfsadmin";
#[cfg(feature = "containers")]
const RUSTFS_SECRET_ACCESS_KEY: &str = "rustfsadmin";
#[cfg(feature = "containers")]
const RUSTFS_REGION: &str = "us-east-1";
#[cfg(feature = "containers")]
const RUSTFS_API_PORT: u16 = 9000;
#[cfg(feature = "containers")]
const RUSTFS_IMAGE: &str = "rustfs/rustfs";
#[cfg(feature = "containers")]
const RUSTFS_TAG: &str = "latest";

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
    /// Start a local S3-compatible container for the contract run.
    Container,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum S3ContainerProvider {
    /// RustFS local object storage.
    Rustfs,
}

#[cfg(feature = "containers")]
impl S3ContainerProvider {
    fn as_label(self) -> &'static str {
        match self {
            Self::Rustfs => "rustfs",
        }
    }
}

#[derive(Debug, Args)]
struct S3LocalArgs {
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

/// Runs an integration harness command.
pub(crate) fn run(args: IntegrationArgs) -> Result<()> {
    match args.command {
        IntegrationCommand::S3Local(args) => run_s3_local(args),
    }
}

fn run_s3_local(args: S3LocalArgs) -> Result<()> {
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
    match args.container_provider {
        S3ContainerProvider::Rustfs => run_rustfs_container_s3(args),
    }
}

#[cfg(feature = "containers")]
fn run_rustfs_container_s3(args: S3LocalArgs) -> Result<()> {
    let container = GenericImage::new(RUSTFS_IMAGE, RUSTFS_TAG)
        .with_exposed_port(RUSTFS_API_PORT.tcp())
        .with_wait_for(WaitFor::http(
            HttpWaitStrategy::new("/health")
                .with_port(RUSTFS_API_PORT.tcp())
                .with_expected_status_code(200_u16)
                .with_poll_interval(Duration::from_millis(250)),
        ))
        .with_cmd([
            "--access-key",
            RUSTFS_ACCESS_KEY_ID,
            "--secret-key",
            RUSTFS_SECRET_ACCESS_KEY,
            "/data",
        ])
        .with_env_var("RUSTFS_ACCESS_KEY", RUSTFS_ACCESS_KEY_ID)
        .with_env_var("RUSTFS_SECRET_KEY", RUSTFS_SECRET_ACCESS_KEY)
        .start()
        .context("failed to start RustFS test container")?;
    let host = container
        .get_host()
        .context("failed to resolve RustFS container host")?;
    let api_port = container
        .get_host_port_ipv4(RUSTFS_API_PORT)
        .context("failed to resolve RustFS API port")?;
    let endpoint_url = format!("http://{host}:{api_port}");
    let bucket = args
        .bucket
        .unwrap_or_else(|| default_container_bucket(args.container_provider));
    let region = args.region.unwrap_or_else(|| RUSTFS_REGION.to_owned());

    create_local_s3_bucket(
        &endpoint_url,
        &region,
        RUSTFS_ACCESS_KEY_ID,
        RUSTFS_SECRET_ACCESS_KEY,
        &bucket,
    )
    .with_context(|| format!("failed to create test bucket `{bucket}` in RustFS"))?;

    run_live_s3_contract(LiveS3Contract {
        provider: args
            .provider
            .unwrap_or_else(|| args.container_provider.as_label().to_owned()),
        bucket: Some(bucket),
        endpoint_url: Some(endpoint_url),
        region: Some(region),
        prefix: args.prefix,
        allow_http: Some(true),
        virtual_hosted_style: Some(false),
        credentials: Some(AwsCredentials {
            access_key_id: RUSTFS_ACCESS_KEY_ID.to_owned(),
            secret_access_key: RUSTFS_SECRET_ACCESS_KEY.to_owned(),
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

#[cfg(feature = "containers")]
fn default_container_bucket(provider: S3ContainerProvider) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    format!(
        "rs3-{}-{}-{millis}",
        provider.as_label(),
        std::process::id()
    )
}

#[cfg(feature = "containers")]
fn create_local_s3_bucket(
    endpoint_url: &str,
    region: &str,
    access_key_id: &str,
    secret_access_key: &str,
    bucket: &str,
) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build S3 setup runtime")?;
    runtime.block_on(create_local_s3_bucket_async(
        endpoint_url,
        region,
        access_key_id,
        secret_access_key,
        bucket,
    ))
}

#[cfg(feature = "containers")]
async fn create_local_s3_bucket_async(
    endpoint_url: &str,
    region: &str,
    access_key_id: &str,
    secret_access_key: &str,
    bucket: &str,
) -> Result<()> {
    let client = local_s3_setup_client(endpoint_url, region, access_key_id, secret_access_key);
    let started = Instant::now();
    loop {
        match try_create_bucket(&client, bucket).await {
            Ok(()) => return Ok(()),
            Err(_error) if started.elapsed() < Duration::from_secs(30) => {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(feature = "containers")]
fn local_s3_setup_client(
    endpoint_url: &str,
    region: &str,
    access_key_id: &str,
    secret_access_key: &str,
) -> Client {
    let timeout_config = TimeoutConfig::builder()
        .operation_attempt_timeout(Duration::from_secs(5))
        .operation_timeout(Duration::from_secs(10))
        .build();
    let config = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(region.to_owned()))
        .endpoint_url(endpoint_url.to_owned())
        .credentials_provider(Credentials::new(
            access_key_id,
            secret_access_key,
            None,
            None,
            "rs3-xtask",
        ))
        .force_path_style(true)
        .timeout_config(timeout_config)
        .build();
    Client::from_conf(config)
}

#[cfg(feature = "containers")]
async fn try_create_bucket(client: &Client, bucket: &str) -> Result<()> {
    match client.create_bucket().bucket(bucket).send().await {
        Ok(_) => Ok(()),
        Err(error) if bucket_already_exists(&error) => Ok(()),
        Err(error) => Err(anyhow::anyhow!("CreateBucket failed: {error}")),
    }
}

#[cfg(feature = "containers")]
fn bucket_already_exists<E>(error: &aws_sdk_s3::error::SdkError<E>) -> bool
where
    E: ProvideErrorMetadata,
{
    matches!(
        error
            .as_service_error()
            .and_then(ProvideErrorMetadata::code),
        Some("BucketAlreadyOwnedByYou" | "BucketAlreadyExists")
    )
}
