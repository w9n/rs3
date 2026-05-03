//! Container-backed S3 provider setup.

use super::S3ContainerProvider;
use anyhow::{Context, Result};
use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Credentials, Region, timeout::TimeoutConfig},
    error::ProvideErrorMetadata,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use testcontainers::{
    Container, GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor, wait::HttpWaitStrategy},
    runners::SyncRunner,
};

const RUSTFS_ACCESS_KEY_ID: &str = "rustfsadmin";
const RUSTFS_SECRET_ACCESS_KEY: &str = "rustfsadmin";
const RUSTFS_REGION: &str = "us-east-1";
const RUSTFS_API_PORT: u16 = 9000;
const RUSTFS_IMAGE: &str = "rustfs/rustfs";
const RUSTFS_TAG: &str = "latest";

pub(super) struct RunningS3Container {
    pub(super) provider: S3ContainerProvider,
    pub(super) endpoint_url: String,
    pub(super) bucket: String,
    pub(super) region: String,
    pub(super) access_key_id: String,
    pub(super) secret_access_key: String,
    _container: Container<GenericImage>,
}

pub(super) fn start_s3_container(
    provider: S3ContainerProvider,
    bucket: Option<String>,
    region: Option<String>,
) -> Result<RunningS3Container> {
    match provider {
        S3ContainerProvider::Rustfs => start_rustfs_container(bucket, region),
    }
}

pub(super) fn s3_client(
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

fn start_rustfs_container(
    bucket: Option<String>,
    region: Option<String>,
) -> Result<RunningS3Container> {
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
    let bucket = bucket.unwrap_or_else(|| default_container_bucket(S3ContainerProvider::Rustfs));
    let region = region.unwrap_or_else(|| RUSTFS_REGION.to_owned());

    create_bucket(
        &endpoint_url,
        &region,
        RUSTFS_ACCESS_KEY_ID,
        RUSTFS_SECRET_ACCESS_KEY,
        &bucket,
    )
    .with_context(|| format!("failed to create test bucket `{bucket}` in RustFS"))?;

    Ok(RunningS3Container {
        provider: S3ContainerProvider::Rustfs,
        endpoint_url,
        bucket,
        region,
        access_key_id: RUSTFS_ACCESS_KEY_ID.to_owned(),
        secret_access_key: RUSTFS_SECRET_ACCESS_KEY.to_owned(),
        _container: container,
    })
}

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

fn create_bucket(
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
    runtime.block_on(create_bucket_async(
        endpoint_url,
        region,
        access_key_id,
        secret_access_key,
        bucket,
    ))
}

async fn create_bucket_async(
    endpoint_url: &str,
    region: &str,
    access_key_id: &str,
    secret_access_key: &str,
    bucket: &str,
) -> Result<()> {
    let client = s3_client(endpoint_url, region, access_key_id, secret_access_key);
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

async fn try_create_bucket(client: &Client, bucket: &str) -> Result<()> {
    match client.create_bucket().bucket(bucket).send().await {
        Ok(_) => Ok(()),
        Err(error) if bucket_already_exists(&error) => Ok(()),
        Err(error) => Err(anyhow::anyhow!("CreateBucket failed: {error}")),
    }
}

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
