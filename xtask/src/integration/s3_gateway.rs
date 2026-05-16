//! Gateway-level S3 integration command.

use super::S3ContainerProvider;
#[cfg(feature = "containers")]
use super::gateway_process::{
    ACCESS_KEY_ID, GatewayBackend, GatewayProcessOptions, PUBLIC_BUCKET, RunningGateway,
    SECRET_ACCESS_KEY,
};
#[cfg(feature = "containers")]
use super::s3_container;
#[cfg(feature = "containers")]
use anyhow::Context;
use anyhow::Result;
#[cfg(feature = "containers")]
use aws_sdk_s3::{Client, primitives::ByteStream};
use clap::{Args, ValueEnum};
#[cfg(feature = "containers")]
use std::env;
#[cfg(feature = "containers")]
use std::fs;
#[cfg(feature = "containers")]
use std::path::PathBuf;
#[cfg(feature = "containers")]
use std::process::Command;
#[cfg(feature = "containers")]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "containers")]
const GATEWAY_TEST_KEY: &str = "snapshots/gateway-object.bin";
#[cfg(feature = "containers")]
const GATEWAY_TEST_BODY: &[u8] = b"hello gateway backend";
#[cfg(feature = "containers")]
const GATEWAY_LIST_KEYS: &[&str] = &[
    "snapshots/paginated/a.bin",
    "snapshots/paginated/b.bin",
    "snapshots/paginated/c.bin",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum S3GatewayMode {
    /// Start a disposable local backend container.
    Container,
    /// Use an already configured S3-compatible backend.
    Provided,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum S3GatewayRepositoryFormat {
    /// Legacy production-preview repository format.
    V1Preview,
    /// Primary production-preview repository format.
    V2Preview,
}

#[cfg(feature = "containers")]
impl S3GatewayRepositoryFormat {
    const fn as_env(self) -> &'static str {
        match self {
            Self::V1Preview => "v1-preview",
            Self::V2Preview => "v2-preview",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum S3GatewayRetentionMode {
    Governance,
    Compliance,
}

#[cfg(feature = "containers")]
impl S3GatewayRetentionMode {
    const fn as_env(self) -> &'static str {
        match self {
            Self::Governance => "governance",
            Self::Compliance => "compliance",
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct S3GatewayArgs {
    /// Integration mode.
    #[arg(long, value_enum, default_value_t = S3GatewayMode::Container)]
    mode: S3GatewayMode,
    /// Container provider used as the gateway backend.
    #[arg(long, value_enum, default_value_t = S3ContainerProvider::Rustfs)]
    container_provider: S3ContainerProvider,
    /// Existing backend bucket. If omitted, a temporary bucket is created.
    #[arg(long, env = "RS3_TEST_S3_BUCKET")]
    backend_bucket: Option<String>,
    /// S3-compatible endpoint URL when --mode provided is selected.
    #[arg(long, env = "RS3_TEST_S3_ENDPOINT_URL")]
    endpoint_url: Option<String>,
    /// Backend S3 signing region.
    #[arg(long, env = "RS3_TEST_S3_REGION")]
    region: Option<String>,
    /// Backend prefix for repository-owned objects.
    #[arg(long, env = "RS3_TEST_S3_PREFIX", default_value = "rs3-gateway")]
    backend_prefix: String,
    /// Repository format used by the gateway process.
    #[arg(long, env = "RS3_REPOSITORY_FORMAT", value_enum, default_value_t = S3GatewayRepositoryFormat::V2Preview)]
    repository_format: S3GatewayRepositoryFormat,
    /// Repository retention mode for repository-owned backend objects.
    #[arg(long, env = "RS3_REPOSITORY_RETENTION_MODE", value_enum)]
    retention_mode: Option<S3GatewayRetentionMode>,
    /// Repository retention duration in days.
    #[arg(long, env = "RS3_REPOSITORY_RETENTION_DAYS")]
    retention_days: Option<u32>,
    /// Also exercise common operator tools (`mc` and default `rclone lsf`).
    #[arg(long, default_value_t = false)]
    tooling_smoke: bool,
}

#[cfg(not(feature = "containers"))]
pub(crate) fn run_s3_gateway(args: S3GatewayArgs) -> Result<()> {
    anyhow::bail!(
        "gateway container integration for {:?} requires `cargo run -p xtask --bin xtask --features containers -- integration s3-gateway`",
        args.container_provider,
    )
}

#[cfg(feature = "containers")]
pub(crate) fn run_s3_gateway(args: S3GatewayArgs) -> Result<()> {
    validate_gateway_args(&args)?;
    let process_options = gateway_process_options(&args);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build gateway integration runtime")?;

    match args.mode {
        S3GatewayMode::Container => {
            let backend = s3_container::start_s3_container_with_options(
                args.container_provider,
                args.backend_bucket,
                args.region,
                s3_container::S3ContainerOptions {
                    object_lock: args.retention_mode.is_some(),
                },
            )?;
            runtime.block_on(async {
                let backend = GatewayBackend::from_container(&backend);
                run_gateway_contract_for_backend(
                    &backend,
                    args.backend_prefix,
                    process_options,
                    args.tooling_smoke,
                )
                .await
            })
        }
        S3GatewayMode::Provided => {
            let backend = provided_gateway_backend(&args)?;
            runtime.block_on(async {
                run_gateway_contract_for_backend(
                    &backend,
                    args.backend_prefix,
                    process_options,
                    args.tooling_smoke,
                )
                .await
            })
        }
    }
}

#[cfg(feature = "containers")]
fn validate_gateway_args(args: &S3GatewayArgs) -> Result<()> {
    if args.retention_mode.is_some() && args.retention_days.is_none() {
        anyhow::bail!("--retention-days is required when --retention-mode is set");
    }
    if args.retention_days.is_some() && args.retention_mode.is_none() {
        anyhow::bail!("--retention-mode is required when --retention-days is set");
    }
    if args.mode == S3GatewayMode::Provided {
        if args.backend_bucket.is_none() {
            anyhow::bail!("--backend-bucket or RS3_TEST_S3_BUCKET is required for --mode provided");
        }
        if args.endpoint_url.is_none() {
            anyhow::bail!(
                "--endpoint-url or RS3_TEST_S3_ENDPOINT_URL is required for --mode provided"
            );
        }
    }
    Ok(())
}

#[cfg(feature = "containers")]
fn gateway_process_options(args: &S3GatewayArgs) -> GatewayProcessOptions {
    GatewayProcessOptions {
        repository_format: Some(args.repository_format.as_env()),
        repository_retention_mode: args.retention_mode.map(S3GatewayRetentionMode::as_env),
        repository_retention_days: args.retention_days,
        ..GatewayProcessOptions::default()
    }
}

#[cfg(feature = "containers")]
fn provided_gateway_backend(args: &S3GatewayArgs) -> Result<GatewayBackend> {
    Ok(GatewayBackend {
        endpoint_url: args
            .endpoint_url
            .clone()
            .context("missing provided S3 endpoint URL")?,
        bucket: args
            .backend_bucket
            .clone()
            .context("missing provided S3 bucket")?,
        region: args
            .region
            .clone()
            .unwrap_or_else(|| "us-east-1".to_owned()),
        access_key_id: required_env("AWS_ACCESS_KEY_ID")?,
        secret_access_key: required_env("AWS_SECRET_ACCESS_KEY")?,
    })
}

#[cfg(feature = "containers")]
fn required_env(name: &'static str) -> Result<String> {
    env::var(name).with_context(|| format!("{name} is required for --mode provided"))
}

#[cfg(feature = "containers")]
async fn run_gateway_contract_for_backend(
    backend: &GatewayBackend,
    backend_prefix: String,
    process_options: GatewayProcessOptions,
    tooling_smoke: bool,
) -> Result<()> {
    let mut gateway = RunningGateway::start_for_backend_with_options(
        backend,
        backend_prefix.clone(),
        process_options,
    )
    .await?;
    let client = gateway.client_for_backend(backend);
    let result: Result<()> = async {
        assert_gateway_contract(&client).await?;
        if tooling_smoke {
            assert_operator_tooling_smoke(&gateway).await?;
        }
        assert_backend_keys_path_private(backend, &backend_prefix).await?;
        Ok(())
    }
    .await;
    let shutdown = gateway.shutdown();

    result?;
    shutdown?;
    Ok(())
}

#[cfg(feature = "containers")]
async fn assert_gateway_contract(client: &Client) -> Result<()> {
    client
        .get_bucket_location()
        .bucket(PUBLIC_BUCKET)
        .send()
        .await
        .context("gateway GetBucketLocation failed")?;

    put_object(client, GATEWAY_TEST_KEY, GATEWAY_TEST_BODY).await?;

    let head = client
        .head_object()
        .bucket(PUBLIC_BUCKET)
        .key(GATEWAY_TEST_KEY)
        .send()
        .await
        .context("gateway HeadObject failed")?;
    let content_length =
        i64::try_from(GATEWAY_TEST_BODY.len()).context("test body length does not fit in i64")?;
    if head.content_length() != Some(content_length) {
        anyhow::bail!(
            "gateway HeadObject returned content length {:?}, expected {content_length}",
            head.content_length()
        );
    }

    let full = client
        .get_object()
        .bucket(PUBLIC_BUCKET)
        .key(GATEWAY_TEST_KEY)
        .send()
        .await
        .context("gateway GetObject failed")?;
    assert_body(full.body, GATEWAY_TEST_BODY).await?;

    let range = client
        .get_object()
        .bucket(PUBLIC_BUCKET)
        .key(GATEWAY_TEST_KEY)
        .range("bytes=6-12")
        .send()
        .await
        .context("gateway ranged GetObject failed")?;
    assert_body(range.body, b"gateway").await?;

    let listed = client
        .list_objects_v2()
        .bucket(PUBLIC_BUCKET)
        .prefix("snapshots/")
        .send()
        .await
        .context("gateway ListObjectsV2 failed")?;
    let listed_keys = listed
        .contents()
        .iter()
        .filter_map(|object| object.key())
        .collect::<Vec<_>>();
    if !listed_keys.contains(&GATEWAY_TEST_KEY) {
        anyhow::bail!("gateway ListObjectsV2 did not include {GATEWAY_TEST_KEY}");
    }

    let listed_v1 = client
        .list_objects()
        .bucket(PUBLIC_BUCKET)
        .prefix("snapshots/")
        .send()
        .await
        .context("gateway ListObjects failed")?;
    let listed_v1_keys = listed_v1
        .contents()
        .iter()
        .filter_map(|object| object.key())
        .collect::<Vec<_>>();
    if !listed_v1_keys.contains(&GATEWAY_TEST_KEY) {
        anyhow::bail!("gateway ListObjects did not include {GATEWAY_TEST_KEY}");
    }

    assert_paginated_listing(client).await?;

    client
        .delete_object()
        .bucket(PUBLIC_BUCKET)
        .key(GATEWAY_TEST_KEY)
        .send()
        .await
        .context("gateway DeleteObject failed")?;

    let listed_after_delete = client
        .list_objects_v2()
        .bucket(PUBLIC_BUCKET)
        .prefix("snapshots/")
        .send()
        .await
        .context("gateway ListObjectsV2 after delete failed")?;
    let still_listed = listed_after_delete
        .contents()
        .iter()
        .any(|object| object.key() == Some(GATEWAY_TEST_KEY));
    if still_listed {
        anyhow::bail!("gateway DeleteObject did not remove {GATEWAY_TEST_KEY} from listings");
    }

    Ok(())
}

#[cfg(feature = "containers")]
async fn put_object(client: &Client, key: &str, body: &[u8]) -> Result<()> {
    client
        .put_object()
        .bucket(PUBLIC_BUCKET)
        .key(key)
        .body(ByteStream::from(body.to_vec()))
        .send()
        .await
        .with_context(|| format!("gateway PutObject failed for {key}"))?;
    Ok(())
}

#[cfg(feature = "containers")]
async fn assert_paginated_listing(client: &Client) -> Result<()> {
    for key in GATEWAY_LIST_KEYS {
        put_object(client, key, key.as_bytes()).await?;
    }

    let first = client
        .list_objects_v2()
        .bucket(PUBLIC_BUCKET)
        .prefix("snapshots/paginated/")
        .max_keys(1)
        .send()
        .await
        .context("gateway paginated ListObjectsV2 first page failed")?;
    let first_key = first
        .contents()
        .first()
        .and_then(|object| object.key())
        .context("gateway paginated ListObjectsV2 first page was empty")?;
    if first_key != GATEWAY_LIST_KEYS[0] {
        anyhow::bail!(
            "gateway paginated ListObjectsV2 first page returned {first_key}, expected {}",
            GATEWAY_LIST_KEYS[0],
        );
    }

    let token = first
        .next_continuation_token()
        .context("gateway paginated ListObjectsV2 first page had no continuation token")?;
    let second = client
        .list_objects_v2()
        .bucket(PUBLIC_BUCKET)
        .prefix("snapshots/paginated/")
        .max_keys(1)
        .continuation_token(token)
        .send()
        .await
        .context("gateway paginated ListObjectsV2 second page failed")?;
    let second_key = second
        .contents()
        .first()
        .and_then(|object| object.key())
        .context("gateway paginated ListObjectsV2 second page was empty")?;
    if second_key != GATEWAY_LIST_KEYS[1] {
        anyhow::bail!(
            "gateway paginated ListObjectsV2 second page returned {second_key}, expected {}",
            GATEWAY_LIST_KEYS[1],
        );
    }

    let delimiter = client
        .list_objects_v2()
        .bucket(PUBLIC_BUCKET)
        .prefix("snapshots/")
        .delimiter("/")
        .send()
        .await
        .context("gateway delimiter ListObjectsV2 failed")?;
    let common_prefixes = delimiter
        .common_prefixes()
        .iter()
        .filter_map(|prefix| prefix.prefix())
        .collect::<Vec<_>>();
    if !common_prefixes.contains(&"snapshots/paginated/") {
        anyhow::bail!("gateway delimiter ListObjectsV2 did not include snapshots/paginated/");
    }

    Ok(())
}

#[cfg(feature = "containers")]
async fn assert_body(body: ByteStream, expected: &[u8]) -> Result<()> {
    let actual = body
        .collect()
        .await
        .context("failed to collect gateway response body")?
        .into_bytes();
    if actual.as_ref() != expected {
        anyhow::bail!(
            "gateway response body mismatch: got {:?}, expected {:?}",
            actual.as_ref(),
            expected
        );
    }
    Ok(())
}

#[cfg(feature = "containers")]
async fn assert_backend_keys_path_private(
    backend: &GatewayBackend,
    backend_prefix: &str,
) -> Result<()> {
    let client = s3_container::s3_client(
        &backend.endpoint_url,
        &backend.region,
        &backend.access_key_id,
        &backend.secret_access_key,
    );
    let mut continuation_token = None;
    let mut checked = 0usize;

    loop {
        let page = client
            .list_objects_v2()
            .bucket(&backend.bucket)
            .prefix(backend_prefix)
            .set_continuation_token(continuation_token.take())
            .send()
            .await
            .context("failed to list gateway backend prefix for path-privacy check")?;
        for object in page.contents() {
            let Some(key) = object.key() else {
                continue;
            };
            checked += 1;
            if key.contains(GATEWAY_TEST_KEY)
                || key.contains("path-private")
                || key.contains(PUBLIC_BUCKET)
            {
                anyhow::bail!("gateway backend key leaked a client-visible name");
            }
        }
        continuation_token = page.next_continuation_token().map(ToOwned::to_owned);
        if continuation_token.is_none() {
            break;
        }
    }

    if checked == 0 {
        anyhow::bail!("gateway backend path-privacy check found no repository objects");
    }
    Ok(())
}

#[cfg(feature = "containers")]
async fn assert_operator_tooling_smoke(gateway: &RunningGateway) -> Result<()> {
    let body = b"rs3 gateway operator tooling smoke\n";
    let body_path = unique_temp_path("body.txt");
    let mc_config_dir = unique_temp_path("mc");
    fs::create_dir_all(&mc_config_dir).context("failed to create temporary mc config directory")?;
    fs::write(&body_path, body).context("failed to write operator tooling smoke body")?;

    let endpoint = gateway.endpoint_url();
    run_status(
        Command::new("mc")
            .env("MC_CONFIG_DIR", &mc_config_dir)
            .args([
                "alias",
                "set",
                "gw",
                endpoint.as_str(),
                ACCESS_KEY_ID,
                SECRET_ACCESS_KEY,
                "--api",
                "S3v4",
            ]),
        "mc alias set",
    )?;
    run_status(
        Command::new("mc")
            .env("MC_CONFIG_DIR", &mc_config_dir)
            .arg("cp")
            .arg(&body_path)
            .arg(format!("gw/{PUBLIC_BUCKET}/smoke/path-private.txt"))
            .arg("--json"),
        "mc cp",
    )?;
    run_status(
        Command::new("mc")
            .env("MC_CONFIG_DIR", &mc_config_dir)
            .args([
                "stat",
                &format!("gw/{PUBLIC_BUCKET}/smoke/path-private.txt"),
                "--json",
            ]),
        "mc stat",
    )?;
    let mc_cat = run_output(
        Command::new("mc")
            .env("MC_CONFIG_DIR", &mc_config_dir)
            .args(["cat", &format!("gw/{PUBLIC_BUCKET}/smoke/path-private.txt")]),
        "mc cat",
    )?;
    if mc_cat.as_slice() != body {
        anyhow::bail!("mc cat returned a different body than mc cp wrote");
    }

    let rclone_list = run_output(
        Command::new("rclone")
            .env("RCLONE_CONFIG_GW_TYPE", "s3")
            .env("RCLONE_CONFIG_GW_PROVIDER", "Other")
            .env("RCLONE_CONFIG_GW_ACCESS_KEY_ID", ACCESS_KEY_ID)
            .env("RCLONE_CONFIG_GW_SECRET_ACCESS_KEY", SECRET_ACCESS_KEY)
            .env("RCLONE_CONFIG_GW_ENDPOINT", endpoint)
            .env("RCLONE_CONFIG_GW_REGION", "us-east-1")
            .env("RCLONE_CONFIG_GW_NO_CHECK_BUCKET", "true")
            .args([
                "lsf",
                &format!("gw:{PUBLIC_BUCKET}/smoke"),
                "--s3-no-check-bucket",
            ]),
        "rclone lsf",
    )?;
    let rclone_list = String::from_utf8(rclone_list).context("rclone lsf output was not UTF-8")?;
    if !rclone_list.lines().any(|line| line == "path-private.txt") {
        anyhow::bail!("rclone lsf did not list the object written by mc");
    }

    let _ = fs::remove_file(body_path);
    let _ = fs::remove_dir_all(mc_config_dir);
    Ok(())
}

#[cfg(feature = "containers")]
fn run_status(command: &mut Command, label: &'static str) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("failed to start {label}"))?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("{label} exited with {status}");
    }
}

#[cfg(feature = "containers")]
fn run_output(command: &mut Command, label: &'static str) -> Result<Vec<u8>> {
    let output = command
        .output()
        .with_context(|| format!("failed to start {label}"))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        anyhow::bail!("{label} exited with {}", output.status);
    }
}

#[cfg(feature = "containers")]
fn unique_temp_path(name: &str) -> PathBuf {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    env::temp_dir().join(format!("rs3-{name}-{}-{millis}", std::process::id()))
}
