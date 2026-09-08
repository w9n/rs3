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
use rs3_crypto::Sha256Hasher;
#[cfg(feature = "containers")]
use serde_json::Value;
#[cfg(feature = "containers")]
use std::env;
#[cfg(feature = "containers")]
use std::fs;
#[cfg(feature = "containers")]
use std::io::{Read, Write};
#[cfg(feature = "containers")]
use std::path::{Path, PathBuf};
#[cfg(feature = "containers")]
use std::process::{Command, Output};
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
#[cfg(feature = "containers")]
const TOOLING_FIXTURE_SIZE: usize = 9 * 1024 * 1024 + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum S3GatewayMode {
    /// Start a disposable local backend container.
    Container,
    /// Use an already configured S3-compatible backend.
    Provided,
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
    /// Repository retention mode for repository-owned backend objects.
    #[arg(long, env = "RS3_REPOSITORY_RETENTION_MODE", value_enum)]
    retention_mode: Option<S3GatewayRetentionMode>,
    /// Repository retention duration in days.
    #[arg(long, env = "RS3_REPOSITORY_RETENTION_DAYS")]
    retention_days: Option<u32>,
    /// Also exercise mc and rclone current/unversioned listing and reads.
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
            assert_operator_tooling_smoke(&gateway, backend).await?;
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
async fn assert_operator_tooling_smoke(
    gateway: &RunningGateway,
    backend: &GatewayBackend,
) -> Result<()> {
    let fixture_root = unique_temp_path("tooling-smoke");
    fs::create_dir_all(&fixture_root).context("failed to create tooling smoke directory")?;
    let _cleanup = ToolingSmokeCleanup(fixture_root.clone());
    let source_dir = fixture_root.join("source");
    fs::create_dir_all(&source_dir).context("failed to create tooling smoke source directory")?;
    let source_path = source_dir.join("large.bin");
    write_tooling_fixture(&source_path)?;
    let source = source_path
        .to_str()
        .context("tooling smoke source path was not valid UTF-8")?;
    let mc_config_dir = fixture_root.join("mc");
    fs::create_dir_all(&mc_config_dir).context("failed to create temporary mc config directory")?;
    let aws_config_path = fixture_root.join("aws-config");
    fs::write(
        &aws_config_path,
        "[default]\nregion = us-east-1\ns3 =\n    multipart_threshold = 8MB\n    multipart_chunksize = 8MB\n    max_concurrent_requests = 2\n",
    )
    .context("failed to write AWS tooling smoke config")?;
    let aws_credentials_path = fixture_root.join("empty-credentials");
    fs::write(&aws_credentials_path, b"")
        .context("failed to write empty AWS tooling smoke credentials")?;

    let endpoint = gateway.endpoint_url();
    require_tool("aws", &["--version"], Some("aws-cli/2"))?;
    require_tool("rclone", &["version"], Some("rclone v"))?;
    require_tool("mc", &["--version"], Some("mc version"))?;
    require_tool("restic", &["version"], Some("restic"))?;
    eprintln!(
        "tooling capability scope: custom metadata is accepted but not persisted for ordinary PUT and multipart uploads; this smoke does not claim metadata preservation"
    );

    let smoke_prefix = format!("tooling/rs3-{}/{}/", std::process::id(), unique_millis());
    let aws_remote = format!("s3://{PUBLIC_BUCKET}/{smoke_prefix}aws/large.bin");
    let mc_remote = format!("gw/{PUBLIC_BUCKET}/{smoke_prefix}mc/large.bin");
    let rclone_remote = format!("gw:{PUBLIC_BUCKET}/{smoke_prefix}rclone/large.bin");
    let rclone_check_remote = format!("gw:{PUBLIC_BUCKET}/{smoke_prefix}aws");
    let restic_repository = format!("s3:{endpoint}/{PUBLIC_BUCKET}/{smoke_prefix}restic");

    let smoke_result: Result<()> = (|| {
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
                .args(["cp", source, mc_remote.as_str(), "--json"]),
            "mc multipart-sized upload",
        )?;
        run_status(
            Command::new("mc")
                .env("MC_CONFIG_DIR", &mc_config_dir)
                .args(["stat", mc_remote.as_str(), "--json"]),
            "mc stat",
        )?;
        let mc_download = fixture_root.join("mc-download.bin");
        run_status(
            Command::new("mc")
                .env("MC_CONFIG_DIR", &mc_config_dir)
                .args([
                    "cp",
                    mc_remote.as_str(),
                    mc_download
                        .to_str()
                        .context("mc download path was not valid UTF-8")?,
                ]),
            "mc download",
        )?;
        assert_files_equal(&source_path, &mc_download, "mc")?;

        let mut aws_upload = configured_aws_command(&aws_config_path, &aws_credentials_path);
        aws_upload.args([
            "s3",
            "cp",
            source,
            aws_remote.as_str(),
            "--no-progress",
            "--endpoint-url",
            endpoint.as_str(),
        ]);
        run_status(&mut aws_upload, "aws cli multipart-sized upload")?;
        let aws_download = fixture_root.join("aws-download.bin");
        let aws_download_str = aws_download
            .to_str()
            .context("AWS download path was not valid UTF-8")?;
        let mut aws_get = configured_aws_command(&aws_config_path, &aws_credentials_path);
        aws_get.args([
            "s3",
            "cp",
            aws_remote.as_str(),
            aws_download_str,
            "--no-progress",
            "--endpoint-url",
            endpoint.as_str(),
        ]);
        run_status(&mut aws_get, "aws cli download")?;
        assert_files_equal(&source_path, &aws_download, "aws cli")?;
        let mut aws_head = configured_aws_command(&aws_config_path, &aws_credentials_path);
        let aws_head_output = run_output(
            aws_head.args([
                "s3api",
                "head-object",
                "--bucket",
                PUBLIC_BUCKET,
                "--key",
                &format!("{smoke_prefix}aws/large.bin"),
                "--checksum-mode",
                "ENABLED",
                "--endpoint-url",
                endpoint.as_str(),
                "--output",
                "json",
            ]),
            "aws cli head-object",
        )?;
        assert_aws_multipart_head(&aws_head_output, "aws")?;

        let rclone_command = || {
            let mut command = Command::new("rclone");
            command
                .env("RCLONE_CONFIG_GW_TYPE", "s3")
                .env("RCLONE_CONFIG_GW_PROVIDER", "Other")
                .env("RCLONE_CONFIG_GW_ACCESS_KEY_ID", ACCESS_KEY_ID)
                .env("RCLONE_CONFIG_GW_SECRET_ACCESS_KEY", SECRET_ACCESS_KEY)
                .env("RCLONE_CONFIG_GW_ENDPOINT", &endpoint)
                .env("RCLONE_CONFIG_GW_REGION", "us-east-1")
                .env("RCLONE_CONFIG_GW_NO_CHECK_BUCKET", "true")
                .env("RCLONE_CONFIG_GW_NO_SYSTEM_METADATA", "true")
                .env("RCLONE_CONFIG_GW_DISABLE_CHECKSUM", "true")
                .env("RCLONE_CONFIG_GW_USE_MULTIPART_ETAG", "true");
            command
        };
        let rclone_mc_remote = format!("gw:{PUBLIC_BUCKET}/{smoke_prefix}mc/large.bin");
        let rclone_mc_download = fixture_root.join("rclone-mc-download.bin");
        run_status(
            rclone_command().args([
                "copyto",
                rclone_mc_remote.as_str(),
                rclone_mc_download
                    .to_str()
                    .context("rclone download path was not valid UTF-8")?,
            ]),
            "rclone read of mc object",
        )?;
        assert_files_equal(&source_path, &rclone_mc_download, "rclone")?;
        let rclone_listing = run_output(
            rclone_command().args([
                "lsf",
                format!("gw:{PUBLIC_BUCKET}/{smoke_prefix}mc").as_str(),
            ]),
            "rclone list",
        )?;
        if !String::from_utf8_lossy(&rclone_listing)
            .lines()
            .any(|line| line.trim() == "large.bin")
        {
            anyhow::bail!("rclone list did not expose the mc-uploaded fixture");
        }
        let rclone_versions = run_output(
            rclone_command().args([
                "lsf",
                format!("gw:{PUBLIC_BUCKET}/{smoke_prefix}mc").as_str(),
                "--s3-versions",
                "--s3-list-chunk",
                "1",
            ]),
            "rclone version list",
        )?;
        if !String::from_utf8_lossy(&rclone_versions)
            .lines()
            .any(|line| line.trim_end().ends_with("large.bin"))
        {
            anyhow::bail!("rclone version list did not expose the current fixture");
        }
        let rclone_version_dirs = run_output(
            rclone_command().args([
                "lsd",
                format!("gw:{PUBLIC_BUCKET}").as_str(),
                "--s3-versions",
            ]),
            "rclone version directory list",
        )?;
        if !String::from_utf8_lossy(&rclone_version_dirs)
            .lines()
            .any(|line| line.split_whitespace().last() == Some("tooling"))
        {
            anyhow::bail!("rclone version directory list did not expose the tooling prefix");
        }
        let rclone_version_body = run_output(
            rclone_command().args(["cat", rclone_mc_remote.as_str(), "--s3-versions"]),
            "rclone version-mode read",
        )?;
        if rclone_version_body.as_slice()
            != fs::read(&source_path)
                .context("failed to read fixture")?
                .as_slice()
        {
            anyhow::bail!("rclone version-mode read returned different bytes");
        }
        eprintln!(
            "tooling capability scope: rclone uses --s3-no-system-metadata, --s3-disable-checksum and --s3-use-multipart-etag; default-client metadata preservation is not asserted"
        );
        let mut rclone_upload = rclone_command();
        run_status(
            rclone_upload.args([
                "copyto",
                source,
                rclone_remote.as_str(),
                "--s3-upload-cutoff",
                "8Mi",
                "--s3-chunk-size",
                "8Mi",
                "--s3-upload-concurrency",
                "2",
                "--retries",
                "1",
                "--low-level-retries",
                "1",
            ]),
            "rclone multipart-sized upload",
        )?;
        let rclone_download = fixture_root.join("rclone-download.bin");
        run_status(
            rclone_command().args([
                "copyto",
                rclone_remote.as_str(),
                rclone_download
                    .to_str()
                    .context("rclone download path was not valid UTF-8")?,
            ]),
            "rclone download",
        )?;
        assert_files_equal(&source_path, &rclone_download, "rclone")?;
        let mut rclone_head = configured_aws_command(&aws_config_path, &aws_credentials_path);
        let rclone_head_output = run_output(
            rclone_head.args([
                "s3api",
                "head-object",
                "--bucket",
                PUBLIC_BUCKET,
                "--key",
                &format!("{smoke_prefix}rclone/large.bin"),
                "--checksum-mode",
                "ENABLED",
                "--endpoint-url",
                endpoint.as_str(),
                "--output",
                "json",
            ]),
            "AWS head-object for rclone upload",
        )?;
        assert_aws_multipart_head(&rclone_head_output, "rclone")?;
        run_status(
            rclone_command().args([
                "check",
                "--download",
                "--one-way",
                source_dir
                    .to_str()
                    .context("rclone source directory was not valid UTF-8")?,
                rclone_check_remote.as_str(),
            ]),
            "rclone multipart download verification",
        )?;

        let restic_cache = fixture_root.join("restic-cache");
        let mut restic_init = configured_restic_command(&restic_repository, &restic_cache);
        restic_init.arg("init");
        run_status(&mut restic_init, "restic init")?;
        let mut restic_backup = configured_restic_command(&restic_repository, &restic_cache);
        restic_backup
            .current_dir(&fixture_root)
            .args(["backup", "source"]);
        run_status(&mut restic_backup, "restic backup")?;
        let restic_restore = fixture_root.join("restic-restore");
        fs::create_dir_all(&restic_restore).context("failed to create restic restore directory")?;
        let mut restic_restore_command =
            configured_restic_command(&restic_repository, &restic_cache);
        restic_restore_command.args([
            "restore",
            "latest",
            "--target",
            restic_restore
                .to_str()
                .context("restic restore path was not valid UTF-8")?,
        ]);
        run_status(&mut restic_restore_command, "restic restore")?;
        let mut restored = Vec::new();
        find_named_files(&restic_restore, "large.bin", &mut restored)?;
        if restored.len() != 1 {
            anyhow::bail!("restic restore did not produce exactly one large fixture");
        }
        assert_files_equal(&source_path, &restored[0], "restic")?;

        Ok(())
    })();
    let cleanup = cleanup_gateway_prefix(gateway, backend, &smoke_prefix)
        .await
        .context("failed to clean tooling smoke objects");
    smoke_result?;
    cleanup?;
    Ok(())
}

#[cfg(feature = "containers")]
struct ToolingSmokeCleanup(PathBuf);

#[cfg(feature = "containers")]
impl Drop for ToolingSmokeCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(feature = "containers")]
fn write_tooling_fixture(path: &Path) -> Result<()> {
    const CHUNK_SIZE: usize = 64 * 1024;
    let mut file = fs::File::create(path).context("failed to create tooling smoke fixture")?;
    let mut chunk = [0_u8; CHUNK_SIZE];
    let mut written = 0usize;
    let mut block_index = 0u64;
    while written < TOOLING_FIXTURE_SIZE {
        let length = (TOOLING_FIXTURE_SIZE - written).min(CHUNK_SIZE);
        for block in chunk[..length].chunks_mut(32) {
            let mut input = [0_u8; 16];
            input[..8].copy_from_slice(b"rs3-t17!");
            input[8..].copy_from_slice(&block_index.to_be_bytes());
            let digest = Sha256Hasher::digest(input);
            block.copy_from_slice(&digest[..block.len()]);
            block_index += 1;
        }
        file.write_all(&chunk[..length])
            .context("failed to write tooling smoke fixture")?;
        written += length;
    }
    Ok(())
}

#[cfg(feature = "containers")]
fn assert_files_equal(expected: &Path, actual: &Path, client: &'static str) -> Result<()> {
    const BUFFER_SIZE: usize = 128 * 1024;
    let mut expected_file = fs::File::open(expected)
        .with_context(|| format!("{client} verification could not open expected file"))?;
    let mut actual_file = fs::File::open(actual)
        .with_context(|| format!("{client} verification could not open downloaded file"))?;
    let mut expected_buffer = [0_u8; BUFFER_SIZE];
    let mut actual_buffer = [0_u8; BUFFER_SIZE];
    loop {
        let expected_read = expected_file
            .read(&mut expected_buffer)
            .with_context(|| format!("{client} verification could not read expected file"))?;
        let actual_read = actual_file
            .read(&mut actual_buffer)
            .with_context(|| format!("{client} verification could not read downloaded file"))?;
        if expected_read != actual_read
            || expected_buffer[..expected_read] != actual_buffer[..actual_read]
        {
            anyhow::bail!("{client} downloaded bytes differ from the fixture");
        }
        if expected_read == 0 {
            break;
        }
    }
    Ok(())
}

#[cfg(feature = "containers")]
fn find_named_files(root: &Path, name: &str, found: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(root).with_context(|| {
        format!(
            "failed to read tooling smoke restore directory {}",
            root.display()
        )
    })? {
        let entry = entry.context("failed to inspect tooling smoke restore entry")?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .context("failed to inspect tooling smoke restore entry type")?;
        if file_type.is_dir() {
            find_named_files(&path, name, found)?;
        } else if file_type.is_file()
            && path.file_name().and_then(|value| value.to_str()) == Some(name)
        {
            found.push(path);
        }
    }
    Ok(())
}

#[cfg(feature = "containers")]
fn require_tool(program: &'static str, args: &[&str], marker: Option<&str>) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("tooling smoke requires {program} on PATH"))?;
    if !output.status.success() {
        anyhow::bail!(
            "tooling smoke preflight {program} exited with {}",
            output.status
        );
    }
    let detail = command_output_detail(&output);
    if let Some(marker) = marker
        && !detail.contains(marker)
    {
        anyhow::bail!("tooling smoke preflight {program} did not report {marker}: {detail}");
    }
    eprintln!("tooling version {program}: {}", detail.replace('\n', " "));
    Ok(())
}

#[cfg(feature = "containers")]
fn configured_aws_command(config_path: &Path, credentials_path: &Path) -> Command {
    let mut command = Command::new("aws");
    command
        .env("AWS_CONFIG_FILE", config_path)
        .env("AWS_SHARED_CREDENTIALS_FILE", credentials_path)
        .env("AWS_ACCESS_KEY_ID", ACCESS_KEY_ID)
        .env("AWS_SECRET_ACCESS_KEY", SECRET_ACCESS_KEY)
        .env("AWS_DEFAULT_REGION", "us-east-1")
        .env("AWS_EC2_METADATA_DISABLED", "true")
        .env("AWS_PAGER", "")
        .env_remove("AWS_REQUEST_CHECKSUM_CALCULATION")
        .env_remove("AWS_RESPONSE_CHECKSUM_VALIDATION")
        .env_remove("AWS_SESSION_TOKEN")
        .env_remove("AWS_PROFILE")
        .env_remove("AWS_WEB_IDENTITY_TOKEN_FILE")
        .env_remove("AWS_ROLE_ARN")
        .env_remove("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
        .env_remove("AWS_CONTAINER_CREDENTIALS_FULL_URI")
        .env_remove("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE");
    command
}

#[cfg(feature = "containers")]
fn configured_restic_command(repository: &str, cache_dir: &Path) -> Command {
    let mut command = Command::new("restic");
    command
        .env("RESTIC_REPOSITORY", repository)
        .env("RESTIC_PASSWORD", "rs3-tooling-smoke-password")
        .env("AWS_ACCESS_KEY_ID", ACCESS_KEY_ID)
        .env("AWS_SECRET_ACCESS_KEY", SECRET_ACCESS_KEY)
        .env("AWS_DEFAULT_REGION", "us-east-1")
        .env("AWS_EC2_METADATA_DISABLED", "true")
        .env("RESTIC_CACHE_DIR", cache_dir)
        .env_remove("AWS_SESSION_TOKEN")
        .env_remove("AWS_PROFILE")
        .env_remove("AWS_WEB_IDENTITY_TOKEN_FILE")
        .env_remove("AWS_ROLE_ARN")
        .env_remove("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
        .env_remove("AWS_CONTAINER_CREDENTIALS_FULL_URI")
        .env_remove("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE");
    command
}

#[cfg(feature = "containers")]
fn command_output_detail(output: &Output) -> String {
    let mut detail = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() {
        if !detail.is_empty() {
            detail.push('\n');
        }
        detail.push_str(&stderr);
    }
    let detail = detail.trim();
    let truncated: String = detail.chars().take(4000).collect();
    if truncated.len() == detail.len() {
        truncated
    } else {
        format!("{truncated}...")
    }
}

#[cfg(feature = "containers")]
fn assert_aws_multipart_head(output: &[u8], client: &'static str) -> Result<()> {
    let value: Value = serde_json::from_slice(output).context("AWS HeadObject JSON was invalid")?;
    let length = value
        .get("ContentLength")
        .and_then(Value::as_u64)
        .context("AWS HeadObject did not return ContentLength")?;
    if length != TOOLING_FIXTURE_SIZE as u64 {
        anyhow::bail!(
            "AWS HeadObject returned ContentLength {length}, expected {TOOLING_FIXTURE_SIZE}"
        );
    }
    let etag = value
        .get("ETag")
        .and_then(Value::as_str)
        .context("AWS HeadObject did not return ETag")?;
    assert_multipart_etag(etag, "AWS HeadObject")?;
    eprintln!(
        "tooling multipart verified: {}",
        serde_json::json!({"client": client, "content_length": length, "etag": etag})
    );
    Ok(())
}

#[cfg(feature = "containers")]
fn assert_multipart_etag(etag: &str, label: &'static str) -> Result<()> {
    let etag = etag.trim_matches('"');
    let (digest, count) = etag
        .rsplit_once('-')
        .context("multipart ETag did not include a part-count suffix")?;
    if count != "2"
        || digest.len() != 32
        || !digest
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        anyhow::bail!("{label} did not return the expected two-part ETag");
    }
    Ok(())
}

#[cfg(feature = "containers")]
async fn cleanup_gateway_prefix(
    gateway: &RunningGateway,
    backend: &GatewayBackend,
    prefix: &str,
) -> Result<()> {
    let client = gateway.client_for_backend(backend);
    for _ in 0..1024 {
        let page = client
            .list_objects_v2()
            .bucket(PUBLIC_BUCKET)
            .prefix(prefix)
            .send()
            .await
            .context("failed to list tooling smoke objects for cleanup")?;
        let keys = page
            .contents()
            .iter()
            .filter_map(|object| object.key())
            .collect::<Vec<_>>();
        if keys.is_empty() {
            return Ok(());
        }
        for key in keys {
            client
                .delete_object()
                .bucket(PUBLIC_BUCKET)
                .key(key)
                .send()
                .await
                .context("failed to delete tooling smoke object during cleanup")?;
        }
    }
    anyhow::bail!("tooling smoke cleanup did not drain its prefix")
}

#[cfg(feature = "containers")]
fn unique_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
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
