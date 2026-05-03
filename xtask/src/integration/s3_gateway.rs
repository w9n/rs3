//! Gateway-level S3 integration command.

use super::S3ContainerProvider;
#[cfg(feature = "containers")]
use super::gateway_process::{PUBLIC_BUCKET, RunningGateway};
#[cfg(feature = "containers")]
use super::s3_container;
#[cfg(feature = "containers")]
use anyhow::Context;
use anyhow::Result;
#[cfg(feature = "containers")]
use aws_sdk_s3::{Client, primitives::ByteStream};
use clap::Args;

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

#[derive(Debug, Args)]
pub(crate) struct S3GatewayArgs {
    /// Container provider used as the gateway backend.
    #[arg(long, value_enum, default_value_t = S3ContainerProvider::Rustfs)]
    container_provider: S3ContainerProvider,
    /// Existing backend bucket. If omitted, a temporary bucket is created.
    #[arg(long, env = "RS3_TEST_S3_BUCKET")]
    backend_bucket: Option<String>,
    /// Backend S3 signing region.
    #[arg(long, env = "RS3_TEST_S3_REGION")]
    region: Option<String>,
    /// Backend prefix for repository-owned objects.
    #[arg(long, env = "RS3_TEST_S3_PREFIX", default_value = "rs3-gateway")]
    backend_prefix: String,
}

#[cfg(not(feature = "containers"))]
pub(crate) fn run_s3_gateway(args: S3GatewayArgs) -> Result<()> {
    anyhow::bail!(
        "gateway container integration for {:?} requires `cargo run -p xtask --features containers -- integration s3-gateway`",
        args.container_provider,
    )
}

#[cfg(feature = "containers")]
pub(crate) fn run_s3_gateway(args: S3GatewayArgs) -> Result<()> {
    let backend = s3_container::start_s3_container(
        args.container_provider,
        args.backend_bucket,
        args.region,
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build gateway integration runtime")?;

    runtime.block_on(async {
        let mut gateway = RunningGateway::start(&backend, args.backend_prefix).await?;
        let client = gateway.client(&backend);
        let result = assert_gateway_contract(&client).await;
        let shutdown = gateway.shutdown();

        result?;
        shutdown?;
        Ok(())
    })
}

#[cfg(feature = "containers")]
async fn assert_gateway_contract(client: &Client) -> Result<()> {
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
