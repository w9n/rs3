//! Opt-in live S3-compatible storage contract tests.
#![cfg(feature = "s3")]

mod common;

use common::assert_core_blob_store_contract;
use rs3_storage::{S3BlobStore, S3BlobStoreConfig};
use std::env;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::test]
#[ignore = "requires RS3_TEST_S3_BUCKET and S3-compatible credentials"]
async fn live_s3_backend_satisfies_core_blob_store_contract() {
    let Some(target) = live_target() else {
        eprintln!("skipping live S3 test: RS3_TEST_S3_BUCKET is not set");
        return;
    };

    let store = S3BlobStore::from_environment(target.config)
        .await
        .unwrap_or_else(|error| panic!("build S3 blob store: {error}"));

    assert_core_blob_store_contract(&store, &target.provider_name).await;
}

struct LiveS3Target {
    provider_name: String,
    config: S3BlobStoreConfig,
}

fn live_target() -> Option<LiveS3Target> {
    let bucket = env::var("RS3_TEST_S3_BUCKET").ok()?;
    let provider_name = env::var("RS3_TEST_S3_PROVIDER")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "s3-compatible".to_owned());
    let prefix = env::var("RS3_TEST_S3_PREFIX")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default_prefix(&provider_name));
    let endpoint_url = env::var("RS3_TEST_S3_ENDPOINT_URL").ok();
    let region = env::var("RS3_TEST_S3_REGION")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| Some("us-east-1".to_owned()));
    let allow_http = env_bool("RS3_TEST_S3_ALLOW_HTTP").unwrap_or_else(|| {
        endpoint_url
            .as_deref()
            .is_some_and(|url| url.starts_with("http://"))
    });
    let virtual_hosted_style = env_bool("RS3_TEST_S3_VIRTUAL_HOSTED_STYLE").unwrap_or(false);

    let config = S3BlobStoreConfig::new(bucket)
        .unwrap_or_else(|error| panic!("invalid live S3 bucket: {error}"))
        .with_prefix(Some(prefix))
        .with_endpoint_url(endpoint_url)
        .with_region(region)
        .with_allow_http(allow_http)
        .with_virtual_hosted_style(virtual_hosted_style);

    Some(LiveS3Target {
        provider_name: provider_slug(&provider_name),
        config,
    })
}

fn default_prefix(provider_name: &str) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    format!(
        "rs3-live/{}-{millis}-{}",
        provider_slug(provider_name),
        process::id()
    )
}

fn provider_slug(provider_name: &str) -> String {
    let slug = provider_name
        .trim()
        .chars()
        .map(|character| match character {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => character,
            _ => '-',
        })
        .collect::<String>();

    if slug.is_empty() {
        "s3-compatible".to_owned()
    } else {
        slug
    }
}

fn env_bool(name: &str) -> Option<bool> {
    env::var(name)
        .ok()
        .and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
}
