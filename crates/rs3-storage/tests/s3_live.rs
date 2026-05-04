//! Opt-in live S3-compatible storage contract tests.
#![cfg(feature = "s3")]

mod common;

use aws_sdk_s3::Client as SdkS3Client;
use aws_sdk_s3::config::{BehaviorVersion, Region};
use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use bytes::Bytes;
use common::assert_core_blob_store_contract;
use rs3_storage::{BlobStore, PutOptions, S3BlobStore, S3BlobStoreConfig};
use rs3_types::{BackendObjectId, RetentionMode, RetentionPolicy};
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

#[tokio::test]
#[ignore = "requires RS3_TEST_S3_OBJECT_LOCK=true and an Object Lock-enabled bucket"]
async fn live_s3_object_lock_retention_round_trips_and_blocks_version_delete() {
    if !env_bool("RS3_TEST_S3_OBJECT_LOCK").unwrap_or(false) {
        eprintln!("skipping live S3 Object Lock test: RS3_TEST_S3_OBJECT_LOCK is not true");
        return;
    }
    let Some(target) = live_target() else {
        eprintln!("skipping live S3 Object Lock test: RS3_TEST_S3_BUCKET is not set");
        return;
    };
    let retain_days = env_u32("RS3_TEST_S3_RETENTION_DAYS").unwrap_or(1);
    let policy = RetentionPolicy::new(RetentionMode::Governance, retain_days);
    let extended_policy = RetentionPolicy::new(RetentionMode::Governance, retain_days + 1);
    let object_id = BackendObjectId::new("retention/live-retained-object".to_owned())
        .unwrap_or_else(|error| panic!("test object id: {error}"));
    let object_key = backend_key(&target.config, &object_id);
    let store = S3BlobStore::from_environment(target.config.clone())
        .await
        .unwrap_or_else(|error| panic!("build S3 blob store: {error}"));

    store
        .validate_retention_support(Some(&policy))
        .await
        .unwrap_or_else(|error| panic!("validate Object Lock support: {error}"));
    let put = store
        .put(
            &object_id,
            Bytes::from_static(b"retained object body"),
            PutOptions {
                retention: Some(policy),
                content_type: Some("application/octet-stream".to_owned()),
                do_not_recreate: true,
            },
        )
        .await
        .unwrap_or_else(|error| panic!("put retained object: {error}"));
    assert!(retention_satisfies(put.retention.as_ref(), &policy));
    let version_id = put
        .version_id
        .clone()
        .unwrap_or_else(|| panic!("retained S3 PUT did not return a version id"));

    store
        .extend_retention(&object_id, extended_policy)
        .await
        .unwrap_or_else(|error| panic!("extend retained object: {error}"));
    let head = store
        .head(&object_id)
        .await
        .unwrap_or_else(|error| panic!("head retained object: {error}"));
    assert!(retention_satisfies(
        head.retention.as_ref(),
        &extended_policy
    ));

    let client = sdk_client(&target.config).await;
    let delete = client
        .delete_object()
        .bucket(target.config.bucket.as_str())
        .key(object_key)
        .version_id(version_id)
        .send()
        .await;
    assert!(
        matches!(delete, Err(ref error) if retention_delete_blocked(error)),
        "version delete was not blocked by Object Lock: {delete:?}"
    );
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

fn backend_key(config: &S3BlobStoreConfig, object_id: &BackendObjectId) -> String {
    match config.prefix.as_deref() {
        Some(prefix) => format!("{prefix}/{}", object_id.as_str()),
        None => object_id.as_str().to_owned(),
    }
}

async fn sdk_client(config: &S3BlobStoreConfig) -> SdkS3Client {
    let region = aws_config::meta::region::RegionProviderChain::first_try(
        config.region.clone().map(Region::new),
    )
    .or_default_provider()
    .or_else(Region::new("us-east-1"));
    let shared_config = aws_config::defaults(BehaviorVersion::latest())
        .region(region)
        .load()
        .await;
    let mut builder = aws_sdk_s3::config::Builder::from(&shared_config)
        .force_path_style(!config.virtual_hosted_style);
    if let Some(endpoint_url) = config.endpoint_url.as_deref() {
        builder = builder.endpoint_url(endpoint_url);
    }
    SdkS3Client::from_conf(builder.build())
}

fn retention_satisfies(actual: Option<&RetentionPolicy>, requested: &RetentionPolicy) -> bool {
    let Some(actual) = actual else {
        return false;
    };
    retention_mode_strength(actual.mode) >= retention_mode_strength(requested.mode)
        && actual.retain_days >= requested.retain_days
}

fn retention_mode_strength(mode: RetentionMode) -> u8 {
    match mode {
        RetentionMode::None => 0,
        RetentionMode::Governance => 1,
        RetentionMode::Compliance => 2,
    }
}

fn retention_delete_blocked<E, R>(error: &SdkError<E, R>) -> bool
where
    E: ProvideErrorMetadata,
{
    matches!(
        error
            .as_service_error()
            .and_then(ProvideErrorMetadata::code),
        Some("AccessDenied" | "InvalidRequest" | "MethodNotAllowed")
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

fn env_u32(name: &str) -> Option<u32> {
    env::var(name).ok()?.parse().ok().filter(|value| *value > 0)
}
