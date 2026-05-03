//! Opt-in live S3-compatible storage contract tests.
#![cfg(feature = "s3")]

use bytes::Bytes;
use rs3_storage::{BlobStore, ByteRange, PutOptions, S3BlobStore, S3BlobStoreConfig, StorageError};
use rs3_types::BackendObjectId;
use std::env;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::test]
#[ignore = "requires RS3_TEST_S3_BUCKET and S3-compatible credentials"]
async fn live_s3_backend_satisfies_core_blob_store_contract() {
    let Some(config) = live_config() else {
        eprintln!("skipping live S3 test: RS3_TEST_S3_BUCKET is not set");
        return;
    };

    let store = S3BlobStore::from_environment(config)
        .await
        .unwrap_or_else(|error| panic!("build S3 blob store: {error}"));

    let first = object_id("segments/first");
    let second = object_id("segments/second");
    let outside = object_id("index/outside");

    store
        .put(
            &first,
            Bytes::from_static(b"hello live s3 backend"),
            PutOptions {
                do_not_recreate: true,
                ..PutOptions::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("put first object: {error}"));
    store
        .put(
            &second,
            Bytes::from_static(b"another object"),
            PutOptions::default(),
        )
        .await
        .unwrap_or_else(|error| panic!("put second object: {error}"));
    store
        .put(
            &outside,
            Bytes::from_static(b"outside listing prefix"),
            PutOptions::default(),
        )
        .await
        .unwrap_or_else(|error| panic!("put outside object: {error}"));

    let duplicate = store
        .put(
            &first,
            Bytes::from_static(b"must not overwrite"),
            PutOptions {
                do_not_recreate: true,
                ..PutOptions::default()
            },
        )
        .await;
    assert!(matches!(duplicate, Err(StorageError::AlreadyExists(_))));

    let metadata = store
        .head(&first)
        .await
        .unwrap_or_else(|error| panic!("head first object: {error}"));
    assert_eq!(metadata.object_id, first);
    assert_eq!(metadata.content_len, 21);

    let full = store
        .get_range(&first, ByteRange::Full)
        .await
        .unwrap_or_else(|error| panic!("get full object: {error}"));
    assert_eq!(full, Bytes::from_static(b"hello live s3 backend"));

    let range = store
        .get_range(&first, ByteRange::Slice { offset: 6, len: 4 })
        .await
        .unwrap_or_else(|error| panic!("get object range: {error}"));
    assert_eq!(range, Bytes::from_static(b"live"));

    let listed = store
        .list_prefix("segments/")
        .await
        .unwrap_or_else(|error| panic!("list object prefix: {error}"));
    let listed_ids = listed
        .into_iter()
        .map(|metadata| metadata.object_id)
        .collect::<Vec<_>>();
    assert_eq!(listed_ids, vec![first.clone(), second.clone()]);

    store
        .delete(&first)
        .await
        .unwrap_or_else(|error| panic!("delete first object: {error}"));
    assert!(matches!(
        store.head(&first).await,
        Err(StorageError::NotFound(_))
    ));

    cleanup(&store, &[second, outside]).await;
}

fn live_config() -> Option<S3BlobStoreConfig> {
    let bucket = env::var("RS3_TEST_S3_BUCKET").ok()?;
    let prefix = env::var("RS3_TEST_S3_PREFIX")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(default_prefix);
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

    Some(
        S3BlobStoreConfig::new(bucket)
            .unwrap_or_else(|error| panic!("invalid live S3 bucket: {error}"))
            .with_prefix(Some(prefix))
            .with_endpoint_url(endpoint_url)
            .with_region(region)
            .with_allow_http(allow_http)
            .with_virtual_hosted_style(virtual_hosted_style),
    )
}

fn default_prefix() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    format!("rs3-live/{millis}-{}", process::id())
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

fn object_id(value: &str) -> BackendObjectId {
    BackendObjectId::new(value).unwrap_or_else(|error| panic!("{error}"))
}

async fn cleanup(store: &S3BlobStore, object_ids: &[BackendObjectId]) {
    for object_id in object_ids {
        let _ = store.delete(object_id).await;
    }
}
