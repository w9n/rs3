//! Exercise SDK response parsing and real pagination cursors without a provider.

use super::{S3BlobStore, S3BlobStoreConfig, collect_get_body};
use crate::{BlobListMode, BlobStore, ByteRange, StorageError};
use aws_sdk_s3::Client;
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;
use bytes::Bytes;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct ScriptedProvider {
    store: S3BlobStore,
    requests: Arc<Mutex<Vec<String>>>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for ScriptedProvider {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl ScriptedProvider {
    async fn new(responses: Vec<String>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let endpoint = format!("http://{}", listener.local_addr().expect("address"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let received = requests.clone();
        let server = tokio::spawn(async move {
            for body in responses {
                let (mut stream, _) = listener.accept().await.expect("request");
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    assert!(header.len() < 16 * 1024, "request header budget");
                    header.push(stream.read_u8().await.expect("header byte"));
                }
                let header = String::from_utf8(header).expect("UTF-8 request");
                // Retain only the request target, never authorization headers.
                received
                    .lock()
                    .expect("requests")
                    .push(header.lines().next().expect("request line").to_owned());
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("response");
                stream.shutdown().await.expect("close response");
            }
        });
        let sdk_config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .endpoint_url(&endpoint)
            .force_path_style(true)
            .credentials_provider(Credentials::new(
                "fixture", "fixture", None, None, "fixture",
            ))
            .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
            .timeout_config(
                aws_sdk_s3::config::timeout::TimeoutConfig::builder()
                    .operation_timeout(Duration::from_secs(5))
                    .build(),
            )
            .build();
        let config = S3BlobStoreConfig::new("bucket")
            .expect("config")
            .with_endpoint_url(Some(endpoint))
            .with_allow_http(true);
        Self {
            store: S3BlobStore::from_client(Client::from_conf(sdk_config), config),
            requests,
            server,
        }
    }
}

fn versions_page(truncated: bool, members: &str, markers: &str) -> String {
    format!(
        "<ListVersionsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><IsTruncated>{truncated}</IsTruncated>{markers}{members}</ListVersionsResult>"
    )
}

const DELETE_MARKER: &str = "<DeleteMarker><Key>objects/a</Key><VersionId>deleted</VersionId><IsLatest>true</IsLatest></DeleteMarker>";
const VERSION: &str =
    "<Version><Key>objects/a</Key><VersionId>old</VersionId><Size>3</Size></Version>";
const NEXT_MARKERS: &str =
    "<NextKeyMarker>objects/a</NextKeyMarker><NextVersionIdMarker>deleted</NextVersionIdMarker>";

#[tokio::test]
async fn version_listing_follows_delete_marker_page_and_stops_at_is_truncated_false() {
    for bounded in [true, false] {
        let provider = ScriptedProvider::new(vec![
            versions_page(true, DELETE_MARKER, NEXT_MARKERS),
            // Terminal markers must not cause another request.
            versions_page(false, VERSION, NEXT_MARKERS),
        ])
        .await;
        let entries = if bounded {
            let mut listing = provider
                .store
                .open_bounded_list("objects/", BlobListMode::Versions)
                .await
                .expect("listing");
            let limit = NonZeroUsize::new(1).expect("limit");
            let first = listing.next_page(limit).await.expect("delete marker page");
            assert!(first.entries.is_empty());
            assert_eq!(first.consumed_items, 1);
            assert!(!first.is_complete);
            let second = listing.next_page(limit).await.expect("version page");
            assert_eq!(second.consumed_items, 1);
            assert!(second.is_complete);
            let terminal = listing.next_page(limit).await.expect("terminal page");
            assert!(terminal.entries.is_empty());
            assert_eq!(terminal.consumed_items, 0);
            assert!(terminal.is_complete);
            second.entries
        } else {
            provider
                .store
                .list_prefix_versions("objects/")
                .await
                .expect("complete inventory")
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].version_id.as_ref().expect("version").as_str(),
            "old"
        );
        let requests = provider.requests.lock().expect("requests");
        assert_eq!(requests.len(), 2);
        assert!(!requests[0].contains("key-marker="));
        assert!(requests[1].contains("key-marker=objects%2Fa"));
        assert!(requests[1].contains("version-id-marker=deleted"));
    }
}

#[tokio::test]
async fn truncated_version_page_requires_advancing_markers() {
    for responses in [
        vec![versions_page(true, DELETE_MARKER, "")],
        vec![
            versions_page(true, DELETE_MARKER, NEXT_MARKERS),
            versions_page(true, DELETE_MARKER, NEXT_MARKERS),
        ],
    ] {
        let provider = ScriptedProvider::new(responses).await;
        assert_eq!(
            provider.store.list_prefix_versions("objects/").await,
            Err(StorageError::InvalidListPage)
        );
    }
}

#[tokio::test]
async fn version_page_budget_includes_filtered_delete_markers() {
    let provider = ScriptedProvider::new(vec![versions_page(
        false,
        &format!("{DELETE_MARKER}{VERSION}"),
        "",
    )])
    .await;
    let mut listing = provider
        .store
        .open_bounded_list("objects/", BlobListMode::Versions)
        .await
        .expect("listing");
    assert_eq!(
        listing
            .next_page(NonZeroUsize::new(1).expect("limit"))
            .await,
        Err(StorageError::InvalidListPage)
    );
}

#[tokio::test]
async fn full_get_requires_declared_length_and_exact_body_without_eager_allocation() {
    for (declared, success) in [
        (Some(5), true),
        (Some(4), false),
        (Some(6), false),
        (None, false),
        (Some(-1), false),
        (Some(i64::MAX), false),
    ] {
        let result = collect_get_body(
            ByteStream::from(Bytes::from_static(b"exact")),
            ByteRange::Full,
            declared,
        )
        .await;
        if success {
            assert_eq!(
                result.expect("exact response"),
                Bytes::from_static(b"exact")
            );
        } else {
            assert!(
                matches!(result, Err(StorageError::Provider(_))),
                "declared={declared:?}"
            );
        }
    }
    assert_eq!(
        collect_get_body(ByteStream::from(Bytes::new()), ByteRange::Full, Some(0))
            .await
            .expect("empty object"),
        Bytes::new()
    );
}

#[tokio::test]
async fn inventory_requires_an_explicit_completion_flag() {
    for (mode, body) in [
        (BlobListMode::Current, "<ListBucketResult/>"),
        (BlobListMode::Versions, "<ListVersionsResult/>"),
    ] {
        let provider = ScriptedProvider::new(vec![body.to_owned()]).await;
        let mut listing = provider
            .store
            .open_bounded_list("objects/", mode)
            .await
            .expect("listing");
        assert_eq!(
            listing
                .next_page(NonZeroUsize::new(1).expect("limit"))
                .await,
            Err(StorageError::InvalidListPage)
        );
    }
}

#[tokio::test]
async fn current_inventory_follows_the_token_and_sorts_the_collected_result() {
    let provider = ScriptedProvider::new(vec![
        "<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>next</NextContinuationToken><Contents><Key>objects/b</Key><Size>3</Size></Contents></ListBucketResult>".to_owned(),
        "<ListBucketResult><IsTruncated>false</IsTruncated><NextContinuationToken>ignored</NextContinuationToken><Contents><Key>objects/a</Key><Size>2</Size></Contents></ListBucketResult>".to_owned(),
    ]).await;
    let entries = provider
        .store
        .list_prefix("objects/")
        .await
        .expect("inventory");
    let keys = entries
        .iter()
        .map(|entry| entry.object_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(keys, vec!["objects/a", "objects/b"]);
    let requests = provider.requests.lock().expect("requests");
    assert_eq!(requests.len(), 2);
    assert!(requests[1].contains("continuation-token=next"));
}

#[tokio::test]
async fn truncated_current_inventory_requires_an_advancing_token() {
    for pages in [
        vec![""],
        vec!["<NextContinuationToken>same</NextContinuationToken>"; 2],
    ] {
        let provider = ScriptedProvider::new(pages.into_iter().map(|token|
            format!("<ListBucketResult><IsTruncated>true</IsTruncated>{token}</ListBucketResult>"))
            .collect()).await;
        assert_eq!(
            provider.store.list_prefix("objects/").await,
            Err(StorageError::InvalidListPage)
        );
    }
}

#[tokio::test]
async fn malformed_inventory_members_cannot_be_interpreted_as_an_empty_prefix() {
    for (mode, root, member_tag) in [
        (BlobListMode::Current, "ListBucketResult", "Contents"),
        (BlobListMode::Versions, "ListVersionsResult", "Version"),
    ] {
        for fields in [
            "<Size>3</Size><VersionId>old</VersionId>",
            "<Key>objects/a</Key><VersionId>old</VersionId>",
            "<Key>objects/a</Key><Size>-1</Size><VersionId>old</VersionId>",
            "<Key>outside/a</Key><Size>3</Size><VersionId>old</VersionId>",
        ] {
            let provider = ScriptedProvider::new(vec![format!(
                "<{root}><IsTruncated>false</IsTruncated><{member_tag}>{fields}</{member_tag}></{root}>"
            )]).await;
            let mut listing = provider
                .store
                .open_bounded_list("objects/", mode)
                .await
                .expect("listing");
            assert_eq!(
                listing
                    .next_page(NonZeroUsize::new(1).expect("limit"))
                    .await,
                Err(StorageError::InvalidListPage),
                "mode={mode:?}, fields={fields}"
            );
        }
        let provider = ScriptedProvider::new(vec![format!(
            "<{root}><IsTruncated>false</IsTruncated><CommonPrefixes><Prefix>objects/</Prefix></CommonPrefixes></{root}>"
        )]).await;
        let mut listing = provider
            .store
            .open_bounded_list("objects/", mode)
            .await
            .expect("listing");
        assert_eq!(
            listing
                .next_page(NonZeroUsize::new(1).expect("limit"))
                .await,
            Err(StorageError::InvalidListPage)
        );
    }
    let provider = ScriptedProvider::new(vec![versions_page(
        false,
        "<Version><Key>objects/a</Key><Size>3</Size></Version>",
        "",
    )])
    .await;
    assert_eq!(
        provider.store.list_prefix_versions("objects/").await,
        Err(StorageError::InvalidListPage)
    );
}
