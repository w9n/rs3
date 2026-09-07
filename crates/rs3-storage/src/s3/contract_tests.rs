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
        Self::with_status(200, responses).await
    }

    async fn with_status(status: u16, responses: Vec<String>) -> Self {
        Self::with_headers(status, responses, "").await
    }

    async fn with_headers(status: u16, responses: Vec<String>, headers: &'static str) -> Self {
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
                    "HTTP/1.1 {status} Fixture\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
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

#[tokio::test]
async fn repository_lifecycle_rules_preserve_direct_reads_and_live_versions() {
    let cases = [
        (
            "<Status>Disabled</Status><Expiration><Days>1</Days></Expiration>",
            true,
        ),
        ("<Status>FutureStatus</Status>", false),
        (
            "<Status>Enabled</Status><Expiration><Days>1</Days></Expiration>",
            false,
        ),
        (
            "<Status>Enabled</Status><Expiration><Date>2030-01-01T00:00:00Z</Date></Expiration>",
            false,
        ),
        (
            "<Status>Enabled</Status><NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration>",
            false,
        ),
        (
            "<Status>Enabled</Status><Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration>",
            true,
        ),
        (
            "<Status>Enabled</Status><AbortIncompleteMultipartUpload><DaysAfterInitiation>7</DaysAfterInitiation></AbortIncompleteMultipartUpload>",
            true,
        ),
        (
            "<Status>Enabled</Status><Filter><Prefix>other/</Prefix></Filter><Expiration><Days>1</Days></Expiration>",
            true,
        ),
        (
            "<Status>Enabled</Status><Filter><Prefix>repo-other/</Prefix></Filter><Expiration><Days>1</Days></Expiration>",
            true,
        ),
        (
            "<Status>Enabled</Status><Prefix>other/</Prefix><Expiration><Days>1</Days></Expiration>",
            true,
        ),
        (
            "<Status>Enabled</Status><Filter><Prefix>repo/commits/</Prefix></Filter><Expiration><Days>1</Days></Expiration>",
            false,
        ),
        (
            "<Status>Enabled</Status><Filter><Prefix>rep</Prefix></Filter><Expiration><Days>1</Days></Expiration>",
            false,
        ),
        (
            "<Status>Enabled</Status><Filter><And><Prefix>other/</Prefix><Tag><Key>x</Key><Value>y</Value></Tag></And></Filter><Expiration><Days>1</Days></Expiration>",
            true,
        ),
        (
            "<Status>Enabled</Status><Filter><Tag><Key>x</Key><Value>y</Value></Tag></Filter><Expiration><Days>1</Days></Expiration>",
            false,
        ),
        (
            "<Status>Enabled</Status><Filter><ObjectSizeGreaterThan>1024</ObjectSizeGreaterThan></Filter><Expiration><Days>1</Days></Expiration>",
            false,
        ),
        (
            "<Status>Enabled</Status><Prefix>other/</Prefix><Filter><Prefix>repo/</Prefix></Filter><Expiration><Days>1</Days></Expiration>",
            false,
        ),
        (
            "<Status>Enabled</Status><Transition><Days>30</Days><StorageClass>STANDARD_IA</StorageClass></Transition>",
            true,
        ),
        (
            "<Status>Enabled</Status><Transition><Days>30</Days><StorageClass>ONEZONE_IA</StorageClass></Transition>",
            true,
        ),
        (
            "<Status>Enabled</Status><Transition><Days>30</Days><StorageClass>GLACIER_IR</StorageClass></Transition>",
            true,
        ),
        (
            "<Status>Enabled</Status><Transition><Days>30</Days><StorageClass>GLACIER</StorageClass></Transition>",
            false,
        ),
        (
            "<Status>Enabled</Status><NoncurrentVersionTransition><NoncurrentDays>30</NoncurrentDays><StorageClass>DEEP_ARCHIVE</StorageClass></NoncurrentVersionTransition>",
            false,
        ),
        (
            "<Status>Enabled</Status><Transition><Days>30</Days><StorageClass>INTELLIGENT_TIERING</StorageClass></Transition>",
            false,
        ),
        (
            "<Status>Enabled</Status><Transition><Days>30</Days><StorageClass>FUTURE_CLASS</StorageClass></Transition>",
            false,
        ),
    ];
    for (rule, allowed) in cases {
        let body = format!(
            "<LifecycleConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Rule>{rule}</Rule></LifecycleConfiguration>"
        );
        let mut provider = ScriptedProvider::new(vec![body]).await;
        provider.store.config = provider
            .store
            .config
            .clone()
            .with_prefix(Some("repo".to_owned()));
        let result = provider.store.validate_repository_write_policy(None).await;
        assert_eq!(result.is_ok(), allowed, "lifecycle fixture: {rule}");
        let requests = provider.requests.lock().expect("requests");
        assert_eq!(requests.len(), 1);
        assert!(requests[0].contains("?lifecycle"));
    }
}

#[tokio::test]
async fn repository_lifecycle_whole_bucket_and_rule_budget_fail_closed() {
    let rule = "<Rule><Status>Enabled</Status><Filter><Prefix>other/</Prefix></Filter><Expiration><Days>1</Days></Expiration></Rule>";
    for body in [
        format!("<LifecycleConfiguration>{rule}</LifecycleConfiguration>"),
        format!(
            "<LifecycleConfiguration>{}</LifecycleConfiguration>",
            "<Rule><Status>Disabled</Status></Rule>".repeat(1_001)
        ),
    ] {
        let provider = ScriptedProvider::new(vec![body]).await;
        assert!(
            provider
                .store
                .validate_repository_write_policy(None)
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn protected_put_does_not_retry_inside_sdk_but_read_retries_remain_enabled() {
    use crate::PutOptions;
    use rs3_types::{BackendObjectId, LegalHoldStatus, RetentionMode, RetentionPolicy};

    for options in [
        PutOptions {
            retention: Some(RetentionPolicy::new(RetentionMode::Compliance, 1)),
            ..PutOptions::default()
        },
        PutOptions {
            legal_hold: Some(LegalHoldStatus::On),
            ..PutOptions::default()
        },
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let endpoint = format!("http://{}", listener.local_addr().expect("address"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let received = Arc::clone(&requests);
        let server = tokio::spawn(async move {
            // A PUT failure may represent a lost reply after durable storage.
            // The following read is a positive control for configured retries.
            for status in [
                "503 Service Unavailable",
                "503 Service Unavailable",
                "200 OK",
            ] {
                let (mut stream, _) = listener.accept().await.expect("request");
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    assert!(header.len() < 16 * 1024, "header budget");
                    header.push(stream.read_u8().await.expect("header byte"));
                }
                let header = String::from_utf8(header).expect("UTF-8 header");
                let length = header
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().expect("length"))
                    })
                    .unwrap_or(0);
                assert!(length < 16 * 1024, "body budget");
                let mut body = vec![0; length];
                stream.read_exact(&mut body).await.expect("body");
                received
                    .lock()
                    .expect("requests")
                    .push(header.lines().next().expect("request line").to_owned());
                let body = if status.starts_with("503") {
                    "<Error><Code>ServiceUnavailable</Code></Error>"
                } else {
                    "<VersioningConfiguration/>"
                };
                stream.write_all(format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len(),
                ).as_bytes()).await.expect("response");
                stream.shutdown().await.expect("close");
            }
        });
        let sdk = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .endpoint_url(&endpoint)
            .force_path_style(true)
            .credentials_provider(Credentials::new(
                "fixture", "fixture", None, None, "fixture",
            ))
            .retry_config(aws_sdk_s3::config::retry::RetryConfig::standard().with_max_attempts(3))
            .timeout_config(
                aws_sdk_s3::config::timeout::TimeoutConfig::builder()
                    .operation_timeout(Duration::from_secs(5))
                    .build(),
            )
            .build();
        let client = Client::from_conf(sdk);
        let store = S3BlobStore::from_client(
            client.clone(),
            S3BlobStoreConfig::new("bucket")
                .expect("config")
                .with_endpoint_url(Some(endpoint))
                .with_allow_http(true),
        );
        let result = store
            .put(
                &BackendObjectId::new("opaque").expect("id"),
                Bytes::from_static(b"abc"),
                options,
            )
            .await;
        // Stop the server even if the assertion fails below.
        if result.is_ok() || requests.lock().expect("requests").len() != 1 {
            server.abort();
            panic!("protected PUT must return the first ambiguous result without retry");
        }
        client
            .get_bucket_versioning()
            .bucket("bucket")
            .send()
            .await
            .expect("read retry");
        server.await.expect("scripted server");
        let requests = requests.lock().expect("requests");
        assert_eq!(requests.len(), 3);
        assert!(requests[0].starts_with("PUT "));
        assert!(
            requests[1..]
                .iter()
                .all(|request| request.starts_with("GET "))
        );
    }
}

fn upload_with_parts(
    store: &S3BlobStore,
    parts: Vec<Option<aws_sdk_s3::types::CompletedPart>>,
) -> Box<dyn crate::BlobMultipartUpload> {
    Box::new(super::S3MultipartUpload {
        store: store.clone(),
        client: store.client.clone(),
        object_id: rs3_types::BackendObjectId::new("objects/multipart").expect("object ID"),
        key: "objects/multipart".to_owned(),
        upload_id: "fixture-upload".to_owned(),
        options: crate::PutOptions::default(),
        content_len: 1,
        parts,
        started: std::time::Instant::now(),
    })
}

#[tokio::test]
async fn invalid_multipart_completion_aborts_without_publishing() {
    for status in [200, 403] {
        for parts in [
            Vec::new(),
            vec![
                None,
                Some(
                    aws_sdk_s3::types::CompletedPart::builder()
                        .part_number(2)
                        .build(),
                ),
            ],
        ] {
            let provider = ScriptedProvider::with_status(
                status,
                vec![if status == 200 {
                    String::new()
                } else {
                    "<Error><Code>AccessDenied</Code><Message>fixture denied</Message></Error>"
                        .to_owned()
                }],
            )
            .await;
            let error = upload_with_parts(&provider.store, parts)
                .complete()
                .await
                .expect_err("invalid upload must not complete");
            assert_eq!(
                error,
                StorageError::Provider("multipart upload has missing parts".to_owned()),
                "cleanup failure must not replace the validation error",
            );
            let requests = provider.requests.lock().expect("requests");
            assert_eq!(requests.len(), 1);
            assert!(requests[0].starts_with("DELETE /bucket/objects/multipart?"));
            let target = requests[0].split_whitespace().nth(1).expect("target");
            let (_, query) = target.split_once('?').expect("upload query");
            assert!(
                query
                    .split('&')
                    .any(|pair| pair == "uploadId=fixture-upload")
            );
        }
    }
}

#[tokio::test]
async fn valid_multipart_completion_publishes_without_aborting() {
    let provider = ScriptedProvider::new(vec![
        "<CompleteMultipartUploadResult><ETag>fixture-etag</ETag></CompleteMultipartUploadResult>"
            .to_owned(),
        String::new(),
    ])
    .await;
    let metadata = upload_with_parts(
        &provider.store,
        vec![Some(
            aws_sdk_s3::types::CompletedPart::builder()
                .part_number(1)
                .e_tag("fixture-part")
                .build(),
        )],
    )
    .complete()
    .await
    .expect("valid completion");
    assert_eq!(metadata.content_len, 1);
    assert_eq!(metadata.etag.as_deref(), Some("fixture-etag"));
    let requests = provider.requests.lock().expect("requests");
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0],
        "POST /bucket/objects/multipart?uploadId=fixture-upload HTTP/1.1",
    );
    assert_eq!(requests[1], "HEAD /bucket/objects/multipart HTTP/1.1");
}

#[tokio::test]
async fn exact_version_reads_reject_missing_and_mismatched_response_versions() {
    let object = rs3_types::BackendObjectId::new("objects/exact").expect("object");
    let version = rs3_types::BackendVersionId::new("accepted-version").expect("version");
    for (headers, accepted) in [
        ("", false),
        ("x-amz-version-id: wrong-version\r\n", false),
        ("x-amz-version-id: accepted-version\r\n", true),
    ] {
        let provider =
            ScriptedProvider::with_headers(200, vec!["abc".to_owned(); 2], headers).await;
        let buffered = provider
            .store
            .get_range_at(&object, Some(&version), ByteRange::Full)
            .await;
        assert_eq!(buffered.is_ok(), accepted);
        let streamed = provider
            .store
            .open_bounded_full_at(&object, Some(&version), 3)
            .await;
        assert_eq!(streamed.is_ok(), accepted);
        if accepted {
            assert_eq!(
                buffered.expect("exact buffered read"),
                Bytes::from_static(b"abc")
            );
            assert_eq!(
                crate::collect_bounded_blob_read(streamed.expect("exact stream"), 3)
                    .await
                    .expect("complete stream"),
                Bytes::from_static(b"abc")
            );
        }
        let requests = provider.requests.lock().expect("requests");
        assert_eq!(requests.len(), 2);
        assert!(
            requests
                .iter()
                .all(|request| request.contains("versionId=accepted-version"))
        );
    }
}
