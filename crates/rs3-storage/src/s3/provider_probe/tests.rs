use super::*;
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct Provider {
    store: S3BlobStore,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Provider {
    async fn new(responses: Vec<String>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let endpoint = format!("http://{}", listener.local_addr().expect("address"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let received = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            for response in responses {
                let (mut stream, _) = listener.accept().await.expect("request");
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    assert!(header.len() < 16 * 1024);
                    header.push(stream.read_u8().await.expect("header"));
                }
                let header = String::from_utf8(header).expect("header UTF-8");
                assert!(
                    header.contains("Credential=fixture/"),
                    "must reuse configured credentials"
                );
                assert!(
                    !header
                        .to_ascii_lowercase()
                        .contains("x-amz-bypass-governance-retention"),
                    "never bypass protection"
                );
                let length = header
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().expect("length"))
                    })
                    .unwrap_or(0);
                assert!(length <= 16 * 1024, "fixture body budget");
                let mut body = vec![0; length];
                stream.read_exact(&mut body).await.expect("body");
                received
                    .lock()
                    .expect("requests")
                    .push(header.lines().next().expect("request line").to_owned());
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("response");
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
                    .operation_timeout(Duration::from_secs(3))
                    .build(),
            )
            .build();
        let config = S3BlobStoreConfig::new("bucket")
            .expect("config")
            .with_prefix(Some("repository".to_owned()))
            .with_endpoint_url(Some(endpoint))
            .with_allow_http(true);
        Self {
            store: S3BlobStore::from_client(SdkS3Client::from_conf(sdk), config),
            requests,
            task,
        }
    }
    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("requests").clone()
    }
}

fn response(status: &str, headers: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/xml\r\nConnection: close\r\n{headers}\r\n{body}",
        body.len()
    )
}
fn head(hold: bool) -> String {
    let protection = if hold {
        "x-amz-object-lock-legal-hold: ON\r\n"
    } else {
        "x-amz-object-lock-mode: COMPLIANCE\r\nx-amz-object-lock-retain-until-date: 2099-01-01T00:00:00Z\r\n"
    };
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nx-amz-version-id: v1\r\n{protection}Connection: close\r\n\r\n"
    )
}
fn unavailable() -> String {
    response(
        "503 Service Unavailable",
        "",
        "<Error><Code>ServiceUnavailable</Code></Error>",
    )
}

#[tokio::test]
async fn probe_scope_is_disjoint_and_cannot_be_redirected_or_nested() {
    let provider = Provider::new(vec![]).await;
    for prefix in [
        "",
        "/",
        "repository",
        "repository/child",
        "/repository//child/",
        "../other",
        "other/%2e%2e/repository",
    ] {
        assert!(
            provider
                .store
                .for_provider_probe(prefix.to_owned())
                .is_err(),
            "invalid scope"
        );
    }
    let nested_config = provider
        .store
        .config
        .clone()
        .with_prefix(Some("repository/child".to_owned()));
    let nested = S3BlobStore::from_client(provider.store.client.clone(), nested_config);
    assert!(nested.for_provider_probe("repository".to_owned()).is_err());
    let root = S3BlobStore::from_client(
        provider.store.client.clone(),
        provider.store.config.clone().with_prefix(None),
    );
    assert!(root.for_provider_probe("probe".to_owned()).is_err());
    let probe = provider
        .store
        .for_provider_probe("repository-other/probe".to_owned())
        .expect("disjoint boundary");
    assert!(probe.supports_provider_delete_probe());
    assert!(!provider.store.supports_provider_delete_probe());
    assert!(probe.for_provider_probe("another".to_owned()).is_err());
    let id = BackendObjectId::new("../repository/value").expect("opaque id");
    let version = BackendVersionId::new("v1").expect("version");
    assert!(probe.delete_at(&id, Some(&version)).await.is_err());
    assert!(provider.requests().is_empty());
}

#[tokio::test]
async fn isolated_probe_observes_provider_delete_instead_of_local_refusal() {
    for hold in [false, true] {
        for denied in [false, true] {
            let provider = Provider::new(vec![
                head(hold),
                head(hold),
                if denied {
                    response(
                        "403 Forbidden",
                        "",
                        "<Error><Code>AccessDenied</Code></Error>",
                    )
                } else {
                    response("204 No Content", "", "")
                },
            ])
            .await;
            let id = BackendObjectId::new("checks/protected").expect("id");
            let version = BackendVersionId::new("v1").expect("version");
            assert!(matches!(
                provider.store.delete_at(&id, Some(&version)).await,
                Err(StorageError::RetentionBlocked | StorageError::LegalHoldBlocked)
            ));
            assert_eq!(
                provider.requests().len(),
                1,
                "ordinary handle refuses locally"
            );
            let probe = provider
                .store
                .for_provider_probe("probes/opaque".to_owned())
                .expect("probe scope");
            let result = probe.delete_at(&id, Some(&version)).await;
            if denied {
                assert!(matches!(
                    result,
                    Err(StorageError::RetentionBlocked | StorageError::LegalHoldBlocked)
                ));
            } else {
                assert!(
                    result.is_ok(),
                    "provider ignoring protection must be exposed to the checker"
                );
            }
            let requests = provider.requests();
            assert_eq!(requests.len(), 3);
            assert!(requests[0].starts_with("HEAD /bucket/repository/"));
            assert!(requests[1].starts_with("HEAD /bucket/probes/opaque/"));
            assert!(requests[2].starts_with("DELETE /bucket/probes/opaque/checks/protected?"));
            assert!(requests[2].contains("versionId=v1"));
        }
    }
}

#[tokio::test]
async fn denied_signatures_and_transport_failures_do_not_prove_protection() {
    for denied in [
        response(
            "403 Forbidden",
            "",
            "<Error><Code>SignatureDoesNotMatch</Code></Error>",
        ),
        unavailable(),
    ] {
        let provider = Provider::new(vec![head(false), denied]).await;
        let probe = provider
            .store
            .for_provider_probe("probes/opaque".to_owned())
            .expect("scope");
        let result = probe
            .delete_at(
                &BackendObjectId::new("checks/protected").expect("id"),
                Some(&BackendVersionId::new("v1").expect("version")),
            )
            .await;
        assert!(matches!(result, Err(StorageError::Provider(_))));
        assert_eq!(
            provider.requests().len(),
            2,
            "one HEAD and one DELETE, no SDK retry"
        );
    }
}

#[tokio::test]
async fn probe_put_and_multipart_requests_each_use_one_sdk_attempt() {
    let provider = Provider::new(vec![unavailable(), unavailable(),
        response("200 OK", "", "<InitiateMultipartUploadResult><Bucket>bucket</Bucket><Key>checks/multipart</Key><UploadId>upload</UploadId></InitiateMultipartUploadResult>"),
        response("200 OK", "ETag: \"part\"\r\n", ""), unavailable(), response("204 No Content", "", ""),
    ]).await;
    let probe = provider
        .store
        .for_provider_probe("probes/opaque".to_owned())
        .expect("scope");
    let id = BackendObjectId::new("checks/multipart").expect("id");
    assert!(
        probe
            .put(&id, Bytes::from_static(b"abc"), PutOptions::default())
            .await
            .is_err()
    );
    assert_eq!(
        provider.requests().len(),
        1,
        "unprotected PUT cannot retry into bucket-default retention"
    );
    assert!(
        probe
            .create_multipart_upload(&id, PutOptions::default())
            .await
            .is_err()
    );
    assert_eq!(
        provider.requests().len(),
        2,
        "MPU creation cannot leave hidden retried upload IDs"
    );
    let mut upload = probe
        .create_multipart_upload(&id, PutOptions::default())
        .await
        .expect("create");
    upload
        .put_part(0, Bytes::from_static(b"abc"))
        .await
        .expect("part");
    assert!(upload.complete().await.is_err());
    let requests = provider.requests();
    assert_eq!(requests.len(), 6, "one completion attempt, then one abort");
    assert!(
        requests
            .iter()
            .all(|request| request.contains("/bucket/probes/opaque/"))
    );
    assert!(requests[4].starts_with("POST "));
    assert!(requests[5].starts_with("DELETE "));
}
