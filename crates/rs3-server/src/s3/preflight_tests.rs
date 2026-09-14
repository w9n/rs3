//! Exercise the real SDK at the runtime bootstrap boundary.

use super::RuntimeRepository;
use crate::s3::runtime_builders::build_store;
use crate::s3::test_support::runtime_config;
use crate::{GatewayMode, RuntimeConfig};
use rs3_types::{RetentionMode, RetentionPolicy};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct Provider {
    endpoint: String,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Provider {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Provider {
    async fn new(responses: Vec<(u16, &'static str)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let endpoint = format!("http://{}", listener.local_addr().expect("address"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            let mut responses = responses.into_iter();
            loop {
                let (mut stream, _) = listener.accept().await.expect("request");
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    assert!(header.len() < 16 * 1024, "bounded request headers");
                    header.push(stream.read_u8().await.expect("header byte"));
                }
                let header = String::from_utf8(header).expect("request header");
                recorded
                    .lock()
                    .expect("requests")
                    .push(header.lines().next().expect("request line").to_owned());
                // Any unexpected bootstrap operation gets a terminal SDK error.
                let (status, body) = responses.next().unwrap_or((403, DENIED));
                let response = format!(
                    "HTTP/1.1 {status} Response\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("response");
                stream.shutdown().await.expect("close");
            }
        });
        Self {
            endpoint,
            requests,
            task,
        }
    }

    fn config(&self) -> RuntimeConfig {
        let mut config = runtime_config(true);
        config.backend.endpoint.clone_from(&self.endpoint);
        config.backend.bucket = "preflight-fixture".to_owned();
        config.backend.timeouts.operation = Duration::from_secs(3);
        config.backend.timeouts.operation_attempt = Duration::from_secs(2);
        config.repository.retention = Some(RetentionPolicy::new(RetentionMode::Compliance, 30));
        config
    }
}

const ENABLED: &str = "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>";
const DISABLED: &str =
    "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>";
const LOCK_ENABLED: &str = "<ObjectLockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>";
const EXPIRY: &str = "<LifecycleConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Rule><Status>Enabled</Status><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>";
const NO_LIFECYCLE: &str = "<Error><Code>NoSuchLifecycleConfiguration</Code></Error>";
const NO_LOCK: &str =
    "<ObjectLockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>";
const DENIED: &str = "<Error><Code>AccessDenied</Code><Message>private-provider-sentinel</Message><Resource>private-provider-sentinel</Resource></Error>";

#[tokio::test]
async fn retained_bootstrap_checks_policy_before_repository_io() {
    // Environment credential discovery is part of the real runtime path. Keep
    // fixture credentials in a child process, avoiding mutation of test peers.
    const CHILD: &str = "RS3_TEST_PREFLIGHT_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", "s3::runtime::preflight_tests::retained_bootstrap_checks_policy_before_repository_io", "--nocapture"])
            .env(CHILD, "1")
            .env("AWS_ACCESS_KEY_ID", "fixture")
            .env("AWS_SECRET_ACCESS_KEY", "fixture")
            .env("AWS_REGION", "us-east-1")
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .env_remove("AWS_PROFILE")
            .env_remove("AWS_SESSION_TOKEN")
            .output().expect("isolated credential fixture");
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "child test actually executed"
        );
        return;
    }
    for (responses, expected) in [
        (vec![(200, DISABLED)], vec!["?versioning"]),
        (
            vec![(200, ENABLED), (200, NO_LOCK)],
            vec!["?versioning", "?object-lock"],
        ),
        (vec![(403, DENIED)], vec!["?versioning"]),
        (
            vec![(200, ENABLED), (403, DENIED)],
            vec!["?versioning", "?object-lock"],
        ),
        (
            vec![(200, ENABLED), (200, LOCK_ENABLED), (200, EXPIRY)],
            vec!["?versioning", "?object-lock", "?lifecycle"],
        ),
        (
            vec![(200, ENABLED), (200, LOCK_ENABLED), (403, DENIED)],
            vec!["?versioning", "?object-lock", "?lifecycle"],
        ),
    ] {
        for init in [false, true] {
            let provider = Provider::new(responses.clone()).await;
            let result = if init {
                super::V3PreparedRepositoryInit::prepare(&provider.config())
                    .await
                    .map(|_| ())
            } else {
                RuntimeRepository::from_config(&provider.config())
                    .await
                    .map(|_| ())
            };
            let error = match result {
                Ok(_) => panic!("invalid storage must fail preflight"),
                Err(error) => error,
            };
            assert!(!error.to_string().contains("private-provider-sentinel"));
            let requests = provider.requests.lock().expect("requests");
            assert_eq!(
                requests.len(),
                expected.len(),
                "no repository IO before failed preflight"
            );
            for (request, query) in requests.iter().zip(&expected) {
                assert!(
                    request.starts_with("GET ") && request.contains(query),
                    "only bucket policy reads are allowed"
                );
            }
        }
    }
    let provider = Provider::new(vec![
        (200, ENABLED),
        (200, LOCK_ENABLED),
        (404, NO_LIFECYCLE),
    ])
    .await;
    let config = provider.config();
    build_store(&config.backend)
        .await
        .expect("store")
        .validate_write_policy(config.mode, config.repository.retention)
        .await
        .expect("explicit absence of lifecycle policy is allowed");
    assert_eq!(provider.requests.lock().expect("requests").len(), 3);
    let provider = Provider::new(Vec::new()).await;
    let mut config = provider.config();
    config.mode = GatewayMode::RestoreReadOnly;
    let store = build_store(&config.backend).await.expect("readonly store");
    store
        .validate_write_policy(config.mode, config.repository.retention)
        .await
        .expect("restore does not need bucket administration");
    assert!(provider.requests.lock().expect("requests").is_empty());
}
