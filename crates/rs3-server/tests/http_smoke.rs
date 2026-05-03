//! HTTP-level smoke tests for the S3 listener.

use rs3_server::{
    AnchorConfig, BackendConfig, BatchConfig, GatewayServer, GatewayServerError, MetricsConfig,
    RepositoryConfig, RepositoryKeysConfig, RuntimeConfig, SecretString, StaticCredentials,
};
use rs3_types::PublicBucket;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

struct TestServer {
    addr: SocketAddr,
    shutdown: oneshot::Sender<()>,
    handle: JoinHandle<Result<(), GatewayServerError>>,
}

impl TestServer {
    async fn start() -> Self {
        let server = match GatewayServer::bind(runtime_config()).await {
            Ok(server) => server,
            Err(error) => panic!("{error}"),
        };
        let addr = server.local_addr();
        let (shutdown, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            server
                .run_until_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        Self {
            addr,
            shutdown,
            handle,
        }
    }

    async fn request(&self, request: &str) -> String {
        let mut stream = match TcpStream::connect(self.addr).await {
            Ok(stream) => stream,
            Err(error) => panic!("{error}"),
        };
        if let Err(error) = stream.write_all(request.as_bytes()).await {
            panic!("{error}");
        }

        let mut response = Vec::new();
        let read =
            tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response)).await;
        match read {
            Ok(Ok(_)) => String::from_utf8_lossy(&response).into_owned(),
            Ok(Err(error)) => panic!("{error}"),
            Err(_) => panic!("timed out waiting for HTTP response"),
        }
    }

    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        match self.handle.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => panic!("{error}"),
            Err(error) => panic!("{error}"),
        }
    }
}

#[tokio::test]
async fn unsigned_bucket_request_is_rejected_by_listener() {
    let server = TestServer::start().await;

    let response = server
        .request(
            "GET /client-bucket?list-type=2 HTTP/1.1\r\n\
             Host: localhost\r\n\
             Connection: close\r\n\
             \r\n",
        )
        .await;

    assert!(
        response.starts_with("HTTP/1.1 403"),
        "unexpected response: {response}"
    );
    assert!(
        response.contains("AccessDenied") || response.contains("Signature"),
        "unexpected response: {response}"
    );

    server.shutdown().await;
}

fn runtime_config() -> RuntimeConfig {
    let bind = match "127.0.0.1:0".parse() {
        Ok(bind) => bind,
        Err(error) => panic!("{error}"),
    };
    let public_bucket = match PublicBucket::new("client-bucket") {
        Ok(bucket) => bucket,
        Err(error) => panic!("{error}"),
    };

    RuntimeConfig {
        bind,
        metrics: MetricsConfig { bind: None },
        public_bucket,
        backend: BackendConfig {
            endpoint: "memory://local".to_owned(),
            bucket: "backend-bucket".to_owned(),
            prefix: Some("repo".to_owned()),
        },
        anchor: AnchorConfig::Memory,
        batching: BatchConfig {
            max_items: 64,
            max_delay: Duration::from_millis(10),
            max_pending_items: 64,
        },
        repository: RepositoryConfig {
            payload_segment_size: rs3_repository::DEFAULT_PAYLOAD_SEGMENT_SIZE,
        },
        repository_keys: RepositoryKeysConfig {
            master_key_hex: SecretString::from(
                "1111111111111111111111111111111111111111111111111111111111111111",
            ),
        },
        static_credentials: Some(StaticCredentials {
            access_key_id: "access".to_owned(),
            secret_access_key: SecretString::from("secret"),
        }),
    }
}
