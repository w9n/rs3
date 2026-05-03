//! Gateway-level S3 integration command.

use super::S3ContainerProvider;
#[cfg(feature = "containers")]
use super::s3_container::{self, RunningS3Container};
#[cfg(feature = "containers")]
use anyhow::Context;
use anyhow::Result;
#[cfg(feature = "containers")]
use aws_sdk_s3::{Client, primitives::ByteStream};
use clap::Args;
#[cfg(feature = "containers")]
use std::net::{SocketAddr, TcpListener};
#[cfg(feature = "containers")]
use std::process::{Child, Command, Stdio};
#[cfg(feature = "containers")]
use std::time::{Duration, Instant};
#[cfg(feature = "containers")]
use tokio::net::TcpStream;

#[cfg(feature = "containers")]
const GATEWAY_PUBLIC_BUCKET: &str = "client-bucket";
#[cfg(feature = "containers")]
const GATEWAY_ACCESS_KEY_ID: &str = "access";
#[cfg(feature = "containers")]
const GATEWAY_SECRET_ACCESS_KEY: &str = "secret";
#[cfg(feature = "containers")]
const GATEWAY_TEST_KEY: &str = "snapshots/gateway-object.bin";
#[cfg(feature = "containers")]
const GATEWAY_TEST_BODY: &[u8] = b"hello gateway backend";

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
        let client = gateway_client(&gateway, &backend);
        let result = assert_gateway_contract(&client).await;
        let shutdown = gateway.shutdown();

        result?;
        shutdown?;
        Ok(())
    })
}

#[cfg(feature = "containers")]
struct RunningGateway {
    addr: SocketAddr,
    child: Child,
}

#[cfg(feature = "containers")]
impl RunningGateway {
    async fn start(backend: &RunningS3Container, backend_prefix: String) -> Result<Self> {
        let addr = reserve_gateway_addr()?;
        let mut child = Command::new("cargo");
        child
            .args([
                "run",
                "-p",
                "rs3-server",
                "--features",
                "s3",
                "--",
                "serve",
                "--bind",
                &addr.to_string(),
            ])
            .env("RS3_PUBLIC_BUCKET", GATEWAY_PUBLIC_BUCKET)
            .env("RS3_BACKEND_ENDPOINT", &backend.endpoint_url)
            .env("RS3_BACKEND_BUCKET", &backend.bucket)
            .env("RS3_BACKEND_PREFIX", backend_prefix)
            .env("RS3_STATIC_ACCESS_KEY_ID", GATEWAY_ACCESS_KEY_ID)
            .env("RS3_STATIC_SECRET_ACCESS_KEY", GATEWAY_SECRET_ACCESS_KEY)
            .env("AWS_ACCESS_KEY_ID", &backend.access_key_id)
            .env("AWS_SECRET_ACCESS_KEY", &backend.secret_access_key)
            .env("AWS_DEFAULT_REGION", &backend.region)
            .env_remove("AWS_SESSION_TOKEN")
            .env_remove("AWS_PROFILE")
            .env_remove("AWS_WEB_IDENTITY_TOKEN_FILE")
            .env_remove("AWS_ROLE_ARN")
            .env_remove("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
            .env_remove("AWS_CONTAINER_CREDENTIALS_FULL_URI")
            .env_remove("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let mut child = child
            .spawn()
            .context("failed to start rs3-server process")?;
        wait_for_gateway(addr, &mut child).await?;

        Ok(Self { addr, child })
    }

    fn shutdown(&mut self) -> Result<()> {
        if self
            .child
            .try_wait()
            .context("failed to inspect gateway process")?
            .is_some()
        {
            return Ok(());
        }
        self.child
            .kill()
            .context("failed to stop gateway process")?;
        let _status = self
            .child
            .wait()
            .context("failed to reap gateway process")?;
        Ok(())
    }
}

#[cfg(feature = "containers")]
impl Drop for RunningGateway {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[cfg(feature = "containers")]
fn gateway_client(gateway: &RunningGateway, backend: &RunningS3Container) -> Client {
    s3_container::s3_client(
        &format!("http://{}", gateway.addr),
        &backend.region,
        GATEWAY_ACCESS_KEY_ID,
        GATEWAY_SECRET_ACCESS_KEY,
    )
}

#[cfg(feature = "containers")]
fn reserve_gateway_addr() -> Result<SocketAddr> {
    let listener =
        TcpListener::bind("127.0.0.1:0").context("failed to reserve gateway listen port")?;
    let addr = listener
        .local_addr()
        .context("failed to read reserved gateway listen port")?;
    drop(listener);
    Ok(addr)
}

#[cfg(feature = "containers")]
async fn wait_for_gateway(addr: SocketAddr, child: &mut Child) -> Result<()> {
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .context("failed to inspect gateway process")?
        {
            anyhow::bail!("gateway process exited before accepting connections: {status}");
        }

        if TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        if started.elapsed() >= Duration::from_secs(30) {
            anyhow::bail!("gateway did not start accepting connections at {addr}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(feature = "containers")]
async fn assert_gateway_contract(client: &Client) -> Result<()> {
    client
        .put_object()
        .bucket(GATEWAY_PUBLIC_BUCKET)
        .key(GATEWAY_TEST_KEY)
        .body(ByteStream::from_static(GATEWAY_TEST_BODY))
        .send()
        .await
        .context("gateway PutObject failed")?;

    let head = client
        .head_object()
        .bucket(GATEWAY_PUBLIC_BUCKET)
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
        .bucket(GATEWAY_PUBLIC_BUCKET)
        .key(GATEWAY_TEST_KEY)
        .send()
        .await
        .context("gateway GetObject failed")?;
    assert_body(full.body, GATEWAY_TEST_BODY).await?;

    let range = client
        .get_object()
        .bucket(GATEWAY_PUBLIC_BUCKET)
        .key(GATEWAY_TEST_KEY)
        .range("bytes=6-12")
        .send()
        .await
        .context("gateway ranged GetObject failed")?;
    assert_body(range.body, b"gateway").await?;

    let listed = client
        .list_objects_v2()
        .bucket(GATEWAY_PUBLIC_BUCKET)
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

    client
        .delete_object()
        .bucket(GATEWAY_PUBLIC_BUCKET)
        .key(GATEWAY_TEST_KEY)
        .send()
        .await
        .context("gateway DeleteObject failed")?;

    let listed_after_delete = client
        .list_objects_v2()
        .bucket(GATEWAY_PUBLIC_BUCKET)
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
