//! Local gateway process management for integration commands.

use super::s3_container::{self, RunningS3Container};
use anyhow::{Context, Result};
use aws_sdk_s3::Client;
use std::net::{SocketAddr, TcpListener};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

pub(crate) const PUBLIC_BUCKET: &str = "client-bucket";
pub(crate) const ACCESS_KEY_ID: &str = "access";
pub(crate) const SECRET_ACCESS_KEY: &str = "secret";

pub(crate) struct RunningGateway {
    addr: SocketAddr,
    child: Child,
}

impl RunningGateway {
    pub(crate) async fn start(
        backend: &RunningS3Container,
        backend_prefix: String,
    ) -> Result<Self> {
        let addr = reserve_gateway_addr()?;
        let mut child = Command::new("cargo");
        child
            .args([
                "run",
                "-p",
                "rs3-server",
                "--bin",
                "rs3-server",
                "--features",
                "s3",
                "--",
                "serve",
                "--bind",
                &addr.to_string(),
            ])
            .env("RS3_PUBLIC_BUCKET", PUBLIC_BUCKET)
            .env("RS3_BACKEND_ENDPOINT", &backend.endpoint_url)
            .env("RS3_BACKEND_BUCKET", &backend.bucket)
            .env("RS3_BACKEND_PREFIX", backend_prefix)
            .env("RS3_STATIC_ACCESS_KEY_ID", ACCESS_KEY_ID)
            .env("RS3_STATIC_SECRET_ACCESS_KEY", SECRET_ACCESS_KEY)
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

    pub(crate) fn endpoint_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub(crate) fn endpoint_authority(&self) -> String {
        self.addr.to_string()
    }

    pub(crate) fn client(&self, backend: &RunningS3Container) -> Client {
        s3_container::s3_client(
            &self.endpoint_url(),
            &backend.region,
            ACCESS_KEY_ID,
            SECRET_ACCESS_KEY,
        )
    }

    pub(crate) fn shutdown(&mut self) -> Result<()> {
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

impl Drop for RunningGateway {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn reserve_gateway_addr() -> Result<SocketAddr> {
    let listener =
        TcpListener::bind("127.0.0.1:0").context("failed to reserve gateway listen port")?;
    let addr = listener
        .local_addr()
        .context("failed to read reserved gateway listen port")?;
    drop(listener);
    Ok(addr)
}

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
