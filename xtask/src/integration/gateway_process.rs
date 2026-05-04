//! Local gateway process management for integration commands.

use super::s3_container::{self, RunningS3Container};
use anyhow::{Context, Result};
use aws_sdk_s3::Client;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpListener};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

pub(crate) const PUBLIC_BUCKET: &str = "client-bucket";
pub(crate) const ACCESS_KEY_ID: &str = "access";
pub(crate) const SECRET_ACCESS_KEY: &str = "secret";
pub(crate) const REPOSITORY_MASTER_KEY_HEX: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub(crate) enum GatewayBuildProfile {
    Dev,
    Release,
}

impl GatewayBuildProfile {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Release => "release",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GatewayProcessOptions {
    pub(crate) build_profile: GatewayBuildProfile,
    pub(crate) payload_segment_size: Option<usize>,
}

impl Default for GatewayProcessOptions {
    fn default() -> Self {
        Self {
            build_profile: GatewayBuildProfile::Dev,
            payload_segment_size: None,
        }
    }
}

pub(crate) struct RunningGateway {
    addr: SocketAddr,
    metrics_addr: Option<SocketAddr>,
    child: Child,
    logs: Option<Arc<Mutex<Vec<String>>>>,
    readers: Vec<JoinHandle<()>>,
}

impl RunningGateway {
    pub(crate) async fn start(
        backend: &RunningS3Container,
        backend_prefix: String,
    ) -> Result<Self> {
        Self::start_inner(
            backend,
            backend_prefix,
            None,
            GatewayProcessOptions::default(),
        )
        .await
    }

    pub(crate) async fn start_with_log_capture_options(
        backend: &RunningS3Container,
        backend_prefix: String,
        rust_log: &str,
        options: GatewayProcessOptions,
    ) -> Result<Self> {
        Self::start_inner(backend, backend_prefix, Some(rust_log), options).await
    }

    async fn start_inner(
        backend: &RunningS3Container,
        backend_prefix: String,
        rust_log: Option<&str>,
        options: GatewayProcessOptions,
    ) -> Result<Self> {
        let addr = reserve_gateway_addr()?;
        let capture_logs = rust_log.is_some();
        let metrics_addr = capture_logs.then(reserve_gateway_addr).transpose()?;
        let bind = addr.to_string();
        let metrics_bind = metrics_addr.map(|addr| addr.to_string());
        let startup_timeout = match options.build_profile {
            GatewayBuildProfile::Dev => Duration::from_secs(30),
            GatewayBuildProfile::Release => Duration::from_secs(600),
        };
        let mut gateway_args = vec!["run"];
        if options.build_profile == GatewayBuildProfile::Release {
            gateway_args.push("--release");
        }
        gateway_args.extend([
            "-p",
            "rs3-server",
            "--bin",
            "rs3-server",
            "--features",
            "s3",
            "--",
        ]);
        if capture_logs {
            gateway_args.extend(["--log-format", "json"]);
        }
        gateway_args.extend(["serve", "--bind", bind.as_str()]);
        if let Some(metrics_bind) = metrics_bind.as_deref() {
            gateway_args.extend(["--metrics-bind", metrics_bind]);
        }

        let mut child = Command::new("cargo");
        child
            .args(gateway_args)
            .env("RS3_PUBLIC_BUCKET", PUBLIC_BUCKET)
            .env("RS3_BACKEND_ENDPOINT", &backend.endpoint_url)
            .env("RS3_BACKEND_BUCKET", &backend.bucket)
            .env("RS3_BACKEND_PREFIX", backend_prefix)
            .env("RS3_ANCHOR_MODE", "memory")
            .env("RS3_ALLOW_MEMORY_ANCHOR", "true")
            .env("RS3_REPOSITORY_MASTER_KEY_HEX", REPOSITORY_MASTER_KEY_HEX)
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
            .stdout(if capture_logs {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stderr(if capture_logs {
                Stdio::piped()
            } else {
                Stdio::null()
            });
        if let Some(rust_log) = rust_log {
            child.env("RUST_LOG", rust_log);
        }
        if let Some(payload_segment_size) = options.payload_segment_size {
            child.env(
                "RS3_PAYLOAD_SEGMENT_SIZE_BYTES",
                payload_segment_size.to_string(),
            );
        }

        let mut child = child
            .spawn()
            .context("failed to start rs3-server process")?;
        let logs = if capture_logs {
            let stdout = child
                .stdout
                .take()
                .context("gateway stdout was not captured")?;
            let stderr = child
                .stderr
                .take()
                .context("gateway stderr was not captured")?;
            let logs = Arc::new(Mutex::new(Vec::new()));
            let readers = vec![
                spawn_gateway_log_reader(stdout, Arc::clone(&logs)),
                spawn_gateway_log_reader(stderr, Arc::clone(&logs)),
            ];
            let mut gateway = Self {
                addr,
                metrics_addr,
                child,
                logs: Some(logs),
                readers,
            };
            if let Err(error) = wait_for_gateway(addr, &mut gateway.child, startup_timeout).await {
                let _ = gateway.shutdown();
                return Err(error);
            }
            gateway.clear_captured_logs()?;
            return Ok(gateway);
        } else {
            wait_for_gateway(addr, &mut child, startup_timeout).await?;
            None
        };

        Ok(Self {
            addr,
            metrics_addr,
            child,
            logs,
            readers: Vec::new(),
        })
    }

    pub(crate) fn endpoint_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub(crate) fn endpoint_authority(&self) -> String {
        self.addr.to_string()
    }

    pub(crate) fn metrics_endpoint_authority(&self) -> Option<String> {
        self.metrics_addr.map(|addr| addr.to_string())
    }

    pub(crate) fn client(&self, backend: &RunningS3Container) -> Client {
        s3_container::s3_client(
            &self.endpoint_url(),
            &backend.region,
            ACCESS_KEY_ID,
            SECRET_ACCESS_KEY,
        )
    }

    pub(crate) fn clear_captured_logs(&self) -> Result<()> {
        let Some(logs) = &self.logs else {
            return Ok(());
        };
        let mut logs = logs
            .lock()
            .map_err(|_| anyhow::anyhow!("gateway log capture lock poisoned"))?;
        logs.clear();
        Ok(())
    }

    pub(crate) fn captured_logs(&self) -> Result<Vec<String>> {
        let Some(logs) = &self.logs else {
            return Ok(Vec::new());
        };
        let logs = logs
            .lock()
            .map_err(|_| anyhow::anyhow!("gateway log capture lock poisoned"))?;
        Ok(logs.clone())
    }

    pub(crate) fn process_metrics_json(&self) -> Value {
        let pid = self.child.id();
        let process = i32::try_from(pid)
            .ok()
            .and_then(|pid| procfs::process::Process::new(pid).ok());
        let status = process.as_ref().and_then(|process| process.status().ok());
        let stat = process.as_ref().and_then(|process| process.stat().ok());
        let ticks_per_second = procfs::ticks_per_second();
        let cpu_user_seconds = stat
            .as_ref()
            .and_then(|stat| ticks_to_seconds(stat.utime, ticks_per_second));
        let cpu_system_seconds = stat
            .as_ref()
            .and_then(|stat| ticks_to_seconds(stat.stime, ticks_per_second));
        let cpu_total_seconds = cpu_user_seconds
            .zip(cpu_system_seconds)
            .map(|(user, system)| user + system);
        json!({
            "pid": pid,
            "cpu_system_seconds": cpu_system_seconds,
            "cpu_total_seconds": cpu_total_seconds,
            "cpu_user_seconds": cpu_user_seconds,
            "vm_hwm_bytes": status.as_ref().and_then(|status| kib_to_bytes(status.vmhwm)),
            "vm_rss_bytes": status.as_ref().and_then(|status| kib_to_bytes(status.vmrss)),
        })
    }

    pub(crate) fn shutdown(&mut self) -> Result<()> {
        if self
            .child
            .try_wait()
            .context("failed to inspect gateway process")?
            .is_none()
        {
            self.child
                .kill()
                .context("failed to stop gateway process")?;
        }
        let _status = self
            .child
            .wait()
            .context("failed to reap gateway process")?;
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
        Ok(())
    }
}

fn kib_to_bytes(kib: Option<u64>) -> Option<u64> {
    kib?.checked_mul(1024)
}

fn ticks_to_seconds(ticks: u64, ticks_per_second: u64) -> Option<f64> {
    if ticks_per_second == 0 {
        return None;
    }
    Some(ticks as f64 / ticks_per_second as f64)
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

async fn wait_for_gateway(
    addr: SocketAddr,
    child: &mut Child,
    startup_timeout: Duration,
) -> Result<()> {
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
        if started.elapsed() >= startup_timeout {
            anyhow::bail!("gateway did not start accepting connections at {addr}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn spawn_gateway_log_reader<R>(reader: R, logs: Arc<Mutex<Vec<String>>>) -> JoinHandle<()>
where
    R: std::io::Read + Send + 'static,
{
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            let Ok(line) = line else {
                break;
            };
            if let Ok(mut captured) = logs.lock() {
                captured.push(line);
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{kib_to_bytes, ticks_to_seconds};

    #[test]
    fn converts_procfs_kib_fields_to_bytes() {
        assert_eq!(kib_to_bytes(Some(1234)), Some(1_263_616));
        assert_eq!(kib_to_bytes(None), None);
    }

    #[test]
    fn converts_procfs_cpu_ticks_to_seconds() {
        assert_eq!(ticks_to_seconds(125, 100), Some(1.25));
        assert_eq!(ticks_to_seconds(125, 0), None);
    }
}
