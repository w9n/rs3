//! Local helper processes used by Kopia measurements.

use super::logs::storage_proxy_metrics_json;
use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpListener};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

pub(crate) struct RunningStorageProxy {
    addr: SocketAddr,
    child: Child,
    logs: Arc<Mutex<Vec<String>>>,
    readers: Vec<JoinHandle<()>>,
}

impl RunningStorageProxy {
    pub(crate) async fn start(target: &str) -> Result<Self> {
        let addr = reserve_proxy_addr()?;
        let bind = addr.to_string();
        let mut child = Command::new("cargo");
        child
            .args([
                "run",
                "-p",
                "rs3-server",
                "--features",
                "integration-tools",
                "--bin",
                "rs3-integration-storage-proxy",
                "--",
                "--bind",
                bind.as_str(),
                "--target",
                target,
                "--report-interval-secs",
                "1",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = child
            .spawn()
            .context("failed to start integration storage proxy")?;
        let stdout = child
            .stdout
            .take()
            .context("storage proxy stdout was not captured")?;
        let stderr = child
            .stderr
            .take()
            .context("storage proxy stderr was not captured")?;
        let logs = Arc::new(Mutex::new(Vec::new()));
        let readers = vec![
            spawn_log_reader(stdout, Arc::clone(&logs)),
            spawn_log_reader(stderr, Arc::clone(&logs)),
        ];
        let mut proxy = Self {
            addr,
            child,
            logs,
            readers,
        };
        if let Err(error) = wait_for_process_port(addr, &mut proxy.child).await {
            let _ = proxy.shutdown();
            return Err(error);
        }
        proxy.clear_logs()?;
        Ok(proxy)
    }

    pub(crate) fn endpoint_authority(&self) -> String {
        self.addr.to_string()
    }

    pub(crate) fn clear_logs(&self) -> Result<()> {
        let mut logs = self
            .logs
            .lock()
            .map_err(|_| anyhow::anyhow!("storage proxy log capture lock poisoned"))?;
        logs.clear();
        Ok(())
    }

    fn captured_logs(&self) -> Result<Vec<String>> {
        let logs = self
            .logs
            .lock()
            .map_err(|_| anyhow::anyhow!("storage proxy log capture lock poisoned"))?;
        Ok(logs.clone())
    }

    pub(crate) fn shutdown(&mut self) -> Result<()> {
        if self
            .child
            .try_wait()
            .context("failed to inspect storage proxy process")?
            .is_none()
        {
            self.child
                .kill()
                .context("failed to stop storage proxy process")?;
        }
        let _status = self
            .child
            .wait()
            .context("failed to reap storage proxy process")?;
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
        Ok(())
    }
}

impl Drop for RunningStorageProxy {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

pub(crate) fn wait_for_storage_proxy_metrics(proxy: &RunningStorageProxy) -> Result<Value> {
    let started = Instant::now();
    loop {
        let logs = proxy.captured_logs()?;
        if let Some(metrics) = storage_proxy_metrics_json(&logs) {
            return Ok(metrics);
        }
        if started.elapsed() >= Duration::from_secs(3) {
            bail!("storage proxy did not emit metrics");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn reserve_proxy_addr() -> Result<SocketAddr> {
    let listener =
        TcpListener::bind("127.0.0.1:0").context("failed to reserve storage proxy listen port")?;
    let addr = listener
        .local_addr()
        .context("failed to read storage proxy listen port")?;
    drop(listener);
    Ok(addr)
}

async fn wait_for_process_port(addr: SocketAddr, child: &mut Child) -> Result<()> {
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .context("failed to inspect integration process")?
        {
            bail!("integration process exited before accepting connections: {status}");
        }
        if TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        if started.elapsed() >= Duration::from_secs(30) {
            bail!("integration process did not start accepting connections at {addr}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn spawn_log_reader<R>(reader: R, logs: Arc<Mutex<Vec<String>>>) -> JoinHandle<()>
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
