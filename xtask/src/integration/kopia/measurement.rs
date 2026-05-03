//! Measurement helpers for Kopia integration lanes.

use super::KopiaRunStats;
use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpListener};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;

pub(super) struct RunningStorageProxy {
    addr: SocketAddr,
    child: Child,
    logs: Arc<Mutex<Vec<String>>>,
    readers: Vec<JoinHandle<()>>,
}

impl RunningStorageProxy {
    pub(super) async fn start(target: &str) -> Result<Self> {
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

    pub(super) fn endpoint_authority(&self) -> String {
        self.addr.to_string()
    }

    pub(super) fn clear_logs(&self) -> Result<()> {
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

    pub(super) fn shutdown(&mut self) -> Result<()> {
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

pub(super) fn measurement_json(
    storage_path: &'static str,
    stats: KopiaRunStats,
    backend_metrics: Value,
) -> Value {
    serde_json::json!({
        "storage_path": storage_path,
        "elapsed_ms": duration_ms(stats.elapsed),
        "phase_timings": stats.phases.iter().map(|phase| serde_json::json!({
            "name": phase.name,
            "elapsed_ms": duration_ms(phase.elapsed),
        })).collect::<Vec<_>>(),
        "backend_metrics": backend_metrics,
    })
}

pub(super) fn gateway_backend_metrics_json(logs: &[String]) -> Value {
    let counts = parse_gateway_backend_counts(logs);
    serde_json::json!({
        "source": "gateway-storage-logs",
        "counts": {
            "put": counts.put,
            "get": counts.get,
            "head": counts.head,
            "list": counts.list,
            "delete": counts.delete,
            "extend_retention": counts.extend_retention,
            "bytes_written": counts.bytes_written,
            "bytes_read": counts.bytes_read,
        },
        "operation_latency_us": parse_gateway_backend_latency(logs),
    })
}

pub(super) fn gateway_client_metrics_json(logs: &[String]) -> Value {
    let mut counts_by_operation: BTreeMap<String, u64> = BTreeMap::new();
    let mut counts_by_result: BTreeMap<String, u64> = BTreeMap::new();
    let mut counts_by_status: BTreeMap<String, u64> = BTreeMap::new();
    let mut latency_by_operation: BTreeMap<String, Vec<u64>> = BTreeMap::new();

    for line in logs {
        let Some(value) = parse_log_json(line) else {
            continue;
        };
        if value.get("target").and_then(Value::as_str) != Some("rs3_server") {
            continue;
        }
        let fields = value.get("fields").unwrap_or(&value);
        if json_field_str(fields, "message") != Some("S3 request completed") {
            continue;
        }
        let Some(operation) = json_field_str(fields, "operation") else {
            continue;
        };
        bump_count(&mut counts_by_operation, operation);

        if let Some(result) = json_field_str(fields, "result") {
            bump_count(&mut counts_by_result, result);
        }
        if let Some(status) = json_field_u64_opt(fields, "status_code") {
            bump_count(&mut counts_by_status, &status.to_string());
        }
        if let Some(elapsed_us) = json_field_u64_opt(fields, "elapsed_us") {
            latency_by_operation
                .entry(operation.to_owned())
                .or_default()
                .push(elapsed_us);
        }
    }

    serde_json::json!({
        "source": "gateway-s3-request-logs",
        "counts_by_operation": counts_by_operation,
        "counts_by_result": counts_by_result,
        "counts_by_status": counts_by_status,
        "operation_latency_us": latency_by_operation
            .into_iter()
            .map(|(operation, samples)| (operation, summarize_latency_us(&samples)))
            .collect::<BTreeMap<_, _>>(),
    })
}

pub(super) fn wait_for_storage_proxy_metrics(proxy: &RunningStorageProxy) -> Result<Value> {
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

pub(super) fn endpoint_authority(endpoint_url: &str) -> Result<String> {
    let authority = endpoint_url
        .strip_prefix("http://")
        .or_else(|| endpoint_url.strip_prefix("https://"))
        .unwrap_or(endpoint_url);
    if authority.contains('/') {
        bail!("endpoint URL `{endpoint_url}` contains a path; expected only scheme and authority");
    }
    Ok(authority.to_owned())
}

pub(super) fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
}

pub(super) fn aggregate_runs(runs: &[Value]) -> Value {
    let mut by_storage_path = serde_json::Map::new();
    for storage_path in ["direct-rustfs", "gateway"] {
        let reports = reports_for_storage_path(runs, storage_path);
        by_storage_path.insert(storage_path.to_owned(), aggregate_reports(&reports));
    }
    Value::Object(by_storage_path)
}

fn reports_for_storage_path<'a>(runs: &'a [Value], storage_path: &str) -> Vec<&'a Value> {
    runs.iter()
        .filter_map(|run| run.get("reports").and_then(Value::as_array))
        .flat_map(|reports| reports.iter())
        .filter(|report| report.get("storage_path").and_then(Value::as_str) == Some(storage_path))
        .collect()
}

fn aggregate_reports(reports: &[&Value]) -> Value {
    let elapsed = reports
        .iter()
        .filter_map(|report| report.get("elapsed_ms").and_then(Value::as_u64))
        .collect::<Vec<_>>();
    serde_json::json!({
        "runs": reports.len(),
        "elapsed_ms": summarize_u64(&elapsed),
        "phase_timings": aggregate_phase_timings(reports),
        "backend_metrics": {
            "counts": aggregate_object(reports, &["backend_metrics", "counts"]),
            "transport": aggregate_object(reports, &["backend_metrics", "transport"]),
            "operation_latency_us": aggregate_operation_latency_at(reports, &[
                "backend_metrics",
                "operation_latency_us",
            ]),
        },
        "client_metrics": {
            "counts_by_operation": aggregate_object(reports, &[
                "client_metrics",
                "counts_by_operation",
            ]),
            "counts_by_result": aggregate_object(reports, &[
                "client_metrics",
                "counts_by_result",
            ]),
            "counts_by_status": aggregate_object(reports, &[
                "client_metrics",
                "counts_by_status",
            ]),
            "operation_latency_us": aggregate_operation_latency_at(reports, &[
                "client_metrics",
                "operation_latency_us",
            ]),
        },
    })
}

fn aggregate_operation_latency_at(reports: &[&Value], path: &[&str]) -> Value {
    let mut metrics_by_operation: BTreeMap<String, BTreeMap<String, Vec<f64>>> = BTreeMap::new();
    for report in reports {
        let mut current = *report;
        for segment in path {
            let Some(next) = current.get(*segment) else {
                current = &Value::Null;
                break;
            };
            current = next;
        }
        let Some(latency_by_operation) = current.as_object() else {
            continue;
        };
        for (operation, summary) in latency_by_operation {
            let Some(summary) = summary.as_object() else {
                continue;
            };
            for (metric, value) in summary {
                let Some(value) = value.as_f64() else {
                    continue;
                };
                metrics_by_operation
                    .entry(operation.clone())
                    .or_default()
                    .entry(metric.clone())
                    .or_default()
                    .push(value);
            }
        }
    }

    Value::Object(
        metrics_by_operation
            .into_iter()
            .map(|(operation, metrics)| {
                (
                    operation,
                    Value::Object(
                        metrics
                            .into_iter()
                            .map(|(metric, values)| (metric, summarize_f64(&values)))
                            .collect(),
                    ),
                )
            })
            .collect(),
    )
}

fn aggregate_phase_timings(reports: &[&Value]) -> Value {
    let mut timings: std::collections::BTreeMap<String, Vec<u64>> =
        std::collections::BTreeMap::new();
    for report in reports {
        let Some(phases) = report.get("phase_timings").and_then(Value::as_array) else {
            continue;
        };
        for phase in phases {
            let Some(name) = phase.get("name").and_then(Value::as_str) else {
                continue;
            };
            let Some(elapsed_ms) = phase.get("elapsed_ms").and_then(Value::as_u64) else {
                continue;
            };
            timings.entry(name.to_owned()).or_default().push(elapsed_ms);
        }
    }

    Value::Object(
        timings
            .into_iter()
            .map(|(name, values)| (name, summarize_u64(&values)))
            .collect(),
    )
}

fn aggregate_object(reports: &[&Value], path: &[&str]) -> Value {
    let mut values_by_key: std::collections::BTreeMap<String, Vec<u64>> =
        std::collections::BTreeMap::new();
    for report in reports {
        let mut current = *report;
        for segment in path {
            let Some(next) = current.get(*segment) else {
                current = &Value::Null;
                break;
            };
            current = next;
        }
        let Some(object) = current.as_object() else {
            continue;
        };
        for (key, value) in object {
            if let Some(value) = value.as_u64() {
                values_by_key.entry(key.clone()).or_default().push(value);
            }
        }
    }

    Value::Object(
        values_by_key
            .into_iter()
            .map(|(key, values)| (key, summarize_u64(&values)))
            .collect(),
    )
}

fn summarize_u64(values: &[u64]) -> Value {
    if values.is_empty() {
        return serde_json::json!({
            "min": null,
            "max": null,
            "avg": null,
        });
    }

    let min = values.iter().copied().min().unwrap_or(0);
    let max = values.iter().copied().max().unwrap_or(0);
    let sum = values.iter().copied().map(u128::from).sum::<u128>();
    let avg = sum as f64 / values.len() as f64;
    serde_json::json!({
        "min": min,
        "max": max,
        "avg": avg,
    })
}

fn summarize_f64(values: &[f64]) -> Value {
    if values.is_empty() {
        return serde_json::json!({
            "min": null,
            "max": null,
            "avg": null,
        });
    }

    let min = values.iter().copied().fold(f64::INFINITY, f64::min);
    let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let avg = values.iter().copied().sum::<f64>() / values.len() as f64;
    serde_json::json!({
        "min": min,
        "max": max,
        "avg": avg,
    })
}

fn parse_gateway_backend_latency(logs: &[String]) -> Value {
    let mut by_operation: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for line in logs {
        let Some(value) = parse_log_json(line) else {
            continue;
        };
        let fields = value.get("fields").unwrap_or(&value);
        if json_field_str(fields, "provider") != Some("s3") {
            continue;
        }
        let Some(operation) = json_field_str(fields, "operation") else {
            continue;
        };
        let Some(elapsed_us) = json_field_u64_opt(fields, "elapsed_us") else {
            continue;
        };
        by_operation
            .entry(operation.to_owned())
            .or_default()
            .push(elapsed_us);
    }

    Value::Object(
        by_operation
            .into_iter()
            .map(|(operation, samples)| (operation, summarize_latency_us(&samples)))
            .collect(),
    )
}

fn summarize_latency_us(samples: &[u64]) -> Value {
    if samples.is_empty() {
        return serde_json::json!({
            "samples": 0,
            "min": null,
            "avg": null,
            "p50": null,
            "p95": null,
            "p99": null,
            "max": null,
        });
    }

    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let sum = sorted.iter().copied().map(u128::from).sum::<u128>();
    let avg = sum as f64 / sorted.len() as f64;
    serde_json::json!({
        "samples": sorted.len(),
        "min": sorted[0],
        "avg": avg,
        "p50": percentile_u64(&sorted, 0.50),
        "p95": percentile_u64(&sorted, 0.95),
        "p99": percentile_u64(&sorted, 0.99),
        "max": sorted[sorted.len() - 1],
    })
}

fn percentile_u64(sorted: &[u64], quantile: f64) -> u64 {
    let index = ((sorted.len() as f64 * quantile).ceil() as usize)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    sorted[index]
}

fn parse_gateway_backend_counts(logs: &[String]) -> rs3_storage::BlobOperationCounts {
    let mut counts = rs3_storage::BlobOperationCounts::default();
    for line in logs {
        let Some(value) = parse_log_json(line) else {
            continue;
        };
        let fields = value.get("fields").unwrap_or(&value);
        if json_field_str(fields, "provider") != Some("s3") {
            continue;
        }
        let Some(operation) = json_field_str(fields, "operation") else {
            continue;
        };
        match operation {
            "put" => counts.put = counts.put.saturating_add(1),
            "get" => counts.get = counts.get.saturating_add(1),
            "head" => counts.head = counts.head.saturating_add(1),
            "list" => counts.list = counts.list.saturating_add(1),
            "delete" => counts.delete = counts.delete.saturating_add(1),
            "extend_retention" => {
                counts.extend_retention = counts.extend_retention.saturating_add(1);
            }
            _ => continue,
        }

        if json_field_str(fields, "result") == Some("ok") {
            counts.bytes_written = counts
                .bytes_written
                .saturating_add(json_field_u64(fields, "bytes_sent"));
            counts.bytes_read = counts
                .bytes_read
                .saturating_add(json_field_u64(fields, "bytes_received"));
        }
    }
    counts
}

fn storage_proxy_metrics_json(logs: &[String]) -> Option<Value> {
    let mut latest = None;
    for line in logs {
        let Some(value) = parse_log_json(line) else {
            continue;
        };
        if value.get("target").and_then(Value::as_str) == Some("rs3_storage_measure") {
            latest = value.get("fields").cloned();
        }
    }
    let fields = latest?;
    Some(serde_json::json!({
        "source": "integration-storage-proxy",
        "counts": {
            "requests": json_field_u64(&fields, "requests"),
            "responses": json_field_u64(&fields, "responses"),
            "bytes_written": json_field_u64(&fields, "request_body_bytes"),
            "bytes_read": json_field_u64(&fields, "response_body_bytes"),
        },
        "transport": {
            "bytes_to_backend": json_field_u64(&fields, "bytes_to_backend"),
            "bytes_from_backend": json_field_u64(&fields, "bytes_from_backend"),
            "accepted_connections": json_field_u64(&fields, "accepted_connections"),
            "active_connections": json_field_u64(&fields, "active_connections"),
            "failed_connections": json_field_u64(&fields, "failed_connections"),
        },
        "methods": fields.get("methods").cloned().unwrap_or_else(|| serde_json::json!({})),
        "statuses": fields.get("statuses").cloned().unwrap_or_else(|| serde_json::json!({})),
    }))
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

fn json_field_str<'a>(fields: &'a Value, key: &str) -> Option<&'a str> {
    fields.get(key).and_then(Value::as_str)
}

fn json_field_u64(fields: &Value, key: &str) -> u64 {
    json_field_u64_opt(fields, key).unwrap_or(0)
}

fn json_field_u64_opt(fields: &Value, key: &str) -> Option<u64> {
    fields.get(key).and_then(|value| {
        value
            .as_u64()
            .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
    })
}

fn parse_log_json(line: &str) -> Option<Value> {
    let trimmed = line.trim_start();
    let json = if trimmed.starts_with('{') {
        trimmed
    } else {
        let start = trimmed.find('{')?;
        &trimmed[start..]
    };
    serde_json::from_str(json).ok()
}

fn bump_count(counts: &mut BTreeMap<String, u64>, key: &str) {
    let next = counts.get(key).copied().unwrap_or(0).saturating_add(1);
    counts.insert(key.to_owned(), next);
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_metrics_include_operation_latency() {
        let logs = vec![
            r#"{"target":"rs3_storage","fields":{"provider":"s3","operation":"put","result":"ok","bytes_sent":12,"bytes_received":0,"elapsed_us":100}}"#.to_owned(),
            r#"{"target":"rs3_storage","fields":{"provider":"s3","operation":"put","result":"ok","bytes_sent":7,"bytes_received":0,"elapsed_us":"300"}}"#.to_owned(),
            r#"{"target":"rs3_storage","fields":{"provider":"s3","operation":"get","result":"ok","bytes_sent":0,"bytes_received":5,"elapsed_us":200}}"#.to_owned(),
            r#"{"target":"rs3_storage","fields":{"operation":"put","elapsed_us":999}}"#.to_owned(),
        ];

        let metrics = gateway_backend_metrics_json(&logs);

        assert_eq!(metrics["counts"]["put"], 2);
        assert_eq!(metrics["counts"]["get"], 1);
        assert_eq!(metrics["counts"]["bytes_written"], 19);
        assert_eq!(metrics["counts"]["bytes_read"], 5);
        assert_eq!(metrics["operation_latency_us"]["put"]["samples"], 2);
        assert_eq!(metrics["operation_latency_us"]["put"]["min"], 100);
        assert_eq!(metrics["operation_latency_us"]["put"]["p50"], 100);
        assert_eq!(metrics["operation_latency_us"]["put"]["p95"], 300);
        assert_eq!(metrics["operation_latency_us"]["put"]["max"], 300);
        assert_eq!(metrics["operation_latency_us"]["get"]["samples"], 1);
        assert_eq!(metrics["operation_latency_us"]["get"]["p95"], 200);
    }

    #[test]
    fn gateway_client_metrics_include_request_counts_and_latency() {
        let logs = vec![
            r#"[gateway] {"target":"rs3_server","fields":{"message":"S3 request completed","operation":"PutObject","request_id":1,"bucket":"client-bucket","result":"ok","status_code":200,"elapsed_us":1000}}"#.to_owned(),
            r#"{"target":"rs3_server","fields":{"message":"S3 request completed","operation":"GetObject","request_id":2,"bucket":"client-bucket","result":"ok","status_code":"206","elapsed_us":"3000"}}"#.to_owned(),
            r#"{"target":"rs3_server","fields":{"message":"S3 request completed","operation":"GetObject","request_id":3,"bucket":"client-bucket","result":"error","status_code":404,"error_code":"NoSuchKey","elapsed_us":2000}}"#.to_owned(),
            r#"{"target":"rs3_server","fields":{"message":"S3 request body collected","operation":"PutObject","request_id":1,"request_body_bytes":7}}"#.to_owned(),
            r#"{"target":"rs3_storage","fields":{"provider":"s3","operation":"put","elapsed_us":999}}"#.to_owned(),
        ];

        let metrics = gateway_client_metrics_json(&logs);

        assert_eq!(metrics["source"], "gateway-s3-request-logs");
        assert_eq!(metrics["counts_by_operation"]["PutObject"], 1);
        assert_eq!(metrics["counts_by_operation"]["GetObject"], 2);
        assert_eq!(metrics["counts_by_result"]["ok"], 2);
        assert_eq!(metrics["counts_by_result"]["error"], 1);
        assert_eq!(metrics["counts_by_status"]["200"], 1);
        assert_eq!(metrics["counts_by_status"]["206"], 1);
        assert_eq!(metrics["counts_by_status"]["404"], 1);
        assert_eq!(metrics["operation_latency_us"]["GetObject"]["samples"], 2);
        assert_eq!(metrics["operation_latency_us"]["GetObject"]["min"], 2000);
        assert_eq!(metrics["operation_latency_us"]["GetObject"]["p50"], 2000);
        assert_eq!(metrics["operation_latency_us"]["GetObject"]["p95"], 3000);
        assert_eq!(metrics["operation_latency_us"]["PutObject"]["max"], 1000);
    }
}
