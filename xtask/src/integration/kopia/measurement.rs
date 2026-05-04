//! Measurement helpers for Kopia integration lanes.

#[path = "measurement/aggregate.rs"]
mod aggregate;
#[path = "measurement/common.rs"]
mod common;
#[path = "measurement/logs.rs"]
mod logs;
#[path = "measurement/process.rs"]
mod process;
#[path = "measurement/prometheus.rs"]
mod prometheus;

use super::KopiaRunStats;
pub(super) use aggregate::{aggregate_runs, compare_runs, workload_consistency_json};
use anyhow::{Result, bail};
pub(super) use logs::{gateway_backend_metrics_json, gateway_client_metrics_json};
pub(super) use process::{RunningStorageProxy, wait_for_storage_proxy_metrics};
pub(super) use prometheus::{prometheus_metrics_delta_json, scrape_prometheus_metrics};
use serde_json::Value;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
        "workload": {
            "source_tree": tree_stats_json(&stats.source_tree),
            "restored_tree": tree_stats_json(&stats.restored_tree),
        },
        "backend_metrics": backend_metrics,
    })
}

fn tree_stats_json(stats: &super::workload::KopiaTreeStats) -> Value {
    serde_json::json!({
        "files": stats.files,
        "directories": stats.directories,
        "bytes": stats.bytes,
        "largest_file_bytes": stats.largest_file_bytes,
    })
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

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
