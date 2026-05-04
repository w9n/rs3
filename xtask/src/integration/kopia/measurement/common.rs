//! Shared parsing and summary helpers for Kopia measurements.

use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn json_field_str<'a>(fields: &'a Value, key: &str) -> Option<&'a str> {
    fields.get(key).and_then(Value::as_str)
}

pub(super) fn json_field_u64(fields: &Value, key: &str) -> u64 {
    json_field_u64_opt(fields, key).unwrap_or(0)
}

pub(super) fn json_field_u64_opt(fields: &Value, key: &str) -> Option<u64> {
    fields.get(key).and_then(|value| {
        value
            .as_u64()
            .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
    })
}

pub(super) fn parse_log_json(line: &str) -> Option<Value> {
    let trimmed = line.trim_start();
    let json = if trimmed.starts_with('{') {
        trimmed
    } else {
        let start = trimmed.find('{')?;
        &trimmed[start..]
    };
    serde_json::from_str(json).ok()
}

pub(super) fn bump_count(counts: &mut BTreeMap<String, u64>, key: &str) {
    let next = counts.get(key).copied().unwrap_or(0).saturating_add(1);
    counts.insert(key.to_owned(), next);
}

pub(super) fn summarize_u64(values: &[u64]) -> Value {
    if values.is_empty() {
        return serde_json::json!({
            "samples": 0,
            "min": null,
            "p50": null,
            "p95": null,
            "max": null,
            "avg": null,
            "stddev": null,
            "relative_stddev": null,
            "spread": null,
        });
    }

    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let sum = sorted.iter().copied().map(u128::from).sum::<u128>();
    let avg = sum as f64 / sorted.len() as f64;
    let stddev = stddev_u64(&sorted, avg);
    serde_json::json!({
        "samples": sorted.len(),
        "min": sorted[0],
        "p50": percentile_u64(&sorted, 0.50),
        "p95": percentile_u64(&sorted, 0.95),
        "max": sorted[sorted.len() - 1],
        "avg": avg,
        "stddev": stddev,
        "relative_stddev": relative_stddev(stddev, avg, sorted.len()),
        "spread": sorted[sorted.len() - 1].saturating_sub(sorted[0]),
    })
}

pub(super) fn summarize_f64(values: &[f64]) -> Value {
    if values.is_empty() {
        return serde_json::json!({
            "samples": 0,
            "min": null,
            "p50": null,
            "p95": null,
            "max": null,
            "avg": null,
            "stddev": null,
            "relative_stddev": null,
            "spread": null,
        });
    }

    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let avg = sorted.iter().copied().sum::<f64>() / sorted.len() as f64;
    let stddev = stddev_f64(&sorted, avg);
    serde_json::json!({
        "samples": sorted.len(),
        "min": sorted[0],
        "p50": percentile_f64(&sorted, 0.50),
        "p95": percentile_f64(&sorted, 0.95),
        "max": sorted[sorted.len() - 1],
        "avg": avg,
        "stddev": stddev,
        "relative_stddev": relative_stddev(stddev, avg, sorted.len()),
        "spread": sorted[sorted.len() - 1] - sorted[0],
    })
}

pub(super) fn summarize_latency_us(samples: &[u64]) -> Value {
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

fn percentile_f64(sorted: &[f64], quantile: f64) -> f64 {
    let index = ((sorted.len() as f64 * quantile).ceil() as usize)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    sorted[index]
}

fn stddev_u64(values: &[u64], avg: f64) -> f64 {
    let variance = values
        .iter()
        .map(|value| {
            let delta = *value as f64 - avg;
            delta * delta
        })
        .sum::<f64>()
        / values.len() as f64;
    variance.sqrt()
}

fn stddev_f64(values: &[f64], avg: f64) -> f64 {
    let variance = values
        .iter()
        .map(|value| {
            let delta = *value - avg;
            delta * delta
        })
        .sum::<f64>()
        / values.len() as f64;
    variance.sqrt()
}

fn relative_stddev(stddev: f64, avg: f64, samples: usize) -> Option<f64> {
    if samples < 2 || avg == 0.0 {
        None
    } else {
        Some(stddev / avg.abs())
    }
}
