//! Prometheus scrape and delta helpers for Kopia measurements.

use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub(crate) async fn scrape_prometheus_metrics(authority: &str) -> Result<String> {
    let started = Instant::now();
    loop {
        match scrape_prometheus_metrics_once(authority).await {
            Ok(body) => return Ok(body),
            Err(error) => {
                if started.elapsed() >= Duration::from_secs(3) {
                    bail!("gateway metrics endpoint did not respond at {authority}: {error}");
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn scrape_prometheus_metrics_once(authority: &str) -> Result<String> {
    let mut stream = TcpStream::connect(authority)
        .await
        .with_context(|| format!("failed to connect to gateway metrics endpoint at {authority}"))?;
    let request =
        format!("GET /metrics HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .context("failed to write metrics scrape request")?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .context("failed to read metrics scrape response")?;
    let response = String::from_utf8(response).context("metrics scrape response was not UTF-8")?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .context("metrics scrape response did not contain HTTP headers")?;
    if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
        bail!("metrics scrape returned non-200 response: {head}");
    }
    Ok(body.to_owned())
}

pub(crate) fn prometheus_metrics_delta_json(before: &str, after: &str) -> Value {
    let before = parse_prometheus_samples(before);
    let after = parse_prometheus_samples(after);
    let mut counts_by_operation = BTreeMap::new();
    let mut counts_by_result = BTreeMap::new();
    let mut counts_by_status = BTreeMap::new();
    let mut request_body_bytes_by_operation = BTreeMap::new();
    let mut response_body_bytes_by_operation = BTreeMap::new();
    let mut duration_counts = BTreeMap::new();
    let mut duration_sums = BTreeMap::new();
    let mut storage_provider_counts_by_operation = BTreeMap::new();
    let mut storage_provider_counts_by_result = BTreeMap::new();
    let mut storage_provider_bytes_sent_by_operation = BTreeMap::new();
    let mut storage_provider_bytes_received_by_operation = BTreeMap::new();
    let mut storage_provider_duration_counts = BTreeMap::new();
    let mut storage_provider_duration_sums = BTreeMap::new();
    let mut repository_counts_by_operation = BTreeMap::new();
    let mut repository_counts_by_result = BTreeMap::new();
    let mut repository_plaintext_bytes_by_operation = BTreeMap::new();
    let mut repository_backend_bytes_written_by_operation = BTreeMap::new();
    let mut repository_backend_bytes_read_by_range = BTreeMap::new();
    let mut repository_returned_bytes_by_range = BTreeMap::new();
    let mut repository_list_lookup_tokens_by_prefix_mode = BTreeMap::new();
    let mut repository_list_candidates_by_prefix_mode = BTreeMap::new();
    let mut repository_list_manifest_misses_by_prefix_mode = BTreeMap::new();
    let mut repository_list_prefix_misses_by_prefix_mode = BTreeMap::new();
    let mut repository_list_returned_by_prefix_mode = BTreeMap::new();
    let mut repository_duration_counts = BTreeMap::new();
    let mut repository_duration_sums = BTreeMap::new();
    let mut repository_commit_enqueues_by_result = BTreeMap::new();
    let mut repository_commit_enqueue_pending_items_by_result = BTreeMap::new();
    let mut repository_commit_batch_publishes_by_result = BTreeMap::new();
    let mut repository_commit_batch_waiters_by_result = BTreeMap::new();
    let mut repository_commit_batch_duration_counts = BTreeMap::new();
    let mut repository_commit_batch_duration_sums = BTreeMap::new();

    for (identity, sample) in after {
        let delta = metric_delta(
            before.get(&identity).map(|sample| sample.value),
            sample.value,
        );
        if delta == 0.0 {
            continue;
        }
        match sample.name.as_str() {
            "rs3_s3_requests_total" => {
                bump_f64_label(&mut counts_by_operation, sample.label("operation"), delta);
                bump_f64_label(&mut counts_by_result, sample.label("result"), delta);
                bump_f64_label(&mut counts_by_status, sample.label("status_code"), delta);
            }
            "rs3_s3_request_body_bytes_total" => {
                bump_f64_label(
                    &mut request_body_bytes_by_operation,
                    sample.label("operation"),
                    delta,
                );
            }
            "rs3_s3_response_body_bytes_total" => {
                bump_f64_label(
                    &mut response_body_bytes_by_operation,
                    sample.label("operation"),
                    delta,
                );
            }
            "rs3_s3_request_duration_seconds_count" => {
                bump_f64_label(&mut duration_counts, sample.label("operation"), delta);
            }
            "rs3_s3_request_duration_seconds_sum" => {
                bump_f64_label(&mut duration_sums, sample.label("operation"), delta);
            }
            "rs3_storage_provider_operations_total" => {
                bump_f64_label(
                    &mut storage_provider_counts_by_operation,
                    sample.label("operation"),
                    delta,
                );
                bump_f64_label(
                    &mut storage_provider_counts_by_result,
                    sample.label("result"),
                    delta,
                );
            }
            "rs3_storage_provider_bytes_sent_total" => {
                bump_f64_label(
                    &mut storage_provider_bytes_sent_by_operation,
                    sample.label("operation"),
                    delta,
                );
            }
            "rs3_storage_provider_bytes_received_total" => {
                bump_f64_label(
                    &mut storage_provider_bytes_received_by_operation,
                    sample.label("operation"),
                    delta,
                );
            }
            "rs3_storage_provider_operation_duration_seconds_count" => {
                bump_f64_label(
                    &mut storage_provider_duration_counts,
                    sample.label("operation"),
                    delta,
                );
            }
            "rs3_storage_provider_operation_duration_seconds_sum" => {
                bump_f64_label(
                    &mut storage_provider_duration_sums,
                    sample.label("operation"),
                    delta,
                );
            }
            "rs3_repository_operations_total" => {
                bump_f64_label(
                    &mut repository_counts_by_operation,
                    sample.label("operation"),
                    delta,
                );
                bump_f64_label(
                    &mut repository_counts_by_result,
                    sample.label("result"),
                    delta,
                );
            }
            "rs3_repository_plaintext_bytes_total" => {
                bump_f64_label(
                    &mut repository_plaintext_bytes_by_operation,
                    sample.label("operation"),
                    delta,
                );
            }
            "rs3_repository_backend_bytes_written_total" => {
                bump_f64_label(
                    &mut repository_backend_bytes_written_by_operation,
                    sample.label("operation"),
                    delta,
                );
            }
            "rs3_repository_backend_bytes_read_total" => {
                bump_f64_label(
                    &mut repository_backend_bytes_read_by_range,
                    sample.label("range"),
                    delta,
                );
            }
            "rs3_repository_returned_bytes_total" => {
                bump_f64_label(
                    &mut repository_returned_bytes_by_range,
                    sample.label("range"),
                    delta,
                );
            }
            "rs3_repository_list_lookup_tokens_total" => {
                bump_f64_label(
                    &mut repository_list_lookup_tokens_by_prefix_mode,
                    sample.label("prefix_mode"),
                    delta,
                );
            }
            "rs3_repository_list_candidates_total" => {
                bump_f64_label(
                    &mut repository_list_candidates_by_prefix_mode,
                    sample.label("prefix_mode"),
                    delta,
                );
            }
            "rs3_repository_list_manifest_misses_total" => {
                bump_f64_label(
                    &mut repository_list_manifest_misses_by_prefix_mode,
                    sample.label("prefix_mode"),
                    delta,
                );
            }
            "rs3_repository_list_prefix_misses_total" => {
                bump_f64_label(
                    &mut repository_list_prefix_misses_by_prefix_mode,
                    sample.label("prefix_mode"),
                    delta,
                );
            }
            "rs3_repository_list_returned_total" => {
                bump_f64_label(
                    &mut repository_list_returned_by_prefix_mode,
                    sample.label("prefix_mode"),
                    delta,
                );
            }
            "rs3_repository_operation_duration_seconds_count" => {
                bump_f64_label(
                    &mut repository_duration_counts,
                    sample.label("operation"),
                    delta,
                );
            }
            "rs3_repository_operation_duration_seconds_sum" => {
                bump_f64_label(
                    &mut repository_duration_sums,
                    sample.label("operation"),
                    delta,
                );
            }
            "rs3_repository_commit_enqueues_total" => {
                bump_f64_label(
                    &mut repository_commit_enqueues_by_result,
                    sample.label("result"),
                    delta,
                );
            }
            "rs3_repository_commit_enqueue_pending_items_total" => {
                bump_f64_label(
                    &mut repository_commit_enqueue_pending_items_by_result,
                    sample.label("result"),
                    delta,
                );
            }
            "rs3_repository_commit_batch_publishes_total" => {
                bump_f64_label(
                    &mut repository_commit_batch_publishes_by_result,
                    sample.label("result"),
                    delta,
                );
            }
            "rs3_repository_commit_batch_waiters_total" => {
                bump_f64_label(
                    &mut repository_commit_batch_waiters_by_result,
                    sample.label("result"),
                    delta,
                );
            }
            "rs3_repository_commit_batch_publish_duration_seconds_count" => {
                bump_f64_label(
                    &mut repository_commit_batch_duration_counts,
                    sample.label("result"),
                    delta,
                );
            }
            "rs3_repository_commit_batch_publish_duration_seconds_sum" => {
                bump_f64_label(
                    &mut repository_commit_batch_duration_sums,
                    sample.label("result"),
                    delta,
                );
            }
            _ => {}
        }
    }

    serde_json::json!({
        "source": "gateway-prometheus-delta",
        "counts_by_operation": counts_by_operation,
        "counts_by_result": counts_by_result,
        "counts_by_status": counts_by_status,
        "request_body_bytes_by_operation": request_body_bytes_by_operation,
        "response_body_bytes_by_operation": response_body_bytes_by_operation,
        "request_duration_seconds": duration_summary_json(duration_counts, duration_sums),
        "storage_provider": {
            "counts_by_operation": storage_provider_counts_by_operation,
            "counts_by_result": storage_provider_counts_by_result,
            "bytes_sent_by_operation": storage_provider_bytes_sent_by_operation,
            "bytes_received_by_operation": storage_provider_bytes_received_by_operation,
            "operation_duration_seconds": duration_summary_json(
                storage_provider_duration_counts,
                storage_provider_duration_sums,
            ),
        },
        "repository": {
            "counts_by_operation": repository_counts_by_operation,
            "counts_by_result": repository_counts_by_result,
            "plaintext_bytes_by_operation": repository_plaintext_bytes_by_operation,
            "backend_bytes_written_by_operation": repository_backend_bytes_written_by_operation,
            "backend_bytes_read_by_range": repository_backend_bytes_read_by_range,
            "returned_bytes_by_range": repository_returned_bytes_by_range,
            "list_lookup_tokens_by_prefix_mode": repository_list_lookup_tokens_by_prefix_mode,
            "list_candidates_by_prefix_mode": repository_list_candidates_by_prefix_mode,
            "list_manifest_misses_by_prefix_mode": repository_list_manifest_misses_by_prefix_mode,
            "list_prefix_misses_by_prefix_mode": repository_list_prefix_misses_by_prefix_mode,
            "list_returned_by_prefix_mode": repository_list_returned_by_prefix_mode,
            "operation_duration_seconds": duration_summary_json(
                repository_duration_counts,
                repository_duration_sums,
            ),
            "commit": {
                "enqueues_by_result": repository_commit_enqueues_by_result,
                "enqueue_pending_items_by_result": repository_commit_enqueue_pending_items_by_result,
                "batch_publishes_by_result": repository_commit_batch_publishes_by_result,
                "batch_waiters_by_result": repository_commit_batch_waiters_by_result,
                "batch_publish_duration_seconds_by_result": duration_summary_json(
                    repository_commit_batch_duration_counts,
                    repository_commit_batch_duration_sums,
                ),
            },
        },
    })
}

#[derive(Clone, Debug)]
struct PrometheusSample {
    name: String,
    labels: BTreeMap<String, String>,
    value: f64,
}

impl PrometheusSample {
    fn label(&self, name: &str) -> Option<&str> {
        self.labels.get(name).map(String::as_str)
    }
}

fn parse_prometheus_samples(body: &str) -> BTreeMap<String, PrometheusSample> {
    body.lines()
        .filter_map(parse_prometheus_sample)
        .map(|sample| (prometheus_sample_identity(&sample), sample))
        .collect()
}

fn parse_prometheus_sample(line: &str) -> Option<PrometheusSample> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut fields = line.split_whitespace();
    let metric = fields.next()?;
    let value = fields.next()?.parse::<f64>().ok()?;
    let (name, labels) = parse_prometheus_metric(metric)?;
    Some(PrometheusSample {
        name,
        labels,
        value,
    })
}

fn parse_prometheus_metric(metric: &str) -> Option<(String, BTreeMap<String, String>)> {
    let Some((name, labels)) = metric.split_once('{') else {
        return Some((metric.to_owned(), BTreeMap::new()));
    };
    let labels = labels.strip_suffix('}')?;
    Some((name.to_owned(), parse_prometheus_labels(labels)))
}

fn parse_prometheus_labels(labels: &str) -> BTreeMap<String, String> {
    labels
        .split(',')
        .filter_map(|label| {
            let (key, value) = label.split_once('=')?;
            Some((key.to_owned(), value.trim_matches('"').to_owned()))
        })
        .collect()
}

fn prometheus_sample_identity(sample: &PrometheusSample) -> String {
    let labels = sample
        .labels
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(",");
    format!("{}{{{labels}}}", sample.name)
}

fn metric_delta(before: Option<f64>, after: f64) -> f64 {
    let before = before.unwrap_or(0.0);
    if after >= before {
        after - before
    } else {
        after
    }
}

fn bump_f64_label(counts: &mut BTreeMap<String, f64>, label: Option<&str>, add: f64) {
    let Some(label) = label else {
        return;
    };
    let next = counts.get(label).copied().unwrap_or(0.0) + add;
    counts.insert(label.to_owned(), next);
}

fn duration_summary_json(
    counts: BTreeMap<String, f64>,
    sums: BTreeMap<String, f64>,
) -> BTreeMap<String, Value> {
    counts
        .into_iter()
        .map(|(operation, count)| {
            let sum = sums.get(&operation).copied().unwrap_or(0.0);
            let avg = if count > 0.0 { Some(sum / count) } else { None };
            (
                operation,
                serde_json::json!({
                    "count": count,
                    "sum": sum,
                    "avg": avg,
                }),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::prometheus_metrics_delta_json;

    #[test]
    fn summarizes_prometheus_metrics_delta_without_run_labels() {
        let before = r#"
# TYPE rs3_s3_requests_total counter
rs3_s3_requests_total{operation="PutObject",result="ok",status_code="200"} 2
rs3_s3_request_duration_seconds_count{operation="PutObject",result="ok",status_code="200"} 2
rs3_s3_request_duration_seconds_sum{operation="PutObject",result="ok",status_code="200"} 0.5
"#;
        let after = r#"
# TYPE rs3_s3_requests_total counter
rs3_s3_requests_total{operation="PutObject",result="ok",status_code="200"} 5
rs3_s3_requests_total{operation="GetObject",result="error",status_code="404"} 1
rs3_s3_request_body_bytes_total{operation="PutObject"} 1024
rs3_s3_response_body_bytes_total{operation="GetObject"} 512
rs3_s3_request_duration_seconds_count{operation="PutObject",result="ok",status_code="200"} 5
rs3_s3_request_duration_seconds_sum{operation="PutObject",result="ok",status_code="200"} 1.25
rs3_storage_provider_operations_total{provider="s3",operation="put",object_kind="segments",result="ok"} 4
rs3_storage_provider_operations_total{provider="s3",operation="get",object_kind="segments",result="ok"} 2
rs3_storage_provider_bytes_sent_total{provider="s3",operation="put",object_kind="segments"} 4096
rs3_storage_provider_bytes_received_total{provider="s3",operation="get",object_kind="segments"} 2048
rs3_storage_provider_operation_duration_seconds_count{provider="s3",operation="put",object_kind="segments",result="ok"} 4
rs3_storage_provider_operation_duration_seconds_sum{provider="s3",operation="put",object_kind="segments",result="ok"} 0.8
rs3_repository_operations_total{operation="put",result="ok"} 4
rs3_repository_operations_total{operation="get_range",result="ok"} 2
rs3_repository_plaintext_bytes_total{operation="put"} 2048
rs3_repository_backend_bytes_written_total{operation="put"} 4096
rs3_repository_backend_bytes_read_total{operation="get_range",range="slice",result="ok"} 1536
rs3_repository_returned_bytes_total{operation="get_range",range="slice"} 512
rs3_repository_list_lookup_tokens_total{prefix_mode="delimiter",result="ok"} 3
rs3_repository_list_candidates_total{prefix_mode="delimiter",result="ok"} 12
rs3_repository_list_manifest_misses_total{prefix_mode="delimiter",result="ok"} 1
rs3_repository_list_prefix_misses_total{prefix_mode="delimiter",result="ok"} 2
rs3_repository_list_returned_total{prefix_mode="delimiter",result="ok"} 9
rs3_repository_operation_duration_seconds_count{operation="get_range",result="ok"} 2
rs3_repository_operation_duration_seconds_sum{operation="get_range",result="ok"} 0.04
rs3_repository_commit_enqueues_total{result="ok"} 4
rs3_repository_commit_enqueue_pending_items_total{result="ok"} 10
rs3_repository_commit_batch_publishes_total{result="ok"} 2
rs3_repository_commit_batch_waiters_total{result="ok"} 4
rs3_repository_commit_batch_publish_duration_seconds_count{result="ok"} 2
rs3_repository_commit_batch_publish_duration_seconds_sum{result="ok"} 0.06
"#;

        let metrics = prometheus_metrics_delta_json(before, after);

        assert_eq!(metrics["source"], "gateway-prometheus-delta");
        assert_eq!(metrics["counts_by_operation"]["PutObject"], 3.0);
        assert_eq!(metrics["counts_by_operation"]["GetObject"], 1.0);
        assert_eq!(metrics["counts_by_result"]["ok"], 3.0);
        assert_eq!(metrics["counts_by_result"]["error"], 1.0);
        assert_eq!(metrics["counts_by_status"]["200"], 3.0);
        assert_eq!(metrics["counts_by_status"]["404"], 1.0);
        assert_eq!(
            metrics["request_body_bytes_by_operation"]["PutObject"],
            1024.0
        );
        assert_eq!(
            metrics["response_body_bytes_by_operation"]["GetObject"],
            512.0
        );
        assert_eq!(
            metrics["request_duration_seconds"]["PutObject"]["count"],
            3.0
        );
        assert_eq!(
            metrics["request_duration_seconds"]["PutObject"]["sum"],
            0.75
        );
        assert_eq!(
            metrics["request_duration_seconds"]["PutObject"]["avg"],
            0.25
        );
        assert_eq!(
            metrics["storage_provider"]["counts_by_operation"]["put"],
            4.0
        );
        assert_eq!(
            metrics["storage_provider"]["counts_by_operation"]["get"],
            2.0
        );
        assert_eq!(metrics["storage_provider"]["counts_by_result"]["ok"], 6.0);
        assert_eq!(
            metrics["storage_provider"]["bytes_sent_by_operation"]["put"],
            4096.0
        );
        assert_eq!(
            metrics["storage_provider"]["bytes_received_by_operation"]["get"],
            2048.0
        );
        assert_eq!(
            metrics["storage_provider"]["operation_duration_seconds"]["put"]["avg"],
            0.2
        );
        assert_eq!(metrics["repository"]["counts_by_operation"]["put"], 4.0);
        assert_eq!(
            metrics["repository"]["counts_by_operation"]["get_range"],
            2.0
        );
        assert_eq!(metrics["repository"]["counts_by_result"]["ok"], 6.0);
        assert_eq!(
            metrics["repository"]["plaintext_bytes_by_operation"]["put"],
            2048.0
        );
        assert_eq!(
            metrics["repository"]["backend_bytes_written_by_operation"]["put"],
            4096.0
        );
        assert_eq!(
            metrics["repository"]["backend_bytes_read_by_range"]["slice"],
            1536.0
        );
        assert_eq!(
            metrics["repository"]["returned_bytes_by_range"]["slice"],
            512.0
        );
        assert_eq!(
            metrics["repository"]["list_lookup_tokens_by_prefix_mode"]["delimiter"],
            3.0
        );
        assert_eq!(
            metrics["repository"]["list_candidates_by_prefix_mode"]["delimiter"],
            12.0
        );
        assert_eq!(
            metrics["repository"]["list_manifest_misses_by_prefix_mode"]["delimiter"],
            1.0
        );
        assert_eq!(
            metrics["repository"]["list_prefix_misses_by_prefix_mode"]["delimiter"],
            2.0
        );
        assert_eq!(
            metrics["repository"]["list_returned_by_prefix_mode"]["delimiter"],
            9.0
        );
        assert_eq!(
            metrics["repository"]["operation_duration_seconds"]["get_range"]["avg"],
            0.02
        );
        assert_eq!(
            metrics["repository"]["commit"]["enqueues_by_result"]["ok"],
            4.0
        );
        assert_eq!(
            metrics["repository"]["commit"]["enqueue_pending_items_by_result"]["ok"],
            10.0
        );
        assert_eq!(
            metrics["repository"]["commit"]["batch_publishes_by_result"]["ok"],
            2.0
        );
        assert_eq!(
            metrics["repository"]["commit"]["batch_waiters_by_result"]["ok"],
            4.0
        );
        assert_eq!(
            metrics["repository"]["commit"]["batch_publish_duration_seconds_by_result"]["ok"]["avg"],
            0.03
        );
    }
}
