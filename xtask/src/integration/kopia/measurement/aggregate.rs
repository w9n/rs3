//! Aggregation and comparison helpers for Kopia measurement reports.

use super::common::{summarize_f64, summarize_u64};
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) fn aggregate_runs(runs: &[Value]) -> Value {
    let mut by_storage_path = serde_json::Map::new();
    for storage_path in ["direct-rustfs", "gateway"] {
        let reports = reports_for_storage_path(runs, storage_path);
        by_storage_path.insert(storage_path.to_owned(), aggregate_reports(&reports));
    }
    Value::Object(by_storage_path)
}

pub(crate) fn compare_runs(runs: &[Value]) -> Value {
    let mut elapsed_ms_ratio = Vec::new();
    let mut client_request_count_ratio = Vec::new();
    let mut backend_request_count_ratio = Vec::new();
    let mut backend_write_bytes_ratio = Vec::new();
    let mut backend_read_bytes_ratio = Vec::new();
    let mut backend_operations_per_client_request = Vec::new();
    let mut backend_puts_per_client_put = Vec::new();
    let mut backend_gets_per_client_get = Vec::new();

    for run in runs {
        let Some(direct) = report_for_storage_path(run, "direct-rustfs") else {
            continue;
        };
        let Some(gateway) = report_for_storage_path(run, "gateway") else {
            continue;
        };

        push_ratio(
            &mut elapsed_ms_ratio,
            value_u64_at(gateway, &["elapsed_ms"]),
            value_u64_at(direct, &["elapsed_ms"]),
        );
        push_ratio(
            &mut client_request_count_ratio,
            gateway_client_request_count(gateway),
            value_u64_at(direct, &["backend_metrics", "counts", "requests"]),
        );
        push_ratio(
            &mut backend_request_count_ratio,
            gateway_backend_operation_count(gateway),
            value_u64_at(direct, &["backend_metrics", "counts", "requests"]),
        );
        push_ratio(
            &mut backend_write_bytes_ratio,
            value_u64_at(gateway, &["backend_metrics", "counts", "bytes_written"]),
            value_u64_at(direct, &["backend_metrics", "counts", "bytes_written"]),
        );
        push_ratio(
            &mut backend_read_bytes_ratio,
            value_u64_at(gateway, &["backend_metrics", "counts", "bytes_read"]),
            value_u64_at(direct, &["backend_metrics", "counts", "bytes_read"]),
        );
        push_ratio(
            &mut backend_operations_per_client_request,
            gateway_backend_operation_count(gateway),
            gateway_client_request_count(gateway),
        );
        push_ratio(
            &mut backend_puts_per_client_put,
            value_u64_at(gateway, &["backend_metrics", "counts", "put"]),
            value_u64_at(
                gateway,
                &["client_metrics", "counts_by_operation", "PutObject"],
            ),
        );
        push_ratio(
            &mut backend_gets_per_client_get,
            value_u64_at(gateway, &["backend_metrics", "counts", "get"]),
            value_u64_at(
                gateway,
                &["client_metrics", "counts_by_operation", "GetObject"],
            ),
        );
    }

    serde_json::json!({
        "gateway_vs_direct": {
            "elapsed_ms_ratio": summarize_f64(&elapsed_ms_ratio),
            "client_request_count_ratio": summarize_f64(&client_request_count_ratio),
            "backend_request_count_ratio": summarize_f64(&backend_request_count_ratio),
            "backend_write_bytes_ratio": summarize_f64(&backend_write_bytes_ratio),
            "backend_read_bytes_ratio": summarize_f64(&backend_read_bytes_ratio),
        },
        "gateway_internal": {
            "backend_operations_per_client_request": summarize_f64(&backend_operations_per_client_request),
            "backend_puts_per_client_put": summarize_f64(&backend_puts_per_client_put),
            "backend_gets_per_client_get": summarize_f64(&backend_gets_per_client_get),
        },
    })
}

fn reports_for_storage_path<'a>(runs: &'a [Value], storage_path: &str) -> Vec<&'a Value> {
    runs.iter()
        .filter_map(|run| run.get("reports").and_then(Value::as_array))
        .flat_map(|reports| reports.iter())
        .filter(|report| report.get("storage_path").and_then(Value::as_str) == Some(storage_path))
        .collect()
}

fn report_for_storage_path<'a>(run: &'a Value, storage_path: &str) -> Option<&'a Value> {
    run.get("reports")?
        .as_array()?
        .iter()
        .find(|report| report.get("storage_path").and_then(Value::as_str) == Some(storage_path))
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
        "prometheus_metrics": {
            "counts_by_operation": aggregate_number_object(reports, &[
                "prometheus_metrics",
                "counts_by_operation",
            ]),
            "counts_by_result": aggregate_number_object(reports, &[
                "prometheus_metrics",
                "counts_by_result",
            ]),
            "counts_by_status": aggregate_number_object(reports, &[
                "prometheus_metrics",
                "counts_by_status",
            ]),
            "request_body_bytes_by_operation": aggregate_number_object(reports, &[
                "prometheus_metrics",
                "request_body_bytes_by_operation",
            ]),
            "response_body_bytes_by_operation": aggregate_number_object(reports, &[
                "prometheus_metrics",
                "response_body_bytes_by_operation",
            ]),
            "request_duration_seconds": aggregate_operation_latency_at(reports, &[
                "prometheus_metrics",
                "request_duration_seconds",
            ]),
        },
        "gateway_process": {
            "vm_hwm_bytes": aggregate_u64_at(reports, &["gateway_process", "vm_hwm_bytes"]),
            "vm_rss_bytes": aggregate_u64_at(reports, &["gateway_process", "vm_rss_bytes"]),
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
    let mut timings: BTreeMap<String, Vec<u64>> = BTreeMap::new();
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
    let mut values_by_key: BTreeMap<String, Vec<u64>> = BTreeMap::new();
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

fn aggregate_u64_at(reports: &[&Value], path: &[&str]) -> Value {
    let values = reports
        .iter()
        .filter_map(|report| value_u64_at(report, path))
        .collect::<Vec<_>>();
    summarize_u64(&values)
}

fn aggregate_number_object(reports: &[&Value], path: &[&str]) -> Value {
    let mut values_by_key: BTreeMap<String, Vec<f64>> = BTreeMap::new();
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
            if let Some(value) = value.as_f64() {
                values_by_key.entry(key.clone()).or_default().push(value);
            }
        }
    }

    Value::Object(
        values_by_key
            .into_iter()
            .map(|(key, values)| (key, summarize_f64(&values)))
            .collect(),
    )
}

fn gateway_client_request_count(report: &Value) -> Option<u64> {
    sum_object_u64_at(report, &["client_metrics", "counts_by_operation"])
}

fn gateway_backend_operation_count(report: &Value) -> Option<u64> {
    let counts = value_at(report, &["backend_metrics", "counts"])?.as_object()?;
    let total = [
        "put",
        "get",
        "head",
        "list",
        "delete",
        "extend_retention",
        "flush",
    ]
    .iter()
    .filter_map(|key| counts.get(*key).and_then(Value::as_u64))
    .fold(0_u64, u64::saturating_add);
    Some(total)
}

fn sum_object_u64_at(value: &Value, path: &[&str]) -> Option<u64> {
    let object = value_at(value, path)?.as_object()?;
    Some(
        object
            .values()
            .filter_map(Value::as_u64)
            .fold(0_u64, u64::saturating_add),
    )
}

fn value_u64_at(value: &Value, path: &[&str]) -> Option<u64> {
    value_at(value, path)?.as_u64()
}

fn value_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    Some(current)
}

fn push_ratio(ratios: &mut Vec<f64>, numerator: Option<u64>, denominator: Option<u64>) {
    let Some(numerator) = numerator else {
        return;
    };
    let Some(denominator) = denominator else {
        return;
    };
    if denominator == 0 {
        return;
    }
    ratios.push(numerator as f64 / denominator as f64);
}

#[cfg(test)]
mod tests {
    use super::{aggregate_runs, compare_runs};

    #[test]
    fn compares_gateway_and_direct_run_ratios() {
        let runs = vec![serde_json::json!({
            "run": 1,
            "reports": [
                {
                    "storage_path": "direct-rustfs",
                    "elapsed_ms": 100,
                    "backend_metrics": {
                        "counts": {
                            "requests": 10,
                            "bytes_written": 1000,
                            "bytes_read": 2000,
                        }
                    }
                },
                {
                    "storage_path": "gateway",
                    "elapsed_ms": 150,
                    "gateway_process": {
                        "vm_hwm_bytes": 4096,
                        "vm_rss_bytes": 2048
                    },
                    "backend_metrics": {
                        "counts": {
                            "put": 12,
                            "get": 3,
                            "head": 2,
                            "list": 1,
                            "delete": 2,
                            "extend_retention": 0,
                            "bytes_written": 1250,
                            "bytes_read": 3000,
                        }
                    },
                    "client_metrics": {
                        "counts_by_operation": {
                            "PutObject": 4,
                            "GetObject": 6,
                        }
                    }
                }
            ]
        })];

        let comparison = compare_runs(&runs);

        assert_eq!(
            comparison["gateway_vs_direct"]["elapsed_ms_ratio"]["avg"],
            serde_json::json!(1.5)
        );
        assert_eq!(
            comparison["gateway_vs_direct"]["client_request_count_ratio"]["avg"],
            serde_json::json!(1.0)
        );
        assert_eq!(
            comparison["gateway_vs_direct"]["backend_request_count_ratio"]["avg"],
            serde_json::json!(2.0)
        );
        assert_eq!(
            comparison["gateway_vs_direct"]["backend_write_bytes_ratio"]["avg"],
            serde_json::json!(1.25)
        );
        assert_eq!(
            comparison["gateway_vs_direct"]["backend_read_bytes_ratio"]["avg"],
            serde_json::json!(1.5)
        );
        assert_eq!(
            comparison["gateway_internal"]["backend_operations_per_client_request"]["avg"],
            serde_json::json!(2.0)
        );
        assert_eq!(
            comparison["gateway_internal"]["backend_puts_per_client_put"]["avg"],
            serde_json::json!(3.0)
        );
        assert_eq!(
            comparison["gateway_internal"]["backend_gets_per_client_get"]["avg"],
            serde_json::json!(0.5)
        );

        let aggregate = aggregate_runs(&runs);
        assert_eq!(
            aggregate["gateway"]["gateway_process"]["vm_hwm_bytes"]["avg"],
            serde_json::json!(4096.0)
        );
        assert_eq!(
            aggregate["gateway"]["gateway_process"]["vm_rss_bytes"]["avg"],
            serde_json::json!(2048.0)
        );
    }
}
