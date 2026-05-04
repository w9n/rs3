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
    let mut backend_read_bytes_per_client_get_response_byte = Vec::new();
    let mut backend_write_bytes_per_client_put_request_byte = Vec::new();
    let mut payload_span_cache_event_hit_ratio = Vec::new();
    let mut payload_span_cache_byte_hit_ratio = Vec::new();
    let mut phase_elapsed_ms_ratio: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    let mut commit_put_phase_avg_seconds: BTreeMap<String, Vec<f64>> = BTreeMap::new();

    for run in runs {
        let Some(direct) = report_for_storage_path(run, "direct-rustfs") else {
            continue;
        };
        let Some(gateway) = report_for_storage_path(run, "gateway") else {
            continue;
        };

        push_gateway_commit_phase_averages(&mut commit_put_phase_avg_seconds, gateway);
        push_ratio(
            &mut elapsed_ms_ratio,
            value_u64_at(gateway, &["elapsed_ms"]),
            value_u64_at(direct, &["elapsed_ms"]),
        );
        push_phase_elapsed_ratios(&mut phase_elapsed_ms_ratio, direct, gateway);
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
        push_f64_ratio(
            &mut backend_read_bytes_per_client_get_response_byte,
            value_f64_at(gateway, &["backend_metrics", "counts", "bytes_read"]),
            value_f64_at(
                gateway,
                &[
                    "prometheus_metrics",
                    "response_body_bytes_by_operation",
                    "GetObject",
                ],
            ),
        );
        push_f64_ratio(
            &mut backend_write_bytes_per_client_put_request_byte,
            value_f64_at(gateway, &["backend_metrics", "counts", "bytes_written"]),
            value_f64_at(
                gateway,
                &[
                    "prometheus_metrics",
                    "request_body_bytes_by_operation",
                    "PutObject",
                ],
            ),
        );
        push_share(
            &mut payload_span_cache_event_hit_ratio,
            value_f64_at(
                gateway,
                &[
                    "prometheus_metrics",
                    "repository",
                    "payload_span_cache_events_by_result",
                    "hit",
                ],
            ),
            value_f64_at(
                gateway,
                &[
                    "prometheus_metrics",
                    "repository",
                    "payload_span_cache_events_by_result",
                    "miss",
                ],
            ),
        );
        push_share(
            &mut payload_span_cache_byte_hit_ratio,
            value_f64_at(
                gateway,
                &[
                    "prometheus_metrics",
                    "repository",
                    "payload_span_cache_bytes_by_result",
                    "hit",
                ],
            ),
            value_f64_at(
                gateway,
                &[
                    "prometheus_metrics",
                    "repository",
                    "payload_span_cache_bytes_by_result",
                    "miss",
                ],
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
            "phase_elapsed_ms_ratio": summarize_ratio_map(&phase_elapsed_ms_ratio),
        },
        "gateway_internal": {
            "backend_operations_per_client_request": summarize_f64(&backend_operations_per_client_request),
            "backend_puts_per_client_put": summarize_f64(&backend_puts_per_client_put),
            "backend_gets_per_client_get": summarize_f64(&backend_gets_per_client_get),
            "backend_read_bytes_per_client_get_response_byte": summarize_f64(&backend_read_bytes_per_client_get_response_byte),
            "backend_write_bytes_per_client_put_request_byte": summarize_f64(&backend_write_bytes_per_client_put_request_byte),
            "payload_span_cache_event_hit_ratio": summarize_f64(&payload_span_cache_event_hit_ratio),
            "payload_span_cache_byte_hit_ratio": summarize_f64(&payload_span_cache_byte_hit_ratio),
            "commit_put_phase_avg_seconds": summarize_ratio_map(&commit_put_phase_avg_seconds),
        },
    })
}

pub(crate) fn workload_consistency_json(runs: &[Value]) -> Value {
    let mut checks = Vec::new();
    for run in runs {
        let profile = run.get("profile").and_then(Value::as_str).unwrap_or("");
        let run_index = run.get("run").and_then(Value::as_u64).unwrap_or(0);
        let reports = run.get("reports").and_then(Value::as_array);
        let direct =
            reports.and_then(|reports| report_for_storage_path_in(reports, "direct-rustfs"));
        let gateway = reports.and_then(|reports| report_for_storage_path_in(reports, "gateway"));

        let Some(direct) = direct else {
            push_consistency_failure(
                &mut checks,
                profile,
                run_index,
                "direct.report_present",
                "missing direct baseline report",
            );
            continue;
        };
        let Some(gateway) = gateway else {
            push_consistency_failure(
                &mut checks,
                profile,
                run_index,
                "gateway.report_present",
                "missing gateway report",
            );
            continue;
        };

        push_tree_consistency_check(
            &mut checks,
            profile,
            run_index,
            "direct.source_matches_restore",
            direct,
            &["workload", "source_tree"],
            direct,
            &["workload", "restored_tree"],
        );
        push_tree_consistency_check(
            &mut checks,
            profile,
            run_index,
            "gateway.source_matches_restore",
            gateway,
            &["workload", "source_tree"],
            gateway,
            &["workload", "restored_tree"],
        );
        push_tree_consistency_check(
            &mut checks,
            profile,
            run_index,
            "direct_source_matches_gateway_source",
            direct,
            &["workload", "source_tree"],
            gateway,
            &["workload", "source_tree"],
        );
        push_tree_consistency_check(
            &mut checks,
            profile,
            run_index,
            "direct_restore_matches_gateway_restore",
            direct,
            &["workload", "restored_tree"],
            gateway,
            &["workload", "restored_tree"],
        );
    }

    if checks.is_empty() {
        checks.push(serde_json::json!({
            "profile": "",
            "run": 0,
            "metric": "run_reports",
            "status": "fail",
            "reason": "no run reports were available",
        }));
    }
    let failed = checks
        .iter()
        .filter(|check| check.get("status").and_then(Value::as_str) == Some("fail"))
        .count();

    serde_json::json!({
        "status": if failed == 0 { "pass" } else { "fail" },
        "failed": failed,
        "checks": checks,
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
    report_for_storage_path_in(run.get("reports")?.as_array()?, storage_path)
}

fn report_for_storage_path_in<'a>(reports: &'a [Value], storage_path: &str) -> Option<&'a Value> {
    reports
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
        "workload": {
            "source_tree": aggregate_object(reports, &["workload", "source_tree"]),
            "restored_tree": aggregate_object(reports, &["workload", "restored_tree"]),
        },
        "backend_metrics": {
            "counts": aggregate_object(reports, &["backend_metrics", "counts"]),
            "by_s3_operation": aggregate_nested_object(reports, &[
                "backend_metrics",
                "by_s3_operation",
            ]),
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
            "request_body_collect_duration_seconds": aggregate_operation_latency_at(reports, &[
                "prometheus_metrics",
                "request_body_collect_duration_seconds",
            ]),
            "request_duration_seconds": aggregate_operation_latency_at(reports, &[
                "prometheus_metrics",
                "request_duration_seconds",
            ]),
            "storage_provider": {
                "counts_by_operation": aggregate_number_object(reports, &[
                    "prometheus_metrics",
                    "storage_provider",
                    "counts_by_operation",
                ]),
                "counts_by_result": aggregate_number_object(reports, &[
                    "prometheus_metrics",
                    "storage_provider",
                    "counts_by_result",
                ]),
                "bytes_sent_by_operation": aggregate_number_object(reports, &[
                    "prometheus_metrics",
                    "storage_provider",
                    "bytes_sent_by_operation",
                ]),
                "bytes_received_by_operation": aggregate_number_object(reports, &[
                    "prometheus_metrics",
                    "storage_provider",
                    "bytes_received_by_operation",
                ]),
                "operation_duration_seconds": aggregate_operation_latency_at(reports, &[
                    "prometheus_metrics",
                    "storage_provider",
                    "operation_duration_seconds",
                ]),
            },
            "repository": {
                "counts_by_operation": aggregate_number_object(reports, &[
                    "prometheus_metrics",
                    "repository",
                    "counts_by_operation",
                ]),
                "counts_by_result": aggregate_number_object(reports, &[
                    "prometheus_metrics",
                    "repository",
                    "counts_by_result",
                ]),
                "plaintext_bytes_by_operation": aggregate_number_object(reports, &[
                    "prometheus_metrics",
                    "repository",
                    "plaintext_bytes_by_operation",
                ]),
                "backend_bytes_written_by_operation": aggregate_number_object(reports, &[
                    "prometheus_metrics",
                    "repository",
                    "backend_bytes_written_by_operation",
                ]),
                "backend_bytes_read_by_range": aggregate_number_object(reports, &[
                    "prometheus_metrics",
                    "repository",
                    "backend_bytes_read_by_range",
                ]),
                "returned_bytes_by_range": aggregate_number_object(reports, &[
                    "prometheus_metrics",
                    "repository",
                    "returned_bytes_by_range",
                ]),
                "payload_span_cache_events_by_result": aggregate_number_object(reports, &[
                    "prometheus_metrics",
                    "repository",
                    "payload_span_cache_events_by_result",
                ]),
                "payload_span_cache_bytes_by_result": aggregate_number_object(reports, &[
                    "prometheus_metrics",
                    "repository",
                    "payload_span_cache_bytes_by_result",
                ]),
                "list_lookup_tokens_by_prefix_mode": aggregate_number_object(reports, &[
                    "prometheus_metrics",
                    "repository",
                    "list_lookup_tokens_by_prefix_mode",
                ]),
                "list_candidates_by_prefix_mode": aggregate_number_object(reports, &[
                    "prometheus_metrics",
                    "repository",
                    "list_candidates_by_prefix_mode",
                ]),
                "list_manifest_misses_by_prefix_mode": aggregate_number_object(reports, &[
                    "prometheus_metrics",
                    "repository",
                    "list_manifest_misses_by_prefix_mode",
                ]),
                "list_prefix_misses_by_prefix_mode": aggregate_number_object(reports, &[
                    "prometheus_metrics",
                    "repository",
                    "list_prefix_misses_by_prefix_mode",
                ]),
                "list_returned_by_prefix_mode": aggregate_number_object(reports, &[
                    "prometheus_metrics",
                    "repository",
                    "list_returned_by_prefix_mode",
                ]),
                "operation_duration_seconds": aggregate_operation_latency_at(reports, &[
                    "prometheus_metrics",
                    "repository",
                    "operation_duration_seconds",
                ]),
                "commit": {
                    "enqueues_by_result": aggregate_number_object(reports, &[
                        "prometheus_metrics",
                        "repository",
                        "commit",
                        "enqueues_by_result",
                    ]),
                    "enqueue_pending_items_by_result": aggregate_number_object(reports, &[
                        "prometheus_metrics",
                        "repository",
                        "commit",
                        "enqueue_pending_items_by_result",
                    ]),
                    "batch_publishes_by_result": aggregate_number_object(reports, &[
                        "prometheus_metrics",
                        "repository",
                        "commit",
                        "batch_publishes_by_result",
                    ]),
                    "batch_waiters_by_result": aggregate_number_object(reports, &[
                        "prometheus_metrics",
                        "repository",
                        "commit",
                        "batch_waiters_by_result",
                    ]),
                    "batch_publish_duration_seconds_by_result": aggregate_operation_latency_at(reports, &[
                        "prometheus_metrics",
                        "repository",
                        "commit",
                        "batch_publish_duration_seconds_by_result",
                    ]),
                    "put_phase_duration_seconds_by_phase": aggregate_operation_latency_at(reports, &[
                        "prometheus_metrics",
                        "repository",
                        "commit",
                        "put_phase_duration_seconds_by_phase",
                    ]),
                },
            },
        },
        "gateway_process": {
            "cpu_system_seconds": aggregate_f64_at(reports, &["gateway_process", "cpu_system_seconds"]),
            "cpu_total_seconds": aggregate_f64_at(reports, &["gateway_process", "cpu_total_seconds"]),
            "cpu_user_seconds": aggregate_f64_at(reports, &["gateway_process", "cpu_user_seconds"]),
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

fn push_phase_elapsed_ratios(
    ratios: &mut BTreeMap<String, Vec<f64>>,
    direct: &Value,
    gateway: &Value,
) {
    let direct_timings = phase_timings_map(direct);
    let gateway_timings = phase_timings_map(gateway);
    for (phase, gateway_elapsed_ms) in gateway_timings {
        let Some(direct_elapsed_ms) = direct_timings.get(&phase).copied() else {
            continue;
        };
        if direct_elapsed_ms == 0 {
            continue;
        }
        ratios
            .entry(phase)
            .or_default()
            .push(gateway_elapsed_ms as f64 / direct_elapsed_ms as f64);
    }
}

fn phase_timings_map(report: &Value) -> BTreeMap<String, u64> {
    let mut timings = BTreeMap::new();
    let Some(phases) = report.get("phase_timings").and_then(Value::as_array) else {
        return timings;
    };
    for phase in phases {
        let Some(name) = phase.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(elapsed_ms) = phase.get("elapsed_ms").and_then(Value::as_u64) else {
            continue;
        };
        timings.insert(name.to_owned(), elapsed_ms);
    }
    timings
}

fn push_gateway_commit_phase_averages(phases: &mut BTreeMap<String, Vec<f64>>, gateway: &Value) {
    let Some(phase_values) = value_at(
        gateway,
        &[
            "prometheus_metrics",
            "repository",
            "commit",
            "put_phase_duration_seconds_by_phase",
        ],
    )
    .and_then(Value::as_object) else {
        return;
    };

    for (phase, value) in phase_values {
        let Some(avg) = value.get("avg").and_then(Value::as_f64) else {
            continue;
        };
        phases.entry(phase.clone()).or_default().push(avg);
    }
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

fn aggregate_nested_object(reports: &[&Value], path: &[&str]) -> Value {
    let mut values_by_outer_key: BTreeMap<String, BTreeMap<String, Vec<u64>>> = BTreeMap::new();
    for report in reports {
        let Some(object) = value_at(report, path).and_then(Value::as_object) else {
            continue;
        };
        for (outer_key, nested) in object {
            let Some(nested) = nested.as_object() else {
                continue;
            };
            let values_by_inner_key = values_by_outer_key.entry(outer_key.clone()).or_default();
            for (inner_key, value) in nested {
                if let Some(value) = value.as_u64() {
                    values_by_inner_key
                        .entry(inner_key.clone())
                        .or_default()
                        .push(value);
                }
            }
        }
    }

    Value::Object(
        values_by_outer_key
            .into_iter()
            .map(|(outer_key, values_by_inner_key)| {
                (
                    outer_key,
                    Value::Object(
                        values_by_inner_key
                            .into_iter()
                            .map(|(inner_key, values)| (inner_key, summarize_u64(&values)))
                            .collect(),
                    ),
                )
            })
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

fn aggregate_f64_at(reports: &[&Value], path: &[&str]) -> Value {
    let values = reports
        .iter()
        .filter_map(|report| value_at(report, path)?.as_f64())
        .collect::<Vec<_>>();
    summarize_f64(&values)
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

fn summarize_ratio_map(ratios: &BTreeMap<String, Vec<f64>>) -> Value {
    Value::Object(
        ratios
            .iter()
            .map(|(name, values)| (name.clone(), summarize_f64(values)))
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
        "set_legal_hold",
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

fn value_f64_at(value: &Value, path: &[&str]) -> Option<f64> {
    value_at(value, path)?.as_f64()
}

fn push_tree_consistency_check(
    checks: &mut Vec<Value>,
    profile: &str,
    run_index: u64,
    metric: &'static str,
    left: &Value,
    left_path: &[&str],
    right: &Value,
    right_path: &[&str],
) {
    let left = value_at(left, left_path);
    let right = value_at(right, right_path);
    checks.push(serde_json::json!({
        "profile": profile,
        "run": run_index,
        "metric": metric,
        "status": if left.is_some() && left == right { "pass" } else { "fail" },
        "reason": if left.is_none() || right.is_none() {
            Some("tree stats unavailable")
        } else if left != right {
            Some("tree stats differ")
        } else {
            None
        },
    }));
}

fn push_consistency_failure(
    checks: &mut Vec<Value>,
    profile: &str,
    run_index: u64,
    metric: &'static str,
    reason: &'static str,
) {
    checks.push(serde_json::json!({
        "profile": profile,
        "run": run_index,
        "metric": metric,
        "status": "fail",
        "reason": reason,
    }));
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

fn push_f64_ratio(ratios: &mut Vec<f64>, numerator: Option<f64>, denominator: Option<f64>) {
    let Some(numerator) = numerator else {
        return;
    };
    let Some(denominator) = denominator else {
        return;
    };
    if denominator == 0.0 {
        return;
    }
    ratios.push(numerator / denominator);
}

fn push_share(ratios: &mut Vec<f64>, numerator: Option<f64>, other: Option<f64>) {
    let (numerator, other) = match (numerator, other) {
        (Some(numerator), Some(other)) => (numerator, other),
        (Some(numerator), None) => (numerator, 0.0),
        (None, Some(other)) => (0.0, other),
        (None, None) => return,
    };
    let denominator = numerator + other;
    if denominator == 0.0 {
        return;
    }
    ratios.push(numerator / denominator);
}

#[cfg(test)]
mod tests {
    use super::{aggregate_runs, compare_runs, workload_consistency_json};

    #[test]
    fn compares_gateway_and_direct_run_ratios() {
        let runs = vec![serde_json::json!({
            "run": 1,
            "reports": [
                {
                    "storage_path": "direct-rustfs",
                    "elapsed_ms": 100,
                    "phase_timings": [
                        { "name": "repository-create", "elapsed_ms": 30 },
                        { "name": "restore", "elapsed_ms": 50 }
                    ],
                    "workload": {
                        "source_tree": {
                            "files": 4,
                            "directories": 1,
                            "bytes": 2048,
                            "largest_file_bytes": 1024
                        },
                        "restored_tree": {
                            "files": 4,
                            "directories": 1,
                            "bytes": 2048,
                            "largest_file_bytes": 1024
                        }
                    },
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
                    "phase_timings": [
                        { "name": "repository-create", "elapsed_ms": 45 },
                        { "name": "restore", "elapsed_ms": 60 }
                    ],
                    "workload": {
                        "source_tree": {
                            "files": 4,
                            "directories": 1,
                            "bytes": 2048,
                            "largest_file_bytes": 1024
                        },
                        "restored_tree": {
                            "files": 4,
                            "directories": 1,
                            "bytes": 2048,
                            "largest_file_bytes": 1024
                        }
                    },
                    "gateway_process": {
                        "cpu_system_seconds": 0.25,
                        "cpu_total_seconds": 1.5,
                        "cpu_user_seconds": 1.25,
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
                            "set_legal_hold": 0,
                            "bytes_written": 1250,
                            "bytes_read": 3000,
                        },
                        "by_s3_operation": {
                            "PutObject": {
                                "put": 12,
                                "bytes_written": 1250
                            },
                            "GetObject": {
                                "get": 3,
                                "bytes_read": 3000
                            }
                        }
                    },
                    "client_metrics": {
                        "counts_by_operation": {
                            "PutObject": 4,
                            "GetObject": 6,
                        }
                    },
                    "prometheus_metrics": {
                        "request_body_bytes_by_operation": {
                            "PutObject": 500
                        },
                        "response_body_bytes_by_operation": {
                            "GetObject": 1000
                        },
                        "request_body_collect_duration_seconds": {
                            "PutObject": {
                                "count": 4.0,
                                "sum": 0.08,
                                "avg": 0.02
                            }
                        },
                        "repository": {
                            "payload_span_cache_events_by_result": {
                                "hit": 6,
                                "miss": 2
                            },
                            "payload_span_cache_bytes_by_result": {
                                "hit": 1200,
                                "miss": 300
                            },
                            "commit": {
                                "put_phase_duration_seconds_by_phase": {
                                    "stage_lock_wait": {
                                        "count": 4.0,
                                        "sum": 0.12,
                                        "avg": 0.03
                                    }
                                }
                            }
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
            comparison["gateway_vs_direct"]["phase_elapsed_ms_ratio"]["restore"]["avg"],
            serde_json::json!(1.2)
        );
        assert_eq!(
            comparison["gateway_vs_direct"]["phase_elapsed_ms_ratio"]["restore"]["samples"],
            serde_json::json!(1)
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
        assert_eq!(
            comparison["gateway_internal"]["backend_read_bytes_per_client_get_response_byte"]["avg"],
            serde_json::json!(3.0)
        );
        assert_eq!(
            comparison["gateway_internal"]["backend_write_bytes_per_client_put_request_byte"]["avg"],
            serde_json::json!(2.5)
        );
        assert_eq!(
            comparison["gateway_internal"]["payload_span_cache_event_hit_ratio"]["avg"],
            serde_json::json!(0.75)
        );
        assert_eq!(
            comparison["gateway_internal"]["payload_span_cache_byte_hit_ratio"]["avg"],
            serde_json::json!(0.8)
        );
        assert_eq!(
            comparison["gateway_internal"]["commit_put_phase_avg_seconds"]["stage_lock_wait"]["avg"],
            serde_json::json!(0.03)
        );

        let aggregate = aggregate_runs(&runs);
        assert_eq!(
            aggregate["gateway"]["gateway_process"]["vm_hwm_bytes"]["avg"],
            serde_json::json!(4096.0)
        );
        assert_eq!(
            aggregate["gateway"]["phase_timings"]["restore"]["p50"],
            serde_json::json!(60)
        );
        assert_eq!(
            aggregate["gateway"]["workload"]["source_tree"]["files"]["avg"],
            serde_json::json!(4.0)
        );
        assert_eq!(
            aggregate["gateway"]["workload"]["restored_tree"]["bytes"]["avg"],
            serde_json::json!(2048.0)
        );
        assert_eq!(
            aggregate["gateway"]["gateway_process"]["vm_rss_bytes"]["avg"],
            serde_json::json!(2048.0)
        );
        assert_eq!(
            aggregate["gateway"]["gateway_process"]["cpu_user_seconds"]["avg"],
            serde_json::json!(1.25)
        );
        assert_eq!(
            aggregate["gateway"]["gateway_process"]["cpu_system_seconds"]["avg"],
            serde_json::json!(0.25)
        );
        assert_eq!(
            aggregate["gateway"]["gateway_process"]["cpu_total_seconds"]["avg"],
            serde_json::json!(1.5)
        );
        assert_eq!(
            aggregate["gateway"]["backend_metrics"]["by_s3_operation"]["PutObject"]["put"]["avg"],
            serde_json::json!(12.0)
        );
        assert_eq!(
            aggregate["gateway"]["backend_metrics"]["by_s3_operation"]["GetObject"]["bytes_read"]["avg"],
            serde_json::json!(3000.0)
        );
        assert_eq!(
            aggregate["gateway"]["prometheus_metrics"]["request_body_collect_duration_seconds"]["PutObject"]
                ["avg"]["avg"],
            serde_json::json!(0.02)
        );
        assert_eq!(
            aggregate["gateway"]["prometheus_metrics"]["repository"]["commit"]["put_phase_duration_seconds_by_phase"]
                ["stage_lock_wait"]["avg"]["avg"],
            serde_json::json!(0.03)
        );
    }

    #[test]
    fn cache_hit_ratios_treat_missing_hit_series_as_zero() {
        let runs = vec![serde_json::json!({
            "run": 1,
            "reports": [
                {
                    "storage_path": "direct-rustfs",
                    "backend_metrics": {
                        "counts": {
                            "requests": 1
                        }
                    }
                },
                {
                    "storage_path": "gateway",
                    "backend_metrics": {
                        "counts": {}
                    },
                    "client_metrics": {
                        "counts_by_operation": {}
                    },
                    "prometheus_metrics": {
                        "repository": {
                            "payload_span_cache_events_by_result": {
                                "miss": 4
                            },
                            "payload_span_cache_bytes_by_result": {
                                "miss": 2048
                            }
                        }
                    }
                }
            ]
        })];

        let comparison = compare_runs(&runs);

        assert_eq!(
            comparison["gateway_internal"]["payload_span_cache_event_hit_ratio"]["avg"],
            serde_json::json!(0.0)
        );
        assert_eq!(
            comparison["gateway_internal"]["payload_span_cache_byte_hit_ratio"]["avg"],
            serde_json::json!(0.0)
        );
    }

    #[test]
    fn ratio_summaries_include_repeated_run_variability() {
        let runs = vec![
            serde_json::json!({
                "run": 1,
                "reports": [
                    {
                        "storage_path": "direct-rustfs",
                        "backend_metrics": {
                            "counts": {
                                "requests": 10,
                                "bytes_read": 1000
                            }
                        }
                    },
                    {
                        "storage_path": "gateway",
                        "backend_metrics": {
                            "counts": {
                                "get": 10,
                                "bytes_read": 1000
                            }
                        },
                        "client_metrics": {
                            "counts_by_operation": {
                                "GetObject": 10
                            }
                        }
                    }
                ]
            }),
            serde_json::json!({
                "run": 2,
                "reports": [
                    {
                        "storage_path": "direct-rustfs",
                        "backend_metrics": {
                            "counts": {
                                "requests": 10,
                                "bytes_read": 1000
                            }
                        }
                    },
                    {
                        "storage_path": "gateway",
                        "backend_metrics": {
                            "counts": {
                                "get": 10,
                                "bytes_read": 1500
                            }
                        },
                        "client_metrics": {
                            "counts_by_operation": {
                                "GetObject": 10
                            }
                        }
                    }
                ]
            }),
        ];

        let comparison = compare_runs(&runs);
        let read_ratio = &comparison["gateway_vs_direct"]["backend_read_bytes_ratio"];

        assert_eq!(read_ratio["samples"], serde_json::json!(2));
        assert_eq!(read_ratio["avg"], serde_json::json!(1.25));
        assert_eq!(read_ratio["spread"], serde_json::json!(0.5));
        assert_eq!(read_ratio["relative_stddev"], serde_json::json!(0.2));
    }

    #[test]
    fn workload_consistency_requires_matching_direct_and_gateway_tree_stats() {
        let source_tree = serde_json::json!({
            "files": 3,
            "directories": 1,
            "bytes": 128,
            "largest_file_bytes": 120,
        });
        let runs = vec![serde_json::json!({
            "profile": "kubernetes-objects-large",
            "run": 1,
            "reports": [
                {
                    "storage_path": "direct-rustfs",
                    "workload": {
                        "source_tree": source_tree.clone(),
                        "restored_tree": source_tree.clone(),
                    }
                },
                {
                    "storage_path": "gateway",
                    "workload": {
                        "source_tree": source_tree.clone(),
                        "restored_tree": source_tree.clone(),
                    }
                }
            ]
        })];

        let consistency = workload_consistency_json(&runs);

        assert_eq!(consistency["status"], serde_json::json!("pass"));
        assert_eq!(consistency["failed"], serde_json::json!(0));
        assert_eq!(consistency["checks"].as_array().map(Vec::len), Some(4));
    }

    #[test]
    fn workload_consistency_fails_when_gateway_tree_differs() {
        let direct_tree = serde_json::json!({
            "files": 3,
            "directories": 1,
            "bytes": 128,
            "largest_file_bytes": 120,
        });
        let gateway_tree = serde_json::json!({
            "files": 4,
            "directories": 1,
            "bytes": 128,
            "largest_file_bytes": 120,
        });
        let runs = vec![serde_json::json!({
            "profile": "postgres-pgdata-large",
            "run": 1,
            "reports": [
                {
                    "storage_path": "direct-rustfs",
                    "workload": {
                        "source_tree": direct_tree.clone(),
                        "restored_tree": direct_tree.clone(),
                    }
                },
                {
                    "storage_path": "gateway",
                    "workload": {
                        "source_tree": gateway_tree.clone(),
                        "restored_tree": gateway_tree.clone(),
                    }
                }
            ]
        })];

        let consistency = workload_consistency_json(&runs);

        assert_eq!(consistency["status"], serde_json::json!("fail"));
        assert_eq!(consistency["failed"], serde_json::json!(2));
    }
}
