//! Log-derived metrics for Kopia integration runs.

use super::common::{
    bump_count, json_field_str, json_field_u64, json_field_u64_opt, parse_log_json,
    summarize_latency_us,
};
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) fn gateway_backend_metrics_json(logs: &[String]) -> Value {
    let counts = parse_gateway_backend_counts(logs);
    serde_json::json!({
        "source": "gateway-storage-logs",
        "counts": backend_counts_json(&counts),
        "by_s3_operation": parse_gateway_backend_counts_by_s3_operation(logs),
        "operation_latency_us": parse_gateway_backend_latency(logs),
    })
}

pub(crate) fn gateway_client_metrics_json(logs: &[String]) -> Value {
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

pub(crate) fn storage_proxy_metrics_json(logs: &[String]) -> Option<Value> {
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
        bump_gateway_backend_counts(fields, &mut counts);
    }
    counts
}

fn parse_gateway_backend_counts_by_s3_operation(logs: &[String]) -> Value {
    let mut by_s3_operation: BTreeMap<String, rs3_storage::BlobOperationCounts> = BTreeMap::new();
    for line in logs {
        let Some(value) = parse_log_json(line) else {
            continue;
        };
        let fields = value.get("fields").unwrap_or(&value);
        if json_field_str(fields, "provider") != Some("s3") {
            continue;
        }
        let Some(s3_operation) = s3_request_span_operation(&value) else {
            continue;
        };
        bump_gateway_backend_counts(
            fields,
            by_s3_operation.entry(s3_operation.to_owned()).or_default(),
        );
    }

    Value::Object(
        by_s3_operation
            .into_iter()
            .map(|(operation, counts)| (operation, backend_counts_json(&counts)))
            .collect(),
    )
}

fn bump_gateway_backend_counts(fields: &Value, counts: &mut rs3_storage::BlobOperationCounts) {
    let Some(operation) = json_field_str(fields, "operation") else {
        return;
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
        "set_legal_hold" => {
            counts.set_legal_hold = counts.set_legal_hold.saturating_add(1);
        }
        _ => return,
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

fn s3_request_span_operation(value: &Value) -> Option<&str> {
    value
        .get("spans")
        .and_then(Value::as_array)
        .and_then(|spans| {
            spans
                .iter()
                .rev()
                .find(|span| json_field_str(span, "name") == Some("s3_request"))
        })
        .or_else(|| {
            value
                .get("span")
                .filter(|span| json_field_str(span, "name") == Some("s3_request"))
        })
        .and_then(|span| json_field_str(span, "operation"))
}

fn backend_counts_json(counts: &rs3_storage::BlobOperationCounts) -> Value {
    serde_json::json!({
        "put": counts.put,
        "get": counts.get,
        "head": counts.head,
        "list": counts.list,
        "delete": counts.delete,
        "extend_retention": counts.extend_retention,
        "set_legal_hold": counts.set_legal_hold,
        "bytes_written": counts.bytes_written,
        "bytes_read": counts.bytes_read,
    })
}

#[cfg(test)]
mod tests {
    use super::{gateway_backend_metrics_json, gateway_client_metrics_json};

    #[test]
    fn gateway_metrics_include_operation_latency() {
        let logs = vec![
            r#"{"target":"rs3_storage","spans":[{"name":"s3_request","operation":"PutObject","request_id":7}],"fields":{"provider":"s3","operation":"put","result":"ok","bytes_sent":12,"bytes_received":0,"elapsed_us":100}}"#.to_owned(),
            r#"{"target":"rs3_storage","span":{"name":"s3_request","operation":"PutObject","request_id":7},"fields":{"provider":"s3","operation":"put","result":"ok","bytes_sent":7,"bytes_received":0,"elapsed_us":"300"}}"#.to_owned(),
            r#"{"target":"rs3_storage","spans":[{"name":"s3_request","operation":"GetObject","request_id":8}],"fields":{"provider":"s3","operation":"get","result":"ok","bytes_sent":0,"bytes_received":5,"elapsed_us":200}}"#.to_owned(),
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
        assert_eq!(metrics["by_s3_operation"]["PutObject"]["put"], 2);
        assert_eq!(metrics["by_s3_operation"]["PutObject"]["bytes_written"], 19);
        assert_eq!(metrics["by_s3_operation"]["GetObject"]["get"], 1);
        assert_eq!(metrics["by_s3_operation"]["GetObject"]["bytes_read"], 5);
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
