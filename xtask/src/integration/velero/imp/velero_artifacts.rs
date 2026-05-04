//! Artifact and backend-pressure capture for Velero integration lanes.

use super::{RunState, integration_storage_proxy, kubectl_capture};
use crate::integration::k8s_support::{helm_fullname, now_millis};
use crate::integration::velero::VeleroKopiaSmokeArgs;
use anyhow::{Context, Result};
use rs3_storage::BlobOperationCounts;
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

pub(super) struct ArtifactCollector {
    root: Option<PathBuf>,
}

impl ArtifactCollector {
    pub(super) fn new(args: &VeleroKopiaSmokeArgs, scenario_label: &str) -> Result<Self> {
        if args.skip_artifacts {
            return Ok(Self { root: None });
        }
        let root = args.artifact_dir.clone().unwrap_or_else(|| {
            PathBuf::from(".local")
                .join("integration")
                .join(format!("velero-{scenario_label}-{}", now_millis()))
        });
        fs::create_dir_all(&root)
            .with_context(|| format!("failed to create artifact directory {}", root.display()))?;
        eprintln!("writing Velero integration artifacts to {}", root.display());
        Ok(Self { root: Some(root) })
    }

    pub(super) fn collect(
        &self,
        args: &VeleroKopiaSmokeArgs,
        kubeconfig_path: &Path,
        state: &RunState,
    ) -> Result<()> {
        let Some(root) = &self.root else {
            return Ok(());
        };

        self.write_json(
            "summary.json",
            json!({
                "scenario": state.scenario_label,
                "storage_path": state.storage_path.as_str(),
                "backup": state.backup_name,
                "restore": state.restore_name,
                "elapsed_ms": state.started.elapsed().as_millis(),
                "phase_timings": state.phase_timings.iter().map(|phase| json!({
                    "name": phase.name,
                    "elapsed_ms": phase.elapsed_ms,
                    "status": phase.status,
                })).collect::<Vec<_>>(),
                "anchor_name": state.anchor_name,
                "backend_prefix": state.backend_prefix,
                "gateway_namespace": args.gateway_namespace,
                "workload_namespace": args.workload_namespace,
                "velero_namespace": args.velero_namespace,
                "openebs_namespace": args.openebs_namespace,
            }),
        )?;
        self.capture_kubectl(
            args,
            kubeconfig_path,
            "cluster-overview.txt",
            &["get", "nodes,pods,pvc,pv,storageclass", "-A", "-o", "wide"],
        )?;
        self.capture_kubectl(
            args,
            kubeconfig_path,
            "events.txt",
            &["get", "events", "-A", "--sort-by=.lastTimestamp"],
        )?;
        self.capture_kubectl(
            args,
            kubeconfig_path,
            "velero-resources.yaml",
            &[
                "-n",
                &args.velero_namespace,
                "get",
                "backups.velero.io,restores.velero.io,podvolumebackups.velero.io,podvolumerestores.velero.io,backuprepositories.velero.io,backupstoragelocations.velero.io",
                "-o",
                "yaml",
            ],
        )?;
        self.capture_kubectl(
            args,
            kubeconfig_path,
            "workload-resources.yaml",
            &[
                "-n",
                &args.workload_namespace,
                "get",
                "all,pvc",
                "-o",
                "yaml",
            ],
        )?;
        self.collect_storage_artifacts(args, kubeconfig_path, state, "final")?;
        self.capture_kubectl(
            args,
            kubeconfig_path,
            "velero-log.txt",
            &[
                "-n",
                &args.velero_namespace,
                "logs",
                "deployment/velero",
                "--all-containers=true",
                "--tail=-1",
            ],
        )?;
        self.capture_kubectl(
            args,
            kubeconfig_path,
            "node-agent-log.txt",
            &[
                "-n",
                &args.velero_namespace,
                "logs",
                "daemonset/node-agent",
                "--all-containers=true",
                "--tail=-1",
            ],
        )?;
        self.capture_kubectl(
            args,
            kubeconfig_path,
            "openebs-log.txt",
            &[
                "-n",
                &args.openebs_namespace,
                "logs",
                &format!(
                    "deployment/{}-localpv-provisioner",
                    args.openebs_release_name
                ),
                "--all-containers=true",
                "--tail=-1",
            ],
        )?;

        eprintln!("Velero integration artifacts written to {}", root.display());
        Ok(())
    }

    pub(super) fn collect_checkpoint(
        &self,
        args: &VeleroKopiaSmokeArgs,
        kubeconfig_path: &Path,
        state: &RunState,
        phase: &str,
    ) -> Result<()> {
        let Some(_) = &self.root else {
            return Ok(());
        };
        if !state.storage_path.uses_gateway() {
            return Ok(());
        }

        let phase = sanitize_file_component(phase);
        self.capture_anchor(args, kubeconfig_path, state, &phase)?;
        self.capture_kubectl(
            args,
            kubeconfig_path,
            &format!("gateway-pods-{phase}.yaml"),
            &[
                "-n",
                &args.gateway_namespace,
                "get",
                "pods",
                "-l",
                &gateway_selector(args),
                "-o",
                "yaml",
            ],
        )?;
        let logs = capture_kubectl_output(
            args,
            kubeconfig_path,
            &[
                "-n",
                &args.gateway_namespace,
                "logs",
                "-l",
                &gateway_selector(args),
                "--all-containers=true",
                "--prefix=true",
                "--tail=-1",
            ],
        );
        let logs = self.write_result(&format!("gateway-logs-{phase}.jsonl"), logs)?;
        self.write_json(
            &format!("gateway-backend-metrics-{phase}.json"),
            gateway_backend_metrics_json(&logs),
        )?;
        Ok(())
    }

    fn collect_storage_artifacts(
        &self,
        args: &VeleroKopiaSmokeArgs,
        kubeconfig_path: &Path,
        state: &RunState,
        phase: &str,
    ) -> Result<()> {
        if state.storage_path.uses_gateway() {
            self.capture_kubectl(
                args,
                kubeconfig_path,
                "gateway-pods.yaml",
                &[
                    "-n",
                    &args.gateway_namespace,
                    "get",
                    "pods",
                    "-l",
                    &gateway_selector(args),
                    "-o",
                    "yaml",
                ],
            )?;
            self.capture_kubectl(
                args,
                kubeconfig_path,
                "gateway-deployment.yaml",
                &[
                    "-n",
                    &args.gateway_namespace,
                    "get",
                    &format!("deployment/{}", helm_fullname(&args.release_name)),
                    "-o",
                    "yaml",
                ],
            )?;
            let gateway_logs = capture_kubectl_output(
                args,
                kubeconfig_path,
                &[
                    "-n",
                    &args.gateway_namespace,
                    "logs",
                    &format!("deployment/{}", helm_fullname(&args.release_name)),
                    "--all-containers=true",
                    "--tail=-1",
                ],
            );
            let gateway_logs = self.write_result("gateway-logs.jsonl", gateway_logs)?;
            self.write_json(
                "gateway-backend-metrics.json",
                gateway_backend_metrics_json(&gateway_logs),
            )?;
            self.capture_anchor(args, kubeconfig_path, state, phase)?;
            return Ok(());
        }

        self.capture_kubectl(
            args,
            kubeconfig_path,
            "rustfs-pods.yaml",
            &[
                "-n",
                &args.gateway_namespace,
                "get",
                "pods",
                "-l",
                "app.kubernetes.io/name=rs3-rustfs",
                "-o",
                "yaml",
            ],
        )?;
        self.capture_kubectl(
            args,
            kubeconfig_path,
            "rustfs-log.txt",
            &[
                "-n",
                &args.gateway_namespace,
                "logs",
                "deployment/rs3-rustfs",
                "--all-containers=true",
                "--tail=-1",
            ],
        )?;
        self.capture_kubectl(
            args,
            kubeconfig_path,
            "integration-storage-proxy-pods.yaml",
            &[
                "-n",
                &args.gateway_namespace,
                "get",
                "pods",
                "-l",
                &format!("app.kubernetes.io/name={}", integration_storage_proxy::NAME),
                "-o",
                "yaml",
            ],
        )?;
        let measure_logs = capture_kubectl_output(
            args,
            kubeconfig_path,
            &[
                "-n",
                &args.gateway_namespace,
                "logs",
                &format!("deployment/{}", integration_storage_proxy::NAME),
                "--all-containers=true",
                "--tail=-1",
            ],
        );
        let measure_logs =
            self.write_result("integration-storage-proxy-log.jsonl", measure_logs)?;
        self.write_json(
            "storage-backend-metrics.json",
            integration_storage_proxy_metrics_json(&measure_logs),
        )
    }

    fn capture_anchor(
        &self,
        args: &VeleroKopiaSmokeArgs,
        kubeconfig_path: &Path,
        state: &RunState,
        phase: &str,
    ) -> Result<()> {
        self.capture_kubectl(
            args,
            kubeconfig_path,
            &format!("anchor-{phase}.yaml"),
            &[
                "-n",
                &args.gateway_namespace,
                "get",
                &format!("lease/{}", state.anchor_name),
                "-o",
                "yaml",
            ],
        )
    }

    fn capture_kubectl(
        &self,
        args: &VeleroKopiaSmokeArgs,
        kubeconfig_path: &Path,
        file_name: &str,
        kubectl_args: &[&str],
    ) -> Result<()> {
        self.write_result(
            file_name,
            capture_kubectl_output(args, kubeconfig_path, kubectl_args),
        )?;
        Ok(())
    }

    fn write_result(&self, file_name: &str, result: Result<String>) -> Result<String> {
        let content = match result {
            Ok(output) => output,
            Err(error) => format!("command failed: {error:#}\n"),
        };
        self.write_text(file_name, &content)?;
        Ok(content)
    }

    fn write_json(&self, file_name: &str, value: Value) -> Result<()> {
        let content = serde_json::to_string_pretty(&value).context("failed to encode JSON")?;
        self.write_text(file_name, &format!("{content}\n"))
    }

    fn write_text(&self, file_name: &str, content: &str) -> Result<()> {
        let Some(root) = &self.root else {
            return Ok(());
        };
        let path = root.join(file_name);
        fs::write(&path, content).with_context(|| format!("failed to write {}", path.display()))
    }
}

fn gateway_selector(args: &VeleroKopiaSmokeArgs) -> String {
    format!(
        "app.kubernetes.io/name=rs3-gateway,app.kubernetes.io/instance={}",
        args.release_name
    )
}

fn sanitize_file_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

fn capture_kubectl_output(
    args: &VeleroKopiaSmokeArgs,
    kubeconfig_path: &Path,
    kubectl_args: &[&str],
) -> Result<String> {
    kubectl_capture(&args.kubectl_bin, kubeconfig_path, kubectl_args)
}

fn gateway_backend_metrics_json(logs: &str) -> Value {
    let lines = logs.lines().map(str::to_owned).collect::<Vec<_>>();
    let (counts, operations, object_kinds) = parse_gateway_backend_metrics(&lines);
    let repository = parse_repository_metrics(&lines);
    json!({
        "counts": {
            "put": counts.put,
            "get": counts.get,
            "head": counts.head,
            "list": counts.list,
            "delete": counts.delete,
            "extend_retention": counts.extend_retention,
            "set_legal_hold": counts.set_legal_hold,
            "flush": counts.flush,
            "bytes_written": counts.bytes_written,
            "bytes_read": counts.bytes_read,
        },
        "derived": derived_metrics(&counts, &repository),
        "operations": operations,
        "object_kinds": object_kinds,
        "repository": repository.to_json(),
    })
}

fn integration_storage_proxy_metrics_json(logs: &str) -> Value {
    let mut latest = None;
    for value in logs.lines().filter_map(parse_log_json) {
        if value.get("target").and_then(Value::as_str) == Some("rs3_storage_measure") {
            latest = value.get("fields").cloned();
        }
    }
    let fields = latest.unwrap_or_else(|| json!({}));
    json!({
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
        "methods": fields.get("methods").cloned().unwrap_or_else(|| json!({})),
        "statuses": fields.get("statuses").cloned().unwrap_or_else(|| json!({})),
    })
}

fn parse_gateway_backend_metrics(logs: &[String]) -> (BlobOperationCounts, Value, Value) {
    let mut counts = BlobOperationCounts::default();
    let mut operations = serde_json::Map::new();
    let mut object_kinds = serde_json::Map::new();
    for line in logs {
        let Some(value) = parse_log_json(line) else {
            continue;
        };
        if value.get("target").and_then(Value::as_str) != Some("rs3_storage") {
            continue;
        }
        let fields = value.get("fields").unwrap_or(&value);
        if fields.get("provider").is_none() {
            continue;
        }
        let Some(operation) = json_field_str(fields, "operation") else {
            continue;
        };
        let normalized = normalize_blob_operation(operation);
        increment_blob_counts(&mut counts, normalized, fields);
        increment_operation_metrics(&mut operations, normalized, fields);
        increment_object_kind_metrics(&mut object_kinds, normalized, fields);
    }
    (
        counts,
        Value::Object(operations),
        Value::Object(object_kinds),
    )
}

fn normalize_blob_operation(operation: &str) -> &str {
    match operation {
        "get_range" => "get",
        "list_prefix" => "list",
        "flush_caches" => "flush",
        other => other,
    }
}

fn increment_blob_counts(counts: &mut BlobOperationCounts, operation: &str, fields: &Value) {
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
        "flush" => counts.flush = counts.flush.saturating_add(1),
        _ => {}
    }

    if json_field_str(fields, "result") != Some("ok") {
        return;
    }
    counts.bytes_written = counts
        .bytes_written
        .saturating_add(json_field_u64(fields, "requested_len"))
        .saturating_add(json_field_u64(fields, "bytes_sent"));
    counts.bytes_read = counts
        .bytes_read
        .saturating_add(json_field_u64(fields, "bytes_read"))
        .saturating_add(json_field_u64(fields, "bytes_received"));
}

fn increment_object_kind_metrics(
    object_kinds: &mut serde_json::Map<String, Value>,
    operation: &str,
    fields: &Value,
) {
    let object_kind = json_field_str(fields, "object_kind").unwrap_or("unknown");
    let entry = object_kinds
        .entry(object_kind.to_owned())
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    let Some(operations) = entry.as_object_mut() else {
        return;
    };
    increment_operation_metrics(operations, operation, fields);
}

fn increment_operation_metrics(
    operations: &mut serde_json::Map<String, Value>,
    operation: &str,
    fields: &Value,
) {
    let entry = operations.entry(operation.to_owned()).or_insert_with(|| {
        json!({
            "requests": 0_u64,
            "successes": 0_u64,
            "failures": 0_u64,
            "elapsed_us": 0_u64,
            "max_elapsed_us": 0_u64,
        })
    });
    let Some(map) = entry.as_object_mut() else {
        return;
    };
    bump_json_u64(map, "requests", 1);
    if json_field_str(fields, "result") == Some("ok") {
        bump_json_u64(map, "successes", 1);
    } else {
        bump_json_u64(map, "failures", 1);
    }
    let elapsed = json_field_u64(fields, "elapsed_us");
    bump_json_u64(map, "elapsed_us", elapsed);
    let max_elapsed = map
        .get("max_elapsed_us")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .max(elapsed);
    map.insert("max_elapsed_us".to_owned(), json!(max_elapsed));
}

fn bump_json_u64(map: &mut serde_json::Map<String, Value>, key: &str, add: u64) {
    let next = map
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .saturating_add(add);
    map.insert(key.to_owned(), json!(next));
}

fn json_field_str<'a>(fields: &'a Value, key: &str) -> Option<&'a str> {
    fields.get(key).and_then(Value::as_str)
}

fn json_field_u64(fields: &Value, key: &str) -> u64 {
    fields
        .get(key)
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        })
        .unwrap_or(0)
}

#[derive(Default)]
struct RepositoryMetrics {
    operations: serde_json::Map<String, Value>,
    put_count: u64,
    list_count: u64,
    list_candidate_count: u64,
    list_prefix_miss_count: u64,
    list_returned_count: u64,
    delete_count: u64,
    publish_checkpoint_count: u64,
    client_bytes_written: u64,
    backend_bytes_written_for_puts: u64,
}

impl RepositoryMetrics {
    fn to_json(&self) -> Value {
        json!({
            "put_count": self.put_count,
            "list_count": self.list_count,
            "list_candidate_count": self.list_candidate_count,
            "list_prefix_miss_count": self.list_prefix_miss_count,
            "list_returned_count": self.list_returned_count,
            "delete_count": self.delete_count,
            "publish_checkpoint_count": self.publish_checkpoint_count,
            "client_bytes_written": self.client_bytes_written,
            "backend_bytes_written_for_puts": self.backend_bytes_written_for_puts,
            "operations": self.operations,
        })
    }
}

fn parse_repository_metrics(logs: &[String]) -> RepositoryMetrics {
    let mut metrics = RepositoryMetrics::default();
    for line in logs {
        let Some(value) = parse_log_json(line) else {
            continue;
        };
        if value.get("target").and_then(Value::as_str) != Some("rs3_repository") {
            continue;
        }
        let fields = value.get("fields").unwrap_or(&value);
        let Some(operation) = json_field_str(fields, "operation") else {
            continue;
        };
        increment_operation_metrics(&mut metrics.operations, operation, fields);
        match operation {
            "put" => {
                metrics.put_count = metrics.put_count.saturating_add(1);
                metrics.client_bytes_written = metrics
                    .client_bytes_written
                    .saturating_add(json_field_u64(fields, "plaintext_len"));
                metrics.backend_bytes_written_for_puts = metrics
                    .backend_bytes_written_for_puts
                    .saturating_add(json_field_u64(fields, "backend_len"));
            }
            "list" => {
                metrics.list_count = metrics.list_count.saturating_add(1);
                metrics.list_candidate_count = metrics
                    .list_candidate_count
                    .saturating_add(json_field_u64(fields, "candidate_count"));
                metrics.list_prefix_miss_count = metrics
                    .list_prefix_miss_count
                    .saturating_add(json_field_u64(fields, "prefix_miss_count"));
                metrics.list_returned_count = metrics
                    .list_returned_count
                    .saturating_add(json_field_u64(fields, "returned_count"));
            }
            "delete" => metrics.delete_count = metrics.delete_count.saturating_add(1),
            "publish_checkpoint" => {
                metrics.publish_checkpoint_count =
                    metrics.publish_checkpoint_count.saturating_add(1);
            }
            _ => {}
        }
    }
    metrics
}

fn derived_metrics(counts: &BlobOperationCounts, repository: &RepositoryMetrics) -> Value {
    let backend_requests = counts
        .put
        .saturating_add(counts.get)
        .saturating_add(counts.head)
        .saturating_add(counts.list)
        .saturating_add(counts.delete)
        .saturating_add(counts.extend_retention)
        .saturating_add(counts.set_legal_hold)
        .saturating_add(counts.flush);
    let repository_mutations = repository.put_count.saturating_add(repository.delete_count);

    json!({
        "backend_requests": backend_requests,
        "repository_mutations": repository_mutations,
        "backend_requests_per_repository_mutation": ratio(backend_requests, repository_mutations),
        "backend_puts_per_repository_put": ratio(counts.put, repository.put_count),
        "repository_list_candidates_per_list": ratio(
            repository.list_candidate_count,
            repository.list_count,
        ),
        "repository_list_returned_per_list": ratio(
            repository.list_returned_count,
            repository.list_count,
        ),
        "checkpoint_publishes_per_repository_mutation": ratio(
            repository.publish_checkpoint_count,
            repository_mutations,
        ),
        "backend_bytes_written_per_client_byte": ratio(
            counts.bytes_written,
            repository.client_bytes_written,
        ),
        "repository_backend_bytes_written_per_client_byte": ratio(
            repository.backend_bytes_written_for_puts,
            repository.client_bytes_written,
        ),
    })
}

fn ratio(numerator: u64, denominator: u64) -> Value {
    if denominator == 0 {
        Value::Null
    } else {
        json!(numerator as f64 / denominator as f64)
    }
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

#[cfg(test)]
mod tests {
    use super::{gateway_backend_metrics_json, integration_storage_proxy_metrics_json};

    #[test]
    fn metrics_parse_kubectl_prefixed_json_logs() {
        let metrics = gateway_backend_metrics_json(
            r#"[pod/rs3/gateway] {"target":"rs3_storage","fields":{"provider":"s3","operation":"put","object_kind":"segments","result":"ok","bytes_sent":42,"elapsed_us":7}}
{"target":"rs3_repository","fields":{"operation":"put","result":"ok","plaintext_len":21,"backend_len":42,"elapsed_us":5}}
{"target":"rs3_repository","fields":{"operation":"list","result":"ok","prefix_mode":"fallback","lookup_token_count":1,"candidate_count":7,"prefix_miss_count":5,"returned_count":2,"elapsed_us":3}}
"#,
        );

        assert_eq!(metrics["counts"]["put"], 1);
        assert_eq!(metrics["counts"]["bytes_written"], 42);
        assert_eq!(metrics["repository"]["put_count"], 1);
        assert_eq!(metrics["repository"]["list_count"], 1);
        assert_eq!(metrics["repository"]["list_candidate_count"], 7);
        assert_eq!(metrics["repository"]["list_prefix_miss_count"], 5);
        assert_eq!(metrics["repository"]["list_returned_count"], 2);
        assert_eq!(
            metrics["repository"]["operations"]["list"]["successes"],
            serde_json::json!(1)
        );
        assert_eq!(
            metrics["derived"]["repository_list_candidates_per_list"],
            serde_json::json!(7.0)
        );
        assert_eq!(
            metrics["derived"]["backend_puts_per_repository_put"],
            serde_json::json!(1.0)
        );
    }

    #[test]
    fn metrics_ignore_wrapper_logs_when_provider_log_exists() {
        let metrics = gateway_backend_metrics_json(
            r#"{"target":"rs3_storage","fields":{"operation":"put","object_kind":"segments","result":"ok","requested_len":42,"elapsed_us":7}}
"#,
        );

        assert_eq!(metrics["counts"]["put"], 0);
        assert_eq!(metrics["counts"]["bytes_written"], 0);
    }

    #[test]
    fn metrics_parse_integration_storage_proxy_latest_log() {
        let metrics = integration_storage_proxy_metrics_json(
            r#"{"target":"rs3_storage_measure","fields":{"requests":1,"responses":1,"request_body_bytes":10,"response_body_bytes":20,"bytes_to_backend":100,"bytes_from_backend":200,"accepted_connections":1,"active_connections":1,"failed_connections":0,"methods":{"PUT":1},"statuses":{"200":1}}}
{"target":"rs3_storage_measure","fields":{"requests":2,"responses":2,"request_body_bytes":30,"response_body_bytes":40,"bytes_to_backend":300,"bytes_from_backend":400,"accepted_connections":1,"active_connections":0,"failed_connections":0,"methods":{"PUT":1,"GET":1},"statuses":{"200":2}}}
"#,
        );

        assert_eq!(metrics["counts"]["requests"], 2);
        assert_eq!(metrics["counts"]["bytes_written"], 30);
        assert_eq!(metrics["counts"]["bytes_read"], 40);
        assert_eq!(metrics["transport"]["bytes_to_backend"], 300);
        assert_eq!(metrics["methods"]["GET"], 1);
        assert_eq!(metrics["statuses"]["200"], 2);
    }
}
