use serde_json::Value;

pub(super) fn regression_budgets_json(
    profile_summaries: &Value,
    payload_segment_size: Option<usize>,
) -> Value {
    let mut checks = Vec::new();
    let Some(profiles) = profile_summaries.as_object() else {
        return serde_json::json!({
            "status": "missing",
            "failed": 1,
            "checks": [{
                "profile": "",
                "metric": "profiles",
                "operator": "present",
                "status": "fail",
                "reason": "profile summaries were not an object",
            }],
        });
    };

    for (profile, summary) in profiles {
        add_common_budget_checks(profile, summary, &mut checks);
        match profile.as_str() {
            "many-small-files"
                if payload_segment_size.unwrap_or(rs3_repository::DEFAULT_PAYLOAD_SEGMENT_SIZE)
                    <= 512 =>
            {
                push_max_budget(
                    &mut checks,
                    profile,
                    summary,
                    "gateway_vs_direct.backend_request_count_ratio",
                    &[
                        "comparison",
                        "gateway_vs_direct",
                        "backend_request_count_ratio",
                        "avg",
                    ],
                    0.50,
                );
                push_max_budget(
                    &mut checks,
                    profile,
                    summary,
                    "gateway_vs_direct.backend_read_bytes_ratio",
                    &[
                        "comparison",
                        "gateway_vs_direct",
                        "backend_read_bytes_ratio",
                        "avg",
                    ],
                    2.00,
                );
                push_max_budget(
                    &mut checks,
                    profile,
                    summary,
                    "gateway_vs_direct.backend_write_bytes_ratio",
                    &[
                        "comparison",
                        "gateway_vs_direct",
                        "backend_write_bytes_ratio",
                        "avg",
                    ],
                    2.25,
                );
            }
            _ => {}
        }
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

fn add_common_budget_checks(profile: &str, summary: &Value, checks: &mut Vec<Value>) {
    match profile {
        "small-smoke" | "changed-snapshot" => {
            push_max_budget(
                checks,
                profile,
                summary,
                "gateway_vs_direct.backend_request_count_ratio",
                &[
                    "comparison",
                    "gateway_vs_direct",
                    "backend_request_count_ratio",
                    "avg",
                ],
                0.90,
            );
            push_max_budget(
                checks,
                profile,
                summary,
                "gateway_vs_direct.backend_read_bytes_ratio",
                &[
                    "comparison",
                    "gateway_vs_direct",
                    "backend_read_bytes_ratio",
                    "avg",
                ],
                1.10,
            );
            push_max_budget(
                checks,
                profile,
                summary,
                "gateway_vs_direct.backend_write_bytes_ratio",
                &[
                    "comparison",
                    "gateway_vs_direct",
                    "backend_write_bytes_ratio",
                    "avg",
                ],
                1.20,
            );
        }
        "medium-restore"
        | "kubernetes-objects"
        | "kubernetes-objects-large"
        | "postgres-pgdata"
        | "postgres-pgdata-large" => {
            push_max_budget(
                checks,
                profile,
                summary,
                "gateway_vs_direct.backend_request_count_ratio",
                &[
                    "comparison",
                    "gateway_vs_direct",
                    "backend_request_count_ratio",
                    "avg",
                ],
                1.20,
            );
            push_max_budget(
                checks,
                profile,
                summary,
                "gateway_vs_direct.backend_read_bytes_ratio",
                &[
                    "comparison",
                    "gateway_vs_direct",
                    "backend_read_bytes_ratio",
                    "avg",
                ],
                1.10,
            );
            push_max_budget(
                checks,
                profile,
                summary,
                "gateway_vs_direct.backend_write_bytes_ratio",
                &[
                    "comparison",
                    "gateway_vs_direct",
                    "backend_write_bytes_ratio",
                    "avg",
                ],
                1.10,
            );
            push_max_budget(
                checks,
                profile,
                summary,
                "gateway_vs_direct.phase_elapsed_ms_ratio.restore",
                &[
                    "comparison",
                    "gateway_vs_direct",
                    "phase_elapsed_ms_ratio",
                    "restore",
                    "avg",
                ],
                1.50,
            );
            push_max_budget(
                checks,
                profile,
                summary,
                "gateway_internal.backend_read_bytes_per_client_get_response_byte",
                &[
                    "comparison",
                    "gateway_internal",
                    "backend_read_bytes_per_client_get_response_byte",
                    "avg",
                ],
                1.10,
            );
            push_max_budget(
                checks,
                profile,
                summary,
                "gateway_internal.backend_write_bytes_per_client_put_request_byte",
                &[
                    "comparison",
                    "gateway_internal",
                    "backend_write_bytes_per_client_put_request_byte",
                    "avg",
                ],
                1.10,
            );
            push_optional_max_budget(
                checks,
                profile,
                summary,
                "gateway_vs_direct.backend_request_count_ratio.relative_stddev",
                &[
                    "comparison",
                    "gateway_vs_direct",
                    "backend_request_count_ratio",
                    "relative_stddev",
                ],
                0.05,
            );
            push_optional_max_budget(
                checks,
                profile,
                summary,
                "gateway_vs_direct.backend_read_bytes_ratio.relative_stddev",
                &[
                    "comparison",
                    "gateway_vs_direct",
                    "backend_read_bytes_ratio",
                    "relative_stddev",
                ],
                0.05,
            );
            push_optional_max_budget(
                checks,
                profile,
                summary,
                "gateway_internal.backend_read_bytes_per_client_get_response_byte.relative_stddev",
                &[
                    "comparison",
                    "gateway_internal",
                    "backend_read_bytes_per_client_get_response_byte",
                    "relative_stddev",
                ],
                0.05,
            );
            push_optional_max_budget(
                checks,
                profile,
                summary,
                "gateway_vs_direct.phase_elapsed_ms_ratio.restore.relative_stddev",
                &[
                    "comparison",
                    "gateway_vs_direct",
                    "phase_elapsed_ms_ratio",
                    "restore",
                    "relative_stddev",
                ],
                0.35,
            );
        }
        _ => {}
    }
}

fn push_max_budget(
    checks: &mut Vec<Value>,
    profile: &str,
    summary: &Value,
    metric: &'static str,
    path: &[&str],
    limit: f64,
) {
    push_budget(checks, profile, summary, metric, path, "<=", limit);
}

fn push_optional_max_budget(
    checks: &mut Vec<Value>,
    profile: &str,
    summary: &Value,
    metric: &'static str,
    path: &[&str],
    limit: f64,
) {
    let observed = value_f64_at(summary, path);
    let status = match observed {
        Some(observed) if observed <= limit => "pass",
        Some(_) => "fail",
        None => "skip",
    };
    checks.push(serde_json::json!({
        "profile": profile,
        "metric": metric,
        "operator": "<=",
        "limit": limit,
        "observed_avg": observed,
        "observed": observed,
        "status": status,
        "reason": if observed.is_none() {
            Some("metric unavailable")
        } else {
            None
        },
    }));
}

fn push_budget(
    checks: &mut Vec<Value>,
    profile: &str,
    summary: &Value,
    metric: &'static str,
    path: &[&str],
    operator: &'static str,
    limit: f64,
) {
    let observed = value_f64_at(summary, path);
    let passed = match (operator, observed) {
        ("<=", Some(observed)) => observed <= limit,
        (">=", Some(observed)) => observed >= limit,
        _ => false,
    };
    checks.push(serde_json::json!({
        "profile": profile,
        "metric": metric,
        "operator": operator,
        "limit": limit,
        "observed_avg": observed,
        "observed": observed,
        "status": if observed.is_none() {
            "fail"
        } else if passed {
            "pass"
        } else {
            "fail"
        },
        "reason": if observed.is_none() {
            Some("metric unavailable")
        } else {
            None
        },
    }));
}

pub(super) fn value_f64_at(value: &Value, path: &[&str]) -> Option<f64> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    current.as_f64()
}

#[cfg(test)]
mod tests {
    use super::regression_budgets_json;

    #[test]
    fn larger_restore_budgets_pass_for_close_backend_ratios() {
        let profiles = serde_json::json!({
            "postgres-pgdata": {
                "comparison": {
                    "gateway_vs_direct": {
                        "backend_request_count_ratio": { "avg": 1.00 },
                        "backend_read_bytes_ratio": { "avg": 1.04 },
                        "backend_write_bytes_ratio": { "avg": 1.04 },
                        "phase_elapsed_ms_ratio": {
                            "restore": { "avg": 1.04 }
                        }
                    },
                    "gateway_internal": {
                        "backend_read_bytes_per_client_get_response_byte": { "avg": 1.04 },
                        "backend_write_bytes_per_client_put_request_byte": { "avg": 1.04 }
                    }
                }
            }
        });

        let budgets = regression_budgets_json(&profiles, Some(512));

        assert_eq!(budgets["status"], serde_json::json!("pass"));
        assert_eq!(budgets["failed"], serde_json::json!(0));
    }

    #[test]
    fn larger_restore_budgets_allow_checkpoint_evidence_request_overhead() {
        let profiles = serde_json::json!({
            "postgres-pgdata-large": {
                "comparison": {
                    "gateway_vs_direct": {
                        "backend_request_count_ratio": { "avg": 1.16 },
                        "backend_read_bytes_ratio": { "avg": 1.04 },
                        "backend_write_bytes_ratio": { "avg": 1.04 },
                        "phase_elapsed_ms_ratio": {
                            "restore": { "avg": 1.04 }
                        }
                    },
                    "gateway_internal": {
                        "backend_read_bytes_per_client_get_response_byte": { "avg": 1.04 },
                        "backend_write_bytes_per_client_put_request_byte": { "avg": 1.04 }
                    }
                }
            }
        });

        let budgets = regression_budgets_json(&profiles, Some(512));

        assert_eq!(budgets["status"], serde_json::json!("pass"));
        assert_eq!(budgets["failed"], serde_json::json!(0));
    }

    #[test]
    fn larger_restore_budgets_skip_stability_without_repeated_samples() {
        let profiles = serde_json::json!({
            "kubernetes-objects": {
                "comparison": {
                    "gateway_vs_direct": {
                        "backend_request_count_ratio": {
                            "avg": 1.00,
                            "relative_stddev": null
                        },
                        "backend_read_bytes_ratio": {
                            "avg": 1.04,
                            "relative_stddev": null
                        },
                        "backend_write_bytes_ratio": { "avg": 1.04 },
                        "phase_elapsed_ms_ratio": {
                            "restore": {
                                "avg": 1.04,
                                "relative_stddev": null
                            }
                        }
                    },
                    "gateway_internal": {
                        "backend_read_bytes_per_client_get_response_byte": {
                            "avg": 1.04,
                            "relative_stddev": null
                        },
                        "backend_write_bytes_per_client_put_request_byte": { "avg": 1.04 }
                    }
                }
            }
        });

        let budgets = regression_budgets_json(&profiles, Some(512));

        assert_eq!(budgets["status"], serde_json::json!("pass"));
        assert_eq!(budgets["failed"], serde_json::json!(0));
        assert!(
            budgets["checks"]
                .as_array()
                .unwrap_or_else(|| panic!("checks should be an array"))
                .iter()
                .any(|check| {
                    check["metric"]
                        == serde_json::json!(
                            "gateway_vs_direct.backend_read_bytes_ratio.relative_stddev"
                        )
                        && check["status"] == serde_json::json!("skip")
                })
        );
    }

    #[test]
    fn larger_restore_budgets_fail_unstable_repeated_metrics() {
        let profiles = serde_json::json!({
            "postgres-pgdata": {
                "comparison": {
                    "gateway_vs_direct": {
                        "backend_request_count_ratio": {
                            "avg": 1.00,
                            "relative_stddev": 0.01
                        },
                        "backend_read_bytes_ratio": {
                            "avg": 1.04,
                            "relative_stddev": 0.12
                        },
                        "backend_write_bytes_ratio": { "avg": 1.04 },
                        "phase_elapsed_ms_ratio": {
                            "restore": {
                                "avg": 1.04,
                                "relative_stddev": 0.10
                            }
                        }
                    },
                    "gateway_internal": {
                        "backend_read_bytes_per_client_get_response_byte": {
                            "avg": 1.04,
                            "relative_stddev": 0.02
                        },
                        "backend_write_bytes_per_client_put_request_byte": { "avg": 1.04 }
                    }
                }
            }
        });

        let budgets = regression_budgets_json(&profiles, Some(512));

        assert_eq!(budgets["status"], serde_json::json!("fail"));
        assert_eq!(budgets["failed"], serde_json::json!(1));
        assert!(
            budgets["checks"]
                .as_array()
                .unwrap_or_else(|| panic!("checks should be an array"))
                .iter()
                .any(|check| {
                    check["metric"]
                        == serde_json::json!(
                            "gateway_vs_direct.backend_read_bytes_ratio.relative_stddev"
                        )
                        && check["status"] == serde_json::json!("fail")
                })
        );
    }

    #[test]
    fn many_small_512_budget_enforces_request_and_byte_ratios() {
        let profiles = serde_json::json!({
            "many-small-files": {
                "comparison": {
                    "gateway_vs_direct": {
                        "backend_request_count_ratio": { "avg": 0.31 },
                        "backend_read_bytes_ratio": { "avg": 1.72 },
                        "backend_write_bytes_ratio": { "avg": 2.04 }
                    },
                    "gateway_internal": {
                        "payload_span_cache_event_hit_ratio": { "avg": 0.10 }
                    }
                }
            }
        });

        let budgets = regression_budgets_json(&profiles, Some(512));

        assert_eq!(budgets["status"], serde_json::json!("pass"));
        assert_eq!(budgets["failed"], serde_json::json!(0));
        assert_eq!(
            budgets["checks"]
                .as_array()
                .unwrap_or_else(|| panic!("checks should be an array"))
                .len(),
            3
        );
    }
}
