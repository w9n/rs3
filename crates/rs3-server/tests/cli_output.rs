//! CLI stdout/stderr contract tests.

use serde_json::Value;
use std::process::{Command, Output};

const PROVIDER_CHECK_LOG_MESSAGE: &str = "v2 provider check configuration validated";

#[test]
fn json_reports_are_not_polluted_by_plain_tracing_logs() {
    let output = run_provider_report(&["check-v2-provider", "--format", "json"]);
    assert_provider_report_stdout(&output.stdout);
    assert!(!output.stdout.contains(PROVIDER_CHECK_LOG_MESSAGE));
    assert!(output.stderr.contains(PROVIDER_CHECK_LOG_MESSAGE));
}

#[test]
fn json_reports_are_not_polluted_by_json_tracing_logs() {
    let output = run_provider_report(&[
        "--log-format",
        "json",
        "check-v2-provider",
        "--format",
        "json",
    ]);
    assert_provider_report_stdout(&output.stdout);
    assert!(!output.stdout.contains(PROVIDER_CHECK_LOG_MESSAGE));
    assert!(output.stderr.contains(PROVIDER_CHECK_LOG_MESSAGE));
}

struct CliOutput {
    stdout: String,
    stderr: String,
}

fn run_provider_report(args: &[&str]) -> CliOutput {
    let output = Command::new(env!("CARGO_BIN_EXE_rs3-server"))
        .args(args)
        .env_clear()
        .env("RUST_LOG", "info")
        .env("RS3_BACKEND_ENDPOINT", "memory://local")
        .env("RS3_BACKEND_BUCKET", "backend-bucket")
        .output()
        .unwrap_or_else(|error| panic!("failed to run rs3-server: {error}"));

    let Output {
        status,
        stdout,
        stderr,
    } = output;
    let stdout =
        String::from_utf8(stdout).unwrap_or_else(|error| panic!("stdout is not UTF-8: {error}"));
    let stderr =
        String::from_utf8(stderr).unwrap_or_else(|error| panic!("stderr is not UTF-8: {error}"));
    assert!(
        status.success(),
        "rs3-server failed with {status}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    CliOutput { stdout, stderr }
}

fn assert_provider_report_stdout(stdout: &str) {
    let report = serde_json::from_str::<Value>(stdout)
        .unwrap_or_else(|error| panic!("stdout is not a JSON report: {error}\n{stdout}"));

    assert_eq!(report["schema"], "rs3.v2-provider-conformance.v2");
    assert_eq!(
        report["target_fingerprint"].as_str().map(str::len),
        Some(64)
    );
    assert_eq!(report["passed"], true);
}
