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
    run_provider_report_binary(std::path::Path::new(env!("CARGO_BIN_EXE_rs3-server")), args)
}

fn run_provider_report_binary(binary: &std::path::Path, args: &[&str]) -> CliOutput {
    let output = Command::new(binary)
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

    assert_eq!(report["schema"], "rs3.v2-provider-conformance.v5");
    assert_eq!(
        report["target_fingerprint"].as_str().map(str::len),
        Some(64)
    );
    assert_eq!(
        report["implementation_fingerprint"].as_str().map(str::len),
        Some(64)
    );
    assert_eq!(report["retention"], Value::Null);
    assert_eq!(report["passed"], true);
}

#[cfg(target_os = "linux")]
#[test]
fn reports_distinguish_executable_bytes_with_the_same_source_revision() {
    use std::fs;
    use std::io::{Read, Write};
    struct Fixture(std::path::PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let directory =
        std::env::temp_dir().join(format!("rs3-evidence-executable-{}", std::process::id()));
    fs::create_dir(&directory).expect("create owned fixture directory");
    let fixture = Fixture(directory);
    let copied = fixture.0.join("rs3-server");
    fs::copy(env!("CARGO_BIN_EXE_rs3-server"), &copied).expect("copy executable");
    // ELF permits a trailing byte; execution and embedded Git revision remain
    // identical while the concrete artifact bytes differ.
    fs::OpenOptions::new()
        .append(true)
        .open(&copied)
        .expect("open copy")
        .write_all(&[0])
        .expect("append fixture byte");
    let args = ["check-v2-provider", "--format", "json"];
    let first: Value =
        serde_json::from_str(&run_provider_report(&args).stdout).expect("first report");
    let second: Value = serde_json::from_str(&run_provider_report_binary(&copied, &args).stdout)
        .expect("second report");
    assert_eq!(first["source_revision"], second["source_revision"]);
    assert_eq!(first["target_fingerprint"], second["target_fingerprint"]);
    assert_ne!(
        first["implementation_fingerprint"],
        second["implementation_fingerprint"]
    );
    let mut file = fs::File::open(copied).expect("copy");
    let mut digest = rs3_crypto::Sha256Hasher::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let len = file.read(&mut buffer).expect("read executable");
        if len == 0 {
            break;
        }
        digest.update(&buffer[..len]);
    }
    assert_eq!(
        second["implementation_fingerprint"],
        hex::encode(digest.finalize())
    );
}
