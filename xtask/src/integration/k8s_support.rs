//! Shared Kubernetes integration helpers.

use anyhow::{Context, Result, bail};
use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;

pub(crate) const ACCESS_KEY_ID: &str = "rs3-fixture-access-key";
pub(crate) const ADMIN_BEARER_TOKEN: &str = "rs3-fixture-admin-token-12345";
pub(crate) const CHART_NAME: &str = "rs3-gateway";
pub(crate) const CHART_PATH: &str = "charts/rs3-gateway";
pub(crate) const DEFAULT_PUBLIC_BUCKET: &str = "client-bucket";
pub(crate) const GATEWAY_PORT: u16 = 9080;
pub(crate) const KEYRING_ENVELOPE_OBJECT_ID: &str = "keyrings/bootstrap-envelope.cbor";
pub(crate) const KEYRING_WRAPPING_KEY_HEX: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";
pub(crate) const KEYRING_WRAPPING_KEY_ID: &str = "wrap-integration";
pub(crate) const REPOSITORY_ID: &str = "rs3-integration-repository";
pub(crate) const REPOSITORY_SALT_HEX: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";
pub(crate) const SECRET_ACCESS_KEY: &str = "rs3-fixture-secret-key";
// This caps diagnostic text attached to the original Helm error. Command::output
// still buffers a command result before this display truncation is applied.
const MAX_NAMESPACE_DIAGNOSTIC_OUTPUT_BYTES: usize = 16 * 1024;

pub(crate) struct GatewayChartValues<'a> {
    pub(crate) release_name: &'a str,
    pub(crate) namespace: &'a str,
    pub(crate) image_repository: &'a str,
    pub(crate) image_tag: &'a str,
    pub(crate) gateway_mode: &'a str,
    pub(crate) public_bucket: &'a str,
    pub(crate) backend_endpoint: &'a str,
    pub(crate) backend_bucket: &'a str,
    pub(crate) backend_prefix: &'a str,
    pub(crate) backend_region: &'a str,
    pub(crate) backend_access_key_id: Option<&'a str>,
    pub(crate) backend_secret_access_key: Option<&'a str>,
    pub(crate) anchor_mode: &'a str,
    pub(crate) anchor_name: &'a str,
    pub(crate) log_format: &'a str,
    pub(crate) rust_log: &'a str,
    pub(crate) payload_segment_size: Option<usize>,
    pub(crate) retention_mode: Option<&'a str>,
    pub(crate) retention_days: Option<u32>,
    pub(crate) repository_id: &'a str,
    /// Pinned public salt, or `None` to let initialization generate one.
    pub(crate) repository_salt_hex: Option<&'a str>,
    pub(crate) keyring_envelope_object_id: &'a str,
    pub(crate) keyring_wrapping_key_id: &'a str,
    pub(crate) keyring_wrapping_key_hex: &'a str,
    pub(crate) persistence_enabled: bool,
    pub(crate) wait_secs: u64,
    /// Operator-asserted governance review inputs. The harness never
    /// fabricates them; governance bootstrap without them fails before Helm.
    pub(crate) governance_review: Option<&'a GovernanceReview>,
}

/// Reviewed governance-bypass inputs supplied by the operator environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GovernanceReview {
    pub(crate) principal_fingerprint: String,
}

pub(crate) const GOVERNANCE_BYPASS_REVIEWED_ENV: &str = "RS3_GOVERNANCE_BYPASS_REVIEWED";
pub(crate) const PROVIDER_PRINCIPAL_FINGERPRINT_ENV: &str = "RS3_PROVIDER_PRINCIPAL_FINGERPRINT";

/// Reads governance review inputs from the environment when the requested
/// retention mode needs them. Non-governance modes never read them.
pub(crate) fn governance_review_from_env(
    retention_mode: Option<&str>,
) -> Result<Option<GovernanceReview>> {
    governance_review_from_values(
        retention_mode,
        std::env::var(GOVERNANCE_BYPASS_REVIEWED_ENV)
            .ok()
            .as_deref(),
        std::env::var(PROVIDER_PRINCIPAL_FINGERPRINT_ENV)
            .ok()
            .as_deref(),
    )
}

fn governance_review_from_values(
    retention_mode: Option<&str>,
    reviewed: Option<&str>,
    fingerprint: Option<&str>,
) -> Result<Option<GovernanceReview>> {
    if retention_mode != Some("governance") {
        return Ok(None);
    }
    if reviewed != Some("true") {
        bail!(
            "governance retention on a provided backend requires {GOVERNANCE_BYPASS_REVIEWED_ENV}=true after reviewing that gateway credentials cannot bypass governance retention; the harness does not assert this review"
        );
    }
    let fingerprint = fingerprint.unwrap_or_default();
    if fingerprint.len() != 64
        || !fingerprint
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        bail!(
            "governance retention requires {PROVIDER_PRINCIPAL_FINGERPRINT_ENV} set to the lowercase SHA-256 fingerprint of the reviewed credential principal"
        );
    }
    Ok(Some(GovernanceReview {
        principal_fingerprint: fingerprint.to_owned(),
    }))
}

pub(crate) fn helm_install_gateway(
    helm_bin: &str,
    kubectl_bin: &str,
    kubeconfig_path: &Path,
    values: &GatewayChartValues<'_>,
) -> Result<()> {
    let kubeconfig = path_str(kubeconfig_path)?;
    let timeout = format!("{}s", values.wait_secs);
    // An unset size must reach Helm as null. An empty --set-string leaves the
    // value as "", which the chart reads as set-to-zero and rejects.
    let payload_segment_size = values
        .payload_segment_size
        .map_or_else(|| "null".to_string(), |value| value.to_string());
    let bootstrap = values.gateway_mode == "read-write"
        && values.anchor_mode == "kubernetes-lease"
        && (values.backend_endpoint == "s3"
            || values.backend_endpoint.starts_with("http://")
            || values.backend_endpoint.starts_with("https://"));
    let allow_init = !bootstrap && values.gateway_mode != "restore-readonly";
    if bootstrap
        && values.retention_mode == Some("governance")
        && values.governance_review.is_none()
    {
        bail!(
            "automatic governance bootstrap requires reviewed operator inputs; set {GOVERNANCE_BYPASS_REVIEWED_ENV}=true and {PROVIDER_PRINCIPAL_FINGERPRINT_ENV}"
        );
    }
    let governance_bypass_reviewed = values.governance_review.is_some();
    let principal_fingerprint = values
        .governance_review
        .map(|review| review.principal_fingerprint.as_str())
        .unwrap_or_default();
    run_command(
        helm_bin,
        &[
            "--kubeconfig",
            kubeconfig,
            "upgrade",
            "--install",
            values.release_name,
            CHART_PATH,
            "--namespace",
            values.namespace,
            "--create-namespace",
            "--wait",
            "--timeout",
            timeout.as_str(),
            "--set-string",
            &format!("image.repository={}", values.image_repository),
            "--set-string",
            &format!("image.tag={}", values.image_tag),
            "--set-string",
            &helm_set_string("gateway.mode", values.gateway_mode),
            "--set-string",
            &helm_set_string("admin.profile", "local"),
            "--set",
            "admin.createToken=true",
            "--set-string",
            &helm_set_string("admin.bearerToken", ADMIN_BEARER_TOKEN),
            "--set-string",
            &format!("publicBucket={}", values.public_bucket),
            "--set",
            "credentials.create=true",
            "--set-string",
            &helm_set_string("credentials.accessKeyId", ACCESS_KEY_ID),
            "--set-string",
            &helm_set_string("credentials.secretAccessKey", SECRET_ACCESS_KEY),
            "--set-string",
            &helm_set_string("backend.endpoint", values.backend_endpoint),
            "--set-string",
            &helm_set_string("backend.bucket", values.backend_bucket),
            "--set-string",
            &helm_set_string("backend.prefix", values.backend_prefix),
            "--set-string",
            &helm_set_string("backend.region", values.backend_region),
            "--set",
            &format!(
                "backendCredentials.create={}",
                values.backend_access_key_id.is_some()
            ),
            "--set-string",
            &helm_set_string(
                "backendCredentials.accessKeyId",
                values.backend_access_key_id.unwrap_or_default(),
            ),
            "--set-string",
            &helm_set_string(
                "backendCredentials.secretAccessKey",
                values.backend_secret_access_key.unwrap_or_default(),
            ),
            "--set-string",
            &helm_set_string("anchor.mode", values.anchor_mode),
            "--set-string",
            &helm_set_string("anchor.name", values.anchor_name),
            "--set-string",
            &format!("logging.format={}", values.log_format),
            "--set-string",
            &helm_set_string("logging.rustLog", values.rust_log),
            "--set",
            &format!("bootstrap.enabled={bootstrap}"),
            "--set",
            &format!("repository.allowInit={allow_init}"),
            "--set",
            &format!("repository.payloadSegmentSizeBytes={payload_segment_size}"),
            "--set-string",
            &helm_set_string(
                "repository.retention.mode",
                values.retention_mode.unwrap_or_default(),
            ),
            "--set",
            &format!(
                "repository.retention.days={}",
                values.retention_days.unwrap_or_default()
            ),
            "--set-string",
            &helm_set_string("repository.id", values.repository_id),
            "--set",
            "repositoryKeys.create=true",
            "--set-string",
            &helm_set_string(
                "repositoryKeys.saltHex",
                values.repository_salt_hex.unwrap_or_default(),
            ),
            "--set-string",
            &helm_set_string(
                "repositoryKeys.envelopeObjectId",
                values.keyring_envelope_object_id,
            ),
            "--set-string",
            &helm_set_string(
                "repositoryKeys.wrappingKeyId",
                values.keyring_wrapping_key_id,
            ),
            "--set-string",
            &helm_set_string(
                "repositoryKeys.wrappingKeyHex",
                values.keyring_wrapping_key_hex,
            ),
            "--set",
            &format!("anchor.allowMemory={}", values.anchor_mode == "memory"),
            "--set",
            &format!("persistence.enabled={}", values.persistence_enabled),
            "--set",
            &format!("bootstrap.governanceBypassReviewed={governance_bypass_reviewed}"),
            "--set-string",
            &helm_set_string(
                "providerConformance.principalFingerprint",
                principal_fingerprint,
            ),
        ],
    )
    .map_err(|error| {
        error.context(format!(
            "failed to install gateway Helm chart; namespace diagnostics before cleanup:\n{}",
            collect_namespace_failure_diagnostics(kubectl_bin, kubeconfig_path, values)
        ))
    })
}

fn collect_namespace_failure_diagnostics(
    kubectl_bin: &str,
    kubeconfig_path: &Path,
    values: &GatewayChartValues<'_>,
) -> String {
    let kubeconfig = kubeconfig_path.to_string_lossy();
    let selector = format!("app.kubernetes.io/instance={}", values.release_name);
    let mut redactions = vec![
        ADMIN_BEARER_TOKEN,
        ACCESS_KEY_ID,
        SECRET_ACCESS_KEY,
        values.backend_endpoint,
        values.backend_prefix,
        values.repository_salt_hex.unwrap_or_default(),
        values.keyring_wrapping_key_hex,
        kubeconfig.as_ref(),
    ];
    if let Some(access_key_id) = values.backend_access_key_id {
        redactions.push(access_key_id);
    }
    if let Some(secret_access_key) = values.backend_secret_access_key {
        redactions.push(secret_access_key);
    }

    [
        capture_namespace_command(
            "gateway pod readiness",
            kubectl_bin,
            &[
                "--kubeconfig",
                kubeconfig.as_ref(),
                "--request-timeout=10s",
                "--namespace",
                values.namespace,
                "get",
                "pods",
                "--selector",
                selector.as_str(),
                "--output",
                "wide",
            ],
            &redactions,
        ),
        capture_namespace_command(
            "namespace events",
            kubectl_bin,
            &[
                "--kubeconfig",
                kubeconfig.as_ref(),
                "--request-timeout=10s",
                "--namespace",
                values.namespace,
                "get",
                "events",
                "--sort-by=.lastTimestamp",
            ],
            &redactions,
        ),
        capture_namespace_command(
            "gateway container logs",
            kubectl_bin,
            &[
                "--kubeconfig",
                kubeconfig.as_ref(),
                "--request-timeout=10s",
                "--namespace",
                values.namespace,
                "logs",
                "--selector",
                selector.as_str(),
                "--all-containers=true",
                "--prefix=true",
                "--tail=80",
                "--max-log-requests=3",
                "--pod-running-timeout=10s",
            ],
            &redactions,
        ),
    ]
    .join("\n\n")
}

fn capture_namespace_command(
    label: &str,
    kubectl_bin: &str,
    args: &[&str],
    redactions: &[&str],
) -> String {
    match Command::new(kubectl_bin).args(args).output() {
        Ok(output) => format!(
            "{label} ({}):\nstdout:\n{}\nstderr:\n{}",
            output.status,
            truncated_redacted_diagnostic(&output.stdout, redactions),
            truncated_redacted_diagnostic(&output.stderr, redactions),
        ),
        Err(error) => format!(
            "{label}: failed to start kubectl: {}",
            truncated_redacted_text(error.to_string(), redactions)
        ),
    }
}

fn truncated_redacted_diagnostic(bytes: &[u8], redactions: &[&str]) -> String {
    truncated_redacted_text(String::from_utf8_lossy(bytes).into_owned(), redactions)
}

fn truncated_redacted_text(mut text: String, redactions: &[&str]) -> String {
    for value in redactions {
        if !value.is_empty() {
            text = text.replace(value, "[REDACTED]");
        }
    }
    if text.len() <= MAX_NAMESPACE_DIAGNOSTIC_OUTPUT_BYTES {
        return text;
    }

    let mut tail_start = text.len() - MAX_NAMESPACE_DIAGNOSTIC_OUTPUT_BYTES;
    while !text.is_char_boundary(tail_start) {
        tail_start += 1;
    }
    format!("[... {tail_start} bytes omitted]\n{}", &text[tail_start..])
}

pub(crate) fn helm_set_gateway_mode(
    helm_bin: &str,
    kubeconfig_path: &Path,
    release_name: &str,
    namespace: &str,
    gateway_mode: &str,
    wait_secs: u64,
) -> Result<()> {
    let kubeconfig = path_str(kubeconfig_path)?;
    let timeout = format!("{wait_secs}s");
    run_command(
        helm_bin,
        &[
            "--kubeconfig",
            kubeconfig,
            "upgrade",
            release_name,
            CHART_PATH,
            "--namespace",
            namespace,
            "--reuse-values",
            "--wait",
            "--timeout",
            timeout.as_str(),
            "--set-string",
            &helm_set_string("gateway.mode", gateway_mode),
        ],
    )
    .context("failed to update gateway Helm mode")
}

pub(crate) fn helm_lint_gateway(helm_bin: &str) -> Result<()> {
    let salt = helm_set_string("repositoryKeys.saltHex", REPOSITORY_SALT_HEX);
    let envelope = helm_set_string(
        "repositoryKeys.envelopeObjectId",
        KEYRING_ENVELOPE_OBJECT_ID,
    );
    let wrapping_key_id = helm_set_string("repositoryKeys.wrappingKeyId", KEYRING_WRAPPING_KEY_ID);
    let wrapping_key_hex =
        helm_set_string("repositoryKeys.wrappingKeyHex", KEYRING_WRAPPING_KEY_HEX);
    run_command(
        helm_bin,
        &[
            "lint",
            CHART_PATH,
            "--set",
            "credentials.create=true",
            "--set-string",
            &helm_set_string("credentials.accessKeyId", ACCESS_KEY_ID),
            "--set-string",
            &helm_set_string("credentials.secretAccessKey", SECRET_ACCESS_KEY),
            "--set",
            "repositoryKeys.create=true",
            "--set-string",
            salt.as_str(),
            "--set-string",
            envelope.as_str(),
            "--set-string",
            wrapping_key_id.as_str(),
            "--set-string",
            wrapping_key_hex.as_str(),
        ],
    )
    .context("gateway Helm chart lint failed")
}

pub(crate) fn assert_v2_lease_anchor(
    kubectl_bin: &str,
    kubeconfig_path: &Path,
    namespace: &str,
    anchor_name: &str,
) -> Result<()> {
    let kubeconfig = path_str(kubeconfig_path)?;
    let lease = run_command_capture(
        kubectl_bin,
        &[
            "--kubeconfig",
            kubeconfig,
            "-n",
            namespace,
            "get",
            "lease",
            anchor_name,
            "-o",
            "json",
        ],
    )
    .with_context(|| format!("failed to read v2 Lease anchor `{anchor_name}`"))?;
    let lease: serde_json::Value =
        serde_json::from_str(&lease).context("Lease anchor JSON was not valid")?;
    let annotations = lease
        .pointer("/metadata/annotations")
        .and_then(serde_json::Value::as_object)
        .context("Lease anchor is missing annotations")?;

    for key in [
        "rs3.rs/v3-commit-key",
        "rs3.rs/v3-body-digest",
        "rs3.rs/v3-signing-key-id",
        "rs3.rs/v3-format-digest",
        "rs3.rs/v3-format-object-id",
    ] {
        let Some(value) = annotations.get(key).and_then(serde_json::Value::as_str) else {
            bail!("Lease anchor is missing `{key}`");
        };
        if value.is_empty() {
            bail!("Lease anchor annotation `{key}` is empty");
        }
    }

    if required_u64_annotation(annotations, "rs3.rs/repository-format-generation")? != 3 {
        bail!("Lease anchor repository format generation must be 3");
    }
    let sequence = required_u64_annotation(annotations, "rs3.rs/v3-sequence")?;
    if sequence == 0 {
        bail!("Lease anchor v2 sequence must be greater than zero");
    }
    let generation = required_u64_annotation(annotations, "rs3.rs/v3-format-generation")?;
    if generation == 0 {
        bail!("Lease anchor v2 format generation must be greater than zero");
    }

    Ok(())
}

fn required_u64_annotation(
    annotations: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u64> {
    let value = annotations
        .get(key)
        .and_then(serde_json::Value::as_str)
        .with_context(|| format!("Lease anchor is missing `{key}`"))?;
    value
        .parse::<u64>()
        .with_context(|| format!("Lease anchor annotation `{key}` is not an integer"))
}

fn helm_set_string(key: &str, value: &str) -> String {
    format!("{key}={}", value.replace('\\', "\\\\").replace(',', "\\,"))
}

/// Restarts the gateway Deployment and waits for the rollout to finish.
pub(crate) fn kubectl_rollout_restart(
    kubectl_bin: &str,
    kubeconfig_path: &Path,
    namespace: &str,
    deployment: &str,
    wait_secs: u64,
) -> Result<()> {
    let kubeconfig = path_str(kubeconfig_path)?;
    let target = format!("deployment/{deployment}");
    run_command(
        kubectl_bin,
        &[
            "--kubeconfig",
            kubeconfig,
            "-n",
            namespace,
            "rollout",
            "restart",
            &target,
        ],
    )?;
    let timeout = format!("--timeout={wait_secs}s");
    run_command(
        kubectl_bin,
        &[
            "--kubeconfig",
            kubeconfig,
            "-n",
            namespace,
            "rollout",
            "status",
            &target,
            &timeout,
        ],
    )
}

/// Waits until every bootstrap Job in the namespace has completed.
pub(crate) fn wait_for_bootstrap_jobs(
    kubectl_bin: &str,
    kubeconfig_path: &Path,
    namespace: &str,
    wait_secs: u64,
) -> Result<()> {
    let kubeconfig = path_str(kubeconfig_path)?;
    let timeout = format!("--timeout={wait_secs}s");
    run_command(
        kubectl_bin,
        &[
            "--kubeconfig",
            kubeconfig,
            "-n",
            namespace,
            "wait",
            "--for=condition=complete",
            "job",
            "--all",
            &timeout,
        ],
    )
    .context("bootstrap Job did not complete")
}

/// Reads the onboarding journal's durable probe reservation count.
pub(crate) fn bootstrap_journal_attempts(
    kubectl_bin: &str,
    kubeconfig_path: &Path,
    namespace: &str,
    release_name: &str,
) -> Result<u64> {
    let kubeconfig = path_str(kubeconfig_path)?;
    let mut journal = helm_fullname(release_name);
    journal.truncate(53);
    let journal = format!("{}-bootstrap", journal.trim_end_matches('-'));
    let state = run_command_capture(
        kubectl_bin,
        &[
            "--kubeconfig",
            kubeconfig,
            "-n",
            namespace,
            "get",
            "secret",
            &journal,
            "-o",
            "go-template={{index .data \"state\" | base64decode}}",
        ],
    )
    .with_context(|| format!("failed to read bootstrap journal `{journal}`"))?;
    let record: serde_json::Value =
        serde_json::from_str(state.trim()).context("bootstrap journal state was not JSON")?;
    record
        .get("attempts")
        .and_then(serde_json::Value::as_u64)
        .context("bootstrap journal state has no attempts count")
}

pub(crate) fn helm_fullname(release_name: &str) -> String {
    format!("{release_name}-{CHART_NAME}")
}

pub(crate) struct PortForward {
    endpoint_url: String,
    child: Child,
}

impl PortForward {
    pub(crate) async fn start(
        kubectl_bin: &str,
        kubeconfig_path: &Path,
        namespace: &str,
        service: &str,
        remote_port: u16,
        wait_secs: u64,
    ) -> Result<Self> {
        let local_port = reserve_local_port()?;
        let mut child = Command::new(kubectl_bin)
            .args([
                "--kubeconfig",
                path_str(kubeconfig_path)?,
                "-n",
                namespace,
                "port-forward",
                &format!("service/{service}"),
                &format!("{local_port}:{remote_port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to start kubectl port-forward")?;
        let addr = format!("127.0.0.1:{local_port}")
            .parse::<SocketAddr>()
            .context("failed to parse local port-forward address")?;

        wait_for_tcp(&addr, &mut child, wait_secs).await?;
        Ok(Self {
            endpoint_url: format!("http://{addr}"),
            child,
        })
    }

    pub(crate) fn endpoint_url(&self) -> String {
        self.endpoint_url.clone()
    }

    pub(crate) fn shutdown(&mut self) -> Result<()> {
        if self
            .child
            .try_wait()
            .context("failed to inspect kubectl port-forward")?
            .is_some()
        {
            return Ok(());
        }
        self.child
            .kill()
            .context("failed to stop kubectl port-forward")?;
        let _status = self
            .child
            .wait()
            .context("failed to reap kubectl port-forward")?;
        Ok(())
    }
}

impl Drop for PortForward {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

async fn wait_for_tcp(addr: &SocketAddr, child: &mut Child, wait_secs: u64) -> Result<()> {
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .context("failed to inspect kubectl port-forward")?
        {
            bail!("kubectl port-forward exited before accepting connections: {status}");
        }
        if TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        if started.elapsed() > Duration::from_secs(wait_secs) {
            bail!("kubectl port-forward did not accept connections within {wait_secs}s");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn reserve_local_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("failed to reserve local port")?;
    let port = listener
        .local_addr()
        .context("failed to read reserved local port")?
        .port();
    drop(listener);
    Ok(port)
}

pub(crate) struct KindCluster {
    kind_bin: String,
    docker_bin: String,
    name: String,
    kubeconfig_path: PathBuf,
    keep: bool,
    deleted: bool,
}

impl KindCluster {
    pub(crate) fn create(
        kind_bin: String,
        docker_bin: String,
        name: String,
        kubeconfig_path: PathBuf,
        keep: bool,
        wait_secs: u64,
    ) -> Result<Self> {
        let wait = format!("{wait_secs}s");
        run_command(
            &kind_bin,
            &[
                "create",
                "cluster",
                "--name",
                name.as_str(),
                "--kubeconfig",
                path_str(&kubeconfig_path)?,
                "--wait",
                wait.as_str(),
            ],
        )
        .with_context(|| format!("failed to create kind cluster `{name}`"))?;

        Ok(Self {
            kind_bin,
            docker_bin,
            name,
            kubeconfig_path,
            keep,
            deleted: false,
        })
    }

    pub(crate) fn reuse(
        kind_bin: String,
        docker_bin: String,
        name: String,
        kubeconfig_path: PathBuf,
    ) -> Result<Self> {
        let kubeconfig =
            run_command_capture(&kind_bin, &["get", "kubeconfig", "--name", name.as_str()])
                .with_context(|| {
                    format!("failed to get kubeconfig for existing kind cluster `{name}`")
                })?;
        fs::write(&kubeconfig_path, kubeconfig)
            .with_context(|| format!("failed to write {}", kubeconfig_path.display()))?;

        Ok(Self {
            kind_bin,
            docker_bin,
            name,
            kubeconfig_path,
            keep: true,
            deleted: false,
        })
    }

    pub(crate) fn kubeconfig_path(&self) -> &Path {
        &self.kubeconfig_path
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Docker network shared by kind control-plane and worker containers.
    pub(crate) const fn docker_network(&self) -> &'static str {
        "kind"
    }

    /// Load a locally available image into the cluster.
    ///
    /// `kind load docker-image` exports a manifest list and imports it with
    /// `--all-platforms`. Docker's containerd image store keeps only the host
    /// platform's blobs, so that import fails on a digest the archive never
    /// carried. Export one platform explicitly and load the archive instead.
    pub(crate) fn load_image(&self, image: &str) -> Result<()> {
        let archive = std::env::temp_dir().join(format!(
            "rs3-kind-{}-{}.tar",
            image
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                .collect::<String>(),
            std::process::id(),
        ));
        let archive_path = path_str(&archive)?;
        let outcome = run_command(
            &self.docker_bin,
            &[
                "save",
                "--platform",
                host_docker_platform()?,
                image,
                "-o",
                archive_path,
            ],
        )
        .with_context(|| format!("failed to export image `{image}` for kind"))
        .and_then(|()| {
            run_command(
                &self.kind_bin,
                &[
                    "load",
                    "image-archive",
                    archive_path,
                    "--name",
                    self.name.as_str(),
                ],
            )
            .with_context(|| format!("failed to load image `{image}` into kind"))
        });
        let _ = fs::remove_file(&archive);
        outcome
    }

    pub(crate) fn delete(&mut self) -> Result<()> {
        if self.deleted || self.keep {
            return Ok(());
        }
        run_command(
            &self.kind_bin,
            &["delete", "cluster", "--name", self.name.as_str()],
        )
        .with_context(|| format!("failed to delete kind cluster `{}`", self.name))?;
        self.deleted = true;
        Ok(())
    }
}

impl Drop for KindCluster {
    fn drop(&mut self) {
        let _ = self.delete();
    }
}

pub(crate) struct K8sWorkspace {
    root: PathBuf,
}

impl K8sWorkspace {
    pub(crate) fn new(label: &str) -> Result<Self> {
        let root =
            std::env::temp_dir().join(format!("{label}-{}-{}", std::process::id(), now_millis(),));
        fs::create_dir_all(&root)
            .with_context(|| format!("failed to create {}", root.display()))?;
        Ok(Self { root })
    }

    pub(crate) fn kubeconfig_path(&self) -> PathBuf {
        self.root.join("kubeconfig")
    }

    pub(crate) fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for K8sWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub(crate) fn split_image_ref(image: &str) -> (String, String) {
    let slash = image.rfind('/');
    let colon = image.rfind(':');
    match colon {
        Some(colon) if slash.is_none_or(|slash| colon > slash) => {
            (image[..colon].to_owned(), image[colon + 1..].to_owned())
        }
        _ => (image.to_owned(), "latest".to_owned()),
    }
}

pub(crate) fn default_cluster_name(prefix: &str) -> String {
    format!("{prefix}-{}-{}", std::process::id(), now_millis())
}

pub(crate) fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
}

pub(crate) fn build_source_revision() -> &'static str {
    option_env!("RS3_BUILD_GIT_SHA").unwrap_or("unknown")
}

/// Docker platform for the host, for single-platform image export.
fn host_docker_platform() -> Result<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("linux/amd64"),
        "aarch64" => Ok("linux/arm64"),
        other => bail!("unsupported host architecture `{other}` for kind image loading"),
    }
}

pub(crate) fn path_str(path: &Path) -> Result<&str> {
    path.to_str().context("path is not valid UTF-8")
}

pub(crate) fn require_command(program: &str, args: &[&str]) -> Result<()> {
    run_command(program, args)
        .with_context(|| format!("required command `{program}` is unavailable"))
}

pub(crate) fn run_command(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("failed to start `{program}`"))?;
    if status.success() {
        Ok(())
    } else {
        bail!("`{program}` exited with {status}");
    }
}

pub(crate) fn run_command_capture(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to start `{program}`"))?;
    if !output.status.success() {
        bail!(
            "`{program}` exited with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    String::from_utf8(output.stdout).context("command stdout was not valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::{
        GovernanceReview, MAX_NAMESPACE_DIAGNOSTIC_OUTPUT_BYTES, governance_review_from_values,
        truncated_redacted_text,
    };

    #[test]
    fn governance_review_requires_explicit_operator_inputs() {
        let fingerprint = "a".repeat(64);
        assert_eq!(
            governance_review_from_values(Some("compliance"), None, None).expect("unused"),
            None
        );
        assert_eq!(
            governance_review_from_values(None, Some("true"), Some(&fingerprint)).expect("unused"),
            None
        );
        let missing = governance_review_from_values(Some("governance"), None, Some(&fingerprint))
            .expect_err("review flag required");
        assert!(
            missing
                .to_string()
                .contains("RS3_GOVERNANCE_BYPASS_REVIEWED=true")
        );
        let wrong =
            governance_review_from_values(Some("governance"), Some("yes"), Some(&fingerprint))
                .expect_err("only the literal true counts as review");
        assert!(
            wrong
                .to_string()
                .contains("RS3_GOVERNANCE_BYPASS_REVIEWED=true")
        );
        for bad in [
            "",
            "ABCDEF",
            &"a".repeat(63),
            &format!("{}G", "a".repeat(63)),
        ] {
            let error = governance_review_from_values(Some("governance"), Some("true"), Some(bad))
                .expect_err("fingerprint must be 64 lowercase hex characters");
            assert!(
                error
                    .to_string()
                    .contains("RS3_PROVIDER_PRINCIPAL_FINGERPRINT")
            );
        }
        assert_eq!(
            governance_review_from_values(Some("governance"), Some("true"), Some(&fingerprint))
                .expect("complete review"),
            Some(GovernanceReview {
                principal_fingerprint: fingerprint,
            })
        );
    }

    #[test]
    fn namespace_diagnostics_redact_before_truncation() {
        let secret = "fixture-secret";
        let output = format!(
            "{}{}",
            "x".repeat(MAX_NAMESPACE_DIAGNOSTIC_OUTPUT_BYTES),
            secret
        );

        let diagnostic = truncated_redacted_text(output, &[secret]);

        assert!(diagnostic.starts_with("[... "));
        assert!(diagnostic.contains("[REDACTED]"));
        assert!(!diagnostic.contains(secret));
        assert!(diagnostic.len() <= MAX_NAMESPACE_DIAGNOSTIC_OUTPUT_BYTES + 64);
    }
}
