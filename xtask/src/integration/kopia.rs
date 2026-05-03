//! Kopia compatibility integration command.

use super::S3ContainerProvider;
#[cfg(feature = "containers")]
use super::gateway_process::{ACCESS_KEY_ID, PUBLIC_BUCKET, RunningGateway, SECRET_ACCESS_KEY};
#[cfg(feature = "containers")]
use super::s3_container;
use anyhow::Result;
#[cfg(feature = "containers")]
use anyhow::{Context, bail};
use clap::Args;
#[cfg(feature = "containers")]
use std::ffi::{OsStr, OsString};
#[cfg(feature = "containers")]
use std::fs;
#[cfg(feature = "containers")]
use std::path::{Path, PathBuf};
#[cfg(feature = "containers")]
use std::process::{Command, Stdio};
#[cfg(feature = "containers")]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(feature = "containers")]
const KOPIA_PASSWORD: &str = "rs3-local-integration-password";

#[derive(Debug, Args)]
pub(crate) struct KopiaGatewayArgs {
    /// Container provider used as the gateway backend.
    #[arg(long, value_enum, default_value_t = S3ContainerProvider::Rustfs)]
    container_provider: S3ContainerProvider,
    /// Existing backend bucket. If omitted, a temporary bucket is created.
    #[arg(long, env = "RS3_TEST_S3_BUCKET")]
    backend_bucket: Option<String>,
    /// Backend S3 signing region.
    #[arg(long, env = "RS3_TEST_S3_REGION")]
    region: Option<String>,
    /// Backend prefix for repository-owned objects.
    #[arg(long, env = "RS3_TEST_S3_PREFIX", default_value = "rs3-kopia")]
    backend_prefix: String,
    /// Kopia executable to run.
    #[arg(long, env = "RS3_TEST_KOPIA_BIN", default_value = "kopia")]
    kopia_bin: String,
}

#[cfg(not(feature = "containers"))]
pub(crate) fn run_kopia_gateway(args: KopiaGatewayArgs) -> Result<()> {
    anyhow::bail!(
        "Kopia gateway integration for {:?} requires `cargo run -p xtask --features containers -- integration kopia-gateway`",
        args.container_provider,
    )
}

#[cfg(feature = "containers")]
pub(crate) fn run_kopia_gateway(args: KopiaGatewayArgs) -> Result<()> {
    let kopia_bin = args.kopia_bin;
    let backend_prefix = args.backend_prefix;
    let backend = s3_container::start_s3_container(
        args.container_provider,
        args.backend_bucket,
        args.region,
    )?;
    let workspace = KopiaWorkspace::new()?;
    workspace.populate_source()?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build Kopia integration runtime")?;

    runtime.block_on(async {
        let mut gateway = RunningGateway::start(&backend, backend_prefix).await?;
        let result = run_kopia_smoke(&kopia_bin, &workspace, &gateway, &backend.region);
        let shutdown = gateway.shutdown();

        result?;
        shutdown?;
        Ok(())
    })
}

#[cfg(feature = "containers")]
fn run_kopia_smoke(
    kopia_bin: &str,
    workspace: &KopiaWorkspace,
    gateway: &RunningGateway,
    region: &str,
) -> Result<()> {
    require_kopia(kopia_bin)?;

    run_kopia(
        kopia_bin,
        workspace,
        vec![
            os("repository"),
            os("create"),
            os("s3"),
            os("--bucket"),
            os(PUBLIC_BUCKET),
            os("--endpoint"),
            os(gateway.endpoint_authority()),
            os("--access-key"),
            os(ACCESS_KEY_ID),
            os("--secret-access-key"),
            os(SECRET_ACCESS_KEY),
            os("--region"),
            os(region),
            os("--disable-tls"),
            os("--prefix"),
            os("kopia/"),
            os("--cache-directory"),
            workspace.cache_dir().into_os_string(),
            os("--override-hostname"),
            os("rs3-integration"),
            os("--override-username"),
            os("rs3"),
        ],
    )?;

    run_kopia(
        kopia_bin,
        workspace,
        vec![
            os("snapshot"),
            os("create"),
            workspace.source_dir().into_os_string(),
        ],
    )?;

    run_kopia(
        kopia_bin,
        workspace,
        vec![
            os("restore"),
            workspace.source_dir().into_os_string(),
            workspace.restore_dir().into_os_string(),
        ],
    )?;

    workspace.assert_restored()
}

#[cfg(feature = "containers")]
fn require_kopia(kopia_bin: &str) -> Result<()> {
    let status = Command::new(kopia_bin)
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| {
            format!("failed to start `{kopia_bin}`; install Kopia or set --kopia-bin")
        })?;

    if status.success() {
        Ok(())
    } else {
        bail!("`{kopia_bin} --help` exited with {status}");
    }
}

#[cfg(feature = "containers")]
fn run_kopia(
    kopia_bin: &str,
    workspace: &KopiaWorkspace,
    command_args: Vec<OsString>,
) -> Result<()> {
    let mut command = Command::new(kopia_bin);
    command
        .arg("--config-file")
        .arg(workspace.config_file())
        .arg("--password")
        .arg(KOPIA_PASSWORD)
        .arg("--no-progress")
        .arg("--log-level")
        .arg("warning")
        .arg("--no-use-keyring");
    command.args(command_args);

    let output = command
        .output()
        .with_context(|| format!("failed to start `{kopia_bin}`"))?;

    if output.status.success() {
        return Ok(());
    }

    bail!(
        "`{}` exited with {}\nstdout:\n{}\nstderr:\n{}",
        kopia_bin,
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[cfg(feature = "containers")]
fn os(value: impl AsRef<OsStr>) -> OsString {
    value.as_ref().to_owned()
}

#[cfg(feature = "containers")]
struct KopiaWorkspace {
    root: PathBuf,
}

#[cfg(feature = "containers")]
impl KopiaWorkspace {
    fn new() -> Result<Self> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "rs3-kopia-integration-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&root).with_context(|| {
            format!(
                "failed to create Kopia integration workspace {}",
                root.display()
            )
        })?;
        Ok(Self { root })
    }

    fn config_file(&self) -> PathBuf {
        self.root.join("repository.config")
    }

    fn cache_dir(&self) -> PathBuf {
        self.root.join("cache")
    }

    fn source_dir(&self) -> PathBuf {
        self.root.join("source")
    }

    fn restore_dir(&self) -> PathBuf {
        self.root.join("restore")
    }

    fn populate_source(&self) -> Result<()> {
        let nested = self.source_dir().join("nested");
        fs::create_dir_all(&nested).context("failed to create Kopia source tree")?;
        fs::write(self.source_dir().join("alpha.txt"), b"alpha\n")
            .context("failed to write Kopia source file")?;
        fs::write(nested.join("beta.txt"), b"beta\n")
            .context("failed to write nested Kopia source file")?;
        fs::write(
            self.source_dir().join("large.bin"),
            deterministic_bytes(1024 * 1024),
        )
        .context("failed to write large Kopia source file")?;
        Ok(())
    }

    fn assert_restored(&self) -> Result<()> {
        assert_file_eq(
            &self.source_dir().join("alpha.txt"),
            &self.restore_dir().join("alpha.txt"),
        )?;
        assert_file_eq(
            &self.source_dir().join("nested").join("beta.txt"),
            &self.restore_dir().join("nested").join("beta.txt"),
        )?;
        assert_file_eq(
            &self.source_dir().join("large.bin"),
            &self.restore_dir().join("large.bin"),
        )?;
        Ok(())
    }
}

#[cfg(feature = "containers")]
impl Drop for KopiaWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(feature = "containers")]
fn deterministic_bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| index.wrapping_mul(31).wrapping_add(17) as u8)
        .collect()
}

#[cfg(feature = "containers")]
fn assert_file_eq(expected: &Path, actual: &Path) -> Result<()> {
    let expected_body =
        fs::read(expected).with_context(|| format!("failed to read {}", expected.display()))?;
    let actual_body =
        fs::read(actual).with_context(|| format!("failed to read {}", actual.display()))?;
    if expected_body != actual_body {
        bail!(
            "restored file {} did not match source {}",
            actual.display(),
            expected.display()
        );
    }
    Ok(())
}
