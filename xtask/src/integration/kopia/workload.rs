//! Source-tree profiles for Kopia integration lanes.

use clap::ValueEnum;

#[cfg(feature = "containers")]
use anyhow::{Context, Result, bail};
#[cfg(feature = "containers")]
use std::fs;
#[cfg(feature = "containers")]
use std::io::Write;
#[cfg(feature = "containers")]
use std::path::{Path, PathBuf};
#[cfg(feature = "containers")]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(super) enum KopiaWorkloadProfile {
    /// Current fast smoke profile with a small tree and one 1 MiB object.
    SmallSmoke,
    /// Restore-heavy profile with one larger 64 MiB object.
    MediumRestore,
    /// Metadata-heavy profile with many small files.
    ManySmallFiles,
    /// Kubernetes-object-shaped restore profile with many manifests and metadata files.
    KubernetesObjects,
    /// Postgres-pgdata-shaped restore profile with relation, WAL, and dump files.
    PostgresPgdata,
    /// Take a second snapshot after modifying the source tree.
    ChangedSnapshot,
}

impl KopiaWorkloadProfile {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::SmallSmoke => "small-smoke",
            Self::MediumRestore => "medium-restore",
            Self::ManySmallFiles => "many-small-files",
            Self::KubernetesObjects => "kubernetes-objects",
            Self::PostgresPgdata => "postgres-pgdata",
            Self::ChangedSnapshot => "changed-snapshot",
        }
    }
}

#[cfg(feature = "containers")]
pub(super) struct KopiaWorkspace {
    root: PathBuf,
}

#[cfg(feature = "containers")]
impl KopiaWorkspace {
    pub(super) fn new() -> Result<Self> {
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

    pub(super) fn config_file(&self) -> PathBuf {
        self.root.join("repository.config")
    }

    pub(super) fn cache_dir(&self) -> PathBuf {
        self.root.join("cache")
    }

    pub(super) fn source_dir(&self) -> PathBuf {
        self.root.join("source")
    }

    pub(super) fn restore_dir(&self) -> PathBuf {
        self.root.join("restore")
    }

    pub(super) fn populate_source(&self, profile: KopiaWorkloadProfile) -> Result<()> {
        let nested = self.source_dir().join("nested");
        fs::create_dir_all(&nested).context("failed to create Kopia source tree")?;
        fs::write(self.source_dir().join("alpha.txt"), b"alpha\n")
            .context("failed to write Kopia source file")?;
        fs::write(nested.join("beta.txt"), b"beta\n")
            .context("failed to write nested Kopia source file")?;

        match profile {
            KopiaWorkloadProfile::SmallSmoke | KopiaWorkloadProfile::ChangedSnapshot => {
                write_deterministic_file(&self.source_dir().join("large.bin"), 1024 * 1024)?;
            }
            KopiaWorkloadProfile::MediumRestore => {
                write_deterministic_file(&self.source_dir().join("large.bin"), 64 * 1024 * 1024)?;
            }
            KopiaWorkloadProfile::ManySmallFiles => {
                let many = self.source_dir().join("many");
                fs::create_dir_all(&many).context("failed to create many-small-files tree")?;
                for index in 0..512 {
                    let bucket = many.join(format!("group-{group:02}", group = index % 16));
                    fs::create_dir_all(&bucket)
                        .context("failed to create many-small-files bucket")?;
                    fs::write(
                        bucket.join(format!("file-{index:04}.txt")),
                        format!("rs3-kopia-small-file-{index:04}\n"),
                    )
                    .context("failed to write many-small-files payload")?;
                }
            }
            KopiaWorkloadProfile::KubernetesObjects => {
                populate_kubernetes_objects(&self.source_dir())?;
            }
            KopiaWorkloadProfile::PostgresPgdata => {
                populate_postgres_pgdata(&self.source_dir())?;
            }
        }
        Ok(())
    }

    pub(super) fn mutate_source_for_second_snapshot(&self) -> Result<()> {
        fs::write(self.source_dir().join("alpha.txt"), b"alpha changed\n")
            .context("failed to modify Kopia source file")?;
        fs::remove_file(self.source_dir().join("nested").join("beta.txt"))
            .context("failed to remove nested Kopia source file")?;
        fs::write(
            self.source_dir().join("nested").join("gamma.txt"),
            b"gamma\n",
        )
        .context("failed to add nested Kopia source file")?;
        write_deterministic_file(&self.source_dir().join("large.bin"), 2 * 1024 * 1024)?;
        Ok(())
    }

    pub(super) fn assert_restored(&self) -> Result<()> {
        assert_tree_eq(&self.source_dir(), &self.restore_dir())
    }
}

#[cfg(feature = "containers")]
impl Drop for KopiaWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(feature = "containers")]
fn write_deterministic_file(path: &Path, len: usize) -> Result<()> {
    let mut file =
        fs::File::create(path).with_context(|| format!("failed to create {}", path.display()))?;
    const CHUNK: usize = 1024 * 1024;
    let mut state = deterministic_file_seed(path, len);
    let mut buffer = vec![0; CHUNK];
    let mut written = 0;
    while written < len {
        let next = (len - written).min(CHUNK);
        fill_deterministic_bytes(&mut buffer[..next], &mut state);
        file.write_all(&buffer[..next])
            .with_context(|| format!("failed to write {}", path.display()))?;
        written += next;
    }
    file.flush()
        .with_context(|| format!("failed to flush {}", path.display()))
}

#[cfg(feature = "containers")]
fn deterministic_file_seed(path: &Path, len: usize) -> u64 {
    let mut state = 0x7d3f_2a91_b6c8_e405_u64 ^ len as u64;
    if let Some(file_name) = path.file_name().and_then(|name| name.to_str()) {
        for byte in file_name.bytes() {
            state ^= u64::from(byte);
            state = splitmix64(state);
        }
    }
    state
}

#[cfg(feature = "containers")]
fn populate_kubernetes_objects(source: &Path) -> Result<()> {
    let root = source.join("kubernetes");
    fs::create_dir_all(&root).context("failed to create Kubernetes object tree")?;
    for namespace in 0..16 {
        let namespace_dir = root.join(format!("namespace-{namespace:02}"));
        fs::create_dir_all(&namespace_dir)
            .context("failed to create Kubernetes namespace directory")?;
        for object in 0..96 {
            let kind = match object % 6 {
                0 => "deployment",
                1 => "configmap",
                2 => "service",
                3 => "role",
                4 => "secret-metadata",
                _ => "custom-resource",
            };
            let manifest = kubernetes_manifest(namespace, object, kind);
            fs::write(
                namespace_dir.join(format!("{kind}-{object:04}.yaml")),
                manifest,
            )
            .context("failed to write Kubernetes manifest")?;
        }
    }
    write_deterministic_file(&root.join("etcd-snapshot-fragment.bin"), 32 * 1024 * 1024)
}

#[cfg(feature = "containers")]
fn kubernetes_manifest(namespace: usize, object: usize, kind: &str) -> String {
    format!(
        "apiVersion: rs3.dev/v1\nkind: {kind}\nmetadata:\n  name: object-{object:04}\n  namespace: namespace-{namespace:02}\n  labels:\n    app.kubernetes.io/name: rs3-perf\n    rs3.dev/profile: kubernetes-objects\nspec:\n  generation: {object}\n  payload: {}\n",
        "x".repeat(256 + object % 97),
    )
}

#[cfg(feature = "containers")]
fn populate_postgres_pgdata(source: &Path) -> Result<()> {
    let root = source.join("postgres");
    let base = root.join("base").join("16384");
    let wal = root.join("pg_wal");
    fs::create_dir_all(&base).context("failed to create Postgres base directory")?;
    fs::create_dir_all(&wal).context("failed to create Postgres WAL directory")?;

    for relation in 0..96 {
        write_deterministic_file(&base.join(format!("{relation}")), 1024 * 1024)?;
    }
    for segment in 0..4 {
        write_deterministic_file(
            &wal.join(format!("0000000100000000000000{segment:02X}")),
            16 * 1024 * 1024,
        )?;
    }
    write_deterministic_file(&root.join("rs3-proof.sql"), 8 * 1024 * 1024)?;
    fs::write(root.join("PG_VERSION"), b"17\n").context("failed to write Postgres version marker")
}

#[cfg(feature = "containers")]
fn fill_deterministic_bytes(buffer: &mut [u8], state: &mut u64) {
    for chunk in buffer.chunks_mut(std::mem::size_of::<u64>()) {
        *state = splitmix64(*state);
        let bytes = state.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
}

#[cfg(feature = "containers")]
fn splitmix64(mut state: u64) -> u64 {
    state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[cfg(feature = "containers")]
fn assert_tree_eq(expected: &Path, actual: &Path) -> Result<()> {
    for entry in fs::read_dir(expected)
        .with_context(|| format!("failed to read directory {}", expected.display()))?
    {
        let entry =
            entry.with_context(|| format!("failed to read entry in {}", expected.display()))?;
        let expected_path = entry.path();
        let actual_path = actual.join(entry.file_name());
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to read file type for {}", expected_path.display()))?;
        if file_type.is_dir() {
            if !actual_path.is_dir() {
                bail!("restored path {} is not a directory", actual_path.display());
            }
            assert_tree_eq(&expected_path, &actual_path)?;
        } else if file_type.is_file() {
            assert_file_eq(&expected_path, &actual_path)?;
        }
    }

    for entry in fs::read_dir(actual)
        .with_context(|| format!("failed to read directory {}", actual.display()))?
    {
        let entry =
            entry.with_context(|| format!("failed to read entry in {}", actual.display()))?;
        let expected_path = expected.join(entry.file_name());
        if !expected_path.exists() {
            bail!(
                "restore included unexpected path {}",
                entry.path().display()
            );
        }
    }

    Ok(())
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

#[cfg(all(test, feature = "containers"))]
mod tests {
    use super::deterministic_file_seed;
    use std::path::Path;

    #[test]
    fn deterministic_file_seed_distinguishes_equal_size_files() {
        assert_ne!(
            deterministic_file_seed(Path::new("0"), 1024 * 1024),
            deterministic_file_seed(Path::new("1"), 1024 * 1024)
        );
        assert_eq!(
            deterministic_file_seed(Path::new("0"), 1024 * 1024),
            deterministic_file_seed(Path::new("0"), 1024 * 1024)
        );
    }
}
