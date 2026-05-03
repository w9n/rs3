//! Provider-neutral `BlobStore` contract tests.

mod common;

use common::assert_core_blob_store_contract;
use rs3_storage::{FilesystemBlobStore, MemoryBlobStore};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[tokio::test]
async fn memory_store_satisfies_core_contract() {
    let store = MemoryBlobStore::new();

    assert_core_blob_store_contract(&store, "memory").await;
}

#[tokio::test]
async fn filesystem_store_satisfies_core_contract() {
    let dir = TestDir::new("filesystem-contract");
    let store = FilesystemBlobStore::new(dir.path()).unwrap_or_else(|error| panic!("{error}"));

    assert_core_blob_store_contract(&store, "filesystem").await;
}

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rs3-storage-{label}-{}-{nanos}",
            std::process::id()
        ));
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
