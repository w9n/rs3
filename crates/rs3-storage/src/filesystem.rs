//! Local filesystem `BlobStore` implementation.

use crate::{
    BlobMetadata, BlobStore, ByteRange, PutOptions, Result, StorageError, object_kind, prefix_kind,
    record_blob_delete, record_blob_extend_retention, record_blob_get, record_blob_head,
    record_blob_list, record_blob_put,
};
use async_trait::async_trait;
use bytes::Bytes;
use rs3_types::{BackendObjectId, RetentionPolicy};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Filesystem-backed `BlobStore` for local durable development and tests.
///
/// Object identifiers are stored as relative paths below the configured root.
/// Path traversal, absolute paths, and platform prefixes are rejected before
/// touching the filesystem.
#[derive(Clone, Debug)]
pub struct FilesystemBlobStore {
    root: PathBuf,
}

impl FilesystemBlobStore {
    /// Creates a filesystem store rooted at `root`.
    ///
    /// # Errors
    ///
    /// Returns a provider error if the root directory cannot be created.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(provider_error)?;
        Ok(Self { root })
    }

    /// Returns the root directory used by this store.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn object_path(&self, object_id: &BackendObjectId) -> Result<PathBuf> {
        let relative = safe_relative_path(object_id.as_str())?;
        Ok(self.root.join(relative))
    }
}

#[async_trait]
impl BlobStore for FilesystemBlobStore {
    async fn put(
        &self,
        object_id: &BackendObjectId,
        body: Bytes,
        options: PutOptions,
    ) -> Result<BlobMetadata> {
        let started = Instant::now();
        let kind = object_kind(object_id);
        let requested_len = body.len();
        let retained = options.retention.is_some();

        if retained {
            record_blob_put(
                kind,
                requested_len,
                retained,
                "retention_unsupported",
                started.elapsed(),
            );
            return Err(StorageError::RetentionExtensionUnsupported);
        }

        let path = self.object_path(object_id)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(provider_error)?;
        }

        let write = if options.do_not_recreate {
            write_new_file(&path, &body).map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    StorageError::AlreadyExists(object_id.clone())
                } else {
                    provider_error(error)
                }
            })
        } else {
            write_replace_file(&path, &body).map_err(provider_error)
        };

        if let Err(error) = write {
            let result = match error {
                StorageError::AlreadyExists(_) => "already_exists",
                _ => "error",
            };
            record_blob_put(kind, requested_len, retained, result, started.elapsed());
            return Err(error);
        }

        let metadata = self.head(object_id).await?;
        record_blob_put(kind, requested_len, retained, "ok", started.elapsed());
        Ok(metadata)
    }

    async fn get_range(&self, object_id: &BackendObjectId, range: ByteRange) -> Result<Bytes> {
        let started = Instant::now();
        let kind = object_kind(object_id);
        let path = self.object_path(object_id)?;

        let body = match read_file_range(&path, range) {
            Ok(body) => body,
            Err(StorageError::NotFound(_)) => {
                record_blob_get(kind, range, 0, "not_found", started.elapsed());
                return Err(StorageError::NotFound(object_id.clone()));
            }
            Err(StorageError::InvalidRange) => {
                record_blob_get(kind, range, 0, "invalid_range", started.elapsed());
                return Err(StorageError::InvalidRange);
            }
            Err(error) => {
                record_blob_get(kind, range, 0, "error", started.elapsed());
                return Err(error);
            }
        };

        let bytes_read = u64::try_from(body.len())
            .map_err(|_| StorageError::Provider("read length does not fit in u64".to_owned()))?;
        record_blob_get(kind, range, bytes_read, "ok", started.elapsed());
        Ok(body)
    }

    async fn head(&self, object_id: &BackendObjectId) -> Result<BlobMetadata> {
        let started = Instant::now();
        let kind = object_kind(object_id);
        let path = self.object_path(object_id)?;
        let metadata = match fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() => metadata,
            Ok(_) => {
                record_blob_head(kind, "not_found", started.elapsed());
                return Err(StorageError::NotFound(object_id.clone()));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                record_blob_head(kind, "not_found", started.elapsed());
                return Err(StorageError::NotFound(object_id.clone()));
            }
            Err(error) => {
                record_blob_head(kind, "error", started.elapsed());
                return Err(provider_error(error));
            }
        };

        record_blob_head(kind, "ok", started.elapsed());
        Ok(blob_metadata(object_id.clone(), metadata))
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<BlobMetadata>> {
        let started = Instant::now();
        let kind = prefix_kind(prefix);
        let prefix_path = if prefix.is_empty() {
            self.root.clone()
        } else {
            self.root.join(safe_relative_path(prefix)?)
        };

        if !prefix_path.exists() {
            record_blob_list(kind, 0, "ok", started.elapsed());
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();
        collect_files(&self.root, &prefix_path, prefix, &mut entries)?;
        entries.sort_by(|left, right| left.object_id.cmp(&right.object_id));

        record_blob_list(kind, entries.len(), "ok", started.elapsed());
        Ok(entries)
    }

    async fn delete(&self, object_id: &BackendObjectId) -> Result<()> {
        let started = Instant::now();
        let kind = object_kind(object_id);
        let path = self.object_path(object_id)?;
        match fs::remove_file(&path) {
            Ok(()) => {
                record_blob_delete(kind, "ok", started.elapsed());
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                record_blob_delete(kind, "not_found", started.elapsed());
                Err(StorageError::NotFound(object_id.clone()))
            }
            Err(error) => {
                record_blob_delete(kind, "error", started.elapsed());
                Err(provider_error(error))
            }
        }
    }

    async fn extend_retention(
        &self,
        object_id: &BackendObjectId,
        _policy: RetentionPolicy,
    ) -> Result<()> {
        let started = Instant::now();
        let kind = object_kind(object_id);
        let path = self.object_path(object_id)?;
        if !path.is_file() {
            record_blob_extend_retention(kind, "not_found", started.elapsed());
            return Err(StorageError::NotFound(object_id.clone()));
        }

        record_blob_extend_retention(kind, "unsupported", started.elapsed());
        Err(StorageError::RetentionExtensionUnsupported)
    }

    async fn flush_caches(&self) -> Result<()> {
        let started = Instant::now();
        tracing::debug!(
            target: "rs3_storage",
            operation = "flush_caches",
            result = "ok",
            elapsed_us = crate::elapsed_us(started.elapsed()),
            "blob store operation completed",
        );
        Ok(())
    }
}

fn write_new_file(path: &Path, body: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(body)?;
    file.sync_all()
}

fn write_replace_file(path: &Path, body: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("object path has no parent"))?;
    let temp_path = parent.join(temp_file_name());
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        file.write_all(body)?;
        file.sync_all()?;
        fs::rename(&temp_path, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn read_file_range(path: &Path, range: ByteRange) -> Result<Bytes> {
    match range {
        ByteRange::Full => fs::read(path)
            .map(Bytes::from)
            .map_err(|error| map_read_error(path, error)),
        ByteRange::Slice { offset, len } => {
            let mut file = File::open(path).map_err(|error| map_read_error(path, error))?;
            let file_len = file.metadata().map_err(provider_error)?.len();
            let end = offset.checked_add(len).ok_or(StorageError::InvalidRange)?;
            if offset > file_len || end > file_len {
                return Err(StorageError::InvalidRange);
            }
            let len = usize::try_from(len).map_err(|_| StorageError::InvalidRange)?;
            let mut body = vec![0u8; len];
            file.seek(SeekFrom::Start(offset)).map_err(provider_error)?;
            file.read_exact(&mut body).map_err(provider_error)?;
            Ok(Bytes::from(body))
        }
    }
}

fn collect_files(
    root: &Path,
    directory: &Path,
    prefix: &str,
    entries: &mut Vec<BlobMetadata>,
) -> Result<()> {
    for entry in fs::read_dir(directory).map_err(provider_error)? {
        let entry = entry.map_err(provider_error)?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(provider_error)?;
        if file_type.is_dir() {
            collect_files(root, &path, prefix, entries)?;
        } else if file_type.is_file() {
            let object_id = object_id_from_path(root, &path)?;
            if object_id.as_str().starts_with(prefix) {
                let metadata = entry.metadata().map_err(provider_error)?;
                entries.push(blob_metadata(object_id, metadata));
            }
        }
    }
    Ok(())
}

fn blob_metadata(object_id: BackendObjectId, metadata: fs::Metadata) -> BlobMetadata {
    let modified_at_ms = metadata.modified().ok().and_then(system_time_millis);
    BlobMetadata {
        object_id,
        content_len: metadata.len(),
        modified_at_ms,
        etag: modified_at_ms.map(|modified| format!("fs-{modified:x}-{:x}", metadata.len())),
        version_id: None,
        retention: None,
    }
}

fn object_id_from_path(root: &Path, path: &Path) -> Result<BackendObjectId> {
    let relative = path.strip_prefix(root).map_err(|error| {
        StorageError::Provider(format!("filesystem path escaped store root: {error}"))
    })?;
    let mut value = String::new();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(StorageError::Provider(
                "filesystem path contains non-normal component".to_owned(),
            ));
        };
        if !value.is_empty() {
            value.push('/');
        }
        value.push_str(component.to_str().ok_or_else(|| {
            StorageError::Provider("filesystem path is not valid UTF-8".to_owned())
        })?);
    }
    BackendObjectId::new(value).map_err(|error| StorageError::Provider(error.to_string()))
}

fn safe_relative_path(value: &str) -> Result<PathBuf> {
    let mut path = PathBuf::new();
    for component in Path::new(value).components() {
        match component {
            Component::Normal(component) => path.push(component),
            Component::CurDir => {}
            Component::RootDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(StorageError::Provider(
                    "object identifier must be a relative path".to_owned(),
                ));
            }
        }
    }
    Ok(path)
}

fn temp_file_name() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos();
    format!(".rs3-tmp-{}-{nanos}", std::process::id())
}

fn system_time_millis(time: SystemTime) -> Option<i64> {
    let millis = time.duration_since(UNIX_EPOCH).ok()?.as_millis();
    i64::try_from(millis).ok()
}

fn map_read_error(path: &Path, error: std::io::Error) -> StorageError {
    if error.kind() == std::io::ErrorKind::NotFound {
        let object_id = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("missing");
        match BackendObjectId::new(object_id.to_owned()) {
            Ok(object_id) => StorageError::NotFound(object_id),
            Err(error) => StorageError::Provider(error.to_string()),
        }
    } else {
        provider_error(error)
    }
}

fn provider_error(error: std::io::Error) -> StorageError {
    StorageError::Provider(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::FilesystemBlobStore;
    use crate::{BlobStore, ByteRange, PutOptions, StorageError};
    use bytes::Bytes;
    use rs3_types::{BackendObjectId, RetentionMode, RetentionPolicy};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new() -> Self {
            let id = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("rs3-storage-test-{}-{id}", std::process::id()));
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

    fn object_id(value: &str) -> BackendObjectId {
        BackendObjectId::new(value).unwrap_or_else(|error| panic!("{error}"))
    }

    #[tokio::test]
    async fn filesystem_store_puts_and_reads_object_ranges() {
        let dir = TestDir::new();
        let store = FilesystemBlobStore::new(dir.path()).unwrap_or_else(|error| panic!("{error}"));
        let object_id = object_id("segments/a");

        let put = store
            .put(
                &object_id,
                Bytes::from_static(b"hello world"),
                PutOptions {
                    do_not_recreate: true,
                    ..PutOptions::default()
                },
            )
            .await;
        assert!(put.is_ok());

        let head = store.head(&object_id).await;
        let body = store
            .get_range(&object_id, ByteRange::Slice { offset: 6, len: 5 })
            .await;

        assert_eq!(head.map(|metadata| metadata.content_len), Ok(11));
        assert_eq!(body, Ok(Bytes::from_static(b"world")));
    }

    #[tokio::test]
    async fn filesystem_store_lists_prefixes_in_order() {
        let dir = TestDir::new();
        let store = FilesystemBlobStore::new(dir.path()).unwrap_or_else(|error| panic!("{error}"));
        for name in ["segments/b", "index/a", "segments/a"] {
            let put = store
                .put(
                    &object_id(name),
                    Bytes::from_static(b"body"),
                    PutOptions::default(),
                )
                .await;
            assert!(put.is_ok());
        }

        let listed = store.list_prefix("segments/").await;
        let object_ids = listed
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .map(|metadata| metadata.object_id)
            .collect::<Vec<_>>();

        assert_eq!(
            object_ids,
            vec![object_id("segments/a"), object_id("segments/b")]
        );
    }

    #[tokio::test]
    async fn filesystem_store_rejects_create_only_duplicate() {
        let dir = TestDir::new();
        let store = FilesystemBlobStore::new(dir.path()).unwrap_or_else(|error| panic!("{error}"));
        let object_id = object_id("segments/a");
        let options = PutOptions {
            do_not_recreate: true,
            ..PutOptions::default()
        };

        let first = store
            .put(&object_id, Bytes::from_static(b"first"), options.clone())
            .await;
        let second = store
            .put(&object_id, Bytes::from_static(b"second"), options)
            .await;

        assert!(first.is_ok());
        assert!(matches!(second, Err(StorageError::AlreadyExists(_))));
    }

    #[tokio::test]
    async fn filesystem_store_deletes_objects() {
        let dir = TestDir::new();
        let store = FilesystemBlobStore::new(dir.path()).unwrap_or_else(|error| panic!("{error}"));
        let object_id = object_id("segments/a");
        let put = store
            .put(
                &object_id,
                Bytes::from_static(b"body"),
                PutOptions::default(),
            )
            .await;
        assert!(put.is_ok());

        let delete = store.delete(&object_id).await;
        let head = store.head(&object_id).await;

        assert!(delete.is_ok());
        assert!(matches!(head, Err(StorageError::NotFound(_))));
    }

    #[tokio::test]
    async fn filesystem_store_rejects_path_traversal() {
        let dir = TestDir::new();
        let store = FilesystemBlobStore::new(dir.path()).unwrap_or_else(|error| panic!("{error}"));
        let object_id = object_id("../segments/a");

        let put = store
            .put(
                &object_id,
                Bytes::from_static(b"body"),
                PutOptions::default(),
            )
            .await;

        assert!(matches!(put, Err(StorageError::Provider(_))));
    }

    #[tokio::test]
    async fn filesystem_store_reports_retention_unsupported() {
        let dir = TestDir::new();
        let store = FilesystemBlobStore::new(dir.path()).unwrap_or_else(|error| panic!("{error}"));
        let object_id = object_id("segments/a");

        let put = store
            .put(
                &object_id,
                Bytes::from_static(b"body"),
                PutOptions {
                    retention: Some(RetentionPolicy::new(RetentionMode::Compliance, 30)),
                    ..PutOptions::default()
                },
            )
            .await;

        assert_eq!(put, Err(StorageError::RetentionExtensionUnsupported));
    }
}
