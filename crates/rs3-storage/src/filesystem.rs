//! Local filesystem `BlobStore` implementation.

use crate::read::{BLOB_READ_CHUNK_BYTES, BlobReadSource, exact_blob_read};
use crate::{
    BlobList, BlobListMode, BlobListPage, BlobMetadata, BlobRead, BlobStore, ByteRange, PutOptions,
    Result, StorageError, object_kind, prefix_kind, record_blob_delete,
    record_blob_extend_retention, record_blob_get, record_blob_head, record_blob_list,
    record_blob_put, record_blob_set_legal_hold,
};
use async_trait::async_trait;
use bytes::Bytes;
use rs3_types::{BackendObjectId, LegalHoldStatus, RetentionMode, RetentionPolicy};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::num::NonZeroUsize;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
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
        sync_directory_ancestors(&root, None).map_err(provider_error)?;
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
        let retained = options
            .retention
            .is_some_and(|policy| retention_is_active(&policy));
        let legal_hold_requested = options.legal_hold == Some(LegalHoldStatus::On);

        if retained || legal_hold_requested {
            record_blob_put(
                kind,
                requested_len,
                retained,
                if retained {
                    "retention_unsupported"
                } else {
                    "legal_hold_unsupported"
                },
                started.elapsed(),
            );
            return Err(if retained {
                StorageError::RetentionExtensionUnsupported
            } else {
                StorageError::LegalHoldUnsupported
            });
        }

        let path = self.object_path(object_id)?;
        let write_id = object_id.clone();
        let root = self.root.clone();
        let write = blocking_io(move || {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(provider_error)?;
            }
            write_file(&path, &body, options.do_not_recreate).map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    StorageError::AlreadyExists(write_id)
                } else {
                    provider_error(error)
                }
            })?;
            sync_directory_ancestors(parent_directory(&path)?, Some(&root)).map_err(provider_error)
        })
        .await;

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

        let body = match blocking_io(move || read_file_range(&path, range)).await {
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

    async fn open_range_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&rs3_types::BackendVersionId>,
        range: ByteRange,
    ) -> Result<Box<dyn BlobRead>> {
        if version_id.is_some() {
            return Err(StorageError::VersionUnsupported);
        }

        let started = Instant::now();
        let kind = object_kind(object_id).to_owned();
        let path = self.object_path(object_id)?;
        let (source, exact_len) = match blocking_io(move || open_file_range(&path, range)).await {
            Ok(opened) => opened,
            Err(StorageError::NotFound(_)) => {
                record_blob_get(&kind, range, 0, "not_found", started.elapsed());
                return Err(StorageError::NotFound(object_id.clone()));
            }
            Err(StorageError::InvalidRange) => {
                record_blob_get(&kind, range, 0, "invalid_range", started.elapsed());
                return Err(StorageError::InvalidRange);
            }
            Err(error) => {
                record_blob_get(&kind, range, 0, "error", started.elapsed());
                return Err(error);
            }
        };
        Ok(Box::new(ObservedFilesystemRead {
            inner: exact_blob_read(source, exact_len),
            kind,
            range,
            started,
            bytes_read: 0,
            terminal: false,
        }))
    }

    async fn open_bounded_full_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&rs3_types::BackendVersionId>,
        max_bytes: u64,
    ) -> Result<Box<dyn BlobRead>> {
        let read = self
            .open_range_at(object_id, version_id, ByteRange::Full)
            .await?;
        crate::read::enforce_full_read_bound(read, max_bytes)
    }

    async fn head(&self, object_id: &BackendObjectId) -> Result<BlobMetadata> {
        let started = Instant::now();
        let kind = object_kind(object_id);
        let path = self.object_path(object_id)?;
        let metadata = match blocking_io(move || Ok(fs::metadata(&path))).await? {
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
        let prefix_path = prefix_search_root(&self.root, prefix)?;

        let root = self.root.clone();
        let prefix = prefix.to_owned();
        let entries = blocking_io(move || {
            if !prefix_path.is_dir() {
                return Ok(Vec::new());
            }
            let mut entries = Vec::new();
            collect_files(&root, &prefix_path, &prefix, &mut entries)?;
            entries.sort_by(|left, right| left.object_id.cmp(&right.object_id));
            Ok(entries)
        })
        .await?;

        record_blob_list(kind, entries.len(), "ok", started.elapsed());
        Ok(entries)
    }

    async fn open_bounded_list(
        &self,
        prefix: &str,
        mode: BlobListMode,
    ) -> Result<Box<dyn BlobList>> {
        if mode == BlobListMode::Versions {
            return Err(StorageError::VersionUnsupported);
        }
        let prefix_path = prefix_search_root(&self.root, prefix)?;
        Ok(Box::new(FilesystemBlobList {
            cursor: Some(FilesystemListCursor {
                root: self.root.clone(),
                prefix: prefix.to_owned(),
                pending_root: Some(prefix_path),
                directories: Vec::new(),
                complete: false,
            }),
        }))
    }

    async fn delete(&self, object_id: &BackendObjectId) -> Result<()> {
        let started = Instant::now();
        let kind = object_kind(object_id);
        let path = self.object_path(object_id)?;
        let root = self.root.clone();
        match blocking_io(move || {
            Ok(fs::remove_file(&path).and_then(|()| {
                let parent = path
                    .parent()
                    .ok_or_else(|| std::io::Error::other("object path has no parent"))?;
                sync_directory_ancestors(parent, Some(&root))
            }))
        })
        .await?
        {
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
        if !blocking_io(move || Ok(path.is_file())).await? {
            record_blob_extend_retention(kind, "not_found", started.elapsed());
            return Err(StorageError::NotFound(object_id.clone()));
        }

        record_blob_extend_retention(kind, "unsupported", started.elapsed());
        Err(StorageError::RetentionExtensionUnsupported)
    }

    async fn set_legal_hold(
        &self,
        object_id: &BackendObjectId,
        _status: LegalHoldStatus,
    ) -> Result<()> {
        let started = Instant::now();
        let kind = object_kind(object_id);
        let path = self.object_path(object_id)?;
        if !blocking_io(move || Ok(path.is_file())).await? {
            record_blob_set_legal_hold(kind, "not_found", started.elapsed());
            return Err(StorageError::NotFound(object_id.clone()));
        }

        record_blob_set_legal_hold(kind, "unsupported", started.elapsed());
        Err(StorageError::LegalHoldUnsupported)
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

struct FilesystemBlobList {
    cursor: Option<FilesystemListCursor>,
}

struct FilesystemListCursor {
    root: PathBuf,
    prefix: String,
    pending_root: Option<PathBuf>,
    directories: Vec<fs::ReadDir>,
    complete: bool,
}

#[async_trait]
impl BlobList for FilesystemBlobList {
    async fn next_page(&mut self, max_items: NonZeroUsize) -> Result<BlobListPage> {
        blocking_cursor(&mut self.cursor, move |cursor| cursor.next_page(max_items)).await
    }
}

impl FilesystemListCursor {
    fn next_page(&mut self, max_items: NonZeroUsize) -> Result<BlobListPage> {
        if self.complete {
            return Ok(BlobListPage {
                entries: Vec::new(),
                consumed_items: 0,
                is_complete: true,
            });
        }

        let started = Instant::now();
        let kind = prefix_kind(&self.prefix);
        let mut entries = Vec::with_capacity(max_items.get().min(1_024));
        let mut consumed_items = 0;
        if let Some(root) = self.pending_root.take() {
            match fs::metadata(&root) {
                Ok(metadata) if metadata.is_dir() => {
                    self.directories
                        .push(fs::read_dir(root).map_err(provider_error)?);
                }
                Ok(metadata) if metadata.is_file() => {
                    consumed_items += 1;
                    let object_id = object_id_from_path(&self.root, &root)?;
                    if object_id.as_str().starts_with(&self.prefix) {
                        entries.push(blob_metadata(object_id, metadata));
                    }
                    self.complete = true;
                }
                Ok(_) => self.complete = true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    self.complete = true;
                }
                Err(error) => return Err(provider_error(error)),
            }
        }

        while consumed_items < max_items.get() && !self.complete {
            let Some(directory) = self.directories.last_mut() else {
                self.complete = true;
                break;
            };
            let Some(entry) = directory.next() else {
                self.directories.pop();
                continue;
            };
            let entry = entry.map_err(provider_error)?;
            consumed_items += 1;
            if is_temporary_name(&entry.file_name()) {
                continue;
            }
            let file_type = entry.file_type().map_err(provider_error)?;
            if file_type.is_dir() {
                self.directories
                    .push(fs::read_dir(entry.path()).map_err(provider_error)?);
            } else if file_type.is_file() {
                let object_id = object_id_from_path(&self.root, &entry.path())?;
                if object_id.as_str().starts_with(&self.prefix) {
                    entries.push(blob_metadata(
                        object_id,
                        entry.metadata().map_err(provider_error)?,
                    ));
                }
            }
        }

        record_blob_list(kind, entries.len(), "ok", started.elapsed());
        Ok(BlobListPage {
            entries,
            consumed_items,
            is_complete: self.complete,
        })
    }
}

struct FileReadSource {
    cursor: Option<FileReadCursor>,
}

struct FileReadCursor {
    file: File,
    range_remaining: Option<u64>,
}

#[async_trait]
impl BlobReadSource for FileReadSource {
    async fn next_source_chunk(&mut self) -> Result<Option<Bytes>> {
        blocking_cursor(&mut self.cursor, FileReadCursor::next_chunk).await
    }
}

impl FileReadCursor {
    fn next_chunk(&mut self) -> Result<Option<Bytes>> {
        if self.range_remaining == Some(0) {
            return Ok(None);
        }
        let limit = self
            .range_remaining
            .map_or(BLOB_READ_CHUNK_BYTES, |remaining| {
                usize::try_from(remaining)
                    .unwrap_or(usize::MAX)
                    .min(BLOB_READ_CHUNK_BYTES)
            });
        let mut buffer = vec![0_u8; limit];
        let read = self.file.read(&mut buffer).map_err(provider_error)?;
        if read == 0 {
            return Ok(None);
        }
        buffer.truncate(read);
        if let Some(remaining) = self.range_remaining.as_mut() {
            *remaining = remaining.saturating_sub(read as u64);
        }
        Ok(Some(Bytes::from(buffer)))
    }
}

struct ObservedFilesystemRead {
    inner: Box<dyn BlobRead>,
    kind: String,
    range: ByteRange,
    started: Instant,
    bytes_read: u64,
    terminal: bool,
}

#[async_trait]
impl BlobRead for ObservedFilesystemRead {
    fn exact_len(&self) -> u64 {
        self.inner.exact_len()
    }

    async fn next_chunk(&mut self) -> Result<Option<Bytes>> {
        match self.inner.next_chunk().await {
            Ok(Some(chunk)) => {
                self.bytes_read = self.bytes_read.saturating_add(chunk.len() as u64);
                Ok(Some(chunk))
            }
            Ok(None) => {
                self.record("ok");
                Ok(None)
            }
            Err(error) => {
                self.record("error");
                Err(error)
            }
        }
    }
}

impl ObservedFilesystemRead {
    fn record(&mut self, result: &str) {
        if self.terminal {
            return;
        }
        self.terminal = true;
        record_blob_get(
            &self.kind,
            self.range,
            self.bytes_read,
            result,
            self.started.elapsed(),
        );
    }
}

impl Drop for ObservedFilesystemRead {
    fn drop(&mut self) {
        self.record("cancelled");
    }
}

/// Runs filesystem syscalls off the async runtime's request workers.
async fn blocking_io<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| StorageError::Provider("filesystem worker failed".to_owned()))?
}

/// A canceled operation consumes its cursor. Reuse fails instead of silently
/// skipping bytes or inventory entries that a detached worker already consumed.
async fn blocking_cursor<T: Send + 'static, O: Send + 'static>(
    cursor: &mut Option<T>,
    operation: impl FnOnce(&mut T) -> Result<O> + Send + 'static,
) -> Result<O> {
    let mut owned = cursor.take().ok_or_else(|| {
        StorageError::Provider("filesystem cursor is no longer available".to_owned())
    })?;
    let (returned, result) = blocking_io(move || {
        let result = operation(&mut owned);
        Ok((owned, result))
    })
    .await?;
    *cursor = Some(returned);
    result
}

fn parent_directory(path: &Path) -> Result<&Path> {
    path.parent()
        .ok_or_else(|| StorageError::Provider("object path has no parent".to_owned()))
}

fn sync_directory_ancestors(path: &Path, stop: Option<&Path>) -> std::io::Result<()> {
    for directory in path.ancestors() {
        // The empty parent of a relative path denotes the current directory.
        let directory = if directory.as_os_str().is_empty() {
            Path::new(".")
        } else {
            directory
        };
        File::open(directory)?.sync_all()?;
        if Some(directory) == stop {
            break;
        }
    }
    Ok(())
}

fn write_file(path: &Path, body: &[u8], create_only: bool) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("object path has no parent"))?;
    let temp_path = parent.join(temp_file_name());
    // Only clean up a temporary file whose exclusive creation succeeded.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)?;
    let result = (|| {
        file.write_all(body)?;
        file.sync_all()?;
        if create_only {
            // Linking a fully written inode publishes atomically and refuses to
            // replace a concurrently published object.
            fs::hard_link(&temp_path, path)?;
            fs::remove_file(&temp_path)
        } else {
            fs::rename(&temp_path, path)
        }
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

fn open_file_range(path: &Path, range: ByteRange) -> Result<(FileReadSource, u64)> {
    let mut file = File::open(path).map_err(|error| map_read_error(path, error))?;
    let file_len = file.metadata().map_err(provider_error)?.len();
    let (offset, exact_len, range_remaining) = match range {
        ByteRange::Full => (0, file_len, None),
        ByteRange::Slice { offset, len } => {
            let end = offset.checked_add(len).ok_or(StorageError::InvalidRange)?;
            if offset > file_len || end > file_len {
                return Err(StorageError::InvalidRange);
            }
            (offset, len, Some(len))
        }
    };
    file.seek(SeekFrom::Start(offset)).map_err(provider_error)?;
    Ok((
        FileReadSource {
            cursor: Some(FileReadCursor {
                file,
                range_remaining,
            }),
        },
        exact_len,
    ))
}

fn prefix_search_root(root: &Path, prefix: &str) -> Result<PathBuf> {
    // A string prefix may end in the middle of a filename or directory name.
    // Start at its last complete directory component and filter actual keys.
    safe_relative_path(prefix)?;
    match prefix.rfind('/') {
        Some(index) => Ok(root.join(safe_relative_path(&prefix[..index])?)),
        None => Ok(root.to_path_buf()),
    }
}

fn is_temporary_name(name: &std::ffi::OsStr) -> bool {
    name.to_string_lossy().starts_with(".rs3-tmp-")
}

fn collect_files(
    root: &Path,
    directory: &Path,
    prefix: &str,
    entries: &mut Vec<BlobMetadata>,
) -> Result<()> {
    for entry in fs::read_dir(directory).map_err(provider_error)? {
        let entry = entry.map_err(provider_error)?;
        if is_temporary_name(&entry.file_name()) {
            continue;
        }
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
        retain_until_ms: None,
        legal_hold: None,
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
    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos();
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    format!(".rs3-tmp-{}-{nanos}-{id}", std::process::id())
}

fn system_time_millis(time: SystemTime) -> Option<i64> {
    let millis = time.duration_since(UNIX_EPOCH).ok()?.as_millis();
    i64::try_from(millis).ok()
}

fn retention_is_active(policy: &RetentionPolicy) -> bool {
    policy.mode != RetentionMode::None && policy.retain_days > 0
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
    use crate::{BlobListMode, BlobStore, ByteRange, PutOptions, StorageError};
    use bytes::Bytes;
    use rs3_types::{BackendObjectId, RetentionMode, RetentionPolicy};
    use std::num::NonZeroUsize;
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

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_filesystem_worker_does_not_block_runtime_or_skip_cursor_state() {
        let mut cursor = Some(0);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        {
            let operation = super::blocking_cursor(&mut cursor, move |value| {
                let _ = started_tx.send(());
                release_rx
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .expect("worker release");
                *value += 1;
                let _ = finished_tx.send(());
                Ok(())
            });
            tokio::pin!(operation);
            tokio::select! {
                started = started_rx => started.expect("worker started without blocking runtime"),
                result = &mut operation => panic!("worker completed before release: {result:?}"),
            }
            // Drop the pending operation, as a disconnected request would.
        }
        release_tx.send(()).expect("release detached worker");
        finished_rx.await.expect("detached worker finished");
        assert!(
            super::blocking_cursor(&mut cursor, |_| Ok(()))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn concurrent_create_only_publishes_one_complete_inode() {
        let dir = TestDir::new();
        let store = FilesystemBlobStore::new(dir.path()).expect("store");
        let id = object_id("nested/objects/create-only");
        let first = Bytes::from(vec![0x11; 2 * 1024 * 1024]);
        let second = Bytes::from(vec![0x22; 2 * 1024 * 1024]);
        let options = PutOptions {
            do_not_recreate: true,
            ..PutOptions::default()
        };
        let (left, right) = tokio::join!(
            store.put(&id, first.clone(), options.clone()),
            store.put(&id, second.clone(), options),
        );
        let expected = match (left, right) {
            (Ok(_), Err(StorageError::AlreadyExists(_))) => first,
            (Err(StorageError::AlreadyExists(_)), Ok(_)) => second,
            other => panic!("expected exactly one create-only winner: {other:?}"),
        };
        assert_eq!(
            store
                .get_range(&id, ByteRange::Full)
                .await
                .expect("read winner"),
            expected
        );
        let names = std::fs::read_dir(dir.path().join("nested/objects"))
            .expect("directory")
            .map(|entry| entry.expect("entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(names, vec![std::ffi::OsString::from("create-only")]);
    }

    #[tokio::test]
    async fn replacement_preserves_an_already_open_read() {
        let dir = TestDir::new();
        let store = FilesystemBlobStore::new(dir.path()).expect("store");
        let id = object_id("objects/replaced");
        let original = Bytes::from(vec![0x31; super::BLOB_READ_CHUNK_BYTES + 13]);
        store
            .put(&id, original.clone(), PutOptions::default())
            .await
            .expect("initial put");
        let read = store
            .open_range_at(&id, None, ByteRange::Full)
            .await
            .expect("open old inode");
        store
            .put(&id, Bytes::from_static(b"new"), PutOptions::default())
            .await
            .expect("replace");
        let actual = crate::collect_bounded_blob_read(read, original.len() as u64)
            .await
            .expect("read original inode");
        assert_eq!(actual, original);
        assert_eq!(
            store
                .get_range(&id, ByteRange::Full)
                .await
                .expect("read current"),
            Bytes::from_static(b"new")
        );
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
    async fn filesystem_store_pages_prefixes_with_a_hard_bound() {
        let dir = TestDir::new();
        let store = FilesystemBlobStore::new(dir.path()).unwrap_or_else(|error| panic!("{error}"));
        for name in [
            "segments/one/a",
            "segments/one/b",
            "segments/two/c",
            "index/a",
        ] {
            store
                .put(
                    &object_id(name),
                    Bytes::from_static(b"body"),
                    PutOptions::default(),
                )
                .await
                .unwrap_or_else(|error| panic!("put object: {error}"));
        }
        let mut listing = store
            .open_bounded_list("segments/", BlobListMode::Current)
            .await
            .unwrap_or_else(|error| panic!("open listing: {error}"));
        let page_size = NonZeroUsize::new(2).unwrap_or_else(|| panic!("non-zero page size"));
        let mut listed = Vec::new();
        loop {
            let page = listing
                .next_page(page_size)
                .await
                .unwrap_or_else(|error| panic!("read page: {error}"));
            assert!(page.entries.len() <= page_size.get());
            listed.extend(page.entries.into_iter().map(|metadata| metadata.object_id));
            if page.is_complete {
                break;
            }
        }
        listed.sort();

        assert_eq!(
            listed,
            vec![
                object_id("segments/one/a"),
                object_id("segments/one/b"),
                object_id("segments/two/c")
            ]
        );
        assert!(matches!(
            store
                .open_bounded_list("segments/", BlobListMode::Versions)
                .await,
            Err(StorageError::VersionUnsupported)
        ));
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

    #[tokio::test]
    async fn filesystem_streams_full_and_sliced_reads_in_bounded_chunks() {
        let dir = TestDir::new();
        let store = FilesystemBlobStore::new(dir.path()).unwrap_or_else(|error| panic!("{error}"));
        let object_id = object_id("segments/streamed");
        let body = Bytes::from(vec![9_u8; super::BLOB_READ_CHUNK_BYTES + 17]);
        store
            .put(&object_id, body.clone(), PutOptions::default())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut full = store
            .open_range_at(&object_id, None, ByteRange::Full)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(full.exact_len(), body.len() as u64);
        let first = full
            .next_chunk()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .expect("first chunk");
        let second = full
            .next_chunk()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .expect("second chunk");
        assert_eq!(first.len(), super::BLOB_READ_CHUNK_BYTES);
        assert_eq!(second.len(), 17);
        assert_eq!(full.next_chunk().await, Ok(None));

        let mut slice = store
            .open_range_at(
                &object_id,
                None,
                ByteRange::Slice {
                    offset: body.len() as u64 - 9,
                    len: 9,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(slice.exact_len(), 9);
        assert_eq!(
            slice.next_chunk().await,
            Ok(Some(Bytes::from_static(&[9_u8; 9])))
        );
        assert_eq!(slice.next_chunk().await, Ok(None));
    }

    #[tokio::test]
    async fn filesystem_stream_detects_truncation_after_open() {
        let dir = TestDir::new();
        let store = FilesystemBlobStore::new(dir.path()).unwrap_or_else(|error| panic!("{error}"));
        let object_id = object_id("segments/truncated");
        store
            .put(
                &object_id,
                Bytes::from_static(b"original"),
                PutOptions::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let mut read = store
            .open_range_at(&object_id, None, ByteRange::Full)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        std::fs::OpenOptions::new()
            .write(true)
            .open(dir.path().join(object_id.as_str()))
            .and_then(|file| file.set_len(3))
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            read.next_chunk().await,
            Ok(Some(Bytes::from_static(b"ori")))
        );
        assert!(matches!(
            read.next_chunk().await,
            Err(StorageError::Provider(message)) if message.contains("before its exact length")
        ));
    }

    #[tokio::test]
    async fn filesystem_stream_never_emits_bytes_appended_after_open() {
        let dir = TestDir::new();
        let store = FilesystemBlobStore::new(dir.path()).unwrap_or_else(|error| panic!("{error}"));
        let object_id = object_id("segments/extended");
        store
            .put(
                &object_id,
                Bytes::from_static(b"abc"),
                PutOptions::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let mut read = store
            .open_range_at(&object_id, None, ByteRange::Full)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.path().join(object_id.as_str()))
            .unwrap_or_else(|error| panic!("{error}"));
        file.write_all(b"d")
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(matches!(
            read.next_chunk().await,
            Err(StorageError::Provider(message)) if message.contains("exceeded its exact length")
        ));
        assert_eq!(read.next_chunk().await, Ok(None));
    }
}
