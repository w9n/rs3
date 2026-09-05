//! Provider-neutral `BlobStore` contract tests.

mod common;

use bytes::Bytes;
use common::assert_core_blob_store_contract_with_create_only;
use rs3_storage::{
    BlobStore, ByteRange, FilesystemBlobStore, MemoryBlobStore, PutOptions, StorageError,
};
use rs3_types::{LegalHoldStatus, RetentionMode, RetentionPolicy};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[tokio::test]
async fn memory_store_satisfies_core_contract() {
    let store = MemoryBlobStore::new();

    assert_core_blob_store_contract_with_create_only(&store, "memory", true).await;
}

#[tokio::test]
async fn filesystem_store_satisfies_core_contract() {
    let dir = TestDir::new("filesystem-contract");
    let store = FilesystemBlobStore::new(dir.path()).unwrap_or_else(|error| panic!("{error}"));

    assert_core_blob_store_contract_with_create_only(&store, "filesystem", true).await;
}

#[tokio::test]
async fn memory_store_multipart_upload_round_trips() {
    let store = MemoryBlobStore::new();
    let object_id = common::object_id("memory-multipart/object");
    let mut upload = store
        .create_multipart_upload(&object_id, PutOptions::default())
        .await
        .unwrap_or_else(|error| panic!("create multipart upload: {error}"));

    upload
        .put_part(1, Bytes::from_static(b"world"))
        .await
        .unwrap_or_else(|error| panic!("put second multipart part: {error}"));
    upload
        .put_part(0, Bytes::from_static(b"hello "))
        .await
        .unwrap_or_else(|error| panic!("put first multipart part: {error}"));
    let metadata = upload
        .complete()
        .await
        .unwrap_or_else(|error| panic!("complete multipart upload: {error}"));
    let body = store
        .get_range(&object_id, ByteRange::Full)
        .await
        .unwrap_or_else(|error| panic!("read completed multipart object: {error}"));
    let counts = store
        .operation_counts()
        .unwrap_or_else(|error| panic!("read operation counts: {error}"));

    assert_eq!(metadata.content_len, 11);
    assert_eq!(body, Bytes::from_static(b"hello world"));
    assert_eq!(counts.multipart_put, 1);
}

#[tokio::test]
async fn stores_ignore_inactive_retention_on_put() {
    let memory = MemoryBlobStore::new();
    assert_inactive_retention_put_is_unretained(&memory, "memory-inactive-retention").await;

    let dir = TestDir::new("filesystem-inactive-retention");
    let filesystem = FilesystemBlobStore::new(dir.path()).unwrap_or_else(|error| panic!("{error}"));
    assert_inactive_retention_put_is_unretained(&filesystem, "filesystem-inactive-retention").await;
}

#[tokio::test]
async fn memory_store_lists_and_deletes_exact_versions() {
    let store = MemoryBlobStore::new();
    let object_id = common::object_id("memory-versioned/object");

    let first = store
        .put(
            &object_id,
            Bytes::from_static(b"first-version"),
            PutOptions::default(),
        )
        .await
        .unwrap_or_else(|error| panic!("put first version: {error}"));
    let second = store
        .put(
            &object_id,
            Bytes::from_static(b"second-version"),
            PutOptions::default(),
        )
        .await
        .unwrap_or_else(|error| panic!("put second version: {error}"));

    let versions = store
        .list_prefix_versions("memory-versioned/")
        .await
        .unwrap_or_else(|error| panic!("list exact versions: {error}"));
    let listed_versions = versions
        .iter()
        .map(|metadata| metadata.version_id.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        listed_versions,
        vec![first.version_id.clone(), second.version_id.clone()]
    );

    store
        .delete_at(&object_id, first.version_id.as_ref())
        .await
        .unwrap_or_else(|error| panic!("delete first exact version: {error}"));
    assert!(matches!(
        store.head_at(&object_id, first.version_id.as_ref()).await,
        Err(StorageError::NotFound(_))
    ));
    let latest = store
        .get_range(&object_id, rs3_storage::ByteRange::Full)
        .await
        .unwrap_or_else(|error| panic!("read latest after exact delete: {error}"));
    assert_eq!(latest, Bytes::from_static(b"second-version"));
}

#[tokio::test]
async fn memory_store_blocks_exact_version_delete_when_protected() {
    let store = MemoryBlobStore::new();
    let retained = common::object_id("memory-versioned/retained");
    let held = common::object_id("memory-versioned/held");

    let retained_put = store
        .put(
            &retained,
            Bytes::from_static(b"retained"),
            PutOptions {
                retention: Some(RetentionPolicy::new(RetentionMode::Governance, 1)),
                ..PutOptions::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("put retained version: {error}"));
    let held_put = store
        .put(
            &held,
            Bytes::from_static(b"held"),
            PutOptions {
                legal_hold: Some(LegalHoldStatus::On),
                ..PutOptions::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("put held version: {error}"));

    assert_eq!(
        store
            .delete_at(&retained, retained_put.version_id.as_ref())
            .await,
        Err(StorageError::RetentionBlocked)
    );
    assert_eq!(
        store.delete_at(&held, held_put.version_id.as_ref()).await,
        Err(StorageError::LegalHoldBlocked)
    );
}

#[tokio::test]
async fn filesystem_store_rejects_exact_version_inventory() {
    let dir = TestDir::new("filesystem-version-contract");
    let store = FilesystemBlobStore::new(dir.path()).unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(
        store.list_prefix_versions("anything/").await,
        Err(StorageError::VersionUnsupported)
    );
}

#[tokio::test]
async fn filesystem_inventory_excludes_temporary_files_and_counts_filtered_members() {
    use rs3_storage::BlobListMode;
    use std::num::NonZeroUsize;
    let dir = TestDir::new("temporary-inventory");
    let store = FilesystemBlobStore::new(dir.path()).expect("store");
    let key = common::object_id("segments/visible");
    store
        .put(&key, Bytes::from_static(b"value"), PutOptions::default())
        .await
        .expect("object");
    std::fs::write(dir.path().join("segments/.rs3-tmp-fixture"), b"incomplete")
        .expect("temporary file");
    assert_eq!(
        store
            .list_prefix("segments/")
            .await
            .expect("list")
            .into_iter()
            .map(|m| m.object_id)
            .collect::<Vec<_>>(),
        vec![key.clone()]
    );
    let mut pages = store
        .open_bounded_list("segments/", BlobListMode::Current)
        .await
        .expect("pages");
    let mut items = Vec::new();
    let mut consumed = 0;
    let mut complete = false;
    for _ in 0..4 {
        let page = pages
            .next_page(NonZeroUsize::new(1).expect("nonzero"))
            .await
            .expect("page");
        assert!(page.entries.len() <= page.consumed_items);
        assert!(page.consumed_items <= 1);
        consumed += page.consumed_items;
        items.extend(page.entries.into_iter().map(|entry| entry.object_id));
        if page.is_complete {
            complete = true;
            break;
        }
    }
    assert!(complete);
    assert_eq!(consumed, 2);
    assert_eq!(items, vec![key]);
}

async fn assert_inactive_retention_put_is_unretained<S>(store: &S, prefix: &str)
where
    S: BlobStore,
{
    for (index, retention) in [
        RetentionPolicy::new(RetentionMode::None, 30),
        RetentionPolicy::new(RetentionMode::Governance, 0),
    ]
    .into_iter()
    .enumerate()
    {
        let object_id = common::object_id(&format!("{prefix}/{index}"));
        let metadata = store
            .put(
                &object_id,
                Bytes::from_static(b"inactive-retention"),
                PutOptions {
                    retention: Some(retention),
                    ..PutOptions::default()
                },
            )
            .await
            .unwrap_or_else(|error| panic!("inactive retention put should be accepted: {error}"));

        assert_eq!(metadata.retention, None);
        assert_eq!(metadata.retain_until_ms, None);
    }
}

struct TestDir {
    path: PathBuf,
}

#[tokio::test]
async fn current_delete_preserves_protected_older_versions_and_allows_recreation() {
    common::assert_current_delete_preserves_protected_versions(&MemoryBlobStore::new(), "memory")
        .await;
}

#[tokio::test]
async fn rejected_multipart_parts_preserve_the_upload() {
    common::assert_multipart_rejection_preserves_parts(&MemoryBlobStore::new(), "memory").await;
}

#[tokio::test]
async fn version_pages_count_delete_markers_and_survive_earlier_version_deletion() {
    use rs3_storage::BlobListMode;
    use std::num::NonZeroUsize;
    let store = MemoryBlobStore::new();
    let key = common::object_id("paged-history/object");
    let first = store
        .put(&key, Bytes::from_static(b"one"), PutOptions::default())
        .await
        .expect("first");
    let second = store
        .put(&key, Bytes::from_static(b"two"), PutOptions::default())
        .await
        .expect("second");
    store.delete(&key).await.expect("marker");
    let mut list = store
        .open_bounded_list("paged-history/", BlobListMode::Versions)
        .await
        .expect("list");
    let one = NonZeroUsize::new(1).expect("nonzero");
    let page = list.next_page(one).await.expect("first page");
    assert_eq!(page.entries, vec![first.clone()]);
    assert_eq!(page.consumed_items, 1);
    assert!(!page.is_complete);
    store
        .delete_at(&key, first.version_id.as_ref())
        .await
        .expect("remove emitted version");
    let page = list.next_page(one).await.expect("second page");
    assert_eq!(page.entries, vec![second]);
    assert_eq!(page.consumed_items, 1);
    assert!(!page.is_complete);
    let page = list.next_page(one).await.expect("marker page");
    assert!(page.entries.is_empty());
    assert_eq!(page.consumed_items, 1);
    assert!(page.is_complete);
    let page = list.next_page(one).await.expect("terminal page");
    assert_eq!(page.consumed_items, 0);
    assert!(page.entries.is_empty());
    assert!(page.is_complete);
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
