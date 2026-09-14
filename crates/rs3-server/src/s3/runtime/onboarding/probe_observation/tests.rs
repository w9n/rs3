use super::*;
use rs3_storage::{BlobList, BlobListPage, BlobMetadata, ByteRange, PutOptions, StorageError};
use rs3_types::{BackendVersionId, LegalHoldStatus};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

struct Fixture {
    pages: Arc<Mutex<VecDeque<BlobListPage>>>,
    limits: Arc<Mutex<Vec<usize>>>,
    heads: Mutex<Vec<(BackendObjectId, Option<BackendVersionId>)>>,
    metadata: BTreeMap<(BackendObjectId, Option<BackendVersionId>), BlobMetadata>,
    fail_open: bool,
    fail_head: bool,
    wrong_head: bool,
}

impl Fixture {
    fn new(pages: Vec<BlobListPage>) -> Self {
        let metadata = pages
            .iter()
            .flat_map(|page| &page.entries)
            .map(|entry| {
                (
                    (entry.object_id.clone(), entry.version_id.clone()),
                    entry.clone(),
                )
            })
            .collect();
        Self {
            pages: Arc::new(Mutex::new(pages.into())),
            limits: Arc::new(Mutex::new(Vec::new())),
            heads: Mutex::new(Vec::new()),
            metadata,
            fail_open: false,
            fail_head: false,
            wrong_head: false,
        }
    }
}
struct Pages {
    pages: Arc<Mutex<VecDeque<BlobListPage>>>,
    limits: Arc<Mutex<Vec<usize>>>,
}
#[async_trait::async_trait]
impl BlobList for Pages {
    async fn next_page(&mut self, limit: NonZeroUsize) -> rs3_storage::Result<BlobListPage> {
        self.limits.lock().expect("limits").push(limit.get());
        Ok(self
            .pages
            .lock()
            .expect("pages")
            .pop_front()
            .expect("unexpected extra LIST"))
    }
}
#[async_trait::async_trait]
impl BlobStore for Fixture {
    async fn flush_caches(&self) -> rs3_storage::Result<()> {
        panic!("observation must not flush caches")
    }
    async fn put(
        &self,
        _: &BackendObjectId,
        _: Bytes,
        _: PutOptions,
    ) -> rs3_storage::Result<BlobMetadata> {
        panic!("observation must not PUT")
    }
    async fn get_range(&self, _: &BackendObjectId, _: ByteRange) -> rs3_storage::Result<Bytes> {
        panic!("observation must not read payloads")
    }
    async fn head(&self, _: &BackendObjectId) -> rs3_storage::Result<BlobMetadata> {
        panic!("observation must use exact HEAD")
    }
    async fn list_prefix(&self, _: &str) -> rs3_storage::Result<Vec<BlobMetadata>> {
        panic!("observation must use bounded LIST")
    }
    async fn delete(&self, _: &BackendObjectId) -> rs3_storage::Result<()> {
        panic!("observation must not DELETE")
    }
    async fn extend_retention(
        &self,
        _: &BackendObjectId,
        _: RetentionPolicy,
    ) -> rs3_storage::Result<()> {
        panic!("observation must not renew")
    }
    async fn set_legal_hold(
        &self,
        _: &BackendObjectId,
        _: LegalHoldStatus,
    ) -> rs3_storage::Result<()> {
        panic!("observation must not change holds")
    }
    async fn open_bounded_list(
        &self,
        prefix: &str,
        mode: BlobListMode,
    ) -> rs3_storage::Result<Box<dyn BlobList>> {
        assert_eq!(prefix, "");
        assert_eq!(mode, BlobListMode::Versions);
        if self.fail_open {
            return Err(StorageError::PagedListingUnsupported);
        }
        Ok(Box::new(Pages {
            pages: Arc::clone(&self.pages),
            limits: Arc::clone(&self.limits),
        }))
    }
    async fn head_at(
        &self,
        id: &BackendObjectId,
        version: Option<&BackendVersionId>,
    ) -> rs3_storage::Result<BlobMetadata> {
        let key = (id.clone(), version.cloned());
        self.heads.lock().expect("heads").push(key.clone());
        if self.fail_head {
            return Err(StorageError::Provider("fixture failure".to_owned()));
        }
        let mut value = self
            .metadata
            .get(&key)
            .expect("listed exact identity")
            .clone();
        if self.wrong_head {
            value.version_id = Some(BackendVersionId::new("wrong").expect("version"));
        }
        Ok(value)
    }
}

fn metadata(number: usize) -> BlobMetadata {
    BlobMetadata {
        object_id: BackendObjectId::new(format!("1/checks/value-{number}")).expect("id"),
        version_id: Some(BackendVersionId::new(format!("version-{number}")).expect("version")),
        content_len: 10,
        modified_at_ms: None,
        etag: None,
        retention: Some(RetentionPolicy::new(RetentionMode::Compliance, 30)),
        retain_until_ms: Some(100 + number as i64),
        legal_hold: None,
    }
}
fn page(entries: Vec<BlobMetadata>, complete: bool) -> BlobListPage {
    BlobListPage {
        consumed_items: entries.len(),
        entries,
        is_complete: complete,
    }
}

#[tokio::test]
async fn exact_metadata_observation_deduplicates_versions_and_reports_deadlines_and_holds() {
    let first = metadata(1);
    let mut held = metadata(2);
    held.retention = None;
    held.retain_until_ms = None;
    held.legal_hold = Some(LegalHoldStatus::On);
    let mut unreported = metadata(3);
    unreported.retention = None;
    unreported.retain_until_ms = None;
    let store = Fixture::new(vec![
        page(vec![first.clone(), held], false),
        page(vec![first, metadata(4), unreported], true),
    ]);
    let report = observe(&store, 2).await;
    assert!(report.listing_exhausted);
    assert_eq!(report.warning, None);
    assert_eq!(report.observed_versions, 4);
    assert_eq!(report.verified_metadata_versions, 4);
    assert_eq!(report.observed_bytes, 40);
    assert_eq!(report.retention_reported_versions, 2);
    assert_eq!(report.legal_hold_on_versions, 1);
    assert_eq!(report.unknown_protection_versions, 1);
    assert_eq!(report.earliest_retain_until_ms, Some(101));
    assert_eq!(report.latest_retain_until_ms, Some(104));
    assert_eq!(report.attempts_covered, 2);
    assert!(!report.multipart_sessions_observed);
    assert_eq!(store.heads.lock().expect("heads").len(), 4);
}

#[tokio::test]
async fn scope_missing_versions_and_wrong_head_identity_never_fall_back_to_latest() {
    for id in [
        "../repository/key",
        "4/checks/key",
        "0/checks/key",
        "01/checks/key",
        "1/checks/..",
        "1/checks/a/b",
        "1/checks/%2e",
        "1/other/key",
    ] {
        let mut value = metadata(1);
        value.object_id = BackendObjectId::new(id).expect("opaque id");
        let store = Fixture::new(vec![page(vec![value], true)]);
        assert_eq!(
            observe(&store, 3).await.warning.as_deref(),
            Some("invalid-inventory")
        );
        assert!(store.heads.lock().expect("heads").is_empty());
    }
    let mut value = metadata(1);
    value.version_id = None;
    let store = Fixture::new(vec![page(vec![value], true)]);
    let report = observe(&store, 1).await;
    assert_eq!(report.unknown_protection_versions, 1);
    assert_eq!(report.verified_metadata_versions, 0);
    assert!(store.heads.lock().expect("heads").is_empty());
    let mut store = Fixture::new(vec![page(vec![metadata(1)], true)]);
    store.wrong_head = true;
    let report = observe(&store, 1).await;
    assert_eq!(report.warning.as_deref(), Some("exact-head-unavailable"));
    assert_eq!(report.observed_bytes, 0);
}

#[tokio::test]
async fn head_page_and_raw_member_budgets_bound_all_work() {
    let store = Fixture::new(vec![
        page((0..32).map(metadata).collect(), false),
        page((32..64).map(metadata).collect(), true),
    ]);
    let report = observe(&store, 1).await;
    assert_eq!(report.warning.as_deref(), Some("head-budget"));
    assert!(!report.listing_exhausted);
    assert_eq!(store.heads.lock().expect("heads").len(), MAX_HEADS);
    for consumed in [0, 32] {
        let store = Fixture::new(
            (0..4)
                .map(|_| BlobListPage {
                    entries: vec![],
                    consumed_items: consumed,
                    is_complete: false,
                })
                .collect(),
        );
        assert_eq!(
            observe(&store, 1).await.warning.as_deref(),
            Some("list-budget")
        );
        assert_eq!(store.limits.lock().expect("limits").as_slice(), &[32; 4]);
    }
    let store = Fixture::new(vec![BlobListPage {
        entries: vec![metadata(1)],
        consumed_items: 0,
        is_complete: true,
    }]);
    assert_eq!(
        observe(&store, 1).await.warning.as_deref(),
        Some("invalid-inventory")
    );
    assert!(store.heads.lock().expect("heads").is_empty());
}

#[tokio::test]
async fn provider_failure_and_overflow_report_unknown_without_authorizing_cleanup() {
    let mut store = Fixture::new(vec![]);
    store.fail_open = true;
    let report = observe(&store, 1).await;
    assert_eq!(report.warning.as_deref(), Some("list-unavailable"));
    assert!(!report.listing_exhausted);
    let mut store = Fixture::new(vec![page(vec![metadata(1)], true)]);
    store.fail_head = true;
    let report = observe(&store, 1).await;
    assert_eq!(report.unknown_protection_versions, 1);
    assert_eq!(report.verified_metadata_versions, 0);
    let mut huge = metadata(1);
    huge.content_len = u64::MAX;
    let store = Fixture::new(vec![page(vec![huge, metadata(2)], true)]);
    let report = observe(&store, 1).await;
    assert_eq!(report.warning.as_deref(), Some("metadata-overflow"));
    assert_eq!(report.observed_bytes, u64::MAX);
}
