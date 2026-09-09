//! Bounded exact-version provider model with one controlled deadline clock.
//!
//! MemoryBlobStore owns real immutable bytes and version assignment. This
//! wrapper alone owns protection, so expiry actually permits exact deletion.
use super::*;
use std::collections::BTreeMap;

const MAX_VERSIONS: usize = 256;
const MAX_BYTES: u64 = 32 * 1024 * 1024;
const MAX_EVENTS: usize = 4096;

#[derive(Clone, Debug)]
pub(super) enum Mutation {
    Extend(BlobMetadata),
    Delete(BlobMetadata),
}

#[derive(Default)]
struct State {
    versions: BTreeMap<(BackendObjectId, BackendVersionId), BlobMetadata>,
    events: Vec<Mutation>,
    stored_bytes: u64,
}

#[derive(Clone)]
pub(super) struct ControlledDeadlineStore {
    inner: MemoryBlobStore,
    now: Arc<AtomicI64>,
    state: Arc<Mutex<State>>,
    max_versions: usize,
    max_bytes: u64,
    record_events: bool,
}

impl ControlledDeadlineStore {
    pub(super) fn new(now: i64) -> Self {
        Self {
            inner: MemoryBlobStore::new(),
            now: Arc::new(AtomicI64::new(now)),
            state: Arc::new(Mutex::new(State::default())),
            max_versions: MAX_VERSIONS,
            max_bytes: MAX_BYTES,
            record_events: true,
        }
    }

    /// Scale runs count operations separately and avoid retaining a per-call log.
    pub(super) fn for_scale(now: i64) -> Self {
        Self {
            max_versions: 2_000_000,
            max_bytes: 8 * 1024 * 1024 * 1024,
            record_events: false,
            ..Self::new(now)
        }
    }

    pub(super) fn occupancy(&self) -> (usize, u64) {
        let state = self.state.lock().expect("provider state");
        (state.versions.len(), state.stored_bytes)
    }

    /// Audit snapshots bypass the operation-counting wrapper deliberately.
    pub(super) fn inventory(&self) -> Vec<BlobMetadata> {
        self.state
            .lock()
            .expect("provider state")
            .versions
            .values()
            .cloned()
            .collect()
    }

    pub(super) fn latest_deadline(&self) -> i64 {
        self.state
            .lock()
            .expect("provider state")
            .versions
            .values()
            .filter_map(|entry| entry.retain_until_ms)
            .max()
            .expect("retained versions")
    }

    pub(super) fn now(&self) -> i64 {
        self.now.load(Ordering::SeqCst)
    }

    pub(super) fn advance_to(&self, now: i64) {
        assert!(now >= self.now(), "provider clock is monotonic");
        self.now.store(now, Ordering::SeqCst);
    }

    pub(super) fn events(&self) -> Vec<Mutation> {
        self.state.lock().expect("provider state").events.clone()
    }

    fn projected(&self, metadata: BlobMetadata) -> BlobMetadata {
        let version = metadata.version_id.clone().expect("memory exact version");
        let mut exact = self
            .state
            .lock()
            .expect("provider state")
            .versions
            .get(&(metadata.object_id, version))
            .expect("all versions have protection state")
            .clone();
        // Match our S3 adapter's remaining-day projection, preserving the absolute
        // deadline and original mode, including after protection expires.
        if let (Some(policy), Some(deadline)) = (exact.retention, exact.retain_until_ms) {
            let remaining = deadline.saturating_sub(self.now()).max(0);
            let days = u32::try_from((remaining + DAY - 1) / DAY).expect("bounded duration");
            exact.retention = Some(RetentionPolicy::new(policy.mode, days));
        }
        exact
    }

    fn record(&self, event: Mutation) {
        if !self.record_events {
            return;
        }
        let mut state = self.state.lock().expect("provider state");
        assert!(state.events.len() < MAX_EVENTS, "bounded mutation journal");
        state.events.push(event);
    }
}

struct ProjectedList {
    inner: Box<dyn BlobList>,
    store: ControlledDeadlineStore,
}

#[async_trait::async_trait]
impl BlobList for ProjectedList {
    async fn next_page(&mut self, limit: NonZeroUsize) -> rs3_storage::Result<BlobListPage> {
        let mut page = self.inner.next_page(limit).await?;
        page.entries = page
            .entries
            .into_iter()
            .map(|entry| self.store.projected(entry))
            .collect();
        Ok(page)
    }
}

#[async_trait::async_trait]
impl BlobStore for ControlledDeadlineStore {
    async fn put(
        &self,
        id: &BackendObjectId,
        body: Bytes,
        mut options: PutOptions,
    ) -> rs3_storage::Result<BlobMetadata> {
        {
            let state = self.state.lock().expect("provider state");
            assert!(
                state.versions.len() < self.max_versions,
                "bounded version count"
            );
            assert!(
                state.stored_bytes + body.len() as u64 <= self.max_bytes,
                "bounded stored bytes"
            );
        }
        let retention = options.retention.take();
        let hold = options.legal_hold.take();
        let mut metadata = self.inner.put(id, body, options).await?;
        metadata.modified_at_ms = Some(self.now());
        metadata.retention = retention;
        metadata.legal_hold = hold;
        metadata.retain_until_ms = retention.map(|policy| {
            self.now()
                .checked_add(i64::from(policy.retain_days) * DAY)
                .expect("bounded deadline")
        });
        let mut state = self.state.lock().expect("provider state");
        state.stored_bytes += metadata.content_len;
        assert!(
            state
                .versions
                .insert(
                    (
                        id.clone(),
                        metadata.version_id.clone().expect("exact version"),
                    ),
                    metadata.clone(),
                )
                .is_none(),
            "new exact version"
        );
        Ok(metadata)
    }

    async fn get_range(
        &self,
        id: &BackendObjectId,
        range: ByteRange,
    ) -> rs3_storage::Result<Bytes> {
        self.inner.get_range(id, range).await
    }
    async fn get_range_at(
        &self,
        id: &BackendObjectId,
        version: Option<&BackendVersionId>,
        range: ByteRange,
    ) -> rs3_storage::Result<Bytes> {
        self.inner.get_range_at(id, version, range).await
    }
    async fn open_range_at(
        &self,
        id: &BackendObjectId,
        version: Option<&BackendVersionId>,
        range: ByteRange,
    ) -> rs3_storage::Result<Box<dyn BlobRead>> {
        self.inner.open_range_at(id, version, range).await
    }
    async fn open_bounded_full_at(
        &self,
        id: &BackendObjectId,
        version: Option<&BackendVersionId>,
        max: u64,
    ) -> rs3_storage::Result<Box<dyn BlobRead>> {
        self.inner.open_bounded_full_at(id, version, max).await
    }
    async fn head(&self, id: &BackendObjectId) -> rs3_storage::Result<BlobMetadata> {
        self.head_at(id, None).await
    }
    async fn head_at(
        &self,
        id: &BackendObjectId,
        version: Option<&BackendVersionId>,
    ) -> rs3_storage::Result<BlobMetadata> {
        Ok(self.projected(self.inner.head_at(id, version).await?))
    }
    async fn list_prefix(&self, prefix: &str) -> rs3_storage::Result<Vec<BlobMetadata>> {
        Ok(self
            .inner
            .list_prefix(prefix)
            .await?
            .into_iter()
            .map(|entry| self.projected(entry))
            .collect())
    }
    async fn list_prefix_versions(&self, prefix: &str) -> rs3_storage::Result<Vec<BlobMetadata>> {
        Ok(self
            .inner
            .list_prefix_versions(prefix)
            .await?
            .into_iter()
            .map(|entry| self.projected(entry))
            .collect())
    }
    async fn open_bounded_list(
        &self,
        prefix: &str,
        mode: BlobListMode,
    ) -> rs3_storage::Result<Box<dyn BlobList>> {
        Ok(Box::new(ProjectedList {
            inner: self.inner.open_bounded_list(prefix, mode).await?,
            store: self.clone(),
        }))
    }

    async fn delete(&self, id: &BackendObjectId) -> rs3_storage::Result<()> {
        self.delete_at(id, None).await
    }
    async fn delete_at(
        &self,
        id: &BackendObjectId,
        version: Option<&BackendVersionId>,
    ) -> rs3_storage::Result<()> {
        let exact = self.head_at(id, version).await?;
        if exact.legal_hold == Some(LegalHoldStatus::On) {
            return Err(StorageError::LegalHoldBlocked);
        }
        if exact
            .retain_until_ms
            .is_some_and(|deadline| deadline > self.now())
        {
            return Err(StorageError::RetentionBlocked);
        }
        self.inner.delete_at(id, exact.version_id.as_ref()).await?;
        {
            let mut state = self.state.lock().expect("provider state");
            let removed = state
                .versions
                .remove(&(id.clone(), exact.version_id.clone().expect("exact version")))
                .expect("deleted version");
            state.stored_bytes -= removed.content_len;
        }
        self.record(Mutation::Delete(exact));
        Ok(())
    }

    async fn extend_retention(
        &self,
        id: &BackendObjectId,
        policy: RetentionPolicy,
    ) -> rs3_storage::Result<()> {
        self.extend_retention_at(id, None, policy).await
    }
    async fn extend_retention_at(
        &self,
        id: &BackendObjectId,
        version: Option<&BackendVersionId>,
        policy: RetentionPolicy,
    ) -> rs3_storage::Result<()> {
        let exact = self.head_at(id, version).await?;
        {
            let mut state = self.state.lock().expect("provider state");
            let stored = state
                .versions
                .get_mut(&(id.clone(), exact.version_id.expect("exact version")))
                .expect("exact state");
            let mode = if stored
                .retention
                .is_some_and(|old| old.mode == RetentionMode::Compliance)
            {
                RetentionMode::Compliance
            } else {
                policy.mode
            };
            stored.retention = Some(RetentionPolicy::new(mode, policy.retain_days));
            let requested = self
                .now()
                .checked_add(i64::from(policy.retain_days) * DAY)
                .expect("bounded deadline");
            stored.retain_until_ms = Some(
                stored
                    .retain_until_ms
                    .map_or(requested, |old| old.max(requested)),
            );
        }
        self.record(Mutation::Extend(self.head_at(id, version).await?));
        Ok(())
    }

    async fn set_legal_hold(
        &self,
        id: &BackendObjectId,
        hold: LegalHoldStatus,
    ) -> rs3_storage::Result<()> {
        self.set_legal_hold_at(id, None, hold).await
    }
    async fn set_legal_hold_at(
        &self,
        id: &BackendObjectId,
        version: Option<&BackendVersionId>,
        hold: LegalHoldStatus,
    ) -> rs3_storage::Result<()> {
        let exact = self.head_at(id, version).await?;
        self.state
            .lock()
            .expect("provider state")
            .versions
            .get_mut(&(id.clone(), exact.version_id.expect("exact version")))
            .expect("exact state")
            .legal_hold = Some(hold);
        Ok(())
    }
    async fn flush_caches(&self) -> rs3_storage::Result<()> {
        self.inner.flush_caches().await
    }
}

#[tokio::test]
async fn recovery_acceptance_provider_enforces_exact_deadlines_and_hold() {
    let store = ControlledDeadlineStore::new(1_000_000);
    let id = must_type(BackendObjectId::new("controlled-provider"));
    let first = store
        .put(
            &id,
            Bytes::from_static(b"original"),
            PutOptions {
                retention: Some(RetentionPolicy::new(RetentionMode::Compliance, 2)),
                ..PutOptions::default()
            },
        )
        .await
        .expect("put");
    let other = store
        .put(
            &id,
            Bytes::from_static(b"other version"),
            PutOptions::default(),
        )
        .await
        .expect("put other");
    assert_eq!(
        store.delete_at(&id, first.version_id.as_ref()).await,
        Err(StorageError::RetentionBlocked)
    );
    store
        .extend_retention_at(
            &id,
            first.version_id.as_ref(),
            RetentionPolicy::new(RetentionMode::Governance, 1),
        )
        .await
        .expect("nonshortening extension");
    let observed = store
        .head_at(&id, first.version_id.as_ref())
        .await
        .expect("head");
    assert_eq!(observed.retain_until_ms, first.retain_until_ms);
    assert_eq!(
        observed.retention.expect("policy").mode,
        RetentionMode::Compliance
    );
    store
        .set_legal_hold_at(&id, first.version_id.as_ref(), LegalHoldStatus::On)
        .await
        .expect("hold");
    store.advance_to(first.retain_until_ms.expect("deadline") + 1);
    assert_eq!(
        store.delete_at(&id, first.version_id.as_ref()).await,
        Err(StorageError::LegalHoldBlocked)
    );
    let inventory = store.list_prefix_versions("").await.expect("inventory");
    assert!(
        inventory.contains(
            &store
                .head_at(&id, first.version_id.as_ref())
                .await
                .expect("same projection")
        )
    );
    store
        .set_legal_hold_at(&id, first.version_id.as_ref(), LegalHoldStatus::Off)
        .await
        .expect("release explicit hold");
    store
        .delete_at(&id, first.version_id.as_ref())
        .await
        .expect("expired exact delete");
    assert!(matches!(
        store
            .get_range_at(&id, first.version_id.as_ref(), ByteRange::Full)
            .await,
        Err(StorageError::NotFound(_))
    ));
    assert_eq!(
        store
            .get_range_at(&id, other.version_id.as_ref(), ByteRange::Full)
            .await
            .expect("other survives"),
        Bytes::from_static(b"other version")
    );
}
