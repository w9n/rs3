//! v2 maintenance planning and conservative apply paths.

pub(in crate::v2) mod capacity;
mod packed_usage;
mod recovery;

pub(in crate::v2) mod introduced;

pub(in crate::v2) mod coverage;

use super::commit::{V2_SECTION_FLAG_MUST_UNDERSTAND, V2CommitKey};
use super::error::{V2FormatError, V2Result};
use super::provider::V2ProviderProfile;
use super::repository::{
    V2AnchorState, V2CommitAnchor, V2CommitStore, V2ReplayChain, V2ReplayCommit, V2ReplayLimits,
};
use super::service::packed::{
    V2PackedIndexRunReplay, apply_packed_index_run, repository_context_from_refs,
};
use super::standalone::validate_v2_standalone_object;
use super::{V2CommitKind, V2IndexRoot, V2IndexRootRunRef, V2SectionType, open_v2_index_root};
use crate::state::RepositoryState;
use async_trait::async_trait;
use bytes::Bytes;
use rs3_index::{NamespaceEntry, PayloadReference, V2StandaloneStreamCarrierReference};
use rs3_storage::{
    BlobList, BlobListMode, BlobListPage, BlobMetadata, BlobMultipartUpload, BlobRead, BlobStore,
    ByteRange, PutOptions, StorageError,
};
use rs3_storage::{
    active_retention, retention_satisfies, strongest_retention_policy as strongest_retention,
};
use rs3_types::{
    BackendObjectId, BackendVersionId, LegalHoldStatus, RetentionMode, RetentionPolicy, Sequence,
};
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
#[cfg(not(test))]
use std::time::{SystemTime, UNIX_EPOCH};

/// Default lead time for extending provider retention on live objects.
pub const DEFAULT_RETENTION_RENEWAL_HORIZON: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const MIN_ORPHAN_GC_AGE: Duration = Duration::from_secs(60 * 60);
const MAINTENANCE_LIST_PAGE_ITEMS: usize = 1_000;
const DEFAULT_MAX_INVENTORY_PAGES: u64 = 4_096;
const DEFAULT_MAX_INVENTORY_ITEMS: u64 = 2_000_000;
const FULL_GC_PLAN_DIGEST_DOMAIN: &[u8] = b"rs3.full-gc.plan.v3-preview.v1";

/// Path-safe reason returned when an apply digest does not match its exact plan.
pub const V2_MAINTENANCE_PLAN_STALE_REASON: &str =
    "maintenance plan digest is stale: repository state moved since the dry run";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct V2MaintenanceIoUsage {
    request_count: u64,
    version_list_count: u64,
    head_count: u64,
    range_read_bytes: u64,
    list_page_count: u64,
    exhausted: bool,
}

struct V2MaintenanceBudgetedStore<'a, S> {
    inner: &'a S,
    budgets: V2MaintenanceBudgets,
    usage: Arc<RwLock<V2MaintenanceIoUsage>>,
}

impl<S> Clone for V2MaintenanceBudgetedStore<'_, S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner,
            budgets: self.budgets,
            usage: Arc::clone(&self.usage),
        }
    }
}

impl<'a, S> V2MaintenanceBudgetedStore<'a, S> {
    fn new(inner: &'a S, budgets: V2MaintenanceBudgets) -> Self {
        Self {
            inner,
            budgets,
            usage: Arc::new(RwLock::new(V2MaintenanceIoUsage::default())),
        }
    }

    fn usage(&self) -> rs3_storage::Result<V2MaintenanceIoUsage> {
        self.usage
            .read()
            .map(|usage| *usage)
            .map_err(|_| maintenance_budget_storage_error())
    }

    fn charge(
        &self,
        head_count: u64,
        range_read_bytes: u64,
        list_mode: Option<BlobListMode>,
    ) -> rs3_storage::Result<()> {
        charge_maintenance_io(
            self.budgets,
            &self.usage,
            1,
            head_count,
            range_read_bytes,
            list_mode,
        )
    }

    fn charge_range_read_bytes(&self, range_read_bytes: u64) -> rs3_storage::Result<()> {
        charge_maintenance_io(self.budgets, &self.usage, 0, 0, range_read_bytes, None)
    }

    fn reject_unbounded_read(&self) -> rs3_storage::Result<()> {
        let mut usage = self
            .usage
            .write()
            .map_err(|_| maintenance_budget_storage_error())?;
        usage.exhausted = true;
        Err(maintenance_budget_storage_error())
    }

    fn charge_range(&self, range: ByteRange) -> rs3_storage::Result<()> {
        match range {
            ByteRange::Slice { len, .. } => self.charge(0, len, None),
            ByteRange::Full => self.reject_unbounded_read(),
        }
    }

    async fn pace(&self) {
        pace_maintenance_operation(self.budgets.op_pacing_delay).await;
    }
}

/// Sleeps for the configured maintenance pacing delay, when one is set.
async fn pace_maintenance_operation(delay: Option<Duration>) {
    if let Some(delay) = delay.filter(|delay| !delay.is_zero()) {
        tokio::time::sleep(delay).await;
    }
}

struct V2MaintenanceBudgetedList {
    inner: Box<dyn BlobList>,
    budgets: V2MaintenanceBudgets,
    usage: Arc<RwLock<V2MaintenanceIoUsage>>,
    mode: BlobListMode,
}

#[async_trait]
impl BlobList for V2MaintenanceBudgetedList {
    async fn next_page(&mut self, max_items: NonZeroUsize) -> rs3_storage::Result<BlobListPage> {
        charge_maintenance_io(self.budgets, &self.usage, 1, 0, 0, Some(self.mode))?;
        pace_maintenance_operation(self.budgets.op_pacing_delay).await;
        let page = self.inner.next_page(max_items).await?;
        if page.consumed_items < page.entries.len() || page.consumed_items > max_items.get() {
            return Err(StorageError::InvalidListPage);
        }
        Ok(page)
    }
}

#[async_trait]
impl<S> BlobStore for V2MaintenanceBudgetedStore<'_, S>
where
    S: BlobStore,
{
    async fn put(
        &self,
        _object_id: &BackendObjectId,
        _body: Bytes,
        _options: PutOptions,
    ) -> rs3_storage::Result<BlobMetadata> {
        Err(maintenance_read_only_storage_error())
    }

    async fn create_multipart_upload(
        &self,
        _object_id: &BackendObjectId,
        _options: PutOptions,
    ) -> rs3_storage::Result<Box<dyn BlobMultipartUpload>> {
        Err(maintenance_read_only_storage_error())
    }

    async fn get_range(
        &self,
        object_id: &BackendObjectId,
        range: ByteRange,
    ) -> rs3_storage::Result<Bytes> {
        self.charge_range(range)?;
        self.pace().await;
        self.inner.get_range(object_id, range).await
    }

    async fn get_range_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        range: ByteRange,
    ) -> rs3_storage::Result<Bytes> {
        self.charge_range(range)?;
        self.pace().await;
        self.inner.get_range_at(object_id, version_id, range).await
    }

    async fn open_range_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        range: ByteRange,
    ) -> rs3_storage::Result<Box<dyn BlobRead>> {
        self.charge_range(range)?;
        self.pace().await;
        self.inner.open_range_at(object_id, version_id, range).await
    }

    async fn open_bounded_full_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        max_bytes: u64,
    ) -> rs3_storage::Result<Box<dyn BlobRead>> {
        self.charge(0, 0, None)?;
        self.pace().await;
        let read = self
            .inner
            .open_bounded_full_at(object_id, version_id, max_bytes)
            .await?;
        self.charge_range_read_bytes(read.exact_len())?;
        Ok(read)
    }

    async fn head(&self, object_id: &BackendObjectId) -> rs3_storage::Result<BlobMetadata> {
        self.charge(1, 0, None)?;
        self.pace().await;
        self.inner.head(object_id).await
    }

    async fn head_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
    ) -> rs3_storage::Result<BlobMetadata> {
        self.charge(1, 0, None)?;
        self.pace().await;
        self.inner.head_at(object_id, version_id).await
    }

    async fn list_prefix(&self, _prefix: &str) -> rs3_storage::Result<Vec<BlobMetadata>> {
        Err(StorageError::PagedListingUnsupported)
    }

    async fn list_prefix_versions(&self, _prefix: &str) -> rs3_storage::Result<Vec<BlobMetadata>> {
        Err(StorageError::PagedListingUnsupported)
    }

    async fn open_bounded_list(
        &self,
        prefix: &str,
        mode: BlobListMode,
    ) -> rs3_storage::Result<Box<dyn BlobList>> {
        let inner = self.inner.open_bounded_list(prefix, mode).await?;
        Ok(Box::new(V2MaintenanceBudgetedList {
            inner,
            budgets: self.budgets,
            usage: Arc::clone(&self.usage),
            mode,
        }))
    }

    async fn delete(&self, _object_id: &BackendObjectId) -> rs3_storage::Result<()> {
        Err(maintenance_read_only_storage_error())
    }

    async fn delete_at(
        &self,
        _object_id: &BackendObjectId,
        _version_id: Option<&BackendVersionId>,
    ) -> rs3_storage::Result<()> {
        Err(maintenance_read_only_storage_error())
    }

    async fn extend_retention(
        &self,
        _object_id: &BackendObjectId,
        _policy: RetentionPolicy,
    ) -> rs3_storage::Result<()> {
        Err(maintenance_read_only_storage_error())
    }

    async fn extend_retention_at(
        &self,
        _object_id: &BackendObjectId,
        _version_id: Option<&BackendVersionId>,
        _policy: RetentionPolicy,
    ) -> rs3_storage::Result<()> {
        Err(maintenance_read_only_storage_error())
    }

    async fn set_legal_hold(
        &self,
        _object_id: &BackendObjectId,
        _status: LegalHoldStatus,
    ) -> rs3_storage::Result<()> {
        Err(maintenance_read_only_storage_error())
    }

    async fn set_legal_hold_at(
        &self,
        _object_id: &BackendObjectId,
        _version_id: Option<&BackendVersionId>,
        _status: LegalHoldStatus,
    ) -> rs3_storage::Result<()> {
        Err(maintenance_read_only_storage_error())
    }

    async fn flush_caches(&self) -> rs3_storage::Result<()> {
        Err(maintenance_read_only_storage_error())
    }
}

fn maintenance_budget_storage_error() -> StorageError {
    StorageError::Provider("maintenance I/O budget exhausted".to_owned())
}

fn charge_maintenance_io(
    budgets: V2MaintenanceBudgets,
    usage: &RwLock<V2MaintenanceIoUsage>,
    request_count: u64,
    head_count: u64,
    range_read_bytes: u64,
    list_mode: Option<BlobListMode>,
) -> rs3_storage::Result<()> {
    let mut usage = usage
        .write()
        .map_err(|_| maintenance_budget_storage_error())?;
    if usage.exhausted {
        return Err(maintenance_budget_storage_error());
    }
    let request_count = usage.request_count.checked_add(request_count);
    let next_head_count = usage.head_count.checked_add(head_count);
    let next_range_read_bytes = usage.range_read_bytes.checked_add(range_read_bytes);
    let list_page_count = usage
        .list_page_count
        .checked_add(u64::from(list_mode.is_some()));
    let version_list_count = usage
        .version_list_count
        .checked_add(u64::from(list_mode == Some(BlobListMode::Versions)));
    let next = request_count
        .zip(next_head_count)
        .zip(next_range_read_bytes)
        .zip(list_page_count)
        .zip(version_list_count);
    let Some((
        (((request_count, head_count), range_read_bytes), list_page_count),
        version_list_count,
    )) = next
    else {
        usage.exhausted = true;
        return Err(maintenance_budget_storage_error());
    };
    if !budget_allows(budgets.max_request_count, request_count)
        || !budget_allows(budgets.max_head_count, head_count)
        || !budget_allows(budgets.max_range_read_bytes, range_read_bytes)
        || list_page_count > budgets.max_inventory_page_count
        || !budget_allows(budgets.max_version_list_count, version_list_count)
    {
        usage.exhausted = true;
        return Err(maintenance_budget_storage_error());
    }
    usage.request_count = request_count;
    usage.head_count = head_count;
    usage.range_read_bytes = range_read_bytes;
    usage.list_page_count = list_page_count;
    usage.version_list_count = version_list_count;
    Ok(())
}

fn maintenance_read_only_storage_error() -> StorageError {
    StorageError::Provider("maintenance planning store is read-only".to_owned())
}

/// Broad path-private class of one v2 orphan candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V2OrphanObjectClass {
    /// Signed commit object under `commits/v03/`.
    Commit,
    /// Opaque independently sealed object under `objects/v03/`.
    Object,
}

/// Unanchored v2 backend object discovered by orphan reporting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2OrphanCandidate {
    /// Broad backend-visible object class.
    pub object_class: V2OrphanObjectClass,
    /// Opaque backend object ID.
    pub object_id: BackendObjectId,
    /// Provider version ID visible in listing, when available.
    pub version_id: Option<BackendVersionId>,
    /// Listed object length.
    pub content_len: u64,
    /// Provider modification timestamp in milliseconds since the Unix epoch.
    pub modified_at_ms: Option<i64>,
    /// Parsed sequence when the object key has a valid v2 commit shape.
    pub sequence: Option<Sequence>,
    /// True when the candidate has the same sequence as the anchor head.
    pub same_sequence_as_anchor: bool,
    /// Provider retention policy visible in listing, when available.
    pub retention: Option<RetentionPolicy>,
    /// Provider retain-until timestamp in milliseconds since the Unix epoch, when available.
    pub retain_until_ms: Option<i64>,
    /// True when known retention should block deletion.
    pub delete_blocked_by_retention: bool,
    /// True when known legal hold should block deletion.
    pub delete_blocked_by_legal_hold: bool,
    /// True when the selected provider profile requires protection metadata but it was not visible.
    pub delete_blocked_by_unknown_protection: bool,
}

/// Redacted v2 orphan report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2OrphanReport {
    /// Reachable commit object count in the verified anchor chain.
    pub reachable_commit_count: usize,
    /// Reachable independently sealed objects referenced by live payload state.
    pub reachable_object_count: usize,
    /// Candidate objects under the v2 commit and object prefixes that are not reachable.
    pub candidates: Vec<V2OrphanCandidate>,
}

/// Conservative v2 orphan garbage-collection policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V2OrphanGcOptions {
    /// Minimum provider-observed age before an unanchored commit may be deleted.
    pub min_age: Duration,
    /// Whether same-sequence candidates may be deleted after normal checks pass.
    pub delete_same_sequence: bool,
}

impl V2OrphanGcOptions {
    /// Creates conservative orphan-GC options.
    pub fn new(min_age: Duration) -> V2Result<Self> {
        if min_age < MIN_ORPHAN_GC_AGE {
            return Err(V2FormatError::OrphanGcMinAgeTooLow);
        }
        Ok(Self {
            min_age,
            delete_same_sequence: false,
        })
    }

    /// Creates orphan-GC options without the production age floor.
    ///
    /// This is only for deterministic tests and isolated rehearsal harnesses
    /// that create disposable objects inside an empty target prefix.
    pub const fn new_for_test_rehearsal(min_age: Duration) -> Self {
        Self {
            min_age,
            delete_same_sequence: false,
        }
    }

    /// Allows deletion of same-sequence candidates after age/protection checks.
    pub const fn with_same_sequence_deletion(mut self, enabled: bool) -> Self {
        self.delete_same_sequence = enabled;
        self
    }
}

/// Result of one conservative v2 orphan garbage-collection pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct V2OrphanGcReport {
    /// Orphan candidates inspected.
    pub scanned_count: usize,
    /// Candidates deleted by this pass.
    pub deleted_count: usize,
    /// Candidates already gone before deletion.
    pub already_gone_count: usize,
    /// Candidates skipped because provider retention or legal hold was visible.
    pub protected_count: usize,
    /// Candidates skipped because they were too young or had no usable age.
    pub age_skipped_count: usize,
    /// Same-sequence candidates skipped by conservative default policy.
    pub same_sequence_skipped_count: usize,
    /// Delete calls that failed for reasons other than known protection or not found.
    pub failed_delete_count: usize,
    /// Mid-pass abort reason after a partial destructive pass.
    pub aborted: Option<V2FormatError>,
}

/// Redacted v2 quick-maintenance report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2MaintenanceReport {
    /// Ciphertext bytes in exact payload-pack sections with referenced records.
    /// Excludes commit headers, index metadata, and wholly unreferenced packs.
    pub packed_payload_stored_bytes: u64,
    /// Union of referenced record ciphertext bytes in those packs, including
    /// conservative protected recovery dependencies and deduplicating shared
    /// physical references, even when history retains obsolete run entries.
    /// The difference from stored bytes is not immediately reclaimable space.
    pub packed_payload_referenced_bytes: u64,
    /// True when an anchor was present.
    pub anchor_present: bool,
    /// Verified commit count in the anchor-selected chain.
    pub verified_commit_count: usize,
    /// Age of the accepted chain head in milliseconds.
    pub last_anchored_commit_age_ms: Option<u128>,
    /// Orphan candidate count under the v2 commit prefix.
    pub orphan_candidate_count: usize,
    /// Total bytes held by orphan candidates under the v2 commit prefix.
    pub orphan_candidate_bytes: u64,
    /// Orphan candidates blocked by retention or legal hold.
    pub protected_orphan_candidate_count: usize,
    /// Oldest visible orphan age in milliseconds, when provider timestamps exist.
    pub oldest_orphan_age_ms: Option<u128>,
    /// Orphan candidates currently eligible for conservative deletion.
    pub reclaimable_orphan_candidate_count: usize,
    /// Total bytes held by orphan candidates currently eligible for deletion.
    pub reclaimable_orphan_candidate_bytes: u64,
    /// Oldest deletion-eligible orphan age in milliseconds.
    pub oldest_reclaimable_orphan_age_ms: Option<u128>,
    /// Live object versions that should have retention extended within the default renewal horizon.
    pub retention_renewal_commit_count: usize,
    /// Live object bytes covered by planned retention renewal.
    pub retention_renewal_bytes: u64,
    /// Live object versions whose renewal could not be planned from available metadata.
    pub retention_renewal_blocked_count: usize,
    /// Live object bytes whose renewal could not be planned from available metadata.
    pub retention_renewal_blocked_bytes: u64,
    /// Earliest provider retain-until deadline observed across live renewal
    /// targets, in milliseconds since the Unix epoch.
    pub nearest_retain_until_ms: Option<i64>,
    /// Earliest authenticated recovery-history expiry time that can advance
    /// the accepted cutoff, including the policy clock-uncertainty floor.
    pub recovery_expiry_due_ms: Option<i64>,
    /// Accepted current and historical recovery points that remain recoverable.
    pub recovery_recoverable_point_count: u64,
    /// Oldest signed publish time among accepted recoverable points.
    pub recovery_oldest_recoverable_publish_time_ms: Option<i64>,
    /// Deduplicated exact bytes retained solely for authenticated recovery history.
    pub recovery_historical_exact_bytes: u64,
    /// Authenticated clock uncertainty used when scheduling recovery renewal.
    pub recovery_clock_uncertainty_ms: Option<u32>,
}

/// Operator-accepted budgets for v2 full-maintenance dry runs and apply plans.
///
/// Request counts are logical `BlobStore` operations issued by rs3. Retries
/// hidden inside a provider SDK are outside this ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V2MaintenanceBudgets {
    /// Maximum planned backend requests.
    pub max_request_count: Option<u64>,
    /// Maximum planned version-list requests.
    pub max_version_list_count: Option<u64>,
    /// Maximum planned exact HEAD requests.
    pub max_head_count: Option<u64>,
    /// Maximum planned range-read bytes.
    pub max_range_read_bytes: Option<u64>,
    /// Maximum planned write bytes.
    pub max_write_bytes: Option<u64>,
    /// Maximum planned exact-version deletes.
    pub max_delete_count: Option<u64>,
    /// Maximum planned retention-extension calls.
    pub max_retention_extend_count: Option<u64>,
    /// Maximum provider pages consumed while building object inventory.
    pub max_inventory_page_count: u64,
    /// Maximum raw provider members consumed while building inventory.
    ///
    /// Filtered members such as S3 delete markers count against this ceiling.
    pub max_inventory_item_count: u64,
    /// Accounted graph metadata ceiling for authenticated history traversal
    /// and packed-record reference accounting, including without history.
    /// Independent of the startup replay chain's commit and retained-byte limits.
    pub max_history_metadata_bytes: u64,
    /// Maximum encrypted sections awaiting historical dependency decoding.
    pub max_history_pending_bytes: u64,
    /// Optional autovacuum-style delay inserted before each budgeted planning
    /// operation and before each destructive maintenance mutation.
    ///
    /// Budgets bound the total work of one pass; this knob bounds its
    /// instantaneous backend pressure so client traffic keeps headroom while
    /// maintenance runs. A true peak-memory ceiling is not cheaply enforceable
    /// here because inventory memory is dominated by per-candidate records,
    /// not by tracked I/O bytes; peak memory stays bounded instead through
    /// bounded-bytes accounting: `max_inventory_page_count`,
    /// `max_inventory_item_count`, and `max_range_read_bytes` cap every input
    /// that grows planning state.
    pub op_pacing_delay: Option<Duration>,
}

impl Default for V2MaintenanceBudgets {
    fn default() -> Self {
        Self {
            max_request_count: None,
            max_version_list_count: None,
            max_head_count: None,
            max_range_read_bytes: None,
            max_write_bytes: None,
            max_delete_count: None,
            max_retention_extend_count: None,
            max_inventory_page_count: DEFAULT_MAX_INVENTORY_PAGES,
            max_inventory_item_count: DEFAULT_MAX_INVENTORY_ITEMS,
            max_history_metadata_bytes: 256 * 1024 * 1024,
            max_history_pending_bytes: 64 * 1024 * 1024,
            op_pacing_delay: None,
        }
    }
}

/// Inputs that bound one read-only quick-maintenance report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2QuickMaintenanceOptions {
    /// Physical I/O and inventory limits for the report.
    pub budgets: V2MaintenanceBudgets,
    /// Lead time used when identifying retention-renewal targets.
    pub retention_renewal_horizon: Duration,
    /// Conservative deletion policy used to classify reclaimable orphans.
    pub orphan_gc: V2OrphanGcOptions,
}

impl Default for V2QuickMaintenanceOptions {
    fn default() -> Self {
        Self {
            budgets: V2MaintenanceBudgets::default(),
            retention_renewal_horizon: DEFAULT_RETENTION_RENEWAL_HORIZON,
            orphan_gc: V2OrphanGcOptions {
                min_age: MIN_ORPHAN_GC_AGE,
                delete_same_sequence: false,
            },
        }
    }
}

/// Observed planning reads and planned mutations for v2 full maintenance.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct V2MaintenancePlanCost {
    /// Planned backend requests across verification, inventory, and mutation.
    pub request_count: u64,
    /// Planned version-list requests.
    pub version_list_count: u64,
    /// Planned exact HEAD requests.
    pub head_count: u64,
    /// Planned range-read bytes.
    pub range_read_bytes: u64,
    /// Planned write bytes.
    pub write_bytes: u64,
    /// Planned exact-version delete calls.
    pub delete_count: u64,
    /// Planned retention-extension calls.
    pub retention_extend_count: u64,
    /// Provider listing pages consumed by the inventory.
    pub inventory_page_count: u64,
    /// Raw provider members consumed by the inventory.
    pub inventory_item_count: u64,
}

impl V2MaintenancePlanCost {
    /// Returns true when this plan fits the supplied operator budgets.
    pub fn fits_budgets(self, budgets: V2MaintenanceBudgets) -> bool {
        budget_allows(budgets.max_request_count, self.request_count)
            && budget_allows(budgets.max_version_list_count, self.version_list_count)
            && budget_allows(budgets.max_head_count, self.head_count)
            && budget_allows(budgets.max_range_read_bytes, self.range_read_bytes)
            && budget_allows(budgets.max_write_bytes, self.write_bytes)
            && budget_allows(budgets.max_delete_count, self.delete_count)
            && budget_allows(
                budgets.max_retention_extend_count,
                self.retention_extend_count,
            )
            && self.inventory_page_count <= budgets.max_inventory_page_count
            && self.inventory_item_count <= budgets.max_inventory_item_count
    }
}

/// Options for v2 full-maintenance dry runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2FullGcDryRunOptions {
    /// Operator request and byte budgets.
    pub budgets: V2MaintenanceBudgets,
    /// Plan live commit retention renewal when retain-until is within this horizon.
    pub retention_renewal_horizon: Duration,
    /// Additional trusted historical roots that must remain reachable.
    ///
    /// Every root must bind the active exact format reference. Cross-format
    /// protected-root maintenance fails with [`V2FormatError::InvalidFormatRoot`].
    pub protected_roots: Vec<V2AnchorState>,
}

impl Default for V2FullGcDryRunOptions {
    fn default() -> Self {
        Self {
            budgets: V2MaintenanceBudgets::default(),
            retention_renewal_horizon: DEFAULT_RETENTION_RENEWAL_HORIZON,
            protected_roots: Vec::new(),
        }
    }
}

/// Path-redacted v2 full-maintenance dry-run report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2FullGcDryRunReport {
    /// Anchor sequence the dry run was based on, if an anchor exists.
    pub base_sequence: Option<Sequence>,
    /// Verified chain-live commits needed for current anchor replay.
    pub chain_live_commit_count: usize,
    /// Operator-supplied historical roots included in reachability.
    pub protected_root_count: usize,
    /// Unique exact object versions included through historical roots.
    pub protected_commit_count: usize,
    /// Unanchored commit and standalone-object candidates inspected.
    pub candidate_commit_count: usize,
    /// Fully dead object candidates outside provider protection.
    pub fully_dead_commit_count: usize,
    /// Mixed accepted commit count selected for repack.
    pub mixed_commit_count: usize,
    /// Bytes in unanchored objects that can become reclaimable by exact delete.
    pub dead_bytes_reclaimable: u64,
    /// Live bytes that would be copied by repack.
    pub live_bytes_to_copy: u64,
    /// Dead bytes inside mixed accepted commits that repack could make reclaimable.
    pub mixed_dead_bytes_repackable: u64,
    /// Dead bytes blocked by active provider retention.
    pub retention_blocked_bytes: u64,
    /// Dead bytes blocked by legal hold.
    pub legal_hold_blocked_bytes: u64,
    /// Dead bytes blocked by missing exact version or protection metadata.
    pub unknown_protection_blocked_bytes: u64,
    /// Live object versions that should have retention extended within the requested horizon.
    pub retention_renewal_commit_count: usize,
    /// Live object bytes covered by planned retention renewal.
    pub retention_renewal_bytes: u64,
    /// Live object versions whose renewal could not be planned from available metadata.
    pub retention_renewal_blocked_count: usize,
    /// Live object bytes whose renewal could not be planned from available metadata.
    pub retention_renewal_blocked_bytes: u64,
    /// Planned request and byte cost.
    pub planned_cost: V2MaintenancePlanCost,
    /// True when the planned cost fits the supplied budgets.
    pub fits_budgets: bool,
    /// True when this dry run includes only exact-version deletion candidates.
    pub exact_version_apply_ready: bool,
}

/// Path-redacted preview of one exact full-maintenance plan.
///
/// The digest is derived inside the repository layer from the complete private
/// mutation plan. It binds every exact object/version identity, observed
/// protection fact, renewal target, protected root, and apply option without
/// exposing those private inputs to callers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2FullGcPlanPreview {
    /// Redacted operator-facing summary of the plan.
    pub report: V2FullGcDryRunReport,
    /// Lowercase SHA-256 digest of the exact private plan.
    pub plan_digest: String,
}

/// Guard required before destructive v2 maintenance can mutate storage.
#[async_trait]
pub trait V2MaintenanceGuard: Send + Sync {
    /// Verifies that the maintenance process still owns its exclusion window.
    async fn verify_v2_maintenance(&self, base_anchor: Option<&V2AnchorState>) -> V2Result<()>;
}

#[async_trait]
impl<G> V2MaintenanceGuard for Arc<G>
where
    G: V2MaintenanceGuard + ?Sized,
{
    async fn verify_v2_maintenance(&self, base_anchor: Option<&V2AnchorState>) -> V2Result<()> {
        self.as_ref().verify_v2_maintenance(base_anchor).await
    }
}

/// Cooperative cancellation signal for destructive v2 maintenance runs.
///
/// Cancellation is honored at mutation boundaries only: an in-flight renewal
/// or delete call always completes and is never interrupted mid-request, so
/// backend state stays exactly what the engine already verified. Signals are
/// one-shot per run; a later run with a fresh signal replans from current
/// state and completes any remainder.
#[derive(Debug, Default)]
pub struct V2MaintenanceCancellation {
    cancelled: AtomicBool,
}

impl V2MaintenanceCancellation {
    /// Creates a signal that has not requested a stop.
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests a clean stop at the next mutation boundary.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Returns true when a stop has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// Unenforced guard for externally quiesced maintenance windows.
///
/// Test and rehearsal use only. This honor-system guard performs no ownership
/// verification and must never appear on a production path: live gateways use
/// the Lease-backed writer fence, and the break-glass offline command acquires
/// exclusive writer-fence ownership through the anchor backend before it runs.
/// The only remaining callers are tests and explicitly isolated rehearsals
/// that opt in (for example `xtask v2 gc-rehearsal --unenforced-guard` against
/// a fresh single-process prefix).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnenforcedQuiescedMaintenanceGuard;

#[async_trait]
impl V2MaintenanceGuard for UnenforcedQuiescedMaintenanceGuard {
    async fn verify_v2_maintenance(&self, _base_anchor: Option<&V2AnchorState>) -> V2Result<()> {
        Ok(())
    }
}

/// Options for destructive v2 full-maintenance apply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2FullGcApplyOptions {
    /// Dry-run budgets that must pass before apply.
    pub dry_run: V2FullGcDryRunOptions,
    /// Conservative orphan deletion policy.
    pub orphan_gc: V2OrphanGcOptions,
    /// Whether retained-version provider conformance has passed for this run.
    pub retained_provider_conformance_passed: bool,
    /// Whether this run may physically reclaim fully dead orphan objects.
    ///
    /// Retention renewal remains active when reclamation is disabled.
    pub reclamation_enabled: bool,
}

/// Result of destructive v2 full-maintenance apply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2FullGcApplyReport {
    /// Dry-run report used as the apply preflight.
    pub dry_run: V2FullGcDryRunReport,
    /// Live exact object versions whose retention was renewed and verified.
    pub retention_renewed_object_count: usize,
    /// Live exact object bytes covered by verified retention renewal.
    pub retention_renewed_bytes: u64,
    /// Exact deletion result for fully dead orphan objects.
    pub orphan_gc: V2OrphanGcReport,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct V2RetentionRenewalPlan {
    commit_count: usize,
    bytes: u64,
    blocked_count: usize,
    blocked_bytes: u64,
    head_count: u64,
    extend_count: u64,
    nearest_retain_until_ms: Option<i64>,
    targets: Vec<V2RetentionTarget>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct V2RetentionTarget {
    object_id: BackendObjectId,
    version_id: Option<BackendVersionId>,
    stored_len: u64,
    required_retention: Option<RetentionPolicy>,
    required_legal_hold: Option<LegalHoldStatus>,
    /// Immutable provider-retention floor for this exact object version.
    required_deadline: Option<i64>,
    /// Dependency of the current accepted namespace, not history alone.
    current_recovery_dependency: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct V2FullGcPlan {
    report: V2FullGcDryRunReport,
    base_anchor: Option<V2AnchorState>,
    recovery_expire_before_ms: Option<i64>,
    verified_current_recovery_floor_ms: Option<i64>,
    retention_renewal: V2RetentionRenewalPlan,
    orphans: V2OrphanReport,
    current_chain: Option<V2ReplayChain>,
    current_state: Option<RepositoryState>,
}

pub(super) struct V2PreparedFullGcPlan {
    pub(super) plan_digest: String,
    pub(super) options: V2FullGcApplyOptions,
    plan: V2FullGcPlan,
}

impl V2PreparedFullGcPlan {
    pub(super) fn report(&self) -> &V2FullGcDryRunReport {
        &self.plan.report
    }

    pub(super) fn current(&self) -> Option<(&V2ReplayChain, &RepositoryState)> {
        self.plan
            .current_chain
            .as_ref()
            .zip(self.plan.current_state.as_ref())
    }
}

fn push_plan_bytes(encoded: &mut Vec<u8>, value: &[u8]) {
    encoded.extend_from_slice(&(value.len() as u64).to_be_bytes());
    encoded.extend_from_slice(value);
}

fn push_plan_bool(encoded: &mut Vec<u8>, value: bool) {
    encoded.push(u8::from(value));
}

fn push_plan_option_u64(encoded: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            encoded.push(1);
            encoded.extend_from_slice(&value.to_be_bytes());
        }
        None => encoded.push(0),
    }
}

fn push_plan_option_i64(encoded: &mut Vec<u8>, value: Option<i64>) {
    match value {
        Some(value) => {
            encoded.push(1);
            encoded.extend_from_slice(&value.to_be_bytes());
        }
        None => encoded.push(0),
    }
}

fn push_plan_duration(encoded: &mut Vec<u8>, value: Duration) {
    encoded.extend_from_slice(&value.as_secs().to_be_bytes());
    encoded.extend_from_slice(&value.subsec_nanos().to_be_bytes());
}

fn push_plan_option_duration(encoded: &mut Vec<u8>, value: Option<Duration>) {
    match value {
        Some(value) => {
            encoded.push(1);
            push_plan_duration(encoded, value);
        }
        None => encoded.push(0),
    }
}

fn push_plan_version(encoded: &mut Vec<u8>, value: Option<&BackendVersionId>) {
    match value {
        Some(value) => {
            encoded.push(1);
            push_plan_bytes(encoded, value.as_str().as_bytes());
        }
        None => encoded.push(0),
    }
}

fn push_plan_retention(encoded: &mut Vec<u8>, value: Option<RetentionPolicy>) {
    match value {
        Some(value) => {
            encoded.push(1);
            encoded.push(match value.mode {
                RetentionMode::None => 0,
                RetentionMode::Governance => 1,
                RetentionMode::Compliance => 2,
            });
            encoded.extend_from_slice(&value.retain_days.to_be_bytes());
        }
        None => encoded.push(0),
    }
}

fn push_plan_legal_hold(encoded: &mut Vec<u8>, value: Option<LegalHoldStatus>) {
    encoded.push(match value {
        None => 0,
        Some(LegalHoldStatus::Off) => 1,
        Some(LegalHoldStatus::On) => 2,
    });
}

fn encode_plan_anchor(anchor: &V2AnchorState) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&anchor.sequence.get().to_be_bytes());
    push_plan_bytes(&mut encoded, anchor.commit_key.as_str().as_bytes());
    encoded.extend_from_slice(&anchor.body_digest);
    push_plan_version(&mut encoded, anchor.version_id.as_ref());
    push_plan_bytes(&mut encoded, anchor.signing_key_id.as_str().as_bytes());
    encoded.extend_from_slice(&anchor.format_ref.generation.to_be_bytes());
    push_plan_bytes(&mut encoded, anchor.format_ref.digest.as_bytes());
    push_plan_bytes(
        &mut encoded,
        anchor.format_ref.object_id.as_str().as_bytes(),
    );
    push_plan_version(&mut encoded, anchor.format_ref.version_id.as_ref());
    encoded
}

fn encode_plan_budgets(encoded: &mut Vec<u8>, budgets: V2MaintenanceBudgets) {
    encoded.extend_from_slice(&budgets.max_history_metadata_bytes.to_be_bytes());
    encoded.extend_from_slice(&budgets.max_history_pending_bytes.to_be_bytes());
    push_plan_option_u64(encoded, budgets.max_request_count);
    push_plan_option_u64(encoded, budgets.max_version_list_count);
    push_plan_option_u64(encoded, budgets.max_head_count);
    push_plan_option_u64(encoded, budgets.max_range_read_bytes);
    push_plan_option_u64(encoded, budgets.max_write_bytes);
    push_plan_option_u64(encoded, budgets.max_delete_count);
    push_plan_option_u64(encoded, budgets.max_retention_extend_count);
    encoded.extend_from_slice(&budgets.max_inventory_page_count.to_be_bytes());
    encoded.extend_from_slice(&budgets.max_inventory_item_count.to_be_bytes());
    push_plan_option_duration(encoded, budgets.op_pacing_delay);
}

fn encode_plan_options(options: &V2FullGcApplyOptions) -> Vec<u8> {
    let mut encoded = Vec::new();
    encode_plan_budgets(&mut encoded, options.dry_run.budgets);
    push_plan_duration(&mut encoded, options.dry_run.retention_renewal_horizon);
    let mut protected_roots: Vec<Vec<u8>> = options
        .dry_run
        .protected_roots
        .iter()
        .map(encode_plan_anchor)
        .collect();
    protected_roots.sort_unstable();
    encoded.extend_from_slice(&(protected_roots.len() as u64).to_be_bytes());
    for root in protected_roots {
        push_plan_bytes(&mut encoded, &root);
    }
    push_plan_duration(&mut encoded, options.orphan_gc.min_age);
    push_plan_bool(&mut encoded, options.orphan_gc.delete_same_sequence);
    push_plan_bool(&mut encoded, options.retained_provider_conformance_passed);
    push_plan_bool(&mut encoded, options.reclamation_enabled);
    encoded
}

fn encode_plan_report(report: &V2FullGcDryRunReport) -> Vec<u8> {
    let mut encoded = Vec::new();
    push_plan_option_u64(&mut encoded, report.base_sequence.map(Sequence::get));
    for value in [
        report.chain_live_commit_count as u64,
        report.protected_root_count as u64,
        report.protected_commit_count as u64,
        report.candidate_commit_count as u64,
        report.fully_dead_commit_count as u64,
        report.mixed_commit_count as u64,
        report.dead_bytes_reclaimable,
        report.live_bytes_to_copy,
        report.mixed_dead_bytes_repackable,
        report.retention_blocked_bytes,
        report.legal_hold_blocked_bytes,
        report.unknown_protection_blocked_bytes,
        report.retention_renewal_commit_count as u64,
        report.retention_renewal_bytes,
        report.retention_renewal_blocked_count as u64,
        report.retention_renewal_blocked_bytes,
        report.planned_cost.request_count,
        report.planned_cost.version_list_count,
        report.planned_cost.head_count,
        report.planned_cost.range_read_bytes,
        report.planned_cost.write_bytes,
        report.planned_cost.delete_count,
        report.planned_cost.retention_extend_count,
        report.planned_cost.inventory_page_count,
        report.planned_cost.inventory_item_count,
    ] {
        encoded.extend_from_slice(&value.to_be_bytes());
    }
    push_plan_bool(&mut encoded, report.fits_budgets);
    push_plan_bool(&mut encoded, report.exact_version_apply_ready);
    encoded
}

fn encode_plan_orphan(candidate: &V2OrphanCandidate) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.push(match candidate.object_class {
        V2OrphanObjectClass::Commit => 0,
        V2OrphanObjectClass::Object => 1,
    });
    push_plan_bytes(&mut encoded, candidate.object_id.as_str().as_bytes());
    push_plan_version(&mut encoded, candidate.version_id.as_ref());
    encoded.extend_from_slice(&candidate.content_len.to_be_bytes());
    push_plan_option_i64(&mut encoded, candidate.modified_at_ms);
    push_plan_option_u64(&mut encoded, candidate.sequence.map(Sequence::get));
    push_plan_bool(&mut encoded, candidate.same_sequence_as_anchor);
    push_plan_retention(&mut encoded, candidate.retention);
    push_plan_option_i64(&mut encoded, candidate.retain_until_ms);
    push_plan_bool(&mut encoded, candidate.delete_blocked_by_retention);
    push_plan_bool(&mut encoded, candidate.delete_blocked_by_legal_hold);
    push_plan_bool(&mut encoded, candidate.delete_blocked_by_unknown_protection);
    encoded
}

fn encode_plan_renewal(target: &V2RetentionTarget) -> Vec<u8> {
    let mut encoded = Vec::new();
    push_plan_bytes(&mut encoded, target.object_id.as_str().as_bytes());
    push_plan_version(&mut encoded, target.version_id.as_ref());
    encoded.extend_from_slice(&target.stored_len.to_be_bytes());
    push_plan_retention(&mut encoded, target.required_retention);
    push_plan_legal_hold(&mut encoded, target.required_legal_hold);
    push_plan_option_i64(&mut encoded, target.required_deadline);
    encoded
}

fn encode_plan_group(tag: &[u8], mut entries: Vec<Vec<u8>>) -> Vec<u8> {
    entries.sort_unstable();
    let mut encoded = Vec::new();
    push_plan_bytes(&mut encoded, tag);
    encoded.extend_from_slice(&(entries.len() as u64).to_be_bytes());
    for entry in entries {
        push_plan_bytes(&mut encoded, &entry);
    }
    encoded
}

fn full_gc_plan_digest(plan: &V2FullGcPlan, options: &V2FullGcApplyOptions) -> String {
    let options = encode_plan_options(options);
    let report = encode_plan_report(&plan.report);
    let mut base_anchor = vec![u8::from(plan.base_anchor.is_some())];
    if let Some(anchor) = plan.base_anchor.as_ref() {
        push_plan_bytes(&mut base_anchor, &encode_plan_anchor(anchor));
    }
    base_anchor.push(u8::from(plan.recovery_expire_before_ms.is_some()));
    if let Some(cutoff) = plan.recovery_expire_before_ms {
        base_anchor.extend_from_slice(&cutoff.to_be_bytes());
    }
    base_anchor.push(u8::from(plan.verified_current_recovery_floor_ms.is_some()));
    if let Some(floor) = plan.verified_current_recovery_floor_ms {
        base_anchor.extend_from_slice(&floor.to_be_bytes());
    }
    let orphans = encode_plan_group(
        b"orphans",
        plan.orphans
            .candidates
            .iter()
            .map(encode_plan_orphan)
            .collect(),
    );
    let renewals = encode_plan_group(
        b"renewals",
        plan.retention_renewal
            .targets
            .iter()
            .map(encode_plan_renewal)
            .collect(),
    );

    let fields = [options, report, base_anchor, orphans, renewals];
    let field_refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    rs3_crypto::derive_public_fingerprint(FULL_GC_PLAN_DIGEST_DOMAIN, &field_refs)
}

/// Bounds applied to one destructive orphan-delete pass.
struct V2OrphanDeleteBounds<'a> {
    /// Delete-attempt ceiling from the accepted dry-run plan, when present.
    max_delete_count: Option<u64>,
    /// Cooperative cancellation checked before each delete.
    cancellation: &'a V2MaintenanceCancellation,
    /// Optional pacing delay applied before each delete mutation.
    op_pacing_delay: Option<Duration>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct V2OrphanInventory {
    report: V2OrphanReport,
    list_request_count: u64,
    version_list_request_count: u64,
    item_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct V2StandalonePayloadRoot {
    object_id: BackendObjectId,
    version_id: Option<BackendVersionId>,
    stored_len: u64,
    object_digest: [u8; 32],
    keyring_envelope_object_id: BackendObjectId,
    keyring_envelope_digest: [u8; 32],
    payload_layout: rs3_index::PayloadLayout,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum V2LivePayloadRoot {
    Commit {
        root: V2AnchorState,
        retention: Option<RetentionPolicy>,
        legal_hold: Option<LegalHoldStatus>,
    },
    Standalone {
        root: V2StandalonePayloadRoot,
        retention: Option<RetentionPolicy>,
        legal_hold: Option<LegalHoldStatus>,
    },
}

#[derive(Clone, Debug, Default)]
struct V2ReachabilityState {
    packed_usage: packed_usage::PackedUsage,
    anchor_state: Option<V2AnchorState>,
    current_chain: Option<V2ReplayChain>,
    current_state: Option<RepositoryState>,
    recovery_expire_before_ms: Option<i64>,
    current_recovery_floor_ms: Option<i64>,
    recovery_next_expiry_ms: Option<i64>,
    recovery_expiry_due_ms: Option<i64>,
    recovery_recoverable_point_count: u64,
    recovery_oldest_recoverable_publish_time_ms: Option<i64>,
    recovery_historical_exact_bytes: u64,
    recovery_clock_uncertainty_ms: Option<u32>,
    history_metadata_bytes: u64,
    history_peak_pending_bytes: u64,
    current_catalog_max_run_bytes: u64,
    current_max_section_bytes: u64,
    history_max_section_bytes: u64,
    verified_commits: BTreeMap<(BackendObjectId, Option<BackendVersionId>), Arc<V2ReplayCommit>>,
    reachable: BTreeSet<BackendObjectId>,
    reachable_versions: BTreeSet<(BackendObjectId, Option<BackendVersionId>)>,
    renewal_targets: BTreeMap<(BackendObjectId, Option<BackendVersionId>), V2RetentionTarget>,
    protected_versions: BTreeSet<(BackendObjectId, Option<BackendVersionId>)>,
    reachable_commit_versions: BTreeSet<(BackendObjectId, Option<BackendVersionId>)>,
    reachable_object_versions: BTreeSet<(BackendObjectId, Option<BackendVersionId>)>,
    standalone_facts:
        BTreeMap<(BackendObjectId, Option<BackendVersionId>), V2StandalonePayloadRoot>,
    chain_get_count: u64,
    chain_read_bytes: u64,
    chain_retained_bytes: u64,
    graph_head_count: u64,
}

pub(crate) struct V2ResolvedIndexRoot {
    pub(crate) runs: Vec<V2IndexRootRunRef>,
    referenced_commits: Vec<V2ReplayCommit>,
}

impl V2ReachabilityState {
    fn include_chain(
        &mut self,
        chain: &V2ReplayChain,
        protected: bool,
        retention: Option<RetentionPolicy>,
        legal_hold: Option<LegalHoldStatus>,
    ) -> V2Result<()> {
        for commit in &chain.commits_newest_first {
            let key = (
                commit.parsed_header.header.self_ref.commit_key.clone(),
                commit.version_id.clone(),
            );
            let newly_verified = !self.verified_commits.contains_key(&key);
            if let Some(previous) = self.verified_commits.get(&key) {
                if previous.parsed_header != commit.parsed_header
                    || previous.version_id != commit.version_id
                    || previous.object_len != commit.object_len
                {
                    return Err(V2FormatError::InvalidHeaderField);
                }
            } else {
                self.verified_commits
                    .insert(key, Arc::new(commit.header_facts()));
            }
            if newly_verified {
                self.chain_get_count = self.chain_get_count.saturating_add(1);
                self.chain_read_bytes = self.chain_read_bytes.saturating_add(commit.object_len);
            }
            // Distinct replay calls can own buffers for the same exact commit.
            // Account loaded sections even when their header facts were cached.
            self.chain_retained_bytes = commit
                .retained_sections
                .iter()
                .flatten()
                .try_fold(self.chain_retained_bytes, |total, section| {
                    total.checked_add(usize_to_u64(section.len()))
                })
                .ok_or(V2FormatError::MaintenanceBudgetExceeded)?;
            self.current_max_section_bytes = self.current_max_section_bytes.max(
                commit
                    .retained_sections
                    .iter()
                    .flatten()
                    .map(|section| usize_to_u64(section.len()))
                    .max()
                    .unwrap_or(0),
            );
            let object_id = commit.parsed_header.header.self_ref.commit_key.clone();
            let version_key = (object_id.clone(), commit.version_id.clone());
            self.reachable.insert(object_id.clone());
            self.reachable_versions.insert(version_key.clone());
            self.reachable_commit_versions.insert(version_key.clone());
            self.include_renewal_target(
                object_id,
                commit.version_id.clone(),
                commit.object_len,
                retention,
                legal_hold,
                None,
            )?;
            if protected {
                self.protected_versions.insert(version_key);
            }
        }
        Ok(())
    }

    fn include_standalone(
        &mut self,
        root: V2StandalonePayloadRoot,
        protected: bool,
        retention: Option<RetentionPolicy>,
        legal_hold: Option<LegalHoldStatus>,
    ) -> V2Result<()> {
        let version_key = (root.object_id.clone(), root.version_id.clone());
        match self.standalone_facts.get(&version_key) {
            Some(previous) if previous != &root => {
                return Err(V2FormatError::InvalidHeaderField);
            }
            Some(_) => {}
            None => {
                self.standalone_facts
                    .insert(version_key.clone(), root.clone());
            }
        }
        self.reachable.insert(root.object_id.clone());
        self.reachable_versions.insert(version_key.clone());
        self.reachable_object_versions.insert(version_key.clone());
        self.include_renewal_target(
            root.object_id,
            root.version_id,
            root.stored_len,
            retention,
            legal_hold,
            None,
        )?;
        if protected {
            self.protected_versions.insert(version_key);
        }
        Ok(())
    }

    fn include_renewal_target(
        &mut self,
        object_id: BackendObjectId,
        version_id: Option<BackendVersionId>,
        stored_len: u64,
        retention: Option<RetentionPolicy>,
        legal_hold: Option<LegalHoldStatus>,
        required_deadline: Option<i64>,
    ) -> V2Result<()> {
        let key = (object_id.clone(), version_id.clone());
        if let Some(target) = self.renewal_targets.get_mut(&key) {
            if target.stored_len != stored_len {
                return Err(V2FormatError::ProviderProfileFailed);
            }
            target.required_retention = strongest_retention(target.required_retention, retention);
            target.required_deadline = target.required_deadline.max(required_deadline);
            if legal_hold == Some(LegalHoldStatus::On) {
                target.required_legal_hold = Some(LegalHoldStatus::On);
            }
            return Ok(());
        }
        self.renewal_targets.insert(
            key,
            V2RetentionTarget {
                object_id,
                version_id,
                stored_len,
                required_retention: retention,
                required_legal_hold: legal_hold,
                required_deadline,
                current_recovery_dependency: false,
            },
        );
        Ok(())
    }

    /// Marks targets reached from the accepted current namespace before
    /// historical recovery traversal contributes any historical-only targets.
    fn mark_current_recovery_dependencies(&mut self) {
        for target in self.renewal_targets.values_mut() {
            target.current_recovery_dependency = true;
        }
    }

    fn include_required_protection(
        &mut self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        retention: Option<RetentionPolicy>,
        legal_hold: Option<LegalHoldStatus>,
    ) -> V2Result<()> {
        let key = (object_id.clone(), version_id.cloned());
        let target = self
            .renewal_targets
            .get_mut(&key)
            .ok_or(V2FormatError::InvalidHeaderField)?;
        target.required_retention = strongest_retention(target.required_retention, retention);
        if legal_hold == Some(LegalHoldStatus::On) {
            target.required_legal_hold = Some(LegalHoldStatus::On);
        }
        Ok(())
    }
}

impl<S> V2CommitStore<S>
where
    S: BlobStore,
{
    // Tests share the commit-store instance clock with provider/publication
    // fixtures. Production keeps the existing maintenance wall-clock source.
    fn maintenance_now_ms(&self) -> i64 {
        #[cfg(test)]
        {
            self.publication_now_ms()
        }
        #[cfg(not(test))]
        {
            current_time_ms()
        }
    }

    pub(crate) fn open_index_root_without_replay(
        &self,
        containing_commit: &V2ReplayCommit,
        section_ordinal: u32,
        stored_root: &[u8],
        limits: V2ReplayLimits,
    ) -> V2Result<V2IndexRoot> {
        let header = &containing_commit.parsed_header.header;
        let context = repository_context_from_refs(
            &self.options().repository_id,
            &header.keyring_envelope_ref,
        )
        .map_err(|_| V2FormatError::InvalidIndexRoot)?;
        let root = open_v2_index_root(
            self.keyring(),
            &context,
            &header.self_ref.commit_key,
            section_ordinal,
            stored_root,
        )?;
        if root.keyring_envelope_ref() != &header.keyring_envelope_ref
            || root.format_ref() != &self.options().format_ref
            || root.required_capabilities() != 0
        {
            return Err(V2FormatError::InvalidIndexRoot);
        }
        match header.parent.as_ref() {
            Some(_) => {}
            None if header.self_ref.sequence == Sequence::new(1)
                && root.covered_generation() == Sequence::ZERO
                && root.runs().is_empty() => {}
            _ => return Err(V2FormatError::InvalidIndexRoot),
        }
        let referenced_commit_bytes = root.runs().iter().try_fold(0_u64, |total, run| {
            total.checked_add(run.location.commit_stored_len)
        });
        if root.runs().len() > limits.max_commits
            || root.claims().total_stored_run_bytes() > limits.max_total_commit_bytes
            || referenced_commit_bytes.is_none_or(|bytes| bytes > limits.max_total_commit_bytes)
        {
            return Err(V2FormatError::ReplayBudgetExceeded);
        }
        Ok(root)
    }

    pub(crate) async fn apply_index_root_to_state(
        &self,
        state: &mut RepositoryState,
        containing_commit: &V2ReplayCommit,
        section_ordinal: u32,
        stored_root: &[u8],
        limits: V2ReplayLimits,
    ) -> V2Result<V2ResolvedIndexRoot> {
        let header = &containing_commit.parsed_header.header;
        let root = self.open_index_root_without_replay(
            containing_commit,
            section_ordinal,
            stored_root,
            limits,
        )?;
        let covered_parent_sequence = match header.parent.as_ref() {
            Some(parent) => parent.sequence,
            None if header.self_ref.sequence == Sequence::new(1)
                && root.covered_generation() == Sequence::ZERO
                && root.runs().is_empty() =>
            {
                Sequence::ZERO
            }
            _ => return Err(V2FormatError::InvalidIndexRoot),
        };
        if root
            .completion_receipts()
            .iter()
            .any(|receipt| receipt.commit_sequence >= header.self_ref.sequence)
        {
            return Err(V2FormatError::InvalidIndexRoot);
        }
        let mut ordered_runs = root.runs().to_vec();
        ordered_runs.sort_by_key(|run| (run.minimum_generation, run.run_sequence, run.run_id));
        *state = RepositoryState::default();
        let mut runs = Vec::with_capacity(ordered_runs.len());
        let mut referenced_commits = Vec::with_capacity(ordered_runs.len());
        for expected in ordered_runs {
            let location = &expected.location;
            let replay = self
                .read_commit_facts_at(&location.commit_key, location.version_id.as_ref())
                .await?;
            let referenced_header = &replay.parsed_header.header;
            let descriptor_index = usize::try_from(location.section_ordinal)
                .map_err(|_| V2FormatError::SectionBounds)?;
            let descriptor = referenced_header
                .section_index
                .get(descriptor_index)
                .ok_or(V2FormatError::InvalidIndexRoot)?;
            let compacted = expected.level > 0;
            let referenced_sequence = referenced_header.self_ref.sequence;
            let valid_lineage = if compacted {
                expected.compaction_generation == referenced_sequence.get()
                    && referenced_sequence <= header.self_ref.sequence
                    && referenced_header.parent.is_some()
                    && referenced_header.section_index.len() == 1
                    && descriptor_index == 0
                    && if referenced_sequence == header.self_ref.sequence {
                        referenced_header.parent == header.parent
                    } else {
                        referenced_sequence <= covered_parent_sequence
                    }
            } else {
                expected.compaction_generation == 0
                    && referenced_sequence <= covered_parent_sequence
            };
            if replay.version_id != location.version_id
                || replay.object_len != location.commit_stored_len
                || replay.parsed_header.sections_start
                    != usize::try_from(location.sections_start)
                        .map_err(|_| V2FormatError::SectionBounds)?
                || referenced_header.kind != V2CommitKind::Delta
                || !valid_lineage
                || referenced_header.body_digest != location.commit_body_digest
                || referenced_header.keyring_envelope_ref != expected.keyring_envelope_ref
                || descriptor.section_type != V2SectionType::IndexRun
                || descriptor.flags != V2_SECTION_FLAG_MUST_UNDERSTAND
                || descriptor.offset != location.section_offset
                || descriptor.length != location.section_len
                || descriptor.digest != location.section_digest
            {
                return Err(V2FormatError::InvalidIndexRoot);
            }
            let stored_run = self
                .read_metadata_section(&replay, location.section_ordinal, limits.max_retained_bytes)
                .await?;
            let actual = apply_packed_index_run(
                self.keyring(),
                &self.options().repository_id,
                state,
                V2PackedIndexRunReplay {
                    parsed_header: &replay.parsed_header,
                    version_id: replay.version_id.as_ref(),
                    object_len: replay.object_len,
                    section_ordinal: location.section_ordinal,
                    stored_run: &stored_run,
                    level: expected.level,
                    compaction_generation: expected.compaction_generation,
                    provider_profile: self.provider_profile(),
                },
            )
            .map_err(|_| V2FormatError::InvalidIndexRun)?;
            if actual != expected {
                return Err(V2FormatError::InvalidIndexRoot);
            }
            runs.push(actual);
            referenced_commits.push(replay);
        }
        if state.next_sequence != root.covered_generation()
            || u64::try_from(state.list_entries.len())
                .map_err(|_| V2FormatError::IndexRootLimitExceeded)?
                != root.expected_live_object_count()
        {
            return Err(V2FormatError::InvalidIndexRoot);
        }
        // The snapshot is authoritative. Receipts found in old catalog-named
        // runs must not resurrect results already evicted from the accepted set.
        state.completion_receipts = root.completion_receipts().clone();
        Ok(V2ResolvedIndexRoot {
            runs,
            referenced_commits,
        })
    }

    /// Reports unanchored v2 objects without deleting anything.
    pub async fn report_orphans<A>(&self, anchor: &A) -> V2Result<V2OrphanReport>
    where
        A: V2CommitAnchor,
    {
        self.report_orphans_with_protected_roots(anchor, &[]).await
    }

    /// Reports unanchored v2 objects while preserving supplied historical roots.
    ///
    /// Supplied roots must bind the active exact format reference.
    pub async fn report_orphans_with_protected_roots<A>(
        &self,
        anchor: &A,
        protected_roots: &[V2AnchorState],
    ) -> V2Result<V2OrphanReport>
    where
        A: V2CommitAnchor,
    {
        let reachability = self
            .load_reachability(
                anchor,
                protected_roots,
                V2MaintenanceBudgets::default(),
                false,
                false,
            )
            .await?;
        self.report_orphans_from_reachability(&reachability, V2MaintenanceBudgets::default())
            .await
            .map(|inventory| inventory.report)
    }

    async fn report_orphans_from_reachability(
        &self,
        reachability: &V2ReachabilityState,
        budgets: V2MaintenanceBudgets,
    ) -> V2Result<V2OrphanInventory> {
        let anchor_sequence = reachability
            .anchor_state
            .as_ref()
            .map(|anchor| anchor.sequence);

        let retained_profile =
            self.provider_profile() == V2ProviderProfile::RetainedVersionObjectLock;
        let mut candidates = Vec::new();
        let mut request_count = reachability
            .chain_get_count
            .saturating_add(reachability.graph_head_count);
        let mut version_list_count = 0_u64;
        let mut list_request_count = 0_u64;
        let mut inventory_item_count = 0_u64;
        let mut head_count = reachability.graph_head_count;
        let now_ms = self.maintenance_now_ms();
        for (prefix, object_class) in [
            ("commits/v03/", V2OrphanObjectClass::Commit),
            ("objects/v03/", V2OrphanObjectClass::Object),
        ] {
            let mode = if retained_profile {
                BlobListMode::Versions
            } else {
                BlobListMode::Current
            };
            let mut listing = self
                .store()
                .open_bounded_list(prefix, mode)
                .await
                .map_err(|_| V2FormatError::StorageOperationFailed)?;
            loop {
                ensure_next_budgeted_operation(
                    Some(budgets.max_inventory_page_count),
                    list_request_count,
                )?;
                ensure_next_budgeted_operation(budgets.max_request_count, request_count)?;
                if retained_profile {
                    ensure_next_budgeted_operation(
                        budgets.max_version_list_count,
                        version_list_count,
                    )?;
                    version_list_count = version_list_count.saturating_add(1);
                }
                let remaining_items = budgets
                    .max_inventory_item_count
                    .checked_sub(inventory_item_count)
                    .ok_or(V2FormatError::MaintenanceBudgetExceeded)?;
                let page_items =
                    usize::try_from(remaining_items.min(MAINTENANCE_LIST_PAGE_ITEMS as u64))
                        .map_err(|_| V2FormatError::MaintenanceBudgetExceeded)?;
                let page_items = NonZeroUsize::new(page_items)
                    .ok_or(V2FormatError::MaintenanceBudgetExceeded)?;
                request_count = request_count.saturating_add(1);
                list_request_count = list_request_count.saturating_add(1);
                let page = listing
                    .next_page(page_items)
                    .await
                    .map_err(|_| V2FormatError::StorageOperationFailed)?;
                if page.consumed_items < page.entries.len()
                    || page.consumed_items > page_items.get()
                {
                    return Err(V2FormatError::ProviderProfileFailed);
                }
                inventory_item_count = inventory_item_count
                    .checked_add(usize_to_u64(page.consumed_items))
                    .filter(|count| *count <= budgets.max_inventory_item_count)
                    .ok_or(V2FormatError::MaintenanceBudgetExceeded)?;
                for mut metadata in page.entries {
                    if object_class == V2OrphanObjectClass::Object
                        && self.is_inflight_standalone_object(&metadata.object_id)?
                    {
                        continue;
                    }
                    let exact_reachable = reachability
                        .reachable_versions
                        .contains(&(metadata.object_id.clone(), metadata.version_id.clone()));
                    let mut exact_protection_checked = !retained_profile;
                    if retained_profile {
                        if exact_reachable {
                            continue;
                        }
                        if let Some(version_id) = metadata.version_id.as_ref() {
                            ensure_next_budgeted_operation(
                                budgets.max_request_count,
                                request_count,
                            )?;
                            ensure_next_budgeted_operation(budgets.max_head_count, head_count)?;
                            request_count = request_count.saturating_add(1);
                            head_count = head_count.saturating_add(1);
                            if let Ok(head) = self
                                .store()
                                .head_at(&metadata.object_id, Some(version_id))
                                .await
                            {
                                metadata = head;
                                exact_protection_checked = true;
                            }
                        }
                    } else if reachability.reachable.contains(&metadata.object_id) {
                        continue;
                    }
                    let sequence = if object_class == V2OrphanObjectClass::Commit {
                        V2CommitKey::parse(&metadata.object_id)
                            .ok()
                            .map(|key| key.sequence)
                    } else {
                        None
                    };
                    let delete_blocked_by_unknown_protection = retained_profile
                        && (metadata.version_id.is_none() || !exact_protection_checked);
                    candidates.push(V2OrphanCandidate {
                        object_class,
                        object_id: metadata.object_id,
                        version_id: metadata.version_id,
                        content_len: metadata.content_len,
                        modified_at_ms: metadata.modified_at_ms,
                        sequence,
                        same_sequence_as_anchor: sequence
                            .zip(anchor_sequence)
                            .is_some_and(|(left, right)| left == right),
                        retention: metadata.retention,
                        retain_until_ms: metadata.retain_until_ms,
                        delete_blocked_by_retention: retention_blocks_delete(
                            metadata.retention.as_ref(),
                            metadata.retain_until_ms,
                            now_ms,
                        ),
                        delete_blocked_by_legal_hold: metadata.legal_hold
                            == Some(LegalHoldStatus::On),
                        delete_blocked_by_unknown_protection,
                    });
                }
                if page.is_complete {
                    break;
                }
            }
        }

        Ok(V2OrphanInventory {
            report: V2OrphanReport {
                reachable_commit_count: reachability.reachable_commit_versions.len(),
                reachable_object_count: reachability.reachable_object_versions.len(),
                candidates,
            },
            list_request_count,
            version_list_request_count: version_list_count,
            item_count: inventory_item_count,
        })
    }

    /// Deletes expired, unprotected v2 orphan objects.
    ///
    /// This pass is intentionally conservative: reachable objects are discovered
    /// from the anchor-selected chain, retained or legally held objects are
    /// skipped, candidates without a usable provider timestamp are skipped, and
    /// same-sequence candidates are skipped unless explicitly enabled.
    pub async fn delete_expired_orphans<A>(
        &self,
        anchor: &A,
        guard: &impl V2MaintenanceGuard,
        options: V2OrphanGcOptions,
    ) -> V2Result<V2OrphanGcReport>
    where
        A: V2CommitAnchor,
    {
        guard.verify_v2_maintenance(None).await?;
        let base_anchor = anchor.read_v2().await?;
        guard.verify_v2_maintenance(base_anchor.as_ref()).await?;
        let report = self.report_orphans(anchor).await?;
        self.delete_expired_orphan_candidates(
            anchor,
            guard,
            base_anchor.as_ref(),
            report,
            options,
            V2OrphanDeleteBounds {
                max_delete_count: None,
                cancellation: &V2MaintenanceCancellation::new(),
                op_pacing_delay: None,
            },
        )
        .await
    }

    /// Deletes expired orphan objects while preserving supplied historical roots.
    ///
    /// Supplied roots must bind the active exact format reference.
    pub async fn delete_expired_orphans_with_protected_roots<A>(
        &self,
        anchor: &A,
        guard: &impl V2MaintenanceGuard,
        protected_roots: &[V2AnchorState],
        options: V2OrphanGcOptions,
    ) -> V2Result<V2OrphanGcReport>
    where
        A: V2CommitAnchor,
    {
        guard.verify_v2_maintenance(None).await?;
        let base_anchor = anchor.read_v2().await?;
        guard.verify_v2_maintenance(base_anchor.as_ref()).await?;
        let report = self
            .report_orphans_with_protected_roots(anchor, protected_roots)
            .await?;
        self.delete_expired_orphan_candidates(
            anchor,
            guard,
            base_anchor.as_ref(),
            report,
            options,
            V2OrphanDeleteBounds {
                max_delete_count: None,
                cancellation: &V2MaintenanceCancellation::new(),
                op_pacing_delay: None,
            },
        )
        .await
    }

    async fn delete_expired_orphan_candidates<A>(
        &self,
        anchor: &A,
        guard: &impl V2MaintenanceGuard,
        base_anchor: Option<&V2AnchorState>,
        report: V2OrphanReport,
        options: V2OrphanGcOptions,
        bounds: V2OrphanDeleteBounds<'_>,
    ) -> V2Result<V2OrphanGcReport>
    where
        A: V2CommitAnchor,
    {
        let V2OrphanDeleteBounds {
            max_delete_count,
            cancellation,
            op_pacing_delay,
        } = bounds;
        let now_ms = self.maintenance_now_ms();
        let min_age_ms = options.min_age.as_millis();
        let mut gc = V2OrphanGcReport {
            scanned_count: report.candidates.len(),
            ..V2OrphanGcReport::default()
        };
        let mut delete_attempt_count = 0_u64;

        for candidate in report.candidates {
            if candidate.delete_blocked_by_retention
                || candidate.delete_blocked_by_legal_hold
                || candidate.delete_blocked_by_unknown_protection
            {
                gc.protected_count += 1;
                continue;
            }
            if candidate.same_sequence_as_anchor && !options.delete_same_sequence {
                gc.same_sequence_skipped_count += 1;
                continue;
            }
            let Some(age_ms) = age_since_ms(now_ms, candidate.modified_at_ms) else {
                gc.age_skipped_count += 1;
                continue;
            };
            if age_ms < min_age_ms {
                gc.age_skipped_count += 1;
                continue;
            }
            if max_delete_count.is_some_and(|max| delete_attempt_count >= max) {
                break;
            }
            // A cancelled pass mirrors a mid-pass guard abort: it stops before
            // the next delete and reports how far the partial pass got.
            if cancellation.is_cancelled() {
                gc.aborted = Some(V2FormatError::MaintenanceCancelled);
                return Ok(gc);
            }
            if let Err(error) = guard.verify_v2_maintenance(base_anchor).await {
                gc.aborted = Some(error);
                return Ok(gc);
            }
            if anchor.read_v2().await? != base_anchor.cloned() {
                gc.aborted = Some(V2FormatError::StaleAnchor);
                return Ok(gc);
            }
            pace_maintenance_operation(op_pacing_delay).await;

            let delete = if self.provider_profile() == V2ProviderProfile::RetainedVersionObjectLock
            {
                let Some(version_id) = candidate.version_id.as_ref() else {
                    gc.protected_count += 1;
                    continue;
                };
                self.store()
                    .delete_at(&candidate.object_id, Some(version_id))
                    .await
            } else {
                self.store().delete(&candidate.object_id).await
            };
            delete_attempt_count = delete_attempt_count.saturating_add(1);

            match delete {
                Ok(()) => gc.deleted_count += 1,
                Err(StorageError::NotFound(_)) => gc.already_gone_count += 1,
                Err(StorageError::RetentionBlocked | StorageError::LegalHoldBlocked) => {
                    gc.protected_count += 1;
                }
                Err(_) => gc.failed_delete_count += 1,
            }
        }

        Ok(gc)
    }

    async fn load_reachability<A>(
        &self,
        anchor: &A,
        protected_roots: &[V2AnchorState],
        budgets: V2MaintenanceBudgets,
        include_restore_metadata: bool,
        collect_packed_usage: bool,
    ) -> V2Result<V2ReachabilityState>
    where
        A: V2CommitAnchor,
    {
        self.load_reachability_from_state(
            anchor.read_v2().await?,
            protected_roots,
            budgets,
            include_restore_metadata,
            collect_packed_usage,
            false,
        )
        .await
    }

    // A candidate is an exact read-only graph root, never latest-state authority.
    // Publication callers must separately fence and recheck the real parent.
    async fn load_reachability_from_state(
        &self,
        anchor_state: Option<V2AnchorState>,
        protected_roots: &[V2AnchorState],
        budgets: V2MaintenanceBudgets,
        include_restore_metadata: bool,
        collect_packed_usage: bool,
        include_current_history: bool,
    ) -> V2Result<V2ReachabilityState> {
        if anchor_state
            .as_ref()
            .is_some_and(|state| state.format_ref != self.options().format_ref)
            || protected_roots
                .iter()
                .any(|root| root.format_ref != self.options().format_ref)
        {
            return Err(V2FormatError::InvalidFormatRoot);
        }
        let mut reachability = V2ReachabilityState {
            anchor_state: anchor_state.clone(),
            packed_usage: packed_usage::PackedUsage::new(collect_packed_usage),
            ..V2ReachabilityState::default()
        };

        if let Some(state) = anchor_state.as_ref() {
            let chain = self
                .load_maintenance_chain(state, &reachability, budgets)
                .await?;
            reachability.include_chain(&chain, false, None, None)?;
            let current_state = self
                .include_live_payload_roots(&mut reachability, &chain, false, budgets)
                .await?;
            reachability.current_chain = Some(chain);
            reachability.current_state = Some(current_state);
            reachability.mark_current_recovery_dependencies();
        }

        for protected_root in protected_roots {
            let chain = self
                .load_maintenance_chain(protected_root, &reachability, budgets)
                .await?;
            reachability.include_chain(&chain, true, None, None)?;
            self.include_live_payload_roots(&mut reachability, &chain, true, budgets)
                .await?;
        }

        self.include_recovery_history(&mut reachability, budgets, include_current_history)
            .await?;

        if include_restore_metadata {
            self.include_restore_metadata_roots(&mut reachability, budgets)
                .await?;
        }

        Ok(reachability)
    }

    async fn include_restore_metadata_roots(
        &self,
        reachability: &mut V2ReachabilityState,
        budgets: V2MaintenanceBudgets,
    ) -> V2Result<()> {
        let retention = reachability
            .renewal_targets
            .values()
            .fold(self.retention_policy(), |retention, target| {
                strongest_retention(retention, target.required_retention)
            });
        let required_deadline = reachability
            .renewal_targets
            .values()
            .filter_map(|target| target.required_deadline)
            .max();
        let has_legal_hold = reachability
            .renewal_targets
            .values()
            .any(|target| target.required_legal_hold == Some(LegalHoldStatus::On));
        if has_legal_hold {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        let Some(retention) = active_retention(retention) else {
            return Ok(());
        };
        let Some(keyring) = self.options().maintenance_keyring_envelope_ref.as_ref() else {
            return Err(V2FormatError::ProviderProfileFailed);
        };
        if keyring.commit_ref()? != self.options().keyring_envelope_ref {
            return Err(V2FormatError::InvalidFormatRoot);
        }
        let roots = [
            (
                self.options().format_ref.object_id.clone(),
                self.options().format_ref.version_id.clone(),
            ),
            (keyring.object_id.clone(), keyring.version_id.clone()),
        ];
        let retained_profile =
            self.provider_profile() == V2ProviderProfile::RetainedVersionObjectLock;
        for (object_id, version_id) in roots {
            if retained_profile && version_id.is_none() {
                return Err(V2FormatError::ProviderProfileFailed);
            }
            ensure_next_budgeted_operation(
                budgets.max_request_count,
                reachability
                    .chain_get_count
                    .saturating_add(reachability.graph_head_count),
            )?;
            ensure_next_budgeted_operation(budgets.max_head_count, reachability.graph_head_count)?;
            reachability.graph_head_count = reachability.graph_head_count.saturating_add(1);
            let exact = self
                .store()
                .head_at(&object_id, version_id.as_ref())
                .await
                .map_err(|_| V2FormatError::StorageOperationFailed)?;
            if exact.object_id != object_id
                || version_id.is_some() && exact.version_id != version_id
                || exact.content_len == 0
            {
                return Err(V2FormatError::ProviderProfileFailed);
            }
            reachability.include_renewal_target(
                object_id,
                version_id,
                exact.content_len,
                Some(retention),
                None,
                required_deadline,
            )?;
        }
        Ok(())
    }

    async fn load_maintenance_chain(
        &self,
        root: &V2AnchorState,
        reachability: &V2ReachabilityState,
        budgets: V2MaintenanceBudgets,
    ) -> V2Result<V2ReplayChain> {
        let configured = self.options().replay_limits;
        let used_commits = usize::try_from(reachability.chain_get_count)
            .map_err(|_| V2FormatError::MaintenanceBudgetExceeded)?;
        let max_commits = configured
            .max_commits
            .checked_sub(used_commits)
            .ok_or(V2FormatError::ReplayBudgetExceeded)?;
        let max_total_commit_bytes = configured
            .max_total_commit_bytes
            .checked_sub(reachability.chain_read_bytes)
            .ok_or(V2FormatError::ReplayBudgetExceeded)?;
        let max_retained_bytes = configured
            .max_retained_bytes
            .checked_sub(reachability.chain_retained_bytes)
            .ok_or(V2FormatError::ReplayBudgetExceeded)?;

        if max_commits == 0 || max_total_commit_bytes == 0 || max_retained_bytes == 0 {
            return Err(V2FormatError::MaintenanceBudgetExceeded);
        }
        self.load_replay_chain_with_pending_limit(
            root,
            V2ReplayLimits {
                max_commits,
                max_total_commit_bytes,
                max_retained_bytes,
                ..configured
            },
            budgets
                .max_history_pending_bytes
                .checked_sub(reachability.chain_retained_bytes)
                .ok_or(V2FormatError::MaintenanceBudgetExceeded)?,
        )
        .await
    }

    async fn include_live_payload_roots(
        &self,
        reachability: &mut V2ReachabilityState,
        chain: &V2ReplayChain,
        protected: bool,
        budgets: V2MaintenanceBudgets,
    ) -> V2Result<RepositoryState> {
        let limits = self.remaining_graph_limits(reachability, budgets)?;
        let (state, live_payload_roots, referenced_run_commits, represented_retention) =
            self.live_payload_roots_from_chain(chain, limits).await?;
        for commit in &chain.commits_newest_first {
            reachability.include_required_protection(
                &commit.parsed_header.header.self_ref.commit_key,
                commit.version_id.as_ref(),
                represented_retention,
                None,
            )?;
        }
        let current_run_max = chain
            .commits_newest_first
            .iter()
            .flat_map(|commit| &commit.parsed_header.header.section_index)
            .filter(|section| section.section_type == V2SectionType::IndexRun)
            .map(|section| section.length)
            .max()
            .unwrap_or(0);
        let catalog_scratch = referenced_run_commits
            .iter()
            .flat_map(|commit| &commit.parsed_header.header.section_index)
            .filter(|section| section.section_type == V2SectionType::IndexRun)
            .map(|section| section.length)
            .max()
            .unwrap_or(0);
        reachability.current_catalog_max_run_bytes = reachability
            .current_catalog_max_run_bytes
            .max(catalog_scratch)
            .max(current_run_max);
        reachability.history_peak_pending_bytes = reachability.history_peak_pending_bytes.max(
            reachability
                .chain_retained_bytes
                .checked_add(
                    super::repository::metadata_section_buffer_bytes(
                        catalog_scratch,
                        limits.read_chunk_bytes,
                    )?
                    .max(
                        reachability
                            .current_max_section_bytes
                            .min(limits.read_chunk_bytes),
                    ),
                )
                .ok_or(V2FormatError::MaintenanceBudgetExceeded)?,
        );
        if !referenced_run_commits.is_empty() {
            reachability.include_chain(
                &V2ReplayChain {
                    commits_newest_first: referenced_run_commits,
                },
                protected,
                represented_retention,
                None,
            )?;
        }
        for root in live_payload_roots {
            match root {
                V2LivePayloadRoot::Commit {
                    root,
                    retention,
                    legal_hold,
                } => {
                    let version_key = (root.commit_key.clone(), root.version_id.clone());
                    if reachability.reachable_versions.contains(&version_key) {
                        reachability.include_required_protection(
                            &root.commit_key,
                            root.version_id.as_ref(),
                            retention,
                            legal_hold,
                        )?;
                        continue;
                    }
                    ensure_next_budgeted_operation(
                        budgets.max_request_count,
                        reachability
                            .chain_get_count
                            .saturating_add(reachability.graph_head_count),
                    )?;
                    let commit = self
                        .read_commit_facts_at(&root.commit_key, root.version_id.as_ref())
                        .await?;
                    if commit.parsed_header.header.self_ref.sequence != root.sequence
                        || commit.parsed_header.header.body_digest != root.body_digest
                        || commit.version_id != root.version_id
                    {
                        return Err(V2FormatError::BodyDigestMismatch);
                    }
                    reachability.include_chain(
                        &V2ReplayChain {
                            commits_newest_first: vec![commit],
                        },
                        protected,
                        retention,
                        legal_hold,
                    )?;
                }
                V2LivePayloadRoot::Standalone {
                    root,
                    retention,
                    legal_hold,
                } => {
                    validate_standalone_payload_root(&root)?;
                    ensure_next_budgeted_operation(
                        budgets.max_request_count,
                        reachability
                            .chain_get_count
                            .saturating_add(reachability.graph_head_count),
                    )?;
                    ensure_next_budgeted_operation(
                        budgets.max_head_count,
                        reachability.graph_head_count,
                    )?;
                    reachability.graph_head_count = reachability.graph_head_count.saturating_add(1);
                    let exact = self
                        .store()
                        .head_at(&root.object_id, root.version_id.as_ref())
                        .await
                        .map_err(|_| V2FormatError::StorageOperationFailed)?;
                    if exact.object_id != root.object_id
                        || root.version_id.is_some() && exact.version_id != root.version_id
                        || exact.content_len != root.stored_len
                        || legal_hold == Some(LegalHoldStatus::On)
                            && exact.legal_hold != Some(LegalHoldStatus::On)
                    {
                        return Err(V2FormatError::ProviderProfileFailed);
                    }
                    reachability.include_standalone(root, protected, retention, legal_hold)?;
                }
            }
        }

        if reachability.packed_usage.enabled {
            for entry in state.namespace.live_entries() {
                reachability.include_packed_usage(entry, budgets)?;
            }
        }

        Ok(state)
    }

    fn remaining_graph_limits(
        &self,
        reachability: &V2ReachabilityState,
        budgets: V2MaintenanceBudgets,
    ) -> V2Result<V2ReplayLimits> {
        let configured = self.options().replay_limits;
        let used_commits = usize::try_from(reachability.chain_get_count)
            .map_err(|_| V2FormatError::MaintenanceBudgetExceeded)?;
        let max_commits = configured
            .max_commits
            .checked_sub(used_commits)
            .ok_or(V2FormatError::ReplayBudgetExceeded)?;
        let max_total_commit_bytes = configured
            .max_total_commit_bytes
            .checked_sub(reachability.chain_read_bytes)
            .ok_or(V2FormatError::ReplayBudgetExceeded)?;
        let max_retained_bytes = configured
            .max_retained_bytes
            .min(budgets.max_history_pending_bytes)
            .checked_sub(reachability.chain_retained_bytes)
            .ok_or(V2FormatError::ReplayBudgetExceeded)?;
        Ok(V2ReplayLimits {
            max_commits,
            max_total_commit_bytes,
            max_retained_bytes,
            ..configured
        })
    }

    async fn live_payload_roots_from_chain(
        &self,
        chain: &V2ReplayChain,
        limits: V2ReplayLimits,
    ) -> V2Result<(
        RepositoryState,
        Vec<V2LivePayloadRoot>,
        Vec<V2ReplayCommit>,
        Option<RetentionPolicy>,
    )> {
        let (state, referenced_run_commits) =
            self.replay_chain_to_namespace_state(chain, limits).await?;
        let signing_key_id = chain
            .commits_newest_first
            .first()
            .ok_or(V2FormatError::InvalidHeaderField)?
            .parsed_header
            .header
            .signing_key_id
            .clone();
        let mut roots = Vec::new();
        let mut represented_retention = None;

        for entry in state.namespace.live_entries() {
            represented_retention = strongest_retention(represented_retention, entry.retention);
            let root = match &entry.payload_ref {
                Some(PayloadReference::V2Pack { carrier, .. }) => commit_payload_root(
                    carrier.commit_key.clone(),
                    carrier.commit_version_id.clone(),
                    carrier.body_digest,
                    &signing_key_id,
                    self.options().format_ref.clone(),
                    entry.retention,
                    entry.legal_hold,
                )?,
                Some(PayloadReference::V2StandaloneStream { carrier }) => {
                    V2LivePayloadRoot::Standalone {
                        root: standalone_payload_root(carrier),
                        retention: entry.retention,
                        legal_hold: entry.legal_hold,
                    }
                }
                None => continue,
                Some(PayloadReference::Pending | PayloadReference::V2PackSelf { .. }) => {
                    return Err(V2FormatError::InvalidHeaderField);
                }
            };
            roots.push(root);
        }

        Ok((state, roots, referenced_run_commits, represented_retention))
    }

    async fn replay_chain_to_namespace_state(
        &self,
        chain: &V2ReplayChain,
        limits: V2ReplayLimits,
    ) -> V2Result<(RepositoryState, Vec<V2ReplayCommit>)> {
        let mut state = RepositoryState::default();
        let mut referenced_run_commits = Vec::new();
        let mut previous_published_at_ms = None;
        for commit in chain.commits_newest_first.iter().rev() {
            let published_at_ms = commit.parsed_header.header.publish_time_ms;
            super::recovery::validate_parent_time(previous_published_at_ms, published_at_ms)?;
            previous_published_at_ms = Some(published_at_ms);
            referenced_run_commits.extend(
                self.apply_commit_sections_to_namespace_state(&mut state, commit, limits)
                    .await?,
            );
        }
        Ok((state, referenced_run_commits))
    }

    async fn apply_commit_sections_to_namespace_state(
        &self,
        state: &mut RepositoryState,
        commit: &V2ReplayCommit,
        limits: V2ReplayLimits,
    ) -> V2Result<Vec<V2ReplayCommit>> {
        let mut referenced_run_commits = Vec::new();
        for (index, section) in commit.parsed_header.header.section_index.iter().enumerate() {
            match section.section_type {
                V2SectionType::PayloadPack | V2SectionType::Recovery => {}
                V2SectionType::IndexRun => {
                    let section_bytes = commit_section_bytes(commit, index)?;
                    apply_packed_index_run(
                        self.keyring(),
                        &self.options().repository_id,
                        state,
                        V2PackedIndexRunReplay {
                            parsed_header: &commit.parsed_header,
                            version_id: commit.version_id.as_ref(),
                            object_len: commit.object_len,
                            section_ordinal: u32::try_from(index)
                                .map_err(|_| V2FormatError::SectionBounds)?,
                            stored_run: section_bytes,
                            level: 0,
                            compaction_generation: 0,
                            provider_profile: self.provider_profile(),
                        },
                    )
                    .map_err(|_| V2FormatError::InvalidIndexRun)?;
                }
                V2SectionType::IndexRoot => {
                    let section_bytes = commit_section_bytes(commit, index)?;
                    let resolved = self
                        .apply_index_root_to_state(
                            state,
                            commit,
                            u32::try_from(index).map_err(|_| V2FormatError::SectionBounds)?,
                            section_bytes,
                            limits,
                        )
                        .await?;
                    referenced_run_commits.extend(resolved.referenced_commits);
                }
                _ => return Err(V2FormatError::UnsupportedSection),
            }
        }
        Ok(referenced_run_commits)
    }

    /// Runs read-only quick maintenance checks.
    pub async fn quick_maintenance<A>(&self, anchor: &A) -> V2Result<V2MaintenanceReport>
    where
        A: V2CommitAnchor,
    {
        self.quick_maintenance_with_options(anchor, V2QuickMaintenanceOptions::default())
            .await
    }

    /// Runs read-only quick maintenance checks under explicit physical limits.
    pub async fn quick_maintenance_with_options<A>(
        &self,
        anchor: &A,
        options: V2QuickMaintenanceOptions,
    ) -> V2Result<V2MaintenanceReport>
    where
        A: V2CommitAnchor,
    {
        let budgeted_store = V2MaintenanceBudgetedStore::new(self.store(), options.budgets);
        let usage_handle = budgeted_store.clone();
        let budgeted_repository = self.rebind_store(budgeted_store);
        let result = budgeted_repository
            .quick_maintenance_inner(anchor, options)
            .await;
        let usage = usage_handle
            .usage()
            .map_err(|_| V2FormatError::StorageOperationFailed)?;
        if usage.exhausted {
            return Err(V2FormatError::MaintenanceBudgetExceeded);
        }
        result
    }

    async fn quick_maintenance_inner<A>(
        &self,
        anchor: &A,
        options: V2QuickMaintenanceOptions,
    ) -> V2Result<V2MaintenanceReport>
    where
        A: V2CommitAnchor,
    {
        let reachability = self
            .load_reachability(anchor, &[], options.budgets, true, true)
            .await?;
        let chain = reachability.current_chain.as_ref();
        let verified_commit_count = chain
            .map(|chain| chain.commits_newest_first.len())
            .unwrap_or_default();
        let now_ms = self.maintenance_now_ms();
        let last_anchored_commit_age_ms = chain
            .and_then(|chain| chain.commits_newest_first.first())
            .and_then(|commit| {
                age_since_ms(now_ms, Some(commit.parsed_header.header.publish_time_ms))
            });
        let orphans = self
            .report_orphans_from_reachability(&reachability, options.budgets)
            .await?
            .report;
        let orphan_candidate_bytes = orphans.candidates.iter().fold(0_u64, |total, candidate| {
            total.saturating_add(candidate.content_len)
        });
        let protected_orphan_candidate_count = orphans
            .candidates
            .iter()
            .filter(|candidate| {
                candidate.delete_blocked_by_retention
                    || candidate.delete_blocked_by_legal_hold
                    || candidate.delete_blocked_by_unknown_protection
            })
            .count();
        let oldest_orphan_age_ms = orphans
            .candidates
            .iter()
            .filter_map(|candidate| age_since_ms(now_ms, candidate.modified_at_ms))
            .max();
        let reclaimable_orphans = orphans.candidates.iter().filter_map(|candidate| {
            if candidate.delete_blocked_by_retention
                || candidate.delete_blocked_by_legal_hold
                || candidate.delete_blocked_by_unknown_protection
                || candidate.same_sequence_as_anchor && !options.orphan_gc.delete_same_sequence
            {
                return None;
            }
            let age_ms = age_since_ms(now_ms, candidate.modified_at_ms)?;
            (age_ms >= options.orphan_gc.min_age.as_millis()).then_some((candidate, age_ms))
        });
        let (
            reclaimable_orphan_candidate_count,
            reclaimable_orphan_candidate_bytes,
            oldest_reclaimable_orphan_age_ms,
        ) = reclaimable_orphans.fold(
            (0_usize, 0_u64, None),
            |(count, bytes, oldest), (candidate, age_ms)| {
                (
                    count.saturating_add(1),
                    bytes.saturating_add(candidate.content_len),
                    Some(oldest.map_or(age_ms, |current: u128| current.max(age_ms))),
                )
            },
        );
        let retention_renewal = if chain.is_some() {
            self.plan_retention_renewal(
                reachability.renewal_targets.values(),
                options.retention_renewal_horizon,
                options.budgets,
                0,
                0,
            )
            .await?
        } else {
            V2RetentionRenewalPlan::default()
        };
        let (packed_payload_stored_bytes, packed_payload_referenced_bytes) =
            reachability.packed_usage.totals()?;
        Ok(V2MaintenanceReport {
            packed_payload_stored_bytes,
            packed_payload_referenced_bytes,
            anchor_present: chain.is_some(),
            verified_commit_count,
            last_anchored_commit_age_ms,
            orphan_candidate_count: orphans.candidates.len(),
            orphan_candidate_bytes,
            protected_orphan_candidate_count,
            oldest_orphan_age_ms,
            reclaimable_orphan_candidate_count,
            reclaimable_orphan_candidate_bytes,
            oldest_reclaimable_orphan_age_ms,
            retention_renewal_commit_count: retention_renewal.commit_count,
            retention_renewal_bytes: retention_renewal.bytes,
            retention_renewal_blocked_count: retention_renewal.blocked_count,
            retention_renewal_blocked_bytes: retention_renewal.blocked_bytes,
            nearest_retain_until_ms: retention_renewal.nearest_retain_until_ms,
            recovery_expiry_due_ms: reachability.recovery_expiry_due_ms,
            recovery_recoverable_point_count: reachability.recovery_recoverable_point_count,
            recovery_oldest_recoverable_publish_time_ms: reachability
                .recovery_oldest_recoverable_publish_time_ms,
            recovery_historical_exact_bytes: reachability.recovery_historical_exact_bytes,
            recovery_clock_uncertainty_ms: reachability.recovery_clock_uncertainty_ms,
        })
    }

    /// Builds a path-redacted full-maintenance dry-run plan.
    ///
    /// This first-stage planner is intentionally limited to v2 object inventory
    /// and fully dead orphan deletion. Mixed accepted-commit repack details are
    /// filled by the repository service after namespace replay. Protected roots
    /// must bind the active exact format reference.
    pub async fn full_gc_dry_run<A>(
        &self,
        anchor: &A,
        options: V2FullGcDryRunOptions,
    ) -> V2Result<V2FullGcDryRunReport>
    where
        A: V2CommitAnchor,
    {
        self.build_full_gc_plan(anchor, options)
            .await
            .map(|plan| plan.report)
    }

    pub(super) async fn full_gc_dry_run_with_state<A>(
        &self,
        anchor: &A,
        options: V2FullGcDryRunOptions,
    ) -> V2Result<(
        V2FullGcDryRunReport,
        Option<(V2ReplayChain, RepositoryState)>,
    )>
    where
        A: V2CommitAnchor,
    {
        let plan = self.build_full_gc_plan(anchor, options).await?;
        let current = plan.current_chain.zip(plan.current_state);
        Ok((plan.report, current))
    }

    async fn build_full_gc_plan<A>(
        &self,
        anchor: &A,
        options: V2FullGcDryRunOptions,
    ) -> V2Result<V2FullGcPlan>
    where
        A: V2CommitAnchor,
    {
        let budgeted_store = V2MaintenanceBudgetedStore::new(self.store(), options.budgets);
        let usage_handle = budgeted_store.clone();
        let budgeted_repository = self.rebind_store(budgeted_store);
        let result = budgeted_repository
            .build_full_gc_plan_inner(anchor, options.clone())
            .await;
        let usage = usage_handle
            .usage()
            .map_err(|_| V2FormatError::StorageOperationFailed)?;
        if usage.exhausted {
            return Err(V2FormatError::MaintenanceBudgetExceeded);
        }
        let mut plan = result?;
        let mutation_request_count = plan
            .report
            .planned_cost
            .delete_count
            .saturating_add(plan.report.planned_cost.retention_extend_count)
            .saturating_add(plan.report.planned_cost.retention_extend_count);
        plan.report.planned_cost.request_count =
            usage.request_count.saturating_add(mutation_request_count);
        plan.report.planned_cost.version_list_count = usage.version_list_count;
        plan.report.planned_cost.head_count = usage
            .head_count
            .saturating_add(plan.report.planned_cost.retention_extend_count);
        plan.report.planned_cost.range_read_bytes = usage.range_read_bytes;
        plan.report.planned_cost.inventory_page_count = usage.list_page_count;
        plan.report.fits_budgets = plan.report.planned_cost.fits_budgets(options.budgets);
        Ok(plan)
    }

    async fn build_full_gc_plan_inner<A>(
        &self,
        anchor: &A,
        options: V2FullGcDryRunOptions,
    ) -> V2Result<V2FullGcPlan>
    where
        A: V2CommitAnchor,
    {
        let reachability = self
            .load_reachability(
                anchor,
                &options.protected_roots,
                options.budgets,
                true,
                false,
            )
            .await?;
        let chain_live_commit_count = reachability
            .current_chain
            .as_ref()
            .map(|chain| chain.commits_newest_first.len())
            .unwrap_or_default();
        let inventory = self
            .report_orphans_from_reachability(&reachability, options.budgets)
            .await?;
        let list_request_count = inventory.list_request_count;
        let version_list_count = inventory.version_list_request_count;
        let inventory_item_count = inventory.item_count;
        let orphans = inventory.report;
        let retained_profile =
            self.provider_profile() == V2ProviderProfile::RetainedVersionObjectLock;
        let inventory_head_count = if retained_profile {
            usize_to_u64(
                orphans
                    .candidates
                    .iter()
                    .filter(|candidate| candidate.version_id.is_some())
                    .count(),
            )
        } else {
            0
        };
        let used_head_count = reachability
            .graph_head_count
            .saturating_add(inventory_head_count);
        let used_request_count = reachability
            .chain_get_count
            .saturating_add(used_head_count)
            .saturating_add(list_request_count);
        let retention_renewal = self
            .plan_retention_renewal(
                reachability.renewal_targets.values(),
                options.retention_renewal_horizon,
                options.budgets,
                used_request_count,
                used_head_count,
            )
            .await?;

        let mut fully_dead_commit_count = 0;
        let mut dead_bytes_reclaimable = 0_u64;
        let mut retention_blocked_bytes = 0_u64;
        let mut legal_hold_blocked_bytes = 0_u64;
        let mut unknown_protection_blocked_bytes = 0_u64;
        let mut delete_count = 0_u64;
        let mut head_count = 0_u64;

        for candidate in &orphans.candidates {
            if retained_profile && candidate.version_id.is_some() {
                head_count = head_count.saturating_add(1);
            }
            if candidate.delete_blocked_by_retention {
                retention_blocked_bytes =
                    retention_blocked_bytes.saturating_add(candidate.content_len);
                continue;
            }
            if candidate.delete_blocked_by_legal_hold {
                legal_hold_blocked_bytes =
                    legal_hold_blocked_bytes.saturating_add(candidate.content_len);
                continue;
            }
            if candidate.delete_blocked_by_unknown_protection {
                unknown_protection_blocked_bytes =
                    unknown_protection_blocked_bytes.saturating_add(candidate.content_len);
                continue;
            }

            fully_dead_commit_count += 1;
            dead_bytes_reclaimable = dead_bytes_reclaimable.saturating_add(candidate.content_len);
            delete_count = delete_count.saturating_add(1);
        }

        let prefix_list_count = list_request_count.saturating_sub(version_list_count);
        let chain_get_count = reachability.chain_get_count;
        let planned_cost = V2MaintenancePlanCost {
            request_count: version_list_count
                .saturating_add(prefix_list_count)
                .saturating_add(chain_get_count)
                .saturating_add(reachability.graph_head_count)
                .saturating_add(head_count)
                .saturating_add(delete_count)
                .saturating_add(retention_renewal.head_count)
                .saturating_add(retention_renewal.extend_count),
            version_list_count,
            head_count: head_count
                .saturating_add(reachability.graph_head_count)
                .saturating_add(retention_renewal.head_count),
            range_read_bytes: reachability.chain_read_bytes,
            write_bytes: 0,
            delete_count,
            retention_extend_count: retention_renewal.extend_count,
            inventory_page_count: list_request_count,
            inventory_item_count,
        };
        let fits_budgets = planned_cost.fits_budgets(options.budgets);
        let exact_version_apply_ready = !retained_profile
            || orphans.candidates.iter().all(|candidate| {
                candidate.version_id.is_some() || candidate.delete_blocked_by_unknown_protection
            });

        let report = V2FullGcDryRunReport {
            base_sequence: reachability
                .anchor_state
                .as_ref()
                .map(|anchor| anchor.sequence),
            chain_live_commit_count,
            protected_root_count: options.protected_roots.len(),
            protected_commit_count: reachability.protected_versions.len(),
            candidate_commit_count: orphans.candidates.len(),
            fully_dead_commit_count,
            mixed_commit_count: 0,
            dead_bytes_reclaimable,
            live_bytes_to_copy: 0,
            mixed_dead_bytes_repackable: 0,
            retention_blocked_bytes,
            legal_hold_blocked_bytes,
            unknown_protection_blocked_bytes,
            retention_renewal_commit_count: retention_renewal.commit_count,
            retention_renewal_bytes: retention_renewal.bytes,
            retention_renewal_blocked_count: retention_renewal.blocked_count,
            retention_renewal_blocked_bytes: retention_renewal.blocked_bytes,
            planned_cost,
            fits_budgets,
            exact_version_apply_ready,
        };
        Ok(V2FullGcPlan {
            report,
            base_anchor: reachability.anchor_state,
            recovery_expire_before_ms: reachability.recovery_expire_before_ms,
            verified_current_recovery_floor_ms: reachability.current_recovery_floor_ms,
            retention_renewal,
            orphans,
            current_chain: reachability.current_chain,
            current_state: reachability.current_state,
        })
    }

    /// Applies guarded exact retention renewal, then fully dead orphan deletion.
    ///
    /// This does not repack mixed accepted commits. A failed run may already
    /// have irreversibly strengthened some exact-version retention, but no
    /// orphan deletion begins until every planned renewal succeeds. Apply fails
    /// closed unless the dry-run budget passes, retained-version provider
    /// conformance is supplied for retained repositories, and the maintenance
    /// guard plus base anchor are still valid before each mutation. Protected
    /// roots must bind the active exact format reference.
    pub async fn apply_full_gc<A, G>(
        &self,
        anchor: &A,
        guard: &G,
        options: V2FullGcApplyOptions,
    ) -> V2Result<V2FullGcApplyReport>
    where
        A: V2CommitAnchor,
        G: V2MaintenanceGuard,
    {
        self.apply_full_gc_cancellable(anchor, guard, options, &V2MaintenanceCancellation::new())
            .await
    }

    /// Applies guarded full maintenance with a cooperative cancellation signal.
    ///
    /// Identical to [`Self::apply_full_gc`], except the run stops cleanly at
    /// the next mutation boundary once `cancellation` fires. Cancellation
    /// during renewal fails the run with
    /// [`V2FormatError::MaintenanceCancelled`] before the next renewal call;
    /// cancellation during deletion returns the partial orphan report with the
    /// same abort marker. Nothing already mutated is rolled back, and a later
    /// run replans from current state and completes the remainder.
    pub async fn apply_full_gc_cancellable<A, G>(
        &self,
        anchor: &A,
        guard: &G,
        options: V2FullGcApplyOptions,
        cancellation: &V2MaintenanceCancellation,
    ) -> V2Result<V2FullGcApplyReport>
    where
        A: V2CommitAnchor,
        G: V2MaintenanceGuard,
    {
        let prepared = self.prepare_full_gc_plan(anchor, options).await?;
        self.apply_prepared_full_gc_cancellable(anchor, guard, prepared, cancellation)
            .await
    }

    pub(super) async fn prepare_full_gc_plan<A>(
        &self,
        anchor: &A,
        options: V2FullGcApplyOptions,
    ) -> V2Result<V2PreparedFullGcPlan>
    where
        A: V2CommitAnchor,
    {
        let plan = self
            .build_full_gc_plan(anchor, options.dry_run.clone())
            .await?;
        let plan_digest = full_gc_plan_digest(&plan, &options);
        Ok(V2PreparedFullGcPlan {
            plan_digest,
            options,
            plan,
        })
    }

    pub(super) async fn apply_prepared_full_gc_cancellable<A, G>(
        &self,
        anchor: &A,
        guard: &G,
        prepared: V2PreparedFullGcPlan,
        cancellation: &V2MaintenanceCancellation,
    ) -> V2Result<V2FullGcApplyReport>
    where
        A: V2CommitAnchor,
        G: V2MaintenanceGuard,
    {
        let V2PreparedFullGcPlan { options, plan, .. } = prepared;
        guard.verify_v2_maintenance(None).await?;
        let base_anchor = plan.base_anchor.clone();
        guard.verify_v2_maintenance(base_anchor.as_ref()).await?;

        if self.provider_profile() == V2ProviderProfile::RetainedVersionObjectLock
            && !options.retained_provider_conformance_passed
        {
            return Err(V2FormatError::ProviderProfileFailed);
        }

        let V2FullGcPlan {
            report: dry_run,
            verified_current_recovery_floor_ms,
            retention_renewal,
            orphans,
            ..
        } = plan;
        if !dry_run.fits_budgets {
            return Err(V2FormatError::MaintenanceBudgetExceeded);
        }
        if !dry_run.exact_version_apply_ready {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        if dry_run.retention_renewal_blocked_count != 0 {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        if anchor.read_v2().await? != base_anchor {
            return Err(V2FormatError::StaleAnchor);
        }

        let op_pacing_delay = options.dry_run.budgets.op_pacing_delay;
        let (retention_renewed_object_count, retention_renewed_bytes) = self
            .apply_retention_renewal(
                anchor,
                guard,
                base_anchor.as_ref(),
                retention_renewal.targets,
                cancellation,
                op_pacing_delay,
            )
            .await?;

        if let (Some(base_anchor), Some(verified_current_floor_ms)) =
            (base_anchor.as_ref(), verified_current_recovery_floor_ms)
        {
            guard.verify_v2_maintenance(Some(base_anchor)).await?;
            if anchor.read_v2().await?.as_ref() != Some(base_anchor) {
                return Err(V2FormatError::StaleAnchor);
            }
            self.cache_verified_recovery_coverage(base_anchor, verified_current_floor_ms);
        }

        let gc = if options.reclamation_enabled {
            self.delete_expired_orphan_candidates(
                anchor,
                guard,
                base_anchor.as_ref(),
                orphans,
                options.orphan_gc,
                V2OrphanDeleteBounds {
                    max_delete_count: Some(dry_run.planned_cost.delete_count),
                    cancellation,
                    op_pacing_delay,
                },
            )
            .await?
        } else {
            V2OrphanGcReport::default()
        };

        Ok(V2FullGcApplyReport {
            dry_run,
            retention_renewed_object_count,
            retention_renewed_bytes,
            orphan_gc: gc,
        })
    }

    /// Protects an accepted copy reference while its caller excludes publication and GC.
    /// At most three exact targets and nine backend operations; never reads payload bytes.
    pub(super) async fn protect_copy_source<A, G>(
        &self,
        anchor: &A,
        guard: &G,
        base_anchor: &V2AnchorState,
        source: &NamespaceEntry,
        modified_at_ms: i64,
    ) -> V2Result<()>
    where
        A: V2CommitAnchor,
        G: V2MaintenanceGuard + ?Sized,
    {
        if source.legal_hold == Some(LegalHoldStatus::On) {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        let Some(policy) = active_retention(strongest_retention(
            self.retention_policy(),
            source.retention,
        )) else {
            return Ok(());
        };
        if self.provider_profile() != V2ProviderProfile::RetainedVersionObjectLock {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        let deadline = modified_at_ms
            .checked_add(i64::from(policy.retain_days) * 86_400_000)
            .filter(|_| modified_at_ms >= 0)
            .ok_or(V2FormatError::ProviderProfileFailed)?;
        let keyring = self
            .options()
            .maintenance_keyring_envelope_ref
            .as_ref()
            .ok_or(V2FormatError::ProviderProfileFailed)?;
        if keyring.commit_ref()? != self.options().keyring_envelope_ref {
            return Err(V2FormatError::InvalidFormatRoot);
        }
        let mut targets = Vec::with_capacity(3);
        let carrier = match &source.payload_ref {
            Some(PayloadReference::V2Pack { carrier, .. }) => Some((
                carrier.commit_key.clone(),
                carrier.commit_version_id.clone(),
                carrier.commit_stored_len,
                &carrier.content_key_id,
            )),
            Some(PayloadReference::V2StandaloneStream { carrier }) => Some((
                carrier.object_id.clone(),
                carrier.version_id.clone(),
                carrier.stored_len,
                &carrier.payload_layout.key_id,
            )),
            None if source.content_len == 0 => None,
            _ => return Err(V2FormatError::InvalidHeaderField),
        };
        if let Some((object_id, version_id, stored_len, content_key_id)) = carrier {
            // Historical envelope IDs/digests remain immutable AEAD context. Restore
            // uses the historical content key carried by the configured current keyring.
            if !self.keyring().descriptors().iter().any(|key| {
                &key.id == content_key_id
                    && key.purpose == rs3_types::KeyPurpose::Content
                    && key.status.is_enabled_for_lookup()
            }) {
                return Err(V2FormatError::ProviderProfileFailed);
            }
            targets.push((object_id, version_id, Some(stored_len)));
        }
        targets.extend([
            (
                self.options().format_ref.object_id.clone(),
                self.options().format_ref.version_id.clone(),
                None,
            ),
            (keyring.object_id.clone(), keyring.version_id.clone(), None),
        ]);
        // Reject incomplete exact references before any provider operation.
        if targets
            .iter()
            .any(|(_, version, length)| version.is_none() || *length == Some(0))
        {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        for (object_id, version_id, stored_len) in targets {
            guard.verify_v2_maintenance(Some(base_anchor)).await?;
            if anchor.read_v2().await?.as_ref() != Some(base_anchor) {
                return Err(V2FormatError::StaleAnchor);
            }
            let observed = self
                .store()
                .head_at(&object_id, version_id.as_ref())
                .await
                .map_err(|_| V2FormatError::StorageOperationFailed)?;
            if observed.object_id != object_id
                || observed.version_id != version_id
                || observed.content_len == 0
                || stored_len.is_some_and(|length| length != observed.content_len)
            {
                return Err(V2FormatError::ProviderProfileFailed);
            }
            let observed_deadline = observed
                .retain_until_ms
                .ok_or(V2FormatError::ProviderProfileFailed)?;
            let observed_policy =
                active_retention(observed.retention).ok_or(V2FormatError::ProviderProfileFailed)?;
            let required_deadline = deadline.max(observed_deadline);
            let required_policy = strongest_retention(Some(policy), Some(observed_policy))
                .ok_or(V2FormatError::ProviderProfileFailed)?;
            if observed_deadline >= deadline
                && retention_satisfies(observed.retention.as_ref(), &required_policy)
            {
                continue;
            }
            let target = V2RetentionTarget {
                object_id,
                version_id,
                stored_len: observed.content_len,
                required_retention: Some(required_policy),
                required_legal_hold: observed.legal_hold,
                required_deadline: Some(required_deadline),
                current_recovery_dependency: false,
            };
            self.extend_and_verify_retention_target(anchor, guard, Some(base_anchor), &target)
                .await?;
        }
        guard.verify_v2_maintenance(Some(base_anchor)).await?;
        if anchor.read_v2().await?.as_ref() != Some(base_anchor) {
            return Err(V2FormatError::StaleAnchor);
        }
        Ok(())
    }

    async fn extend_and_verify_retention_target<A, G>(
        &self,
        anchor: &A,
        guard: &G,
        base_anchor: Option<&V2AnchorState>,
        target: &V2RetentionTarget,
    ) -> V2Result<i64>
    where
        A: V2CommitAnchor,
        G: V2MaintenanceGuard + ?Sized,
    {
        guard.verify_v2_maintenance(base_anchor).await?;
        if anchor.read_v2().await? != base_anchor.cloned() {
            return Err(V2FormatError::StaleAnchor);
        }
        if self.provider_profile() == V2ProviderProfile::RetainedVersionObjectLock
            && target.version_id.is_none()
        {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        let requested_policy = target
            .required_retention
            .ok_or(V2FormatError::ProviderProfileFailed)?;
        // Absolute recovery floors are translated only after the fence and
        // anchor are verified, immediately before the provider mutation.
        let required_deadline = match target.required_deadline {
            Some(deadline) if deadline >= 0 => deadline,
            Some(_) => return Err(V2FormatError::ProviderProfileFailed),
            None => required_retain_until_ms(requested_policy, self.maintenance_now_ms())?,
        };
        let policy = super::recovery::policy::physical_retention_for_deadline(
            Some(requested_policy),
            target.required_deadline,
            self.maintenance_now_ms(),
        )?
        .ok_or(V2FormatError::ProviderProfileFailed)?;
        self.store()
            .extend_retention_at(&target.object_id, target.version_id.as_ref(), policy)
            .await
            .map_err(|_| V2FormatError::StorageOperationFailed)?;
        let exact = self
            .store()
            .head_at(&target.object_id, target.version_id.as_ref())
            .await
            .map_err(|_| V2FormatError::ProviderProfileFailed)?;
        let object_matches = exact.object_id == target.object_id;
        let version_matches = exact.version_id == target.version_id;
        let length_matches = exact.content_len == target.stored_len;
        let retention_matches = retention_satisfies(exact.retention.as_ref(), &policy);
        let legal_hold_matches = target.required_legal_hold != Some(LegalHoldStatus::On)
            || exact.legal_hold == Some(LegalHoldStatus::On);
        let deadline_matches = exact
            .retain_until_ms
            .is_some_and(|actual| actual >= required_deadline);
        if !(object_matches
            && version_matches
            && length_matches
            && retention_matches
            && legal_hold_matches
            && deadline_matches)
        {
            tracing::error!(
                target: "rs3_repository",
                operation = "v2_retention_renewal_verify",
                object_matches,
                version_matches,
                length_matches,
                retention_matches,
                legal_hold_matches,
                deadline_matches,
                "exact retention renewal postcondition failed",
            );
            return Err(V2FormatError::ProviderProfileFailed);
        }
        exact
            .retain_until_ms
            .ok_or(V2FormatError::ProviderProfileFailed)
    }

    async fn apply_retention_renewal<A, G>(
        &self,
        anchor: &A,
        guard: &G,
        base_anchor: Option<&V2AnchorState>,
        targets: Vec<V2RetentionTarget>,
        cancellation: &V2MaintenanceCancellation,
        op_pacing_delay: Option<Duration>,
    ) -> V2Result<(usize, u64)>
    where
        A: V2CommitAnchor,
        G: V2MaintenanceGuard,
    {
        let mut renewed_count = 0_usize;
        let mut renewed_bytes = 0_u64;

        for target in targets {
            // Renewals only strengthen protection, so a cancelled run keeps
            // everything already renewed and a later run replans the rest.
            if cancellation.is_cancelled() {
                return Err(V2FormatError::MaintenanceCancelled);
            }
            pace_maintenance_operation(op_pacing_delay).await;
            self.extend_and_verify_retention_target(anchor, guard, base_anchor, &target)
                .await?;
            renewed_count = renewed_count.saturating_add(1);
            renewed_bytes = renewed_bytes.saturating_add(target.stored_len);
        }

        Ok((renewed_count, renewed_bytes))
    }

    async fn plan_retention_renewal(
        &self,
        targets: impl IntoIterator<Item = &V2RetentionTarget>,
        horizon: Duration,
        budgets: V2MaintenanceBudgets,
        mut used_request_count: u64,
        mut used_head_count: u64,
    ) -> V2Result<V2RetentionRenewalPlan> {
        let retained_profile =
            self.provider_profile() == V2ProviderProfile::RetainedVersionObjectLock;
        let now_ms = self.maintenance_now_ms();
        let renew_before_ms = now_ms.saturating_add(duration_millis_i64_saturating(horizon));
        let mut plan = V2RetentionRenewalPlan::default();

        for target in targets {
            let requested_policy = active_retention(strongest_retention(
                self.retention_policy(),
                target.required_retention,
            ));
            let requires_hold = target.required_legal_hold == Some(LegalHoldStatus::On);
            if target
                .required_deadline
                .is_some_and(|deadline| deadline < 0)
                || target.required_deadline.is_some() && requested_policy.is_none()
            {
                plan.blocked_count = plan.blocked_count.saturating_add(1);
                plan.blocked_bytes = plan.blocked_bytes.saturating_add(target.stored_len);
                continue;
            }
            if requested_policy.is_none() && !requires_hold {
                continue;
            }
            let object_id = &target.object_id;
            let version_id = target.version_id.as_ref();
            if retained_profile && version_id.is_none() {
                plan.blocked_count = plan.blocked_count.saturating_add(1);
                plan.blocked_bytes = plan.blocked_bytes.saturating_add(target.stored_len);
                continue;
            }

            ensure_next_budgeted_operation(budgets.max_request_count, used_request_count)?;
            ensure_next_budgeted_operation(budgets.max_head_count, used_head_count)?;
            used_request_count = used_request_count.saturating_add(1);
            used_head_count = used_head_count.saturating_add(1);
            plan.head_count = plan.head_count.saturating_add(1);
            let metadata = if retained_profile {
                self.store().head_at(object_id, version_id).await
            } else {
                self.store().head(object_id).await
            }
            .map_err(|_| V2FormatError::StorageOperationFailed)?;

            if metadata.object_id != target.object_id
                || metadata.version_id != target.version_id
                || metadata.content_len != target.stored_len
                || requires_hold && metadata.legal_hold != Some(LegalHoldStatus::On)
            {
                plan.blocked_count = plan.blocked_count.saturating_add(1);
                plan.blocked_bytes = plan.blocked_bytes.saturating_add(target.stored_len);
                continue;
            }

            let policy = requested_policy.and_then(|requested| {
                active_retention(strongest_retention(
                    Some(requested),
                    active_retention(metadata.retention),
                ))
            });

            if policy.is_some()
                && let Some(retain_until_ms) = metadata.retain_until_ms
            {
                plan.nearest_retain_until_ms = Some(
                    plan.nearest_retain_until_ms
                        .map_or(retain_until_ms, |nearest| nearest.min(retain_until_ms)),
                );
            }

            if let Some(policy) = policy
                && (retention_renewal_needed(&metadata, policy, renew_before_ms)
                    || target.required_deadline.is_some_and(|deadline| {
                        metadata
                            .retain_until_ms
                            .is_none_or(|retain_until_ms| retain_until_ms < deadline)
                    }))
            {
                plan.commit_count = plan.commit_count.saturating_add(1);
                plan.bytes = plan.bytes.saturating_add(metadata.content_len);
                plan.extend_count = plan.extend_count.saturating_add(1);
                plan.head_count = plan.head_count.saturating_add(1);
                let (required_deadline, required_legal_hold) =
                    planned_renewal_requirements(target, &metadata, policy, now_ms)?;
                plan.targets.push(V2RetentionTarget {
                    object_id: metadata.object_id,
                    version_id: metadata.version_id,
                    stored_len: metadata.content_len,
                    required_retention: Some(policy),
                    required_legal_hold,
                    required_deadline: Some(required_deadline),
                    current_recovery_dependency: target.current_recovery_dependency,
                });
            }
        }

        Ok(plan)
    }
}

fn commit_payload_root(
    commit_key: BackendObjectId,
    version_id: Option<BackendVersionId>,
    body_digest: [u8; 32],
    signing_key_id: &rs3_types::KeyId,
    format_ref: super::V2FormatRef,
    retention: Option<RetentionPolicy>,
    legal_hold: Option<LegalHoldStatus>,
) -> V2Result<V2LivePayloadRoot> {
    let parsed_key = V2CommitKey::parse(&commit_key)?;
    Ok(V2LivePayloadRoot::Commit {
        root: V2AnchorState {
            sequence: parsed_key.sequence,
            commit_key,
            body_digest,
            version_id,
            signing_key_id: signing_key_id.clone(),
            format_ref,
        },
        retention,
        legal_hold,
    })
}

fn standalone_payload_root(
    carrier: &V2StandaloneStreamCarrierReference,
) -> V2StandalonePayloadRoot {
    V2StandalonePayloadRoot {
        object_id: carrier.object_id.clone(),
        version_id: carrier.version_id.clone(),
        stored_len: carrier.stored_len,
        object_digest: carrier.object_digest,
        keyring_envelope_object_id: carrier.keyring_envelope_object_id.clone(),
        keyring_envelope_digest: carrier.keyring_envelope_digest,
        payload_layout: carrier.payload_layout.clone(),
    }
}

fn validate_standalone_payload_root(root: &V2StandalonePayloadRoot) -> V2Result<()> {
    validate_v2_standalone_object(&root.object_id, root.stored_len)
}

#[cfg(not(test))]
fn current_time_ms() -> i64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis();
    i64::try_from(millis).unwrap_or(i64::MAX)
}

fn age_since_ms(now_ms: i64, timestamp_ms: Option<i64>) -> Option<u128> {
    let timestamp_ms = timestamp_ms?;
    let age_ms = now_ms.checked_sub(timestamp_ms)?;
    u128::try_from(age_ms).ok()
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn budget_allows(limit: Option<u64>, value: u64) -> bool {
    limit.is_none_or(|limit| value <= limit)
}

fn ensure_next_budgeted_operation(limit: Option<u64>, used: u64) -> V2Result<()> {
    if limit.is_some_and(|limit| used >= limit) {
        return Err(V2FormatError::MaintenanceBudgetExceeded);
    }
    Ok(())
}

/// Carries observed exact protections into an extension target.
///
/// A mutable provider operation must never weaken a longer observed deadline
/// or an active legal hold. Targets without an existing absolute floor retain
/// their moving relative renewal deadline.
fn planned_renewal_requirements(
    target: &V2RetentionTarget,
    metadata: &BlobMetadata,
    policy: RetentionPolicy,
    now_ms: i64,
) -> V2Result<(i64, Option<LegalHoldStatus>)> {
    let required_deadline = target
        .required_deadline
        .unwrap_or(planned_retain_until_ms_at(policy, now_ms)?);
    let required_deadline = metadata
        .retain_until_ms
        .map_or(required_deadline, |observed| {
            observed.max(required_deadline)
        });
    let required_legal_hold = if target.required_legal_hold == Some(LegalHoldStatus::On)
        || metadata.legal_hold == Some(LegalHoldStatus::On)
    {
        Some(LegalHoldStatus::On)
    } else {
        None
    };
    Ok((required_deadline, required_legal_hold))
}

fn retention_renewal_needed(
    metadata: &BlobMetadata,
    requested: RetentionPolicy,
    renew_before_ms: i64,
) -> bool {
    !retention_satisfies(metadata.retention.as_ref(), &requested)
        || metadata
            .retain_until_ms
            .is_none_or(|retain_until_ms| retain_until_ms <= renew_before_ms)
}

fn retention_blocks_delete(
    policy: Option<&RetentionPolicy>,
    retain_until_ms: Option<i64>,
    now_ms: i64,
) -> bool {
    match policy {
        Some(policy) if policy.mode != RetentionMode::None && policy.retain_days > 0 => {
            retain_until_ms.is_none_or(|retain_until_ms| retain_until_ms > now_ms)
        }
        Some(_) | None => false,
    }
}

fn duration_millis_i64_saturating(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

fn required_retain_until_ms(policy: RetentionPolicy, now_ms: i64) -> V2Result<i64> {
    now_ms
        .checked_add(
            i64::from(policy.retain_days)
                .checked_mul(86_400_000)
                .ok_or(V2FormatError::ProviderProfileFailed)?,
        )
        .ok_or(V2FormatError::ProviderProfileFailed)
}

fn planned_retain_until_ms_at(policy: RetentionPolicy, now_ms: i64) -> V2Result<i64> {
    super::recovery::policy::ceil_physical_deadline_ms(required_retain_until_ms(policy, now_ms)?)
}

fn commit_section_bytes(commit: &V2ReplayCommit, index: usize) -> V2Result<&[u8]> {
    commit
        .retained_sections
        .get(index)
        .and_then(Option::as_deref)
        .ok_or(V2FormatError::SectionBounds)
}

#[cfg(test)]
mod tests {
    use super::{
        V2FormatError, V2FullGcApplyOptions, V2FullGcDryRunOptions, V2FullGcDryRunReport,
        V2FullGcPlan, V2MaintenanceBudgetedStore, V2MaintenanceBudgets, V2MaintenancePlanCost,
        V2OrphanCandidate, V2OrphanGcOptions, V2OrphanObjectClass, V2OrphanReport,
        V2ReachabilityState, V2RetentionRenewalPlan, V2RetentionTarget, V2StandalonePayloadRoot,
        full_gc_plan_digest, planned_renewal_requirements, validate_standalone_payload_root,
    };
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use bytes::Bytes;
    use rs3_index::PayloadLayout;
    use rs3_storage::{BlobMetadata, BlobStore, MemoryBlobStore, PutOptions, read_bounded_full_at};
    use rs3_types::{
        BackendObjectId, BackendVersionId, KeyId, LegalHoldStatus, RetentionMode, RetentionPolicy,
    };
    use std::time::Duration;

    #[tokio::test]
    async fn bounded_full_read_charges_the_declared_object_length() {
        let store = MemoryBlobStore::new();
        let object_id = BackendObjectId::new("format/root").expect("object id");
        store
            .put(
                &object_id,
                Bytes::from_static(b"body"),
                PutOptions::default(),
            )
            .await
            .expect("store body");
        let budgeted = V2MaintenanceBudgetedStore::new(
            &store,
            V2MaintenanceBudgets {
                max_range_read_bytes: Some(4),
                ..V2MaintenanceBudgets::default()
            },
        );

        let body = read_bounded_full_at(&budgeted, &object_id, None, 8)
            .await
            .expect("bounded read");

        assert_eq!(body, Bytes::from_static(b"body"));
        let usage = budgeted.usage().expect("usage");
        assert_eq!(usage.request_count, 1);
        assert_eq!(usage.range_read_bytes, 4);
    }

    #[tokio::test]
    async fn bounded_full_read_reserves_request_budget_before_opening_backend_read() {
        let store = MemoryBlobStore::new();
        let object_id = BackendObjectId::new("format/root").expect("object id");
        store
            .put(
                &object_id,
                Bytes::from_static(b"body"),
                PutOptions::default(),
            )
            .await
            .expect("store body");
        store.reset_operation_counts().expect("reset counts");
        let budgeted = V2MaintenanceBudgetedStore::new(
            &store,
            V2MaintenanceBudgets {
                max_request_count: Some(0),
                ..V2MaintenanceBudgets::default()
            },
        );

        let result = read_bounded_full_at(&budgeted, &object_id, None, 8).await;

        assert!(result.is_err());
        assert_eq!(store.operation_counts().expect("operation counts").get, 0);
        assert!(budgeted.usage().expect("usage").exhausted);
    }

    fn standalone_root(byte: u8) -> V2StandalonePayloadRoot {
        V2StandalonePayloadRoot {
            object_id: BackendObjectId::new(format!(
                "objects/v03/{}",
                URL_SAFE_NO_PAD.encode([byte; 32])
            ))
            .expect("standalone object id"),
            version_id: Some(
                BackendVersionId::new(format!("standalone-version-{byte}")).expect("version id"),
            ),
            stored_len: 4_096,
            object_digest: [byte.wrapping_add(1); 32],
            keyring_envelope_object_id: BackendObjectId::new(format!("meta/v02/keyring-{byte}"))
                .expect("keyring object id"),
            keyring_envelope_digest: [byte.wrapping_add(2); 32],
            payload_layout: PayloadLayout {
                chunk_size: 1_024,
                plaintext_len: 3_000,
                key_id: KeyId::new(format!("content-key-{byte}")).expect("content key id"),
                carrier_id: [byte.wrapping_add(3); 32],
                parts: vec![rs3_index::PayloadPart {
                    part_number: 1,
                    attempt_id: rs3_types::PayloadAttemptId::from_bytes([0x81; 32]),
                    plaintext_len: 3_000,
                }],
            },
        }
    }

    fn digest_plan(candidate_ids: [&str; 2]) -> V2FullGcPlan {
        let candidates = candidate_ids
            .into_iter()
            .enumerate()
            .map(|(ordinal, object_id)| V2OrphanCandidate {
                object_class: V2OrphanObjectClass::Object,
                object_id: BackendObjectId::new(object_id).expect("candidate object ID"),
                version_id: Some(
                    BackendVersionId::new(format!("version-{ordinal}"))
                        .expect("candidate version ID"),
                ),
                content_len: if ordinal == 0 { 10 } else { 20 },
                modified_at_ms: Some(1_000 + ordinal as i64),
                sequence: None,
                same_sequence_as_anchor: false,
                retention: None,
                retain_until_ms: None,
                delete_blocked_by_retention: false,
                delete_blocked_by_legal_hold: false,
                delete_blocked_by_unknown_protection: false,
            })
            .collect();
        V2FullGcPlan {
            report: V2FullGcDryRunReport {
                base_sequence: None,
                chain_live_commit_count: 0,
                protected_root_count: 0,
                protected_commit_count: 0,
                candidate_commit_count: 2,
                fully_dead_commit_count: 2,
                mixed_commit_count: 0,
                dead_bytes_reclaimable: 30,
                live_bytes_to_copy: 0,
                mixed_dead_bytes_repackable: 0,
                retention_blocked_bytes: 0,
                legal_hold_blocked_bytes: 0,
                unknown_protection_blocked_bytes: 0,
                retention_renewal_commit_count: 0,
                retention_renewal_bytes: 0,
                retention_renewal_blocked_count: 0,
                retention_renewal_blocked_bytes: 0,
                planned_cost: V2MaintenancePlanCost {
                    delete_count: 2,
                    ..V2MaintenancePlanCost::default()
                },
                fits_budgets: true,
                exact_version_apply_ready: true,
            },
            base_anchor: None,
            recovery_expire_before_ms: None,
            verified_current_recovery_floor_ms: None,
            retention_renewal: V2RetentionRenewalPlan::default(),
            orphans: V2OrphanReport {
                reachable_commit_count: 0,
                reachable_object_count: 0,
                candidates,
            },
            current_chain: None,
            current_state: None,
        }
    }

    fn digest_options() -> V2FullGcApplyOptions {
        V2FullGcApplyOptions {
            dry_run: V2FullGcDryRunOptions::default(),
            orphan_gc: V2OrphanGcOptions::new_for_test_rehearsal(Duration::ZERO),
            retained_provider_conformance_passed: true,
            reclamation_enabled: true,
        }
    }

    #[test]
    fn exact_plan_digest_rejects_aggregate_collisions_and_ignores_inventory_order() {
        let first = digest_plan(["objects/v03/a", "objects/v03/b"]);
        let collision = digest_plan(["objects/v03/c", "objects/v03/d"]);
        assert_eq!(first.report, collision.report);
        assert_ne!(
            full_gc_plan_digest(&first, &digest_options()),
            full_gc_plan_digest(&collision, &digest_options())
        );

        let mut reordered = first.clone();
        reordered.orphans.candidates.reverse();
        assert_eq!(
            full_gc_plan_digest(&first, &digest_options()),
            full_gc_plan_digest(&reordered, &digest_options())
        );

        let mut reclamation_disabled = digest_options();
        reclamation_disabled.reclamation_enabled = false;
        assert_ne!(
            full_gc_plan_digest(&first, &digest_options()),
            full_gc_plan_digest(&first, &reclamation_disabled)
        );
    }

    #[test]
    fn canonical_physical_floor_changes_plan_digest_at_the_next_bucket() {
        const DAY: i64 = 86_400_000;
        let mut within_bucket = digest_plan(["objects/v03/a", "objects/v03/b"]);
        within_bucket.verified_current_recovery_floor_ms = Some(3 * DAY);
        let mut next_bucket = within_bucket.clone();
        next_bucket.verified_current_recovery_floor_ms = Some(4 * DAY);
        assert_ne!(
            full_gc_plan_digest(&within_bucket, &digest_options()),
            full_gc_plan_digest(&next_bucket, &digest_options())
        );
    }

    #[test]
    fn standalone_roots_mark_exact_live_and_protected_versions() {
        let root = standalone_root(0x31);
        validate_standalone_payload_root(&root).expect("valid standalone root");
        let version_key = (root.object_id.clone(), root.version_id.clone());
        let mut reachability = V2ReachabilityState::default();

        reachability
            .include_standalone(root.clone(), false, None, None)
            .expect("mark live standalone root");
        assert!(reachability.reachable.contains(&root.object_id));
        assert!(reachability.reachable_versions.contains(&version_key));
        assert!(
            reachability
                .reachable_object_versions
                .contains(&version_key)
        );
        assert!(!reachability.protected_versions.contains(&version_key));
        assert_eq!(reachability.renewal_targets.len(), 1);

        reachability
            .include_standalone(root.clone(), true, None, None)
            .expect("protect exact standalone root");
        assert!(reachability.protected_versions.contains(&version_key));
        assert_eq!(reachability.renewal_targets.len(), 1);

        let mut conflicting = root;
        conflicting.object_digest[0] ^= 1;
        assert!(
            reachability
                .include_standalone(conflicting, true, None, None)
                .is_err()
        );
    }

    #[test]
    fn standalone_roots_require_canonical_random_object_keys() {
        let valid = standalone_root(0x41);
        assert!(validate_standalone_payload_root(&valid).is_ok());

        for invalid in [
            "objects/v03/short",
            "objects/v03/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "objects/v03/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+",
            "objects/v03/AAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAA",
            "commits/v03/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            let mut root = valid.clone();
            root.object_id = BackendObjectId::new(invalid).expect("syntactically valid object id");
            assert!(
                validate_standalone_payload_root(&root).is_err(),
                "accepted malformed standalone key {invalid}"
            );
        }

        let mut empty = valid;
        empty.stored_len = 0;
        assert!(validate_standalone_payload_root(&empty).is_err());
    }

    #[test]
    fn renewal_targets_scale_with_unique_exact_versions_and_reject_conflicts() {
        let mut reachability = V2ReachabilityState::default();
        for ordinal in 0..4_096_u64 {
            let object_id = BackendObjectId::new(format!("objects/v03/{ordinal:020}"))
                .expect("bounded object ID");
            reachability
                .include_renewal_target(object_id, None, ordinal + 1, None, None, None)
                .expect("unique target");
        }
        assert_eq!(reachability.renewal_targets.len(), 4_096);

        let object_id =
            BackendObjectId::new("objects/v03/00000000000000000000").expect("bounded object ID");
        assert_eq!(
            reachability.include_renewal_target(object_id, None, 2, None, None, None),
            Err(V2FormatError::ProviderProfileFailed)
        );
    }

    #[test]
    fn planned_renewal_preserves_observed_deadline_and_legal_hold() {
        let object_id =
            BackendObjectId::new("objects/v03/renewal-observed").expect("bounded object id");
        let version_id = Some(BackendVersionId::new("version-observed").expect("version id"));
        let policy = RetentionPolicy::new(RetentionMode::Compliance, 1);
        let target = V2RetentionTarget {
            object_id: object_id.clone(),
            version_id: version_id.clone(),
            stored_len: 32,
            required_retention: Some(policy),
            required_legal_hold: None,
            required_deadline: Some(2_000),
            current_recovery_dependency: false,
        };
        let metadata = BlobMetadata {
            object_id,
            content_len: 32,
            modified_at_ms: None,
            etag: None,
            version_id,
            retention: Some(RetentionPolicy::new(RetentionMode::Governance, 30)),
            retain_until_ms: Some(3_000),
            legal_hold: Some(LegalHoldStatus::On),
        };

        let (deadline, hold) = planned_renewal_requirements(&target, &metadata, policy, 0)
            .expect("planned requirements");
        assert_eq!(deadline, 3_000);
        assert_eq!(hold, Some(LegalHoldStatus::On));

        let no_fixed_floor = V2RetentionTarget {
            required_deadline: None,
            ..target
        };
        let (moving_deadline, _) = planned_renewal_requirements(
            &no_fixed_floor,
            &BlobMetadata {
                retain_until_ms: Some(0),
                legal_hold: None,
                ..metadata
            },
            policy,
            0,
        )
        .expect("moving deadline");
        assert!(
            moving_deadline > 0,
            "relative renewal must advance a missing floor"
        );
    }

    #[test]
    fn renewal_targets_merge_strongest_fixed_deadline_per_exact_version() {
        let object_id =
            BackendObjectId::new("objects/v03/renewal-target").expect("bounded object ID");
        let version_id = Some(BackendVersionId::new("version-a").expect("version ID"));
        let mut reachability = V2ReachabilityState::default();

        reachability
            .include_renewal_target(
                object_id.clone(),
                version_id.clone(),
                32,
                None,
                None,
                Some(1_000),
            )
            .expect("first target");
        reachability
            .include_renewal_target(
                object_id.clone(),
                version_id.clone(),
                32,
                None,
                None,
                Some(2_000),
            )
            .expect("stronger target");

        let target = reachability
            .renewal_targets
            .get(&(object_id, version_id))
            .expect("merged exact target");
        assert_eq!(target.required_deadline, Some(2_000));
    }
}
