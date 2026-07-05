//! Fault-injecting `BlobStore` test utilities.

use crate::{
    BlobMetadata, BlobMultipartUpload, BlobStore, ByteRange, PutOptions, Result, StorageError,
};
use async_trait::async_trait;
use bytes::Bytes;
use rs3_types::{BackendObjectId, BackendVersionId, LegalHoldStatus, RetentionPolicy};
use std::collections::BTreeSet;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Blob-store operation observed by the fault-injection wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultOperationKind {
    /// Whole-object write.
    Put,
    /// Multipart upload creation.
    CreateMultipartUpload,
    /// Multipart part upload.
    MultipartPutPart,
    /// Multipart completion.
    MultipartComplete,
    /// Multipart abort.
    MultipartAbort,
    /// Latest-version range read.
    GetRange,
    /// Version-addressed range read.
    GetRangeAt,
    /// Latest-version metadata read.
    Head,
    /// Version-addressed metadata read.
    HeadAt,
    /// Latest-version prefix listing.
    ListPrefix,
    /// Version-addressed prefix listing.
    ListPrefixVersions,
    /// Latest-version delete.
    Delete,
    /// Version-addressed delete.
    DeleteAt,
    /// Latest-version retention extension.
    ExtendRetention,
    /// Version-addressed retention extension.
    ExtendRetentionAt,
    /// Latest-version legal-hold update.
    SetLegalHold,
    /// Version-addressed legal-hold update.
    SetLegalHoldAt,
    /// Cache flush.
    FlushCaches,
}

/// One observed operation in a fault-injection run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultEvent {
    /// Zero-based operation index within this wrapper.
    pub operation_index: u64,
    /// Operation kind.
    pub kind: FaultOperationKind,
    /// Object identifier, when the operation addresses one object.
    pub object_id: Option<BackendObjectId>,
    /// Prefix string, when the operation lists a prefix.
    pub prefix: Option<String>,
}

/// Match criteria for a one-shot injected fault.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FaultMatcher {
    operation_index: Option<u64>,
    kind: Option<FaultOperationKind>,
    object_prefix: Option<String>,
}

impl FaultMatcher {
    /// Matches one exact operation index.
    pub fn operation_index(operation_index: u64) -> Self {
        Self {
            operation_index: Some(operation_index),
            kind: None,
            object_prefix: None,
        }
    }

    /// Matches the next operation of a given kind.
    pub fn operation(kind: FaultOperationKind) -> Self {
        Self {
            operation_index: None,
            kind: Some(kind),
            object_prefix: None,
        }
    }

    /// Narrows this matcher to one operation kind.
    pub fn with_operation(mut self, kind: FaultOperationKind) -> Self {
        self.kind = Some(kind);
        self
    }

    /// Narrows this matcher to object ids or list prefixes with the given opaque prefix.
    pub fn with_object_prefix(mut self, object_prefix: impl Into<String>) -> Self {
        self.object_prefix = Some(object_prefix.into());
        self
    }

    fn matches(&self, event: &FaultEvent) -> bool {
        self.operation_index
            .is_none_or(|operation_index| operation_index == event.operation_index)
            && self.kind.is_none_or(|kind| kind == event.kind)
            && self.object_prefix.as_ref().is_none_or(|object_prefix| {
                event
                    .object_id
                    .as_ref()
                    .is_some_and(|object_id| object_id.as_str().starts_with(object_prefix))
                    || event
                        .prefix
                        .as_deref()
                        .is_some_and(|prefix| prefix.starts_with(object_prefix))
            })
    }
}

/// Shared crash hook triggered by a `FaultAction::crash_point`.
#[derive(Clone, Default)]
pub struct FaultCrashHook {
    hit_count: Arc<AtomicUsize>,
    last_event: Arc<RwLock<Option<FaultEvent>>>,
}

impl FaultCrashHook {
    /// Creates a hook with no recorded crash points.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns how many times the hook was triggered.
    pub fn hit_count(&self) -> usize {
        self.hit_count.load(Ordering::SeqCst)
    }

    /// Returns the most recent crash-point event, when one was recorded.
    pub fn last_event(&self) -> Option<FaultEvent> {
        self.last_event.read().ok().and_then(|event| event.clone())
    }

    fn trigger(&self, event: FaultEvent) {
        self.hit_count.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut last_event) = self.last_event.write() {
            *last_event = Some(event);
        }
    }
}

impl fmt::Debug for FaultCrashHook {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FaultCrashHook")
            .field("hit_count", &self.hit_count())
            .field("last_event", &self.last_event())
            .finish()
    }
}

/// One fault action to apply when a rule matches.
#[derive(Clone, Debug)]
pub struct FaultAction {
    kind: FaultActionKind,
}

impl FaultAction {
    /// Returns a provider error before calling the wrapped store.
    pub fn return_error(message: impl Into<String>) -> Self {
        Self {
            kind: FaultActionKind::ReturnError(message.into()),
        }
    }

    /// Sleeps before calling the wrapped store.
    pub fn delay(duration: Duration) -> Self {
        Self {
            kind: FaultActionKind::Delay(duration),
        }
    }

    /// Calls the wrapped store and returns a provider error after a successful operation.
    pub fn error_after_write(message: impl Into<String>) -> Self {
        Self {
            kind: FaultActionKind::ErrorAfterWrite(message.into()),
        }
    }

    /// Omits the newest entries from a successful list result.
    pub fn stale_list(omit_newest: usize) -> Self {
        Self {
            kind: FaultActionKind::StaleList(omit_newest),
        }
    }

    /// Triggers a crash hook and returns a provider error before calling the wrapped store.
    pub fn crash_point(hook: FaultCrashHook) -> Self {
        Self {
            kind: FaultActionKind::CrashPoint(hook),
        }
    }
}

#[derive(Clone, Debug)]
enum FaultActionKind {
    ReturnError(String),
    Delay(Duration),
    ErrorAfterWrite(String),
    StaleList(usize),
    CrashPoint(FaultCrashHook),
}

/// One one-shot rule in a fault schedule.
#[derive(Clone, Debug)]
pub struct FaultRule {
    matcher: FaultMatcher,
    action: FaultAction,
}

impl FaultRule {
    /// Creates a rule from a matcher and an action.
    pub fn new(matcher: FaultMatcher, action: FaultAction) -> Self {
        Self { matcher, action }
    }
}

/// A `BlobStore` wrapper that injects deterministic, one-shot operation faults.
#[derive(Clone, Debug)]
pub struct FaultInjectingBlobStore<S> {
    inner: S,
    script: FaultScript,
}

impl<S> FaultInjectingBlobStore<S> {
    /// Wraps a store with an initial one-shot fault schedule.
    pub fn new(inner: S, rules: Vec<FaultRule>) -> Self {
        Self {
            inner,
            script: FaultScript::new(rules),
        }
    }

    /// Returns the wrapped store.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Adds one one-shot fault rule to the end of the schedule.
    pub fn push_rule(&self, rule: FaultRule) -> Result<()> {
        self.script.push_rule(rule)
    }

    /// Returns the next operation index that will be assigned.
    pub fn next_operation_index(&self) -> Result<u64> {
        self.script.next_operation_index()
    }

    /// Returns the observed operation log.
    pub fn operation_log(&self) -> Result<Vec<FaultEvent>> {
        self.script.operation_log()
    }
}

#[derive(Clone, Debug)]
struct FaultScript {
    state: Arc<RwLock<FaultState>>,
}

#[derive(Debug)]
struct FaultState {
    next_operation_index: u64,
    rules: Vec<FaultRule>,
    events: Vec<FaultEvent>,
}

impl FaultScript {
    fn new(rules: Vec<FaultRule>) -> Self {
        Self {
            state: Arc::new(RwLock::new(FaultState {
                next_operation_index: 0,
                rules,
                events: Vec::new(),
            })),
        }
    }

    fn push_rule(&self, rule: FaultRule) -> Result<()> {
        let mut state = self.write_state()?;
        state.rules.push(rule);
        Ok(())
    }

    fn next_operation_index(&self) -> Result<u64> {
        let state = self.read_state()?;
        Ok(state.next_operation_index)
    }

    fn operation_log(&self) -> Result<Vec<FaultEvent>> {
        let state = self.read_state()?;
        Ok(state.events.clone())
    }

    fn read_state(&self) -> Result<std::sync::RwLockReadGuard<'_, FaultState>> {
        self.state
            .read()
            .map_err(|_| StorageError::Provider("fault-injection state lock poisoned".to_owned()))
    }

    fn write_state(&self) -> Result<std::sync::RwLockWriteGuard<'_, FaultState>> {
        self.state
            .write()
            .map_err(|_| StorageError::Provider("fault-injection state lock poisoned".to_owned()))
    }

    fn begin(
        &self,
        kind: FaultOperationKind,
        object_id: Option<&BackendObjectId>,
        prefix: Option<&str>,
    ) -> Result<FaultEffect> {
        let (event, action) = {
            let mut state = self.write_state()?;
            let event = FaultEvent {
                operation_index: state.next_operation_index,
                kind,
                object_id: object_id.cloned(),
                prefix: prefix.map(ToOwned::to_owned),
            };
            state.next_operation_index = state.next_operation_index.saturating_add(1);
            state.events.push(event.clone());
            let action = state
                .rules
                .iter()
                .position(|rule| rule.matcher.matches(&event))
                .map(|index| state.rules.remove(index).action);
            (event, action)
        };

        let Some(action) = action else {
            return Ok(FaultEffect::Continue);
        };
        match action.kind {
            FaultActionKind::ReturnError(message) => Err(injected_error(message)),
            FaultActionKind::Delay(duration) => {
                if !duration.is_zero() {
                    std::thread::sleep(duration);
                }
                Ok(FaultEffect::Continue)
            }
            FaultActionKind::ErrorAfterWrite(message) => Ok(FaultEffect::ErrorAfterWrite(message)),
            FaultActionKind::StaleList(omit_newest) => Ok(FaultEffect::StaleList(omit_newest)),
            FaultActionKind::CrashPoint(hook) => {
                hook.trigger(event);
                Err(injected_error("crash point"))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum FaultEffect {
    Continue,
    ErrorAfterWrite(String),
    StaleList(usize),
}

fn finish_success<T>(value: T, effect: FaultEffect) -> Result<T> {
    match effect {
        FaultEffect::Continue | FaultEffect::StaleList(_) => Ok(value),
        FaultEffect::ErrorAfterWrite(message) => Err(injected_error(message)),
    }
}

fn injected_error(message: impl Into<String>) -> StorageError {
    StorageError::Provider(format!("fault injection: {}", message.into()))
}

fn omit_newest(entries: Vec<BlobMetadata>, omit_newest: usize) -> Vec<BlobMetadata> {
    if omit_newest == 0 || entries.is_empty() {
        return entries;
    }
    let mut newest = entries
        .iter()
        .map(|metadata| {
            (
                metadata.modified_at_ms.unwrap_or(i64::MIN),
                metadata.object_id.clone(),
                metadata.version_id.clone(),
            )
        })
        .collect::<Vec<_>>();
    newest.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| right.1.cmp(&left.1))
            .then_with(|| right.2.cmp(&left.2))
    });
    let omitted = newest
        .into_iter()
        .take(omit_newest)
        .map(|(_, object_id, version_id)| (object_id, version_id))
        .collect::<BTreeSet<_>>();
    entries
        .into_iter()
        .filter(|metadata| {
            !omitted.contains(&(metadata.object_id.clone(), metadata.version_id.clone()))
        })
        .collect()
}

#[async_trait]
impl<S> BlobStore for FaultInjectingBlobStore<S>
where
    S: BlobStore,
{
    async fn put(
        &self,
        object_id: &BackendObjectId,
        body: Bytes,
        options: PutOptions,
    ) -> Result<BlobMetadata> {
        let effect = self
            .script
            .begin(FaultOperationKind::Put, Some(object_id), None)?;
        let metadata = self.inner.put(object_id, body, options).await?;
        finish_success(metadata, effect)
    }

    fn supports_multipart_upload(&self) -> bool {
        self.inner.supports_multipart_upload()
    }

    async fn create_multipart_upload(
        &self,
        object_id: &BackendObjectId,
        options: PutOptions,
    ) -> Result<Box<dyn BlobMultipartUpload>> {
        let effect = self.script.begin(
            FaultOperationKind::CreateMultipartUpload,
            Some(object_id),
            None,
        )?;
        let upload = self
            .inner
            .create_multipart_upload(object_id, options)
            .await?;
        let upload = Box::new(FaultInjectingMultipartUpload {
            inner: upload,
            script: self.script.clone(),
            object_id: object_id.clone(),
        });
        finish_success(upload as Box<dyn BlobMultipartUpload>, effect)
    }

    async fn get_range(&self, object_id: &BackendObjectId, range: ByteRange) -> Result<Bytes> {
        let effect = self
            .script
            .begin(FaultOperationKind::GetRange, Some(object_id), None)?;
        let body = self.inner.get_range(object_id, range).await?;
        finish_success(body, effect)
    }

    async fn get_range_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        range: ByteRange,
    ) -> Result<Bytes> {
        let effect = self
            .script
            .begin(FaultOperationKind::GetRangeAt, Some(object_id), None)?;
        let body = self
            .inner
            .get_range_at(object_id, version_id, range)
            .await?;
        finish_success(body, effect)
    }

    async fn head(&self, object_id: &BackendObjectId) -> Result<BlobMetadata> {
        let effect = self
            .script
            .begin(FaultOperationKind::Head, Some(object_id), None)?;
        let metadata = self.inner.head(object_id).await?;
        finish_success(metadata, effect)
    }

    async fn head_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
    ) -> Result<BlobMetadata> {
        let effect = self
            .script
            .begin(FaultOperationKind::HeadAt, Some(object_id), None)?;
        let metadata = self.inner.head_at(object_id, version_id).await?;
        finish_success(metadata, effect)
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<BlobMetadata>> {
        let effect = self
            .script
            .begin(FaultOperationKind::ListPrefix, None, Some(prefix))?;
        let entries = self.inner.list_prefix(prefix).await?;
        match effect {
            FaultEffect::StaleList(omit_count) => Ok(omit_newest(entries, omit_count)),
            other => finish_success(entries, other),
        }
    }

    async fn list_prefix_versions(&self, prefix: &str) -> Result<Vec<BlobMetadata>> {
        let effect =
            self.script
                .begin(FaultOperationKind::ListPrefixVersions, None, Some(prefix))?;
        let entries = self.inner.list_prefix_versions(prefix).await?;
        match effect {
            FaultEffect::StaleList(omit_count) => Ok(omit_newest(entries, omit_count)),
            other => finish_success(entries, other),
        }
    }

    async fn delete(&self, object_id: &BackendObjectId) -> Result<()> {
        let effect = self
            .script
            .begin(FaultOperationKind::Delete, Some(object_id), None)?;
        self.inner.delete(object_id).await?;
        finish_success((), effect)
    }

    async fn delete_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
    ) -> Result<()> {
        let effect = self
            .script
            .begin(FaultOperationKind::DeleteAt, Some(object_id), None)?;
        self.inner.delete_at(object_id, version_id).await?;
        finish_success((), effect)
    }

    async fn extend_retention(
        &self,
        object_id: &BackendObjectId,
        policy: RetentionPolicy,
    ) -> Result<()> {
        let effect =
            self.script
                .begin(FaultOperationKind::ExtendRetention, Some(object_id), None)?;
        self.inner.extend_retention(object_id, policy).await?;
        finish_success((), effect)
    }

    async fn extend_retention_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        policy: RetentionPolicy,
    ) -> Result<()> {
        let effect =
            self.script
                .begin(FaultOperationKind::ExtendRetentionAt, Some(object_id), None)?;
        self.inner
            .extend_retention_at(object_id, version_id, policy)
            .await?;
        finish_success((), effect)
    }

    async fn set_legal_hold(
        &self,
        object_id: &BackendObjectId,
        status: LegalHoldStatus,
    ) -> Result<()> {
        let effect = self
            .script
            .begin(FaultOperationKind::SetLegalHold, Some(object_id), None)?;
        self.inner.set_legal_hold(object_id, status).await?;
        finish_success((), effect)
    }

    async fn set_legal_hold_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        status: LegalHoldStatus,
    ) -> Result<()> {
        let effect =
            self.script
                .begin(FaultOperationKind::SetLegalHoldAt, Some(object_id), None)?;
        self.inner
            .set_legal_hold_at(object_id, version_id, status)
            .await?;
        finish_success((), effect)
    }

    async fn flush_caches(&self) -> Result<()> {
        let effect = self
            .script
            .begin(FaultOperationKind::FlushCaches, None, None)?;
        self.inner.flush_caches().await?;
        finish_success((), effect)
    }
}

struct FaultInjectingMultipartUpload {
    inner: Box<dyn BlobMultipartUpload>,
    script: FaultScript,
    object_id: BackendObjectId,
}

#[async_trait]
impl BlobMultipartUpload for FaultInjectingMultipartUpload {
    async fn put_part(&mut self, part_index: usize, body: Bytes) -> Result<()> {
        let effect = self.script.begin(
            FaultOperationKind::MultipartPutPart,
            Some(&self.object_id),
            None,
        )?;
        self.inner.put_part(part_index, body).await?;
        finish_success((), effect)
    }

    async fn complete(self: Box<Self>) -> Result<BlobMetadata> {
        let Self {
            inner,
            script,
            object_id,
        } = *self;
        let effect = script.begin(
            FaultOperationKind::MultipartComplete,
            Some(&object_id),
            None,
        )?;
        let metadata = inner.complete().await?;
        finish_success(metadata, effect)
    }

    async fn abort(self: Box<Self>) -> Result<()> {
        let Self {
            inner,
            script,
            object_id,
        } = *self;
        let effect = script.begin(FaultOperationKind::MultipartAbort, Some(&object_id), None)?;
        inner.abort().await?;
        finish_success((), effect)
    }
}
