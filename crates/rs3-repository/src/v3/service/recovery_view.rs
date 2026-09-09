//! Operator selection from the current authenticated registry, without anchor writes.

use super::*;
use crate::v3::V3AnchorState;
use crate::v3::recovery::history::RecoveryPoint;

/// Maximum number of point descriptions returned in one operator request.
const MAX_POINT_LIMIT: usize = 256;

/// A path-redacted authenticated restore point. Sequences identify commits.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct V3RecoveryPointInfo {
    /// Exact commit sequence, independent of namespace generations.
    pub sequence: u64,
    /// Authenticated publication time in Unix milliseconds.
    pub publish_time_ms: i64,
    /// Immutable history deadline; the current point has no expiry.
    pub protected_until_ms: Option<i64>,
    /// True only for the current accepted head.
    pub current: bool,
}

/// Opaque continuation bound to one accepted registry. It conveys no authority.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V3RecoveryCursor {
    sequence: u64,
    digest: [u8; 32],
    group: usize,
    offset: usize,
}

impl V3RecoveryCursor {
    /// Encodes a bounded continuation for a later operator command.
    pub fn encode(&self) -> Result<String> {
        serde_json::to_vec(self)
            .map(hex::encode)
            .map_err(|_| unavailable("invalid recovery cursor"))
    }

    /// Decodes an untrusted continuation; registry binding is checked on use.
    pub fn decode(value: &str) -> Result<Self> {
        if value.len() > 1024 {
            return Err(unavailable("invalid recovery cursor"));
        }
        let bytes = hex::decode(value).map_err(|_| unavailable("invalid recovery cursor"))?;
        serde_json::from_slice(&bytes).map_err(|_| unavailable("invalid recovery cursor"))
    }
}

/// One bounded page. Empty pages may still have a continuation.
#[derive(Clone, Debug, serde::Serialize)]
pub struct V3RecoveryPointPage {
    /// Current authority that authenticated this page.
    pub registry_sequence: u64,
    /// Ordered point descriptions, oldest first.
    pub points: Vec<V3RecoveryPointInfo>,
    /// Continue under the same registry, or restart if it has advanced.
    pub next_cursor: Option<V3RecoveryCursor>,
}

struct Registry {
    anchor: V3AnchorState,
    published_at_ms: i64,
    history: AcceptedRecoveryState,
    selected_point: Option<RecoveryPoint>,
}

/// An isolated historical namespace with only the existing reader exposed.
///
/// The selected root's embedded history is never installed as authority.
/// Call `check_authority` before each read admission. Already admitted reads use
/// the fixed selected state; this facade cannot publish or rewind an anchor.
pub struct V3RecoveryView<S> {
    reader: V3Repository<S>,
    selected: V3AnchorState,
    authority: Mutex<Registry>,
}

fn unavailable(reason: &'static str) -> RepositoryError {
    RepositoryError::CommitFailed {
        reason: reason.to_owned(),
    }
}

fn registry_binding(anchor: &V3AnchorState) -> Result<[u8; 32]> {
    let bytes =
        serde_json::to_vec(anchor).map_err(|_| unavailable("invalid recovery authority"))?;
    Ok(digest_v3_section(&bytes))
}

fn operator_now_ms() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| unavailable("recovery clock is unavailable"))?;
    i64::try_from(duration.as_millis()).map_err(|_| unavailable("recovery clock is unavailable"))
}

fn point_info(point: &RecoveryPoint) -> V3RecoveryPointInfo {
    V3RecoveryPointInfo {
        sequence: point.anchor.sequence.get(),
        publish_time_ms: point.publish_time_ms,
        protected_until_ms: Some(point.protected_until_ms),
        current: false,
    }
}

fn live_point(point: &RecoveryPoint, registry: &Registry, now_ms: i64) -> bool {
    point.protected_until_ms > registry.history.snapshot.expire_before_ms
        && point.protected_until_ms > now_ms
}

impl<S: BlobStore> V3CommitStore<S> {
    async fn operator_registry<A: V3CommitAnchor>(&self, anchor: &A) -> Result<Registry> {
        let state = anchor
            .read_v3()
            .await
            .map_err(v3_repository_error)?
            .ok_or_else(|| unavailable("recovery requires a current accepted anchor"))?;
        if state.format_ref != self.options().format_ref {
            return Err(unavailable(
                "recovery format binding changed; reopen the reader",
            ));
        }
        let chain = self
            .load_replay_chain_from_state(&state)
            .await
            .map_err(v3_repository_error)?;
        let history = self
            .replay_recovery_history(&chain)
            .map_err(v3_repository_error)?
            .ok_or_else(|| unavailable("authenticated recovery history is unavailable"))?;
        let published_at_ms = chain
            .commits_newest_first
            .first()
            .ok_or_else(|| unavailable("authenticated recovery history is unavailable"))?
            .parsed_header
            .header
            .publish_time_ms;
        if anchor.read_v3().await.map_err(v3_repository_error)? != Some(state.clone()) {
            return Err(v3_repository_error(V3FormatError::StaleAnchor));
        }
        Ok(Registry {
            anchor: state,
            published_at_ms,
            history,
            selected_point: None,
        })
    }

    async fn operator_point(
        &self,
        registry: &mut Registry,
        sequence: Sequence,
        now_ms: i64,
    ) -> Result<V3AnchorState> {
        if sequence == registry.anchor.sequence {
            return Ok(registry.anchor.clone());
        }
        if let Some(point) = &registry.selected_point
            && point.anchor.sequence == sequence
        {
            return if live_point(point, registry, now_ms) {
                Ok(point.anchor.clone())
            } else {
                Err(unavailable("recovery point is expired or unknown"))
            };
        }
        let snapshot = &registry.history.snapshot;
        if let Some(point) = snapshot
            .tail
            .iter()
            .find(|point| point.anchor.sequence == sequence)
        {
            if !live_point(point, registry, now_ms) {
                return Err(unavailable("recovery point is expired or unknown"));
            }
            let point = point.clone();
            let anchor = point.anchor.clone();
            registry.selected_point = Some(point);
            return Ok(anchor);
        }
        if let Some(reference) = snapshot.pages.iter().find(|reference| {
            reference.claims.first_sequence <= sequence
                && sequence <= reference.claims.last_sequence
        }) {
            let page = self
                .read_recovery_page(reference)
                .await
                .map_err(v3_repository_error)?;
            if let Some(point) = page.points.iter().find(|point| {
                point.anchor.sequence == sequence && live_point(point, registry, now_ms)
            }) {
                let point = point.clone();
                let anchor = point.anchor.clone();
                registry.selected_point = Some(point);
                return Ok(anchor);
            }
        }
        Err(unavailable("recovery point is expired or unknown"))
    }
}

impl<S: BlobStore> V3Repository<S> {
    /// Lists one bounded group from the live accepted registry. At most one
    /// exact history page is fetched, and backend LIST is never used.
    pub async fn recovery_points<A: V3CommitAnchor>(
        &self,
        anchor: &A,
        limit: usize,
        cursor: Option<&V3RecoveryCursor>,
    ) -> Result<V3RecoveryPointPage> {
        if !(1..=MAX_POINT_LIMIT).contains(&limit) {
            return Err(unavailable(
                "recovery point limit must be between 1 and 256",
            ));
        }
        let registry = self.commit_store.operator_registry(anchor).await?;
        let snapshot = &registry.history.snapshot;
        let binding = registry_binding(&registry.anchor)?;
        let (group, offset) = match cursor {
            Some(cursor)
                if cursor.sequence == registry.anchor.sequence.get()
                    && cursor.digest == binding =>
            {
                (cursor.group, cursor.offset)
            }
            Some(_) => return Err(unavailable("recovery cursor is stale; restart listing")),
            None => (0, 0),
        };
        if group > snapshot.pages.len() + 1 {
            return Err(unavailable("invalid recovery cursor"));
        }
        let now = operator_now_ms()?;
        let owned;
        let records: &[RecoveryPoint] = if group < snapshot.pages.len() {
            owned = self
                .commit_store
                .read_recovery_page(&snapshot.pages[group])
                .await
                .map_err(v3_repository_error)?;
            &owned.points
        } else if group == snapshot.pages.len() {
            &snapshot.tail
        } else {
            &[]
        };
        if offset > records.len() {
            return Err(unavailable("invalid recovery cursor"));
        }
        let mut points = Vec::new();
        let mut next_offset = offset;
        while next_offset < records.len() && points.len() < limit {
            let point = &records[next_offset];
            next_offset += 1;
            if live_point(point, &registry, now) {
                points.push(point_info(point));
            }
        }
        let next = if next_offset < records.len() {
            Some((group, next_offset))
        } else if group <= snapshot.pages.len() {
            Some((group + 1, 0))
        } else {
            points.push(V3RecoveryPointInfo {
                sequence: registry.anchor.sequence.get(),
                publish_time_ms: registry.published_at_ms,
                protected_until_ms: None,
                current: true,
            });
            None
        };
        if anchor.read_v3().await.map_err(v3_repository_error)? != Some(registry.anchor.clone()) {
            return Err(v3_repository_error(V3FormatError::StaleAnchor));
        }
        Ok(V3RecoveryPointPage {
            registry_sequence: registry.anchor.sequence.get(),
            points,
            next_cursor: next.map(|(group, offset)| V3RecoveryCursor {
                sequence: registry.anchor.sequence.get(),
                digest: binding,
                group,
                offset,
            }),
        })
    }
}

impl<S: BlobStore + Clone> V3Repository<S> {
    /// Opens one authenticated point as an isolated reader, without changing
    /// accepted state in this repository or writing any anchor.
    pub async fn open_recovery_point<A: V3CommitAnchor>(
        &self,
        anchor: &A,
        sequence: Sequence,
    ) -> Result<V3RecoveryView<S>> {
        let mut registry = self.commit_store.operator_registry(anchor).await?;
        let selected = self
            .commit_store
            .operator_point(&mut registry, sequence, operator_now_ms()?)
            .await?;
        let reader = V3Repository::new(
            self.commit_store.store().clone(),
            self.commit_store.keyring().clone(),
            self.repository.options,
            self.commit_store.options().clone(),
        );
        let chain = reader
            .commit_store
            .load_replay_chain_from_state(&selected)
            .await
            .map_err(v3_repository_error)?;
        let (repository, runs) = reader
            .replay_bounded_chain_to_state_and_runs(&chain)
            .await?;
        // Deliberately omit the selected root's recovery registry.
        *reader
            .accepted
            .write()
            .map_err(|_| RepositoryError::StatePoisoned)? = V3AcceptedState {
            recovery: None,
            repository,
            runs,
            anchor: Some(selected.clone()),
        };
        if anchor.read_v3().await.map_err(v3_repository_error)? != Some(registry.anchor.clone()) {
            return Err(v3_repository_error(V3FormatError::StaleAnchor));
        }
        reader
            .commit_store
            .operator_point(&mut registry, sequence, operator_now_ms()?)
            .await?;
        Ok(V3RecoveryView {
            reader,
            selected,
            authority: Mutex::new(registry),
        })
    }
}

impl<S: BlobStore + Clone> V3RecoveryView<S> {
    /// Exact root selected at construction, stable across live compaction.
    pub fn selected_anchor(&self) -> &V3AnchorState {
        &self.selected
    }

    /// Verifies current authority and the fixed deadline before admitting a
    /// request. Head changes replay history metadata only, not live namespace.
    pub async fn check_authority<A: V3CommitAnchor>(&self, anchor: &A) -> Result<()> {
        let mut registry = self.authority.lock().await;
        let live = anchor
            .read_v3()
            .await
            .map_err(v3_repository_error)?
            .ok_or_else(|| unavailable("recovery requires a current accepted anchor"))?;
        if live != registry.anchor {
            if live.sequence <= registry.anchor.sequence {
                return Err(v3_repository_error(V3FormatError::StaleAnchor));
            }
            *registry = self.reader.commit_store.operator_registry(anchor).await?;
        }
        let selected = self
            .reader
            .commit_store
            .operator_point(&mut registry, self.selected.sequence, operator_now_ms()?)
            .await?;
        if selected != self.selected
            || anchor.read_v3().await.map_err(v3_repository_error)? != Some(registry.anchor.clone())
        {
            return Err(v3_repository_error(V3FormatError::StaleAnchor));
        }
        Ok(())
    }

    /// Resolves trusted metadata in the selected namespace.
    pub fn resolve_object(&self, key: &LogicalPath) -> Result<V3ResolvedObject> {
        self.reader.resolve_object(key)
    }
    /// Reads trusted metadata in the selected namespace.
    pub fn head(&self, key: &LogicalPath) -> Result<RepositoryObjectMetadata> {
        self.reader.head(key)
    }
    /// Lists using the existing bounded namespace reader.
    pub fn list_page(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<RepositoryListEntry>> {
        self.reader.list_page(prefix, start_after, limit)
    }
    /// Reads a resolved object's range using the existing authenticated reader.
    pub async fn get_resolved_range(
        &self,
        resolved: &V3ResolvedObject,
        range: ByteRange,
    ) -> Result<Bytes> {
        self.reader.get_resolved_range(resolved, range).await
    }
    /// Opens the existing authenticated streaming reader.
    pub async fn get_resolved_full_stream(
        &self,
        resolved: &V3ResolvedObject,
    ) -> Result<Option<V3AuthenticatedReadBody>> {
        self.reader.get_resolved_full_stream(resolved).await
    }
}
