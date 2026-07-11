//! Repository service implementation.

use crate::checkpoint::seal_manifest_record;
use crate::error::{RepositoryError, Result};
use crate::lru::LruCache;
use crate::model::RepositoryObjectMetadata;
use crate::namespace::{first_namespace_entry, prefix_tokens_for_key};
use crate::payload::{
    DEFAULT_PAYLOAD_SEGMENT_SIZE, SegmentCiphertextSpan, SegmentPlaintextSelection,
    SegmentedPayloadHeader, open_segmented_payload_cached_segments,
    open_segmented_payload_span_with_segments, segmented_plaintext_segment_len,
    segmented_plaintext_selection,
};
use crate::state::{RepositoryState, TrustedManifest, next_sequence, object_material};
use bytes::Bytes;
use rs3_crypto::{KeyRing, NamespaceBlindKey};
use rs3_index::{IndexDelta, KeyringEnvelopeReference};
use rs3_storage::{BlobStore, ByteRange, StorageError};
use rs3_types::{
    BackendObjectId, BackendObjectRef, BackendVersionId, LegalHoldStatus, LogicalPath,
    RetentionMode, RetentionPolicy,
};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default maximum plaintext bytes retained in the decrypted segment LRU cache.
pub const DEFAULT_DECRYPTED_SEGMENT_CACHE_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// Trusted repository service.
pub struct Repository<S> {
    pub(crate) store: S,
    pub(crate) keyring: RwLock<Arc<KeyRing>>,
    pub(crate) keyring_envelope: RwLock<Option<KeyringEnvelopeReference>>,
    pub(crate) state: RwLock<RepositoryState>,
    pub(crate) options: RepositoryOptions,
    decrypted_segments: RwLock<DecryptedSegmentCache>,
}

pub(crate) struct DecryptedSegmentIdentity<'a> {
    pub(crate) cache_ref: &'a BackendObjectRef,
    pub(crate) payload_id: &'a BackendObjectId,
}

/// Repository runtime options.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepositoryOptions {
    /// Plaintext bytes per independently encrypted payload segment.
    pub payload_segment_size: usize,
    /// Adapt payload segment size upward for medium and large objects.
    pub adaptive_payload_segment_size: bool,
    /// Maximum plaintext bytes retained in the decrypted segment LRU cache.
    ///
    /// Set to zero to disable decrypted segment caching.
    pub decrypted_segment_cache_max_bytes: u64,
    /// Default provider retention policy for repository-owned objects.
    pub default_retention: Option<RetentionPolicy>,
}

impl Default for RepositoryOptions {
    fn default() -> Self {
        Self {
            payload_segment_size: DEFAULT_PAYLOAD_SEGMENT_SIZE,
            adaptive_payload_segment_size: true,
            decrypted_segment_cache_max_bytes: DEFAULT_DECRYPTED_SEGMENT_CACHE_MAX_BYTES,
            default_retention: None,
        }
    }
}

impl<S> Repository<S>
where
    S: BlobStore,
{
    /// Creates a trusted repository service with an explicit keyring.
    pub fn with_keyring(store: S, keyring: KeyRing) -> Self {
        Self::with_keyring_and_options(store, keyring, RepositoryOptions::default())
    }

    /// Creates a trusted repository service with an explicit keyring and options.
    pub fn with_keyring_and_options(
        store: S,
        keyring: KeyRing,
        options: RepositoryOptions,
    ) -> Self {
        Self {
            store,
            keyring: RwLock::new(Arc::new(keyring)),
            keyring_envelope: RwLock::new(None),
            state: RwLock::new(RepositoryState::default()),
            options,
            decrypted_segments: RwLock::new(DecryptedSegmentCache::with_max_bytes(
                options.decrypted_segment_cache_max_bytes,
            )),
        }
    }

    /// Replaces the active keyring after a validated data-key update.
    pub fn replace_keyring(&self, keyring: KeyRing) -> Result<()> {
        let mut active = self
            .keyring
            .write()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        *active = Arc::new(keyring);
        Ok(())
    }

    pub(crate) fn cached_decrypted_segment_span(
        &self,
        object_ref: &BackendObjectRef,
        start_segment: usize,
        segment_count: usize,
    ) -> Result<Option<Vec<Bytes>>> {
        let mut segments = Vec::with_capacity(segment_count);
        {
            let cache = self
                .decrypted_segments
                .read()
                .map_err(|_| RepositoryError::StatePoisoned)?;
            for relative_index in 0..segment_count {
                let segment_index = start_segment
                    .checked_add(relative_index)
                    .ok_or(StorageError::InvalidRange)?;
                let Some(segment) = cache.peek(object_ref, segment_index) else {
                    record_decrypted_segment_cache_many("miss", 1, 0);
                    return Ok(None);
                };
                segments.push(segment);
            }
        }
        if let Ok(mut cache) = self.decrypted_segments.try_write() {
            for relative_index in 0..segment_count {
                let segment_index = start_segment
                    .checked_add(relative_index)
                    .ok_or(StorageError::InvalidRange)?;
                cache.touch(object_ref, segment_index);
            }
        }
        let bytes = segments.iter().fold(0_u64, |total, segment| {
            total.saturating_add(u64::try_from(segment.len()).unwrap_or(u64::MAX))
        });
        record_decrypted_segment_cache_many(
            "hit",
            u64::try_from(segment_count).unwrap_or(u64::MAX),
            bytes,
        );
        Ok(Some(segments))
    }

    pub(crate) fn cache_decrypted_segment_span(
        &self,
        object_ref: &BackendObjectRef,
        segments: &[(usize, Bytes)],
    ) -> Result<()> {
        self.cache_decrypted_segments(object_ref, segments)
    }

    pub(crate) fn open_cached_decrypted_segments(
        &self,
        identity: DecryptedSegmentIdentity<'_>,
        header: &SegmentedPayloadHeader,
        range: ByteRange,
    ) -> Result<Option<Bytes>> {
        let selection = segmented_plaintext_selection(header, range)?;
        match self.cached_decrypted_segments(identity.cache_ref, header, selection)? {
            DecryptedSegmentLookup::Hit { segments, bytes } => {
                record_decrypted_segment_cache_many(
                    "hit",
                    u64::try_from(segments.len()).unwrap_or(u64::MAX),
                    bytes,
                );
                Ok(Some(open_segmented_payload_cached_segments(
                    identity.payload_id,
                    header,
                    range,
                    selection.start_segment,
                    &segments,
                )?))
            }
            DecryptedSegmentLookup::Miss {
                missing_segments,
                missing_bytes,
            } => {
                record_decrypted_segment_cache_many("miss", missing_segments, missing_bytes);
                Ok(None)
            }
        }
    }

    pub(crate) fn open_and_cache_decrypted_segments(
        &self,
        keyring: &KeyRing,
        identity: DecryptedSegmentIdentity<'_>,
        header: &SegmentedPayloadHeader,
        range: ByteRange,
        span: SegmentCiphertextSpan,
        ciphertext: Bytes,
    ) -> Result<Bytes> {
        let opened = open_segmented_payload_span_with_segments(
            keyring,
            identity.payload_id,
            header,
            range,
            span,
            ciphertext,
        )?;
        self.cache_decrypted_segments(identity.cache_ref, &opened.segments)?;
        Ok(opened.plaintext)
    }

    fn cached_decrypted_segments(
        &self,
        object_ref: &BackendObjectRef,
        header: &SegmentedPayloadHeader,
        selection: SegmentPlaintextSelection,
    ) -> Result<DecryptedSegmentLookup> {
        if selection.segment_count == 0 {
            return Ok(DecryptedSegmentLookup::Hit {
                segments: Vec::new(),
                bytes: 0,
            });
        }

        let mut segments = Vec::with_capacity(selection.segment_count);
        let mut bytes = 0_u64;
        let mut missing_segments = 0_u64;
        let mut missing_bytes = 0_u64;

        {
            let cache = self
                .decrypted_segments
                .read()
                .map_err(|_| RepositoryError::StatePoisoned)?;
            for relative_index in 0..selection.segment_count {
                let Some(segment_index) = selection.start_segment.checked_add(relative_index)
                else {
                    return Err(StorageError::InvalidRange.into());
                };
                match cache.peek(object_ref, segment_index) {
                    Some(segment) => {
                        bytes =
                            bytes.saturating_add(u64::try_from(segment.len()).unwrap_or(u64::MAX));
                        segments.push(segment);
                    }
                    None => {
                        missing_segments = missing_segments.saturating_add(1);
                        missing_bytes = missing_bytes.saturating_add(
                            segmented_plaintext_segment_len(header, segment_index)?,
                        );
                    }
                }
            }
        }

        if missing_segments == 0 {
            if let Ok(mut cache) = self.decrypted_segments.try_write() {
                for relative_index in 0..selection.segment_count {
                    let Some(segment_index) = selection.start_segment.checked_add(relative_index)
                    else {
                        return Err(StorageError::InvalidRange.into());
                    };
                    cache.touch(object_ref, segment_index);
                }
            }
            Ok(DecryptedSegmentLookup::Hit { segments, bytes })
        } else {
            Ok(DecryptedSegmentLookup::Miss {
                missing_segments,
                missing_bytes,
            })
        }
    }

    fn cache_decrypted_segments(
        &self,
        object_ref: &BackendObjectRef,
        segments: &[(usize, Bytes)],
    ) -> Result<()> {
        let mut cache = self
            .decrypted_segments
            .write()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        for (segment_index, plaintext) in segments {
            let outcome = cache.insert(object_ref.clone(), *segment_index, plaintext.clone());
            match outcome {
                DecryptedSegmentCacheInsert::Inserted {
                    bytes,
                    evicted_entries,
                    evicted_bytes,
                } => {
                    record_decrypted_segment_cache("insert", bytes);
                    record_decrypted_segment_cache_many("evict", evicted_entries, evicted_bytes);
                }
                DecryptedSegmentCacheInsert::SkippedTooLarge { bytes } => {
                    record_decrypted_segment_cache("skip_too_large", bytes);
                }
            }
        }
        Ok(())
    }

    /// Applies legal hold for a client-visible object and its backend payload.
    pub async fn set_legal_hold(
        &self,
        key: &LogicalPath,
        status: LegalHoldStatus,
    ) -> Result<RepositoryObjectMetadata> {
        let keyring = self.keyring()?;
        let lookup_blind_keys = keyring.derive_blind_index_keys_for_lookup(key)?;
        let object_ref = self.object_ref_for_candidates(key, &lookup_blind_keys)?;
        self.store
            .set_legal_hold_at(
                &object_ref.object_id,
                object_ref.version_id.as_ref(),
                status,
            )
            .await?;
        let backend = self
            .store
            .head_at(&object_ref.object_id, object_ref.version_id.as_ref())
            .await?;

        let mut state = self.write_state()?;
        let entry = first_namespace_entry(&state.namespace, &lookup_blind_keys)
            .ok_or_else(|| RepositoryError::NotFound(key.clone()))?
            .clone();
        let content_len = state
            .manifests
            .get(&entry.manifest_id)
            .map(|manifest| manifest.content_len)
            .unwrap_or(entry.content_len);
        let retention = state
            .manifests
            .get(&entry.manifest_id)
            .map(|manifest| manifest.retention)
            .unwrap_or(entry.retention);
        let sequence = next_sequence(&mut state)?;
        let material = object_material(key.as_str(), sequence);
        let manifest_id = keyring.derive_manifest_id(&material)?;
        let mut updated = entry;
        updated.manifest_id = manifest_id.clone();
        updated.generation = sequence;
        updated.retention = retention;
        updated.legal_hold = backend.legal_hold.or(Some(status));
        updated.object_version_id = backend.version_id.or(updated.object_version_id);
        let prefix_tokens =
            prefix_tokens_for_key(&keyring, &updated.namespace_key_id, key.as_str())?;
        let manifest = TrustedManifest {
            key: key.clone(),
            content_len,
            modified_at_ms: modified_at_ms_or_now(backend.modified_at_ms, sequence),
            retention,
            legal_hold: updated.legal_hold,
        };
        let sealed_manifest = seal_manifest_record(&keyring, &manifest_id, &manifest)?;
        state.pending_index_deltas.push(IndexDelta::Upsert {
            entry: Box::new(updated.clone()),
            prefix_tokens: prefix_tokens.clone(),
            sealed_manifest: Box::new(sealed_manifest),
        });
        state.manifests.insert(manifest_id, manifest.clone());
        state.upsert_namespace_entry(updated.clone(), prefix_tokens);

        Ok(manifest.into_metadata())
    }

    fn object_ref_for_candidates(
        &self,
        key: &LogicalPath,
        lookup_blind_keys: &[NamespaceBlindKey],
    ) -> Result<BackendObjectRef> {
        let state = self.read_state()?;
        first_namespace_entry(&state.namespace, lookup_blind_keys)
            .map(|entry| BackendObjectRef {
                object_id: entry.object_id.clone(),
                version_id: entry.object_version_id.clone(),
            })
            .ok_or_else(|| RepositoryError::NotFound(key.clone()))
    }

    /// Returns the active keyring.
    pub(crate) fn keyring(&self) -> Result<Arc<KeyRing>> {
        self.keyring
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)
            .map(|keyring| Arc::clone(&*keyring))
    }

    /// Replaces the keyring envelope reference recorded in future checkpoints.
    ///
    /// Runtime constructors use this after opening an externally stored
    /// encrypted keyring envelope so checkpoint records bind the active
    /// wrapping-key source without requiring production server code to create
    /// key material.
    pub fn set_keyring_envelope_reference(
        &self,
        reference: Option<KeyringEnvelopeReference>,
    ) -> Result<()> {
        let mut active = self
            .keyring_envelope
            .write()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        *active = reference;
        Ok(())
    }

    /// Reads repository state.
    pub(crate) fn read_state(&self) -> Result<RwLockReadGuard<'_, RepositoryState>> {
        self.state
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)
    }

    /// Writes repository state.
    pub(crate) fn write_state(&self) -> Result<RwLockWriteGuard<'_, RepositoryState>> {
        self.state
            .write()
            .map_err(|_| RepositoryError::StatePoisoned)
    }
}

enum DecryptedSegmentLookup {
    Hit {
        segments: Vec<Bytes>,
        bytes: u64,
    },
    Miss {
        missing_segments: u64,
        missing_bytes: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct PayloadCacheObjectKey {
    object_id: BackendObjectId,
    version_id: Option<BackendVersionId>,
}

impl From<&BackendObjectRef> for PayloadCacheObjectKey {
    fn from(object_ref: &BackendObjectRef) -> Self {
        Self {
            object_id: object_ref.object_id.clone(),
            version_id: object_ref.version_id.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct DecryptedSegmentCacheKey {
    object: PayloadCacheObjectKey,
    segment_index: usize,
}

impl DecryptedSegmentCacheKey {
    fn new(object_ref: &BackendObjectRef, segment_index: usize) -> Self {
        Self {
            object: PayloadCacheObjectKey::from(object_ref),
            segment_index,
        }
    }
}

#[derive(Debug)]
struct DecryptedSegmentCache {
    segments: LruCache<DecryptedSegmentCacheKey, Bytes>,
    max_entries: usize,
    max_bytes: u64,
    current_bytes: u64,
}

impl Default for DecryptedSegmentCache {
    fn default() -> Self {
        Self::with_max_bytes(DEFAULT_DECRYPTED_SEGMENT_CACHE_MAX_BYTES)
    }
}

impl DecryptedSegmentCache {
    fn with_max_bytes(max_bytes: u64) -> Self {
        Self {
            segments: LruCache::new(),
            max_entries: 65_536,
            max_bytes,
            current_bytes: 0,
        }
    }

    fn peek(&self, object_ref: &BackendObjectRef, segment_index: usize) -> Option<Bytes> {
        let key = DecryptedSegmentCacheKey::new(object_ref, segment_index);
        self.segments.peek_cloned(&key)
    }

    fn touch(&mut self, object_ref: &BackendObjectRef, segment_index: usize) {
        let key = DecryptedSegmentCacheKey::new(object_ref, segment_index);
        self.segments.touch(&key);
    }

    fn insert(
        &mut self,
        object_ref: BackendObjectRef,
        segment_index: usize,
        plaintext: Bytes,
    ) -> DecryptedSegmentCacheInsert {
        let bytes = u64::try_from(plaintext.len()).unwrap_or(u64::MAX);
        if bytes > self.max_bytes {
            return DecryptedSegmentCacheInsert::SkippedTooLarge { bytes };
        }

        let key = DecryptedSegmentCacheKey::new(&object_ref, segment_index);
        match self.segments.insert(key, plaintext) {
            Some(previous) => {
                let previous = u64::try_from(previous.len()).unwrap_or(u64::MAX);
                self.current_bytes = self.current_bytes.saturating_sub(previous);
                self.current_bytes = self.current_bytes.saturating_add(bytes);
            }
            None => {
                self.current_bytes = self.current_bytes.saturating_add(bytes);
            }
        }
        let evicted = self.evict_over_limits();
        DecryptedSegmentCacheInsert::Inserted {
            bytes,
            evicted_entries: evicted.entries,
            evicted_bytes: evicted.bytes,
        }
    }

    fn evict_over_limits(&mut self) -> DecryptedSegmentCacheEviction {
        let mut evicted = DecryptedSegmentCacheEviction::default();
        while self.segments.len() > self.max_entries || self.current_bytes > self.max_bytes {
            let Some((_evicted_key, plaintext)) = self.segments.pop_lru() else {
                break;
            };
            let bytes = u64::try_from(plaintext.len()).unwrap_or(u64::MAX);
            self.current_bytes = self.current_bytes.saturating_sub(bytes);
            evicted.entries = evicted.entries.saturating_add(1);
            evicted.bytes = evicted.bytes.saturating_add(bytes);
        }
        evicted
    }
}

enum DecryptedSegmentCacheInsert {
    Inserted {
        bytes: u64,
        evicted_entries: u64,
        evicted_bytes: u64,
    },
    SkippedTooLarge {
        bytes: u64,
    },
}

#[derive(Default)]
struct DecryptedSegmentCacheEviction {
    entries: u64,
    bytes: u64,
}

fn record_decrypted_segment_cache(result: &'static str, bytes: u64) {
    record_decrypted_segment_cache_many(result, 1, bytes);
}

fn record_decrypted_segment_cache_many(result: &'static str, events: u64, bytes: u64) {
    if events == 0 && bytes == 0 {
        return;
    }
    metrics::counter!(
        "rs3_repository_decrypted_segment_cache_events_total",
        "result" => result,
    )
    .increment(events);
    metrics::counter!(
        "rs3_repository_decrypted_segment_cache_bytes_total",
        "result" => result,
    )
    .increment(bytes);
}

fn modified_at_ms_or_now(modified_at_ms: Option<i64>, sequence: rs3_types::Sequence) -> i64 {
    modified_at_ms.unwrap_or_else(|| current_time_ms().unwrap_or(sequence.get() as i64))
}

pub(crate) fn strongest_retention_policy(
    left: Option<RetentionPolicy>,
    right: Option<RetentionPolicy>,
) -> Option<RetentionPolicy> {
    match (active_retention(left), active_retention(right)) {
        (Some(left), Some(right)) => Some(RetentionPolicy::new(
            stronger_retention_mode(left.mode, right.mode),
            left.retain_days.max(right.retain_days),
        )),
        (Some(policy), None) | (None, Some(policy)) => Some(policy),
        (None, None) => None,
    }
}

pub(crate) fn require_version_for_retained_write(
    object_id: &BackendObjectId,
    metadata: &rs3_storage::BlobMetadata,
    retention: Option<RetentionPolicy>,
    legal_hold: Option<LegalHoldStatus>,
) -> Result<Option<BackendVersionId>> {
    if version_binding_required(retention, legal_hold) && metadata.version_id.is_none() {
        return Err(StorageError::MissingVersionId(object_id.clone()).into());
    }
    Ok(metadata.version_id.clone())
}

pub(crate) fn version_binding_required(
    retention: Option<RetentionPolicy>,
    legal_hold: Option<LegalHoldStatus>,
) -> bool {
    active_retention(retention).is_some() || legal_hold == Some(LegalHoldStatus::On)
}

fn active_retention(policy: Option<RetentionPolicy>) -> Option<RetentionPolicy> {
    policy.filter(|policy| policy.mode != RetentionMode::None && policy.retain_days > 0)
}

fn stronger_retention_mode(left: RetentionMode, right: RetentionMode) -> RetentionMode {
    match (left, right) {
        (RetentionMode::Compliance, _) | (_, RetentionMode::Compliance) => {
            RetentionMode::Compliance
        }
        (RetentionMode::Governance, _) | (_, RetentionMode::Governance) => {
            RetentionMode::Governance
        }
        (RetentionMode::None, RetentionMode::None) => RetentionMode::None,
    }
}

fn current_time_ms() -> Option<i64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis();
    i64::try_from(millis).ok()
}

#[cfg(test)]
mod tests {
    use super::{
        DecryptedSegmentCache, DecryptedSegmentCacheInsert, DecryptedSegmentIdentity, Repository,
    };
    use crate::payload::{
        parse_segmented_payload_header, seal_streamable_payload_object, segmented_ciphertext_span,
    };
    use crate::test_support::signing_keyring;
    use bytes::Bytes;
    use rs3_storage::{ByteRange, MemoryBlobStore};
    use rs3_types::{BackendObjectId, BackendObjectRef};

    fn object_id(value: &str) -> BackendObjectId {
        match BackendObjectId::new(value.to_owned()) {
            Ok(object_id) => object_id,
            Err(error) => panic!("{error}"),
        }
    }

    fn decrypted_cache(max_entries: usize, max_bytes: u64) -> DecryptedSegmentCache {
        let mut cache = DecryptedSegmentCache::with_max_bytes(max_bytes);
        cache.max_entries = max_entries;
        cache
    }

    fn decrypted_inserted(outcome: DecryptedSegmentCacheInsert) -> (u64, u64, u64) {
        match outcome {
            DecryptedSegmentCacheInsert::Inserted {
                bytes,
                evicted_entries,
                evicted_bytes,
            } => (bytes, evicted_entries, evicted_bytes),
            DecryptedSegmentCacheInsert::SkippedTooLarge { bytes } => {
                panic!("decrypted segment insert skipped unexpectedly with {bytes} bytes")
            }
        }
    }

    #[test]
    fn decrypted_segment_cache_is_lru_and_version_aware() {
        let mut cache = decrypted_cache(2, 1024);
        let object = BackendObjectRef::from(object_id("payload-a"));
        let other_version = BackendObjectRef {
            object_id: object.object_id.clone(),
            version_id: Some(
                rs3_types::BackendVersionId::new("version-2")
                    .unwrap_or_else(|error| panic!("{error}")),
            ),
        };

        assert_eq!(
            decrypted_inserted(cache.insert(object.clone(), 0, Bytes::from_static(b"aaaa"))),
            (4, 0, 0)
        );
        assert_eq!(
            decrypted_inserted(cache.insert(object.clone(), 1, Bytes::from_static(b"bbbb"))),
            (4, 0, 0)
        );
        assert_eq!(cache.peek(&object, 0), Some(Bytes::from_static(b"aaaa")));
        cache.touch(&object, 0);
        assert_eq!(
            decrypted_inserted(cache.insert(object.clone(), 2, Bytes::from_static(b"cccc"))),
            (4, 1, 4)
        );

        assert_eq!(cache.peek(&object, 0), Some(Bytes::from_static(b"aaaa")));
        assert!(cache.peek(&object, 1).is_none());
        assert_eq!(cache.peek(&object, 2), Some(Bytes::from_static(b"cccc")));
        assert!(cache.peek(&other_version, 0).is_none());
        assert_eq!(cache.current_bytes, 8);
    }

    #[test]
    fn decrypted_segment_cache_can_be_disabled() {
        let mut cache = DecryptedSegmentCache::with_max_bytes(0);
        let object = BackendObjectRef::from(object_id("payload-disabled"));

        match cache.insert(object.clone(), 0, Bytes::from_static(b"aaaa")) {
            DecryptedSegmentCacheInsert::SkippedTooLarge { bytes } => assert_eq!(bytes, 4),
            DecryptedSegmentCacheInsert::Inserted { .. } => {
                panic!("disabled decrypted segment cache inserted plaintext")
            }
        }
        assert!(cache.peek(&object, 0).is_none());
        assert_eq!(cache.current_bytes, 0);
    }

    #[test]
    fn decrypted_segment_cache_identity_is_separate_from_payload_auth_identity() {
        let keyring = signing_keyring();
        let repository = Repository::with_keyring(MemoryBlobStore::new(), keyring.clone());
        let payload_id = object_id("v2-payload/authenticated-payload");
        let cache_ref = BackendObjectRef::from(object_id("v2-stream-cache/exact-carrier"));
        let other_cache_ref = BackendObjectRef::from(object_id("v2-stream-cache/other-carrier"));
        let plaintext = b"payload crossing more than one encrypted segment";
        let sealed = seal_streamable_payload_object(&keyring, &payload_id, plaintext, 16)
            .unwrap_or_else(|error| panic!("{error}"));
        let header = parse_segmented_payload_header(&payload_id, &sealed)
            .unwrap_or_else(|error| panic!("{error}"));
        let range = ByteRange::Slice { offset: 7, len: 29 };
        let span =
            segmented_ciphertext_span(&header, range).unwrap_or_else(|error| panic!("{error}"));
        let start = usize::try_from(span.offset).unwrap_or_else(|error| panic!("{error}"));
        let end = usize::try_from(span.offset + span.len).unwrap_or_else(|error| panic!("{error}"));

        let opened = repository
            .open_and_cache_decrypted_segments(
                &keyring,
                DecryptedSegmentIdentity {
                    cache_ref: &cache_ref,
                    payload_id: &payload_id,
                },
                &header,
                range,
                span,
                sealed.slice(start..end),
            )
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(opened, Bytes::copy_from_slice(&plaintext[7..36]));
        assert_eq!(
            repository
                .open_cached_decrypted_segments(
                    DecryptedSegmentIdentity {
                        cache_ref: &cache_ref,
                        payload_id: &payload_id,
                    },
                    &header,
                    range,
                )
                .unwrap_or_else(|error| panic!("{error}")),
            Some(opened)
        );
        assert!(
            repository
                .open_cached_decrypted_segments(
                    DecryptedSegmentIdentity {
                        cache_ref: &other_cache_ref,
                        payload_id: &payload_id,
                    },
                    &header,
                    range,
                )
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none()
        );
    }
}
