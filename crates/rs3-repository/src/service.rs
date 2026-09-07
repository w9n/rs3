//! Repository service implementation.

use crate::error::{RepositoryError, Result};
use crate::lru::LruCache;
use crate::payload::{
    DEFAULT_PAYLOAD_SEGMENT_SIZE, SegmentCiphertextSpan, SegmentPlaintextSelection,
    SegmentedPayloadLayout, open_segmented_payload_cached_segments,
    open_segmented_payload_span_with_segments, segmented_plaintext_segment_len,
    segmented_plaintext_selection,
};
use bytes::Bytes;
use rs3_crypto::KeyRing;
use rs3_storage::{ByteRange, StorageError, active_retention};
use rs3_types::{
    BackendObjectId, BackendObjectRef, BackendVersionId, LegalHoldStatus, RetentionPolicy,
};
use std::sync::{Arc, RwLock};

/// Default maximum plaintext bytes retained in the decrypted segment LRU cache.
pub const DEFAULT_DECRYPTED_SEGMENT_CACHE_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// Keyring, read cache and options shared by current repository operations.
pub(crate) struct RepositoryResources {
    pub(crate) keyring: RwLock<Arc<KeyRing>>,
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

impl RepositoryResources {
    /// Creates shared repository resources with an explicit keyring and options.
    pub(crate) fn new(keyring: KeyRing, options: RepositoryOptions) -> Self {
        Self {
            keyring: RwLock::new(Arc::new(keyring)),
            options,
            decrypted_segments: RwLock::new(DecryptedSegmentCache::with_max_bytes(
                options.decrypted_segment_cache_max_bytes,
            )),
        }
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
        header: &SegmentedPayloadLayout,
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
        header: &SegmentedPayloadLayout,
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
        header: &SegmentedPayloadLayout,
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

    /// Returns the active keyring.
    pub(crate) fn keyring(&self) -> Result<Arc<KeyRing>> {
        self.keyring
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)
            .map(|keyring| Arc::clone(&*keyring))
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

#[cfg(test)]
mod tests {
    use super::{
        DecryptedSegmentCache, DecryptedSegmentCacheInsert, DecryptedSegmentIdentity,
        RepositoryResources,
    };
    use crate::payload::{seal_payload_object, segmented_ciphertext_span};
    use crate::test_support::signing_keyring;
    use bytes::Bytes;
    use rs3_storage::ByteRange;
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
        let repository =
            RepositoryResources::new(keyring.clone(), super::RepositoryOptions::default());
        let payload_id = object_id("v2-payload/authenticated-payload");
        let cache_ref = BackendObjectRef::from(object_id("v2-stream-cache/exact-carrier"));
        let other_cache_ref = BackendObjectRef::from(object_id("v2-stream-cache/other-carrier"));
        let plaintext = b"payload crossing more than one encrypted segment";
        let (sealed, header) = seal_payload_object(
            &keyring,
            &payload_id,
            plaintext,
            16,
            b"fixture-context".to_vec(),
            [4; 32],
        )
        .expect("seal fixture");
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
