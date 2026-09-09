//! Append-friendly namespace and authenticated index-run model.

pub mod completion;

pub mod run;

use rs3_types::{
    BackendObjectId, BackendVersionId, BlindIndexKey, KeyId, LegalHoldStatus, LogicalPath,
    ManifestId, ObjectEtag, PrefixToken, RetentionPolicy, Sequence,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

/// Domain separator prepended to plaintext manifest payloads before sealing.
pub const MANIFEST_PLAINTEXT_DOMAIN: &[u8] = b"rs3:manifest-plaintext:v1\n";

/// Pointer to encrypted object payload stored in the backend.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ObjectPointer {
    /// Blind index key for lookup inside the trusted boundary.
    pub blind_key: BlindIndexKey,
    /// Opaque backend object identifier.
    pub object_id: BackendObjectId,
    /// Provider version identifier for exact restore reads, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_version_id: Option<BackendVersionId>,
    /// Sealed metadata record that describes the logical object.
    pub manifest_id: ManifestId,
    /// Logical generation assigned by the repository.
    pub generation: Sequence,
    /// Ciphertext length in bytes.
    pub ciphertext_len: u64,
}

/// Payload location recorded inside encrypted namespace index state.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PayloadReference {
    /// Compact payload-pack record in the current commit carrying this index run.
    #[serde(rename = "V2PackSelf")]
    V3PackSelf {
        /// Commit section ordinal containing the payload pack.
        pack_section_ordinal: u32,
        /// Random pack identity bound into every record AEAD operation.
        pack_id: [u8; 32],
        /// Fresh encryption attempt for this immutable pack.
        attempt_id: rs3_types::PayloadAttemptId,
        /// Historical content-encryption key needed to open the record.
        content_key_id: KeyId,
        /// Current commit's encrypted-keyring envelope object bound into payload AEAD context.
        keyring_envelope_object_id: BackendObjectId,
        /// SHA-256 digest of that encrypted-keyring envelope.
        keyring_envelope_digest: [u8; 32],
        /// Authenticated number of logical records in the pack directory.
        pack_record_count: u32,
        /// Logical record ordinal in the pack directory.
        record_ordinal: u32,
        /// Absolute ciphertext offset from the start of the payload-pack section.
        record_offset: u32,
    },
    /// Compact payload-pack record in an accepted exact commit object.
    #[serde(rename = "V2Pack")]
    V3Pack {
        /// Exact carrier facts shared by every record in the same payload pack.
        #[serde(flatten)]
        carrier: Arc<V3PackCarrierReference>,
        /// Record-specific facts inside the shared payload pack.
        #[serde(flatten)]
        record: V3PackRecordReference,
    },
    /// Staged value awaiting an authenticated carrier reference; never persisted.
    Pending,
    /// Streamed payload bytes stored in one exact standalone object.
    #[serde(rename = "V2StandaloneStream")]
    V3StandaloneStream {
        /// Exact carrier facts shared by every reference to this streamed payload.
        #[serde(flatten)]
        carrier: Arc<V3StandaloneStreamCarrierReference>,
    },
}

/// Exact accepted commit and section facts shared by records in one payload pack.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct V3PackCarrierReference {
    /// Commit object key containing the payload-pack section.
    pub commit_key: BackendObjectId,
    /// Provider version identifier for exact-version reads, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_version_id: Option<BackendVersionId>,
    /// Commit body digest from the signed header.
    pub body_digest: [u8; 32],
    /// Provider-reported complete commit-object length.
    pub commit_stored_len: u64,
    /// Commit section ordinal containing the payload pack.
    pub pack_section_ordinal: u32,
    /// Absolute byte offset of the payload-pack section in the commit object.
    pub pack_offset: u64,
    /// Encrypted payload-pack section byte length.
    pub length: u64,
    /// Random pack identity bound into every record AEAD operation.
    pub pack_id: [u8; 32],
    /// Fresh sealing attempt shared by this immutable pack.
    pub attempt_id: rs3_types::PayloadAttemptId,
    /// Historical content-encryption key needed to open the record.
    pub content_key_id: KeyId,
    /// Historical encrypted-keyring envelope object bound into payload AEAD context.
    pub keyring_envelope_object_id: BackendObjectId,
    /// SHA-256 digest of that encrypted-keyring envelope.
    pub keyring_envelope_digest: [u8; 32],
    /// Authenticated number of logical records in the pack directory.
    pub pack_record_count: u32,
}

/// Record-specific authenticated facts inside an accepted payload pack.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct V3PackRecordReference {
    /// Logical record ordinal in the pack directory.
    pub record_ordinal: u32,
    /// Absolute ciphertext offset from the start of the payload-pack section.
    pub record_offset: u32,
}

/// Exact accepted standalone object facts for a streamed payload.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct V3StandaloneStreamCarrierReference {
    /// Standalone backend object containing the encrypted payload.
    pub object_id: BackendObjectId,
    /// Provider version identifier for exact-version reads, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<BackendVersionId>,
    /// Digest of the complete standalone ciphertext object.
    pub object_digest: [u8; 32],
    /// Provider-reported complete object length.
    pub stored_len: u64,
    /// Historical encrypted-keyring envelope object bound into payload AEAD context.
    pub keyring_envelope_object_id: BackendObjectId,
    /// SHA-256 digest of that encrypted-keyring envelope.
    pub keyring_envelope_digest: [u8; 32],
    /// Authenticated selected-part layout needed for direct range reads.
    pub payload_layout: PayloadLayout,
}

/// Maximum independently sealed parts in a detached payload.
pub const MAX_PAYLOAD_PARTS: usize = 10_000;

/// One selected independently sealed part, in original part-number order.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PayloadPart {
    /// Original positive client part number, at most 10,000.
    pub part_number: u32,
    /// Fresh identity for this exact sealing attempt.
    pub attempt_id: rs3_types::PayloadAttemptId,
    /// Positive plaintext length of this selected part.
    pub plaintext_len: u64,
}

/// Authenticated encrypted layout of a ciphertext-only detached payload.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PayloadLayout {
    /// Plaintext bytes per segment, except the final segment of each part.
    pub chunk_size: u64,
    /// Sum of all selected part lengths.
    pub plaintext_len: u64,
    /// Historical content-encryption key identifier.
    pub key_id: KeyId,
    /// Random immutable carrier identity.
    pub carrier_id: [u8; 32],
    /// Ordered selected parts. Zero-length values have no backend carrier.
    pub parts: Vec<PayloadPart>,
}

impl PayloadLayout {
    /// Validates bounds, part order and lengths, returning exact ciphertext bytes.
    /// Invalid layouts and arithmetic overflow return `None`.
    #[must_use]
    pub fn stored_len(&self) -> Option<u64> {
        if self.chunk_size == 0
            || self.chunk_size > 64 * 1024 * 1024
            || self.plaintext_len == 0
            || self.parts.is_empty()
            || self.parts.len() > MAX_PAYLOAD_PARTS
            || self.key_id.as_str().is_empty()
            || self.key_id.as_str().len() > 255
        {
            return None;
        }
        let mut previous = 0;
        let mut plaintext = 0_u64;
        let mut stored = 0_u64;
        for part in &self.parts {
            if part.part_number <= previous
                || part.part_number > MAX_PAYLOAD_PARTS as u32
                || part.plaintext_len == 0
            {
                return None;
            }
            previous = part.part_number;
            plaintext = plaintext.checked_add(part.plaintext_len)?;
            let tags = part
                .plaintext_len
                .div_ceil(self.chunk_size)
                .checked_mul(rs3_types::PAYLOAD_AEAD_TAG_LEN as u64)?;
            stored = stored.checked_add(part.plaintext_len.checked_add(tags)?)?;
        }
        (plaintext == self.plaintext_len).then_some(stored)
    }
}

/// A single index mutation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndexDelta {
    /// Insert or replace a namespace entry for a blind key.
    Upsert {
        /// Namespace entry made visible by the update.
        entry: Box<NamespaceEntry>,
        /// Prefix tokens associated with the entry.
        prefix_tokens: Vec<PrefixToken>,
        /// Sealed client-visible metadata needed to replay this entry.
        sealed_manifest: Box<ManifestObject>,
    },
    /// Mark a blind key as deleted at a repository generation.
    Tombstone {
        /// Namespace key that produced the blind key.
        namespace_key_id: KeyId,
        /// Blind key being tombstoned.
        blind_key: BlindIndexKey,
        /// Client-visible path needed to build the encrypted listing projection.
        path: LogicalPath,
        /// Generation at which the tombstone was written.
        generation: Sequence,
    },
}

impl fmt::Debug for IndexDelta {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Upsert {
                entry,
                prefix_tokens,
                sealed_manifest,
            } => formatter
                .debug_struct("Upsert")
                .field("entry", entry)
                .field("prefix_tokens", prefix_tokens)
                .field("sealed_manifest", sealed_manifest)
                .finish(),
            Self::Tombstone {
                namespace_key_id,
                blind_key,
                path: _,
                generation,
            } => formatter
                .debug_struct("Tombstone")
                .field("namespace_key_id", namespace_key_id)
                .field("blind_key", blind_key)
                .field("path", &"<redacted>")
                .field("generation", generation)
                .finish(),
        }
    }
}

/// Client-visible metadata stored in a sealed manifest object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableManifest {
    /// Client-visible key inside the trusted boundary.
    pub key: rs3_types::LogicalPath,
    /// Client-visible content length.
    pub content_len: u64,
    /// Last modification timestamp in milliseconds since the Unix epoch.
    pub modified_at_ms: i64,
    /// Effective retention policy, if known.
    pub retention: Option<RetentionPolicy>,
    /// Effective legal-hold status, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_hold: Option<LegalHoldStatus>,
    /// Trusted plaintext MD5 ETag for this object.
    pub etag: ObjectEtag,
    /// Client-declared checksum accepted for the complete object, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<rs3_types::ObjectChecksum>,
}

/// Sealed client-visible metadata embedded in an index delta.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestObject {
    /// Metadata key that sealed the payload.
    pub key_id: KeyId,
    /// Nonce used for the sealed payload.
    pub nonce: Vec<u8>,
    /// Sealed manifest payload.
    pub ciphertext: Vec<u8>,
    /// Authentication tag over the manifest object context.
    pub tag: Vec<u8>,
}

/// Exact reference to an encrypted keyring envelope used by the repository.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyringEnvelopeReference {
    /// Envelope generation assigned by the operator workflow.
    pub generation: u64,
    /// Digest of the encrypted envelope object.
    pub digest: String,
    /// Backend object that stores the encrypted envelope.
    pub object_id: BackendObjectId,
    /// Provider version identifier for the encrypted envelope, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<BackendVersionId>,
}

/// Encodes manifest plaintext before sealing.
pub fn manifest_plaintext_bytes(manifest: &DurableManifest) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = MANIFEST_PLAINTEXT_DOMAIN.to_vec();
    serde_json::to_writer(&mut bytes, manifest)?;
    Ok(bytes)
}

/// Metadata needed to answer trusted namespace lookups.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceEntry {
    /// Namespace key that produced the blind key and prefix tokens.
    pub namespace_key_id: KeyId,
    /// Blind key for the client-visible object.
    pub blind_key: BlindIndexKey,
    /// Opaque backend object identifier for the primary payload or segment root.
    pub object_id: BackendObjectId,
    /// Provider version identifier for exact restore reads, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_version_id: Option<BackendVersionId>,
    /// Commit-backed payload location for v3 repositories.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_ref: Option<PayloadReference>,
    /// Sealed metadata record containing client-visible metadata.
    pub manifest_id: ManifestId,
    /// Client-visible ciphertext-backed length in bytes.
    pub content_len: u64,
    /// Last modification timestamp in milliseconds since the Unix epoch.
    pub modified_at_ms: i64,
    /// Repository generation that made this entry visible.
    pub generation: Sequence,
    /// Effective retention policy, if known.
    pub retention: Option<RetentionPolicy>,
    /// Effective legal-hold status, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_hold: Option<LegalHoldStatus>,
}

/// In-memory trusted namespace index.
///
/// This is not the durable encrypted index format. It is the query model used
/// by local repository code and tests. It intentionally stores blind keys and
/// prefix tokens, not plaintext client keys.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NamespaceIndex {
    entries: BTreeMap<BlindIndexKey, NamespaceEntry>,
    entry_prefixes: BTreeMap<BlindIndexKey, BTreeSet<PrefixToken>>,
    prefixes: BTreeMap<PrefixToken, BTreeSet<BlindIndexKey>>,
}

/// Opaque snapshot of one namespace-index key for transactional rollback.
///
/// Capturing this value is proportional to the prefix membership of one
/// entry, rather than the size of the complete namespace.
#[derive(Debug)]
pub struct NamespaceIndexKeySnapshot {
    blind_key: BlindIndexKey,
    entry: Option<NamespaceEntry>,
    prefix_tokens: Vec<PrefixToken>,
}

impl NamespaceIndex {
    /// Creates an empty namespace index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts or replaces an entry and associates it with prefix tokens.
    pub fn upsert(&mut self, entry: NamespaceEntry, prefix_tokens: Vec<PrefixToken>) {
        self.remove_prefix_membership(&entry.blind_key);

        let prefix_set = prefix_tokens.into_iter().collect::<BTreeSet<_>>();
        for prefix_token in &prefix_set {
            self.prefixes
                .entry(prefix_token.clone())
                .or_default()
                .insert(entry.blind_key.clone());
        }

        if !prefix_set.is_empty() {
            self.entry_prefixes
                .insert(entry.blind_key.clone(), prefix_set);
        }
        self.entries.insert(entry.blind_key.clone(), entry);
    }

    /// Inserts or replaces an entry without building the legacy prefix-token
    /// projection.
    ///
    /// Callers that maintain a separate plaintext listing projection inside
    /// their trusted boundary do not need the forward and reverse prefix maps.
    pub fn upsert_without_prefixes(&mut self, entry: NamespaceEntry) {
        self.upsert(entry, Vec::new());
    }

    /// Looks up an entry by blind key.
    pub fn head(&self, blind_key: &BlindIndexKey) -> Option<&NamespaceEntry> {
        self.entries.get(blind_key)
    }

    /// Iterates live namespace entries in stable blind-key order without cloning.
    pub fn live_entries(&self) -> impl Iterator<Item = &NamespaceEntry> {
        self.entries.values()
    }

    /// Iterates one live entry's prefix tokens in stable order without cloning.
    pub fn prefix_tokens(&self, blind_key: &BlindIndexKey) -> impl Iterator<Item = &PrefixToken> {
        self.entry_prefixes.get(blind_key).into_iter().flatten()
    }

    /// Captures one key's live entry and prefix membership.
    pub fn snapshot_key(&self, blind_key: &BlindIndexKey) -> NamespaceIndexKeySnapshot {
        NamespaceIndexKeySnapshot {
            blind_key: blind_key.clone(),
            entry: self.entries.get(blind_key).cloned(),
            prefix_tokens: self
                .entry_prefixes
                .get(blind_key)
                .map(|tokens| tokens.iter().cloned().collect())
                .unwrap_or_default(),
        }
    }

    /// Restores a key from a snapshot captured before a staged mutation.
    pub fn restore_key(&mut self, snapshot: NamespaceIndexKeySnapshot) {
        self.entries.remove(&snapshot.blind_key);
        self.remove_prefix_membership(&snapshot.blind_key);

        if let Some(entry) = snapshot.entry {
            self.upsert(entry, snapshot.prefix_tokens);
        }
    }

    /// Lists entries for a prefix token in stable blind-key order.
    pub fn list_prefix(&self, prefix_token: &PrefixToken) -> Vec<&NamespaceEntry> {
        self.prefixes
            .get(prefix_token)
            .into_iter()
            .flatten()
            .filter_map(|blind_key| self.entries.get(blind_key))
            .collect()
    }

    /// Removes an entry from the live query index and its prefix lists.
    /// Durable tombstones and generation checks belong to authenticated index runs.
    pub fn remove(&mut self, blind_key: &BlindIndexKey) {
        self.entries.remove(blind_key);
        self.remove_prefix_membership(blind_key);
    }

    fn remove_prefix_membership(&mut self, blind_key: &BlindIndexKey) {
        let Some(prefix_tokens) = self.entry_prefixes.remove(blind_key) else {
            return;
        };

        for prefix_token in prefix_tokens {
            let should_remove = match self.prefixes.get_mut(&prefix_token) {
                Some(members) => {
                    members.remove(blind_key);
                    members.is_empty()
                }
                None => false,
            };

            if should_remove {
                self.prefixes.remove(&prefix_token);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        IndexDelta, MANIFEST_PLAINTEXT_DOMAIN, NamespaceEntry, NamespaceIndex, PayloadReference,
        V3PackCarrierReference, V3PackRecordReference, V3StandaloneStreamCarrierReference,
        manifest_plaintext_bytes,
    };
    use rs3_types::{
        BackendObjectId, BackendVersionId, BlindIndexKey, KeyId, LogicalPath, ManifestId,
        ObjectEtag, PrefixToken, Sequence,
    };
    use std::sync::Arc;

    fn blind_key(value: &str) -> BlindIndexKey {
        match BlindIndexKey::new(value) {
            Ok(value) => value,
            Err(error) => panic!("{error}"),
        }
    }

    fn prefix_token(value: &str) -> PrefixToken {
        match PrefixToken::new(value) {
            Ok(value) => value,
            Err(error) => panic!("{error}"),
        }
    }

    fn object_id(value: &str) -> BackendObjectId {
        match BackendObjectId::new(value) {
            Ok(value) => value,
            Err(error) => panic!("{error}"),
        }
    }

    fn manifest_id(value: &str) -> ManifestId {
        match ManifestId::new(value) {
            Ok(value) => value,
            Err(error) => panic!("{error}"),
        }
    }

    fn key_id(value: &str) -> KeyId {
        match KeyId::new(value) {
            Ok(value) => value,
            Err(error) => panic!("{error}"),
        }
    }

    fn logical_path(value: &str) -> LogicalPath {
        match LogicalPath::new(value) {
            Ok(value) => value,
            Err(error) => panic!("{error}"),
        }
    }

    fn entry(blind_key: BlindIndexKey, object_id: BackendObjectId) -> NamespaceEntry {
        NamespaceEntry {
            namespace_key_id: key_id("namespace-a"),
            blind_key,
            object_id,
            object_version_id: None,
            payload_ref: None,
            manifest_id: manifest_id("manifest-a"),
            content_len: 42,
            modified_at_ms: 7,
            generation: Sequence::new(1),
            retention: None,
            legal_hold: None,
        }
    }

    #[test]
    fn tombstone_keeps_generation() {
        let blind_key = blind_key("abc");
        let delta = IndexDelta::Tombstone {
            namespace_key_id: key_id("namespace-a"),
            blind_key,
            path: logical_path("private/path"),
            generation: Sequence::new(7),
        };

        assert!(!format!("{delta:?}").contains("private/path"));
        match delta {
            IndexDelta::Tombstone {
                namespace_key_id,
                path,
                generation,
                ..
            } => {
                assert_eq!(namespace_key_id, key_id("namespace-a"));
                assert_eq!(path, logical_path("private/path"));
                assert_eq!(generation, Sequence::new(7));
            }
            IndexDelta::Upsert { .. } => panic!("unexpected upsert"),
        }
    }

    #[test]
    fn manifest_plaintext_encoding_has_domain_prefix() {
        let manifest = super::DurableManifest {
            key: logical_path("p/12/object"),
            content_len: 42,
            modified_at_ms: 7,
            retention: None,
            legal_hold: None,
            etag: ObjectEtag::single(rs3_types::Md5Digest::from_bytes([0x55; 16])),
            checksum: None,
        };

        let plaintext = manifest_plaintext_bytes(&manifest);

        assert!(matches!(
            plaintext,
            Ok(bytes) if bytes.starts_with(MANIFEST_PLAINTEXT_DOMAIN)
        ));
    }

    #[test]
    fn payload_pack_references_round_trip_direct_read_facts() {
        let accepted = PayloadReference::V3Pack {
            carrier: Arc::new(V3PackCarrierReference {
                commit_key: object_id("commits/opaque"),
                commit_version_id: Some(BackendVersionId::new("version-1").expect("version id")),
                body_digest: [0x33; 32],
                commit_stored_len: 32_768,
                pack_section_ordinal: 4,
                pack_offset: 8_192,
                length: 16_384,
                pack_id: [0x44; 32],
                attempt_id: rs3_types::PayloadAttemptId::from_bytes([0xa3; 32]),
                content_key_id: key_id("older-content"),
                keyring_envelope_object_id: object_id("keyrings/historical"),
                keyring_envelope_digest: [0x45; 32],
                pack_record_count: 11,
            }),
            record: V3PackRecordReference {
                record_ordinal: 5,
                record_offset: 12_288,
            },
        };
        let references = [
            PayloadReference::V3PackSelf {
                pack_section_ordinal: 2,
                pack_id: [0x11; 32],
                attempt_id: rs3_types::PayloadAttemptId::from_bytes([0xa3; 32]),
                content_key_id: key_id("historical-content"),
                keyring_envelope_object_id: object_id("keyrings/current"),
                keyring_envelope_digest: [0x12; 32],
                pack_record_count: 7,
                record_ordinal: 3,
                record_offset: 4_096,
            },
            accepted,
        ];

        for reference in references {
            let encoded = serde_json::to_vec(&reference).expect("serialize payload reference");
            let decoded: PayloadReference =
                serde_json::from_slice(&encoded).expect("deserialize payload reference");
            assert_eq!(decoded, reference);
        }
    }

    #[test]
    fn shared_payload_pack_reference_round_trips() {
        let carrier = Arc::new(V3PackCarrierReference {
            commit_key: object_id("commits/opaque"),
            commit_version_id: Some(BackendVersionId::new("version-1").expect("version id")),
            body_digest: [0x33; 32],
            commit_stored_len: 32_768,
            pack_section_ordinal: 4,
            pack_offset: 8_192,
            length: 16_384,
            pack_id: [0x44; 32],
            attempt_id: rs3_types::PayloadAttemptId::from_bytes([0xa3; 32]),
            content_key_id: key_id("older-content"),
            keyring_envelope_object_id: object_id("keyrings/historical"),
            keyring_envelope_digest: [0x45; 32],
            pack_record_count: 11,
        });
        let record = V3PackRecordReference {
            record_ordinal: 5,
            record_offset: 12_288,
        };
        let shared = PayloadReference::V3Pack {
            carrier: Arc::clone(&carrier),
            record,
        };
        let bytes = serde_json::to_vec(&shared).expect("encode pack reference");
        assert_eq!(
            serde_json::from_slice::<PayloadReference>(&bytes).expect("decode pack reference"),
            shared
        );
    }

    #[test]
    fn standalone_stream_reference_round_trips_its_distinct_typed_shape() {
        let reference = PayloadReference::V3StandaloneStream {
            carrier: Arc::new(V3StandaloneStreamCarrierReference {
                object_id: object_id("objects/v03/standalone-stream"),
                version_id: Some(BackendVersionId::new("version-3").expect("version id")),
                object_digest: [0x71; 32],
                stored_len: 131_233,
                keyring_envelope_object_id: object_id("keyrings/standalone"),
                keyring_envelope_digest: [0x72; 32],
                payload_layout: super::PayloadLayout {
                    chunk_size: 64 * 1024,
                    plaintext_len: 131_072,
                    key_id: key_id("standalone-content"),
                    carrier_id: [0x73; 32],
                    parts: vec![crate::PayloadPart {
                        part_number: 1,
                        attempt_id: rs3_types::PayloadAttemptId::from_bytes([0x81; 32]),
                        plaintext_len: 131_072,
                    }],
                },
            }),
        };

        let encoded = serde_json::to_vec(&reference).expect("serialize standalone reference");
        assert!(encoded.starts_with(br#"{"V2StandaloneStream":{"#));
        assert!(!encoded.windows(8).any(|window| window == b"V2Commit"));
        assert_eq!(
            serde_json::from_slice::<PayloadReference>(&encoded)
                .expect("deserialize standalone reference"),
            reference
        );
    }

    #[test]
    fn namespace_head_and_prefix_list_use_blind_identifiers() {
        let mut index = NamespaceIndex::new();
        let blind_key = blind_key("blind-a");
        let object_id = object_id("segments/opaque-a");
        let prefix_token = prefix_token("prefix-p");

        index.upsert(
            entry(blind_key.clone(), object_id.clone()),
            vec![prefix_token.clone()],
        );

        assert_eq!(
            index.head(&blind_key).map(|entry| entry.object_id.clone()),
            Some(object_id.clone())
        );
        assert_eq!(
            index
                .list_prefix(&prefix_token)
                .into_iter()
                .map(|entry| entry.object_id.clone())
                .collect::<Vec<_>>(),
            vec![object_id]
        );
    }

    #[test]
    fn namespace_upsert_without_prefixes_skips_both_prefix_projections() {
        let mut index = NamespaceIndex::new();
        let blind_key = blind_key("blind-a");
        let old_prefix = prefix_token("prefix-old");
        let replacement = object_id("segments/opaque-b");

        index.upsert(
            entry(blind_key.clone(), object_id("segments/opaque-a")),
            vec![old_prefix.clone()],
        );
        index.upsert_without_prefixes(entry(blind_key.clone(), replacement.clone()));

        assert_eq!(
            index.head(&blind_key).map(|entry| &entry.object_id),
            Some(&replacement)
        );
        assert!(index.prefix_tokens(&blind_key).next().is_none());
        assert!(index.list_prefix(&old_prefix).is_empty());
        assert!(!index.entry_prefixes.contains_key(&blind_key));
        assert!(index.prefixes.is_empty());
    }

    #[test]
    fn namespace_removal_clears_live_entry_and_prefix() {
        let mut index = NamespaceIndex::new();
        let blind_key = blind_key("blind-a");
        let prefix_token = prefix_token("prefix-p");

        index.upsert(
            entry(blind_key.clone(), object_id("segments/opaque-a")),
            vec![prefix_token.clone()],
        );
        index.remove(&blind_key);

        assert!(index.head(&blind_key).is_none());
        assert!(index.list_prefix(&prefix_token).is_empty());
    }

    #[test]
    fn namespace_key_snapshot_restores_entry_and_prefixes_after_removal() {
        let mut index = NamespaceIndex::new();
        let blind_key = blind_key("blind-a");
        let old_prefix = prefix_token("prefix-old");
        let new_prefix = prefix_token("prefix-new");
        let original_object = object_id("segments/opaque-original");
        let snapshot = {
            index.upsert(
                entry(blind_key.clone(), original_object.clone()),
                vec![old_prefix.clone()],
            );
            index.snapshot_key(&blind_key)
        };

        index.upsert(
            entry(blind_key.clone(), object_id("segments/opaque-new")),
            vec![new_prefix.clone()],
        );
        index.remove(&blind_key);
        index.restore_key(snapshot);

        assert_eq!(
            index.head(&blind_key).map(|entry| &entry.object_id),
            Some(&original_object)
        );
        assert_eq!(index.list_prefix(&old_prefix).len(), 1);
        assert!(index.list_prefix(&new_prefix).is_empty());
    }

    #[test]
    fn namespace_upsert_replaces_stale_prefix_membership() {
        let mut index = NamespaceIndex::new();
        let blind_key = blind_key("blind-a");
        let old_prefix = prefix_token("prefix-old");
        let new_prefix = prefix_token("prefix-new");

        index.upsert(
            entry(blind_key.clone(), object_id("segments/opaque-a")),
            vec![old_prefix.clone()],
        );
        index.upsert(
            entry(blind_key, object_id("segments/opaque-b")),
            vec![new_prefix.clone()],
        );

        assert!(index.list_prefix(&old_prefix).is_empty());
        assert_eq!(
            index
                .list_prefix(&new_prefix)
                .into_iter()
                .map(|entry| entry.object_id.clone())
                .collect::<Vec<_>>(),
            vec![object_id("segments/opaque-b")]
        );
    }

    #[test]
    fn absent_key_snapshot_rollback_preserves_unrelated_changes() {
        let mut index = NamespaceIndex::new();
        let staged = blind_key("staged");
        let unrelated = blind_key("unrelated");
        let prefix = prefix_token("shared-prefix");
        let snapshot = index.snapshot_key(&staged);
        index.upsert(
            entry(staged.clone(), object_id("objects/staged")),
            vec![prefix.clone()],
        );
        index.upsert(
            entry(unrelated.clone(), object_id("objects/accepted")),
            vec![prefix.clone()],
        );

        index.restore_key(snapshot);

        assert!(index.head(&staged).is_none());
        assert_eq!(
            index.list_prefix(&prefix),
            vec![index.head(&unrelated).expect("unrelated entry")]
        );
        assert_eq!(index.live_entries().count(), 1);
    }
}
