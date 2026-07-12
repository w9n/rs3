//! Append-friendly index and checkpoint model.

pub mod run;

use rs3_types::{
    BackendObjectId, BackendObjectRef, BackendVersionId, BlindIndexKey, CheckpointId,
    KeyDescriptor, KeyId, KeyPurpose, KeyStatus, LegalHoldStatus, LogicalPath, ManifestId,
    PrefixToken, RetentionPolicy, Sequence,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

/// Domain separator prepended to canonical checkpoint payload bytes.
pub const CHECKPOINT_RECORD_DOMAIN: &[u8] = b"rs3:checkpoint-record:v1\n";

/// Domain separator prepended to durable checkpoint objects.
pub const CHECKPOINT_OBJECT_DOMAIN: &[u8] = b"rs3:checkpoint-object:v1\n";

/// Domain separator prepended to durable checkpoint evidence objects.
pub const CHECKPOINT_EVIDENCE_DOMAIN: &[u8] = b"rs3:checkpoint-evidence:v1\n";

/// Domain separator prepended to durable index delta objects.
pub const INDEX_DELTA_OBJECT_DOMAIN: &[u8] = b"rs3:index-delta-object:v1\n";

/// Domain separator prepended to plaintext index delta payloads before sealing.
pub const INDEX_DELTA_PLAINTEXT_DOMAIN: &[u8] = b"rs3:index-delta-plaintext:v1\n";

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
    V2PackSelf {
        /// Commit section ordinal containing the payload pack.
        pack_section_ordinal: u32,
        /// Random pack identity bound into every record AEAD operation.
        pack_id: [u8; 32],
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
        /// SHA-256 digest over the complete plaintext record.
        plaintext_digest: [u8; 32],
    },
    /// Compact payload-pack record in an accepted exact commit object.
    V2Pack {
        /// Exact carrier facts shared by every record in the same payload pack.
        #[serde(flatten)]
        carrier: Arc<V2PackCarrierReference>,
        /// Record-specific facts inside the shared payload pack.
        #[serde(flatten)]
        record: V2PackRecordReference,
    },
    /// Payload bytes are in the current commit that carries this index delta.
    V2Self {
        /// Opaque payload identity used as the AEAD associated-data object id.
        payload_id: BackendObjectId,
        /// Parsed segmented-payload header needed for direct range reads.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        payload_header: Option<PayloadHeaderReference>,
        /// Absolute byte offset where the containing commit's section region starts.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sections_start: Option<u64>,
        /// Byte offset relative to the commit section region.
        offset: u64,
        /// Encrypted payload-section byte length.
        length: u64,
    },
    /// Payload bytes are in a resolved v2 commit object.
    V2Commit {
        /// Exact carrier facts shared by every reference to this streamed payload.
        #[serde(flatten)]
        carrier: Arc<V2StreamCarrierReference>,
    },
}

/// Exact accepted commit and section facts shared by records in one payload pack.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct V2PackCarrierReference {
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
pub struct V2PackRecordReference {
    /// Logical record ordinal in the pack directory.
    pub record_ordinal: u32,
    /// Absolute ciphertext offset from the start of the payload-pack section.
    pub record_offset: u32,
    /// SHA-256 digest over the complete plaintext record.
    pub plaintext_digest: [u8; 32],
}

/// Exact accepted commit and section facts for a streamed payload.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct V2StreamCarrierReference {
    /// Commit object key containing the payload section.
    pub commit_key: BackendObjectId,
    /// Provider version identifier for exact-version reads, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_version_id: Option<BackendVersionId>,
    /// Commit body digest from the signed header.
    pub body_digest: [u8; 32],
    /// Provider-reported complete commit-object length.
    pub commit_stored_len: u64,
    /// Historical encrypted-keyring envelope object bound into payload AEAD context.
    pub keyring_envelope_object_id: BackendObjectId,
    /// SHA-256 digest of that encrypted-keyring envelope.
    pub keyring_envelope_digest: [u8; 32],
    /// Signed section ordinal containing the streamed payload.
    pub payload_section_ordinal: u32,
    /// Signed digest of the complete streamed payload section.
    pub payload_section_digest: [u8; 32],
    /// Opaque payload identity used as the AEAD associated-data object id.
    pub payload_id: BackendObjectId,
    /// Parsed segmented-payload header needed for direct range reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_header: Option<PayloadHeaderReference>,
    /// Absolute byte offset where the containing commit's section region starts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sections_start: Option<u64>,
    /// Byte offset relative to the commit section region.
    pub offset: u64,
    /// Encrypted payload-section byte length.
    pub length: u64,
}

/// Signed/encrypted payload-header facts used to plan direct range reads.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PayloadHeaderReference {
    /// Plaintext bytes per independently encrypted segment.
    pub chunk_size: u64,
    /// Total plaintext payload length.
    pub plaintext_len: u64,
    /// Content-encryption key identifier.
    pub key_id: KeyId,
    /// Per-payload nonce prefix used for segment nonce derivation.
    pub nonce_prefix: [u8; 16],
    /// Encoded payload-header byte length.
    pub header_len: u64,
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

/// Durable index delta object referenced by a checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexDeltaObject {
    /// Repository sequence represented by this delta batch.
    pub sequence: Sequence,
    /// Ordered index mutations to replay.
    pub deltas: Vec<IndexDelta>,
}

/// Sealed index delta object stored in the backend and referenced by a checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedIndexDeltaObject {
    /// Metadata key that sealed the payload.
    pub key_id: KeyId,
    /// Nonce used for the sealed payload.
    pub nonce: Vec<u8>,
    /// Sealed index delta payload.
    pub ciphertext: Vec<u8>,
    /// Authentication tag over the index delta object context.
    pub tag: Vec<u8>,
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

/// Public keyring metadata captured in a checkpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyringSnapshot {
    /// Public descriptors for repository keys.
    pub keys: Vec<KeyDescriptor>,
}

impl KeyringSnapshot {
    /// Creates a deterministic keyring snapshot.
    pub fn new(mut keys: Vec<KeyDescriptor>) -> Self {
        keys.sort_by(|left, right| {
            left.purpose
                .cmp(&right.purpose)
                .then_with(|| left.id.cmp(&right.id))
        });
        Self { keys }
    }

    /// Finds the primary key descriptor for a purpose.
    pub fn primary_for(&self, purpose: KeyPurpose) -> Option<&KeyDescriptor> {
        self.keys
            .iter()
            .find(|key| key.purpose == purpose && key.status == KeyStatus::Primary)
    }

    /// Returns descriptors enabled for read, verify, or lookup for a purpose.
    pub fn enabled_for(&self, purpose: KeyPurpose) -> Vec<&KeyDescriptor> {
        self.keys
            .iter()
            .filter(|key| key.purpose == purpose && key.status.is_enabled_for_lookup())
            .collect()
    }
}

/// Public reference to the encrypted keyring envelope active for a checkpoint.
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

/// Signed checkpoint payload before signature wrapping.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitRecord {
    /// Checkpoint sequence.
    pub sequence: Sequence,
    /// Checkpoint publish timestamp in milliseconds since the Unix epoch.
    pub published_at_ms: i64,
    /// Previous checkpoint, if any.
    pub parent: Option<CheckpointId>,
    /// Provider version identifier for the previous checkpoint object, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_checkpoint_version_id: Option<BackendVersionId>,
    /// Referenced durable index delta objects.
    pub index_deltas: Vec<BackendObjectRef>,
    /// Sealed index delta embedded directly in this checkpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline_index_delta: Option<SealedIndexDeltaObject>,
    /// Referenced compacted manifest objects.
    pub compacted_manifests: Vec<ManifestId>,
    /// Public keyring metadata active for this checkpoint.
    pub keyring: KeyringSnapshot,
    /// Encrypted keyring envelope active for this checkpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyring_envelope: Option<KeyringEnvelopeReference>,
}

impl CommitRecord {
    /// Returns a normalized copy for deterministic checkpoint encoding.
    pub fn canonicalized(&self) -> Self {
        let mut record = self.clone();
        record.index_deltas.sort();
        record.compacted_manifests.sort();
        record.keyring = KeyringSnapshot::new(record.keyring.keys);
        record
    }
}

/// Published checkpoint with signature material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Checkpoint identifier.
    pub id: CheckpointId,
    /// Signed checkpoint payload.
    pub record: CommitRecord,
    /// Key that produced the signature.
    pub signature_key_id: KeyId,
    /// Signature bytes over the canonical checkpoint payload.
    pub signature: Vec<u8>,
}

impl Checkpoint {
    /// Returns the checkpoint sequence.
    pub const fn sequence(&self) -> Sequence {
        self.record.sequence
    }
}

/// Storage-side evidence that a checkpoint was published.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointEvidence {
    /// Checkpoint sequence.
    pub sequence: Sequence,
    /// Checkpoint identifier.
    pub checkpoint_id: CheckpointId,
    /// Digest of the canonical checkpoint payload.
    pub checkpoint_digest: String,
    /// Backend object that stores the signed checkpoint.
    pub checkpoint_object_id: BackendObjectId,
    /// Provider version identifier for the signed checkpoint object, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_object_version_id: Option<BackendVersionId>,
}

/// Encodes a checkpoint payload into deterministic signed bytes.
pub fn canonical_commit_record_bytes(record: &CommitRecord) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = CHECKPOINT_RECORD_DOMAIN.to_vec();
    serde_json::to_writer(&mut bytes, &record.canonicalized())?;
    Ok(bytes)
}

/// Encodes a durable checkpoint object.
pub fn checkpoint_object_bytes(checkpoint: &Checkpoint) -> Result<Vec<u8>, serde_json::Error> {
    let mut checkpoint = checkpoint.clone();
    checkpoint.record = checkpoint.record.canonicalized();
    let mut bytes = CHECKPOINT_OBJECT_DOMAIN.to_vec();
    serde_json::to_writer(&mut bytes, &checkpoint)?;
    Ok(bytes)
}

/// Encodes durable checkpoint evidence.
pub fn checkpoint_evidence_bytes(
    evidence: &CheckpointEvidence,
) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = CHECKPOINT_EVIDENCE_DOMAIN.to_vec();
    serde_json::to_writer(&mut bytes, evidence)?;
    Ok(bytes)
}

/// Encodes a durable sealed index delta object.
pub fn index_delta_object_bytes(
    delta: &SealedIndexDeltaObject,
) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = INDEX_DELTA_OBJECT_DOMAIN.to_vec();
    serde_json::to_writer(&mut bytes, delta)?;
    Ok(bytes)
}

/// Encodes index delta plaintext before sealing.
pub fn index_delta_plaintext_bytes(delta: &IndexDeltaObject) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = INDEX_DELTA_PLAINTEXT_DOMAIN.to_vec();
    serde_json::to_writer(&mut bytes, delta)?;
    Ok(bytes)
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
    /// Commit-backed payload location for v2 repositories.
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

/// Tombstone for a removed namespace entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceTombstone {
    /// Blind key removed by this tombstone.
    pub blind_key: BlindIndexKey,
    /// Repository generation that made the tombstone visible.
    pub generation: Sequence,
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
    tombstones: BTreeMap<BlindIndexKey, NamespaceTombstone>,
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
    tombstone: Option<NamespaceTombstone>,
}

impl NamespaceIndex {
    /// Creates an empty namespace index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts or replaces an entry and associates it with prefix tokens.
    pub fn upsert(&mut self, entry: NamespaceEntry, prefix_tokens: Vec<PrefixToken>) {
        self.remove_prefix_membership(&entry.blind_key);
        self.tombstones.remove(&entry.blind_key);

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

    /// Captures one key's live entry, prefix membership, and tombstone.
    pub fn snapshot_key(&self, blind_key: &BlindIndexKey) -> NamespaceIndexKeySnapshot {
        NamespaceIndexKeySnapshot {
            blind_key: blind_key.clone(),
            entry: self.entries.get(blind_key).cloned(),
            prefix_tokens: self
                .entry_prefixes
                .get(blind_key)
                .map(|tokens| tokens.iter().cloned().collect())
                .unwrap_or_default(),
            tombstone: self.tombstones.get(blind_key).cloned(),
        }
    }

    /// Restores a key from a snapshot captured before a staged mutation.
    pub fn restore_key(&mut self, snapshot: NamespaceIndexKeySnapshot) {
        self.entries.remove(&snapshot.blind_key);
        self.remove_prefix_membership(&snapshot.blind_key);
        self.tombstones.remove(&snapshot.blind_key);

        if let Some(entry) = snapshot.entry {
            self.upsert(entry, snapshot.prefix_tokens);
        }
        if let Some(tombstone) = snapshot.tombstone {
            self.tombstones.insert(snapshot.blind_key, tombstone);
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

    /// Writes a tombstone and removes the live entry from prefix lists.
    pub fn tombstone(&mut self, blind_key: BlindIndexKey, generation: Sequence) {
        self.entries.remove(&blind_key);
        self.remove_prefix_membership(&blind_key);
        self.tombstones.insert(
            blind_key.clone(),
            NamespaceTombstone {
                blind_key,
                generation,
            },
        );
    }

    /// Looks up a tombstone by blind key.
    pub fn tombstone_for(&self, blind_key: &BlindIndexKey) -> Option<&NamespaceTombstone> {
        self.tombstones.get(blind_key)
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
        CHECKPOINT_EVIDENCE_DOMAIN, CHECKPOINT_OBJECT_DOMAIN, Checkpoint, CheckpointEvidence,
        CommitRecord, INDEX_DELTA_OBJECT_DOMAIN, INDEX_DELTA_PLAINTEXT_DOMAIN, IndexDelta,
        IndexDeltaObject, KeyringSnapshot, MANIFEST_PLAINTEXT_DOMAIN, ManifestObject,
        NamespaceEntry, NamespaceIndex, PayloadReference, SealedIndexDeltaObject,
        V2PackCarrierReference, V2PackRecordReference, V2StreamCarrierReference,
        canonical_commit_record_bytes, checkpoint_evidence_bytes, checkpoint_object_bytes,
        index_delta_object_bytes, index_delta_plaintext_bytes, manifest_plaintext_bytes,
    };
    use rs3_types::{
        BackendObjectId, BackendVersionId, BlindIndexKey, CheckpointId, KeyDescriptor, KeyId,
        KeyPurpose, KeyStatus, LogicalPath, ManifestId, PrefixToken, Sequence,
    };
    use serde::Serialize;
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

    fn checkpoint_id(value: &str) -> CheckpointId {
        match CheckpointId::new(value) {
            Ok(value) => value,
            Err(error) => panic!("{error}"),
        }
    }

    fn key_descriptor(id: &str, purpose: KeyPurpose, status: KeyStatus) -> KeyDescriptor {
        KeyDescriptor {
            id: key_id(id),
            purpose,
            algorithm: "hmac-sha256".to_string(),
            status,
            created_at_ms: 0,
            not_before_ms: None,
            not_after_ms: None,
            public_key: None,
            external_kms_uri: None,
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

    fn sealed_manifest() -> ManifestObject {
        ManifestObject {
            key_id: key_id("metadata"),
            nonce: vec![1, 2, 3],
            ciphertext: vec![4, 5, 6],
            tag: vec![7, 8, 9],
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
    fn commit_record_starts_without_parent() {
        let record = CommitRecord {
            sequence: Sequence::ZERO,
            published_at_ms: 0,
            parent: None,
            parent_checkpoint_version_id: None,
            index_deltas: Vec::new(),
            inline_index_delta: None,
            compacted_manifests: Vec::new(),
            keyring: KeyringSnapshot::default(),
            keyring_envelope: None,
        };

        assert!(record.parent.is_none());
    }

    #[test]
    fn canonical_commit_record_encoding_is_stable() {
        let unsorted = CommitRecord {
            sequence: Sequence::new(3),
            published_at_ms: 123,
            parent: None,
            parent_checkpoint_version_id: None,
            index_deltas: vec![
                object_id("segments/b").into(),
                object_id("segments/a").into(),
            ],
            inline_index_delta: None,
            compacted_manifests: vec![manifest_id("manifest-b"), manifest_id("manifest-a")],
            keyring: KeyringSnapshot::new(vec![
                key_descriptor("old", KeyPurpose::Namespace, KeyStatus::Enabled),
                key_descriptor("new", KeyPurpose::Namespace, KeyStatus::Primary),
            ]),
            keyring_envelope: None,
        };
        let sorted = CommitRecord {
            sequence: Sequence::new(3),
            published_at_ms: 123,
            parent: None,
            parent_checkpoint_version_id: None,
            index_deltas: vec![
                object_id("segments/a").into(),
                object_id("segments/b").into(),
            ],
            inline_index_delta: None,
            compacted_manifests: vec![manifest_id("manifest-a"), manifest_id("manifest-b")],
            keyring: KeyringSnapshot::new(vec![
                key_descriptor("new", KeyPurpose::Namespace, KeyStatus::Primary),
                key_descriptor("old", KeyPurpose::Namespace, KeyStatus::Enabled),
            ]),
            keyring_envelope: None,
        };

        let left = canonical_commit_record_bytes(&unsorted);
        let right = canonical_commit_record_bytes(&sorted);

        assert!(left.is_ok());
        assert_eq!(left.ok(), right.ok());
    }

    #[test]
    fn canonical_commit_record_encoding_changes_with_sequence() {
        let first = CommitRecord {
            sequence: Sequence::new(1),
            published_at_ms: 123,
            parent: None,
            parent_checkpoint_version_id: None,
            index_deltas: Vec::new(),
            inline_index_delta: None,
            compacted_manifests: Vec::new(),
            keyring: KeyringSnapshot::default(),
            keyring_envelope: None,
        };
        let second = CommitRecord {
            sequence: Sequence::new(2),
            published_at_ms: 123,
            parent: None,
            parent_checkpoint_version_id: None,
            index_deltas: Vec::new(),
            inline_index_delta: None,
            compacted_manifests: Vec::new(),
            keyring: KeyringSnapshot::default(),
            keyring_envelope: None,
        };

        let first_bytes = canonical_commit_record_bytes(&first);
        let second_bytes = canonical_commit_record_bytes(&second);

        assert!(first_bytes.is_ok());
        assert!(second_bytes.is_ok());
        assert_ne!(first_bytes.ok(), second_bytes.ok());
    }

    #[test]
    fn checkpoint_object_encoding_has_domain_prefix() {
        let checkpoint = Checkpoint {
            id: checkpoint_id("checkpoint-a"),
            record: CommitRecord {
                sequence: Sequence::new(1),
                published_at_ms: 123,
                parent: None,
                parent_checkpoint_version_id: None,
                index_deltas: Vec::new(),
                inline_index_delta: None,
                compacted_manifests: Vec::new(),
                keyring: KeyringSnapshot::default(),
                keyring_envelope: None,
            },
            signature_key_id: key_id("signing"),
            signature: vec![1, 2, 3],
        };

        let encoded = checkpoint_object_bytes(&checkpoint);

        assert!(matches!(
            encoded,
            Ok(bytes) if bytes.starts_with(CHECKPOINT_OBJECT_DOMAIN)
        ));
    }

    #[test]
    fn checkpoint_evidence_encoding_has_domain_prefix() {
        let evidence = CheckpointEvidence {
            sequence: Sequence::new(1),
            checkpoint_id: checkpoint_id("checkpoint-a"),
            checkpoint_digest: "digest-a".to_owned(),
            checkpoint_object_id: object_id("checkpoints/checkpoint-a"),
            checkpoint_object_version_id: None,
        };

        let encoded = checkpoint_evidence_bytes(&evidence);

        assert!(matches!(
            encoded,
            Ok(bytes) if bytes.starts_with(CHECKPOINT_EVIDENCE_DOMAIN)
        ));
    }

    #[test]
    fn index_delta_object_encoding_has_domain_prefix() {
        let delta = SealedIndexDeltaObject {
            key_id: key_id("metadata"),
            nonce: vec![1; 24],
            ciphertext: vec![2; 32],
            tag: vec![3; 16],
        };

        let encoded = index_delta_object_bytes(&delta);

        assert!(matches!(
            encoded,
            Ok(bytes) if bytes.starts_with(INDEX_DELTA_OBJECT_DOMAIN)
        ));
    }

    #[test]
    fn index_delta_plaintext_encoding_has_domain_prefix() {
        let delta = IndexDeltaObject {
            sequence: Sequence::new(1),
            deltas: vec![IndexDelta::Upsert {
                entry: Box::new(entry(blind_key("blind-a"), object_id("segments/opaque-a"))),
                prefix_tokens: vec![prefix_token("prefix-a")],
                sealed_manifest: Box::new(sealed_manifest()),
            }],
        };

        let encoded = index_delta_plaintext_bytes(&delta);

        assert!(matches!(
            encoded,
            Ok(bytes) if bytes.starts_with(INDEX_DELTA_PLAINTEXT_DOMAIN)
        ));
    }

    #[test]
    fn manifest_plaintext_encoding_has_domain_prefix() {
        let manifest = super::DurableManifest {
            key: logical_path("p/12/object"),
            content_len: 42,
            modified_at_ms: 7,
            retention: None,
            legal_hold: None,
        };

        let plaintext = manifest_plaintext_bytes(&manifest);

        assert!(matches!(
            plaintext,
            Ok(bytes) if bytes.starts_with(MANIFEST_PLAINTEXT_DOMAIN)
        ));
    }

    #[test]
    fn keyring_snapshot_tracks_primary_and_enabled_keys() {
        let snapshot = KeyringSnapshot::new(vec![
            key_descriptor("old", KeyPurpose::Namespace, KeyStatus::Enabled),
            key_descriptor("new", KeyPurpose::Namespace, KeyStatus::Primary),
            key_descriptor("disabled", KeyPurpose::Namespace, KeyStatus::Disabled),
        ]);

        assert_eq!(
            snapshot
                .primary_for(KeyPurpose::Namespace)
                .map(|key| key.id.clone()),
            Some(key_id("new"))
        );
        assert_eq!(
            snapshot
                .enabled_for(KeyPurpose::Namespace)
                .into_iter()
                .map(|key| key.id.clone())
                .collect::<Vec<_>>(),
            vec![key_id("new"), key_id("old")]
        );
    }

    #[test]
    fn payload_pack_references_round_trip_direct_read_facts() {
        let accepted = PayloadReference::V2Pack {
            carrier: Arc::new(V2PackCarrierReference {
                commit_key: object_id("commits/opaque"),
                commit_version_id: Some(BackendVersionId::new("version-1").expect("version id")),
                body_digest: [0x33; 32],
                commit_stored_len: 32_768,
                pack_section_ordinal: 4,
                pack_offset: 8_192,
                length: 16_384,
                pack_id: [0x44; 32],
                content_key_id: key_id("older-content"),
                keyring_envelope_object_id: object_id("keyrings/historical"),
                keyring_envelope_digest: [0x45; 32],
                pack_record_count: 11,
            }),
            record: V2PackRecordReference {
                record_ordinal: 5,
                record_offset: 12_288,
                plaintext_digest: [0x55; 32],
            },
        };
        let references = [
            PayloadReference::V2PackSelf {
                pack_section_ordinal: 2,
                pack_id: [0x11; 32],
                content_key_id: key_id("historical-content"),
                keyring_envelope_object_id: object_id("keyrings/current"),
                keyring_envelope_digest: [0x12; 32],
                pack_record_count: 7,
                record_ordinal: 3,
                record_offset: 4_096,
                plaintext_digest: [0x22; 32],
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

    #[derive(Serialize)]
    enum LegacyPayloadReference<'a> {
        V2Pack {
            commit_key: &'a BackendObjectId,
            #[serde(skip_serializing_if = "Option::is_none")]
            commit_version_id: &'a Option<BackendVersionId>,
            body_digest: [u8; 32],
            commit_stored_len: u64,
            pack_section_ordinal: u32,
            pack_offset: u64,
            length: u64,
            pack_id: [u8; 32],
            content_key_id: &'a KeyId,
            keyring_envelope_object_id: &'a BackendObjectId,
            keyring_envelope_digest: [u8; 32],
            pack_record_count: u32,
            record_ordinal: u32,
            record_offset: u32,
            plaintext_digest: [u8; 32],
        },
        V2Commit {
            commit_key: &'a BackendObjectId,
            #[serde(skip_serializing_if = "Option::is_none")]
            commit_version_id: &'a Option<BackendVersionId>,
            body_digest: [u8; 32],
            commit_stored_len: u64,
            keyring_envelope_object_id: &'a BackendObjectId,
            keyring_envelope_digest: [u8; 32],
            payload_section_ordinal: u32,
            payload_section_digest: [u8; 32],
            payload_id: &'a BackendObjectId,
            #[serde(skip_serializing_if = "Option::is_none")]
            payload_header: &'a Option<super::PayloadHeaderReference>,
            #[serde(skip_serializing_if = "Option::is_none")]
            sections_start: &'a Option<u64>,
            offset: u64,
            length: u64,
        },
    }

    #[test]
    fn shared_payload_pack_reference_preserves_the_flat_serialized_shape() {
        let carrier = Arc::new(V2PackCarrierReference {
            commit_key: object_id("commits/opaque"),
            commit_version_id: Some(BackendVersionId::new("version-1").expect("version id")),
            body_digest: [0x33; 32],
            commit_stored_len: 32_768,
            pack_section_ordinal: 4,
            pack_offset: 8_192,
            length: 16_384,
            pack_id: [0x44; 32],
            content_key_id: key_id("older-content"),
            keyring_envelope_object_id: object_id("keyrings/historical"),
            keyring_envelope_digest: [0x45; 32],
            pack_record_count: 11,
        });
        let record = V2PackRecordReference {
            record_ordinal: 5,
            record_offset: 12_288,
            plaintext_digest: [0x55; 32],
        };
        let shared = PayloadReference::V2Pack {
            carrier: Arc::clone(&carrier),
            record,
        };
        let legacy = LegacyPayloadReference::V2Pack {
            commit_key: &carrier.commit_key,
            commit_version_id: &carrier.commit_version_id,
            body_digest: carrier.body_digest,
            commit_stored_len: carrier.commit_stored_len,
            pack_section_ordinal: carrier.pack_section_ordinal,
            pack_offset: carrier.pack_offset,
            length: carrier.length,
            pack_id: carrier.pack_id,
            content_key_id: &carrier.content_key_id,
            keyring_envelope_object_id: &carrier.keyring_envelope_object_id,
            keyring_envelope_digest: carrier.keyring_envelope_digest,
            pack_record_count: carrier.pack_record_count,
            record_ordinal: record.record_ordinal,
            record_offset: record.record_offset,
            plaintext_digest: record.plaintext_digest,
        };

        assert_eq!(
            serde_json::to_vec(&shared).expect("serialize shared payload reference"),
            serde_json::to_vec(&legacy).expect("serialize legacy payload reference")
        );
    }

    #[test]
    fn shared_stream_reference_preserves_the_flat_serialized_shape() {
        let carrier = Arc::new(V2StreamCarrierReference {
            commit_key: object_id("commits/stream"),
            commit_version_id: Some(BackendVersionId::new("version-2").expect("version id")),
            body_digest: [0x61; 32],
            commit_stored_len: 65_536,
            keyring_envelope_object_id: object_id("keyrings/stream"),
            keyring_envelope_digest: [0x62; 32],
            payload_section_ordinal: 3,
            payload_section_digest: [0x63; 32],
            payload_id: object_id("payloads/stream"),
            payload_header: Some(super::PayloadHeaderReference {
                chunk_size: 64 * 1024,
                plaintext_len: 123_456,
                key_id: key_id("stream-content"),
                nonce_prefix: [0x64; 16],
                header_len: 96,
            }),
            sections_start: Some(8_192),
            offset: 17,
            length: 123_789,
        });
        let shared = PayloadReference::V2Commit {
            carrier: Arc::clone(&carrier),
        };
        let legacy = LegacyPayloadReference::V2Commit {
            commit_key: &carrier.commit_key,
            commit_version_id: &carrier.commit_version_id,
            body_digest: carrier.body_digest,
            commit_stored_len: carrier.commit_stored_len,
            keyring_envelope_object_id: &carrier.keyring_envelope_object_id,
            keyring_envelope_digest: carrier.keyring_envelope_digest,
            payload_section_ordinal: carrier.payload_section_ordinal,
            payload_section_digest: carrier.payload_section_digest,
            payload_id: &carrier.payload_id,
            payload_header: &carrier.payload_header,
            sections_start: &carrier.sections_start,
            offset: carrier.offset,
            length: carrier.length,
        };

        assert_eq!(
            serde_json::to_vec(&shared).expect("serialize shared stream reference"),
            serde_json::to_vec(&legacy).expect("serialize legacy stream reference")
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
    fn namespace_tombstone_removes_live_entry_from_prefix() {
        let mut index = NamespaceIndex::new();
        let blind_key = blind_key("blind-a");
        let prefix_token = prefix_token("prefix-p");

        index.upsert(
            entry(blind_key.clone(), object_id("segments/opaque-a")),
            vec![prefix_token.clone()],
        );
        index.tombstone(blind_key.clone(), Sequence::new(2));

        assert!(index.head(&blind_key).is_none());
        assert!(index.list_prefix(&prefix_token).is_empty());
        assert_eq!(
            index
                .tombstone_for(&blind_key)
                .map(|tombstone| tombstone.generation),
            Some(Sequence::new(2))
        );
    }

    #[test]
    fn namespace_key_snapshot_restores_entry_prefixes_and_tombstone() {
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
        index.tombstone(blind_key.clone(), Sequence::new(9));
        index.restore_key(snapshot);

        assert_eq!(
            index.head(&blind_key).map(|entry| &entry.object_id),
            Some(&original_object)
        );
        assert_eq!(index.list_prefix(&old_prefix).len(), 1);
        assert!(index.list_prefix(&new_prefix).is_empty());
        assert!(index.tombstone_for(&blind_key).is_none());
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
}
