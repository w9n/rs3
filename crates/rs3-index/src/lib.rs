//! Append-friendly index and checkpoint model.

use rs3_types::{
    BackendObjectId, BlindIndexKey, CheckpointId, KeyDescriptor, KeyId, KeyPurpose, KeyStatus,
    LegalHoldStatus, ManifestId, PrefixToken, RetentionPolicy, Sequence,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Domain separator prepended to canonical checkpoint payload bytes.
pub const CHECKPOINT_RECORD_DOMAIN: &[u8] = b"rs3:checkpoint-record:v1\n";

/// Domain separator prepended to durable checkpoint objects.
pub const CHECKPOINT_OBJECT_DOMAIN: &[u8] = b"rs3:checkpoint-object:v1\n";

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
    /// Sealed metadata record that describes the logical object.
    pub manifest_id: ManifestId,
    /// Logical generation assigned by the repository.
    pub generation: Sequence,
    /// Ciphertext length in bytes.
    pub ciphertext_len: u64,
}

/// A single index mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndexDelta {
    /// Insert or replace a namespace entry for a blind key.
    Upsert {
        /// Namespace entry made visible by the update.
        entry: NamespaceEntry,
        /// Prefix tokens associated with the entry.
        prefix_tokens: Vec<PrefixToken>,
        /// Sealed client-visible metadata needed to replay this entry.
        sealed_manifest: Box<ManifestObject>,
    },
    /// Mark a blind key as deleted at a repository generation.
    Tombstone {
        /// Blind key being tombstoned.
        blind_key: BlindIndexKey,
        /// Generation at which the tombstone was written.
        generation: Sequence,
    },
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

/// Signed checkpoint payload before signature wrapping.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitRecord {
    /// Checkpoint sequence.
    pub sequence: Sequence,
    /// Previous checkpoint, if any.
    pub parent: Option<CheckpointId>,
    /// Referenced durable index delta objects.
    pub index_deltas: Vec<BackendObjectId>,
    /// Sealed index delta embedded directly in this checkpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline_index_delta: Option<SealedIndexDeltaObject>,
    /// Referenced compacted manifest objects.
    pub compacted_manifests: Vec<ManifestId>,
    /// Public keyring metadata active for this checkpoint.
    pub keyring: KeyringSnapshot,
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

        self.entry_prefixes
            .insert(entry.blind_key.clone(), prefix_set);
        self.entries.insert(entry.blind_key.clone(), entry);
    }

    /// Looks up an entry by blind key.
    pub fn head(&self, blind_key: &BlindIndexKey) -> Option<&NamespaceEntry> {
        self.entries.get(blind_key)
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
        CHECKPOINT_OBJECT_DOMAIN, Checkpoint, CommitRecord, INDEX_DELTA_OBJECT_DOMAIN,
        INDEX_DELTA_PLAINTEXT_DOMAIN, IndexDelta, IndexDeltaObject, KeyringSnapshot,
        MANIFEST_PLAINTEXT_DOMAIN, ManifestObject, NamespaceEntry, NamespaceIndex,
        SealedIndexDeltaObject, canonical_commit_record_bytes, checkpoint_object_bytes,
        index_delta_object_bytes, index_delta_plaintext_bytes, manifest_plaintext_bytes,
    };
    use rs3_types::{
        BackendObjectId, BlindIndexKey, CheckpointId, KeyDescriptor, KeyId, KeyPurpose, KeyStatus,
        LogicalPath, ManifestId, PrefixToken, Sequence,
    };

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
            blind_key,
            generation: Sequence::new(7),
        };

        match delta {
            IndexDelta::Tombstone { generation, .. } => {
                assert_eq!(generation, Sequence::new(7));
            }
            IndexDelta::Upsert { .. } => panic!("unexpected upsert"),
        }
    }

    #[test]
    fn commit_record_starts_without_parent() {
        let record = CommitRecord {
            sequence: Sequence::ZERO,
            parent: None,
            index_deltas: Vec::new(),
            inline_index_delta: None,
            compacted_manifests: Vec::new(),
            keyring: KeyringSnapshot::default(),
        };

        assert!(record.parent.is_none());
    }

    #[test]
    fn canonical_commit_record_encoding_is_stable() {
        let unsorted = CommitRecord {
            sequence: Sequence::new(3),
            parent: None,
            index_deltas: vec![object_id("segments/b"), object_id("segments/a")],
            inline_index_delta: None,
            compacted_manifests: vec![manifest_id("manifest-b"), manifest_id("manifest-a")],
            keyring: KeyringSnapshot::new(vec![
                key_descriptor("old", KeyPurpose::Namespace, KeyStatus::Enabled),
                key_descriptor("new", KeyPurpose::Namespace, KeyStatus::Primary),
            ]),
        };
        let sorted = CommitRecord {
            sequence: Sequence::new(3),
            parent: None,
            index_deltas: vec![object_id("segments/a"), object_id("segments/b")],
            inline_index_delta: None,
            compacted_manifests: vec![manifest_id("manifest-a"), manifest_id("manifest-b")],
            keyring: KeyringSnapshot::new(vec![
                key_descriptor("new", KeyPurpose::Namespace, KeyStatus::Primary),
                key_descriptor("old", KeyPurpose::Namespace, KeyStatus::Enabled),
            ]),
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
            parent: None,
            index_deltas: Vec::new(),
            inline_index_delta: None,
            compacted_manifests: Vec::new(),
            keyring: KeyringSnapshot::default(),
        };
        let second = CommitRecord {
            sequence: Sequence::new(2),
            parent: None,
            index_deltas: Vec::new(),
            inline_index_delta: None,
            compacted_manifests: Vec::new(),
            keyring: KeyringSnapshot::default(),
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
                parent: None,
                index_deltas: Vec::new(),
                inline_index_delta: None,
                compacted_manifests: Vec::new(),
                keyring: KeyringSnapshot::default(),
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
                entry: entry(blind_key("blind-a"), object_id("segments/opaque-a")),
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
