//! In-memory trusted repository state.

use crate::model::{RepositoryListEntry, RepositoryObjectMetadata};
use rs3_index::{
    DurableManifest, NamespaceEntry, NamespaceIndex, V2StandaloneStreamCarrierReference,
};
use rs3_types::{
    BackendObjectId, BackendVersionId, BlindIndexKey, LegalHoldStatus, LogicalPath, ManifestId,
    RetentionPolicy, Sequence,
};
use std::collections::BTreeMap;
use std::ops::Bound;
use std::sync::Arc;

/// Trusted manifest metadata used by the current in-memory query model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TrustedManifest {
    /// Accepted plaintext ETag, kept inside trusted metadata.
    pub(crate) etag: rs3_types::ObjectEtag,
    /// Verified checksum, visible only through authenticated object metadata.
    pub(crate) checksum: Option<rs3_types::ObjectChecksum>,
    /// Client-visible key inside the trusted boundary.
    pub(crate) key: LogicalPath,
    /// Client-visible content length.
    pub(crate) content_len: u64,
    /// Last modification timestamp in milliseconds since the Unix epoch.
    pub(crate) modified_at_ms: i64,
    /// Effective retention policy, if known.
    pub(crate) retention: Option<RetentionPolicy>,
    /// Effective legal-hold status, if known.
    pub(crate) legal_hold: Option<LegalHoldStatus>,
}

/// Mutable repository state guarded by the repository lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RepositoryState {
    /// Accepted bounded multipart results, independent of namespace liveness.
    pub(crate) completion_receipts: rs3_index::completion::CompletionReceipts,
    /// Trusted namespace query model.
    pub(crate) namespace: NamespaceIndex,
    /// Trusted manifests keyed by opaque manifest ID.
    pub(crate) manifests: BTreeMap<ManifestId, TrustedManifest>,
    /// Trusted list entries keyed by plaintext path inside the trusted boundary.
    pub(crate) list_entries: BTreeMap<LogicalPath, RepositoryListEntry>,
    /// Highest applied logical mutation generation.
    pub(crate) next_sequence: Sequence,
    /// Exact standalone carrier facts interned during v2 replay.
    pub(crate) v2_standalone_carriers: BTreeMap<
        (BackendObjectId, Option<BackendVersionId>),
        Arc<V2StandaloneStreamCarrierReference>,
    >,
}

impl Default for RepositoryState {
    fn default() -> Self {
        Self {
            namespace: NamespaceIndex::new(),
            completion_receipts: Default::default(),
            manifests: BTreeMap::new(),
            list_entries: BTreeMap::new(),
            next_sequence: Sequence::ZERO,
            v2_standalone_carriers: BTreeMap::new(),
        }
    }
}

impl RepositoryState {
    /// Inserts an entry for a repository generation whose listing projection
    /// is maintained separately from the legacy prefix-token index.
    pub(crate) fn upsert_namespace_entry_without_prefixes(&mut self, entry: NamespaceEntry) {
        let affected_manifest = self.manifests.get(&entry.manifest_id).cloned();
        self.namespace.upsert_without_prefixes(entry);
        self.update_list_entry(affected_manifest);
    }

    fn update_list_entry(&mut self, affected_manifest: Option<TrustedManifest>) {
        if let Some(manifest) = affected_manifest {
            // A logical path has one live namespace entry. Key rotation first
            // tombstones historical blind keys, so the new entry can update
            // the list projection directly without scanning the repository.
            let key = manifest.key.clone();
            self.list_entries.insert(
                key,
                RepositoryListEntry {
                    etag: manifest.etag,
                    key: manifest.key,
                    content_len: manifest.content_len,
                    modified_at_ms: manifest.modified_at_ms,
                },
            );
        }
    }

    #[cfg(test)]
    pub(crate) fn replace_namespace_entry(
        &mut self,
        entry: NamespaceEntry,
        prefix_tokens: Vec<rs3_types::PrefixToken>,
    ) {
        self.namespace.upsert(entry, prefix_tokens);
    }

    pub(crate) fn remove_namespace_entry(&mut self, blind_key: BlindIndexKey) {
        let affected_key = self
            .namespace
            .head(&blind_key)
            .and_then(|entry| self.manifests.get(&entry.manifest_id))
            .map(|manifest| manifest.key.clone());
        self.namespace.remove(&blind_key);
        if let Some(key) = affected_key {
            self.refresh_list_entry(&key);
        }
    }

    pub(crate) fn list_page(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        limit: usize,
    ) -> Vec<RepositoryListEntry> {
        let page_len = limit.saturating_add(1);
        let lower_bound = match start_after {
            Some(start_after) if start_after >= prefix => Bound::Excluded(start_after),
            _ => Bound::Included(prefix),
        };
        let mut entries = Vec::with_capacity(page_len.min(1024));

        for (key, entry) in self
            .list_entries
            .range::<str, _>((lower_bound, Bound::Unbounded))
        {
            if !key.as_str().starts_with(prefix) {
                break;
            }
            entries.push(entry.clone());
            if entries.len() == page_len {
                break;
            }
        }

        entries
    }

    fn refresh_list_entry(&mut self, key: &LogicalPath) {
        let mut selected = None;
        for entry in self.namespace.live_entries() {
            let Some(manifest) = self.manifests.get(&entry.manifest_id) else {
                continue;
            };
            if manifest.key != *key {
                continue;
            }
            let list_entry = RepositoryListEntry {
                etag: manifest.etag,
                key: manifest.key.clone(),
                content_len: manifest.content_len,
                modified_at_ms: manifest.modified_at_ms,
            };
            if selected
                .as_ref()
                .is_none_or(|selected: &RepositoryListEntry| {
                    list_entry.modified_at_ms >= selected.modified_at_ms
                })
            {
                selected = Some(list_entry);
            }
        }

        match selected {
            Some(entry) => {
                self.list_entries.insert(key.clone(), entry);
            }
            None => {
                self.list_entries.remove(key.as_str());
            }
        }
    }
}

impl TrustedManifest {
    /// Converts trusted manifest metadata into public repository metadata.
    pub(crate) fn into_metadata(self) -> RepositoryObjectMetadata {
        RepositoryObjectMetadata {
            etag: self.etag,
            checksum: self.checksum,
            key: self.key,
            content_len: self.content_len,
            modified_at_ms: self.modified_at_ms,
            retention: self.retention,
            legal_hold: self.legal_hold,
        }
    }

    /// Converts trusted manifest metadata into durable manifest metadata.
    pub(crate) fn into_durable(self) -> DurableManifest {
        DurableManifest {
            etag: self.etag,
            checksum: self.checksum,
            key: self.key,
            content_len: self.content_len,
            modified_at_ms: self.modified_at_ms,
            retention: self.retention,
            legal_hold: self.legal_hold,
        }
    }
}

/// Builds deterministic material for opaque object IDs in the prototype model.
pub(crate) fn object_material(key: &str, sequence: Sequence) -> Vec<u8> {
    format!("{key}\0{}", sequence.get()).into_bytes()
}
