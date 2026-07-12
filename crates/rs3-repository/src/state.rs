//! In-memory trusted repository state.

use crate::error::{RepositoryError, Result};
use crate::model::{RepositoryListEntry, RepositoryObjectMetadata};
use rs3_index::{DurableManifest, IndexDelta, IndexDeltaObject, NamespaceEntry, NamespaceIndex};
use rs3_types::{
    BlindIndexKey, LegalHoldStatus, LogicalPath, ManifestId, PrefixToken, RetentionPolicy, Sequence,
};
use std::collections::BTreeMap;
use std::ops::Bound;

/// Trusted manifest metadata used by the current in-memory query model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TrustedManifest {
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
    /// Trusted namespace query model.
    pub(crate) namespace: NamespaceIndex,
    /// Trusted manifests keyed by opaque manifest ID.
    pub(crate) manifests: BTreeMap<ManifestId, TrustedManifest>,
    /// Trusted list entries keyed by plaintext path inside the trusted boundary.
    pub(crate) list_entries: BTreeMap<LogicalPath, RepositoryListEntry>,
    /// Next logical sequence to allocate.
    pub(crate) next_sequence: Sequence,
    /// Durable index mutations not yet covered by an accepted checkpoint.
    pub(crate) pending_index_deltas: Vec<IndexDelta>,
    /// Stable timestamp for the current unaccepted checkpoint draft.
    pub(crate) pending_checkpoint_published_at_ms: Option<i64>,
}

impl Default for RepositoryState {
    fn default() -> Self {
        Self {
            namespace: NamespaceIndex::new(),
            manifests: BTreeMap::new(),
            list_entries: BTreeMap::new(),
            next_sequence: Sequence::ZERO,
            pending_index_deltas: Vec::new(),
            pending_checkpoint_published_at_ms: None,
        }
    }
}

impl RepositoryState {
    pub(crate) fn upsert_namespace_entry(
        &mut self,
        entry: NamespaceEntry,
        prefix_tokens: Vec<PrefixToken>,
    ) {
        let affected_manifest = self.manifests.get(&entry.manifest_id).cloned();
        self.namespace.upsert(entry, prefix_tokens);
        self.update_list_entry(affected_manifest);
    }

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
        prefix_tokens: Vec<PrefixToken>,
    ) {
        self.namespace.upsert(entry, prefix_tokens);
    }

    pub(crate) fn tombstone_namespace_entry(
        &mut self,
        blind_key: BlindIndexKey,
        generation: Sequence,
    ) {
        let affected_key = self
            .namespace
            .head(&blind_key)
            .and_then(|entry| self.manifests.get(&entry.manifest_id))
            .map(|manifest| manifest.key.clone());
        self.namespace.tombstone(blind_key, generation);
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
            key: self.key,
            content_len: self.content_len,
            modified_at_ms: self.modified_at_ms,
            retention: self.retention,
            legal_hold: self.legal_hold,
        }
    }

    /// Converts durable manifest metadata into trusted manifest metadata.
    pub(crate) fn from_durable(manifest: DurableManifest) -> Self {
        Self {
            key: manifest.key,
            content_len: manifest.content_len,
            modified_at_ms: manifest.modified_at_ms,
            retention: manifest.retention,
            legal_hold: manifest.legal_hold,
        }
    }
}

/// Allocates the next repository sequence.
pub(crate) fn next_sequence(state: &mut RepositoryState) -> Result<Sequence> {
    let next = state
        .next_sequence
        .checked_next()
        .ok_or(RepositoryError::SequenceOverflow)?;
    state.next_sequence = next;
    Ok(next)
}

/// Builds deterministic material for opaque object IDs in the prototype model.
pub(crate) fn object_material(key: &str, sequence: Sequence) -> Vec<u8> {
    format!("{key}\0{}", sequence.get()).into_bytes()
}

/// Applies a durable index delta object to trusted query state.
pub(crate) fn apply_index_delta_object(state: &mut RepositoryState, delta: IndexDeltaObject) {
    for delta in delta.deltas {
        match delta {
            IndexDelta::Upsert {
                entry,
                prefix_tokens,
                sealed_manifest: _,
            } => state.upsert_namespace_entry(*entry, prefix_tokens),
            IndexDelta::Tombstone {
                blind_key,
                generation,
                ..
            } => state.tombstone_namespace_entry(blind_key, generation),
        }
    }

    state.next_sequence = state.next_sequence.max(delta.sequence);
}
