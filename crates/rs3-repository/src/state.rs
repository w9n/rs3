//! In-memory trusted repository state.

use crate::error::{RepositoryError, Result};
use crate::model::RepositoryObjectMetadata;
use rs3_index::{DurableManifest, IndexDelta, IndexDeltaObject, NamespaceIndex};
use rs3_types::{LegalHoldStatus, LogicalPath, ManifestId, RetentionPolicy, Sequence};
use std::collections::BTreeMap;

/// Trusted manifest metadata used by the current in-memory query model.
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
pub(crate) struct RepositoryState {
    /// Trusted namespace query model.
    pub(crate) namespace: NamespaceIndex,
    /// Trusted manifests keyed by opaque manifest ID.
    pub(crate) manifests: BTreeMap<ManifestId, TrustedManifest>,
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
            next_sequence: Sequence::ZERO,
            pending_index_deltas: Vec::new(),
            pending_checkpoint_published_at_ms: None,
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
            } => state.namespace.upsert(*entry, prefix_tokens),
            IndexDelta::Tombstone {
                blind_key,
                generation,
            } => state.namespace.tombstone(blind_key, generation),
        }
    }

    state.next_sequence = state.next_sequence.max(delta.sequence);
}
