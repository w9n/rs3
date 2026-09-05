//! Namespace lookup helpers.

use rs3_crypto::NamespaceBlindKey;
use rs3_index::{NamespaceEntry, NamespaceIndex};

/// Returns the first matching namespace entry for ordered blind-key candidates.
pub(crate) fn first_namespace_entry<'a>(
    namespace: &'a NamespaceIndex,
    lookup_blind_keys: &[NamespaceBlindKey],
) -> Option<&'a NamespaceEntry> {
    lookup_blind_keys
        .iter()
        .find_map(|candidate| namespace.head(&candidate.blind_key))
}
