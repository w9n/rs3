//! Namespace lookup helpers.

use crate::error::Result;
use rs3_crypto::{KeyRing, NamespaceBlindKey};
use rs3_index::{NamespaceEntry, NamespaceIndex};
use rs3_types::{BlindIndexKey, KeyId, PrefixToken};

/// Returns the first matching namespace entry for ordered blind-key candidates.
pub(crate) fn first_namespace_entry<'a>(
    namespace: &'a NamespaceIndex,
    lookup_blind_keys: &[NamespaceBlindKey],
) -> Option<&'a NamespaceEntry> {
    lookup_blind_keys
        .iter()
        .find_map(|candidate| namespace.head(&candidate.blind_key))
}

/// Returns every existing blind key among lookup candidates.
pub(crate) fn existing_blind_keys(
    namespace: &NamespaceIndex,
    lookup_blind_keys: &[NamespaceBlindKey],
) -> Vec<BlindIndexKey> {
    lookup_blind_keys
        .iter()
        .filter(|candidate| namespace.head(&candidate.blind_key).is_some())
        .map(|candidate| candidate.blind_key.clone())
        .collect()
}

/// Derives all prefix tokens needed to index a client-visible key.
pub(crate) fn prefix_tokens_for_key(
    keyring: &KeyRing,
    key_id: &KeyId,
    key: &str,
) -> Result<Vec<PrefixToken>> {
    let mut tokens = Vec::with_capacity(key.len().saturating_add(1));
    tokens.push(keyring.derive_prefix_token_with_namespace_key(key_id, "")?);

    for boundary in 1..=key.len() {
        if key.is_char_boundary(boundary) {
            tokens.push(keyring.derive_prefix_token_with_namespace_key(key_id, &key[..boundary])?);
        }
    }

    Ok(tokens)
}
