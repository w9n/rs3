//! Namespace lookup helpers.

use crate::error::Result;
use rs3_crypto::{KeyRing, NamespaceBlindKey};
use rs3_index::{NamespaceEntry, NamespaceIndex};
use rs3_types::{BlindIndexKey, KeyId, PrefixToken};

/// Privacy-preserving class of a repository LIST lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IndexedListPrefixMode {
    Root,
    Delimiter,
    Fallback,
}

impl IndexedListPrefixMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Delimiter => "delimiter",
            Self::Fallback => "fallback",
        }
    }
}

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

/// Derives the prefix tokens needed to index delimiter-aligned list prefixes.
pub(crate) fn prefix_tokens_for_key(
    keyring: &KeyRing,
    key_id: &KeyId,
    key: &str,
) -> Result<Vec<PrefixToken>> {
    let mut tokens = Vec::with_capacity(key.bytes().filter(|byte| *byte == b'/').count() + 1);
    tokens.push(keyring.derive_prefix_token_with_namespace_key(key_id, "")?);

    for (index, character) in key.char_indices() {
        if character == '/' {
            let boundary = index + character.len_utf8();
            tokens.push(keyring.derive_prefix_token_with_namespace_key(key_id, &key[..boundary])?);
        }
    }

    Ok(tokens)
}

/// Returns the indexed prefix used to collect trusted LIST candidates.
pub(crate) fn indexed_list_prefix(prefix: &str) -> &str {
    match indexed_list_prefix_mode(prefix) {
        IndexedListPrefixMode::Root | IndexedListPrefixMode::Delimiter => prefix,
        IndexedListPrefixMode::Fallback => "",
    }
}

/// Returns the privacy-preserving LIST lookup mode for tracing.
pub(crate) fn indexed_list_prefix_mode(prefix: &str) -> IndexedListPrefixMode {
    if prefix.is_empty() {
        IndexedListPrefixMode::Root
    } else if prefix.ends_with('/') {
        IndexedListPrefixMode::Delimiter
    } else {
        IndexedListPrefixMode::Fallback
    }
}
