//! Namespace lookup helpers.

use crate::error::Result;
use rs3_crypto::{KeyRing, NamespaceBlindKey};
use rs3_index::{NamespaceEntry, NamespaceIndex};
use rs3_types::{KeyId, PrefixToken};

/// Returns the first matching namespace entry for ordered blind-key candidates.
pub(crate) fn first_namespace_entry<'a>(
    namespace: &'a NamespaceIndex,
    lookup_blind_keys: &[NamespaceBlindKey],
) -> Option<&'a NamespaceEntry> {
    lookup_blind_keys
        .iter()
        .find_map(|candidate| namespace.head(&candidate.blind_key))
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

#[cfg(test)]
mod tests {
    use super::prefix_tokens_for_key;
    use rs3_crypto::{KeyRing, SecretBytes};

    fn secret() -> SecretBytes {
        SecretBytes::new(vec![9; SecretBytes::MIN_LEN]).unwrap_or_else(|error| panic!("{error}"))
    }

    #[test]
    fn prefix_tokens_include_root_and_delimiter_prefixes() {
        let keyring = KeyRing::single_namespace(secret());
        let key_id = keyring
            .primary_namespace_key_id()
            .unwrap_or_else(|error| panic!("{error}"));
        let tokens = prefix_tokens_for_key(&keyring, &key_id, "p/12/abcdef")
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(tokens.len(), 3);
    }
}
