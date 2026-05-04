//! Public, domain-separated fingerprints for non-secret observability values.

use sha2::{Digest, Sha256};

/// Derives a stable SHA-256 fingerprint for public, length-framed fields.
pub fn derive_public_fingerprint(domain: &[u8], fields: &[&[u8]]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update((fields.len() as u64).to_be_bytes());
    for field in fields {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    hex::encode(digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::derive_public_fingerprint;

    #[test]
    fn public_fingerprint_is_stable() {
        let first = derive_public_fingerprint(b"domain", &[b"left", b"right"]);
        let second = derive_public_fingerprint(b"domain", &[b"left", b"right"]);

        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn public_fingerprint_is_domain_separated() {
        let first = derive_public_fingerprint(b"domain-a", &[b"value"]);
        let second = derive_public_fingerprint(b"domain-b", &[b"value"]);

        assert_ne!(first, second);
    }

    #[test]
    fn public_fingerprint_frames_fields() {
        let split = derive_public_fingerprint(b"domain", &[b"ab", b"c"]);
        let joined = derive_public_fingerprint(b"domain", &[b"a", b"bc"]);

        assert_ne!(split, joined);
    }
}
