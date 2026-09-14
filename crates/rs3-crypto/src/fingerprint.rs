//! SHA-256 hashing and domain-separated public fingerprints.

use sha2::{Digest, Sha256};

/// Incremental SHA-256 with a fixed-size result and no exposed backend types.
///
/// This hashes exactly the supplied bytes. Callers must retain the framing and
/// domain separation required by their wire format or cache identity.
#[derive(Clone, Default)]
pub struct Sha256Hasher(Sha256);

impl Sha256Hasher {
    /// Starts hashing an empty byte stream.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends bytes to the stream without inserting framing or separators.
    pub fn update(&mut self, bytes: impl AsRef<[u8]>) {
        self.0.update(bytes);
    }

    /// Consumes the stream and returns its digest.
    pub fn finalize(self) -> [u8; 32] {
        self.0.finalize().into()
    }

    /// Hashes one contiguous byte string.
    pub fn digest(bytes: impl AsRef<[u8]>) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }
}

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
    use super::{Sha256Hasher, derive_public_fingerprint};

    #[test]
    fn sha256_matches_known_vectors_across_stream_boundaries() {
        let vectors = [
            (
                Vec::new(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc".to_vec(),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                vec![b'a'; 1_000_000],
                "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
            ),
        ];
        for (input, expected) in vectors {
            assert_eq!(hex::encode(Sha256Hasher::digest(&input)), expected);
            for chunk_size in [1, 63, 64, 65, 65_536] {
                let mut digest = Sha256Hasher::new();
                for chunk in input.chunks(chunk_size) {
                    digest.update([]);
                    digest.update(chunk);
                }
                assert_eq!(hex::encode(digest.finalize()), expected);
            }
        }
    }

    #[test]
    fn sha256_snapshot_preserves_independent_streams() {
        let mut digest = Sha256Hasher::new();
        digest.update(b"a");
        let snapshot = digest.clone();
        digest.update(b"bc");
        assert_eq!(snapshot.finalize(), Sha256Hasher::digest(b"a"));
        assert_eq!(digest.finalize(), Sha256Hasher::digest(b"abc"));
    }

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
