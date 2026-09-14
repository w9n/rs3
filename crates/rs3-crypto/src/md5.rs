//! MD5 for client compatibility only, never repository authentication.

use ::md5::{Digest, Md5};
use rs3_types::{Md5Digest, ObjectEtag, ObjectEtagError};

/// Bounded plaintext MD5 state used alongside encryption.
#[derive(Default)]
pub struct Md5Hasher(Md5);

impl Md5Hasher {
    /// Starts a fresh digest.
    pub fn new() -> Self {
        Self::default()
    }
    /// Hashes bytes without retaining plaintext.
    pub fn update(&mut self, bytes: impl AsRef<[u8]>) {
        self.0.update(bytes.as_ref());
    }
    /// Returns the digest after the caller has verified complete EOF.
    pub fn finalize(self) -> Md5Digest {
        Md5Digest::from_bytes(self.0.finalize().into())
    }
}

/// Computes MD5 for a bounded plaintext value.
pub fn md5(bytes: impl AsRef<[u8]>) -> Md5Digest {
    let mut hasher = Md5Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

/// Combines selected part MD5s in client order, without payload reads.
pub fn multipart_etag(parts: &[Md5Digest]) -> Result<ObjectEtag, ObjectEtagError> {
    if !(1..=10_000).contains(&parts.len()) {
        return Err(ObjectEtagError::InvalidPartCount);
    }
    let mut hasher = Md5Hasher::new();
    for part in parts {
        hasher.update(part.as_bytes());
    }
    ObjectEtag::multipart(hasher.finalize(), parts.len() as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_1321_vectors_and_stream_partitions() {
        for (input, expected) in [
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("a", "0cc175b9c0f1b6a831c399e269772661"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
        ] {
            assert_eq!(hex::encode(md5(input).as_bytes()), expected);
            for width in 1..=input.len().max(1) {
                let mut hasher = Md5Hasher::new();
                for part in input.as_bytes().chunks(width) {
                    hasher.update(part);
                    hasher.update([]);
                }
                assert_eq!(hasher.finalize(), md5(input));
            }
        }
    }

    #[test]
    fn multipart_vectors_hash_raw_digests_and_preserve_order() {
        for (parts, expected) in [
            (vec![md5("")], "59adb24ef3cdbe0297f05b395827453f-1"),
            (vec![md5("hello")], "62109206880d38a4010a98e11243924a-1"),
            (
                vec![md5("hello"), md5("world")],
                "065947336a2f2a95ba8899f3675c3be6-2",
            ),
        ] {
            assert_eq!(
                multipart_etag(&parts).expect("valid parts").to_s3_string(),
                expected
            );
        }
        assert_ne!(
            multipart_etag(&[md5("hello"), md5("world")]),
            multipart_etag(&[md5("world"), md5("hello")])
        );
        assert!(multipart_etag(&[]).is_err());
        assert!(multipart_etag(&vec![md5(""); 10_001]).is_err());
        assert_eq!(
            multipart_etag(&vec![md5(""); 10_000])
                .expect("maximum parts")
                .part_count(),
            Some(10_000)
        );
    }
}
