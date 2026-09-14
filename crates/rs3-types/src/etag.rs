//! Bounded plaintext ETag facts for encrypted metadata and S3 compatibility.

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Plaintext MD5, never repository authentication or operation identity.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Md5Digest([u8; 16]);

impl Md5Digest {
    /// Reconstructs a fixed-width digest from a trusted result or client input.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    /// Raw bytes for validation, encrypted encoding or client responses.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for Md5Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Md5Digest(<redacted>)")
    }
}

/// Trusted ETag; multipart digests hash ordered raw part MD5 values.
/// Serialization is for encrypted metadata. Diagnostics redact the digest.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "[u8; 20]", into = "[u8; 20]")]
pub struct ObjectEtag {
    digest: Md5Digest,
    parts: u32,
}

/// Invalid ETag data, without client-controlled diagnostic details.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ObjectEtagError {
    /// Canonical encoding must contain exactly twenty bytes.
    #[error("invalid ETag encoding")]
    InvalidEncoding,
    /// Multipart count must be one through ten thousand.
    #[error("invalid ETag part count")]
    InvalidPartCount,
}

impl ObjectEtag {
    /// Exact width of the encrypted metadata encoding.
    pub const ENCODED_BYTES: usize = 20;
    /// Constructs an ordinary PUT ETag from its verified whole-object MD5.
    pub const fn single(digest: Md5Digest) -> Self {
        Self { digest, parts: 0 }
    }
    /// Constructs a multipart ETag from the MD5 of selected raw part digests.
    pub fn multipart(digest: Md5Digest, parts: u32) -> Result<Self, ObjectEtagError> {
        if !(1..=10_000).contains(&parts) {
            return Err(ObjectEtagError::InvalidPartCount);
        }
        Ok(Self { digest, parts })
    }
    /// Verified whole-object or ordered-part aggregate MD5.
    pub const fn digest(self) -> Md5Digest {
        self.digest
    }
    /// Selected multipart count, absent for an ordinary PUT.
    pub const fn part_count(self) -> Option<u32> {
        if self.parts == 0 {
            None
        } else {
            Some(self.parts)
        }
    }
    /// Big-endian count (zero for ordinary PUT), then sixteen raw MD5 bytes.
    pub fn encode(self) -> [u8; Self::ENCODED_BYTES] {
        let mut bytes = [0; Self::ENCODED_BYTES];
        bytes[..4].copy_from_slice(&self.parts.to_be_bytes());
        bytes[4..].copy_from_slice(self.digest.as_bytes());
        bytes
    }
    /// Decodes an exact bounded encoding, refusing truncation and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ObjectEtagError> {
        let bytes: [u8; Self::ENCODED_BYTES] = bytes
            .try_into()
            .map_err(|_| ObjectEtagError::InvalidEncoding)?;
        Self::try_from(bytes)
    }
    /// Formats the unquoted lowercase hex value for a trusted S3 response.
    pub fn to_s3_string(self) -> String {
        let digest = hex::encode(self.digest.as_bytes());
        match self.part_count() {
            Some(parts) => format!("{digest}-{parts}"),
            None => digest,
        }
    }
}

impl fmt::Debug for ObjectEtag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectEtag")
            .field("digest", &"<redacted>")
            .field("parts", &self.part_count())
            .finish()
    }
}

impl TryFrom<[u8; 20]> for ObjectEtag {
    type Error = ObjectEtagError;
    fn try_from(bytes: [u8; 20]) -> Result<Self, Self::Error> {
        let parts = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let mut digest = [0; 16];
        digest.copy_from_slice(&bytes[4..]);
        let digest = Md5Digest::from_bytes(digest);
        if parts == 0 {
            Ok(Self::single(digest))
        } else {
            Self::multipart(digest, parts)
        }
    }
}

impl From<ObjectEtag> for [u8; 20] {
    fn from(value: ObjectEtag) -> Self {
        value.encode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etag_encoding_is_exact_and_bounded() {
        let digest = Md5Digest::from_bytes([0xab; 16]);
        for etag in [
            ObjectEtag::single(digest),
            ObjectEtag::multipart(digest, 1).expect("one part"),
            ObjectEtag::multipart(digest, 10_000).expect("maximum parts"),
        ] {
            assert_eq!(ObjectEtag::decode(&etag.encode()), Ok(etag));
            assert!(ObjectEtag::decode(&etag.encode()[..19]).is_err());
            let mut trailing = etag.encode().to_vec();
            trailing.push(0);
            assert!(ObjectEtag::decode(&trailing).is_err());
            let json = serde_json::to_string(&etag).expect("encode");
            assert_eq!(
                serde_json::from_str::<ObjectEtag>(&json).expect("decode"),
                etag
            );
            assert!(!format!("{etag:?}").contains("abab"));
        }
        assert!(ObjectEtag::multipart(digest, 0).is_err());
        assert!(ObjectEtag::multipart(digest, 10_001).is_err());
        let mut invalid = ObjectEtag::single(digest).encode();
        invalid[..4].copy_from_slice(&10_001_u32.to_be_bytes());
        assert!(ObjectEtag::decode(&invalid).is_err());
        assert!(
            serde_json::from_str::<ObjectEtag>(
                &serde_json::to_string(&invalid).expect("encode invalid")
            )
            .is_err()
        );
    }

    #[test]
    fn one_part_multipart_is_distinct_from_single_put() {
        let digest = Md5Digest::from_bytes([0xab; 16]);
        let single = ObjectEtag::single(digest);
        let multipart = ObjectEtag::multipart(digest, 1).expect("one part");
        assert_ne!(single, multipart);
        assert_eq!(single.to_s3_string(), "abababababababababababababababab");
        assert_eq!(
            multipart.to_s3_string(),
            "abababababababababababababababab-1"
        );
    }
}
