//! Bounded client checksum facts stored inside trusted encrypted metadata.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;

use crate::cbor::{self, Reader};

/// Checksum algorithms supported by the preview S3 compatibility surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChecksumAlgorithm {
    /// CRC-32/ISO-HDLC, encoded most significant byte first.
    Crc32,
    /// CRC-32/ISCSI (Castagnoli), encoded most significant byte first.
    Crc32c,
    /// CRC-64/NVME, encoded most significant byte first.
    Crc64Nvme,
    /// SHA-1 for client compatibility, never repository authentication.
    Sha1,
    /// SHA-256.
    Sha256,
}

impl ChecksumAlgorithm {
    /// Exact number of raw digest bytes for this algorithm.
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Crc32 | Self::Crc32c => 4,
            Self::Crc64Nvme => 8,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }
}

/// Whether a checksum covers object bytes or ordered raw part digests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChecksumType {
    /// Checksum of the complete object byte stream, including ordinary PUTs.
    FullObject,
    /// Checksum of concatenated raw part digests, with the exact part count.
    Composite {
        /// Number of ordered selected parts, from 1 through 10,000 inclusive.
        parts: u32,
    },
}

/// A malformed or unsupported checksum fact, without client data in its error.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ChecksumError {
    /// Encoding is malformed, noncanonical, oversized, or has trailing bytes.
    #[error("invalid checksum encoding")]
    InvalidEncoding,
    /// Digest width does not match its algorithm.
    #[error("invalid checksum digest length")]
    InvalidDigestLength,
    /// Multipart count is out of bounds or disagrees with selected parts.
    #[error("invalid checksum part count")]
    InvalidPartCount,
    /// Algorithm and checksum type cannot be used in this operation.
    #[error("unsupported checksum type")]
    UnsupportedType,
    /// Part lengths overflow or an empty part has a nonempty-stream digest.
    #[error("invalid checksum part length")]
    InvalidPartLength,
}

/// Validated checksum metadata; raw digests must remain inside the trusted boundary.
///
/// Serialization is for encrypted authenticated metadata, not backend metadata,
/// logs, object names, or S3 wire formatting. Deserialization enforces the same
/// bounds as construction and limits digest allocation to 32 bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "DecodedChecksum")]
pub struct ObjectChecksum {
    algorithm: ChecksumAlgorithm,
    kind: ChecksumType,
    digest: Vec<u8>,
}

impl ObjectChecksum {
    /// Maximum encoded size accepted by the preview canonical checksum schema.
    pub const MAX_ENCODED_BYTES: usize = 48;

    /// Validates digest width, composite part count, and algorithm/type support.
    ///
    /// SHA full-object checksums are valid for ordinary PUTs. Multipart callers
    /// must separately reject full-object SHA combinations, which cannot be
    /// computed from part digests alone.
    pub fn new(
        algorithm: ChecksumAlgorithm,
        kind: ChecksumType,
        digest: Vec<u8>,
    ) -> Result<Self, ChecksumError> {
        if digest.len() != algorithm.digest_len() {
            return Err(ChecksumError::InvalidDigestLength);
        }
        if let ChecksumType::Composite { parts } = kind {
            if !(1..=10_000).contains(&parts) {
                return Err(ChecksumError::InvalidPartCount);
            }
            if algorithm == ChecksumAlgorithm::Crc64Nvme {
                return Err(ChecksumError::UnsupportedType);
            }
        }
        Ok(Self {
            algorithm,
            kind,
            digest,
        })
    }

    /// Returns the validated checksum algorithm.
    pub const fn algorithm(&self) -> ChecksumAlgorithm {
        self.algorithm
    }

    /// Returns the checksum type and exact composite count, if present.
    pub const fn kind(&self) -> ChecksumType {
        self.kind
    }

    /// Returns raw digest bytes, without Base64 encoding or a part-count suffix.
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }

    /// Encodes `[algorithm_tag, composite_parts_or_zero, raw_digest]` as canonical CBOR.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::MAX_ENCODED_BYTES);
        cbor::write_array_len(&mut out, 3);
        cbor::write_u64(
            &mut out,
            match self.algorithm {
                ChecksumAlgorithm::Crc32 => 0,
                ChecksumAlgorithm::Crc32c => 1,
                ChecksumAlgorithm::Crc64Nvme => 2,
                ChecksumAlgorithm::Sha1 => 3,
                ChecksumAlgorithm::Sha256 => 4,
            },
        );
        cbor::write_u64(
            &mut out,
            match self.kind {
                ChecksumType::FullObject => 0,
                ChecksumType::Composite { parts } => u64::from(parts),
            },
        );
        cbor::write_bytes(&mut out, &self.digest);
        out
    }

    /// Decodes the exact canonical preview schema with bounded allocation.
    pub fn decode(bytes: &[u8]) -> Result<Self, ChecksumError> {
        if bytes.len() > Self::MAX_ENCODED_BYTES {
            return Err(ChecksumError::InvalidEncoding);
        }
        let mut reader = Reader::new(bytes);
        if reader.read_array_len()? != 3 {
            return Err(ChecksumError::InvalidEncoding);
        }
        let algorithm = match reader.read_u64()? {
            0 => ChecksumAlgorithm::Crc32,
            1 => ChecksumAlgorithm::Crc32c,
            2 => ChecksumAlgorithm::Crc64Nvme,
            3 => ChecksumAlgorithm::Sha1,
            4 => ChecksumAlgorithm::Sha256,
            _ => return Err(ChecksumError::InvalidEncoding),
        };
        let kind = match reader.read_u64()? {
            0 => ChecksumType::FullObject,
            parts => ChecksumType::Composite {
                parts: u32::try_from(parts).map_err(|_| ChecksumError::InvalidPartCount)?,
            },
        };
        let digest = reader.read_bytes_bounded(algorithm.digest_len())?;
        if !reader.is_finished() {
            return Err(ChecksumError::InvalidEncoding);
        }
        Self::new(algorithm, kind, digest)
    }
}

impl From<cbor::CborError> for ChecksumError {
    fn from(_: cbor::CborError) -> Self {
        Self::InvalidEncoding
    }
}

impl fmt::Debug for ObjectChecksum {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectChecksum")
            .field("algorithm", &self.algorithm)
            .field("kind", &self.kind)
            .field("digest", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecodedChecksum {
    algorithm: ChecksumAlgorithm,
    kind: ChecksumType,
    #[serde(deserialize_with = "deserialize_digest")]
    digest: Vec<u8>,
}

impl TryFrom<DecodedChecksum> for ObjectChecksum {
    type Error = ChecksumError;

    fn try_from(value: DecodedChecksum) -> Result<Self, Self::Error> {
        Self::new(value.algorithm, value.kind, value.digest)
    }
}

fn deserialize_digest<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    struct DigestVisitor;
    impl<'de> de::Visitor<'de> for DigestVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("at most 32 raw checksum bytes")
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut sequence: A) -> Result<Vec<u8>, A::Error> {
            let mut digest = Vec::with_capacity(32);
            while let Some(byte) = sequence.next_element::<u8>()? {
                if digest.len() == 32 {
                    return Err(de::Error::custom(ChecksumError::InvalidDigestLength));
                }
                digest.push(byte);
            }
            Ok(digest)
        }
    }
    deserializer.deserialize_seq(DigestVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_digest_widths_and_composite_bounds() {
        for algorithm in [
            ChecksumAlgorithm::Crc32,
            ChecksumAlgorithm::Crc32c,
            ChecksumAlgorithm::Crc64Nvme,
            ChecksumAlgorithm::Sha1,
            ChecksumAlgorithm::Sha256,
        ] {
            for width in 0..=33 {
                assert_eq!(
                    ObjectChecksum::new(algorithm, ChecksumType::FullObject, vec![0; width])
                        .is_ok(),
                    width == algorithm.digest_len()
                );
            }
            for parts in [0, 1, 10_000, 10_001, u32::MAX] {
                assert_eq!(
                    ObjectChecksum::new(
                        algorithm,
                        ChecksumType::Composite { parts },
                        vec![0; algorithm.digest_len()]
                    )
                    .is_ok(),
                    (1..=10_000).contains(&parts) && algorithm != ChecksumAlgorithm::Crc64Nvme
                );
            }
        }
    }

    #[test]
    fn decoded_checksum_cannot_bypass_validation() {
        let malformed = DecodedChecksum {
            algorithm: ChecksumAlgorithm::Crc32,
            kind: ChecksumType::FullObject,
            digest: vec![0; 32],
        };
        assert_eq!(
            ObjectChecksum::try_from(malformed),
            Err(ChecksumError::InvalidDigestLength)
        );
        for len in [0, 4, 8, 20, 32, 33, 1024] {
            let decoder =
                de::value::SeqDeserializer::<_, de::value::Error>::new(vec![0_u8; len].into_iter());
            assert_eq!(deserialize_digest(decoder).is_ok(), len <= 32);
        }
    }

    #[test]
    fn debug_redacts_content_fingerprints() {
        let checksum = ObjectChecksum::new(
            ChecksumAlgorithm::Crc32,
            ChecksumType::FullObject,
            vec![11, 22, 33, 44],
        )
        .expect("valid checksum");
        assert!(format!("{checksum:?}").contains("<redacted>"));
        assert!(!format!("{checksum:?}").contains("11"));
    }

    #[test]
    fn canonical_codec_round_trips_every_supported_type() {
        for algorithm in [
            ChecksumAlgorithm::Crc32,
            ChecksumAlgorithm::Crc32c,
            ChecksumAlgorithm::Crc64Nvme,
            ChecksumAlgorithm::Sha1,
            ChecksumAlgorithm::Sha256,
        ] {
            for kind in [
                ChecksumType::FullObject,
                ChecksumType::Composite { parts: 1 },
                ChecksumType::Composite { parts: 10_000 },
            ] {
                let Ok(checksum) =
                    ObjectChecksum::new(algorithm, kind, vec![42; algorithm.digest_len()])
                else {
                    continue;
                };
                let encoded = checksum.encode();
                assert!(encoded.len() <= ObjectChecksum::MAX_ENCODED_BYTES);
                assert_eq!(ObjectChecksum::decode(&encoded), Ok(checksum));
                for end in 0..encoded.len() {
                    assert!(ObjectChecksum::decode(&encoded[..end]).is_err());
                }
                let mut trailing = encoded;
                trailing.push(0);
                assert!(ObjectChecksum::decode(&trailing).is_err());
            }
        }
    }

    #[test]
    fn canonical_codec_rejects_unknown_nonminimal_and_unbounded_facts() {
        let checksum = ObjectChecksum::new(
            ChecksumAlgorithm::Crc32,
            ChecksumType::FullObject,
            vec![1, 2, 3, 4],
        )
        .expect("checksum");
        assert_eq!(checksum.encode(), [0x83, 0, 0, 0x44, 1, 2, 3, 4]);
        for invalid in [
            vec![0x83, 5, 0, 0x44, 1, 2, 3, 4],
            vec![0x83, 0x18, 0, 0, 0x44, 1, 2, 3, 4],
            vec![0x83, 0, 0x18, 0, 0x44, 1, 2, 3, 4],
            vec![0x83, 0, 0, 0x58, 4, 1, 2, 3, 4],
            vec![0x83, 0, 0, 0x5f, 0xff],
            vec![0x83, 0, 0x19, 0x27, 0x11, 0x44, 1, 2, 3, 4],
            vec![0x83, 2, 1, 0x48, 0, 0, 0, 0, 0, 0, 0, 0],
            vec![0; 49],
        ] {
            assert!(ObjectChecksum::decode(&invalid).is_err());
        }
    }
}
