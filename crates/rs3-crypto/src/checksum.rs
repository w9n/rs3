//! Streaming client checksums and multipart combinations without payload reads.

use crc_fast::{CrcAlgorithm, Digest as CrcDigest};
use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY};
use rs3_types::{ChecksumAlgorithm, ChecksumError, ChecksumType, ObjectChecksum};
use sha2::{Digest, Sha256};

/// Incremental client checksum with bounded state and no exposed backend types.
///
/// These checksums provide S3 compatibility, not repository authentication or
/// object identity. Callers must keep checksum state and outputs out of logs
/// and unencrypted backend metadata.
#[derive(Clone)]
pub struct ChecksumHasher(HasherState);

#[derive(Clone)]
enum HasherState {
    Crc32(CrcDigest),
    Crc64(CrcDigest),
    Sha1(Context),
    Sha256(Sha256),
}

impl ChecksumHasher {
    /// Starts hashing an empty byte stream with the selected algorithm.
    pub fn new(algorithm: ChecksumAlgorithm) -> Self {
        Self(match algorithm {
            ChecksumAlgorithm::Crc32 => {
                HasherState::Crc32(CrcDigest::new(CrcAlgorithm::Crc32IsoHdlc))
            }
            ChecksumAlgorithm::Crc32c => {
                HasherState::Crc32(CrcDigest::new(CrcAlgorithm::Crc32Iscsi))
            }
            ChecksumAlgorithm::Crc64Nvme => {
                HasherState::Crc64(CrcDigest::new(CrcAlgorithm::Crc64Nvme))
            }
            ChecksumAlgorithm::Sha1 => HasherState::Sha1(Context::new(&SHA1_FOR_LEGACY_USE_ONLY)),
            ChecksumAlgorithm::Sha256 => HasherState::Sha256(Sha256::new()),
        })
    }

    /// Appends bytes without framing, separators, or whole-stream buffering.
    pub fn update(&mut self, bytes: &[u8]) {
        match &mut self.0 {
            HasherState::Crc32(state) | HasherState::Crc64(state) => state.update(bytes),
            HasherState::Sha1(state) => state.update(bytes),
            HasherState::Sha256(state) => state.update(bytes),
        }
    }

    /// Consumes the stream and returns raw digest bytes, CRCs in network order.
    pub fn finalize(self) -> Vec<u8> {
        match self.0 {
            HasherState::Crc32(state) => (state.finalize() as u32).to_be_bytes().to_vec(),
            HasherState::Crc64(state) => state.finalize().to_be_bytes().to_vec(),
            HasherState::Sha1(state) => state.finish().as_ref().to_vec(),
            HasherState::Sha256(state) => state.finalize().to_vec(),
        }
    }
}

/// Combines validated raw part digests and plaintext lengths in selected order.
///
/// Full-object CRC combinations use polynomial combination from `crc-fast` and
/// require no plaintext reads. Composite checksums hash the ordered raw part
/// digests; even a single part is hashed again. Full-object SHA combinations and
/// composite CRC64/NVME are unsupported. There must be 1 to 10,000 parts, exactly
/// matching the composite count. Empty parts must carry the empty-stream digest.
///
/// Callers validate each digest against its uploaded bytes and bind part
/// selection, algorithm, and type to the accepted multipart operation.
pub fn combine_part_checksums(
    algorithm: ChecksumAlgorithm,
    kind: ChecksumType,
    parts: &[(&[u8], u64)],
) -> Result<ObjectChecksum, ChecksumError> {
    if !(1..=10_000).contains(&parts.len()) {
        return Err(ChecksumError::InvalidPartCount);
    }
    if let ChecksumType::Composite { parts: count } = kind
        && usize::try_from(count).ok() != Some(parts.len())
    {
        return Err(ChecksumError::InvalidPartCount);
    }
    let empty_digest = ChecksumHasher::new(algorithm).finalize();
    // Validate the algorithm/type pair using the same rules as persisted facts.
    ObjectChecksum::new(algorithm, kind, empty_digest.clone())?;
    let mut total_length = 0_u64;
    for (digest, length) in parts {
        if digest.len() != algorithm.digest_len() {
            return Err(ChecksumError::InvalidDigestLength);
        }
        if *length == 0 && *digest != empty_digest {
            return Err(ChecksumError::InvalidPartLength);
        }
        total_length = total_length
            .checked_add(*length)
            .ok_or(ChecksumError::InvalidPartLength)?;
    }
    let digest = match kind {
        ChecksumType::Composite { .. } => {
            let mut hasher = ChecksumHasher::new(algorithm);
            for (digest, _) in parts {
                hasher.update(digest);
            }
            hasher.finalize()
        }
        ChecksumType::FullObject => {
            let crc_algorithm = match algorithm {
                ChecksumAlgorithm::Crc32 => CrcAlgorithm::Crc32IsoHdlc,
                ChecksumAlgorithm::Crc32c => CrcAlgorithm::Crc32Iscsi,
                ChecksumAlgorithm::Crc64Nvme => CrcAlgorithm::Crc64Nvme,
                ChecksumAlgorithm::Sha1 | ChecksumAlgorithm::Sha256 => {
                    return Err(ChecksumError::UnsupportedType);
                }
            };
            let mut combined = 0;
            for (digest, length) in parts {
                let value = digest
                    .iter()
                    .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
                combined = crc_fast::checksum_combine(crc_algorithm, combined, value, *length);
            }
            let bytes = combined.to_be_bytes();
            bytes[8 - algorithm.digest_len()..].to_vec()
        }
    };
    ObjectChecksum::new(algorithm, kind, digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALGORITHMS: [ChecksumAlgorithm; 5] = [
        ChecksumAlgorithm::Crc32,
        ChecksumAlgorithm::Crc32c,
        ChecksumAlgorithm::Crc64Nvme,
        ChecksumAlgorithm::Sha1,
        ChecksumAlgorithm::Sha256,
    ];

    fn hash(algorithm: ChecksumAlgorithm, bytes: &[u8]) -> Vec<u8> {
        let mut hasher = ChecksumHasher::new(algorithm);
        hasher.update(bytes);
        hasher.finalize()
    }

    #[test]
    fn streaming_matches_independent_known_vectors() {
        // CRC RevEng catalogue check values for ASCII "123456789":
        // https://reveng.sourceforge.io/crc-catalogue/17plus.htm
        // SHA vectors independently reproduced with Python hashlib/OpenSSL.
        let vectors = [
            (ChecksumAlgorithm::Crc32, "cbf43926", "00000000"),
            (ChecksumAlgorithm::Crc32c, "e3069283", "00000000"),
            (
                ChecksumAlgorithm::Crc64Nvme,
                "ae8b14860a799888",
                "0000000000000000",
            ),
            (
                ChecksumAlgorithm::Sha1,
                "f7c3bc1d808e04732adf679965ccc34ca7ae3441",
                "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            ),
            (
                ChecksumAlgorithm::Sha256,
                "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
        ];
        for (algorithm, expected, empty) in vectors {
            assert_eq!(hex::encode(hash(algorithm, b"")), empty);
            for boundary in 0..=9 {
                let mut state = ChecksumHasher::new(algorithm);
                state.update(&b"123456789"[..boundary]);
                state.update(b"");
                state.update(&b"123456789"[boundary..]);
                assert_eq!(hex::encode(state.finalize()), expected);
            }
        }
    }

    #[test]
    fn crc64_nvme_matches_nvm_command_set_codewords() {
        // NVM Command Set 1.0d, section 5.2.1.3.5, 4096-byte codewords:
        // https://reveng.sourceforge.io/crc-catalogue/17plus.htm#crc.cat.crc-64-nvme
        for (bytes, expected) in [
            (vec![0; 4096], "6482d367eb22b64e"),
            (vec![255; 4096], "c0ddba7302eca3ac"),
            ((0..4096).map(|i| i as u8).collect(), "3e729f5f6750449c"),
            (
                (0..4096).map(|i| (4095 - i) as u8).collect(),
                "9a2df64b8e9e517e",
            ),
        ] {
            assert_eq!(
                hex::encode(hash(ChecksumAlgorithm::Crc64Nvme, &bytes)),
                expected
            );
            for boundary in [0, 1, 63, 64, 65, 2048, 4096] {
                let left = hash(ChecksumAlgorithm::Crc64Nvme, &bytes[..boundary]);
                let right = hash(ChecksumAlgorithm::Crc64Nvme, &bytes[boundary..]);
                let combined = combine_part_checksums(
                    ChecksumAlgorithm::Crc64Nvme,
                    ChecksumType::FullObject,
                    &[(&left, boundary as u64), (&right, (4096 - boundary) as u64)],
                )
                .expect("valid combination");
                assert_eq!(hex::encode(combined.digest()), expected);
            }
        }
    }

    #[test]
    fn full_crc_combinations_match_every_partition_and_empty_segments() {
        let input: Vec<u8> = (0..8193).map(|i| (i * 37) as u8).collect();
        for algorithm in &ALGORITHMS[..3] {
            for bytes in [b"123456789".as_slice(), input.as_slice(), b""] {
                let expected = hash(*algorithm, bytes);
                for chunk_len in [1, 7, 63, 64, 65, 127, 128, 129, 1024, 4096, 16_384] {
                    let empty = hash(*algorithm, b"");
                    let digests: Vec<_> = bytes
                        .chunks(chunk_len)
                        .map(|chunk| (hash(*algorithm, chunk), chunk.len() as u64))
                        .collect();
                    let mut parts = vec![(empty.as_slice(), 0)];
                    for (digest, len) in &digests {
                        parts.extend([(digest.as_slice(), *len), (empty.as_slice(), 0)]);
                    }
                    if parts.len() > 10_000 {
                        continue;
                    }
                    let combined =
                        combine_part_checksums(*algorithm, ChecksumType::FullObject, &parts)
                            .expect("valid combination");
                    assert_eq!(combined.digest(), expected);
                }
            }
        }
    }

    #[test]
    fn combination_rejects_invalid_shapes_lengths_and_types() {
        for algorithm in ALGORITHMS {
            let digest = hash(algorithm, b"1234");
            let empty = hash(algorithm, b"");
            let valid_kind = if algorithm == ChecksumAlgorithm::Crc64Nvme {
                ChecksumType::FullObject
            } else {
                ChecksumType::Composite { parts: 1 }
            };
            assert!(combine_part_checksums(algorithm, valid_kind, &[]).is_err());
            assert!(
                combine_part_checksums(algorithm, valid_kind, &vec![(empty.as_slice(), 0); 10_001])
                    .is_err()
            );
            assert!(combine_part_checksums(algorithm, valid_kind, &[(&digest[..1], 4)]).is_err());
            assert!(combine_part_checksums(algorithm, valid_kind, &[(&digest, 0)]).is_err());
            assert!(
                combine_part_checksums(
                    algorithm,
                    ChecksumType::Composite { parts: 2 },
                    &[(&digest, 4)]
                )
                .is_err()
            );
            assert!(
                combine_part_checksums(
                    algorithm,
                    ChecksumType::FullObject,
                    &[(&digest, u64::MAX), (&digest, 1)]
                )
                .is_err()
            );
            if matches!(
                algorithm,
                ChecksumAlgorithm::Sha1 | ChecksumAlgorithm::Sha256
            ) {
                assert_eq!(
                    combine_part_checksums(algorithm, ChecksumType::FullObject, &[(&digest, 4)]),
                    Err(ChecksumError::UnsupportedType)
                );
            }
        }
        let empty = hash(ChecksumAlgorithm::Crc64Nvme, b"");
        assert_eq!(
            combine_part_checksums(
                ChecksumAlgorithm::Crc64Nvme,
                ChecksumType::Composite { parts: 1 },
                &[(&empty, 0)]
            ),
            Err(ChecksumError::UnsupportedType)
        );
    }

    #[test]
    fn composite_matches_aws_published_sha256_example() {
        // AWS tutorial, step 9, decoded Base64 part digests and published result:
        // https://docs.aws.amazon.com/AmazonS3/latest/userguide/tutorial-s3-mpu-additional-checksums.html
        let digests: Vec<_> = [
            "40b97c4788b8f9268996b97c64872eb5ce536d9b70b7637007c9535e4777187d",
            "c42760b352b9066e235844d8c3f0a6198afe9ba3b60dc19fa5c931e4d56892f1",
            "7f9c2c7ec6b96c1fb25eec33a86d41b2df75b989dea860f708289da5be78980a",
        ]
        .iter()
        .map(|digest| hex::decode(digest).expect("published digest"))
        .collect();
        let parts: Vec<_> = digests
            .iter()
            .map(|digest| (digest.as_slice(), 5 * 1024 * 1024 * 1024))
            .collect();
        let checksum = combine_part_checksums(
            ChecksumAlgorithm::Sha256,
            ChecksumType::Composite { parts: 3 },
            &parts,
        )
        .expect("AWS composite");
        assert_eq!(
            hex::encode(checksum.digest()),
            "688f04a24b42768b6353c06ae3a0eb3c2c50086b8670f221279d67a16b3a86f9"
        );
    }

    #[test]
    fn composite_binds_raw_digests_order_and_empty_parts() {
        // SHA and CRC32 independently reproduced with Python hashlib and zlib.
        // CRC32C reproduced with a scalar bitwise 0x82f63b78 reflected polynomial.
        for (algorithm, expected) in [
            (ChecksumAlgorithm::Crc32, "ac133007"),
            (ChecksumAlgorithm::Crc32c, "c0295959"),
            (
                ChecksumAlgorithm::Sha1,
                "64f325cd500fc209b0032d18777b59797431e371",
            ),
            (
                ChecksumAlgorithm::Sha256,
                "6e74410538a57820d54252d3ffa7d9246aea71fdcedd7e86f240fc57bcd9ab14",
            ),
        ] {
            let left = hash(algorithm, b"1234");
            let right = hash(algorithm, b"56789");
            let empty = hash(algorithm, b"");
            let kind = ChecksumType::Composite { parts: 2 };
            let result = combine_part_checksums(algorithm, kind, &[(&left, 4), (&right, 5)])
                .expect("composite");
            assert_eq!(hex::encode(result.digest()), expected);
            let reversed = combine_part_checksums(algorithm, kind, &[(&right, 5), (&left, 4)])
                .expect("reversed");
            assert_ne!(result, reversed);
            let single = combine_part_checksums(
                algorithm,
                ChecksumType::Composite { parts: 1 },
                &[(&left, 4)],
            )
            .expect("single composite");
            assert_eq!(single.digest(), hash(algorithm, &left));
            assert_ne!(single.digest(), left);
            let with_empty = combine_part_checksums(algorithm, kind, &[(&left, 4), (&empty, 0)])
                .expect("empty part composite");
            let mut raw = left.clone();
            raw.extend(&empty);
            assert_eq!(with_empty.digest(), hash(algorithm, &raw));
            assert_ne!(single.digest(), with_empty.digest());
        }
    }
}
