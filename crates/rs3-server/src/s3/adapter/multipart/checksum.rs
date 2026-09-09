//! Bounded S3 multipart checksum facts, separate from streaming validation.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rs3_repository::{MultipartChecksumKind, MultipartChecksumPolicy};
use rs3_types::{ChecksumAlgorithm, ChecksumType, ObjectChecksum};
use s3s::S3Result;
use s3s::dto::{
    ChecksumType as S3ChecksumType, CompleteMultipartUploadInput, CompletedPart,
    CreateMultipartUploadInput,
};

/// Captures the immutable algorithm and construction before accepting parts.
pub(super) fn creation_policy(
    input: &CreateMultipartUploadInput,
) -> S3Result<MultipartChecksumPolicy> {
    let algorithm = input
        .checksum_algorithm
        .as_ref()
        .map(crate::s3::checksum::parse_algorithm)
        .transpose()
        .map_err(|failure| failure.into_s3_error())?
        .unwrap_or(ChecksumAlgorithm::Crc64Nvme);
    let kind = input
        .checksum_type
        .as_ref()
        .map(parse_kind)
        .transpose()?
        .unwrap_or(if algorithm == ChecksumAlgorithm::Crc64Nvme {
            MultipartChecksumKind::FullObject
        } else {
            MultipartChecksumKind::Composite
        });
    MultipartChecksumPolicy::new(algorithm, kind).map_err(|_| invalid_request())
}

/// Parses one selected part's raw checksum, whose digest always covers part bytes.
pub(super) fn part_checksum(input: &CompletedPart) -> S3Result<Option<ObjectChecksum>> {
    let selected = one_checksum([
        (ChecksumAlgorithm::Crc32, input.checksum_crc32.as_deref()),
        (ChecksumAlgorithm::Crc32c, input.checksum_crc32c.as_deref()),
        (
            ChecksumAlgorithm::Crc64Nvme,
            input.checksum_crc64nvme.as_deref(),
        ),
        (ChecksumAlgorithm::Sha1, input.checksum_sha1.as_deref()),
        (ChecksumAlgorithm::Sha256, input.checksum_sha256.as_deref()),
    ])?;
    selected
        .map(|(algorithm, value)| {
            ObjectChecksum::new(
                algorithm,
                ChecksumType::FullObject,
                decode_digest(algorithm, value)?,
            )
            .map_err(|_| bad_digest())
        })
        .transpose()
}

/// Preserves an explicit completion type even when no final digest is supplied.
///
/// Callers bind this optional fact to the selection digest and validate it
/// against both the active upload policy and an already accepted receipt.
pub(super) fn completion_kind(
    input: &CompleteMultipartUploadInput,
) -> S3Result<Option<MultipartChecksumKind>> {
    input.checksum_type.as_ref().map(parse_kind).transpose()
}

/// Parses an optional final checksum using its explicit type or `-N` suffix.
///
/// A plain Base64 composite digest uses the selected part count. An optional
/// suffix must be canonical decimal and agree with the selection and type.
/// A full-object SHA digest and a
/// composite CRC64/NVME digest are unsupported multipart constructions.
pub(super) fn completion_checksum(
    input: &CompleteMultipartUploadInput,
    selected_count: usize,
) -> S3Result<Option<ObjectChecksum>> {
    if !(1..=10_000).contains(&selected_count) {
        return Err(invalid_request());
    }
    let explicit_kind = completion_kind(input)?;
    let selected = one_checksum([
        (ChecksumAlgorithm::Crc32, input.checksum_crc32.as_deref()),
        (ChecksumAlgorithm::Crc32c, input.checksum_crc32c.as_deref()),
        (
            ChecksumAlgorithm::Crc64Nvme,
            input.checksum_crc64nvme.as_deref(),
        ),
        (ChecksumAlgorithm::Sha1, input.checksum_sha1.as_deref()),
        (ChecksumAlgorithm::Sha256, input.checksum_sha256.as_deref()),
    ])?;
    let Some((algorithm, value)) = selected else {
        return Ok(None);
    };
    // At most 44 Base64 bytes followed by a hyphen and five decimal digits.
    // Bound before scanning or decoding caller-controlled text.
    if value.len() > 50 {
        return Err(bad_digest());
    }
    let (raw, kind, checksum_type) = match value.split_once('-') {
        Some((raw, count)) => {
            if count.is_empty()
                || count.len() > 5
                || count.starts_with('0')
                || !count.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(bad_digest());
            }
            let count: u32 = count.parse().map_err(|_| bad_digest())?;
            if !(1..=10_000).contains(&count) || usize::try_from(count).ok() != Some(selected_count)
            {
                return Err(bad_digest());
            }
            (
                raw,
                MultipartChecksumKind::Composite,
                ChecksumType::Composite { parts: count },
            )
        }
        None if explicit_kind == Some(MultipartChecksumKind::Composite) => (
            value,
            MultipartChecksumKind::Composite,
            ChecksumType::Composite {
                parts: selected_count as u32,
            },
        ),
        None => (
            value,
            MultipartChecksumKind::FullObject,
            ChecksumType::FullObject,
        ),
    };
    if explicit_kind.is_some_and(|explicit| explicit != kind) {
        return Err(bad_digest());
    }
    MultipartChecksumPolicy::new(algorithm, kind).map_err(|_| invalid_request())?;
    ObjectChecksum::new(algorithm, checksum_type, decode_digest(algorithm, raw)?)
        .map(Some)
        .map_err(|_| bad_digest())
}

fn parse_kind(value: &S3ChecksumType) -> S3Result<MultipartChecksumKind> {
    match value.as_str() {
        S3ChecksumType::FULL_OBJECT => Ok(MultipartChecksumKind::FullObject),
        S3ChecksumType::COMPOSITE => Ok(MultipartChecksumKind::Composite),
        _ => Err(invalid_request()),
    }
}

fn one_checksum(
    fields: [(ChecksumAlgorithm, Option<&str>); 5],
) -> S3Result<Option<(ChecksumAlgorithm, &str)>> {
    let mut selected = fields
        .into_iter()
        .filter_map(|(algorithm, value)| value.map(|value| (algorithm, value)));
    let first = selected.next();
    if selected.next().is_some() {
        return Err(invalid_request());
    }
    Ok(first)
}

fn decode_digest(algorithm: ChecksumAlgorithm, value: &str) -> S3Result<Vec<u8>> {
    if value.len() != algorithm.digest_len().div_ceil(3) * 4 {
        return Err(bad_digest());
    }
    let digest = STANDARD.decode(value).map_err(|_| bad_digest())?;
    if digest.len() != algorithm.digest_len() || STANDARD.encode(&digest) != value {
        return Err(bad_digest());
    }
    Ok(digest)
}

fn invalid_request() -> s3s::S3Error {
    s3s::s3_error!(InvalidRequest, "invalid multipart checksum request")
}

fn bad_digest() -> s3s::S3Error {
    s3s::s3_error!(BadDigest, "invalid multipart checksum")
}

#[cfg(test)]
mod tests {
    use super::*;
    use s3s::dto::ChecksumAlgorithm as S3ChecksumAlgorithm;

    fn creation(
        algorithm: Option<&'static str>,
        kind: Option<&'static str>,
    ) -> CreateMultipartUploadInput {
        CreateMultipartUploadInput {
            checksum_algorithm: algorithm.map(S3ChecksumAlgorithm::from_static),
            checksum_type: kind.map(S3ChecksumType::from_static),
            ..Default::default()
        }
    }

    fn part(algorithm: ChecksumAlgorithm, value: String) -> CompletedPart {
        let mut input = CompletedPart::default();
        match algorithm {
            ChecksumAlgorithm::Crc32 => input.checksum_crc32 = Some(value),
            ChecksumAlgorithm::Crc32c => input.checksum_crc32c = Some(value),
            ChecksumAlgorithm::Crc64Nvme => input.checksum_crc64nvme = Some(value),
            ChecksumAlgorithm::Sha1 => input.checksum_sha1 = Some(value),
            ChecksumAlgorithm::Sha256 => input.checksum_sha256 = Some(value),
        }
        input
    }

    fn completion(
        algorithm: ChecksumAlgorithm,
        value: String,
        kind: Option<&'static str>,
    ) -> CompleteMultipartUploadInput {
        let part = part(algorithm, value);
        CompleteMultipartUploadInput {
            checksum_crc32: part.checksum_crc32,
            checksum_crc32c: part.checksum_crc32c,
            checksum_crc64nvme: part.checksum_crc64nvme,
            checksum_sha1: part.checksum_sha1,
            checksum_sha256: part.checksum_sha256,
            checksum_type: kind.map(S3ChecksumType::from_static),
            ..Default::default()
        }
    }

    const ALGORITHMS: [(ChecksumAlgorithm, &str); 5] = [
        (ChecksumAlgorithm::Crc32, S3ChecksumAlgorithm::CRC32),
        (ChecksumAlgorithm::Crc32c, S3ChecksumAlgorithm::CRC32C),
        (ChecksumAlgorithm::Crc64Nvme, S3ChecksumAlgorithm::CRC64NVME),
        (ChecksumAlgorithm::Sha1, S3ChecksumAlgorithm::SHA1),
        (ChecksumAlgorithm::Sha256, S3ChecksumAlgorithm::SHA256),
    ];

    #[test]
    fn creation_defaults_and_explicit_types_match_supported_matrix() {
        let policy = creation_policy(&creation(None, None)).expect("default policy");
        assert_eq!(policy.algorithm(), ChecksumAlgorithm::Crc64Nvme);
        assert_eq!(policy.kind(), MultipartChecksumKind::FullObject);
        for (algorithm, wire) in ALGORITHMS {
            let policy = creation_policy(&creation(Some(wire), None)).expect("algorithm default");
            assert_eq!(policy.algorithm(), algorithm);
            assert_eq!(
                policy.kind(),
                if algorithm == ChecksumAlgorithm::Crc64Nvme {
                    MultipartChecksumKind::FullObject
                } else {
                    MultipartChecksumKind::Composite
                }
            );
            assert_eq!(
                creation_policy(&creation(Some(wire), Some(S3ChecksumType::FULL_OBJECT))).is_ok(),
                !matches!(
                    algorithm,
                    ChecksumAlgorithm::Sha1 | ChecksumAlgorithm::Sha256
                )
            );
            assert_eq!(
                creation_policy(&creation(Some(wire), Some(S3ChecksumType::COMPOSITE))).is_ok(),
                algorithm != ChecksumAlgorithm::Crc64Nvme
            );
        }
        assert!(creation_policy(&creation(Some("SHA512"), None)).is_err());
        assert!(creation_policy(&creation(Some("sha256"), None)).is_err());
        assert!(creation_policy(&creation(None, Some("other"))).is_err());
        assert!(creation_policy(&creation(None, Some(S3ChecksumType::COMPOSITE))).is_err());
    }

    #[test]
    fn part_digest_is_exactly_one_canonical_full_object_value() {
        assert_eq!(
            part_checksum(&CompletedPart::default()).expect("no checksum"),
            None
        );
        for (algorithm, _) in ALGORITHMS {
            let digest = vec![0x77; algorithm.digest_len()];
            let encoded = STANDARD.encode(&digest);
            let parsed = part_checksum(&part(algorithm, encoded.clone()))
                .expect("part checksum")
                .expect("present");
            assert_eq!(parsed.algorithm(), algorithm);
            assert_eq!(parsed.kind(), ChecksumType::FullObject);
            assert_eq!(parsed.digest(), digest);
            for malformed in [
                format!("{encoded}-1"),
                format!(" {encoded}"),
                encoded.trim_end_matches('=').to_owned(),
                "A".repeat(2048),
            ] {
                assert!(part_checksum(&part(algorithm, malformed)).is_err());
            }
        }
        let mut multiple = part(ChecksumAlgorithm::Crc32, "AAAAAA==".to_owned());
        multiple.checksum_sha1 = Some(STANDARD.encode([0; 20]));
        assert!(part_checksum(&multiple).is_err());
        for malformed in ["AAAAAB==", "AAAAAA=", "AAAAAA===", "AAAAAA-_", "AAAAAA\n="] {
            assert!(part_checksum(&part(ChecksumAlgorithm::Crc32, malformed.to_owned())).is_err());
        }
    }

    #[test]
    fn completion_digest_checks_type_suffix_count_and_supported_algorithms() {
        for (algorithm, _) in ALGORITHMS {
            let digest = vec![0x22; algorithm.digest_len()];
            let encoded = STANDARD.encode(&digest);
            let full_supported = !matches!(
                algorithm,
                ChecksumAlgorithm::Sha1 | ChecksumAlgorithm::Sha256
            );
            let composite_supported = algorithm != ChecksumAlgorithm::Crc64Nvme;
            for explicit in [None, Some(S3ChecksumType::FULL_OBJECT)] {
                let result =
                    completion_checksum(&completion(algorithm, encoded.clone(), explicit), 2);
                assert_eq!(result.is_ok(), full_supported);
                if let Ok(Some(checksum)) = result {
                    assert_eq!(checksum.kind(), ChecksumType::FullObject);
                }
            }
            for explicit in [None, Some(S3ChecksumType::COMPOSITE)] {
                let result = completion_checksum(
                    &completion(algorithm, format!("{encoded}-2"), explicit),
                    2,
                );
                assert_eq!(result.is_ok(), composite_supported);
                if let Ok(Some(checksum)) = result {
                    assert_eq!(checksum.kind(), ChecksumType::Composite { parts: 2 });
                }
            }
            assert_eq!(
                completion_checksum(
                    &completion(algorithm, encoded.clone(), Some(S3ChecksumType::COMPOSITE)),
                    2
                )
                .is_ok(),
                composite_supported
            );
            assert!(
                completion_checksum(
                    &completion(
                        algorithm,
                        format!("{encoded}-2"),
                        Some(S3ChecksumType::FULL_OBJECT)
                    ),
                    2
                )
                .is_err()
            );
            for suffix in ["", "0", "01", "+2", "-2", "2-2", "3", "10001", "4294967297"] {
                assert!(
                    completion_checksum(
                        &completion(algorithm, format!("{encoded}-{suffix}"), None),
                        2
                    )
                    .is_err()
                );
            }
        }
        for count in [1, 10_000] {
            assert!(
                completion_checksum(
                    &completion(
                        ChecksumAlgorithm::Crc32,
                        format!("AAAAAA==-{count}"),
                        Some(S3ChecksumType::COMPOSITE)
                    ),
                    count
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn explicit_type_survives_without_final_digest_and_invalid_shape_fails() {
        for (wire, expected) in [
            (
                S3ChecksumType::FULL_OBJECT,
                MultipartChecksumKind::FullObject,
            ),
            (S3ChecksumType::COMPOSITE, MultipartChecksumKind::Composite),
        ] {
            let input = CompleteMultipartUploadInput {
                checksum_type: Some(S3ChecksumType::from_static(wire)),
                ..Default::default()
            };
            assert_eq!(
                completion_checksum(&input, 1).expect("no final checksum"),
                None
            );
            assert_eq!(
                completion_kind(&input).expect("explicit type"),
                Some(expected)
            );
        }
        let input = CompleteMultipartUploadInput::default();
        assert_eq!(completion_kind(&input).expect("no type"), None);
        assert!(completion_checksum(&input, 0).is_err());
        assert!(completion_checksum(&input, 10_001).is_err());
        let mut input = completion(
            ChecksumAlgorithm::Crc32,
            "AAAAAA==".to_owned(),
            Some("other"),
        );
        assert!(completion_checksum(&input, 1).is_err());
        assert!(completion_kind(&input).is_err());
        input.checksum_type = None;
        input.checksum_crc32c = Some("AAAAAA==".to_owned());
        assert!(completion_checksum(&input, 1).is_err());
    }
}
