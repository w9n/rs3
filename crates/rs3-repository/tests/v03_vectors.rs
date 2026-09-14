//! Executable repository-format v03 vectors.

use bytes::Bytes;
use rs3_crypto::{KeyMaterial, KeyRing, SecretBytes};
use rs3_repository::v3::{
    V3_HEADER_META_LEN, V3_SECTION_FLAG_MUST_UNDERSTAND, V3Algorithms, V3CommitHeader, V3CommitKey,
    V3CommitKind, V3CommitParentRef, V3CommitSelfRef, V3ErrorClass, V3FormatError,
    V3KeyringEnvelopeRef, V3SectionDescriptor, V3SectionType, body_digest_for_v3_sections,
    digest_v3_section, parse_v3_commit_object,
};
use rs3_types::{
    BackendObjectId, BackendVersionId, KeyDescriptor, KeyId, KeyPurpose, KeyStatus, Sequence,
};

struct CommitVectorFixture {
    keyring: KeyRing,
    commit_key: V3CommitKey,
    header: V3CommitHeader,
    section_region: Bytes,
}

impl CommitVectorFixture {
    fn new() -> Self {
        let keyring = signing_keyring();
        let commit_key = must_v3(V3CommitKey::from_parts(Sequence::new(42), [0x42; 32]));
        let parent_key = must_v3(V3CommitKey::from_parts(Sequence::new(41), [0x41; 32]));
        let section_region = Bytes::from_static(b"v03-vector-section-bytes");
        let section_index = vec![V3SectionDescriptor {
            section_type: V3SectionType::IndexRoot,
            offset: 0,
            length: section_region.len() as u64,
            flags: V3_SECTION_FLAG_MUST_UNDERSTAND,
            digest: digest_v3_section(&section_region),
        }];
        let body_digest = must_v3(body_digest_for_v3_sections(
            &section_index,
            section_region.as_ref(),
        ));
        let header = V3CommitHeader {
            self_ref: V3CommitSelfRef {
                sequence: commit_key.sequence,
                commit_key: commit_key.object_id.clone(),
            },
            parent: Some(V3CommitParentRef {
                sequence: parent_key.sequence,
                commit_key: parent_key.object_id,
                body_digest: [0x41; 32],
                version_id: Some(must_type(BackendVersionId::new("vector-parent-version"))),
            }),
            publish_time_ms: 1_765_000_123_456,
            kind: V3CommitKind::Root,
            algorithms: V3Algorithms::v03(),
            keyring_envelope_ref: V3KeyringEnvelopeRef {
                object_id: object_id("keyrings/00000000000000000042-vector"),
                digest: [0x24; 32],
            },
            section_index,
            body_digest,
            signature: [0_u8; 64],
            signing_key_id: key_id("signing"),
        };
        let header = must_v3(header.sign_with_keyring(&keyring));

        Self {
            keyring,
            commit_key,
            header,
            section_region,
        }
    }

    fn encode(&self) -> Bytes {
        must_v3(self.header.encode_object(self.section_region.as_ref()))
    }
}

#[test]
fn vector_valid_single_put() {
    let fixture = CommitVectorFixture::new();
    let body = fixture.encode();

    let parsed = must_v3(parse_v3_commit_object(
        &fixture.commit_key.object_id,
        body,
        &fixture.keyring,
    ));

    assert_eq!(
        parsed.parsed_header.sections_start,
        V3_HEADER_META_LEN + parsed.parsed_header.header_len
    );
}

#[test]
fn vector_rejects_nonzero_capability() {
    let fixture = CommitVectorFixture::new();
    let mut body = fixture.encode().to_vec();
    body[24] = 1;
    assert!(matches!(
        parse_v3_commit_object(
            &fixture.commit_key.object_id,
            Bytes::from(body),
            &fixture.keyring
        ),
        Err(V3FormatError::UnsupportedCapabilities)
    ));
}

#[test]
fn vector_invalid_cases_have_expected_classes() {
    let cases = [
        invalid_case_wrong_object_key(),
        invalid_case_old_format_version(),
        invalid_case_bad_signature(),
        invalid_case_bad_body_digest(),
        invalid_case_bad_algorithm(),
        invalid_case_old_reader_version(),
        invalid_case_unsupported_capability(),
        invalid_case_reserved_fixed_header(),
    ];

    for case in cases {
        let error = parse_v3_commit_object(&case.object_id, case.body, &case.keyring);
        let error = match error {
            Ok(_) => panic!("invalid vector passed: {}", case.name),
            Err(error) => error,
        };
        assert_eq!(error, case.expected_error, "{}", case.name);
        assert_eq!(error.class(), V3ErrorClass::FailClosedSecurity);
    }
}

struct InvalidVectorCase {
    name: &'static str,
    keyring: KeyRing,
    object_id: BackendObjectId,
    body: Bytes,
    expected_error: V3FormatError,
}

fn invalid_case_wrong_object_key() -> InvalidVectorCase {
    let fixture = CommitVectorFixture::new();
    let wrong_key = must_v3(V3CommitKey::from_parts(Sequence::new(42), [0x11; 32]));
    let body = fixture.encode();
    InvalidVectorCase {
        name: "wrong-object-key",
        keyring: fixture.keyring,
        object_id: wrong_key.object_id,
        body,
        expected_error: V3FormatError::SelfKeyMismatch,
    }
}

fn invalid_case_old_format_version() -> InvalidVectorCase {
    let fixture = CommitVectorFixture::new();
    let mut body = fixture.encode().to_vec();
    body[8..12].copy_from_slice(&2_u32.to_be_bytes());
    InvalidVectorCase {
        name: "old-format-version",
        keyring: fixture.keyring,
        object_id: fixture.commit_key.object_id,
        body: Bytes::from(body),
        expected_error: V3FormatError::UnsupportedFormatVersion,
    }
}

fn invalid_case_bad_signature() -> InvalidVectorCase {
    let mut fixture = CommitVectorFixture::new();
    fixture.header.signature[0] ^= 0x01;
    let body = fixture.encode();
    InvalidVectorCase {
        name: "bad-signature",
        keyring: fixture.keyring,
        object_id: fixture.commit_key.object_id,
        body,
        expected_error: V3FormatError::SignatureVerification,
    }
}

fn invalid_case_bad_body_digest() -> InvalidVectorCase {
    let fixture = CommitVectorFixture::new();
    let mut body = fixture.encode().to_vec();
    let last = body.len() - 1;
    body[last] ^= 0x01;
    InvalidVectorCase {
        name: "bad-section-digest",
        keyring: fixture.keyring,
        object_id: fixture.commit_key.object_id,
        body: Bytes::from(body),
        expected_error: V3FormatError::SectionDigestMismatch,
    }
}

fn invalid_case_bad_algorithm() -> InvalidVectorCase {
    let mut fixture = CommitVectorFixture::new();
    fixture.header.algorithms.digest = "SHA-512".to_owned();
    fixture.header = must_v3(fixture.header.sign_with_keyring(&fixture.keyring));
    let body = fixture.encode();
    InvalidVectorCase {
        name: "bad-algorithm",
        keyring: fixture.keyring,
        object_id: fixture.commit_key.object_id,
        body,
        expected_error: V3FormatError::InvalidAlgorithms,
    }
}

fn invalid_case_unsupported_capability() -> InvalidVectorCase {
    let fixture = CommitVectorFixture::new();
    let mut body = fixture.encode().to_vec();
    body[23] = 0x81;
    InvalidVectorCase {
        name: "unsupported-capability",
        keyring: fixture.keyring,
        object_id: fixture.commit_key.object_id,
        body: Bytes::from(body),
        expected_error: V3FormatError::UnsupportedCapabilities,
    }
}

fn invalid_case_old_reader_version() -> InvalidVectorCase {
    let fixture = CommitVectorFixture::new();
    let mut body = fixture.encode().to_vec();
    body[12..16].copy_from_slice(&2_u32.to_be_bytes());
    InvalidVectorCase {
        name: "old-reader-version",
        keyring: fixture.keyring,
        object_id: fixture.commit_key.object_id,
        body: Bytes::from(body),
        expected_error: V3FormatError::UnsupportedReaderVersion,
    }
}

fn invalid_case_reserved_fixed_header() -> InvalidVectorCase {
    let fixture = CommitVectorFixture::new();
    let mut body = fixture.encode().to_vec();
    body[28] = 1;
    InvalidVectorCase {
        name: "reserved-fixed-header",
        keyring: fixture.keyring,
        object_id: fixture.commit_key.object_id,
        body: Bytes::from(body),
        expected_error: V3FormatError::NonzeroReserved,
    }
}

fn signing_keyring() -> KeyRing {
    must_crypto(KeyRing::new(vec![
        key_material("namespace", KeyPurpose::Namespace, KeyStatus::Primary, 0x01),
        key_material(
            "signing",
            KeyPurpose::CheckpointSigning,
            KeyStatus::Primary,
            0x03,
        ),
    ]))
}

fn key_material(id: &str, purpose: KeyPurpose, status: KeyStatus, byte: u8) -> KeyMaterial {
    KeyMaterial::new(
        KeyDescriptor {
            id: key_id(id),
            purpose,
            status,
            created_at_ms: 0,
            public_key: None,
        },
        secret(byte),
    )
}

fn secret(byte: u8) -> SecretBytes {
    must_crypto(SecretBytes::new(vec![byte; SecretBytes::MIN_LEN]))
}

fn key_id(value: &str) -> KeyId {
    must_type(KeyId::new(value))
}

fn object_id(value: &str) -> BackendObjectId {
    must_type(BackendObjectId::new(value))
}

fn must_v3<T>(result: rs3_repository::v3::V3Result<T>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{error}"),
    }
}

fn must_type<T>(result: rs3_types::Result<T>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{error}"),
    }
}

fn must_crypto<T>(result: std::result::Result<T, rs3_crypto::CryptoError>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{error}"),
    }
}

impl CommitVectorFixture {
    fn shape(shape: u8) -> Self {
        let mut fixture = Self::new();
        let bytes = fixture.section_region.as_ref();
        let descriptor = |section_type, offset: usize, length: usize| V3SectionDescriptor {
            section_type,
            offset: offset as u64,
            length: length as u64,
            flags: V3_SECTION_FLAG_MUST_UNDERSTAND,
            digest: digest_v3_section(&bytes[offset..offset + length]),
        };
        fixture.header.kind = if shape == 0 {
            V3CommitKind::Root
        } else {
            V3CommitKind::Delta
        };
        fixture.header.section_index = match shape {
            0 => vec![descriptor(V3SectionType::IndexRoot, 0, bytes.len())],
            1 => vec![descriptor(V3SectionType::IndexRun, 0, bytes.len())],
            2 => vec![
                descriptor(V3SectionType::PayloadPack, 0, 8),
                descriptor(V3SectionType::IndexRun, 8, bytes.len() - 8),
            ],
            _ => panic!("unknown fixture shape"),
        };
        fixture.header.body_digest = must_v3(body_digest_for_v3_sections(
            &fixture.header.section_index,
            bytes,
        ));
        fixture.header = must_v3(fixture.header.sign_with_keyring(&fixture.keyring));
        fixture
    }
}

#[test]
fn frozen_commit_shapes_verify_and_reject_every_truncation() {
    let vectors = [
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/v03/v03_commit/commit-root.bin"
        ))
        .as_slice(),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/v03/v03_commit/commit-delta.bin"
        ))
        .as_slice(),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/v03/v03_commit/commit-pack.bin"
        ))
        .as_slice(),
    ];
    for (shape, expected) in vectors.into_iter().enumerate() {
        let fixture = CommitVectorFixture::shape(shape as u8);
        assert_eq!(fixture.encode().as_ref(), expected);
        must_v3(parse_v3_commit_object(
            &fixture.commit_key.object_id,
            Bytes::copy_from_slice(expected),
            &fixture.keyring,
        ));
        for length in 0..expected.len() {
            assert!(
                parse_v3_commit_object(
                    &fixture.commit_key.object_id,
                    Bytes::copy_from_slice(&expected[..length]),
                    &fixture.keyring
                )
                .is_err(),
                "shape {shape}, truncation {length}"
            );
        }
        let mut trailing = expected.to_vec();
        trailing.push(0);
        assert!(
            parse_v3_commit_object(
                &fixture.commit_key.object_id,
                Bytes::from(trailing),
                &fixture.keyring
            )
            .is_err()
        );
    }
}
