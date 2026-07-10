//! Executable repository-format v2 vectors.

use bytes::Bytes;
use rs3_crypto::{KeyMaterial, KeyRing, SecretBytes};
use rs3_repository::v2::{
    V2_HEADER_META_LEN, V2_SECTION_FLAG_MUST_UNDERSTAND, V2Algorithms, V2CommitHeader, V2CommitKey,
    V2CommitParentRef, V2CommitSelfRef, V2ErrorClass, V2FormatError, V2KeyringEnvelopeRef,
    V2SectionDescriptor, V2SectionType, V2UploadMode, body_digest_for_v2_sections,
    parse_v2_commit_object,
};
use rs3_types::{
    BackendObjectId, BackendVersionId, KeyDescriptor, KeyId, KeyPurpose, KeyStatus, Sequence,
};

struct V2VectorFixture {
    keyring: KeyRing,
    commit_key: V2CommitKey,
    header: V2CommitHeader,
    section_region: Bytes,
}

impl V2VectorFixture {
    fn new(upload_mode: V2UploadMode) -> Self {
        let keyring = signing_keyring();
        let commit_key = must_v2(V2CommitKey::from_parts(Sequence::new(42), [0x42; 32]));
        let parent_key = must_v2(V2CommitKey::from_parts(Sequence::new(41), [0x41; 32]));
        let section_region = Bytes::from_static(b"v2-vector-section-bytes");
        let section_index = vec![V2SectionDescriptor {
            section_type: V2SectionType::IndexSnapshot,
            offset: 0,
            length: section_region.len() as u64,
            flags: V2_SECTION_FLAG_MUST_UNDERSTAND,
        }];
        let body_digest = must_v2(body_digest_for_v2_sections(
            &section_index,
            section_region.as_ref(),
        ));
        let header = V2CommitHeader {
            self_ref: V2CommitSelfRef {
                sequence: commit_key.sequence,
                commit_key: commit_key.object_id.clone(),
            },
            parent: Some(V2CommitParentRef {
                sequence: parent_key.sequence,
                commit_key: parent_key.object_id,
                body_digest: [0x41; 32],
                version_id: Some(must_type(BackendVersionId::new("vector-parent-version"))),
            }),
            publish_time_ms: 1_765_000_123_456,
            is_snapshot: true,
            algorithms: V2Algorithms::v02(),
            keyring_envelope_ref: V2KeyringEnvelopeRef {
                object_id: object_id("keyrings/00000000000000000042-vector"),
                digest: [0x24; 32],
            },
            section_index,
            body_digest,
            signature: [0_u8; 64],
            signing_key_id: key_id("signing"),
        };
        let header = must_v2(header.sign_with_keyring(&keyring, upload_mode));

        Self {
            keyring,
            commit_key,
            header,
            section_region,
        }
    }

    fn encode(&self, upload_mode: V2UploadMode) -> Bytes {
        must_v2(
            self.header
                .encode_object(upload_mode, self.section_region.as_ref()),
        )
    }
}

#[test]
fn vector_valid_single_put() {
    let fixture = V2VectorFixture::new(V2UploadMode::SinglePut);
    let body = fixture.encode(V2UploadMode::SinglePut);

    let parsed = must_v2(parse_v2_commit_object(
        &fixture.commit_key.object_id,
        body,
        &fixture.keyring,
    ));

    assert_eq!(parsed.parsed_header.upload_mode, V2UploadMode::SinglePut);
    assert_eq!(
        parsed.parsed_header.sections_start,
        V2_HEADER_META_LEN + parsed.parsed_header.header_len
    );
}

#[test]
fn vector_valid_multipart_padded() {
    let fixture = V2VectorFixture::new(V2UploadMode::MultipartPadded);
    let body = fixture.encode(V2UploadMode::MultipartPadded);

    let parsed = must_v2(parse_v2_commit_object(
        &fixture.commit_key.object_id,
        body,
        &fixture.keyring,
    ));

    assert_eq!(
        parsed.parsed_header.upload_mode,
        V2UploadMode::MultipartPadded
    );
}

#[test]
fn vector_invalid_cases_have_expected_classes() {
    let cases = [
        invalid_case_wrong_object_key(),
        invalid_case_bad_header_digest(),
        invalid_case_bad_signature(),
        invalid_case_bad_body_digest(),
        invalid_case_bad_algorithm(),
        invalid_case_unsupported_capability(),
        invalid_case_reserved_fixed_header(),
    ];

    for case in cases {
        let error = parse_v2_commit_object(&case.object_id, case.body, &case.keyring);
        let error = match error {
            Ok(_) => panic!("invalid vector passed: {}", case.name),
            Err(error) => error,
        };
        assert_eq!(error, case.expected_error, "{}", case.name);
        assert_eq!(error.class(), V2ErrorClass::FailClosedSecurity);
    }
}

struct InvalidVectorCase {
    name: &'static str,
    keyring: KeyRing,
    object_id: BackendObjectId,
    body: Bytes,
    expected_error: V2FormatError,
}

fn invalid_case_wrong_object_key() -> InvalidVectorCase {
    let fixture = V2VectorFixture::new(V2UploadMode::SinglePut);
    let wrong_key = must_v2(V2CommitKey::from_parts(Sequence::new(42), [0x11; 32]));
    let body = fixture.encode(V2UploadMode::SinglePut);
    InvalidVectorCase {
        name: "wrong-object-key",
        keyring: fixture.keyring,
        object_id: wrong_key.object_id,
        body,
        expected_error: V2FormatError::SelfKeyMismatch,
    }
}

fn invalid_case_bad_header_digest() -> InvalidVectorCase {
    let fixture = V2VectorFixture::new(V2UploadMode::SinglePut);
    let mut body = fixture.encode(V2UploadMode::SinglePut).to_vec();
    body[63] ^= 0x01;
    InvalidVectorCase {
        name: "bad-header-digest",
        keyring: fixture.keyring,
        object_id: fixture.commit_key.object_id,
        body: Bytes::from(body),
        expected_error: V2FormatError::HeaderDigestMismatch,
    }
}

fn invalid_case_bad_signature() -> InvalidVectorCase {
    let mut fixture = V2VectorFixture::new(V2UploadMode::SinglePut);
    fixture.header.signature[0] ^= 0x01;
    let body = fixture.encode(V2UploadMode::SinglePut);
    InvalidVectorCase {
        name: "bad-signature",
        keyring: fixture.keyring,
        object_id: fixture.commit_key.object_id,
        body,
        expected_error: V2FormatError::SignatureVerification,
    }
}

fn invalid_case_bad_body_digest() -> InvalidVectorCase {
    let fixture = V2VectorFixture::new(V2UploadMode::SinglePut);
    let mut body = fixture.encode(V2UploadMode::SinglePut).to_vec();
    let last = body.len() - 1;
    body[last] ^= 0x01;
    InvalidVectorCase {
        name: "bad-body-digest",
        keyring: fixture.keyring,
        object_id: fixture.commit_key.object_id,
        body: Bytes::from(body),
        expected_error: V2FormatError::BodyDigestMismatch,
    }
}

fn invalid_case_bad_algorithm() -> InvalidVectorCase {
    let mut fixture = V2VectorFixture::new(V2UploadMode::SinglePut);
    fixture.header.algorithms.digest = "SHA-512".to_owned();
    fixture.header = must_v2(
        fixture
            .header
            .sign_with_keyring(&fixture.keyring, V2UploadMode::SinglePut),
    );
    let body = fixture.encode(V2UploadMode::SinglePut);
    InvalidVectorCase {
        name: "bad-algorithm",
        keyring: fixture.keyring,
        object_id: fixture.commit_key.object_id,
        body,
        expected_error: V2FormatError::InvalidAlgorithms,
    }
}

fn invalid_case_unsupported_capability() -> InvalidVectorCase {
    let fixture = V2VectorFixture::new(V2UploadMode::SinglePut);
    let mut body = fixture.encode(V2UploadMode::SinglePut).to_vec();
    body[23] = 1;
    InvalidVectorCase {
        name: "unsupported-capability",
        keyring: fixture.keyring,
        object_id: fixture.commit_key.object_id,
        body: Bytes::from(body),
        expected_error: V2FormatError::UnsupportedCapabilities,
    }
}

fn invalid_case_reserved_fixed_header() -> InvalidVectorCase {
    let fixture = V2VectorFixture::new(V2UploadMode::SinglePut);
    let mut body = fixture.encode(V2UploadMode::SinglePut).to_vec();
    body[27] = 1;
    InvalidVectorCase {
        name: "reserved-fixed-header",
        keyring: fixture.keyring,
        object_id: fixture.commit_key.object_id,
        body: Bytes::from(body),
        expected_error: V2FormatError::NonzeroReserved,
    }
}

fn signing_keyring() -> KeyRing {
    must_crypto(KeyRing::new(vec![
        key_material(
            "namespace",
            KeyPurpose::Namespace,
            KeyStatus::Primary,
            "hmac-sha256",
            0x01,
        ),
        key_material(
            "signing",
            KeyPurpose::CheckpointSigning,
            KeyStatus::Primary,
            "ed25519",
            0x02,
        ),
    ]))
}

fn key_material(
    id: &str,
    purpose: KeyPurpose,
    status: KeyStatus,
    algorithm: &str,
    byte: u8,
) -> KeyMaterial {
    KeyMaterial::new(
        KeyDescriptor {
            id: key_id(id),
            purpose,
            algorithm: algorithm.to_owned(),
            status,
            created_at_ms: 0,
            not_before_ms: None,
            not_after_ms: None,
            public_key: None,
            external_kms_uri: None,
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

fn must_v2<T>(result: rs3_repository::v2::V2Result<T>) -> T {
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
