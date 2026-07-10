//! Fuzz-only adapters for backend-controlled v2 parser inputs.

use crate::checkpoint::open_index_delta_object;
use crate::v2::{
    V2_SECTION_FLAG_MUST_UNDERSTAND, V2Algorithms, V2CommitHeader, V2CommitKey, V2CommitKind,
    V2CommitParentRef, V2CommitSelfRef, V2FormatError, V2KeyringEnvelopeRef, V2Result,
    V2SectionDescriptor, V2SectionType, V2UploadMode, body_digest_for_v2_sections,
    digest_v2_section, parse_v2_commit_header, parse_v2_commit_object,
};
use bytes::Bytes;
use rs3_crypto::{KeyMaterial, KeyRing, SecretBytes};
use rs3_index::SealedIndexDeltaObject;
use rs3_types::{BackendObjectId, KeyDescriptor, KeyId, KeyPurpose, KeyStatus, Sequence};

const MAX_FUZZ_INPUT_LEN: usize = 1024 * 1024;

/// Parses a candidate v2 commit header and round-trips successful decodes.
pub fn parse_v2_commit_header_bytes(input: &[u8]) {
    if input.len() > MAX_FUZZ_INPUT_LEN {
        return;
    }

    let keyring = signing_keyring();
    let object_id = commit_object_id();
    let Ok(parsed) = parse_v2_commit_header(&object_id, input, &keyring) else {
        return;
    };

    let encoded = parsed
        .header
        .encode_header_span(parsed.upload_mode)
        .unwrap_or_else(|error| panic!("parsed v2 commit header failed to re-encode: {error}"));
    let reparsed = parse_v2_commit_header(&object_id, &encoded, &keyring)
        .unwrap_or_else(|error| panic!("re-encoded v2 commit header failed to parse: {error}"));

    assert_eq!(reparsed.header, parsed.header);
    assert_eq!(reparsed.upload_mode, parsed.upload_mode);
    assert_eq!(reparsed.header_len, parsed.header_len);
    assert_eq!(reparsed.sections_start, parsed.sections_start);
}

/// Parses a candidate v2 commit object and round-trips successful decodes.
pub fn parse_v2_commit_object_bytes(input: &[u8]) {
    if input.len() > MAX_FUZZ_INPUT_LEN {
        return;
    }

    let keyring = signing_keyring();
    let object_id = commit_object_id();
    let Ok(parsed) = parse_v2_commit_object(&object_id, Bytes::copy_from_slice(input), &keyring)
    else {
        return;
    };

    let section_region = &parsed.body[parsed.parsed_header.sections_start..];
    let encoded = parsed
        .parsed_header
        .header
        .encode_object(parsed.parsed_header.upload_mode, section_region)
        .unwrap_or_else(|error| panic!("parsed v2 commit object failed to re-encode: {error}"));

    assert_eq!(encoded, parsed.body);
}

/// Builds a bounded signed commit from fuzz bytes and exercises the reachable parser path.
pub fn round_trip_v2_commit_structure(input: &[u8]) {
    if input.len() > MAX_FUZZ_INPUT_LEN {
        return;
    }
    let selector = input.first().copied().unwrap_or(0);
    let section_region = input.get(1..).unwrap_or_default();
    let kind = if selector & 1 == 0 {
        V2CommitKind::Root
    } else {
        V2CommitKind::Delta
    };
    let upload_mode = if selector & 2 == 0 {
        V2UploadMode::SinglePut
    } else {
        V2UploadMode::MultipartPadded
    };
    let commit_key = commit_object_key();
    let parent_key = V2CommitKey::from_parts(Sequence::new(41), [0x41; 32])
        .unwrap_or_else(|error| panic!("{error}"));
    let sections = if kind == V2CommitKind::Root {
        vec![V2SectionDescriptor {
            section_type: V2SectionType::IndexSnapshot,
            offset: 0,
            length: section_region.len() as u64,
            flags: V2_SECTION_FLAG_MUST_UNDERSTAND,
            digest: digest_v2_section(section_region),
        }]
    } else {
        let payload_len = section_region.len() / 2;
        vec![
            V2SectionDescriptor {
                section_type: V2SectionType::Payload,
                offset: 0,
                length: payload_len as u64,
                flags: V2_SECTION_FLAG_MUST_UNDERSTAND,
                digest: digest_v2_section(&section_region[..payload_len]),
            },
            V2SectionDescriptor {
                section_type: V2SectionType::IndexDelta,
                offset: payload_len as u64,
                length: (section_region.len() - payload_len) as u64,
                flags: V2_SECTION_FLAG_MUST_UNDERSTAND,
                digest: digest_v2_section(&section_region[payload_len..]),
            },
        ]
    };
    let body_digest = body_digest_for_v2_sections(&sections, section_region)
        .unwrap_or_else(|error| panic!("{error}"));
    let keyring = signing_keyring();
    let header = V2CommitHeader {
        self_ref: V2CommitSelfRef {
            sequence: commit_key.sequence,
            commit_key: commit_key.object_id.clone(),
        },
        parent: (kind == V2CommitKind::Delta).then_some(V2CommitParentRef {
            sequence: parent_key.sequence,
            commit_key: parent_key.object_id,
            body_digest: [0x41; 32],
            version_id: None,
        }),
        publish_time_ms: 0,
        kind,
        algorithms: V2Algorithms::v02(),
        keyring_envelope_ref: V2KeyringEnvelopeRef {
            object_id: object_id("keyrings/fuzz"),
            digest: [0x24; 32],
        },
        section_index: sections,
        body_digest,
        signature: [0; 64],
        signing_key_id: key_id("signing"),
    }
    .sign_with_keyring(&keyring, upload_mode)
    .unwrap_or_else(|error| panic!("{error}"));
    let encoded = header
        .encode_object(upload_mode, section_region)
        .unwrap_or_else(|error| panic!("{error}"));
    let parsed = parse_v2_commit_object(&commit_key.object_id, encoded.clone(), &keyring)
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(parsed.body, encoded);
    assert_eq!(parsed.parsed_header.header, header);
}

/// Decodes one canonical CBOR value with the same primitive reader used by commits.
pub fn decode_canonical_cbor(input: &[u8]) -> V2Result<()> {
    super::cbor::fuzz_decode_one(input).map_err(|_| V2FormatError::MalformedCbor)
}

/// Decodes the sealed index-delta object shape used by v2 commit replay.
pub fn decode_index_delta_object(input: &[u8]) {
    if input.len() > MAX_FUZZ_INPUT_LEN {
        return;
    }

    let Ok(sealed_delta) = serde_json::from_slice::<SealedIndexDeltaObject>(input) else {
        return;
    };
    let _ = open_index_delta_object(&signing_keyring(), &object_id("index/fuzz"), &sealed_delta);
}

fn commit_object_id() -> BackendObjectId {
    commit_object_key().object_id
}

fn commit_object_key() -> V2CommitKey {
    V2CommitKey::from_parts(Sequence::new(42), [0x42; 32]).unwrap_or_else(|error| panic!("{error}"))
}

fn object_id(value: &str) -> BackendObjectId {
    BackendObjectId::new(value).unwrap_or_else(|error| panic!("{error}"))
}

fn key_id(value: &str) -> KeyId {
    KeyId::new(value).unwrap_or_else(|error| panic!("{error}"))
}

fn secret_with_byte(byte: u8) -> SecretBytes {
    SecretBytes::new(vec![byte; SecretBytes::MIN_LEN]).unwrap_or_else(|error| panic!("{error}"))
}

fn key_material(
    value: &str,
    purpose: KeyPurpose,
    status: KeyStatus,
    algorithm: &str,
    secret_byte: u8,
) -> KeyMaterial {
    KeyMaterial::new(
        KeyDescriptor {
            id: key_id(value),
            purpose,
            algorithm: algorithm.to_owned(),
            status,
            created_at_ms: 0,
            not_before_ms: None,
            not_after_ms: None,
            public_key: None,
            external_kms_uri: None,
        },
        secret_with_byte(secret_byte),
    )
}

fn signing_keyring() -> KeyRing {
    KeyRing::new(vec![
        key_material(
            "namespace",
            KeyPurpose::Namespace,
            KeyStatus::Primary,
            "hmac-sha256",
            1,
        ),
        key_material(
            "metadata",
            KeyPurpose::Metadata,
            KeyStatus::Primary,
            "aes-256-gcm-siv-hmac-sha256-nonce-v1",
            2,
        ),
        key_material(
            "signing",
            KeyPurpose::CheckpointSigning,
            KeyStatus::Primary,
            "ed25519",
            3,
        ),
        key_material(
            "content",
            KeyPurpose::Content,
            KeyStatus::Primary,
            "xchacha20poly1305",
            4,
        ),
    ])
    .unwrap_or_else(|error| panic!("{error}"))
}
