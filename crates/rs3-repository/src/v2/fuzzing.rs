//! Fuzz-only adapters for backend-controlled v2 parser inputs.

use crate::checkpoint::open_index_delta_object;
use crate::v2::{
    V2CommitKey, V2FormatError, V2Result, parse_v2_commit_header, parse_v2_commit_object,
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
    V2CommitKey::from_parts(Sequence::new(42), [0x42; 32])
        .unwrap_or_else(|error| panic!("{error}"))
        .object_id
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
