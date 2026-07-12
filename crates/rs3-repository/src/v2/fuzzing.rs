//! Fuzz-only adapters for backend-controlled v2 parser inputs.

use crate::checkpoint::open_index_delta_object;
use crate::payload::{
    open_payload_object, parse_segmented_payload_header_with_total_len,
    seal_streamable_payload_object, segmented_ciphertext_span, total_segmented_payload_len,
};
use crate::v2::index_root::{
    decode_v2_index_root_plaintext_for_fuzzing, encode_v2_index_root_plaintext_for_fuzzing,
};
use crate::v2::{
    V2_SECTION_FLAG_MUST_UNDERSTAND, V2Algorithms, V2CommitHeader, V2CommitKey, V2CommitKind,
    V2CommitParentRef, V2CommitSelfRef, V2EmbeddedIndexRunLocation, V2FormatError, V2FormatRef,
    V2IndexRoot, V2IndexRootRunRef, V2KeyringEnvelopeRef, V2PayloadPackFacts, V2PayloadPackId,
    V2PayloadPackRecordContext, V2PayloadPackRecordInput, V2PayloadPackRecordRef, V2Result,
    V2SectionDescriptor, V2SectionType, V2UploadMode, body_digest_for_v2_sections,
    digest_v2_section, open_v2_index_root, open_v2_payload_pack_record, parse_v2_commit_header,
    parse_v2_commit_object, plan_v2_payload_pack_record_range, seal_v2_index_root,
    seal_v2_payload_pack, validate_v2_payload_pack_record_ref,
};
use bytes::Bytes;
use rs3_crypto::{KeyMaterial, KeyRing, SecretBytes};
use rs3_index::run::{
    IndexBlindKey, IndexMutation, IndexPayloadPointer, IndexRun, IndexRunKeyringRef,
    IndexRunLimits, IndexRunStandaloneStreamContainer, IndexTombstone, IndexUpsert,
    decode_index_run, encode_index_run,
};
use rs3_index::{PayloadHeaderReference, SealedIndexDeltaObject};
use rs3_storage::ByteRange;
use rs3_types::{
    BackendObjectId, BackendVersionId, KeyDescriptor, KeyId, KeyPurpose, KeyStatus, LogicalPath,
    Sequence,
};

const MAX_FUZZ_INPUT_LEN: usize = 1024 * 1024;
const MAX_STRUCTURED_PAYLOAD_LEN: usize = 64 * 1024;

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
    let fallback_section_region = [0_u8; 2];
    let section_region = input
        .get(1..)
        .filter(|region| region.len() >= fallback_section_region.len())
        .unwrap_or(&fallback_section_region);
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
    let commit_key = if kind == V2CommitKind::Root {
        V2CommitKey::from_parts(Sequence::new(1), [0x42; 32])
            .unwrap_or_else(|error| panic!("{error}"))
    } else {
        commit_object_key()
    };
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
    } else if selector & 4 == 0 {
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
    } else if selector & 8 == 0 {
        vec![V2SectionDescriptor {
            section_type: V2SectionType::IndexRun,
            offset: 0,
            length: section_region.len() as u64,
            flags: V2_SECTION_FLAG_MUST_UNDERSTAND,
            digest: digest_v2_section(section_region),
        }]
    } else {
        let payload_len = section_region.len() / 2;
        vec![
            V2SectionDescriptor {
                section_type: V2SectionType::PayloadPack,
                offset: 0,
                length: payload_len as u64,
                flags: V2_SECTION_FLAG_MUST_UNDERSTAND,
                digest: digest_v2_section(&section_region[..payload_len]),
            },
            V2SectionDescriptor {
                section_type: V2SectionType::IndexRun,
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

/// Exercises the current v6 plaintext index-run parser with raw and near-valid inputs.
pub fn decode_v6_index_run(input: &[u8]) {
    if input.len() > MAX_FUZZ_INPUT_LEN {
        return;
    }

    let limits = IndexRunLimits::default();
    let _ = decode_index_run(input, &limits);

    let run = standalone_index_run_fixture();
    let encoded = encode_index_run(&run, &limits)
        .unwrap_or_else(|error| panic!("v6 index-run fixture failed to encode: {error}"));
    let decoded = decode_index_run(&encoded, &limits)
        .unwrap_or_else(|error| panic!("encoded v6 index run failed to decode: {error}"));
    assert_eq!(decoded, run);
    exercise_near_valid_bytes(input, &encoded, |candidate| {
        let _ = decode_index_run(candidate, &limits);
    });
}

/// Exercises the authenticated index-root envelope and its current canonical decoder.
pub fn open_v2_index_root_object(input: &[u8]) {
    if input.len() > MAX_FUZZ_INPUT_LEN {
        return;
    }

    let _ = decode_v2_index_root_plaintext_for_fuzzing(input);

    let keyring = signing_keyring();
    let containing_object = object_id("commits/v02/fuzz-index-root");
    let _ = open_v2_index_root(&keyring, b"fuzz-repository", &containing_object, 3, input);

    let root = index_root_fixture();
    let plaintext = encode_v2_index_root_plaintext_for_fuzzing(&root)
        .unwrap_or_else(|error| panic!("index-root fixture failed to encode: {error}"));
    decode_v2_index_root_plaintext_for_fuzzing(&plaintext)
        .unwrap_or_else(|error| panic!("encoded index-root fixture failed to decode: {error}"));
    exercise_near_valid_bytes(input, &plaintext, |candidate| {
        let _ = decode_v2_index_root_plaintext_for_fuzzing(candidate);
    });
    let sealed = seal_v2_index_root(&keyring, b"fuzz-repository", &containing_object, 3, &root)
        .unwrap_or_else(|error| panic!("index-root fixture failed to seal: {error}"));
    let opened = open_v2_index_root(
        &keyring,
        b"fuzz-repository",
        &containing_object,
        3,
        sealed.bytes(),
    )
    .unwrap_or_else(|error| panic!("sealed index-root fixture failed to open: {error}"));
    assert_eq!(opened, root);
    exercise_near_valid_bytes(input, sealed.bytes(), |candidate| {
        let _ = open_v2_index_root(
            &keyring,
            b"fuzz-repository",
            &containing_object,
            3,
            candidate,
        );
    });
}

/// Exercises payload-pack fact validation, exact range planning, and segment AEAD opening.
pub fn open_v2_payload_pack(input: &[u8]) {
    if input.len() > MAX_FUZZ_INPUT_LEN {
        return;
    }

    exercise_raw_payload_pack_facts(input);

    let keyring = signing_keyring();
    let containing_object = object_id("commits/v02/fuzz-payload-pack");
    let plaintext = input.get(..MAX_STRUCTURED_PAYLOAD_LEN).unwrap_or(input);
    let records = [V2PayloadPackRecordInput {
        plaintext: Bytes::copy_from_slice(plaintext),
    }];
    let sealed = seal_v2_payload_pack(
        &keyring,
        b"fuzz-repository",
        &containing_object,
        2,
        &records,
    )
    .unwrap_or_else(|error| panic!("payload-pack fixture failed to seal: {error}"));
    let record = sealed
        .layout()
        .record(0)
        .unwrap_or_else(|| panic!("sealed payload pack omitted its only record"));
    let context = V2PayloadPackRecordContext::new(
        b"fuzz-repository",
        &containing_object,
        2,
        sealed.layout().facts(),
        record.reference(),
        record.plaintext_len(),
    )
    .unwrap_or_else(|error| panic!("payload-pack fixture context was invalid: {error}"));
    let opened = open_v2_payload_pack_record(&keyring, &context, sealed.bytes())
        .unwrap_or_else(|error| panic!("sealed payload-pack fixture failed to open: {error}"));
    assert_eq!(opened.as_ref(), plaintext);
    exercise_near_valid_bytes(input, sealed.bytes(), |candidate| {
        let _ = open_v2_payload_pack_record(&keyring, &context, candidate);
    });
}

/// Exercises both segmented standalone header generations and exact span arithmetic.
pub fn parse_segmented_payload(input: &[u8]) {
    if input.len() > MAX_FUZZ_INPUT_LEN {
        return;
    }

    let object = object_id("objects/v02/fuzz-standalone");
    let total_len = fuzz_u64(input).unwrap_or(input.len() as u64);
    if let Ok(header) = parse_segmented_payload_header_with_total_len(&object, input, total_len) {
        let _ = total_segmented_payload_len(&header);
        let _ = segmented_ciphertext_span(&header, ByteRange::Full);
    }

    let keyring = signing_keyring();
    let plaintext = input.get(..MAX_STRUCTURED_PAYLOAD_LEN).unwrap_or(input);
    let chunk_size = usize::from(input.first().copied().unwrap_or(0))
        .saturating_add(1)
        .min(512);
    let sealed = seal_streamable_payload_object(&keyring, &object, plaintext, chunk_size)
        .unwrap_or_else(|error| panic!("segmented payload fixture failed to seal: {error}"));
    let opened = open_payload_object(&keyring, &object, sealed.clone(), ByteRange::Full)
        .unwrap_or_else(|error| panic!("sealed segmented payload failed to open: {error}"));
    assert_eq!(opened.as_ref(), plaintext);
    exercise_near_valid_bytes(input, &sealed, |candidate| {
        let candidate = Bytes::copy_from_slice(candidate);
        let _ = open_payload_object(&keyring, &object, candidate, ByteRange::Full);
    });
}

fn standalone_index_run_fixture() -> IndexRun {
    let header = payload_header();
    let stored_len = header.header_len
        + header.plaintext_len
        + header.plaintext_len.div_ceil(header.chunk_size) * 16;
    IndexRun {
        sequence: Sequence::new(7),
        self_pack: None,
        self_stream: None,
        containers: Vec::new(),
        stream_containers: Vec::new(),
        standalone_stream_containers: vec![IndexRunStandaloneStreamContainer {
            object_id: object_id("objects/v02/fuzz-standalone"),
            version_id: Some(version_id("fuzz-version")),
            stored_len,
            object_digest: [0x51; 32],
            keyring_envelope: IndexRunKeyringRef {
                object_id: object_id("keyrings/fuzz"),
                digest: [0x52; 32],
            },
            payload_header: header.clone(),
        }],
        mutations: vec![
            IndexMutation::Upsert(IndexUpsert {
                mutation_ordinal: 0,
                blind_key: IndexBlindKey::from_bytes([0x31; 32]),
                namespace_key_id: key_id("namespace"),
                path: logical_path("private/fuzz-object"),
                generation: Sequence::new(6),
                payload: IndexPayloadPointer::ExternalStandaloneStream {
                    container_ordinal: 0,
                },
                content_len: header.plaintext_len,
                modified_at_ms: -1,
                retention: None,
                legal_hold: None,
            }),
            IndexMutation::Tombstone(IndexTombstone {
                mutation_ordinal: 1,
                blind_key: IndexBlindKey::from_bytes([0x32; 32]),
                namespace_key_id: key_id("namespace"),
                path: logical_path("private/deleted"),
                generation: Sequence::new(7),
            }),
        ],
    }
}

fn index_root_fixture() -> V2IndexRoot {
    let keyring_ref = V2KeyringEnvelopeRef {
        object_id: object_id("keyrings/fuzz"),
        digest: [0x61; 32],
    };
    let run = V2IndexRootRunRef {
        run_id: [0x62; 32],
        run_sequence: Sequence::new(7),
        minimum_generation: Sequence::new(6),
        maximum_generation: Sequence::new(7),
        mutation_count: 2,
        frame_count: 3,
        level: 0,
        compaction_generation: 0,
        namespace_bounds: (
            IndexBlindKey::from_bytes([0x31; 32]),
            IndexBlindKey::from_bytes([0x32; 32]),
        ),
        listing_bounds: (
            logical_path("private/deleted"),
            logical_path("private/fuzz-object"),
        ),
        keyring_envelope_ref: keyring_ref.clone(),
        location: V2EmbeddedIndexRunLocation {
            commit_key: object_id("commits/v02/fuzz-run"),
            version_id: Some(version_id("fuzz-version")),
            commit_stored_len: 16_384,
            commit_body_digest: [0x63; 32],
            sections_start: 1_024,
            section_ordinal: 1,
            section_offset: 4_096,
            section_len: 4_096,
            section_digest: [0x64; 32],
        },
    };
    V2IndexRoot::new(
        Sequence::new(7),
        1,
        V2FormatRef {
            generation: 1,
            digest: hex::encode([0x65; 32]),
            object_id: object_id("format/fuzz"),
            version_id: Some(version_id("fuzz-format-version")),
        },
        keyring_ref,
        vec![run],
    )
    .unwrap_or_else(|error| panic!("index-root fixture was invalid: {error}"))
}

fn payload_header() -> PayloadHeaderReference {
    PayloadHeaderReference {
        chunk_size: 512,
        plaintext_len: 1_025,
        key_id: key_id("content"),
        nonce_prefix: [0x41; 16],
        header_len: 73,
    }
}

fn exercise_raw_payload_pack_facts(input: &[u8]) {
    let mut pack_id = [0_u8; 32];
    let copied = input.len().min(pack_id.len());
    pack_id[..copied].copy_from_slice(&input[..copied]);
    let stored_len = fuzz_u32(input.get(32..).unwrap_or_default()).unwrap_or(0);
    let record_count = fuzz_u32(input.get(36..).unwrap_or_default()).unwrap_or(0);
    let Ok(facts) = V2PayloadPackFacts::new(
        V2PayloadPackId::from_bytes(pack_id),
        key_id("content"),
        stored_len,
        record_count,
    ) else {
        return;
    };
    let record = V2PayloadPackRecordRef::new(
        fuzz_u32(input.get(40..).unwrap_or_default()).unwrap_or(0),
        fuzz_u32(input.get(44..).unwrap_or_default()).unwrap_or(0),
    );
    let plaintext_len = fuzz_u64(input.get(48..).unwrap_or_default()).unwrap_or(0);
    let _ = validate_v2_payload_pack_record_ref(&facts, &record, plaintext_len);
    let end = fuzz_u64(input.get(56..).unwrap_or_default()).unwrap_or(0);
    let _ = plan_v2_payload_pack_record_range(&facts, &record, plaintext_len, 0..end);
}

fn exercise_near_valid_bytes(input: &[u8], valid: &[u8], mut exercise: impl FnMut(&[u8])) {
    if valid.is_empty() {
        return;
    }
    let selector = fuzz_u64(input).unwrap_or(0);
    let index = usize::try_from(selector % valid.len() as u64).unwrap_or(0);
    let mut mutated = valid.to_vec();
    mutated[index] ^= input.get(8).copied().unwrap_or(1).max(1);
    exercise(&mutated);

    let truncation = usize::try_from(selector % (valid.len() as u64 + 1)).unwrap_or(0);
    exercise(&valid[..truncation]);
}

fn fuzz_u32(input: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(input.get(..4)?.try_into().ok()?))
}

fn fuzz_u64(input: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(input.get(..8)?.try_into().ok()?))
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

fn version_id(value: &str) -> BackendVersionId {
    BackendVersionId::new(value).unwrap_or_else(|error| panic!("{error}"))
}

fn logical_path(value: &str) -> LogicalPath {
    LogicalPath::new(value).unwrap_or_else(|error| panic!("{error}"))
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
