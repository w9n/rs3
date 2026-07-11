//! Compact authenticated payload packs for bounded v02 commit batches.

use super::{V2FormatError, V2Result};
use bytes::Bytes;
use getrandom::fill as fill_random;
use rs3_crypto::{KeyRing, ct_eq, digest_payload_record};
use rs3_types::{BackendObjectId, KeyId, KeyPurpose};
use std::fmt;
use std::ops::Range;

/// Maximum logical records in one normal v02 payload pack.
pub const V2_PAYLOAD_PACK_MAX_RECORDS: usize = 64;
/// Maximum complete pack bytes accepted by the bounded in-memory codec.
pub const V2_PAYLOAD_PACK_MAX_BYTES: usize = 32 * 1024 * 1024;
/// Maximum encrypted pack-directory header bytes.
pub const V2_PAYLOAD_PACK_MAX_HEADER_BYTES: usize = 64 * 1024;
/// Fixed bytes needed to probe the encrypted pack-directory header length.
pub const V2_PAYLOAD_PACK_FIXED_HEADER_BYTES: usize = PAYLOAD_PACK_FIXED_HEADER_LEN;
/// Canonical maximum independently authenticated plaintext segment size.
pub const V2_PAYLOAD_PACK_SEGMENT_BYTES: usize = 64 * 1024;

const PAYLOAD_PACK_MAGIC: &[u8; 8] = b"rs3:ppk\n";
const PAYLOAD_PACK_VERSION: u16 = 1;
const PAYLOAD_PACK_FIXED_HEADER_LEN: usize = 64;
const PAYLOAD_PACK_DIRECTORY_DOMAIN: &[u8] = b"rs3:payload-pack-directory:v1\n";
const PAYLOAD_PACK_DIRECTORY_AAD_DOMAIN: &[u8] = b"rs3:payload-pack-directory-aad:v1\n";
const PAYLOAD_PACK_SEGMENT_AAD_DOMAIN: &[u8] = b"rs3:payload-pack-segment-aad:v1\n";
const PAYLOAD_PACK_SEGMENT_NONCE_CONTEXT_DOMAIN: &[u8] = b"rs3:payload-pack-segment-context:v1\n";
const PAYLOAD_PACK_ID_LEN: usize = 32;
const METADATA_NONCE_LEN: usize = 12;
const METADATA_TAG_LEN: usize = 16;
const AEAD_TAG_LEN: u64 = 16;
const DIRECTORY_RECORD_LEN: usize = 60;
const MAX_CONTEXT_LEN: usize = 1024;
const MAX_OBJECT_KEY_LEN: usize = 1024;
const MAX_KEY_ID_LEN: usize = 255;

/// One plaintext value and its authenticated range-read segment policy.
#[derive(Clone, PartialEq, Eq)]
pub struct V2PayloadPackRecordInput {
    /// Complete plaintext logical object bytes.
    pub plaintext: Bytes,
}

impl fmt::Debug for V2PayloadPackRecordInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V2PayloadPackRecordInput")
            .field("plaintext_len", &self.plaintext.len())
            .finish()
    }
}

/// Authenticated directory facts for one logical payload-pack record.
#[derive(Clone, PartialEq, Eq)]
pub struct V2PayloadPackRecord {
    /// Logical zero-based record ordinal used by compact index pointers.
    record_ordinal: u32,
    /// Physical ciphertext offset relative to the record region.
    physical_offset: u64,
    /// Complete ciphertext and tag bytes for all record segments.
    stored_len: u64,
    /// Complete plaintext record length.
    plaintext_len: u64,
    /// Plaintext bytes per independently authenticated segment.
    segment_size: u32,
    /// SHA-256 digest over the complete plaintext record.
    plaintext_digest: [u8; 32],
}

impl fmt::Debug for V2PayloadPackRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V2PayloadPackRecord")
            .field("record_ordinal", &self.record_ordinal)
            .field("physical_offset", &self.physical_offset)
            .field("stored_len", &self.stored_len)
            .field("plaintext_len", &self.plaintext_len)
            .field("segment_size", &self.segment_size)
            .field("plaintext_digest", &"<redacted>")
            .finish()
    }
}

impl V2PayloadPackRecord {
    /// Returns the logical record ordinal used by compact index pointers.
    #[must_use]
    pub const fn ordinal(&self) -> u32 {
        self.record_ordinal
    }

    /// Returns the complete ciphertext length of this record.
    #[must_use]
    pub const fn stored_len(&self) -> u64 {
        self.stored_len
    }

    /// Returns the client-visible plaintext length of this record.
    #[must_use]
    pub const fn plaintext_len(&self) -> u64 {
        self.plaintext_len
    }

    /// Returns the canonical independently authenticated segment size.
    #[must_use]
    pub const fn segment_size(&self) -> u32 {
        self.segment_size
    }
}

/// Opened and authenticated payload-pack directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2PayloadPackDirectory {
    pack_id: [u8; PAYLOAD_PACK_ID_LEN],
    content_key_id: KeyId,
    header_len: u64,
    stored_len: u64,
    records: Vec<V2PayloadPackRecord>,
}

impl V2PayloadPackDirectory {
    /// Returns the random pack identity bound into every AEAD operation.
    #[must_use]
    pub const fn pack_id(&self) -> &[u8; PAYLOAD_PACK_ID_LEN] {
        &self.pack_id
    }

    /// Returns the shared content-encryption key identifier.
    #[must_use]
    pub const fn content_key_id(&self) -> &KeyId {
        &self.content_key_id
    }

    /// Returns the byte offset where the physical record region starts.
    #[must_use]
    pub const fn records_start(&self) -> u64 {
        self.header_len
    }

    /// Returns the complete stored pack length.
    #[must_use]
    pub const fn stored_len(&self) -> u64 {
        self.stored_len
    }

    /// Returns directory records in logical ordinal order.
    #[must_use]
    pub fn records(&self) -> &[V2PayloadPackRecord] {
        &self.records
    }

    /// Returns one logical record by ordinal.
    #[must_use]
    pub fn record(&self, ordinal: u32) -> Option<&V2PayloadPackRecord> {
        usize::try_from(ordinal)
            .ok()
            .and_then(|ordinal| self.records.get(ordinal))
    }
}

/// Complete encrypted pack bytes plus its authenticated directory.
#[derive(Clone, PartialEq, Eq)]
pub struct V2SealedPayloadPack {
    directory: V2PayloadPackDirectory,
    bytes: Bytes,
}

impl fmt::Debug for V2SealedPayloadPack {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V2SealedPayloadPack")
            .field("directory", &self.directory)
            .field("stored_len", &self.bytes.len())
            .finish()
    }
}

impl V2SealedPayloadPack {
    /// Returns the directory needed to build compact index pointers.
    #[must_use]
    pub const fn directory(&self) -> &V2PayloadPackDirectory {
        &self.directory
    }

    /// Returns complete stored section bytes.
    #[must_use]
    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// Consumes the pack and returns complete stored section bytes.
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }
}

/// Exact ciphertext span needed for a plaintext range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2PayloadPackRecordSpan {
    /// Absolute offset relative to the payload-pack section start.
    pub offset: u64,
    /// Stored ciphertext bytes in the selected contiguous segment span.
    pub stored_len: u64,
    /// First selected segment ordinal.
    pub start_segment: u32,
    /// Number of selected segments.
    pub segment_count: u32,
    record_ordinal: u32,
    requested: Range<u64>,
}

/// Authenticated plaintext range plus complete plaintext segments for caching.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2OpenedPayloadPackRecordSpan {
    /// Exact client-requested plaintext bytes.
    pub plaintext: Bytes,
    /// Complete authenticated segments, keyed by record-relative ordinal.
    pub segments: Vec<(u32, Bytes)>,
}

#[derive(Clone, Copy)]
struct PayloadPackContext<'a> {
    repository_context: &'a [u8],
    containing_object: &'a BackendObjectId,
    section_ordinal: u32,
}

/// Seals a bounded set of non-empty logical values into one compact pack.
pub fn seal_v2_payload_pack(
    keyring: &KeyRing,
    repository_context: &[u8],
    containing_object: &BackendObjectId,
    section_ordinal: u32,
    records: &[V2PayloadPackRecordInput],
) -> V2Result<V2SealedPayloadPack> {
    let mut pack_id = [0_u8; PAYLOAD_PACK_ID_LEN];
    fill_random(&mut pack_id).map_err(|_| V2FormatError::RandomnessUnavailable)?;
    let order = random_physical_order(records.len())?;
    seal_v2_payload_pack_with_layout(
        keyring,
        repository_context,
        containing_object,
        section_ordinal,
        records,
        pack_id,
        &order,
    )
}

fn seal_v2_payload_pack_with_layout(
    keyring: &KeyRing,
    repository_context: &[u8],
    containing_object: &BackendObjectId,
    section_ordinal: u32,
    inputs: &[V2PayloadPackRecordInput],
    pack_id: [u8; PAYLOAD_PACK_ID_LEN],
    physical_order: &[usize],
) -> V2Result<V2SealedPayloadPack> {
    validate_public_context(repository_context, containing_object)?;
    let context = PayloadPackContext {
        repository_context,
        containing_object,
        section_ordinal,
    };
    if inputs.is_empty() || inputs.len() > V2_PAYLOAD_PACK_MAX_RECORDS {
        return Err(V2FormatError::PayloadPackLimitExceeded);
    }
    validate_physical_order(physical_order, inputs.len())?;

    let content_key_id = keyring.primary_content_key_id()?;
    if content_key_id.as_str().len() > MAX_KEY_ID_LEN {
        return Err(V2FormatError::PayloadPackLimitExceeded);
    }

    let mut records = Vec::with_capacity(inputs.len());
    for (ordinal, input) in inputs.iter().enumerate() {
        if input.plaintext.is_empty() {
            return Err(V2FormatError::InvalidPayloadPack);
        }
        let plaintext_len = u64::try_from(input.plaintext.len())
            .map_err(|_| V2FormatError::PayloadPackLimitExceeded)?;
        let segment_size = u32::try_from(input.plaintext.len().min(V2_PAYLOAD_PACK_SEGMENT_BYTES))
            .map_err(|_| V2FormatError::PayloadPackLimitExceeded)?;
        let segment_count = segment_count(plaintext_len, u64::from(segment_size))?;
        let stored_len = plaintext_len
            .checked_add(
                segment_count
                    .checked_mul(AEAD_TAG_LEN)
                    .ok_or(V2FormatError::PayloadPackLimitExceeded)?,
            )
            .ok_or(V2FormatError::PayloadPackLimitExceeded)?;
        records.push(V2PayloadPackRecord {
            record_ordinal: u32::try_from(ordinal)
                .map_err(|_| V2FormatError::PayloadPackLimitExceeded)?,
            physical_offset: 0,
            stored_len,
            plaintext_len,
            segment_size,
            plaintext_digest: digest_payload_record(&input.plaintext),
        });
    }

    let mut records_len = 0_u64;
    for logical_ordinal in physical_order {
        let record = records
            .get_mut(*logical_ordinal)
            .ok_or(V2FormatError::InvalidPayloadPack)?;
        record.physical_offset = records_len;
        records_len = records_len
            .checked_add(record.stored_len)
            .ok_or(V2FormatError::PayloadPackLimitExceeded)?;
    }
    if usize::try_from(records_len).map_or(true, |len| len > V2_PAYLOAD_PACK_MAX_BYTES) {
        return Err(V2FormatError::PayloadPackLimitExceeded);
    }

    let directory_plaintext = encode_directory(&content_key_id, &records)?;
    let projected_header_len = PAYLOAD_PACK_FIXED_HEADER_LEN
        .checked_add(MAX_KEY_ID_LEN)
        .and_then(|len| len.checked_add(METADATA_NONCE_LEN + METADATA_TAG_LEN))
        .and_then(|len| len.checked_add(directory_plaintext.len()))
        .ok_or(V2FormatError::PayloadPackLimitExceeded)?;
    if projected_header_len > V2_PAYLOAD_PACK_MAX_HEADER_BYTES {
        return Err(V2FormatError::PayloadPackLimitExceeded);
    }

    let metadata_key_id = keyring.primary_key_id(KeyPurpose::Metadata)?;
    if metadata_key_id.as_str().len() > MAX_KEY_ID_LEN {
        return Err(V2FormatError::PayloadPackLimitExceeded);
    }
    let exact_header_len = PAYLOAD_PACK_FIXED_HEADER_LEN
        .checked_add(metadata_key_id.as_str().len())
        .and_then(|len| len.checked_add(METADATA_NONCE_LEN + METADATA_TAG_LEN))
        .and_then(|len| len.checked_add(directory_plaintext.len()))
        .ok_or(V2FormatError::PayloadPackLimitExceeded)?;
    let stored_len = u64::try_from(exact_header_len)
        .map_err(|_| V2FormatError::PayloadPackLimitExceeded)?
        .checked_add(records_len)
        .ok_or(V2FormatError::PayloadPackLimitExceeded)?;
    if usize::try_from(stored_len).map_or(true, |len| len > V2_PAYLOAD_PACK_MAX_BYTES) {
        return Err(V2FormatError::PayloadPackLimitExceeded);
    }

    let directory_aad = directory_associated_data(
        context,
        &pack_id,
        &metadata_key_id,
        stored_len,
        u64::try_from(exact_header_len).map_err(|_| V2FormatError::PayloadPackLimitExceeded)?,
        records_len,
    )?;
    let sealed_directory = keyring.seal_metadata_payload(&directory_aad, &directory_plaintext)?;
    if sealed_directory.key_id != metadata_key_id
        || sealed_directory.nonce.len() != METADATA_NONCE_LEN
        || sealed_directory.tag.len() != METADATA_TAG_LEN
        || sealed_directory.ciphertext.len() != directory_plaintext.len()
    {
        return Err(V2FormatError::CryptoOperation);
    }

    let directory = V2PayloadPackDirectory {
        pack_id,
        content_key_id,
        header_len: u64::try_from(exact_header_len)
            .map_err(|_| V2FormatError::PayloadPackLimitExceeded)?,
        stored_len,
        records,
    };
    let mut stored = Vec::with_capacity(
        usize::try_from(stored_len).map_err(|_| V2FormatError::PayloadPackLimitExceeded)?,
    );
    encode_fixed_header(
        &mut stored,
        &pack_id,
        exact_header_len,
        &metadata_key_id,
        sealed_directory.ciphertext.len(),
        records_len,
    )?;
    stored.extend_from_slice(metadata_key_id.as_str().as_bytes());
    stored.extend_from_slice(&sealed_directory.nonce);
    stored.extend_from_slice(&sealed_directory.tag);
    stored.extend_from_slice(&sealed_directory.ciphertext);
    if stored.len() != exact_header_len {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    stored.resize(
        usize::try_from(stored_len).map_err(|_| V2FormatError::PayloadPackLimitExceeded)?,
        0,
    );
    let record_region = stored
        .get_mut(exact_header_len..)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    for (logical_ordinal, input) in inputs.iter().enumerate() {
        let record = directory
            .records
            .get(logical_ordinal)
            .ok_or(V2FormatError::InvalidPayloadPack)?;
        seal_record_into(
            keyring,
            context,
            &directory,
            record,
            &input.plaintext,
            record_region,
        )?;
    }
    if u64::try_from(stored.len()).ok() != Some(stored_len) {
        return Err(V2FormatError::InvalidPayloadPack);
    }

    Ok(V2SealedPayloadPack {
        directory,
        bytes: Bytes::from(stored),
    })
}

/// Returns the exact header range that must be fetched before opening a pack directory.
pub fn probe_v2_payload_pack_header_len(fixed_header: &[u8]) -> V2Result<u64> {
    Ok(parse_fixed_header(fixed_header)?.header_len)
}

/// Opens and authenticates a payload-pack directory from its exact header bytes.
pub fn open_v2_payload_pack_directory(
    keyring: &KeyRing,
    repository_context: &[u8],
    containing_object: &BackendObjectId,
    section_ordinal: u32,
    header: &[u8],
    total_stored_len: u64,
) -> V2Result<V2PayloadPackDirectory> {
    validate_public_context(repository_context, containing_object)?;
    let context = PayloadPackContext {
        repository_context,
        containing_object,
        section_ordinal,
    };
    let parsed = parse_fixed_header(header)?;
    if parsed.stored_len != total_stored_len
        || usize::try_from(parsed.header_len).ok() != Some(header.len())
        || parsed.header_len > V2_PAYLOAD_PACK_MAX_HEADER_BYTES as u64
        || usize::try_from(parsed.stored_len)
            .map_or(true, |length| length > V2_PAYLOAD_PACK_MAX_BYTES)
    {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    let key_start = PAYLOAD_PACK_FIXED_HEADER_LEN;
    let key_end = key_start
        .checked_add(parsed.metadata_key_id_len)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let nonce_end = key_end
        .checked_add(METADATA_NONCE_LEN)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let tag_end = nonce_end
        .checked_add(METADATA_TAG_LEN)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let ciphertext_end = tag_end
        .checked_add(parsed.directory_ciphertext_len)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    if ciphertext_end != header.len() {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    let key_bytes = header
        .get(key_start..key_end)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let key_text = std::str::from_utf8(key_bytes).map_err(|_| V2FormatError::InvalidPayloadPack)?;
    let metadata_key_id = KeyId::new(key_text.to_owned())?;
    let nonce = header
        .get(key_end..nonce_end)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let tag = header
        .get(nonce_end..tag_end)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let ciphertext = header
        .get(tag_end..ciphertext_end)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let aad = directory_associated_data(
        context,
        &parsed.pack_id,
        &metadata_key_id,
        parsed.stored_len,
        parsed.header_len,
        parsed.records_len,
    )?;
    let plaintext =
        keyring.open_metadata_payload(&metadata_key_id, &aad, nonce, ciphertext, tag)?;
    let (content_key_id, records) = decode_directory(&plaintext, parsed.records_len)?;
    Ok(V2PayloadPackDirectory {
        pack_id: parsed.pack_id,
        content_key_id,
        header_len: parsed.header_len,
        stored_len: parsed.stored_len,
        records,
    })
}

/// Opens a directory from a complete stored payload pack.
pub fn open_v2_payload_pack(
    keyring: &KeyRing,
    repository_context: &[u8],
    containing_object: &BackendObjectId,
    section_ordinal: u32,
    pack: &[u8],
) -> V2Result<V2PayloadPackDirectory> {
    let header_len = probe_v2_payload_pack_header_len(pack)?;
    let header_len = usize::try_from(header_len).map_err(|_| V2FormatError::InvalidPayloadPack)?;
    let header = pack.get(..header_len).ok_or(V2FormatError::TruncatedBody)?;
    let stored_len =
        u64::try_from(pack.len()).map_err(|_| V2FormatError::PayloadPackLimitExceeded)?;
    open_v2_payload_pack_directory(
        keyring,
        repository_context,
        containing_object,
        section_ordinal,
        header,
        stored_len,
    )
}

/// Plans the single contiguous ciphertext range needed for a plaintext range.
pub fn plan_v2_payload_pack_record_range(
    directory: &V2PayloadPackDirectory,
    record_ordinal: u32,
    requested: Range<u64>,
) -> V2Result<V2PayloadPackRecordSpan> {
    let record = directory
        .record(record_ordinal)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    if requested.start >= requested.end || requested.end > record.plaintext_len {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    let segment_size = u64::from(record.segment_size);
    let start_segment = requested.start / segment_size;
    let end_segment = requested
        .end
        .checked_sub(1)
        .ok_or(V2FormatError::InvalidPayloadPack)?
        / segment_size;
    let segment_count = end_segment
        .checked_sub(start_segment)
        .and_then(|count| count.checked_add(1))
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let relative_start = segment_ciphertext_offset(start_segment, segment_size)?;
    let last_plaintext_len = segment_plaintext_len(record, end_segment)?;
    let relative_end = segment_ciphertext_offset(end_segment, segment_size)?
        .checked_add(last_plaintext_len)
        .and_then(|end| end.checked_add(AEAD_TAG_LEN))
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let offset = directory
        .header_len
        .checked_add(record.physical_offset)
        .and_then(|offset| offset.checked_add(relative_start))
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    Ok(V2PayloadPackRecordSpan {
        offset,
        stored_len: relative_end
            .checked_sub(relative_start)
            .ok_or(V2FormatError::InvalidPayloadPack)?,
        start_segment: u32::try_from(start_segment)
            .map_err(|_| V2FormatError::InvalidPayloadPack)?,
        segment_count: u32::try_from(segment_count)
            .map_err(|_| V2FormatError::InvalidPayloadPack)?,
        record_ordinal,
        requested,
    })
}

/// Authenticates and opens an exact planned ciphertext span.
pub fn open_v2_payload_pack_record_span(
    keyring: &KeyRing,
    repository_context: &[u8],
    containing_object: &BackendObjectId,
    section_ordinal: u32,
    directory: &V2PayloadPackDirectory,
    span: &V2PayloadPackRecordSpan,
    ciphertext_span: &[u8],
) -> V2Result<Bytes> {
    open_v2_payload_pack_record_span_with_segments(
        keyring,
        repository_context,
        containing_object,
        section_ordinal,
        directory,
        span,
        ciphertext_span,
    )
    .map(|opened| opened.plaintext)
}

/// Authenticates an exact ciphertext span and retains complete plaintext
/// segments so callers can populate a bounded decrypted-segment cache.
pub fn open_v2_payload_pack_record_span_with_segments(
    keyring: &KeyRing,
    repository_context: &[u8],
    containing_object: &BackendObjectId,
    section_ordinal: u32,
    directory: &V2PayloadPackDirectory,
    span: &V2PayloadPackRecordSpan,
    ciphertext_span: &[u8],
) -> V2Result<V2OpenedPayloadPackRecordSpan> {
    validate_public_context(repository_context, containing_object)?;
    let context = PayloadPackContext {
        repository_context,
        containing_object,
        section_ordinal,
    };
    let expected =
        plan_v2_payload_pack_record_range(directory, span.record_ordinal, span.requested.clone())?;
    if &expected != span || usize::try_from(span.stored_len).ok() != Some(ciphertext_span.len()) {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    let record = directory
        .record(span.record_ordinal)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let start_segment = u64::from(span.start_segment);
    let segment_count = u64::from(span.segment_count);
    let mut cursor = 0_usize;
    let mut selected_plaintext = Vec::new();
    let mut segments = Vec::with_capacity(
        usize::try_from(segment_count).map_err(|_| V2FormatError::InvalidPayloadPack)?,
    );
    for relative_segment in 0..segment_count {
        let segment_ordinal = start_segment
            .checked_add(relative_segment)
            .ok_or(V2FormatError::InvalidPayloadPack)?;
        let plaintext_len = segment_plaintext_len(record, segment_ordinal)?;
        let stored_len = plaintext_len
            .checked_add(AEAD_TAG_LEN)
            .ok_or(V2FormatError::InvalidPayloadPack)?;
        let stored_len =
            usize::try_from(stored_len).map_err(|_| V2FormatError::InvalidPayloadPack)?;
        let end = cursor
            .checked_add(stored_len)
            .ok_or(V2FormatError::InvalidPayloadPack)?;
        let ciphertext = ciphertext_span
            .get(cursor..end)
            .ok_or(V2FormatError::TruncatedBody)?;
        let aad =
            segment_associated_data(context, directory, record, segment_ordinal, plaintext_len)?;
        let nonce_context =
            segment_nonce_context(directory.pack_id(), record.record_ordinal, segment_ordinal);
        let plaintext = keyring.open_payload_pack_segment(
            directory.content_key_id(),
            &aad,
            &nonce_context,
            &record.plaintext_digest,
            ciphertext,
        )?;
        if u64::try_from(plaintext.len()).ok() != Some(plaintext_len) {
            return Err(V2FormatError::InvalidPayloadPack);
        }
        selected_plaintext.extend_from_slice(&plaintext);
        segments.push((
            u32::try_from(segment_ordinal).map_err(|_| V2FormatError::InvalidPayloadPack)?,
            Bytes::from(plaintext),
        ));
        cursor = end;
    }
    if cursor != ciphertext_span.len() {
        return Err(V2FormatError::InvalidPayloadPack);
    }

    let selected_plaintext_start = start_segment
        .checked_mul(u64::from(record.segment_size))
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let trim_start = span
        .requested
        .start
        .checked_sub(selected_plaintext_start)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let requested_len = span
        .requested
        .end
        .checked_sub(span.requested.start)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let trim_end = trim_start
        .checked_add(requested_len)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let trim_start = usize::try_from(trim_start).map_err(|_| V2FormatError::InvalidPayloadPack)?;
    let trim_end = usize::try_from(trim_end).map_err(|_| V2FormatError::InvalidPayloadPack)?;
    if span.requested.start == 0 && span.requested.end == record.plaintext_len {
        let digest = digest_payload_record(
            selected_plaintext
                .get(trim_start..trim_end)
                .ok_or(V2FormatError::InvalidPayloadPack)?,
        );
        if !ct_eq(&digest, &record.plaintext_digest) {
            selected_plaintext.fill(0);
            return Err(V2FormatError::InvalidPayloadPack);
        }
    }
    Ok(V2OpenedPayloadPackRecordSpan {
        plaintext: Bytes::copy_from_slice(
            selected_plaintext
                .get(trim_start..trim_end)
                .ok_or(V2FormatError::InvalidPayloadPack)?,
        ),
        segments,
    })
}

/// Reassembles an exact planned range from already authenticated complete
/// plaintext segments.
pub fn open_v2_payload_pack_cached_record_span(
    directory: &V2PayloadPackDirectory,
    span: &V2PayloadPackRecordSpan,
    plaintext_segments: &[Bytes],
) -> V2Result<Bytes> {
    let record = directory
        .record(span.record_ordinal)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    if plaintext_segments.len()
        != usize::try_from(span.segment_count).map_err(|_| V2FormatError::InvalidPayloadPack)?
    {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    let start_segment = u64::from(span.start_segment);
    let mut selected_plaintext = Vec::new();
    for (relative_segment, plaintext) in plaintext_segments.iter().enumerate() {
        let segment_ordinal = start_segment
            .checked_add(
                u64::try_from(relative_segment).map_err(|_| V2FormatError::InvalidPayloadPack)?,
            )
            .ok_or(V2FormatError::InvalidPayloadPack)?;
        if u64::try_from(plaintext.len()).ok()
            != Some(segment_plaintext_len(record, segment_ordinal)?)
        {
            return Err(V2FormatError::InvalidPayloadPack);
        }
        selected_plaintext.extend_from_slice(plaintext);
    }
    let selected_plaintext_start = start_segment
        .checked_mul(u64::from(record.segment_size))
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let trim_start = span
        .requested
        .start
        .checked_sub(selected_plaintext_start)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let requested_len = span
        .requested
        .end
        .checked_sub(span.requested.start)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let trim_end = trim_start
        .checked_add(requested_len)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let trim_start = usize::try_from(trim_start).map_err(|_| V2FormatError::InvalidPayloadPack)?;
    let trim_end = usize::try_from(trim_end).map_err(|_| V2FormatError::InvalidPayloadPack)?;
    let requested = selected_plaintext
        .get(trim_start..trim_end)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    if span.requested.start == 0 && span.requested.end == record.plaintext_len {
        let digest = digest_payload_record(requested);
        if !ct_eq(&digest, &record.plaintext_digest) {
            selected_plaintext.fill(0);
            return Err(V2FormatError::InvalidPayloadPack);
        }
    }
    Ok(Bytes::copy_from_slice(requested))
}

/// Opens one plaintext range from complete pack bytes.
pub fn open_v2_payload_pack_record_range(
    keyring: &KeyRing,
    repository_context: &[u8],
    containing_object: &BackendObjectId,
    section_ordinal: u32,
    pack: &[u8],
    record_ordinal: u32,
    requested: Range<u64>,
) -> V2Result<Bytes> {
    let directory = open_v2_payload_pack(
        keyring,
        repository_context,
        containing_object,
        section_ordinal,
        pack,
    )?;
    let span = plan_v2_payload_pack_record_range(&directory, record_ordinal, requested)?;
    let start = usize::try_from(span.offset).map_err(|_| V2FormatError::InvalidPayloadPack)?;
    let end = span
        .offset
        .checked_add(span.stored_len)
        .and_then(|end| usize::try_from(end).ok())
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let ciphertext = pack.get(start..end).ok_or(V2FormatError::TruncatedBody)?;
    open_v2_payload_pack_record_span(
        keyring,
        repository_context,
        containing_object,
        section_ordinal,
        &directory,
        &span,
        ciphertext,
    )
}

/// Opens a complete logical record from complete pack bytes.
pub fn open_v2_payload_pack_record(
    keyring: &KeyRing,
    repository_context: &[u8],
    containing_object: &BackendObjectId,
    section_ordinal: u32,
    pack: &[u8],
    record_ordinal: u32,
) -> V2Result<Bytes> {
    let directory = open_v2_payload_pack(
        keyring,
        repository_context,
        containing_object,
        section_ordinal,
        pack,
    )?;
    let record = directory
        .record(record_ordinal)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    open_v2_payload_pack_record_range(
        keyring,
        repository_context,
        containing_object,
        section_ordinal,
        pack,
        record_ordinal,
        0..record.plaintext_len,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ParsedFixedHeader {
    pack_id: [u8; PAYLOAD_PACK_ID_LEN],
    header_len: u64,
    stored_len: u64,
    records_len: u64,
    metadata_key_id_len: usize,
    directory_ciphertext_len: usize,
}

fn parse_fixed_header(input: &[u8]) -> V2Result<ParsedFixedHeader> {
    let fixed = input
        .get(..PAYLOAD_PACK_FIXED_HEADER_LEN)
        .ok_or(V2FormatError::TruncatedHeader)?;
    if fixed.get(..8) != Some(PAYLOAD_PACK_MAGIC.as_slice()) {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    if read_u16(fixed, 8)? != PAYLOAD_PACK_VERSION {
        return Err(V2FormatError::UnsupportedFormatVersion);
    }
    if read_u16(fixed, 10)? != 0 || fixed.get(56..64).is_none() {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    let header_len = u64::from(read_u32(fixed, 12)?);
    let pack_id: [u8; PAYLOAD_PACK_ID_LEN] = fixed
        .get(16..48)
        .ok_or(V2FormatError::TruncatedHeader)?
        .try_into()
        .map_err(|_| V2FormatError::InvalidPayloadPack)?;
    let metadata_key_id_len = usize::from(read_u16(fixed, 48)?);
    let nonce_len = fixed
        .get(50)
        .copied()
        .ok_or(V2FormatError::TruncatedHeader)?;
    let tag_len = fixed
        .get(51)
        .copied()
        .ok_or(V2FormatError::TruncatedHeader)?;
    let directory_ciphertext_len =
        usize::try_from(read_u32(fixed, 52)?).map_err(|_| V2FormatError::InvalidPayloadPack)?;
    let records_len = read_u64(fixed, 56)?;
    let expected_header_len = PAYLOAD_PACK_FIXED_HEADER_LEN
        .checked_add(metadata_key_id_len)
        .and_then(|length| length.checked_add(usize::from(nonce_len)))
        .and_then(|length| length.checked_add(usize::from(tag_len)))
        .and_then(|length| length.checked_add(directory_ciphertext_len))
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let stored_len = header_len
        .checked_add(records_len)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    if metadata_key_id_len == 0
        || metadata_key_id_len > MAX_KEY_ID_LEN
        || nonce_len != METADATA_NONCE_LEN as u8
        || tag_len != METADATA_TAG_LEN as u8
        || header_len != expected_header_len as u64
        || header_len < PAYLOAD_PACK_FIXED_HEADER_LEN as u64
        || header_len > V2_PAYLOAD_PACK_MAX_HEADER_BYTES as u64
        || stored_len > V2_PAYLOAD_PACK_MAX_BYTES as u64
    {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    Ok(ParsedFixedHeader {
        pack_id,
        header_len,
        stored_len,
        records_len,
        metadata_key_id_len,
        directory_ciphertext_len,
    })
}

fn encode_fixed_header(
    output: &mut Vec<u8>,
    pack_id: &[u8; PAYLOAD_PACK_ID_LEN],
    header_len: usize,
    metadata_key_id: &KeyId,
    directory_ciphertext_len: usize,
    records_len: u64,
) -> V2Result<()> {
    output.extend_from_slice(PAYLOAD_PACK_MAGIC);
    output.extend_from_slice(&PAYLOAD_PACK_VERSION.to_be_bytes());
    output.extend_from_slice(&0_u16.to_be_bytes());
    output.extend_from_slice(
        &u32::try_from(header_len)
            .map_err(|_| V2FormatError::PayloadPackLimitExceeded)?
            .to_be_bytes(),
    );
    output.extend_from_slice(pack_id);
    output.extend_from_slice(
        &u16::try_from(metadata_key_id.as_str().len())
            .map_err(|_| V2FormatError::PayloadPackLimitExceeded)?
            .to_be_bytes(),
    );
    output.push(METADATA_NONCE_LEN as u8);
    output.push(METADATA_TAG_LEN as u8);
    output.extend_from_slice(
        &u32::try_from(directory_ciphertext_len)
            .map_err(|_| V2FormatError::PayloadPackLimitExceeded)?
            .to_be_bytes(),
    );
    output.extend_from_slice(&records_len.to_be_bytes());
    if output.len() != PAYLOAD_PACK_FIXED_HEADER_LEN {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    Ok(())
}

fn encode_directory(content_key_id: &KeyId, records: &[V2PayloadPackRecord]) -> V2Result<Vec<u8>> {
    let key = content_key_id.as_str().as_bytes();
    let key_len = u16::try_from(key.len()).map_err(|_| V2FormatError::PayloadPackLimitExceeded)?;
    let count =
        u32::try_from(records.len()).map_err(|_| V2FormatError::PayloadPackLimitExceeded)?;
    let mut output = Vec::with_capacity(
        PAYLOAD_PACK_DIRECTORY_DOMAIN
            .len()
            .saturating_add(2)
            .saturating_add(key.len())
            .saturating_add(4)
            .saturating_add(records.len().saturating_mul(DIRECTORY_RECORD_LEN)),
    );
    output.extend_from_slice(PAYLOAD_PACK_DIRECTORY_DOMAIN);
    output.extend_from_slice(&key_len.to_be_bytes());
    output.extend_from_slice(key);
    output.extend_from_slice(&count.to_be_bytes());
    for (ordinal, record) in records.iter().enumerate() {
        if usize::try_from(record.record_ordinal).ok() != Some(ordinal) {
            return Err(V2FormatError::InvalidPayloadPack);
        }
        output.extend_from_slice(&record.physical_offset.to_be_bytes());
        output.extend_from_slice(&record.stored_len.to_be_bytes());
        output.extend_from_slice(&record.plaintext_len.to_be_bytes());
        output.extend_from_slice(&record.segment_size.to_be_bytes());
        output.extend_from_slice(&record.plaintext_digest);
    }
    Ok(output)
}

fn decode_directory(
    plaintext: &[u8],
    records_len: u64,
) -> V2Result<(KeyId, Vec<V2PayloadPackRecord>)> {
    let mut cursor = 0_usize;
    take_exact(plaintext, &mut cursor, PAYLOAD_PACK_DIRECTORY_DOMAIN)?;
    let key_len = usize::from(take_u16(plaintext, &mut cursor)?);
    if key_len == 0 || key_len > MAX_KEY_ID_LEN {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    let key = take(plaintext, &mut cursor, key_len)?;
    let key = std::str::from_utf8(key).map_err(|_| V2FormatError::InvalidPayloadPack)?;
    let content_key_id = KeyId::new(key.to_owned())?;
    let count = usize::try_from(take_u32(plaintext, &mut cursor)?)
        .map_err(|_| V2FormatError::InvalidPayloadPack)?;
    if count == 0 || count > V2_PAYLOAD_PACK_MAX_RECORDS {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    let expected_remaining = count
        .checked_mul(DIRECTORY_RECORD_LEN)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    if plaintext.len().checked_sub(cursor) != Some(expected_remaining) {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    let mut records = Vec::with_capacity(count);
    for ordinal in 0..count {
        let physical_offset = take_u64(plaintext, &mut cursor)?;
        let stored_len = take_u64(plaintext, &mut cursor)?;
        let plaintext_len = take_u64(plaintext, &mut cursor)?;
        let segment_size = take_u32(plaintext, &mut cursor)?;
        let plaintext_digest: [u8; 32] = take(plaintext, &mut cursor, 32)?
            .try_into()
            .map_err(|_| V2FormatError::InvalidPayloadPack)?;
        let count = segment_count(plaintext_len, u64::from(segment_size))?;
        let expected_stored_len = plaintext_len
            .checked_add(
                count
                    .checked_mul(AEAD_TAG_LEN)
                    .ok_or(V2FormatError::InvalidPayloadPack)?,
            )
            .ok_or(V2FormatError::InvalidPayloadPack)?;
        let canonical_segment_size = plaintext_len.min(V2_PAYLOAD_PACK_SEGMENT_BYTES as u64);
        if segment_size == 0
            || u64::from(segment_size) != canonical_segment_size
            || plaintext_len == 0
            || stored_len != expected_stored_len
        {
            return Err(V2FormatError::InvalidPayloadPack);
        }
        records.push(V2PayloadPackRecord {
            record_ordinal: u32::try_from(ordinal)
                .map_err(|_| V2FormatError::InvalidPayloadPack)?,
            physical_offset,
            stored_len,
            plaintext_len,
            segment_size,
            plaintext_digest,
        });
    }
    validate_record_coverage(&records, records_len)?;
    Ok((content_key_id, records))
}

fn validate_record_coverage(records: &[V2PayloadPackRecord], records_len: u64) -> V2Result<()> {
    let mut spans: Vec<(u64, u64)> = records
        .iter()
        .map(|record| {
            record
                .physical_offset
                .checked_add(record.stored_len)
                .map(|end| (record.physical_offset, end))
                .ok_or(V2FormatError::InvalidPayloadPack)
        })
        .collect::<V2Result<_>>()?;
    spans.sort_unstable();
    let mut expected_start = 0_u64;
    for (start, end) in spans {
        if start != expected_start || end <= start || end > records_len {
            return Err(V2FormatError::InvalidPayloadPack);
        }
        expected_start = end;
    }
    if expected_start != records_len {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    Ok(())
}

fn seal_record_into(
    keyring: &KeyRing,
    context: PayloadPackContext<'_>,
    directory: &V2PayloadPackDirectory,
    record: &V2PayloadPackRecord,
    plaintext: &[u8],
    record_region: &mut [u8],
) -> V2Result<()> {
    let count = segment_count(record.plaintext_len, u64::from(record.segment_size))?;
    for segment_ordinal in 0..count {
        let plaintext_start = segment_ordinal
            .checked_mul(u64::from(record.segment_size))
            .ok_or(V2FormatError::PayloadPackLimitExceeded)?;
        let plaintext_len = segment_plaintext_len(record, segment_ordinal)?;
        let plaintext_end = plaintext_start
            .checked_add(plaintext_len)
            .ok_or(V2FormatError::PayloadPackLimitExceeded)?;
        let plaintext_segment = plaintext
            .get(
                usize::try_from(plaintext_start)
                    .map_err(|_| V2FormatError::PayloadPackLimitExceeded)?
                    ..usize::try_from(plaintext_end)
                        .map_err(|_| V2FormatError::PayloadPackLimitExceeded)?,
            )
            .ok_or(V2FormatError::InvalidPayloadPack)?;
        let aad =
            segment_associated_data(context, directory, record, segment_ordinal, plaintext_len)?;
        let nonce_context =
            segment_nonce_context(directory.pack_id(), record.record_ordinal, segment_ordinal);
        let sealed = keyring.seal_payload_pack_segment(
            &aad,
            &nonce_context,
            &record.plaintext_digest,
            plaintext_segment,
        )?;
        if sealed.key_id != *directory.content_key_id()
            || u64::try_from(sealed.ciphertext.len()).ok()
                != plaintext_len.checked_add(AEAD_TAG_LEN)
        {
            return Err(V2FormatError::CryptoOperation);
        }
        let relative_offset =
            segment_ciphertext_offset(segment_ordinal, u64::from(record.segment_size))?;
        let start = record
            .physical_offset
            .checked_add(relative_offset)
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or(V2FormatError::PayloadPackLimitExceeded)?;
        let end = start
            .checked_add(sealed.ciphertext.len())
            .ok_or(V2FormatError::PayloadPackLimitExceeded)?;
        let destination = record_region
            .get_mut(start..end)
            .ok_or(V2FormatError::InvalidPayloadPack)?;
        destination.copy_from_slice(&sealed.ciphertext);
    }
    Ok(())
}

fn directory_associated_data(
    context: PayloadPackContext<'_>,
    pack_id: &[u8; PAYLOAD_PACK_ID_LEN],
    metadata_key_id: &KeyId,
    stored_len: u64,
    header_len: u64,
    records_len: u64,
) -> V2Result<Vec<u8>> {
    let mut aad = Vec::new();
    aad.extend_from_slice(PAYLOAD_PACK_DIRECTORY_AAD_DOMAIN);
    push_framed(&mut aad, context.repository_context)?;
    push_framed(&mut aad, context.containing_object.as_str().as_bytes())?;
    aad.extend_from_slice(&PAYLOAD_PACK_VERSION.to_be_bytes());
    aad.extend_from_slice(&context.section_ordinal.to_be_bytes());
    aad.extend_from_slice(pack_id);
    push_framed(&mut aad, metadata_key_id.as_str().as_bytes())?;
    aad.extend_from_slice(&stored_len.to_be_bytes());
    aad.extend_from_slice(&header_len.to_be_bytes());
    aad.extend_from_slice(&records_len.to_be_bytes());
    Ok(aad)
}

fn segment_associated_data(
    context: PayloadPackContext<'_>,
    directory: &V2PayloadPackDirectory,
    record: &V2PayloadPackRecord,
    segment_ordinal: u64,
    segment_plaintext_len: u64,
) -> V2Result<Vec<u8>> {
    let mut aad = Vec::new();
    aad.extend_from_slice(PAYLOAD_PACK_SEGMENT_AAD_DOMAIN);
    push_framed(&mut aad, context.repository_context)?;
    push_framed(&mut aad, context.containing_object.as_str().as_bytes())?;
    aad.extend_from_slice(&PAYLOAD_PACK_VERSION.to_be_bytes());
    aad.extend_from_slice(&context.section_ordinal.to_be_bytes());
    aad.extend_from_slice(directory.pack_id());
    push_framed(&mut aad, directory.content_key_id().as_str().as_bytes())?;
    aad.extend_from_slice(&directory.header_len.to_be_bytes());
    aad.extend_from_slice(&directory.stored_len.to_be_bytes());
    aad.extend_from_slice(&record.record_ordinal.to_be_bytes());
    aad.extend_from_slice(&record.physical_offset.to_be_bytes());
    aad.extend_from_slice(&record.stored_len.to_be_bytes());
    aad.extend_from_slice(&record.plaintext_len.to_be_bytes());
    aad.extend_from_slice(&record.segment_size.to_be_bytes());
    aad.extend_from_slice(&record.plaintext_digest);
    aad.extend_from_slice(&segment_ordinal.to_be_bytes());
    aad.extend_from_slice(
        &segment_ciphertext_offset(segment_ordinal, u64::from(record.segment_size))?.to_be_bytes(),
    );
    aad.extend_from_slice(&segment_plaintext_len.to_be_bytes());
    aad.extend_from_slice(
        &segment_plaintext_len
            .checked_add(AEAD_TAG_LEN)
            .ok_or(V2FormatError::InvalidPayloadPack)?
            .to_be_bytes(),
    );
    let count = segment_count(record.plaintext_len, u64::from(record.segment_size))?;
    aad.push(u8::from(segment_ordinal.checked_add(1) == Some(count)));
    Ok(aad)
}

fn segment_nonce_context(
    pack_id: &[u8; PAYLOAD_PACK_ID_LEN],
    record_ordinal: u32,
    segment_ordinal: u64,
) -> Vec<u8> {
    let mut context = Vec::with_capacity(
        PAYLOAD_PACK_SEGMENT_NONCE_CONTEXT_DOMAIN.len() + PAYLOAD_PACK_ID_LEN + 4 + 8,
    );
    context.extend_from_slice(PAYLOAD_PACK_SEGMENT_NONCE_CONTEXT_DOMAIN);
    context.extend_from_slice(pack_id);
    context.extend_from_slice(&record_ordinal.to_be_bytes());
    context.extend_from_slice(&segment_ordinal.to_be_bytes());
    context
}

fn validate_public_context(
    repository_context: &[u8],
    containing_object: &BackendObjectId,
) -> V2Result<()> {
    if repository_context.is_empty()
        || repository_context.len() > MAX_CONTEXT_LEN
        || containing_object.as_str().len() > MAX_OBJECT_KEY_LEN
    {
        return Err(V2FormatError::PayloadPackLimitExceeded);
    }
    Ok(())
}

fn random_physical_order(record_count: usize) -> V2Result<Vec<usize>> {
    if record_count == 0 || record_count > V2_PAYLOAD_PACK_MAX_RECORDS {
        return Err(V2FormatError::PayloadPackLimitExceeded);
    }
    let mut keyed = Vec::with_capacity(record_count);
    for ordinal in 0..record_count {
        let mut key = [0_u8; 16];
        fill_random(&mut key).map_err(|_| V2FormatError::RandomnessUnavailable)?;
        keyed.push((key, ordinal));
    }
    keyed.sort_unstable();
    Ok(keyed.into_iter().map(|(_, ordinal)| ordinal).collect())
}

fn validate_physical_order(order: &[usize], count: usize) -> V2Result<()> {
    if order.len() != count {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    let mut seen = vec![false; count];
    for ordinal in order {
        let slot = seen
            .get_mut(*ordinal)
            .ok_or(V2FormatError::InvalidPayloadPack)?;
        if *slot {
            return Err(V2FormatError::InvalidPayloadPack);
        }
        *slot = true;
    }
    Ok(())
}

fn segment_count(plaintext_len: u64, segment_size: u64) -> V2Result<u64> {
    if plaintext_len == 0 || segment_size == 0 {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    plaintext_len
        .checked_add(segment_size - 1)
        .map(|rounded| rounded / segment_size)
        .ok_or(V2FormatError::PayloadPackLimitExceeded)
}

fn segment_plaintext_len(record: &V2PayloadPackRecord, segment_ordinal: u64) -> V2Result<u64> {
    let segment_size = u64::from(record.segment_size);
    let count = segment_count(record.plaintext_len, segment_size)?;
    if segment_ordinal >= count {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    let start = segment_ordinal
        .checked_mul(segment_size)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    Ok(record.plaintext_len.saturating_sub(start).min(segment_size))
}

fn segment_ciphertext_offset(segment_ordinal: u64, segment_size: u64) -> V2Result<u64> {
    segment_ordinal
        .checked_mul(
            segment_size
                .checked_add(AEAD_TAG_LEN)
                .ok_or(V2FormatError::InvalidPayloadPack)?,
        )
        .ok_or(V2FormatError::InvalidPayloadPack)
}

fn push_framed(output: &mut Vec<u8>, value: &[u8]) -> V2Result<()> {
    output.extend_from_slice(
        &u64::try_from(value.len())
            .map_err(|_| V2FormatError::PayloadPackLimitExceeded)?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}

fn read_u16(input: &[u8], offset: usize) -> V2Result<u16> {
    let bytes: [u8; 2] = input
        .get(offset..offset.saturating_add(2))
        .ok_or(V2FormatError::TruncatedHeader)?
        .try_into()
        .map_err(|_| V2FormatError::InvalidPayloadPack)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u32(input: &[u8], offset: usize) -> V2Result<u32> {
    let bytes: [u8; 4] = input
        .get(offset..offset.saturating_add(4))
        .ok_or(V2FormatError::TruncatedHeader)?
        .try_into()
        .map_err(|_| V2FormatError::InvalidPayloadPack)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_u64(input: &[u8], offset: usize) -> V2Result<u64> {
    let bytes: [u8; 8] = input
        .get(offset..offset.saturating_add(8))
        .ok_or(V2FormatError::TruncatedHeader)?
        .try_into()
        .map_err(|_| V2FormatError::InvalidPayloadPack)?;
    Ok(u64::from_be_bytes(bytes))
}

fn take<'a>(input: &'a [u8], cursor: &mut usize, length: usize) -> V2Result<&'a [u8]> {
    let end = cursor
        .checked_add(length)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let value = input
        .get(*cursor..end)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    *cursor = end;
    Ok(value)
}

fn take_exact(input: &[u8], cursor: &mut usize, expected: &[u8]) -> V2Result<()> {
    if take(input, cursor, expected.len())? != expected {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    Ok(())
}

fn take_u16(input: &[u8], cursor: &mut usize) -> V2Result<u16> {
    let bytes: [u8; 2] = take(input, cursor, 2)?
        .try_into()
        .map_err(|_| V2FormatError::InvalidPayloadPack)?;
    Ok(u16::from_be_bytes(bytes))
}

fn take_u32(input: &[u8], cursor: &mut usize) -> V2Result<u32> {
    let bytes: [u8; 4] = take(input, cursor, 4)?
        .try_into()
        .map_err(|_| V2FormatError::InvalidPayloadPack)?;
    Ok(u32::from_be_bytes(bytes))
}

fn take_u64(input: &[u8], cursor: &mut usize) -> V2Result<u64> {
    let bytes: [u8; 8] = take(input, cursor, 8)?
        .try_into()
        .map_err(|_| V2FormatError::InvalidPayloadPack)?;
    Ok(u64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rs3_crypto::{KeyMaterial, SecretBytes};
    use rs3_types::{KeyDescriptor, KeyStatus};

    fn must_v2<T>(result: V2Result<T>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{error}"),
        }
    }

    fn keyring() -> KeyRing {
        let secret = match SecretBytes::new(vec![7_u8; SecretBytes::MIN_LEN]) {
            Ok(secret) => secret,
            Err(error) => panic!("{error}"),
        };
        KeyRing::single_namespace(secret)
    }

    fn object_id(value: &str) -> BackendObjectId {
        match BackendObjectId::new(value) {
            Ok(value) => value,
            Err(error) => panic!("{error}"),
        }
    }

    fn key_material(
        id: &str,
        purpose: KeyPurpose,
        algorithm: &str,
        secret_byte: u8,
    ) -> KeyMaterial {
        let id = match KeyId::new(id.to_owned()) {
            Ok(id) => id,
            Err(error) => panic!("{error}"),
        };
        let secret = match SecretBytes::new(vec![secret_byte; SecretBytes::MIN_LEN]) {
            Ok(secret) => secret,
            Err(error) => panic!("{error}"),
        };
        KeyMaterial::new(
            KeyDescriptor {
                id,
                purpose,
                algorithm: algorithm.to_owned(),
                status: KeyStatus::Primary,
                created_at_ms: 0,
                not_before_ms: None,
                not_after_ms: None,
                public_key: None,
                external_kms_uri: None,
            },
            secret,
        )
    }

    fn sample_pack() -> V2SealedPayloadPack {
        must_v2(seal_v2_payload_pack_with_layout(
            &keyring(),
            b"repository-format-root-generation-4",
            &object_id("commits/opaque-commit"),
            2,
            &[
                V2PayloadPackRecordInput {
                    plaintext: Bytes::from_static(b"abcdefghijk"),
                },
                V2PayloadPackRecordInput {
                    plaintext: Bytes::from_static(b"range-friendly-value"),
                },
            ],
            [9_u8; PAYLOAD_PACK_ID_LEN],
            &[1, 0],
        ))
    }

    #[test]
    fn pack_round_trip_preserves_logical_order_despite_physical_shuffle() {
        let pack = sample_pack();
        assert!(
            pack.directory().records()[1].physical_offset
                < pack.directory().records()[0].physical_offset
        );
        let first = must_v2(open_v2_payload_pack_record(
            &keyring(),
            b"repository-format-root-generation-4",
            &object_id("commits/opaque-commit"),
            2,
            pack.bytes(),
            0,
        ));
        let second = must_v2(open_v2_payload_pack_record(
            &keyring(),
            b"repository-format-root-generation-4",
            &object_id("commits/opaque-commit"),
            2,
            pack.bytes(),
            1,
        ));
        assert_eq!(first, Bytes::from_static(b"abcdefghijk"));
        assert_eq!(second, Bytes::from_static(b"range-friendly-value"));
    }

    #[test]
    fn planned_range_fetch_opens_only_intersecting_segments() {
        let pack = sample_pack();
        let fixed = &pack.bytes()[..PAYLOAD_PACK_FIXED_HEADER_LEN];
        let header_len = must_v2(probe_v2_payload_pack_header_len(fixed));
        let header_len = usize::try_from(header_len).expect("test header fits usize");
        let directory = must_v2(open_v2_payload_pack_directory(
            &keyring(),
            b"repository-format-root-generation-4",
            &object_id("commits/opaque-commit"),
            2,
            &pack.bytes()[..header_len],
            pack.bytes().len() as u64,
        ));
        let span = must_v2(plan_v2_payload_pack_record_range(&directory, 1, 5..15));
        assert_eq!(span.start_segment, 0);
        assert_eq!(span.segment_count, 1);
        let start = span.offset as usize;
        let end = start + span.stored_len as usize;
        let opened = must_v2(open_v2_payload_pack_record_span(
            &keyring(),
            b"repository-format-root-generation-4",
            &object_id("commits/opaque-commit"),
            2,
            &directory,
            &span,
            &pack.bytes()[start..end],
        ));
        assert_eq!(opened, Bytes::from_static(b"-friendly-"));
    }

    #[test]
    fn range_plan_fetches_only_intersecting_canonical_segments() {
        let plaintext = Bytes::from(
            (0..(V2_PAYLOAD_PACK_SEGMENT_BYTES + 32))
                .map(|offset| (offset % 251) as u8)
                .collect::<Vec<_>>(),
        );
        let pack = must_v2(seal_v2_payload_pack_with_layout(
            &keyring(),
            b"repository-format-root-generation-4",
            &object_id("commits/opaque-commit"),
            2,
            &[V2PayloadPackRecordInput {
                plaintext: plaintext.clone(),
            }],
            [13_u8; PAYLOAD_PACK_ID_LEN],
            &[0],
        ));
        let requested =
            (V2_PAYLOAD_PACK_SEGMENT_BYTES as u64 - 8)..(V2_PAYLOAD_PACK_SEGMENT_BYTES as u64 + 8);
        let span = must_v2(plan_v2_payload_pack_record_range(
            pack.directory(),
            0,
            requested.clone(),
        ));
        assert_eq!(span.start_segment, 0);
        assert_eq!(span.segment_count, 2);
        let start = span.offset as usize;
        let end = start + span.stored_len as usize;
        let opened = must_v2(open_v2_payload_pack_record_span(
            &keyring(),
            b"repository-format-root-generation-4",
            &object_id("commits/opaque-commit"),
            2,
            pack.directory(),
            &span,
            &pack.bytes()[start..end],
        ));
        assert_eq!(
            opened.as_ref(),
            &plaintext[requested.start as usize..requested.end as usize]
        );
    }

    #[test]
    fn directory_and_segments_reject_context_transplants_and_tampering() {
        let pack = sample_pack();
        let wrong_object = open_v2_payload_pack(
            &keyring(),
            b"repository-format-root-generation-4",
            &object_id("commits/other"),
            2,
            pack.bytes(),
        );
        assert!(wrong_object.is_err());
        let wrong_section = open_v2_payload_pack(
            &keyring(),
            b"repository-format-root-generation-4",
            &object_id("commits/opaque-commit"),
            3,
            pack.bytes(),
        );
        assert!(wrong_section.is_err());

        let mut directory_tamper = pack.bytes().to_vec();
        directory_tamper[PAYLOAD_PACK_FIXED_HEADER_LEN + 2] ^= 1;
        assert!(
            open_v2_payload_pack(
                &keyring(),
                b"repository-format-root-generation-4",
                &object_id("commits/opaque-commit"),
                2,
                &directory_tamper,
            )
            .is_err()
        );

        let mut segment_tamper = pack.bytes().to_vec();
        let record = &pack.directory().records()[0];
        let offset = pack.directory().records_start() + record.physical_offset;
        segment_tamper[offset as usize] ^= 1;
        assert!(
            open_v2_payload_pack_record(
                &keyring(),
                b"repository-format-root-generation-4",
                &object_id("commits/opaque-commit"),
                2,
                &segment_tamper,
                0,
            )
            .is_err()
        );
    }

    #[test]
    fn every_truncation_fails_closed() {
        let pack = sample_pack();
        for length in 0..pack.bytes().len() {
            let result = open_v2_payload_pack(
                &keyring(),
                b"repository-format-root-generation-4",
                &object_id("commits/opaque-commit"),
                2,
                &pack.bytes()[..length],
            );
            assert!(result.is_err(), "truncation at {length} bytes was accepted");
        }
    }

    #[test]
    fn sixty_four_small_values_have_compact_fixed_overhead() {
        let records = (0..V2_PAYLOAD_PACK_MAX_RECORDS)
            .map(|ordinal| V2PayloadPackRecordInput {
                plaintext: Bytes::from(vec![ordinal as u8; 512]),
            })
            .collect::<Vec<_>>();
        let order = (0..records.len()).rev().collect::<Vec<_>>();
        let pack = must_v2(seal_v2_payload_pack_with_layout(
            &keyring(),
            b"repository-format-root-generation-4",
            &object_id("commits/opaque-commit"),
            2,
            &records,
            [11_u8; PAYLOAD_PACK_ID_LEN],
            &order,
        ));
        assert!(pack.bytes().len() <= 38 * 1024, "{}", pack.bytes().len());
        assert_eq!(pack.directory().records().len(), 64);
    }

    #[test]
    fn invalid_ranges_and_record_counts_are_rejected() {
        let pack = sample_pack();
        assert!(plan_v2_payload_pack_record_range(pack.directory(), 0, 4..4).is_err());
        assert!(plan_v2_payload_pack_record_range(pack.directory(), 0, 0..12).is_err());
        assert!(
            seal_v2_payload_pack_with_layout(
                &keyring(),
                b"repository-format-root-generation-4",
                &object_id("commits/opaque-commit"),
                2,
                &[],
                [0_u8; PAYLOAD_PACK_ID_LEN],
                &[],
            )
            .is_err()
        );
    }

    #[test]
    fn writer_rejects_metadata_key_ids_the_reader_cannot_encode() {
        let long_metadata_id = "m".repeat(MAX_KEY_ID_LEN + 1);
        let keyring = match KeyRing::new(vec![
            key_material("namespace", KeyPurpose::Namespace, "hmac-sha256", 1),
            key_material("content", KeyPurpose::Content, "xchacha20poly1305", 2),
            key_material(
                &long_metadata_id,
                KeyPurpose::Metadata,
                "aes-256-gcm-siv-hmac-sha256-nonce-v1",
                3,
            ),
        ]) {
            Ok(keyring) => keyring,
            Err(error) => panic!("{error}"),
        };
        let result = seal_v2_payload_pack(
            &keyring,
            b"repository-format-root-generation-4",
            &object_id("commits/opaque-commit"),
            2,
            &[V2PayloadPackRecordInput {
                plaintext: Bytes::from_static(b"value"),
            }],
        );
        assert_eq!(result, Err(V2FormatError::PayloadPackLimitExceeded));
    }

    #[test]
    fn decoder_rejects_noncanonical_segment_sizes() {
        let content_key = match KeyId::new("content") {
            Ok(key) => key,
            Err(error) => panic!("{error}"),
        };
        let plaintext_len = 512_u64;
        let stored_len = plaintext_len + plaintext_len * AEAD_TAG_LEN;
        let record = V2PayloadPackRecord {
            record_ordinal: 0,
            physical_offset: 0,
            stored_len,
            plaintext_len,
            segment_size: 1,
            plaintext_digest: [0_u8; 32],
        };
        let encoded = must_v2(encode_directory(&content_key, &[record]));
        assert_eq!(
            decode_directory(&encoded, stored_len),
            Err(V2FormatError::InvalidPayloadPack)
        );
    }

    #[test]
    fn debug_output_does_not_expose_plaintext() {
        let input = V2PayloadPackRecordInput {
            plaintext: Bytes::from_static(b"top-secret-payload"),
        };
        let debug = format!("{input:?}");
        assert!(!debug.contains("top-secret-payload"));
        assert!(debug.contains("plaintext_len"));

        let pack = sample_pack();
        let digest_debug = format!("{:?}", digest_payload_record(b"range-friendly-value"));
        let debug = format!("{pack:?}");
        assert!(!debug.contains(&digest_debug));
        assert!(debug.contains("plaintext_digest: \"<redacted>\""));
    }
}
