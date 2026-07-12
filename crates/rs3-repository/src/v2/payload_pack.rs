//! Compact authenticated payload packs for bounded v02 commit batches.
//!
//! A stored payload pack has no self-describing header. Its bytes are only
//! independently authenticated record segments, in a randomized physical
//! order. The encrypted index run carries the pack and record facts needed to
//! derive exact byte ranges and reconstruct the segment AEAD inputs.

use super::{V2FormatError, V2Result};
use bytes::Bytes;
use getrandom::fill as fill_random;
use rs3_crypto::KeyRing;
use rs3_types::{BackendObjectId, KeyId};
use std::fmt;
use std::ops::Range;

/// Maximum logical records in one v02 payload pack.
pub const V2_PAYLOAD_PACK_MAX_RECORDS: usize = 1_024;
/// Maximum complete pack bytes accepted by the bounded in-memory codec.
pub const V2_PAYLOAD_PACK_MAX_BYTES: usize = 32 * 1024 * 1024;
/// Canonical independently authenticated plaintext segment size.
pub const V2_PAYLOAD_PACK_SEGMENT_BYTES: usize = 64 * 1024;
/// Random pack identifier bytes.
pub const V2_PAYLOAD_PACK_ID_LEN: usize = 32;

const PAYLOAD_PACK_SEGMENT_AAD_DOMAIN: &[u8] = b"rs3:payload-pack-segment-aad:v3\n";
const PAYLOAD_PACK_SEGMENT_NONCE_CONTEXT_DOMAIN: &[u8] = b"rs3:payload-pack-segment-context:v3\n";
const AEAD_TAG_LEN: u64 = 16;
const MAX_CONTEXT_LEN: usize = 1024;
const MAX_OBJECT_KEY_LEN: usize = 1024;
const MAX_KEY_ID_LEN: usize = 255;

/// One plaintext value to place in a payload pack.
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

/// Random 256-bit identity that prevents segment nonce reuse across packs.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct V2PayloadPackId([u8; V2_PAYLOAD_PACK_ID_LEN]);

impl V2PayloadPackId {
    /// Constructs an identifier from its exact bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; V2_PAYLOAD_PACK_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the exact identifier bytes for encrypted index serialization.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; V2_PAYLOAD_PACK_ID_LEN] {
        &self.0
    }

    /// Consumes the identifier and returns its exact bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; V2_PAYLOAD_PACK_ID_LEN] {
        self.0
    }
}

impl fmt::Debug for V2PayloadPackId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("V2PayloadPackId(<redacted>)")
    }
}

/// Authenticated facts shared by every record reference in one pack.
#[derive(Clone, PartialEq, Eq)]
pub struct V2PayloadPackFacts {
    pack_id: V2PayloadPackId,
    content_key_id: KeyId,
    stored_len: u32,
    record_count: u32,
}

impl fmt::Debug for V2PayloadPackFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V2PayloadPackFacts")
            .field("pack_id", &self.pack_id)
            .field("content_key_id", &self.content_key_id)
            .field("stored_len", &self.stored_len)
            .field("record_count", &self.record_count)
            .finish()
    }
}

impl V2PayloadPackFacts {
    /// Validates facts recovered from an authenticated encrypted index run.
    pub fn new(
        pack_id: V2PayloadPackId,
        content_key_id: KeyId,
        stored_len: u32,
        record_count: u32,
    ) -> V2Result<Self> {
        if content_key_id.as_str().is_empty()
            || content_key_id.as_str().len() > MAX_KEY_ID_LEN
            || stored_len == 0
            || stored_len as usize > V2_PAYLOAD_PACK_MAX_BYTES
            || record_count == 0
            || record_count as usize > V2_PAYLOAD_PACK_MAX_RECORDS
        {
            return Err(V2FormatError::InvalidPayloadPack);
        }
        Ok(Self {
            pack_id,
            content_key_id,
            stored_len,
            record_count,
        })
    }

    /// Returns the random pack identity bound into every segment AEAD.
    #[must_use]
    pub const fn pack_id(&self) -> V2PayloadPackId {
        self.pack_id
    }

    /// Returns the historical content key needed to open this pack.
    #[must_use]
    pub const fn content_key_id(&self) -> &KeyId {
        &self.content_key_id
    }

    /// Returns the exact stored object length.
    #[must_use]
    pub const fn stored_len(&self) -> u32 {
        self.stored_len
    }

    /// Returns the authenticated number of logical records in the pack.
    #[must_use]
    pub const fn record_count(&self) -> u32 {
        self.record_count
    }
}

/// Authenticated index facts for one logical record in a payload pack.
#[derive(Clone, PartialEq, Eq)]
pub struct V2PayloadPackRecordRef {
    record_ordinal: u32,
    physical_offset: u32,
}

impl fmt::Debug for V2PayloadPackRecordRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V2PayloadPackRecordRef")
            .field("record_ordinal", &self.record_ordinal)
            .field("physical_offset", &self.physical_offset)
            .finish()
    }
}

impl V2PayloadPackRecordRef {
    /// Constructs record facts recovered from an authenticated encrypted index run.
    #[must_use]
    pub const fn new(record_ordinal: u32, physical_offset: u32) -> Self {
        Self {
            record_ordinal,
            physical_offset,
        }
    }

    /// Returns the logical zero-based record ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> u32 {
        self.record_ordinal
    }

    /// Returns the record's physical ciphertext offset from the pack start.
    #[must_use]
    pub const fn physical_offset(&self) -> u32 {
        self.physical_offset
    }
}

/// Complete writer-side facts for one record in a validated pack layout.
#[derive(Clone, PartialEq, Eq)]
pub struct V2PayloadPackRecord {
    reference: V2PayloadPackRecordRef,
    plaintext_len: u64,
}

impl fmt::Debug for V2PayloadPackRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V2PayloadPackRecord")
            .field("reference", &self.reference)
            .field("plaintext_len", &self.plaintext_len)
            .finish()
    }
}

impl V2PayloadPackRecord {
    /// Returns the compact record reference stored alongside an index upsert.
    #[must_use]
    pub const fn reference(&self) -> &V2PayloadPackRecordRef {
        &self.reference
    }

    /// Returns the plaintext length already carried by the index upsert.
    #[must_use]
    pub const fn plaintext_len(&self) -> u64 {
        self.plaintext_len
    }

    /// Returns the complete derived ciphertext length for this record.
    pub fn stored_len(&self) -> V2Result<u32> {
        record_stored_len(self.plaintext_len)
    }
}

impl std::ops::Deref for V2PayloadPackRecord {
    type Target = V2PayloadPackRecordRef;

    fn deref(&self) -> &Self::Target {
        &self.reference
    }
}

/// Complete validated layout returned to a pack writer.
///
/// Unlike a single external record reference, a layout proves exact coverage
/// and non-overlap across every record in the pack.
#[derive(Clone, PartialEq, Eq)]
pub struct V2PayloadPackLayout {
    facts: V2PayloadPackFacts,
    records: Vec<V2PayloadPackRecord>,
}

impl fmt::Debug for V2PayloadPackLayout {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V2PayloadPackLayout")
            .field("facts", &self.facts)
            .field("records", &self.records)
            .finish()
    }
}

impl V2PayloadPackLayout {
    /// Validates a complete logical and physical pack layout.
    pub fn new(facts: V2PayloadPackFacts, records: Vec<V2PayloadPackRecord>) -> V2Result<Self> {
        if records.len() != facts.record_count as usize {
            return Err(V2FormatError::InvalidPayloadPack);
        }
        for (ordinal, record) in records.iter().enumerate() {
            if usize::try_from(record.reference.record_ordinal).ok() != Some(ordinal) {
                return Err(V2FormatError::InvalidPayloadPack);
            }
            validate_v2_payload_pack_record_ref(&facts, &record.reference, record.plaintext_len)?;
        }
        validate_record_coverage(&facts, &records)?;
        Ok(Self { facts, records })
    }

    /// Returns authenticated pack-wide facts for INDEX_RUN serialization.
    #[must_use]
    pub const fn facts(&self) -> &V2PayloadPackFacts {
        &self.facts
    }

    /// Returns record references in logical ordinal order.
    #[must_use]
    pub fn records(&self) -> &[V2PayloadPackRecord] {
        &self.records
    }

    /// Returns one logical record reference by ordinal.
    #[must_use]
    pub fn record(&self, ordinal: u32) -> Option<&V2PayloadPackRecord> {
        usize::try_from(ordinal)
            .ok()
            .and_then(|ordinal| self.records.get(ordinal))
    }
}

/// Complete ciphertext-only pack bytes plus its authenticated layout facts.
#[derive(Clone, PartialEq, Eq)]
pub struct V2SealedPayloadPack {
    layout: V2PayloadPackLayout,
    bytes: Bytes,
}

impl fmt::Debug for V2SealedPayloadPack {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V2SealedPayloadPack")
            .field("layout", &self.layout)
            .field("stored_len", &self.bytes.len())
            .finish()
    }
}

impl V2SealedPayloadPack {
    /// Returns the facts needed to construct encrypted index pointers.
    #[must_use]
    pub const fn layout(&self) -> &V2PayloadPackLayout {
        &self.layout
    }

    /// Returns complete ciphertext-only stored bytes.
    #[must_use]
    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// Consumes the pack and returns complete ciphertext-only stored bytes.
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }
}

/// Exact ciphertext span needed for a plaintext range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2PayloadPackRecordSpan {
    /// Absolute offset from the payload-pack object start.
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

/// Complete authenticated context needed to open one packed record.
///
/// Keeping these facts together prevents callers from accidentally combining
/// a record descriptor with a different pack, commit, or section identity.
#[derive(Clone, Copy)]
pub struct V2PayloadPackRecordContext<'a> {
    object: PayloadPackContext<'a>,
    facts: &'a V2PayloadPackFacts,
    record: &'a V2PayloadPackRecordRef,
    plaintext_len: u64,
}

impl fmt::Debug for V2PayloadPackRecordContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V2PayloadPackRecordContext")
            .field("section_ordinal", &self.object.section_ordinal)
            .field("facts", self.facts)
            .field("record", self.record)
            .field("plaintext_len", &self.plaintext_len)
            .finish_non_exhaustive()
    }
}

impl<'a> V2PayloadPackRecordContext<'a> {
    /// Validates and binds all facts required for exact range planning and AEAD.
    pub fn new(
        repository_context: &'a [u8],
        containing_object: &'a BackendObjectId,
        section_ordinal: u32,
        facts: &'a V2PayloadPackFacts,
        record: &'a V2PayloadPackRecordRef,
        plaintext_len: u64,
    ) -> V2Result<Self> {
        validate_public_context(repository_context, containing_object)?;
        validate_v2_payload_pack_record_ref(facts, record, plaintext_len)?;
        Ok(Self {
            object: PayloadPackContext {
                repository_context,
                containing_object,
                section_ordinal,
            },
            facts,
            record,
            plaintext_len,
        })
    }
}

/// Seals a bounded set of logical values into a ciphertext-only pack.
pub fn seal_v2_payload_pack(
    keyring: &KeyRing,
    repository_context: &[u8],
    containing_object: &BackendObjectId,
    section_ordinal: u32,
    records: &[V2PayloadPackRecordInput],
) -> V2Result<V2SealedPayloadPack> {
    let mut pack_id = [0_u8; V2_PAYLOAD_PACK_ID_LEN];
    fill_random(&mut pack_id).map_err(|_| V2FormatError::RandomnessUnavailable)?;
    let order = random_physical_order(records.len())?;
    seal_v2_payload_pack_with_layout(
        keyring,
        repository_context,
        containing_object,
        section_ordinal,
        records,
        V2PayloadPackId::from_bytes(pack_id),
        &order,
    )
}

fn seal_v2_payload_pack_with_layout(
    keyring: &KeyRing,
    repository_context: &[u8],
    containing_object: &BackendObjectId,
    section_ordinal: u32,
    inputs: &[V2PayloadPackRecordInput],
    pack_id: V2PayloadPackId,
    physical_order: &[usize],
) -> V2Result<V2SealedPayloadPack> {
    validate_public_context(repository_context, containing_object)?;
    if inputs.is_empty() || inputs.len() > V2_PAYLOAD_PACK_MAX_RECORDS {
        return Err(V2FormatError::PayloadPackLimitExceeded);
    }
    validate_physical_order(physical_order, inputs.len())?;

    let content_key_id = keyring.primary_content_key_id()?;
    if content_key_id.as_str().is_empty() || content_key_id.as_str().len() > MAX_KEY_ID_LEN {
        return Err(V2FormatError::PayloadPackLimitExceeded);
    }

    let mut records = Vec::with_capacity(inputs.len());
    for (ordinal, input) in inputs.iter().enumerate() {
        let plaintext_len = u64::try_from(input.plaintext.len())
            .map_err(|_| V2FormatError::PayloadPackLimitExceeded)?;
        record_stored_len(plaintext_len)?;
        records.push(V2PayloadPackRecord {
            reference: V2PayloadPackRecordRef::new(
                u32::try_from(ordinal).map_err(|_| V2FormatError::PayloadPackLimitExceeded)?,
                0,
            ),
            plaintext_len,
        });
    }

    let mut stored_len = 0_u32;
    for logical_ordinal in physical_order {
        let record = records
            .get_mut(*logical_ordinal)
            .ok_or(V2FormatError::InvalidPayloadPack)?;
        record.reference.physical_offset = stored_len;
        stored_len = stored_len
            .checked_add(record.stored_len()?)
            .ok_or(V2FormatError::PayloadPackLimitExceeded)?;
    }
    if stored_len as usize > V2_PAYLOAD_PACK_MAX_BYTES {
        return Err(V2FormatError::PayloadPackLimitExceeded);
    }

    let facts = V2PayloadPackFacts::new(
        pack_id,
        content_key_id,
        stored_len,
        u32::try_from(records.len()).map_err(|_| V2FormatError::PayloadPackLimitExceeded)?,
    )?;
    let layout = V2PayloadPackLayout::new(facts, records)?;
    let mut stored = vec![0_u8; stored_len as usize];
    let context = PayloadPackContext {
        repository_context,
        containing_object,
        section_ordinal,
    };
    for (logical_ordinal, input) in inputs.iter().enumerate() {
        let record = layout
            .records
            .get(logical_ordinal)
            .ok_or(V2FormatError::InvalidPayloadPack)?;
        seal_record_into(
            keyring,
            context,
            layout.facts(),
            &record.reference,
            record.plaintext_len,
            &input.plaintext,
            &mut stored,
        )?;
    }

    Ok(V2SealedPayloadPack {
        layout,
        bytes: Bytes::from(stored),
    })
}

/// Validates one externally supplied record reference against shared pack facts.
///
/// The reference need not cover any other record in the pack. Exact whole-pack
/// coverage is enforced only by [`V2PayloadPackLayout::new`].
pub fn validate_v2_payload_pack_record_ref(
    facts: &V2PayloadPackFacts,
    record: &V2PayloadPackRecordRef,
    plaintext_len: u64,
) -> V2Result<()> {
    if record.record_ordinal >= facts.record_count {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    let stored_len = record_stored_len(plaintext_len)?;
    let end = record
        .physical_offset
        .checked_add(stored_len)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    if end > facts.stored_len {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    Ok(())
}

/// Plans the one contiguous ciphertext range needed for a plaintext range.
pub fn plan_v2_payload_pack_record_range(
    facts: &V2PayloadPackFacts,
    record: &V2PayloadPackRecordRef,
    plaintext_len: u64,
    requested: Range<u64>,
) -> V2Result<V2PayloadPackRecordSpan> {
    validate_v2_payload_pack_record_ref(facts, record, plaintext_len)?;
    let empty_record = plaintext_len == 0;
    if (empty_record && requested != (0..0))
        || (!empty_record && (requested.start >= requested.end || requested.end > plaintext_len))
    {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    let segment_size = V2_PAYLOAD_PACK_SEGMENT_BYTES as u64;
    let start_segment = if empty_record {
        0
    } else {
        requested.start / segment_size
    };
    let end_segment = if empty_record {
        0
    } else {
        requested
            .end
            .checked_sub(1)
            .ok_or(V2FormatError::InvalidPayloadPack)?
            / segment_size
    };
    let segment_count = end_segment
        .checked_sub(start_segment)
        .and_then(|count| count.checked_add(1))
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let relative_start = segment_ciphertext_offset(start_segment)?;
    let relative_end = segment_ciphertext_offset(end_segment)?
        .checked_add(segment_plaintext_len(plaintext_len, end_segment)?)
        .and_then(|end| end.checked_add(AEAD_TAG_LEN))
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let offset = u64::from(record.physical_offset)
        .checked_add(relative_start)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let stored_len = relative_end
        .checked_sub(relative_start)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    if offset.checked_add(stored_len) > Some(u64::from(facts.stored_len)) {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    Ok(V2PayloadPackRecordSpan {
        offset,
        stored_len,
        start_segment: u32::try_from(start_segment)
            .map_err(|_| V2FormatError::InvalidPayloadPack)?,
        segment_count: u32::try_from(segment_count)
            .map_err(|_| V2FormatError::InvalidPayloadPack)?,
        record_ordinal: record.record_ordinal,
        requested,
    })
}

/// Authenticates and opens an exact planned ciphertext span.
pub fn open_v2_payload_pack_record_span(
    keyring: &KeyRing,
    context: &V2PayloadPackRecordContext<'_>,
    span: &V2PayloadPackRecordSpan,
    ciphertext_span: &[u8],
) -> V2Result<Bytes> {
    open_v2_payload_pack_record_span_with_segments(keyring, context, span, ciphertext_span)
        .map(|opened| opened.plaintext)
}

/// Authenticates an exact span while retaining complete segments for caching.
pub fn open_v2_payload_pack_record_span_with_segments(
    keyring: &KeyRing,
    context: &V2PayloadPackRecordContext<'_>,
    span: &V2PayloadPackRecordSpan,
    ciphertext_span: &[u8],
) -> V2Result<V2OpenedPayloadPackRecordSpan> {
    let expected = plan_v2_payload_pack_record_range(
        context.facts,
        context.record,
        context.plaintext_len,
        span.requested.clone(),
    )?;
    if &expected != span
        || span.record_ordinal != context.record.record_ordinal
        || usize::try_from(span.stored_len).ok() != Some(ciphertext_span.len())
    {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    let start_segment = u64::from(span.start_segment);
    let segment_count = u64::from(span.segment_count);
    let mut cursor = 0_usize;
    let mut selected_plaintext = Vec::new();
    let mut segments = Vec::with_capacity(span.segment_count as usize);
    for relative_segment in 0..segment_count {
        let segment_ordinal = start_segment
            .checked_add(relative_segment)
            .ok_or(V2FormatError::InvalidPayloadPack)?;
        let segment_plaintext_len = segment_plaintext_len(context.plaintext_len, segment_ordinal)?;
        let stored_len = segment_plaintext_len
            .checked_add(AEAD_TAG_LEN)
            .and_then(|length| usize::try_from(length).ok())
            .ok_or(V2FormatError::InvalidPayloadPack)?;
        let end = cursor
            .checked_add(stored_len)
            .ok_or(V2FormatError::InvalidPayloadPack)?;
        let ciphertext = ciphertext_span
            .get(cursor..end)
            .ok_or(V2FormatError::TruncatedBody)?;
        let aad = segment_associated_data(
            context.object,
            context.facts,
            context.record,
            context.plaintext_len,
            segment_ordinal,
            segment_plaintext_len,
        )?;
        let nonce_context = segment_nonce_context(
            context.facts.pack_id,
            context.record.record_ordinal,
            segment_ordinal,
        );
        let plaintext = keyring.open_payload_pack_segment(
            context.facts.content_key_id(),
            &aad,
            &nonce_context,
            ciphertext,
        )?;
        if u64::try_from(plaintext.len()).ok() != Some(segment_plaintext_len) {
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
    finish_opened_span(span, selected_plaintext, segments)
}

/// Reassembles an exact planned range from authenticated cached segments.
pub fn open_v2_payload_pack_cached_record_span(
    facts: &V2PayloadPackFacts,
    record: &V2PayloadPackRecordRef,
    plaintext_len: u64,
    span: &V2PayloadPackRecordSpan,
    plaintext_segments: &[Bytes],
) -> V2Result<Bytes> {
    let expected =
        plan_v2_payload_pack_record_range(facts, record, plaintext_len, span.requested.clone())?;
    if &expected != span || plaintext_segments.len() != span.segment_count as usize {
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
            != Some(segment_plaintext_len(plaintext_len, segment_ordinal)?)
        {
            return Err(V2FormatError::InvalidPayloadPack);
        }
        selected_plaintext.extend_from_slice(plaintext);
    }
    finish_opened_span(span, selected_plaintext, Vec::new()).map(|opened| opened.plaintext)
}

/// Opens one range from complete ciphertext-only pack bytes.
pub fn open_v2_payload_pack_record_range(
    keyring: &KeyRing,
    context: &V2PayloadPackRecordContext<'_>,
    pack: &[u8],
    requested: Range<u64>,
) -> V2Result<Bytes> {
    if pack.len() != context.facts.stored_len as usize {
        return Err(V2FormatError::TruncatedBody);
    }
    let span = plan_v2_payload_pack_record_range(
        context.facts,
        context.record,
        context.plaintext_len,
        requested,
    )?;
    let start = usize::try_from(span.offset).map_err(|_| V2FormatError::InvalidPayloadPack)?;
    let end = span
        .offset
        .checked_add(span.stored_len)
        .and_then(|end| usize::try_from(end).ok())
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let ciphertext = pack.get(start..end).ok_or(V2FormatError::TruncatedBody)?;
    open_v2_payload_pack_record_span(keyring, context, &span, ciphertext)
}

/// Opens one complete logical record from complete ciphertext-only pack bytes.
pub fn open_v2_payload_pack_record(
    keyring: &KeyRing,
    context: &V2PayloadPackRecordContext<'_>,
    pack: &[u8],
) -> V2Result<Bytes> {
    open_v2_payload_pack_record_range(keyring, context, pack, 0..context.plaintext_len)
}

fn finish_opened_span(
    span: &V2PayloadPackRecordSpan,
    selected_plaintext: Vec<u8>,
    segments: Vec<(u32, Bytes)>,
) -> V2Result<V2OpenedPayloadPackRecordSpan> {
    let selected_start = u64::from(span.start_segment)
        .checked_mul(V2_PAYLOAD_PACK_SEGMENT_BYTES as u64)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let trim_start = span
        .requested
        .start
        .checked_sub(selected_start)
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let requested_len = span
        .requested
        .end
        .checked_sub(span.requested.start)
        .and_then(|length| usize::try_from(length).ok())
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let trim_end = trim_start
        .checked_add(requested_len)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    let requested = selected_plaintext
        .get(trim_start..trim_end)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    Ok(V2OpenedPayloadPackRecordSpan {
        plaintext: Bytes::copy_from_slice(requested),
        segments,
    })
}

fn validate_record_coverage(
    facts: &V2PayloadPackFacts,
    records: &[V2PayloadPackRecord],
) -> V2Result<()> {
    let mut spans = records
        .iter()
        .map(|record| {
            let end = record
                .reference
                .physical_offset
                .checked_add(record.stored_len()?)
                .ok_or(V2FormatError::InvalidPayloadPack)?;
            Ok((record.reference.physical_offset, end))
        })
        .collect::<V2Result<Vec<_>>>()?;
    spans.sort_unstable();
    let mut expected_start = 0_u32;
    for (start, end) in spans {
        if start != expected_start || end <= start || end > facts.stored_len {
            return Err(V2FormatError::InvalidPayloadPack);
        }
        expected_start = end;
    }
    if expected_start != facts.stored_len {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    Ok(())
}

fn seal_record_into(
    keyring: &KeyRing,
    context: PayloadPackContext<'_>,
    facts: &V2PayloadPackFacts,
    record: &V2PayloadPackRecordRef,
    plaintext_len: u64,
    plaintext: &[u8],
    pack: &mut [u8],
) -> V2Result<()> {
    if u64::try_from(plaintext.len()).ok() != Some(plaintext_len) {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    let count = segment_count(plaintext_len)?;
    for segment_ordinal in 0..count {
        let plaintext_start = segment_ordinal
            .checked_mul(V2_PAYLOAD_PACK_SEGMENT_BYTES as u64)
            .ok_or(V2FormatError::PayloadPackLimitExceeded)?;
        let segment_plaintext_len = segment_plaintext_len(plaintext_len, segment_ordinal)?;
        let plaintext_end = plaintext_start
            .checked_add(segment_plaintext_len)
            .ok_or(V2FormatError::PayloadPackLimitExceeded)?;
        let plaintext_segment = plaintext
            .get(
                usize::try_from(plaintext_start)
                    .map_err(|_| V2FormatError::PayloadPackLimitExceeded)?
                    ..usize::try_from(plaintext_end)
                        .map_err(|_| V2FormatError::PayloadPackLimitExceeded)?,
            )
            .ok_or(V2FormatError::InvalidPayloadPack)?;
        let aad = segment_associated_data(
            context,
            facts,
            record,
            plaintext_len,
            segment_ordinal,
            segment_plaintext_len,
        )?;
        let nonce_context =
            segment_nonce_context(facts.pack_id, record.record_ordinal, segment_ordinal);
        let sealed = keyring.seal_payload_pack_segment(&aad, &nonce_context, plaintext_segment)?;
        if sealed.key_id != *facts.content_key_id()
            || u64::try_from(sealed.ciphertext.len()).ok()
                != segment_plaintext_len.checked_add(AEAD_TAG_LEN)
        {
            return Err(V2FormatError::CryptoOperation);
        }
        let start = u64::from(record.physical_offset)
            .checked_add(segment_ciphertext_offset(segment_ordinal)?)
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or(V2FormatError::PayloadPackLimitExceeded)?;
        let end = start
            .checked_add(sealed.ciphertext.len())
            .ok_or(V2FormatError::PayloadPackLimitExceeded)?;
        pack.get_mut(start..end)
            .ok_or(V2FormatError::InvalidPayloadPack)?
            .copy_from_slice(&sealed.ciphertext);
    }
    Ok(())
}

fn segment_associated_data(
    context: PayloadPackContext<'_>,
    facts: &V2PayloadPackFacts,
    record: &V2PayloadPackRecordRef,
    plaintext_len: u64,
    segment_ordinal: u64,
    segment_plaintext_len: u64,
) -> V2Result<Vec<u8>> {
    let mut aad = Vec::new();
    aad.extend_from_slice(PAYLOAD_PACK_SEGMENT_AAD_DOMAIN);
    push_framed(&mut aad, context.repository_context)?;
    push_framed(&mut aad, context.containing_object.as_str().as_bytes())?;
    aad.extend_from_slice(&context.section_ordinal.to_be_bytes());
    aad.extend_from_slice(facts.pack_id.as_bytes());
    push_framed(&mut aad, facts.content_key_id.as_str().as_bytes())?;
    aad.extend_from_slice(&facts.stored_len.to_be_bytes());
    aad.extend_from_slice(&facts.record_count.to_be_bytes());
    aad.extend_from_slice(&record.record_ordinal.to_be_bytes());
    aad.extend_from_slice(&record.physical_offset.to_be_bytes());
    aad.extend_from_slice(&plaintext_len.to_be_bytes());
    aad.extend_from_slice(&segment_ordinal.to_be_bytes());
    aad.extend_from_slice(&segment_ciphertext_offset(segment_ordinal)?.to_be_bytes());
    aad.extend_from_slice(&segment_plaintext_len.to_be_bytes());
    aad.extend_from_slice(
        &segment_plaintext_len
            .checked_add(AEAD_TAG_LEN)
            .ok_or(V2FormatError::InvalidPayloadPack)?
            .to_be_bytes(),
    );
    aad.push(u8::from(
        segment_ordinal.checked_add(1) == Some(segment_count(plaintext_len)?),
    ));
    Ok(aad)
}

fn segment_nonce_context(
    pack_id: V2PayloadPackId,
    record_ordinal: u32,
    segment_ordinal: u64,
) -> Vec<u8> {
    let mut context = Vec::with_capacity(
        PAYLOAD_PACK_SEGMENT_NONCE_CONTEXT_DOMAIN.len() + V2_PAYLOAD_PACK_ID_LEN + 4 + 8,
    );
    context.extend_from_slice(PAYLOAD_PACK_SEGMENT_NONCE_CONTEXT_DOMAIN);
    context.extend_from_slice(pack_id.as_bytes());
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

fn segment_count(plaintext_len: u64) -> V2Result<u64> {
    if plaintext_len == 0 {
        return Ok(1);
    }
    plaintext_len
        .checked_add(V2_PAYLOAD_PACK_SEGMENT_BYTES as u64 - 1)
        .map(|rounded| rounded / V2_PAYLOAD_PACK_SEGMENT_BYTES as u64)
        .ok_or(V2FormatError::PayloadPackLimitExceeded)
}

fn record_stored_len(plaintext_len: u64) -> V2Result<u32> {
    let stored_len = plaintext_len
        .checked_add(
            segment_count(plaintext_len)?
                .checked_mul(AEAD_TAG_LEN)
                .ok_or(V2FormatError::PayloadPackLimitExceeded)?,
        )
        .ok_or(V2FormatError::PayloadPackLimitExceeded)?;
    let stored_len =
        u32::try_from(stored_len).map_err(|_| V2FormatError::PayloadPackLimitExceeded)?;
    if stored_len as usize > V2_PAYLOAD_PACK_MAX_BYTES {
        return Err(V2FormatError::PayloadPackLimitExceeded);
    }
    Ok(stored_len)
}

fn segment_plaintext_len(plaintext_len: u64, segment_ordinal: u64) -> V2Result<u64> {
    let count = segment_count(plaintext_len)?;
    if segment_ordinal >= count {
        return Err(V2FormatError::InvalidPayloadPack);
    }
    let start = segment_ordinal
        .checked_mul(V2_PAYLOAD_PACK_SEGMENT_BYTES as u64)
        .ok_or(V2FormatError::InvalidPayloadPack)?;
    Ok(plaintext_len
        .saturating_sub(start)
        .min(V2_PAYLOAD_PACK_SEGMENT_BYTES as u64))
}

fn segment_ciphertext_offset(segment_ordinal: u64) -> V2Result<u64> {
    segment_ordinal
        .checked_mul(V2_PAYLOAD_PACK_SEGMENT_BYTES as u64 + AEAD_TAG_LEN)
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

#[cfg(test)]
mod tests {
    use super::*;
    use rs3_crypto::{KeyMaterial, SecretBytes};
    use rs3_types::{KeyDescriptor, KeyPurpose, KeyStatus};

    const REPOSITORY_CONTEXT: &[u8] = b"repository-format-root-generation-4";
    const SECTION_ORDINAL: u32 = 2;

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
            REPOSITORY_CONTEXT,
            &object_id("commits/opaque-commit"),
            SECTION_ORDINAL,
            &[
                V2PayloadPackRecordInput {
                    plaintext: Bytes::from_static(b"abcdefghijk"),
                },
                V2PayloadPackRecordInput {
                    plaintext: Bytes::from_static(b"range-friendly-value"),
                },
            ],
            V2PayloadPackId::from_bytes([9_u8; V2_PAYLOAD_PACK_ID_LEN]),
            &[1, 0],
        ))
    }

    fn open_record(pack: &V2SealedPayloadPack, ordinal: u32) -> V2Result<Bytes> {
        let containing_object = object_id("commits/opaque-commit");
        let record = pack
            .layout()
            .record(ordinal)
            .ok_or(V2FormatError::InvalidPayloadPack)?;
        let context = V2PayloadPackRecordContext::new(
            REPOSITORY_CONTEXT,
            &containing_object,
            SECTION_ORDINAL,
            pack.layout().facts(),
            record,
            record.plaintext_len(),
        )?;
        open_v2_payload_pack_record(&keyring(), &context, pack.bytes())
    }

    #[test]
    fn pack_is_ciphertext_only_and_round_trips_shuffled_records() {
        let pack = sample_pack();
        assert_eq!(
            pack.bytes().len(),
            pack.layout().facts().stored_len() as usize
        );
        assert_eq!(pack.layout().records()[1].physical_offset(), 0);
        assert!(pack.layout().records()[0].physical_offset() > 0);
        assert_eq!(
            must_v2(open_record(&pack, 0)),
            Bytes::from_static(b"abcdefghijk")
        );
        assert_eq!(
            must_v2(open_record(&pack, 1)),
            Bytes::from_static(b"range-friendly-value")
        );
    }

    #[test]
    fn production_seal_attempts_use_fresh_pack_identities() {
        let records = [V2PayloadPackRecordInput {
            plaintext: Bytes::from_static(b"same logical record"),
        }];
        let containing_object = object_id("commits/opaque-commit");
        let first = must_v2(seal_v2_payload_pack(
            &keyring(),
            REPOSITORY_CONTEXT,
            &containing_object,
            SECTION_ORDINAL,
            &records,
        ));
        let second = must_v2(seal_v2_payload_pack(
            &keyring(),
            REPOSITORY_CONTEXT,
            &containing_object,
            SECTION_ORDINAL,
            &records,
        ));

        assert_ne!(
            first.layout().facts().pack_id(),
            second.layout().facts().pack_id()
        );
        assert_ne!(first.bytes(), second.bytes());
        assert_eq!(must_v2(open_record(&first, 0)), records[0].plaintext);
        assert_eq!(must_v2(open_record(&second, 0)), records[0].plaintext);
    }

    #[test]
    fn segment_reorder_and_cross_record_transplant_fail_closed() {
        let plaintext_len = V2_PAYLOAD_PACK_SEGMENT_BYTES * 2;
        let records = [
            V2PayloadPackRecordInput {
                plaintext: Bytes::from(vec![0x41; plaintext_len]),
            },
            V2PayloadPackRecordInput {
                plaintext: Bytes::from(vec![0x42; plaintext_len]),
            },
        ];
        let pack = must_v2(seal_v2_payload_pack_with_layout(
            &keyring(),
            REPOSITORY_CONTEXT,
            &object_id("commits/opaque-commit"),
            SECTION_ORDINAL,
            &records,
            V2PayloadPackId::from_bytes([0x31; V2_PAYLOAD_PACK_ID_LEN]),
            &[0, 1],
        ));
        let segment_stored_len = V2_PAYLOAD_PACK_SEGMENT_BYTES + AEAD_TAG_LEN as usize;
        let first_offset = pack
            .layout()
            .record(0)
            .expect("first record")
            .physical_offset() as usize;
        let second_offset = pack
            .layout()
            .record(1)
            .expect("second record")
            .physical_offset() as usize;

        let mut reordered = pack.bytes().to_vec();
        reordered[first_offset..first_offset + segment_stored_len * 2]
            .rotate_left(segment_stored_len);
        let first = pack.layout().record(0).expect("first record");
        let containing_object = object_id("commits/opaque-commit");
        let context = must_v2(V2PayloadPackRecordContext::new(
            REPOSITORY_CONTEXT,
            &containing_object,
            SECTION_ORDINAL,
            pack.layout().facts(),
            first,
            first.plaintext_len(),
        ));
        assert!(open_v2_payload_pack_record(&keyring(), &context, &reordered).is_err());

        let mut transplanted = pack.bytes().to_vec();
        let source = pack.bytes()[second_offset..second_offset + segment_stored_len].to_vec();
        transplanted[first_offset..first_offset + segment_stored_len].copy_from_slice(&source);
        assert!(open_v2_payload_pack_record(&keyring(), &context, &transplanted).is_err());
    }

    #[test]
    fn range_plan_fetches_only_intersecting_canonical_segments_and_caches_them() {
        let plaintext = Bytes::from(
            (0..(V2_PAYLOAD_PACK_SEGMENT_BYTES * 2 + 32))
                .map(|offset| (offset % 251) as u8)
                .collect::<Vec<_>>(),
        );
        let pack = must_v2(seal_v2_payload_pack_with_layout(
            &keyring(),
            REPOSITORY_CONTEXT,
            &object_id("commits/opaque-commit"),
            SECTION_ORDINAL,
            &[V2PayloadPackRecordInput {
                plaintext: plaintext.clone(),
            }],
            V2PayloadPackId::from_bytes([13_u8; V2_PAYLOAD_PACK_ID_LEN]),
            &[0],
        ));
        let facts = pack.layout().facts();
        let record = pack.layout().record(0).expect("record exists");
        let requested =
            (V2_PAYLOAD_PACK_SEGMENT_BYTES as u64 - 8)..(V2_PAYLOAD_PACK_SEGMENT_BYTES as u64 + 8);
        let span = must_v2(plan_v2_payload_pack_record_range(
            facts,
            record,
            record.plaintext_len(),
            requested.clone(),
        ));
        assert_eq!(span.offset, u64::from(record.physical_offset()));
        assert_eq!(span.start_segment, 0);
        assert_eq!(span.segment_count, 2);
        assert_eq!(
            span.stored_len,
            (V2_PAYLOAD_PACK_SEGMENT_BYTES * 2) as u64 + AEAD_TAG_LEN * 2
        );
        let start = span.offset as usize;
        let end = start + span.stored_len as usize;
        let containing_object = object_id("commits/opaque-commit");
        let context = must_v2(V2PayloadPackRecordContext::new(
            REPOSITORY_CONTEXT,
            &containing_object,
            SECTION_ORDINAL,
            facts,
            record,
            record.plaintext_len(),
        ));
        let opened = must_v2(open_v2_payload_pack_record_span_with_segments(
            &keyring(),
            &context,
            &span,
            &pack.bytes()[start..end],
        ));
        assert_eq!(opened.segments.len(), 2);
        assert_eq!(
            opened.plaintext.as_ref(),
            &plaintext[requested.start as usize..requested.end as usize]
        );
        let cached = opened
            .segments
            .iter()
            .map(|(_, plaintext)| plaintext.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            must_v2(open_v2_payload_pack_cached_record_span(
                facts,
                record,
                record.plaintext_len(),
                &span,
                &cached
            )),
            opened.plaintext
        );
        assert!(
            open_v2_payload_pack_cached_record_span(
                facts,
                record,
                record.plaintext_len(),
                &span,
                &cached[..1]
            )
            .is_err()
        );
    }

    #[test]
    fn empty_record_is_one_authenticated_tag() {
        let pack = must_v2(seal_v2_payload_pack_with_layout(
            &keyring(),
            REPOSITORY_CONTEXT,
            &object_id("commits/opaque-commit"),
            SECTION_ORDINAL,
            &[V2PayloadPackRecordInput {
                plaintext: Bytes::new(),
            }],
            V2PayloadPackId::from_bytes([3_u8; V2_PAYLOAD_PACK_ID_LEN]),
            &[0],
        ));
        assert_eq!(pack.bytes().len(), AEAD_TAG_LEN as usize);
        assert_eq!(must_v2(open_record(&pack, 0)), Bytes::new());
    }

    #[test]
    fn context_and_every_authenticated_index_fact_fail_closed() {
        let pack = sample_pack();
        let facts = pack.layout().facts();
        let record = pack.layout().record(0).expect("record exists");
        let containing_object = object_id("commits/opaque-commit");
        let open = |facts: &V2PayloadPackFacts, record: &V2PayloadPackRecordRef| {
            let context = V2PayloadPackRecordContext::new(
                REPOSITORY_CONTEXT,
                &containing_object,
                SECTION_ORDINAL,
                facts,
                record,
                11,
            )?;
            open_v2_payload_pack_record(&keyring(), &context, pack.bytes())
        };

        let open_with = |repository_context: &[u8],
                         containing_object: &BackendObjectId,
                         section_ordinal: u32,
                         facts: &V2PayloadPackFacts,
                         record: &V2PayloadPackRecordRef,
                         plaintext_len: u64,
                         bytes: &[u8]| {
            let context = V2PayloadPackRecordContext::new(
                repository_context,
                containing_object,
                section_ordinal,
                facts,
                record,
                plaintext_len,
            )?;
            open_v2_payload_pack_record(&keyring(), &context, bytes)
        };

        assert!(
            open_with(
                b"other-repository",
                &containing_object,
                SECTION_ORDINAL,
                facts,
                record,
                record.plaintext_len(),
                pack.bytes(),
            )
            .is_err()
        );
        let other_object = object_id("commits/other");
        assert!(
            open_with(
                REPOSITORY_CONTEXT,
                &other_object,
                SECTION_ORDINAL,
                facts,
                record,
                record.plaintext_len(),
                pack.bytes(),
            )
            .is_err()
        );
        assert!(
            open_with(
                REPOSITORY_CONTEXT,
                &containing_object,
                SECTION_ORDINAL + 1,
                facts,
                record,
                record.plaintext_len(),
                pack.bytes(),
            )
            .is_err()
        );

        let mut bad_facts = facts.clone();
        bad_facts.pack_id = V2PayloadPackId::from_bytes([8_u8; V2_PAYLOAD_PACK_ID_LEN]);
        assert!(open(&bad_facts, record).is_err());
        bad_facts = facts.clone();
        bad_facts.content_key_id = match KeyId::new("unknown-content-key".to_owned()) {
            Ok(key_id) => key_id,
            Err(error) => panic!("{error}"),
        };
        assert!(open(&bad_facts, record).is_err());
        bad_facts = facts.clone();
        bad_facts.stored_len += 1;
        assert!(open(&bad_facts, record).is_err());
        bad_facts = facts.clone();
        bad_facts.record_count += 1;
        assert!(open(&bad_facts, record).is_err());

        let mut bad_record = record.reference().clone();
        bad_record.record_ordinal += 1;
        assert!(open(facts, &bad_record).is_err());
        bad_record = record.reference().clone();
        bad_record.physical_offset += 1;
        assert!(open(facts, &bad_record).is_err());
        assert!(
            open_with(
                REPOSITORY_CONTEXT,
                &containing_object,
                SECTION_ORDINAL,
                facts,
                record,
                record.plaintext_len() - 1,
                pack.bytes(),
            )
            .is_err()
        );
        let mut ciphertext = pack.bytes().to_vec();
        ciphertext[record.physical_offset() as usize] ^= 1;
        assert!(
            open_with(
                REPOSITORY_CONTEXT,
                &containing_object,
                SECTION_ORDINAL,
                facts,
                record,
                record.plaintext_len(),
                &ciphertext,
            )
            .is_err()
        );
    }

    #[test]
    fn every_ciphertext_truncation_fails_closed() {
        let pack = sample_pack();
        let facts = pack.layout().facts();
        let record = pack.layout().record(0).expect("record exists");
        let span = must_v2(plan_v2_payload_pack_record_range(
            facts,
            record,
            record.plaintext_len(),
            0..record.plaintext_len(),
        ));
        let start = span.offset as usize;
        let end = start + span.stored_len as usize;
        let ciphertext = &pack.bytes()[start..end];
        let containing_object = object_id("commits/opaque-commit");
        let context = must_v2(V2PayloadPackRecordContext::new(
            REPOSITORY_CONTEXT,
            &containing_object,
            SECTION_ORDINAL,
            facts,
            record,
            record.plaintext_len(),
        ));
        for length in 0..ciphertext.len() {
            assert!(
                open_v2_payload_pack_record_span(
                    &keyring(),
                    &context,
                    &span,
                    &ciphertext[..length],
                )
                .is_err(),
                "truncation at {length} bytes was accepted"
            );
        }
        for length in 0..pack.bytes().len() {
            assert!(
                open_v2_payload_pack_record(&keyring(), &context, &pack.bytes()[..length]).is_err()
            );
        }
    }

    #[test]
    fn sixty_four_small_values_have_only_record_ciphertext_overhead() {
        let records = (0..64)
            .map(|ordinal| V2PayloadPackRecordInput {
                plaintext: Bytes::from(vec![ordinal as u8; 512]),
            })
            .collect::<Vec<_>>();
        let order = (0..records.len()).rev().collect::<Vec<_>>();
        let pack = must_v2(seal_v2_payload_pack_with_layout(
            &keyring(),
            REPOSITORY_CONTEXT,
            &object_id("commits/opaque-commit"),
            SECTION_ORDINAL,
            &records,
            V2PayloadPackId::from_bytes([11_u8; V2_PAYLOAD_PACK_ID_LEN]),
            &order,
        ));
        assert_eq!(pack.bytes().len(), 64 * (512 + AEAD_TAG_LEN as usize));
        assert_eq!(pack.layout().records().len(), 64);
    }

    #[test]
    fn bulk_pack_accepts_and_opens_the_bounded_record_ceiling() {
        let keyring = keyring();
        let containing_object = object_id("commits/opaque-commit");
        let records = (0..V2_PAYLOAD_PACK_MAX_RECORDS)
            .map(|ordinal| V2PayloadPackRecordInput {
                plaintext: Bytes::from(vec![ordinal as u8]),
            })
            .collect::<Vec<_>>();
        let pack = must_v2(seal_v2_payload_pack(
            &keyring,
            REPOSITORY_CONTEXT,
            &containing_object,
            SECTION_ORDINAL,
            &records,
        ));
        assert_eq!(
            pack.bytes().len(),
            V2_PAYLOAD_PACK_MAX_RECORDS * (1 + AEAD_TAG_LEN as usize)
        );
        assert_eq!(pack.layout().records().len(), V2_PAYLOAD_PACK_MAX_RECORDS);
        for ordinal in [
            0,
            V2_PAYLOAD_PACK_MAX_RECORDS / 2,
            V2_PAYLOAD_PACK_MAX_RECORDS - 1,
        ] {
            let record = pack.layout().record(ordinal as u32).expect("record exists");
            let context = must_v2(V2PayloadPackRecordContext::new(
                REPOSITORY_CONTEXT,
                &containing_object,
                SECTION_ORDINAL,
                pack.layout().facts(),
                record,
                record.plaintext_len(),
            ));
            assert_eq!(
                must_v2(open_v2_payload_pack_record(
                    &keyring,
                    &context,
                    pack.bytes()
                )),
                records[ordinal].plaintext
            );
        }
    }

    #[test]
    fn record_references_validate_bounds_without_requiring_full_layout() {
        let pack = sample_pack();
        let facts = pack.layout().facts();
        let live = pack.layout().record(1).expect("record exists").clone();
        assert!(validate_v2_payload_pack_record_ref(facts, &live, live.plaintext_len()).is_ok());

        let mut invalid = live.reference().clone();
        invalid.record_ordinal = facts.record_count();
        assert_eq!(
            validate_v2_payload_pack_record_ref(facts, &invalid, live.plaintext_len()),
            Err(V2FormatError::InvalidPayloadPack)
        );
        invalid = live.reference().clone();
        invalid.physical_offset = facts.stored_len();
        assert_eq!(
            validate_v2_payload_pack_record_ref(facts, &invalid, live.plaintext_len()),
            Err(V2FormatError::InvalidPayloadPack)
        );

        let partial = V2PayloadPackLayout::new(facts.clone(), vec![live]);
        assert_eq!(partial, Err(V2FormatError::InvalidPayloadPack));
    }

    #[test]
    fn complete_layout_rejects_gaps_overlaps_and_bad_logical_ordinals() {
        let pack = sample_pack();
        let facts = pack.layout().facts().clone();
        let records = pack.layout().records().to_vec();

        let mut gap = records.clone();
        gap[0].reference.physical_offset += 1;
        assert_eq!(
            V2PayloadPackLayout::new(facts.clone(), gap),
            Err(V2FormatError::InvalidPayloadPack)
        );
        let mut overlap = records.clone();
        overlap[0].reference.physical_offset = overlap[1].reference.physical_offset;
        assert_eq!(
            V2PayloadPackLayout::new(facts.clone(), overlap),
            Err(V2FormatError::InvalidPayloadPack)
        );
        let mut bad_ordinal = records;
        bad_ordinal[1].reference.record_ordinal = 0;
        assert_eq!(
            V2PayloadPackLayout::new(facts, bad_ordinal),
            Err(V2FormatError::InvalidPayloadPack)
        );
    }

    #[test]
    fn invalid_ranges_record_counts_and_sizes_are_rejected() {
        let pack = sample_pack();
        let facts = pack.layout().facts();
        let record = pack.layout().record(0).expect("record exists");
        assert!(
            plan_v2_payload_pack_record_range(facts, record, record.plaintext_len(), 4..4).is_err()
        );
        assert!(
            plan_v2_payload_pack_record_range(facts, record, record.plaintext_len(), 0..12)
                .is_err()
        );
        assert!(
            seal_v2_payload_pack_with_layout(
                &keyring(),
                REPOSITORY_CONTEXT,
                &object_id("commits/opaque-commit"),
                SECTION_ORDINAL,
                &[],
                V2PayloadPackId::from_bytes([0_u8; V2_PAYLOAD_PACK_ID_LEN]),
                &[],
            )
            .is_err()
        );
        let too_many = vec![
            V2PayloadPackRecordInput {
                plaintext: Bytes::new(),
            };
            V2_PAYLOAD_PACK_MAX_RECORDS + 1
        ];
        assert!(
            seal_v2_payload_pack(
                &keyring(),
                REPOSITORY_CONTEXT,
                &object_id("commits/opaque-commit"),
                SECTION_ORDINAL,
                &too_many,
            )
            .is_err()
        );
        assert!(record_stored_len(V2_PAYLOAD_PACK_MAX_BYTES as u64).is_err());
    }

    #[test]
    fn writer_rejects_content_key_ids_the_reader_cannot_encode() {
        let long_content_id = "c".repeat(MAX_KEY_ID_LEN + 1);
        let keyring = match KeyRing::new(vec![
            key_material("namespace", KeyPurpose::Namespace, "hmac-sha256", 1),
            key_material(
                &long_content_id,
                KeyPurpose::Content,
                "xchacha20poly1305",
                2,
            ),
            key_material(
                "metadata",
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
            REPOSITORY_CONTEXT,
            &object_id("commits/opaque-commit"),
            SECTION_ORDINAL,
            &[V2PayloadPackRecordInput {
                plaintext: Bytes::from_static(b"value"),
            }],
        );
        assert_eq!(result, Err(V2FormatError::PayloadPackLimitExceeded));
    }

    #[test]
    fn debug_output_redacts_plaintext_and_pack_identity() {
        let input = V2PayloadPackRecordInput {
            plaintext: Bytes::from_static(b"top-secret-payload"),
        };
        let debug = format!("{input:?}");
        assert!(!debug.contains("top-secret-payload"));
        assert!(debug.contains("plaintext_len"));

        let pack = sample_pack();
        let debug = format!("{pack:?}");
        assert!(!debug.contains("range-friendly-value"));
        assert!(!debug.contains(&format!("{:?}", [9_u8; V2_PAYLOAD_PACK_ID_LEN])));
        assert!(debug.contains("<redacted>"));
    }
}
