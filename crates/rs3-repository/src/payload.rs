//! Durable payload object envelope handling.

use crate::error::{RepositoryError, Result};
use bytes::Bytes;
use rs3_crypto::KeyRing;
use rs3_storage::{ByteRange, StorageError};
use rs3_types::{BackendObjectId, KeyId};

const PAYLOAD_OBJECT_DOMAIN: &[u8] = b"rs3:payload-object:v2-segmented\n";
const PAYLOAD_SEGMENT_AAD_DOMAIN: &[u8] = b"rs3:payload-segment-associated-data:v2\n";
const STREAMABLE_PAYLOAD_OBJECT_DOMAIN: &[u8] = b"rs3:payload-object:v2-streamable\n";
const STREAMABLE_PAYLOAD_SEGMENT_AAD_DOMAIN: &[u8] =
    b"rs3:payload-segment-associated-data:v2-streamable\n";
pub(crate) const PAYLOAD_HEADER_PROBE_LEN: u64 = 128;
/// Default plaintext bytes per independently encrypted payload segment.
pub const DEFAULT_PAYLOAD_SEGMENT_SIZE: usize = 512;
/// Maximum plaintext bytes accepted in one independently encrypted payload segment.
///
/// This bounds reader and writer working memory even when authenticated repository
/// metadata or operator configuration is malformed.
pub const MAX_PAYLOAD_SEGMENT_SIZE: usize = 64 * 1024 * 1024;
const MEDIUM_PAYLOAD_SEGMENT_SIZE: usize = 8 * 1024;
const LARGE_PAYLOAD_SEGMENT_SIZE: usize = 64 * 1024;
const MEDIUM_PAYLOAD_THRESHOLD: usize = 8 * 1024;
const LARGE_PAYLOAD_THRESHOLD: usize = 256 * 1024;
const U64_LEN: usize = 8;
const AEAD_TAG_LEN: u64 = 16;
const NONCE_PREFIX_LEN: usize = 16;
const XCHACHA20_NONCE_LEN: usize = 24;
const FINAL_SEGMENT_NONCE_FLAG: u64 = 1 << 63;

/// Result of a short payload header probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PayloadHeaderProbe {
    /// The object uses the segmented random-access format.
    Segmented { header_len: usize },
    /// More bytes are required to parse the complete header.
    NeedMore { len: u64 },
}

/// Parsed v2 segmented payload header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SegmentedPayloadHeader {
    pub(crate) format: SegmentedPayloadFormat,
    pub(crate) chunk_size: u64,
    pub(crate) plaintext_len: u64,
    pub(crate) key_id: KeyId,
    pub(crate) nonce_prefix: [u8; NONCE_PREFIX_LEN],
    pub(crate) header_len: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SegmentedPayloadFormat {
    LengthBearing,
    Streamable,
}

/// Streaming sealer for a streamable segmented payload object.
#[derive(Clone, Debug)]
pub(crate) struct SegmentedPayloadSealer {
    chunk_size: u64,
    key_id: KeyId,
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    header: Bytes,
}

impl SegmentedPayloadSealer {
    pub(crate) fn new(keyring: &KeyRing, chunk_size: usize) -> Result<Self> {
        if chunk_size == 0 || chunk_size > MAX_PAYLOAD_SEGMENT_SIZE {
            return Err(StorageError::Provider(format!(
                "payload chunk size must be between 1 and {MAX_PAYLOAD_SEGMENT_SIZE} bytes"
            ))
            .into());
        }
        let chunk_size = u64::try_from(chunk_size).map_err(|_| {
            StorageError::Provider("payload chunk size does not fit in u64".to_owned())
        })?;
        let key_id = keyring.primary_content_key_id()?;
        let nonce_prefix = random_nonce_prefix()?;
        let header = Bytes::from(streamable_segmented_payload_header_bytes(
            chunk_size,
            &key_id,
            &nonce_prefix,
        ));
        Ok(Self {
            chunk_size,
            key_id,
            nonce_prefix,
            header,
        })
    }

    pub(crate) fn header(&self) -> Bytes {
        self.header.clone()
    }

    pub(crate) fn header_reference(&self, plaintext_len: u64) -> Result<SegmentedPayloadHeader> {
        Ok(SegmentedPayloadHeader {
            format: SegmentedPayloadFormat::Streamable,
            chunk_size: self.chunk_size,
            plaintext_len,
            key_id: self.key_id.clone(),
            nonce_prefix: self.nonce_prefix,
            header_len: self.header.len(),
        })
    }

    pub(crate) fn sealed_len_for_plaintext_len(&self, plaintext_len: u64) -> Result<u64> {
        let segment_count = segment_count_for_len(plaintext_len, self.chunk_size)?;
        let ciphertext_len = plaintext_len
            .checked_add(
                segment_count
                    .checked_mul(AEAD_TAG_LEN)
                    .ok_or(StorageError::InvalidRange)?,
            )
            .ok_or(StorageError::InvalidRange)?;
        u64::try_from(self.header.len())
            .map_err(|_| StorageError::InvalidRange)?
            .checked_add(ciphertext_len)
            .ok_or_else(|| StorageError::InvalidRange.into())
    }

    pub(crate) fn seal_segment(
        &self,
        keyring: &KeyRing,
        object_id: &BackendObjectId,
        segment_index: usize,
        plaintext: &[u8],
        is_final: bool,
    ) -> Result<Bytes> {
        let segment_index_u64 =
            u64::try_from(segment_index).map_err(|_| StorageError::InvalidRange)?;
        let segment_plaintext_len =
            u64::try_from(plaintext.len()).map_err(|_| StorageError::InvalidRange)?;
        if segment_plaintext_len > self.chunk_size
            || (!is_final && segment_plaintext_len != self.chunk_size)
        {
            return Err(invalid_payload_object(object_id));
        }
        let nonce = segment_nonce(&self.nonce_prefix, segment_index_u64, is_final)?;
        let mut associated_data = Vec::with_capacity(segment_associated_data_capacity(object_id));
        write_streamable_segment_associated_data(
            &mut associated_data,
            object_id,
            self.chunk_size,
            segment_index_u64,
            is_final,
            segment_plaintext_len,
        );
        let seal = keyring.seal_payload_with_nonce(&associated_data, plaintext, &nonce)?;
        if seal.key_id != self.key_id {
            return Err(invalid_payload_object(object_id));
        }
        Ok(seal.ciphertext.into())
    }
}

/// Contiguous ciphertext span covering one or more selected segments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SegmentCiphertextSpan {
    pub(crate) offset: u64,
    pub(crate) len: u64,
    pub(crate) start_segment: usize,
    pub(crate) segment_count: usize,
}

/// Plaintext segment selection required for a client-visible range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SegmentPlaintextSelection {
    pub(crate) start_segment: usize,
    pub(crate) segment_count: usize,
}

/// Opened plaintext for a contiguous selected segment span.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OpenedSegmentedPayloadSpan {
    pub(crate) plaintext: Bytes,
    pub(crate) segments: Vec<(usize, Bytes)>,
}

/// Encrypts plaintext into a durable payload object body.
#[cfg(test)]
pub(crate) fn seal_payload_object(
    keyring: &KeyRing,
    object_id: &BackendObjectId,
    plaintext: &[u8],
    chunk_size: usize,
) -> Result<Bytes> {
    seal_segmented_payload_object(keyring, object_id, plaintext, chunk_size)
}

/// Encrypts plaintext into the streamable v2 commit-embedded payload format.
pub(crate) fn seal_streamable_payload_object(
    keyring: &KeyRing,
    object_id: &BackendObjectId,
    plaintext: &[u8],
    chunk_size: usize,
) -> Result<Bytes> {
    seal_streamable_segmented_payload_object(keyring, object_id, plaintext, chunk_size)
}

/// Selects an adaptive payload segment size for a plaintext object.
fn adaptive_payload_segment_size(plaintext_len: usize, configured_floor: usize) -> usize {
    let target = if plaintext_len < MEDIUM_PAYLOAD_THRESHOLD {
        DEFAULT_PAYLOAD_SEGMENT_SIZE
    } else if plaintext_len < LARGE_PAYLOAD_THRESHOLD {
        MEDIUM_PAYLOAD_SEGMENT_SIZE
    } else {
        LARGE_PAYLOAD_SEGMENT_SIZE
    };
    configured_floor.max(target)
}

/// Returns the payload segment size selected for an object under repository configuration.
pub fn effective_payload_segment_size(
    plaintext_len: usize,
    configured_size: usize,
    adaptive: bool,
) -> usize {
    if adaptive {
        adaptive_payload_segment_size(plaintext_len, configured_size)
    } else {
        configured_size
    }
}

/// Opens a durable payload object body and applies a client-visible range.
pub(crate) fn open_payload_object(
    keyring: &KeyRing,
    object_id: &BackendObjectId,
    body: Bytes,
    range: ByteRange,
) -> Result<Bytes> {
    let header = parse_segmented_payload_header(object_id, &body)?;
    open_segmented_payload_from_body(keyring, object_id, &header, body, range)
}

/// Probes enough bytes to parse the segmented payload header length.
pub(crate) fn probe_payload_header(
    object_id: &BackendObjectId,
    body: &[u8],
) -> Result<PayloadHeaderProbe> {
    let Some(format) = probe_payload_format(body) else {
        return Err(invalid_payload_object(object_id));
    };

    let domain_len = format.domain().len();
    let preamble_len = match format {
        SegmentedPayloadFormat::LengthBearing => domain_len + U64_LEN + U64_LEN + U64_LEN,
        SegmentedPayloadFormat::Streamable => domain_len + U64_LEN + U64_LEN,
    };
    if body.len() < preamble_len {
        return Ok(PayloadHeaderProbe::NeedMore {
            len: u64::try_from(preamble_len).unwrap_or(u64::MAX),
        });
    }

    let mut cursor = &body[domain_len..];
    let _chunk_size = read_u64(object_id, &mut cursor)?;
    if format == SegmentedPayloadFormat::LengthBearing {
        let _plaintext_len = read_u64(object_id, &mut cursor)?;
    }
    let key_id_len = read_u64(object_id, &mut cursor)?;
    let key_id_len = usize::try_from(key_id_len).map_err(|_| invalid_payload_object(object_id))?;
    let header_len = preamble_len
        .checked_add(key_id_len)
        .and_then(|len| len.checked_add(NONCE_PREFIX_LEN))
        .ok_or_else(|| invalid_payload_object(object_id))?;
    if body.len() < header_len {
        return Ok(PayloadHeaderProbe::NeedMore {
            len: u64::try_from(header_len).unwrap_or(u64::MAX),
        });
    }

    Ok(PayloadHeaderProbe::Segmented { header_len })
}

/// Parses a complete segmented payload header.
pub(crate) fn parse_segmented_payload_header(
    object_id: &BackendObjectId,
    body: &[u8],
) -> Result<SegmentedPayloadHeader> {
    let total_len = u64::try_from(body.len()).map_err(|_| invalid_payload_object(object_id))?;
    parse_segmented_payload_header_with_total_len(object_id, body, total_len)
}

/// Parses a segmented payload header from bounded prefix bytes while using the
/// signed payload-section length for streamable plaintext-length derivation.
pub(crate) fn parse_segmented_payload_header_with_total_len(
    object_id: &BackendObjectId,
    body: &[u8],
    total_len: u64,
) -> Result<SegmentedPayloadHeader> {
    let PayloadHeaderProbe::Segmented { header_len } = probe_payload_header(object_id, body)?
    else {
        return Err(invalid_payload_object(object_id));
    };
    let Some(format) = probe_payload_format(body) else {
        return Err(invalid_payload_object(object_id));
    };
    let Some(mut cursor) = body
        .get(format.domain().len()..header_len)
        .filter(|_| body.starts_with(format.domain()))
    else {
        return Err(invalid_payload_object(object_id));
    };

    let chunk_size = read_u64(object_id, &mut cursor)?;
    if chunk_size == 0
        || chunk_size
            > u64::try_from(MAX_PAYLOAD_SEGMENT_SIZE).map_err(|_| StorageError::InvalidRange)?
    {
        return Err(invalid_payload_object(object_id));
    }
    let plaintext_len = match format {
        SegmentedPayloadFormat::LengthBearing => read_u64(object_id, &mut cursor)?,
        SegmentedPayloadFormat::Streamable => {
            streamable_plaintext_len_from_total_len(object_id, total_len, header_len, chunk_size)?
        }
    };
    let key_id = read_len_prefixed(object_id, &mut cursor)?;
    let key_id = std::str::from_utf8(key_id)
        .map_err(|_| invalid_payload_object(object_id))
        .and_then(|value| {
            KeyId::new(value.to_owned()).map_err(|_| invalid_payload_object(object_id))
        })?;
    let nonce_prefix = read_exact(object_id, &mut cursor, NONCE_PREFIX_LEN)?;
    if !cursor.is_empty() {
        return Err(invalid_payload_object(object_id));
    }

    let mut prefix = [0_u8; NONCE_PREFIX_LEN];
    prefix.copy_from_slice(nonce_prefix);
    Ok(SegmentedPayloadHeader {
        format,
        chunk_size,
        plaintext_len,
        key_id,
        nonce_prefix: prefix,
        header_len,
    })
}

fn streamable_plaintext_len_from_total_len(
    object_id: &BackendObjectId,
    total_len: u64,
    header_len: usize,
    chunk_size: u64,
) -> Result<u64> {
    let header_len = u64::try_from(header_len).map_err(|_| invalid_payload_object(object_id))?;
    let ciphertext_len = total_len
        .checked_sub(header_len)
        .ok_or_else(|| invalid_payload_object(object_id))?;
    streamable_plaintext_len_from_ciphertext_len(object_id, ciphertext_len, chunk_size)
}

/// Returns the contiguous ciphertext span required for a requested plaintext range.
pub(crate) fn segmented_ciphertext_span(
    header: &SegmentedPayloadHeader,
    range: ByteRange,
) -> Result<SegmentCiphertextSpan> {
    let selection = SegmentSelection::new(header, range)?;
    let Some(first) = segment_ciphertext_range(header, selection.start_segment)? else {
        return Ok(SegmentCiphertextSpan {
            offset: u64::try_from(header.header_len).unwrap_or(u64::MAX),
            len: 0,
            start_segment: 0,
            segment_count: 0,
        });
    };
    let Some(last) = segment_ciphertext_range(header, selection.end_segment - 1)? else {
        return Err(StorageError::InvalidRange.into());
    };
    let end = last
        .offset
        .checked_add(last.len)
        .ok_or(StorageError::InvalidRange)?;
    Ok(SegmentCiphertextSpan {
        offset: first.offset,
        len: end
            .checked_sub(first.offset)
            .ok_or(StorageError::InvalidRange)?,
        start_segment: selection.start_segment,
        segment_count: selection.segment_count(),
    })
}

/// Returns the plaintext segments required for a requested plaintext range.
pub(crate) fn segmented_plaintext_selection(
    header: &SegmentedPayloadHeader,
    range: ByteRange,
) -> Result<SegmentPlaintextSelection> {
    let selection = SegmentSelection::new(header, range)?;
    Ok(SegmentPlaintextSelection {
        start_segment: selection.start_segment,
        segment_count: selection.segment_count(),
    })
}

/// Returns the plaintext byte length of one encrypted payload segment.
pub(crate) fn segmented_plaintext_segment_len(
    header: &SegmentedPayloadHeader,
    segment_index: usize,
) -> Result<u64> {
    segment_plaintext_len(header, segment_index)
}

/// Opens selected segmented ciphertext bytes and applies the requested plaintext range.
pub(crate) fn open_segmented_payload_span(
    keyring: &KeyRing,
    object_id: &BackendObjectId,
    header: &SegmentedPayloadHeader,
    range: ByteRange,
    span: SegmentCiphertextSpan,
    ciphertext: Bytes,
) -> Result<Bytes> {
    open_segmented_payload_span_inner(keyring, object_id, header, range, span, ciphertext, false)
        .map(|opened| opened.plaintext)
}

/// Opens selected segmented ciphertext bytes and returns decrypted segment cache material.
pub(crate) fn open_segmented_payload_span_with_segments(
    keyring: &KeyRing,
    object_id: &BackendObjectId,
    header: &SegmentedPayloadHeader,
    range: ByteRange,
    span: SegmentCiphertextSpan,
    ciphertext: Bytes,
) -> Result<OpenedSegmentedPayloadSpan> {
    open_segmented_payload_span_inner(keyring, object_id, header, range, span, ciphertext, true)
}

fn open_segmented_payload_span_inner(
    keyring: &KeyRing,
    object_id: &BackendObjectId,
    header: &SegmentedPayloadHeader,
    range: ByteRange,
    span: SegmentCiphertextSpan,
    ciphertext: Bytes,
    retain_segments: bool,
) -> Result<OpenedSegmentedPayloadSpan> {
    let selection = SegmentSelection::new(header, range)?;
    if span.start_segment != selection.start_segment
        || span.segment_count != selection.segment_count()
    {
        return Err(invalid_payload_object(object_id));
    }

    let expected_len = usize::try_from(span.len).map_err(|_| StorageError::InvalidRange)?;
    if ciphertext.len() != expected_len {
        return Err(invalid_payload_object(object_id));
    }

    let mut output = Vec::with_capacity(selection.output_capacity()?);
    let mut segments = retain_segments.then(|| Vec::with_capacity(selection.segment_count()));
    let mut associated_data = Vec::with_capacity(segment_associated_data_capacity(object_id));
    for segment_index in selection.start_segment..selection.end_segment {
        let segment_range =
            segment_ciphertext_range(header, segment_index)?.ok_or(StorageError::InvalidRange)?;
        let start = usize::try_from(
            segment_range
                .offset
                .checked_sub(span.offset)
                .ok_or(StorageError::InvalidRange)?,
        )
        .map_err(|_| StorageError::InvalidRange)?;
        let len = usize::try_from(segment_range.len).map_err(|_| StorageError::InvalidRange)?;
        let end = start.checked_add(len).ok_or(StorageError::InvalidRange)?;
        let segment_ciphertext = ciphertext
            .get(start..end)
            .ok_or_else(|| invalid_payload_object(object_id))?;
        let plaintext = open_segment(
            keyring,
            object_id,
            header,
            segment_index,
            segment_ciphertext,
            &mut associated_data,
        )?;
        append_segment_overlap(&mut output, header, &selection, segment_index, &plaintext)?;
        if let Some(segments) = segments.as_mut() {
            segments.push((segment_index, Bytes::from(plaintext)));
        }
    }

    Ok(OpenedSegmentedPayloadSpan {
        plaintext: Bytes::from(output),
        segments: segments.unwrap_or_default(),
    })
}

/// Applies a client-visible range to cached decrypted plaintext segments.
pub(crate) fn open_segmented_payload_cached_segments(
    object_id: &BackendObjectId,
    header: &SegmentedPayloadHeader,
    range: ByteRange,
    start_segment: usize,
    segments: &[Bytes],
) -> Result<Bytes> {
    let selection = SegmentSelection::new(header, range)?;
    if start_segment != selection.start_segment || segments.len() != selection.segment_count() {
        return Err(invalid_payload_object(object_id));
    }

    let mut output = Vec::with_capacity(selection.output_capacity()?);
    for (relative_index, plaintext) in segments.iter().enumerate() {
        let segment_index = start_segment
            .checked_add(relative_index)
            .ok_or(StorageError::InvalidRange)?;
        append_segment_overlap(&mut output, header, &selection, segment_index, plaintext)?;
    }

    Ok(Bytes::from(output))
}

#[cfg(test)]
fn seal_segmented_payload_object(
    keyring: &KeyRing,
    object_id: &BackendObjectId,
    plaintext: &[u8],
    chunk_size: usize,
) -> Result<Bytes> {
    if chunk_size == 0 {
        return Err(StorageError::Provider(
            "payload chunk size must be greater than zero".to_owned(),
        )
        .into());
    }
    let chunk_size_u64 = u64::try_from(chunk_size)
        .map_err(|_| StorageError::Provider("payload chunk size does not fit in u64".to_owned()))?;
    let plaintext_len = u64::try_from(plaintext.len())
        .map_err(|_| StorageError::Provider("payload length does not fit in u64".to_owned()))?;
    let key_id = keyring.primary_content_key_id()?;
    let nonce_prefix = random_nonce_prefix()?;
    let header =
        segmented_payload_header_bytes(chunk_size_u64, plaintext_len, &key_id, &nonce_prefix);
    let header_len = header.len();
    let mut body = Vec::with_capacity(
        header_len
            .checked_add(plaintext.len())
            .and_then(|len| {
                len.checked_add(
                    plaintext
                        .chunks(chunk_size)
                        .count()
                        .checked_mul(usize::try_from(AEAD_TAG_LEN).ok()?)?,
                )
            })
            .ok_or_else(|| StorageError::Provider("segmented payload too large".to_owned()))?,
    );
    body.extend_from_slice(&header);

    let segment_count = plaintext.chunks(chunk_size).count();
    let mut associated_data = Vec::with_capacity(segment_associated_data_capacity(object_id));
    for (segment_index, segment) in plaintext.chunks(chunk_size).enumerate() {
        let is_final = segment_index + 1 == segment_count;
        let segment_index_u64 =
            u64::try_from(segment_index).map_err(|_| StorageError::InvalidRange)?;
        let nonce = segment_nonce(&nonce_prefix, segment_index_u64, is_final)?;
        write_segment_associated_data(
            &mut associated_data,
            object_id,
            chunk_size_u64,
            plaintext_len,
            segment_index_u64,
            is_final,
        );
        let seal = keyring.seal_payload_with_nonce(&associated_data, segment, &nonce)?;
        if seal.key_id != key_id {
            return Err(invalid_payload_object(object_id));
        }
        body.extend_from_slice(&seal.ciphertext);
    }

    Ok(Bytes::from(body))
}

fn seal_streamable_segmented_payload_object(
    keyring: &KeyRing,
    object_id: &BackendObjectId,
    plaintext: &[u8],
    chunk_size: usize,
) -> Result<Bytes> {
    let sealer = SegmentedPayloadSealer::new(keyring, chunk_size)?;
    let mut body = Vec::with_capacity(
        usize::try_from(
            sealer
                .sealed_len_for_plaintext_len(u64::try_from(plaintext.len()).map_err(|_| {
                    StorageError::Provider("payload length does not fit in u64".to_owned())
                })?)
                .map_err(|_| StorageError::Provider("segmented payload too large".to_owned()))?,
        )
        .map_err(|_| StorageError::Provider("segmented payload too large".to_owned()))?,
    );
    body.extend_from_slice(&sealer.header());
    let segment_count = plaintext.chunks(chunk_size).count();
    for (segment_index, segment) in plaintext.chunks(chunk_size).enumerate() {
        let is_final = segment_index + 1 == segment_count;
        let ciphertext =
            sealer.seal_segment(keyring, object_id, segment_index, segment, is_final)?;
        body.extend_from_slice(&ciphertext);
    }
    Ok(Bytes::from(body))
}

#[cfg(test)]
fn segmented_payload_header_bytes(
    chunk_size: u64,
    plaintext_len: u64,
    key_id: &KeyId,
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
) -> Vec<u8> {
    let key_id = key_id.as_str().as_bytes();
    let mut body = Vec::with_capacity(
        PAYLOAD_OBJECT_DOMAIN.len() + U64_LEN + U64_LEN + U64_LEN + key_id.len() + NONCE_PREFIX_LEN,
    );
    body.extend_from_slice(PAYLOAD_OBJECT_DOMAIN);
    body.extend_from_slice(&chunk_size.to_be_bytes());
    body.extend_from_slice(&plaintext_len.to_be_bytes());
    push_u64_len(&mut body, key_id.len());
    body.extend_from_slice(key_id);
    body.extend_from_slice(nonce_prefix);
    body
}

fn streamable_segmented_payload_header_bytes(
    chunk_size: u64,
    key_id: &KeyId,
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
) -> Vec<u8> {
    let key_id = key_id.as_str().as_bytes();
    let mut body = Vec::with_capacity(
        STREAMABLE_PAYLOAD_OBJECT_DOMAIN.len()
            + U64_LEN
            + U64_LEN
            + key_id.len()
            + NONCE_PREFIX_LEN,
    );
    body.extend_from_slice(STREAMABLE_PAYLOAD_OBJECT_DOMAIN);
    body.extend_from_slice(&chunk_size.to_be_bytes());
    push_u64_len(&mut body, key_id.len());
    body.extend_from_slice(key_id);
    body.extend_from_slice(nonce_prefix);
    body
}

fn open_segmented_payload_from_body(
    keyring: &KeyRing,
    object_id: &BackendObjectId,
    header: &SegmentedPayloadHeader,
    body: Bytes,
    range: ByteRange,
) -> Result<Bytes> {
    let expected_len = total_segmented_payload_len(header)?;
    if u64::try_from(body.len()).ok() != Some(expected_len) {
        return Err(invalid_payload_object(object_id));
    }
    let span = segmented_ciphertext_span(header, range)?;
    let start = usize::try_from(span.offset).map_err(|_| StorageError::InvalidRange)?;
    let len = usize::try_from(span.len).map_err(|_| StorageError::InvalidRange)?;
    let end = start.checked_add(len).ok_or(StorageError::InvalidRange)?;
    if end > body.len() {
        return Err(invalid_payload_object(object_id));
    }
    open_segmented_payload_span(
        keyring,
        object_id,
        header,
        range,
        span,
        body.slice(start..end),
    )
}

fn open_segment(
    keyring: &KeyRing,
    object_id: &BackendObjectId,
    header: &SegmentedPayloadHeader,
    segment_index: usize,
    ciphertext: &[u8],
    associated_data: &mut Vec<u8>,
) -> Result<Vec<u8>> {
    let segment_index_u64 = u64::try_from(segment_index).map_err(|_| StorageError::InvalidRange)?;
    let is_final = final_segment_index(header)? == segment_index;
    let segment_plaintext_len = segment_plaintext_len(header, segment_index)?;
    let nonce = segment_nonce(&header.nonce_prefix, segment_index_u64, is_final)?;
    match header.format {
        SegmentedPayloadFormat::LengthBearing => write_segment_associated_data(
            associated_data,
            object_id,
            header.chunk_size,
            header.plaintext_len,
            segment_index_u64,
            is_final,
        ),
        SegmentedPayloadFormat::Streamable => write_streamable_segment_associated_data(
            associated_data,
            object_id,
            header.chunk_size,
            segment_index_u64,
            is_final,
            segment_plaintext_len,
        ),
    }
    let plaintext = keyring
        .open_payload(&header.key_id, associated_data, &nonce, ciphertext)
        .map_err(RepositoryError::from)?;
    if u64::try_from(plaintext.len()).ok() != Some(segment_plaintext_len) {
        return Err(invalid_payload_object(object_id));
    }
    Ok(plaintext)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SegmentSelection {
    start: u64,
    end: u64,
    start_segment: usize,
    end_segment: usize,
}

impl SegmentSelection {
    fn new(header: &SegmentedPayloadHeader, range: ByteRange) -> Result<Self> {
        let (start, end) = match range {
            ByteRange::Full => (0, header.plaintext_len),
            ByteRange::Slice { offset, len } => {
                let end = offset.checked_add(len).ok_or(StorageError::InvalidRange)?;
                if len == 0 || end > header.plaintext_len {
                    return Err(StorageError::InvalidRange.into());
                }
                (offset, end)
            }
        };
        if start == end {
            return Ok(Self {
                start,
                end,
                start_segment: 0,
                end_segment: 0,
            });
        }

        let start_segment =
            usize::try_from(start / header.chunk_size).map_err(|_| StorageError::InvalidRange)?;
        let end_segment = usize::try_from((end - 1) / header.chunk_size)
            .map_err(|_| StorageError::InvalidRange)?
            .checked_add(1)
            .ok_or(StorageError::InvalidRange)?;
        if end_segment > segment_count(header)? {
            return Err(StorageError::InvalidRange.into());
        }

        Ok(Self {
            start,
            end,
            start_segment,
            end_segment,
        })
    }

    fn segment_count(self) -> usize {
        self.end_segment.saturating_sub(self.start_segment)
    }

    fn output_capacity(self) -> Result<usize> {
        usize::try_from(self.end.saturating_sub(self.start))
            .map_err(|_| StorageError::InvalidRange.into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CiphertextRange {
    offset: u64,
    len: u64,
}

fn segment_ciphertext_range(
    header: &SegmentedPayloadHeader,
    segment_index: usize,
) -> Result<Option<CiphertextRange>> {
    let segment_count = segment_count(header)?;
    if segment_index >= segment_count {
        return Ok(None);
    }
    let prefix_len = u64::try_from(header.header_len).map_err(|_| StorageError::InvalidRange)?;
    let full_segment_len = header
        .chunk_size
        .checked_add(AEAD_TAG_LEN)
        .ok_or(StorageError::InvalidRange)?;
    let offset = prefix_len
        .checked_add(
            u64::try_from(segment_index)
                .map_err(|_| StorageError::InvalidRange)?
                .checked_mul(full_segment_len)
                .ok_or(StorageError::InvalidRange)?,
        )
        .ok_or(StorageError::InvalidRange)?;
    let plaintext_len = segment_plaintext_len(header, segment_index)?;
    Ok(Some(CiphertextRange {
        offset,
        len: plaintext_len
            .checked_add(AEAD_TAG_LEN)
            .ok_or(StorageError::InvalidRange)?,
    }))
}

fn append_segment_overlap(
    output: &mut Vec<u8>,
    header: &SegmentedPayloadHeader,
    selection: &SegmentSelection,
    segment_index: usize,
    plaintext: &[u8],
) -> Result<()> {
    let segment_start = u64::try_from(segment_index)
        .map_err(|_| StorageError::InvalidRange)?
        .checked_mul(header.chunk_size)
        .ok_or(StorageError::InvalidRange)?;
    let segment_end = segment_start
        .checked_add(u64::try_from(plaintext.len()).map_err(|_| StorageError::InvalidRange)?)
        .ok_or(StorageError::InvalidRange)?;
    let overlap_start = selection.start.max(segment_start);
    let overlap_end = selection.end.min(segment_end);
    if overlap_start > overlap_end {
        return Err(StorageError::InvalidRange.into());
    }
    let local_start =
        usize::try_from(overlap_start - segment_start).map_err(|_| StorageError::InvalidRange)?;
    let local_end =
        usize::try_from(overlap_end - segment_start).map_err(|_| StorageError::InvalidRange)?;
    let slice = plaintext
        .get(local_start..local_end)
        .ok_or(StorageError::InvalidRange)?;
    output.extend_from_slice(slice);
    Ok(())
}

pub(crate) fn total_segmented_payload_len(header: &SegmentedPayloadHeader) -> Result<u64> {
    let count = segment_count(header)?;
    let Some(last_index) = count.checked_sub(1) else {
        return u64::try_from(header.header_len).map_err(|_| StorageError::InvalidRange.into());
    };
    let last = segment_ciphertext_range(header, last_index)?.ok_or(StorageError::InvalidRange)?;
    last.offset
        .checked_add(last.len)
        .ok_or(StorageError::InvalidRange.into())
}

fn segment_count(header: &SegmentedPayloadHeader) -> Result<usize> {
    if header.chunk_size == 0
        || header.chunk_size
            > u64::try_from(MAX_PAYLOAD_SEGMENT_SIZE).map_err(|_| StorageError::InvalidRange)?
    {
        return Err(StorageError::InvalidRange.into());
    }
    let count = if header.plaintext_len == 0 {
        0
    } else {
        header
            .plaintext_len
            .checked_add(header.chunk_size - 1)
            .ok_or(StorageError::InvalidRange)?
            / header.chunk_size
    };
    usize::try_from(count).map_err(|_| StorageError::InvalidRange.into())
}

fn final_segment_index(header: &SegmentedPayloadHeader) -> Result<usize> {
    segment_count(header)?
        .checked_sub(1)
        .ok_or(StorageError::InvalidRange.into())
}

fn segment_plaintext_len(header: &SegmentedPayloadHeader, segment_index: usize) -> Result<u64> {
    let segment_start = u64::try_from(segment_index)
        .map_err(|_| StorageError::InvalidRange)?
        .checked_mul(header.chunk_size)
        .ok_or(StorageError::InvalidRange)?;
    let remaining = header
        .plaintext_len
        .checked_sub(segment_start)
        .ok_or(StorageError::InvalidRange)?;
    Ok(remaining.min(header.chunk_size))
}

fn random_nonce_prefix() -> Result<[u8; NONCE_PREFIX_LEN]> {
    let mut prefix = [0_u8; NONCE_PREFIX_LEN];
    getrandom::fill(&mut prefix)
        .map_err(|_| StorageError::Provider("system randomness unavailable".to_owned()))?;
    Ok(prefix)
}

fn segment_nonce(
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    segment_index: u64,
    is_final: bool,
) -> Result<[u8; XCHACHA20_NONCE_LEN]> {
    if segment_index >= FINAL_SEGMENT_NONCE_FLAG {
        return Err(StorageError::InvalidRange.into());
    }
    let mut nonce = [0_u8; XCHACHA20_NONCE_LEN];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(nonce_prefix);
    let counter = if is_final {
        segment_index | FINAL_SEGMENT_NONCE_FLAG
    } else {
        segment_index
    };
    nonce[NONCE_PREFIX_LEN..].copy_from_slice(&counter.to_be_bytes());
    Ok(nonce)
}

fn segment_associated_data_capacity(object_id: &BackendObjectId) -> usize {
    PAYLOAD_SEGMENT_AAD_DOMAIN
        .len()
        .max(STREAMABLE_PAYLOAD_SEGMENT_AAD_DOMAIN.len())
        .saturating_add(object_id.as_str().len())
        .saturating_add(1)
        .saturating_add(U64_LEN * 3)
        .saturating_add(1)
}

fn write_segment_associated_data(
    aad: &mut Vec<u8>,
    object_id: &BackendObjectId,
    chunk_size: u64,
    plaintext_len: u64,
    segment_index: u64,
    is_final: bool,
) {
    aad.clear();
    aad.extend_from_slice(PAYLOAD_SEGMENT_AAD_DOMAIN);
    aad.extend_from_slice(object_id.as_str().as_bytes());
    aad.push(0);
    aad.extend_from_slice(&chunk_size.to_be_bytes());
    aad.extend_from_slice(&plaintext_len.to_be_bytes());
    aad.extend_from_slice(&segment_index.to_be_bytes());
    aad.push(u8::from(is_final));
}

fn write_streamable_segment_associated_data(
    aad: &mut Vec<u8>,
    object_id: &BackendObjectId,
    chunk_size: u64,
    segment_index: u64,
    is_final: bool,
    segment_plaintext_len: u64,
) {
    aad.clear();
    aad.extend_from_slice(STREAMABLE_PAYLOAD_SEGMENT_AAD_DOMAIN);
    aad.extend_from_slice(object_id.as_str().as_bytes());
    aad.push(0);
    aad.extend_from_slice(&chunk_size.to_be_bytes());
    aad.extend_from_slice(&segment_index.to_be_bytes());
    aad.push(u8::from(is_final));
    aad.extend_from_slice(&segment_plaintext_len.to_be_bytes());
}

fn probe_payload_format(body: &[u8]) -> Option<SegmentedPayloadFormat> {
    if body.starts_with(PAYLOAD_OBJECT_DOMAIN) {
        Some(SegmentedPayloadFormat::LengthBearing)
    } else if body.starts_with(STREAMABLE_PAYLOAD_OBJECT_DOMAIN) {
        Some(SegmentedPayloadFormat::Streamable)
    } else {
        None
    }
}

impl SegmentedPayloadFormat {
    fn domain(self) -> &'static [u8] {
        match self {
            Self::LengthBearing => PAYLOAD_OBJECT_DOMAIN,
            Self::Streamable => STREAMABLE_PAYLOAD_OBJECT_DOMAIN,
        }
    }
}

fn streamable_plaintext_len_from_ciphertext_len(
    object_id: &BackendObjectId,
    ciphertext_len: u64,
    chunk_size: u64,
) -> Result<u64> {
    if ciphertext_len == 0 {
        return Ok(0);
    }
    let full_ciphertext_segment_len = chunk_size
        .checked_add(AEAD_TAG_LEN)
        .ok_or(StorageError::InvalidRange)?;
    let segment_count = ciphertext_len.div_ceil(full_ciphertext_segment_len);
    let tag_bytes = segment_count
        .checked_mul(AEAD_TAG_LEN)
        .ok_or(StorageError::InvalidRange)?;
    let plaintext_len = ciphertext_len
        .checked_sub(tag_bytes)
        .ok_or_else(|| invalid_payload_object(object_id))?;
    let max_plaintext_len = segment_count
        .checked_mul(chunk_size)
        .ok_or(StorageError::InvalidRange)?;
    if plaintext_len == 0 || plaintext_len > max_plaintext_len {
        return Err(invalid_payload_object(object_id));
    }
    Ok(plaintext_len)
}

fn segment_count_for_len(plaintext_len: u64, chunk_size: u64) -> Result<u64> {
    if chunk_size == 0 {
        return Err(StorageError::InvalidRange.into());
    }
    if plaintext_len == 0 {
        return Ok(0);
    }
    Ok(plaintext_len.div_ceil(chunk_size))
}

fn push_u64_len(body: &mut Vec<u8>, len: usize) {
    body.extend_from_slice(&(len as u64).to_be_bytes());
}

fn read_len_prefixed<'a>(object_id: &BackendObjectId, cursor: &mut &'a [u8]) -> Result<&'a [u8]> {
    let len = read_u64_len(object_id, cursor)?;
    read_exact(object_id, cursor, len)
}

fn read_u64_len(object_id: &BackendObjectId, cursor: &mut &[u8]) -> Result<usize> {
    usize::try_from(read_u64(object_id, cursor)?).map_err(|_| invalid_payload_object(object_id))
}

fn read_u64(object_id: &BackendObjectId, cursor: &mut &[u8]) -> Result<u64> {
    let bytes = read_exact(object_id, cursor, U64_LEN)?;
    let mut len = [0_u8; U64_LEN];
    len.copy_from_slice(bytes);
    Ok(u64::from_be_bytes(len))
}

fn read_exact<'a>(
    object_id: &BackendObjectId,
    cursor: &mut &'a [u8],
    len: usize,
) -> Result<&'a [u8]> {
    if cursor.len() < len {
        return Err(invalid_payload_object(object_id));
    }
    let (value, remaining) = cursor.split_at(len);
    *cursor = remaining;
    Ok(value)
}

fn invalid_payload_object(object_id: &BackendObjectId) -> RepositoryError {
    RepositoryError::InvalidObjectFormat {
        object_id: object_id.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_PAYLOAD_SEGMENT_SIZE, MAX_PAYLOAD_SEGMENT_SIZE, PayloadHeaderProbe,
        SegmentedPayloadSealer, open_payload_object, open_segmented_payload_span_inner,
        parse_segmented_payload_header, parse_segmented_payload_header_with_total_len,
        probe_payload_header, seal_payload_object, seal_streamable_payload_object,
        segmented_ciphertext_span,
    };
    use crate::test_support::{backend_object_id, signing_keyring, wrong_content_keyring};
    use bytes::Bytes;
    use rs3_storage::ByteRange;

    #[test]
    fn payload_sealer_rejects_unbounded_segment_size() {
        let keyring = signing_keyring();
        let result =
            SegmentedPayloadSealer::new(&keyring, MAX_PAYLOAD_SEGMENT_SIZE.saturating_add(1));

        assert!(result.is_err());
    }

    #[test]
    fn payload_parser_rejects_unbounded_segment_size() {
        let keyring = signing_keyring();
        let object_id = backend_object_id("segments/unbounded");
        let sealed = seal_streamable_payload_object(
            &keyring,
            &object_id,
            b"bounded",
            DEFAULT_PAYLOAD_SEGMENT_SIZE,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let mut malformed = sealed.to_vec();
        let start = super::STREAMABLE_PAYLOAD_OBJECT_DOMAIN.len();
        let end = start + std::mem::size_of::<u64>();
        malformed[start..end].copy_from_slice(&(MAX_PAYLOAD_SEGMENT_SIZE as u64 + 1).to_be_bytes());

        let parsed = parse_segmented_payload_header(&object_id, &malformed);

        assert!(parsed.is_err());
    }

    #[test]
    fn payload_object_round_trips() {
        let keyring = signing_keyring();
        let object_id = backend_object_id("segments/object");
        let body = match seal_payload_object(
            &keyring,
            &object_id,
            b"hello world",
            DEFAULT_PAYLOAD_SEGMENT_SIZE,
        ) {
            Ok(body) => body,
            Err(error) => panic!("{error}"),
        };
        let opened = open_payload_object(&keyring, &object_id, body, ByteRange::Full);

        assert_eq!(opened.ok().as_deref(), Some(&b"hello world"[..]));
    }

    #[test]
    fn small_payloads_use_segmented_format_too() {
        let keyring = signing_keyring();
        let object_id = backend_object_id("segments/small");
        let body =
            seal_payload_object(&keyring, &object_id, b"small", DEFAULT_PAYLOAD_SEGMENT_SIZE)
                .unwrap_or_else(|error| panic!("{error}"));

        assert!(body.starts_with(super::PAYLOAD_OBJECT_DOMAIN));
        assert!(matches!(
            probe_payload_header(&object_id, &body),
            Ok(PayloadHeaderProbe::Segmented { .. })
        ));
    }

    #[test]
    fn streamable_payload_round_trips_exact_segment_and_supports_ranges() {
        let keyring = signing_keyring();
        let object_id = backend_object_id("v2-payload/exact");
        let plaintext = vec![9_u8; DEFAULT_PAYLOAD_SEGMENT_SIZE];
        let body = seal_streamable_payload_object(
            &keyring,
            &object_id,
            &plaintext,
            DEFAULT_PAYLOAD_SEGMENT_SIZE,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let header = parse_segmented_payload_header(&object_id, &body)
            .unwrap_or_else(|error| panic!("{error}"));
        let range = open_payload_object(
            &keyring,
            &object_id,
            body.clone(),
            ByteRange::Slice { offset: 7, len: 11 },
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let full = open_payload_object(&keyring, &object_id, body, ByteRange::Full)
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(header.plaintext_len, DEFAULT_PAYLOAD_SEGMENT_SIZE as u64);
        assert_eq!(range, Bytes::from(vec![9_u8; 11]));
        assert_eq!(full, plaintext);
    }

    #[test]
    fn streamable_payload_rejects_wrong_object_id() {
        let keyring = signing_keyring();
        let object_id = backend_object_id("v2-payload/object");
        let other_id = backend_object_id("v2-payload/other");
        let body = seal_streamable_payload_object(
            &keyring,
            &object_id,
            b"authenticated identity",
            DEFAULT_PAYLOAD_SEGMENT_SIZE,
        )
        .unwrap_or_else(|error| panic!("{error}"));

        let opened = open_payload_object(&keyring, &other_id, body, ByteRange::Full);

        assert!(opened.is_err());
    }

    #[test]
    fn streamable_payload_rejects_truncated_ciphertext() {
        let keyring = signing_keyring();
        let object_id = backend_object_id("v2-payload/truncated");
        let mut body = seal_streamable_payload_object(
            &keyring,
            &object_id,
            b"truncated ciphertext",
            DEFAULT_PAYLOAD_SEGMENT_SIZE,
        )
        .unwrap_or_else(|error| panic!("{error}"))
        .to_vec();
        body.truncate(body.len().saturating_sub(1));

        let opened = open_payload_object(&keyring, &object_id, Bytes::from(body), ByteRange::Full);

        assert!(opened.is_err());
    }

    #[test]
    fn streamable_payload_header_parses_from_a_bounded_prefix_and_signed_total_len() {
        let keyring = signing_keyring();
        let object_id = backend_object_id("v2-payload/bounded-header");
        let body = seal_streamable_payload_object(
            &keyring,
            &object_id,
            &vec![7_u8; DEFAULT_PAYLOAD_SEGMENT_SIZE * 3 + 17],
            DEFAULT_PAYLOAD_SEGMENT_SIZE,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let full = parse_segmented_payload_header(&object_id, &body)
            .unwrap_or_else(|error| panic!("{error}"));
        let prefix = &body[..full.header_len];
        let total_len = u64::try_from(body.len()).unwrap_or_else(|error| panic!("{error}"));

        let bounded = parse_segmented_payload_header_with_total_len(&object_id, prefix, total_len)
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(bounded, full);
    }

    #[test]
    fn empty_payloads_use_segmented_format_too() {
        let keyring = signing_keyring();
        let object_id = backend_object_id("segments/empty");
        let body = seal_payload_object(&keyring, &object_id, b"", DEFAULT_PAYLOAD_SEGMENT_SIZE)
            .unwrap_or_else(|error| panic!("{error}"));
        let opened = open_payload_object(&keyring, &object_id, body.clone(), ByteRange::Full)
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(body.starts_with(super::PAYLOAD_OBJECT_DOMAIN));
        assert!(opened.is_empty());
    }

    #[test]
    fn segmented_payload_round_trips_and_supports_ranges() {
        let keyring = signing_keyring();
        let object_id = backend_object_id("segments/large");
        let chunk_size = DEFAULT_PAYLOAD_SEGMENT_SIZE;
        let plaintext = (0..(chunk_size * 2 + 17))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();

        let body = seal_payload_object(&keyring, &object_id, &plaintext, chunk_size)
            .unwrap_or_else(|error| panic!("{error}"));
        let full = open_payload_object(&keyring, &object_id, body.clone(), ByteRange::Full)
            .unwrap_or_else(|error| panic!("{error}"));
        let range = open_payload_object(
            &keyring,
            &object_id,
            body.clone(),
            ByteRange::Slice {
                offset: (chunk_size - 3) as u64,
                len: 16,
            },
        )
        .unwrap_or_else(|error| panic!("{error}"));

        assert!(body.starts_with(super::PAYLOAD_OBJECT_DOMAIN));
        assert_eq!(full, plaintext);
        assert_eq!(range, &plaintext[chunk_size - 3..chunk_size + 13]);
    }

    #[test]
    fn non_caching_open_does_not_retain_duplicate_plaintext_segments() {
        let keyring = signing_keyring();
        let object_id = backend_object_id("segments/non-caching-open");
        let chunk_size = DEFAULT_PAYLOAD_SEGMENT_SIZE;
        let plaintext = vec![7_u8; chunk_size * 2 + 17];
        let body = seal_payload_object(&keyring, &object_id, &plaintext, chunk_size)
            .unwrap_or_else(|error| panic!("{error}"));
        let header = parse_segmented_payload_header(&object_id, &body)
            .unwrap_or_else(|error| panic!("{error}"));
        let span = segmented_ciphertext_span(&header, ByteRange::Full)
            .unwrap_or_else(|error| panic!("{error}"));
        let start = usize::try_from(span.offset).unwrap_or_else(|error| panic!("{error}"));
        let len = usize::try_from(span.len).unwrap_or_else(|error| panic!("{error}"));
        let end = start
            .checked_add(len)
            .unwrap_or_else(|| panic!("ciphertext span overflow"));
        let ciphertext = body.slice(start..end);

        let non_caching = open_segmented_payload_span_inner(
            &keyring,
            &object_id,
            &header,
            ByteRange::Full,
            span,
            ciphertext.clone(),
            false,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let caching = open_segmented_payload_span_inner(
            &keyring,
            &object_id,
            &header,
            ByteRange::Full,
            span,
            ciphertext,
            true,
        )
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(non_caching.plaintext, plaintext);
        assert!(non_caching.segments.is_empty());
        assert_eq!(caching.plaintext, plaintext);
        assert_eq!(caching.segments.len(), 3);
    }

    #[test]
    fn segmented_payload_header_probe_finds_derivable_range_span() {
        let keyring = signing_keyring();
        let object_id = backend_object_id("segments/large");
        let chunk_size = DEFAULT_PAYLOAD_SEGMENT_SIZE;
        let plaintext = vec![7_u8; chunk_size * 2 + 17];
        let body = seal_payload_object(&keyring, &object_id, &plaintext, chunk_size)
            .unwrap_or_else(|error| panic!("{error}"));
        let probe_len = super::PAYLOAD_HEADER_PROBE_LEN as usize;

        let probe = probe_payload_header(&object_id, &body[..probe_len])
            .unwrap_or_else(|error| panic!("{error}"));
        let header_len = match probe {
            PayloadHeaderProbe::NeedMore { len } => usize::try_from(len)
                .unwrap_or_else(|error| panic!("header length does not fit usize: {error}")),
            PayloadHeaderProbe::Segmented { header_len } => header_len,
        };
        let header = parse_segmented_payload_header(&object_id, &body[..header_len])
            .unwrap_or_else(|error| panic!("{error}"));
        let span = segmented_ciphertext_span(
            &header,
            ByteRange::Slice {
                offset: (chunk_size + 12) as u64,
                len: 8,
            },
        )
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(span.segment_count, 1);
        let body_len = u64::try_from(body.len())
            .unwrap_or_else(|error| panic!("body length does not fit u64: {error}"));
        assert!(span.len < body_len);
    }

    #[test]
    fn payload_object_rejects_wrong_object_context() {
        let keyring = signing_keyring();
        let object_id = backend_object_id("segments/object");
        let moved_object_id = backend_object_id("segments/other");
        let body = match seal_payload_object(
            &keyring,
            &object_id,
            b"hello world",
            DEFAULT_PAYLOAD_SEGMENT_SIZE,
        ) {
            Ok(body) => body,
            Err(error) => panic!("{error}"),
        };

        let opened = open_payload_object(&keyring, &moved_object_id, body, ByteRange::Full);

        assert!(opened.is_err());
    }

    #[test]
    fn payload_object_rejects_wrong_content_key() {
        let writer = signing_keyring();
        let reader = wrong_content_keyring();
        let object_id = backend_object_id("segments/object");
        let body = match seal_payload_object(
            &writer,
            &object_id,
            b"hello world",
            DEFAULT_PAYLOAD_SEGMENT_SIZE,
        ) {
            Ok(body) => body,
            Err(error) => panic!("{error}"),
        };

        let opened = open_payload_object(&reader, &object_id, body, ByteRange::Full);

        assert!(opened.is_err());
    }
}
