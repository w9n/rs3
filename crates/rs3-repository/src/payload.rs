//! Ciphertext-only payload segments with authenticated, bounded index layouts.

use crate::error::{RepositoryError, Result};
use bytes::Bytes;
use rs3_crypto::{KeyRing, PayloadSegmentContext};
use rs3_index::{PayloadLayout, PayloadPart};
use rs3_storage::{ByteRange, StorageError};
use rs3_types::{BackendObjectId, KeyId, PayloadAttemptId};

/// Default plaintext bytes per independently encrypted payload segment.
pub const DEFAULT_PAYLOAD_SEGMENT_SIZE: usize = 512;
/// Hard reader and writer bound for one plaintext segment.
pub const MAX_PAYLOAD_SEGMENT_SIZE: usize = 64 * 1024 * 1024;
const AEAD_TAG_LEN: u64 = rs3_types::PAYLOAD_AEAD_TAG_LEN as u64;

/// Returns the adaptive payload segment size, respecting the configured floor.
pub fn effective_payload_segment_size(
    plaintext_len: usize,
    configured_size: usize,
    adaptive: bool,
) -> usize {
    if !adaptive {
        return configured_size;
    }
    configured_size.max(if plaintext_len < 8 * 1024 {
        512
    } else if plaintext_len < 256 * 1024 {
        8 * 1024
    } else {
        64 * 1024
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PartStart {
    plaintext: u64,
    ciphertext: u64,
    segment: usize,
}

/// Validated descriptor with prefix sums for logarithmic part lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SegmentedPayloadLayout {
    reference: PayloadLayout,
    repository_context: Vec<u8>,
    starts: Vec<PartStart>,
    stored_len: u64,
    segment_count: usize,
}

impl std::ops::Deref for SegmentedPayloadLayout {
    type Target = PayloadLayout;
    fn deref(&self) -> &Self::Target {
        &self.reference
    }
}

impl SegmentedPayloadLayout {
    pub(crate) fn new(reference: PayloadLayout, repository_context: Vec<u8>) -> Result<Self> {
        let stored_len = reference.stored_len().ok_or(StorageError::InvalidRange)?;
        if repository_context.is_empty() || repository_context.len() > 4096 {
            return Err(StorageError::InvalidRange.into());
        }
        let mut starts = Vec::with_capacity(reference.parts.len());
        let mut next = PartStart {
            plaintext: 0,
            ciphertext: 0,
            segment: 0,
        };
        for part in &reference.parts {
            starts.push(next.clone());
            let count = part.plaintext_len.div_ceil(reference.chunk_size);
            next.plaintext = next
                .plaintext
                .checked_add(part.plaintext_len)
                .ok_or(StorageError::InvalidRange)?;
            next.ciphertext = next
                .ciphertext
                .checked_add(part.plaintext_len)
                .and_then(|value| value.checked_add(count.checked_mul(AEAD_TAG_LEN)?))
                .ok_or(StorageError::InvalidRange)?;
            next.segment = next
                .segment
                .checked_add(usize::try_from(count).map_err(|_| StorageError::InvalidRange)?)
                .ok_or(StorageError::InvalidRange)?;
        }
        Ok(Self {
            reference,
            repository_context,
            starts,
            stored_len,
            segment_count: next.segment,
        })
    }

    pub(crate) fn retained_bytes(&self) -> u64 {
        // Part count and all variable fields were bounded at construction.
        (self.reference.parts.capacity() * std::mem::size_of::<PayloadPart>()
            + self.starts.capacity() * std::mem::size_of::<PartStart>()
            + self.repository_context.capacity()
            + self.key_id.as_str().len()) as u64
    }

    pub(crate) fn reference(&self) -> &PayloadLayout {
        &self.reference
    }
    pub(crate) fn segment_count(&self) -> usize {
        self.segment_count
    }

    /// Plaintext start of a segment, or total length at the end sentinel.
    pub(crate) fn plaintext_offset(&self, segment: usize) -> Result<u64> {
        if segment == self.segment_count {
            return Ok(self.plaintext_len);
        }
        let facts = self.segment(segment)?;
        Ok(facts.plaintext_offset)
    }

    fn segment_at_byte(&self, offset: u64) -> Result<usize> {
        if offset >= self.plaintext_len {
            return Err(StorageError::InvalidRange.into());
        }
        let part = self
            .starts
            .partition_point(|start| start.plaintext <= offset)
            - 1;
        let start = &self.starts[part];
        start
            .segment
            .checked_add(
                usize::try_from((offset - start.plaintext) / self.chunk_size)
                    .map_err(|_| StorageError::InvalidRange)?,
            )
            .ok_or(StorageError::InvalidRange.into())
    }

    fn segment(&self, ordinal: usize) -> Result<SegmentFacts<'_>> {
        if ordinal >= self.segment_count {
            return Err(StorageError::InvalidRange.into());
        }
        let part_index = self
            .starts
            .partition_point(|start| start.segment <= ordinal)
            - 1;
        let start = &self.starts[part_index];
        let part = &self.parts[part_index];
        let relative =
            u64::try_from(ordinal - start.segment).map_err(|_| StorageError::InvalidRange)?;
        let local_offset = relative
            .checked_mul(self.chunk_size)
            .ok_or(StorageError::InvalidRange)?;
        let plaintext_len = (part.plaintext_len - local_offset).min(self.chunk_size);
        Ok(SegmentFacts {
            part,
            ordinal: relative,
            plaintext_len,
            plaintext_offset: start.plaintext + local_offset,
            ciphertext_offset: start.ciphertext + local_offset + relative * AEAD_TAG_LEN,
            is_final: local_offset + plaintext_len == part.plaintext_len,
        })
    }
}

struct SegmentFacts<'a> {
    part: &'a PayloadPart,
    ordinal: u64,
    plaintext_len: u64,
    plaintext_offset: u64,
    ciphertext_offset: u64,
    is_final: bool,
}

/// Fresh immutable encryption attempt for one independently sealable part.
#[derive(Clone, Debug)]
pub(crate) struct SegmentedPayloadSealer {
    chunk_size: u64,
    key_id: KeyId,
    repository_context: Vec<u8>,
    carrier_id: [u8; 32],
    attempt_id: PayloadAttemptId,
    part_number: u32,
}

impl SegmentedPayloadSealer {
    pub(crate) fn new(
        keyring: &KeyRing,
        chunk_size: usize,
        repository_context: Vec<u8>,
        carrier_id: [u8; 32],
        part_number: u32,
    ) -> Result<Self> {
        if chunk_size == 0
            || chunk_size > MAX_PAYLOAD_SEGMENT_SIZE
            || repository_context.is_empty()
            || repository_context.len() > 4096
            || part_number == 0
            || part_number > rs3_index::MAX_PAYLOAD_PARTS as u32
        {
            return Err(StorageError::InvalidRange.into());
        }
        Ok(Self {
            chunk_size: chunk_size as u64,
            key_id: keyring.primary_content_key_id()?,
            repository_context,
            carrier_id,
            attempt_id: rs3_crypto::random_payload_attempt_id()?,
            part_number,
        })
    }

    pub(crate) fn attempt_id(&self) -> PayloadAttemptId {
        self.attempt_id
    }

    pub(crate) fn layout_reference(&self, plaintext_len: u64) -> Result<SegmentedPayloadLayout> {
        SegmentedPayloadLayout::new(
            PayloadLayout {
                chunk_size: self.chunk_size,
                plaintext_len,
                key_id: self.key_id.clone(),
                carrier_id: self.carrier_id,
                parts: vec![PayloadPart {
                    part_number: self.part_number,
                    attempt_id: self.attempt_id,
                    plaintext_len,
                }],
            },
            self.repository_context.clone(),
        )
    }

    pub(crate) fn sealed_len_for_plaintext_len(&self, plaintext_len: u64) -> Result<u64> {
        plaintext_len
            .checked_add(
                plaintext_len
                    .div_ceil(self.chunk_size)
                    .checked_mul(AEAD_TAG_LEN)
                    .ok_or(StorageError::InvalidRange)?,
            )
            .ok_or(StorageError::InvalidRange.into())
    }

    pub(crate) fn seal_segment(
        &self,
        keyring: &KeyRing,
        object_id: &BackendObjectId,
        segment_index: usize,
        plaintext: &[u8],
        is_final: bool,
    ) -> Result<Bytes> {
        let plaintext_len = plaintext.len() as u64;
        if plaintext_len == 0
            || plaintext_len > self.chunk_size
            || (!is_final && plaintext_len != self.chunk_size)
        {
            return Err(invalid_payload_object(object_id));
        }
        let layout = self.chunk_size.to_be_bytes();
        let sealed = keyring.seal_payload_segment(
            PayloadSegmentContext {
                repository_context: &self.repository_context,
                containing_object: object_id,
                section_ordinal: None,
                carrier_id: &self.carrier_id,
                attempt_id: self.attempt_id,
                part_ordinal: self.part_number,
                segment_ordinal: segment_index as u64,
                plaintext_len,
                is_final,
                layout_context: &layout,
            },
            plaintext,
        )?;
        if sealed.key_id != self.key_id {
            return Err(invalid_payload_object(object_id));
        }
        Ok(sealed.ciphertext.into())
    }
}

/// Contiguous ciphertext span covering selected whole segments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SegmentCiphertextSpan {
    pub(crate) offset: u64,
    pub(crate) len: u64,
    pub(crate) start_segment: usize,
    pub(crate) segment_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SegmentPlaintextSelection {
    pub(crate) start_segment: usize,
    pub(crate) segment_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OpenedSegmentedPayloadSpan {
    pub(crate) plaintext: Bytes,
    pub(crate) segments: Vec<(usize, Bytes)>,
}

pub(crate) fn segmented_ciphertext_span(
    layout: &SegmentedPayloadLayout,
    range: ByteRange,
) -> Result<SegmentCiphertextSpan> {
    let selection = SegmentSelection::new(layout, range)?;
    let first = layout.segment(selection.start_segment)?;
    let last = layout.segment(selection.end_segment - 1)?;
    Ok(SegmentCiphertextSpan {
        offset: first.ciphertext_offset,
        len: last.ciphertext_offset + last.plaintext_len + AEAD_TAG_LEN - first.ciphertext_offset,
        start_segment: selection.start_segment,
        segment_count: selection.end_segment - selection.start_segment,
    })
}

pub(crate) fn segmented_plaintext_selection(
    layout: &SegmentedPayloadLayout,
    range: ByteRange,
) -> Result<SegmentPlaintextSelection> {
    let selection = SegmentSelection::new(layout, range)?;
    Ok(SegmentPlaintextSelection {
        start_segment: selection.start_segment,
        segment_count: selection.end_segment - selection.start_segment,
    })
}

pub(crate) fn segmented_plaintext_segment_len(
    layout: &SegmentedPayloadLayout,
    segment_index: usize,
) -> Result<u64> {
    Ok(layout.segment(segment_index)?.plaintext_len)
}

pub(crate) fn open_payload_object(
    keyring: &KeyRing,
    object_id: &BackendObjectId,
    layout: &SegmentedPayloadLayout,
    body: Bytes,
    range: ByteRange,
) -> Result<Bytes> {
    if body.len() as u64 != layout.stored_len {
        return Err(invalid_payload_object(object_id));
    }
    let span = segmented_ciphertext_span(layout, range)?;
    let start = usize::try_from(span.offset).map_err(|_| StorageError::InvalidRange)?;
    let end = usize::try_from(span.offset + span.len).map_err(|_| StorageError::InvalidRange)?;
    open_segmented_payload_span(
        keyring,
        object_id,
        layout,
        range,
        span,
        body.slice(start..end),
    )
}

pub(crate) fn open_segmented_payload_span(
    keyring: &KeyRing,
    object_id: &BackendObjectId,
    layout: &SegmentedPayloadLayout,
    range: ByteRange,
    span: SegmentCiphertextSpan,
    ciphertext: Bytes,
) -> Result<Bytes> {
    open_segmented_payload_span_inner(keyring, object_id, layout, range, span, ciphertext, false)
        .map(|opened| opened.plaintext)
}

pub(crate) fn open_segmented_payload_span_with_segments(
    keyring: &KeyRing,
    object_id: &BackendObjectId,
    layout: &SegmentedPayloadLayout,
    range: ByteRange,
    span: SegmentCiphertextSpan,
    ciphertext: Bytes,
) -> Result<OpenedSegmentedPayloadSpan> {
    open_segmented_payload_span_inner(keyring, object_id, layout, range, span, ciphertext, true)
}

fn open_segmented_payload_span_inner(
    keyring: &KeyRing,
    object_id: &BackendObjectId,
    layout: &SegmentedPayloadLayout,
    range: ByteRange,
    span: SegmentCiphertextSpan,
    ciphertext: Bytes,
    retain_segments: bool,
) -> Result<OpenedSegmentedPayloadSpan> {
    if span != segmented_ciphertext_span(layout, range)? || ciphertext.len() as u64 != span.len {
        return Err(invalid_payload_object(object_id));
    }
    let selection = SegmentSelection::new(layout, range)?;
    let mut output = Vec::with_capacity(
        usize::try_from(selection.end - selection.start).map_err(|_| StorageError::InvalidRange)?,
    );
    let mut segments = Vec::new();
    let chunk_size = layout.chunk_size.to_be_bytes();
    for ordinal in selection.start_segment..selection.end_segment {
        let facts = layout.segment(ordinal)?;
        let start = usize::try_from(facts.ciphertext_offset - span.offset)
            .map_err(|_| StorageError::InvalidRange)?;
        let len = usize::try_from(facts.plaintext_len + AEAD_TAG_LEN)
            .map_err(|_| StorageError::InvalidRange)?;
        let sealed = ciphertext
            .get(start..start.checked_add(len).ok_or(StorageError::InvalidRange)?)
            .ok_or(StorageError::InvalidRange)?;
        let plaintext = keyring.open_payload_segment(
            &layout.key_id,
            PayloadSegmentContext {
                repository_context: &layout.repository_context,
                containing_object: object_id,
                section_ordinal: None,
                carrier_id: &layout.carrier_id,
                attempt_id: facts.part.attempt_id,
                part_ordinal: facts.part.part_number,
                segment_ordinal: facts.ordinal,
                plaintext_len: facts.plaintext_len,
                is_final: facts.is_final,
                layout_context: &chunk_size,
            },
            sealed,
        )?;
        append_segment_overlap(&mut output, &selection, &facts, &plaintext)?;
        if retain_segments {
            segments.push((ordinal, plaintext.into()));
        }
    }
    Ok(OpenedSegmentedPayloadSpan {
        plaintext: output.into(),
        segments,
    })
}

pub(crate) fn open_segmented_payload_cached_segments(
    object_id: &BackendObjectId,
    layout: &SegmentedPayloadLayout,
    range: ByteRange,
    start_segment: usize,
    segments: &[Bytes],
) -> Result<Bytes> {
    let selection = SegmentSelection::new(layout, range)?;
    if start_segment != selection.start_segment
        || segments.len() != selection.end_segment - selection.start_segment
    {
        return Err(invalid_payload_object(object_id));
    }
    let mut output = Vec::with_capacity(
        usize::try_from(selection.end - selection.start).map_err(|_| StorageError::InvalidRange)?,
    );
    for (relative, plaintext) in segments.iter().enumerate() {
        let facts = layout.segment(start_segment + relative)?;
        if plaintext.len() as u64 != facts.plaintext_len {
            return Err(invalid_payload_object(object_id));
        }
        append_segment_overlap(&mut output, &selection, &facts, plaintext)?;
    }
    Ok(output.into())
}

struct SegmentSelection {
    start: u64,
    end: u64,
    start_segment: usize,
    end_segment: usize,
}
impl SegmentSelection {
    fn new(layout: &SegmentedPayloadLayout, range: ByteRange) -> Result<Self> {
        let (start, end) = match range {
            ByteRange::Full => (0, layout.plaintext_len),
            ByteRange::Slice { offset, len } => {
                let end = offset.checked_add(len).ok_or(StorageError::InvalidRange)?;
                if len == 0 || end > layout.plaintext_len {
                    return Err(StorageError::InvalidRange.into());
                }
                (offset, end)
            }
        };
        Ok(Self {
            start,
            end,
            start_segment: layout.segment_at_byte(start)?,
            end_segment: layout.segment_at_byte(end - 1)? + 1,
        })
    }
}

fn append_segment_overlap(
    output: &mut Vec<u8>,
    selection: &SegmentSelection,
    facts: &SegmentFacts<'_>,
    plaintext: &[u8],
) -> Result<()> {
    let start = selection.start.max(facts.plaintext_offset) - facts.plaintext_offset;
    let end = selection
        .end
        .min(facts.plaintext_offset + facts.plaintext_len)
        - facts.plaintext_offset;
    let slice = plaintext
        .get(
            usize::try_from(start).map_err(|_| StorageError::InvalidRange)?
                ..usize::try_from(end).map_err(|_| StorageError::InvalidRange)?,
        )
        .ok_or(StorageError::InvalidRange)?;
    output.extend_from_slice(slice);
    Ok(())
}

pub(crate) fn total_segmented_payload_len(layout: &SegmentedPayloadLayout) -> Result<u64> {
    Ok(layout.stored_len)
}

fn invalid_payload_object(object_id: &BackendObjectId) -> RepositoryError {
    RepositoryError::InvalidObjectFormat {
        object_id: object_id.clone(),
    }
}

/// Fixture/fuzz producer using the same segment scheme as the streaming writer.
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn seal_payload_object(
    keyring: &KeyRing,
    object_id: &BackendObjectId,
    plaintext: &[u8],
    chunk_size: usize,
    repository_context: Vec<u8>,
    carrier_id: [u8; 32],
) -> Result<(Bytes, SegmentedPayloadLayout)> {
    let sealer =
        SegmentedPayloadSealer::new(keyring, chunk_size, repository_context, carrier_id, 1)?;
    let layout = sealer.layout_reference(plaintext.len() as u64)?;
    let mut body = Vec::new();
    for (ordinal, part) in plaintext.chunks(chunk_size).enumerate() {
        body.extend_from_slice(&sealer.seal_segment(
            keyring,
            object_id,
            ordinal,
            part,
            ordinal + 1 == layout.segment_count(),
        )?);
    }
    Ok((body.into(), layout))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{backend_object_id, signing_keyring, wrong_content_keyring};

    fn multipart_fixture(chunk_size: usize) -> (Bytes, SegmentedPayloadLayout, Vec<u8>) {
        let keyring = signing_keyring();
        let object = backend_object_id("opaque-carrier");
        let mut ciphertext = Vec::new();
        let mut plaintext = Vec::new();
        let mut parts = Vec::new();
        // Short finals, missing unselected part numbers and repeated segment ordinals.
        for (number, bytes) in [
            (1, b"first".as_slice()),
            (3, b"second-part"),
            (10_000, b"last"),
        ] {
            let sealer = SegmentedPayloadSealer::new(
                &keyring,
                chunk_size,
                b"repo".to_vec(),
                [4; 32],
                number,
            )
            .expect("part sealer");
            let layout = sealer
                .layout_reference(bytes.len() as u64)
                .expect("part layout");
            for (ordinal, segment) in bytes.chunks(chunk_size).enumerate() {
                ciphertext.extend_from_slice(
                    &sealer
                        .seal_segment(
                            &keyring,
                            &object,
                            ordinal,
                            segment,
                            ordinal + 1 == layout.segment_count(),
                        )
                        .expect("segment"),
                );
            }
            parts.extend(layout.parts.iter().cloned());
            plaintext.extend_from_slice(bytes);
        }
        let layout = SegmentedPayloadLayout::new(
            PayloadLayout {
                chunk_size: chunk_size as u64,
                plaintext_len: plaintext.len() as u64,
                key_id: keyring.primary_content_key_id().expect("key"),
                carrier_id: [4; 32],
                parts,
            },
            b"repo".to_vec(),
        )
        .expect("assembled layout");
        (ciphertext.into(), layout, plaintext)
    }

    #[test]
    fn every_range_matches_full_read_across_independently_sealed_parts() {
        let object = backend_object_id("opaque-carrier");
        let keyring = signing_keyring();
        for chunk_size in [1, 3, 4, 5, 8, 16, 512] {
            let (body, layout, plaintext) = multipart_fixture(chunk_size);
            assert_eq!(
                body.len() as u64,
                total_segmented_payload_len(&layout).expect("length")
            );
            assert_eq!(
                open_payload_object(&keyring, &object, &layout, body.clone(), ByteRange::Full)
                    .expect("full"),
                plaintext
            );
            for start in 0..plaintext.len() {
                for end in start + 1..=plaintext.len() {
                    let range = ByteRange::Slice {
                        offset: start as u64,
                        len: (end - start) as u64,
                    };
                    let span = segmented_ciphertext_span(&layout, range).expect("range plan");
                    let sealed =
                        body.slice(span.offset as usize..(span.offset + span.len) as usize);
                    let opened = open_segmented_payload_span_with_segments(
                        &keyring, &object, &layout, range, span, sealed,
                    )
                    .expect("range open");
                    assert_eq!(opened.plaintext.as_ref(), &plaintext[start..end]);
                    let cached = opened
                        .segments
                        .into_iter()
                        .map(|(_, bytes)| bytes)
                        .collect::<Vec<_>>();
                    assert_eq!(
                        open_segmented_payload_cached_segments(
                            &object,
                            &layout,
                            range,
                            span.start_segment,
                            &cached
                        )
                        .expect("cache"),
                        opened.plaintext
                    );
                }
            }
        }
    }

    #[test]
    fn part_attempt_boundaries_and_final_segments_are_authenticated() {
        let (body, layout, _) = multipart_fixture(4);
        let object = backend_object_id("opaque-carrier");
        let keyring = signing_keyring();
        for change in 0..5 {
            let mut reference = layout.reference().clone();
            match change {
                0 => reference.parts[0].attempt_id = reference.parts[1].attempt_id,
                1 => reference.parts[0].part_number = 2,
                2 => {
                    reference.parts[0].plaintext_len += 1;
                    reference.parts[1].plaintext_len -= 1;
                }
                3 => reference.chunk_size += 1,
                _ => reference.carrier_id[0] ^= 1,
            }
            let changed = SegmentedPayloadLayout::new(reference, b"repo".to_vec())
                .expect("structurally valid");
            assert!(
                open_payload_object(&keyring, &object, &changed, body.clone(), ByteRange::Full)
                    .is_err()
            );
        }
        let transplanted =
            SegmentedPayloadLayout::new(layout.reference().clone(), b"other-repo".to_vec())
                .expect("layout");
        assert!(
            open_payload_object(
                &keyring,
                &object,
                &transplanted,
                body.clone(),
                ByteRange::Full
            )
            .is_err()
        );
        assert!(
            open_payload_object(
                &keyring,
                &backend_object_id("other-carrier"),
                &layout,
                body.clone(),
                ByteRange::Full
            )
            .is_err()
        );
        assert!(
            open_payload_object(
                &wrong_content_keyring(),
                &object,
                &layout,
                body.clone(),
                ByteRange::Full
            )
            .is_err()
        );
        for index in 0..body.len() {
            let mut changed = body.to_vec();
            changed[index] ^= 1;
            assert!(
                open_payload_object(&keyring, &object, &layout, changed.into(), ByteRange::Full)
                    .is_err()
            );
        }
        assert!(
            open_payload_object(
                &keyring,
                &object,
                &layout,
                body.slice(..body.len() - 1),
                ByteRange::Full
            )
            .is_err()
        );
        let mut extra = body.to_vec();
        extra.push(0);
        assert!(
            open_payload_object(&keyring, &object, &layout, extra.into(), ByteRange::Full).is_err()
        );
    }

    #[test]
    fn descriptor_rejects_bad_bounds_order_lengths_and_overflow() {
        let (_, layout, _) = multipart_fixture(4);
        for change in 0..10 {
            let mut reference = layout.reference().clone();
            match change {
                0 => reference.chunk_size = 0,
                1 => reference.chunk_size = MAX_PAYLOAD_SEGMENT_SIZE as u64 + 1,
                2 => reference.plaintext_len = 0,
                3 => reference.plaintext_len += 1,
                4 => reference.parts.clear(),
                5 => reference.parts[0].part_number = 0,
                6 => reference.parts[0].part_number = 3,
                7 => reference.parts[2].part_number = 10_001,
                8 => reference.parts[0].plaintext_len = 0,
                _ => {
                    reference.parts[0].plaintext_len = u64::MAX;
                    reference.plaintext_len = u64::MAX;
                }
            }
            assert!(SegmentedPayloadLayout::new(reference, b"repo".to_vec()).is_err());
        }
        let keyring = signing_keyring();
        assert!(
            SegmentedPayloadSealer::new(
                &keyring,
                MAX_PAYLOAD_SEGMENT_SIZE + 1,
                b"repo".to_vec(),
                [4; 32],
                1
            )
            .is_err()
        );
        assert!(
            seal_payload_object(
                &keyring,
                &backend_object_id("empty"),
                b"",
                512,
                b"repo".to_vec(),
                [4; 32],
            )
            .is_err()
        );
        for range in [
            ByteRange::Slice { offset: 0, len: 0 },
            ByteRange::Slice {
                offset: u64::MAX,
                len: 2,
            },
            ByteRange::Slice {
                offset: 0,
                len: u64::MAX,
            },
        ] {
            assert!(segmented_ciphertext_span(&layout, range).is_err());
        }
    }
}
