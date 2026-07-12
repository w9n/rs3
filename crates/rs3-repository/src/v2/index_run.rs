//! Authenticated physical framing for canonical v02 index-run projections.
//!
//! `rs3-index` owns the canonical plaintext records. This module owns their
//! exact immutable repository context, encrypted range directory, and frame
//! authentication. The directory is opened before any data-frame range is
//! selected, and full-run visitors are called only after every frame and the
//! complete logical run have been verified.

use super::{V2FormatError, V2Result, digest_v2_section};
use bytes::Bytes;
use getrandom::fill as fill_random;
use rs3_crypto::KeyRing;
use rs3_index::run::{
    EncodedIndexRunFrame, IndexBlindKey, IndexRun, IndexRunFrameRole, IndexRunLimits,
    IndexRunSearchBound, decode_index_run_frames, encode_index_run_frames,
};
use rs3_types::{BackendObjectId, KeyId, KeyPurpose, LogicalPath, Sequence};
use std::cmp::Ordering;
use std::fmt;
use std::ops::Range;

/// Byte length of a random v02 index-run identity.
pub const V2_INDEX_RUN_ID_LEN: usize = 32;
/// Maximum number of independently authenticated data frames in one run.
pub const V2_INDEX_RUN_MAX_FRAME_COUNT: usize = 4_096;
/// Maximum plaintext bytes in one independently authenticated data frame.
pub const V2_INDEX_RUN_MAX_FRAME_PLAINTEXT_BYTES: usize = 1024 * 1024;
/// Maximum complete encrypted index-run section or standalone object size.
pub const V2_INDEX_RUN_MAX_OBJECT_BYTES: usize = 8 * 1024 * 1024;
/// Fixed byte count required for the first range probe.
pub const V2_INDEX_RUN_FIXED_HEADER_BYTES: usize = 76;
/// Maximum encrypted-directory plaintext bytes.
pub const V2_INDEX_RUN_MAX_DIRECTORY_PLAINTEXT_BYTES: usize = 1024 * 1024;

const INDEX_RUN_MAGIC: &[u8; 8] = b"rs3:irn\n";
const INDEX_RUN_DIRECTORY_DOMAIN: &[u8] = b"rs3:index-run-directory:v02\n";
const INDEX_RUN_DIRECTORY_AAD_DOMAIN: &[u8] = b"rs3:index-run-directory-aad:v02\n";
const INDEX_RUN_FRAME_AAD_DOMAIN: &[u8] = b"rs3:index-run-frame-aad:v02\n";
const INDEX_RUN_FORMAT_GENERATION: u16 = 2;
const INDEX_RUN_DIRECTORY_VERSION: u16 = 1;
const INDEX_RUN_FIXED_HEADER_LEN: usize = V2_INDEX_RUN_FIXED_HEADER_BYTES;
const INDEX_RUN_SEAL_OVERHEAD: usize = 28;
const INDEX_RUN_NONCE_LEN: usize = 12;
const INDEX_RUN_TAG_LEN: usize = 16;
const INDEX_RUN_DIGEST_LEN: usize = 32;
const INDEX_RUN_MAX_KEY_ID_LEN: usize = 255;
const INDEX_RUN_MAX_OBJECT_KEY_LEN: usize = 1024;
const INDEX_RUN_MAX_REPOSITORY_CONTEXT_LEN: usize = 4096;

/// Random identity authenticated by the directory and every data frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct V2IndexRunId([u8; V2_INDEX_RUN_ID_LEN]);

impl V2IndexRunId {
    /// Returns the exact random identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; V2_INDEX_RUN_ID_LEN] {
        &self.0
    }

    fn generate() -> V2Result<Self> {
        let mut bytes = [0_u8; V2_INDEX_RUN_ID_LEN];
        fill_random(&mut bytes).map_err(|_| V2FormatError::RandomnessUnavailable)?;
        Ok(Self(bytes))
    }
}

/// Complete encrypted bytes and random identity of a v02 framed index run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2SealedIndexRun {
    run_id: V2IndexRunId,
    bytes: Bytes,
}

impl V2SealedIndexRun {
    /// Returns the random identity authenticated by the run.
    #[must_use]
    pub const fn run_id(&self) -> V2IndexRunId {
        self.run_id
    }

    /// Returns the complete section or standalone-object bytes.
    #[must_use]
    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// Consumes the sealed run and returns its complete stored bytes.
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }
}

/// Authenticated physical descriptor for one independently readable frame.
#[derive(Clone, PartialEq, Eq)]
pub struct V2IndexRunFrameDescriptor {
    ordinal: u32,
    role: IndexRunFrameRole,
    role_ordinal: u32,
    offset: u64,
    stored_len: u32,
    plaintext_len: u32,
    record_count: u32,
    first_bound: Option<IndexRunSearchBound>,
    last_bound: Option<IndexRunSearchBound>,
}

impl fmt::Debug for V2IndexRunFrameDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V2IndexRunFrameDescriptor")
            .field("ordinal", &self.ordinal)
            .field("role", &self.role)
            .field("role_ordinal", &self.role_ordinal)
            .field("offset", &self.offset)
            .field("stored_len", &self.stored_len)
            .field("plaintext_len", &self.plaintext_len)
            .field("record_count", &self.record_count)
            .field("bounds", &"<redacted>")
            .finish()
    }
}

impl V2IndexRunFrameDescriptor {
    /// Returns the physical zero-based frame ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    /// Returns the semantic projection role.
    #[must_use]
    pub const fn role(&self) -> IndexRunFrameRole {
        self.role
    }

    /// Returns the zero-based ordinal within the projection role.
    #[must_use]
    pub const fn role_ordinal(&self) -> u32 {
        self.role_ordinal
    }

    /// Returns the number of canonical records in this frame.
    #[must_use]
    pub const fn record_count(&self) -> u32 {
        self.record_count
    }

    /// Returns the exact stored-object range needed to open this frame.
    #[must_use]
    pub const fn stored_range(&self) -> Range<u64> {
        self.offset..self.offset + self.stored_len as u64
    }

    /// Returns the authenticated inclusive first search bound.
    #[must_use]
    pub const fn first_bound(&self) -> Option<&IndexRunSearchBound> {
        self.first_bound.as_ref()
    }

    /// Returns the authenticated inclusive last search bound.
    #[must_use]
    pub const fn last_bound(&self) -> Option<&IndexRunSearchBound> {
        self.last_bound.as_ref()
    }
}

/// Opened and authenticated encrypted run directory.
#[derive(Clone, PartialEq, Eq)]
pub struct V2VerifiedIndexRunDirectory {
    header: RunHeader,
    directory_digest: [u8; INDEX_RUN_DIGEST_LEN],
    sequence: Sequence,
    mutation_count: u32,
    container_count: u32,
    directory_end: usize,
    frames: Vec<V2IndexRunFrameDescriptor>,
}

/// Unauthenticated but strictly bounded facts available from the fixed header.
///
/// A range reader uses this probe only to size its directory-prefix fetch. The
/// returned facts become trusted only after [`open_v2_index_run_directory`]
/// authenticates the encrypted directory under the exact repository context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V2IndexRunHeaderProbe {
    header_len: usize,
    directory_prefix_len: usize,
    stored_len: u64,
    section_ordinal: u32,
    frame_count: u32,
}

impl V2IndexRunHeaderProbe {
    /// Returns the dynamic public-header length including its key identifier.
    #[must_use]
    pub const fn header_len(&self) -> usize {
        self.header_len
    }

    /// Returns the exact prefix length needed to authenticate the directory.
    #[must_use]
    pub const fn directory_prefix_len(&self) -> usize {
        self.directory_prefix_len
    }

    /// Returns the declared complete stored-run length.
    #[must_use]
    pub const fn stored_len(&self) -> u64 {
        self.stored_len
    }

    /// Returns the declared containing-object section ordinal.
    #[must_use]
    pub const fn section_ordinal(&self) -> u32 {
        self.section_ordinal
    }

    /// Returns the bounded declared number of data frames.
    #[must_use]
    pub const fn frame_count(&self) -> u32 {
        self.frame_count
    }
}

impl fmt::Debug for V2VerifiedIndexRunDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V2VerifiedIndexRunDirectory")
            .field("run_id", &self.header.run_id)
            .field("sequence", &self.sequence)
            .field("mutation_count", &self.mutation_count)
            .field("container_count", &self.container_count)
            .field("stored_len", &self.header.stored_len)
            .field("frame_count", &self.frames.len())
            .finish()
    }
}

impl V2VerifiedIndexRunDirectory {
    /// Returns the authenticated random run identity.
    #[must_use]
    pub const fn run_id(&self) -> V2IndexRunId {
        self.header.run_id
    }

    /// Returns the repository sequence repeated by every logical frame.
    #[must_use]
    pub const fn sequence(&self) -> Sequence {
        self.sequence
    }

    /// Returns the exact complete stored-run length.
    #[must_use]
    pub const fn stored_len(&self) -> u64 {
        self.header.stored_len
    }

    /// Returns the byte length needed to fetch and authenticate the directory.
    #[must_use]
    pub const fn directory_end(&self) -> usize {
        self.directory_end
    }

    /// Returns the canonical frame descriptors.
    #[must_use]
    pub fn frames(&self) -> &[V2IndexRunFrameDescriptor] {
        &self.frames
    }

    /// Returns one authenticated frame descriptor by physical ordinal.
    #[must_use]
    pub fn frame(&self, ordinal: u32) -> Option<&V2IndexRunFrameDescriptor> {
        usize::try_from(ordinal)
            .ok()
            .and_then(|ordinal| self.frames.get(ordinal))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RunHeader {
    header_len: u32,
    stored_len: u64,
    section_ordinal: u32,
    frame_count: u32,
    run_id: V2IndexRunId,
    key_id: KeyId,
    directory_plaintext_len: u32,
    directory_ciphertext_len: u32,
}

/// Parses only the fixed public header to plan the directory-prefix range GET.
///
/// No value returned by this function is authenticated. Callers must compare a
/// metadata-only `HEAD` length with `stored_len`, fetch exactly
/// `directory_prefix_len`, and then call [`open_v2_index_run_directory`].
pub fn probe_v2_index_run_header(stored_fixed_header: &[u8]) -> V2Result<V2IndexRunHeaderProbe> {
    if stored_fixed_header.len() < INDEX_RUN_FIXED_HEADER_LEN {
        return Err(V2FormatError::InvalidIndexRun);
    }
    let mut reader = RunReader::new(stored_fixed_header);
    if reader.take(INDEX_RUN_MAGIC.len())? != INDEX_RUN_MAGIC
        || reader.read_u16()? != INDEX_RUN_FORMAT_GENERATION
        || reader.read_u16()? != 0
    {
        return Err(V2FormatError::InvalidIndexRun);
    }
    let header_len = reader.read_u32()? as usize;
    let stored_len = reader.read_u64()?;
    let section_ordinal = reader.read_u32()?;
    let frame_count = reader.read_u32()?;
    let _run_id: [u8; V2_INDEX_RUN_ID_LEN] = reader.read_array()?;
    let key_id_len = usize::from(reader.read_u16()?);
    if reader.read_u16()? != 0 {
        return Err(V2FormatError::InvalidIndexRun);
    }
    let directory_plaintext_len = reader.read_u32()?;
    let directory_ciphertext_len = reader.read_u32()?;
    let directory_prefix_len = header_len
        .checked_add(INDEX_RUN_SEAL_OVERHEAD)
        .and_then(|value| value.checked_add(directory_ciphertext_len as usize))
        .ok_or(V2FormatError::IndexRunLimitExceeded)?;
    if key_id_len == 0
        || key_id_len > INDEX_RUN_MAX_KEY_ID_LEN
        || header_len != INDEX_RUN_FIXED_HEADER_LEN + key_id_len
        || frame_count == 0
        || frame_count as usize > V2_INDEX_RUN_MAX_FRAME_COUNT
        || stored_len > V2_INDEX_RUN_MAX_OBJECT_BYTES as u64
        || directory_plaintext_len == 0
        || directory_plaintext_len as usize > V2_INDEX_RUN_MAX_DIRECTORY_PLAINTEXT_BYTES
        || directory_ciphertext_len != directory_plaintext_len
        || directory_prefix_len as u64 > stored_len
    {
        return Err(V2FormatError::IndexRunLimitExceeded);
    }
    Ok(V2IndexRunHeaderProbe {
        header_len,
        directory_prefix_len,
        stored_len,
        section_ordinal,
        frame_count,
    })
}

/// Canonically encodes and seals one complete logical index run.
pub fn seal_v2_index_run(
    keyring: &KeyRing,
    repository_context: &[u8],
    containing_object: &BackendObjectId,
    section_ordinal: u32,
    run: &IndexRun,
    limits: &IndexRunLimits,
) -> V2Result<V2SealedIndexRun> {
    validate_context(repository_context, containing_object, limits)?;
    let encoded =
        encode_index_run_frames(run, limits).map_err(|_| V2FormatError::InvalidIndexRun)?;
    if encoded.frames.is_empty() || encoded.frames.len() > V2_INDEX_RUN_MAX_FRAME_COUNT {
        return Err(V2FormatError::IndexRunLimitExceeded);
    }

    let key_id = keyring.primary_key_id(KeyPurpose::Metadata)?;
    let key_id_len = key_id.as_str().len();
    if key_id_len == 0 || key_id_len > INDEX_RUN_MAX_KEY_ID_LEN {
        return Err(V2FormatError::IndexRunLimitExceeded);
    }
    let header_len = INDEX_RUN_FIXED_HEADER_LEN
        .checked_add(key_id_len)
        .ok_or(V2FormatError::IndexRunLimitExceeded)?;
    let header_len_u32 = to_u32(header_len)?;
    let frame_count = to_u32(encoded.frames.len())?;
    let container_count = run
        .containers
        .len()
        .checked_add(run.stream_containers.len())
        .and_then(|count| count.checked_add(run.standalone_stream_containers.len()))
        .ok_or(V2FormatError::IndexRunLimitExceeded)?;
    let container_count = to_u32(container_count)?;
    let run_id = V2IndexRunId::generate()?;

    // Descriptor widths do not depend on their offsets, so this provisional
    // encoding determines the exact encrypted-directory length without a
    // self-referential varint calculation.
    let mut descriptors = descriptors_with_first_offset(&encoded.frames, 0)?;
    let provisional_directory = encode_directory(
        run.sequence,
        to_u32(run.mutations.len())?,
        container_count,
        &descriptors,
    )?;
    if provisional_directory.len() > V2_INDEX_RUN_MAX_DIRECTORY_PLAINTEXT_BYTES {
        return Err(V2FormatError::IndexRunLimitExceeded);
    }
    let directory_len = provisional_directory.len();
    let directory_end = header_len
        .checked_add(INDEX_RUN_SEAL_OVERHEAD)
        .and_then(|value| value.checked_add(directory_len))
        .ok_or(V2FormatError::IndexRunLimitExceeded)?;
    descriptors = descriptors_with_first_offset(&encoded.frames, to_u64(directory_end)?)?;
    let directory = encode_directory(
        run.sequence,
        to_u32(run.mutations.len())?,
        container_count,
        &descriptors,
    )?;
    if directory.len() != directory_len {
        return Err(V2FormatError::InvalidIndexRun);
    }

    let stored_len = descriptors
        .last()
        .and_then(|descriptor| {
            descriptor
                .offset
                .checked_add(u64::from(descriptor.stored_len))
        })
        .ok_or(V2FormatError::InvalidIndexRun)?;
    if stored_len > V2_INDEX_RUN_MAX_OBJECT_BYTES as u64 {
        return Err(V2FormatError::IndexRunLimitExceeded);
    }
    let directory_plaintext_len = to_u32(directory.len())?;
    let header = RunHeader {
        header_len: header_len_u32,
        stored_len,
        section_ordinal,
        frame_count,
        run_id,
        key_id: key_id.clone(),
        directory_plaintext_len,
        directory_ciphertext_len: directory_plaintext_len,
    };
    let common_aad = common_associated_data(repository_context, containing_object, &header)?;
    let mut directory_aad =
        Vec::with_capacity(INDEX_RUN_DIRECTORY_AAD_DOMAIN.len() + common_aad.len());
    directory_aad.extend_from_slice(INDEX_RUN_DIRECTORY_AAD_DOMAIN);
    directory_aad.extend_from_slice(&common_aad);
    let directory_seal = keyring.seal_metadata_payload(&directory_aad, &directory)?;
    validate_metadata_seal(
        &directory_seal.key_id,
        &key_id,
        &directory_seal.nonce,
        &directory_seal.tag,
        &directory_seal.ciphertext,
        directory.len(),
    )?;
    let directory_digest = digest_v2_section(&directory);

    let mut stored = Vec::with_capacity(to_usize(stored_len)?);
    encode_header(&mut stored, &header)?;
    stored.extend_from_slice(&directory_seal.nonce);
    stored.extend_from_slice(&directory_seal.tag);
    stored.extend_from_slice(&directory_seal.ciphertext);
    for (plaintext_frame, descriptor) in encoded.frames.iter().zip(&descriptors) {
        if stored.len() != to_usize(descriptor.offset)? {
            return Err(V2FormatError::InvalidIndexRun);
        }
        let frame_aad = frame_associated_data(&common_aad, &directory_digest, descriptor)?;
        let sealed = keyring.seal_metadata_payload(&frame_aad, &plaintext_frame.bytes)?;
        validate_metadata_seal(
            &sealed.key_id,
            &key_id,
            &sealed.nonce,
            &sealed.tag,
            &sealed.ciphertext,
            plaintext_frame.bytes.len(),
        )?;
        stored.extend_from_slice(&sealed.nonce);
        stored.extend_from_slice(&sealed.tag);
        stored.extend_from_slice(&sealed.ciphertext);
    }
    if stored.len() != to_usize(stored_len)? {
        return Err(V2FormatError::InvalidIndexRun);
    }
    Ok(V2SealedIndexRun {
        run_id,
        bytes: Bytes::from(stored),
    })
}

/// Authenticates the encrypted run directory from a prefix or complete run.
pub fn open_v2_index_run_directory(
    keyring: &KeyRing,
    repository_context: &[u8],
    containing_object: &BackendObjectId,
    expected_section_ordinal: u32,
    stored_prefix: &[u8],
    limits: &IndexRunLimits,
) -> V2Result<V2VerifiedIndexRunDirectory> {
    validate_context(repository_context, containing_object, limits)?;
    let header = parse_header(stored_prefix)?;
    if header.section_ordinal != expected_section_ordinal {
        return Err(V2FormatError::InvalidIndexRun);
    }
    let directory_start = to_usize(u64::from(header.header_len))?;
    let directory_end = directory_start
        .checked_add(INDEX_RUN_SEAL_OVERHEAD)
        .and_then(|value| value.checked_add(header.directory_ciphertext_len as usize))
        .ok_or(V2FormatError::InvalidIndexRun)?;
    if directory_end > stored_prefix.len() || directory_end as u64 > header.stored_len {
        return Err(V2FormatError::InvalidIndexRun);
    }
    let directory_seal = stored_prefix
        .get(directory_start..directory_end)
        .ok_or(V2FormatError::InvalidIndexRun)?;
    let nonce = directory_seal
        .get(..INDEX_RUN_NONCE_LEN)
        .ok_or(V2FormatError::InvalidIndexRun)?;
    let tag = directory_seal
        .get(INDEX_RUN_NONCE_LEN..INDEX_RUN_SEAL_OVERHEAD)
        .ok_or(V2FormatError::InvalidIndexRun)?;
    let ciphertext = directory_seal
        .get(INDEX_RUN_SEAL_OVERHEAD..)
        .ok_or(V2FormatError::InvalidIndexRun)?;
    let common_aad = common_associated_data(repository_context, containing_object, &header)?;
    let mut directory_aad =
        Vec::with_capacity(INDEX_RUN_DIRECTORY_AAD_DOMAIN.len() + common_aad.len());
    directory_aad.extend_from_slice(INDEX_RUN_DIRECTORY_AAD_DOMAIN);
    directory_aad.extend_from_slice(&common_aad);
    let directory =
        keyring.open_metadata_payload(&header.key_id, &directory_aad, nonce, ciphertext, tag)?;
    if directory.len() != header.directory_plaintext_len as usize {
        return Err(V2FormatError::InvalidIndexRun);
    }
    let directory_digest = digest_v2_section(&directory);
    let decoded = decode_directory(&directory, &header, directory_end, limits)?;
    Ok(V2VerifiedIndexRunDirectory {
        header,
        directory_digest,
        sequence: decoded.sequence,
        mutation_count: decoded.mutation_count,
        container_count: decoded.container_count,
        directory_end,
        frames: decoded.frames,
    })
}

/// Authenticates and opens one exact selected frame range.
pub fn open_v2_index_run_frame(
    keyring: &KeyRing,
    repository_context: &[u8],
    containing_object: &BackendObjectId,
    expected_section_ordinal: u32,
    directory: &V2VerifiedIndexRunDirectory,
    frame_ordinal: u32,
    exact_stored_frame: &[u8],
) -> V2Result<Bytes> {
    validate_context_bytes(repository_context, containing_object)?;
    if directory.header.section_ordinal != expected_section_ordinal {
        return Err(V2FormatError::InvalidIndexRun);
    }
    let descriptor = directory
        .frame(frame_ordinal)
        .ok_or(V2FormatError::InvalidIndexRun)?;
    if exact_stored_frame.len() != descriptor.stored_len as usize {
        return Err(V2FormatError::InvalidIndexRun);
    }
    let nonce = exact_stored_frame
        .get(..INDEX_RUN_NONCE_LEN)
        .ok_or(V2FormatError::InvalidIndexRun)?;
    let tag = exact_stored_frame
        .get(INDEX_RUN_NONCE_LEN..INDEX_RUN_SEAL_OVERHEAD)
        .ok_or(V2FormatError::InvalidIndexRun)?;
    let ciphertext = exact_stored_frame
        .get(INDEX_RUN_SEAL_OVERHEAD..)
        .ok_or(V2FormatError::InvalidIndexRun)?;
    let common_aad =
        common_associated_data(repository_context, containing_object, &directory.header)?;
    let frame_aad = frame_associated_data(&common_aad, &directory.directory_digest, descriptor)?;
    let plaintext = keyring.open_metadata_payload(
        &directory.header.key_id,
        &frame_aad,
        nonce,
        ciphertext,
        tag,
    )?;
    if plaintext.len() != descriptor.plaintext_len as usize {
        return Err(V2FormatError::InvalidIndexRun);
    }
    Ok(Bytes::from(plaintext))
}

/// Fully verifies, canonically decodes, and then visits every plaintext frame.
///
/// The visitor is never invoked when any later frame, projection, bound, or
/// trailing byte is invalid. Callers still must treat an error returned by
/// their own visitor as a failed candidate transaction.
pub fn open_v2_index_run_frames<F>(
    keyring: &KeyRing,
    repository_context: &[u8],
    containing_object: &BackendObjectId,
    expected_section_ordinal: u32,
    stored: &[u8],
    limits: &IndexRunLimits,
    mut visit: F,
) -> V2Result<IndexRun>
where
    F: FnMut(&V2IndexRunFrameDescriptor, Bytes) -> V2Result<()>,
{
    let directory = open_v2_index_run_directory(
        keyring,
        repository_context,
        containing_object,
        expected_section_ordinal,
        stored,
        limits,
    )?;
    if stored.len() != to_usize(directory.header.stored_len)? {
        return Err(V2FormatError::InvalidIndexRun);
    }

    let mut plaintext_frames = Vec::new();
    plaintext_frames
        .try_reserve_exact(directory.frames.len())
        .map_err(|_| V2FormatError::IndexRunLimitExceeded)?;
    for descriptor in &directory.frames {
        let range = descriptor.stored_range();
        let frame = stored
            .get(to_usize(range.start)?..to_usize(range.end)?)
            .ok_or(V2FormatError::InvalidIndexRun)?;
        plaintext_frames.push(open_v2_index_run_frame(
            keyring,
            repository_context,
            containing_object,
            expected_section_ordinal,
            &directory,
            descriptor.ordinal,
            frame,
        )?);
    }

    let run = decode_index_run_frames(&plaintext_frames, limits)
        .map_err(|_| V2FormatError::InvalidIndexRun)?;
    verify_logical_directory_match(&run, limits, &plaintext_frames, &directory)?;
    for (descriptor, plaintext) in directory.frames.iter().zip(plaintext_frames) {
        visit(descriptor, plaintext)?;
    }
    Ok(run)
}

/// Fully verifies and decodes one complete stored run without a visitor.
pub fn open_v2_index_run(
    keyring: &KeyRing,
    repository_context: &[u8],
    containing_object: &BackendObjectId,
    expected_section_ordinal: u32,
    stored: &[u8],
    limits: &IndexRunLimits,
) -> V2Result<IndexRun> {
    open_v2_index_run_frames(
        keyring,
        repository_context,
        containing_object,
        expected_section_ordinal,
        stored,
        limits,
        |_, _| Ok(()),
    )
}

fn verify_logical_directory_match(
    run: &IndexRun,
    limits: &IndexRunLimits,
    opened: &[Bytes],
    directory: &V2VerifiedIndexRunDirectory,
) -> V2Result<()> {
    let container_count = run
        .containers
        .len()
        .checked_add(run.stream_containers.len())
        .and_then(|count| count.checked_add(run.standalone_stream_containers.len()))
        .ok_or(V2FormatError::IndexRunLimitExceeded)?;
    if run.sequence != directory.sequence
        || run.mutations.len() != directory.mutation_count as usize
        || container_count != directory.container_count as usize
    {
        return Err(V2FormatError::InvalidIndexRun);
    }
    let canonical =
        encode_index_run_frames(run, limits).map_err(|_| V2FormatError::InvalidIndexRun)?;
    if canonical.frames.len() != directory.frames.len() || opened.len() != directory.frames.len() {
        return Err(V2FormatError::InvalidIndexRun);
    }
    for ((encoded, descriptor), plaintext) in
        canonical.frames.iter().zip(&directory.frames).zip(opened)
    {
        if !descriptor_matches_encoded(descriptor, encoded)
            || encoded.bytes.as_slice() != plaintext.as_ref()
        {
            return Err(V2FormatError::InvalidIndexRun);
        }
    }
    Ok(())
}

fn descriptors_with_first_offset(
    frames: &[EncodedIndexRunFrame],
    first_offset: u64,
) -> V2Result<Vec<V2IndexRunFrameDescriptor>> {
    let mut offset = first_offset;
    let mut descriptors = Vec::new();
    descriptors
        .try_reserve_exact(frames.len())
        .map_err(|_| V2FormatError::IndexRunLimitExceeded)?;
    for (ordinal, frame) in frames.iter().enumerate() {
        if frame.bytes.is_empty() || frame.bytes.len() > V2_INDEX_RUN_MAX_FRAME_PLAINTEXT_BYTES {
            return Err(V2FormatError::IndexRunLimitExceeded);
        }
        let plaintext_len = to_u32(frame.bytes.len())?;
        let stored_len = to_u32(
            frame
                .bytes
                .len()
                .checked_add(INDEX_RUN_SEAL_OVERHEAD)
                .ok_or(V2FormatError::IndexRunLimitExceeded)?,
        )?;
        descriptors.push(V2IndexRunFrameDescriptor {
            ordinal: to_u32(ordinal)?,
            role: frame.role,
            role_ordinal: frame.role_ordinal,
            offset,
            stored_len,
            plaintext_len,
            record_count: frame.record_count,
            first_bound: frame.first_bound.clone(),
            last_bound: frame.last_bound.clone(),
        });
        offset = offset
            .checked_add(u64::from(stored_len))
            .ok_or(V2FormatError::IndexRunLimitExceeded)?;
    }
    Ok(descriptors)
}

fn descriptor_matches_encoded(
    descriptor: &V2IndexRunFrameDescriptor,
    encoded: &EncodedIndexRunFrame,
) -> bool {
    descriptor.role == encoded.role
        && descriptor.role_ordinal == encoded.role_ordinal
        && descriptor.record_count == encoded.record_count
        && descriptor.plaintext_len as usize == encoded.bytes.len()
        && descriptor.first_bound == encoded.first_bound
        && descriptor.last_bound == encoded.last_bound
}

fn encode_header(output: &mut Vec<u8>, header: &RunHeader) -> V2Result<()> {
    output.extend_from_slice(INDEX_RUN_MAGIC);
    output.extend_from_slice(&INDEX_RUN_FORMAT_GENERATION.to_be_bytes());
    output.extend_from_slice(&0_u16.to_be_bytes());
    output.extend_from_slice(&header.header_len.to_be_bytes());
    output.extend_from_slice(&header.stored_len.to_be_bytes());
    output.extend_from_slice(&header.section_ordinal.to_be_bytes());
    output.extend_from_slice(&header.frame_count.to_be_bytes());
    output.extend_from_slice(header.run_id.as_bytes());
    push_u16(output, header.key_id.as_str().len())?;
    output.extend_from_slice(&0_u16.to_be_bytes());
    output.extend_from_slice(&header.directory_plaintext_len.to_be_bytes());
    output.extend_from_slice(&header.directory_ciphertext_len.to_be_bytes());
    output.extend_from_slice(header.key_id.as_str().as_bytes());
    if output.len() != header.header_len as usize {
        return Err(V2FormatError::InvalidIndexRun);
    }
    Ok(())
}

fn parse_header(stored: &[u8]) -> V2Result<RunHeader> {
    if stored.len() < INDEX_RUN_FIXED_HEADER_LEN {
        return Err(V2FormatError::InvalidIndexRun);
    }
    let mut reader = RunReader::new(stored);
    if reader.take(INDEX_RUN_MAGIC.len())? != INDEX_RUN_MAGIC
        || reader.read_u16()? != INDEX_RUN_FORMAT_GENERATION
        || reader.read_u16()? != 0
    {
        return Err(V2FormatError::InvalidIndexRun);
    }
    let header_len = reader.read_u32()?;
    let stored_len = reader.read_u64()?;
    let section_ordinal = reader.read_u32()?;
    let frame_count = reader.read_u32()?;
    let run_id = V2IndexRunId(reader.read_array()?);
    let key_id_len = usize::from(reader.read_u16()?);
    if reader.read_u16()? != 0 {
        return Err(V2FormatError::InvalidIndexRun);
    }
    let directory_plaintext_len = reader.read_u32()?;
    let directory_ciphertext_len = reader.read_u32()?;
    if key_id_len == 0
        || key_id_len > INDEX_RUN_MAX_KEY_ID_LEN
        || header_len as usize != INDEX_RUN_FIXED_HEADER_LEN + key_id_len
        || frame_count == 0
        || frame_count as usize > V2_INDEX_RUN_MAX_FRAME_COUNT
        || stored_len > V2_INDEX_RUN_MAX_OBJECT_BYTES as u64
        || directory_plaintext_len == 0
        || directory_plaintext_len as usize > V2_INDEX_RUN_MAX_DIRECTORY_PLAINTEXT_BYTES
        || directory_ciphertext_len != directory_plaintext_len
    {
        return Err(V2FormatError::IndexRunLimitExceeded);
    }
    let key_id_bytes = reader.take(key_id_len)?;
    let key_id_text =
        std::str::from_utf8(key_id_bytes).map_err(|_| V2FormatError::InvalidIndexRun)?;
    let key_id = KeyId::new(key_id_text.to_owned()).map_err(|_| V2FormatError::InvalidIndexRun)?;
    Ok(RunHeader {
        header_len,
        stored_len,
        section_ordinal,
        frame_count,
        run_id,
        key_id,
        directory_plaintext_len,
        directory_ciphertext_len,
    })
}

fn encode_directory(
    sequence: Sequence,
    mutation_count: u32,
    container_count: u32,
    frames: &[V2IndexRunFrameDescriptor],
) -> V2Result<Vec<u8>> {
    let mut output = Vec::new();
    output.extend_from_slice(INDEX_RUN_DIRECTORY_DOMAIN);
    output.extend_from_slice(&INDEX_RUN_DIRECTORY_VERSION.to_be_bytes());
    output.extend_from_slice(&0_u16.to_be_bytes());
    output.extend_from_slice(&sequence.get().to_be_bytes());
    output.extend_from_slice(&mutation_count.to_be_bytes());
    output.extend_from_slice(&container_count.to_be_bytes());
    push_u32(&mut output, frames.len())?;
    for descriptor in frames {
        encode_descriptor(&mut output, descriptor)?;
    }
    Ok(output)
}

struct DecodedDirectory {
    sequence: Sequence,
    mutation_count: u32,
    container_count: u32,
    frames: Vec<V2IndexRunFrameDescriptor>,
}

fn decode_directory(
    encoded: &[u8],
    header: &RunHeader,
    directory_end: usize,
    limits: &IndexRunLimits,
) -> V2Result<DecodedDirectory> {
    let mut reader = RunReader::new(encoded);
    if reader.take(INDEX_RUN_DIRECTORY_DOMAIN.len())? != INDEX_RUN_DIRECTORY_DOMAIN
        || reader.read_u16()? != INDEX_RUN_DIRECTORY_VERSION
        || reader.read_u16()? != 0
    {
        return Err(V2FormatError::InvalidIndexRun);
    }
    let sequence = Sequence::new(reader.read_u64()?);
    let mutation_count = reader.read_u32()?;
    let container_count = reader.read_u32()?;
    let frame_count = reader.read_u32()?;
    if frame_count != header.frame_count
        || mutation_count as usize > limits.max_mutations
        || container_count as usize > limits.max_containers
    {
        return Err(V2FormatError::IndexRunLimitExceeded);
    }
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(frame_count as usize)
        .map_err(|_| V2FormatError::IndexRunLimitExceeded)?;
    for ordinal in 0..frame_count {
        let descriptor = decode_descriptor(&mut reader, limits)?;
        if descriptor.ordinal != ordinal {
            return Err(V2FormatError::InvalidIndexRun);
        }
        frames.push(descriptor);
    }
    if !reader.is_empty() {
        return Err(V2FormatError::InvalidIndexRun);
    }
    validate_directory_layout(
        &frames,
        directory_end,
        header.stored_len,
        mutation_count,
        container_count,
    )?;
    Ok(DecodedDirectory {
        sequence,
        mutation_count,
        container_count,
        frames,
    })
}

fn encode_descriptor(output: &mut Vec<u8>, descriptor: &V2IndexRunFrameDescriptor) -> V2Result<()> {
    output.extend_from_slice(&descriptor.ordinal.to_be_bytes());
    output.push(role_tag(descriptor.role));
    output.extend_from_slice(&[0_u8; 3]);
    output.extend_from_slice(&descriptor.role_ordinal.to_be_bytes());
    output.extend_from_slice(&descriptor.offset.to_be_bytes());
    output.extend_from_slice(&descriptor.stored_len.to_be_bytes());
    output.extend_from_slice(&descriptor.plaintext_len.to_be_bytes());
    output.extend_from_slice(&descriptor.record_count.to_be_bytes());
    encode_bound(output, descriptor.first_bound.as_ref())?;
    encode_bound(output, descriptor.last_bound.as_ref())?;
    Ok(())
}

fn decode_descriptor(
    reader: &mut RunReader<'_>,
    limits: &IndexRunLimits,
) -> V2Result<V2IndexRunFrameDescriptor> {
    let ordinal = reader.read_u32()?;
    let role = decode_role(reader.read_u8()?)?;
    if reader.take(3)? != [0_u8; 3] {
        return Err(V2FormatError::InvalidIndexRun);
    }
    let role_ordinal = reader.read_u32()?;
    let offset = reader.read_u64()?;
    let stored_len = reader.read_u32()?;
    let plaintext_len = reader.read_u32()?;
    let record_count = reader.read_u32()?;
    let first_bound = decode_bound(reader, limits)?;
    let last_bound = decode_bound(reader, limits)?;
    Ok(V2IndexRunFrameDescriptor {
        ordinal,
        role,
        role_ordinal,
        offset,
        stored_len,
        plaintext_len,
        record_count,
        first_bound,
        last_bound,
    })
}

fn encode_bound(output: &mut Vec<u8>, bound: Option<&IndexRunSearchBound>) -> V2Result<()> {
    match bound {
        None => output.push(0),
        Some(IndexRunSearchBound::Namespace {
            blind_key,
            mutation_ordinal,
        }) => {
            output.push(1);
            output.extend_from_slice(blind_key.as_bytes());
            output.extend_from_slice(&mutation_ordinal.to_be_bytes());
        }
        Some(IndexRunSearchBound::Listing {
            path,
            mutation_ordinal,
        }) => {
            output.push(2);
            push_u16(output, path.as_str().len())?;
            output.extend_from_slice(path.as_str().as_bytes());
            output.extend_from_slice(&mutation_ordinal.to_be_bytes());
        }
    }
    Ok(())
}

fn decode_bound(
    reader: &mut RunReader<'_>,
    limits: &IndexRunLimits,
) -> V2Result<Option<IndexRunSearchBound>> {
    match reader.read_u8()? {
        0 => Ok(None),
        1 => Ok(Some(IndexRunSearchBound::Namespace {
            blind_key: IndexBlindKey::from_bytes(reader.read_array()?),
            mutation_ordinal: reader.read_u32()?,
        })),
        2 => {
            let path_len = usize::from(reader.read_u16()?);
            if path_len == 0 || path_len > limits.max_path_bytes {
                return Err(V2FormatError::IndexRunLimitExceeded);
            }
            let path = std::str::from_utf8(reader.take(path_len)?)
                .map_err(|_| V2FormatError::InvalidIndexRun)?;
            Ok(Some(IndexRunSearchBound::Listing {
                path: LogicalPath::new(path.to_owned())
                    .map_err(|_| V2FormatError::InvalidIndexRun)?,
                mutation_ordinal: reader.read_u32()?,
            }))
        }
        _ => Err(V2FormatError::InvalidIndexRun),
    }
}

fn validate_directory_layout(
    frames: &[V2IndexRunFrameDescriptor],
    directory_end: usize,
    stored_len: u64,
    mutation_count: u32,
    container_count: u32,
) -> V2Result<()> {
    let Some(first) = frames.first() else {
        return Err(V2FormatError::InvalidIndexRun);
    };
    if first.role != IndexRunFrameRole::Metadata || first.role_ordinal != 0 {
        return Err(V2FormatError::InvalidIndexRun);
    }
    let mut expected_offset = to_u64(directory_end)?;
    let mut previous_role = IndexRunFrameRole::Metadata;
    let mut expected_role_ordinal = 0_u32;
    let mut previous_bound: Option<IndexRunSearchBound> = None;
    let mut metadata_records = 0_u64;
    let mut namespace_records = 0_u64;
    let mut listing_records = 0_u64;
    let mut saw_namespace = false;
    let mut saw_listing = false;

    for descriptor in frames {
        if descriptor.offset != expected_offset
            || descriptor.plaintext_len == 0
            || descriptor.plaintext_len as usize > V2_INDEX_RUN_MAX_FRAME_PLAINTEXT_BYTES
            || descriptor.stored_len as usize
                != descriptor.plaintext_len as usize + INDEX_RUN_SEAL_OVERHEAD
        {
            return Err(V2FormatError::InvalidIndexRun);
        }
        expected_offset = expected_offset
            .checked_add(u64::from(descriptor.stored_len))
            .ok_or(V2FormatError::InvalidIndexRun)?;

        if descriptor.role == previous_role {
            if descriptor.role_ordinal != expected_role_ordinal {
                return Err(V2FormatError::InvalidIndexRun);
            }
        } else {
            if role_tag(descriptor.role) != role_tag(previous_role) + 1
                || descriptor.role_ordinal != 0
            {
                return Err(V2FormatError::InvalidIndexRun);
            }
            previous_role = descriptor.role;
            expected_role_ordinal = 0;
            previous_bound = None;
        }
        expected_role_ordinal = expected_role_ordinal
            .checked_add(1)
            .ok_or(V2FormatError::InvalidIndexRun)?;

        match descriptor.role {
            IndexRunFrameRole::Metadata => {
                if descriptor.first_bound.is_some() || descriptor.last_bound.is_some() {
                    return Err(V2FormatError::InvalidIndexRun);
                }
                metadata_records += u64::from(descriptor.record_count);
            }
            IndexRunFrameRole::Namespace => {
                saw_namespace = true;
                validate_projection_descriptor(descriptor, true, &mut previous_bound)?;
                namespace_records += u64::from(descriptor.record_count);
            }
            IndexRunFrameRole::Listing => {
                saw_listing = true;
                validate_projection_descriptor(descriptor, false, &mut previous_bound)?;
                listing_records += u64::from(descriptor.record_count);
            }
        }
    }
    if expected_offset != stored_len
        || metadata_records != u64::from(container_count)
        || (mutation_count == 0 && (saw_namespace || saw_listing))
        || (mutation_count > 0 && (!saw_namespace || !saw_listing))
        || namespace_records != u64::from(mutation_count)
        || listing_records != u64::from(mutation_count)
    {
        return Err(V2FormatError::InvalidIndexRun);
    }
    Ok(())
}

fn validate_projection_descriptor(
    descriptor: &V2IndexRunFrameDescriptor,
    namespace: bool,
    previous_bound: &mut Option<IndexRunSearchBound>,
) -> V2Result<()> {
    if descriptor.record_count == 0 {
        return Err(V2FormatError::InvalidIndexRun);
    }
    let (Some(first), Some(last)) = (&descriptor.first_bound, &descriptor.last_bound) else {
        return Err(V2FormatError::InvalidIndexRun);
    };
    let correct_role = matches!(
        (namespace, first, last),
        (
            true,
            IndexRunSearchBound::Namespace { .. },
            IndexRunSearchBound::Namespace { .. }
        ) | (
            false,
            IndexRunSearchBound::Listing { .. },
            IndexRunSearchBound::Listing { .. }
        )
    );
    if !correct_role || compare_bounds(first, last)? == Ordering::Greater {
        return Err(V2FormatError::InvalidIndexRun);
    }
    if let Some(previous) = previous_bound
        && compare_bounds(previous, first)? != Ordering::Less
    {
        return Err(V2FormatError::InvalidIndexRun);
    }
    *previous_bound = Some(last.clone());
    Ok(())
}

fn compare_bounds(left: &IndexRunSearchBound, right: &IndexRunSearchBound) -> V2Result<Ordering> {
    match (left, right) {
        (
            IndexRunSearchBound::Namespace {
                blind_key: left_key,
                mutation_ordinal: left_ordinal,
            },
            IndexRunSearchBound::Namespace {
                blind_key: right_key,
                mutation_ordinal: right_ordinal,
            },
        ) => Ok(left_key
            .cmp(right_key)
            .then_with(|| left_ordinal.cmp(right_ordinal))),
        (
            IndexRunSearchBound::Listing {
                path: left_path,
                mutation_ordinal: left_ordinal,
            },
            IndexRunSearchBound::Listing {
                path: right_path,
                mutation_ordinal: right_ordinal,
            },
        ) => Ok(left_path
            .as_str()
            .as_bytes()
            .cmp(right_path.as_str().as_bytes())
            .then_with(|| left_ordinal.cmp(right_ordinal))),
        _ => Err(V2FormatError::InvalidIndexRun),
    }
}

fn common_associated_data(
    repository_context: &[u8],
    containing_object: &BackendObjectId,
    header: &RunHeader,
) -> V2Result<Vec<u8>> {
    validate_context_bytes(repository_context, containing_object)?;
    let object_key = containing_object.as_str().as_bytes();
    let key_id = header.key_id.as_str().as_bytes();
    let mut aad = Vec::new();
    aad.extend_from_slice(&INDEX_RUN_FORMAT_GENERATION.to_be_bytes());
    push_u32(&mut aad, repository_context.len())?;
    aad.extend_from_slice(repository_context);
    push_u32(&mut aad, object_key.len())?;
    aad.extend_from_slice(object_key);
    aad.extend_from_slice(&header.section_ordinal.to_be_bytes());
    aad.extend_from_slice(header.run_id.as_bytes());
    aad.extend_from_slice(&header.header_len.to_be_bytes());
    aad.extend_from_slice(&header.stored_len.to_be_bytes());
    aad.extend_from_slice(&header.frame_count.to_be_bytes());
    push_u16(&mut aad, key_id.len())?;
    aad.extend_from_slice(key_id);
    aad.extend_from_slice(&header.directory_plaintext_len.to_be_bytes());
    aad.extend_from_slice(&header.directory_ciphertext_len.to_be_bytes());
    Ok(aad)
}

fn frame_associated_data(
    common: &[u8],
    directory_digest: &[u8; INDEX_RUN_DIGEST_LEN],
    descriptor: &V2IndexRunFrameDescriptor,
) -> V2Result<Vec<u8>> {
    let mut aad = Vec::new();
    aad.extend_from_slice(INDEX_RUN_FRAME_AAD_DOMAIN);
    aad.extend_from_slice(common);
    aad.extend_from_slice(directory_digest);
    encode_descriptor(&mut aad, descriptor)?;
    Ok(aad)
}

fn validate_context(
    repository_context: &[u8],
    containing_object: &BackendObjectId,
    limits: &IndexRunLimits,
) -> V2Result<()> {
    validate_context_bytes(repository_context, containing_object)?;
    if limits.max_frame_bytes == 0
        || limits.max_frame_bytes > V2_INDEX_RUN_MAX_FRAME_PLAINTEXT_BYTES
        || limits.max_total_bytes > V2_INDEX_RUN_MAX_OBJECT_BYTES
    {
        return Err(V2FormatError::IndexRunLimitExceeded);
    }
    Ok(())
}

fn validate_context_bytes(
    repository_context: &[u8],
    containing_object: &BackendObjectId,
) -> V2Result<()> {
    if repository_context.is_empty()
        || repository_context.len() > INDEX_RUN_MAX_REPOSITORY_CONTEXT_LEN
        || containing_object.as_str().len() > INDEX_RUN_MAX_OBJECT_KEY_LEN
    {
        return Err(V2FormatError::IndexRunLimitExceeded);
    }
    Ok(())
}

fn validate_metadata_seal(
    actual_key_id: &KeyId,
    expected_key_id: &KeyId,
    nonce: &[u8],
    tag: &[u8],
    ciphertext: &[u8],
    plaintext_len: usize,
) -> V2Result<()> {
    if actual_key_id != expected_key_id
        || nonce.len() != INDEX_RUN_NONCE_LEN
        || tag.len() != INDEX_RUN_TAG_LEN
        || ciphertext.len() != plaintext_len
    {
        return Err(V2FormatError::CryptoOperation);
    }
    Ok(())
}

const fn role_tag(role: IndexRunFrameRole) -> u8 {
    match role {
        IndexRunFrameRole::Metadata => 0,
        IndexRunFrameRole::Namespace => 1,
        IndexRunFrameRole::Listing => 2,
    }
}

fn decode_role(tag: u8) -> V2Result<IndexRunFrameRole> {
    match tag {
        0 => Ok(IndexRunFrameRole::Metadata),
        1 => Ok(IndexRunFrameRole::Namespace),
        2 => Ok(IndexRunFrameRole::Listing),
        _ => Err(V2FormatError::InvalidIndexRun),
    }
}

fn push_u16(output: &mut Vec<u8>, value: usize) -> V2Result<()> {
    output.extend_from_slice(
        &u16::try_from(value)
            .map_err(|_| V2FormatError::IndexRunLimitExceeded)?
            .to_be_bytes(),
    );
    Ok(())
}

fn push_u32(output: &mut Vec<u8>, value: usize) -> V2Result<()> {
    output.extend_from_slice(&to_u32(value)?.to_be_bytes());
    Ok(())
}

fn to_u32(value: usize) -> V2Result<u32> {
    u32::try_from(value).map_err(|_| V2FormatError::IndexRunLimitExceeded)
}

fn to_u64(value: usize) -> V2Result<u64> {
    u64::try_from(value).map_err(|_| V2FormatError::IndexRunLimitExceeded)
}

fn to_usize(value: u64) -> V2Result<usize> {
    usize::try_from(value).map_err(|_| V2FormatError::IndexRunLimitExceeded)
}

struct RunReader<'a> {
    remaining: &'a [u8],
}

impl<'a> RunReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, len: usize) -> V2Result<&'a [u8]> {
        let Some((value, remaining)) = self.remaining.split_at_checked(len) else {
            return Err(V2FormatError::InvalidIndexRun);
        };
        self.remaining = remaining;
        Ok(value)
    }

    fn read_u8(&mut self) -> V2Result<u8> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(V2FormatError::InvalidIndexRun)
    }

    fn read_u16(&mut self) -> V2Result<u16> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> V2Result<u32> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> V2Result<u64> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    fn read_array<const N: usize>(&mut self) -> V2Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| V2FormatError::InvalidIndexRun)
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        INDEX_RUN_FIXED_HEADER_LEN, INDEX_RUN_SEAL_OVERHEAD, V2FormatError,
        V2IndexRunFrameDescriptor, common_associated_data, encode_directory, open_v2_index_run,
        open_v2_index_run_directory, open_v2_index_run_frame, open_v2_index_run_frames,
        parse_header, probe_v2_index_run_header, seal_v2_index_run,
    };
    use bytes::Bytes;
    use rs3_crypto::{KeyMaterial, KeyRing, SecretBytes};
    use rs3_index::PayloadHeaderReference;
    use rs3_index::run::{
        IndexBlindKey, IndexMutation, IndexPackRecordPointer, IndexPayloadPointer, IndexRun,
        IndexRunContainer, IndexRunFrameRole, IndexRunKeyringRef, IndexRunLimits,
        IndexRunSearchBound, IndexRunSelfPack, IndexRunSelfStream, IndexRunStreamContainer,
        IndexTombstone, IndexUpsert, encode_index_run_frames,
    };
    use rs3_types::{
        BackendObjectId, BackendVersionId, KeyDescriptor, KeyId, KeyPurpose, KeyStatus,
        LegalHoldStatus, LogicalPath, RetentionMode, RetentionPolicy, Sequence,
    };
    use std::cell::Cell;

    const REPOSITORY_CONTEXT: &[u8] = b"format-root/repository-a/generation-2";

    fn must<T, E: std::fmt::Display>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{error}"),
        }
    }

    fn keyring() -> KeyRing {
        must(KeyRing::new(vec![
            KeyMaterial::new(
                KeyDescriptor {
                    id: must(KeyId::new("namespace")),
                    purpose: KeyPurpose::Namespace,
                    algorithm: "hmac-sha256".to_owned(),
                    status: KeyStatus::Primary,
                    created_at_ms: 0,
                    not_before_ms: None,
                    not_after_ms: None,
                    public_key: None,
                    external_kms_uri: None,
                },
                must(SecretBytes::new(vec![3; SecretBytes::MIN_LEN])),
            ),
            KeyMaterial::new(
                KeyDescriptor {
                    id: must(KeyId::new("metadata")),
                    purpose: KeyPurpose::Metadata,
                    algorithm: "aes-256-gcm-siv-hmac-sha256-nonce-v1".to_owned(),
                    status: KeyStatus::Primary,
                    created_at_ms: 0,
                    not_before_ms: None,
                    not_after_ms: None,
                    public_key: None,
                    external_kms_uri: None,
                },
                must(SecretBytes::new(vec![7; SecretBytes::MIN_LEN])),
            ),
        ]))
    }

    fn object_id(value: &str) -> BackendObjectId {
        must(BackendObjectId::new(value))
    }

    fn limits() -> IndexRunLimits {
        IndexRunLimits {
            max_frame_bytes: 512,
            ..IndexRunLimits::default()
        }
    }

    fn fixture() -> IndexRun {
        IndexRun {
            sequence: Sequence::new(9),
            self_pack: Some(IndexRunSelfPack {
                pack_id: [0x11; 32],
                content_key_id: must(KeyId::new("content-v1")),
                stored_len: 128,
                record_count: 4,
            }),
            self_stream: None,
            containers: vec![IndexRunContainer {
                object_id: object_id("objects/v02/pack-a"),
                version_id: Some(must(BackendVersionId::new("version-3"))),
                stored_len: 4_096,
                commit_body_digest: [0x22; 32],
                keyring_envelope: IndexRunKeyringRef {
                    object_id: object_id("metadata/v02/keyring-a"),
                    digest: [0x33; 32],
                },
                pack_section_ordinal: 1,
                pack_section_offset: 512,
                pack_section_len: 2_048,
                pack_id: [0x44; 32],
                content_key_id: must(KeyId::new("content-v0")),
                pack_record_count: 8,
            }],
            stream_containers: Vec::new(),
            standalone_stream_containers: Vec::new(),
            mutations: vec![
                IndexMutation::Upsert(IndexUpsert {
                    mutation_ordinal: 0,
                    blind_key: IndexBlindKey::from_bytes([0x30; 32]),
                    namespace_key_id: must(KeyId::new("namespace")),
                    path: must(LogicalPath::new("tenant/z-last")),
                    generation: Sequence::new(17),
                    payload: IndexPayloadPointer::SelfPack {
                        record: IndexPackRecordPointer {
                            record_ordinal: 0,
                            physical_offset: 0,
                            plaintext_digest: [0x55; 32],
                        },
                    },
                    content_len: 4,
                    modified_at_ms: 10,
                    retention: Some(RetentionPolicy::new(RetentionMode::Compliance, 30)),
                    legal_hold: Some(LegalHoldStatus::On),
                }),
                IndexMutation::Upsert(IndexUpsert {
                    mutation_ordinal: 1,
                    blind_key: IndexBlindKey::from_bytes([0x10; 32]),
                    namespace_key_id: must(KeyId::new("namespace")),
                    path: must(LogicalPath::new("tenant/a-first")),
                    generation: Sequence::new(18),
                    payload: IndexPayloadPointer::ExternalPack {
                        container_ordinal: 0,
                        record: IndexPackRecordPointer {
                            record_ordinal: 2,
                            physical_offset: 42,
                            plaintext_digest: [0x66; 32],
                        },
                    },
                    content_len: 5,
                    modified_at_ms: 11,
                    retention: None,
                    legal_hold: None,
                }),
                IndexMutation::Tombstone(IndexTombstone {
                    mutation_ordinal: 2,
                    blind_key: IndexBlindKey::from_bytes([0x20; 32]),
                    namespace_key_id: must(KeyId::new("namespace")),
                    path: must(LogicalPath::new("tenant/m-deleted")),
                    generation: Sequence::new(19),
                }),
                IndexMutation::Upsert(IndexUpsert {
                    mutation_ordinal: 3,
                    blind_key: IndexBlindKey::from_bytes([0x40; 32]),
                    namespace_key_id: must(KeyId::new("namespace")),
                    path: must(LogicalPath::new("tenant/empty")),
                    generation: Sequence::new(20),
                    payload: IndexPayloadPointer::Empty,
                    content_len: 0,
                    modified_at_ms: 12,
                    retention: None,
                    legal_hold: Some(LegalHoldStatus::Off),
                }),
            ],
        }
    }

    fn stream_header() -> PayloadHeaderReference {
        PayloadHeaderReference {
            chunk_size: 64 * 1024,
            plaintext_len: 131_089,
            key_id: must(KeyId::new("stream-content-v1")),
            nonce_prefix: [0x91; 16],
            header_len: 73,
        }
    }

    fn self_stream_fixture() -> IndexRun {
        IndexRun {
            sequence: Sequence::new(31),
            self_pack: None,
            self_stream: Some(IndexRunSelfStream {
                payload_section_ordinal: 0,
                payload_id: object_id("payloads/v02/self-stream"),
                payload_header: stream_header(),
            }),
            containers: Vec::new(),
            stream_containers: Vec::new(),
            standalone_stream_containers: Vec::new(),
            mutations: vec![IndexMutation::Upsert(IndexUpsert {
                mutation_ordinal: 0,
                blind_key: IndexBlindKey::from_bytes([0x92; 32]),
                namespace_key_id: must(KeyId::new("namespace")),
                path: must(LogicalPath::new("tenant/self-stream")),
                generation: Sequence::new(31),
                payload: IndexPayloadPointer::SelfStream,
                content_len: stream_header().plaintext_len,
                modified_at_ms: 31,
                retention: None,
                legal_hold: None,
            })],
        }
    }

    fn external_stream_fixture() -> IndexRun {
        let payload_header = stream_header();
        let payload_section_len = payload_header.header_len
            + payload_header.plaintext_len
            + payload_header
                .plaintext_len
                .div_ceil(payload_header.chunk_size)
                * 16;
        IndexRun {
            sequence: Sequence::new(32),
            self_pack: None,
            self_stream: None,
            containers: Vec::new(),
            stream_containers: vec![IndexRunStreamContainer {
                object_id: object_id("commits/v02/external-stream"),
                version_id: Some(must(BackendVersionId::new("stream-version-4"))),
                stored_len: 200_000,
                commit_body_digest: [0x93; 32],
                keyring_envelope: IndexRunKeyringRef {
                    object_id: object_id("metadata/v02/stream-keyring"),
                    digest: [0x94; 32],
                },
                sections_start: 8_192,
                payload_section_ordinal: 0,
                payload_section_offset: 512,
                payload_section_len,
                payload_section_digest: [0x95; 32],
                payload_id: object_id("payloads/v02/external-stream"),
                payload_header,
            }],
            standalone_stream_containers: Vec::new(),
            mutations: vec![IndexMutation::Upsert(IndexUpsert {
                mutation_ordinal: 0,
                blind_key: IndexBlindKey::from_bytes([0x96; 32]),
                namespace_key_id: must(KeyId::new("namespace")),
                path: must(LogicalPath::new("tenant/external-stream")),
                generation: Sequence::new(32),
                payload: IndexPayloadPointer::ExternalStream {
                    container_ordinal: 0,
                },
                content_len: stream_header().plaintext_len,
                modified_at_ms: 32,
                retention: Some(RetentionPolicy::new(RetentionMode::Governance, 7)),
                legal_hold: None,
            })],
        }
    }

    fn sealed() -> (KeyRing, BackendObjectId, IndexRunLimits, IndexRun, Bytes) {
        let keyring = keyring();
        let object = object_id("commits/v02/framed-example");
        let limits = limits();
        let run = fixture();
        let sealed = must(seal_v2_index_run(
            &keyring,
            REPOSITORY_CONTEXT,
            &object,
            2,
            &run,
            &limits,
        ));
        (keyring, object, limits, run, sealed.into_bytes())
    }

    #[test]
    fn round_trips_and_opens_selected_exact_ranges() {
        let (keyring, object, limits, run, stored) = sealed();
        let probe = must(probe_v2_index_run_header(
            &stored[..INDEX_RUN_FIXED_HEADER_LEN],
        ));
        assert_eq!(probe.stored_len(), stored.len() as u64);
        assert_eq!(probe.section_ordinal(), 2);
        assert!(probe.directory_prefix_len() < stored.len());

        let directory = must(open_v2_index_run_directory(
            &keyring,
            REPOSITORY_CONTEXT,
            &object,
            2,
            &stored[..probe.directory_prefix_len()],
            &limits,
        ));
        assert_eq!(directory.stored_len(), stored.len() as u64);
        assert_eq!(directory.directory_end(), probe.directory_prefix_len());
        assert_eq!(directory.frames().len(), probe.frame_count() as usize);
        assert!(!format!("{directory:?}").contains("tenant/"));

        let canonical = must(encode_index_run_frames(&run, &limits));
        for (descriptor, expected) in directory.frames().iter().zip(canonical.frames) {
            let range = descriptor.stored_range();
            let selected = must(open_v2_index_run_frame(
                &keyring,
                REPOSITORY_CONTEXT,
                &object,
                2,
                &directory,
                descriptor.ordinal(),
                &stored[range.start as usize..range.end as usize],
            ));
            assert_eq!(selected.as_ref(), expected.bytes);
            assert_eq!(descriptor.role(), expected.role);
            assert_eq!(descriptor.role_ordinal(), expected.role_ordinal);
            assert_eq!(descriptor.record_count(), expected.record_count);
        }
        assert_eq!(
            must(open_v2_index_run(
                &keyring,
                REPOSITORY_CONTEXT,
                &object,
                2,
                &stored,
                &limits,
            )),
            run
        );
    }

    #[test]
    fn streamed_payload_carriers_round_trip_through_outer_framing() {
        let keyring = keyring();
        let limits = IndexRunLimits::default();
        for (name, run) in [
            ("self", self_stream_fixture()),
            ("external", external_stream_fixture()),
        ] {
            let object = object_id(&format!("commits/v02/{name}-stream-run"));
            let sealed = must(seal_v2_index_run(
                &keyring,
                REPOSITORY_CONTEXT,
                &object,
                1,
                &run,
                &limits,
            ));
            let directory = must(open_v2_index_run_directory(
                &keyring,
                REPOSITORY_CONTEXT,
                &object,
                1,
                sealed.bytes(),
                &limits,
            ));
            assert!(!directory.frames().is_empty());
            assert_eq!(
                must(open_v2_index_run(
                    &keyring,
                    REPOSITORY_CONTEXT,
                    &object,
                    1,
                    sealed.bytes(),
                    &limits,
                )),
                run,
                "{name} stream run must round trip"
            );
        }
    }

    #[test]
    fn streamed_payload_carrier_frames_reject_tampering() {
        let keyring = keyring();
        let limits = IndexRunLimits::default();
        for (name, run) in [
            ("self", self_stream_fixture()),
            ("external", external_stream_fixture()),
        ] {
            let object = object_id(&format!("commits/v02/{name}-stream-tamper"));
            let sealed = must(seal_v2_index_run(
                &keyring,
                REPOSITORY_CONTEXT,
                &object,
                1,
                &run,
                &limits,
            ));
            let directory = must(open_v2_index_run_directory(
                &keyring,
                REPOSITORY_CONTEXT,
                &object,
                1,
                sealed.bytes(),
                &limits,
            ));
            let metadata = directory
                .frames()
                .iter()
                .find(|frame| frame.role() == IndexRunFrameRole::Metadata)
                .expect("metadata frame");
            let mut tampered = sealed.bytes().to_vec();
            let range = metadata.stored_range();
            tampered[usize::try_from(range.end).expect("frame end") - 1] ^= 1;

            assert!(
                open_v2_index_run(&keyring, REPOSITORY_CONTEXT, &object, 1, &tampered, &limits,)
                    .is_err(),
                "accepted tampered {name} stream carrier"
            );
        }
    }

    #[test]
    fn round_trips_an_all_delete_run_without_any_payload_pack() {
        let keyring = keyring();
        let object = object_id("commits/v02/delete-only");
        let limits = limits();
        let run = IndexRun {
            sequence: Sequence::new(21),
            self_pack: None,
            self_stream: None,
            containers: Vec::new(),
            stream_containers: Vec::new(),
            standalone_stream_containers: Vec::new(),
            mutations: vec![IndexMutation::Tombstone(IndexTombstone {
                mutation_ordinal: 0,
                blind_key: IndexBlindKey::from_bytes([0x55; 32]),
                namespace_key_id: must(KeyId::new("namespace")),
                path: must(LogicalPath::new("tenant/deleted-only")),
                generation: Sequence::new(21),
            })],
        };
        let sealed = must(seal_v2_index_run(
            &keyring,
            REPOSITORY_CONTEXT,
            &object,
            0,
            &run,
            &limits,
        ));
        assert_eq!(
            must(open_v2_index_run(
                &keyring,
                REPOSITORY_CONTEXT,
                &object,
                0,
                sealed.bytes(),
                &limits,
            )),
            run
        );
    }

    #[test]
    fn rejects_every_complete_run_truncation_and_trailing_bytes() {
        let (keyring, object, limits, _, stored) = sealed();
        for length in 0..stored.len() {
            assert!(
                open_v2_index_run(
                    &keyring,
                    REPOSITORY_CONTEXT,
                    &object,
                    2,
                    &stored[..length],
                    &limits,
                )
                .is_err(),
                "accepted truncation at {length}"
            );
        }
        let mut trailing = stored.to_vec();
        trailing.push(0);
        assert_eq!(
            open_v2_index_run(&keyring, REPOSITORY_CONTEXT, &object, 2, &trailing, &limits,),
            Err(V2FormatError::InvalidIndexRun)
        );
    }

    #[test]
    fn rejects_directory_context_object_section_and_header_transplants() {
        let (keyring, object, limits, _, stored) = sealed();
        assert!(
            open_v2_index_run_directory(
                &keyring,
                b"format-root/repository-b/generation-2",
                &object,
                2,
                &stored,
                &limits,
            )
            .is_err()
        );
        assert!(
            open_v2_index_run_directory(
                &keyring,
                REPOSITORY_CONTEXT,
                &object_id("commits/v02/other"),
                2,
                &stored,
                &limits,
            )
            .is_err()
        );
        assert!(
            open_v2_index_run_directory(
                &keyring,
                REPOSITORY_CONTEXT,
                &object,
                3,
                &stored,
                &limits,
            )
            .is_err()
        );

        for byte_offset in [16_usize, 28, 32] {
            let mut changed = stored.to_vec();
            changed[byte_offset] ^= 1;
            assert!(
                open_v2_index_run_directory(
                    &keyring,
                    REPOSITORY_CONTEXT,
                    &object,
                    2,
                    &changed,
                    &limits,
                )
                .is_err(),
                "accepted changed authenticated header byte {byte_offset}"
            );
        }
    }

    #[test]
    fn rejects_directory_frame_and_selected_range_tampering() {
        let (keyring, object, limits, _, stored) = sealed();
        let directory = must(open_v2_index_run_directory(
            &keyring,
            REPOSITORY_CONTEXT,
            &object,
            2,
            &stored,
            &limits,
        ));
        let mut directory_tampered = stored.to_vec();
        directory_tampered[directory.directory_end() - 1] ^= 1;
        assert!(
            open_v2_index_run_directory(
                &keyring,
                REPOSITORY_CONTEXT,
                &object,
                2,
                &directory_tampered,
                &limits,
            )
            .is_err()
        );

        let last = directory.frames().last().expect("frame descriptor");
        let mut frame_tampered = stored.to_vec();
        let frame_last = last.stored_range().end as usize - 1;
        frame_tampered[frame_last] ^= 1;
        assert!(
            open_v2_index_run(
                &keyring,
                REPOSITORY_CONTEXT,
                &object,
                2,
                &frame_tampered,
                &limits,
            )
            .is_err()
        );

        let first = &directory.frames()[0];
        let first_range = first.stored_range();
        let exact = &stored[first_range.start as usize..first_range.end as usize];
        assert!(
            open_v2_index_run_frame(
                &keyring,
                REPOSITORY_CONTEXT,
                &object,
                2,
                &directory,
                first.ordinal(),
                &exact[..exact.len() - 1],
            )
            .is_err()
        );
        assert!(
            open_v2_index_run_frame(
                &keyring,
                b"format-root/repository-b/generation-2",
                &object,
                2,
                &directory,
                first.ordinal(),
                exact,
            )
            .is_err()
        );
        assert!(
            open_v2_index_run_frame(
                &keyring,
                REPOSITORY_CONTEXT,
                &object_id("commits/v02/other"),
                2,
                &directory,
                first.ordinal(),
                exact,
            )
            .is_err()
        );
        if directory.frames().len() > 1 {
            assert!(
                open_v2_index_run_frame(
                    &keyring,
                    REPOSITORY_CONTEXT,
                    &object,
                    2,
                    &directory,
                    1,
                    exact,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_authenticated_role_and_bound_directory_corruption() {
        let (keyring, object, limits, _, stored) = sealed();
        let changed_role = rewrite_directory(&keyring, &object, &limits, &stored, |frames| {
            frames[0].role = IndexRunFrameRole::Namespace
        });
        assert!(
            open_v2_index_run_directory(
                &keyring,
                REPOSITORY_CONTEXT,
                &object,
                2,
                &changed_role,
                &limits,
            )
            .is_err()
        );

        let changed_bound = rewrite_directory(&keyring, &object, &limits, &stored, |frames| {
            let frame = frames
                .iter_mut()
                .find(|frame| frame.role == IndexRunFrameRole::Namespace)
                .expect("namespace frame");
            let ordinal = match frame.first_bound.as_ref() {
                Some(IndexRunSearchBound::Namespace {
                    mutation_ordinal, ..
                }) => *mutation_ordinal,
                _ => panic!("namespace bound"),
            };
            frame.first_bound = Some(IndexRunSearchBound::Namespace {
                blind_key: IndexBlindKey::from_bytes([0xff; 32]),
                mutation_ordinal: ordinal,
            });
        });
        assert!(
            open_v2_index_run_directory(
                &keyring,
                REPOSITORY_CONTEXT,
                &object,
                2,
                &changed_bound,
                &limits,
            )
            .is_err()
        );
    }

    #[test]
    fn never_visits_a_frame_before_complete_verification() {
        let (keyring, object, limits, _, stored) = sealed();
        let mut corrupt = stored.to_vec();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        let visits = Cell::new(0_usize);
        assert!(
            open_v2_index_run_frames(
                &keyring,
                REPOSITORY_CONTEXT,
                &object,
                2,
                &corrupt,
                &limits,
                |_, _| {
                    visits.set(visits.get() + 1);
                    Ok(())
                },
            )
            .is_err()
        );
        assert_eq!(visits.get(), 0);

        let directory = must(open_v2_index_run_directory(
            &keyring,
            REPOSITORY_CONTEXT,
            &object,
            2,
            &stored,
            &limits,
        ));
        must(open_v2_index_run_frames(
            &keyring,
            REPOSITORY_CONTEXT,
            &object,
            2,
            &stored,
            &limits,
            |_, _| {
                visits.set(visits.get() + 1);
                Ok(())
            },
        ));
        assert_eq!(visits.get(), directory.frames().len());
    }

    #[test]
    fn fixed_header_probe_rejects_hostile_lengths() {
        let (_, _, _, _, stored) = sealed();
        for length in 0..INDEX_RUN_FIXED_HEADER_LEN {
            assert!(probe_v2_index_run_header(&stored[..length]).is_err());
        }
        let mut oversized = stored[..INDEX_RUN_FIXED_HEADER_LEN].to_vec();
        oversized[68..72].copy_from_slice(&u32::MAX.to_be_bytes());
        oversized[72..76].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(probe_v2_index_run_header(&oversized).is_err());
    }

    fn rewrite_directory(
        keyring: &KeyRing,
        object: &BackendObjectId,
        limits: &IndexRunLimits,
        stored: &[u8],
        mutate: impl FnOnce(&mut Vec<V2IndexRunFrameDescriptor>),
    ) -> Vec<u8> {
        let verified = must(open_v2_index_run_directory(
            keyring,
            REPOSITORY_CONTEXT,
            object,
            2,
            stored,
            limits,
        ));
        let header = must(parse_header(stored));
        let mut frames = verified.frames.clone();
        mutate(&mut frames);
        let directory = must(encode_directory(
            verified.sequence,
            verified.mutation_count,
            verified.container_count,
            &frames,
        ));
        assert_eq!(directory.len(), header.directory_plaintext_len as usize);
        let common = must(common_associated_data(REPOSITORY_CONTEXT, object, &header));
        let mut aad = Vec::from(super::INDEX_RUN_DIRECTORY_AAD_DOMAIN);
        aad.extend_from_slice(&common);
        let sealed = must(keyring.seal_metadata_payload(&aad, &directory));
        let mut changed = stored.to_vec();
        let start = header.header_len as usize;
        let end = start + INDEX_RUN_SEAL_OVERHEAD + sealed.ciphertext.len();
        changed[start..start + sealed.nonce.len()].copy_from_slice(&sealed.nonce);
        changed[start + sealed.nonce.len()..start + INDEX_RUN_SEAL_OVERHEAD]
            .copy_from_slice(&sealed.tag);
        changed[start + INDEX_RUN_SEAL_OVERHEAD..end].copy_from_slice(&sealed.ciphertext);
        changed
    }
}
