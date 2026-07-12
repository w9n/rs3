//! Canonical encrypted catalog for embedded v02 index-run sections.
//!
//! Run references name exact accepted foreground commits or exact
//! metadata-only sibling commits published by guarded compaction.

use super::{
    V2_CAPABILITY_COMPACTED_INDEX_RUNS, V2_CAPABILITY_FRAMED_INDEX,
    V2_CAPABILITY_SIGNED_SECTION_DIGESTS, V2_CAPABILITY_STANDALONE_PAYLOADS, V2FormatError,
    V2FormatRef, V2KeyringEnvelopeRef, V2Result,
};
use bytes::Bytes;
use getrandom::fill as fill_random;
use rs3_crypto::KeyRing;
use rs3_index::run::IndexBlindKey;
use rs3_types::{BackendObjectId, BackendVersionId, KeyId, KeyPurpose, LogicalPath, Sequence};
use std::collections::BTreeSet;
use std::fmt;

/// Byte length of a random index-root identity.
pub const V2_INDEX_ROOT_ID_LEN: usize = 32;
/// Maximum complete encrypted index-root section size.
pub const V2_INDEX_ROOT_MAX_BYTES: usize = 8 * 1024 * 1024;
/// Maximum active embedded run references in one root.
pub const V2_INDEX_ROOT_MAX_RUNS: usize = 1_024;
/// Maximum cumulative mutations claimed by one root.
pub const V2_INDEX_ROOT_MAX_TOTAL_MUTATIONS: u64 = 16 * 1024 * 1024;
/// Maximum cumulative encrypted run bytes claimed by one root.
pub const V2_INDEX_ROOT_MAX_TOTAL_RUN_BYTES: u64 = 8 * 1024 * 1024 * 1024;
/// Maximum storage tier accepted in one index-root run reference.
pub const V2_INDEX_ROOT_MAX_LEVEL: u16 = 1;
/// Fixed public-envelope bytes required before the metadata key identifier.
pub const V2_INDEX_ROOT_FIXED_HEADER_BYTES: usize = 72;

const INDEX_ROOT_MAGIC: &[u8; 8] = b"rs3:irt\n";
const INDEX_ROOT_PLAINTEXT_DOMAIN: &[u8] = b"rs3:index-root-plaintext:v02\n";
const INDEX_ROOT_AAD_DOMAIN: &[u8] = b"rs3:index-root-aad:v02\n";
const INDEX_ROOT_FORMAT_GENERATION: u16 = 2;
const INDEX_ROOT_WIRE_VERSION: u16 = 2;
const INDEX_ROOT_NONCE_LEN: usize = 12;
const INDEX_ROOT_TAG_LEN: usize = 16;
const INDEX_ROOT_SEAL_OVERHEAD: usize = INDEX_ROOT_NONCE_LEN + INDEX_ROOT_TAG_LEN;
const INDEX_ROOT_MAX_KEY_ID_LEN: usize = 255;
const INDEX_ROOT_MAX_OBJECT_ID_LEN: usize = 1_024;
const INDEX_ROOT_MAX_VERSION_ID_LEN: usize = 1_024;
const INDEX_ROOT_MAX_PATH_LEN: usize = 1_024;
const INDEX_ROOT_MAX_REPOSITORY_CONTEXT_LEN: usize = 4_096;
const INDEX_ROOT_MAX_RUN_RECORD_LEN: usize = 8 * 1_024;
const INDEX_ROOT_MAX_RUN_BYTES: u64 = 8 * 1024 * 1024;
const INDEX_ROOT_MAX_FRAMES_PER_RUN: u32 = 4_096;
const INDEX_ROOT_MAX_MUTATIONS_PER_RUN: u32 = 65_536;
const INDEX_ROOT_REQUIRED_CAPABILITIES: u64 = V2_CAPABILITY_SIGNED_SECTION_DIGESTS
    | V2_CAPABILITY_FRAMED_INDEX
    | V2_CAPABILITY_COMPACTED_INDEX_RUNS
    | V2_CAPABILITY_STANDALONE_PAYLOADS;

/// Random identity authenticated by the index-root envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct V2IndexRootId([u8; V2_INDEX_ROOT_ID_LEN]);

impl V2IndexRootId {
    /// Returns the exact random identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; V2_INDEX_ROOT_ID_LEN] {
        &self.0
    }

    fn generate() -> V2Result<Self> {
        let mut bytes = [0_u8; V2_INDEX_ROOT_ID_LEN];
        fill_random(&mut bytes).map_err(|_| V2FormatError::RandomnessUnavailable)?;
        Ok(Self(bytes))
    }
}

/// Exact accepted commit section containing one active framed index run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2EmbeddedIndexRunLocation {
    /// Opaque commit object key.
    pub commit_key: BackendObjectId,
    /// Exact provider version, when supplied by the backend.
    pub version_id: Option<BackendVersionId>,
    /// Provider-reported complete commit-object length.
    pub commit_stored_len: u64,
    /// Signed digest over the complete commit section region.
    pub commit_body_digest: [u8; 32],
    /// Absolute offset at which the commit section region starts.
    pub sections_start: u64,
    /// Physical section ordinal of the embedded `INDEX_RUN`.
    pub section_ordinal: u32,
    /// Offset relative to the commit section region.
    pub section_offset: u64,
    /// Exact encrypted run-section length.
    pub section_len: u64,
    /// Signed digest over the encrypted run-section bytes.
    pub section_digest: [u8; 32],
}

/// Authenticated catalog facts for one active embedded index run.
#[derive(Clone, PartialEq, Eq)]
pub struct V2IndexRootRunRef {
    /// Random identity authenticated by the run envelope.
    pub run_id: [u8; 32],
    /// Highest logical mutation sequence represented by the run.
    pub run_sequence: Sequence,
    /// Lowest logical mutation generation in the run.
    pub minimum_generation: Sequence,
    /// Highest logical mutation generation in the run.
    pub maximum_generation: Sequence,
    /// Exact authenticated mutation count.
    pub mutation_count: u32,
    /// Exact authenticated physical frame count.
    pub frame_count: u32,
    /// LSM level. Embedded recent runs are level zero in this generation.
    pub level: u16,
    /// Compaction generation. Embedded recent runs use zero.
    pub compaction_generation: u64,
    /// Inclusive namespace-projection bounds.
    pub namespace_bounds: (IndexBlindKey, IndexBlindKey),
    /// Inclusive listing-projection bounds inside the trusted boundary.
    pub listing_bounds: (LogicalPath, LogicalPath),
    /// Exact keyring-envelope context used to seal the run.
    pub keyring_envelope_ref: V2KeyringEnvelopeRef,
    /// Exact commit section containing the run.
    pub location: V2EmbeddedIndexRunLocation,
}

impl fmt::Debug for V2IndexRootRunRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V2IndexRootRunRef")
            .field("run_id", &self.run_id)
            .field("run_sequence", &self.run_sequence)
            .field("minimum_generation", &self.minimum_generation)
            .field("maximum_generation", &self.maximum_generation)
            .field("mutation_count", &self.mutation_count)
            .field("frame_count", &self.frame_count)
            .field("level", &self.level)
            .field("compaction_generation", &self.compaction_generation)
            .field("projection_bounds", &"<redacted>")
            .field("keyring_envelope_ref", &self.keyring_envelope_ref)
            .field("location", &self.location)
            .finish()
    }
}

/// Recomputed resource claims authenticated by an index root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V2IndexRootClaims {
    run_count: u32,
    total_stored_run_bytes: u64,
    total_frame_count: u64,
    total_mutation_count: u64,
    maximum_level: u16,
}

impl V2IndexRootClaims {
    /// Returns the number of active run references.
    #[must_use]
    pub const fn run_count(&self) -> u32 {
        self.run_count
    }

    /// Returns the cumulative encrypted run-section bytes.
    #[must_use]
    pub const fn total_stored_run_bytes(&self) -> u64 {
        self.total_stored_run_bytes
    }

    /// Returns the cumulative authenticated frame count.
    #[must_use]
    pub const fn total_frame_count(&self) -> u64 {
        self.total_frame_count
    }

    /// Returns the cumulative authenticated mutation count.
    #[must_use]
    pub const fn total_mutation_count(&self) -> u64 {
        self.total_mutation_count
    }

    /// Returns the highest active LSM level.
    #[must_use]
    pub const fn maximum_level(&self) -> u16 {
        self.maximum_level
    }
}

/// Canonical logical index-root catalog.
#[derive(Clone, PartialEq, Eq)]
pub struct V2IndexRoot {
    covered_generation: Sequence,
    expected_live_object_count: u64,
    required_capabilities: u64,
    format_ref: V2FormatRef,
    keyring_envelope_ref: V2KeyringEnvelopeRef,
    claims: V2IndexRootClaims,
    runs: Vec<V2IndexRootRunRef>,
}

impl fmt::Debug for V2IndexRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V2IndexRoot")
            .field("covered_generation", &self.covered_generation)
            .field(
                "expected_live_object_count",
                &self.expected_live_object_count,
            )
            .field("required_capabilities", &self.required_capabilities)
            .field("format_ref", &self.format_ref)
            .field("keyring_envelope_ref", &self.keyring_envelope_ref)
            .field("claims", &self.claims)
            .field("run_count", &self.runs.len())
            .field("run_projection_bounds", &"<redacted>")
            .finish()
    }
}

impl V2IndexRoot {
    /// Builds a canonical catalog and sorts its run references by random run ID.
    pub fn new(
        covered_generation: Sequence,
        expected_live_object_count: u64,
        format_ref: V2FormatRef,
        keyring_envelope_ref: V2KeyringEnvelopeRef,
        mut runs: Vec<V2IndexRootRunRef>,
    ) -> V2Result<Self> {
        runs.sort_by_key(|run| run.run_id);
        let claims = validate_runs(covered_generation, expected_live_object_count, &runs)?;
        validate_format_ref(&format_ref)?;
        validate_keyring_ref(&keyring_envelope_ref)?;
        let root = Self {
            covered_generation,
            expected_live_object_count,
            required_capabilities: INDEX_ROOT_REQUIRED_CAPABILITIES,
            format_ref,
            keyring_envelope_ref,
            claims,
            runs,
        };
        validate_root(&root)?;
        Ok(root)
    }

    /// Returns the repository sequence covered by this catalog.
    #[must_use]
    pub const fn covered_generation(&self) -> Sequence {
        self.covered_generation
    }

    /// Returns the expected number of effective live namespace objects.
    #[must_use]
    pub const fn expected_live_object_count(&self) -> u64 {
        self.expected_live_object_count
    }

    /// Returns the reader capabilities required by this root.
    #[must_use]
    pub const fn required_capabilities(&self) -> u64 {
        self.required_capabilities
    }

    /// Returns the exact active format-root reference.
    #[must_use]
    pub const fn format_ref(&self) -> &V2FormatRef {
        &self.format_ref
    }

    /// Returns the active keyring-envelope reference.
    #[must_use]
    pub const fn keyring_envelope_ref(&self) -> &V2KeyringEnvelopeRef {
        &self.keyring_envelope_ref
    }

    /// Returns the recomputed bounded resource claims.
    #[must_use]
    pub const fn claims(&self) -> V2IndexRootClaims {
        self.claims
    }

    /// Returns active run references in canonical run-ID order.
    #[must_use]
    pub fn runs(&self) -> &[V2IndexRootRunRef] {
        &self.runs
    }
}

/// Complete encrypted bytes and random identity of an index root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2SealedIndexRoot {
    root_id: V2IndexRootId,
    bytes: Bytes,
}

impl V2SealedIndexRoot {
    /// Returns the random identity authenticated by this root envelope.
    #[must_use]
    pub const fn root_id(&self) -> V2IndexRootId {
        self.root_id
    }

    /// Returns the exact encrypted section bytes.
    #[must_use]
    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// Consumes the envelope and returns its exact stored bytes.
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }
}

struct RootHeader {
    header_len: u32,
    stored_len: u64,
    section_ordinal: u32,
    root_id: V2IndexRootId,
    key_id: KeyId,
    ciphertext_len: u32,
}

/// Canonically encodes and encrypts one complete logical index root.
pub fn seal_v2_index_root(
    keyring: &KeyRing,
    repository_context: &[u8],
    containing_object: &BackendObjectId,
    section_ordinal: u32,
    root: &V2IndexRoot,
) -> V2Result<V2SealedIndexRoot> {
    validate_context(repository_context, containing_object)?;
    validate_root(root)?;
    let plaintext = encode_root(root)?;
    if plaintext.len() > V2_INDEX_ROOT_MAX_BYTES {
        return Err(V2FormatError::IndexRootLimitExceeded);
    }
    let key_id = keyring.primary_key_id(KeyPurpose::Metadata)?;
    let key_id_len = key_id.as_str().len();
    if key_id_len == 0 || key_id_len > INDEX_ROOT_MAX_KEY_ID_LEN {
        return Err(V2FormatError::IndexRootLimitExceeded);
    }
    let header_len = V2_INDEX_ROOT_FIXED_HEADER_BYTES
        .checked_add(key_id_len)
        .ok_or(V2FormatError::IndexRootLimitExceeded)?;
    let stored_len = header_len
        .checked_add(INDEX_ROOT_SEAL_OVERHEAD)
        .and_then(|value| value.checked_add(plaintext.len()))
        .ok_or(V2FormatError::IndexRootLimitExceeded)?;
    if stored_len > V2_INDEX_ROOT_MAX_BYTES {
        return Err(V2FormatError::IndexRootLimitExceeded);
    }
    let root_id = V2IndexRootId::generate()?;
    let header = RootHeader {
        header_len: to_u32(header_len)?,
        stored_len: to_u64(stored_len)?,
        section_ordinal,
        root_id,
        key_id: key_id.clone(),
        ciphertext_len: to_u32(plaintext.len())?,
    };
    let aad = associated_data(repository_context, containing_object, &header)?;
    let sealed = keyring.seal_metadata_payload(&aad, &plaintext)?;
    if sealed.key_id != key_id
        || sealed.nonce.len() != INDEX_ROOT_NONCE_LEN
        || sealed.tag.len() != INDEX_ROOT_TAG_LEN
        || sealed.ciphertext.len() != plaintext.len()
    {
        return Err(V2FormatError::InvalidIndexRoot);
    }
    let mut stored = Vec::with_capacity(stored_len);
    encode_header(&mut stored, &header)?;
    stored.extend_from_slice(&sealed.nonce);
    stored.extend_from_slice(&sealed.tag);
    stored.extend_from_slice(&sealed.ciphertext);
    if stored.len() != stored_len {
        return Err(V2FormatError::InvalidIndexRoot);
    }
    Ok(V2SealedIndexRoot {
        root_id,
        bytes: Bytes::from(stored),
    })
}

/// Authenticates, decrypts, and canonically decodes one complete index root.
pub fn open_v2_index_root(
    keyring: &KeyRing,
    repository_context: &[u8],
    containing_object: &BackendObjectId,
    expected_section_ordinal: u32,
    stored: &[u8],
) -> V2Result<V2IndexRoot> {
    validate_context(repository_context, containing_object)?;
    let header = parse_header(stored)?;
    if header.section_ordinal != expected_section_ordinal
        || header.stored_len != to_u64(stored.len())?
    {
        return Err(V2FormatError::InvalidIndexRoot);
    }
    let ciphertext_start =
        usize::try_from(header.header_len).map_err(|_| V2FormatError::InvalidIndexRoot)?;
    let ciphertext_end = ciphertext_start
        .checked_add(INDEX_ROOT_SEAL_OVERHEAD)
        .and_then(|value| value.checked_add(header.ciphertext_len as usize))
        .ok_or(V2FormatError::InvalidIndexRoot)?;
    if ciphertext_end != stored.len() {
        return Err(V2FormatError::InvalidIndexRoot);
    }
    let sealed = stored
        .get(ciphertext_start..ciphertext_end)
        .ok_or(V2FormatError::InvalidIndexRoot)?;
    let nonce = sealed
        .get(..INDEX_ROOT_NONCE_LEN)
        .ok_or(V2FormatError::InvalidIndexRoot)?;
    let tag = sealed
        .get(INDEX_ROOT_NONCE_LEN..INDEX_ROOT_SEAL_OVERHEAD)
        .ok_or(V2FormatError::InvalidIndexRoot)?;
    let ciphertext = sealed
        .get(INDEX_ROOT_SEAL_OVERHEAD..)
        .ok_or(V2FormatError::InvalidIndexRoot)?;
    let aad = associated_data(repository_context, containing_object, &header)?;
    let plaintext = keyring.open_metadata_payload(&header.key_id, &aad, nonce, ciphertext, tag)?;
    let root = decode_root(&plaintext)?;
    if encode_root(&root)? != plaintext {
        return Err(V2FormatError::InvalidIndexRoot);
    }
    validate_root(&root)?;
    Ok(root)
}

fn validate_root(root: &V2IndexRoot) -> V2Result<()> {
    if root.required_capabilities != INDEX_ROOT_REQUIRED_CAPABILITIES {
        return Err(V2FormatError::InvalidIndexRoot);
    }
    validate_format_ref(&root.format_ref)?;
    validate_keyring_ref(&root.keyring_envelope_ref)?;
    let claims = validate_runs(
        root.covered_generation,
        root.expected_live_object_count,
        &root.runs,
    )?;
    if claims != root.claims {
        return Err(V2FormatError::InvalidIndexRoot);
    }
    Ok(())
}

fn validate_runs(
    covered_generation: Sequence,
    expected_live_object_count: u64,
    runs: &[V2IndexRootRunRef],
) -> V2Result<V2IndexRootClaims> {
    if runs.len() > V2_INDEX_ROOT_MAX_RUNS {
        return Err(V2FormatError::IndexRootLimitExceeded);
    }
    let mut previous_id = None;
    let mut locations = BTreeSet::new();
    let mut total_stored_run_bytes = 0_u64;
    let mut total_frame_count = 0_u64;
    let mut total_mutation_count = 0_u64;
    let mut maximum_level = 0_u16;
    let mut maximum_run_generation = None;
    for run in runs {
        if previous_id.is_some_and(|previous| previous >= run.run_id)
            || run.run_id == [0_u8; 32]
            || run.mutation_count == 0
            || run.mutation_count > INDEX_ROOT_MAX_MUTATIONS_PER_RUN
            || run.frame_count == 0
            || run.frame_count > INDEX_ROOT_MAX_FRAMES_PER_RUN
            || run.minimum_generation == Sequence::ZERO
            || run.minimum_generation > run.maximum_generation
            || run.maximum_generation != run.run_sequence
            || run.run_sequence > covered_generation
            || run.level > V2_INDEX_ROOT_MAX_LEVEL
            || (run.level == 0) != (run.compaction_generation == 0)
            || run.namespace_bounds.0 > run.namespace_bounds.1
            || run.listing_bounds.0.as_str().as_bytes() > run.listing_bounds.1.as_str().as_bytes()
        {
            return Err(V2FormatError::InvalidIndexRoot);
        }
        previous_id = Some(run.run_id);
        validate_keyring_ref(&run.keyring_envelope_ref)?;
        validate_run_location(&run.location)?;
        if !locations.insert((
            run.location.commit_key.clone(),
            run.location.version_id.clone(),
            run.location.section_ordinal,
        )) {
            return Err(V2FormatError::InvalidIndexRoot);
        }
        total_stored_run_bytes = total_stored_run_bytes
            .checked_add(run.location.section_len)
            .ok_or(V2FormatError::IndexRootLimitExceeded)?;
        total_frame_count = total_frame_count
            .checked_add(u64::from(run.frame_count))
            .ok_or(V2FormatError::IndexRootLimitExceeded)?;
        total_mutation_count = total_mutation_count
            .checked_add(u64::from(run.mutation_count))
            .ok_or(V2FormatError::IndexRootLimitExceeded)?;
        maximum_level = maximum_level.max(run.level);
        maximum_run_generation = Some(
            maximum_run_generation.map_or(run.maximum_generation, |current: Sequence| {
                current.max(run.maximum_generation)
            }),
        );
    }
    let mut generation_order = runs.iter().collect::<Vec<_>>();
    generation_order.sort_by_key(|run| (run.minimum_generation, run.run_sequence, run.run_id));
    if generation_order
        .windows(2)
        .any(|pair| pair[0].maximum_generation >= pair[1].minimum_generation)
    {
        return Err(V2FormatError::InvalidIndexRoot);
    }
    if total_stored_run_bytes > V2_INDEX_ROOT_MAX_TOTAL_RUN_BYTES
        || total_mutation_count > V2_INDEX_ROOT_MAX_TOTAL_MUTATIONS
        || expected_live_object_count > total_mutation_count
    {
        return Err(V2FormatError::IndexRootLimitExceeded);
    }
    if maximum_run_generation.is_none_or(|generation| generation != covered_generation)
        && !(runs.is_empty()
            && covered_generation == Sequence::ZERO
            && expected_live_object_count == 0)
    {
        return Err(V2FormatError::InvalidIndexRoot);
    }
    Ok(V2IndexRootClaims {
        run_count: to_u32(runs.len())?,
        total_stored_run_bytes,
        total_frame_count,
        total_mutation_count,
        maximum_level,
    })
}

fn validate_run_location(location: &V2EmbeddedIndexRunLocation) -> V2Result<()> {
    validate_len(
        location.commit_key.as_str().len(),
        INDEX_ROOT_MAX_OBJECT_ID_LEN,
    )?;
    if let Some(version_id) = location.version_id.as_ref() {
        validate_len(version_id.as_str().len(), INDEX_ROOT_MAX_VERSION_ID_LEN)?;
    }
    let section_end = location
        .sections_start
        .checked_add(location.section_offset)
        .and_then(|value| value.checked_add(location.section_len))
        .ok_or(V2FormatError::InvalidIndexRoot)?;
    if location.commit_stored_len == 0
        || location.section_len == 0
        || location.section_len > INDEX_ROOT_MAX_RUN_BYTES
        || section_end > location.commit_stored_len
        || location.section_ordinal >= 65
    {
        return Err(V2FormatError::InvalidIndexRoot);
    }
    Ok(())
}

fn validate_format_ref(reference: &V2FormatRef) -> V2Result<()> {
    validate_len(
        reference.object_id.as_str().len(),
        INDEX_ROOT_MAX_OBJECT_ID_LEN,
    )?;
    if let Some(version_id) = reference.version_id.as_ref() {
        validate_len(version_id.as_str().len(), INDEX_ROOT_MAX_VERSION_ID_LEN)?;
    }
    let digest = hex::decode(&reference.digest).map_err(|_| V2FormatError::InvalidIndexRoot)?;
    if digest.len() != 32 || hex::encode(&digest) != reference.digest {
        return Err(V2FormatError::InvalidIndexRoot);
    }
    Ok(())
}

fn validate_keyring_ref(reference: &V2KeyringEnvelopeRef) -> V2Result<()> {
    validate_len(
        reference.object_id.as_str().len(),
        INDEX_ROOT_MAX_OBJECT_ID_LEN,
    )
}

fn validate_context(
    repository_context: &[u8],
    containing_object: &BackendObjectId,
) -> V2Result<()> {
    if repository_context.is_empty()
        || repository_context.len() > INDEX_ROOT_MAX_REPOSITORY_CONTEXT_LEN
    {
        return Err(V2FormatError::IndexRootLimitExceeded);
    }
    validate_len(
        containing_object.as_str().len(),
        INDEX_ROOT_MAX_OBJECT_ID_LEN,
    )
}

fn validate_len(actual: usize, maximum: usize) -> V2Result<()> {
    if actual == 0 || actual > maximum {
        Err(V2FormatError::IndexRootLimitExceeded)
    } else {
        Ok(())
    }
}

fn encode_root(root: &V2IndexRoot) -> V2Result<Vec<u8>> {
    let mut output = Vec::new();
    output.extend_from_slice(INDEX_ROOT_PLAINTEXT_DOMAIN);
    push_u16(&mut output, INDEX_ROOT_WIRE_VERSION);
    push_u64(&mut output, root.covered_generation.get());
    push_u64(&mut output, root.expected_live_object_count);
    push_u64(&mut output, root.required_capabilities);
    push_u64(&mut output, root.format_ref.generation);
    let format_digest =
        hex::decode(&root.format_ref.digest).map_err(|_| V2FormatError::InvalidIndexRoot)?;
    output.extend_from_slice(&format_digest);
    push_string(&mut output, root.format_ref.object_id.as_str())?;
    push_optional_string(
        &mut output,
        root.format_ref
            .version_id
            .as_ref()
            .map(BackendVersionId::as_str),
    )?;
    push_string(&mut output, root.keyring_envelope_ref.object_id.as_str())?;
    output.extend_from_slice(&root.keyring_envelope_ref.digest);
    push_u32(&mut output, root.claims.run_count);
    push_u64(&mut output, root.claims.total_stored_run_bytes);
    push_u64(&mut output, root.claims.total_frame_count);
    push_u64(&mut output, root.claims.total_mutation_count);
    push_u16(&mut output, root.claims.maximum_level);
    for run in &root.runs {
        let record = encode_run_ref(run)?;
        if record.len() > INDEX_ROOT_MAX_RUN_RECORD_LEN {
            return Err(V2FormatError::IndexRootLimitExceeded);
        }
        push_u32(&mut output, to_u32(record.len())?);
        output.extend_from_slice(&record);
    }
    if output.len() > V2_INDEX_ROOT_MAX_BYTES {
        return Err(V2FormatError::IndexRootLimitExceeded);
    }
    Ok(output)
}

fn encode_run_ref(run: &V2IndexRootRunRef) -> V2Result<Vec<u8>> {
    let mut output = Vec::new();
    output.extend_from_slice(&run.run_id);
    push_u64(&mut output, run.run_sequence.get());
    push_u64(&mut output, run.minimum_generation.get());
    push_u64(&mut output, run.maximum_generation.get());
    push_u32(&mut output, run.mutation_count);
    push_u32(&mut output, run.frame_count);
    push_u16(&mut output, run.level);
    push_u64(&mut output, run.compaction_generation);
    output.extend_from_slice(run.namespace_bounds.0.as_bytes());
    output.extend_from_slice(run.namespace_bounds.1.as_bytes());
    push_string(&mut output, run.listing_bounds.0.as_str())?;
    push_string(&mut output, run.listing_bounds.1.as_str())?;
    push_string(&mut output, run.keyring_envelope_ref.object_id.as_str())?;
    output.extend_from_slice(&run.keyring_envelope_ref.digest);
    push_string(&mut output, run.location.commit_key.as_str())?;
    push_optional_string(
        &mut output,
        run.location
            .version_id
            .as_ref()
            .map(BackendVersionId::as_str),
    )?;
    push_u64(&mut output, run.location.commit_stored_len);
    output.extend_from_slice(&run.location.commit_body_digest);
    push_u64(&mut output, run.location.sections_start);
    push_u32(&mut output, run.location.section_ordinal);
    push_u64(&mut output, run.location.section_offset);
    push_u64(&mut output, run.location.section_len);
    output.extend_from_slice(&run.location.section_digest);
    Ok(output)
}

fn decode_root(input: &[u8]) -> V2Result<V2IndexRoot> {
    if input.len() > V2_INDEX_ROOT_MAX_BYTES {
        return Err(V2FormatError::IndexRootLimitExceeded);
    }
    let mut reader = Reader::new(input);
    if reader.take(INDEX_ROOT_PLAINTEXT_DOMAIN.len())? != INDEX_ROOT_PLAINTEXT_DOMAIN {
        return Err(V2FormatError::InvalidIndexRoot);
    }
    if reader.u16()? != INDEX_ROOT_WIRE_VERSION {
        return Err(V2FormatError::InvalidIndexRoot);
    }
    let covered_generation = Sequence::new(reader.u64()?);
    let expected_live_object_count = reader.u64()?;
    let required_capabilities = reader.u64()?;
    let format_generation = reader.u64()?;
    let format_digest = hex::encode(reader.array_32()?);
    let format_object_id = BackendObjectId::new(reader.string(INDEX_ROOT_MAX_OBJECT_ID_LEN)?)?;
    let format_version_id = reader
        .optional_string(INDEX_ROOT_MAX_VERSION_ID_LEN)?
        .map(BackendVersionId::new)
        .transpose()?;
    let keyring_object_id = BackendObjectId::new(reader.string(INDEX_ROOT_MAX_OBJECT_ID_LEN)?)?;
    let keyring_digest = reader.array_32()?;
    let claims = V2IndexRootClaims {
        run_count: reader.u32()?,
        total_stored_run_bytes: reader.u64()?,
        total_frame_count: reader.u64()?,
        total_mutation_count: reader.u64()?,
        maximum_level: reader.u16()?,
    };
    let run_count =
        usize::try_from(claims.run_count).map_err(|_| V2FormatError::IndexRootLimitExceeded)?;
    if run_count > V2_INDEX_ROOT_MAX_RUNS {
        return Err(V2FormatError::IndexRootLimitExceeded);
    }
    let mut runs = Vec::new();
    runs.try_reserve_exact(run_count)
        .map_err(|_| V2FormatError::IndexRootLimitExceeded)?;
    for _ in 0..run_count {
        let record_len =
            usize::try_from(reader.u32()?).map_err(|_| V2FormatError::IndexRootLimitExceeded)?;
        if record_len == 0 || record_len > INDEX_ROOT_MAX_RUN_RECORD_LEN {
            return Err(V2FormatError::IndexRootLimitExceeded);
        }
        runs.push(decode_run_ref(reader.take(record_len)?)?);
    }
    reader.finish()?;
    let root = V2IndexRoot {
        covered_generation,
        expected_live_object_count,
        required_capabilities,
        format_ref: V2FormatRef {
            generation: format_generation,
            digest: format_digest,
            object_id: format_object_id,
            version_id: format_version_id,
        },
        keyring_envelope_ref: V2KeyringEnvelopeRef {
            object_id: keyring_object_id,
            digest: keyring_digest,
        },
        claims,
        runs,
    };
    validate_root(&root)?;
    Ok(root)
}

fn decode_run_ref(input: &[u8]) -> V2Result<V2IndexRootRunRef> {
    let mut reader = Reader::new(input);
    let run_id = reader.array_32()?;
    let run_sequence = Sequence::new(reader.u64()?);
    let minimum_generation = Sequence::new(reader.u64()?);
    let maximum_generation = Sequence::new(reader.u64()?);
    let mutation_count = reader.u32()?;
    let frame_count = reader.u32()?;
    let level = reader.u16()?;
    let compaction_generation = reader.u64()?;
    let namespace_bounds = (
        IndexBlindKey::from_bytes(reader.array_32()?),
        IndexBlindKey::from_bytes(reader.array_32()?),
    );
    let listing_bounds = (
        LogicalPath::new(reader.string(INDEX_ROOT_MAX_PATH_LEN)?)?,
        LogicalPath::new(reader.string(INDEX_ROOT_MAX_PATH_LEN)?)?,
    );
    let keyring_envelope_ref = V2KeyringEnvelopeRef {
        object_id: BackendObjectId::new(reader.string(INDEX_ROOT_MAX_OBJECT_ID_LEN)?)?,
        digest: reader.array_32()?,
    };
    let location = V2EmbeddedIndexRunLocation {
        commit_key: BackendObjectId::new(reader.string(INDEX_ROOT_MAX_OBJECT_ID_LEN)?)?,
        version_id: reader
            .optional_string(INDEX_ROOT_MAX_VERSION_ID_LEN)?
            .map(BackendVersionId::new)
            .transpose()?,
        commit_stored_len: reader.u64()?,
        commit_body_digest: reader.array_32()?,
        sections_start: reader.u64()?,
        section_ordinal: reader.u32()?,
        section_offset: reader.u64()?,
        section_len: reader.u64()?,
        section_digest: reader.array_32()?,
    };
    reader.finish()?;
    Ok(V2IndexRootRunRef {
        run_id,
        run_sequence,
        minimum_generation,
        maximum_generation,
        mutation_count,
        frame_count,
        level,
        compaction_generation,
        namespace_bounds,
        listing_bounds,
        keyring_envelope_ref,
        location,
    })
}

fn encode_header(output: &mut Vec<u8>, header: &RootHeader) -> V2Result<()> {
    output.extend_from_slice(INDEX_ROOT_MAGIC);
    push_u16(output, INDEX_ROOT_FORMAT_GENERATION);
    push_u16(output, INDEX_ROOT_WIRE_VERSION);
    push_u32(output, header.header_len);
    push_u64(output, header.stored_len);
    push_u32(output, header.section_ordinal);
    push_u32(output, 0);
    output.extend_from_slice(header.root_id.as_bytes());
    push_u16(output, to_u16(header.key_id.as_str().len())?);
    output.push(INDEX_ROOT_NONCE_LEN as u8);
    output.push(INDEX_ROOT_TAG_LEN as u8);
    push_u32(output, header.ciphertext_len);
    if output.len() != V2_INDEX_ROOT_FIXED_HEADER_BYTES {
        return Err(V2FormatError::InvalidIndexRoot);
    }
    output.extend_from_slice(header.key_id.as_str().as_bytes());
    Ok(())
}

fn parse_header(input: &[u8]) -> V2Result<RootHeader> {
    if input.len() < V2_INDEX_ROOT_FIXED_HEADER_BYTES || input.len() > V2_INDEX_ROOT_MAX_BYTES {
        return Err(V2FormatError::InvalidIndexRoot);
    }
    if input.get(..8) != Some(INDEX_ROOT_MAGIC.as_slice()) {
        return Err(V2FormatError::InvalidIndexRoot);
    }
    if read_u16(input, 8)? != INDEX_ROOT_FORMAT_GENERATION
        || read_u16(input, 10)? != INDEX_ROOT_WIRE_VERSION
        || read_u32(input, 28)? != 0
        || input.get(66).copied() != Some(INDEX_ROOT_NONCE_LEN as u8)
        || input.get(67).copied() != Some(INDEX_ROOT_TAG_LEN as u8)
    {
        return Err(V2FormatError::InvalidIndexRoot);
    }
    let header_len = read_u32(input, 12)?;
    let stored_len = read_u64(input, 16)?;
    let section_ordinal = read_u32(input, 24)?;
    let root_id = V2IndexRootId(
        input
            .get(32..64)
            .ok_or(V2FormatError::InvalidIndexRoot)?
            .try_into()
            .map_err(|_| V2FormatError::InvalidIndexRoot)?,
    );
    let key_id_len = usize::from(read_u16(input, 64)?);
    let ciphertext_len = read_u32(input, 68)?;
    let expected_header_len = V2_INDEX_ROOT_FIXED_HEADER_BYTES
        .checked_add(key_id_len)
        .ok_or(V2FormatError::InvalidIndexRoot)?;
    let expected_stored_len = expected_header_len
        .checked_add(INDEX_ROOT_SEAL_OVERHEAD)
        .and_then(|value| value.checked_add(ciphertext_len as usize))
        .ok_or(V2FormatError::InvalidIndexRoot)?;
    if key_id_len == 0
        || key_id_len > INDEX_ROOT_MAX_KEY_ID_LEN
        || usize::try_from(header_len).ok() != Some(expected_header_len)
        || usize::try_from(stored_len).ok() != Some(expected_stored_len)
        || expected_stored_len != input.len()
    {
        return Err(V2FormatError::InvalidIndexRoot);
    }
    let key_bytes = input
        .get(V2_INDEX_ROOT_FIXED_HEADER_BYTES..expected_header_len)
        .ok_or(V2FormatError::InvalidIndexRoot)?;
    let key_id =
        KeyId::new(std::str::from_utf8(key_bytes).map_err(|_| V2FormatError::InvalidIndexRoot)?)?;
    Ok(RootHeader {
        header_len,
        stored_len,
        section_ordinal,
        root_id,
        key_id,
        ciphertext_len,
    })
}

fn associated_data(
    repository_context: &[u8],
    containing_object: &BackendObjectId,
    header: &RootHeader,
) -> V2Result<Vec<u8>> {
    validate_context(repository_context, containing_object)?;
    let mut aad = Vec::new();
    aad.extend_from_slice(INDEX_ROOT_AAD_DOMAIN);
    push_u32(&mut aad, to_u32(repository_context.len())?);
    aad.extend_from_slice(repository_context);
    push_string(&mut aad, containing_object.as_str())?;
    push_u16(&mut aad, INDEX_ROOT_FORMAT_GENERATION);
    push_u16(&mut aad, INDEX_ROOT_WIRE_VERSION);
    push_u32(&mut aad, header.header_len);
    push_u64(&mut aad, header.stored_len);
    push_u32(&mut aad, header.section_ordinal);
    aad.extend_from_slice(header.root_id.as_bytes());
    push_string(&mut aad, header.key_id.as_str())?;
    push_u32(&mut aad, header.ciphertext_len);
    Ok(aad)
}

fn push_optional_string(output: &mut Vec<u8>, value: Option<&str>) -> V2Result<()> {
    match value {
        None => output.push(0),
        Some(value) => {
            output.push(1);
            push_string(output, value)?;
        }
    }
    Ok(())
}

fn push_string(output: &mut Vec<u8>, value: &str) -> V2Result<()> {
    push_u16(output, to_u16(value.len())?);
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn read_u16(input: &[u8], offset: usize) -> V2Result<u16> {
    Ok(u16::from_be_bytes(
        input
            .get(offset..offset + 2)
            .ok_or(V2FormatError::InvalidIndexRoot)?
            .try_into()
            .map_err(|_| V2FormatError::InvalidIndexRoot)?,
    ))
}

fn read_u32(input: &[u8], offset: usize) -> V2Result<u32> {
    Ok(u32::from_be_bytes(
        input
            .get(offset..offset + 4)
            .ok_or(V2FormatError::InvalidIndexRoot)?
            .try_into()
            .map_err(|_| V2FormatError::InvalidIndexRoot)?,
    ))
}

fn read_u64(input: &[u8], offset: usize) -> V2Result<u64> {
    Ok(u64::from_be_bytes(
        input
            .get(offset..offset + 8)
            .ok_or(V2FormatError::InvalidIndexRoot)?
            .try_into()
            .map_err(|_| V2FormatError::InvalidIndexRoot)?,
    ))
}

fn to_u16(value: usize) -> V2Result<u16> {
    u16::try_from(value).map_err(|_| V2FormatError::IndexRootLimitExceeded)
}

fn to_u32<T>(value: T) -> V2Result<u32>
where
    T: TryInto<u32>,
{
    value
        .try_into()
        .map_err(|_| V2FormatError::IndexRootLimitExceeded)
}

fn to_u64<T>(value: T) -> V2Result<u64>
where
    T: TryInto<u64>,
{
    value
        .try_into()
        .map_err(|_| V2FormatError::IndexRootLimitExceeded)
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn take(&mut self, len: usize) -> V2Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(V2FormatError::InvalidIndexRoot)?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(V2FormatError::InvalidIndexRoot)?;
        self.offset = end;
        Ok(bytes)
    }

    fn u16(&mut self) -> V2Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| V2FormatError::InvalidIndexRoot)?,
        ))
    }

    fn u32(&mut self) -> V2Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| V2FormatError::InvalidIndexRoot)?,
        ))
    }

    fn u64(&mut self) -> V2Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| V2FormatError::InvalidIndexRoot)?,
        ))
    }

    fn array_32(&mut self) -> V2Result<[u8; 32]> {
        self.take(32)?
            .try_into()
            .map_err(|_| V2FormatError::InvalidIndexRoot)
    }

    fn string(&mut self, maximum: usize) -> V2Result<String> {
        let len = usize::from(self.u16()?);
        if len == 0 || len > maximum {
            return Err(V2FormatError::IndexRootLimitExceeded);
        }
        let value =
            std::str::from_utf8(self.take(len)?).map_err(|_| V2FormatError::InvalidIndexRoot)?;
        Ok(value.to_owned())
    }

    fn optional_string(&mut self, maximum: usize) -> V2Result<Option<String>> {
        match self.take(1)?[0] {
            0 => Ok(None),
            1 => self.string(maximum).map(Some),
            _ => Err(V2FormatError::InvalidIndexRoot),
        }
    }

    fn finish(self) -> V2Result<()> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(V2FormatError::InvalidIndexRoot)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        V2_INDEX_ROOT_FIXED_HEADER_BYTES, V2_INDEX_ROOT_MAX_LEVEL, V2_INDEX_ROOT_MAX_RUNS,
        V2EmbeddedIndexRunLocation, V2IndexRoot, V2IndexRootRunRef, open_v2_index_root,
        seal_v2_index_root,
    };
    use crate::v2::{V2FormatError, V2FormatRef, V2KeyringEnvelopeRef};
    use rs3_crypto::{KeyMaterial, KeyRing, SecretBytes};
    use rs3_index::run::IndexBlindKey;
    use rs3_types::{
        BackendObjectId, BackendVersionId, KeyDescriptor, KeyId, KeyPurpose, KeyStatus,
        LogicalPath, Sequence,
    };
    use sha2::{Digest, Sha256};

    const REPOSITORY_CONTEXT: &[u8] = b"repository-context-v02";

    fn must<T>(result: crate::v2::V2Result<T>) -> T {
        result.unwrap_or_else(|error| panic!("{error}"))
    }

    fn object_id(value: &str) -> BackendObjectId {
        BackendObjectId::new(value).unwrap_or_else(|error| panic!("{error}"))
    }

    fn version_id(value: &str) -> BackendVersionId {
        BackendVersionId::new(value).unwrap_or_else(|error| panic!("{error}"))
    }

    fn key_id(value: &str) -> KeyId {
        KeyId::new(value).unwrap_or_else(|error| panic!("{error}"))
    }

    fn logical_path(value: &str) -> LogicalPath {
        LogicalPath::new(value).unwrap_or_else(|error| panic!("{error}"))
    }

    fn keyring() -> KeyRing {
        let material = |id: &str, purpose: KeyPurpose, algorithm: &str, byte: u8| {
            KeyMaterial::new(
                KeyDescriptor {
                    id: key_id(id),
                    purpose,
                    algorithm: algorithm.to_owned(),
                    status: KeyStatus::Primary,
                    created_at_ms: 0,
                    not_before_ms: None,
                    not_after_ms: None,
                    public_key: None,
                    external_kms_uri: None,
                },
                SecretBytes::new(vec![byte; SecretBytes::MIN_LEN])
                    .unwrap_or_else(|error| panic!("{error}")),
            )
        };
        KeyRing::new(vec![
            material("namespace", KeyPurpose::Namespace, "hmac-sha256", 6),
            material("metadata", KeyPurpose::Metadata, "aes-256-gcm-siv", 7),
        ])
        .unwrap_or_else(|error| panic!("{error}"))
    }

    fn keyring_ref() -> V2KeyringEnvelopeRef {
        V2KeyringEnvelopeRef {
            object_id: object_id("keyrings/00000000000000000007-root"),
            digest: [0x77; 32],
        }
    }

    fn format_ref() -> V2FormatRef {
        V2FormatRef {
            generation: 7,
            digest: hex::encode([0x66; 32]),
            object_id: object_id("format/00000000000000000007-root"),
            version_id: Some(version_id("format-version-7")),
        }
    }

    fn run_ref(id: u8, sequence: u64, path: &str) -> V2IndexRootRunRef {
        V2IndexRootRunRef {
            run_id: [id; 32],
            run_sequence: Sequence::new(sequence),
            minimum_generation: Sequence::new(sequence),
            maximum_generation: Sequence::new(sequence),
            mutation_count: 1,
            frame_count: 3,
            level: 0,
            compaction_generation: 0,
            namespace_bounds: (
                IndexBlindKey::from_bytes([id; 32]),
                IndexBlindKey::from_bytes([id; 32]),
            ),
            listing_bounds: (logical_path(path), logical_path(path)),
            keyring_envelope_ref: keyring_ref(),
            location: V2EmbeddedIndexRunLocation {
                commit_key: object_id(&format!("commits/v02/{sequence:020}/opaque-{id}")),
                version_id: Some(version_id(&format!("commit-version-{id}"))),
                commit_stored_len: 16_384,
                commit_body_digest: [id.wrapping_add(1); 32],
                sections_start: 1_024,
                section_ordinal: 1,
                section_offset: 4_096,
                section_len: 4_096,
                section_digest: [id.wrapping_add(2); 32],
            },
        }
    }

    fn fixture() -> V2IndexRoot {
        must(V2IndexRoot::new(
            Sequence::new(9),
            2,
            format_ref(),
            keyring_ref(),
            vec![run_ref(2, 9, "private/b"), run_ref(1, 8, "private/a")],
        ))
    }

    fn compacted_fixture() -> V2IndexRoot {
        let mut older = run_ref(1, 8, "private/a");
        older.level = 1;
        older.compaction_generation = 10;
        let mut newer = run_ref(2, 9, "private/b");
        newer.level = V2_INDEX_ROOT_MAX_LEVEL;
        newer.compaction_generation = 11;
        must(V2IndexRoot::new(
            Sequence::new(9),
            2,
            format_ref(),
            keyring_ref(),
            vec![newer, older],
        ))
    }

    #[test]
    fn encrypted_root_round_trips_and_sorts_runs() {
        let keyring = keyring();
        let object = object_id("commits/v02/00000000000000000010/root");
        let root = fixture();
        assert_eq!(root.runs()[0].run_id, [1; 32]);
        let sealed = must(seal_v2_index_root(
            &keyring,
            REPOSITORY_CONTEXT,
            &object,
            0,
            &root,
        ));
        let opened = must(open_v2_index_root(
            &keyring,
            REPOSITORY_CONTEXT,
            &object,
            0,
            sealed.bytes(),
        ));
        assert_eq!(opened, root);
        assert_eq!(opened.claims().run_count(), 2);
        assert_eq!(opened.claims().total_mutation_count(), 2);
        assert!(
            !sealed
                .bytes()
                .windows(9)
                .any(|window| window == b"private/a")
        );
    }

    #[test]
    fn canonical_logical_encoding_is_stable() {
        let encoded = must(super::encode_root(&fixture()));
        let digest: [u8; 32] = Sha256::digest(encoded).into();
        assert_eq!(
            hex::encode(digest),
            "35f15d7fc27f058c963bb8c2df350e9875bf94fe1705b785f06324ed3de168f5"
        );
    }

    #[test]
    fn compacted_levels_round_trip_canonically() {
        let keyring = keyring();
        let object = object_id("commits/v02/00000000000000000012/compacted-root");
        let root = compacted_fixture();
        assert_eq!(root.claims().maximum_level(), V2_INDEX_ROOT_MAX_LEVEL);
        let sealed = must(seal_v2_index_root(
            &keyring,
            REPOSITORY_CONTEXT,
            &object,
            0,
            &root,
        ));
        assert_eq!(
            must(open_v2_index_root(
                &keyring,
                REPOSITORY_CONTEXT,
                &object,
                0,
                sealed.bytes(),
            )),
            root
        );

        let encoded = must(super::encode_root(&root));
        let digest: [u8; 32] = Sha256::digest(encoded).into();
        assert_eq!(
            hex::encode(digest),
            "6a6f0ff7f0436fdee46eb25454dddbe3d85fb3a9ed3702464885a17c59697b8e"
        );
    }

    #[test]
    fn empty_genesis_root_round_trips() {
        let keyring = keyring();
        let object = object_id("commits/v02/00000000000000000001/genesis");
        let root = must(V2IndexRoot::new(
            Sequence::ZERO,
            0,
            format_ref(),
            keyring_ref(),
            Vec::new(),
        ));
        let sealed = must(seal_v2_index_root(
            &keyring,
            REPOSITORY_CONTEXT,
            &object,
            0,
            &root,
        ));
        assert_eq!(
            must(open_v2_index_root(
                &keyring,
                REPOSITORY_CONTEXT,
                &object,
                0,
                sealed.bytes(),
            )),
            root
        );
    }

    #[test]
    fn rejects_context_object_ordinal_and_ciphertext_transplants() {
        let keyring = keyring();
        let object = object_id("commits/v02/00000000000000000010/root");
        let sealed = must(seal_v2_index_root(
            &keyring,
            REPOSITORY_CONTEXT,
            &object,
            3,
            &fixture(),
        ));
        assert!(matches!(
            open_v2_index_root(&keyring, b"other-context", &object, 3, sealed.bytes()),
            Err(V2FormatError::CryptoOperation)
        ));
        assert!(matches!(
            open_v2_index_root(
                &keyring,
                REPOSITORY_CONTEXT,
                &object_id("commits/v02/00000000000000000010/other"),
                3,
                sealed.bytes()
            ),
            Err(V2FormatError::CryptoOperation)
        ));
        assert!(matches!(
            open_v2_index_root(&keyring, REPOSITORY_CONTEXT, &object, 4, sealed.bytes()),
            Err(V2FormatError::InvalidIndexRoot)
        ));
        let mut tampered = sealed.bytes().to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(open_v2_index_root(&keyring, REPOSITORY_CONTEXT, &object, 3, &tampered).is_err());
    }

    #[test]
    fn rejects_every_truncation_and_trailing_bytes() {
        let keyring = keyring();
        let object = object_id("commits/v02/00000000000000000010/root");
        let sealed = must(seal_v2_index_root(
            &keyring,
            REPOSITORY_CONTEXT,
            &object,
            0,
            &fixture(),
        ));
        for end in 0..sealed.bytes().len() {
            assert!(
                open_v2_index_root(
                    &keyring,
                    REPOSITORY_CONTEXT,
                    &object,
                    0,
                    &sealed.bytes()[..end]
                )
                .is_err()
            );
        }
        let mut trailing = sealed.bytes().to_vec();
        trailing.push(0);
        assert!(open_v2_index_root(&keyring, REPOSITORY_CONTEXT, &object, 0, &trailing).is_err());
    }

    #[test]
    fn rejects_duplicate_runs_invalid_bounds_and_limits() {
        let duplicate = run_ref(1, 8, "private/a");
        assert!(matches!(
            V2IndexRoot::new(
                Sequence::new(9),
                1,
                format_ref(),
                keyring_ref(),
                vec![duplicate.clone(), duplicate]
            ),
            Err(V2FormatError::InvalidIndexRoot)
        ));

        let mut invalid = run_ref(1, 8, "private/a");
        invalid.minimum_generation = Sequence::new(9);
        assert!(matches!(
            V2IndexRoot::new(
                Sequence::new(9),
                1,
                format_ref(),
                keyring_ref(),
                vec![invalid]
            ),
            Err(V2FormatError::InvalidIndexRoot)
        ));

        let too_many = (0..=V2_INDEX_ROOT_MAX_RUNS)
            .map(|index| {
                let mut run = run_ref(1, 8, "private/a");
                run.run_id[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
                run.location.section_ordinal = u32::try_from(index % 64).unwrap_or(0);
                run.location.commit_key = object_id(&format!("commits/v02/{index:020}/run"));
                run
            })
            .collect();
        assert!(matches!(
            V2IndexRoot::new(Sequence::new(9), 1, format_ref(), keyring_ref(), too_many),
            Err(V2FormatError::IndexRootLimitExceeded)
        ));
    }

    #[test]
    fn rejects_invalid_level_and_compaction_generation_pairs() {
        let mut level_zero_with_generation = run_ref(1, 9, "private/a");
        level_zero_with_generation.compaction_generation = 10;
        assert!(matches!(
            V2IndexRoot::new(
                Sequence::new(9),
                1,
                format_ref(),
                keyring_ref(),
                vec![level_zero_with_generation],
            ),
            Err(V2FormatError::InvalidIndexRoot)
        ));

        let mut compacted_without_generation = run_ref(1, 9, "private/a");
        compacted_without_generation.level = 1;
        assert!(matches!(
            V2IndexRoot::new(
                Sequence::new(9),
                1,
                format_ref(),
                keyring_ref(),
                vec![compacted_without_generation],
            ),
            Err(V2FormatError::InvalidIndexRoot)
        ));

        let mut level_above_limit = run_ref(1, 9, "private/a");
        level_above_limit.level = V2_INDEX_ROOT_MAX_LEVEL + 1;
        level_above_limit.compaction_generation = 10;
        assert!(matches!(
            V2IndexRoot::new(
                Sequence::new(9),
                1,
                format_ref(),
                keyring_ref(),
                vec![level_above_limit],
            ),
            Err(V2FormatError::InvalidIndexRoot)
        ));
    }

    #[test]
    fn rejects_legacy_root_wire_version() {
        let keyring = keyring();
        let object = object_id("commits/v02/00000000000000000010/root");
        let sealed = must(seal_v2_index_root(
            &keyring,
            REPOSITORY_CONTEXT,
            &object,
            0,
            &fixture(),
        ));
        let mut legacy = sealed.bytes().to_vec();
        legacy[10..12].copy_from_slice(&1_u16.to_be_bytes());
        assert!(matches!(
            open_v2_index_root(&keyring, REPOSITORY_CONTEXT, &object, 0, &legacy),
            Err(V2FormatError::InvalidIndexRoot)
        ));
    }

    #[test]
    fn rejects_noncanonical_run_order() {
        let keyring = keyring();
        let object = object_id("commits/v02/00000000000000000010/root");
        let mut root = fixture();
        root.runs.reverse();
        assert!(matches!(
            seal_v2_index_root(&keyring, REPOSITORY_CONTEXT, &object, 0, &root),
            Err(V2FormatError::InvalidIndexRoot)
        ));
    }

    #[test]
    fn debug_redacts_listing_bounds() {
        let debug = format!("{:?}", fixture());
        let run_debug = format!("{:?}", fixture().runs()[0]);
        assert!(!debug.contains("private/a"));
        assert!(!debug.contains("private/b"));
        assert!(!run_debug.contains("private/a"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn rejects_fixed_header_tampering() {
        let keyring = keyring();
        let object = object_id("commits/v02/00000000000000000010/root");
        let sealed = must(seal_v2_index_root(
            &keyring,
            REPOSITORY_CONTEXT,
            &object,
            0,
            &fixture(),
        ));
        let mut tampered = sealed.bytes().to_vec();
        tampered[V2_INDEX_ROOT_FIXED_HEADER_BYTES - 1] ^= 1;
        assert!(open_v2_index_root(&keyring, REPOSITORY_CONTEXT, &object, 0, &tampered).is_err());
    }
}
