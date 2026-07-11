//! v2 commit-key, commit-header, and commit-object validation.

use super::cbor;
use super::error::{V2FormatError, V2Result};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use getrandom::fill as fill_random;
use rs3_crypto::KeyRing;
use rs3_types::{BackendObjectId, BackendVersionId, KeyId, KeyPurpose, Sequence};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Fixed byte length of a v2 random commit identifier.
pub const V2_COMMIT_RANDOM_ID_LEN: usize = 32;
/// Base64url length of a v2 random commit identifier without padding.
pub const V2_COMMIT_RANDOM_ID_B64_LEN: usize = 43;
/// Fixed byte length of a v2 SHA-256 digest.
pub const V2_DIGEST_LEN: usize = 32;
/// Fixed byte length of an Ed25519 signature.
pub const V2_SIGNATURE_LEN: usize = 64;
/// Fixed v2 commit header prefix length.
pub const V2_HEADER_META_LEN: usize = 64;
/// Maximum complete v2 commit header span.
pub const V2_MAX_HEADER_SIZE: usize = 8192;
/// Maximum number of physical sections in one v02 commit.
pub const V2_MAX_COMMIT_SECTIONS: usize = 65;
/// Magic bytes at the start of every v2 commit object.
pub const V2_COMMIT_MAGIC: &[u8; 8] = b"rs3:cmt\n";
/// v02 commit format version.
pub const V2_FORMAT_VERSION: u32 = 2;
/// v02 minimum reader version.
pub const V2_MIN_READER_VERSION: u32 = 2;
/// Commit sections carry signed digests over their exact stored bytes.
pub const V2_CAPABILITY_SIGNED_SECTION_DIGESTS: u64 = 1 << 0;
/// Commit index sections use the framed v02 run/catalog encoding.
pub const V2_CAPABILITY_FRAMED_INDEX: u64 = 1 << 1;
/// Signed roots can reference metadata-only compacted run siblings.
pub const V2_CAPABILITY_COMPACTED_INDEX_RUNS: u64 = 1 << 2;
/// v02 capabilities understood by this transitional reader.
pub const V2_SUPPORTED_CAPABILITY_FLAGS: u64 = V2_CAPABILITY_SIGNED_SECTION_DIGESTS
    | V2_CAPABILITY_FRAMED_INDEX
    | V2_CAPABILITY_COMPACTED_INDEX_RUNS;
/// Capabilities required on every commit written or accepted by this reader.
pub const V2_REQUIRED_CAPABILITY_FLAGS: u64 = V2_CAPABILITY_SIGNED_SECTION_DIGESTS;
/// Section flag indicating the section type must be understood.
pub const V2_SECTION_FLAG_MUST_UNDERSTAND: u8 = 0x01;
/// Section flag indicating compressed section bytes.
pub const V2_SECTION_FLAG_COMPRESSED: u8 = 0x02;
/// Media type used for v2 commit objects.
pub const V2_COMMIT_CONTENT_TYPE: &str = "application/vnd.rs3.commit.v2";

const COMMIT_PREFIX: &str = "commits/v02/";
const HEADER_DIGEST_START: usize = 32;
const HEADER_DIGEST_END: usize = HEADER_DIGEST_START + V2_DIGEST_LEN;
const HEADER_CBOR_START: usize = V2_HEADER_META_LEN;
const MAX_HEADER_CBOR_LEN: usize = V2_MAX_HEADER_SIZE - V2_HEADER_META_LEN;

/// v2 commit upload mode encoded in the fixed header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V2UploadMode {
    /// Header is immediately followed by sections.
    SinglePut,
    /// Header is padded to the fixed v02 header span for multipart assembly.
    MultipartPadded,
}

impl V2UploadMode {
    /// Returns the wire-code value for this upload mode.
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::SinglePut => 0,
            Self::MultipartPadded => 1,
        }
    }

    fn from_wire(value: u8) -> V2Result<Self> {
        match value {
            0 => Ok(Self::SinglePut),
            1 => Ok(Self::MultipartPadded),
            _ => Err(V2FormatError::UnsupportedUploadMode),
        }
    }
}

/// Semantic role of a v02 commit in the authenticated history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V2CommitKind {
    /// An incremental mutation commit that links to a parent.
    Delta,
    /// A self-contained repository root used for genesis or checkpoints.
    Root,
}

impl V2CommitKind {
    /// Returns the canonical wire value for this commit kind.
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::Delta => 1,
            Self::Root => 2,
        }
    }

    fn from_wire(value: u64) -> V2Result<Self> {
        match value {
            1 => Ok(Self::Delta),
            2 => Ok(Self::Root),
            _ => Err(V2FormatError::InvalidHeaderField),
        }
    }
}

/// v02 commit section type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V2SectionType {
    /// Encrypted incremental namespace mutation section.
    IndexDelta,
    /// Encrypted full live namespace snapshot section.
    IndexSnapshot,
    /// Encrypted payload bytes stored in this commit.
    Payload,
    /// Encrypted maintenance directive section.
    Directives,
    /// Framed encrypted namespace mutation run.
    IndexRun,
    /// Encrypted catalog of the index runs that form a repository root.
    IndexRoot,
    /// Immutable encrypted value container referenced by an index run.
    PayloadPack,
    /// Unknown section type preserved for validation decisions.
    Unknown(u16),
}

impl V2SectionType {
    /// Converts a section type to its wire-code value.
    pub const fn to_wire(self) -> u16 {
        match self {
            Self::IndexDelta => 0x0001,
            Self::IndexSnapshot => 0x0002,
            Self::Payload => 0x0003,
            Self::Directives => 0x0004,
            Self::IndexRun => 0x0005,
            Self::IndexRoot => 0x0006,
            Self::PayloadPack => 0x0007,
            Self::Unknown(value) => value,
        }
    }

    fn from_wire(value: u16) -> Self {
        match value {
            0x0001 => Self::IndexDelta,
            0x0002 => Self::IndexSnapshot,
            0x0003 => Self::Payload,
            0x0004 => Self::Directives,
            0x0005 => Self::IndexRun,
            0x0006 => Self::IndexRoot,
            0x0007 => Self::PayloadPack,
            other => Self::Unknown(other),
        }
    }

    fn is_supported(self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

/// Strict v2 commit object key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2CommitKey {
    /// Parsed commit sequence segment.
    pub sequence: Sequence,
    /// Parsed random commit identifier bytes.
    pub random_id: [u8; V2_COMMIT_RANDOM_ID_LEN],
    /// Full backend object key.
    pub object_id: BackendObjectId,
}

impl V2CommitKey {
    /// Builds a strict v2 commit key from a sequence and 32 random bytes.
    pub fn from_parts(
        sequence: Sequence,
        random_id: [u8; V2_COMMIT_RANDOM_ID_LEN],
    ) -> V2Result<Self> {
        let encoded = URL_SAFE_NO_PAD.encode(random_id);
        let object_id =
            BackendObjectId::new(format!("{COMMIT_PREFIX}{:020}/{encoded}", sequence.get()))?;
        Ok(Self {
            sequence,
            random_id,
            object_id,
        })
    }

    /// Parses and validates a v2 commit key.
    pub fn parse(object_id: &BackendObjectId) -> V2Result<Self> {
        let Some(rest) = object_id.as_str().strip_prefix(COMMIT_PREFIX) else {
            return Err(V2FormatError::InvalidCommitKey);
        };
        let Some((seq_segment, encoded_id)) = rest.split_once('/') else {
            return Err(V2FormatError::InvalidCommitKey);
        };
        if seq_segment.len() != 20
            || !seq_segment.bytes().all(|byte| byte.is_ascii_digit())
            || encoded_id.len() != V2_COMMIT_RANDOM_ID_B64_LEN
            || encoded_id.contains('=')
            || encoded_id.contains('/')
        {
            return Err(V2FormatError::InvalidCommitKey);
        }
        if encoded_id.contains('+') {
            return Err(V2FormatError::InvalidCommitKey);
        }
        let sequence_raw = seq_segment
            .parse::<u64>()
            .map_err(|_| V2FormatError::InvalidCommitKey)?;
        if format!("{sequence_raw:020}") != seq_segment {
            return Err(V2FormatError::InvalidCommitKey);
        }

        let decoded = URL_SAFE_NO_PAD
            .decode(encoded_id)
            .map_err(|_| V2FormatError::InvalidCommitKey)?;
        let random_id: [u8; V2_COMMIT_RANDOM_ID_LEN] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| V2FormatError::InvalidCommitKey)?;
        if URL_SAFE_NO_PAD.encode(random_id) != encoded_id {
            return Err(V2FormatError::InvalidCommitKey);
        }

        Ok(Self {
            sequence: Sequence::new(sequence_raw),
            random_id,
            object_id: object_id.clone(),
        })
    }
}

/// Generates a fresh random v2 commit key for one upload attempt.
pub fn generate_v2_commit_key(sequence: Sequence) -> V2Result<V2CommitKey> {
    let mut random_id = [0_u8; V2_COMMIT_RANDOM_ID_LEN];
    fill_random(&mut random_id).map_err(|_| V2FormatError::RandomnessUnavailable)?;
    V2CommitKey::from_parts(sequence, random_id)
}

/// Signed self-reference carried by every v2 commit header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2CommitSelfRef {
    /// Commit sequence.
    pub sequence: Sequence,
    /// Full backend commit key.
    pub commit_key: BackendObjectId,
}

/// Signed parent-reference carried by non-genesis v2 commit headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2CommitParentRef {
    /// Parent commit sequence.
    pub sequence: Sequence,
    /// Full backend parent commit key.
    pub commit_key: BackendObjectId,
    /// Parent commit body digest.
    pub body_digest: [u8; V2_DIGEST_LEN],
    /// Provider version ID when the repository profile requires exact versions.
    pub version_id: Option<BackendVersionId>,
}

/// v02 algorithm identifiers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2Algorithms {
    /// Header signature algorithm identifier.
    pub signature: String,
    /// Payload AEAD algorithm identifier.
    pub payload_aead: String,
    /// Index metadata AEAD and deterministic nonce suite identifier.
    pub index_aead: String,
    /// Digest algorithm identifier.
    pub digest: String,
    /// Key-derivation algorithm identifier.
    pub kdf: String,
}

impl V2Algorithms {
    /// Returns the exact v02 primitive identifiers.
    pub fn v02() -> Self {
        Self {
            signature: "Ed25519".to_owned(),
            payload_aead: "XChaCha20-Poly1305".to_owned(),
            index_aead: "AES-256-GCM-SIV-HMAC-SHA256-Nonce-v1".to_owned(),
            digest: "SHA-256".to_owned(),
            kdf: "HMAC-SHA256".to_owned(),
        }
    }
}

impl Default for V2Algorithms {
    fn default() -> Self {
        Self::v02()
    }
}

/// Signed reference to the encrypted keyring envelope active for a commit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V2KeyringEnvelopeRef {
    /// Full backend keyring envelope object key.
    pub object_id: BackendObjectId,
    /// SHA-256 digest of the encrypted envelope object.
    pub digest: [u8; V2_DIGEST_LEN],
}

/// One section entry in a v2 commit header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2SectionDescriptor {
    /// Section type code.
    pub section_type: V2SectionType,
    /// Byte offset relative to the start of the section region.
    pub offset: u64,
    /// Section length in bytes.
    pub length: u64,
    /// Section flags.
    pub flags: u8,
    /// SHA-256 digest over the section's exact stored bytes.
    pub digest: [u8; V2_DIGEST_LEN],
}

/// Canonical v2 commit header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2CommitHeader {
    /// Signed self-reference.
    pub self_ref: V2CommitSelfRef,
    /// Signed parent-reference, absent only for the genesis commit.
    pub parent: Option<V2CommitParentRef>,
    /// Commit publish time in milliseconds since Unix epoch.
    pub publish_time_ms: i64,
    /// Semantic role of this commit in the authenticated history.
    pub kind: V2CommitKind,
    /// Exact v02 algorithm identifiers.
    pub algorithms: V2Algorithms,
    /// Active keyring envelope reference.
    pub keyring_envelope_ref: V2KeyringEnvelopeRef,
    /// Declared section layout.
    pub section_index: Vec<V2SectionDescriptor>,
    /// SHA-256 digest over declared section bytes in header order.
    pub body_digest: [u8; V2_DIGEST_LEN],
    /// Ed25519 signature over the header span with this field zeroed.
    pub signature: [u8; V2_SIGNATURE_LEN],
    /// Signing key ID used to verify the header signature.
    pub signing_key_id: KeyId,
}

impl V2CommitHeader {
    /// Signs this header using the primary checkpoint-signing key.
    pub fn sign_with_keyring(
        mut self,
        keyring: &KeyRing,
        upload_mode: V2UploadMode,
    ) -> V2Result<Self> {
        self.signing_key_id = keyring.primary_key_id(KeyPurpose::CheckpointSigning)?;
        self.signature = [0_u8; V2_SIGNATURE_LEN];
        let signing_bytes = header_span(&self, upload_mode, SignatureMode::Zero)?;
        let signature = keyring.sign_checkpoint_payload(&signing_bytes)?;
        let signature_bytes: [u8; V2_SIGNATURE_LEN] = signature
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| V2FormatError::InvalidHeaderField)?;
        self.signing_key_id = signature.key_id;
        self.signature = signature_bytes;
        Ok(self)
    }

    /// Encodes this signed header plus section-region bytes as a commit object.
    pub fn encode_object(
        &self,
        upload_mode: V2UploadMode,
        section_region: &[u8],
    ) -> V2Result<Bytes> {
        validate_commit_section_semantics(self)?;
        let digest = body_digest_for_v2_sections(&self.section_index, section_region)?;
        if digest != self.body_digest {
            return Err(V2FormatError::BodyDigestMismatch);
        }

        let mut span = header_span(self, upload_mode, SignatureMode::Actual)?;
        let digest = Sha256::digest(&span);
        span[HEADER_DIGEST_START..HEADER_DIGEST_END].copy_from_slice(&digest);
        span.extend_from_slice(section_region);
        Ok(Bytes::from(span))
    }

    /// Encodes only the signed fixed/header span for multipart assembly.
    pub(crate) fn encode_header_span(&self, upload_mode: V2UploadMode) -> V2Result<Bytes> {
        validate_commit_section_semantics(self)?;
        let mut span = header_span(self, upload_mode, SignatureMode::Actual)?;
        let digest = Sha256::digest(&span);
        span[HEADER_DIGEST_START..HEADER_DIGEST_END].copy_from_slice(&digest);
        Ok(Bytes::from(span))
    }
}

/// Parsed v2 commit header plus fixed-header metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2ParsedCommitHeader {
    /// Decoded and verified header.
    pub header: V2CommitHeader,
    /// Commit upload mode from the fixed header.
    pub upload_mode: V2UploadMode,
    /// Declared v2 header CBOR length.
    pub header_len: usize,
    /// Absolute byte offset where section-region bytes start.
    pub sections_start: usize,
}

/// Parsed and fully body-verified v2 commit object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2ParsedCommit {
    /// Decoded and verified header plus fixed-header metadata.
    pub parsed_header: V2ParsedCommitHeader,
    /// Provider version identifier used to read this commit, when available.
    pub version_id: Option<BackendVersionId>,
    /// Full object bytes that were verified.
    pub body: Bytes,
}

/// Parses and verifies a v2 commit header from a full object or header prefix.
pub fn parse_v2_commit_header(
    object_id: &BackendObjectId,
    input: &[u8],
    keyring: &KeyRing,
) -> V2Result<V2ParsedCommitHeader> {
    let fixed = parse_fixed_header(input)?;
    let header_span_bytes = input
        .get(..fixed.header_span_len)
        .ok_or(V2FormatError::TruncatedHeader)?;
    verify_header_digest(header_span_bytes)?;
    if fixed.upload_mode == V2UploadMode::MultipartPadded {
        let padding_start = V2_HEADER_META_LEN + fixed.header_len;
        if header_span_bytes[padding_start..]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(V2FormatError::HeaderDigestMismatch);
        }
    }

    let header_cbor = &header_span_bytes[HEADER_CBOR_START..HEADER_CBOR_START + fixed.header_len];
    let header = decode_header_cbor(header_cbor)?;
    let canonical = encode_header_cbor(&header, SignatureMode::Actual)?;
    if canonical != header_cbor {
        return Err(V2FormatError::NonCanonicalCbor);
    }
    if header.algorithms != V2Algorithms::v02() {
        return Err(V2FormatError::InvalidAlgorithms);
    }
    if fixed.capability_flags != capability_flags_for_header(&header) {
        return Err(V2FormatError::UnsupportedCapabilities);
    }
    let commit_key = V2CommitKey::parse(&header.self_ref.commit_key)?;
    if commit_key.sequence != header.self_ref.sequence {
        return Err(V2FormatError::SelfKeyMismatch);
    }
    if &header.self_ref.commit_key != object_id {
        return Err(V2FormatError::SelfKeyMismatch);
    }

    let signing_bytes = header_span(&header, fixed.upload_mode, SignatureMode::Zero)?;
    keyring
        .verify_checkpoint_payload(&header.signing_key_id, &signing_bytes, &header.signature)
        .map_err(|_| V2FormatError::SignatureVerification)?;

    Ok(V2ParsedCommitHeader {
        header,
        upload_mode: fixed.upload_mode,
        header_len: fixed.header_len,
        sections_start: fixed.header_span_len,
    })
}

/// Returns the exact header span length after reading the fixed v2 header.
pub(crate) fn v2_commit_header_span_len(input: &[u8]) -> V2Result<usize> {
    if input.len() < V2_HEADER_META_LEN {
        return Err(V2FormatError::TruncatedHeader);
    }
    if &input[..V2_COMMIT_MAGIC.len()] != V2_COMMIT_MAGIC {
        return Err(V2FormatError::TruncatedHeader);
    }

    let format_version = u32::from_be_bytes(
        input[8..12]
            .try_into()
            .map_err(|_| V2FormatError::TruncatedHeader)?,
    );
    if format_version != V2_FORMAT_VERSION {
        return Err(V2FormatError::UnsupportedFormatVersion);
    }
    let min_reader_version = u32::from_be_bytes(
        input[12..16]
            .try_into()
            .map_err(|_| V2FormatError::TruncatedHeader)?,
    );
    if min_reader_version > V2_MIN_READER_VERSION {
        return Err(V2FormatError::UnsupportedReaderVersion);
    }
    let capability_flags = u64::from_be_bytes(
        input[16..24]
            .try_into()
            .map_err(|_| V2FormatError::TruncatedHeader)?,
    );
    if capability_flags & !V2_SUPPORTED_CAPABILITY_FLAGS != 0
        || capability_flags & V2_REQUIRED_CAPABILITY_FLAGS != V2_REQUIRED_CAPABILITY_FLAGS
    {
        return Err(V2FormatError::UnsupportedCapabilities);
    }
    let upload_mode = V2UploadMode::from_wire(input[24])?;
    if input[25..28].iter().any(|byte| *byte != 0) {
        return Err(V2FormatError::NonzeroReserved);
    }
    let header_len = usize::try_from(u32::from_be_bytes(
        input[28..32]
            .try_into()
            .map_err(|_| V2FormatError::TruncatedHeader)?,
    ))
    .map_err(|_| V2FormatError::HeaderTooLarge)?;
    if header_len > MAX_HEADER_CBOR_LEN {
        return Err(V2FormatError::HeaderTooLarge);
    }

    match upload_mode {
        V2UploadMode::SinglePut => V2_HEADER_META_LEN
            .checked_add(header_len)
            .ok_or(V2FormatError::HeaderTooLarge),
        V2UploadMode::MultipartPadded => Ok(V2_MAX_HEADER_SIZE),
    }
}

/// Parses and verifies a complete v2 commit object, including section digest.
pub fn parse_v2_commit_object(
    object_id: &BackendObjectId,
    body: Bytes,
    keyring: &KeyRing,
) -> V2Result<V2ParsedCommit> {
    let parsed_header = parse_v2_commit_header(object_id, &body, keyring)?;
    let section_region = body
        .get(parsed_header.sections_start..)
        .ok_or(V2FormatError::TruncatedBody)?;
    let digest = body_digest_for_v2_sections(&parsed_header.header.section_index, section_region)?;
    if digest != parsed_header.header.body_digest {
        return Err(V2FormatError::BodyDigestMismatch);
    }
    validate_commit_section_semantics(&parsed_header.header)?;
    Ok(V2ParsedCommit {
        parsed_header,
        version_id: None,
        body,
    })
}

/// Computes the v2 body digest over declared section bytes in header order.
pub fn body_digest_for_v2_sections(
    section_index: &[V2SectionDescriptor],
    section_region: &[u8],
) -> V2Result<[u8; V2_DIGEST_LEN]> {
    let section_region_len =
        u64::try_from(section_region.len()).map_err(|_| V2FormatError::SectionBounds)?;
    validate_section_layout(section_index, section_region_len)?;
    let mut digest = Sha256::new();
    for section in section_index {
        let start = usize::try_from(section.offset).map_err(|_| V2FormatError::SectionBounds)?;
        let length = usize::try_from(section.length).map_err(|_| V2FormatError::SectionBounds)?;
        let end = start
            .checked_add(length)
            .ok_or(V2FormatError::SectionBounds)?;
        let section_bytes = &section_region[start..end];
        if digest_v2_section(section_bytes) != section.digest {
            return Err(V2FormatError::SectionDigestMismatch);
        }
        digest.update(section_bytes);
    }
    Ok(digest.finalize().into())
}

/// Computes the digest authenticated by one v02 section descriptor.
pub fn digest_v2_section(section_bytes: &[u8]) -> [u8; V2_DIGEST_LEN] {
    Sha256::digest(section_bytes).into()
}

/// Validates the signed section layout against provider-reported object length.
///
/// Bounded readers call this before issuing section range reads so hostile
/// offsets and lengths cannot trigger oversized allocations or unbounded reads.
pub(crate) fn validate_v2_commit_object_len(
    parsed_header: &V2ParsedCommitHeader,
    object_len: u64,
) -> V2Result<()> {
    let sections_start =
        u64::try_from(parsed_header.sections_start).map_err(|_| V2FormatError::SectionBounds)?;
    let section_region_len = object_len
        .checked_sub(sections_start)
        .ok_or(V2FormatError::TruncatedBody)?;
    validate_section_layout(&parsed_header.header.section_index, section_region_len)?;
    validate_commit_section_semantics(&parsed_header.header)
}

#[derive(Clone, Copy)]
enum SignatureMode {
    Actual,
    Zero,
}

#[derive(Clone, Copy)]
struct FixedHeader {
    capability_flags: u64,
    upload_mode: V2UploadMode,
    header_len: usize,
    header_span_len: usize,
}

fn parse_fixed_header(input: &[u8]) -> V2Result<FixedHeader> {
    if input.len() < V2_HEADER_META_LEN {
        return Err(V2FormatError::TruncatedHeader);
    }
    if &input[..V2_COMMIT_MAGIC.len()] != V2_COMMIT_MAGIC {
        return Err(V2FormatError::TruncatedHeader);
    }

    let format_version = u32::from_be_bytes(
        input[8..12]
            .try_into()
            .map_err(|_| V2FormatError::TruncatedHeader)?,
    );
    if format_version != V2_FORMAT_VERSION {
        return Err(V2FormatError::UnsupportedFormatVersion);
    }
    let min_reader_version = u32::from_be_bytes(
        input[12..16]
            .try_into()
            .map_err(|_| V2FormatError::TruncatedHeader)?,
    );
    if min_reader_version > V2_MIN_READER_VERSION {
        return Err(V2FormatError::UnsupportedReaderVersion);
    }
    let capability_flags = u64::from_be_bytes(
        input[16..24]
            .try_into()
            .map_err(|_| V2FormatError::TruncatedHeader)?,
    );
    if capability_flags & !V2_SUPPORTED_CAPABILITY_FLAGS != 0
        || capability_flags & V2_REQUIRED_CAPABILITY_FLAGS != V2_REQUIRED_CAPABILITY_FLAGS
    {
        return Err(V2FormatError::UnsupportedCapabilities);
    }
    let upload_mode = V2UploadMode::from_wire(input[24])?;
    if input[25..28].iter().any(|byte| *byte != 0) {
        return Err(V2FormatError::NonzeroReserved);
    }
    let header_len = usize::try_from(u32::from_be_bytes(
        input[28..32]
            .try_into()
            .map_err(|_| V2FormatError::TruncatedHeader)?,
    ))
    .map_err(|_| V2FormatError::HeaderTooLarge)?;
    if header_len > MAX_HEADER_CBOR_LEN {
        return Err(V2FormatError::HeaderTooLarge);
    }
    let header_span_len = match upload_mode {
        V2UploadMode::SinglePut => V2_HEADER_META_LEN
            .checked_add(header_len)
            .ok_or(V2FormatError::HeaderTooLarge)?,
        V2UploadMode::MultipartPadded => V2_MAX_HEADER_SIZE,
    };
    if input.len() < header_span_len {
        return Err(V2FormatError::TruncatedHeader);
    }

    Ok(FixedHeader {
        capability_flags,
        upload_mode,
        header_len,
        header_span_len,
    })
}

fn verify_header_digest(header_span_bytes: &[u8]) -> V2Result<()> {
    let declared = &header_span_bytes[HEADER_DIGEST_START..HEADER_DIGEST_END];
    let mut digest_input = header_span_bytes.to_vec();
    digest_input[HEADER_DIGEST_START..HEADER_DIGEST_END].fill(0);
    let actual = Sha256::digest(&digest_input);
    if actual.as_slice() == declared {
        Ok(())
    } else {
        Err(V2FormatError::HeaderDigestMismatch)
    }
}

fn header_span(
    header: &V2CommitHeader,
    upload_mode: V2UploadMode,
    signature_mode: SignatureMode,
) -> V2Result<Vec<u8>> {
    let cbor = encode_header_cbor(header, signature_mode)?;
    if cbor.len() > MAX_HEADER_CBOR_LEN {
        return Err(V2FormatError::HeaderTooLarge);
    }

    let header_span_len = match upload_mode {
        V2UploadMode::SinglePut => V2_HEADER_META_LEN + cbor.len(),
        V2UploadMode::MultipartPadded => V2_MAX_HEADER_SIZE,
    };
    let mut out = vec![0_u8; header_span_len];
    out[..V2_COMMIT_MAGIC.len()].copy_from_slice(V2_COMMIT_MAGIC);
    out[8..12].copy_from_slice(&V2_FORMAT_VERSION.to_be_bytes());
    out[12..16].copy_from_slice(&V2_MIN_READER_VERSION.to_be_bytes());
    out[16..24].copy_from_slice(&capability_flags_for_header(header).to_be_bytes());
    out[24] = upload_mode.to_wire();
    out[28..32].copy_from_slice(&(cbor.len() as u32).to_be_bytes());
    out[HEADER_CBOR_START..HEADER_CBOR_START + cbor.len()].copy_from_slice(&cbor);
    Ok(out)
}

fn encode_header_cbor(header: &V2CommitHeader, signature_mode: SignatureMode) -> V2Result<Vec<u8>> {
    let mut out = Vec::new();
    cbor::write_map_len(&mut out, 10);

    cbor::write_u64(&mut out, 1);
    encode_self_ref(&mut out, &header.self_ref);

    cbor::write_u64(&mut out, 2);
    match header.parent.as_ref() {
        Some(parent) => encode_parent_ref(&mut out, parent),
        None => cbor::write_null(&mut out),
    }

    cbor::write_u64(&mut out, 3);
    cbor::write_i64(&mut out, header.publish_time_ms);

    cbor::write_u64(&mut out, 4);
    cbor::write_u64(&mut out, u64::from(header.kind.to_wire()));

    cbor::write_u64(&mut out, 5);
    encode_algorithms(&mut out, &header.algorithms);

    cbor::write_u64(&mut out, 6);
    encode_keyring_ref(&mut out, &header.keyring_envelope_ref);

    cbor::write_u64(&mut out, 7);
    cbor::write_array_len(&mut out, header.section_index.len());
    for section in &header.section_index {
        encode_section(&mut out, section);
    }

    cbor::write_u64(&mut out, 8);
    cbor::write_bytes(&mut out, &header.body_digest);

    cbor::write_u64(&mut out, 9);
    match signature_mode {
        SignatureMode::Actual => cbor::write_bytes(&mut out, &header.signature),
        SignatureMode::Zero => cbor::write_bytes(&mut out, &[0_u8; V2_SIGNATURE_LEN]),
    }

    cbor::write_u64(&mut out, 10);
    cbor::write_bytes(&mut out, header.signing_key_id.as_str().as_bytes());

    Ok(out)
}

fn encode_self_ref(out: &mut Vec<u8>, self_ref: &V2CommitSelfRef) {
    cbor::write_map_len(out, 2);
    cbor::write_u64(out, 1);
    cbor::write_u64(out, self_ref.sequence.get());
    cbor::write_u64(out, 2);
    cbor::write_text(out, self_ref.commit_key.as_str());
}

fn encode_parent_ref(out: &mut Vec<u8>, parent: &V2CommitParentRef) {
    cbor::write_map_len(out, 4);
    cbor::write_u64(out, 1);
    cbor::write_u64(out, parent.sequence.get());
    cbor::write_u64(out, 2);
    cbor::write_text(out, parent.commit_key.as_str());
    cbor::write_u64(out, 3);
    cbor::write_bytes(out, &parent.body_digest);
    cbor::write_u64(out, 4);
    match parent.version_id.as_ref() {
        Some(version_id) => cbor::write_bytes(out, version_id.as_str().as_bytes()),
        None => cbor::write_null(out),
    }
}

fn encode_algorithms(out: &mut Vec<u8>, algorithms: &V2Algorithms) {
    cbor::write_map_len(out, 5);
    cbor::write_u64(out, 1);
    cbor::write_text(out, &algorithms.signature);
    cbor::write_u64(out, 2);
    cbor::write_text(out, &algorithms.payload_aead);
    cbor::write_u64(out, 3);
    cbor::write_text(out, &algorithms.index_aead);
    cbor::write_u64(out, 4);
    cbor::write_text(out, &algorithms.digest);
    cbor::write_u64(out, 5);
    cbor::write_text(out, &algorithms.kdf);
}

fn encode_keyring_ref(out: &mut Vec<u8>, reference: &V2KeyringEnvelopeRef) {
    cbor::write_map_len(out, 2);
    cbor::write_u64(out, 1);
    cbor::write_text(out, reference.object_id.as_str());
    cbor::write_u64(out, 2);
    cbor::write_bytes(out, &reference.digest);
}

fn encode_section(out: &mut Vec<u8>, section: &V2SectionDescriptor) {
    cbor::write_map_len(out, 5);
    cbor::write_u64(out, 1);
    cbor::write_u64(out, u64::from(section.section_type.to_wire()));
    cbor::write_u64(out, 2);
    cbor::write_u64(out, section.offset);
    cbor::write_u64(out, 3);
    cbor::write_u64(out, section.length);
    cbor::write_u64(out, 4);
    cbor::write_u64(out, u64::from(section.flags));
    cbor::write_u64(out, 5);
    cbor::write_bytes(out, &section.digest);
}

fn decode_header_cbor(input: &[u8]) -> V2Result<V2CommitHeader> {
    let mut reader = cbor::Reader::new(input);
    let len = reader
        .read_map_len()
        .map_err(|_| V2FormatError::MalformedCbor)?;
    if len != 10 {
        return Err(V2FormatError::MissingHeaderField);
    }

    let mut self_ref = None;
    let mut parent = None;
    let mut publish_time_ms = None;
    let mut kind = None;
    let mut algorithms = None;
    let mut keyring_envelope_ref = None;
    let mut section_index = None;
    let mut body_digest = None;
    let mut signature = None;
    let mut signing_key_id = None;
    let mut last_key = 0_u64;

    for _ in 0..len {
        let key = read_ordered_key(&mut reader, &mut last_key)?;
        match key {
            1 => self_ref = Some(decode_self_ref(&mut reader)?),
            2 => {
                parent = Some(if reader.next_is_null() {
                    reader
                        .read_null()
                        .map_err(|_| V2FormatError::MalformedCbor)?;
                    None
                } else {
                    Some(decode_parent_ref(&mut reader)?)
                });
            }
            3 => {
                publish_time_ms = Some(
                    reader
                        .read_i64()
                        .map_err(|_| V2FormatError::MalformedCbor)?,
                );
            }
            4 => {
                let value = reader
                    .read_u64()
                    .map_err(|_| V2FormatError::MalformedCbor)?;
                kind = Some(V2CommitKind::from_wire(value)?);
            }
            5 => algorithms = Some(decode_algorithms(&mut reader)?),
            6 => keyring_envelope_ref = Some(decode_keyring_ref(&mut reader)?),
            7 => section_index = Some(decode_sections(&mut reader)?),
            8 => body_digest = Some(decode_digest(&mut reader)?),
            9 => signature = Some(decode_signature(&mut reader)?),
            10 => signing_key_id = Some(decode_key_id(&mut reader)?),
            _ => return Err(V2FormatError::InvalidHeaderField),
        }
    }

    if !reader.is_finished() {
        return Err(V2FormatError::MalformedCbor);
    }

    Ok(V2CommitHeader {
        self_ref: self_ref.ok_or(V2FormatError::MissingHeaderField)?,
        parent: parent.ok_or(V2FormatError::MissingHeaderField)?,
        publish_time_ms: publish_time_ms.ok_or(V2FormatError::MissingHeaderField)?,
        kind: kind.ok_or(V2FormatError::MissingHeaderField)?,
        algorithms: algorithms.ok_or(V2FormatError::MissingHeaderField)?,
        keyring_envelope_ref: keyring_envelope_ref.ok_or(V2FormatError::MissingHeaderField)?,
        section_index: section_index.ok_or(V2FormatError::MissingHeaderField)?,
        body_digest: body_digest.ok_or(V2FormatError::MissingHeaderField)?,
        signature: signature.ok_or(V2FormatError::MissingHeaderField)?,
        signing_key_id: signing_key_id.ok_or(V2FormatError::MissingHeaderField)?,
    })
}

fn decode_self_ref(reader: &mut cbor::Reader<'_>) -> V2Result<V2CommitSelfRef> {
    let len = reader
        .read_map_len()
        .map_err(|_| V2FormatError::MalformedCbor)?;
    if len != 2 {
        return Err(V2FormatError::MissingHeaderField);
    }
    let mut sequence = None;
    let mut commit_key = None;
    let mut last_key = 0_u64;
    for _ in 0..len {
        let key = read_ordered_key(reader, &mut last_key)?;
        match key {
            1 => {
                sequence = Some(Sequence::new(
                    reader
                        .read_u64()
                        .map_err(|_| V2FormatError::MalformedCbor)?,
                ));
            }
            2 => {
                let value = reader
                    .read_text()
                    .map_err(|_| V2FormatError::MalformedCbor)?;
                commit_key = Some(BackendObjectId::new(value)?);
            }
            _ => return Err(V2FormatError::InvalidHeaderField),
        }
    }
    Ok(V2CommitSelfRef {
        sequence: sequence.ok_or(V2FormatError::MissingHeaderField)?,
        commit_key: commit_key.ok_or(V2FormatError::MissingHeaderField)?,
    })
}

fn decode_parent_ref(reader: &mut cbor::Reader<'_>) -> V2Result<V2CommitParentRef> {
    let len = reader
        .read_map_len()
        .map_err(|_| V2FormatError::MalformedCbor)?;
    if len != 4 {
        return Err(V2FormatError::MissingHeaderField);
    }
    let mut sequence = None;
    let mut commit_key = None;
    let mut body_digest = None;
    let mut version_id = None;
    let mut last_key = 0_u64;
    for _ in 0..len {
        let key = read_ordered_key(reader, &mut last_key)?;
        match key {
            1 => {
                sequence = Some(Sequence::new(
                    reader
                        .read_u64()
                        .map_err(|_| V2FormatError::MalformedCbor)?,
                ));
            }
            2 => {
                let value = reader
                    .read_text()
                    .map_err(|_| V2FormatError::MalformedCbor)?;
                commit_key = Some(BackendObjectId::new(value)?);
            }
            3 => body_digest = Some(decode_digest(reader)?),
            4 => {
                version_id = Some(if reader.next_is_null() {
                    reader
                        .read_null()
                        .map_err(|_| V2FormatError::MalformedCbor)?;
                    None
                } else {
                    let bytes = reader
                        .read_bytes()
                        .map_err(|_| V2FormatError::MalformedCbor)?;
                    Some(BackendVersionId::new(bytes_to_string(bytes)?)?)
                });
            }
            _ => return Err(V2FormatError::InvalidHeaderField),
        }
    }

    Ok(V2CommitParentRef {
        sequence: sequence.ok_or(V2FormatError::MissingHeaderField)?,
        commit_key: commit_key.ok_or(V2FormatError::MissingHeaderField)?,
        body_digest: body_digest.ok_or(V2FormatError::MissingHeaderField)?,
        version_id: version_id.ok_or(V2FormatError::MissingHeaderField)?,
    })
}

fn decode_algorithms(reader: &mut cbor::Reader<'_>) -> V2Result<V2Algorithms> {
    let len = reader
        .read_map_len()
        .map_err(|_| V2FormatError::MalformedCbor)?;
    if len != 5 {
        return Err(V2FormatError::MissingHeaderField);
    }
    let mut signature = None;
    let mut payload_aead = None;
    let mut index_aead = None;
    let mut digest = None;
    let mut kdf = None;
    let mut last_key = 0_u64;
    for _ in 0..len {
        let key = read_ordered_key(reader, &mut last_key)?;
        let value = reader
            .read_text()
            .map_err(|_| V2FormatError::MalformedCbor)?;
        match key {
            1 => signature = Some(value),
            2 => payload_aead = Some(value),
            3 => index_aead = Some(value),
            4 => digest = Some(value),
            5 => kdf = Some(value),
            _ => return Err(V2FormatError::InvalidHeaderField),
        }
    }
    Ok(V2Algorithms {
        signature: signature.ok_or(V2FormatError::MissingHeaderField)?,
        payload_aead: payload_aead.ok_or(V2FormatError::MissingHeaderField)?,
        index_aead: index_aead.ok_or(V2FormatError::MissingHeaderField)?,
        digest: digest.ok_or(V2FormatError::MissingHeaderField)?,
        kdf: kdf.ok_or(V2FormatError::MissingHeaderField)?,
    })
}

fn decode_keyring_ref(reader: &mut cbor::Reader<'_>) -> V2Result<V2KeyringEnvelopeRef> {
    let len = reader
        .read_map_len()
        .map_err(|_| V2FormatError::MalformedCbor)?;
    if len != 2 {
        return Err(V2FormatError::MissingHeaderField);
    }
    let mut object_id = None;
    let mut digest = None;
    let mut last_key = 0_u64;
    for _ in 0..len {
        let key = read_ordered_key(reader, &mut last_key)?;
        match key {
            1 => {
                let value = reader
                    .read_text()
                    .map_err(|_| V2FormatError::MalformedCbor)?;
                object_id = Some(BackendObjectId::new(value)?);
            }
            2 => digest = Some(decode_digest(reader)?),
            _ => return Err(V2FormatError::InvalidHeaderField),
        }
    }
    Ok(V2KeyringEnvelopeRef {
        object_id: object_id.ok_or(V2FormatError::MissingHeaderField)?,
        digest: digest.ok_or(V2FormatError::MissingHeaderField)?,
    })
}

fn decode_sections(reader: &mut cbor::Reader<'_>) -> V2Result<Vec<V2SectionDescriptor>> {
    let len = reader
        .read_array_len()
        .map_err(|_| V2FormatError::MalformedCbor)?;
    if len > V2_MAX_COMMIT_SECTIONS {
        return Err(V2FormatError::InvalidHeaderField);
    }
    let mut sections = Vec::with_capacity(len);
    for _ in 0..len {
        sections.push(decode_section(reader)?);
    }
    Ok(sections)
}

fn decode_section(reader: &mut cbor::Reader<'_>) -> V2Result<V2SectionDescriptor> {
    let len = reader
        .read_map_len()
        .map_err(|_| V2FormatError::MalformedCbor)?;
    if len != 5 {
        return Err(V2FormatError::MissingHeaderField);
    }
    let mut section_type = None;
    let mut offset = None;
    let mut length = None;
    let mut flags = None;
    let mut digest = None;
    let mut last_key = 0_u64;
    for _ in 0..len {
        let key = read_ordered_key(reader, &mut last_key)?;
        match key {
            1 => {
                let value = reader
                    .read_u64()
                    .map_err(|_| V2FormatError::MalformedCbor)?;
                let value = u16::try_from(value).map_err(|_| V2FormatError::InvalidHeaderField)?;
                section_type = Some(V2SectionType::from_wire(value));
            }
            2 => {
                offset = Some(
                    reader
                        .read_u64()
                        .map_err(|_| V2FormatError::MalformedCbor)?,
                );
            }
            3 => {
                length = Some(
                    reader
                        .read_u64()
                        .map_err(|_| V2FormatError::MalformedCbor)?,
                );
            }
            4 => {
                let value = reader
                    .read_u64()
                    .map_err(|_| V2FormatError::MalformedCbor)?;
                flags = Some(u8::try_from(value).map_err(|_| V2FormatError::InvalidHeaderField)?);
            }
            5 => digest = Some(decode_digest(reader)?),
            _ => return Err(V2FormatError::InvalidHeaderField),
        }
    }
    Ok(V2SectionDescriptor {
        section_type: section_type.ok_or(V2FormatError::MissingHeaderField)?,
        offset: offset.ok_or(V2FormatError::MissingHeaderField)?,
        length: length.ok_or(V2FormatError::MissingHeaderField)?,
        flags: flags.ok_or(V2FormatError::MissingHeaderField)?,
        digest: digest.ok_or(V2FormatError::MissingHeaderField)?,
    })
}

fn decode_digest(reader: &mut cbor::Reader<'_>) -> V2Result<[u8; V2_DIGEST_LEN]> {
    let bytes = reader
        .read_bytes()
        .map_err(|_| V2FormatError::MalformedCbor)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| V2FormatError::InvalidHeaderField)
}

fn decode_signature(reader: &mut cbor::Reader<'_>) -> V2Result<[u8; V2_SIGNATURE_LEN]> {
    let bytes = reader
        .read_bytes()
        .map_err(|_| V2FormatError::MalformedCbor)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| V2FormatError::InvalidHeaderField)
}

fn decode_key_id(reader: &mut cbor::Reader<'_>) -> V2Result<KeyId> {
    let bytes = reader
        .read_bytes()
        .map_err(|_| V2FormatError::MalformedCbor)?;
    KeyId::new(bytes_to_string(bytes)?).map_err(Into::into)
}

fn bytes_to_string(bytes: Vec<u8>) -> V2Result<String> {
    String::from_utf8(bytes).map_err(|_| V2FormatError::InvalidHeaderField)
}

fn read_ordered_key(reader: &mut cbor::Reader<'_>, last_key: &mut u64) -> V2Result<u64> {
    let key = reader
        .read_u64()
        .map_err(|_| V2FormatError::MalformedCbor)?;
    if key <= *last_key {
        return Err(V2FormatError::MalformedCbor);
    }
    *last_key = key;
    Ok(key)
}

fn validate_section_layout(
    section_index: &[V2SectionDescriptor],
    section_region_len: u64,
) -> V2Result<()> {
    if section_index.len() > V2_MAX_COMMIT_SECTIONS {
        return Err(V2FormatError::InvalidHeaderField);
    }
    let mut next_start = 0_u64;
    for section in section_index {
        if section.flags & !(V2_SECTION_FLAG_MUST_UNDERSTAND | V2_SECTION_FLAG_COMPRESSED) != 0 {
            return Err(V2FormatError::ReservedSectionFlags);
        }
        if section.flags & V2_SECTION_FLAG_MUST_UNDERSTAND != 0
            && !section.section_type.is_supported()
        {
            return Err(V2FormatError::UnsupportedSection);
        }
        let end = section
            .offset
            .checked_add(section.length)
            .ok_or(V2FormatError::SectionBounds)?;
        if section.offset != next_start || end > section_region_len {
            return Err(V2FormatError::SectionBounds);
        }
        next_start = end;
    }
    if next_start != section_region_len {
        return Err(V2FormatError::SectionBounds);
    }

    Ok(())
}

pub(crate) fn validate_commit_section_semantics(header: &V2CommitHeader) -> V2Result<()> {
    match header.parent.as_ref() {
        None if header.self_ref.sequence != Sequence::new(1) => {
            return Err(V2FormatError::InvalidHeaderField);
        }
        Some(parent) if parent.sequence.checked_next() != Some(header.self_ref.sequence) => {
            return Err(V2FormatError::InvalidHeaderField);
        }
        _ => {}
    }
    let snapshot_count = header
        .section_index
        .iter()
        .filter(|section| section.section_type == V2SectionType::IndexSnapshot)
        .count();
    let delta_count = header
        .section_index
        .iter()
        .filter(|section| section.section_type == V2SectionType::IndexDelta)
        .count();

    for section in &header.section_index {
        if matches!(
            section.section_type,
            V2SectionType::IndexDelta
                | V2SectionType::IndexSnapshot
                | V2SectionType::IndexRun
                | V2SectionType::IndexRoot
                | V2SectionType::PayloadPack
        ) && section.flags & V2_SECTION_FLAG_COMPRESSED != 0
        {
            return Err(V2FormatError::InvalidHeaderField);
        }
    }

    if header.kind == V2CommitKind::Root {
        let legacy_root = snapshot_count == 1
            && delta_count == 0
            && header
                .section_index
                .last()
                .map(|section| section.section_type)
                == Some(V2SectionType::IndexSnapshot)
            && header.section_index[..header.section_index.len().saturating_sub(1)]
                .iter()
                .all(|section| section.section_type == V2SectionType::Payload);
        let framed_root = matches!(
            header.section_index.as_slice(),
            [V2SectionDescriptor {
                section_type: V2SectionType::IndexRoot,
                ..
            }]
        );
        if delta_count != 0
            || (!legacy_root && !framed_root)
            || (framed_root && snapshot_count != 0)
            || (!framed_root && snapshot_count != 1)
            || header
                .section_index
                .iter()
                .any(|section| section.section_type == V2SectionType::IndexRun)
            || (framed_root && header.section_index[0].flags != V2_SECTION_FLAG_MUST_UNDERSTAND)
        {
            return Err(V2FormatError::InvalidHeaderField);
        }
    } else {
        let transitional_delta = snapshot_count == 0
            && delta_count == 1
            && header
                .section_index
                .last()
                .map(|section| section.section_type)
                == Some(V2SectionType::IndexDelta)
            && header.section_index[..header.section_index.len().saturating_sub(1)]
                .iter()
                .all(|section| section.section_type == V2SectionType::Payload);
        let framed_delta = matches!(
            header.section_index.as_slice(),
            [V2SectionDescriptor {
                section_type: V2SectionType::IndexRun,
                flags: V2_SECTION_FLAG_MUST_UNDERSTAND,
                ..
            }] | [
                V2SectionDescriptor {
                    section_type: V2SectionType::PayloadPack,
                    flags: V2_SECTION_FLAG_MUST_UNDERSTAND,
                    ..
                },
                V2SectionDescriptor {
                    section_type: V2SectionType::IndexRun,
                    flags: V2_SECTION_FLAG_MUST_UNDERSTAND,
                    ..
                }
            ] | [
                V2SectionDescriptor {
                    section_type: V2SectionType::Payload,
                    flags: V2_SECTION_FLAG_MUST_UNDERSTAND,
                    ..
                },
                V2SectionDescriptor {
                    section_type: V2SectionType::IndexRun,
                    flags: V2_SECTION_FLAG_MUST_UNDERSTAND,
                    ..
                }
            ]
        );
        if header.parent.is_none() || (!transitional_delta && !framed_delta) {
            return Err(V2FormatError::InvalidHeaderField);
        }
    }

    Ok(())
}

fn capability_flags_for_header(header: &V2CommitHeader) -> u64 {
    let framed = if header.section_index.iter().any(|section| {
        matches!(
            section.section_type,
            V2SectionType::IndexRun | V2SectionType::IndexRoot | V2SectionType::PayloadPack
        )
    }) {
        V2_CAPABILITY_FRAMED_INDEX
    } else {
        0
    };
    let compacted_runs = if header
        .section_index
        .iter()
        .any(|section| section.section_type == V2SectionType::IndexRoot)
    {
        V2_CAPABILITY_COMPACTED_INDEX_RUNS
    } else {
        0
    };
    V2_REQUIRED_CAPABILITY_FLAGS | framed | compacted_runs
}
