//! Canonical bounded plaintext encoding for v02 index runs.

use crate::PayloadHeaderReference;
use rs3_types::{
    BackendObjectId, BackendVersionId, BlindIndexKey, KeyId, LegalHoldStatus, LogicalPath,
    RetentionMode, RetentionPolicy, Sequence,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Domain separator at the start of every independently authenticated frame plaintext.
pub const INDEX_RUN_PLAINTEXT_DOMAIN: &[u8] = b"rs3:index-run-frame-plaintext:v2\n";

/// Version of the canonical index-run wire encoding.
pub const INDEX_RUN_WIRE_VERSION: u16 = 6;

/// Maximum stored size of one v02 payload pack.
pub const INDEX_PACK_MAX_STORED_BYTES: u64 = 32 * 1024 * 1024;

/// Maximum number of records in one v02 payload pack.
pub const INDEX_PACK_MAX_RECORDS: u32 = 4_096;

const INDEX_PACK_SEGMENT_BYTES: u64 = 64 * 1024;
const INDEX_PACK_SEGMENT_TAG_BYTES: u64 = 16;
const INDEX_STREAM_SEGMENT_TAG_BYTES: u64 = 16;
const INDEX_STREAM_MAX_HEADER_BYTES: u64 = 4 * 1024;

/// Decoder and encoder resource limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexRunLimits {
    /// Maximum encoded plaintext run size.
    pub max_total_bytes: usize,
    /// Maximum plaintext bytes in one independently authenticated frame.
    pub max_frame_bytes: usize,
    /// Maximum encoded size of one container or mutation record.
    pub max_record_bytes: usize,
    /// Maximum combined number of external payload containers.
    pub max_containers: usize,
    /// Maximum number of mutations.
    pub max_mutations: usize,
    /// Maximum logical-path length in bytes.
    pub max_path_bytes: usize,
    /// Maximum key-identifier length in bytes.
    pub max_key_id_bytes: usize,
    /// Maximum backend object-identifier length in bytes.
    pub max_object_id_bytes: usize,
    /// Maximum backend version-identifier length in bytes.
    pub max_version_id_bytes: usize,
}

impl Default for IndexRunLimits {
    fn default() -> Self {
        Self {
            // The physical v02 run envelope is 8 MiB and adds an authenticated
            // header plus framing around these plaintext bytes.
            max_total_bytes: 7 * 1024 * 1024,
            max_frame_bytes: 1024 * 1024 - 1024,
            max_record_bytes: 16 * 1024,
            max_containers: 4_096,
            max_mutations: 65_536,
            max_path_bytes: 1_024,
            max_key_id_bytes: 256,
            max_object_id_bytes: 1_024,
            max_version_id_bytes: 1_024,
        }
    }
}

/// Raw fixed-width blind index key used by the v02 wire format.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IndexBlindKey([u8; 32]);

impl IndexBlindKey {
    /// Creates a key from its raw PRF output.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw PRF output.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Converts the raw key to the legacy lowercase-hex typed boundary.
    pub fn to_blind_index_key(self) -> Result<BlindIndexKey, IndexRunError> {
        let mut encoded = String::with_capacity(64);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in self.0 {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        BlindIndexKey::new(encoded).map_err(|_| IndexRunError::InvalidValue { field: "blind key" })
    }
}

impl fmt::Debug for IndexBlindKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IndexBlindKey(<redacted>)")
    }
}

impl TryFrom<&BlindIndexKey> for IndexBlindKey {
    type Error = IndexRunError;

    fn try_from(value: &BlindIndexKey) -> Result<Self, Self::Error> {
        let encoded = value.as_str().as_bytes();
        if encoded.len() != 64 {
            return Err(IndexRunError::InvalidValue { field: "blind key" });
        }

        let mut bytes = [0_u8; 32];
        for (index, pair) in encoded.chunks_exact(2).enumerate() {
            let high = decode_lower_hex(pair[0])
                .ok_or(IndexRunError::InvalidValue { field: "blind key" })?;
            let low = decode_lower_hex(pair[1])
                .ok_or(IndexRunError::InvalidValue { field: "blind key" })?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }
}

fn decode_lower_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Exact external payload-pack container referenced by compact pointers.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct IndexRunContainer {
    /// Opaque backend object identifier.
    pub object_id: BackendObjectId,
    /// Exact provider version, when the provider supplies version identifiers.
    pub version_id: Option<BackendVersionId>,
    /// Stored object length used to constrain range reads.
    pub stored_len: u64,
    /// Signed commit body digest authenticating every declared section.
    pub commit_body_digest: [u8; 32],
    /// Historical encrypted-keyring envelope needed to reconstruct payload AEAD context.
    pub keyring_envelope: IndexRunKeyringRef,
    /// Absolute byte offset of the payload-pack section in the stored object.
    pub pack_section_offset: u64,
    /// Section ordinal bound into payload-pack record and directory authentication.
    pub pack_section_ordinal: u32,
    /// Stored byte length of the payload-pack section.
    pub pack_section_len: u64,
    /// Random identity bound into every payload-pack AEAD operation.
    pub pack_id: [u8; 32],
    /// Historical content-encryption key needed to open payload records.
    pub content_key_id: KeyId,
    /// Authenticated number of records in the payload-pack directory.
    pub pack_record_count: u32,
}

/// Exact external streamed-payload container referenced by compact pointers.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct IndexRunStreamContainer {
    /// Opaque backend object identifier of the containing commit.
    pub object_id: BackendObjectId,
    /// Exact provider version, when the provider supplies version identifiers.
    pub version_id: Option<BackendVersionId>,
    /// Stored commit length used to constrain range reads.
    pub stored_len: u64,
    /// Signed commit body digest authenticating every declared section.
    pub commit_body_digest: [u8; 32],
    /// Historical encrypted-keyring envelope selected by the containing commit.
    pub keyring_envelope: IndexRunKeyringRef,
    /// Absolute byte offset where the commit's section region begins.
    pub sections_start: u64,
    /// Ordinal of the streamed payload section in the containing commit.
    pub payload_section_ordinal: u32,
    /// Byte offset of the payload relative to the commit's section region.
    pub payload_section_offset: u64,
    /// Exact stored byte length of the streamed payload section.
    pub payload_section_len: u64,
    /// Signed digest of the complete streamed payload section.
    pub payload_section_digest: [u8; 32],
    /// Opaque identity bound into every streamed-payload AEAD operation.
    pub payload_id: BackendObjectId,
    /// Authenticated header facts needed for direct range reads.
    pub payload_header: PayloadHeaderReference,
}

/// Exact standalone streamed-payload object referenced by compact pointers.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct IndexRunStandaloneStreamContainer {
    /// Opaque backend object identifier of the standalone payload.
    pub object_id: BackendObjectId,
    /// Exact provider version, when the provider supplies version identifiers.
    pub version_id: Option<BackendVersionId>,
    /// Exact stored length used to constrain reads.
    pub stored_len: u64,
    /// Digest of the complete standalone ciphertext object.
    pub object_digest: [u8; 32],
    /// Historical encrypted-keyring envelope selected when the payload was sealed.
    pub keyring_envelope: IndexRunKeyringRef,
    /// Authenticated header facts needed for direct range reads.
    pub payload_header: PayloadHeaderReference,
}

impl fmt::Debug for IndexRunStandaloneStreamContainer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IndexRunStandaloneStreamContainer")
            .field("object_id", &self.object_id)
            .field("version_id", &self.version_id)
            .field("stored_len", &self.stored_len)
            .field("object_digest", &"<redacted>")
            .field("keyring_envelope", &self.keyring_envelope)
            .field("payload_header", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for IndexRunStreamContainer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IndexRunStreamContainer")
            .field("object_id", &self.object_id)
            .field("version_id", &self.version_id)
            .field("stored_len", &self.stored_len)
            .field("commit_body_digest", &"<redacted>")
            .field("keyring_envelope", &self.keyring_envelope)
            .field("sections_start", &self.sections_start)
            .field("payload_section_ordinal", &self.payload_section_ordinal)
            .field("payload_section_offset", &self.payload_section_offset)
            .field("payload_section_len", &self.payload_section_len)
            .field("payload_section_digest", &"<redacted>")
            .field("payload_id", &self.payload_id)
            .field("payload_header", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for IndexRunContainer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IndexRunContainer")
            .field("object_id", &self.object_id)
            .field("version_id", &self.version_id)
            .field("stored_len", &self.stored_len)
            .field("commit_body_digest", &"<redacted>")
            .field("keyring_envelope", &self.keyring_envelope)
            .field("pack_section_offset", &self.pack_section_offset)
            .field("pack_section_ordinal", &self.pack_section_ordinal)
            .field("pack_section_len", &self.pack_section_len)
            .field("pack_id", &"<redacted>")
            .field("content_key_id", &self.content_key_id)
            .field("pack_record_count", &self.pack_record_count)
            .finish()
    }
}

/// Historical encrypted-keyring envelope facts bound into a payload pack's AEAD context.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct IndexRunKeyringRef {
    /// Exact backend object identifier of the encrypted keyring envelope.
    pub object_id: BackendObjectId,
    /// SHA-256 digest of the encrypted keyring envelope.
    pub digest: [u8; 32],
}

impl fmt::Debug for IndexRunKeyringRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IndexRunKeyringRef")
            .field("object_id", &self.object_id)
            .field("digest", &"<redacted>")
            .finish()
    }
}

/// Shared facts for the payload pack carried by the same commit as an index run.
#[derive(Clone, PartialEq, Eq)]
pub struct IndexRunSelfPack {
    /// Random identity bound into every payload-pack AEAD operation.
    pub pack_id: [u8; 32],
    /// Historical content-encryption key needed to open payload records.
    pub content_key_id: KeyId,
    /// Exact stored payload-pack section length.
    pub stored_len: u64,
    /// Authenticated number of records in the pack.
    pub record_count: u32,
}

/// Shared facts for a streamed payload carried by the same commit as an index run.
#[derive(Clone, PartialEq, Eq)]
pub struct IndexRunSelfStream {
    /// Ordinal of the streamed payload section in the containing commit.
    pub payload_section_ordinal: u32,
    /// Opaque identity bound into every streamed-payload AEAD operation.
    pub payload_id: BackendObjectId,
    /// Authenticated header facts needed for direct range reads.
    pub payload_header: PayloadHeaderReference,
}

impl fmt::Debug for IndexRunSelfStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IndexRunSelfStream")
            .field("payload_section_ordinal", &self.payload_section_ordinal)
            .field("payload_id", &self.payload_id)
            .field("payload_header", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for IndexRunSelfPack {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IndexRunSelfPack")
            .field("pack_id", &"<redacted>")
            .field("content_key_id", &self.content_key_id)
            .field("stored_len", &self.stored_len)
            .field("record_count", &self.record_count)
            .finish()
    }
}

/// Exact compact facts needed to read and authenticate one payload-pack record.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct IndexPackRecordPointer {
    /// Logical directory ordinal of the payload record.
    pub record_ordinal: u32,
    /// Absolute ciphertext offset from the start of the payload-pack section.
    pub physical_offset: u32,
}

impl fmt::Debug for IndexPackRecordPointer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IndexPackRecordPointer")
            .field("record_ordinal", &self.record_ordinal)
            .field("physical_offset", &self.physical_offset)
            .finish()
    }
}

/// Compact location of an encrypted payload-pack record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IndexPayloadPointer {
    /// No payload bytes exist for an empty logical object.
    Empty,
    /// Record in the payload pack carried by the same commit as this run.
    SelfPack {
        /// Exact record read and authentication facts.
        record: IndexPackRecordPointer,
    },
    /// Record in an exact external payload-pack container.
    ExternalPack {
        /// Ordinal into [`IndexRun::containers`].
        container_ordinal: u32,
        /// Exact record read and authentication facts.
        record: IndexPackRecordPointer,
    },
    /// Streamed payload carried by the same commit as this run.
    SelfStream,
    /// Streamed payload in an exact external commit container.
    ExternalStream {
        /// Ordinal into [`IndexRun::stream_containers`].
        container_ordinal: u32,
    },
    /// Streamed payload in an exact standalone object.
    ExternalStandaloneStream {
        /// Ordinal into [`IndexRun::standalone_stream_containers`].
        container_ordinal: u32,
    },
}

/// One live namespace mutation.
#[derive(Clone, PartialEq, Eq)]
pub struct IndexUpsert {
    /// Mutation ordinal, canonical and zero-based within the run.
    pub mutation_ordinal: u32,
    /// Raw namespace PRF output.
    pub blind_key: IndexBlindKey,
    /// Namespace key that produced `blind_key`.
    pub namespace_key_id: KeyId,
    /// Trusted plaintext path. The codec stores it once.
    pub path: LogicalPath,
    /// Logical object generation.
    pub generation: Sequence,
    /// Compact payload-pack record pointer.
    pub payload: IndexPayloadPointer,
    /// Client-visible plaintext content length.
    pub content_len: u64,
    /// Last modification time in milliseconds since the Unix epoch.
    pub modified_at_ms: i64,
    /// Effective retention policy, when present.
    pub retention: Option<RetentionPolicy>,
    /// Effective legal-hold state, when present.
    pub legal_hold: Option<LegalHoldStatus>,
}

impl fmt::Debug for IndexUpsert {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IndexUpsert")
            .field("mutation_ordinal", &self.mutation_ordinal)
            .field("blind_key", &self.blind_key)
            .field("namespace_key_id", &self.namespace_key_id)
            .field("path", &"<redacted>")
            .field("generation", &self.generation)
            .field("payload", &self.payload)
            .field("content_len", &self.content_len)
            .field("modified_at_ms", &self.modified_at_ms)
            .field("retention", &self.retention)
            .field("legal_hold", &self.legal_hold)
            .finish()
    }
}

/// One deleted namespace mutation.
#[derive(Clone, PartialEq, Eq)]
pub struct IndexTombstone {
    /// Mutation ordinal, canonical and zero-based within the run.
    pub mutation_ordinal: u32,
    /// Raw namespace PRF output being hidden.
    pub blind_key: IndexBlindKey,
    /// Namespace key that produced `blind_key`.
    pub namespace_key_id: KeyId,
    /// Trusted plaintext path. The codec stores it once.
    pub path: LogicalPath,
    /// Logical deletion generation.
    pub generation: Sequence,
}

impl fmt::Debug for IndexTombstone {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IndexTombstone")
            .field("mutation_ordinal", &self.mutation_ordinal)
            .field("blind_key", &self.blind_key)
            .field("namespace_key_id", &self.namespace_key_id)
            .field("path", &"<redacted>")
            .field("generation", &self.generation)
            .finish()
    }
}

/// A canonical mutation in an index run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexMutation {
    /// Insert or supersede a namespace value.
    Upsert(IndexUpsert),
    /// Hide an older namespace value.
    Tombstone(IndexTombstone),
}

impl IndexMutation {
    /// Returns the canonical zero-based mutation ordinal.
    pub const fn ordinal(&self) -> u32 {
        match self {
            Self::Upsert(upsert) => upsert.mutation_ordinal,
            Self::Tombstone(tombstone) => tombstone.mutation_ordinal,
        }
    }
}

/// Canonical bounded plaintext index run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexRun {
    /// Repository sequence represented by this batch.
    pub sequence: Sequence,
    /// Exact shared facts for the payload pack carried by this run's commit.
    pub self_pack: Option<IndexRunSelfPack>,
    /// Exact shared facts for a streamed payload carried by this run's commit.
    pub self_stream: Option<IndexRunSelfStream>,
    /// Deduplicated exact external payload-pack containers.
    pub containers: Vec<IndexRunContainer>,
    /// Deduplicated exact external streamed-payload containers.
    pub stream_containers: Vec<IndexRunStreamContainer>,
    /// Deduplicated exact standalone streamed-payload objects.
    pub standalone_stream_containers: Vec<IndexRunStandaloneStreamContainer>,
    /// Canonically ordered namespace mutations.
    pub mutations: Vec<IndexMutation>,
}

/// Semantic role of one independently authenticated index-run frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexRunFrameRole {
    /// Run metadata and the canonical external-container table.
    Metadata,
    /// Namespace records ordered by blind key and mutation ordinal.
    Namespace,
    /// Listing records ordered by path bytes and mutation ordinal.
    Listing,
}

/// Inclusive search bound advertised for a projection frame.
#[derive(Clone, PartialEq, Eq)]
pub enum IndexRunSearchBound {
    /// Namespace projection key.
    Namespace {
        /// Raw namespace PRF output.
        blind_key: IndexBlindKey,
        /// Mutation ordinal used as the canonical tie breaker.
        mutation_ordinal: u32,
    },
    /// Listing projection key.
    Listing {
        /// Trusted plaintext path.
        path: LogicalPath,
        /// Mutation ordinal used as the canonical tie breaker.
        mutation_ordinal: u32,
    },
}

impl fmt::Debug for IndexRunSearchBound {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Namespace {
                blind_key,
                mutation_ordinal,
            } => formatter
                .debug_struct("Namespace")
                .field("blind_key", blind_key)
                .field("mutation_ordinal", mutation_ordinal)
                .finish(),
            Self::Listing {
                mutation_ordinal, ..
            } => formatter
                .debug_struct("Listing")
                .field("path", &"<redacted>")
                .field("mutation_ordinal", mutation_ordinal)
                .finish(),
        }
    }
}

/// One canonical plaintext frame ready for independent outer authentication.
#[derive(Clone, PartialEq, Eq)]
pub struct EncodedIndexRunFrame {
    /// Semantic frame role.
    pub role: IndexRunFrameRole,
    /// Zero-based frame ordinal within this role.
    pub role_ordinal: u32,
    /// Number of records carried by the frame.
    pub record_count: u32,
    /// First projection search key, absent for metadata.
    pub first_bound: Option<IndexRunSearchBound>,
    /// Last projection search key, absent for metadata.
    pub last_bound: Option<IndexRunSearchBound>,
    /// Canonical frame plaintext.
    pub bytes: Vec<u8>,
}

impl fmt::Debug for EncodedIndexRunFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodedIndexRunFrame")
            .field("role", &self.role)
            .field("role_ordinal", &self.role_ordinal)
            .field("record_count", &self.record_count)
            .field("first_bound", &self.first_bound)
            .field("last_bound", &self.last_bound)
            .field("plaintext_len", &self.bytes.len())
            .finish()
    }
}

/// Canonical independently decodable plaintext frames for one logical run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedIndexRun {
    /// Frames in metadata, namespace, then listing role order.
    pub frames: Vec<EncodedIndexRunFrame>,
}

/// Canonical index-run encoding or validation error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexRunError {
    /// The input does not start with the index-run domain.
    InvalidDomain,
    /// The encoded wire version is unsupported.
    UnsupportedVersion(u16),
    /// The input ended before a declared value was complete.
    UnexpectedEof,
    /// Bytes remained after the canonical run ended.
    TrailingBytes,
    /// An integer used a longer varint representation than necessary.
    NonCanonicalVarint,
    /// An encoded integer cannot be represented by the target type.
    IntegerOverflow,
    /// A byte or record limit was exceeded.
    LimitExceeded {
        /// Name of the bounded field.
        field: &'static str,
        /// Observed value.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// A string was not valid UTF-8.
    InvalidUtf8 {
        /// Name of the invalid field.
        field: &'static str,
    },
    /// A strong type rejected the decoded value.
    InvalidValue {
        /// Name of the invalid field.
        field: &'static str,
    },
    /// A closed wire enum contained an unknown tag.
    InvalidTag {
        /// Name of the tagged field.
        field: &'static str,
        /// Unknown tag value.
        value: u8,
    },
    /// A length-delimited record was not consumed exactly.
    RecordLengthMismatch,
    /// Mutation ordinals were duplicated, skipped, or out of order.
    InvalidMutationOrdinal {
        /// Required ordinal at this position.
        expected: u32,
        /// Encoded ordinal.
        actual: u32,
    },
    /// Two container-table entries name the same exact object.
    DuplicateContainer,
    /// Container-table entries are not in canonical exact-object order.
    InvalidContainerOrder,
    /// A declared payload-pack record count is zero or disagrees with use.
    InvalidPackRecordCount,
    /// A compact record pointer falls outside its exact payload pack.
    InvalidPackRecordRange,
    /// Repeated facts for the same logical payload-pack record disagree.
    PackRecordFactsMismatch,
    /// A container-table entry is not referenced by any namespace mutation.
    UnusedContainer(u32),
    /// A streamed-container-table entry is not referenced by any namespace mutation.
    UnusedStreamContainer(u32),
    /// A standalone-stream table entry is not referenced by any namespace mutation.
    UnusedStandaloneStreamContainer(u32),
    /// Namespace-key table entries are not in canonical order.
    InvalidNamespaceKeyOrder,
    /// A namespace-key table entry is repeated.
    DuplicateNamespaceKey,
    /// A namespace-key table entry is not referenced by any mutation.
    UnusedNamespaceKey(u32),
    /// A namespace mutation references no namespace-key table entry.
    InvalidNamespaceKeyOrdinal(u32),
    /// A payload-pack section is empty or falls outside its containing object.
    InvalidContainerRange,
    /// A streamed payload section or its authenticated header facts are invalid.
    InvalidStreamContainer,
    /// A standalone streamed payload or its authenticated header facts are invalid.
    InvalidStandaloneStreamContainer,
    /// A self-stream declaration is unused, absent when referenced, or conflicts with a self pack.
    InvalidSelfStream,
    /// A payload pointer references no container-table entry.
    InvalidContainerOrdinal(u32),
    /// Empty payload pointers and logical content lengths disagree.
    InvalidEmptyPayload,
    /// Namespace and listing projection record counts differ.
    ProjectionCountMismatch {
        /// Number of namespace projection records.
        namespace: usize,
        /// Number of listing projection records.
        listing: usize,
    },
    /// A projection is not in its required canonical sort order.
    InvalidProjectionOrder {
        /// Name of the malformed projection.
        projection: &'static str,
    },
    /// A projection repeats a mutation ordinal.
    DuplicateProjectionOrdinal {
        /// Name of the malformed projection.
        projection: &'static str,
        /// Repeated ordinal.
        ordinal: u32,
    },
    /// A projection contains an ordinal outside its declared record count.
    InvalidProjectionOrdinal {
        /// Name of the malformed projection.
        projection: &'static str,
        /// Out-of-range ordinal.
        ordinal: u32,
    },
    /// Namespace and listing facts disagree for a mutation ordinal.
    ProjectionMismatch {
        /// Ordinal whose projection facts disagree.
        ordinal: u32,
    },
    /// Index-run frames are absent, out of role order, or skip a role ordinal.
    InvalidFrameOrder,
    /// Immutable facts repeated in different frames disagree.
    FrameFactsMismatch,
}

impl fmt::Display for IndexRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDomain => formatter.write_str("invalid index-run domain"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported index-run version {version}")
            }
            Self::UnexpectedEof => formatter.write_str("truncated index run"),
            Self::TrailingBytes => formatter.write_str("trailing bytes after index run"),
            Self::NonCanonicalVarint => formatter.write_str("non-canonical varint"),
            Self::IntegerOverflow => formatter.write_str("encoded integer overflow"),
            Self::LimitExceeded {
                field,
                actual,
                maximum,
            } => write!(formatter, "{field} exceeds limit ({actual} > {maximum})"),
            Self::InvalidUtf8 { field } => write!(formatter, "{field} is not valid UTF-8"),
            Self::InvalidValue { field } => write!(formatter, "invalid {field}"),
            Self::InvalidTag { field, value } => {
                write!(formatter, "invalid {field} tag {value}")
            }
            Self::RecordLengthMismatch => formatter.write_str("record length mismatch"),
            Self::InvalidMutationOrdinal { expected, actual } => write!(
                formatter,
                "invalid mutation ordinal {actual}, expected {expected}"
            ),
            Self::DuplicateContainer => formatter.write_str("duplicate index-run container"),
            Self::InvalidContainerOrder => {
                formatter.write_str("index-run containers are not canonically ordered")
            }
            Self::InvalidPackRecordCount => {
                formatter.write_str("invalid payload-pack record count")
            }
            Self::InvalidPackRecordRange => {
                formatter.write_str("invalid payload-pack record range")
            }
            Self::PackRecordFactsMismatch => {
                formatter.write_str("payload-pack record facts disagree")
            }
            Self::UnusedContainer(ordinal) => {
                write!(formatter, "unused container ordinal {ordinal}")
            }
            Self::UnusedStreamContainer(ordinal) => {
                write!(formatter, "unused stream container ordinal {ordinal}")
            }
            Self::UnusedStandaloneStreamContainer(ordinal) => {
                write!(
                    formatter,
                    "unused standalone stream container ordinal {ordinal}"
                )
            }
            Self::InvalidNamespaceKeyOrder => {
                formatter.write_str("namespace key table is not canonically ordered")
            }
            Self::DuplicateNamespaceKey => {
                formatter.write_str("duplicate namespace key table entry")
            }
            Self::UnusedNamespaceKey(ordinal) => {
                write!(formatter, "unused namespace key ordinal {ordinal}")
            }
            Self::InvalidNamespaceKeyOrdinal(ordinal) => {
                write!(formatter, "invalid namespace key ordinal {ordinal}")
            }
            Self::InvalidContainerRange => {
                formatter.write_str("invalid payload-pack section range")
            }
            Self::InvalidStreamContainer => {
                formatter.write_str("invalid streamed payload container")
            }
            Self::InvalidStandaloneStreamContainer => {
                formatter.write_str("invalid standalone streamed payload container")
            }
            Self::InvalidSelfStream => formatter.write_str("invalid self streamed payload"),
            Self::InvalidContainerOrdinal(ordinal) => {
                write!(formatter, "invalid container ordinal {ordinal}")
            }
            Self::InvalidEmptyPayload => {
                formatter.write_str("empty payload and content length disagree")
            }
            Self::ProjectionCountMismatch { namespace, listing } => write!(
                formatter,
                "projection record counts differ ({namespace} namespace, {listing} listing)"
            ),
            Self::InvalidProjectionOrder { projection } => {
                write!(
                    formatter,
                    "{projection} projection is not canonically sorted"
                )
            }
            Self::DuplicateProjectionOrdinal {
                projection,
                ordinal,
            } => write!(
                formatter,
                "{projection} projection repeats ordinal {ordinal}"
            ),
            Self::InvalidProjectionOrdinal {
                projection,
                ordinal,
            } => write!(
                formatter,
                "{projection} projection has invalid ordinal {ordinal}"
            ),
            Self::ProjectionMismatch { ordinal } => {
                write!(formatter, "projection facts disagree for ordinal {ordinal}")
            }
            Self::InvalidFrameOrder => formatter.write_str("invalid index-run frame order"),
            Self::FrameFactsMismatch => formatter.write_str("index-run frame facts disagree"),
        }
    }
}

impl std::error::Error for IndexRunError {}

/// Encodes a length-prefixed bundle of canonical frames for tests and tooling.
///
/// Repository writes should pass the frames returned by
/// [`encode_index_run_frames`] directly to the authenticated outer framing
/// layer instead of storing this convenience bundle.
pub fn encode_index_run(run: &IndexRun, limits: &IndexRunLimits) -> Result<Vec<u8>, IndexRunError> {
    let encoded = encode_index_run_frames(run, limits)?;
    let mut writer = Writer::new(limits.max_total_bytes);
    writer.varint(usize_to_u64(encoded.frames.len())?)?;
    for frame in encoded.frames {
        let mut record = Writer::new(limits.max_frame_bytes);
        record.bytes(&frame.bytes)?;
        writer.record(record)?;
    }
    Ok(writer.finish())
}

/// Encodes independently authenticatable, bounded frames for a canonical run.
pub fn encode_index_run_frames(
    run: &IndexRun,
    limits: &IndexRunLimits,
) -> Result<EncodedIndexRun, IndexRunError> {
    let container_count = run
        .containers
        .len()
        .checked_add(run.stream_containers.len())
        .and_then(|count| count.checked_add(run.standalone_stream_containers.len()))
        .ok_or(IndexRunError::IntegerOverflow)?;
    validate_count("container count", container_count, limits.max_containers)?;
    validate_count("mutation count", run.mutations.len(), limits.max_mutations)?;
    validate_self_pack(run.self_pack.as_ref(), limits)?;
    validate_self_stream(run.self_stream.as_ref(), limits)?;
    if run.self_pack.is_some() && run.self_stream.is_some() {
        return Err(IndexRunError::InvalidSelfStream);
    }
    let self_payload = match (run.self_pack.as_ref(), run.self_stream.as_ref()) {
        (None, None) => IndexRunSelfPayload::None,
        (Some(pack), None) => IndexRunSelfPayload::Pack(pack),
        (None, Some(stream)) => IndexRunSelfPayload::Stream(stream),
        (Some(_), Some(_)) => return Err(IndexRunError::InvalidSelfStream),
    };
    validate_containers(&run.containers, limits)?;
    validate_stream_containers(&run.stream_containers, limits)?;
    validate_standalone_stream_containers(&run.standalone_stream_containers, limits)?;
    validate_distinct_container_objects(
        &run.containers,
        &run.stream_containers,
        &run.standalone_stream_containers,
    )?;
    validate_mutations(run, limits)?;

    let namespace_key_ids = run
        .mutations
        .iter()
        .map(mutation_namespace_key_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    validate_count(
        "namespace key count",
        namespace_key_ids.len(),
        limits.max_mutations,
    )?;

    let metadata_count = container_count
        .checked_add(namespace_key_ids.len())
        .ok_or(IndexRunError::IntegerOverflow)?;
    let mut metadata = Vec::with_capacity(metadata_count);
    for container in &run.containers {
        let mut record = Writer::new(limits.max_record_bytes);
        record.u8(0)?;
        encode_exact_container(
            &mut record,
            &container.object_id,
            container.version_id.as_ref(),
            container.stored_len,
            &container.commit_body_digest,
            &container.keyring_envelope,
            limits,
        )?;
        record.u32(container.pack_section_ordinal)?;
        record.u64(container.pack_section_offset)?;
        record.u64(container.pack_section_len)?;
        record.bytes(&container.pack_id)?;
        record.string(
            container.content_key_id.as_str(),
            limits.max_key_id_bytes,
            "content key id",
        )?;
        record.varint(u64::from(container.pack_record_count))?;
        metadata.push(PreparedRecord::metadata(record.finish()));
    }
    for container in &run.stream_containers {
        let mut record = Writer::new(limits.max_record_bytes);
        record.u8(1)?;
        encode_exact_container(
            &mut record,
            &container.object_id,
            container.version_id.as_ref(),
            container.stored_len,
            &container.commit_body_digest,
            &container.keyring_envelope,
            limits,
        )?;
        record.u64(container.sections_start)?;
        record.u32(container.payload_section_ordinal)?;
        record.u64(container.payload_section_offset)?;
        record.u64(container.payload_section_len)?;
        record.bytes(&container.payload_section_digest)?;
        record.string(
            container.payload_id.as_str(),
            limits.max_object_id_bytes,
            "payload id",
        )?;
        encode_payload_header(&mut record, &container.payload_header)?;
        metadata.push(PreparedRecord::metadata(record.finish()));
    }
    for container in &run.standalone_stream_containers {
        let mut record = Writer::new(limits.max_record_bytes);
        record.u8(2)?;
        encode_exact_container(
            &mut record,
            &container.object_id,
            container.version_id.as_ref(),
            container.stored_len,
            &container.object_digest,
            &container.keyring_envelope,
            limits,
        )?;
        encode_payload_header(&mut record, &container.payload_header)?;
        metadata.push(PreparedRecord::metadata(record.finish()));
    }
    for namespace_key_id in &namespace_key_ids {
        let mut record = Writer::new(limits.max_record_bytes);
        record.u8(3)?;
        record.string(
            namespace_key_id.as_str(),
            limits.max_key_id_bytes,
            "namespace key id",
        )?;
        metadata.push(PreparedRecord::metadata(record.finish()));
    }

    let mut namespace_order: Vec<_> = run.mutations.iter().collect();
    namespace_order.sort_by(|left, right| {
        mutation_blind_key(left)
            .cmp(&mutation_blind_key(right))
            .then_with(|| left.ordinal().cmp(&right.ordinal()))
    });
    let mut namespace = Vec::with_capacity(namespace_order.len());
    for mutation in namespace_order {
        let mut record = Writer::new(limits.max_record_bytes);
        record.varint(u64::from(mutation.ordinal()))?;
        match mutation {
            IndexMutation::Upsert(upsert) => {
                record.u8(0)?;
                record.bytes(upsert.blind_key.as_bytes())?;
                record.varint(namespace_key_ordinal(
                    &namespace_key_ids,
                    &upsert.namespace_key_id,
                )?)?;
                record.varint(upsert.generation.get())?;
                encode_payload_pointer(&mut record, upsert.payload)?;
                record.varint(upsert.content_len)?;
                record.i64(upsert.modified_at_ms)?;
                encode_retention(&mut record, upsert.retention)?;
                encode_legal_hold(&mut record, upsert.legal_hold)?;
            }
            IndexMutation::Tombstone(tombstone) => {
                record.u8(1)?;
                record.bytes(tombstone.blind_key.as_bytes())?;
                record.varint(namespace_key_ordinal(
                    &namespace_key_ids,
                    &tombstone.namespace_key_id,
                )?)?;
                record.varint(tombstone.generation.get())?;
            }
        }
        namespace.push(PreparedRecord {
            bytes: record.finish(),
            bound: Some(IndexRunSearchBound::Namespace {
                blind_key: mutation_blind_key(mutation),
                mutation_ordinal: mutation.ordinal(),
            }),
        });
    }

    let mut listing_order: Vec<_> = run.mutations.iter().collect();
    listing_order.sort_by(|left, right| {
        mutation_path(left)
            .as_str()
            .as_bytes()
            .cmp(mutation_path(right).as_str().as_bytes())
            .then_with(|| left.ordinal().cmp(&right.ordinal()))
    });
    let mut listing = Vec::with_capacity(listing_order.len());
    for mutation in listing_order {
        let mut record = Writer::new(limits.max_record_bytes);
        record.varint(u64::from(mutation.ordinal()))?;
        match mutation {
            IndexMutation::Upsert(upsert) => {
                record.u8(0)?;
                record.string(upsert.path.as_str(), limits.max_path_bytes, "logical path")?;
                record.varint(upsert.generation.get())?;
                record.varint(upsert.content_len)?;
                record.i64(upsert.modified_at_ms)?;
            }
            IndexMutation::Tombstone(tombstone) => {
                record.u8(1)?;
                record.string(
                    tombstone.path.as_str(),
                    limits.max_path_bytes,
                    "logical path",
                )?;
                record.varint(tombstone.generation.get())?;
            }
        }
        listing.push(PreparedRecord {
            bytes: record.finish(),
            bound: Some(IndexRunSearchBound::Listing {
                path: mutation_path(mutation).clone(),
                mutation_ordinal: mutation.ordinal(),
            }),
        });
    }

    let mutation_count =
        u32::try_from(run.mutations.len()).map_err(|_| IndexRunError::IntegerOverflow)?;
    let mut frames = pack_prepared_frames(
        IndexRunFrameRole::Metadata,
        run.sequence,
        mutation_count,
        self_payload,
        namespace_key_ids.len(),
        &metadata,
        limits,
    )?;
    frames.extend(pack_prepared_frames(
        IndexRunFrameRole::Namespace,
        run.sequence,
        mutation_count,
        self_payload,
        namespace_key_ids.len(),
        &namespace,
        limits,
    )?);
    frames.extend(pack_prepared_frames(
        IndexRunFrameRole::Listing,
        run.sequence,
        mutation_count,
        self_payload,
        namespace_key_ids.len(),
        &listing,
        limits,
    )?);
    let total = frames.iter().try_fold(0_usize, |total, frame| {
        total
            .checked_add(frame.bytes.len())
            .ok_or(IndexRunError::IntegerOverflow)
    })?;
    validate_count("total frame bytes", total, limits.max_total_bytes)?;
    Ok(EncodedIndexRun { frames })
}

struct PreparedRecord {
    bytes: Vec<u8>,
    bound: Option<IndexRunSearchBound>,
}

impl PreparedRecord {
    fn metadata(bytes: Vec<u8>) -> Self {
        Self { bytes, bound: None }
    }
}

#[derive(Clone, Copy)]
enum IndexRunSelfPayload<'a> {
    None,
    Pack(&'a IndexRunSelfPack),
    Stream(&'a IndexRunSelfStream),
}

fn pack_prepared_frames(
    role: IndexRunFrameRole,
    sequence: Sequence,
    mutation_count: u32,
    self_payload: IndexRunSelfPayload<'_>,
    namespace_key_count: usize,
    records: &[PreparedRecord],
    limits: &IndexRunLimits,
) -> Result<Vec<EncodedIndexRunFrame>, IndexRunError> {
    if records.is_empty() && role != IndexRunFrameRole::Metadata {
        return Ok(Vec::new());
    }
    let mut frames = Vec::new();
    let mut start = 0_usize;
    loop {
        let mut end = start;
        let mut payload_len = 0_usize;
        while let Some(record) = records.get(end) {
            let framed_len = varint_len(usize_to_u64(record.bytes.len())?)
                .checked_add(record.bytes.len())
                .ok_or(IndexRunError::IntegerOverflow)?;
            let candidate_payload = payload_len
                .checked_add(framed_len)
                .ok_or(IndexRunError::IntegerOverflow)?;
            let candidate_count = end - start + 1;
            if frame_header_len(
                role,
                records.len(),
                candidate_count,
                self_payload,
                namespace_key_count,
            )?
            .checked_add(candidate_payload)
            .ok_or(IndexRunError::IntegerOverflow)?
                > limits.max_frame_bytes
            {
                break;
            }
            payload_len = candidate_payload;
            end += 1;
        }
        if end == start && !records.is_empty() {
            return Err(IndexRunError::LimitExceeded {
                field: "frame bytes",
                actual: limits.max_frame_bytes.saturating_add(1),
                maximum: limits.max_frame_bytes,
            });
        }
        let role_ordinal =
            u32::try_from(frames.len()).map_err(|_| IndexRunError::IntegerOverflow)?;
        let frame_records = &records[start..end];
        let mut writer = Writer::new(limits.max_frame_bytes);
        encode_frame_header(
            &mut writer,
            &FrameEncodingFacts {
                role,
                role_ordinal,
                sequence,
                mutation_count,
                role_record_count: records.len(),
                frame_record_count: frame_records.len(),
                self_payload,
                namespace_key_count,
            },
        )?;
        for record in frame_records {
            let mut encoded_record = Writer::new(limits.max_record_bytes);
            encoded_record.bytes(&record.bytes)?;
            writer.record(encoded_record)?;
        }
        frames.push(EncodedIndexRunFrame {
            role,
            role_ordinal,
            record_count: u32::try_from(frame_records.len())
                .map_err(|_| IndexRunError::IntegerOverflow)?,
            first_bound: frame_records
                .first()
                .and_then(|record| record.bound.clone()),
            last_bound: frame_records.last().and_then(|record| record.bound.clone()),
            bytes: writer.finish(),
        });
        if end == records.len() {
            break;
        }
        start = end;
    }
    Ok(frames)
}

struct FrameEncodingFacts<'a> {
    role: IndexRunFrameRole,
    role_ordinal: u32,
    sequence: Sequence,
    mutation_count: u32,
    role_record_count: usize,
    frame_record_count: usize,
    self_payload: IndexRunSelfPayload<'a>,
    namespace_key_count: usize,
}

fn encode_frame_header(
    writer: &mut Writer,
    facts: &FrameEncodingFacts<'_>,
) -> Result<(), IndexRunError> {
    writer.bytes(INDEX_RUN_PLAINTEXT_DOMAIN)?;
    writer.u16(INDEX_RUN_WIRE_VERSION)?;
    writer.u8(frame_role_tag(facts.role))?;
    writer.u32(facts.role_ordinal)?;
    writer.u64(facts.sequence.get())?;
    writer.varint(u64::from(facts.mutation_count))?;
    writer.varint(usize_to_u64(facts.role_record_count)?)?;
    writer.varint(usize_to_u64(facts.frame_record_count)?)?;
    if facts.role == IndexRunFrameRole::Metadata {
        match facts.self_payload {
            IndexRunSelfPayload::None => writer.u8(0)?,
            IndexRunSelfPayload::Pack(pack) => {
                writer.u8(1)?;
                writer.bytes(&pack.pack_id)?;
                writer.string(pack.content_key_id.as_str(), usize::MAX, "content key id")?;
                writer.u64(pack.stored_len)?;
                writer.varint(u64::from(pack.record_count))?;
            }
            IndexRunSelfPayload::Stream(stream) => {
                writer.u8(2)?;
                writer.u32(stream.payload_section_ordinal)?;
                writer.string(stream.payload_id.as_str(), usize::MAX, "payload id")?;
                encode_payload_header(writer, &stream.payload_header)?;
            }
        }
        writer.varint(usize_to_u64(facts.namespace_key_count)?)?;
    }
    Ok(())
}

fn frame_header_len(
    role: IndexRunFrameRole,
    role_record_count: usize,
    frame_record_count: usize,
    self_payload: IndexRunSelfPayload<'_>,
    namespace_key_count: usize,
) -> Result<usize, IndexRunError> {
    let base = INDEX_RUN_PLAINTEXT_DOMAIN.len() + 2 + 1 + 4 + 8 + 5;
    let mut length = base
        .checked_add(varint_len(usize_to_u64(role_record_count)?))
        .and_then(|value| value.checked_add(varint_len(usize_to_u64(frame_record_count).ok()?)))
        .ok_or(IndexRunError::IntegerOverflow)?;
    if role == IndexRunFrameRole::Metadata {
        length = length
            .checked_add(1)
            .ok_or(IndexRunError::IntegerOverflow)?;
        match self_payload {
            IndexRunSelfPayload::Pack(pack) => {
                length = length
                    .checked_add(32)
                    .and_then(|value| {
                        value.checked_add(varint_len(
                            usize_to_u64(pack.content_key_id.as_str().len()).ok()?,
                        ))
                    })
                    .and_then(|value| value.checked_add(pack.content_key_id.as_str().len()))
                    .and_then(|value| value.checked_add(8))
                    .and_then(|value| value.checked_add(varint_len(u64::from(pack.record_count))))
                    .ok_or(IndexRunError::IntegerOverflow)?;
            }
            IndexRunSelfPayload::Stream(stream) => {
                length = length
                    .checked_add(4)
                    .and_then(|value| {
                        value.checked_add(varint_len(
                            usize_to_u64(stream.payload_id.as_str().len()).ok()?,
                        ))
                    })
                    .and_then(|value| value.checked_add(stream.payload_id.as_str().len()))
                    .and_then(|value| {
                        value.checked_add(payload_header_encoded_len(&stream.payload_header).ok()?)
                    })
                    .ok_or(IndexRunError::IntegerOverflow)?;
            }
            IndexRunSelfPayload::None => {}
        }
        length = length
            .checked_add(varint_len(usize_to_u64(namespace_key_count)?))
            .ok_or(IndexRunError::IntegerOverflow)?;
    }
    Ok(length)
}

const fn frame_role_tag(role: IndexRunFrameRole) -> u8 {
    match role {
        IndexRunFrameRole::Metadata => 0,
        IndexRunFrameRole::Namespace => 1,
        IndexRunFrameRole::Listing => 2,
    }
}

fn encode_exact_container(
    writer: &mut Writer,
    object_id: &BackendObjectId,
    version_id: Option<&BackendVersionId>,
    stored_len: u64,
    object_digest: &[u8; 32],
    keyring_envelope: &IndexRunKeyringRef,
    limits: &IndexRunLimits,
) -> Result<(), IndexRunError> {
    writer.string(object_id.as_str(), limits.max_object_id_bytes, "object id")?;
    match version_id {
        None => writer.u8(0)?,
        Some(version_id) => {
            writer.u8(1)?;
            writer.string(
                version_id.as_str(),
                limits.max_version_id_bytes,
                "version id",
            )?;
        }
    }
    writer.u64(stored_len)?;
    writer.bytes(object_digest)?;
    writer.string(
        keyring_envelope.object_id.as_str(),
        limits.max_object_id_bytes,
        "keyring envelope object id",
    )?;
    writer.bytes(&keyring_envelope.digest)
}

fn encode_payload_header(
    writer: &mut Writer,
    header: &PayloadHeaderReference,
) -> Result<(), IndexRunError> {
    writer.varint(header.chunk_size)?;
    writer.varint(header.plaintext_len)?;
    writer.string(header.key_id.as_str(), usize::MAX, "content key id")?;
    writer.bytes(&header.nonce_prefix)?;
    writer.varint(header.header_len)
}

fn decode_payload_header(
    reader: &mut Reader<'_>,
    limits: &IndexRunLimits,
) -> Result<PayloadHeaderReference, IndexRunError> {
    let header = PayloadHeaderReference {
        chunk_size: reader.varint()?,
        plaintext_len: reader.varint()?,
        key_id: reader.typed_string("content key id", limits.max_key_id_bytes, KeyId::new)?,
        nonce_prefix: {
            let mut nonce_prefix = [0_u8; 16];
            nonce_prefix.copy_from_slice(reader.bytes(16)?);
            nonce_prefix
        },
        header_len: reader.varint()?,
    };
    validate_payload_header(&header, limits)?;
    Ok(header)
}

fn payload_header_encoded_len(header: &PayloadHeaderReference) -> Result<usize, IndexRunError> {
    varint_len(header.chunk_size)
        .checked_add(varint_len(header.plaintext_len))
        .and_then(|value| {
            value.checked_add(varint_len(usize_to_u64(header.key_id.as_str().len()).ok()?))
        })
        .and_then(|value| value.checked_add(header.key_id.as_str().len()))
        .and_then(|value| value.checked_add(16))
        .and_then(|value| value.checked_add(varint_len(header.header_len)))
        .ok_or(IndexRunError::IntegerOverflow)
}

/// Decodes and pairs independently authenticated index-run plaintext frames.
pub fn decode_index_run_frames<B: AsRef<[u8]>>(
    frames: &[B],
    limits: &IndexRunLimits,
) -> Result<IndexRun, IndexRunError> {
    if frames.is_empty() {
        return Err(IndexRunError::InvalidFrameOrder);
    }
    let total_bytes = frames.iter().try_fold(0_usize, |total, frame| {
        total
            .checked_add(frame.as_ref().len())
            .ok_or(IndexRunError::IntegerOverflow)
    })?;
    validate_count("total frame bytes", total_bytes, limits.max_total_bytes)?;

    let mut sequence = None;
    let mut mutation_count = None;
    let mut self_pack = None;
    let mut self_stream = None;
    let mut saw_self_payload_fact = false;
    let mut containers = Vec::new();
    let mut stream_containers = Vec::new();
    let mut standalone_stream_containers = Vec::new();
    let mut namespace_key_ids: Vec<KeyId> = Vec::new();
    let mut declared_namespace_key_count = None;
    let mut namespace: Vec<Option<NamespaceProjection>> = Vec::new();
    let mut mutations: Vec<Option<IndexMutation>> = Vec::new();
    let mut previous_container = None;
    let mut previous_stream_container = None;
    let mut previous_standalone_stream_container = None;
    let mut saw_stream_container = false;
    let mut saw_standalone_stream_container = false;
    let mut saw_namespace_key_id = false;
    let mut previous_namespace_key = None;
    let mut previous_listing_key: Option<(LogicalPath, u32)> = None;
    let mut used_containers = BTreeSet::new();
    let mut used_stream_containers = BTreeSet::new();
    let mut used_standalone_stream_containers = BTreeSet::new();
    let mut used_namespace_key_ids = BTreeSet::new();
    let mut uses_self_pack = false;
    let mut self_stream_uses = 0_usize;
    let mut expected_role = IndexRunFrameRole::Metadata;
    let mut expected_role_ordinal = 0_u32;
    let mut role_total = None;
    let mut role_seen = 0_usize;
    let mut saw_namespace = false;
    let mut saw_listing = false;

    for encoded in frames {
        validate_count(
            "frame bytes",
            encoded.as_ref().len(),
            limits.max_frame_bytes,
        )?;
        let (header, mut reader) = decode_frame_header(encoded.as_ref(), limits)?;
        if header.role != expected_role || header.role_ordinal != expected_role_ordinal {
            if frame_role_tag(header.role) != frame_role_tag(expected_role) + 1
                || header.role_ordinal != 0
                || role_seen != role_total.ok_or(IndexRunError::InvalidFrameOrder)?
            {
                return Err(IndexRunError::InvalidFrameOrder);
            }
            expected_role = header.role;
            expected_role_ordinal = 0;
            role_seen = 0;
            role_total = None;
        }
        if header.role != expected_role || header.role_ordinal != expected_role_ordinal {
            return Err(IndexRunError::InvalidFrameOrder);
        }
        expected_role_ordinal = expected_role_ordinal
            .checked_add(1)
            .ok_or(IndexRunError::IntegerOverflow)?;
        match sequence {
            None => sequence = Some(header.sequence),
            Some(value) if value == header.sequence => {}
            Some(_) => return Err(IndexRunError::FrameFactsMismatch),
        }
        match mutation_count {
            None => {
                mutation_count = Some(header.mutation_count);
                let count = usize::try_from(header.mutation_count)
                    .map_err(|_| IndexRunError::IntegerOverflow)?;
                validate_count("mutation count", count, limits.max_mutations)?;
            }
            Some(value) if value == header.mutation_count => {}
            Some(_) => return Err(IndexRunError::FrameFactsMismatch),
        }
        match role_total {
            None => role_total = Some(header.role_record_count),
            Some(value) if value == header.role_record_count => {}
            Some(_) => return Err(IndexRunError::FrameFactsMismatch),
        }
        role_seen = role_seen
            .checked_add(header.frame_record_count)
            .ok_or(IndexRunError::IntegerOverflow)?;
        if role_seen > header.role_record_count {
            return Err(IndexRunError::FrameFactsMismatch);
        }

        match header.role {
            IndexRunFrameRole::Metadata => {
                let frame_namespace_key_count = header
                    .namespace_key_count
                    .ok_or(IndexRunError::FrameFactsMismatch)?;
                if frame_namespace_key_count > header.role_record_count
                    || frame_namespace_key_count
                        > usize::try_from(header.mutation_count)
                            .map_err(|_| IndexRunError::IntegerOverflow)?
                {
                    return Err(IndexRunError::FrameFactsMismatch);
                }
                match declared_namespace_key_count {
                    None => {
                        declared_namespace_key_count = Some(frame_namespace_key_count);
                        namespace_key_ids = Vec::with_capacity(frame_namespace_key_count);
                    }
                    Some(count) if count == frame_namespace_key_count => {}
                    Some(_) => return Err(IndexRunError::FrameFactsMismatch),
                }
                let frame_self_pack = header.self_pack.ok_or(IndexRunError::FrameFactsMismatch)?;
                let frame_self_stream = header
                    .self_stream
                    .ok_or(IndexRunError::FrameFactsMismatch)?;
                if saw_self_payload_fact
                    && (self_pack != frame_self_pack || self_stream != frame_self_stream)
                {
                    return Err(IndexRunError::FrameFactsMismatch);
                }
                self_pack = frame_self_pack;
                self_stream = frame_self_stream;
                saw_self_payload_fact = true;
                for _ in 0..header.frame_record_count {
                    let mut record = reader.record(limits.max_record_bytes)?;
                    match record.u8()? {
                        0 => {
                            if saw_stream_container
                                || saw_standalone_stream_container
                                || saw_namespace_key_id
                            {
                                return Err(IndexRunError::InvalidContainerOrder);
                            }
                            validate_next_container_count(
                                &containers,
                                &stream_containers,
                                &standalone_stream_containers,
                                limits,
                            )?;
                            let container = decode_container(&mut record, limits)?;
                            let key = (container.object_id.clone(), container.version_id.clone());
                            if let Some(previous) = &previous_container {
                                if previous == &key {
                                    return Err(IndexRunError::DuplicateContainer);
                                }
                                if previous > &key {
                                    return Err(IndexRunError::InvalidContainerOrder);
                                }
                            }
                            previous_container = Some(key);
                            containers.push(container);
                        }
                        1 => {
                            if saw_standalone_stream_container || saw_namespace_key_id {
                                return Err(IndexRunError::InvalidContainerOrder);
                            }
                            validate_next_container_count(
                                &containers,
                                &stream_containers,
                                &standalone_stream_containers,
                                limits,
                            )?;
                            saw_stream_container = true;
                            let container = decode_stream_container(&mut record, limits)?;
                            let key = (container.object_id.clone(), container.version_id.clone());
                            if let Some(previous) = &previous_stream_container {
                                if previous == &key {
                                    return Err(IndexRunError::DuplicateContainer);
                                }
                                if previous > &key {
                                    return Err(IndexRunError::InvalidContainerOrder);
                                }
                            }
                            previous_stream_container = Some(key);
                            stream_containers.push(container);
                        }
                        2 => {
                            if saw_namespace_key_id {
                                return Err(IndexRunError::InvalidContainerOrder);
                            }
                            validate_next_container_count(
                                &containers,
                                &stream_containers,
                                &standalone_stream_containers,
                                limits,
                            )?;
                            saw_standalone_stream_container = true;
                            let container =
                                decode_standalone_stream_container(&mut record, limits)?;
                            let key = (container.object_id.clone(), container.version_id.clone());
                            if let Some(previous) = &previous_standalone_stream_container {
                                if previous == &key {
                                    return Err(IndexRunError::DuplicateContainer);
                                }
                                if previous > &key {
                                    return Err(IndexRunError::InvalidContainerOrder);
                                }
                            }
                            previous_standalone_stream_container = Some(key);
                            standalone_stream_containers.push(container);
                        }
                        3 => {
                            saw_namespace_key_id = true;
                            let declared = declared_namespace_key_count
                                .ok_or(IndexRunError::FrameFactsMismatch)?;
                            if namespace_key_ids.len() >= declared {
                                return Err(IndexRunError::FrameFactsMismatch);
                            }
                            let namespace_key_id = record.typed_string(
                                "namespace key id",
                                limits.max_key_id_bytes,
                                KeyId::new,
                            )?;
                            if let Some(previous) = namespace_key_ids.last() {
                                match previous.cmp(&namespace_key_id) {
                                    std::cmp::Ordering::Less => {}
                                    std::cmp::Ordering::Equal => {
                                        return Err(IndexRunError::DuplicateNamespaceKey);
                                    }
                                    std::cmp::Ordering::Greater => {
                                        return Err(IndexRunError::InvalidNamespaceKeyOrder);
                                    }
                                }
                            }
                            namespace_key_ids.push(namespace_key_id);
                        }
                        value => {
                            return Err(IndexRunError::InvalidTag {
                                field: "container type",
                                value,
                            });
                        }
                    }
                    record.finish_record()?;
                }
            }
            IndexRunFrameRole::Namespace => {
                let declared =
                    declared_namespace_key_count.ok_or(IndexRunError::FrameFactsMismatch)?;
                if namespace_key_ids.len() != declared {
                    return Err(IndexRunError::FrameFactsMismatch);
                }
                if header.role_record_count
                    != usize::try_from(header.mutation_count)
                        .map_err(|_| IndexRunError::IntegerOverflow)?
                {
                    return Err(IndexRunError::FrameFactsMismatch);
                }
                if !saw_namespace {
                    let count = usize::try_from(header.mutation_count)
                        .map_err(|_| IndexRunError::IntegerOverflow)?;
                    namespace.resize_with(count, || None);
                    mutations.resize_with(count, || None);
                    saw_namespace = true;
                }
                for _ in 0..header.frame_record_count {
                    let mut record = reader.record(limits.max_record_bytes)?;
                    let ordinal = record.u32_varint()?;
                    let (projection, namespace_key_ordinal) = decode_namespace_projection(
                        &mut record,
                        &namespace_key_ids,
                        &containers,
                        self_pack.as_ref(),
                        &stream_containers,
                        self_stream.as_ref(),
                        &standalone_stream_containers,
                    )?;
                    used_namespace_key_ids.insert(namespace_key_ordinal);
                    if let NamespaceProjection::Upsert { payload, .. } = &projection {
                        match payload {
                            IndexPayloadPointer::Empty => {}
                            IndexPayloadPointer::SelfPack { .. } => uses_self_pack = true,
                            IndexPayloadPointer::ExternalPack {
                                container_ordinal, ..
                            } => {
                                used_containers.insert(*container_ordinal);
                            }
                            IndexPayloadPointer::SelfStream => {
                                self_stream_uses = self_stream_uses.saturating_add(1);
                            }
                            IndexPayloadPointer::ExternalStream { container_ordinal } => {
                                used_stream_containers.insert(*container_ordinal);
                            }
                            IndexPayloadPointer::ExternalStandaloneStream { container_ordinal } => {
                                used_standalone_stream_containers.insert(*container_ordinal);
                            }
                        }
                    }
                    record.finish_record()?;
                    let sort_key = (projection.blind_key(), ordinal);
                    if previous_namespace_key.is_some_and(|previous| previous >= sort_key) {
                        return Err(IndexRunError::InvalidProjectionOrder {
                            projection: "namespace",
                        });
                    }
                    previous_namespace_key = Some(sort_key);
                    let slot = projection_slot(&mut namespace, "namespace", ordinal)?;
                    if slot.is_some() {
                        return Err(IndexRunError::DuplicateProjectionOrdinal {
                            projection: "namespace",
                            ordinal,
                        });
                    }
                    *slot = Some(projection);
                }
            }
            IndexRunFrameRole::Listing => {
                saw_listing = true;
                if header.role_record_count
                    != usize::try_from(header.mutation_count)
                        .map_err(|_| IndexRunError::IntegerOverflow)?
                {
                    return Err(IndexRunError::FrameFactsMismatch);
                }
                for _ in 0..header.frame_record_count {
                    let mut record = reader.record(limits.max_record_bytes)?;
                    let ordinal = record.u32_varint()?;
                    let listing = decode_listing_projection(&mut record, limits)?;
                    record.finish_record()?;
                    let sort_key = (listing.path(), ordinal);
                    if previous_listing_key
                        .as_ref()
                        .is_some_and(|previous| previous >= &sort_key)
                    {
                        return Err(IndexRunError::InvalidProjectionOrder {
                            projection: "listing",
                        });
                    }
                    previous_listing_key = Some(sort_key);
                    let mutation_slot = projection_slot(&mut mutations, "listing", ordinal)?;
                    if mutation_slot.is_some() {
                        return Err(IndexRunError::DuplicateProjectionOrdinal {
                            projection: "listing",
                            ordinal,
                        });
                    }
                    let namespace_mutation = projection_slot(&mut namespace, "namespace", ordinal)?
                        .take()
                        .ok_or(IndexRunError::ProjectionMismatch { ordinal })?;
                    *mutation_slot = Some(pair_projections(ordinal, namespace_mutation, listing)?);
                }
            }
        }
        if !reader.is_empty() {
            return Err(IndexRunError::TrailingBytes);
        }
    }
    if role_seen != role_total.ok_or(IndexRunError::InvalidFrameOrder)? {
        return Err(IndexRunError::InvalidFrameOrder);
    }
    let count = usize::try_from(mutation_count.ok_or(IndexRunError::InvalidFrameOrder)?)
        .map_err(|_| IndexRunError::IntegerOverflow)?;
    if count > 0 && (!saw_namespace || !saw_listing) {
        return Err(IndexRunError::InvalidFrameOrder);
    }
    if count == 0 && (saw_namespace || saw_listing) {
        return Err(IndexRunError::FrameFactsMismatch);
    }
    let declared_namespace_key_count =
        declared_namespace_key_count.ok_or(IndexRunError::FrameFactsMismatch)?;
    if namespace_key_ids.len() != declared_namespace_key_count {
        return Err(IndexRunError::FrameFactsMismatch);
    }
    if containers
        .len()
        .checked_add(stream_containers.len())
        .and_then(|count| count.checked_add(standalone_stream_containers.len()))
        .and_then(|count| count.checked_add(namespace_key_ids.len()))
        .ok_or(IndexRunError::IntegerOverflow)?
        != frames_metadata_total(frames, limits)?
    {
        return Err(IndexRunError::FrameFactsMismatch);
    }

    validate_distinct_container_objects(
        &containers,
        &stream_containers,
        &standalone_stream_containers,
    )?;

    validate_container_use(
        containers.len(),
        &used_containers,
        uses_self_pack,
        self_pack.as_ref(),
    )?;
    validate_stream_container_use(
        stream_containers.len(),
        &used_stream_containers,
        self_stream_uses,
        self_stream.as_ref(),
    )?;
    validate_standalone_stream_container_use(
        standalone_stream_containers.len(),
        &used_standalone_stream_containers,
    )?;
    validate_namespace_key_use(namespace_key_ids.len(), &used_namespace_key_ids)?;
    let mut ordered_mutations = Vec::with_capacity(mutations.len());
    for (index, mutation) in mutations.into_iter().enumerate() {
        let ordinal = u32::try_from(index).map_err(|_| IndexRunError::IntegerOverflow)?;
        ordered_mutations.push(mutation.ok_or(IndexRunError::ProjectionMismatch { ordinal })?);
    }
    validate_repeated_record_facts(&ordered_mutations, self_pack.as_ref(), &containers)?;
    Ok(IndexRun {
        sequence: sequence.ok_or(IndexRunError::InvalidFrameOrder)?,
        self_pack,
        self_stream,
        containers,
        stream_containers,
        standalone_stream_containers,
        mutations: ordered_mutations,
    })
}

struct DecodedFrameHeader {
    role: IndexRunFrameRole,
    role_ordinal: u32,
    sequence: Sequence,
    mutation_count: u32,
    role_record_count: usize,
    frame_record_count: usize,
    self_pack: Option<Option<IndexRunSelfPack>>,
    self_stream: Option<Option<IndexRunSelfStream>>,
    namespace_key_count: Option<usize>,
}

fn decode_frame_header<'a>(
    encoded: &'a [u8],
    limits: &IndexRunLimits,
) -> Result<(DecodedFrameHeader, Reader<'a>), IndexRunError> {
    let mut reader = Reader::new(encoded);
    if reader.bytes(INDEX_RUN_PLAINTEXT_DOMAIN.len())? != INDEX_RUN_PLAINTEXT_DOMAIN {
        return Err(IndexRunError::InvalidDomain);
    }
    let version = reader.u16()?;
    if version != INDEX_RUN_WIRE_VERSION {
        return Err(IndexRunError::UnsupportedVersion(version));
    }
    let role = match reader.u8()? {
        0 => IndexRunFrameRole::Metadata,
        1 => IndexRunFrameRole::Namespace,
        2 => IndexRunFrameRole::Listing,
        value => {
            return Err(IndexRunError::InvalidTag {
                field: "frame role",
                value,
            });
        }
    };
    let role_ordinal = reader.u32()?;
    let sequence = Sequence::new(reader.u64()?);
    let mutation_count = reader.u32_varint()?;
    let role_record_limit = if role == IndexRunFrameRole::Metadata {
        limits
            .max_containers
            .checked_add(limits.max_mutations)
            .ok_or(IndexRunError::IntegerOverflow)?
    } else {
        limits.max_mutations
    };
    let role_record_count = reader.bounded_count("role record count", role_record_limit)?;
    let frame_record_count = reader.bounded_count("frame record count", role_record_limit)?;
    let (self_pack, self_stream, namespace_key_count) = if role == IndexRunFrameRole::Metadata {
        let (self_pack, self_stream) = match reader.u8()? {
            0 => (Some(None), Some(None)),
            1 => {
                let mut pack_id = [0_u8; 32];
                pack_id.copy_from_slice(reader.bytes(32)?);
                let content_key_id =
                    reader.typed_string("content key id", limits.max_key_id_bytes, KeyId::new)?;
                let stored_len = reader.u64()?;
                let record_count = reader.u32_varint()?;
                let pack = IndexRunSelfPack {
                    pack_id,
                    content_key_id,
                    stored_len,
                    record_count,
                };
                validate_self_pack(Some(&pack), limits)?;
                (Some(Some(pack)), Some(None))
            }
            2 => {
                let stream = IndexRunSelfStream {
                    payload_section_ordinal: reader.u32()?,
                    payload_id: reader.typed_string(
                        "payload id",
                        limits.max_object_id_bytes,
                        BackendObjectId::new,
                    )?,
                    payload_header: decode_payload_header(&mut reader, limits)?,
                };
                validate_self_stream(Some(&stream), limits)?;
                (Some(None), Some(Some(stream)))
            }
            value => {
                return Err(IndexRunError::InvalidTag {
                    field: "self payload option",
                    value,
                });
            }
        };
        let namespace_key_count =
            reader.bounded_count("namespace key count", limits.max_mutations)?;
        (self_pack, self_stream, Some(namespace_key_count))
    } else {
        (None, None, None)
    };
    Ok((
        DecodedFrameHeader {
            role,
            role_ordinal,
            sequence,
            mutation_count,
            role_record_count,
            frame_record_count,
            self_pack,
            self_stream,
            namespace_key_count,
        },
        reader,
    ))
}

fn frames_metadata_total<B: AsRef<[u8]>>(
    frames: &[B],
    limits: &IndexRunLimits,
) -> Result<usize, IndexRunError> {
    for frame in frames {
        let (header, _) = decode_frame_header(frame.as_ref(), limits)?;
        if header.role == IndexRunFrameRole::Metadata {
            return Ok(header.role_record_count);
        }
    }
    Err(IndexRunError::InvalidFrameOrder)
}

fn decode_container(
    record: &mut Reader<'_>,
    limits: &IndexRunLimits,
) -> Result<IndexRunContainer, IndexRunError> {
    let exact = decode_exact_container(record, limits)?;
    let container = IndexRunContainer {
        object_id: exact.object_id,
        version_id: exact.version_id,
        stored_len: exact.stored_len,
        commit_body_digest: exact.object_digest,
        keyring_envelope: exact.keyring_envelope,
        pack_section_ordinal: record.u32()?,
        pack_section_offset: record.u64()?,
        pack_section_len: record.u64()?,
        pack_id: {
            let mut pack_id = [0_u8; 32];
            pack_id.copy_from_slice(record.bytes(32)?);
            pack_id
        },
        content_key_id: record.typed_string(
            "content key id",
            limits.max_key_id_bytes,
            KeyId::new,
        )?,
        pack_record_count: record.u32_varint()?,
    };
    validate_container_range(&container)?;
    Ok(container)
}

fn decode_stream_container(
    record: &mut Reader<'_>,
    limits: &IndexRunLimits,
) -> Result<IndexRunStreamContainer, IndexRunError> {
    let exact = decode_exact_container(record, limits)?;
    let sections_start = record.u64()?;
    let payload_section_ordinal = record.u32()?;
    let payload_section_offset = record.u64()?;
    let payload_section_len = record.u64()?;
    let mut payload_section_digest = [0_u8; 32];
    payload_section_digest.copy_from_slice(record.bytes(32)?);
    let payload_id = record.typed_string(
        "payload id",
        limits.max_object_id_bytes,
        BackendObjectId::new,
    )?;
    let payload_header = decode_payload_header(record, limits)?;
    let container = IndexRunStreamContainer {
        object_id: exact.object_id,
        version_id: exact.version_id,
        stored_len: exact.stored_len,
        commit_body_digest: exact.object_digest,
        keyring_envelope: exact.keyring_envelope,
        sections_start,
        payload_section_ordinal,
        payload_section_offset,
        payload_section_len,
        payload_section_digest,
        payload_id,
        payload_header,
    };
    validate_stream_container(&container, limits)?;
    Ok(container)
}

fn decode_standalone_stream_container(
    record: &mut Reader<'_>,
    limits: &IndexRunLimits,
) -> Result<IndexRunStandaloneStreamContainer, IndexRunError> {
    let exact = decode_exact_container(record, limits)?;
    let container = IndexRunStandaloneStreamContainer {
        object_id: exact.object_id,
        version_id: exact.version_id,
        stored_len: exact.stored_len,
        object_digest: exact.object_digest,
        keyring_envelope: exact.keyring_envelope,
        payload_header: decode_payload_header(record, limits)?,
    };
    validate_standalone_stream_container(&container, limits)?;
    Ok(container)
}

struct DecodedExactContainer {
    object_id: BackendObjectId,
    version_id: Option<BackendVersionId>,
    stored_len: u64,
    object_digest: [u8; 32],
    keyring_envelope: IndexRunKeyringRef,
}

fn decode_exact_container(
    record: &mut Reader<'_>,
    limits: &IndexRunLimits,
) -> Result<DecodedExactContainer, IndexRunError> {
    let object_id = record.typed_string(
        "object id",
        limits.max_object_id_bytes,
        BackendObjectId::new,
    )?;
    let version_id = match record.u8()? {
        0 => None,
        1 => Some(record.typed_string(
            "version id",
            limits.max_version_id_bytes,
            BackendVersionId::new,
        )?),
        value => {
            return Err(IndexRunError::InvalidTag {
                field: "version option",
                value,
            });
        }
    };
    let stored_len = record.u64()?;
    let mut object_digest = [0_u8; 32];
    object_digest.copy_from_slice(record.bytes(32)?);
    let keyring_envelope_object_id = record.typed_string(
        "keyring envelope object id",
        limits.max_object_id_bytes,
        BackendObjectId::new,
    )?;
    let mut keyring_envelope_digest = [0_u8; 32];
    keyring_envelope_digest.copy_from_slice(record.bytes(32)?);
    Ok(DecodedExactContainer {
        object_id,
        version_id,
        stored_len,
        object_digest,
        keyring_envelope: IndexRunKeyringRef {
            object_id: keyring_envelope_object_id,
            digest: keyring_envelope_digest,
        },
    })
}

fn decode_namespace_projection(
    record: &mut Reader<'_>,
    namespace_key_ids: &[KeyId],
    containers: &[IndexRunContainer],
    self_pack: Option<&IndexRunSelfPack>,
    stream_containers: &[IndexRunStreamContainer],
    self_stream: Option<&IndexRunSelfStream>,
    standalone_stream_containers: &[IndexRunStandaloneStreamContainer],
) -> Result<(NamespaceProjection, u32), IndexRunError> {
    match record.u8()? {
        0 => {
            let blind_key = decode_blind_key(record)?;
            let (namespace_key_ordinal, namespace_key_id) =
                decode_namespace_key_reference(record, namespace_key_ids)?;
            let generation = Sequence::new(record.varint()?);
            let payload = decode_payload_pointer(
                record,
                containers,
                self_pack,
                stream_containers,
                self_stream,
                standalone_stream_containers,
            )?;
            let content_len = record.varint()?;
            validate_empty_payload(payload, content_len)?;
            validate_payload_pointer(
                payload,
                content_len,
                self_pack,
                containers,
                self_stream,
                stream_containers,
                standalone_stream_containers,
            )?;
            Ok((
                NamespaceProjection::Upsert {
                    blind_key,
                    namespace_key_id,
                    generation,
                    payload,
                    content_len,
                    modified_at_ms: record.i64()?,
                    retention: decode_retention(record)?,
                    legal_hold: decode_legal_hold(record)?,
                },
                namespace_key_ordinal,
            ))
        }
        1 => {
            let blind_key = decode_blind_key(record)?;
            let (namespace_key_ordinal, namespace_key_id) =
                decode_namespace_key_reference(record, namespace_key_ids)?;
            Ok((
                NamespaceProjection::Tombstone {
                    blind_key,
                    namespace_key_id,
                    generation: Sequence::new(record.varint()?),
                },
                namespace_key_ordinal,
            ))
        }
        value => Err(IndexRunError::InvalidTag {
            field: "namespace mutation",
            value,
        }),
    }
}

fn decode_namespace_key_reference(
    record: &mut Reader<'_>,
    namespace_key_ids: &[KeyId],
) -> Result<(u32, KeyId), IndexRunError> {
    let ordinal = record.u32_varint()?;
    let index = usize::try_from(ordinal).map_err(|_| IndexRunError::IntegerOverflow)?;
    let namespace_key_id = namespace_key_ids
        .get(index)
        .ok_or(IndexRunError::InvalidNamespaceKeyOrdinal(ordinal))?
        .clone();
    Ok((ordinal, namespace_key_id))
}

fn decode_listing_projection(
    record: &mut Reader<'_>,
    limits: &IndexRunLimits,
) -> Result<ListingProjection, IndexRunError> {
    let tag = record.u8()?;
    let path = record.typed_string("logical path", limits.max_path_bytes, LogicalPath::new)?;
    let generation = Sequence::new(record.varint()?);
    match tag {
        0 => Ok(ListingProjection::Upsert {
            path,
            generation,
            content_len: record.varint()?,
            modified_at_ms: record.i64()?,
        }),
        1 => Ok(ListingProjection::Tombstone { path, generation }),
        value => Err(IndexRunError::InvalidTag {
            field: "listing mutation",
            value,
        }),
    }
}

fn pair_projections(
    ordinal: u32,
    namespace: NamespaceProjection,
    listing: ListingProjection,
) -> Result<IndexMutation, IndexRunError> {
    match (namespace, listing) {
        (
            NamespaceProjection::Upsert {
                blind_key,
                namespace_key_id,
                generation: namespace_generation,
                payload,
                content_len: namespace_content_len,
                modified_at_ms: namespace_modified_at_ms,
                retention,
                legal_hold,
            },
            ListingProjection::Upsert {
                path,
                generation,
                content_len,
                modified_at_ms,
            },
        ) if namespace_generation == generation
            && namespace_content_len == content_len
            && namespace_modified_at_ms == modified_at_ms =>
        {
            Ok(IndexMutation::Upsert(IndexUpsert {
                mutation_ordinal: ordinal,
                blind_key,
                namespace_key_id,
                path,
                generation,
                payload,
                content_len,
                modified_at_ms,
                retention,
                legal_hold,
            }))
        }
        (
            NamespaceProjection::Tombstone {
                blind_key,
                namespace_key_id,
                generation: namespace_generation,
            },
            ListingProjection::Tombstone { path, generation },
        ) if namespace_generation == generation => Ok(IndexMutation::Tombstone(IndexTombstone {
            mutation_ordinal: ordinal,
            blind_key,
            namespace_key_id,
            path,
            generation,
        })),
        _ => Err(IndexRunError::ProjectionMismatch { ordinal }),
    }
}

fn validate_container_use(
    container_count: usize,
    used_containers: &BTreeSet<u32>,
    uses_self_pack: bool,
    self_pack: Option<&IndexRunSelfPack>,
) -> Result<(), IndexRunError> {
    if uses_self_pack != self_pack.is_some() || self_pack.is_some_and(|pack| pack.record_count == 0)
    {
        return Err(IndexRunError::InvalidPackRecordCount);
    }
    for index in 0..container_count {
        let ordinal = u32::try_from(index).map_err(|_| IndexRunError::IntegerOverflow)?;
        if !used_containers.contains(&ordinal) {
            return Err(IndexRunError::UnusedContainer(ordinal));
        }
    }
    Ok(())
}

fn validate_next_container_count(
    containers: &[IndexRunContainer],
    stream_containers: &[IndexRunStreamContainer],
    standalone_stream_containers: &[IndexRunStandaloneStreamContainer],
    limits: &IndexRunLimits,
) -> Result<(), IndexRunError> {
    let actual = containers
        .len()
        .checked_add(stream_containers.len())
        .and_then(|count| count.checked_add(standalone_stream_containers.len()))
        .and_then(|count| count.checked_add(1))
        .ok_or(IndexRunError::IntegerOverflow)?;
    validate_count("container count", actual, limits.max_containers)
}

fn validate_namespace_key_use(
    namespace_key_count: usize,
    used_namespace_key_ids: &BTreeSet<u32>,
) -> Result<(), IndexRunError> {
    for index in 0..namespace_key_count {
        let ordinal = u32::try_from(index).map_err(|_| IndexRunError::IntegerOverflow)?;
        if !used_namespace_key_ids.contains(&ordinal) {
            return Err(IndexRunError::UnusedNamespaceKey(ordinal));
        }
    }
    Ok(())
}

fn validate_stream_container_use(
    container_count: usize,
    used_containers: &BTreeSet<u32>,
    self_stream_uses: usize,
    self_stream: Option<&IndexRunSelfStream>,
) -> Result<(), IndexRunError> {
    if (self_stream_uses > 0) != self_stream.is_some() {
        return Err(IndexRunError::InvalidSelfStream);
    }
    for index in 0..container_count {
        let ordinal = u32::try_from(index).map_err(|_| IndexRunError::IntegerOverflow)?;
        if !used_containers.contains(&ordinal) {
            return Err(IndexRunError::UnusedStreamContainer(ordinal));
        }
    }
    Ok(())
}

fn validate_standalone_stream_container_use(
    container_count: usize,
    used_containers: &BTreeSet<u32>,
) -> Result<(), IndexRunError> {
    for index in 0..container_count {
        let ordinal = u32::try_from(index).map_err(|_| IndexRunError::IntegerOverflow)?;
        if !used_containers.contains(&ordinal) {
            return Err(IndexRunError::UnusedStandaloneStreamContainer(ordinal));
        }
    }
    Ok(())
}

/// Decodes the length-prefixed convenience bundle produced by
/// [`encode_index_run`].
pub fn decode_index_run(
    encoded: &[u8],
    limits: &IndexRunLimits,
) -> Result<IndexRun, IndexRunError> {
    validate_count("total bytes", encoded.len(), limits.max_total_bytes)?;
    let mut bundle = Reader::new(encoded);
    let maximum_frames = limits
        .max_mutations
        .checked_mul(3)
        .and_then(|value| value.checked_add(limits.max_containers))
        .and_then(|value| value.checked_add(1))
        .ok_or(IndexRunError::IntegerOverflow)?;
    let frame_count = bundle.bounded_count("frame count", maximum_frames)?;
    let mut frames = Vec::with_capacity(frame_count);
    for _ in 0..frame_count {
        frames.push(bundle.record(limits.max_frame_bytes)?.remaining);
    }
    if !bundle.is_empty() {
        return Err(IndexRunError::TrailingBytes);
    }
    decode_index_run_frames(&frames, limits)
}

enum NamespaceProjection {
    Upsert {
        blind_key: IndexBlindKey,
        namespace_key_id: KeyId,
        generation: Sequence,
        payload: IndexPayloadPointer,
        content_len: u64,
        modified_at_ms: i64,
        retention: Option<RetentionPolicy>,
        legal_hold: Option<LegalHoldStatus>,
    },
    Tombstone {
        blind_key: IndexBlindKey,
        namespace_key_id: KeyId,
        generation: Sequence,
    },
}

impl NamespaceProjection {
    const fn blind_key(&self) -> IndexBlindKey {
        match self {
            Self::Upsert { blind_key, .. } | Self::Tombstone { blind_key, .. } => *blind_key,
        }
    }
}

enum ListingProjection {
    Upsert {
        path: LogicalPath,
        generation: Sequence,
        content_len: u64,
        modified_at_ms: i64,
    },
    Tombstone {
        path: LogicalPath,
        generation: Sequence,
    },
}

impl ListingProjection {
    fn path(&self) -> LogicalPath {
        match self {
            Self::Upsert { path, .. } | Self::Tombstone { path, .. } => path.clone(),
        }
    }
}

fn projection_slot<'a, T>(
    projection: &'a mut [Option<T>],
    name: &'static str,
    ordinal: u32,
) -> Result<&'a mut Option<T>, IndexRunError> {
    let index = usize::try_from(ordinal).map_err(|_| IndexRunError::IntegerOverflow)?;
    projection
        .get_mut(index)
        .ok_or(IndexRunError::InvalidProjectionOrdinal {
            projection: name,
            ordinal,
        })
}

fn mutation_blind_key(mutation: &IndexMutation) -> IndexBlindKey {
    match mutation {
        IndexMutation::Upsert(upsert) => upsert.blind_key,
        IndexMutation::Tombstone(tombstone) => tombstone.blind_key,
    }
}

fn mutation_namespace_key_id(mutation: &IndexMutation) -> &KeyId {
    match mutation {
        IndexMutation::Upsert(upsert) => &upsert.namespace_key_id,
        IndexMutation::Tombstone(tombstone) => &tombstone.namespace_key_id,
    }
}

fn namespace_key_ordinal(
    namespace_key_ids: &[&KeyId],
    namespace_key_id: &KeyId,
) -> Result<u64, IndexRunError> {
    let ordinal = namespace_key_ids
        .binary_search_by(|candidate| candidate.cmp(&namespace_key_id))
        .map_err(|_| IndexRunError::InvalidValue {
            field: "namespace key id",
        })?;
    usize_to_u64(ordinal)
}

fn mutation_path(mutation: &IndexMutation) -> &LogicalPath {
    match mutation {
        IndexMutation::Upsert(upsert) => &upsert.path,
        IndexMutation::Tombstone(tombstone) => &tombstone.path,
    }
}

fn validate_count(field: &'static str, actual: usize, maximum: usize) -> Result<(), IndexRunError> {
    if actual > maximum {
        return Err(IndexRunError::LimitExceeded {
            field,
            actual,
            maximum,
        });
    }
    Ok(())
}

fn validate_containers(
    containers: &[IndexRunContainer],
    limits: &IndexRunLimits,
) -> Result<(), IndexRunError> {
    let mut previous = None;
    for container in containers {
        validate_count(
            "object id",
            container.object_id.as_str().len(),
            limits.max_object_id_bytes,
        )?;
        if let Some(version_id) = &container.version_id {
            validate_count(
                "version id",
                version_id.as_str().len(),
                limits.max_version_id_bytes,
            )?;
        }
        validate_count(
            "keyring envelope object id",
            container.keyring_envelope.object_id.as_str().len(),
            limits.max_object_id_bytes,
        )?;
        validate_count(
            "content key id",
            container.content_key_id.as_str().len(),
            limits.max_key_id_bytes,
        )?;
        validate_container_range(container)?;
        let key = (&container.object_id, &container.version_id);
        if let Some(previous_key) = previous {
            if previous_key == key {
                return Err(IndexRunError::DuplicateContainer);
            }
            if previous_key > key {
                return Err(IndexRunError::InvalidContainerOrder);
            }
        }
        previous = Some(key);
    }
    Ok(())
}

fn validate_stream_containers(
    containers: &[IndexRunStreamContainer],
    limits: &IndexRunLimits,
) -> Result<(), IndexRunError> {
    let mut previous = None;
    for container in containers {
        validate_exact_container(
            &container.object_id,
            container.version_id.as_ref(),
            &container.keyring_envelope,
            limits,
        )?;
        validate_stream_container(container, limits)?;
        let key = (&container.object_id, &container.version_id);
        if let Some(previous_key) = previous {
            if previous_key == key {
                return Err(IndexRunError::DuplicateContainer);
            }
            if previous_key > key {
                return Err(IndexRunError::InvalidContainerOrder);
            }
        }
        previous = Some(key);
    }
    Ok(())
}

fn validate_standalone_stream_containers(
    containers: &[IndexRunStandaloneStreamContainer],
    limits: &IndexRunLimits,
) -> Result<(), IndexRunError> {
    let mut previous = None;
    for container in containers {
        validate_exact_container(
            &container.object_id,
            container.version_id.as_ref(),
            &container.keyring_envelope,
            limits,
        )?;
        validate_standalone_stream_container(container, limits)?;
        let key = (&container.object_id, &container.version_id);
        if let Some(previous_key) = previous {
            if previous_key == key {
                return Err(IndexRunError::DuplicateContainer);
            }
            if previous_key > key {
                return Err(IndexRunError::InvalidContainerOrder);
            }
        }
        previous = Some(key);
    }
    Ok(())
}

fn validate_distinct_container_objects(
    pack: &[IndexRunContainer],
    stream: &[IndexRunStreamContainer],
    standalone_stream: &[IndexRunStandaloneStreamContainer],
) -> Result<(), IndexRunError> {
    let mut exact = BTreeSet::new();
    for key in pack
        .iter()
        .map(|container| (&container.object_id, &container.version_id))
        .chain(
            stream
                .iter()
                .map(|container| (&container.object_id, &container.version_id)),
        )
        .chain(
            standalone_stream
                .iter()
                .map(|container| (&container.object_id, &container.version_id)),
        )
    {
        if !exact.insert(key) {
            return Err(IndexRunError::DuplicateContainer);
        }
    }
    Ok(())
}

fn validate_exact_container(
    object_id: &BackendObjectId,
    version_id: Option<&BackendVersionId>,
    keyring_envelope: &IndexRunKeyringRef,
    limits: &IndexRunLimits,
) -> Result<(), IndexRunError> {
    validate_count(
        "object id",
        object_id.as_str().len(),
        limits.max_object_id_bytes,
    )?;
    if let Some(version_id) = version_id {
        validate_count(
            "version id",
            version_id.as_str().len(),
            limits.max_version_id_bytes,
        )?;
    }
    validate_count(
        "keyring envelope object id",
        keyring_envelope.object_id.as_str().len(),
        limits.max_object_id_bytes,
    )
}

fn validate_container_range(container: &IndexRunContainer) -> Result<(), IndexRunError> {
    let section_end = container
        .pack_section_offset
        .checked_add(container.pack_section_len)
        .ok_or(IndexRunError::InvalidContainerRange)?;
    if container.pack_section_len == 0
        || container.pack_section_len > INDEX_PACK_MAX_STORED_BYTES
        || container.pack_record_count == 0
        || container.pack_record_count > INDEX_PACK_MAX_RECORDS
        || section_end > container.stored_len
    {
        return Err(IndexRunError::InvalidContainerRange);
    }
    Ok(())
}

fn validate_self_pack(
    self_pack: Option<&IndexRunSelfPack>,
    limits: &IndexRunLimits,
) -> Result<(), IndexRunError> {
    let Some(pack) = self_pack else {
        return Ok(());
    };
    validate_count(
        "content key id",
        pack.content_key_id.as_str().len(),
        limits.max_key_id_bytes,
    )?;
    if pack.stored_len == 0
        || pack.stored_len > INDEX_PACK_MAX_STORED_BYTES
        || pack.record_count == 0
        || pack.record_count > INDEX_PACK_MAX_RECORDS
    {
        return Err(IndexRunError::InvalidPackRecordCount);
    }
    Ok(())
}

fn validate_self_stream(
    self_stream: Option<&IndexRunSelfStream>,
    limits: &IndexRunLimits,
) -> Result<(), IndexRunError> {
    let Some(stream) = self_stream else {
        return Ok(());
    };
    validate_count(
        "payload id",
        stream.payload_id.as_str().len(),
        limits.max_object_id_bytes,
    )?;
    validate_payload_header(&stream.payload_header, limits)
        .map_err(|_| IndexRunError::InvalidSelfStream)
}

fn validate_stream_container(
    container: &IndexRunStreamContainer,
    limits: &IndexRunLimits,
) -> Result<(), IndexRunError> {
    validate_count(
        "payload id",
        container.payload_id.as_str().len(),
        limits.max_object_id_bytes,
    )?;
    validate_payload_header(&container.payload_header, limits)?;
    let section_start = container
        .sections_start
        .checked_add(container.payload_section_offset)
        .ok_or(IndexRunError::InvalidStreamContainer)?;
    let section_end = section_start
        .checked_add(container.payload_section_len)
        .ok_or(IndexRunError::InvalidStreamContainer)?;
    if container.sections_start == 0
        || container.payload_section_len == 0
        || section_end > container.stored_len
        || stream_payload_stored_len(&container.payload_header)? != container.payload_section_len
    {
        return Err(IndexRunError::InvalidStreamContainer);
    }
    Ok(())
}

fn validate_standalone_stream_container(
    container: &IndexRunStandaloneStreamContainer,
    limits: &IndexRunLimits,
) -> Result<(), IndexRunError> {
    validate_payload_header(&container.payload_header, limits)
        .map_err(|_| IndexRunError::InvalidStandaloneStreamContainer)?;
    if stream_payload_stored_len(&container.payload_header)
        .map_err(|_| IndexRunError::InvalidStandaloneStreamContainer)?
        != container.stored_len
    {
        return Err(IndexRunError::InvalidStandaloneStreamContainer);
    }
    Ok(())
}

fn validate_payload_header(
    header: &PayloadHeaderReference,
    limits: &IndexRunLimits,
) -> Result<(), IndexRunError> {
    validate_count(
        "content key id",
        header.key_id.as_str().len(),
        limits.max_key_id_bytes,
    )?;
    if header.chunk_size == 0
        || header.header_len == 0
        || header.header_len > INDEX_STREAM_MAX_HEADER_BYTES
    {
        return Err(IndexRunError::InvalidStreamContainer);
    }
    stream_payload_stored_len(header).map(|_| ())
}

fn stream_payload_stored_len(header: &PayloadHeaderReference) -> Result<u64, IndexRunError> {
    let segment_count = header.plaintext_len.div_ceil(header.chunk_size);
    header
        .plaintext_len
        .checked_add(
            segment_count
                .checked_mul(INDEX_STREAM_SEGMENT_TAG_BYTES)
                .ok_or(IndexRunError::InvalidStreamContainer)?,
        )
        .and_then(|ciphertext_len| header.header_len.checked_add(ciphertext_len))
        .ok_or(IndexRunError::InvalidStreamContainer)
}

fn validate_mutations(run: &IndexRun, limits: &IndexRunLimits) -> Result<(), IndexRunError> {
    let mut used_containers = BTreeSet::new();
    let mut used_stream_containers = BTreeSet::new();
    let mut used_standalone_stream_containers = BTreeSet::new();
    let mut uses_self_pack = false;
    let mut self_stream_uses = 0_usize;
    for (index, mutation) in run.mutations.iter().enumerate() {
        let expected = u32::try_from(index).map_err(|_| IndexRunError::IntegerOverflow)?;
        let actual = mutation.ordinal();
        if actual != expected {
            return Err(IndexRunError::InvalidMutationOrdinal { expected, actual });
        }
        match mutation {
            IndexMutation::Upsert(upsert) => {
                validate_count(
                    "namespace key id",
                    upsert.namespace_key_id.as_str().len(),
                    limits.max_key_id_bytes,
                )?;
                validate_count(
                    "logical path",
                    upsert.path.as_str().len(),
                    limits.max_path_bytes,
                )?;
                validate_empty_payload(upsert.payload, upsert.content_len)?;
                validate_payload_pointer(
                    upsert.payload,
                    upsert.content_len,
                    run.self_pack.as_ref(),
                    &run.containers,
                    run.self_stream.as_ref(),
                    &run.stream_containers,
                    &run.standalone_stream_containers,
                )?;
                match upsert.payload {
                    IndexPayloadPointer::Empty => {}
                    IndexPayloadPointer::SelfPack { record } => {
                        let count = run
                            .self_pack
                            .as_ref()
                            .map(|pack| pack.record_count)
                            .ok_or(IndexRunError::InvalidPackRecordCount)?;
                        if record.record_ordinal >= count {
                            return Err(IndexRunError::InvalidPackRecordCount);
                        }
                        uses_self_pack = true;
                    }
                    IndexPayloadPointer::ExternalPack {
                        container_ordinal,
                        record,
                    } => {
                        validate_container_ordinal(container_ordinal, run.containers.len())?;
                        let container = &run.containers[usize::try_from(container_ordinal)
                            .map_err(|_| IndexRunError::IntegerOverflow)?];
                        if record.record_ordinal >= container.pack_record_count {
                            return Err(IndexRunError::InvalidPackRecordCount);
                        }
                        used_containers.insert(container_ordinal);
                    }
                    IndexPayloadPointer::SelfStream => {
                        self_stream_uses = self_stream_uses.saturating_add(1);
                    }
                    IndexPayloadPointer::ExternalStream { container_ordinal } => {
                        validate_container_ordinal(container_ordinal, run.stream_containers.len())?;
                        used_stream_containers.insert(container_ordinal);
                    }
                    IndexPayloadPointer::ExternalStandaloneStream { container_ordinal } => {
                        validate_container_ordinal(
                            container_ordinal,
                            run.standalone_stream_containers.len(),
                        )?;
                        used_standalone_stream_containers.insert(container_ordinal);
                    }
                }
            }
            IndexMutation::Tombstone(tombstone) => {
                validate_count(
                    "namespace key id",
                    tombstone.namespace_key_id.as_str().len(),
                    limits.max_key_id_bytes,
                )?;
                validate_count(
                    "logical path",
                    tombstone.path.as_str().len(),
                    limits.max_path_bytes,
                )?;
            }
        }
    }
    validate_container_use(
        run.containers.len(),
        &used_containers,
        uses_self_pack,
        run.self_pack.as_ref(),
    )?;
    validate_stream_container_use(
        run.stream_containers.len(),
        &used_stream_containers,
        self_stream_uses,
        run.self_stream.as_ref(),
    )?;
    validate_standalone_stream_container_use(
        run.standalone_stream_containers.len(),
        &used_standalone_stream_containers,
    )?;
    validate_repeated_record_facts(&run.mutations, run.self_pack.as_ref(), &run.containers)
}

fn validate_empty_payload(
    pointer: IndexPayloadPointer,
    content_len: u64,
) -> Result<(), IndexRunError> {
    match pointer {
        IndexPayloadPointer::Empty if content_len == 0 => Ok(()),
        IndexPayloadPointer::SelfStream
        | IndexPayloadPointer::ExternalStream { .. }
        | IndexPayloadPointer::ExternalStandaloneStream { .. } => Ok(()),
        IndexPayloadPointer::SelfPack { .. } | IndexPayloadPointer::ExternalPack { .. }
            if content_len != 0 =>
        {
            Ok(())
        }
        _ => Err(IndexRunError::InvalidEmptyPayload),
    }
}

fn validate_payload_pointer(
    pointer: IndexPayloadPointer,
    content_len: u64,
    self_pack: Option<&IndexRunSelfPack>,
    containers: &[IndexRunContainer],
    self_stream: Option<&IndexRunSelfStream>,
    stream_containers: &[IndexRunStreamContainer],
    standalone_stream_containers: &[IndexRunStandaloneStreamContainer],
) -> Result<(), IndexRunError> {
    let (record, pack_stored_len) = match pointer {
        IndexPayloadPointer::Empty => return Ok(()),
        IndexPayloadPointer::SelfPack { record } => (
            record,
            self_pack
                .map(|pack| pack.stored_len)
                .ok_or(IndexRunError::InvalidPackRecordCount)?,
        ),
        IndexPayloadPointer::ExternalPack {
            container_ordinal,
            record,
        } => {
            validate_container_ordinal(container_ordinal, containers.len())?;
            let container = &containers
                [usize::try_from(container_ordinal).map_err(|_| IndexRunError::IntegerOverflow)?];
            (record, container.pack_section_len)
        }
        IndexPayloadPointer::SelfStream => {
            let stream = self_stream.ok_or(IndexRunError::InvalidSelfStream)?;
            if stream.payload_header.plaintext_len != content_len {
                return Err(IndexRunError::InvalidSelfStream);
            }
            return Ok(());
        }
        IndexPayloadPointer::ExternalStream { container_ordinal } => {
            validate_container_ordinal(container_ordinal, stream_containers.len())?;
            let container = &stream_containers
                [usize::try_from(container_ordinal).map_err(|_| IndexRunError::IntegerOverflow)?];
            if container.payload_header.plaintext_len != content_len {
                return Err(IndexRunError::InvalidStreamContainer);
            }
            return Ok(());
        }
        IndexPayloadPointer::ExternalStandaloneStream { container_ordinal } => {
            validate_container_ordinal(container_ordinal, standalone_stream_containers.len())?;
            let container = &standalone_stream_containers
                [usize::try_from(container_ordinal).map_err(|_| IndexRunError::IntegerOverflow)?];
            if container.payload_header.plaintext_len != content_len {
                return Err(IndexRunError::InvalidStandaloneStreamContainer);
            }
            return Ok(());
        }
    };
    let stored_len = derived_record_stored_len(content_len)?;
    let end = u64::from(record.physical_offset)
        .checked_add(stored_len)
        .ok_or(IndexRunError::InvalidPackRecordRange)?;
    if content_len == 0 || end > pack_stored_len {
        return Err(IndexRunError::InvalidPackRecordRange);
    }
    Ok(())
}

fn derived_record_stored_len(content_len: u64) -> Result<u64, IndexRunError> {
    let segment_count = content_len.div_ceil(INDEX_PACK_SEGMENT_BYTES);
    content_len
        .checked_add(
            segment_count
                .checked_mul(INDEX_PACK_SEGMENT_TAG_BYTES)
                .ok_or(IndexRunError::InvalidPackRecordRange)?,
        )
        .ok_or(IndexRunError::InvalidPackRecordRange)
}

fn validate_repeated_record_facts(
    mutations: &[IndexMutation],
    self_pack: Option<&IndexRunSelfPack>,
    containers: &[IndexRunContainer],
) -> Result<(), IndexRunError> {
    let mut facts = BTreeMap::new();
    let mut spans = Vec::new();
    for mutation in mutations {
        let IndexMutation::Upsert(upsert) = mutation else {
            continue;
        };
        let (source, record) = match upsert.payload {
            IndexPayloadPointer::Empty => continue,
            IndexPayloadPointer::SelfStream
            | IndexPayloadPointer::ExternalStream { .. }
            | IndexPayloadPointer::ExternalStandaloneStream { .. } => continue,
            IndexPayloadPointer::SelfPack { record } => (0_u32, record),
            IndexPayloadPointer::ExternalPack {
                container_ordinal,
                record,
            } => (
                container_ordinal
                    .checked_add(1)
                    .ok_or(IndexRunError::IntegerOverflow)?,
                record,
            ),
        };
        validate_payload_pointer(
            upsert.payload,
            upsert.content_len,
            self_pack,
            containers,
            None,
            &[],
            &[],
        )?;
        let key = (source, record.record_ordinal);
        let value = (record, upsert.content_len);
        match facts.get(&key) {
            Some(previous) if previous != &value => {
                return Err(IndexRunError::PackRecordFactsMismatch);
            }
            Some(_) => continue,
            None => {
                facts.insert(key, value);
            }
        }
        let end = u64::from(record.physical_offset)
            .checked_add(derived_record_stored_len(upsert.content_len)?)
            .ok_or(IndexRunError::InvalidPackRecordRange)?;
        spans.push((source, record.physical_offset, end, record.record_ordinal));
    }
    spans.sort_unstable();
    for adjacent in spans.windows(2) {
        let (left_source, _, left_end, left_ordinal) = adjacent[0];
        let (right_source, right_start, _, right_ordinal) = adjacent[1];
        if left_source == right_source
            && left_ordinal != right_ordinal
            && u64::from(right_start) < left_end
        {
            return Err(IndexRunError::PackRecordFactsMismatch);
        }
    }
    Ok(())
}

fn validate_container_ordinal(ordinal: u32, container_count: usize) -> Result<(), IndexRunError> {
    let ordinal_usize = usize::try_from(ordinal).map_err(|_| IndexRunError::IntegerOverflow)?;
    if ordinal_usize >= container_count {
        return Err(IndexRunError::InvalidContainerOrdinal(ordinal));
    }
    Ok(())
}

fn encode_payload_pointer(
    writer: &mut Writer,
    pointer: IndexPayloadPointer,
) -> Result<(), IndexRunError> {
    match pointer {
        IndexPayloadPointer::Empty => writer.u8(0)?,
        IndexPayloadPointer::SelfPack { record } => {
            writer.u8(1)?;
            encode_pack_record_pointer(writer, record)?;
        }
        IndexPayloadPointer::ExternalPack {
            container_ordinal,
            record,
        } => {
            writer.u8(2)?;
            writer.varint(u64::from(container_ordinal))?;
            encode_pack_record_pointer(writer, record)?;
        }
        IndexPayloadPointer::SelfStream => writer.u8(3)?,
        IndexPayloadPointer::ExternalStream { container_ordinal } => {
            writer.u8(4)?;
            writer.varint(u64::from(container_ordinal))?;
        }
        IndexPayloadPointer::ExternalStandaloneStream { container_ordinal } => {
            writer.u8(5)?;
            writer.varint(u64::from(container_ordinal))?;
        }
    }
    Ok(())
}

fn decode_payload_pointer(
    reader: &mut Reader<'_>,
    containers: &[IndexRunContainer],
    self_pack: Option<&IndexRunSelfPack>,
    stream_containers: &[IndexRunStreamContainer],
    self_stream: Option<&IndexRunSelfStream>,
    standalone_stream_containers: &[IndexRunStandaloneStreamContainer],
) -> Result<IndexPayloadPointer, IndexRunError> {
    match reader.u8()? {
        0 => Ok(IndexPayloadPointer::Empty),
        1 => {
            let record = decode_pack_record_pointer(reader)?;
            if self_pack.is_none_or(|pack| record.record_ordinal >= pack.record_count) {
                return Err(IndexRunError::InvalidPackRecordCount);
            }
            Ok(IndexPayloadPointer::SelfPack { record })
        }
        2 => {
            let container_ordinal = reader.u32_varint()?;
            validate_container_ordinal(container_ordinal, containers.len())?;
            let record = decode_pack_record_pointer(reader)?;
            if record.record_ordinal
                >= containers[usize::try_from(container_ordinal)
                    .map_err(|_| IndexRunError::IntegerOverflow)?]
                .pack_record_count
            {
                return Err(IndexRunError::InvalidPackRecordCount);
            }
            Ok(IndexPayloadPointer::ExternalPack {
                container_ordinal,
                record,
            })
        }
        3 => {
            if self_stream.is_none() {
                return Err(IndexRunError::InvalidSelfStream);
            }
            Ok(IndexPayloadPointer::SelfStream)
        }
        4 => {
            let container_ordinal = reader.u32_varint()?;
            validate_container_ordinal(container_ordinal, stream_containers.len())?;
            Ok(IndexPayloadPointer::ExternalStream { container_ordinal })
        }
        5 => {
            let container_ordinal = reader.u32_varint()?;
            validate_container_ordinal(container_ordinal, standalone_stream_containers.len())?;
            Ok(IndexPayloadPointer::ExternalStandaloneStream { container_ordinal })
        }
        value => Err(IndexRunError::InvalidTag {
            field: "payload pointer",
            value,
        }),
    }
}

fn encode_pack_record_pointer(
    writer: &mut Writer,
    pointer: IndexPackRecordPointer,
) -> Result<(), IndexRunError> {
    writer.varint(u64::from(pointer.record_ordinal))?;
    writer.varint(u64::from(pointer.physical_offset))
}

fn decode_pack_record_pointer(
    reader: &mut Reader<'_>,
) -> Result<IndexPackRecordPointer, IndexRunError> {
    let record_ordinal = reader.u32_varint()?;
    let physical_offset = reader.u32_varint()?;
    Ok(IndexPackRecordPointer {
        record_ordinal,
        physical_offset,
    })
}

fn encode_retention(
    writer: &mut Writer,
    retention: Option<RetentionPolicy>,
) -> Result<(), IndexRunError> {
    match retention {
        None => writer.u8(0),
        Some(retention) => {
            writer.u8(1)?;
            writer.u8(match retention.mode {
                RetentionMode::None => 0,
                RetentionMode::Governance => 1,
                RetentionMode::Compliance => 2,
            })?;
            writer.u32(retention.retain_days)
        }
    }
}

fn decode_retention(reader: &mut Reader<'_>) -> Result<Option<RetentionPolicy>, IndexRunError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => {
            let mode = match reader.u8()? {
                0 => RetentionMode::None,
                1 => RetentionMode::Governance,
                2 => RetentionMode::Compliance,
                value => {
                    return Err(IndexRunError::InvalidTag {
                        field: "retention mode",
                        value,
                    });
                }
            };
            Ok(Some(RetentionPolicy::new(mode, reader.u32()?)))
        }
        value => Err(IndexRunError::InvalidTag {
            field: "retention option",
            value,
        }),
    }
}

fn encode_legal_hold(
    writer: &mut Writer,
    legal_hold: Option<LegalHoldStatus>,
) -> Result<(), IndexRunError> {
    writer.u8(match legal_hold {
        None => 0,
        Some(LegalHoldStatus::Off) => 1,
        Some(LegalHoldStatus::On) => 2,
    })
}

fn decode_legal_hold(reader: &mut Reader<'_>) -> Result<Option<LegalHoldStatus>, IndexRunError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(LegalHoldStatus::Off)),
        2 => Ok(Some(LegalHoldStatus::On)),
        value => Err(IndexRunError::InvalidTag {
            field: "legal hold",
            value,
        }),
    }
}

fn decode_blind_key(reader: &mut Reader<'_>) -> Result<IndexBlindKey, IndexRunError> {
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(reader.bytes(32)?);
    Ok(IndexBlindKey::from_bytes(bytes))
}

fn usize_to_u64(value: usize) -> Result<u64, IndexRunError> {
    u64::try_from(value).map_err(|_| IndexRunError::IntegerOverflow)
}

fn varint_len(mut value: u64) -> usize {
    let mut length = 1;
    while value >= 0x80 {
        value >>= 7;
        length += 1;
    }
    length
}

struct Writer {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Writer {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn reserve(&self, additional: usize) -> Result<(), IndexRunError> {
        let actual = self
            .bytes
            .len()
            .checked_add(additional)
            .ok_or(IndexRunError::IntegerOverflow)?;
        validate_count("encoded bytes", actual, self.maximum)
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), IndexRunError> {
        self.reserve(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), IndexRunError> {
        self.bytes(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<(), IndexRunError> {
        self.bytes(&value.to_be_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), IndexRunError> {
        self.bytes(&value.to_be_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), IndexRunError> {
        self.bytes(&value.to_be_bytes())
    }

    fn i64(&mut self, value: i64) -> Result<(), IndexRunError> {
        self.bytes(&value.to_be_bytes())
    }

    fn varint(&mut self, mut value: u64) -> Result<(), IndexRunError> {
        loop {
            let low = u8::try_from(value & 0x7f).map_err(|_| IndexRunError::IntegerOverflow)?;
            value >>= 7;
            self.u8(if value == 0 { low } else { low | 0x80 })?;
            if value == 0 {
                return Ok(());
            }
        }
    }

    fn string(
        &mut self,
        value: &str,
        maximum: usize,
        field: &'static str,
    ) -> Result<(), IndexRunError> {
        validate_count(field, value.len(), maximum)?;
        self.varint(usize_to_u64(value.len())?)?;
        self.bytes(value.as_bytes())
    }

    fn record(&mut self, record: Writer) -> Result<(), IndexRunError> {
        self.varint(usize_to_u64(record.bytes.len())?)?;
        self.bytes(&record.bytes)
    }
}

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], IndexRunError> {
        if length > self.remaining.len() {
            return Err(IndexRunError::UnexpectedEof);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, IndexRunError> {
        self.bytes(1)?
            .first()
            .copied()
            .ok_or(IndexRunError::UnexpectedEof)
    }

    fn u16(&mut self) -> Result<u16, IndexRunError> {
        let mut bytes = [0_u8; 2];
        bytes.copy_from_slice(self.bytes(2)?);
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, IndexRunError> {
        let mut bytes = [0_u8; 4];
        bytes.copy_from_slice(self.bytes(4)?);
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, IndexRunError> {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(self.bytes(8)?);
        Ok(u64::from_be_bytes(bytes))
    }

    fn i64(&mut self) -> Result<i64, IndexRunError> {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(self.bytes(8)?);
        Ok(i64::from_be_bytes(bytes))
    }

    fn varint(&mut self) -> Result<u64, IndexRunError> {
        let mut value = 0_u64;
        for index in 0_u32..10 {
            let byte = self.u8()?;
            let low = u64::from(byte & 0x7f);
            if index == 9 && low > 1 {
                return Err(IndexRunError::IntegerOverflow);
            }
            value |= low << (index * 7);
            if byte & 0x80 == 0 {
                if index > 0 && low == 0 {
                    return Err(IndexRunError::NonCanonicalVarint);
                }
                return Ok(value);
            }
        }
        Err(IndexRunError::IntegerOverflow)
    }

    fn u32_varint(&mut self) -> Result<u32, IndexRunError> {
        u32::try_from(self.varint()?).map_err(|_| IndexRunError::IntegerOverflow)
    }

    fn bounded_count(
        &mut self,
        field: &'static str,
        maximum: usize,
    ) -> Result<usize, IndexRunError> {
        let value = usize::try_from(self.varint()?).map_err(|_| IndexRunError::IntegerOverflow)?;
        validate_count(field, value, maximum)?;
        Ok(value)
    }

    fn record(&mut self, maximum: usize) -> Result<Reader<'a>, IndexRunError> {
        let length = self.bounded_count("record bytes", maximum)?;
        Ok(Self::new(self.bytes(length)?))
    }

    fn typed_string<T, E>(
        &mut self,
        field: &'static str,
        maximum: usize,
        constructor: impl FnOnce(String) -> Result<T, E>,
    ) -> Result<T, IndexRunError> {
        let length = self.bounded_count(field, maximum)?;
        let text = std::str::from_utf8(self.bytes(length)?)
            .map_err(|_| IndexRunError::InvalidUtf8 { field })?;
        constructor(text.to_owned()).map_err(|_| IndexRunError::InvalidValue { field })
    }

    fn finish_record(self) -> Result<(), IndexRunError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(IndexRunError::RecordLengthMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::PayloadHeaderReference;
    use crate::run::{
        INDEX_RUN_PLAINTEXT_DOMAIN, IndexBlindKey, IndexMutation, IndexPackRecordPointer,
        IndexPayloadPointer, IndexRun, IndexRunContainer, IndexRunError, IndexRunFrameRole,
        IndexRunKeyringRef, IndexRunLimits, IndexRunSearchBound, IndexRunSelfPack,
        IndexRunSelfStream, IndexRunStandaloneStreamContainer, IndexRunStreamContainer,
        IndexTombstone, IndexUpsert, decode_index_run, decode_index_run_frames, encode_index_run,
        encode_index_run_frames,
    };
    use rs3_types::{
        BackendObjectId, BackendVersionId, BlindIndexKey, KeyId, LegalHoldStatus, LogicalPath,
        RetentionMode, RetentionPolicy, Sequence,
    };

    fn fixture() -> IndexRun {
        IndexRun {
            sequence: Sequence::new(9),
            self_pack: None,
            self_stream: None,
            containers: vec![IndexRunContainer {
                object_id: BackendObjectId::new("objects/pack-a").expect("object id"),
                version_id: Some(BackendVersionId::new("version-3").expect("version id")),
                stored_len: 4_096,
                commit_body_digest: [0x22; 32],
                keyring_envelope: IndexRunKeyringRef {
                    object_id: BackendObjectId::new("keyrings/historical").expect("object id"),
                    digest: [0x23; 32],
                },
                pack_section_ordinal: 3,
                pack_section_offset: 512,
                pack_section_len: 2_048,
                pack_id: [0x11; 32],
                content_key_id: KeyId::new("content-1").expect("key id"),
                pack_record_count: 8,
            }],
            stream_containers: Vec::new(),
            standalone_stream_containers: Vec::new(),
            mutations: vec![
                IndexMutation::Upsert(IndexUpsert {
                    mutation_ordinal: 0,
                    blind_key: IndexBlindKey::from_bytes([0x33; 32]),
                    namespace_key_id: KeyId::new("namespace-1").expect("key id"),
                    path: LogicalPath::new("tenant/snapshot/chunk").expect("path"),
                    generation: Sequence::new(17),
                    payload: IndexPayloadPointer::ExternalPack {
                        container_ordinal: 0,
                        record: IndexPackRecordPointer {
                            record_ordinal: 7,
                            physical_offset: 100,
                        },
                    },
                    content_len: 1_234,
                    modified_at_ms: -55,
                    retention: Some(RetentionPolicy::new(RetentionMode::Compliance, 30)),
                    legal_hold: Some(LegalHoldStatus::On),
                }),
                IndexMutation::Tombstone(IndexTombstone {
                    mutation_ordinal: 1,
                    blind_key: IndexBlindKey::from_bytes([0x44; 32]),
                    namespace_key_id: KeyId::new("namespace-1").expect("key id"),
                    path: LogicalPath::new("tenant/deleted").expect("path"),
                    generation: Sequence::new(18),
                }),
            ],
        }
    }

    fn two_namespace_key_fixture() -> IndexRun {
        let mut run = fixture();
        let IndexMutation::Upsert(upsert) = &mut run.mutations[0] else {
            panic!("fixture starts with an upsert");
        };
        upsert.namespace_key_id = KeyId::new("namespace-b").expect("namespace key id");
        let IndexMutation::Tombstone(tombstone) = &mut run.mutations[1] else {
            panic!("fixture ends with a tombstone");
        };
        tombstone.namespace_key_id = KeyId::new("namespace-a").expect("namespace key id");
        run
    }

    fn stream_header() -> PayloadHeaderReference {
        PayloadHeaderReference {
            chunk_size: 64 * 1024,
            plaintext_len: 131_089,
            key_id: KeyId::new("stream-content-1").expect("content key id"),
            nonce_prefix: [0x91; 16],
            header_len: 73,
        }
    }

    fn stream_container() -> IndexRunStreamContainer {
        let payload_header = stream_header();
        let payload_section_len = payload_header.header_len
            + payload_header.plaintext_len
            + payload_header
                .plaintext_len
                .div_ceil(payload_header.chunk_size)
                * 16;
        IndexRunStreamContainer {
            object_id: BackendObjectId::new("commits/v02/stream-a").expect("object id"),
            version_id: Some(BackendVersionId::new("version-stream-4").expect("version id")),
            stored_len: 140_000,
            commit_body_digest: [0x81; 32],
            keyring_envelope: IndexRunKeyringRef {
                object_id: BackendObjectId::new("keyrings/stream-historical")
                    .expect("keyring object id"),
                digest: [0x82; 32],
            },
            sections_start: 8_192,
            payload_section_ordinal: 0,
            payload_section_offset: 0,
            payload_section_len,
            payload_section_digest: [0x83; 32],
            payload_id: BackendObjectId::new("payloads/stream-a").expect("payload id"),
            payload_header,
        }
    }

    fn self_stream_fixture() -> IndexRun {
        let mut run = fixture();
        run.containers.clear();
        run.self_stream = Some(IndexRunSelfStream {
            payload_section_ordinal: 0,
            payload_id: BackendObjectId::new("payloads/self-stream").expect("payload id"),
            payload_header: stream_header(),
        });
        let IndexMutation::Upsert(upsert) = &mut run.mutations[0] else {
            panic!("fixture starts with an upsert");
        };
        upsert.payload = IndexPayloadPointer::SelfStream;
        upsert.content_len = stream_header().plaintext_len;
        run
    }

    fn external_stream_fixture() -> IndexRun {
        let mut run = fixture();
        run.containers.clear();
        run.stream_containers.push(stream_container());
        let IndexMutation::Upsert(upsert) = &mut run.mutations[0] else {
            panic!("fixture starts with an upsert");
        };
        upsert.payload = IndexPayloadPointer::ExternalStream {
            container_ordinal: 0,
        };
        upsert.content_len = stream_header().plaintext_len;
        run
    }

    fn standalone_stream_container(byte: u8) -> IndexRunStandaloneStreamContainer {
        let payload_header = stream_header();
        let stored_len = payload_header.header_len
            + payload_header.plaintext_len
            + payload_header
                .plaintext_len
                .div_ceil(payload_header.chunk_size)
                * 16;
        IndexRunStandaloneStreamContainer {
            object_id: BackendObjectId::new(format!("objects/v02/standalone-{byte}"))
                .expect("object id"),
            version_id: Some(
                BackendVersionId::new(format!("version-standalone-{byte}")).expect("version id"),
            ),
            stored_len,
            object_digest: [byte; 32],
            keyring_envelope: IndexRunKeyringRef {
                object_id: BackendObjectId::new("keyrings/standalone-historical")
                    .expect("keyring object id"),
                digest: [byte.wrapping_add(1); 32],
            },
            payload_header,
        }
    }

    fn standalone_stream_fixture() -> IndexRun {
        let mut run = fixture();
        run.containers.clear();
        run.standalone_stream_containers
            .push(standalone_stream_container(0x94));
        let IndexMutation::Upsert(upsert) = &mut run.mutations[0] else {
            panic!("fixture starts with an upsert");
        };
        upsert.payload = IndexPayloadPointer::ExternalStandaloneStream {
            container_ordinal: 0,
        };
        upsert.content_len = stream_header().plaintext_len;
        run
    }

    #[test]
    fn round_trips_all_fields() {
        let run = fixture();
        let limits = IndexRunLimits::default();
        let encoded = encode_index_run(&run, &limits).expect("encode run");
        let decoded = decode_index_run(&encoded, &limits).expect("decode run");

        assert_eq!(decoded, run);
        let IndexMutation::Upsert(upsert) = &decoded.mutations[0] else {
            panic!("fixture starts with an upsert");
        };
        let IndexMutation::Tombstone(tombstone) = &decoded.mutations[1] else {
            panic!("fixture ends with a tombstone");
        };
        assert_eq!(
            upsert.namespace_key_id.as_str().as_ptr(),
            tombstone.namespace_key_id.as_str().as_ptr(),
            "decoded table references should share KeyId storage"
        );
    }

    #[test]
    fn namespace_key_table_is_sorted_unique_and_referenced_by_ordinal() {
        let run = two_namespace_key_fixture();
        let limits = IndexRunLimits::default();
        let encoded = encode_index_run_frames(&run, &limits).expect("encode key table");
        let frames = frame_bytes(encoded.clone());
        let all_bytes = frames.concat();

        assert_eq!(
            all_bytes
                .windows(b"namespace-a".len())
                .filter(|window| *window == b"namespace-a")
                .count(),
            1
        );
        assert_eq!(
            all_bytes
                .windows(b"namespace-b".len())
                .filter(|window| *window == b"namespace-b")
                .count(),
            1
        );
        assert!(
            all_bytes
                .windows(b"namespace-a".len())
                .position(|window| window == b"namespace-a")
                < all_bytes
                    .windows(b"namespace-b".len())
                    .position(|window| window == b"namespace-b")
        );
        assert_eq!(decode_index_run_frames(&frames, &limits), Ok(run));
    }

    #[test]
    fn rejects_malformed_namespace_key_tables_and_ordinals() {
        let run = two_namespace_key_fixture();
        let limits = IndexRunLimits::default();
        let encoded = encode_index_run_frames(&run, &limits).expect("encode key table");

        let mut duplicate = frame_bytes(encoded.clone());
        replace_frame_bytes(&mut duplicate, b"namespace-b", b"namespace-a");
        assert_eq!(
            decode_index_run_frames(&duplicate, &limits),
            Err(IndexRunError::DuplicateNamespaceKey)
        );

        let mut unsorted = frame_bytes(encoded.clone());
        replace_frame_bytes(&mut unsorted, b"namespace-a", b"namespace-z");
        assert_eq!(
            decode_index_run_frames(&unsorted, &limits),
            Err(IndexRunError::InvalidNamespaceKeyOrder)
        );

        let mut unused = frame_bytes(encoded.clone());
        set_namespace_key_ordinal(&mut unused, 0x33, 0);
        assert_eq!(
            decode_index_run_frames(&unused, &limits),
            Err(IndexRunError::UnusedNamespaceKey(1))
        );

        let mut out_of_range = frame_bytes(encoded);
        set_namespace_key_ordinal(&mut out_of_range, 0x33, 2);
        assert_eq!(
            decode_index_run_frames(&out_of_range, &limits),
            Err(IndexRunError::InvalidNamespaceKeyOrdinal(2))
        );
    }

    #[test]
    fn namespace_key_table_limits_fail_closed() {
        let limits = IndexRunLimits {
            max_mutations: 2,
            ..IndexRunLimits::default()
        };
        let encoded = encode_index_run_frames(&fixture(), &limits).expect("encode key table");
        let mut excessive_count = frame_bytes(encoded);
        let table_count_offset = INDEX_RUN_PLAINTEXT_DOMAIN.len() + 2 + 1 + 4 + 8 + 3 + 1;
        excessive_count[0][table_count_offset] = 3;
        assert_eq!(
            decode_index_run_frames(&excessive_count, &limits),
            Err(IndexRunError::LimitExceeded {
                field: "namespace key count",
                actual: 3,
                maximum: 2,
            })
        );

        let encoded = encode_index_run_frames(&fixture(), &IndexRunLimits::default())
            .expect("encode key table");
        let short_key_limit = IndexRunLimits {
            max_key_id_bytes: 10,
            ..IndexRunLimits::default()
        };
        assert_eq!(
            decode_index_run_frames(&frame_bytes(encoded), &short_key_limit),
            Err(IndexRunError::LimitExceeded {
                field: "namespace key id",
                actual: 11,
                maximum: 10,
            })
        );
    }

    #[test]
    fn self_and_external_streams_round_trip_canonically() {
        let limits = IndexRunLimits::default();
        for run in [
            self_stream_fixture(),
            external_stream_fixture(),
            standalone_stream_fixture(),
        ] {
            let encoded = encode_index_run(&run, &limits).expect("encode stream run");
            assert_eq!(
                decode_index_run(&encoded, &limits),
                Ok(run),
                "stream run must round trip"
            );
        }
    }

    #[test]
    fn standalone_stream_requires_exact_length_and_use() {
        let limits = IndexRunLimits::default();
        let mut run = standalone_stream_fixture();
        run.standalone_stream_containers[0].stored_len += 1;
        assert_eq!(
            encode_index_run_frames(&run, &limits),
            Err(IndexRunError::InvalidStandaloneStreamContainer)
        );

        run = standalone_stream_fixture();
        run.standalone_stream_containers
            .push(standalone_stream_container(0x95));
        assert_eq!(
            encode_index_run_frames(&run, &limits),
            Err(IndexRunError::UnusedStandaloneStreamContainer(1))
        );

        run.standalone_stream_containers.swap(0, 1);
        assert_eq!(
            encode_index_run_frames(&run, &limits),
            Err(IndexRunError::InvalidContainerOrder)
        );
    }

    #[test]
    fn zero_plaintext_standalone_stream_keeps_its_authenticated_object() {
        let limits = IndexRunLimits::default();
        let mut run = standalone_stream_fixture();
        let container = &mut run.standalone_stream_containers[0];
        container.payload_header.plaintext_len = 0;
        container.stored_len = container.payload_header.header_len;
        let IndexMutation::Upsert(upsert) = &mut run.mutations[0] else {
            panic!("fixture starts with an upsert");
        };
        upsert.content_len = 0;

        let encoded = encode_index_run(&run, &limits).expect("encode zero standalone stream");
        assert_eq!(decode_index_run(&encoded, &limits), Ok(run));
    }

    #[test]
    fn container_limit_counts_standalone_and_commit_streams_together() {
        let mut limits = IndexRunLimits {
            max_containers: 1,
            ..IndexRunLimits::default()
        };
        let mut run = standalone_stream_fixture();
        run.stream_containers.push(stream_container());
        let IndexMutation::Upsert(mut peer) = run.mutations[0].clone() else {
            panic!("fixture starts with an upsert");
        };
        peer.mutation_ordinal = 2;
        peer.blind_key = IndexBlindKey::from_bytes([0x97; 32]);
        peer.path = LogicalPath::new("tenant/commit-stream-limit-peer").expect("path");
        peer.payload = IndexPayloadPointer::ExternalStream {
            container_ordinal: 0,
        };
        run.mutations.push(IndexMutation::Upsert(peer));

        assert_eq!(
            encode_index_run_frames(&run, &limits),
            Err(IndexRunError::LimitExceeded {
                field: "container count",
                actual: 2,
                maximum: 1,
            })
        );

        limits.max_containers = 2;
        assert!(encode_index_run_frames(&run, &limits).is_ok());
    }

    #[test]
    fn standalone_stream_rejects_invalid_pointer_and_cross_table_alias() {
        let limits = IndexRunLimits::default();
        let mut run = standalone_stream_fixture();
        let IndexMutation::Upsert(upsert) = &mut run.mutations[0] else {
            panic!("fixture starts with an upsert");
        };
        upsert.payload = IndexPayloadPointer::ExternalStandaloneStream {
            container_ordinal: 1,
        };
        assert_eq!(
            encode_index_run_frames(&run, &limits),
            Err(IndexRunError::InvalidContainerOrdinal(1))
        );

        run = standalone_stream_fixture();
        let mut commit_stream = stream_container();
        commit_stream.object_id = run.standalone_stream_containers[0].object_id.clone();
        commit_stream.version_id = run.standalone_stream_containers[0].version_id.clone();
        run.stream_containers.push(commit_stream);
        let IndexMutation::Upsert(mut peer) = run.mutations[0].clone() else {
            panic!("fixture starts with an upsert");
        };
        peer.mutation_ordinal = 2;
        peer.blind_key = IndexBlindKey::from_bytes([0x96; 32]);
        peer.path = LogicalPath::new("tenant/commit-stream-peer").expect("path");
        peer.payload = IndexPayloadPointer::ExternalStream {
            container_ordinal: 0,
        };
        run.mutations.push(IndexMutation::Upsert(peer));
        assert_eq!(
            encode_index_run_frames(&run, &limits),
            Err(IndexRunError::DuplicateContainer)
        );
    }

    #[test]
    fn decoder_rejects_pre_v6_frames() {
        let limits = IndexRunLimits::default();
        let mut encoded = encode_index_run(&standalone_stream_fixture(), &limits)
            .expect("encode standalone stream run");
        let domain_offset = encoded
            .windows(INDEX_RUN_PLAINTEXT_DOMAIN.len())
            .position(|window| window == INDEX_RUN_PLAINTEXT_DOMAIN)
            .expect("frame domain");
        let version_offset = domain_offset + INDEX_RUN_PLAINTEXT_DOMAIN.len();
        encoded[version_offset..version_offset + 2].copy_from_slice(&5_u16.to_be_bytes());

        assert_eq!(
            decode_index_run(&encoded, &limits),
            Err(IndexRunError::UnsupportedVersion(5))
        );
    }

    #[test]
    fn zero_plaintext_stream_keeps_its_authenticated_carrier() {
        let limits = IndexRunLimits::default();
        let mut run = self_stream_fixture();
        run.self_stream
            .as_mut()
            .expect("self stream")
            .payload_header
            .plaintext_len = 0;
        let IndexMutation::Upsert(upsert) = &mut run.mutations[0] else {
            panic!("fixture starts with an upsert");
        };
        upsert.content_len = 0;

        let encoded = encode_index_run(&run, &limits).expect("encode zero plaintext stream");
        assert_eq!(decode_index_run(&encoded, &limits), Ok(run));
    }

    #[test]
    fn one_self_stream_can_back_multiple_namespace_mutations() {
        let limits = IndexRunLimits::default();
        let mut run = self_stream_fixture();
        let IndexMutation::Upsert(mut rotated) = run.mutations[0].clone() else {
            panic!("fixture starts with an upsert");
        };
        rotated.mutation_ordinal = 2;
        rotated.blind_key = IndexBlindKey::from_bytes([0x92; 32]);
        rotated.namespace_key_id = KeyId::new("namespace-rotated").expect("namespace key id");
        run.mutations.push(IndexMutation::Upsert(rotated));

        let encoded = encode_index_run(&run, &limits).expect("encode shared self stream");
        assert_eq!(decode_index_run(&encoded, &limits), Ok(run));
    }

    #[test]
    fn streamed_payloads_require_exact_matching_declarations() {
        let limits = IndexRunLimits::default();
        let mut run = self_stream_fixture();
        run.self_pack = Some(IndexRunSelfPack {
            pack_id: [0x71; 32],
            content_key_id: KeyId::new("pack-content").expect("content key id"),
            stored_len: 256,
            record_count: 1,
        });
        assert_eq!(
            encode_index_run_frames(&run, &limits),
            Err(IndexRunError::InvalidSelfStream)
        );

        run = self_stream_fixture();
        let IndexMutation::Upsert(upsert) = &mut run.mutations[0] else {
            panic!("fixture starts with an upsert");
        };
        upsert.content_len += 1;
        assert_eq!(
            encode_index_run_frames(&run, &limits),
            Err(IndexRunError::InvalidSelfStream)
        );

        run = external_stream_fixture();
        run.stream_containers[0].payload_header.plaintext_len += 1;
        assert_eq!(
            encode_index_run_frames(&run, &limits),
            Err(IndexRunError::InvalidStreamContainer)
        );
    }

    #[test]
    fn rejects_invalid_or_unused_stream_containers() {
        let limits = IndexRunLimits::default();
        let mut run = external_stream_fixture();
        run.stream_containers[0].payload_section_len -= 1;
        assert_eq!(
            encode_index_run_frames(&run, &limits),
            Err(IndexRunError::InvalidStreamContainer)
        );

        run = external_stream_fixture();
        let mut unused = run.stream_containers[0].clone();
        unused.object_id = BackendObjectId::new("commits/v02/stream-b").expect("object id");
        run.stream_containers.push(unused);
        assert_eq!(
            encode_index_run_frames(&run, &limits),
            Err(IndexRunError::UnusedStreamContainer(1))
        );

        run.stream_containers.swap(0, 1);
        assert_eq!(
            encode_index_run_frames(&run, &limits),
            Err(IndexRunError::InvalidContainerOrder)
        );
    }

    #[test]
    fn rejects_tampered_stream_container_ranges_during_decode() {
        let limits = IndexRunLimits::default();
        let run = external_stream_fixture();
        let expected_len = run.stream_containers[0].payload_section_len.to_be_bytes();
        let mut encoded = encode_index_run(&run, &limits).expect("encode stream run");
        let offset = encoded
            .windows(expected_len.len())
            .position(|window| window == expected_len)
            .expect("stream section length");
        encoded[offset + expected_len.len() - 1] ^= 1;

        assert_eq!(
            decode_index_run(&encoded, &limits),
            Err(IndexRunError::InvalidStreamContainer)
        );
    }

    #[test]
    fn rejects_one_exact_object_in_both_container_tables() {
        let limits = IndexRunLimits::default();
        let mut run = external_stream_fixture();
        run.stream_containers[0].object_id = run.containers.first().map_or_else(
            || BackendObjectId::new("objects/pack-a").expect("pack object id"),
            |container| container.object_id.clone(),
        );
        run.stream_containers[0].version_id =
            Some(BackendVersionId::new("version-3").expect("matching pack version id"));
        run.containers = fixture().containers;
        let IndexMutation::Upsert(mut pack_upsert) = run.mutations[0].clone() else {
            panic!("fixture starts with an upsert");
        };
        pack_upsert.mutation_ordinal = 2;
        pack_upsert.blind_key = IndexBlindKey::from_bytes([0x72; 32]);
        pack_upsert.path = LogicalPath::new("tenant/pack-peer").expect("path");
        pack_upsert.payload = IndexPayloadPointer::ExternalPack {
            container_ordinal: 0,
            record: IndexPackRecordPointer {
                record_ordinal: 0,
                physical_offset: 0,
            },
        };
        pack_upsert.content_len = 16;
        run.mutations.push(IndexMutation::Upsert(pack_upsert));

        assert_eq!(
            encode_index_run_frames(&run, &limits),
            Err(IndexRunError::DuplicateContainer)
        );
    }

    #[test]
    fn converts_only_canonical_lowercase_blind_key_hex() {
        let raw = IndexBlindKey::from_bytes([0xab; 32]);
        let typed = raw.to_blind_index_key().expect("typed blind key");
        assert_eq!(IndexBlindKey::try_from(&typed), Ok(raw));

        let uppercase = BlindIndexKey::new("AB".repeat(32)).expect("legacy type accepts text");
        assert_eq!(
            IndexBlindKey::try_from(&uppercase),
            Err(IndexRunError::InvalidValue { field: "blind key" })
        );
    }

    #[test]
    fn rejects_every_truncation() {
        let limits = IndexRunLimits::default();
        let encoded = encode_index_run(&fixture(), &limits).expect("encode run");
        for length in 0..encoded.len() {
            assert!(
                decode_index_run(&encoded[..length], &limits).is_err(),
                "accepted truncation at {length}"
            );
        }
    }

    #[test]
    fn rejects_oversized_input_and_fields() {
        let run = fixture();
        let encoded = encode_index_run(&run, &IndexRunLimits::default()).expect("encode run");
        let mut limits = IndexRunLimits {
            max_total_bytes: encoded.len() - 1,
            ..IndexRunLimits::default()
        };
        assert!(matches!(
            decode_index_run(&encoded, &limits),
            Err(IndexRunError::LimitExceeded {
                field: "total bytes",
                ..
            })
        ));

        limits = IndexRunLimits {
            max_path_bytes: 3,
            ..IndexRunLimits::default()
        };
        assert!(matches!(
            encode_index_run(&run, &limits),
            Err(IndexRunError::LimitExceeded {
                field: "logical path",
                ..
            })
        ));
        assert!(matches!(
            decode_index_run(&encoded, &limits),
            Err(IndexRunError::LimitExceeded {
                field: "logical path",
                ..
            })
        ));
    }

    #[test]
    fn rejects_noncanonical_varint() {
        let limits = IndexRunLimits::default();
        let mut frames =
            frame_bytes(encode_index_run_frames(&fixture(), &limits).expect("encode framed run"));
        let mutation_count_offset = INDEX_RUN_PLAINTEXT_DOMAIN.len() + 2 + 1 + 4 + 8;
        frames[0].splice(mutation_count_offset..=mutation_count_offset, [0x82, 0x00]);

        assert_eq!(
            decode_index_run_frames(&frames, &limits),
            Err(IndexRunError::NonCanonicalVarint)
        );
    }

    #[test]
    fn rejects_out_of_order_and_duplicate_mutation_ordinals() {
        let limits = IndexRunLimits::default();
        let mut run = fixture();
        if let IndexMutation::Tombstone(tombstone) = &mut run.mutations[1] {
            tombstone.mutation_ordinal = 0;
        }
        assert_eq!(
            encode_index_run(&run, &limits),
            Err(IndexRunError::InvalidMutationOrdinal {
                expected: 1,
                actual: 0,
            })
        );
    }

    #[test]
    fn rejects_empty_overflowing_and_out_of_bounds_container_ranges() {
        let limits = IndexRunLimits::default();
        let mut run = fixture();
        run.containers[0].pack_section_len = 0;
        assert_eq!(
            encode_index_run(&run, &limits),
            Err(IndexRunError::InvalidContainerRange)
        );

        run.containers[0].pack_section_offset = u64::MAX;
        run.containers[0].pack_section_len = 1;
        assert_eq!(
            encode_index_run(&run, &limits),
            Err(IndexRunError::InvalidContainerRange)
        );

        run.containers[0].pack_section_offset = 3_072;
        run.containers[0].pack_section_len = 2_048;
        assert_eq!(
            encode_index_run(&run, &limits),
            Err(IndexRunError::InvalidContainerRange)
        );

        let mut encoded =
            encode_index_run(&fixture(), &limits).expect("encode valid container range");
        let range = [
            512_u64.to_be_bytes().as_slice(),
            2_048_u64.to_be_bytes().as_slice(),
        ]
        .concat();
        let range_start = encoded
            .windows(range.len())
            .position(|window| window == range)
            .expect("fixture range bytes");
        encoded[range_start + 8..range_start + 16].fill(0);
        assert_eq!(
            decode_index_run(&encoded, &limits),
            Err(IndexRunError::InvalidContainerRange)
        );
    }

    #[test]
    fn rejects_duplicate_exact_containers_even_when_facts_disagree() {
        let limits = IndexRunLimits::default();
        let mut run = fixture();
        let mut duplicate = run.containers[0].clone();
        duplicate.stored_len = 8_192;
        duplicate.commit_body_digest = [0x55; 32];
        run.containers.push(duplicate);
        assert_eq!(
            encode_index_run(&run, &limits),
            Err(IndexRunError::DuplicateContainer)
        );

        run.containers[1].object_id =
            BackendObjectId::new("objects/pack-b").expect("distinct object id");
        let IndexMutation::Upsert(mut second_upsert) = run.mutations[0].clone() else {
            panic!("fixture starts with upsert");
        };
        second_upsert.mutation_ordinal = 2;
        second_upsert.blind_key = IndexBlindKey::from_bytes([0x55; 32]);
        second_upsert.path = LogicalPath::new("tenant/second").expect("second path");
        second_upsert.payload = IndexPayloadPointer::ExternalPack {
            container_ordinal: 1,
            record: IndexPackRecordPointer {
                record_ordinal: 0,
                physical_offset: 100,
            },
        };
        run.mutations.push(IndexMutation::Upsert(second_upsert));
        let mut encoded = encode_index_run(&run, &limits).expect("encode distinct containers");
        let object_id = b"objects/pack-b";
        let object_id_start = encoded
            .windows(object_id.len())
            .position(|window| window == object_id)
            .expect("second object id bytes");
        encoded[object_id_start + object_id.len() - 1] = b'a';
        assert_eq!(
            decode_index_run(&encoded, &limits),
            Err(IndexRunError::DuplicateContainer)
        );
    }

    #[test]
    fn canonical_vector_is_stable() {
        let encoded = encode_index_run(&fixture(), &IndexRunLimits::default()).expect("encode run");
        assert_eq!(
            hex(&encoded),
            "03fb017273333a696e6465782d72756e2d6672616d652d706c61696e746578743a76320a0006000000000000000000000000090202020001b601000e6f626a656374732f7061636b2d61010976657273696f6e2d3300000000000010002222222222222222222222222222222222222222222222222222222222222222136b657972696e67732f686973746f726963616c23232323232323232323232323232323232323232323232323232323232323230000000300000000000002000000000000000800111111111111111111111111111111111111111111111111111111111111111109636f6e74656e742d31080d030b6e616d6573706163652d3192017273333a696e6465782d72756e2d6672616d652d706c61696e746578743a76320a0006010000000000000000000000090202023900003333333333333333333333333333333333333333333333333333333333333333001102000764d209ffffffffffffffc901020000001e02240101444444444444444444444444444444444444444444444444444444444444444400126a7273333a696e6465782d72756e2d6672616d652d706c61696e746578743a76320a0006020000000000000000000000090202021201010e74656e616e742f64656c65746564122300001574656e616e742f736e617073686f742f6368756e6b11d209ffffffffffffffc9"
        );
    }

    #[test]
    fn debug_output_redacts_paths_and_frame_plaintext() {
        let run = fixture();
        let debug = format!("{run:?}");
        assert!(!debug.contains("tenant/snapshot/chunk"));
        assert!(!debug.contains("tenant/deleted"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("[17, 17, 17"));
        assert!(!debug.contains("[102, 102, 102"));

        let encoded = encode_index_run_frames(&run, &IndexRunLimits::default())
            .expect("encode redaction fixture");
        let debug = format!("{encoded:?}");
        assert!(!debug.contains("tenant/snapshot/chunk"));
        assert!(!debug.contains("tenant/deleted"));
        assert!(!debug.contains("plaintext: ["));
    }

    #[test]
    fn frames_are_bounded_typed_and_canonically_sorted() {
        let limits = IndexRunLimits {
            max_frame_bytes: 300,
            ..IndexRunLimits::default()
        };
        let encoded = encode_index_run_frames(&fixture(), &limits).expect("encode frames");
        assert!(encoded.frames.iter().all(|frame| frame.bytes.len() <= 300));
        assert_eq!(encoded.frames[0].role, IndexRunFrameRole::Metadata);
        let namespace = encoded
            .frames
            .iter()
            .find(|frame| frame.role == IndexRunFrameRole::Namespace)
            .expect("namespace frame");
        assert_eq!(
            namespace.first_bound,
            Some(IndexRunSearchBound::Namespace {
                blind_key: IndexBlindKey::from_bytes([0x33; 32]),
                mutation_ordinal: 0,
            })
        );
        let listing = encoded
            .frames
            .iter()
            .find(|frame| frame.role == IndexRunFrameRole::Listing)
            .expect("listing frame");
        assert_eq!(
            listing.first_bound,
            Some(IndexRunSearchBound::Listing {
                path: LogicalPath::new("tenant/deleted").expect("path"),
                mutation_ordinal: 1,
            })
        );
        assert_eq!(
            decode_index_run_frames(&frame_bytes(encoded), &limits),
            Ok(fixture())
        );
    }

    #[test]
    fn rejects_projection_fact_mismatch_and_duplicate_ordinal() {
        let limits = IndexRunLimits::default();
        let encoded = encode_index_run_frames(&fixture(), &limits).expect("encode frames");
        let mut mismatched = frame_bytes(encoded.clone());
        let listing_index = encoded
            .frames
            .iter()
            .position(|frame| frame.role == IndexRunFrameRole::Listing)
            .expect("listing frame");
        let content_len = [0xd2, 0x09];
        let content_len_offset = mismatched[listing_index]
            .windows(content_len.len())
            .position(|window| window == content_len)
            .expect("listing content length");
        mismatched[listing_index][content_len_offset + 1] ^= 1;
        assert_eq!(
            decode_index_run_frames(&mismatched, &limits),
            Err(IndexRunError::ProjectionMismatch { ordinal: 0 })
        );

        let mut duplicate = frame_bytes(encoded);
        let upsert_prefix = [0_u8, 0_u8, 21_u8];
        let ordinal_offset = duplicate[listing_index]
            .windows(upsert_prefix.len())
            .position(|window| window == upsert_prefix)
            .expect("listing upsert prefix");
        duplicate[listing_index][ordinal_offset] = 1;
        assert_eq!(
            decode_index_run_frames(&duplicate, &limits),
            Err(IndexRunError::DuplicateProjectionOrdinal {
                projection: "listing",
                ordinal: 1,
            })
        );
    }

    #[test]
    fn empty_payload_is_required_exactly_for_empty_content() {
        let limits = IndexRunLimits::default();
        let mut run = fixture();
        if let IndexMutation::Upsert(upsert) = &mut run.mutations[0] {
            upsert.content_len = 0;
        }
        assert_eq!(
            encode_index_run_frames(&run, &limits),
            Err(IndexRunError::InvalidEmptyPayload)
        );

        if let IndexMutation::Upsert(upsert) = &mut run.mutations[0] {
            upsert.payload = IndexPayloadPointer::Empty;
        }
        run.containers.clear();
        let encoded = encode_index_run_frames(&run, &limits).expect("encode empty object");
        assert_eq!(
            decode_index_run_frames(&frame_bytes(encoded), &limits),
            Ok(run)
        );
    }

    #[test]
    fn pack_record_counts_bound_pointers_without_payload_reads() {
        let limits = IndexRunLimits::default();
        let mut run = fixture();
        if let IndexMutation::Upsert(upsert) = &mut run.mutations[0] {
            upsert.payload = IndexPayloadPointer::ExternalPack {
                container_ordinal: 0,
                record: IndexPackRecordPointer {
                    record_ordinal: 8,
                    physical_offset: 100,
                },
            };
        }
        assert_eq!(
            encode_index_run_frames(&run, &limits),
            Err(IndexRunError::InvalidPackRecordCount)
        );

        if let IndexMutation::Upsert(upsert) = &mut run.mutations[0] {
            upsert.payload = IndexPayloadPointer::SelfPack {
                record: IndexPackRecordPointer {
                    record_ordinal: 2,
                    physical_offset: 100,
                },
            };
        }
        run.containers.clear();
        assert_eq!(
            encode_index_run_frames(&run, &limits),
            Err(IndexRunError::InvalidPackRecordCount)
        );
        run.self_pack = Some(IndexRunSelfPack {
            pack_id: [0x88; 32],
            content_key_id: KeyId::new("historical-content").expect("key id"),
            stored_len: 2_048,
            record_count: 3,
        });
        let encoded = encode_index_run_frames(&run, &limits).expect("encode self pack pointer");
        assert_eq!(
            decode_index_run_frames(&frame_bytes(encoded), &limits),
            Ok(run)
        );
    }

    #[test]
    fn rejects_out_of_pack_record_ranges_on_encode_and_decode() {
        let limits = IndexRunLimits::default();
        let mut run = fixture();
        set_fixture_physical_offset(&mut run, 799);
        assert_eq!(
            encode_index_run_frames(&run, &limits),
            Err(IndexRunError::InvalidPackRecordRange)
        );

        set_fixture_physical_offset(&mut run, 798);
        let encoded = encode_index_run_frames(&run, &limits).expect("boundary record range");
        let mut frames = frame_bytes(encoded);
        let encoded_offset = [0x9e, 0x06];
        let offset = frames
            .iter()
            .enumerate()
            .find_map(|(frame_index, frame)| {
                frame
                    .windows(encoded_offset.len())
                    .position(|window| window == encoded_offset)
                    .map(|offset| (frame_index, offset))
            })
            .expect("encoded physical offset");
        frames[offset.0][offset.1] = 0x9f;
        assert_eq!(
            decode_index_run_frames(&frames, &limits),
            Err(IndexRunError::InvalidPackRecordRange)
        );
    }

    #[test]
    fn rejects_mismatched_or_overlapping_repeated_record_facts() {
        let limits = IndexRunLimits::default();
        let mut run = fixture();
        let IndexMutation::Upsert(mut duplicate) = run.mutations[0].clone() else {
            panic!("fixture starts with upsert");
        };
        duplicate.mutation_ordinal = 2;
        duplicate.blind_key = IndexBlindKey::from_bytes([0x55; 32]);
        duplicate.path = LogicalPath::new("tenant/duplicate").expect("path");
        if let IndexPayloadPointer::ExternalPack { record, .. } = &mut duplicate.payload {
            record.physical_offset += 1;
        }
        run.mutations.push(IndexMutation::Upsert(duplicate.clone()));
        assert_eq!(
            encode_index_run_frames(&run, &limits),
            Err(IndexRunError::PackRecordFactsMismatch)
        );

        if let IndexPayloadPointer::ExternalPack { record, .. } = &mut duplicate.payload {
            record.physical_offset -= 1;
            record.record_ordinal = 6;
        }
        run.mutations[2] = IndexMutation::Upsert(duplicate);
        assert_eq!(
            encode_index_run_frames(&run, &limits),
            Err(IndexRunError::PackRecordFactsMismatch)
        );
    }

    #[test]
    fn rejects_transplanted_self_pack_facts_between_metadata_frames() {
        let limits = IndexRunLimits {
            max_frame_bytes: 320,
            ..IndexRunLimits::default()
        };
        let mut run = fixture();
        let mut second_container = run.containers[0].clone();
        second_container.object_id =
            BackendObjectId::new("objects/pack-b").expect("second object id");
        second_container.pack_id = [0x12; 32];
        run.containers.push(second_container);

        let IndexMutation::Upsert(mut external) = run.mutations[0].clone() else {
            panic!("fixture starts with upsert");
        };
        external.mutation_ordinal = 2;
        external.blind_key = IndexBlindKey::from_bytes([0x55; 32]);
        external.path = LogicalPath::new("tenant/external-two").expect("path");
        let IndexPayloadPointer::ExternalPack {
            container_ordinal, ..
        } = &mut external.payload
        else {
            panic!("fixture uses an external pack");
        };
        *container_ordinal = 1;
        run.mutations.push(IndexMutation::Upsert(external));

        let IndexMutation::Upsert(mut local) = run.mutations[0].clone() else {
            panic!("fixture starts with upsert");
        };
        local.mutation_ordinal = 3;
        local.blind_key = IndexBlindKey::from_bytes([0x77; 32]);
        local.path = LogicalPath::new("tenant/local").expect("path");
        local.payload = IndexPayloadPointer::SelfPack {
            record: IndexPackRecordPointer {
                record_ordinal: 0,
                physical_offset: 0,
            },
        };
        run.self_pack = Some(IndexRunSelfPack {
            pack_id: [0x88; 32],
            content_key_id: KeyId::new("historical-content").expect("key id"),
            stored_len: 1_250,
            record_count: 1,
        });
        run.mutations.push(IndexMutation::Upsert(local));

        let encoded = encode_index_run_frames(&run, &limits).expect("multi-frame metadata");
        let metadata: Vec<_> = encoded
            .frames
            .iter()
            .enumerate()
            .filter(|(_, frame)| frame.role == IndexRunFrameRole::Metadata)
            .map(|(index, _)| index)
            .collect();
        assert!(metadata.len() >= 2);
        let mut frames = frame_bytes(encoded);
        let pack_id_offset = frames[metadata[1]]
            .windows(32)
            .position(|window| window == [0x88; 32])
            .expect("repeated self-pack id");
        frames[metadata[1]][pack_id_offset] ^= 1;
        assert_eq!(
            decode_index_run_frames(&frames, &limits),
            Err(IndexRunError::FrameFactsMismatch)
        );
    }

    #[test]
    fn rejects_hostile_pack_fact_bounds() {
        let limits = IndexRunLimits::default();
        let mut run = fixture();
        run.containers[0].pack_section_len = super::INDEX_PACK_MAX_STORED_BYTES + 1;
        run.containers[0].stored_len = run.containers[0].pack_section_len;
        assert_eq!(
            encode_index_run_frames(&run, &limits),
            Err(IndexRunError::InvalidContainerRange)
        );

        run = fixture();
        run.containers[0].pack_record_count = super::INDEX_PACK_MAX_RECORDS + 1;
        assert_eq!(
            encode_index_run_frames(&run, &limits),
            Err(IndexRunError::InvalidContainerRange)
        );

        run = fixture();
        run.containers.clear();
        let IndexMutation::Upsert(upsert) = &mut run.mutations[0] else {
            panic!("fixture starts with upsert");
        };
        upsert.payload = IndexPayloadPointer::SelfPack {
            record: IndexPackRecordPointer {
                record_ordinal: 0,
                physical_offset: 0,
            },
        };
        run.self_pack = Some(IndexRunSelfPack {
            pack_id: [0x88; 32],
            content_key_id: KeyId::new("historical-content").expect("key id"),
            stored_len: super::INDEX_PACK_MAX_STORED_BYTES + 1,
            record_count: 1,
        });
        assert_eq!(
            encode_index_run_frames(&run, &limits),
            Err(IndexRunError::InvalidPackRecordCount)
        );
    }

    #[test]
    fn pack_record_capacity_accepts_4096_and_rejects_4097() {
        let limits = IndexRunLimits::default();
        let mut run = fixture();
        run.sequence = Sequence::new(4_096);
        run.containers[0].pack_record_count = 4_096;
        run.containers[0].pack_section_offset = 0;
        run.containers[0].pack_section_len = 4_096 * 17;
        run.containers[0].stored_len = run.containers[0].pack_section_len;
        let IndexMutation::Upsert(template) = run.mutations.remove(0) else {
            panic!("fixture starts with upsert");
        };
        run.mutations.clear();
        for ordinal in 0_u32..4_096 {
            let mut upsert = template.clone();
            let mut blind_key = [0_u8; 32];
            blind_key[..4].copy_from_slice(&ordinal.to_be_bytes());
            upsert.mutation_ordinal = ordinal;
            upsert.blind_key = IndexBlindKey::from_bytes(blind_key);
            upsert.path =
                LogicalPath::new(format!("tiny/{ordinal:04}")).expect("bounded logical path");
            upsert.generation = Sequence::new(u64::from(ordinal) + 1);
            upsert.payload = IndexPayloadPointer::ExternalPack {
                container_ordinal: 0,
                record: IndexPackRecordPointer {
                    record_ordinal: ordinal,
                    physical_offset: ordinal * 17,
                },
            };
            upsert.content_len = 1;
            upsert.modified_at_ms = i64::from(ordinal);
            run.mutations.push(IndexMutation::Upsert(upsert));
        }
        let encoded = encode_index_run(&run, &limits).expect("4096-record pack fact");
        assert_eq!(
            decode_index_run(&encoded, &limits).expect("decode 4096-record pack fact"),
            run
        );

        run.containers[0].pack_record_count = 4_097;
        assert_eq!(
            encode_index_run_frames(&run, &limits),
            Err(IndexRunError::InvalidContainerRange)
        );
    }

    #[test]
    fn rejects_noncanonical_and_unused_containers() {
        let limits = IndexRunLimits::default();
        let mut run = fixture();
        let mut second = run.containers[0].clone();
        second.object_id = BackendObjectId::new("objects/pack-b").expect("second object");
        run.containers.push(second);
        assert_eq!(
            encode_index_run_frames(&run, &limits),
            Err(IndexRunError::UnusedContainer(1))
        );
        run.containers.swap(0, 1);
        assert_eq!(
            encode_index_run_frames(&run, &limits),
            Err(IndexRunError::InvalidContainerOrder)
        );
    }

    fn frame_bytes(encoded: crate::run::EncodedIndexRun) -> Vec<Vec<u8>> {
        encoded
            .frames
            .into_iter()
            .map(|frame| frame.bytes)
            .collect()
    }

    fn replace_frame_bytes(frames: &mut [Vec<u8>], from: &[u8], to: &[u8]) {
        assert_eq!(from.len(), to.len());
        let (frame_index, offset) = frames
            .iter()
            .enumerate()
            .find_map(|(frame_index, frame)| {
                frame
                    .windows(from.len())
                    .position(|window| window == from)
                    .map(|offset| (frame_index, offset))
            })
            .expect("encoded bytes");
        frames[frame_index][offset..offset + from.len()].copy_from_slice(to);
    }

    fn set_namespace_key_ordinal(frames: &mut [Vec<u8>], blind_byte: u8, ordinal: u8) {
        let blind_key = [blind_byte; 32];
        let (frame_index, offset) = frames
            .iter()
            .enumerate()
            .find_map(|(frame_index, frame)| {
                frame
                    .windows(blind_key.len())
                    .position(|window| window == blind_key)
                    .map(|offset| (frame_index, offset))
            })
            .expect("namespace blind key");
        frames[frame_index][offset + blind_key.len()] = ordinal;
    }

    fn set_fixture_physical_offset(run: &mut IndexRun, physical_offset: u32) {
        let IndexMutation::Upsert(upsert) = &mut run.mutations[0] else {
            panic!("fixture starts with upsert");
        };
        let IndexPayloadPointer::ExternalPack { record, .. } = &mut upsert.payload else {
            panic!("fixture uses an external pack");
        };
        record.physical_offset = physical_offset;
    }

    fn hex(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len() * 2);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in bytes {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }
}
