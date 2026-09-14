//! Bounded authenticated multipart completion results, independent of payload
//! retention. Only accepted repository publication may install these records.

use rs3_types::{
    ChecksumAlgorithm, ChecksumType, LogicalPath, MultipartUploadId, ObjectChecksum, ObjectEtag,
    Sequence, cbor,
};
use std::collections::{BTreeMap, BTreeSet};

/// Maximum durable results retained, newest accepted commit sequences first.
pub const MAX_COMPLETION_RECEIPTS: usize = 1024;
/// Encoded ceiling for one canonical receipt, including its logical key.
pub const MAX_COMPLETION_RECEIPT_BYTES: usize = 2048;

/// Authenticated result of a single accepted multipart completion.
#[derive(Clone, PartialEq, Eq)]
pub struct CompletionReceipt {
    /// Client upload identity, never inferred from a path or content digest.
    pub upload_id: MultipartUploadId,
    /// Sequence of the signed commit that first accepted this completion.
    pub commit_sequence: Sequence,
    /// Domain-separated digest of the exact client-selected part list.
    pub selection_digest: [u8; 32],
    /// Domain-separated digest of the selected immutable sealing attempts.
    pub attempts_digest: [u8; 32],
    /// Logical destination, stored only inside authenticated encryption.
    pub key: LogicalPath,
    /// Accepted plaintext length.
    pub content_len: u64,
    /// Exact multipart MD5 ETag, distinct from provider ciphertext ETags.
    pub etag: ObjectEtag,
    /// Accepted client checksum, when supplied with this multipart completion.
    pub checksum: Option<ObjectChecksum>,
}

impl std::fmt::Debug for CompletionReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompletionReceipt")
            .field("commit_sequence", &self.commit_sequence)
            .field("key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Invalid, conflicting or oversized completion receipt data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompletionReceiptError;

impl std::fmt::Display for CompletionReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid multipart completion receipt")
    }
}
impl std::error::Error for CompletionReceiptError {}

type Result<T> = std::result::Result<T, CompletionReceiptError>;

impl CompletionReceipt {
    /// Validates semantic and allocation bounds independently of a wire decoder.
    pub fn validate(&self) -> Result<()> {
        let Some(part_count) = self.etag.part_count() else {
            return Err(CompletionReceiptError);
        };
        if self.commit_sequence == Sequence::ZERO
            || self.key.as_str().len() > 1024
            || self.checksum.as_ref().is_some_and(|checksum| {
                matches!(
                    (checksum.algorithm(), checksum.kind()),
                    (
                        ChecksumAlgorithm::Sha1 | ChecksumAlgorithm::Sha256,
                        ChecksumType::FullObject
                    )
                ) || matches!(checksum.kind(), ChecksumType::Composite { parts } if parts != part_count)
            })
        {
            return Err(CompletionReceiptError);
        }
        Ok(())
    }

    /// Encodes the fixed eight-field canonical CBOR array.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        cbor::write_array_len(&mut out, 8);
        cbor::write_bytes(&mut out, self.upload_id.as_bytes());
        cbor::write_u64(&mut out, self.commit_sequence.get());
        cbor::write_bytes(&mut out, &self.selection_digest);
        cbor::write_bytes(&mut out, &self.attempts_digest);
        cbor::write_text(&mut out, self.key.as_str());
        cbor::write_u64(&mut out, self.content_len);
        cbor::write_bytes(&mut out, &self.etag.encode());
        match &self.checksum {
            Some(checksum) => cbor::write_bytes(&mut out, &checksum.encode()),
            None => cbor::write_null(&mut out),
        }
        if out.len() > MAX_COMPLETION_RECEIPT_BYTES {
            return Err(CompletionReceiptError);
        }
        Ok(out)
    }

    /// Decodes exact canonical bytes under fixed field and whole-record limits.
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() > MAX_COMPLETION_RECEIPT_BYTES {
            return Err(CompletionReceiptError);
        }
        decode(input).map_err(|_| CompletionReceiptError)
    }
}

fn decode(input: &[u8]) -> cbor::CborResult<CompletionReceipt> {
    let mut reader = cbor::Reader::new(input);
    if reader.read_array_len()? != 8 {
        return Err(cbor::CborError::Invalid);
    }
    let upload_id = MultipartUploadId::from_bytes(
        reader
            .read_bytes_bounded(32)?
            .try_into()
            .map_err(|_| cbor::CborError::Invalid)?,
    );
    let commit_sequence = Sequence::new(reader.read_u64()?);
    let selection_digest = reader
        .read_bytes_bounded(32)?
        .try_into()
        .map_err(|_| cbor::CborError::Invalid)?;
    let attempts_digest = reader
        .read_bytes_bounded(32)?
        .try_into()
        .map_err(|_| cbor::CborError::Invalid)?;
    let key =
        LogicalPath::new(reader.read_text_bounded(1024)?).map_err(|_| cbor::CborError::Invalid)?;
    let content_len = reader.read_u64()?;
    let etag = ObjectEtag::decode(&reader.read_bytes_bounded(ObjectEtag::ENCODED_BYTES)?)
        .map_err(|_| cbor::CborError::Invalid)?;
    let checksum = if reader.next_is_null() {
        reader.read_null()?;
        None
    } else {
        Some(
            ObjectChecksum::decode(&reader.read_bytes_bounded(ObjectChecksum::MAX_ENCODED_BYTES)?)
                .map_err(|_| cbor::CborError::Invalid)?,
        )
    };
    if !reader.is_finished() {
        return Err(cbor::CborError::Invalid);
    }
    let receipt = CompletionReceipt {
        upload_id,
        commit_sequence,
        selection_digest,
        attempts_digest,
        key,
        content_len,
        etag,
        checksum,
    };
    receipt.validate().map_err(|_| cbor::CborError::Invalid)?;
    Ok(receipt)
}

/// Latest bounded accepted results. Eviction only permits NoSuchUpload; it never
/// authorizes a repeat publication or reclamation of the represented payload.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompletionReceipts {
    entries: BTreeMap<MultipartUploadId, CompletionReceipt>,
}

impl CompletionReceipts {
    /// Looks up a result selected by the authenticated current repository state.
    pub fn get(&self, id: &MultipartUploadId) -> Option<&CompletionReceipt> {
        self.entries.get(id)
    }

    /// Returns canonical upload-ID order for an encrypted root snapshot.
    pub fn iter(&self) -> impl Iterator<Item = &CompletionReceipt> {
        self.entries.values()
    }

    /// Validates before any mutation. Equal replay is harmless; conflicting
    /// identity or accepted sequence is corruption rather than last-write-wins.
    pub fn validate_insert(&self, receipt: &CompletionReceipt) -> Result<()> {
        receipt.validate()?;
        if self
            .entries
            .get(&receipt.upload_id)
            .is_some_and(|old| old != receipt)
            || self
                .entries
                .values()
                .any(|old| old.commit_sequence == receipt.commit_sequence && old != receipt)
        {
            return Err(CompletionReceiptError);
        }
        Ok(())
    }

    /// Applies one verified accepted result, evicting the oldest if necessary.
    /// Call validate_insert before the external publication CAS as well.
    pub fn insert(&mut self, receipt: CompletionReceipt) -> Result<()> {
        self.validate_insert(&receipt)?;
        self.entries.insert(receipt.upload_id, receipt);
        if self.entries.len() > MAX_COMPLETION_RECEIPTS {
            let oldest = self
                .entries
                .values()
                .min_by_key(|entry| entry.commit_sequence)
                .map(|entry| entry.upload_id)
                .ok_or(CompletionReceiptError)?;
            self.entries.remove(&oldest);
        }
        Ok(())
    }

    /// Opens a bounded, strictly ID-ordered root snapshot without silent eviction.
    pub fn from_snapshot(receipts: Vec<CompletionReceipt>) -> Result<Self> {
        if receipts.len() > MAX_COMPLETION_RECEIPTS {
            return Err(CompletionReceiptError);
        }
        let mut previous = None;
        let mut sequences = BTreeSet::new();
        let mut entries = BTreeMap::new();
        for receipt in receipts {
            receipt.validate()?;
            if previous.is_some_and(|id| id >= receipt.upload_id)
                || !sequences.insert(receipt.commit_sequence)
            {
                return Err(CompletionReceiptError);
            }
            previous = Some(receipt.upload_id);
            entries.insert(receipt.upload_id, receipt);
        }
        Ok(Self { entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn multipart_etag(byte: u8, parts: u32) -> ObjectEtag {
        ObjectEtag::multipart(rs3_types::Md5Digest::from_bytes([byte; 16]), parts)
            .expect("multipart etag")
    }

    fn receipt(sequence: u64) -> CompletionReceipt {
        let mut id = [0; 32];
        id[..8].copy_from_slice(&sequence.to_be_bytes());
        CompletionReceipt {
            upload_id: MultipartUploadId::from_bytes(id),
            commit_sequence: Sequence::new(sequence),
            selection_digest: [3; 32],
            attempts_digest: [4; 32],
            key: LogicalPath::new("private/key").expect("key"),
            content_len: 42,
            etag: multipart_etag(0x05, 1),
            checksum: None,
        }
    }

    #[test]
    fn canonical_receipt_rejects_truncation_trailing_and_unbounded_fields() {
        let original = receipt(1);
        let bytes = original.encode().expect("encode");
        assert_eq!(CompletionReceipt::decode(&bytes).expect("decode"), original);
        for end in 0..bytes.len() {
            assert!(CompletionReceipt::decode(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(CompletionReceipt::decode(&trailing).is_err());
        let mut overlong = bytes; // sequence 1 follows array + byte-string header + ID.
        assert_eq!(overlong[35], 1);
        overlong.splice(35..36, [0x18, 1]);
        assert!(CompletionReceipt::decode(&overlong).is_err());
        let mut invalid = original.clone();
        invalid.etag = ObjectEtag::single(rs3_types::Md5Digest::from_bytes([0; 16]));
        assert!(invalid.encode().is_err());
        invalid = original.clone();
        invalid.commit_sequence = Sequence::ZERO;
        assert!(invalid.encode().is_err());
        assert!(!format!("{original:?}").contains("private"));
    }

    #[test]
    fn receipt_checksum_round_trips_and_rejects_malformed_cbor() {
        let checksum = ObjectChecksum::new(
            rs3_types::ChecksumAlgorithm::Crc32,
            rs3_types::ChecksumType::FullObject,
            vec![0xa5; 4],
        )
        .expect("checksum");
        let mut original = receipt(1);
        original.checksum = Some(checksum.clone());
        let bytes = original.encode().expect("encode");
        assert_eq!(CompletionReceipt::decode(&bytes), Ok(original));

        let checksum_bytes = checksum.encode();
        let checksum_offset = bytes.len() - checksum_bytes.len();
        let mut malformed = bytes;
        malformed[checksum_offset + 3] = 0x43;
        assert!(CompletionReceipt::decode(&malformed).is_err());
    }

    #[test]
    fn multipart_receipt_rejects_full_object_sha_checksums() {
        for algorithm in [ChecksumAlgorithm::Sha1, ChecksumAlgorithm::Sha256] {
            let mut invalid = receipt(1);
            invalid.checksum = Some(
                ObjectChecksum::new(
                    algorithm,
                    ChecksumType::FullObject,
                    vec![0; algorithm.digest_len()],
                )
                .expect("checksum"),
            );
            assert!(invalid.encode().is_err());
        }
        let mut accepted = receipt(1);
        accepted.checksum = Some(
            ObjectChecksum::new(
                ChecksumAlgorithm::Sha256,
                ChecksumType::Composite { parts: 1 },
                vec![0; ChecksumAlgorithm::Sha256.digest_len()],
            )
            .expect("checksum"),
        );
        assert!(accepted.encode().is_ok());
        accepted.checksum = Some(
            ObjectChecksum::new(
                ChecksumAlgorithm::Sha256,
                ChecksumType::Composite { parts: 2 },
                vec![0; ChecksumAlgorithm::Sha256.digest_len()],
            )
            .expect("checksum"),
        );
        assert!(accepted.encode().is_err());
    }

    #[test]
    fn bounded_results_keep_newest_acceptances_without_wall_clock_or_resurrection() {
        let mut receipts = CompletionReceipts::default();
        for sequence in (1..=MAX_COMPLETION_RECEIPTS as u64 + 1).rev() {
            receipts
                .insert(receipt(sequence))
                .expect("out-of-order replay");
        }
        assert_eq!(receipts.iter().count(), MAX_COMPLETION_RECEIPTS);
        assert!(receipts.get(&receipt(1).upload_id).is_none());
        let before = receipts.clone();
        receipts
            .insert(receipt(1))
            .expect("older record stays evicted");
        assert_eq!(receipts, before);
        let snapshot = receipts.iter().cloned().collect();
        assert_eq!(
            CompletionReceipts::from_snapshot(snapshot).expect("root snapshot"),
            receipts
        );
        let mut conflict = receipt(2);
        conflict.etag = multipart_etag(0x06, 1);
        assert!(receipts.insert(conflict).is_err());
        assert_eq!(receipts, before, "reject before mutation");
        receipts.insert(receipt(2)).expect("equal replay");
        let mut bad_sequence = receipt(10000);
        bad_sequence.commit_sequence = Sequence::new(2);
        assert!(receipts.insert(bad_sequence).is_err());
    }

    #[test]
    fn snapshot_rejects_duplicate_ids_sequences_order_and_excess_count() {
        for snapshot in [
            vec![receipt(1), receipt(1)],
            vec![receipt(2), receipt(1)],
            (1..=MAX_COMPLETION_RECEIPTS as u64 + 1)
                .map(receipt)
                .collect(),
        ] {
            assert!(CompletionReceipts::from_snapshot(snapshot).is_err());
        }
        let mut second = receipt(2);
        second.commit_sequence = Sequence::new(1);
        assert!(CompletionReceipts::from_snapshot(vec![receipt(1), second]).is_err());
    }
}
