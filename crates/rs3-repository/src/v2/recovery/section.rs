//! Bounded recovery-section framing; cryptography remains in rs3-crypto.

use crate::v2::{V2FormatError, V2Result};
use bytes::Bytes;
use rs3_crypto::KeyRing;
use rs3_types::{BackendObjectId, KeyId, KeyPurpose};

pub(in crate::v2) const MAX_RECOVERY_SECTION_BYTES: usize = 8 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"rs3:rcv\n";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 56;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const AAD_DOMAIN: &[u8] = b"rs3:recovery-section-aad:v03\n";

pub(in crate::v2) fn seal(
    keys: &KeyRing,
    repository_context: &[u8],
    object: &BackendObjectId,
    ordinal: u32,
    plaintext: &[u8],
) -> V2Result<Bytes> {
    let key_id = keys.primary_key_id(KeyPurpose::Metadata)?;
    if key_id.as_str().is_empty() || key_id.as_str().len() > 255 {
        return Err(V2FormatError::InvalidRecoveryHistory);
    }
    let stored_len = HEADER_BYTES
        .checked_add(key_id.as_str().len())
        .and_then(|size| size.checked_add(NONCE_BYTES + TAG_BYTES))
        .and_then(|size| size.checked_add(plaintext.len()))
        .filter(|size| *size <= MAX_RECOVERY_SECTION_BYTES)
        .ok_or(V2FormatError::RecoveryHistoryCapacity)?;
    let mut header = Vec::with_capacity(HEADER_BYTES + key_id.as_str().len());
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&VERSION.to_be_bytes());
    header.extend_from_slice(&(key_id.as_str().len() as u16).to_be_bytes());
    header.extend_from_slice(&ordinal.to_be_bytes());
    header.extend_from_slice(&(plaintext.len() as u64).to_be_bytes());
    header.extend_from_slice(&rs3_crypto::random_carrier_id()?);
    header.extend_from_slice(key_id.as_str().as_bytes());
    let aad = associated_data(repository_context, object, &header)?;
    let sealed = keys.seal_metadata_payload(&aad, plaintext)?;
    if sealed.key_id != key_id
        || sealed.nonce.len() != NONCE_BYTES
        || sealed.tag.len() != TAG_BYTES
        || sealed.ciphertext.len() != plaintext.len()
    {
        return Err(V2FormatError::InvalidRecoveryHistory);
    }
    let mut bytes = Vec::with_capacity(stored_len);
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(&sealed.nonce);
    bytes.extend_from_slice(&sealed.tag);
    bytes.extend_from_slice(&sealed.ciphertext);
    Ok(Bytes::from(bytes))
}

pub(in crate::v2) fn open(
    keys: &KeyRing,
    repository_context: &[u8],
    object: &BackendObjectId,
    ordinal: u32,
    stored: &[u8],
) -> V2Result<Vec<u8>> {
    if stored.len() > MAX_RECOVERY_SECTION_BYTES {
        return Err(V2FormatError::RecoveryHistoryCapacity);
    }
    let mut offset = 0;
    if &take::<8>(stored, &mut offset)? != MAGIC
        || u16::from_be_bytes(take(stored, &mut offset)?) != VERSION
    {
        return Err(V2FormatError::InvalidRecoveryHistory);
    }
    let key_len = usize::from(u16::from_be_bytes(take(stored, &mut offset)?));
    let actual_ordinal = u32::from_be_bytes(take(stored, &mut offset)?);
    let ciphertext_len = usize::try_from(u64::from_be_bytes(take(stored, &mut offset)?))
        .map_err(|_| V2FormatError::RecoveryHistoryCapacity)?;
    let _identity = take::<32>(stored, &mut offset)?;
    if key_len == 0 || key_len > 255 || actual_ordinal != ordinal {
        return Err(V2FormatError::InvalidRecoveryHistory);
    }
    let header_end = offset
        .checked_add(key_len)
        .ok_or(V2FormatError::RecoveryHistoryCapacity)?;
    let expected_len = header_end
        .checked_add(NONCE_BYTES + TAG_BYTES)
        .and_then(|size| size.checked_add(ciphertext_len))
        .ok_or(V2FormatError::RecoveryHistoryCapacity)?;
    if expected_len != stored.len() {
        return Err(V2FormatError::InvalidRecoveryHistory);
    }
    let key = std::str::from_utf8(
        stored
            .get(offset..header_end)
            .ok_or(V2FormatError::InvalidRecoveryHistory)?,
    )
    .map_err(|_| V2FormatError::InvalidRecoveryHistory)?;
    let key_id = KeyId::new(key).map_err(|_| V2FormatError::InvalidRecoveryHistory)?;
    let aad = associated_data(repository_context, object, &stored[..header_end])?;
    offset = header_end;
    let nonce = take::<NONCE_BYTES>(stored, &mut offset)?;
    let tag = take::<TAG_BYTES>(stored, &mut offset)?;
    keys.open_metadata_payload(&key_id, &aad, &nonce, &stored[offset..], &tag)
        .map_err(|_| V2FormatError::InvalidRecoveryHistory)
}

fn associated_data(context: &[u8], object: &BackendObjectId, header: &[u8]) -> V2Result<Vec<u8>> {
    if context.is_empty() || context.len() > 4096 || object.as_str().len() > 1024 {
        return Err(V2FormatError::InvalidRecoveryHistory);
    }
    let mut aad = Vec::with_capacity(
        AAD_DOMAIN.len() + 8 + context.len() + object.as_str().len() + header.len(),
    );
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(&(context.len() as u32).to_be_bytes());
    aad.extend_from_slice(context);
    aad.extend_from_slice(&(object.as_str().len() as u32).to_be_bytes());
    aad.extend_from_slice(object.as_str().as_bytes());
    aad.extend_from_slice(header);
    Ok(aad)
}

fn take<const N: usize>(bytes: &[u8], offset: &mut usize) -> V2Result<[u8; N]> {
    let end = offset
        .checked_add(N)
        .ok_or(V2FormatError::InvalidRecoveryHistory)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(V2FormatError::InvalidRecoveryHistory)?
        .try_into()
        .map_err(|_| V2FormatError::InvalidRecoveryHistory)?;
    *offset = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_envelope_binds_every_context_and_rejects_truncation() {
        let keys = KeyRing::generate_random().expect("keys");
        let object = BackendObjectId::new("commits/v03/recovery-fixture").expect("object");
        let other = BackendObjectId::new("commits/v03/other-fixture").expect("object");
        let bytes = seal(&keys, b"repository", &object, 2, b"private-history").expect("seal");
        assert_eq!(
            open(&keys, b"repository", &object, 2, &bytes).expect("open"),
            b"private-history"
        );
        assert!(open(&keys, b"other", &object, 2, &bytes).is_err());
        assert!(open(&keys, b"repository", &other, 2, &bytes).is_err());
        assert!(open(&keys, b"repository", &object, 1, &bytes).is_err());
        for len in [0, HEADER_BYTES - 1, bytes.len() - 1] {
            assert!(open(&keys, b"repository", &object, 2, &bytes[..len]).is_err());
        }
        let mut tampered = bytes.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(open(&keys, b"repository", &object, 2, &tampered).is_err());
        let oversized = vec![0; MAX_RECOVERY_SECTION_BYTES];
        assert_eq!(
            seal(&keys, b"repository", &object, 2, &oversized),
            Err(V2FormatError::RecoveryHistoryCapacity)
        );
    }
}
