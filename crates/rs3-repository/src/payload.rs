//! Durable payload object envelope handling.

use crate::error::{RepositoryError, Result};
use bytes::Bytes;
use rs3_crypto::{KeyRing, PayloadSeal};
use rs3_storage::{ByteRange, StorageError};
use rs3_types::{BackendObjectId, KeyId};

const PAYLOAD_OBJECT_DOMAIN: &[u8] = b"rs3:payload-object:v1\n";
const U64_LEN: usize = 8;

/// Encrypts plaintext into a durable payload object body.
pub(crate) fn seal_payload_object(
    keyring: &KeyRing,
    object_id: &BackendObjectId,
    plaintext: &[u8],
) -> Result<Bytes> {
    let seal = keyring.seal_payload(&payload_associated_data(object_id), plaintext)?;
    Ok(payload_object_bytes(&seal))
}

/// Opens a durable payload object body and applies a client-visible range.
pub(crate) fn open_payload_object(
    keyring: &KeyRing,
    object_id: &BackendObjectId,
    body: Bytes,
    range: ByteRange,
) -> Result<Bytes> {
    let seal = parse_payload_object(object_id, &body)?;
    let plaintext = keyring.open_payload(
        &seal.key_id,
        &payload_associated_data(object_id),
        &seal.nonce,
        &seal.ciphertext,
    )?;

    plaintext_range(plaintext, range)
}

fn payload_associated_data(object_id: &BackendObjectId) -> Vec<u8> {
    format!("rs3:payload-associated-data:v1:{}", object_id.as_str()).into_bytes()
}

fn payload_object_bytes(seal: &PayloadSeal) -> Bytes {
    let key_id = seal.key_id.as_str().as_bytes();
    let mut body = Vec::with_capacity(
        PAYLOAD_OBJECT_DOMAIN.len()
            + U64_LEN
            + key_id.len()
            + U64_LEN
            + seal.nonce.len()
            + U64_LEN
            + seal.ciphertext.len(),
    );
    body.extend_from_slice(PAYLOAD_OBJECT_DOMAIN);
    push_u64_len(&mut body, key_id.len());
    body.extend_from_slice(key_id);
    push_u64_len(&mut body, seal.nonce.len());
    body.extend_from_slice(&seal.nonce);
    body.extend_from_slice(&(seal.ciphertext.len() as u64).to_be_bytes());
    body.extend_from_slice(&seal.ciphertext);
    Bytes::from(body)
}

fn parse_payload_object(object_id: &BackendObjectId, body: &[u8]) -> Result<PayloadSeal> {
    let Some(mut cursor) = body.strip_prefix(PAYLOAD_OBJECT_DOMAIN) else {
        return Err(invalid_payload_object(object_id));
    };

    let key_id = read_len_prefixed(object_id, &mut cursor)?;
    let key_id = std::str::from_utf8(key_id)
        .map_err(|_| invalid_payload_object(object_id))
        .and_then(|value| {
            KeyId::new(value.to_owned()).map_err(|_| invalid_payload_object(object_id))
        })?;
    let nonce = read_len_prefixed(object_id, &mut cursor)?.to_vec();
    let ciphertext_len = read_u64_len(object_id, &mut cursor)?;
    let ciphertext = read_exact(object_id, &mut cursor, ciphertext_len)?.to_vec();
    if !cursor.is_empty() {
        return Err(invalid_payload_object(object_id));
    }

    Ok(PayloadSeal {
        key_id,
        nonce,
        ciphertext,
    })
}

fn plaintext_range(plaintext: Vec<u8>, range: ByteRange) -> Result<Bytes> {
    match range {
        ByteRange::Full => Ok(Bytes::from(plaintext)),
        ByteRange::Slice { offset, len } => {
            let offset = usize::try_from(offset).map_err(|_| StorageError::InvalidRange)?;
            let len = usize::try_from(len).map_err(|_| StorageError::InvalidRange)?;
            let end = offset.checked_add(len).ok_or(StorageError::InvalidRange)?;
            if end > plaintext.len() {
                return Err(StorageError::InvalidRange.into());
            }
            Ok(Bytes::copy_from_slice(&plaintext[offset..end]))
        }
    }
}

fn push_u64_len(body: &mut Vec<u8>, len: usize) {
    body.extend_from_slice(&(len as u64).to_be_bytes());
}

fn read_len_prefixed<'a>(object_id: &BackendObjectId, cursor: &mut &'a [u8]) -> Result<&'a [u8]> {
    let len = read_u64_len(object_id, cursor)?;
    read_exact(object_id, cursor, len)
}

fn read_u64_len(object_id: &BackendObjectId, cursor: &mut &[u8]) -> Result<usize> {
    let bytes = read_exact(object_id, cursor, U64_LEN)?;
    let mut len = [0_u8; U64_LEN];
    len.copy_from_slice(bytes);
    usize::try_from(u64::from_be_bytes(len)).map_err(|_| invalid_payload_object(object_id))
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
    use super::{open_payload_object, seal_payload_object};
    use crate::tests::{backend_object_id, signing_keyring, wrong_content_keyring};
    use rs3_storage::ByteRange;

    #[test]
    fn payload_object_round_trips() {
        let keyring = signing_keyring();
        let object_id = backend_object_id("segments/object");
        let body = match seal_payload_object(&keyring, &object_id, b"hello world") {
            Ok(body) => body,
            Err(error) => panic!("{error}"),
        };
        let opened = open_payload_object(&keyring, &object_id, body, ByteRange::Full);

        assert_eq!(opened.ok().as_deref(), Some(&b"hello world"[..]));
    }

    #[test]
    fn payload_object_rejects_wrong_object_context() {
        let keyring = signing_keyring();
        let object_id = backend_object_id("segments/object");
        let moved_object_id = backend_object_id("segments/other");
        let body = match seal_payload_object(&keyring, &object_id, b"hello world") {
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
        let body = match seal_payload_object(&writer, &object_id, b"hello world") {
            Ok(body) => body,
            Err(error) => panic!("{error}"),
        };

        let opened = open_payload_object(&reader, &object_id, body, ByteRange::Full);

        assert!(opened.is_err());
    }
}
