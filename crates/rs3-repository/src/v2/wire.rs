//! Shared bounded fields for canonical metadata and recovery wire schemas.

use super::{V2FormatError, V2Result};
use rs3_types::cbor::{self, Reader};
use rs3_types::{BackendObjectId, BackendVersionId};

pub(super) const MAX_WIRE_TEXT: usize = 1024;
pub(super) const MAX_WIRE_KEY_ID: usize = 255;

pub(super) fn require(valid: bool) -> V2Result<()> {
    if valid {
        Ok(())
    } else {
        Err(V2FormatError::MalformedCbor)
    }
}

pub(super) fn write_text(out: &mut Vec<u8>, text: &str, maximum: usize) -> V2Result<()> {
    require(text.len() <= maximum)?;
    cbor::write_text(out, text);
    Ok(())
}

pub(super) fn write_optional_text(out: &mut Vec<u8>, text: Option<&str>) -> V2Result<()> {
    match text {
        Some(text) => write_text(out, text, MAX_WIRE_TEXT),
        None => {
            cbor::write_null(out);
            Ok(())
        }
    }
}

pub(super) fn read_optional_text(reader: &mut Reader<'_>) -> V2Result<Option<String>> {
    if reader.next_is_null() {
        reader.read_null()?;
        Ok(None)
    } else {
        Ok(Some(reader.read_text_bounded(MAX_WIRE_TEXT)?))
    }
}

pub(super) fn read_digest(reader: &mut Reader<'_>) -> V2Result<[u8; 32]> {
    reader
        .read_bytes_bounded(32)?
        .try_into()
        .map_err(|_| V2FormatError::MalformedCbor)
}

pub(super) fn digest_bytes(hex_digest: &str) -> V2Result<[u8; 32]> {
    require(hex_digest.len() == 64)?;
    hex::decode(hex_digest)
        .map_err(|_| V2FormatError::MalformedCbor)?
        .try_into()
        .map_err(|_| V2FormatError::MalformedCbor)
}

pub(super) fn write_envelope_ref(
    out: &mut Vec<u8>,
    generation: u64,
    digest: &str,
    object_id: &BackendObjectId,
    version_id: Option<&BackendVersionId>,
) -> V2Result<()> {
    let digest = digest_bytes(digest)?;
    cbor::write_array_len(out, 4);
    cbor::write_u64(out, generation);
    cbor::write_bytes(out, &digest);
    write_text(out, object_id.as_str(), MAX_WIRE_TEXT)?;
    write_optional_text(out, version_id.map(BackendVersionId::as_str))
}

pub(super) fn read_envelope_ref(
    reader: &mut Reader<'_>,
) -> V2Result<(u64, String, BackendObjectId, Option<BackendVersionId>)> {
    require(reader.read_array_len()? == 4)?;
    let generation = reader.read_u64()?;
    let digest = hex::encode(read_digest(reader)?);
    let object_id = BackendObjectId::new(reader.read_text_bounded(MAX_WIRE_TEXT)?)?;
    let version_id = read_optional_text(reader)?
        .map(BackendVersionId::new)
        .transpose()?;
    Ok((generation, digest, object_id, version_id))
}
