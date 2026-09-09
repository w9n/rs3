//! Canonical identities for independently sealed v3 objects.

use super::{V3FormatError, V3Result};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rs3_types::BackendObjectId;

/// Backend prefix reserved for independently sealed v3 objects.
pub(in crate::v3) const V3_STANDALONE_OBJECT_PREFIX: &str = "objects/v03/";
const V3_STANDALONE_OBJECT_ID_BYTES: usize = 32;
const V3_STANDALONE_OBJECT_ID_B64_LEN: usize = 43;

/// Generates a fresh path-private identity for one immutable standalone object.
pub(in crate::v3) fn generate_v3_standalone_object_id() -> V3Result<BackendObjectId> {
    let random_id =
        rs3_crypto::random_carrier_id().map_err(|_| V3FormatError::RandomnessUnavailable)?;
    BackendObjectId::new(format!(
        "{V3_STANDALONE_OBJECT_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(random_id)
    ))
    .map_err(V3FormatError::from)
}

/// Validates the canonical random object key and non-empty sealed-object length.
pub(in crate::v3) fn validate_v3_standalone_object(
    object_id: &BackendObjectId,
    stored_len: u64,
) -> V3Result<()> {
    if stored_len == 0 {
        return Err(V3FormatError::InvalidHeaderField);
    }
    standalone_carrier_id(object_id).map(|_| ())
}

/// Returns the canonical random identity already present in an opaque object key.
pub(in crate::v3) fn standalone_carrier_id(object_id: &BackendObjectId) -> V3Result<[u8; 32]> {
    let Some(encoded_id) = object_id.as_str().strip_prefix(V3_STANDALONE_OBJECT_PREFIX) else {
        return Err(V3FormatError::InvalidHeaderField);
    };
    if encoded_id.len() != V3_STANDALONE_OBJECT_ID_B64_LEN || encoded_id.contains(['=', '/', '+']) {
        return Err(V3FormatError::InvalidHeaderField);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded_id)
        .map_err(|_| V3FormatError::InvalidHeaderField)?;
    let random_id: [u8; V3_STANDALONE_OBJECT_ID_BYTES] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| V3FormatError::InvalidHeaderField)?;
    if URL_SAFE_NO_PAD.encode(random_id) != encoded_id {
        return Err(V3FormatError::InvalidHeaderField);
    }
    Ok(random_id)
}
