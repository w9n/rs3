//! Canonical identities for independently sealed v2 objects.

use super::{V2FormatError, V2Result};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rs3_types::BackendObjectId;

/// Backend prefix reserved for independently sealed v2 objects.
pub(in crate::v2) const V2_STANDALONE_OBJECT_PREFIX: &str = "objects/v02/";
const V2_STANDALONE_OBJECT_ID_BYTES: usize = 32;
const V2_STANDALONE_OBJECT_ID_B64_LEN: usize = 43;

/// Validates the canonical random object key and non-empty sealed-object length.
pub(in crate::v2) fn validate_v2_standalone_object(
    object_id: &BackendObjectId,
    stored_len: u64,
) -> V2Result<()> {
    let Some(encoded_id) = object_id.as_str().strip_prefix(V2_STANDALONE_OBJECT_PREFIX) else {
        return Err(V2FormatError::InvalidHeaderField);
    };
    if encoded_id.len() != V2_STANDALONE_OBJECT_ID_B64_LEN
        || encoded_id.contains(['=', '/', '+'])
        || stored_len == 0
    {
        return Err(V2FormatError::InvalidHeaderField);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded_id)
        .map_err(|_| V2FormatError::InvalidHeaderField)?;
    let random_id: [u8; V2_STANDALONE_OBJECT_ID_BYTES] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| V2FormatError::InvalidHeaderField)?;
    if URL_SAFE_NO_PAD.encode(random_id) != encoded_id {
        return Err(V2FormatError::InvalidHeaderField);
    }
    Ok(())
}
