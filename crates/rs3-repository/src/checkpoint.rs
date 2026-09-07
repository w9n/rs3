//! Repository index and manifest object helpers.

use crate::error::Result;
use crate::state::TrustedManifest;
use rs3_crypto::KeyRing;
use rs3_index::{ManifestObject, manifest_plaintext_bytes};
use rs3_types::ManifestId;

fn manifest_associated_data(manifest_id: &ManifestId) -> Vec<u8> {
    format!("rs3:manifest-associated-data:v1:{}", manifest_id.as_str()).into_bytes()
}

pub(crate) fn seal_manifest_record(
    keyring: &KeyRing,
    manifest_id: &ManifestId,
    manifest: &TrustedManifest,
) -> Result<ManifestObject> {
    let plaintext = manifest_plaintext_bytes(&manifest.clone().into_durable())?;
    let sealed =
        keyring.seal_metadata_payload(&manifest_associated_data(manifest_id), &plaintext)?;

    Ok(ManifestObject {
        key_id: sealed.key_id,
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
        tag: sealed.tag,
    })
}
