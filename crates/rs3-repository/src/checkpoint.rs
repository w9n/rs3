//! Repository index and manifest object helpers.

use crate::error::Result;
use crate::service::{Repository, strongest_retention_policy};
use crate::state::{RepositoryState, TrustedManifest};
use rs3_crypto::KeyRing;
use rs3_index::{
    INDEX_DELTA_PLAINTEXT_DOMAIN, IndexDelta, IndexDeltaObject, MANIFEST_PLAINTEXT_DOMAIN,
    ManifestObject, SealedIndexDeltaObject, index_delta_plaintext_bytes, manifest_plaintext_bytes,
};
use rs3_storage::BlobStore;
use rs3_types::{BackendObjectId, ManifestId};

const INDEX_DELTA_ASSOCIATED_DATA: &[u8] = b"rs3:index-delta-object:v1";

impl<S> Repository<S>
where
    S: BlobStore,
{
    pub(crate) fn checkpoint_retention_policy(&self) -> Result<Option<rs3_types::RetentionPolicy>> {
        let state = self.read_state()?;
        let mut retention = self.options.default_retention;
        for delta in &state.pending_index_deltas {
            if let IndexDelta::Upsert { entry, .. } = delta {
                retention = strongest_retention_policy(retention, entry.retention);
            }
        }
        Ok(retention)
    }

    pub(crate) fn checkpoint_legal_hold(&self) -> Result<Option<rs3_types::LegalHoldStatus>> {
        let state = self.read_state()?;
        Ok(state
            .pending_index_deltas
            .iter()
            .find_map(|delta| match delta {
                IndexDelta::Upsert { entry, .. } => entry
                    .legal_hold
                    .filter(|status| *status == rs3_types::LegalHoldStatus::On),
                IndexDelta::Tombstone { .. } => None,
            }))
    }

    pub(crate) fn load_embedded_manifest_records(
        &self,
        state: &mut RepositoryState,
        delta: &IndexDeltaObject,
    ) -> Result<()> {
        let keyring = self.keyring()?;
        for mutation in &delta.deltas {
            let IndexDelta::Upsert {
                entry,
                sealed_manifest,
                ..
            } = mutation
            else {
                continue;
            };

            let manifest = open_manifest_record(&keyring, &entry.manifest_id, sealed_manifest)?;
            state.manifests.insert(entry.manifest_id.clone(), manifest);
        }

        Ok(())
    }
}

fn manifest_associated_data(manifest_id: &ManifestId) -> Vec<u8> {
    format!("rs3:manifest-associated-data:v1:{}", manifest_id.as_str()).into_bytes()
}

pub(crate) fn seal_index_delta_object(
    keyring: &KeyRing,
    delta: &IndexDeltaObject,
) -> Result<SealedIndexDeltaObject> {
    let plaintext = index_delta_plaintext_bytes(delta)?;
    let associated_data = INDEX_DELTA_ASSOCIATED_DATA;
    let sealed = keyring.seal_metadata_payload(associated_data, &plaintext)?;

    Ok(SealedIndexDeltaObject {
        key_id: sealed.key_id,
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
        tag: sealed.tag,
    })
}

pub(crate) fn open_index_delta_object(
    keyring: &KeyRing,
    object_id: &BackendObjectId,
    sealed_delta: &SealedIndexDeltaObject,
) -> Result<IndexDeltaObject> {
    let plaintext = keyring.open_metadata_payload(
        &sealed_delta.key_id,
        INDEX_DELTA_ASSOCIATED_DATA,
        &sealed_delta.nonce,
        &sealed_delta.ciphertext,
        &sealed_delta.tag,
    )?;
    let Some(payload) = plaintext.strip_prefix(INDEX_DELTA_PLAINTEXT_DOMAIN) else {
        return Err(crate::RepositoryError::InvalidObjectFormat {
            object_id: object_id.clone(),
        });
    };

    serde_json::from_slice(payload).map_err(Into::into)
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

pub(crate) fn open_manifest_record(
    keyring: &KeyRing,
    manifest_id: &ManifestId,
    manifest_object: &ManifestObject,
) -> Result<TrustedManifest> {
    let plaintext = keyring.open_metadata_payload(
        &manifest_object.key_id,
        &manifest_associated_data(manifest_id),
        &manifest_object.nonce,
        &manifest_object.ciphertext,
        &manifest_object.tag,
    )?;
    let object_id = BackendObjectId::new(format!("index-metadata/{}", manifest_id.as_str()))?;
    let Some(payload) = plaintext.strip_prefix(MANIFEST_PLAINTEXT_DOMAIN) else {
        return Err(crate::RepositoryError::InvalidObjectFormat { object_id });
    };
    let manifest = serde_json::from_slice(payload)?;

    Ok(TrustedManifest::from_durable(manifest))
}
