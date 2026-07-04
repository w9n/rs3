//! Keyring envelope object storage.

use crate::error::{RepositoryError, Result};
use crate::service::{Repository, require_version_for_retained_write};
use bytes::Bytes;
use rs3_crypto::KeyringEnvelope;
use rs3_index::KeyringEnvelopeReference;
use rs3_storage::{BlobStore, ByteRange, PutOptions, StorageError};
use rs3_types::{BackendObjectId, LegalHoldStatus, RetentionPolicy};

pub(crate) const KEYRING_ENVELOPE_OBJECT_PREFIX: &str = "keyrings/";
/// Content type for serialized keyring envelope objects.
pub const KEYRING_ENVELOPE_OBJECT_CONTENT_TYPE: &str = "application/vnd.rs3.keyring-envelope+json";

/// Stores an encrypted keyring envelope object and returns its durable reference.
pub async fn store_keyring_envelope<S>(
    store: &S,
    envelope: &KeyringEnvelope,
    retention: Option<RetentionPolicy>,
    legal_hold: Option<LegalHoldStatus>,
) -> Result<KeyringEnvelopeReference>
where
    S: BlobStore,
{
    let digest = envelope.digest()?;
    let object_id = keyring_envelope_object_id(envelope.generation, &digest)?;
    let body = Bytes::from(envelope.to_object_bytes()?);
    let put = store
        .put(
            &object_id,
            body.clone(),
            PutOptions {
                retention,
                legal_hold,
                content_type: Some(KEYRING_ENVELOPE_OBJECT_CONTENT_TYPE.to_owned()),
                do_not_recreate: true,
            },
        )
        .await;

    let version_id = match put {
        Ok(metadata) => {
            require_version_for_retained_write(&object_id, &metadata, retention, legal_hold)?
        }
        Err(StorageError::AlreadyExists(_)) => {
            let existing_metadata = store.head(&object_id).await?;
            let existing = store.get_range(&object_id, ByteRange::Full).await?;
            if existing != body {
                return Err(RepositoryError::KeyringEnvelopeObjectConflict { object_id });
            }
            require_version_for_retained_write(
                &object_id,
                &existing_metadata,
                retention,
                legal_hold,
            )?
        }
        Err(error) => return Err(error.into()),
    };

    Ok(KeyringEnvelopeReference {
        generation: envelope.generation,
        digest,
        object_id,
        version_id,
    })
}

impl<S> Repository<S>
where
    S: BlobStore,
{
    /// Stores an encrypted keyring envelope and records its reference for new checkpoints.
    pub async fn store_keyring_envelope(
        &self,
        envelope: &KeyringEnvelope,
    ) -> Result<KeyringEnvelopeReference> {
        let retention = self.checkpoint_retention_policy()?;
        let legal_hold = self.checkpoint_legal_hold()?;
        let reference =
            store_keyring_envelope(&self.store, envelope, retention, legal_hold).await?;
        self.set_keyring_envelope_reference(Some(reference.clone()))?;
        Ok(reference)
    }
}

fn keyring_envelope_object_id(generation: u64, digest: &str) -> Result<BackendObjectId> {
    BackendObjectId::new(format!(
        "{KEYRING_ENVELOPE_OBJECT_PREFIX}{generation:020}-{digest}.json"
    ))
    .map_err(Into::into)
}
