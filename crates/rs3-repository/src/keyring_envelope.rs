//! Keyring envelope object storage.

use crate::error::{RepositoryError, Result};
use crate::service::require_version_for_retained_write;
use bytes::Bytes;
use rs3_crypto::{MAX_KEYRING_ENVELOPE_OBJECT_BYTES, RepositoryEnvelope};
use rs3_index::KeyringEnvelopeReference;
use rs3_storage::{BlobStore, PutOptions, StorageError, read_bounded_full_at};
use rs3_types::{BackendObjectId, LegalHoldStatus, RetentionPolicy};

pub(crate) const KEYRING_ENVELOPE_OBJECT_PREFIX: &str = "keyrings/";
/// Content type for serialized keyring envelope objects.
pub const KEYRING_ENVELOPE_OBJECT_CONTENT_TYPE: &str = "application/vnd.rs3.keyring-envelope+cbor";

/// Stores an encrypted keyring envelope object and returns its durable reference.
pub async fn store_keyring_envelope<S>(
    store: &S,
    envelope: &RepositoryEnvelope,
    retention: Option<RetentionPolicy>,
    legal_hold: Option<LegalHoldStatus>,
) -> Result<KeyringEnvelopeReference>
where
    S: BlobStore,
{
    if envelope.purpose != rs3_crypto::EnvelopePurpose::Keyring {
        return Err(rs3_crypto::CryptoError::InvalidRepositoryEnvelope {
            reason: "keyring storage requires keyring purpose".to_owned(),
        }
        .into());
    }
    let body = Bytes::from(envelope.to_object_bytes()?);
    let digest = hex::encode(rs3_crypto::Sha256Hasher::digest(&body));
    let object_id = keyring_envelope_object_id(envelope.generation, &digest)?;
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
            let existing = read_bounded_full_at(
                store,
                &object_id,
                existing_metadata.version_id.as_ref(),
                MAX_KEYRING_ENVELOPE_OBJECT_BYTES,
            )
            .await?;
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

/// Returns the canonical preview object identity for an encrypted envelope.
pub fn keyring_envelope_object_id(generation: u64, digest: &str) -> Result<BackendObjectId> {
    BackendObjectId::new(format!(
        "{KEYRING_ENVELOPE_OBJECT_PREFIX}{generation:020}-{digest}.cbor"
    ))
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use crate::keyring_envelope::{keyring_envelope_object_id, store_keyring_envelope};
    use bytes::Bytes;
    use rs3_crypto::{
        KeyRing, MAX_KEYRING_ENVELOPE_OBJECT_BYTES, RepositoryKeyContext, SecretBytes,
    };
    use rs3_storage::{BlobStore, MemoryBlobStore, PutOptions, StorageError};
    use rs3_types::RepositoryId;

    #[tokio::test]
    async fn keyring_storage_rejects_format_purpose_before_writing() {
        let store = MemoryBlobStore::new();
        let mut envelope = keyring_envelope();
        envelope.purpose = rs3_crypto::EnvelopePurpose::Format;
        assert!(
            store_keyring_envelope(&store, &envelope, None, None)
                .await
                .is_err()
        );
        let object_id =
            keyring_envelope_object_id(envelope.generation, &envelope.digest().expect("digest"))
                .expect("object key");
        assert!(matches!(
            store.head(&object_id).await,
            Err(StorageError::NotFound(_))
        ));
    }

    fn keyring_envelope() -> rs3_crypto::RepositoryEnvelope {
        let keyring = KeyRing::generate_random().unwrap_or_else(|error| panic!("{error}"));
        let repository_id =
            RepositoryId::new("keyring-conflict-test").unwrap_or_else(|error| panic!("{error}"));
        let context = RepositoryKeyContext::new(repository_id, vec![7; 32])
            .unwrap_or_else(|error| panic!("{error}"));
        let wrapping_key = SecretBytes::new(vec![9; SecretBytes::MIN_LEN])
            .unwrap_or_else(|error| panic!("{error}"));
        keyring
            .seal_keyring_envelope(&context, "wrapping-key", &wrapping_key, 1)
            .unwrap_or_else(|error| panic!("{error}"))
    }

    #[tokio::test]
    async fn conflict_verification_rejects_oversized_existing_object() {
        let store = MemoryBlobStore::new();
        let envelope = keyring_envelope();
        let digest = envelope.digest().unwrap_or_else(|error| panic!("{error}"));
        let object_id = keyring_envelope_object_id(envelope.generation, &digest)
            .unwrap_or_else(|error| panic!("{error}"));
        store
            .put(
                &object_id,
                Bytes::from(vec![
                    0;
                    usize::try_from(MAX_KEYRING_ENVELOPE_OBJECT_BYTES + 1)
                        .unwrap_or_else(|error| panic!("{error}"))
                ]),
                PutOptions::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let result = store_keyring_envelope(&store, &envelope, None, None).await;

        assert!(matches!(
            result,
            Err(crate::RepositoryError::Storage(
                StorageError::BoundedReadExceeded {
                    max_bytes: MAX_KEYRING_ENVELOPE_OBJECT_BYTES,
                    ..
                }
            ))
        ));
    }
}
