use crate::v2::{V2FormatError, V2Result};
use rs3_crypto::Sha256Hasher;
use rs3_index::PayloadLayout;
use rs3_types::{BackendObjectId, BackendObjectRef, BackendVersionId};

const V2_STREAM_PAYLOAD_CACHE_DOMAIN: &[u8] = b"rs3:v02-stream-segment-cache:v1\n";

/// Authenticated carrier facts that distinguish one streamed payload cache entry.
///
/// `payload_id` remains the AEAD associated-data identity. The derived object
/// reference is only a cache namespace and must never replace it during open.
pub(crate) struct V2StreamPayloadCacheIdentity<'a> {
    pub(crate) repository_keyring_context: &'a [u8],
    pub(crate) carrier: V2StreamPayloadCarrierCacheIdentity<'a>,
    pub(crate) payload_id: &'a BackendObjectId,
    pub(crate) payload_layout: &'a PayloadLayout,
    pub(crate) content_len: u64,
}

pub(crate) enum V2StreamPayloadCarrierCacheIdentity<'a> {
    Standalone {
        object_id: &'a BackendObjectId,
        version_id: Option<&'a BackendVersionId>,
        object_digest: [u8; 32],
        stored_len: u64,
    },
}

impl V2StreamPayloadCacheIdentity<'_> {
    /// Validates the exact carrier range and derives its plaintext-cache identity.
    pub(crate) fn cache_ref(&self) -> V2Result<BackendObjectRef> {
        if self.payload_layout.plaintext_len != self.content_len {
            return Err(V2FormatError::InvalidHeaderField);
        }

        let mut digest = Sha256Hasher::new();
        digest.update(V2_STREAM_PAYLOAD_CACHE_DOMAIN);
        update_digest_field(&mut digest, self.repository_keyring_context)?;
        let cache_version_id = match &self.carrier {
            V2StreamPayloadCarrierCacheIdentity::Standalone {
                object_id,
                version_id,
                object_digest,
                stored_len,
            } => {
                digest.update([1]);
                update_digest_field(&mut digest, object_id.as_str().as_bytes())?;
                update_version_id(&mut digest, *version_id)?;
                digest.update(object_digest);
                digest.update(stored_len.to_be_bytes());
                *version_id
            }
        };
        update_digest_field(&mut digest, self.payload_id.as_str().as_bytes())?;
        digest.update(self.payload_layout.chunk_size.to_be_bytes());
        digest.update(self.payload_layout.plaintext_len.to_be_bytes());
        update_digest_field(&mut digest, self.payload_layout.key_id.as_str().as_bytes())?;
        digest.update(self.payload_layout.carrier_id);
        digest.update((self.payload_layout.parts.len() as u64).to_be_bytes());
        for part in &self.payload_layout.parts {
            digest.update(part.part_number.to_be_bytes());
            digest.update(part.attempt_id.as_bytes());
            digest.update(part.plaintext_len.to_be_bytes());
        }
        digest.update(self.content_len.to_be_bytes());

        let object_id = BackendObjectId::new(format!(
            "v2-stream-cache/{}",
            hex::encode(digest.finalize())
        ))
        .map_err(|_| V2FormatError::InvalidHeaderField)?;
        Ok(BackendObjectRef {
            object_id,
            version_id: cache_version_id.cloned(),
        })
    }
}

fn update_version_id(
    digest: &mut Sha256Hasher,
    version_id: Option<&BackendVersionId>,
) -> V2Result<()> {
    match version_id {
        None => digest.update([0]),
        Some(version_id) => {
            digest.update([1]);
            update_digest_field(digest, version_id.as_str().as_bytes())?;
        }
    }
    Ok(())
}

fn update_digest_field(digest: &mut Sha256Hasher, value: &[u8]) -> V2Result<()> {
    let length = u64::try_from(value.len()).map_err(|_| V2FormatError::SectionBounds)?;
    digest.update(length.to_be_bytes());
    digest.update(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{V2StreamPayloadCacheIdentity, V2StreamPayloadCarrierCacheIdentity};
    use crate::v2::V2FormatError;
    use rs3_index::PayloadLayout;
    use rs3_types::{BackendObjectId, BackendVersionId, KeyId};

    struct Fixture {
        context: Vec<u8>,
        commit_key: BackendObjectId,
        version_id: Option<BackendVersionId>,
        body_digest: [u8; 32],
        stored_len: u64,
        payload_id: BackendObjectId,
        header: PayloadLayout,
        content_len: u64,
    }

    impl Fixture {
        fn identity(&self) -> V2StreamPayloadCacheIdentity<'_> {
            V2StreamPayloadCacheIdentity {
                repository_keyring_context: &self.context,
                carrier: V2StreamPayloadCarrierCacheIdentity::Standalone {
                    object_id: &self.commit_key,
                    version_id: self.version_id.as_ref(),
                    object_digest: self.body_digest,
                    stored_len: self.stored_len,
                },
                payload_id: &self.payload_id,
                payload_layout: &self.header,
                content_len: self.content_len,
            }
        }
    }

    fn object_id(value: &str) -> BackendObjectId {
        BackendObjectId::new(value).unwrap_or_else(|error| panic!("{error}"))
    }

    fn fixture() -> Fixture {
        Fixture {
            context: b"repository-and-keyring-context".to_vec(),
            commit_key: object_id("commits/v02/42/commit"),
            version_id: Some(
                BackendVersionId::new("version-1").unwrap_or_else(|error| panic!("{error}")),
            ),
            body_digest: [1; 32],
            stored_len: 16_384,
            payload_id: object_id("v2-payload/payload-1"),
            header: PayloadLayout {
                chunk_size: 65_536,
                plaintext_len: 8_000,
                key_id: KeyId::new("content-key-1").unwrap_or_else(|error| panic!("{error}")),
                carrier_id: [3; 32],
                parts: vec![rs3_index::PayloadPart {
                    part_number: 1,
                    attempt_id: rs3_types::PayloadAttemptId::from_bytes([0x81; 32]),
                    plaintext_len: 8_000,
                }],
            },
            content_len: 8_000,
        }
    }

    #[test]
    fn cache_identity_binds_every_authenticated_carrier_fact() {
        let original = fixture();
        let expected = original
            .identity()
            .cache_ref()
            .unwrap_or_else(|error| panic!("{error}"));

        let variants = [
            {
                let mut value = fixture();
                value.context.push(1);
                value
            },
            {
                let mut value = fixture();
                value.commit_key = object_id("commits/v02/42/other");
                value
            },
            {
                let mut value = fixture();
                value.version_id = None;
                value
            },
            {
                let mut value = fixture();
                value.body_digest[0] ^= 1;
                value
            },
            {
                let mut value = fixture();
                value.stored_len += 1;
                value
            },
            {
                let mut value = fixture();
                value.payload_id = object_id("v2-payload/payload-2");
                value
            },
            {
                let mut value = fixture();
                value.header.chunk_size += 1;
                value
            },
            {
                let mut value = fixture();
                value.header.plaintext_len += 1;
                value.content_len += 1;
                value
            },
            {
                let mut value = fixture();
                value.header.key_id =
                    KeyId::new("content-key-2").unwrap_or_else(|error| panic!("{error}"));
                value
            },
            {
                let mut value = fixture();
                value.header.carrier_id[0] ^= 1;
                value
            },
            {
                let mut value = fixture();
                value.header.parts[0].part_number += 1;
                value
            },
            {
                let mut value = fixture();
                value.header.parts[0].attempt_id =
                    rs3_types::PayloadAttemptId::from_bytes([0x82; 32]);
                value
            },
            {
                let mut value = fixture();
                value.header.parts[0].plaintext_len += 1;
                value
            },
        ];

        for variant in variants {
            let actual = variant
                .identity()
                .cache_ref()
                .unwrap_or_else(|error| panic!("{error}"));
            assert_ne!(actual, expected);
        }
    }

    #[test]
    fn cache_identity_rejects_plaintext_length_mismatch() {
        let mut value = fixture();
        value.content_len += 1;
        assert_eq!(
            value.identity().cache_ref(),
            Err(V2FormatError::InvalidHeaderField)
        );
    }
}
