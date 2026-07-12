use crate::v2::{V2FormatError, V2Result};
use rs3_index::PayloadHeaderReference;
use rs3_types::{BackendObjectId, BackendObjectRef, BackendVersionId};
use sha2::{Digest, Sha256};

const V2_STREAM_PAYLOAD_CACHE_DOMAIN: &[u8] = b"rs3:v02-stream-segment-cache:v1\n";

/// Authenticated carrier facts that distinguish one streamed payload cache entry.
///
/// `payload_id` remains the AEAD associated-data identity. The derived object
/// reference is only a cache namespace and must never replace it during open.
pub(crate) struct V2StreamPayloadCacheIdentity<'a> {
    pub(crate) repository_keyring_context: &'a [u8],
    pub(crate) carrier: V2StreamPayloadCarrierCacheIdentity<'a>,
    pub(crate) payload_id: &'a BackendObjectId,
    pub(crate) payload_header: &'a PayloadHeaderReference,
    pub(crate) content_len: u64,
}

pub(crate) enum V2StreamPayloadCarrierCacheIdentity<'a> {
    Commit {
        commit_key: &'a BackendObjectId,
        commit_version_id: Option<&'a BackendVersionId>,
        commit_body_digest: [u8; 32],
        commit_stored_len: u64,
        payload_section_ordinal: u32,
        payload_section_digest: [u8; 32],
        sections_start: u64,
        payload_section_offset: u64,
        payload_section_len: u64,
    },
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
        if self.payload_header.plaintext_len != self.content_len {
            return Err(V2FormatError::InvalidHeaderField);
        }

        let mut digest = Sha256::new();
        digest.update(V2_STREAM_PAYLOAD_CACHE_DOMAIN);
        update_digest_field(&mut digest, self.repository_keyring_context)?;
        let cache_version_id = match &self.carrier {
            V2StreamPayloadCarrierCacheIdentity::Commit {
                commit_key,
                commit_version_id,
                commit_body_digest,
                commit_stored_len,
                payload_section_ordinal,
                payload_section_digest,
                sections_start,
                payload_section_offset,
                payload_section_len,
            } => {
                validated_v2_stream_payload_start(
                    *sections_start,
                    *payload_section_offset,
                    *payload_section_len,
                    *commit_stored_len,
                )?;
                digest.update([0]);
                update_digest_field(&mut digest, commit_key.as_str().as_bytes())?;
                update_version_id(&mut digest, *commit_version_id)?;
                digest.update(commit_body_digest);
                digest.update(commit_stored_len.to_be_bytes());
                digest.update(payload_section_ordinal.to_be_bytes());
                digest.update(payload_section_digest);
                digest.update(sections_start.to_be_bytes());
                digest.update(payload_section_offset.to_be_bytes());
                digest.update(payload_section_len.to_be_bytes());
                *commit_version_id
            }
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
        digest.update(self.payload_header.chunk_size.to_be_bytes());
        digest.update(self.payload_header.plaintext_len.to_be_bytes());
        update_digest_field(&mut digest, self.payload_header.key_id.as_str().as_bytes())?;
        digest.update(self.payload_header.nonce_prefix);
        digest.update(self.payload_header.header_len.to_be_bytes());
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

fn update_version_id(digest: &mut Sha256, version_id: Option<&BackendVersionId>) -> V2Result<()> {
    match version_id {
        None => digest.update([0]),
        Some(version_id) => {
            digest.update([1]);
            update_digest_field(digest, version_id.as_str().as_bytes())?;
        }
    }
    Ok(())
}

/// Returns the absolute payload start after proving the complete section is in bounds.
pub(crate) fn validated_v2_stream_payload_start(
    sections_start: u64,
    payload_section_offset: u64,
    payload_section_len: u64,
    commit_stored_len: u64,
) -> V2Result<u64> {
    let payload_start = sections_start
        .checked_add(payload_section_offset)
        .ok_or(V2FormatError::SectionBounds)?;
    let payload_end = payload_start
        .checked_add(payload_section_len)
        .ok_or(V2FormatError::SectionBounds)?;
    if payload_end > commit_stored_len {
        return Err(V2FormatError::SectionBounds);
    }
    Ok(payload_start)
}

fn update_digest_field(digest: &mut Sha256, value: &[u8]) -> V2Result<()> {
    let length = u64::try_from(value.len()).map_err(|_| V2FormatError::SectionBounds)?;
    digest.update(length.to_be_bytes());
    digest.update(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        V2StreamPayloadCacheIdentity, V2StreamPayloadCarrierCacheIdentity,
        validated_v2_stream_payload_start,
    };
    use crate::v2::V2FormatError;
    use rs3_index::PayloadHeaderReference;
    use rs3_types::{BackendObjectId, BackendVersionId, KeyId};

    struct Fixture {
        context: Vec<u8>,
        commit_key: BackendObjectId,
        version_id: Option<BackendVersionId>,
        body_digest: [u8; 32],
        stored_len: u64,
        section_ordinal: u32,
        section_digest: [u8; 32],
        sections_start: u64,
        section_offset: u64,
        section_len: u64,
        payload_id: BackendObjectId,
        header: PayloadHeaderReference,
        content_len: u64,
    }

    impl Fixture {
        fn identity(&self) -> V2StreamPayloadCacheIdentity<'_> {
            V2StreamPayloadCacheIdentity {
                repository_keyring_context: &self.context,
                carrier: V2StreamPayloadCarrierCacheIdentity::Commit {
                    commit_key: &self.commit_key,
                    commit_version_id: self.version_id.as_ref(),
                    commit_body_digest: self.body_digest,
                    commit_stored_len: self.stored_len,
                    payload_section_ordinal: self.section_ordinal,
                    payload_section_digest: self.section_digest,
                    sections_start: self.sections_start,
                    payload_section_offset: self.section_offset,
                    payload_section_len: self.section_len,
                },
                payload_id: &self.payload_id,
                payload_header: &self.header,
                content_len: self.content_len,
            }
        }
    }

    #[test]
    fn standalone_and_commit_carriers_cannot_alias_cache_identity() {
        let fixture = fixture();
        let commit = fixture
            .identity()
            .cache_ref()
            .unwrap_or_else(|error| panic!("{error}"));
        let standalone = V2StreamPayloadCacheIdentity {
            repository_keyring_context: &fixture.context,
            carrier: V2StreamPayloadCarrierCacheIdentity::Standalone {
                object_id: &fixture.commit_key,
                version_id: fixture.version_id.as_ref(),
                object_digest: fixture.body_digest,
                stored_len: fixture.stored_len,
            },
            payload_id: &fixture.payload_id,
            payload_header: &fixture.header,
            content_len: fixture.content_len,
        }
        .cache_ref()
        .unwrap_or_else(|error| panic!("{error}"));

        assert_ne!(commit, standalone);
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
            section_ordinal: 0,
            section_digest: [2; 32],
            sections_start: 4_096,
            section_offset: 128,
            section_len: 8_192,
            payload_id: object_id("v2-payload/payload-1"),
            header: PayloadHeaderReference {
                chunk_size: 65_536,
                plaintext_len: 8_000,
                key_id: KeyId::new("content-key-1").unwrap_or_else(|error| panic!("{error}")),
                nonce_prefix: [3; 16],
                header_len: 96,
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
                value.section_ordinal += 1;
                value
            },
            {
                let mut value = fixture();
                value.section_digest[0] ^= 1;
                value
            },
            {
                let mut value = fixture();
                value.sections_start += 1;
                value
            },
            {
                let mut value = fixture();
                value.section_offset += 1;
                value
            },
            {
                let mut value = fixture();
                value.section_len += 1;
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
                value.header.nonce_prefix[0] ^= 1;
                value
            },
            {
                let mut value = fixture();
                value.header.header_len += 1;
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
    fn cache_identity_rejects_carrier_ranges_beyond_stored_object() {
        let mut value = fixture();
        value.stored_len = value.sections_start + value.section_offset + value.section_len - 1;
        assert_eq!(
            value.identity().cache_ref(),
            Err(V2FormatError::SectionBounds)
        );

        value.sections_start = u64::MAX;
        assert_eq!(
            value.identity().cache_ref(),
            Err(V2FormatError::SectionBounds)
        );
    }

    #[test]
    fn validated_payload_start_rejects_overflow_and_out_of_bounds_sections() {
        assert_eq!(
            validated_v2_stream_payload_start(4_096, 128, 8_192, 16_384),
            Ok(4_224)
        );
        assert_eq!(
            validated_v2_stream_payload_start(4_096, 128, 8_192, 12_415),
            Err(V2FormatError::SectionBounds)
        );
        assert_eq!(
            validated_v2_stream_payload_start(u64::MAX, 1, 0, u64::MAX),
            Err(V2FormatError::SectionBounds)
        );
        assert_eq!(
            validated_v2_stream_payload_start(1, 0, u64::MAX, u64::MAX),
            Err(V2FormatError::SectionBounds)
        );
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
