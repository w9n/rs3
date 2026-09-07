//! Canonical portable recovery artifacts, independent of operator JSON reports.

use super::{V2AnchorState, V2FormatError, V2FormatRef, V2RecoveryBundle, V2Result, cbor, wire};
use rs3_types::{BackendObjectId, BackendVersionId, KeyId, RepositoryId, Sequence};

/// Maximum encoded portable recovery bundle size, including its signature.
pub const MAX_RECOVERY_BUNDLE_BYTES: usize = 16 * 1024;
const VERSION: u64 = 3;
const SIGNATURE_DOMAIN: &str = "rs3:v3-recovery-bundle-offline-signature:v1";

impl V2RecoveryBundle {
    /// Encodes the canonical artifact. JSON reports are not importable artifacts.
    pub fn to_object_bytes(&self) -> V2Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode(&mut out, true)?;
        wire::require(out.len() <= MAX_RECOVERY_BUNDLE_BYTES)?;
        Ok(out)
    }

    /// Decodes a bounded canonical artifact, rejecting retired JSON and trailing bytes.
    pub fn from_object_bytes(bytes: &[u8]) -> V2Result<Self> {
        wire::require(bytes.len() <= MAX_RECOVERY_BUNDLE_BYTES)?;
        let mut reader = cbor::Reader::new(bytes);
        wire::require(reader.read_array_len()? == 7 && reader.read_u64()? == VERSION)?;
        let repository_id = wire::read_optional_text(&mut reader)?
            .map(RepositoryId::new)
            .transpose()?;
        let repository_salt_digest = if reader.next_is_null() {
            reader.read_null()?;
            None
        } else {
            Some(wire::read_digest(&mut reader)?)
        };
        wire::require(
            reader.read_array_len()? == 7
                && reader.read_u64()? == u64::from(super::V2_FORMAT_VERSION),
        )?;
        let sequence = Sequence::new(reader.read_u64()?);
        let commit_key = BackendObjectId::new(reader.read_text_bounded(wire::MAX_WIRE_TEXT)?)?;
        let body_digest = wire::read_digest(&mut reader)?;
        let version_id = wire::read_optional_text(&mut reader)?
            .map(BackendVersionId::new)
            .transpose()?;
        let signing_key_id = KeyId::new(reader.read_text_bounded(wire::MAX_WIRE_KEY_ID)?)?;
        let (generation, digest, object_id, format_version_id) =
            wire::read_envelope_ref(&mut reader)?;
        let anchor = V2AnchorState {
            sequence,
            commit_key,
            body_digest,
            version_id,
            signing_key_id,
            format_ref: V2FormatRef {
                generation,
                digest,
                object_id,
                version_id: format_version_id,
            },
        };
        let weak_subjectivity_floor_sequence = Sequence::new(reader.read_u64()?);
        let exported_at_ms = reader.read_i64()?;
        let offline_signature = if reader.next_is_null() {
            reader.read_null()?;
            None
        } else {
            let signature = reader.read_bytes_bounded(64)?;
            wire::require(signature.len() == 64)?;
            Some(signature)
        };
        wire::require(reader.is_finished())?;
        Ok(Self {
            repository_id,
            repository_salt_digest,
            anchor,
            weak_subjectivity_floor_sequence,
            exported_at_ms,
            offline_signature,
        })
    }

    /// Returns the domain and canonical unsigned bundle covered by the offline signature.
    pub fn offline_signature_payload(&self) -> V2Result<Vec<u8>> {
        if self.repository_id.is_none() {
            return Err(V2FormatError::RecoveryBundleRequired);
        }
        let mut out = Vec::new();
        cbor::write_array_len(&mut out, 2);
        cbor::write_text(&mut out, SIGNATURE_DOMAIN);
        self.encode(&mut out, false)?;
        Ok(out)
    }

    fn encode(&self, out: &mut Vec<u8>, include_signature: bool) -> V2Result<()> {
        cbor::write_array_len(out, if include_signature { 7 } else { 6 });
        cbor::write_u64(out, VERSION);
        wire::write_optional_text(out, self.repository_id.as_ref().map(RepositoryId::as_str))?;
        match self.repository_salt_digest {
            Some(digest) => cbor::write_bytes(out, &digest),
            None => cbor::write_null(out),
        }
        let anchor = &self.anchor;
        cbor::write_array_len(out, 7);
        cbor::write_u64(out, u64::from(super::V2_FORMAT_VERSION));
        cbor::write_u64(out, anchor.sequence.get());
        wire::write_text(out, anchor.commit_key.as_str(), wire::MAX_WIRE_TEXT)?;
        cbor::write_bytes(out, &anchor.body_digest);
        wire::write_optional_text(
            out,
            anchor.version_id.as_ref().map(BackendVersionId::as_str),
        )?;
        wire::write_text(out, anchor.signing_key_id.as_str(), wire::MAX_WIRE_KEY_ID)?;
        let format = &anchor.format_ref;
        wire::write_envelope_ref(
            out,
            format.generation,
            &format.digest,
            &format.object_id,
            format.version_id.as_ref(),
        )?;
        cbor::write_u64(out, self.weak_subjectivity_floor_sequence.get());
        cbor::write_i64(out, self.exported_at_ms);
        if include_signature {
            match &self.offline_signature {
                Some(signature) => {
                    wire::require(signature.len() == 64)?;
                    cbor::write_bytes(out, signature);
                }
                None => cbor::write_null(out),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle() -> V2RecoveryBundle {
        let anchor = V2AnchorState {
            sequence: Sequence::new(7),
            commit_key: BackendObjectId::new("c").expect("key"),
            body_digest: [0x11; 32],
            version_id: None,
            signing_key_id: KeyId::new("s").expect("key"),
            format_ref: V2FormatRef {
                generation: 1,
                digest: "22".repeat(32),
                object_id: BackendObjectId::new("f").expect("key"),
                version_id: None,
            },
        };
        let mut bundle = V2RecoveryBundle::from_anchor(anchor, Sequence::new(5));
        bundle.repository_id = Some(RepositoryId::new("r").expect("repo"));
        bundle.exported_at_ms = -1;
        bundle
    }

    #[test]
    fn canonical_bundle_has_pinned_bytes_and_rejects_malformed_encodings() {
        let bundle = bundle();
        let bytes = bundle.to_object_bytes().expect("encode");
        // Independently specified CBOR: array7, version, repo, salt, anchor7, floor, time, signature.
        let expected = format!(
            "87036172f687030761635820{}f6617384015820{}6166f60520f6",
            "11".repeat(32),
            "22".repeat(32)
        );
        assert_eq!(hex::encode(&bytes), expected);
        assert_eq!(
            V2RecoveryBundle::from_object_bytes(&bytes).expect("decode"),
            bundle
        );
        for length in 0..bytes.len() {
            assert!(V2RecoveryBundle::from_object_bytes(&bytes[..length]).is_err());
        }
        let mut nonminimal = vec![0x87, 0x18, 3];
        nonminimal.extend_from_slice(&bytes[2..]);
        let mut trailing = bytes.clone();
        trailing.push(0);
        let mut unknown = bytes.clone();
        unknown[1] = 4;
        let mut indefinite = bytes.clone();
        indefinite[0] = 0x9f;
        let mut extra = bytes.clone();
        extra[0] = 0x88;
        extra.push(0);
        let oversized_repo = [0x87, 3, 0x7a, 0xff, 0xff, 0xff, 0xff];
        for invalid in [
            nonminimal,
            trailing,
            unknown,
            indefinite,
            extra,
            oversized_repo.to_vec(),
            vec![0; MAX_RECOVERY_BUNDLE_BYTES + 1],
            b"{}".to_vec(),
        ] {
            assert!(V2RecoveryBundle::from_object_bytes(&invalid).is_err());
        }
    }

    #[test]
    fn offline_signature_covers_every_bundle_field() {
        let signer = rs3_crypto::KeyRing::generate_random().expect("signer");
        let public_key = signer
            .descriptors()
            .into_iter()
            .find(|key| key.purpose == rs3_types::KeyPurpose::CheckpointSigning)
            .and_then(|key| key.public_key)
            .expect("public key");
        let mut bundle = bundle();
        let payload = bundle.offline_signature_payload().expect("payload");
        let mut expected = vec![0x82, 0x78, 0x2b];
        expected.extend_from_slice(b"rs3:v3-recovery-bundle-offline-signature:v1");
        // The unsigned schema omits the final signature element entirely.
        let mut unsigned = bundle.to_object_bytes().expect("bytes");
        unsigned[0] = 0x86;
        unsigned.pop();
        expected.extend_from_slice(&unsigned);
        assert_eq!(payload, expected);
        bundle.offline_signature = Some(
            signer
                .sign_checkpoint_payload(&payload)
                .expect("sign")
                .signature,
        );
        bundle.verify_offline_signature(&public_key).expect("valid");
        let decoded =
            V2RecoveryBundle::from_object_bytes(&bundle.to_object_bytes().expect("encode"))
                .expect("decode");
        decoded
            .verify_offline_signature(&public_key)
            .expect("portable signature");
        for field in 0..12 {
            let mut changed = bundle.clone();
            match field {
                0 => changed.repository_id = Some(RepositoryId::new("other").expect("repo")),
                1 => changed.repository_salt_digest = Some([7; 32]),
                2 => changed.anchor.sequence = Sequence::new(8),
                3 => changed.anchor.commit_key = BackendObjectId::new("other").expect("key"),
                4 => changed.anchor.body_digest[0] ^= 1,
                5 => {
                    changed.anchor.version_id =
                        Some(BackendVersionId::new("other").expect("version"))
                }
                6 => changed.anchor.signing_key_id = KeyId::new("other").expect("key"),
                7 => changed.anchor.format_ref.generation += 1,
                8 => changed.anchor.format_ref.digest = "33".repeat(32),
                9 => {
                    changed.anchor.format_ref.object_id =
                        BackendObjectId::new("other").expect("key")
                }
                10 => changed.weak_subjectivity_floor_sequence = Sequence::new(4),
                _ => changed.exported_at_ms += 1,
            }
            assert!(
                changed.verify_offline_signature(&public_key).is_err(),
                "field {field}"
            );
        }
        let mut changed = bundle.clone();
        changed.anchor.format_ref.version_id =
            Some(BackendVersionId::new("other").expect("version"));
        assert!(changed.verify_offline_signature(&public_key).is_err());
        changed = bundle.clone();
        changed.offline_signature = Some(vec![0; 64]);
        assert!(changed.verify_offline_signature(&public_key).is_err());
        changed.offline_signature = Some(vec![0; 65]);
        assert!(changed.to_object_bytes().is_err());
    }
}
