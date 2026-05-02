//! Checkpoint signing helpers.

use crate::CryptoError;
use crate::keyring::KeyRing;
use crate::primitives::{derive_hmac, verify_hmac};
use rs3_types::{CheckpointId, KeyId, KeyPurpose};
use sha2::{Digest, Sha256};

/// Checkpoint signature and the key that produced it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointSignature {
    /// Checkpoint signing key ID.
    pub key_id: KeyId,
    /// Signature bytes.
    pub signature: Vec<u8>,
}

impl KeyRing {
    /// Signs canonical checkpoint payload bytes with the primary signing key.
    pub fn sign_checkpoint_payload(
        &self,
        canonical_payload: &[u8],
    ) -> Result<CheckpointSignature, CryptoError> {
        let key = self.primary_key(KeyPurpose::CheckpointSigning)?;
        Ok(CheckpointSignature {
            key_id: key.descriptor.id.clone(),
            signature: derive_hmac(
                &key.secret,
                b"rs3:checkpoint-signature:hmac-sha256:v1",
                canonical_payload,
            )?,
        })
    }

    /// Verifies canonical checkpoint payload bytes with an enabled signing key.
    pub fn verify_checkpoint_payload(
        &self,
        key_id: &KeyId,
        canonical_payload: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let key = self.enabled_key_by_id(key_id, KeyPurpose::CheckpointSigning)?;
        verify_hmac(
            &key.secret,
            b"rs3:checkpoint-signature:hmac-sha256:v1",
            canonical_payload,
            signature,
        )
    }
}

/// Derives a stable checkpoint identifier from signed checkpoint bytes.
pub fn derive_checkpoint_id(
    canonical_payload: &[u8],
    signature: &[u8],
) -> Result<CheckpointId, CryptoError> {
    let mut digest = Sha256::new();
    digest.update(b"rs3:checkpoint-id:v1");
    digest.update([0]);
    digest.update(canonical_payload);
    digest.update([0]);
    digest.update(signature);
    CheckpointId::new(hex::encode(digest.finalize())).map_err(CryptoError::from)
}

#[cfg(test)]
mod tests {
    use super::derive_checkpoint_id;
    use crate::{KeyMaterial, KeyRing, SecretBytes};
    use rs3_types::{KeyDescriptor, KeyId, KeyPurpose, KeyStatus};

    fn secret(byte: u8) -> SecretBytes {
        match SecretBytes::new(vec![byte; SecretBytes::MIN_LEN]) {
            Ok(secret) => secret,
            Err(error) => panic!("{error}"),
        }
    }

    fn key_id(value: &str) -> KeyId {
        match KeyId::new(value) {
            Ok(key_id) => key_id,
            Err(error) => panic!("{error}"),
        }
    }

    fn namespace_key(value: &str, status: KeyStatus, secret_byte: u8) -> KeyMaterial {
        key_material(
            value,
            KeyPurpose::Namespace,
            status,
            "hmac-sha256",
            secret_byte,
        )
    }

    fn checkpoint_key(value: &str, status: KeyStatus, secret_byte: u8) -> KeyMaterial {
        key_material(
            value,
            KeyPurpose::CheckpointSigning,
            status,
            "hmac-sha256",
            secret_byte,
        )
    }

    fn key_material(
        value: &str,
        purpose: KeyPurpose,
        status: KeyStatus,
        algorithm: &str,
        secret_byte: u8,
    ) -> KeyMaterial {
        KeyMaterial::new(
            KeyDescriptor {
                id: key_id(value),
                purpose,
                algorithm: algorithm.to_string(),
                status,
                created_at_ms: 0,
                not_before_ms: None,
                not_after_ms: None,
                external_kms_uri: None,
            },
            secret(secret_byte),
        )
    }

    #[test]
    fn checkpoint_signatures_verify_with_enabled_signing_key() {
        let keyring = match KeyRing::new(vec![
            namespace_key("namespace", KeyStatus::Primary, 1),
            checkpoint_key("signing", KeyStatus::Primary, 2),
        ]) {
            Ok(keyring) => keyring,
            Err(error) => panic!("{error}"),
        };

        let signature = match keyring.sign_checkpoint_payload(b"canonical checkpoint") {
            Ok(signature) => signature,
            Err(error) => panic!("{error}"),
        };
        let verified = keyring.verify_checkpoint_payload(
            &signature.key_id,
            b"canonical checkpoint",
            &signature.signature,
        );

        assert!(verified.is_ok());
    }

    #[test]
    fn checkpoint_signature_verification_rejects_tampering() {
        let keyring = match KeyRing::new(vec![
            namespace_key("namespace", KeyStatus::Primary, 1),
            checkpoint_key("signing", KeyStatus::Primary, 2),
        ]) {
            Ok(keyring) => keyring,
            Err(error) => panic!("{error}"),
        };

        let signature = match keyring.sign_checkpoint_payload(b"canonical checkpoint") {
            Ok(signature) => signature,
            Err(error) => panic!("{error}"),
        };
        let verified = keyring.verify_checkpoint_payload(
            &signature.key_id,
            b"modified checkpoint",
            &signature.signature,
        );

        assert!(verified.is_err());
    }

    #[test]
    fn disabled_checkpoint_signing_key_cannot_verify() {
        let signer = match KeyRing::new(vec![
            namespace_key("namespace", KeyStatus::Primary, 1),
            checkpoint_key("signing", KeyStatus::Primary, 2),
        ]) {
            Ok(keyring) => keyring,
            Err(error) => panic!("{error}"),
        };
        let verifier = match KeyRing::new(vec![
            namespace_key("namespace", KeyStatus::Primary, 1),
            checkpoint_key("signing", KeyStatus::Disabled, 2),
            checkpoint_key("new-signing", KeyStatus::Primary, 3),
        ]) {
            Ok(keyring) => keyring,
            Err(error) => panic!("{error}"),
        };

        let signature = match signer.sign_checkpoint_payload(b"canonical checkpoint") {
            Ok(signature) => signature,
            Err(error) => panic!("{error}"),
        };
        let verified = verifier.verify_checkpoint_payload(
            &signature.key_id,
            b"canonical checkpoint",
            &signature.signature,
        );

        assert!(verified.is_err());
    }

    #[test]
    fn checkpoint_id_changes_with_signature() {
        let first = derive_checkpoint_id(b"canonical checkpoint", b"signature-a");
        let second = derive_checkpoint_id(b"canonical checkpoint", b"signature-b");

        assert!(first.is_ok());
        assert!(second.is_ok());
        assert_ne!(first.ok(), second.ok());
    }
}
