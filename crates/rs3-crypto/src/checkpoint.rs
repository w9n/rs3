//! Checkpoint signing helpers.

use crate::CryptoError;
use crate::SecretBytes;
use crate::keyring::KeyRing;
use crate::primitives::derive_hmac;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use rs3_types::{BackendObjectId, CheckpointId, KeyId, KeyPurpose};
use sha2::{Digest, Sha256};

const CHECKPOINT_PUBLIC_KEY_HEX_LEN: usize = 64;
const CHECKPOINT_PUBLIC_KEY_PREFIX: &str = "ed25519:";

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
        let signing_key = checkpoint_signing_key(&key.secret)?;
        Ok(CheckpointSignature {
            key_id: key.descriptor.id.clone(),
            signature: signing_key.sign(canonical_payload).as_ref().to_vec(),
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
        let public_key = match key.descriptor.public_key.as_deref() {
            Some(public_key) => checkpoint_public_key_bytes(public_key)?,
            None => derive_checkpoint_public_key(&key.secret)?,
        };
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(canonical_payload, signature)
            .map_err(|_| CryptoError::SignatureMismatch)
    }
}

/// Verifies an offline recovery signature with an `ed25519:<hex-public-key>` descriptor.
pub fn verify_recovery_signature(
    public_key: &str,
    canonical_payload: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let public_key = recovery_public_key_bytes(public_key)?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(canonical_payload, signature)
        .map_err(|_| CryptoError::SignatureMismatch)
}

/// Validates an `ed25519:<hex-public-key>` recovery verification key.
pub fn validate_recovery_public_key(public_key: &str) -> Result<(), CryptoError> {
    recovery_public_key_bytes(public_key).map(|_| ())
}

/// Derives the public Ed25519 checkpoint verification key for a secret key.
pub(crate) fn derive_checkpoint_public_key(secret: &SecretBytes) -> Result<Vec<u8>, CryptoError> {
    Ok(checkpoint_signing_key(secret)?
        .public_key()
        .as_ref()
        .to_vec())
}

/// Derives the descriptor form for a public checkpoint verification key.
pub(crate) fn derive_checkpoint_public_key_descriptor(
    secret: &SecretBytes,
) -> Result<String, CryptoError> {
    Ok(format!(
        "{CHECKPOINT_PUBLIC_KEY_PREFIX}{}",
        hex::encode(derive_checkpoint_public_key(secret)?)
    ))
}

fn checkpoint_signing_key(secret: &SecretBytes) -> Result<Ed25519KeyPair, CryptoError> {
    let seed = derive_hmac(secret, b"rs3:checkpoint-ed25519-seed:v1", b"ed25519")?;
    Ed25519KeyPair::from_seed_unchecked(&seed)
        .map_err(|_| CryptoError::CheckpointSigningKeyRejected)
}

fn checkpoint_public_key_bytes(public_key: &str) -> Result<Vec<u8>, CryptoError> {
    prefixed_ed25519_public_key_bytes(public_key)
        .map_err(|_| CryptoError::CheckpointPublicKeyMalformed)
}

fn recovery_public_key_bytes(public_key: &str) -> Result<Vec<u8>, CryptoError> {
    prefixed_ed25519_public_key_bytes(public_key)
        .map_err(|_| CryptoError::RecoveryPublicKeyMalformed)
}

fn prefixed_ed25519_public_key_bytes(public_key: &str) -> Result<Vec<u8>, ()> {
    let Some(hex_key) = public_key.strip_prefix(CHECKPOINT_PUBLIC_KEY_PREFIX) else {
        return Err(());
    };
    if hex_key.len() != CHECKPOINT_PUBLIC_KEY_HEX_LEN {
        return Err(());
    }
    hex::decode(hex_key).map_err(|_| ())
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

/// Derives a stable digest for canonical checkpoint payload bytes.
pub fn derive_checkpoint_payload_digest(canonical_payload: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"rs3:checkpoint-payload-digest:v1");
    digest.update([0]);
    digest.update(canonical_payload);
    hex::encode(digest.finalize())
}

/// Derives an opaque backend object ID for an encoded index delta object.
pub fn derive_index_delta_object_id(delta_object: &[u8]) -> Result<BackendObjectId, CryptoError> {
    let mut digest = Sha256::new();
    digest.update(b"rs3:index-delta-object-id:v1");
    digest.update([0]);
    digest.update(delta_object);
    BackendObjectId::new(format!("index/{}", hex::encode(digest.finalize())))
        .map_err(CryptoError::from)
}

#[cfg(test)]
mod tests {
    use super::{
        derive_checkpoint_id, derive_checkpoint_payload_digest, derive_index_delta_object_id,
        validate_recovery_public_key, verify_recovery_signature,
    };
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
            "ed25519",
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
                public_key: None,
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
        assert_eq!(signature.signature.len(), 64);
    }

    #[test]
    fn recovery_signatures_verify_with_public_descriptor() {
        let keyring = match KeyRing::generate_random() {
            Ok(keyring) => keyring,
            Err(error) => panic!("{error}"),
        };
        let signature = match keyring.sign_checkpoint_payload(b"canonical recovery payload") {
            Ok(signature) => signature,
            Err(error) => panic!("{error}"),
        };
        let public_key = keyring
            .descriptors()
            .into_iter()
            .find(|descriptor| descriptor.id == signature.key_id)
            .and_then(|descriptor| descriptor.public_key)
            .unwrap_or_else(|| panic!("missing recovery public key"));

        validate_recovery_public_key(&public_key).unwrap_or_else(|error| panic!("{error}"));
        verify_recovery_signature(
            &public_key,
            b"canonical recovery payload",
            &signature.signature,
        )
        .unwrap_or_else(|error| panic!("{error}"));

        let error = match verify_recovery_signature(
            &public_key,
            b"tampered recovery payload",
            &signature.signature,
        ) {
            Ok(_) => panic!("tampered recovery payload should be rejected"),
            Err(error) => error,
        };
        assert!(matches!(error, crate::CryptoError::SignatureMismatch));
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
    fn checkpoint_signature_verification_rejects_wrong_public_key_metadata() {
        let signer = match KeyRing::new(vec![
            namespace_key("namespace", KeyStatus::Primary, 1),
            key_material(
                "signing",
                KeyPurpose::CheckpointSigning,
                KeyStatus::Primary,
                "ed25519",
                2,
            ),
        ]) {
            Ok(keyring) => keyring,
            Err(error) => panic!("{error}"),
        };
        let verifier = match KeyRing::new(vec![
            namespace_key("namespace", KeyStatus::Primary, 1),
            KeyMaterial::new(
                KeyDescriptor {
                    id: key_id("signing"),
                    purpose: KeyPurpose::CheckpointSigning,
                    algorithm: "ed25519".to_owned(),
                    status: KeyStatus::Primary,
                    created_at_ms: 0,
                    not_before_ms: None,
                    not_after_ms: None,
                    public_key: Some(
                        "ed25519:0000000000000000000000000000000000000000000000000000000000000000"
                            .to_owned(),
                    ),
                    external_kms_uri: None,
                },
                secret(2),
            ),
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
    fn checkpoint_signature_verification_rejects_malformed_public_key_metadata() {
        let signer = match KeyRing::new(vec![
            namespace_key("namespace", KeyStatus::Primary, 1),
            key_material(
                "signing",
                KeyPurpose::CheckpointSigning,
                KeyStatus::Primary,
                "ed25519",
                2,
            ),
        ]) {
            Ok(keyring) => keyring,
            Err(error) => panic!("{error}"),
        };
        let verifier = match KeyRing::new(vec![
            namespace_key("namespace", KeyStatus::Primary, 1),
            KeyMaterial::new(
                KeyDescriptor {
                    id: key_id("signing"),
                    purpose: KeyPurpose::CheckpointSigning,
                    algorithm: "ed25519".to_owned(),
                    status: KeyStatus::Primary,
                    created_at_ms: 0,
                    not_before_ms: None,
                    not_after_ms: None,
                    public_key: Some("ed25519:not-hex".to_owned()),
                    external_kms_uri: None,
                },
                secret(2),
            ),
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

        assert!(matches!(
            verified,
            Err(crate::CryptoError::CheckpointPublicKeyMalformed)
        ));
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

    #[test]
    fn checkpoint_payload_digest_ignores_signature() {
        let first = derive_checkpoint_payload_digest(b"canonical checkpoint");
        let second = derive_checkpoint_payload_digest(b"canonical checkpoint");

        assert_eq!(first, second);
    }

    #[test]
    fn index_delta_object_id_uses_index_prefix() {
        let object_id = derive_index_delta_object_id(b"delta bytes");

        assert!(matches!(
            object_id,
            Ok(object_id) if object_id.as_str().starts_with("index/")
        ));
    }
}
