//! Shared test fixtures for module-level repository tests.

use rs3_crypto::{KeyMaterial, KeyRing, SecretBytes};
use rs3_types::{BackendObjectId, KeyDescriptor, KeyId, KeyPurpose, KeyStatus};

pub(crate) fn backend_object_id(value: &str) -> BackendObjectId {
    BackendObjectId::new(value).unwrap_or_else(|error| panic!("{error}"))
}

fn secret_with_byte(byte: u8) -> SecretBytes {
    SecretBytes::new(vec![byte; SecretBytes::MIN_LEN]).unwrap_or_else(|error| panic!("{error}"))
}

fn key_id(value: &str) -> KeyId {
    KeyId::new(value).unwrap_or_else(|error| panic!("{error}"))
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
        secret_with_byte(secret_byte),
    )
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

fn content_key(value: &str, status: KeyStatus, secret_byte: u8) -> KeyMaterial {
    key_material(
        value,
        KeyPurpose::Content,
        status,
        "xchacha20poly1305",
        secret_byte,
    )
}

fn metadata_key(value: &str, status: KeyStatus, secret_byte: u8) -> KeyMaterial {
    key_material(
        value,
        KeyPurpose::Metadata,
        status,
        "aes-256-gcm-siv-hmac-sha256-nonce-v1",
        secret_byte,
    )
}

fn keyring(mut keys: Vec<KeyMaterial>) -> KeyRing {
    if !keys
        .iter()
        .any(|key| key.descriptor().purpose == KeyPurpose::Content)
    {
        keys.push(content_key("content", KeyStatus::Primary, 4));
    }
    if !keys
        .iter()
        .any(|key| key.descriptor().purpose == KeyPurpose::Metadata)
    {
        keys.push(metadata_key("metadata", KeyStatus::Primary, 2));
    }

    KeyRing::new(keys).unwrap_or_else(|error| panic!("{error}"))
}

pub(crate) fn signing_keyring() -> KeyRing {
    keyring(vec![
        namespace_key("namespace", KeyStatus::Primary, 1),
        metadata_key("metadata", KeyStatus::Primary, 2),
        checkpoint_key("signing", KeyStatus::Primary, 3),
        content_key("content", KeyStatus::Primary, 4),
    ])
}

pub(crate) fn wrong_content_keyring() -> KeyRing {
    keyring(vec![
        namespace_key("namespace", KeyStatus::Primary, 1),
        metadata_key("metadata", KeyStatus::Primary, 2),
        checkpoint_key("signing", KeyStatus::Primary, 3),
        content_key("content", KeyStatus::Primary, 44),
    ])
}
