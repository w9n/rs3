//! Property tests for client path metadata minimization invariants.

use bytes::Bytes;
use proptest::prelude::*;
use rs3_crypto::{KeyMaterial, KeyRing, SecretBytes};
use rs3_repository::v2::{
    V2CommitStoreOptions, V2FormatRef, V2KeyringEnvelopeRef, V2MemoryAnchor, V2ProviderProfile,
    V2Repository,
};
use rs3_repository::{RepositoryOptions, RepositoryPutOptions};
use rs3_storage::{BlobStore, ByteRange, MemoryBlobStore};
use rs3_types::{
    BackendObjectId, BackendVersionId, KeyDescriptor, KeyId, KeyPurpose, KeyStatus, LogicalPath,
};
use tokio::runtime::{Builder, Runtime};

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn committed_write_keeps_client_path_out_of_backend_metadata(
        path in "client/[a-z0-9]{1,16}/object-[a-z0-9]{1,16}"
    ) {
        let runtime = runtime();
        let result = runtime.block_on(check_committed_path(path));
        if let Err(error) = result {
            prop_assert!(false, "{error}");
        }
    }
}

async fn check_committed_path(path: String) -> Result<(), String> {
    let store = MemoryBlobStore::new();
    let repository = V2Repository::new(
        store.clone(),
        signing_keyring(),
        RepositoryOptions::default(),
        V2CommitStoreOptions::for_profile(
            V2ProviderProfile::Dev,
            sample_keyring_envelope_ref()?,
            sample_format_ref()?,
        ),
    );
    let anchor = V2MemoryAnchor::new();
    let logical_path = logical_path(path.clone())?;

    repository
        .write_genesis_snapshot(&anchor)
        .await
        .map_err(|error| error.to_string())?;
    repository
        .put_committed(
            &anchor,
            logical_path,
            Bytes::from_static(b"constant test body"),
            RepositoryPutOptions::default(),
        )
        .await
        .map_err(|error| error.to_string())?;

    let objects = store
        .list_prefix("")
        .await
        .map_err(|error| error.to_string())?;
    if objects.is_empty() {
        return Err("committed write produced no backend objects".to_owned());
    }

    for metadata in objects {
        let object_id = metadata.object_id.as_str();
        if object_id.contains(&path) {
            return Err(format!(
                "backend object id contains client path: {object_id}"
            ));
        }

        if object_id.starts_with("index/")
            || object_id.starts_with("checkpoints/")
            || object_id.starts_with("commits/")
            || object_id.starts_with("evidence/")
        {
            let body = store
                .get_range(&metadata.object_id, ByteRange::Full)
                .await
                .map_err(|error| error.to_string())?;
            let body = String::from_utf8_lossy(&body);
            if body.contains(&path) {
                return Err(format!(
                    "durable metadata object contains client path: {object_id}"
                ));
            }
        }
    }

    Ok(())
}

fn runtime() -> Runtime {
    match Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => panic!("{error}"),
    }
}

fn logical_path(value: String) -> Result<LogicalPath, String> {
    LogicalPath::new(value).map_err(|error| error.to_string())
}

fn sample_keyring_envelope_ref() -> Result<V2KeyringEnvelopeRef, String> {
    Ok(V2KeyringEnvelopeRef {
        object_id: object_id("keyrings/00000000000000000001-bootstrap")?,
        digest: [6_u8; 32],
    })
}

fn sample_format_ref() -> Result<V2FormatRef, String> {
    Ok(V2FormatRef {
        generation: 1,
        digest: hex::encode([7_u8; 32]),
        object_id: object_id(&format!("format/{:020}-{}", 1_u64, hex::encode([7_u8; 32])))?,
        version_id: Some(
            BackendVersionId::new("format-version-1").map_err(|error| error.to_string())?,
        ),
    })
}

fn object_id(value: &str) -> Result<BackendObjectId, String> {
    BackendObjectId::new(value).map_err(|error| error.to_string())
}

fn signing_keyring() -> KeyRing {
    keyring(vec![
        key_material(
            "namespace",
            KeyPurpose::Namespace,
            KeyStatus::Primary,
            "hmac-sha256",
            1,
        ),
        key_material(
            "metadata",
            KeyPurpose::Metadata,
            KeyStatus::Primary,
            "aes-256-gcm-siv-hmac-sha256-nonce-v1",
            2,
        ),
        key_material(
            "content",
            KeyPurpose::Content,
            KeyStatus::Primary,
            "xchacha20poly1305",
            4,
        ),
        key_material(
            "signing",
            KeyPurpose::CheckpointSigning,
            KeyStatus::Primary,
            "ed25519",
            3,
        ),
    ])
}

fn keyring(keys: Vec<KeyMaterial>) -> KeyRing {
    match KeyRing::new(keys) {
        Ok(keyring) => keyring,
        Err(error) => panic!("{error}"),
    }
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
            algorithm: algorithm.to_owned(),
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

fn key_id(value: &str) -> KeyId {
    match KeyId::new(value) {
        Ok(key_id) => key_id,
        Err(error) => panic!("{error}"),
    }
}

fn secret(byte: u8) -> SecretBytes {
    match SecretBytes::new(vec![byte; SecretBytes::MIN_LEN]) {
        Ok(secret) => secret,
        Err(error) => panic!("{error}"),
    }
}
