//! Cryptographic boundaries for repository privacy.

mod checkpoint;
mod constant_time;
mod derive;
mod envelope;
mod error;
mod fingerprint;
#[cfg(feature = "fuzzing")]
pub mod fuzzing;
mod keyring;
mod metadata;
mod payload;
mod primitives;
mod secret;

pub use checkpoint::{
    CheckpointSignature, validate_recovery_public_key, verify_recovery_signature,
};
pub use constant_time::ct_eq;
pub use derive::{
    NamespaceBlindKey, derive_backend_object_id, derive_blind_index_key, derive_manifest_id,
};
pub use envelope::{
    FormatEnvelope, KEYRING_ENVELOPE_VERSION, KeyringEnvelope, MAX_FORMAT_ENVELOPE_OBJECT_BYTES,
    MAX_KEYRING_ENVELOPE_OBJECT_BYTES,
};
pub use error::CryptoError;
pub use fingerprint::derive_public_fingerprint;
pub use keyring::{KeyMaterial, KeyRing, MIN_REPOSITORY_SALT_LEN, RepositoryKeyContext};
pub use metadata::MetadataSeal;
pub use payload::{PayloadPackSegmentSeal, PayloadSeal};
pub use secret::SecretBytes;
