//! Cryptographic boundaries for repository privacy.

mod checkpoint;
mod derive;
mod envelope;
mod error;
mod fingerprint;
mod keyring;
mod metadata;
mod payload;
mod primitives;
mod secret;

pub use checkpoint::{
    CheckpointSignature, derive_checkpoint_id, derive_checkpoint_payload_digest,
    derive_index_delta_object_id,
};
pub use derive::{
    NamespaceBlindKey, NamespacePrefixToken, derive_backend_object_id, derive_blind_index_key,
    derive_manifest_id, derive_prefix_token,
};
pub use envelope::{FormatEnvelope, KEYRING_ENVELOPE_VERSION, KeyringEnvelope};
pub use error::CryptoError;
pub use fingerprint::derive_public_fingerprint;
pub use keyring::{KeyMaterial, KeyRing, MIN_REPOSITORY_SALT_LEN, RepositoryKeyContext};
pub use metadata::MetadataSeal;
pub use payload::PayloadSeal;
pub use secret::SecretBytes;
