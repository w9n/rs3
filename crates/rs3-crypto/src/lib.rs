//! Cryptographic boundaries for repository privacy.

mod checkpoint;
mod derive;
mod error;
mod keyring;
mod metadata;
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
pub use error::CryptoError;
pub use keyring::{KeyMaterial, KeyRing};
pub use metadata::MetadataSeal;
pub use secret::SecretBytes;
