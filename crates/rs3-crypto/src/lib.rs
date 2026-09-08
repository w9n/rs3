//! Cryptographic boundaries for repository privacy.

mod checkpoint;
mod checksum;
mod constant_time;
mod derive;
mod envelope;
mod error;
mod fingerprint;
#[cfg(feature = "fuzzing")]
pub mod fuzzing;
mod keyring;
mod md5;
mod metadata;
mod payload;
mod primitives;
mod random;
mod secret;

pub use checkpoint::{
    CheckpointSignature, validate_recovery_public_key, verify_recovery_signature,
};
pub use checksum::{ChecksumHasher, combine_part_checksums};
pub use constant_time::ct_eq;
pub use derive::{NamespaceBlindKey, derive_blind_index_key, derive_manifest_id};
pub use envelope::{
    EnvelopePurpose, MAX_FORMAT_ENVELOPE_OBJECT_BYTES, MAX_KEYRING_ENVELOPE_OBJECT_BYTES,
    REPOSITORY_ENVELOPE_VERSION, RepositoryEnvelope,
};
pub use error::CryptoError;
pub use fingerprint::{Sha256Hasher, derive_public_fingerprint};
pub use keyring::{KeyMaterial, KeyRing, MIN_REPOSITORY_SALT_LEN, RepositoryKeyContext};
pub use md5::{Md5Hasher, md5, multipart_etag};
pub use metadata::MetadataSeal;
pub use payload::{PayloadSegmentContext, PayloadSegmentSeal};
pub use random::{
    random_carrier_id, random_payload_attempt_id, random_physical_order_key, random_repository_salt,
};
pub use secret::SecretBytes;
