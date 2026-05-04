//! Repository behavior tests.

use crate::checkpoint::{CHECKPOINT_OBJECT_PREFIX, checkpoint_object_id};
use crate::namespace::{indexed_list_prefix, indexed_list_prefix_mode, prefix_tokens_for_key};
use crate::payload::PAYLOAD_HEADER_PROBE_LEN;
use crate::{
    BackendObjectReferenceKind, CheckpointPosition, CommitCoordinator, CommitCoordinatorOptions,
    PhysicalDeleteOutcome, Repository, RepositoryError, RepositoryOrphanCandidate,
    RepositoryPutOptions,
};
use bytes::Bytes;
use rs3_anchor::{AnchorError, CheckpointAnchor, MemoryCheckpointAnchor};
use rs3_crypto::{KeyRing, RepositoryKeyContext};
use rs3_index::{CHECKPOINT_OBJECT_DOMAIN, canonical_commit_record_bytes};
use rs3_storage::{
    BlobStore, ByteRange, FilesystemBlobStore, MemoryBlobStore, PutOptions, StorageError,
};
use rs3_types::{
    KeyPurpose, KeyStatus, LegalHoldStatus, RepositoryId, RetentionMode, RetentionPolicy, Sequence,
};
use std::sync::Arc;

mod basic_io;
mod checkpoint;
mod commit_coordinator;
mod immutability;
mod keys;
mod namespace_privacy;
mod orphans;
mod payload;
mod support;
use support::*;
pub(crate) use support::{backend_object_id, signing_keyring, wrong_content_keyring};
