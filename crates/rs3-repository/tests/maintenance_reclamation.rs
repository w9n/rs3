//! Full-maintenance reclamation controls.

use async_trait::async_trait;
use bytes::Bytes;
use rs3_crypto::{KeyMaterial, KeyRing, SecretBytes};
use rs3_repository::v3::{
    UnenforcedQuiescedMaintenanceGuard, V3_SECTION_FLAG_MUST_UNDERSTAND, V3AnchorState,
    V3CommitAnchor, V3CommitSection, V3CommitStore, V3CommitStoreOptions, V3CommitWrite,
    V3FormatError, V3FormatRef, V3FullGcApplyOptions, V3FullGcDryRunOptions, V3KeyringEnvelopeRef,
    V3MemoryAnchor, V3OrphanGcOptions, V3ProviderProfile, V3Result, V3SectionType,
};
use rs3_storage::MemoryBlobStore;
use rs3_types::{
    BackendObjectId, BackendVersionId, KeyDescriptor, KeyId, KeyPurpose, KeyStatus, RepositoryId,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[tokio::test]
async fn disabled_reclamation_preserves_orphans_until_enabled_apply() {
    let store = MemoryBlobStore::new();
    let repository = V3CommitStore::new(store, test_keyring(), test_options());
    let anchor = V3MemoryAnchor::new();

    repository
        .write_genesis_snapshot(&anchor)
        .await
        .expect("genesis snapshot");
    let failed = repository
        .write_child_commit(
            &FailOnceAnchor::new(anchor.clone()),
            V3CommitWrite::delta(vec![V3CommitSection::new(
                V3SectionType::IndexRun,
                V3_SECTION_FLAG_MUST_UNDERSTAND,
                Bytes::from_static(b"unanchored maintenance fixture"),
            )]),
        )
        .await;
    assert_eq!(failed, Err(V3FormatError::AnchorAdvanceFailed));
    assert_eq!(
        repository
            .report_orphans(&anchor)
            .await
            .expect("orphan report before apply")
            .candidates
            .len(),
        1
    );

    let disabled = repository
        .apply_full_gc(
            &anchor,
            &UnenforcedQuiescedMaintenanceGuard,
            apply_options(false),
        )
        .await
        .expect("renewal-only apply");
    assert_eq!(disabled.dry_run.candidate_commit_count, 1);
    assert_eq!(disabled.dry_run.planned_cost.delete_count, 1);
    assert_eq!(disabled.orphan_gc.deleted_count, 0);
    assert_eq!(disabled.orphan_gc.scanned_count, 0);
    assert_eq!(
        repository
            .report_orphans(&anchor)
            .await
            .expect("orphan remains when reclamation is disabled")
            .candidates
            .len(),
        1
    );

    let enabled = repository
        .apply_full_gc(
            &anchor,
            &UnenforcedQuiescedMaintenanceGuard,
            apply_options(true),
        )
        .await
        .expect("reclamation-enabled apply");
    assert_eq!(enabled.orphan_gc.deleted_count, 1);
    assert!(
        repository
            .report_orphans(&anchor)
            .await
            .expect("orphan report after enabled apply")
            .candidates
            .is_empty()
    );
}

fn apply_options(reclamation_enabled: bool) -> V3FullGcApplyOptions {
    V3FullGcApplyOptions {
        dry_run: V3FullGcDryRunOptions::default(),
        orphan_gc: V3OrphanGcOptions::new_for_test_rehearsal(Duration::ZERO),
        retained_provider_conformance_passed: false,
        reclamation_enabled,
    }
}

struct FailOnceAnchor {
    inner: V3MemoryAnchor,
    remaining_failures: AtomicUsize,
}

impl FailOnceAnchor {
    fn new(inner: V3MemoryAnchor) -> Self {
        Self {
            inner,
            remaining_failures: AtomicUsize::new(1),
        }
    }
}

#[async_trait]
impl V3CommitAnchor for FailOnceAnchor {
    async fn read_v3(&self) -> V3Result<Option<V3AnchorState>> {
        self.inner.read_v3().await
    }

    async fn compare_and_advance_v3(
        &self,
        expected: Option<&V3AnchorState>,
        next: V3AnchorState,
    ) -> V3Result<V3AnchorState> {
        if self
            .remaining_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(V3FormatError::AnchorAdvanceFailed);
        }
        self.inner.compare_and_advance_v3(expected, next).await
    }
}

fn test_options() -> V3CommitStoreOptions {
    V3CommitStoreOptions::for_profile(
        V3ProviderProfile::Dev,
        repository_id("rs3-maintenance-reclamation-test"),
        V3KeyringEnvelopeRef {
            object_id: object_id("keyrings/00000000000000000001-maintenance"),
            digest: [6_u8; 32],
        },
        V3FormatRef {
            generation: 1,
            digest: hex::encode([7_u8; 32]),
            object_id: object_id(&format!("format/{:020}-{}", 1_u64, hex::encode([7_u8; 32]))),
            version_id: Some(
                BackendVersionId::new("format-version-1").expect("test format version ID"),
            ),
        },
    )
}

fn test_keyring() -> KeyRing {
    KeyRing::new(vec![
        key_material("namespace", KeyPurpose::Namespace, 1),
        key_material("signing", KeyPurpose::CheckpointSigning, 2),
        key_material("metadata", KeyPurpose::Metadata, 3),
    ])
    .expect("test keyring")
}

fn key_material(id: &str, purpose: KeyPurpose, byte: u8) -> KeyMaterial {
    KeyMaterial::new(
        KeyDescriptor {
            id: key_id(id),
            purpose,
            status: KeyStatus::Primary,
            created_at_ms: 0,
            public_key: None,
        },
        SecretBytes::new(vec![byte; SecretBytes::MIN_LEN]).expect("test key material"),
    )
}

fn repository_id(value: &str) -> RepositoryId {
    RepositoryId::new(value).expect("test repository ID")
}

fn object_id(value: &str) -> BackendObjectId {
    BackendObjectId::new(value).expect("test object ID")
}

fn key_id(value: &str) -> KeyId {
    KeyId::new(value).expect("test key ID")
}
