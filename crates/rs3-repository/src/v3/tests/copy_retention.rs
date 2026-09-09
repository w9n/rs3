use super::*;
use rs3_index::{NamespaceEntry, PayloadReference, V3PackCarrierReference, V3PackRecordReference};

#[derive(Clone, Copy, Default, Debug)]
enum Fault {
    #[default]
    None,
    MissingDeadline,
    WrongVersion,
    WrongLength,
    ShortDeadline,
    WeakerMode,
    LostHold,
    ExtensionFailure,
}

#[derive(Clone)]
struct CopyProtectionStore {
    inner: MemoryBlobStore,
    fault: Fault,
    extended: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl BlobStore for CopyProtectionStore {
    async fn put(
        &self,
        id: &BackendObjectId,
        body: Bytes,
        options: PutOptions,
    ) -> rs3_storage::Result<BlobMetadata> {
        self.inner.put(id, body, options).await
    }
    async fn get_range(
        &self,
        id: &BackendObjectId,
        range: ByteRange,
    ) -> rs3_storage::Result<Bytes> {
        self.inner.get_range(id, range).await
    }
    async fn head(&self, id: &BackendObjectId) -> rs3_storage::Result<BlobMetadata> {
        self.head_at(id, None).await
    }
    async fn head_at(
        &self,
        id: &BackendObjectId,
        version: Option<&BackendVersionId>,
    ) -> rs3_storage::Result<BlobMetadata> {
        let mut result = self.inner.head_at(id, version).await?;
        if matches!(self.fault, Fault::MissingDeadline) {
            result.retain_until_ms = None;
        }
        if self.extended.load(Ordering::SeqCst) > 0 {
            match self.fault {
                Fault::WrongVersion => {
                    result.version_id = Some(must_type(BackendVersionId::new("wrong-version")))
                }
                Fault::WrongLength => result.content_len += 1,
                Fault::ShortDeadline => result.retain_until_ms = Some(1),
                Fault::WeakerMode => {
                    result.retention = Some(RetentionPolicy::new(RetentionMode::Governance, 99))
                }
                Fault::LostHold => result.legal_hold = Some(LegalHoldStatus::Off),
                _ => {}
            }
        }
        Ok(result)
    }
    async fn list_prefix(&self, prefix: &str) -> rs3_storage::Result<Vec<BlobMetadata>> {
        self.inner.list_prefix(prefix).await
    }
    async fn delete(&self, id: &BackendObjectId) -> rs3_storage::Result<()> {
        self.inner.delete(id).await
    }
    async fn extend_retention(
        &self,
        id: &BackendObjectId,
        policy: RetentionPolicy,
    ) -> rs3_storage::Result<()> {
        self.extend_retention_at(id, None, policy).await
    }
    async fn extend_retention_at(
        &self,
        id: &BackendObjectId,
        version: Option<&BackendVersionId>,
        policy: RetentionPolicy,
    ) -> rs3_storage::Result<()> {
        self.extended.fetch_add(1, Ordering::SeqCst);
        if matches!(self.fault, Fault::ExtensionFailure) {
            return Err(StorageError::Provider(
                "injected extension failure".to_owned(),
            ));
        }
        self.inner.extend_retention_at(id, version, policy).await
    }
    async fn set_legal_hold(
        &self,
        id: &BackendObjectId,
        hold: LegalHoldStatus,
    ) -> rs3_storage::Result<()> {
        self.inner.set_legal_hold(id, hold).await
    }
    async fn flush_caches(&self) -> rs3_storage::Result<()> {
        self.inner.flush_caches().await
    }
}

async fn fixture(
    fault: Fault,
) -> (
    V3CommitStore<CopyProtectionStore>,
    V3MemoryAnchor,
    NamespaceEntry,
) {
    let inner = MemoryBlobStore::new();
    let options = commit_store_options_with_maintenance_roots(
        &inner,
        V3ProviderProfile::RetainedVersionObjectLock,
        Some(RetentionPolicy::new(RetentionMode::Governance, 1)),
    )
    .await;
    let keyring = must_crypto(KeyRing::generate_random());
    let key = must_type(LogicalPath::new("copy/source"));
    let blind = must_crypto(keyring.derive_primary_blind_index_key(&key));
    let carrier_id = object_id("commits/copy-carrier");
    let stored = inner
        .put(
            &carrier_id,
            Bytes::from_static(b"opaque exact carrier"),
            PutOptions {
                retention: Some(RetentionPolicy::new(RetentionMode::Compliance, 1)),
                legal_hold: Some(LegalHoldStatus::On),
                ..PutOptions::default()
            },
        )
        .await
        .expect("store carrier");
    let entry = NamespaceEntry {
        namespace_key_id: blind.key_id,
        blind_key: blind.blind_key,
        object_id: carrier_id.clone(),
        object_version_id: stored.version_id.clone(),
        payload_ref: Some(PayloadReference::V3Pack {
            carrier: Arc::new(V3PackCarrierReference {
                commit_key: carrier_id,
                commit_version_id: stored.version_id,
                body_digest: [1; 32],
                commit_stored_len: stored.content_len,
                pack_section_ordinal: 0,
                pack_offset: 0,
                length: stored.content_len,
                pack_id: [2; 32],
                attempt_id: rs3_types::PayloadAttemptId::from_bytes([3; 32]),
                content_key_id: must_crypto(keyring.primary_content_key_id()),
                // Deliberately historical context: only current keyring is a restore root.
                keyring_envelope_object_id: object_id("keyrings/historical-context"),
                keyring_envelope_digest: [4; 32],
                pack_record_count: 1,
            }),
            record: V3PackRecordReference {
                record_ordinal: 0,
                record_offset: 0,
            },
        }),
        manifest_id: must_crypto(keyring.derive_manifest_id(b"copy manifest")),
        content_len: 4,
        modified_at_ms: 1,
        generation: Sequence::ZERO,
        retention: Some(RetentionPolicy::new(RetentionMode::Governance, 2)),
        legal_hold: None,
    };
    let anchor = V3MemoryAnchor::new();
    let setup = V3CommitStore::new(inner.clone(), keyring.clone(), options.clone());
    must_v3(setup.write_genesis_snapshot(&anchor).await);
    inner.reset_operation_counts().expect("reset counts");
    let repository = V3CommitStore::new(
        CopyProtectionStore {
            inner,
            fault,
            extended: Arc::new(AtomicUsize::new(0)),
        },
        keyring,
        options,
    );
    (repository, anchor, entry)
}

fn copy_time() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("timestamp")
        + 86_400_000
}

#[tokio::test]
async fn retained_copy_extends_only_three_exact_dependencies_to_fixed_copy_deadline() {
    let (repository, anchor, source) = fixture(Fault::None).await;
    let base = must_v3(anchor.read_v3().await).expect("anchor");
    let modified = copy_time();
    must_v3(
        repository
            .protect_copy_source(
                &anchor,
                &UnenforcedQuiescedMaintenanceGuard,
                &base,
                &source,
                modified,
            )
            .await,
    );
    let counts = repository.store().inner.operation_counts().expect("counts");
    assert_eq!(counts.head, 6);
    assert_eq!(counts.extend_retention, 3);
    assert_eq!(
        (counts.get, counts.put, counts.list, counts.delete),
        (0, 0, 0, 0)
    );
    for (id, version) in [
        (&source.object_id, source.object_version_id.as_ref()),
        (
            &repository.options().format_ref.object_id,
            repository.options().format_ref.version_id.as_ref(),
        ),
        (
            &repository
                .options()
                .maintenance_keyring_envelope_ref
                .as_ref()
                .expect("keyring")
                .object_id,
            repository
                .options()
                .maintenance_keyring_envelope_ref
                .as_ref()
                .expect("keyring")
                .version_id
                .as_ref(),
        ),
    ] {
        let metadata = repository
            .store()
            .inner
            .head_at(id, version)
            .await
            .expect("exact metadata");
        assert!(
            metadata
                .retain_until_ms
                .is_some_and(|deadline| deadline >= modified + 2 * 86_400_000)
        );
        if id == &source.object_id {
            assert_eq!(
                metadata.retention.expect("retention").mode,
                RetentionMode::Compliance
            );
            assert_eq!(metadata.legal_hold, Some(LegalHoldStatus::On));
        }
    }
    // Already sufficient exact protection avoids needless extension on retry.
    must_v3(
        repository
            .protect_copy_source(
                &anchor,
                &UnenforcedQuiescedMaintenanceGuard,
                &base,
                &source,
                modified,
            )
            .await,
    );
    assert_eq!(
        repository
            .store()
            .inner
            .operation_counts()
            .expect("counts")
            .extend_retention,
        3
    );
}

#[tokio::test]
async fn retained_copy_fails_closed_on_missing_or_false_protection_facts() {
    for fault in [
        Fault::MissingDeadline,
        Fault::WrongVersion,
        Fault::WrongLength,
        Fault::ShortDeadline,
        Fault::WeakerMode,
        Fault::LostHold,
        Fault::ExtensionFailure,
    ] {
        let (repository, anchor, source) = fixture(fault).await;
        let base = must_v3(anchor.read_v3().await).expect("anchor");
        let result = repository
            .protect_copy_source(
                &anchor,
                &UnenforcedQuiescedMaintenanceGuard,
                &base,
                &source,
                copy_time(),
            )
            .await;
        assert!(result.is_err(), "fault {fault:?}");
        assert_eq!(must_v3(anchor.read_v3().await), Some(base));
        let counts = repository.store().inner.operation_counts().expect("counts");
        assert_eq!(
            (counts.get, counts.put, counts.list, counts.delete),
            (0, 0, 0, 0)
        );
        assert!(counts.extend_retention <= 1);
    }
}

#[tokio::test]
async fn retained_copy_rejects_lost_fence_stale_anchor_and_missing_exact_version_before_mutation() {
    let (repository, anchor, mut source) = fixture(Fault::None).await;
    let base = must_v3(anchor.read_v3().await).expect("anchor");
    assert_eq!(
        repository
            .protect_copy_source(
                &anchor,
                &RejectingMaintenanceGuard,
                &base,
                &source,
                copy_time()
            )
            .await,
        Err(V3FormatError::MaintenanceAccessRequired)
    );
    let mut stale = base.clone();
    stale.body_digest[0] ^= 1;
    assert_eq!(
        repository
            .protect_copy_source(
                &anchor,
                &UnenforcedQuiescedMaintenanceGuard,
                &stale,
                &source,
                copy_time()
            )
            .await,
        Err(V3FormatError::StaleAnchor)
    );
    if let Some(PayloadReference::V3Pack { carrier, .. }) = &mut source.payload_ref {
        Arc::make_mut(carrier).commit_version_id = None;
    }
    assert_eq!(
        repository
            .protect_copy_source(
                &anchor,
                &UnenforcedQuiescedMaintenanceGuard,
                &base,
                &source,
                copy_time()
            )
            .await,
        Err(V3FormatError::ProviderProfileFailed)
    );
    let counts = repository.store().inner.operation_counts().expect("counts");
    assert_eq!((counts.head, counts.extend_retention), (0, 0));
}

#[tokio::test]
async fn retained_copy_refuses_missing_roots_key_material_and_deadline_overflow_without_io() {
    let (repository, anchor, source) = fixture(Fault::None).await;
    let base = must_v3(anchor.read_v3().await).expect("anchor");
    for case in 0..4 {
        let mut options = repository.options().clone();
        let mut captured = source.clone();
        let mut modified = copy_time();
        match case {
            0 => options.maintenance_keyring_envelope_ref = None,
            1 => options.format_ref.version_id = None,
            2 => {
                if let Some(PayloadReference::V3Pack { carrier, .. }) = &mut captured.payload_ref {
                    Arc::make_mut(carrier).content_key_id = key_id("missing-content-key");
                }
            }
            _ => modified = i64::MAX,
        }
        let invalid = V3CommitStore::new(
            repository.store().clone(),
            repository.keyring().clone(),
            options,
        );
        assert!(
            invalid
                .protect_copy_source(
                    &anchor,
                    &UnenforcedQuiescedMaintenanceGuard,
                    &base,
                    &captured,
                    modified
                )
                .await
                .is_err()
        );
    }
    let counts = repository.store().inner.operation_counts().expect("counts");
    assert_eq!((counts.head, counts.extend_retention), (0, 0));
}

#[tokio::test]
async fn retained_copy_losing_fence_after_inspection_performs_no_extension() {
    let (repository, anchor, source) = fixture(Fault::None).await;
    let base = must_v3(anchor.read_v3().await).expect("anchor");
    assert!(
        repository
            .protect_copy_source(
                &anchor,
                &FailsAfterMaintenanceGuard::new(1),
                &base,
                &source,
                copy_time()
            )
            .await
            .is_err()
    );
    let counts = repository.store().inner.operation_counts().expect("counts");
    assert_eq!((counts.head, counts.extend_retention), (1, 0));
}

#[tokio::test]
async fn retained_copy_empty_and_standalone_restore_after_source_delete_and_restart() {
    for empty in [true, false] {
        let store = MemoryBlobStore::new();
        let options = commit_store_options_with_maintenance_roots(
            &store,
            V3ProviderProfile::RetainedVersionObjectLock,
            Some(RetentionPolicy::new(RetentionMode::Compliance, 1)),
        )
        .await;
        let keyring = must_crypto(KeyRing::generate_random());
        let repository = Arc::new(V3Repository::new(
            store.clone(),
            keyring.clone(),
            RepositoryOptions::default(),
            options.clone(),
        ));
        let anchor = V3MemoryAnchor::new();
        must_repo(repository.write_genesis_snapshot(&anchor).await);
        let coordinator = must_repo(V3CommitCoordinator::with_options(
            Arc::clone(&repository),
            anchor.clone(),
            CommitCoordinatorOptions::new(1, Duration::ZERO),
        ))
        .with_maintenance_guard(UnenforcedQuiescedMaintenanceGuard);
        let source = must_type(LogicalPath::new("copy/retained-source"));
        let destination = must_type(LogicalPath::new("copy/retained-destination"));
        let body = if empty {
            Bytes::new()
        } else {
            Bytes::from(vec![0x57; 128 * 1024])
        };
        let original = if empty {
            must_repo(
                coordinator
                    .put_committed(
                        source.clone(),
                        body.clone(),
                        RepositoryPutOptions {
                            retention: Some(RetentionPolicy::new(RetentionMode::Compliance, 1)),
                            ..RepositoryPutOptions::default()
                        },
                    )
                    .await,
            )
        } else {
            must_repo(
                coordinator
                    .put_committed_streaming_known_len(
                        source.clone(),
                        body.len() as u64,
                        stream::iter([Ok(body.clone())]),
                        RepositoryPutOptions {
                            retention: Some(RetentionPolicy::new(RetentionMode::Compliance, 1)),
                            ..RepositoryPutOptions::default()
                        },
                        64 * 1024,
                    )
                    .await,
            )
        };
        tokio::time::sleep(Duration::from_millis(2)).await;
        store.reset_operation_counts().expect("reset counts");
        let copied = must_repo(
            coordinator
                .copy_committed(
                    source.clone(),
                    destination.clone(),
                    crate::RepositoryCopyOptions::default(),
                )
                .await,
        );
        assert_eq!(copied.metadata.etag, original.metadata.etag);
        assert_eq!(copied.metadata.retention, original.metadata.retention);
        assert!(
            store.operation_counts().expect("counts").extend_retention >= if empty { 2 } else { 3 }
        );
        for metadata in store
            .list_prefix_versions("")
            .await
            .expect("exact inventory")
        {
            // All currently referenced payload and restore metadata dependencies,
            // including the newly published copy index, cover its fixed timestamp.
            if metadata.object_id == copied.anchor_state.commit_key
                || metadata.object_id == options.format_ref.object_id
                || metadata.object_id == options.keyring_envelope_ref.object_id
                || metadata.object_id.as_str().starts_with("objects/v03/")
            {
                assert!(metadata.retain_until_ms.is_some_and(
                    |deadline| deadline >= copied.metadata.modified_at_ms + 86_400_000
                ));
            }
        }
        must_repo(coordinator.delete_committed(source.clone()).await);
        must_repo(coordinator.write_index_snapshot().await);
        drop(coordinator);
        let fresh = V3Repository::new(store, keyring, RepositoryOptions::default(), options);
        must_repo(fresh.load_chain_from_anchor(&anchor).await);
        assert!(matches!(
            fresh.head(&source),
            Err(RepositoryError::NotFound(_))
        ));
        assert_eq!(
            must_repo(fresh.head(&destination)).etag,
            original.metadata.etag
        );
        assert_eq!(
            must_repo(fresh.get_range(&destination, ByteRange::Full).await),
            body
        );
    }
}
