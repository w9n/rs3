use super::*;
use crate::v3::V3MultipartSelection;
use crate::{RepositoryCopyOptions, UploadChecksum};
use rs3_types::{ChecksumAlgorithm, ChecksumType, ObjectChecksum};

struct Body(Bytes);
#[async_trait::async_trait]
impl BlobRead for Body {
    fn exact_len(&self) -> u64 {
        self.0.len() as u64
    }
    async fn next_chunk(&mut self) -> rs3_storage::Result<Option<Bytes>> {
        Ok((!self.0.is_empty()).then(|| self.0.split_to(self.0.len().min(64 * 1024))))
    }
}

fn key(value: &str) -> LogicalPath {
    must_type(LogicalPath::new(format!("copy/{value}")))
}

#[tokio::test]
async fn copy_preserves_all_carrier_shapes_without_payload_io_through_delete_compaction_and_replay()
{
    for shape in 0..4 {
        let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
        let keyring = must_crypto(KeyRing::generate_random());
        let options = V3CommitStoreOptions::for_profile(
            V3ProviderProfile::Dev,
            sample_repository_id(),
            sample_keyring_envelope_ref(),
            sample_format_ref(),
        );
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
        let body = if shape == 0 {
            Bytes::new()
        } else {
            Bytes::from(vec![0x71; 256 * 1024])
        };
        let mut hasher = rs3_crypto::ChecksumHasher::new(ChecksumAlgorithm::Crc64Nvme);
        hasher.update(&body);
        let checksum = ObjectChecksum::new(
            ChecksumAlgorithm::Crc64Nvme,
            ChecksumType::FullObject,
            hasher.finalize(),
        )
        .expect("checksum");
        let put_options = RepositoryPutOptions {
            checksum: Some(UploadChecksum::verified(checksum.clone())),
            ..Default::default()
        };
        let original = match shape {
            0 | 1 => {
                must_repo(
                    coordinator
                        .put_committed(key("source"), body.clone(), put_options)
                        .await,
                )
                .metadata
            }
            2 => {
                must_repo(
                    coordinator
                        .put_committed_streaming_known_len(
                            key("source"),
                            body.len() as u64,
                            stream::iter([Ok(body.clone())]),
                            put_options,
                            64 * 1024,
                        )
                        .await,
                )
                .metadata
            }
            _ => {
                let upload = must_repo(
                    repository
                        .create_multipart_upload(
                            key("source"),
                            RepositoryPutOptions::default(),
                            Some(
                                crate::MultipartChecksumPolicy::new(
                                    ChecksumAlgorithm::Crc64Nvme,
                                    crate::MultipartChecksumKind::FullObject,
                                )
                                .expect("policy"),
                            ),
                        )
                        .await,
                );
                let part = must_repo(
                    upload
                        .upload_part(
                            1,
                            Box::new(Body(body.clone())),
                            Some(UploadChecksum::verified(checksum.clone())),
                            None,
                        )
                        .await,
                );
                let selection = must_repo(V3MultipartSelection::new(vec![(1, part.etag())]));
                must_repo(
                    coordinator
                        .complete_multipart_upload(upload, selection)
                        .await,
                );
                must_repo(repository.head(&key("source")))
            }
        };
        let original_anchor = must_v3(anchor.read_v3().await).expect("source anchor");
        // The packed source carrier must not be fetched while publishing the copy.
        if shape == 1 {
            store.corrupt_ranged_commit_gets_for(original_anchor.commit_key.clone());
        }
        store.reset_operation_counts();
        let copied = must_repo(
            coordinator
                .copy_committed(
                    key("source"),
                    key("destination"),
                    RepositoryCopyOptions {
                        source_if_match: Some(original.etag.to_s3_string()),
                    },
                )
                .await,
        );
        let counts = store.operation_counts();
        assert_eq!(store.standalone_io_counts(), (0, 0), "shape {shape}");
        assert!(
            counts.bytes_read < 32 * 1024,
            "copy metadata read bound: {counts:?}"
        );
        assert!(
            counts.bytes_written < 32 * 1024,
            "copy metadata write bound: {counts:?}"
        );
        assert_eq!(counts.multipart_create, 0);
        assert_eq!(copied.metadata.etag, original.etag);
        assert_eq!(copied.metadata.checksum, original.checksum);
        assert_eq!(copied.metadata.content_len, original.content_len);
        assert!(copied.metadata.modified_at_ms >= original.modified_at_ms);
        store.clear_corruption();
        must_repo(coordinator.delete_committed(key("source")).await);
        must_repo(coordinator.write_index_snapshot().await);
        drop(coordinator);
        must_repo(
            repository
                .compact_packed_index_runs(&anchor, &UnenforcedQuiescedMaintenanceGuard)
                .await,
        );
        must_repo(repository.write_index_snapshot(&anchor).await);
        must_v3(
            repository
                .commit_store()
                .apply_full_gc(
                    &anchor,
                    &UnenforcedQuiescedMaintenanceGuard,
                    V3FullGcApplyOptions {
                        dry_run: V3FullGcDryRunOptions::default(),
                        orphan_gc: V3OrphanGcOptions::new_for_test_rehearsal(Duration::ZERO),
                        retained_provider_conformance_passed: false,
                        reclamation_enabled: true,
                    },
                )
                .await,
        );
        let fresh = V3Repository::new(
            store.clone(),
            keyring,
            RepositoryOptions::default(),
            options,
        );
        must_repo(fresh.load_chain_from_anchor(&anchor).await);
        assert!(matches!(
            fresh.head(&key("source")),
            Err(RepositoryError::NotFound(_))
        ));
        assert_eq!(
            must_repo(fresh.head(&key("destination"))).etag,
            original.etag
        );
        assert_eq!(
            must_repo(fresh.get_range(&key("destination"), ByteRange::Full).await),
            body
        );
    }
}

#[tokio::test]
async fn copy_conditions_fail_before_staging_and_destination_overwrite_uses_source_facts() {
    let store = MemoryBlobStore::new();
    let repository = Arc::new(V3Repository::new(
        store.clone(),
        must_crypto(KeyRing::generate_random()),
        RepositoryOptions::default(),
        V3CommitStoreOptions::for_profile(
            V3ProviderProfile::Dev,
            sample_repository_id(),
            sample_keyring_envelope_ref(),
            sample_format_ref(),
        ),
    ));
    let anchor = V3MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    let c = must_repo(V3CommitCoordinator::with_options(
        Arc::clone(&repository),
        anchor.clone(),
        CommitCoordinatorOptions::new(1, Duration::ZERO),
    ));
    let source = must_repo(
        c.put_committed(
            key("source"),
            Bytes::from_static(b"source"),
            Default::default(),
        )
        .await,
    );
    must_repo(
        c.put_committed(
            key("destination"),
            Bytes::from_static(b"other"),
            Default::default(),
        )
        .await,
    );
    let accepted = must_v3(anchor.read_v3().await);
    for condition in ["*", "bad-etag"] {
        let result = c
            .copy_committed(
                key("source"),
                key("destination"),
                RepositoryCopyOptions {
                    source_if_match: Some(condition.to_owned()),
                },
            )
            .await;
        assert!(matches!(result, Err(RepositoryError::PreconditionFailed)));
        assert_eq!(must_v3(anchor.read_v3().await), accepted);
        assert_eq!(must_repo(repository.pending_operation_count_for_tests()), 0);
    }
    let condition = "x".repeat(129);
    let options = RepositoryCopyOptions {
        source_if_match: Some(condition.clone()),
    };
    assert!(!format!("{options:?}").contains(&condition));
    assert!(matches!(
        c.copy_committed(key("source"), key("destination"), options)
            .await,
        Err(RepositoryError::InvalidCopyOptions)
    ));
    let copied = must_repo(
        c.copy_committed(key("source"), key("destination"), Default::default())
            .await,
    );
    assert_eq!(copied.metadata.etag, source.metadata.etag);
    assert_eq!(
        must_repo(
            repository
                .get_range(&key("destination"), ByteRange::Full)
                .await
        ),
        Bytes::from_static(b"source")
    );
    assert!(matches!(
        c.copy_committed(key("missing"), key("destination"), Default::default())
            .await,
        Err(RepositoryError::NotFound(_))
    ));
}
