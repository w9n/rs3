use super::*;
use crate::v2::RecoveryPolicy;
use rs3_storage::FaultInjectingBlobStore;

#[tokio::test]
async fn recovery_pending_selective_reader_reserves_before_get_and_verifies_required_bytes() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
    let writer = V2CommitStore::new(
        store.clone(),
        signing_keyring(),
        V2CommitStoreOptions::for_profile(
            V2ProviderProfile::Dev,
            sample_repository_id(),
            sample_keyring_envelope_ref(),
            sample_format_ref(),
        )
        .with_replay_limits(V2ReplayLimits {
            read_chunk_bytes: 8,
            ..V2ReplayLimits::default()
        }),
    );
    let anchor = V2MemoryAnchor::new();
    must_v2(writer.write_genesis_snapshot(&anchor).await);
    let body = Bytes::from_static(b"required signed metadata bytes");
    let stored = must_v2(
        writer
            .write_child_commit(
                &anchor,
                V2CommitWrite::delta(vec![V2CommitSection::new(
                    V2SectionType::IndexRun,
                    V2_SECTION_FLAG_MUST_UNDERSTAND,
                    body.clone(),
                )]),
            )
            .await,
    );
    let facts = must_v2(
        writer
            .read_commit_facts_at(&stored.anchor_state.commit_key, stored.version_id.as_ref())
            .await,
    );
    assert!(facts.retained_sections.iter().all(Option::is_none));
    let bound = body.len() as u64 + 8;
    let before = store.ranged_commit_get_count();
    assert_eq!(
        writer.read_metadata_section(&facts, 0, bound - 1).await,
        Err(V2FormatError::MaintenanceBudgetExceeded)
    );
    assert_eq!(
        store.ranged_commit_get_count(),
        before,
        "reject before allocating range read"
    );
    assert_eq!(
        must_v2(writer.read_metadata_section(&facts, 0, bound).await),
        body
    );
    assert_eq!(
        store.ranged_commit_get_count() - before,
        (body.len() as u64).div_ceil(8)
    );
    store.corrupt_ranged_commit_gets_for(stored.anchor_state.commit_key);
    assert_eq!(
        writer.read_metadata_section(&facts, 0, bound).await,
        Err(V2FormatError::SectionDigestMismatch)
    );
}

#[tokio::test]
async fn recovery_pending_history_skips_old_registry_bytes_and_releases_section_buffers() {
    let store = FaultInjectingBlobStore::new(MemoryBlobStore::new(), vec![]);
    let repository = V2Repository::new(
        store.clone(),
        must_crypto(KeyRing::generate_random()),
        RepositoryOptions::default(),
        V2CommitStoreOptions::for_profile(
            V2ProviderProfile::Dev,
            sample_repository_id(),
            sample_keyring_envelope_ref(),
            sample_format_ref(),
        )
        .with_recovery_policy(Some(RecoveryPolicy::PRESET)),
    );
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    let key = must_type(LogicalPath::new("private/pending-history"));
    let mut old_recovery_ranges = Vec::new();
    for value in 0..12_u8 {
        must_repo(
            repository
                .put_committed(
                    &anchor,
                    key.clone(),
                    Bytes::from(vec![value; 512]),
                    RepositoryPutOptions::default(),
                )
                .await,
        );
        let head = must_v2(anchor.read_v2().await).expect("accepted");
        let facts = must_v2(
            repository
                .commit_store()
                .read_commit_facts_at(&head.commit_key, head.version_id.as_ref())
                .await,
        );
        let section = facts
            .parsed_header
            .header
            .section_index
            .iter()
            .find(|section| section.section_type == V2SectionType::Recovery)
            .expect("recovery section");
        old_recovery_ranges.push((
            head.commit_key,
            facts.parsed_header.sections_start as u64 + section.offset,
            section.length,
        ));
    }
    must_repo(repository.write_index_snapshot(&anchor).await);
    let before = store.operation_log().expect("operation log").len();
    let graph = must_v2(
        repository
            .commit_store()
            .recovery_mark_for_tests(&anchor, V2MaintenanceBudgets::default())
            .await,
    );
    assert_eq!(
        graph.pending_section_bytes, 0,
        "cached facts and the consumed current chain must contain no section buffers"
    );
    assert!(graph.peak_pending_section_bytes > 0);
    assert!(graph.peak_pending_section_bytes < 64 * 1024);
    for event in &store.operation_log().expect("operation log")[before..] {
        let Some(ByteRange::Slice { offset, len }) = event.range else {
            continue;
        };
        for (object, start, length) in &old_recovery_ranges {
            if event.object_id.as_ref() == Some(object) {
                assert!(
                    offset + len <= *start || offset >= start + length,
                    "unused historical registry read"
                );
            }
        }
    }
    assert_eq!(
        must_repo(repository.get_range(&key, ByteRange::Full).await),
        Bytes::from(vec![11; 512])
    );
}

#[tokio::test]
async fn recovery_replay_rejects_mismatched_exact_head_before_reading_sections() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
    let writer = V2CommitStore::new(
        store.clone(),
        signing_keyring(),
        V2CommitStoreOptions::for_profile(
            V2ProviderProfile::Dev,
            sample_repository_id(),
            sample_keyring_envelope_ref(),
            sample_format_ref(),
        ),
    );
    let anchor = V2MemoryAnchor::new();
    let stored = must_v2(writer.write_genesis_snapshot(&anchor).await);
    let expected = must_v2(
        writer
            .read_replay_commit_at(&stored.anchor_state.commit_key, stored.version_id.as_ref())
            .await,
    );
    assert!(expected.retained_sections.iter().any(Option::is_some));
    for fault in [
        CommitHeadIdentityFault::WrongObject,
        CommitHeadIdentityFault::WrongVersion,
    ] {
        *store
            .commit_head_identity_fault
            .lock()
            .expect("HEAD fault lock") = fault;
        let before = store.ranged_commit_get_count();
        assert_eq!(
            writer
                .read_replay_commit_at(&stored.anchor_state.commit_key, stored.version_id.as_ref())
                .await,
            Err(V2FormatError::ProviderProfileFailed)
        );
        assert_eq!(
            store.ranged_commit_get_count(),
            before,
            "reject HEAD identity before fetching signed headers or section bodies"
        );
    }
    *store
        .commit_head_identity_fault
        .lock()
        .expect("HEAD fault lock") = CommitHeadIdentityFault::None;
    assert_eq!(
        must_v2(
            writer
                .read_replay_commit_at(&stored.anchor_state.commit_key, stored.version_id.as_ref())
                .await
        ),
        expected
    );
}
