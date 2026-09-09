//! Provider range evidence for selective compaction source loading.
use super::*;
use crate::v2::RecoveryPolicy;
use rs3_storage::FaultInjectingBlobStore;

#[tokio::test]
async fn compaction_source_reads_skip_recovery_and_payload_sections() {
    let store = FaultInjectingBlobStore::new(MemoryBlobStore::new(), vec![]);
    let keys = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    )
    .with_recovery_policy(Some(RecoveryPolicy::PRESET));
    let repository = V2Repository::new(
        store.clone(),
        keys.clone(),
        RepositoryOptions::default(),
        options.clone(),
    );
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    let mut source_ranges = Vec::new();
    let mut values = Vec::new();
    for value in 0..3_u8 {
        let path = must_type(LogicalPath::new(format!("private/compaction/{value}")));
        let body = Bytes::from(vec![value; 512]);
        must_repo(
            repository
                .put_committed(
                    &anchor,
                    path.clone(),
                    body.clone(),
                    RepositoryPutOptions::default(),
                )
                .await,
        );
        values.push((path, body));
        let head = must_v2(anchor.read_v2().await).expect("accepted");
        let facts = must_v2(
            repository
                .commit_store()
                .read_commit_facts_at(&head.commit_key, head.version_id.as_ref())
                .await,
        );
        for section in &facts.parsed_header.header.section_index {
            source_ranges.push((
                head.commit_key.clone(),
                section.section_type,
                facts.parsed_header.sections_start as u64 + section.offset,
                section.length,
            ));
        }
    }
    let before = store.operation_log().expect("events").len();
    must_repo(
        repository
            .compact_packed_index_runs(&anchor, &UnenforcedQuiescedMaintenanceGuard)
            .await,
    );
    let events = store.operation_log().expect("events");
    let mut index_reads = 0;
    for event in &events[before..] {
        for (object, section_type, start, length) in &source_ranges {
            if event.object_id.as_ref() != Some(object) {
                continue;
            }
            match event.range {
                Some(ByteRange::Full) => panic!("full source object read"),
                Some(ByteRange::Slice { offset, len })
                    if offset < start + length && offset + len > *start =>
                {
                    assert_eq!(
                        *section_type,
                        V2SectionType::IndexRun,
                        "only selected index metadata is needed"
                    );
                    index_reads += 1;
                }
                _ => {}
            }
        }
    }
    assert!(
        index_reads >= 3,
        "each selected source index was authenticated"
    );
    assert_eq!(must_repo(repository.active_index_run_count()), 1);
    let fresh = V2Repository::new(store, keys, RepositoryOptions::default(), options);
    must_repo(fresh.load_chain_from_anchor(&anchor).await).expect("compacted replay");
    for (path, body) in values {
        assert_eq!(
            must_repo(fresh.get_range(&path, ByteRange::Full).await),
            body
        );
    }
}

#[tokio::test]
async fn compaction_prefetch_preserves_unselected_exact_reference_through_fresh_replay() {
    let store = FaultInjectingBlobStore::new(MemoryBlobStore::new(), vec![]);
    let keys = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    )
    .with_recovery_policy(Some(RecoveryPolicy::PRESET));
    let repository = V2Repository::new(
        store.clone(),
        keys.clone(),
        RepositoryOptions::default(),
        options.clone(),
    );
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    let mut expected_paths = Vec::new();
    let mut sampled_values = Vec::new();
    // Small payloads, but enough real index metadata to make preserving this
    // batch cheaper than rewriting it with the 24 newer single-entry runs.
    for ordinal in 0..512 {
        let path = must_type(LogicalPath::new(format!(
            "subset/old/{ordinal:04x}-{}",
            "x".repeat(960)
        )));
        let body = Bytes::from(vec![(ordinal % 251) as u8]);
        must_repo(
            repository
                .stage_put(path.clone(), body.clone(), RepositoryPutOptions::default())
                .await,
        );
        expected_paths.push(path.clone());
        if [0, 256, 511].contains(&ordinal) {
            sampled_values.push((path, body));
        }
    }
    must_repo(repository.publish_pending_index_delta(&anchor, None).await);
    let old_checkpoint = must_repo(repository.write_index_snapshot(&anchor).await);
    let context = must_repo(repository_context_from_refs(
        &options.repository_id,
        &options.keyring_envelope_ref,
    ));
    let decode_root = |commit: &crate::v2::repository::V2ReplayCommit| {
        assert_eq!(
            commit.parsed_header.header.section_index[0].section_type,
            V2SectionType::IndexRoot
        );
        must_v2(crate::v2::open_v2_index_root(
            &keys,
            &context,
            &commit.parsed_header.header.self_ref.commit_key,
            0,
            commit.retained_sections[0]
                .as_deref()
                .expect("root section"),
        ))
    };
    let old_chain = must_v2(
        repository
            .commit_store()
            .load_replay_chain_from_state(&old_checkpoint.anchor_state)
            .await,
    );
    let old_root = decode_root(&old_chain.commits_newest_first[0]);
    assert_eq!(old_root.runs().len(), 1);
    let preserved = old_root.runs()[0].clone();
    for ordinal in 0..24 {
        let path = must_type(LogicalPath::new(format!("subset/new/{ordinal:02}")));
        let body = Bytes::from(vec![ordinal as u8; 32]);
        must_repo(
            repository
                .put_committed(
                    &anchor,
                    path.clone(),
                    body.clone(),
                    RepositoryPutOptions::default(),
                )
                .await,
        );
        expected_paths.push(path.clone());
        sampled_values.push((path, body));
    }
    let before_checkpoint = must_repo(repository.write_index_snapshot(&anchor).await);
    let before_chain = must_v2(
        repository
            .commit_store()
            .load_replay_chain_from_state(&before_checkpoint.anchor_state)
            .await,
    );
    let before_root = decode_root(&before_chain.commits_newest_first[0]);
    assert_eq!(before_root.runs().len(), 25);
    let newer_bytes: u64 = before_root
        .runs()
        .iter()
        .filter(|run| run.run_id != preserved.run_id)
        .map(|run| run.location.section_len)
        .sum();
    // Compare the same one-output catalog estimate using actual sealed sizes.
    let publication_cost = 8 * 1024 * 1024_u64;
    assert!(
        (publication_cost + newer_bytes) * 24
            < (publication_cost + newer_bytes + preserved.location.section_len) * 23,
        "fixture must favor the newer subset before any compaction IO"
    );
    let before_events = store.operation_log().expect("events").len();
    let compacted = must_repo(
        repository
            .compact_packed_index_runs(&anchor, &UnenforcedQuiescedMaintenanceGuard)
            .await,
    );
    let events = store.operation_log().expect("events");
    assert!(
        events[before_events..]
            .iter()
            .all(|event| event.object_id.as_ref() != Some(&preserved.location.commit_key)),
        "the preserved older carrier must not be fetched during subset publication"
    );
    let compacted_chain = must_v2(
        repository
            .commit_store()
            .load_replay_chain_from_state(&compacted.anchor_state)
            .await,
    );
    let compacted_root = decode_root(&compacted_chain.commits_newest_first[0]);
    assert_eq!(compacted_root.runs().len(), 2);
    assert_eq!(
        compacted_root
            .runs()
            .iter()
            .find(|run| run.run_id == preserved.run_id),
        Some(&preserved)
    );

    let fresh = V2Repository::new(
        store.clone(),
        keys.clone(),
        RepositoryOptions::default(),
        options.clone(),
    );
    must_repo(fresh.load_chain_from_anchor(&anchor).await).expect("fresh compacted replay");
    let mut actual_paths = must_repo(fresh.list("subset/"))
        .into_iter()
        .map(|entry| entry.key)
        .collect::<Vec<_>>();
    actual_paths.sort();
    expected_paths.sort();
    assert_eq!(actual_paths, expected_paths);
    for (path, body) in &sampled_values {
        assert_eq!(
            must_repo(fresh.get_range(path, ByteRange::Full).await),
            *body
        );
    }
    // The earlier accepted root remains independently recoverable with its
    // original exact references after current-catalog replacement.
    let historical = V2Repository::new(store, keys, RepositoryOptions::default(), options);
    let old_anchor = V2MemoryAnchor::with_state(old_checkpoint.anchor_state);
    must_repo(historical.load_chain_from_anchor(&old_anchor).await).expect("old accepted root");
    assert_eq!(must_repo(historical.list("subset/old/")).len(), 512);
    for (path, body) in &sampled_values[..3] {
        assert_eq!(
            must_repo(historical.get_range(path, ByteRange::Full).await),
            *body
        );
    }
}
