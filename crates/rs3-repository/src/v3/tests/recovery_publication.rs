use super::*;
use crate::v3::RecoveryPolicy;

fn history_options(policy: Option<RecoveryPolicy>) -> V3CommitStoreOptions {
    V3CommitStoreOptions::for_profile(
        V3ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    )
    .with_recovery_policy(policy)
}

#[tokio::test]
async fn recovery_publication_preserves_fixed_predecessor_policy_across_restart_reduction_and_root_cut()
 {
    let store = MemoryBlobStore::new();
    let keys = must_crypto(KeyRing::generate_random());
    let old_policy = RecoveryPolicy::PRESET;
    let options = history_options(Some(old_policy));
    let repository = V3Repository::new(
        store.clone(),
        keys.clone(),
        RepositoryOptions::default(),
        options,
    );
    repository
        .commit_store()
        .set_publication_time_for_tests(1_000);
    let anchor = V3MemoryAnchor::new();
    let genesis = must_repo(repository.write_genesis_snapshot(&anchor).await);
    let key = LogicalPath::new("private/history-object").expect("path");
    let metadata = must_repo(
        repository
            .put_committed(
                &anchor,
                key.clone(),
                Bytes::from_static(b"history-body"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    let first = must_v3(anchor.read_v3().await).expect("accepted");
    let chain = must_v3(
        repository
            .commit_store()
            .load_replay_chain_from_state(&first)
            .await,
    );
    let history =
        must_v3(repository.commit_store().replay_recovery_history(&chain)).expect("history");
    assert_eq!(history.snapshot.tail.len(), 1);
    assert_eq!(history.snapshot.tail[0].anchor, genesis.anchor_state);
    assert_eq!(
        history.snapshot.tail[0].protected_until_ms,
        must_v3(old_policy.promised_until_ms(1_001))
    );
    assert_eq!(must_repo(repository.head(&key)).etag, metadata.etag);

    let reduced = must_v3(RecoveryPolicy::new(1, 86_400, 60_000));
    let restarted = V3Repository::new(
        store.clone(),
        keys.clone(),
        RepositoryOptions::default(),
        history_options(Some(reduced)),
    );
    restarted
        .commit_store()
        .set_publication_time_for_tests(2_000);
    must_repo(restarted.load_chain_from_anchor(&anchor).await);
    let checkpoint = must_repo(restarted.write_index_snapshot(&anchor).await);
    let chain = must_v3(
        restarted
            .commit_store()
            .load_replay_chain_from_state(&checkpoint.anchor_state)
            .await,
    );
    assert_eq!(chain.commits_newest_first.len(), 1);
    let history =
        must_v3(restarted.commit_store().replay_recovery_history(&chain)).expect("history");
    assert_eq!(history.policy, reduced);
    assert_eq!(history.snapshot.tail.len(), 2);
    assert_eq!(history.snapshot.tail[1].anchor, first);
    assert_eq!(history.snapshot.tail[1].policy_id, old_policy.identity());
    assert_eq!(
        history.snapshot.tail[1].protected_until_ms,
        must_v3(old_policy.promised_until_ms(2_000))
    );
    // Replay a checkpoint without loading its predecessor carrier or old policy.
    store
        .delete(&genesis.anchor_state.commit_key)
        .await
        .expect("remove old checkpoint fixture");
    let cold = V3Repository::new(
        store.clone(),
        keys.clone(),
        RepositoryOptions::default(),
        history_options(Some(reduced)),
    );
    cold.commit_store().set_publication_time_for_tests(3_000);
    must_repo(cold.load_chain_from_anchor(&anchor).await);
    assert_eq!(
        must_repo(cold.get_range(&key, ByteRange::Full).await),
        Bytes::from_static(b"history-body")
    );
    must_repo(cold.delete_committed(&anchor, key.clone()).await);
    let accepted = must_v3(anchor.read_v3().await).expect("accepted");
    let chain = must_v3(
        cold.commit_store()
            .load_replay_chain_from_state(&accepted)
            .await,
    );
    let history = must_v3(cold.commit_store().replay_recovery_history(&chain)).expect("history");
    assert_eq!(history.snapshot.tail.len(), 3);
    assert_eq!(history.snapshot.tail[2].anchor, checkpoint.anchor_state);
    assert_eq!(history.snapshot.tail[2].policy_id, reduced.identity());
}

#[tokio::test]
async fn recovery_publication_refuses_missing_section_and_cannot_disable_accepted_history() {
    let store = MemoryBlobStore::new();
    let keys = must_crypto(KeyRing::generate_random());
    let native = V3Repository::new(
        store.clone(),
        keys.clone(),
        RepositoryOptions::default(),
        history_options(None),
    );
    let native_anchor = V3MemoryAnchor::new();
    must_repo(native.write_genesis_snapshot(&native_anchor).await);
    let requires = V3Repository::new(
        store.clone(),
        keys.clone(),
        RepositoryOptions::default(),
        history_options(Some(RecoveryPolicy::PRESET)),
    );
    assert!(
        requires
            .load_chain_from_anchor(&native_anchor)
            .await
            .is_err()
    );

    let anchor = V3MemoryAnchor::new();
    must_repo(requires.write_genesis_snapshot(&anchor).await);
    let historical = V3Repository::new(
        store.clone(),
        keys,
        RepositoryOptions::default(),
        history_options(None),
    );
    must_repo(historical.load_chain_from_anchor(&anchor).await);
    let before = must_v3(anchor.read_v3().await);
    let puts = store.operation_counts().expect("counts").put;
    assert!(
        historical
            .put_committed(
                &anchor,
                LogicalPath::new("private/disabled").expect("path"),
                Bytes::from_static(b"x"),
                RepositoryPutOptions::default()
            )
            .await
            .is_err()
    );
    assert_eq!(must_v3(anchor.read_v3().await), before);
    assert_eq!(store.operation_counts().expect("counts").put, puts);
}

#[tokio::test]
async fn recovery_publication_raw_child_apis_fail_before_put_for_configured_and_loaded_history() {
    let store = MemoryBlobStore::new();
    let keys = must_crypto(KeyRing::generate_random());
    let writer = V3CommitStore::new(
        store.clone(),
        keys.clone(),
        history_options(Some(RecoveryPolicy::PRESET)),
    );
    let anchor = V3MemoryAnchor::new();
    must_v3(writer.write_genesis_snapshot(&anchor).await);
    let accepted = must_v3(anchor.read_v3().await);
    let puts = store.operation_counts().expect("counts").put;
    let native = V3CommitStore::new(store.clone(), keys, history_options(None));
    for candidate in [&writer, &native] {
        let write = V3CommitWrite::delta(vec![V3CommitSection::new(
            V3SectionType::IndexRun,
            V3_SECTION_FLAG_MUST_UNDERSTAND,
            Bytes::from_static(b"must-not-publish"),
        )]);
        assert_eq!(
            candidate
                .write_child_commit(&anchor, write.clone())
                .await
                .err(),
            Some(V3FormatError::InvalidRecoveryHistory),
        );
        let mut built = false;
        assert_eq!(
            candidate
                .write_child_commit_with(&anchor, |_| {
                    built = true;
                    Ok(write.clone())
                })
                .await
                .err(),
            Some(V3FormatError::InvalidRecoveryHistory),
        );
        assert!(
            !built,
            "rejected history must not invoke the raw section builder"
        );
    }
    assert_eq!(store.operation_counts().expect("counts").put, puts);
    assert_eq!(must_v3(anchor.read_v3().await), accepted);
}

#[tokio::test]
async fn recovery_publication_delayed_candidate_cannot_shorten_supersession_promise() {
    let store = MemoryBlobStore::new();
    let keys = must_crypto(KeyRing::generate_random());
    let options = history_options(Some(RecoveryPolicy::PRESET));
    let writer = V3CommitStore::new(store.clone(), keys.clone(), options.clone());
    writer.set_publication_time_for_tests(1_000);
    let anchor = V3MemoryAnchor::new();
    let genesis = must_v3(writer.write_genesis_snapshot(&anchor).await);
    let chain = must_v3(
        writer
            .load_replay_chain_from_state(&genesis.anchor_state)
            .await,
    );
    let previous = must_v3(writer.replay_recovery_history(&chain)).expect("history");
    let plan = must_v3(
        writer
            .prepare_child_publication(&genesis.anchor_state)
            .await,
    );
    let captured = must_v3(
        crate::v3::recovery::publication::CapturedRecoveryPublication::new(
            plan.clone(),
            previous,
            RecoveryPolicy::PRESET,
            true,
        ),
    );
    let temporary = V3MemoryAnchor::with_state(genesis.anchor_state.clone());
    let context = must_repo(repository_context_from_refs(
        &options.repository_id,
        &options.keyring_envelope_ref,
    ));
    let root = must_v3(crate::v3::V3IndexRoot::new(
        Sequence::new(0),
        0,
        options.format_ref.clone(),
        options.keyring_envelope_ref.clone(),
        Vec::new(),
    ));
    let candidate = must_v3(
        writer
            .write_prepared_child_commit_with(&temporary, &plan, |key| {
                let index =
                    crate::v3::seal_v3_index_root(&keys, &context, &key.object_id, 0, &root)?;
                let history = crate::v3::recovery::section::seal(
                    &keys,
                    &context,
                    &key.object_id,
                    1,
                    &captured.section.encode()?,
                )?;
                Ok(V3CommitWrite::snapshot(vec![
                    V3CommitSection::new(
                        V3SectionType::IndexRoot,
                        V3_SECTION_FLAG_MUST_UNDERSTAND,
                        index.into_bytes(),
                    ),
                    V3CommitSection::new(
                        V3SectionType::Recovery,
                        V3_SECTION_FLAG_MUST_UNDERSTAND,
                        history,
                    ),
                ]))
            })
            .await,
    );
    assert_eq!(
        writer
            .adopt_unanchored_child(
                &anchor,
                &candidate.commit_key.object_id,
                candidate.version_id.as_ref()
            )
            .await,
        Err(V3FormatError::InvalidRecoveryHistory)
    );
    let no_policy = V3CommitStore::new(store.clone(), keys.clone(), history_options(None));
    assert_eq!(
        no_policy
            .adopt_unanchored_child(
                &anchor,
                &candidate.commit_key.object_id,
                candidate.version_id.as_ref()
            )
            .await,
        Err(V3FormatError::InvalidRecoveryHistory)
    );
    // An upload or lock-extension delay beyond declared uncertainty must not
    // consume the current anchor with a promise measured from the old sample.
    writer.set_publication_time_for_tests(61_002);
    assert_eq!(
        writer
            .adopt_verified_unanchored_child(
                &anchor,
                &genesis.anchor_state,
                &candidate,
                Some(60_000)
            )
            .await,
        Err(V3FormatError::InvalidPublicationTime)
    );
    assert_eq!(must_v3(anchor.read_v3().await), Some(genesis.anchor_state));
}

#[tokio::test]
async fn recovery_page_reads_only_exact_recovery_span_and_rejects_changed_claims() {
    use crate::v3::recovery::history::{
        RecoveryDelta, RecoveryPage, RecoveryPageLocation, RecoveryPageRef, RecoveryPoint,
        RecoverySection,
    };
    use rs3_storage::FaultInjectingBlobStore;
    let store = FaultInjectingBlobStore::new(MemoryBlobStore::new(), Vec::new());
    let keys = must_crypto(KeyRing::generate_random());
    let options = history_options(None);
    let writer = V3CommitStore::new(store.clone(), keys.clone(), options.clone());
    writer.set_publication_time_for_tests(1_000);
    let anchor = V3MemoryAnchor::new();
    let genesis = must_v3(writer.write_genesis_snapshot(&anchor).await);
    let parent = must_v3(
        writer
            .write_child_commit(
                &anchor,
                V3CommitWrite::delta(vec![V3CommitSection::new(
                    V3SectionType::IndexRun,
                    V3_SECTION_FLAG_MUST_UNDERSTAND,
                    Bytes::from_static(b"opaque-fixture"),
                )]),
            )
            .await,
    );
    let policy = RecoveryPolicy::PRESET;
    let page = RecoveryPage {
        points: vec![RecoveryPoint {
            anchor: genesis.anchor_state,
            publish_time_ms: genesis.publish_time_ms,
            protected_until_ms: must_v3(policy.promised_until_ms(parent.publish_time_ms)),
            policy_id: policy.identity(),
        }],
    };
    let section = RecoverySection {
        current_policy: policy,
        delta: RecoveryDelta {
            register: Some(RecoveryPoint {
                anchor: parent.anchor_state,
                publish_time_ms: parent.publish_time_ms,
                protected_until_ms: must_v3(policy.promised_until_ms(1_002)),
                policy_id: policy.identity(),
            }),
            expire_before_ms: None,
            roll_tail: Some(0),
        },
        snapshot: None,
        local_pages: vec![page.clone()],
    };
    let context = must_repo(repository_context_from_refs(
        &options.repository_id,
        &options.keyring_envelope_ref,
    ));
    let parent_anchor = must_v3(anchor.read_v3().await).expect("parent");
    let plan = must_v3(writer.prepare_child_publication(&parent_anchor).await);
    let carrier = must_v3(
        writer
            .write_prepared_child_commit_with(&anchor, &plan, |key| {
                let history = crate::v3::recovery::section::seal(
                    &keys,
                    &context,
                    &key.object_id,
                    1,
                    &section.encode()?,
                )?;
                Ok(V3CommitWrite::delta(vec![
                    V3CommitSection::new(
                        V3SectionType::IndexRun,
                        V3_SECTION_FLAG_MUST_UNDERSTAND,
                        Bytes::from_static(b"must-not-read-this-index"),
                    ),
                    V3CommitSection::new(
                        V3SectionType::Recovery,
                        V3_SECTION_FLAG_MUST_UNDERSTAND,
                        history,
                    ),
                ]))
            })
            .await,
    );
    let reference = RecoveryPageRef {
        location: RecoveryPageLocation::Exact {
            anchor: carrier.anchor_state,
            section_ordinal: 1,
            page_index: 0,
        },
        claims: must_v3(page.claims()),
    };
    let before = store.operation_log().expect("log").len();
    assert_eq!(must_v3(writer.read_recovery_page(&reference).await), page);
    for event in &store.operation_log().expect("log")[before..] {
        if let Some(range) = event.range {
            let ByteRange::Slice { offset, len } = range else {
                panic!("page used full GET")
            };
            assert!(
                offset + len <= carrier.sections_start || offset >= carrier.sections_start + 24,
                "page loader read the unrelated index bytes"
            );
        }
    }
    let mut changed = reference;
    changed.claims.maximum_deadline_ms += 1;
    assert_eq!(
        writer.read_recovery_page(&changed).await,
        Err(V3FormatError::InvalidRecoveryHistory)
    );
}

#[tokio::test]
async fn recovery_publication_extends_detached_payload_without_changing_logical_retention_or_rewalking_base()
 {
    use rs3_storage::{FaultInjectingBlobStore, FaultOperationKind};
    let memory = MemoryBlobStore::new();
    let logical = RetentionPolicy::new(RetentionMode::Compliance, 1);
    let policy = RecoveryPolicy::PRESET;
    let options = commit_store_options_with_maintenance_roots(
        &memory,
        V3ProviderProfile::RetainedVersionObjectLock,
        Some(logical),
    )
    .await
    .with_recovery_policy(Some(policy));
    let store = FaultInjectingBlobStore::new(memory.clone(), Vec::new());
    let repository = Arc::new(V3Repository::new(
        store.clone(),
        must_crypto(KeyRing::generate_random()),
        RepositoryOptions::default(),
        options,
    ));
    let anchor = V3MemoryAnchor::new();
    must_repo(
        repository
            .write_genesis_snapshot_with_guard(&anchor, Some(&UnenforcedQuiescedMaintenanceGuard))
            .await,
    );
    let coordinator = must_repo(V3CommitCoordinator::with_options(
        Arc::clone(&repository),
        anchor.clone(),
        CommitCoordinatorOptions::new(1, Duration::ZERO),
    ))
    .with_maintenance_guard(UnenforcedQuiescedMaintenanceGuard);
    let first = must_repo(
        coordinator
            .put_committed(
                LogicalPath::new("history/packed").expect("path"),
                Bytes::from_static(b"packed"),
                RepositoryPutOptions {
                    retention: Some(logical),
                    ..RepositoryPutOptions::default()
                },
            )
            .await,
    );
    assert_eq!(first.metadata.retention, Some(logical));
    let before = store.operation_log().expect("log").len();
    let key = LogicalPath::new("history/detached").expect("path");
    let body = Bytes::from(vec![42; 128 * 1024]);
    let detached = must_repo(
        coordinator
            .put_committed_streaming_known_len(
                key.clone(),
                body.len() as u64,
                stream::iter([Ok(body.clone())]),
                RepositoryPutOptions {
                    retention: Some(logical),
                    ..RepositoryPutOptions::default()
                },
                64 * 1024,
            )
            .await,
    );
    assert_eq!(detached.metadata.retention, Some(logical));
    assert_eq!(must_repo(repository.head(&key)).retention, Some(logical));
    assert!(
        !store.operation_log().expect("log")[before..]
            .iter()
            .any(
                |event| event.object_id.as_ref() == Some(&first.anchor_state.commit_key)
                    && matches!(
                        event.kind,
                        FaultOperationKind::GetRange | FaultOperationKind::GetRangeAt
                    )
            ),
        "ordinary covered successor must not replay the prior graph"
    );
    let current = must_v3(repository.commit_store().read_anchor_head(&anchor).await).expect("head");
    let required = must_v3(policy.promised_until_ms(current.parsed_header.header.publish_time_ms));
    let payloads = memory
        .list_prefix_versions("objects/v03/")
        .await
        .expect("payload versions");
    assert_eq!(payloads.len(), 1);
    assert!(
        payloads[0]
            .retain_until_ms
            .is_some_and(|deadline| deadline >= required)
    );
    assert!(
        payloads[0]
            .retention
            .is_some_and(|physical| physical.retain_days > logical.retain_days)
    );
    assert_eq!(
        must_repo(repository.get_range(&key, ByteRange::Full).await),
        body
    );
}

#[tokio::test]
async fn recovery_publication_quiet_expiry_writes_once_only_when_a_known_promise_expires() {
    let store = MemoryBlobStore::new();
    let policy = must_v3(RecoveryPolicy::new(1, 120, 60_000));
    let repository = V3Repository::new(
        store.clone(),
        must_crypto(KeyRing::generate_random()),
        RepositoryOptions::default(),
        history_options(Some(policy)),
    );
    repository
        .commit_store()
        .set_publication_time_for_tests(1_000);
    let anchor = V3MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(
        repository
            .put_committed(
                &anchor,
                LogicalPath::new("quiet/live").expect("path"),
                Bytes::from_static(b"still-current"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    let before = must_v3(anchor.read_v3().await).expect("anchor");
    let lease = must_repo(repository.claim_commit_coordinator());
    let mutation = || crate::v3::service::V3CoordinatedMutation::new(&lease, &anchor);
    assert!(
        must_repo(
            repository
                .maybe_publish_recovery_expiry_checkpoint_coordinated(mutation())
                .await
        )
        .is_none()
    );
    let due = must_v3(policy.promised_until_ms(1_001)) + i64::from(policy.clock_uncertainty_ms());
    repository
        .commit_store()
        .set_publication_time_for_tests(due);
    let expired = must_repo(
        repository
            .maybe_publish_recovery_expiry_checkpoint_coordinated(mutation())
            .await,
    )
    .expect("expiry root");
    assert_eq!(
        expired.anchor_state.sequence,
        before.sequence.checked_next().expect("next")
    );
    let chain = must_v3(
        repository
            .commit_store()
            .load_replay_chain_from_state(&expired.anchor_state)
            .await,
    );
    let history =
        must_v3(repository.commit_store().replay_recovery_history(&chain)).expect("history");
    assert_eq!(history.snapshot.tail.len(), 1);
    assert_eq!(history.snapshot.tail[0].anchor, before);
    let puts = store.operation_counts().expect("counts").put;
    assert!(
        must_repo(
            repository
                .maybe_publish_recovery_expiry_checkpoint_coordinated(mutation())
                .await
        )
        .is_none()
    );
    assert_eq!(store.operation_counts().expect("counts").put, puts);
    assert_eq!(must_v3(anchor.read_v3().await), Some(expired.anchor_state));
}
