use super::*;
use crate::v3::RecoveryPolicy;
use rs3_storage::FaultInjectingBlobStore;
use std::collections::BTreeMap;

fn options() -> V3CommitStoreOptions {
    V3CommitStoreOptions::for_profile(
        V3ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    )
    .with_recovery_policy(Some(RecoveryPolicy::PRESET))
}

#[tokio::test]
async fn recovery_reachability_deduplicates_overlapping_points_and_keeps_deleted_payload() {
    let store = FaultInjectingBlobStore::new(MemoryBlobStore::new(), Vec::new());
    let repository = V3Repository::new(
        store.clone(),
        must_crypto(KeyRing::generate_random()),
        RepositoryOptions::default(),
        options(),
    );
    let anchor = V3MemoryAnchor::new();
    repository
        .commit_store()
        .set_publication_time_for_tests(1_000);
    let genesis = must_repo(repository.write_genesis_snapshot(&anchor).await);
    let key = must_type(LogicalPath::new("history/private-deleted-object"));
    must_repo(
        repository
            .put_committed(
                &anchor,
                key.clone(),
                Bytes::from_static(b"protected payload"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    let payload = must_v3(anchor.read_v3().await).expect("payload anchor");
    must_repo(repository.delete_committed(&anchor, key).await);
    must_repo(repository.write_index_snapshot(&anchor).await);
    let before = store.operation_log().expect("log").len();
    let graph = must_v3(
        repository
            .commit_store()
            .recovery_mark_for_tests(&anchor, V3MaintenanceBudgets::default())
            .await,
    );
    let deadline = must_v3(RecoveryPolicy::PRESET.promised_until_ms(1_003));
    assert_eq!(
        graph.targets.get(&(payload.commit_key, payload.version_id)),
        Some(&Some(deadline))
    );
    assert_eq!(
        graph.targets.get(&(
            genesis.anchor_state.commit_key,
            genesis.anchor_state.version_id
        )),
        Some(&Some(deadline))
    );
    let mut header_probes = BTreeMap::new();
    for event in &store.operation_log().expect("log")[before..] {
        if matches!(event.range, Some(ByteRange::Slice { offset: 0, .. })) {
            *header_probes.entry(event.object_id.clone()).or_insert(0) += 1;
        }
    }
    assert!(!header_probes.is_empty());
    assert!(
        header_probes.values().all(|count| *count == 1),
        "duplicate exact commit traversal"
    );
    assert_eq!(graph.cutoff, Some(0));
    assert_eq!(graph.point_count, 4);
    assert_eq!(graph.oldest_publish_time_ms, Some(1_000));
    assert!(graph.historical_exact_bytes > 0);
    assert_eq!(
        graph.clock_uncertainty_ms,
        Some(RecoveryPolicy::PRESET.clock_uncertainty_ms())
    );
    assert_eq!(
        graph.expiry_due,
        Some(must_v3(RecoveryPolicy::PRESET.promised_until_ms(1_001)) + 60_000)
    );
}

#[tokio::test]
async fn recovery_reachability_missing_historical_root_and_actual_read_budget_fail_closed() {
    let store = MemoryBlobStore::new();
    let repository = V3Repository::new(
        store.clone(),
        must_crypto(KeyRing::generate_random()),
        RepositoryOptions::default(),
        options(),
    );
    let anchor = V3MemoryAnchor::new();
    let genesis = must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(repository.write_index_snapshot(&anchor).await);
    let counts = store.operation_counts().expect("counts");
    assert!(
        repository
            .commit_store()
            .recovery_mark_for_tests(
                &anchor,
                V3MaintenanceBudgets {
                    max_request_count: Some(1),
                    ..V3MaintenanceBudgets::default()
                }
            )
            .await
            .is_err()
    );
    let after = store.operation_counts().expect("counts");
    assert_eq!(after.head - counts.head, 1);
    assert_eq!(after.get - counts.get, 0);
    store
        .delete_at(
            &genesis.anchor_state.commit_key,
            genesis.anchor_state.version_id.as_ref(),
        )
        .await
        .expect("remove historical root");
    // The current root remains independently replayable, but its authenticated
    // registry still promises the removed predecessor. Marking must not accept it.
    must_repo(repository.load_chain_from_anchor(&anchor).await);
    assert!(
        repository
            .commit_store()
            .recovery_mark_for_tests(&anchor, V3MaintenanceBudgets::default())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn recovery_reachability_expiry_does_not_reactivate_an_old_root_registry() {
    let store = MemoryBlobStore::new();
    let keys = must_crypto(KeyRing::generate_random());
    let options = options();
    let repository = V3Repository::new(
        store.clone(),
        keys.clone(),
        RepositoryOptions::default(),
        options.clone(),
    );
    let anchor = V3MemoryAnchor::new();
    repository
        .commit_store()
        .set_publication_time_for_tests(1_000);
    let genesis = must_repo(repository.write_genesis_snapshot(&anchor).await);
    repository
        .commit_store()
        .set_publication_time_for_tests(2_000);
    let parent = must_repo(repository.write_index_snapshot(&anchor).await);
    let writer = repository.commit_store();
    let chain = must_v3(
        writer
            .load_replay_chain_from_state(&parent.anchor_state)
            .await,
    );
    let previous = must_v3(writer.replay_recovery_history(&chain)).expect("history");
    let cutoff = previous.snapshot.tail[0].protected_until_ms;
    writer.set_publication_time_for_tests(cutoff + 60_000);
    let plan = must_v3(writer.prepare_child_publication(&parent.anchor_state).await);
    let mut captured = must_v3(
        crate::v3::recovery::publication::CapturedRecoveryPublication::new(
            plan.clone(),
            previous,
            RecoveryPolicy::PRESET,
            true,
        ),
    );
    captured.section.delta.expire_before_ms = Some(cutoff);
    let snapshot = captured.section.snapshot.as_mut().expect("root snapshot");
    snapshot.expire_before_ms = cutoff;
    snapshot
        .tail
        .retain(|point| point.protected_until_ms > cutoff);
    let context = must_repo(repository_context_from_refs(
        &options.repository_id,
        &options.keyring_envelope_ref,
    ));
    let root = must_v3(crate::v3::V3IndexRoot::new(
        Sequence::ZERO,
        0,
        options.format_ref.clone(),
        options.keyring_envelope_ref.clone(),
        Vec::new(),
    ));
    must_v3(
        writer
            .write_prepared_child_commit_with(&anchor, &plan, |key| {
                let index =
                    crate::v3::seal_v3_index_root(&keys, &context, &key.object_id, 0, &root)?;
                let recovery = crate::v3::recovery::section::seal(
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
                        recovery,
                    ),
                ]))
            })
            .await,
    );
    store
        .delete_at(
            &genesis.anchor_state.commit_key,
            genesis.anchor_state.version_id.as_ref(),
        )
        .await
        .expect("expired carrier removed");
    let graph = must_v3(
        writer
            .recovery_mark_for_tests(&anchor, V3MaintenanceBudgets::default())
            .await,
    );
    assert_eq!(graph.cutoff, Some(cutoff));
    assert!(!graph.targets.contains_key(&(
        genesis.anchor_state.commit_key,
        genesis.anchor_state.version_id
    )));
    assert!(graph.targets.contains_key(&(
        parent.anchor_state.commit_key,
        parent.anchor_state.version_id
    )));
}

#[tokio::test]
async fn recovery_reachability_streams_more_than_4096_points_beyond_startup_chain_limit() {
    use crate::v3::recovery::history::{
        RecoveryDelta, RecoveryPage, RecoveryPageLocation, RecoveryPageRef, RecoveryPoint,
        RecoverySection, RecoverySnapshot,
    };
    let store = MemoryBlobStore::new();
    let keys = must_crypto(KeyRing::generate_random());
    // Historical checkpoint carriers are independently signed empty namespaces.
    // Only the final root supplies registry authority, keeping fixture generation
    // linear rather than storing thousands of growing historical snapshots.
    let mut options = options().with_recovery_policy(None);
    options.replay_limits.max_commits = 16;
    let writer = V3CommitStore::new(store, keys.clone(), options.clone());
    writer.set_publication_time_for_tests(1_000);
    let anchor = V3MemoryAnchor::new();
    let context = must_repo(repository_context_from_refs(
        &options.repository_id,
        &options.keyring_envelope_ref,
    ));
    let empty = must_v3(crate::v3::V3IndexRoot::new(
        Sequence::ZERO,
        0,
        options.format_ref.clone(),
        options.keyring_envelope_ref.clone(),
        Vec::new(),
    ));
    let policy = RecoveryPolicy::PRESET;
    let deadline = must_v3(policy.promised_until_ms(10_000));
    let first = must_v3(writer.write_genesis_snapshot(&anchor).await);
    let mut points = vec![RecoveryPoint {
        anchor: first.anchor_state,
        publish_time_ms: first.publish_time_ms,
        protected_until_ms: deadline,
        policy_id: policy.identity(),
    }];
    for _ in 0..4096 {
        let base = must_v3(anchor.read_v3().await).expect("accepted checkpoint");
        let plan = must_v3(writer.prepare_child_publication(&base).await);
        let stored = must_v3(
            writer
                .write_prepared_child_commit_with(&anchor, &plan, |key| {
                    let bytes =
                        crate::v3::seal_v3_index_root(&keys, &context, &key.object_id, 0, &empty)?;
                    Ok(V3CommitWrite::snapshot(vec![V3CommitSection::new(
                        V3SectionType::IndexRoot,
                        V3_SECTION_FLAG_MUST_UNDERSTAND,
                        bytes.into_bytes(),
                    )]))
                })
                .await,
        );
        points.push(RecoveryPoint {
            anchor: stored.anchor_state,
            publish_time_ms: stored.publish_time_ms,
            protected_until_ms: deadline,
            policy_id: policy.identity(),
        });
    }
    let parent = points.pop().expect("last accepted checkpoint");
    let page = RecoveryPage { points };
    let section = RecoverySection {
        current_policy: policy,
        delta: RecoveryDelta {
            register: Some(parent.clone()),
            expire_before_ms: None,
            roll_tail: Some(0),
        },
        snapshot: Some(RecoverySnapshot {
            pages: vec![RecoveryPageRef {
                location: RecoveryPageLocation::ThisSection { page_index: 0 },
                claims: must_v3(page.claims()),
            }],
            tail: vec![parent],
            expire_before_ms: 0,
        }),
        local_pages: vec![page],
    };
    let base = must_v3(anchor.read_v3().await).expect("accepted checkpoint");
    let plan = must_v3(writer.prepare_child_publication(&base).await);
    must_v3(
        writer
            .write_prepared_child_commit_with(&anchor, &plan, |key| {
                let bytes =
                    crate::v3::seal_v3_index_root(&keys, &context, &key.object_id, 0, &empty)?;
                let recovery = crate::v3::recovery::section::seal(
                    &keys,
                    &context,
                    &key.object_id,
                    1,
                    &section.encode()?,
                )?;
                Ok(V3CommitWrite::snapshot(vec![
                    V3CommitSection::new(
                        V3SectionType::IndexRoot,
                        V3_SECTION_FLAG_MUST_UNDERSTAND,
                        bytes.into_bytes(),
                    ),
                    V3CommitSection::new(
                        V3SectionType::Recovery,
                        V3_SECTION_FLAG_MUST_UNDERSTAND,
                        recovery,
                    ),
                ]))
            })
            .await,
    );
    let graph = must_v3(
        writer
            .recovery_mark_for_tests(&anchor, V3MaintenanceBudgets::default())
            .await,
    );
    assert_eq!(graph.targets.len(), 4098);
    assert_eq!(graph.point_count, 4098);
    assert!(
        graph.accounted_metadata_bytes < V3MaintenanceBudgets::default().max_history_metadata_bytes
    );
    assert!(
        graph.pending_section_bytes < V3MaintenanceBudgets::default().max_history_pending_bytes
    );
    println!(
        "recovery graph points=4097 targets={} accounted_metadata_bytes={} pending_section_bytes={} startup_max_commits=16",
        graph.targets.len(),
        graph.accounted_metadata_bytes,
        graph.pending_section_bytes
    );
    assert_eq!(
        graph
            .targets
            .values()
            .filter(|floor| **floor == Some(deadline))
            .count(),
        4098
    );
    assert!(
        writer
            .recovery_mark_for_tests(
                &anchor,
                V3MaintenanceBudgets {
                    max_history_metadata_bytes: 1,
                    ..V3MaintenanceBudgets::default()
                }
            )
            .await
            .is_err()
    );
}
