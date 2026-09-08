use super::*;
use rs3_storage::{FaultInjectingBlobStore, FaultOperationKind};

fn options() -> V2CommitStoreOptions {
    V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    )
}

#[tokio::test]
async fn publication_times_are_strict_under_equal_backward_clocks_without_parent_reads() {
    let store = FaultInjectingBlobStore::new(MemoryBlobStore::new(), Vec::new());
    let writer = V2CommitStore::new(store.clone(), signing_keyring(), options());
    writer.set_publication_time_for_tests(1_000);
    let anchor = V2MemoryAnchor::new();
    let mut previous = must_v2(writer.write_genesis_snapshot(&anchor).await);
    for sampled_now in [1_000, 1_000, 999, 1_001] {
        writer.set_publication_time_for_tests(sampled_now);
        let before = store.operation_log().expect("operation log").len();
        let next = must_v2(write_empty_metadata_child(&writer, &anchor, false).await);
        assert_eq!(next.publish_time_ms, previous.publish_time_ms + 1);
        assert!(
            !store.operation_log().expect("operation log")[before..]
                .iter()
                .any(|event| {
                    event.object_id.as_ref() == Some(&previous.anchor_state.commit_key)
                        && matches!(
                            event.kind,
                            FaultOperationKind::GetRange | FaultOperationKind::GetRangeAt
                        )
                }),
            "ordinary publication must use verified parent facts without a parent GET"
        );
        previous = next;
    }
    let restarted = V2CommitStore::new(store.clone(), signing_keyring(), options());
    restarted.set_publication_time_for_tests(1_000);
    must_v2(restarted.load_replay_chain_from_anchor(&anchor).await).expect("verified chain");
    let before = store.operation_log().expect("operation log").len();
    let next = must_v2(write_empty_metadata_child(&restarted, &anchor, false).await);
    assert_eq!(next.publish_time_ms, previous.publish_time_ms + 1);
    assert!(
        !store.operation_log().expect("operation log")[before..]
            .iter()
            .any(|event| {
                event.object_id.as_ref() == Some(&previous.anchor_state.commit_key)
                    && matches!(
                        event.kind,
                        FaultOperationKind::GetRange | FaultOperationKind::GetRangeAt
                    )
            }),
        "verified replay must seed the same bounded head cache"
    );
}

#[tokio::test]
async fn future_parent_refuses_publication_after_restart_and_future_candidate_refuses_adoption() {
    let store = MemoryBlobStore::new();
    let writer = V2CommitStore::new(store.clone(), signing_keyring(), options());
    let anchor = V2MemoryAnchor::new();
    for bad_sample in [-1, i64::MAX] {
        writer.set_publication_time_for_tests(bad_sample);
        assert!(matches!(
            writer.prepare_genesis_snapshot(),
            Err(V2FormatError::InvalidPublicationTime)
        ));
    }
    writer.set_publication_time_for_tests(100_000);
    let genesis = must_v2(writer.write_genesis_snapshot(&anchor).await);
    let restarted = V2CommitStore::new(store.clone(), signing_keyring(), options());
    restarted.set_publication_time_for_tests(1_000);
    must_v2(restarted.load_replay_chain_from_anchor(&anchor).await);
    let before = store.operation_counts().expect("counts");
    assert_eq!(
        write_empty_metadata_child(&restarted, &anchor, false).await,
        Err(V2FormatError::InvalidPublicationTime)
    );
    assert_eq!(store.operation_counts().expect("counts").put, before.put);
    assert_eq!(
        must_v2(anchor.read_v2().await),
        Some(genesis.anchor_state.clone())
    );

    writer.set_publication_time_for_tests(200_000);
    let temporary = V2MemoryAnchor::with_state(genesis.anchor_state.clone());
    let candidate = must_v2(write_empty_metadata_child(&writer, &temporary, true).await);
    writer.set_publication_time_for_tests(100_000);
    assert_eq!(
        writer
            .adopt_unanchored_child(
                &anchor,
                &candidate.commit_key.object_id,
                candidate.version_id.as_ref()
            )
            .await,
        Err(V2FormatError::InvalidPublicationTime)
    );
    assert_eq!(must_v2(anchor.read_v2().await), Some(genesis.anchor_state));
}

#[tokio::test]
async fn replay_rejects_equal_and_backward_signed_parent_edges() {
    for bad_time in [999, 1_000] {
        let store = MemoryBlobStore::new();
        let keys = signing_keyring();
        let writer = V2CommitStore::new(store.clone(), keys.clone(), options());
        writer.set_publication_time_for_tests(1_000);
        let anchor = V2MemoryAnchor::new();
        must_v2(writer.write_genesis_snapshot(&anchor).await);
        let child = must_v2(write_empty_metadata_child(&writer, &anchor, false).await);
        let body = store
            .get_range_at(
                &child.commit_key.object_id,
                child.version_id.as_ref(),
                ByteRange::Full,
            )
            .await
            .expect("child bytes");
        let parsed = must_v2(parse_v2_commit_object(
            &child.commit_key.object_id,
            body,
            &keys,
        ));
        let mut header = parsed.parsed_header.header;
        header.publish_time_ms = bad_time;
        let header = must_v2(header.sign_with_keyring(&keys));
        let replacement =
            must_v2(header.encode_object(&parsed.body[parsed.parsed_header.sections_start..]));
        let changed = store
            .put(
                &child.commit_key.object_id,
                replacement,
                PutOptions::default(),
            )
            .await
            .expect("signed fixture");
        let bad_anchor = V2AnchorState {
            version_id: changed.version_id,
            ..child.anchor_state
        };
        let restarted = V2CommitStore::new(store, keys, options());
        assert_eq!(
            restarted.load_replay_chain_from_state(&bad_anchor).await,
            Err(V2FormatError::InvalidPublicationTime)
        );
    }
}

#[tokio::test]
async fn siblings_share_a_parent_time_and_checkpoint_replay_does_not_fetch_pruned_parent() {
    let store = MemoryBlobStore::new();
    let writer = V2CommitStore::new(store.clone(), signing_keyring(), options());
    writer.set_publication_time_for_tests(1_000);
    let anchor = V2MemoryAnchor::new();
    let base = must_v2(writer.write_genesis_snapshot(&anchor).await);
    let mut siblings = Vec::new();
    for _ in 0..8 {
        let temporary = V2MemoryAnchor::with_state(base.anchor_state.clone());
        siblings.push(must_v2(
            write_empty_metadata_child(&writer, &temporary, true).await,
        ));
    }
    assert!(
        siblings
            .iter()
            .all(|sibling| sibling.publish_time_ms == 1_001)
    );
    let chosen = &siblings[7];
    let accepted = must_v2(
        writer
            .adopt_unanchored_child(
                &anchor,
                &chosen.commit_key.object_id,
                chosen.version_id.as_ref(),
            )
            .await,
    );
    store
        .delete_at(&base.commit_key.object_id, base.version_id.as_ref())
        .await
        .expect("pruned parent");
    let restarted = V2CommitStore::new(store, signing_keyring(), options());
    restarted.set_publication_time_for_tests(1_000);
    let chain =
        must_v2(restarted.load_replay_chain_from_anchor(&anchor).await).expect("checkpoint");
    assert_eq!(
        chain.commits_newest_first.len(),
        1,
        "trusted exact root is the replay cut"
    );
    let child = must_v2(write_empty_metadata_child(&restarted, &anchor, false).await);
    assert_eq!(child.publish_time_ms, accepted.publish_time_ms + 1);
}

#[tokio::test]
async fn prepared_genesis_keeps_chosen_time_across_exact_retries() {
    let writer = V2CommitStore::new(MemoryBlobStore::new(), signing_keyring(), options());
    writer.set_publication_time_for_tests(1_000);
    let prepared = must_v2(writer.prepare_genesis_snapshot());
    let anchor = V2MemoryAnchor::new();
    writer.set_publication_time_for_tests(2_000);
    let first = must_v2(
        writer
            .publish_prepared_genesis(&anchor, &prepared, true)
            .await,
    );
    writer.set_publication_time_for_tests(3_000);
    let retry = must_v2(
        writer
            .publish_prepared_genesis(&anchor, &prepared, false)
            .await,
    );
    assert_eq!(first, retry);
    assert_eq!(retry.publish_time_ms, 1_000);
}
