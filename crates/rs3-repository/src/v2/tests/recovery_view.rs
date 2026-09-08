use super::*;
use crate::v2::{RecoveryPolicy, V2RecoveryCursor};

fn options() -> V2CommitStoreOptions {
    V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    )
    .with_recovery_policy(Some(RecoveryPolicy::PRESET))
}

#[tokio::test]
async fn recovery_view_keeps_original_namespace_through_overwrite_delete_restart_and_root_cut() {
    let store = MemoryBlobStore::new();
    let keys = must_crypto(KeyRing::generate_random());
    let repository = V2Repository::new(
        store.clone(),
        keys.clone(),
        RepositoryOptions::default(),
        options(),
    );
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    let key = must_type(LogicalPath::new("private/restore-object"));
    must_repo(
        repository
            .put_committed(
                &anchor,
                key.clone(),
                Bytes::from_static(b"original"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    let selected = must_v2(anchor.read_v2().await).expect("selected anchor");
    let initially_current = must_repo(
        repository
            .open_recovery_point(&anchor, selected.sequence)
            .await,
    );
    must_repo(
        repository
            .put_committed(
                &anchor,
                key.clone(),
                Bytes::from_static(b"replacement"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    let view = must_repo(
        repository
            .open_recovery_point(&anchor, selected.sequence)
            .await,
    );
    must_repo(repository.delete_committed(&anchor, key.clone()).await);
    must_repo(repository.write_index_snapshot(&anchor).await);
    let current = must_v2(anchor.read_v2().await).expect("live anchor");
    must_repo(view.check_authority(&anchor).await);
    must_repo(initially_current.check_authority(&anchor).await);
    assert_eq!(initially_current.selected_anchor(), &selected);
    let resolved = must_repo(view.resolve_object(&key));
    assert_eq!(
        must_repo(view.get_resolved_range(&resolved, ByteRange::Full).await),
        Bytes::from_static(b"original")
    );
    assert!(repository.head(&key).is_err());
    assert_eq!(view.selected_anchor(), &selected);
    assert_eq!(must_repo(view.list_page("private/", None, 10)).len(), 1);
    let restarted = V2Repository::new(store, keys, RepositoryOptions::default(), options());
    assert!(
        restarted.head(&key).is_err(),
        "authority reader starts without live namespace"
    );
    let recovered = must_repo(
        restarted
            .open_recovery_point(&anchor, selected.sequence)
            .await,
    );
    assert_eq!(recovered.selected_anchor(), &selected);
    assert_eq!(must_repo(restarted.active_index_run_count()), 0);
    assert!(
        restarted.head(&key).is_err(),
        "history lookup must not install live or historical namespace in authority reader"
    );
    let resolved = must_repo(recovered.resolve_object(&key));
    assert_eq!(
        must_repo(
            recovered
                .get_resolved_range(&resolved, ByteRange::Full)
                .await
        ),
        Bytes::from_static(b"original")
    );
    assert_eq!(must_v2(anchor.read_v2().await), Some(current));
    assert!(
        recovered
            .check_authority(&V2MemoryAnchor::new())
            .await
            .is_err()
    );
    assert!(
        restarted
            .open_recovery_point(&anchor, Sequence::new(u64::MAX))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn recovery_point_pagination_is_bounded_stale_and_never_resurrects_expired_history() {
    let store = MemoryBlobStore::new();
    let repository = V2Repository::new(
        store,
        signing_keyring(),
        RepositoryOptions::default(),
        options(),
    );
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(repository.write_index_snapshot(&anchor).await);
    must_repo(repository.write_index_snapshot(&anchor).await);
    assert!(repository.recovery_points(&anchor, 0, None).await.is_err());
    assert!(
        repository
            .recovery_points(&anchor, 257, None)
            .await
            .is_err()
    );
    let first = must_repo(repository.recovery_points(&anchor, 1, None).await);
    assert_eq!(first.points.len(), 1);
    let cursor = first.next_cursor.expect("more history");
    let encoded = must_repo(cursor.encode());
    let cursor = must_repo(V2RecoveryCursor::decode(&encoded));
    let second = must_repo(repository.recovery_points(&anchor, 1, Some(&cursor)).await);
    assert_eq!(second.points.len(), 1);
    assert!(first.points[0].sequence < second.points[0].sequence);
    let current_page = must_repo(
        repository
            .recovery_points(&anchor, 1, second.next_cursor.as_ref())
            .await,
    );
    assert!(current_page.points[0].current);
    assert!(current_page.next_cursor.is_none());
    must_repo(repository.write_index_snapshot(&anchor).await);
    assert!(
        repository
            .recovery_points(&anchor, 1, Some(&cursor))
            .await
            .is_err()
    );
    assert!(V2RecoveryCursor::decode(&"f".repeat(1025)).is_err());

    let old = V2Repository::new(
        MemoryBlobStore::new(),
        signing_keyring(),
        RepositoryOptions::default(),
        options(),
    );
    old.commit_store().set_publication_time_for_tests(1_000);
    let old_anchor = V2MemoryAnchor::new();
    let genesis = must_repo(old.write_genesis_snapshot(&old_anchor).await);
    must_repo(old.write_index_snapshot(&old_anchor).await);
    assert!(
        old.open_recovery_point(&old_anchor, genesis.anchor_state.sequence)
            .await
            .is_err()
    );
    // Current is implicit and non-expiring even if no writes occur for a long time.
    let current = must_v2(old_anchor.read_v2().await).expect("current");
    assert!(
        old.open_recovery_point(&old_anchor, current.sequence)
            .await
            .is_ok()
    );
}
