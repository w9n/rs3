use super::*;

#[tokio::test]
async fn orphan_report_is_empty_for_accepted_repository_objects() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let repo = Repository::with_keyring(store, keyring);
    let anchor = MemoryCheckpointAnchor::new();

    let first = repo
        .put_committed(
            key("p/12/a"),
            Bytes::from_static(b"a"),
            RepositoryPutOptions::default(),
            &anchor,
        )
        .await;
    assert!(first.is_ok());
    let second = must(
        repo.put_committed(
            key("p/12/b"),
            Bytes::from_static(b"b"),
            RepositoryPutOptions::default(),
            &anchor,
        )
        .await,
    );

    let report = must(repo.orphan_report(&second.checkpoint).await);

    assert!(report.candidates.is_empty());
    assert_eq!(
        report
            .reachable
            .iter()
            .filter(|object| object.kind == BackendObjectReferenceKind::Checkpoint)
            .count(),
        2
    );
    assert_eq!(
        report
            .reachable
            .iter()
            .filter(|object| object.kind == BackendObjectReferenceKind::CheckpointEvidence)
            .count(),
        2
    );
    assert_eq!(
        report
            .reachable
            .iter()
            .filter(|object| object.kind == BackendObjectReferenceKind::IndexDelta)
            .count(),
        0
    );
    assert_eq!(
        report
            .reachable
            .iter()
            .filter(|object| object.kind == BackendObjectReferenceKind::Payload)
            .count(),
        2
    );
}

#[tokio::test]
async fn orphan_report_finds_unaccepted_payload_objects() {
    let inner = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let anchor = MemoryCheckpointAnchor::new();
    let accepted_repo = Repository::with_keyring(inner.clone(), keyring.clone());
    let accepted = must(
        accepted_repo
            .put_committed(
                key("p/12/accepted"),
                Bytes::from_static(b"accepted"),
                RepositoryPutOptions::default(),
                &anchor,
            )
            .await,
    );
    let failing_store = FailOncePutStore::new(inner.clone(), CHECKPOINT_OBJECT_PREFIX);
    let writer = Repository::with_keyring(failing_store, keyring.clone());
    let loaded = writer.load_checkpoint_position(&accepted.checkpoint).await;
    assert!(loaded.is_ok());
    let staged = writer
        .put(
            key("p/12/unaccepted"),
            Bytes::from_static(b"unaccepted"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(staged.is_ok());

    let failed = writer.publish_checkpoint(&anchor).await;
    let current_anchor = match anchor.read().await {
        Ok(anchor) => CheckpointPosition::from(anchor),
        Err(error) => panic!("{error}"),
    };
    let report_repo = Repository::with_keyring(inner, keyring);
    let report = must(report_repo.orphan_report(&accepted.checkpoint).await);
    let candidate_ids = report
        .candidates
        .iter()
        .map(|candidate| candidate.object_id.as_str())
        .collect::<Vec<_>>();

    assert!(matches!(
        failed,
        Err(RepositoryError::Storage(StorageError::Provider(_)))
    ));
    assert_eq!(current_anchor, accepted.checkpoint);
    assert_eq!(report.candidates.len(), 1);
    assert!(
        report
            .candidates
            .iter()
            .any(|candidate| candidate.kind == BackendObjectReferenceKind::Payload)
    );
    assert!(candidate_ids.iter().all(|id| id.starts_with("segments/")));
}

#[tokio::test]
async fn orphan_report_finds_unaccepted_checkpoint_evidence() {
    let store = MemoryBlobStore::new();
    let repo = Repository::with_keyring(store.clone(), signing_keyring());
    let anchor = MemoryCheckpointAnchor::new();
    let accepted = must(
        repo.put_committed(
            key("p/12/accepted"),
            Bytes::from_static(b"accepted"),
            RepositoryPutOptions::default(),
            &anchor,
        )
        .await,
    );
    let unaccepted = CheckpointPosition {
        sequence: Sequence::new(9),
        checkpoint_id: checkpoint_id("unaccepted-checkpoint"),
        payload_digest: "unaccepted-digest".to_owned(),
    };
    let evidence_id = must(checkpoint_evidence_object_id(&unaccepted));
    let put = store
        .put(
            &evidence_id,
            Bytes::from_static(b"manual-evidence"),
            PutOptions::default(),
        )
        .await;
    assert!(put.is_ok());

    let report = must(repo.orphan_report(&accepted.checkpoint).await);

    assert!(report.candidates.iter().any(|candidate| {
        candidate.object_id == evidence_id
            && candidate.kind == BackendObjectReferenceKind::CheckpointEvidence
    }));
}

async fn manual_orphan_candidate(
    object_id: &str,
    options: PutOptions,
) -> RepositoryOrphanCandidate {
    let store = MemoryBlobStore::new();
    let repo = Repository::with_keyring(store.clone(), signing_keyring());
    let anchor = MemoryCheckpointAnchor::new();
    let committed = must(
        repo.put_committed(
            key("p/12/accepted"),
            Bytes::from_static(b"accepted"),
            RepositoryPutOptions::default(),
            &anchor,
        )
        .await,
    );
    let object_id = backend_object_id(object_id);
    let put = store
        .put(&object_id, Bytes::from_static(b"manual-orphan"), options)
        .await;
    assert!(put.is_ok());

    let report = must(repo.orphan_report(&committed.checkpoint).await);
    report
        .candidates
        .into_iter()
        .find(|candidate| candidate.object_id == object_id)
        .unwrap_or_else(|| panic!("missing manual orphan candidate"))
}

#[tokio::test]
async fn orphan_report_marks_retention_blocked_candidates() {
    let retention = RetentionPolicy::new(RetentionMode::Compliance, 30);
    let candidate = manual_orphan_candidate(
        "segments/manual-retained",
        PutOptions {
            retention: Some(retention),
            ..PutOptions::default()
        },
    )
    .await;

    assert_eq!(candidate.retention, Some(retention));
    assert!(candidate.delete_blocked_by_retention);
}

#[tokio::test]
async fn orphan_report_marks_legal_hold_blocked_candidates() {
    let candidate = manual_orphan_candidate(
        "segments/manual-legal-held",
        PutOptions {
            legal_hold: Some(LegalHoldStatus::On),
            ..PutOptions::default()
        },
    )
    .await;

    assert!(candidate.delete_blocked_by_legal_hold);
    assert!(!candidate.delete_blocked_by_retention);
}

#[tokio::test]
async fn delete_unprotected_orphans_removes_only_unprotected_candidates() {
    let store = MemoryBlobStore::new();
    let repo = Repository::with_keyring(store.clone(), signing_keyring());
    let anchor = MemoryCheckpointAnchor::new();
    let committed = must(
        repo.put_committed(
            key("p/12/accepted"),
            Bytes::from_static(b"accepted"),
            RepositoryPutOptions::default(),
            &anchor,
        )
        .await,
    );
    let removable_id = backend_object_id("segments/manual-removable");
    let retained_id = backend_object_id("segments/manual-retained");
    let held_id = backend_object_id("segments/manual-held");
    for (object_id, options) in [
        (removable_id.clone(), PutOptions::default()),
        (
            retained_id.clone(),
            PutOptions {
                retention: Some(RetentionPolicy::new(RetentionMode::Compliance, 30)),
                ..PutOptions::default()
            },
        ),
        (
            held_id.clone(),
            PutOptions {
                legal_hold: Some(LegalHoldStatus::On),
                ..PutOptions::default()
            },
        ),
    ] {
        let put = store
            .put(&object_id, Bytes::from_static(b"manual-orphan"), options)
            .await;
        assert!(put.is_ok());
    }

    let report = must(repo.delete_unprotected_orphans(&committed.checkpoint).await);
    let remaining = must_storage(store.list_prefix("segments/").await)
        .into_iter()
        .map(|metadata| metadata.object_id)
        .collect::<Vec<_>>();

    assert_eq!(report.candidate_count, 3);
    assert_eq!(report.deleted_count, 1);
    assert_eq!(report.retention_blocked_count, 1);
    assert_eq!(report.legal_hold_blocked_count, 1);
    assert!(!remaining.contains(&removable_id));
    assert!(remaining.contains(&retained_id));
    assert!(remaining.contains(&held_id));
}
