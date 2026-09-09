use super::*;
use crate::lease_guard::lease_with_guard_state;
use crate::test_support::{FakeLeaseApi, Fault, Operation};
use crate::tests::v3_state;
use k8s_openapi::jiff::Timestamp;
use std::time::Duration;

fn settings() -> LeaseSettings {
    LeaseSettings {
        namespace: "fixture".to_owned(),
        name: "anchor".to_owned(),
        field_manager: "rs3-test".to_owned(),
    }
}

fn stored_lease(sequence: u64, version: &str) -> Lease {
    let mut lease = new_v3_lease("anchor", &v3_state(sequence));
    lease.metadata.resource_version = Some(version.to_owned());
    lease
}

async fn fault(
    api: &FakeLeaseApi,
    operation: Operation,
    error: LeaseGuardError,
    lease: Option<Lease>,
) {
    api.faults.lock().await.push_back(Fault {
        operation,
        error,
        concurrent_lease: lease,
    });
}

async fn advance(api: &FakeLeaseApi, expected: Option<u64>, next: u64) -> V3Result<V3AnchorState> {
    compare_and_advance_lease(
        api,
        &settings(),
        None,
        expected.map(v3_state).as_ref(),
        v3_state(next),
    )
    .await
}

#[tokio::test]
async fn missing_anchor_is_created_then_advanced_with_resource_version() {
    let api = FakeLeaseApi::default();
    assert_eq!(advance(&api, None, 1).await.expect("create"), v3_state(1));
    assert_eq!(
        advance(&api, Some(1), 2).await.expect("advance"),
        v3_state(2)
    );
    assert_eq!(
        *api.calls.lock().await,
        vec![
            Operation::Get,
            Operation::Create,
            Operation::Get,
            Operation::Replace
        ]
    );
    let stored = api.lease.lock().await.clone().expect("stored lease");
    assert_eq!(stored.metadata.resource_version.as_deref(), Some("2"));
    assert_eq!(
        v3_anchor_state_from_lease(&stored).expect("anchor"),
        v3_state(2)
    );
}

#[tokio::test]
async fn create_conflict_rereads_and_updates_the_concurrently_created_empty_lease() {
    let api = FakeLeaseApi::default();
    let mut empty = Lease::default();
    empty.metadata.resource_version = Some("7".to_owned());
    fault(
        &api,
        Operation::Create,
        LeaseGuardError::Conflict,
        Some(empty),
    )
    .await;
    assert_eq!(
        advance(&api, None, 1).await.expect("retry create race"),
        v3_state(1)
    );
    assert_eq!(
        *api.calls.lock().await,
        vec![
            Operation::Get,
            Operation::Create,
            Operation::Get,
            Operation::Replace
        ]
    );
    assert_eq!(
        api.lease
            .lock()
            .await
            .as_ref()
            .expect("lease")
            .metadata
            .resource_version
            .as_deref(),
        Some("8")
    );
}

#[tokio::test]
async fn conflicts_reread_and_reject_a_concurrent_anchor_change() {
    for operation in [Operation::Create, Operation::Replace] {
        let api = FakeLeaseApi::default();
        let expected = (operation == Operation::Replace).then_some(1);
        *api.lease.lock().await = expected.map(|seq| stored_lease(seq, "1"));
        let other = stored_lease(3, "2");
        fault(
            &api,
            operation,
            LeaseGuardError::Conflict,
            Some(other.clone()),
        )
        .await;
        assert!(matches!(
            advance(&api, expected, 2).await,
            Err(V3FormatError::StaleAnchor)
        ));
        assert_eq!(*api.lease.lock().await, Some(other));
        assert_eq!(
            *api.calls.lock().await,
            vec![Operation::Get, operation, Operation::Get]
        );
    }
}

#[tokio::test]
async fn create_and_replace_conflicts_stop_at_sixteen_attempts() {
    for operation in [Operation::Create, Operation::Replace] {
        let api = FakeLeaseApi::default();
        let expected = (operation == Operation::Replace).then_some(1);
        *api.lease.lock().await = expected.map(|seq| stored_lease(seq, "1"));
        let original = api.lease.lock().await.clone();
        for _ in 0..16 {
            fault(&api, operation, LeaseGuardError::Conflict, None).await;
        }
        assert!(matches!(
            advance(&api, expected, 2).await,
            Err(V3FormatError::AnchorAdvanceFailed)
        ));
        assert_eq!(
            *api.calls.lock().await,
            [Operation::Get, operation].repeat(16)
        );
        assert_eq!(*api.lease.lock().await, original);
        assert!(api.faults.lock().await.is_empty());
    }
}

#[tokio::test]
async fn final_allowed_attempt_can_succeed() {
    for operation in [Operation::Create, Operation::Replace] {
        let api = FakeLeaseApi::default();
        let expected = (operation == Operation::Replace).then_some(1);
        *api.lease.lock().await = expected.map(|seq| stored_lease(seq, "1"));
        for _ in 0..15 {
            fault(&api, operation, LeaseGuardError::Conflict, None).await;
        }
        assert_eq!(
            advance(&api, expected, 2).await.expect("sixteenth attempt"),
            v3_state(2)
        );
        assert_eq!(
            *api.calls.lock().await,
            [Operation::Get, operation].repeat(16)
        );
    }
}

#[tokio::test]
async fn unexpected_api_failures_fail_closed_without_retrying() {
    for operation in [Operation::Get, Operation::Create, Operation::Replace] {
        let api = FakeLeaseApi::default();
        let expected = (operation == Operation::Replace).then_some(1);
        *api.lease.lock().await = expected.map(|seq| stored_lease(seq, "1"));
        let original = api.lease.lock().await.clone();
        fault(&api, operation, LeaseGuardError::ApiUnavailable, None).await;
        let result = advance(&api, expected, 2).await;
        if operation == Operation::Get {
            assert!(matches!(result, Err(V3FormatError::AnchorReadFailed)));
            assert_eq!(*api.calls.lock().await, vec![Operation::Get]);
        } else {
            assert!(matches!(result, Err(V3FormatError::AnchorAdvanceFailed)));
            assert_eq!(*api.calls.lock().await, vec![Operation::Get, operation]);
        }
        assert_eq!(*api.lease.lock().await, original);
    }
}

#[tokio::test]
async fn expected_anchor_is_never_recreated_after_disappearance() {
    let api = FakeLeaseApi::default();
    assert!(matches!(
        advance(&api, Some(1), 2).await,
        Err(V3FormatError::StaleAnchor)
    ));
    assert_eq!(*api.calls.lock().await, vec![Operation::Get]);
    assert!(api.lease.lock().await.is_none());
}

#[tokio::test]
async fn stale_nonmonotonic_and_malformed_candidates_do_not_write() {
    let api = FakeLeaseApi::default();
    *api.lease.lock().await = Some(stored_lease(7, "1"));
    for (expected, next) in [(None, 8), (Some(6), 8), (Some(7), 6)] {
        assert!(matches!(
            advance(&api, expected, next).await,
            Err(V3FormatError::StaleAnchor)
        ));
    }
    let mut changed = v3_state(7);
    changed.body_digest = [42; 32];
    assert!(matches!(
        compare_and_advance_lease(&api, &settings(), None, Some(&v3_state(7)), changed).await,
        Err(V3FormatError::StaleAnchor)
    ));
    let mut malformed = stored_lease(7, "1");
    malformed
        .metadata
        .annotations
        .as_mut()
        .expect("annotations")
        .remove(V3_BODY_DIGEST_ANNOTATION);
    *api.lease.lock().await = Some(malformed);
    assert!(matches!(
        advance(&api, Some(7), 8).await,
        Err(V3FormatError::AnchorReadFailed)
    ));
    assert_eq!(*api.calls.lock().await, vec![Operation::Get; 5]);
}

async fn fenced_api() -> (FakeLeaseApi, WriterFence) {
    let api = FakeLeaseApi::default();
    let guard = LeaseGuard::new(
        api.clone(),
        settings(),
        "writer-a".to_owned(),
        Duration::from_secs(30),
    )
    .expect("guard");
    guard
        .acquire_at(Timestamp::now(), Duration::ZERO)
        .await
        .expect("acquire");
    let fence = guard.writer_fence().expect("fence");
    api.calls.lock().await.clear();
    (api, fence)
}

#[tokio::test]
async fn locally_live_fence_cannot_recreate_a_missing_lease() {
    let (api, fence) = fenced_api().await;
    *api.lease.lock().await = None;
    assert!(fence.is_live());
    assert!(matches!(
        compare_and_advance_lease(&api, &settings(), Some(&fence), None, v3_state(1)).await,
        Err(V3FormatError::AnchorAdvanceFailed)
    ));
    assert_eq!(*api.calls.lock().await, vec![Operation::Get]);
}

#[tokio::test]
async fn stolen_fence_is_rejected_even_while_local_deadline_is_live() {
    for during_replace in [false, true] {
        let (api, fence) = fenced_api().await;
        let current = api.lease.lock().await.clone().expect("lease");
        let mut stolen = lease_with_guard_state(
            current,
            &WriterFenceClaim {
                holder_identity: "writer-b".to_owned(),
                token: 2,
            },
            2,
            Duration::from_secs(30),
            Timestamp::now(),
            true,
        )
        .expect("handoff");
        stolen.metadata.resource_version = Some("2".to_owned());
        if during_replace {
            fault(
                &api,
                Operation::Replace,
                LeaseGuardError::Conflict,
                Some(stolen.clone()),
            )
            .await;
        } else {
            *api.lease.lock().await = Some(stolen.clone());
        }
        assert!(fence.is_live());
        assert!(matches!(
            compare_and_advance_lease(&api, &settings(), Some(&fence), None, v3_state(1)).await,
            Err(V3FormatError::AnchorAdvanceFailed)
        ));
        assert_eq!(*api.lease.lock().await, Some(stolen));
        let calls = if during_replace {
            vec![Operation::Get, Operation::Replace, Operation::Get]
        } else {
            vec![Operation::Get]
        };
        assert_eq!(*api.calls.lock().await, calls);
    }
}

#[tokio::test]
async fn renewal_conflict_preserves_the_latest_coordination_metadata() {
    let (api, fence) = fenced_api().await;
    let mut renewed = api.lease.lock().await.clone().expect("lease");
    renewed.metadata.resource_version = Some("2".to_owned());
    renewed
        .metadata
        .annotations
        .as_mut()
        .expect("annotations")
        .insert(
            lease_guard::WRITER_RENEWAL_ANNOTATION.to_owned(),
            "2".to_owned(),
        );
    fault(
        &api,
        Operation::Replace,
        LeaseGuardError::Conflict,
        Some(renewed.clone()),
    )
    .await;
    assert_eq!(
        compare_and_advance_lease(&api, &settings(), Some(&fence), None, v3_state(1))
            .await
            .expect("retry renewal"),
        v3_state(1)
    );
    let stored = api.lease.lock().await.clone().expect("lease");
    assert_eq!(stored.spec, renewed.spec);
    assert_eq!(stored.metadata.resource_version.as_deref(), Some("3"));
    let annotations = stored.metadata.annotations.expect("annotations");
    assert_eq!(
        annotations
            .get(lease_guard::WRITER_RENEWAL_ANNOTATION)
            .map(String::as_str),
        Some("2")
    );
    assert_eq!(
        *api.calls.lock().await,
        vec![
            Operation::Get,
            Operation::Replace,
            Operation::Get,
            Operation::Replace
        ]
    );
}

#[tokio::test]
async fn accepted_write_with_lost_response_is_not_republished_from_old_parent() {
    let api = FakeLeaseApi::default();
    *api.lease.lock().await = Some(stored_lease(1, "1"));
    fault(
        &api,
        Operation::Replace,
        LeaseGuardError::ApiUnavailable,
        Some(stored_lease(2, "2")),
    )
    .await;
    assert!(matches!(
        advance(&api, Some(1), 2).await,
        Err(V3FormatError::AnchorAdvanceFailed)
    ));
    assert!(matches!(
        advance(&api, Some(1), 2).await,
        Err(V3FormatError::StaleAnchor)
    ));
    assert_eq!(
        *api.calls.lock().await,
        vec![Operation::Get, Operation::Replace, Operation::Get]
    );
    assert_eq!(
        advance(&api, Some(2), 2)
            .await
            .expect("reconciled idempotent update"),
        v3_state(2)
    );
}

#[tokio::test]
async fn fencing_read_bumps_the_resource_version_so_earlier_updates_cannot_land() {
    let api = FakeLeaseApi::default();
    *api.lease.lock().await = Some(stored_lease(1, "1"));
    // A delayed advance prepared against the version the fencing read replaces.
    let mut delayed = stored_lease(2, "1");
    delayed.metadata.resource_version = Some("1".to_owned());

    assert_eq!(
        fence_and_read_lease(&api, &settings(), None)
            .await
            .expect("fenced read"),
        Some(v3_state(1))
    );
    let stored = api.lease.lock().await.clone().expect("lease");
    assert_eq!(stored.metadata.resource_version.as_deref(), Some("2"));
    assert_eq!(
        stored
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(ANCHOR_FENCE_ANNOTATION))
            .map(String::as_str),
        Some("1")
    );
    assert_eq!(
        *api.calls.lock().await,
        vec![Operation::Get, Operation::Replace]
    );
    // The earlier request is refused: it can never land after the fence.
    assert!(matches!(
        api.replace_lease("fixture", "anchor", &delayed).await,
        Err(LeaseGuardError::Conflict)
    ));
    assert_eq!(
        fence_and_read_lease(&api, &settings(), None)
            .await
            .expect("second fenced read"),
        Some(v3_state(1))
    );
    // Anchor decoding ignores the fence counter, and advances keep it.
    assert_eq!(
        advance(&api, Some(1), 2).await.expect("advance"),
        v3_state(2)
    );
    assert_eq!(
        fence_and_read_lease(&api, &settings(), None)
            .await
            .expect("fenced read after advance"),
        Some(v3_state(2))
    );
}

#[tokio::test]
async fn fencing_read_never_creates_a_lease_and_requires_the_live_writer_claim() {
    let api = FakeLeaseApi::default();
    assert_eq!(
        fence_and_read_lease(&api, &settings(), None)
            .await
            .expect("no lease"),
        None
    );
    assert_eq!(*api.calls.lock().await, vec![Operation::Get]);

    let (api, fence) = fenced_api().await;
    // The Lease holds the writer claim but no anchor yet.
    assert_eq!(
        fence_and_read_lease(&api, &settings(), Some(&fence))
            .await
            .expect("fenced read under the live claim"),
        None
    );
    let current = api.lease.lock().await.clone().expect("lease");
    let mut stolen = lease_with_guard_state(
        current,
        &WriterFenceClaim {
            holder_identity: "writer-b".to_owned(),
            token: 2,
        },
        2,
        Duration::from_secs(30),
        Timestamp::now(),
        true,
    )
    .expect("handoff");
    stolen.metadata.resource_version = Some("9".to_owned());
    *api.lease.lock().await = Some(stolen);
    assert!(matches!(
        fence_and_read_lease(&api, &settings(), Some(&fence)).await,
        Err(V3FormatError::AnchorAdvanceFailed)
    ));
}
