use super::*;
use crate::test_support::FakeLeaseApi;
use crate::{LeaseGuard, LeaseGuardApi};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::jiff::Timestamp;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::sync::{Mutex, Notify};

#[derive(Clone, Copy, Default)]
enum UpdateFault {
    #[default]
    None,
    Before,
    After,
    BlockAfter,
}

#[derive(Clone)]
struct FakeApi {
    lease: FakeLeaseApi,
    secret: Arc<Mutex<Option<Secret>>>,
    writes: Arc<AtomicUsize>,
    fault: Arc<Mutex<UpdateFault>>,
    blocked: Arc<Notify>,
}

#[async_trait]
impl JournalApi for FakeApi {
    async fn get_lease(&self, name: &str) -> Result<Option<Lease>> {
        self.lease
            .get_lease("fixture", name)
            .await
            .map_err(|_| BootstrapJournalError::ApiUnavailable)
    }
    async fn get_secret(&self, _name: &str) -> Result<Option<Secret>> {
        Ok(self.secret.lock().await.clone())
    }
    async fn replace_secret(&self, _name: &str, _manager: &str, next: &Secret) -> Result<Secret> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        let fault = std::mem::take(&mut *self.fault.lock().await);
        if matches!(fault, UpdateFault::Before) {
            return Err(BootstrapJournalError::ApiUnavailable);
        }
        let accepted = {
            let mut secret = self.secret.lock().await;
            let current = secret.as_ref().ok_or(BootstrapJournalError::Missing)?;
            if current.metadata.resource_version != next.metadata.resource_version
                || current.metadata.uid != next.metadata.uid
            {
                return Err(BootstrapJournalError::Conflict);
            }
            let revision = current
                .metadata
                .resource_version
                .as_deref()
                .expect("revision")
                .parse::<u64>()
                .expect("numeric fixture revision")
                + 1;
            let mut accepted = next.clone();
            accepted.metadata.resource_version = Some(revision.to_string());
            *secret = Some(accepted.clone());
            accepted
        };
        if matches!(fault, UpdateFault::BlockAfter) {
            self.blocked.notify_one();
            std::future::pending::<()>().await;
        }
        if matches!(fault, UpdateFault::After) {
            return Err(BootstrapJournalError::ApiUnavailable);
        }
        Ok(accepted)
    }
}

fn settings() -> LeaseSettings {
    LeaseSettings {
        namespace: "fixture".to_owned(),
        name: "anchor".to_owned(),
        field_manager: "rs3-fixture".to_owned(),
    }
}

fn guard(api: FakeLeaseApi, holder: &str) -> LeaseGuard<FakeLeaseApi> {
    LeaseGuard::new(api, settings(), holder.to_owned(), Duration::from_secs(30)).expect("guard")
}

async fn fixture() -> (FakeApi, LeaseGuard<FakeLeaseApi>) {
    let lease = FakeLeaseApi::default();
    let guard = guard(lease.clone(), "writer-a");
    guard
        .acquire_at(Timestamp::now(), Duration::ZERO)
        .await
        .expect("acquire");
    lease
        .lease
        .lock()
        .await
        .as_mut()
        .expect("lease")
        .metadata
        .uid = Some("lease-uid".to_owned());
    let secret = Secret {
        metadata: ObjectMeta {
            name: Some("journal".to_owned()),
            uid: Some("secret-uid".to_owned()),
            resource_version: Some("1".to_owned()),
            annotations: Some(BTreeMap::from([
                (OWNER.to_owned(), "v1".to_owned()),
                ("fixture/keep".to_owned(), "kept".to_owned()),
            ])),
            labels: Some(BTreeMap::from([(
                "fixture/label".to_owned(),
                "kept".to_owned(),
            )])),
            ..Default::default()
        },
        type_: Some("Opaque".to_owned()),
        ..Default::default()
    };
    (
        FakeApi {
            lease,
            secret: Arc::new(Mutex::new(Some(secret))),
            writes: Arc::default(),
            fault: Arc::default(),
            blocked: Arc::default(),
        },
        guard,
    )
}

async fn claim(api: &FakeApi, guard: &LeaseGuard<FakeLeaseApi>) -> Journal<FakeApi> {
    Journal::claim(
        api.clone(),
        settings(),
        "journal".to_owned(),
        guard.writer_fence().expect("fence"),
    )
    .await
    .expect("journal claim")
}

#[tokio::test]
async fn journal_handoff_preserves_state_and_unrelated_metadata() {
    let (api, first) = fixture().await;
    let mut journal = claim(&api, &first).await;
    assert_eq!(journal.state().expect("state"), None);
    journal
        .save(b"prepared exact bytes", None)
        .await
        .expect("save");
    first.release_at(Timestamp::now()).await.expect("release");
    let second = guard(api.lease.clone(), "writer-b");
    second
        .acquire_at(Timestamp::now(), Duration::ZERO)
        .await
        .expect("new owner");
    let mut successor = claim(&api, &second).await;
    assert_eq!(
        successor.state().expect("state"),
        Some(b"prepared exact bytes".as_slice())
    );
    let writes = api.writes.load(Ordering::SeqCst);
    assert_eq!(
        journal.save(b"stale", None).await,
        Err(BootstrapJournalError::OwnershipLost)
    );
    assert_eq!(api.writes.load(Ordering::SeqCst), writes);
    successor.save(b"complete", None).await.expect("complete");
    let stored = api.secret.lock().await.clone().expect("stored");
    assert_eq!(annotation(&stored, "fixture/keep"), Some("kept"));
    assert_eq!(
        stored.metadata.labels.as_ref().expect("labels")["fixture/label"],
        "kept"
    );
    assert_eq!(annotation(&stored, EPOCH), Some("2"));
}

#[tokio::test]
async fn journal_revision_conflict_poison_prevents_blind_retry() {
    let (api, guard) = fixture().await;
    let mut first = claim(&api, &guard).await;
    let mut second = claim(&api, &guard).await;
    second
        .save(b"newer progress", None)
        .await
        .expect("save newer");
    assert_eq!(
        first.save(b"older progress", None).await,
        Err(BootstrapJournalError::Conflict)
    );
    let writes = api.writes.load(Ordering::SeqCst);
    assert_eq!(
        first.save(b"retry", None).await,
        Err(BootstrapJournalError::OwnershipLost)
    );
    assert_eq!(first.state(), Err(BootstrapJournalError::OwnershipLost));
    assert_eq!(api.writes.load(Ordering::SeqCst), writes);
    assert_eq!(
        second.state().expect("state"),
        Some(b"newer progress".as_slice())
    );
}

#[tokio::test]
async fn journal_reconciles_only_an_identical_accepted_update() {
    for accepted in [false, true] {
        let (api, guard) = fixture().await;
        let mut journal = claim(&api, &guard).await;
        *api.fault.lock().await = if accepted {
            UpdateFault::After
        } else {
            UpdateFault::Before
        };
        let result = journal.save(b"exact planned bytes", None).await;
        assert_eq!(result.is_ok(), accepted);
        if accepted {
            assert_eq!(
                journal.state().expect("state"),
                Some(b"exact planned bytes".as_slice())
            );
        } else {
            assert_eq!(journal.state(), Err(BootstrapJournalError::OwnershipLost));
            assert_eq!(
                claim(&api, &guard).await.state().expect("fresh state"),
                None
            );
        }
    }
}

#[tokio::test]
async fn evidence_projection_commits_and_reconciles_atomically_with_state() {
    for fault in [UpdateFault::None, UpdateFault::Before, UpdateFault::After] {
        let (api, guard) = fixture().await;
        let mut journal = claim(&api, &guard).await;
        journal
            .save(b"old state", Some(b"old evidence"))
            .await
            .expect("initial revision");
        *api.fault.lock().await = fault;
        let result = journal.save(b"new state", Some(b"new evidence")).await;
        let accepted = !matches!(fault, UpdateFault::Before);
        assert_eq!(result.is_ok(), accepted);
        let secret = api.secret.lock().await.clone().expect("secret");
        let data = secret.data.expect("data");
        assert_eq!(
            data[STATE].0,
            if accepted { b"new state" } else { b"old state" }
        );
        assert_eq!(
            data[EVIDENCE].0,
            if accepted {
                b"new evidence"
            } else {
                b"old evidence"
            }
        );
    }
    let (api, guard) = fixture().await;
    let mut journal = claim(&api, &guard).await;
    journal
        .save(b"qualified", Some(b"evidence"))
        .await
        .expect("qualified");
    journal
        .save(b"reserved refresh", None)
        .await
        .expect("reserve");
    assert!(
        !api.secret
            .lock()
            .await
            .as_ref()
            .expect("secret")
            .data
            .as_ref()
            .expect("data")
            .contains_key(EVIDENCE)
    );
    assert_eq!(
        journal.save(b"state", Some(&[])).await,
        Err(BootstrapJournalError::InvalidState)
    );
    assert_eq!(
        journal
            .save(&vec![1; MAX_BOOTSTRAP_JOURNAL_BYTES], Some(b"x"))
            .await,
        Err(BootstrapJournalError::BudgetExceeded)
    );
}

#[tokio::test]
async fn journal_cancellation_discards_the_cached_revision() {
    let (api, guard) = fixture().await;
    let mut journal = claim(&api, &guard).await;
    *api.fault.lock().await = UpdateFault::BlockAfter;
    {
        let save = journal.save(b"persisted before cancellation", None);
        tokio::pin!(save);
        tokio::select! {
            result = &mut save => panic!("save returned before fixture unblock: {result:?}"),
            () = api.blocked.notified() => {}
        }
    }
    assert_eq!(journal.state(), Err(BootstrapJournalError::OwnershipLost));
    let resumed = claim(&api, &guard).await;
    assert_eq!(
        resumed.state().expect("state"),
        Some(b"persisted before cancellation".as_slice())
    );
}

#[tokio::test]
async fn journal_refuses_missing_unowned_malformed_and_oversized_secrets() {
    for case in 0..7 {
        let (api, guard) = fixture().await;
        {
            let mut current = api.secret.lock().await;
            if case == 0 {
                *current = None;
            } else {
                let secret = current.as_mut().expect("secret");
                match case {
                    1 => {
                        secret.metadata.annotations = None;
                    }
                    2 => {
                        secret.data = Some(BTreeMap::from([(
                            "user-key".to_owned(),
                            ByteString(vec![1]),
                        )]));
                    }
                    3 => {
                        secret.immutable = Some(true);
                    }
                    4 => {
                        secret.data = Some(BTreeMap::from([(
                            STATE.to_owned(),
                            ByteString(vec![1; MAX_BOOTSTRAP_JOURNAL_BYTES + 1]),
                        )]));
                    }
                    5 => {
                        secret.metadata.uid = None;
                    }
                    6 => {
                        secret
                            .metadata
                            .annotations
                            .as_mut()
                            .expect("annotations")
                            .insert(EPOCH.to_owned(), "2".to_owned());
                    }
                    _ => unreachable!(),
                }
            }
        }
        assert!(
            Journal::claim(
                api.clone(),
                settings(),
                "journal".to_owned(),
                guard.writer_fence().expect("fence")
            )
            .await
            .is_err()
        );
        assert_eq!(api.writes.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn journal_rejects_recreated_lease_or_secret_and_bounds_new_writes() {
    let (api, guard) = fixture().await;
    let mut journal = claim(&api, &guard).await;
    let before = api.writes.load(Ordering::SeqCst);
    assert_eq!(
        journal
            .save(&vec![1; MAX_BOOTSTRAP_JOURNAL_BYTES + 1], None)
            .await,
        Err(BootstrapJournalError::BudgetExceeded)
    );
    assert_eq!(
        journal.save(&[], None).await,
        Err(BootstrapJournalError::InvalidState)
    );
    assert_eq!(api.writes.load(Ordering::SeqCst), before);
    api.secret
        .lock()
        .await
        .as_mut()
        .expect("secret")
        .metadata
        .uid = Some("replacement".to_owned());
    assert_eq!(
        journal.save(b"unsafe", None).await,
        Err(BootstrapJournalError::Conflict)
    );

    let (api, guard) = fixture().await;
    let mut journal = claim(&api, &guard).await;
    api.lease
        .lease
        .lock()
        .await
        .as_mut()
        .expect("lease")
        .metadata
        .uid = Some("replacement".to_owned());
    assert_eq!(
        journal.save(b"unsafe", None).await,
        Err(BootstrapJournalError::OwnershipLost)
    );
    assert!(
        Journal::claim(
            api,
            settings(),
            "journal".to_owned(),
            guard.writer_fence().expect("fence")
        )
        .await
        .is_err()
    );
}

/// Run only in the disposable namespace supplied by the integration fixture.
#[tokio::test]
#[ignore = "requires an explicitly supplied disposable Kubernetes namespace and kubeconfig"]
async fn live_bootstrap_journal_claim_save_conflict_and_handoff() {
    // The server selects this provider at startup. This standalone fixture has
    // to do the same when dependency features enable both TLS providers.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let namespace = std::env::var("RS3_TEST_BOOTSTRAP_NAMESPACE").expect("fixture namespace");
    assert!(
        std::env::var_os("KUBECONFIG").is_some(),
        "explicit fixture kubeconfig required"
    );
    let client = Client::try_default().await.expect("fixture client");
    let secrets: Api<Secret> = Api::namespaced(client, &namespace);
    let anchor = LeaseSettings {
        namespace,
        name: "bootstrap-anchor".to_owned(),
        field_manager: "rs3-journal-fixture".to_owned(),
    };
    let guard = crate::KubernetesLeaseGuard::new(
        anchor.clone(),
        "fixture-a".to_owned(),
        Duration::from_secs(30),
    )
    .expect("guard");
    guard.acquire().await.expect("acquire");
    let fence = guard.writer_fence().expect("fence");
    assert!(matches!(
        KubernetesBootstrapJournal::claim(anchor.clone(), "missing".to_owned(), fence.clone())
            .await,
        Err(BootstrapJournalError::Missing)
    ));
    assert!(
        secrets
            .get_opt("missing")
            .await
            .expect("absence check")
            .is_none()
    );

    let declared = Secret {
        metadata: ObjectMeta {
            name: Some("journal".to_owned()),
            annotations: Some(BTreeMap::from([
                (OWNER.to_owned(), "v1".to_owned()),
                ("fixture/keep".to_owned(), "kept".to_owned()),
            ])),
            ..Default::default()
        },
        type_: Some("Opaque".to_owned()),
        ..Default::default()
    };
    secrets
        .create(&PostParams::default(), &declared)
        .await
        .expect("declare fixture Secret");
    let mut first =
        KubernetesBootstrapJournal::claim(anchor.clone(), "journal".to_owned(), fence.clone())
            .await
            .expect("claim");
    assert_eq!(first.state().expect("state"), None);
    first.save(b"prepared bytes", None).await.expect("save");
    let mut second = KubernetesBootstrapJournal::claim(anchor.clone(), "journal".to_owned(), fence)
        .await
        .expect("second handle");
    assert_eq!(
        second.state().expect("state"),
        Some(b"prepared bytes".as_slice())
    );
    second
        .save(b"new progress", None)
        .await
        .expect("second save");
    assert_eq!(
        first.save(b"stale", None).await,
        Err(BootstrapJournalError::Conflict)
    );
    assert_eq!(first.state(), Err(BootstrapJournalError::OwnershipLost));
    guard.release().await.expect("release");

    let successor = crate::KubernetesLeaseGuard::new(
        anchor.clone(),
        "fixture-b".to_owned(),
        Duration::from_secs(30),
    )
    .expect("successor guard");
    successor.acquire().await.expect("take over");
    let fence = successor.writer_fence().expect("new fence");
    let mut resumed =
        KubernetesBootstrapJournal::claim(anchor.clone(), "journal".to_owned(), fence.clone())
            .await
            .expect("resumed journal");
    assert_eq!(
        resumed.state().expect("state"),
        Some(b"new progress".as_slice())
    );
    resumed
        .save(b"complete", None)
        .await
        .expect("save complete");
    let stored = secrets.get("journal").await.expect("stored Secret");
    assert_eq!(annotation(&stored, "fixture/keep"), Some("kept"));
    assert_eq!(annotation(&stored, EPOCH), Some("2"));

    secrets
        .delete("journal", &kube::api::DeleteParams::default())
        .await
        .expect("delete owned fixture Secret");
    let mut replacement = stored;
    replacement.metadata.uid = None;
    replacement.metadata.resource_version = None;
    replacement.metadata.managed_fields = None;
    replacement.metadata.creation_timestamp = None;
    secrets
        .create(&PostParams::default(), &replacement)
        .await
        .expect("recreate fixture resource");
    assert!(matches!(
        KubernetesBootstrapJournal::claim(anchor, "journal".to_owned(), fence).await,
        Err(BootstrapJournalError::InvalidState)
    ));
    successor.release().await.expect("release successor");
}
