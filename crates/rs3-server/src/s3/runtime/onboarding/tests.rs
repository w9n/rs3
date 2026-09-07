use super::*;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Default)]
pub(super) struct MemoryJournal {
    pub(super) bytes: Option<Vec<u8>>,
    pub(super) saves: usize,
    pub(super) fail: Option<(usize, bool)>,
    hang: bool,
}

#[async_trait::async_trait]
impl Journal for MemoryJournal {
    fn state(&self) -> Result<Option<&[u8]>, S3BoundaryError> {
        Ok(self.bytes.as_deref())
    }
    async fn save(&mut self, bytes: &[u8], evidence: Option<&str>) -> Result<(), S3BoundaryError> {
        let record: Record = serde_json::from_slice(bytes).expect("onboarding state");
        assert_eq!(
            record.evidence.as_deref(),
            evidence,
            "projected evidence must match the authoritative revision"
        );
        self.saves += 1;
        if self.fail == Some((self.saves, false)) {
            return Err(invalid());
        }
        self.bytes = Some(bytes.to_vec());
        if self.hang {
            std::future::pending::<()>().await;
        }
        if self.fail == Some((self.saves, true)) {
            return Err(invalid());
        }
        Ok(())
    }
}

pub(super) struct Guard(pub(super) AtomicBool);
impl Default for Guard {
    fn default() -> Self {
        Self(AtomicBool::new(true))
    }
}
#[async_trait::async_trait]
impl V2MaintenanceGuard for Guard {
    async fn verify_v2_maintenance(
        &self,
        _: Option<&V2AnchorState>,
    ) -> rs3_repository::v2::V2Result<()> {
        if self.0.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(rs3_repository::v2::V2FormatError::MaintenanceAccessRequired)
        }
    }
}

struct FixtureProbe<'a> {
    prefixes: Mutex<Vec<String>>,
    expected: &'static str,
    fail: AtomicBool,
    ready: bool,
    lose_guard: Option<&'a Guard>,
}
impl Default for FixtureProbe<'_> {
    fn default() -> Self {
        Self {
            prefixes: Mutex::new(Vec::new()),
            expected: "matching image and policy",
            fail: AtomicBool::new(false),
            ready: true,
            lose_guard: None,
        }
    }
}
#[async_trait::async_trait]
impl Probe for FixtureProbe<'_> {
    async fn observe(&self, _root: String, attempts: u8) -> V2ProbeObservation {
        probe_observation::unavailable(attempts, "fixture-unobserved")
    }
    fn accepts(&self, evidence: &str) -> bool {
        evidence == self.expected
    }
    fn ready(&self) -> Result<(), S3BoundaryError> {
        if self.ready { Ok(()) } else { Err(invalid()) }
    }
    async fn run(&self, prefix: String) -> Result<String, S3BoundaryError> {
        self.prefixes.lock().expect("prefixes").push(prefix);
        if let Some(guard) = self.lose_guard {
            guard.0.store(false, Ordering::SeqCst);
        }
        if self.fail.load(Ordering::SeqCst) {
            Err(invalid())
        } else {
            Ok(self.expected.to_owned())
        }
    }
}

fn open(journal: &mut MemoryJournal) -> OnboardingJournal<'_, MemoryJournal> {
    OnboardingJournal::open(journal, "context".to_owned()).expect("open")
}

#[tokio::test]
async fn matching_evidence_and_bootstrap_progress_survive_reopen_without_new_probes() {
    let mut backing = MemoryJournal::default();
    let probe = FixtureProbe::default();
    let guard = Guard::default();
    let root = {
        let mut journal = open(&mut backing);
        journal
            .qualify(&probe, &guard, None)
            .await
            .expect("qualify");
        journal
            .save(b"exact bootstrap intent", None)
            .await
            .expect("bootstrap save");
        journal.record.probe_root.clone()
    };
    let saves = backing.saves;
    let mut journal = open(&mut backing);
    journal.qualify(&probe, &guard, None).await.expect("reuse");
    assert_eq!(
        journal.state().expect("state"),
        Some(b"exact bootstrap intent".as_slice())
    );
    assert_eq!(journal.record.probe_root, root);
    assert_eq!(journal.record.attempts, 1);
    assert_eq!(probe.prefixes.lock().expect("prefixes").len(), 1);
    assert_eq!(backing.saves, saves);
}

#[tokio::test]
async fn reservations_and_evidence_reconcile_each_before_and_after_save_failure() {
    for at in 1..=2 {
        for after in [false, true] {
            let mut backing = MemoryJournal {
                fail: Some((at, after)),
                ..Default::default()
            };
            let probe = FixtureProbe::default();
            let guard = Guard::default();
            {
                let mut journal = open(&mut backing);
                assert!(journal.qualify(&probe, &guard, None).await.is_err());
                assert!(journal.state().is_err(), "failed save poisons wrapper");
                assert!(journal.qualify(&probe, &guard, None).await.is_err());
            }
            backing.fail = None;
            let mut journal = open(&mut backing);
            journal.qualify(&probe, &guard, None).await.expect("resume");
            let prefixes = probe.prefixes.lock().expect("prefixes");
            let expected_runs = if at == 2 && !after { 2 } else { 1 };
            assert_eq!(prefixes.len(), expected_runs, "failure {at}/{after}");
            assert!(
                prefixes
                    .iter()
                    .all(|prefix| prefix.starts_with(&journal.record.probe_root))
            );
            assert_eq!(
                prefixes
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len(),
                prefixes.len()
            );
            assert!(journal.record.attempts <= 2);
        }
    }
}

#[tokio::test]
async fn repeated_ambiguous_runs_exhaust_one_durable_budget_and_external_evidence_can_resume() {
    let mut backing = MemoryJournal::default();
    let probe = FixtureProbe {
        fail: AtomicBool::new(true),
        ..Default::default()
    };
    let guard = Guard::default();
    for _ in 0..6 {
        assert!(
            open(&mut backing)
                .qualify(&probe, &guard, None)
                .await
                .is_err()
        );
    }
    let mut journal = open(&mut backing);
    assert_eq!(journal.record.attempts, MAX_PROBE_RUNS);
    let before = serde_json::to_vec(&journal.record).expect("record");
    assert!(
        journal
            .qualify(&probe, &guard, Some("wrong evidence".to_owned()))
            .await
            .is_err()
    );
    assert_eq!(serde_json::to_vec(&journal.record).expect("record"), before);
    journal
        .qualify(&probe, &guard, Some(probe.expected.to_owned()))
        .await
        .expect("external recovery of exhausted qualification");
    assert_eq!(journal.record.attempts, MAX_PROBE_RUNS);
    assert_eq!(probe.prefixes.lock().expect("prefixes").len(), 3);
}

#[tokio::test]
async fn changed_implementation_requalifies_without_replacing_bootstrap_or_resetting_budget() {
    let mut backing = MemoryJournal::default();
    let first = FixtureProbe::default();
    let guard = Guard::default();
    {
        let mut journal = open(&mut backing);
        journal
            .qualify(&first, &guard, None)
            .await
            .expect("first qualification");
        journal
            .save(b"unfinished exact genesis", None)
            .await
            .expect("bootstrap");
    }
    let second = FixtureProbe {
        expected: "new implementation",
        ..Default::default()
    };
    let mut journal = open(&mut backing);
    journal
        .qualify(&second, &guard, None)
        .await
        .expect("requalify");
    assert_eq!(journal.record.attempts, 2);
    assert_eq!(
        journal.state().expect("state"),
        Some(b"unfinished exact genesis".as_slice())
    );
    assert!(second.prefixes.lock().expect("prefixes")[0].ends_with("/2"));
    assert!(OnboardingJournal::open(&mut backing, "other context".to_owned()).is_err());
}

#[tokio::test]
async fn guard_loss_after_probe_cannot_publish_evidence_and_lost_reservation_stays_consumed() {
    let mut backing = MemoryJournal::default();
    let guard = Guard::default();
    let probe = FixtureProbe {
        lose_guard: Some(&guard),
        ..Default::default()
    };
    assert!(
        open(&mut backing)
            .qualify(&probe, &guard, None)
            .await
            .is_err()
    );
    let journal = open(&mut backing);
    assert_eq!(journal.record.attempts, 1);
    assert!(journal.record.evidence.is_none());
    let saves = backing.saves;
    assert!(
        open(&mut backing)
            .qualify(&probe, &guard, None)
            .await
            .is_err()
    );
    assert_eq!(backing.saves, saves);
    guard.0.store(true, Ordering::SeqCst);
    let next = FixtureProbe::default();
    open(&mut backing)
        .qualify(&next, &guard, None)
        .await
        .expect("new owner");
    assert!(next.prefixes.lock().expect("prefixes")[0].ends_with("/2"));
}

#[tokio::test]
async fn cancellation_poisons_wrapper_and_unavailable_review_does_not_consume_budget() {
    let mut backing = MemoryJournal {
        hang: true,
        ..Default::default()
    };
    let guard = Guard::default();
    let unavailable = FixtureProbe {
        ready: false,
        ..Default::default()
    };
    assert!(
        open(&mut backing)
            .qualify(&unavailable, &guard, None)
            .await
            .is_err()
    );
    assert_eq!(backing.saves, 0);
    let probe = FixtureProbe::default();
    {
        let mut journal = open(&mut backing);
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(1),
                journal.qualify(&probe, &guard, None)
            )
            .await
            .is_err()
        );
        assert!(journal.state().is_err());
        assert!(journal.qualify(&probe, &guard, None).await.is_err());
    }
    assert!(probe.prefixes.lock().expect("prefixes").is_empty());
    backing.hang = false;
    open(&mut backing)
        .qualify(&probe, &guard, None)
        .await
        .expect("resume consumed reservation");
    assert!(probe.prefixes.lock().expect("prefixes")[0].ends_with("/2"));
}

#[test]
fn malformed_context_scope_budget_and_retired_journals_are_rejected() {
    let mut backing = MemoryJournal::default();
    let record = serde_json::to_value(open(&mut backing).record).expect("record");
    for (field, value) in [
        ("schema", serde_json::json!("retired")),
        ("schema", serde_json::json!("rs3.onboarding.v1")),
        ("context", serde_json::json!("other")),
        ("probe_root", serde_json::json!("repository/real-data")),
        ("attempts", serde_json::json!(4)),
        ("unknown", serde_json::json!(true)),
    ] {
        let mut malformed = record.clone();
        malformed[field] = value;
        backing.bytes = Some(serde_json::to_vec(&malformed).expect("malformed"));
        assert!(
            OnboardingJournal::open(&mut backing, "context".to_owned()).is_err(),
            "{field}"
        );
    }
    backing.bytes = Some(vec![b' '; MAX_BOOTSTRAP_JOURNAL_BYTES + 1]);
    assert!(OnboardingJournal::open(&mut backing, "context".to_owned()).is_err());
}

#[tokio::test]
async fn qualification_wrapper_drives_the_real_bootstrap_engine_and_reuses_accepted_genesis() {
    let mut config = crate::s3::test_support::runtime_config(true);
    config.repository.retention = Some(RetentionPolicy::new(RetentionMode::Compliance, 1));
    let store = RuntimeStore::new(rs3_storage::MemoryBlobStore::new());
    let anchor = RuntimeV2Anchor::new(rs3_repository::v2::V2MemoryAnchor::new());
    let mut backing = MemoryJournal::default();
    let probe = FixtureProbe::default();
    let guard = Guard::default();
    let first = {
        let mut journal =
            OnboardingJournal::open(&mut backing, bootstrap::context(&config).expect("context"))
                .expect("journal");
        journal
            .qualify(&probe, &guard, None)
            .await
            .expect("qualify");
        bootstrap::initialize(&config, &store, &anchor, &guard, &mut journal)
            .await
            .expect("bootstrap")
    };
    assert!(first.initialized);
    let saves = backing.saves;
    let mut journal =
        OnboardingJournal::open(&mut backing, bootstrap::context(&config).expect("context"))
            .expect("reopen");
    journal.qualify(&probe, &guard, None).await.expect("reuse");
    let second = bootstrap::initialize(&config, &store, &anchor, &guard, &mut journal)
        .await
        .expect("verify accepted");
    assert_eq!(first.anchor, second.anchor);
    assert!(!second.initialized);
    assert_eq!(probe.prefixes.lock().expect("prefixes").len(), 1);
    assert_eq!(backing.saves, saves);
}

#[tokio::test]
async fn projected_readiness_requires_matching_evidence_and_completed_bootstrap() {
    use rs3_repository::v2::{
        V2ProviderCheckStatus, V2ProviderConformanceCheck, required_v2_provider_check_names,
    };
    let mut config = crate::s3::test_support::runtime_config(true);
    let store = build_store(&config.backend).await.expect("memory store");
    config.backend.endpoint = "https://fixture.invalid".to_owned();
    config.anchor = crate::AnchorConfig::KubernetesLease {
        namespace: "fixture".to_owned(),
        name: "fixture".to_owned(),
        field_manager: "fixture".to_owned(),
    };
    config.repository.retention = Some(RetentionPolicy::new(RetentionMode::Compliance, 30));
    let profile = V2ProviderProfile::RetainedVersionObjectLock;
    let report = V2ProviderConformanceReport {
        profile,
        checks: required_v2_provider_check_names(profile)
            .into_iter()
            .map(|name| V2ProviderConformanceCheck {
                name,
                status: V2ProviderCheckStatus::Passed,
                reason: None,
            })
            .collect(),
    };
    let evidence =
        encode_provider_conformance_evidence(&V2ProviderCheckConfig::from(&config), &report)
            .expect("fixture evidence");
    let mut backing = MemoryJournal::default();
    let guard = Guard::default();
    let anchor = RuntimeV2Anchor::new(rs3_repository::v2::V2MemoryAnchor::new());
    {
        let mut journal =
            OnboardingJournal::open(&mut backing, bootstrap::context(&config).expect("context"))
                .expect("journal");
        journal
            .qualify(
                &ProviderProbe {
                    config: &config,
                    store: &store,
                    governance_bypass_reviewed: false,
                },
                &guard,
                Some(evidence),
            )
            .await
            .expect("qualified");
    }
    assert!(
        !is_initialized(&config, backing.bytes.as_deref().expect("qualified state"))
            .expect("not initialized")
    );
    {
        let mut journal =
            OnboardingJournal::open(&mut backing, bootstrap::context(&config).expect("context"))
                .expect("journal");
        let mut report =
            bootstrap::initialize(&config, store.handle(), &anchor, &guard, &mut journal)
                .await
                .expect("initialize");
        assert!(
            !v2_bootstrap_journal_is_initialized(
                &config,
                &serde_json::to_vec(&journal.record).expect("journal bytes"),
            )
            .expect("initialized repository still needs payload verification")
        );
        round_trip::verify(
            &config,
            store.handle(),
            &anchor,
            &guard,
            &mut journal,
            &mut report,
        )
        .await
        .expect("restore fixture");
    }
    let bytes = backing.bytes.as_deref().expect("completed state");
    assert!(v2_bootstrap_journal_is_initialized(&config, bytes).expect("initialized"));
    let original: serde_json::Value = serde_json::from_slice(bytes).expect("record");
    for field in [
        "implementation_fingerprint",
        "target_fingerprint",
        "source_revision",
    ] {
        let mut record = original.clone();
        let mut report: serde_json::Value =
            serde_json::from_str(record["evidence"].as_str().expect("evidence")).expect("report");
        report[field] = serde_json::json!("mismatch");
        record["evidence"] = serde_json::json!(serde_json::to_string(&report).expect("report"));
        assert!(
            !is_initialized(&config, &serde_json::to_vec(&record).expect("record"))
                .expect("unqualified")
        );
    }
    let mut other = config.clone();
    other.backend.prefix = Some("another".to_owned());
    assert!(is_initialized(&other, bytes).is_err());
    assert!(is_initialized(&config, &vec![b' '; MAX_BOOTSTRAP_JOURNAL_BYTES + 1]).is_err());
}
