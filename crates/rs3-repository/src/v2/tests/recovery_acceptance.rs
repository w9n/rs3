//! Day-scale acceptance through real recovery, maintenance and decoded reads.
use super::*;
use crate::v2::RecoveryPolicy;
use rs3_storage::{
    FaultAction, FaultInjectingBlobStore, FaultMatcher, FaultOperationKind, FaultRule,
};

mod lifecycle;
mod safety;
mod scale;
mod store;
use store::{ControlledDeadlineStore, Mutation};

const DAY: i64 = 86_400_000;
type TestStore = FaultInjectingBlobStore<ControlledDeadlineStore>;

struct Fixture {
    store: TestStore,
    repository: Arc<V2Repository<TestStore>>,
    anchor: V2MemoryAnchor,
}

impl Fixture {
    async fn new(policy: RecoveryPolicy) -> Self {
        let now = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_millis(),
        )
        .expect("timestamp");
        let store = FaultInjectingBlobStore::new(ControlledDeadlineStore::new(now), vec![]);
        let retention = Some(RetentionPolicy::new(RetentionMode::Compliance, 1));
        let keyring_ref = sample_keyring_envelope_ref();
        let keyring_metadata = store
            .put(
                &keyring_ref.object_id,
                Bytes::from_static(b"encrypted-keyring-envelope"),
                PutOptions {
                    retention,
                    ..PutOptions::default()
                },
            )
            .await
            .expect("keyring root");
        let mut format_ref = sample_format_ref();
        let format_metadata = store
            .put(
                &format_ref.object_id,
                Bytes::from_static(b"encrypted-format-root"),
                PutOptions {
                    retention,
                    ..PutOptions::default()
                },
            )
            .await
            .expect("format root");
        format_ref.version_id = format_metadata.version_id;
        let root = V2KeyringEnvelopeRootRef {
            generation: 1,
            digest: hex::encode(keyring_ref.digest),
            object_id: keyring_ref.object_id.clone(),
            version_id: keyring_metadata.version_id,
        };
        let options = V2CommitStoreOptions::for_profile(
            V2ProviderProfile::RetainedVersionObjectLock,
            sample_repository_id(),
            keyring_ref,
            format_ref,
        )
        .with_maintenance_keyring_envelope_ref(root)
        .with_retention(retention)
        .with_recovery_policy(Some(policy));
        let repository = Arc::new(V2Repository::new(
            store.clone(),
            must_crypto(KeyRing::generate_random()),
            RepositoryOptions::default(),
            options,
        ));
        repository
            .commit_store()
            .set_publication_time_for_tests(now);
        let anchor = V2MemoryAnchor::new();
        must_repo(
            repository
                .write_genesis_snapshot_with_guard(
                    &anchor,
                    Some(&UnenforcedQuiescedMaintenanceGuard),
                )
                .await,
        );
        Self {
            store,
            repository,
            anchor,
        }
    }

    fn advance_to(&self, now: i64) {
        self.store.inner().advance_to(now);
        self.repository
            .commit_store()
            .set_publication_time_for_tests(now);
    }

    async fn put(&self, path: &str, body: &'static [u8]) -> V2AnchorState {
        must_repo(
            self.repository
                .put_committed_with_guard(
                    &self.anchor,
                    must_type(LogicalPath::new(path)),
                    Bytes::from_static(body),
                    RepositoryPutOptions::default(),
                    Some(&UnenforcedQuiescedMaintenanceGuard),
                )
                .await,
        );
        self.current().await
    }

    async fn current(&self) -> V2AnchorState {
        must_v2(self.anchor.read_v2().await).expect("accepted anchor")
    }

    async fn orphan(&self, sequence: u64, hold: Option<LegalHoldStatus>) -> BlobMetadata {
        let id = must_v2(generate_v2_commit_key(Sequence::new(sequence))).object_id;
        self.store
            .put(
                &id,
                Bytes::from_static(b"unanchored exact version"),
                PutOptions {
                    legal_hold: hold,
                    ..PutOptions::default()
                },
            )
            .await
            .expect("orphan")
    }

    async fn restart(&mut self, policy: RecoveryPolicy) {
        let options = self
            .repository
            .commit_store()
            .options()
            .clone()
            .with_recovery_policy(Some(policy));
        let keys = self.repository.commit_store().keyring().clone();
        let repository = Arc::new(V2Repository::new(
            self.store.clone(),
            keys,
            RepositoryOptions::default(),
            options,
        ));
        repository
            .commit_store()
            .set_publication_time_for_tests(self.store.inner().now());
        must_repo(repository.load_chain_from_anchor(&self.anchor).await);
        self.repository = repository;
    }

    async fn delete(&self, path: &str) {
        let coordinator = must_repo(V2CommitCoordinator::with_options(
            Arc::clone(&self.repository),
            self.anchor.clone(),
            CommitCoordinatorOptions::new(1, Duration::ZERO),
        ))
        .with_maintenance_guard(UnenforcedQuiescedMaintenanceGuard);
        must_repo(
            coordinator
                .delete_committed(must_type(LogicalPath::new(path)))
                .await,
        );
    }

    async fn expire(&self) -> bool {
        let lease = must_repo(self.repository.claim_commit_coordinator());
        let mutation = crate::v2::service::V2CoordinatedMutation::new(&lease, &self.anchor)
            .with_guard(Some(&UnenforcedQuiescedMaintenanceGuard));
        must_repo(
            self.repository
                .maybe_publish_recovery_expiry_checkpoint_coordinated(mutation)
                .await,
        )
        .is_some()
    }

    async fn restore(&self, selected: &V2AnchorState, path: &str, expected: &'static [u8]) {
        let before = self.current().await;
        let view = must_repo(
            self.repository
                .open_recovery_point(&self.anchor, selected.sequence)
                .await,
        );
        let object = must_repo(view.resolve_object(&must_type(LogicalPath::new(path))));
        let decoded = must_repo(view.get_resolved_range(&object, ByteRange::Full).await);
        assert_eq!(decoded, Bytes::from_static(expected));
        assert_eq!(
            self.current().await,
            before,
            "selected restore cannot move live authority"
        );
    }
}

fn apply_options(reclamation_enabled: bool) -> V2FullGcApplyOptions {
    V2FullGcApplyOptions {
        dry_run: V2FullGcDryRunOptions::default(),
        orphan_gc: V2OrphanGcOptions::new_for_test_rehearsal(Duration::ZERO),
        retained_provider_conformance_passed: true,
        reclamation_enabled,
    }
}
