//! Native write postconditions isolated from history publication and page loading.
use super::*;

#[derive(Clone, Copy, Debug)]
enum DeadlineFault {
    None,
    Missing,
    Short(i64),
}

#[derive(Clone)]
struct DeadlineStore {
    inner: MemoryBlobStore,
    fault: DeadlineFault,
    put_policies: Arc<Mutex<Vec<Option<RetentionPolicy>>>>,
}

#[async_trait::async_trait]
impl BlobStore for DeadlineStore {
    async fn put(
        &self,
        id: &BackendObjectId,
        body: Bytes,
        options: PutOptions,
    ) -> rs3_storage::Result<BlobMetadata> {
        self.put_policies
            .lock()
            .expect("put policy probe")
            .push(options.retention);
        let mut metadata = self.inner.put(id, body, options).await?;
        // The writer must return the exact HEAD observation, not this optimistic
        // PUT response, when establishing its private protection coverage fact.
        metadata.retain_until_ms = Some(i64::MAX);
        Ok(metadata)
    }

    async fn get_range(
        &self,
        id: &BackendObjectId,
        range: ByteRange,
    ) -> rs3_storage::Result<Bytes> {
        self.inner.get_range(id, range).await
    }

    async fn get_range_at(
        &self,
        id: &BackendObjectId,
        version: Option<&BackendVersionId>,
        range: ByteRange,
    ) -> rs3_storage::Result<Bytes> {
        self.inner.get_range_at(id, version, range).await
    }

    async fn open_range_at(
        &self,
        id: &BackendObjectId,
        version: Option<&BackendVersionId>,
        range: ByteRange,
    ) -> rs3_storage::Result<Box<dyn BlobRead>> {
        self.inner.open_range_at(id, version, range).await
    }

    async fn open_bounded_full_at(
        &self,
        id: &BackendObjectId,
        version: Option<&BackendVersionId>,
        max_bytes: u64,
    ) -> rs3_storage::Result<Box<dyn BlobRead>> {
        self.inner
            .open_bounded_full_at(id, version, max_bytes)
            .await
    }

    async fn head(&self, id: &BackendObjectId) -> rs3_storage::Result<BlobMetadata> {
        self.inner.head(id).await
    }

    async fn head_at(
        &self,
        id: &BackendObjectId,
        version: Option<&BackendVersionId>,
    ) -> rs3_storage::Result<BlobMetadata> {
        let mut metadata = self.inner.head_at(id, version).await?;
        // Only falsify the successor's post-write observation, not its parent.
        if !self
            .put_policies
            .lock()
            .expect("put policy probe")
            .is_empty()
        {
            match self.fault {
                DeadlineFault::None => {}
                DeadlineFault::Missing => metadata.retain_until_ms = None,
                DeadlineFault::Short(deadline) => metadata.retain_until_ms = Some(deadline - 1),
            }
        }
        Ok(metadata)
    }

    async fn list_prefix(&self, prefix: &str) -> rs3_storage::Result<Vec<BlobMetadata>> {
        self.inner.list_prefix(prefix).await
    }

    async fn delete(&self, id: &BackendObjectId) -> rs3_storage::Result<()> {
        self.inner.delete(id).await
    }

    async fn extend_retention(
        &self,
        id: &BackendObjectId,
        policy: RetentionPolicy,
    ) -> rs3_storage::Result<()> {
        self.inner.extend_retention(id, policy).await
    }

    async fn set_legal_hold(
        &self,
        id: &BackendObjectId,
        hold: LegalHoldStatus,
    ) -> rs3_storage::Result<()> {
        self.inner.set_legal_hold(id, hold).await
    }

    async fn flush_caches(&self) -> rs3_storage::Result<()> {
        self.inner.flush_caches().await
    }
}

async fn fixture(fault: DeadlineFault) -> (V3CommitStore<DeadlineStore>, V3MemoryAnchor) {
    let inner = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let options = V3CommitStoreOptions::for_profile(
        V3ProviderProfile::RetainedVersionObjectLock,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    )
    .with_retention(Some(RetentionPolicy::new(RetentionMode::Compliance, 1)));
    let setup = V3CommitStore::new(inner.clone(), keyring.clone(), options.clone());
    let anchor = V3MemoryAnchor::new();
    must_v3(setup.write_genesis_snapshot(&anchor).await);
    inner.reset_operation_counts().expect("reset counts");
    let store = DeadlineStore {
        inner,
        fault,
        put_policies: Arc::new(Mutex::new(Vec::new())),
    };
    (V3CommitStore::new(store, keyring, options), anchor)
}

fn required_floor() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("time fits")
        + 32 * 86_400_000
}

async fn native_snapshot(
    repository: &V3CommitStore<DeadlineStore>,
    anchor: &V3MemoryAnchor,
    floor: i64,
    hold: Option<LegalHoldStatus>,
) -> super::super::V3Result<super::super::V3StoredCommit> {
    let options = repository.options();
    let context =
        repository_context_from_refs(&options.repository_id, &options.keyring_envelope_ref)
            .expect("repository context");
    let root = super::super::V3IndexRoot::new(
        Sequence::ZERO,
        0,
        options.format_ref.clone(),
        options.keyring_envelope_ref.clone(),
        Vec::new(),
    )?;
    repository
        .write_child_commit_with(anchor, |key| {
            let sealed = super::super::seal_v3_index_root(
                repository.keyring(),
                &context,
                &key.object_id,
                0,
                &root,
            )?;
            let logical = RetentionPolicy::new(RetentionMode::Governance, 1);
            let write = V3CommitWrite::snapshot(vec![V3CommitSection::new(
                V3SectionType::IndexRoot,
                V3_SECTION_FLAG_MUST_UNDERSTAND,
                sealed.into_bytes(),
            )])
            .with_retention(Some(logical))
            .with_legal_hold(hold)
            .with_required_retain_until_ms(Some(floor));
            assert_eq!(
                write.retention,
                Some(logical),
                "physical floor must not rewrite requested logical days or mode"
            );
            assert_eq!(write.required_retain_until_ms, Some(floor));
            Ok(write)
        })
        .await
}

#[tokio::test]
async fn native_recovery_physical_floor_exceeds_logical_days_and_returns_verified_exact_observation()
 {
    let (repository, anchor) = fixture(DeadlineFault::None).await;
    let floor = required_floor();
    let stored = must_v3(native_snapshot(&repository, &anchor, floor, None).await);
    let exact = repository
        .store()
        .inner
        .head_at(&stored.commit_key.object_id, stored.version_id.as_ref())
        .await
        .expect("exact HEAD");
    assert!(
        exact
            .retain_until_ms
            .is_some_and(|deadline| deadline >= floor)
    );
    assert_eq!(stored.verified_retain_until_ms, exact.retain_until_ms);
    assert_ne!(
        stored.verified_retain_until_ms,
        Some(i64::MAX),
        "do not trust the optimistic PUT response"
    );
    let physical = {
        let policies = repository
            .store()
            .put_policies
            .lock()
            .expect("put policies");
        assert_eq!(policies.len(), 1);
        policies[0].expect("physical policy")
    };
    assert_eq!(
        physical.mode,
        RetentionMode::Compliance,
        "existing stronger repository mode survives"
    );
    assert!(physical.retain_days >= 32);
    assert_eq!(exact.retention, Some(physical));
    assert_eq!(must_v3(anchor.read_v3().await), Some(stored.anchor_state));
}

#[tokio::test]
async fn native_recovery_missing_or_short_postwrite_deadline_refuses_anchor_advance() {
    for missing in [true, false] {
        let floor = required_floor();
        let fault = if missing {
            DeadlineFault::Missing
        } else {
            DeadlineFault::Short(floor)
        };
        let (repository, anchor) = fixture(fault).await;
        let before = must_v3(anchor.read_v3().await);
        assert_eq!(
            native_snapshot(&repository, &anchor, floor, None).await,
            Err(V3FormatError::ProviderProfileFailed)
        );
        assert_eq!(must_v3(anchor.read_v3().await), before);
        assert_eq!(
            repository
                .store()
                .put_policies
                .lock()
                .expect("put policies")
                .len(),
            1
        );
        let counts = repository.store().inner.operation_counts().expect("counts");
        assert_eq!(counts.put, 1, "failure occurs after the new physical write");
        assert_eq!(
            counts.delete, 0,
            "retained failed candidate remains an orphan for normal maintenance"
        );
    }
}

#[tokio::test]
async fn native_recovery_physical_floor_does_not_bypass_unsupported_logical_hold() {
    let (repository, anchor) = fixture(DeadlineFault::None).await;
    let before = must_v3(anchor.read_v3().await);
    assert_eq!(
        native_snapshot(
            &repository,
            &anchor,
            required_floor(),
            Some(LegalHoldStatus::On)
        )
        .await,
        Err(V3FormatError::ProviderProfileFailed)
    );
    assert_eq!(must_v3(anchor.read_v3().await), before);
    assert!(
        repository
            .store()
            .put_policies
            .lock()
            .expect("put policies")
            .is_empty()
    );
}
