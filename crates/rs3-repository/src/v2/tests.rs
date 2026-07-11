use super::{
    UnenforcedQuiescedMaintenanceGuard, V2_INDEX_COMPACTION_PAUSE_RUNS,
    V2_INDEX_COMPACTION_REQUEST_RUNS, V2AnchorState, V2CommitAnchor, V2CommitCoordinator,
    V2CommitSection, V2CommitStore, V2CommitStoreOptions, V2CommitWrite, V2FullGcApplyOptions,
    V2FullGcDryRunOptions, V2MaintenanceBudgets, V2MaintenanceGuard, V2MemoryAnchor,
    V2OrphanGcOptions, V2RecoveryBundle, V2ReplayLimits, V2Repository,
};
use super::{
    V2_RESTORE_BUNDLE_SCHEMA, V2_SECTION_FLAG_MUST_UNDERSTAND, V2Algorithms, V2CommitHeader,
    V2CommitKey, V2CommitKind, V2CommitParentRef, V2CommitSelfRef, V2ErrorClass, V2FormatError,
    V2FormatRef, V2FormatRoot, V2KeyringEnvelopeRef, V2KeyringEnvelopeRootRef,
    V2ProviderCheckStatus, V2ProviderConformanceOptions, V2ProviderProfile, V2SectionDescriptor,
    V2SectionType, V2UploadMode, body_digest_for_v2_sections, check_v2_provider_conformance,
    digest_v2_section, generate_v2_commit_key, parse_v2_commit_object,
};
use crate::{CommitCoordinatorOptions, RepositoryError, RepositoryOptions, RepositoryPutOptions};
use bytes::Bytes;
use rs3_crypto::{KeyMaterial, KeyRing, SecretBytes};
use rs3_storage::{BlobMetadata, BlobStore, ByteRange, MemoryBlobStore, PutOptions};
use rs3_types::{
    BackendObjectId, BackendVersionId, KeyDescriptor, KeyId, KeyPurpose, KeyStatus,
    LegalHoldStatus, LogicalPath, RepositoryId, RetentionMode, RetentionPolicy, Sequence,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Barrier, Notify};

fn must_v2<T>(result: super::V2Result<T>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{error}"),
    }
}

fn must_repo<T>(result: crate::Result<T>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{error}"),
    }
}

fn must_type<T>(result: rs3_types::Result<T>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{error}"),
    }
}

fn must_crypto<T>(result: std::result::Result<T, rs3_crypto::CryptoError>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{error}"),
    }
}

fn key_id(value: &str) -> KeyId {
    must_type(KeyId::new(value))
}

fn object_id(value: &str) -> BackendObjectId {
    must_type(BackendObjectId::new(value))
}

fn secret(byte: u8) -> SecretBytes {
    must_crypto(SecretBytes::new(vec![byte; SecretBytes::MIN_LEN]))
}

fn key_material(
    id: &str,
    purpose: KeyPurpose,
    status: KeyStatus,
    algorithm: &str,
    byte: u8,
) -> KeyMaterial {
    KeyMaterial::new(
        KeyDescriptor {
            id: key_id(id),
            purpose,
            algorithm: algorithm.to_owned(),
            status,
            created_at_ms: 0,
            not_before_ms: None,
            not_after_ms: None,
            public_key: None,
            external_kms_uri: None,
        },
        secret(byte),
    )
}

fn signing_keyring() -> KeyRing {
    must_crypto(KeyRing::new(vec![
        key_material(
            "namespace",
            KeyPurpose::Namespace,
            KeyStatus::Primary,
            "hmac-sha256",
            1,
        ),
        key_material(
            "signing",
            KeyPurpose::CheckpointSigning,
            KeyStatus::Primary,
            "ed25519",
            2,
        ),
    ]))
}

fn sample_commit_key() -> V2CommitKey {
    must_v2(V2CommitKey::from_parts(Sequence::new(7), [9_u8; 32]))
}

fn sample_sections() -> (Vec<V2SectionDescriptor>, Bytes, [u8; 32]) {
    let section_region = Bytes::from_static(b"snapshot-delta");
    let section_index = vec![V2SectionDescriptor {
        section_type: V2SectionType::IndexSnapshot,
        offset: 0,
        length: section_region.len() as u64,
        flags: super::commit::V2_SECTION_FLAG_MUST_UNDERSTAND,
        digest: digest_v2_section(&section_region),
    }];
    let digest = must_v2(body_digest_for_v2_sections(
        &section_index,
        section_region.as_ref(),
    ));
    (section_index, section_region, digest)
}

fn sample_header(upload_mode: V2UploadMode) -> (V2CommitKey, V2CommitHeader, Bytes) {
    let keyring = signing_keyring();
    let commit_key = sample_commit_key();
    let parent_key = must_v2(V2CommitKey::from_parts(Sequence::new(6), [8_u8; 32]));
    let (section_index, section_region, body_digest) = sample_sections();
    let header = V2CommitHeader {
        self_ref: V2CommitSelfRef {
            sequence: commit_key.sequence,
            commit_key: commit_key.object_id.clone(),
        },
        parent: Some(V2CommitParentRef {
            sequence: parent_key.sequence,
            commit_key: parent_key.object_id,
            body_digest: [7_u8; 32],
            version_id: Some(must_type(BackendVersionId::new("version-1"))),
        }),
        publish_time_ms: 1_765_000_000_000,
        kind: V2CommitKind::Root,
        algorithms: V2Algorithms::v02(),
        keyring_envelope_ref: V2KeyringEnvelopeRef {
            object_id: object_id("keyrings/00000000000000000001-deadbeef"),
            digest: [4_u8; 32],
        },
        section_index,
        body_digest,
        signature: [0_u8; 64],
        signing_key_id: key_id("signing"),
    };
    let header = must_v2(header.sign_with_keyring(&keyring, upload_mode));
    (commit_key, header, section_region)
}

fn sample_keyring_envelope_ref() -> V2KeyringEnvelopeRef {
    V2KeyringEnvelopeRef {
        object_id: object_id("keyrings/00000000000000000001-bootstrap"),
        digest: [6_u8; 32],
    }
}

fn sample_repository_id() -> RepositoryId {
    must_type(RepositoryId::new("rs3-v2-test-repository"))
}

fn sample_keyring_envelope_root_ref() -> V2KeyringEnvelopeRootRef {
    V2KeyringEnvelopeRootRef {
        generation: 1,
        digest: hex::encode([6_u8; 32]),
        object_id: object_id("keyrings/00000000000000000001-bootstrap"),
        version_id: Some(must_type(BackendVersionId::new("keyring-version-1"))),
    }
}

fn sample_format_ref() -> V2FormatRef {
    V2FormatRef {
        generation: 1,
        digest: hex::encode([7_u8; 32]),
        object_id: object_id(&format!("format/{:020}-{}", 1_u64, hex::encode([7_u8; 32]))),
        version_id: Some(must_type(BackendVersionId::new("format-version-1"))),
    }
}

#[test]
fn recovery_bundle_json_round_trips_shared_wire_shape() {
    let anchor = V2AnchorState {
        sequence: Sequence::new(7),
        commit_key: sample_commit_key().object_id,
        body_digest: [8_u8; 32],
        version_id: Some(must_type(BackendVersionId::new("commit-version-1"))),
        signing_key_id: key_id("signing"),
        format_ref: sample_format_ref(),
    };
    let mut bundle = V2RecoveryBundle::from_anchor(anchor, Sequence::new(7));
    bundle.repository_id = Some(must_type(RepositoryId::new("repo-a")));
    bundle.repository_salt_digest = Some([3_u8; 32]);
    bundle.exported_at_ms = 42;
    bundle.offline_signature = Some(vec![4_u8; 64]);

    let value = serde_json::to_value(&bundle).unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(value["schema"], V2_RESTORE_BUNDLE_SCHEMA);
    assert_eq!(value["repository"]["id"], "repo-a");
    assert_eq!(value["repository"]["salt_digest"], hex::encode([3_u8; 32]));
    assert_eq!(value["anchor"]["body_digest"], hex::encode([8_u8; 32]));
    assert!(value["offline_signature_payload_hex"].as_str().is_some());
    assert_eq!(value["offline_signature"], hex::encode([4_u8; 64]));

    let decoded: V2RecoveryBundle =
        serde_json::from_value(value).unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(decoded, bundle);
}

#[test]
fn recovery_bundle_json_accepts_root_repository_salt_digest() {
    let input = serde_json::json!({
        "schema": V2_RESTORE_BUNDLE_SCHEMA,
        "repository": {
            "id": "repo-a"
        },
        "repository_salt_digest": "03".repeat(32),
        "anchor": {
            "sequence": 7,
            "commit_key": sample_commit_key().object_id.as_str(),
            "body_digest": "08".repeat(32),
            "version_id": "commit-version-1",
            "signing_key_id": "signing",
            "format": {
                "generation": 1,
                "digest": "07".repeat(32),
                "object_id": "format/00000000000000000001/legacy",
                "version_id": "format-version-1"
            }
        },
        "weak_subjectivity_floor_sequence": 7,
        "format_digest": "07".repeat(32),
        "format_generation": 1,
        "exported_at_ms": 42,
        "offline_signature": null
    });

    let decoded: V2RecoveryBundle =
        serde_json::from_value(input).unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(decoded.repository_salt_digest, Some([3_u8; 32]));
}

struct FailOnceV2Anchor {
    inner: V2MemoryAnchor,
    remaining_failures: AtomicUsize,
}

impl FailOnceV2Anchor {
    fn new(inner: V2MemoryAnchor) -> Self {
        Self {
            inner,
            remaining_failures: AtomicUsize::new(1),
        }
    }
}

#[async_trait::async_trait]
impl V2CommitAnchor for FailOnceV2Anchor {
    async fn read_v2(&self) -> super::V2Result<Option<V2AnchorState>> {
        self.inner.read_v2().await
    }

    async fn compare_and_advance_v2(
        &self,
        expected: Option<&V2AnchorState>,
        next: V2AnchorState,
    ) -> super::V2Result<V2AnchorState> {
        if self
            .remaining_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(V2FormatError::AnchorAdvanceFailed);
        }
        self.inner.compare_and_advance_v2(expected, next).await
    }
}

struct RejectingMaintenanceGuard;

#[async_trait::async_trait]
impl V2MaintenanceGuard for RejectingMaintenanceGuard {
    async fn verify_v2_maintenance(
        &self,
        _base_anchor: Option<&V2AnchorState>,
    ) -> super::V2Result<()> {
        Err(V2FormatError::MaintenanceAccessRequired)
    }
}

struct FailsAfterMaintenanceGuard {
    remaining_successes: AtomicUsize,
}

impl FailsAfterMaintenanceGuard {
    fn new(remaining_successes: usize) -> Self {
        Self {
            remaining_successes: AtomicUsize::new(remaining_successes),
        }
    }
}

#[async_trait::async_trait]
impl V2MaintenanceGuard for FailsAfterMaintenanceGuard {
    async fn verify_v2_maintenance(
        &self,
        _base_anchor: Option<&V2AnchorState>,
    ) -> super::V2Result<()> {
        if self
            .remaining_successes
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            Ok(())
        } else {
            Err(V2FormatError::MaintenanceAccessRequired)
        }
    }
}

#[derive(Clone)]
struct BlockingV2Anchor {
    inner: V2MemoryAnchor,
    blocked: Arc<Notify>,
    release: Arc<Notify>,
}

impl BlockingV2Anchor {
    fn new(inner: V2MemoryAnchor) -> Self {
        Self {
            inner,
            blocked: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
        }
    }

    async fn wait_until_blocked(&self) {
        self.blocked.notified().await;
    }

    fn release(&self) {
        self.release.notify_one();
    }
}

#[async_trait::async_trait]
impl V2CommitAnchor for BlockingV2Anchor {
    async fn read_v2(&self) -> super::V2Result<Option<V2AnchorState>> {
        self.inner.read_v2().await
    }

    async fn compare_and_advance_v2(
        &self,
        expected: Option<&V2AnchorState>,
        next: V2AnchorState,
    ) -> super::V2Result<V2AnchorState> {
        self.blocked.notify_one();
        self.release.notified().await;
        self.inner.compare_and_advance_v2(expected, next).await
    }
}

#[derive(Clone)]
struct SlowCommitGetStore {
    inner: MemoryBlobStore,
    delay: Duration,
    full_commit_gets: Arc<AtomicUsize>,
    ranged_commit_gets: Arc<AtomicUsize>,
    in_flight_ranged_commit_gets: Arc<AtomicUsize>,
    max_in_flight_ranged_commit_gets: Arc<AtomicUsize>,
    corrupt_ranged_commit_gets_for: Arc<Mutex<Option<BackendObjectId>>>,
}

impl SlowCommitGetStore {
    fn new(inner: MemoryBlobStore, delay: Duration) -> Self {
        Self {
            inner,
            delay,
            full_commit_gets: Arc::new(AtomicUsize::new(0)),
            ranged_commit_gets: Arc::new(AtomicUsize::new(0)),
            in_flight_ranged_commit_gets: Arc::new(AtomicUsize::new(0)),
            max_in_flight_ranged_commit_gets: Arc::new(AtomicUsize::new(0)),
            corrupt_ranged_commit_gets_for: Arc::new(Mutex::new(None)),
        }
    }

    fn reset_operation_counts(&self) {
        self.inner
            .reset_operation_counts()
            .unwrap_or_else(|error| panic!("{error}"));
        self.full_commit_gets.store(0, Ordering::SeqCst);
        self.ranged_commit_gets.store(0, Ordering::SeqCst);
        self.in_flight_ranged_commit_gets.store(0, Ordering::SeqCst);
        self.max_in_flight_ranged_commit_gets
            .store(0, Ordering::SeqCst);
    }

    fn operation_counts(&self) -> rs3_storage::BlobOperationCounts {
        self.inner
            .operation_counts()
            .unwrap_or_else(|error| panic!("{error}"))
    }

    fn full_commit_get_count(&self) -> u64 {
        self.full_commit_gets.load(Ordering::SeqCst) as u64
    }

    fn ranged_commit_get_count(&self) -> u64 {
        self.ranged_commit_gets.load(Ordering::SeqCst) as u64
    }

    fn max_in_flight_ranged_commit_get_count(&self) -> u64 {
        self.max_in_flight_ranged_commit_gets.load(Ordering::SeqCst) as u64
    }

    fn corrupt_ranged_commit_gets_for(&self, object_id: BackendObjectId) {
        let mut guard = self
            .corrupt_ranged_commit_gets_for
            .lock()
            .expect("corruption target lock should not be poisoned");
        *guard = Some(object_id);
    }

    fn clear_corruption(&self) {
        let mut guard = self
            .corrupt_ranged_commit_gets_for
            .lock()
            .expect("corruption target lock should not be poisoned");
        *guard = None;
    }

    fn maybe_corrupt_commit_range(
        &self,
        object_id: &BackendObjectId,
        range: ByteRange,
        body: Bytes,
    ) -> Bytes {
        if matches!(range, ByteRange::Full) {
            return body;
        }
        let should_corrupt = self
            .corrupt_ranged_commit_gets_for
            .lock()
            .expect("corruption target lock should not be poisoned")
            .as_ref()
            == Some(object_id);
        if !should_corrupt || body.is_empty() {
            return body;
        }
        let mut corrupted = body.to_vec();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0x80;
        Bytes::from(corrupted)
    }

    async fn record_commit_get(&self, object_id: &BackendObjectId, range: ByteRange) {
        if object_id.as_str().starts_with("commits/") {
            match range {
                ByteRange::Full => {
                    self.full_commit_gets.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(self.delay).await;
                }
                ByteRange::Slice { .. } => {
                    self.ranged_commit_gets.fetch_add(1, Ordering::SeqCst);
                    let in_flight = self
                        .in_flight_ranged_commit_gets
                        .fetch_add(1, Ordering::SeqCst)
                        .saturating_add(1);
                    self.max_in_flight_ranged_commit_gets
                        .fetch_max(in_flight, Ordering::SeqCst);
                    tokio::time::sleep(self.delay).await;
                    self.in_flight_ranged_commit_gets
                        .fetch_sub(1, Ordering::SeqCst);
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl BlobStore for SlowCommitGetStore {
    async fn put(
        &self,
        object_id: &BackendObjectId,
        body: Bytes,
        options: PutOptions,
    ) -> rs3_storage::Result<BlobMetadata> {
        self.inner.put(object_id, body, options).await
    }

    async fn get_range(
        &self,
        object_id: &BackendObjectId,
        range: ByteRange,
    ) -> rs3_storage::Result<Bytes> {
        self.record_commit_get(object_id, range).await;
        let body = self.inner.get_range(object_id, range).await?;
        Ok(self.maybe_corrupt_commit_range(object_id, range, body))
    }

    async fn get_range_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        range: ByteRange,
    ) -> rs3_storage::Result<Bytes> {
        self.record_commit_get(object_id, range).await;
        let body = self
            .inner
            .get_range_at(object_id, version_id, range)
            .await?;
        Ok(self.maybe_corrupt_commit_range(object_id, range, body))
    }

    async fn head(&self, object_id: &BackendObjectId) -> rs3_storage::Result<BlobMetadata> {
        self.inner.head(object_id).await
    }

    async fn head_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
    ) -> rs3_storage::Result<BlobMetadata> {
        self.inner.head_at(object_id, version_id).await
    }

    async fn list_prefix(&self, prefix: &str) -> rs3_storage::Result<Vec<BlobMetadata>> {
        self.inner.list_prefix(prefix).await
    }

    async fn list_prefix_versions(&self, prefix: &str) -> rs3_storage::Result<Vec<BlobMetadata>> {
        self.inner.list_prefix_versions(prefix).await
    }

    async fn delete(&self, object_id: &BackendObjectId) -> rs3_storage::Result<()> {
        self.inner.delete(object_id).await
    }

    async fn delete_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
    ) -> rs3_storage::Result<()> {
        self.inner.delete_at(object_id, version_id).await
    }

    async fn extend_retention(
        &self,
        object_id: &BackendObjectId,
        policy: RetentionPolicy,
    ) -> rs3_storage::Result<()> {
        self.inner.extend_retention(object_id, policy).await
    }

    async fn extend_retention_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        policy: RetentionPolicy,
    ) -> rs3_storage::Result<()> {
        self.inner
            .extend_retention_at(object_id, version_id, policy)
            .await
    }

    async fn set_legal_hold(
        &self,
        object_id: &BackendObjectId,
        status: LegalHoldStatus,
    ) -> rs3_storage::Result<()> {
        self.inner.set_legal_hold(object_id, status).await
    }

    async fn set_legal_hold_at(
        &self,
        object_id: &BackendObjectId,
        version_id: Option<&BackendVersionId>,
        status: LegalHoldStatus,
    ) -> rs3_storage::Result<()> {
        self.inner
            .set_legal_hold_at(object_id, version_id, status)
            .await
    }

    async fn flush_caches(&self) -> rs3_storage::Result<()> {
        self.inner.flush_caches().await
    }
}

struct StaleOnAdvanceV2Anchor {
    inner: V2MemoryAnchor,
    remaining_stale_advances: AtomicUsize,
}

impl StaleOnAdvanceV2Anchor {
    fn new(inner: V2MemoryAnchor) -> Self {
        Self {
            inner,
            remaining_stale_advances: AtomicUsize::new(1),
        }
    }
}

#[async_trait::async_trait]
impl V2CommitAnchor for StaleOnAdvanceV2Anchor {
    async fn read_v2(&self) -> super::V2Result<Option<V2AnchorState>> {
        self.inner.read_v2().await
    }

    async fn compare_and_advance_v2(
        &self,
        expected: Option<&V2AnchorState>,
        next: V2AnchorState,
    ) -> super::V2Result<V2AnchorState> {
        if self
            .remaining_stale_advances
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            let mut competing = next.clone();
            competing.body_digest = [0x5a; 32];
            self.inner
                .compare_and_advance_v2(expected, competing)
                .await?;
        }
        self.inner.compare_and_advance_v2(expected, next).await
    }
}

fn sample_object(upload_mode: V2UploadMode) -> (V2CommitKey, V2CommitHeader, Bytes) {
    let (commit_key, header, section_region) = sample_header(upload_mode);
    let body = must_v2(header.encode_object(upload_mode, section_region.as_ref()));
    (commit_key, header, body)
}

#[test]
fn commit_key_round_trips_and_rejects_non_v2_shapes() {
    let key = sample_commit_key();
    assert_eq!(
        key.object_id.as_str().len(),
        "commits/v02/".len() + 20 + 1 + 43
    );

    let parsed = must_v2(V2CommitKey::parse(&key.object_id));
    assert_eq!(parsed.sequence, Sequence::new(7));
    assert_eq!(parsed.random_id, [9_u8; 32]);

    for invalid in [
        "checkpoints/not-v2",
        "commits/v02/00000000000000000007/short",
        "commits/v02/0000000000000000007/not-wide-enough",
        "commits/v02/00000000000000000007/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    ] {
        let object_id = object_id(invalid);
        assert!(matches!(
            V2CommitKey::parse(&object_id),
            Err(V2FormatError::InvalidCommitKey)
        ));
    }
}

#[test]
fn single_put_commit_round_trips_with_verified_header_and_body() {
    let keyring = signing_keyring();
    let (commit_key, header, body) = sample_object(V2UploadMode::SinglePut);

    let parsed = must_v2(parse_v2_commit_object(
        &commit_key.object_id,
        body,
        &keyring,
    ));
    assert_eq!(parsed.parsed_header.upload_mode, V2UploadMode::SinglePut);
    assert_eq!(
        parsed.parsed_header.header.self_ref.sequence,
        Sequence::new(7)
    );
    assert_eq!(parsed.parsed_header.header.body_digest, header.body_digest);
    assert_eq!(
        parsed.parsed_header.sections_start,
        super::commit::V2_HEADER_META_LEN + parsed.parsed_header.header_len
    );
}

#[test]
fn multipart_commit_round_trips_with_padded_header() {
    let keyring = signing_keyring();
    let (commit_key, _, body) = sample_object(V2UploadMode::MultipartPadded);

    let parsed = must_v2(parse_v2_commit_object(
        &commit_key.object_id,
        body,
        &keyring,
    ));
    assert_eq!(
        parsed.parsed_header.upload_mode,
        V2UploadMode::MultipartPadded
    );
    assert_eq!(
        parsed.parsed_header.sections_start,
        super::commit::V2_MAX_HEADER_SIZE
    );
}

#[test]
fn v02_wire_codes_and_required_capabilities_are_closed() {
    assert_eq!(V2CommitKind::Delta.to_wire(), 1);
    assert_eq!(V2CommitKind::Root.to_wire(), 2);
    assert_eq!(V2SectionType::IndexDelta.to_wire(), 1);
    assert_eq!(V2SectionType::IndexSnapshot.to_wire(), 2);
    assert_eq!(V2SectionType::Payload.to_wire(), 3);
    assert_eq!(V2SectionType::Directives.to_wire(), 4);
    assert_eq!(V2SectionType::IndexRun.to_wire(), 5);
    assert_eq!(V2SectionType::IndexRoot.to_wire(), 6);
    assert_eq!(V2SectionType::PayloadPack.to_wire(), 7);

    let keyring = signing_keyring();
    let (commit_key, _, body) = sample_object(V2UploadMode::SinglePut);
    assert_eq!(&body[16..24], &1_u64.to_be_bytes());
    for capability_flags in [0_u8, 2, 0x81] {
        let mut tampered = body.to_vec();
        tampered[23] = capability_flags;
        let error = parse_v2_commit_object(&commit_key.object_id, Bytes::from(tampered), &keyring);
        assert!(matches!(error, Err(V2FormatError::UnsupportedCapabilities)));
    }
    let mut tampered = body.to_vec();
    tampered[23] = 3;
    assert!(matches!(
        parse_v2_commit_object(&commit_key.object_id, Bytes::from(tampered), &keyring),
        Err(V2FormatError::HeaderDigestMismatch)
    ));
}

#[test]
fn framed_delta_section_shapes_round_trip() {
    let keyring = signing_keyring();
    let cases = [
        (
            Bytes::from_static(b"index-run"),
            vec![V2SectionDescriptor {
                section_type: V2SectionType::IndexRun,
                offset: 0,
                length: 9,
                flags: V2_SECTION_FLAG_MUST_UNDERSTAND,
                digest: digest_v2_section(b"index-run"),
            }],
        ),
        (
            Bytes::from_static(b"packindex-run"),
            vec![
                V2SectionDescriptor {
                    section_type: V2SectionType::PayloadPack,
                    offset: 0,
                    length: 4,
                    flags: V2_SECTION_FLAG_MUST_UNDERSTAND,
                    digest: digest_v2_section(b"pack"),
                },
                V2SectionDescriptor {
                    section_type: V2SectionType::IndexRun,
                    offset: 4,
                    length: 9,
                    flags: V2_SECTION_FLAG_MUST_UNDERSTAND,
                    digest: digest_v2_section(b"index-run"),
                },
            ],
        ),
    ];

    for (section_region, section_index) in cases {
        let (commit_key, mut header, _) = sample_header(V2UploadMode::SinglePut);
        header.kind = V2CommitKind::Delta;
        header.body_digest = must_v2(body_digest_for_v2_sections(
            &section_index,
            section_region.as_ref(),
        ));
        header.section_index = section_index.clone();
        header = must_v2(header.sign_with_keyring(&keyring, V2UploadMode::SinglePut));
        let body = must_v2(header.encode_object(V2UploadMode::SinglePut, &section_region));
        assert_eq!(&body[16..24], &3_u64.to_be_bytes());
        let parsed = must_v2(parse_v2_commit_object(
            &commit_key.object_id,
            body,
            &keyring,
        ));
        assert_eq!(parsed.parsed_header.header.section_index, section_index);
    }
}

#[test]
fn framed_section_semantics_reject_noncanonical_shapes() {
    let (_, mut header, _) = sample_header(V2UploadMode::SinglePut);
    header.kind = V2CommitKind::Delta;

    let invalid_shapes = [
        vec![V2SectionType::PayloadPack],
        vec![V2SectionType::IndexRun, V2SectionType::PayloadPack],
        vec![
            V2SectionType::PayloadPack,
            V2SectionType::PayloadPack,
            V2SectionType::IndexRun,
        ],
        vec![V2SectionType::Payload, V2SectionType::IndexRun],
        vec![V2SectionType::IndexDelta, V2SectionType::IndexRun],
    ];
    for shape in invalid_shapes {
        header.section_index = shape
            .into_iter()
            .map(|section_type| V2SectionDescriptor {
                section_type,
                offset: 0,
                length: 0,
                flags: V2_SECTION_FLAG_MUST_UNDERSTAND,
                digest: digest_v2_section(&[]),
            })
            .collect();
        assert!(matches!(
            super::commit::validate_commit_section_semantics(&header),
            Err(V2FormatError::InvalidHeaderField)
        ));
    }

    header.kind = V2CommitKind::Root;
    header.section_index = vec![V2SectionDescriptor {
        section_type: V2SectionType::IndexRoot,
        offset: 0,
        length: 0,
        flags: V2_SECTION_FLAG_MUST_UNDERSTAND,
        digest: digest_v2_section(&[]),
    }];
    assert!(super::commit::validate_commit_section_semantics(&header).is_ok());
    header.section_index[0].flags = 0;
    assert!(matches!(
        super::commit::validate_commit_section_semantics(&header),
        Err(V2FormatError::InvalidHeaderField)
    ));
    header.section_index[0].flags = V2_SECTION_FLAG_MUST_UNDERSTAND;
    header.self_ref.sequence = Sequence::new(4);
    assert!(matches!(
        super::commit::validate_commit_section_semantics(&header),
        Err(V2FormatError::InvalidHeaderField)
    ));
}

#[test]
fn framed_sections_reject_commit_level_compression() {
    let (_, mut header, _) = sample_header(V2UploadMode::SinglePut);
    header.kind = V2CommitKind::Delta;
    header.section_index = vec![V2SectionDescriptor {
        section_type: V2SectionType::IndexRun,
        offset: 0,
        length: 0,
        flags: V2_SECTION_FLAG_MUST_UNDERSTAND | super::commit::V2_SECTION_FLAG_COMPRESSED,
        digest: digest_v2_section(&[]),
    }];
    assert!(matches!(
        super::commit::validate_commit_section_semantics(&header),
        Err(V2FormatError::InvalidHeaderField)
    ));
}

#[test]
fn copied_commit_under_a_different_key_is_rejected() {
    let keyring = signing_keyring();
    let (_, _, body) = sample_object(V2UploadMode::SinglePut);
    let wrong_key = must_v2(V2CommitKey::from_parts(Sequence::new(7), [3_u8; 32]));

    let error = parse_v2_commit_object(&wrong_key.object_id, body, &keyring);
    assert!(matches!(error, Err(V2FormatError::SelfKeyMismatch)));
}

#[test]
fn header_digest_tampering_is_rejected_before_trusting_cbor() {
    let keyring = signing_keyring();
    let (commit_key, _, body) = sample_object(V2UploadMode::SinglePut);
    let mut tampered = body.to_vec();
    tampered[63] ^= 0x80;

    let error = parse_v2_commit_object(&commit_key.object_id, Bytes::from(tampered), &keyring);
    assert!(matches!(error, Err(V2FormatError::HeaderDigestMismatch)));
}

#[test]
fn signature_tampering_is_rejected_with_valid_header_digest() {
    let keyring = signing_keyring();
    let (commit_key, mut header, section_region) = sample_header(V2UploadMode::SinglePut);
    header.signature[0] ^= 0x80;
    let body = must_v2(header.encode_object(V2UploadMode::SinglePut, section_region.as_ref()));

    let error = parse_v2_commit_object(&commit_key.object_id, body, &keyring);
    assert!(matches!(error, Err(V2FormatError::SignatureVerification)));
}

#[test]
fn section_digest_tampering_is_rejected_after_header_verification() {
    let keyring = signing_keyring();
    let (commit_key, _, body) = sample_object(V2UploadMode::SinglePut);
    let mut tampered = body.to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x80;

    let error = parse_v2_commit_object(&commit_key.object_id, Bytes::from(tampered), &keyring);
    assert!(matches!(error, Err(V2FormatError::SectionDigestMismatch)));
}

#[test]
fn signed_body_digest_must_match_authenticated_sections() {
    let keyring = signing_keyring();
    let (commit_key, mut header, section_region) = sample_header(V2UploadMode::SinglePut);
    header.body_digest[0] ^= 0x80;
    header = must_v2(header.sign_with_keyring(&keyring, V2UploadMode::SinglePut));
    let mut body = must_v2(header.encode_header_span(V2UploadMode::SinglePut)).to_vec();
    body.extend_from_slice(&section_region);

    let error = parse_v2_commit_object(&commit_key.object_id, Bytes::from(body), &keyring);
    assert!(matches!(error, Err(V2FormatError::BodyDigestMismatch)));
}

#[test]
fn signed_section_digest_must_match_stored_section() {
    let keyring = signing_keyring();
    let (commit_key, mut header, section_region) = sample_header(V2UploadMode::SinglePut);
    header.section_index[0].digest[0] ^= 0x80;
    header = must_v2(header.sign_with_keyring(&keyring, V2UploadMode::SinglePut));
    let mut body = must_v2(header.encode_header_span(V2UploadMode::SinglePut)).to_vec();
    body.extend_from_slice(&section_region);

    let error = parse_v2_commit_object(&commit_key.object_id, Bytes::from(body), &keyring);
    assert!(matches!(error, Err(V2FormatError::SectionDigestMismatch)));
}

#[test]
fn maximum_section_batch_fits_bounded_header() {
    let keyring = signing_keyring();
    let (commit_key, mut header, _) = sample_header(V2UploadMode::MultipartPadded);
    let empty_digest = digest_v2_section(&[]);
    header.section_index = (0..64)
        .map(|_| V2SectionDescriptor {
            section_type: V2SectionType::Payload,
            offset: 0,
            length: 0,
            flags: V2_SECTION_FLAG_MUST_UNDERSTAND,
            digest: empty_digest,
        })
        .chain(std::iter::once(V2SectionDescriptor {
            section_type: V2SectionType::IndexSnapshot,
            offset: 0,
            length: 0,
            flags: V2_SECTION_FLAG_MUST_UNDERSTAND,
            digest: empty_digest,
        }))
        .collect();
    header.body_digest = digest_v2_section(&[]);
    header = must_v2(header.sign_with_keyring(&keyring, V2UploadMode::MultipartPadded));
    let body = must_v2(header.encode_object(V2UploadMode::MultipartPadded, &[]));
    let parsed = must_v2(parse_v2_commit_object(
        &commit_key.object_id,
        body,
        &keyring,
    ));
    assert_eq!(parsed.parsed_header.header.section_index.len(), 65);

    header.section_index.insert(
        0,
        V2SectionDescriptor {
            section_type: V2SectionType::Payload,
            offset: 0,
            length: 0,
            flags: V2_SECTION_FLAG_MUST_UNDERSTAND,
            digest: empty_digest,
        },
    );
    assert!(matches!(
        body_digest_for_v2_sections(&header.section_index, &[]),
        Err(V2FormatError::InvalidHeaderField)
    ));
}

#[test]
fn section_layout_rejects_reserved_flags_and_unauthenticated_gaps() {
    let section_region = Bytes::from_static(b"abcdef");
    let reserved = vec![V2SectionDescriptor {
        section_type: V2SectionType::IndexDelta,
        offset: 0,
        length: 6,
        flags: 0x04,
        digest: digest_v2_section(&section_region),
    }];
    assert!(matches!(
        body_digest_for_v2_sections(&reserved, section_region.as_ref()),
        Err(V2FormatError::ReservedSectionFlags)
    ));

    let gap = vec![V2SectionDescriptor {
        section_type: V2SectionType::IndexDelta,
        offset: 1,
        length: 5,
        flags: 0,
        digest: digest_v2_section(&section_region[1..]),
    }];
    assert!(matches!(
        body_digest_for_v2_sections(&gap, section_region.as_ref()),
        Err(V2FormatError::SectionBounds)
    ));
}

#[test]
fn commit_rejects_snapshot_section_mismatch() {
    let keyring = signing_keyring();
    let (_commit_key, mut header, section_region) = sample_header(V2UploadMode::SinglePut);
    header.kind = V2CommitKind::Delta;
    header = must_v2(header.sign_with_keyring(&keyring, V2UploadMode::SinglePut));
    let error = header.encode_object(V2UploadMode::SinglePut, section_region.as_ref());

    assert!(matches!(error, Err(V2FormatError::InvalidHeaderField)));
}

#[test]
fn format_root_round_trips_and_exposes_commit_keyring_ref() {
    let root = V2FormatRoot::new(
        rs3_types::RepositoryId::new("format-root-test").unwrap_or_else(|error| panic!("{error}")),
        sample_keyring_envelope_root_ref(),
        key_id("signing"),
        V2ProviderProfile::Dev,
        None,
    );

    let bytes = must_v2(root.to_plaintext_bytes());
    let decoded = must_v2(V2FormatRoot::from_plaintext_bytes(&bytes));
    let commit_ref = must_v2(decoded.active_keyring_envelope_ref.commit_ref());

    assert_eq!(decoded, root);
    assert_eq!(commit_ref, sample_keyring_envelope_ref());
}

#[test]
fn error_taxonomy_marks_format_failures_as_fail_closed() {
    assert_eq!(
        V2FormatError::SelfKeyMismatch.class(),
        V2ErrorClass::FailClosedSecurity
    );
    assert_eq!(
        V2FormatError::ProviderProfileFailed.class(),
        V2ErrorClass::ProviderConformance
    );
    assert_eq!(
        V2FormatError::RecoveryBundleRequired.class(),
        V2ErrorClass::OperatorActionRequired
    );
    assert_eq!(
        V2FormatError::MaintenanceBudgetExceeded.class(),
        V2ErrorClass::OperatorActionRequired
    );
}

#[tokio::test]
async fn dev_provider_conformance_passes_on_memory_store() {
    let store = MemoryBlobStore::new();
    let options =
        V2ProviderConformanceOptions::new(V2ProviderProfile::Dev, "v2-provider/dev-memory");

    let report = must_v2(check_v2_provider_conformance(&store, &options).await);

    assert!(report.passed());
    assert!(report.checks.iter().any(|check| {
        check.name == "multipart-complete" && check.status == V2ProviderCheckStatus::Passed
    }));
}

#[tokio::test]
async fn atomic_provider_conformance_checks_multipart_create_only() {
    let store = MemoryBlobStore::new();
    let options = V2ProviderConformanceOptions::new(
        V2ProviderProfile::AtomicCreate,
        "v2-provider/atomic-reviewed",
    );

    let report = must_v2(check_v2_provider_conformance(&store, &options).await);

    assert!(report.passed());
    assert!(report.checks.iter().any(|check| {
        check.name == "multipart-atomic-complete-rejected"
            && check.status == V2ProviderCheckStatus::Passed
    }));
}

#[tokio::test]
async fn retained_provider_conformance_requires_governance_review() {
    let store = MemoryBlobStore::new();
    let options = V2ProviderConformanceOptions::new(
        V2ProviderProfile::RetainedVersionObjectLock,
        "v2-provider/retained-missing-review",
    )
    .with_legal_hold(true);

    let report = must_v2(check_v2_provider_conformance(&store, &options).await);

    assert!(!report.passed());
    assert!(report.checks.iter().any(|check| {
        check.name == "retained-governance-bypass-review"
            && check.status == V2ProviderCheckStatus::Failed
    }));
    assert_eq!(report.failure_class(), V2ErrorClass::ProviderConformance);
}

#[tokio::test]
async fn retained_provider_conformance_passes_on_memory_store_with_review_flag() {
    let store = MemoryBlobStore::new();
    let options = V2ProviderConformanceOptions::new(
        V2ProviderProfile::RetainedVersionObjectLock,
        "v2-provider/retained-reviewed",
    )
    .with_legal_hold(true)
    .with_governance_bypass_reviewed(true);

    let report = must_v2(check_v2_provider_conformance(&store, &options).await);

    assert!(report.passed());
    assert!(report.checks.iter().any(|check| {
        check.name == "multipart-retained-exact-head"
            && check.status == V2ProviderCheckStatus::Passed
    }));
    assert!(report.checks.iter().any(|check| {
        check.name == "retained-exact-version-inventory"
            && check.status == V2ProviderCheckStatus::Passed
    }));
    assert!(report.checks.iter().any(|check| {
        check.name == "retained-active-exact-delete-blocked"
            && check.status == V2ProviderCheckStatus::Passed
    }));
    assert!(report.checks.iter().any(|check| {
        check.name == "retained-unprotected-exact-delete"
            && check.status == V2ProviderCheckStatus::Passed
    }));
}

#[tokio::test]
async fn compliance_retained_provider_conformance_does_not_require_governance_review() {
    let store = MemoryBlobStore::new();
    let options = V2ProviderConformanceOptions::new(
        V2ProviderProfile::RetainedVersionObjectLock,
        "v2-provider/retained-compliance",
    )
    .with_retention(RetentionPolicy::new(RetentionMode::Compliance, 1))
    .with_legal_hold(true);

    let report = must_v2(check_v2_provider_conformance(&store, &options).await);

    assert!(report.passed());
    assert!(report.checks.iter().any(|check| {
        check.name == "retained-governance-bypass-review"
            && check.status == V2ProviderCheckStatus::Passed
    }));
}

#[tokio::test]
async fn v2_commit_store_writes_genesis_child_and_loads_chain() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2CommitStore::new(store, keyring, options);
    let anchor = V2MemoryAnchor::new();

    let genesis = must_v2(repository.write_genesis_snapshot(&anchor).await);
    assert_eq!(genesis.anchor_state.sequence, Sequence::new(1));

    let child = must_v2(
        repository
            .write_child_commit(
                &anchor,
                V2CommitWrite::delta(vec![V2CommitSection::new(
                    V2SectionType::IndexDelta,
                    0,
                    Bytes::from_static(b"opaque-index-delta"),
                )]),
            )
            .await,
    );
    assert_eq!(child.anchor_state.sequence, Sequence::new(2));

    let chain = must_v2(repository.load_chain_from_anchor(&anchor).await);
    let Some(chain) = chain else {
        panic!("chain should exist after genesis");
    };
    assert_eq!(chain.commits_newest_first.len(), 2);
    assert_eq!(
        chain.commits_newest_first[0].parsed_header.header.kind,
        V2CommitKind::Delta
    );
    assert_eq!(
        chain.commits_newest_first[1].parsed_header.header.kind,
        V2CommitKind::Root
    );
}

#[tokio::test]
async fn bounded_replay_uses_only_fixed_size_range_reads() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
    let keyring = signing_keyring();
    let limits = V2ReplayLimits {
        max_retained_bytes: 64,
        read_chunk_bytes: 4 * 1024,
        ..V2ReplayLimits::default()
    };
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    )
    .with_replay_limits(limits);
    let repository = V2CommitStore::new(store.clone(), keyring, options);
    let anchor = V2MemoryAnchor::new();

    must_v2(repository.write_genesis_snapshot(&anchor).await);
    must_v2(
        repository
            .write_child_commit(
                &anchor,
                V2CommitWrite::delta(vec![
                    V2CommitSection::new(
                        V2SectionType::Payload,
                        0,
                        Bytes::from(vec![0x5a; 256 * 1024]),
                    ),
                    V2CommitSection::new(
                        V2SectionType::IndexDelta,
                        0,
                        Bytes::from_static(b"bounded-index"),
                    ),
                ]),
            )
            .await,
    );
    store.reset_operation_counts();

    let chain = must_v2(repository.load_replay_chain_from_anchor(&anchor).await)
        .expect("bounded replay chain should exist");

    assert_eq!(chain.commits_newest_first.len(), 2);
    assert_eq!(store.full_commit_get_count(), 0);
    let ranged_gets = store.ranged_commit_get_count();
    assert!((2..=5).contains(&ranged_gets), "ranged gets: {ranged_gets}");
    assert_eq!(
        chain.commits_newest_first[0].retained_sections[1].as_deref(),
        Some(b"bounded-index".as_slice())
    );
    assert!(chain.commits_newest_first[0].retained_sections[0].is_none());
}

#[tokio::test]
async fn bounded_replay_retains_index_run_but_skips_payload_pack() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2CommitStore::new(store, signing_keyring(), options);
    let anchor = V2MemoryAnchor::new();

    must_v2(repository.write_genesis_snapshot(&anchor).await);
    must_v2(
        repository
            .write_child_commit(
                &anchor,
                V2CommitWrite::delta(vec![
                    V2CommitSection::new(
                        V2SectionType::PayloadPack,
                        V2_SECTION_FLAG_MUST_UNDERSTAND,
                        Bytes::from_static(b"payload-pack"),
                    ),
                    V2CommitSection::new(
                        V2SectionType::IndexRun,
                        V2_SECTION_FLAG_MUST_UNDERSTAND,
                        Bytes::from_static(b"index-run"),
                    ),
                ]),
            )
            .await,
    );

    let chain = must_v2(repository.load_replay_chain_from_anchor(&anchor).await)
        .expect("bounded replay chain should exist");
    let newest = &chain.commits_newest_first[0];
    assert!(newest.retained_sections[0].is_none());
    assert_eq!(
        newest.retained_sections[1].as_deref(),
        Some(&b"index-run"[..])
    );
}

#[tokio::test]
async fn replay_skips_tampered_payload_but_adoption_verifies_it() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2CommitStore::new(store.clone(), keyring.clone(), options);
    let anchor = V2MemoryAnchor::new();
    let genesis = must_v2(repository.write_genesis_snapshot(&anchor).await);
    let child = must_v2(
        repository
            .write_child_commit(
                &anchor,
                V2CommitWrite::delta(vec![
                    V2CommitSection::new(
                        V2SectionType::Payload,
                        0,
                        Bytes::from_static(b"payload-ciphertext"),
                    ),
                    V2CommitSection::new(
                        V2SectionType::IndexDelta,
                        0,
                        Bytes::from_static(b"authenticated-index"),
                    ),
                ]),
            )
            .await,
    );
    let body = must_v2(
        store
            .get_range(&child.commit_key.object_id, ByteRange::Full)
            .await
            .map_err(|_| V2FormatError::StorageOperationFailed),
    );
    let parsed = must_v2(parse_v2_commit_object(
        &child.commit_key.object_id,
        body.clone(),
        &keyring,
    ));
    let payload = &parsed.parsed_header.header.section_index[0];
    let payload_offset = parsed
        .parsed_header
        .sections_start
        .checked_add(usize::try_from(payload.offset).unwrap_or_else(|error| panic!("{error}")))
        .unwrap_or_else(|| panic!("payload offset overflow"));
    let mut corrupted = body.to_vec();
    corrupted[payload_offset] ^= 0x80;
    must_v2(
        store
            .put(
                &child.commit_key.object_id,
                Bytes::from(corrupted),
                PutOptions::default(),
            )
            .await
            .map(|_| ())
            .map_err(|_| V2FormatError::StorageOperationFailed),
    );

    let chain = must_v2(repository.load_replay_chain_from_anchor(&anchor).await)
        .unwrap_or_else(|| panic!("anchored chain should remain replayable"));
    assert_eq!(chain.commits_newest_first.len(), 2);

    let adoption_anchor = V2MemoryAnchor::new();
    must_v2(
        adoption_anchor
            .compare_and_advance_v2(None, genesis.anchor_state)
            .await,
    );
    assert_eq!(
        repository
            .adopt_unanchored_child(&adoption_anchor, &child.commit_key.object_id, None)
            .await,
        Err(V2FormatError::SectionDigestMismatch)
    );
}

#[tokio::test]
async fn bounded_replay_rejects_a_chain_deeper_than_its_commit_budget() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let writer = V2CommitStore::new(store.clone(), keyring.clone(), options.clone());
    let anchor = V2MemoryAnchor::new();

    must_v2(writer.write_genesis_snapshot(&anchor).await);
    for byte in [1_u8, 2] {
        must_v2(
            writer
                .write_child_commit(
                    &anchor,
                    V2CommitWrite::delta(vec![V2CommitSection::new(
                        V2SectionType::IndexDelta,
                        0,
                        Bytes::from(vec![byte]),
                    )]),
                )
                .await,
        );
    }

    let reader = V2CommitStore::new(
        store,
        keyring,
        options.with_replay_limits(V2ReplayLimits {
            max_commits: 2,
            ..V2ReplayLimits::default()
        }),
    );
    assert_eq!(
        reader.load_replay_chain_from_anchor(&anchor).await,
        Err(V2FormatError::ReplayBudgetExceeded)
    );
}

#[tokio::test]
async fn bounded_replay_checks_total_bytes_before_reading_commit_bodies() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let writer = V2CommitStore::new(store.clone(), keyring.clone(), options.clone());
    let anchor = V2MemoryAnchor::new();
    let stored = must_v2(writer.write_genesis_snapshot(&anchor).await);
    let object_len = must_v2(
        store
            .head(&stored.commit_key.object_id)
            .await
            .map_err(|_| V2FormatError::StorageOperationFailed),
    )
    .content_len;
    store.reset_operation_counts();

    let reader = V2CommitStore::new(
        store.clone(),
        keyring,
        options.with_replay_limits(V2ReplayLimits {
            max_total_commit_bytes: object_len.saturating_sub(1),
            ..V2ReplayLimits::default()
        }),
    );
    assert_eq!(
        reader.load_replay_chain_from_anchor(&anchor).await,
        Err(V2FormatError::ReplayBudgetExceeded)
    );
    assert_eq!(store.full_commit_get_count(), 0);
    assert_eq!(store.ranged_commit_get_count(), 0);
}

#[tokio::test]
async fn bounded_replay_rejects_index_bytes_over_its_retention_budget() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let writer = V2CommitStore::new(store.clone(), keyring.clone(), options.clone());
    let anchor = V2MemoryAnchor::new();
    must_v2(writer.write_genesis_snapshot(&anchor).await);
    must_v2(
        writer
            .write_child_commit(
                &anchor,
                V2CommitWrite::delta(vec![V2CommitSection::new(
                    V2SectionType::IndexDelta,
                    0,
                    Bytes::from(vec![0x44; 65]),
                )]),
            )
            .await,
    );

    let reader = V2CommitStore::new(
        store,
        keyring,
        options.with_replay_limits(V2ReplayLimits {
            max_retained_bytes: 64,
            ..V2ReplayLimits::default()
        }),
    );
    assert_eq!(
        reader.load_replay_chain_from_anchor(&anchor).await,
        Err(V2FormatError::ReplayBudgetExceeded)
    );
}

#[tokio::test]
async fn bounded_replay_rejects_provider_length_shorter_than_signed_layout() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2CommitStore::new(store.clone(), keyring, options);
    let anchor = V2MemoryAnchor::new();
    must_v2(repository.write_genesis_snapshot(&anchor).await);
    let stored = must_v2(
        repository
            .write_child_commit(
                &anchor,
                V2CommitWrite::delta(vec![V2CommitSection::new(
                    V2SectionType::IndexDelta,
                    0,
                    Bytes::from_static(b"signed-layout"),
                )]),
            )
            .await,
    );
    let body = must_v2(
        store
            .get_range(&stored.commit_key.object_id, ByteRange::Full)
            .await
            .map_err(|_| V2FormatError::StorageOperationFailed),
    );
    let truncated = body.slice(..body.len() - 1);
    must_v2(
        store
            .put(
                &stored.commit_key.object_id,
                truncated,
                PutOptions::default(),
            )
            .await
            .map_err(|_| V2FormatError::StorageOperationFailed),
    );
    let mut unversioned_head = stored.anchor_state;
    unversioned_head.version_id = None;

    assert_eq!(
        repository
            .load_replay_chain_from_state(&unversioned_head)
            .await,
        Err(V2FormatError::SectionBounds)
    );
}

#[tokio::test]
async fn bounded_replay_rejects_range_tampering() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2CommitStore::new(store.clone(), keyring, options);
    let anchor = V2MemoryAnchor::new();
    let stored = must_v2(repository.write_genesis_snapshot(&anchor).await);
    store.corrupt_ranged_commit_gets_for(stored.commit_key.object_id);

    assert_eq!(
        repository.load_replay_chain_from_anchor(&anchor).await,
        Err(V2FormatError::HeaderDigestMismatch)
    );
}

#[tokio::test]
async fn legacy_full_commit_reader_checks_length_before_body_allocation() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let writer = V2CommitStore::new(store.clone(), keyring.clone(), options.clone());
    let anchor = V2MemoryAnchor::new();
    let stored = must_v2(writer.write_genesis_snapshot(&anchor).await);
    let object_len = must_v2(
        store
            .head(&stored.commit_key.object_id)
            .await
            .map_err(|_| V2FormatError::StorageOperationFailed),
    )
    .content_len;
    store.reset_operation_counts();

    let reader = V2CommitStore::new(
        store.clone(),
        keyring,
        options.with_replay_limits(V2ReplayLimits {
            max_full_commit_bytes: object_len.saturating_sub(1),
            ..V2ReplayLimits::default()
        }),
    );

    assert_eq!(
        reader.load_chain_from_anchor(&anchor).await,
        Err(V2FormatError::ReplayBudgetExceeded)
    );
    assert_eq!(store.full_commit_get_count(), 0);
    assert_eq!(store.ranged_commit_get_count(), 0);
}

#[tokio::test]
async fn legacy_full_chain_reader_checks_depth_before_next_object_read() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let writer = V2CommitStore::new(store.clone(), keyring.clone(), options.clone());
    let anchor = V2MemoryAnchor::new();
    must_v2(writer.write_genesis_snapshot(&anchor).await);
    must_v2(
        writer
            .write_child_commit(
                &anchor,
                V2CommitWrite::delta(vec![V2CommitSection::new(
                    V2SectionType::IndexDelta,
                    0,
                    Bytes::from_static(b"one-child"),
                )]),
            )
            .await,
    );
    store.reset_operation_counts();

    let reader = V2CommitStore::new(
        store.clone(),
        keyring,
        options.with_replay_limits(V2ReplayLimits {
            max_commits: 1,
            ..V2ReplayLimits::default()
        }),
    );

    assert_eq!(
        reader.load_chain_from_anchor(&anchor).await,
        Err(V2FormatError::ReplayBudgetExceeded)
    );
    assert_eq!(store.full_commit_get_count(), 0);
    assert_eq!(store.operation_counts().head, 1);
}

#[tokio::test]
async fn legacy_full_chain_reader_checks_cumulative_bytes_before_next_allocation() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let writer = V2CommitStore::new(store.clone(), keyring.clone(), options.clone());
    let anchor = V2MemoryAnchor::new();
    must_v2(writer.write_genesis_snapshot(&anchor).await);
    let child = must_v2(
        writer
            .write_child_commit(
                &anchor,
                V2CommitWrite::delta(vec![V2CommitSection::new(
                    V2SectionType::IndexDelta,
                    0,
                    Bytes::from_static(b"one-child"),
                )]),
            )
            .await,
    );
    let child_len = must_v2(
        store
            .head(&child.commit_key.object_id)
            .await
            .map_err(|_| V2FormatError::StorageOperationFailed),
    )
    .content_len;
    store.reset_operation_counts();

    let reader = V2CommitStore::new(
        store.clone(),
        keyring,
        options.with_replay_limits(V2ReplayLimits {
            max_full_chain_bytes: child_len,
            ..V2ReplayLimits::default()
        }),
    );

    assert_eq!(
        reader.load_chain_from_anchor(&anchor).await,
        Err(V2FormatError::ReplayBudgetExceeded)
    );
    assert_eq!(store.full_commit_get_count(), 0);
    assert_eq!(store.ranged_commit_get_count(), 1);
    assert_eq!(store.operation_counts().head, 2);
}

#[tokio::test]
async fn v2_repository_replays_committed_index_delta_after_reload() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        options.clone(),
    );
    let anchor = V2MemoryAnchor::new();
    let key = LogicalPath::new("snapshots/v2-replay.bin").unwrap_or_else(|error| panic!("{error}"));

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    let metadata = must_repo(
        repository
            .put_committed(
                &anchor,
                key.clone(),
                Bytes::from_static(b"replayed-body"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    let fresh = V2Repository::new(store, keyring, RepositoryOptions::default(), options);
    let chain = must_repo(fresh.load_chain_from_anchor(&anchor).await);
    let head = must_repo(fresh.head(&key));
    let body = must_repo(fresh.get_range(&key, ByteRange::Full).await);
    let listed = must_repo(fresh.list("snapshots/"));

    assert!(chain.is_some());
    assert_eq!(metadata.content_len, 13);
    assert_eq!(head.content_len, 13);
    assert_eq!(body, Bytes::from_static(b"replayed-body"));
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].key, key);
}

#[tokio::test]
async fn v2_repository_startup_replay_never_fetches_full_commit_objects() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    )
    .with_replay_limits(V2ReplayLimits {
        read_chunk_bytes: 4 * 1024,
        ..V2ReplayLimits::default()
    });
    let repository = V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        options.clone(),
    );
    let anchor = V2MemoryAnchor::new();
    let key =
        LogicalPath::new("snapshots/bounded-startup.bin").unwrap_or_else(|error| panic!("{error}"));

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(
        repository
            .put_committed(
                &anchor,
                key.clone(),
                Bytes::from(vec![0x7a; 256 * 1024]),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    store.reset_operation_counts();

    let fresh = V2Repository::new(
        store.clone(),
        keyring,
        RepositoryOptions::default(),
        options,
    );
    must_repo(fresh.load_chain_from_anchor(&anchor).await)
        .unwrap_or_else(|| panic!("startup replay should find an anchor"));

    assert_eq!(store.full_commit_get_count(), 0);
    let ranged_gets = store.ranged_commit_get_count();
    assert!((2..=5).contains(&ranged_gets), "ranged gets: {ranged_gets}");
    assert_eq!(must_repo(fresh.head(&key)).content_len, 256 * 1024);
}

#[tokio::test]
async fn v2_repository_reads_previously_resolved_object_range() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2Repository::new(store, keyring, RepositoryOptions::default(), options);
    let anchor = V2MemoryAnchor::new();
    let key = LogicalPath::new("snapshots/v2-resolved-range.bin")
        .unwrap_or_else(|error| panic!("{error}"));

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(
        repository
            .put_committed(
                &anchor,
                key.clone(),
                Bytes::from_static(b"resolved-body"),
                RepositoryPutOptions::default(),
            )
            .await,
    );

    let resolved = must_repo(repository.resolve_object(&key));
    let read = must_repo(
        repository
            .get_resolved_range(&resolved, ByteRange::Slice { offset: 9, len: 4 })
            .await,
    );

    assert_eq!(resolved.metadata().content_len, 13);
    assert_eq!(read, Bytes::from_static(b"body"));
}

#[tokio::test]
async fn v2_repository_list_page_returns_limit_plus_one_after_marker() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2Repository::new(store, keyring, RepositoryOptions::default(), options);
    let anchor = V2MemoryAnchor::new();

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    for key in [
        "snapshots/list-a.bin",
        "snapshots/list-b.bin",
        "snapshots/list-c.bin",
    ] {
        must_repo(
            repository
                .put_committed(
                    &anchor,
                    must_type(LogicalPath::new(key)),
                    Bytes::from_static(b"body"),
                    RepositoryPutOptions::default(),
                )
                .await,
        );
    }

    let first_page = must_repo(repository.list_page("snapshots/", None, 2));
    let second_page =
        must_repo(repository.list_page("snapshots/", Some("snapshots/list-a.bin"), 1));

    assert_eq!(
        first_page
            .iter()
            .map(|entry| entry.key.as_str())
            .collect::<Vec<_>>(),
        vec![
            "snapshots/list-a.bin",
            "snapshots/list-b.bin",
            "snapshots/list-c.bin"
        ]
    );
    assert_eq!(
        second_page
            .iter()
            .map(|entry| entry.key.as_str())
            .collect::<Vec<_>>(),
        vec!["snapshots/list-b.bin", "snapshots/list-c.bin"]
    );
}

#[tokio::test]
async fn v2_repository_range_reads_cache_headers_without_full_commit_gets() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2Repository::new(
        store.clone(),
        keyring,
        RepositoryOptions::default(),
        options,
    );
    let anchor = V2MemoryAnchor::new();
    let key = LogicalPath::new("snapshots/v2-cached-ranges.bin")
        .unwrap_or_else(|error| panic!("{error}"));
    let body = Bytes::from(vec![42_u8; 4096]);

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(
        repository
            .put_committed(&anchor, key.clone(), body, RepositoryPutOptions::default())
            .await,
    );
    store.reset_operation_counts();

    for offset in (0..4096).step_by(512) {
        let read = must_repo(
            repository
                .get_range(&key, ByteRange::Slice { offset, len: 512 })
                .await,
        );
        assert_eq!(read, Bytes::from(vec![42_u8; 512]));
    }

    let counts = store.operation_counts();
    assert_eq!(store.full_commit_get_count(), 0);
    assert_eq!(store.ranged_commit_get_count(), counts.get);
    assert_eq!(counts.get, 1);
}

#[tokio::test]
async fn v2_rooted_cold_pack_read_fetches_only_exact_record_ciphertext() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        options.clone(),
    );
    let anchor = V2MemoryAnchor::new();
    let key = must_type(LogicalPath::new("snapshots/v2-direct-cold-read.bin"));
    let body = Bytes::from(vec![37_u8; 512]);

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(
        repository
            .put_committed(
                &anchor,
                key.clone(),
                body.clone(),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    must_repo(repository.write_index_snapshot(&anchor).await);

    let fresh = V2Repository::new(
        store.clone(),
        keyring,
        RepositoryOptions::default(),
        options,
    );
    must_repo(fresh.load_chain_from_anchor(&anchor).await);
    store.reset_operation_counts();

    let restored = must_repo(fresh.get_range(&key, ByteRange::Full).await);
    let counts = store.operation_counts();

    assert_eq!(restored, body);
    assert_eq!(counts.get, 1);
    assert_eq!(counts.head, 0);
    assert_eq!(counts.list, 0);
    assert_eq!(counts.bytes_read, 512 + 16);
    assert_eq!(store.full_commit_get_count(), 0);
    assert_eq!(store.ranged_commit_get_count(), 1);
}

#[tokio::test]
async fn v2_rooted_pack_read_uses_the_historical_keyring_envelope_context() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
    let keyring = must_crypto(KeyRing::generate_random());
    let original_options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let original = V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        original_options,
    );
    let anchor = V2MemoryAnchor::new();
    let key = must_type(LogicalPath::new("snapshots/v2-historical-envelope.bin"));
    let body = Bytes::from(vec![73_u8; 512]);

    must_repo(original.write_genesis_snapshot(&anchor).await);
    must_repo(
        original
            .put_committed(
                &anchor,
                key.clone(),
                body.clone(),
                RepositoryPutOptions::default(),
            )
            .await,
    );

    let rotated_envelope = V2KeyringEnvelopeRef {
        object_id: object_id("keyrings/00000000000000000002-rotated"),
        digest: [8_u8; 32],
    };
    let rotated_options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        rotated_envelope,
        sample_format_ref(),
    );
    let rotated = V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        rotated_options.clone(),
    );
    must_repo(rotated.load_chain_from_anchor(&anchor).await);
    must_repo(rotated.write_index_snapshot(&anchor).await);

    let fresh = V2Repository::new(
        store.clone(),
        keyring,
        RepositoryOptions::default(),
        rotated_options,
    );
    must_repo(fresh.load_chain_from_anchor(&anchor).await);
    store.reset_operation_counts();

    let restored = must_repo(fresh.get_range(&key, ByteRange::Full).await);
    let counts = store.operation_counts();

    assert_eq!(restored, body);
    assert_eq!(counts.get, 1);
    assert_eq!(counts.head, 0);
    assert_eq!(counts.list, 0);
    assert_eq!(counts.bytes_read, 512 + 16);
}

#[tokio::test]
async fn v2_repository_concurrent_range_reads_avoid_full_commit_gets() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::from_millis(50));
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = Arc::new(V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        options.clone(),
    ));
    let anchor = V2MemoryAnchor::new();
    let key = LogicalPath::new("snapshots/v2-concurrent-cache-miss.bin")
        .unwrap_or_else(|error| panic!("{error}"));
    let body = Bytes::from(vec![11_u8; 4096]);

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(
        repository
            .put_committed(&anchor, key.clone(), body, RepositoryPutOptions::default())
            .await,
    );
    store.reset_operation_counts();

    let readers = 8_usize;
    let barrier = Arc::new(Barrier::new(readers + 1));
    let tasks = (0..readers)
        .map(|index| {
            let repository = Arc::clone(&repository);
            let key = key.clone();
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                repository
                    .get_range(
                        &key,
                        ByteRange::Slice {
                            offset: (index * 64) as u64,
                            len: 64,
                        },
                    )
                    .await
            })
        })
        .collect::<Vec<_>>();
    barrier.wait().await;

    for task in tasks {
        let read = must_repo(task.await.unwrap_or_else(|error| panic!("{error}")));
        assert_eq!(read, Bytes::from(vec![11_u8; 64]));
    }

    assert_eq!(store.full_commit_get_count(), 0);
    assert!(store.ranged_commit_get_count() >= 1);
    assert!(store.ranged_commit_get_count() <= readers as u64);
}

#[tokio::test]
async fn v2_repository_full_reads_fetch_payload_sections_not_full_commits() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::from_millis(10));
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = Arc::new(V2Repository::new(
        store.clone(),
        keyring,
        RepositoryOptions::default(),
        options,
    ));
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    let coordinator = Arc::new(must_repo(V2CommitCoordinator::with_options(
        Arc::clone(&repository),
        anchor,
        CommitCoordinatorOptions::new(2, Duration::from_secs(60)),
    )));
    let first_key =
        LogicalPath::new("snapshots/v2-cache-fill-a.bin").unwrap_or_else(|error| panic!("{error}"));
    let second_key =
        LogicalPath::new("snapshots/v2-cache-fill-b.bin").unwrap_or_else(|error| panic!("{error}"));

    let first_put = {
        let coordinator = Arc::clone(&coordinator);
        let key = first_key.clone();
        async move {
            coordinator
                .put_committed(
                    key,
                    Bytes::from(vec![1_u8; 4096]),
                    RepositoryPutOptions::default(),
                )
                .await
        }
    };
    let second_put = {
        let coordinator = Arc::clone(&coordinator);
        let key = second_key.clone();
        async move {
            coordinator
                .put_committed(
                    key,
                    Bytes::from(vec![2_u8; 4096]),
                    RepositoryPutOptions::default(),
                )
                .await
        }
    };
    let (first_put, second_put) = tokio::join!(first_put, second_put);
    must_repo(first_put);
    must_repo(second_put);
    store.reset_operation_counts();

    let first = must_repo(repository.get_range(&first_key, ByteRange::Full).await);
    let second = must_repo(repository.get_range(&second_key, ByteRange::Full).await);

    assert_eq!(first, Bytes::from(vec![1_u8; 4096]));
    assert_eq!(second, Bytes::from(vec![2_u8; 4096]));
    let counts = store.operation_counts();
    assert_eq!(store.full_commit_get_count(), 0);
    assert_eq!(store.ranged_commit_get_count(), counts.get);
    assert_eq!(counts.get, 2);
}

#[tokio::test]
async fn v2_repository_range_reads_do_not_require_payload_section_cache() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository_options = RepositoryOptions {
        decrypted_segment_cache_max_bytes: 0,
        ..RepositoryOptions::default()
    };
    let repository = V2Repository::new(store.clone(), keyring, repository_options, options);
    let anchor = V2MemoryAnchor::new();
    let key = LogicalPath::new("snapshots/v2-cache-disabled.bin")
        .unwrap_or_else(|error| panic!("{error}"));

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(
        repository
            .put_committed(
                &anchor,
                key.clone(),
                Bytes::from(vec![7_u8; 2048]),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    store.reset_operation_counts();

    for offset in [0, 512] {
        let read = must_repo(
            repository
                .get_range(&key, ByteRange::Slice { offset, len: 512 })
                .await,
        );
        assert_eq!(read, Bytes::from(vec![7_u8; 512]));
    }

    let counts = store.operation_counts();
    assert_eq!(store.full_commit_get_count(), 0);
    assert_eq!(store.ranged_commit_get_count(), counts.get);
    assert_eq!(counts.get, 2);
}

#[tokio::test]
async fn v2_repository_repeated_ranges_reuse_decrypted_segments() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2Repository::new(
        store.clone(),
        keyring,
        RepositoryOptions::default(),
        options,
    );
    let anchor = V2MemoryAnchor::new();
    let key = LogicalPath::new("snapshots/v2-segment-cache.bin")
        .unwrap_or_else(|error| panic!("{error}"));

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(
        repository
            .put_committed(
                &anchor,
                key.clone(),
                Bytes::from(vec![9_u8; 2048]),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    store.reset_operation_counts();

    for offset in [0, 64, 128] {
        let read = must_repo(
            repository
                .get_range(&key, ByteRange::Slice { offset, len: 64 })
                .await,
        );
        assert_eq!(read, Bytes::from(vec![9_u8; 64]));
    }

    let counts = store.operation_counts();
    assert_eq!(store.full_commit_get_count(), 0);
    assert_eq!(store.ranged_commit_get_count(), counts.get);
    assert_eq!(counts.get, 1);
}

#[tokio::test]
async fn v2_repository_range_read_rejects_corrupted_payload_ciphertext() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2Repository::new(
        store.clone(),
        keyring,
        RepositoryOptions::default(),
        options,
    );
    let anchor = V2MemoryAnchor::new();
    let key = LogicalPath::new("snapshots/v2-corrupt-range.bin")
        .unwrap_or_else(|error| panic!("{error}"));

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(
        repository
            .put_committed(
                &anchor,
                key.clone(),
                Bytes::from(vec![13_u8; 2048]),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    let accepted = must_v2(anchor.read_v2().await).expect("v2 anchor should exist");
    store.corrupt_ranged_commit_gets_for(accepted.commit_key);

    let error = repository
        .get_range(&key, ByteRange::Slice { offset: 0, len: 64 })
        .await;

    assert!(error.is_err());
}

#[tokio::test]
async fn v2_repository_full_read_does_not_cache_unauthenticated_payload_section() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2Repository::new(
        store.clone(),
        keyring,
        RepositoryOptions::default(),
        options,
    );
    let anchor = V2MemoryAnchor::new();
    let key =
        LogicalPath::new("snapshots/v2-corrupt-full.bin").unwrap_or_else(|error| panic!("{error}"));
    let body = Bytes::from(vec![17_u8; 2048]);

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(
        repository
            .put_committed(
                &anchor,
                key.clone(),
                body.clone(),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    let accepted = must_v2(anchor.read_v2().await).expect("v2 anchor should exist");
    store.corrupt_ranged_commit_gets_for(accepted.commit_key);

    let corrupted = repository.get_range(&key, ByteRange::Full).await;
    assert!(corrupted.is_err());

    store.clear_corruption();
    let repaired = must_repo(repository.get_range(&key, ByteRange::Full).await);
    assert_eq!(repaired, body);
}

#[tokio::test]
async fn v2_repository_range_read_rejects_payload_length_metadata_mismatch() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2Repository::new(store, keyring, RepositoryOptions::default(), options);
    let anchor = V2MemoryAnchor::new();
    let key = LogicalPath::new("snapshots/v2-length-mismatch.bin")
        .unwrap_or_else(|error| panic!("{error}"));

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(
        repository
            .put_committed(
                &anchor,
                key.clone(),
                Bytes::from(vec![21_u8; 2048]),
                RepositoryPutOptions::default(),
            )
            .await,
    );

    must_repo(repository.shorten_accepted_payload_section_for_tests(2048));

    let error = repository
        .get_range(&key, ByteRange::Slice { offset: 0, len: 64 })
        .await;

    assert!(error.is_err());
}

#[tokio::test]
async fn v2_repository_range_read_rejects_payload_plaintext_length_metadata_mismatch() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2Repository::new(store, keyring, RepositoryOptions::default(), options);
    let anchor = V2MemoryAnchor::new();
    let key = LogicalPath::new("snapshots/v2-plaintext-length-mismatch.bin")
        .unwrap_or_else(|error| panic!("{error}"));

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(
        repository
            .put_committed(
                &anchor,
                key.clone(),
                Bytes::from(vec![22_u8; 2048]),
                RepositoryPutOptions::default(),
            )
            .await,
    );

    must_repo(repository.shorten_accepted_content_len_for_tests(2048));

    let error = repository
        .get_range(&key, ByteRange::Slice { offset: 0, len: 64 })
        .await;

    assert!(error.is_err());
}

#[tokio::test]
async fn v2_repository_independent_payload_range_fills_run_concurrently() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::from_millis(50));
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = Arc::new(V2Repository::new(
        store.clone(),
        keyring,
        RepositoryOptions::default(),
        options,
    ));
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);

    let object_count = 16_usize;
    let mut keys = Vec::with_capacity(object_count);
    for index in 0..object_count {
        let key = LogicalPath::new(format!("snapshots/v2-independent-fill-{index}.bin"))
            .unwrap_or_else(|error| panic!("{error}"));
        must_repo(
            repository
                .put_committed(
                    &anchor,
                    key.clone(),
                    Bytes::from(vec![index as u8; 2048]),
                    RepositoryPutOptions::default(),
                )
                .await,
        );
        keys.push(key);
    }
    store.reset_operation_counts();

    let barrier = Arc::new(Barrier::new(object_count + 1));
    let tasks = keys
        .into_iter()
        .map(|key| {
            let repository = Arc::clone(&repository);
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                repository
                    .get_range(&key, ByteRange::Slice { offset: 0, len: 64 })
                    .await
            })
        })
        .collect::<Vec<_>>();
    barrier.wait().await;

    for (index, task) in tasks.into_iter().enumerate() {
        let read = must_repo(task.await.unwrap_or_else(|error| panic!("{error}")));
        assert_eq!(read, Bytes::from(vec![index as u8; 64]));
    }

    assert_eq!(store.full_commit_get_count(), 0);
    assert_eq!(store.ranged_commit_get_count(), object_count as u64);
    assert!(store.max_in_flight_ranged_commit_get_count() > 1);
}

#[tokio::test]
async fn v2_repository_hides_unaccepted_mutation_after_anchor_failure() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2Repository::new(
        store,
        keyring,
        RepositoryOptions::default(),
        options.clone(),
    );
    let anchor = V2MemoryAnchor::new();
    let key =
        LogicalPath::new("snapshots/unaccepted-v2.bin").unwrap_or_else(|error| panic!("{error}"));

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    let failed_put = repository
        .put_committed(
            &FailOnceV2Anchor::new(anchor.clone()),
            key.clone(),
            Bytes::from_static(b"unaccepted"),
            RepositoryPutOptions::default(),
        )
        .await;

    assert!(matches!(
        failed_put,
        Err(crate::RepositoryError::CommitFailed { .. })
    ));
    assert!(matches!(
        repository.head(&key),
        Err(crate::RepositoryError::NotFound(_))
    ));

    let accepted = must_repo(
        repository
            .put_committed(
                &anchor,
                key.clone(),
                Bytes::from_static(b"accepted"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    let failed_delete = repository
        .delete_committed(&FailOnceV2Anchor::new(anchor.clone()), key.clone())
        .await;
    let body = must_repo(repository.get_range(&key, ByteRange::Full).await);

    assert_eq!(accepted.content_len, 8);
    assert!(matches!(
        failed_delete,
        Err(crate::RepositoryError::CommitFailed { .. })
    ));
    assert_eq!(body, Bytes::from_static(b"accepted"));
}

#[tokio::test]
async fn v2_repository_does_not_expose_staged_put_before_anchor_acceptance() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = Arc::new(V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        options.clone(),
    ));
    let anchor = V2MemoryAnchor::new();
    let blocking_anchor = BlockingV2Anchor::new(anchor.clone());
    let key =
        LogicalPath::new("snapshots/pending-put.bin").unwrap_or_else(|error| panic!("{error}"));

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    let pending_put = {
        let repository = Arc::clone(&repository);
        let blocking_anchor = blocking_anchor.clone();
        let key = key.clone();
        tokio::spawn(async move {
            repository
                .put_committed(
                    &blocking_anchor,
                    key,
                    Bytes::from_static(b"pending"),
                    RepositoryPutOptions::default(),
                )
                .await
        })
    };
    blocking_anchor.wait_until_blocked().await;

    assert!(matches!(
        repository.head(&key),
        Err(crate::RepositoryError::NotFound(_))
    ));
    assert!(matches!(
        repository.get_range(&key, ByteRange::Full).await,
        Err(crate::RepositoryError::NotFound(_))
    ));
    assert!(must_repo(repository.list("snapshots/")).is_empty());

    blocking_anchor.release();
    must_repo(pending_put.await.unwrap_or_else(|error| panic!("{error}")));
    assert_eq!(
        must_repo(repository.get_range(&key, ByteRange::Full).await),
        Bytes::from_static(b"pending")
    );
}

#[tokio::test]
async fn v2_repository_keeps_accepted_object_visible_during_pending_delete() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = Arc::new(V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        options.clone(),
    ));
    let anchor = V2MemoryAnchor::new();
    let blocking_anchor = BlockingV2Anchor::new(anchor.clone());
    let key =
        LogicalPath::new("snapshots/pending-delete.bin").unwrap_or_else(|error| panic!("{error}"));

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(
        repository
            .put_committed(
                &anchor,
                key.clone(),
                Bytes::from_static(b"accepted"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    let pending_delete = {
        let repository = Arc::clone(&repository);
        let blocking_anchor = blocking_anchor.clone();
        let key = key.clone();
        tokio::spawn(async move { repository.delete_committed(&blocking_anchor, key).await })
    };
    blocking_anchor.wait_until_blocked().await;

    assert_eq!(
        must_repo(repository.get_range(&key, ByteRange::Full).await),
        Bytes::from_static(b"accepted")
    );
    assert_eq!(must_repo(repository.list("snapshots/")).len(), 1);

    blocking_anchor.release();
    must_repo(
        pending_delete
            .await
            .unwrap_or_else(|error| panic!("{error}")),
    );
    assert!(matches!(
        repository.head(&key),
        Err(crate::RepositoryError::NotFound(_))
    ));
}

#[tokio::test]
async fn v2_repository_legal_hold_is_visible_only_after_anchor_acceptance() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        options.clone(),
    );
    let anchor = V2MemoryAnchor::new();
    let key =
        LogicalPath::new("snapshots/legal-hold.bin").unwrap_or_else(|error| panic!("{error}"));

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(
        repository
            .put_committed(
                &anchor,
                key.clone(),
                Bytes::from_static(b"held"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    let failed = repository
        .set_legal_hold_committed(
            &FailOnceV2Anchor::new(anchor.clone()),
            key.clone(),
            LegalHoldStatus::On,
        )
        .await;

    assert!(matches!(failed, Err(RepositoryError::CommitFailed { .. })));
    assert_eq!(must_repo(repository.head(&key)).legal_hold, None);

    let held = must_repo(
        repository
            .set_legal_hold_committed(&anchor, key.clone(), LegalHoldStatus::On)
            .await,
    );
    assert_eq!(held.legal_hold, Some(LegalHoldStatus::On));
    assert_eq!(
        must_repo(repository.get_range(&key, ByteRange::Full).await),
        Bytes::from_static(b"held")
    );

    let fresh = V2Repository::new(store, keyring, RepositoryOptions::default(), options);
    must_repo(fresh.load_chain_from_anchor(&anchor).await);
    assert_eq!(
        must_repo(fresh.head(&key)).legal_hold,
        Some(LegalHoldStatus::On)
    );
    assert_eq!(
        must_repo(fresh.get_range(&key, ByteRange::Full).await),
        Bytes::from_static(b"held")
    );
}

#[tokio::test]
async fn v2_commit_coordinator_batches_concurrent_puts_into_one_commit() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = Arc::new(V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        options.clone(),
    ));
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    let coordinator = Arc::new(must_repo(V2CommitCoordinator::with_options(
        Arc::clone(&repository),
        anchor.clone(),
        CommitCoordinatorOptions::new(2, Duration::from_secs(60)),
    )));
    let first_key =
        LogicalPath::new("snapshots/v2-batched-a.bin").unwrap_or_else(|error| panic!("{error}"));
    let second_key =
        LogicalPath::new("snapshots/v2-batched-b.bin").unwrap_or_else(|error| panic!("{error}"));

    let first = {
        let coordinator = Arc::clone(&coordinator);
        let key = first_key.clone();
        async move {
            coordinator
                .put_committed(
                    key,
                    Bytes::from_static(b"batched-a"),
                    RepositoryPutOptions::default(),
                )
                .await
        }
    };
    let second = {
        let coordinator = Arc::clone(&coordinator);
        let key = second_key.clone();
        async move {
            coordinator
                .put_committed(
                    key,
                    Bytes::from_static(b"batched-b"),
                    RepositoryPutOptions::default(),
                )
                .await
        }
    };

    let (first, second) = tokio::join!(first, second);
    let first = must_repo(first);
    let second = must_repo(second);
    let accepted = must_v2(anchor.read_v2().await).expect("v2 anchor should exist");
    let fresh = V2Repository::new(
        store.clone(),
        keyring,
        RepositoryOptions::default(),
        options,
    );
    let chain = must_repo(fresh.load_chain_from_anchor(&anchor).await)
        .expect("v2 chain should load after batch commit");
    let listed = must_repo(fresh.list("snapshots/"));
    let commits = must_v2(
        store
            .list_prefix("commits/v02/")
            .await
            .map_err(|_| V2FormatError::StorageOperationFailed),
    );
    let retired_payloads = must_v2(
        store
            .list_prefix("segments/")
            .await
            .map_err(|_| V2FormatError::StorageOperationFailed),
    );
    let retired_index = must_v2(
        store
            .list_prefix("index/")
            .await
            .map_err(|_| V2FormatError::StorageOperationFailed),
    );
    let retired_manifests = must_v2(
        store
            .list_prefix("manifests/")
            .await
            .map_err(|_| V2FormatError::StorageOperationFailed),
    );
    let retired_checkpoints = must_v2(
        store
            .list_prefix("checkpoints/")
            .await
            .map_err(|_| V2FormatError::StorageOperationFailed),
    );
    let retired_evidence = must_v2(
        store
            .list_prefix("evidence/")
            .await
            .map_err(|_| V2FormatError::StorageOperationFailed),
    );

    assert_eq!(first.anchor_state, second.anchor_state);
    assert_eq!(accepted.sequence, Sequence::new(2));
    assert_eq!(chain.commits_newest_first.len(), 2);
    assert_eq!(commits.len(), 2);
    let batched_commit = &chain.commits_newest_first[0].parsed_header;
    let payload_pack_count = batched_commit
        .header
        .section_index
        .iter()
        .filter(|section| section.section_type == V2SectionType::PayloadPack)
        .count();
    let index_run_count = batched_commit
        .header
        .section_index
        .iter()
        .filter(|section| section.section_type == V2SectionType::IndexRun)
        .count();
    assert_eq!(retired_payloads.len(), 0);
    assert_eq!(retired_index.len(), 0);
    assert_eq!(retired_manifests.len(), 0);
    assert_eq!(retired_checkpoints.len(), 0);
    assert_eq!(retired_evidence.len(), 0);
    assert_eq!(batched_commit.upload_mode, V2UploadMode::SinglePut);
    assert_eq!(payload_pack_count, 1);
    assert_eq!(index_run_count, 1);
    assert_eq!(
        listed
            .into_iter()
            .map(|entry| entry.key)
            .collect::<Vec<_>>(),
        vec![first_key, second_key]
    );
}

#[tokio::test]
async fn v2_repository_admits_only_one_commit_coordinator_instance() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = Arc::new(V2Repository::new(
        store,
        keyring,
        RepositoryOptions::default(),
        options,
    ));
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);

    let first = must_repo(V2CommitCoordinator::new(
        Arc::clone(&repository),
        anchor.clone(),
    ));
    let duplicate = V2CommitCoordinator::new(Arc::clone(&repository), anchor.clone());
    assert!(matches!(
        duplicate,
        Err(crate::RepositoryError::CommitFailed { reason })
            if reason == "v2 repository already has an active mutation owner"
    ));
    let direct = repository
        .put_committed(
            &anchor,
            must_type(LogicalPath::new("snapshots/direct-bypass.bin")),
            Bytes::from_static(b"must not stage"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(matches!(
        direct,
        Err(crate::RepositoryError::CommitFailed { reason })
            if reason == "v2 repository mutation is owned by the active commit coordinator"
    ));
    assert!(matches!(
        repository
            .compact_packed_index_runs(&anchor, &UnenforcedQuiescedMaintenanceGuard,)
            .await,
        Err(crate::RepositoryError::CommitFailed { .. })
    ));
    assert!(matches!(
        repository
            .write_compaction_snapshot(
                &anchor,
                &UnenforcedQuiescedMaintenanceGuard,
                V2FullGcDryRunOptions::default(),
                false,
            )
            .await,
        Err(crate::RepositoryError::CommitFailed { .. })
    ));
    assert_eq!(must_repo(repository.pending_operation_count_for_tests()), 0);

    drop(first);
    let replacement = must_repo(V2CommitCoordinator::new(repository, anchor));
    assert!(!replacement.status().poisoned);
}

#[tokio::test]
async fn v2_delayed_publisher_retains_repository_ownership_after_cancellation() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = Arc::new(V2Repository::new(
        store,
        keyring,
        RepositoryOptions::default(),
        options,
    ));
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    let coordinator = Arc::new(must_repo(V2CommitCoordinator::with_options(
        Arc::clone(&repository),
        anchor.clone(),
        CommitCoordinatorOptions::new(2, Duration::from_millis(25)),
    )));
    let pending = {
        let coordinator = Arc::clone(&coordinator);
        tokio::spawn(async move {
            coordinator
                .put_committed(
                    must_type(LogicalPath::new("snapshots/cancelled-waiter.bin")),
                    Bytes::from_static(b"accepted by delayed publisher"),
                    RepositoryPutOptions::default(),
                )
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(1), async {
        while must_repo(repository.pending_operation_count_for_tests()) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|error| panic!("staged write did not appear: {error}"));

    pending.abort();
    assert!(pending.await.is_err());
    drop(coordinator);
    assert!(matches!(
        V2CommitCoordinator::new(Arc::clone(&repository), anchor.clone()),
        Err(crate::RepositoryError::CommitFailed { .. })
    ));

    let replacement = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match V2CommitCoordinator::new(Arc::clone(&repository), anchor.clone()) {
                Ok(replacement) => break replacement,
                Err(crate::RepositoryError::CommitFailed { .. }) => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Err(error) => panic!("unexpected replacement error: {error}"),
            }
        }
    })
    .await
    .unwrap_or_else(|error| panic!("delayed publisher did not release ownership: {error}"));
    assert!(!replacement.status().poisoned);
}

#[tokio::test]
async fn v2_accepted_commit_reports_local_recovery_requirement() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = Arc::new(V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        options.clone(),
    ));
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    let coordinator = must_repo(V2CommitCoordinator::with_options(
        Arc::clone(&repository),
        anchor.clone(),
        CommitCoordinatorOptions::new(1, Duration::ZERO),
    ));
    repository.fail_next_local_install_for_tests();
    let key = must_type(LogicalPath::new("snapshots/recovery-required.bin"));

    let result = coordinator
        .put_committed(
            key.clone(),
            Bytes::from_static(b"durably accepted"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(matches!(
        result,
        Err(crate::RepositoryError::AcceptedRecoveryRequired)
    ));
    assert!(coordinator.status().poisoned);
    drop(coordinator);
    assert!(matches!(
        V2CommitCoordinator::new(Arc::clone(&repository), anchor.clone()),
        Err(crate::RepositoryError::AcceptedRecoveryRequired)
    ));

    let fresh = V2Repository::new(store, keyring, RepositoryOptions::default(), options);
    must_repo(fresh.load_chain_from_anchor(&anchor).await);
    assert_eq!(must_repo(fresh.head(&key)).content_len, 16);
}

#[tokio::test]
async fn v2_direct_accepted_commit_reports_local_recovery_requirement() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        options.clone(),
    );
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    repository.fail_next_local_install_for_tests();
    let key = must_type(LogicalPath::new("snapshots/direct-recovery-required.bin"));

    let result = repository
        .put_committed(
            &anchor,
            key.clone(),
            Bytes::from_static(b"durably accepted"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(matches!(
        result,
        Err(crate::RepositoryError::AcceptedRecoveryRequired)
    ));

    let fresh = V2Repository::new(store, keyring, RepositoryOptions::default(), options);
    must_repo(fresh.load_chain_from_anchor(&anchor).await);
    assert_eq!(must_repo(fresh.head(&key)).content_len, 16);
}

#[tokio::test]
async fn v2_commit_coordinator_packs_sixty_four_small_objects_with_bounded_amplification() {
    const OBJECT_COUNT: usize = 64;
    const OBJECT_BYTES: usize = 512;

    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = Arc::new(V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        options.clone(),
    ));
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    let coordinator = Arc::new(must_repo(V2CommitCoordinator::with_options(
        Arc::clone(&repository),
        anchor.clone(),
        CommitCoordinatorOptions::new(OBJECT_COUNT, Duration::from_secs(60)),
    )));
    let mut writes = tokio::task::JoinSet::new();
    for ordinal in 0..OBJECT_COUNT {
        let coordinator = Arc::clone(&coordinator);
        writes.spawn(async move {
            coordinator
                .put_committed(
                    must_type(LogicalPath::new(format!(
                        "small/{ordinal:02}/{}",
                        "x".repeat(23)
                    ))),
                    Bytes::from(vec![ordinal as u8; OBJECT_BYTES]),
                    RepositoryPutOptions::default(),
                )
                .await
        });
    }
    while let Some(write) = writes.join_next().await {
        must_repo(write.unwrap_or_else(|error| panic!("{error}")));
    }

    let accepted = must_v2(anchor.read_v2().await).expect("v2 anchor should exist");
    let metadata = store
        .head_at(&accepted.commit_key, accepted.version_id.as_ref())
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let logical_bytes =
        u64::try_from(OBJECT_COUNT * OBJECT_BYTES).unwrap_or_else(|error| panic!("{error}"));
    assert!(
        metadata.content_len <= logical_bytes.saturating_mul(3) / 2,
        "stored={} logical={logical_bytes}",
        metadata.content_len
    );
    let fresh = V2Repository::new(store, keyring, RepositoryOptions::default(), options);
    let chain =
        must_repo(fresh.load_chain_from_anchor(&anchor).await).expect("v2 chain should exist");
    let sections = &chain.commits_newest_first[0]
        .parsed_header
        .header
        .section_index;
    assert_eq!(
        sections
            .iter()
            .filter(|section| section.section_type == V2SectionType::PayloadPack)
            .count(),
        1
    );
    assert_eq!(
        sections
            .iter()
            .filter(|section| section.section_type == V2SectionType::IndexRun)
            .count(),
        1
    );
}

#[tokio::test]
async fn v2_commit_retention_covers_strongest_staged_object() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = Arc::new(V2Repository::new(
        store.clone(),
        keyring,
        RepositoryOptions::default(),
        options,
    ));
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    let coordinator = Arc::new(must_repo(V2CommitCoordinator::with_options(
        Arc::clone(&repository),
        anchor.clone(),
        CommitCoordinatorOptions::new(2, Duration::from_secs(60)),
    )));

    let weak = {
        let coordinator = Arc::clone(&coordinator);
        async move {
            coordinator
                .put_committed(
                    LogicalPath::new("snapshots/weak-retention.bin")
                        .unwrap_or_else(|error| panic!("{error}")),
                    Bytes::from_static(b"weak"),
                    RepositoryPutOptions {
                        retention: Some(RetentionPolicy::new(RetentionMode::Governance, 1)),
                        ..RepositoryPutOptions::default()
                    },
                )
                .await
        }
    };
    let strong = {
        let coordinator = Arc::clone(&coordinator);
        async move {
            coordinator
                .put_committed(
                    LogicalPath::new("snapshots/strong-retention.bin")
                        .unwrap_or_else(|error| panic!("{error}")),
                    Bytes::from_static(b"strong"),
                    RepositoryPutOptions {
                        retention: Some(RetentionPolicy::new(RetentionMode::Compliance, 30)),
                        legal_hold: Some(LegalHoldStatus::On),
                        ..RepositoryPutOptions::default()
                    },
                )
                .await
        }
    };

    let (weak, strong) = tokio::join!(weak, strong);
    must_repo(weak);
    must_repo(strong);
    let accepted = must_v2(anchor.read_v2().await).expect("v2 anchor should exist");
    let metadata = store
        .head_at(&accepted.commit_key, accepted.version_id.as_ref())
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(
        metadata.retention,
        Some(RetentionPolicy::new(RetentionMode::Compliance, 30))
    );
    assert_eq!(metadata.legal_hold, Some(LegalHoldStatus::On));
}

#[tokio::test]
async fn v2_commit_coordinator_rolls_back_batch_after_anchor_failure() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = Arc::new(V2Repository::new(
        store,
        keyring,
        RepositoryOptions::default(),
        options,
    ));
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    let coordinator = Arc::new(must_repo(V2CommitCoordinator::with_options(
        Arc::clone(&repository),
        FailOnceV2Anchor::new(anchor.clone()),
        CommitCoordinatorOptions::new(2, Duration::from_secs(60)),
    )));
    let first_key =
        LogicalPath::new("snapshots/v2-failed-a.bin").unwrap_or_else(|error| panic!("{error}"));
    let second_key =
        LogicalPath::new("snapshots/v2-failed-b.bin").unwrap_or_else(|error| panic!("{error}"));

    let first = {
        let coordinator = Arc::clone(&coordinator);
        let key = first_key.clone();
        async move {
            coordinator
                .put_committed(
                    key,
                    Bytes::from_static(b"failed-a"),
                    RepositoryPutOptions::default(),
                )
                .await
        }
    };
    let second = {
        let coordinator = Arc::clone(&coordinator);
        let key = second_key.clone();
        async move {
            coordinator
                .put_committed(
                    key,
                    Bytes::from_static(b"failed-b"),
                    RepositoryPutOptions::default(),
                )
                .await
        }
    };

    let (first, second) = tokio::join!(first, second);
    assert!(!coordinator.status().poisoned);

    let later_key =
        LogicalPath::new("snapshots/v2-later.bin").unwrap_or_else(|error| panic!("{error}"));
    let later = must_repo(
        coordinator
            .put_committed(
                later_key.clone(),
                Bytes::from_static(b"later"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    let accepted = must_v2(anchor.read_v2().await).expect("v2 later anchor should be accepted");

    assert!(matches!(
        first,
        Err(crate::RepositoryError::CommitFailed { .. })
    ));
    assert!(matches!(
        second,
        Err(crate::RepositoryError::CommitFailed { .. })
    ));
    assert_eq!(later.anchor_state, accepted);
    assert_eq!(accepted.sequence, Sequence::new(2));
    assert!(!coordinator.status().poisoned);
    assert!(coordinator.status().poison_reason.is_none());
    assert!(matches!(
        repository.head(&first_key),
        Err(crate::RepositoryError::NotFound(_))
    ));
    assert!(matches!(
        repository.head(&second_key),
        Err(crate::RepositoryError::NotFound(_))
    ));
    assert!(repository.head(&later_key).is_ok());
}

#[tokio::test]
async fn v2_commit_coordinator_recovers_after_transient_publish_failure() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = Arc::new(V2Repository::new(
        store,
        keyring,
        RepositoryOptions::default(),
        options,
    ));
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    let coordinator = must_repo(V2CommitCoordinator::with_options(
        Arc::clone(&repository),
        FailOnceV2Anchor::new(anchor.clone()),
        CommitCoordinatorOptions::new(1, Duration::from_secs(60)),
    ));
    let failed_key = LogicalPath::new("snapshots/v2-transient-failed.bin")
        .unwrap_or_else(|error| panic!("{error}"));

    let failed = coordinator
        .put_committed(
            failed_key.clone(),
            Bytes::from_static(b"transient-failed"),
            RepositoryPutOptions::default(),
        )
        .await;
    let failed_status = coordinator.status();

    assert!(matches!(
        failed,
        Err(crate::RepositoryError::CommitFailed { .. })
    ));
    assert!(!failed_status.poisoned);
    assert!(failed_status.poison_reason.is_none());
    assert!(matches!(
        repository.head(&failed_key),
        Err(crate::RepositoryError::NotFound(_))
    ));

    let recovered_key = LogicalPath::new("snapshots/v2-transient-recovered.bin")
        .unwrap_or_else(|error| panic!("{error}"));
    let recovered = must_repo(
        coordinator
            .put_committed(
                recovered_key.clone(),
                Bytes::from_static(b"transient-recovered"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    let accepted = must_v2(anchor.read_v2().await).expect("v2 recovered anchor should be accepted");
    let recovered_status = coordinator.status();

    assert_eq!(recovered.anchor_state, accepted);
    assert_eq!(accepted.sequence, Sequence::new(2));
    assert!(!recovered_status.poisoned);
    assert!(recovered_status.poison_reason.is_none());
    assert!(repository.head(&recovered_key).is_ok());
}

#[tokio::test]
async fn v2_commit_coordinator_rollback_restores_overwritten_object() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = Arc::new(V2Repository::new(
        store,
        keyring,
        RepositoryOptions::default(),
        options,
    ));
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    let key = LogicalPath::new("snapshots/v2-overwrite-rollback.bin")
        .unwrap_or_else(|error| panic!("{error}"));
    must_repo(
        repository
            .put_committed(
                &anchor,
                key.clone(),
                Bytes::from_static(b"accepted"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    let coordinator = must_repo(V2CommitCoordinator::with_options(
        Arc::clone(&repository),
        FailOnceV2Anchor::new(anchor.clone()),
        CommitCoordinatorOptions::new(1, Duration::from_secs(1)),
    ));

    let failed = coordinator
        .put_committed(
            key.clone(),
            Bytes::from_static(b"unaccepted"),
            RepositoryPutOptions::default(),
        )
        .await;

    assert!(matches!(
        failed,
        Err(crate::RepositoryError::CommitFailed { .. })
    ));
    assert_eq!(
        must_repo(repository.get_range(&key, ByteRange::Full).await),
        Bytes::from_static(b"accepted")
    );
    assert_eq!(must_repo(repository.list("snapshots/")).len(), 1);
}

#[tokio::test]
async fn v2_commit_coordinator_poisons_when_batch_rollback_fails() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = Arc::new(V2Repository::new(
        store,
        keyring,
        RepositoryOptions::default(),
        options,
    ));
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    repository.fail_next_restore_for_tests();
    let coordinator = Arc::new(must_repo(V2CommitCoordinator::with_options(
        Arc::clone(&repository),
        FailOnceV2Anchor::new(anchor.clone()),
        CommitCoordinatorOptions::new(2, Duration::from_secs(60)),
    )));
    let first_key =
        LogicalPath::new("snapshots/v2-poison-a.bin").unwrap_or_else(|error| panic!("{error}"));
    let second_key =
        LogicalPath::new("snapshots/v2-poison-b.bin").unwrap_or_else(|error| panic!("{error}"));

    let first = {
        let coordinator = Arc::clone(&coordinator);
        let key = first_key;
        async move {
            coordinator
                .put_committed(
                    key,
                    Bytes::from_static(b"poison-a"),
                    RepositoryPutOptions::default(),
                )
                .await
        }
    };
    let second = {
        let coordinator = Arc::clone(&coordinator);
        let key = second_key;
        async move {
            coordinator
                .put_committed(
                    key,
                    Bytes::from_static(b"poison-b"),
                    RepositoryPutOptions::default(),
                )
                .await
        }
    };

    let (first, second) = tokio::join!(first, second);
    let later = coordinator
        .put_committed(
            LogicalPath::new("snapshots/v2-poison-later.bin")
                .unwrap_or_else(|error| panic!("{error}")),
            Bytes::from_static(b"poison-later"),
            RepositoryPutOptions::default(),
        )
        .await;
    let accepted = must_v2(anchor.read_v2().await).expect("v2 genesis anchor should remain");
    let status = coordinator.status();

    assert!(matches!(
        first,
        Err(crate::RepositoryError::CommitFailed { .. })
    ));
    assert!(matches!(
        second,
        Err(crate::RepositoryError::CommitFailed { .. })
    ));
    assert!(matches!(
        later,
        Err(crate::RepositoryError::CommitFailed { .. })
    ));
    assert_eq!(accepted.sequence, Sequence::new(1));
    assert!(status.poisoned);
    let poison_reason = status
        .poison_reason
        .unwrap_or_else(|| panic!("poison reason should be recorded"));
    assert!(poison_reason.contains("rollback failed"));
    assert!(poison_reason.contains("repository state lock poisoned"));
}

#[tokio::test]
async fn v2_commit_coordinator_applies_backpressure_before_payload_write() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = Arc::new(V2Repository::new(
        store.clone(),
        keyring,
        RepositoryOptions::default(),
        options,
    ));
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    let coordinator = Arc::new(must_repo(V2CommitCoordinator::with_options(
        Arc::clone(&repository),
        anchor.clone(),
        CommitCoordinatorOptions::new(8, Duration::from_secs(60)).with_max_pending_items(1),
    )));
    let first_key = LogicalPath::new("snapshots/v2-backpressure-first.bin")
        .unwrap_or_else(|error| panic!("{error}"));

    let first = {
        let coordinator = Arc::clone(&coordinator);
        let key = first_key.clone();
        tokio::spawn(async move {
            coordinator
                .put_committed(
                    key,
                    Bytes::from_static(b"first"),
                    RepositoryPutOptions::default(),
                )
                .await
        })
    };

    for _ in 0..100 {
        if repository.head(&first_key).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    let rejected = coordinator
        .put_committed(
            LogicalPath::new("snapshots/v2-backpressure-rejected.bin")
                .unwrap_or_else(|error| panic!("{error}")),
            Bytes::from_static(b"rejected"),
            RepositoryPutOptions::default(),
        )
        .await;
    let commits_after_rejection = must_v2(
        store
            .list_prefix("commits/v02/")
            .await
            .map_err(|_| V2FormatError::StorageOperationFailed),
    );
    must_repo(coordinator.write_index_snapshot().await);
    let first = tokio::time::timeout(Duration::from_secs(1), first).await;

    assert!(matches!(
        rejected,
        Err(crate::RepositoryError::CommitBackpressure)
    ));
    assert_eq!(commits_after_rejection.len(), 1);
    match first {
        Ok(joined) => assert!(matches!(joined, Ok(Ok(_)))),
        Err(error) => panic!("{error}"),
    }
}

#[tokio::test]
async fn v2_commit_coordinator_round_trips_128_writes_across_reload() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = Arc::new(V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        options.clone(),
    ));
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    let coordinator = Arc::new(must_repo(V2CommitCoordinator::with_options(
        Arc::clone(&repository),
        anchor.clone(),
        CommitCoordinatorOptions::new(32, Duration::from_secs(1)),
    )));

    for batch in 0..4 {
        let mut writes = tokio::task::JoinSet::new();
        for item in 0..32 {
            let coordinator = Arc::clone(&coordinator);
            writes.spawn(async move {
                let key = LogicalPath::new(format!("snapshots/scale-{batch:02}-{item:02}.bin"))
                    .unwrap_or_else(|error| panic!("{error}"));
                coordinator
                    .put_committed(
                        key,
                        Bytes::from_static(b"x"),
                        RepositoryPutOptions::default(),
                    )
                    .await
            });
        }
        while let Some(result) = writes.join_next().await {
            match result {
                Ok(result) => {
                    must_repo(result);
                }
                Err(error) => panic!("{error}"),
            }
        }
    }

    assert_eq!(must_repo(repository.list("snapshots/")).len(), 128);
    let fresh = V2Repository::new(store, keyring, RepositoryOptions::default(), options);
    must_repo(fresh.load_chain_from_anchor(&anchor).await);
    assert_eq!(must_repo(fresh.list("snapshots/")).len(), 128);
}

#[tokio::test]
async fn v2_index_snapshot_bounds_replay_and_preserves_namespace() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        options.clone(),
    );
    let anchor = V2MemoryAnchor::new();
    let first_key =
        LogicalPath::new("snapshots/v2-snapshot-a.bin").unwrap_or_else(|error| panic!("{error}"));
    let second_key =
        LogicalPath::new("snapshots/v2-snapshot-b.bin").unwrap_or_else(|error| panic!("{error}"));
    let third_key =
        LogicalPath::new("snapshots/v2-snapshot-c.bin").unwrap_or_else(|error| panic!("{error}"));

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(
        repository
            .put_committed(
                &anchor,
                first_key.clone(),
                Bytes::from_static(b"first"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    must_repo(
        repository
            .put_committed(
                &anchor,
                second_key.clone(),
                Bytes::from_static(b"second"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    let snapshot = must_repo(repository.write_index_snapshot(&anchor).await);
    assert_eq!(snapshot.anchor_state.sequence, Sequence::new(4));
    must_repo(
        repository
            .put_committed(
                &anchor,
                third_key.clone(),
                Bytes::from_static(b"third"),
                RepositoryPutOptions::default(),
            )
            .await,
    );

    let fresh = V2Repository::new(store, keyring, RepositoryOptions::default(), options);
    let chain = must_repo(fresh.load_chain_from_anchor(&anchor).await)
        .expect("v2 chain should load from latest snapshot");
    let listed = must_repo(fresh.list("snapshots/"));
    let third_body = must_repo(fresh.get_range(&third_key, ByteRange::Full).await);

    assert_eq!(chain.commits_newest_first.len(), 2);
    assert_eq!(
        chain.commits_newest_first[0].parsed_header.header.kind,
        V2CommitKind::Delta
    );
    assert_eq!(
        chain.commits_newest_first[1].parsed_header.header.kind,
        V2CommitKind::Root
    );
    assert_eq!(third_body, Bytes::from_static(b"third"));
    assert_eq!(
        listed
            .into_iter()
            .map(|entry| entry.key)
            .collect::<Vec<_>>(),
        vec![first_key, second_key, third_key]
    );
}

#[tokio::test]
async fn v2_index_root_recovery_rejects_tampered_exact_catalog_run() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        options.clone(),
    );
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(
        repository
            .put_committed(
                &anchor,
                must_type(LogicalPath::new("roots/exact-run")),
                Bytes::from_static(b"catalog run payload"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    let run_anchor = must_v2(anchor.read_v2().await).expect("run head should be anchored");
    must_repo(repository.write_index_snapshot(&anchor).await);
    store.corrupt_ranged_commit_gets_for(run_anchor.commit_key);

    let fresh = V2Repository::new(store, keyring, RepositoryOptions::default(), options);
    assert!(matches!(
        fresh.load_chain_from_anchor(&anchor).await,
        Err(RepositoryError::CommitFailed { .. })
    ));
}

#[tokio::test]
async fn v2_orphan_gc_keeps_live_payload_commits_referenced_by_index_snapshot() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        options.clone(),
    );
    let anchor = V2MemoryAnchor::new();
    let first_key = must_type(LogicalPath::new("snapshots/gc-live-first.bin"));
    let second_key = must_type(LogicalPath::new("snapshots/gc-live-second.bin"));
    let first_body = Bytes::from_static(b"live payload before snapshot one");
    let second_body = Bytes::from_static(b"live payload before snapshot two");

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(
        repository
            .put_committed(
                &anchor,
                first_key.clone(),
                first_body.clone(),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    must_repo(
        repository
            .put_committed(
                &anchor,
                second_key.clone(),
                second_body.clone(),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    let before_snapshot = must_v2(
        repository
            .commit_store()
            .load_chain_from_anchor(&anchor)
            .await,
    )
    .expect("v2 chain should exist before snapshot");
    let pre_snapshot_payload_commits = before_snapshot
        .commits_newest_first
        .iter()
        .filter(|commit| {
            commit
                .parsed_header
                .header
                .section_index
                .iter()
                .any(|section| section.section_type == V2SectionType::PayloadPack)
        })
        .map(|commit| commit.parsed_header.header.self_ref.commit_key.clone())
        .collect::<Vec<_>>();

    must_repo(repository.write_index_snapshot(&anchor).await);

    let report = must_v2(repository.commit_store().report_orphans(&anchor).await);
    let candidates = report
        .candidates
        .iter()
        .map(|candidate| candidate.object_id.clone())
        .collect::<Vec<_>>();
    let gc = must_v2(
        repository
            .commit_store()
            .delete_expired_orphans(
                &anchor,
                &UnenforcedQuiescedMaintenanceGuard,
                V2OrphanGcOptions::new_for_test_rehearsal(Duration::ZERO),
            )
            .await,
    );
    let fresh = V2Repository::new(store, keyring, RepositoryOptions::default(), options);
    must_repo(fresh.load_chain_from_anchor(&anchor).await);

    for commit_key in pre_snapshot_payload_commits {
        assert!(!candidates.contains(&commit_key));
    }
    assert!(gc.deleted_count > 0);
    assert_eq!(
        must_repo(fresh.get_range(&first_key, ByteRange::Full).await),
        first_body
    );
    assert_eq!(
        must_repo(fresh.get_range(&second_key, ByteRange::Full).await),
        second_body
    );
}

#[tokio::test]
async fn v2_index_snapshot_allows_repeated_exact_catalog_checkpoints() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2Repository::new(store, keyring, RepositoryOptions::default(), options);
    let anchor = V2MemoryAnchor::new();
    let key = must_type(LogicalPath::new("snapshots/repeated-index-snapshot.bin"));

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(
        repository
            .put_committed(
                &anchor,
                key,
                Bytes::from_static(b"live payload before repeated snapshot"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    must_repo(repository.write_index_snapshot(&anchor).await);

    let repeated = must_repo(repository.write_index_snapshot(&anchor).await);
    assert_eq!(repeated.anchor_state.sequence, Sequence::new(4));
}

#[tokio::test]
async fn v2_writer_stops_before_the_run_catalog_becomes_uncheckpointable() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2Repository::new(store, keyring, RepositoryOptions::default(), options);
    let anchor = V2MemoryAnchor::new();
    let accepted_key = must_type(LogicalPath::new("catalog/accepted"));
    let rejected_key = must_type(LogicalPath::new("catalog/rejected"));

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(
        repository
            .put_committed(
                &anchor,
                accepted_key.clone(),
                Bytes::from_static(b"accepted"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    must_repo(repository.fill_accepted_run_catalog_for_tests());
    let accepted_anchor = must_v2(anchor.read_v2().await);

    let rejected = repository
        .put_committed(
            &anchor,
            rejected_key,
            Bytes::from_static(b"rejected"),
            RepositoryPutOptions::default(),
        )
        .await;

    assert!(matches!(
        rejected,
        Err(RepositoryError::CommitFailed { reason })
            if reason.contains("index root limit exceeded")
    ));
    assert_eq!(must_v2(anchor.read_v2().await), accepted_anchor);
    assert_eq!(
        must_repo(repository.list("catalog/"))
            .into_iter()
            .map(|entry| entry.key)
            .collect::<Vec<_>>(),
        vec![accepted_key]
    );
}

#[tokio::test]
async fn v2_concurrent_writers_cas_without_losing_the_winner() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let first = V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        options.clone(),
    );
    let second = V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        options.clone(),
    );
    let anchor = V2MemoryAnchor::new();
    must_repo(first.write_genesis_snapshot(&anchor).await);
    must_repo(second.load_chain_from_anchor(&anchor).await);

    let first_key = must_type(LogicalPath::new("writers/first"));
    let second_key = must_type(LogicalPath::new("writers/second"));
    let (first_result, second_result) = tokio::join!(
        first.put_committed(
            &anchor,
            first_key.clone(),
            Bytes::from_static(b"first writer"),
            RepositoryPutOptions::default(),
        ),
        second.put_committed(
            &anchor,
            second_key.clone(),
            Bytes::from_static(b"second writer"),
            RepositoryPutOptions::default(),
        )
    );
    assert_ne!(first_result.is_ok(), second_result.is_ok());
    let loser_was_stale = [first_result.as_ref(), second_result.as_ref()]
        .into_iter()
        .filter_map(|result| result.err())
        .all(|error| {
            matches!(error, RepositoryError::CommitFailed { reason } if reason.contains("stale"))
        });
    assert!(loser_was_stale);

    let retry_repository = if first_result.is_err() {
        &first
    } else {
        &second
    };
    let retry_key = if first_result.is_err() {
        first_key
    } else {
        second_key
    };
    must_repo(retry_repository.load_chain_from_anchor(&anchor).await);
    must_repo(
        retry_repository
            .put_committed(
                &anchor,
                retry_key,
                Bytes::from_static(b"retried writer"),
                RepositoryPutOptions::default(),
            )
            .await,
    );

    let fresh = V2Repository::new(store, keyring, RepositoryOptions::default(), options);
    let chain = must_repo(fresh.load_chain_from_anchor(&anchor).await);
    assert!(chain.is_some());
    assert_eq!(must_repo(fresh.list_page("writers/", None, 10)).len(), 2);
}

#[tokio::test]
async fn v2_commit_coordinator_flushes_before_index_snapshot() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = Arc::new(V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        options.clone(),
    ));
    let anchor = V2MemoryAnchor::new();
    let key = LogicalPath::new("snapshots/v2-coordinator-snapshot.bin")
        .unwrap_or_else(|error| panic!("{error}"));

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    let coordinator = Arc::new(must_repo(V2CommitCoordinator::with_options(
        Arc::clone(&repository),
        anchor.clone(),
        CommitCoordinatorOptions::new(8, Duration::from_secs(60)),
    )));
    let pending = {
        let coordinator = Arc::clone(&coordinator);
        let key = key.clone();
        tokio::spawn(async move {
            coordinator
                .put_committed(
                    key,
                    Bytes::from_static(b"pending"),
                    RepositoryPutOptions::default(),
                )
                .await
        })
    };
    tokio::task::yield_now().await;

    let snapshot = must_repo(coordinator.write_index_snapshot().await);
    let pending = tokio::time::timeout(Duration::from_secs(1), pending).await;
    let fresh = V2Repository::new(store, keyring, RepositoryOptions::default(), options);
    let chain = must_repo(fresh.load_chain_from_anchor(&anchor).await)
        .expect("v2 chain should load after coordinator snapshot");
    let body = must_repo(fresh.get_range(&key, ByteRange::Full).await);

    match pending {
        Ok(joined) => assert!(matches!(joined, Ok(Ok(_)))),
        Err(error) => panic!("{error}"),
    }
    assert_eq!(snapshot.sequence, Sequence::new(3));
    assert_eq!(chain.commits_newest_first.len(), 1);
    assert_eq!(
        chain.commits_newest_first[0].parsed_header.header.kind,
        V2CommitKind::Root
    );
    assert_eq!(body, Bytes::from_static(b"pending"));
}

#[tokio::test]
async fn v2_orphan_gc_deletes_expired_unprotected_commit() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2CommitStore::new(store.clone(), keyring, options);
    let anchor = V2MemoryAnchor::new();

    must_v2(repository.write_genesis_snapshot(&anchor).await);
    let failed = repository
        .write_child_commit(
            &FailOnceV2Anchor::new(anchor.clone()),
            V2CommitWrite::delta(vec![V2CommitSection::new(
                V2SectionType::IndexDelta,
                0,
                Bytes::from_static(b"orphan-delta"),
            )]),
        )
        .await;
    let before = must_v2(repository.report_orphans(&anchor).await);
    let gc = must_v2(
        repository
            .delete_expired_orphans(
                &anchor,
                &UnenforcedQuiescedMaintenanceGuard,
                V2OrphanGcOptions::new_for_test_rehearsal(Duration::ZERO),
            )
            .await,
    );
    let after = must_v2(repository.report_orphans(&anchor).await);

    assert!(matches!(failed, Err(V2FormatError::AnchorAdvanceFailed)));
    assert_eq!(before.candidates.len(), 1);
    assert_eq!(gc.scanned_count, 1);
    assert_eq!(gc.deleted_count, 1);
    assert_eq!(after.candidates.len(), 0);
}

#[test]
fn v2_orphan_gc_options_rejects_sub_hour_production_min_age() {
    assert_eq!(
        V2OrphanGcOptions::new(Duration::ZERO),
        Err(V2FormatError::OrphanGcMinAgeTooLow)
    );
    assert!(matches!(
        V2OrphanGcOptions::new(Duration::from_secs(60 * 60)),
        Ok(options) if options.min_age == Duration::from_secs(60 * 60)
    ));
}

#[tokio::test]
async fn v2_orphan_gc_skips_retained_or_held_candidates() {
    let retained_store = MemoryBlobStore::new();
    let retained_options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::RetainedVersionObjectLock,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    )
    .with_retention(Some(RetentionPolicy::new(RetentionMode::Compliance, 30)));
    let retained = V2CommitStore::new(retained_store.clone(), signing_keyring(), retained_options);
    let retained_anchor = V2MemoryAnchor::new();

    must_v2(retained.write_genesis_snapshot(&retained_anchor).await);
    let retained_failed = retained
        .write_child_commit(
            &FailOnceV2Anchor::new(retained_anchor.clone()),
            V2CommitWrite::delta(vec![V2CommitSection::new(
                V2SectionType::IndexDelta,
                0,
                Bytes::from_static(b"retained-orphan"),
            )]),
        )
        .await;
    let retained_gc = must_v2(
        retained
            .delete_expired_orphans(
                &retained_anchor,
                &UnenforcedQuiescedMaintenanceGuard,
                V2OrphanGcOptions::new_for_test_rehearsal(Duration::ZERO)
                    .with_same_sequence_deletion(true),
            )
            .await,
    );
    let retained_after = must_v2(retained.report_orphans(&retained_anchor).await);

    assert!(matches!(
        retained_failed,
        Err(V2FormatError::AnchorAdvanceFailed)
    ));
    assert_eq!(retained_gc.protected_count, 1);
    assert_eq!(retained_gc.deleted_count, 0);
    assert_eq!(retained_after.candidates.len(), 1);

    let held_store = MemoryBlobStore::new();
    let held_options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    )
    .with_legal_hold(Some(LegalHoldStatus::On));
    let held = V2CommitStore::new(held_store, signing_keyring(), held_options);
    let held_anchor = V2MemoryAnchor::new();

    must_v2(held.write_genesis_snapshot(&held_anchor).await);
    let held_failed = held
        .write_child_commit(
            &FailOnceV2Anchor::new(held_anchor.clone()),
            V2CommitWrite::delta(vec![V2CommitSection::new(
                V2SectionType::IndexDelta,
                0,
                Bytes::from_static(b"held-orphan"),
            )]),
        )
        .await;
    let held_gc = must_v2(
        held.delete_expired_orphans(
            &held_anchor,
            &UnenforcedQuiescedMaintenanceGuard,
            V2OrphanGcOptions::new_for_test_rehearsal(Duration::ZERO)
                .with_same_sequence_deletion(true),
        )
        .await,
    );
    let held_after = must_v2(held.report_orphans(&held_anchor).await);

    assert!(matches!(
        held_failed,
        Err(V2FormatError::AnchorAdvanceFailed)
    ));
    assert_eq!(held_gc.protected_count, 1);
    assert_eq!(held_gc.deleted_count, 0);
    assert_eq!(held_after.candidates.len(), 1);
}

#[tokio::test]
async fn v2_full_gc_dry_run_reports_unanchored_commit_budget() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2CommitStore::new(store, keyring, options);
    let anchor = V2MemoryAnchor::new();

    let genesis = must_v2(repository.write_genesis_snapshot(&anchor).await);
    let failed = repository
        .write_child_commit(
            &FailOnceV2Anchor::new(anchor.clone()),
            V2CommitWrite::delta(vec![V2CommitSection::new(
                V2SectionType::IndexDelta,
                0,
                Bytes::from_static(b"dry-run-orphan"),
            )]),
        )
        .await;
    let report = must_v2(
        repository
            .full_gc_dry_run(
                &anchor,
                V2FullGcDryRunOptions {
                    budgets: V2MaintenanceBudgets {
                        max_delete_count: Some(0),
                        ..V2MaintenanceBudgets::default()
                    },
                    ..V2FullGcDryRunOptions::default()
                },
            )
            .await,
    );

    assert!(matches!(failed, Err(V2FormatError::AnchorAdvanceFailed)));
    assert_eq!(report.base_sequence, Some(genesis.anchor_state.sequence));
    assert_eq!(report.chain_live_commit_count, 1);
    assert_eq!(report.candidate_commit_count, 1);
    assert_eq!(report.fully_dead_commit_count, 1);
    assert_eq!(report.mixed_commit_count, 0);
    assert!(report.dead_bytes_reclaimable > 0);
    assert_eq!(report.planned_cost.delete_count, 1);
    assert!(!report.fits_budgets);
    assert!(report.exact_version_apply_ready);
}

#[tokio::test]
async fn retained_v2_full_gc_dry_run_reports_version_inventory_and_blocked_bytes() {
    let store = MemoryBlobStore::new();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::RetainedVersionObjectLock,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    )
    .with_retention(Some(RetentionPolicy::new(RetentionMode::Compliance, 30)));
    let repository = V2CommitStore::new(store, signing_keyring(), options);
    let anchor = V2MemoryAnchor::new();

    must_v2(repository.write_genesis_snapshot(&anchor).await);
    let failed = repository
        .write_child_commit(
            &FailOnceV2Anchor::new(anchor.clone()),
            V2CommitWrite::delta(vec![V2CommitSection::new(
                V2SectionType::IndexDelta,
                0,
                Bytes::from_static(b"retained-dry-run-orphan"),
            )]),
        )
        .await;
    let report = must_v2(
        repository
            .full_gc_dry_run(&anchor, V2FullGcDryRunOptions::default())
            .await,
    );

    assert!(matches!(failed, Err(V2FormatError::AnchorAdvanceFailed)));
    assert_eq!(report.candidate_commit_count, 1);
    assert_eq!(report.fully_dead_commit_count, 0);
    assert_eq!(report.dead_bytes_reclaimable, 0);
    assert!(report.retention_blocked_bytes > 0);
    assert_eq!(report.planned_cost.version_list_count, 1);
    assert_eq!(report.planned_cost.head_count, 2);
    assert_eq!(report.planned_cost.delete_count, 0);
    assert_eq!(report.planned_cost.retention_extend_count, 0);
    assert!(report.fits_budgets);
    assert!(report.exact_version_apply_ready);
}

#[tokio::test]
async fn retained_v2_full_gc_dry_run_plans_live_commit_retention_renewal() {
    let store = MemoryBlobStore::new();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::RetainedVersionObjectLock,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    )
    .with_retention(Some(RetentionPolicy::new(RetentionMode::Compliance, 30)));
    let repository = V2CommitStore::new(store, signing_keyring(), options);
    let anchor = V2MemoryAnchor::new();

    must_v2(repository.write_genesis_snapshot(&anchor).await);
    must_v2(
        repository
            .write_child_commit(
                &anchor,
                V2CommitWrite::delta(vec![V2CommitSection::new(
                    V2SectionType::IndexDelta,
                    0,
                    Bytes::from_static(b"retention-renewal-live-commit"),
                )]),
            )
            .await,
    );

    let default_report = must_v2(
        repository
            .full_gc_dry_run(&anchor, V2FullGcDryRunOptions::default())
            .await,
    );
    let renewal_report = must_v2(
        repository
            .full_gc_dry_run(
                &anchor,
                V2FullGcDryRunOptions {
                    budgets: V2MaintenanceBudgets {
                        max_retention_extend_count: Some(1),
                        ..V2MaintenanceBudgets::default()
                    },
                    retention_renewal_horizon: Duration::from_secs(31 * 24 * 60 * 60),
                    ..V2FullGcDryRunOptions::default()
                },
            )
            .await,
    );

    assert_eq!(default_report.retention_renewal_commit_count, 0);
    assert_eq!(default_report.planned_cost.retention_extend_count, 0);
    assert_eq!(renewal_report.chain_live_commit_count, 2);
    assert_eq!(renewal_report.retention_renewal_commit_count, 2);
    assert!(renewal_report.retention_renewal_bytes > 0);
    assert_eq!(renewal_report.retention_renewal_blocked_count, 0);
    assert_eq!(renewal_report.planned_cost.retention_extend_count, 2);
    assert_eq!(renewal_report.planned_cost.head_count, 2);
    assert!(!renewal_report.fits_budgets);
}

#[tokio::test]
async fn retained_v2_full_gc_dry_run_plans_protected_root_retention_renewal() {
    let store = MemoryBlobStore::new();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::RetainedVersionObjectLock,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    )
    .with_retention(Some(RetentionPolicy::new(RetentionMode::Compliance, 30)));
    let repository = V2CommitStore::new(store, signing_keyring(), options);
    let anchor = V2MemoryAnchor::new();

    must_v2(repository.write_genesis_snapshot(&anchor).await);
    must_v2(
        repository
            .write_child_commit(
                &anchor,
                V2CommitWrite::delta(vec![V2CommitSection::new(
                    V2SectionType::IndexDelta,
                    0,
                    Bytes::from_static(b"retained-historical-root-delta"),
                )]),
            )
            .await,
    );
    let historical_root =
        must_v2(anchor.read_v2().await).expect("retained historical root should exist");
    must_v2(
        repository
            .write_child_commit(
                &anchor,
                V2CommitWrite::snapshot(vec![V2CommitSection::new(
                    V2SectionType::IndexSnapshot,
                    0,
                    Bytes::new(),
                )]),
            )
            .await,
    );

    let report = must_v2(
        repository
            .full_gc_dry_run(
                &anchor,
                V2FullGcDryRunOptions {
                    retention_renewal_horizon: Duration::from_secs(31 * 24 * 60 * 60),
                    protected_roots: vec![historical_root],
                    ..V2FullGcDryRunOptions::default()
                },
            )
            .await,
    );

    assert_eq!(report.chain_live_commit_count, 1);
    assert_eq!(report.protected_root_count, 1);
    assert_eq!(report.protected_commit_count, 2);
    assert_eq!(report.candidate_commit_count, 0);
    assert_eq!(report.retention_renewal_commit_count, 3);
    assert_eq!(report.planned_cost.head_count, 3);
    assert_eq!(report.planned_cost.retention_extend_count, 3);
}

#[tokio::test]
async fn v2_full_gc_apply_requires_maintenance_guard() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2CommitStore::new(store, keyring, options);
    let anchor = V2MemoryAnchor::new();

    must_v2(repository.write_genesis_snapshot(&anchor).await);
    let failed = repository
        .write_child_commit(
            &FailOnceV2Anchor::new(anchor.clone()),
            V2CommitWrite::delta(vec![V2CommitSection::new(
                V2SectionType::IndexDelta,
                0,
                Bytes::from_static(b"guarded-orphan"),
            )]),
        )
        .await;
    let apply = repository
        .apply_fully_dead_orphans(
            &anchor,
            &RejectingMaintenanceGuard,
            V2FullGcApplyOptions {
                dry_run: V2FullGcDryRunOptions::default(),
                orphan_gc: V2OrphanGcOptions::new_for_test_rehearsal(Duration::ZERO),
                retained_provider_conformance_passed: false,
            },
        )
        .await;
    let after = must_v2(repository.report_orphans(&anchor).await);

    assert!(matches!(failed, Err(V2FormatError::AnchorAdvanceFailed)));
    assert_eq!(apply, Err(V2FormatError::MaintenanceAccessRequired));
    assert_eq!(after.candidates.len(), 1);
}

#[tokio::test]
async fn v2_full_gc_apply_deletes_only_fully_dead_orphans_after_dry_run() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2CommitStore::new(store, keyring, options);
    let anchor = V2MemoryAnchor::new();

    must_v2(repository.write_genesis_snapshot(&anchor).await);
    let failed = repository
        .write_child_commit(
            &FailOnceV2Anchor::new(anchor.clone()),
            V2CommitWrite::delta(vec![V2CommitSection::new(
                V2SectionType::IndexDelta,
                0,
                Bytes::from_static(b"apply-orphan"),
            )]),
        )
        .await;
    let apply = must_v2(
        repository
            .apply_fully_dead_orphans(
                &anchor,
                &UnenforcedQuiescedMaintenanceGuard,
                V2FullGcApplyOptions {
                    dry_run: V2FullGcDryRunOptions::default(),
                    orphan_gc: V2OrphanGcOptions::new_for_test_rehearsal(Duration::ZERO),
                    retained_provider_conformance_passed: false,
                },
            )
            .await,
    );
    let after = must_v2(repository.report_orphans(&anchor).await);

    assert!(matches!(failed, Err(V2FormatError::AnchorAdvanceFailed)));
    assert_eq!(apply.dry_run.fully_dead_commit_count, 1);
    assert_eq!(apply.orphan_gc.deleted_count, 1);
    assert_eq!(after.candidates.len(), 0);
}

#[tokio::test]
async fn v2_full_gc_apply_returns_partial_report_on_mid_pass_guard_abort() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2CommitStore::new(store, keyring, options);
    let anchor = V2MemoryAnchor::new();

    must_v2(repository.write_genesis_snapshot(&anchor).await);
    let first_failed = repository
        .write_child_commit(
            &FailOnceV2Anchor::new(anchor.clone()),
            V2CommitWrite::delta(vec![V2CommitSection::new(
                V2SectionType::IndexDelta,
                0,
                Bytes::from_static(b"partial-apply-orphan-one"),
            )]),
        )
        .await;
    let second_failed = repository
        .write_child_commit(
            &FailOnceV2Anchor::new(anchor.clone()),
            V2CommitWrite::delta(vec![V2CommitSection::new(
                V2SectionType::IndexDelta,
                0,
                Bytes::from_static(b"partial-apply-orphan-two"),
            )]),
        )
        .await;
    let guard = FailsAfterMaintenanceGuard::new(3);

    let apply = must_v2(
        repository
            .apply_fully_dead_orphans(
                &anchor,
                &guard,
                V2FullGcApplyOptions {
                    dry_run: V2FullGcDryRunOptions::default(),
                    orphan_gc: V2OrphanGcOptions::new_for_test_rehearsal(Duration::ZERO),
                    retained_provider_conformance_passed: false,
                },
            )
            .await,
    );
    let after = must_v2(repository.report_orphans(&anchor).await);

    assert!(matches!(
        first_failed,
        Err(V2FormatError::AnchorAdvanceFailed)
    ));
    assert!(matches!(
        second_failed,
        Err(V2FormatError::AnchorAdvanceFailed)
    ));
    assert_eq!(apply.dry_run.fully_dead_commit_count, 2);
    assert_eq!(apply.orphan_gc.deleted_count, 1);
    assert_eq!(
        apply.orphan_gc.aborted,
        Some(V2FormatError::MaintenanceAccessRequired)
    );
    assert_eq!(after.candidates.len(), 1);
}

#[tokio::test]
async fn v2_full_gc_apply_preserves_supplied_historical_roots() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2CommitStore::new(store, keyring, options);
    let anchor = V2MemoryAnchor::new();

    must_v2(repository.write_genesis_snapshot(&anchor).await);
    must_v2(
        repository
            .write_child_commit(
                &anchor,
                V2CommitWrite::delta(vec![V2CommitSection::new(
                    V2SectionType::IndexDelta,
                    0,
                    Bytes::from_static(b"historical-root-delta"),
                )]),
            )
            .await,
    );
    let historical_root = must_v2(anchor.read_v2().await).expect("historical root should exist");
    must_v2(
        repository
            .write_child_commit(
                &anchor,
                V2CommitWrite::snapshot(vec![V2CommitSection::new(
                    V2SectionType::IndexSnapshot,
                    0,
                    Bytes::new(),
                )]),
            )
            .await,
    );

    let unprotected = must_v2(repository.report_orphans(&anchor).await);
    let protected = must_v2(
        repository
            .report_orphans_with_protected_roots(&anchor, std::slice::from_ref(&historical_root))
            .await,
    );
    let dry_run = must_v2(
        repository
            .full_gc_dry_run(
                &anchor,
                V2FullGcDryRunOptions {
                    protected_roots: vec![historical_root.clone()],
                    ..V2FullGcDryRunOptions::default()
                },
            )
            .await,
    );
    let apply = must_v2(
        repository
            .apply_fully_dead_orphans(
                &anchor,
                &UnenforcedQuiescedMaintenanceGuard,
                V2FullGcApplyOptions {
                    dry_run: V2FullGcDryRunOptions {
                        protected_roots: vec![historical_root],
                        ..V2FullGcDryRunOptions::default()
                    },
                    orphan_gc: V2OrphanGcOptions::new_for_test_rehearsal(Duration::ZERO),
                    retained_provider_conformance_passed: false,
                },
            )
            .await,
    );

    assert_eq!(unprotected.candidates.len(), 2);
    assert_eq!(protected.candidates.len(), 0);
    assert_eq!(dry_run.protected_root_count, 1);
    assert_eq!(dry_run.protected_commit_count, 2);
    assert_eq!(dry_run.candidate_commit_count, 0);
    assert_eq!(apply.orphan_gc.deleted_count, 0);
}

#[tokio::test]
async fn retained_v2_full_gc_apply_requires_provider_conformance() {
    let store = MemoryBlobStore::new();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::RetainedVersionObjectLock,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    )
    .with_retention(Some(RetentionPolicy::new(RetentionMode::Compliance, 30)));
    let repository = V2CommitStore::new(store, signing_keyring(), options);
    let anchor = V2MemoryAnchor::new();

    must_v2(repository.write_genesis_snapshot(&anchor).await);
    let apply = repository
        .apply_fully_dead_orphans(
            &anchor,
            &UnenforcedQuiescedMaintenanceGuard,
            V2FullGcApplyOptions {
                dry_run: V2FullGcDryRunOptions::default(),
                orphan_gc: V2OrphanGcOptions::new_for_test_rehearsal(Duration::ZERO),
                retained_provider_conformance_passed: false,
            },
        )
        .await;

    assert_eq!(apply, Err(V2FormatError::ProviderProfileFailed));
}

#[tokio::test]
async fn retained_v2_full_gc_apply_deletes_unprotected_exact_version_after_conformance() {
    let store = MemoryBlobStore::new();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::RetainedVersionObjectLock,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    )
    .with_retention(Some(RetentionPolicy::new(RetentionMode::Compliance, 30)));
    let repository = V2CommitStore::new(store.clone(), signing_keyring(), options);
    let anchor = V2MemoryAnchor::new();

    must_v2(repository.write_genesis_snapshot(&anchor).await);
    let unprotected_key = must_v2(generate_v2_commit_key(Sequence::new(99))).object_id;
    store
        .put(
            &unprotected_key,
            Bytes::from_static(b"unprotected-exact-version-orphan"),
            PutOptions::default(),
        )
        .await
        .unwrap_or_else(|error| panic!("put unprotected orphan: {error}"));

    let dry_run = must_v2(
        repository
            .full_gc_dry_run(&anchor, V2FullGcDryRunOptions::default())
            .await,
    );
    let apply = must_v2(
        repository
            .apply_fully_dead_orphans(
                &anchor,
                &UnenforcedQuiescedMaintenanceGuard,
                V2FullGcApplyOptions {
                    dry_run: V2FullGcDryRunOptions::default(),
                    orphan_gc: V2OrphanGcOptions::new_for_test_rehearsal(Duration::ZERO),
                    retained_provider_conformance_passed: true,
                },
            )
            .await,
    );
    let after = must_v2(repository.report_orphans(&anchor).await);

    assert_eq!(dry_run.candidate_commit_count, 1);
    assert_eq!(dry_run.fully_dead_commit_count, 1);
    assert_eq!(dry_run.unknown_protection_blocked_bytes, 0);
    assert_eq!(dry_run.planned_cost.delete_count, 1);
    assert!(dry_run.exact_version_apply_ready);
    assert_eq!(apply.orphan_gc.deleted_count, 1);
    assert_eq!(after.candidates.len(), 0);
}

#[tokio::test]
async fn v2_repository_full_gc_dry_run_reports_mixed_commit_payload_bytes() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2Repository::new(store, keyring, RepositoryOptions::default(), options);
    let anchor = V2MemoryAnchor::new();
    let live_key = must_type(LogicalPath::new("snapshots/live-after-delete.bin"));
    let deleted_key = must_type(LogicalPath::new("snapshots/deleted-from-mixed.bin"));

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(
        repository
            .stage_put(
                live_key.clone(),
                Bytes::from(vec![1_u8; 2048]),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    must_repo(
        repository
            .stage_put(
                deleted_key.clone(),
                Bytes::from(vec![2_u8; 4096]),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    must_repo(repository.publish_pending_index_delta(&anchor).await);
    must_repo(repository.delete_committed(&anchor, deleted_key).await);

    let report = must_repo(
        repository
            .full_gc_dry_run(&anchor, V2FullGcDryRunOptions::default())
            .await,
    );

    assert_eq!(report.mixed_commit_count, 1);
    assert!(report.live_bytes_to_copy > 0);
    assert!(report.mixed_dead_bytes_repackable > report.live_bytes_to_copy);
    assert_eq!(report.fully_dead_commit_count, 0);
}

#[tokio::test]
async fn v2_full_gc_dry_run_does_not_discard_concurrent_staged_delta() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2Repository::new(store, keyring, RepositoryOptions::default(), options);
    let anchor = V2MemoryAnchor::new();
    let blocking_anchor = BlockingV2Anchor::new(anchor.clone());
    let key = must_type(LogicalPath::new("snapshots/dry-run-race.bin"));
    let body = Bytes::from_static(b"staged while dry run replays");

    must_repo(repository.write_genesis_snapshot(&anchor).await);

    let put = async {
        repository
            .put_committed(
                &blocking_anchor,
                key.clone(),
                body.clone(),
                RepositoryPutOptions::default(),
            )
            .await
    };
    let dry_run = async {
        blocking_anchor.wait_until_blocked().await;
        let report = repository
            .full_gc_dry_run(&anchor, V2FullGcDryRunOptions::default())
            .await;
        blocking_anchor.release();
        report
    };

    let (put_result, dry_run_result) = tokio::join!(put, dry_run);

    must_repo(dry_run_result);
    must_repo(put_result);
    assert_eq!(
        must_repo(repository.get_range(&key, ByteRange::Full).await),
        body
    );
}

#[tokio::test]
async fn v2_compaction_snapshot_rejects_packed_state_until_index_root_exists() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        options.clone(),
    );
    let anchor = V2MemoryAnchor::new();
    let live_key = must_type(LogicalPath::new("snapshots/live-after-compaction.bin"));
    let deleted_key = must_type(LogicalPath::new("snapshots/deleted-before-compaction.bin"));
    let live_body = Bytes::from(vec![7_u8; 2048]);

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(
        repository
            .stage_put(
                live_key.clone(),
                live_body.clone(),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    must_repo(
        repository
            .stage_put(
                deleted_key.clone(),
                Bytes::from(vec![8_u8; 4096]),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    must_repo(repository.publish_pending_index_delta(&anchor).await);
    must_repo(
        repository
            .delete_committed(&anchor, deleted_key.clone())
            .await,
    );

    let before = must_repo(
        repository
            .full_gc_dry_run(&anchor, V2FullGcDryRunOptions::default())
            .await,
    );
    let compaction = repository
        .write_compaction_snapshot(
            &anchor,
            &UnenforcedQuiescedMaintenanceGuard,
            V2FullGcDryRunOptions::default(),
            false,
        )
        .await;
    let fresh = V2Repository::new(store, keyring, RepositoryOptions::default(), options);
    must_repo(fresh.load_chain_from_anchor(&anchor).await);
    let restored = must_repo(fresh.get_range(&live_key, ByteRange::Full).await);
    let deleted = fresh.head(&deleted_key);

    assert_eq!(before.mixed_commit_count, 1);
    assert!(before.live_bytes_to_copy > 0);
    assert!(matches!(
        compaction,
        Err(RepositoryError::CommitFailed { .. })
    ));
    assert_eq!(restored, live_body);
    assert!(matches!(deleted, Err(RepositoryError::NotFound(_))));
}

#[tokio::test]
async fn v2_packed_run_compaction_preserves_newest_state_without_copying_payloads() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        options.clone(),
    );
    let anchor = V2MemoryAnchor::new();
    let overwritten_key = must_type(LogicalPath::new("snapshots/compacted-overwrite.bin"));
    let deleted_key = must_type(LogicalPath::new("snapshots/compacted-delete.bin"));
    let stable_key = must_type(LogicalPath::new("snapshots/compacted-stable.bin"));
    let old_body = Bytes::from(vec![11_u8; 512]);
    let new_body = Bytes::from(vec![12_u8; 512]);
    let stable_body = Bytes::from(vec![13_u8; 512]);

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    for (key, body) in [
        (overwritten_key.clone(), old_body),
        (deleted_key.clone(), Bytes::from(vec![14_u8; 512])),
        (overwritten_key.clone(), new_body.clone()),
        (stable_key.clone(), stable_body.clone()),
    ] {
        must_repo(
            repository
                .put_committed(&anchor, key, body, RepositoryPutOptions::default())
                .await,
        );
    }
    must_repo(
        repository
            .delete_committed(&anchor, deleted_key.clone())
            .await,
    );
    let source_run_count = must_repo(repository.active_index_run_count());
    assert_eq!(source_run_count, 5);

    store.reset_operation_counts();
    must_repo(
        repository
            .compact_packed_index_runs(&anchor, &UnenforcedQuiescedMaintenanceGuard)
            .await,
    );
    let compaction_counts = store.operation_counts();
    assert_eq!(compaction_counts.list, 0);
    assert_eq!(compaction_counts.delete, 0);
    assert!(must_repo(repository.active_index_run_count()) < source_run_count);

    let fresh = V2Repository::new(
        store.clone(),
        keyring,
        RepositoryOptions::default(),
        options,
    );
    must_repo(fresh.load_chain_from_anchor(&anchor).await);
    store.reset_operation_counts();
    assert_eq!(
        must_repo(fresh.get_range(&overwritten_key, ByteRange::Full).await),
        new_body
    );
    let cold_counts = store.operation_counts();
    assert_eq!(cold_counts.get, 1);
    assert_eq!(cold_counts.bytes_read, 528);
    assert_eq!(cold_counts.bytes_written, 0);
    assert_eq!(
        must_repo(fresh.get_range(&stable_key, ByteRange::Full).await),
        stable_body
    );
    assert!(fresh.head(&deleted_key).is_err());
    assert_eq!(
        must_repo(fresh.list("snapshots/"))
            .into_iter()
            .map(|entry| entry.key)
            .collect::<Vec<_>>(),
        vec![overwritten_key, stable_key]
    );
}

#[tokio::test]
async fn v2_packed_run_compaction_preserves_historical_pack_envelope_context() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
    let keyring = must_crypto(KeyRing::generate_random());
    let original_options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let original = V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        original_options,
    );
    let anchor = V2MemoryAnchor::new();
    let first_key = must_type(LogicalPath::new("snapshots/compacted-envelope-a.bin"));
    let second_key = must_type(LogicalPath::new("snapshots/compacted-envelope-b.bin"));
    let first_body = Bytes::from(vec![21_u8; 512]);

    must_repo(original.write_genesis_snapshot(&anchor).await);
    must_repo(
        original
            .put_committed(
                &anchor,
                first_key.clone(),
                first_body.clone(),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    must_repo(
        original
            .put_committed(
                &anchor,
                second_key,
                Bytes::from(vec![22_u8; 512]),
                RepositoryPutOptions::default(),
            )
            .await,
    );

    let rotated_options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        V2KeyringEnvelopeRef {
            object_id: object_id("keyrings/00000000000000000002-compaction"),
            digest: [23_u8; 32],
        },
        sample_format_ref(),
    );
    let rotated = V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        rotated_options.clone(),
    );
    must_repo(rotated.load_chain_from_anchor(&anchor).await);
    must_repo(
        rotated
            .compact_packed_index_runs(&anchor, &UnenforcedQuiescedMaintenanceGuard)
            .await,
    );

    let fresh = V2Repository::new(
        store.clone(),
        keyring,
        RepositoryOptions::default(),
        rotated_options,
    );
    must_repo(fresh.load_chain_from_anchor(&anchor).await);
    store.reset_operation_counts();
    assert_eq!(
        must_repo(fresh.get_range(&first_key, ByteRange::Full).await),
        first_body
    );
    let counts = store.operation_counts();
    assert_eq!(counts.get, 1);
    assert_eq!(counts.head, 0);
    assert_eq!(counts.list, 0);
    assert_eq!(counts.bytes_read, 528);
}

#[tokio::test]
async fn v2_packed_run_compaction_recovery_rejects_a_tampered_sibling() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        options.clone(),
    );
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    for index in 0..2 {
        must_repo(
            repository
                .put_committed(
                    &anchor,
                    must_type(LogicalPath::new(format!(
                        "snapshots/compacted-sibling-{index}.bin"
                    ))),
                    Bytes::from(vec![index as u8; 512]),
                    RepositoryPutOptions::default(),
                )
                .await,
        );
    }
    must_repo(
        repository
            .compact_packed_index_runs(&anchor, &UnenforcedQuiescedMaintenanceGuard)
            .await,
    );
    let root = must_v2(anchor.read_v2().await).expect("compacted root should be anchored");
    let sibling = store
        .list_prefix("commits/v02/")
        .await
        .expect("memory store listing should succeed")
        .into_iter()
        .find(|metadata| {
            metadata.object_id != root.commit_key
                && V2CommitKey::parse(&metadata.object_id)
                    .is_ok_and(|key| key.sequence == root.sequence)
        })
        .expect("compacted sibling should exist");
    store.corrupt_ranged_commit_gets_for(sibling.object_id);

    let fresh = V2Repository::new(store, keyring, RepositoryOptions::default(), options);
    assert!(matches!(
        fresh.load_chain_from_anchor(&anchor).await,
        Err(RepositoryError::CommitFailed { .. })
    ));
}

#[tokio::test]
async fn v2_packed_run_compaction_guard_loss_leaves_the_base_anchored() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2Repository::new(store, keyring, RepositoryOptions::default(), options);
    let anchor = V2MemoryAnchor::new();
    let first_key = must_type(LogicalPath::new("snapshots/compaction-guard-a.bin"));
    let second_key = must_type(LogicalPath::new("snapshots/compaction-guard-b.bin"));

    must_repo(repository.write_genesis_snapshot(&anchor).await);
    for (key, body) in [
        (first_key.clone(), Bytes::from_static(b"first")),
        (second_key.clone(), Bytes::from_static(b"second")),
    ] {
        must_repo(
            repository
                .put_committed(&anchor, key, body, RepositoryPutOptions::default())
                .await,
        );
    }
    let base = must_v2(anchor.read_v2().await).expect("base anchor should exist");
    let error = repository
        .compact_packed_index_runs(&anchor, &FailsAfterMaintenanceGuard::new(2))
        .await
        .expect_err("lost maintenance guard must stop the final anchor CAS");

    assert!(matches!(error, RepositoryError::CommitFailed { .. }));
    assert_eq!(must_v2(anchor.read_v2().await), Some(base));
    assert_eq!(
        must_repo(repository.get_range(&first_key, ByteRange::Full).await),
        Bytes::from_static(b"first")
    );
    assert_eq!(
        must_repo(repository.get_range(&second_key, ByteRange::Full).await),
        Bytes::from_static(b"second")
    );
    assert!(
        must_v2(repository.commit_store().report_orphans(&anchor).await)
            .candidates
            .len()
            >= 2
    );
}

#[tokio::test]
async fn v2_packed_run_compaction_loses_final_cas_without_local_adoption() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = Arc::new(V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        options.clone(),
    ));
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    for index in 0..2 {
        must_repo(
            repository
                .put_committed(
                    &anchor,
                    must_type(LogicalPath::new(format!(
                        "snapshots/compaction-cas-base-{index}.bin"
                    ))),
                    Bytes::from(vec![index as u8; 512]),
                    RepositoryPutOptions::default(),
                )
                .await,
        );
    }

    let competitor = V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        options.clone(),
    );
    must_repo(competitor.load_chain_from_anchor(&anchor).await);
    let blocking_anchor = BlockingV2Anchor::new(anchor.clone());
    let task_repository = Arc::clone(&repository);
    let task_anchor = blocking_anchor.clone();
    let compaction = tokio::spawn(async move {
        task_repository
            .compact_packed_index_runs(&task_anchor, &UnenforcedQuiescedMaintenanceGuard)
            .await
    });
    blocking_anchor.wait_until_blocked().await;

    let competing_key = must_type(LogicalPath::new("snapshots/compaction-cas-winner.bin"));
    must_repo(
        competitor
            .put_committed(
                &anchor,
                competing_key.clone(),
                Bytes::from_static(b"winner"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    blocking_anchor.release();
    let error = compaction
        .await
        .expect("compaction task should join")
        .expect_err("compaction must lose the final anchor CAS");

    assert!(matches!(error, RepositoryError::CommitFailed { .. }));
    assert!(repository.head(&competing_key).is_err());
    let fresh = V2Repository::new(store, keyring, RepositoryOptions::default(), options);
    must_repo(fresh.load_chain_from_anchor(&anchor).await);
    assert_eq!(
        must_repo(fresh.get_range(&competing_key, ByteRange::Full).await),
        Bytes::from_static(b"winner")
    );
    assert!(
        must_v2(repository.commit_store().report_orphans(&anchor).await)
            .candidates
            .len()
            >= 2
    );
}

#[tokio::test]
async fn v2_packed_run_compaction_preserves_older_tier_across_cycles() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        options.clone(),
    );
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);

    for cycle in 0..2 {
        for index in 0..2 {
            must_repo(
                repository
                    .put_committed(
                        &anchor,
                        must_type(LogicalPath::new(format!(
                            "snapshots/tiered-cycle-{cycle}-{index}.bin"
                        ))),
                        Bytes::from(vec![(cycle * 2 + index) as u8; 512]),
                        RepositoryPutOptions::default(),
                    )
                    .await,
            );
        }
        must_repo(
            repository
                .compact_packed_index_runs(&anchor, &UnenforcedQuiescedMaintenanceGuard)
                .await,
        );
    }

    assert_eq!(must_repo(repository.active_index_run_count()), 2);
    assert_eq!(must_repo(repository.active_level_zero_index_run_count()), 0);
    let fresh = V2Repository::new(store, keyring, RepositoryOptions::default(), options);
    must_repo(fresh.load_chain_from_anchor(&anchor).await);
    assert_eq!(must_repo(fresh.active_index_run_count()), 2);
    assert_eq!(must_repo(fresh.list("snapshots/")).len(), 4);
    for cycle in 0..2 {
        for index in 0..2 {
            let key = must_type(LogicalPath::new(format!(
                "snapshots/tiered-cycle-{cycle}-{index}.bin"
            )));
            assert_eq!(
                must_repo(fresh.get_range(&key, ByteRange::Full).await),
                Bytes::from(vec![(cycle * 2 + index) as u8; 512])
            );
        }
    }
}

#[tokio::test]
async fn v2_coordinator_compacts_automatically_at_the_run_watermark() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = Arc::new(V2Repository::new(
        store.clone(),
        keyring.clone(),
        RepositoryOptions::default(),
        options.clone(),
    ));
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    let coordinator = must_repo(V2CommitCoordinator::with_options(
        Arc::clone(&repository),
        anchor.clone(),
        CommitCoordinatorOptions::new(1, Duration::ZERO).with_max_pending_items(1),
    ))
    .with_maintenance_guard(UnenforcedQuiescedMaintenanceGuard);
    let object_count = V2_INDEX_COMPACTION_REQUEST_RUNS + 1;

    for index in 0..object_count {
        must_repo(
            coordinator
                .put_committed(
                    must_type(LogicalPath::new(format!(
                        "snapshots/automatic-compaction-{index:04}.bin"
                    ))),
                    Bytes::from(vec![index as u8; 32]),
                    RepositoryPutOptions::default(),
                )
                .await,
        );
    }

    assert!(must_repo(repository.active_index_run_count()) < V2_INDEX_COMPACTION_REQUEST_RUNS);
    let fresh = V2Repository::new(store, keyring, RepositoryOptions::default(), options);
    must_repo(fresh.load_chain_from_anchor(&anchor).await);
    assert_eq!(must_repo(fresh.list("snapshots/")).len(), object_count);
}

#[tokio::test]
async fn v2_coordinator_poisoned_compaction_guard_stops_before_staging() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = Arc::new(V2Repository::new(
        store.clone(),
        keyring,
        RepositoryOptions::default(),
        options,
    ));
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(
        repository
            .put_committed(
                &anchor,
                must_type(LogicalPath::new("snapshots/guard-poison-existing.bin")),
                Bytes::from_static(b"existing"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    must_repo(repository.resize_accepted_run_catalog_for_tests(V2_INDEX_COMPACTION_REQUEST_RUNS));
    let coordinator = must_repo(V2CommitCoordinator::with_options(
        Arc::clone(&repository),
        anchor,
        CommitCoordinatorOptions::new(1, Duration::ZERO).with_max_pending_items(1),
    ))
    .with_maintenance_guard(FailsAfterMaintenanceGuard::new(0));
    store
        .reset_operation_counts()
        .expect("memory store should reset operation counts");

    let error = coordinator
        .put_committed(
            must_type(LogicalPath::new("snapshots/guard-poison-blocked.bin")),
            Bytes::from_static(b"must not stage"),
            RepositoryPutOptions::default(),
        )
        .await
        .expect_err("maintenance guard loss must poison the writer");

    assert!(matches!(error, RepositoryError::CommitFailed { .. }));
    assert!(coordinator.status().poisoned);
    assert_eq!(
        store
            .operation_counts()
            .expect("memory store should expose operation counts")
            .put,
        0
    );
    assert!(
        repository
            .head(&must_type(LogicalPath::new(
                "snapshots/guard-poison-blocked.bin"
            )))
            .is_err()
    );
}

#[tokio::test]
async fn v2_coordinator_pauses_before_staging_when_compaction_guard_is_unavailable() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = Arc::new(V2Repository::new(
        store.clone(),
        keyring,
        RepositoryOptions::default(),
        options,
    ));
    let anchor = V2MemoryAnchor::new();
    must_repo(repository.write_genesis_snapshot(&anchor).await);
    must_repo(
        repository
            .put_committed(
                &anchor,
                must_type(LogicalPath::new("snapshots/watermark-existing.bin")),
                Bytes::from_static(b"existing"),
                RepositoryPutOptions::default(),
            )
            .await,
    );
    must_repo(repository.resize_accepted_run_catalog_for_tests(V2_INDEX_COMPACTION_PAUSE_RUNS));
    let coordinator = must_repo(V2CommitCoordinator::with_options(
        Arc::clone(&repository),
        anchor.clone(),
        CommitCoordinatorOptions::new(1, Duration::ZERO).with_max_pending_items(1),
    ));
    let base = must_v2(anchor.read_v2().await).expect("base anchor should exist");
    store
        .reset_operation_counts()
        .expect("memory store should reset operation counts");

    let error = coordinator
        .put_committed(
            must_type(LogicalPath::new("snapshots/watermark-blocked.bin")),
            Bytes::from_static(b"must not stage"),
            RepositoryPutOptions::default(),
        )
        .await
        .expect_err("pause watermark must require guarded compaction");

    assert!(matches!(error, RepositoryError::CommitFailed { .. }));
    assert_eq!(must_v2(anchor.read_v2().await), Some(base));
    assert_eq!(
        store
            .operation_counts()
            .expect("memory store should expose operation counts")
            .put,
        0
    );
    assert!(
        repository
            .head(&must_type(LogicalPath::new(
                "snapshots/watermark-blocked.bin"
            )))
            .is_err()
    );
}

#[tokio::test]
async fn v2_commit_store_preserves_stale_anchor_error_class() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2CommitStore::new(store, keyring, options);
    let anchor = V2MemoryAnchor::new();

    must_v2(repository.write_genesis_snapshot(&anchor).await);
    let stale = repository
        .write_child_commit(
            &StaleOnAdvanceV2Anchor::new(anchor),
            V2CommitWrite::delta(vec![V2CommitSection::new(
                V2SectionType::IndexDelta,
                0,
                Bytes::from_static(b"stale-writer"),
            )]),
        )
        .await;

    assert_eq!(stale, Err(V2FormatError::StaleAnchor));
    assert_eq!(
        V2FormatError::StaleAnchor.class(),
        V2ErrorClass::FailClosedSecurity
    );
}

#[tokio::test]
async fn v2_commit_store_rejects_child_write_without_anchor() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2CommitStore::new(store, keyring, options);
    let anchor = V2MemoryAnchor::new();

    let error = repository
        .write_child_commit(
            &anchor,
            V2CommitWrite::delta(vec![V2CommitSection::new(
                V2SectionType::IndexDelta,
                0,
                Bytes::from_static(b"opaque-index-delta"),
            )]),
        )
        .await;

    assert!(matches!(error, Err(V2FormatError::MissingAnchor)));
}

#[tokio::test]
async fn retained_v2_commit_store_records_versioned_anchor() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::RetainedVersionObjectLock,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2CommitStore::new(store, keyring, options);
    let anchor = V2MemoryAnchor::new();

    let genesis = must_v2(repository.write_genesis_snapshot(&anchor).await);
    let head = must_v2(repository.read_anchor_head(&anchor).await);

    assert!(genesis.version_id.is_some());
    assert!(genesis.anchor_state.version_id.is_some());
    assert!(head.is_some());
}

#[tokio::test]
async fn v2_commit_store_adopts_strict_unanchored_child() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2CommitStore::new(store, keyring, options);
    let anchor = V2MemoryAnchor::new();

    let genesis = must_v2(repository.write_genesis_snapshot(&anchor).await);
    let ambiguous_anchor = V2MemoryAnchor::with_state(genesis.anchor_state.clone());
    let uploaded = must_v2(
        repository
            .write_child_commit(
                &ambiguous_anchor,
                V2CommitWrite::delta(vec![V2CommitSection::new(
                    V2SectionType::IndexDelta,
                    0,
                    Bytes::from_static(b"ambiguous-upload-delta"),
                )]),
            )
            .await,
    );

    let adopted = must_v2(
        repository
            .adopt_unanchored_child(
                &anchor,
                &uploaded.commit_key.object_id,
                uploaded.version_id.as_ref(),
            )
            .await,
    );

    assert_eq!(adopted.anchor_state.sequence, Sequence::new(2));
    assert_eq!(
        adopted.anchor_state.commit_key,
        uploaded.anchor_state.commit_key
    );
}

#[tokio::test]
async fn v2_recovery_bundle_recreates_missing_anchor_after_chain_verification() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2CommitStore::new(store, keyring, options);
    let anchor = V2MemoryAnchor::new();

    let genesis = must_v2(repository.write_genesis_snapshot(&anchor).await);
    let mut bundle = V2RecoveryBundle::from_anchor(genesis.anchor_state.clone(), Sequence::new(1));
    bundle.repository_id = Some(sample_repository_id());
    let recovered_anchor = V2MemoryAnchor::new();

    let chain = must_v2(
        repository
            .recreate_anchor_from_recovery_bundle(&recovered_anchor, &bundle, Sequence::new(1))
            .await,
    );
    let recovered_head = must_v2(repository.read_anchor_head(&recovered_anchor).await);

    assert_eq!(chain.commits_newest_first.len(), 1);
    assert!(recovered_head.is_some());
}

#[tokio::test]
async fn v2_recovery_bundle_rejects_anchor_below_external_floor() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2CommitStore::new(store, keyring, options);
    let anchor = V2MemoryAnchor::new();

    let genesis = must_v2(repository.write_genesis_snapshot(&anchor).await);
    let mut bundle = V2RecoveryBundle::from_anchor(genesis.anchor_state, Sequence::new(1));
    bundle.repository_id = Some(sample_repository_id());
    let recovered_anchor = V2MemoryAnchor::new();
    let error = match repository
        .recreate_anchor_from_recovery_bundle(&recovered_anchor, &bundle, Sequence::new(2))
        .await
    {
        Ok(_) => panic!("below-floor recovery bundle should be rejected"),
        Err(error) => error,
    };

    assert_eq!(error, V2FormatError::RecoveryBundleRequired);
}

#[tokio::test]
async fn v2_recovery_bundle_rejects_a_different_repository_identity() {
    let store = MemoryBlobStore::new();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2CommitStore::new(store, signing_keyring(), options);
    let anchor = V2MemoryAnchor::new();
    let genesis = must_v2(repository.write_genesis_snapshot(&anchor).await);
    let mut bundle = V2RecoveryBundle::from_anchor(genesis.anchor_state, Sequence::new(1));
    bundle.repository_id = Some(must_type(RepositoryId::new("different-repository")));

    let error = repository
        .recreate_anchor_from_recovery_bundle(&V2MemoryAnchor::new(), &bundle, Sequence::new(1))
        .await
        .expect_err("cross-repository recovery bundle must fail closed");

    assert_eq!(error, V2FormatError::RecoveryBundleRequired);
}

#[tokio::test]
async fn v2_orphan_report_surfaces_same_sequence_candidates() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
        sample_repository_id(),
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2CommitStore::new(store, keyring, options);
    let anchor = V2MemoryAnchor::new();

    let genesis = must_v2(repository.write_genesis_snapshot(&anchor).await);
    let ambiguous_anchor = V2MemoryAnchor::with_state(genesis.anchor_state.clone());
    let _uploaded = must_v2(
        repository
            .write_child_commit(
                &ambiguous_anchor,
                V2CommitWrite::delta(vec![V2CommitSection::new(
                    V2SectionType::IndexDelta,
                    0,
                    Bytes::from_static(b"same-sequence-orphan"),
                )]),
            )
            .await,
    );
    let _accepted = must_v2(
        repository
            .write_child_commit(
                &anchor,
                V2CommitWrite::delta(vec![V2CommitSection::new(
                    V2SectionType::IndexDelta,
                    0,
                    Bytes::from_static(b"accepted-sequence-delta"),
                )]),
            )
            .await,
    );

    let report = must_v2(repository.report_orphans(&anchor).await);
    let maintenance = must_v2(repository.quick_maintenance(&anchor).await);

    assert_eq!(report.candidates.len(), 1);
    assert!(report.candidates[0].same_sequence_as_anchor);
    assert_eq!(maintenance.orphan_candidate_count, 1);
    assert_eq!(maintenance.verified_commit_count, 2);
}
