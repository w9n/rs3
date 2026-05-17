use super::{
    V2Algorithms, V2CommitHeader, V2CommitKey, V2CommitParentRef, V2CommitSelfRef, V2ErrorClass,
    V2FormatError, V2FormatRef, V2FormatRoot, V2KeyringEnvelopeRef, V2KeyringEnvelopeRootRef,
    V2ProviderCheckStatus, V2ProviderConformanceOptions, V2ProviderProfile, V2SectionDescriptor,
    V2SectionType, V2UploadMode, body_digest_for_v2_sections, check_v2_provider_conformance,
    parse_v2_commit_object,
};
use super::{
    V2AnchorState, V2CommitAnchor, V2CommitCoordinator, V2CommitSection, V2CommitStore,
    V2CommitStoreOptions, V2CommitWrite, V2MemoryAnchor, V2OrphanGcOptions, V2RecoveryBundle,
    V2Repository,
};
use crate::{CommitCoordinatorOptions, RepositoryError, RepositoryOptions, RepositoryPutOptions};
use bytes::Bytes;
use rs3_crypto::{KeyMaterial, KeyRing, SecretBytes};
use rs3_storage::{BlobMetadata, BlobStore, ByteRange, MemoryBlobStore, PutOptions};
use rs3_types::{
    BackendObjectId, BackendVersionId, KeyDescriptor, KeyId, KeyPurpose, KeyStatus,
    LegalHoldStatus, LogicalPath, RetentionMode, RetentionPolicy, Sequence,
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
        is_snapshot: true,
        algorithms: V2Algorithms::v01(),
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

    async fn delete(&self, object_id: &BackendObjectId) -> rs3_storage::Result<()> {
        self.inner.delete(object_id).await
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
        "commits/v01/".len() + 20 + 1 + 43
    );

    let parsed = must_v2(V2CommitKey::parse(&key.object_id));
    assert_eq!(parsed.sequence, Sequence::new(7));
    assert_eq!(parsed.random_id, [9_u8; 32]);

    for invalid in [
        "checkpoints/not-v2",
        "commits/v01/00000000000000000007/short",
        "commits/v01/0000000000000000007/not-wide-enough",
        "commits/v01/00000000000000000007/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
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
fn body_digest_tampering_is_rejected_after_header_verification() {
    let keyring = signing_keyring();
    let (commit_key, _, body) = sample_object(V2UploadMode::SinglePut);
    let mut tampered = body.to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x80;

    let error = parse_v2_commit_object(&commit_key.object_id, Bytes::from(tampered), &keyring);
    assert!(matches!(error, Err(V2FormatError::BodyDigestMismatch)));
}

#[test]
fn section_layout_rejects_reserved_flags_and_unauthenticated_gaps() {
    let section_region = Bytes::from_static(b"abcdef");
    let reserved = vec![V2SectionDescriptor {
        section_type: V2SectionType::IndexDelta,
        offset: 0,
        length: 6,
        flags: 0x04,
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
    }];
    assert!(matches!(
        body_digest_for_v2_sections(&gap, section_region.as_ref()),
        Err(V2FormatError::SectionBounds)
    ));
}

#[test]
fn commit_rejects_snapshot_section_mismatch() {
    let keyring = signing_keyring();
    let (commit_key, mut header, section_region) = sample_header(V2UploadMode::SinglePut);
    header.is_snapshot = false;
    header = must_v2(header.sign_with_keyring(&keyring, V2UploadMode::SinglePut));
    let body = must_v2(header.encode_object(V2UploadMode::SinglePut, section_region.as_ref()));

    let error = parse_v2_commit_object(&commit_key.object_id, body, &keyring);

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
    assert!(
        !chain.commits_newest_first[0]
            .parsed_header
            .header
            .is_snapshot
    );
    assert!(
        chain.commits_newest_first[1]
            .parsed_header
            .header
            .is_snapshot
    );
}

#[tokio::test]
async fn v2_repository_replays_committed_index_delta_after_reload() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
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
async fn v2_repository_range_reads_cache_headers_without_full_commit_gets() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
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
    assert_eq!(counts.get, 8);
}

#[tokio::test]
async fn v2_repository_concurrent_range_reads_avoid_full_commit_gets() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::from_millis(50));
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
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
    let coordinator = Arc::new(V2CommitCoordinator::with_options(
        Arc::clone(&repository),
        anchor,
        CommitCoordinatorOptions::new(2, Duration::from_secs(60)),
    ));
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

    assert!(matches!(error, Err(RepositoryError::Crypto(_))));
}

#[tokio::test]
async fn v2_repository_full_read_does_not_cache_unauthenticated_payload_section() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::ZERO);
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
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
    assert!(matches!(corrupted, Err(RepositoryError::Crypto(_))));

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

    assert!(matches!(
        error,
        Err(RepositoryError::InvalidObjectFormat { .. })
    ));
}

#[tokio::test]
async fn v2_repository_range_read_rejects_payload_plaintext_length_metadata_mismatch() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
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

    assert!(matches!(
        error,
        Err(RepositoryError::InvalidObjectFormat { .. })
    ));
}

#[tokio::test]
async fn v2_repository_independent_payload_range_fills_run_concurrently() {
    let store = SlowCommitGetStore::new(MemoryBlobStore::new(), Duration::from_millis(50));
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
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
async fn v2_commit_coordinator_batches_concurrent_puts_into_one_commit() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
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
    let coordinator = Arc::new(V2CommitCoordinator::with_options(
        Arc::clone(&repository),
        anchor.clone(),
        CommitCoordinatorOptions::new(2, Duration::from_secs(60)),
    ));
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
            .list_prefix("commits/v01/")
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
    let payload_section_count = chain.commits_newest_first[0]
        .parsed_header
        .header
        .section_index
        .iter()
        .filter(|section| section.section_type == V2SectionType::Payload)
        .count();
    assert_eq!(retired_payloads.len(), 0);
    assert_eq!(retired_index.len(), 0);
    assert_eq!(retired_manifests.len(), 0);
    assert_eq!(retired_checkpoints.len(), 0);
    assert_eq!(retired_evidence.len(), 0);
    assert_eq!(payload_section_count, 2);
    assert_eq!(
        listed
            .into_iter()
            .map(|entry| entry.key)
            .collect::<Vec<_>>(),
        vec![first_key, second_key]
    );
}

#[tokio::test]
async fn v2_commit_retention_covers_strongest_staged_object() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
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
    let coordinator = Arc::new(V2CommitCoordinator::with_options(
        Arc::clone(&repository),
        anchor.clone(),
        CommitCoordinatorOptions::new(2, Duration::from_secs(60)),
    ));

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
    let coordinator = Arc::new(V2CommitCoordinator::with_options(
        Arc::clone(&repository),
        FailOnceV2Anchor::new(anchor.clone()),
        CommitCoordinatorOptions::new(2, Duration::from_secs(60)),
    ));
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
    let later = coordinator
        .put_committed(
            LogicalPath::new("snapshots/v2-later.bin").unwrap_or_else(|error| panic!("{error}")),
            Bytes::from_static(b"later"),
            RepositoryPutOptions::default(),
        )
        .await;
    let accepted = must_v2(anchor.read_v2().await).expect("v2 genesis anchor should remain");

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
    assert!(matches!(
        repository.head(&first_key),
        Err(crate::RepositoryError::NotFound(_))
    ));
    assert!(matches!(
        repository.head(&second_key),
        Err(crate::RepositoryError::NotFound(_))
    ));
}

#[tokio::test]
async fn v2_commit_coordinator_applies_backpressure_before_payload_write() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
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
    let coordinator = Arc::new(V2CommitCoordinator::with_options(
        Arc::clone(&repository),
        anchor,
        CommitCoordinatorOptions::new(8, Duration::from_millis(250)).with_max_pending_items(1),
    ));
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
            .list_prefix("commits/v01/")
            .await
            .map_err(|_| V2FormatError::StorageOperationFailed),
    );
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
async fn v2_index_snapshot_bounds_replay_and_preserves_namespace() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
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
    assert!(
        !chain.commits_newest_first[0]
            .parsed_header
            .header
            .is_snapshot
    );
    assert!(
        chain.commits_newest_first[1]
            .parsed_header
            .header
            .is_snapshot
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
async fn v2_commit_coordinator_flushes_before_index_snapshot() {
    let store = MemoryBlobStore::new();
    let keyring = must_crypto(KeyRing::generate_random());
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
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
    let coordinator = Arc::new(V2CommitCoordinator::with_options(
        Arc::clone(&repository),
        anchor.clone(),
        CommitCoordinatorOptions::new(8, Duration::from_secs(60)),
    ));
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
    assert!(
        chain.commits_newest_first[0]
            .parsed_header
            .header
            .is_snapshot
    );
    assert_eq!(body, Bytes::from_static(b"pending"));
}

#[tokio::test]
async fn v2_orphan_gc_deletes_expired_unprotected_commit() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
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
            .delete_expired_orphans(&anchor, V2OrphanGcOptions::new(Duration::ZERO))
            .await,
    );
    let after = must_v2(repository.report_orphans(&anchor).await);

    assert!(matches!(failed, Err(V2FormatError::AnchorAdvanceFailed)));
    assert_eq!(before.candidates.len(), 1);
    assert_eq!(gc.scanned_count, 1);
    assert_eq!(gc.deleted_count, 1);
    assert_eq!(after.candidates.len(), 0);
}

#[tokio::test]
async fn v2_orphan_gc_skips_retained_or_held_candidates() {
    let retained_store = MemoryBlobStore::new();
    let retained_options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::RetainedVersionObjectLock,
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
                V2OrphanGcOptions::new(Duration::ZERO).with_same_sequence_deletion(true),
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
            V2OrphanGcOptions::new(Duration::ZERO).with_same_sequence_deletion(true),
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
async fn v2_commit_store_preserves_stale_anchor_error_class() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
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
        sample_keyring_envelope_ref(),
        sample_format_ref(),
    );
    let repository = V2CommitStore::new(store, keyring, options);
    let anchor = V2MemoryAnchor::new();

    let genesis = must_v2(repository.write_genesis_snapshot(&anchor).await);
    let bundle = V2RecoveryBundle::from_anchor(genesis.anchor_state.clone(), Sequence::new(1));
    let recovered_anchor = V2MemoryAnchor::new();

    let chain = must_v2(
        repository
            .recreate_anchor_from_recovery_bundle(&recovered_anchor, &bundle)
            .await,
    );
    let recovered_head = must_v2(repository.read_anchor_head(&recovered_anchor).await);

    assert_eq!(chain.commits_newest_first.len(), 1);
    assert!(recovered_head.is_some());
}

#[tokio::test]
async fn v2_orphan_report_surfaces_same_sequence_candidates() {
    let store = MemoryBlobStore::new();
    let keyring = signing_keyring();
    let options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::Dev,
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
