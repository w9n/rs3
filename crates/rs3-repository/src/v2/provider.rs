//! Storage-provider conformance checks for v2 profiles.

use super::error::{V2ErrorClass, V2FormatError, V2Result};
use bytes::Bytes;
use rs3_storage::{BlobStore, ByteRange, PutOptions, StorageError};
use rs3_types::{BackendObjectId, LegalHoldStatus, RetentionMode, RetentionPolicy};
use serde::{Deserialize, Serialize};

const S3_MIN_MULTIPART_PART_BYTES: usize = 5 * 1024 * 1024;

/// v2 storage-provider profile selected for a repository.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum V2ProviderProfile {
    /// Local development profile with no production rollback-safety claim.
    Dev,
    /// Provider-enforced atomic create-only profile.
    AtomicCreate,
    /// Versioning plus Object Lock profile for providers without atomic create.
    RetainedVersionObjectLock,
}

/// Options for a v2 provider conformance run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2ProviderConformanceOptions {
    /// Profile whose requirements are being checked.
    pub profile: V2ProviderProfile,
    /// Opaque object-key prefix used for probe objects.
    pub probe_prefix: String,
    /// Retention policy requested for retained-version probes.
    pub retention: RetentionPolicy,
    /// Whether legal-hold add/verify probes should run.
    pub legal_hold: bool,
    /// Whether an operator has reviewed that gateway credentials cannot bypass
    /// governance retention.
    pub governance_bypass_reviewed: bool,
}

impl V2ProviderConformanceOptions {
    /// Creates conformance options for a profile with an explicit probe prefix.
    pub fn new(profile: V2ProviderProfile, probe_prefix: impl Into<String>) -> Self {
        Self {
            profile,
            probe_prefix: probe_prefix.into(),
            retention: RetentionPolicy::new(RetentionMode::Governance, 1),
            legal_hold: false,
            governance_bypass_reviewed: false,
        }
    }

    /// Requests a specific retained-version policy for retained probes.
    pub const fn with_retention(mut self, retention: RetentionPolicy) -> Self {
        self.retention = retention;
        self
    }

    /// Enables or disables legal-hold conformance probes.
    pub const fn with_legal_hold(mut self, legal_hold: bool) -> Self {
        self.legal_hold = legal_hold;
        self
    }

    /// Records whether governance-bypass IAM review has been completed.
    pub const fn with_governance_bypass_reviewed(mut self, reviewed: bool) -> Self {
        self.governance_bypass_reviewed = reviewed;
        self
    }
}

/// Status of a single provider conformance check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V2ProviderCheckStatus {
    /// The check passed.
    Passed,
    /// The check failed.
    Failed,
}

/// One redacted provider conformance check result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2ProviderConformanceCheck {
    /// Stable check name.
    pub name: &'static str,
    /// Check status.
    pub status: V2ProviderCheckStatus,
    /// Redacted failure reason, when status is failed.
    pub reason: Option<&'static str>,
}

impl V2ProviderConformanceCheck {
    fn passed(name: &'static str) -> Self {
        Self {
            name,
            status: V2ProviderCheckStatus::Passed,
            reason: None,
        }
    }

    fn failed(name: &'static str, reason: &'static str) -> Self {
        Self {
            name,
            status: V2ProviderCheckStatus::Failed,
            reason: Some(reason),
        }
    }
}

/// Redacted provider conformance report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2ProviderConformanceReport {
    /// Profile checked by this report.
    pub profile: V2ProviderProfile,
    /// Individual check results.
    pub checks: Vec<V2ProviderConformanceCheck>,
}

impl V2ProviderConformanceReport {
    /// Returns true when every conformance check passed.
    pub fn passed(&self) -> bool {
        self.checks
            .iter()
            .all(|check| check.status == V2ProviderCheckStatus::Passed)
    }

    /// Converts the report into a v2 result, preserving the report on success.
    pub fn require_pass(self) -> V2Result<Self> {
        if self.passed() {
            Ok(self)
        } else {
            Err(V2FormatError::ProviderProfileFailed)
        }
    }

    /// Returns the operator-facing class for failed conformance.
    pub const fn failure_class(&self) -> V2ErrorClass {
        V2ErrorClass::ProviderConformance
    }
}

/// Runs redacted v2 provider conformance checks against a `BlobStore`.
pub async fn check_v2_provider_conformance<S>(
    store: &S,
    options: &V2ProviderConformanceOptions,
) -> V2Result<V2ProviderConformanceReport>
where
    S: BlobStore,
{
    let mut checks = Vec::new();
    run_basic_surface_checks(store, options, &mut checks).await?;
    run_multipart_checks(store, options, &mut checks).await?;

    match options.profile {
        V2ProviderProfile::Dev => {}
        V2ProviderProfile::AtomicCreate => {
            run_atomic_create_checks(store, options, &mut checks).await?;
        }
        V2ProviderProfile::RetainedVersionObjectLock => {
            run_retained_version_checks(store, options, &mut checks).await?;
        }
    }

    Ok(V2ProviderConformanceReport {
        profile: options.profile,
        checks,
    })
}

async fn run_multipart_checks<S>(
    store: &S,
    options: &V2ProviderConformanceOptions,
    checks: &mut Vec<V2ProviderConformanceCheck>,
) -> V2Result<()>
where
    S: BlobStore,
{
    if !store.supports_multipart_upload() {
        checks.push(V2ProviderConformanceCheck::failed(
            "multipart-supported",
            "multipart upload unsupported",
        ));
        return Ok(());
    }
    checks.push(V2ProviderConformanceCheck::passed("multipart-supported"));

    let object_id = probe_object_id(options, "multipart")?;
    let first_part = Bytes::from(vec![b'a'; S3_MIN_MULTIPART_PART_BYTES]);
    let second_part = Bytes::from_static(b"tail-conformance");
    let content_len = u64::try_from(first_part.len() + second_part.len())
        .map_err(|_| V2FormatError::SectionBounds)?;

    let mut upload = match store
        .create_multipart_upload(
            &object_id,
            PutOptions {
                retention: retention_for_profile(options),
                legal_hold: None,
                content_type: Some("application/octet-stream".to_owned()),
                do_not_recreate: options.profile == V2ProviderProfile::AtomicCreate,
            },
        )
        .await
    {
        Ok(upload) => {
            checks.push(V2ProviderConformanceCheck::passed("multipart-create"));
            upload
        }
        Err(_) => {
            checks.push(V2ProviderConformanceCheck::failed(
                "multipart-create",
                "create multipart upload failed",
            ));
            return Ok(());
        }
    };

    if upload.put_part(0, first_part.clone()).await.is_err()
        || upload.put_part(1, second_part.clone()).await.is_err()
    {
        let _ = upload.abort().await;
        checks.push(V2ProviderConformanceCheck::failed(
            "multipart-put-part",
            "part upload failed",
        ));
        return Ok(());
    }
    checks.push(V2ProviderConformanceCheck::passed("multipart-put-part"));

    let metadata = match upload.complete().await {
        Ok(metadata) if metadata.content_len == content_len => {
            checks.push(V2ProviderConformanceCheck::passed("multipart-complete"));
            metadata
        }
        Ok(_) => {
            checks.push(V2ProviderConformanceCheck::failed(
                "multipart-complete",
                "metadata mismatch",
            ));
            return Ok(());
        }
        Err(_) => {
            checks.push(V2ProviderConformanceCheck::failed(
                "multipart-complete",
                "complete failed",
            ));
            return Ok(());
        }
    };

    match store.head(&object_id).await {
        Ok(head) if head.content_len == content_len => {
            checks.push(V2ProviderConformanceCheck::passed("multipart-head"));
        }
        Ok(_) => checks.push(V2ProviderConformanceCheck::failed(
            "multipart-head",
            "metadata mismatch",
        )),
        Err(_) => checks.push(V2ProviderConformanceCheck::failed(
            "multipart-head",
            "head failed",
        )),
    }

    match store
        .get_range_at(
            &object_id,
            metadata.version_id.as_ref(),
            ByteRange::Slice {
                offset: u64::try_from(S3_MIN_MULTIPART_PART_BYTES - 4)
                    .map_err(|_| V2FormatError::SectionBounds)?,
                len: 8,
            },
        )
        .await
    {
        Ok(read) if read == Bytes::from_static(b"aaaatail") => {
            checks.push(V2ProviderConformanceCheck::passed(
                "multipart-boundary-range-get",
            ));
        }
        Ok(_) => checks.push(V2ProviderConformanceCheck::failed(
            "multipart-boundary-range-get",
            "range mismatch",
        )),
        Err(_) => checks.push(V2ProviderConformanceCheck::failed(
            "multipart-boundary-range-get",
            "range get failed",
        )),
    }

    if options.profile == V2ProviderProfile::RetainedVersionObjectLock {
        match metadata.version_id.as_ref() {
            Some(version_id) => {
                checks.push(V2ProviderConformanceCheck::passed(
                    "multipart-retained-version-id",
                ));
                match store.head_at(&object_id, Some(version_id)).await {
                    Ok(head)
                        if retention_satisfies(head.retention.as_ref(), &options.retention) =>
                    {
                        checks.push(V2ProviderConformanceCheck::passed(
                            "multipart-retained-exact-head",
                        ));
                    }
                    Ok(_) => checks.push(V2ProviderConformanceCheck::failed(
                        "multipart-retained-exact-head",
                        "retention metadata mismatch",
                    )),
                    Err(_) => checks.push(V2ProviderConformanceCheck::failed(
                        "multipart-retained-exact-head",
                        "exact head failed",
                    )),
                }
            }
            None => checks.push(V2ProviderConformanceCheck::failed(
                "multipart-retained-version-id",
                "missing version id",
            )),
        }
    }

    if options.profile == V2ProviderProfile::AtomicCreate {
        run_multipart_atomic_complete_check(store, options, checks).await?;
    }

    Ok(())
}

async fn run_multipart_atomic_complete_check<S>(
    store: &S,
    options: &V2ProviderConformanceOptions,
    checks: &mut Vec<V2ProviderConformanceCheck>,
) -> V2Result<()>
where
    S: BlobStore,
{
    let object_id = probe_object_id(options, "multipart-atomic-complete")?;
    let original = Bytes::from_static(b"v2-multipart-atomic-original");
    let mut upload = match store
        .create_multipart_upload(
            &object_id,
            PutOptions {
                retention: None,
                legal_hold: None,
                content_type: None,
                do_not_recreate: true,
            },
        )
        .await
    {
        Ok(upload) => upload,
        Err(_) => {
            checks.push(V2ProviderConformanceCheck::failed(
                "multipart-atomic-open-before-race",
                "create multipart upload failed",
            ));
            return Ok(());
        }
    };
    checks.push(V2ProviderConformanceCheck::passed(
        "multipart-atomic-open-before-race",
    ));

    if store
        .put(
            &object_id,
            original.clone(),
            PutOptions {
                retention: None,
                legal_hold: None,
                content_type: None,
                do_not_recreate: true,
            },
        )
        .await
        .is_err()
    {
        let _ = upload.abort().await;
        checks.push(V2ProviderConformanceCheck::failed(
            "multipart-atomic-racing-put",
            "racing put failed",
        ));
        return Ok(());
    }
    checks.push(V2ProviderConformanceCheck::passed(
        "multipart-atomic-racing-put",
    ));

    if upload
        .put_part(0, Bytes::from(vec![b'z'; S3_MIN_MULTIPART_PART_BYTES]))
        .await
        .is_err()
    {
        let _ = upload.abort().await;
        checks.push(V2ProviderConformanceCheck::failed(
            "multipart-atomic-put-part",
            "part upload failed",
        ));
        return Ok(());
    }
    checks.push(V2ProviderConformanceCheck::passed(
        "multipart-atomic-put-part",
    ));

    match upload.complete().await {
        Err(StorageError::AlreadyExists(_)) => checks.push(V2ProviderConformanceCheck::passed(
            "multipart-atomic-complete-rejected",
        )),
        Ok(_) => checks.push(V2ProviderConformanceCheck::failed(
            "multipart-atomic-complete-rejected",
            "complete accepted after racing create",
        )),
        Err(_) => checks.push(V2ProviderConformanceCheck::failed(
            "multipart-atomic-complete-rejected",
            "unexpected complete error",
        )),
    }

    match store.get_range(&object_id, ByteRange::Full).await {
        Ok(read) if read == original => checks.push(V2ProviderConformanceCheck::passed(
            "multipart-atomic-preserves-existing",
        )),
        Ok(_) => checks.push(V2ProviderConformanceCheck::failed(
            "multipart-atomic-preserves-existing",
            "existing bytes changed",
        )),
        Err(_) => checks.push(V2ProviderConformanceCheck::failed(
            "multipart-atomic-preserves-existing",
            "read failed",
        )),
    }

    Ok(())
}

async fn run_basic_surface_checks<S>(
    store: &S,
    options: &V2ProviderConformanceOptions,
    checks: &mut Vec<V2ProviderConformanceCheck>,
) -> V2Result<()>
where
    S: BlobStore,
{
    let object_id = probe_object_id(options, "basic")?;
    let body = Bytes::from_static(b"v2-provider-basic-body");
    match store
        .put(
            &object_id,
            body.clone(),
            PutOptions {
                retention: None,
                legal_hold: None,
                content_type: Some("application/octet-stream".to_owned()),
                do_not_recreate: options.profile != V2ProviderProfile::RetainedVersionObjectLock,
            },
        )
        .await
    {
        Ok(metadata) if metadata.content_len == body.len() as u64 => {
            checks.push(V2ProviderConformanceCheck::passed("basic-put"));
        }
        Ok(_) => checks.push(V2ProviderConformanceCheck::failed(
            "basic-put",
            "metadata mismatch",
        )),
        Err(_) => checks.push(V2ProviderConformanceCheck::failed(
            "basic-put",
            "put failed",
        )),
    }

    match store.head(&object_id).await {
        Ok(metadata) if metadata.content_len == body.len() as u64 => {
            checks.push(V2ProviderConformanceCheck::passed("basic-head"));
        }
        Ok(_) => checks.push(V2ProviderConformanceCheck::failed(
            "basic-head",
            "metadata mismatch",
        )),
        Err(_) => checks.push(V2ProviderConformanceCheck::failed(
            "basic-head",
            "head failed",
        )),
    }

    match store.get_range(&object_id, ByteRange::Full).await {
        Ok(read) if read == body => checks.push(V2ProviderConformanceCheck::passed("basic-get")),
        Ok(_) => checks.push(V2ProviderConformanceCheck::failed(
            "basic-get",
            "body mismatch",
        )),
        Err(_) => {
            checks.push(V2ProviderConformanceCheck::failed(
                "basic-get",
                "get failed",
            ));
        }
    }

    match store
        .get_range(&object_id, ByteRange::Slice { offset: 3, len: 8 })
        .await
    {
        Ok(read) if read == Bytes::from_static(b"provider") => {
            checks.push(V2ProviderConformanceCheck::passed("basic-range-get"));
        }
        Ok(_) => checks.push(V2ProviderConformanceCheck::failed(
            "basic-range-get",
            "range mismatch",
        )),
        Err(_) => checks.push(V2ProviderConformanceCheck::failed(
            "basic-range-get",
            "range get failed",
        )),
    }

    match store.list_prefix(&options.probe_prefix).await {
        Ok(entries) if entries.iter().any(|entry| entry.object_id == object_id) => {
            checks.push(V2ProviderConformanceCheck::passed("basic-list"));
        }
        Ok(_) => checks.push(V2ProviderConformanceCheck::failed(
            "basic-list",
            "object missing from list",
        )),
        Err(_) => checks.push(V2ProviderConformanceCheck::failed(
            "basic-list",
            "list failed",
        )),
    }

    Ok(())
}

async fn run_atomic_create_checks<S>(
    store: &S,
    options: &V2ProviderConformanceOptions,
    checks: &mut Vec<V2ProviderConformanceCheck>,
) -> V2Result<()>
where
    S: BlobStore,
{
    let object_id = probe_object_id(options, "atomic-create")?;
    let original = Bytes::from_static(b"v2-atomic-original");
    let duplicate = Bytes::from_static(b"v2-atomic-duplicate");
    let first = store
        .put(
            &object_id,
            original.clone(),
            PutOptions {
                retention: None,
                legal_hold: None,
                content_type: None,
                do_not_recreate: true,
            },
        )
        .await;
    if first.is_err() {
        checks.push(V2ProviderConformanceCheck::failed(
            "atomic-create-first-put",
            "put failed",
        ));
        return Ok(());
    }
    checks.push(V2ProviderConformanceCheck::passed(
        "atomic-create-first-put",
    ));

    match store
        .put(
            &object_id,
            duplicate,
            PutOptions {
                retention: None,
                legal_hold: None,
                content_type: None,
                do_not_recreate: true,
            },
        )
        .await
    {
        Err(StorageError::AlreadyExists(_)) => checks.push(V2ProviderConformanceCheck::passed(
            "atomic-create-duplicate-rejected",
        )),
        Ok(_) => checks.push(V2ProviderConformanceCheck::failed(
            "atomic-create-duplicate-rejected",
            "duplicate accepted",
        )),
        Err(_) => checks.push(V2ProviderConformanceCheck::failed(
            "atomic-create-duplicate-rejected",
            "unexpected duplicate error",
        )),
    }

    match store.get_range(&object_id, ByteRange::Full).await {
        Ok(read) if read == original => checks.push(V2ProviderConformanceCheck::passed(
            "atomic-create-preserves-existing",
        )),
        Ok(_) => checks.push(V2ProviderConformanceCheck::failed(
            "atomic-create-preserves-existing",
            "existing bytes changed",
        )),
        Err(_) => checks.push(V2ProviderConformanceCheck::failed(
            "atomic-create-preserves-existing",
            "read failed",
        )),
    }

    Ok(())
}

async fn run_retained_version_checks<S>(
    store: &S,
    options: &V2ProviderConformanceOptions,
    checks: &mut Vec<V2ProviderConformanceCheck>,
) -> V2Result<()>
where
    S: BlobStore,
{
    let object_id = probe_object_id(options, "retained-version")?;
    let first_body = Bytes::from_static(b"v2-retained-version-one");
    let second_body = Bytes::from_static(b"v2-retained-version-two");
    let first = store
        .put(
            &object_id,
            first_body.clone(),
            PutOptions {
                retention: Some(options.retention),
                legal_hold: None,
                content_type: None,
                do_not_recreate: false,
            },
        )
        .await;
    let Ok(first) = first else {
        checks.push(V2ProviderConformanceCheck::failed(
            "retained-put-version-id",
            "retained put failed",
        ));
        return Ok(());
    };
    let Some(first_version) = first.version_id.clone() else {
        checks.push(V2ProviderConformanceCheck::failed(
            "retained-put-version-id",
            "missing version id",
        ));
        return Ok(());
    };
    checks.push(V2ProviderConformanceCheck::passed(
        "retained-put-version-id",
    ));

    match store.head_at(&object_id, Some(&first_version)).await {
        Ok(metadata) if retention_satisfies(metadata.retention.as_ref(), &options.retention) => {
            checks.push(V2ProviderConformanceCheck::passed("retained-exact-head"));
        }
        Ok(_) => checks.push(V2ProviderConformanceCheck::failed(
            "retained-exact-head",
            "retention metadata mismatch",
        )),
        Err(_) => checks.push(V2ProviderConformanceCheck::failed(
            "retained-exact-head",
            "exact head failed",
        )),
    }

    match store
        .get_range_at(&object_id, Some(&first_version), ByteRange::Full)
        .await
    {
        Ok(read) if read == first_body => {
            checks.push(V2ProviderConformanceCheck::passed("retained-exact-get"));
        }
        Ok(_) => checks.push(V2ProviderConformanceCheck::failed(
            "retained-exact-get",
            "body mismatch",
        )),
        Err(_) => checks.push(V2ProviderConformanceCheck::failed(
            "retained-exact-get",
            "exact get failed",
        )),
    }

    match store
        .get_range_at(
            &object_id,
            Some(&first_version),
            ByteRange::Slice { offset: 3, len: 8 },
        )
        .await
    {
        Ok(read) if read == Bytes::from_static(b"retained") => {
            checks.push(V2ProviderConformanceCheck::passed(
                "retained-exact-range-get",
            ));
        }
        Ok(_) => checks.push(V2ProviderConformanceCheck::failed(
            "retained-exact-range-get",
            "range mismatch",
        )),
        Err(_) => checks.push(V2ProviderConformanceCheck::failed(
            "retained-exact-range-get",
            "exact range get failed",
        )),
    }

    let second = store
        .put(
            &object_id,
            second_body.clone(),
            PutOptions {
                retention: Some(options.retention),
                legal_hold: None,
                content_type: None,
                do_not_recreate: false,
            },
        )
        .await;
    let Ok(second) = second else {
        checks.push(V2ProviderConformanceCheck::failed(
            "retained-overwrite-version-id",
            "new version put failed",
        ));
        return Ok(());
    };
    match second.version_id.as_ref() {
        Some(second_version) if second_version != &first_version => {
            checks.push(V2ProviderConformanceCheck::passed(
                "retained-overwrite-version-id",
            ));
        }
        Some(_) => checks.push(V2ProviderConformanceCheck::failed(
            "retained-overwrite-version-id",
            "version id reused",
        )),
        None => checks.push(V2ProviderConformanceCheck::failed(
            "retained-overwrite-version-id",
            "missing version id",
        )),
    }

    match store.get_range(&object_id, ByteRange::Full).await {
        Ok(read) if read == second_body => {
            checks.push(V2ProviderConformanceCheck::passed("retained-latest-get"));
        }
        Ok(_) => checks.push(V2ProviderConformanceCheck::failed(
            "retained-latest-get",
            "latest body mismatch",
        )),
        Err(_) => checks.push(V2ProviderConformanceCheck::failed(
            "retained-latest-get",
            "latest get failed",
        )),
    }

    match store
        .get_range_at(&object_id, Some(&first_version), ByteRange::Full)
        .await
    {
        Ok(read) if read == first_body => checks.push(V2ProviderConformanceCheck::passed(
            "retained-old-version-survives",
        )),
        Ok(_) => checks.push(V2ProviderConformanceCheck::failed(
            "retained-old-version-survives",
            "old version changed",
        )),
        Err(_) => checks.push(V2ProviderConformanceCheck::failed(
            "retained-old-version-survives",
            "old version read failed",
        )),
    }

    match store.list_prefix_versions(&options.probe_prefix).await {
        Ok(versions)
            if versions
                .iter()
                .any(|metadata| metadata.version_id.as_ref() == Some(&first_version))
                && versions
                    .iter()
                    .any(|metadata| metadata.version_id.as_ref() == second.version_id.as_ref()) =>
        {
            checks.push(V2ProviderConformanceCheck::passed(
                "retained-exact-version-inventory",
            ));
        }
        Ok(_) => checks.push(V2ProviderConformanceCheck::failed(
            "retained-exact-version-inventory",
            "expected versions missing",
        )),
        Err(_) => checks.push(V2ProviderConformanceCheck::failed(
            "retained-exact-version-inventory",
            "version inventory failed",
        )),
    }

    match store.delete_at(&object_id, Some(&first_version)).await {
        Err(StorageError::RetentionBlocked | StorageError::LegalHoldBlocked) => {
            checks.push(V2ProviderConformanceCheck::passed(
                "retained-active-exact-delete-blocked",
            ));
        }
        Ok(()) => checks.push(V2ProviderConformanceCheck::failed(
            "retained-active-exact-delete-blocked",
            "exact delete succeeded",
        )),
        Err(_) => checks.push(V2ProviderConformanceCheck::failed(
            "retained-active-exact-delete-blocked",
            "unexpected exact delete error",
        )),
    }

    run_unprotected_exact_delete_check(store, options, checks).await?;

    let extended = RetentionPolicy::new(options.retention.mode, options.retention.retain_days + 1);
    match store
        .extend_retention_at(&object_id, Some(&first_version), extended)
        .await
    {
        Ok(()) => match store.head_at(&object_id, Some(&first_version)).await {
            Ok(metadata) if retention_satisfies(metadata.retention.as_ref(), &extended) => {
                checks.push(V2ProviderConformanceCheck::passed(
                    "retained-extension-verifiable",
                ));
            }
            Ok(_) => checks.push(V2ProviderConformanceCheck::failed(
                "retained-extension-verifiable",
                "extension metadata mismatch",
            )),
            Err(_) => checks.push(V2ProviderConformanceCheck::failed(
                "retained-extension-verifiable",
                "head after extension failed",
            )),
        },
        Err(_) => checks.push(V2ProviderConformanceCheck::failed(
            "retained-extension-verifiable",
            "extension failed",
        )),
    }

    match store.delete(&object_id).await {
        Err(StorageError::RetentionBlocked | StorageError::LegalHoldBlocked) => checks.push(
            V2ProviderConformanceCheck::passed("retained-delete-blocked"),
        ),
        Ok(()) => checks.push(V2ProviderConformanceCheck::failed(
            "retained-delete-blocked",
            "delete succeeded",
        )),
        Err(_) => checks.push(V2ProviderConformanceCheck::failed(
            "retained-delete-blocked",
            "unexpected delete error",
        )),
    }

    if options.legal_hold {
        run_legal_hold_checks(store, options, checks).await?;
    }

    if options.retention.mode == RetentionMode::Governance {
        if options.governance_bypass_reviewed {
            checks.push(V2ProviderConformanceCheck::passed(
                "retained-governance-bypass-review",
            ));
        } else {
            checks.push(V2ProviderConformanceCheck::failed(
                "retained-governance-bypass-review",
                "operator IAM review missing",
            ));
        }
    } else {
        checks.push(V2ProviderConformanceCheck::passed(
            "retained-governance-bypass-review",
        ));
    }

    Ok(())
}

async fn run_unprotected_exact_delete_check<S>(
    store: &S,
    options: &V2ProviderConformanceOptions,
    checks: &mut Vec<V2ProviderConformanceCheck>,
) -> V2Result<()>
where
    S: BlobStore,
{
    let object_id = probe_object_id(options, "retained-unprotected-delete")?;
    let put = store
        .put(
            &object_id,
            Bytes::from_static(b"v2-retained-unprotected-delete"),
            PutOptions {
                retention: None,
                legal_hold: None,
                content_type: None,
                do_not_recreate: false,
            },
        )
        .await;
    let Ok(put) = put else {
        checks.push(V2ProviderConformanceCheck::failed(
            "retained-unprotected-exact-delete",
            "unprotected put failed",
        ));
        return Ok(());
    };
    let Some(version_id) = put.version_id.clone() else {
        checks.push(V2ProviderConformanceCheck::failed(
            "retained-unprotected-exact-delete",
            "missing version id",
        ));
        return Ok(());
    };

    match store.delete_at(&object_id, Some(&version_id)).await {
        Ok(()) => match store.head_at(&object_id, Some(&version_id)).await {
            Err(StorageError::NotFound(_)) => checks.push(V2ProviderConformanceCheck::passed(
                "retained-unprotected-exact-delete",
            )),
            Ok(_) => checks.push(V2ProviderConformanceCheck::failed(
                "retained-unprotected-exact-delete",
                "version still visible",
            )),
            Err(_) => checks.push(V2ProviderConformanceCheck::failed(
                "retained-unprotected-exact-delete",
                "head after delete failed unexpectedly",
            )),
        },
        Err(_) => checks.push(V2ProviderConformanceCheck::failed(
            "retained-unprotected-exact-delete",
            "exact delete failed",
        )),
    }

    Ok(())
}

async fn run_legal_hold_checks<S>(
    store: &S,
    options: &V2ProviderConformanceOptions,
    checks: &mut Vec<V2ProviderConformanceCheck>,
) -> V2Result<()>
where
    S: BlobStore,
{
    let object_id = probe_object_id(options, "legal-hold")?;
    let put = store
        .put(
            &object_id,
            Bytes::from_static(b"v2-legal-hold-body"),
            PutOptions {
                retention: None,
                legal_hold: Some(LegalHoldStatus::On),
                content_type: None,
                do_not_recreate: false,
            },
        )
        .await;
    let Ok(put) = put else {
        checks.push(V2ProviderConformanceCheck::failed(
            "legal-hold-put-version-id",
            "put failed",
        ));
        return Ok(());
    };
    let Some(version_id) = put.version_id.clone() else {
        checks.push(V2ProviderConformanceCheck::failed(
            "legal-hold-put-version-id",
            "missing version id",
        ));
        return Ok(());
    };
    checks.push(V2ProviderConformanceCheck::passed(
        "legal-hold-put-version-id",
    ));

    match store.head_at(&object_id, Some(&version_id)).await {
        Ok(metadata) if metadata.legal_hold == Some(LegalHoldStatus::On) => {
            checks.push(V2ProviderConformanceCheck::passed("legal-hold-verifiable"));
        }
        Ok(_) => checks.push(V2ProviderConformanceCheck::failed(
            "legal-hold-verifiable",
            "legal hold metadata mismatch",
        )),
        Err(_) => checks.push(V2ProviderConformanceCheck::failed(
            "legal-hold-verifiable",
            "head failed",
        )),
    }

    match store.delete(&object_id).await {
        Err(StorageError::LegalHoldBlocked | StorageError::RetentionBlocked) => {
            checks.push(V2ProviderConformanceCheck::passed(
                "legal-hold-delete-blocked",
            ));
        }
        Ok(()) => checks.push(V2ProviderConformanceCheck::failed(
            "legal-hold-delete-blocked",
            "delete succeeded",
        )),
        Err(_) => checks.push(V2ProviderConformanceCheck::failed(
            "legal-hold-delete-blocked",
            "unexpected delete error",
        )),
    }

    Ok(())
}

fn probe_object_id(
    options: &V2ProviderConformanceOptions,
    name: &'static str,
) -> V2Result<BackendObjectId> {
    BackendObjectId::new(format!(
        "{}/{name}",
        options.probe_prefix.trim_end_matches('/')
    ))
    .map_err(Into::into)
}

fn retention_for_profile(options: &V2ProviderConformanceOptions) -> Option<RetentionPolicy> {
    (options.profile == V2ProviderProfile::RetainedVersionObjectLock).then_some(options.retention)
}

fn retention_satisfies(actual: Option<&RetentionPolicy>, requested: &RetentionPolicy) -> bool {
    let Some(actual) = actual else {
        return false;
    };
    retention_mode_strength(actual.mode) >= retention_mode_strength(requested.mode)
        && actual.retain_days >= requested.retain_days
}

fn retention_mode_strength(mode: RetentionMode) -> u8 {
    match mode {
        RetentionMode::None => 0,
        RetentionMode::Governance => 1,
        RetentionMode::Compliance => 2,
    }
}
