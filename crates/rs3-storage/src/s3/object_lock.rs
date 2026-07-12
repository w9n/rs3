use crate::{BlobMetadata, Result, StorageError};
use aws_sdk_s3::primitives::DateTime as SdkDateTime;
use aws_sdk_s3::types::{
    ObjectLockLegalHold, ObjectLockLegalHoldStatus as SdkObjectLockLegalHoldStatus,
    ObjectLockMode as SdkObjectLockMode, ObjectLockRetentionMode,
};
use rs3_types::{
    BackendObjectId, BackendVersionId, LegalHoldStatus, RetentionMode, RetentionPolicy,
};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn retention_is_active(policy: &RetentionPolicy) -> bool {
    policy.mode != RetentionMode::None && policy.retain_days > 0
}

pub(super) fn retention_blocks_delete(policy: Option<&RetentionPolicy>) -> bool {
    policy.is_some_and(retention_is_active)
}

pub(super) fn legal_hold_blocks_delete(status: Option<LegalHoldStatus>) -> bool {
    status == Some(LegalHoldStatus::On)
}

pub(super) fn provider_legal_hold(status: Option<LegalHoldStatus>) -> Option<LegalHoldStatus> {
    status.filter(|status| *status == LegalHoldStatus::On)
}

pub(super) fn retain_until_date(policy: &RetentionPolicy) -> Result<SdkDateTime> {
    let now_ms = current_epoch_ms()?;
    let retain_ms = i64::from(policy.retain_days)
        .checked_mul(86_400_000)
        .ok_or_else(|| StorageError::Provider("retention period is out of range".to_owned()))?;
    let retain_until_ms = now_ms
        .checked_add(retain_ms)
        .ok_or_else(|| StorageError::Provider("retention date is out of range".to_owned()))?;
    Ok(SdkDateTime::from_millis(retain_until_ms))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RetentionExtension {
    pub(super) policy: RetentionPolicy,
    pub(super) retain_until_ms: i64,
    pub(super) update_required: bool,
}

pub(super) fn plan_retention_extension(
    actual: Option<&RetentionPolicy>,
    actual_retain_until_ms: Option<i64>,
    requested: RetentionPolicy,
    now_ms: i64,
) -> Result<RetentionExtension> {
    if !retention_is_active(&requested) {
        return Err(StorageError::Provider(
            "retention extension requires an active policy".to_owned(),
        ));
    }
    if actual.is_some() != actual_retain_until_ms.is_some() {
        return Err(StorageError::Provider(
            "S3 HEAD returned partial Object Lock metadata".to_owned(),
        ));
    }

    let requested_duration_ms = i64::from(requested.retain_days)
        .checked_mul(86_400_000)
        .ok_or_else(|| StorageError::Provider("retention period is out of range".to_owned()))?;
    let requested_retain_until_ms = now_ms
        .checked_add(requested_duration_ms)
        .ok_or_else(|| StorageError::Provider("retention date is out of range".to_owned()))?;
    let mode = actual
        .map(|actual| stronger_retention_mode(actual.mode, requested.mode))
        .unwrap_or(requested.mode);
    let retain_until_ms = actual_retain_until_ms
        .map(|actual| actual.max(requested_retain_until_ms))
        .unwrap_or(requested_retain_until_ms);
    let update_required = actual
        .is_none_or(|actual| retention_mode_strength(actual.mode) < retention_mode_strength(mode))
        || actual_retain_until_ms.is_none_or(|actual| actual < requested_retain_until_ms);

    Ok(RetentionExtension {
        policy: RetentionPolicy::new(mode, requested.retain_days),
        retain_until_ms,
        update_required,
    })
}

pub(super) fn verify_retention_extension(
    metadata: &BlobMetadata,
    object_id: &BackendObjectId,
    version_id: Option<&BackendVersionId>,
    expected_content_len: u64,
    extension: RetentionExtension,
) -> Result<()> {
    if metadata.object_id != *object_id
        || metadata.content_len != expected_content_len
        || version_id.is_some() && metadata.version_id.as_ref() != version_id
        || !retention_satisfies(metadata.retention.as_ref(), &extension.policy)
        || metadata
            .retain_until_ms
            .is_none_or(|actual| actual < extension.retain_until_ms)
    {
        return Err(StorageError::Provider(
            "S3 Object Lock extension verification failed".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn sdk_retention_extension_date(extension: RetentionExtension) -> SdkDateTime {
    SdkDateTime::from_millis(extension.retain_until_ms)
}

pub(super) fn sdk_object_lock_mode(policy: &RetentionPolicy) -> Result<SdkObjectLockMode> {
    match policy.mode {
        RetentionMode::Compliance => Ok(SdkObjectLockMode::Compliance),
        RetentionMode::Governance => Ok(SdkObjectLockMode::Governance),
        RetentionMode::None => Err(StorageError::Provider(
            "Object Lock mode cannot be None for retained S3 PUT".to_owned(),
        )),
    }
}

pub(super) fn sdk_object_lock_retention_mode(
    policy: &RetentionPolicy,
) -> Result<ObjectLockRetentionMode> {
    match policy.mode {
        RetentionMode::Compliance => Ok(ObjectLockRetentionMode::Compliance),
        RetentionMode::Governance => Ok(ObjectLockRetentionMode::Governance),
        RetentionMode::None => Err(StorageError::Provider(
            "Object Lock mode cannot be None for retained S3 operation".to_owned(),
        )),
    }
}

pub(super) fn sdk_legal_hold_status(status: LegalHoldStatus) -> SdkObjectLockLegalHoldStatus {
    match status {
        LegalHoldStatus::Off => SdkObjectLockLegalHoldStatus::Off,
        LegalHoldStatus::On => SdkObjectLockLegalHoldStatus::On,
    }
}

pub(super) fn retention_from_s3_head(
    mode: Option<&SdkObjectLockMode>,
    retain_until_date: Option<&SdkDateTime>,
) -> Result<Option<RetentionPolicy>> {
    let (Some(mode), Some(retain_until_date)) = (mode, retain_until_date) else {
        if mode.is_some() || retain_until_date.is_some() {
            return Err(StorageError::Provider(
                "S3 HEAD returned partial Object Lock metadata".to_owned(),
            ));
        }
        return Ok(None);
    };

    let mode = match mode {
        SdkObjectLockMode::Compliance => RetentionMode::Compliance,
        SdkObjectLockMode::Governance => RetentionMode::Governance,
        _ => {
            return Err(StorageError::Provider(
                "S3 HEAD returned an unknown Object Lock mode".to_owned(),
            ));
        }
    };
    let now_secs = current_epoch_secs()?;
    let retain_days = if retain_until_date.secs() <= now_secs {
        0
    } else {
        ceil_days_from_seconds(retain_until_date.secs() - now_secs)?
    };
    Ok(Some(RetentionPolicy::new(mode, retain_days)))
}

pub(super) fn retain_until_ms_from_s3_head(
    retain_until_date: Option<&SdkDateTime>,
) -> Result<Option<i64>> {
    retain_until_date
        .map(|retain_until_date| retain_until_date.to_millis())
        .transpose()
        .map_err(|error| StorageError::Provider(error.to_string()))
}

pub(super) fn legal_hold_from_s3_head(
    status: Option<&SdkObjectLockLegalHoldStatus>,
) -> Result<Option<LegalHoldStatus>> {
    status.map(legal_hold_from_sdk_status).transpose()
}

pub(super) fn legal_hold_from_s3_legal_hold(
    legal_hold: Option<&ObjectLockLegalHold>,
) -> Result<Option<LegalHoldStatus>> {
    let Some(legal_hold) = legal_hold else {
        return Ok(None);
    };
    legal_hold
        .status()
        .map(legal_hold_from_sdk_status)
        .transpose()
}

pub(super) fn verify_retention(
    actual: Option<&RetentionPolicy>,
    requested: &RetentionPolicy,
) -> Result<()> {
    if retention_satisfies(actual, requested) {
        Ok(())
    } else {
        Err(StorageError::Provider(
            "S3 Object Lock verification failed".to_owned(),
        ))
    }
}

pub(super) fn verify_legal_hold(
    actual: Option<LegalHoldStatus>,
    requested: LegalHoldStatus,
) -> Result<()> {
    if legal_hold_satisfies(actual, requested) {
        Ok(())
    } else {
        Err(StorageError::Provider(
            "S3 Object Lock legal hold verification failed".to_owned(),
        ))
    }
}

pub(super) fn retention_satisfies(
    actual: Option<&RetentionPolicy>,
    requested: &RetentionPolicy,
) -> bool {
    if !retention_is_active(requested) {
        return true;
    }
    let Some(actual) = actual else {
        return false;
    };
    retention_mode_strength(actual.mode) >= retention_mode_strength(requested.mode)
        && actual.retain_days >= requested.retain_days
}

pub(super) fn retention_mode_label(mode: RetentionMode) -> &'static str {
    match mode {
        RetentionMode::None => "none",
        RetentionMode::Governance => "governance",
        RetentionMode::Compliance => "compliance",
    }
}

fn legal_hold_from_sdk_status(status: &SdkObjectLockLegalHoldStatus) -> Result<LegalHoldStatus> {
    match status {
        SdkObjectLockLegalHoldStatus::Off => Ok(LegalHoldStatus::Off),
        SdkObjectLockLegalHoldStatus::On => Ok(LegalHoldStatus::On),
        _ => Err(StorageError::Provider(
            "S3 returned an unknown Object Lock legal hold status".to_owned(),
        )),
    }
}

fn ceil_days_from_seconds(seconds: i64) -> Result<u32> {
    let seconds = u64::try_from(seconds)
        .map_err(|_| StorageError::Provider("retention date is before current time".to_owned()))?;
    let days = seconds.div_ceil(86_400);
    u32::try_from(days)
        .map_err(|_| StorageError::Provider("retention period exceeds u32 days".to_owned()))
}

fn legal_hold_satisfies(actual: Option<LegalHoldStatus>, requested: LegalHoldStatus) -> bool {
    match requested {
        LegalHoldStatus::Off => actual.is_none_or(|actual| actual == LegalHoldStatus::Off),
        LegalHoldStatus::On => actual == Some(LegalHoldStatus::On),
    }
}

fn retention_mode_strength(mode: RetentionMode) -> u8 {
    match mode {
        RetentionMode::None => 0,
        RetentionMode::Governance => 1,
        RetentionMode::Compliance => 2,
    }
}

fn stronger_retention_mode(left: RetentionMode, right: RetentionMode) -> RetentionMode {
    if retention_mode_strength(left) >= retention_mode_strength(right) {
        left
    } else {
        right
    }
}

pub(super) fn current_epoch_ms() -> Result<i64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| StorageError::Provider(error.to_string()))?
        .as_millis();
    i64::try_from(millis)
        .map_err(|_| StorageError::Provider("current time is out of range".to_owned()))
}

fn current_epoch_secs() -> Result<i64> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| StorageError::Provider(error.to_string()))?
        .as_secs();
    i64::try_from(secs)
        .map_err(|_| StorageError::Provider("current time is out of range".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::{RetentionExtension, plan_retention_extension, verify_retention_extension};
    use crate::BlobMetadata;
    use rs3_types::{BackendObjectId, BackendVersionId, RetentionMode, RetentionPolicy};

    const DAY_MS: i64 = 86_400_000;

    fn object_id() -> BackendObjectId {
        BackendObjectId::new("objects/v02/retention-test").unwrap_or_else(|error| panic!("{error}"))
    }

    fn version_id(value: &str) -> BackendVersionId {
        BackendVersionId::new(value).unwrap_or_else(|error| panic!("{error}"))
    }

    fn metadata(
        version_id: BackendVersionId,
        policy: Option<RetentionPolicy>,
        retain_until_ms: Option<i64>,
    ) -> BlobMetadata {
        BlobMetadata {
            object_id: object_id(),
            content_len: 4096,
            modified_at_ms: None,
            etag: None,
            version_id: Some(version_id),
            retention: policy,
            retain_until_ms,
            legal_hold: None,
        }
    }

    #[test]
    fn same_policy_nearing_expiry_advances_from_one_captured_time() {
        let now_ms = 1_700_000_000_000;
        let actual = RetentionPolicy::new(RetentionMode::Governance, 30);
        let extension = plan_retention_extension(
            Some(&actual),
            Some(now_ms + 5 * DAY_MS),
            RetentionPolicy::new(RetentionMode::Governance, 30),
            now_ms,
        )
        .unwrap_or_else(|error| panic!("{error}"));

        assert!(extension.update_required);
        assert_eq!(extension.policy.mode, RetentionMode::Governance);
        assert_eq!(extension.retain_until_ms, now_ms + 30 * DAY_MS);
    }

    #[test]
    fn stronger_compliance_mode_and_longer_deadline_are_preserved() {
        let now_ms = 1_700_000_000_000;
        let actual = RetentionPolicy::new(RetentionMode::Compliance, 90);
        let actual_deadline = now_ms + 90 * DAY_MS;
        let extension = plan_retention_extension(
            Some(&actual),
            Some(actual_deadline),
            RetentionPolicy::new(RetentionMode::Governance, 30),
            now_ms,
        )
        .unwrap_or_else(|error| panic!("{error}"));

        assert!(!extension.update_required);
        assert_eq!(extension.policy.mode, RetentionMode::Compliance);
        assert_eq!(extension.retain_until_ms, actual_deadline);
    }

    #[test]
    fn verification_is_bound_to_the_exact_version() {
        let expected_version = version_id("expected-version");
        let extension = RetentionExtension {
            policy: RetentionPolicy::new(RetentionMode::Compliance, 30),
            retain_until_ms: 1_800_000_000_000,
            update_required: true,
        };
        let exact = metadata(
            expected_version.clone(),
            Some(extension.policy),
            Some(extension.retain_until_ms),
        );
        assert!(
            verify_retention_extension(
                &exact,
                &object_id(),
                Some(&expected_version),
                4096,
                extension,
            )
            .is_ok()
        );

        let wrong = metadata(
            version_id("wrong-version"),
            Some(extension.policy),
            Some(extension.retain_until_ms),
        );
        assert!(
            verify_retention_extension(
                &wrong,
                &object_id(),
                Some(&expected_version),
                4096,
                extension,
            )
            .is_err()
        );
    }

    #[test]
    fn ambiguous_success_without_a_verified_deadline_fails_closed() {
        let version = version_id("exact-version");
        let extension = RetentionExtension {
            policy: RetentionPolicy::new(RetentionMode::Governance, 30),
            retain_until_ms: 1_800_000_000_000,
            update_required: true,
        };
        let unverifiable = metadata(version.clone(), Some(extension.policy), None);

        assert!(
            verify_retention_extension(
                &unverifiable,
                &object_id(),
                Some(&version),
                4096,
                extension,
            )
            .is_err()
        );
    }
}
