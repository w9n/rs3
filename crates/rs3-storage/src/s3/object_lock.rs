use crate::{Result, StorageError};
use aws_sdk_s3::primitives::DateTime as SdkDateTime;
use aws_sdk_s3::types::{
    ObjectLockLegalHold, ObjectLockLegalHoldStatus as SdkObjectLockLegalHoldStatus,
    ObjectLockMode as SdkObjectLockMode, ObjectLockRetentionMode,
};
use rs3_types::{LegalHoldStatus, RetentionMode, RetentionPolicy};
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
    let now_secs = current_epoch_secs()?;
    let retain_secs = i64::from(policy.retain_days)
        .checked_mul(86_400)
        .ok_or_else(|| StorageError::Provider("retention period is out of range".to_owned()))?;
    let retain_until_secs = now_secs
        .checked_add(retain_secs)
        .ok_or_else(|| StorageError::Provider("retention date is out of range".to_owned()))?;
    Ok(SdkDateTime::from_secs(retain_until_secs))
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

fn current_epoch_secs() -> Result<i64> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| StorageError::Provider(error.to_string()))?
        .as_secs();
    i64::try_from(secs)
        .map_err(|_| StorageError::Provider("current time is out of range".to_owned()))
}
