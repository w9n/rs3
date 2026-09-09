//! Recovery promises and conservative deadlines, independent of provider I/O.

use crate::v3::{V3FormatError, V3Result};
use rs3_crypto::Sha256Hasher;
use rs3_types::{RetentionMode, RetentionPolicy};

const DAY_MS: i64 = 86_400_000;
const MAX_WINDOW_DAYS: u32 = 36_500;
const MAX_MARGIN_SECONDS: u32 = 365 * 86_400;
const MAX_CLOCK_UNCERTAINTY_MS: u32 = 3_600_000;

/// Validated preview policy authenticated with each current recovery point.
///
/// Changing configuration governs newly published points. An already accepted
/// point retains its governing policy until supersession fixes its deadline.
/// Reclamation is a separate operational switch and cannot disable protection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryPolicy {
    window_days: u32,
    renewal_margin_seconds: u32,
    clock_uncertainty_ms: u32,
}

impl RecoveryPolicy {
    /// Visible deployment preset: thirty days, one day of renewal margin,
    /// and a sixty-second bound on the operator's trusted clock uncertainty.
    pub const PRESET: Self = Self {
        window_days: 30,
        renewal_margin_seconds: 86_400,
        clock_uncertainty_ms: 60_000,
    };

    /// Validates finite positive protection and clock assumptions.
    ///
    /// The renewal margin must exceed clock uncertainty. It is an operational
    /// outage allowance, not an extension of the advertised recovery window.
    pub fn new(
        window_days: u32,
        renewal_margin_seconds: u32,
        clock_uncertainty_ms: u32,
    ) -> V3Result<Self> {
        if !(1..=MAX_WINDOW_DAYS).contains(&window_days)
            || !(1..=MAX_MARGIN_SECONDS).contains(&renewal_margin_seconds)
            || !(1..=MAX_CLOCK_UNCERTAINTY_MS).contains(&clock_uncertainty_ms)
            || u64::from(renewal_margin_seconds) * 1_000 <= u64::from(clock_uncertainty_ms)
        {
            return Err(V3FormatError::InvalidRecoveryPolicy);
        }
        Ok(Self {
            window_days,
            renewal_margin_seconds,
            clock_uncertainty_ms,
        })
    }

    /// Full recoverability window promised at supersession, in days.
    pub const fn window_days(self) -> u32 {
        self.window_days
    }

    /// Additional provider-protection runway reserved for renewal outages.
    pub const fn renewal_margin_seconds(self) -> u32 {
        self.renewal_margin_seconds
    }

    /// Declared maximum error of the trusted current-time input.
    pub const fn clock_uncertainty_ms(self) -> u32 {
        self.clock_uncertainty_ms
    }

    /// Domain-separated identity of the complete immutable promise policy.
    pub fn identity(self) -> [u8; 32] {
        let mut digest = Sha256Hasher::new();
        digest.update(b"rs3:recovery-policy:v03\n");
        digest.update(self.window_days.to_be_bytes());
        digest.update(self.renewal_margin_seconds.to_be_bytes());
        digest.update(self.clock_uncertainty_ms.to_be_bytes());
        digest.finalize()
    }

    /// Fixes a predecessor's promised deadline using its accepted policy.
    /// The uncertainty allowance covers the bounded delay between choosing the
    /// successor timestamp and accepting its CAS, even if later policy changes
    /// reduce clock uncertainty. Callers must enforce that pre-CAS age bound.
    pub fn promised_until_ms(self, superseded_at_ms: i64) -> V3Result<i64> {
        checked_deadline(
            superseded_at_ms,
            i64::from(self.window_days) * DAY_MS + i64::from(self.clock_uncertainty_ms),
        )
    }

    /// Absolute backend protection required to cover a promise and renewal
    /// runway. Backend observations must be verified against this deadline.
    pub fn coverage_until_ms(self, superseded_at_ms: i64) -> V3Result<i64> {
        checked_deadline(
            self.promised_until_ms(superseded_at_ms)?,
            i64::from(self.renewal_margin_seconds) * 1_000 + i64::from(self.clock_uncertainty_ms),
        )
    }

    /// Conservative proposed expiry cutoff. This calculation alone does not
    /// authorize deletion: expiry must be published under the accepted history,
    /// clock assumptions, writer fence and ordinary anchor protocol.
    pub fn expiry_cutoff_ms(self, trusted_now_ms: i64) -> V3Result<i64> {
        if trusted_now_ms < 0 {
            return Err(V3FormatError::InvalidPublicationTime);
        }
        Ok((trusted_now_ms - i64::from(self.clock_uncertainty_ms)).max(0))
    }
}

fn checked_deadline(base_ms: i64, offset_ms: i64) -> V3Result<i64> {
    base_ms
        .checked_add(offset_ms)
        .filter(|_| base_ms >= 0)
        .ok_or(V3FormatError::InvalidPublicationTime)
}

/// Rounds an absolute provider deadline upward to its UTC-day bucket.
///
/// Our storage adapter accepts retention as a relative whole-day policy.
/// Planning with this canonical physical floor keeps a quiescent preview and
/// apply stable during one bucket, while never shortening the exact protection
/// required by the logical policy.
pub(crate) fn ceil_physical_deadline_ms(required_until_ms: i64) -> V3Result<i64> {
    if required_until_ms < 0 {
        return Err(V3FormatError::InvalidPublicationTime);
    }
    let remainder = required_until_ms % DAY_MS;
    required_until_ms
        .checked_add((DAY_MS - remainder) % DAY_MS)
        .ok_or(V3FormatError::InvalidPublicationTime)
}

/// Translates an absolute minimum into the provider's relative-day primitive.
/// The caller must still verify the exact returned deadline after the write or
/// extension; this calculation cannot establish backend protection by itself.
pub(crate) fn physical_retention_for_deadline(
    retention: Option<RetentionPolicy>,
    required_until_ms: Option<i64>,
    now_ms: i64,
) -> V3Result<Option<RetentionPolicy>> {
    let Some(required) = required_until_ms else {
        return Ok(retention);
    };
    let mut policy = retention
        .filter(|policy| policy.mode != RetentionMode::None && policy.retain_days > 0)
        .ok_or(V3FormatError::ProviderProfileFailed)?;
    if required < 0 || now_ms < 0 {
        return Err(V3FormatError::InvalidPublicationTime);
    }
    let remaining_ms = required.saturating_sub(now_ms).max(0);
    let days = u32::try_from(remaining_ms / DAY_MS + i64::from(remaining_ms % DAY_MS != 0))
        .map_err(|_| V3FormatError::InvalidRecoveryPolicy)?;
    policy.retain_days = policy.retain_days.max(days);
    Ok(Some(policy))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supersession_keeps_the_predecessors_accepted_promise() {
        let old = RecoveryPolicy::PRESET;
        let reduced = RecoveryPolicy::new(1, 86_400, 60_000).expect("valid policy");
        let superseded = 40 * DAY_MS;
        assert_eq!(old.promised_until_ms(superseded), Ok(70 * DAY_MS + 60_000));
        assert_eq!(
            reduced.promised_until_ms(superseded),
            Ok(41 * DAY_MS + 60_000)
        );
        assert_eq!(old.coverage_until_ms(superseded), Ok(71 * DAY_MS + 120_000));
        assert_ne!(old.identity(), reduced.identity());
    }

    #[test]
    fn policy_and_time_bounds_fail_closed() {
        for values in [
            (0, 86_400, 60_000),
            (36_501, 86_400, 60_000),
            (30, 0, 60_000),
            (30, MAX_MARGIN_SECONDS + 1, 60_000),
            (30, 60, 60_000),
            (30, 86_400, 0),
            (30, 86_400, MAX_CLOCK_UNCERTAINTY_MS + 1),
        ] {
            assert_eq!(
                RecoveryPolicy::new(values.0, values.1, values.2),
                Err(V3FormatError::InvalidRecoveryPolicy)
            );
        }
        let policy = RecoveryPolicy::PRESET;
        for timestamp in [-1, i64::MAX] {
            assert_eq!(
                policy.promised_until_ms(timestamp),
                Err(V3FormatError::InvalidPublicationTime)
            );
            assert_eq!(
                policy.coverage_until_ms(timestamp),
                Err(V3FormatError::InvalidPublicationTime)
            );
        }
        assert_eq!(policy.expiry_cutoff_ms(100_000), Ok(40_000));
        assert_eq!(policy.expiry_cutoff_ms(10_000), Ok(0));
        assert_eq!(
            policy.expiry_cutoff_ms(-1),
            Err(V3FormatError::InvalidPublicationTime)
        );
    }

    #[test]
    fn physical_deadlines_round_up_without_weakening_the_logical_floor() {
        assert_eq!(ceil_physical_deadline_ms(0), Ok(0));
        assert_eq!(ceil_physical_deadline_ms(DAY_MS), Ok(DAY_MS));
        assert_eq!(ceil_physical_deadline_ms(DAY_MS + 1), Ok(2 * DAY_MS));
        assert_eq!(
            ceil_physical_deadline_ms(i64::MAX),
            Err(V3FormatError::InvalidPublicationTime)
        );
        assert_eq!(
            ceil_physical_deadline_ms(-1),
            Err(V3FormatError::InvalidPublicationTime)
        );
    }

    #[test]
    fn physical_days_round_up_without_changing_logical_policy_or_shortening() {
        let logical = RetentionPolicy::new(RetentionMode::Compliance, 1);
        let physical = physical_retention_for_deadline(Some(logical), Some(DAY_MS + 1), 0)
            .expect("bounded deadline")
            .expect("active retention");
        assert_eq!(physical.mode, RetentionMode::Compliance);
        assert_eq!(physical.retain_days, 2);
        assert_eq!(logical.retain_days, 1);
        assert_eq!(
            physical_retention_for_deadline(Some(physical), Some(1), DAY_MS),
            Ok(Some(physical))
        );
        assert_eq!(
            physical_retention_for_deadline(None, Some(DAY_MS), 0),
            Err(V3FormatError::ProviderProfileFailed)
        );
    }
}
