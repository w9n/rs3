//! Shared retention policy comparisons, independent of provider wall clocks.

use rs3_types::{RetentionMode, RetentionPolicy};

/// Keeps a policy only when it requests a nonzero protection period.
pub fn active_retention(policy: Option<RetentionPolicy>) -> Option<RetentionPolicy> {
    policy.filter(retention_is_active)
}

pub(crate) fn retention_is_active(policy: &RetentionPolicy) -> bool {
    policy.mode != RetentionMode::None && policy.retain_days > 0
}

pub(crate) fn retention_mode_strength(mode: RetentionMode) -> u8 {
    match mode {
        RetentionMode::None => 0,
        RetentionMode::Governance => 1,
        RetentionMode::Compliance => 2,
    }
}

pub(crate) fn stronger_retention_mode(left: RetentionMode, right: RetentionMode) -> RetentionMode {
    if retention_mode_strength(left) >= retention_mode_strength(right) {
        left
    } else {
        right
    }
}

/// Combines active policy requirements without reducing mode or duration.
///
/// Inactive policies contribute neither strength nor duration. This compares
/// policy requirements only; provider expiry timestamps must be checked separately.
pub fn strongest_retention_policy(
    left: Option<RetentionPolicy>,
    right: Option<RetentionPolicy>,
) -> Option<RetentionPolicy> {
    match (active_retention(left), active_retention(right)) {
        (Some(left), Some(right)) => Some(RetentionPolicy::new(
            stronger_retention_mode(left.mode, right.mode),
            left.retain_days.max(right.retain_days),
        )),
        (Some(policy), None) | (None, Some(policy)) => Some(policy),
        (None, None) => None,
    }
}

/// Compares a present policy's strength and duration against a requirement.
///
/// This does not establish whether any absolute provider retention date is live.
pub fn retention_satisfies(actual: Option<&RetentionPolicy>, requested: &RetentionPolicy) -> bool {
    let Some(actual) = actual else {
        return false;
    };
    retention_mode_strength(actual.mode) >= retention_mode_strength(requested.mode)
        && actual.retain_days >= requested.retain_days
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merging_policy_requirements_never_weakens_either_active_side() {
        let policies = [
            None,
            Some(RetentionPolicy::new(RetentionMode::None, 999)),
            Some(RetentionPolicy::new(RetentionMode::Compliance, 0)),
            Some(RetentionPolicy::new(RetentionMode::Governance, 30)),
            Some(RetentionPolicy::new(RetentionMode::Compliance, 7)),
        ];
        for left in policies {
            for right in policies {
                let merged = strongest_retention_policy(left, right);
                assert_eq!(merged, strongest_retention_policy(right, left));
                for required in [active_retention(left), active_retention(right)]
                    .into_iter()
                    .flatten()
                {
                    assert!(retention_satisfies(merged.as_ref(), &required));
                }
                if active_retention(left).is_none() && active_retention(right).is_none() {
                    assert_eq!(merged, None);
                }
            }
        }
        assert_eq!(
            strongest_retention_policy(policies[3], policies[4]),
            Some(RetentionPolicy::new(RetentionMode::Compliance, 30))
        );
    }
}
