//! Shared recovery time arithmetic. Signed commit times establish ancestry only;
//! they are never independent evidence of current time or permission to expire data.

pub(super) mod policy;
pub(super) mod publication;
pub(super) mod replay;
pub(super) mod section;

pub(super) mod history;

use super::{V3FormatError, V3Result};

/// Maximum publication clock lead over the sampled wall clock. Millisecond
/// tie-breaking may borrow at most one minute; larger drift blocks publication.
pub(super) const MAX_PUBLICATION_CLOCK_LEAD_MS: i64 = 60_000;

/// Chooses once per publication, before retrying exact bytes or random identities.
pub(super) fn choose_publish_time(now_ms: i64, parent_ms: Option<i64>) -> V3Result<i64> {
    let next = match parent_ms {
        Some(parent) if parent >= 0 => parent
            .checked_add(1)
            .ok_or(V3FormatError::InvalidPublicationTime)?,
        Some(_) => return Err(V3FormatError::InvalidPublicationTime),
        None => 0,
    };
    let chosen = now_ms.max(next);
    validate_publication_time(now_ms, chosen)?;
    Ok(chosen)
}

/// Validates a signed ancestry edge, without ordering unrelated sibling commits.
pub(super) fn validate_parent_time(parent_ms: Option<i64>, child_ms: i64) -> V3Result<()> {
    if child_ms < 0 || parent_ms.is_some_and(|parent| parent < 0 || child_ms <= parent) {
        return Err(V3FormatError::InvalidPublicationTime);
    }
    Ok(())
}

/// Refuses invalid/uncertain publication clocks. An old prepared timestamp may
/// remain valid for an exact retry; a future timestamp cannot grant more lead.
pub(super) fn validate_publication_time(now_ms: i64, chosen_ms: i64) -> V3Result<()> {
    let maximum = now_ms
        .checked_add(MAX_PUBLICATION_CLOCK_LEAD_MS)
        .filter(|_| now_ms >= 0)
        .ok_or(V3FormatError::InvalidPublicationTime)?;
    if chosen_ms < 0 || chosen_ms > maximum {
        return Err(V3FormatError::InvalidPublicationTime);
    }
    Ok(())
}

/// A new history CAS must remain within declared clock uncertainty of its
/// sampled supersession time; old already-accepted results are not a new CAS.
pub(super) fn validate_history_publication_freshness(
    now_ms: i64,
    chosen_ms: i64,
    uncertainty_ms: u32,
) -> V3Result<()> {
    validate_publication_time(now_ms, chosen_ms)?;
    let minimum = now_ms
        .checked_sub(i64::from(uncertainty_ms))
        .ok_or(V3FormatError::InvalidPublicationTime)?;
    if chosen_ms < minimum {
        return Err(V3FormatError::InvalidPublicationTime);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_time_handles_equal_backward_and_future_samples_with_bounded_lead() {
        assert_eq!(choose_publish_time(1_000, None), Ok(1_000));
        assert_eq!(choose_publish_time(1_000, Some(1_000)), Ok(1_001));
        assert_eq!(choose_publish_time(999, Some(1_000)), Ok(1_001));
        assert_eq!(choose_publish_time(1_000, Some(60_999)), Ok(61_000));
        for (now, parent) in [
            (-1, None),
            (0, Some(-1)),
            (1_000, Some(61_000)),
            (0, Some(i64::MAX)),
            (i64::MAX, None),
        ] {
            assert_eq!(
                choose_publish_time(now, parent),
                Err(V3FormatError::InvalidPublicationTime)
            );
        }
    }

    #[test]
    fn history_freshness_blocks_delayed_new_acceptance_but_not_native_retry() {
        assert_eq!(
            validate_history_publication_freshness(61_000, 1_000, 60_000),
            Ok(())
        );
        assert_eq!(
            validate_history_publication_freshness(61_001, 1_000, 60_000),
            Err(V3FormatError::InvalidPublicationTime)
        );
        assert_eq!(validate_publication_time(61_001, 1_000), Ok(()));
    }

    #[test]
    fn ancestry_is_strict_but_siblings_need_no_total_order() {
        assert_eq!(validate_parent_time(Some(10), 11), Ok(()));
        assert_eq!(validate_parent_time(Some(10), 11), Ok(()));
        for child in [-1, 9, 10] {
            assert_eq!(
                validate_parent_time(Some(10), child),
                Err(V3FormatError::InvalidPublicationTime)
            );
        }
        assert_eq!(validate_parent_time(None, 0), Ok(()));
        assert_eq!(
            validate_parent_time(None, -1),
            Err(V3FormatError::InvalidPublicationTime)
        );
    }
}
