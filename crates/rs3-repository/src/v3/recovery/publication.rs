//! Captured accepted history and one immutable successor transition.

use super::history::{
    MAX_RECOVERY_PAGES, MAX_RECOVERY_TAIL_RECORDS, RecoveryDelta, RecoveryPage,
    RecoveryPageLocation, RecoveryPageRef, RecoveryPoint, RecoverySection, RecoverySnapshot,
};
use super::policy::RecoveryPolicy;
use crate::v3::repository::V3PublicationPlan;
use crate::v3::{V3FormatError, V3Result};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub(in crate::v3) struct AcceptedRecoveryState {
    pub policy: RecoveryPolicy,
    pub snapshot: Arc<RecoverySnapshot>,
}

impl AcceptedRecoveryState {
    pub fn next_expiry_cutoff_ms(&self) -> Option<i64> {
        let old = self.snapshot.expire_before_ms;
        self.snapshot
            .tail
            .iter()
            .map(|point| point.protected_until_ms)
            .chain(self.snapshot.pages.iter().map(|page| {
                if page.claims.minimum_deadline_ms > old {
                    page.claims.minimum_deadline_ms
                } else {
                    page.claims.maximum_deadline_ms
                }
            }))
            .filter(|deadline| *deadline > old)
            .min()
    }

    /// Uses only known exact tail deadlines or authenticated page extrema.
    /// Interior page expiry may be conservatively delayed until the maximum.
    pub fn expiry_checkpoint_due(
        &self,
        sampled_now_ms: i64,
        policy: RecoveryPolicy,
    ) -> V3Result<bool> {
        let cutoff = policy
            .expiry_cutoff_ms(sampled_now_ms)?
            .max(self.snapshot.expire_before_ms);
        Ok(self
            .next_expiry_cutoff_ms()
            .is_some_and(|deadline| deadline <= cutoff))
    }
}

/// Coverage binds the full exact parent anchor in `publication`, which already
/// authenticates this accepted registry. No per-write registry hash is needed.
#[derive(Clone, Debug)]
pub(in crate::v3) struct CapturedRecoveryPublication {
    pub publication: V3PublicationPlan,
    pub previous: AcceptedRecoveryState,
    pub current_policy: RecoveryPolicy,
    pub required_coverage_until_ms: i64,
    pub section: RecoverySection,
}

impl CapturedRecoveryPublication {
    pub fn new(
        publication: V3PublicationPlan,
        previous: AcceptedRecoveryState,
        current_policy: RecoveryPolicy,
        is_root: bool,
    ) -> V3Result<Self> {
        let chosen = publication.publish_time_ms;
        // Expiry uses the captured trusted clock, never a synthetic parent+1
        // timestamp that may lead that clock during a burst of publications.
        let cutoff = current_policy
            .expiry_cutoff_ms(publication.sampled_now_ms)?
            .max(previous.snapshot.expire_before_ms);
        let required_coverage_until_ms = previous
            .policy
            .coverage_until_ms(chosen)?
            .max(current_policy.coverage_until_ms(chosen)?);
        let point = RecoveryPoint {
            anchor: publication.parent.clone(),
            publish_time_ms: publication.parent_publish_time_ms,
            protected_until_ms: previous.policy.promised_until_ms(chosen)?,
            policy_id: previous.policy.identity(),
        };
        let mut section = RecoverySection {
            current_policy,
            delta: RecoveryDelta {
                register: Some(point.clone()),
                expire_before_ms: (cutoff > previous.snapshot.expire_before_ms).then_some(cutoff),
                ..RecoveryDelta::default()
            },
            snapshot: None,
            local_pages: Vec::new(),
        };
        let live_tail_len = previous
            .snapshot
            .tail
            .iter()
            .filter(|point| point.protected_until_ms > cutoff)
            .count();
        let roll = live_tail_len == MAX_RECOVERY_TAIL_RECORDS;
        if roll {
            if previous
                .snapshot
                .pages
                .iter()
                .filter(|page| page.claims.maximum_deadline_ms > cutoff)
                .count()
                >= MAX_RECOVERY_PAGES
            {
                return Err(V3FormatError::RecoveryHistoryCapacity);
            }
            section.delta.roll_tail = Some(0);
            section.local_pages.push(RecoveryPage {
                points: previous
                    .snapshot
                    .tail
                    .iter()
                    .filter(|point| point.protected_until_ms > cutoff)
                    .cloned()
                    .collect(),
            });
        }
        if is_root {
            let mut snapshot = (*previous.snapshot).clone();
            snapshot.expire_before_ms = cutoff;
            snapshot
                .tail
                .retain(|point| point.protected_until_ms > cutoff);
            snapshot
                .pages
                .retain(|page| page.claims.maximum_deadline_ms > cutoff);
            if roll {
                snapshot.pages.push(RecoveryPageRef {
                    location: RecoveryPageLocation::ThisSection { page_index: 0 },
                    claims: section.local_pages[0].claims()?,
                });
                snapshot.tail.clear();
            }
            snapshot.tail.push(point);
            section.snapshot = Some(snapshot);
        }
        section.validate_for_commit(
            Some((
                &publication.parent,
                publication.parent_publish_time_ms,
                &previous.policy,
            )),
            chosen,
            is_root,
            cutoff,
        )?;
        Ok(Self {
            publication,
            previous,
            current_policy,
            required_coverage_until_ms,
            section,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v3::recovery::history::{
        MAX_RECOVERY_PAGE_RECORDS, RecoveryPageClaims, RecoveryPageLocation,
    };
    use crate::v3::{V3AnchorState, V3CommitKey, V3FormatRef};
    use rs3_types::{BackendObjectId, BackendVersionId, KeyId, Sequence};

    fn anchor(sequence: u64) -> V3AnchorState {
        V3AnchorState {
            sequence: Sequence::new(sequence),
            commit_key: V3CommitKey::from_parts(Sequence::new(sequence), [0x41; 32])
                .expect("commit key")
                .object_id,
            body_digest: [0x42; 32],
            version_id: Some(
                BackendVersionId::new(format!("version-{sequence}")).expect("version"),
            ),
            signing_key_id: KeyId::new("signing-key").expect("key id"),
            format_ref: V3FormatRef {
                generation: 1,
                digest: hex::encode([0x43; 32]),
                object_id: BackendObjectId::new("format/exact-root").expect("format id"),
                version_id: Some(BackendVersionId::new("format-version").expect("format version")),
            },
        }
    }

    fn accepted(deadline: i64) -> AcceptedRecoveryState {
        AcceptedRecoveryState {
            policy: RecoveryPolicy::PRESET,
            snapshot: Arc::new(RecoverySnapshot {
                tail: vec![RecoveryPoint {
                    anchor: anchor(1),
                    publish_time_ms: 1_000,
                    protected_until_ms: deadline,
                    policy_id: RecoveryPolicy::PRESET.identity(),
                }],
                ..RecoverySnapshot::default()
            }),
        }
    }

    #[test]
    fn monotonic_header_lead_does_not_expire_history_early() {
        let previous = accepted(100_000);
        let plan = V3PublicationPlan {
            sampled_now_ms: 150_000,
            parent: anchor(2),
            parent_publish_time_ms: 160_000,
            publish_time_ms: 160_001,
        };
        let capture =
            CapturedRecoveryPublication::new(plan, previous.clone(), RecoveryPolicy::PRESET, true)
                .expect("bounded clock lead");
        assert_eq!(capture.section.delta.expire_before_ms, Some(90_000));
        let snapshot = capture.section.snapshot.expect("root snapshot");
        assert_eq!(snapshot.tail.len(), 2, "old promise still applies");
        assert!(
            !previous
                .expiry_checkpoint_due(159_999, RecoveryPolicy::PRESET)
                .expect("trusted time")
        );
        assert!(
            previous
                .expiry_checkpoint_due(160_000, RecoveryPolicy::PRESET)
                .expect("trusted time")
        );
    }

    #[test]
    fn expiry_is_applied_before_new_registration_and_root_snapshot() {
        let previous = accepted(100_000);
        let capture = CapturedRecoveryPublication::new(
            V3PublicationPlan {
                sampled_now_ms: 160_000,
                parent: anchor(2),
                parent_publish_time_ms: 150_000,
                publish_time_ms: 160_000,
            },
            previous.clone(),
            RecoveryPolicy::PRESET,
            true,
        )
        .expect("expiry transition");
        let replayed = capture
            .section
            .apply_delta(&previous.snapshot, &anchor(3), 1)
            .expect("same post-state during replay");
        assert_eq!(replayed.expire_before_ms, 100_000);
        assert_eq!(replayed.tail.len(), 1);
        assert_eq!(replayed.tail[0].anchor.sequence, Sequence::new(2));
        assert!(replayed.tail[0].protected_until_ms > 160_000);
    }

    /// A registry at the storage ceiling: 1,024 exact pages of 4,096 points
    /// followed by a full live tail, with consistent sequence ordering.
    fn full_registry(tail_deadline: i64, page_deadline: i64) -> AcceptedRecoveryState {
        let policy = RecoveryPolicy::PRESET;
        let paged = (MAX_RECOVERY_PAGES * MAX_RECOVERY_PAGE_RECORDS) as u64;
        let tail = (0..MAX_RECOVERY_TAIL_RECORDS as u64)
            .map(|ordinal| RecoveryPoint {
                anchor: anchor(paged + ordinal + 1),
                publish_time_ms: 1_000 + ordinal as i64,
                protected_until_ms: tail_deadline,
                policy_id: policy.identity(),
            })
            .collect();
        let pages = (0..MAX_RECOVERY_PAGES as u64)
            .map(|page_index| {
                let first = page_index * MAX_RECOVERY_PAGE_RECORDS as u64 + 1;
                let last = (page_index + 1) * MAX_RECOVERY_PAGE_RECORDS as u64;
                RecoveryPageRef {
                    location: RecoveryPageLocation::Exact {
                        anchor: anchor(last + 1),
                        section_ordinal: 0,
                        page_index: 0,
                    },
                    claims: RecoveryPageClaims {
                        record_count: MAX_RECOVERY_PAGE_RECORDS as u32,
                        first_sequence: Sequence::new(first),
                        last_sequence: Sequence::new(last),
                        minimum_deadline_ms: page_deadline,
                        maximum_deadline_ms: page_deadline,
                    },
                }
            })
            .collect();
        AcceptedRecoveryState {
            policy,
            snapshot: Arc::new(RecoverySnapshot {
                pages,
                tail,
                expire_before_ms: 0,
            }),
        }
    }

    /// The storage ceiling is 4,096 live tail points plus 1,024 live pages of
    /// 4,096 points, about 4.2 million points. At the thirty-day preset that
    /// is roughly 1.62 accepted commits per second sustained for the window.
    #[test]
    fn full_history_fails_closed_until_pages_expire_and_drops_no_live_point() {
        let page_deadline = 10_000_000;
        let tail_deadline = 20_000_000;
        let previous = full_registry(tail_deadline, page_deadline);
        let parent =
            (MAX_RECOVERY_PAGES * MAX_RECOVERY_PAGE_RECORDS + MAX_RECOVERY_TAIL_RECORDS) as u64 + 1;
        let plan = V3PublicationPlan {
            sampled_now_ms: 5_000_000,
            parent: anchor(parent),
            parent_publish_time_ms: 4_999_000,
            publish_time_ms: 5_000_000,
        };

        // Every page and every tail point is still live: the publication is
        // refused and the accepted registry is left exactly as it was.
        let refused = CapturedRecoveryPublication::new(
            plan.clone(),
            previous.clone(),
            RecoveryPolicy::PRESET,
            true,
        );
        assert!(matches!(
            refused,
            Err(V3FormatError::RecoveryHistoryCapacity)
        ));
        assert_eq!(previous.snapshot.pages.len(), MAX_RECOVERY_PAGES);
        assert_eq!(previous.snapshot.tail.len(), MAX_RECOVERY_TAIL_RECORDS);

        // One live page short of the ceiling still publishes; the roll keeps
        // every live tail point in the new page.
        let mut almost_full = previous.clone();
        Arc::make_mut(&mut almost_full.snapshot).pages.pop();
        let capture = CapturedRecoveryPublication::new(
            plan.clone(),
            almost_full,
            RecoveryPolicy::PRESET,
            true,
        )
        .expect("one free page slot");
        assert_eq!(capture.section.delta.roll_tail, Some(0));
        assert_eq!(
            capture.section.local_pages[0].points.len(),
            MAX_RECOVERY_TAIL_RECORDS
        );
        let snapshot = capture.section.snapshot.expect("root snapshot");
        assert_eq!(snapshot.pages.len(), MAX_RECOVERY_PAGES);
        assert_eq!(snapshot.tail.len(), 1);

        // Once trusted time passes the pages' deadline plus clock uncertainty,
        // the same publication succeeds: expired pages are released, the still
        // protected tail rolls into one page, and nothing live is dropped.
        let later = V3PublicationPlan {
            sampled_now_ms: page_deadline + 60_001,
            parent: anchor(parent),
            parent_publish_time_ms: page_deadline + 60_000,
            publish_time_ms: page_deadline + 60_001,
        };
        let capture =
            CapturedRecoveryPublication::new(later, previous, RecoveryPolicy::PRESET, true)
                .expect("expired pages free capacity");
        assert_eq!(
            capture.section.delta.expire_before_ms,
            Some(page_deadline + 1)
        );
        assert_eq!(capture.section.delta.roll_tail, Some(0));
        assert_eq!(
            capture.section.local_pages[0].points.len(),
            MAX_RECOVERY_TAIL_RECORDS
        );
        let snapshot = capture.section.snapshot.expect("root snapshot");
        assert_eq!(snapshot.pages.len(), 1);
        assert_eq!(snapshot.tail.len(), 1);
        assert!(snapshot.tail[0].protected_until_ms > page_deadline + 60_001);
    }

    #[test]
    fn clock_regression_never_rolls_back_an_accepted_expiry_cutoff() {
        let mut previous = accepted(200_000);
        Arc::make_mut(&mut previous.snapshot).expire_before_ms = 90_000;
        let capture = CapturedRecoveryPublication::new(
            V3PublicationPlan {
                sampled_now_ms: 149_000,
                parent: anchor(2),
                parent_publish_time_ms: 150_000,
                publish_time_ms: 150_001,
            },
            previous,
            RecoveryPolicy::PRESET,
            true,
        )
        .expect("small backwards clock step");
        assert_eq!(capture.section.delta.expire_before_ms, None);
        assert_eq!(
            capture.section.snapshot.expect("snapshot").expire_before_ms,
            90_000
        );
    }
}
