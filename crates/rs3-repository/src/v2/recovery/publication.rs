//! Captured accepted history and one immutable successor transition.

use super::history::{
    MAX_RECOVERY_PAGES, MAX_RECOVERY_TAIL_RECORDS, RecoveryDelta, RecoveryPage,
    RecoveryPageLocation, RecoveryPageRef, RecoveryPoint, RecoverySection, RecoverySnapshot,
};
use super::policy::RecoveryPolicy;
use crate::v2::repository::V2PublicationPlan;
use crate::v2::{V2FormatError, V2Result};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub(in crate::v2) struct AcceptedRecoveryState {
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
    ) -> V2Result<bool> {
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
pub(in crate::v2) struct CapturedRecoveryPublication {
    pub publication: V2PublicationPlan,
    pub previous: AcceptedRecoveryState,
    pub current_policy: RecoveryPolicy,
    pub required_coverage_until_ms: i64,
    pub section: RecoverySection,
}

impl CapturedRecoveryPublication {
    pub fn new(
        publication: V2PublicationPlan,
        previous: AcceptedRecoveryState,
        current_policy: RecoveryPolicy,
        is_root: bool,
    ) -> V2Result<Self> {
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
                return Err(V2FormatError::RecoveryHistoryCapacity);
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
    use crate::v2::{V2AnchorState, V2CommitKey, V2FormatRef};
    use rs3_types::{BackendObjectId, BackendVersionId, KeyId, Sequence};

    fn anchor(sequence: u64) -> V2AnchorState {
        V2AnchorState {
            sequence: Sequence::new(sequence),
            commit_key: V2CommitKey::from_parts(Sequence::new(sequence), [0x41; 32])
                .expect("commit key")
                .object_id,
            body_digest: [0x42; 32],
            version_id: Some(
                BackendVersionId::new(format!("version-{sequence}")).expect("version"),
            ),
            signing_key_id: KeyId::new("signing-key").expect("key id"),
            format_ref: V2FormatRef {
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
        let plan = V2PublicationPlan {
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
            V2PublicationPlan {
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

    #[test]
    fn clock_regression_never_rolls_back_an_accepted_expiry_cutoff() {
        let mut previous = accepted(200_000);
        Arc::make_mut(&mut previous.snapshot).expire_before_ms = 90_000;
        let capture = CapturedRecoveryPublication::new(
            V2PublicationPlan {
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
