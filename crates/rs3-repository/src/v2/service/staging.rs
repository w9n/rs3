//! Bounded speculative state for v2 repository mutations.

use super::PendingV2Payload;
use crate::error::{RepositoryError, Result};
use crate::state::{RepositoryState, TrustedManifest};
use rs3_index::{IndexDelta, NamespaceEntry};
use rs3_types::{BlindIndexKey, ManifestId, Sequence};
use std::collections::{BTreeMap, BTreeSet};

/// Hard service-level bound for one unpublished mutation draft.
///
/// The coordinator normally publishes much smaller batches. This limit is an
/// invariant of the repository itself, so independently configured callers
/// cannot grow speculative trusted state without bound. The repository admits
/// only one commit coordinator per service instance.
pub(super) const V2_MAX_PENDING_OPERATIONS: usize = rs3_index::run::INDEX_PACK_MAX_RECORDS as usize;

/// One rollback position inside the bounded speculative vectors.
///
/// Sequence allocation is deliberately absent. Failed writes may leave gaps,
/// but a sequence allocated in this process is never reused by rollback.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct PendingV2Checkpoint {
    deltas_len: usize,
    manifests_len: usize,
    payloads_len: usize,
}

#[derive(Clone, Copy, Debug)]
struct FrozenPrefix {
    revision: u64,
    end: PendingV2Checkpoint,
    sequence: Option<Sequence>,
}

/// Result of resolving a namespace key through the speculative overlay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PendingV2EffectiveHead<'a> {
    /// A staged or accepted live namespace entry.
    Live(&'a NamespaceEntry),
    /// A staged tombstone hides any accepted entry.
    Tombstoned,
    /// Neither the staged overlay nor accepted state contains the key.
    Absent,
}

impl<'a> PendingV2EffectiveHead<'a> {
    /// Returns the live entry, if the effective view contains one.
    pub(super) fn live(self) -> Option<&'a NamespaceEntry> {
        match self {
            Self::Live(entry) => Some(entry),
            Self::Tombstoned | Self::Absent => None,
        }
    }
}

/// Immutable bounded input used while constructing and publishing one commit.
#[derive(Clone, Debug)]
pub(super) struct PendingV2Snapshot {
    pub(super) completion_receipt: Option<rs3_index::completion::CompletionReceipt>,
    revision: u64,
    #[cfg(test)]
    allocation_sequence: Sequence,
    deltas: Vec<IndexDelta>,
    manifests: Vec<(ManifestId, TrustedManifest)>,
    payloads: Vec<PendingV2Payload>,
}

impl PendingV2Snapshot {
    #[cfg(test)]
    pub(super) fn allocation_sequence(&self) -> Sequence {
        self.allocation_sequence
    }

    pub(super) fn deltas(&self) -> &[IndexDelta] {
        &self.deltas
    }

    pub(super) fn deltas_mut(&mut self) -> &mut [IndexDelta] {
        &mut self.deltas
    }

    pub(super) fn manifests(&self) -> &[(ManifestId, TrustedManifest)] {
        &self.manifests
    }

    pub(super) fn payloads(&self) -> &[PendingV2Payload] {
        &self.payloads
    }

    /// Returns the highest generation actually represented by this draft.
    ///
    /// This intentionally does not return the allocation cursor. Failed
    /// speculative operations may consume sequence values without contributing
    /// a mutation to the eventual commit.
    pub(super) fn commit_sequence(&self) -> Option<Sequence> {
        maximum_delta_generation(&self.deltas)
    }

    pub(super) fn manifest<'a>(
        &'a self,
        accepted: &'a RepositoryState,
        manifest_id: &ManifestId,
    ) -> Option<&'a TrustedManifest> {
        self.manifests
            .iter()
            .rev()
            .find_map(|(candidate_id, manifest)| (candidate_id == manifest_id).then_some(manifest))
            .or_else(|| accepted.manifests.get(manifest_id))
    }

    fn coalesce(&mut self) {
        let mut last_by_blind_key = BTreeMap::new();
        for (index, delta) in self.deltas.iter().enumerate() {
            let blind_key = match delta {
                IndexDelta::Upsert { entry, .. } => &entry.blind_key,
                IndexDelta::Tombstone { blind_key, .. } => blind_key,
            };
            last_by_blind_key.insert(blind_key.clone(), index);
        }
        let mut index = 0_usize;
        self.deltas.retain(|delta| {
            let blind_key = match delta {
                IndexDelta::Upsert { entry, .. } => &entry.blind_key,
                IndexDelta::Tombstone { blind_key, .. } => blind_key,
            };
            let retain = last_by_blind_key.get(blind_key) == Some(&index);
            index = index.saturating_add(1);
            retain
        });

        let live_manifests = self
            .deltas
            .iter()
            .filter_map(|delta| match delta {
                IndexDelta::Upsert { entry, .. } => Some(entry.manifest_id.clone()),
                IndexDelta::Tombstone { .. } => None,
            })
            .collect::<BTreeSet<_>>();
        self.manifests
            .retain(|(manifest_id, _)| live_manifests.contains(manifest_id));
        self.payloads
            .retain(|payload| live_manifests.contains(&payload.manifest_id));
    }
}

/// Bounded append-only state for mutations not yet covered by an accepted anchor.
#[derive(Debug)]
pub(super) struct PendingV2State {
    revision: u64,
    base: PendingV2Checkpoint,
    end: PendingV2Checkpoint,
    frozen: Option<FrozenPrefix>,
    allocation_sequence: Sequence,
    deltas: Vec<IndexDelta>,
    manifests: Vec<(ManifestId, TrustedManifest)>,
    payloads: Vec<PendingV2Payload>,
}

impl PendingV2State {
    pub(super) fn new(accepted_sequence: Sequence) -> Self {
        Self {
            revision: 0,
            base: PendingV2Checkpoint::default(),
            end: PendingV2Checkpoint::default(),
            frozen: None,
            allocation_sequence: accepted_sequence,
            deltas: Vec::new(),
            manifests: Vec::new(),
            payloads: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(super) fn allocation_sequence(&self) -> Sequence {
        self.allocation_sequence
    }

    pub(super) fn allocate_sequence(&mut self) -> Result<Sequence> {
        let next = self
            .allocation_sequence
            .checked_next()
            .ok_or(RepositoryError::SequenceOverflow)?;
        self.allocation_sequence = next;
        Ok(next)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.deltas.is_empty() && self.manifests.is_empty() && self.payloads.is_empty()
    }

    pub(super) fn deltas(&self) -> &[IndexDelta] {
        &self.deltas
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.deltas.len()
    }

    pub(super) fn checkpoint(&self) -> PendingV2Checkpoint {
        self.end
    }

    /// Freezes the current prefix while allowing bounded successor appends.
    pub(super) fn freeze(&mut self) -> Result<PendingV2Snapshot> {
        if self.frozen.is_some() || self.is_empty() {
            return Err(RepositoryError::StatePoisoned);
        }
        let snapshot = self.snapshot();
        self.frozen = Some(FrozenPrefix {
            revision: snapshot.revision,
            end: self.end,
            sequence: snapshot.commit_sequence(),
        });
        Ok(snapshot)
    }

    /// Appends one logical staged operation atomically.
    ///
    /// One operation can contain several namespace deltas during key rotation.
    /// Every retained vector has the same hard ceiling, including malformed
    /// caller combinations that contain metadata or payloads without deltas.
    pub(super) fn append_operation(
        &mut self,
        deltas: Vec<IndexDelta>,
        manifest: Option<(ManifestId, TrustedManifest)>,
        payload: Option<PendingV2Payload>,
    ) -> Result<PendingV2Checkpoint> {
        let checkpoint = self.checkpoint();
        ensure_bounded_append(self.deltas.len(), deltas.len())?;
        ensure_bounded_append(self.manifests.len(), usize::from(manifest.is_some()))?;
        ensure_bounded_append(self.payloads.len(), usize::from(payload.is_some()))?;
        let next_revision = self
            .revision
            .checked_add(1)
            .ok_or(RepositoryError::StatePoisoned)?;

        let end = PendingV2Checkpoint {
            deltas_len: self
                .end
                .deltas_len
                .checked_add(deltas.len())
                .ok_or(RepositoryError::StatePoisoned)?,
            manifests_len: self
                .end
                .manifests_len
                .checked_add(usize::from(manifest.is_some()))
                .ok_or(RepositoryError::StatePoisoned)?,
            payloads_len: self
                .end
                .payloads_len
                .checked_add(usize::from(payload.is_some()))
                .ok_or(RepositoryError::StatePoisoned)?,
        };
        self.deltas.extend(deltas);
        self.manifests.extend(manifest);
        self.payloads.extend(payload);
        self.revision = next_revision;
        self.end = end;
        Ok(checkpoint)
    }

    /// Restores a prior vector position without rolling sequence allocation back.
    pub(super) fn rollback(&mut self, checkpoint: PendingV2Checkpoint) -> Result<()> {
        let relative = self.relative_position(checkpoint)?;
        let next_revision = self
            .revision
            .checked_add(1)
            .ok_or(RepositoryError::StatePoisoned)?;
        self.deltas.truncate(relative.deltas_len);
        self.manifests.truncate(relative.manifests_len);
        self.payloads.truncate(relative.payloads_len);
        self.revision = next_revision;
        self.end = checkpoint;
        self.frozen = None;
        Ok(())
    }

    pub(super) fn validate_snapshot(&self, snapshot: &PendingV2Snapshot) -> Result<()> {
        let (revision, sequence) = match self.frozen {
            Some(frozen) => {
                self.relative_position(frozen.end)?;
                (frozen.revision, frozen.sequence)
            }
            None => (self.revision, maximum_delta_generation(&self.deltas)),
        };
        if revision != snapshot.revision || sequence != snapshot.commit_sequence() {
            return Err(RepositoryError::StatePoisoned);
        }
        Ok(())
    }

    fn relative_position(&self, position: PendingV2Checkpoint) -> Result<PendingV2Checkpoint> {
        fn relative(value: usize, base: usize, end: usize) -> Result<usize> {
            value
                .checked_sub(base)
                .filter(|_| value <= end)
                .ok_or(RepositoryError::StatePoisoned)
        }
        Ok(PendingV2Checkpoint {
            deltas_len: relative(
                position.deltas_len,
                self.base.deltas_len,
                self.end.deltas_len,
            )?,
            manifests_len: relative(
                position.manifests_len,
                self.base.manifests_len,
                self.end.manifests_len,
            )?,
            payloads_len: relative(
                position.payloads_len,
                self.base.payloads_len,
                self.end.payloads_len,
            )?,
        })
    }

    /// Consumes only the validated prefix; successor checkpoints stay absolute.
    pub(super) fn finish_publication(&mut self) -> Result<()> {
        if let Some(frozen) = self.frozen {
            let prefix = self.relative_position(frozen.end)?;
            self.deltas.drain(..prefix.deltas_len);
            self.manifests.drain(..prefix.manifests_len);
            self.payloads.drain(..prefix.payloads_len);
            self.base = frozen.end;
            self.frozen = None;
        } else {
            self.clear_after_validated_publication();
        }
        Ok(())
    }

    /// Clears a draft already validated under the exclusive publication barrier.
    pub(super) fn clear_after_validated_publication(&mut self) {
        self.deltas.clear();
        self.manifests.clear();
        self.payloads.clear();
        self.base = self.end;
        self.frozen = None;
    }

    /// Synchronizes an already-empty overlay after recovery or initialization.
    pub(super) fn reset_to_accepted_sequence(&mut self, accepted_sequence: Sequence) -> Result<()> {
        if !self.is_empty() {
            return Err(RepositoryError::CommitFailed {
                reason: "cannot reset a non-empty v2 staging overlay".to_owned(),
            });
        }
        self.allocation_sequence = accepted_sequence;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn manifests(&self) -> &[(ManifestId, TrustedManifest)] {
        &self.manifests
    }

    pub(super) fn snapshot(&self) -> PendingV2Snapshot {
        let mut snapshot = PendingV2Snapshot {
            completion_receipt: None,
            revision: self.revision,
            #[cfg(test)]
            allocation_sequence: self.allocation_sequence,
            deltas: self.deltas.clone(),
            manifests: self.manifests.clone(),
            payloads: self.payloads.clone(),
        };
        snapshot.coalesce();
        snapshot
    }

    /// Resolves the newest speculative mutation before consulting accepted state.
    pub(super) fn effective_head<'a>(
        &'a self,
        accepted: &'a RepositoryState,
        blind_key: &BlindIndexKey,
    ) -> PendingV2EffectiveHead<'a> {
        for delta in self.deltas.iter().rev() {
            match delta {
                IndexDelta::Upsert { entry, .. } if entry.blind_key == *blind_key => {
                    return PendingV2EffectiveHead::Live(entry);
                }
                IndexDelta::Tombstone {
                    blind_key: candidate,
                    ..
                } if candidate == blind_key => return PendingV2EffectiveHead::Tombstoned,
                IndexDelta::Upsert { .. } | IndexDelta::Tombstone { .. } => {}
            }
        }

        accepted
            .namespace
            .head(blind_key)
            .map_or(PendingV2EffectiveHead::Absent, PendingV2EffectiveHead::Live)
    }

    #[cfg(test)]
    pub(super) fn manifest<'a>(
        &'a self,
        accepted: &'a RepositoryState,
        manifest_id: &ManifestId,
    ) -> Option<&'a TrustedManifest> {
        self.manifests
            .iter()
            .rev()
            .find_map(|(candidate_id, manifest)| (candidate_id == manifest_id).then_some(manifest))
            .or_else(|| accepted.manifests.get(manifest_id))
    }
}

fn ensure_bounded_append(current: usize, additional: usize) -> Result<()> {
    if current
        .checked_add(additional)
        .is_none_or(|next| next > V2_MAX_PENDING_OPERATIONS)
    {
        return Err(RepositoryError::CommitBackpressure);
    }
    Ok(())
}

fn maximum_delta_generation(deltas: &[IndexDelta]) -> Option<Sequence> {
    deltas
        .iter()
        .map(|delta| match delta {
            IndexDelta::Upsert { entry, .. } => entry.generation,
            IndexDelta::Tombstone { generation, .. } => *generation,
        })
        .max()
}

#[cfg(test)]
mod tests {
    use super::{
        PendingV2EffectiveHead, PendingV2State, V2_MAX_PENDING_OPERATIONS, maximum_delta_generation,
    };
    use crate::error::RepositoryError;
    use crate::state::{RepositoryState, TrustedManifest};
    use crate::v2::service::PendingV2Payload;
    use bytes::Bytes;
    use rs3_index::{IndexDelta, NamespaceEntry, PayloadReference};
    use rs3_types::{BackendObjectId, BlindIndexKey, KeyId, LogicalPath, ManifestId, Sequence};

    #[test]
    fn overlay_lookup_prefers_newest_mutation_and_preserves_tombstone_state() {
        let blind_key = blind_key("accepted");
        let accepted_entry = entry(blind_key.clone(), "accepted", Sequence::new(1));
        let staged_entry = entry(blind_key.clone(), "staged", Sequence::new(2));
        let mut accepted = RepositoryState::default();
        accepted
            .namespace
            .upsert(accepted_entry.clone(), Vec::new());
        let mut pending = PendingV2State::new(Sequence::new(1));

        assert_eq!(
            pending.effective_head(&accepted, &blind_key),
            PendingV2EffectiveHead::Live(&accepted_entry)
        );
        pending
            .append_operation(vec![upsert(staged_entry.clone())], None, None)
            .expect("append staged upsert");
        assert_eq!(
            pending.effective_head(&accepted, &blind_key),
            PendingV2EffectiveHead::Live(&staged_entry)
        );
        pending
            .append_operation(
                vec![IndexDelta::Tombstone {
                    namespace_key_id: key_id(),
                    blind_key: blind_key.clone(),
                    path: path("objects/key"),
                    generation: Sequence::new(3),
                }],
                None,
                None,
            )
            .expect("append staged tombstone");
        assert_eq!(
            pending.effective_head(&accepted, &blind_key),
            PendingV2EffectiveHead::Tombstoned
        );
        assert!(
            pending
                .effective_head(&accepted, &blind_key)
                .live()
                .is_none()
        );
    }

    #[test]
    fn frozen_coalesced_prefix_preserves_successor_and_absolute_rollback() {
        let mut pending = PendingV2State::new(Sequence::ZERO);
        let append = |pending: &mut PendingV2State, label: &str| {
            let sequence = pending.allocate_sequence().expect("allocate");
            let id = manifest_id(label);
            pending
                .append_operation(
                    vec![upsert(entry(blind_key("shared"), label, sequence))],
                    Some((id.clone(), manifest("objects/shared"))),
                    Some(PendingV2Payload {
                        manifest_id: id,
                        body: Bytes::from(label.to_owned()),
                    }),
                )
                .expect("append")
        };
        let retired = append(&mut pending, "superseded");
        append(&mut pending, "published");
        let frozen = pending.freeze().expect("freeze prefix");
        assert_eq!(
            frozen.deltas().len(),
            1,
            "frozen snapshot coalesces the two raw entries"
        );
        assert_eq!(frozen.payloads().len(), 1);
        let successor_checkpoint = append(&mut pending, "successor");
        pending
            .validate_snapshot(&frozen)
            .expect("append preserves frozen snapshot");
        assert!(pending.freeze().is_err(), "one publisher only");
        pending
            .finish_publication()
            .expect("consume frozen raw prefix");
        assert_eq!(pending.deltas().len(), 1);
        assert_eq!(pending.payloads.len(), 1);
        assert_eq!(pending.payloads[0].body, Bytes::from_static(b"successor"));
        assert!(
            pending.rollback(retired).is_err(),
            "cannot roll back an accepted prefix"
        );
        pending
            .rollback(successor_checkpoint)
            .expect("checkpoint survives prefix removal");
        assert!(pending.is_empty());
        assert_eq!(
            pending.allocate_sequence().expect("burned generations"),
            Sequence::new(4)
        );
        assert!(pending.validate_snapshot(&frozen).is_err());
    }

    #[test]
    fn frozen_prefix_and_successor_share_the_service_limit() {
        let mut pending = PendingV2State::new(Sequence::ZERO);
        let half = V2_MAX_PENDING_OPERATIONS / 2;
        let append = |pending: &mut PendingV2State, start: usize| {
            let deltas = (start..start + half)
                .map(|n| {
                    upsert(entry(
                        blind_key(&format!("key-{n}")),
                        "value",
                        Sequence::new(n as u64 + 1),
                    ))
                })
                .collect();
            pending
                .append_operation(deltas, None, None)
                .expect("bounded append")
        };
        let rollback = append(&mut pending, 0);
        let frozen = pending.freeze().expect("freeze");
        append(&mut pending, half);
        assert!(matches!(
            pending.append_operation(
                vec![upsert(entry(
                    blind_key("overflow"),
                    "extra",
                    Sequence::new(10_000)
                ))],
                None,
                None
            ),
            Err(RepositoryError::CommitBackpressure)
        ));
        pending
            .validate_snapshot(&frozen)
            .expect("failed append is atomic");
        pending
            .rollback(rollback)
            .expect("reject failed prefix and dependent suffix");
        assert!(pending.is_empty());
        assert!(pending.validate_snapshot(&frozen).is_err());
    }

    #[test]
    fn rollback_truncates_every_vector_without_reusing_sequence() {
        let mut pending = PendingV2State::new(Sequence::new(7));
        let allocated = pending.allocate_sequence().expect("allocate sequence");
        let manifest_id = manifest_id("manifest-staged");
        let checkpoint = pending
            .append_operation(
                vec![upsert(entry(blind_key("staged"), "staged", allocated))],
                Some((manifest_id.clone(), manifest("objects/staged"))),
                Some(PendingV2Payload {
                    manifest_id,
                    body: Bytes::from_static(b"payload"),
                }),
            )
            .expect("append operation");

        pending.rollback(checkpoint).expect("rollback operation");

        assert!(pending.is_empty());
        assert_eq!(pending.allocation_sequence(), allocated);
        assert_eq!(
            pending
                .allocate_sequence()
                .expect("allocate after rollback"),
            Sequence::new(9)
        );
    }

    #[test]
    fn append_rejects_the_hard_limit_atomically() {
        assert_eq!(V2_MAX_PENDING_OPERATIONS, 4_096);
        let mut pending = PendingV2State::new(Sequence::ZERO);
        let deltas = (0..V2_MAX_PENDING_OPERATIONS)
            .map(|index| {
                upsert(entry(
                    blind_key(&format!("blind-{index}")),
                    &format!("manifest-{index}"),
                    Sequence::new(u64::try_from(index).expect("index fits") + 1),
                ))
            })
            .collect();
        pending
            .append_operation(deltas, None, None)
            .expect("fill pending limit");
        let before = pending.snapshot();

        let result = pending.append_operation(
            vec![upsert(entry(
                blind_key("overflow"),
                "overflow",
                Sequence::new(2_000),
            ))],
            Some((
                manifest_id("overflow-manifest"),
                manifest("objects/overflow"),
            )),
            None,
        );

        assert!(matches!(
            result,
            Err(crate::RepositoryError::CommitBackpressure)
        ));
        assert_eq!(pending.len(), V2_MAX_PENDING_OPERATIONS);
        assert_eq!(pending.manifests().len(), before.manifests().len());
    }

    #[test]
    fn snapshot_uses_highest_included_generation_not_allocation_cursor() {
        let mut pending = PendingV2State::new(Sequence::new(10));
        pending.allocate_sequence().expect("consume sequence gap");
        pending
            .append_operation(
                vec![upsert(entry(
                    blind_key("included"),
                    "included",
                    Sequence::new(10),
                ))],
                None,
                None,
            )
            .expect("append included mutation");
        let snapshot = pending.snapshot();

        assert_eq!(snapshot.allocation_sequence(), Sequence::new(11));
        assert_eq!(snapshot.commit_sequence(), Some(Sequence::new(10)));
        assert_eq!(
            maximum_delta_generation(snapshot.deltas()),
            Some(Sequence::new(10))
        );
    }

    #[test]
    fn snapshot_coalesces_overwrites_and_unreachable_payloads() {
        let mut pending = PendingV2State::new(Sequence::ZERO);
        let blind_key = blind_key("shared-key");
        for (name, generation) in [("old", 1), ("new", 2)] {
            let manifest_id = manifest_id(name);
            pending
                .append_operation(
                    vec![upsert(entry(
                        blind_key.clone(),
                        name,
                        Sequence::new(generation),
                    ))],
                    Some((manifest_id.clone(), manifest(&format!("objects/{name}")))),
                    Some(PendingV2Payload {
                        manifest_id,
                        body: Bytes::from(name.to_owned()),
                    }),
                )
                .expect("append overwrite");
        }

        let snapshot = pending.snapshot();

        assert_eq!(snapshot.deltas().len(), 1);
        assert_eq!(snapshot.manifests().len(), 1);
        assert_eq!(snapshot.payloads().len(), 1);
        assert_eq!(snapshot.payloads()[0].body, Bytes::from_static(b"new"));
        assert_eq!(snapshot.commit_sequence(), Some(Sequence::new(2)));
        assert_eq!(pending.len(), 2);
    }

    #[test]
    fn manifest_lookup_prefers_latest_staged_value_then_accepted() {
        let shared_id = manifest_id("shared");
        let accepted_only_id = manifest_id("accepted-only");
        let mut accepted = RepositoryState::default();
        accepted
            .manifests
            .insert(shared_id.clone(), manifest("objects/old"));
        accepted
            .manifests
            .insert(accepted_only_id.clone(), manifest("objects/accepted-only"));
        let mut pending = PendingV2State::new(Sequence::ZERO);
        pending
            .append_operation(
                vec![upsert(entry(
                    blind_key("shared"),
                    "shared",
                    Sequence::new(1),
                ))],
                Some((shared_id.clone(), manifest("objects/new"))),
                None,
            )
            .expect("append staged manifest");

        assert_eq!(
            pending
                .manifest(&accepted, &shared_id)
                .expect("staged manifest")
                .key,
            path("objects/new")
        );
        assert_eq!(
            pending
                .manifest(&accepted, &accepted_only_id)
                .expect("accepted manifest")
                .key,
            path("objects/accepted-only")
        );
        assert_eq!(
            pending
                .snapshot()
                .manifest(&accepted, &shared_id)
                .expect("snapshot manifest")
                .key,
            path("objects/new")
        );
    }

    #[test]
    fn reset_requires_empty_overlay() {
        let mut pending = PendingV2State::new(Sequence::new(3));
        let checkpoint = pending
            .append_operation(
                vec![upsert(entry(
                    blind_key("pending"),
                    "pending",
                    Sequence::new(4),
                ))],
                None,
                None,
            )
            .expect("append pending mutation");

        assert!(
            pending
                .reset_to_accepted_sequence(Sequence::new(9))
                .is_err()
        );
        pending.rollback(checkpoint).expect("clear staged mutation");
        pending
            .reset_to_accepted_sequence(Sequence::new(9))
            .expect("reset empty overlay");
        assert!(pending.is_empty());
        assert_eq!(pending.allocation_sequence(), Sequence::new(9));
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 128,
            ..proptest::test_runner::Config::default()
        })]

        #[test]
        fn random_staging_rollback_preserves_burned_generations(
            history in proptest::collection::vec((0_u8..6, 0_u8..8), 1..96)
        ) {
            use proptest::prelude::*;
            use std::collections::BTreeMap;

            let mut accepted = RepositoryState::default();
            let mut accepted_model = BTreeMap::new();
            for key in 0_u8..8 {
                accepted.namespace.upsert(entry(blind_key(&key.to_string()), "base", Sequence::new(7)), Vec::new());
                accepted_model.insert(key, (7_u64, true));
            }
            let mut pending = PendingV2State::new(Sequence::new(7));
            let mut allocated = 7_u64;
            let mut mutations = Vec::<(u8, u64, bool)>::new();
            let mut checkpoints = Vec::new();
            for (operation, key) in history {
                let previous = pending.snapshot();
                let mut invalidates_snapshot = false;
                match operation {
                    0 | 1 => {
                        allocated += 1;
                        let generation = pending.allocate_sequence().expect("allocate mutation");
                        prop_assert_eq!(generation.get(), allocated);
                        let live = operation == 0;
                        let name = format!("manifest-{allocated}");
                        let delta = if live {
                            upsert(entry(blind_key(&key.to_string()), &name, generation))
                        } else {
                            IndexDelta::Tombstone {
                                namespace_key_id: key_id(),
                                blind_key: blind_key(&key.to_string()),
                                path: path(&format!("objects/{key}")),
                                generation,
                            }
                        };
                        let id = manifest_id(&name);
                        let checkpoint = pending.append_operation(
                            vec![delta],
                            live.then(|| (id.clone(), manifest(&format!("objects/{key}")))),
                            live.then(|| PendingV2Payload { manifest_id: id, body: Bytes::from(vec![key]) }),
                        ).expect("append mutation");
                        checkpoints.push((checkpoint, mutations.len()));
                        mutations.push((key, allocated, live));
                        invalidates_snapshot = true;
                    }
                    2 => {
                        // An operation can fail after reserving its generation
                        // and before it appends any speculative vectors.
                        allocated += 1;
                        prop_assert_eq!(pending.allocate_sequence().expect("burn failed allocation").get(), allocated);
                    }
                    3 if !checkpoints.is_empty() => {
                        let index = usize::from(key) % checkpoints.len();
                        let (checkpoint, length) = checkpoints[index];
                        pending.rollback(checkpoint).expect("rollback a speculative suffix");
                        mutations.truncate(length);
                        checkpoints.truncate(index);
                        invalidates_snapshot = true;
                    }
                    4 => {
                        // Model ordinary accepted publication, which clears the
                        // overlay without rewinding its allocation cursor.
                        let snapshot = pending.snapshot();
                        pending.validate_snapshot(&snapshot).expect("current publication snapshot");
                        for (key, generation, live) in &mutations {
                            accepted_model.insert(*key, (*generation, *live));
                            if *live {
                                accepted.namespace.upsert(entry(blind_key(&key.to_string()), "published", Sequence::new(*generation)), Vec::new());
                            } else {
                                accepted.namespace.remove(&blind_key(&key.to_string()));
                            }
                        }
                        invalidates_snapshot = !mutations.is_empty();
                        pending.clear_after_validated_publication();
                        mutations.clear();
                        checkpoints.clear();
                    }
                    _ => {}
                }
                prop_assert_eq!(pending.validate_snapshot(&previous).is_err(), invalidates_snapshot);
                prop_assert_eq!(pending.allocation_sequence().get(), allocated);
                prop_assert_eq!(pending.deltas().len(), mutations.len());
                let mut winners = BTreeMap::new();
                for (key, generation, live) in &mutations {
                    winners.insert(*key, (*generation, *live));
                }
                let snapshot = pending.snapshot();
                prop_assert_eq!(snapshot.deltas().len(), winners.len());
                prop_assert_eq!(snapshot.commit_sequence().map(Sequence::get),
                    mutations.iter().map(|(_, generation, _)| *generation).max());
                let live_count = winners.values().filter(|(_, live)| *live).count();
                prop_assert_eq!(snapshot.manifests().len(), live_count);
                prop_assert_eq!(snapshot.payloads().len(), live_count);
                let expected_ids = winners.values().filter(|(_, live)| *live)
                    .map(|(generation, _)| manifest_id(&format!("manifest-{generation}")))
                    .collect::<std::collections::BTreeSet<_>>();
                prop_assert_eq!(snapshot.manifests().iter().map(|(id, _)| id.clone()).collect::<std::collections::BTreeSet<_>>(), expected_ids.clone());
                prop_assert_eq!(snapshot.payloads().iter().map(|payload| payload.manifest_id.clone()).collect::<std::collections::BTreeSet<_>>(), expected_ids);
                for key in 0_u8..8 {
                    let (_, live) = winners.get(&key).or_else(|| accepted_model.get(&key)).expect("model key");
                    let head = pending.effective_head(&accepted, &blind_key(&key.to_string()));
                    prop_assert_eq!(head.live().is_some(), *live);
                    if let Some(entry) = head.live() {
                        prop_assert_eq!(entry.generation.get(), winners.get(&key).or_else(|| accepted_model.get(&key)).expect("model generation").0);
                    }
                    if winners.get(&key).is_some_and(|(_, live)| !live) {
                        prop_assert_eq!(head, PendingV2EffectiveHead::Tombstoned);
                    }
                }
            }
        }
    }

    fn upsert(entry: NamespaceEntry) -> IndexDelta {
        IndexDelta::Upsert {
            entry: Box::new(entry),
            prefix_tokens: Vec::new(),
            sealed_manifest: Box::new(rs3_index::ManifestObject {
                key_id: key_id(),
                nonce: vec![0; 12],
                ciphertext: vec![1],
                tag: vec![2; 16],
            }),
        }
    }

    fn entry(blind_key: BlindIndexKey, manifest: &str, generation: Sequence) -> NamespaceEntry {
        NamespaceEntry {
            namespace_key_id: key_id(),
            blind_key,
            object_id: object_id("pending"),
            object_version_id: None,
            payload_ref: Some(PayloadReference::Pending),
            manifest_id: manifest_id(manifest),
            content_len: 1,
            modified_at_ms: i64::try_from(generation.get()).expect("generation fits"),
            generation,
            retention: None,
            legal_hold: None,
        }
    }

    fn manifest(key: &str) -> TrustedManifest {
        TrustedManifest {
            checksum: None,
            key: path(key),
            content_len: 1,
            modified_at_ms: 1,
            retention: None,
            legal_hold: None,
        }
    }

    fn blind_key(value: &str) -> BlindIndexKey {
        BlindIndexKey::new(value).unwrap_or_else(|error| panic!("{error}"))
    }

    fn manifest_id(value: &str) -> ManifestId {
        ManifestId::new(value).unwrap_or_else(|error| panic!("{error}"))
    }

    fn object_id(value: &str) -> BackendObjectId {
        BackendObjectId::new(value.to_owned()).unwrap_or_else(|error| panic!("{error}"))
    }

    fn path(value: &str) -> LogicalPath {
        LogicalPath::new(value).unwrap_or_else(|error| panic!("{error}"))
    }

    fn key_id() -> KeyId {
        KeyId::new("namespace").unwrap_or_else(|error| panic!("{error}"))
    }
}
