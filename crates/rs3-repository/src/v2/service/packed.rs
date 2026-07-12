//! Compact payload-pack and framed index-run publication for bounded v02 batches.

use super::{
    PendingV2PayloadLocation, PendingV2Snapshot, V2Repository, commit_protection_for_deltas,
    payload_header_from_reference, v2_repository_error,
};
use crate::error::{RepositoryError, Result};
use crate::payload::total_segmented_payload_len;
use crate::state::{RepositoryState, TrustedManifest, object_material};
use rs3_index::run::{
    IndexBlindKey, IndexMutation, IndexPackRecordPointer, IndexPayloadPointer, IndexRun,
    IndexRunContainer, IndexRunKeyringRef, IndexRunLimits, IndexRunSelfPack, IndexRunSelfStream,
    IndexRunStreamContainer, IndexTombstone, IndexUpsert,
};
use rs3_index::{
    IndexDelta, NamespaceEntry, PayloadReference, V2PackCarrierReference, V2PackRecordReference,
    V2StreamCarrierReference,
};
use rs3_storage::BlobStore;
use rs3_types::{BackendVersionId, LogicalPath, ManifestId, Sequence};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::v2::{
    V2_SECTION_FLAG_MUST_UNDERSTAND, V2CommitKey, V2CommitSection, V2FormatError,
    V2KeyringEnvelopeRef, V2ParsedCommitHeader, V2PayloadPackLayout, V2PayloadPackRecord,
    V2PayloadPackRecordInput, V2SectionType, V2StoredCommit, digest_v2_section, open_v2_index_run,
    open_v2_index_run_directory, probe_v2_index_run_header, seal_v2_index_run,
    seal_v2_payload_pack,
};

pub(super) struct PendingV2PackRecordLocation {
    pub(super) manifest_id: ManifestId,
    pub(super) pack_section_ordinal: Option<u32>,
    pub(super) pack: Option<IndexRunSelfPack>,
    pub(super) record: Option<IndexPackRecordPointer>,
    pub(super) offset: u64,
    pub(super) length: u64,
}

pub(super) struct PendingV2PackedCommitSections {
    pub(super) sections: Vec<V2CommitSection>,
    pub(super) locations: Vec<PendingV2PackRecordLocation>,
    pub(super) run: PendingV2IndexRunFacts,
    pub(super) retention: Option<rs3_types::RetentionPolicy>,
    pub(super) legal_hold: Option<rs3_types::LegalHoldStatus>,
}

pub(super) struct PendingV2StreamingIndexRun {
    pub(super) bytes: bytes::Bytes,
    pub(super) run: PendingV2IndexRunFacts,
}

pub(super) struct PendingV2IndexRunFacts {
    pub(super) run_id: [u8; 32],
    pub(super) run_sequence: Sequence,
    pub(super) minimum_generation: Sequence,
    pub(super) maximum_generation: Sequence,
    pub(super) mutation_count: u32,
    pub(super) frame_count: u32,
    pub(super) namespace_bounds: (IndexBlindKey, IndexBlindKey),
    pub(super) listing_bounds: (LogicalPath, LogicalPath),
    pub(super) keyring_envelope_ref: V2KeyringEnvelopeRef,
    pub(super) section_ordinal: u32,
    pub(super) section_offset: u64,
    pub(super) section_len: u64,
    pub(super) section_digest: [u8; 32],
}

pub(in crate::v2) struct IndexRunBounds {
    pub(in crate::v2) minimum_generation: Sequence,
    pub(in crate::v2) maximum_generation: Sequence,
    pub(in crate::v2) namespace: (IndexBlindKey, IndexBlindKey),
    pub(in crate::v2) listing: (LogicalPath, LogicalPath),
}

impl<S> V2Repository<S>
where
    S: BlobStore + Clone,
{
    pub(super) fn pending_streaming_index_run_for_commit(
        &self,
        commit_key: &V2CommitKey,
        location: &PendingV2PayloadLocation,
        pending: &PendingV2Snapshot,
    ) -> Result<PendingV2StreamingIndexRun> {
        let keyring = self.repository.keyring()?;
        let accepted = self
            .accepted
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        let mut mutations = Vec::with_capacity(pending.deltas().len());
        for (ordinal, delta) in pending.deltas().iter().enumerate() {
            let mutation_ordinal = u32::try_from(ordinal)
                .map_err(|_| v2_repository_error(V2FormatError::IndexRunLimitExceeded))?;
            match delta {
                IndexDelta::Upsert { entry, .. } => {
                    if entry.manifest_id != location.manifest_id
                        || entry.content_len != location.payload_header.plaintext_len
                    {
                        return Err(v2_repository_error(V2FormatError::InvalidHeaderField));
                    }
                    let manifest = pending
                        .manifest(&accepted.repository, &entry.manifest_id)
                        .ok_or_else(|| v2_repository_error(V2FormatError::InvalidHeaderField))?;
                    mutations.push(IndexMutation::Upsert(IndexUpsert {
                        mutation_ordinal,
                        blind_key: IndexBlindKey::try_from(&entry.blind_key)
                            .map_err(|_| v2_repository_error(V2FormatError::InvalidHeaderField))?,
                        namespace_key_id: entry.namespace_key_id.clone(),
                        path: manifest.key.clone(),
                        generation: entry.generation,
                        payload: IndexPayloadPointer::SelfStream,
                        content_len: entry.content_len,
                        modified_at_ms: entry.modified_at_ms,
                        retention: entry.retention,
                        legal_hold: entry.legal_hold,
                    }));
                }
                IndexDelta::Tombstone {
                    namespace_key_id,
                    blind_key,
                    path,
                    generation,
                } => mutations.push(IndexMutation::Tombstone(IndexTombstone {
                    mutation_ordinal,
                    blind_key: IndexBlindKey::try_from(blind_key)
                        .map_err(|_| v2_repository_error(V2FormatError::InvalidHeaderField))?,
                    namespace_key_id: namespace_key_id.clone(),
                    path: path.clone(),
                    generation: *generation,
                })),
            }
        }
        drop(accepted);

        let run_sequence = pending
            .commit_sequence()
            .ok_or_else(|| v2_repository_error(V2FormatError::InvalidHeaderField))?;
        let bounds = index_run_bounds(&mutations)?;
        let mutation_count = u32::try_from(mutations.len())
            .map_err(|_| v2_repository_error(V2FormatError::IndexRunLimitExceeded))?;
        let run = IndexRun {
            sequence: run_sequence,
            self_pack: None,
            self_stream: Some(IndexRunSelfStream {
                payload_section_ordinal: location.section_ordinal,
                payload_id: location.payload_id.clone(),
                payload_header: location.payload_header.clone(),
            }),
            containers: Vec::new(),
            stream_containers: Vec::new(),
            standalone_stream_containers: Vec::new(),
            mutations,
        };
        let context = commit_repository_context(self, commit_key)?;
        let sealed = seal_v2_index_run(
            &keyring,
            &context,
            &commit_key.object_id,
            1,
            &run,
            &IndexRunLimits::default(),
        )
        .map_err(v2_repository_error)?;
        let probe = probe_v2_index_run_header(sealed.bytes()).map_err(v2_repository_error)?;
        let section_len = u64::try_from(sealed.bytes().len())
            .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?;
        let run = PendingV2IndexRunFacts {
            run_id: *sealed.run_id().as_bytes(),
            run_sequence,
            minimum_generation: bounds.minimum_generation,
            maximum_generation: bounds.maximum_generation,
            mutation_count,
            frame_count: probe.frame_count(),
            namespace_bounds: bounds.namespace,
            listing_bounds: bounds.listing,
            keyring_envelope_ref: self.commit_store.options().keyring_envelope_ref.clone(),
            section_ordinal: 1,
            section_offset: location.length,
            section_len,
            section_digest: digest_v2_section(sealed.bytes()),
        };
        Ok(PendingV2StreamingIndexRun {
            bytes: sealed.into_bytes(),
            run,
        })
    }

    pub(super) fn pending_packed_sections_for_commit(
        &self,
        commit_key: &V2CommitKey,
        pending: &PendingV2Snapshot,
    ) -> Result<Option<PendingV2PackedCommitSections>> {
        let keyring = self.repository.keyring()?;
        let accepted = self
            .accepted
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?;
        let pending_deltas = pending.deltas();
        let (retention, legal_hold) = commit_protection_for_deltas(pending_deltas);
        let mut last_by_blind_key = BTreeMap::new();
        for (index, delta) in pending_deltas.iter().enumerate() {
            let blind_key = match delta {
                IndexDelta::Upsert { entry, .. } => &entry.blind_key,
                IndexDelta::Tombstone { blind_key, .. } => blind_key,
            };
            last_by_blind_key.insert(blind_key.clone(), index);
        }
        let deltas = pending_deltas
            .iter()
            .enumerate()
            .filter_map(|(index, delta)| {
                let blind_key = match delta {
                    IndexDelta::Upsert { entry, .. } => &entry.blind_key,
                    IndexDelta::Tombstone { blind_key, .. } => blind_key,
                };
                (last_by_blind_key.get(blind_key) == Some(&index)).then_some(delta)
            })
            .collect::<Vec<_>>();
        let live_manifests = deltas
            .iter()
            .filter_map(|delta| match delta {
                IndexDelta::Upsert { entry, .. } => Some(entry.manifest_id.clone()),
                IndexDelta::Tombstone { .. } => None,
            })
            .collect::<BTreeSet<_>>();

        let mut record_ordinals = BTreeMap::new();
        let mut pack_inputs = Vec::new();
        for payload in pending.payloads() {
            if !live_manifests.contains(&payload.manifest_id) {
                continue;
            }
            if payload.body.is_empty() {
                if record_ordinals
                    .insert(payload.manifest_id.clone(), None)
                    .is_some()
                {
                    return Err(v2_repository_error(V2FormatError::InvalidHeaderField));
                }
                continue;
            }
            let ordinal = u32::try_from(pack_inputs.len())
                .map_err(|_| v2_repository_error(V2FormatError::PayloadPackLimitExceeded))?;
            if record_ordinals
                .insert(payload.manifest_id.clone(), Some(ordinal))
                .is_some()
            {
                return Err(v2_repository_error(V2FormatError::InvalidHeaderField));
            }
            pack_inputs.push(V2PayloadPackRecordInput {
                plaintext: payload.body.clone(),
            });
        }
        let pack_section_ordinal = (!pack_inputs.is_empty()).then_some(0_u32);
        let index_section_ordinal = u32::from(pack_section_ordinal.is_some());

        let mut external_containers = BTreeSet::new();
        let mut external_stream_containers = BTreeSet::new();
        for delta in &deltas {
            let IndexDelta::Upsert { entry, .. } = delta else {
                continue;
            };
            if record_ordinals.contains_key(&entry.manifest_id) || entry.content_len == 0 {
                continue;
            }
            match entry.payload_ref.as_ref() {
                Some(PayloadReference::V2Pack { carrier, .. }) => {
                    external_containers.insert(index_run_pack_container(carrier));
                }
                Some(reference @ PayloadReference::V2Commit { .. }) => {
                    external_stream_containers.insert(index_run_stream_container(reference)?);
                }
                _ => return Err(v2_repository_error(V2FormatError::InvalidHeaderField)),
            }
        }
        let containers = external_containers.into_iter().collect::<Vec<_>>();
        let stream_containers = external_stream_containers.into_iter().collect::<Vec<_>>();

        let context = commit_repository_context(self, commit_key)?;
        let sealed_pack = if pack_inputs.is_empty() {
            None
        } else {
            Some(
                match seal_v2_payload_pack(
                    &keyring,
                    &context,
                    &commit_key.object_id,
                    pack_section_ordinal
                        .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))?,
                    &pack_inputs,
                ) {
                    Ok(pack) => pack,
                    Err(V2FormatError::PayloadPackLimitExceeded) => return Ok(None),
                    Err(error) => return Err(v2_repository_error(error)),
                },
            )
        };

        let mut mutations = Vec::with_capacity(deltas.len());
        for (ordinal, delta) in deltas.iter().enumerate() {
            let mutation_ordinal = u32::try_from(ordinal)
                .map_err(|_| v2_repository_error(V2FormatError::IndexRunLimitExceeded))?;
            match *delta {
                IndexDelta::Upsert { entry, .. } => {
                    let manifest = pending
                        .manifest(&accepted.repository, &entry.manifest_id)
                        .ok_or_else(|| v2_repository_error(V2FormatError::InvalidHeaderField))?;
                    let payload = if entry.content_len == 0 {
                        IndexPayloadPointer::Empty
                    } else if let Some(Some(record_ordinal)) =
                        record_ordinals.get(&entry.manifest_id)
                    {
                        let record = sealed_pack
                            .as_ref()
                            .and_then(|pack| pack.layout().record(*record_ordinal))
                            .ok_or_else(|| {
                                v2_repository_error(V2FormatError::InvalidPayloadPack)
                            })?;
                        IndexPayloadPointer::SelfPack {
                            record: IndexPackRecordPointer {
                                record_ordinal: record.ordinal(),
                                physical_offset: record.physical_offset(),
                                plaintext_digest: *record.plaintext_digest(),
                            },
                        }
                    } else if let Some(PayloadReference::V2Pack { carrier, record }) =
                        entry.payload_ref.as_ref()
                    {
                        let container = index_run_pack_container(carrier);
                        let container_ordinal = containers
                            .binary_search(&container)
                            .map_err(|_| v2_repository_error(V2FormatError::InvalidHeaderField))?;
                        IndexPayloadPointer::ExternalPack {
                            container_ordinal: u32::try_from(container_ordinal).map_err(|_| {
                                v2_repository_error(V2FormatError::IndexRunLimitExceeded)
                            })?,
                            record: IndexPackRecordPointer {
                                record_ordinal: record.record_ordinal,
                                physical_offset: record.record_offset,
                                plaintext_digest: record.plaintext_digest,
                            },
                        }
                    } else if let Some(reference @ PayloadReference::V2Commit { .. }) =
                        entry.payload_ref.as_ref()
                    {
                        let container = index_run_stream_container(reference)?;
                        let container_ordinal = stream_containers
                            .binary_search(&container)
                            .map_err(|_| v2_repository_error(V2FormatError::InvalidHeaderField))?;
                        IndexPayloadPointer::ExternalStream {
                            container_ordinal: u32::try_from(container_ordinal).map_err(|_| {
                                v2_repository_error(V2FormatError::IndexRunLimitExceeded)
                            })?,
                        }
                    } else {
                        return Ok(None);
                    };
                    mutations.push(IndexMutation::Upsert(IndexUpsert {
                        mutation_ordinal,
                        blind_key: IndexBlindKey::try_from(&entry.blind_key)
                            .map_err(|_| v2_repository_error(V2FormatError::InvalidHeaderField))?,
                        namespace_key_id: entry.namespace_key_id.clone(),
                        path: manifest.key.clone(),
                        generation: entry.generation,
                        payload,
                        content_len: entry.content_len,
                        modified_at_ms: entry.modified_at_ms,
                        retention: entry.retention,
                        legal_hold: entry.legal_hold,
                    }));
                }
                IndexDelta::Tombstone {
                    namespace_key_id,
                    blind_key,
                    path,
                    generation,
                } => mutations.push(IndexMutation::Tombstone(IndexTombstone {
                    mutation_ordinal,
                    blind_key: IndexBlindKey::try_from(blind_key)
                        .map_err(|_| v2_repository_error(V2FormatError::InvalidHeaderField))?,
                    namespace_key_id: namespace_key_id.clone(),
                    path: path.clone(),
                    generation: *generation,
                })),
            }
        }
        drop(accepted);

        let mut sections = Vec::with_capacity(2);
        let mut locations = Vec::with_capacity(pack_inputs.len());
        if let (Some(pack_section_ordinal), Some(pack)) = (pack_section_ordinal, sealed_pack) {
            let length = u64::try_from(pack.bytes().len())
                .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?;
            for (manifest_id, record_ordinal) in &record_ordinals {
                let record = record_ordinal
                    .and_then(|ordinal| pack.layout().record(ordinal))
                    .map(index_pack_record_pointer);
                locations.push(PendingV2PackRecordLocation {
                    manifest_id: manifest_id.clone(),
                    pack_section_ordinal: record_ordinal.map(|_| pack_section_ordinal),
                    pack: record.map(|_| index_run_self_pack(pack.layout())),
                    record,
                    offset: 0,
                    length: record_ordinal.map_or(0, |_| length),
                });
            }
            sections.push(V2CommitSection::new(
                V2SectionType::PayloadPack,
                V2_SECTION_FLAG_MUST_UNDERSTAND,
                pack.into_bytes(),
            ));
        } else {
            for manifest_id in record_ordinals.keys() {
                locations.push(PendingV2PackRecordLocation {
                    manifest_id: manifest_id.clone(),
                    pack_section_ordinal: None,
                    pack: None,
                    record: None,
                    offset: 0,
                    length: 0,
                });
            }
        }
        let run_sequence = pending
            .commit_sequence()
            .ok_or_else(|| v2_repository_error(V2FormatError::InvalidHeaderField))?;
        let bounds = index_run_bounds(&mutations)?;
        let mutation_count = u32::try_from(mutations.len())
            .map_err(|_| v2_repository_error(V2FormatError::IndexRunLimitExceeded))?;
        let run = IndexRun {
            sequence: run_sequence,
            self_pack: locations.iter().find_map(|location| location.pack.clone()),
            self_stream: None,
            containers,
            stream_containers,
            standalone_stream_containers: Vec::new(),
            mutations,
        };
        let sealed_run = match seal_v2_index_run(
            &keyring,
            &context,
            &commit_key.object_id,
            index_section_ordinal,
            &run,
            &IndexRunLimits::default(),
        ) {
            Ok(run) => run,
            Err(V2FormatError::IndexRunLimitExceeded) => return Ok(None),
            Err(error) => return Err(v2_repository_error(error)),
        };
        let probe = probe_v2_index_run_header(sealed_run.bytes()).map_err(v2_repository_error)?;
        let section_offset = sections.iter().try_fold(0_u64, |offset, section| {
            offset.checked_add(u64::try_from(section.bytes.len()).ok()?)
        });
        let section_offset =
            section_offset.ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))?;
        let section_len = u64::try_from(sealed_run.bytes().len())
            .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?;
        let run_facts = PendingV2IndexRunFacts {
            run_id: *sealed_run.run_id().as_bytes(),
            run_sequence,
            minimum_generation: bounds.minimum_generation,
            maximum_generation: bounds.maximum_generation,
            mutation_count,
            frame_count: probe.frame_count(),
            namespace_bounds: bounds.namespace,
            listing_bounds: bounds.listing,
            keyring_envelope_ref: self.commit_store.options().keyring_envelope_ref.clone(),
            section_ordinal: index_section_ordinal,
            section_offset,
            section_len,
            section_digest: digest_v2_section(sealed_run.bytes()),
        };
        sections.push(V2CommitSection::new(
            V2SectionType::IndexRun,
            V2_SECTION_FLAG_MUST_UNDERSTAND,
            sealed_run.into_bytes(),
        ));
        Ok(Some(PendingV2PackedCommitSections {
            sections,
            locations,
            run: run_facts,
            retention,
            legal_hold,
        }))
    }

    pub(super) fn resolve_pending_pack_refs(
        &self,
        pending: &mut PendingV2Snapshot,
        stored: &V2StoredCommit,
        locations: &[PendingV2PackRecordLocation],
    ) -> Result<()> {
        let mut resolved_count = 0_usize;
        let mut shared_carrier: Option<Arc<V2PackCarrierReference>> = None;
        for delta in pending.deltas_mut() {
            let IndexDelta::Upsert { entry, .. } = delta else {
                continue;
            };
            let Some(location) = locations
                .iter()
                .find(|location| location.manifest_id == entry.manifest_id)
            else {
                continue;
            };
            entry.object_id = stored.anchor_state.commit_key.clone();
            entry.object_version_id = stored.version_id.clone();
            entry.payload_ref = match (
                location.pack_section_ordinal,
                location.pack.as_ref(),
                location.record,
            ) {
                (Some(pack_section_ordinal), Some(pack), Some(record)) => {
                    let candidate = V2PackCarrierReference {
                        commit_key: stored.anchor_state.commit_key.clone(),
                        commit_version_id: stored.version_id.clone(),
                        body_digest: stored.anchor_state.body_digest,
                        commit_stored_len: stored.object_len,
                        pack_section_ordinal,
                        pack_offset: stored
                            .sections_start
                            .checked_add(location.offset)
                            .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))?,
                        length: location.length,
                        pack_id: pack.pack_id,
                        content_key_id: pack.content_key_id.clone(),
                        keyring_envelope_object_id: self
                            .commit_store
                            .options()
                            .keyring_envelope_ref
                            .object_id
                            .clone(),
                        keyring_envelope_digest: self
                            .commit_store
                            .options()
                            .keyring_envelope_ref
                            .digest,
                        pack_record_count: pack.record_count,
                    };
                    let carrier = match shared_carrier.as_ref() {
                        Some(carrier) if **carrier == candidate => Arc::clone(carrier),
                        Some(_) => {
                            return Err(v2_repository_error(V2FormatError::InvalidHeaderField));
                        }
                        None => {
                            let carrier = Arc::new(candidate);
                            shared_carrier = Some(Arc::clone(&carrier));
                            carrier
                        }
                    };
                    Some(PayloadReference::V2Pack {
                        carrier,
                        record: V2PackRecordReference {
                            record_ordinal: record.record_ordinal,
                            record_offset: record.physical_offset,
                            plaintext_digest: record.plaintext_digest,
                        },
                    })
                }
                (None, None, None) if entry.content_len == 0 => None,
                _ => return Err(v2_repository_error(V2FormatError::InvalidHeaderField)),
            };
            resolved_count = resolved_count.saturating_add(1);
        }
        let unresolved = pending.deltas().iter().any(|delta| {
            matches!(
                delta,
                IndexDelta::Upsert { entry, .. }
                    if matches!(entry.payload_ref, Some(PayloadReference::V2Self { .. }))
            )
        });
        if resolved_count != locations.len() || unresolved {
            return Err(v2_repository_error(V2FormatError::InvalidHeaderField));
        }
        Ok(())
    }
}

pub(in crate::v2) struct V2PackedIndexRunReplay<'a> {
    pub(in crate::v2) parsed_header: &'a V2ParsedCommitHeader,
    pub(in crate::v2) version_id: Option<&'a BackendVersionId>,
    pub(in crate::v2) object_len: u64,
    pub(in crate::v2) section_ordinal: u32,
    pub(in crate::v2) stored_run: &'a [u8],
    pub(in crate::v2) level: u16,
    pub(in crate::v2) compaction_generation: u64,
}

pub(in crate::v2) fn apply_packed_index_run(
    keyring: &rs3_crypto::KeyRing,
    repository_id: &rs3_types::RepositoryId,
    state: &mut RepositoryState,
    replay: V2PackedIndexRunReplay<'_>,
) -> Result<crate::v2::V2IndexRootRunRef> {
    let context = repository_context_from_refs(
        repository_id,
        &replay.parsed_header.header.keyring_envelope_ref,
    )?;
    let commit_key = &replay.parsed_header.header.self_ref.commit_key;
    let run = open_v2_index_run(
        keyring,
        &context,
        commit_key,
        replay.section_ordinal,
        replay.stored_run,
        &IndexRunLimits::default(),
    )
    .map_err(v2_repository_error)?;
    // Wire v5 reserves and authenticates standalone stream carriers before the
    // repository read, reachability, and maintenance graph accepts them.
    if !run.standalone_stream_containers.is_empty() {
        return Err(v2_repository_error(V2FormatError::UnsupportedSection));
    }
    let directory = open_v2_index_run_directory(
        keyring,
        &context,
        commit_key,
        replay.section_ordinal,
        replay.stored_run,
        &IndexRunLimits::default(),
    )
    .map_err(v2_repository_error)?;
    if replay.level == 0 {
        if replay.compaction_generation != 0 {
            return Err(v2_repository_error(V2FormatError::InvalidIndexRun));
        }
    } else if replay.compaction_generation == 0
        || run.self_pack.is_some()
        || run.self_stream.is_some()
    {
        return Err(v2_repository_error(V2FormatError::InvalidIndexRun));
    }
    // Logical mutations and signed commits have independent counters: one
    // batched commit can cover many mutation generations. Replay is oldest
    // first, so only enforce monotonicity within the mutation domain.
    if run.sequence <= state.next_sequence {
        return Err(v2_repository_error(V2FormatError::InvalidHeaderField));
    }
    let mutation_generations = run.mutations.iter().map(|mutation| match mutation {
        IndexMutation::Upsert(upsert) => upsert.generation,
        IndexMutation::Tombstone(tombstone) => tombstone.generation,
    });
    let mut maximum_generation = None;
    for generation in mutation_generations {
        if generation <= state.next_sequence || generation > run.sequence {
            return Err(v2_repository_error(V2FormatError::InvalidIndexRun));
        }
        maximum_generation = Some(
            maximum_generation.map_or(generation, |current: rs3_types::Sequence| {
                current.max(generation)
            }),
        );
    }
    if maximum_generation != Some(run.sequence) {
        return Err(v2_repository_error(V2FormatError::InvalidIndexRun));
    }
    let bounds = index_run_bounds(&run.mutations)?;
    let mutation_count = u32::try_from(run.mutations.len())
        .map_err(|_| v2_repository_error(V2FormatError::IndexRunLimitExceeded))?;
    let descriptor = replay
        .parsed_header
        .header
        .section_index
        .get(
            usize::try_from(replay.section_ordinal)
                .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?,
        )
        .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))?;
    if descriptor.section_type != V2SectionType::IndexRun
        || descriptor.length
            != u64::try_from(replay.stored_run.len())
                .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?
        || descriptor.digest != digest_v2_section(replay.stored_run)
    {
        return Err(v2_repository_error(V2FormatError::InvalidIndexRun));
    }
    let accepted_run = crate::v2::V2IndexRootRunRef {
        run_id: *directory.run_id().as_bytes(),
        run_sequence: run.sequence,
        minimum_generation: bounds.minimum_generation,
        maximum_generation: bounds.maximum_generation,
        mutation_count,
        frame_count: u32::try_from(directory.frames().len())
            .map_err(|_| v2_repository_error(V2FormatError::IndexRunLimitExceeded))?,
        level: replay.level,
        compaction_generation: replay.compaction_generation,
        namespace_bounds: bounds.namespace,
        listing_bounds: bounds.listing,
        keyring_envelope_ref: replay.parsed_header.header.keyring_envelope_ref.clone(),
        location: crate::v2::V2EmbeddedIndexRunLocation {
            commit_key: commit_key.clone(),
            version_id: replay.version_id.cloned(),
            commit_stored_len: replay.object_len,
            commit_body_digest: replay.parsed_header.header.body_digest,
            sections_start: u64::try_from(replay.parsed_header.sections_start)
                .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?,
            section_ordinal: replay.section_ordinal,
            section_offset: descriptor.offset,
            section_len: descriptor.length,
            section_digest: descriptor.digest,
        },
    };
    let self_pack = match run.self_pack.as_ref() {
        Some(pack) => {
            let mut matches = replay
                .parsed_header
                .header
                .section_index
                .iter()
                .enumerate()
                .filter(|(_, section)| section.section_type == V2SectionType::PayloadPack);
            let Some((ordinal, section)) = matches.next() else {
                return Err(v2_repository_error(V2FormatError::SectionBounds));
            };
            if matches.next().is_some() || section.length != pack.stored_len {
                return Err(v2_repository_error(V2FormatError::SectionBounds));
            }
            Some((
                u32::try_from(ordinal)
                    .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?,
                section,
                pack,
            ))
        }
        None => {
            if replay
                .parsed_header
                .header
                .section_index
                .iter()
                .any(|section| section.section_type == V2SectionType::PayloadPack)
            {
                return Err(v2_repository_error(V2FormatError::SectionBounds));
            }
            None
        }
    };
    let self_stream = match run.self_stream.as_ref() {
        Some(stream) => {
            let section = replay
                .parsed_header
                .header
                .section_index
                .get(
                    usize::try_from(stream.payload_section_ordinal)
                        .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?,
                )
                .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))?;
            let payload_header = payload_header_from_reference(&stream.payload_header)?;
            if section.section_type != V2SectionType::Payload
                || section.flags != V2_SECTION_FLAG_MUST_UNDERSTAND
                || total_segmented_payload_len(&payload_header)? != section.length
            {
                return Err(v2_repository_error(V2FormatError::SectionBounds));
            }
            Some((section, stream))
        }
        None => {
            if replay
                .parsed_header
                .header
                .section_index
                .iter()
                .any(|section| section.section_type == V2SectionType::Payload)
            {
                return Err(v2_repository_error(V2FormatError::SectionBounds));
            }
            None
        }
    };
    let self_pack_carrier = self_pack
        .map(|(pack_section_ordinal, section, pack)| {
            Ok::<Arc<V2PackCarrierReference>, RepositoryError>(Arc::new(V2PackCarrierReference {
                commit_key: commit_key.clone(),
                commit_version_id: replay.version_id.cloned(),
                body_digest: replay.parsed_header.header.body_digest,
                commit_stored_len: replay.object_len,
                pack_section_ordinal,
                pack_offset: u64::try_from(replay.parsed_header.sections_start)
                    .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?
                    .checked_add(section.offset)
                    .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))?,
                length: section.length,
                pack_id: pack.pack_id,
                content_key_id: pack.content_key_id.clone(),
                keyring_envelope_object_id: replay
                    .parsed_header
                    .header
                    .keyring_envelope_ref
                    .object_id
                    .clone(),
                keyring_envelope_digest: replay.parsed_header.header.keyring_envelope_ref.digest,
                pack_record_count: pack.record_count,
            }))
        })
        .transpose()?;
    let pack_carriers = run
        .containers
        .iter()
        .map(|container| Arc::new(pack_carrier_from_index_run(container)))
        .collect::<Vec<_>>();
    let sections_start = u64::try_from(replay.parsed_header.sections_start)
        .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?;
    let self_stream_carrier = self_stream.map(|(section, stream)| {
        Arc::new(V2StreamCarrierReference {
            commit_key: commit_key.clone(),
            commit_version_id: replay.version_id.cloned(),
            body_digest: replay.parsed_header.header.body_digest,
            commit_stored_len: replay.object_len,
            keyring_envelope_object_id: replay
                .parsed_header
                .header
                .keyring_envelope_ref
                .object_id
                .clone(),
            keyring_envelope_digest: replay.parsed_header.header.keyring_envelope_ref.digest,
            payload_section_ordinal: stream.payload_section_ordinal,
            payload_section_digest: section.digest,
            payload_id: stream.payload_id.clone(),
            payload_header: Some(stream.payload_header.clone()),
            sections_start: Some(sections_start),
            offset: section.offset,
            length: section.length,
        })
    });
    let stream_carriers = run
        .stream_containers
        .iter()
        .map(|container| Arc::new(stream_carrier_from_index_run(container)))
        .collect::<Vec<_>>();

    for mutation in run.mutations {
        match mutation {
            IndexMutation::Upsert(upsert) => {
                let blind_key = upsert
                    .blind_key
                    .to_blind_index_key()
                    .map_err(|_| v2_repository_error(V2FormatError::InvalidIndexRun))?;
                verify_blind_key(keyring, &upsert.namespace_key_id, &upsert.path, &blind_key)?;
                let payload_ref = match upsert.payload {
                    IndexPayloadPointer::Empty => None,
                    IndexPayloadPointer::SelfPack { record } => {
                        let Some(carrier) = self_pack_carrier.as_ref() else {
                            return Err(v2_repository_error(V2FormatError::SectionBounds));
                        };
                        Some(PayloadReference::V2Pack {
                            carrier: Arc::clone(carrier),
                            record: pack_record_reference(record),
                        })
                    }
                    IndexPayloadPointer::ExternalPack {
                        container_ordinal,
                        record,
                    } => {
                        let carrier = pack_carriers
                            .get(
                                usize::try_from(container_ordinal).map_err(|_| {
                                    v2_repository_error(V2FormatError::InvalidIndexRun)
                                })?,
                            )
                            .ok_or_else(|| v2_repository_error(V2FormatError::InvalidIndexRun))?;
                        Some(PayloadReference::V2Pack {
                            carrier: Arc::clone(carrier),
                            record: pack_record_reference(record),
                        })
                    }
                    IndexPayloadPointer::SelfStream => {
                        let Some(carrier) = self_stream_carrier.as_ref() else {
                            return Err(v2_repository_error(V2FormatError::SectionBounds));
                        };
                        Some(PayloadReference::V2Commit {
                            carrier: Arc::clone(carrier),
                        })
                    }
                    IndexPayloadPointer::ExternalStream { container_ordinal } => {
                        let carrier = stream_carriers
                            .get(
                                usize::try_from(container_ordinal).map_err(|_| {
                                    v2_repository_error(V2FormatError::InvalidIndexRun)
                                })?,
                            )
                            .ok_or_else(|| v2_repository_error(V2FormatError::InvalidIndexRun))?;
                        Some(PayloadReference::V2Commit {
                            carrier: Arc::clone(carrier),
                        })
                    }
                    IndexPayloadPointer::ExternalStandaloneStream { .. } => {
                        return Err(v2_repository_error(V2FormatError::UnsupportedSection));
                    }
                };
                let manifest_id = keyring.derive_manifest_id(&object_material(
                    upsert.path.as_str(),
                    upsert.generation,
                ))?;
                let (object_id, object_version_id) = match payload_ref.as_ref() {
                    Some(PayloadReference::V2Pack { carrier, .. }) => (
                        carrier.commit_key.clone(),
                        carrier.commit_version_id.clone(),
                    ),
                    Some(PayloadReference::V2Commit { carrier }) => (
                        carrier.commit_key.clone(),
                        carrier.commit_version_id.clone(),
                    ),
                    _ => (commit_key.clone(), replay.version_id.cloned()),
                };
                state.manifests.insert(
                    manifest_id.clone(),
                    TrustedManifest {
                        key: upsert.path,
                        content_len: upsert.content_len,
                        modified_at_ms: upsert.modified_at_ms,
                        retention: upsert.retention,
                        legal_hold: upsert.legal_hold,
                    },
                );
                state.upsert_namespace_entry_without_prefixes(NamespaceEntry {
                    namespace_key_id: upsert.namespace_key_id,
                    blind_key,
                    object_id,
                    object_version_id,
                    payload_ref,
                    manifest_id,
                    content_len: upsert.content_len,
                    modified_at_ms: upsert.modified_at_ms,
                    generation: upsert.generation,
                    retention: upsert.retention,
                    legal_hold: upsert.legal_hold,
                });
            }
            IndexMutation::Tombstone(tombstone) => {
                let blind_key = tombstone
                    .blind_key
                    .to_blind_index_key()
                    .map_err(|_| v2_repository_error(V2FormatError::InvalidIndexRun))?;
                verify_blind_key(
                    keyring,
                    &tombstone.namespace_key_id,
                    &tombstone.path,
                    &blind_key,
                )?;
                state.tombstone_namespace_entry(blind_key, tombstone.generation);
            }
        }
    }
    state.next_sequence = state.next_sequence.max(run.sequence);
    Ok(accepted_run)
}

fn index_run_self_pack(layout: &V2PayloadPackLayout) -> IndexRunSelfPack {
    IndexRunSelfPack {
        pack_id: layout.facts().pack_id().into_bytes(),
        content_key_id: layout.facts().content_key_id().clone(),
        stored_len: u64::from(layout.facts().stored_len()),
        record_count: layout.facts().record_count(),
    }
}

fn index_run_stream_container(reference: &PayloadReference) -> Result<IndexRunStreamContainer> {
    let PayloadReference::V2Commit { carrier } = reference else {
        return Err(v2_repository_error(V2FormatError::InvalidHeaderField));
    };
    let (Some(payload_header), Some(sections_start)) =
        (carrier.payload_header.as_ref(), carrier.sections_start)
    else {
        return Err(v2_repository_error(V2FormatError::InvalidHeaderField));
    };
    Ok(IndexRunStreamContainer {
        object_id: carrier.commit_key.clone(),
        version_id: carrier.commit_version_id.clone(),
        stored_len: carrier.commit_stored_len,
        commit_body_digest: carrier.body_digest,
        keyring_envelope: IndexRunKeyringRef {
            object_id: carrier.keyring_envelope_object_id.clone(),
            digest: carrier.keyring_envelope_digest,
        },
        sections_start,
        payload_section_ordinal: carrier.payload_section_ordinal,
        payload_section_offset: carrier.offset,
        payload_section_len: carrier.length,
        payload_section_digest: carrier.payload_section_digest,
        payload_id: carrier.payload_id.clone(),
        payload_header: payload_header.clone(),
    })
}

fn index_run_pack_container(carrier: &V2PackCarrierReference) -> IndexRunContainer {
    IndexRunContainer {
        object_id: carrier.commit_key.clone(),
        version_id: carrier.commit_version_id.clone(),
        stored_len: carrier.commit_stored_len,
        commit_body_digest: carrier.body_digest,
        keyring_envelope: IndexRunKeyringRef {
            object_id: carrier.keyring_envelope_object_id.clone(),
            digest: carrier.keyring_envelope_digest,
        },
        pack_section_offset: carrier.pack_offset,
        pack_section_ordinal: carrier.pack_section_ordinal,
        pack_section_len: carrier.length,
        pack_id: carrier.pack_id,
        content_key_id: carrier.content_key_id.clone(),
        pack_record_count: carrier.pack_record_count,
    }
}

fn pack_carrier_from_index_run(container: &IndexRunContainer) -> V2PackCarrierReference {
    V2PackCarrierReference {
        commit_key: container.object_id.clone(),
        commit_version_id: container.version_id.clone(),
        body_digest: container.commit_body_digest,
        commit_stored_len: container.stored_len,
        pack_section_ordinal: container.pack_section_ordinal,
        pack_offset: container.pack_section_offset,
        length: container.pack_section_len,
        pack_id: container.pack_id,
        content_key_id: container.content_key_id.clone(),
        keyring_envelope_object_id: container.keyring_envelope.object_id.clone(),
        keyring_envelope_digest: container.keyring_envelope.digest,
        pack_record_count: container.pack_record_count,
    }
}

fn stream_carrier_from_index_run(container: &IndexRunStreamContainer) -> V2StreamCarrierReference {
    V2StreamCarrierReference {
        commit_key: container.object_id.clone(),
        commit_version_id: container.version_id.clone(),
        body_digest: container.commit_body_digest,
        commit_stored_len: container.stored_len,
        keyring_envelope_object_id: container.keyring_envelope.object_id.clone(),
        keyring_envelope_digest: container.keyring_envelope.digest,
        payload_section_ordinal: container.payload_section_ordinal,
        payload_section_digest: container.payload_section_digest,
        payload_id: container.payload_id.clone(),
        payload_header: Some(container.payload_header.clone()),
        sections_start: Some(container.sections_start),
        offset: container.payload_section_offset,
        length: container.payload_section_len,
    }
}

fn pack_record_reference(record: IndexPackRecordPointer) -> V2PackRecordReference {
    V2PackRecordReference {
        record_ordinal: record.record_ordinal,
        record_offset: record.physical_offset,
        plaintext_digest: record.plaintext_digest,
    }
}

fn index_pack_record_pointer(record: &V2PayloadPackRecord) -> IndexPackRecordPointer {
    IndexPackRecordPointer {
        record_ordinal: record.ordinal(),
        physical_offset: record.physical_offset(),
        plaintext_digest: *record.plaintext_digest(),
    }
}

pub(in crate::v2) fn index_run_bounds(mutations: &[IndexMutation]) -> Result<IndexRunBounds> {
    let Some(first) = mutations.first() else {
        return Err(v2_repository_error(V2FormatError::InvalidIndexRun));
    };
    let (first_generation, first_blind_key, first_path) = mutation_facts(first);
    let mut minimum_generation = first_generation;
    let mut maximum_generation = first_generation;
    let mut minimum_blind_key = first_blind_key;
    let mut maximum_blind_key = first_blind_key;
    let mut minimum_path = first_path.clone();
    let mut maximum_path = first_path.clone();
    for mutation in &mutations[1..] {
        let (generation, blind_key, path) = mutation_facts(mutation);
        minimum_generation = minimum_generation.min(generation);
        maximum_generation = maximum_generation.max(generation);
        minimum_blind_key = minimum_blind_key.min(blind_key);
        maximum_blind_key = maximum_blind_key.max(blind_key);
        minimum_path = minimum_path.min(path.clone());
        maximum_path = maximum_path.max(path.clone());
    }
    Ok(IndexRunBounds {
        minimum_generation,
        maximum_generation,
        namespace: (minimum_blind_key, maximum_blind_key),
        listing: (minimum_path, maximum_path),
    })
}

fn mutation_facts(mutation: &IndexMutation) -> (Sequence, IndexBlindKey, &LogicalPath) {
    match mutation {
        IndexMutation::Upsert(upsert) => (upsert.generation, upsert.blind_key, &upsert.path),
        IndexMutation::Tombstone(tombstone) => {
            (tombstone.generation, tombstone.blind_key, &tombstone.path)
        }
    }
}

pub(in crate::v2) fn repository_context_from_refs(
    repository_id: &rs3_types::RepositoryId,
    keyring_reference: &crate::v2::V2KeyringEnvelopeRef,
) -> Result<Vec<u8>> {
    let repository_id = repository_id.as_str().as_bytes();
    let keyring_object_id = keyring_reference.object_id.as_str().as_bytes();
    let mut context = Vec::with_capacity(
        96_usize
            .saturating_add(repository_id.len())
            .saturating_add(keyring_object_id.len()),
    );
    context.extend_from_slice(b"rs3:v02-repository-context:repository-and-keyring:v1\n");
    context.extend_from_slice(
        &u32::try_from(repository_id.len())
            .map_err(|_| v2_repository_error(V2FormatError::InvalidHeaderField))?
            .to_be_bytes(),
    );
    context.extend_from_slice(repository_id);
    context.extend_from_slice(
        &u32::try_from(keyring_object_id.len())
            .map_err(|_| v2_repository_error(V2FormatError::InvalidHeaderField))?
            .to_be_bytes(),
    );
    context.extend_from_slice(keyring_object_id);
    context.extend_from_slice(&keyring_reference.digest);
    Ok(context)
}

fn commit_repository_context<S>(
    repository: &V2Repository<S>,
    _commit_key: &V2CommitKey,
) -> Result<Vec<u8>>
where
    S: BlobStore + Clone,
{
    repository_context_from_refs(
        &repository.commit_store.options().repository_id,
        &repository.commit_store.options().keyring_envelope_ref,
    )
}

fn verify_blind_key(
    keyring: &rs3_crypto::KeyRing,
    namespace_key_id: &rs3_types::KeyId,
    path: &rs3_types::LogicalPath,
    expected: &rs3_types::BlindIndexKey,
) -> Result<()> {
    let matches = keyring
        .derive_blind_index_keys_for_lookup(path)?
        .into_iter()
        .any(|derived| derived.key_id == *namespace_key_id && derived.blind_key == *expected);
    if !matches {
        return Err(v2_repository_error(V2FormatError::CryptoOperation));
    }
    Ok(())
}
