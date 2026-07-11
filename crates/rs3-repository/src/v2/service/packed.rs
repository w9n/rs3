//! Compact payload-pack and framed index-run publication for bounded v02 batches.

use super::{PendingV2Payload, V2Repository, commit_protection_for_deltas, v2_repository_error};
use crate::error::Result;
use crate::namespace::prefix_tokens_for_key;
use crate::state::{RepositoryState, TrustedManifest, object_material};
use rs3_index::run::{
    IndexBlindKey, IndexMutation, IndexPayloadPointer, IndexRun, IndexRunContainer, IndexRunLimits,
    IndexTombstone, IndexUpsert,
};
use rs3_index::{IndexDelta, NamespaceEntry, PayloadReference};
use rs3_storage::BlobStore;
use rs3_types::{BackendVersionId, ManifestId};
use std::collections::{BTreeMap, BTreeSet};

use crate::v2::{
    V2_SECTION_FLAG_MUST_UNDERSTAND, V2CommitKey, V2CommitSection, V2FormatError,
    V2ParsedCommitHeader, V2PayloadPackDirectory, V2PayloadPackRecordInput, V2SectionType,
    V2StoredCommit, open_v2_index_run, seal_v2_index_run, seal_v2_payload_pack,
};

pub(super) struct PendingV2PackRecordLocation {
    pub(super) manifest_id: ManifestId,
    pub(super) pack_section_ordinal: Option<u32>,
    pub(super) pack_record_count: u32,
    pub(super) record_ordinal: Option<u32>,
    pub(super) offset: u64,
    pub(super) length: u64,
}

pub(super) struct PendingV2PackedCommitSections {
    pub(super) sections: Vec<V2CommitSection>,
    pub(super) locations: Vec<PendingV2PackRecordLocation>,
    pub(super) pack_directory: Option<V2PayloadPackDirectory>,
    pub(super) retention: Option<rs3_types::RetentionPolicy>,
    pub(super) legal_hold: Option<rs3_types::LegalHoldStatus>,
}

impl<S> V2Repository<S>
where
    S: BlobStore + Clone,
{
    pub(super) fn pending_packed_sections_for_commit(
        &self,
        commit_key: &V2CommitKey,
        pending_payloads: &[PendingV2Payload],
    ) -> Result<Option<PendingV2PackedCommitSections>> {
        let keyring = self.repository.keyring()?;
        let state = self.repository.read_state()?;
        let pending_deltas = &state.pending_index_deltas;
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
        for pending in pending_payloads {
            if !live_manifests.contains(&pending.manifest_id) {
                continue;
            }
            if pending.body.is_empty() {
                if record_ordinals
                    .insert(pending.manifest_id.clone(), None)
                    .is_some()
                {
                    return Err(v2_repository_error(V2FormatError::InvalidHeaderField));
                }
                continue;
            }
            let ordinal = u32::try_from(pack_inputs.len())
                .map_err(|_| v2_repository_error(V2FormatError::PayloadPackLimitExceeded))?;
            if record_ordinals
                .insert(pending.manifest_id.clone(), Some(ordinal))
                .is_some()
            {
                return Err(v2_repository_error(V2FormatError::InvalidHeaderField));
            }
            pack_inputs.push(V2PayloadPackRecordInput {
                plaintext: pending.body.clone(),
            });
        }
        let pack_record_count = u32::try_from(pack_inputs.len())
            .map_err(|_| v2_repository_error(V2FormatError::PayloadPackLimitExceeded))?;
        let pack_section_ordinal = (!pack_inputs.is_empty()).then_some(0_u32);
        let index_section_ordinal = u32::from(pack_section_ordinal.is_some());

        let mut external_containers = BTreeSet::new();
        for delta in &deltas {
            let IndexDelta::Upsert { entry, .. } = delta else {
                continue;
            };
            if record_ordinals.contains_key(&entry.manifest_id) || entry.content_len == 0 {
                continue;
            }
            match entry.payload_ref.as_ref() {
                Some(PayloadReference::V2Pack {
                    commit_key,
                    commit_version_id,
                    body_digest,
                    commit_stored_len,
                    pack_section_ordinal,
                    pack_offset,
                    length,
                    pack_record_count,
                    ..
                }) => {
                    external_containers.insert(IndexRunContainer {
                        object_id: commit_key.clone(),
                        version_id: commit_version_id.clone(),
                        stored_len: *commit_stored_len,
                        commit_body_digest: *body_digest,
                        pack_section_ordinal: *pack_section_ordinal,
                        pack_section_offset: *pack_offset,
                        pack_section_len: *length,
                        pack_record_count: *pack_record_count,
                    });
                }
                // Transitional segmented payloads remain on the old delta path
                // until the streaming writer adopts pack/run framing.
                Some(PayloadReference::V2Commit { .. }) => return Ok(None),
                _ => return Err(v2_repository_error(V2FormatError::InvalidHeaderField)),
            }
        }
        let containers = external_containers.into_iter().collect::<Vec<_>>();

        let mut mutations = Vec::with_capacity(deltas.len());
        for (ordinal, delta) in deltas.iter().enumerate() {
            let mutation_ordinal = u32::try_from(ordinal)
                .map_err(|_| v2_repository_error(V2FormatError::IndexRunLimitExceeded))?;
            match *delta {
                IndexDelta::Upsert { entry, .. } => {
                    let manifest = state
                        .manifests
                        .get(&entry.manifest_id)
                        .ok_or_else(|| v2_repository_error(V2FormatError::InvalidHeaderField))?;
                    let payload = if entry.content_len == 0 {
                        IndexPayloadPointer::Empty
                    } else if let Some(Some(record_ordinal)) =
                        record_ordinals.get(&entry.manifest_id)
                    {
                        IndexPayloadPointer::SelfPack {
                            record_ordinal: *record_ordinal,
                        }
                    } else {
                        let Some(PayloadReference::V2Pack {
                            commit_key,
                            commit_version_id,
                            body_digest,
                            commit_stored_len,
                            pack_section_ordinal,
                            pack_offset,
                            length,
                            pack_record_count,
                            record_ordinal,
                            ..
                        }) = entry.payload_ref.as_ref()
                        else {
                            return Ok(None);
                        };
                        let container = IndexRunContainer {
                            object_id: commit_key.clone(),
                            version_id: commit_version_id.clone(),
                            stored_len: *commit_stored_len,
                            commit_body_digest: *body_digest,
                            pack_section_ordinal: *pack_section_ordinal,
                            pack_section_offset: *pack_offset,
                            pack_section_len: *length,
                            pack_record_count: *pack_record_count,
                        };
                        let container_ordinal = containers
                            .binary_search(&container)
                            .map_err(|_| v2_repository_error(V2FormatError::InvalidHeaderField))?;
                        IndexPayloadPointer::ExternalPack {
                            container_ordinal: u32::try_from(container_ordinal).map_err(|_| {
                                v2_repository_error(V2FormatError::IndexRunLimitExceeded)
                            })?,
                            record_ordinal: *record_ordinal,
                        }
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
        drop(state);

        let context = commit_repository_context(self, commit_key)?;
        let mut sections = Vec::with_capacity(2);
        let mut locations = Vec::with_capacity(pack_inputs.len());
        let mut pack_directory = None;
        if let Some(pack_section_ordinal) = pack_section_ordinal {
            let pack = match seal_v2_payload_pack(
                &keyring,
                &context,
                &commit_key.object_id,
                pack_section_ordinal,
                &pack_inputs,
            ) {
                Ok(pack) => pack,
                Err(V2FormatError::PayloadPackLimitExceeded) => return Ok(None),
                Err(error) => return Err(v2_repository_error(error)),
            };
            pack_directory = Some(pack.directory().clone());
            let length = u64::try_from(pack.bytes().len())
                .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?;
            for (manifest_id, record_ordinal) in &record_ordinals {
                locations.push(PendingV2PackRecordLocation {
                    manifest_id: manifest_id.clone(),
                    pack_section_ordinal: record_ordinal.map(|_| pack_section_ordinal),
                    pack_record_count,
                    record_ordinal: *record_ordinal,
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
                    pack_record_count: 0,
                    record_ordinal: None,
                    offset: 0,
                    length: 0,
                });
            }
        }
        let run = IndexRun {
            sequence: self
                .pending_index_delta_sequence()?
                .ok_or_else(|| v2_repository_error(V2FormatError::InvalidHeaderField))?,
            self_pack_record_count: (pack_record_count > 0).then_some(pack_record_count),
            containers,
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
        sections.push(V2CommitSection::new(
            V2SectionType::IndexRun,
            V2_SECTION_FLAG_MUST_UNDERSTAND,
            sealed_run.into_bytes(),
        ));
        Ok(Some(PendingV2PackedCommitSections {
            sections,
            locations,
            pack_directory,
            retention,
            legal_hold,
        }))
    }

    pub(super) fn resolve_accepted_pack_refs(
        &self,
        stored: &V2StoredCommit,
        locations: &[PendingV2PackRecordLocation],
    ) -> Result<()> {
        if locations.is_empty() {
            return Ok(());
        }
        let mut state = self.repository.write_state()?;
        let pending = state
            .pending_index_deltas
            .iter()
            .filter_map(|delta| match delta {
                IndexDelta::Upsert {
                    entry,
                    prefix_tokens,
                    ..
                } => Some((entry.blind_key.clone(), prefix_tokens.clone())),
                IndexDelta::Tombstone { .. } => None,
            })
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .collect::<Vec<_>>();
        let mut resolved_count = 0_usize;
        for (blind_key, prefix_tokens) in &pending {
            let Some(mut entry) = state.namespace.head(blind_key).cloned() else {
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
            entry.payload_ref = match (location.pack_section_ordinal, location.record_ordinal) {
                (Some(pack_section_ordinal), Some(record_ordinal)) => {
                    Some(PayloadReference::V2Pack {
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
                        pack_record_count: location.pack_record_count,
                        record_ordinal,
                    })
                }
                (None, None) if entry.content_len == 0 => None,
                _ => return Err(v2_repository_error(V2FormatError::InvalidHeaderField)),
            };
            state.replace_namespace_entry(entry, prefix_tokens.clone());
            resolved_count = resolved_count.saturating_add(1);
        }
        let unresolved = pending.iter().any(|(blind_key, _)| {
            state.namespace.head(blind_key).is_some_and(|entry| {
                matches!(entry.payload_ref, Some(PayloadReference::V2Self { .. }))
            })
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
}

pub(in crate::v2) fn apply_packed_index_run(
    keyring: &rs3_crypto::KeyRing,
    repository_id: &rs3_types::RepositoryId,
    state: &mut RepositoryState,
    replay: V2PackedIndexRunReplay<'_>,
) -> Result<()> {
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
    let self_pack = match run.self_pack_record_count {
        Some(record_count) => {
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
            if matches.next().is_some() || record_count == 0 {
                return Err(v2_repository_error(V2FormatError::SectionBounds));
            }
            Some((
                u32::try_from(ordinal)
                    .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?,
                section,
                record_count,
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
                    IndexPayloadPointer::SelfPack { record_ordinal } => {
                        let Some((pack_section_ordinal, section, pack_record_count)) = self_pack
                        else {
                            return Err(v2_repository_error(V2FormatError::SectionBounds));
                        };
                        Some(PayloadReference::V2Pack {
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
                            pack_record_count,
                            record_ordinal,
                        })
                    }
                    IndexPayloadPointer::ExternalPack {
                        container_ordinal,
                        record_ordinal,
                    } => {
                        let container = run
                            .containers
                            .get(
                                usize::try_from(container_ordinal).map_err(|_| {
                                    v2_repository_error(V2FormatError::InvalidIndexRun)
                                })?,
                            )
                            .ok_or_else(|| v2_repository_error(V2FormatError::InvalidIndexRun))?;
                        Some(PayloadReference::V2Pack {
                            commit_key: container.object_id.clone(),
                            commit_version_id: container.version_id.clone(),
                            body_digest: container.commit_body_digest,
                            commit_stored_len: container.stored_len,
                            pack_section_ordinal: container.pack_section_ordinal,
                            pack_offset: container.pack_section_offset,
                            length: container.pack_section_len,
                            pack_record_count: container.pack_record_count,
                            record_ordinal,
                        })
                    }
                };
                let manifest_id = keyring.derive_manifest_id(&object_material(
                    upsert.path.as_str(),
                    upsert.generation,
                ))?;
                let (object_id, object_version_id) = match payload_ref.as_ref() {
                    Some(PayloadReference::V2Pack {
                        commit_key,
                        commit_version_id,
                        ..
                    }) => (commit_key.clone(), commit_version_id.clone()),
                    _ => (commit_key.clone(), replay.version_id.cloned()),
                };
                let prefix_tokens =
                    prefix_tokens_for_key(keyring, &upsert.namespace_key_id, upsert.path.as_str())?;
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
                state.upsert_namespace_entry(
                    NamespaceEntry {
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
                    },
                    prefix_tokens,
                );
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
    Ok(())
}

pub(super) fn repository_context_from_refs(
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
