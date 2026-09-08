//! Pure planning for metadata-only compaction of packed v03 index runs.

use crate::v2::{V2FormatError, V2Result};
use rs3_index::run::encode_index_run_frames;
use rs3_index::run::{
    IndexBlindKey, IndexMutation, IndexPayloadPointer, IndexRun, IndexRunContainer, IndexRunLimits,
    IndexRunStandaloneStreamContainer,
};
use rs3_types::Sequence;
#[cfg(test)]
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::sync::Arc;

/// One decoded source run and the exact containers that held its self payload.
///
/// Each exact container is required precisely when its corresponding self
/// carrier is present. It converts a commit-relative pointer into durable
/// exact-object facts before source-run boundaries disappear during compaction.
pub(super) struct PackedCompactionSourceRun {
    pub(super) run: IndexRun,
    pub(super) self_pack_container: Option<IndexRunContainer>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ResolvedCarrier {
    Pack(Arc<IndexRunContainer>),
    StandaloneStream(Arc<IndexRunStandaloneStreamContainer>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResolvedMutation {
    mutation: IndexMutation,
    carrier: Option<ResolvedCarrier>,
}

impl ResolvedMutation {
    fn generation(&self) -> Sequence {
        mutation_generation(&self.mutation)
    }

    fn blind_key(&self) -> IndexBlindKey {
        mutation_blind_key(&self.mutation)
    }
}

/// Plans strictly reducing, metadata-only compaction runs.
///
/// No object is uploaded and no root is published here. All source-relative
/// payload pointers are first resolved to exact external containers, winners
/// are selected by generation, and the result is adaptively sharded on whole
/// generation groups so a generation can never be partially published.
/// When supplied, `current_namespace` must be the complete accepted namespace
/// held under the caller's publication lock and bound to its accepted anchor.
/// It permits pruning obsolete upserts, including an empty replacement set;
/// winning tombstones and all source validation remain mandatory.
pub(super) fn plan_packed_run_compaction(
    sources: Vec<PackedCompactionSourceRun>,
    limits: &IndexRunLimits,
    current_namespace: Option<&rs3_index::NamespaceIndex>,
) -> V2Result<Vec<IndexRun>> {
    plan_packed_run_compaction_counted(
        sources,
        limits,
        &EncodeAttemptCounter::default(),
        current_namespace,
    )
}

#[derive(Default)]
struct EncodeAttemptCounter {
    #[cfg(test)]
    attempts: Cell<usize>,
}

impl EncodeAttemptCounter {
    fn record(&self) {
        #[cfg(test)]
        self.attempts.set(self.attempts.get().saturating_add(1));
        #[cfg(not(test))]
        let _ = self;
    }

    #[cfg(test)]
    fn get(&self) -> usize {
        self.attempts.get()
    }
}

fn plan_packed_run_compaction_counted(
    sources: Vec<PackedCompactionSourceRun>,
    limits: &IndexRunLimits,
    encode_attempts: &EncodeAttemptCounter,
    current_namespace: Option<&rs3_index::NamespaceIndex>,
) -> V2Result<Vec<IndexRun>> {
    if sources.is_empty() {
        return Err(V2FormatError::InvalidIndexRun);
    }

    let source_count = sources.len();
    let mut winners = BTreeMap::<IndexBlindKey, ResolvedMutation>::new();
    let mut standalone_carriers = BTreeMap::<
        (
            rs3_types::BackendObjectId,
            Option<rs3_types::BackendVersionId>,
        ),
        Arc<IndexRunStandaloneStreamContainer>,
    >::new();

    for mut source in sources {
        // Decoded input is normally already validated. Revalidating at this
        // trust boundary keeps the pure planner safe for every future caller.
        encode_index_run_frames(&source.run, limits).map_err(|_| V2FormatError::InvalidIndexRun)?;
        validate_self_containers(&source)?;

        let self_pack_container = source.self_pack_container.map(Arc::new);
        let pack_containers = source
            .run
            .containers
            .drain(..)
            .map(Arc::new)
            .collect::<Vec<_>>();
        let standalone_stream_containers = source
            .run
            .standalone_stream_containers
            .drain(..)
            .map(|container| {
                let key = (container.object_id.clone(), container.version_id.clone());
                match standalone_carriers.get(&key) {
                    Some(existing) if existing.as_ref() != &container => {
                        Err(V2FormatError::InvalidIndexRun)
                    }
                    Some(existing) => Ok(Arc::clone(existing)),
                    None => {
                        let container = Arc::new(container);
                        standalone_carriers.insert(key, Arc::clone(&container));
                        Ok(container)
                    }
                }
            })
            .collect::<V2Result<Vec<_>>>()?;
        for mutation in source.run.mutations.drain(..) {
            let resolved = resolve_mutation(
                &pack_containers,
                &standalone_stream_containers,
                self_pack_container.as_ref(),
                mutation,
            )?;
            match winners.get(&resolved.blind_key()) {
                None => {
                    winners.insert(resolved.blind_key(), resolved);
                }
                Some(current) if resolved.generation() > current.generation() => {
                    winners.insert(resolved.blind_key(), resolved);
                }
                Some(current) if resolved.generation() == current.generation() => {
                    if resolved != *current {
                        return Err(V2FormatError::InvalidIndexRun);
                    }
                }
                Some(_) => {}
            }
        }
    }

    if winners.is_empty() {
        return Err(V2FormatError::InvalidIndexRun);
    }

    // Validate and resolve every source before pruning, including conflicting
    // generations and carrier facts. The caller holds the accepted state and
    // publication locks: a different accepted generation (or no live entry)
    // proves an upsert obsolete. Tombstones remain even when no key is live,
    // because they can still mask values outside this bounded source window.
    let mut ordered = Vec::with_capacity(winners.len());
    for winner in winners.into_values() {
        if let (Some(namespace), IndexMutation::Upsert(upsert)) =
            (current_namespace, &winner.mutation)
        {
            let blind_key = upsert
                .blind_key
                .to_blind_index_key()
                .map_err(|_| V2FormatError::InvalidIndexRun)?;
            match namespace.head(&blind_key) {
                None => continue,
                Some(entry) if entry.generation > upsert.generation => continue,
                Some(entry)
                    if entry.generation == upsert.generation
                        && entry.namespace_key_id == upsert.namespace_key_id => {}
                Some(_) => return Err(V2FormatError::InvalidIndexRun),
            }
        }
        ordered.push(winner);
    }
    // An entirely obsolete source window needs no replacement run. The newer
    // retained runs still carry the accepted coverage generation and deletes.

    ordered.sort_by(|left, right| {
        left.generation()
            .cmp(&right.generation())
            .then_with(|| left.blind_key().cmp(&right.blind_key()))
    });

    let generation_groups = equal_generation_groups(&ordered);
    let chunks = maximal_mutation_chunks(&generation_groups, limits.max_mutations)?;
    let mut output = Vec::new();
    for chunk in chunks {
        encode_group_chunk(
            &ordered,
            &generation_groups,
            chunk,
            limits,
            encode_attempts,
            &mut output,
        )?;
    }

    if output.len() >= source_count {
        return Err(V2FormatError::MaintenanceBudgetExceeded);
    }
    Ok(output)
}

fn validate_self_containers(source: &PackedCompactionSourceRun) -> V2Result<()> {
    match (&source.run.self_pack, &source.self_pack_container) {
        (None, None) => {}
        (Some(pack), Some(container))
            if pack.pack_id == container.pack_id
                && pack.content_key_id == container.content_key_id
                && pack.stored_len == container.pack_section_len
                && pack.record_count == container.pack_record_count => {}
        _ => return Err(V2FormatError::InvalidIndexRun),
    }
    Ok(())
}

fn resolve_mutation(
    pack_containers: &[Arc<IndexRunContainer>],
    standalone_stream_containers: &[Arc<IndexRunStandaloneStreamContainer>],
    self_pack_container: Option<&Arc<IndexRunContainer>>,
    mutation: IndexMutation,
) -> V2Result<ResolvedMutation> {
    let (normalized, carrier) = match mutation {
        IndexMutation::Upsert(mut upsert) => {
            let (payload, carrier) = match upsert.payload {
                IndexPayloadPointer::Empty => (IndexPayloadPointer::Empty, None),
                IndexPayloadPointer::SelfPack { record } => {
                    let container = self_pack_container
                        .cloned()
                        .ok_or(V2FormatError::InvalidIndexRun)?;
                    (
                        IndexPayloadPointer::ExternalPack {
                            container_ordinal: 0,
                            record,
                        },
                        Some(ResolvedCarrier::Pack(container)),
                    )
                }
                IndexPayloadPointer::ExternalPack {
                    container_ordinal,
                    record,
                } => {
                    let index = usize::try_from(container_ordinal)
                        .map_err(|_| V2FormatError::InvalidIndexRun)?;
                    let container = pack_containers
                        .get(index)
                        .cloned()
                        .ok_or(V2FormatError::InvalidIndexRun)?;
                    (
                        IndexPayloadPointer::ExternalPack {
                            container_ordinal: 0,
                            record,
                        },
                        Some(ResolvedCarrier::Pack(container)),
                    )
                }

                IndexPayloadPointer::ExternalStandaloneStream { container_ordinal } => {
                    let index = usize::try_from(container_ordinal)
                        .map_err(|_| V2FormatError::InvalidIndexRun)?;
                    let container = standalone_stream_containers
                        .get(index)
                        .cloned()
                        .ok_or(V2FormatError::InvalidIndexRun)?;
                    (
                        IndexPayloadPointer::ExternalStandaloneStream {
                            container_ordinal: 0,
                        },
                        Some(ResolvedCarrier::StandaloneStream(container)),
                    )
                }
            };
            upsert.mutation_ordinal = 0;
            upsert.payload = payload;
            (IndexMutation::Upsert(upsert), carrier)
        }
        IndexMutation::Tombstone(mut tombstone) => {
            tombstone.mutation_ordinal = 0;
            (IndexMutation::Tombstone(tombstone), None)
        }
    };
    Ok(ResolvedMutation {
        mutation: normalized,
        carrier,
    })
}

fn equal_generation_groups(mutations: &[ResolvedMutation]) -> Vec<Range<usize>> {
    let mut groups = Vec::new();
    let mut start = 0;
    while start < mutations.len() {
        let generation = mutations[start].generation();
        let mut end = start + 1;
        while end < mutations.len() && mutations[end].generation() == generation {
            end += 1;
        }
        groups.push(start..end);
        start = end;
    }
    groups
}

fn maximal_mutation_chunks(
    groups: &[Range<usize>],
    max_mutations: usize,
) -> V2Result<Vec<Range<usize>>> {
    let mut chunks = Vec::new();
    let mut start = 0;
    while start < groups.len() {
        let mut end = start;
        let mut mutation_count = 0_usize;
        while let Some(group) = groups.get(end) {
            let group_len = group.len();
            if group_len > max_mutations {
                return Err(V2FormatError::IndexRunLimitExceeded);
            }
            let candidate = mutation_count
                .checked_add(group_len)
                .ok_or(V2FormatError::IndexRunLimitExceeded)?;
            if mutation_count != 0 && candidate > max_mutations {
                break;
            }
            mutation_count = candidate;
            end += 1;
        }
        if end == start {
            return Err(V2FormatError::IndexRunLimitExceeded);
        }
        chunks.push(start..end);
        start = end;
    }
    Ok(chunks)
}

fn encode_group_chunk(
    ordered: &[ResolvedMutation],
    groups: &[Range<usize>],
    chunk: Range<usize>,
    limits: &IndexRunLimits,
    encode_attempts: &EncodeAttemptCounter,
    output: &mut Vec<IndexRun>,
) -> V2Result<()> {
    let mutation_start = groups
        .get(chunk.start)
        .map(|group| group.start)
        .ok_or(V2FormatError::InvalidIndexRun)?;
    let mutation_end = chunk
        .end
        .checked_sub(1)
        .and_then(|last| groups.get(last))
        .map(|group| group.end)
        .ok_or(V2FormatError::InvalidIndexRun)?;
    let mutations = ordered
        .get(mutation_start..mutation_end)
        .ok_or(V2FormatError::InvalidIndexRun)?;

    encode_attempts.record();
    match build_and_validate_run(mutations, limits) {
        Ok(run) => {
            output.push(run);
            Ok(())
        }
        Err(_) if chunk.len() == 1 => Err(V2FormatError::IndexRunLimitExceeded),
        Err(_) => {
            let middle = chunk.start + chunk.len() / 2;
            encode_group_chunk(
                ordered,
                groups,
                chunk.start..middle,
                limits,
                encode_attempts,
                output,
            )?;
            encode_group_chunk(
                ordered,
                groups,
                middle..chunk.end,
                limits,
                encode_attempts,
                output,
            )
        }
    }
}

fn build_and_validate_run(
    mutations: &[ResolvedMutation],
    limits: &IndexRunLimits,
) -> V2Result<IndexRun> {
    let sequence = mutations
        .last()
        .map(ResolvedMutation::generation)
        .ok_or(V2FormatError::InvalidIndexRun)?;
    let pack_containers = mutations
        .iter()
        .filter_map(|mutation| match &mutation.carrier {
            Some(ResolvedCarrier::Pack(container)) => Some(Arc::clone(container)),
            Some(ResolvedCarrier::StandaloneStream(_)) | None => None,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let standalone_stream_containers = mutations
        .iter()
        .filter_map(|mutation| match &mutation.carrier {
            Some(ResolvedCarrier::StandaloneStream(container)) => Some(Arc::clone(container)),
            Some(ResolvedCarrier::Pack(_)) | None => None,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut canonical_mutations = Vec::with_capacity(mutations.len());
    for (index, resolved) in mutations.iter().enumerate() {
        let ordinal = u32::try_from(index).map_err(|_| V2FormatError::IndexRunLimitExceeded)?;
        let mut mutation = resolved.mutation.clone();
        set_mutation_ordinal(&mut mutation, ordinal);
        if let IndexMutation::Upsert(upsert) = &mut mutation {
            match (upsert.payload, &resolved.carrier) {
                (
                    IndexPayloadPointer::ExternalPack { record, .. },
                    Some(ResolvedCarrier::Pack(container)),
                ) => {
                    let container_ordinal = pack_containers
                        .binary_search(container)
                        .map_err(|_| V2FormatError::InvalidIndexRun)?;
                    upsert.payload = IndexPayloadPointer::ExternalPack {
                        container_ordinal: u32::try_from(container_ordinal)
                            .map_err(|_| V2FormatError::IndexRunLimitExceeded)?,
                        record,
                    };
                }
                (
                    IndexPayloadPointer::ExternalStandaloneStream { .. },
                    Some(ResolvedCarrier::StandaloneStream(container)),
                ) => {
                    let container_ordinal = standalone_stream_containers
                        .binary_search(container)
                        .map_err(|_| V2FormatError::InvalidIndexRun)?;
                    upsert.payload = IndexPayloadPointer::ExternalStandaloneStream {
                        container_ordinal: u32::try_from(container_ordinal)
                            .map_err(|_| V2FormatError::IndexRunLimitExceeded)?,
                    };
                }
                (IndexPayloadPointer::Empty, None) => {}
                _ => return Err(V2FormatError::InvalidIndexRun),
            }
        }
        canonical_mutations.push(mutation);
    }

    let run = IndexRun {
        completion_receipt: None,
        sequence,
        self_pack: None,

        containers: pack_containers
            .into_iter()
            .map(|container| container.as_ref().clone())
            .collect(),
        standalone_stream_containers: standalone_stream_containers
            .into_iter()
            .map(|container| container.as_ref().clone())
            .collect(),
        mutations: canonical_mutations,
    };
    encode_index_run_frames(&run, limits).map_err(|_| V2FormatError::IndexRunLimitExceeded)?;
    Ok(run)
}

fn mutation_generation(mutation: &IndexMutation) -> Sequence {
    match mutation {
        IndexMutation::Upsert(upsert) => upsert.generation,
        IndexMutation::Tombstone(tombstone) => tombstone.generation,
    }
}

fn mutation_blind_key(mutation: &IndexMutation) -> IndexBlindKey {
    match mutation {
        IndexMutation::Upsert(upsert) => upsert.blind_key,
        IndexMutation::Tombstone(tombstone) => tombstone.blind_key,
    }
}

fn set_mutation_ordinal(mutation: &mut IndexMutation, ordinal: u32) {
    match mutation {
        IndexMutation::Upsert(upsert) => upsert.mutation_ordinal = ordinal,
        IndexMutation::Tombstone(tombstone) => tombstone.mutation_ordinal = ordinal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rs3_index::PayloadLayout;
    use rs3_index::run::{
        IndexPackRecordPointer, IndexRunKeyringRef, IndexRunSelfPack, IndexTombstone, IndexUpsert,
    };
    use rs3_types::{BackendObjectId, BackendVersionId, KeyId, LogicalPath};

    fn must<T, E: std::fmt::Debug>(result: std::result::Result<T, E>) -> T {
        result.unwrap_or_else(|error| panic!("unexpected error: {error:?}"))
    }

    fn key(byte: u8) -> IndexBlindKey {
        IndexBlindKey::from_bytes([byte; 32])
    }

    fn numbered_key(value: u64) -> IndexBlindKey {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&value.to_be_bytes());
        IndexBlindKey::from_bytes(bytes)
    }

    fn plan_packed_run_compaction(
        sources: Vec<PackedCompactionSourceRun>,
        limits: &IndexRunLimits,
    ) -> V2Result<Vec<IndexRun>> {
        super::plan_packed_run_compaction(sources, limits, None)
    }

    fn plan_with_attempt_count(
        sources: Vec<PackedCompactionSourceRun>,
        limits: &IndexRunLimits,
    ) -> (V2Result<Vec<IndexRun>>, usize) {
        let counter = EncodeAttemptCounter::default();
        let result = plan_packed_run_compaction_counted(sources, limits, &counter, None);
        (result, counter.get())
    }

    fn sequence(value: u64) -> Sequence {
        Sequence::new(value)
    }

    fn object_id(value: &str) -> BackendObjectId {
        must(BackendObjectId::new(value.to_owned()))
    }

    fn key_id(value: &str) -> KeyId {
        must(KeyId::new(value.to_owned()))
    }

    fn path(value: &str) -> LogicalPath {
        must(LogicalPath::new(value.to_owned()))
    }

    fn container(byte: u8) -> IndexRunContainer {
        IndexRunContainer {
            object_id: object_id(&format!("objects/{byte}")),
            version_id: None,
            stored_len: 2_048,
            commit_body_digest: [byte; 32],
            keyring_envelope: IndexRunKeyringRef {
                object_id: object_id(&format!("keys/{byte}")),
                digest: [byte.wrapping_add(1); 32],
            },
            pack_section_offset: 512,
            pack_section_ordinal: 0,
            pack_section_len: 1_024,
            pack_id: [byte.wrapping_add(2); 32],
            attempt_id: rs3_types::PayloadAttemptId::from_bytes([0xa3; 32]),
            content_key_id: key_id("content-key"),
            pack_record_count: 4,
        }
    }

    fn stream_header() -> PayloadLayout {
        PayloadLayout {
            chunk_size: 64 * 1024,
            plaintext_len: 32,
            key_id: key_id("stream-content-key"),
            carrier_id: [0x51; 32],
            parts: vec![rs3_index::PayloadPart {
                part_number: 1,
                attempt_id: rs3_types::PayloadAttemptId::from_bytes([0x81; 32]),
                plaintext_len: 32,
            }],
        }
    }

    fn standalone_stream_container(byte: u8) -> IndexRunStandaloneStreamContainer {
        let payload_layout = stream_header();
        IndexRunStandaloneStreamContainer {
            object_id: object_id(&format!(
                "objects/v03/{}",
                URL_SAFE_NO_PAD.encode([byte; 32])
            )),
            version_id: Some(must(BackendVersionId::new(format!(
                "standalone-version-{byte}"
            )))),
            stored_len: payload_layout.plaintext_len + 16,
            object_digest: [byte; 32],
            keyring_envelope: IndexRunKeyringRef {
                object_id: object_id(&format!("keys/standalone-{byte}")),
                digest: [byte.wrapping_add(1); 32],
            },
            payload_layout,
        }
    }

    fn record(ordinal: u32) -> IndexPackRecordPointer {
        IndexPackRecordPointer {
            record_ordinal: ordinal,
            physical_offset: ordinal * 64,
        }
    }

    fn upsert(
        ordinal: u32,
        blind_key: IndexBlindKey,
        generation: u64,
        payload: IndexPayloadPointer,
    ) -> IndexMutation {
        IndexMutation::Upsert(IndexUpsert {
            checksum: None,
            mutation_ordinal: ordinal,
            blind_key,
            namespace_key_id: key_id("namespace-key"),
            path: path(&format!("path/{generation}/{ordinal}")),
            generation: sequence(generation),
            payload,
            content_len: u64::from(!matches!(payload, IndexPayloadPointer::Empty)) * 32,
            modified_at_ms: 1,
            retention: None,
            legal_hold: None,
        })
    }

    fn tombstone(ordinal: u32, blind_key: IndexBlindKey, generation: u64) -> IndexMutation {
        IndexMutation::Tombstone(IndexTombstone {
            mutation_ordinal: ordinal,
            blind_key,
            namespace_key_id: key_id("namespace-key"),
            path: path(&format!("path/{generation}/{ordinal}")),
            generation: sequence(generation),
        })
    }

    fn run(sequence_value: u64, mutations: Vec<IndexMutation>) -> IndexRun {
        IndexRun {
            completion_receipt: None,
            sequence: sequence(sequence_value),
            self_pack: None,

            containers: Vec::new(),

            standalone_stream_containers: Vec::new(),
            mutations,
        }
    }

    fn source(run: IndexRun) -> PackedCompactionSourceRun {
        PackedCompactionSourceRun {
            run,
            self_pack_container: None,
        }
    }

    fn external_source(
        sequence_value: u64,
        blind_key: IndexBlindKey,
        generation: u64,
        container_byte: u8,
    ) -> PackedCompactionSourceRun {
        PackedCompactionSourceRun {
            run: IndexRun {
                completion_receipt: None,
                sequence: sequence(sequence_value),
                self_pack: None,

                containers: vec![container(container_byte)],

                standalone_stream_containers: Vec::new(),
                mutations: vec![upsert(
                    0,
                    blind_key,
                    generation,
                    IndexPayloadPointer::ExternalPack {
                        container_ordinal: 0,
                        record: record(0),
                    },
                )],
            },
            self_pack_container: None,
        }
    }

    fn external_standalone_stream_source(
        sequence_value: u64,
        blind_key: IndexBlindKey,
        generation: u64,
        exact_container: IndexRunStandaloneStreamContainer,
    ) -> PackedCompactionSourceRun {
        PackedCompactionSourceRun {
            run: IndexRun {
                completion_receipt: None,
                sequence: sequence(sequence_value),
                self_pack: None,

                containers: Vec::new(),

                standalone_stream_containers: vec![exact_container],
                mutations: vec![upsert(
                    0,
                    blind_key,
                    generation,
                    IndexPayloadPointer::ExternalStandaloneStream {
                        container_ordinal: 0,
                    },
                )],
            },
            self_pack_container: None,
        }
    }

    #[test]
    fn mixed_carriers_are_deduplicated_sorted_and_reindexed_exactly() {
        let pack = container(7);
        let standalone = standalone_stream_container(9);
        let planned = must(plan_packed_run_compaction(
            vec![
                external_source(3, key(3), 3, 7),
                external_standalone_stream_source(5, key(5), 5, standalone.clone()),
            ],
            &IndexRunLimits::default(),
        ));

        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].containers, vec![pack]);
        assert_eq!(planned[0].standalone_stream_containers, vec![standalone]);
        let IndexMutation::Upsert(standalone_upsert) = &planned[0].mutations[1] else {
            panic!("expected standalone upsert");
        };
        assert_eq!(
            standalone_upsert.payload,
            IndexPayloadPointer::ExternalStandaloneStream {
                container_ordinal: 0,
            }
        );
    }

    #[test]
    fn conflicting_exact_standalone_carrier_facts_fail_planning() {
        let first = standalone_stream_container(9);
        let mut conflicting = first.clone();
        conflicting.keyring_envelope.digest[0] ^= 0x80;

        assert_eq!(
            plan_packed_run_compaction(
                vec![
                    external_standalone_stream_source(3, key(3), 3, first),
                    external_standalone_stream_source(4, key(4), 4, conflicting),
                ],
                &IndexRunLimits::default(),
            ),
            Err(V2FormatError::InvalidIndexRun)
        );
    }

    fn accepted_entry(blind_key: IndexBlindKey, generation: u64) -> rs3_index::NamespaceEntry {
        rs3_index::NamespaceEntry {
            namespace_key_id: key_id("namespace-key"),
            blind_key: must(blind_key.to_blind_index_key()),
            object_id: object_id("objects/current"),
            object_version_id: None,
            payload_ref: None,
            manifest_id: must(rs3_types::ManifestId::new("current-manifest")),
            content_len: 0,
            modified_at_ms: 1,
            generation: sequence(generation),
            retention: None,
            legal_hold: None,
        }
    }

    #[test]
    fn full_older_shards_cannot_starve_later_fixed_key_churn() {
        let limits = IndexRunLimits::default();
        let count = limits.max_mutations as u64;
        let full_sources = || {
            (0..2)
                .map(|shard| {
                    let mutations = (0..count)
                        .map(|index| {
                            let generation = shard * count + index + 1;
                            upsert(
                                index as u32,
                                numbered_key(generation),
                                generation,
                                IndexPayloadPointer::Empty,
                            )
                        })
                        .collect();
                    source(run((shard + 1) * count, mutations))
                })
                .collect::<Vec<_>>()
        };
        // These are two genuinely full canonical runs, with disjoint keys.
        // Merging them alone cannot reduce the catalog without liveness proof.
        assert_eq!(
            plan_packed_run_compaction(full_sources(), &limits),
            Err(V2FormatError::MaintenanceBudgetExceeded)
        );
        let mut namespace = rs3_index::NamespaceIndex::new();
        // Later accepted runs deleted every old key except this overwritten key.
        namespace.upsert_without_prefixes(accepted_entry(numbered_key(1), 2 * count + 1));
        let compacted = must(super::plan_packed_run_compaction(
            full_sources(),
            &limits,
            Some(&namespace),
        ));
        assert!(
            compacted.is_empty(),
            "fully obsolete oldest window needs only a new root"
        );

        let mut catalog = vec![source(run(
            2 * count + 1,
            vec![upsert(
                0,
                numbered_key(1),
                2 * count + 1,
                IndexPayloadPointer::Empty,
            )],
        ))];
        for cycle in 1..=32 {
            let deleted_generation = 2 * count + 2 * cycle;
            catalog.push(source(run(
                deleted_generation,
                vec![tombstone(0, numbered_key(1), deleted_generation)],
            )));
            namespace.remove(&must(numbered_key(1).to_blind_index_key()));
            let deleted = must(super::plan_packed_run_compaction(
                catalog,
                &limits,
                Some(&namespace),
            ));
            assert_eq!(deleted.len(), 1);
            assert!(matches!(
                deleted[0].mutations.as_slice(),
                [IndexMutation::Tombstone(_)]
            ));
            let generation = deleted_generation + 1;
            namespace.upsert_without_prefixes(accepted_entry(numbered_key(1), generation));
            catalog = deleted.into_iter().map(source).collect();
            catalog.push(source(run(
                generation,
                vec![upsert(
                    0,
                    numbered_key(1),
                    generation,
                    IndexPayloadPointer::Empty,
                )],
            )));
            let recreated = must(super::plan_packed_run_compaction(
                catalog,
                &limits,
                Some(&namespace),
            ));
            assert_eq!(recreated.len(), 1);
            assert_eq!(recreated[0].mutations.len(), 1);
            catalog = recreated.into_iter().map(source).collect();
        }
    }

    #[test]
    fn accepted_blind_key_generation_controls_pruning_not_plaintext_path() {
        let mut namespace = rs3_index::NamespaceIndex::new();
        namespace.upsert_without_prefixes(accepted_entry(key(1), 8));
        let mut old_namespace_mutation = upsert(0, key(2), 7, IndexPayloadPointer::Empty);
        let IndexMutation::Upsert(old) = &mut old_namespace_mutation else {
            panic!("upsert");
        };
        old.path = path("same/path");
        let mut current_mutation = upsert(0, key(1), 8, IndexPayloadPointer::Empty);
        let IndexMutation::Upsert(current) = &mut current_mutation else {
            panic!("upsert");
        };
        current.path = path("same/path");
        let sources = vec![
            source(run(7, vec![old_namespace_mutation])),
            source(run(8, vec![current_mutation])),
            source(run(9, vec![tombstone(0, key(3), 9)])),
        ];
        let result = must(super::plan_packed_run_compaction(
            sources,
            &IndexRunLimits::default(),
            Some(&namespace),
        ));
        assert_eq!(result[0].mutations.len(), 2);
        assert_eq!(mutation_blind_key(&result[0].mutations[0]), key(1));
        assert!(matches!(
            &result[0].mutations[1],
            IndexMutation::Tombstone(_)
        ));
    }

    #[test]
    fn obsolete_conflicts_are_validated_before_pruning() {
        let left = source(run(3, vec![tombstone(0, key(1), 3)]));
        let right = source(run(
            4,
            vec![upsert(0, key(1), 3, IndexPayloadPointer::Empty)],
        ));
        assert_eq!(
            super::plan_packed_run_compaction(
                vec![left, right],
                &IndexRunLimits::default(),
                Some(&rs3_index::NamespaceIndex::new())
            ),
            Err(V2FormatError::InvalidIndexRun)
        );
    }

    #[test]
    fn accepted_generation_behind_a_source_fails_closed() {
        let mut namespace = rs3_index::NamespaceIndex::new();
        namespace.upsert_without_prefixes(accepted_entry(key(1), 2));
        let sources = vec![
            source(run(
                3,
                vec![upsert(0, key(1), 3, IndexPayloadPointer::Empty)],
            )),
            source(run(4, vec![tombstone(0, key(2), 4)])),
        ];
        assert_eq!(
            super::plan_packed_run_compaction(
                sources,
                &IndexRunLimits::default(),
                Some(&namespace)
            ),
            Err(V2FormatError::InvalidIndexRun)
        );
    }

    #[test]
    fn newer_tombstone_wins_and_ordinals_are_reassigned() {
        let older = source(run(
            4,
            vec![upsert(0, key(1), 4, IndexPayloadPointer::Empty)],
        ));
        let newer = source(run(9, vec![tombstone(0, key(1), 9)]));

        let planned = must(plan_packed_run_compaction(
            vec![older, newer],
            &IndexRunLimits::default(),
        ));

        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].sequence, sequence(9));
        assert_eq!(planned[0].mutations, vec![tombstone(0, key(1), 9)]);
        assert!(planned[0].self_pack.is_none());
    }

    #[test]
    fn sharding_never_splits_an_equal_generation_group() {
        let limits = IndexRunLimits {
            max_mutations: 2,
            ..IndexRunLimits::default()
        };

        let planned = must(plan_packed_run_compaction(
            vec![
                source(run(0, vec![tombstone(0, key(1), 0)])),
                source(run(
                    1,
                    vec![tombstone(0, key(1), 1), tombstone(1, key(2), 2)],
                )),
                source(run(2, vec![tombstone(0, key(3), 2)])),
                source(run(3, vec![tombstone(0, key(4), 3)])),
            ],
            &limits,
        ));

        assert_eq!(planned.len(), 3);
        assert_eq!(planned[0].mutations.len(), 1);
        assert_eq!(planned[1].mutations.len(), 2);
        assert!(
            planned[1]
                .mutations
                .iter()
                .all(|mutation| mutation_generation(mutation) == sequence(2))
        );
    }

    #[test]
    fn self_pack_is_converted_to_its_exact_external_container() {
        let exact_container = container(7);
        let self_pack = IndexRunSelfPack {
            pack_id: exact_container.pack_id,
            attempt_id: exact_container.attempt_id,
            content_key_id: exact_container.content_key_id.clone(),
            stored_len: exact_container.pack_section_len,
            record_count: exact_container.pack_record_count,
        };
        let source_with_pack = PackedCompactionSourceRun {
            run: IndexRun {
                completion_receipt: None,
                sequence: sequence(3),
                self_pack: Some(self_pack),

                containers: Vec::new(),

                standalone_stream_containers: Vec::new(),
                mutations: vec![upsert(
                    0,
                    key(3),
                    3,
                    IndexPayloadPointer::SelfPack { record: record(2) },
                )],
            },
            self_pack_container: Some(exact_container.clone()),
        };

        let planned = must(plan_packed_run_compaction(
            vec![
                source_with_pack,
                source(run(4, vec![tombstone(0, key(4), 4)])),
            ],
            &IndexRunLimits::default(),
        ));

        assert_eq!(planned[0].containers, vec![exact_container]);
        let IndexMutation::Upsert(upsert) = &planned[0].mutations[0] else {
            panic!("expected upsert");
        };
        assert_eq!(
            upsert.payload,
            IndexPayloadPointer::ExternalPack {
                container_ordinal: 0,
                record: record(2),
            }
        );
    }

    #[test]
    fn external_containers_are_deduplicated_sorted_and_reindexed() {
        let high = container(9);
        let low = container(2);
        let high_source = PackedCompactionSourceRun {
            run: IndexRun {
                completion_receipt: None,
                sequence: sequence(4),
                self_pack: None,

                containers: vec![high.clone()],

                standalone_stream_containers: Vec::new(),
                mutations: vec![upsert(
                    0,
                    key(1),
                    4,
                    IndexPayloadPointer::ExternalPack {
                        container_ordinal: 0,
                        record: record(0),
                    },
                )],
            },
            self_pack_container: None,
        };
        let low_source = PackedCompactionSourceRun {
            run: IndexRun {
                completion_receipt: None,
                sequence: sequence(5),
                self_pack: None,

                containers: vec![low.clone()],

                standalone_stream_containers: Vec::new(),
                mutations: vec![upsert(
                    0,
                    key(2),
                    5,
                    IndexPayloadPointer::ExternalPack {
                        container_ordinal: 0,
                        record: record(1),
                    },
                )],
            },
            self_pack_container: None,
        };

        let planned = must(plan_packed_run_compaction(
            vec![high_source, low_source],
            &IndexRunLimits::default(),
        ));

        assert_eq!(planned[0].containers, vec![low, high]);
        let IndexMutation::Upsert(first) = &planned[0].mutations[0] else {
            panic!("expected first upsert");
        };
        let IndexMutation::Upsert(second) = &planned[0].mutations[1] else {
            panic!("expected second upsert");
        };
        assert!(matches!(
            first.payload,
            IndexPayloadPointer::ExternalPack {
                container_ordinal: 1,
                ..
            }
        ));
        assert!(matches!(
            second.payload,
            IndexPayloadPointer::ExternalPack {
                container_ordinal: 0,
                ..
            }
        ));
    }

    #[test]
    fn standalone_containers_are_deduplicated_sorted_and_reindexed() {
        let high = standalone_stream_container(9);
        let low = standalone_stream_container(2);
        let planned = must(plan_packed_run_compaction(
            vec![
                external_standalone_stream_source(4, key(1), 4, high.clone()),
                external_standalone_stream_source(5, key(2), 5, low.clone()),
                external_standalone_stream_source(6, key(3), 6, high.clone()),
            ],
            &IndexRunLimits::default(),
        ));

        assert_eq!(planned.len(), 1);
        assert!(planned[0].self_pack.is_none());
        assert!(planned[0].containers.is_empty());
        assert_eq!(planned[0].standalone_stream_containers, vec![low, high]);
        let ordinals = planned[0]
            .mutations
            .iter()
            .map(|mutation| {
                let IndexMutation::Upsert(upsert) = mutation else {
                    panic!("expected upsert");
                };
                let IndexPayloadPointer::ExternalStandaloneStream { container_ordinal } =
                    upsert.payload
                else {
                    panic!("expected external stream");
                };
                container_ordinal
            })
            .collect::<Vec<_>>();
        assert_eq!(ordinals, vec![1, 0, 1]);
    }

    #[test]
    fn equivalent_self_and_external_facts_are_not_ambiguous() {
        let exact_container = container(5);
        let record = record(1);
        let self_source = PackedCompactionSourceRun {
            run: IndexRun {
                completion_receipt: None,
                sequence: sequence(6),
                self_pack: Some(IndexRunSelfPack {
                    pack_id: exact_container.pack_id,
                    attempt_id: exact_container.attempt_id,
                    content_key_id: exact_container.content_key_id.clone(),
                    stored_len: exact_container.pack_section_len,
                    record_count: exact_container.pack_record_count,
                }),

                containers: Vec::new(),

                standalone_stream_containers: Vec::new(),
                mutations: vec![upsert(
                    0,
                    key(5),
                    6,
                    IndexPayloadPointer::SelfPack { record },
                )],
            },
            self_pack_container: Some(exact_container.clone()),
        };
        let external_source = PackedCompactionSourceRun {
            run: IndexRun {
                completion_receipt: None,
                sequence: sequence(7),
                self_pack: None,

                containers: vec![exact_container.clone()],

                standalone_stream_containers: Vec::new(),
                mutations: vec![upsert(
                    0,
                    key(5),
                    6,
                    IndexPayloadPointer::ExternalPack {
                        container_ordinal: 0,
                        record,
                    },
                )],
            },
            self_pack_container: None,
        };

        let planned = must(plan_packed_run_compaction(
            vec![self_source, external_source],
            &IndexRunLimits::default(),
        ));

        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].containers, vec![exact_container]);
    }

    #[test]
    fn same_generation_nonidentical_facts_fail_closed() {
        let left = source(run(3, vec![tombstone(0, key(1), 3)]));
        let mut different = tombstone(0, key(1), 3);
        let IndexMutation::Tombstone(tombstone) = &mut different else {
            panic!("expected tombstone");
        };
        tombstone.path = path("different/path");
        let right = source(run(4, vec![different]));

        assert_eq!(
            plan_packed_run_compaction(vec![left, right], &IndexRunLimits::default()),
            Err(V2FormatError::InvalidIndexRun)
        );
    }

    #[test]
    fn single_oversize_generation_group_is_rejected() {
        let limits = IndexRunLimits {
            max_mutations: 1,
            ..IndexRunLimits::default()
        };

        assert_eq!(
            plan_packed_run_compaction(
                vec![
                    source(run(8, vec![tombstone(0, key(1), 8)])),
                    source(run(9, vec![tombstone(0, key(2), 8)])),
                ],
                &limits,
            ),
            Err(V2FormatError::IndexRunLimitExceeded)
        );
    }

    #[test]
    fn non_reducing_output_is_rejected() {
        let limits = IndexRunLimits {
            max_mutations: 1,
            ..IndexRunLimits::default()
        };

        assert_eq!(
            plan_packed_run_compaction(
                vec![source(run(3, vec![tombstone(0, key(1), 3)]))],
                &limits,
            ),
            Err(V2FormatError::MaintenanceBudgetExceeded)
        );
    }

    #[test]
    fn encoding_attempts_scale_with_maximal_chunks_not_generations() {
        const GENERATIONS: u64 = 1_024;
        const MUTATIONS_PER_CHUNK: usize = 64;
        let limits = IndexRunLimits {
            max_mutations: MUTATIONS_PER_CHUNK,
            ..IndexRunLimits::default()
        };
        let sources = (1..=GENERATIONS)
            .map(|generation| {
                source(run(
                    generation,
                    vec![tombstone(0, numbered_key(generation), generation)],
                ))
            })
            .collect();

        let (planned, attempts) = plan_with_attempt_count(sources, &limits);
        let planned = must(planned);

        assert_eq!(planned.len(), 16);
        assert_eq!(attempts, 16);
    }

    #[test]
    fn exact_container_rejection_bisects_only_on_generation_boundaries() {
        let limits = IndexRunLimits {
            max_containers: 1,
            ..IndexRunLimits::default()
        };
        let sources = vec![
            external_source(0, key(1), 0, 10),
            external_source(1, key(1), 1, 1),
            external_source(2, key(2), 2, 2),
            external_source(3, key(3), 3, 3),
            external_source(4, key(4), 4, 4),
        ];

        let (planned, attempts) = plan_with_attempt_count(sources, &limits);
        let planned = must(planned);

        assert_eq!(planned.len(), 4);
        assert!(planned.iter().all(|run| run.mutations.len() == 1));
        // One rejected four-group chunk, two rejected halves, then four
        // successful leaves. A balanced boundary bisection is seven attempts.
        assert_eq!(attempts, 7);
    }
}
