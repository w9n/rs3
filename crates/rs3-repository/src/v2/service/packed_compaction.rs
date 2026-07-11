//! Pure planning for metadata-only compaction of packed v02 index runs.

use crate::v2::{V2FormatError, V2Result};
use rs3_index::run::encode_index_run_frames;
use rs3_index::run::{
    IndexBlindKey, IndexMutation, IndexPayloadPointer, IndexRun, IndexRunContainer, IndexRunLimits,
    IndexRunStreamContainer,
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
    pub(super) self_stream_container: Option<IndexRunStreamContainer>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ResolvedCarrier {
    Pack(Arc<IndexRunContainer>),
    Stream(Arc<IndexRunStreamContainer>),
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
pub(super) fn plan_packed_run_compaction(
    sources: Vec<PackedCompactionSourceRun>,
    limits: &IndexRunLimits,
) -> V2Result<Vec<IndexRun>> {
    plan_packed_run_compaction_counted(sources, limits, &EncodeAttemptCounter::default())
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
) -> V2Result<Vec<IndexRun>> {
    if sources.is_empty() {
        return Err(V2FormatError::InvalidIndexRun);
    }

    let source_count = sources.len();
    let mut winners = BTreeMap::<IndexBlindKey, ResolvedMutation>::new();

    for mut source in sources {
        // Decoded input is normally already validated. Revalidating at this
        // trust boundary keeps the pure planner safe for every future caller.
        encode_index_run_frames(&source.run, limits).map_err(|_| V2FormatError::InvalidIndexRun)?;
        validate_self_containers(&source)?;

        let self_pack_container = source.self_pack_container.map(Arc::new);
        let self_stream_container = source.self_stream_container.map(Arc::new);
        let pack_containers = source
            .run
            .containers
            .drain(..)
            .map(Arc::new)
            .collect::<Vec<_>>();
        let stream_containers = source
            .run
            .stream_containers
            .drain(..)
            .map(Arc::new)
            .collect::<Vec<_>>();
        for mutation in source.run.mutations.drain(..) {
            let resolved = resolve_mutation(
                &pack_containers,
                &stream_containers,
                self_pack_container.as_ref(),
                self_stream_container.as_ref(),
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

    let mut ordered = winners.into_values().collect::<Vec<_>>();
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
    match (&source.run.self_stream, &source.self_stream_container) {
        (None, None) => Ok(()),
        (Some(stream), Some(container))
            if stream.payload_section_ordinal == container.payload_section_ordinal
                && stream.payload_id == container.payload_id
                && stream.payload_header == container.payload_header =>
        {
            Ok(())
        }
        _ => Err(V2FormatError::InvalidIndexRun),
    }
}

fn resolve_mutation(
    pack_containers: &[Arc<IndexRunContainer>],
    stream_containers: &[Arc<IndexRunStreamContainer>],
    self_pack_container: Option<&Arc<IndexRunContainer>>,
    self_stream_container: Option<&Arc<IndexRunStreamContainer>>,
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
                IndexPayloadPointer::SelfStream => {
                    let container = self_stream_container
                        .cloned()
                        .ok_or(V2FormatError::InvalidIndexRun)?;
                    (
                        IndexPayloadPointer::ExternalStream {
                            container_ordinal: 0,
                        },
                        Some(ResolvedCarrier::Stream(container)),
                    )
                }
                IndexPayloadPointer::ExternalStream { container_ordinal } => {
                    let index = usize::try_from(container_ordinal)
                        .map_err(|_| V2FormatError::InvalidIndexRun)?;
                    let container = stream_containers
                        .get(index)
                        .cloned()
                        .ok_or(V2FormatError::InvalidIndexRun)?;
                    (
                        IndexPayloadPointer::ExternalStream {
                            container_ordinal: 0,
                        },
                        Some(ResolvedCarrier::Stream(container)),
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
            Some(ResolvedCarrier::Stream(_)) | None => None,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let stream_containers = mutations
        .iter()
        .filter_map(|mutation| match &mutation.carrier {
            Some(ResolvedCarrier::Stream(container)) => Some(Arc::clone(container)),
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
                    IndexPayloadPointer::ExternalStream { .. },
                    Some(ResolvedCarrier::Stream(container)),
                ) => {
                    let container_ordinal = stream_containers
                        .binary_search(container)
                        .map_err(|_| V2FormatError::InvalidIndexRun)?;
                    upsert.payload = IndexPayloadPointer::ExternalStream {
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
        sequence,
        self_pack: None,
        self_stream: None,
        containers: pack_containers
            .into_iter()
            .map(|container| container.as_ref().clone())
            .collect(),
        stream_containers: stream_containers
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
    use rs3_index::PayloadHeaderReference;
    use rs3_index::run::{
        IndexPackRecordPointer, IndexRunKeyringRef, IndexRunSelfPack, IndexRunSelfStream,
        IndexTombstone, IndexUpsert,
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

    fn plan_with_attempt_count(
        sources: Vec<PackedCompactionSourceRun>,
        limits: &IndexRunLimits,
    ) -> (V2Result<Vec<IndexRun>>, usize) {
        let counter = EncodeAttemptCounter::default();
        let result = plan_packed_run_compaction_counted(sources, limits, &counter);
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
            content_key_id: key_id("content-key"),
            pack_record_count: 4,
        }
    }

    fn stream_header() -> PayloadHeaderReference {
        PayloadHeaderReference {
            chunk_size: 64 * 1024,
            plaintext_len: 32,
            key_id: key_id("stream-content-key"),
            nonce_prefix: [0x51; 16],
            header_len: 73,
        }
    }

    fn stream_container(byte: u8) -> IndexRunStreamContainer {
        let payload_header = stream_header();
        let payload_section_len = payload_header.header_len + payload_header.plaintext_len + 16;
        IndexRunStreamContainer {
            object_id: object_id(&format!("commits/v02/stream-{byte}")),
            version_id: Some(must(BackendVersionId::new(format!("version-{byte}")))),
            stored_len: 16 * 1024,
            commit_body_digest: [byte; 32],
            keyring_envelope: IndexRunKeyringRef {
                object_id: object_id(&format!("keys/stream-{byte}")),
                digest: [byte.wrapping_add(1); 32],
            },
            sections_start: 8 * 1024,
            payload_section_ordinal: 0,
            payload_section_offset: 0,
            payload_section_len,
            payload_section_digest: [byte.wrapping_add(2); 32],
            payload_id: object_id(&format!("payloads/stream-{byte}")),
            payload_header,
        }
    }

    fn record(ordinal: u32, byte: u8) -> IndexPackRecordPointer {
        IndexPackRecordPointer {
            record_ordinal: ordinal,
            physical_offset: ordinal * 64,
            plaintext_digest: [byte; 32],
        }
    }

    fn upsert(
        ordinal: u32,
        blind_key: IndexBlindKey,
        generation: u64,
        payload: IndexPayloadPointer,
    ) -> IndexMutation {
        IndexMutation::Upsert(IndexUpsert {
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
            sequence: sequence(sequence_value),
            self_pack: None,
            self_stream: None,
            containers: Vec::new(),
            stream_containers: Vec::new(),
            mutations,
        }
    }

    fn source(run: IndexRun) -> PackedCompactionSourceRun {
        PackedCompactionSourceRun {
            run,
            self_pack_container: None,
            self_stream_container: None,
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
                sequence: sequence(sequence_value),
                self_pack: None,
                self_stream: None,
                containers: vec![container(container_byte)],
                stream_containers: Vec::new(),
                mutations: vec![upsert(
                    0,
                    blind_key,
                    generation,
                    IndexPayloadPointer::ExternalPack {
                        container_ordinal: 0,
                        record: record(0, container_byte),
                    },
                )],
            },
            self_pack_container: None,
            self_stream_container: None,
        }
    }

    fn external_stream_source(
        sequence_value: u64,
        blind_key: IndexBlindKey,
        generation: u64,
        exact_container: IndexRunStreamContainer,
    ) -> PackedCompactionSourceRun {
        PackedCompactionSourceRun {
            run: IndexRun {
                sequence: sequence(sequence_value),
                self_pack: None,
                self_stream: None,
                containers: Vec::new(),
                stream_containers: vec![exact_container],
                mutations: vec![upsert(
                    0,
                    blind_key,
                    generation,
                    IndexPayloadPointer::ExternalStream {
                        container_ordinal: 0,
                    },
                )],
            },
            self_pack_container: None,
            self_stream_container: None,
        }
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
            content_key_id: exact_container.content_key_id.clone(),
            stored_len: exact_container.pack_section_len,
            record_count: exact_container.pack_record_count,
        };
        let source_with_pack = PackedCompactionSourceRun {
            run: IndexRun {
                sequence: sequence(3),
                self_pack: Some(self_pack),
                self_stream: None,
                containers: Vec::new(),
                stream_containers: Vec::new(),
                mutations: vec![upsert(
                    0,
                    key(3),
                    3,
                    IndexPayloadPointer::SelfPack {
                        record: record(2, 9),
                    },
                )],
            },
            self_pack_container: Some(exact_container.clone()),
            self_stream_container: None,
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
                record: record(2, 9),
            }
        );
    }

    #[test]
    fn self_stream_is_converted_to_its_exact_external_container() {
        let exact_container = stream_container(7);
        let source_with_stream = PackedCompactionSourceRun {
            run: IndexRun {
                sequence: sequence(3),
                self_pack: None,
                self_stream: Some(IndexRunSelfStream {
                    payload_section_ordinal: exact_container.payload_section_ordinal,
                    payload_id: exact_container.payload_id.clone(),
                    payload_header: exact_container.payload_header.clone(),
                }),
                containers: Vec::new(),
                stream_containers: Vec::new(),
                mutations: vec![upsert(0, key(3), 3, IndexPayloadPointer::SelfStream)],
            },
            self_pack_container: None,
            self_stream_container: Some(exact_container.clone()),
        };

        let planned = must(plan_packed_run_compaction(
            vec![
                source_with_stream,
                source(run(4, vec![tombstone(0, key(4), 4)])),
            ],
            &IndexRunLimits::default(),
        ));

        assert_eq!(planned.len(), 1);
        assert!(planned[0].self_pack.is_none());
        assert!(planned[0].self_stream.is_none());
        assert!(planned[0].containers.is_empty());
        assert_eq!(planned[0].stream_containers, vec![exact_container]);
        let IndexMutation::Upsert(upsert) = &planned[0].mutations[0] else {
            panic!("expected upsert");
        };
        assert_eq!(
            upsert.payload,
            IndexPayloadPointer::ExternalStream {
                container_ordinal: 0,
            }
        );
    }

    #[test]
    fn mismatched_self_stream_container_fails_closed() {
        let exact_container = stream_container(7);
        let mut mismatched = exact_container.clone();
        mismatched.payload_section_digest = [0x99; 32];
        mismatched.payload_id = object_id("payloads/different");
        let source_with_stream = PackedCompactionSourceRun {
            run: IndexRun {
                sequence: sequence(3),
                self_pack: None,
                self_stream: Some(IndexRunSelfStream {
                    payload_section_ordinal: exact_container.payload_section_ordinal,
                    payload_id: exact_container.payload_id,
                    payload_header: exact_container.payload_header,
                }),
                containers: Vec::new(),
                stream_containers: Vec::new(),
                mutations: vec![upsert(0, key(3), 3, IndexPayloadPointer::SelfStream)],
            },
            self_pack_container: None,
            self_stream_container: Some(mismatched),
        };

        assert_eq!(
            plan_packed_run_compaction(
                vec![
                    source_with_stream,
                    source(run(4, vec![tombstone(0, key(4), 4)])),
                ],
                &IndexRunLimits::default(),
            ),
            Err(V2FormatError::InvalidIndexRun)
        );
    }

    #[test]
    fn external_containers_are_deduplicated_sorted_and_reindexed() {
        let high = container(9);
        let low = container(2);
        let high_source = PackedCompactionSourceRun {
            run: IndexRun {
                sequence: sequence(4),
                self_pack: None,
                self_stream: None,
                containers: vec![high.clone()],
                stream_containers: Vec::new(),
                mutations: vec![upsert(
                    0,
                    key(1),
                    4,
                    IndexPayloadPointer::ExternalPack {
                        container_ordinal: 0,
                        record: record(0, 1),
                    },
                )],
            },
            self_pack_container: None,
            self_stream_container: None,
        };
        let low_source = PackedCompactionSourceRun {
            run: IndexRun {
                sequence: sequence(5),
                self_pack: None,
                self_stream: None,
                containers: vec![low.clone()],
                stream_containers: Vec::new(),
                mutations: vec![upsert(
                    0,
                    key(2),
                    5,
                    IndexPayloadPointer::ExternalPack {
                        container_ordinal: 0,
                        record: record(1, 2),
                    },
                )],
            },
            self_pack_container: None,
            self_stream_container: None,
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
    fn external_stream_containers_are_deduplicated_sorted_and_reindexed() {
        let high = stream_container(9);
        let low = stream_container(2);
        let planned = must(plan_packed_run_compaction(
            vec![
                external_stream_source(4, key(1), 4, high.clone()),
                external_stream_source(5, key(2), 5, low.clone()),
                external_stream_source(6, key(3), 6, high.clone()),
            ],
            &IndexRunLimits::default(),
        ));

        assert_eq!(planned.len(), 1);
        assert!(planned[0].self_pack.is_none());
        assert!(planned[0].self_stream.is_none());
        assert!(planned[0].containers.is_empty());
        assert_eq!(planned[0].stream_containers, vec![low, high]);
        let ordinals = planned[0]
            .mutations
            .iter()
            .map(|mutation| {
                let IndexMutation::Upsert(upsert) = mutation else {
                    panic!("expected upsert");
                };
                let IndexPayloadPointer::ExternalStream { container_ordinal } = upsert.payload
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
        let record = record(1, 5);
        let self_source = PackedCompactionSourceRun {
            run: IndexRun {
                sequence: sequence(6),
                self_pack: Some(IndexRunSelfPack {
                    pack_id: exact_container.pack_id,
                    content_key_id: exact_container.content_key_id.clone(),
                    stored_len: exact_container.pack_section_len,
                    record_count: exact_container.pack_record_count,
                }),
                self_stream: None,
                containers: Vec::new(),
                stream_containers: Vec::new(),
                mutations: vec![upsert(
                    0,
                    key(5),
                    6,
                    IndexPayloadPointer::SelfPack { record },
                )],
            },
            self_pack_container: Some(exact_container.clone()),
            self_stream_container: None,
        };
        let external_source = PackedCompactionSourceRun {
            run: IndexRun {
                sequence: sequence(7),
                self_pack: None,
                self_stream: None,
                containers: vec![exact_container.clone()],
                stream_containers: Vec::new(),
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
            self_stream_container: None,
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
