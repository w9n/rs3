//! White-box properties for the pure planner without widening the production API.
//!
//! Compile the same private planner source in this test crate. Staging properties
//! live beside PendingV2State because they also need private repository state.

use proptest::prelude::*;
use rs3_index::run::{
    IndexBlindKey, IndexMutation, IndexPayloadPointer, IndexRun, IndexRunLimits, IndexTombstone,
    IndexUpsert,
};
use rs3_repository::v2;
use rs3_types::{KeyId, LogicalPath, Sequence};
use std::collections::BTreeMap;

#[path = "../src/v2/service/packed_compaction.rs"]
mod packed_compaction;
use packed_compaction::{PackedCompactionSourceRun, plan_packed_run_compaction};

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn random_histories_match_newest_wins_and_keep_generation_groups_whole(
        batches in prop::collection::vec(prop::collection::btree_map(0_u8..16, any::<bool>(), 1..5), 2..24),
        shard_limit in 1_usize..9,
        reverse_sources in any::<bool>(),
    ) {
        let mut expected = BTreeMap::new();
        let mut sources = Vec::new();
        for (batch, changes) in batches.into_iter().enumerate() {
            let generation = batch as u64 + 1;
            for (key, live) in changes {
                expected.insert(key, (generation, live));
                sources.push(source(mutation(key, generation, live)));
            }
        }
        if reverse_sources {
            sources.reverse();
        }
        let source_count = sources.len();
        let limits = IndexRunLimits { max_mutations: shard_limit, ..IndexRunLimits::default() };
        let mut group_sizes = BTreeMap::new();
        for (generation, _) in expected.values() {
            *group_sizes.entry(*generation).or_insert(0_usize) += 1;
        }
        let planned = plan_packed_run_compaction(sources, &limits, None);
        if group_sizes.values().any(|count| *count > shard_limit) {
            prop_assert_eq!(planned, Err(v2::V2FormatError::IndexRunLimitExceeded));
        } else {
            // An independent capacity model: whole generations fill each shard
            // until the next group would exceed its mutation count ceiling.
            let mut shard_count = 1;
            let mut used = 0;
            for count in group_sizes.values() {
                if used + count > shard_limit {
                    shard_count += 1;
                    used = 0;
                }
                used += count;
            }
            if shard_count >= source_count {
                prop_assert_eq!(planned, Err(v2::V2FormatError::MaintenanceBudgetExceeded));
            } else {
                let runs = planned.expect("reducing bounded history should compact");
                prop_assert_eq!(runs.len(), shard_count);
                let mut actual = BTreeMap::new();
                let mut generation_shards = BTreeMap::new();
                let mut previous_max = None;
                for (shard, run) in runs.iter().enumerate() {
                    prop_assert!(!run.mutations.is_empty());
                    prop_assert!(run.mutations.len() <= shard_limit);
                    let mut minimum = u64::MAX;
                    let mut maximum = 0;
                    for (ordinal, mutation) in run.mutations.iter().enumerate() {
                        let (key, generation, live, stored_ordinal) = facts(mutation);
                        prop_assert_eq!(stored_ordinal as usize, ordinal);
                        prop_assert!(actual.insert(key, (generation, live)).is_none());
                        if let Some(prior_shard) = generation_shards.insert(generation, shard) {
                            prop_assert_eq!(prior_shard, shard, "equal generation was split");
                        }
                        minimum = minimum.min(generation);
                        maximum = maximum.max(generation);
                    }
                    prop_assert!(previous_max.is_none_or(|prior| prior < minimum));
                    prop_assert_eq!(run.sequence.get(), maximum);
                    previous_max = Some(maximum);
                }
                prop_assert_eq!(&actual, &expected);
                // Model older preserved shards containing live values. Winning
                // tombstones must mask them even after the selected runs merge.
                let mut visible = (0_u8..16).map(|key| (key, (0, true))).collect::<BTreeMap<_, _>>();
                visible.extend(actual);
                for (key, expected_value) in &expected {
                    prop_assert_eq!(visible.get(key), Some(expected_value));
                }
            }
        }
    }

    #[test]
    fn conflicting_equal_generation_is_never_resolved_by_source_order(
        key in 0_u8..16,
        generation in 1_u64..u64::MAX,
        reverse in any::<bool>(),
    ) {
        let mut sources = vec![source(mutation(key, generation, true)), source(mutation(key, generation, false))];
        if reverse { sources.reverse(); }
        prop_assert_eq!(plan_packed_run_compaction(sources, &IndexRunLimits::default(), None),
            Err(v2::V2FormatError::InvalidIndexRun));
    }
}

fn mutation(key: u8, generation: u64, live: bool) -> IndexMutation {
    let blind_key = IndexBlindKey::from_bytes([key; 32]);
    let namespace_key_id = KeyId::new("namespace").expect("namespace key");
    let path = LogicalPath::new(format!("objects/key-{key:02}")).expect("logical path");
    let generation = Sequence::new(generation);
    if live {
        IndexMutation::Upsert(IndexUpsert {
            checksum: None,
            mutation_ordinal: 0,
            blind_key,
            namespace_key_id,
            path,
            generation,
            payload: IndexPayloadPointer::Empty,
            content_len: 0,
            modified_at_ms: 1,
            retention: None,
            legal_hold: None,
        })
    } else {
        IndexMutation::Tombstone(IndexTombstone {
            mutation_ordinal: 0,
            blind_key,
            namespace_key_id,
            path,
            generation,
        })
    }
}

fn source(mutation: IndexMutation) -> PackedCompactionSourceRun {
    let (_, generation, _, _) = facts(&mutation);
    PackedCompactionSourceRun {
        run: IndexRun {
            completion_receipt: None,
            sequence: Sequence::new(generation),
            self_pack: None,

            containers: Vec::new(),

            standalone_stream_containers: Vec::new(),
            mutations: vec![mutation],
        },
        self_pack_container: None,
    }
}

fn facts(mutation: &IndexMutation) -> (u8, u64, bool, u32) {
    match mutation {
        IndexMutation::Upsert(value) => (
            value.blind_key.as_bytes()[0],
            value.generation.get(),
            true,
            value.mutation_ordinal,
        ),
        IndexMutation::Tombstone(value) => (
            value.blind_key.as_bytes()[0],
            value.generation.get(),
            false,
            value.mutation_ordinal,
        ),
    }
}
