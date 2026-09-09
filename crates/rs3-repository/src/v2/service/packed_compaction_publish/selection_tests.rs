use super::super::plan_packed_run_compaction;
use super::*;
use rs3_index::run::IndexRunLimits;
use rs3_index::run::{IndexBlindKey, IndexMutation, IndexTombstone, IndexUpsert};
use rs3_types::{KeyId, LogicalPath, Sequence};
use std::cell::{Cell, RefCell};

fn source(sequence: u64, keys: &[u8]) -> PackedCompactionSourceRun {
    PackedCompactionSourceRun {
        run: IndexRun {
            completion_receipt: None,
            sequence: Sequence::new(sequence),
            self_pack: None,
            containers: Vec::new(),
            standalone_stream_containers: Vec::new(),
            mutations: keys
                .iter()
                .enumerate()
                .map(|(ordinal, &key)| {
                    IndexMutation::Tombstone(IndexTombstone {
                        mutation_ordinal: ordinal as u32,
                        blind_key: IndexBlindKey::from_bytes([key; 32]),
                        namespace_key_id: KeyId::new("namespace-key").expect("key"),
                        path: LogicalPath::new(format!("fixture/{key}")).expect("path"),
                        generation: Sequence::new(sequence),
                    })
                })
                .collect(),
        },
        self_pack_container: None,
    }
}

fn append_source(
    sequence: u64,
    keys: &[u8],
    namespace: &mut rs3_index::NamespaceIndex,
) -> PackedCompactionSourceRun {
    let mut source = source(sequence, keys);
    for mutation in &mut source.run.mutations {
        let IndexMutation::Tombstone(entry) = mutation else {
            panic!("fixture starts with tombstones");
        };
        namespace.upsert_without_prefixes(rs3_index::NamespaceEntry {
            namespace_key_id: entry.namespace_key_id.clone(),
            blind_key: entry.blind_key.to_blind_index_key().expect("blind key"),
            object_id: rs3_types::BackendObjectId::new("objects/fixture").expect("object"),
            object_version_id: None,
            payload_ref: None,
            manifest_id: rs3_types::ManifestId::new("fixture").expect("manifest"),
            content_len: 0,
            modified_at_ms: 1,
            generation: entry.generation,
            retention: None,
            legal_hold: None,
        });
        *mutation = IndexMutation::Upsert(IndexUpsert {
            mutation_ordinal: entry.mutation_ordinal,
            blind_key: entry.blind_key,
            namespace_key_id: entry.namespace_key_id.clone(),
            path: entry.path.clone(),
            generation: entry.generation,
            payload: rs3_index::run::IndexPayloadPointer::Empty,
            content_len: 0,
            modified_at_ms: 1,
            retention: None,
            legal_hold: None,
            etag: rs3_types::ObjectEtag::single(rs3_crypto::md5([])),
            checksum: None,
        });
    }
    source
}

async fn fixture_plan(
    sources: Vec<PackedCompactionSourceRun>,
    sizes: &[(u32, u64)],
    limits: &IndexRunLimits,
    namespace: &rs3_index::NamespaceIndex,
) -> (
    Result<(Range<usize>, Vec<IndexRun>)>,
    Vec<Range<usize>>,
    usize,
) {
    let reads = RefCell::new(Vec::new());
    let plans = Cell::new(0);
    let output = cost_aware_compaction_plan(
        sizes,
        |range| {
            reads.borrow_mut().push(range.clone());
            std::future::ready(Ok(sources[range].to_vec()))
        },
        |sources| {
            plans.set(plans.get() + 1);
            Ok(plan_packed_run_compaction(sources, limits, Some(namespace)))
        },
    )
    .await;
    (output, reads.into_inner(), plans.get())
}

#[tokio::test]
async fn append_cliff_leaves_large_older_shard_out_of_rewrite() {
    // The accepted 256-run catalog has 129 older append shards and 127 new
    // single-entry runs. The bounded read envelope includes one older shard.
    let mut catalog = vec![(128, 128 * 1024); 129];
    catalog.extend(vec![(1, 1024); 127]);
    let envelope = super::super::compaction_window(&catalog).expect("envelope");
    assert_eq!(envelope, 128..256);
    assert_eq!(
        compaction_challenger(&catalog[envelope]).expect("challenger"),
        Some(1..128)
    );
    let whole = CompactionCost::new(&catalog[128..], 1).expect("whole cost");
    let newer = CompactionCost::new(&catalog[129..], 1).expect("newer cost");
    assert!(newer.cheaper_than(whole));

    let mut namespace = rs3_index::NamespaceIndex::new();
    let mut sources = vec![append_source(
        1,
        &(0..128).collect::<Vec<_>>(),
        &mut namespace,
    )];
    sources
        .extend((128..255).map(|key| append_source(u64::from(key) - 126, &[key], &mut namespace)));
    let (result, reads, plans) = fixture_plan(
        sources,
        &catalog[128..],
        &IndexRunLimits::default(),
        &namespace,
    )
    .await;
    let (selected, output) = result.expect("append plan");
    assert_eq!(
        reads,
        std::iter::once(1..128).collect::<Vec<_>>(),
        "no fetch of the preserved older source"
    );
    assert_eq!(plans, 1);
    assert_eq!(selected, 1..128);
    assert_eq!(output.len(), 1);
    assert_eq!(output[0].mutations.len(), 127);
    assert!(
        output[0]
            .mutations
            .iter()
            .all(|entry| matches!(entry, IndexMutation::Upsert(_)))
    );
}

#[test]
fn fixed_publication_cost_amortizes_small_runs_and_ties_are_stable() {
    let small = vec![(1, 1024); 128];
    assert_eq!(
        compaction_challenger(&small).expect("candidate"),
        Some(0..127)
    );
    let whole = CompactionCost::new(&small, 1).expect("whole");
    let pair = CompactionCost::new(&small[..2], 1).expect("pair");
    assert!(whole.cheaper_than(pair));
    assert!(!whole.cheaper_than(whole));
    assert!(CompactionCost::new(&small, 128).is_none());
    assert!(CompactionCost::new(&[(1, u64::MAX)], 0).is_none());
}

#[tokio::test]
async fn actual_output_shards_override_the_one_output_ranking_heuristic() {
    let sources = vec![
        source(1, &[0, 1]),
        source(2, &[0]),
        source(3, &[1]),
        source(4, &[2]),
        source(5, &[3]),
    ];
    // Section costs deliberately isolate scheduling from fixture path length.
    // Both plans retain four distinct winning mutations, requiring two shards.
    let sizes = [
        (2, 3 * 1024 * 1024),
        (1, 1024),
        (1, 1024),
        (1, 1024),
        (1, 1024),
    ];
    assert_eq!(
        compaction_challenger(&sizes).expect("candidate"),
        Some(1..5)
    );
    let limits = IndexRunLimits {
        max_mutations: 2,
        ..IndexRunLimits::default()
    };
    let (result, reads, plans) =
        fixture_plan(sources, &sizes, &limits, &rs3_index::NamespaceIndex::new()).await;
    let (selected, output) = result.expect("plan");
    assert_eq!(
        reads,
        [1..5, 0..1],
        "fallback never refetches cached sources"
    );
    assert_eq!(plans, 2);
    // Actual reduction is three for the whole window and two for the cheaper
    // source subset, so the whole window wins despite the initial estimate.
    assert_eq!(selected, 0..5);
    assert_eq!(output.len(), 2);
    assert_eq!(
        output.iter().map(|run| run.mutations.len()).sum::<usize>(),
        4
    );
}

#[tokio::test]
async fn full_older_shards_allow_repeated_fixed_key_tombstone_churn() {
    let limits = IndexRunLimits {
        max_mutations: 32,
        ..IndexRunLimits::default()
    };
    let mut sources = vec![
        source(1, &(0..32).collect::<Vec<_>>()),
        source(2, &(32..64).collect::<Vec<_>>()),
    ];
    let mut sizes = vec![(32, 8 * 1024 * 1024); 2];
    for round in 0..100 {
        let generation = 3 + round;
        sources.push(source(generation, &[200]));
        sizes.push((1, 1024));
        if sources.len() < 4 {
            continue;
        }
        let envelope = super::super::compaction_window(&sizes).expect("bounded envelope");
        let (result, reads, plans) = fixture_plan(
            sources[envelope.clone()].to_vec(),
            &sizes[envelope.clone()],
            &limits,
            &rs3_index::NamespaceIndex::new(),
        )
        .await;
        let (selected, output) = result.expect("newer churn reduces");
        assert_eq!(
            reads,
            std::iter::once(0..3).collect::<Vec<_>>(),
            "cached second candidate adds no source reads"
        );
        assert_eq!(plans, 2);
        let selected = envelope.start + selected.start..envelope.start + selected.end;
        assert_eq!(selected, 2..4, "older full shards remain unchanged");
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].mutations.len(), 1);
        assert!(
            matches!(&output[0].mutations[0], IndexMutation::Tombstone(entry)
            if entry.generation == Sequence::new(generation))
        );
        sources.splice(
            selected.clone(),
            output.into_iter().map(|run| PackedCompactionSourceRun {
                run,
                self_pack_container: None,
            }),
        );
        sizes.splice(selected, [(1, 1024)]);
        assert_eq!(sources.len(), 3);
    }
    assert_eq!(sources[0].run.mutations.len(), 32);
    assert_eq!(sources[1].run.mutations.len(), 32);
}

#[tokio::test]
async fn unselected_source_is_not_fetched_and_selected_corruption_never_falls_back() {
    let sizes = [(1, 8 * 1024 * 1024), (1, 1024), (1, 1024), (1, 1024)];
    for bad_source in [0, 1] {
        let mut sources = vec![
            source(1, &[9]),
            source(2, &[0]),
            source(3, &[1]),
            source(4, &[2]),
        ];
        let IndexMutation::Tombstone(entry) = &mut sources[bad_source].run.mutations[0] else {
            panic!("fixture tombstone");
        };
        entry.mutation_ordinal = 1;
        let (result, reads, plans) = fixture_plan(
            sources,
            &sizes,
            &IndexRunLimits::default(),
            &rs3_index::NamespaceIndex::new(),
        )
        .await;
        assert_eq!(reads, std::iter::once(1..4).collect::<Vec<_>>());
        assert_eq!(plans, 1);
        assert_eq!(result.is_ok(), bad_source == 0);
    }
}

#[tokio::test]
async fn nonreducing_primary_expands_once_and_rejects_corrupt_fallback_input() {
    let sizes = [(1, 8 * 1024 * 1024), (2, 1024), (2, 1024), (2, 1024)];
    let limits = IndexRunLimits {
        max_mutations: 2,
        ..IndexRunLimits::default()
    };
    for corrupt in [false, true] {
        let mut namespace = rs3_index::NamespaceIndex::new();
        // The old upsert is obsolete. Three full newer shards cannot compact
        // by themselves, but adding the obsolete old run reduces the catalog.
        let mut old = append_source(1, &[9], &mut rs3_index::NamespaceIndex::new());
        if corrupt {
            let IndexMutation::Upsert(entry) = &mut old.run.mutations[0] else {
                panic!("upsert");
            };
            entry.mutation_ordinal = 1;
        }
        let sources = vec![
            old,
            append_source(2, &[0, 1], &mut namespace),
            append_source(3, &[2, 3], &mut namespace),
            append_source(4, &[4, 5], &mut namespace),
        ];
        let (result, reads, plans) = fixture_plan(sources, &sizes, &limits, &namespace).await;
        assert_eq!(reads, [1..4, 0..1]);
        assert_eq!(plans, 2);
        if corrupt {
            assert!(result.is_err());
        } else {
            let (selected, output) = result.expect("fallback removes obsolete source");
            assert_eq!(selected, 0..4);
            assert_eq!(output.len(), 3);
        }
    }
}
