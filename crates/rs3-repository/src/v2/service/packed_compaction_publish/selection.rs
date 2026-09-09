//! Two bounded contiguous plans, compared by their actual catalog reduction.

use super::plan_packed_run_compaction;
use super::{IndexRun, IndexRunLimits, PackedCompactionSourceRun, V2FormatError};

// A scheduling weight, not an estimate of measured publication traffic. Charge
// one maximum-size recovery section to amortize roots over catalog reduction.
// Source bytes proxy rewrite cost. Reads still cover the original bounded
// envelope even if a subwindow wins; this does not promise fewer input reads.
const COMPACTION_PUBLICATION_COST_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Copy)]
struct CompactionCost {
    bytes: u64,
    reduction: usize,
}

impl CompactionCost {
    fn new(sizes: &[(u32, u64)], output_runs: usize) -> Option<Self> {
        let reduction = sizes.len().checked_sub(output_runs)?;
        if reduction == 0 {
            return None;
        }
        let bytes = sizes
            .iter()
            .try_fold(COMPACTION_PUBLICATION_COST_BYTES, |total, &(_, bytes)| {
                total.checked_add(bytes)
            })?;
        Some(Self { bytes, reduction })
    }

    fn cheaper_than(self, other: Self) -> bool {
        // Source bytes and count are validated before scoring. u128 products
        // keep the comparison exact without division or floating point.
        u128::from(self.bytes) * (other.reduction as u128)
            < u128::from(other.bytes) * (self.reduction as u128)
    }
}

/// Pick just one challenger inside the already bounded read envelope. Assuming
/// one output here is only a ranking heuristic: adaptive sharding and obsolete
/// upsert removal determine the actual reduction before either plan can win.
fn compaction_challenger(
    sizes: &[(u32, u64)],
) -> crate::v2::V2Result<Option<std::ops::Range<usize>>> {
    let mut best: Option<(std::ops::Range<usize>, CompactionCost)> = None;
    for start in 0..sizes.len() {
        for end in start + 2..=sizes.len() {
            if start == 0 && end == sizes.len() {
                continue;
            }
            let cost = CompactionCost::new(&sizes[start..end], 1)
                .ok_or(V2FormatError::IndexRootLimitExceeded)?;
            if best
                .as_ref()
                .is_none_or(|(_, incumbent)| cost.cheaper_than(*incumbent))
            {
                best = Some((start..end, cost));
            }
        }
    }
    Ok(best.map(|(window, _)| window))
}

pub(super) fn cost_aware_compaction_plan(
    sources: Vec<PackedCompactionSourceRun>,
    sizes: &[(u32, u64)],
    limits: &IndexRunLimits,
    namespace: &rs3_index::NamespaceIndex,
) -> crate::v2::V2Result<(std::ops::Range<usize>, Vec<IndexRun>)> {
    if sources.len() != sizes.len() || sources.len() < 2 {
        return Err(V2FormatError::InvalidIndexRoot);
    }
    let full = 0..sources.len();
    let challenger = compaction_challenger(sizes)?;
    // Clone one decoded source at a time while planning the challenger. Keep
    // only its output while consuming the full envelope below.
    let challenger_plan = challenger.map(|window| {
        let output = plan_packed_run_compaction(
            sources[window.clone()].iter().cloned(),
            limits,
            Some(namespace),
        );
        (window, output)
    });
    // A valid challenger never hides invalid input elsewhere in the envelope.
    let full_sources = sources.into_iter();
    let mut best = match plan_packed_run_compaction(full_sources, limits, Some(namespace)) {
        Ok(output) => Some((full, output)),
        Err(V2FormatError::MaintenanceBudgetExceeded) => None,
        Err(error) => return Err(error),
    };
    if let Some((challenger, output)) = challenger_plan {
        match output {
            Ok(output) => {
                let cost = CompactionCost::new(&sizes[challenger.clone()], output.len())
                    .ok_or(V2FormatError::IndexRootLimitExceeded)?;
                let cheaper = match &best {
                    Some((window, output)) => {
                        let incumbent = CompactionCost::new(&sizes[window.clone()], output.len())
                            .ok_or(V2FormatError::IndexRootLimitExceeded)?;
                        cost.cheaper_than(incumbent)
                    }
                    None => true,
                };
                if cheaper {
                    best = Some((challenger, output));
                }
            }
            Err(V2FormatError::MaintenanceBudgetExceeded) => {}
            Err(error) => return Err(error),
        }
    }
    best.ok_or(V2FormatError::MaintenanceBudgetExceeded)
}

#[cfg(test)]
#[path = "selection_tests.rs"]
mod tests;
