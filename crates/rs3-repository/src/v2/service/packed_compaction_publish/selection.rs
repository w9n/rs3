//! Fetch a catalog-ranked window first, with one bounded cached fallback.

use super::{IndexRun, PackedCompactionSourceRun, V2FormatError, v2_repository_error};
use crate::error::{RepositoryError, Result};
use std::future::Future;
use std::ops::Range;

// A scheduling weight, not an estimate of measured publication traffic. Charge
// one maximum-size recovery section to amortize roots over catalog reduction.
// Source bytes proxy read/rewrite cost. Only the chosen window is fetched
// unless actual sharding or nonreduction requires the bounded fallback.
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

/// Fetch the better catalog estimate first. Only nonreduction or unexpectedly
/// expensive actual sharding triggers the other bounded candidate. Estimates
/// rank work; the encoder's output count alone proves catalog reduction.
pub(super) async fn cost_aware_compaction_plan<Load, Loaded, Plan>(
    sizes: &[(u32, u64)],
    mut load: Load,
    mut plan: Plan,
) -> Result<(Range<usize>, Vec<IndexRun>)>
where
    Load: FnMut(Range<usize>) -> Loaded,
    Loaded: Future<Output = Result<Vec<PackedCompactionSourceRun>>>,
    Plan: FnMut(
        &mut dyn ExactSizeIterator<Item = PackedCompactionSourceRun>,
    ) -> Result<crate::v2::V2Result<Vec<IndexRun>>>,
{
    let full = 0..sizes.len();
    if sizes.len() < 2 || super::compaction_window(sizes).map_err(v2_repository_error)? != full {
        return Err(v2_repository_error(V2FormatError::InvalidIndexRoot));
    }
    let cost = |window: Range<usize>, outputs| {
        CompactionCost::new(&sizes[window], outputs)
            .ok_or_else(|| v2_repository_error(V2FormatError::IndexRootLimitExceeded))
    };
    let mut primary = full.clone();
    let mut secondary = compaction_challenger(sizes).map_err(v2_repository_error)?;
    if let Some(challenger) = &secondary
        && cost(challenger.clone(), 1)?.cheaper_than(cost(full.clone(), 1)?)
    {
        primary = challenger.clone();
        secondary = Some(full.clone());
    }
    let sources = load(primary.clone()).await?;
    if sources.len() != primary.len() {
        return Err(v2_repository_error(V2FormatError::InvalidIndexRoot));
    }
    let mut primary_output = reducing_output(plan(&mut sources.iter().cloned())?)?;
    if let Some(output) = primary_output.take() {
        let actual = cost(primary.clone(), output.len())?;
        let worthwhile = match &secondary {
            Some(window) => cost(window.clone(), 1)?.cheaper_than(actual),
            None => false,
        };
        if !worthwhile {
            return Ok((primary, output));
        }
        primary_output = Some(output);
    }
    let Some(secondary) = secondary else {
        return Err(RepositoryError::MaintenanceNotBeneficial);
    };

    let secondary_output = if primary == full {
        // The alternative is already in the fetched envelope: no new GETs.
        reducing_output(plan(&mut sources[secondary.clone()].iter().cloned())?)?
    } else {
        // Fetch only the missing prefix and suffix. The disjoint union stays
        // within the original 128-run/16MiB/131072-mutation envelope.
        let mut all_sources = if primary.start == 0 {
            Vec::with_capacity(sizes.len())
        } else {
            let prefix = load(0..primary.start).await?;
            if prefix.len() != primary.start {
                return Err(v2_repository_error(V2FormatError::InvalidIndexRoot));
            }
            prefix
        };
        all_sources.extend(sources);
        if primary.end < sizes.len() {
            let suffix = load(primary.end..sizes.len()).await?;
            if suffix.len() != sizes.len() - primary.end {
                return Err(v2_repository_error(V2FormatError::InvalidIndexRoot));
            }
            all_sources.extend(suffix);
        }
        let mut full_sources = all_sources.into_iter();
        reducing_output(plan(&mut full_sources)?)?
    };
    if let Some(output) = &secondary_output {
        cost(secondary.clone(), output.len())?;
    }
    match (primary_output, secondary_output) {
        (Some(first), Some(second)) => {
            let first_cost = cost(primary.clone(), first.len())?;
            let second_cost = cost(secondary.clone(), second.len())?;
            if first_cost.cheaper_than(second_cost)
                || (!second_cost.cheaper_than(first_cost) && primary == full)
            {
                Ok((primary, first))
            } else {
                Ok((secondary, second))
            }
        }
        (Some(output), None) => Ok((primary, output)),
        (None, Some(output)) => Ok((secondary, output)),
        (None, None) => Err(RepositoryError::MaintenanceNotBeneficial),
    }
}

fn reducing_output(output: crate::v2::V2Result<Vec<IndexRun>>) -> Result<Option<Vec<IndexRun>>> {
    match output {
        Ok(output) => Ok(Some(output)),
        Err(V2FormatError::MaintenanceBudgetExceeded) => Ok(None),
        // Selected-source corruption is fatal, never a reason to try fallback.
        Err(error) => Err(v2_repository_error(error)),
    }
}

#[cfg(test)]
#[path = "selection_tests.rs"]
mod tests;
