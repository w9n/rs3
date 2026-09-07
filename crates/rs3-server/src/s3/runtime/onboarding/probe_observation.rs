//! Read-only, bounded observations. Provider visibility never authorizes cleanup.

use super::*;
use rs3_storage::{BlobListMode, BlobStore};
use rs3_types::LegalHoldStatus;
use std::collections::BTreeSet;
use std::num::NonZeroUsize;

const MAX_PAGES: usize = 4;
const MAX_RAW_MEMBERS: usize = 128;
const MAX_HEADS: usize = 32;

pub(super) fn unavailable(attempts: u8, warning: &str) -> V2ProbeObservation {
    V2ProbeObservation {
        attempts_covered: attempts,
        observed_at_ms: current_time_ms(),
        listing_exhausted: false,
        observed_versions: 0,
        verified_metadata_versions: 0,
        observed_bytes: 0,
        retention_reported_versions: 0,
        legal_hold_on_versions: 0,
        unknown_protection_versions: 0,
        earliest_retain_until_ms: None,
        latest_retain_until_ms: None,
        multipart_sessions_observed: false,
        warning: Some(warning.to_owned()),
    }
}

fn in_scope(id: &str, attempts: u8) -> bool {
    let mut components = id.split('/');
    let (Some(attempt), Some("checks"), Some(name), None) = (
        components.next(),
        components.next(),
        components.next(),
        components.next(),
    ) else {
        return false;
    };
    attempt
        .parse::<u8>()
        .is_ok_and(|number| number > 0 && number <= attempts && number.to_string() == attempt)
        && !name.is_empty()
        && name != "."
        && name != ".."
        && name.len() <= 512
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub(super) async fn observe(store: &impl BlobStore, attempts: u8) -> V2ProbeObservation {
    let mut report = unavailable(attempts, "list-unavailable");
    let Ok(mut listing) = store.open_bounded_list("", BlobListMode::Versions).await else {
        return report;
    };
    report.warning = None;
    let mut remaining = MAX_RAW_MEMBERS;
    let mut seen = BTreeSet::new();
    let mut heads = 0;
    for _ in 0..MAX_PAGES {
        let Some(limit) = NonZeroUsize::new(remaining.min(32)) else {
            break;
        };
        let page = match listing.next_page(limit).await {
            Ok(page) => page,
            Err(_) => {
                report.warning = Some("list-unavailable".to_owned());
                return report;
            }
        };
        if page.consumed_items > limit.get() || page.entries.len() > page.consumed_items {
            report.warning = Some("invalid-inventory".to_owned());
            return report;
        }
        remaining -= page.consumed_items;
        for entry in page.entries {
            if !in_scope(entry.object_id.as_str(), attempts)
                || entry
                    .version_id
                    .as_ref()
                    .is_some_and(|id| id.as_str().len() > 1024)
            {
                report.warning = Some("invalid-inventory".to_owned());
                return report;
            }
            if !seen.insert((entry.object_id.clone(), entry.version_id.clone())) {
                continue;
            }
            report.observed_versions += 1;
            let Some(version) = entry.version_id.as_ref() else {
                report.unknown_protection_versions += 1;
                report
                    .warning
                    .get_or_insert_with(|| "exact-version-unavailable".to_owned());
                continue;
            };
            if heads == MAX_HEADS {
                report.unknown_protection_versions += 1;
                report.warning = Some("head-budget".to_owned());
                return report;
            }
            heads += 1;
            let metadata = match store.head_at(&entry.object_id, Some(version)).await {
                Ok(metadata)
                    if metadata.object_id == entry.object_id
                        && metadata.version_id.as_ref() == Some(version) =>
                {
                    metadata
                }
                _ => {
                    report.unknown_protection_versions += 1;
                    report
                        .warning
                        .get_or_insert_with(|| "exact-head-unavailable".to_owned());
                    continue;
                }
            };
            let Some(bytes) = report.observed_bytes.checked_add(metadata.content_len) else {
                report.unknown_protection_versions += 1;
                report.warning = Some("metadata-overflow".to_owned());
                return report;
            };
            report.observed_bytes = bytes;
            report.verified_metadata_versions += 1;
            let retention = metadata
                .retention
                .as_ref()
                .is_some_and(|policy| policy.mode != RetentionMode::None)
                .then_some(metadata.retain_until_ms)
                .flatten();
            if let Some(deadline) = retention {
                report.retention_reported_versions += 1;
                report.earliest_retain_until_ms = Some(
                    report
                        .earliest_retain_until_ms
                        .map_or(deadline, |old| old.min(deadline)),
                );
                report.latest_retain_until_ms = Some(
                    report
                        .latest_retain_until_ms
                        .map_or(deadline, |old| old.max(deadline)),
                );
            }
            let held = metadata.legal_hold == Some(LegalHoldStatus::On);
            if held {
                report.legal_hold_on_versions += 1;
            }
            if retention.is_none() && !held {
                report.unknown_protection_versions += 1;
            }
        }
        if page.is_complete {
            report.listing_exhausted = true;
            return report;
        }
    }
    report.warning = Some("list-budget".to_owned());
    report
}

#[cfg(test)]
mod tests;
