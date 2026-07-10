//! v2 full-maintenance dry-run and compaction snapshot orchestration.

use super::super::commit::{V2_SECTION_FLAG_MUST_UNDERSTAND, V2CommitKey};
use super::super::error::V2FormatError;
use super::super::repository::{
    V2CommitAnchor, V2CommitSection, V2CommitWrite, V2MemoryAnchor, V2ReplayChain, V2StoredCommit,
};
use super::super::{
    V2FullGcDryRunOptions, V2FullGcDryRunReport, V2MaintenanceGuard, V2ProviderProfile,
    V2SectionType,
};
use super::{
    PendingV2CommitSections, PendingV2PayloadLocation, V2CommitHeaderCacheKey, V2Repository,
    commit_protection_for_deltas, ensure_payload_section_declared_in_header,
    payload_header_from_reference, payload_header_reference, v2_repository_error,
};
use crate::checkpoint::{seal_index_delta_object, seal_manifest_record};
use crate::error::{RepositoryError, Result};
use crate::payload::{parse_segmented_payload_header, total_segmented_payload_len};
use crate::state::TrustedManifest;
use bytes::Bytes;
use rs3_index::{
    IndexDelta, IndexDeltaObject, NamespaceEntry, PayloadHeaderReference, PayloadReference,
    index_delta_object_bytes,
};
use rs3_storage::{BlobStore, ByteRange};
use rs3_types::{BackendObjectId, BackendVersionId, LogicalPath, PrefixToken, Sequence};
use std::collections::BTreeSet;

struct V2CompactionSnapshotPlan {
    sequence: Sequence,
    payloads: Vec<V2CompactionPayload>,
    verification: Vec<V2CompactionVerification>,
}

struct V2CompactionPayload {
    entry: NamespaceEntry,
    prefix_tokens: Vec<PrefixToken>,
    manifest: TrustedManifest,
    payload_id: BackendObjectId,
    payload_header: PayloadHeaderReference,
    payload: Bytes,
}

struct V2CompactionVerification {
    key: LogicalPath,
    plaintext: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct V2LivePayloadSectionKey {
    commit_key: BackendObjectId,
    commit_version_id: Option<BackendVersionId>,
    body_digest: [u8; 32],
    offset: u64,
    length: u64,
}

impl<S> V2Repository<S>
where
    S: BlobStore + Clone,
{
    /// Builds a path-redacted full-maintenance dry-run plan from current
    /// trusted namespace state.
    pub async fn full_gc_dry_run<A>(
        &self,
        anchor: &A,
        options: V2FullGcDryRunOptions,
    ) -> Result<V2FullGcDryRunReport>
    where
        A: V2CommitAnchor,
    {
        let mut report = self
            .commit_store
            .full_gc_dry_run(anchor, options.clone())
            .await
            .map_err(v2_repository_error)?;
        let Some(chain) = self
            .commit_store
            .load_replay_chain_from_anchor(anchor)
            .await
            .map_err(v2_repository_error)?
        else {
            return Ok(report);
        };
        let state = self.replay_bounded_chain_to_state(&chain).await?;
        let (mixed_count, live_bytes_to_copy, mixed_dead_bytes_repackable) =
            self.current_head_mixed_payload_summary(&state, &chain)?;
        report.mixed_commit_count = mixed_count;
        report.live_bytes_to_copy = live_bytes_to_copy;
        report.mixed_dead_bytes_repackable = mixed_dead_bytes_repackable;
        if live_bytes_to_copy > 0 {
            report.planned_cost.request_count = report.planned_cost.request_count.saturating_add(1);
            report.planned_cost.write_bytes = report
                .planned_cost
                .write_bytes
                .saturating_add(live_bytes_to_copy);
            report.fits_budgets = report.planned_cost.fits_budgets(options.budgets);
        }
        Ok(report)
    }

    /// Writes a guarded compaction snapshot that copies current live payload
    /// sections into the new snapshot commit.
    ///
    /// The compaction commit is first written against a temporary anchor and
    /// verified through a fresh reader. The real anchor is advanced only after
    /// that verification passes and the maintenance guard still owns the base
    /// anchor. Old source commits are left for the existing exact-version orphan
    /// GC path, which still applies retention and legal-hold checks.
    pub async fn write_compaction_snapshot<A, G>(
        &self,
        anchor: &A,
        guard: &G,
        options: V2FullGcDryRunOptions,
        retained_provider_conformance_passed: bool,
    ) -> Result<V2StoredCommit>
    where
        A: V2CommitAnchor,
        G: V2MaintenanceGuard,
    {
        let _guard = self.mutation_lock.lock().await;
        if self.pending_index_delta_sequence()?.is_some() {
            return Err(RepositoryError::CommitFailed {
                reason: "v2 compaction requires no pending index delta".to_owned(),
            });
        }

        guard
            .verify_v2_maintenance(None)
            .await
            .map_err(v2_repository_error)?;
        let base_anchor = anchor.read_v2().await.map_err(v2_repository_error)?;
        let Some(base_anchor) = base_anchor else {
            return Err(v2_repository_error(V2FormatError::MissingAnchor));
        };
        guard
            .verify_v2_maintenance(Some(&base_anchor))
            .await
            .map_err(v2_repository_error)?;

        if self.commit_store.provider_profile() == V2ProviderProfile::RetainedVersionObjectLock
            && !retained_provider_conformance_passed
        {
            return Err(v2_repository_error(V2FormatError::ProviderProfileFailed));
        }

        let dry_run = self.full_gc_dry_run(anchor, options).await?;
        if dry_run.mixed_commit_count == 0 {
            return Err(RepositoryError::CommitFailed {
                reason: "v2 compaction found no mixed commits".to_owned(),
            });
        }
        if !dry_run.fits_budgets {
            return Err(v2_repository_error(
                V2FormatError::MaintenanceBudgetExceeded,
            ));
        }

        let plan = self.compaction_snapshot_plan().await?;
        let temporary_anchor = V2MemoryAnchor::with_state(base_anchor.clone());
        let mut accepted_locations = None;
        let uploaded = self
            .commit_store
            .write_child_commit_with(&temporary_anchor, |commit_key| {
                let pending = self
                    .compaction_snapshot_sections(commit_key, &plan)
                    .map_err(|_| V2FormatError::InvalidHeaderField)?;
                accepted_locations = Some(pending.locations);
                let mut write =
                    V2CommitWrite::snapshot(pending.sections).with_retention(pending.retention);
                write = write.with_legal_hold(pending.legal_hold);
                Ok(write)
            })
            .await
            .map_err(v2_repository_error)?;

        self.verify_compaction_snapshot_with_fresh_reader(&temporary_anchor, &plan)
            .await?;

        guard
            .verify_v2_maintenance(Some(&base_anchor))
            .await
            .map_err(v2_repository_error)?;
        if anchor.read_v2().await.map_err(v2_repository_error)? != Some(base_anchor) {
            return Err(v2_repository_error(V2FormatError::StaleAnchor));
        }

        let adopted = self
            .commit_store
            .adopt_unanchored_child(
                anchor,
                &uploaded.commit_key.object_id,
                uploaded.version_id.as_ref(),
            )
            .await
            .map_err(v2_repository_error)?;
        let locations = accepted_locations
            .ok_or_else(|| v2_repository_error(V2FormatError::InvalidHeaderField))?;
        self.resolve_accepted_payload_refs(&adopted.anchor_state, &locations)?;
        self.accept_current_state()?;
        Ok(adopted)
    }

    fn current_head_mixed_payload_summary(
        &self,
        state: &crate::state::RepositoryState,
        chain: &V2ReplayChain,
    ) -> Result<(usize, u64, u64)> {
        let live_sections = Self::live_payload_sections_from_state(state);
        let mut mixed_commit_count = 0_usize;
        let mut live_bytes_to_copy = 0_u64;
        let mut mixed_dead_bytes_repackable = 0_u64;

        for commit in &chain.commits_newest_first {
            let mut commit_live_bytes = 0_u64;
            let mut commit_dead_bytes = 0_u64;
            let header = &commit.parsed_header.header;
            for section in &header.section_index {
                if section.section_type != V2SectionType::Payload {
                    continue;
                }
                let key = V2LivePayloadSectionKey {
                    commit_key: header.self_ref.commit_key.clone(),
                    commit_version_id: commit.version_id.clone(),
                    body_digest: header.body_digest,
                    offset: section.offset,
                    length: section.length,
                };
                if live_sections.contains(&key) {
                    commit_live_bytes = commit_live_bytes.saturating_add(section.length);
                    live_bytes_to_copy = live_bytes_to_copy.saturating_add(section.length);
                } else {
                    commit_dead_bytes = commit_dead_bytes.saturating_add(section.length);
                }
            }
            if commit_live_bytes > 0 && commit_dead_bytes > 0 {
                mixed_commit_count = mixed_commit_count.saturating_add(1);
                mixed_dead_bytes_repackable =
                    mixed_dead_bytes_repackable.saturating_add(commit_dead_bytes);
            }
        }

        Ok((
            mixed_commit_count,
            live_bytes_to_copy,
            mixed_dead_bytes_repackable,
        ))
    }

    fn live_payload_sections_from_state(
        state: &crate::state::RepositoryState,
    ) -> BTreeSet<V2LivePayloadSectionKey> {
        let mut sections = BTreeSet::new();
        for (entry, _) in state.namespace.live_entries_with_prefixes() {
            let Some(PayloadReference::V2Commit {
                commit_key,
                commit_version_id,
                body_digest,
                offset,
                length,
                ..
            }) = entry.payload_ref
            else {
                continue;
            };
            sections.insert(V2LivePayloadSectionKey {
                commit_key,
                commit_version_id,
                body_digest,
                offset,
                length,
            });
        }
        sections
    }

    async fn compaction_snapshot_plan(&self) -> Result<V2CompactionSnapshotPlan> {
        let entries = {
            let state = self
                .accepted_state
                .read()
                .map_err(|_| RepositoryError::StatePoisoned)?;
            state
                .namespace
                .live_entries_with_prefixes()
                .into_iter()
                .map(|(entry, prefix_tokens)| {
                    let manifest = state
                        .manifests
                        .get(&entry.manifest_id)
                        .cloned()
                        .ok_or_else(|| RepositoryError::InvalidObjectFormat {
                            object_id: entry.object_id.clone(),
                        })?;
                    Ok((entry, prefix_tokens, manifest))
                })
                .collect::<Result<Vec<_>>>()?
        };
        let sequence = self.repository.read_state()?.next_sequence;
        let mut payloads = Vec::with_capacity(entries.len());
        let mut verification = Vec::with_capacity(entries.len());

        for (entry, prefix_tokens, manifest) in entries {
            let Some(PayloadReference::V2Commit {
                commit_key,
                commit_version_id,
                body_digest,
                payload_id,
                payload_header,
                sections_start,
                offset,
                length,
            }) = entry.payload_ref.clone()
            else {
                return Err(RepositoryError::InvalidObjectFormat {
                    object_id: entry.object_id,
                });
            };
            let sections_start = match sections_start {
                Some(sections_start) => sections_start,
                None => {
                    let header_key = V2CommitHeaderCacheKey {
                        commit_key: commit_key.clone(),
                        commit_version_id: commit_version_id.clone(),
                        body_digest,
                    };
                    let header = self.read_commit_header_for_payload(&header_key).await?;
                    ensure_payload_section_declared_in_header(&header, offset, length)?;
                    u64::try_from(header.sections_start)
                        .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?
                }
            };
            let payload_start = sections_start
                .checked_add(offset)
                .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))?;
            let payload = self
                .commit_store
                .read_commit_range_at(
                    &commit_key,
                    commit_version_id.as_ref(),
                    ByteRange::Slice {
                        offset: payload_start,
                        len: length,
                    },
                )
                .await
                .map_err(v2_repository_error)?;
            let payload_header = match payload_header {
                Some(reference) => reference,
                None => payload_header_reference(&parse_segmented_payload_header(
                    &payload_id,
                    &payload,
                )?)?,
            };
            let parsed_header = payload_header_from_reference(&payload_header)?;
            if parsed_header.plaintext_len != entry.content_len
                || total_segmented_payload_len(&parsed_header)? != length
            {
                return Err(RepositoryError::InvalidObjectFormat {
                    object_id: payload_id,
                });
            }
            let plaintext = self.get_range(&manifest.key, ByteRange::Full).await?;
            verification.push(V2CompactionVerification {
                key: manifest.key.clone(),
                plaintext,
            });
            payloads.push(V2CompactionPayload {
                entry,
                prefix_tokens,
                manifest,
                payload_id,
                payload_header,
                payload,
            });
        }

        Ok(V2CompactionSnapshotPlan {
            sequence,
            payloads,
            verification,
        })
    }

    fn compaction_snapshot_sections(
        &self,
        commit_key: &V2CommitKey,
        plan: &V2CompactionSnapshotPlan,
    ) -> Result<PendingV2CommitSections> {
        let keyring = self.repository.keyring()?;
        let mut sections = Vec::with_capacity(plan.payloads.len().saturating_add(1));
        let mut locations = Vec::with_capacity(plan.payloads.len());
        let mut deltas = Vec::with_capacity(plan.payloads.len());
        let mut next_offset = 0_u64;

        for payload in &plan.payloads {
            let length = u64::try_from(payload.payload.len())
                .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?;
            sections.push(V2CommitSection::new(
                V2SectionType::Payload,
                V2_SECTION_FLAG_MUST_UNDERSTAND,
                payload.payload.clone(),
            ));
            let location = PendingV2PayloadLocation {
                manifest_id: payload.entry.manifest_id.clone(),
                payload_id: payload.payload_id.clone(),
                payload_header: payload.payload_header.clone(),
                sections_start: Self::sections_start_for_upload_mode(self.commit_upload_mode),
                offset: next_offset,
                length,
            };
            let mut entry = payload.entry.clone();
            entry.object_id = commit_key.object_id.clone();
            entry.object_version_id = None;
            entry.payload_ref = Some(PayloadReference::V2Self {
                payload_id: location.payload_id.clone(),
                payload_header: Some(location.payload_header.clone()),
                sections_start: location.sections_start,
                offset: location.offset,
                length: location.length,
            });
            let sealed_manifest =
                seal_manifest_record(&keyring, &entry.manifest_id, &payload.manifest)?;
            deltas.push(IndexDelta::Upsert {
                entry: Box::new(entry),
                prefix_tokens: payload.prefix_tokens.clone(),
                sealed_manifest: Box::new(sealed_manifest),
            });
            locations.push(location);
            next_offset = next_offset
                .checked_add(length)
                .ok_or_else(|| v2_repository_error(V2FormatError::SectionBounds))?;
        }

        let snapshot = IndexDeltaObject {
            sequence: plan.sequence,
            deltas,
        };
        let (retention, legal_hold) = commit_protection_for_deltas(&snapshot.deltas);
        let sealed_snapshot = seal_index_delta_object(&keyring, &snapshot)?;
        let bytes = Bytes::from(index_delta_object_bytes(&sealed_snapshot)?);
        sections.push(V2CommitSection::new(
            V2SectionType::IndexSnapshot,
            V2_SECTION_FLAG_MUST_UNDERSTAND,
            bytes,
        ));

        Ok(PendingV2CommitSections {
            sections,
            locations,
            retention,
            legal_hold,
        })
    }

    async fn verify_compaction_snapshot_with_fresh_reader<A>(
        &self,
        anchor: &A,
        plan: &V2CompactionSnapshotPlan,
    ) -> Result<()>
    where
        A: V2CommitAnchor,
    {
        let fresh = V2Repository::new(
            self.commit_store.store().clone(),
            self.repository.keyring()?.as_ref().clone(),
            self.repository.options,
            self.commit_store.options().clone(),
        );
        fresh.load_chain_from_anchor(anchor).await?;
        for check in &plan.verification {
            let restored = fresh.get_range(&check.key, ByteRange::Full).await?;
            if restored != check.plaintext {
                return Err(v2_repository_error(V2FormatError::ObjectLengthMismatch));
            }
        }
        Ok(())
    }
}
