//! v2 full-maintenance dry-run and compaction snapshot orchestration.

use super::super::commit::{V2_SECTION_FLAG_MUST_UNDERSTAND, V2CommitKey};
use super::super::error::V2FormatError;
use super::super::repository::{
    V2CommitAnchor, V2CommitSection, V2CommitWrite, V2MemoryAnchor, V2ReplayChain, V2StoredCommit,
};
use super::super::{
    V2_PAYLOAD_PACK_SEGMENT_BYTES, V2FullGcDryRunOptions, V2FullGcDryRunReport, V2MaintenanceGuard,
    V2ProviderProfile, V2SectionType, digest_v2_section,
};
use super::{
    PendingV2CommitSections, PendingV2PayloadLocation, V2Repository, commit_protection_for_deltas,
    payload_header_reference, v2_repository_error,
};
use crate::checkpoint::{seal_index_delta_object, seal_manifest_record};
use crate::error::{RepositoryError, Result};
use crate::payload::{parse_segmented_payload_header, seal_streamable_payload_object};
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct V2LivePayloadPackRecordKey {
    commit_key: BackendObjectId,
    commit_version_id: Option<BackendVersionId>,
    body_digest: [u8; 32],
    pack_section_ordinal: u32,
    pack_record_count: u32,
    record_ordinal: u32,
    content_len: u64,
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
        let _mutation_lease = self.claim_direct_mutation()?;
        self.write_compaction_snapshot_inner(
            anchor,
            guard,
            options,
            retained_provider_conformance_passed,
        )
        .await
    }

    async fn write_compaction_snapshot_inner<A, G>(
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
        let _publication_guard = self.publication_lock.write().await;
        if self.pending_index_delta_sequence()?.is_some() {
            return Err(RepositoryError::CommitFailed {
                reason: "v2 compaction requires no pending index delta".to_owned(),
            });
        }
        let (has_packed_payload, live_object_count, live_plaintext_bytes) = {
            let state = self
                .accepted
                .read()
                .map_err(|_| RepositoryError::StatePoisoned)?;
            state.repository.namespace.live_entries().fold(
                (false, 0_usize, 0_u64),
                |(has_pack, count, bytes), entry| {
                    (
                        has_pack
                            || matches!(entry.payload_ref, Some(PayloadReference::V2Pack { .. })),
                        count.saturating_add(1),
                        bytes.saturating_add(entry.content_len),
                    )
                },
            )
        };
        if has_packed_payload {
            return Err(RepositoryError::CommitFailed {
                reason: "packed v02 compaction requires the INDEX_ROOT checkpoint path".to_owned(),
            });
        }
        if live_object_count > 64
            || live_plaintext_bytes > super::super::V2_PAYLOAD_PACK_MAX_BYTES as u64
        {
            return Err(v2_repository_error(
                V2FormatError::MaintenanceBudgetExceeded,
            ));
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

        let compacted_state = self
            .verify_compaction_snapshot_with_fresh_reader(&temporary_anchor, &plan)
            .await?;
        accepted_locations.ok_or_else(|| v2_repository_error(V2FormatError::InvalidHeaderField))?;
        let recovered_sequence = compacted_state.next_sequence;

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
        let mut accepted = match self.accepted.write() {
            Ok(accepted) => accepted,
            Err(error) => {
                self.mark_local_recovery_required();
                tracing::error!(
                    target: "rs3_repository",
                    operation = "v2_install_legacy_compaction",
                    error = %error,
                    "v2 compaction anchor advanced but local state installation failed; restart is required",
                );
                return Err(RepositoryError::AcceptedRecoveryRequired);
            }
        };
        let mut pending = match self.pending.lock() {
            Ok(pending) => pending,
            Err(error) => {
                self.mark_local_recovery_required();
                tracing::error!(
                    target: "rs3_repository",
                    operation = "v2_install_legacy_compaction",
                    error = %error,
                    "v2 compaction anchor advanced but local staging installation failed; restart is required",
                );
                return Err(RepositoryError::AcceptedRecoveryRequired);
            }
        };
        *accepted = super::V2AcceptedState {
            repository: compacted_state,
            runs: Vec::new(),
            anchor: Some(adopted.anchor_state.clone()),
        };
        pending.reset_after_validated_publication(recovered_sequence);
        Ok(adopted)
    }

    fn current_head_mixed_payload_summary(
        &self,
        state: &crate::state::RepositoryState,
        chain: &V2ReplayChain,
    ) -> Result<(usize, u64, u64)> {
        let (live_sections, live_pack_records) = Self::live_payload_refs_from_state(state)?;
        let mut mixed_commit_count = 0_usize;
        let mut live_bytes_to_copy = 0_u64;
        let mut mixed_dead_bytes_repackable = 0_u64;

        for commit in &chain.commits_newest_first {
            let mut commit_live_bytes = 0_u64;
            let mut commit_dead_bytes = 0_u64;
            let header = &commit.parsed_header.header;
            for (section_ordinal, section) in header.section_index.iter().enumerate() {
                match section.section_type {
                    V2SectionType::Payload => {
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
                    V2SectionType::PayloadPack => {
                        let section_ordinal = u32::try_from(section_ordinal)
                            .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?;
                        let records = live_pack_records
                            .iter()
                            .filter(|record| {
                                record.commit_key == header.self_ref.commit_key
                                    && record.commit_version_id == commit.version_id
                                    && record.body_digest == header.body_digest
                                    && record.pack_section_ordinal == section_ordinal
                            })
                            .collect::<Vec<_>>();
                        let live_stored_bytes = records.iter().fold(0_u64, |total, record| {
                            let segment_count = record
                                .content_len
                                .saturating_add(V2_PAYLOAD_PACK_SEGMENT_BYTES as u64 - 1)
                                / V2_PAYLOAD_PACK_SEGMENT_BYTES as u64;
                            total.saturating_add(
                                record
                                    .content_len
                                    .saturating_add(segment_count.saturating_mul(16)),
                            )
                        });
                        let record_count =
                            records.first().map_or(0, |record| record.pack_record_count);
                        if records.iter().any(|record| {
                            record.pack_record_count != record_count
                                || record.record_ordinal >= record.pack_record_count
                        }) || u32::try_from(records.len())
                            .ok()
                            .is_some_and(|count| count > record_count)
                        {
                            return Err(v2_repository_error(V2FormatError::InvalidPayloadPack));
                        }
                        if records.is_empty() {
                            commit_dead_bytes = commit_dead_bytes.saturating_add(section.length);
                        } else if u32::try_from(records.len()).ok() == Some(record_count) {
                            commit_live_bytes = commit_live_bytes.saturating_add(section.length);
                            live_bytes_to_copy = live_bytes_to_copy.saturating_add(section.length);
                        } else {
                            commit_live_bytes = commit_live_bytes.saturating_add(live_stored_bytes);
                            live_bytes_to_copy =
                                live_bytes_to_copy.saturating_add(live_stored_bytes);
                            commit_dead_bytes = commit_dead_bytes
                                .saturating_add(section.length.saturating_sub(live_stored_bytes));
                        }
                    }
                    _ => {}
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

    fn live_payload_refs_from_state(
        state: &crate::state::RepositoryState,
    ) -> Result<(
        BTreeSet<V2LivePayloadSectionKey>,
        BTreeSet<V2LivePayloadPackRecordKey>,
    )> {
        let mut sections = BTreeSet::new();
        let mut pack_records = BTreeSet::new();
        for entry in state.namespace.live_entries() {
            match &entry.payload_ref {
                Some(PayloadReference::V2CommitStream { carrier }) => {
                    sections.insert(V2LivePayloadSectionKey {
                        commit_key: carrier.commit_key.clone(),
                        commit_version_id: carrier.commit_version_id.clone(),
                        body_digest: carrier.body_digest,
                        offset: carrier.offset,
                        length: carrier.length,
                    });
                }
                Some(PayloadReference::V2Pack { carrier, record }) => {
                    pack_records.insert(V2LivePayloadPackRecordKey {
                        commit_key: carrier.commit_key.clone(),
                        commit_version_id: carrier.commit_version_id.clone(),
                        body_digest: carrier.body_digest,
                        pack_section_ordinal: carrier.pack_section_ordinal,
                        pack_record_count: carrier.pack_record_count,
                        record_ordinal: record.record_ordinal,
                        content_len: entry.content_len,
                    });
                }
                None => {}
                Some(PayloadReference::V2Self { .. } | PayloadReference::V2PackSelf { .. }) => {
                    return Err(v2_repository_error(V2FormatError::InvalidHeaderField));
                }
                Some(PayloadReference::V2StandaloneStream { .. }) => {
                    return Err(v2_repository_error(V2FormatError::UnsupportedSection));
                }
            }
        }
        Ok((sections, pack_records))
    }

    async fn compaction_snapshot_plan(&self) -> Result<V2CompactionSnapshotPlan> {
        let entries = {
            let state = self
                .accepted
                .read()
                .map_err(|_| RepositoryError::StatePoisoned)?;
            state
                .repository
                .namespace
                .live_entries()
                .map(|entry| {
                    let prefix_tokens = state
                        .repository
                        .namespace
                        .prefix_tokens(&entry.blind_key)
                        .cloned()
                        .collect();
                    let manifest = state
                        .repository
                        .manifests
                        .get(&entry.manifest_id)
                        .cloned()
                        .ok_or_else(|| RepositoryError::InvalidObjectFormat {
                            object_id: entry.object_id.clone(),
                        })?;
                    Ok((entry.clone(), prefix_tokens, manifest))
                })
                .collect::<Result<Vec<_>>>()?
        };
        let sequence = self
            .accepted
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?
            .repository
            .next_sequence;
        let mut payloads = Vec::with_capacity(entries.len());
        let mut verification = Vec::with_capacity(entries.len());
        let keyring = self.repository.keyring()?;

        for (entry, prefix_tokens, manifest) in entries {
            let plaintext = self.get_range(&manifest.key, ByteRange::Full).await?;
            if u64::try_from(plaintext.len()).ok() != Some(entry.content_len) {
                return Err(RepositoryError::InvalidObjectFormat {
                    object_id: entry.object_id,
                });
            }
            let payload_id = BackendObjectId::new(format!(
                "v2-compaction-payload/{}",
                entry.manifest_id.as_str()
            ))?;
            let payload = seal_streamable_payload_object(
                &keyring,
                &payload_id,
                &plaintext,
                self.payload_segment_size_for_object(plaintext.len()),
            )?;
            let payload_header =
                payload_header_reference(&parse_segmented_payload_header(&payload_id, &payload)?)?;
            verification.push(V2CompactionVerification {
                key: manifest.key.clone(),
                plaintext: plaintext.clone(),
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
            let section_ordinal = u32::try_from(sections.len())
                .map_err(|_| v2_repository_error(V2FormatError::SectionBounds))?;
            let section_digest = digest_v2_section(&payload.payload);
            sections.push(V2CommitSection::new(
                V2SectionType::Payload,
                V2_SECTION_FLAG_MUST_UNDERSTAND,
                payload.payload.clone(),
            ));
            let location = PendingV2PayloadLocation {
                manifest_id: payload.entry.manifest_id.clone(),
                payload_id: payload.payload_id.clone(),
                payload_header: payload.payload_header.clone(),
                section_ordinal,
                section_digest,
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
    ) -> Result<crate::state::RepositoryState>
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
        let state = fresh
            .accepted
            .read()
            .map_err(|_| RepositoryError::StatePoisoned)?
            .repository
            .clone();
        Ok(state)
    }
}
