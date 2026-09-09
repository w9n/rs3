//! Recovery decoding is separate from namespace replay and never creates authority.

use super::history::{RecoveryPage, RecoveryPageLocation, RecoveryPageRef, RecoverySection};
use super::publication::AcceptedRecoveryState;
use super::section;
use crate::v2::repository::{
    V2AnchorState, V2CommitStore, V2PublicationPlan, V2ReplayChain, V2ReplayCommit, V2StoredCommit,
};
use crate::v2::{V2CommitKind, V2FormatError, V2Result, V2SectionType};
use rs3_storage::BlobStore;
use std::sync::Arc;

pub(in crate::v2) struct AuthenticatedRecoverySection {
    pub ordinal: u32,
    pub kind: V2CommitKind,
    pub section: RecoverySection,
    pub header: crate::v2::commit::V2ParsedCommitHeader,
}

impl<S: BlobStore> V2CommitStore<S> {
    /// Authenticates stored history using the writer's known header span. The
    /// unrelated index and payload sections are not read by this history check.
    pub(in crate::v2) async fn read_published_recovery(
        &self,
        uploaded: &V2StoredCommit,
        plan: &V2PublicationPlan,
    ) -> V2Result<AuthenticatedRecoverySection> {
        if uploaded.sections_start > crate::v2::commit::V2_MAX_HEADER_SIZE as u64
            || uploaded.sections_start > uploaded.object_len
        {
            return Err(V2FormatError::HeaderTooLarge);
        }
        let bytes = self
            .read_commit_range_at(
                &uploaded.anchor_state.commit_key,
                uploaded.version_id.as_ref(),
                rs3_storage::ByteRange::Slice {
                    offset: 0,
                    len: uploaded.sections_start,
                },
            )
            .await?;
        if bytes.len() as u64 != uploaded.sections_start {
            return Err(V2FormatError::TruncatedBody);
        }
        let parsed = crate::v2::commit::parse_v2_commit_header(
            &uploaded.anchor_state.commit_key,
            &bytes,
            self.keyring(),
        )?;
        let header = &parsed.header;
        if parsed.sections_start as u64 != uploaded.sections_start
            || header.self_ref.sequence != uploaded.anchor_state.sequence
            || header.body_digest != uploaded.anchor_state.body_digest
            || header.signing_key_id != uploaded.anchor_state.signing_key_id
            || header.publish_time_ms != uploaded.publish_time_ms
            || header.publish_time_ms != plan.publish_time_ms
            || header.keyring_envelope_ref != self.options().keyring_envelope_ref
            || header.parent.as_ref().is_none_or(|parent| {
                parent.commit_key != plan.parent.commit_key
                    || parent.sequence != plan.parent.sequence
                    || parent.body_digest != plan.parent.body_digest
                    || parent.version_id != plan.parent.version_id
            })
        {
            return Err(V2FormatError::InvalidRecoveryHistory);
        }
        crate::v2::commit::validate_v2_commit_object_len(&parsed, uploaded.object_len)?;
        let ordinal = header
            .section_index
            .iter()
            .position(|descriptor| descriptor.section_type == V2SectionType::Recovery)
            .ok_or(V2FormatError::InvalidRecoveryHistory)?;
        let descriptor = &header.section_index[ordinal];
        if descriptor.length > section::MAX_RECOVERY_SECTION_BYTES as u64 {
            return Err(V2FormatError::RecoveryHistoryCapacity);
        }
        let offset = uploaded
            .sections_start
            .checked_add(descriptor.offset)
            .ok_or(V2FormatError::SectionBounds)?;
        let bytes = self
            .read_commit_range_at(
                &uploaded.anchor_state.commit_key,
                uploaded.version_id.as_ref(),
                rs3_storage::ByteRange::Slice {
                    offset,
                    len: descriptor.length,
                },
            )
            .await?;
        if bytes.len() as u64 != descriptor.length
            || crate::v2::digest_v2_section(&bytes) != descriptor.digest
        {
            return Err(V2FormatError::InvalidRecoveryHistory);
        }
        let kind = header.kind;
        let mut retained_sections = vec![None; header.section_index.len()];
        retained_sections[ordinal] = Some(bytes);
        let commit = V2ReplayCommit {
            parsed_header: parsed,
            version_id: uploaded.version_id.clone(),
            object_len: uploaded.object_len,
            retained_sections,
        };
        let (ordinal, section) = self
            .decode_recovery_section(&commit)?
            .ok_or(V2FormatError::InvalidRecoveryHistory)?;
        Ok(AuthenticatedRecoverySection {
            ordinal,
            kind,
            section,
            header: commit.parsed_header,
        })
    }

    /// Reads one exact page carrier without activating its old snapshot or
    /// replaying its namespace. Only the signed header and Recovery bytes are read.
    pub(in crate::v2) async fn read_recovery_page(
        &self,
        reference: &RecoveryPageRef,
    ) -> V2Result<RecoveryPage> {
        let RecoveryPageLocation::Exact {
            anchor,
            section_ordinal,
            ..
        } = &reference.location
        else {
            return Err(V2FormatError::InvalidRecoveryHistory);
        };
        let commit = self
            .read_commit_facts_at(&anchor.commit_key, anchor.version_id.as_ref())
            .await?;
        let bytes = self
            .read_metadata_section(&commit, *section_ordinal, u64::MAX)
            .await?;
        self.decode_recovery_page(reference, &commit, bytes)
    }

    /// Decodes only the referenced page; its old registry never becomes authority.
    pub(in crate::v2) fn decode_recovery_page(
        &self,
        reference: &RecoveryPageRef,
        facts: &V2ReplayCommit,
        bytes: bytes::Bytes,
    ) -> V2Result<RecoveryPage> {
        let RecoveryPageLocation::Exact {
            anchor,
            section_ordinal,
            page_index,
        } = &reference.location
        else {
            return Err(V2FormatError::InvalidRecoveryHistory);
        };
        let header = &facts.parsed_header.header;
        if facts.version_id != anchor.version_id
            || header.self_ref.commit_key != anchor.commit_key
            || header.self_ref.sequence != anchor.sequence
            || header.body_digest != anchor.body_digest
            || header.signing_key_id != anchor.signing_key_id
        {
            return Err(V2FormatError::InvalidRecoveryHistory);
        }
        let ordinal = *section_ordinal as usize;
        if header
            .section_index
            .get(ordinal)
            .is_none_or(|section| section.section_type != V2SectionType::Recovery)
        {
            return Err(V2FormatError::InvalidRecoveryHistory);
        }
        let mut commit = facts.header_facts();
        commit.retained_sections[ordinal] = Some(bytes);
        let (_, history) = self
            .decode_recovery_section(&commit)?
            .ok_or(V2FormatError::InvalidRecoveryHistory)?;
        let page = history.page(*page_index)?;
        reference.verify_page(page)?;
        Ok(page.clone())
    }

    pub(in crate::v2) fn decode_recovery_section(
        &self,
        commit: &V2ReplayCommit,
    ) -> V2Result<Option<(u32, RecoverySection)>> {
        let header = &commit.parsed_header.header;
        let Some(index) = header
            .section_index
            .iter()
            .position(|section| section.section_type == V2SectionType::Recovery)
        else {
            return Ok(None);
        };
        let ordinal = u32::try_from(index).map_err(|_| V2FormatError::InvalidRecoveryHistory)?;
        let bytes = commit
            .retained_sections
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(V2FormatError::InvalidRecoveryHistory)?;
        let context = crate::v2::service::packed::repository_context_from_refs(
            &self.options().repository_id,
            &header.keyring_envelope_ref,
        )
        .map_err(|_| V2FormatError::InvalidRecoveryHistory)?;
        let plaintext = section::open(
            self.keyring(),
            &context,
            &header.self_ref.commit_key,
            ordinal,
            bytes,
        )?;
        Ok(Some((ordinal, RecoverySection::decode(&plaintext)?)))
    }

    /// Replays authenticated accepted transitions, preserving the policy stored
    /// at each point. A root cut validates its signed predecessor binding without
    /// fetching the possibly reclaimed predecessor carrier.
    pub(in crate::v2) fn replay_recovery_history(
        &self,
        chain: &V2ReplayChain,
    ) -> V2Result<Option<AcceptedRecoveryState>> {
        let mut accepted: Option<AcceptedRecoveryState> = None;
        let mut previous: Option<(V2AnchorState, i64)> = None;
        for commit in chain.commits_newest_first.iter().rev() {
            let header = &commit.parsed_header.header;
            let anchor = V2AnchorState {
                sequence: header.self_ref.sequence,
                commit_key: header.self_ref.commit_key.clone(),
                body_digest: header.body_digest,
                version_id: commit.version_id.clone(),
                signing_key_id: header.signing_key_id.clone(),
                format_ref: self.options().format_ref.clone(),
            };
            let decoded = self.decode_recovery_section(commit)?;
            match (decoded, accepted.as_ref(), previous.as_ref()) {
                (None, None, _) if self.options().recovery_policy.is_none() => {}
                (Some((ordinal, section)), None, None) => {
                    section.validate_for_header(
                        header.parent.as_ref(),
                        header.publish_time_ms,
                        header.kind == V2CommitKind::Root,
                    )?;
                    let snapshot = section
                        .normalized_snapshot(&anchor, ordinal)?
                        .ok_or(V2FormatError::InvalidRecoveryHistory)?;
                    accepted = Some(AcceptedRecoveryState {
                        policy: section.current_policy,
                        snapshot: Arc::new(snapshot),
                    });
                }
                (Some((ordinal, section)), Some(state), Some((parent, time))) => {
                    section.validate_for_commit(
                        Some((parent, *time, &state.policy)),
                        header.publish_time_ms,
                        header.kind == V2CommitKind::Root,
                        section
                            .delta
                            .expire_before_ms
                            .unwrap_or(state.snapshot.expire_before_ms),
                    )?;
                    let snapshot = section.apply_delta(&state.snapshot, &anchor, ordinal)?;
                    accepted = Some(AcceptedRecoveryState {
                        policy: section.current_policy,
                        snapshot: Arc::new(snapshot),
                    });
                }
                _ => return Err(V2FormatError::InvalidRecoveryHistory),
            }
            previous = Some((anchor, header.publish_time_ms));
        }
        Ok(accepted)
    }
}
