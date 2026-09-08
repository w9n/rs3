//! Exact genesis preparation for a trusted, unfinished bootstrap journal.

use super::*;
use crate::v2::service::packed::repository_context_from_refs;
use crate::v2::{V2IndexRoot, open_v2_index_root, seal_v2_index_root};

const JOURNAL_SCHEMA: &str = "rs3.prepared-genesis.v1";
const MAX_JOURNAL_BYTES: usize = 64 * 1024;

/// Exact signed genesis bytes prepared without backend or anchor writes.
///
/// Persist this intent in the trusted bootstrap journal before publication.
/// It is not recovery authority: after bootstrap completes, loss of the anchor
/// requires explicit recovery, even if an old copy of this intent survives.
/// Journal data must never be discovered or selected from the backing store.
#[derive(Clone)]
pub struct V2PreparedGenesis {
    record: GenesisRecord,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenesisRecord {
    schema: String,
    repository_id: RepositoryId,
    provider_profile: V2ProviderProfile,
    retention: Option<RetentionPolicy>,
    legal_hold: Option<LegalHoldStatus>,
    format_ref: V2FormatRef,
    keyring_envelope_ref: V2KeyringEnvelopeRef,
    object_id: BackendObjectId,
    body: Vec<u8>,
}

impl V2PreparedGenesis {
    /// Encodes bounded intent for storage outside the untrusted backend.
    pub fn to_journal_bytes(&self) -> V2Result<Bytes> {
        let encoded =
            serde_json::to_vec(&self.record).map_err(|_| V2FormatError::InvalidHeaderField)?;
        if encoded.len() > MAX_JOURNAL_BYTES {
            return Err(V2FormatError::ReplayBudgetExceeded);
        }
        Ok(Bytes::from(encoded))
    }
}

impl<S> V2CommitStore<S>
where
    S: BlobStore,
{
    /// Prepares one empty signed genesis using the current preview encoding.
    /// The returned bytes and identity are reused for every authorized retry.
    pub fn prepare_genesis_snapshot(&self) -> V2Result<V2PreparedGenesis> {
        self.validate_write_protection_profile(self.options.retention, self.options.legal_hold)?;
        let commit_key = generate_v2_commit_key(Sequence::new(1))?;
        let root = V2IndexRoot::new(
            Sequence::new(0),
            0,
            self.options.format_ref.clone(),
            self.options.keyring_envelope_ref.clone(),
            Vec::new(),
        )?;
        let context = repository_context_from_refs(
            &self.options.repository_id,
            &self.options.keyring_envelope_ref,
        )
        .map_err(|_| V2FormatError::InvalidHeaderField)?;
        let sealed = seal_v2_index_root(&self.keyring, &context, &commit_key.object_id, 0, &root)?;
        let mut write = V2CommitWrite::snapshot(vec![V2CommitSection::new(
            V2SectionType::IndexRoot,
            V2_SECTION_FLAG_MUST_UNDERSTAND,
            sealed.bytes().clone(),
        )]);
        if let Some(policy) = self.options.recovery_policy {
            let recovery = crate::v2::recovery::history::RecoverySection {
                current_policy: policy,
                delta: Default::default(),
                snapshot: Some(Default::default()),
                local_pages: Vec::new(),
            };
            let bytes = crate::v2::recovery::section::seal(
                &self.keyring,
                &context,
                &commit_key.object_id,
                1,
                &recovery.encode()?,
            )?;
            write.sections.push(V2CommitSection::new(
                V2SectionType::Recovery,
                V2_SECTION_FLAG_MUST_UNDERSTAND,
                bytes,
            ));
        }
        let (section_index, section_region) = build_section_region(&write.sections)?;
        let body_digest = body_digest_for_v2_sections(&section_index, &section_region)?;
        let publish_time_ms =
            super::super::recovery::choose_publish_time(self.publication_now_ms(), None)?;
        let header = self.build_header(
            &commit_key,
            None,
            &write,
            section_index,
            body_digest,
            publish_time_ms,
        )?;
        Ok(V2PreparedGenesis {
            record: GenesisRecord {
                schema: JOURNAL_SCHEMA.to_owned(),
                repository_id: self.options.repository_id.clone(),
                provider_profile: self.options.provider_profile,
                retention: self.options.retention,
                legal_hold: self.options.legal_hold,
                format_ref: self.options.format_ref.clone(),
                keyring_envelope_ref: self.options.keyring_envelope_ref.clone(),
                object_id: commit_key.object_id,
                body: header.encode_object(&section_region)?.to_vec(),
            },
        })
    }

    /// Opens bounded intent supplied by a trusted unfinished bootstrap journal.
    /// Verifies the signature, empty genesis shape and configured context.
    pub fn open_prepared_genesis(&self, encoded: &[u8]) -> V2Result<V2PreparedGenesis> {
        if encoded.len() > MAX_JOURNAL_BYTES {
            return Err(V2FormatError::ReplayBudgetExceeded);
        }
        let record =
            serde_json::from_slice(encoded).map_err(|_| V2FormatError::InvalidHeaderField)?;
        let prepared = V2PreparedGenesis { record };
        self.validate_prepared_genesis(&prepared)?;
        Ok(prepared)
    }

    fn validate_prepared_genesis(&self, prepared: &V2PreparedGenesis) -> V2Result<V2ParsedCommit> {
        let record = &prepared.record;
        if record.schema != JOURNAL_SCHEMA
            || record.repository_id != self.options.repository_id
            || record.provider_profile != self.options.provider_profile
            || record.retention != self.options.retention
            || record.legal_hold != self.options.legal_hold
            || record.format_ref != self.options.format_ref
            || record.keyring_envelope_ref != self.options.keyring_envelope_ref
            || record.body.len() > MAX_JOURNAL_BYTES
        {
            return Err(V2FormatError::InvalidHeaderField);
        }
        self.validate_write_protection_profile(record.retention, record.legal_hold)?;
        let parsed = parse_v2_commit_object(
            &record.object_id,
            Bytes::copy_from_slice(&record.body),
            &self.keyring,
        )?;
        let header = &parsed.parsed_header.header;
        if header.parent.is_some()
            || header.self_ref.sequence != Sequence::new(1)
            || header.kind != V2CommitKind::Root
            || header.keyring_envelope_ref != record.keyring_envelope_ref
            || header.section_index.len()
                != if self.options.recovery_policy.is_some() {
                    2
                } else {
                    1
                }
            || header.section_index[0].section_type != V2SectionType::IndexRoot
        {
            return Err(V2FormatError::InvalidHeaderField);
        }
        let context = repository_context_from_refs(
            &self.options.repository_id,
            &self.options.keyring_envelope_ref,
        )
        .map_err(|_| V2FormatError::InvalidHeaderField)?;
        let root = open_v2_index_root(
            &self.keyring,
            &context,
            &record.object_id,
            0,
            &record.body[parsed.parsed_header.sections_start
                ..parsed.parsed_header.sections_start
                    + usize::try_from(header.section_index[0].length)
                        .map_err(|_| V2FormatError::SectionBounds)?],
        )?;
        let expected = V2IndexRoot::new(
            Sequence::new(0),
            0,
            self.options.format_ref.clone(),
            self.options.keyring_envelope_ref.clone(),
            Vec::new(),
        )?;
        if let Some(policy) = self.options.recovery_policy {
            let descriptor = &header.section_index[1];
            if descriptor.section_type != V2SectionType::Recovery {
                return Err(V2FormatError::InvalidRecoveryHistory);
            }
            let start = parsed
                .parsed_header
                .sections_start
                .checked_add(
                    usize::try_from(descriptor.offset).map_err(|_| V2FormatError::SectionBounds)?,
                )
                .ok_or(V2FormatError::SectionBounds)?;
            let length =
                usize::try_from(descriptor.length).map_err(|_| V2FormatError::SectionBounds)?;
            let stored = record
                .body
                .get(
                    start
                        ..start
                            .checked_add(length)
                            .ok_or(V2FormatError::SectionBounds)?,
                )
                .ok_or(V2FormatError::SectionBounds)?;
            let plaintext = crate::v2::recovery::section::open(
                &self.keyring,
                &context,
                &record.object_id,
                1,
                stored,
            )?;
            let recovery = crate::v2::recovery::history::RecoverySection::decode(&plaintext)?;
            recovery.validate_for_commit(None, header.publish_time_ms, true, 0)?;
            if recovery.current_policy != policy {
                return Err(V2FormatError::InvalidRecoveryPolicy);
            }
        }
        if root != expected {
            return Err(V2FormatError::InvalidHeaderField);
        }
        Ok(parsed)
    }

    /// Publishes exactly the supplied trusted bootstrap intent.
    ///
    /// Verifies the complete stored object before fenced anchor CAS. A lost CAS
    /// reply or repeated call succeeds only for this same accepted genesis;
    /// any different or newer anchor fails without overwriting it. A caller
    /// persisting retries must also persist a bounded physical write-attempt
    /// budget and stop using the intent once bootstrap is marked complete.
    /// Set `allow_upload` only after reserving one attempt durably. With no
    /// allowance, an existing object can still be verified and anchored; a
    /// missing unaccepted object returns `BootstrapUploadRequired` without PUT.
    pub async fn publish_prepared_genesis<A>(
        &self,
        anchor: &A,
        prepared: &V2PreparedGenesis,
        allow_upload: bool,
    ) -> V2Result<V2StoredCommit>
    where
        A: V2CommitAnchor,
    {
        self.publish_prepared_genesis_inner(anchor, prepared, allow_upload, None)
            .await
    }

    /// Publishes retained recovery genesis under the caller's real writer fence.
    pub async fn publish_prepared_genesis_with_guard<A: V2CommitAnchor>(
        &self,
        anchor: &A,
        prepared: &V2PreparedGenesis,
        allow_upload: bool,
        guard: &dyn crate::v2::V2MaintenanceGuard,
    ) -> V2Result<V2StoredCommit> {
        self.publish_prepared_genesis_inner(anchor, prepared, allow_upload, Some(guard))
            .await
    }

    /// Creates retained recovery genesis under the caller's real writer fence.
    pub async fn write_genesis_snapshot_with_guard<A: V2CommitAnchor>(
        &self,
        anchor: &A,
        guard: &dyn crate::v2::V2MaintenanceGuard,
    ) -> V2Result<V2StoredCommit> {
        if anchor.read_v2().await?.is_some() {
            return Err(V2FormatError::StaleAnchor);
        }
        let prepared = self.prepare_genesis_snapshot()?;
        self.publish_prepared_genesis_with_guard(anchor, &prepared, true, guard)
            .await
    }

    async fn publish_prepared_genesis_inner<A: V2CommitAnchor>(
        &self,
        anchor: &A,
        prepared: &V2PreparedGenesis,
        allow_upload: bool,
        guard: Option<&dyn crate::v2::V2MaintenanceGuard>,
    ) -> V2Result<V2StoredCommit> {
        let parsed = self.validate_prepared_genesis(prepared)?;
        let header = &parsed.parsed_header.header;
        super::super::recovery::validate_publication_time(
            self.publication_now_ms(),
            header.publish_time_ms,
        )?;
        let record = &prepared.record;
        let current = anchor.read_v2().await?;
        if let Some(current) = current.as_ref()
            && (current.sequence != Sequence::new(1)
                || current.commit_key != record.object_id
                || current.body_digest != header.body_digest
                || current.signing_key_id != header.signing_key_id
                || current.format_ref != record.format_ref)
        {
            return Err(V2FormatError::StaleAnchor);
        }
        let needs_recovery_protection = current.is_none()
            && record.provider_profile == V2ProviderProfile::RetainedVersionObjectLock
            && self.options.recovery_policy.is_some();
        if needs_recovery_protection {
            guard
                .ok_or(V2FormatError::ProviderProfileFailed)?
                .verify_v2_maintenance(None)
                .await?;
        }
        // Once accepted, the external anchor selects the exact version. Before
        // acceptance, only the journal's one preselected random identity is read.
        let version = current.as_ref().and_then(|state| state.version_id.as_ref());
        let mut required_deadline = if current.is_none() {
            required_retain_until_ms(record.retention)
        } else {
            None
        };
        if current.is_none()
            && record.provider_profile == V2ProviderProfile::RetainedVersionObjectLock
            && let Some(policy) = self.options.recovery_policy
        {
            let recovery_deadline = policy.coverage_until_ms(self.publication_now_ms())?;
            required_deadline = Some(required_deadline.map_or(recovery_deadline, |existing| {
                existing.max(recovery_deadline)
            }));
        }
        let physical_retention = crate::v2::recovery::policy::physical_retention_for_deadline(
            record.retention,
            required_deadline,
            self.publication_now_ms(),
        )?;
        let metadata = match self.store.head_at(&record.object_id, version).await {
            Ok(metadata) => metadata,
            Err(StorageError::NotFound(_)) if current.is_none() => {
                if !allow_upload {
                    return Err(V2FormatError::BootstrapUploadRequired);
                }
                match self
                    .put_commit_object(
                        &record.object_id,
                        Bytes::copy_from_slice(&record.body),
                        physical_retention,
                        record.legal_hold,
                    )
                    .await
                {
                    Ok(metadata) => metadata,
                    Err(_) => self
                        .store
                        .head(&record.object_id)
                        .await
                        .map_err(|_| V2FormatError::StorageOperationFailed)?,
                }
            }
            Err(_) => return Err(V2FormatError::StorageOperationFailed),
        };
        if current.is_some() && metadata.version_id.as_ref() != version {
            return Err(V2FormatError::ProviderProfileFailed);
        }
        let object_len =
            u64::try_from(record.body.len()).map_err(|_| V2FormatError::InvalidHeaderField)?;
        if needs_recovery_protection {
            let candidate = V2AnchorState {
                sequence: Sequence::new(1),
                commit_key: record.object_id.clone(),
                body_digest: header.body_digest,
                version_id: metadata.version_id.clone(),
                signing_key_id: header.signing_key_id.clone(),
                format_ref: record.format_ref.clone(),
            };
            // Repair protection under the real guard before verifying the
            // complete candidate. This preserves stronger observed mode/hold
            // and never gives an unverified candidate anchor authority.
            self.protect_recovery_genesis(
                anchor,
                guard.ok_or(V2FormatError::ProviderProfileFailed)?,
                &candidate,
                object_len,
                required_deadline.ok_or(V2FormatError::ProviderProfileFailed)?,
            )
            .await?;
        } else if required_deadline.is_some_and(|required| {
            metadata
                .retain_until_ms
                .is_none_or(|actual| actual < required)
        }) {
            if metadata.object_id != record.object_id
                || (record.provider_profile == V2ProviderProfile::RetainedVersionObjectLock
                    && metadata.version_id.is_none())
            {
                return Err(V2FormatError::ProviderProfileFailed);
            }
            self.store
                .extend_retention_at(
                    &record.object_id,
                    metadata.version_id.as_ref(),
                    crate::v2::recovery::policy::physical_retention_for_deadline(
                        record.retention,
                        required_deadline,
                        self.publication_now_ms(),
                    )?
                    .ok_or(V2FormatError::ProviderProfileFailed)?,
                )
                .await
                .map_err(|_| V2FormatError::StorageOperationFailed)?;
        }
        let verified = self
            .verify_commit_postconditions(
                &record.object_id,
                &metadata,
                V2WritePostconditions::verified_object(
                    object_len,
                    record.retention,
                    required_deadline,
                    record.legal_hold,
                    digest_v2_section(&record.body),
                ),
            )
            .await?;
        let version_id = verified.version_id.clone();
        let next = V2AnchorState {
            sequence: Sequence::new(1),
            commit_key: record.object_id.clone(),
            body_digest: header.body_digest,
            version_id: version_id.clone(),
            signing_key_id: header.signing_key_id.clone(),
            format_ref: record.format_ref.clone(),
        };
        if needs_recovery_protection {
            guard
                .ok_or(V2FormatError::ProviderProfileFailed)?
                .verify_v2_maintenance(None)
                .await?;
            if anchor.read_v2().await?.is_some() {
                return Err(V2FormatError::StaleAnchor);
            }
        }
        self.remember_verified_publication_time(
            &next,
            header.publish_time_ms,
            header
                .section_index
                .iter()
                .any(|section| section.section_type == V2SectionType::Recovery),
        )?;
        if current.as_ref() != Some(&next) {
            let result = anchor.compare_and_advance_v2(None, next.clone()).await;
            // Never repeat CAS after an ambiguous result until the accepted
            // state has been reconciled. Read failure remains fail closed.
            if anchor.read_v2().await?.as_ref() != Some(&next) {
                return Err(result.err().unwrap_or(V2FormatError::StaleAnchor));
            }
        }
        Ok(V2StoredCommit {
            verified_retain_until_ms: verified.retain_until_ms,
            publish_time_ms: header.publish_time_ms,
            anchor_state: next,
            commit_key: V2CommitKey::parse(&record.object_id)?,
            version_id,
            object_len,
            sections_start: u64::try_from(parsed.parsed_header.sections_start)
                .map_err(|_| V2FormatError::InvalidHeaderField)?,
        })
    }
}
