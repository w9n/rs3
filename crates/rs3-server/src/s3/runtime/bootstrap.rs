//! Resumable initialization from trusted external intent, never backend discovery.

use super::*;
use crate::admin::provider_conformance_target_fingerprint;
use crate::s3::runtime_keyring::{open_gateway_keyring_object, prepare_gateway_keyring};
use rs3_crypto::derive_public_fingerprint;
use rs3_k8s::{KubernetesBootstrapJournal, MAX_BOOTSTRAP_JOURNAL_BYTES};
use rs3_repository::v2::V2FormatError;
use rs3_repository::{KEYRING_ENVELOPE_OBJECT_CONTENT_TYPE, keyring_envelope_object_id};
use rs3_storage::retention_satisfies;
use rs3_types::BackendVersionId;
use serde::{Deserialize, Serialize};

const SCHEMA: &str = "rs3.bootstrap.v1";
const WRITE_ATTEMPTS: u8 = 3;

// Private seam for crash tests; Kubernetes is the sole durable implementation.
#[async_trait::async_trait]
pub(super) trait Journal: Send {
    fn state(&self) -> Result<Option<&[u8]>, S3BoundaryError>;
    async fn save(&mut self, bytes: &[u8], evidence: Option<&str>) -> Result<(), S3BoundaryError>;
}

#[async_trait::async_trait]
impl Journal for KubernetesBootstrapJournal {
    fn state(&self) -> Result<Option<&[u8]>, S3BoundaryError> {
        self.state().map_err(repository_init)
    }

    async fn save(&mut self, bytes: &[u8], evidence: Option<&str>) -> Result<(), S3BoundaryError> {
        self.save(bytes, evidence.map(str::as_bytes))
            .await
            .map_err(repository_init)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    context: String,
    phase: Phase,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "phase", deny_unknown_fields)]
enum Phase {
    Keyring {
        artifact: Artifact,
    },
    Format {
        keyring: V2KeyringEnvelopeRootRef,
        artifact: Artifact,
    },
    Genesis {
        keyring: V2KeyringEnvelopeRootRef,
        format: V2FormatRef,
        intent: Vec<u8>,
        remaining: u8,
    },
    Initialized {
        accepted: V2AnchorState,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    object_id: BackendObjectId,
    body: Vec<u8>,
    remaining: u8,
}

impl Artifact {
    fn new(object_id: BackendObjectId, body: Vec<u8>) -> Self {
        Self {
            object_id,
            body,
            remaining: WRITE_ATTEMPTS,
        }
    }
}

fn invalid() -> S3BoundaryError {
    repository_init("bootstrap journal does not match the configured unfinished initialization")
}

pub(super) fn context(config: &RuntimeConfig) -> Result<String, S3BoundaryError> {
    let keys = &config.repository_keys;
    let salt = hex::decode(&keys.repository_salt_hex).map_err(|_| invalid())?;
    let identity = serde_json::to_vec(&(
        &keys.repository_id,
        salt,
        &keys.wrapping_key_id,
        &keys.envelope_object_id,
        v2_provider_profile(&config.backend, config.repository.retention),
        config.repository.retention,
    ))
    .map_err(|_| invalid())?;
    Ok(derive_public_fingerprint(
        b"rs3.bootstrap.context.v1",
        &[
            provider_conformance_target_fingerprint(&V2ProviderCheckConfig::from(config))
                .as_bytes(),
            &identity,
        ],
    ))
}

fn decode(bytes: &[u8], expected: &str) -> Result<Record, S3BoundaryError> {
    if bytes.len() > MAX_BOOTSTRAP_JOURNAL_BYTES {
        return Err(invalid());
    }
    let record: Record = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    let remaining = match &record.phase {
        Phase::Keyring { artifact } | Phase::Format { artifact, .. } => artifact.remaining,
        Phase::Genesis { remaining, .. } => *remaining,
        Phase::Initialized { .. } => 0,
    };
    if record.schema != SCHEMA || record.context != expected || remaining > WRITE_ATTEMPTS {
        return Err(invalid());
    }
    Ok(record)
}

pub(super) fn is_initialized(
    config: &RuntimeConfig,
    bytes: &[u8],
) -> Result<bool, S3BoundaryError> {
    Ok(matches!(
        decode(bytes, &context(config)?)?.phase,
        Phase::Initialized { .. }
    ))
}

async fn save(journal: &mut impl Journal, record: &Record) -> Result<(), S3BoundaryError> {
    let bytes = serde_json::to_vec(record).map_err(|_| invalid())?;
    if bytes.len() > MAX_BOOTSTRAP_JOURNAL_BYTES {
        return Err(invalid());
    }
    journal.save(&bytes, None).await
}

struct Bootstrap<'a, J> {
    config: &'a RuntimeConfig,
    store: &'a RuntimeStore,
    anchor: &'a RuntimeV2Anchor,
    guard: &'a dyn V2MaintenanceGuard,
    journal: &'a mut J,
}

impl<J: Journal> Bootstrap<'_, J> {
    async fn check_guard(&self) -> Result<(), S3BoundaryError> {
        self.guard
            .verify_v2_maintenance(None)
            .await
            .map_err(repository_init)
    }

    async fn require_unaccepted(&self) -> Result<(), S3BoundaryError> {
        self.check_guard().await?;
        if self
            .anchor
            .read_v2()
            .await
            .map_err(repository_init)?
            .is_some()
        {
            return Err(invalid());
        }
        Ok(())
    }

    async fn verify_accepted(
        &self,
        initialized: bool,
    ) -> Result<V2RepositoryInitReport, S3BoundaryError> {
        let anchor = self
            .anchor
            .read_v2()
            .await
            .map_err(repository_init)?
            .ok_or_else(|| {
                repository_init(
                    "completed bootstrap requires explicit recovery of its missing anchor",
                )
            })?;
        let loaded = load_existing_v2_repository(
            self.store,
            &self.config.repository_keys,
            &anchor,
            self.config,
        )
        .await?;
        let options = bootstrap_commit_options(self.config, &loaded)?;
        let commits = V2CommitStore::new(self.store.clone(), loaded.keyring, options);
        let chain = commits
            .load_replay_chain_from_state(&anchor)
            .await
            .map_err(repository_init)?;
        Ok(V2RepositoryInitReport {
            anchor,
            initialized,
            verified_commit_count: chain.commits_newest_first.len(),
            probe_attempts: 0,
            payload_restore_verified: false,
            probe_observation: None,
        })
    }

    async fn run(&mut self) -> Result<V2RepositoryInitReport, S3BoundaryError> {
        self.check_guard().await?;
        let expected = context(self.config)?;
        let mut record = match self.journal.state()? {
            Some(bytes) => decode(bytes, &expected)?,
            None => {
                if self
                    .anchor
                    .read_v2()
                    .await
                    .map_err(repository_init)?
                    .is_some()
                {
                    let report = self.verify_accepted(false).await?;
                    save(
                        self.journal,
                        &Record {
                            schema: SCHEMA.to_owned(),
                            context: expected,
                            phase: Phase::Initialized {
                                accepted: report.anchor.clone(),
                            },
                        },
                    )
                    .await?;
                    return Ok(report);
                }
                self.require_init_permission()?;
                reject_v2_bootstrap_with_foreign_objects(
                    self.store,
                    v2_provider_profile(&self.config.backend, self.config.repository.retention),
                    None,
                )
                .await?;
                let (_, envelope) = prepare_gateway_keyring(&self.config.repository_keys)?;
                let artifact = Artifact::new(
                    self.keyring_id(&envelope)?,
                    envelope.to_object_bytes().map_err(repository_init)?,
                );
                let record = Record {
                    schema: SCHEMA.to_owned(),
                    context: expected,
                    phase: Phase::Keyring { artifact },
                };
                save(self.journal, &record).await?;
                record
            }
        };
        loop {
            self.check_guard().await?;
            if let Phase::Initialized { accepted } = &record.phase {
                let report = self.verify_accepted(false).await?;
                if report.anchor.sequence < accepted.sequence
                    || (report.anchor.sequence == accepted.sequence && report.anchor != *accepted)
                {
                    return Err(invalid());
                }
                return Ok(report);
            }
            self.require_init_permission()?;
            match record.phase.clone() {
                Phase::Keyring { artifact } => {
                    self.require_unaccepted().await?;
                    let envelope = RepositoryEnvelope::from_object_bytes(
                        &artifact.body,
                        rs3_crypto::EnvelopePurpose::Keyring,
                    )
                    .map_err(repository_init)?;
                    if artifact.object_id != self.keyring_id(&envelope)? {
                        return Err(invalid());
                    }
                    // Decrypt before any PUT: a changed wrapping key must fail here.
                    let loaded = open_gateway_keyring_object(
                        &self.config.repository_keys,
                        artifact.object_id.clone(),
                        None,
                        Bytes::copy_from_slice(&artifact.body),
                    )?;
                    let version_id = self
                        .publish_artifact(
                            &mut record,
                            &artifact,
                            KEYRING_ENVELOPE_OBJECT_CONTENT_TYPE,
                        )
                        .await?;
                    let keyring = V2KeyringEnvelopeRootRef {
                        generation: envelope.generation,
                        digest: envelope.digest().map_err(repository_init)?,
                        object_id: artifact.object_id,
                        version_id,
                    };
                    let root = V2FormatRoot::new(
                        self.config.repository_keys.repository_id.clone(),
                        keyring.clone(),
                        loaded
                            .keyring
                            .primary_key_id(KeyPurpose::CheckpointSigning)
                            .map_err(repository_init)?,
                        v2_provider_profile(&self.config.backend, self.config.repository.retention),
                        self.config.repository.retention,
                    );
                    let envelope = prepare_format_root(&self.config.repository_keys, &root)?;
                    record.phase = Phase::Format {
                        keyring,
                        artifact: Artifact::new(
                            v2_format_object_id(
                                envelope.generation,
                                &envelope.digest().map_err(repository_init)?,
                            )
                            .map_err(repository_init)?,
                            envelope.to_object_bytes().map_err(repository_init)?,
                        ),
                    };
                }
                Phase::Format { keyring, artifact } => {
                    self.require_unaccepted().await?;
                    let envelope = RepositoryEnvelope::from_object_bytes(
                        &artifact.body,
                        rs3_crypto::EnvelopePurpose::Format,
                    )
                    .map_err(repository_init)?;
                    let digest = envelope.digest().map_err(repository_init)?;
                    if artifact.object_id
                        != v2_format_object_id(envelope.generation, &digest)
                            .map_err(repository_init)?
                    {
                        return Err(invalid());
                    }
                    let mut format = V2FormatRef {
                        generation: envelope.generation,
                        digest,
                        object_id: artifact.object_id.clone(),
                        version_id: None,
                    };
                    let root = open_format_root_body(
                        &self.config.repository_keys,
                        &format,
                        &artifact.body,
                    )?;
                    let loaded = self.load_dependencies(&keyring, &root, &format).await?;
                    self.protect_dependency(&keyring.object_id, keyring.version_id.as_ref())
                        .await?;
                    format.version_id = self
                        .publish_artifact(&mut record, &artifact, V2_FORMAT_ENVELOPE_CONTENT_TYPE)
                        .await?;
                    let loaded = LoadedV2Repository {
                        format_ref: format.clone(),
                        ..loaded
                    };
                    let options = bootstrap_commit_options(self.config, &loaded)?;
                    let commits = V2CommitStore::new(self.store.clone(), loaded.keyring, options);
                    let intent = commits
                        .prepare_genesis_snapshot()
                        .map_err(repository_init)?
                        .to_journal_bytes()
                        .map_err(repository_init)?
                        .to_vec();
                    record.phase = Phase::Genesis {
                        keyring,
                        format,
                        intent,
                        remaining: WRITE_ATTEMPTS,
                    };
                }
                Phase::Genesis {
                    keyring,
                    format,
                    intent,
                    remaining,
                } => {
                    let root =
                        open_format_root(self.store, &self.config.repository_keys, &format).await?;
                    let loaded = self.load_dependencies(&keyring, &root, &format).await?;
                    let options = bootstrap_commit_options(self.config, &loaded)?;
                    let commits = V2CommitStore::new(self.store.clone(), loaded.keyring, options);
                    let prepared = commits
                        .open_prepared_genesis(&intent)
                        .map_err(repository_init)?;
                    self.protect_dependency(&keyring.object_id, keyring.version_id.as_ref())
                        .await?;
                    self.protect_dependency(&format.object_id, format.version_id.as_ref())
                        .await?;
                    let result = commits
                        .publish_prepared_genesis(self.anchor, &prepared, false)
                        .await;
                    match result {
                        Ok(_) => {}
                        Err(V2FormatError::BootstrapUploadRequired) => {
                            if remaining == 0 {
                                return Err(repository_init(
                                    "bootstrap upload budget exhausted; reconcile or recover explicitly",
                                ));
                            }
                            if let Phase::Genesis { remaining, .. } = &mut record.phase {
                                *remaining -= 1;
                            }
                            save(self.journal, &record).await?;
                            self.check_guard().await?;
                            commits
                                .publish_prepared_genesis(self.anchor, &prepared, true)
                                .await
                                .map_err(repository_init)?;
                        }
                        Err(error) => return Err(repository_init(error)),
                    }
                    let report = self.verify_accepted(true).await?;
                    record.phase = Phase::Initialized {
                        accepted: report.anchor.clone(),
                    };
                    save(self.journal, &record).await?;
                    return Ok(report);
                }
                Phase::Initialized { .. } => return Err(invalid()),
            }
            save(self.journal, &record).await?;
        }
    }

    fn require_init_permission(&self) -> Result<(), S3BoundaryError> {
        if !self.config.mode.allows_mutation() || !self.config.repository.allow_init {
            return Err(repository_init(
                "unfinished bootstrap requires explicit initialization permission",
            ));
        }
        Ok(())
    }

    fn keyring_id(
        &self,
        envelope: &RepositoryEnvelope,
    ) -> Result<BackendObjectId, S3BoundaryError> {
        match &self.config.repository_keys.envelope_object_id {
            Some(id) => Ok(id.clone()),
            None => keyring_envelope_object_id(
                envelope.generation,
                &envelope.digest().map_err(repository_init)?,
            )
            .map_err(repository_init),
        }
    }

    async fn load_dependencies(
        &self,
        keyring: &V2KeyringEnvelopeRootRef,
        root: &V2FormatRoot,
        format: &V2FormatRef,
    ) -> Result<LoadedV2Repository, S3BoundaryError> {
        if root.active_keyring_envelope_ref != *keyring
            || root.repository_id != self.config.repository_keys.repository_id
            || root.provider_profile
                != v2_provider_profile(&self.config.backend, self.config.repository.retention)
            || root.retention != self.config.repository.retention
        {
            return Err(invalid());
        }
        let loaded = open_gateway_keyring_reference(
            self.store,
            &self.config.repository_keys,
            &keyring_reference_from_v2(keyring),
        )
        .await?;
        if loaded
            .keyring
            .primary_key_id(KeyPurpose::CheckpointSigning)
            .map_err(repository_init)?
            != root.signing_key_id
        {
            return Err(invalid());
        }
        Ok(LoadedV2Repository {
            keyring: loaded.keyring,
            keyring_ref: keyring.clone(),
            format_ref: format.clone(),
            anchor_present: false,
        })
    }

    async fn publish_artifact(
        &mut self,
        record: &mut Record,
        artifact: &Artifact,
        content_type: &'static str,
    ) -> Result<Option<BackendVersionId>, S3BoundaryError> {
        let metadata = match self.store.head(&artifact.object_id).await {
            Ok(metadata) => metadata,
            Err(StorageError::NotFound(_)) => {
                if artifact.remaining == 0 {
                    return Err(repository_init(
                        "bootstrap upload budget exhausted; reconcile or recover explicitly",
                    ));
                }
                match &mut record.phase {
                    Phase::Keyring { artifact } | Phase::Format { artifact, .. } => {
                        artifact.remaining -= 1
                    }
                    _ => return Err(invalid()),
                }
                save(self.journal, record).await?;
                self.require_unaccepted().await?;
                match self
                    .store
                    .put(
                        &artifact.object_id,
                        Bytes::copy_from_slice(&artifact.body),
                        PutOptions {
                            retention: self.config.repository.retention,
                            legal_hold: None,
                            content_type: Some(content_type.to_owned()),
                            do_not_recreate: !retained_version_required(
                                self.config.repository.retention,
                                None,
                            ),
                        },
                    )
                    .await
                {
                    Ok(metadata) => metadata,
                    Err(_) => self
                        .store
                        .head(&artifact.object_id)
                        .await
                        .map_err(repository_init)?,
                }
            }
            Err(error) => return Err(repository_init(error)),
        };
        if metadata.object_id != artifact.object_id
            || metadata.content_len != artifact.body.len() as u64
        {
            return Err(invalid());
        }
        let version = retained_version_id(
            &artifact.object_id,
            &metadata,
            self.config.repository.retention,
            None,
        )
        .map_err(repository_init)?;
        let body = read_bounded_object_at(
            self.store,
            &artifact.object_id,
            version.as_ref(),
            MAX_BOOTSTRAP_JOURNAL_BYTES as u64,
        )
        .await?;
        if body.as_ref() != artifact.body {
            return Err(invalid());
        }
        self.protect_dependency(&artifact.object_id, version.as_ref())
            .await?;
        Ok(version)
    }

    async fn protect_dependency(
        &self,
        id: &BackendObjectId,
        version: Option<&BackendVersionId>,
    ) -> Result<(), S3BoundaryError> {
        let retention = self
            .config
            .repository
            .retention
            .filter(|policy| policy.mode != RetentionMode::None && policy.retain_days > 0);
        let deadline = retention
            .map(|policy| {
                current_time_ms()
                    .checked_add(i64::from(policy.retain_days) * 86_400_000)
                    .ok_or_else(invalid)
            })
            .transpose()?;
        let mut metadata = self
            .store
            .head_at(id, version)
            .await
            .map_err(repository_init)?;
        if metadata.object_id != *id
            || metadata.version_id.as_ref() != version
            || (retention.is_some() && version.is_none())
        {
            return Err(invalid());
        }
        if let Some(policy) = retention {
            if deadline.is_some_and(|required| {
                metadata
                    .retain_until_ms
                    .is_none_or(|actual| actual < required)
            }) {
                self.check_guard().await?;
                self.store
                    .extend_retention_at(id, version, policy)
                    .await
                    .map_err(repository_init)?;
                metadata = self
                    .store
                    .head_at(id, version)
                    .await
                    .map_err(repository_init)?;
            }
            if metadata.object_id != *id
                || metadata.version_id.as_ref() != version
                || !retention_satisfies(metadata.retention.as_ref(), &policy)
                || deadline.is_some_and(|required| {
                    metadata
                        .retain_until_ms
                        .is_none_or(|actual| actual < required)
                })
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

pub(super) async fn initialize(
    config: &RuntimeConfig,
    store: &RuntimeStore,
    anchor: &RuntimeV2Anchor,
    guard: &dyn V2MaintenanceGuard,
    journal: &mut impl Journal,
) -> Result<V2RepositoryInitReport, S3BoundaryError> {
    Bootstrap {
        config,
        store,
        anchor,
        guard,
        journal,
    }
    .run()
    .await
}

#[cfg(test)]
mod tests;
