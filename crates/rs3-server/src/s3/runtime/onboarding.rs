//! Bounded provider qualification around the single journaled bootstrap engine.

use super::bootstrap::Journal;
use super::*;
use crate::admin::{
    encode_provider_conformance_evidence, provider_conformance_implementation_fingerprint,
    provider_conformance_summary_from_bytes, provider_conformance_target_fingerprint,
    read_provider_conformance_evidence, selected_provider_profile,
};
use crate::s3::runtime_keyring::{
    configured_or_generated_repository_salt, configured_repository_salt,
};
use rs3_k8s::MAX_BOOTSTRAP_JOURNAL_BYTES;
use serde::{Deserialize, Serialize};

const SCHEMA: &str = "rs3.onboarding.v2";
const MAX_PROBE_RUNS: u8 = 3;

mod probe_observation;
mod round_trip;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    context: String,
    /// Public salt fixed for the whole onboarding, journaled before any
    /// artifact exists so retries and the nested bootstrap share it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    repository_salt_hex: Option<String>,
    probe_root: String,
    attempts: u8,
    evidence: Option<String>,
    bootstrap: Option<String>,
    probe_observation: Option<V2ProbeObservation>,
    round_trip: Option<round_trip::State>,
}

impl Record {
    fn decode(bytes: &[u8], config: &RuntimeConfig) -> Result<(Self, Vec<u8>), S3BoundaryError> {
        if bytes.len() > MAX_BOOTSTRAP_JOURNAL_BYTES {
            return Err(invalid());
        }
        let record: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        let salt =
            bootstrap::resolve_recorded_salt(config, None, record.repository_salt_hex.as_deref())?;
        let context = bootstrap::context(config, &salt)?;
        let root_valid = record
            .probe_root
            .strip_prefix("rs3-probes/")
            .is_some_and(|id| {
                id.len() == 32
                    && id
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            });
        if record.schema != SCHEMA
            || record.context != context
            || record.attempts > MAX_PROBE_RUNS
            || !root_valid
            || record
                .round_trip
                .as_ref()
                .is_some_and(|state| !state.valid())
        {
            return Err(invalid());
        }
        Ok((record, salt))
    }
}

pub(super) fn is_initialized(
    config: &RuntimeConfig,
    bytes: &[u8],
) -> Result<bool, S3BoundaryError> {
    let (record, salt) = Record::decode(bytes, config)?;
    if !record
        .round_trip
        .as_ref()
        .is_some_and(round_trip::State::complete)
    {
        return Ok(false);
    }
    if !record
        .evidence
        .as_deref()
        .is_some_and(|evidence| matching_evidence(config, evidence))
    {
        return Ok(false);
    }
    record
        .bootstrap
        .as_deref()
        .map(|bytes| bootstrap::is_initialized(config, Some(&salt), bytes.as_bytes()))
        .transpose()
        .map(|completed| completed.unwrap_or(false))
}

fn invalid() -> S3BoundaryError {
    repository_init("onboarding journal is invalid or belongs to a different repository")
}

// The production implementation retains the already configured StoreBuild.
// Tests inject failures at the boundary of one complete qualification suite.
#[async_trait::async_trait]
trait Probe: Sync {
    fn accepts(&self, evidence: &str) -> bool;
    fn ready(&self) -> Result<(), S3BoundaryError>;
    async fn run(&self, prefix: String) -> Result<String, S3BoundaryError>;
    async fn observe(&self, root: String, attempts: u8) -> V2ProbeObservation;
}

struct ProviderProbe<'a> {
    config: &'a RuntimeConfig,
    store: &'a StoreBuild,
    governance_bypass_reviewed: bool,
}

#[async_trait::async_trait]
impl Probe for ProviderProbe<'_> {
    fn accepts(&self, evidence: &str) -> bool {
        matching_evidence(self.config, evidence)
    }

    fn ready(&self) -> Result<(), S3BoundaryError> {
        require_probe_review(self.config, self.governance_bypass_reviewed)
    }

    async fn run(&self, prefix: String) -> Result<String, S3BoundaryError> {
        let config = V2ProviderCheckConfig::from(self.config);
        let report = check_v2_provider_conformance_with_store(
            &config,
            RuntimeV2ProviderConformanceOptions {
                probe_prefix: Some(prefix),
                legal_hold: true,
                governance_bypass_reviewed: self.governance_bypass_reviewed,
            },
            self.store,
        )
        .await?;
        encode_provider_conformance_evidence(&config, &report)
    }

    async fn observe(&self, root: String, attempts: u8) -> V2ProbeObservation {
        match self
            .store
            .provider_probe_store(root, self.config.repository.retention)
            .await
        {
            Ok(store) => probe_observation::observe(&store, attempts).await,
            Err(_) => probe_observation::unavailable(attempts, "store-unavailable"),
        }
    }
}

fn matching_evidence(runtime: &RuntimeConfig, evidence: &str) -> bool {
    let config = V2ProviderCheckConfig::from(runtime);
    provider_conformance_summary_from_bytes(
        &runtime.provider_conformance,
        selected_provider_profile(runtime),
        &provider_conformance_target_fingerprint(&config),
        config.repository_retention,
        evidence.as_bytes(),
    )
    .state
        == "passed"
}

fn require_probe_review(
    config: &RuntimeConfig,
    governance_bypass_reviewed: bool,
) -> Result<(), S3BoundaryError> {
    if provider_conformance_implementation_fingerprint().is_none() {
        return Err(repository_init(
            "provider evidence cannot identify the running executable",
        ));
    }
    if config
        .repository
        .retention
        .is_some_and(|policy| policy.mode == RetentionMode::Governance && policy.retain_days > 0)
        && (!governance_bypass_reviewed
            || config.provider_conformance.principal_fingerprint.is_none())
    {
        return Err(repository_init(
            "automatic governance qualification requires a bound principal and explicit bypass review",
        ));
    }
    Ok(())
}

struct OnboardingJournal<'a, J> {
    journal: &'a mut J,
    record: Record,
    /// Salt every envelope of this onboarding is sealed and opened under.
    salt: Vec<u8>,
    usable: bool,
}

impl<'a, J: Journal> OnboardingJournal<'a, J> {
    /// Opens or creates the onboarding record.
    ///
    /// `existing_salt` is the salt recovered from an already anchored
    /// repository. A fresh journal over such a repository must adopt it: only
    /// a repository that does not exist yet gets a generated salt.
    fn open(
        journal: &'a mut J,
        config: &RuntimeConfig,
        existing_salt: Option<Vec<u8>>,
    ) -> Result<Self, S3BoundaryError> {
        let (record, salt) = match journal.state()? {
            Some(bytes) => Record::decode(bytes, config)?,
            None => {
                let configured = configured_repository_salt(&config.repository_keys)?;
                let salt = match (configured, existing_salt) {
                    (Some(configured), Some(existing)) if configured != existing => {
                        return Err(repository_init(
                            "RS3_REPOSITORY_SALT_HEX does not match the salt of the anchored repository this journal would onboard",
                        ));
                    }
                    (Some(configured), _) => configured,
                    (None, Some(existing)) => existing,
                    (None, None) => {
                        configured_or_generated_repository_salt(&config.repository_keys)?
                    }
                };
                let record = Record {
                    schema: SCHEMA.to_owned(),
                    context: bootstrap::context(config, &salt)?,
                    repository_salt_hex: Some(hex::encode(&salt)),
                    probe_root: default_v2_provider_probe_prefix()?,
                    attempts: 0,
                    evidence: None,
                    bootstrap: None,
                    probe_observation: None,
                    round_trip: None,
                };
                (record, salt)
            }
        };
        Ok(Self {
            journal,
            record,
            salt,
            usable: true,
        })
    }

    async fn persist(&mut self) -> Result<(), S3BoundaryError> {
        if !self.usable {
            return Err(invalid());
        }
        let bytes = serde_json::to_vec(&self.record).map_err(|_| invalid())?;
        if bytes
            .len()
            .saturating_add(self.record.evidence.as_ref().map_or(0, String::len))
            > MAX_BOOTSTRAP_JOURNAL_BYTES
        {
            return Err(invalid());
        }
        // A failed or cancelled save must never permit this in-memory record
        // to authorize a probe or bootstrap mutation after an ambiguous CAS.
        self.usable = false;
        self.journal
            .save(&bytes, self.record.evidence.as_deref())
            .await?;
        self.usable = true;
        Ok(())
    }

    async fn qualify(
        &mut self,
        probe: &impl Probe,
        guard: &dyn V2MaintenanceGuard,
        external: Option<String>,
    ) -> Result<(), S3BoundaryError> {
        self.state()?;
        guard
            .verify_v2_maintenance(None)
            .await
            .map_err(repository_init)?;
        if let Some(evidence) = external {
            if !probe.accepts(&evidence) {
                return Err(repository_init(
                    "configured external provider evidence is not current and matching",
                ));
            }
            if self.record.evidence.as_ref() != Some(&evidence) {
                self.record.evidence = Some(evidence);
                self.persist().await?;
            }
            return Ok(());
        }
        if self
            .record
            .evidence
            .as_deref()
            .is_some_and(|evidence| probe.accepts(evidence))
        {
            return Ok(());
        }
        probe.ready()?;
        if self.record.attempts == MAX_PROBE_RUNS {
            return Err(repository_init(
                "onboarding provider probe budget exhausted; preserve the journal and supply reviewed matching evidence",
            ));
        }
        self.record.attempts += 1;
        self.record.evidence = None;
        self.persist().await?;
        guard
            .verify_v2_maintenance(None)
            .await
            .map_err(repository_init)?;
        let prefix = format!("{}/{}", self.record.probe_root, self.record.attempts);
        let outcome = probe.run(prefix).await;
        guard
            .verify_v2_maintenance(None)
            .await
            .map_err(repository_init)?;
        self.record.probe_observation = Some(
            probe
                .observe(self.record.probe_root.clone(), self.record.attempts)
                .await,
        );
        guard
            .verify_v2_maintenance(None)
            .await
            .map_err(repository_init)?;
        let passed = outcome
            .as_ref()
            .is_ok_and(|evidence| probe.accepts(evidence));
        self.record.evidence = outcome.as_ref().ok().cloned();
        self.persist().await?;
        outcome?;
        if !passed {
            return Err(repository_init(
                "onboarding provider qualification failed; evidence retained in the journal",
            ));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl<J: Journal> Journal for OnboardingJournal<'_, J> {
    fn state(&self) -> Result<Option<&[u8]>, S3BoundaryError> {
        if !self.usable {
            return Err(invalid());
        }
        // Also test underlying ownership, including its live writer fence.
        self.journal.state()?;
        Ok(self.record.bootstrap.as_deref().map(str::as_bytes))
    }

    async fn save(&mut self, bytes: &[u8], evidence: Option<&str>) -> Result<(), S3BoundaryError> {
        if evidence.is_some() {
            return Err(invalid());
        }
        self.record.bootstrap = Some(String::from_utf8(bytes.to_vec()).map_err(|_| invalid())?);
        self.persist().await
    }
}

/// Recovers the salt of an already anchored repository for a journal that
/// has not recorded anything yet.
///
/// A fresh journal over an intact anchor must adopt that salt from the
/// authenticated format root: generating one would seal nothing the existing
/// envelopes accept and leave every retry stuck. Only a repository that does
/// not exist yet gets a generated salt.
async fn existing_repository_salt(
    config: &RuntimeConfig,
    store: &RuntimeStore,
    anchor: &RuntimeV2Anchor,
    journal: &impl Journal,
) -> Result<Option<Vec<u8>>, S3BoundaryError> {
    if journal.state()?.is_some() {
        return Ok(None);
    }
    let Some(anchor_state) = anchor.read_v2().await.map_err(repository_init)? else {
        return Ok(None);
    };
    Ok(Some(
        load_existing_v2_repository(store, &config.repository_keys, &anchor_state, config)
            .await?
            .repository_salt,
    ))
}

pub(super) async fn initialize(
    config: &RuntimeConfig,
    store: &StoreBuild,
    anchor: &RuntimeV2Anchor,
    guard: &dyn V2MaintenanceGuard,
    journal: &mut impl Journal,
    governance_bypass_reviewed: bool,
) -> Result<V2RepositoryInitReport, S3BoundaryError> {
    let existing_salt = existing_repository_salt(config, store.handle(), anchor, journal).await?;
    let mut journal = OnboardingJournal::open(journal, config, existing_salt)?;
    let salt = journal.salt.clone();
    guard
        .verify_v2_maintenance(None)
        .await
        .map_err(repository_init)?;
    if journal.state()?.is_none() && anchor.read_v2().await.map_err(repository_init)?.is_none() {
        if !config.repository.allow_init {
            return Err(repository_init("repository initialization is disabled"));
        }
        reject_v2_bootstrap_with_foreign_objects(
            store.handle(),
            v2_provider_profile(&config.backend, config.repository.retention),
            None,
        )
        .await?;
    }
    let external = config
        .provider_conformance
        .report_file
        .as_ref()
        .map(|path| {
            read_provider_conformance_evidence(path).map_err(|_| {
                repository_init(
                    "configured external provider evidence cannot be read within its byte budget",
                )
            })
        })
        .transpose()?
        .map(|bytes| String::from_utf8(bytes).map_err(|_| invalid()))
        .transpose()?;
    journal
        .qualify(
            &ProviderProbe {
                config,
                store,
                governance_bypass_reviewed,
            },
            guard,
            external,
        )
        .await?;
    let mut report = bootstrap::initialize(
        config,
        store.handle(),
        anchor,
        guard,
        &mut journal,
        Some(salt),
    )
    .await?;
    round_trip::verify(
        config,
        store.handle(),
        anchor,
        guard,
        &mut journal,
        &mut report,
    )
    .await?;
    report.payload_restore_verified = true;
    report.probe_attempts = journal.record.attempts;
    report.probe_observation = journal.record.probe_observation.clone();
    Ok(report)
}

#[cfg(test)]
mod tests;
