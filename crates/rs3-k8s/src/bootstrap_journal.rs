//! Trusted bootstrap progress on a declared Secret, with epoch and revision CAS.

use crate::lease_guard::{WriterFenceClaim, lease_holds_claim};
use crate::{LeaseSettings, WriterFence};
use async_trait::async_trait;
use k8s_openapi::ByteString;
use k8s_openapi::api::{coordination::v1::Lease, core::v1::Secret};
use kube::{Api, Client, api::PostParams};
use std::collections::BTreeMap;
use std::fmt;

const OWNER: &str = "rs3.rs/bootstrap-journal";
const SECRET_UID: &str = "rs3.rs/bootstrap-secret-uid";
const LEASE_UID: &str = "rs3.rs/bootstrap-lease-uid";
const EPOCH: &str = "rs3.rs/bootstrap-epoch";
const STATE: &str = "state";
const EVIDENCE: &str = "provider-conformance.json";

/// Maximum decoded bootstrap journal bytes, below the Kubernetes Secret limit.
pub const MAX_BOOTSTRAP_JOURNAL_BYTES: usize = 512 * 1024;

/// Path-redacted failure of a declared bootstrap journal operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapJournalError {
    /// Settings cannot identify the declared resources.
    InvalidConfig,
    /// The chart or operator has not declared the journal Secret.
    Missing,
    /// The Secret is unowned, malformed or belongs to a replaced anchor Lease.
    InvalidState,
    /// Another update changed the resource revision.
    Conflict,
    /// The writer epoch is no longer live, or a prior update is unresolved.
    OwnershipLost,
    /// Journal bytes exceed the supported bound.
    BudgetExceeded,
    /// Required API access or update reconciliation failed.
    ApiUnavailable,
}

impl fmt::Display for BootstrapJournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfig => "bootstrap journal configuration is invalid",
            Self::Missing => "bootstrap journal requires a declared Secret",
            Self::InvalidState => "bootstrap journal state or resource ownership is invalid",
            Self::Conflict => "bootstrap journal changed concurrently; restart under a fresh claim",
            Self::OwnershipLost => {
                "bootstrap journal ownership is unavailable; restart initialization"
            }
            Self::BudgetExceeded => "bootstrap journal exceeds its byte budget",
            Self::ApiUnavailable => "bootstrap journal API access or update verification failed",
        })
    }
}
impl std::error::Error for BootstrapJournalError {}

type Result<T> = std::result::Result<T, BootstrapJournalError>;

/// Opaque bootstrap progress stored outside the object-store backend.
///
/// The Secret must already have annotation `rs3.rs/bootstrap-journal: v1` and
/// be dedicated to this purpose. The client never creates or deletes Secrets.
/// Claiming binds it to the exact anchor Lease UID and live writer epoch;
/// cached resource-version CAS prevents a stale claimant overwriting progress.
/// The caller owns validation of journal contents and completion semantics.
/// This journal is not an independent disaster-recovery authority.
pub struct KubernetesBootstrapJournal {
    inner: Journal<KubernetesJournalApi>,
}

impl KubernetesBootstrapJournal {
    /// Claims a declared journal while holding the supplied live writer fence.
    pub async fn claim(
        anchor: LeaseSettings,
        secret_name: String,
        fence: WriterFence,
    ) -> Result<Self> {
        if anchor.namespace.is_empty() || anchor.name.is_empty() || secret_name.is_empty() {
            return Err(BootstrapJournalError::InvalidConfig);
        }
        let client = Client::try_default()
            .await
            .map_err(|_| BootstrapJournalError::ApiUnavailable)?;
        let api = KubernetesJournalApi {
            leases: Api::namespaced(client.clone(), &anchor.namespace),
            secrets: Api::namespaced(client, &anchor.namespace),
        };
        Ok(Self {
            inner: Journal::claim(api, anchor, secret_name, fence).await?,
        })
    }

    /// Reads the owned state. Absence is permitted only before the first save.
    pub fn state(&self) -> Result<Option<&[u8]>> {
        self.inner.state()
    }

    /// Saves exact bytes with revision CAS, verifying ambiguous update replies.
    /// Optional derived evidence is projected as `provider-conformance.json`
    /// in the same Secret revision; `None` removes that projection. The caller
    /// verifies that evidence corresponds to the supplied authoritative state.
    /// A conflict or unresolved write invalidates this handle; reopen under a
    /// new claim instead of blindly retrying with a refreshed resource version.
    pub async fn save(&mut self, state: &[u8], evidence: Option<&[u8]>) -> Result<()> {
        self.inner.save(state, evidence).await
    }
}

#[async_trait]
trait JournalApi: Send + Sync {
    async fn get_lease(&self, name: &str) -> Result<Option<Lease>>;
    async fn get_secret(&self, name: &str) -> Result<Option<Secret>>;
    async fn replace_secret(
        &self,
        name: &str,
        field_manager: &str,
        secret: &Secret,
    ) -> Result<Secret>;
}

struct Journal<A> {
    api: A,
    anchor: LeaseSettings,
    secret_name: String,
    fence: WriterFence,
    claim: WriterFenceClaim,
    lease_uid: String,
    // Taken before update: cancellation cannot leave a usable stale revision.
    secret: Option<Secret>,
}

impl<A: JournalApi> Journal<A> {
    async fn claim(
        api: A,
        anchor: LeaseSettings,
        secret_name: String,
        fence: WriterFence,
    ) -> Result<Self> {
        let claim = fence
            .live_claim()
            .ok_or(BootstrapJournalError::OwnershipLost)?;
        let lease = api
            .get_lease(&anchor.name)
            .await?
            .ok_or(BootstrapJournalError::OwnershipLost)?;
        if !lease_holds_claim(&lease, &claim).map_err(|_| BootstrapJournalError::InvalidState)? {
            return Err(BootstrapJournalError::OwnershipLost);
        }
        let lease_uid = required(&lease.metadata.uid)?.to_owned();
        let secret = api
            .get_secret(&secret_name)
            .await?
            .ok_or(BootstrapJournalError::Missing)?;
        validate_secret(&secret, &secret_name)?;
        let annotations = secret
            .metadata
            .annotations
            .as_ref()
            .ok_or(BootstrapJournalError::InvalidState)?;
        match (
            annotations.get(SECRET_UID),
            annotations.get(LEASE_UID),
            annotations.get(EPOCH),
        ) {
            (None, None, None) if secret.data.as_ref().is_none_or(BTreeMap::is_empty) => {}
            (Some(secret_uid), Some(uid), Some(epoch)) => {
                let token: u64 = epoch
                    .parse()
                    .map_err(|_| BootstrapJournalError::InvalidState)?;
                if secret_uid != required(&secret.metadata.uid)?
                    || uid != &lease_uid
                    || token == 0
                    || token.to_string() != *epoch
                {
                    return Err(BootstrapJournalError::InvalidState);
                }
                if token > claim.token {
                    return Err(BootstrapJournalError::OwnershipLost);
                }
            }
            _ => return Err(BootstrapJournalError::InvalidState),
        }
        let mut journal = Self {
            api,
            anchor,
            secret_name,
            fence,
            claim,
            lease_uid,
            secret: Some(secret),
        };
        let mut next = journal
            .secret
            .take()
            .ok_or(BootstrapJournalError::OwnershipLost)?;
        let secret_uid = required(&next.metadata.uid)?.to_owned();
        let annotations = next.metadata.annotations.get_or_insert_with(BTreeMap::new);
        annotations.insert(SECRET_UID.to_owned(), secret_uid);
        annotations.insert(LEASE_UID.to_owned(), journal.lease_uid.clone());
        annotations.insert(EPOCH.to_owned(), journal.claim.token.to_string());
        journal.store_exact(next).await?;
        Ok(journal)
    }

    fn state(&self) -> Result<Option<&[u8]>> {
        if !self.fence.is_live() {
            return Err(BootstrapJournalError::OwnershipLost);
        }
        let secret = self
            .secret
            .as_ref()
            .ok_or(BootstrapJournalError::OwnershipLost)?;
        Ok(secret
            .data
            .as_ref()
            .and_then(|data| data.get(STATE))
            .map(|bytes| bytes.0.as_slice()))
    }

    async fn verify_fence(&self) -> Result<()> {
        let claim = self
            .fence
            .live_claim()
            .ok_or(BootstrapJournalError::OwnershipLost)?;
        let lease = self
            .api
            .get_lease(&self.anchor.name)
            .await?
            .ok_or(BootstrapJournalError::OwnershipLost)?;
        if required(&lease.metadata.uid)? != self.lease_uid
            || claim != self.claim
            || !lease_holds_claim(&lease, &claim)
                .map_err(|_| BootstrapJournalError::InvalidState)?
        {
            return Err(BootstrapJournalError::OwnershipLost);
        }
        Ok(())
    }

    async fn save(&mut self, state: &[u8], evidence: Option<&[u8]>) -> Result<()> {
        if state.len().saturating_add(evidence.map_or(0, <[u8]>::len)) > MAX_BOOTSTRAP_JOURNAL_BYTES
        {
            return Err(BootstrapJournalError::BudgetExceeded);
        }
        if state.is_empty() || evidence.is_some_and(<[u8]>::is_empty) {
            return Err(BootstrapJournalError::InvalidState);
        }
        let mut next = self
            .secret
            .take()
            .ok_or(BootstrapJournalError::OwnershipLost)?;
        let mut data = BTreeMap::from([(STATE.to_owned(), ByteString(state.to_vec()))]);
        if let Some(evidence) = evidence {
            data.insert(EVIDENCE.to_owned(), ByteString(evidence.to_vec()));
        }
        next.data = Some(data);
        self.store_exact(next).await
    }

    async fn store_exact(&mut self, next: Secret) -> Result<()> {
        self.verify_fence().await?;
        let result = self
            .api
            .replace_secret(&self.secret_name, &self.anchor.field_manager, &next)
            .await;
        let stored = match result {
            Ok(stored) => stored,
            Err(BootstrapJournalError::Conflict) => return Err(BootstrapJournalError::Conflict),
            Err(_) => self
                .api
                .get_secret(&self.secret_name)
                .await?
                .ok_or(BootstrapJournalError::Missing)?,
        };
        validate_secret(&stored, &self.secret_name)?;
        if stored.metadata.uid != next.metadata.uid
            || stored.data != next.data
            || ![OWNER, SECRET_UID, LEASE_UID, EPOCH]
                .into_iter()
                .all(|key| annotation(&stored, key) == annotation(&next, key))
        {
            return Err(BootstrapJournalError::OwnershipLost);
        }
        if !self.fence.is_live() {
            return Err(BootstrapJournalError::OwnershipLost);
        }
        self.secret = Some(stored);
        Ok(())
    }
}

fn required(value: &Option<String>) -> Result<&str> {
    value
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or(BootstrapJournalError::InvalidState)
}

fn annotation<'a>(secret: &'a Secret, key: &str) -> Option<&'a str> {
    secret
        .metadata
        .annotations
        .as_ref()?
        .get(key)
        .map(String::as_str)
}

fn validate_secret(secret: &Secret, name: &str) -> Result<()> {
    required(&secret.metadata.uid)?;
    required(&secret.metadata.resource_version)?;
    if required(&secret.metadata.name)? != name
        || annotation(secret, OWNER) != Some("v1")
        || secret.immutable == Some(true)
        || secret.type_.as_deref().is_some_and(|kind| kind != "Opaque")
        || secret.metadata.deletion_timestamp.is_some()
        || secret
            .string_data
            .as_ref()
            .is_some_and(|data| !data.is_empty())
    {
        return Err(BootstrapJournalError::InvalidState);
    }
    if let Some(data) = secret.data.as_ref() {
        if data.keys().any(|key| key != STATE && key != EVIDENCE)
            || data.values().any(|bytes| bytes.0.is_empty())
            || (data.contains_key(EVIDENCE) && !data.contains_key(STATE))
        {
            return Err(BootstrapJournalError::InvalidState);
        }
        if data
            .values()
            .fold(0_usize, |total, bytes| total.saturating_add(bytes.0.len()))
            > MAX_BOOTSTRAP_JOURNAL_BYTES
        {
            return Err(BootstrapJournalError::BudgetExceeded);
        }
    }
    Ok(())
}

struct KubernetesJournalApi {
    leases: Api<Lease>,
    secrets: Api<Secret>,
}

#[async_trait]
impl JournalApi for KubernetesJournalApi {
    async fn get_lease(&self, name: &str) -> Result<Option<Lease>> {
        self.leases
            .get_opt(name)
            .await
            .map_err(|_| BootstrapJournalError::ApiUnavailable)
    }
    async fn get_secret(&self, name: &str) -> Result<Option<Secret>> {
        self.secrets
            .get_opt(name)
            .await
            .map_err(|_| BootstrapJournalError::ApiUnavailable)
    }
    async fn replace_secret(
        &self,
        name: &str,
        field_manager: &str,
        secret: &Secret,
    ) -> Result<Secret> {
        let params = PostParams {
            field_manager: Some(field_manager.to_owned()),
            ..PostParams::default()
        };
        self.secrets
            .replace(name, &params, secret)
            .await
            .map_err(|error| match error {
                kube::Error::Api(response) if response.code == 409 => {
                    BootstrapJournalError::Conflict
                }
                _ => BootstrapJournalError::ApiUnavailable,
            })
    }
}

#[cfg(test)]
mod tests;
