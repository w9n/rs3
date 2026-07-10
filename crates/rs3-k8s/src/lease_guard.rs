use async_trait::async_trait;
use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{MicroTime, ObjectMeta};
use k8s_openapi::jiff::Timestamp;
use kube::api::PostParams;
use kube::{Api, Client};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::OnceCell;

use crate::{LeaseSettings, is_kube_status};

pub(crate) const WRITER_FENCE_ANNOTATION: &str = "rs3.rs/writer-fence";
pub(crate) const WRITER_RENEWAL_ANNOTATION: &str = "rs3.rs/writer-renewal";
const MAX_UPDATE_ATTEMPTS: usize = 16;
const ACQUIRE_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Minimal Kubernetes Lease API needed by acquire/renew logic.
#[async_trait]
pub trait LeaseGuardApi: Send + Sync {
    /// Returns the current Lease, or `None` when the object does not exist.
    async fn get_lease(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<Lease>, LeaseGuardError>;

    /// Creates a new Lease object.
    async fn create_lease(&self, namespace: &str, lease: &Lease) -> Result<Lease, LeaseGuardError>;

    /// Replaces an existing Lease object using Kubernetes resource-version
    /// compare-and-swap semantics carried by the object metadata.
    async fn replace_lease(
        &self,
        namespace: &str,
        name: &str,
        lease: &Lease,
    ) -> Result<Lease, LeaseGuardError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WriterFenceClaim {
    pub(crate) holder_identity: String,
    pub(crate) token: u64,
}

#[derive(Debug)]
struct LocalFenceState {
    claim: Option<WriterFenceClaim>,
    last_success: Option<Duration>,
    active: bool,
}

impl LocalFenceState {
    fn inactive() -> Self {
        Self {
            claim: None,
            last_success: None,
            active: false,
        }
    }
}

#[derive(Clone, Debug)]
struct MonotonicClock {
    started_at: Instant,
}

impl MonotonicClock {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
        }
    }

    fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }
}

/// A process-local proof that identifies one acquired writer epoch.
///
/// Kubernetes anchor updates validate both this claim and the live Lease in one
/// resource-version compare-and-swap. The local monotonic deadline prevents a
/// process that was suspended past its lease duration from resuming writes
/// before its renewal task has re-established ownership.
#[derive(Clone, Debug)]
pub struct WriterFence {
    claim: WriterFenceClaim,
    local_state: Arc<Mutex<LocalFenceState>>,
    lease_duration: Duration,
    clock: MonotonicClock,
}

impl WriterFence {
    /// Returns whether this process still has a locally live writer epoch.
    pub fn is_live(&self) -> bool {
        self.live_claim().is_some()
    }

    pub(crate) fn live_claim(&self) -> Option<WriterFenceClaim> {
        self.live_claim_at(self.clock.elapsed())
    }

    fn live_claim_at(&self, now: Duration) -> Option<WriterFenceClaim> {
        let state = self.local_state.lock().ok()?;
        if !state.active || state.claim.as_ref() != Some(&self.claim) {
            return None;
        }
        let last_success = state.last_success?;
        if now.saturating_sub(last_success) >= self.lease_duration {
            return None;
        }
        Some(self.claim.clone())
    }
}

pub(crate) fn lease_holds_claim(
    lease: &Lease,
    claim: &WriterFenceClaim,
) -> Result<bool, LeaseGuardError> {
    let current = lease_coordination_state(lease, Duration::from_secs(1))?;
    Ok(
        current.holder_identity.as_deref() == Some(claim.holder_identity.as_str())
            && current.fence_token == claim.token,
    )
}

pub(crate) fn lease_has_writer_coordination(lease: &Lease) -> bool {
    let has_annotations = lease
        .metadata
        .annotations
        .as_ref()
        .is_some_and(|annotations| {
            annotations.contains_key(WRITER_FENCE_ANNOTATION)
                || annotations.contains_key(WRITER_RENEWAL_ANNOTATION)
        });
    has_annotations
        && lease
            .spec
            .as_ref()
            .and_then(|spec| spec.holder_identity.as_ref())
            .is_some()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LeaseObservation {
    holder_identity: String,
    fence_token: u64,
    renewal: u64,
    lease_duration_seconds: i32,
}

#[derive(Clone, Debug)]
struct ObservedCompetitor {
    record: LeaseObservation,
    observed_at: Duration,
}

#[derive(Clone, Debug)]
struct LeaseCoordinationState {
    holder_identity: Option<String>,
    fence_token: u64,
    renewal: u64,
    lease_duration: Duration,
    lease_duration_seconds: i32,
}

impl LeaseCoordinationState {
    fn observation(&self) -> Option<LeaseObservation> {
        Some(LeaseObservation {
            holder_identity: self.holder_identity.clone()?,
            fence_token: self.fence_token,
            renewal: self.renewal,
            lease_duration_seconds: self.lease_duration_seconds,
        })
    }
}

/// Reusable Kubernetes Lease guard for single-owner runtime operations.
pub struct LeaseGuard<A> {
    api: A,
    settings: LeaseSettings,
    holder_identity: String,
    lease_duration: Duration,
    observation: Mutex<Option<ObservedCompetitor>>,
    local_state: Arc<Mutex<LocalFenceState>>,
    clock: MonotonicClock,
}

impl<A> LeaseGuard<A> {
    /// Creates a Lease guard around an API implementation.
    pub fn new(
        api: A,
        settings: LeaseSettings,
        holder_identity: String,
        lease_duration: Duration,
    ) -> Result<Self, LeaseGuardError> {
        if settings.name.is_empty() || settings.namespace.is_empty() || holder_identity.is_empty() {
            return Err(LeaseGuardError::InvalidConfig);
        }
        duration_seconds_i32(lease_duration)?;

        Ok(Self {
            api,
            settings,
            holder_identity,
            lease_duration,
            observation: Mutex::new(None),
            local_state: Arc::new(Mutex::new(LocalFenceState::inactive())),
            clock: MonotonicClock::new(),
        })
    }

    /// Returns the live writer fence created by a successful acquisition.
    pub fn writer_fence(&self) -> Result<WriterFence, LeaseGuardError> {
        let state = self
            .local_state
            .lock()
            .map_err(|_| LeaseGuardError::InvalidLease)?;
        let claim = state
            .claim
            .clone()
            .filter(|_| state.active)
            .ok_or(LeaseGuardError::LostLease)?;
        Ok(WriterFence {
            claim,
            local_state: Arc::clone(&self.local_state),
            lease_duration: self.lease_duration,
            clock: self.clock.clone(),
        })
    }
}

impl<A> LeaseGuard<A>
where
    A: LeaseGuardApi,
{
    /// Attempts to acquire the Lease at supplied wall and monotonic times.
    ///
    /// Wall time is written for Kubernetes interoperability and diagnostics. It
    /// is never used to decide whether a competing holder may be replaced.
    pub async fn acquire_at(
        &self,
        wall_time: Timestamp,
        monotonic_time: Duration,
    ) -> Result<LeaseGuardState, LeaseGuardError> {
        for _attempt in 0..MAX_UPDATE_ATTEMPTS {
            match self
                .api
                .get_lease(&self.settings.namespace, &self.settings.name)
                .await?
            {
                Some(lease) => {
                    let current = lease_coordination_state(&lease, self.lease_duration)?;
                    if !self.may_take_ownership(&current, monotonic_time)? {
                        return Err(LeaseGuardError::HeldByOther);
                    }
                    let claim = WriterFenceClaim {
                        holder_identity: self.holder_identity.clone(),
                        token: current
                            .fence_token
                            .checked_add(1)
                            .ok_or(LeaseGuardError::InvalidLease)?,
                    };
                    let renewal = current
                        .renewal
                        .checked_add(1)
                        .ok_or(LeaseGuardError::InvalidLease)?;
                    let updated = lease_with_guard_state(
                        lease,
                        &claim,
                        renewal,
                        self.lease_duration,
                        wall_time,
                        true,
                    )?;
                    match self
                        .api
                        .replace_lease(&self.settings.namespace, &self.settings.name, &updated)
                        .await
                    {
                        Ok(lease) => {
                            return self.record_success(lease, claim, monotonic_time);
                        }
                        Err(LeaseGuardError::Conflict) => continue,
                        Err(error) => return Err(error),
                    }
                }
                None => {
                    let claim = WriterFenceClaim {
                        holder_identity: self.holder_identity.clone(),
                        token: 1,
                    };
                    let lease = new_guard_lease(
                        &self.settings.name,
                        &claim,
                        self.lease_duration,
                        wall_time,
                    )?;
                    match self
                        .api
                        .create_lease(&self.settings.namespace, &lease)
                        .await
                    {
                        Ok(lease) => {
                            return self.record_success(lease, claim, monotonic_time);
                        }
                        Err(LeaseGuardError::Conflict) => continue,
                        Err(error) => return Err(error),
                    }
                }
            }
        }

        Err(LeaseGuardError::UpdateConflictLimit)
    }

    /// Renews an already acquired Lease at supplied wall and monotonic times.
    pub async fn renew_at(
        &self,
        wall_time: Timestamp,
        monotonic_time: Duration,
    ) -> Result<LeaseGuardState, LeaseGuardError> {
        let claim = self.current_claim()?;
        for _attempt in 0..MAX_UPDATE_ATTEMPTS {
            let Some(lease) = self
                .api
                .get_lease(&self.settings.namespace, &self.settings.name)
                .await?
            else {
                self.deactivate();
                return Err(LeaseGuardError::LostLease);
            };
            let current = lease_coordination_state(&lease, self.lease_duration)?;
            if current.holder_identity.as_deref() != Some(claim.holder_identity.as_str())
                || current.fence_token != claim.token
            {
                self.deactivate();
                return Err(LeaseGuardError::HeldByOther);
            }
            let renewal = current
                .renewal
                .checked_add(1)
                .ok_or(LeaseGuardError::InvalidLease)?;
            let updated = lease_with_guard_state(
                lease,
                &claim,
                renewal,
                self.lease_duration,
                wall_time,
                false,
            )?;
            match self
                .api
                .replace_lease(&self.settings.namespace, &self.settings.name, &updated)
                .await
            {
                Ok(lease) => return self.record_success(lease, claim, monotonic_time),
                Err(LeaseGuardError::Conflict) => continue,
                Err(error) => return Err(error),
            }
        }

        Err(LeaseGuardError::UpdateConflictLimit)
    }

    /// Releases an owned Lease with a resource-version compare-and-swap.
    pub async fn release_at(&self, wall_time: Timestamp) -> Result<(), LeaseGuardError> {
        let claim = self.current_claim()?;
        for _attempt in 0..MAX_UPDATE_ATTEMPTS {
            let Some(lease) = self
                .api
                .get_lease(&self.settings.namespace, &self.settings.name)
                .await?
            else {
                self.deactivate();
                return Err(LeaseGuardError::LostLease);
            };
            if !lease_holds_claim(&lease, &claim)? {
                self.deactivate();
                return Err(LeaseGuardError::HeldByOther);
            }
            let current = lease_coordination_state(&lease, self.lease_duration)?;
            let renewal = current
                .renewal
                .checked_add(1)
                .ok_or(LeaseGuardError::InvalidLease)?;
            let updated = lease_with_released_state(lease, renewal, wall_time)?;
            match self
                .api
                .replace_lease(&self.settings.namespace, &self.settings.name, &updated)
                .await
            {
                Ok(_) => {
                    self.deactivate();
                    return Ok(());
                }
                Err(LeaseGuardError::Conflict) => continue,
                Err(error) => return Err(error),
            }
        }

        Err(LeaseGuardError::UpdateConflictLimit)
    }

    fn may_take_ownership(
        &self,
        current: &LeaseCoordinationState,
        now: Duration,
    ) -> Result<bool, LeaseGuardError> {
        let Some(record) = current.observation() else {
            return Ok(true);
        };

        let mut observed = self
            .observation
            .lock()
            .map_err(|_| LeaseGuardError::InvalidLease)?;
        let Some(previous) = observed.as_ref() else {
            *observed = Some(ObservedCompetitor {
                record,
                observed_at: now,
            });
            return Ok(false);
        };
        if previous.record != record {
            *observed = Some(ObservedCompetitor {
                record,
                observed_at: now,
            });
            return Ok(false);
        }
        Ok(now.saturating_sub(previous.observed_at) >= current.lease_duration)
    }

    fn current_claim(&self) -> Result<WriterFenceClaim, LeaseGuardError> {
        let state = self
            .local_state
            .lock()
            .map_err(|_| LeaseGuardError::InvalidLease)?;
        state
            .claim
            .clone()
            .filter(|_| state.active)
            .ok_or(LeaseGuardError::LostLease)
    }

    fn record_success(
        &self,
        lease: Lease,
        expected_claim: WriterFenceClaim,
        monotonic_time: Duration,
    ) -> Result<LeaseGuardState, LeaseGuardError> {
        let state = lease_state_from_spec(&lease)?;
        if state.holder_identity != expected_claim.holder_identity
            || state.fence_token != expected_claim.token
        {
            self.deactivate();
            return Err(LeaseGuardError::LostLease);
        }
        let mut local = self
            .local_state
            .lock()
            .map_err(|_| LeaseGuardError::InvalidLease)?;
        local.claim = Some(expected_claim);
        local.last_success = Some(monotonic_time);
        local.active = true;
        drop(local);
        let mut observation = self
            .observation
            .lock()
            .map_err(|_| LeaseGuardError::InvalidLease)?;
        *observation = None;
        Ok(state)
    }

    fn deactivate(&self) {
        if let Ok(mut state) = self.local_state.lock() {
            state.active = false;
        }
    }
}

/// Kubernetes-backed Lease guard.
pub struct KubernetesLeaseGuard {
    inner: LeaseGuard<KubernetesLeaseGuardApi>,
}

impl KubernetesLeaseGuard {
    /// Creates a Kubernetes-backed Lease guard.
    pub fn new(
        settings: LeaseSettings,
        holder_identity: String,
        lease_duration: Duration,
    ) -> Result<Self, LeaseGuardError> {
        Ok(Self {
            inner: LeaseGuard::new(
                KubernetesLeaseGuardApi::default(),
                settings,
                holder_identity,
                lease_duration,
            )?,
        })
    }

    /// Waits until the configured Lease can be acquired safely.
    pub async fn acquire(&self) -> Result<LeaseGuardState, LeaseGuardError> {
        loop {
            match self
                .inner
                .acquire_at(Timestamp::now(), self.inner.clock.elapsed())
                .await
            {
                Err(LeaseGuardError::HeldByOther) => {
                    tokio::time::sleep(ACQUIRE_POLL_INTERVAL).await;
                }
                result => return result,
            }
        }
    }

    /// Renews the configured Lease using monotonic local liveness.
    pub async fn renew(&self) -> Result<LeaseGuardState, LeaseGuardError> {
        self.inner
            .renew_at(Timestamp::now(), self.inner.clock.elapsed())
            .await
    }

    /// Releases the writer epoch during an orderly shutdown.
    pub async fn release(&self) -> Result<(), LeaseGuardError> {
        self.inner.release_at(Timestamp::now()).await
    }

    /// Returns the writer fence established by [`Self::acquire`].
    pub fn writer_fence(&self) -> Result<WriterFence, LeaseGuardError> {
        self.inner.writer_fence()
    }
}

/// Public state written into and read back from a Lease guard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseGuardState {
    /// Identity currently holding the Lease.
    pub holder_identity: String,
    /// Monotonic fencing token for this ownership epoch.
    pub fence_token: u64,
    /// Monotonic renewal counter for liveness observation.
    pub renewal: u64,
    /// Lease duration in seconds.
    pub lease_duration_seconds: i32,
    /// Last wall-clock renewal time, retained for Kubernetes interoperability.
    pub renew_time: Timestamp,
}

/// Errors raised by reusable Lease guard operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeaseGuardError {
    /// Lease is held by another live identity.
    HeldByOther,
    /// This process no longer owns the previously acquired Lease.
    LostLease,
    /// Kubernetes update conflicted enough times that the guard gave up.
    UpdateConflictLimit,
    /// Kubernetes reported an update conflict.
    Conflict,
    /// Kubernetes API was unavailable or returned an unexpected error.
    ApiUnavailable,
    /// Lease configuration is invalid.
    InvalidConfig,
    /// Existing Lease state is missing or has invalid coordination fields.
    InvalidLease,
}

impl fmt::Display for LeaseGuardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::HeldByOther => "lease is held by another live identity",
            Self::LostLease => "writer lease ownership was lost",
            Self::UpdateConflictLimit => "lease update conflict limit exceeded",
            Self::Conflict => "lease update conflict",
            Self::ApiUnavailable => "kubernetes lease API unavailable",
            Self::InvalidConfig => "lease guard configuration is invalid",
            Self::InvalidLease => "lease has invalid coordination fields",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for LeaseGuardError {}

#[derive(Default)]
pub struct KubernetesLeaseGuardApi {
    client: OnceCell<Client>,
}

#[async_trait]
impl LeaseGuardApi for KubernetesLeaseGuardApi {
    async fn get_lease(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<Lease>, LeaseGuardError> {
        let api = self.api(namespace).await?;
        match api.get(name).await {
            Ok(lease) => Ok(Some(lease)),
            Err(error) if is_kube_status(&error, 404) => Ok(None),
            Err(_) => Err(LeaseGuardError::ApiUnavailable),
        }
    }

    async fn create_lease(&self, namespace: &str, lease: &Lease) -> Result<Lease, LeaseGuardError> {
        let api = self.api(namespace).await?;
        api.create(&PostParams::default(), lease)
            .await
            .map_err(kube_guard_error)
    }

    async fn replace_lease(
        &self,
        namespace: &str,
        name: &str,
        lease: &Lease,
    ) -> Result<Lease, LeaseGuardError> {
        let api = self.api(namespace).await?;
        api.replace(name, &PostParams::default(), lease)
            .await
            .map_err(kube_guard_error)
    }
}

impl KubernetesLeaseGuardApi {
    async fn api(&self, namespace: &str) -> Result<Api<Lease>, LeaseGuardError> {
        let client = self
            .client
            .get_or_try_init(|| async {
                Client::try_default()
                    .await
                    .map_err(|_| LeaseGuardError::ApiUnavailable)
            })
            .await?;
        Ok(Api::namespaced(client.clone(), namespace))
    }
}

fn kube_guard_error(error: kube::Error) -> LeaseGuardError {
    if is_kube_status(&error, 409) {
        LeaseGuardError::Conflict
    } else {
        LeaseGuardError::ApiUnavailable
    }
}

fn new_guard_lease(
    name: &str,
    claim: &WriterFenceClaim,
    lease_duration: Duration,
    wall_time: Timestamp,
) -> Result<Lease, LeaseGuardError> {
    lease_with_guard_state(
        Lease {
            metadata: ObjectMeta {
                name: Some(name.to_owned()),
                ..ObjectMeta::default()
            },
            spec: None,
        },
        claim,
        1,
        lease_duration,
        wall_time,
        true,
    )
}

pub(crate) fn lease_with_guard_state(
    mut lease: Lease,
    claim: &WriterFenceClaim,
    renewal: u64,
    lease_duration: Duration,
    wall_time: Timestamp,
    ownership_transition: bool,
) -> Result<Lease, LeaseGuardError> {
    let annotations = lease.metadata.annotations.get_or_insert_with(BTreeMap::new);
    annotations.insert(WRITER_FENCE_ANNOTATION.to_owned(), claim.token.to_string());
    annotations.insert(WRITER_RENEWAL_ANNOTATION.to_owned(), renewal.to_string());

    let spec = lease.spec.get_or_insert_with(LeaseSpec::default);
    let previous_holder = spec.holder_identity.as_deref();
    if ownership_transition && previous_holder != Some(claim.holder_identity.as_str()) {
        let transitions = spec.lease_transitions.unwrap_or(0);
        spec.lease_transitions = Some(if previous_holder.is_some() {
            transitions
                .checked_add(1)
                .ok_or(LeaseGuardError::InvalidLease)?
        } else {
            transitions
        });
        spec.acquire_time = Some(MicroTime(wall_time));
    }
    spec.holder_identity = Some(claim.holder_identity.clone());
    spec.lease_duration_seconds = Some(duration_seconds_i32(lease_duration)?);
    spec.renew_time = Some(MicroTime(wall_time));
    Ok(lease)
}

fn lease_with_released_state(
    mut lease: Lease,
    renewal: u64,
    wall_time: Timestamp,
) -> Result<Lease, LeaseGuardError> {
    let annotations = lease
        .metadata
        .annotations
        .as_mut()
        .ok_or(LeaseGuardError::InvalidLease)?;
    if !annotations.contains_key(WRITER_FENCE_ANNOTATION) {
        return Err(LeaseGuardError::InvalidLease);
    }
    annotations.insert(WRITER_RENEWAL_ANNOTATION.to_owned(), renewal.to_string());
    let spec = lease.spec.as_mut().ok_or(LeaseGuardError::InvalidLease)?;
    spec.holder_identity = None;
    spec.renew_time = Some(MicroTime(wall_time));
    Ok(lease)
}

fn lease_coordination_state(
    lease: &Lease,
    default_lease_duration: Duration,
) -> Result<LeaseCoordinationState, LeaseGuardError> {
    let annotations = lease.metadata.annotations.as_ref();
    let fence_token = parse_counter_annotation(annotations, WRITER_FENCE_ANNOTATION)?;
    let renewal = parse_counter_annotation(annotations, WRITER_RENEWAL_ANNOTATION)?;
    let spec = lease.spec.as_ref();
    let holder_identity = spec.and_then(|spec| spec.holder_identity.clone());
    let lease_duration_seconds = match spec.and_then(|spec| spec.lease_duration_seconds) {
        Some(seconds) if seconds > 0 => seconds,
        Some(_) => return Err(LeaseGuardError::InvalidLease),
        None => duration_seconds_i32(default_lease_duration)?,
    };
    let seconds =
        u64::try_from(lease_duration_seconds).map_err(|_| LeaseGuardError::InvalidLease)?;
    Ok(LeaseCoordinationState {
        holder_identity,
        fence_token,
        renewal,
        lease_duration: Duration::from_secs(seconds),
        lease_duration_seconds,
    })
}

fn parse_counter_annotation(
    annotations: Option<&BTreeMap<String, String>>,
    key: &'static str,
) -> Result<u64, LeaseGuardError> {
    annotations
        .and_then(|annotations| annotations.get(key))
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| LeaseGuardError::InvalidLease)
        })
        .transpose()
        .map(|value| value.unwrap_or(0))
}

fn lease_state_from_spec(lease: &Lease) -> Result<LeaseGuardState, LeaseGuardError> {
    let coordination = lease_coordination_state(lease, Duration::from_secs(1))?;
    let spec = lease.spec.as_ref().ok_or(LeaseGuardError::InvalidLease)?;
    Ok(LeaseGuardState {
        holder_identity: coordination
            .holder_identity
            .ok_or(LeaseGuardError::InvalidLease)?,
        fence_token: coordination.fence_token,
        renewal: coordination.renewal,
        lease_duration_seconds: coordination.lease_duration_seconds,
        renew_time: spec
            .renew_time
            .as_ref()
            .ok_or(LeaseGuardError::InvalidLease)?
            .0,
    })
}

fn duration_seconds_i32(duration: Duration) -> Result<i32, LeaseGuardError> {
    if duration.is_zero() || duration.subsec_nanos() != 0 {
        return Err(LeaseGuardError::InvalidConfig);
    }
    i32::try_from(duration.as_secs()).map_err(|_| LeaseGuardError::InvalidConfig)
}

#[cfg(test)]
mod tests {
    use super::{
        LeaseGuard, LeaseGuardApi, LeaseGuardError, WriterFenceClaim,
        lease_has_writer_coordination, lease_with_guard_state,
    };
    use crate::LeaseSettings;
    use async_trait::async_trait;
    use k8s_openapi::api::coordination::v1::Lease;
    use k8s_openapi::jiff::{SignedDuration, Timestamp};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex;

    #[derive(Clone, Default)]
    struct FakeLeaseApi {
        lease: Arc<Mutex<Option<Lease>>>,
    }

    #[async_trait]
    impl LeaseGuardApi for FakeLeaseApi {
        async fn get_lease(
            &self,
            _namespace: &str,
            _name: &str,
        ) -> Result<Option<Lease>, LeaseGuardError> {
            Ok(self.lease.lock().await.clone())
        }

        async fn create_lease(
            &self,
            _namespace: &str,
            lease: &Lease,
        ) -> Result<Lease, LeaseGuardError> {
            let mut current = self.lease.lock().await;
            if current.is_some() {
                return Err(LeaseGuardError::Conflict);
            }
            let mut created = lease.clone();
            created.metadata.resource_version = Some("1".to_owned());
            *current = Some(created.clone());
            Ok(created)
        }

        async fn replace_lease(
            &self,
            _namespace: &str,
            _name: &str,
            lease: &Lease,
        ) -> Result<Lease, LeaseGuardError> {
            let mut current = self.lease.lock().await;
            let Some(stored) = current.as_ref() else {
                return Err(LeaseGuardError::Conflict);
            };
            if lease.metadata.resource_version != stored.metadata.resource_version {
                return Err(LeaseGuardError::Conflict);
            }
            let next_version = stored
                .metadata
                .resource_version
                .as_deref()
                .unwrap_or("0")
                .parse::<u64>()
                .unwrap_or(0)
                .saturating_add(1);
            let mut replaced = lease.clone();
            replaced.metadata.resource_version = Some(next_version.to_string());
            *current = Some(replaced.clone());
            Ok(replaced)
        }
    }

    fn lease_guard(api: FakeLeaseApi, holder_identity: &str) -> LeaseGuard<FakeLeaseApi> {
        LeaseGuard::new(
            api,
            LeaseSettings {
                namespace: "backup".to_owned(),
                name: "v2-anchor".to_owned(),
                field_manager: "rs3-test".to_owned(),
            },
            holder_identity.to_owned(),
            Duration::from_secs(30),
        )
        .expect("valid lease guard")
    }

    fn timestamp(seconds: i64) -> Timestamp {
        Timestamp::UNIX_EPOCH
            .checked_add(SignedDuration::from_secs(seconds))
            .expect("timestamp should be valid")
    }

    fn held_lease(holder_identity: &str, fence_token: u64, renewal: u64) -> Lease {
        let mut lease = lease_with_guard_state(
            Lease::default(),
            &WriterFenceClaim {
                holder_identity: holder_identity.to_owned(),
                token: fence_token,
            },
            renewal,
            Duration::from_secs(30),
            timestamp(100),
            true,
        )
        .expect("valid lease");
        lease.metadata.resource_version = Some("1".to_owned());
        lease
    }

    #[tokio::test]
    async fn acquire_missing_lease_creates_fenced_coordination_spec() {
        let api = FakeLeaseApi::default();
        let guard = lease_guard(api.clone(), "pod-a/process-1");

        let state = guard
            .acquire_at(timestamp(100), Duration::ZERO)
            .await
            .expect("lease acquired");

        assert_eq!(state.holder_identity, "pod-a/process-1");
        assert_eq!(state.fence_token, 1);
        assert_eq!(state.renewal, 1);
        assert_eq!(state.lease_duration_seconds, 30);
        assert_eq!(state.renew_time, timestamp(100));
        let stored = api
            .lease
            .lock()
            .await
            .clone()
            .expect("lease should be stored");
        assert_eq!(stored.metadata.name.as_deref(), Some("v2-anchor"));
    }

    #[tokio::test]
    async fn wall_clock_skew_cannot_steal_an_unchanged_lease_early() {
        let api = FakeLeaseApi::default();
        *api.lease.lock().await = Some(held_lease("pod-b/process-1", 7, 11));
        let guard = lease_guard(api, "pod-a/process-2");

        let first = guard
            .acquire_at(timestamp(100_000), Duration::from_secs(10))
            .await;
        let second = guard
            .acquire_at(timestamp(-100_000), Duration::from_secs(39))
            .await;

        assert_eq!(first, Err(LeaseGuardError::HeldByOther));
        assert_eq!(second, Err(LeaseGuardError::HeldByOther));
    }

    #[tokio::test]
    async fn unchanged_competitor_can_be_replaced_after_monotonic_duration() {
        let api = FakeLeaseApi::default();
        *api.lease.lock().await = Some(held_lease("pod-b/process-1", 7, 11));
        let guard = lease_guard(api, "pod-a/process-2");

        let first = guard
            .acquire_at(timestamp(500), Duration::from_secs(10))
            .await;
        let acquired = guard
            .acquire_at(timestamp(-500), Duration::from_secs(40))
            .await
            .expect("unchanged lease may transfer after local duration");

        assert_eq!(first, Err(LeaseGuardError::HeldByOther));
        assert_eq!(acquired.holder_identity, "pod-a/process-2");
        assert_eq!(acquired.fence_token, 8);
        assert_eq!(acquired.renewal, 12);
    }

    #[tokio::test]
    async fn renewal_change_restarts_the_monotonic_observation_window() {
        let api = FakeLeaseApi::default();
        *api.lease.lock().await = Some(held_lease("pod-b/process-1", 7, 11));
        let guard = lease_guard(api.clone(), "pod-a/process-2");

        assert_eq!(
            guard.acquire_at(timestamp(0), Duration::ZERO).await,
            Err(LeaseGuardError::HeldByOther)
        );
        *api.lease.lock().await = Some(held_lease("pod-b/process-1", 7, 12));
        assert_eq!(
            guard
                .acquire_at(timestamp(10_000), Duration::from_secs(29))
                .await,
            Err(LeaseGuardError::HeldByOther)
        );
        assert_eq!(
            guard
                .acquire_at(timestamp(-10_000), Duration::from_secs(58))
                .await,
            Err(LeaseGuardError::HeldByOther)
        );
    }

    #[tokio::test]
    async fn stale_owner_cannot_renew_after_handoff() {
        let api = FakeLeaseApi::default();
        let old_guard = lease_guard(api.clone(), "pod-a/process-1");
        old_guard
            .acquire_at(timestamp(100), Duration::ZERO)
            .await
            .expect("old owner acquires");

        let new_guard = lease_guard(api, "pod-b/process-2");
        assert_eq!(
            new_guard
                .acquire_at(timestamp(90), Duration::from_secs(5))
                .await,
            Err(LeaseGuardError::HeldByOther)
        );
        let transferred = new_guard
            .acquire_at(timestamp(80), Duration::from_secs(35))
            .await
            .expect("ownership transfers");
        let stale_renewal = old_guard
            .renew_at(timestamp(1_000), Duration::from_secs(1))
            .await;

        assert_eq!(transferred.fence_token, 2);
        assert_eq!(stale_renewal, Err(LeaseGuardError::HeldByOther));
        assert!(old_guard.writer_fence().is_err());
    }

    #[tokio::test]
    async fn local_fence_expires_monotonically_without_a_successful_renewal() {
        let api = FakeLeaseApi::default();
        let guard = lease_guard(api, "pod-a/process-1");
        guard
            .acquire_at(timestamp(100), Duration::from_secs(10))
            .await
            .expect("lease acquired");
        let fence = guard.writer_fence().expect("writer fence");

        assert!(fence.live_claim_at(Duration::from_secs(39)).is_some());
        assert!(fence.live_claim_at(Duration::from_secs(40)).is_none());
    }

    #[tokio::test]
    async fn clean_release_allows_immediate_fenced_handoff() {
        let api = FakeLeaseApi::default();
        let old_guard = lease_guard(api.clone(), "pod-a/process-1");
        old_guard
            .acquire_at(timestamp(100), Duration::ZERO)
            .await
            .expect("old owner acquires");
        old_guard
            .release_at(timestamp(101))
            .await
            .expect("old owner releases");
        let released = api
            .lease
            .lock()
            .await
            .clone()
            .expect("released lease remains stored");
        assert!(!lease_has_writer_coordination(&released));

        let new_guard = lease_guard(api, "pod-b/process-2");
        let acquired = new_guard
            .acquire_at(timestamp(-1_000), Duration::ZERO)
            .await
            .expect("released lease hands off without a TTL wait");

        assert_eq!(acquired.fence_token, 2);
        assert!(old_guard.writer_fence().is_err());
    }
}
