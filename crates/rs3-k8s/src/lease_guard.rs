use async_trait::async_trait;
use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{MicroTime, ObjectMeta};
use k8s_openapi::jiff::{SignedDuration, Timestamp};
use kube::api::PostParams;
use kube::{Api, Client};
use std::fmt;
use std::time::Duration;
use tokio::sync::OnceCell;

use crate::{LeaseSettings, is_kube_status};

const MAX_UPDATE_ATTEMPTS: usize = 16;

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

/// Reusable Kubernetes Lease guard for single-owner runtime operations.
pub struct LeaseGuard<A> {
    api: A,
    settings: LeaseSettings,
    holder_identity: String,
    lease_duration: Duration,
}

impl<A> LeaseGuard<A> {
    /// Creates a Lease guard around an API implementation.
    pub fn new(
        api: A,
        settings: LeaseSettings,
        holder_identity: String,
        lease_duration: Duration,
    ) -> Result<Self, LeaseGuardError> {
        if settings.name.is_empty() {
            return Err(LeaseGuardError::InvalidConfig);
        }
        if settings.namespace.is_empty() {
            return Err(LeaseGuardError::InvalidConfig);
        }
        if holder_identity.is_empty() {
            return Err(LeaseGuardError::InvalidConfig);
        }
        duration_seconds_i32(lease_duration)?;

        Ok(Self {
            api,
            settings,
            holder_identity,
            lease_duration,
        })
    }
}

impl<A> LeaseGuard<A>
where
    A: LeaseGuardApi,
{
    /// Acquires the Lease at the supplied time.
    pub async fn acquire_at(&self, now: Timestamp) -> Result<LeaseGuardState, LeaseGuardError> {
        self.acquire_or_renew_at(now).await
    }

    /// Renews the Lease at the supplied time.
    pub async fn renew_at(&self, now: Timestamp) -> Result<LeaseGuardState, LeaseGuardError> {
        self.acquire_or_renew_at(now).await
    }

    async fn acquire_or_renew_at(
        &self,
        now: Timestamp,
    ) -> Result<LeaseGuardState, LeaseGuardError> {
        for _attempt in 0..MAX_UPDATE_ATTEMPTS {
            match self
                .api
                .get_lease(&self.settings.namespace, &self.settings.name)
                .await?
            {
                Some(lease) => {
                    if lease_is_held_by_other_and_fresh(
                        &lease,
                        &self.holder_identity,
                        now,
                        self.lease_duration,
                    ) {
                        return Err(LeaseGuardError::HeldByOther);
                    }
                    let updated = lease_with_guard_state(
                        lease,
                        &self.holder_identity,
                        self.lease_duration,
                        now,
                    )?;
                    match self
                        .api
                        .replace_lease(&self.settings.namespace, &self.settings.name, &updated)
                        .await
                    {
                        Ok(lease) => return lease_state_from_spec(&lease),
                        Err(LeaseGuardError::Conflict) => continue,
                        Err(error) => return Err(error),
                    }
                }
                None => {
                    let lease = new_guard_lease(
                        &self.settings.name,
                        &self.holder_identity,
                        self.lease_duration,
                        now,
                    )?;
                    match self
                        .api
                        .create_lease(&self.settings.namespace, &lease)
                        .await
                    {
                        Ok(lease) => return lease_state_from_spec(&lease),
                        Err(LeaseGuardError::Conflict) => continue,
                        Err(error) => return Err(error),
                    }
                }
            }
        }

        Err(LeaseGuardError::UpdateConflictLimit)
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

    /// Acquires the configured Lease using the current wall-clock time.
    pub async fn acquire(&self) -> Result<LeaseGuardState, LeaseGuardError> {
        self.inner.acquire_at(Timestamp::now()).await
    }

    /// Renews the configured Lease using the current wall-clock time.
    pub async fn renew(&self) -> Result<LeaseGuardState, LeaseGuardError> {
        self.inner.renew_at(Timestamp::now()).await
    }
}

/// Public state written into and read back from a Lease guard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseGuardState {
    /// Identity currently holding the Lease.
    pub holder_identity: String,
    /// Lease duration in seconds.
    pub lease_duration_seconds: i32,
    /// Last renewal time.
    pub renew_time: Timestamp,
}

/// Errors raised by reusable Lease guard operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeaseGuardError {
    /// Lease is held by another live identity.
    HeldByOther,
    /// Kubernetes update conflicted enough times that the guard gave up.
    UpdateConflictLimit,
    /// Kubernetes reported an update conflict.
    Conflict,
    /// Kubernetes API was unavailable or returned an unexpected error.
    ApiUnavailable,
    /// Lease configuration is invalid.
    InvalidConfig,
    /// Existing Lease state is missing required coordination fields.
    InvalidLease,
}

impl fmt::Display for LeaseGuardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::HeldByOther => "lease is held by another live identity",
            Self::UpdateConflictLimit => "lease update conflict limit exceeded",
            Self::Conflict => "lease update conflict",
            Self::ApiUnavailable => "kubernetes lease API unavailable",
            Self::InvalidConfig => "lease guard configuration is invalid",
            Self::InvalidLease => "lease is missing required coordination fields",
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
    holder_identity: &str,
    lease_duration: Duration,
    now: Timestamp,
) -> Result<Lease, LeaseGuardError> {
    lease_with_guard_state(
        Lease {
            metadata: ObjectMeta {
                name: Some(name.to_owned()),
                ..ObjectMeta::default()
            },
            spec: None,
        },
        holder_identity,
        lease_duration,
        now,
    )
}

fn lease_with_guard_state(
    mut lease: Lease,
    holder_identity: &str,
    lease_duration: Duration,
    now: Timestamp,
) -> Result<Lease, LeaseGuardError> {
    let spec = lease.spec.get_or_insert_with(LeaseSpec::default);
    spec.holder_identity = Some(holder_identity.to_owned());
    spec.lease_duration_seconds = Some(duration_seconds_i32(lease_duration)?);
    spec.renew_time = Some(MicroTime(now));
    Ok(lease)
}

fn lease_state_from_spec(lease: &Lease) -> Result<LeaseGuardState, LeaseGuardError> {
    let spec = lease.spec.as_ref().ok_or(LeaseGuardError::InvalidLease)?;
    Ok(LeaseGuardState {
        holder_identity: spec
            .holder_identity
            .clone()
            .ok_or(LeaseGuardError::InvalidLease)?,
        lease_duration_seconds: spec
            .lease_duration_seconds
            .ok_or(LeaseGuardError::InvalidLease)?,
        renew_time: spec
            .renew_time
            .as_ref()
            .ok_or(LeaseGuardError::InvalidLease)?
            .0,
    })
}

fn lease_is_held_by_other_and_fresh(
    lease: &Lease,
    holder_identity: &str,
    now: Timestamp,
    default_lease_duration: Duration,
) -> bool {
    let Some(spec) = lease.spec.as_ref() else {
        return false;
    };
    let Some(existing_holder) = spec.holder_identity.as_deref() else {
        return false;
    };
    if existing_holder == holder_identity {
        return false;
    }

    let Some(renew_time) = spec.renew_time.as_ref().map(|renew_time| renew_time.0) else {
        return true;
    };
    let lease_duration = spec
        .lease_duration_seconds
        .and_then(|seconds| u64::try_from(seconds).ok())
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
        .unwrap_or(default_lease_duration);

    !lease_is_expired(renew_time, now, lease_duration)
}

fn lease_is_expired(renew_time: Timestamp, now: Timestamp, lease_duration: Duration) -> bool {
    let Ok(lease_seconds) = i64::try_from(lease_duration.as_secs()) else {
        return false;
    };
    let elapsed = renew_time.duration_until(now);
    elapsed >= SignedDuration::from_secs(lease_seconds)
}

fn duration_seconds_i32(duration: Duration) -> Result<i32, LeaseGuardError> {
    if duration.is_zero() {
        return Err(LeaseGuardError::InvalidConfig);
    }
    i32::try_from(duration.as_secs()).map_err(|_| LeaseGuardError::InvalidConfig)
}

#[cfg(test)]
mod tests {
    use super::{LeaseGuard, LeaseGuardApi, LeaseGuardError, lease_with_guard_state};
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
            *current = Some(lease.clone());
            Ok(lease.clone())
        }

        async fn replace_lease(
            &self,
            _namespace: &str,
            _name: &str,
            lease: &Lease,
        ) -> Result<Lease, LeaseGuardError> {
            *self.lease.lock().await = Some(lease.clone());
            Ok(lease.clone())
        }
    }

    fn lease_guard(api: FakeLeaseApi, holder_identity: &str) -> LeaseGuard<FakeLeaseApi> {
        LeaseGuard::new(
            api,
            LeaseSettings {
                namespace: "backup".to_owned(),
                name: "v2-anchor-writer".to_owned(),
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

    fn held_lease(holder_identity: &str, renewed_at: Timestamp) -> Lease {
        lease_with_guard_state(
            Lease::default(),
            holder_identity,
            Duration::from_secs(30),
            renewed_at,
        )
        .expect("valid lease")
    }

    #[tokio::test]
    async fn acquire_missing_lease_creates_standard_coordination_spec() {
        let api = FakeLeaseApi::default();
        let guard = lease_guard(api.clone(), "pod-a");

        let state = guard
            .acquire_at(timestamp(100))
            .await
            .expect("lease acquired");

        assert_eq!(state.holder_identity, "pod-a");
        assert_eq!(state.lease_duration_seconds, 30);
        assert_eq!(state.renew_time, timestamp(100));
        let stored = api
            .lease
            .lock()
            .await
            .clone()
            .expect("lease should be stored");
        assert_eq!(stored.metadata.name.as_deref(), Some("v2-anchor-writer"));
    }

    #[tokio::test]
    async fn acquire_fails_when_other_holder_is_not_expired() {
        let api = FakeLeaseApi::default();
        *api.lease.lock().await = Some(held_lease("pod-b", timestamp(100)));
        let guard = lease_guard(api, "pod-a");

        let result = guard.acquire_at(timestamp(120)).await;

        assert_eq!(result, Err(LeaseGuardError::HeldByOther));
    }

    #[tokio::test]
    async fn acquire_replaces_expired_other_holder() {
        let api = FakeLeaseApi::default();
        *api.lease.lock().await = Some(held_lease("pod-b", timestamp(100)));
        let guard = lease_guard(api, "pod-a");

        let state = guard
            .acquire_at(timestamp(131))
            .await
            .expect("expired lease should be acquired");

        assert_eq!(state.holder_identity, "pod-a");
        assert_eq!(state.renew_time, timestamp(131));
    }

    #[tokio::test]
    async fn renew_updates_owned_lease_time() {
        let api = FakeLeaseApi::default();
        *api.lease.lock().await = Some(held_lease("pod-a", timestamp(100)));
        let guard = lease_guard(api, "pod-a");

        let state = guard
            .renew_at(timestamp(110))
            .await
            .expect("owned lease should renew");

        assert_eq!(state.holder_identity, "pod-a");
        assert_eq!(state.renew_time, timestamp(110));
    }
}
