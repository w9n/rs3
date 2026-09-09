use super::{LeaseGuardApi, LeaseGuardError};
use async_trait::async_trait;
use k8s_openapi::api::coordination::v1::Lease;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Operation {
    Get,
    Create,
    Replace,
}

pub(crate) struct Fault {
    pub(crate) operation: Operation,
    pub(crate) error: LeaseGuardError,
    pub(crate) concurrent_lease: Option<Lease>,
}

#[derive(Clone, Default)]
pub(crate) struct FakeLeaseApi {
    pub(crate) lease: Arc<Mutex<Option<Lease>>>,
    pub(crate) calls: Arc<Mutex<Vec<Operation>>>,
    pub(crate) faults: Arc<Mutex<VecDeque<Fault>>>,
}

impl FakeLeaseApi {
    async fn before(&self, operation: Operation) -> Result<(), LeaseGuardError> {
        self.calls.lock().await.push(operation);
        let mut faults = self.faults.lock().await;
        if faults
            .front()
            .is_some_and(|fault| fault.operation == operation)
        {
            let fault = faults.pop_front().expect("matching fault exists");
            if let Some(lease) = fault.concurrent_lease {
                *self.lease.lock().await = Some(lease);
            }
            return Err(fault.error);
        }
        Ok(())
    }
}

#[async_trait]
impl LeaseGuardApi for FakeLeaseApi {
    async fn get_lease(
        &self,
        _namespace: &str,
        _name: &str,
    ) -> Result<Option<Lease>, LeaseGuardError> {
        self.before(Operation::Get).await?;
        Ok(self.lease.lock().await.clone())
    }

    async fn create_lease(
        &self,
        _namespace: &str,
        lease: &Lease,
    ) -> Result<Lease, LeaseGuardError> {
        self.before(Operation::Create).await?;
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
        self.before(Operation::Replace).await?;
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
