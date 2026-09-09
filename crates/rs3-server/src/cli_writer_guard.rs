//! Shared writer Lease ownership for serving and repository initialization.

#[cfg(feature = "k8s")]
use super::{WRITER_LEASE_DURATION, WRITER_LEASE_RENEW_INTERVAL, random_hex};
#[cfg(feature = "k8s")]
use anyhow::Context;
use anyhow::{Result, bail};
#[cfg(feature = "k8s")]
use rs3_k8s::{KubernetesLeaseGuard, LeaseGuardError, LeaseSettings, WriterFence};
use rs3_server::{
    AdminReadiness, AdminReadinessSource, AnchorConfig, RuntimeConfig, WriterGuardConfig,
};
use tokio::sync::watch;

pub(super) struct WriterGuardRuntime {
    shutdown: Option<watch::Receiver<bool>>,
    held: std::sync::Arc<std::sync::atomic::AtomicBool>,
    required: bool,
    #[cfg(feature = "k8s")]
    writer_fence: Option<WriterFence>,
    #[cfg(feature = "k8s")]
    lease_guard: Option<std::sync::Arc<KubernetesLeaseGuard>>,
    renew_task: Option<tokio::task::JoinHandle<()>>,
}

impl WriterGuardRuntime {
    fn disabled() -> Self {
        Self {
            shutdown: None,
            held: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            required: false,
            #[cfg(feature = "k8s")]
            writer_fence: None,
            #[cfg(feature = "k8s")]
            lease_guard: None,
            renew_task: None,
        }
    }

    #[cfg(feature = "k8s")]
    pub(super) fn writer_fence(&self) -> Option<WriterFence> {
        self.writer_fence.clone()
    }

    pub(super) fn shutdown(&self) -> Option<watch::Receiver<bool>> {
        self.shutdown.clone()
    }

    pub(super) fn readiness_source(
        &self,
        repository: std::sync::Arc<dyn AdminReadinessSource>,
    ) -> std::sync::Arc<dyn AdminReadinessSource> {
        std::sync::Arc::new(ServeReadinessSource {
            repository,
            writer_guard_held: std::sync::Arc::clone(&self.held),
            writer_guard_required: self.required,
            #[cfg(feature = "k8s")]
            writer_fence: self.writer_fence.clone(),
        })
    }

    pub(super) async fn release(&self) -> Result<()> {
        self.held.store(false, std::sync::atomic::Ordering::Release);
        if let Some(renew_task) = self.renew_task.as_ref() {
            renew_task.abort();
        }
        #[cfg(feature = "k8s")]
        if let Some(lease_guard) = self.lease_guard.as_ref() {
            lease_guard
                .release()
                .await
                .context("failed to release writer fence during orderly shutdown")?;
        }
        Ok(())
    }
}

struct ServeReadinessSource {
    repository: std::sync::Arc<dyn AdminReadinessSource>,
    writer_guard_held: std::sync::Arc<std::sync::atomic::AtomicBool>,
    writer_guard_required: bool,
    #[cfg(feature = "k8s")]
    writer_fence: Option<WriterFence>,
}

#[async_trait::async_trait]
impl AdminReadinessSource for ServeReadinessSource {
    async fn check_readiness(&self) -> AdminReadiness {
        if self.writer_guard_required
            && (!self
                .writer_guard_held
                .load(std::sync::atomic::Ordering::Acquire)
                || !writer_fence_is_live(self))
        {
            return AdminReadiness::unavailable("writer-guard.not-held");
        }
        self.repository.check_readiness().await
    }
}

fn writer_fence_is_live(_readiness: &ServeReadinessSource) -> bool {
    #[cfg(feature = "k8s")]
    {
        _readiness
            .writer_fence
            .as_ref()
            .is_some_and(WriterFence::is_live)
    }
    #[cfg(not(feature = "k8s"))]
    {
        true
    }
}

/// How acquisition treats a Lease that a live writer keeps renewing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LiveWriterPolicy {
    /// Serving waits for the current writer to exit or expire.
    Wait,
    /// One-shot commands fail closed instead of deadlocking behind a gateway
    /// that only exits once they finish.
    FailFast,
}

pub(super) async fn acquire(config: &RuntimeConfig) -> Result<WriterGuardRuntime> {
    acquire_with_policy(config, LiveWriterPolicy::Wait).await
}

pub(super) async fn acquire_with_policy(
    config: &RuntimeConfig,
    policy: LiveWriterPolicy,
) -> Result<WriterGuardRuntime> {
    if !config.mode.allows_mutation() || config.writer_guard == WriterGuardConfig::Off {
        return Ok(WriterGuardRuntime::disabled());
    }

    let AnchorConfig::KubernetesLease {
        namespace,
        name,
        field_manager,
    } = &config.anchor
    else {
        bail!("RS3_WRITER_GUARD=required needs RS3_ANCHOR_MODE=kubernetes-lease");
    };

    #[cfg(feature = "k8s")]
    {
        let hostname = std::env::var("HOSTNAME")
            .context("RS3_WRITER_GUARD=required needs HOSTNAME to identify this writer pod")?;
        let holder_identity = format!("{hostname}/{}", random_hex(16)?);
        let lease_guard = KubernetesLeaseGuard::new(
            LeaseSettings {
                namespace: namespace.clone(),
                name: name.clone(),
                field_manager: field_manager.clone(),
            },
            holder_identity,
            WRITER_LEASE_DURATION,
        )
        .context("failed to configure writer lease guard")?;

        match policy {
            LiveWriterPolicy::Wait => lease_guard
                .acquire()
                .await
                .context("failed to acquire writer lease guard")?,
            LiveWriterPolicy::FailFast => match lease_guard.acquire_unless_live_writer().await {
                Ok(state) => state,
                Err(LeaseGuardError::HeldByLiveWriter) => bail!(
                    "the anchor Lease is held by a live gateway writer; initialization and fresh qualification need exclusive ownership. A completed journal is verified without the Lease, so stop the serving gateway only when this run must initialize or requalify"
                ),
                Err(error) => {
                    return Err(
                        anyhow::Error::new(error).context("failed to acquire writer lease guard")
                    );
                }
            },
        };
        let writer_fence = lease_guard
            .writer_fence()
            .context("failed to establish writer fencing token")?;
        tracing::info!("writer lease guard acquired");

        let lease_guard = std::sync::Arc::new(lease_guard);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let held = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let renew_task = tokio::spawn(renew_writer_guard(
            std::sync::Arc::clone(&lease_guard),
            shutdown_tx,
            std::sync::Arc::clone(&held),
        ));

        Ok(WriterGuardRuntime {
            shutdown: Some(shutdown_rx),
            held,
            required: true,
            writer_fence: Some(writer_fence),
            lease_guard: Some(lease_guard),
            renew_task: Some(renew_task),
        })
    }

    #[cfg(not(feature = "k8s"))]
    {
        let _ = namespace;
        let _ = name;
        let _ = field_manager;
        let _ = policy;
        bail!("RS3_WRITER_GUARD=required needs the k8s feature");
    }
}

#[cfg(feature = "k8s")]
async fn renew_writer_guard(
    lease_guard: std::sync::Arc<KubernetesLeaseGuard>,
    shutdown_tx: watch::Sender<bool>,
    held: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let mut last_success = std::time::Instant::now();
    loop {
        tokio::time::sleep(WRITER_LEASE_RENEW_INTERVAL).await;
        match lease_guard.renew().await {
            Ok(_) => {
                last_success = std::time::Instant::now();
            }
            Err(error) => {
                let elapsed = last_success.elapsed();
                tracing::warn!(
                    %error,
                    elapsed_ms = elapsed.as_millis(),
                    "writer lease renewal failed",
                );
                if matches!(
                    error,
                    LeaseGuardError::HeldByOther | LeaseGuardError::LostLease
                ) {
                    held.store(false, std::sync::atomic::Ordering::Release);
                    tracing::error!(
                        "writer lease is held by another live identity; initiating graceful shutdown",
                    );
                    let _ = shutdown_tx.send(true);
                    break;
                }
                if elapsed >= WRITER_LEASE_DURATION {
                    held.store(false, std::sync::atomic::Ordering::Release);
                    tracing::error!(
                        "writer lease renewal failed past the lease duration; initiating graceful shutdown",
                    );
                    let _ = shutdown_tx.send(true);
                    break;
                }
            }
        }
    }
}

impl Drop for WriterGuardRuntime {
    fn drop(&mut self) {
        self.held.store(false, std::sync::atomic::Ordering::Release);
        if let Some(task) = self.renew_task.as_ref() {
            task.abort();
        }
        // Cancellation stops renewal. The provider Lease then expires naturally;
        // asynchronous release must not outlive an unfinished mutation.
    }
}

#[cfg(test)]
mod tests {
    use super::WriterGuardRuntime;
    use std::sync::atomic::Ordering;
    use tokio::sync::oneshot;

    struct DropSignal(Option<oneshot::Sender<()>>);
    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    #[tokio::test]
    async fn cancellation_and_orderly_release_stop_lease_renewal() {
        for orderly in [false, true] {
            let mut guard = WriterGuardRuntime::disabled();
            let held = guard.held.clone();
            let (started_tx, started_rx) = oneshot::channel();
            let (dropped_tx, dropped_rx) = oneshot::channel();
            guard.renew_task = Some(tokio::spawn(async move {
                let _dropped = DropSignal(Some(dropped_tx));
                let _ = started_tx.send(());
                std::future::pending::<()>().await;
            }));
            started_rx.await.expect("renewal running");
            if orderly {
                guard.release().await.expect("release");
            }
            drop(guard);
            tokio::time::timeout(std::time::Duration::from_secs(1), dropped_rx)
                .await
                .expect("renewal is cancelled")
                .expect("renewal destructor runs");
            assert!(!held.load(Ordering::Acquire));
        }
    }
}
