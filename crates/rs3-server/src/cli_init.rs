//! One-shot initialization under the shared writer Lease runtime.

use super::DoctorProfile;
use anyhow::{Result, bail};
use rs3_server::{
    AnchorConfig, RuntimeConfig, V3PreparedRepositoryInit, V3RepositoryInitReport,
    WriterGuardConfig, doctor_findings,
};

pub(super) async fn wait_for_journal(
    config: &RuntimeConfig,
    path: &std::path::Path,
    timeout_seconds: u64,
) -> Result<()> {
    use std::io::Read;
    if !cfg!(feature = "k8s")
        || !config.backend.is_s3()
        || !matches!(config.anchor, AnchorConfig::KubernetesLease { .. })
    {
        bail!("projected initialization wait requires S3 and Kubernetes support");
    }
    if config.provider_conformance.report_file.is_none() {
        bail!("projected initialization wait requires a configured provider evidence file");
    }
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_seconds);
    loop {
        match std::fs::File::open(path) {
            Ok(file) => {
                // Same decoded state ceiling as the declared Kubernetes journal.
                let mut bytes = Vec::new();
                file.take(512 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| {
                        anyhow::anyhow!("projected initialization journal cannot be read")
                    })?;
                if rs3_server::v3_bootstrap_journal_is_initialized(config, &bytes)?
                    && rs3_server::provider_conformance_evidence_passed(config)
                {
                    return Ok(());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => bail!("projected initialization journal cannot be opened"),
        }
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "initialization is incomplete or current qualification is unavailable; wait budget exhausted"
            );
        }
        tokio::time::sleep_until(std::cmp::min(
            deadline,
            tokio::time::Instant::now() + std::time::Duration::from_secs(1),
        ))
        .await;
    }
}

pub(super) fn enforce_profile(
    config: &RuntimeConfig,
    profile: DoctorProfile,
    journal_qualification: bool,
) -> Result<()> {
    let findings = doctor_findings(config, profile.into());
    let mut blocking = Vec::new();
    for finding in findings {
        // Deliberate bootstrap may defer only the evidence that its journal
        // caller must qualify before repository publication.
        if finding.code == "repository.init-enabled"
            || (journal_qualification && finding.code == "maintenance.provider-conformance")
        {
            continue;
        }
        if finding.is_blocking() {
            blocking.push(finding.code);
        } else {
            tracing::warn!(code = finding.code, "initialization posture warning");
        }
    }
    if !blocking.is_empty() {
        bail!(
            "production init posture failed ({}); run `rs3-server doctor --profile production` for remediation",
            blocking.join(",")
        );
    }
    Ok(())
}

pub(super) async fn run(
    config: &RuntimeConfig,
    profile: DoctorProfile,
    journal_secret: Option<&str>,
    governance_bypass_reviewed: bool,
) -> Result<V3RepositoryInitReport> {
    let needs_journal = config.mode.allows_mutation()
        && matches!(config.anchor, AnchorConfig::KubernetesLease { .. });
    if needs_journal && journal_secret.is_none_or(str::is_empty) {
        bail!(
            "Kubernetes initialization requires --journal-secret naming a declared bootstrap Secret"
        );
    }
    if !needs_journal && journal_secret.is_some() {
        bail!("--journal-secret applies only to writable Kubernetes initialization");
    }
    let journal_qualification = needs_journal
        && config.backend.is_s3()
        && config.provider_conformance.report_file.is_none();
    enforce_profile(config, profile, journal_qualification)?;
    // Storage policy failures must precede even writer Lease acquisition.
    let prepared = V3PreparedRepositoryInit::prepare(config).await?;
    #[cfg(feature = "k8s")]
    if needs_journal && config.backend.is_s3() {
        // A journal completed under this exact configuration is verified
        // read-only. Contending for the Lease would deadlock behind a serving
        // gateway whose rollout waits for this very Job.
        let state =
            rs3_server::v3_bootstrap_journal_state(config, journal_secret.unwrap_or_default())
                .await?;
        if state
            .as_deref()
            .map(|bytes| rs3_server::v3_bootstrap_journal_is_initialized(config, bytes))
            .transpose()?
            .unwrap_or(false)
        {
            tracing::info!(
                "journaled initialization already completed for this configuration; verifying without the writer Lease"
            );
            return Ok(prepared.verify_initialized().await?);
        }
    }
    let mut guard_config = config.clone();
    if config.mode.allows_mutation()
        && matches!(config.anchor, AnchorConfig::KubernetesLease { .. })
    {
        guard_config.writer_guard = WriterGuardConfig::Required;
    }
    let guard = super::cli_writer_guard::acquire_with_policy(
        &guard_config,
        super::cli_writer_guard::LiveWriterPolicy::FailFast,
    )
    .await?;
    #[cfg(feature = "k8s")]
    let result = match guard.writer_fence() {
        Some(fence) => {
            prepared
                .initialize_with_writer_fence(
                    fence,
                    journal_secret.unwrap_or_default(),
                    governance_bypass_reviewed,
                )
                .await
        }
        None => prepared.initialize().await,
    };
    #[cfg(not(feature = "k8s"))]
    let result = {
        let _ = governance_bypass_reviewed;
        prepared.initialize().await
    };
    let release = guard.release().await;
    match result {
        Ok(report) => {
            release?;
            Ok(report)
        }
        Err(error) => {
            if release.is_err() {
                tracing::warn!("writer Lease release failed after initialization failure");
            }
            Err(error.into())
        }
    }
}
