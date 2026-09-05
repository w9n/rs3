//! Retained-profile GC rehearsal in an isolated backend prefix.

use anyhow::{Context, Result, bail};
#[cfg(feature = "s3")]
use bytes::Bytes;
use clap::{Args, Subcommand, ValueEnum};
#[cfg(feature = "s3")]
use rs3_crypto::{FormatEnvelope, KeyRing, KeyringEnvelope, RepositoryKeyContext, SecretBytes};
#[cfg(feature = "s3")]
use rs3_repository::store_keyring_envelope;
#[cfg(feature = "s3")]
use rs3_repository::v2::v2_format_object_id;
#[cfg(feature = "s3")]
use rs3_repository::v2::{
    UnenforcedQuiescedMaintenanceGuard, V2FullGcApplyOptions, V2FullGcDryRunOptions,
    V2MaintenanceBudgets, V2OrphanGcOptions, generate_v2_commit_key,
};
#[cfg(feature = "s3")]
use rs3_repository::v2::{
    V2CommitStore, V2CommitStoreOptions, V2FormatRef, V2FormatRoot, V2KeyringEnvelopeRootRef,
    V2ProviderProfile,
};
#[cfg(feature = "s3")]
use rs3_storage::PutOptions;
#[cfg(feature = "s3")]
use rs3_storage::{BlobStore, ByteRange};
#[cfg(feature = "s3")]
use rs3_storage::{S3BlobStore, S3BlobStoreConfig};
#[cfg(feature = "s3")]
use rs3_types::KeyPurpose;
#[cfg(feature = "s3")]
use rs3_types::{RepositoryId, RetentionMode, RetentionPolicy, Sequence};

/// v2 repository automation.
#[derive(Args)]
pub(crate) struct V2Args {
    #[command(subcommand)]
    command: V2Command,
}

#[derive(Subcommand)]
enum V2Command {
    /// Rehearse retained-profile v2 orphan GC against a fresh backend prefix.
    GcRehearsal(Box<V2GcRehearsalArgs>),
}

#[derive(Args)]
struct V2GcRehearsalArgs {
    /// Backend object-store target.
    #[command(flatten)]
    backend: V2BackendArgs,
    /// Retention mode used for the protected rehearsal orphan.
    #[arg(long, value_enum, default_value_t = V2RetentionModeArg::Governance)]
    retention_mode: V2RetentionModeArg,
    /// Retention duration for protected rehearsal objects.
    #[arg(long, default_value_t = 1)]
    retention_days: u32,
    /// Confirm retained-version provider conformance passed for this backend profile.
    #[arg(long, default_value_t = false)]
    retained_provider_conformance_passed: bool,
    /// Apply with the honor-system unenforced maintenance guard.
    ///
    /// Only for isolated local rehearsals where nothing else can write the
    /// rehearsal prefix. Without this flag the rehearsal acquires an enforced
    /// Kubernetes writer fence before the destructive apply.
    #[arg(long, default_value_t = false)]
    unenforced_guard: bool,
    /// Kubernetes namespace of the rehearsal writer-fence Lease.
    ///
    /// Required for the enforced (default) rehearsal path.
    #[arg(long, env = "RS3_V2_REHEARSAL_LEASE_NAMESPACE")]
    lease_namespace: Option<String>,
    /// Kubernetes Lease name fencing this rehearsal.
    ///
    /// Use a dedicated rehearsal Lease, never the gateway writer lease.
    #[arg(
        long,
        env = "RS3_V2_REHEARSAL_LEASE_NAME",
        default_value = "rs3-v2-gc-rehearsal"
    )]
    lease_name: String,
    /// Output format.
    #[arg(long, value_enum, default_value_t = V2ReportFormat::Json)]
    format: V2ReportFormat,
}

/// Maintenance-guard selection for the destructive rehearsal apply.
#[cfg(feature = "s3")]
enum RehearsalGuardMode {
    /// Honor-system guard for explicitly isolated rehearsals.
    Unenforced,
    /// Enforced Kubernetes writer fence on a dedicated rehearsal Lease.
    #[cfg(feature = "k8s")]
    KubernetesWriterFence { namespace: String, name: String },
}

#[cfg(feature = "s3")]
impl RehearsalGuardMode {
    fn label(&self) -> &'static str {
        match self {
            Self::Unenforced => "unenforced",
            #[cfg(feature = "k8s")]
            Self::KubernetesWriterFence { .. } => "kubernetes-writer-fence",
        }
    }
}

/// Resolves the rehearsal guard mode, failing closed without explicit opt-in.
#[cfg(feature = "s3")]
fn rehearsal_guard_mode(args: &V2GcRehearsalArgs) -> Result<RehearsalGuardMode> {
    if args.unenforced_guard {
        return Ok(RehearsalGuardMode::Unenforced);
    }
    #[cfg(feature = "k8s")]
    {
        let namespace = args.lease_namespace.clone().context(
            "enforced GC rehearsal needs --lease-namespace (RS3_V2_REHEARSAL_LEASE_NAMESPACE); \
             pass --unenforced-guard only for isolated rehearsals",
        )?;
        Ok(RehearsalGuardMode::KubernetesWriterFence {
            namespace,
            name: args.lease_name.clone(),
        })
    }
    #[cfg(not(feature = "k8s"))]
    bail!(
        "enforced GC rehearsal requires building xtask with the k8s feature; \
         pass --unenforced-guard only for isolated rehearsals"
    )
}

#[derive(Clone, Debug, Args)]
struct V2BackendArgs {
    /// Backend implementation used by retained GC rehearsal.
    #[arg(long, value_enum, default_value_t = V2Backend::S3)]
    backend: V2Backend,
    /// S3 bucket used with `--backend s3`.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_V2_S3_BUCKET")]
    s3_bucket: Option<String>,
    /// S3 key prefix used with `--backend s3`.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_V2_S3_PREFIX")]
    s3_prefix: Option<String>,
    /// Custom S3 endpoint URL used with `--backend s3`.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_V2_S3_ENDPOINT_URL")]
    s3_endpoint_url: Option<String>,
    /// AWS region override used with `--backend s3`.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_V2_S3_REGION")]
    s3_region: Option<String>,
    /// Allow plain HTTP for local S3-compatible endpoints used with `--backend s3`.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_V2_S3_ALLOW_HTTP", default_value_t = false)]
    s3_allow_http: bool,
    /// Use virtual-hosted bucket addressing instead of path-style addressing.
    #[cfg(feature = "s3")]
    #[arg(long, env = "RS3_V2_S3_VIRTUAL_HOSTED_STYLE", default_value_t = false)]
    s3_virtual_hosted_style: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum V2Backend {
    /// S3-compatible backend using the default environment/config chain.
    S3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum V2ReportFormat {
    /// JSON object.
    Json,
    /// Human-readable key-value lines.
    Text,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum V2RetentionModeArg {
    /// Governance retention.
    Governance,
    /// Compliance retention.
    Compliance,
}

pub(crate) fn run(args: V2Args) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build v2 automation runtime")?;
    runtime.block_on(run_async(args))
}

async fn run_async(args: V2Args) -> Result<()> {
    match args.command {
        V2Command::GcRehearsal(args) => {
            let format = args.format;
            let report = gc_rehearsal(*args).await?;
            print_gc_rehearsal_report(&report, format)?;
        }
    }
    Ok(())
}

async fn gc_rehearsal(args: V2GcRehearsalArgs) -> Result<serde_json::Value> {
    if !args.retained_provider_conformance_passed {
        bail!("--retained-provider-conformance-passed is required for retained GC rehearsal");
    }
    if args.retention_days == 0 {
        bail!("--retention-days must be greater than zero");
    }
    match args.backend.backend {
        #[cfg(not(feature = "s3"))]
        V2Backend::S3 => bail!("retained GC rehearsal requires the s3 feature"),
        #[cfg(feature = "s3")]
        V2Backend::S3 => {
            let guard_mode = rehearsal_guard_mode(&args)?;
            let mut random = [0_u8; 12];
            getrandom::fill(&mut random)
                .map_err(|_| anyhow::anyhow!("failed to create isolated rehearsal prefix"))?;
            let parent = args
                .backend
                .s3_prefix
                .as_deref()
                .unwrap_or_default()
                .trim_end_matches('/');
            let prefix = if parent.is_empty() {
                format!("rs3-gc-rehearsal/{}/", hex::encode(random))
            } else {
                format!("{parent}/rs3-gc-rehearsal/{}/", hex::encode(random))
            };
            let mut args = args;
            args.backend.s3_prefix = Some(prefix.clone());
            let store = s3_store(&args.backend).await?;
            gc_rehearsal_with_store(store, args, guard_mode).await
        }
    }
}

#[cfg(feature = "s3")]
async fn gc_rehearsal_with_store<S>(
    store: S,
    args: V2GcRehearsalArgs,
    guard_mode: RehearsalGuardMode,
) -> Result<serde_json::Value>
where
    S: BlobStore + Clone,
{
    let retention = RetentionPolicy::new(retention_mode(args.retention_mode), args.retention_days);
    for prefix in ["commits/v02/", "objects/v02/", "keyrings/", "format/"] {
        let existing = store
            .list_prefix(prefix)
            .await
            .with_context(|| format!("failed to inspect rehearsal prefix class {prefix}"))?;
        if !existing.is_empty() {
            bail!("retained GC rehearsal isolated prefix is unexpectedly non-empty");
        }
    }

    let repository_id = rehearsal_repository_id()?;
    let mut repository_salt = vec![0_u8; 32];
    getrandom::fill(&mut repository_salt)
        .map_err(|_| anyhow::anyhow!("failed to generate rehearsal repository salt"))?;
    let context = RepositoryKeyContext::new(repository_id.clone(), repository_salt)
        .context("failed to create rehearsal repository key context")?;
    let mut wrapping_key_bytes = vec![0_u8; SecretBytes::MIN_LEN];
    getrandom::fill(&mut wrapping_key_bytes)
        .map_err(|_| anyhow::anyhow!("failed to generate rehearsal wrapping key"))?;
    let wrapping_key =
        SecretBytes::new(wrapping_key_bytes).context("failed to create rehearsal wrapping key")?;
    let keyring = KeyRing::generate_random().context("failed to generate rehearsal keyring")?;
    let keyring_envelope = keyring
        .seal_keyring_envelope(&context, "gc-rehearsal-wrap", &wrapping_key, 1)
        .context("failed to seal rehearsal keyring")?;
    let keyring_reference =
        store_keyring_envelope(&store, &keyring_envelope, Some(retention), None)
            .await
            .context("failed to store rehearsal keyring envelope")?;
    let keyring_root = V2KeyringEnvelopeRootRef {
        generation: keyring_reference.generation,
        digest: keyring_reference.digest,
        object_id: keyring_reference.object_id,
        version_id: keyring_reference.version_id,
    };
    let signing_key_id = keyring
        .primary_key_id(KeyPurpose::CheckpointSigning)
        .context("rehearsal keyring has no signing key")?;
    let format_root = V2FormatRoot::new(
        repository_id.clone(),
        keyring_root.clone(),
        signing_key_id,
        V2ProviderProfile::RetainedVersionObjectLock,
        Some(retention),
    );
    let format_plaintext = format_root
        .to_plaintext_bytes()
        .context("failed to encode rehearsal format root")?;
    let format_envelope = FormatEnvelope::seal(
        &context,
        "gc-rehearsal-wrap",
        &wrapping_key,
        1,
        &format_plaintext,
    )
    .context("failed to seal rehearsal format root")?;
    let format_digest = format_envelope
        .digest()
        .context("failed to digest rehearsal format root")?;
    let format_object_id = v2_format_object_id(format_envelope.generation, &format_digest)
        .context("failed to build rehearsal format-root object ID")?;
    let format_metadata = store
        .put(
            &format_object_id,
            Bytes::from(
                format_envelope
                    .to_object_bytes()
                    .context("failed to encode rehearsal format envelope")?,
            ),
            PutOptions {
                retention: Some(retention),
                ..PutOptions::default()
            },
        )
        .await
        .context("failed to store rehearsal format root")?;
    let format_ref = V2FormatRef {
        generation: format_envelope.generation,
        digest: format_digest,
        object_id: format_object_id,
        version_id: format_metadata.version_id,
    };
    let keyring_ref = keyring_root
        .commit_ref()
        .context("failed to create rehearsal commit keyring reference")?;
    let commit_options = V2CommitStoreOptions::for_profile(
        V2ProviderProfile::RetainedVersionObjectLock,
        repository_id,
        keyring_ref,
        format_ref.clone(),
    )
    .with_maintenance_keyring_envelope_ref(keyring_root.clone())
    .with_retention(Some(retention));
    let repository = V2CommitStore::new(store.clone(), keyring, commit_options.clone());
    let anchor = rs3_repository::v2::V2MemoryAnchor::new();

    let genesis = repository
        .write_genesis_snapshot(&anchor)
        .await
        .context("failed to write retained rehearsal genesis")?;
    let unprotected_key = generate_v2_commit_key(Sequence::new(99))
        .context("failed to generate unprotected orphan key")?
        .object_id;
    let protected_key = generate_v2_commit_key(Sequence::new(100))
        .context("failed to generate protected orphan key")?
        .object_id;

    store
        .put(
            &unprotected_key,
            Bytes::from_static(b"rs3-v2-gc-rehearsal-unprotected"),
            PutOptions::default(),
        )
        .await
        .context("failed to write unprotected exact-version orphan")?;
    store
        .put(
            &protected_key,
            Bytes::from_static(b"rs3-v2-gc-rehearsal-protected"),
            PutOptions {
                retention: Some(retention),
                ..PutOptions::default()
            },
        )
        .await
        .context("failed to write retained exact-version orphan")?;

    let dry_run_options = V2FullGcDryRunOptions {
        budgets: V2MaintenanceBudgets {
            max_delete_count: Some(1),
            max_retention_extend_count: Some(3),
            ..V2MaintenanceBudgets::default()
        },
        retention_renewal_horizon: std::time::Duration::from_secs(
            u64::from(args.retention_days.saturating_add(1)) * 24 * 60 * 60,
        ),
        ..V2FullGcDryRunOptions::default()
    };
    let before = repository
        .full_gc_dry_run(&anchor, dry_run_options.clone())
        .await
        .context("failed to dry-run retained GC rehearsal")?;
    if !before.fits_budgets {
        bail!("retained GC rehearsal dry run exceeded its safety budget");
    }
    if before.fully_dead_commit_count != 1 || before.planned_cost.delete_count != 1 {
        bail!(
            "retained GC rehearsal expected one unprotected exact-version delete candidate, got {} candidates and {} planned deletes",
            before.fully_dead_commit_count,
            before.planned_cost.delete_count
        );
    }
    if before.retention_blocked_bytes == 0 {
        bail!("retained GC rehearsal expected a retention-blocked protected candidate");
    }
    if before.retention_renewal_commit_count != 3 {
        bail!(
            "retained GC rehearsal expected three live root renewals, got {}",
            before.retention_renewal_commit_count
        );
    }

    let apply_options = V2FullGcApplyOptions {
        dry_run: dry_run_options,
        orphan_gc: V2OrphanGcOptions::new_for_test_rehearsal(std::time::Duration::ZERO),
        retained_provider_conformance_passed: true,
    };
    let apply = match &guard_mode {
        RehearsalGuardMode::Unenforced => {
            eprintln!(
                "WARNING: gc-rehearsal is applying with the unenforced honor-system \
                 maintenance guard; isolated rehearsal prefixes only"
            );
            repository
                .apply_full_gc(&anchor, &UnenforcedQuiescedMaintenanceGuard, apply_options)
                .await
                .context("failed to apply retained GC rehearsal")?
        }
        #[cfg(feature = "k8s")]
        RehearsalGuardMode::KubernetesWriterFence { namespace, name } => {
            apply_with_kubernetes_writer_fence(&repository, &anchor, apply_options, namespace, name)
                .await?
        }
    };
    if let Some(error) = apply.orphan_gc.aborted {
        bail!("retained GC rehearsal apply aborted before completion: {error}");
    }
    if apply.orphan_gc.deleted_count != 1 || apply.orphan_gc.protected_count != 1 {
        bail!(
            "retained GC rehearsal expected one delete and one protected candidate, got {} deletes and {} protected",
            apply.orphan_gc.deleted_count,
            apply.orphan_gc.protected_count
        );
    }
    if apply.retention_renewed_object_count != 3 {
        bail!(
            "retained GC rehearsal expected three verified renewals, got {}",
            apply.retention_renewed_object_count
        );
    }

    let after = repository
        .full_gc_dry_run(&anchor, V2FullGcDryRunOptions::default())
        .await
        .context("failed to dry-run after retained GC rehearsal apply")?;
    if after.fully_dead_commit_count != 0 || after.retention_blocked_bytes == 0 {
        bail!("retained GC rehearsal post-apply state did not preserve only protected candidates");
    }

    let opened_format = open_format_root(
        &store,
        &context,
        "gc-rehearsal-wrap",
        &wrapping_key,
        &format_ref,
    )
    .await
    .context("failed to reopen renewed format root")?;
    if opened_format != format_root {
        bail!("renewed format root did not reopen to the expected authenticated state");
    }
    let reopened_keyring = open_keyring_envelope(
        &store,
        &context,
        "gc-rehearsal-wrap",
        &wrapping_key,
        &keyring_root,
    )
    .await
    .context("failed to reopen renewed keyring envelope")?;
    let fresh_repository = V2CommitStore::new(store.clone(), reopened_keyring, commit_options);
    let verified = fresh_repository
        .load_chain_from_anchor(&anchor)
        .await
        .context("failed to verify anchor chain through renewed restore roots")?
        .map(|chain| chain.commits_newest_first.len())
        .unwrap_or_default();

    Ok(serde_json::json!({
        "schema": "rs3.xtask.v2-gc-rehearsal.v1",
        "passed": true,
        "backend": {
            "kind": "s3",
        },
        "guard": {
            "mode": guard_mode.label(),
        },
        "retention": {
            "mode": retention_mode_name(retention.mode),
            "days": retention.retain_days,
        },
        "anchor": {
            "sequence": genesis.anchor_state.sequence.get(),
        },
        "dry_run_before": {
            "candidate_commit_count": before.candidate_commit_count,
            "fully_dead_commit_count": before.fully_dead_commit_count,
            "retention_blocked_bytes": before.retention_blocked_bytes,
            "unknown_protection_blocked_bytes": before.unknown_protection_blocked_bytes,
            "planned_delete_count": before.planned_cost.delete_count,
            "planned_request_count": before.planned_cost.request_count,
            "fits_budgets": before.fits_budgets,
            "exact_version_apply_ready": before.exact_version_apply_ready,
        },
        "apply": {
            "retention_renewed_object_count": apply.retention_renewed_object_count,
            "retention_renewed_bytes": apply.retention_renewed_bytes,
            "scanned_count": apply.orphan_gc.scanned_count,
            "deleted_count": apply.orphan_gc.deleted_count,
            "protected_count": apply.orphan_gc.protected_count,
            "failed_delete_count": apply.orphan_gc.failed_delete_count,
        },
        "dry_run_after": {
            "candidate_commit_count": after.candidate_commit_count,
            "fully_dead_commit_count": after.fully_dead_commit_count,
            "retention_blocked_bytes": after.retention_blocked_bytes,
            "planned_delete_count": after.planned_cost.delete_count,
        },
        "verification": {
            "verified_commit_count": verified,
        },
    }))
}

#[cfg(feature = "s3")]
fn rehearsal_repository_id() -> Result<RepositoryId> {
    RepositoryId::new("rs3-xtask-gc-rehearsal").map_err(Into::into)
}

#[cfg(feature = "k8s")]
const REHEARSAL_LEASE_DURATION: std::time::Duration = std::time::Duration::from_secs(30);
#[cfg(feature = "k8s")]
const REHEARSAL_LEASE_RENEW_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
#[cfg(feature = "k8s")]
const REHEARSAL_FENCE_ACQUIRE_POLL: std::time::Duration = std::time::Duration::from_secs(1);

/// Applies the rehearsal under an enforced Kubernetes writer fence.
///
/// Mirrors the gateway and offline-command fencing discipline: a live writer
/// renewing the rehearsal Lease fails the rehearsal closed, takeover of a
/// dead holder happens only after the full monotonic observation window, the
/// fence is renewed while the apply runs, and it is released on every exit
/// path.
#[cfg(feature = "k8s")]
async fn apply_with_kubernetes_writer_fence<S, A>(
    repository: &V2CommitStore<S>,
    anchor: &A,
    options: rs3_repository::v2::V2FullGcApplyOptions,
    namespace: &str,
    name: &str,
) -> Result<rs3_repository::v2::V2FullGcApplyReport>
where
    S: BlobStore + Clone,
    A: rs3_repository::v2::V2CommitAnchor,
{
    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "xtask".to_owned());
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|_| anyhow::anyhow!("failed to create rehearsal holder identity"))?;
    let holder_identity = format!("{hostname}/{}/gc-rehearsal", hex::encode(random));
    let lease_guard = std::sync::Arc::new(
        rs3_k8s::KubernetesLeaseGuard::new(
            rs3_k8s::LeaseSettings {
                namespace: namespace.to_owned(),
                name: name.to_owned(),
                field_manager: "rs3-xtask".to_owned(),
            },
            holder_identity,
            REHEARSAL_LEASE_DURATION,
        )
        .context("failed to configure rehearsal writer lease guard")?,
    );

    acquire_rehearsal_fence(&lease_guard).await?;
    let renew_task = tokio::spawn(renew_rehearsal_fence(std::sync::Arc::clone(&lease_guard)));
    let fence = lease_guard
        .writer_fence()
        .context("failed to establish rehearsal writer fencing token")?;
    let result = repository.apply_full_gc(anchor, &fence, options).await;
    renew_task.abort();
    let release = lease_guard.release().await;
    let apply = result.context("failed to apply retained GC rehearsal")?;
    release.context("failed to release rehearsal writer fence")?;
    Ok(apply)
}

#[cfg(feature = "k8s")]
async fn acquire_rehearsal_fence(lease_guard: &rs3_k8s::KubernetesLeaseGuard) -> Result<()> {
    let deadline = std::time::Instant::now() + 4 * REHEARSAL_LEASE_DURATION;
    loop {
        match lease_guard.try_acquire().await {
            Ok(_state) => return Ok(()),
            Err(rs3_k8s::LeaseGuardError::HeldByOther) => {
                if std::time::Instant::now() >= deadline {
                    bail!("rehearsal writer fence takeover observation did not resolve in time");
                }
                tokio::time::sleep(REHEARSAL_FENCE_ACQUIRE_POLL).await;
            }
            Err(error @ rs3_k8s::LeaseGuardError::HeldByLiveWriter) => {
                bail!("refusing GC rehearsal while a live writer holds the fence: {error}");
            }
            Err(error) => {
                return Err(error).context("failed to acquire rehearsal writer fence");
            }
        }
    }
}

/// Renews the rehearsal fence until release or loss of ownership.
///
/// On loss of ownership the local fence goes dead and the engine's
/// per-mutation guard checks fail the apply closed at the next boundary.
#[cfg(feature = "k8s")]
async fn renew_rehearsal_fence(lease_guard: std::sync::Arc<rs3_k8s::KubernetesLeaseGuard>) {
    loop {
        tokio::time::sleep(REHEARSAL_LEASE_RENEW_INTERVAL).await;
        if let Err(error) = lease_guard.renew().await {
            eprintln!("rehearsal writer fence renewal failed: {error}");
            if matches!(
                error,
                rs3_k8s::LeaseGuardError::HeldByOther
                    | rs3_k8s::LeaseGuardError::HeldByLiveWriter
                    | rs3_k8s::LeaseGuardError::LostLease
            ) {
                break;
            }
        }
    }
}

#[cfg(feature = "s3")]
fn retention_mode(mode: V2RetentionModeArg) -> RetentionMode {
    match mode {
        V2RetentionModeArg::Governance => RetentionMode::Governance,
        V2RetentionModeArg::Compliance => RetentionMode::Compliance,
    }
}

fn print_gc_rehearsal_report(report: &serde_json::Value, format: V2ReportFormat) -> Result<()> {
    match format {
        V2ReportFormat::Json => {
            println!("{}", serde_json::to_string_pretty(report)?);
        }
        V2ReportFormat::Text => {
            println!("schema={}", report["schema"].as_str().unwrap_or_default());
            println!("passed={}", report["passed"].as_bool().unwrap_or(false));
            println!(
                "backend_kind={}",
                report["backend"]["kind"].as_str().unwrap_or_default()
            );
            println!(
                "guard_mode={}",
                report["guard"]["mode"].as_str().unwrap_or_default()
            );
            println!(
                "retention_mode={}",
                report["retention"]["mode"].as_str().unwrap_or_default()
            );
            println!(
                "retention_days={}",
                report["retention"]["days"].as_u64().unwrap_or_default()
            );
            println!(
                "dry_run_before_candidates={}",
                report["dry_run_before"]["candidate_commit_count"]
                    .as_u64()
                    .unwrap_or_default()
            );
            println!(
                "dry_run_before_fully_dead={}",
                report["dry_run_before"]["fully_dead_commit_count"]
                    .as_u64()
                    .unwrap_or_default()
            );
            println!(
                "dry_run_before_retention_blocked_bytes={}",
                report["dry_run_before"]["retention_blocked_bytes"]
                    .as_u64()
                    .unwrap_or_default()
            );
            println!(
                "apply_deleted_count={}",
                report["apply"]["deleted_count"]
                    .as_u64()
                    .unwrap_or_default()
            );
            println!(
                "apply_protected_count={}",
                report["apply"]["protected_count"]
                    .as_u64()
                    .unwrap_or_default()
            );
            println!(
                "dry_run_after_candidates={}",
                report["dry_run_after"]["candidate_commit_count"]
                    .as_u64()
                    .unwrap_or_default()
            );
            println!(
                "verified_commit_count={}",
                report["verification"]["verified_commit_count"]
                    .as_u64()
                    .unwrap_or_default()
            );
        }
    }
    Ok(())
}

#[cfg(feature = "s3")]
async fn open_format_root<S>(
    store: &S,
    context: &RepositoryKeyContext,
    wrapping_key_id: &str,
    wrapping_key: &SecretBytes,
    reference: &V2FormatRef,
) -> Result<V2FormatRoot>
where
    S: BlobStore,
{
    let body = store
        .get_range_at(
            &reference.object_id,
            reference.version_id.as_ref(),
            ByteRange::Full,
        )
        .await
        .context("failed to read v2 format root envelope")?;
    let envelope = FormatEnvelope::from_object_bytes(body.as_ref())
        .context("failed to decode v2 format root envelope")?;
    if envelope.generation != reference.generation || envelope.digest()? != reference.digest {
        bail!("v2 format root object does not match the bundle reference");
    }
    let plaintext = envelope
        .open(context, wrapping_key_id, wrapping_key)
        .context("failed to open v2 format root envelope")?;
    V2FormatRoot::from_plaintext_bytes(&plaintext).context("failed to decode v2 format root")
}

#[cfg(feature = "s3")]
async fn open_keyring_envelope<S>(
    store: &S,
    context: &RepositoryKeyContext,
    wrapping_key_id: &str,
    wrapping_key: &SecretBytes,
    reference: &V2KeyringEnvelopeRootRef,
) -> Result<KeyRing>
where
    S: BlobStore,
{
    let body = store
        .get_range_at(
            &reference.object_id,
            reference.version_id.as_ref(),
            ByteRange::Full,
        )
        .await
        .context("failed to read v2 keyring envelope")?;
    let envelope = KeyringEnvelope::from_object_bytes(body.as_ref())
        .context("failed to decode keyring envelope")?;
    if envelope.generation != reference.generation || envelope.digest()? != reference.digest {
        bail!("v2 keyring envelope does not match the format-root reference");
    }
    envelope
        .open(context, wrapping_key_id, wrapping_key)
        .context("failed to open v2 keyring envelope")
}

#[cfg(feature = "s3")]
async fn s3_store(args: &V2BackendArgs) -> Result<S3BlobStore> {
    let bucket = args
        .s3_bucket
        .clone()
        .context("--s3-bucket or RS3_V2_S3_BUCKET is required with --backend s3")?;
    let config = S3BlobStoreConfig::new(bucket)
        .context("failed to create S3 backend config")?
        .with_prefix(args.s3_prefix.clone())
        .with_endpoint_url(args.s3_endpoint_url.clone())
        .with_region(args.s3_region.clone())
        .with_allow_http(args.s3_allow_http)
        .with_virtual_hosted_style(args.s3_virtual_hosted_style);
    S3BlobStore::from_environment(config)
        .await
        .context("failed to create S3 backend")
}

#[cfg(feature = "s3")]
fn retention_mode_name(mode: RetentionMode) -> &'static str {
    match mode {
        RetentionMode::None => "none",
        RetentionMode::Governance => "governance",
        RetentionMode::Compliance => "compliance",
    }
}

#[cfg(test)]
mod tests {
    fn parse_gc_rehearsal_args(arguments: &[&str]) -> super::V2GcRehearsalArgs {
        use clap::Parser;
        let mut full = vec!["xtask", "v2", "gc-rehearsal"];
        full.extend_from_slice(arguments);
        let cli = crate::Cli::try_parse_from(full)
            .unwrap_or_else(|error| panic!("parse gc-rehearsal arguments: {error}"));
        let Some(crate::Commands::V2(args)) = cli.command else {
            panic!("expected v2 command");
        };
        let super::V2Command::GcRehearsal(args) = args.command;
        *args
    }

    #[test]
    fn gc_rehearsal_guard_is_enforced_unless_explicitly_unenforced() {
        let default_args = parse_gc_rehearsal_args(&["--retained-provider-conformance-passed"]);
        assert!(!default_args.unenforced_guard);
        assert_eq!(default_args.lease_name, "rs3-v2-gc-rehearsal");

        let isolated = parse_gc_rehearsal_args(&[
            "--retained-provider-conformance-passed",
            "--unenforced-guard",
            "--lease-namespace",
            "backup",
            "--lease-name",
            "rehearsal-fence",
        ]);
        assert!(isolated.unenforced_guard);
        assert_eq!(isolated.lease_namespace.as_deref(), Some("backup"));
        assert_eq!(isolated.lease_name, "rehearsal-fence");
    }
}
