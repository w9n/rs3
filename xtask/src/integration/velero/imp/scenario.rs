//! Scenario model shared by Velero integration lanes.

use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub(super) enum WorkloadVolume {
    EmptyDir,
    LocalPv,
    DynamicPvc,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum WorkloadKind {
    ProofFile,
    Postgres,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum StoragePath {
    Gateway,
    DirectRustfs,
}

impl StoragePath {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Gateway => "gateway",
            Self::DirectRustfs => "direct-rustfs",
        }
    }

    pub(super) fn uses_gateway(self) -> bool {
        matches!(self, Self::Gateway)
    }

    pub(super) fn uses_integration_storage_proxy(self) -> bool {
        matches!(self, Self::DirectRustfs)
    }

    pub(super) fn uses_rs3_image(self) -> bool {
        self.uses_gateway() || self.uses_integration_storage_proxy()
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Scenario {
    pub(super) label: &'static str,
    pub(super) volume: WorkloadVolume,
    pub(super) workload: WorkloadKind,
    pub(super) storage_path: StoragePath,
    pub(super) restart_gateway_before_restore: bool,
    pub(super) restore_readonly_before_restore: bool,
}

impl Scenario {
    pub(super) const fn empty_dir() -> Self {
        Self {
            label: "empty-dir",
            volume: WorkloadVolume::EmptyDir,
            workload: WorkloadKind::ProofFile,
            storage_path: StoragePath::Gateway,
            restart_gateway_before_restore: false,
            restore_readonly_before_restore: false,
        }
    }

    pub(super) const fn local_pv() -> Self {
        Self {
            label: "local-pv",
            volume: WorkloadVolume::LocalPv,
            workload: WorkloadKind::ProofFile,
            storage_path: StoragePath::Gateway,
            restart_gateway_before_restore: false,
            restore_readonly_before_restore: false,
        }
    }

    pub(super) const fn dynamic_pvc() -> Self {
        Self {
            label: "dynamic-pvc",
            volume: WorkloadVolume::DynamicPvc,
            workload: WorkloadKind::ProofFile,
            storage_path: StoragePath::Gateway,
            restart_gateway_before_restore: false,
            restore_readonly_before_restore: false,
        }
    }

    pub(super) const fn dynamic_pvc_gateway_restart() -> Self {
        Self {
            label: "dynamic-pvc-gateway-restart",
            volume: WorkloadVolume::DynamicPvc,
            workload: WorkloadKind::ProofFile,
            storage_path: StoragePath::Gateway,
            restart_gateway_before_restore: true,
            restore_readonly_before_restore: true,
        }
    }

    pub(super) const fn postgres() -> Self {
        Self {
            label: "postgres",
            volume: WorkloadVolume::DynamicPvc,
            workload: WorkloadKind::Postgres,
            storage_path: StoragePath::Gateway,
            restart_gateway_before_restore: false,
            restore_readonly_before_restore: false,
        }
    }

    pub(super) const fn postgres_direct_rustfs() -> Self {
        Self {
            label: "postgres-direct-rustfs",
            volume: WorkloadVolume::DynamicPvc,
            workload: WorkloadKind::Postgres,
            storage_path: StoragePath::DirectRustfs,
            restart_gateway_before_restore: false,
            restore_readonly_before_restore: false,
        }
    }
}

#[derive(Debug)]
pub(super) struct PhaseTiming {
    pub(super) name: &'static str,
    pub(super) elapsed_ms: u64,
    pub(super) status: &'static str,
}

#[derive(Debug)]
pub(super) struct RunState {
    pub(super) scenario_label: &'static str,
    pub(super) storage_path: StoragePath,
    pub(super) anchor_name: String,
    pub(super) backend_prefix: String,
    pub(super) backup_name: Option<String>,
    pub(super) restore_name: Option<String>,
    pub(super) started: Instant,
    pub(super) phase_timings: Vec<PhaseTiming>,
}

impl RunState {
    pub(super) fn new(scenario: Scenario, anchor_name: String, backend_prefix: String) -> Self {
        Self {
            scenario_label: scenario.label,
            storage_path: scenario.storage_path,
            anchor_name,
            backend_prefix,
            backup_name: None,
            restore_name: None,
            started: Instant::now(),
            phase_timings: Vec::new(),
        }
    }

    pub(super) fn record_phase(&mut self, name: &'static str, elapsed: Duration, succeeded: bool) {
        self.phase_timings.push(PhaseTiming {
            name,
            elapsed_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            status: if succeeded { "ok" } else { "failed" },
        });
    }
}
