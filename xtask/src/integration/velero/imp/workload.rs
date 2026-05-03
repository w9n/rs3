//! Workload lifecycle and proof checks for Velero integration lanes.

use super::scenario::{Scenario, WorkloadKind, WorkloadVolume};
use super::{kubectl, kubectl_capture, timeout_arg, velero_diagnostics};
use crate::integration::k8s_support::{K8sWorkspace, path_str, run_command};
use crate::integration::velero::VeleroKopiaSmokeArgs;
use anyhow::{Context, Result, bail};
use std::fs;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

const WORKLOAD_NAME: &str = "rs3-velero-smoke";
const LOCAL_PV_NAME: &str = "rs3-velero-smoke-local-pv";
const LOCAL_STORAGE_CLASS: &str = "rs3-local";
const LOCAL_PV_PATH: &str = "/var/local/rs3-velero-smoke-data";
const PROOF_PATH: &str = "/data/proof.txt";
const POSTGRES_DATA_PATH: &str = "/var/lib/postgresql/data";
const POSTGRES_DUMP_PATH: &str = "/var/lib/postgresql/data/rs3-proof.sql";
const POSTGRES_DB: &str = "rs3";
const EXPECTED_CONTENT: &str = "rs3 velero kopia smoke\n";

pub(super) fn prepare_local_pv_path(args: &VeleroKopiaSmokeArgs, cluster_name: &str) -> Result<()> {
    let node_container = format!("{cluster_name}-control-plane");
    run_command(
        &args.docker_bin,
        &["exec", &node_container, "mkdir", "-p", LOCAL_PV_PATH],
    )
    .with_context(|| format!("failed to create local PV path in `{node_container}`"))?;
    run_command(
        &args.docker_bin,
        &["exec", &node_container, "chmod", "0777", LOCAL_PV_PATH],
    )
    .with_context(|| format!("failed to make local PV path writable in `{node_container}`"))
}

pub(super) fn apply_workload(
    args: &VeleroKopiaSmokeArgs,
    kubeconfig_path: &Path,
    workspace: &K8sWorkspace,
    scenario: Scenario,
) -> Result<()> {
    let manifest_path = workspace.path("workload.yaml");
    let node_name = match scenario.volume {
        WorkloadVolume::EmptyDir | WorkloadVolume::DynamicPvc => None,
        WorkloadVolume::LocalPv => Some(first_node_name(args, kubeconfig_path)?),
    };
    fs::write(
        &manifest_path,
        workload_manifest(args, scenario, node_name.as_deref()),
    )
    .with_context(|| format!("failed to write {}", manifest_path.display()))?;
    kubectl(
        &args.kubectl_bin,
        kubeconfig_path,
        &["apply", "-f", path_str(&manifest_path)?],
    )
    .context("failed to apply Velero smoke workload")?;
    wait_for_workload_available(args, kubeconfig_path)
}

pub(super) fn wait_for_workload_available(
    args: &VeleroKopiaSmokeArgs,
    kubeconfig_path: &Path,
) -> Result<()> {
    let timeout = timeout_arg(args.wait_secs);
    kubectl(
        &args.kubectl_bin,
        kubeconfig_path,
        &[
            "-n",
            &args.workload_namespace,
            "wait",
            "--for=condition=Ready",
            &format!("pod/{WORKLOAD_NAME}"),
            "--timeout",
            timeout.as_str(),
        ],
    )
    .context("Velero smoke workload did not become available")
}

pub(super) fn write_workload_proof(
    args: &VeleroKopiaSmokeArgs,
    kubeconfig_path: &Path,
    workload: WorkloadKind,
) -> Result<()> {
    match workload {
        WorkloadKind::ProofFile => kubectl(
            &args.kubectl_bin,
            kubeconfig_path,
            &[
                "-n",
                &args.workload_namespace,
                "exec",
                &format!("pod/{WORKLOAD_NAME}"),
                "--",
                "/bin/sh",
                "-c",
                &format!("printf '{EXPECTED_CONTENT}' > {PROOF_PATH} && sync"),
            ],
        )
        .context("failed to write Velero smoke proof file"),
        WorkloadKind::Postgres => kubectl(
            &args.kubectl_bin,
            kubeconfig_path,
            &[
                "-n",
                &args.workload_namespace,
                "exec",
                &format!("pod/{WORKLOAD_NAME}"),
                "-c",
                "postgres",
                "--",
                "/bin/sh",
                "-c",
                &postgres_write_script(),
            ],
        )
        .context("failed to write Postgres smoke proof data"),
    }
}

pub(super) fn assert_workload_proof(
    args: &VeleroKopiaSmokeArgs,
    kubeconfig_path: &Path,
    workload: WorkloadKind,
) -> Result<()> {
    let actual = read_workload_proof(args, kubeconfig_path, workload)
        .context("failed to read Velero smoke proof")?;
    match workload {
        WorkloadKind::ProofFile if actual != EXPECTED_CONTENT => {
            bail!("Velero smoke proof file mismatch before backup");
        }
        WorkloadKind::Postgres if actual.trim() != "ok" => {
            bail!("Postgres smoke proof mismatch before backup: {actual:?}");
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn remove_workload_proof(
    args: &VeleroKopiaSmokeArgs,
    kubeconfig_path: &Path,
    workload: WorkloadKind,
) -> Result<()> {
    match workload {
        WorkloadKind::ProofFile => kubectl(
            &args.kubectl_bin,
            kubeconfig_path,
            &[
                "-n",
                &args.workload_namespace,
                "exec",
                &format!("pod/{WORKLOAD_NAME}"),
                "--",
                "rm",
                "-f",
                PROOF_PATH,
            ],
        )
        .context("failed to remove original local-PV proof file before restore"),
        WorkloadKind::Postgres => kubectl(
            &args.kubectl_bin,
            kubeconfig_path,
            &[
                "-n",
                &args.workload_namespace,
                "exec",
                &format!("pod/{WORKLOAD_NAME}"),
                "-c",
                "postgres",
                "--",
                "/bin/sh",
                "-c",
                "rm -f /var/lib/postgresql/data/rs3-proof.sql",
            ],
        )
        .context("failed to remove original Postgres proof file before restore"),
    }
}

pub(super) fn delete_workload_namespace(
    args: &VeleroKopiaSmokeArgs,
    kubeconfig_path: &Path,
) -> Result<()> {
    let timeout = timeout_arg(args.wait_secs);
    kubectl(
        &args.kubectl_bin,
        kubeconfig_path,
        &[
            "delete",
            "namespace",
            &args.workload_namespace,
            "--wait=true",
            "--timeout",
            timeout.as_str(),
        ],
    )
    .context("failed to delete Velero smoke workload namespace")
}

pub(super) fn delete_workload_pod(
    args: &VeleroKopiaSmokeArgs,
    kubeconfig_path: &Path,
) -> Result<()> {
    let timeout = timeout_arg(args.wait_secs);
    kubectl(
        &args.kubectl_bin,
        kubeconfig_path,
        &[
            "-n",
            &args.workload_namespace,
            "delete",
            "pod",
            WORKLOAD_NAME,
            "--wait=true",
            "--timeout",
            timeout.as_str(),
        ],
    )
    .context("failed to delete Velero smoke workload pod")
}

pub(super) fn wait_for_restored_proof(
    args: &VeleroKopiaSmokeArgs,
    kubeconfig_path: &Path,
    workload: WorkloadKind,
) -> Result<()> {
    let started = Instant::now();
    loop {
        match read_workload_proof(args, kubeconfig_path, workload) {
            Ok(actual) if proof_matches(workload, &actual) => return Ok(()),
            Ok(_) | Err(_) if started.elapsed() <= Duration::from_secs(args.wait_secs) => {
                thread::sleep(Duration::from_secs(2));
            }
            Ok(_) => bail!("restored Velero smoke proof file had unexpected content"),
            Err(error) => {
                let diagnostics =
                    velero_diagnostics(args, kubeconfig_path).unwrap_or_else(|diag_error| {
                        format!("diagnostics unavailable: {diag_error:#}")
                    });
                return Err(error).context(format!(
                    "failed to read restored Velero proof file\n{diagnostics}"
                ));
            }
        }
    }
}

fn first_node_name(args: &VeleroKopiaSmokeArgs, kubeconfig_path: &Path) -> Result<String> {
    let node_name = kubectl_capture(
        &args.kubectl_bin,
        kubeconfig_path,
        &["get", "nodes", "-o", "jsonpath={.items[0].metadata.name}"],
    )
    .context("failed to read kind node name")?;
    if node_name.trim().is_empty() {
        bail!("cluster has no Kubernetes nodes");
    }
    Ok(node_name)
}

fn workload_manifest(
    args: &VeleroKopiaSmokeArgs,
    scenario: Scenario,
    node_name: Option<&str>,
) -> String {
    let workload_image = workload_image(args, scenario.workload);
    let volume_resources = match scenario.volume {
        WorkloadVolume::EmptyDir => String::new(),
        WorkloadVolume::LocalPv => local_pv_resources(args, node_name.expect("node name")),
        WorkloadVolume::DynamicPvc => dynamic_pvc_resources(args),
    };
    let volume_spec = match scenario.volume {
        WorkloadVolume::EmptyDir => "emptyDir: {}".to_owned(),
        WorkloadVolume::LocalPv | WorkloadVolume::DynamicPvc => {
            "persistentVolumeClaim:\n        claimName: data".to_owned()
        }
    };
    let annotations = workload_annotations(scenario.workload);
    let container_spec = workload_container_spec(scenario.workload, workload_image);
    format!(
        r#"apiVersion: v1
kind: Namespace
metadata:
  name: {namespace}
{volume_resources}
---
apiVersion: v1
kind: Pod
metadata:
  name: {name}
  namespace: {namespace}
  annotations:
{annotations}
  labels:
    app.kubernetes.io/name: {name}
spec:
  containers:
{container_spec}
  volumes:
    - name: data
      {volume_spec}
"#,
        annotations = annotations,
        container_spec = container_spec,
        name = WORKLOAD_NAME,
        namespace = args.workload_namespace,
        volume_resources = volume_resources,
        volume_spec = volume_spec,
    )
}

fn workload_image(args: &VeleroKopiaSmokeArgs, workload: WorkloadKind) -> &str {
    match workload {
        WorkloadKind::ProofFile => args.workload_image.as_deref().unwrap_or(&args.image),
        WorkloadKind::Postgres => args
            .workload_image
            .as_deref()
            .unwrap_or(&args.postgres_image),
    }
}

fn workload_annotations(workload: WorkloadKind) -> &'static str {
    match workload {
        WorkloadKind::ProofFile => "    backup.velero.io/backup-volumes: data",
        WorkloadKind::Postgres => {
            r#"    backup.velero.io/backup-volumes: data
    pre.hook.backup.velero.io/container: postgres
    pre.hook.backup.velero.io/command: '["/bin/sh","-c","psql -U postgres -d rs3 -v ON_ERROR_STOP=1 -c \"CHECKPOINT\" && pg_dump -U postgres -d rs3 -f /var/lib/postgresql/data/rs3-proof.sql && sync"]'
    pre.hook.backup.velero.io/timeout: 60s"#
        }
    }
}

fn workload_container_spec(workload: WorkloadKind, image: &str) -> String {
    match workload {
        WorkloadKind::ProofFile => format!(
            r#"    - name: workload
      image: {image}
      imagePullPolicy: IfNotPresent
      command:
        - /bin/sh
        - -c
        - sleep 3600
      volumeMounts:
        - name: data
          mountPath: /data"#,
        ),
        WorkloadKind::Postgres => format!(
            r#"    - name: postgres
      image: {image}
      imagePullPolicy: IfNotPresent
      env:
        - name: POSTGRES_DB
          value: {db}
        - name: POSTGRES_USER
          value: postgres
        - name: POSTGRES_HOST_AUTH_METHOD
          value: trust
        - name: PGDATA
          value: {data_path}/pgdata
      ports:
        - name: postgres
          containerPort: 5432
      readinessProbe:
        exec:
          command:
            - pg_isready
            - -U
            - postgres
            - -d
            - {db}
        periodSeconds: 2
        failureThreshold: 30
      volumeMounts:
        - name: data
          mountPath: {data_path}"#,
            data_path = POSTGRES_DATA_PATH,
            db = POSTGRES_DB,
        ),
    }
}

fn dynamic_pvc_resources(args: &VeleroKopiaSmokeArgs) -> String {
    format!(
        r#"
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: data
  namespace: {namespace}
  labels:
    app.kubernetes.io/name: {name}
spec:
  storageClassName: {storage_class}
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 64Mi
"#,
        name = WORKLOAD_NAME,
        namespace = args.workload_namespace,
        storage_class = args.openebs_storage_class,
    )
}

fn local_pv_resources(args: &VeleroKopiaSmokeArgs, node_name: &str) -> String {
    format!(
        r#"
---
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: {storage_class}
provisioner: kubernetes.io/no-provisioner
volumeBindingMode: WaitForFirstConsumer
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: {pv_name}
  labels:
    app.kubernetes.io/name: {name}
spec:
  capacity:
    storage: 64Mi
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Retain
  storageClassName: {storage_class}
  local:
    path: {local_path}
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
            - key: kubernetes.io/hostname
              operator: In
              values:
                - {node_name}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: data
  namespace: {namespace}
  labels:
    app.kubernetes.io/name: {name}
spec:
  storageClassName: {storage_class}
  volumeName: {pv_name}
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 64Mi
"#,
        local_path = LOCAL_PV_PATH,
        name = WORKLOAD_NAME,
        namespace = args.workload_namespace,
        node_name = node_name,
        pv_name = LOCAL_PV_NAME,
        storage_class = LOCAL_STORAGE_CLASS,
    )
}

fn read_workload_proof(
    args: &VeleroKopiaSmokeArgs,
    kubeconfig_path: &Path,
    workload: WorkloadKind,
) -> Result<String> {
    match workload {
        WorkloadKind::ProofFile => kubectl_capture(
            &args.kubectl_bin,
            kubeconfig_path,
            &[
                "-n",
                &args.workload_namespace,
                "exec",
                &format!("pod/{WORKLOAD_NAME}"),
                "--",
                "cat",
                PROOF_PATH,
            ],
        ),
        WorkloadKind::Postgres => kubectl_capture(
            &args.kubectl_bin,
            kubeconfig_path,
            &[
                "-n",
                &args.workload_namespace,
                "exec",
                &format!("pod/{WORKLOAD_NAME}"),
                "-c",
                "postgres",
                "--",
                "/bin/sh",
                "-c",
                &postgres_verify_script(),
            ],
        ),
    }
}

fn postgres_write_script() -> String {
    format!(
        "psql -U postgres -d {POSTGRES_DB} -v ON_ERROR_STOP=1 -c \"DROP TABLE IF EXISTS proof; CREATE TABLE proof(id integer PRIMARY KEY, value text NOT NULL); INSERT INTO proof SELECT i, 'row-' || lpad(i::text, 4, '0') FROM generate_series(0, 127) AS i; CHECKPOINT;\" && pg_dump -U postgres -d {POSTGRES_DB} -f {POSTGRES_DUMP_PATH} && sync",
    )
}

fn postgres_verify_script() -> String {
    format!(
        "test -s {POSTGRES_DUMP_PATH} && psql -U postgres -d {POSTGRES_DB} -v ON_ERROR_STOP=1 -At -c \"SELECT CASE WHEN (SELECT count(*) FROM proof) = 128 AND (SELECT md5(string_agg(value, ',' ORDER BY id)) FROM proof) = (SELECT md5(string_agg('row-' || lpad(i::text, 4, '0'), ',' ORDER BY i)) FROM generate_series(0, 127) AS i) THEN 'ok' ELSE 'bad' END;\"",
    )
}

fn proof_matches(workload: WorkloadKind, actual: &str) -> bool {
    match workload {
        WorkloadKind::ProofFile => actual == EXPECTED_CONTENT,
        WorkloadKind::Postgres => actual.trim() == "ok",
    }
}
