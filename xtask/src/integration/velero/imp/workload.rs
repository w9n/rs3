//! Workload lifecycle and proof checks for Velero integration lanes.

use super::scenario::{Scenario, WorkloadKind, WorkloadVolume};
use super::velero_cli::velero_diagnostics;
use super::{kubectl, kubectl_capture, timeout_arg};
use crate::integration::k8s_support::{K8sWorkspace, path_str, run_command};
use crate::integration::velero::VeleroKopiaSmokeArgs;
use anyhow::{Context, Result, bail};
use rs3_crypto::Sha256Hasher;
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
const BACKUP_FIXTURE_NAME_PREFIX: &str = "rs3-velero-multipart";
const BACKUP_FIXTURE_CHUNK_BYTES: usize = 700 * 1024;
const MAX_BACKUP_FIXTURE_BYTES: usize = 16 * 1024 * 1024;
const MAX_BACKUP_FIXTURE_CHUNKS: usize = 24;

pub(super) struct BackupFixture {
    chunks: Vec<BackupFixtureChunk>,
}

struct BackupFixtureChunk {
    name: String,
    payload_digest: String,
}

impl BackupFixture {
    fn new(bytes: usize) -> Result<(Self, String)> {
        if bytes > MAX_BACKUP_FIXTURE_BYTES {
            bail!(
                "Velero backup fixture exceeds the bounded {} MiB limit",
                MAX_BACKUP_FIXTURE_BYTES / (1024 * 1024)
            );
        }
        if bytes == 0 {
            return Ok((Self { chunks: Vec::new() }, String::new()));
        }

        let chunk_count = bytes.div_ceil(BACKUP_FIXTURE_CHUNK_BYTES);
        if chunk_count > MAX_BACKUP_FIXTURE_CHUNKS {
            bail!("Velero backup fixture exceeds the bounded ConfigMap count");
        }

        let mut remaining = bytes;
        let mut chunks = Vec::with_capacity(chunk_count);
        let mut documents = Vec::with_capacity(chunk_count);
        for index in 0..chunk_count {
            let len = remaining.min(BACKUP_FIXTURE_CHUNK_BYTES);
            remaining = remaining.saturating_sub(len);
            let payload = deterministic_fixture_payload(index, len);
            let name = format!("{BACKUP_FIXTURE_NAME_PREFIX}-{index:02}");
            chunks.push(BackupFixtureChunk {
                name: name.clone(),
                payload_digest: hex::encode(Sha256Hasher::digest(payload.as_bytes())),
            });
            documents.push(format!(
                "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {name}\n  namespace: {{namespace}}\n  labels:\n    app.kubernetes.io/name: {BACKUP_FIXTURE_NAME_PREFIX}\ndata:\n  payload: {payload}\n"
            ));
        }
        Ok((Self { chunks }, documents.join("---\n")))
    }

    pub(super) fn is_enabled(&self) -> bool {
        !self.chunks.is_empty()
    }
}

pub(super) fn apply_backup_fixture(
    args: &VeleroKopiaSmokeArgs,
    kubeconfig_path: &Path,
    workspace: &K8sWorkspace,
) -> Result<BackupFixture> {
    let (fixture, manifest) = BackupFixture::new(args.velero_backup_fixture_bytes)?;
    if !fixture.is_enabled() {
        return Ok(fixture);
    }
    let manifest_path = workspace.path("velero-backup-fixture.yaml");
    let manifest = manifest.replace("{namespace}", &args.workload_namespace);
    fs::write(&manifest_path, manifest)
        .with_context(|| format!("failed to write {}", manifest_path.display()))?;
    kubectl(
        &args.kubectl_bin,
        kubeconfig_path,
        &[
            "apply",
            "--server-side",
            "--field-manager=rs3-velero-fixture",
            "-f",
            path_str(&manifest_path)?,
        ],
    )
    .context("failed to apply bounded Velero backup fixture")?;
    assert_backup_fixture(args, kubeconfig_path, &fixture)?;
    Ok(fixture)
}

pub(super) fn assert_backup_fixture(
    args: &VeleroKopiaSmokeArgs,
    kubeconfig_path: &Path,
    fixture: &BackupFixture,
) -> Result<()> {
    for chunk in &fixture.chunks {
        let payload = kubectl_capture(
            &args.kubectl_bin,
            kubeconfig_path,
            &[
                "-n",
                &args.workload_namespace,
                "get",
                "configmap",
                &chunk.name,
                "-o",
                "jsonpath={.data.payload}",
            ],
        )
        .context("failed to read a bounded Velero backup fixture ConfigMap")?;
        if hex::encode(Sha256Hasher::digest(payload.as_bytes())) != chunk.payload_digest {
            bail!("restored Velero backup fixture digest mismatch");
        }
    }
    Ok(())
}

fn deterministic_fixture_payload(index: usize, len: usize) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut state = (index as u64).wrapping_add(1);
    let mut payload = String::with_capacity(len);
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let alphabet_index = (state & 63) as usize;
        payload.push(char::from(ALPHABET[alphabet_index]));
    }
    payload
}

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
    let manifest = workload_manifest(args, scenario, node_name.as_deref())?;
    fs::write(&manifest_path, manifest)
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
        WorkloadKind::Postgres => write_postgres_workload_proof(args, kubeconfig_path),
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
) -> Result<String> {
    let workload_image = workload_image(args, scenario.workload);
    let volume_resources = match scenario.volume {
        WorkloadVolume::EmptyDir => String::new(),
        WorkloadVolume::LocalPv => {
            let Some(node_name) = node_name else {
                bail!("local PV workload requires a Kubernetes node name");
            };
            local_pv_resources(args, node_name)
        }
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
    Ok(format!(
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
    ))
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
                &postgres_verify_script(args.postgres_row_count, args.postgres_padding_repeat),
            ],
        ),
    }
}

fn write_postgres_workload_proof(
    args: &VeleroKopiaSmokeArgs,
    kubeconfig_path: &Path,
) -> Result<()> {
    let script = postgres_write_script(args.postgres_row_count, args.postgres_padding_repeat);
    let started = Instant::now();
    loop {
        let result = kubectl_capture(
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
                &script,
            ],
        );
        match result {
            Ok(_) => return Ok(()),
            Err(_) if started.elapsed() <= Duration::from_secs(args.wait_secs) => {
                thread::sleep(Duration::from_secs(2));
            }
            Err(error) => {
                return Err(error).context("failed to write Postgres smoke proof data");
            }
        }
    }
}

fn postgres_write_script(row_count: u32, padding_repeat: u32) -> String {
    let last_row = row_count.saturating_sub(1);
    format!(
        "psql -U postgres -d {POSTGRES_DB} -v ON_ERROR_STOP=1 -c \"DROP TABLE IF EXISTS proof; CREATE TABLE proof(id integer PRIMARY KEY, value text NOT NULL, padding text NOT NULL); INSERT INTO proof SELECT i, 'row-' || lpad(i::text, 4, '0'), repeat(md5(i::text), {padding_repeat}) FROM generate_series(0, {last_row}) AS i; CHECKPOINT;\" && pg_dump -U postgres -d {POSTGRES_DB} -f {POSTGRES_DUMP_PATH} && sync",
    )
}

fn postgres_verify_script(row_count: u32, padding_repeat: u32) -> String {
    let last_row = row_count.saturating_sub(1);
    let padding_len = padding_repeat.saturating_mul(32);
    format!(
        "test -s {POSTGRES_DUMP_PATH} && psql -U postgres -d {POSTGRES_DB} -v ON_ERROR_STOP=1 -At -c \"SELECT CASE WHEN (SELECT count(*) FROM proof) = {row_count} AND (SELECT md5(string_agg(value, ',' ORDER BY id)) FROM proof) = (SELECT md5(string_agg('row-' || lpad(i::text, 4, '0'), ',' ORDER BY i)) FROM generate_series(0, {last_row}) AS i) AND (SELECT coalesce(min(length(padding)), 0) FROM proof) = {padding_len} AND (SELECT coalesce(max(length(padding)), 0) FROM proof) = {padding_len} THEN 'ok' ELSE 'bad' END;\"",
    )
}

fn proof_matches(workload: WorkloadKind, actual: &str) -> bool {
    match workload {
        WorkloadKind::ProofFile => actual == EXPECTED_CONTENT,
        WorkloadKind::Postgres => actual.trim() == "ok",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BACKUP_FIXTURE_CHUNK_BYTES, BackupFixture, MAX_BACKUP_FIXTURE_BYTES,
        deterministic_fixture_payload, postgres_verify_script, postgres_write_script,
    };

    #[test]
    fn postgres_scripts_scale_rows_and_padding() {
        let write = postgres_write_script(1024, 16);
        assert!(write.contains("generate_series(0, 1023)"));
        assert!(write.contains("repeat(md5(i::text), 16)"));

        let verify = postgres_verify_script(1024, 16);
        assert!(verify.contains("(SELECT count(*) FROM proof) = 1024"));
        assert!(verify.contains("length(padding)), 0) FROM proof) = 512"));
    }

    #[test]
    fn backup_fixture_is_bounded_and_deterministic() {
        let (fixture, manifest) =
            BackupFixture::new(BACKUP_FIXTURE_CHUNK_BYTES + 1).expect("bounded fixture");
        assert!(fixture.is_enabled());
        assert_eq!(fixture.chunks.len(), 2);
        assert!(manifest.contains("{namespace}"));
        assert_eq!(
            deterministic_fixture_payload(3, 128),
            deterministic_fixture_payload(3, 128)
        );
        assert!(BackupFixture::new(MAX_BACKUP_FIXTURE_BYTES + 1).is_err());
    }
}
