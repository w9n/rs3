# Integration Harness

This directory is reserved for integration harness assets that are too broad
for default Cargo tests.

See [../TEST_LANES.md](../TEST_LANES.md) for the current lane map and planned
restore coverage.

Current entrypoint:

```sh
cargo run -p xtask -- integration s3-local
```

The default mode expects an already running S3-compatible endpoint and an
existing test bucket. It delegates to the live storage contract test and uses
`RS3_TEST_S3_*` environment variables or matching command-line flags.

The container mode starts a local provider, creates a temporary bucket, and
then runs the same storage contract:

```sh
cargo run -p xtask --features containers -- integration s3-local --mode container
```

The gateway mode starts a local provider, creates a backend bucket, starts the
gateway, and drives object operations through the gateway's S3 endpoint:

```sh
cargo run -p xtask --features containers -- integration s3-gateway
```

The Kopia gateway mode uses the same local provider and gateway, then runs a
real Kopia repository create/snapshot/restore smoke test:

```sh
cargo run -p xtask --features containers -- integration kopia-gateway
```

Set `RS3_TEST_KOPIA_BIN` or pass `--kopia-bin` when the executable is not named
`kopia`.

The Kubernetes gateway mode creates a disposable kind cluster, builds and loads
the gateway image, deploys the gateway, waits for readiness, and runs an S3
smoke test through `kubectl port-forward`:

```sh
cargo run -p xtask --features k8s -- integration k8s-gateway
```

Pass `--keep-cluster` to inspect a failing cluster before deletion. The Helm
chart under `charts/rs3-gateway` is the install packaging surface; the `xtask`
Kubernetes smoke remains the deterministic CI orchestrator.

For faster local iteration, create or keep a kind cluster once and pass
`--reuse-kind-cluster --cluster-name <name>`. CI should keep using disposable
clusters unless the job explicitly owns cleanup.

The Velero Kopia smoke extends the Kubernetes path by installing a small
S3-compatible backend behind the gateway, deploying the gateway with a
Kubernetes Lease checkpoint anchor, installing Velero with the node-agent,
pointing its S3 backup location at the gateway service, backing up a pod volume,
restoring it, and checking the restored file content. The gateway has no durable
local state in these lanes; object data lives in the backend service and current
checkpoint state lives in the Lease.

```sh
cargo run -p xtask --features k8s -- integration velero-kopia-smoke
```

The local-PV variant adds static PV data-restore coverage without deploying a
dynamic storage provider. It keeps the PV/PVC bound, removes the original file,
deletes the pod, restores the pod, and verifies that Velero repopulates the
volume through Kopia..

```sh
cargo run -p xtask --features k8s -- integration velero-kopia-local-pv-smoke
```

The dynamic-PVC variant installs OpenEBS LocalPV Hostpath through its pinned Helm
chart, creates a PVC from that StorageClass, deletes the workload namespace after
backup, restores it, and verifies the restored file bytes. This is the first
kind-friendly disaster-restore lane..

```sh
cargo run -p xtask --features k8s -- integration velero-kopia-dynamic-pvc-smoke
```

The gateway-restart variant restarts the gateway after backup and before restore.
It is a targeted durability smoke for repository state that must survive process
replacement without relying on a gateway PVC.

```sh
cargo run -p xtask --features k8s -- integration velero-kopia-dynamic-pvc-gateway-restart-smoke
```

The Postgres smoke uses a single Postgres pod on the same dynamic PVC path. It
writes deterministic rows, runs a `CHECKPOINT` and `pg_dump` pre-backup hook,
then verifies live SQL state and the dump file after restore.

```sh
cargo run -p xtask --features k8s -- integration velero-kopia-postgres-smoke
```

That Postgres smoke verifies only the gateway and Velero/Kopia compatibility path for a small
stateful workload. Database-native backup systems still need their own
consistency and restore validation.

Velero lanes collect artifacts under `.local/integration` unless
`--skip-artifacts` is passed. Use `--artifact-dir` to pin the output path. The
artifact set includes gateway logs, Kubernetes Lease checkpoint snapshots,
parsed backend operation counts, amplification ratios, Velero CRs, PVC/PV state,
pod events, and relevant controller logs. Restart lanes also capture gateway
logs and anchor state before and after the restart so checkpoint reload is
visible without manual `kubectl` inspection.

The Velero lanes load the Velero server and AWS plugin images from the local
Docker daemon into kind by default. Preload or mirror
`velero/velero:v1.18.0` and `velero/velero-plugin-for-aws:v1.14.0`, or pass
`--pull-velero-images` when registry pulls are acceptable. CI can point at a
mirror with `RS3_TEST_VELERO_IMAGE` and
`RS3_TEST_VELERO_AWS_PLUGIN_IMAGE`.

The dynamic-PVC lane also loads `openebs/provisioner-localpv:4.4.0` and
`openebs/linux-utils:4.3.0` by default. CI can mirror them with
`RS3_TEST_OPENEBS_PROVISIONER_IMAGE` and `RS3_TEST_OPENEBS_HELPER_IMAGE`, and can
mirror the chart package with `RS3_TEST_OPENEBS_CHART`.

The Postgres lane additionally uses `postgres:17-alpine` by default. CI can
mirror it with `RS3_TEST_POSTGRES_IMAGE`.

The Velero lanes additionally use `rustfs/rustfs:latest` as the in-cluster
S3-compatible backend by default. CI can mirror it with `RS3_TEST_RUSTFS_IMAGE`.

CI should not depend on anonymous public registry pulls. Configure the CI secret
store or image sync job outside this repository, mirror the pinned third-party
images into a CI-owned registry, and set the image variables above for the job.
Keep registry credentials out of command-line arguments because they are easy to
leak through logs and process listings.

Upstream Velero e2e is best used as a reference and optional release lane, not as
embedded Rust test code. The upstream suite is Go/Ginkgo-based, configured by
`make test-e2e`, and supports label filtering plus `UPLOADER_TYPE=kopia`. The
Rust harness should keep owning cluster setup, gateway wiring, metrics,
artifacts, and cleanup; selected upstream cases should inform the restore matrix.

Container provider setup stays behind the opt-in `xtask/containers` feature so
Docker and provider bootstrap dependencies stay outside normal unit tests and
runtime crates.
