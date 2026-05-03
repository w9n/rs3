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

The Velero Kopia smoke extends the Kubernetes path by installing Velero with the
node-agent, pointing its S3 backup location at the gateway service, backing up a
pod volume, restoring it, and checking the restored file content. It uses an
`emptyDir` volume because kind's default PVC provisioner exposes `hostPath` PVs,
which Velero file-system backup intentionally skips.

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

CI should not depend on anonymous public registry pulls. Configure the CI secret
store or image sync job outside this repository, mirror the pinned third-party
images into a CI-owned registry, and set the image variables above for the job.
Keep registry credentials out of command-line arguments because they are easy to
leak through logs and process listings.

Container provider setup stays behind the opt-in `xtask/containers` feature so
Docker and provider bootstrap dependencies stay outside normal unit tests and
runtime crates.
