//! Kubernetes deployment for the direct-storage measurement proxy.

use super::{kubectl, timeout_arg};
use crate::integration::k8s_support::{K8sWorkspace, path_str};
use crate::integration::velero::VeleroKopiaSmokeArgs;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

pub(super) const NAME: &str = "rs3-integration-storage-proxy";

const PORT: u16 = 9000;

pub(super) fn service_endpoint(namespace: &str) -> String {
    format!("http://{NAME}.{namespace}.svc:{PORT}")
}

pub(super) fn install(
    args: &VeleroKopiaSmokeArgs,
    kubeconfig_path: &Path,
    workspace: &K8sWorkspace,
    target: &str,
) -> Result<()> {
    let manifest_path = workspace.path("integration-storage-proxy.yaml");
    fs::write(&manifest_path, manifest(args, target))
        .with_context(|| format!("failed to write {}", manifest_path.display()))?;
    kubectl(
        &args.kubectl_bin,
        kubeconfig_path,
        &["apply", "-f", path_str(&manifest_path)?],
    )
    .context("failed to apply storage measurement proxy manifest")?;

    let timeout = timeout_arg(args.wait_secs);
    kubectl(
        &args.kubectl_bin,
        kubeconfig_path,
        &[
            "-n",
            &args.gateway_namespace,
            "rollout",
            "status",
            &format!("deployment/{NAME}"),
            "--timeout",
            timeout.as_str(),
        ],
    )
    .context("storage measurement proxy did not become ready")
}

fn manifest(args: &VeleroKopiaSmokeArgs, target: &str) -> String {
    format!(
        r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: {name}
  namespace: {namespace}
  labels:
    app.kubernetes.io/name: {name}
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: {name}
  template:
    metadata:
      labels:
        app.kubernetes.io/name: {name}
    spec:
      containers:
        - name: proxy
          image: {image}
          imagePullPolicy: IfNotPresent
          command:
            - /usr/local/bin/rs3-integration-storage-proxy
          args:
            - --bind
            - 0.0.0.0:{port}
            - --target
            - {target}
            - --report-interval-secs
            - "1"
          ports:
            - name: s3
              containerPort: {port}
          readinessProbe:
            tcpSocket:
              port: s3
            periodSeconds: 1
            failureThreshold: 60
---
apiVersion: v1
kind: Service
metadata:
  name: {name}
  namespace: {namespace}
  labels:
    app.kubernetes.io/name: {name}
spec:
  selector:
    app.kubernetes.io/name: {name}
  ports:
    - name: s3
      port: {port}
      targetPort: s3
"#,
        image = args.image,
        name = NAME,
        namespace = args.gateway_namespace,
        port = PORT,
        target = target,
    )
}
