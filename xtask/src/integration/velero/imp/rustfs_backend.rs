//! RustFS backend setup for Velero integration lanes.

use super::{kubectl, timeout_arg};
use crate::integration::k8s_support::{K8sWorkspace, PortForward, path_str};
use crate::integration::velero::VeleroKopiaSmokeArgs;
use anyhow::{Context, Result};
use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Credentials, Region, timeout::TimeoutConfig},
    error::ProvideErrorMetadata,
};
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

pub(super) const BACKEND_BUCKET: &str = "rs3-backend";
pub(super) const BACKEND_REGION: &str = "us-east-1";
pub(super) const RUSTFS_ACCESS_KEY_ID: &str = "rustfsadmin";
pub(super) const RUSTFS_SECRET_ACCESS_KEY: &str = "rustfsadmin";

const RUSTFS_NAME: &str = "rs3-rustfs";
const RUSTFS_PORT: u16 = 9000;

pub(super) fn service_endpoint(namespace: &str) -> String {
    format!("http://{RUSTFS_NAME}.{namespace}.svc:{RUSTFS_PORT}")
}

pub(super) fn install(
    args: &VeleroKopiaSmokeArgs,
    kubeconfig_path: &Path,
    workspace: &K8sWorkspace,
) -> Result<()> {
    let manifest_path = workspace.path("rustfs.yaml");
    fs::write(&manifest_path, manifest(args))
        .with_context(|| format!("failed to write {}", manifest_path.display()))?;
    kubectl(
        &args.kubectl_bin,
        kubeconfig_path,
        &["apply", "-f", path_str(&manifest_path)?],
    )
    .context("failed to apply RustFS backend manifest")?;

    let timeout = timeout_arg(args.wait_secs);
    kubectl(
        &args.kubectl_bin,
        kubeconfig_path,
        &[
            "-n",
            &args.gateway_namespace,
            "rollout",
            "status",
            &format!("deployment/{RUSTFS_NAME}"),
            "--timeout",
            timeout.as_str(),
        ],
    )
    .context("RustFS backend did not become ready")
}

pub(super) fn create_bucket(args: &VeleroKopiaSmokeArgs, kubeconfig_path: &Path) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build RustFS setup runtime")?;
    runtime.block_on(async {
        let mut port_forward = PortForward::start(
            &args.kubectl_bin,
            kubeconfig_path,
            &args.gateway_namespace,
            RUSTFS_NAME,
            RUSTFS_PORT,
            args.wait_secs,
        )
        .await?;
        let create = create_s3_bucket(
            &port_forward.endpoint_url(),
            BACKEND_REGION,
            RUSTFS_ACCESS_KEY_ID,
            RUSTFS_SECRET_ACCESS_KEY,
            BACKEND_BUCKET,
            args.wait_secs,
        )
        .await;
        let shutdown = port_forward.shutdown();

        create?;
        shutdown?;
        Ok(())
    })
}

fn manifest(args: &VeleroKopiaSmokeArgs) -> String {
    format!(
        r#"apiVersion: v1
kind: Namespace
metadata:
  name: {namespace}
---
apiVersion: apps/v1
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
        - name: rustfs
          image: {image}
          imagePullPolicy: IfNotPresent
          args:
            - --access-key
            - {access_key}
            - --secret-key
            - {secret_key}
            - /data
          env:
            - name: RUSTFS_ACCESS_KEY
              value: {access_key}
            - name: RUSTFS_SECRET_KEY
              value: {secret_key}
          ports:
            - name: s3
              containerPort: {port}
          readinessProbe:
            httpGet:
              path: /health
              port: s3
            periodSeconds: 1
            failureThreshold: 60
          volumeMounts:
            - name: data
              mountPath: /data
      volumes:
        - name: data
          emptyDir: {{}}
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
        access_key = RUSTFS_ACCESS_KEY_ID,
        image = args.rustfs_image,
        name = RUSTFS_NAME,
        namespace = args.gateway_namespace,
        port = RUSTFS_PORT,
        secret_key = RUSTFS_SECRET_ACCESS_KEY,
    )
}

async fn create_s3_bucket(
    endpoint_url: &str,
    region: &str,
    access_key_id: &str,
    secret_access_key: &str,
    bucket: &str,
    wait_secs: u64,
) -> Result<()> {
    let client = s3_client(endpoint_url, region, access_key_id, secret_access_key);
    let started = Instant::now();
    loop {
        match try_create_bucket(&client, bucket).await {
            Ok(()) => return Ok(()),
            Err(_error) if started.elapsed() < Duration::from_secs(wait_secs) => {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

async fn try_create_bucket(client: &Client, bucket: &str) -> Result<()> {
    match client.create_bucket().bucket(bucket).send().await {
        Ok(_) => Ok(()),
        Err(error) if bucket_already_exists(&error) => Ok(()),
        Err(error) => Err(anyhow::anyhow!("CreateBucket failed: {error}")),
    }
}

fn bucket_already_exists<E>(error: &aws_sdk_s3::error::SdkError<E>) -> bool
where
    E: ProvideErrorMetadata,
{
    matches!(
        error
            .as_service_error()
            .and_then(ProvideErrorMetadata::code),
        Some("BucketAlreadyOwnedByYou" | "BucketAlreadyExists")
    )
}

fn s3_client(
    endpoint_url: &str,
    region: &str,
    access_key_id: &str,
    secret_access_key: &str,
) -> Client {
    let timeout_config = TimeoutConfig::builder()
        .operation_attempt_timeout(Duration::from_secs(5))
        .operation_timeout(Duration::from_secs(10))
        .build();
    let config = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(region.to_owned()))
        .endpoint_url(endpoint_url.to_owned())
        .credentials_provider(Credentials::new(
            access_key_id,
            secret_access_key,
            None,
            None,
            "rs3-xtask",
        ))
        .force_path_style(true)
        .timeout_config(timeout_config)
        .build();
    Client::from_conf(config)
}
