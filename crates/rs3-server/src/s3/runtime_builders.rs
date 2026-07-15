use super::runtime_handles::{RuntimeStore, RuntimeV2Anchor};
use super::{S3BoundaryError, repository_init};
use crate::{AnchorConfig, BackendConfig, BatchConfig};
#[cfg(feature = "k8s")]
use rs3_k8s::{KubernetesLeaseAnchor, LeaseSettings, WriterFence};
use rs3_repository::CommitCoordinatorOptions;
use rs3_repository::v2::V2MemoryAnchor;
use rs3_storage::{FilesystemBlobStore, MemoryBlobStore};
#[cfg(feature = "s3")]
use rs3_storage::{S3BlobStore, S3BlobStoreConfig, S3ClientTimeoutConfig};
use std::path::{Component, Path, PathBuf};

pub(super) struct StoreBuild {
    handle: RuntimeStore,
    #[cfg(feature = "s3")]
    s3_store: Option<S3BlobStore>,
    #[cfg(test)]
    memory_store: Option<MemoryBlobStore>,
}

pub(super) struct V2AnchorBuild {
    handle: RuntimeV2Anchor,
    #[cfg(test)]
    memory_anchor: Option<V2MemoryAnchor>,
}

impl StoreBuild {
    pub(super) fn handle(&self) -> &RuntimeStore {
        &self.handle
    }

    pub(super) fn into_handle(self) -> RuntimeStore {
        self.handle
    }

    #[cfg(feature = "s3")]
    pub(super) fn s3_store(&self) -> Option<&S3BlobStore> {
        self.s3_store.as_ref()
    }

    #[cfg(test)]
    pub(super) fn memory_store(&self) -> Option<&MemoryBlobStore> {
        self.memory_store.as_ref()
    }
}

impl V2AnchorBuild {
    pub(super) fn handle(&self) -> &RuntimeV2Anchor {
        &self.handle
    }

    #[cfg(test)]
    pub(super) fn memory_anchor(&self) -> Option<&V2MemoryAnchor> {
        self.memory_anchor.as_ref()
    }
}

pub(super) async fn build_store(config: &BackendConfig) -> Result<StoreBuild, S3BoundaryError> {
    if is_memory_backend(config) {
        let store = MemoryBlobStore::new();
        return Ok(StoreBuild {
            handle: RuntimeStore::new(store.clone()),
            #[cfg(feature = "s3")]
            s3_store: None,
            #[cfg(test)]
            memory_store: Some(store),
        });
    }

    if let Some(root) = filesystem_backend_root(config)? {
        let store = FilesystemBlobStore::new(root).map_err(repository_init)?;
        return Ok(StoreBuild {
            handle: RuntimeStore::new(store),
            #[cfg(feature = "s3")]
            s3_store: None,
            #[cfg(test)]
            memory_store: None,
        });
    }

    #[cfg(feature = "s3")]
    if let Some(store) = s3_backend_store(config).await? {
        return Ok(StoreBuild {
            handle: RuntimeStore::new(store.clone()),
            s3_store: Some(store),
            #[cfg(test)]
            memory_store: None,
        });
    }

    Err(S3BoundaryError::UnsupportedBackendMode)
}

#[cfg(feature = "k8s")]
pub(super) fn build_v2_anchor(config: &AnchorConfig) -> Result<V2AnchorBuild, S3BoundaryError> {
    build_v2_anchor_with_writer_fence(config, None)
}

#[cfg(not(feature = "k8s"))]
pub(super) fn build_v2_anchor(config: &AnchorConfig) -> Result<V2AnchorBuild, S3BoundaryError> {
    build_v2_anchor_inner(config)
}

#[cfg(feature = "k8s")]
pub(super) fn build_v2_anchor_with_writer_fence(
    config: &AnchorConfig,
    writer_fence: Option<WriterFence>,
) -> Result<V2AnchorBuild, S3BoundaryError> {
    match config {
        AnchorConfig::Memory => {
            let anchor = V2MemoryAnchor::new();
            Ok(V2AnchorBuild {
                handle: RuntimeV2Anchor::new(anchor.clone()),
                #[cfg(test)]
                memory_anchor: Some(anchor),
            })
        }
        AnchorConfig::KubernetesLease {
            namespace,
            name,
            field_manager,
        } => {
            #[cfg(feature = "k8s")]
            {
                let settings = LeaseSettings {
                    namespace: namespace.clone(),
                    name: name.clone(),
                    field_manager: field_manager.clone(),
                };
                let anchor = match writer_fence {
                    Some(writer_fence) => KubernetesLeaseAnchor::new_fenced(settings, writer_fence),
                    None => KubernetesLeaseAnchor::new(settings),
                };
                Ok(V2AnchorBuild {
                    handle: RuntimeV2Anchor::new(anchor),
                    #[cfg(test)]
                    memory_anchor: None,
                })
            }
            #[cfg(not(feature = "k8s"))]
            {
                let _ = (namespace, name, field_manager);
                Err(S3BoundaryError::UnsupportedAnchorMode)
            }
        }
    }
}

#[cfg(not(feature = "k8s"))]
fn build_v2_anchor_inner(config: &AnchorConfig) -> Result<V2AnchorBuild, S3BoundaryError> {
    match config {
        AnchorConfig::Memory => {
            let anchor = V2MemoryAnchor::new();
            Ok(V2AnchorBuild {
                handle: RuntimeV2Anchor::new(anchor.clone()),
                #[cfg(test)]
                memory_anchor: Some(anchor),
            })
        }
        AnchorConfig::KubernetesLease {
            namespace,
            name,
            field_manager,
        } => {
            let _ = (namespace, name, field_manager);
            Err(S3BoundaryError::UnsupportedAnchorMode)
        }
    }
}

pub(super) fn coordinator_options(config: BatchConfig) -> CommitCoordinatorOptions {
    CommitCoordinatorOptions::new(config.max_items, config.max_delay)
        .with_max_pending_items(config.max_pending_items)
}

fn is_memory_backend(config: &BackendConfig) -> bool {
    config.endpoint == "memory" || config.endpoint.starts_with("memory://")
}

fn filesystem_backend_root(config: &BackendConfig) -> Result<Option<PathBuf>, S3BoundaryError> {
    let Some(endpoint_path) = config.endpoint.strip_prefix("file://") else {
        return Ok(None);
    };
    if endpoint_path.is_empty() {
        return Err(repository_init("file backend endpoint must include a path"));
    }

    let mut root = PathBuf::from(endpoint_path);
    push_relative_component(&mut root, &config.bucket)?;
    if let Some(prefix) = config.prefix.as_deref() {
        push_relative_component(&mut root, prefix)?;
    }

    Ok(Some(root))
}

#[cfg(feature = "s3")]
async fn s3_backend_store(config: &BackendConfig) -> Result<Option<S3BlobStore>, S3BoundaryError> {
    let Some(store_config) = s3_backend_config(config)? else {
        return Ok(None);
    };

    S3BlobStore::from_environment(store_config)
        .await
        .map(Some)
        .map_err(repository_init)
}

#[cfg(feature = "s3")]
pub(super) fn s3_backend_config(
    config: &BackendConfig,
) -> Result<Option<S3BlobStoreConfig>, S3BoundaryError> {
    let endpoint_url = match config.endpoint.as_str() {
        "s3" | "s3://" | "s3://aws" => None,
        endpoint if endpoint.starts_with("https://") || endpoint.starts_with("http://") => {
            Some(endpoint.to_owned())
        }
        _ => return Ok(None),
    };
    let allow_http = endpoint_url
        .as_deref()
        .is_some_and(|endpoint| endpoint.starts_with("http://"));
    let config = S3BlobStoreConfig::new(config.bucket.clone())
        .map_err(repository_init)?
        .with_prefix(config.prefix.clone())
        .with_endpoint_url(endpoint_url)
        .with_region(None)
        .with_allow_http(allow_http)
        .with_virtual_hosted_style(false)
        .with_timeouts(S3ClientTimeoutConfig {
            connect: config.timeouts.connect,
            read: config.timeouts.read,
            operation_attempt: config.timeouts.operation_attempt,
            operation: config.timeouts.operation,
            stalled_stream_grace: config.timeouts.stalled_stream_grace,
        });

    Ok(Some(config))
}

fn push_relative_component(root: &mut PathBuf, value: &str) -> Result<(), S3BoundaryError> {
    for component in Path::new(value).components() {
        match component {
            Component::Normal(component) => root.push(component),
            Component::CurDir => {}
            Component::RootDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(repository_init(
                    "file backend bucket and prefix must be relative paths",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(all(test, feature = "s3"))]
mod tests {
    use super::s3_backend_config;
    use crate::{BackendConfig, BackendTimeoutConfig};
    use std::time::Duration;

    #[test]
    fn s3_backend_receives_every_runtime_timeout() {
        let backend = BackendConfig {
            endpoint: "https://storage.example".to_owned(),
            bucket: "bucket".to_owned(),
            prefix: Some("prefix".to_owned()),
            timeouts: BackendTimeoutConfig {
                connect: Duration::from_secs(1),
                read: Duration::from_secs(2),
                operation_attempt: Duration::from_secs(3),
                operation: Duration::from_secs(4),
                stalled_stream_grace: Duration::from_secs(5),
            },
        };

        let config = s3_backend_config(&backend)
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("expected S3 backend config"));

        assert_eq!(config.timeouts.connect, Duration::from_secs(1));
        assert_eq!(config.timeouts.read, Duration::from_secs(2));
        assert_eq!(config.timeouts.operation_attempt, Duration::from_secs(3));
        assert_eq!(config.timeouts.operation, Duration::from_secs(4));
        assert_eq!(config.timeouts.stalled_stream_grace, Duration::from_secs(5));
    }
}
