//! TCP listener and HTTP serving loop for the S3 boundary.

use crate::{GatewayS3Boundary, RuntimeConfig, S3BoundaryError};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnectionBuilder;
use hyper_util::server::graceful::GracefulShutdown;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound S3 server ready to accept client connections.
pub struct GatewayServer {
    config: RuntimeConfig,
    boundary: GatewayS3Boundary,
    listener: TcpListener,
    local_addr: SocketAddr,
}

impl GatewayServer {
    /// Binds the gateway listener and builds the S3 boundary.
    ///
    /// # Errors
    ///
    /// Returns an error when boundary construction fails, binding fails, or the
    /// listener address cannot be read.
    pub async fn bind(config: RuntimeConfig) -> Result<Self, GatewayServerError> {
        let boundary = GatewayS3Boundary::build(config.clone()).await?;
        let listener =
            TcpListener::bind(config.bind)
                .await
                .map_err(|source| GatewayServerError::Bind {
                    bind: config.bind,
                    source,
                })?;
        let local_addr = listener
            .local_addr()
            .map_err(GatewayServerError::LocalAddr)?;

        Ok(Self {
            config,
            boundary,
            listener,
            local_addr,
        })
    }

    /// Returns the validated runtime configuration used by this server.
    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    /// Returns the address actually bound by the listener.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Serves connections until the provided shutdown future resolves.
    ///
    /// Existing connections are given a short graceful shutdown window after
    /// the listener stops accepting new connections.
    ///
    /// # Errors
    ///
    /// Returns an error when accepting a connection fails or graceful shutdown
    /// does not finish before the timeout.
    pub async fn run_until_shutdown<F>(self, shutdown: F) -> Result<(), GatewayServerError>
    where
        F: Future<Output = ()>,
    {
        let GatewayServer {
            config,
            boundary,
            listener,
            ..
        } = self;
        let service = boundary.into_service();
        let connection_builder = ConnectionBuilder::new(TokioExecutor::new());
        let graceful = GracefulShutdown::new();
        let mut shutdown = std::pin::pin!(shutdown);
        let connection_slots =
            Arc::new(Semaphore::new(config.hardening.max_concurrent_connections));

        loop {
            let (stream, remote_addr) = tokio::select! {
                result = listener.accept() => {
                    result.map_err(GatewayServerError::Accept)?
                }
                () = shutdown.as_mut() => {
                    break;
                }
            };

            let connection_permit = match connection_slots.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_error) => {
                    record_s3_connection_rejection();
                    tracing::debug!(
                        %remote_addr,
                        "S3 HTTP connection rejected by configured connection limit",
                    );
                    continue;
                }
            };
            let connection =
                connection_builder.serve_connection(TokioIo::new(stream), service.clone());
            let connection = graceful.watch(connection.into_owned());

            tokio::spawn(async move {
                let _connection_permit = connection_permit;
                if let Err(error) = connection.await {
                    tracing::debug!(
                        %remote_addr,
                        %error,
                        "S3 HTTP connection ended with error",
                    );
                }
            });
        }

        tokio::select! {
            () = graceful.shutdown() => Ok(()),
            () = tokio::time::sleep(GRACEFUL_SHUTDOWN_TIMEOUT) => {
                Err(GatewayServerError::ShutdownTimeout {
                    timeout: GRACEFUL_SHUTDOWN_TIMEOUT,
                })
            }
        }
    }
}

fn record_s3_connection_rejection() {
    metrics::counter!("rs3_s3_connection_admission_rejections_total").increment(1);
}

/// Server binding and serving errors.
#[derive(Debug, Error)]
pub enum GatewayServerError {
    /// S3 boundary construction failed.
    #[error(transparent)]
    Boundary(#[from] S3BoundaryError),
    /// TCP listener bind failed.
    #[error("failed to bind S3 listener at {bind}: {source}")]
    Bind {
        /// Requested bind address.
        bind: SocketAddr,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Reading the listener's local address failed.
    #[error("failed to read S3 listener address: {0}")]
    LocalAddr(#[source] std::io::Error),
    /// Accepting a client connection failed.
    #[error("failed to accept S3 client connection: {0}")]
    Accept(#[source] std::io::Error),
    /// Graceful shutdown exceeded the configured timeout.
    #[error("S3 server shutdown did not finish within {timeout:?}")]
    ShutdownTimeout {
        /// Graceful shutdown timeout.
        timeout: Duration,
    },
}

#[cfg(test)]
mod tests {
    use super::{GatewayServer, GatewayServerError};
    use crate::HardeningConfig;
    use crate::{
        AnchorConfig, BackendConfig, BatchConfig, GatewayMode, MetricsConfig,
        ProviderConformanceConfig, RepositoryConfig, RepositoryKeysConfig, RuntimeConfig,
        SecretString,
    };
    use rs3_types::{BackendObjectId, PublicBucket, RepositoryId};
    use std::time::Duration;

    fn runtime_config(static_credentials: bool) -> RuntimeConfig {
        let bind = match "127.0.0.1:0".parse() {
            Ok(bind) => bind,
            Err(error) => panic!("{error}"),
        };
        let public_bucket = match PublicBucket::new("client-bucket") {
            Ok(bucket) => bucket,
            Err(error) => panic!("{error}"),
        };

        RuntimeConfig {
            mode: GatewayMode::ReadWrite,
            bind,
            metrics: MetricsConfig { bind: None },
            hardening: HardeningConfig::default(),
            public_bucket,
            backend: BackendConfig {
                endpoint: "memory://local".to_owned(),
                bucket: "backend-bucket".to_owned(),
                prefix: Some("repo".to_owned()),
            },
            anchor: AnchorConfig::Memory,
            batching: BatchConfig {
                max_items: 64,
                max_delay: Duration::from_millis(10),
                max_pending_items: 64,
            },
            repository: RepositoryConfig {
                format: crate::RepositoryFormat::V2Preview,
                payload_segment_size: rs3_repository::DEFAULT_PAYLOAD_SEGMENT_SIZE,
                adaptive_payload_segment_size: true,
                decrypted_segment_cache_max_bytes:
                    rs3_repository::DEFAULT_DECRYPTED_SEGMENT_CACHE_MAX_BYTES,
                retention: None,
                allow_init: true,
            },
            provider_conformance: ProviderConformanceConfig::default(),
            repository_keys: RepositoryKeysConfig {
                repository_id: RepositoryId::new("test-repository")
                    .unwrap_or_else(|error| panic!("{error}")),
                repository_salt_hex:
                    "2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
                envelope_object_id: Some(
                    BackendObjectId::new("keyrings/test-envelope.json")
                        .unwrap_or_else(|error| panic!("{error}")),
                ),
                wrapping_key_id: "wrap-v1".to_owned(),
                wrapping_key_hex: SecretString::from(
                    "3333333333333333333333333333333333333333333333333333333333333333",
                ),
            },
            static_credentials: static_credentials.then(|| crate::StaticCredentials {
                access_key_id: "access".to_owned(),
                secret_access_key: SecretString::from("secret"),
            }),
        }
    }

    #[tokio::test]
    async fn server_requires_boundary_credentials() {
        let server = GatewayServer::bind(runtime_config(false)).await;

        assert!(matches!(server, Err(GatewayServerError::Boundary(_))));
    }

    #[tokio::test]
    async fn server_binds_ephemeral_port() {
        let server = match GatewayServer::bind(runtime_config(true)).await {
            Ok(server) => server,
            Err(error) => panic!("{error}"),
        };

        assert_eq!(server.config().bind.port(), 0);
        assert_ne!(server.local_addr().port(), 0);
    }

    #[tokio::test]
    async fn server_stops_on_shutdown_signal() {
        let server = match GatewayServer::bind(runtime_config(true)).await {
            Ok(server) => server,
            Err(error) => panic!("{error}"),
        };
        let result = server.run_until_shutdown(async {}).await;

        assert!(result.is_ok());
    }
}
