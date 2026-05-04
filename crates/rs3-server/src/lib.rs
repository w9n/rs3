//! Server-side runtime configuration and request identity contracts.

mod config;
mod identity;
mod s3;
mod server;

pub use config::{
    AnchorConfig, BackendConfig, BatchConfig, ConfigError, GatewayMode, MetricsConfig,
    RepositoryConfig, RepositoryKeysConfig, RuntimeConfig,
};
pub use identity::{
    AuthError, Authorizer, Identity, IdentityProvider, RequestAction, StaticCredentialProvider,
    StaticCredentials,
};
pub use s3::{
    AnchorRecoveryError, AnchorRecoveryOptions, AnchorRecoveryReport, GatewayS3Boundary,
    S3BoundaryError, S3Hardening, recover_anchor_from_config,
};
pub use secrecy::SecretString;
pub use server::{GatewayServer, GatewayServerError};
