//! Read-only single-gateway operations console.
//!
//! The console is intentionally separate from the S3 data plane. It keeps the
//! gateway admin bearer token server-side, serves a small browser UI, and
//! exposes only a read-only status API backed by the gateway's path-redacted
//! `GET /admin/status` report.

mod admin_client;
mod http;
mod runtime;
mod ui_assets;

pub use admin_client::{
    GatewayAdminBearerToken, GatewayAdminClient, GatewayAdminClientConfig, GatewayAdminClientError,
    GatewayAdminEndpoint, GatewayAdminEndpointError,
};
pub use http::{
    ConsoleBearerToken, ConsoleHttpAuth, ConsoleHttpAuthError, ConsoleHttpServer,
    ConsoleHttpServerError, ConsoleHttpService,
};
pub use runtime::{ConsoleRuntimeConfig, ConsoleRuntimeConfigError};
