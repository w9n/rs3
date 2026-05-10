//! HTTP entry point for the read-only rs3 single-gateway console.

use rs3_console::{
    ConsoleHttpServer, ConsoleHttpService, ConsoleRuntimeConfig, GatewayAdminClient,
};
use std::error::Error;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    init_tracing();

    let config = ConsoleRuntimeConfig::from_env()?;
    let admin_client = GatewayAdminClient::new(config.gateway_admin.clone());
    let service = ConsoleHttpService::new(admin_client, config.auth.clone());
    let server = ConsoleHttpServer::bind_service(config.bind, service).await?;

    tracing::info!(
        bind = %server.local_addr(),
        auth = "bearer",
        gateway_admin = "configured",
        "rs3 console listener started",
    );
    server.run_until_shutdown(shutdown_signal()).await?;
    Ok(())
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::warn!(%error, "failed to install Ctrl+C shutdown handler");
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if std::env::var("RS3_LOG_FORMAT").as_deref() == Ok("json") {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}
