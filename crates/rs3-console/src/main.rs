//! HTTP entry point for the read-only rs3 single-gateway console.

use rs3_console::{
    ConsoleHttpServer, ConsoleHttpService, ConsoleRuntimeConfig, GatewayAdminClient,
};
use std::env::VarError;
use std::error::Error;
use std::ffi::OsStr;
use tracing_subscriber::filter::{EnvFilter, FilterExt, filter_fn};
use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_GIT_SHA: Option<&str> = option_env!("RS3_BUILD_GIT_SHA");

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    if maybe_print_version() {
        return Ok(());
    }

    init_tracing();

    let config = ConsoleRuntimeConfig::from_env()?;
    let admin_client = GatewayAdminClient::new(config.gateway_admin.clone())?;
    let service = ConsoleHttpService::new(admin_client, config.auth.clone());
    let server = ConsoleHttpServer::bind_service(config.bind, service).await?;

    tracing::info!(
        version = VERSION,
        build_git_sha = build_git_sha(),
        bind = %server.local_addr(),
        auth = "bearer",
        gateway_admin = "configured",
        "rs3 console listener started",
    );
    server.run_until_shutdown(shutdown_signal()).await?;
    Ok(())
}

fn maybe_print_version() -> bool {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() == 1 && (args[0] == OsStr::new("--version") || args[0] == OsStr::new("-V")) {
        println!("{}", version_line());
        return true;
    }
    false
}

fn version_line() -> String {
    match BUILD_GIT_SHA {
        Some(sha) => format!("rs3-console {VERSION} ({sha})"),
        None => format!("rs3-console {VERSION}"),
    }
}

fn build_git_sha() -> &'static str {
    BUILD_GIT_SHA.unwrap_or("unknown")
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::warn!(%error, "failed to install Ctrl+C shutdown handler");
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let filter = filter.and(filter_fn(|metadata| {
        is_path_safe_tracing_target(metadata.target())
    }));
    match std::env::var("RS3_LOG_FORMAT") {
        Ok(value) if value == "json" => {
            tracing_subscriber::registry()
                .with(tracing_subscriber::fmt::layer().json().with_filter(filter))
                .init();
        }
        Ok(value) => {
            tracing_subscriber::registry()
                .with(tracing_subscriber::fmt::layer().with_filter(filter))
                .init();
            if value != "plain" {
                tracing::warn!(
                    log_format = %value,
                    "unrecognized RS3_LOG_FORMAT; defaulting to plain logs",
                );
            }
        }
        Err(VarError::NotPresent) => {
            tracing_subscriber::registry()
                .with(tracing_subscriber::fmt::layer().with_filter(filter))
                .init();
        }
        Err(VarError::NotUnicode(_)) => {
            tracing_subscriber::registry()
                .with(tracing_subscriber::fmt::layer().with_filter(filter))
                .init();
            tracing::warn!("RS3_LOG_FORMAT is not valid Unicode; defaulting to plain logs");
        }
    }
}

fn is_path_safe_tracing_target(target: &str) -> bool {
    const ALLOWED_TARGETS: &[&str] = &["rs3_console", "rs3_crypto"];

    ALLOWED_TARGETS.iter().any(|allowed| {
        target == *allowed
            || target
                .strip_prefix(allowed)
                .is_some_and(|suffix| suffix.starts_with("::"))
    })
}

#[cfg(test)]
mod tests {
    use super::is_path_safe_tracing_target;

    #[test]
    fn tracing_filter_allows_console_targets_and_blocks_dependencies() {
        assert!(is_path_safe_tracing_target("rs3_console"));
        assert!(is_path_safe_tracing_target("rs3_console::http"));
        assert!(!is_path_safe_tracing_target("hyper::client"));
        assert!(!is_path_safe_tracing_target("rustls"));
    }
}
