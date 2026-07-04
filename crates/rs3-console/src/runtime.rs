use crate::{
    ConsoleBearerToken, ConsoleHttpAuth, ConsoleHttpAuthError, GatewayAdminBearerToken,
    GatewayAdminClientConfig, GatewayAdminEndpoint, GatewayAdminEndpointError,
};
use std::env;
use std::fmt;
use std::net::SocketAddr;
use thiserror::Error;

const DEFAULT_BIND: &str = "127.0.0.1:9083";
const ENV_BIND: &str = "RS3_CONSOLE_BIND";
const ENV_CONSOLE_TOKEN: &str = "RS3_CONSOLE_BEARER_TOKEN";
const ENV_GATEWAY_ADMIN_URL: &str = "RS3_GATEWAY_ADMIN_URL";
const ENV_GATEWAY_ADMIN_TOKEN: &str = "RS3_GATEWAY_ADMIN_BEARER_TOKEN";

/// Runtime configuration for the single-gateway console.
#[derive(Clone, PartialEq, Eq)]
pub struct ConsoleRuntimeConfig {
    /// Console listener bind address.
    pub bind: SocketAddr,
    /// Authentication policy for console API routes.
    pub auth: ConsoleHttpAuth,
    /// Gateway admin client configuration.
    pub gateway_admin: GatewayAdminClientConfig,
}

impl fmt::Debug for ConsoleRuntimeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsoleRuntimeConfig")
            .field("bind", &self.bind)
            .field("auth", &self.auth)
            .field("gateway_admin_configured", &true)
            .finish()
    }
}

impl ConsoleRuntimeConfig {
    /// Loads runtime configuration from environment variables.
    ///
    /// `RS3_CONSOLE_BEARER_TOKEN`, `RS3_GATEWAY_ADMIN_URL`, and
    /// `RS3_GATEWAY_ADMIN_BEARER_TOKEN` are required. `RS3_CONSOLE_BIND`
    /// defaults to `127.0.0.1:9083`.
    ///
    /// # Errors
    ///
    /// Returns an error when required values are missing or invalid.
    pub fn from_env() -> Result<Self, ConsoleRuntimeConfigError> {
        let bind = env::var(ENV_BIND).ok();
        let console_token = env::var(ENV_CONSOLE_TOKEN).ok();
        let gateway_admin_url = env::var(ENV_GATEWAY_ADMIN_URL).ok();
        let gateway_admin_token = env::var(ENV_GATEWAY_ADMIN_TOKEN).ok();

        Self::from_env_values(
            bind.as_deref(),
            console_token.as_deref(),
            gateway_admin_url.as_deref(),
            gateway_admin_token.as_deref(),
        )
    }

    fn from_env_values(
        bind: Option<&str>,
        console_token: Option<&str>,
        gateway_admin_url: Option<&str>,
        gateway_admin_token: Option<&str>,
    ) -> Result<Self, ConsoleRuntimeConfigError> {
        let bind_value = bind.unwrap_or(DEFAULT_BIND);
        let bind = bind_value
            .parse()
            .map_err(|source| ConsoleRuntimeConfigError::InvalidBind {
                value: bind_value.to_owned(),
                source,
            })?;
        let console_token =
            console_token.ok_or(ConsoleRuntimeConfigError::MissingConsoleBearerToken)?;
        let console_token = ConsoleBearerToken::new(console_token.to_owned())
            .map_err(ConsoleRuntimeConfigError::InvalidConsoleBearerToken)?;
        let gateway_admin_url =
            gateway_admin_url.ok_or(ConsoleRuntimeConfigError::MissingGatewayAdminUrl)?;
        let endpoint = GatewayAdminEndpoint::parse(gateway_admin_url)
            .map_err(ConsoleRuntimeConfigError::InvalidGatewayAdminUrl)?;
        let gateway_admin_token =
            gateway_admin_token.ok_or(ConsoleRuntimeConfigError::MissingGatewayAdminBearerToken)?;
        let gateway_admin_token = GatewayAdminBearerToken::new(gateway_admin_token.to_owned())
            .map_err(ConsoleRuntimeConfigError::InvalidGatewayAdminBearerToken)?;

        Ok(Self {
            bind,
            auth: ConsoleHttpAuth::bearer(console_token),
            gateway_admin: GatewayAdminClientConfig::new(endpoint, gateway_admin_token),
        })
    }
}

/// Runtime configuration errors.
#[derive(Debug, Error)]
pub enum ConsoleRuntimeConfigError {
    /// Listener bind address is invalid.
    #[error("invalid RS3_CONSOLE_BIND value {value:?}: {source}")]
    InvalidBind {
        /// Rejected bind address.
        value: String,
        /// Parse error.
        source: std::net::AddrParseError,
    },
    /// Console bearer token is missing.
    #[error("RS3_CONSOLE_BEARER_TOKEN is required")]
    MissingConsoleBearerToken,
    /// Console bearer token is invalid.
    #[error(transparent)]
    InvalidConsoleBearerToken(ConsoleHttpAuthError),
    /// Gateway admin URL is missing.
    #[error("RS3_GATEWAY_ADMIN_URL is required")]
    MissingGatewayAdminUrl,
    /// Gateway admin URL is invalid.
    #[error(transparent)]
    InvalidGatewayAdminUrl(GatewayAdminEndpointError),
    /// Gateway admin bearer token is missing.
    #[error("RS3_GATEWAY_ADMIN_BEARER_TOKEN is required")]
    MissingGatewayAdminBearerToken,
    /// Gateway admin bearer token is invalid.
    #[error(transparent)]
    InvalidGatewayAdminBearerToken(crate::GatewayAdminClientError),
}

#[cfg(test)]
mod tests {
    use super::{ConsoleRuntimeConfig, ConsoleRuntimeConfigError};
    use std::net::SocketAddr;

    #[test]
    fn runtime_config_defaults_bind_and_redacts_debug() {
        let config = ConsoleRuntimeConfig::from_env_values(
            None,
            Some("console-token-12345"),
            Some("http://127.0.0.1:9082"),
            Some("gateway-admin-token-12345"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let bind: SocketAddr = "127.0.0.1:9083"
            .parse()
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(config.bind, bind);
        let encoded = format!("{config:?}");
        assert!(!encoded.contains("console-token"));
        assert!(!encoded.contains("gateway-admin-token"));
        assert!(!encoded.contains("127.0.0.1:9082"));
    }

    #[test]
    fn runtime_config_rejects_missing_console_token() {
        let error = match ConsoleRuntimeConfig::from_env_values(
            None,
            None,
            Some("http://127.0.0.1:9082"),
            Some("gateway-admin-token-12345"),
        ) {
            Ok(config) => panic!("unexpected config: {config:?}"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ConsoleRuntimeConfigError::MissingConsoleBearerToken
        ));
    }

    #[test]
    fn runtime_config_accepts_https_gateway_admin_url_and_redacts_debug() {
        let config = ConsoleRuntimeConfig::from_env_values(
            Some("127.0.0.1:0"),
            Some("console-token-12345"),
            Some("https://127.0.0.1:9082"),
            Some("gateway-admin-token-12345"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let encoded = format!("{config:?}");

        assert!(!encoded.contains("127.0.0.1:9082"));
        assert!(!encoded.contains("gateway-admin-token"));
    }
}
