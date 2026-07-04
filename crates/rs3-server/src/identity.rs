//! Request identity and authorization contracts.

use rs3_crypto::ct_eq;
use rs3_types::PublicBucket;
use secrecy::{ExposeSecret, SecretString};
use std::fmt;
use thiserror::Error;

/// Static S3-compatible access credentials.
#[derive(Clone)]
pub struct StaticCredentials {
    /// S3 access key ID.
    pub access_key_id: String,
    /// S3 secret access key.
    pub secret_access_key: SecretString,
}

impl fmt::Debug for StaticCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StaticCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .finish()
    }
}

impl PartialEq for StaticCredentials {
    fn eq(&self, other: &Self) -> bool {
        self.access_key_id == other.access_key_id
            && ct_eq(
                self.secret_access_key.expose_secret().as_bytes(),
                other.secret_access_key.expose_secret().as_bytes(),
            )
    }
}

impl Eq for StaticCredentials {}

/// Authenticated request identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    /// Stable subject name used for authorization decisions and audit logs.
    pub subject: String,
}

/// Repository operation requested through the server surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestAction {
    /// List bucket contents.
    ListBucket,
    /// Read object metadata.
    HeadObject,
    /// Read object bytes.
    GetObject,
    /// Write object bytes.
    PutObject,
    /// Delete an object.
    DeleteObject,
    /// Run an administrative dry-run report.
    AdminReport,
}

/// Authentication and authorization errors.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    /// The presented credentials are missing or invalid.
    #[error("invalid credentials")]
    InvalidCredentials,
    /// The authenticated identity is not allowed to perform the requested action.
    #[error("access denied for requested bucket/action")]
    AccessDenied {
        /// Requested bucket.
        bucket: PublicBucket,
        /// Requested operation.
        action: RequestAction,
    },
}

/// Authenticates presented request credentials.
pub trait IdentityProvider {
    /// Authenticates an access key ID and secret access key.
    fn authenticate(
        &self,
        access_key_id: &str,
        secret_access_key: &str,
    ) -> Result<Identity, AuthError>;
}

/// Authorizes authenticated requests.
pub trait Authorizer {
    /// Checks whether an identity may perform an action on a bucket.
    fn authorize(
        &self,
        identity: &Identity,
        bucket: &PublicBucket,
        action: RequestAction,
    ) -> Result<(), AuthError>;
}

/// Static single-identity provider for deployments with externally managed credentials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticCredentialProvider {
    credentials: StaticCredentials,
    allowed_bucket: PublicBucket,
}

impl StaticCredentialProvider {
    /// Creates a static credential provider scoped to one public bucket.
    pub fn new(credentials: StaticCredentials, allowed_bucket: PublicBucket) -> Self {
        Self {
            credentials,
            allowed_bucket,
        }
    }
}

impl IdentityProvider for StaticCredentialProvider {
    fn authenticate(
        &self,
        access_key_id: &str,
        secret_access_key: &str,
    ) -> Result<Identity, AuthError> {
        if self.credentials.access_key_id != access_key_id
            || !ct_eq(
                self.credentials
                    .secret_access_key
                    .expose_secret()
                    .as_bytes(),
                secret_access_key.as_bytes(),
            )
        {
            return Err(AuthError::InvalidCredentials);
        }

        Ok(Identity {
            subject: self.credentials.access_key_id.clone(),
        })
    }
}

impl Authorizer for StaticCredentialProvider {
    fn authorize(
        &self,
        _identity: &Identity,
        bucket: &PublicBucket,
        action: RequestAction,
    ) -> Result<(), AuthError> {
        if bucket != &self.allowed_bucket {
            return Err(AuthError::AccessDenied {
                bucket: bucket.clone(),
                action,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuthError, Authorizer, IdentityProvider, RequestAction, StaticCredentialProvider,
        StaticCredentials,
    };
    use rs3_types::PublicBucket;
    use secrecy::SecretString;

    fn bucket(value: &str) -> PublicBucket {
        match PublicBucket::new(value) {
            Ok(bucket) => bucket,
            Err(error) => panic!("{error}"),
        }
    }

    fn provider() -> StaticCredentialProvider {
        StaticCredentialProvider::new(
            StaticCredentials {
                access_key_id: "rs3-fixture-access-key".to_owned(),
                secret_access_key: SecretString::from("rs3-fixture-secret-key"),
            },
            bucket("backups"),
        )
    }

    #[test]
    fn authenticates_static_credentials() {
        let provider = provider();

        let identity = provider.authenticate("rs3-fixture-access-key", "rs3-fixture-secret-key");

        assert_eq!(
            identity,
            Ok(super::Identity {
                subject: "rs3-fixture-access-key".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_invalid_static_secret() {
        let provider = provider();

        let identity = provider.authenticate("rs3-fixture-access-key", "wrong");

        assert_eq!(identity, Err(AuthError::InvalidCredentials));
    }

    #[test]
    fn authorizes_only_configured_bucket() {
        let provider = provider();
        let identity = provider.authenticate("rs3-fixture-access-key", "rs3-fixture-secret-key");
        let identity = match identity {
            Ok(identity) => identity,
            Err(error) => panic!("{error}"),
        };

        let allowed = provider.authorize(&identity, &bucket("backups"), RequestAction::PutObject);
        let denied = provider.authorize(&identity, &bucket("other"), RequestAction::GetObject);

        assert_eq!(allowed, Ok(()));
        assert!(matches!(denied, Err(AuthError::AccessDenied { .. })));
        let rendered = denied
            .err()
            .unwrap_or_else(|| panic!("expected access denial"))
            .to_string();
        assert!(!rendered.contains("other"));
        assert!(!rendered.contains("GetObject"));
    }

    #[test]
    fn secret_debug_output_is_redacted() {
        let credentials = StaticCredentials {
            access_key_id: "rs3-fixture-access-key".to_owned(),
            secret_access_key: SecretString::from("top-secret-token"),
        };

        let debug = format!("{credentials:?}");

        assert!(debug.contains("rs3-fixture-access-key"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("top-secret-token"));
    }
}
