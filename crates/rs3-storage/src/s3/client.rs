use super::config::{S3BlobStoreConfig, S3ClientTimeoutConfig, non_blank};
use crate::{Result, StorageError};
use aws_sdk_s3::{
    Client as SdkS3Client,
    config::{BehaviorVersion, Credentials, Region, StalledStreamProtectionConfig},
};
use aws_smithy_types::timeout::TimeoutConfig;
use std::sync::Once;

static RUSTLS_PROVIDER: Once = Once::new();

pub(super) fn install_rustls_provider() {
    RUSTLS_PROVIDER.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

pub(super) async fn sdk_client_from_environment(config: &S3BlobStoreConfig) -> Result<SdkS3Client> {
    validate_endpoint(config)?;
    let region = aws_config::meta::region::RegionProviderChain::first_try(
        config.region.clone().map(Region::new),
    )
    .or_default_provider()
    .or_else(Region::new("us-east-1"));
    let shared_config = aws_config::defaults(BehaviorVersion::latest())
        .region(region)
        .load()
        .await;
    let mut builder = aws_sdk_s3::config::Builder::from(&shared_config)
        .force_path_style(!config.virtual_hosted_style)
        .timeout_config(sdk_timeout_config(config.timeouts))
        .stalled_stream_protection(stalled_stream_config(config.timeouts));
    if let Some(endpoint_url) = config.endpoint_url.as_deref() {
        builder = builder.endpoint_url(endpoint_url);
    }

    Ok(SdkS3Client::from_conf(builder.build()))
}

pub(super) fn sdk_client_from_static_environment(
    config: &S3BlobStoreConfig,
) -> Result<SdkS3Client> {
    validate_endpoint(config)?;
    let access_key = optional_env_value("AWS_ACCESS_KEY_ID")?;
    let secret_key = optional_env_value("AWS_SECRET_ACCESS_KEY")?;
    let (access_key, secret_key) = match (access_key, secret_key) {
        (Some(access_key), Some(secret_key)) => (access_key, secret_key),
        (None, None) => {
            return Err(StorageError::Provider(
                "synchronous S3 construction requires AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY; use S3BlobStore::from_environment for the full AWS credential chain"
                    .to_owned(),
            ));
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(StorageError::Provider(
                "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be provided together".to_owned(),
            ));
        }
    };

    let session_token = optional_env_value("AWS_SESSION_TOKEN")?;
    let region = config
        .region
        .clone()
        .or(optional_env_value("AWS_REGION")?)
        .or(optional_env_value("AWS_DEFAULT_REGION")?)
        .unwrap_or_else(|| "us-east-1".to_owned());
    let credentials = Credentials::new(
        access_key,
        secret_key,
        session_token,
        None,
        "rs3-storage-env",
    );
    let mut builder = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(region))
        .force_path_style(!config.virtual_hosted_style)
        .credentials_provider(credentials)
        .timeout_config(sdk_timeout_config(config.timeouts))
        .stalled_stream_protection(stalled_stream_config(config.timeouts));

    if let Some(endpoint_url) = config.endpoint_url.as_deref() {
        builder = builder.endpoint_url(endpoint_url);
    }

    Ok(SdkS3Client::from_conf(builder.build()))
}

fn sdk_timeout_config(timeouts: S3ClientTimeoutConfig) -> TimeoutConfig {
    TimeoutConfig::builder()
        .connect_timeout(timeouts.connect)
        .read_timeout(timeouts.read)
        .operation_attempt_timeout(timeouts.operation_attempt)
        .operation_timeout(timeouts.operation)
        .build()
}

fn stalled_stream_config(timeouts: S3ClientTimeoutConfig) -> StalledStreamProtectionConfig {
    StalledStreamProtectionConfig::enabled()
        .grace_period(timeouts.stalled_stream_grace)
        .build()
}

fn validate_endpoint(config: &S3BlobStoreConfig) -> Result<()> {
    if !config.allow_http
        && config
            .endpoint_url
            .as_deref()
            .is_some_and(|endpoint| endpoint.starts_with("http://"))
    {
        return Err(StorageError::Provider(
            "plain HTTP S3 endpoints require allow_http=true".to_owned(),
        ));
    }
    Ok(())
}

fn optional_env_value(name: &str) -> Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) => Ok(non_blank(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(StorageError::Provider(format!(
            "{name} must be valid Unicode"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{sdk_timeout_config, stalled_stream_config};
    use crate::S3ClientTimeoutConfig;
    use std::time::Duration;

    #[test]
    fn maps_every_finite_timeout_into_the_aws_sdk() {
        let timeouts = S3ClientTimeoutConfig {
            connect: Duration::from_secs(1),
            read: Duration::from_secs(2),
            operation_attempt: Duration::from_secs(3),
            operation: Duration::from_secs(4),
            stalled_stream_grace: Duration::from_secs(5),
        };

        let sdk = sdk_timeout_config(timeouts);
        assert_eq!(sdk.connect_timeout(), Some(Duration::from_secs(1)));
        assert_eq!(sdk.read_timeout(), Some(Duration::from_secs(2)));
        assert_eq!(
            sdk.operation_attempt_timeout(),
            Some(Duration::from_secs(3))
        );
        assert_eq!(sdk.operation_timeout(), Some(Duration::from_secs(4)));

        let stalled = stalled_stream_config(timeouts);
        assert!(stalled.upload_enabled());
        assert!(stalled.download_enabled());
        assert_eq!(stalled.grace_period(), Duration::from_secs(5));
    }
}
