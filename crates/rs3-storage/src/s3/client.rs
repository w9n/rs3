use super::config::{S3BlobStoreConfig, non_blank};
use crate::{Result, StorageError};
use aws_sdk_s3::{
    Client as SdkS3Client,
    config::{BehaviorVersion, Credentials, Region},
};
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
        .force_path_style(!config.virtual_hosted_style);
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
        .credentials_provider(credentials);

    if let Some(endpoint_url) = config.endpoint_url.as_deref() {
        builder = builder.endpoint_url(endpoint_url);
    }

    Ok(SdkS3Client::from_conf(builder.build()))
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
