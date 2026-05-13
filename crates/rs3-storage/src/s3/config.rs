use crate::{Result, StorageError};
use rs3_types::BackendObjectId;

/// Configuration for an S3-backed blob store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S3BlobStoreConfig {
    /// Backend bucket containing repository-owned objects.
    pub bucket: String,
    /// Optional key prefix for repository-owned objects inside the bucket.
    pub prefix: Option<String>,
    /// Optional custom endpoint URL for S3-compatible providers.
    pub endpoint_url: Option<String>,
    /// Optional AWS region override.
    pub region: Option<String>,
    /// Allows plain HTTP for local S3-compatible development endpoints.
    pub allow_http: bool,
    /// Uses virtual-hosted bucket addressing instead of path-style addressing.
    pub virtual_hosted_style: bool,
}

impl S3BlobStoreConfig {
    /// Creates S3 backend configuration for a bucket.
    ///
    /// # Errors
    ///
    /// Returns a provider error when the bucket is blank.
    pub fn new(bucket: impl Into<String>) -> Result<Self> {
        let bucket = bucket.into();
        if bucket.trim().is_empty() {
            return Err(StorageError::Provider(
                "S3 backend bucket cannot be empty".to_owned(),
            ));
        }

        Ok(Self {
            bucket,
            prefix: None,
            endpoint_url: None,
            region: None,
            allow_http: false,
            virtual_hosted_style: false,
        })
    }

    /// Sets the repository-owned key prefix.
    pub fn with_prefix(mut self, prefix: Option<String>) -> Self {
        self.prefix = normalize_prefix(prefix);
        self
    }

    /// Sets a custom endpoint URL.
    pub fn with_endpoint_url(mut self, endpoint_url: Option<String>) -> Self {
        self.endpoint_url = endpoint_url.and_then(non_blank);
        self
    }

    /// Sets an AWS region override.
    pub fn with_region(mut self, region: Option<String>) -> Self {
        self.region = region.and_then(non_blank);
        self
    }

    /// Enables or disables plain HTTP endpoints.
    pub fn with_allow_http(mut self, allow_http: bool) -> Self {
        self.allow_http = allow_http;
        self
    }

    /// Enables or disables virtual-hosted bucket addressing.
    pub fn with_virtual_hosted_style(mut self, virtual_hosted_style: bool) -> Self {
        self.virtual_hosted_style = virtual_hosted_style;
        self
    }

    fn base_prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }

    pub(super) fn object_key(&self, object_id: &BackendObjectId) -> String {
        join_key(self.base_prefix(), object_id.as_str())
    }

    pub(super) fn list_key_prefix(&self, prefix: &str) -> String {
        join_key(self.base_prefix(), prefix)
    }

    pub(super) fn object_id_from_key(&self, key: &str) -> Result<Option<BackendObjectId>> {
        let relative = match self.base_prefix() {
            Some(prefix) => {
                let Some(rest) = key.strip_prefix(prefix) else {
                    return Ok(None);
                };
                let Some(rest) = rest.strip_prefix('/') else {
                    return Ok(None);
                };
                rest
            }
            None => key,
        };

        if relative.is_empty() {
            return Ok(None);
        }

        BackendObjectId::new(relative.to_owned())
            .map(Some)
            .map_err(|error| StorageError::Provider(error.to_string()))
    }
}

pub(super) fn non_blank(value: String) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

fn normalize_prefix(prefix: Option<String>) -> Option<String> {
    prefix.and_then(non_blank).map(|prefix| {
        prefix
            .trim_matches('/')
            .split('/')
            .filter(|component| !component.is_empty())
            .collect::<Vec<_>>()
            .join("/")
    })
}

fn join_key(prefix: Option<&str>, value: &str) -> String {
    match (prefix, value) {
        (Some(prefix), "") => format!("{prefix}/"),
        (Some(prefix), value) => format!("{prefix}/{value}"),
        (None, value) => value.to_owned(),
    }
}
