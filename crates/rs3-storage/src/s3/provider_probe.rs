//! Isolated provider qualification with actual DELETE requests and bounded attempts.

use super::*;
use aws_sdk_s3::error::ProvideErrorMetadata;

fn valid_probe_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 512
        && path.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
}

fn overlaps(left: &str, right: &str) -> bool {
    left == right
        || left
            .strip_prefix(right)
            .is_some_and(|rest| rest.starts_with('/'))
        || right
            .strip_prefix(left)
            .is_some_and(|rest| rest.starts_with('/'))
}

impl S3BlobStore {
    /// Creates an isolated qualification handle in the same bucket and endpoint.
    ///
    /// Reuses the existing credential provider/cache and timeout configuration,
    /// disables SDK retries, and sends exact-version DELETE probes to the provider
    /// without governance-bypass headers. This handle is only for synthetic probe
    /// objects. Both prefixes must be nonempty, canonical and disjoint; a probe
    /// handle cannot be re-scoped. Ordinary repository handles keep local guards.
    pub fn for_provider_probe(&self, prefix: String) -> Result<Self> {
        let config = self.config.clone().with_prefix(Some(prefix));
        let repository = self.config.prefix.as_deref().unwrap_or_default();
        let probe = config.prefix.as_deref().unwrap_or_default();
        if self.provider_probe
            || !valid_probe_path(repository)
            || !valid_probe_path(probe)
            || overlaps(repository, probe)
        {
            return Err(StorageError::Provider(
                "provider qualification requires nonempty disjoint canonical prefixes".to_owned(),
            ));
        }
        // to_builder clones SDK runtime components, including the configured
        // credential provider and identity cache. Do not reload environment or IAM.
        let client = SdkS3Client::from_conf(
            self.client
                .config()
                .to_builder()
                .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
                .build(),
        );
        Ok(Self {
            client,
            config,
            metrics: Arc::clone(&self.metrics),
            provider_probe: true,
        })
    }

    pub(super) async fn probe_provider_delete(
        &self,
        object_id: &BackendObjectId,
        version_id: &BackendVersionId,
    ) -> Result<()> {
        if !self.provider_probe || !valid_probe_path(object_id.as_str()) {
            return Err(StorageError::Provider(
                "provider delete probe has an invalid scope".to_owned(),
            ));
        }
        let metadata = self.head_at(object_id, Some(version_id)).await?;
        if metadata.object_id != *object_id || metadata.version_id.as_ref() != Some(version_id) {
            return Err(StorageError::Provider(
                "provider delete probe could not verify its exact version".to_owned(),
            ));
        }
        let started = Instant::now();
        let object_kind = object_kind(object_id);
        let result = self
            .client
            .delete_object()
            .bucket(self.config.bucket.as_str())
            .key(self.config.object_key(object_id))
            .version_id(version_id.as_str())
            .send()
            .await;
        let result = match result {
            Ok(_) => Ok(()),
            Err(error)
                if error
                    .as_service_error()
                    .and_then(ProvideErrorMetadata::code)
                    == Some("AccessDenied") =>
            {
                // This observes provider denial, not its IAM/Object Lock cause.
                // The unprotected delete control and governance policy review
                // remain separate required checks in the qualification suite.
                if legal_hold_blocks_delete(metadata.legal_hold) {
                    Err(StorageError::LegalHoldBlocked)
                } else if retention_blocks_delete(metadata.retention.as_ref()) {
                    Err(StorageError::RetentionBlocked)
                } else {
                    Err(StorageError::Provider(
                        "provider denied an unprotected delete probe".to_owned(),
                    ))
                }
            }
            Err(_) => Err(StorageError::Provider(
                "provider delete probe failed without verified denial".to_owned(),
            )),
        };
        let label = result
            .as_ref()
            .map_or_else(|error| storage_error_result(error), |_| "ok");
        self.record_provider_operation(
            S3ProviderOperation::Delete,
            object_kind,
            label,
            0,
            0,
            started.elapsed(),
        )?;
        record_blob_delete(object_kind, label, started.elapsed());
        result
    }
}

#[cfg(test)]
mod tests;
