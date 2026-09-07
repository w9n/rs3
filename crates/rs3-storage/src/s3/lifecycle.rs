//! Validate backend lifecycle policy without modifying a shared bucket.

use super::{LimitMetadataResponseBody, S3BlobStore};
use crate::{Result, StorageError};
use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::types::{ExpirationStatus, LifecycleRule, TransitionStorageClass};
use rs3_types::RetentionPolicy;

impl S3BlobStore {
    /// Checks write retention and lifecycle compatibility before repository init.
    ///
    /// Unknown or denied policy inspection fails closed. This does not replace
    /// behavioral provider qualification or prove renewal/bypass permissions.
    pub async fn validate_repository_write_policy(
        &self,
        retention: Option<&RetentionPolicy>,
    ) -> Result<()> {
        self.validate_retention_support(retention).await?;
        let output = self
            .client
            .get_bucket_lifecycle_configuration()
            .bucket(self.config.bucket.as_str())
            .customize()
            .interceptor(LimitMetadataResponseBody)
            .send()
            .await;
        let output = match output {
            Ok(output) => output,
            Err(error)
                if error
                    .as_service_error()
                    .and_then(ProvideErrorMetadata::code)
                    == Some("NoSuchLifecycleConfiguration") =>
            {
                return Ok(());
            }
            Err(_) => {
                return Err(policy_error(
                    "cannot verify S3 bucket lifecycle configuration",
                ));
            }
        };
        let prefix = self.config.list_key_prefix("");
        validate_rules(output.rules(), &prefix)
    }
}

fn policy_error(reason: &'static str) -> StorageError {
    StorageError::Provider(reason.to_owned())
}

#[allow(deprecated)] // The SDK still decodes the legacy top-level rule prefix.
fn validate_rules(rules: &[LifecycleRule], repository_prefix: &str) -> Result<()> {
    if rules.len() > 1_000 {
        return Err(policy_error(
            "S3 lifecycle configuration exceeds the rule budget",
        ));
    }
    for rule in rules {
        match rule.status() {
            ExpirationStatus::Disabled => continue,
            ExpirationStatus::Enabled => {}
            _ => return Err(policy_error("S3 lifecycle rule status is unknown")),
        }
        let mut prefix = rule.prefix();
        if let Some(filter) = rule.filter() {
            let fields = usize::from(filter.prefix().is_some())
                + usize::from(filter.and().is_some())
                + usize::from(filter.tag().is_some())
                + usize::from(filter.object_size_greater_than().is_some())
                + usize::from(filter.object_size_less_than().is_some());
            if prefix.is_some() || fields > 1 {
                return Err(policy_error("S3 lifecycle rule filter is ambiguous"));
            }
            prefix = filter
                .prefix()
                .or_else(|| filter.and().and_then(|and| and.prefix()));
        }
        // Tag and size filters cannot establish disjointness for future opaque
        // repository objects. A non-overlapping prefix can establish it.
        if let Some(prefix) = prefix
            && !prefix.starts_with(repository_prefix)
            && !repository_prefix.starts_with(prefix)
        {
            continue;
        }
        if rule.noncurrent_version_expiration().is_some()
            || rule.expiration().is_some_and(|expiry| {
                expiry.days().is_some()
                    || expiry.date().is_some()
                    || expiry.expired_object_delete_marker() != Some(true)
            })
        {
            return Err(policy_error(
                "S3 lifecycle expiration overlaps repository storage",
            ));
        }
        let transitions = rule.transitions().iter().map(|t| t.storage_class()).chain(
            rule.noncurrent_version_transitions()
                .iter()
                .map(|t| t.storage_class()),
        );
        if transitions.into_iter().any(|class| {
            !matches!(
                class,
                Some(
                    TransitionStorageClass::StandardIa
                        | TransitionStorageClass::OnezoneIa
                        | TransitionStorageClass::GlacierIr
                )
            )
        }) {
            // Intelligent-Tiering can have independently configured archive
            // tiers, so this policy read alone cannot qualify it for direct GET.
            return Err(policy_error(
                "S3 lifecycle transition requires unavailable restore qualification",
            ));
        }
    }
    Ok(())
}
