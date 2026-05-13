use super::S3BlobStore;
use crate::{Result, StorageError};
use std::time::Duration;

/// Metrics captured at the S3 provider boundary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct S3ProviderMetrics {
    /// PUT operation metrics.
    pub put: S3ProviderOperationMetrics,
    /// GET operation metrics.
    pub get: S3ProviderOperationMetrics,
    /// HEAD operation metrics.
    pub head: S3ProviderOperationMetrics,
    /// LIST operation metrics.
    pub list: S3ProviderOperationMetrics,
    /// DELETE operation metrics.
    pub delete: S3ProviderOperationMetrics,
    /// Retention-extension operation metrics.
    pub extend_retention: S3ProviderOperationMetrics,
    /// Legal-hold update operation metrics.
    pub set_legal_hold: S3ProviderOperationMetrics,
}

/// Per-operation S3 provider metrics.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct S3ProviderOperationMetrics {
    /// Number of operation attempts sent through the adapter.
    pub requests: u64,
    /// Number of operation attempts that returned success.
    pub successes: u64,
    /// Number of operation attempts that returned an error.
    pub failures: u64,
    /// Bytes sent in successful requests, when known.
    pub bytes_sent: u64,
    /// Bytes received in successful responses, when known.
    pub bytes_received: u64,
    /// Total elapsed time in microseconds across attempts.
    pub elapsed_us: u64,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum S3ProviderOperation {
    Put,
    Get,
    Head,
    List,
    Delete,
    ExtendRetention,
    SetLegalHold,
}

impl S3ProviderOperation {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Put => "put",
            Self::Get => "get",
            Self::Head => "head",
            Self::List => "list",
            Self::Delete => "delete",
            Self::ExtendRetention => "extend_retention",
            Self::SetLegalHold => "set_legal_hold",
        }
    }
}

impl S3BlobStore {
    pub(super) fn record_provider_operation(
        &self,
        operation: S3ProviderOperation,
        object_kind: &str,
        result: &str,
        bytes_sent: u64,
        bytes_received: u64,
        elapsed: Duration,
    ) -> Result<()> {
        let mut metrics = self
            .metrics
            .write()
            .map_err(|_| StorageError::Provider("S3 metrics lock poisoned".to_owned()))?;
        let operation_metrics = match operation {
            S3ProviderOperation::Put => &mut metrics.put,
            S3ProviderOperation::Get => &mut metrics.get,
            S3ProviderOperation::Head => &mut metrics.head,
            S3ProviderOperation::List => &mut metrics.list,
            S3ProviderOperation::Delete => &mut metrics.delete,
            S3ProviderOperation::ExtendRetention => &mut metrics.extend_retention,
            S3ProviderOperation::SetLegalHold => &mut metrics.set_legal_hold,
        };
        operation_metrics.requests = operation_metrics.requests.saturating_add(1);
        if result == "ok" {
            operation_metrics.successes = operation_metrics.successes.saturating_add(1);
            operation_metrics.bytes_sent = operation_metrics.bytes_sent.saturating_add(bytes_sent);
            operation_metrics.bytes_received = operation_metrics
                .bytes_received
                .saturating_add(bytes_received);
        } else {
            operation_metrics.failures = operation_metrics.failures.saturating_add(1);
        }
        operation_metrics.elapsed_us = operation_metrics
            .elapsed_us
            .saturating_add(crate::elapsed_us(elapsed));
        record_s3_provider_metrics(
            operation.as_str(),
            object_kind,
            result,
            bytes_sent,
            bytes_received,
            elapsed,
        );

        tracing::debug!(
            target: "rs3_storage",
            provider = "s3",
            operation = operation.as_str(),
            object_kind,
            result,
            bytes_sent,
            bytes_received,
            elapsed_us = crate::elapsed_us(elapsed),
            "provider blob store operation completed",
        );

        Ok(())
    }
}

fn record_s3_provider_metrics(
    operation: &'static str,
    object_kind: &str,
    result: &str,
    bytes_sent: u64,
    bytes_received: u64,
    elapsed: Duration,
) {
    metrics::counter!(
        "rs3_storage_provider_operations_total",
        "provider" => "s3",
        "operation" => operation,
        "object_kind" => object_kind.to_owned(),
        "result" => result.to_owned(),
    )
    .increment(1);
    metrics::histogram!(
        "rs3_storage_provider_operation_duration_seconds",
        "provider" => "s3",
        "operation" => operation,
        "object_kind" => object_kind.to_owned(),
        "result" => result.to_owned(),
    )
    .record(elapsed.as_secs_f64());

    if result == "ok" {
        metrics::counter!(
            "rs3_storage_provider_bytes_sent_total",
            "provider" => "s3",
            "operation" => operation,
            "object_kind" => object_kind.to_owned(),
        )
        .increment(bytes_sent);
        metrics::counter!(
            "rs3_storage_provider_bytes_received_total",
            "provider" => "s3",
            "operation" => operation,
            "object_kind" => object_kind.to_owned(),
        )
        .increment(bytes_received);
    }
}
