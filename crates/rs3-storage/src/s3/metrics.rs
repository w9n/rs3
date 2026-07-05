use super::S3BlobStore;
use crate::Result;
use std::sync::atomic::{AtomicU64, Ordering};
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

#[derive(Debug, Default)]
pub(super) struct S3ProviderMetricCounters {
    put: S3ProviderOperationCounters,
    get: S3ProviderOperationCounters,
    head: S3ProviderOperationCounters,
    list: S3ProviderOperationCounters,
    delete: S3ProviderOperationCounters,
    extend_retention: S3ProviderOperationCounters,
    set_legal_hold: S3ProviderOperationCounters,
}

impl S3ProviderMetricCounters {
    pub(super) fn record(
        &self,
        operation: S3ProviderOperation,
        result: &str,
        bytes_sent: u64,
        bytes_received: u64,
        elapsed: Duration,
    ) {
        let operation_metrics = match operation {
            S3ProviderOperation::Put => &self.put,
            S3ProviderOperation::Get => &self.get,
            S3ProviderOperation::Head => &self.head,
            S3ProviderOperation::List => &self.list,
            S3ProviderOperation::Delete => &self.delete,
            S3ProviderOperation::ExtendRetention => &self.extend_retention,
            S3ProviderOperation::SetLegalHold => &self.set_legal_hold,
        };
        operation_metrics.record(result, bytes_sent, bytes_received, elapsed);
    }

    pub(super) fn snapshot(&self) -> S3ProviderMetrics {
        S3ProviderMetrics {
            put: self.put.snapshot(),
            get: self.get.snapshot(),
            head: self.head.snapshot(),
            list: self.list.snapshot(),
            delete: self.delete.snapshot(),
            extend_retention: self.extend_retention.snapshot(),
            set_legal_hold: self.set_legal_hold.snapshot(),
        }
    }

    pub(super) fn reset(&self) {
        self.put.reset();
        self.get.reset();
        self.head.reset();
        self.list.reset();
        self.delete.reset();
        self.extend_retention.reset();
        self.set_legal_hold.reset();
    }
}

#[derive(Debug, Default)]
struct S3ProviderOperationCounters {
    requests: AtomicU64,
    successes: AtomicU64,
    failures: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    elapsed_us: AtomicU64,
}

impl S3ProviderOperationCounters {
    fn record(&self, result: &str, bytes_sent: u64, bytes_received: u64, elapsed: Duration) {
        saturating_fetch_add(&self.requests, 1);
        if result == "ok" {
            saturating_fetch_add(&self.successes, 1);
            saturating_fetch_add(&self.bytes_sent, bytes_sent);
            saturating_fetch_add(&self.bytes_received, bytes_received);
        } else {
            saturating_fetch_add(&self.failures, 1);
        }
        saturating_fetch_add(&self.elapsed_us, crate::elapsed_us(elapsed));
    }

    fn snapshot(&self) -> S3ProviderOperationMetrics {
        S3ProviderOperationMetrics {
            requests: self.requests.load(Ordering::Relaxed),
            successes: self.successes.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            elapsed_us: self.elapsed_us.load(Ordering::Relaxed),
        }
    }

    fn reset(&self) {
        self.requests.store(0, Ordering::Relaxed);
        self.successes.store(0, Ordering::Relaxed);
        self.failures.store(0, Ordering::Relaxed);
        self.bytes_sent.store(0, Ordering::Relaxed);
        self.bytes_received.store(0, Ordering::Relaxed);
        self.elapsed_us.store(0, Ordering::Relaxed);
    }
}

fn saturating_fetch_add(counter: &AtomicU64, value: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(value))
    });
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
        self.metrics
            .record(operation, result, bytes_sent, bytes_received, elapsed);
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

#[cfg(test)]
mod tests {
    use super::{S3ProviderMetricCounters, S3ProviderOperation};
    use std::time::Duration;

    #[test]
    fn provider_metric_counters_snapshot_and_reset_without_locks() {
        let metrics = S3ProviderMetricCounters::default();

        metrics.record(
            S3ProviderOperation::Put,
            "ok",
            7,
            11,
            Duration::from_micros(13),
        );
        metrics.record(
            S3ProviderOperation::Put,
            "error",
            17,
            19,
            Duration::from_micros(23),
        );

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.put.requests, 2);
        assert_eq!(snapshot.put.successes, 1);
        assert_eq!(snapshot.put.failures, 1);
        assert_eq!(snapshot.put.bytes_sent, 7);
        assert_eq!(snapshot.put.bytes_received, 11);
        assert_eq!(snapshot.put.elapsed_us, 36);

        metrics.reset();
        assert_eq!(metrics.snapshot().put.requests, 0);
    }
}
