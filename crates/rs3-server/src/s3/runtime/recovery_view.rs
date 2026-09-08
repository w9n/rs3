//! Readonly selection uses the real current anchor as independent authority.

use super::*;
use rs3_repository::v2::{V2RecoveryCursor, V2RecoveryPointPage};

impl RuntimeRepository {
    pub(in crate::s3) async fn from_config_with_recovery_point(
        config: &RuntimeConfig,
        sequence: Sequence,
    ) -> Result<Self, S3BoundaryError> {
        if config.mode != GatewayMode::RestoreReadOnly {
            return Err(repository_init(
                "recovery point selection requires restore-readonly mode",
            ));
        }
        let mut runtime =
            Self::from_config_inner(config, None, None, RuntimeStartup::HistoryOnly).await?;
        let view = runtime
            .repository
            .open_recovery_point(&runtime.anchor, sequence)
            .await
            .map_err(repository_init)?;
        runtime.recovery_view = Some(Arc::new(view));
        Ok(runtime)
    }

    pub(in crate::s3) async fn check_recovery_authority(&self) -> Result<(), RepositoryError> {
        match &self.recovery_view {
            Some(view) => view.check_authority(&self.anchor).await,
            None => Ok(()),
        }
    }
}

/// Lists a bounded page from the current authenticated recovery registry.
/// Configuration must already be in restore-readonly mode; this never initializes.
pub async fn recovery_points_from_config(
    config: &RuntimeConfig,
    limit: usize,
    cursor: Option<&V2RecoveryCursor>,
) -> Result<V2RecoveryPointPage, S3BoundaryError> {
    if config.mode != GatewayMode::RestoreReadOnly {
        return Err(repository_init(
            "recovery point listing requires restore-readonly mode",
        ));
    }
    let runtime =
        RuntimeRepository::from_config_inner(config, None, None, RuntimeStartup::HistoryOnly)
            .await?;
    runtime
        .repository
        .recovery_points(&runtime.anchor, limit, cursor)
        .await
        .map_err(repository_init)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn selected_runtime_startup_keeps_historical_reads_and_current_anchor() {
        let mut config = crate::s3::test_support::runtime_config(true);
        config.repository.retention = Some(rs3_types::RetentionPolicy::new(
            rs3_types::RetentionMode::Compliance,
            30,
        ));
        let mut runtime = RuntimeRepository::from_config_with_maintenance_guard(
            &config,
            Arc::new(rs3_repository::v2::UnenforcedQuiescedMaintenanceGuard),
        )
        .await
        .expect("runtime");
        let key = LogicalPath::new("private/historical-object").expect("path");
        runtime
            .put_committed(
                key.clone(),
                Bytes::from_static(b"old"),
                RepositoryPutOptions::default(),
            )
            .await
            .expect("old put");
        let selected = runtime
            .anchor
            .read_v2()
            .await
            .expect("anchor")
            .expect("present");
        runtime
            .put_committed(
                key.clone(),
                Bytes::from_static(b"replacement"),
                RepositoryPutOptions::default(),
            )
            .await
            .expect("replacement");
        let current = runtime.anchor.read_v2().await.expect("current anchor");
        runtime.recovery_view = Some(Arc::new(
            runtime
                .repository
                .open_recovery_point(&runtime.anchor, selected.sequence)
                .await
                .expect("view"),
        ));
        runtime
            .load_accepted_anchor(GatewayMode::RestoreReadOnly)
            .await
            .expect("selected startup");
        assert_eq!(
            runtime
                .get_range(&key, ByteRange::Full)
                .await
                .expect("selected bytes"),
            Bytes::from_static(b"old")
        );
        assert_eq!(runtime.head(&key).expect("selected head").content_len, 3);
        assert_eq!(
            runtime.anchor.read_v2().await.expect("unchanged anchor"),
            current
        );
        assert!(
            RuntimeRepository::from_config_with_recovery_point(&config, selected.sequence)
                .await
                .is_err(),
            "writable mode must be rejected"
        );
    }
}
