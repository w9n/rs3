//! Operator history listing uses the current anchor, never backend discovery.

use super::RecoveryReportFormat;
use anyhow::Result;
use rs3_repository::v2::V2RecoveryCursor;
use rs3_server::{GatewayMode, RuntimeConfig, recovery_points_from_config};

pub(super) async fn run(
    limit: usize,
    cursor: Option<&str>,
    format: RecoveryReportFormat,
) -> Result<()> {
    let config = RuntimeConfig::from_env_with_mode_override(Some(GatewayMode::RestoreReadOnly))?;
    let cursor = cursor.map(V2RecoveryCursor::decode).transpose()?;
    let page = recovery_points_from_config(&config, limit, cursor.as_ref()).await?;
    let next = page
        .next_cursor
        .as_ref()
        .map(V2RecoveryCursor::encode)
        .transpose()?;
    match format {
        RecoveryReportFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "registry_sequence": page.registry_sequence,
                "points": page.points,
                "next_cursor": next,
            }))?
        ),
        RecoveryReportFormat::Text => {
            println!("registry sequence: {}", page.registry_sequence);
            for point in page.points {
                println!(
                    "sequence={} publish_time_ms={} protected_until_ms={} current={}",
                    point.sequence,
                    point.publish_time_ms,
                    point
                        .protected_until_ms
                        .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                    point.current
                );
            }
            if let Some(next) = next {
                println!("next cursor: {next}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{Cli, Commands, GatewayModeArg};
    use clap::Parser;

    #[test]
    fn operator_history_cli_bounds_and_exact_sequence() {
        assert!(Cli::try_parse_from(["rs3", "recovery-points", "--limit", "0"]).is_err());
        assert!(Cli::try_parse_from(["rs3", "recovery-points", "--limit", "257"]).is_err());
        assert!(matches!(
            Cli::try_parse_from(["rs3", "recovery-points", "--limit", "256"])
                .expect("bounded listing")
                .command,
            Commands::RecoveryPoints { limit: 256, .. }
        ));
        assert!(matches!(
            Cli::try_parse_from([
                "rs3",
                "serve",
                "--gateway-mode",
                "restore-readonly",
                "--recovery-point",
                "42"
            ])
            .expect("historical serve")
            .command,
            Commands::Serve {
                gateway_mode: Some(GatewayModeArg::RestoreReadonly),
                recovery_point: Some(42),
                ..
            }
        ));
    }
}
