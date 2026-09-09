//! A journaled synthetic PUT, independent reopen, and logical cleanup.

use super::*;

const WRITE_ATTEMPTS: u8 = 3;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "phase", deny_unknown_fields)]
pub(super) enum State {
    Planned {
        base: V3AnchorState,
        remaining: u8,
    },
    Verified {
        accepted: V3AnchorState,
        remaining: u8,
    },
    Complete,
}

impl State {
    pub(super) fn valid(&self) -> bool {
        match self {
            Self::Planned { remaining, .. } | Self::Verified { remaining, .. } => {
                *remaining <= WRITE_ATTEMPTS
            }
            Self::Complete => true,
        }
    }

    pub(super) fn complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

fn failed() -> S3BoundaryError {
    repository_init(
        "bootstrap payload restore could not be verified; preserve the journal and retry",
    )
}

fn fixture(root: &str) -> Result<(LogicalPath, Bytes), S3BoundaryError> {
    let id = root.strip_prefix("rs3-probes/").ok_or_else(invalid)?;
    let key = LogicalPath::new(format!("rs3-bootstrap/{id}")).map_err(|_| invalid())?;
    Ok((
        key,
        Bytes::from(format!("rs3 bootstrap restore fixture: {id}")),
    ))
}

// Construct a fresh repository/keyring/cache for each verification. Use the
// normal authenticated recovery and data-read implementation, never HEAD alone.
async fn reopen(
    config: &RuntimeConfig,
    store: &RuntimeStore,
    anchor: &RuntimeV3Anchor,
) -> Result<(V3Repository<RuntimeStore>, V3AnchorState, usize), S3BoundaryError> {
    let accepted = anchor
        .read_v3()
        .await
        .map_err(|_| failed())?
        .ok_or_else(failed)?;
    let loaded = load_existing_v3_repository(store, &config.repository_keys, &accepted, config)
        .await
        .map_err(|_| failed())?;
    let options = bootstrap_commit_options(config, &loaded).map_err(|_| failed())?;
    let repository = V3Repository::new(
        store.clone(),
        loaded.keyring,
        RepositoryOptions {
            payload_segment_size: config.repository.payload_segment_size,
            adaptive_payload_segment_size: config.repository.adaptive_payload_segment_size,
            decrypted_segment_cache_max_bytes: 0,
            default_retention: config.repository.retention,
        },
        options,
    );
    let chain = repository
        .load_chain_from_anchor(anchor)
        .await
        .map_err(|_| failed())?
        .ok_or_else(failed)?;
    if anchor.read_v3().await.map_err(|_| failed())? != Some(accepted.clone()) {
        return Err(failed());
    }
    Ok((repository, accepted, chain.commits_newest_first.len()))
}

async fn verify_body(
    repository: &V3Repository<RuntimeStore>,
    key: &LogicalPath,
    body: &Bytes,
) -> Result<bool, S3BoundaryError> {
    match repository.head(key) {
        Err(RepositoryError::NotFound(_)) => return Ok(false),
        Ok(metadata) if metadata.content_len == body.len() as u64 => {}
        _ => return Err(failed()),
    }
    if repository
        .get_range(key, ByteRange::Full)
        .await
        .map_err(|_| failed())?
        != *body
    {
        return Err(failed());
    }
    Ok(true)
}

pub(super) async fn verify<J: Journal>(
    config: &RuntimeConfig,
    store: &RuntimeStore,
    anchor: &RuntimeV3Anchor,
    guard: &dyn V3MaintenanceGuard,
    journal: &mut OnboardingJournal<'_, J>,
    report: &mut V3RepositoryInitReport,
) -> Result<(), S3BoundaryError> {
    journal.state()?;
    if journal
        .record
        .round_trip
        .as_ref()
        .is_some_and(State::complete)
    {
        return Ok(());
    }
    guard
        .verify_v3_maintenance(None)
        .await
        .map_err(|_| failed())?;
    if journal.record.round_trip.is_none() {
        journal.record.round_trip = Some(State::Planned {
            base: report.anchor.clone(),
            remaining: WRITE_ATTEMPTS,
        });
        journal.persist().await?;
    }
    let (key, body) = fixture(&journal.record.probe_root)?;
    if let Some(State::Planned { base, remaining }) = journal.record.round_trip.clone() {
        let (repository, accepted, _) = reopen(config, store, anchor).await?;
        if !verify_body(&repository, &key, &body).await? {
            // An accepted changed state without our key is not permission to
            // republish an old attempt over a newer repository value.
            if accepted != base {
                return Err(failed());
            }
            let remaining = remaining.checked_sub(1).ok_or_else(|| {
                repository_init("bootstrap fixture PUT budget exhausted; preserve the journal")
            })?;
            journal.record.round_trip = Some(State::Planned { base, remaining });
            journal.persist().await?;
            guard
                .verify_v3_maintenance(None)
                .await
                .map_err(|_| failed())?;
            repository
                .put_committed_with_guard(
                    anchor,
                    key.clone(),
                    body.clone(),
                    RepositoryPutOptions {
                        create_only: true,
                        ..Default::default()
                    },
                    Some(guard),
                )
                .await
                .map_err(|_| failed())?;
        }
        drop(repository);
        let (reader, accepted, _) = reopen(config, store, anchor).await?;
        if !verify_body(&reader, &key, &body).await? {
            return Err(failed());
        }
        guard
            .verify_v3_maintenance(Some(&accepted))
            .await
            .map_err(|_| failed())?;
        journal.record.round_trip = Some(State::Verified {
            accepted,
            remaining: WRITE_ATTEMPTS,
        });
        journal.persist().await?;
    }
    if let Some(State::Verified {
        accepted: verified,
        remaining,
    }) = journal.record.round_trip.clone()
    {
        let (repository, accepted, _) = reopen(config, store, anchor).await?;
        if verify_body(&repository, &key, &body).await? {
            if accepted != verified {
                return Err(failed());
            }
            let remaining = remaining.checked_sub(1).ok_or_else(|| {
                repository_init("bootstrap fixture DELETE budget exhausted; preserve the journal")
            })?;
            journal.record.round_trip = Some(State::Verified {
                accepted: verified,
                remaining,
            });
            journal.persist().await?;
            guard
                .verify_v3_maintenance(None)
                .await
                .map_err(|_| failed())?;
            repository
                .delete_committed_with_guard(anchor, key.clone(), Some(guard))
                .await
                .map_err(|_| failed())?;
        } else if accepted.sequence <= verified.sequence {
            return Err(failed());
        }
        drop(repository);
        let (reader, accepted, count) = reopen(config, store, anchor).await?;
        if verify_body(&reader, &key, &body).await? {
            return Err(failed());
        }
        guard
            .verify_v3_maintenance(Some(&accepted))
            .await
            .map_err(|_| failed())?;
        journal.record.round_trip = Some(State::Complete);
        journal.persist().await?;
        report.anchor = accepted;
        report.verified_commit_count = count;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
