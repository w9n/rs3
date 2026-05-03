//! Kubernetes checkpoint anchoring integration.

use async_trait::async_trait;
use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::PostParams;
use kube::{Api, Client};
pub use rs3_anchor::{AnchorError, AnchorState, CheckpointAnchor};
use rs3_types::{CheckpointId, Sequence};
use std::collections::BTreeMap;
use tokio::sync::OnceCell;

const CHECKPOINT_SEQUENCE_ANNOTATION: &str = "rs3.rs/checkpoint-sequence";
const CHECKPOINT_ID_ANNOTATION: &str = "rs3.rs/checkpoint-id";
const CHECKPOINT_DIGEST_ANNOTATION: &str = "rs3.rs/checkpoint-digest";
const MAX_ADVANCE_ATTEMPTS: usize = 16;

/// Kubernetes object settings used for checkpoint anchoring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseSettings {
    /// Namespace that stores the anchor object.
    pub namespace: String,
    /// Name of the anchor object.
    pub name: String,
    /// Field manager used by server-side apply compatible deployments.
    pub field_manager: String,
}

/// Checkpoint anchor stored in a Kubernetes Lease object.
///
/// The anchor state is encoded in Lease annotations and updated with Kubernetes
/// resource-version compare-and-swap semantics. This makes concurrent writers
/// retry on update conflicts instead of silently overwriting each other.
pub struct KubernetesLeaseAnchor {
    settings: LeaseSettings,
    client: OnceCell<Client>,
}

impl KubernetesLeaseAnchor {
    /// Creates a Lease-backed checkpoint anchor.
    pub fn new(settings: LeaseSettings) -> Self {
        Self {
            settings,
            client: OnceCell::new(),
        }
    }

    async fn api(&self) -> rs3_anchor::Result<Api<Lease>> {
        let client = self
            .client
            .get_or_try_init(|| async { Client::try_default().await.map_err(anchor_backend) })
            .await?;
        Ok(Api::namespaced(client.clone(), &self.settings.namespace))
    }
}

#[async_trait]
impl CheckpointAnchor for KubernetesLeaseAnchor {
    async fn read(&self) -> rs3_anchor::Result<AnchorState> {
        let api = self.api().await?;
        let lease = match api.get(&self.settings.name).await {
            Ok(lease) => lease,
            Err(error) if is_kube_status(&error, 404) => return Err(AnchorError::MissingAnchor),
            Err(error) => return Err(anchor_backend(error)),
        };
        anchor_state_from_lease(&lease)
    }

    async fn compare_and_advance(&self, next: AnchorState) -> rs3_anchor::Result<AnchorState> {
        let api = self.api().await?;

        for _attempt in 0..MAX_ADVANCE_ATTEMPTS {
            match api.get(&self.settings.name).await {
                Ok(lease) => {
                    if let Ok(current) = anchor_state_from_lease(&lease) {
                        if next == current {
                            return Ok(current);
                        }
                        if next.sequence <= current.sequence {
                            return Err(AnchorError::StaleSequence);
                        }
                    }

                    let updated = lease_with_state(lease, &next, &self.settings.field_manager);
                    match api
                        .replace(&self.settings.name, &PostParams::default(), &updated)
                        .await
                    {
                        Ok(lease) => return anchor_state_from_lease(&lease),
                        Err(error) if is_kube_status(&error, 409) => continue,
                        Err(error) => return Err(anchor_backend(error)),
                    }
                }
                Err(error) if is_kube_status(&error, 404) => {
                    let lease = new_lease(&self.settings.name, &next, &self.settings.field_manager);
                    match api.create(&PostParams::default(), &lease).await {
                        Ok(lease) => return anchor_state_from_lease(&lease),
                        Err(error) if is_kube_status(&error, 409) => continue,
                        Err(error) => return Err(anchor_backend(error)),
                    }
                }
                Err(error) => return Err(anchor_backend(error)),
            }
        }

        Err(AnchorError::Backend(
            "checkpoint Lease update conflicted too many times".to_owned(),
        ))
    }
}

fn new_lease(name: &str, state: &AnchorState, field_manager: &str) -> Lease {
    lease_with_state(
        Lease {
            metadata: ObjectMeta {
                name: Some(name.to_owned()),
                ..ObjectMeta::default()
            },
            spec: None,
        },
        state,
        field_manager,
    )
}

fn lease_with_state(mut lease: Lease, state: &AnchorState, field_manager: &str) -> Lease {
    let annotations = lease.metadata.annotations.get_or_insert_with(BTreeMap::new);
    annotations.insert(
        CHECKPOINT_SEQUENCE_ANNOTATION.to_owned(),
        state.sequence.get().to_string(),
    );
    annotations.insert(
        CHECKPOINT_ID_ANNOTATION.to_owned(),
        state.checkpoint_id.as_str().to_owned(),
    );
    annotations.insert(
        CHECKPOINT_DIGEST_ANNOTATION.to_owned(),
        state.checkpoint_digest.clone(),
    );

    let spec = lease.spec.get_or_insert_with(LeaseSpec::default);
    spec.holder_identity = Some(format!(
        "{field_manager}:{}:{}",
        state.sequence.get(),
        state.checkpoint_id.as_str()
    ));
    lease
}

fn anchor_state_from_lease(lease: &Lease) -> rs3_anchor::Result<AnchorState> {
    let annotations = lease
        .metadata
        .annotations
        .as_ref()
        .ok_or(AnchorError::MissingAnchor)?;
    let sequence = annotation(annotations, CHECKPOINT_SEQUENCE_ANNOTATION)?
        .parse::<u64>()
        .map_err(|error| {
            AnchorError::Backend(format!("invalid checkpoint sequence in Lease: {error}"))
        })?;
    let checkpoint_id = CheckpointId::new(annotation(annotations, CHECKPOINT_ID_ANNOTATION)?)
        .map_err(anchor_backend)?;
    let checkpoint_digest = annotation(annotations, CHECKPOINT_DIGEST_ANNOTATION)?.to_owned();

    if checkpoint_digest.is_empty() {
        return Err(AnchorError::Backend(
            "checkpoint digest annotation is empty".to_owned(),
        ));
    }

    Ok(AnchorState {
        sequence: Sequence::new(sequence),
        checkpoint_id,
        checkpoint_digest,
    })
}

fn annotation<'a>(
    annotations: &'a BTreeMap<String, String>,
    key: &'static str,
) -> rs3_anchor::Result<&'a str> {
    annotations
        .get(key)
        .map(String::as_str)
        .ok_or(AnchorError::MissingAnchor)
}

fn is_kube_status(error: &kube::Error, code: u16) -> bool {
    matches!(error, kube::Error::Api(api_error) if api_error.code == code)
}

fn anchor_backend(error: impl ToString) -> AnchorError {
    AnchorError::Backend(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        CHECKPOINT_DIGEST_ANNOTATION, CHECKPOINT_ID_ANNOTATION, CHECKPOINT_SEQUENCE_ANNOTATION,
        anchor_state_from_lease, lease_with_state,
    };
    use k8s_openapi::api::coordination::v1::Lease;
    use rs3_anchor::{AnchorError, AnchorState};
    use rs3_types::{CheckpointId, Sequence};

    fn state(sequence: u64, checkpoint_id: &str) -> AnchorState {
        AnchorState {
            sequence: Sequence::new(sequence),
            checkpoint_id: CheckpointId::new(checkpoint_id).expect("valid checkpoint id"),
            checkpoint_digest: format!("digest-{checkpoint_id}"),
        }
    }

    #[test]
    fn lease_annotations_round_trip_anchor_state() {
        let expected = state(7, "checkpoint-7");
        let lease = lease_with_state(Lease::default(), &expected, "rs3-test");

        let actual = anchor_state_from_lease(&lease);

        assert_eq!(actual.ok(), Some(expected));
    }

    #[test]
    fn lease_anchor_state_requires_all_annotations() {
        let mut lease = lease_with_state(Lease::default(), &state(1, "checkpoint-1"), "rs3-test");
        let annotations = lease
            .metadata
            .annotations
            .as_mut()
            .expect("annotations exist");
        annotations.remove(CHECKPOINT_DIGEST_ANNOTATION);
        assert!(annotations.contains_key(CHECKPOINT_SEQUENCE_ANNOTATION));
        assert!(annotations.contains_key(CHECKPOINT_ID_ANNOTATION));

        let actual = anchor_state_from_lease(&lease);

        assert!(matches!(actual, Err(AnchorError::MissingAnchor)));
    }
}
