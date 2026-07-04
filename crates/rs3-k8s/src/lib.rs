//! Kubernetes checkpoint anchoring integration.

mod lease_guard;

use async_trait::async_trait;
use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::PostParams;
use kube::{Api, Client};
use rs3_repository::v2::{V2AnchorState, V2CommitAnchor, V2FormatError, V2FormatRef, V2Result};
use rs3_types::{BackendObjectId, BackendVersionId, KeyId, Sequence};
use std::collections::BTreeMap;
use tokio::sync::OnceCell;

pub use lease_guard::{
    KubernetesLeaseGuard, LeaseGuard, LeaseGuardApi, LeaseGuardError, LeaseGuardState,
};

const V2_SEQUENCE_ANNOTATION: &str = "rs3.rs/v2-sequence";
const V2_COMMIT_KEY_ANNOTATION: &str = "rs3.rs/v2-commit-key";
const V2_BODY_DIGEST_ANNOTATION: &str = "rs3.rs/v2-body-digest";
const V2_VERSION_ID_ANNOTATION: &str = "rs3.rs/v2-version-id";
const V2_SIGNING_KEY_ID_ANNOTATION: &str = "rs3.rs/v2-signing-key-id";
const V2_FORMAT_GENERATION_ANNOTATION: &str = "rs3.rs/v2-format-generation";
const V2_FORMAT_DIGEST_ANNOTATION: &str = "rs3.rs/v2-format-digest";
const V2_FORMAT_OBJECT_ID_ANNOTATION: &str = "rs3.rs/v2-format-object-id";
const V2_FORMAT_VERSION_ID_ANNOTATION: &str = "rs3.rs/v2-format-version-id";
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

    async fn api(&self) -> V2Result<Api<Lease>> {
        let client = self
            .client
            .get_or_try_init(|| async {
                Client::try_default()
                    .await
                    .map_err(|_| V2FormatError::AnchorReadFailed)
            })
            .await?;
        Ok(Api::namespaced(client.clone(), &self.settings.namespace))
    }
}

#[async_trait]
impl V2CommitAnchor for KubernetesLeaseAnchor {
    async fn read_v2(&self) -> V2Result<Option<V2AnchorState>> {
        let api = self.api().await?;
        let lease = match api.get(&self.settings.name).await {
            Ok(lease) => lease,
            Err(error) if is_kube_status(&error, 404) => return Ok(None),
            Err(_) => return Err(V2FormatError::AnchorReadFailed),
        };
        v2_anchor_state_from_lease(&lease).map(Some)
    }

    async fn compare_and_advance_v2(
        &self,
        expected: Option<&V2AnchorState>,
        next: V2AnchorState,
    ) -> V2Result<V2AnchorState> {
        let api = self
            .api()
            .await
            .map_err(|_| V2FormatError::AnchorAdvanceFailed)?;

        for _attempt in 0..MAX_ADVANCE_ATTEMPTS {
            match api.get(&self.settings.name).await {
                Ok(lease) => {
                    let current = v2_anchor_state_from_lease(&lease)?;
                    if expected != Some(&current) {
                        return Err(V2FormatError::StaleAnchor);
                    }
                    if next == current {
                        return Ok(current);
                    }
                    if next.sequence <= current.sequence {
                        return Err(V2FormatError::StaleAnchor);
                    }

                    let updated = v2_lease_with_state(lease, &next, &self.settings.field_manager);
                    match api
                        .replace(&self.settings.name, &PostParams::default(), &updated)
                        .await
                    {
                        Ok(lease) => return v2_anchor_state_from_lease(&lease),
                        Err(error) if is_kube_status(&error, 409) => continue,
                        Err(_) => return Err(V2FormatError::AnchorAdvanceFailed),
                    }
                }
                Err(error) if is_kube_status(&error, 404) => {
                    if expected.is_some() {
                        return Err(V2FormatError::StaleAnchor);
                    }
                    let lease =
                        new_v2_lease(&self.settings.name, &next, &self.settings.field_manager);
                    match api.create(&PostParams::default(), &lease).await {
                        Ok(lease) => return v2_anchor_state_from_lease(&lease),
                        Err(error) if is_kube_status(&error, 409) => continue,
                        Err(_) => return Err(V2FormatError::AnchorAdvanceFailed),
                    }
                }
                Err(_) => return Err(V2FormatError::AnchorReadFailed),
            }
        }

        Err(V2FormatError::AnchorAdvanceFailed)
    }
}

fn new_v2_lease(name: &str, state: &V2AnchorState, field_manager: &str) -> Lease {
    v2_lease_with_state(
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

fn v2_lease_with_state(mut lease: Lease, state: &V2AnchorState, field_manager: &str) -> Lease {
    let annotations = lease.metadata.annotations.get_or_insert_with(BTreeMap::new);
    annotations.insert(
        V2_SEQUENCE_ANNOTATION.to_owned(),
        state.sequence.get().to_string(),
    );
    annotations.insert(
        V2_COMMIT_KEY_ANNOTATION.to_owned(),
        state.commit_key.as_str().to_owned(),
    );
    annotations.insert(
        V2_BODY_DIGEST_ANNOTATION.to_owned(),
        hex::encode(state.body_digest),
    );
    match state.version_id.as_ref() {
        Some(version_id) => {
            annotations.insert(
                V2_VERSION_ID_ANNOTATION.to_owned(),
                version_id.as_str().to_owned(),
            );
        }
        None => {
            annotations.remove(V2_VERSION_ID_ANNOTATION);
        }
    }
    annotations.insert(
        V2_SIGNING_KEY_ID_ANNOTATION.to_owned(),
        state.signing_key_id.as_str().to_owned(),
    );
    annotations.insert(
        V2_FORMAT_GENERATION_ANNOTATION.to_owned(),
        state.format_ref.generation.to_string(),
    );
    annotations.insert(
        V2_FORMAT_DIGEST_ANNOTATION.to_owned(),
        state.format_ref.digest.clone(),
    );
    annotations.insert(
        V2_FORMAT_OBJECT_ID_ANNOTATION.to_owned(),
        state.format_ref.object_id.as_str().to_owned(),
    );
    match state.format_ref.version_id.as_ref() {
        Some(version_id) => {
            annotations.insert(
                V2_FORMAT_VERSION_ID_ANNOTATION.to_owned(),
                version_id.as_str().to_owned(),
            );
        }
        None => {
            annotations.remove(V2_FORMAT_VERSION_ID_ANNOTATION);
        }
    }

    let spec = lease.spec.get_or_insert_with(LeaseSpec::default);
    spec.holder_identity = Some(format!(
        "{field_manager}:v2:{}:{}",
        state.sequence.get(),
        state.format_ref.generation
    ));
    lease
}

fn v2_anchor_state_from_lease(lease: &Lease) -> V2Result<V2AnchorState> {
    let annotations = lease
        .metadata
        .annotations
        .as_ref()
        .ok_or(V2FormatError::AnchorReadFailed)?;
    let sequence = v2_annotation(annotations, V2_SEQUENCE_ANNOTATION)?
        .parse::<u64>()
        .map_err(|_| V2FormatError::AnchorReadFailed)?;
    let commit_key =
        BackendObjectId::new(v2_annotation(annotations, V2_COMMIT_KEY_ANNOTATION)?.to_owned())?;
    let body_digest = hex_digest(v2_annotation(annotations, V2_BODY_DIGEST_ANNOTATION)?)?;
    let version_id = annotations
        .get(V2_VERSION_ID_ANNOTATION)
        .map(|value| BackendVersionId::new(value.to_owned()))
        .transpose()?;
    let signing_key_id =
        KeyId::new(v2_annotation(annotations, V2_SIGNING_KEY_ID_ANNOTATION)?.to_owned())?;
    let format_generation = v2_annotation(annotations, V2_FORMAT_GENERATION_ANNOTATION)?
        .parse::<u64>()
        .map_err(|_| V2FormatError::AnchorReadFailed)?;
    let format_digest = v2_annotation(annotations, V2_FORMAT_DIGEST_ANNOTATION)?.to_owned();
    let format_object_id = BackendObjectId::new(
        v2_annotation(annotations, V2_FORMAT_OBJECT_ID_ANNOTATION)?.to_owned(),
    )?;
    let format_version_id = annotations
        .get(V2_FORMAT_VERSION_ID_ANNOTATION)
        .map(|value| BackendVersionId::new(value.to_owned()))
        .transpose()?;

    if format_digest.is_empty() {
        return Err(V2FormatError::AnchorReadFailed);
    }

    Ok(V2AnchorState {
        sequence: Sequence::new(sequence),
        commit_key,
        body_digest,
        version_id,
        signing_key_id,
        format_ref: V2FormatRef {
            generation: format_generation,
            digest: format_digest,
            object_id: format_object_id,
            version_id: format_version_id,
        },
    })
}

fn v2_annotation<'a>(
    annotations: &'a BTreeMap<String, String>,
    key: &'static str,
) -> V2Result<&'a str> {
    annotations
        .get(key)
        .map(String::as_str)
        .ok_or(V2FormatError::AnchorReadFailed)
}

fn hex_digest(value: &str) -> V2Result<[u8; 32]> {
    let bytes = hex::decode(value).map_err(|_| V2FormatError::AnchorReadFailed)?;
    bytes
        .try_into()
        .map_err(|_| V2FormatError::AnchorReadFailed)
}

fn is_kube_status(error: &kube::Error, code: u16) -> bool {
    matches!(error, kube::Error::Api(api_error) if api_error.code == code)
}

#[cfg(test)]
mod tests {
    use super::{V2_FORMAT_VERSION_ID_ANNOTATION, v2_anchor_state_from_lease, v2_lease_with_state};
    use k8s_openapi::api::coordination::v1::Lease;
    use rs3_repository::v2::{V2AnchorState, V2FormatError, V2FormatRef};
    use rs3_types::{BackendObjectId, BackendVersionId, KeyId, Sequence};

    fn v2_state(sequence: u64) -> V2AnchorState {
        V2AnchorState {
            sequence: Sequence::new(sequence),
            commit_key: BackendObjectId::new(format!(
                "commits/v01/{sequence:020}/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            ))
            .expect("valid backend object id"),
            body_digest: [sequence as u8; 32],
            version_id: Some(
                BackendVersionId::new(format!("commit-version-{sequence}"))
                    .expect("valid version id"),
            ),
            signing_key_id: KeyId::new("signing").expect("valid key id"),
            format_ref: V2FormatRef {
                generation: 1,
                digest: hex::encode([7_u8; 32]),
                object_id: BackendObjectId::new(format!(
                    "format/{:020}-{}",
                    1_u64,
                    hex::encode([7_u8; 32])
                ))
                .expect("valid backend object id"),
                version_id: Some(
                    BackendVersionId::new("format-version-1").expect("valid version id"),
                ),
            },
        }
    }

    #[test]
    fn lease_annotations_round_trip_v2_anchor_state() {
        let expected = v2_state(7);
        let lease = v2_lease_with_state(Lease::default(), &expected, "rs3-test");

        let actual = v2_anchor_state_from_lease(&lease);

        assert_eq!(actual.ok(), Some(expected));
    }

    #[test]
    fn lease_annotations_round_trip_v2_format_version() {
        let expected = v2_state(8);
        let lease = v2_lease_with_state(Lease::default(), &expected, "rs3-test");

        assert_eq!(
            lease
                .metadata
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.get(V2_FORMAT_VERSION_ID_ANNOTATION))
                .map(String::as_str),
            Some("format-version-1")
        );
        assert_eq!(v2_anchor_state_from_lease(&lease).ok(), Some(expected));
    }

    #[test]
    fn v2_anchor_state_fails_closed_when_annotations_are_missing() {
        let mut lease = v2_lease_with_state(Lease::default(), &v2_state(1), "rs3-test");
        lease
            .metadata
            .annotations
            .as_mut()
            .expect("annotations exist")
            .remove(super::V2_FORMAT_DIGEST_ANNOTATION);

        let actual = v2_anchor_state_from_lease(&lease);

        assert!(matches!(actual, Err(V2FormatError::AnchorReadFailed)));
    }
}
