//! Opt-in live S3-compatible storage contract tests.
#![cfg(feature = "s3")]

mod common;

use aws_sdk_s3::Client as SdkS3Client;
use aws_sdk_s3::config::{BehaviorVersion, Region};
use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use bytes::Bytes;
use common::assert_core_blob_store_contract_with_create_only;
use rs3_storage::{BlobStore, ByteRange, PutOptions, S3BlobStore, S3BlobStoreConfig, StorageError};
use rs3_types::{BackendObjectId, LegalHoldStatus, RetentionMode, RetentionPolicy};
use std::env;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

const S3_MIN_MULTIPART_PART_BYTES: usize = 5 * 1024 * 1024;

#[tokio::test]
#[ignore = "requires RS3_TEST_S3_BUCKET and S3-compatible credentials"]
async fn live_s3_backend_satisfies_core_blob_store_contract() {
    let Some(target) = live_target() else {
        eprintln!("skipping live S3 test: RS3_TEST_S3_BUCKET is not set");
        return;
    };
    let store = S3BlobStore::from_environment(target.config)
        .await
        .unwrap_or_else(|error| panic!("build S3 blob store: {error}"));

    let require_duplicate_rejection =
        target.qualification_profile == S3QualificationProfile::AtomicCreate;
    assert_core_blob_store_contract_with_create_only(
        &store,
        &target.provider_name,
        require_duplicate_rejection,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires RS3_TEST_S3_OBJECT_LOCK=true and an Object Lock-enabled bucket"]
async fn live_s3_object_lock_retention_round_trips_and_blocks_version_delete() {
    if !env_bool("RS3_TEST_S3_OBJECT_LOCK").unwrap_or(false) {
        eprintln!("skipping live S3 Object Lock test: RS3_TEST_S3_OBJECT_LOCK is not true");
        return;
    }
    let Some(target) = live_target() else {
        eprintln!("skipping live S3 Object Lock test: RS3_TEST_S3_BUCKET is not set");
        return;
    };
    let retain_days = env_u32("RS3_TEST_S3_RETENTION_DAYS").unwrap_or(1);
    let policy = RetentionPolicy::new(RetentionMode::Governance, retain_days);
    let extended_policy = RetentionPolicy::new(RetentionMode::Governance, retain_days + 1);
    let object_id = BackendObjectId::new("retention/live-retained-object".to_owned())
        .unwrap_or_else(|error| panic!("test object id: {error}"));
    let object_key = backend_key(&target.config, &object_id);
    let store = S3BlobStore::from_environment(target.config.clone())
        .await
        .unwrap_or_else(|error| panic!("build S3 blob store: {error}"));

    store
        .validate_retention_support(Some(&policy))
        .await
        .unwrap_or_else(|error| panic!("validate Object Lock support: {error}"));
    let put = store
        .put(
            &object_id,
            Bytes::from_static(b"retained object body"),
            PutOptions {
                retention: Some(policy),
                legal_hold: None,
                content_type: Some("application/octet-stream".to_owned()),
                do_not_recreate: true,
            },
        )
        .await
        .unwrap_or_else(|error| panic!("put retained object: {error}"));
    assert!(retention_satisfies(put.retention.as_ref(), &policy));
    let version_id = put
        .version_id
        .clone()
        .unwrap_or_else(|| panic!("retained S3 PUT did not return a version id"));

    let duplicate = store
        .put(
            &object_id,
            Bytes::from_static(b"duplicate create-only body"),
            PutOptions {
                retention: Some(policy),
                legal_hold: None,
                content_type: Some("application/octet-stream".to_owned()),
                do_not_recreate: true,
            },
        )
        .await;
    match (&target.qualification_profile, duplicate) {
        (S3QualificationProfile::AtomicCreate, Err(StorageError::AlreadyExists(_))) => {}
        (S3QualificationProfile::AtomicCreate, Ok(metadata)) => {
            panic!(
                "atomic-create profile requires duplicate create-only retained PUT to fail, but provider accepted version {:?}",
                metadata.version_id
            );
        }
        (S3QualificationProfile::AtomicCreate, Err(error)) => {
            panic!("duplicate create-only retained PUT returned unexpected error: {error}");
        }
        (S3QualificationProfile::RetainedVersion, Err(StorageError::AlreadyExists(_))) => {}
        (S3QualificationProfile::RetainedVersion, Ok(metadata)) => {
            let duplicate_version = metadata
                .version_id
                .clone()
                .unwrap_or_else(|| panic!("duplicate retained PUT did not return a version id"));
            assert_ne!(duplicate_version, version_id);
            let original = store
                .get_range_at(&object_id, Some(&version_id), ByteRange::Full)
                .await
                .unwrap_or_else(|error| panic!("read original retained version: {error}"));
            let duplicate_body = store
                .get_range_at(&object_id, Some(&duplicate_version), ByteRange::Full)
                .await
                .unwrap_or_else(|error| panic!("read duplicate retained version: {error}"));
            assert_eq!(original, Bytes::from_static(b"retained object body"));
            assert_eq!(
                duplicate_body,
                Bytes::from_static(b"duplicate create-only body")
            );
        }
        (S3QualificationProfile::RetainedVersion, Err(error)) => {
            panic!(
                "retained-version duplicate create-only probe returned unexpected error: {error}"
            );
        }
    }

    let overwrite = store
        .put(
            &object_id,
            Bytes::from_static(b"poisoned latest body"),
            PutOptions {
                retention: Some(policy),
                legal_hold: None,
                content_type: Some("application/octet-stream".to_owned()),
                do_not_recreate: false,
            },
        )
        .await
        .unwrap_or_else(|error| panic!("put newer retained object version: {error}"));
    assert_ne!(overwrite.version_id, Some(version_id.clone()));
    let exact = store
        .get_range_at(&object_id, Some(&version_id), ByteRange::Full)
        .await
        .unwrap_or_else(|error| panic!("read exact retained object version: {error}"));
    let latest = store
        .get_range(&object_id, ByteRange::Full)
        .await
        .unwrap_or_else(|error| panic!("read latest retained object version: {error}"));
    assert_eq!(exact, Bytes::from_static(b"retained object body"));
    assert_eq!(latest, Bytes::from_static(b"poisoned latest body"));

    store
        .extend_retention_at(&object_id, Some(&version_id), extended_policy)
        .await
        .unwrap_or_else(|error| panic!("extend retained object: {error}"));
    let head = store
        .head_at(&object_id, Some(&version_id))
        .await
        .unwrap_or_else(|error| panic!("head retained object: {error}"));
    assert!(retention_satisfies(
        head.retention.as_ref(),
        &extended_policy
    ));

    let client = sdk_client(&target.config).await;
    let delete = client
        .delete_object()
        .bucket(target.config.bucket.as_str())
        .key(object_key)
        .version_id(version_id.as_str())
        .send()
        .await;
    assert!(
        matches!(delete, Err(ref error) if retention_delete_blocked(error)),
        "version delete was not blocked by Object Lock: {delete:?}"
    );
}

#[tokio::test]
#[ignore = "requires RS3_TEST_S3_OBJECT_LOCK=true and an Object Lock-enabled bucket"]
async fn live_s3_object_lock_retained_multipart_round_trips_and_blocks_version_delete() {
    if !env_bool("RS3_TEST_S3_OBJECT_LOCK").unwrap_or(false) {
        eprintln!("skipping live S3 Object Lock test: RS3_TEST_S3_OBJECT_LOCK is not true");
        return;
    }
    let Some(target) = live_target() else {
        eprintln!("skipping live S3 Object Lock test: RS3_TEST_S3_BUCKET is not set");
        return;
    };
    let retain_days = env_u32("RS3_TEST_S3_RETENTION_DAYS").unwrap_or(1);
    let policy = RetentionPolicy::new(RetentionMode::Governance, retain_days);
    let object_id = BackendObjectId::new("retention/live-retained-multipart-object".to_owned())
        .unwrap_or_else(|error| panic!("test object id: {error}"));
    let object_key = backend_key(&target.config, &object_id);
    let store = S3BlobStore::from_environment(target.config.clone())
        .await
        .unwrap_or_else(|error| panic!("build S3 blob store: {error}"));

    store
        .validate_retention_support(Some(&policy))
        .await
        .unwrap_or_else(|error| panic!("validate Object Lock support: {error}"));
    let mut upload = store
        .create_multipart_upload(
            &object_id,
            PutOptions {
                retention: Some(policy),
                legal_hold: None,
                content_type: Some("application/octet-stream".to_owned()),
                do_not_recreate: false,
            },
        )
        .await
        .unwrap_or_else(|error| panic!("create retained multipart upload: {error}"));
    upload
        .put_part(0, Bytes::from(vec![b'a'; S3_MIN_MULTIPART_PART_BYTES]))
        .await
        .unwrap_or_else(|error| panic!("upload retained multipart first part: {error}"));
    upload
        .put_part(1, Bytes::from_static(b"tail-conformance"))
        .await
        .unwrap_or_else(|error| panic!("upload retained multipart final part: {error}"));
    let metadata = upload
        .complete()
        .await
        .unwrap_or_else(|error| panic!("complete retained multipart upload: {error}"));
    assert!(retention_satisfies(metadata.retention.as_ref(), &policy));
    let version_id = metadata
        .version_id
        .clone()
        .unwrap_or_else(|| panic!("retained multipart upload did not return a version id"));

    let head = store
        .head_at(&object_id, Some(&version_id))
        .await
        .unwrap_or_else(|error| panic!("head retained multipart object: {error}"));
    assert!(retention_satisfies(head.retention.as_ref(), &policy));
    let offset = u64::try_from(S3_MIN_MULTIPART_PART_BYTES - 4)
        .unwrap_or_else(|error| panic!("multipart boundary offset conversion failed: {error}"));
    let boundary = store
        .get_range_at(
            &object_id,
            Some(&version_id),
            ByteRange::Slice { offset, len: 8 },
        )
        .await
        .unwrap_or_else(|error| panic!("read retained multipart boundary range: {error}"));
    assert_eq!(boundary, Bytes::from_static(b"aaaatail"));

    let client = sdk_client(&target.config).await;
    let delete = client
        .delete_object()
        .bucket(target.config.bucket.as_str())
        .key(object_key)
        .version_id(version_id.as_str())
        .send()
        .await;
    assert!(
        matches!(delete, Err(ref error) if retention_delete_blocked(error)),
        "multipart version delete was not blocked by Object Lock: {delete:?}"
    );
}

#[tokio::test]
#[ignore = "requires RS3_TEST_S3_OBJECT_LOCK=true and an Object Lock-enabled bucket"]
async fn live_s3_object_lock_legal_hold_round_trips_and_blocks_version_delete() {
    if !env_bool("RS3_TEST_S3_OBJECT_LOCK").unwrap_or(false) {
        eprintln!("skipping live S3 Object Lock test: RS3_TEST_S3_OBJECT_LOCK is not true");
        return;
    }
    let Some(target) = live_target() else {
        eprintln!("skipping live S3 Object Lock test: RS3_TEST_S3_BUCKET is not set");
        return;
    };
    let object_id = BackendObjectId::new("retention/live-legal-hold-object".to_owned())
        .unwrap_or_else(|error| panic!("test object id: {error}"));
    let object_key = backend_key(&target.config, &object_id);
    let store = S3BlobStore::from_environment(target.config.clone())
        .await
        .unwrap_or_else(|error| panic!("build S3 blob store: {error}"));

    let put = store
        .put(
            &object_id,
            Bytes::from_static(b"legal hold object body"),
            PutOptions {
                retention: None,
                legal_hold: Some(LegalHoldStatus::On),
                content_type: Some("application/octet-stream".to_owned()),
                do_not_recreate: true,
            },
        )
        .await
        .unwrap_or_else(|error| panic!("put legal-held object: {error}"));
    assert_eq!(put.legal_hold, Some(LegalHoldStatus::On));
    let version_id = put
        .version_id
        .clone()
        .unwrap_or_else(|| panic!("legal-held S3 PUT did not return a version id"));

    let client = sdk_client(&target.config).await;
    let delete_held = client
        .delete_object()
        .bucket(target.config.bucket.as_str())
        .key(object_key.clone())
        .version_id(version_id.as_str())
        .send()
        .await;
    assert!(
        matches!(delete_held, Err(ref error) if retention_delete_blocked(error)),
        "version delete was not blocked by legal hold: {delete_held:?}"
    );

    store
        .set_legal_hold_at(&object_id, Some(&version_id), LegalHoldStatus::Off)
        .await
        .unwrap_or_else(|error| panic!("clear legal hold: {error}"));
    let head = store
        .head_at(&object_id, Some(&version_id))
        .await
        .unwrap_or_else(|error| panic!("head legal-held object: {error}"));
    assert!(
        head.legal_hold
            .is_none_or(|status| status == LegalHoldStatus::Off)
    );

    client
        .delete_object()
        .bucket(target.config.bucket.as_str())
        .key(object_key)
        .version_id(version_id.as_str())
        .send()
        .await
        .unwrap_or_else(|error| panic!("delete released legal-held version: {error}"));
}

struct LiveS3Target {
    provider_name: String,
    config: S3BlobStoreConfig,
    qualification_profile: S3QualificationProfile,
}

fn live_target() -> Option<LiveS3Target> {
    let bucket = env::var("RS3_TEST_S3_BUCKET").ok()?;
    let provider_name = env::var("RS3_TEST_S3_PROVIDER")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "s3-compatible".to_owned());
    let prefix = env::var("RS3_TEST_S3_PREFIX")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default_prefix(&provider_name));
    let endpoint_url = env::var("RS3_TEST_S3_ENDPOINT_URL").ok();
    let region = env::var("RS3_TEST_S3_REGION")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| Some("us-east-1".to_owned()));
    let allow_http = env_bool("RS3_TEST_S3_ALLOW_HTTP").unwrap_or_else(|| {
        endpoint_url
            .as_deref()
            .is_some_and(|url| url.starts_with("http://"))
    });
    let virtual_hosted_style = env_bool("RS3_TEST_S3_VIRTUAL_HOSTED_STYLE").unwrap_or(false);
    let qualification_profile = qualification_profile_from_env();
    let object_lock = env_bool("RS3_TEST_S3_OBJECT_LOCK").unwrap_or(false);
    assert!(
        qualification_profile != S3QualificationProfile::RetainedVersion || object_lock,
        "RS3_TEST_S3_QUALIFICATION_PROFILE=retained-version requires RS3_TEST_S3_OBJECT_LOCK=true"
    );

    let config = S3BlobStoreConfig::new(bucket)
        .unwrap_or_else(|error| panic!("invalid live S3 bucket: {error}"))
        .with_prefix(Some(prefix))
        .with_endpoint_url(endpoint_url)
        .with_region(region)
        .with_allow_http(allow_http)
        .with_virtual_hosted_style(virtual_hosted_style);

    Some(LiveS3Target {
        provider_name: provider_slug(&provider_name),
        config,
        qualification_profile,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum S3QualificationProfile {
    AtomicCreate,
    RetainedVersion,
}

fn qualification_profile_from_env() -> S3QualificationProfile {
    match env::var("RS3_TEST_S3_QUALIFICATION_PROFILE")
        .ok()
        .map(|value| value.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("retained-version" | "retained_version" | "object-lock") => {
            S3QualificationProfile::RetainedVersion
        }
        Some("atomic-create" | "atomic_create" | "strict" | "") | None => {
            S3QualificationProfile::AtomicCreate
        }
        Some(other) => panic!("invalid RS3_TEST_S3_QUALIFICATION_PROFILE={other:?}"),
    }
}

fn default_prefix(provider_name: &str) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    format!(
        "rs3-live/{}-{millis}-{}",
        provider_slug(provider_name),
        process::id()
    )
}

fn backend_key(config: &S3BlobStoreConfig, object_id: &BackendObjectId) -> String {
    match config.prefix.as_deref() {
        Some(prefix) => format!("{prefix}/{}", object_id.as_str()),
        None => object_id.as_str().to_owned(),
    }
}

async fn sdk_client(config: &S3BlobStoreConfig) -> SdkS3Client {
    let region = aws_config::meta::region::RegionProviderChain::first_try(
        config.region.clone().map(Region::new),
    )
    .or_default_provider()
    .or_else(Region::new("us-east-1"));
    let shared_config = aws_config::defaults(BehaviorVersion::latest())
        .region(region)
        .load()
        .await;
    let mut builder = aws_sdk_s3::config::Builder::from(&shared_config)
        .force_path_style(!config.virtual_hosted_style);
    if let Some(endpoint_url) = config.endpoint_url.as_deref() {
        builder = builder.endpoint_url(endpoint_url);
    }
    SdkS3Client::from_conf(builder.build())
}

fn retention_satisfies(actual: Option<&RetentionPolicy>, requested: &RetentionPolicy) -> bool {
    let Some(actual) = actual else {
        return false;
    };
    retention_mode_strength(actual.mode) >= retention_mode_strength(requested.mode)
        && actual.retain_days >= requested.retain_days
}

fn retention_mode_strength(mode: RetentionMode) -> u8 {
    match mode {
        RetentionMode::None => 0,
        RetentionMode::Governance => 1,
        RetentionMode::Compliance => 2,
    }
}

fn retention_delete_blocked<E, R>(error: &SdkError<E, R>) -> bool
where
    E: ProvideErrorMetadata,
{
    matches!(
        error
            .as_service_error()
            .and_then(ProvideErrorMetadata::code),
        Some("AccessDenied" | "InvalidRequest" | "MethodNotAllowed")
    )
}

fn provider_slug(provider_name: &str) -> String {
    let slug = provider_name
        .trim()
        .chars()
        .map(|character| match character {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => character,
            _ => '-',
        })
        .collect::<String>();

    if slug.is_empty() {
        "s3-compatible".to_owned()
    } else {
        slug
    }
}

fn env_bool(name: &str) -> Option<bool> {
    env::var(name)
        .ok()
        .and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
}

fn env_u32(name: &str) -> Option<u32> {
    env::var(name).ok()?.parse().ok().filter(|value| *value > 0)
}
