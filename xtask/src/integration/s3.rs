//! Storage-level S3 integration command.

use super::S3ContainerProvider;
#[cfg(feature = "containers")]
use super::s3_container;
use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use std::process::Command;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum S3LocalMode {
    /// Use an already running endpoint and bucket.
    Provided,
    /// Start a local S3-compatible container for the contract run.
    Container,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum S3QualificationProfile {
    /// Provider must reject duplicate create-only PUTs atomically.
    AtomicCreate,
    /// Provider qualifies through Object Lock, version IDs, and exact-version reads.
    RetainedVersion,
}

impl S3QualificationProfile {
    const fn as_env(self) -> &'static str {
        match self {
            Self::AtomicCreate => "atomic-create",
            Self::RetainedVersion => "retained-version",
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct S3LocalArgs {
    /// Integration mode.
    #[arg(long, value_enum, default_value_t = S3LocalMode::Provided)]
    mode: S3LocalMode,
    /// Container provider used when --mode container is selected.
    #[arg(long, value_enum, default_value_t = S3ContainerProvider::Rustfs)]
    container_provider: S3ContainerProvider,
    /// Provider label used only in test object prefixes and output. Defaults by mode.
    #[arg(long, env = "RS3_TEST_S3_PROVIDER")]
    provider: Option<String>,
    /// Existing test bucket. If omitted, the live test compiles and skips.
    #[arg(long, env = "RS3_TEST_S3_BUCKET")]
    bucket: Option<String>,
    /// S3-compatible endpoint URL. Omit for the default AWS endpoint.
    #[arg(long, env = "RS3_TEST_S3_ENDPOINT_URL")]
    endpoint_url: Option<String>,
    /// S3 signing region.
    #[arg(long, env = "RS3_TEST_S3_REGION")]
    region: Option<String>,
    /// Prefix for objects created by this test run.
    #[arg(long, env = "RS3_TEST_S3_PREFIX")]
    prefix: Option<String>,
    /// Allow plain HTTP endpoints.
    #[arg(long, env = "RS3_TEST_S3_ALLOW_HTTP")]
    allow_http: Option<bool>,
    /// Use virtual-hosted-style S3 requests.
    #[arg(long, env = "RS3_TEST_S3_VIRTUAL_HOSTED_STYLE")]
    virtual_hosted_style: Option<bool>,
    /// Provider qualification profile.
    #[arg(
        long,
        env = "RS3_TEST_S3_QUALIFICATION_PROFILE",
        value_enum,
        default_value_t = S3QualificationProfile::AtomicCreate
    )]
    qualification_profile: S3QualificationProfile,
    /// Run Object Lock retention checks against the bucket.
    #[arg(long, env = "RS3_TEST_S3_OBJECT_LOCK", default_value_t = false)]
    object_lock: bool,
    /// Retention duration used by the Object Lock live test.
    #[arg(long, env = "RS3_TEST_S3_RETENTION_DAYS")]
    retention_days: Option<u32>,
    /// Rehearse exact retained-version GC in the disposable container bucket.
    #[arg(long, default_value_t = false)]
    gc_rehearsal: bool,
}

pub(crate) fn run_s3_local(args: S3LocalArgs) -> Result<()> {
    validate_s3_profile(&args)?;

    match args.mode {
        S3LocalMode::Provided => run_provided_s3(args),
        S3LocalMode::Container => run_container_s3(args),
    }
}

fn validate_s3_profile(args: &S3LocalArgs) -> Result<()> {
    if args.qualification_profile == S3QualificationProfile::RetainedVersion && !args.object_lock {
        anyhow::bail!(
            "the retained-version S3 qualification profile requires --object-lock so retention, legal hold, version IDs, and exact-version reads are tested"
        );
    }
    if args.gc_rehearsal
        && (args.mode != S3LocalMode::Container
            || args.qualification_profile != S3QualificationProfile::RetainedVersion)
    {
        anyhow::bail!(
            "--gc-rehearsal requires container mode with the retained-version qualification profile"
        );
    }

    Ok(())
}

fn run_provided_s3(args: S3LocalArgs) -> Result<()> {
    run_live_s3_contract(LiveS3Contract {
        provider: args.provider.unwrap_or_else(|| "s3-compatible".to_owned()),
        bucket: args.bucket,
        endpoint_url: args.endpoint_url,
        region: args.region,
        prefix: args.prefix,
        allow_http: args.allow_http,
        virtual_hosted_style: args.virtual_hosted_style,
        qualification_profile: args.qualification_profile,
        object_lock: args.object_lock,
        retention_days: args.retention_days,
        credentials: None,
    })
}

#[cfg(not(feature = "containers"))]
fn run_container_s3(args: S3LocalArgs) -> Result<()> {
    anyhow::bail!(
        "container integration for {:?} requires `cargo run -p xtask --bin xtask --features containers -- integration s3-local --mode container`",
        args.container_provider,
    )
}

#[cfg(feature = "containers")]
fn run_container_s3(args: S3LocalArgs) -> Result<()> {
    let target = s3_container::start_s3_container_with_options(
        args.container_provider,
        args.bucket,
        args.region,
        s3_container::S3ContainerOptions {
            object_lock: args.object_lock,
        },
    )?;

    run_live_s3_contract(LiveS3Contract {
        provider: args
            .provider
            .unwrap_or_else(|| target.provider.as_label().to_owned()),
        bucket: Some(target.bucket.clone()),
        endpoint_url: Some(target.endpoint_url.clone()),
        region: Some(target.region.clone()),
        prefix: args.prefix,
        allow_http: Some(true),
        virtual_hosted_style: Some(false),
        qualification_profile: args.qualification_profile,
        object_lock: args.object_lock,
        retention_days: args.retention_days,
        credentials: Some(AwsCredentials {
            access_key_id: target.access_key_id.clone(),
            secret_access_key: target.secret_access_key.clone(),
        }),
    })?;
    if args.gc_rehearsal {
        run_container_gc_rehearsal(&target, args.retention_days.unwrap_or(1))?;
    }
    Ok(())
}

#[cfg(feature = "containers")]
fn run_container_gc_rehearsal(
    target: &s3_container::RunningS3Container,
    retention_days: u32,
) -> Result<()> {
    let executable = std::env::current_exe().context("failed to locate xtask executable")?;
    let retention_days = retention_days.to_string();
    let mut command = Command::new(executable);
    command.args([
        "v2",
        "gc-rehearsal",
        "--backend",
        "s3",
        "--s3-bucket",
        &target.bucket,
        "--s3-prefix",
        "local-retained-gc",
        "--s3-endpoint-url",
        &target.endpoint_url,
        "--s3-region",
        &target.region,
        "--s3-allow-http",
        "--retention-days",
        &retention_days,
        "--retained-provider-conformance-passed",
        // The container bucket is disposable and single-process, so the
        // isolated rehearsal explicitly opts into the honor-system guard.
        "--unenforced-guard",
        "--format",
        "json",
    ]);
    command.env("AWS_ACCESS_KEY_ID", &target.access_key_id);
    command.env("AWS_SECRET_ACCESS_KEY", &target.secret_access_key);
    command.env("AWS_DEFAULT_REGION", &target.region);
    command.env_remove("AWS_SESSION_TOKEN");
    command.env_remove("AWS_PROFILE");
    let status = command
        .status()
        .context("failed to start retained GC rehearsal")?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("retained GC rehearsal exited with {status}");
    }
}

struct LiveS3Contract {
    provider: String,
    bucket: Option<String>,
    endpoint_url: Option<String>,
    region: Option<String>,
    prefix: Option<String>,
    allow_http: Option<bool>,
    virtual_hosted_style: Option<bool>,
    qualification_profile: S3QualificationProfile,
    object_lock: bool,
    retention_days: Option<u32>,
    credentials: Option<AwsCredentials>,
}

struct AwsCredentials {
    access_key_id: String,
    secret_access_key: String,
}

fn run_live_s3_contract(contract: LiveS3Contract) -> Result<()> {
    let mut command = Command::new("cargo");
    command.args([
        "test",
        "-p",
        "rs3-storage",
        "--features",
        "s3",
        "--test",
        "s3_live",
        "--",
        "--ignored",
        "--nocapture",
    ]);
    command.env("RS3_TEST_S3_PROVIDER", contract.provider);
    set_env(&mut command, "RS3_TEST_S3_BUCKET", contract.bucket);
    set_env(
        &mut command,
        "RS3_TEST_S3_ENDPOINT_URL",
        contract.endpoint_url,
    );
    set_env(&mut command, "RS3_TEST_S3_REGION", contract.region.clone());
    set_env(&mut command, "RS3_TEST_S3_PREFIX", contract.prefix);
    set_env_bool(&mut command, "RS3_TEST_S3_ALLOW_HTTP", contract.allow_http);
    set_env_bool(
        &mut command,
        "RS3_TEST_S3_VIRTUAL_HOSTED_STYLE",
        contract.virtual_hosted_style,
    );
    command.env(
        "RS3_TEST_S3_QUALIFICATION_PROFILE",
        contract.qualification_profile.as_env(),
    );
    command.env(
        "RS3_TEST_S3_OBJECT_LOCK",
        if contract.object_lock {
            "true"
        } else {
            "false"
        },
    );
    set_env(
        &mut command,
        "RS3_TEST_S3_RETENTION_DAYS",
        contract.retention_days.map(|days| days.to_string()),
    );
    if let Some(credentials) = contract.credentials {
        command.env("AWS_ACCESS_KEY_ID", credentials.access_key_id);
        command.env("AWS_SECRET_ACCESS_KEY", credentials.secret_access_key);
        set_env(&mut command, "AWS_DEFAULT_REGION", contract.region);
        command.env_remove("AWS_SESSION_TOKEN");
        command.env_remove("AWS_PROFILE");
        command.env_remove("AWS_WEB_IDENTITY_TOKEN_FILE");
        command.env_remove("AWS_ROLE_ARN");
        command.env_remove("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI");
        command.env_remove("AWS_CONTAINER_CREDENTIALS_FULL_URI");
        command.env_remove("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE");
    }

    let status = command
        .status()
        .context("failed to start live S3 integration test")?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("live S3 integration test exited with {status}");
    }
}

fn set_env(command: &mut Command, key: &'static str, value: Option<String>) {
    if let Some(value) = value {
        command.env(key, value);
    }
}

fn set_env_bool(command: &mut Command, key: &'static str, value: Option<bool>) {
    if let Some(value) = value {
        command.env(key, if value { "true" } else { "false" });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_for_profile(
        qualification_profile: S3QualificationProfile,
        object_lock: bool,
    ) -> S3LocalArgs {
        S3LocalArgs {
            mode: S3LocalMode::Provided,
            container_provider: S3ContainerProvider::Rustfs,
            provider: None,
            bucket: None,
            endpoint_url: None,
            region: None,
            prefix: None,
            allow_http: None,
            virtual_hosted_style: None,
            qualification_profile,
            object_lock,
            retention_days: None,
            gc_rehearsal: false,
        }
    }

    #[test]
    fn retained_version_profile_requires_object_lock_checks() {
        let error = validate_s3_profile(&args_for_profile(
            S3QualificationProfile::RetainedVersion,
            false,
        ))
        .expect_err("retained-version without Object Lock should fail");

        assert!(error.to_string().contains("requires --object-lock"));
    }

    #[test]
    fn retained_version_profile_accepts_object_lock_checks() {
        validate_s3_profile(&args_for_profile(
            S3QualificationProfile::RetainedVersion,
            true,
        ))
        .expect("retained-version with Object Lock should pass");
    }
}
