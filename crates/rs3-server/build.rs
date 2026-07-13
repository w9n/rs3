//! Embeds the exact tracked source revision in release evidence and runtime metadata.

use std::env;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=RS3_BUILD_GIT_SHA");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");

    let revision = env::var("RS3_BUILD_GIT_SHA")
        .ok()
        .and_then(normalize_revision)
        .or_else(git_revision)
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=RS3_BUILD_GIT_SHA={revision}");
}

fn git_revision() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--verify", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let mut revision = normalize_revision(String::from_utf8(output.stdout).ok()?)?;
    let dirty = Command::new("git")
        .args(["diff", "--quiet", "--ignore-submodules", "--"])
        .status()
        .ok()
        .is_some_and(|status| !status.success())
        || Command::new("git")
            .args(["diff", "--cached", "--quiet", "--ignore-submodules", "--"])
            .status()
            .ok()
            .is_some_and(|status| !status.success());
    if dirty {
        revision.push_str("-dirty");
    }
    Some(revision)
}

fn normalize_revision(value: String) -> Option<String> {
    let value = value.trim();
    let hash = value.strip_suffix("-dirty").unwrap_or(value);
    if matches!(hash.len(), 40 | 64)
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Some(value.to_owned())
    } else {
        None
    }
}
