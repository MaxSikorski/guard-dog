//! Bakes the git commit into the binary, so `guard-dog --version` says exactly
//! which source it was built from.
//!
//! A build without git (for example from a source tarball) says "unknown".
//! Packagers can set `GD_GIT_COMMIT` to the commit they built from.

use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=GD_GIT_COMMIT");

    let commit = match std::env::var("GD_GIT_COMMIT") {
        Ok(given) if !given.is_empty() => {
            assert!(
                is_commit_id(&given),
                "GD_GIT_COMMIT must be a git commit id (7 to 64 hex characters), got {given:?}"
            );
            given
        }
        _ => {
            rebuild_when_head_moves();
            git(&["rev-parse", "--short=12", "HEAD"])
                .filter(|commit| is_commit_id(commit))
                .unwrap_or_else(|| "unknown".to_owned())
        }
    };
    println!("cargo:rustc-env=GD_GIT_COMMIT={commit}");
}

/// Re-runs this script after a new commit or a checkout, so the version line
/// never names a stale commit. Works in plain clones and in git worktrees.
fn rebuild_when_head_moves() {
    let mut watched = vec![git_path("HEAD"), git_path("packed-refs")];
    if let Some(branch) = git(&["symbolic-ref", "-q", "HEAD"]) {
        watched.push(git_path(&branch));
    }
    for path in watched.into_iter().flatten() {
        if Path::new(&path).exists() {
            println!("cargo:rerun-if-changed={path}");
        }
    }
}

fn git_path(name: &str) -> Option<String> {
    git(&["rev-parse", "--path-format=absolute", "--git-path", name])
}

/// Runs git with a fixed argument list (no shell) and returns its trimmed output.
fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

fn is_commit_id(text: &str) -> bool {
    (7..=64).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}
