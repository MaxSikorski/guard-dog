//! Bakes the source commit into the binary for `guard-dog --version`.
//!
//! Release builds set `GD_GIT_COMMIT` to the full commit id they were built
//! from (the release pipeline does; packagers can too). Every other build says
//! "development build" rather than guessing: a commit read from a local
//! checkout can be stale, have uncommitted changes, or belong to another
//! repository the source happens to sit inside.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=GD_GIT_COMMIT");

    let source = match std::env::var("GD_GIT_COMMIT") {
        Ok(commit) if !commit.is_empty() => {
            assert!(
                is_full_commit_id(&commit),
                "GD_GIT_COMMIT must be a full git commit id (40 or 64 lowercase hex characters), got {commit:?}"
            );
            format!("commit {commit}")
        }
        _ => "development build".to_owned(),
    };
    println!("cargo:rustc-env=GD_BUILD_SOURCE={source}");
}

fn is_full_commit_id(text: &str) -> bool {
    matches!(text.len(), 40 | 64)
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}
