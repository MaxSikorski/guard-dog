//! `guard-dog --version` names the release and the exact source commit.

use std::process::Command;

#[test]
fn version_names_the_release_and_the_current_commit() {
    let output = Command::new(env!("CARGO_BIN_EXE_guard-dog"))
        .arg("--version")
        .output()
        .expect("guard-dog --version should run");
    assert!(output.status.success(), "exit status: {}", output.status);

    let printed = String::from_utf8(output.stdout).expect("the version line is UTF-8");
    let expected = format!(
        "guard-dog {} (commit {})\n",
        env!("CARGO_PKG_VERSION"),
        expected_commit()
    );
    assert_eq!(printed, expected);
}

/// The commit worked out here, independently of the build script, so a stale
/// or broken build script fails this test.
fn expected_commit() -> String {
    if let Ok(given) = std::env::var("GD_GIT_COMMIT")
        && !given.is_empty()
    {
        return given;
    }
    Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_else(|| "unknown".to_owned())
}
