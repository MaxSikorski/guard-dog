//! `guard-dog --version` names the release, plus the exact source commit when
//! the build was given one (`GD_GIT_COMMIT`), or "development build".

use std::process::Command;

#[test]
fn version_names_the_release_and_its_source() {
    let output = Command::new(env!("CARGO_BIN_EXE_guard-dog"))
        .arg("--version")
        .output()
        .expect("guard-dog --version should run");
    assert!(output.status.success(), "exit status: {}", output.status);

    let printed = String::from_utf8(output.stdout).expect("the version line is UTF-8");
    let expected = format!(
        "guard-dog {} ({})\n",
        env!("CARGO_PKG_VERSION"),
        expected_source()
    );
    assert_eq!(printed, expected);
}

/// Worked out from the build's input, `GD_GIT_COMMIT`, never from the value the
/// build script baked in, so a broken build script fails this test. CI runs it
/// with `GD_GIT_COMMIT` set; a plain local run checks the development path.
fn expected_source() -> String {
    match std::env::var("GD_GIT_COMMIT") {
        Ok(commit) if !commit.is_empty() => format!("commit {commit}"),
        _ => "development build".to_owned(),
    }
}
