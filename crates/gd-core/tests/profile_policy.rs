//! Panic policy (Max, 2026-11-16): release builds unwind and check overflow,
//! and a crashing sensor is contained instead of taking the daemon down.

use std::fs;
use std::path::Path;

/// Collects the `key = value` lines of one `[table]` in the workspace
/// `Cargo.toml`, with comments and spaces removed. A line-based read is enough
/// for this one table and avoids a new dependency.
fn table_lines(manifest: &str, table: &str) -> Vec<String> {
    let header = format!("[{table}]");
    let mut inside = false;
    let mut lines = Vec::new();
    for raw in manifest.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            inside = line == header;
            continue;
        }
        if inside && !line.is_empty() {
            lines.push(line.replace(' ', ""));
        }
    }
    lines
}

#[test]
fn release_profile_unwinds_and_checks_overflow() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let manifest = fs::read_to_string(&path).expect("workspace Cargo.toml should be readable");
    let release = table_lines(&manifest, "profile.release");

    assert!(
        !release.is_empty(),
        "the [profile.release] table must exist, or this test reads nothing"
    );
    assert!(
        !release.iter().any(|l| l.starts_with("panic=")),
        "release must not set `panic` at all: it unwinds by default, and abort is only for a future action-executor process; found {release:?}"
    );
    assert!(
        release.iter().any(|l| l == "overflow-checks=true"),
        "release must set overflow-checks = true; found {release:?}"
    );
}

#[test]
fn the_table_reader_sees_what_it_should() {
    let sample = "[a]\nx = 1\n[profile.release]\npanic = \"abort\" # no\n\n[b]\ny = 2\n";
    assert_eq!(
        table_lines(sample, "profile.release"),
        vec!["panic=\"abort\"".to_string()]
    );
}

/// The containment primitive the daemon will use: run each sensor under
/// `catch_unwind`, treat a panic as that sensor's failure, and carry on.
/// Only meaningful when panics unwind, so it is compiled out under abort.
#[cfg(panic = "unwind")]
#[test]
fn sensor_panic_is_contained() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let crashed = catch_unwind(AssertUnwindSafe(|| {
        panic!("simulated sensor crash");
    }));
    assert!(crashed.is_err(), "a panicking sensor must come back as Err");

    // The caller is still alive and can run the next sensor.
    let healthy = catch_unwind(AssertUnwindSafe(|| 2 + 2));
    assert_eq!(healthy.ok(), Some(4));
}
