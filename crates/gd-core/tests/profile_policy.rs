//! Panic policy (Max, 2026-11-16): release builds unwind and check overflow,
//! and a crashing sensor is contained instead of taking the daemon down.

use std::fs;
use std::path::Path;

/// Checks the `[profile.release]` table of a parsed manifest. Returns what is
/// wrong, or `Ok` when release unwinds and checks overflow.
fn release_policy(manifest: &str) -> Result<(), String> {
    let doc: toml::Table = manifest
        .parse()
        .map_err(|e| format!("not valid TOML: {e}"))?;
    let release = doc
        .get("profile")
        .and_then(|p| p.get("release"))
        .and_then(|r| r.as_table())
        .ok_or("no [profile.release] table")?;
    match release.get("panic") {
        None => {}
        Some(v) if v.as_str() == Some("unwind") => {}
        Some(v) => return Err(format!("panic must be absent or \"unwind\", found {v}")),
    }
    match release.get("overflow-checks") {
        Some(v) if v.as_bool() == Some(true) => Ok(()),
        other => Err(format!("overflow-checks must be true, found {other:?}")),
    }
}

#[test]
fn release_profile_unwinds_and_checks_overflow() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let manifest = fs::read_to_string(&path).expect("workspace Cargo.toml should be readable");
    assert_eq!(release_policy(&manifest), Ok(()));
}

#[test]
fn the_policy_check_cannot_be_dodged_by_toml_spelling() {
    let ok = "[profile.release]\noverflow-checks = true\n";
    let cases: [(&str, &str); 9] = [
        (
            "plain abort",
            "[profile.release]\npanic = \"abort\"\noverflow-checks = true\n",
        ),
        (
            "tabs",
            "[profile.release]\npanic\t=\t\"abort\"\noverflow-checks = true\n",
        ),
        (
            "quoted key",
            "[profile.release]\n\"panic\" = \"abort\"\noverflow-checks = true\n",
        ),
        (
            "quoted header",
            "[\"profile\".\"release\"]\npanic = \"abort\"\noverflow-checks = true\n",
        ),
        (
            "dotted key",
            "[profile]\nrelease.panic = \"abort\"\nrelease.overflow-checks = true\n",
        ),
        (
            "inline table",
            "[profile]\nrelease = { panic = \"abort\", overflow-checks = true }\n",
        ),
        (
            "comment trick",
            "[profile.release] # panic = \"unwind\"\npanic = \"abort\" # overflow-checks = true\n",
        ),
        ("overflow checks missing", "[profile.release]\nlto = true\n"),
        (
            "overflow checks false",
            "[profile.release]\noverflow-checks = false\n",
        ),
    ];
    for (name, manifest) in cases {
        assert!(
            release_policy(manifest).is_err(),
            "{name} should be rejected"
        );
    }
    assert_eq!(release_policy(ok), Ok(()));
    assert_eq!(
        release_policy("[profile.release]\n\"panic\"\t=\t\"unwind\"\noverflow-checks = true\n"),
        Ok(())
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
