//! The `gd-egress` command line, run as a real process.

// Test-only crate: see `crates/gd-core/tests/judge_d_injection.rs` for why helpers need this.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod support;

use gd_egress::canary::Class;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use support::*;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_gd-egress"))
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("gd-egress-cli-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn canaries_command_writes_root_judge_teeth_and_control() {
    let out = temp("canaries");
    let result = bin()
        .args(["canaries", "--seed", "1"])
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&result.stderr).contains("GD_CANARY_SEED=1"));
    let golden = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/egress/golden/canaries-seed-1.json"
    ))
    .unwrap();
    assert_eq!(
        fs::read_to_string(out.join("judge/canaries.json")).unwrap(),
        golden
    );
    assert!(out.join("root/home/umbrel/seed.txt").is_file());
    let set = gd_egress::canary::generate(1);
    assert_eq!(
        fs::read_to_string(out.join("control.env")).unwrap(),
        format!("GD_CONTROL_TOKEN={}\n", set.control_token)
    );
    let leak = fs::read_to_string(out.join("teeth/leak.env")).unwrap();
    let keys: Vec<&str> = leak.lines().map(|l| l.split('=').next().unwrap()).collect();
    assert_eq!(
        keys,
        [
            "GD_LEAK_NSEC",
            "GD_LEAK_SEED",
            "GD_LEAK_XPUB",
            "GD_LEAK_MACAROON_LABEL",
            "GD_LEAK_MACAROON_B64"
        ]
    );
    assert!(leak.lines().all(|l| l.contains("='") && l.ends_with('\'')));
    assert!(leak.contains(&format!("GD_LEAK_NSEC='{}'", set.text(Class::Nsec))));
    assert!(leak.contains(&format!(
        "GD_LEAK_MACAROON_LABEL='{}'",
        &set.text(Class::Macaroon)[..60]
    )));
    // `random` works and prints the seed it used.
    let random = temp("random");
    let result = bin()
        .args(["canaries", "--seed", "random"])
        .arg("--out")
        .arg(&random)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&result.stderr)
            .trim()
            .starts_with("GD_CANARY_SEED=")
    );
}

#[test]
fn canaries_command_refuses_an_existing_output() {
    let out = temp("refuse");
    fs::create_dir_all(out.join("root")).unwrap();
    let result = bin()
        .args(["canaries", "--seed", "1"])
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(!out.join("judge").exists(), "nothing was written");
    let again = temp("refuse-judge");
    fs::create_dir_all(again.join("judge")).unwrap();
    assert_eq!(
        bin()
            .args(["canaries", "--seed", "1"])
            .arg("--out")
            .arg(&again)
            .output()
            .unwrap()
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        bin()
            .args(["canaries", "--seed", "x"])
            .arg("--out")
            .arg(&out)
            .output()
            .unwrap()
            .status
            .code(),
        Some(2)
    );
}

fn check(capture: &Path, canaries: &Path, work: &Path) -> Output {
    let rules =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/egress/expected-rules.txt");
    bin()
        .args(["check", "--capture"])
        .arg(capture)
        .arg("--canaries")
        .arg(canaries)
        .arg("--allowlist")
        .arg(work.join("allowlist.toml"))
        .arg("--expected-rules")
        .arg(rules)
        .arg("--report")
        .arg(work.join("report.txt"))
        .arg("--details")
        .arg(work.join("details.txt"))
        .output()
        .unwrap()
}

#[test]
fn check_exits_0_on_pass_1_on_fail_2_on_bad_input() {
    let work = temp("check");
    fs::write(work.join("allowlist.toml"), EMPTY_ALLOWLIST).unwrap();

    let clean = Scenario::new("cli-s01", 1);
    let canaries = work.join("canaries.json");
    fs::write(&canaries, clean.set.to_json()).unwrap();
    let pass = check(&clean.write(), &canaries, &work);
    assert_eq!(pass.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&pass.stdout),
        expected_report("S01-clean-baseline")
    );
    assert_eq!(
        fs::read_to_string(work.join("report.txt")).unwrap(),
        expected_report("S01-clean-baseline")
    );
    assert!(
        fs::read_to_string(work.join("details.txt"))
            .unwrap()
            .contains("mitm: 2 connections")
    );

    let mut leaky = Scenario::new("cli-s03", 1);
    leaky.dns_query("leak.example.net");
    let c = leaky.connect("198.18.0.1", 443);
    leaky.tls(c, Some("leak.example.net"), true);
    let nsec = leaky.canary(Class::Nsec);
    leaky.http(
        c,
        "https",
        "POST",
        "leak.example.net",
        443,
        "/collect",
        &[],
        nsec.as_bytes(),
        false,
        false,
    );
    let fail = check(&leaky.write(), &canaries, &work);
    assert_eq!(fail.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&fail.stdout),
        expected_report("S03-https-body-leak")
    );
    assert!(
        !String::from_utf8_lossy(&fail.stdout).contains(&nsec),
        "the report never prints a canary"
    );

    let missing = check(&clean.write(), &work.join("nope.json"), &work);
    assert_eq!(missing.status.code(), Some(2));
    fs::write(work.join("allowlist.toml"), "format = 2\n").unwrap();
    assert_eq!(
        check(&clean.write(), &canaries, &work).status.code(),
        Some(2)
    );
    assert_eq!(bin().arg("check").output().unwrap().status.code(), Some(2));
    // A capture directory with nothing in it fails closed, it does not pass.
    fs::write(work.join("allowlist.toml"), EMPTY_ALLOWLIST).unwrap();
    let empty = temp("empty-capture");
    let blank = check(&empty, &canaries, &work);
    assert_eq!(blank.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&blank.stdout).contains("F5 capture-unreadable pcap: missing-file")
    );
}
