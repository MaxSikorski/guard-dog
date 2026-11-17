//! Phase 2.1, PR 3 and 4 (part): Core Lightning's `calver` scheme and
//! `git-describe` (strfry; also CLN's describe suffix).
//!
//! Every rule and example of design 2.1 section 2 for these two schemes, every
//! corpus endpoint and fixture version for Core Lightning and strfry, the
//! ordering laws, refused and oversized input, the two schemes wired through
//! `evaluate_entry` on the real advisory records and the fixture's expected
//! version results, and three local test-only mutants that must fail.

// Test-only crate: helper functions build data and check it, and a panic there
// is a failed check (clippy.toml exempts only `#[test]` functions).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::cmp::Ordering;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use gd_advisories::{
    Advisory, Calver, Candidate, ClnVersion, Commit, GitDescribe, Place, SemVer, Source,
    TagVersion, UnknownReason, VersionError, VersionEvidence, VersionScheme, evaluate_entry,
    parse_advisory, parse_advisory_from,
};
use proptest::prelude::*;
use serde_json::{Value, json};

// ---------------------------------------------------------------- helpers

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn cln(s: &str) -> ClnVersion {
    Calver
        .parse(s)
        .unwrap_or_else(|e| panic!("a calver test input should parse: {e}"))
}

fn tag(s: &str) -> TagVersion {
    GitDescribe
        .parse(s)
        .unwrap_or_else(|e| panic!("a git-describe test input should parse: {e}"))
}

fn order_cln(a: &str, b: &str) -> Ordering {
    cln(a).cmp(&cln(b))
}

fn order_tag(a: &str, b: &str) -> Ordering {
    tag(a).cmp(&tag(b))
}

fn git_advisory(ranges: Value, versions: Value) -> Advisory {
    let mut e =
        json!({"package": {"ecosystem": "GIT", "name": "https://github.com/hoytech/strfry"}});
    if ranges.as_array().is_some_and(|r| !r.is_empty()) {
        e["ranges"] = ranges;
    }
    if versions.as_array().is_some_and(|r| !r.is_empty()) {
        e["versions"] = versions;
    }
    let record = json!({"id": "x_test-1", "modified": "2026-11-17T00:00:00Z", "affected": [e]});
    parse_advisory(record.to_string().as_bytes()).unwrap()
}

fn eco(events: Value) -> Value {
    json!({"type": "ECOSYSTEM", "events": events})
}

fn kind(e: &VersionEvidence) -> &'static str {
    match e {
        VersionEvidence::InRange(_) => "in-range",
        VersionEvidence::OutOfRange => "out-of-range",
        VersionEvidence::Unknown { .. } => "unknown",
        VersionEvidence::NotApplicable => "not-applicable",
    }
}

fn reason(e: &VersionEvidence) -> UnknownReason {
    match e {
        VersionEvidence::Unknown { reason, .. } => *reason,
        other => panic!("expected unknown, got {other:?}"),
    }
}

// ----------------------------------------------------- fixture and corpus

/// One `[[table]]` block of `fixtures/expected-matches.toml`, with the id of the
/// `[[setup]]` it belongs to. Only `key = "string"` lines are read.
struct Row {
    table: String,
    setup: String,
    fields: HashMap<String, String>,
}

fn fixture_rows() -> Vec<Row> {
    let text = fs::read_to_string(root().join("fixtures/expected-matches.toml")).unwrap();
    let mut rows: Vec<Row> = Vec::new();
    let mut setup = String::new();
    for line in text.lines() {
        let l = line.trim();
        if let Some(name) = l.strip_prefix("[[").and_then(|r| r.strip_suffix("]]")) {
            rows.push(Row {
                table: name.to_string(),
                setup: setup.clone(),
                fields: HashMap::new(),
            });
        } else if let Some((k, v)) = l.split_once(" = ")
            && let Some(v) = v.strip_prefix('"').and_then(|v| v.strip_suffix('"'))
            && let Some(row) = rows.last_mut()
        {
            if row.table == "setup" && k == "id" {
                setup = v.to_string();
                row.setup = v.to_string();
            }
            row.fields.insert(k.to_string(), v.to_string());
        }
    }
    rows
}

fn service_version(setup: &str, id: &str) -> String {
    fixture_rows()
        .into_iter()
        .find(|r| {
            r.table == "setup.service"
                && r.setup == setup
                && r.fields.get("id").map(String::as_str) == Some(id)
        })
        .and_then(|r| r.fields.get("version").cloned())
        .unwrap_or_else(|| panic!("a fixture service row is missing"))
}

fn expected_version(setup: &str, advisory: &str) -> String {
    fixture_rows()
        .into_iter()
        .find(|r| {
            r.table == "expect"
                && r.fields.get("setup").map(String::as_str) == Some(setup)
                && r.fields.get("advisory").map(String::as_str) == Some(advisory)
        })
        .and_then(|r| r.fields.get("version").cloned())
        .unwrap_or_else(|| panic!("a fixture expectation row is missing"))
}

fn corpus_record(id: &str) -> (Advisory, Value) {
    let bytes = fs::read(root().join(format!("advisories/corpus/{id}.json"))).unwrap();
    (
        parse_advisory_from(&bytes, Source::GuardDogCorpus).unwrap(),
        serde_json::from_slice(&bytes).unwrap(),
    )
}

/// Every event value (and listed version) of every affected entry in the corpus
/// whose package name contains `needle`, read from the raw JSON.
fn corpus_values_for(needle: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut paths: Vec<PathBuf> = fs::read_dir(root().join("advisories/corpus"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    paths.sort();
    for p in paths {
        let v: Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
        for entry in v["affected"].as_array().unwrap() {
            let name = entry["package"]["name"].as_str().unwrap_or_default();
            if !name.contains(needle) {
                continue;
            }
            for range in entry["ranges"].as_array().into_iter().flatten() {
                for event in range["events"].as_array().unwrap() {
                    for (_, val) in event.as_object().unwrap() {
                        out.push(val.as_str().unwrap().to_string());
                    }
                }
            }
            for listed in entry["versions"].as_array().into_iter().flatten() {
                out.push(listed.as_str().unwrap().to_string());
            }
        }
    }
    out
}

/// The `version = "..."` and `raw = "..."` values of a catalog entry's
/// `[[version.examples]]`.
fn catalog_examples(id: &str) -> Vec<(String, String)> {
    let text = fs::read_to_string(root().join(format!("catalog/{id}.toml"))).unwrap();
    let mut out = Vec::new();
    let mut raw = None;
    let mut inside = false;
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            inside = l == "[[version.examples]]";
            raw = None;
        } else if inside && let Some((k, v)) = l.split_once(" = ") {
            let v = v.trim_matches('"').to_string();
            match k {
                "raw" => raw = Some(v),
                "version" => out.push((raw.take().unwrap_or_default(), v)),
                _ => {}
            }
        }
    }
    out
}

// ---------------------------------------------------------- CLN: the rules

#[test]
fn cln_design_examples_order_as_stated() {
    // Legacy releases sit below the first calendar release.
    assert_eq!(order_cln("v0.10.2", "v0.12.1"), Ordering::Less);
    assert_eq!(order_cln("v0.12.1", "v22.11"), Ordering::Less);
    assert_eq!(order_cln("v0.10.2", "v22.11"), Ordering::Less);
    // The patch defaults to 0.
    assert_eq!(order_cln("v24.11", "24.11.0"), Ordering::Equal);
    assert_eq!(order_cln("24.11.0", "24.11.1"), Ordering::Less);
    assert_eq!(order_cln("24.11.1", "25.02"), Ordering::Less);
    // A release candidate sits below its final release, numerically.
    assert_eq!(order_cln("26.06rc2", "26.06rc10"), Ordering::Less);
    assert_eq!(order_cln("26.06rc10", "26.06"), Ordering::Less);
    assert_eq!(order_cln("26.06rc2", "26.06"), Ordering::Less);
    // Month 13 is not a month.
    assert_eq!(Calver.parse("26.13").unwrap_err(), VersionError::Malformed);
}

#[test]
fn cln_orders_numerically_never_lexically() {
    assert_eq!(order_cln("v0.9.0", "v0.10.2"), Ordering::Less);
    assert_eq!(order_cln("v0.2.0", "v0.10.0"), Ordering::Less);
    assert_eq!(order_cln("24.11.9", "24.11.10"), Ordering::Less);
    assert_eq!(order_cln("24.11rc9", "24.11rc10"), Ordering::Less);
    assert_eq!(order_cln("24.09", "24.10"), Ordering::Less);
    assert_eq!(order_cln("00.12", "99.01"), Ordering::Less);
}

#[test]
fn cln_legacy_forms() {
    for ok in [
        "0.10.2",
        "v0.12.1",
        "v0.9.0rc1",
        "0.11.0rc2",
        "v0.0.1",
        "0.7.3",
    ] {
        assert!(cln(ok).is_legacy());
    }
    for ok in ["22.11", "v24.11.1", "00.01", "99.12", "26.06rc1"] {
        assert!(!cln(ok).is_legacy());
    }
    assert_eq!(order_cln("v0.11.0rc2", "v0.11.0"), Ordering::Less);
    assert_eq!(order_cln("v0.11.0rc2", "v0.11.0rc10"), Ordering::Less);
    // A legacy release is below every calendar release, even the first possible one.
    assert_eq!(order_cln("v0.99.99", "00.01"), Ordering::Less);
    assert_eq!(order_cln("v0.12.1rc9", "00.01rc1"), Ordering::Less);
}

#[test]
fn cln_accepts_the_stated_shapes() {
    for ok in [
        "24.11",
        "v24.11",
        "24.11.0",
        "24.11.1",
        "24.11rc1",
        "24.11.2rc3",
        "v26.06.9",
        "25.09",
        "00.01",
        "99.12",
        "26.06rc0",
        "24.11.18446744073709551616",
    ] {
        assert!(Calver.parse(ok).is_ok());
    }
}

#[test]
fn cln_refuses_everything_else() {
    for bad in [
        "",
        "v",
        "vv24.11",
        "V24.11",
        "26.13",
        "26.00",
        "24.1",
        "24.011",
        "2024.11",
        "24.",
        "24",
        "24.11.",
        "24.11.01",
        "24.11.1.1",
        "24.11rc",
        "24.11-rc1",
        "24.11RC1",
        "24.11rc01",
        "24.11rc1rc2",
        "24.11.rc1",
        " 24.11",
        "24.11 ",
        "24.11+build",
        "0.10",
        "0.10.2.1",
        "0.01.2",
        "0.10.02",
        "1.2.3",
        "5.1",
        "0",
        "０.10.2",
        "２４.11",
        "24.11\n",
        "24.11-12-gabc1234",
        "24.11-dirty",
        "v24.11-modded",
    ] {
        assert_eq!(Calver.parse(bad), Err(VersionError::Malformed));
    }
}

#[test]
fn cln_refuses_oversize_input() {
    let long = format!("24.11.{}", "9".repeat(300));
    assert_eq!(Calver.parse(&long).unwrap_err(), VersionError::TooLong);
    assert_eq!(Calver.candidate(&long).unwrap_err(), VersionError::TooLong);
    // At the limit a long number still reads, and compares by length then bytes.
    let at_limit = format!("24.11.{}", "9".repeat(249));
    let past = format!("24.11.1{}", "0".repeat(249));
    assert!(order_cln(&at_limit, &past) == Ordering::Less);
}

#[test]
fn cln_numbers_beyond_64_bits_compare_exactly() {
    let big = "24.11.18446744073709551616";
    let smaller = "24.11.18446744073709551615";
    assert_eq!(order_cln(smaller, big), Ordering::Less);
    assert_eq!(order_cln(big, "24.11.9"), Ordering::Greater);
}

#[test]
fn cln_display_is_the_canonical_form() {
    for (raw, canonical) in [
        ("v24.11", "24.11.0"),
        ("24.11", "24.11.0"),
        ("24.11.0", "24.11.0"),
        ("v26.06.9", "26.06.9"),
        ("26.06rc2", "26.06.0rc2"),
        ("v0.10.2", "0.10.2"),
        ("v0.9.0rc1", "0.9.0rc1"),
        ("00.01", "00.01.0"),
    ] {
        let v = cln(raw);
        assert_eq!(v.to_string(), canonical);
        assert_eq!(cln(canonical), v);
        assert_eq!(cln(canonical).to_string(), canonical);
    }
}

#[test]
fn cln_identity_is_the_canonical_form() {
    assert_eq!(Calver.same_identity("v24.11", "24.11.0"), Some(true));
    assert_eq!(Calver.same_identity("24.11", "24.11.1"), Some(false));
    assert_eq!(Calver.same_identity("26.06rc2", "26.06"), Some(false));
    assert_eq!(Calver.same_identity("v0.10.2", "0.10.2"), Some(true));
    assert_eq!(Calver.same_identity("24.13", "24.11"), None);
    assert_eq!(Calver.same_identity("24.11", "junk"), None);
    // A describe string is not a release: no identity answer, never "different".
    let a = "v24.11-12-gabc1234";
    assert_eq!(Calver.same_identity(a, a), None);
    assert_eq!(Calver.same_identity(a, "v24.11"), None);
    assert_eq!(Calver.same_identity("v24.11", a), None);
    assert_eq!(Calver.same_identity("v24.11", "v24.11-modded"), None);
    assert_eq!(
        Calver.same_identity("v24.08.2-modded", "24.08.2-modded"),
        None
    );
}

#[test]
fn cln_a_describe_or_modded_listed_version_is_never_a_miss() {
    // Installed v24.11 against a list that names a describe or modded build of
    // it: the scheme cannot say they differ, and the evaluator must not call
    // that a miss.
    for listed in ["v24.11-0-gabc1234", "v24.11-modded", "v24.11-5-gabc1234"] {
        let adv = git_advisory(json!([]), json!([listed]));
        let e = evaluate_entry(&Calver, &adv, 0, Some("v24.11"));
        assert_eq!(reason(&e), UnknownReason::UnreadableListedVersion,);
    }
    // A readable listed tag that differs is still a clean miss.
    let adv = git_advisory(json!([]), json!(["v24.11.1", "v25.02"]));
    assert_eq!(
        evaluate_entry(&Calver, &adv, 0, Some("v24.11")),
        VersionEvidence::OutOfRange
    );
}

#[test]
fn cln_precedence_equal_spelling_is_not_a_listed_hit() {
    // 24.11 and 24.11.0 are equal by order and (here) the same identity; a
    // release candidate never equals its final release in either respect.
    let v = cln("24.11");
    assert_eq!(Calver.same_version(&v, "24.11.0"), Some(true));
    assert_eq!(Calver.same_version(&v, "24.11.1"), Some(false));
    assert_eq!(Calver.same_version(&v, "24.13"), None);
    assert_eq!(Calver.same_version(&v, "v24.11-3-gabcdef0"), None);
}

#[test]
fn cln_scheme_flags() {
    assert!(Calver.orders());
    assert!(!Calver.reads_semver_ranges());
}

// ------------------------------------------------- CLN: describe and modded

#[test]
fn cln_describe_forms_keep_every_field() {
    let d = Calver.parse_describe("v24.11-12-gabc1234-modded").unwrap();
    assert!(d.dirty);
    assert_eq!(
        d.commit,
        Some(Commit {
            distance: "12".into(),
            hash: "abc1234".into()
        })
    );
    assert_eq!(d.tag, cln("v24.11"));

    let d = Calver.parse_describe("v24.08.2-modded").unwrap();
    assert!(d.dirty);
    assert_eq!(d.commit, None);
    assert_eq!(d.tag, cln("24.08.2"));

    let d = Calver.parse_describe("v24.11rc1-3-gabcd").unwrap();
    assert!(!d.dirty);
    assert_eq!(d.commit.unwrap().hash, "abcd");
    assert_eq!(d.tag, cln("24.11rc1"));

    let d = Calver.parse_describe("v26.06.9").unwrap();
    assert!(!d.dirty);
    assert_eq!(d.commit, None);

    // The generic dirty marker is read too.
    let d = Calver.parse_describe("26.06.9-dirty").unwrap();
    assert!(d.dirty);

    // Distance zero is kept as written; it is not a release.
    let d = Calver.parse_describe("v24.11-0-gabc1234").unwrap();
    assert_eq!(d.commit.unwrap().distance, "0");

    let d = Calver
        .parse_describe("v0.12.1-5-g0123456789abcdef")
        .unwrap();
    assert!(d.tag.is_legacy());
}

#[test]
fn cln_describe_hash_rules() {
    // 4 to 64 lowercase hex.
    assert!(Calver.parse_describe("v24.11-1-gabcd").is_ok());
    assert!(
        Calver
            .parse_describe(&format!("v24.11-1-g{}", "a".repeat(64)))
            .is_ok()
    );
    for bad in [
        "v24.11-1-gabc".to_string(),
        format!("v24.11-1-g{}", "a".repeat(65)),
        "v24.11-1-gABCDEF0".to_string(),
        "v24.11-1-gabcdefg".to_string(),
        "v24.11-1-g".to_string(),
        "v24.11-01-gabcdef0".to_string(),
        "v24.11--gabcdef0".to_string(),
        "v24.11-1-abcdef0".to_string(),
        "v24.11-x-gabcdef0".to_string(),
        "-1-gabcdef0".to_string(),
        "v24.13-1-gabcdef0".to_string(),
        "v24.11-1-gabcdef0-modded-modded".to_string(),
        "v24.11-1-gabcdef0-dirty-modded".to_string(),
    ] {
        assert!(Calver.parse_describe(&bad).is_err());
        assert!(Calver.candidate(&bad).is_err());
    }
}

#[test]
fn cln_parse_never_reads_a_describe_string_as_a_version() {
    // Boundaries and listed versions go through `parse`: a describe string is
    // not a release, so it can never become a range boundary.
    for s in [
        "v24.11-12-gabc1234",
        "v24.11-12-gabc1234-modded",
        "v24.08.2-modded",
    ] {
        assert_eq!(Calver.parse(s), Err(VersionError::Malformed));
    }
}

#[test]
fn cln_candidate_exact_between_or_nothing() {
    assert_eq!(
        Calver.candidate("v26.06.9").unwrap(),
        Candidate::Exact(cln("26.06.9"))
    );
    // A clean describe descends from its tag: an interval, never the tag itself.
    let between = Candidate::Between {
        low: cln("24.11"),
        high: None,
    };
    assert_eq!(Calver.candidate("v24.11-12-gabc1234").unwrap(), between);
    // Distance zero equals the tag only with a verified tag-to-commit mapping,
    // which does not exist here.
    assert_eq!(Calver.candidate("v24.11-0-gabc1234").unwrap(), between);
    // A modded or dirty build can say nothing.
    for dirty in [
        "v24.11-12-gabc1234-modded",
        "v24.08.2-modded",
        "v24.11-dirty",
        "v24.11-12-gabc1234-dirty",
    ] {
        assert_eq!(Calver.candidate(dirty), Err(VersionError::Malformed),);
    }
    assert!(Calver.candidate("v24.13-1-gabc1234").is_err());
}

// ------------------------------------------------ git-describe: the rules

#[test]
fn describe_tags_use_semver_order() {
    assert_eq!(order_tag("1.0.0-alpha.9", "1.0.0-alpha.10"), Ordering::Less);
    assert_eq!(order_tag("1.0.0-alpha.10", "1.0.0-beta"), Ordering::Less);
    assert_eq!(order_tag("1.0.0-beta", "1.0.0"), Ordering::Less);
    assert_eq!(order_tag("1.0.0-alpha", "1.0.0-alpha.1"), Ordering::Less);
    assert_eq!(
        order_tag("1.0.0-alpha.1", "1.0.0-alpha.beta"),
        Ordering::Less
    );
    assert_eq!(order_tag("1.0.0-beta.2", "1.0.0-beta.11"), Ordering::Less);
    assert_eq!(order_tag("1.0.0-rc.1", "1.0.0"), Ordering::Less);
    assert_eq!(order_tag("1.1.2", "1.1.3"), Ordering::Less);
    assert_eq!(order_tag("1.9.0", "1.10.0"), Ordering::Less);
    assert_eq!(order_tag("1.0.0+a", "1.0.0+b"), Ordering::Equal);
    assert_eq!(order_tag("1.0.0+a", "1.0.0"), Ordering::Equal);
    assert_eq!(
        order_tag("18446744073709551615.0.0", "18446744073709551616.0.0"),
        Ordering::Less
    );
    // Numeric identifiers sit below text ones.
    assert_eq!(order_tag("1.0.0-1", "1.0.0-a"), Ordering::Less);
    assert_eq!(order_tag("1.0.0-9", "1.0.0-10"), Ordering::Less);
}

#[test]
fn describe_tag_precedence_is_not_identity() {
    assert_eq!(GitDescribe.same_identity("1.0.0+a", "1.0.0+b"), Some(false));
    assert_eq!(GitDescribe.same_identity("1.0.0+a", "1.0.0+a"), Some(true));
    assert_eq!(GitDescribe.same_identity("1.1.2", "1.1.2"), Some(true));
    assert_eq!(GitDescribe.same_identity("1.1.2", "1.1.3"), Some(false));
    assert_eq!(GitDescribe.same_identity("1.1.2", "junk"), None);
    assert_eq!(GitDescribe.same_identity("v1.1.2", "1.1.2"), None);
}

#[test]
fn describe_tag_refuses_what_semver_refuses() {
    for bad in [
        "",
        "1",
        "1.2",
        "1.02.3",
        "01.2.3",
        "1.2.03",
        "1.2.3.4",
        "v1.1.2",
        "1.0.0-",
        "1.0.0-01",
        "1.0.0-a..b",
        "1.0.0-.a",
        "1.0.0-a.",
        "1.0.0+",
        "1.0.0+a..b",
        "1.0.0 ",
        " 1.0.0",
        "1.0.0-é",
        "１.0.0",
        "1.0.0-a_b",
        "1.0.0++a",
    ] {
        assert_eq!(GitDescribe.parse(bad), Err(VersionError::Malformed),);
    }
    // Numeric prerelease identifiers forbid leading zeros; build metadata allows them.
    assert!(GitDescribe.parse("1.0.0+001").is_ok());
    assert!(GitDescribe.parse("1.0.0-0").is_ok());
    let long = format!("1.0.0-{}", "a".repeat(300));
    assert_eq!(GitDescribe.parse(&long), Err(VersionError::TooLong));
    let many = format!("1.0.0-{}", vec!["a"; 70].join("."));
    assert_eq!(GitDescribe.parse(&many), Err(VersionError::TooLong));
}

#[test]
fn describe_strict_parse_never_reads_a_description_as_a_tag() {
    // The hazard: `-148-g4cd3cf6` is a valid SemVer prerelease. It must never be
    // read as one.
    for s in [
        "1.1.2-148-g4cd3cf6",
        "1.1.2-148-g4cd3cf6-dirty",
        "1.1.2-dirty",
        "1.1.2-0-g4cd3cf6",
        "1.1.2-148-g4cd3cf6-modded",
        "1.2.0-rc.1-5-gabcdef0",
        // Looks like a description but its hash is not valid: still refused.
        "1.1.2-148-g4CD3CF6",
        "1.1.2-148-gxyz",
        "1.1.2-148-g4cd",
        "1.1.2-148-g",
        "1.1.2-007-g4cd3cf6",
    ] {
        assert_eq!(GitDescribe.parse(s), Err(VersionError::Malformed));
    }
    // A plain prerelease tag is still a tag.
    assert!(GitDescribe.parse("1.2.0-rc.1").is_ok());
    assert!(GitDescribe.parse("1.2.0-gabcd").is_ok());
}

#[test]
fn describe_parse_from_the_right() {
    let d = GitDescribe.parse_describe("1.1.2-148-g4cd3cf6").unwrap();
    assert_eq!(d.tag, tag("1.1.2"));
    assert_eq!(
        d.commit,
        Some(Commit {
            distance: "148".into(),
            hash: "4cd3cf6".into()
        })
    );
    assert!(!d.dirty);

    let d = GitDescribe
        .parse_describe("1.1.2-148-g4cd3cf6-dirty")
        .unwrap();
    assert!(d.dirty);
    assert_eq!(d.commit.unwrap().distance, "148");

    // Bare tag and dirty tag are accepted.
    let d = GitDescribe.parse_describe("1.1.2").unwrap();
    assert_eq!((d.commit, d.dirty), (None, false));
    let d = GitDescribe.parse_describe("1.1.2-dirty").unwrap();
    assert_eq!((d.commit, d.dirty), (None, true));

    // The tag may itself hold hyphens; only the right-hand part is the suffix.
    let d = GitDescribe.parse_describe("1.2.0-rc.1-5-gabcdef0").unwrap();
    assert_eq!(d.tag, tag("1.2.0-rc.1"));
    assert_eq!(d.commit.unwrap().distance, "5");
    let d = GitDescribe
        .parse_describe("1.2.0-beta-12-g0123abcd-dirty")
        .unwrap();
    assert_eq!(d.tag, tag("1.2.0-beta"));
    assert!(d.dirty);

    // `-modded` is CLN's marker, not strfry's.
    assert!(
        GitDescribe
            .parse_describe("1.1.2-148-g4cd3cf6-modded")
            .is_err()
    );
    // An unreadable tag or hash is an error, never a guess.
    let long_hash = format!("1.1.2-148-g{}", "a".repeat(65));
    for bad in [
        "v1.1.2-148-g4cd3cf6",
        "1.1-148-g4cd3cf6",
        "1.1.2-148-g4CD3CF6",
        "1.1.2-148-gabc",
        long_hash.as_str(),
        "-148-g4cd3cf6",
        "1.1.2-148-g4cd3cf6-dirty-dirty",
        "",
    ] {
        assert!(GitDescribe.parse_describe(bad).is_err());
    }
    assert!(
        GitDescribe
            .parse_describe(&format!("1.1.2-148-g{}", "a".repeat(64)))
            .is_ok()
    );
}

#[test]
fn describe_candidate_is_an_interval_or_nothing() {
    let between = |t: &str| Candidate::Between {
        low: tag(t),
        high: None,
    };
    assert_eq!(
        GitDescribe.candidate("1.1.2-148-g4cd3cf6").unwrap(),
        between("1.1.2")
    );
    // Distance zero equals its tag only with a verified mapping, which is
    // not available; a bare tag carries no commit at all.
    assert_eq!(
        GitDescribe.candidate("1.1.2-0-g4cd3cf6").unwrap(),
        between("1.1.2")
    );
    assert_eq!(GitDescribe.candidate("1.1.2").unwrap(), between("1.1.2"));
    assert_eq!(
        GitDescribe.candidate("1.2.0-rc.1-5-gabcdef0").unwrap(),
        between("1.2.0-rc.1")
    );
    // Dirty builds and unreadable tags never supply an interval.
    for bad in [
        "1.1.2-148-g4cd3cf6-dirty",
        "1.1.2-dirty",
        "v1.1.2-148-g4cd3cf6",
        "1.1-148-g4cd3cf6",
        "1.1.2-148-g4CD3CF6",
        "garbage",
        "",
    ] {
        assert_eq!(GitDescribe.candidate(bad), Err(VersionError::Malformed),);
    }
    assert_eq!(
        GitDescribe
            .candidate(&format!("1.1.2-148-g4cd3cf6{}", "x".repeat(300)))
            .unwrap_err(),
        VersionError::TooLong
    );
}

#[test]
fn describe_identity_keeps_every_field() {
    let a = "1.1.2-148-g4cd3cf6";
    assert_eq!(GitDescribe.same_identity(a, a), Some(true));
    assert_eq!(
        GitDescribe.same_identity(a, "1.1.2-148-g4cd3cf7"),
        Some(false)
    );
    assert_eq!(
        GitDescribe.same_identity(a, "1.1.2-149-g4cd3cf6"),
        Some(false)
    );
    assert_eq!(GitDescribe.same_identity(a, "1.1.2"), Some(false));
    assert_eq!(
        GitDescribe.same_identity(a, "1.1.2-148-g4cd3cf6-dirty"),
        Some(false)
    );
    assert_eq!(
        GitDescribe.same_identity(a, "1.1.3-148-g4cd3cf6"),
        Some(false)
    );
    assert_eq!(GitDescribe.same_identity(a, "nope"), None);
    assert_eq!(
        GitDescribe.same_identity("1.1.2-dirty", "1.1.2-dirty"),
        Some(true)
    );
}

#[test]
fn describe_scheme_flags() {
    assert!(GitDescribe.orders());
    assert!(!GitDescribe.reads_semver_ranges());
}

// ------------------------------------------------ describe through ranges

fn describe_ev(events: &str, installed: &str) -> VersionEvidence {
    let ev: Value = serde_json::from_str(events).unwrap();
    let adv = git_advisory(json!([eco(ev)]), json!([]));
    evaluate_entry(&GitDescribe, &adv, 0, Some(installed))
}

const FIXTURE_STRFRY: &str = "1.1.2-148-g4cd3cf6";

#[test]
fn describe_interval_proof_clears_only_when_the_whole_interval_misses() {
    // Fixed at the tag, nothing introduced later: [1.1.2, inf) is outside.
    let r = r#"[{"introduced":"0"},{"fixed":"1.1.2"}]"#;
    assert_eq!(describe_ev(r, FIXTURE_STRFRY), VersionEvidence::OutOfRange);
    let r = r#"[{"introduced":"0"},{"fixed":"1.0.4"}]"#;
    assert_eq!(describe_ev(r, FIXTURE_STRFRY), VersionEvidence::OutOfRange);
    let r = r#"[{"introduced":"1.0.0"},{"last_affected":"1.1.1"}]"#;
    assert_eq!(describe_ev(r, FIXTURE_STRFRY), VersionEvidence::OutOfRange);
}

#[test]
fn describe_is_neither_its_tag_nor_proved_below_the_next_release() {
    // fixed 1.1.3: the build may be before or after it.
    let r = r#"[{"introduced":"0"},{"fixed":"1.1.3"}]"#;
    let e = describe_ev(r, FIXTURE_STRFRY);
    assert_eq!(reason(&e), UnknownReason::CandidateIsAnInterval);
    // The tag itself would be in range (1.1.2 < 1.1.3), but the build is not
    // proved to be the tag: still unknown, never in range.
    assert_eq!(kind(&e), "unknown");
    // introduced at the tag: unknown, never in range or out.
    let r = r#"[{"introduced":"1.1.2"},{"fixed":"1.1.3"}]"#;
    assert_eq!(kind(&describe_ev(r, FIXTURE_STRFRY)), "unknown");
    // A later introduction opens inside the interval.
    let r = r#"[{"introduced":"1.2.0"},{"fixed":"1.3.0"}]"#;
    assert_eq!(
        reason(&describe_ev(r, FIXTURE_STRFRY)),
        UnknownReason::CandidateIsAnInterval
    );
    // One range proving the interval is out does not hide another that does not.
    let adv = git_advisory(
        json!([
            eco(json!([{"introduced": "0"}, {"fixed": "1.1.2"}])),
            eco(json!([{"introduced": "1.5.0"}]))
        ]),
        json!([]),
    );
    let e = evaluate_entry(&GitDescribe, &adv, 0, Some(FIXTURE_STRFRY));
    assert_eq!(reason(&e), UnknownReason::CandidateIsAnInterval);
}

#[test]
fn describe_dirty_or_unreadable_never_clears() {
    let r = r#"[{"introduced":"0"},{"fixed":"1.0.4"}]"#;
    for installed in [
        "1.1.2-148-g4cd3cf6-dirty",
        "1.1.2-dirty",
        "v1.1.2-148-g4cd3cf6",
        "1.1.2-148-g4CD3CF6",
        "not a version",
    ] {
        let e = describe_ev(r, installed);
        assert_eq!(reason(&e), UnknownReason::InstalledVersionUnparseable,);
    }
    let adv = git_advisory(
        json!([eco(json!([{"introduced": "0"}, {"fixed": "1.0.4"}]))]),
        json!([]),
    );
    assert_eq!(
        reason(&evaluate_entry(&GitDescribe, &adv, 0, None)),
        UnknownReason::InstalledVersionUnknown
    );
}

#[test]
fn describe_list_and_git_range_paths() {
    // A GIT range is unknown whatever the scheme: no commit graph.
    let adv = git_advisory(
        json!([{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "0123456789abcdef0123456789abcdef01234567"}]}]),
        json!([]),
    );
    assert_eq!(
        reason(&evaluate_entry(&GitDescribe, &adv, 0, Some(FIXTURE_STRFRY))),
        UnknownReason::NoCommitGraph
    );
    // A listed tag inside the installed build's interval is not a hit and not a miss.
    let adv = git_advisory(json!([]), json!(["1.1.2", "1.0.3"]));
    assert_eq!(
        reason(&evaluate_entry(&GitDescribe, &adv, 0, Some(FIXTURE_STRFRY))),
        UnknownReason::CandidateIsAnInterval
    );
    // A list entirely below the tag is a complete miss for this build.
    let adv = git_advisory(json!([]), json!(["1.0.3", "1.0.4"]));
    assert_eq!(
        evaluate_entry(&GitDescribe, &adv, 0, Some(FIXTURE_STRFRY)),
        VersionEvidence::OutOfRange
    );
    // A listed describe string is not a release the evaluator can place against
    // an interval: unreadable, so unknown, never a hit or a miss.
    let adv = git_advisory(json!([]), json!([FIXTURE_STRFRY]));
    assert_eq!(
        reason(&evaluate_entry(&GitDescribe, &adv, 0, Some(FIXTURE_STRFRY))),
        UnknownReason::UnreadableListedVersion
    );
    // A SEMVER range on this scheme is a scheme mismatch, never a SemVer fallback.
    let adv = git_advisory(
        json!([{"type": "SEMVER", "events": [{"introduced": "1.1.2"}, {"fixed": "1.1.3"}]}]),
        json!([]),
    );
    assert_eq!(
        reason(&evaluate_entry(&GitDescribe, &adv, 0, Some(FIXTURE_STRFRY))),
        UnknownReason::SchemeMismatch
    );
}

// ---------------------------------------- CLN and describe through ranges

fn cln_ev(events: &str, installed: &str) -> VersionEvidence {
    let ev: Value = serde_json::from_str(events).unwrap();
    let adv = git_advisory(json!([eco(ev)]), json!([]));
    evaluate_entry(&Calver, &adv, 0, Some(installed))
}

#[test]
fn cln_ranges_use_calendar_and_legacy_order() {
    let r = r#"[{"introduced":"0"},{"fixed":"26.06.8"}]"#;
    for inside in [
        "v0.12.1",
        "25.09",
        "26.06",
        "26.06rc3",
        "26.06.7",
        "v26.06.7rc1",
        "26.06.8rc2",
    ] {
        assert_eq!(kind(&cln_ev(r, inside)), "in-range");
    }
    for outside in ["26.06.8", "26.06.9", "26.09", "v27.01", "26.06.10"] {
        assert_eq!(kind(&cln_ev(r, outside)), "out-of-range");
    }
    // A described build is an interval, which only settles when nothing can open
    // or stay open above its tag.
    assert_eq!(kind(&cln_ev(r, "v26.06.9-3-gabcdef0")), "out-of-range");
    assert_eq!(kind(&cln_ev(r, "v25.09-3-gabcdef0")), "unknown");
    // Modded and dirty builds are never cleared.
    assert_eq!(
        reason(&cln_ev(r, "v26.06.9-modded")),
        UnknownReason::InstalledVersionUnparseable
    );
    // Legacy boundaries read in the same scheme.
    let r = r#"[{"introduced":"0.10.0"},{"fixed":"0.12.0"}]"#;
    assert_eq!(kind(&cln_ev(r, "v0.10.2")), "in-range");
    assert_eq!(kind(&cln_ev(r, "v0.12.1")), "out-of-range");
    assert_eq!(kind(&cln_ev(r, "v22.11")), "out-of-range");
    assert_eq!(kind(&cln_ev(r, "v0.9.5")), "out-of-range");
    // A boundary that is a describe string is not a release: unreadable, unknown.
    let r = r#"[{"introduced":"0"},{"fixed":"v26.06.8-3-gabcdef0"}]"#;
    assert_eq!(
        reason(&cln_ev(r, "26.06.9")),
        UnknownReason::UnparseableBoundary
    );
}

// ----------------------------------- corpus endpoints and fixture versions

#[test]
fn every_corpus_endpoint_for_cln_and_strfry_parses_in_its_scheme() {
    let cln_values = corpus_values_for("ElementsProject/lightning");
    assert!(cln_values.contains(&"26.06.8".to_string()));
    let mut parsed = 0;
    for (i, v) in cln_values.iter().enumerate() {
        if v == "0" || v == "*" {
            continue;
        }
        assert!(Calver.parse(v).is_ok(), "cln corpus value {i}");
        parsed += 1;
    }
    assert!(parsed >= 1);
    // The corpus has no strfry record (no advisories exist for it); the
    // describe scheme is exercised on synthetic records only.
    assert!(corpus_values_for("hoytech/strfry").is_empty());
}

#[test]
fn every_fixture_and_catalog_version_for_cln_and_strfry_parses() {
    for setup in ["lab-old-synthetic", "lab-regtest"] {
        let v = service_version(setup, "core-lightning");
        assert!(Calver.parse(&v).is_ok(), "cln fixture version in {setup}");
        assert!(Calver.candidate(&v).unwrap() == Candidate::Exact(cln(&v)));
    }
    let v = service_version("lab-regtest", "strfry");
    assert!(v == FIXTURE_STRFRY, "strfry fixture version");
    assert!(GitDescribe.parse_describe(&v).is_ok());
    assert!(GitDescribe.candidate(&v).is_ok());
    // The old synthetic setup runs no strfry.
    assert!(!fixture_rows().iter().any(|r| r.table == "setup.service"
        && r.setup == "lab-old-synthetic"
        && r.fields.get("id").map(String::as_str) == Some("strfry")));

    let examples = catalog_examples("core-lightning");
    assert!(!examples.is_empty());
    for (i, (raw, version)) in examples.iter().enumerate() {
        assert!(Calver.parse(raw).is_ok(), "cln catalog example {i} raw");
        assert!(
            Calver.parse(version).is_ok(),
            "cln catalog example {i} version"
        );
    }
    let examples = catalog_examples("strfry");
    assert!(!examples.is_empty());
    for (i, (raw, version)) in examples.iter().enumerate() {
        assert!(
            GitDescribe.parse_describe(raw).is_ok(),
            "strfry catalog example {i} raw"
        );
        assert!(
            GitDescribe.parse_describe(version).is_ok(),
            "strfry catalog example {i} version"
        );
    }
}

#[test]
fn cln_fixture_pairs_give_the_version_subresult_the_fixture_states() {
    let advisory = "x_cln-2026-v26.06.8-unspecified-vulnerabilities";
    let (adv, _) = corpus_record(advisory);
    assert_eq!(adv.affected.len(), 1);
    for (setup, installed_is) in [("lab-old-synthetic", "25.09"), ("lab-regtest", "26.06.9")] {
        let installed = service_version(setup, "core-lightning");
        assert!(installed == installed_is, "cln fixture version {setup}");
        let got = evaluate_entry(&Calver, &adv, 0, Some(&installed));
        let expected = expected_version(setup, advisory);
        assert!(kind(&got) == expected, "cln fixture subresult {setup}");
        // The same version spelled as the lab reports it (with `v`).
        let got = evaluate_entry(&Calver, &adv, 0, Some(&format!("v{installed}")));
        assert!(
            kind(&got) == expected,
            "cln fixture subresult {setup} with v"
        );
    }
    // The in-range answer is decided by the `fixed` event of the one range.
    assert_eq!(
        evaluate_entry(&Calver, &adv, 0, Some("25.09")),
        VersionEvidence::InRange(gd_advisories::Location {
            entry: 0,
            place: Place::Range {
                range: 0,
                event: Some(0)
            }
        })
    );
}

// ------------------------------------------------------------- properties

const SEED: u64 = 0x0000_0000_2026_1117;

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 1024,
        failure_persistence: None,
        rng_algorithm: proptest::test_runner::RngAlgorithm::ChaCha,
        rng_seed: proptest::test_runner::RngSeed::Fixed(SEED),
        ..ProptestConfig::default()
    }
}

/// A CLN version as numbers, with a spelling; the model orders the numbers.
#[derive(Clone, Debug)]
struct ClnSpec {
    legacy: bool,
    a: u32,
    b: u32,
    c: u32,
    patch_written: bool,
    rc: Option<u32>,
    v: bool,
}

impl ClnSpec {
    fn text(&self) -> String {
        let v = if self.v { "v" } else { "" };
        let rc = self.rc.map_or(String::new(), |n| format!("rc{n}"));
        if self.legacy {
            format!("{v}0.{}.{}{rc}", self.a, self.b)
        } else if self.patch_written {
            format!("{v}{:02}.{:02}.{}{rc}", self.a, self.b, self.c)
        } else {
            format!("{v}{:02}.{:02}{rc}", self.a, self.b)
        }
    }

    /// The independent model: (era, a, b, patch, rc rank).
    fn key(&self) -> (u8, u32, u32, u32, (u8, u32)) {
        let c = if self.legacy || !self.patch_written {
            0
        } else {
            self.c
        };
        (
            u8::from(!self.legacy),
            self.a,
            self.b,
            c,
            self.rc.map_or((1, 0), |n| (0, n)),
        )
    }
}

fn cln_spec() -> impl Strategy<Value = ClnSpec> {
    (
        any::<bool>(),
        0u32..100,
        1u32..13,
        0u32..40,
        any::<bool>(),
        proptest::option::of(0u32..30),
        any::<bool>(),
        0u32..40,
        0u32..40,
    )
        .prop_map(|(legacy, yy, mm, c, patch_written, rc, v, lx, ly)| {
            if legacy {
                ClnSpec {
                    legacy: true,
                    a: lx,
                    b: ly,
                    c: 0,
                    patch_written: true,
                    rc,
                    v,
                }
            } else {
                ClnSpec {
                    legacy: false,
                    a: yy,
                    b: mm,
                    c,
                    patch_written,
                    rc,
                    v,
                }
            }
        })
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn cln_order_follows_the_model(a in cln_spec(), b in cln_spec()) {
        let (ta, tb) = (a.text(), b.text());
        let (pa, pb) = (Calver.parse(&ta).unwrap(), Calver.parse(&tb).unwrap());
        prop_assert_eq!(pa.cmp(&pb), a.key().cmp(&b.key()));
        prop_assert_eq!(pa == pb, a.key() == b.key());
    }

    #[test]
    fn cln_order_laws(a in cln_spec(), b in cln_spec(), c in cln_spec()) {
        let (a, b, c) = (
            Calver.parse(&a.text()).unwrap(),
            Calver.parse(&b.text()).unwrap(),
            Calver.parse(&c.text()).unwrap(),
        );
        // Reflexivity and trichotomy.
        prop_assert_eq!(a.cmp(&a), Ordering::Equal);
        let n = [a.cmp(&b) == Ordering::Less, a.cmp(&b) == Ordering::Equal, a.cmp(&b) == Ordering::Greater];
        prop_assert_eq!(n.iter().filter(|x| **x).count(), 1);
        // Antisymmetry.
        prop_assert_eq!(a.cmp(&b), b.cmp(&a).reverse());
        // Transitivity.
        if a <= b && b <= c {
            prop_assert!(a <= c);
        }
        // `Eq` agrees with the order.
        prop_assert_eq!(a == b, a.cmp(&b) == Ordering::Equal);
    }

    #[test]
    fn cln_normalization_is_idempotent_and_round_trips(a in cln_spec()) {
        let v = Calver.parse(&a.text()).unwrap();
        let canonical = v.to_string();
        let again = Calver.parse(&canonical).unwrap();
        prop_assert_eq!(&again, &v);
        prop_assert_eq!(again.to_string(), canonical.clone());
        // Identity of every spelling of one release is the canonical form.
        prop_assert_eq!(Calver.same_identity(&a.text(), &canonical), Some(true));
    }

    #[test]
    fn cln_describe_suffix_is_kept_and_never_a_version(a in cln_spec(), dist in 0u32..100_000, hash in "[0-9a-f]{4,64}", dirty in any::<bool>()) {
        let tag_text = a.text();
        let s = format!("{tag_text}-{dist}-g{hash}{}", if dirty { "-modded" } else { "" });
        prop_assert!(Calver.parse(&s).is_err());
        let d = Calver.parse_describe(&s).unwrap();
        prop_assert_eq!(d.dirty, dirty);
        prop_assert_eq!(&d.tag, &Calver.parse(&tag_text).unwrap());
        let c = d.commit.unwrap();
        prop_assert_eq!(c.distance, dist.to_string());
        prop_assert_eq!(c.hash, hash);
        let cand = Calver.candidate(&s);
        if dirty {
            prop_assert!(cand.is_err());
        } else {
            prop_assert_eq!(cand.unwrap(), Candidate::Between { low: d.tag, high: None });
        }
    }

    #[test]
    fn cln_parse_never_panics_and_failures_are_errors(s in "\\PC{0,40}") {
        let _ = Calver.parse(&s);
        let _ = Calver.candidate(&s);
        let _ = Calver.parse_describe(&s);
    }
}

/// A SemVer tag as numbers and identifiers, for the describe scheme's tags.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Ident {
    Num(u32),
    Text(String),
}

#[derive(Clone, Debug)]
struct TagSpec {
    nums: (u32, u32, u32),
    pre: Option<Vec<Ident>>,
    meta: Option<String>,
}

impl TagSpec {
    fn text(&self) -> String {
        let mut s = format!("{}.{}.{}", self.nums.0, self.nums.1, self.nums.2);
        if let Some(pre) = &self.pre {
            let ids: Vec<String> = pre
                .iter()
                .map(|i| match i {
                    Ident::Num(n) => n.to_string(),
                    Ident::Text(t) => t.clone(),
                })
                .collect();
            s.push('-');
            s.push_str(&ids.join("."));
        }
        if let Some(m) = &self.meta {
            s.push('+');
            s.push_str(m);
        }
        s
    }

    /// Model: pre-release `None` is above every list; metadata is ignored.
    fn key(&self) -> ((u32, u32, u32), (bool, Vec<Ident>)) {
        (
            self.nums,
            match &self.pre {
                None => (true, Vec::new()),
                Some(p) => (false, p.clone()),
            },
        )
    }
}

fn tag_spec() -> impl Strategy<Value = TagSpec> {
    (
        (0u32..12, 0u32..12, 0u32..12),
        proptest::option::of(proptest::collection::vec(
            prop_oneof![
                (0u32..30).prop_map(Ident::Num),
                "[a-z][a-z0-9-]{0,5}".prop_map(Ident::Text)
            ],
            1..4,
        )),
        proptest::option::of("[0-9a-z]{1,4}"),
    )
        .prop_map(|(nums, pre, meta)| TagSpec { nums, pre, meta })
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn describe_tag_order_follows_the_model(a in tag_spec(), b in tag_spec()) {
        let (ta, tb) = (a.text(), b.text());
        // A generated hyphenated identifier can look like a description; skip those.
        prop_assume!(GitDescribe.parse(&ta).is_ok() && GitDescribe.parse(&tb).is_ok());
        let (pa, pb) = (tag(&ta), tag(&tb));
        prop_assert_eq!(pa.cmp(&pb), a.key().cmp(&b.key()));
        prop_assert_eq!(pa == pb, a.key() == b.key());
        prop_assert_eq!(pa.cmp(&pb), pb.cmp(&pa).reverse());
    }

    #[test]
    fn describe_tag_round_trips(a in tag_spec()) {
        let t = a.text();
        prop_assume!(GitDescribe.parse(&t).is_ok());
        let v = tag(&t);
        let shown = v.to_string();
        prop_assert_eq!(tag(&shown), v.clone());
        prop_assert_eq!(tag(&shown).to_string(), shown.clone());
        prop_assert_eq!(GitDescribe.same_identity(&t, &shown), Some(true));
    }

    #[test]
    fn describe_suffix_never_becomes_a_prerelease(a in tag_spec(), dist in 0u32..100_000, hash in "[0-9a-f]{4,64}", dirty in any::<bool>()) {
        let t = a.text();
        prop_assume!(GitDescribe.parse(&t).is_ok());
        let s = format!("{t}-{dist}-g{hash}{}", if dirty { "-dirty" } else { "" });
        prop_assert!(GitDescribe.parse(&s).is_err());
        let d = GitDescribe.parse_describe(&s).unwrap();
        prop_assert_eq!(d.dirty, dirty);
        prop_assert_eq!(d.tag, tag(&t));
        prop_assert_eq!(d.commit.unwrap().hash, hash);
        match GitDescribe.candidate(&s) {
            Ok(Candidate::Between { low, high: None }) => prop_assert!(!dirty && low == tag(&t)),
            other => prop_assert!(dirty && other.is_err()),
        }
    }

    #[test]
    fn describe_parse_never_panics(s in "\\PC{0,60}") {
        let _ = GitDescribe.parse(&s);
        let _ = GitDescribe.candidate(&s);
        let _ = GitDescribe.parse_describe(&s);
    }
}

// --------------------------------------------------------------- mutants
//
// Each mutant is a local test-only scheme with one fault. The same checks that
// the real scheme passes must fail for it.

/// "A describe string must never be read as a SemVer prerelease": the build
/// `1.1.2-148-g4cd3cf6` against a range that starts at its tag is unknown.
fn describe_check<S: VersionScheme>(scheme: &S) -> Result<(), String> {
    let adv = git_advisory(
        json!([eco(json!([{"introduced": "1.1.2"}, {"fixed": "1.1.3"}]))]),
        json!([]),
    );
    let e = evaluate_entry(scheme, &adv, 0, Some(FIXTURE_STRFRY));
    if !matches!(e, VersionEvidence::Unknown { .. }) {
        return Err(format!(
            "introduced at the tag: expected unknown, got {}",
            kind(&e)
        ));
    }
    let adv = git_advisory(
        json!([eco(json!([{"introduced": "0"}, {"fixed": "1.1.3"}]))]),
        json!([]),
    );
    let e = evaluate_entry(scheme, &adv, 0, Some(FIXTURE_STRFRY));
    if !matches!(e, VersionEvidence::Unknown { .. }) {
        return Err(format!(
            "fixed at 1.1.3: expected unknown, got {}",
            kind(&e)
        ));
    }
    Ok(())
}

/// The mutant: the string goes straight into a SemVer comparison, where
/// `148-g4cd3cf6` is a prerelease, so the build reads as below `1.1.2`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Sv {
    nums: [u64; 3],
    pre: Option<String>,
}
impl Ord for Sv {
    fn cmp(&self, o: &Self) -> Ordering {
        self.nums
            .cmp(&o.nums)
            .then_with(|| match (&self.pre, &o.pre) {
                (None, None) => Ordering::Equal,
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (Some(a), Some(b)) => a.cmp(b),
            })
    }
}
impl PartialOrd for Sv {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
struct DescribeAsSemver;
impl VersionScheme for DescribeAsSemver {
    type Version = Sv;
    fn parse(&self, raw: &str) -> Result<Sv, VersionError> {
        let (core, pre) = match raw.split_once('-') {
            Some((c, p)) => (c, Some(p.to_string())),
            None => (raw, None),
        };
        let mut it = core
            .split('.')
            .map(|p| p.parse::<u64>().map_err(|_| VersionError::Malformed));
        let nums = [
            it.next().ok_or(VersionError::Malformed)??,
            it.next().ok_or(VersionError::Malformed)??,
            it.next().ok_or(VersionError::Malformed)??,
        ];
        Ok(Sv { nums, pre })
    }
    fn same_identity(&self, a: &str, b: &str) -> Option<bool> {
        Some(a == b)
    }
    fn reads_semver_ranges(&self) -> bool {
        true
    }
    fn orders(&self) -> bool {
        true
    }
}

#[test]
fn mutant_describe_as_semver_is_caught() {
    assert_eq!(describe_check(&GitDescribe), Ok(()));
    let err = describe_check(&DescribeAsSemver).unwrap_err();
    assert!(err.contains("expected unknown"), "{err}");
}

/// The legacy-ordering checks: the design's chain, numeric (not lexical) legacy
/// order, and legacy release candidates.
fn cln_legacy_check<S: VersionScheme>(scheme: &S) -> Result<(), String> {
    let lt = |a: &str, b: &str| -> Result<(), String> {
        let (pa, pb) = (
            scheme
                .parse(a)
                .map_err(|e| format!("a test input should parse: {e}"))?,
            scheme
                .parse(b)
                .map_err(|e| format!("a test input should parse: {e}"))?,
        );
        if pa < pb {
            Ok(())
        } else {
            Err("expected a strict ordering".to_string())
        }
    };
    lt("v0.10.2", "v0.12.1")?;
    lt("v0.12.1", "v22.11")?;
    lt("v0.9.0", "v0.10.2")?;
    lt("v0.11.0rc2", "v0.11.0")?;
    lt("v0.99.99", "00.01")
}

/// Mutant 1: legacy releases sort above calendar releases.
struct LegacyAbove;
#[derive(Clone, PartialEq, Eq)]
struct LegacyAboveV(ClnVersion);
impl Ord for LegacyAboveV {
    fn cmp(&self, o: &Self) -> Ordering {
        match (self.0.is_legacy(), o.0.is_legacy()) {
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            _ => self.0.cmp(&o.0),
        }
    }
}
impl PartialOrd for LegacyAboveV {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl VersionScheme for LegacyAbove {
    type Version = LegacyAboveV;
    fn parse(&self, raw: &str) -> Result<LegacyAboveV, VersionError> {
        Calver.parse(raw).map(LegacyAboveV)
    }
    fn same_identity(&self, a: &str, b: &str) -> Option<bool> {
        Calver.same_identity(a, b)
    }
    fn reads_semver_ranges(&self) -> bool {
        false
    }
    fn orders(&self) -> bool {
        true
    }
}

/// Mutant 2: versions compare as their canonical text (lexical).
struct Lexical;
#[derive(Clone, PartialEq, Eq)]
struct LexicalV(String);
impl Ord for LexicalV {
    fn cmp(&self, o: &Self) -> Ordering {
        self.0.cmp(&o.0)
    }
}
impl PartialOrd for LexicalV {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl VersionScheme for Lexical {
    type Version = LexicalV;
    fn parse(&self, raw: &str) -> Result<LexicalV, VersionError> {
        Calver.parse(raw).map(|v| LexicalV(v.to_string()))
    }
    fn same_identity(&self, a: &str, b: &str) -> Option<bool> {
        Calver.same_identity(a, b)
    }
    fn reads_semver_ranges(&self) -> bool {
        false
    }
    fn orders(&self) -> bool {
        true
    }
}

#[test]
fn mutant_cln_legacy_misordered_is_caught() {
    assert_eq!(cln_legacy_check(&Calver), Ok(()));
    let err = cln_legacy_check(&LegacyAbove).unwrap_err();
    assert!(err.starts_with("expected"), "{err}");
    let err = cln_legacy_check(&Lexical).unwrap_err();
    assert!(err.starts_with("expected"), "{err}");
}

// ------------------------------------------------ fix round 1: describe tags

#[test]
fn describe_refuses_a_modded_marker_everywhere() {
    // `-modded` is CLN's marker. strfry's reader must not read it as a SemVer
    // prerelease named `modded`.
    for s in [
        "1.1.2-modded",
        "1.1.2-148-g4cd3cf6-modded",
        "1.2.0-rc.1-modded",
    ] {
        assert!(GitDescribe.parse(s).is_err(), "parse {s}");
        assert!(GitDescribe.parse_describe(s).is_err(), "parse_describe {s}");
        assert!(GitDescribe.candidate(s).is_err(), "candidate {s}");
        assert_eq!(GitDescribe.same_identity(s, s), None, "identity {s}");
    }
    // The dirty marker keeps its own spelling in identity: a dirty build is
    // neither the clean build nor a modded one.
    let a = "1.1.2-148-g4cd3cf6";
    assert_eq!(
        GitDescribe.same_identity(a, "1.1.2-148-g4cd3cf6-dirty"),
        Some(false)
    );
    assert_eq!(
        GitDescribe.same_identity("1.1.2-148-g4cd3cf6-dirty", "1.1.2-148-g4cd3cf6-dirty"),
        Some(true)
    );
}

#[test]
fn describe_tags_are_read_by_the_semver_scheme() {
    for s in ["1.1.2", "1.2.0-rc.1", "1.0.0+a", "1.0.0-alpha.1+b.2"] {
        let via_describe = GitDescribe.parse(s).unwrap();
        let via_semver = SemVer.parse(s).unwrap();
        // Same type, same order, and the identity is the raw spelling.
        assert_eq!(via_describe.cmp(&via_semver), Ordering::Equal);
        assert_eq!(via_describe.identity(), s);
        assert_eq!(via_describe.raw(), s);
    }
    // What SemVer refuses, the tag reader refuses (leading zeros, a `v`).
    for s in ["1.01.2", "v1.1.2", "1.1", "1.1.2.3"] {
        assert!(GitDescribe.parse(s).is_err());
        assert!(SemVer.parse(s).is_err());
    }
}

#[test]
fn cln_a_modded_value_through_the_evaluator_is_never_out_of_range() {
    for installed in [
        "24.11-modded",
        "v24.11-modded",
        "v24.11-12-gabc1234-modded",
        "24.11.0-modded",
    ] {
        for r in [
            r#"[{"introduced":"0"},{"fixed":"24.11"}]"#,
            r#"[{"introduced":"0"},{"fixed":"25.02"}]"#,
            r#"[{"introduced":"24.11"},{"fixed":"25.02"}]"#,
        ] {
            let e = cln_ev(r, installed);
            assert_eq!(reason(&e), UnknownReason::InstalledVersionUnparseable,);
            assert_ne!(kind(&e), "out-of-range");
        }
    }
}

#[test]
fn describe_refuses_the_broken_marker_and_markers_on_either_side_of_metadata() {
    for s in [
        "2.0.0-broken",
        "1.1.2-148-g4cd3cf6-broken",
        "1.1.2-modded+meta",
        "1.1.2-dirty+meta",
        "1.1.2-broken+meta",
        "1.1.2+meta-broken",
        "1.1.2+meta-modded",
        "2.0.0+vendor-broken",
        "1.2.0-rc.1-broken",
        "1.1.2-dirty-dirty",
    ] {
        assert!(GitDescribe.parse(s).is_err(), "parse {s}");
        assert!(GitDescribe.parse_describe(s).is_err(), "parse_describe {s}");
        assert!(GitDescribe.candidate(s).is_err(), "candidate {s}");
        assert_eq!(GitDescribe.same_identity(s, s), None, "identity {s}");
    }
    // As a boundary.
    assert_eq!(
        reason(&describe_ev(
            r#"[{"introduced":"0"},{"fixed":"2.0.0-broken"}]"#,
            "2.0.0"
        )),
        UnknownReason::UnparseableBoundary
    );
    assert_eq!(
        reason(&describe_ev(
            r#"[{"introduced":"0"},{"last_affected":"2.0.0-broken"}]"#,
            "2.0.0"
        )),
        UnknownReason::UnparseableBoundary
    );
    assert_eq!(
        reason(&describe_ev(
            r#"[{"introduced":"0"},{"limit":"2.0.0-broken"}]"#,
            "2.0.0"
        )),
        UnknownReason::UnparseableLimit
    );
    // As a list entry.
    let adv = git_advisory(json!([]), json!(["2.0.0-broken"]));
    assert_eq!(
        reason(&evaluate_entry(&GitDescribe, &adv, 0, Some("2.0.0"))),
        UnknownReason::UnreadableListedVersion
    );
    // Markers after build metadata: boundary and list entry.
    for s in [
        "1.1.2+meta-broken",
        "1.1.2+meta-modded",
        "2.0.0+vendor-broken",
    ] {
        let events = format!(r#"[{{"introduced":"0"}},{{"fixed":"{s}"}}]"#);
        assert_eq!(
            reason(&describe_ev(&events, "2.0.0")),
            UnknownReason::UnparseableBoundary,
            "boundary {s}"
        );
        let adv = git_advisory(json!([]), json!([s]));
        assert_eq!(
            reason(&evaluate_entry(&GitDescribe, &adv, 0, Some("2.0.0"))),
            UnknownReason::UnreadableListedVersion,
            "listed {s}"
        );
    }
    // CLN.
    for s in ["24.11-broken", "v24.11-12-gabc1234-broken"] {
        assert!(Calver.parse(s).is_err(), "parse {s}");
        assert!(Calver.parse_describe(s).is_err(), "parse_describe {s}");
        assert!(Calver.candidate(s).is_err(), "candidate {s}");
        assert_eq!(
            reason(&cln_ev(r#"[{"introduced":"0"},{"fixed":"24.11"}]"#, s)),
            UnknownReason::InstalledVersionUnparseable,
        );
    }
    // Still accepted.
    for s in ["1.0.0+a", "1.0.0-alpha.1+b.2"] {
        assert!(GitDescribe.parse(s).is_ok());
    }
    let d = GitDescribe
        .parse_describe("1.1.2-148-g4cd3cf6-dirty")
        .unwrap();
    assert!(d.dirty);
}

#[test]
fn cln_legacy_four_part_and_two_part_tags_are_refused_not_cleared() {
    for s in ["v0.7.2.1", "0.7.2.1", "v0.6", "0.6"] {
        assert!(Calver.parse(s).is_err());
    }
    let adv = git_advisory(json!([]), json!(["v0.7.2.1"]));
    assert_eq!(
        reason(&evaluate_entry(&Calver, &adv, 0, Some("v0.7.2.1"))),
        UnknownReason::InstalledVersionUnparseable
    );
    assert_eq!(
        reason(&cln_ev(
            r#"[{"introduced":"0"},{"fixed":"0.7.2.1"}]"#,
            "v24.11"
        )),
        UnknownReason::UnparseableBoundary
    );
    assert_eq!(
        reason(&cln_ev(r#"[{"introduced":"0"},{"fixed":"24.11"}]"#, "v0.6")),
        UnknownReason::InstalledVersionUnparseable
    );
    let listed = git_advisory(json!([]), json!(["v0.7.2.1"]));
    assert_eq!(
        reason(&evaluate_entry(&Calver, &listed, 0, Some("v24.11"))),
        UnknownReason::UnreadableListedVersion
    );
}

#[test]
fn strfry_dirty_marker_inside_the_residual_tag_is_refused() {
    let r = r#"[{"introduced":"0"},{"fixed":"2.0.0"}]"#;
    for installed in [
        "2.0.0+vendor-dirty-1-gabcd",
        "2.0.0-dirty-1-gabcd",
        "2.0.0-rc1-dirty-1-gabcd",
    ] {
        assert!(
            reason(&describe_ev(r, installed)) == UnknownReason::InstalledVersionUnparseable,
            "strfry residual dirty marker, case {}",
            installed.len()
        );
    }
}

#[test]
fn strfry_nested_describe_fragment_in_the_residual_tag_is_refused() {
    let r = r#"[{"introduced":"0"},{"fixed":"2.0.0"}]"#;
    for installed in [
        "2.0.0+vendor-1-g-1-gabcd",
        "2.0.0-1-g-1-gabcd",
        "2.0.0-1-gabcd-1-gabcd",
        "2.0.0+vendor-1-gab.x-1-gabcd",
    ] {
        assert!(
            reason(&describe_ev(r, installed)) == UnknownReason::InstalledVersionUnparseable,
            "strfry nested describe fragment, case {}",
            installed.len()
        );
    }
}

#[test]
fn strfry_tag_budget_counts_the_whole_version() {
    let dots = |s: &str| vec![s; 33].join(".");
    let listed = format!("1.0.0-{}+{}", dots("a"), dots("b"));
    assert!(listed.len() <= 256);
    let adv = git_advisory(json!([]), json!([listed]));
    assert!(
        reason(&evaluate_entry(&GitDescribe, &adv, 0, Some("2.0.0")))
            == UnknownReason::UnreadableListedVersion
    );
    // Installed and boundary sides use the same budget.
    assert!(GitDescribe.parse(&listed).is_err());
    assert!(GitDescribe.parse_describe(&listed).is_err());
    let within = format!(
        "1.0.0-{}+{}",
        vec!["a"; 30].join("."),
        vec!["b"; 30].join(".")
    );
    assert!(GitDescribe.parse(&within).is_ok());
}
