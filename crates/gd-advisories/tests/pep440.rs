//! Phase 2.1, PR 3: PEP 440 ordering for Nutshell (`PyPI cashu`).
//!
//! Every rule and example of design 2.1 section 2 ("PyPI / PEP 440"), the
//! parser and the ordering against vectors recorded once from a pinned
//! `packaging` release (`tests/reference/gen_pep440.py`; the tests read only the
//! committed JSON), the ordering laws against an independent model, refused and
//! oversized input, the corpus endpoints and fixture versions for `cashu`, the
//! scheme wired through `evaluate_entry` with the fixture's expected version
//! results, and four local test-only mutants that must fail.

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
    Advisory, Candidate, Location, Pep440, Pep440Version, Place, Source, UnknownReason,
    VersionError, VersionEvidence, VersionScheme, evaluate_entry, parse_advisory,
    parse_advisory_from,
};
use proptest::prelude::*;
use serde_json::{Value, json};

// ---------------------------------------------------------------- helpers

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn p(s: &str) -> Pep440Version {
    Pep440
        .parse(s)
        .unwrap_or_else(|e| panic!("a test input should parse: {e}"))
}

fn order(a: &str, b: &str) -> Ordering {
    p(a).cmp(&p(b))
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

fn pypi_advisory(ranges: Value, versions: Value) -> Advisory {
    let mut e = json!({"package": {"ecosystem": "PyPI", "name": "cashu"}});
    if ranges.as_array().is_some_and(|r| !r.is_empty()) {
        e["ranges"] = ranges;
    }
    if versions.as_array().is_some_and(|r| !r.is_empty()) {
        e["versions"] = versions;
    }
    let record = json!({"id": "x_test-1", "modified": "2026-11-17T00:00:00Z", "affected": [e]});
    parse_advisory(record.to_string().as_bytes()).unwrap()
}

fn ev(events: &str, installed: &str) -> VersionEvidence {
    let events: Value = serde_json::from_str(events).unwrap();
    let adv = pypi_advisory(json!([{"type": "ECOSYSTEM", "events": events}]), json!([]));
    evaluate_entry(&Pep440, &adv, 0, Some(installed))
}

// ----------------------------------------------------- fixture and corpus

struct Row {
    table: String,
    setup: String,
    fields: HashMap<String, String>,
}

/// The `[[table]]` blocks of `fixtures/expected-matches.toml`, each with the id
/// of the `[[setup]]` it follows. Only `key = "string"` lines are read.
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

fn corpus_record(id: &str) -> Advisory {
    let bytes = fs::read(root().join(format!("advisories/corpus/{id}.json"))).unwrap();
    parse_advisory_from(&bytes, Source::GuardDogCorpus).unwrap()
}

// ------------------------------------------------------ the design rules

#[test]
fn design_examples_order_as_stated() {
    assert_eq!(order("1.0", "1.0.0"), Ordering::Equal);
    assert!(p("1.0") == p("1.0.0"));
    let chain = ["1.0.dev1", "1.0a1", "1.0b1", "1.0rc1", "1.0", "1.0.post1"];
    for w in chain.windows(2) {
        assert_eq!(order(w[0], w[1]), Ordering::Less);
        assert_eq!(order(w[1], w[0]), Ordering::Greater);
    }
    assert_eq!(order("1.0.post1.dev1", "1.0.post1"), Ordering::Less);
    assert_eq!(order("1!0.1", "9999.0"), Ordering::Greater);
    assert_eq!(order("1.0+abc", "1.0+1"), Ordering::Less);
    assert_eq!(order("V01.0RC", "1.0rc0"), Ordering::Equal);
}

#[test]
fn normalization_rules() {
    for (raw, normalized) in [
        // case, one `v`, outer ASCII whitespace
        ("V01.0RC", "1.0rc0"),
        ("v1.0", "1.0"),
        ("V1.0", "1.0"),
        (" 1.0 ", "1.0"),
        ("\t1.0\n", "1.0"),
        ("1.0RC1", "1.0rc1"),
        ("1.0.POST1", "1.0.post1"),
        // numeric zeros
        ("01.00", "1.0"),
        ("00001.0", "1.0"),
        ("1.0+001", "1.0+1"),
        ("0!1.0", "1.0"),
        ("1!1.0", "1!1.0"),
        ("1.0.0.0", "1.0.0.0"),
        // spellings
        ("1.0alpha1", "1.0a1"),
        ("1.0beta2", "1.0b2"),
        ("1.0c1", "1.0rc1"),
        ("1.0pre1", "1.0rc1"),
        ("1.0preview1", "1.0rc1"),
        ("1.0r1", "1.0.post1"),
        ("1.0rev1", "1.0.post1"),
        ("1.0post1", "1.0.post1"),
        // allowed separators
        ("1.0-alpha-1", "1.0a1"),
        ("1.0_a_1", "1.0a1"),
        ("1.0.a.1", "1.0a1"),
        ("1.0-rc.1", "1.0rc1"),
        ("1.0_post_1", "1.0.post1"),
        ("1.0-dev2", "1.0.dev2"),
        ("1.0_dev_3", "1.0.dev3"),
        // omitted suffix numbers are 0
        ("1.0a", "1.0a0"),
        ("1.0b", "1.0b0"),
        ("1.0rc", "1.0rc0"),
        ("1.0.post", "1.0.post0"),
        ("1.0dev", "1.0.dev0"),
        // the implicit post-release
        ("1.0-1", "1.0.post1"),
        ("1.0-2", "1.0.post2"),
        // local labels: lowercase, separators become dots, numbers lose zeros
        ("1.0+ABC", "1.0+abc"),
        ("1.0+a-b_c", "1.0+a.b.c"),
        ("1.0+1.0.0", "1.0+1.0.0"),
        // order of the parts is fixed on output
        ("1!2.3a4.post5.dev6+x.7", "1!2.3a4.post5.dev6+x.7"),
    ] {
        assert!(
            p(raw).to_string() == normalized,
            "normalization of a table spelling"
        );
        // Normalization is idempotent.
        assert!(
            p(normalized).to_string() == normalized,
            "normalization is not idempotent"
        );
        assert_eq!(p(raw), p(normalized));
    }
}

#[test]
fn getters_report_the_parts() {
    let v = p("1!2.3.0a4.post5.dev6+Abc.007");
    assert_eq!(v.epoch(), "1");
    assert_eq!(v.release(), vec!["2", "3", "0"]);
    assert_eq!(v.pre(), Some(("a", "4")));
    assert_eq!(v.post(), Some("5"));
    assert_eq!(v.dev(), Some("6"));
    assert_eq!(v.local().as_deref(), Some("abc.7"));
    let v = p("1.0");
    assert_eq!(v.epoch(), "0");
    assert_eq!(
        (v.pre(), v.post(), v.dev(), v.local()),
        (None, None, None, None)
    );
    assert_eq!(p("1.0rc").pre(), Some(("rc", "0")));
    assert_eq!(p("1.0beta").pre(), Some(("b", "0")));
}

#[test]
fn pre_releases_order_a_b_rc_then_by_number() {
    assert_eq!(order("1.0a1", "1.0b1"), Ordering::Less);
    assert_eq!(order("1.0b1", "1.0rc1"), Ordering::Less);
    assert_eq!(order("1.0a9", "1.0a10"), Ordering::Less);
    assert_eq!(order("1.0rc2", "1.0rc10"), Ordering::Less);
    assert_eq!(order("1.0a10", "1.0b0"), Ordering::Less);
    assert_eq!(order("1.0a", "1.0a0"), Ordering::Equal);
    assert_eq!(order("1.0c1", "1.0rc1"), Ordering::Equal);
    assert_eq!(order("1.0rc1", "1.0"), Ordering::Less);
}

#[test]
fn dev_only_release_sorts_below_its_pre_releases() {
    // No pre and no post: a dev release is below every pre-release.
    assert_eq!(order("1.0.dev1", "1.0a0"), Ordering::Less);
    assert_eq!(order("1.0.dev99", "1.0a0"), Ordering::Less);
    assert_eq!(order("1.0.dev1", "1.0.dev2"), Ordering::Less);
    assert_eq!(order("1.0.dev9", "1.0.dev10"), Ordering::Less);
    // With a pre-release, a dev release is just below that pre-release.
    assert_eq!(order("1.0a1.dev1", "1.0a1"), Ordering::Less);
    assert_eq!(order("1.0a1.dev2", "1.0a1"), Ordering::Less);
    assert_eq!(order("1.0a0", "1.0a1.dev1"), Ordering::Less);
    assert_eq!(order("1.0a1.dev1", "1.0a1.dev2"), Ordering::Less);
    // With a post-release the absent pre-release is +infinity, not -infinity.
    assert_eq!(order("1.0", "1.0.post1.dev1"), Ordering::Less);
    assert_eq!(order("1.0rc1", "1.0.post1.dev1"), Ordering::Less);
    assert_eq!(order("1.0.post1.dev1", "1.0.post1"), Ordering::Less);
    assert_eq!(order("1.0.post1.dev1", "1.0.post1.dev2"), Ordering::Less);
    assert_eq!(order("1.0.post1", "1.0.post2.dev1"), Ordering::Less);
}

#[test]
fn post_releases_order_numerically_above_the_release() {
    assert_eq!(order("1.0", "1.0.post0"), Ordering::Less);
    assert_eq!(order("1.0.post0", "1.0.post1"), Ordering::Less);
    assert_eq!(order("1.0.post9", "1.0.post10"), Ordering::Less);
    assert_eq!(order("1.0.post10", "1.0.1"), Ordering::Less);
    assert_eq!(order("1.0-1", "1.0.post1"), Ordering::Equal);
    assert_eq!(order("1.0rc1.post1", "1.0"), Ordering::Less);
    assert_eq!(order("1.0rc1", "1.0rc1.post1"), Ordering::Less);
}

#[test]
fn release_compares_zero_padded_and_numerically() {
    assert_eq!(order("1", "1.0.0.0"), Ordering::Equal);
    assert_eq!(order("1.0.0.1", "1.0.1"), Ordering::Less);
    assert_eq!(order("1.9", "1.10"), Ordering::Less);
    assert_eq!(order("1.2", "1.2.3"), Ordering::Less);
    assert_eq!(order("2.0", "10.0"), Ordering::Less);
    assert_eq!(order("0.17.0", "0.18.0rc1"), Ordering::Less);
    assert_eq!(order("0.18.0rc1", "0.18.0"), Ordering::Less);
    assert_eq!(order("0.18.0", "0.21.0"), Ordering::Less);
}

#[test]
fn epoch_dominates_everything_else() {
    assert_eq!(order("1!0.1", "9999.0"), Ordering::Greater);
    assert_eq!(order("1!0.0.dev1", "999999.9.post9"), Ordering::Greater);
    assert_eq!(order("2!0", "1!99"), Ordering::Greater);
    assert_eq!(order("0!1.0", "1.0"), Ordering::Equal);
    assert_eq!(
        order("18446744073709551616!1.0", "18446744073709551615!9"),
        Ordering::Greater
    );
}

#[test]
fn local_labels_order_after_their_public_version() {
    // Local absence sorts first.
    assert_eq!(order("1.0", "1.0+abc"), Ordering::Less);
    assert_eq!(order("1.0", "1.0+0"), Ordering::Less);
    assert_eq!(order("1.0.post1", "1.0+abc"), Ordering::Greater);
    // Numeric segments above text ones.
    assert_eq!(order("1.0+abc", "1.0+1"), Ordering::Less);
    assert_eq!(order("1.0+zzz", "1.0+0"), Ordering::Less);
    // Numbers compare numerically, text lexically, a shorter equal prefix first.
    assert_eq!(order("1.0+2", "1.0+10"), Ordering::Less);
    assert_eq!(order("1.0+abc", "1.0+abd"), Ordering::Less);
    assert_eq!(order("1.0+abc", "1.0+abc.1"), Ordering::Less);
    assert_eq!(order("1.0+abc.1", "1.0+abc.2"), Ordering::Less);
    assert_eq!(order("1.0+1.0", "1.0+1.0.0"), Ordering::Less);
    assert_eq!(order("1.0+001", "1.0+1"), Ordering::Equal);
    assert_eq!(order("1.0+a-b_c", "1.0+a.b.c"), Ordering::Equal);
    // The local label never overrides the public order.
    assert_eq!(order("1.0+zzz", "1.0.post1"), Ordering::Less);
    assert_eq!(order("1.0.dev1+local", "1.0"), Ordering::Less);
}

#[test]
fn numbers_beyond_64_bits_compare_exactly() {
    assert_eq!(
        order("18446744073709551615.0", "18446744073709551616.0"),
        Ordering::Less
    );
    assert_eq!(order("1.18446744073709551616", "1.9"), Ordering::Greater);
    assert_eq!(
        order("1.0a18446744073709551616", "1.0a9"),
        Ordering::Greater
    );
    assert_eq!(
        order("1.0+18446744073709551616", "1.0+9"),
        Ordering::Greater
    );
}

#[test]
fn refused_inputs() {
    for bad in [
        "",
        " ",
        "v",
        "1.",
        ".1",
        "1..0",
        "1.0+",
        "1.0+a..b",
        "1.0+a.",
        "1.0+.a",
        "1!",
        "!1.0",
        "a1",
        "1.0.0-",
        "1.0 1",
        "1.0xyz",
        "vv1.0",
        "1.0++a",
        "1.0.post1.post2",
        "1.0.dev1.dev2",
        "1.0a1a2",
        "1.0-a-b",
        "1.0+a b",
        "1,0",
        "١.٠",
        "1.0\u{e9}",
        "1_0",
        "1.0.dev1.post1",
        "1.0.post1a1",
        "1.0!1",
        "1!1!1.0",
        "-1.0",
        "+1.0",
        "1.0+-a",
        "1.0+a-",
        "1.0+_",
        "1.0 +a",
        "1 .0",
        "1.0\u{0}",
        "\u{ff11}.0",
        "v 1.0",
        "1.0.0.0.",
        "1.0-",
        "1.0.",
        "1.0a1+",
        "1.0rc1.",
    ] {
        assert_eq!(Pep440.parse(bad), Err(VersionError::Malformed));
    }
}

#[test]
fn separators_after_a_label_without_a_number_are_read_as_packaging_reads_them() {
    // The reference accepts a separator after a label even with no number.
    assert_eq!(p("1.0a.").to_string(), "1.0a0");
    assert_eq!(p("1.0post-").to_string(), "1.0.post0");
    assert_eq!(p("1.0.dev_").to_string(), "1.0.dev0");
}

#[test]
fn budgets_are_named_errors() {
    let too_long = format!("1.{}", "9".repeat(300));
    assert_eq!(Pep440.parse(&too_long), Err(VersionError::TooLong));
    assert_eq!(Pep440.candidate(&too_long), Err(VersionError::TooLong));
    // 64 components read; 65 do not.
    let ok = vec!["1"; 64].join(".");
    assert!(Pep440.parse(&ok).is_ok());
    let many = vec!["1"; 65].join(".");
    assert_eq!(Pep440.parse(&many), Err(VersionError::TooLong));
    let local_ok = format!("1.0+{}", vec!["a"; 62].join("."));
    assert!(Pep440.parse(&local_ok).is_ok());
    let local_many = format!("1.0+{}", vec!["a"; 63].join("."));
    assert_eq!(Pep440.parse(&local_many), Err(VersionError::TooLong));
    // 256 bytes read; more do not. Whitespace outside counts.
    let at = format!("1.{}", "9".repeat(254));
    assert_eq!(at.len(), 256);
    assert!(Pep440.parse(&at).is_ok());
    assert_eq!(Pep440.parse(&format!("{at} ")), Err(VersionError::TooLong));
}

#[test]
fn identity_is_the_normalized_text() {
    // Spelling classes of one release share an identity.
    assert_eq!(Pep440.same_identity("V01.0RC", "1.0rc0"), Some(true));
    assert_eq!(Pep440.same_identity("1.0-1", "1.0.post1"), Some(true));
    assert_eq!(Pep440.same_identity("0!1.0", "1.0"), Some(true));
    assert_eq!(Pep440.same_identity("1.0+ABC", "1.0+abc"), Some(true));
    assert_eq!(Pep440.same_identity("1.0+a-b", "1.0+a.b"), Some(true));
    // Equal by order is not the same identity.
    assert_eq!(order("1.0", "1.0.0"), Ordering::Equal);
    assert_eq!(Pep440.same_identity("1.0", "1.0.0"), Some(false));
    // Local labels and epochs are part of identity.
    assert_eq!(Pep440.same_identity("1.0+abc", "1.0+abd"), Some(false));
    assert_eq!(Pep440.same_identity("1.0", "1.0+abc"), Some(false));
    assert_eq!(Pep440.same_identity("1!1.0", "1.0"), Some(false));
    // Unreadable on either side: cannot say.
    assert_eq!(Pep440.same_identity("1.0", "junk"), None);
    assert_eq!(Pep440.same_identity("", "1.0"), None);
}

#[test]
fn candidate_is_exact_and_flags_are_declared() {
    assert_eq!(
        Pep440.candidate("0.21.0").unwrap(),
        Candidate::Exact(p("0.21.0"))
    );
    assert!(Pep440.candidate("0.21.0-").is_err());
    assert!(Pep440.orders());
    // A SEMVER range is not read in this scheme without a reviewed interpretation.
    assert!(!Pep440.reads_semver_ranges());
    // `same_version` is precedence equality, and a local label is not equal.
    let v = p("1.0");
    assert_eq!(Pep440.same_version(&v, "1.0.0"), Some(true));
    assert_eq!(Pep440.same_version(&v, "1.0+abc"), Some(false));
    assert_eq!(Pep440.same_version(&v, "junk"), None);
}

// ------------------------------------------------- recorded packaging data

#[test]
fn parse_and_order_agree_with_the_recorded_packaging_vectors() {
    let path = root().join("crates/gd-advisories/tests/reference/pep440-vectors.json");
    let data: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert!(
        data["generator"] == "packaging.version.Version",
        "vector file generator"
    );
    assert!(data["packaging"] == "26.3", "vector file packaging version");
    let inputs: Vec<&str> = data["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let normalized = data["normalized"].as_array().unwrap();
    assert_eq!(inputs.len(), normalized.len());
    assert!(inputs.len() >= 130, "vectors look truncated");

    let mut readable = 0usize;
    let mut refused = 0usize;
    let mut parsed: Vec<Option<Pep440Version>> = Vec::with_capacity(inputs.len());
    for (idx, (raw, n)) in inputs.iter().zip(normalized).enumerate() {
        match n.as_str() {
            Some(expected) => {
                readable += 1;
                let v = Pep440
                    .parse(raw)
                    .unwrap_or_else(|_| panic!("vector {idx} should parse"));
                assert!(
                    v.to_string() == expected,
                    "vector {idx} normalizes differently"
                );
                parsed.push(Some(v));
            }
            None => {
                refused += 1;
                assert!(Pep440.parse(raw).is_err(), "vector {idx} should be refused");
                assert!(
                    Pep440.candidate(raw).is_err(),
                    "vector {idx} should be refused"
                );
                parsed.push(None);
            }
        }
    }
    assert!(readable >= 100 && refused >= 25, "vector counts look wrong");

    let pairs = data["pairs"].as_array().unwrap();
    assert_eq!(pairs.len(), readable * (readable - 1) / 2);
    for (pair_idx, pair) in pairs.iter().enumerate() {
        let pair = pair.as_array().unwrap();
        let (i, j) = (
            usize::try_from(pair[0].as_u64().unwrap()).unwrap(),
            usize::try_from(pair[1].as_u64().unwrap()).unwrap(),
        );
        let want = match pair[2].as_i64().unwrap() {
            -1 => Ordering::Less,
            0 => Ordering::Equal,
            _ => Ordering::Greater,
        };
        let (Some(Some(a)), Some(Some(b))) = (parsed.get(i), parsed.get(j)) else {
            panic!("pair #{pair_idx} refers to a refused or missing input");
        };
        assert!(a.cmp(b) == want, "pair {pair_idx} order");
        assert!(b.cmp(a) == want.reverse(), "pair {pair_idx} reverse order");
        assert!(
            (a == b) == (want == Ordering::Equal),
            "pair {pair_idx} equality"
        );
    }
}

// ----------------------------------------- corpus, fixtures and the scheme

#[test]
fn every_corpus_endpoint_for_cashu_parses_in_pep440() {
    let mut seen = Vec::new();
    for entry in std::fs::read_dir(root().join("advisories/corpus")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let v: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        for entry in v["affected"].as_array().unwrap() {
            if entry["package"]["ecosystem"] != "PyPI" || entry["package"]["name"] != "cashu" {
                continue;
            }
            for range in entry["ranges"].as_array().into_iter().flatten() {
                for event in range["events"].as_array().unwrap() {
                    for (_, val) in event.as_object().unwrap() {
                        seen.push(val.as_str().unwrap().to_string());
                    }
                }
            }
            for listed in entry["versions"].as_array().into_iter().flatten() {
                seen.push(listed.as_str().unwrap().to_string());
            }
        }
    }
    assert!(seen.contains(&"0.18.0".to_string()));
    for (i, s) in seen.iter().enumerate() {
        if s == "0" || s == "*" {
            continue;
        }
        assert!(Pep440.parse(s).is_ok(), "cashu corpus value {i}");
    }
}

#[test]
fn every_fixture_and_catalog_version_for_nutshell_parses_in_pep440() {
    for setup in ["lab-old-synthetic", "lab-regtest"] {
        let v = service_version(setup, "nutshell");
        assert!(
            Pep440.parse(&v).is_ok(),
            "nutshell fixture version in {setup}"
        );
        assert!(Pep440.candidate(&v).is_ok());
    }
    let text = fs::read_to_string(root().join("catalog/nutshell.toml")).unwrap();
    let mut inside = false;
    let mut versions = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            inside = l == "[[version.examples]]";
        } else if inside && let Some(v) = l.strip_prefix("version = ") {
            versions.push(v.trim_matches('"').to_string());
        }
    }
    assert!(!versions.is_empty());
    for (i, v) in versions.iter().enumerate() {
        assert!(Pep440.parse(v).is_ok(), "nutshell catalog example {i}");
    }
}

#[test]
fn cashu_fixture_pairs_give_the_version_subresult_the_fixture_states() {
    let advisory = "PYSEC-2025-89";
    let adv = corpus_record(advisory);
    assert_eq!(adv.affected.len(), 1);
    for (setup, installed_is) in [("lab-old-synthetic", "0.17.0"), ("lab-regtest", "0.21.0")] {
        let installed = service_version(setup, "nutshell");
        assert!(
            installed == installed_is,
            "nutshell fixture version {setup}"
        );
        let got = evaluate_entry(&Pep440, &adv, 0, Some(&installed));
        assert!(
            kind(&got) == expected_version(setup, advisory),
            "nutshell fixture subresult {setup}"
        );
    }
    assert_eq!(
        evaluate_entry(&Pep440, &adv, 0, Some("0.17.0")),
        VersionEvidence::InRange(Location {
            entry: 0,
            place: Place::Range {
                range: 0,
                event: Some(0)
            }
        })
    );
}

#[test]
fn cashu_boundaries_follow_pep440() {
    let adv = corpus_record("PYSEC-2025-89");
    let at = |v: &str| kind(&evaluate_entry(&Pep440, &adv, 0, Some(v)));
    // Below the fix, by PEP 440 rules.
    for v in [
        "0.0.1",
        "0.17.9",
        "0.18.0rc1",
        "0.18.0.dev1",
        "0.18.0a1",
        "0.17.0.post3",
        "V0.18.0RC2",
    ] {
        assert_eq!(at(v), "in-range");
    }
    // At or above the fix.
    for v in [
        "0.18.0",
        "0.18.0.0",
        "0.18.0.post1",
        "0.18.1",
        "1!0.1",
        "0.21.0",
    ] {
        assert_eq!(at(v), "out-of-range");
    }
    // A local build of the fixed release may or may not carry the fix.
    assert_eq!(
        reason(&evaluate_entry(&Pep440, &adv, 0, Some("0.18.0+local"))),
        UnknownReason::CandidateIsAnInterval
    );
    // A version the scheme cannot read is unknown, never out of range.
    let adv_read = |v: &str| evaluate_entry(&Pep440, &adv, 0, Some(v));
    assert_eq!(
        reason(&adv_read("0.21.0-")),
        UnknownReason::InstalledVersionUnparseable
    );
    assert_eq!(
        reason(&adv_read("Nutshell/0.21.0")),
        UnknownReason::InstalledVersionUnparseable
    );
    assert_eq!(
        reason(&evaluate_entry(&Pep440, &adv, 0, None)),
        UnknownReason::InstalledVersionUnknown
    );
}

#[test]
fn pep_ranges_lists_and_scheme_gates() {
    let r = r#"[{"introduced":"1.0"},{"fixed":"2.0"}]"#;
    assert_eq!(kind(&ev(r, "1.0.dev1")), "out-of-range");
    assert_eq!(kind(&ev(r, "1.0")), "in-range");
    assert_eq!(kind(&ev(r, "1.9.post4")), "in-range");
    assert_eq!(kind(&ev(r, "2.0rc1")), "in-range");
    assert_eq!(kind(&ev(r, "2.0.dev1")), "in-range");
    assert_eq!(kind(&ev(r, "2.0")), "out-of-range");
    // An epoch raises the version above any range written without one.
    assert_eq!(kind(&ev(r, "1!1.5")), "out-of-range");
    let r = r#"[{"introduced":"0"},{"fixed":"1!0"}]"#;
    assert_eq!(kind(&ev(r, "9999.0")), "in-range");
    assert_eq!(kind(&ev(r, "1!0")), "out-of-range");
    // A local label on a boundary is refused (see
    // `a_local_label_on_a_boundary_is_unreadable`); on the installed version it
    // is fine.
    let r = r#"[{"introduced":"1.0"},{"fixed":"2.0"}]"#;
    assert_eq!(kind(&ev(r, "1.5+abd")), "in-range");
    assert_eq!(kind(&ev(r, "2.1+abd")), "out-of-range");
    assert_eq!(
        reason(&ev(r, "1.0+abd")),
        UnknownReason::CandidateIsAnInterval
    );
    assert_eq!(
        reason(&ev(r, "2.0+abd")),
        UnknownReason::CandidateIsAnInterval
    );

    // A list identity: the same release spelled another way is a hit; equal by
    // order but written differently is not a hit and not a miss.
    let adv = pypi_advisory(json!([]), json!(["1.0.post1", "2.0.0"]));
    assert!(matches!(
        evaluate_entry(&Pep440, &adv, 0, Some("1.0-1")),
        VersionEvidence::InRange(_)
    ));
    assert_eq!(
        reason(&evaluate_entry(&Pep440, &adv, 0, Some("2.0"))),
        UnknownReason::SameVersionDifferentSpelling
    );
    assert_eq!(
        evaluate_entry(&Pep440, &adv, 0, Some("3.0")),
        VersionEvidence::OutOfRange
    );
    // A SEMVER range gets no SemVer fallback.
    let adv = pypi_advisory(
        json!([{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]),
        json!([]),
    );
    assert_eq!(
        reason(&evaluate_entry(&Pep440, &adv, 0, Some("1.0"))),
        UnknownReason::SchemeMismatch
    );
    // An unreadable boundary poisons its range.
    let r = r#"[{"introduced":"0"},{"fixed":"2.0-"}]"#;
    assert_eq!(reason(&ev(r, "1.0")), UnknownReason::UnparseableBoundary);
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

/// One local-label segment.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Seg {
    /// Text sorts below numbers.
    Text(String),
    Num(u32),
}

/// A version as numbers, with spelling choices. The model orders the numbers
/// with small integers (packaging's `_cmpkey`, not our code); the text covers
/// the spellings the specification allows.
#[derive(Clone, Debug)]
struct Spec {
    v: bool,
    epoch: u32,
    epoch_written: bool,
    release: Vec<u32>,
    pad: bool,
    pre: Option<(u8, u32)>,
    post: Option<u32>,
    implicit_post: bool,
    dev: Option<u32>,
    local: Option<Vec<Seg>>,
    upper: bool,
    omit_zero: bool,
    label: [u8; 3],
    seps: [u8; 6],
    local_seps: [u8; 3],
    ws: bool,
}

const SEPS: [&str; 4] = ["", ".", "-", "_"];

impl Spec {
    fn sep(&self, i: usize) -> &'static str {
        SEPS[usize::from(self.seps[i] % 4)]
    }

    fn num(&self, n: u32) -> String {
        if self.pad {
            format!("00{n}")
        } else {
            n.to_string()
        }
    }

    fn case(&self, s: &str) -> String {
        if self.upper {
            s.to_ascii_uppercase()
        } else {
            s.to_string()
        }
    }

    fn pre_number_written(&self) -> bool {
        self.pre.is_none_or(|(_, n)| !(n == 0 && self.omit_zero))
    }

    fn text(&self) -> String {
        let mut s = String::new();
        if self.ws {
            s.push_str(" \t");
        }
        if self.v {
            s.push_str(&self.case("v"));
        }
        if self.epoch > 0 || self.epoch_written {
            s.push_str(&format!("{}!", self.num(self.epoch)));
        }
        let rel: Vec<String> = self.release.iter().map(|n| self.num(*n)).collect();
        s.push_str(&rel.join("."));
        if let Some((k, n)) = self.pre {
            let labels: [&[&str]; 3] = [
                &["a", "alpha"],
                &["b", "beta"],
                &["rc", "c", "pre", "preview"],
            ];
            let set = labels[usize::from(k % 3)];
            let label = set[usize::from(self.label[0]) % set.len()];
            s.push_str(self.sep(0));
            s.push_str(&self.case(label));
            if !(n == 0 && self.omit_zero) {
                s.push_str(self.sep(1));
                s.push_str(&self.num(n));
            }
        }
        if let Some(n) = self.post {
            if self.implicit_post && self.pre_number_written() {
                s.push('-');
                s.push_str(&self.num(n));
            } else {
                let set = ["post", "rev", "r"];
                s.push_str(self.sep(2));
                s.push_str(&self.case(set[usize::from(self.label[1]) % 3]));
                if !(n == 0 && self.omit_zero) {
                    s.push_str(self.sep(3));
                    s.push_str(&self.num(n));
                }
            }
        }
        if let Some(n) = self.dev {
            s.push_str(self.sep(4));
            s.push_str(&self.case("dev"));
            if !(n == 0 && self.omit_zero) {
                s.push_str(self.sep(5));
                s.push_str(&self.num(n));
            }
        }
        if let Some(local) = &self.local {
            s.push('+');
            for (i, seg) in local.iter().enumerate() {
                if i > 0 {
                    s.push_str(["-", ".", "_"][usize::from(self.local_seps[i % 3] % 3)]);
                }
                match seg {
                    Seg::Text(t) => s.push_str(&self.case(t)),
                    Seg::Num(n) => s.push_str(&self.num(*n)),
                }
            }
        }
        if self.ws {
            s.push_str("\n ");
        }
        s
    }

    /// The expected normalized text.
    fn canonical(&self) -> String {
        let mut s = String::new();
        if self.epoch > 0 {
            s.push_str(&format!("{}!", self.epoch));
        }
        let rel: Vec<String> = self.release.iter().map(u32::to_string).collect();
        s.push_str(&rel.join("."));
        if let Some((k, n)) = self.pre {
            s.push_str(["a", "b", "rc"][usize::from(k % 3)]);
            s.push_str(&n.to_string());
        }
        if let Some(n) = self.post {
            s.push_str(&format!(".post{n}"));
        }
        if let Some(n) = self.dev {
            s.push_str(&format!(".dev{n}"));
        }
        if let Some(local) = &self.local {
            let segs: Vec<String> = local
                .iter()
                .map(|g| match g {
                    Seg::Text(t) => t.clone(),
                    Seg::Num(n) => n.to_string(),
                })
                .collect();
            s.push('+');
            s.push_str(&segs.join("."));
        }
        s
    }

    /// packaging's comparison key, with small integers and class numbers for
    /// the infinities.
    #[allow(clippy::type_complexity)]
    fn key(
        &self,
    ) -> (
        u32,
        Vec<u32>,
        (u8, u8, u32),
        (u8, u32),
        (u8, u32),
        Option<Vec<Seg>>,
    ) {
        let mut rel = self.release.clone();
        while rel.last() == Some(&0) {
            rel.pop();
        }
        let pre = match self.pre {
            Some((k, n)) => (1, k % 3, n),
            None if self.post.is_none() && self.dev.is_some() => (0, 0, 0),
            None => (2, 0, 0),
        };
        let post = self.post.map_or((0, 0), |n| (1, n));
        let dev = self.dev.map_or((1, 0), |n| (0, n));
        (self.epoch, rel, pre, post, dev, self.local.clone())
    }
}

fn spec() -> impl Strategy<Value = Spec> {
    let release = proptest::collection::vec(0u32..12, 1..5);
    let pre = proptest::option::of((0u8..3, 0u32..12));
    let local = proptest::option::of(proptest::collection::vec(
        prop_oneof![
            "[a-z][a-z0-9]{0,3}".prop_map(Seg::Text),
            (0u32..30).prop_map(Seg::Num)
        ],
        1..4,
    ));
    let flags = (
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
    );
    let seps = (
        proptest::array::uniform3(0u8..4),
        proptest::array::uniform6(0u8..4),
        proptest::array::uniform3(0u8..3),
    );
    (
        (0u32..4, release, pre),
        (
            proptest::option::of(0u32..12),
            proptest::option::of(0u32..12),
            local,
        ),
        flags,
        seps,
    )
        .prop_map(
            |(
                (epoch, release, pre),
                (post, dev, local),
                (v, epoch_written, pad, implicit_post, upper, omit_zero),
                (label, seps, local_seps),
            )| Spec {
                v,
                epoch,
                epoch_written,
                release,
                pad,
                pre,
                post,
                implicit_post,
                dev,
                local,
                upper,
                omit_zero,
                label,
                seps,
                local_seps,
                ws: pad && upper,
            },
        )
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn spelled_versions_normalize_and_order_like_the_model(a in spec(), b in spec()) {
        let (ta, tb) = (a.text(), b.text());
        let (pa, pb) = (Pep440.parse(&ta), Pep440.parse(&tb));
        prop_assert!(pa.is_ok());
        prop_assert!(pb.is_ok());
        let (pa, pb) = (pa.unwrap(), pb.unwrap());
        prop_assert_eq!(pa.to_string(), a.canonical());
        prop_assert_eq!(pa.cmp(&pb), a.key().cmp(&b.key()));
        prop_assert_eq!(pa == pb, a.key() == b.key());
    }

    #[test]
    fn order_laws(a in spec(), b in spec(), c in spec()) {
        let (a, b, c) = (
            Pep440.parse(&a.text()).unwrap(),
            Pep440.parse(&b.text()).unwrap(),
            Pep440.parse(&c.text()).unwrap(),
        );
        prop_assert_eq!(a.cmp(&a), Ordering::Equal);
        let ab = a.cmp(&b);
        let flags = [ab == Ordering::Less, ab == Ordering::Equal, ab == Ordering::Greater];
        prop_assert_eq!(flags.iter().filter(|f| **f).count(), 1);
        prop_assert_eq!(ab, b.cmp(&a).reverse());
        if a <= b && b <= c {
            prop_assert!(a <= c);
        }
        if a == b && b == c {
            prop_assert!(a == c);
        }
        prop_assert_eq!(a == b, ab == Ordering::Equal);
        prop_assert_eq!(a.partial_cmp(&b), Some(ab));
    }

    #[test]
    fn normalization_is_idempotent_and_round_trips(a in spec()) {
        let v = Pep440.parse(&a.text()).unwrap();
        let normalized = v.to_string();
        let again = Pep440.parse(&normalized).unwrap();
        prop_assert_eq!(&again, &v);
        prop_assert_eq!(again.to_string(), normalized.clone());
        // Every spelling of one version shares an identity with its normal form.
        prop_assert_eq!(Pep440.same_identity(&a.text(), &normalized), Some(true));
        // Equal identity implies equal order.
        prop_assert_eq!(Pep440.same_version(&v, &normalized), Some(true));
    }

    #[test]
    fn parse_never_panics(s in "\\PC{0,50}") {
        let _ = Pep440.parse(&s);
        let _ = Pep440.candidate(&s);
        let _ = Pep440.same_identity(&s, "1.0");
    }
}

// --------------------------------------------------------------- mutants
//
// Each mutant is a local test-only scheme that reads a version with one part
// of the rules dropped. The same checks that the real scheme passes must fail.

fn pep_check<S: VersionScheme>(scheme: &S) -> Result<(), String> {
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
    lt("1.0.dev1", "1.0a1")?;
    lt("1.0a1", "1.0b1")?;
    lt("1.0rc1", "1.0")?;
    lt("1.0", "1.0.post1")?;
    lt("1.0.post1.dev1", "1.0.post1")?;
    lt("9999.0", "1!0.1")?;
    lt("1.0+abc", "1.0+1")?;
    lt("1.0", "1.0+abc")
}

#[derive(Clone, Copy, Debug)]
enum Part {
    Epoch,
    Local,
    Post,
    Dev,
}

/// Reads with the real parser, writes the version back without one part, and
/// reads that again.
struct Mutant(Part);

fn without(v: &Pep440Version, drop: Part) -> String {
    let mut s = String::new();
    if !matches!(drop, Part::Epoch) && v.epoch() != "0" {
        s.push_str(&format!("{}!", v.epoch()));
    }
    s.push_str(&v.release().join("."));
    if let Some((l, n)) = v.pre() {
        s.push_str(&format!("{l}{n}"));
    }
    if let (Some(n), false) = (v.post(), matches!(drop, Part::Post)) {
        s.push_str(&format!(".post{n}"));
    }
    if let (Some(n), false) = (v.dev(), matches!(drop, Part::Dev)) {
        s.push_str(&format!(".dev{n}"));
    }
    if let (Some(l), false) = (v.local(), matches!(drop, Part::Local)) {
        s.push_str(&format!("+{l}"));
    }
    s
}

impl VersionScheme for Mutant {
    type Version = Pep440Version;
    fn parse(&self, raw: &str) -> Result<Pep440Version, VersionError> {
        let v = Pep440.parse(raw)?;
        Pep440.parse(&without(&v, self.0))
    }
    fn same_identity(&self, a: &str, b: &str) -> Option<bool> {
        Pep440.same_identity(a, b)
    }
    fn reads_semver_ranges(&self) -> bool {
        false
    }
    fn orders(&self) -> bool {
        true
    }
}

#[test]
fn mutants_dropping_an_epoch_local_post_or_dev_are_caught() {
    assert_eq!(pep_check(&Pep440), Ok(()));
    for drop in [Part::Epoch, Part::Local, Part::Post, Part::Dev] {
        let err = pep_check(&Mutant(drop)).unwrap_err();
        assert!(err.starts_with("expected"), "a mutant check failed: {err}");
    }
    // The rebuild itself is faithful when nothing is dropped from a plain version.
    assert_eq!(without(&p("1.0"), Part::Epoch), "1.0");
}

// ------------------------------------------------ local labels (fix round 1)

#[test]
fn a_local_build_of_a_listed_public_version_is_never_a_miss() {
    // Installed `0.16.0+umbrel1` against a list naming `0.16.0`: PEP 440 matching
    // ignores the installed label, so this is a spelling question, not a miss.
    let adv = pypi_advisory(json!([]), json!(["0.16.0"]));
    assert_eq!(
        reason(&evaluate_entry(&Pep440, &adv, 0, Some("0.16.0+umbrel1"))),
        UnknownReason::SameVersionDifferentSpelling
    );
    // A different public version is still a miss.
    assert_eq!(
        evaluate_entry(&Pep440, &adv, 0, Some("0.16.1+umbrel1")),
        VersionEvidence::OutOfRange
    );
    // The same label on both sides is the same identity, a hit.
    let adv = pypi_advisory(json!([]), json!(["0.16.0+umbrel1"]));
    assert!(matches!(
        evaluate_entry(&Pep440, &adv, 0, Some("0.16.0+umbrel1")),
        VersionEvidence::InRange(_)
    ));
    // A listed label that differs from the installed one is another build of
    // the same release: not the same build, but never a clean miss either.
    assert_eq!(
        reason(&evaluate_entry(&Pep440, &adv, 0, Some("0.16.0+umbrel2"))),
        UnknownReason::CandidateIsAnInterval
    );
    // The hook itself.
    let v = p("0.16.0+umbrel1");
    assert_eq!(Pep440.same_version(&v, "0.16.0"), Some(true));
    assert_eq!(Pep440.same_version(&v, "0.16.1"), Some(false));
    assert_eq!(Pep440.same_version(&v, "0.16.0+other"), Some(false));
    assert_eq!(Pep440.same_version(&v, "junk"), None);
}

#[test]
fn a_local_label_on_a_boundary_is_unreadable() {
    for (events, want) in [
        (
            r#"[{"introduced":"1.0+abc"},{"fixed":"2.0"}]"#,
            UnknownReason::UnparseableBoundary,
        ),
        (
            r#"[{"introduced":"1.0"},{"fixed":"2.0+abc"}]"#,
            UnknownReason::UnparseableBoundary,
        ),
        (
            r#"[{"introduced":"1.0"},{"last_affected":"2.0+abc"}]"#,
            UnknownReason::UnparseableBoundary,
        ),
        (
            r#"[{"introduced":"1.0"},{"limit":"3.0+abc"}]"#,
            UnknownReason::UnparseableLimit,
        ),
    ] {
        for installed in ["1.0", "1.5", "2.0"] {
            assert_eq!(reason(&ev(events, installed)), want);
        }
    }
    // Without a label the same shapes are read.
    assert_eq!(
        kind(&ev(r#"[{"introduced":"1.0"},{"fixed":"2.0"}]"#, "1.0")),
        "in-range"
    );
}

#[test]
fn unicode_whitespace_and_case_folding_tricks_are_refused() {
    // `packaging` accepts the first five (Unicode `strip`, Unicode case folding
    // in `post`). It refuses the two Kelvin-sign local labels too, which are also
    // recorded vectors. This scheme refuses all seven.
    for s in [
        "\u{a0}1.0",
        "1.0\u{a0}",
        "\u{2003}1.0\u{2003}",
        "\u{3000}1.0",
        "1.0.po\u{17f}t1",
        "1.0+\u{212a}",
        "1.0+a\u{212a}",
    ] {
        assert_eq!(Pep440.parse(s).err(), Some(VersionError::Malformed),);
    }
    // Plain ASCII whitespace is still trimmed.
    assert!(Pep440.parse(" \t1.0\r\n").is_ok());
}

#[test]
fn a_local_build_is_an_interval_above_its_public_release() {
    // Installed `1.0+x` is a build of `1.0`: a boundary at its public release can
    // go either way, so it is never a clean miss.
    let at_public = |events: &str| ev(events, "1.0+x");
    for events in [
        r#"[{"introduced":"0"},{"last_affected":"1.0"}]"#,
        r#"[{"introduced":"0"},{"fixed":"1.0"}]"#,
        r#"[{"introduced":"1.0"},{"fixed":"2.0"}]"#,
    ] {
        assert_eq!(
            reason(&at_public(events)),
            UnknownReason::CandidateIsAnInterval,
        );
    }
    // An interval wholly inside a range is a hit; wholly outside is a miss.
    assert_eq!(
        kind(&at_public(r#"[{"introduced":"0.9"},{"fixed":"2.0"}]"#)),
        "in-range"
    );
    assert_eq!(
        kind(&at_public(r#"[{"introduced":"1.1"},{"fixed":"2.0"}]"#)),
        "out-of-range"
    );
    assert_eq!(
        kind(&at_public(r#"[{"introduced":"0"},{"fixed":"0.9"}]"#)),
        "out-of-range"
    );
    // Post, dev and pre builds sit in their own intervals.
    let r = r#"[{"introduced":"0"},{"last_affected":"1.0.post1"}]"#;
    assert_eq!(
        reason(&ev(r, "1.0.post1+x")),
        UnknownReason::CandidateIsAnInterval
    );
    assert_eq!(kind(&ev(r, "1.0.post2+x")), "out-of-range");
    let r = r#"[{"introduced":"0"},{"last_affected":"1.0rc1"}]"#;
    assert_eq!(
        reason(&ev(r, "1.0rc1+x")),
        UnknownReason::CandidateIsAnInterval
    );
    assert_eq!(kind(&ev(r, "1.0rc2+x")), "out-of-range");
    // The list case is unchanged.
    let adv = pypi_advisory(json!([]), json!(["0.16.0"]));
    assert_eq!(
        reason(&evaluate_entry(&Pep440, &adv, 0, Some("0.16.0+umbrel1"))),
        UnknownReason::SameVersionDifferentSpelling
    );
    // The question names the build.
    assert!(
        Pep440
            .interval_question()
            .contains("Which public release is this local build (+label) based on")
    );
    // A public installed version is still exact.
    assert!(matches!(
        Pep440.candidate("1.0").unwrap(),
        Candidate::Exact(_)
    ));
}

#[test]
fn a_local_build_at_a_dev0_release_is_never_a_miss_at_its_own_release() {
    let unknown = UnknownReason::CandidateIsAnInterval;
    for (installed, events) in [
        ("1.0.dev0+x", r#"[{"introduced":"0"},{"fixed":"1.0.dev0"}]"#),
        (
            "1.0.dev0+x",
            r#"[{"introduced":"0"},{"last_affected":"1.0.dev0"}]"#,
        ),
        (
            "1.0.dev0+x",
            r#"[{"introduced":"1.0.dev0"},{"fixed":"2.0"}]"#,
        ),
        (
            "1.0rc1.dev0+x",
            r#"[{"introduced":"0"},{"fixed":"1.0rc1.dev0"}]"#,
        ),
        (
            "1.0.post1.dev0+x",
            r#"[{"introduced":"0"},{"fixed":"1.0.post1.dev0"}]"#,
        ),
        ("1.0+x", r#"[{"introduced":"0"},{"fixed":"1.0.dev0"}]"#),
    ] {
        assert_eq!(reason(&ev(events, installed)), unknown,);
    }
    assert_eq!(
        kind(&ev(r#"[{"introduced":"0"},{"fixed":"0.9"}]"#, "1.0.dev0+x")),
        "out-of-range"
    );
    assert_eq!(
        kind(&ev(
            r#"[{"introduced":"0.9"},{"fixed":"2.0"}]"#,
            "1.0.dev0+x"
        )),
        "in-range"
    );
    match Pep440.candidate("1.0.dev0+x").unwrap() {
        Candidate::Between { low, high: Some(h) } => {
            assert!(low < p("1.0.dev0"));
            assert!(low > p("0.9"));
            assert_eq!(h, p("1.0.dev1"));
        }
        other => panic!("expected an interval, got {other:?}"),
    }
}

#[test]
fn a_dev_local_build_is_an_interval_over_its_dev_line() {
    let unknown = UnknownReason::CandidateIsAnInterval;
    for events in [
        r#"[{"introduced":"0"},{"fixed":"1.0.dev3"}]"#,
        r#"[{"introduced":"0"},{"fixed":"1.0.dev0"}]"#,
        r#"[{"introduced":"0"},{"last_affected":"1.0.dev2"}]"#,
    ] {
        assert_eq!(reason(&ev(events, "1.0.dev3+x")), unknown);
    }
    assert_eq!(
        kind(&ev(
            r#"[{"introduced":"0"},{"fixed":"1.0.dev4"}]"#,
            "1.0.dev3+x"
        )),
        "in-range"
    );
    assert_eq!(
        kind(&ev(
            r#"[{"introduced":"1.0.dev5"},{"fixed":"2.0"}]"#,
            "1.0.dev3+x"
        )),
        "out-of-range"
    );
    assert_eq!(
        kind(&ev(r#"[{"introduced":"0"},{"fixed":"0.9"}]"#, "1.0.dev3+x")),
        "out-of-range"
    );
    let listed = |v: &str| {
        let adv = pypi_advisory(json!([]), json!([v]));
        evaluate_entry(&Pep440, &adv, 0, Some("1.0.dev3+x"))
    };
    assert_eq!(
        reason(&listed("1.0.dev3")),
        UnknownReason::SameVersionDifferentSpelling
    );
    assert_eq!(reason(&listed("1.0.dev1")), unknown);
    assert_eq!(kind(&listed("1.0.dev4")), "out-of-range");
    assert_eq!(kind(&listed("1.0.dev3+x")), "in-range");
    match Pep440.candidate("1.0.dev3+x").unwrap() {
        Candidate::Between { low, high } => {
            assert_eq!(high, Some(p("1.0.dev4")));
            assert!(low < p("1.0.dev0"));
        }
        other => panic!("expected an interval, got {other:?}"),
    }
}

#[test]
fn a_local_build_listed_with_another_spelling_is_a_spelling_question() {
    let listed = |installed: &str, v: &str| {
        let adv = pypi_advisory(json!([]), json!([v]));
        evaluate_entry(&Pep440, &adv, 0, Some(installed))
    };
    let spelling = UnknownReason::SameVersionDifferentSpelling;
    assert_eq!(reason(&listed("1.0+x", "1.0.0+x")), spelling);
    assert_eq!(reason(&listed("1.0.0+x", "1.0+x")), spelling);
    assert_eq!(kind(&listed("1.0+x", "1.0+X")), "in-range");
    assert_eq!(reason(&listed("1.0+vendor", "1.0")), spelling);
    assert_eq!(reason(&listed("1.0.0+vendor", "1.0")), spelling);
    assert_eq!(
        reason(&listed("0.16.0+umbrel2", "0.16.0+umbrel1")),
        UnknownReason::CandidateIsAnInterval
    );
}

#[test]
fn installed_whitespace_is_refused_but_advisory_side_is_normalized() {
    let r = r#"[{"introduced":"0"},{"fixed":"0.18.0"}]"#;
    for installed in [" 0.18.0\n", " 0.18.0", "0.18.0\n", "\t0.18.0"] {
        assert!(
            reason(&ev(r, installed)) == UnknownReason::InstalledVersionUnparseable,
            "installed value with whitespace, case {}",
            installed.len()
        );
    }
    assert!(kind(&ev(r, "0.18.0")) == "out-of-range");
    // Boundaries keep the advisory-side normalization.
    let padded = r#"[{"introduced":"0"},{"fixed":" 0.18.0 "}]"#;
    assert!(kind(&ev(padded, "0.17.0")) == "in-range");
}

#[test]
fn the_component_budget_covers_the_whole_version() {
    let long = format!("{}+{}", vec!["2"; 33].join("."), vec!["x"; 33].join("."));
    assert!(long.len() <= 256);
    assert!(Pep440.parse(&long) == Err(VersionError::TooLong));
    let adv = pypi_advisory(json!([]), json!([long]));
    assert!(
        reason(&evaluate_entry(&Pep440, &adv, 0, Some("1.0")))
            == UnknownReason::UnreadableListedVersion
    );
    // Within the budget in total is still read.
    let ok = format!("{}+{}", vec!["2"; 31].join("."), vec!["x"; 31].join("."));
    assert!(Pep440.parse(&ok).is_ok());
}
