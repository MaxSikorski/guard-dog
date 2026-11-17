//! Judge B, steps 3 and 5: the expected advisory matches in
//! `fixtures/expected-matches.toml`, written by hand before any matcher
//! exists, and the judge that scores a matcher against them.
//!
//! Deterministic: no network, no Docker, no clock. Advisory ids come from
//! `advisories/corpus/*.json`; the lab's service versions come from the pinned
//! image labels in `lab/compose.yml` (the same labels `lab/up.sh` checks the
//! running services against). Everything is kept in sorted maps and sets.

// Test-only crate: its helper functions (not just `#[test]` ones) read files and
// check data, and a panic there is a failed check. The workspace panic lints
// protect shipped code; clippy.toml exempts `#[test]` functions and code under `#[cfg(test)]`,
// but not these unannotated helpers.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use toml::{Table, Value};
use yaml_rust2::YamlLoader;

const FILE: &str = "fixtures/expected-matches.toml";
/// The setups judged today. A new recorded setup is added here and in the file.
const SETUPS: [&str; 1] = ["lab-regtest"];
const RESULTS: [&str; 3] = ["affected", "not-affected", "possibly-affected"];
const VERSION_STATES: [&str; 4] = ["in-range", "out-of-range", "unknown", "not-applicable"];
const CONDITION_STATES: [&str; 3] = ["met", "not-met", "unknown"];
const TOP_KEYS: [&str; 3] = ["expect", "format", "setup"];
const SETUP_KEYS: [&str; 7] = [
    "chain",
    "description",
    "exposure",
    "id",
    "platform",
    "service",
    "versions_from",
];
const SERVICE_KEYS: [&str; 2] = ["id", "version"];
const EXPECT_KEYS: [&str; 8] = [
    "advisory",
    "condition",
    "question",
    "reason",
    "result",
    "review",
    "setup",
    "version",
];

#[derive(Debug, Clone)]
struct Expect {
    setup: String,
    advisory: String,
    result: String,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    let path = root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// Every advisory id in the corpus, from each file's `id` field.
fn corpus_ids() -> BTreeSet<String> {
    let dir = root().join("advisories/corpus");
    let mut ids = BTreeSet::new();
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(&fs::read_to_string(&path).unwrap())
            .unwrap_or_else(|e| panic!("{} is not JSON: {e}", path.display()));
        ids.insert(v["id"].as_str().unwrap().to_owned());
    }
    assert!(!ids.is_empty(), "no advisories found in {}", dir.display());
    ids
}

/// The lab's services as `lab/up.sh` pins them: id label to expected-version
/// label, from `lab/compose.yml`.
fn lab_versions() -> BTreeMap<String, String> {
    let up = read("lab/up.sh");
    assert!(
        up.contains("label \"$svc\" expected-version") && up.contains("label \"$1\" id"),
        "lab/up.sh no longer checks each service against its id and expected-version labels; \
         this test's source of truth has moved"
    );
    let docs = YamlLoader::load_from_str(&read("lab/compose.yml")).unwrap();
    let services = docs[0]["services"].as_hash().unwrap();
    let mut out = BTreeMap::new();
    for svc in services.values() {
        let labels = &svc["labels"];
        let id = labels["org.guard-dog.lab.id"].as_str().unwrap();
        let version = labels["org.guard-dog.lab.expected-version"]
            .as_str()
            .unwrap();
        assert!(
            out.insert(id.to_owned(), version.to_owned()).is_none(),
            "duplicate lab id {id}"
        );
    }
    out
}

fn is_slug(s: &str) -> bool {
    !s.is_empty()
        && s.split('-').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
}

/// Printable ASCII on one line, no surrounding spaces: what every text field must be.
fn is_clean_line(s: &str) -> bool {
    !s.is_empty() && s.trim() == s && s.chars().all(|c| (' '..='~').contains(&c))
}

fn unknown_keys(table: &Table, allowed: &[&str], what: &str, errors: &mut Vec<String>) {
    for key in table.keys() {
        if !allowed.contains(&key.as_str()) {
            errors.push(format!("{what}: unknown key `{key}`"));
        }
    }
}

fn text<'a>(table: &'a Table, key: &str, what: &str, errors: &mut Vec<String>) -> &'a str {
    match table.get(key) {
        Some(Value::String(s)) if is_clean_line(s) => s,
        Some(_) => {
            errors.push(format!(
                "{what}: `{key}` must be one line of printable ASCII text"
            ));
            ""
        }
        None => {
            errors.push(format!("{what}: `{key}` is missing"));
            ""
        }
    }
}

fn tables<'a>(v: Option<&'a Value>, what: &str, errors: &mut Vec<String>) -> Vec<&'a Table> {
    match v {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|i| {
                let t = i.as_table();
                if t.is_none() {
                    errors.push(format!("{what}: every item must be a table"));
                }
                t
            })
            .collect(),
        _ => {
            errors.push(format!("{what}: must be an array of tables"));
            Vec::new()
        }
    }
}

/// The result the version and condition calls imply (see the file's header).
fn implied(version: &str, condition: &str) -> &'static str {
    if version == "out-of-range" || condition == "not-met" {
        "not-affected"
    } else if version == "in-range" && condition == "met" {
        "affected"
    } else {
        "possibly-affected"
    }
}

/// Check the whole file. Returns the expectations, or every problem found.
fn check(
    text_in: &str,
    corpus: &BTreeSet<String>,
    lab: &BTreeMap<String, String>,
) -> Result<Vec<Expect>, Vec<String>> {
    let mut errors = Vec::new();
    let doc: Table = match text_in.parse() {
        Ok(t) => t,
        Err(e) => return Err(vec![format!("not TOML: {e}")]),
    };
    unknown_keys(&doc, &TOP_KEYS, "top level", &mut errors);
    if doc.get("format").and_then(Value::as_integer) != Some(1) {
        errors.push("top level: `format` must be 1".to_owned());
    }

    // Setups.
    let mut setup_ids = Vec::new();
    for (i, s) in tables(doc.get("setup"), "setup", &mut errors)
        .into_iter()
        .enumerate()
    {
        let what = format!("setup {i}");
        unknown_keys(s, &SETUP_KEYS, &what, &mut errors);
        let id = text(s, "id", &what, &mut errors);
        if !is_slug(id) {
            errors.push(format!("{what}: id `{id}` is not a lower-case slug"));
        }
        for key in ["platform", "chain", "exposure", "description"] {
            text(s, key, &what, &mut errors);
        }
        let mut services = BTreeMap::new();
        for svc in tables(s.get("service"), &format!("{what} service"), &mut errors) {
            unknown_keys(svc, &SERVICE_KEYS, &format!("{what} service"), &mut errors);
            let sid = text(svc, "id", &what, &mut errors).to_owned();
            let version = text(svc, "version", &what, &mut errors).to_owned();
            if services.insert(sid.clone(), version).is_some() {
                errors.push(format!("{what}: service `{sid}` listed twice"));
            }
        }
        match text(s, "versions_from", &what, &mut errors) {
            "lab/compose.yml" => {
                if &services != lab {
                    errors.push(format!(
                        "setup {id}: services and versions {services:?} differ from the \
                         lab's pinned images {lab:?}"
                    ));
                }
            }
            other => errors.push(format!(
                "setup {id}: versions_from `{other}` is not a known source of truth"
            )),
        }
        setup_ids.push(id.to_owned());
    }
    let listed: Vec<&str> = setup_ids.iter().map(String::as_str).collect();
    if listed != SETUPS {
        errors.push(format!(
            "setups are {listed:?}, expected exactly {SETUPS:?} in that order"
        ));
    }

    // Expectations.
    let mut out: Vec<Expect> = Vec::new();
    for (i, e) in tables(doc.get("expect"), "expect", &mut errors)
        .into_iter()
        .enumerate()
    {
        let what = format!("expect {i}");
        unknown_keys(e, &EXPECT_KEYS, &what, &mut errors);
        let setup = text(e, "setup", &what, &mut errors).to_owned();
        let advisory = text(e, "advisory", &what, &mut errors).to_owned();
        let what = format!("expect {setup} x {advisory}");
        if !setup_ids.contains(&setup) {
            errors.push(format!("{what}: setup is not listed"));
        }
        if !corpus.contains(&advisory) {
            errors.push(format!("{what}: advisory is not in advisories/corpus/"));
        }
        let result = text(e, "result", &what, &mut errors).to_owned();
        if !RESULTS.contains(&result.as_str()) {
            errors.push(format!(
                "{what}: result `{result}` is not one of {RESULTS:?}"
            ));
        }
        let version = text(e, "version", &what, &mut errors);
        if !VERSION_STATES.contains(&version) {
            errors.push(format!(
                "{what}: version `{version}` is not one of {VERSION_STATES:?}"
            ));
        }
        let condition = text(e, "condition", &what, &mut errors);
        if !CONDITION_STATES.contains(&condition) {
            errors.push(format!(
                "{what}: condition `{condition}` is not one of {CONDITION_STATES:?}"
            ));
        }
        if version == "not-applicable" && condition != "not-met" {
            errors.push(format!(
                "{what}: a product that isn't there leaves its service condition not-met"
            ));
        }
        if implied(version, condition) != result {
            errors.push(format!(
                "{what}: version {version} and condition {condition} give {}, not {result}",
                implied(version, condition)
            ));
        }
        text(e, "reason", &what, &mut errors);
        match (result.as_str(), e.get("question")) {
            ("possibly-affected", Some(_)) => {
                if !text(e, "question", &what, &mut errors).ends_with('?') {
                    errors.push(format!("{what}: the question must end with `?`"));
                }
            }
            ("possibly-affected", None) => {
                errors.push(format!(
                    "{what}: possibly-affected needs the question that settles it"
                ));
            }
            (_, Some(_)) => errors.push(format!("{what}: only possibly-affected has a question")),
            (_, None) => {}
        }
        if let Some(r) = e.get("review")
            && r.as_str() != Some("max")
        {
            errors.push(format!("{what}: review, when present, must be \"max\""));
        }
        if let Some(prev) = out.last()
            && (prev.setup.as_str(), prev.advisory.as_str()) >= (setup.as_str(), advisory.as_str())
        {
            errors.push(format!(
                "{what}: entries must be sorted by setup then advisory, each pair once"
            ));
        }
        out.push(Expect {
            setup,
            advisory,
            result,
        });
    }
    for id in &setup_ids {
        let have: BTreeSet<String> = out
            .iter()
            .filter(|e| &e.setup == id)
            .map(|e| e.advisory.clone())
            .collect();
        for missing in corpus.difference(&have) {
            errors.push(format!("setup {id}: no expectation for advisory {missing}"));
        }
    }
    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

fn load() -> Vec<Expect> {
    check(&read(FILE), &corpus_ids(), &lab_versions())
        .unwrap_or_else(|errs| panic!("{FILE} has problems:\n  {}", errs.join("\n  ")))
}

/// A matcher's answer for one pair: `Some(result)` when it raises an alert
/// (affected or possibly-affected), `None` when it says nothing.
type Matcher = fn(&Expect) -> Option<&'static str>;

#[derive(Debug, PartialEq, Eq)]
struct Score {
    expected_alerts: usize,
    reported: usize,
    correct: usize,
}

impl Score {
    fn percent(n: usize, d: usize) -> String {
        (n * 100)
            .checked_div(d)
            .map_or_else(|| "n/a".to_owned(), |p| format!("{p}%"))
    }
    fn line(&self) -> String {
        format!(
            "reported {}, correct {}; precision {} ({} of {}), recall {} ({} of {})",
            self.reported,
            self.correct,
            Self::percent(self.correct, self.reported),
            self.correct,
            self.reported,
            Self::percent(self.correct, self.expected_alerts),
            self.correct,
            self.expected_alerts,
        )
    }
}

/// Precision and recall over alerts: an alert is correct only when its result
/// (affected or possibly-affected) is exactly the expected one. Saying nothing
/// is the matcher's way of saying not-affected.
fn score(expects: &[Expect], matcher: Matcher) -> Score {
    let mut s = Score {
        expected_alerts: 0,
        reported: 0,
        correct: 0,
    };
    for e in expects {
        let expected = (e.result != "not-affected").then_some(e.result.as_str());
        let got = matcher(e).filter(|r| *r != "not-affected");
        s.expected_alerts += usize::from(expected.is_some());
        s.reported += usize::from(got.is_some());
        s.correct += usize::from(got.is_some() && got == expected);
    }
    s
}

/// Phase 2 replaces this with the real matcher.
fn no_matcher_yet(_: &Expect) -> Option<&'static str> {
    None
}

#[test]
fn expected_matches_cover_every_setup_and_advisory() {
    let expects = load();
    let corpus = corpus_ids();
    assert_eq!(expects.len(), SETUPS.len() * corpus.len());
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for e in &expects {
        *counts.entry(e.result.as_str()).or_default() += 1;
    }
    eprintln!("expected matches: {counts:?}");
}

#[test]
fn judge_b_matcher_baseline() {
    let expects = load();
    let s = score(&expects, no_matcher_yet);
    eprintln!("Judge B, no matcher yet: {}", s.line());
    // The recorded baseline (tests/README.md). Update both when the matcher lands.
    assert_eq!(
        s,
        Score {
            expected_alerts: 1,
            reported: 0,
            correct: 0
        }
    );
}

#[test]
fn the_scoring_has_teeth() {
    let expects = load();
    fn oracle(e: &Expect) -> Option<&'static str> {
        RESULTS.iter().copied().find(|r| *r == e.result)
    }
    fn alarm_everything(_: &Expect) -> Option<&'static str> {
        Some("affected")
    }
    fn hedge_everything(_: &Expect) -> Option<&'static str> {
        Some("possibly-affected")
    }
    let perfect = score(&expects, oracle);
    assert_eq!(perfect.correct, perfect.reported);
    assert_eq!(perfect.correct, perfect.expected_alerts);
    let loud = score(&expects, alarm_everything);
    assert_eq!((loud.reported, loud.correct), (expects.len(), 0));
    let hedge = score(&expects, hedge_everything);
    assert_eq!(hedge.reported, expects.len());
    assert!(
        hedge.correct < hedge.reported,
        "hedging must cost precision"
    );
}

#[test]
fn every_broken_file_is_refused() {
    let good = read(FILE);
    let corpus = corpus_ids();
    let lab = lab_versions();
    let first = "advisory = \"CVE-2024-35202\"\nresult = \"not-affected\"";
    let cases: [(&str, &str, &str, &str); 17] = [
        (
            "unknown result",
            first,
            "advisory = \"CVE-2024-35202\"\nresult = \"safe\"",
            "is not one of",
        ),
        (
            "result disagrees with the calls",
            first,
            "advisory = \"CVE-2024-35202\"\nresult = \"affected\"",
            "give not-affected",
        ),
        (
            "unknown advisory",
            "advisory = \"CVE-2024-35202\"",
            "advisory = \"CVE-2099-0001\"",
            "not in advisories/corpus",
        ),
        (
            "duplicate pair",
            "advisory = \"CVE-2024-38359\"",
            "advisory = \"CVE-2024-35202\"",
            "each pair once",
        ),
        (
            "missing pair",
            "advisory = \"CVE-2024-38359\"",
            "advisory = \"CVE-2024-38359x\"",
            "no expectation for advisory CVE-2024-38359",
        ),
        (
            "unlisted setup",
            "setup = \"lab-regtest\"\nadvisory = \"CVE-2024-35202\"",
            "setup = \"lab-other\"\nadvisory = \"CVE-2024-35202\"",
            "setup is not listed",
        ),
        (
            "possibly without a question",
            "question = \"Which xz-utils",
            "#question = \"Which xz-utils",
            "needs the question",
        ),
        (
            "question without a question mark",
            "lab images?\"",
            "lab images\"",
            "must end with `?`",
        ),
        (
            "question on a not-affected pair",
            first,
            "question = \"Why?\"\nadvisory = \"CVE-2024-35202\"\nresult = \"not-affected\"",
            "only possibly-affected",
        ),
        (
            "empty reason",
            "reason = \"Bitcoin Core 32.1 is not below the fix 25.0 (range 0 to fixed 25.0).\"",
            "reason = \"\"",
            "`reason` must be one line",
        ),
        (
            "reason with a control character",
            "fix 25.0 (range",
            "fix 25.0\\u001b(range",
            "`reason` must be one line",
        ),
        (
            "review other than max",
            "\nreview = \"max\"",
            "\nreview = \"someone\"",
            "must be \"max\"",
        ),
        (
            "unknown key",
            first,
            "severity = \"high\"\nadvisory = \"CVE-2024-35202\"\nresult = \"not-affected\"",
            "unknown key `severity`",
        ),
        (
            "a version that isn't the lab's",
            "version = \"32.1\"",
            "version = \"32.0\"",
            "differ from the lab's pinned images",
        ),
        (
            "a service the lab doesn't run",
            "id = \"strfry\"",
            "id = \"nostr-rs-relay\"",
            "differ from the lab's pinned images",
        ),
        (
            "absent product with condition met",
            "version = \"not-applicable\"\ncondition = \"not-met\"",
            "version = \"not-applicable\"\ncondition = \"met\"",
            "leaves its service condition not-met",
        ),
        (
            "wrong format",
            "format = 1",
            "format = 2",
            "`format` must be 1",
        ),
    ];
    for (name, from, to, want) in cases {
        assert!(good.contains(from), "{name}: anchor `{from}` not found");
        let bad = good.replacen(from, to, 1);
        match check(&bad, &corpus, &lab) {
            Ok(_) => panic!("{name}: the broken file was accepted"),
            Err(errs) => assert!(
                errs.iter().any(|e| e.contains(want)),
                "{name}: expected a problem containing `{want}`, got:\n  {}",
                errs.join("\n  ")
            ),
        }
    }
}
