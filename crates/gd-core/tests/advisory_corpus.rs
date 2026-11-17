//! Judge B, steps 1, 2 and 4: every advisory in `advisories/corpus/*.json` is
//! valid OSV JSON, and carries what Guard Dog needs from it.
//!
//! Deterministic by design: no network, no clock, and nothing random decides a
//! result. The files are read in sorted order, and the schema is the vendored
//! copy in `advisories/schema/` (the `jsonschema` crate is built without its
//! HTTP and file-resolving features, so it cannot fetch anything). That crate's
//! internal hash maps are randomly seeded, so schema messages are sorted before
//! they are printed.

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

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

/// The OSV schema version every record is written against.
const SCHEMA_VERSION: &str = "1.9.2";
/// The vendored copy of that schema.
const SCHEMA_FILE: &str = "osv-schema-1.9.2.json";
/// The plan asks for at least 20 real advisories.
const MIN_ADVISORIES: usize = 20;

/// Every reviewed advisory, sorted. Deleting, renaming or adding a file
/// without updating this list fails `corpus_is_exactly_the_reviewed_list`.
const EXPECTED_IDS: [&str; 23] = [
    "CVE-2024-3094",
    "CVE-2024-35202",
    "CVE-2024-38359",
    "CVE-2024-49379",
    "CVE-2024-52911",
    "CVE-2024-52922",
    "CVE-2025-46598",
    "CVE-2025-62859",
    "CVE-2025-62861",
    "CVE-2026-117346",
    "CVE-2026-117349",
    "CVE-2026-119757",
    "GHSA-wj92-jhwh-85j5",
    "PYSEC-2025-89",
    "x_alby-hub-2026-09-internet-exposed-takeover",
    "x_btcpay-2026-v2.4.7-85-security-findings",
    "x_cln-2026-v26.06.8-unspecified-vulnerabilities",
    "x_coinkite-2026-07-coldcard-weak-seed-entropy",
    "x_fedimint-2026-v0.11.2-security-fixes",
    "x_lightning-labs-2026-lnd-brontide-write-allocation-oom",
    "x_lightning-labs-2026-lnd-dns-bootstrap-type-assertion-panic",
    "x_lightning-labs-2026-lnd-gossip-validation-barrier-stall",
    "x_lightning-labs-2026-lnd-tapd-cancelled-htlc-marked-settled",
];
const _: () = assert!(EXPECTED_IDS.len() >= MIN_ADVISORIES);

fn advisories_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../advisories")
}

fn load(path: &Path) -> Value {
    let text =
        fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{} is not JSON: {e}", path.display()))
}

/// The vendored schema, with `format` checks on: draft 2020-12 treats formats
/// as notes unless asked, and without them a timestamp like 2026-02-30 or a
/// reference URL with spaces in it would pass.
fn schema_validator() -> jsonschema::Validator {
    let schema = load(&advisories_dir().join("schema").join(SCHEMA_FILE));
    jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .expect("the vendored OSV schema compiles")
}

/// All corpus files, sorted by file name so every run sees the same order.
/// Anything in the folder other than `<id>.json` fails (hidden files such as
/// `.DS_Store` are skipped).
fn corpus_files() -> Vec<PathBuf> {
    let dir = advisories_dir().join("corpus");
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
        .map(|entry| entry.expect("directory entry").path())
        .filter(|p| {
            !p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with('.'))
        })
        .collect();
    files.sort();
    for path in &files {
        assert!(
            path.is_file() && path.extension().is_some_and(|e| e == "json"),
            "{}: only <id>.json files belong in advisories/corpus",
            path.display()
        );
    }
    files
}

fn is_nonempty_string(v: &Value) -> bool {
    v.as_str().is_some_and(|s| !s.trim().is_empty())
}

/// `YYYY-MM-DD` naming a day that exists (leap years included).
fn is_calendar_date(s: &str) -> bool {
    let b = s.as_bytes();
    let shaped = b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit());
    if !shaped {
        return false;
    }
    let num = |range: std::ops::Range<usize>| s[range].parse::<u32>().unwrap_or(0);
    let (year, month, day) = (num(0..4), num(5..7), num(8..10));
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days_in_month).contains(&day)
}

/// OSV range rules the schema can't express. Events start with `introduced`;
/// each `fixed` or `last_affected` closes the interval opened just before it,
/// so two closings never follow each other; and one range uses `fixed` or
/// `last_affected`, not both. Returns what is wrong, or `None`.
/// The closed chain names: the same five as the fact model's `Chain` enum.
const CHAINS: [&str; 5] = ["main", "testnet3", "testnet4", "signet", "regtest"];

/// What is wrong with one condition, if anything: a `chain` condition's
/// `any_of` must be a non-empty list of known chain names.
fn condition_problem(cond: &Value) -> Option<String> {
    if cond["fact"].as_str() != Some("chain") {
        return None;
    }
    let Some(any_of) = cond["any_of"].as_array().filter(|a| !a.is_empty()) else {
        return Some("a chain condition needs a non-empty any_of list".to_owned());
    };
    any_of
        .iter()
        .find(|v| !v.as_str().is_some_and(|s| CHAINS.contains(&s)))
        .map(|v| format!("chain {v} is not one of {CHAINS:?}"))
}

fn range_problem(events: &[Value]) -> Option<String> {
    let mut kinds = Vec::new();
    for event in events {
        let object = event.as_object()?;
        if object.len() != 1 {
            return Some(format!("an event must have exactly one key: {event}"));
        }
        kinds.push(object.keys().next()?.as_str());
    }
    if kinds.first() != Some(&"introduced") {
        return Some(format!("events must start with `introduced`: {kinds:?}"));
    }
    if let Some(kind) = kinds
        .iter()
        .find(|k| !["introduced", "fixed", "last_affected"].contains(k))
    {
        return Some(format!(
            "unexpected event `{kind}` (the corpus uses no `limit`)"
        ));
    }
    if kinds.contains(&"fixed") && kinds.contains(&"last_affected") {
        return Some(format!(
            "`fixed` and `last_affected` in one range: {kinds:?}"
        ));
    }
    if let Some(pair) = kinds.windows(2).find(|pair| pair[0] == pair[1]) {
        return Some(format!("two `{}` events in a row: {kinds:?}", pair[0]));
    }
    None
}

#[test]
fn corpus_is_exactly_the_reviewed_list() {
    let mut ids: Vec<String> = corpus_files()
        .iter()
        .map(|p| {
            load(p)["id"]
                .as_str()
                .unwrap_or_else(|| panic!("{} has no string id", p.display()))
                .to_owned()
        })
        .collect();
    ids.sort();
    let expected: Vec<String> = EXPECTED_IDS.iter().map(|s| (*s).to_owned()).collect();
    assert_eq!(
        ids, expected,
        "advisories/corpus no longer matches the reviewed list in EXPECTED_IDS"
    );
}

#[test]
fn every_advisory_is_valid_osv_json() {
    let validator = schema_validator();
    let mut problems = Vec::new();
    for path in corpus_files() {
        let doc = load(&path);
        if doc["schema_version"] != SCHEMA_VERSION {
            problems.push(format!(
                "{}: schema_version must be {SCHEMA_VERSION}",
                path.display()
            ));
        }
        for error in validator.iter_errors(&doc) {
            problems.push(format!(
                "{}: {} (at {})",
                path.display(),
                error,
                error.instance_path()
            ));
        }
    }
    problems.sort();
    assert!(
        problems.is_empty(),
        "schema violations:\n{}",
        problems.join("\n")
    );
}

#[test]
fn every_advisory_is_named_after_its_id() {
    for path in corpus_files() {
        let doc = load(&path);
        let id = doc["id"]
            .as_str()
            .unwrap_or_else(|| panic!("{} has no string id", path.display()));
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("file name");
        assert_eq!(
            stem,
            id,
            "{}: the file name must equal the advisory id",
            path.display()
        );
    }
}

#[test]
fn every_advisory_has_a_primary_source_reference() {
    for path in corpus_files() {
        let doc = load(&path);
        let refs = doc["references"]
            .as_array()
            .unwrap_or_else(|| panic!("{} has no references array", path.display()));
        assert!(!refs.is_empty(), "{}: references is empty", path.display());
        let has_source = refs.iter().any(|r| {
            r["type"] == "ADVISORY" && r["url"].as_str().is_some_and(|u| u.starts_with("https://"))
        });
        // One record is built from a news report because the project's own
        // announcement (an X post) could not be retrieved. It must say so
        // explicitly, so a missing primary source is never an accident.
        let admits_no_primary = doc["database_specific"]["primary_source_retrieved"] == false
            && refs.iter().any(|r| r["type"] == "ARTICLE");
        assert!(
            has_source || admits_no_primary,
            "{}: no ADVISORY reference with an https address (the primary source)",
            path.display()
        );
    }
}

#[test]
fn every_advisory_has_a_plain_english_playbook_and_checked_date() {
    for path in corpus_files() {
        let doc = load(&path);
        let gd = &doc["database_specific"]["guard_dog"];
        assert!(
            gd.is_object(),
            "{}: no database_specific.guard_dog",
            path.display()
        );

        let playbook = gd["playbook"].as_array().unwrap_or_else(|| {
            panic!(
                "{}: no database_specific.guard_dog.playbook array",
                path.display()
            )
        });
        assert!(
            (2..=4).contains(&playbook.len()),
            "{}: playbook has {} steps, expected 2 to 4",
            path.display(),
            playbook.len()
        );
        assert!(
            playbook.iter().all(is_nonempty_string),
            "{}: a playbook step is empty",
            path.display()
        );

        let conditions = gd["conditions"].as_array().unwrap_or_else(|| {
            panic!(
                "{}: no database_specific.guard_dog.conditions array",
                path.display()
            )
        });
        assert!(
            !conditions.is_empty(),
            "{}: conditions is empty",
            path.display()
        );
        assert!(
            conditions.iter().all(|c| is_nonempty_string(&c["fact"])),
            "{}: every condition needs a \"fact\"",
            path.display()
        );
        for cond in conditions {
            if let Some(problem) = condition_problem(cond) {
                panic!("{}: {problem}", path.display());
            }
        }
        assert!(
            gd["conditions_format"]
                .as_str()
                .is_some_and(|s| s.contains("draft")),
            "{}: conditions_format must say the format is a draft",
            path.display()
        );

        let checked = gd["source_checked"].as_str().unwrap_or("");
        assert!(
            is_calendar_date(checked),
            "{}: source_checked must be a real YYYY-MM-DD date, got {checked:?}",
            path.display()
        );
        let modified = doc["modified"].as_str().unwrap_or("");
        let published = doc["published"].as_str().unwrap_or("");
        assert!(
            published.get(..19) <= modified.get(..19),
            "{}: published ({published}) is after modified ({modified})",
            path.display()
        );
        assert!(
            Some(checked) <= modified.get(..10),
            "{}: source_checked ({checked}) is after modified ({modified})",
            path.display()
        );
    }
}

#[test]
fn every_advisory_says_what_it_affects_and_how_unknown_ranges_are_marked() {
    for path in corpus_files() {
        let doc = load(&path);
        let affected = doc["affected"]
            .as_array()
            .unwrap_or_else(|| panic!("{}: no affected array", path.display()));
        assert!(
            !affected.is_empty(),
            "{}: affected is empty",
            path.display()
        );
        for entry in affected {
            assert!(
                is_nonempty_string(&entry["package"]["ecosystem"])
                    && is_nonempty_string(&entry["package"]["name"]),
                "{}: an affected entry has no package ecosystem and name",
                path.display()
            );
            let ranges = entry["ranges"]
                .as_array()
                .unwrap_or_else(|| panic!("{}: no ranges", path.display()));
            assert!(
                !ranges.is_empty(),
                "{}: an affected entry has no ranges",
                path.display()
            );
            for range in ranges {
                let events = range["events"].as_array().expect("events");
                if let Some(problem) = range_problem(events) {
                    panic!("{}: {problem}", path.display());
                }
                // OSV needs an `introduced` event. When the source gives no start,
                // the record uses "0" and its range_note must say the start is unknown.
                let introduced_zero = events.iter().any(|e| e["introduced"] == "0");
                if introduced_zero {
                    let note = entry["database_specific"]["range_note"]
                        .as_str()
                        .unwrap_or("");
                    assert!(
                        note.to_lowercase().contains("unknown"),
                        "{}: an `introduced: 0` range needs a range_note saying the start is unknown",
                        path.display()
                    );
                }
            }
        }
    }
}

#[test]
fn ids_are_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for path in corpus_files() {
        let id = load(&path)["id"].as_str().expect("id").to_owned();
        assert!(seen.insert(id.clone()), "duplicate advisory id {id}");
    }
}

/// Mutation check: the validator really enforces the schema, so a corpus that
/// "passes" is not passing because the check does nothing.
#[test]
fn validator_rejects_broken_advisories() {
    let validator = schema_validator();
    let good = json!({
        "id": "x_test-advisory",
        "modified": "2026-11-16T00:00:00Z",
        "affected": [{
            "package": {"ecosystem": "Go", "name": "example.com/pkg"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]
        }],
        "references": [{"type": "ADVISORY", "url": "https://example.com/advisory"}]
    });
    assert!(
        validator.is_valid(&good),
        "the known-good example must pass"
    );

    let mut missing_modified = good.clone();
    missing_modified.as_object_mut().unwrap().remove("modified");
    assert!(
        !validator.is_valid(&missing_modified),
        "a missing `modified` must fail"
    );

    let mut bad_prefix = good.clone();
    bad_prefix["id"] = json!("NOPE-2026-1");
    assert!(
        !validator.is_valid(&bad_prefix),
        "an id with an unknown prefix must fail"
    );

    let mut bad_ecosystem = good.clone();
    bad_ecosystem["affected"][0]["package"]["ecosystem"] = json!("NotAnEcosystem");
    assert!(
        !validator.is_valid(&bad_ecosystem),
        "an unknown ecosystem must fail"
    );

    let mut no_introduced = good.clone();
    no_introduced["affected"][0]["ranges"][0]["events"] = json!([{"fixed": "1.0.0"}]);
    assert!(
        !validator.is_valid(&no_introduced),
        "a range with no `introduced` event must fail"
    );

    let mut bad_date = good.clone();
    bad_date["modified"] = json!("16 November 2026");
    assert!(
        !validator.is_valid(&bad_date),
        "a malformed timestamp must fail"
    );

    // These two pass the schema's patterns and only fail on its `format`s.
    let mut impossible_date = good.clone();
    impossible_date["modified"] = json!("2026-02-30T00:00:00Z");
    assert!(
        !validator.is_valid(&impossible_date),
        "a timestamp on a day that does not exist must fail"
    );

    let mut bad_url = good;
    bad_url["references"][0]["url"] = json!("not a web address");
    assert!(
        !validator.is_valid(&bad_url),
        "a reference that is not a URI must fail"
    );
}

/// Mutation check for the corpus's own rules: broken ranges and impossible
/// dates are caught, and correct ones are not.
#[test]
fn custom_checks_reject_broken_ranges_and_dates() {
    let ok = |events: Value| range_problem(events.as_array().unwrap()).is_none();
    assert!(ok(json!([{"introduced": "0"}, {"fixed": "1.0"}])));
    assert!(ok(json!([{"introduced": "0"}])), "an open range is allowed");
    assert!(ok(json!([
        {"introduced": "1.0"}, {"last_affected": "1.2"},
        {"introduced": "2.0"}, {"last_affected": "2.1"}
    ])));
    assert!(!ok(json!([{"fixed": "1.0"}, {"introduced": "0"}])));
    assert!(
        !ok(json!([{"introduced": "0"}, {"fixed": "1.0"}, {"fixed": "2.0"}])),
        "two fixed events in a row must fail"
    );
    assert!(!ok(json!([
        {"introduced": "0"}, {"fixed": "1.0"},
        {"introduced": "2.0"}, {"last_affected": "2.1"}
    ])));
    assert!(!ok(json!([{"introduced": "0"}, {"limit": "abc"}])));

    let chain_ok = |any_of: Value| {
        condition_problem(&json!({"fact": "chain", "any_of": any_of, "required": true})).is_none()
    };
    assert!(chain_ok(json!(["main", "signet", "regtest"])));
    assert!(
        !chain_ok(json!(["testnet"])),
        "a typo in a chain name must fail"
    );
    assert!(!chain_ok(json!(["mainnet"])));
    assert!(!chain_ok(json!([])));
    assert!(!chain_ok(json!([3])));
    assert!(condition_problem(&json!({"fact": "chain"})).is_some());
    assert!(condition_problem(&json!({"fact": "service_running"})).is_none());

    assert!(is_calendar_date("2026-11-16"));
    assert!(is_calendar_date("2024-02-29"));
    assert!(!is_calendar_date("2026-02-29"));
    assert!(!is_calendar_date("1900-02-29"));
    assert!(!is_calendar_date("2026-13-01"));
    assert!(!is_calendar_date("2026-04-31"));
    assert!(!is_calendar_date("2026-11-1"));
    assert!(!is_calendar_date("2026/11/16"));
}
