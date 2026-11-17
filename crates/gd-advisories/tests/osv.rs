//! Phase 2.1, PR 1: OSV records become bounded typed data, and package names
//! get one canonical form.
//!
//! The fixture caller is the real corpus in `advisories/corpus/*.json`, read in
//! sorted order with no network and no clock. The expected values here are read
//! straight from the raw JSON by code that does not use the parser, so a field
//! the parser loses or changes fails a check.

// Test-only crate: helper functions read files and check data, and a panic
// there is a failed check (clippy.toml exempts only `#[test]` functions).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::fs;
use std::path::{Path, PathBuf};

use gd_advisories::{
    Advisory, Ecosystem, Event, GapKind, MAX_AFFECTED, MAX_DEPTH, MAX_GAPS, MAX_RANGES_AND_EVENTS,
    MAX_RECORD_BYTES, MAX_VERSION_BYTES, MAX_VERSIONS, PackageError, RangeKind, Refusal, Source,
    canonical_package, parse_advisory, parse_advisory_from,
};
use proptest::prelude::*;
use serde_json::{Value, json};

// ---------------------------------------------------------------- fixtures

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../advisories/corpus")
}

/// Every corpus file as (file name, raw bytes), sorted.
fn corpus_files() -> Vec<(String, Vec<u8>)> {
    let mut paths: Vec<PathBuf> = fs::read_dir(corpus_dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    paths.sort();
    paths
        .into_iter()
        .map(|p| {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            (name, fs::read(&p).unwrap())
        })
        .collect()
}

fn base() -> Value {
    json!({
        "id": "x_test-1",
        "modified": "2026-11-17T00:00:00Z",
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "Cashu"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}]
        }]
    })
}

fn parse_value(v: &Value) -> Result<Advisory, gd_advisories::OsvError> {
    parse_advisory(v.to_string().as_bytes())
}

fn corpus_parse(bytes: &[u8]) -> Result<Advisory, Refusal> {
    parse_advisory_from(bytes, Source::GuardDogCorpus)
}

fn parse_corpus_value(v: &Value) -> Result<Advisory, Refusal> {
    corpus_parse(v.to_string().as_bytes())
}

fn refused(v: &Value) -> String {
    parse_value(v).unwrap_err().code().to_string()
}

fn text(u: &gd_core::Untrusted<String>) -> &str {
    u.expose_untrusted()
}

// ------------------------------------------------------- the corpus parses

#[test]
fn every_corpus_record_parses_with_no_loss() {
    let files = corpus_files();
    assert_eq!(files.len(), 23);
    for (name, bytes) in &files {
        let raw: Value = serde_json::from_slice(bytes).unwrap();
        let adv = corpus_parse(bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(adv.id.as_str(), raw["id"].as_str().unwrap(), "{name}");
        assert_eq!(
            adv.modified.as_str(),
            raw["modified"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(
            adv.published.as_ref().map(|t| t.as_str()),
            raw["published"].as_str(),
            "{name}"
        );
        assert!(adv.withdrawn.is_none(), "{name}");
        assert_eq!(
            text(adv.summary.as_ref().unwrap()),
            raw["summary"],
            "{name}"
        );
        assert_eq!(
            text(adv.details.as_ref().unwrap()),
            raw["details"],
            "{name}"
        );
        let aliases: Vec<&str> = adv.aliases.iter().map(text).collect();
        let want: Vec<&str> = raw["aliases"]
            .as_array()
            .map(|a| a.iter().map(|v| v.as_str().unwrap()).collect())
            .unwrap_or_default();
        assert_eq!(aliases, want, "{name}");

        let refs: Vec<String> = adv
            .references
            .iter()
            .map(|r| text(&r.url).to_string())
            .collect();
        let want: Vec<String> = raw["references"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["url"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(refs, want, "{name}");

        let gd = &raw["database_specific"]["guard_dog"];
        let playbook: Vec<&str> = adv.curation.playbook.iter().map(text).collect();
        let want: Vec<&str> = gd["playbook"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(playbook, want, "{name}");
        assert_eq!(
            text(adv.curation.source_checked.as_ref().unwrap()),
            gd["source_checked"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(
            adv.curation.conditions.as_ref().unwrap().expose_untrusted(),
            &gd["conditions"],
            "{name}"
        );
        assert_eq!(
            text(adv.curation.primary_source_kind.as_ref().unwrap()),
            raw["database_specific"]["primary_source_kind"]
                .as_str()
                .unwrap(),
            "{name}"
        );
        // The whole database_specific block is kept as data too.
        assert_eq!(
            &Value::Object(adv.extensions.expose_untrusted().clone()),
            &raw["database_specific"],
            "{name}"
        );

        let entries = raw["affected"].as_array().unwrap();
        assert_eq!(adv.affected.len(), entries.len(), "{name}");
        for (got, want) in adv.affected.iter().zip(entries) {
            assert_eq!(
                text(&got.package.ecosystem),
                want["package"]["ecosystem"],
                "{name}"
            );
            assert_eq!(text(&got.package.name), want["package"]["name"], "{name}");
            assert_eq!(
                got.package.purl.as_ref().map(text),
                want["package"]["purl"].as_str(),
                "{name}"
            );
            assert!(got.package.key.is_ok(), "{name}");
            assert!(got.versions.is_empty(), "{name}");
            let ranges = want["ranges"].as_array().unwrap();
            assert_eq!(got.ranges.len(), ranges.len(), "{name}");
            for (gr, wr) in got.ranges.iter().zip(ranges) {
                let kind = match &gr.kind {
                    RangeKind::Semver => "SEMVER",
                    RangeKind::Ecosystem => "ECOSYSTEM",
                    RangeKind::Git => "GIT",
                    other => panic!("{name}: unexpected {other:?}"),
                };
                assert_eq!(kind, wr["type"].as_str().unwrap(), "{name}");
                let events = wr["events"].as_array().unwrap();
                assert_eq!(gr.events.len(), events.len(), "{name}");
                for (ge, we) in gr.events.iter().zip(events) {
                    let (key, value) = match ge {
                        Event::Introduced(v) => ("introduced", text(v)),
                        Event::Fixed(v) => ("fixed", text(v)),
                        Event::LastAffected(v) => ("last_affected", text(v)),
                        Event::Limit(v) => ("limit", text(v)),
                        other => panic!("{name}: unexpected {other:?}"),
                    };
                    assert_eq!(we.as_object().unwrap().len(), 1, "{name}");
                    assert_eq!(we[key].as_str(), Some(value), "{name}");
                }
            }
            // Scope and prose notes are typed, never lost.
            let db = &want["database_specific"];
            assert_eq!(
                got.scope.platform.as_ref().map(text),
                db["platform"].as_str(),
                "{name}"
            );
            assert_eq!(
                got.scope.model.as_ref().map(text),
                db["model"].as_str(),
                "{name}"
            );
        }
        // Everything in the corpus is reviewed: no gaps at all.
        assert!(adv.gaps.is_empty(), "{name}: {:?}", adv.gaps);
    }
}

#[test]
fn corpus_totals_match_the_design() {
    let (mut entries, mut ranges, mut eco, mut semver) = (0, 0, 0, 0);
    let (mut intro, mut fixed, mut last) = (0, 0, 0);
    let (mut git, mut go, mut pypi) = (0, 0, 0);
    for (name, bytes) in corpus_files() {
        let adv = corpus_parse(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        for e in &adv.affected {
            entries += 1;
            match e.package.key.as_ref().unwrap().ecosystem() {
                Ecosystem::Git => git += 1,
                Ecosystem::Go => go += 1,
                Ecosystem::PyPi => pypi += 1,
                _ => panic!("{name}: an ecosystem outside the corpus"),
            }
            for r in &e.ranges {
                ranges += 1;
                match r.kind {
                    RangeKind::Ecosystem => eco += 1,
                    RangeKind::Semver => semver += 1,
                    _ => panic!("{name}: a range type outside the corpus"),
                }
                for ev in &r.events {
                    match ev {
                        Event::Introduced(_) => intro += 1,
                        Event::Fixed(_) => fixed += 1,
                        Event::LastAffected(_) => last += 1,
                        _ => panic!("{name}: an event outside the corpus"),
                    }
                }
            }
        }
    }
    assert_eq!((entries, ranges, eco, semver), (31, 39, 31, 8));
    assert_eq!((intro, fixed, last), (39, 35, 3));
    assert_eq!((git, go, pypi), (23, 7, 1));
}

#[test]
fn corpus_package_names_get_their_canonical_form() {
    let mut keys = std::collections::BTreeSet::new();
    for (_, bytes) in corpus_files() {
        for e in corpus_parse(&bytes).unwrap().affected {
            let k = e.package.key.unwrap();
            keys.insert(format!("{:?} {}", k.ecosystem(), k.name()));
        }
    }
    let want = [
        "Git https://github.com/bitcoin/bitcoin",
        "Git https://github.com/btcpayserver/btcpayserver",
        "Git https://github.com/coldcard/firmware",
        "Git https://github.com/elementsproject/lightning",
        "Git https://github.com/fedimint/fedimint",
        "Git https://github.com/getalby/hub",
        "Git https://github.com/getumbrel/umbrel",
        "Git https://github.com/ride-the-lightning/rtl",
        "Git https://github.com/tukaani-project/xz",
        "Go github.com/lightninglabs/lightning-terminal",
        "Go github.com/lightninglabs/taproot-assets",
        "Go github.com/lightningnetwork/lnd",
        "PyPi cashu",
    ];
    assert_eq!(keys.into_iter().collect::<Vec<_>>(), want);
}

#[test]
fn fixture_scopes_and_the_withheld_flag_are_typed() {
    let mut platforms = Vec::new();
    for (name, bytes) in corpus_files() {
        let adv = corpus_parse(&bytes).unwrap();
        for e in &adv.affected {
            if let Some(p) = &e.scope.platform {
                platforms.push(text(p).to_string());
            }
        }
        let want = (name == "x_cln-2026-v26.06.8-unspecified-vulnerabilities.json").then_some(true);
        assert_eq!(adv.curation.details_withheld_by_vendor, want, "{name}");
    }
    platforms.sort();
    assert_eq!(
        platforms,
        [
            "32-bit systems, or blocks stored on a FAT32 file system",
            "64-bit systems, including Windows"
        ]
    );
}

// ------------------------------------------------- hostile and big records

#[test]
fn hostile_and_oversized_records_are_refused_with_named_errors() {
    let code = |bytes: &[u8]| parse_advisory(bytes).unwrap_err().code();

    // Not JSON at all, bad UTF-8, trailing bytes, wrong top level.
    assert_eq!(code(b""), "not_json");
    assert_eq!(code(b"{"), "not_json");
    assert_eq!(code(b"\xff\xfe{}"), "not_json");
    assert_eq!(
        code(br#"{"id":"a","modified":"2026-11-17T00:00:00Z"} x"#),
        "trailing_data"
    );
    assert_eq!(code(b"[]"), "not_an_object");
    assert_eq!(code(b"null"), "not_an_object");
    assert_eq!(code(br#"{"x": 1e999}"#), "not_json");

    // Size: one byte over the cap is refused before any parsing.
    let mut big = base().to_string().into_bytes();
    big.resize(MAX_RECORD_BYTES + 1, b' ');
    assert_eq!(code(&big), "record_too_large");

    // Depth: exactly the limit is fine, one more is refused, and an absurd
    // nesting neither overflows the stack nor panics.
    let nested = |n: usize| {
        let mut v = Value::Null;
        for _ in 0..n {
            v = Value::Array(vec![v]);
        }
        let mut r = base();
        r["database_specific"] = json!({ "deep": v });
        r.to_string().into_bytes()
    };
    // The record itself is depth 1, `database_specific` 2, then the arrays.
    assert!(parse_advisory(&nested(MAX_DEPTH - 2)).is_ok());
    assert_eq!(code(&nested(MAX_DEPTH - 1)), "too_deep");
    let mut absurd = vec![b'['; 200_000];
    absurd.extend(vec![b']'; 200_000]);
    assert_eq!(code(&absurd), "too_deep");
    let mut absurd_obj = br#"{"a":"#.repeat(100_000);
    absurd_obj.extend(b"1");
    assert_eq!(code(&absurd_obj), "too_deep");

    // Duplicate keys, at the top and nested, even with equal values.
    assert_eq!(
        code(br#"{"id":"a","id":"a","modified":"2026-11-17T00:00:00Z"}"#),
        "duplicate_key"
    );
    assert_eq!(
        code(br#"{"id":"a","modified":"2026-11-17T00:00:00Z","database_specific":{"k":1,"k":1}}"#),
        "duplicate_key"
    );
}

#[test]
fn malformed_records_are_refused_with_named_errors() {
    let with = |key: &str, value: Value| {
        let mut r = base();
        r[key] = value;
        r
    };
    let without = |key: &str| {
        let mut r = base();
        r.as_object_mut().unwrap().remove(key);
        r
    };
    assert_eq!(refused(&without("id")), "missing_field");
    assert_eq!(refused(&without("modified")), "missing_field");
    assert_eq!(refused(&with("id", json!(7))), "wrong_type");
    for bad in ["", "../etc", "a/b", "-x", ".x", "a b", "a\u{1b}[31m", "é"] {
        assert_eq!(refused(&with("id", json!(bad))), "bad_id", "{bad:?}");
    }
    assert_eq!(refused(&with("id", json!("a".repeat(129)))), "bad_id");
    for bad in [
        "yesterday",
        "2026-11-17",
        "2026-11-17T00:00:00",
        "2026-11-17T00:00:00+01:00",
        "2026-13-17T00:00:00Z",
        "2026-02-30T00:00:00Z",
        "2026-11-17T24:00:00Z",
        "2026-11-17T00:60:00Z",
        "2026-11-17T00:00:00.Z",
    ] {
        assert_eq!(
            refused(&with("modified", json!(bad))),
            "bad_timestamp",
            "{bad}"
        );
        // A bad withdrawn date must not quietly read as "not withdrawn".
        assert_eq!(
            refused(&with("withdrawn", json!(bad))),
            "bad_timestamp",
            "{bad}"
        );
    }
    assert_eq!(refused(&with("affected", json!({}))), "wrong_type");
    assert_eq!(refused(&with("affected", json!(["x"]))), "wrong_type");
    let entry = |e: Value| with("affected", json!([e]));
    let pkg = json!({"ecosystem": "Go", "name": "example.test/m"});
    assert_eq!(refused(&entry(json!({}))), "missing_field");
    assert_eq!(
        refused(&entry(json!({"package": {"name": "x"}}))),
        "missing_field"
    );
    assert_eq!(
        refused(&entry(
            json!({"package": {"ecosystem": "Go", "name": "n".repeat(513)}})
        )),
        "too_long"
    );
    assert_eq!(
        refused(&entry(
            json!({"package": pkg, "ranges": [{"type": "SEMVER"}]})
        )),
        "missing_field"
    );
    // Event shapes: two kinds at once, none, or a non-string value.
    let events =
        |e: Value| entry(json!({"package": pkg, "ranges": [{"type": "SEMVER", "events": [e]}]}));
    assert_eq!(
        refused(&events(json!({"introduced": "0", "fixed": "1"}))),
        "bad_event"
    );
    assert_eq!(refused(&events(json!({}))), "bad_event");
    assert_eq!(refused(&events(json!("introduced"))), "bad_event");
    assert_eq!(refused(&events(json!({"introduced": 0}))), "bad_event");
    assert_eq!(
        refused(&events(json!({"fixed": "9".repeat(MAX_VERSION_BYTES + 1)}))),
        "too_long"
    );
    assert!(parse_value(&events(json!({"fixed": "9".repeat(MAX_VERSION_BYTES)}))).is_ok());
}

#[test]
fn every_budget_is_enforced_without_truncating() {
    let entry = |extra: Value| {
        let mut e = json!({"package": {"ecosystem": "Go", "name": "example.test/m"}});
        for (k, v) in extra.as_object().unwrap() {
            e[k] = v.clone();
        }
        e
    };
    let rec = |entries: Vec<Value>| {
        let mut r = base();
        r["affected"] = Value::Array(entries);
        r
    };

    let at_limit = rec((0..MAX_AFFECTED)
        .map(|_| entry(json!({"versions": ["1"]})))
        .collect());
    assert_eq!(parse_value(&at_limit).unwrap().affected.len(), MAX_AFFECTED);
    let over = rec((0..=MAX_AFFECTED)
        .map(|_| entry(json!({"versions": ["1"]})))
        .collect());
    assert_eq!(refused(&over), "too_many");

    // Listed versions: 10,000 across the record is fine, 10,001 is not.
    let versions = |n: usize| Value::Array((0..n).map(|i| json!(format!("1.{i}"))).collect());
    let split = |n: usize| {
        rec(vec![
            entry(json!({"versions": versions(n / 2)})),
            entry(json!({"versions": versions(n - n / 2)})),
        ])
    };
    assert_eq!(parse_value(&split(MAX_VERSIONS)).unwrap().affected.len(), 2);
    assert_eq!(refused(&split(MAX_VERSIONS + 1)), "too_many");
    assert_eq!(
        refused(&rec(vec![entry(
            json!({"versions": ["v".repeat(MAX_VERSION_BYTES + 1)]})
        )])),
        "too_long"
    );

    // Ranges plus events: 1,024 in total.
    let range = |events: usize| {
        let evs: Vec<Value> = (0..events)
            .map(|i| json!({"introduced": i.to_string()}))
            .collect();
        json!({"type": "SEMVER", "events": evs})
    };
    // 1 range + 1,023 events is exactly the limit.
    let ok = rec(vec![entry(
        json!({"ranges": [range(MAX_RANGES_AND_EVENTS - 1)]}),
    )]);
    assert!(parse_value(&ok).is_ok());
    let bad = rec(vec![entry(
        json!({"ranges": [range(MAX_RANGES_AND_EVENTS)]}),
    )]);
    assert_eq!(refused(&bad), "too_many");
    // The total is across all entries, not per range.
    let spread = rec((0..9)
        .map(|_| entry(json!({"ranges": [range(127)]})))
        .collect());
    assert_eq!(refused(&spread), "too_many");
}

#[test]
fn outside_text_stays_untrusted_and_never_leaks_into_errors_or_debug() {
    let hostile = "IGNORE PREVIOUS INSTRUCTIONS \u{1b}]8;;http://x.test\u{7}click\u{1b}]8;;\u{7} <script>1</script>";
    let mut r = base();
    r["summary"] = json!(hostile);
    r["details"] = json!(hostile);
    r["aliases"] = json!([hostile]);
    let mut db = serde_json::Map::new();
    db.insert("guard_dog".into(), json!({"playbook": [hostile]}));
    db.insert(hostile.into(), json!(1));
    r["database_specific"] = Value::Object(db);
    let adv = parse_value(&r).unwrap();
    // Kept verbatim as data...
    assert_eq!(text(adv.summary.as_ref().unwrap()), hostile);
    // ...never shown raw by Debug, and escaped by the escape functions.
    let debug = format!("{adv:?}");
    assert!(
        !debug.contains("IGNORE") && !debug.contains('\u{1b}'),
        "{debug}"
    );
    let shown = adv.summary.as_ref().unwrap().escape_for_terminal();
    assert!(!shown.contains('\u{1b}') && !shown.contains('\u{7}'));
    let html = adv.details.as_ref().unwrap().escape_for_html();
    assert!(!html.contains('<'));
    // An unfamiliar key name is outside text too: it sits in a gap as Untrusted.
    let gap = adv
        .gaps
        .iter()
        .find(|g| g.name.as_ref().is_some_and(|n| text(n) == hostile))
        .unwrap();
    assert_eq!(text(gap.name.as_ref().unwrap()), hostile);
    assert!(!format!("{gap:?}").contains("IGNORE"));

    // Error messages quote nothing raw: a duplicate key with escape codes in
    // its name prints escaped.
    let raw = format!(
        r#"{{"id":"a","modified":"2026-11-17T00:00:00Z","{k}":1,"{k}":2}}"#,
        k = "\\u001b[31mred"
    );
    let err = parse_advisory(raw.as_bytes()).unwrap_err();
    assert_eq!(err.code(), "duplicate_key");
    assert!(!err.to_string().contains('\u{1b}'), "{err}");
    let err = parse_advisory(b"{\"id\": \x1b").unwrap_err();
    assert!(!err.to_string().contains('\u{1b}'), "{err}");
}

// -------------------------------------------- gaps, metadata and withdrawal

#[test]
fn unknown_fields_become_explicit_gaps_never_silent_drops() {
    let mut r = base();
    r["x_future"] = json!({"a": 1});
    r["affected"][0]["x_applicability"] = json!("yes");
    r["affected"][0]["package"]["x_arch"] = json!("arm");
    r["affected"][0]["ranges"][0]["x_graph"] = json!(1);
    r["affected"][0]["ranges"][0]["type"] = json!("FUTURE");
    r["affected"][0]["ranges"][0]["events"] =
        json!([{"introduced": "0"}, {"x_cond": "1"}, {"fixed": "2"}]);
    r["affected"][0]["database_specific"] = json!({"platform": "arm only", "x_new": 1});
    r["database_specific"] = json!({"x_top": 1, "guard_dog": {"x_inner": 1, "playbook": ["a"]}});
    let adv = parse_corpus_value(&r).unwrap();

    let got: Vec<(GapKind, String, Option<String>)> = adv
        .gaps
        .iter()
        .map(|g| {
            (
                g.kind,
                g.at.clone(),
                g.name.as_ref().map(|n| text(n).to_string()),
            )
        })
        .collect();
    let g = |kind, at: &str, name: Option<&str>| (kind, at.to_string(), name.map(String::from));
    assert_eq!(
        got,
        [
            g(GapKind::UnknownField, "", Some("x_future")),
            g(
                GapKind::UnreviewedExtension,
                "database_specific",
                Some("x_top")
            ),
            g(
                GapKind::UnreviewedExtension,
                "database_specific.guard_dog",
                Some("x_inner")
            ),
            g(
                GapKind::UnknownField,
                "affected[0]",
                Some("x_applicability")
            ),
            g(GapKind::UnknownField, "affected[0].package", Some("x_arch")),
            g(
                GapKind::UnknownRangeType,
                "affected[0].ranges[0]",
                Some("FUTURE")
            ),
            g(
                GapKind::UnknownField,
                "affected[0].ranges[0]",
                Some("x_graph")
            ),
            g(
                GapKind::UnknownEventKind,
                "affected[0].ranges[0].events[1]",
                Some("x_cond")
            ),
            g(
                GapKind::UnreviewedExtension,
                "affected[0].database_specific",
                Some("x_new")
            ),
        ]
    );
    // The unknown range type and the unknown event are still in the data, in
    // position, so a later evaluator can poison that range instead of skipping it.
    let range = &adv.affected[0].ranges[0];
    assert!(matches!(&range.kind, RangeKind::Unsupported(t) if text(t) == "FUTURE"));
    assert_eq!(range.events.len(), 3);
    assert!(matches!(range.events[1], Event::Unrecognised));
    // The raw extension block is kept whole.
    assert_eq!(
        adv.extensions.expose_untrusted().get("x_top"),
        Some(&json!(1))
    );
    // Same input, same gaps in the same order.
    assert_eq!(
        format!("{:?}", parse_corpus_value(&r).unwrap().gaps),
        format!("{:?}", adv.gaps)
    );
}

#[test]
fn entries_that_cannot_be_evaluated_are_gaps_not_clearance() {
    let mut r = base();
    r["affected"] = json!([
        {"package": {"ecosystem": "PyPI", "name": "cashu"}},
        {"package": {"ecosystem": "PyPI", "name": "cashu"}, "ranges": [{"type": "SEMVER", "events": []}]},
        {"package": {"ecosystem": "npm", "name": "left-pad"}, "versions": ["1.0.0"]},
        {"package": {"ecosystem": "GIT", "name": "https://u:p@example.test/a/b"}, "versions": ["1"]},
        {"package": {"ecosystem": "Go", "name": "example.test/m"}, "versions": []},
    ]);
    let adv = parse_value(&r).unwrap();
    let got: Vec<(GapKind, &str)> = adv.gaps.iter().map(|g| (g.kind, g.at.as_str())).collect();
    assert_eq!(
        got,
        [
            (GapKind::NoRangeOrVersions, "affected[0]"),
            (GapKind::EmptyRange, "affected[1].ranges[0]"),
            (GapKind::NoRangeOrVersions, "affected[1]"),
            (
                GapKind::PackageIdentity(PackageError::UnsupportedEcosystem),
                "affected[2].package"
            ),
            (
                GapKind::PackageIdentity(PackageError::Credentials),
                "affected[3].package"
            ),
            (GapKind::NoRangeOrVersions, "affected[4]"),
        ]
    );
    assert!(adv.affected[2].package.key.is_err());
    // And a record with no affected entries at all says so.
    let mut empty = base();
    empty["affected"] = json!([]);
    assert_eq!(
        parse_value(&empty).unwrap().gaps[0].kind,
        GapKind::NoAffectedEntries
    );
    let mut none = base();
    none.as_object_mut().unwrap().remove("affected");
    assert_eq!(
        parse_value(&none).unwrap().gaps[0].kind,
        GapKind::NoAffectedEntries
    );
}

#[test]
fn metadata_withdrawal_and_gaps_are_three_different_things() {
    let mut r = base();
    r["published"] = json!("2024-03-29T00:00:00.5Z");
    r["aliases"] = json!(["CVE-2024-0001", "GHSA-aaaa-bbbb-cccc"]);
    r["related"] = json!(["CVE-2024-0002"]);
    r["upstream"] = json!(["CVE-2024-0003"]);
    r["schema_version"] = json!("1.9.2");
    r["severity"] = json!([{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "source": "CNA"}]);
    r["references"] = json!([{"type": "ADVISORY", "url": "https://example.test/a"}, {"type": "WEIRD", "url": "https://example.test/b"}]);
    r["credits"] = json!([{"name": "A. Person"}]);
    r["affected"][0]["severity"] = json!([{"type": "Ubuntu", "score": "high"}]);
    let adv = parse_value(&r).unwrap();
    assert!(adv.gaps.is_empty(), "{:?}", adv.gaps);
    assert!(!adv.is_withdrawn());
    assert_eq!(
        adv.published.as_ref().unwrap().as_str(),
        "2024-03-29T00:00:00.5Z"
    );
    assert_eq!(adv.aliases.len(), 2);
    assert_eq!((adv.related.len(), adv.upstream.len()), (1, 1));
    assert_eq!(adv.severity.len(), 1);
    assert_eq!(
        text(&adv.severity[0].score),
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    );
    assert_eq!(adv.affected[0].severity.len(), 1);
    assert_eq!(adv.references.len(), 2);
    assert!(adv.credits.is_some());
    assert_eq!(text(adv.schema_version.as_ref().unwrap()), "1.9.2");

    // Withdrawn: the date is kept and there is no gap.
    r["withdrawn"] = json!("2026-11-01T12:00:00Z");
    let adv = parse_value(&r).unwrap();
    assert!(adv.is_withdrawn());
    assert_eq!(
        adv.withdrawn.as_ref().unwrap().as_str(),
        "2026-11-01T12:00:00Z"
    );
    assert!(adv.gaps.is_empty());

    // A gap does not make a record withdrawn, and a withdrawn record keeps its gaps.
    let mut gappy = base();
    gappy["x_new"] = json!(1);
    let adv = parse_value(&gappy).unwrap();
    assert!(!adv.is_withdrawn());
    assert_eq!(adv.gaps.len(), 1);
    gappy["withdrawn"] = json!("2026-11-01T12:00:00Z");
    let adv = parse_value(&gappy).unwrap();
    assert!(adv.is_withdrawn());
    assert_eq!(adv.gaps.len(), 1);

    // An unfamiliar schema version is visible, not silently trusted.
    let mut odd = base();
    odd["schema_version"] = json!("2.0.0");
    assert_eq!(
        parse_value(&odd).unwrap().gaps[0].kind,
        GapKind::UnexpectedSchemaVersion
    );
}

// ------------------------------------------------ package canonicalisation

fn canon(eco: &str, name: &str) -> Result<String, PackageError> {
    canonical_package(eco, name).map(|k| k.name().to_string())
}

#[test]
fn pypi_names_follow_pep_503() {
    for (raw, want) in [
        ("cashu", "cashu"),
        ("Cashu", "cashu"),
        ("CASHU", "cashu"),
        ("cashu_x", "cashu-x"),
        ("Cashu.X", "cashu-x"),
        ("Foo.Bar__baz", "foo-bar-baz"),
        ("a--b", "a-b"),
        ("a-._b", "a-b"),
        ("A", "a"),
        ("0", "0"),
    ] {
        assert_eq!(canon("PyPI", raw), Ok(want.to_string()), "{raw}");
    }
    for bad in [
        "", "-a", "a-", ".a", "a_", "a b", "a/b", "é", "a\u{1b}", "a@b",
    ] {
        assert!(canon("PyPI", bad).is_err(), "{bad:?}");
    }
    assert_eq!(canon("PyPI", &"a".repeat(513)), Err(PackageError::TooLong));
}

#[test]
fn go_module_paths_are_exact_and_case_sensitive() {
    for same in [
        "github.com/lightningnetwork/lnd",
        "github.com/LightningNetwork/lnd",
        "github.com/lightningnetwork/lnd/v2",
        "golang.org/x/mod",
        "example.test/a_b~c",
    ] {
        assert_eq!(canon("Go", same), Ok(same.to_string()));
    }
    assert_ne!(canon("Go", "github.com/A/b"), canon("Go", "github.com/a/b"));
    assert_ne!(
        canon("Go", "example.test/m"),
        canon("Go", "example.test/m/v2")
    );
    for bad in ["", "a b", "a?b", "a#b", "a@b", "é.test/m", "a\u{1b}", "a:b"] {
        assert!(canon("Go", bad).is_err(), "{bad:?}");
    }
}

#[test]
fn git_urls_collapse_to_one_form() {
    for (raw, want) in [
        (
            "https://github.com/bitcoin/bitcoin",
            "https://github.com/bitcoin/bitcoin",
        ),
        (
            "https://github.com/bitcoin/bitcoin/",
            "https://github.com/bitcoin/bitcoin",
        ),
        (
            "https://github.com/bitcoin/bitcoin.git",
            "https://github.com/bitcoin/bitcoin",
        ),
        (
            "https://github.com/bitcoin/bitcoin.git/",
            "https://github.com/bitcoin/bitcoin",
        ),
        (
            "https://github.com/bitcoin/bitcoin///",
            "https://github.com/bitcoin/bitcoin",
        ),
        (
            "HTTPS://GitHub.COM/Bitcoin/BITCOIN.git",
            "https://github.com/bitcoin/bitcoin",
        ),
        (
            "https://github.com/ElementsProject/lightning.git",
            "https://github.com/elementsproject/lightning",
        ),
        ("http://github.com/a/b", "http://github.com/a/b"),
        (
            "git://example.test/Team/Repo.git",
            "git://example.test/Team/Repo",
        ),
        (
            "https://GitLab.test/Group/Sub/Repo.git/",
            "https://gitlab.test/Group/Sub/Repo",
        ),
        (
            "https://example.test:08080/A/b",
            "https://example.test:8080/A/b",
        ),
        ("ssh://example.test/a/b.git", "ssh://example.test/a/b"),
    ] {
        assert_eq!(canon("GIT", raw), Ok(want.to_string()), "{raw}");
    }
    // Path case is kept off GitHub: these are different repositories.
    assert_ne!(
        canon("GIT", "https://example.test/A/b"),
        canon("GIT", "https://example.test/a/b")
    );
    // http and https are not merged, and a host is not guessed from a sibling.
    assert_ne!(
        canon("GIT", "http://github.com/a/b"),
        canon("GIT", "https://github.com/a/b")
    );
    assert_ne!(
        canon("GIT", "https://github.com/a/b"),
        canon("GIT", "https://www.github.com/a/b")
    );
    assert_ne!(
        canon("GIT", "https://github.com/a/b"),
        canon("GIT", "https://github.com/a/c")
    );
    // The same text in two ecosystems is two packages.
    assert_ne!(
        canonical_package("Go", "a.test/b").unwrap(),
        canonical_package("PyPI", "a.test-b").unwrap()
    );
}

#[test]
fn ambiguous_or_unsupported_git_forms_are_refused_with_a_reason() {
    use PackageError as E;
    for (raw, want) in [
        ("", E::Empty),
        ("github.com/a/b", E::NotAUrl),
        ("git@github.com:a/b.git", E::NotAUrl),
        ("ftp://example.test/a/b", E::UnsupportedScheme),
        ("file:///a/b", E::UnsupportedScheme),
        ("https://user:pw@example.test/a/b", E::Credentials),
        ("https://git@example.test/a/b", E::Credentials),
        ("https://example.test/a/b?ref=x", E::Query),
        ("https://example.test/a/b#frag", E::Fragment),
        ("https://example.test/a%2fb", E::PercentEncoding),
        ("https://example.test", E::EmptyPath),
        ("https://example.test/", E::EmptyPath),
        ("https://example.test/.git", E::AmbiguousSuffix),
        ("https://example.test/a.git.git", E::AmbiguousSuffix),
        ("https://example.test/a.git/.git", E::AmbiguousSuffix),
        ("https://example.test/a/../b", E::BadPathSegment),
        ("https://example.test/a/./b", E::BadPathSegment),
        ("https://example.test/a//b", E::BadPathSegment),
        ("https://github.com/a", E::NotARepository),
        ("https://github.com/a/b/tree/main", E::NotARepository),
        ("https://[::1]/a", E::BadHost),
        ("https://exa mple.test/a", E::BadCharacters),
        ("https://example.test/a b", E::BadCharacters),
        ("https://example.test/é", E::BadCharacters),
        ("https://example.test/a\\b", E::BadCharacters),
        ("https://-bad.test/a", E::BadHost),
        ("https://a..test/a", E::BadHost),
        ("https://:80/a", E::BadHost),
        ("https://example.test:/a", E::BadPort),
        ("https://example.test:0/a", E::BadPort),
        ("https://example.test:65536/a", E::BadPort),
        ("https://example.test:80a/a", E::BadPort),
    ] {
        assert_eq!(canon("GIT", raw), Err(want), "{raw:?}");
    }
    assert_eq!(canon("npm", "left-pad"), Err(E::UnsupportedEcosystem));
    assert_eq!(canon("pypi", "cashu"), Err(E::UnsupportedEcosystem));
    assert_eq!(canon("PyPI:x", "cashu"), Err(E::UnsupportedEcosystem));
    assert_eq!(
        canon("GIT", &format!("https://example.test/{}", "a".repeat(600))),
        Err(E::TooLong)
    );
}

// -------------------------------------------------------- property tests

/// The seed every property test uses unless `GD_PROPTEST_SEED` says otherwise
/// (the nightly run does). No failure files: a failure becomes an explicit
/// regression test above.
const SEED: u64 = 0x0000_0000_2026_1117;

fn config() -> ProptestConfig {
    static ANNOUNCE: std::sync::Once = std::sync::Once::new();
    let seed = std::env::var("GD_PROPTEST_SEED")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(SEED);
    ANNOUNCE.call_once(|| eprintln!("GD_PROPTEST_SEED={seed} (property test seed in use)"));
    ProptestConfig {
        cases: 1024,
        failure_persistence: None,
        rng_seed: proptest::test_runner::RngSeed::Fixed(seed),
        ..ProptestConfig::default()
    }
}

/// Text shaped like a name or a URL, so most cases get past the refusals and
/// reach the assertion (a test below counts how many do).
fn eco_and_name() -> impl Strategy<Value = (&'static str, String)> {
    let git = prop_oneof![
        "[ -~]{0,30}",
        "(https?|git|ssh|ftp)://[A-Za-z0-9.:@?#%-]{0,12}(/[A-Za-z0-9._~%-]{0,8}){0,4}/{0,2}(\\.git)?",
        "(https?|git)://[A-Za-z]{1,6}\\.[a-z]{2,3}(:[0-9]{1,5})?(/[A-Za-z0-9_-]{1,6}){1,3}(\\.git)?/?",
    ];
    prop_oneof![
        git.prop_map(|n| ("GIT", n)),
        prop_oneof!["[ -~]{0,30}", go_path()].prop_map(|n| ("Go", n)),
        prop_oneof!["[ -~]{0,30}", "[A-Za-z0-9][A-Za-z0-9._-]{0,15}"].prop_map(|n| ("PyPI", n)),
    ]
}

/// A real corpus record (or the base record) with a few random mutations, as bytes.
fn mutated_record() -> impl Strategy<Value = Vec<u8>> {
    static RECORDS: std::sync::OnceLock<Vec<Value>> = std::sync::OnceLock::new();
    let records = RECORDS.get_or_init(|| {
        let mut all: Vec<Value> = corpus_files()
            .iter()
            .map(|(_, b)| serde_json::from_slice(b).unwrap())
            .collect();
        all.push(base());
        all
    });
    let count = records.len();
    (
        0..count,
        prop::collection::vec(
            (any::<u8>(), any::<usize>(), any::<usize>(), 0usize..4),
            0..5,
        ),
    )
        .prop_map(move |(i, mutations)| {
            let mut record = records[i].clone();
            for (op, seed, arg, steps) in mutations {
                mutate(&mut record, steps, seed, op, arg);
            }
            record.to_string().into_bytes()
        })
}

fn child_mut(v: &mut Value, n: usize) -> Option<&mut Value> {
    match v {
        Value::Object(o) => {
            let key = o.keys().nth(n % o.len().max(1))?.clone();
            o.get_mut(&key)
        }
        Value::Array(a) => {
            let len = a.len().max(1);
            a.get_mut(n % len)
        }
        _ => None,
    }
}

fn mutate(v: &mut Value, steps: usize, seed: usize, op: u8, arg: usize) {
    if steps > 0
        && let Some(child) = child_mut(v, seed)
    {
        return mutate(child, steps - 1, seed / 3 + 1, op, arg);
    }
    let replacement = |arg: usize| match arg % 7 {
        0 => Value::Null,
        1 => json!(1),
        2 => json!("x"),
        3 => json!([]),
        4 => json!({}),
        5 => json!(true),
        _ => json!(1.5),
    };
    match (v, op % 6) {
        (Value::Object(o), op) => {
            let Some(key) = o.keys().nth(seed % o.len().max(1)).cloned() else {
                return;
            };
            match op {
                0 => drop(o.remove(&key)),
                1 => drop(o.insert(key, replacement(arg))),
                2 => {
                    if let Some(c) = o.get_mut(&key) {
                        for _ in 0..arg % 70 {
                            *c = Value::Array(vec![c.take()]);
                        }
                    }
                }
                3 => {
                    if let Some(c) = o.remove(&key) {
                        o.insert("x_new".into(), c);
                    }
                }
                4 => drop(o.insert(key, Value::String("a".repeat(arg % 5000)))),
                _ => {
                    if let Some(c) = o.get(&key).cloned() {
                        o.insert("x_dup".into(), c);
                    }
                }
            }
        }
        (Value::Array(a), op) => {
            let len = a.len();
            if len == 0 {
                a.push(replacement(arg));
                return;
            }
            let at = seed % len;
            match op {
                0 => drop(a.remove(at)),
                1 => a[at] = replacement(arg),
                2 => {
                    for _ in 0..arg % 70 {
                        a[at] = Value::Array(vec![a[at].take()]);
                    }
                }
                4 => a[at] = Value::String("a".repeat(arg % 5000)),
                _ => a.push(a[at].clone()),
            }
        }
        (leaf, _) => *leaf = replacement(arg),
    }
}

/// A Go module path: `/`-joined elements that are never empty, `.` or `..`.
fn go_path() -> impl Strategy<Value = String> {
    prop::collection::vec("[A-Za-z0-9_~-][A-Za-z0-9._~-]{0,5}", 1..4).prop_map(|v| v.join("/"))
}

/// A repository or owner name with no dots, so `.git` handling is the only
/// thing that can make two of them collide.
fn word() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_-]{1,12}"
}

fn host() -> impl Strategy<Value = String> {
    "[A-Za-z0-9]{1,8}(\\.[A-Za-z0-9]{1,8}){0,2}"
}

fn scheme() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("http"), Just("https"), Just("git"), Just("ssh")]
}

/// Dressing that must not change a GitHub identity: scheme and host case,
/// a `.git` suffix and trailing slashes.
fn dress(scheme: &str, owner: &str, repo: &str, upper: bool, git: bool, slashes: usize) -> String {
    let mut s = format!("{scheme}://github.com/{owner}/{repo}");
    if upper {
        s = format!(
            "{}://GITHUB.com/{owner}/{repo}",
            scheme.to_ascii_uppercase()
        );
    }
    if git {
        s.push_str(".git");
    }
    s.push_str(&"/".repeat(slashes));
    s
}

proptest! {
    #![proptest_config(config())]

    /// Whatever text comes in, nothing panics, and whatever comes out is a
    /// fixed point: canonicalising it again changes nothing.
    #[test]
    fn canonical_form_is_idempotent_for_any_input((eco, raw) in eco_and_name()) {
        if let Ok(k) = canonical_package(eco, &raw) {
            prop_assert_eq!(canonical_package(eco, k.name()), Ok(k));
        }
    }

    #[test]
    fn canonical_git_urls_are_idempotent(
        s in scheme(), h in host(), segs in prop::collection::vec(word(), 1..4),
        git in any::<bool>(), slashes in 0usize..3, port in prop::option::of(0u32..70000),
    ) {
        let mut url = format!("{s}://{h}");
        if let Some(p) = port { url.push_str(&format!(":{p}")); }
        url.push('/');
        url.push_str(&segs.join("/"));
        if git { url.push_str(".git"); }
        url.push_str(&"/".repeat(slashes));
        if let Ok(k) = canonical_package("GIT", &url) {
            prop_assert_eq!(canonical_package("GIT", k.name()), Ok(k));
        }
    }

    #[test]
    fn github_variants_collapse(
        s in scheme(), owner in word(), repo in word(),
        a in (any::<bool>(), any::<bool>(), 0usize..3), b in (any::<bool>(), any::<bool>(), 0usize..3),
    ) {
        let one = dress(s, &owner, &repo, a.0, a.1, a.2);
        let two = dress(s, &owner.to_ascii_uppercase(), &repo.to_ascii_lowercase(), b.0, b.1, b.2);
        let plain = format!("{s}://github.com/{}/{}", owner.to_ascii_lowercase(), repo.to_ascii_lowercase());
        let (k1, k2, kp) = (
            canonical_package("GIT", &one).unwrap(),
            canonical_package("GIT", &two).unwrap(),
            canonical_package("GIT", &plain).unwrap(),
        );
        prop_assert_eq!(&k1, &k2);
        prop_assert_eq!(&k1, &kp);
        prop_assert_eq!(k1.name(), &plain);
    }

    #[test]
    fn distinct_git_repositories_stay_distinct(
        h in host(), o1 in word(), r1 in word(), o2 in word(), r2 in word(), git in any::<bool>(),
    ) {
        // Off GitHub the path keeps its case, so only identical paths collapse.
        let url = |o: &str, r: &str| format!("https://{h}.example/{o}/{r}{}", if git { ".git" } else { "" });
        let (k1, k2) = (
            canonical_package("GIT", &url(&o1, &r1)).unwrap(),
            canonical_package("GIT", &url(&o2, &r2)).unwrap(),
        );
        prop_assert_eq!(k1 == k2, (&o1, &r1) == (&o2, &r2));
        // On GitHub only case differences collapse.
        let gh = |o: &str, r: &str| canonical_package("GIT", &format!("https://github.com/{o}/{r}")).unwrap();
        prop_assert_eq!(
            gh(&o1, &r1) == gh(&o2, &r2),
            (o1.to_ascii_lowercase(), r1.to_ascii_lowercase()) == (o2.to_ascii_lowercase(), r2.to_ascii_lowercase())
        );
    }

    #[test]
    fn pypi_variants_collapse_and_distinct_names_stay_distinct(
        parts in prop::collection::vec("[A-Za-z0-9]{1,6}", 1..5),
        seps in prop::collection::vec(prop::sample::select(vec!["-", "_", ".", "--", "-_", "._-"]), 4),
        other in prop::collection::vec("[A-Za-z0-9]{1,6}", 1..5),
    ) {
        let join = |parts: &[String], seps: &[&str]| {
            let mut s = parts[0].clone();
            for (p, sep) in parts[1..].iter().zip(seps) { s.push_str(sep); s.push_str(p); }
            s
        };
        let plain = join(&parts, &["-"; 4]);
        let messy = join(&parts, &seps).to_ascii_uppercase();
        prop_assert_eq!(canonical_package("PyPI", &messy), canonical_package("PyPI", &plain));
        let lower = |p: &[String]| p.iter().map(|s| s.to_ascii_lowercase()).collect::<Vec<_>>();
        let a = canonical_package("PyPI", &plain).unwrap();
        let b = canonical_package("PyPI", &join(&other, &["-"; 4])).unwrap();
        prop_assert_eq!(a == b, lower(&parts) == lower(&other));
    }

    #[test]
    fn go_paths_are_equal_only_when_identical(a in go_path(), b in go_path()) {
        let (ka, kb) = (canonical_package("Go", &a).unwrap(), canonical_package("Go", &b).unwrap());
        prop_assert_eq!(ka.name(), a.as_str());
        prop_assert_eq!(ka == kb, a == b);
    }

    /// Hostile or random bytes never panic the intake: they parse or are refused.
    #[test]
    fn random_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..400)) {
        let _ = parse_advisory(&bytes);
    }

    /// Real records with fields dropped, retyped, nested, renamed, stuffed and
    /// duplicated: the intake parses or refuses them, within its bounds, and
    /// never panics. (The next test shows most of these get past the JSON reader.)
    #[test]
    fn mutated_records_parse_or_refuse_within_bounds(bytes in mutated_record()) {
        for source in [Source::GuardDogCorpus, Source::External] {
            match parse_advisory_from(&bytes, source) {
                Ok(adv) => {
                    prop_assert!(adv.gaps.len() <= MAX_GAPS + 1);
                    prop_assert!(adv.affected.len() <= MAX_AFFECTED);
                }
                Err(refusal) => prop_assert!(!refusal.error.code().is_empty()),
            }
        }
    }
}

// ------------------------------------------------ reach and generator quality

#[test]
fn the_property_generators_reach_their_assertions() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    let mut runner = TestRunner::new(config());
    let names = eco_and_name();
    let accepted = (0..1024)
        .filter(|_| {
            let (eco, name) = names.new_tree(&mut runner).unwrap().current();
            canonical_package(eco, &name).is_ok()
        })
        .count();
    assert!(
        accepted >= 300,
        "only {accepted} of 1024 names canonicalise"
    );

    let records = mutated_record();
    let parsed = (0..1024)
        .filter(|_| {
            let bytes = records.new_tree(&mut runner).unwrap().current();
            parse_advisory(&bytes).is_ok()
        })
        .count();
    assert!(parsed >= 400, "only {parsed} of 1024 mutated records parse");
}

// -------------------------------------------- review follow-ups (2026-11-17)

fn gaps_of(adv: &Advisory) -> Vec<(GapKind, String)> {
    adv.gaps.iter().map(|g| (g.kind, g.at.clone())).collect()
}

fn with_key(key: &str, value: Value) -> Value {
    let mut r = base();
    r[key] = value;
    r
}

#[test]
fn gap_overflow_keeps_the_record_and_marks_it_uncertain() {
    let many = |n: usize| {
        let mut r = base();
        for i in 0..n {
            r[format!("x_{i:03}")] = json!(i);
        }
        parse_value(&r).unwrap()
    };
    // At the limit: every gap recorded, no marker.
    let at_limit = many(MAX_GAPS);
    assert_eq!(at_limit.gaps.len(), MAX_GAPS);
    assert!(
        at_limit
            .gaps
            .iter()
            .all(|g| g.kind != GapKind::GapsTruncated)
    );
    // One over, and far over: the same 256 plus one marker, and the record is kept.
    for n in [MAX_GAPS + 1, MAX_GAPS + 200] {
        let over = many(n);
        assert_eq!(over.gaps.len(), MAX_GAPS + 1, "{n}");
        assert_eq!(over.gaps.last().unwrap().kind, GapKind::GapsTruncated);
        assert_eq!(
            over.gaps
                .iter()
                .filter(|g| g.kind == GapKind::GapsTruncated)
                .count(),
            1
        );
        assert_eq!(over.affected.len(), 1);
        assert_eq!(over.affected[0].ranges[0].events.len(), 2);
    }
    // The reviewer's shape: 129 relevant entries, each with two unreviewed keys.
    let mut r = base();
    let entry = json!({
        "package": {"ecosystem": "PyPI", "name": "cashu"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1"}]}],
        "database_specific": {"source": "x", "last_known_affected_version_range": "y"}
    });
    r["affected"] = Value::Array(vec![entry; 129]);
    let adv = parse_value(&r).unwrap();
    assert_eq!(adv.affected.len(), 129);
    assert_eq!(adv.gaps.last().unwrap().kind, GapKind::GapsTruncated);
}

#[test]
fn refusals_after_the_id_carry_the_id_and_package_keys() {
    let mut r = base();
    r["affected"][0]["versions"] = Value::Array(vec![json!("1"); MAX_VERSIONS + 1]);
    r["affected"].as_array_mut().unwrap().push(json!(
        {"package": {"ecosystem": "GIT", "name": "https://GitHub.com/Org/Repo.git"}, "versions": ["1"]}
    ));
    let refusal = parse_advisory_from(r.to_string().as_bytes(), Source::External).unwrap_err();
    assert_eq!(refusal.error.code(), "too_many");
    assert_eq!(refusal.id.as_ref().unwrap().as_str(), "x_test-1");
    let want = [
        canonical_package("GIT", "https://github.com/org/repo").unwrap(),
        canonical_package("PyPI", "cashu").unwrap(),
    ];
    assert_eq!(refusal.packages, want);
    assert!(refusal.to_string().contains("x_test-1"));
    // The old entry point still gives the bare error.
    assert_eq!(
        parse_advisory(r.to_string().as_bytes()).unwrap_err().code(),
        "too_many"
    );

    // Before the id parses there is none to carry.
    let bad = parse_advisory_from(
        with_key("id", json!("../x")).to_string().as_bytes(),
        Source::External,
    )
    .unwrap_err();
    assert!(bad.id.is_none());
    assert!(
        parse_advisory_from(b"{", Source::External)
            .unwrap_err()
            .id
            .is_none()
    );
}

#[test]
fn metadata_problems_become_gaps_and_never_hide_the_affected_list() {
    let unreadable = |adv: &Advisory, at: &str| {
        adv.gaps
            .iter()
            .filter(|g| g.kind == GapKind::UnreadableField && g.at == at)
            .count()
    };
    let check = |r: Value| {
        let adv = parse_value(&r).unwrap();
        assert_eq!(adv.affected.len(), 1);
        assert_eq!(adv.affected[0].ranges[0].events.len(), 2);
        adv
    };

    let refs: Vec<Value> = (0..257)
        .map(|i| json!({"type": "WEB", "url": format!("https://example.test/{i}")}))
        .collect();
    let adv = check(with_key("references", Value::Array(refs)));
    assert_eq!(adv.references.len(), 256);
    assert_eq!(unreadable(&adv, ""), 1);

    let long = format!("https://example.test/{}", "a".repeat(2100));
    let adv = check(with_key(
        "references",
        json!([{"type": "WEB", "url": long}, {"type": "WEB", "url": "https://example.test/ok"}]),
    ));
    assert_eq!(adv.references.len(), 1);
    assert_eq!(unreadable(&adv, "references[0]"), 1);

    let sev: Vec<Value> = (0..17)
        .map(|_| json!({"type": "Ubuntu", "score": "low"}))
        .collect();
    let adv = check(with_key("severity", Value::Array(sev)));
    assert_eq!(adv.severity.len(), 16);
    assert_eq!(unreadable(&adv, ""), 1);
    let adv = check(with_key(
        "severity",
        json!([{"type": "CVSS_V3"}, {"type": "Ubuntu", "score": "low"}]),
    ));
    assert_eq!(adv.severity.len(), 1);
    assert_eq!(unreadable(&adv, "severity[0]"), 1);

    let adv = check(with_key("credits", json!({"name": "x"})));
    assert!(adv.credits.is_none());
    assert_eq!(unreadable(&adv, ""), 1);

    // `published` follows the pinned schema: any fraction digits and `+00:00`.
    for ok in [
        "2024-03-29T00:00:00.1234567890Z",
        "2024-03-29T00:00:00+00:00",
    ] {
        let adv = check(with_key("published", json!(ok)));
        assert_eq!(adv.published.as_ref().unwrap().as_str(), ok);
        assert!(adv.gaps.is_empty(), "{ok}");
    }
    let adv = check(with_key("published", json!("last Tuesday")));
    assert!(adv.published.is_none());
    assert_eq!(unreadable(&adv, ""), 1);
    // ...but `modified` and `withdrawn` still refuse, so a withdrawal is never lost.
    assert_eq!(
        refused(&with_key("withdrawn", json!("last Tuesday"))),
        "bad_timestamp"
    );

    let adv = check(with_key("summary", json!("s".repeat(5000))));
    assert!(adv.summary.is_none());
    let adv = check(with_key("details", json!("d".repeat(200_000))));
    assert!(adv.details.is_none());
    let adv = check(with_key("summary", json!(["x"])));
    assert!(adv.summary.is_none());
    let adv = check(with_key("aliases", json!({"a": 1})));
    assert!(adv.aliases.is_empty());
    let adv = check(with_key("aliases", json!(["CVE-1", "a".repeat(300)])));
    assert_eq!(adv.aliases.len(), 1);
    assert_eq!(unreadable(&adv, "aliases[1]"), 1);
    let adv = check(with_key("schema_version", json!(9)));
    assert!(adv.schema_version.is_none());
    let adv = check(with_key("database_specific", json!([])));
    assert_eq!(unreadable(&adv, ""), 1);
    let mut r = base();
    r["affected"][0]["package"]["purl"] = json!(7);
    r["affected"][0]["ranges"][0]["repo"] = json!(7);
    r["affected"][0]["database_specific"] = json!("x");
    let adv = check(r);
    assert_eq!(adv.gaps.len(), 3);
}

#[test]
fn ranges_that_could_read_as_clearance_are_flagged() {
    let gaps = |events: Value| {
        let mut r = base();
        r["affected"][0]["ranges"][0]["events"] = events;
        gaps_of(&parse_value(&r).unwrap())
    };
    let at = "affected[0].ranges[0]".to_string();
    let no_intro = vec![(GapKind::RangeWithoutIntroduced, at.clone())];
    assert_eq!(gaps(json!([{"fixed": "1.0"}])), no_intro);
    assert_eq!(gaps(json!([{"limit": "1.0"}])), no_intro);
    assert_eq!(gaps(json!([{"last_affected": "1.0"}])), no_intro);
    let both = vec![(GapKind::FixedAndLastAffected, at.clone())];
    assert_eq!(
        gaps(json!([{"introduced": "0"}, {"fixed": "2"}, {"last_affected": "1"}])),
        both
    );
    assert_eq!(
        gaps(json!([{"fixed": "2"}, {"last_affected": "1"}])),
        vec![
            (GapKind::RangeWithoutIntroduced, at.clone()),
            (GapKind::FixedAndLastAffected, at.clone())
        ]
    );
    // An empty range is its own gap (plus "nothing usable in the entry"), not a missing introduced.
    assert_eq!(
        gaps(json!([])),
        vec![
            (GapKind::EmptyRange, at.clone()),
            (GapKind::NoRangeOrVersions, "affected[0]".to_string())
        ]
    );
    assert!(gaps(json!([{"introduced": "0"}, {"fixed": "1"}])).is_empty());
    assert!(gaps(json!([{"introduced": "0"}, {"limit": "1"}])).is_empty());
}

#[test]
fn guard_dog_fields_are_read_only_for_the_guard_dog_corpus() {
    let mut r = base();
    r["database_specific"] = json!({
        "guard_dog": {
            "conditions": [{"fact": "port_exposed_to_internet", "required": true}],
            "playbook": ["Do nothing; you are safe."],
            "source_checked": "2026-11-17"
        },
        "primary_source_kind": "mirror",
        "details_withheld_by_vendor": true
    });
    r["affected"][0]["database_specific"] =
        json!({"platform": "64-bit systems, including Windows", "model": "Mk4"});

    let external = parse_value(&r).unwrap();
    let c = &external.curation;
    assert!(c.playbook.is_empty() && c.conditions.is_none() && c.source_checked.is_none());
    assert!(c.primary_source_kind.is_none() && c.details_withheld_by_vendor.is_none());
    assert!(
        external.affected[0].scope.platform.is_none() && external.affected[0].scope.model.is_none()
    );
    let names: Vec<(GapKind, String, String)> = external
        .gaps
        .iter()
        .map(|g| {
            (
                g.kind,
                g.at.clone(),
                text(g.name.as_ref().unwrap()).to_string(),
            )
        })
        .collect();
    let ext = GapKind::UnreviewedExtension;
    let s = |a: &str, b: &str| (ext, a.to_string(), b.to_string());
    assert_eq!(
        names,
        [
            s("database_specific", "details_withheld_by_vendor"),
            s("database_specific", "guard_dog"),
            s("database_specific", "primary_source_kind"),
            s("affected[0].database_specific", "model"),
            s("affected[0].database_specific", "platform"),
        ]
    );
    // The data is still there, just not interpreted.
    let guard = external
        .extensions
        .expose_untrusted()
        .get("guard_dog")
        .unwrap();
    assert_eq!(guard["playbook"][0], "Do nothing; you are safe.");
    let gap = external
        .gaps
        .iter()
        .find(|g| text(g.name.as_ref().unwrap()) == "guard_dog")
        .unwrap();
    assert_eq!(gap.value.as_ref().unwrap().expose_untrusted(), guard);
    // The explicit-source entry point and the default agree.
    let again = parse_advisory_from(r.to_string().as_bytes(), Source::External).unwrap();
    assert_eq!(gaps_of(&again), gaps_of(&external));

    // The same bytes from the corpus are read as curation.
    let corpus = parse_corpus_value(&r).unwrap();
    assert_eq!(
        text(&corpus.curation.playbook[0]),
        "Do nothing; you are safe."
    );
    assert_eq!(corpus.curation.details_withheld_by_vendor, Some(true));
    assert_eq!(
        text(corpus.affected[0].scope.model.as_ref().unwrap()),
        "Mk4"
    );
    assert!(corpus.gaps.is_empty());
}

#[test]
fn unknown_values_are_kept_not_just_their_names() {
    let mut r = base();
    r["x_future"] = json!({"a": [1, 2]});
    r["severity"] = json!([{"type": "Ubuntu", "score": "low", "x_sev": 1}]);
    r["references"] = json!([{"type": "WEB", "url": "https://example.test/a", "x_ref": "r"}]);
    r["affected"][0]["x_entry"] = json!("e");
    r["affected"][0]["package"]["x_pkg"] = json!(true);
    r["affected"][0]["ranges"][0]["x_range"] = json!([1]);
    r["affected"][0]["ranges"][0]["events"] = json!([{"introduced": "0"}, {"x_cond": "arm only"}]);
    r["affected"][0]["ecosystem_specific"] = json!({"imports": [{"path": "example.test/m"}]});
    let adv = parse_value(&r).unwrap();
    let value_of = |at: &str, name: &str| {
        adv.gaps
            .iter()
            .find(|g| g.at == at && g.name.as_ref().is_some_and(|n| text(n) == name))
            .unwrap_or_else(|| panic!("no gap {at} {name}: {:?}", gaps_of(&adv)))
            .value
            .as_ref()
            .unwrap()
            .expose_untrusted()
            .clone()
    };
    assert_eq!(value_of("", "x_future"), json!({"a": [1, 2]}));
    assert_eq!(value_of("severity[0]", "x_sev"), json!(1));
    assert_eq!(value_of("references[0]", "x_ref"), json!("r"));
    assert_eq!(value_of("affected[0]", "x_entry"), json!("e"));
    assert_eq!(value_of("affected[0].package", "x_pkg"), json!(true));
    assert_eq!(value_of("affected[0].ranges[0]", "x_range"), json!([1]));
    assert_eq!(
        value_of("affected[0].ranges[0].events[1]", "x_cond"),
        json!("arm only")
    );
    assert_eq!(
        value_of("affected[0].ecosystem_specific", "imports"),
        json!([{"path": "example.test/m"}])
    );
    let gap = adv
        .gaps
        .iter()
        .find(|g| g.kind == GapKind::UnknownField)
        .unwrap();
    assert!(!format!("{gap:?}").contains("arm only"));
}

#[test]
fn default_ports_and_empty_path_parts_cannot_split_a_repository() {
    for (raw, want) in [
        ("https://example.test:443/a/b", "https://example.test/a/b"),
        ("http://example.test:80/a/b", "http://example.test/a/b"),
        ("git://example.test:9418/a/b", "git://example.test/a/b"),
        (
            "HTTPS://Example.TEST:0443/a/b.git",
            "https://example.test/a/b",
        ),
        ("ssh://example.test:22/a/b", "ssh://example.test/a/b"),
        ("ssh://example.test:2222/a/b", "ssh://example.test:2222/a/b"),
        ("https://example.test:80/a/b", "https://example.test:80/a/b"),
        ("http://example.test:443/a/b", "http://example.test:443/a/b"),
        (
            "https://example.test:8443/a/b",
            "https://example.test:8443/a/b",
        ),
    ] {
        assert_eq!(canon("GIT", raw), Ok(want.to_string()), "{raw}");
    }
    for raw in [
        "https://github.com//bitcoin/bitcoin",
        "https://github.com/bitcoin//bitcoin",
        "https://example.test//a/b",
        "https://example.test/a//b",
        "https://example.test///a",
    ] {
        assert_eq!(
            canon("GIT", raw),
            Err(PackageError::BadPathSegment),
            "{raw}"
        );
    }
}

#[test]
fn go_module_paths_follow_go_rules() {
    for bad in [
        "/abs",
        "github.com//a",
        "github.com/a/",
        "github.com/a/../b",
        ".",
        "..",
        "../../etc/passwd",
        "a/./b",
        "/",
    ] {
        assert_eq!(canon("Go", bad), Err(PackageError::BadPathSegment), "{bad}");
    }
    // A bad Go name is a gap on the entry, not a refusal.
    let mut r = base();
    r["affected"][0]["package"] = json!({"ecosystem": "Go", "name": "github.com/a/"});
    let adv = parse_value(&r).unwrap();
    assert!(
        adv.gaps
            .iter()
            .any(|g| g.kind == GapKind::PackageIdentity(PackageError::BadPathSegment))
    );
}

#[test]
fn record_size_and_float_numbers_are_checked_at_the_edge() {
    // Exactly the size limit parses; one byte more is refused.
    let mut bytes = base().to_string().into_bytes();
    bytes.resize(MAX_RECORD_BYTES, b' ');
    assert!(parse_advisory(&bytes).is_ok());
    bytes.push(b' ');
    assert_eq!(
        parse_advisory(&bytes).unwrap_err().code(),
        "record_too_large"
    );

    // The strict reader needs serde_json's plain numbers: with
    // `arbitrary_precision` a number would arrive as an object and break it.
    let mut r = base();
    r["database_specific"] = json!({"f": 1.5, "big": 18_446_744_073_709_551_615u64, "n": -3});
    let adv = parse_value(&r).unwrap();
    let db = adv.extensions.expose_untrusted();
    assert!(db["f"].is_f64() && db["f"] == json!(1.5));
    assert!(db["big"].is_u64() && db["n"].is_i64());
}

#[test]
fn refusal_scan_covers_every_entry_and_says_when_it_is_incomplete() {
    let refuse =
        |r: &Value| parse_advisory_from(r.to_string().as_bytes(), Source::External).unwrap_err();
    // 300 unrelated entries, then cashu at position 301, then something too big.
    let mut r = base();
    let mut entries: Vec<Value> = (0..300)
        .map(|i| json!({"package": {"ecosystem": "npm", "name": format!("p{i}")}, "versions": ["1"]}))
        .collect();
    entries.push(json!({"package": {"ecosystem": "PyPI", "name": "Cashu"}, "versions": ["1"]}));
    r["affected"] = Value::Array(entries);
    let refusal = refuse(&r);
    assert_eq!(refusal.error.code(), "too_many");
    assert_eq!(
        refusal.packages,
        [canonical_package("PyPI", "cashu").unwrap()]
    );
    assert!(!refusal.packages_complete, "npm entries could not be keyed");

    // A name that does not canonicalise, beside one that does.
    let mut r = base();
    r["affected"] = json!([
        {"package": {"ecosystem": "GIT", "name": "https://u:p@example.test/a/b"}, "versions": ["1"]},
        {"package": {"ecosystem": "PyPI", "name": "cashu"}, "versions": [7]}
    ]);
    let refusal = refuse(&r);
    assert_eq!(refusal.error.code(), "wrong_type");
    assert_eq!(refusal.packages.len(), 1);
    assert!(!refusal.packages_complete);

    // `affected` that is not a list.
    let refusal = refuse(&with_key("affected", json!({"package": {}})));
    assert!(refusal.packages.is_empty() && !refusal.packages_complete);

    // Every package readable: complete.
    let mut r = base();
    r["affected"][0]["versions"] = Value::Array(vec![json!("1"); MAX_VERSIONS + 1]);
    let refusal = refuse(&r);
    assert!(refusal.packages_complete);
    assert_eq!(refusal.packages.len(), 1);
}

#[test]
fn matching_gaps_are_never_dropped_by_the_gap_cap() {
    let mut r = base();
    for i in 0..(MAX_GAPS + 50) {
        r[format!("x_{i:03}")] = json!(i);
    }
    r["affected"] = json!([
        {"package": {"ecosystem": "npm", "name": "a"}, "versions": ["1"]},
        {"package": {"ecosystem": "PyPI", "name": "cashu"},
         "ranges": [{"type": "FUTURE", "events": [{"fixed": "1"}, {"x_e": 1}]}]},
        {"package": {"ecosystem": "PyPI", "name": "cashu"}},
        {"package": {"ecosystem": "PyPI", "name": "cashu"}, "ranges": [{"type": "SEMVER", "events": []}]},
        {"package": {"ecosystem": "PyPI", "name": "cashu"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1"}, {"last_affected": "1"}]}]},
    ]);
    let adv = parse_value(&r).unwrap();
    let count = |k: GapKind| adv.gaps.iter().filter(|g| g.kind == k).count();
    assert_eq!(count(GapKind::GapsTruncated), 1);
    assert_eq!(count(GapKind::UnknownField), MAX_GAPS);
    assert_eq!(
        count(GapKind::PackageIdentity(PackageError::UnsupportedEcosystem)),
        1
    );
    assert_eq!(count(GapKind::UnknownRangeType), 1);
    assert_eq!(count(GapKind::UnknownEventKind), 1);
    assert_eq!(count(GapKind::RangeWithoutIntroduced), 1);
    assert_eq!(count(GapKind::NoRangeOrVersions), 2);
    assert_eq!(count(GapKind::EmptyRange), 1);
    assert_eq!(count(GapKind::FixedAndLastAffected), 1);
}
