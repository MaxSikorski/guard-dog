//! Phase 2.1, PR 5: ordered ranges and the GIT fallback.
//!
//! No real version parser exists yet, so these tests use a small ordering of
//! their own (dotted decimal numbers with an optional `-rcN`, where a release
//! candidate sorts below its final release). The evaluator never learns what the
//! ordering is; the table rows, ties, limits, lists, the GIT path and the
//! "unknown never becomes not-affected" property are checked against it.

// Test-only crate: helper functions build data and check it, and a panic there
// is a failed check (clippy.toml exempts only `#[test]` functions).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::cmp::Ordering;
use std::fs;
use std::path::{Path, PathBuf};

use gd_advisories::{
    AffectedEntry, Location, Place, RangeKind, Source, UnknownReason, VersionError,
    VersionEvidence, VersionScheme, evaluate_entry, parse_advisory, parse_advisory_from,
};
use proptest::prelude::*;
use serde_json::{Value, json};

// ------------------------------------------------------------ test scheme

#[derive(Clone, Debug)]
struct V {
    nums: Vec<u64>,
    rc: Option<u64>,
}

impl Ord for V {
    fn cmp(&self, other: &Self) -> Ordering {
        let n = self.nums.len().max(other.nums.len());
        for i in 0..n {
            let a = self.nums.get(i).copied().unwrap_or(0);
            let b = other.nums.get(i).copied().unwrap_or(0);
            match a.cmp(&b) {
                Ordering::Equal => {}
                o => return o,
            }
        }
        match (self.rc, other.rc) {
            (None, None) => Ordering::Equal,
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (Some(a), Some(b)) => a.cmp(&b),
        }
    }
}
impl PartialOrd for V {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl PartialEq for V {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for V {}

/// `semver` says whether the scheme has declared SemVer compatibility;
/// `poison` lists raw strings the scheme refuses to read.
#[derive(Clone, Default)]
struct TestScheme {
    semver: bool,
    poison: Vec<String>,
}

fn scheme() -> TestScheme {
    TestScheme {
        semver: true,
        poison: vec![],
    }
}

impl VersionScheme for TestScheme {
    type Version = V;

    fn parse(&self, raw: &str) -> Result<V, VersionError> {
        if self.poison.iter().any(|p| p == raw) {
            return Err(VersionError::Malformed);
        }
        let (core, rc) = match raw.split_once("-rc") {
            Some((c, r)) => (c, Some(r.parse::<u64>().map_err(|_| VersionError::Malformed)?)),
            None => (raw, None),
        };
        let mut nums = Vec::new();
        for part in core.split('.') {
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err(VersionError::Malformed);
            }
            nums.push(part.parse::<u64>().map_err(|_| VersionError::Malformed)?);
        }
        Ok(V { nums, rc })
    }

    /// Identity is the exact text: `1.0` and `1.0.0` compare equal in order but
    /// are different identities.
    fn same_identity(&self, a: &str, b: &str) -> Option<bool> {
        self.parse(a).ok()?;
        self.parse(b).ok()?;
        Some(a == b)
    }

    fn reads_semver_ranges(&self) -> bool {
        self.semver
    }
}

// ---------------------------------------------------------------- helpers

fn entry_from(ranges: Value, versions: Value) -> AffectedEntry {
    let mut e = json!({"package": {"ecosystem": "PyPI", "name": "cashu"}});
    if ranges.as_array().is_some_and(|r| !r.is_empty()) {
        e["ranges"] = ranges;
    }
    if versions.as_array().is_some_and(|r| !r.is_empty()) {
        e["versions"] = versions;
    }
    let record = json!({"id": "x_test-1", "modified": "2026-11-17T00:00:00Z", "affected": [e]});
    let mut adv = parse_advisory(record.to_string().as_bytes()).unwrap();
    adv.affected.remove(0)
}

fn eco(events: Value) -> Value {
    json!({"type": "ECOSYSTEM", "events": events})
}

fn ev(s: &str, installed: &str) -> VersionEvidence {
    let events: Value = serde_json::from_str(s).unwrap();
    let entry = entry_from(json!([eco(events)]), json!([]));
    evaluate_entry(&scheme(), 0, &entry, Some(installed))
}

fn kind(e: &VersionEvidence) -> &'static str {
    match e {
        VersionEvidence::InRange(_) => "in",
        VersionEvidence::OutOfRange => "out",
        VersionEvidence::Unknown { .. } => "unknown",
        VersionEvidence::NotApplicable => "not-applicable",
    }
}

fn is_in(s: &str, installed: &str) -> bool {
    matches!(ev(s, installed), VersionEvidence::InRange(_))
}
fn is_out(s: &str, installed: &str) -> bool {
    ev(s, installed) == VersionEvidence::OutOfRange
}
fn is_unknown(s: &str, installed: &str) -> bool {
    matches!(ev(s, installed), VersionEvidence::Unknown { .. })
}

fn reason(e: &VersionEvidence) -> UnknownReason {
    match e {
        VersionEvidence::Unknown { reason, .. } => *reason,
        other => panic!("expected unknown, got {other:?}"),
    }
}

// --------------------------------------------------------- the §3 table

#[test]
fn row_introduced_zero_fixed() {
    let r = r#"[{"introduced":"0"},{"fixed":"1.0.2"}]"#;
    assert!(is_in(r, "0.0.0"));
    assert!(is_in(r, "1.0.2-rc1"));
    assert!(is_out(r, "1.0.2"));
    assert!(is_out(r, "1.0.3"));
}

#[test]
fn row_reintroduction_reopens() {
    let r = r#"[{"introduced":"1.0.0"},{"fixed":"1.0.2"},{"introduced":"3.0.0"},{"fixed":"3.2.5"}]"#;
    assert!(is_out(r, "0.9.0"));
    assert!(is_in(r, "1.0.0"));
    assert!(is_out(r, "2.0.0"));
    assert!(is_in(r, "3.0.0"));
    assert!(is_in(r, "3.2.4"));
    assert!(is_out(r, "3.2.5"));
}

#[test]
fn row_last_affected_is_inclusive() {
    let r = r#"[{"introduced":"1.0.0"},{"last_affected":"1.0.2"}]"#;
    assert!(is_in(r, "1.0.0"));
    assert!(is_in(r, "1.0.2"));
    assert!(is_out(r, "1.0.3"));
    assert!(is_out(r, "0.9"));
}

#[test]
fn row_limits_expand_scope() {
    let r = r#"[{"introduced":"0"},{"limit":"2.0.0"},{"limit":"4.0.0"}]"#;
    assert!(is_in(r, "3.0.0"));
    assert!(is_in(r, "1.0.0"));
    assert!(is_out(r, "4.0.0"));
    assert!(is_out(r, "9.0.0"));
}

#[test]
fn row_introduced_zero_alone() {
    let r = r#"[{"introduced":"0"}]"#;
    for v in ["0", "1.0.0", "99.9.9", "1.0-rc2"] {
        assert!(is_in(r, v), "{v}");
    }
    let entry = entry_from(json!([eco(serde_json::from_str(r).unwrap())]), json!([]));
    let e = evaluate_entry(&scheme(), 0, &entry, None);
    assert_eq!(reason(&e), UnknownReason::InstalledVersionUnknown);
}

#[test]
fn row_list_and_range_are_a_union() {
    let entry = entry_from(
        json!([eco(json!([{"introduced": "0"}, {"fixed": "1.0.2"}]))]),
        json!(["1.0.2"]),
    );
    let e = evaluate_entry(&scheme(), 0, &entry, Some("1.0.2"));
    assert_eq!(
        e,
        VersionEvidence::InRange(Location {
            entry: 0,
            place: Place::Listed { index: 0 }
        })
    );
    assert_eq!(
        evaluate_entry(&scheme(), 0, &entry, Some("1.0.3")),
        VersionEvidence::OutOfRange
    );
}

#[test]
fn row_core_style_ranges() {
    let entry = entry_from(
        json!([
            eco(json!([{"introduced": "28.0"}, {"fixed": "28.3"}])),
            eco(json!([{"introduced": "29.0"}, {"fixed": "29.2"}]))
        ]),
        json!([]),
    );
    let run = |v| evaluate_entry(&scheme(), 0, &entry, Some(v));
    assert!(matches!(run("28.2"), VersionEvidence::InRange(_)));
    assert_eq!(run("28.3"), VersionEvidence::OutOfRange);
    assert!(matches!(run("29.1"), VersionEvidence::InRange(_)));
    assert_eq!(run("32.1"), VersionEvidence::OutOfRange);
}

#[test]
fn evidence_carries_entry_range_and_event_indices() {
    let entry = entry_from(
        json!([
            eco(json!([{"introduced": "5"}, {"fixed": "6"}])),
            eco(json!([{"introduced": "0"}, {"fixed": "2"}, {"introduced": "3"}, {"fixed": "4"}]))
        ]),
        json!([]),
    );
    let e = evaluate_entry(&scheme(), 7, &entry, Some("3.5"));
    assert_eq!(
        e,
        VersionEvidence::InRange(Location {
            entry: 7,
            place: Place::Range {
                range: 1,
                event: Some(2)
            }
        })
    );
}

// ------------------------------------------------- semantics and boundaries

#[test]
fn boundaries_are_inclusive_and_exclusive_as_specified() {
    let r = r#"[{"introduced":"2"},{"fixed":"4"}]"#;
    assert!(is_out(r, "1.9"));
    assert!(is_in(r, "2"));
    assert!(is_in(r, "2.0.0"));
    assert!(is_in(r, "3.9"));
    assert!(is_out(r, "4"));
    assert!(is_out(r, "4.0.0"));
    // A release candidate sorts below its final release.
    assert!(is_in(r, "4-rc1"));
    assert!(is_out(r, "2-rc1"));
}

#[test]
fn zero_is_minus_infinity_not_a_release() {
    // "0" opens before every version, including ones below 0.0.0 in the scheme.
    let r = r#"[{"introduced":"0"},{"fixed":"1"}]"#;
    assert!(is_in(r, "0-rc1"));
    assert!(is_in(r, "0"));
}

#[test]
fn identical_duplicates_are_removed() {
    let r = r#"[{"introduced":"1"},{"introduced":"1"},{"fixed":"2"},{"fixed":"2"}]"#;
    assert!(is_in(r, "1.5"));
    assert!(is_out(r, "2"));
    let z = r#"[{"introduced":"0"},{"introduced":"0"},{"fixed":"2"}]"#;
    assert!(is_in(z, "0.1"));
}

#[test]
fn event_order_never_changes_the_result() {
    let events = [
        json!({"introduced": "1"}),
        json!({"fixed": "2"}),
        json!({"introduced": "3"}),
        json!({"fixed": "4"}),
        json!({"limit": "9"}),
    ];
    let cands = ["0.5", "1", "1.5", "2", "2.5", "3", "3.9", "4", "8", "9", "10"];
    let expected: Vec<&str> = cands
        .iter()
        .map(|c| {
            let entry = entry_from(json!([eco(Value::Array(events.to_vec()))]), json!([]));
            kind(&evaluate_entry(&scheme(), 0, &entry, Some(c)))
        })
        .collect();
    assert_eq!(expected, ["out", "in", "in", "out", "out", "in", "in", "out", "out", "out", "out"]);
    let mut idx: Vec<usize> = (0..events.len()).collect();
    let mut count = 0;
    permute(&mut idx, 0, &mut |p| {
        count += 1;
        let shuffled: Vec<Value> = p.iter().map(|&i| events[i].clone()).collect();
        let entry = entry_from(json!([eco(Value::Array(shuffled))]), json!([]));
        let got: Vec<&str> = cands
            .iter()
            .map(|c| kind(&evaluate_entry(&scheme(), 0, &entry, Some(c))))
            .collect();
        assert_eq!(got, expected, "{p:?}");
    });
    assert_eq!(count, 120);
}

fn permute(items: &mut Vec<usize>, k: usize, f: &mut impl FnMut(&[usize])) {
    if k == items.len() {
        f(items);
        return;
    }
    for i in k..items.len() {
        items.swap(k, i);
        permute(items, k + 1, f);
        items.swap(k, i);
    }
}

// ------------------------------------------------------ ties and invalid

#[test]
fn both_fixed_and_last_affected_is_unknown() {
    let r = r#"[{"introduced":"1"},{"fixed":"3"},{"last_affected":"2"}]"#;
    for c in ["0.5", "1.5", "2", "2.5", "3", "9"] {
        assert!(is_unknown(r, c), "{c}");
    }
    assert!(is_unknown(
        r#"[{"introduced":"1"},{"last_affected":"2"},{"introduced":"5"},{"fixed":"6"}]"#,
        "5.5"
    ));
}

#[test]
fn unparseable_limit_is_unknown() {
    let r = r#"[{"introduced":"0"},{"fixed":"3"},{"limit":"banana"}]"#;
    for c in ["0.5", "2", "3", "9"] {
        let e = ev(r, c);
        assert_eq!(reason(&e), UnknownReason::UnparseableLimit, "{c}");
    }
}

#[test]
fn unparseable_event_is_unknown() {
    for r in [
        r#"[{"introduced":"x"},{"fixed":"3"}]"#,
        r#"[{"introduced":"0"},{"fixed":"x"}]"#,
        r#"[{"introduced":"1"},{"last_affected":"x"}]"#,
    ] {
        for c in ["0.5", "2", "5"] {
            let e = ev(r, c);
            assert_eq!(reason(&e), UnknownReason::UnparseableBoundary, "{r} {c}");
        }
    }
}

#[test]
fn zero_on_a_non_introduced_event_is_unknown() {
    for r in [
        r#"[{"introduced":"0"},{"fixed":"0"}]"#,
        r#"[{"introduced":"0"},{"last_affected":"0"}]"#,
        r#"[{"introduced":"1"},{"fixed":"2"},{"fixed":"0"}]"#,
    ] {
        for c in ["0", "1.5", "3"] {
            assert!(is_unknown(r, c), "{r} {c}");
        }
    }
}

#[test]
fn conflicting_kinds_at_equal_coordinates_are_unknown() {
    for r in [
        r#"[{"introduced":"1"},{"fixed":"1"}]"#,
        r#"[{"fixed":"1"},{"introduced":"1"}]"#,
        r#"[{"introduced":"1"},{"last_affected":"1"}]"#,
        r#"[{"introduced":"0"},{"fixed":"2"},{"introduced":"2"}]"#,
        // Equal by precedence, spelled differently.
        r#"[{"introduced":"1.0"},{"fixed":"1.0.0"}]"#,
    ] {
        for c in ["0.5", "1", "1.5", "2", "5"] {
            assert!(is_unknown(r, c), "{r} {c}");
        }
    }
}

#[test]
fn malformed_shapes_are_unknown_never_out() {
    // No introduced, no events, only a limit.
    for r in [
        r#"[{"fixed":"2"}]"#,
        r#"[{"limit":"2"}]"#,
        r#"[{"last_affected":"2"}]"#,
    ] {
        assert!(is_unknown(r, "1"), "{r}");
        assert!(is_unknown(r, "5"), "{r}");
    }
}

#[test]
fn unrecognised_event_kind_is_unknown() {
    let r = r#"[{"introduced":"0"},{"fixed":"2"},{"wibble":"1"}]"#;
    assert!(is_unknown(r, "1"));
    assert!(is_unknown(r, "5"));
}

#[test]
fn range_level_extension_data_never_changes_membership() {
    let plain = entry_from(
        json!([eco(json!([{"introduced": "0"}, {"fixed": "2"}]))]),
        json!([]),
    );
    let noted = entry_from(
        json!([{
            "type": "ECOSYSTEM",
            "events": [{"introduced": "0"}, {"fixed": "2"}],
            "database_specific": {"range_note": "not affected after 1", "fixed_in": "1"}
        }]),
        json!([]),
    );
    for c in ["0.5", "1", "1.5", "2", "3"] {
        assert_eq!(
            kind(&evaluate_entry(&scheme(), 0, &plain, Some(c))),
            kind(&evaluate_entry(&scheme(), 0, &noted, Some(c))),
            "{c}"
        );
    }
}

// ----------------------------------------------------------------- limits

#[test]
fn limits_none_one_two_and_star() {
    let none = r#"[{"introduced":"0"}]"#;
    assert!(is_in(none, "1000"));
    let one = r#"[{"introduced":"0"},{"limit":"2"}]"#;
    assert!(is_in(one, "1.9"));
    assert!(is_out(one, "2"));
    let star = r#"[{"introduced":"0"},{"limit":"*"}]"#;
    assert!(is_in(star, "1000"));
    let two = r#"[{"introduced":"0"},{"limit":"2"},{"limit":"4"}]"#;
    assert!(is_in(two, "3"));
    assert!(is_out(two, "4"));
    // A star among other limits is infinity: nothing is cut off.
    let mixed = r#"[{"introduced":"0"},{"limit":"2"},{"limit":"*"}]"#;
    assert!(is_in(mixed, "1000"));
    // A limit never widens: outside the transitions the candidate is still out.
    let narrow = r#"[{"introduced":"1"},{"fixed":"2"},{"limit":"9"}]"#;
    assert!(is_out(narrow, "3"));
}

// ------------------------------------------------------------------ lists

fn listed(versions: Value) -> AffectedEntry {
    entry_from(json!([]), versions)
}

#[test]
fn a_complete_list_only_entry_clears_what_it_does_not_name() {
    let entry = listed(json!(["1.0.0", "1.0.1"]));
    let run = |v| evaluate_entry(&scheme(), 3, &entry, Some(v));
    assert_eq!(
        run("1.0.1"),
        VersionEvidence::InRange(Location {
            entry: 3,
            place: Place::Listed { index: 1 }
        })
    );
    assert_eq!(run("1.0.2"), VersionEvidence::OutOfRange);
}

#[test]
fn list_identity_is_not_precedence_equality() {
    let entry = listed(json!(["1.0.0"]));
    // 1.0 and 1.0.0 compare equal in this ordering but are different identities.
    assert_eq!(
        evaluate_entry(&scheme(), 0, &entry, Some("1.0")),
        VersionEvidence::OutOfRange
    );
}

#[test]
fn a_list_cannot_clear_without_a_known_installed_identity() {
    let entry = listed(json!(["1.0.0"]));
    let none = evaluate_entry(&scheme(), 0, &entry, None);
    assert_eq!(reason(&none), UnknownReason::InstalledVersionUnknown);
    let junk = evaluate_entry(&scheme(), 0, &entry, Some("banana"));
    assert_eq!(reason(&junk), UnknownReason::InstalledVersionUnparseable);
    let empty = evaluate_entry(&scheme(), 0, &entry, Some(""));
    assert!(matches!(empty, VersionEvidence::Unknown { .. }));
}

#[test]
fn an_unreadable_listed_version_keeps_the_answer_open() {
    let entry = listed(json!(["1.0.0", "banana"]));
    let e = evaluate_entry(&scheme(), 0, &entry, Some("2.0.0"));
    assert_eq!(reason(&e), UnknownReason::UnreadableListedVersion);
    // A hit elsewhere in the list is still positive evidence.
    assert!(matches!(
        evaluate_entry(&scheme(), 0, &entry, Some("1.0.0")),
        VersionEvidence::InRange(_)
    ));
}

#[test]
fn a_list_miss_does_not_clear_when_a_range_is_unknown() {
    let entry = entry_from(
        json!([eco(json!([{"introduced": "x"}, {"fixed": "2"}]))]),
        json!(["1.0.0"]),
    );
    let e = evaluate_entry(&scheme(), 0, &entry, Some("5"));
    assert_eq!(reason(&e), UnknownReason::UnparseableBoundary);
    // And a list hit still wins the union.
    assert!(matches!(
        evaluate_entry(&scheme(), 0, &entry, Some("1.0.0")),
        VersionEvidence::InRange(_)
    ));
}

#[test]
fn ranges_and_list_both_must_exclude() {
    let entry = entry_from(
        json!([eco(json!([{"introduced": "1"}, {"fixed": "2"}]))]),
        json!(["7"]),
    );
    let run = |v| evaluate_entry(&scheme(), 0, &entry, Some(v));
    assert!(matches!(run("7"), VersionEvidence::InRange(_)));
    assert!(matches!(run("1.5"), VersionEvidence::InRange(_)));
    assert_eq!(run("5"), VersionEvidence::OutOfRange);
}

#[test]
fn an_entry_with_nothing_usable_is_unknown() {
    let entry = entry_from(json!([]), json!([]));
    let e = evaluate_entry(&scheme(), 2, &entry, Some("1"));
    assert_eq!(reason(&e), UnknownReason::NoUsableRangeOrVersions);
    let entry = entry_from(json!([eco(json!([]))]), json!([]));
    assert!(matches!(
        evaluate_entry(&scheme(), 0, &entry, Some("1")),
        VersionEvidence::Unknown { .. }
    ));
}

// ------------------------------------------------------------ GIT ranges

fn git_entry(versions: Value) -> AffectedEntry {
    entry_from(
        json!([{
            "type": "GIT",
            "repo": "https://github.com/example/project",
            "events": [{"introduced": "0"}, {"fixed": "4cd3cf6a1b2c3d4e5f60718293a4b5c6d7e8f901"}]
        }]),
        versions,
    )
}

#[test]
fn a_git_range_is_unknown_and_asks_for_a_release() {
    let entry = git_entry(json!([]));
    assert!(matches!(entry.ranges[0].kind, RangeKind::Git));
    let e = evaluate_entry(&scheme(), 0, &entry, Some("1.2.3"));
    match &e {
        VersionEvidence::Unknown { reason, question, .. } => {
            assert_eq!(*reason, UnknownReason::NoCommitGraph);
            let q = question.to_lowercase();
            assert!(q.contains("release") && q.contains("tag"), "{question}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_git_range_still_checks_the_versions_list() {
    let entry = git_entry(json!(["1.2.3", "1.2.4"]));
    // A list hit is positive evidence.
    assert_eq!(
        evaluate_entry(&scheme(), 0, &entry, Some("1.2.4")),
        VersionEvidence::InRange(Location {
            entry: 0,
            place: Place::Listed { index: 1 }
        })
    );
    // A list miss cannot clear the unresolved GIT range.
    let miss = evaluate_entry(&scheme(), 0, &entry, Some("9.9.9"));
    assert_eq!(reason(&miss), UnknownReason::NoCommitGraph);
}

#[test]
fn a_git_range_never_hides_a_hit_in_another_range() {
    let entry = entry_from(
        json!([
            {"type": "GIT", "repo": "https://github.com/example/project",
             "events": [{"introduced": "0"}, {"fixed": "4cd3cf6a1b2c3d4e5f60718293a4b5c6d7e8f901"}]},
            eco(json!([{"introduced": "1"}, {"fixed": "2"}]))
        ]),
        json!([]),
    );
    assert!(matches!(
        evaluate_entry(&scheme(), 0, &entry, Some("1.5")),
        VersionEvidence::InRange(_)
    ));
    assert!(matches!(
        evaluate_entry(&scheme(), 0, &entry, Some("5")),
        VersionEvidence::Unknown { .. }
    ));
}

// ------------------------------------------------- scheme authority

#[test]
fn semver_range_on_a_scheme_without_semver_compatibility_is_unknown() {
    let entry = entry_from(
        json!([{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2"}]}]),
        json!([]),
    );
    let strict = TestScheme {
        semver: false,
        poison: vec![],
    };
    for c in ["1", "3"] {
        let e = evaluate_entry(&strict, 0, &entry, Some(c));
        assert_eq!(reason(&e), UnknownReason::SchemeMismatch, "{c}");
    }
    // The same range on a SemVer-compatible scheme is evaluated.
    assert!(matches!(
        evaluate_entry(&scheme(), 0, &entry, Some("1")),
        VersionEvidence::InRange(_)
    ));
    // ECOSYSTEM ranges are in the product's own scheme, whatever it declares.
    let eco_entry = entry_from(
        json!([eco(json!([{"introduced": "0"}, {"fixed": "2"}]))]),
        json!([]),
    );
    assert!(matches!(
        evaluate_entry(&strict, 0, &eco_entry, Some("1")),
        VersionEvidence::InRange(_)
    ));
    assert_eq!(
        evaluate_entry(&strict, 0, &eco_entry, Some("3")),
        VersionEvidence::OutOfRange
    );
}

#[test]
fn an_unsupported_range_type_is_unknown() {
    let entry = entry_from(
        json!([{"type": "WIBBLE", "events": [{"introduced": "0"}, {"fixed": "2"}]}]),
        json!([]),
    );
    let e = evaluate_entry(&scheme(), 0, &entry, Some("5"));
    assert!(matches!(e, VersionEvidence::Unknown { .. }));
}

#[test]
fn unknown_installed_version_is_never_out_of_range() {
    let entry = entry_from(
        json!([eco(json!([{"introduced": "1"}, {"fixed": "2"}]))]),
        json!([]),
    );
    let e = evaluate_entry(&scheme(), 4, &entry, None);
    match e {
        VersionEvidence::Unknown { reason, question, at } => {
            assert_eq!(reason, UnknownReason::InstalledVersionUnknown);
            assert!(!question.is_empty());
            assert_eq!(at.entry, 4);
        }
        other => panic!("{other:?}"),
    }
    let junk = evaluate_entry(&scheme(), 0, &entry, Some("not a version"));
    assert_eq!(reason(&junk), UnknownReason::InstalledVersionUnparseable);
}

#[test]
fn every_unknown_carries_a_question() {
    let cases = [
        r#"[{"introduced":"x"},{"fixed":"3"}]"#,
        r#"[{"introduced":"1"},{"fixed":"3"},{"last_affected":"2"}]"#,
        r#"[{"introduced":"1"},{"fixed":"1"}]"#,
        r#"[{"introduced":"0"},{"limit":"q"}]"#,
        r#"[{"fixed":"3"}]"#,
    ];
    for r in cases {
        match ev(r, "1.5") {
            VersionEvidence::Unknown { question, .. } => assert!(!question.trim().is_empty(), "{r}"),
            other => panic!("{r}: {other:?}"),
        }
    }
}

// ----------------------------------------------------------------- budgets

#[test]
fn a_maximum_size_record_evaluates() {
    // The intake allows 1,024 ranges and events together and 10,000 versions.
    let mut events = vec![json!({"introduced": "0"})];
    for i in 1..1020u64 {
        if i % 2 == 1 {
            events.push(json!({"fixed": i.to_string()}));
        } else {
            events.push(json!({"introduced": i.to_string()}));
        }
    }
    let versions: Vec<Value> = (0..10_000u64).map(|i| json!(format!("7.{i}"))).collect();
    let entry = entry_from(json!([eco(Value::Array(events))]), Value::Array(versions));
    // 500 is between introduced 500 and fixed 501.
    assert!(matches!(
        evaluate_entry(&scheme(), 0, &entry, Some("500")),
        VersionEvidence::InRange(_)
    ));
    assert_eq!(
        evaluate_entry(&scheme(), 0, &entry, Some("501")),
        VersionEvidence::OutOfRange
    );
    assert!(matches!(
        evaluate_entry(&scheme(), 0, &entry, Some("7.9999")),
        VersionEvidence::InRange(_)
    ));
    // Past the last fix, nothing in the list or the ranges names it.
    assert_eq!(
        evaluate_entry(&scheme(), 0, &entry, Some("5000")),
        VersionEvidence::OutOfRange
    );
}

// ---------------------------------------------------- property: monotonicity

const SEED: u64 = 0x0000_0000_2026_1117;

fn config() -> ProptestConfig {
    let seed = std::env::var("GD_PROPTEST_SEED")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(SEED);
    ProptestConfig {
        cases: 1024,
        failure_persistence: None,
        rng_algorithm: proptest::test_runner::RngAlgorithm::ChaCha,
        rng_seed: proptest::test_runner::RngSeed::Fixed(seed),
        ..ProptestConfig::default()
    }
}

#[derive(Clone, Debug)]
struct EventSpec {
    kind: u8,
    value: String,
}

#[derive(Clone, Debug)]
struct RangeSpec {
    range_type: u8,
    events: Vec<EventSpec>,
}

#[derive(Clone, Debug)]
struct Spec {
    ranges: Vec<RangeSpec>,
    versions: Vec<String>,
}

fn coordinate() -> impl Strategy<Value = String> {
    prop_oneof![
        8 => (0u8..8).prop_map(|n| n.to_string()),
        2 => (1u8..8).prop_map(|n| format!("{n}-rc1")),
        1 => Just("0".to_string()),
        1 => Just("*".to_string()),
        1 => Just("banana".to_string()),
    ]
}

fn spec() -> impl Strategy<Value = Spec> {
    let event = (0u8..4, coordinate()).prop_map(|(kind, value)| EventSpec { kind, value });
    let range = (0u8..4, prop::collection::vec(event, 0..7))
        .prop_map(|(range_type, events)| RangeSpec { range_type, events });
    (
        prop::collection::vec(range, 0..4),
        prop::collection::vec((0u8..8).prop_map(|n| n.to_string()), 0..4),
    )
        .prop_map(|(ranges, versions)| Spec { ranges, versions })
}

/// `replace` swaps one event's value for text the scheme cannot read.
fn build(spec: &Spec, replace: Option<(usize, usize)>) -> Option<AffectedEntry> {
    let ranges: Vec<Value> = spec
        .ranges
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let events: Vec<Value> = r
                .events
                .iter()
                .enumerate()
                .map(|(j, e)| {
                    let v = if replace == Some((i, j)) {
                        "not-a-version".to_string()
                    } else {
                        e.value.clone()
                    };
                    let key = ["introduced", "fixed", "last_affected", "limit"][e.kind as usize];
                    json!({ key: v })
                })
                .collect();
            let ty = ["ECOSYSTEM", "SEMVER", "GIT", "WIBBLE"][r.range_type as usize];
            if ty == "GIT" {
                json!({"type": ty, "repo": "https://github.com/example/project", "events": events})
            } else {
                json!({"type": ty, "events": events})
            }
        })
        .collect();
    let mut e = json!({"package": {"ecosystem": "PyPI", "name": "cashu"}});
    if !ranges.is_empty() {
        e["ranges"] = Value::Array(ranges);
    }
    if !spec.versions.is_empty() {
        e["versions"] = json!(spec.versions);
    }
    let record = json!({"id": "x_test-1", "modified": "2026-11-17T00:00:00Z", "affected": [e]});
    let mut adv = parse_advisory(record.to_string().as_bytes()).ok()?;
    if adv.affected.is_empty() {
        return None;
    }
    Some(adv.affected.remove(0))
}

fn not_out(before: &VersionEvidence, after: &VersionEvidence) -> bool {
    *before == VersionEvidence::OutOfRange || *after != VersionEvidence::OutOfRange
}

proptest! {
    #![proptest_config(config())]

    /// Unknown never moves a result toward not-affected: an installed version,
    /// a boundary, or the scheme's reading of a string replaced by something
    /// unreadable never turns InRange or Unknown into OutOfRange.
    #[test]
    fn unknown_never_moves_toward_out_of_range(
        spec in spec(),
        installed in prop_oneof![(0u8..9).prop_map(|n| n.to_string()), (1u8..9).prop_map(|n| format!("{n}-rc1"))],
        pick in (any::<usize>(), any::<usize>()),
    ) {
        let Some(entry) = build(&spec, None) else { return Ok(()); };
        let s = scheme();
        let base = evaluate_entry(&s, 0, &entry, Some(&installed));
        prop_assert!(base != VersionEvidence::NotApplicable);

        // The installed version becomes unknown or unreadable.
        for gone in [None, Some("banana"), Some("")] {
            let after = evaluate_entry(&s, 0, &entry, gone);
            prop_assert!(after != VersionEvidence::OutOfRange, "{gone:?}");
            prop_assert!(after != VersionEvidence::NotApplicable);
        }

        // One boundary becomes unreadable.
        let total: usize = spec.ranges.iter().map(|r| r.events.len()).sum();
        if total > 0 {
            let mut n = pick.0 % total;
            let mut at = (0, 0);
            for (i, r) in spec.ranges.iter().enumerate() {
                if n < r.events.len() { at = (i, n); break; }
                n -= r.events.len();
            }
            if let Some(mutated) = build(&spec, Some(at)) {
                let after = evaluate_entry(&s, 0, &mutated, Some(&installed));
                prop_assert!(not_out(&base, &after), "{base:?} -> {after:?}");
                prop_assert!(after != VersionEvidence::NotApplicable);
            }

            // The scheme refuses to read that same boundary text.
            let (i, j) = at;
            let poisoned = TestScheme {
                semver: true,
                poison: vec![spec.ranges[i].events[j].value.clone()],
            };
            let after = evaluate_entry(&poisoned, 0, &entry, Some(&installed));
            prop_assert!(not_out(&base, &after), "{base:?} -> {after:?}");
        }

        // The scheme refuses to read a listed version.
        if let Some(v) = spec.versions.get(pick.1 % spec.versions.len().max(1)) {
            let poisoned = TestScheme { semver: true, poison: vec![v.clone()] };
            let after = evaluate_entry(&poisoned, 0, &entry, Some(&installed));
            prop_assert!(not_out(&base, &after), "{base:?} -> {after:?}");
        }

        // A scheme that has not declared SemVer compatibility never clears.
        let strict = TestScheme { semver: false, poison: vec![] };
        let after = evaluate_entry(&strict, 0, &entry, Some(&installed));
        prop_assert!(not_out(&base, &after), "{base:?} -> {after:?}");
    }

    /// Shuffling the events of every range never changes the kind of result.
    #[test]
    fn shuffling_events_never_changes_the_result(spec in spec(), installed in (0u8..9).prop_map(|n| n.to_string()), rot in any::<usize>()) {
        let Some(entry) = build(&spec, None) else { return Ok(()); };
        let mut shuffled = spec.clone();
        for r in &mut shuffled.ranges {
            if !r.events.is_empty() {
                let k = rot % r.events.len();
                r.events.rotate_left(k);
                r.events.reverse();
            }
        }
        let Some(other) = build(&shuffled, None) else { return Ok(()); };
        let a = evaluate_entry(&scheme(), 0, &entry, Some(&installed));
        let b = evaluate_entry(&scheme(), 0, &other, Some(&installed));
        prop_assert_eq!(kind(&a), kind(&b));
    }
}

// ------------------------------------------------------------------ corpus

fn corpus_files() -> Vec<(String, Vec<u8>)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../advisories/corpus");
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    paths.sort();
    paths
        .into_iter()
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                fs::read(&p).unwrap(),
            )
        })
        .collect()
}

/// The text with its last number moved by one, if it has one.
fn neighbours(s: &str) -> Vec<String> {
    let mut out = vec![s.to_string()];
    let head_end = s.rfind(|c: char| !c.is_ascii_digit()).map_or(0, |i| i + 1);
    let (head, tail) = s.split_at(head_end);
    if let Ok(n) = tail.parse::<u64>() {
        out.push(format!("{head}{}", n + 1));
        if n > 0 {
            out.push(format!("{head}{}", n - 1));
        }
    }
    out
}

#[test]
fn every_corpus_boundary_and_neighbour_gives_a_deterministic_answer() {
    let files = corpus_files();
    assert_eq!(files.len(), 23);
    let s = scheme();
    let (mut ins, mut outs, mut unknowns) = (0, 0, 0);
    for (name, bytes) in &files {
        let adv = parse_advisory_from(bytes, Source::GuardDogCorpus).unwrap();
        for (idx, entry) in adv.affected.iter().enumerate() {
            let mut boundaries: Vec<String> = Vec::new();
            // Collect boundary strings from the raw record, independently of the parser.
            let raw: Value = serde_json::from_slice(bytes).unwrap();
            if let Some(ranges) = raw["affected"][idx]["ranges"].as_array() {
                for r in ranges {
                    for e in r["events"].as_array().into_iter().flatten() {
                        if let Some(o) = e.as_object() {
                            for v in o.values() {
                                if let Some(t) = v.as_str() {
                                    boundaries.extend(neighbours(t.trim_start_matches('v')));
                                }
                            }
                        }
                    }
                }
            }
            boundaries.sort();
            boundaries.dedup();
            for b in &boundaries {
                let first = evaluate_entry(&s, idx, entry, Some(b));
                let second = evaluate_entry(&s, idx, entry, Some(b));
                assert_eq!(first, second, "{name} entry {idx} {b}");
                assert!(first != VersionEvidence::NotApplicable, "{name}");
                match first {
                    VersionEvidence::InRange(_) => ins += 1,
                    VersionEvidence::OutOfRange => outs += 1,
                    _ => unknowns += 1,
                }
            }
        }
    }
    // The run is not vacuous: every kind of answer occurs on real records.
    assert!(ins > 0 && outs > 0 && unknowns > 0, "{ins} {outs} {unknowns}");
}
