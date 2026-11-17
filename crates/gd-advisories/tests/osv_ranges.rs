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
    Advisory, Candidate, GapKind, Location, MAX_GAPS, Place, RangeKind, Source, UnknownReason,
    VersionError, VersionEvidence, VersionScheme, evaluate_entry, parse_advisory,
    parse_advisory_from,
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
/// `poison` lists raw strings the scheme refuses to read; `unordered` makes it
/// an identity-only scheme.
#[derive(Clone, Default)]
struct TestScheme {
    semver: bool,
    unordered: bool,
    poison: Vec<String>,
}

fn scheme() -> TestScheme {
    TestScheme {
        semver: true,
        ..TestScheme::default()
    }
}

impl VersionScheme for TestScheme {
    type Version = V;

    fn parse(&self, raw: &str) -> Result<V, VersionError> {
        if self.poison.iter().any(|p| p == raw) {
            return Err(VersionError::Malformed);
        }
        let raw = raw.strip_prefix('v').unwrap_or(raw);
        let (core, rc) = match raw.split_once("-rc") {
            Some((c, r)) => (
                c,
                Some(r.parse::<u64>().map_err(|_| VersionError::Malformed)?),
            ),
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

    /// `low~high` (or `low~`) is an installed value known only to lie in an interval.
    fn candidate(&self, raw: &str) -> Result<Candidate<V>, VersionError> {
        match raw.split_once('~') {
            Some((low, "")) => Ok(Candidate::Between {
                low: self.parse(low)?,
                high: None,
            }),
            Some((low, high)) => Ok(Candidate::Between {
                low: self.parse(low)?,
                high: Some(self.parse(high)?),
            }),
            None => self.parse(raw).map(Candidate::Exact),
        }
    }

    fn reads_semver_ranges(&self) -> bool {
        self.semver
    }

    fn orders(&self) -> bool {
        !self.unordered
    }
}

// ---------------------------------------------------------------- helpers

fn entry_from(ranges: Value, versions: Value) -> Advisory {
    let mut e = json!({"package": {"ecosystem": "PyPI", "name": "cashu"}});
    if ranges.as_array().is_some_and(|r| !r.is_empty()) {
        e["ranges"] = ranges;
    }
    if versions.as_array().is_some_and(|r| !r.is_empty()) {
        e["versions"] = versions;
    }
    // The same entry at indices 0 to 7, so tests can check an index is carried.
    let big = e.to_string().len() > 4096;
    let affected: Vec<Value> = (0..if big { 1 } else { 8 }).map(|_| e.clone()).collect();
    let record =
        json!({"id": "x_test-1", "modified": "2026-11-17T00:00:00Z", "affected": affected});
    parse_advisory(record.to_string().as_bytes()).unwrap()
}

fn eco(events: Value) -> Value {
    json!({"type": "ECOSYSTEM", "events": events})
}

fn ev(s: &str, installed: &str) -> VersionEvidence {
    let events: Value = serde_json::from_str(s).unwrap();
    let entry = entry_from(json!([eco(events)]), json!([]));
    evaluate_entry(&scheme(), &entry, 0, Some(installed))
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
    let r =
        r#"[{"introduced":"1.0.0"},{"fixed":"1.0.2"},{"introduced":"3.0.0"},{"fixed":"3.2.5"}]"#;
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
    let e = evaluate_entry(&scheme(), &entry, 0, None);
    assert_eq!(reason(&e), UnknownReason::InstalledVersionUnknown);
}

#[test]
fn row_list_and_range_are_a_union() {
    let entry = entry_from(
        json!([eco(json!([{"introduced": "0"}, {"fixed": "1.0.2"}]))]),
        json!(["1.0.2"]),
    );
    let e = evaluate_entry(&scheme(), &entry, 0, Some("1.0.2"));
    assert_eq!(
        e,
        VersionEvidence::InRange(Location {
            entry: 0,
            place: Place::Listed { index: 0 }
        })
    );
    assert_eq!(
        evaluate_entry(&scheme(), &entry, 0, Some("1.0.3")),
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
    let run = |v| evaluate_entry(&scheme(), &entry, 0, Some(v));
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
    let e = evaluate_entry(&scheme(), &entry, 7, Some("3.5"));
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
    let cands = [
        "0.5", "1", "1.5", "2", "2.5", "3", "3.9", "4", "8", "9", "10",
    ];
    let expected: Vec<&str> = cands
        .iter()
        .map(|c| {
            let entry = entry_from(json!([eco(Value::Array(events.to_vec()))]), json!([]));
            kind(&evaluate_entry(&scheme(), &entry, 0, Some(c)))
        })
        .collect();
    assert_eq!(
        expected,
        [
            "out", "in", "in", "out", "out", "in", "in", "out", "out", "out", "out"
        ]
    );
    let mut idx: Vec<usize> = (0..events.len()).collect();
    let mut count = 0;
    permute(&mut idx, 0, &mut |p| {
        count += 1;
        let shuffled: Vec<Value> = p.iter().map(|&i| events[i].clone()).collect();
        let entry = entry_from(json!([eco(Value::Array(shuffled))]), json!([]));
        let got: Vec<&str> = cands
            .iter()
            .map(|c| kind(&evaluate_entry(&scheme(), &entry, 0, Some(c))))
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
            kind(&evaluate_entry(&scheme(), &plain, 0, Some(c))),
            kind(&evaluate_entry(&scheme(), &noted, 0, Some(c))),
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

fn listed(versions: Value) -> Advisory {
    entry_from(json!([]), versions)
}

#[test]
fn a_complete_list_only_entry_clears_what_it_does_not_name() {
    let entry = listed(json!(["1.0.0", "1.0.1"]));
    let run = |v| evaluate_entry(&scheme(), &entry, 3, Some(v));
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
fn a_list_cannot_clear_without_a_known_installed_identity() {
    let entry = listed(json!(["1.0.0"]));
    let none = evaluate_entry(&scheme(), &entry, 0, None);
    assert_eq!(reason(&none), UnknownReason::InstalledVersionUnknown);
    let junk = evaluate_entry(&scheme(), &entry, 0, Some("banana"));
    assert_eq!(reason(&junk), UnknownReason::InstalledVersionUnparseable);
    let empty = evaluate_entry(&scheme(), &entry, 0, Some(""));
    assert!(matches!(empty, VersionEvidence::Unknown { .. }));
}

#[test]
fn an_unreadable_listed_version_keeps_the_answer_open() {
    let entry = listed(json!(["1.0.0", "banana"]));
    let e = evaluate_entry(&scheme(), &entry, 0, Some("2.0.0"));
    assert_eq!(reason(&e), UnknownReason::UnreadableListedVersion);
    // A hit elsewhere in the list is still positive evidence.
    assert!(matches!(
        evaluate_entry(&scheme(), &entry, 0, Some("1.0.0")),
        VersionEvidence::InRange(_)
    ));
}

#[test]
fn a_list_miss_does_not_clear_when_a_range_is_unknown() {
    let entry = entry_from(
        json!([eco(json!([{"introduced": "x"}, {"fixed": "2"}]))]),
        json!(["1.0.0"]),
    );
    let e = evaluate_entry(&scheme(), &entry, 0, Some("5"));
    assert_eq!(reason(&e), UnknownReason::UnparseableBoundary);
    // And a list hit still wins the union.
    assert!(matches!(
        evaluate_entry(&scheme(), &entry, 0, Some("1.0.0")),
        VersionEvidence::InRange(_)
    ));
}

#[test]
fn ranges_and_list_both_must_exclude() {
    let entry = entry_from(
        json!([eco(json!([{"introduced": "1"}, {"fixed": "2"}]))]),
        json!(["7"]),
    );
    let run = |v| evaluate_entry(&scheme(), &entry, 0, Some(v));
    assert!(matches!(run("7"), VersionEvidence::InRange(_)));
    assert!(matches!(run("1.5"), VersionEvidence::InRange(_)));
    assert_eq!(run("5"), VersionEvidence::OutOfRange);
}

#[test]
fn an_entry_with_nothing_usable_is_unknown() {
    let entry = entry_from(json!([]), json!([]));
    let e = evaluate_entry(&scheme(), &entry, 2, Some("1"));
    assert_eq!(reason(&e), UnknownReason::NoUsableRangeOrVersions);
    let entry = entry_from(json!([eco(json!([]))]), json!([]));
    assert!(matches!(
        evaluate_entry(&scheme(), &entry, 0, Some("1")),
        VersionEvidence::Unknown { .. }
    ));
}

// ------------------------------------------------------------ GIT ranges

fn git_entry(versions: Value) -> Advisory {
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
    assert!(matches!(entry.affected[0].ranges[0].kind, RangeKind::Git));
    let e = evaluate_entry(&scheme(), &entry, 0, Some("1.2.3"));
    match &e {
        VersionEvidence::Unknown {
            reason, question, ..
        } => {
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
        evaluate_entry(&scheme(), &entry, 0, Some("1.2.4")),
        VersionEvidence::InRange(Location {
            entry: 0,
            place: Place::Listed { index: 1 }
        })
    );
    // A list miss cannot clear the unresolved GIT range.
    let miss = evaluate_entry(&scheme(), &entry, 0, Some("9.9.9"));
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
        evaluate_entry(&scheme(), &entry, 0, Some("1.5")),
        VersionEvidence::InRange(_)
    ));
    assert!(matches!(
        evaluate_entry(&scheme(), &entry, 0, Some("5")),
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
    let strict = TestScheme::default();
    for c in ["1", "3"] {
        let e = evaluate_entry(&strict, &entry, 0, Some(c));
        assert_eq!(reason(&e), UnknownReason::SchemeMismatch, "{c}");
    }
    // The same range on a SemVer-compatible scheme is evaluated.
    assert!(matches!(
        evaluate_entry(&scheme(), &entry, 0, Some("1")),
        VersionEvidence::InRange(_)
    ));
    // ECOSYSTEM ranges are in the product's own scheme, whatever it declares.
    let eco_entry = entry_from(
        json!([eco(json!([{"introduced": "0"}, {"fixed": "2"}]))]),
        json!([]),
    );
    assert!(matches!(
        evaluate_entry(&strict, &eco_entry, 0, Some("1")),
        VersionEvidence::InRange(_)
    ));
    assert_eq!(
        evaluate_entry(&strict, &eco_entry, 0, Some("3")),
        VersionEvidence::OutOfRange
    );
}

#[test]
fn an_unsupported_range_type_is_unknown() {
    let entry = entry_from(
        json!([{"type": "WIBBLE", "events": [{"introduced": "0"}, {"fixed": "2"}]}]),
        json!([]),
    );
    let e = evaluate_entry(&scheme(), &entry, 0, Some("5"));
    assert!(matches!(e, VersionEvidence::Unknown { .. }));
}

#[test]
fn unknown_installed_version_is_never_out_of_range() {
    let entry = entry_from(
        json!([eco(json!([{"introduced": "1"}, {"fixed": "2"}]))]),
        json!([]),
    );
    let e = evaluate_entry(&scheme(), &entry, 4, None);
    match e {
        VersionEvidence::Unknown {
            reason,
            question,
            at,
        } => {
            assert_eq!(reason, UnknownReason::InstalledVersionUnknown);
            assert!(!question.is_empty());
            assert_eq!(at.entry, 4);
        }
        other => panic!("{other:?}"),
    }
    let junk = evaluate_entry(&scheme(), &entry, 0, Some("not a version"));
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
            VersionEvidence::Unknown { question, .. } => {
                assert!(!question.trim().is_empty(), "{r}")
            }
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
        evaluate_entry(&scheme(), &entry, 0, Some("500")),
        VersionEvidence::InRange(_)
    ));
    assert_eq!(
        evaluate_entry(&scheme(), &entry, 0, Some("501")),
        VersionEvidence::OutOfRange
    );
    assert!(matches!(
        evaluate_entry(&scheme(), &entry, 0, Some("7.9999")),
        VersionEvidence::InRange(_)
    ));
    // Past the last fix, nothing in the list or the ranges names it.
    assert_eq!(
        evaluate_entry(&scheme(), &entry, 0, Some("5000")),
        VersionEvidence::OutOfRange
    );
}

// ------------------------------------------------- fix round: new rules

fn all_reasons(r: &str, cands: &[&str]) -> Vec<UnknownReason> {
    cands
        .iter()
        .map(|c| {
            let e = ev(r, c);
            assert!(
                matches!(e, VersionEvidence::Unknown { .. }),
                "{r} {c}: {e:?}"
            );
            reason(&e)
        })
        .collect()
}

#[test]
fn zero_on_a_limit_is_malformed_never_out() {
    for r in [
        r#"[{"introduced":"0"},{"limit":"0"}]"#,
        r#"[{"introduced":"1"},{"fixed":"2"},{"limit":"0"}]"#,
        r#"[{"introduced":"0"},{"fixed":"2"},{"limit":" 0"}]"#,
        r#"[{"introduced":"0"},{"fixed":"2"},{"limit":"0 "}]"#,
        r#"[{"introduced":"0"},{"fixed":" 0 "}]"#,
        r#"[{"introduced":"0"},{"last_affected":"\t0"}]"#,
    ] {
        for reason in all_reasons(r, &["0", "0.5", "1", "5"]) {
            assert_eq!(reason, UnknownReason::MalformedRange, "{r}");
        }
    }
}

#[test]
fn outer_whitespace_is_trimmed_before_the_zero_and_star_rules() {
    // " 0" is the "from the start" introduction, not a string for a parser.
    let r = r#"[{"introduced":" 0 "},{"fixed":" 2"}]"#;
    assert!(is_in(r, "0"));
    assert!(is_in(r, "1"));
    assert!(is_out(r, "2"));
    let star = r#"[{"introduced":"0"},{"limit":" * "}]"#;
    assert!(is_in(star, "1000"));
    // Ordinary boundaries with outer whitespace read as the bare version.
    let padded = r#"[{"introduced":" 1 "},{"fixed":"\t3\n"}]"#;
    assert!(is_in(padded, "2"));
    assert!(is_out(padded, "3"));
    // Listed versions are trimmed too.
    let entry = listed(json!([" 1.0.0 "]));
    assert!(matches!(
        evaluate_entry(&scheme(), &entry, 0, Some("1.0.0")),
        VersionEvidence::InRange(_)
    ));
}

#[test]
fn a_single_release_range_names_exactly_that_release() {
    let r = r#"[{"introduced":"1"},{"last_affected":"1"}]"#;
    assert!(is_in(r, "1"));
    assert!(is_out(r, "0.5"));
    assert!(is_out(r, "1-rc1"));
    assert!(is_out(r, "2"));
    assert_eq!(
        ev(r, "1"),
        VersionEvidence::InRange(Location {
            entry: 0,
            place: Place::Range {
                range: 0,
                event: Some(0)
            }
        })
    );
    // After a closed interval, the same shape is still a point.
    let r =
        r#"[{"introduced":"0"},{"last_affected":"1"},{"introduced":"3"},{"last_affected":"3"}]"#;
    assert!(is_in(r, "0.5"));
    assert!(is_out(r, "2"));
    assert!(is_in(r, "3"));
    assert!(is_out(r, "4"));
    // Written in any order.
    let r = r#"[{"last_affected":"1"},{"introduced":"1"}]"#;
    assert!(is_in(r, "1"));
    assert!(is_out(r, "2"));
}

#[test]
fn a_tie_with_an_interval_open_below_is_unknown() {
    for r in [
        r#"[{"introduced":"0"},{"last_affected":"2"},{"introduced":"2"}]"#,
        r#"[{"introduced":"0"},{"fixed":"2"},{"introduced":"2"}]"#,
        r#"[{"introduced":"1"},{"fixed":"1"}]"#,
        r#"[{"introduced":"1"},{"fixed":"1"},{"last_affected":"1"}]"#,
    ] {
        for c in ["0.5", "1", "2", "3"] {
            assert!(is_unknown(r, c), "{r} {c}");
        }
    }
}

#[test]
fn events_must_alternate_opening_and_closing() {
    for r in [
        // Reversed bounds.
        r#"[{"introduced":"5"},{"fixed":"3"}]"#,
        r#"[{"introduced":"5"},{"last_affected":"3"}]"#,
        // Two closings in a row.
        r#"[{"introduced":"1"},{"fixed":"2"},{"fixed":"3"}]"#,
        // A closing before any opening.
        r#"[{"fixed":"1"},{"introduced":"2"}]"#,
        r#"[{"introduced":"3"},{"fixed":"2"},{"introduced":"4"}]"#,
    ] {
        for reason in all_reasons(r, &["0.5", "1.5", "2.5", "4", "6"]) {
            assert_eq!(reason, UnknownReason::MalformedRange, "{r}");
        }
    }
    // Openings in a row and a trailing opening are fine.
    let ok = r#"[{"introduced":"1"},{"introduced":"3"},{"fixed":"5"},{"introduced":"7"}]"#;
    assert!(is_out(ok, "0.5"));
    assert!(is_in(ok, "4"));
    assert!(is_out(ok, "6"));
    assert!(is_in(ok, "9"));
}

#[test]
fn a_range_cannot_reopen_beyond_its_own_limit() {
    for r in [
        r#"[{"introduced":"0"},{"limit":"2"},{"introduced":"3"}]"#,
        r#"[{"introduced":"3"},{"limit":"3"}]"#,
        r#"[{"introduced":"1"},{"fixed":"2"},{"introduced":"5"},{"limit":"4"}]"#,
    ] {
        for reason in all_reasons(r, &["0.5", "1.5", "2.5", "4", "6"]) {
            assert_eq!(reason, UnknownReason::MalformedRange, "{r}");
        }
    }
}

#[test]
fn a_closing_cannot_contradict_the_limits_of_its_own_range() {
    for r in [
        // The record names 3 as affected and also caps the range at 3.
        r#"[{"introduced":"1"},{"last_affected":"3"},{"limit":"3"}]"#,
        r#"[{"introduced":"1"},{"last_affected":"3"},{"limit":"2"},{"limit":"3"}]"#,
        // The fix lies beyond every limit.
        r#"[{"introduced":"1"},{"fixed":"5"},{"limit":"3"}]"#,
        r#"[{"introduced":"1"},{"fixed":"5"},{"limit":"3"},{"limit":"4"}]"#,
    ] {
        for reason in all_reasons(r, &["0.5", "1.5", "3", "4", "6"]) {
            assert_eq!(reason, UnknownReason::MalformedRange, "{r}");
        }
    }
    // Valid shapes stay as they were.
    let r = r#"[{"introduced":"1"},{"fixed":"2"},{"limit":"3"}]"#;
    assert!(is_in(r, "1.5"));
    assert!(is_out(r, "2.5"));
    // A fix at the limit, a last_affected below it, or a star are all fine.
    let r = r#"[{"introduced":"1"},{"fixed":"3"},{"limit":"3"}]"#;
    assert!(is_in(r, "2"));
    assert!(is_out(r, "3"));
    let r = r#"[{"introduced":"1"},{"last_affected":"3"},{"limit":"4"}]"#;
    assert!(is_in(r, "3"));
    assert!(is_out(r, "3.5"));
    let r = r#"[{"introduced":"1"},{"last_affected":"3"},{"limit":"3"},{"limit":"*"}]"#;
    assert!(is_in(r, "3"));
    // One limit above the closing is enough, since limits expand.
    let r = r#"[{"introduced":"1"},{"fixed":"5"},{"limit":"3"},{"limit":"9"}]"#;
    assert!(is_in(r, "4"));
}

#[test]
fn limits_expand_so_a_reopening_below_only_some_limits_is_fine() {
    // 3 is below the limit 9, so the range may reopen there.
    let r = r#"[{"introduced":"0"},{"fixed":"2"},{"limit":"9"},{"limit":"1"},{"introduced":"3"}]"#;
    assert!(is_in(r, "1.5"));
    assert!(is_out(r, "2.5"));
    assert!(is_in(r, "3"));
    assert!(is_in(r, "8"));
    assert!(is_out(r, "9"));
    // A star is infinity: nothing is at or above every limit.
    let star = r#"[{"introduced":"0"},{"limit":"2"},{"limit":"*"},{"introduced":"3"}]"#;
    assert!(is_in(star, "5"));
}

#[test]
fn a_listed_version_spelled_differently_is_never_a_miss() {
    // 1.0 and 1.0.0 are equal in order and different identities.
    let entry = listed(json!(["1.0.0"]));
    let e = evaluate_entry(&scheme(), &entry, 0, Some("1.0"));
    match &e {
        VersionEvidence::Unknown {
            reason, question, ..
        } => {
            assert_eq!(*reason, UnknownReason::SameVersionDifferentSpelling);
            assert!(!question.trim().is_empty());
        }
        other => panic!("{other:?}"),
    }
    // Next to a range that excludes it, still not a clearance.
    let entry = entry_from(
        json!([eco(json!([{"introduced": "5"}, {"fixed": "6"}]))]),
        json!(["1.0.0"]),
    );
    let e = evaluate_entry(&scheme(), &entry, 0, Some("1.0"));
    assert_eq!(reason(&e), UnknownReason::SameVersionDifferentSpelling);
    // The same spelling is a hit; a genuinely different version is a miss.
    assert!(matches!(
        evaluate_entry(&scheme(), &entry, 0, Some("1.0.0")),
        VersionEvidence::InRange(_)
    ));
    assert_eq!(
        evaluate_entry(&scheme(), &entry, 0, Some("1.0.1")),
        VersionEvidence::OutOfRange
    );
}

fn record_with(extra: Value) -> Advisory {
    let mut record = json!({
        "id": "x_test-1",
        "modified": "2026-11-17T00:00:00Z",
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "cashu"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1"}, {"fixed": "2"}]}]
        }]
    });
    for (k, v) in extra.as_object().unwrap() {
        record[k] = v.clone();
    }
    parse_advisory(record.to_string().as_bytes()).unwrap()
}

#[test]
fn a_record_that_is_uncertain_as_a_whole_never_clears() {
    let plain = record_with(json!({}));
    assert_eq!(
        evaluate_entry(&scheme(), &plain, 0, Some("5")),
        VersionEvidence::OutOfRange
    );

    let schema = record_with(json!({"schema_version": "1.0.0"}));
    assert!(
        schema
            .gaps
            .iter()
            .any(|g| g.kind == GapKind::UnexpectedSchemaVersion)
    );

    let mut many = serde_json::Map::new();
    for i in 0..(MAX_GAPS + 20) {
        many.insert(format!("zz_unknown_{i}"), json!(1));
    }
    let truncated = record_with(Value::Object(many));
    assert!(
        truncated
            .gaps
            .iter()
            .any(|g| g.kind == GapKind::GapsTruncated)
    );

    for adv in [&schema, &truncated] {
        let e = evaluate_entry(&scheme(), adv, 0, Some("5"));
        assert_eq!(reason(&e), UnknownReason::RecordUncertain);
        // Positive evidence still stands.
        assert!(matches!(
            evaluate_entry(&scheme(), adv, 0, Some("1.5")),
            VersionEvidence::InRange(_)
        ));
    }
}

#[test]
fn an_entry_index_outside_the_record_is_unknown() {
    let adv = record_with(json!({}));
    assert!(matches!(
        evaluate_entry(&scheme(), &adv, 9, Some("1")),
        VersionEvidence::Unknown { .. }
    ));
}

#[test]
fn an_interval_candidate_is_out_only_when_nothing_inside_can_open_a_range() {
    let entry = entry_from(
        json!([eco(json!([{"introduced": "5"}, {"fixed": "7"}]))]),
        json!([]),
    );
    let run = |v| evaluate_entry(&scheme(), &entry, 0, Some(v));
    // Below the range, and the interval ends before it opens.
    assert_eq!(run("1~3"), VersionEvidence::OutOfRange);
    // Past the fix, with nothing above that opens.
    assert_eq!(run("8~"), VersionEvidence::OutOfRange);
    assert_eq!(run("8~20"), VersionEvidence::OutOfRange);
    // An opening inside the interval, or an open low end, cannot be decided.
    for v in ["1~6", "1~", "6~", "4~5"] {
        assert_eq!(reason(&run(v)), UnknownReason::CandidateIsAnInterval, "{v}");
    }
    // Open at the low end with no closing inside: every version in it is in.
    assert!(matches!(run("5~6"), VersionEvidence::InRange(_)));
    // An exact version is unaffected.
    assert!(matches!(run("6"), VersionEvidence::InRange(_)));
    // A listed version inside the interval keeps it open; outside does not.
    let listed_in = entry_from(
        json!([eco(json!([{"introduced": "5"}, {"fixed": "7"}]))]),
        json!(["2"]),
    );
    assert_eq!(
        reason(&evaluate_entry(&scheme(), &listed_in, 0, Some("1~3"))),
        UnknownReason::CandidateIsAnInterval
    );
    let listed_out = entry_from(
        json!([eco(json!([{"introduced": "5"}, {"fixed": "7"}]))]),
        json!(["9"]),
    );
    assert_eq!(
        evaluate_entry(&scheme(), &listed_out, 0, Some("1~3")),
        VersionEvidence::OutOfRange
    );
}

#[test]
fn an_interval_candidate_is_in_range_when_no_closing_lies_inside() {
    let between = |events: &str, installed: &str| {
        let entry = entry_from(
            json!([eco(serde_json::from_str(events).unwrap())]),
            json!([]),
        );
        evaluate_entry(&scheme(), &entry, 0, Some(installed))
    };
    // Core style: a release candidate that may read as a final release.
    let rc = "28.3-rc0~28.3.1";
    assert!(matches!(
        between(r#"[{"introduced":"28.0"},{"fixed":"29.0"}]"#, rc),
        VersionEvidence::InRange(_)
    ));
    // The fix 28.3 lies inside the interval, so it cannot be decided.
    let e = between(r#"[{"introduced":"28.0"},{"fixed":"28.3"}]"#, rc);
    assert_eq!(reason(&e), UnknownReason::CandidateIsAnInterval);
    // No upper end: in only when nothing closes above.
    assert!(matches!(
        between(r#"[{"introduced":"0"}]"#, "1.1.2~"),
        VersionEvidence::InRange(_)
    ));
    let e = between(r#"[{"introduced":"0"},{"fixed":"2"}]"#, "1.1.2~");
    assert_eq!(reason(&e), UnknownReason::CandidateIsAnInterval);
    // A last_affected at the low end still closes everything above it.
    let e = between(r#"[{"introduced":"0"},{"last_affected":"1"}]"#, "1~3");
    assert_eq!(reason(&e), UnknownReason::CandidateIsAnInterval);
    // The upper end must be within a limit.
    let limited = r#"[{"introduced":"0"},{"limit":"4"}]"#;
    assert!(matches!(
        between(limited, "1~3"),
        VersionEvidence::InRange(_)
    ));
    assert!(matches!(
        between(limited, "1~4"),
        VersionEvidence::InRange(_)
    ));
    assert_eq!(
        reason(&between(limited, "1~5")),
        UnknownReason::CandidateIsAnInterval
    );
    assert_eq!(
        reason(&between(limited, "1~")),
        UnknownReason::CandidateIsAnInterval
    );
    let star = r#"[{"introduced":"0"},{"limit":"*"}]"#;
    assert!(matches!(between(star, "1~"), VersionEvidence::InRange(_)));
}

#[test]
fn a_scheme_without_an_order_makes_ranges_unknown_and_still_checks_the_list() {
    let none = TestScheme {
        unordered: true,
        semver: true,
        ..TestScheme::default()
    };
    let ranges = entry_from(
        json!([eco(json!([{"introduced": "0"}, {"fixed": "2"}]))]),
        json!([]),
    );
    for c in ["1", "5"] {
        let e = evaluate_entry(&none, &ranges, 0, Some(c));
        assert_eq!(reason(&e), UnknownReason::SchemeDoesNotOrder, "{c}");
    }
    let both = entry_from(
        json!([eco(json!([{"introduced": "0"}, {"fixed": "2"}]))]),
        json!(["9"]),
    );
    assert!(matches!(
        evaluate_entry(&none, &both, 0, Some("9")),
        VersionEvidence::InRange(_)
    ));
    assert!(matches!(
        evaluate_entry(&none, &both, 0, Some("1")),
        VersionEvidence::Unknown { .. }
    ));
    // A complete list-only entry is decided by identity alone.
    let only = listed(json!(["9"]));
    assert_eq!(
        evaluate_entry(&none, &only, 0, Some("1")),
        VersionEvidence::OutOfRange
    );
}

#[test]
fn the_smallest_reason_wins_whatever_the_order() {
    let git = json!({"type": "GIT", "repo": "https://github.com/example/project",
        "events": [{"introduced": "0"}, {"fixed": "4cd3cf6a1b2c3d4e5f60718293a4b5c6d7e8f901"}]});
    let bad_limit = eco(json!([{"introduced": "0"}, {"limit": "banana"}]));
    for ranges in [json!([git, bad_limit]), json!([bad_limit, git])] {
        let entry = entry_from(ranges, json!(["banana"]));
        let e = evaluate_entry(&scheme(), &entry, 0, Some("1"));
        assert_eq!(reason(&e), UnknownReason::NoCommitGraph);
    }
    // Within one range too: an unparseable boundary beats a malformed shape.
    let r = r#"[{"introduced":"x"},{"fixed":"2"},{"fixed":"1"}]"#;
    assert_eq!(reason(&ev(r, "1")), UnknownReason::UnparseableBoundary);
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
        1 => Just(" 0 ".to_string()),
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

fn range_json(r: &RangeSpec, range_index: usize, replace: Option<(usize, usize)>) -> Value {
    let events: Vec<Value> = r
        .events
        .iter()
        .enumerate()
        .map(|(j, e)| {
            let v = if replace == Some((range_index, j)) {
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
}

/// `replace` swaps one event's value for text the scheme cannot read.
fn build_from(
    ranges: &[RangeSpec],
    versions: &[String],
    replace: Option<(usize, usize)>,
) -> Option<Advisory> {
    let ranges: Vec<Value> = ranges
        .iter()
        .enumerate()
        .map(|(i, r)| range_json(r, i, replace))
        .collect();
    let mut e = json!({"package": {"ecosystem": "PyPI", "name": "cashu"}});
    if !ranges.is_empty() {
        e["ranges"] = Value::Array(ranges);
    }
    if !versions.is_empty() {
        e["versions"] = json!(versions);
    }
    let record = json!({"id": "x_test-1", "modified": "2026-11-17T00:00:00Z", "affected": [e]});
    parse_advisory(record.to_string().as_bytes()).ok()
}

fn build(spec: &Spec, replace: Option<(usize, usize)>) -> Option<Advisory> {
    build_from(&spec.ranges, &spec.versions, replace)
}

/// A result can lose certainty but never swap it for the opposite answer.
fn no_stronger_or_opposite(before: &VersionEvidence, after: &VersionEvidence) -> bool {
    kind(before) == kind(after) || matches!(after, VersionEvidence::Unknown { .. })
}

/// Exact versions, and intervals (`low~high`, `low~`) the test scheme reads.
fn installed_or_interval() -> impl Strategy<Value = String> {
    prop_oneof![
        6 => installed_strategy(),
        2 => (0u8..8, 1u8..4).prop_map(|(a, k)| format!("{a}~{}", a + k)),
        1 => (0u8..8).prop_map(|a| format!("{a}~")),
    ]
}

fn installed_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        (0u8..9).prop_map(|n| n.to_string()),
        (1u8..9).prop_map(|n| format!("{n}-rc1"))
    ]
}

/// Unknown never moves a result toward not-affected: an installed version, a
/// boundary, a listed version or the scheme's reading replaced by something
/// unreadable never turns InRange or Unknown into OutOfRange, and never makes
/// an OutOfRange base into a positive answer either. The run also counts what
/// it reached, so a generator that stops producing one kind of base fails.
#[test]
fn unknown_never_moves_toward_out_of_range() {
    use std::cell::Cell;
    let (ins, outs, unknowns, mutated) = (Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0));
    let mut runner = proptest::test_runner::TestRunner::new(config());
    let strategy = (
        spec(),
        installed_or_interval(),
        (any::<usize>(), any::<usize>()),
    );
    runner
        .run(&strategy, |(spec, installed, pick)| {
            let Some(entry) = build(&spec, None) else {
                return Ok(());
            };
            let s = scheme();
            let base = evaluate_entry(&s, &entry, 0, Some(&installed));
            prop_assert!(base != VersionEvidence::NotApplicable);
            match base {
                VersionEvidence::InRange(_) => ins.set(ins.get() + 1),
                VersionEvidence::OutOfRange => outs.set(outs.get() + 1),
                _ => unknowns.set(unknowns.get() + 1),
            }

            // The installed version becomes unknown or unreadable.
            for gone in [None, Some("banana"), Some("")] {
                let after = evaluate_entry(&s, &entry, 0, gone);
                prop_assert!(
                    matches!(after, VersionEvidence::Unknown { .. }),
                    "{gone:?} {after:?}"
                );
            }

            // One boundary becomes unreadable.
            let total: usize = spec.ranges.iter().map(|r| r.events.len()).sum();
            if total > 0 {
                let mut n = pick.0 % total;
                let mut at = (0, 0);
                for (i, r) in spec.ranges.iter().enumerate() {
                    if n < r.events.len() {
                        at = (i, n);
                        break;
                    }
                    n -= r.events.len();
                }
                if let Some(changed) = build(&spec, Some(at)) {
                    let after = evaluate_entry(&s, &changed, 0, Some(&installed));
                    prop_assert!(
                        no_stronger_or_opposite(&base, &after),
                        "{base:?} -> {after:?}"
                    );
                    mutated.set(mutated.get() + 1);
                }
                // The scheme refuses to read that same boundary text.
                let (i, j) = at;
                let poisoned = TestScheme {
                    semver: true,
                    poison: vec![spec.ranges[i].events[j].value.clone()],
                    ..TestScheme::default()
                };
                let after = evaluate_entry(&poisoned, &entry, 0, Some(&installed));
                prop_assert!(
                    no_stronger_or_opposite(&base, &after),
                    "{base:?} -> {after:?}"
                );
            }

            // The scheme refuses to read a listed version.
            if let Some(v) = spec.versions.get(pick.1 % spec.versions.len().max(1)) {
                let poisoned = TestScheme {
                    semver: true,
                    poison: vec![v.clone()],
                    ..TestScheme::default()
                };
                let after = evaluate_entry(&poisoned, &entry, 0, Some(&installed));
                prop_assert!(
                    no_stronger_or_opposite(&base, &after),
                    "{base:?} -> {after:?}"
                );
            }

            // A scheme without SemVer compatibility, or without an order.
            for weaker in [
                TestScheme::default(),
                TestScheme {
                    semver: true,
                    unordered: true,
                    ..TestScheme::default()
                },
            ] {
                let after = evaluate_entry(&weaker, &entry, 0, Some(&installed));
                prop_assert!(
                    no_stronger_or_opposite(&base, &after),
                    "{base:?} -> {after:?}"
                );
            }
            Ok(())
        })
        .unwrap();
    // The generator reaches every kind of base, and boundary mutations.
    assert!(ins.get() >= 50, "in-range bases: {}", ins.get());
    assert!(outs.get() >= 100, "out-of-range bases: {}", outs.get());
    assert!(unknowns.get() >= 100, "unknown bases: {}", unknowns.get());
    assert!(mutated.get() >= 300, "mutated entries: {}", mutated.get());
}

/// Known-invalid patterns are never out of range, whatever else is around them.
#[test]
fn a_known_invalid_range_is_never_out_of_range() {
    let pattern = (0u8..10, 0u8..4, 1u8..4, 0u8..3).prop_map(|(shape, a, k, ws)| {
        let pad = ["", " ", "\t"][ws as usize];
        let (lo, hi) = (a, a + k);
        let events = match shape {
            0 => json!([{"introduced": "0"}, {"limit": format!("{pad}0{pad}")}]),
            1 => json!([{"introduced": lo.to_string()}, {"fixed": hi.to_string()}, {"limit": format!("{pad}0")}]),
            2 => json!([{"introduced": hi.to_string()}, {"fixed": lo.to_string()}]),
            3 => json!([{"introduced": lo.to_string()}, {"fixed": hi.to_string()}, {"fixed": (hi + 1).to_string()}]),
            4 => json!([{"fixed": lo.to_string()}, {"introduced": hi.to_string()}]),
            5 => json!([{"introduced": "0"}, {"limit": hi.to_string()}, {"introduced": (hi + 1).to_string()}]),
            6 => json!([{"introduced": "0"}, {"fixed": format!("{pad}0{pad}")}]),
            7 => json!([{"introduced": lo.to_string()}, {"last_affected": hi.to_string()}, {"last_affected": (hi + 1).to_string()}]),
            8 => json!([{"introduced": lo.to_string()}, {"last_affected": hi.to_string()}, {"limit": hi.to_string()}]),
            _ => json!([{"introduced": lo.to_string()}, {"fixed": (hi + 1).to_string()}, {"limit": hi.to_string()}]),
        };
        eco(events)
    });
    let strategy = (
        pattern,
        prop::collection::vec(spec(), 0..1),
        installed_strategy(),
        any::<bool>(),
    );
    proptest::test_runner::TestRunner::new(config())
        .run(&strategy, |(bad, other, installed, first)| {
            let mut ranges: Vec<Value> = other
                .first()
                .map(|s| {
                    s.ranges
                        .iter()
                        .enumerate()
                        .map(|(i, r)| range_json(r, i, None))
                        .collect()
                })
                .unwrap_or_default();
            if first {
                ranges.insert(0, bad);
            } else {
                ranges.push(bad);
            }
            let versions = other
                .first()
                .map(|s| s.versions.clone())
                .unwrap_or_default();
            let entry = entry_from(Value::Array(ranges), json!(versions));
            let after = evaluate_entry(&scheme(), &entry, 0, Some(&installed));
            prop_assert!(after != VersionEvidence::OutOfRange, "{after:?}");
            prop_assert!(after != VersionEvidence::NotApplicable);
            Ok(())
        })
        .unwrap();
}

/// Shuffling the events of every range never changes the kind of result.
#[test]
fn shuffling_events_never_changes_the_result() {
    let strategy = (spec(), installed_strategy(), any::<usize>());
    proptest::test_runner::TestRunner::new(config())
        .run(&strategy, |(spec, installed, rot)| {
            let Some(entry) = build(&spec, None) else {
                return Ok(());
            };
            let mut shuffled = spec.clone();
            for r in &mut shuffled.ranges {
                if !r.events.is_empty() {
                    let k = rot % r.events.len();
                    r.events.rotate_left(k);
                    r.events.reverse();
                }
            }
            let Some(other) = build(&shuffled, None) else {
                return Ok(());
            };
            let a = evaluate_entry(&scheme(), &entry, 0, Some(&installed));
            let b = evaluate_entry(&scheme(), &other, 0, Some(&installed));
            prop_assert_eq!(kind(&a), kind(&b));
            Ok(())
        })
        .unwrap();
}

// ------------------------------------------------- differential oracle

/// A valid range: openings and closings alternate in increasing order, limits
/// lie above every opening, and a point range is an introduced and a
/// last_affected at one release.
#[derive(Clone, Debug)]
enum Valid {
    Normal {
        zero_start: bool,
        coords: Vec<u8>,
        last_affected: bool,
        limits: Vec<u8>,
        star: bool,
        range_type: u8,
        rot: usize,
    },
    Point {
        at: u8,
    },
}

fn valid_range() -> impl Strategy<Value = Valid> {
    prop_oneof![
        3 => (
            any::<bool>(),
            prop::collection::btree_set(1u8..9, 1..6),
            any::<bool>(),
            prop::collection::vec(1u8..12, 0..3),
            any::<bool>(),
            0u8..2,
            any::<usize>(),
        )
            .prop_map(|(zero_start, coords, last_affected, limits, star, range_type, rot)| {
                Valid::Normal {
                    zero_start,
                    coords: coords.into_iter().collect(),
                    last_affected,
                    limits,
                    star,
                    range_type,
                    rot,
                }
            }),
        1 => (1u8..9).prop_map(|at| Valid::Point { at }),
    ]
}

type Step = (char, Option<u8>);

/// The events as (kind, coordinate) with `None` for "from the start", the
/// limits, and the JSON of the range.
fn valid_parts(v: &Valid) -> (Vec<Step>, Vec<u8>, bool, Value) {
    match v {
        Valid::Point { at } => {
            let steps = vec![('I', Some(*at)), ('L', Some(*at))];
            let json =
                eco(json!([{"last_affected": at.to_string()}, {"introduced": at.to_string()}]));
            (steps, vec![], false, json)
        }
        Valid::Normal {
            zero_start,
            coords,
            last_affected,
            limits,
            star,
            range_type,
            rot,
        } => {
            let close = if *last_affected { 'L' } else { 'F' };
            let mut steps: Vec<Step> = Vec::new();
            let mut open = true;
            if *zero_start {
                steps.push(('I', None));
                open = false;
            }
            for c in coords {
                steps.push((if open { 'I' } else { close }, Some(*c)));
                open = !open;
            }
            let max_open = steps
                .iter()
                .filter(|(k, _)| *k == 'I')
                .filter_map(|(_, c)| *c)
                .max()
                .unwrap_or(0);
            let mut limits: Vec<u8> = limits.iter().copied().filter(|l| *l > max_open).collect();
            // A closing must not sit beyond every limit (a last_affected at or
            // above them all, a fixed strictly above them all): drop the limits.
            if !*star
                && steps.iter().any(|(k, c)| {
                    c.is_some_and(|c| match k {
                        'L' => !limits.iter().any(|l| *l > c),
                        'F' => !limits.iter().any(|l| *l >= c),
                        _ => false,
                    })
                })
            {
                limits.clear();
            }
            let mut events: Vec<Value> = steps
                .iter()
                .map(|(k, c)| {
                    let text = c.map_or("0".to_string(), |c| c.to_string());
                    match k {
                        'I' => json!({"introduced": text}),
                        'F' => json!({"fixed": text}),
                        _ => json!({"last_affected": text}),
                    }
                })
                .collect();
            for l in &limits {
                events.push(json!({"limit": l.to_string()}));
            }
            if *star {
                events.push(json!({"limit": "*"}));
            }
            let k = rot % events.len();
            events.rotate_left(k);
            if rot % 2 == 1 {
                events.reverse();
            }
            let ty = ["ECOSYSTEM", "SEMVER"][*range_type as usize];
            (steps, limits, *star, json!({"type": ty, "events": events}))
        }
    }
}

/// OSV's evaluation, written out directly: walk the events in version order,
/// applying each one that the candidate has reached.
fn oracle_range(steps: &[Step], limits: &[u8], star: bool, candidate: &str) -> bool {
    let s = scheme();
    let cand = s.parse(candidate).unwrap();
    let key = |c: &Option<u8>| c.map(|c| s.parse(&c.to_string()).unwrap());
    let mut sorted = steps.to_vec();
    sorted.sort_by(|a, b| key(&a.1).cmp(&key(&b.1)).then(a.0.cmp(&b.0)));
    let mut affected = false;
    for (k, c) in &sorted {
        let reached_incl = key(c).is_none_or(|v| v <= cand);
        let reached_strict = key(c).is_none_or(|v| v < cand);
        match k {
            'I' if reached_incl => affected = true,
            'F' if reached_incl => affected = false,
            'L' if reached_strict => affected = false,
            _ => {}
        }
    }
    let below_a_limit = star
        || limits.is_empty()
        || limits
            .iter()
            .any(|l| cand < s.parse(&l.to_string()).unwrap());
    affected && below_a_limit
}

#[test]
fn the_evaluator_agrees_with_a_direct_transcription_of_osv_on_valid_ranges() {
    let strategy = (
        prop::collection::vec(valid_range(), 1..4),
        prop::collection::vec(1u8..9, 0..4),
        installed_strategy(),
        (0u8..8, 1u8..4),
    );
    let (ins, outs) = (std::cell::Cell::new(0), std::cell::Cell::new(0));
    let (b_in, b_out) = (std::cell::Cell::new(0), std::cell::Cell::new(0));
    proptest::test_runner::TestRunner::new(config())
        .run(&strategy, |(ranges, list, installed, (a, k))| {
            let parts: Vec<_> = ranges.iter().map(valid_parts).collect();
            let json_ranges: Vec<Value> = parts.iter().map(|p| p.3.clone()).collect();
            let versions: Vec<String> = list.iter().map(|n| n.to_string()).collect();
            let entry = entry_from(Value::Array(json_ranges), json!(versions));
            let expected = parts
                .iter()
                .any(|(steps, limits, star, _)| oracle_range(steps, limits, *star, &installed))
                || versions.contains(&installed);
            let got = evaluate_entry(&scheme(), &entry, 0, Some(&installed));
            let want = if expected { "in" } else { "out" };
            prop_assert_eq!(kind(&got), want, "{:?} installed {}", ranges, installed);
            if expected {
                ins.set(ins.get() + 1);
            } else {
                outs.set(outs.get() + 1);
            }

            // An interval answer holds for every version inside it, release
            // candidates included.
            let interval = format!("{a}~{}", a + k);
            let got = evaluate_entry(&scheme(), &entry, 0, Some(&interval));
            let members: Vec<String> = (a..a + k)
                .map(|n| n.to_string())
                .chain((a + 1..=a + k).map(|n| format!("{n}-rc1")))
                .collect();
            let member_in = |m: &String| {
                parts
                    .iter()
                    .any(|(steps, limits, star, _)| oracle_range(steps, limits, *star, m))
                    || versions.contains(m)
            };
            match kind(&got) {
                "in" => {
                    prop_assert!(members.iter().all(member_in), "{ranges:?} {interval}");
                    b_in.set(b_in.get() + 1);
                }
                "out" => {
                    prop_assert!(!members.iter().any(member_in), "{ranges:?} {interval}");
                    b_out.set(b_out.get() + 1);
                }
                _ => {}
            }
            Ok(())
        })
        .unwrap();
    assert!(
        ins.get() >= 100 && outs.get() >= 100,
        "{} {}",
        ins.get(),
        outs.get()
    );
    assert!(
        b_in.get() >= 10 && b_out.get() >= 10,
        "{} {}",
        b_in.get(),
        b_out.get()
    );
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

/// Every event of a raw range as (kind, text), read without the parser.
fn raw_events(range: &Value) -> Vec<(String, String)> {
    range["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| e.as_object())
        .flat_map(|o| {
            o.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
        })
        .collect()
}

#[test]
fn every_corpus_boundary_gives_the_stated_answer() {
    let files = corpus_files();
    assert_eq!(files.len(), 23);
    let s = scheme();
    let (mut ins, mut outs, mut unknowns) = (0, 0, 0);
    let (mut introduced_checked, mut fixed_checked) = (0, 0);
    for (name, bytes) in &files {
        let adv = parse_advisory_from(bytes, Source::GuardDogCorpus).unwrap();
        let raw: Value = serde_json::from_slice(bytes).unwrap();
        for (idx, entry) in adv.affected.iter().enumerate() {
            // Determinism and no panic at every boundary and its neighbours.
            let mut boundaries: Vec<String> = Vec::new();
            let raw_ranges = raw["affected"][idx]["ranges"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            for r in &raw_ranges {
                for (_, t) in raw_events(r) {
                    boundaries.extend(neighbours(t.trim().trim_start_matches('v')));
                }
            }
            boundaries.sort();
            boundaries.dedup();
            for b in &boundaries {
                let first = evaluate_entry(&s, &adv, idx, Some(b));
                assert_eq!(
                    first,
                    evaluate_entry(&s, &adv, idx, Some(b)),
                    "{name} {idx} {b}"
                );
                assert!(first != VersionEvidence::NotApplicable, "{name}");
                // No corpus range is malformed or has a tie.
                if let VersionEvidence::Unknown { reason, .. } = &first {
                    assert!(
                        !matches!(
                            reason,
                            UnknownReason::MalformedRange | UnknownReason::ConflictingEvents
                        ),
                        "{name} entry {idx} {b}: {reason:?}"
                    );
                }
                match first {
                    VersionEvidence::InRange(_) => ins += 1,
                    VersionEvidence::OutOfRange => outs += 1,
                    _ => unknowns += 1,
                }
            }

            // Per-range facts, on each ordered range alone and fully readable.
            for (ri, r) in raw_ranges.iter().enumerate() {
                let ty = r["type"].as_str().unwrap();
                if ty != "ECOSYSTEM" && ty != "SEMVER" {
                    continue;
                }
                let events = raw_events(r);
                let readable = events
                    .iter()
                    .all(|(_, t)| matches!(t.trim(), "0" | "*") || s.parse(t.trim()).is_ok());
                if !readable {
                    continue;
                }
                let alone = entry_from(json!([r.clone()]), json!([]));
                let _ = entry;
                for (ei, (k, t)) in events.iter().enumerate() {
                    let t = t.trim();
                    if t == "0" || t == "*" {
                        continue;
                    }
                    let got = evaluate_entry(&s, &alone, 0, Some(t));
                    match k.as_str() {
                        "introduced" => {
                            assert_eq!(
                                got,
                                VersionEvidence::InRange(Location {
                                    entry: 0,
                                    place: Place::Range {
                                        range: 0,
                                        event: Some(ei)
                                    }
                                }),
                                "{name} entry {idx} range {ri} introduced {t}"
                            );
                            introduced_checked += 1;
                        }
                        "fixed" => {
                            assert_eq!(
                                got,
                                VersionEvidence::OutOfRange,
                                "{name} entry {idx} range {ri} fixed {t}"
                            );
                            fixed_checked += 1;
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    // The run is not vacuous.
    assert!(
        ins > 0 && outs > 0 && unknowns > 0,
        "{ins} {outs} {unknowns}"
    );
    assert!(
        introduced_checked > 0 && fixed_checked > 0,
        "{introduced_checked} {fixed_checked}"
    );
}
