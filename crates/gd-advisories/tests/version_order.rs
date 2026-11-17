//! Phase 2.1, PR 2 and the channel part of PR 4: SemVer (with the Go tag
//! adapter), Bitcoin Core and the `semver-beta` channel scheme.
//!
//! Tables for every rule and example in design 2.1 section 2, the recorded
//! SemVer precedence list (`tests/reference/`), every corpus endpoint and every
//! fixture or catalog version of Bitcoin Core and LND, ordering laws as
//! fixed-seed properties, refusals, the dual-order check, the fixture pairs'
//! version subresults through the range evaluator, and test-only mutants that
//! each must break the check they are aimed at.

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
    Advisory, BitcoinCore, Candidate, Channel, ChannelScheme, GapKind, GoTag, Place, RcEvidence,
    SemVer, Source, UnknownReason, VersionError, VersionEvidence, VersionScheme, canonical_package,
    evaluate_channel_entry, evaluate_entry, parse_advisory, parse_advisory_from,
};
use proptest::prelude::*;
use serde_json::{Value, json};

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

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

// ---------------------------------------------------------------- helpers

fn cmp_with<S: VersionScheme>(s: &S, a: &str, b: &str) -> Ordering {
    let (a, b) = (s.parse(a).unwrap(), s.parse(b).unwrap());
    a.cmp(&b)
}

fn lt<S: VersionScheme>(s: &S, a: &str, b: &str) {
    assert!(cmp_with(s, a, b) == Ordering::Less, "ordering a < b failed");
    assert!(
        cmp_with(s, b, a) == Ordering::Greater,
        "ordering b > a failed"
    );
}

fn eq<S: VersionScheme>(s: &S, a: &str, b: &str) {
    assert!(
        cmp_with(s, a, b) == Ordering::Equal,
        "ordering a = b failed"
    );
}

fn refused<S: VersionScheme>(s: &S, bad: &[&str]) {
    for b in bad {
        assert!(s.parse(b).is_err(), "{b:?} should be refused");
    }
}

fn entry(ecosystem: &str, name: &str, ranges: Value, versions: Value) -> Advisory {
    let mut e = json!({"package": {"ecosystem": ecosystem, "name": name}});
    e["ranges"] = ranges;
    if versions.as_array().is_some_and(|v| !v.is_empty()) {
        e["versions"] = versions;
    }
    let record = json!({"id": "x_test-1", "modified": "2026-11-17T00:00:00Z", "affected": [e]});
    parse_advisory(record.to_string().as_bytes()).unwrap()
}

fn range(kind: &str, events: Value) -> Value {
    json!([{"type": kind, "events": events}])
}

fn place(e: &VersionEvidence) -> Place {
    match e {
        VersionEvidence::Unknown { at, .. } => at.place,
        _ => panic!("expected an unknown result"),
    }
}

fn reason(e: &VersionEvidence) -> UnknownReason {
    match e {
        VersionEvidence::Unknown { reason, .. } => *reason,
        _ => panic!("expected an unknown result"),
    }
}

// ------------------------------------------------------------ SemVer rules

#[test]
fn semver_reads_the_valid_forms() {
    let s = SemVer;
    for ok in [
        "0.0.0",
        "1.2.3",
        "10.20.30",
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-0.3.7",
        "1.0.0-x.7.z.92",
        "1.0.0-x-y-z.--",
        "1.0.0+20130313144700",
        "1.0.0-beta+exp.sha.5114f85",
        "1.0.0+001",
        "1.0.0+0.0",
        "0.0.0-20240101000000-abcdef123456",
        "99999999999999999999999999.0.0",
    ] {
        assert!(s.parse(ok).is_ok(), "{ok}");
    }
}

#[test]
fn semver_refuses_each_malformed_form() {
    refused(
        &SemVer,
        &[
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "1.02.3",
            "01.2.3",
            "1.2.03",
            "1.0.0-01",
            "1.0.0-alpha.01",
            "1.0.0-",
            "1.0.0-.",
            "1.0.0-a..b",
            "1.0.0-a.",
            "1.0.0+",
            "1.0.0+a..b",
            "1.0.0++a",
            "1.0.0+a+b",
            "1.0.0-alpha_1",
            "1.0.0-\u{e9}",
            "\u{ff11}.0.0",
            "1.0.0-\u{ff11}",
            "1.0.0 ",
            " 1.0.0",
            "-1.0.0",
            "1.-1.0",
            "1.0.0\n",
            "v1.0.0",
            "1.x.0",
            "+1.0.0",
        ],
    );
}

#[test]
fn semver_orders_the_published_precedence_chain() {
    let text = fs::read_to_string(root().join("tests/reference/semver-precedence.txt")).unwrap();
    let chain: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    assert_eq!(chain.len(), 8, "the spec's example chain has eight entries");
    for i in 0..chain.len() {
        for j in (i + 1)..chain.len() {
            for (name, ord) in [
                ("SemVer", cmp_with(&SemVer, chain[i], chain[j])),
                ("Go tag", cmp_with(&GoTag, chain[i], chain[j])),
            ] {
                assert!(
                    ord == Ordering::Less,
                    "precedence order broken in {name}: entries #{i} and #{j}"
                );
            }
        }
    }
}

#[test]
fn semver_design_examples() {
    let s = SemVer;
    lt(&s, "1.0.0-alpha.9", "1.0.0-alpha.10");
    lt(&s, "1.0.0-alpha.10", "1.0.0-beta");
    lt(&s, "1.0.0-beta", "1.0.0");
    // Numeric identifiers sort below text ones, text by ASCII, shorter prefix first.
    lt(&s, "1.0.0-1", "1.0.0-a");
    lt(&s, "1.0.0-99", "1.0.0-0a");
    lt(&s, "1.0.0-Beta", "1.0.0-alpha");
    lt(&s, "1.0.0-a", "1.0.0-a-");
    lt(&s, "1.0.0-alpha", "1.0.0-alpha.0");
    // The triple dominates.
    lt(&s, "1.9.0", "1.10.0");
    lt(&s, "1.2.3", "1.2.10");
    lt(&s, "2.0.0-rc.1", "2.0.1-alpha");
    lt(&s, "1.9.9", "2.0.0-alpha");
    // No package-manager prerelease exclusion: a prerelease is an ordinary version.
    lt(&s, "0.0.0-0", "0.0.0");
}

#[test]
fn semver_metadata_is_ignored_for_order_but_kept_for_identity() {
    let s = SemVer;
    eq(&s, "1.0.0+a", "1.0.0+b");
    eq(&s, "1.0.0", "1.0.0+anything");
    eq(&s, "1.0.0-rc.1+a", "1.0.0-rc.1");
    assert_eq!(s.same_identity("1.0.0+a", "1.0.0+b"), Some(false));
    assert_eq!(s.same_identity("1.0.0+a", "1.0.0+a"), Some(true));
    assert_eq!(s.same_identity("1.0.0", "1.0.0+a"), Some(false));
    // Metadata may carry leading zeros; prerelease numbers may not.
    assert_eq!(s.same_identity("1.0.0+001", "1.0.0+1"), Some(false));
    assert_eq!(s.same_identity("1.0.0", "garbage"), None);
    assert_eq!(s.same_identity("garbage", "1.0.0"), None);
    // The precedence-equal listed version is a different spelling for the evaluator.
    let v = s.parse("1.0.0+a").unwrap();
    assert_eq!(s.same_version(&v, "1.0.0+b"), Some(true));
    assert_eq!(s.same_version(&v, "garbage"), None);
}

#[test]
fn semver_numbers_never_overflow() {
    let s = SemVer;
    let big = "99999999999999999999999999999999";
    let bigger = "100000000000000000000000000000000";
    lt(&s, &format!("{big}.0.0"), &format!("{bigger}.0.0"));
    lt(&s, &format!("1.0.0-{big}"), &format!("1.0.0-{bigger}"));
    lt(&s, "1.0.0-9", "1.0.0-10");
}

#[test]
fn semver_declares_its_capabilities() {
    assert!(SemVer.reads_semver_ranges());
    assert!(SemVer.orders());
    assert!(GoTag.reads_semver_ranges());
    assert!(GoTag.orders());
}

#[test]
fn semver_budgets_are_refused_by_name() {
    let s = SemVer;
    let long_pre = format!("1.0.0-{}", "a".repeat(300));
    assert_eq!(s.parse(&long_pre).unwrap_err(), VersionError::TooLong);
    let at_limit = format!("1.0.0-{}", "a".repeat(250));
    assert_eq!(at_limit.len(), 256);
    assert!(s.parse(&at_limit).is_ok());
    let over = format!("1.0.0-{}", "a".repeat(251));
    assert_eq!(s.parse(&over).unwrap_err(), VersionError::TooLong);
    let many = |n: usize| format!("1.0.0-{}", vec!["a"; n].join("."));
    assert!(s.parse(&many(64)).is_ok());
    assert_eq!(s.parse(&many(65)).unwrap_err(), VersionError::TooLong);
    let many_meta = |n: usize| format!("1.0.0+{}", vec!["a"; n].join("."));
    assert!(s.parse(&many_meta(64)).is_ok());
    assert_eq!(s.parse(&many_meta(65)).unwrap_err(), VersionError::TooLong);
    let huge = "9".repeat(5000);
    assert_eq!(s.parse(&huge).unwrap_err(), VersionError::TooLong);
    assert_eq!(GoTag.parse(&huge).unwrap_err(), VersionError::TooLong);
    assert_eq!(
        BitcoinCore::new(RcEvidence::Reported)
            .parse(&huge)
            .unwrap_err(),
        VersionError::TooLong
    );
    assert_eq!(
        ChannelScheme::beta().parse(&huge).unwrap_err(),
        VersionError::TooLong
    );
}

// --------------------------------------------------------------- Go adapter

#[test]
fn go_tag_removes_exactly_one_lowercase_v_and_keeps_the_spelling() {
    let g = GoTag;
    eq(&g, "v0.5.1", "0.5.1");
    let v = g.parse("v0.5.1").unwrap();
    assert_eq!(v.raw(), "v0.5.1");
    assert_eq!(v.identity(), "0.5.1");
    assert_eq!(g.parse("0.5.1").unwrap().raw(), "0.5.1");
    assert_eq!(g.same_identity("v0.5.1", "0.5.1"), Some(true));
    assert_eq!(g.same_identity("v1.0.0+a", "v1.0.0+b"), Some(false));
    refused(
        &g,
        &["vv0.5.1", "V0.5.1", "v", "v v0.5.1", "v 0.5.1", "v+1.0.0"],
    );
    // Strict SemVer has no adapter.
    assert!(SemVer.parse("v0.5.1").is_err());
}

#[test]
fn go_tag_refuses_incomplete_tags() {
    refused(&GoTag, &["v1", "v1.2", "1", "1.2", "v1.2.3.4", "v01.2.3"]);
}

#[test]
fn go_pseudo_versions_stay_whole_prereleases() {
    let g = GoTag;
    lt(&g, "v0.0.0-20240101000000-abcdef123456", "v0.0.0");
    lt(
        &g,
        "v0.0.0-20240101000000-abcdef123456",
        "v0.0.0-20240102000000-000000000000",
    );
    // The hash is never ancestry: same timestamp, hashes ordered as text only.
    assert_eq!(
        g.same_identity(
            "v0.0.0-20240101000000-abcdef123456",
            "v0.0.0-20240101000000-abcdef123457"
        ),
        Some(false)
    );
}

// ------------------------------------------------------------- Bitcoin Core

fn core() -> BitcoinCore {
    BitcoinCore::new(RcEvidence::Reported)
}

#[test]
fn core_reads_the_valid_forms() {
    let c = core();
    for ok in [
        "28.1",
        "28.1.0",
        "v28.1",
        "v28.1.0",
        "0.21.1",
        "v0.14.0",
        "32.1",
        "22.0",
        "28.1rc2",
        "v29.0rc1",
        "0.21.0rc3",
        "28.1.1rc10",
    ] {
        assert!(c.parse(ok).is_ok(), "{ok}");
    }
}

#[test]
fn core_refuses_everything_else() {
    refused(
        &core(),
        &[
            "",
            "28",
            "28.",
            ".1",
            "28.01",
            "028.1",
            "28.1.01",
            "28.1.0.0",
            "28.1-rc1",
            "28.1.0-rc1",
            "28.1rc",
            "28.1rc0",
            "28.1rc01",
            "28.1RC1",
            "28.1rc1.1",
            "28.1rc2rc3",
            "28.1 ",
            " 28.1",
            "V28.1",
            "vv28.1",
            "28.1.x",
            "28.1beta",
            "28.1+build",
            "28.1.rc1",
            "/Satoshi:28.1.0/",
            "Satoshi:28.1.0",
            "\u{ff12}8.1",
            "28.\u{ff11}",
        ],
    );
}

#[test]
fn core_order_examples() {
    let c = core();
    lt(&c, "0.21.1", "22.0");
    lt(&c, "0.9.0", "0.10.0");
    lt(&c, "9.0", "10.0");
    eq(&c, "28.1", "28.1.0");
    eq(&c, "v28.1", "28.1.0");
    lt(&c, "28.1rc2", "28.1rc10");
    lt(&c, "28.1rc10", "28.1");
    lt(&c, "28.1rc2", "28.1.0");
    lt(&c, "28.0.9", "28.1rc1");
    lt(&c, "28.1", "28.1.1rc1");
    lt(&c, "0.21.0rc3", "0.21.0");
    lt(&c, "28.3", "29.0rc1");
}

#[test]
fn core_identity_is_the_normalized_release() {
    let c = core();
    assert_eq!(c.same_identity("28.1", "v28.1.0"), Some(true));
    assert_eq!(c.same_identity("28.1rc2", "28.1"), Some(false));
    assert_eq!(c.same_identity("28.1rc2", "v28.1.0rc2"), Some(true));
    assert_eq!(c.same_identity("28.1", "nope"), None);
}

#[test]
fn core_declares_its_capabilities() {
    // The corpus's Core ranges are ECOSYSTEM; a SEMVER range stays unknown
    // until a reviewed interpretation exists.
    assert!(!core().reads_semver_ranges());
    assert!(core().orders());
}

/// Whether `s` treats a final-looking installed value as possibly a release
/// candidate: the interval from the lowest RC of 28.1 to just below 28.1.1rc1.
fn marks_rc_unknown(s: &BitcoinCore) -> bool {
    match s.candidate("28.1") {
        Ok(Candidate::Between {
            low,
            high: Some(high),
        }) => {
            let rc1 = s.parse("28.1rc1").unwrap();
            let fin = s.parse("28.1").unwrap();
            low == rc1
                && fin >= low
                && fin < high
                && s.parse("28.1.1rc1").unwrap() >= high
                && s.parse("28.1.1rc0").is_err()
                && s.parse("28.1.1").unwrap() > high
        }
        _ => false,
    }
}

#[test]
fn core_rc_unknown_source_gives_an_interval() {
    let unknown = BitcoinCore::new(RcEvidence::Unknown);
    assert!(marks_rc_unknown(&unknown));
    // A value that shows its rc is exact from a full-version source.
    assert!(matches!(
        core().candidate("28.1rc2"),
        Ok(Candidate::Exact(_))
    ));
    // A source that reports the full version makes a final value exact.
    assert!(matches!(core().candidate("28.1"), Ok(Candidate::Exact(_))));
    assert!(unknown.candidate("nope").is_err());
    // Advisory boundaries are never affected by the flag.
    assert_eq!(
        unknown.parse("28.1").unwrap(),
        core().parse("28.1").unwrap()
    );
}

#[test]
fn core_rc_unknown_ends_unknown_when_rc_and_final_differ() {
    let unknown = BitcoinCore::new(RcEvidence::Unknown);
    let reported = core();
    // Fix at 28.3: 28.3rc1 is affected, 28.3 is not.
    let fixed = entry(
        "GIT",
        "https://github.com/bitcoin/bitcoin",
        range(
            "ECOSYSTEM",
            json!([{"introduced": "28.0"}, {"fixed": "28.3"}]),
        ),
        json!([]),
    );
    let e = evaluate_entry(&unknown, &fixed, 0, Some("28.3"));
    assert_eq!(reason(&e), UnknownReason::CandidateIsAnInterval);
    // With the full version the same value is simply out of range.
    assert_eq!(
        evaluate_entry(&reported, &fixed, 0, Some("28.3")),
        VersionEvidence::OutOfRange
    );
    // Introduced at 28.3: the final is affected, an rc is not.
    let intro = entry(
        "GIT",
        "https://github.com/bitcoin/bitcoin",
        range(
            "ECOSYSTEM",
            json!([{"introduced": "28.3"}, {"fixed": "29.0"}]),
        ),
        json!([]),
    );
    let e = evaluate_entry(&unknown, &intro, 0, Some("28.3"));
    assert_eq!(reason(&e), UnknownReason::CandidateIsAnInterval);
    // A range that misses the whole interval is still a clean answer.
    let miss = entry(
        "GIT",
        "https://github.com/bitcoin/bitcoin",
        range("ECOSYSTEM", json!([{"introduced": "0"}, {"fixed": "28.2"}])),
        json!([]),
    );
    assert_eq!(
        evaluate_entry(&unknown, &miss, 0, Some("28.3")),
        VersionEvidence::OutOfRange
    );
    // A SEMVER range on Core is not read in-scheme.
    let semver_range = entry(
        "GIT",
        "https://github.com/bitcoin/bitcoin",
        range("SEMVER", json!([{"introduced": "0"}, {"fixed": "28.3"}])),
        json!([]),
    );
    let e = evaluate_entry(&reported, &semver_range, 0, Some("28.1"));
    assert_eq!(reason(&e), UnknownReason::SchemeMismatch);
}

// ------------------------------------------------------------------ channel

#[test]
fn channel_reads_the_valid_forms() {
    let b = ChannelScheme::beta();
    for ok in [
        "0.18.3-beta",
        "v0.18.3-beta",
        "0.18.3-beta.rc2",
        "0.18.3-rc2",
        "v0.20.0-beta.rc10",
        "10.0.0-beta",
    ] {
        assert!(b.parse(ok).is_ok(), "{ok}");
    }
    let a = ChannelScheme::alpha();
    for ok in ["0.15.0-alpha", "v0.15.0-alpha.rc1", "0.15.0-rc1"] {
        assert!(a.parse(ok).is_ok(), "{ok}");
    }
}

#[test]
fn channel_refuses_everything_else() {
    refused(
        &ChannelScheme::beta(),
        &[
            "",
            // A bare X.Y.Z has no channel: refused, never ranked above the
            // channel release.
            "0.18.3",
            "v0.18.3",
            "10.0.0",
            "0.18",
            "0.18.3.1",
            "0.18.03",
            "0.18.3-",
            "0.18.3-alpha",
            "0.18.3-alpha.rc1",
            "0.18.3-beta.",
            "0.18.3-beta.rc",
            "0.18.3-beta.rc0",
            "0.18.3-rc0",
            "0.18.3-beta.rc01",
            "0.18.3-beta.rc1.1",
            "0.18.3-beta.1",
            "0.18.3-beta2",
            "0.18.3-Beta",
            "0.18.3-beta+meta",
            "0.18.3+meta",
            "0.18.3-beta-beta",
            "0.18.3-rc",
            "0.18.3-rc1rc2",
            "vv0.18.3",
            "V0.18.3",
            "0.18.3-beta ",
            "v0.0.0-20240101000000-abcdef123456",
        ],
    );
    refused(
        &ChannelScheme::alpha(),
        &["0.15.0-beta", "0.15.0-beta.rc1", "0.15.0-alpha.rc"],
    );
}

#[test]
fn channel_orders_rc_then_channel_release() {
    let b = ChannelScheme::beta();
    lt(&b, "0.18.3-beta.rc2", "0.18.3-beta.rc10");
    lt(&b, "0.18.3-beta.rc10", "0.18.3-beta");
    lt(&b, "0.18.2-beta", "0.18.3-beta.rc1");
    lt(&b, "0.18.3-beta", "0.18.4-beta.rc1");
    lt(&b, "0.9.0-beta", "0.10.0-beta.rc1");
    // The alias.
    eq(&b, "0.18.3-rc2", "0.18.3-beta.rc2");
    lt(&b, "0.18.3-rc2", "0.18.3-beta.rc10");
    lt(&b, "0.18.3-rc10", "0.18.3-beta");
    // Same rule for alpha.
    let a = ChannelScheme::alpha();
    lt(&a, "0.15.0-alpha.rc1", "0.15.0-alpha");
    lt(&a, "0.15.0-alpha.rc2", "0.15.0-alpha.rc10");
    eq(&a, "v0.15.0-alpha", "0.15.0-alpha");
}

#[test]
fn channel_is_never_erased() {
    let b = ChannelScheme::beta();
    assert_eq!(b.channel(), Channel::Beta);
    assert_eq!(b.parse("0.18.3-beta").unwrap().channel(), Channel::Beta);
    assert_eq!(b.parse("0.18.3-beta").unwrap().to_string(), "0.18.3-beta");
    assert_eq!(
        b.parse("v0.18.3-rc2").unwrap().to_string(),
        "0.18.3-beta.rc2"
    );
    // The bare final has no channel and is not readable at all.
    assert_eq!(b.same_identity("0.18.3-beta", "0.18.3"), None);
    assert_eq!(
        b.same_identity("v0.18.3-rc2", "0.18.3-beta.rc2"),
        Some(true)
    );
    assert_eq!(b.same_identity("0.18.3-beta", "0.18.3-alpha"), None);
    assert_eq!(Channel::from_name("beta"), Some(Channel::Beta));
    assert_eq!(Channel::from_name("alpha"), Some(Channel::Alpha));
    assert_eq!(Channel::from_name("gamma"), None);
    assert_eq!(Channel::from_name("Beta"), None);
    // Only the dual check may read SEMVER ranges for a channel product.
    assert!(!b.reads_semver_ranges() && b.orders());
}

// ---------------------------------------------------------------- dual check

fn dual(adv: &Advisory, installed: &str) -> VersionEvidence {
    evaluate_channel_entry(&ChannelScheme::beta(), adv, 0, Some(installed))
}

fn lnd_fix(fixed: &str) -> Advisory {
    entry(
        "Go",
        "github.com/lightningnetwork/lnd",
        range("SEMVER", json!([{"introduced": "0"}, {"fixed": fixed}])),
        json!([]),
    )
}

/// Test-only: the channel scheme with its range guards removed, as a caller
/// that bypassed the dual check would have it. The real scheme refuses both
/// range kinds on its own.
struct Unguarded(ChannelScheme);

impl VersionScheme for Unguarded {
    type Version = <ChannelScheme as VersionScheme>::Version;

    fn parse(&self, raw: &str) -> Result<Self::Version, VersionError> {
        self.0.parse(raw)
    }

    fn same_identity(&self, a: &str, b: &str) -> Option<bool> {
        self.0.same_identity(a, b)
    }

    fn reads_semver_ranges(&self) -> bool {
        true
    }

    fn orders(&self) -> bool {
        true
    }
}

#[test]
fn dual_check_rc_before_the_fix_stays_possible() {
    let adv = lnd_fix("0.20.0-beta");
    // Channel order: rc1 < 0.20.0-beta, so affected. SemVer: beta.rc1 > beta.
    let e = dual(&adv, "0.20.0-beta.rc1");
    assert_eq!(reason(&e), UnknownReason::SchemeConflict);
    assert_eq!(
        reason(&dual(&adv, "0.20.0-rc1")),
        UnknownReason::SchemeConflict
    );
    // Each order alone gives a confident, and different, answer (the channel
    // scheme alone, made readable by the test-only `Unguarded` wrapper).
    let eco = entry(
        "Go",
        "github.com/lightningnetwork/lnd",
        range(
            "ECOSYSTEM",
            json!([{"introduced": "0"}, {"fixed": "0.20.0-beta"}]),
        ),
        json!([]),
    );
    assert!(matches!(
        evaluate_entry(
            &Unguarded(ChannelScheme::beta()),
            &eco,
            0,
            Some("0.20.0-beta.rc1")
        ),
        VersionEvidence::InRange(_)
    ));
    // Calling the primitive with GoTag for an LND value is the misuse
    // `evaluate_entry`'s doc forbids; this shows why.
    assert_eq!(
        evaluate_entry(&GoTag, &adv, 0, Some("0.20.0-beta.rc1")),
        VersionEvidence::OutOfRange
    );
}

#[test]
fn dual_check_agreeing_orders_answer() {
    let adv = lnd_fix("0.20.0-beta");
    assert!(matches!(
        dual(&adv, "0.18.4-beta"),
        VersionEvidence::InRange(_)
    ));
    assert!(matches!(
        dual(&adv, "0.0.1-beta"),
        VersionEvidence::InRange(_)
    ));
    assert_eq!(dual(&adv, "0.20.0-beta"), VersionEvidence::OutOfRange);
    assert_eq!(dual(&adv, "0.21.6-beta"), VersionEvidence::OutOfRange);
    // A bare X.Y.Z has no channel, so the channel scheme refuses it and the
    // answer is unknown for that reason, never the SemVer side alone.
    for v in ["0.20.0", "0.0.1", "0.21.6"] {
        assert_eq!(
            reason(&dual(&adv, v)),
            UnknownReason::InstalledVersionUnparseable,
            "{v}"
        );
    }
}

#[test]
fn dual_check_final_release_inside_a_range_ended_by_a_rc() {
    // Fixed at an RC. The orders disagree about the channel release itself.
    let adv = lnd_fix("0.20.0-beta.rc2");
    // Channel: 0.20.0-beta > rc2 so out. SemVer: beta < beta.rc2 so in.
    assert_eq!(
        reason(&dual(&adv, "0.20.0-beta")),
        UnknownReason::SchemeConflict
    );
}

#[test]
fn dual_check_a_parser_failure_never_lets_the_other_answer_alone() {
    let adv = lnd_fix("0.20.0-beta");
    // A Go pseudo-version: SemVer reads it, the channel scheme cannot. The
    // unreadable side's own reason and place come back, not a conflict.
    let e = dual(&adv, "v0.0.0-20240101000000-abcdef123456");
    assert_eq!(reason(&e), UnknownReason::InstalledVersionUnparseable);
    assert_eq!(place(&e), Place::Entry);
    // A bound only SemVer can read: the channel side names the boundary.
    let odd = lnd_fix("0.20.0-nightly");
    let e = dual(&odd, "0.18.4-beta");
    assert_eq!(reason(&e), UnknownReason::UnparseableBoundary);
    assert_eq!(
        place(&e),
        Place::Range {
            range: 0,
            event: Some(1)
        }
    );
    // The same through a listed version only the channel side cannot read.
    let listed = entry(
        "Go",
        "github.com/lightningnetwork/lnd",
        json!([]),
        json!(["0.20.0-nightly"]),
    );
    let e = dual(&listed, "0.18.4-beta");
    assert_eq!(reason(&e), UnknownReason::UnreadableListedVersion);
    assert_eq!(place(&e), Place::Listed { index: 0 });
    // Neither can read the installed value: the evaluator's own reason stands.
    let e = dual(&adv, "garbage");
    assert_eq!(reason(&e), UnknownReason::InstalledVersionUnparseable);
    let none = evaluate_channel_entry(&ChannelScheme::beta(), &adv, 0, None);
    assert_eq!(reason(&none), UnknownReason::InstalledVersionUnknown);
}

#[test]
fn dual_check_covers_go_ecosystem_ranges_and_lists() {
    let eco = entry(
        "Go",
        "github.com/lightningnetwork/lnd",
        range(
            "ECOSYSTEM",
            json!([{"introduced": "0.19.0-beta"}, {"fixed": "0.20.1-beta"}]),
        ),
        json!([]),
    );
    assert!(matches!(
        dual(&eco, "0.20.0-beta"),
        VersionEvidence::InRange(_)
    ));
    assert_eq!(dual(&eco, "0.18.4-beta"), VersionEvidence::OutOfRange);
    assert_eq!(
        reason(&dual(&eco, "0.20.1-beta.rc1")),
        UnknownReason::SchemeConflict
    );
    // Listed version: identity under both schemes.
    let listed = entry(
        "Go",
        "github.com/lightningnetwork/lnd",
        range(
            "SEMVER",
            json!([{"introduced": "0.19.0-beta"}, {"fixed": "0.19.1-beta"}]),
        ),
        json!(["0.21.0-beta"]),
    );
    assert!(matches!(
        dual(&listed, "0.21.0-beta"),
        VersionEvidence::InRange(_)
    ));
}

#[test]
fn dual_check_lightning_terminal_alpha() {
    let adv = entry(
        "Go",
        "github.com/lightninglabs/lightning-terminal",
        range(
            "SEMVER",
            json!([{"introduced": "0"}, {"fixed": "0.15.0-alpha"}]),
        ),
        json!([]),
    );
    let d = |v: &str| evaluate_channel_entry(&ChannelScheme::alpha(), &adv, 0, Some(v));
    assert!(matches!(d("0.14.0-alpha"), VersionEvidence::InRange(_)));
    assert_eq!(d("0.15.0-alpha"), VersionEvidence::OutOfRange);
    assert_eq!(
        reason(&d("0.15.0")),
        UnknownReason::InstalledVersionUnparseable
    );
    assert_eq!(
        reason(&d("0.15.0-alpha.rc1")),
        UnknownReason::SchemeConflict
    );
    assert_eq!(reason(&d("0.15.0-rc1")), UnknownReason::SchemeConflict);
}

#[test]
fn scheme_conflict_is_declared_last_and_asks_about_release_candidates() {
    let adv = lnd_fix("0.20.0-beta");
    match dual(&adv, "0.20.0-beta.rc1") {
        VersionEvidence::Unknown { question, .. } => {
            assert!(
                question.contains("release candidate"),
                "the question names release candidates"
            );
            assert!(
                question.contains("final release"),
                "the question names the final release"
            );
        }
        _ => panic!("expected an unknown result"),
    }
    // Declaration order is load-bearing: SchemeConflict is the last reason.
    assert!(UnknownReason::SchemeConflict > UnknownReason::NoUsableRangeOrVersions);
    assert!(UnknownReason::SchemeConflict > UnknownReason::CandidateIsAnInterval);
}

// ------------------------------------------------- corpus, fixtures, catalog

fn corpus() -> Vec<(String, Advisory, Value)> {
    let dir = root().join("advisories/corpus");
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    paths.sort();
    paths
        .into_iter()
        .map(|p| {
            let bytes = fs::read(&p).unwrap();
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                parse_advisory_from(&bytes, Source::GuardDogCorpus).unwrap(),
                serde_json::from_slice(&bytes).unwrap(),
            )
        })
        .collect()
}

const CORE_PKG: (&str, &str) = ("GIT", "https://github.com/bitcoin/bitcoin");
const LND_PKG: (&str, &str) = ("Go", "github.com/lightningnetwork/lnd");
const LIT_PKG: (&str, &str) = ("Go", "github.com/lightninglabs/lightning-terminal");
const TAPD_PKG: (&str, &str) = ("Go", "github.com/lightninglabs/taproot-assets");

/// Whether an (ecosystem, name) pair is `pkg` after canonicalisation, so the
/// same repository spelled two ways is one package.
fn same_package(ecosystem: &str, name: &str, pkg: (&str, &str)) -> bool {
    match (
        canonical_package(ecosystem, name),
        canonical_package(pkg.0, pkg.1),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Every range event value (as written) of every entry for `pkg`, with its
/// position: (entry, range, event, kind, value). The positions are numbers
/// only, so a failure message never repeats advisory text.
fn endpoints(raw: &Value, pkg: (&str, &str)) -> Vec<(usize, usize, usize, String, String)> {
    let mut out = Vec::new();
    for (ei, e) in raw["affected"].as_array().into_iter().flatten().enumerate() {
        if !same_package(
            e["package"]["ecosystem"].as_str().unwrap_or(""),
            e["package"]["name"].as_str().unwrap_or(""),
            pkg,
        ) {
            continue;
        }
        for (ri, r) in e["ranges"].as_array().into_iter().flatten().enumerate() {
            for (vi, ev) in r["events"].as_array().into_iter().flatten().enumerate() {
                for (k, v) in ev.as_object().unwrap() {
                    out.push((ei, ri, vi, k.clone(), v.as_str().unwrap().to_string()));
                }
            }
        }
    }
    out
}

#[test]
fn every_corpus_endpoint_of_core_lnd_lit_and_tapd_parses() {
    let (mut core_n, mut lnd_n, mut lit_n, mut tapd_n) = (0, 0, 0, 0);
    for (i, (_, _, raw)) in corpus().into_iter().enumerate() {
        for (e, r, v, _, text) in endpoints(&raw, CORE_PKG) {
            core_n += 1;
            assert!(
                text == "0" || core().parse(&text).is_ok(),
                "Core advisory #{i} entry {e} range {r} event {v}"
            );
        }
        for (e, r, v, _, text) in endpoints(&raw, LND_PKG) {
            lnd_n += 1;
            assert!(
                text == "0" || ChannelScheme::beta().parse(&text).is_ok(),
                "LND advisory #{i} entry {e} range {r} event {v} (channel)"
            );
            assert!(
                text == "0" || GoTag.parse(&text).is_ok(),
                "LND advisory #{i} entry {e} range {r} event {v} (Go tag)"
            );
        }
        for (e, r, v, _, text) in endpoints(&raw, LIT_PKG) {
            lit_n += 1;
            assert!(
                text == "0" || ChannelScheme::alpha().parse(&text).is_ok(),
                "LiT advisory #{i} entry {e} range {r} event {v} (channel)"
            );
            assert!(
                text == "0" || GoTag.parse(&text).is_ok(),
                "LiT advisory #{i} entry {e} range {r} event {v} (Go tag)"
            );
        }
        for (e, r, v, _, text) in endpoints(&raw, TAPD_PKG) {
            tapd_n += 1;
            assert!(
                text == "0" || SemVer.parse(&text).is_ok(),
                "tapd advisory #{i} entry {e} range {r} event {v} (SemVer)"
            );
            assert!(
                text == "0" || GoTag.parse(&text).is_ok(),
                "tapd advisory #{i} entry {e} range {r} event {v} (Go tag)"
            );
        }
    }
    // Counted so a corpus change is noticed here (CVE-2026-117346 has two
    // Core entries).
    assert_eq!(core_n, 31, "Core events");
    assert_eq!(lnd_n, 12, "LND events");
    assert_eq!(lit_n, 2, "LiT events");
    assert_eq!(tapd_n, 2, "tapd events");
}

/// Quoted `key = "value"` lines of a TOML text, in order.
fn toml_values(text: &str, key: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix(key)?.trim_start().strip_prefix('=')?;
            Some(rest.trim().trim_matches('"').to_string())
        })
        .collect()
}

/// What a catalog file's `[version]` table says: its `scheme` (the first
/// `scheme =` line directly under the `[version]` header, before the next
/// header) and the `version` and `raw` of each `[[version.examples]]`. Lines
/// inside a multiline string are skipped, so text there never counts.
struct CatalogVersion {
    scheme: Option<String>,
    examples: Vec<(Option<String>, Option<String>)>,
}

fn catalog_version(text: &str) -> CatalogVersion {
    let mut out = CatalogVersion {
        scheme: None,
        examples: Vec::new(),
    };
    let mut in_version = false;
    let mut in_example = false;
    let mut in_string = false;
    for line in text.lines() {
        let l = line.trim();
        let was_in_string = in_string;
        for quote in ["\"\"\"", "\'\'\'"] {
            if l.matches(quote).count() % 2 == 1 {
                in_string = !in_string;
            }
        }
        if was_in_string {
            continue;
        }
        if l.starts_with('[') {
            in_version = l == "[version]";
            in_example = l == "[[version.examples]]";
            if in_example {
                out.examples.push((None, None));
            }
        } else if in_version && out.scheme.is_none() {
            out.scheme = toml_values(l, "scheme").into_iter().next();
        } else if in_example && let Some(last) = out.examples.last_mut() {
            if let Some(v) = toml_values(l, "version").into_iter().next() {
                last.0 = Some(v);
            }
            if let Some(r) = toml_values(l, "raw").into_iter().next() {
                last.1 = Some(r);
            }
        }
    }
    out
}

#[test]
fn catalog_names_and_examples_parse_in_their_schemes() {
    let core_toml = fs::read_to_string(root().join("catalog/bitcoin-core.toml")).unwrap();
    let core_cat = catalog_version(&core_toml);
    assert!(
        core_cat.scheme.as_deref() == Some("bitcoin-core"),
        "Core catalog scheme"
    );
    assert!(
        core_cat
            .examples
            .iter()
            .any(|(v, _)| v.as_deref() == Some("32.1")),
        "Core catalog lists the 32.1 example"
    );
    for (n, (v, _)) in core_cat.examples.iter().enumerate() {
        let v = v.as_deref().unwrap_or("");
        assert!(core().parse(v).is_ok(), "Core example #{n}");
    }
    let lnd_toml = fs::read_to_string(root().join("catalog/lnd.toml")).unwrap();
    let lnd_cat = catalog_version(&lnd_toml);
    assert!(
        lnd_cat.scheme.as_deref() == Some("semver-beta"),
        "LND catalog scheme"
    );
    assert!(!lnd_cat.examples.is_empty(), "LND catalog has examples");
    for (n, (v, raw)) in lnd_cat.examples.iter().enumerate() {
        let v = v.as_deref().unwrap_or("");
        assert!(ChannelScheme::beta().parse(v).is_ok(), "LND example #{n}");
        if let Some(raw) = raw {
            assert!(ChannelScheme::beta().parse(raw).is_ok(), "LND raw #{n}");
        }
    }
}

#[test]
fn a_scheme_line_inside_a_multiline_string_is_not_the_catalog_scheme() {
    let text = "[upstream]\nnote = \'\'\'\nscheme = \"operator-private-marker\"\n\'\'\'\n\n[version]\nscheme = \"semver-beta\"\n\n[version.call]\nscheme = \"other\"\n";
    assert!(
        catalog_version(text).scheme.as_deref() == Some("semver-beta"),
        "the real scheme"
    );
    let text = "[version]\ndoc = \"\"\"\nscheme = \"operator-private-marker\"\n\"\"\"\nscheme = \"semver-beta\"\n";
    assert!(
        catalog_version(text).scheme.as_deref() == Some("semver-beta"),
        "the real scheme after a multiline doc"
    );
}

struct Pair {
    setup: String,
    product: String,
    version: String,
}

/// Every `[[setup.service]]` of the fixture file, with its setup.
fn fixture_services(text: &str) -> Vec<Pair> {
    let mut out = Vec::new();
    let mut setup = String::new();
    let mut in_setup = false;
    let mut in_service = false;
    let mut id = String::new();
    for line in text.lines() {
        let l = line.trim();
        if l == "[[setup]]" {
            in_setup = true;
            in_service = false;
        } else if l == "[[setup.service]]" {
            in_service = true;
        } else if l.starts_with("[[") {
            in_setup = false;
            in_service = false;
        } else if in_setup && !in_service && l.starts_with("id = ") {
            setup = toml_values(l, "id").remove(0);
        } else if in_service && l.starts_with("id = ") {
            id = toml_values(l, "id").remove(0);
        } else if in_service && l.starts_with("version = ") {
            out.push(Pair {
                setup: setup.clone(),
                product: id.clone(),
                version: toml_values(l, "version").remove(0),
            });
        }
    }
    out
}

/// (setup, advisory, version subresult) of every `[[expect]]`.
fn fixture_expects(text: &str) -> Vec<(String, String, String)> {
    text.split("\n[[expect]]\n")
        .skip(1)
        .map(|block| {
            let get = |k: &str| toml_values(block, k).into_iter().next().unwrap();
            (get("setup"), get("advisory"), get("version"))
        })
        .collect()
}

#[test]
fn every_fixture_version_of_core_and_lnd_parses() {
    let text = fs::read_to_string(root().join("fixtures/expected-matches.toml")).unwrap();
    let mut seen = 0;
    for (n, p) in fixture_services(&text).into_iter().enumerate() {
        match p.product.as_str() {
            "bitcoin-core" => {
                seen += 1;
                assert!(
                    core().parse(&p.version).is_ok(),
                    "Core fixture service #{n}"
                );
            }
            "lnd" => {
                seen += 1;
                assert!(
                    ChannelScheme::beta().parse(&p.version).is_ok(),
                    "LND fixture service #{n} (channel)"
                );
                assert!(
                    GoTag.parse(&p.version).is_ok(),
                    "LND fixture service #{n} (Go tag)"
                );
            }
            _ => {}
        }
    }
    assert_eq!(seen, 4, "two setups, two products each");
}

/// The two reviewed platform notes of CVE-2026-117346's Core entries.
const PLATFORM_64: &str = "64-bit systems, including Windows";
const PLATFORM_32: &str = "32-bit systems, or blocks stored on a FAT32 file system";

/// The entries of `adv` that belong to the product and apply to the fixture
/// setups (64-bit, blocks on tmpfs): the 32-bit or FAT32 entry waits for the
/// later scope step, as the design says (scope before OR, a later PR). The
/// platform note must be absent or exactly one of the two reviewed strings;
/// anything else is `Err(entry index)`, never the text.
fn applicable_entries_checked(adv: &Advisory, pkg: (&str, &str)) -> Result<Vec<usize>, usize> {
    // A record whose gap list was cut cannot be trusted to show every
    // unreadable note: the whole advisory is rejected.
    if adv.gaps.iter().any(|g| g.kind == GapKind::GapsTruncated) {
        return Err(0);
    }
    let mut out = Vec::new();
    for (i, e) in adv.affected.iter().enumerate() {
        if !same_package(
            e.package.ecosystem.expose_untrusted(),
            e.package.name.expose_untrusted(),
            pkg,
        ) {
            continue;
        }
        // A hardware model note is never reviewed here, and an unreadable
        // `database_specific` field (a platform or model note of the wrong
        // type or size) cannot be trusted to mean "no note".
        let db_at = format!("affected[{i}].database_specific");
        let entry_at = format!("affected[{i}]");
        if e.scope.model.is_some()
            || adv.gaps.iter().any(|g| {
                g.kind == GapKind::UnreadableField
                    && (g.at == db_at
                        || (g.at == entry_at
                            && g.name
                                .as_ref()
                                .is_some_and(|n| n.expose_untrusted() == "database_specific")))
            })
        {
            return Err(i);
        }
        match e
            .scope
            .platform
            .as_ref()
            .map(|p| p.expose_untrusted().as_str())
        {
            None | Some(PLATFORM_64) => out.push(i),
            Some(PLATFORM_32) => {}
            Some(_) => return Err(i),
        }
    }
    Ok(out)
}

fn applicable_entries(adv: &Advisory, adv_index: usize, pkg: (&str, &str)) -> Vec<usize> {
    match applicable_entries_checked(adv, pkg) {
        Ok(v) => v,
        Err(e) => panic!("advisory #{adv_index} entry {e} has an unreviewed platform note"),
    }
}

#[test]
fn an_unreviewed_platform_note_on_a_core_entry_is_rejected() {
    let (_, adv, raw) = corpus()
        .into_iter()
        .find(|(n, _, _)| n == "CVE-2026-117346.json")
        .unwrap();
    assert_eq!(applicable_entries_checked(&adv, CORE_PKG), Ok(vec![0]));
    let mut changed = raw.clone();
    changed["affected"][1]["database_specific"]["platform"] = json!("32-bit or 64-bit systems");
    let bytes = serde_json::to_vec(&changed).unwrap();
    let adv = parse_advisory_from(&bytes, Source::GuardDogCorpus).unwrap();
    assert_eq!(applicable_entries_checked(&adv, CORE_PKG), Err(1));
    // A platform note of 4,097 bytes is unreadable (over the note size), not
    // "no note": entry 0 is rejected.
    let mut long = raw.clone();
    long["affected"][0]["database_specific"]["platform"] = json!("x".repeat(4097));
    let bytes = serde_json::to_vec(&long).unwrap();
    let adv = parse_advisory_from(&bytes, Source::GuardDogCorpus).unwrap();
    assert_eq!(applicable_entries_checked(&adv, CORE_PKG), Err(0));
    // A `database_specific` that is not an object is unreadable, not "no note".
    let mut text = raw.clone();
    text["affected"][0]["database_specific"] = json!("64-bit systems only");
    let bytes = serde_json::to_vec(&text).unwrap();
    let adv = parse_advisory_from(&bytes, Source::GuardDogCorpus).unwrap();
    assert_eq!(applicable_entries_checked(&adv, CORE_PKG), Err(0));
    // 256 unknown top-level keys use up the gap list, so the unreadable
    // platform on entry 1 is not recorded; the truncation mark rejects it all.
    let mut many = raw.clone();
    for k in 0..256 {
        many[format!("x_extra_{k:03}")] = json!(k);
    }
    many["affected"][1]["database_specific"]["platform"] = json!("x".repeat(4097));
    let bytes = serde_json::to_vec(&many).unwrap();
    let adv = parse_advisory_from(&bytes, Source::GuardDogCorpus).unwrap();
    assert!(
        adv.gaps.iter().any(|g| g.kind == GapKind::GapsTruncated),
        "the gap list was cut"
    );
    assert!(applicable_entries_checked(&adv, CORE_PKG).is_err());
    // A hardware model note, whatever its text, is never reviewed here.
    let mut model = raw.clone();
    model["affected"][0]["database_specific"]["model"] = json!("a hardware model");
    let bytes = serde_json::to_vec(&model).unwrap();
    let adv = parse_advisory_from(&bytes, Source::GuardDogCorpus).unwrap();
    assert_eq!(applicable_entries_checked(&adv, CORE_PKG), Err(0));
}

#[test]
fn the_same_package_spelled_two_ways_is_one_package_for_both_helpers() {
    let (_, _, raw) = corpus()
        .into_iter()
        .find(|(n, _, _)| n == "CVE-2026-117349.json")
        .unwrap();
    let mut changed = raw.clone();
    let before = changed["affected"].as_array().unwrap().len();
    changed["affected"].as_array_mut().unwrap().push(json!({
        "package": {
            "ecosystem": "GIT",
            "name": "https://github.com/bitcoin/bitcoin.git"
        },
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "32.1"}]}]
    }));
    let bytes = serde_json::to_vec(&changed).unwrap();
    let adv = parse_advisory_from(&bytes, Source::GuardDogCorpus).unwrap();
    let idx = applicable_entries_checked(&adv, CORE_PKG).unwrap();
    assert!(idx.contains(&before), "the appended entry is applicable");
    let counted = endpoints(&changed, CORE_PKG);
    assert!(
        counted.iter().any(|(e, _, _, _, _)| *e == before),
        "the endpoint counter sees the appended entry"
    );
    // Core 32.1 is fixed in every original range but starts the new one, so
    // the answer is InRange only if the helper kept the new entry.
    let c = BitcoinCore::new(RcEvidence::Reported);
    let rs: Vec<_> = idx
        .iter()
        .map(|&i| evaluate_entry(&c, &adv, i, Some("32.1")))
        .collect();
    assert_eq!(union(&rs), "in-range");
}

fn subresult(e: &VersionEvidence) -> &'static str {
    match e {
        VersionEvidence::InRange(_) => "in-range",
        VersionEvidence::OutOfRange => "out-of-range",
        VersionEvidence::Unknown { .. } => "unknown",
        VersionEvidence::NotApplicable => "not-applicable",
    }
}

/// The union of entries: any in-range wins, then unknown, else out-of-range.
fn union(results: &[VersionEvidence]) -> &'static str {
    if results.iter().any(|r| subresult(r) == "in-range") {
        "in-range"
    } else if results.iter().any(|r| subresult(r) == "unknown") {
        "unknown"
    } else {
        "out-of-range"
    }
}

/// The fixture pairs whose version subresult changes when Core's installed
/// value is read as a subversion (`RcEvidence::Unknown`, no `rcN`): the answer
/// key says `out-of-range` (its versions are full versions, `Reported`), the
/// subversion reading is `unknown` (design 2.1 section 2). Each is a pair where
/// the fixed version equals the installed one. Judge B's key files are not
/// edited; the live expectations (J1) must list exactly these pairs.
const SUBVERSION_UNKNOWN: &[(&str, &str, &str, &str)] = &[
    ("lab-regtest", "bitcoin-core", "32.1", "CVE-2026-117346"),
    ("lab-regtest", "bitcoin-core", "32.1", "CVE-2026-117349"),
];

#[test]
fn fixture_pairs_give_the_expected_version_subresult() {
    let text = fs::read_to_string(root().join("fixtures/expected-matches.toml")).unwrap();
    let services = fixture_services(&text);
    let expects = fixture_expects(&text);
    let docs = corpus();
    let mut checked: Vec<String> = Vec::new();
    let mut subversion_unknown = 0;
    for (xi, (setup, advisory, expected)) in expects.iter().enumerate() {
        let Some((ai, (_, adv, _))) = docs
            .iter()
            .enumerate()
            .find(|(_, (n, _, _))| n.strip_suffix(".json") == Some(advisory.as_str()))
        else {
            panic!("expectation #{xi} names no corpus record");
        };
        for svc in services.iter().filter(|s| &s.setup == setup) {
            let (pkg, got) = match svc.product.as_str() {
                "bitcoin-core" => {
                    let idx = applicable_entries(adv, ai, CORE_PKG);
                    // The key's Core versions come from the lab's pinned image
                    // (`versions_from`) or are stated (synthetic): full versions,
                    // so `Reported`. A live scan reads `subversion` instead
                    // (`Unknown`); the second pass below covers that.
                    let c = BitcoinCore::new(RcEvidence::Reported);
                    let rs: Vec<_> = idx
                        .iter()
                        .map(|&i| evaluate_entry(&c, adv, i, Some(&svc.version)))
                        .collect();
                    // The same pairs read as `subversion`: they equal the key
                    // except exactly the listed pairs, which are `unknown`.
                    let sub = BitcoinCore::new(RcEvidence::Unknown);
                    let srs: Vec<_> = idx
                        .iter()
                        .map(|&i| evaluate_entry(&sub, adv, i, Some(&svc.version)))
                        .collect();
                    let listed = SUBVERSION_UNKNOWN.iter().any(|(s, p, v, a)| {
                        (*s, *p, *v, *a)
                            == (
                                setup.as_str(),
                                "bitcoin-core",
                                svc.version.as_str(),
                                advisory.as_str(),
                            )
                    });
                    if !idx.is_empty() {
                        if listed {
                            subversion_unknown += 1;
                            assert!(
                                expected == "out-of-range",
                                "the key's value, expectation #{xi}"
                            );
                            assert_eq!(union(&srs), "unknown", "expectation #{xi}");
                            let unknowns: Vec<_> = srs
                                .iter()
                                .enumerate()
                                .filter(|(_, r)| subresult(r) == "unknown")
                                .collect();
                            assert_eq!(unknowns.len(), 1, "expectation #{xi}");
                            let (ui, u) = unknowns[0];
                            assert_eq!(
                                idx[ui], 0,
                                "expectation #{xi}: the unknown entry is entry 0"
                            );
                            assert_eq!(reason(u), UnknownReason::CandidateIsAnInterval);
                            let VersionEvidence::Unknown { question, .. } = u else {
                                unreachable!()
                            };
                            assert_eq!(
                                question,
                                "What full version does bitcoind report, including any rcN?"
                            );
                        } else {
                            assert!(union(&srs) == expected, "expectation #{xi} as subversion");
                        }
                    }
                    ("bitcoin-core", (!idx.is_empty()).then(|| union(&rs)))
                }
                "lnd" => {
                    let idx = applicable_entries(adv, ai, LND_PKG);
                    let rs: Vec<_> = idx
                        .iter()
                        .map(|&i| {
                            evaluate_channel_entry(
                                &ChannelScheme::beta(),
                                adv,
                                i,
                                Some(&svc.version),
                            )
                        })
                        .collect();
                    ("lnd", (!idx.is_empty()).then(|| union(&rs)))
                }
                _ => continue,
            };
            let Some(got) = got else { continue };
            assert!(got == expected, "{pkg} expectation #{xi}");
            checked.push(format!("{setup}/{pkg}/{advisory}"));
        }
    }
    assert_eq!(subversion_unknown, SUBVERSION_UNKNOWN.len());
    // Core: 8 advisories x 2 setups; LND: 5 advisories x 2 setups.
    assert_eq!(
        checked
            .iter()
            .filter(|c| c.contains("/bitcoin-core/"))
            .count(),
        16
    );
    assert_eq!(checked.iter().filter(|c| c.contains("/lnd/")).count(), 10);
}

// ------------------------------------------------------------- properties

fn num() -> impl Strategy<Value = String> {
    prop_oneof![
        8 => "0|[1-9][0-9]{0,3}",
        1 => "[1-9][0-9]{20,35}",
    ]
}

fn pre_id() -> impl Strategy<Value = String> {
    prop_oneof![
        "0|[1-9][0-9]{0,2}",
        "[a-zA-Z-][a-zA-Z0-9-]{0,4}",
        "[0-9]+[a-z-][a-z0-9]{0,2}"
    ]
    .prop_filter("numeric ids carry no leading zero", |s| {
        !(s.len() > 1 && s.starts_with('0') && s.bytes().all(|b| b.is_ascii_digit()))
    })
}

fn semver_text() -> impl Strategy<Value = String> {
    (
        num(),
        num(),
        num(),
        prop::option::of(prop::collection::vec(pre_id(), 1..4)),
        prop::option::of(prop::collection::vec("[0-9a-zA-Z-]{1,4}", 1..3)),
    )
        .prop_map(|(a, b, c, pre, build)| {
            let mut s = format!("{a}.{b}.{c}");
            if let Some(p) = pre {
                s.push('-');
                s.push_str(&p.join("."));
            }
            if let Some(m) = build {
                s.push('+');
                s.push_str(&m.join("."));
            }
            s
        })
}

fn core_text() -> impl Strategy<Value = String> {
    (
        any::<bool>(),
        num(),
        num(),
        prop::option::of(num()),
        prop::option::of("[1-9][0-9]{0,2}"),
    )
        .prop_map(|(v, a, b, c, rc)| {
            let mut s = String::new();
            if v {
                s.push('v');
            }
            s.push_str(&format!("{a}.{b}"));
            if let Some(c) = c {
                s.push_str(&format!(".{c}"));
            }
            if let Some(rc) = rc {
                s.push_str(&format!("rc{rc}"));
            }
            s
        })
}

fn channel_text() -> impl Strategy<Value = String> {
    (
        any::<bool>(),
        num(),
        num(),
        num(),
        0u8..3,
        "[1-9][0-9]{0,2}",
    )
        .prop_map(|(v, a, b, c, kind, rc)| {
            let mut s = String::new();
            if v {
                s.push('v');
            }
            s.push_str(&format!("{a}.{b}.{c}"));
            match kind {
                0 => s.push_str("-beta"),
                1 => s.push_str(&format!("-beta.rc{rc}")),
                _ => s.push_str(&format!("-rc{rc}")),
            }
            s
        })
}

/// The ordering laws, round trips and idempotence for one scheme.
fn laws<S: VersionScheme>(s: &S, a: &str, b: &str, c: &str, text_of: impl Fn(&S::Version) -> String)
where
    S::Version: std::fmt::Debug,
{
    let (va, vb, vc) = (
        s.parse(a).unwrap(),
        s.parse(b).unwrap(),
        s.parse(c).unwrap(),
    );
    // Reflexivity.
    assert_eq!(va.cmp(&va), Ordering::Equal);
    let twin = va.clone();
    assert!(va == twin);
    // Antisymmetry and trichotomy.
    assert_eq!(va.cmp(&vb), vb.cmp(&va).reverse());
    let ord = va.cmp(&vb);
    assert_eq!(
        [va < vb, va == vb, va > vb].iter().filter(|x| **x).count(),
        1
    );
    // cmp is Equal exactly when Eq says so.
    assert_eq!(ord == Ordering::Equal, va == vb);
    // Transitivity.
    if va <= vb && vb <= vc {
        assert!(va <= vc);
    }
    if va < vb && vb < vc {
        assert!(va < vc);
    }
    if va == vb && vb == vc {
        assert!(va == vc);
    }
    // Normalization is idempotent and the text round-trips.
    for (n, (raw, v)) in [(a, &va), (b, &vb), (c, &vc)].into_iter().enumerate() {
        let once = text_of(v);
        let again = s
            .parse(&once)
            .unwrap_or_else(|_| panic!("input #{n} does not re-parse"));
        assert!(text_of(&again) == once, "input #{n} text is not stable");
        assert!(again == *v, "input #{n} does not round-trip");
        assert_eq!(
            s.same_identity(raw, &once),
            Some(true),
            "input #{n} identity"
        );
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn semver_laws(a in semver_text(), b in semver_text(), c in semver_text()) {
        laws(&SemVer, &a, &b, &c, |v| v.identity());
        laws(&GoTag, &format!("v{a}"), &b, &format!("v{c}"), |v| v.identity());
    }

    #[test]
    fn semver_metadata_never_changes_order(a in semver_text(), b in semver_text(), m in "[0-9a-z]{1,5}") {
        let strip = |s: &str| s.split('+').next().unwrap().to_string();
        let (pa, pb) = (strip(&a), strip(&b));
        let with = format!("{pa}+{m}");
        prop_assert_eq!(
            SemVer.parse(&with).unwrap().cmp(&SemVer.parse(&pb).unwrap()),
            SemVer.parse(&pa).unwrap().cmp(&SemVer.parse(&pb).unwrap())
        );
        prop_assert_eq!(SemVer.same_identity(&pa, &with), Some(false));
    }

    #[test]
    fn core_laws(a in core_text(), b in core_text(), c in core_text()) {
        laws(&core(), &a, &b, &c, |v| v.to_string());
    }

    #[test]
    fn channel_laws(a in channel_text(), b in channel_text(), c in channel_text()) {
        laws(&ChannelScheme::beta(), &a, &b, &c, |v| v.to_string());
        laws(&ChannelScheme::alpha(),
            &a.replace("beta", "alpha"), &b.replace("beta", "alpha"), &c.replace("beta", "alpha"),
            |v| v.to_string());
    }

    #[test]
    fn channel_release_sits_above_its_rcs_and_a_bare_form_is_refused(a in num(), b in num(), c in num(), rc in "[1-9][0-9]{0,3}") {
        let s = ChannelScheme::beta();
        let p = |t: String| s.parse(&t).unwrap();
        let (rcv, rel) = (
            p(format!("{a}.{b}.{c}-beta.rc{rc}")),
            p(format!("{a}.{b}.{c}-beta")),
        );
        prop_assert!(rcv < rel);
        // A bare X.Y.Z is never read.
        let bare = format!("{a}.{b}.{c}");
        prop_assert!(s.parse(&bare).is_err());
        let alias = p(format!("{a}.{b}.{c}-rc{rc}"));
        prop_assert!(alias == rcv);
    }

    #[test]
    fn core_rc_is_below_final_and_patch_zero_is_absent(a in num(), b in num(), rc in "[1-9][0-9]{0,3}") {
        let c = core();
        let rcv = c.parse(&format!("{a}.{b}rc{rc}")).unwrap();
        let fin = c.parse(&format!("{a}.{b}")).unwrap();
        prop_assert!(rcv < fin);
        let explicit = c.parse(&format!("{a}.{b}.0")).unwrap();
        prop_assert!(fin == explicit);
    }

    #[test]
    fn nothing_panics_on_arbitrary_text(s in "\\PC{0,300}") {
        let _ = SemVer.parse(&s);
        let _ = GoTag.parse(&s);
        let _ = core().parse(&s);
        let _ = ChannelScheme::beta().parse(&s);
        let _ = ChannelScheme::alpha().parse(&s);
    }

    // Round trips are driven from valid strings with one mutation each, so the
    // accepted branch is reached often (the reach test below counts it).
    #[test]
    fn accepted_text_round_trips(
        a in mutated(semver_text()),
        b in mutated(core_text()),
        c in mutated(channel_text()),
    ) {
        round_trips(&a, &b, &c);
    }

    #[test]
    fn near_miss_strings_are_refused(s in "[0-9vrc.+a-z-]{0,24}") {
        // Whatever the schemes accept must round-trip through their own text
        // and never be accepted by the channel scheme without the channel it names.
        if let Ok(v) = ChannelScheme::beta().parse(&s) {
            prop_assert!(!v.to_string().contains("alpha"));
        }
        if let Ok(v) = SemVer.parse(&s) {
            prop_assert!(!s.starts_with('v') && !s.contains(' '));
            prop_assert!(v.identity() == s);
        }
    }
}

// ----------------------------------------------------------------- mutants
//
// Each mutant is a local, test-only copy of one behaviour with one fault. The
// original check must pass first; the mutant must fail the check it is aimed at.

type Cmp<'a> = &'a dyn Fn(&str, &str) -> Option<Ordering>;

fn real_cmp<S: VersionScheme>(s: &S) -> impl Fn(&str, &str) -> Option<Ordering> + '_ {
    move |a, b| Some(s.parse(a).ok()?.cmp(&s.parse(b).ok()?))
}

fn all_less(cmp: Cmp<'_>, pairs: &[(&str, &str)]) -> bool {
    pairs.iter().all(|(a, b)| cmp(a, b) == Some(Ordering::Less))
}

const SEMVER_NUMERIC_PAIRS: &[(&str, &str)] = &[
    ("1.9.0", "1.10.0"),
    ("1.0.0-alpha.9", "1.0.0-alpha.10"),
    ("1.0.0-beta.2", "1.0.0-beta.11"),
    ("1.0.0-9", "1.0.0-10"),
];

const FINAL_ABOVE_PRE_PAIRS: &[(&str, &str)] = &[
    ("1.0.0-rc.1", "1.0.0"),
    ("1.0.0-alpha", "1.0.0"),
    ("28.1rc2", "28.1"),
    ("28.1rc2", "28.1rc10"),
];

const CHANNEL_PAIRS: &[(&str, &str)] = &[
    ("0.18.3-beta.rc2", "0.18.3-beta.rc10"),
    ("0.18.3-beta.rc10", "0.18.3-beta"),
    ("0.18.3-beta", "0.18.4-beta.rc1"),
];

#[test]
fn mutant_numeric_to_lexical_is_caught() {
    let real = real_cmp(&SemVer);
    assert!(all_less(&real, SEMVER_NUMERIC_PAIRS), "original passes");
    // Mutant: compare the text.
    let lexical = |a: &str, b: &str| Some(a.cmp(b));
    assert!(!all_less(&lexical, SEMVER_NUMERIC_PAIRS));
    // Mutant: numbers compared as bytes without the length rule.
    let bytes_only = |a: &str, b: &str| {
        let key = |s: &str| -> Vec<Vec<u8>> {
            s.split(['.', '-']).map(|p| p.as_bytes().to_vec()).collect()
        };
        Some(key(a).cmp(&key(b)))
    };
    assert!(!all_less(&bytes_only, SEMVER_NUMERIC_PAIRS));
    // The same fault in Core and the channel scheme.
    let c = core();
    let core_real = real_cmp(&c);
    assert!(all_less(
        &core_real,
        &[("9.0", "10.0"), ("0.9.0", "0.10.0")]
    ));
    assert!(!all_less(&lexical, &[("9.0", "10.0"), ("0.9.0", "0.10.0")]));
    let b = ChannelScheme::beta();
    let chan_real = real_cmp(&b);
    assert!(all_less(&chan_real, &[("0.9.0-beta", "0.10.0-beta")]));
    assert!(!all_less(&lexical, &[("0.9.0-beta", "0.10.0-beta")]));
}

#[test]
fn mutant_rc_and_final_reversed_is_caught() {
    let c = core();
    let real = real_cmp(&c);
    assert!(all_less(&real, FINAL_ABOVE_PRE_PAIRS[2..].as_ref()));
    // Mutant: the final release sorts below its release candidates.
    let reversed = |a: &str, b: &str| {
        let order = real(a, b)?;
        let (ra, rb) = (a.contains("rc"), b.contains("rc"));
        Some(if ra != rb { order.reverse() } else { order })
    };
    assert!(!all_less(&reversed, &FINAL_ABOVE_PRE_PAIRS[2..]));
    // Channel: rc above the channel release.
    let b = ChannelScheme::beta();
    let chan = real_cmp(&b);
    assert!(all_less(&chan, CHANNEL_PAIRS));
    let chan_reversed = |x: &str, y: &str| {
        let order = chan(x, y)?;
        Some(if x.contains("rc") != y.contains("rc") {
            order.reverse()
        } else {
            order
        })
    };
    assert!(!all_less(&chan_reversed, CHANNEL_PAIRS));
    // SemVer: a prerelease above its final.
    let sv = real_cmp(&SemVer);
    assert!(all_less(&sv, &FINAL_ABOVE_PRE_PAIRS[..2]));
    let sv_reversed = |x: &str, y: &str| {
        let order = sv(x, y)?;
        Some(if x.contains('-') != y.contains('-') {
            order.reverse()
        } else {
            order
        })
    };
    assert!(!all_less(&sv_reversed, &FINAL_ABOVE_PRE_PAIRS[..2]));
}

#[test]
fn mutant_alpha_beta_stripped_is_caught() {
    let b = ChannelScheme::beta();
    let real = real_cmp(&b);
    assert!(all_less(&real, CHANNEL_PAIRS));
    // Mutant: the channel suffix is dropped before reading, so the channel
    // release equals the final release and the rc form no longer reads.
    let strip = |s: &str| s.replace("-beta", "");
    let stripped = |x: &str, y: &str| real(&strip(x), &strip(y));
    assert!(!all_less(&stripped, CHANNEL_PAIRS));
    // The refusal catches it too: the channel release is readable, the bare
    // text it would be stripped to is not.
    assert!(b.parse("0.18.3-beta").is_ok());
    assert!(b.parse(&strip("0.18.3-beta")).is_err());
    // And an alpha string is not readable by the beta scheme.
    assert!(b.parse("0.15.0-alpha").is_err());
}

#[test]
fn mutant_core_zero_prefix_is_caught() {
    let c = core();
    let accepts = |s: &str| c.parse(s).is_ok();
    let bad = ["28.01", "028.1", "28.1.01", "28.1rc01"];
    assert!(bad.iter().all(|s| !accepts(s)), "original refuses");
    // Mutant: leading zeros are trimmed from each number before reading.
    let trimmed = |s: &str| {
        let fixed: String = s
            .split('.')
            .map(|p| {
                let t = p.trim_start_matches('0');
                if t.is_empty() || !t.as_bytes()[0].is_ascii_digit() {
                    p.to_string()
                } else {
                    t.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(".");
        c.parse(&fixed).is_ok()
    };
    assert!(!bad.iter().all(|s| !trimmed(s)));
}

#[test]
fn mutant_core_rc_flag_lost_is_caught() {
    assert!(marks_rc_unknown(&BitcoinCore::new(RcEvidence::Unknown)));
    // Mutant: the flag is dropped, so a final-looking value is trusted.
    assert!(!marks_rc_unknown(&BitcoinCore::new(RcEvidence::Reported)));
    // And through the evaluator: the clean answer that would result.
    let fixed = entry(
        "GIT",
        "https://github.com/bitcoin/bitcoin",
        range(
            "ECOSYSTEM",
            json!([{"introduced": "28.0"}, {"fixed": "28.3"}]),
        ),
        json!([]),
    );
    let honest = evaluate_entry(
        &BitcoinCore::new(RcEvidence::Unknown),
        &fixed,
        0,
        Some("28.3"),
    );
    let mutant = evaluate_entry(
        &BitcoinCore::new(RcEvidence::Reported),
        &fixed,
        0,
        Some("28.3"),
    );
    assert!(matches!(honest, VersionEvidence::Unknown { .. }));
    assert_eq!(mutant, VersionEvidence::OutOfRange);
}

#[test]
fn mutant_single_order_channel_answer_is_caught() {
    // Mutant: trust the channel order alone (skip the SemVer side). Unguarded
    // removes the scheme's own refusal, as a bypassing caller would.
    let adv = entry(
        "Go",
        "github.com/lightningnetwork/lnd",
        range(
            "ECOSYSTEM",
            json!([{"introduced": "0"}, {"fixed": "0.20.0-beta"}]),
        ),
        json!([]),
    );
    let honest = dual(&adv, "0.20.0-beta.rc1");
    let mutant = evaluate_entry(
        &Unguarded(ChannelScheme::beta()),
        &adv,
        0,
        Some("0.20.0-beta.rc1"),
    );
    assert!(matches!(honest, VersionEvidence::Unknown { .. }));
    assert!(matches!(mutant, VersionEvidence::InRange(_)));
    assert_ne!(subresult(&honest), subresult(&mutant));
}

// ---------------------------------------------- round trips and their reach

/// One mutation of a valid string: kind 0 keeps it, the rest delete, insert,
/// replace, append or prepend one character at a position that wraps.
fn mutate(base: &str, kind: u8, pos: usize, ch: char) -> String {
    let mut chars: Vec<char> = base.chars().collect();
    let at = if chars.is_empty() {
        0
    } else {
        pos % chars.len()
    };
    match kind {
        1 if !chars.is_empty() => {
            chars.remove(at);
        }
        2 => chars.insert(at, ch),
        3 if !chars.is_empty() => chars[at] = ch,
        4 => chars.push(ch),
        5 => chars.insert(0, ch),
        _ => {}
    }
    chars.into_iter().collect()
}

fn mutated(text: impl Strategy<Value = String>) -> impl Strategy<Value = String> {
    (
        text,
        0u8..6,
        any::<usize>(),
        prop::sample::select(vec![
            '.', '-', '+', 'v', 'r', 'c', 'x', '0', '1', '9', ' ', 'b', 'e', 't', 'a',
        ]),
    )
        .prop_map(|(s, kind, pos, ch)| mutate(&s, kind, pos, ch))
}

/// How many strings of each scheme were accepted and round-tripped.
#[derive(Default)]
struct Reach {
    semver: usize,
    core: usize,
    channel: usize,
}

fn round_trips(a: &str, b: &str, c: &str) -> Reach {
    let mut reach = Reach::default();
    if let Ok(v) = SemVer.parse(a) {
        assert!(
            SemVer.parse(&v.identity()).unwrap().identity() == v.identity(),
            "identity is not stable"
        );
        assert!(v.identity() == a, "identity differs from the input");
        reach.semver += 1;
    }
    let _ = GoTag.parse(a);
    if let Ok(v) = core().parse(b) {
        assert!(core().parse(&v.to_string()).unwrap() == v);
        reach.core += 1;
    }
    if let Ok(v) = ChannelScheme::beta().parse(c) {
        assert!(ChannelScheme::beta().parse(&v.to_string()).unwrap() == v);
        reach.channel += 1;
    }
    reach
}

#[test]
fn the_round_trip_generators_reach_the_accepted_branch() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    let mut runner = TestRunner::new(config());
    let (sa, sb, sc) = (
        mutated(semver_text()),
        mutated(core_text()),
        mutated(channel_text()),
    );
    let mut total = Reach::default();
    let mut refused_any = [false; 3];
    for _ in 0..1024 {
        let a = sa.new_tree(&mut runner).unwrap().current();
        let b = sb.new_tree(&mut runner).unwrap().current();
        let c = sc.new_tree(&mut runner).unwrap().current();
        let r = round_trips(&a, &b, &c);
        total.semver += r.semver;
        total.core += r.core;
        total.channel += r.channel;
        refused_any[0] |= SemVer.parse(&a).is_err();
        refused_any[1] |= core().parse(&b).is_err();
        refused_any[2] |= ChannelScheme::beta().parse(&c).is_err();
    }
    // Most strings stay valid (a mutation is one of six kinds and many keep the
    // text readable), and the mutations also produce refusals.
    assert!(total.semver >= 250, "semver reached {}", total.semver);
    assert!(total.core >= 250, "core reached {}", total.core);
    assert!(total.channel >= 250, "channel reached {}", total.channel);
    assert!(
        refused_any.iter().all(|r| *r),
        "no mutation was ever refused"
    );
}

// ------------------------------------------------- fix round 1 (2026-11-17)

fn core_entry(kind: &str, events: Value) -> Advisory {
    entry(
        "GIT",
        "https://github.com/bitcoin/bitcoin",
        range(kind, events),
        json!([]),
    )
}

#[test]
fn core_interval_wholly_inside_a_range_is_in_range() {
    // Opus M1: the installed 28.3 from a source that drops rcN is somewhere in
    // 28.3rc1 .. 28.3. A range 28.0 to 29.0 holds every one of them.
    let unknown = BitcoinCore::new(RcEvidence::Unknown);
    let wide = core_entry(
        "ECOSYSTEM",
        json!([{"introduced": "28.0"}, {"fixed": "29.0"}]),
    );
    assert!(matches!(
        evaluate_entry(&unknown, &wide, 0, Some("28.3")),
        VersionEvidence::InRange(_)
    ));
    // A fix on the very release splits the interval (the rcs are affected, the
    // final is not): unknown.
    let split = core_entry(
        "ECOSYSTEM",
        json!([{"introduced": "28.0"}, {"fixed": "28.3"}]),
    );
    assert_eq!(
        reason(&evaluate_entry(&unknown, &split, 0, Some("28.3"))),
        UnknownReason::CandidateIsAnInterval
    );
    // A last_affected on the release is a closing inside the interval too.
    let last = core_entry(
        "ECOSYSTEM",
        json!([{"introduced": "28.0"}, {"last_affected": "28.3"}]),
    );
    assert_eq!(
        reason(&evaluate_entry(&unknown, &last, 0, Some("28.3"))),
        UnknownReason::CandidateIsAnInterval
    );
    // A fix in the next patch is outside the interval: every candidate is in.
    let next = core_entry(
        "ECOSYSTEM",
        json!([{"introduced": "28.0"}, {"fixed": "28.3.1"}]),
    );
    assert!(matches!(
        evaluate_entry(&unknown, &next, 0, Some("28.3")),
        VersionEvidence::InRange(_)
    ));
    // A limit below the end of the interval keeps it unsettled.
    let capped = core_entry(
        "ECOSYSTEM",
        json!([{"introduced": "28.0"}, {"limit": "28.3"}]),
    );
    assert_eq!(
        reason(&evaluate_entry(&unknown, &capped, 0, Some("28.3"))),
        UnknownReason::CandidateIsAnInterval
    );
}

#[test]
fn core_interval_end_is_just_below_the_next_patch_rc() {
    // A fix that is the first rc of the next patch does not split 28.3's
    // interval: every rc of 28.3 and 28.3 itself are below it.
    let unknown = BitcoinCore::new(RcEvidence::Unknown);
    let adv = core_entry(
        "ECOSYSTEM",
        json!([{"introduced": "28.0"}, {"fixed": "28.3.1rc1"}]),
    );
    assert!(matches!(
        evaluate_entry(&unknown, &adv, 0, Some("28.3")),
        VersionEvidence::InRange(_)
    ));
    // An introduction at the next patch's rc is not inside it either.
    let later = core_entry(
        "ECOSYSTEM",
        json!([{"introduced": "28.3.1rc1"}, {"fixed": "29.0"}]),
    );
    assert_eq!(
        evaluate_entry(&unknown, &later, 0, Some("28.3")),
        VersionEvidence::OutOfRange
    );
}

#[test]
fn core_interval_asks_the_design_question() {
    let unknown = BitcoinCore::new(RcEvidence::Unknown);
    let split = core_entry(
        "ECOSYSTEM",
        json!([{"introduced": "28.0"}, {"fixed": "28.3"}]),
    );
    match evaluate_entry(&unknown, &split, 0, Some("28.3")) {
        VersionEvidence::Unknown { question, .. } => assert_eq!(
            question,
            "What full version does bitcoind report, including any rcN?"
        ),
        other => panic!("{other:?}"),
    }
}

#[test]
fn core_refuses_the_old_four_part_versions() {
    refused(
        &core(),
        &["0.9.2.1", "v0.9.2.1", "0.8.6.0", "0.9.2.1rc1", "28.1.0.0"],
    );
    assert!(
        BitcoinCore::new(RcEvidence::Unknown)
            .candidate("0.9.2.1")
            .is_err()
    );
}

#[test]
fn a_channel_scheme_alone_never_answers_a_semver_range() {
    // Opus M3: the bare scheme is not allowed to read SEMVER ranges; only the
    // dual check may.
    let adv = lnd_fix("0.20.0-beta");
    let alpha_adv = entry(
        "Go",
        "github.com/lightninglabs/lightning-terminal",
        range(
            "SEMVER",
            json!([{"introduced": "0"}, {"fixed": "0.15.0-alpha"}]),
        ),
        json!([]),
    );
    for (scheme, adv, v) in [
        (ChannelScheme::beta(), &adv, "0.18.4-beta"),
        (ChannelScheme::alpha(), &alpha_adv, "0.14.0-alpha"),
    ] {
        let e = evaluate_entry(&scheme, adv, 0, Some(v));
        assert_eq!(reason(&e), UnknownReason::SchemeMismatch, "{v}");
    }
    // The dual check still answers it.
    assert!(matches!(
        dual(&adv, "0.18.4-beta"),
        VersionEvidence::InRange(_)
    ));
}

#[test]
fn a_bare_final_never_reads_as_past_a_channel_fix() {
    // pi M: fixed 0.18.3-beta, installed 0.18.3 used to be out of range.
    let adv = lnd_fix("0.18.3-beta");
    let e = dual(&adv, "0.18.3");
    assert_ne!(e, VersionEvidence::OutOfRange);
    assert_eq!(reason(&e), UnknownReason::InstalledVersionUnparseable);
    // And as a boundary.
    let bare_fix = lnd_fix("0.18.3");
    let e = dual(&bare_fix, "0.18.2-beta");
    assert_eq!(reason(&e), UnknownReason::UnparseableBoundary);
}

#[test]
fn dual_check_both_unknown_keeps_the_smaller_reason() {
    // The channel side cannot read the listed version (UnreadableListedVersion);
    // the SemVer side reads it but sees the same version spelled differently
    // (SameVersionDifferentSpelling, a later reason).
    let adv = entry(
        "Go",
        "github.com/lightningnetwork/lnd",
        json!([]),
        json!(["0.18.4-beta+build5"]),
    );
    let e = dual(&adv, "0.18.4-beta");
    assert_eq!(reason(&e), UnknownReason::UnreadableListedVersion);
    assert_eq!(place(&e), Place::Listed { index: 0 });
    assert!(UnknownReason::UnreadableListedVersion < UnknownReason::SameVersionDifferentSpelling);
}

// ------------------------------------------------- fix round 2 (2026-11-17)

#[test]
fn a_channel_scheme_alone_never_answers_a_go_ecosystem_range() {
    // Codex H1: introduced 0, fixed 0.20.0-beta.rc1, installed 0.20.0-beta.
    let adv = entry(
        "Go",
        "github.com/lightningnetwork/lnd",
        range(
            "ECOSYSTEM",
            json!([{"introduced": "0"}, {"fixed": "0.20.0-beta.rc1"}]),
        ),
        json!([]),
    );
    let e = evaluate_entry(&ChannelScheme::beta(), &adv, 0, Some("0.20.0-beta"));
    assert_eq!(reason(&e), UnknownReason::SchemeMismatch);
    // The public entry routes through the dual check: the orders disagree.
    let e = evaluate_channel_entry(&ChannelScheme::beta(), &adv, 0, Some("0.20.0-beta"));
    assert_ne!(e, VersionEvidence::OutOfRange);
    assert_eq!(reason(&e), UnknownReason::SchemeConflict);
    // The SEMVER form of the same range behaves the same way.
    let semver = lnd_fix("0.20.0-beta.rc1");
    let e = evaluate_channel_entry(&ChannelScheme::beta(), &semver, 0, Some("0.20.0-beta"));
    assert_eq!(reason(&e), UnknownReason::SchemeConflict);
}

#[test]
fn go_tag_refuses_installed_build_metadata_except_incompatible() {
    // Codex H2 (round 2) and C-H3 (round 4).
    let adv = entry(
        "Go",
        "github.com/example/project",
        range("SEMVER", json!([{"introduced": "0"}, {"fixed": "v1.2.3"}])),
        json!([]),
    );
    let e = evaluate_entry(&GoTag, &adv, 0, Some("v1.2.3+dirty"));
    assert_ne!(e, VersionEvidence::OutOfRange);
    assert_eq!(reason(&e), UnknownReason::InstalledVersionUnparseable);
    for dirty in ["v1.2.3+dirty", "v1.2.3+build.dirty", "1.2.3+Dirty"] {
        assert!(GoTag.candidate(dirty).is_err(), "{dirty}");
    }
    // Any other build metadata is refused too: it is not the clean tag.
    let e = evaluate_entry(&GoTag, &adv, 0, Some("v1.2.3+build5"));
    assert_eq!(reason(&e), UnknownReason::InstalledVersionUnparseable);
    assert!(GoTag.candidate("v1.2.3+build5").is_err());
    // Go's own `+incompatible` is the one exception, and only exactly so.
    assert!(GoTag.candidate("v2.0.0+incompatible").is_ok());
    // `+incompatible` exists only for major 2 and above; on major 0 or 1 it is
    // refused like any other metadata.
    for bad in ["v1.2.3+incompatible", "v0.1.0+incompatible"] {
        assert!(GoTag.candidate(bad).is_err(), "{bad}");
    }
    for bad in ["v2.0.0+INCOMPATIBLE", "v2.0.0+incompatible.build5"] {
        assert!(GoTag.candidate(bad).is_err(), "{bad}");
    }
    let inc = |fixed: &str| {
        entry(
            "Go",
            "github.com/example/project",
            range("SEMVER", json!([{"introduced": "0"}, {"fixed": fixed}])),
            json!([]),
        )
    };
    assert!(matches!(
        evaluate_entry(&GoTag, &inc("v2.0.1"), 0, Some("v2.0.0+incompatible")),
        VersionEvidence::InRange(_)
    ));
    assert_eq!(
        evaluate_entry(&GoTag, &inc("v2.0.0"), 0, Some("v2.0.0+incompatible")),
        VersionEvidence::OutOfRange
    );
    // Strict SemVer and boundaries keep ordinary metadata rules.
    assert!(SemVer.candidate("1.2.3+dirty").is_ok());
    assert!(GoTag.parse("v1.2.3+build5").is_ok());
}

#[test]
fn core_installed_rc_contradicts_a_source_that_drops_rc() {
    // Codex H3: the same input under both evidence modes.
    assert!(matches!(
        BitcoinCore::new(RcEvidence::Reported).candidate("28.0rc1"),
        Ok(Candidate::Exact(_))
    ));
    assert!(
        BitcoinCore::new(RcEvidence::Unknown)
            .candidate("28.0rc1")
            .is_err()
    );
    let adv = core_entry("ECOSYSTEM", json!([{"introduced": "0"}, {"fixed": "29.0"}]));
    let e = evaluate_entry(
        &BitcoinCore::new(RcEvidence::Unknown),
        &adv,
        0,
        Some("28.0rc1"),
    );
    assert_eq!(reason(&e), UnknownReason::InstalledVersionUnparseable);
}

#[test]
fn core_interval_starts_at_rc1() {
    // Codex M: subversion 28.0 against introduced 28.0rc1 and no closing.
    let unknown = BitcoinCore::new(RcEvidence::Unknown);
    let adv = core_entry("ECOSYSTEM", json!([{"introduced": "28.0rc1"}]));
    assert!(matches!(
        evaluate_entry(&unknown, &adv, 0, Some("28.0")),
        VersionEvidence::InRange(_)
    ));
    // An introduction at rc2 splits it: unknown.
    let rc2 = core_entry("ECOSYSTEM", json!([{"introduced": "28.0rc2"}]));
    assert_eq!(
        reason(&evaluate_entry(&unknown, &rc2, 0, Some("28.0"))),
        UnknownReason::CandidateIsAnInterval
    );
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn known_invalid_mutations_are_refused(
        a in num(), b in num(), c in num(), rc in "[1-9][0-9]{0,2}", which in 0u8..3,
    ) {
        // A leading zero in a numeric component, an empty identifier, a
        // trailing dot: each must be refused by every scheme that reads the form.
        let zero = |n: &str| format!("0{n}");
        let (sv, co, ch) = match which {
            0 => (
                format!("{}.{b}.{c}", zero(&a)),
                format!("{}.{b}", zero(&a)),
                format!("{}.{b}.{c}-beta", zero(&a)),
            ),
            1 => (
                format!("{a}.{b}.{c}-"),
                format!("{a}.{b}rc"),
                format!("{a}.{b}.{c}-beta.rc"),
            ),
            _ => (
                format!("{a}.{b}.{c}."),
                format!("{a}.{b}."),
                format!("{a}.{b}.{c}.-beta.rc{rc}"),
            ),
        };
        prop_assert!(SemVer.parse(&sv).is_err(), "{sv}");
        prop_assert!(core().parse(&co).is_err(), "{co}");
        prop_assert!(ChannelScheme::beta().parse(&ch).is_err(), "{ch}");
    }
}

// ------------------------------------------------- fix round 4 (2026-11-17)

#[test]
fn dual_check_reads_each_range_with_its_own_literal_parser() {
    let lnd = "github.com/lightningnetwork/lnd";
    let two = entry(
        "Go",
        lnd,
        json!([
            {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "v0.20.0-beta"}]},
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.19.0-beta"}]},
        ]),
        json!([]),
    );
    let semver_only = entry(
        "Go",
        lnd,
        range(
            "SEMVER",
            json!([{"introduced": "0"}, {"fixed": "v0.20.0-beta"}]),
        ),
        json!([]),
    );
    let want = Place::Range {
        range: 0,
        event: Some(1),
    };
    for adv in [&two, &semver_only] {
        let e = dual(adv, "0.21.0-beta");
        assert_ne!(e, VersionEvidence::OutOfRange);
        assert_eq!(reason(&e), UnknownReason::UnparseableBoundary);
        assert_eq!(place(&e), want);
    }
    // Control: GoTag reads the Go boundary's `v`; SemVer reads the plain one.
    let control = entry(
        "Go",
        lnd,
        json!([
            {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.20.0-beta"}]},
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "v0.19.0-beta"}]},
        ]),
        json!([]),
    );
    assert_eq!(dual(&control, "0.21.0-beta"), VersionEvidence::OutOfRange);
}

#[test]
fn a_channel_scheme_alone_answers_no_entry() {
    let lnd = "github.com/lightningnetwork/lnd";
    let miss = entry("Go", lnd, json!([]), json!(["0.20.0-beta.rc2"]));
    let hit = entry("Go", lnd, json!([]), json!(["0.20.0-beta.rc1"]));
    for adv in [&miss, &hit] {
        let e = evaluate_entry(&ChannelScheme::beta(), adv, 0, Some("0.20.0-beta.rc1"));
        assert_eq!(reason(&e), UnknownReason::SchemeMismatch);
        assert_eq!(place(&e), Place::Entry);
    }
    // Through the public entry both identities miss, so it is out of range.
    assert_eq!(dual(&miss, "0.20.0-beta.rc1"), VersionEvidence::OutOfRange);
    let lit = entry(
        "Go",
        "github.com/lightninglabs/lightning-terminal",
        json!([]),
        json!(["0.15.0-alpha.rc2"]),
    );
    let e = evaluate_entry(&ChannelScheme::alpha(), &lit, 0, Some("0.15.0-alpha.rc1"));
    assert_eq!(reason(&e), UnknownReason::SchemeMismatch);
    assert_eq!(place(&e), Place::Entry);
}

#[test]
fn a_refused_installed_value_never_matches_the_list() {
    let git = entry(
        "GIT",
        "https://github.com/bitcoin/bitcoin",
        json!([]),
        json!(["28.0rc1"]),
    );
    let e = evaluate_entry(
        &BitcoinCore::new(RcEvidence::Unknown),
        &git,
        0,
        Some("28.0rc1"),
    );
    assert_eq!(reason(&e), UnknownReason::InstalledVersionUnparseable);
    assert_eq!(place(&e), Place::Entry);
    assert_eq!(
        evaluate_entry(
            &BitcoinCore::new(RcEvidence::Reported),
            &git,
            0,
            Some("28.0rc1")
        ),
        VersionEvidence::InRange(gd_advisories::Location {
            entry: 0,
            place: Place::Listed { index: 0 },
        })
    );
    let go = entry(
        "Go",
        "github.com/example/project",
        json!([]),
        json!(["v1.2.3+dirty"]),
    );
    let e = evaluate_entry(&GoTag, &go, 0, Some("v1.2.3+dirty"));
    assert_eq!(reason(&e), UnknownReason::InstalledVersionUnparseable);
}

#[test]
fn canonical_text_fits_the_limit_and_round_trips() {
    let nines = |n: usize| "9".repeat(n);
    let ones = |n: usize| "1".repeat(n);
    let c = BitcoinCore::new(RcEvidence::Reported);
    assert_eq!(
        c.parse(&format!("{}.1", nines(254))).unwrap_err(),
        VersionError::TooLong
    );
    let v = c.parse(&format!("{}.1", nines(252))).unwrap();
    assert_eq!(v.to_string().len(), 256);
    assert_eq!(c.parse(&v.to_string()).unwrap().to_string(), v.to_string());
    assert_eq!(c.parse(&v.to_string()).unwrap(), v);

    let beta = ChannelScheme::beta();
    assert_eq!(
        beta.parse(&format!("{}.0.0-rc1", ones(248))).unwrap_err(),
        VersionError::TooLong
    );
    let v = beta.parse(&format!("{}.0.0-rc1", ones(243))).unwrap();
    assert_eq!(v.to_string().len(), 256);
    assert_eq!(beta.parse(&v.to_string()).unwrap(), v);
    assert_eq!(
        beta.parse(&v.to_string()).unwrap().to_string(),
        v.to_string()
    );

    let alpha = ChannelScheme::alpha();
    assert_eq!(
        alpha.parse(&format!("{}.0.0-rc1", ones(243))).unwrap_err(),
        VersionError::TooLong
    );
    let v = alpha.parse(&format!("{}.0.0-rc1", ones(242))).unwrap();
    assert_eq!(v.to_string().len(), 256);
    assert_eq!(alpha.parse(&v.to_string()).unwrap(), v);
    assert_eq!(
        alpha.parse(&v.to_string()).unwrap().to_string(),
        v.to_string()
    );
}

#[test]
fn go_tag_refuses_git_describe_installed_values() {
    for bad in [
        "v0.18.3-beta-12-gabc1234",
        "v0.18.3-beta-dirty",
        "v1.2.3-12-gabc1234",
        "v1.2.3-12-gabc1234-dirty",
        "v1.2.3-dirty",
        "v1.2.3-0-gDEADBEEF",
    ] {
        assert!(GoTag.candidate(bad).is_err(), "{bad}");
    }
    for good in [
        "v0.0.0-20240101000000-abcdef123456",
        "v1.2.4-0.20240101000000-abcdef123456",
        "v1.2.3-beta.rc1",
        "v1.2.3-rc.1-2",
        "v1.2.3-12-g12",
    ] {
        assert!(GoTag.candidate(good).is_ok(), "{good}");
    }
    let adv = entry(
        "Go",
        "github.com/example/project",
        range("SEMVER", json!([{"introduced": "1.2.3"}])),
        json!([]),
    );
    let e = evaluate_entry(&GoTag, &adv, 0, Some("v1.2.3-5-gabc1234"));
    assert_ne!(e, VersionEvidence::OutOfRange);
    assert_eq!(reason(&e), UnknownReason::InstalledVersionUnparseable);
    let e = dual(&lnd_fix("0.20.0-beta"), "v0.18.3-beta-12-gabc1234");
    assert_eq!(reason(&e), UnknownReason::InstalledVersionUnparseable);
}
